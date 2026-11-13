use std::path::Path;
use std::time::Duration;

use anyhow::Context;
use rusqlite::Connection;

use super::login_policy::{retain_api_key_rows, CredentialDb};

#[derive(Debug, Clone)]
pub struct SnapshotOutcome {
    pub created: bool,
    pub dropped_logins: Vec<String>,
}

pub fn snapshot_db(
    src: &Path,
    dst: &Path,
    keep_table: impl Fn(&str) -> bool,
    db: CredentialDb,
) -> anyhow::Result<SnapshotOutcome> {
    if !src.is_file() {
        return Ok(SnapshotOutcome {
            created: false,
            dropped_logins: Vec::new(),
        });
    }

    if dst.exists() {
        let _ = std::fs::remove_file(dst);
    }
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let outcome = (|| -> anyhow::Result<SnapshotOutcome> {
        let dst_str = dst.to_str().context("dst path is not valid UTF-8")?;
        // Step 2: Open read-only with 5s busy timeout, run VACUUM INTO ?1
        let vacuum_res = (|| -> anyhow::Result<()> {
            let conn = Connection::open_with_flags(
                src,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                    | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )?;
            conn.busy_timeout(Duration::from_secs(5))?;
            conn.execute("VACUUM INTO ?1", [dst_str])?;
            Ok(())
        })();

        if vacuum_res.is_err() {
            if dst.exists() {
                let _ = std::fs::remove_file(dst);
            }
            let conn = Connection::open(src)?;
            conn.busy_timeout(Duration::from_secs(5))?;
            conn.execute("VACUUM INTO ?1", [dst_str])?;
        }

        // Step 3: Open dst, verify required_table
        let conn = Connection::open(dst)?;
        conn.busy_timeout(Duration::from_secs(5))?;

        let table_exists: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name = ?1",
                [db.table()],
                |row| row.get(0),
            )
            .unwrap_or(false);

        if !table_exists {
            drop(conn);
            let _ = std::fs::remove_file(dst);
            return Ok(SnapshotOutcome {
                created: false,
                dropped_logins: Vec::new(),
            });
        }

        let retain_report = retain_api_key_rows(&conn, db)?;
        if retain_report.kept == 0 {
            drop(conn);
            let _ = std::fs::remove_file(dst);
            return Ok(SnapshotOutcome {
                created: false,
                dropped_logins: retain_report.dropped_logins,
            });
        }

        // Step 4: Delete non-kept tables
        let table_names: Vec<String> = {
            let mut stmt = conn.prepare(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
            )?;
            let items = stmt
                .query_map([], |row| row.get(0))?
                .filter_map(|r| r.ok())
                .collect();
            items
        };
        for table in table_names {
            if !keep_table(&table) {
                let delete_sql = format!("DELETE FROM \"{}\"", table.replace('"', "\"\""));
                let _ = conn.execute(&delete_sql, []);
            }
        }

        // Step 5: Clean up dst
        conn.execute_batch("PRAGMA journal_mode=DELETE; VACUUM;")?;
        drop(conn);

        Ok(SnapshotOutcome {
            created: true,
            dropped_logins: retain_report.dropped_logins,
        })
    })();

    if outcome.is_err() {
        let _ = std::fs::remove_file(dst);
    }
    outcome
}

fn prune_snapshot(snapshot: &Path, db: CredentialDb) -> anyhow::Result<i64> {
    let conn = Connection::open(snapshot)?;
    conn.busy_timeout(Duration::from_secs(5))?;
    let table_exists: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name = ?1",
            [db.table()],
            |row| row.get(0),
        )
        .unwrap_or(false);
    if !table_exists {
        return Ok(0);
    }
    let report = retain_api_key_rows(&conn, db)?;
    conn.execute_batch("PRAGMA journal_mode=DELETE; VACUUM;")?;
    drop(conn);
    Ok(report.kept)
}

pub fn omp_keep(name: &str) -> bool {
    matches!(
        name,
        "auth_credentials" | "auth_schema_version" | "auth_change_revision" | "schema_version"
    )
}

pub fn opencode_keep(name: &str) -> bool {
    name == "credential" || name.to_ascii_lowercase().contains("migration")
}

pub fn merge_omp_credentials(snapshot: &Path, target: &Path) -> anyhow::Result<()> {
    if prune_snapshot(snapshot, CredentialDb::Omp)? == 0 {
        return Ok(());
    }

    let target_exists = target.is_file();
    let has_auth_table = if target_exists {
        if let Ok(conn) = Connection::open(target) {
            conn.query_row(
                "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='auth_credentials'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(false)
        } else {
            false
        }
    } else {
        false
    };

    if !target_exists || !has_auth_table {
        let _ = std::fs::remove_file(target);
        let _ = std::fs::remove_file(format!("{}-wal", target.display()));
        let _ = std::fs::remove_file(format!("{}-shm", target.display()));

        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(snapshot, target)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(target, std::fs::Permissions::from_mode(0o600));
        }
        return Ok(());
    }

    let conn = Connection::open(target)?;
    conn.busy_timeout(Duration::from_secs(5))?;
    let snapshot_str = snapshot
        .to_str()
        .context("snapshot path is not valid UTF-8")?;
    conn.execute("ATTACH DATABASE ?1 AS src", [snapshot_str])?;

    let tx = conn.unchecked_transaction()?;
    tx.execute(
        "DELETE FROM main.auth_credentials WHERE credential_type = 'api_key' AND provider IN (SELECT DISTINCT provider FROM src.auth_credentials)",
        [],
    )?;
    tx.execute(
        r#"
        INSERT INTO main.auth_credentials (provider, credential_type, data, disabled_cause, identity_key, created_at, updated_at)
        SELECT provider, credential_type, data, disabled_cause, identity_key, created_at, updated_at
        FROM src.auth_credentials
        "#,
        [],
    )?;
    tx.commit()?;

    conn.execute("DETACH DATABASE src", [])?;
    Ok(())
}

pub fn merge_opencode_credentials(snapshot: &Path, target: &Path) -> anyhow::Result<()> {
    if prune_snapshot(snapshot, CredentialDb::OpenCode)? == 0 {
        return Ok(());
    }

    let target_exists = target.is_file();
    let has_credential_table = if target_exists {
        if let Ok(conn) = Connection::open(target) {
            conn.query_row(
                "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='credential'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(false)
        } else {
            false
        }
    } else {
        false
    };

    if !target_exists || !has_credential_table {
        let _ = std::fs::remove_file(target);
        let _ = std::fs::remove_file(format!("{}-wal", target.display()));
        let _ = std::fs::remove_file(format!("{}-shm", target.display()));

        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(snapshot, target)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(target, std::fs::Permissions::from_mode(0o600));
        }
        return Ok(());
    }

    let conn = Connection::open(target)?;
    conn.busy_timeout(Duration::from_secs(5))?;
    let snapshot_str = snapshot
        .to_str()
        .context("snapshot path is not valid UTF-8")?;
    conn.execute("ATTACH DATABASE ?1 AS src", [snapshot_str])?;

    let tx = conn.unchecked_transaction()?;
    tx.execute(
        "DELETE FROM main.credential WHERE (CASE WHEN json_valid(value) THEN json_extract(value, '$.type') = 'key' ELSE 0 END) AND integration_id IN (SELECT integration_id FROM src.credential WHERE integration_id IS NOT NULL)",
        [],
    )?;
    tx.execute(
        r#"
        INSERT OR REPLACE INTO main.credential (id, integration_id, label, value, connector_id, method_id, active, time_created, time_updated)
        SELECT id, integration_id, label, value, connector_id, method_id, active, time_created, time_updated
        FROM src.credential
        "#,
        [],
    )?;
    tx.execute(
        r#"
        UPDATE main.credential SET active = 0
        WHERE id IN (SELECT id FROM src.credential)
          AND integration_id IN (
            SELECT integration_id FROM main.credential
            WHERE active = 1 AND id NOT IN (SELECT id FROM src.credential)
          )
        "#,
        [],
    )?;
    tx.commit()?;

    conn.execute("DETACH DATABASE src", [])?;
    Ok(())
}
