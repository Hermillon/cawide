use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use rusqlite::{Connection, OpenFlags};
use serde_json::Value;

use super::ObservedEvent;

#[derive(Debug, Default)]
struct DbRootState {
    initialized: bool,
    busy: bool,
}

#[derive(Debug)]
pub struct OpenCodeDbPoller {
    db_path: PathBuf,
    conn: Option<Connection>,
    roots: HashMap<String, DbRootState>,
    last_open_attempt: Option<Instant>,
}

impl OpenCodeDbPoller {
    pub fn new(opencode_data: PathBuf) -> Self {
        Self {
            db_path: opencode_data.join("opencode.db"),
            conn: None,
            roots: HashMap::new(),
            last_open_attempt: None,
        }
    }

    pub fn retain_roots(&mut self, active_roots: &[String]) {
        self.roots
            .retain(|id, _| active_roots.iter().any(|r| r == id));
    }

    pub fn poll_roots(&mut self, root_ids: &[String]) -> Vec<(String, ObservedEvent)> {
        if root_ids.is_empty() {
            return Vec::new();
        }
        if !self.ensure_conn() {
            return Vec::new();
        }
        let Some(conn) = self.conn.as_ref() else {
            return Vec::new();
        };

        let mut out = Vec::new();
        let mut drop_conn = false;

        for root_id in root_ids {
            match poll_single_root(conn, root_id) {
                Ok(Some((is_busy, outcome))) => {
                    let st = self.roots.entry(root_id.clone()).or_default();
                    if !st.initialized {
                        st.initialized = true;
                        st.busy = is_busy;
                        continue;
                    }
                    if !st.busy && is_busy {
                        st.busy = true;
                        out.push((root_id.clone(), ObservedEvent::TurnStarted));
                    } else if st.busy && !is_busy {
                        st.busy = false;
                        if let Some(ev) = build_idle_event(conn, root_id, outcome.as_deref()) {
                            out.push((root_id.clone(), ev));
                        }
                    }
                }
                Ok(None) => {}
                Err(err) => {
                    tracing::debug!("opencode_db poll skipped for {root_id}: {err}");
                    if is_fatal_db_error(&err) {
                        drop_conn = true;
                        break;
                    }
                }
            }
        }

        if drop_conn {
            self.conn = None;
        }
        out
    }

    fn ensure_conn(&mut self) -> bool {
        if self.conn.is_some() {
            return true;
        }
        if !self.db_path.is_file() {
            return false;
        }
        let now = Instant::now();
        if self
            .last_open_attempt
            .is_some_and(|t| now.duration_since(t).as_secs() < 1)
        {
            return false;
        }
        self.last_open_attempt = Some(now);
        match open_readonly_db(&self.db_path) {
            Ok(c) => {
                self.conn = Some(c);
                true
            }
            Err(err) => {
                tracing::debug!("opencode_db open skipped: {err}");
                false
            }
        }
    }
}

fn open_readonly_db(path: &Path) -> rusqlite::Result<Connection> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let _ = conn.busy_timeout(std::time::Duration::from_millis(100));
    Ok(conn)
}

fn is_fatal_db_error(err: &rusqlite::Error) -> bool {
    !matches!(
        err,
        rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error {
                code: rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked,
                ..
            },
            _
        )
    )
}

fn poll_single_root(
    conn: &Connection,
    root_id: &str,
) -> rusqlite::Result<Option<(bool, Option<String>)>> {
    let mut stmt = conn.prepare_cached(
        "SELECT time_busy, time_idle, idle_outcome FROM session_v2 WHERE id = ?1",
    )?;
    let mut rows = stmt.query([root_id])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    let time_busy: Option<i64> = row.get(0)?;
    let time_idle: Option<i64> = row.get(1)?;
    let idle_outcome: Option<String> = row.get(2)?;
    let is_busy = match (time_busy, time_idle) {
        (Some(_), None) => true,
        (Some(b), Some(i)) => b > i,
        _ => false,
    };
    Ok(Some((is_busy, idle_outcome)))
}

fn build_idle_event(
    conn: &Connection,
    root_id: &str,
    outcome: Option<&str>,
) -> Option<ObservedEvent> {
    match outcome {
        Some("succeeded") => {
            let summary = query_last_assistant_text(conn, root_id).unwrap_or_default();
            Some(ObservedEvent::TurnCompleted { summary })
        }
        Some("failed") => {
            let error = query_last_idle_error(conn, root_id)
                .unwrap_or_else(|| "OpenCode run failed".to_string());
            Some(ObservedEvent::TurnFailed { error })
        }
        Some("interrupted") => Some(ObservedEvent::TurnInterrupted),
        _ => {
            let summary = query_last_assistant_text(conn, root_id).unwrap_or_default();
            Some(ObservedEvent::TurnCompleted { summary })
        }
    }
}

fn query_last_assistant_text(conn: &Connection, root_id: &str) -> Option<String> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT data FROM session_message WHERE session_id = ?1 AND type = 'assistant' ORDER BY seq DESC LIMIT 1",
        )
        .ok()?;
    let raw: String = stmt.query_row([root_id], |row| row.get(0)).ok()?;
    let val: Value = serde_json::from_str(&raw).ok()?;
    let content = val.get("content")?.as_array()?;
    let mut joined = String::new();
    for part in content {
        if part.get("type").and_then(|v| v.as_str()) == Some("text") {
            if let Some(txt) = part.get("text").and_then(|v| v.as_str()) {
                if !txt.is_empty() {
                    if !joined.is_empty() {
                        joined.push('\n');
                    }
                    joined.push_str(txt);
                }
            }
        }
    }
    Some(joined)
}

fn query_last_idle_error(conn: &Connection, root_id: &str) -> Option<String> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT data FROM session_message WHERE session_id = ?1 AND type = 'idle' ORDER BY seq DESC LIMIT 1",
        )
        .ok()?;
    let raw: String = stmt.query_row([root_id], |row| row.get(0)).ok()?;
    let val: Value = serde_json::from_str(&raw).ok()?;
    val.get("error")
        .and_then(|e| e.get("message"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn setup_test_db(path: &Path) -> Connection {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(
            "CREATE TABLE session_v2 (
                id TEXT PRIMARY KEY,
                time_busy INTEGER,
                time_idle INTEGER,
                idle_outcome TEXT
            );
            CREATE TABLE session_message (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                type TEXT NOT NULL,
                seq INTEGER NOT NULL,
                data TEXT NOT NULL
            );",
        )
        .unwrap();
        conn
    }

    #[test]
    fn test_opencode_db_baseline_and_edges() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().to_path_buf();
        let db_path = data_dir.join("opencode.db");
        let writer = setup_test_db(&db_path);

        let sid = "ses_test1";
        writer
            .execute(
                "INSERT INTO session_v2 (id, time_busy, time_idle, idle_outcome) VALUES (?1, 100, NULL, NULL)",
                [sid],
            )
            .unwrap();

        let mut poller = OpenCodeDbPoller::new(data_dir);
        let roots = vec![sid.to_string()];

        // First observation is baseline (already busy -> emits nothing).
        assert!(poller.poll_roots(&roots).is_empty());

        // Transition to idle succeeded.
        writer
            .execute(
                "INSERT INTO session_message (id, session_id, type, seq, data) VALUES ('m1', ?1, 'assistant', 1, ?2)",
                [
                    sid,
                    &json!({
                        "content": [
                            { "type": "reasoning", "text": "thinking" },
                            { "type": "text", "text": "First part" },
                            { "type": "text", "text": "Second part" }
                        ]
                    })
                    .to_string(),
                ],
            )
            .unwrap();
        writer
            .execute(
                "UPDATE session_v2 SET time_idle = 200, idle_outcome = 'succeeded' WHERE id = ?1",
                [sid],
            )
            .unwrap();

        assert_eq!(
            poller.poll_roots(&roots),
            vec![(
                sid.to_string(),
                ObservedEvent::TurnCompleted {
                    summary: "First part\nSecond part".into()
                }
            )]
        );

        // Transition to busy -> TurnStarted.
        writer
            .execute("UPDATE session_v2 SET time_busy = 300 WHERE id = ?1", [sid])
            .unwrap();
        assert_eq!(
            poller.poll_roots(&roots),
            vec![(sid.to_string(), ObservedEvent::TurnStarted)]
        );

        // Transition to idle failed.
        writer
            .execute(
                "INSERT INTO session_message (id, session_id, type, seq, data) VALUES ('m2', ?1, 'idle', 2, ?2)",
                [
                    sid,
                    &json!({
                        "outcome": "failed",
                        "error": { "message": "Rate limit exceeded" }
                    })
                    .to_string(),
                ],
            )
            .unwrap();
        writer
            .execute(
                "UPDATE session_v2 SET time_idle = 400, idle_outcome = 'failed' WHERE id = ?1",
                [sid],
            )
            .unwrap();
        assert_eq!(
            poller.poll_roots(&roots),
            vec![(
                sid.to_string(),
                ObservedEvent::TurnFailed {
                    error: "Rate limit exceeded".into()
                }
            )]
        );

        // Transition to busy then interrupted.
        writer
            .execute("UPDATE session_v2 SET time_busy = 500 WHERE id = ?1", [sid])
            .unwrap();
        assert_eq!(
            poller.poll_roots(&roots),
            vec![(sid.to_string(), ObservedEvent::TurnStarted)]
        );
        writer
            .execute(
                "UPDATE session_v2 SET time_idle = 600, idle_outcome = 'interrupted' WHERE id = ?1",
                [sid],
            )
            .unwrap();
        assert_eq!(
            poller.poll_roots(&roots),
            vec![(sid.to_string(), ObservedEvent::TurnInterrupted)]
        );
    }

    #[test]
    fn test_opencode_db_missing_file_skips_cleanly() {
        let tmp = tempfile::tempdir().unwrap();
        let mut poller = OpenCodeDbPoller::new(tmp.path().to_path_buf());
        assert!(poller.poll_roots(&["ses_missing".to_string()]).is_empty());
    }
}
