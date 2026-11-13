//! Unified diff parsing and hunk hash computation.

use cawide_protocol::types::{DiffHunk, DiffLine, DiffLineKind};
use sha2::{Digest, Sha256};

/// Computes lowercase hex SHA-256 via `sha2::Sha256` of `header` + "\n" +
/// each line as kind char (' ' | '+' | '-') + content + "\n",
/// ignoring `\ No newline at end of file` lines.
pub(crate) fn compute_hunk_hash(header: &str, lines: &[DiffLine]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(b"\n");
    for line in lines {
        if line.content.starts_with(r"\ No newline at end of file")
            || line.content.starts_with('\\')
        {
            continue;
        }
        let kind_char = match line.kind {
            DiffLineKind::Context => b' ',
            DiffLineKind::Addition => b'+',
            DiffLineKind::Deletion => b'-',
        };
        hasher.update([kind_char]);
        hasher.update(line.content.as_bytes());
        hasher.update(b"\n");
    }
    hex::encode(hasher.finalize())
}

/// Unquotes a Git C-style quoted path (`"a\tb\303\251"`); unquoted input is returned as is.
pub(crate) fn unquote_path(raw: &str) -> String {
    let Some(inner) = raw.strip_prefix('"').and_then(|r| r.strip_suffix('"')) else {
        return raw.to_string();
    };
    let mut bytes = Vec::with_capacity(inner.len());
    let mut it = inner.bytes().peekable();
    while let Some(b) = it.next() {
        if b != b'\\' {
            bytes.push(b);
            continue;
        }
        match it.next() {
            Some(b'n') => bytes.push(b'\n'),
            Some(b't') => bytes.push(b'\t'),
            Some(b'r') => bytes.push(b'\r'),
            Some(b'a') => bytes.push(0x07),
            Some(b'b') => bytes.push(0x08),
            Some(b'f') => bytes.push(0x0c),
            Some(b'v') => bytes.push(0x0b),
            Some(d @ b'0'..=b'7') => {
                let mut v = u32::from(d - b'0');
                for _ in 0..2 {
                    match it.peek() {
                        Some(&o @ b'0'..=b'7') => {
                            v = v * 8 + u32::from(o - b'0');
                            it.next();
                        }
                        _ => break,
                    }
                }
                bytes.push(v as u8);
            }
            // `\\` and `\"`, plus any unknown escape, are taken literally.
            Some(other) => bytes.push(other),
            None => bytes.push(b'\\'),
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Path from a `--- a/x` / `+++ b/x` header; `None` for `/dev/null`.
pub(crate) fn header_path(rest: &str) -> Option<String> {
    // Git appends a TAB to paths containing spaces.
    let path = unquote_path(rest.strip_suffix('\t').unwrap_or(rest));
    if path == "/dev/null" {
        return None;
    }
    let path = path
        .strip_prefix("a/")
        .or_else(|| path.strip_prefix("b/"))
        .map(str::to_string)
        .unwrap_or(path);
    Some(path)
}

/// Parses `-a[,b]` / `+c[,d]` hunk ranges; a missing count means 1.
pub(crate) fn parse_range(s: &str) -> Option<(u32, u32)> {
    match s.split_once(',') {
        Some((start, count)) => Some((start.parse().ok()?, count.parse().ok()?)),
        None => Some((s.parse().ok()?, 1)),
    }
}

pub(crate) fn parse_hunk_header(line: &str) -> Option<(u32, u32, u32, u32)> {
    let mut parts = line.strip_prefix("@@ ")?.split(' ');
    let (old_start, old_lines) = parse_range(parts.next()?.strip_prefix('-')?)?;
    let (new_start, new_lines) = parse_range(parts.next()?.strip_prefix('+')?)?;
    Some((old_start, old_lines, new_start, new_lines))
}

/// Parses unified diff text into hunks. Hunk bodies are consumed by line count,
/// so content lines that look like headers (`--- x`) are never misread.
pub fn parse_unified_diff(text: &str) -> Vec<DiffHunk> {
    let mut hunks: Vec<DiffHunk> = Vec::new();
    let mut old_path: Option<String> = None;
    let mut file_path = String::new();
    let (mut old_left, mut new_left) = (0u32, 0u32);

    for line in text.lines() {
        if old_left > 0 || new_left > 0 {
            let (kind, content) = match line.as_bytes().first() {
                Some(b'+') => (DiffLineKind::Addition, &line[1..]),
                Some(b'-') => (DiffLineKind::Deletion, &line[1..]),
                Some(b' ') => (DiffLineKind::Context, &line[1..]),
                Some(b'\\') => continue, // "\ No newline at end of file"
                // Git prefixes every hunk line (blank context is " "), so anything
                // else means a truncated hunk: resynchronize on headers.
                _ => {
                    old_left = 0;
                    new_left = 0;
                    continue;
                }
            };
            match kind {
                DiffLineKind::Addition => new_left = new_left.saturating_sub(1),
                DiffLineKind::Deletion => old_left = old_left.saturating_sub(1),
                DiffLineKind::Context => {
                    old_left = old_left.saturating_sub(1);
                    new_left = new_left.saturating_sub(1);
                }
            }
            if let Some(h) = hunks.last_mut() {
                h.lines.push(DiffLine {
                    kind,
                    content: content.to_string(),
                });
            }
            continue;
        }
        if line.starts_with('\\') {
            continue;
        }
        if line.starts_with("diff --git ") {
            old_path = None;
            file_path.clear();
        } else if let Some(rest) = line.strip_prefix("--- ") {
            old_path = header_path(rest);
        } else if let Some(rest) = line.strip_prefix("+++ ") {
            file_path = header_path(rest)
                .or_else(|| old_path.clone())
                .unwrap_or_default();
        } else if let Some((old_start, old_lines, new_start, new_lines)) = parse_hunk_header(line) {
            old_left = old_lines;
            new_left = new_lines;
            hunks.push(DiffHunk {
                file_path: file_path.clone(),
                old_start,
                old_lines,
                new_start,
                new_lines,
                header: line.to_string(),
                lines: Vec::new(),
                content_hash: String::new(),
            });
        }
    }
    for h in &mut hunks {
        h.content_hash = compute_hunk_hash(&h.header, &h.lines);
    }
    hunks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_diff_handles_header_lookalikes_inside_hunks() {
        let text =
            "diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1,2 +1,2 @@ fn f\n--- old\n+++ new\n ctx\n";
        let hunks = parse_unified_diff(text);
        assert_eq!(hunks.len(), 1);
        let h = &hunks[0];
        assert_eq!(
            (
                h.file_path.as_str(),
                h.old_start,
                h.old_lines,
                h.new_start,
                h.new_lines
            ),
            ("x", 1, 2, 1, 2)
        );
        let kinds: Vec<_> = h
            .lines
            .iter()
            .map(|l| (l.kind.clone(), l.content.as_str()))
            .collect();
        assert_eq!(
            kinds,
            vec![
                (DiffLineKind::Deletion, "-- old"),
                (DiffLineKind::Addition, "++ new"),
                (DiffLineKind::Context, "ctx"),
            ]
        );
    }

    #[test]
    fn parse_diff_deleted_file_uses_old_path_and_quoted_names() {
        let text = "diff --git \"a/\\303\\251 x\" \"b/\\303\\251 x\"\n--- \"a/\\303\\251 x\"\n+++ /dev/null\n@@ -1 +0,0 @@\n-gone\n\\ No newline at end of file\n";
        let hunks = parse_unified_diff(text);
        assert_eq!(hunks.len(), 1);
        assert_eq!(hunks[0].file_path, "é x");
        assert_eq!(
            (hunks[0].old_lines, hunks[0].new_start, hunks[0].new_lines),
            (1, 0, 0)
        );
        assert_eq!(hunks[0].lines.len(), 1);
    }

    #[test]
    fn test_compute_hunk_hash() {
        let header = "@@ -1,2 +1,2 @@";
        let lines = vec![
            DiffLine {
                kind: DiffLineKind::Deletion,
                content: "old line".to_string(),
            },
            DiffLine {
                kind: DiffLineKind::Addition,
                content: "new line".to_string(),
            },
            DiffLine {
                kind: DiffLineKind::Context,
                content: "\\ No newline at end of file".to_string(),
            },
        ];
        let hash = compute_hunk_hash(header, &lines);
        assert_eq!(hash.len(), 64);
        assert!(hash
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));

        let mut expected = Sha256::new();
        expected.update(b"@@ -1,2 +1,2 @@\n-old line\n+new line\n");
        assert_eq!(hash, hex::encode(expected.finalize()));
    }
}

#[cfg(test)]
mod prop {
    use super::*;
    use proptest::collection::vec as prop_vec;
    use proptest::prelude::*;

    #[derive(Debug, Clone)]
    enum SyntheticLineKind {
        Context,
        Addition,
        Deletion,
    }

    #[derive(Debug, Clone)]
    struct SyntheticHunk {
        old_start: u32,
        new_start: u32,
        lines: Vec<(SyntheticLineKind, String)>,
    }

    fn safe_line_content() -> impl Strategy<Value = String> {
        "[a-zA-Z0-9 _-]{0,64}"
    }

    fn arb_synthetic_hunk() -> impl Strategy<Value = SyntheticHunk> {
        let line_strat = (
            prop_oneof![
                Just(SyntheticLineKind::Context),
                Just(SyntheticLineKind::Addition),
                Just(SyntheticLineKind::Deletion),
            ],
            safe_line_content(),
        );

        (
            1u32..=10_000u32,
            1u32..=10_000u32,
            prop_vec(line_strat, 1..=20),
        )
            .prop_map(|(old_start, new_start, lines)| SyntheticHunk {
                old_start,
                new_start,
                lines,
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(50))]

        #[test]
        fn prop_parse_unified_diff_arbitrary_never_panics(s in any::<String>()) {
            let _ = parse_unified_diff(&s);
        }

        #[test]
        fn prop_parse_unified_diff_well_formed_counts(
            hunks in prop_vec(arb_synthetic_hunk(), 1..=5)
        ) {
            let mut diff_text = String::from("diff --git a/test.txt b/test.txt\n--- a/test.txt\n+++ b/test.txt\n");

            struct ExpectedCounts {
                additions: usize,
                deletions: usize,
                contexts: usize,
            }

            let mut expected = Vec::new();

            for hunk in &hunks {
                let mut additions = 0;
                let mut deletions = 0;
                let mut contexts = 0;

                for (kind, _) in &hunk.lines {
                    match kind {
                        SyntheticLineKind::Addition => additions += 1,
                        SyntheticLineKind::Deletion => deletions += 1,
                        SyntheticLineKind::Context => contexts += 1,
                    }
                }

                let old_lines = deletions + contexts;
                let new_lines = additions + contexts;

                diff_text.push_str(&format!(
                    "@@ -{},{} +{},{} @@\n",
                    hunk.old_start, old_lines, hunk.new_start, new_lines
                ));

                for (kind, text) in &hunk.lines {
                    match kind {
                        SyntheticLineKind::Addition => diff_text.push('+'),
                        SyntheticLineKind::Deletion => diff_text.push('-'),
                        SyntheticLineKind::Context => diff_text.push(' '),
                    }
                    diff_text.push_str(text);
                    diff_text.push('\n');
                }

                expected.push(ExpectedCounts {
                    additions,
                    deletions,
                    contexts,
                });
            }

            let parsed = parse_unified_diff(&diff_text);
            prop_assert_eq!(parsed.len(), expected.len());

            for (hunk, exp) in parsed.iter().zip(expected.iter()) {
                let actual_additions = hunk.lines.iter().filter(|l| l.kind == DiffLineKind::Addition).count();
                let actual_deletions = hunk.lines.iter().filter(|l| l.kind == DiffLineKind::Deletion).count();
                let actual_contexts = hunk.lines.iter().filter(|l| l.kind == DiffLineKind::Context).count();

                prop_assert_eq!(actual_additions, exp.additions);
                prop_assert_eq!(actual_deletions, exp.deletions);
                prop_assert_eq!(actual_contexts, exp.contexts);
            }
        }
    }
}
