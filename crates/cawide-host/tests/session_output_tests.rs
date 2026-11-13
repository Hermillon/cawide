use std::num::NonZeroU16;

use cawide_host::pty::{AttachStart, SessionOutput, TerminalSignals};
use cawide_protocol::MAX_SNAPSHOT_PART_BYTES;

fn nz(v: u16) -> NonZeroU16 {
    NonZeroU16::new(v).expect("non-zero value expected")
}

#[test]
fn test_replay() {
    let mut output = SessionOutput::new(nz(80), nz(24));
    output.write(b"hello");
    match output.attach_start(0) {
        AttachStart::Replay(slice) => {
            assert_eq!(slice.data, b"hello");
            assert_eq!(slice.start_offset, 0);
            assert_eq!(slice.end_offset, 5);
        }
        AttachStart::Snapshot { .. } => panic!("expected replay"),
    }
}

#[test]
fn test_alt_screen_snapshot() {
    let mut output = SessionOutput::new(nz(80), nz(24));
    let mut source = vt100::Parser::new(nz(24), nz(80), 0);

    let prefix = b"\x1b[?1049h\x1b[HTUI-HEADER\r\n";
    output.write(prefix);
    source.process(prefix);

    // Write > 4 MiB (e.g. 5 MiB) to force underrun of offset 0
    let frame = b"\x1b[2;1H\x1b[2Kcount 12345";
    let iterations = (5 * 1024 * 1024) / frame.len() + 1;
    for _ in 0..iterations {
        output.write(frame);
        source.process(frame);
    }

    let last = b"\x1b[2;1H\x1b[2KLAST";
    output.write(last);
    source.process(last);

    let head = output.head_offset();
    match output.attach_start(0) {
        AttachStart::Snapshot {
            offset,
            history,
            screen,
        } => {
            assert_eq!(offset, head);
            assert!(history.is_empty(), "history must be empty in alt-screen");
            assert!(
                screen.starts_with(b"\x1b[?1049h"),
                "screen must start with alt-screen switch"
            );

            let mut replica = vt100::Parser::new(nz(24), nz(80), 0);
            replica.process(&screen);

            assert!(replica.screen().alternate_screen());
            let contents = replica.screen().contents();
            assert!(contents.contains("TUI-HEADER"));
            assert!(contents.contains("LAST"));
            assert!(!contents.contains("count"));
            assert_eq!(
                replica.screen().cursor_position(),
                source.screen().cursor_position()
            );
        }
        AttachStart::Replay(_) => panic!("expected snapshot on underrun"),
    }
}

#[test]
fn test_past_the_head() {
    let mut output = SessionOutput::new(nz(80), nz(24));
    output.write(b"content");
    let head = output.head_offset();
    match output.attach_start(head + 10) {
        AttachStart::Snapshot { offset, .. } => {
            assert_eq!(offset, head);
        }
        AttachStart::Replay(_) => panic!("expected snapshot when offset > head"),
    }
}

#[test]
fn test_primary_screen_history() {
    let mut output = SessionOutput::new(nz(80), nz(24));
    let mut source = vt100::Parser::new(nz(24), nz(80), 1_000);

    for i in 0..300 {
        let line = format!("line-{:04}\r\n", i);
        output.write(line.as_bytes());
        source.process(line.as_bytes());
    }

    // Write > 4 MiB to push offset 0 out of ring buffer
    let overwrite = b"\x1b[1;1H\x1b[2Kx";
    let iterations = (5 * 1024 * 1024) / overwrite.len() + 1;
    for _ in 0..iterations {
        output.write(overwrite);
        source.process(overwrite);
    }

    match output.attach_start(0) {
        AttachStart::Snapshot {
            history, screen, ..
        } => {
            let hist_str = String::from_utf8_lossy(&history);
            let pos_0 = hist_str.find("line-0000").expect("line-0000 not found");
            let pos_299 = hist_str.find("line-0299").expect("line-0299 not found");
            assert!(pos_0 < pos_299);
            assert!(history.windows(2).any(|w| w == b"\r\n"));
            let expected_prefix =
                [b"\x1b[?1049l", cawide_host::pty::SNAPSHOT_MODE_BASELINE].concat();
            assert!(screen.starts_with(&expected_prefix));

            let mut replica = vt100::Parser::new(nz(24), nz(80), 1_000);
            replica.process(&history);
            replica.process(&screen);

            assert_eq!(
                replica.screen().scrollback_len(),
                source.screen().scrollback_len()
            );
            assert_eq!(replica.screen().scrollback_len(), 277);

            let mut source_cap = String::new();
            let mut source_state = vt100::capture::BasicFormattedCaptureState::new();
            let _ = source.screen().write_contents_formatted_basic(
                &mut source_cap,
                vt100::capture::BasicFormattedCaptureRange::Full(&mut source_state),
            );

            let mut replica_cap = String::new();
            let mut replica_state = vt100::capture::BasicFormattedCaptureState::new();
            let _ = replica.screen().write_contents_formatted_basic(
                &mut replica_cap,
                vt100::capture::BasicFormattedCaptureRange::Full(&mut replica_state),
            );

            assert_eq!(replica_cap, source_cap);
            assert_eq!(replica.screen().contents(), source.screen().contents());
        }
        AttachStart::Replay(_) => panic!("expected snapshot on underrun"),
    }
}

#[test]
fn test_resize() {
    let mut output = SessionOutput::new(nz(80), nz(24));
    output.resize(nz(100), nz(30));
    output.write(b"\x1b[30;91HEDGE");

    let head = output.head_offset();
    match output.attach_start(head + 1) {
        AttachStart::Snapshot { screen, .. } => {
            let mut replica = vt100::Parser::new(nz(30), nz(100), 0);
            replica.process(&screen);
            let cell = replica.screen().cell(29, 90).expect("cell 29,90 exists");
            assert_eq!(cell.contents(), "E");
        }
        AttachStart::Replay(_) => panic!("expected snapshot"),
    }
}

#[test]
fn test_max_replay_bound() {
    let mut output = SessionOutput::new(nz(80), nz(24));
    let total_bytes = (cawide_host::pty::MAX_REPLAY_BYTES + 1) as usize;
    let chunk = vec![b'a'; total_bytes];
    output.write(&chunk);

    assert_eq!(output.tail_offset(), 0);
    let head = output.head_offset();
    assert_eq!(head, cawide_host::pty::MAX_REPLAY_BYTES + 1);

    // Exact boundary check:
    // requested = 1: gap = head - 1 = MAX_REPLAY_BYTES -> AttachStart::Replay
    match output.attach_start(1) {
        AttachStart::Replay(slice) => {
            assert_eq!(slice.start_offset, 1);
            assert_eq!(slice.end_offset, head);
            assert_eq!(
                slice.data.len(),
                cawide_host::pty::MAX_REPLAY_BYTES as usize
            );
        }
        AttachStart::Snapshot { .. } => {
            panic!("expected replay at exact MAX_REPLAY_BYTES bound")
        }
    }

    // requested = 0: gap = head - 0 = MAX_REPLAY_BYTES + 1 -> AttachStart::Snapshot
    match output.attach_start(0) {
        AttachStart::Snapshot { offset, .. } => {
            assert_eq!(offset, head);
        }
        AttachStart::Replay(_) => panic!("expected snapshot when exceeding MAX_REPLAY_BYTES"),
    }
}

#[test]
fn test_terminal_signals() {
    let mut output = SessionOutput::new(nz(80), nz(24));
    assert_eq!(
        output.signals(),
        TerminalSignals {
            title: None,
            progress_active: false,
        }
    );

    // OSC 0 BEL title -> Some("hello")
    output.write(b"\x1b]0;hello\x07");
    assert_eq!(output.signals().title.as_deref(), Some("hello"));

    // OSC 2 ST title (\e]2;x\e\) -> Some("x")
    output.write(b"\x1b]2;x\x1b\\");
    assert_eq!(output.signals().title.as_deref(), Some("x"));

    // \e]0;a;b\a -> Some("a;b")
    output.write(b"\x1b]0;a;b\x07");
    assert_eq!(output.signals().title.as_deref(), Some("a;b"));

    // title with \t and control chars stripped
    output.write(b"\x1b]0;foo\tbar\x01baz\x07");
    assert_eq!(output.signals().title.as_deref(), Some("foobarbaz"));

    // whitespace-only title -> None
    output.write(b"\x1b]0;   \x07");
    assert_eq!(output.signals().title, None);

    // a title split across two write calls still parses
    output.write(b"\x1b]0;spl");
    output.write(b"it\x07");
    assert_eq!(output.signals().title.as_deref(), Some("split"));

    // \e]9;4;3\a -> active and still active after further plain output with no repeat
    output.write(b"\x1b]9;4;3\x07");
    assert!(output.signals().progress_active);
    output.write(b"plain terminal output without any progress update");
    assert!(output.signals().progress_active);

    // then \e]9;4;0;\a -> inactive
    output.write(b"\x1b]9;4;0;\x07");
    assert!(!output.signals().progress_active);

    // \e]9;4;1;50\a -> active
    output.write(b"\x1b]9;4;1;50\x07");
    assert!(output.signals().progress_active);

    // \e]9;4;2\a -> inactive
    output.write(b"\x1b]9;4;2\x07");
    assert!(!output.signals().progress_active);

    // active then clear_progress() -> inactive
    output.write(b"\x1b]9;4;3\x07");
    assert!(output.signals().progress_active);
    output.clear_progress();
    assert!(!output.signals().progress_active);

    // OSC 7501 state=busy:app=claude
    output.write(b"\x1b]7501;state=busy:app=claude\x1b\\");
    assert!(output.signals().progress_active);

    // OSC 7501 state=idle:app=claude
    output.write(b"\x1b]7501;state=idle:app=claude\x1b\\");
    assert!(!output.signals().progress_active);

    // OSC 7501 state=running
    output.write(b"\x1b]7501;state=running\x1b\\");
    assert!(output.signals().progress_active);

    // OSC 7501 state=clear
    output.write(b"\x1b]7501;state=clear\x1b\\");
    assert!(!output.signals().progress_active);
}

#[test]
fn snapshot_history_keeps_ten_thousand_lines() {
    let mut output = SessionOutput::new(nz(80), nz(24));
    for i in 0..12_000 {
        output.write(format!("line-{:05}\r\n", i).as_bytes());
    }
    let start = output.attach_start(output.head_offset() + 10);
    let history = match start {
        AttachStart::Snapshot { history, .. } => history,
        other => panic!("expected snapshot, got {:?}", other),
    };
    let lossy = String::from_utf8_lossy(&history);
    assert!(lossy.contains("line-01977"), "should contain line-01977");
    assert!(
        !lossy.contains("line-01976"),
        "should not contain line-01976"
    );
    assert!(lossy.contains("line-11999"), "should contain line-11999");
}

#[test]
fn snapshot_history_fallback_truncation_is_exactly_part_ceiling() {
    let mut output = SessionOutput::new(nz(80), nz(24));
    // Write 900,000 cells alternating "\x1b[31mX" and "\x1b[32mY" with no \r or \n, in chunks of 64 KiB.
    let mut payload = Vec::with_capacity(900_000 * 6);
    for i in 0..900_000 {
        if i % 2 == 0 {
            payload.extend_from_slice(b"\x1b[31mX");
        } else {
            payload.extend_from_slice(b"\x1b[32mY");
        }
    }
    for chunk in payload.chunks(64 * 1024) {
        output.write(chunk);
    }
    output.write(b"TAIL-MARKER");

    let start = output.attach_start(output.head_offset() + 10);
    let history = match start {
        AttachStart::Snapshot { history, .. } => history,
        other => panic!("expected snapshot, got {:?}", other),
    };
    let lossy = String::from_utf8_lossy(&history);
    assert_eq!(history.len(), MAX_SNAPSHOT_PART_BYTES);
    assert!(history.starts_with(b"\x1b[0m"));
    assert!(lossy.contains("TAIL-MARKER"));
}

#[test]
fn snapshot_history_crlf_truncation_stays_within_part_ceiling() {
    let mut output = SessionOutput::new(nz(80), nz(24));
    // Write 10_100 lines: each 79 cells alternating "\x1b[31mX"/"\x1b[32mY", followed by "\x1b[0m\r\n".
    let mut line = Vec::with_capacity(79 * 6 + 7);
    for i in 0..79 {
        if i % 2 == 0 {
            line.extend_from_slice(b"\x1b[31mX");
        } else {
            line.extend_from_slice(b"\x1b[32mY");
        }
    }
    line.extend_from_slice(b"\x1b[0m\r\n");

    for _ in 0..10_100 {
        output.write(&line);
    }
    output.write(b"TAIL-MARKER\r\n");

    let start = output.attach_start(output.head_offset() + 10);
    let history = match start {
        AttachStart::Snapshot { history, .. } => history,
        other => panic!("expected snapshot, got {:?}", other),
    };
    let lossy = String::from_utf8_lossy(&history);
    assert!(history.len() <= MAX_SNAPSHOT_PART_BYTES);
    assert!(history.starts_with(b"\x1b[0m"));
    assert!(lossy.contains("TAIL-MARKER"));
}
