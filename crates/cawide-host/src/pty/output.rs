//! Everything a session has printed: the replay ring plus a headless terminal that tracks the
//! current screen for clients whose position is no longer in the ring.

use std::num::NonZeroU16;

use crate::pty::ring_buffer::{SliceResult, Utf8RingBuffer, DEFAULT_RING_BUFFER_CAPACITY};

pub const SNAPSHOT_SCROLLBACK_LINES: usize = 10_000; // host-side history kept for snapshots
pub const MAX_REPLAY_BYTES: u64 = 2 * 1024 * 1024; // 2 MiB
const SGR_RESET: &[u8] = b"\x1b[0m";
const MAX_TITLE_CHARS: usize = 256;

#[derive(Default)]
struct TermSignals {
    title: Option<String>,
    progress_active: bool,
}

impl vt100::Callbacks for TermSignals {
    fn set_window_title(&mut self, _: &mut vt100::Screen, title: &[u8]) {
        self.title = sanitize_title(title);
    }

    fn unhandled_osc(&mut self, _: &mut vt100::Screen, params: &[&[u8]]) {
        match params {
            [b"0" | b"2", rest @ ..] if !rest.is_empty() => {
                let joined = rest.join(&b";"[..]);
                self.title = sanitize_title(&joined);
            }
            [b"9", b"4", state, ..] => {
                self.progress_active = matches!(*state, b"1" | b"3");
            }
            [b"7501", rest @ ..] if !rest.is_empty() => {
                for part in rest {
                    for item in part.split(|&b| b == b':' || b == b';') {
                        if let Some(eq_idx) = item.iter().position(|&b| b == b'=') {
                            let key = &item[..eq_idx];
                            let val = &item[eq_idx + 1..];
                            if key == b"state" {
                                if val == b"busy" || val == b"running" {
                                    self.progress_active = true;
                                } else if val == b"clear" || val == b"idle" {
                                    self.progress_active = false;
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

fn sanitize_title(raw: &[u8]) -> Option<String> {
    let lossy = String::from_utf8_lossy(raw);
    let filtered: String = lossy.chars().filter(|c| !c.is_control()).collect();
    let trimmed = filtered.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.chars().take(MAX_TITLE_CHARS).collect())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalSignals {
    pub title: Option<String>,
    pub progress_active: bool,
}
#[derive(Debug)]
pub enum AttachStart {
    /// `tail <= requested <= head`: stream `slice` (starts at `requested`) and continue live.
    Replay(SliceResult),
    /// Requested offset unavailable; `offset` is the head at snapshot time.
    Snapshot {
        offset: u64,
        history: Vec<u8>,
        screen: Vec<u8>,
    },
}

pub struct SessionOutput {
    ring: Utf8RingBuffer,
    terminal: vt100::Parser<TermSignals>,
    urls: crate::pty::url_scan::UrlScanner,
}

impl SessionOutput {
    pub fn new(cols: NonZeroU16, rows: NonZeroU16) -> Self {
        Self {
            ring: Utf8RingBuffer::new(DEFAULT_RING_BUFFER_CAPACITY),
            terminal: vt100::Parser::new_with_callbacks(
                rows,
                cols,
                SNAPSHOT_SCROLLBACK_LINES,
                TermSignals::default(),
            ),
            urls: crate::pty::url_scan::UrlScanner::new(),
        }
    }

    pub fn write(&mut self, data: &[u8]) {
        self.ring.write(data);
        self.terminal.process(data);
        self.urls.feed(data);
    }

    pub fn take_detected_urls(&mut self) -> Vec<String> {
        self.urls.take()
    }

    pub fn resize(&mut self, cols: NonZeroU16, rows: NonZeroU16) {
        self.terminal.set_size(rows, cols);
    }

    pub fn signals(&self) -> TerminalSignals {
        TerminalSignals {
            title: self.terminal.callbacks().title.clone(),
            progress_active: self.terminal.callbacks().progress_active,
        }
    }

    pub fn clear_progress(&mut self) {
        self.terminal.callbacks_mut().progress_active = false;
    }
    pub fn read_slice(&self, from_offset: u64) -> SliceResult {
        self.ring.read_slice(from_offset)
    }

    pub fn head_offset(&self) -> u64 {
        self.ring.head_offset()
    }

    pub fn tail_offset(&self) -> u64 {
        self.ring.tail_offset()
    }

    pub fn attach_start(&self, requested: u64) -> AttachStart {
        let head = self.ring.head_offset();
        if requested >= self.ring.tail_offset()
            && requested <= head
            && head - requested <= MAX_REPLAY_BYTES
        {
            AttachStart::Replay(self.ring.read_slice(requested))
        } else {
            let screen = self.terminal.screen();
            AttachStart::Snapshot {
                offset: head,
                history: snapshot_history(screen),
                screen: snapshot_screen(screen),
            }
        }
    }
}

pub const SNAPSHOT_MODE_BASELINE: &[u8] =
    b"\x1b[r\x1b[?6l\x1b[?7h\x1b[4l\x1b[?69l\x1b(B\x0f\x1b[?9l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1005l\x1b[?1006l\x1b[0 q";

fn snapshot_screen(screen: &vt100::Screen) -> Vec<u8> {
    let formatted = screen.state_formatted();
    let buffer: &[u8] = if screen.alternate_screen() {
        b"\x1b[?1049h"
    } else {
        b"\x1b[?1049l"
    };
    let mut bytes =
        Vec::with_capacity(buffer.len() + SNAPSHOT_MODE_BASELINE.len() + formatted.len());
    bytes.extend_from_slice(buffer);
    bytes.extend_from_slice(SNAPSHOT_MODE_BASELINE);
    bytes.extend_from_slice(formatted.as_bytes());
    bytes
}

fn snapshot_history(screen: &vt100::Screen) -> Vec<u8> {
    if screen.alternate_screen() {
        return Vec::new();
    }

    let mut text = String::new();
    let mut state = vt100::capture::BasicFormattedCaptureState::new();
    let _ = screen.write_contents_formatted_basic(
        &mut text,
        vt100::capture::BasicFormattedCaptureRange::Full(&mut state),
    );

    let mut out = Vec::with_capacity(text.len() + 16);
    out.extend_from_slice(SGR_RESET);
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\r' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
                out.extend_from_slice(b"\r\n");
                i += 2;
                continue;
            } else {
                out.push(b'\r');
            }
        } else if b == b'\n' {
            out.extend_from_slice(b"\r\n");
        } else {
            out.push(b);
        }
        i += 1;
    }
    out.extend_from_slice(SGR_RESET);

    let max = cawide_protocol::MAX_SNAPSHOT_PART_BYTES;
    if out.len() > max {
        let budget = max - SGR_RESET.len();
        let min_start = out.len() - budget;
        let start = match out[min_start..].windows(2).position(|w| w == b"\r\n") {
            Some(pos) => min_start + pos + 2,
            None => min_start,
        };
        let mut truncated = Vec::with_capacity(SGR_RESET.len() + (out.len() - start));
        truncated.extend_from_slice(SGR_RESET);
        truncated.extend_from_slice(&out[start..]);
        out = truncated;
    }

    out
}
