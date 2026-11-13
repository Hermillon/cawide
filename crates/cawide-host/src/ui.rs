//! Aesthetic Terminal UI Module for Cawide.
//!
//! Provides styled wordmark banners, pairing screens, and status cards
//! with clean Unicode rounded borders and ANSI color support.

use std::borrow::Cow;
use std::io::IsTerminal;
use std::path::Path;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const TAGLINE: &str = "Remote Vibe Coding";

/// Official 6-line CAWIDE block text wordmark.
pub const BANNER_LINES: [&str; 6] = [
    r" ██████╗ █████╗ ██╗    ██╗██╗██████╗ ███████╗",
    r"██╔════╝██╔══██╗██║    ██║██║██╔══██╗██╔════╝",
    r"██║     ███████║██║ █╗ ██║██║██║  ██║█████╗  ",
    r"██║     ██╔══██║██║███╗██║██║██║  ██║██╔══╝  ",
    r"╚██████╗██║  ██║╚███╔███╔╝██║██████╔╝███████╗",
    r" ╚═════╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝╚═════╝ ╚══════╝",
];

/// Returns the detected number of terminal columns, falling back to 80.
#[cfg(unix)]
pub fn terminal_columns() -> usize {
    let mut ws = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: STDOUT_FILENO is a valid file descriptor; ws is a valid winsize pointer.
    let ret = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) };
    if ret == 0 && ws.ws_col > 0 {
        ws.ws_col as usize
    } else {
        80
    }
}

#[cfg(windows)]
pub fn terminal_columns() -> usize {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::System::Console::{
        GetConsoleScreenBufferInfo, GetStdHandle, CONSOLE_SCREEN_BUFFER_INFO, STD_OUTPUT_HANDLE,
    };

    // SAFETY: STD_OUTPUT_HANDLE is a valid handle identifier and csbi is a zero-initialized buffer.
    unsafe {
        let handle = GetStdHandle(STD_OUTPUT_HANDLE);
        if handle == 0 || handle == INVALID_HANDLE_VALUE {
            return 80;
        }
        let mut csbi: CONSOLE_SCREEN_BUFFER_INFO = std::mem::zeroed();
        if GetConsoleScreenBufferInfo(handle, &mut csbi) != 0 {
            let width = csbi.srWindow.Right - csbi.srWindow.Left + 1;
            if width > 0 {
                return width as usize;
            }
        }
        80
    }
}

#[cfg(not(any(unix, windows)))]
pub fn terminal_columns() -> usize {
    80
}

/// Returns true if color output is enabled (NO_COLOR is unset and stdout is a terminal).
pub fn is_color_enabled() -> bool {
    std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal()
}

// -----------------------------------------------------------------------------
// Style Helpers
// -----------------------------------------------------------------------------

struct Style {
    color: bool,
}

impl Style {
    fn new(color: bool) -> Self {
        Self { color }
    }

    fn cyan<'a>(&self, text: &'a str) -> Cow<'a, str> {
        if self.color {
            Cow::Owned(format!("\x1b[36m{text}\x1b[0m"))
        } else {
            Cow::Borrowed(text)
        }
    }

    fn bold_cyan<'a>(&self, text: &'a str) -> Cow<'a, str> {
        if self.color {
            Cow::Owned(format!("\x1b[1;36m{text}\x1b[0m"))
        } else {
            Cow::Borrowed(text)
        }
    }

    fn bold<'a>(&self, text: &'a str) -> Cow<'a, str> {
        if self.color {
            Cow::Owned(format!("\x1b[1m{text}\x1b[0m"))
        } else {
            Cow::Borrowed(text)
        }
    }

    fn dim<'a>(&self, text: &'a str) -> Cow<'a, str> {
        if self.color {
            Cow::Owned(format!("\x1b[2m{text}\x1b[0m"))
        } else {
            Cow::Borrowed(text)
        }
    }

    fn green<'a>(&self, text: &'a str) -> Cow<'a, str> {
        if self.color {
            Cow::Owned(format!("\x1b[32m{text}\x1b[0m"))
        } else {
            Cow::Borrowed(text)
        }
    }
}

// -----------------------------------------------------------------------------
// Wordmark Banner
// -----------------------------------------------------------------------------

/// Renders the clean CAWIDE wordmark banner inside an elegant Unicode rounded box.
pub fn render_banner() -> String {
    render_banner_with(is_color_enabled())
}

/// Renders the banner with explicit color configuration.
pub fn render_banner_with(color: bool) -> String {
    let s = Style::new(color);
    let inner_width = 49usize;
    let version_str = format!("v{VERSION}");

    // Top border: ╭─ v0.8.0 ─────────────────── Remote Vibe Coding ─╮
    // Total width = 51 chars (inner_width + 2)
    let left_prefix = format!("╭─ {version_str} ");
    let right_suffix = format!(" {TAGLINE} ─╮");
    let left_len = left_prefix.chars().count();
    let right_len = right_suffix.chars().count();
    let dashes = (inner_width + 2).saturating_sub(left_len + right_len);

    let top_border = if color {
        format!(
            "{}{}{}{}{}",
            s.dim("╭─ "),
            s.cyan(&version_str),
            s.dim(&"─".repeat(dashes)),
            s.cyan(TAGLINE),
            s.dim(" ─╮")
        )
    } else {
        format!("{left_prefix}{}{right_suffix}", "─".repeat(dashes))
    };

    let bottom_border = if color {
        s.dim(&format!("╰{}╯", "─".repeat(inner_width)))
            .into_owned()
    } else {
        format!("╰{}╯", "─".repeat(inner_width))
    };

    let empty_line = if color {
        format!("{}{}{}", s.dim("│"), " ".repeat(inner_width), s.dim("│"))
    } else {
        format!("│{}│", " ".repeat(inner_width))
    };

    let mut out = String::new();
    out.push_str(&top_border);
    out.push('\n');
    out.push_str(&empty_line);
    out.push('\n');

    for line in BANNER_LINES {
        let line_len = line.chars().count();
        let pad_right = inner_width.saturating_sub(2 + line_len);
        if color {
            out.push_str(&format!(
                "{}{}{}{}{}\n",
                s.dim("│"),
                "  ",
                s.bold_cyan(line),
                " ".repeat(pad_right),
                s.dim("│")
            ));
        } else {
            out.push_str(&format!("│  {line}{}│\n", " ".repeat(pad_right)));
        }
    }

    out.push_str(&empty_line);
    out.push('\n');
    out.push_str(&bottom_border);
    out
}

// -----------------------------------------------------------------------------
// Pairing Screen
// -----------------------------------------------------------------------------

/// Renders the complete pairing screen, including banner, status line,
/// compact Unicode pairing card with QR code and metadata, clickable pairing URI,
/// and helpful tips.
pub fn render_pairing_screen(
    ticket_uri: &str,
    qr_text: &str,
    expires_in_secs: u64,
    node_id: &str,
    pid: Option<u32>,
) -> String {
    render_pairing_screen_with(
        ticket_uri,
        qr_text,
        expires_in_secs,
        node_id,
        pid,
        is_color_enabled(),
        terminal_columns(),
    )
}

/// Renders the pairing screen with explicit color and column configurations.
pub fn render_pairing_screen_with(
    ticket_uri: &str,
    qr_text: &str,
    expires_in_secs: u64,
    node_id: &str,
    pid: Option<u32>,
    color: bool,
    cols: usize,
) -> String {
    let s = Style::new(color);
    let mut out = String::new();

    // 1. Wordmark banner
    out.push_str(&render_banner_with(color));
    out.push('\n');
    out.push('\n');

    // 2. Status lines
    let daemon_line = match pid {
        Some(p) => format!(
            "{} {} {}",
            s.green("✔"),
            s.bold("Cawide daemon started in background"),
            s.dim(&format!("(PID: {p})"))
        ),
        None => format!("{} {}", s.green("✔"), s.bold("Cawide daemon active")),
    };
    out.push_str(&daemon_line);
    out.push('\n');

    let status_line = format!(
        "{} {}{}",
        s.green("●"),
        s.bold("Status: "),
        "Ready for pairing"
    );
    out.push_str(&status_line);
    out.push('\n');
    out.push('\n');

    // Metadata lines
    let short_node_id = if node_id.len() > 16 {
        format!("{}...{}", &node_id[..8], &node_id[node_id.len() - 8..])
    } else {
        node_id.to_string()
    };
    let minutes = expires_in_secs / 60;
    let time_str = if minutes == 1 {
        "1 minute".to_string()
    } else if minutes > 1 {
        format!("{minutes} minutes")
    } else {
        format!("{expires_in_secs} seconds")
    };

    let meta_items = [
        "Scan with Cawide on iOS",
        "",
        "● Status: Ready for pairing",
        &format!("Valid for: {time_str}"),
        &format!("Node ID:   {short_node_id}"),
        "Relay:     direct + n0 fallback",
        "",
        "1. Open Cawide app on iOS",
        "2. Tap Scan QR Code to connect",
    ];

    let qr_lines: Vec<&str> = qr_text.lines().collect();
    let qr_width = qr_lines
        .iter()
        .map(|l| l.chars().count())
        .max()
        .unwrap_or(0);

    let left_width = qr_width.max(39);
    let right_width = 34usize;
    let needed_side_by_side = left_width + right_width + 3;

    // 3. Pairing card: side-by-side only if terminal is wide enough, stacked otherwise
    if cols >= needed_side_by_side {
        // Top border
        let left_title = "╭─ Pairing ";
        let left_title_len = left_title.chars().count();
        let left_dashes = (left_width + 1).saturating_sub(left_title_len);

        let right_title = "─ Details ";
        let right_title_len = right_title.chars().count();
        let right_dashes = right_width.saturating_sub(right_title_len);

        let top_border = if color {
            format!(
                "{}{}{}{}{}{}",
                s.dim(left_title),
                s.dim(&"─".repeat(left_dashes)),
                s.dim("┬"),
                s.dim(right_title),
                s.dim(&"─".repeat(right_dashes)),
                s.dim("╮")
            )
        } else {
            format!(
                "{left_title}{}┬{right_title}{}╮",
                "─".repeat(left_dashes),
                "─".repeat(right_dashes)
            )
        };
        out.push_str(&top_border);
        out.push('\n');

        let total_rows = qr_lines.len().max(meta_items.len());
        let meta_offset = if total_rows > meta_items.len() {
            (total_rows - meta_items.len()) / 2
        } else {
            0
        };

        for r in 0..total_rows {
            let left_text = if r < qr_lines.len() { qr_lines[r] } else { "" };
            let left_pad = left_width.saturating_sub(left_text.chars().count());

            let right_text = if r >= meta_offset && (r - meta_offset) < meta_items.len() {
                meta_items[r - meta_offset]
            } else {
                ""
            };
            let right_pad = right_width.saturating_sub(1 + right_text.chars().count());

            if color {
                out.push_str(&format!(
                    "{}{}{}{} {}{}{}\n",
                    s.dim("│"),
                    left_text,
                    " ".repeat(left_pad),
                    s.dim("│"),
                    right_text,
                    " ".repeat(right_pad),
                    s.dim("│")
                ));
            } else {
                out.push_str(&format!(
                    "│{}{}{left_pad_spaces}│ {}{right_pad_spaces}│\n",
                    left_text,
                    "",
                    right_text,
                    left_pad_spaces = " ".repeat(left_pad),
                    right_pad_spaces = " ".repeat(right_pad)
                ));
            }
        }

        // Bottom border
        let bottom_border = if color {
            format!(
                "{}{}{}{}{}",
                s.dim("╰"),
                s.dim(&"─".repeat(left_width)),
                s.dim("┴"),
                s.dim(&"─".repeat(right_width)),
                s.dim("╯")
            )
        } else {
            format!("╰{}┴{}╯", "─".repeat(left_width), "─".repeat(right_width))
        };
        out.push_str(&bottom_border);
        out.push('\n');
    } else {
        // Stacked layout (< 76 columns)
        let box_width = qr_width.max(36);

        // Top border
        let top_title = "╭─ Pairing QR ";
        let top_dashes = (box_width + 1).saturating_sub(top_title.chars().count());
        let top_border = if color {
            format!(
                "{}{}{}",
                s.dim(top_title),
                s.dim(&"─".repeat(top_dashes)),
                s.dim("╮")
            )
        } else {
            format!("{top_title}{}╮", "─".repeat(top_dashes))
        };
        out.push_str(&top_border);
        out.push('\n');

        for qr_line in qr_lines {
            let pad = box_width.saturating_sub(qr_line.chars().count());
            if color {
                out.push_str(&format!(
                    "{}{}{}{}\n",
                    s.dim("│"),
                    qr_line,
                    " ".repeat(pad),
                    s.dim("│")
                ));
            } else {
                out.push_str(&format!("│{qr_line}{}│\n", " ".repeat(pad)));
            }
        }

        // Section divider
        let div_title = "├─ Details ";
        let div_dashes = (box_width + 1).saturating_sub(div_title.chars().count());
        let divider = if color {
            format!(
                "{}{}{}",
                s.dim(div_title),
                s.dim(&"─".repeat(div_dashes)),
                s.dim("┤")
            )
        } else {
            format!("{div_title}{}┤", "─".repeat(div_dashes))
        };
        out.push_str(&divider);
        out.push('\n');

        for item in meta_items {
            let item_len = item.chars().count();
            let pad = box_width.saturating_sub(1 + item_len);
            if color {
                out.push_str(&format!(
                    "{} {}{}{}\n",
                    s.dim("│"),
                    item,
                    " ".repeat(pad),
                    s.dim("│")
                ));
            } else {
                out.push_str(&format!("│ {item}{}│\n", " ".repeat(pad)));
            }
        }

        let bottom_border = if color {
            format!(
                "{}{}{}",
                s.dim("╰"),
                s.dim(&"─".repeat(box_width)),
                s.dim("╯")
            )
        } else {
            format!("╰{}╯", "─".repeat(box_width))
        };
        out.push_str(&bottom_border);
        out.push('\n');
    }

    // 4. CRITICAL: Unindented pairing URI on its own line below the card
    out.push('\n');
    out.push_str(ticket_uri);
    out.push('\n');
    out.push('\n');

    // 5. Tips section
    out.push_str("💡 Tips:\n");
    out.push_str("   • Terminal is ready for your commands!\n");
    out.push_str("   • Run 'cawide status' to inspect active connections.\n");
    out.push_str("   • Run 'cawide pair' anytime for a new QR code.\n");
    out.push_str("   • Run 'cawide quit' to stop the daemon.\n");

    out
}

// -----------------------------------------------------------------------------
// Status Card
// -----------------------------------------------------------------------------

/// Renders a clean status card showing daemon activity, connection status,
/// authorized keys, log path, and quick commands.
pub fn render_status_card(
    node_id: &str,
    pid: Option<u32>,
    sessions: usize,
    active_conn: bool,
    authorized_keys: usize,
    pairing_active: bool,
    log_path: &Path,
) -> String {
    render_status_card_with(
        node_id,
        pid,
        sessions,
        active_conn,
        authorized_keys,
        pairing_active,
        log_path,
        is_color_enabled(),
        terminal_columns(),
    )
}

/// Renders the status card with explicit color and column configurations.
#[allow(clippy::too_many_arguments)]
pub fn render_status_card_with(
    node_id: &str,
    pid: Option<u32>,
    sessions: usize,
    active_conn: bool,
    authorized_keys: usize,
    pairing_active: bool,
    log_path: &Path,
    color: bool,
    cols: usize,
) -> String {
    let s = Style::new(color);
    let mut out = String::new();

    let box_width = if cols >= 76 {
        68usize
    } else {
        cols.saturating_sub(4).max(46)
    };

    // Header
    let top_title = "╭─ Cawide Status ";
    let top_dashes = (box_width + 1).saturating_sub(top_title.chars().count());
    let top_border = if color {
        format!(
            "{}{}{}",
            s.dim(top_title),
            s.dim(&"─".repeat(top_dashes)),
            s.dim("╮")
        )
    } else {
        format!("{top_title}{}╮", "─".repeat(top_dashes))
    };
    out.push_str(&top_border);
    out.push('\n');

    let active_banner = "● CAWIDE DAEMON ACTIVE";
    let active_banner_styled = if color {
        format!("{} {}", s.green("●"), s.bold("CAWIDE DAEMON ACTIVE"))
    } else {
        active_banner.to_string()
    };
    let active_banner_pad = box_width.saturating_sub(2 + active_banner.chars().count());

    if color {
        out.push_str(&format!(
            "{}  {}{}{}\n",
            s.dim("│"),
            active_banner_styled,
            " ".repeat(active_banner_pad),
            s.dim("│")
        ));
    } else {
        out.push_str(&format!(
            "│  {active_banner}{}│\n",
            " ".repeat(active_banner_pad)
        ));
    }

    // Blank separator
    if color {
        out.push_str(&format!(
            "{}{}{}\n",
            s.dim("│"),
            " ".repeat(box_width),
            s.dim("│")
        ));
    } else {
        out.push_str(&format!("│{}│\n", " ".repeat(box_width)));
    }

    // Key-value items
    let pid_val = pid
        .map(|p| p.to_string())
        .unwrap_or_else(|| "N/A".to_string());
    let short_node_id = if node_id.len() > 16 {
        format!("{}...{}", &node_id[..8], &node_id[node_id.len() - 8..])
    } else {
        node_id.to_string()
    };
    let conn_val = if active_conn {
        "Connected (active)"
    } else {
        "Idle (listening)"
    };
    let keys_val = format!("{authorized_keys} device(s)");
    let pairing_val = if pairing_active {
        "Active (ready for scan)"
    } else {
        "Inactive"
    };

    let log_str = log_path.to_string_lossy();
    let max_path_len = box_width.saturating_sub(22);
    let char_count = log_str.chars().count();
    let log_val = if char_count > max_path_len && max_path_len > 10 {
        let skip_chars = char_count.saturating_sub(max_path_len.saturating_sub(3));
        let truncated: String = log_str.chars().skip(skip_chars).collect();
        format!("...{truncated}")
    } else {
        log_str.into_owned()
    };

    let items = [
        ("PID:", pid_val),
        ("Node ID:", short_node_id),
        ("Active Sessions:", sessions.to_string()),
        ("Connection:", conn_val.to_string()),
        ("Authorized Keys:", keys_val),
        ("Pairing Active:", pairing_val.to_string()),
        ("Log Path:", log_val),
    ];

    for (k, v) in items {
        let label_width = 18usize;
        let k_pad = label_width.saturating_sub(k.chars().count());
        let line_content_len = label_width + v.chars().count();
        let total_pad = box_width.saturating_sub(2 + line_content_len);

        if color {
            out.push_str(&format!(
                "{}  {}{}{}{}{}\n",
                s.dim("│"),
                s.bold(k),
                " ".repeat(k_pad),
                v,
                " ".repeat(total_pad),
                s.dim("│")
            ));
        } else {
            out.push_str(&format!(
                "│  {k}{}{v}{}│\n",
                " ".repeat(k_pad),
                " ".repeat(total_pad)
            ));
        }
    }

    // Quick Commands Section
    let div_title = "├─ Commands ";
    let div_dashes = (box_width + 1).saturating_sub(div_title.chars().count());
    let divider = if color {
        format!(
            "{}{}{}",
            s.dim(div_title),
            s.dim(&"─".repeat(div_dashes)),
            s.dim("┤")
        )
    } else {
        format!("{div_title}{}┤", "─".repeat(div_dashes))
    };
    out.push_str(&divider);
    out.push('\n');

    let cmds = [
        ("cawide pair", "Generate a fresh pairing QR code"),
        ("cawide devices", "List authorized client devices"),
        ("cawide quit", "Stop the daemon"),
    ];

    for (cmd, desc) in cmds {
        let cmd_width = 17usize;
        let cmd_pad = cmd_width.saturating_sub(cmd.chars().count());
        let desc_len = desc.chars().count();
        let total_pad = box_width.saturating_sub(2 + cmd_width + desc_len);

        if color {
            out.push_str(&format!(
                "{}  {}{}{}{}{}\n",
                s.dim("│"),
                s.bold_cyan(cmd),
                " ".repeat(cmd_pad),
                desc,
                " ".repeat(total_pad),
                s.dim("│")
            ));
        } else {
            out.push_str(&format!(
                "│  {cmd}{}{desc}{}│\n",
                " ".repeat(cmd_pad),
                " ".repeat(total_pad)
            ));
        }
    }

    // Bottom border
    let bottom_border = if color {
        format!(
            "{}{}{}",
            s.dim("╰"),
            s.dim(&"─".repeat(box_width)),
            s.dim("╯")
        )
    } else {
        format!("╰{}╯", "─".repeat(box_width))
    };
    out.push_str(&bottom_border);
    out.push('\n');

    out
}

// -----------------------------------------------------------------------------
// Update Notice
// -----------------------------------------------------------------------------

/// Renders a compact ANSI update notice banner.
pub fn render_update_notice(current: &str, latest: &str, color: bool) -> String {
    let s = Style::new(color);
    let box_width = 62usize;

    let line1 = format!("Update available: v{current} → v{latest}");
    let line2 = "Run 'cawide update' to upgrade to the latest version!";

    let pad1 = box_width.saturating_sub(2 + line1.chars().count());
    let pad2 = box_width.saturating_sub(2 + line2.chars().count());

    let top = if color {
        format!(
            "{}{}{}",
            s.dim("╭─ "),
            s.bold_cyan("Update "),
            s.dim(&format!("{}╮", "─".repeat(box_width.saturating_sub(9))))
        )
    } else {
        format!("╭─ Update {}╮", "─".repeat(box_width.saturating_sub(9)))
    };

    let bottom = if color {
        s.dim(&format!("╰{}╯", "─".repeat(box_width))).into_owned()
    } else {
        format!("╰{}╯", "─".repeat(box_width))
    };

    let row1 = if color {
        format!(
            "{}  {}{}{}\n",
            s.dim("│"),
            s.bold(&line1),
            " ".repeat(pad1),
            s.dim("│")
        )
    } else {
        format!("│  {line1}{}│\n", " ".repeat(pad1))
    };

    let row2 = if color {
        format!(
            "{}  {}{}{}\n",
            s.dim("│"),
            s.cyan(line2),
            " ".repeat(pad2),
            s.dim("│")
        )
    } else {
        format!("│  {line2}{}│\n", " ".repeat(pad2))
    };

    format!("{top}\n{row1}{row2}{bottom}")
}
// -----------------------------------------------------------------------------
// Unit Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_banner_uncolored() {
        let banner = render_banner_with(false);
        assert!(banner.contains("╭─ v"));
        assert!(banner.contains("Remote Vibe Coding"));
        assert!(banner.contains("╰"));
        assert!(!banner.contains("\x1b["));
        for line in BANNER_LINES {
            assert!(banner.contains(line));
        }
    }

    #[test]
    fn test_render_banner_colored() {
        let banner = render_banner_with(true);
        assert!(banner.contains("\x1b[1;36m"));
        assert!(banner.contains("Remote Vibe Coding"));
    }

    #[test]
    fn test_terminal_columns() {
        let cols = terminal_columns();
        assert!(cols >= 40);
    }

    #[test]
    fn test_is_color_enabled() {
        let _ = is_color_enabled();
    }

    #[test]
    fn test_render_pairing_screen_side_by_side() {
        let ticket_uri = "cawide://pair?node=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef&secret=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"; // gitleaks:allow
        let fake_qr = " ▄▄▄ \n █ █ \n ▀▀▀ ";
        let rendered = render_pairing_screen_with(
            ticket_uri,
            fake_qr,
            300,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            Some(1234),
            false,
            80,
        );

        // Verification of requirements
        assert!(rendered.contains("Cawide daemon started in background (PID: 1234)"));
        assert!(rendered.contains("● Status: Ready for pairing"));
        assert!(rendered.contains("Scan with Cawide on iOS"));
        assert!(rendered.contains("Valid for: 5 minutes"));
        assert!(rendered.contains("Node ID:   01234567...89abcdef"));
        assert!(rendered.contains("Relay:     direct + n0 fallback"));

        // Critical requirement: Unindented URI
        let uri_line = rendered
            .lines()
            .find(|line| line.starts_with("cawide://pair?"));
        assert_eq!(uri_line, Some(ticket_uri));

        // Tips section
        assert!(rendered.contains("💡 Tips:"));
        assert!(rendered.contains("   • Terminal is ready for your commands!"));
        assert!(rendered.contains("   • Run 'cawide status' to inspect active connections."));
        assert!(rendered.contains("   • Run 'cawide pair' anytime for a new QR code."));
        assert!(rendered.contains("   • Run 'cawide quit' to stop the daemon."));
    }

    #[test]
    fn test_render_pairing_screen_stacked() {
        let ticket_uri = "cawide://pair?node=abcdef&secret=123456";
        let fake_qr = " ▄▄▄ \n █ █ \n ▀▀▀ ";
        let rendered = render_pairing_screen_with(
            ticket_uri,
            fake_qr,
            60,
            "abcdef123456",
            None,
            false,
            60, // < 76 columns triggers stacked
        );

        assert!(rendered.contains("Cawide daemon active"));
        assert!(rendered.contains("├─ Details"));
        assert!(rendered.contains("Valid for: 1 minute"));

        // Critical requirement: Unindented URI
        let uri_line = rendered
            .lines()
            .find(|line| line.starts_with("cawide://pair?"));
        assert_eq!(uri_line, Some(ticket_uri));
    }

    #[test]
    fn test_render_status_card() {
        let rendered = render_status_card_with(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            Some(5678),
            2,
            true,
            3,
            true,
            Path::new("/var/log/cawide.log"),
            false,
            80,
        );

        assert!(rendered.contains("● CAWIDE DAEMON ACTIVE"));
        assert!(rendered.contains("PID:              5678"));
        assert!(rendered.contains("Node ID:          01234567...89abcdef"));
        assert!(rendered.contains("Active Sessions:  2"));
        assert!(rendered.contains("Connection:       Connected (active)"));
        assert!(rendered.contains("Authorized Keys:  3 device(s)"));
        assert!(rendered.contains("Pairing Active:   Active (ready for scan)"));
        assert!(rendered.contains("/var/log/cawide.log"));
        assert!(rendered.contains("cawide pair"));
        assert!(rendered.contains("cawide devices"));
        assert!(rendered.contains("cawide quit"));
    }

    #[test]
    fn test_pairing_screen_box_alignment_side_by_side() {
        let qr_text = " █▀▀▀▀▀█ ▄▄▄▀▀█ ▄  █  █ █▄▄ ▄▄▄▀▄▀█ ▀▀   ▄ █▀▄ ▀█  █▀▀▀▀▀█ \n █ ███ █ █ ██▀ ▀▀█ ██▀▀▀ ▀█▀██▀█ ▀▀ ▀█▄▀  ▄█▀▄██▀▀████▄▀ ▀ ";
        let rendered = render_pairing_screen_with(
            "cawide://pair?node=test",
            qr_text,
            300,
            "abcdef123456",
            Some(1234),
            false,
            120, // Wide terminal -> side-by-side
        );

        let mut box_lines = Vec::new();
        for line in rendered.lines() {
            if line.starts_with('╭') || line.starts_with('│') || line.starts_with('╰') {
                box_lines.push(line);
            }
        }
        // Filter out banner (banner is 51 wide, card is ~96 wide)
        let card_lines: Vec<&str> = box_lines
            .into_iter()
            .filter(|l| {
                l.contains("Pairing")
                    || l.contains("Details")
                    || l.contains('┴')
                    || l.chars().count() > 60
            })
            .collect();

        assert!(!card_lines.is_empty());
        let expected_len = card_lines[0].chars().count();
        let top_mid = card_lines[0]
            .chars()
            .position(|c| c == '┬')
            .expect("top mid ┬");
        let top_right = card_lines[0]
            .chars()
            .position(|c| c == '╮')
            .expect("top right ╮");

        for (idx, line) in card_lines.iter().enumerate() {
            assert_eq!(
                line.chars().count(),
                expected_len,
                "Card line {idx} length mismatch: got {}, expected {expected_len}\nLine: {line}",
                line.chars().count()
            );
            if idx == card_lines.len() - 1 {
                assert_eq!(
                    line.chars().position(|c| c == '┴'),
                    Some(top_mid),
                    "Bottom ┴ must align with ┬"
                );
                assert_eq!(
                    line.chars().position(|c| c == '╯'),
                    Some(top_right),
                    "Bottom ╯ must align with ╮"
                );
            } else if idx > 0 {
                let mut bar_indices = line
                    .chars()
                    .enumerate()
                    .filter(|(_, c)| *c == '│')
                    .map(|(i, _)| i);
                let first = bar_indices.next();
                let mid = bar_indices.next();
                let right = bar_indices.next();
                assert_eq!(first, Some(0), "Left border at 0");
                assert_eq!(
                    mid,
                    Some(top_mid),
                    "Body mid │ must align with ┬ at row {idx}"
                );
                assert_eq!(
                    right,
                    Some(top_right),
                    "Body right │ must align with ╮ at row {idx}"
                );
            }
        }
    }

    #[test]
    fn test_pairing_screen_box_alignment_stacked() {
        let qr_text = " █▀▀▀▀▀█ ▄▄▄▀▀█ ▄ \n █ ███ █ █ ██▀ ▀▀ ";
        let rendered = render_pairing_screen_with(
            "cawide://pair?node=test",
            qr_text,
            300,
            "abcdef123456",
            Some(1234),
            false,
            60, // Stacked view
        );

        let card_lines: Vec<&str> = rendered
            .lines()
            .filter(|l| {
                l.contains("Pairing QR")
                    || l.contains("├─ Details")
                    || (l.starts_with('│')
                        && (l.contains("Scan") || l.contains("Node ID") || l.contains("█▀▀▀▀▀█")))
                    || (l.starts_with('╰') && l.chars().count() < 50)
            })
            .collect();

        assert!(!card_lines.is_empty());
        let expected_len = card_lines[0].chars().count();
        for (idx, line) in card_lines.iter().enumerate() {
            assert_eq!(
                line.chars().count(),
                expected_len,
                "Stacked card line {idx} length mismatch: got {}, expected {expected_len}\nLine: {line}",
                line.chars().count()
            );
        }
    }

    #[test]
    fn test_update_notice_box_alignment() {
        let notice = render_update_notice("0.9.0", "0.9.1", false);
        let lines: Vec<&str> = notice.lines().collect();
        assert_eq!(lines.len(), 4);
        let expected_len = lines[0].chars().count();
        for (idx, line) in lines.iter().enumerate() {
            assert_eq!(
                line.chars().count(),
                expected_len,
                "Update notice line {idx} length mismatch"
            );
        }
        assert!(notice.contains("Update available: v0.9.0 → v0.9.1"));
        assert!(notice.contains("cawide update"));
    }
}
