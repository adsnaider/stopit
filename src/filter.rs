//! The output filter between a sandbox's terminal and the host's (DESIGN.md
//! §5.3).
//!
//! Everything the sandbox writes to its PTY passes through
//! [`OutputFilter`] before it reaches the host terminal. The filter is a
//! streaming ECMA-48 parser with no screen model. It keeps only the bytes of
//! the escape sequence in progress, never more than a fixed bound, and
//! decides each sequence when it ends. Allowed sequences are written out
//! again from what was parsed, so the host terminal only ever sees
//! well-formed sequences, and a sequence split across reads is decided
//! exactly as if it had arrived whole.
//!
//! What passes: printable text as valid UTF-8, the layout controls `\t`,
//! `\n`, `\r`, backspace and bell, every CSI sequence except media copy
//! (`CSI i`) and window operations other than size reports and the title
//! stack (`CSI t`), a few plain escapes such as cursor save and keypad
//! modes, charset selection between ASCII and line drawing, titles, color
//! queries, `http` and `https` hyperlinks, rate-limited notifications, shell
//! prompt marks, OSC 52 clipboard writes when allowed, sixel images and the
//! DECRQSS and XTGETTCAP queries. Everything else is dropped, including
//! clipboard reads, OSC 7, OSC 1337, OSC 5113, every APC, PM and SOS string
//! (kitty graphics among them), `DCS tmux;` passthrough, C1 controls in any
//! encoding, and invalid UTF-8, which becomes U+FFFD.
//!
//! The filter also records which terminal modes the sandbox changed, so the
//! supervisor can change them back when the sandbox ends
//! ([`OutputFilter::restore_sequence`]). A TUI killed in the alternate
//! screen with mouse reporting on would otherwise leave the host terminal
//! unusable.
//!
//! The filter assumes a UTF-8 host terminal. A terminal that reads bytes as
//! Latin-1 would take continuation bytes 0x80 to 0x9F of valid UTF-8 text
//! as C1 controls.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

/// Whether OSC 52 clipboard writes reach the host terminal. Reads never do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardPolicy {
    /// Drop every clipboard write.
    Block,
    /// Pass clipboard writes whose payload is well-formed base64.
    Allow,
}

/// The most bytes of a CSI sequence kept; a longer one is dropped whole.
const MAX_CSI: usize = 256;
/// The most bytes of an OSC payload kept, except for clipboard writes.
const MAX_OSC: usize = 4096;
/// The most bytes of an OSC 52 payload kept: 1 MiB of base64.
const MAX_OSC52: usize = 1 << 20;
/// The most bytes of a title passed on, cut at a character boundary.
const MAX_TITLE: usize = 256;
/// The most bytes of a DCS header (parameters and intermediates) kept.
const MAX_DCS_HEAD: usize = 64;
/// The most bytes of a DECRQSS or XTGETTCAP query body passed on.
const MAX_DCS_QUERY: usize = 4096;
/// The most intermediate bytes of a plain escape sequence kept.
const MAX_ESC_INTER: usize = 4;
/// The shortest time between two notifications passed on.
const NOTIFY_INTERVAL: Duration = Duration::from_secs(1);

const ESC: u8 = 0x1b;
const BEL: u8 = 0x07;
const CAN: u8 = 0x18;
const SUB: u8 = 0x1a;
const REPLACEMENT: &[u8] = "\u{fffd}".as_bytes();

/// How a string sequence ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Terminator {
    Bel,
    St,
}

impl Terminator {
    fn bytes(self) -> &'static [u8] {
        match self {
            Terminator::Bel => &[BEL],
            Terminator::St => b"\x1b\\",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Ground,
    /// Inside a multibyte UTF-8 character: `need` continuation bytes left,
    /// the first of which must lie in `lo..=hi`.
    Utf8 {
        need: u8,
        lo: u8,
        hi: u8,
    },
    Esc,
    EscInter,
    Csi,
    /// A CSI sequence too long to keep, dropped up to its final byte.
    CsiIgnore,
    Osc,
    /// `ESC` inside an OSC string: `\` ends it, anything else aborts it.
    OscEsc,
    DcsHead,
    /// The body of an allowed DCS string, passed through; `left` bytes may
    /// still pass, or any number for `None`.
    DcsPass {
        left: Option<usize>,
    },
    DcsPassEsc,
    /// A DCS, SOS, PM or APC string being dropped.
    StrIgnore,
    StrIgnoreEsc,
}

/// The streaming escape-sequence filter. See the module documentation.
#[derive(Debug)]
pub struct OutputFilter {
    clipboard: ClipboardPolicy,
    state: State,
    /// The character or sequence in progress: UTF-8 bytes, CSI parameters
    /// and intermediates, an OSC payload, or a DCS header.
    buf: Vec<u8>,
    /// Whether the sequence in progress outgrew its bound.
    overflow: bool,
    last_notification: Option<Instant>,
    /// What the sandbox changed in the terminal and did not change back.
    left: Leftovers,
}

/// Terminal state the sandbox changed and did not change back, for
/// [`OutputFilter::restore_sequence`].
#[derive(Debug, Default)]
struct Leftovers {
    /// DEC private modes of [`OFF_BY_DEFAULT`] turned on.
    on: BTreeSet<u32>,
    /// DEC private modes of [`ON_BY_DEFAULT`] turned off.
    off: BTreeSet<u32>,
    /// ANSI insert mode (IRM).
    insert: bool,
    /// Application keypad (`ESC =`).
    keypad: bool,
    /// The line drawing character set as G0 (`ESC ( 0`).
    line_drawing: bool,
    /// A scroll region (DECSTBM).
    scroll_region: bool,
    /// xterm key modifier resources set with `CSI > Pp ; Pv m`.
    key_modifiers: BTreeSet<u32>,
    /// Kitty keyboard flags pushed on the main and the alternate screen,
    /// whose stacks are separate.
    kitty_main: u32,
    kitty_alt: u32,
    /// Kitty keyboard flags set without a push on either screen.
    kitty_set_main: bool,
    kitty_set_alt: bool,
    /// Character attributes.
    attributes: bool,
}

impl Leftovers {
    fn on_alt_screen(&self) -> bool {
        ALT_SCREENS.iter().any(|m| self.on.contains(m))
    }
}

/// The alternate screen modes.
const ALT_SCREENS: [u32; 3] = [47, 1047, 1049];

/// DEC private modes that are off in a fresh terminal and outlast a
/// program: cursor keys, reverse video, origin, X10 and later mouse
/// reporting, numeric keypad, left and right margins, focus events,
/// alternate scroll, the alternate screens, bracketed paste, synchronized output, theme change
/// and in-band resize reports.
const OFF_BY_DEFAULT: &[u32] = &[
    1, 5, 6, 9, 47, 66, 69, 1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1015, 1016, 1047, 1049,
    2004, 2026, 2031, 2048,
];

/// DEC private modes that are on in a fresh terminal: autowrap and the
/// visible cursor.
const ON_BY_DEFAULT: &[u32] = &[7, 25];

impl OutputFilter {
    /// A filter in its initial state, applying `clipboard` to OSC 52 writes.
    pub fn new(clipboard: ClipboardPolicy) -> Self {
        OutputFilter {
            clipboard,
            state: State::Ground,
            buf: Vec::new(),
            overflow: false,
            last_notification: None,
            left: Leftovers::default(),
        }
    }

    /// Filters `input`, appending what may reach the host terminal to `out`.
    pub fn feed(&mut self, input: &[u8], out: &mut Vec<u8>) {
        self.feed_at(input, Instant::now(), out);
    }

    /// [`feed`](Self::feed) at the time `now`, which rate-limits
    /// notifications.
    pub fn feed_at(&mut self, input: &[u8], now: Instant, out: &mut Vec<u8>) {
        for &b in input {
            self.byte(b, now, out);
        }
    }

    /// Ends the stream: drops any incomplete sequence, closing a DCS string
    /// already passed on so the terminal leaves it.
    pub fn finish(&mut self, out: &mut Vec<u8>) {
        if matches!(self.state, State::DcsPass { .. } | State::DcsPassEsc) {
            out.extend_from_slice(b"\x1b\\");
        }
        self.state = State::Ground;
        self.buf.clear();
        self.overflow = false;
    }

    /// The bytes that undo what the sandbox changed in the terminal and
    /// left changed: the modes of [`OFF_BY_DEFAULT`] it turned on and of
    /// [`ON_BY_DEFAULT`] it turned off, insert mode, the application keypad,
    /// line drawing, a scroll region, key modifier resources, kitty keyboard
    /// flags on either screen, and character attributes. Empty when it left
    /// none of them changed, so plain output stays as it was.
    pub fn restore_sequence(&self) -> Vec<u8> {
        let left = &self.left;
        let mut out = Vec::new();
        let mut put = |s: &str| out.extend_from_slice(s.as_bytes());
        // The alternate screen's kitty stack first, while it is current;
        // leaving the alternate screen also restores the cursor saved when
        // mode 1049 was entered.
        if left.on_alt_screen() {
            if left.kitty_alt > 0 {
                put(&format!("\x1b[<{}u", left.kitty_alt));
            }
            if left.kitty_set_alt {
                put("\x1b[=0u");
            }
        }
        for mode in ALT_SCREENS.iter().rev().filter(|m| left.on.contains(m)) {
            put(&format!("\x1b[?{mode}l"));
        }
        if left.kitty_main > 0 {
            put(&format!("\x1b[<{}u", left.kitty_main));
        }
        if left.kitty_set_main {
            put("\x1b[=0u");
        }
        for mode in left.on.iter().filter(|m| !ALT_SCREENS.contains(m)) {
            put(&format!("\x1b[?{mode}l"));
        }
        for mode in &left.off {
            put(&format!("\x1b[?{mode}h"));
        }
        if left.insert {
            put("\x1b[4l");
        }
        if left.keypad {
            put("\x1b>");
        }
        if left.line_drawing {
            put("\x1b(B");
        }
        if left.scroll_region {
            // Resetting the region homes the cursor, so it is saved and
            // restored around it.
            put("\x1b7\x1b[r\x1b8");
        }
        for resource in &left.key_modifiers {
            put(&format!("\x1b[>{resource}m"));
        }
        if left.attributes {
            put("\x1b[0m");
        }
        out
    }

    fn byte(&mut self, b: u8, now: Instant, out: &mut Vec<u8>) {
        match self.state {
            State::Ground => self.ground(b, out),
            State::Utf8 { need, lo, hi } => {
                if (lo..=hi).contains(&b) {
                    self.buf.push(b);
                    if need == 1 {
                        self.state = State::Ground;
                        self.emit_char(out);
                    } else {
                        self.state = State::Utf8 {
                            need: need - 1,
                            lo: 0x80,
                            hi: 0xbf,
                        };
                    }
                } else {
                    out.extend_from_slice(REPLACEMENT);
                    self.buf.clear();
                    self.state = State::Ground;
                    self.ground(b, out);
                }
            }
            State::Esc => self.esc(b, out),
            State::EscInter => match b {
                0x20..=0x2f => {
                    if self.buf.len() < MAX_ESC_INTER {
                        self.buf.push(b);
                    } else {
                        self.overflow = true;
                    }
                }
                0x30..=0x7e => {
                    let allowed = !self.overflow
                        && matches!(self.buf.as_slice(), [b'(' | b')'])
                        && matches!(b, b'0' | b'B');
                    if allowed {
                        out.push(ESC);
                        out.extend_from_slice(&self.buf);
                        out.push(b);
                        if self.buf == b"(" {
                            self.left.line_drawing = b == b'0';
                        }
                    }
                    self.reset_to_ground();
                }
                _ => self.control_in_sequence(b, out),
            },
            State::Csi => match b {
                0x20..=0x3f => {
                    if self.buf.len() < MAX_CSI {
                        self.buf.push(b);
                    } else {
                        self.buf.clear();
                        self.state = State::CsiIgnore;
                    }
                }
                0x40..=0x7e => {
                    self.csi(b, out);
                    self.reset_to_ground();
                }
                0x7f => {}
                _ => self.control_in_sequence(b, out),
            },
            State::CsiIgnore => match b {
                0x20..=0x3f | 0x7f => {}
                0x40..=0x7e => self.reset_to_ground(),
                _ => self.control_in_sequence(b, out),
            },
            State::Osc => match b {
                BEL => self.osc(Terminator::Bel, now, out),
                ESC => self.state = State::OscEsc,
                CAN | SUB => self.reset_to_ground(),
                0x00..=0x1f | 0x7f => {}
                _ => {
                    let limit = if self.buf.starts_with(b"52;") {
                        MAX_OSC52
                    } else {
                        MAX_OSC
                    };
                    if self.buf.len() < limit {
                        self.buf.push(b);
                    } else {
                        self.overflow = true;
                    }
                }
            },
            State::OscEsc => {
                if b == b'\\' {
                    self.osc(Terminator::St, now, out);
                } else {
                    self.buf.clear();
                    self.overflow = false;
                    self.state = State::Esc;
                    self.esc(b, out);
                }
            }
            State::DcsHead => match b {
                0x20..=0x3f => {
                    if self.buf.len() < MAX_DCS_HEAD {
                        self.buf.push(b);
                    } else {
                        self.buf.clear();
                        self.state = State::StrIgnore;
                    }
                }
                0x40..=0x7e => self.dcs(b, out),
                ESC => {
                    self.buf.clear();
                    self.state = State::StrIgnoreEsc;
                }
                CAN | SUB => self.reset_to_ground(),
                _ => {}
            },
            State::DcsPass { left } => match b {
                ESC => self.state = State::DcsPassEsc,
                CAN | SUB => {
                    out.push(CAN);
                    self.reset_to_ground();
                }
                0x20..=0x7e => match left {
                    Some(0) => {
                        out.extend_from_slice(b"\x1b\\");
                        self.state = State::StrIgnore;
                    }
                    _ => {
                        out.push(b);
                        self.state = State::DcsPass {
                            left: left.map(|n| n - 1),
                        };
                    }
                },
                _ => {}
            },
            State::DcsPassEsc => {
                out.extend_from_slice(b"\x1b\\");
                self.state = State::Ground;
                if b != b'\\' {
                    self.state = State::Esc;
                    self.esc(b, out);
                }
            }
            State::StrIgnore => match b {
                ESC => self.state = State::StrIgnoreEsc,
                CAN | SUB => self.reset_to_ground(),
                _ => {}
            },
            State::StrIgnoreEsc => {
                if b == b'\\' {
                    self.reset_to_ground();
                } else {
                    self.state = State::Esc;
                    self.esc(b, out);
                }
            }
        }
    }

    fn reset_to_ground(&mut self) {
        self.state = State::Ground;
        self.buf.clear();
        self.overflow = false;
    }

    fn ground(&mut self, b: u8, out: &mut Vec<u8>) {
        match b {
            ESC => {
                self.buf.clear();
                self.state = State::Esc;
            }
            b'\t' | b'\n' | b'\r' | 0x08 | BEL => out.push(b),
            0x20..=0x7e => out.push(b),
            0x00..=0x1f | 0x7f => {}
            0xc2..=0xdf => self.start_char(b, 1, 0x80, 0xbf),
            0xe0 => self.start_char(b, 2, 0xa0, 0xbf),
            0xe1..=0xec | 0xee..=0xef => self.start_char(b, 2, 0x80, 0xbf),
            0xed => self.start_char(b, 2, 0x80, 0x9f),
            0xf0 => self.start_char(b, 3, 0x90, 0xbf),
            0xf1..=0xf3 => self.start_char(b, 3, 0x80, 0xbf),
            0xf4 => self.start_char(b, 3, 0x80, 0x8f),
            _ => out.extend_from_slice(REPLACEMENT),
        }
    }

    fn start_char(&mut self, b: u8, need: u8, lo: u8, hi: u8) {
        self.buf.clear();
        self.buf.push(b);
        self.state = State::Utf8 { need, lo, hi };
    }

    /// Emits the complete UTF-8 character in `buf`, unless it is a C1
    /// control (U+0080 to U+009F), which some terminals obey.
    fn emit_char(&mut self, out: &mut Vec<u8>) {
        let c1 = self.buf.len() == 2 && self.buf[0] == 0xc2 && self.buf[1] <= 0x9f;
        if !c1 {
            out.extend_from_slice(&self.buf);
        }
        self.buf.clear();
    }

    /// A C0 control, or a byte that cannot continue the sequence in
    /// progress. `ESC` starts a new sequence, `CAN` and `SUB` cancel, other
    /// C0 controls are obeyed as terminals do and the sequence goes on, and
    /// anything else ends the sequence and is read again as text.
    fn control_in_sequence(&mut self, b: u8, out: &mut Vec<u8>) {
        match b {
            ESC => {
                self.buf.clear();
                self.state = State::Esc;
            }
            CAN | SUB => self.reset_to_ground(),
            0x00..=0x1f => {
                if matches!(b, b'\t' | b'\n' | b'\r' | 0x08 | BEL) {
                    out.push(b);
                }
            }
            _ => {
                self.reset_to_ground();
                self.ground(b, out);
            }
        }
    }

    fn esc(&mut self, b: u8, out: &mut Vec<u8>) {
        self.buf.clear();
        self.overflow = false;
        match b {
            b'[' => self.state = State::Csi,
            b']' => {
                self.overflow = false;
                self.state = State::Osc;
            }
            b'P' => self.state = State::DcsHead,
            b'X' | b'^' | b'_' => self.state = State::StrIgnore,
            0x20..=0x2f => {
                self.buf.push(b);
                self.state = State::EscInter;
            }
            0x30..=0x7e => {
                // Cursor save and restore, keypad modes, index, reverse
                // index, next line, tab set, and full reset.
                if matches!(
                    b,
                    b'7' | b'8' | b'=' | b'>' | b'D' | b'E' | b'H' | b'M' | b'c'
                ) {
                    out.extend_from_slice(&[ESC, b]);
                    match b {
                        b'=' => self.left.keypad = true,
                        b'>' => self.left.keypad = false,
                        b'c' => self.left = Leftovers::default(),
                        _ => {}
                    }
                }
                self.state = State::Ground;
            }
            _ => self.control_in_sequence(b, out),
        }
    }

    fn csi(&mut self, fin: u8, out: &mut Vec<u8>) {
        let seq = &self.buf;
        // Parameter bytes come before intermediates.
        let params_end = seq
            .iter()
            .position(|b| (0x20..=0x2f).contains(b))
            .unwrap_or(seq.len());
        if seq[params_end..].iter().any(|b| (0x30..=0x3f).contains(b)) {
            return;
        }
        let (params, inter) = seq.split_at(params_end);
        let private = params
            .first()
            .copied()
            .filter(|b| (0x3c..=0x3f).contains(b));
        let numbers = numbers(if private.is_some() {
            &params[1..]
        } else {
            params
        });
        match (fin, private, inter) {
            // Media copy: printer controller mode hides output and may hand
            // it to a host program.
            (b'i', _, _) => return,
            // Window operations: only size reports and the title stack.
            (b't', None, []) => {
                if !matches!(numbers.first(), Some(Some(14 | 16 | 18 | 19 | 22 | 23))) {
                    return;
                }
            }
            (b't', _, _) => return,
            // ANSI modes: only insert mode. Keyboard lock, local echo and
            // newline mode would change how the host terminal takes input
            // after the sandbox ends.
            (b'h' | b'l', None, []) => {
                if numbers.is_empty() || numbers.iter().any(|n| *n != Some(4)) {
                    return;
                }
                self.left.insert = fin == b'h';
            }
            // DECSCL can turn on 8-bit replies.
            (b'p', _, b"\"") => return,
            // Modes behind other private markers, and xterm's key modifier
            // switches that the restore does not undo.
            (b'h' | b'l', Some(b'>' | b'=' | b'<'), _) => return,
            (b'n' | b'f', Some(b'>'), []) => return,
            // XTRESTORE can bring back any saved mode: each tracked one it
            // names counts as changed, and the restore undoes it either way.
            (b'r', Some(b'?'), []) => {
                for mode in numbers.iter().flatten() {
                    if OFF_BY_DEFAULT.contains(mode) {
                        self.left.on.insert(*mode);
                    } else if ON_BY_DEFAULT.contains(mode) {
                        self.left.off.insert(*mode);
                    }
                }
            }
            (b'h' | b'l', Some(b'?'), []) => {
                let was_alt = self.left.on_alt_screen();
                for mode in numbers.iter().flatten() {
                    let (set, set_when_on) = if OFF_BY_DEFAULT.contains(mode) {
                        (&mut self.left.on, true)
                    } else if ON_BY_DEFAULT.contains(mode) {
                        (&mut self.left.off, false)
                    } else {
                        continue;
                    };
                    if (fin == b'h') == set_when_on {
                        set.insert(*mode);
                    } else {
                        set.remove(mode);
                    }
                }
                if was_alt != self.left.on_alt_screen() {
                    // Each entry to the alternate screen starts its stack
                    // afresh, and leaving it makes its stack irrelevant.
                    self.left.kitty_alt = 0;
                    self.left.kitty_set_alt = false;
                }
            }
            (b'r', None, []) => self.left.scroll_region = !params.is_empty(),
            (b'm', None, []) => {
                // A plain reset (`CSI m`, `CSI 0 m`) clears them; anything
                // else may set some, as far as this filter knows.
                self.left.attributes = !params.iter().all(|&b| b == b'0' || b == b';');
            }
            (b'm', Some(b'>'), []) => {
                if let Some(Some(resource)) = numbers.first() {
                    if numbers.len() > 1 {
                        self.left.key_modifiers.insert(*resource);
                    } else {
                        self.left.key_modifiers.remove(resource);
                    }
                }
            }
            (b'u', Some(b'>'), []) => {
                let pushes = if self.left.on_alt_screen() {
                    &mut self.left.kitty_alt
                } else {
                    &mut self.left.kitty_main
                };
                *pushes = pushes.saturating_add(1);
            }
            (b'u', Some(b'<'), []) => {
                let n = numbers.first().copied().flatten().unwrap_or(1).max(1);
                let pushes = if self.left.on_alt_screen() {
                    &mut self.left.kitty_alt
                } else {
                    &mut self.left.kitty_main
                };
                *pushes = pushes.saturating_sub(n);
            }
            (b'u', Some(b'='), []) => {
                let set = !matches!(numbers.first(), None | Some(None | Some(0)));
                if self.left.on_alt_screen() {
                    self.left.kitty_set_alt = set;
                } else {
                    self.left.kitty_set_main = set;
                }
            }
            _ => {}
        }
        out.extend_from_slice(b"\x1b[");
        out.extend_from_slice(seq);
        out.push(fin);
    }

    fn osc(&mut self, term: Terminator, now: Instant, out: &mut Vec<u8>) {
        let payload = std::mem::take(&mut self.buf);
        let overflow = std::mem::replace(&mut self.overflow, false);
        self.state = State::Ground;
        if overflow {
            return;
        }
        let Ok(text) = std::str::from_utf8(&payload) else {
            return;
        };
        if text.chars().any(|c| ('\u{80}'..='\u{9f}').contains(&c)) {
            return;
        }
        let (cmd, rest) = match text.split_once(';') {
            Some((cmd, rest)) => (cmd, Some(rest)),
            None => (text, None),
        };
        let pass = match (cmd, rest) {
            ("0" | "1" | "2", Some(title)) => {
                let mut end = title.len().min(MAX_TITLE);
                while !title.is_char_boundary(end) {
                    end -= 1;
                }
                out.extend_from_slice(b"\x1b]");
                out.extend_from_slice(cmd.as_bytes());
                out.push(b';');
                out.extend_from_slice(&title.as_bytes()[..end]);
                out.extend_from_slice(term.bytes());
                return;
            }
            ("4", Some(rest)) => {
                let parts: Vec<&str> = rest.split(';').collect();
                parts.len() % 2 == 0
                    && parts.chunks(2).all(|pair| {
                        !pair[0].is_empty()
                            && pair[0].bytes().all(|b| b.is_ascii_digit())
                            && pair[1] == "?"
                    })
            }
            ("10" | "11" | "12", Some(rest)) => rest.split(';').all(|q| q == "?"),
            ("104" | "110" | "111" | "112", None) => true,
            ("104", Some(rest)) => rest
                .split(';')
                .all(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())),
            ("8", Some(rest)) => match rest.split_once(';') {
                Some((_, "")) => true,
                Some((_, uri)) => {
                    let lower = uri.get(..8).unwrap_or(uri).to_ascii_lowercase();
                    lower.starts_with("http://") || lower.starts_with("https://")
                }
                None => false,
            },
            ("133", Some(_)) => true,
            // ConEmu progress. Its other numbered OSC 9 commands set the
            // working directory, run macros and more.
            ("9", Some(rest)) if rest.starts_with("4;") => true,
            ("9", Some(rest))
                if rest
                    .split(';')
                    .next()
                    .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())) =>
            {
                false
            }
            // urxvt hands other OSC 777 commands to its extensions.
            ("777", Some(rest)) if !rest.starts_with("notify;") => false,
            ("9" | "99" | "777", Some(_)) => {
                let due = self
                    .last_notification
                    .is_none_or(|last| now.duration_since(last) >= NOTIFY_INTERVAL);
                if due {
                    self.last_notification = Some(now);
                }
                due
            }
            ("52", Some(rest)) => match rest.split_once(';') {
                Some((_, "?")) | None => false,
                Some((targets, data)) => {
                    self.clipboard == ClipboardPolicy::Allow
                        && targets.bytes().all(|b| b"cpqs01234567".contains(&b))
                        && data
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
                }
            },
            _ => false,
        };
        if pass {
            out.extend_from_slice(b"\x1b]");
            out.extend_from_slice(&payload);
            out.extend_from_slice(term.bytes());
        }
    }

    fn dcs(&mut self, fin: u8, out: &mut Vec<u8>) {
        let inter: Vec<u8> = self
            .buf
            .iter()
            .copied()
            .filter(|b| (0x20..=0x2f).contains(b))
            .collect();
        let left = match (inter.as_slice(), fin) {
            // Sixel graphics.
            ([], b'q') => None,
            // DECRQSS and XTGETTCAP queries: the answers go to the sandbox.
            (b"$" | b"+", b'q') => Some(MAX_DCS_QUERY),
            _ => {
                self.buf.clear();
                self.state = State::StrIgnore;
                return;
            }
        };
        out.extend_from_slice(b"\x1bP");
        out.extend_from_slice(&self.buf);
        out.push(fin);
        self.buf.clear();
        self.state = State::DcsPass { left };
    }
}

/// The numeric parameters of a CSI sequence, split at `;` (sub-parameters
/// after `:` ignored), `None` for an empty or non-numeric one.
fn numbers(params: &[u8]) -> Vec<Option<u32>> {
    if params.is_empty() {
        return Vec::new();
    }
    params
        .split(|&b| b == b';')
        .map(|p| {
            let p = p.split(|&b| b == b':').next().unwrap_or_default();
            std::str::from_utf8(p).ok()?.parse().ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filter_with(policy: ClipboardPolicy, input: &[u8]) -> Vec<u8> {
        let mut f = OutputFilter::new(policy);
        let mut out = Vec::new();
        f.feed(input, &mut out);
        f.finish(&mut out);
        out
    }

    fn filter(input: &[u8]) -> Vec<u8> {
        filter_with(ClipboardPolicy::Block, input)
    }

    #[track_caller]
    fn passes(input: &[u8]) {
        assert_eq!(filter(input), input, "{:?}", String::from_utf8_lossy(input));
    }

    #[track_caller]
    fn dropped(input: &[u8]) {
        let mut wrapped = b"a".to_vec();
        wrapped.extend_from_slice(input);
        wrapped.push(b'b');
        assert_eq!(
            filter(&wrapped),
            b"ab",
            "{:?}",
            String::from_utf8_lossy(input)
        );
    }

    #[test]
    fn text_and_layout_controls_pass() {
        passes(b"hello, world\r\n\tx\x08y\x07");
        passes("héllo 日本語 🦀 ok".as_bytes());
        passes(b"");
    }

    #[test]
    fn other_controls_and_c1_are_dropped() {
        for c in [0x00, 0x01, 0x05, 0x0b, 0x0c, 0x0e, 0x0f, 0x7f] {
            dropped(&[c]);
        }
        // UTF-8 encoded C1 controls: CSI, OSC, ST and DCS.
        for c in ["\u{9b}", "\u{9d}", "\u{9c}", "\u{90}", "\u{85}"] {
            dropped(c.as_bytes());
        }
    }

    #[test]
    fn invalid_utf8_becomes_the_replacement_character() {
        let r = "\u{fffd}";
        for (input, want) in [
            (&b"\x9b"[..], format!("a{r}b")),
            (b"\xff", format!("a{r}b")),
            (b"\xc0\xaf", format!("a{r}{r}b")),
            // Overlong, surrogate and past U+10FFFF.
            (b"\xe0\x80\x80", format!("a{r}{r}{r}b")),
            (b"\xed\xa0\x80", format!("a{r}{r}{r}b")),
            (b"\xf4\x90\x80\x80", format!("a{r}{r}{r}{r}b")),
            // A truncated character, then text.
            (b"\xe6\x97", format!("a{r}b")),
            // A truncated character, then an escape sequence.
            (b"\xe6\x1b[1m", format!("a{r}\x1b[1mb")),
        ] {
            let mut wrapped = b"a".to_vec();
            wrapped.extend_from_slice(input);
            wrapped.push(b'b');
            assert_eq!(
                String::from_utf8(filter(&wrapped)).unwrap(),
                want,
                "{input:?}"
            );
        }
        // A truncated character at the end of the stream is dropped.
        assert_eq!(filter(b"a\xe6\x97"), b"a");
    }

    #[test]
    fn tui_sequences_pass() {
        for seq in [
            &b"\x1b[0m\x1b[1;31m\x1b[38;2;10;20;30m\x1b[48:5:200m"[..],
            b"\x1b[H\x1b[2J\x1b[10;20H\x1b[A\x1b[3B\x1b[K\x1b[?25l\x1b[?25h",
            b"\x1b[?1049h\x1b[?1049l\x1b[?2026h\x1b[?2026l\x1b[?2004h\x1b[?1004h",
            b"\x1b[?1000h\x1b[?1002h\x1b[?1006h\x1b[?1015h\x1b[?1016h",
            // Kitty keyboard: push, query, set and pop.
            b"\x1b[>1u\x1b[?u\x1b[=5;1u\x1b[<u\x1b[<3u",
            // Cursor shape, scroll region, device attributes and status.
            b"\x1b[2 q\x1b[1;24r\x1b[c\x1b[>c\x1b[6n\x1b[?1$p",
            // Size reports and the title stack.
            b"\x1b[14t\x1b[16t\x1b[18t\x1b[19t\x1b[22;0t\x1b[23;0t",
            b"\x1b7\x1b8\x1b=\x1b>\x1bM\x1bD\x1bE\x1bH\x1b(0\x1b(B\x1b)0",
        ] {
            passes(seq);
        }
    }

    #[test]
    fn dangerous_csi_and_escapes_are_dropped() {
        for seq in [
            &b"\x1b[21t"[..],
            b"\x1b[20t",
            b"\x1b[t",
            b"\x1b[8;100;100t",
            b"\x1b[3;0;0t",
            b"\x1b[>3t",
            b"\x1b[5i",
            b"\x1b[?5i",
            b"\x1b[4i",
            // Parameters after intermediates are malformed.
            b"\x1b[1 1q",
            // Plain escapes outside the list, and other charsets.
            b"\x1bZ",
            b"\x1b#8",
            b"\x1b%G",
            b"\x1b(K",
            b"\x1bn",
        ] {
            dropped(seq);
        }
    }

    #[test]
    fn titles_pass_cut_to_length() {
        passes(b"\x1b]0;my title\x07");
        passes(b"\x1b]2;my title\x1b\\");
        passes("\x1b]1;tîtle\x07".as_bytes());
        let long = format!("\x1b]2;{}\x07", "é".repeat(200));
        let out = String::from_utf8(filter(long.as_bytes())).unwrap();
        assert_eq!(out, format!("\x1b]2;{}\x07", "é".repeat(MAX_TITLE / 2)));
        // C0 controls inside are left out.
        assert_eq!(filter(b"\x1b]2;a\x01b\x07"), b"\x1b]2;ab\x07");
    }

    #[test]
    fn color_queries_pass_but_not_color_changes() {
        passes(b"\x1b]10;?\x07");
        passes(b"\x1b]11;?\x1b\\");
        passes(b"\x1b]10;?;?\x07");
        passes(b"\x1b]4;1;?;2;?\x07");
        passes(b"\x1b]104\x07");
        passes(b"\x1b]104;1;2\x07");
        passes(b"\x1b]110\x07");
        dropped(b"\x1b]11;rgb:00/00/00\x07");
        dropped(b"\x1b]4;1;rgb:ff/00/00\x07");
        dropped(b"\x1b]4;1;?;2\x07");
    }

    #[test]
    fn hyperlinks_pass_only_for_http() {
        passes(b"\x1b]8;;https://example.com/a?b\x1b\\link\x1b]8;;\x1b\\");
        passes(b"\x1b]8;id=x;HTTP://example.com\x07");
        dropped(b"\x1b]8;;file:///etc/passwd\x1b\\");
        dropped(b"\x1b]8;;ssh://host\x07");
        dropped(b"\x1b]8;;javascript:alert(1)\x07");
        dropped(b"\x1b]8\x07");
    }

    #[test]
    fn clipboard_reads_never_pass_and_writes_follow_the_policy() {
        let write = b"\x1b]52;c;aGVsbG8=\x07";
        assert_eq!(filter_with(ClipboardPolicy::Allow, write), write);
        assert_eq!(filter_with(ClipboardPolicy::Block, write), b"");
        for policy in [ClipboardPolicy::Allow, ClipboardPolicy::Block] {
            for seq in [
                &b"\x1b]52;c;?\x07"[..],
                b"\x1b]52;c;?\x1b\\",
                b"\x1b]52;c\x07",
                b"\x1b]52;c;not base64!\x07",
                b"\x1b]52;xyz;aGVsbG8=\x07",
            ] {
                assert_eq!(filter_with(policy, seq), b"", "{policy:?} {seq:?}");
            }
        }
        // Large writes pass up to the bound, and are dropped past it.
        let data = "A".repeat(MAX_OSC52 - 5);
        let big = format!("\x1b]52;c;{data}\x07");
        assert_eq!(
            filter_with(ClipboardPolicy::Allow, big.as_bytes()),
            big.as_bytes()
        );
        let data = "A".repeat(MAX_OSC52);
        let big = format!("\x1b]52;c;{data}\x07ok");
        assert_eq!(filter_with(ClipboardPolicy::Allow, big.as_bytes()), b"ok");
    }

    #[test]
    fn host_reaching_osc_are_dropped() {
        for seq in [
            &b"\x1b]7;file://host/home/user\x07"[..],
            b"\x1b]1337;File=name=x:AAAA\x07",
            b"\x1b]1337;SetUserVar=x=eQ==\x07",
            b"\x1b]5113;x\x1b\\",
            b"\x1b]50;font\x07",
            b"\x1b]22;pointer\x07",
            b"\x1b]\x07",
            b"\x1b]abc;def\x07",
        ] {
            dropped(seq);
        }
        // An OSC with a C1 character inside is dropped whole.
        dropped("\x1b]2;a\u{9c}b\x07".as_bytes());
        // So is one that is not UTF-8.
        dropped(b"\x1b]2;a\xffb\x07");
    }

    #[test]
    fn prompt_marks_and_progress_pass() {
        passes(b"\x1b]133;A\x07\x1b]133;D;0\x1b\\");
        passes(b"\x1b]9;4;1;50\x07\x1b]9;4;1;60\x07");
        // Other numbered OSC 9 commands and OSC 777 extensions are not
        // notifications.
        dropped(b"\x1b]9;9;/home/user\x07");
        dropped(b"\x1b]9;7;cmd.exe\x07");
        dropped(b"\x1b]9;1\x07");
        dropped(b"\x1b]777;preexec;x\x07");
        passes(b"\x1b]9;build done\x07");
    }

    #[test]
    fn notifications_are_rate_limited() {
        let mut f = OutputFilter::new(ClipboardPolicy::Block);
        let start = Instant::now();
        let note = b"\x1b]9;done\x07";
        let mut feed = |at: Duration| {
            let mut out = Vec::new();
            f.feed_at(note, start + at, &mut out);
            out
        };
        assert_eq!(feed(Duration::ZERO), note);
        assert_eq!(feed(Duration::from_millis(500)), b"");
        assert_eq!(feed(Duration::from_millis(999)), b"");
        assert_eq!(feed(Duration::from_millis(1000)), note);
        assert_eq!(feed(Duration::from_millis(1500)), b"");
        // Other notification kinds share the limit.
        let mut out = Vec::new();
        f.feed_at(
            b"\x1b]777;notify;t;b\x07",
            start + Duration::from_millis(2100),
            &mut out,
        );
        f.feed_at(
            b"\x1b]99;;hi\x07",
            start + Duration::from_millis(2200),
            &mut out,
        );
        assert_eq!(out, b"\x1b]777;notify;t;b\x07");
    }

    #[test]
    fn dcs_passes_only_sixel_and_queries() {
        passes(b"\x1bPq#0;2;0;0;0#1!10~-\x1b\\");
        passes(b"\x1bP0;1;0q\"1;1;10;10#0~~\x1b\\");
        passes(b"\x1bP$qm\x1b\\");
        passes(b"\x1bP+q544e\x1b\\");
        dropped(b"\x1bPtmux;\x1b\x1b]52;c;?\x07\x1b\\");
        dropped(b"\x1bP1|17/ab\x1b\\");
        dropped(b"\x1bP=1s\x1b\\");
        dropped(b"\x1bPp\x1b\\");
        // Controls inside a passed body are left out.
        assert_eq!(filter(b"\x1bPq#0\n~\x1b\\"), b"\x1bPq#0~\x1b\\");
        // A query body past its bound is closed and the rest dropped.
        let body = "a".repeat(MAX_DCS_QUERY + 10);
        let out = filter(format!("\x1bP+q{body}\x1b\\ok").as_bytes());
        assert_eq!(
            out,
            format!("\x1bP+q{}\x1b\\ok", "a".repeat(MAX_DCS_QUERY)).as_bytes()
        );
        // A passed body cut off by the end of the stream is closed.
        assert_eq!(filter(b"\x1bPq#0"), b"\x1bPq#0\x1b\\");
    }

    #[test]
    fn apc_pm_and_sos_are_dropped() {
        // Kitty graphics from a file, shared memory, and inline data.
        dropped(b"\x1b_Gf=100,t=f;L2V0Yy9wYXNzd2Q=\x1b\\");
        dropped(b"\x1b_Ga=T,t=s;c2htLW5hbWU=\x1b\\");
        dropped(b"\x1b_Ga=T,f=24;AAAA\x07still\x1b\\");
        dropped(b"\x1b^private\x1b\\");
        dropped(b"\x1bXstring\x1b\\");
    }

    #[test]
    fn escape_cancel_and_sub_end_strings_as_terminals_do() {
        // `ESC` other than ST aborts a string and starts a new sequence.
        assert_eq!(filter(b"\x1b]2;title\x1b[1mX"), b"\x1b[1mX");
        assert_eq!(filter(b"\x1b_Gsecret\x1b[1mX"), b"\x1b[1mX");
        assert_eq!(filter(b"\x1bPtmux;\x1b[1mX"), b"\x1b[1mX");
        // CAN and SUB cancel any sequence.
        assert_eq!(filter(b"\x1b]2;title\x18X"), b"X");
        assert_eq!(filter(b"\x1b[1;2\x1aX"), b"X");
        assert_eq!(filter(b"\x1b_G\x18X"), b"X");
        // A passed DCS cancelled by CAN cancels in the terminal too.
        assert_eq!(filter(b"\x1bPq#0\x18X"), b"\x1bPq#0\x18X");
        // C0 controls inside a CSI are obeyed, as terminals do.
        assert_eq!(filter(b"\x1b[1\r;2H"), b"\r\x1b[1;2H");
        // A non-ASCII byte ends a CSI and is read as text.
        assert_eq!(filter("\x1b[1é".as_bytes()), "é".as_bytes());
    }

    #[test]
    fn long_sequences_are_bounded() {
        let mut f = OutputFilter::new(ClipboardPolicy::Block);
        let mut out = Vec::new();
        f.feed(b"\x1b]1337;", &mut out);
        let chunk = vec![b'A'; 1 << 16];
        for _ in 0..160 {
            f.feed(&chunk, &mut out);
            assert!(f.buf.len() <= MAX_OSC, "{}", f.buf.len());
        }
        f.feed(b"\x07after", &mut out);
        assert_eq!(out, b"after");

        let long_csi = format!("\x1b[{}m after", "1;".repeat(MAX_CSI));
        assert_eq!(filter(long_csi.as_bytes()), b" after");
        let long_dcs = format!("\x1bP{}q data\x1b\\after", "1;".repeat(MAX_DCS_HEAD));
        assert_eq!(filter(long_dcs.as_bytes()), b"after");
        let long_esc = b"\x1b((((((B after";
        assert_eq!(filter(long_esc), b" after");
        let mut f = OutputFilter::new(ClipboardPolicy::Block);
        let mut out = Vec::new();
        f.feed(b"\x1b", &mut out);
        let spaces = vec![b' '; 1 << 16];
        for _ in 0..16 {
            f.feed(&spaces, &mut out);
            assert!(f.buf.len() <= MAX_ESC_INTER, "{}", f.buf.len());
        }
        f.feed(b"(0after", &mut out);
        assert_eq!(out, b"after");
        let long_title = format!("\x1b]2;{}\x07after", "x".repeat(MAX_OSC + 1));
        assert_eq!(filter(long_title.as_bytes()), b"after");
    }

    /// Inputs mixing everything above, for the split test.
    fn corpus() -> Vec<Vec<u8>> {
        let mut all: Vec<Vec<u8>> = [
            &b"plain text\r\n"[..],
            "日本語🦀\u{9b}".as_bytes(),
            b"\x1b[1;31mred\x1b[0m\x1b[?1049h\x1b[>1u\x1b[21t\x1b[5i",
            b"\x1b]0;title\x07\x1b]2;t\x1b\\\x1b]52;c;?\x07\x1b]52;c;aGk=\x07",
            b"\x1b]8;;https://x\x1b\\l\x1b]8;;\x1b\\\x1b]8;;file:///x\x07",
            b"\x1bPq#0~\x1b\\\x1bPtmux;\x1b\x1bx\x1b\\\x1b_Gt=f;x\x1b\\",
            b"\xe6\x97\x1b]2;a\x1b[1m\x1b]2;b\x18\x1b(0q\x1b(B",
            b"\x1b]10;?\x07\x1b]4;1;rgb:0/0/0\x07\xf0\x9f\xa6",
        ]
        .iter()
        .map(|s| s.to_vec())
        .collect();
        all.push(all.concat());
        all
    }

    #[test]
    fn splitting_the_input_anywhere_changes_nothing() {
        for policy in [ClipboardPolicy::Block, ClipboardPolicy::Allow] {
            for input in corpus() {
                let whole = filter_with(policy, &input);
                for at in 0..=input.len() {
                    let mut f = OutputFilter::new(policy);
                    let mut out = Vec::new();
                    f.feed(&input[..at], &mut out);
                    f.feed(&input[at..], &mut out);
                    f.finish(&mut out);
                    assert_eq!(out, whole, "{policy:?} split at {at} of {input:?}");
                }
                let mut f = OutputFilter::new(policy);
                let mut out = Vec::new();
                for b in &input {
                    f.feed(std::slice::from_ref(b), &mut out);
                }
                f.finish(&mut out);
                assert_eq!(out, whole, "{policy:?} byte by byte: {input:?}");
            }
        }
    }

    #[test]
    fn the_output_never_holds_a_dropped_introducer() {
        // Whatever the input, no APC, PM, SOS or C1 byte comes out, and every
        // OSC that comes out is one the filter allows.
        let mut input = Vec::new();
        for a in 0..=255u8 {
            for b in [b'_', b'^', b'X', b']', b'P', b'[', 0x9b, 0x9d, b'\\'] {
                input.extend_from_slice(&[ESC, a, b, ESC, b, a]);
            }
        }
        let out = filter(&input);
        for w in out.windows(2) {
            assert!(
                !(w[0] == ESC && matches!(w[1], b'_' | b'^' | b'X')),
                "{out:?}"
            );
        }
        assert!(std::str::from_utf8(&out).is_ok());
        assert!(
            !String::from_utf8(out)
                .unwrap()
                .chars()
                .any(|c| ('\u{80}'..='\u{9f}').contains(&c))
        );
    }

    fn restore_after(input: &[u8]) -> String {
        let mut f = OutputFilter::new(ClipboardPolicy::Block);
        let mut out = Vec::new();
        f.feed(input, &mut out);
        String::from_utf8(f.restore_sequence()).unwrap()
    }

    #[test]
    fn modes_left_on_are_turned_off_at_the_end() {
        assert_eq!(restore_after(b""), "");
        assert_eq!(restore_after(b"plain \x1b[1;31mx\x1b[0m"), "");
        assert_eq!(restore_after(b"\x1b[38;5;0m"), "\x1b[0m");
        assert_eq!(restore_after(b"\x1b[38;5;0m\x1b[m"), "");
        assert_eq!(
            restore_after(
                b"\x1b[4m\x1b[?1000;1006h\x1b[?2004h\x1b[?25l\x1b[?1h\x1b[?1h\x1b[?2004l\
                  \x1b[?7l\x1b[?9999h\x1b[?9h\x1b[?2048h\x1b[?2031h\x1b[?5h\x1b[?6h\x1b[?66h"
            ),
            "\x1b[?1l\x1b[?5l\x1b[?6l\x1b[?9l\x1b[?66l\x1b[?1000l\x1b[?1006l\x1b[?2031l\
             \x1b[?2048l\x1b[?7h\x1b[?25h\x1b[0m"
        );
        // Turned back on or off, nothing is left.
        assert_eq!(
            restore_after(b"\x1b[?25l\x1b[?7l\x1b[?1000h\x1b[?25h\x1b[?7h\x1b[?1000l"),
            ""
        );
        // Insert mode, keypad, line drawing, scroll region, key modifiers.
        assert_eq!(
            restore_after(b"\x1b[4h\x1b=\x1b(0\x1b[2;20r\x1b[>4;2m\x1b[>1;1m"),
            "\x1b[4l\x1b>\x1b(B\x1b7\x1b[r\x1b8\x1b[>1m\x1b[>4m"
        );
        assert_eq!(
            restore_after(
                b"\x1b[4h\x1b=\x1b(0\x1b[2;20r\x1b[>4;2m\x1b[4l\x1b>\x1b(B\x1b[r\x1b[>4m"
            ),
            ""
        );
        // A full reset forgets everything.
        assert_eq!(restore_after(b"\x1b[?1049h\x1b[7m\x1b[4h\x1b=\x1bc"), "");
    }

    #[test]
    fn kitty_keyboard_stacks_are_restored_per_screen() {
        // Pushed on the main screen, then two on the alternate screen: the
        // alternate pops come first, then the screen is left, then the main
        // pops.
        assert_eq!(
            restore_after(b"\x1b[>1u\x1b[?1049h\x1b[>3u\x1b[>5u\x1b[?1000h"),
            "\x1b[<2u\x1b[?1049l\x1b[<1u\x1b[?1000l"
        );
        // Leaving the alternate screen forgets its stack; pops apply to the
        // current screen.
        assert_eq!(
            restore_after(b"\x1b[>1u\x1b[>1u\x1b[?1049h\x1b[>3u\x1b[?1049l\x1b[<u"),
            "\x1b[<1u"
        );
        assert_eq!(restore_after(b"\x1b[?1049h\x1b[>3u\x1b[<9u"), "\x1b[?1049l");
        // Flags set without a push are reset to zero.
        assert_eq!(restore_after(b"\x1b[=5;1u"), "\x1b[=0u");
        assert_eq!(restore_after(b"\x1b[=5;1u\x1b[=0u"), "");
        assert_eq!(restore_after(b"\x1b[?1049h\x1b[=1u"), "\x1b[=0u\x1b[?1049l");
    }

    #[test]
    fn xtrestore_and_margins_are_restored_and_other_switches_dropped() {
        assert_eq!(
            restore_after(b"\x1b[?2048h\x1b[?2048s\x1b[?2048l\x1b[?2048;7;9999r"),
            "\x1b[?2048l\x1b[?7h"
        );
        assert_eq!(restore_after(b"\x1b[?69h"), "\x1b[?69l");
        passes(b"\x1b[?2048s");
        for seq in [
            &b"\x1b[>1n"[..],
            b"\x1b[>4f",
            b"\x1b[>1h",
            b"\x1b[=1l",
            b"\x1b[<1h",
        ] {
            dropped(seq);
        }
    }

    #[test]
    fn ansi_modes_other_than_insert_and_decscl_are_dropped() {
        passes(b"\x1b[4h\x1b[4l");
        for seq in [
            &b"\x1b[12l"[..],
            b"\x1b[12h",
            b"\x1b[2h",
            b"\x1b[20h",
            b"\x1b[4;12l",
            b"\x1b[h",
            b"\x1b[61;1\"p",
            b"\x1b[64\"p",
        ] {
            dropped(seq);
        }
    }

    /// A deterministic stream of bytes biased towards escape sequences.
    fn noise(seed: u64, len: usize) -> Vec<u8> {
        const PICKS: &[u8] =
            b"\x1b\x1b\x1b[]P_^X\\;?>=<0123456789:mhlqtu\x07\x18\x9b\xc2\xe6 abc\r\n";
        let mut x = seed;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                if x % 7 == 0 {
                    (x >> 8) as u8
                } else {
                    PICKS[(x >> 16) as usize % PICKS.len()]
                }
            })
            .collect()
    }

    #[test]
    fn filtering_twice_changes_nothing_more() {
        // What the filter emits must parse back to itself, or the host
        // terminal could read it differently from the filter.
        let now = Instant::now();
        let run = |input: &[u8]| {
            let mut f = OutputFilter::new(ClipboardPolicy::Allow);
            let mut out = Vec::new();
            f.feed_at(input, now, &mut out);
            f.finish(&mut out);
            out
        };
        for seed in 1..400u64 {
            let input = noise(seed, 512);
            let once = run(&input);
            assert_eq!(run(&once), once, "seed {seed}: {input:?}");
        }
        for input in corpus() {
            let once = run(&input);
            assert_eq!(run(&once), once, "{input:?}");
        }
    }
}
