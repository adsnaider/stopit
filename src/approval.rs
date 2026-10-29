//! Approval prompts on the `stopit server` terminal (DESIGN.md §5.4).
//!
//! A sandbox cannot draw on the server's terminal, so nothing it prints can
//! forge a prompt there. The server asks about one request at a time.
//! Before reading the answer it discards keys typed earlier and waits
//! 300 ms, so keystrokes meant for something else cannot answer it. "For
//! this session" answers are remembered until the server stops, and after
//! the user denies a request, requests in its scope are denied without a
//! prompt for five seconds.

use std::collections::{HashMap, HashSet};
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::config::ApprovalTimeout;
use crate::escape::{escape_bytes, escape_message};
use crate::pty::RawMode;

/// How long a prompt ignores keys after it appears.
const ARMING_DELAY: Duration = Duration::from_millis(300);

/// How long requests in a scope are denied without a prompt after the user
/// denied one in it, so a sandbox cannot bury the user in prompts.
pub const QUIET_AFTER_DENY: Duration = Duration::from_secs(5);

/// The most characters of escaped clipboard content a prompt shows from
/// its start. Longer content shows `...` and then [`PREVIEW_TAIL`].
const PREVIEW_HEAD: usize = 160;
/// The most characters of escaped clipboard content a prompt shows from
/// its end, after [`PREVIEW_HEAD`] and `...`.
const PREVIEW_TAIL: usize = 40;

/// Something a sandbox asks the user to allow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ApprovalRequest {
    /// An OSC 52 clipboard write.
    ClipboardWrite {
        /// The selections written, such as `c`.
        targets: String,
        /// The content, base64 as the sandbox sent it.
        data: String,
    },
    /// A command through a shim (DESIGN.md §7.1).
    Command {
        /// The shim.
        shim: String,
        /// The shim rule that matched, its subcommand pattern, or
        /// `default`. An answer for the session covers the rule.
        rule: String,
        /// The profile the command runs in.
        profile: String,
        /// The command line, each argument quoted for a shell, escaped.
        command: String,
        /// The working directory in the sandbox, escaped.
        cwd: String,
    },
}

impl ApprovalRequest {
    /// What a "for this session" answer to this request covers in `profile`.
    fn scope(&self, profile: &str) -> String {
        match self {
            ApprovalRequest::ClipboardWrite { .. } => format!("{profile}\0clipboard"),
            ApprovalRequest::Command {
                shim,
                rule,
                profile: target,
                ..
            } => format!("{profile}\0command\0{shim}\0{rule}\0{target}"),
        }
    }

    /// What the prompt says about the request, escaped, or `None` if the
    /// request cannot be shown faithfully and so is denied unseen.
    fn describe(&self) -> Option<Vec<String>> {
        match self {
            ApprovalRequest::ClipboardWrite { targets, data } => {
                let content = decode_base64(data)?;
                let newlines = match content.iter().filter(|&&b| b == b'\n').count() {
                    1 => "1 newline".to_owned(),
                    n => format!("{n} newlines"),
                };
                let bytes = match content.len() {
                    1 => "1 byte".to_owned(),
                    n => format!("{n} bytes"),
                };
                Some(vec![
                    format!(
                        "write {bytes} with {newlines} to the clipboard ({})",
                        escape_message(targets)
                    ),
                    format!("content: {}", preview(&content)),
                ])
            }
            ApprovalRequest::Command {
                shim,
                rule,
                profile,
                command,
                cwd,
            } => Some(vec![
                format!("run {command}"),
                format!(
                    "in profile {}, from {cwd}",
                    escape_message(&format!("{profile:?}"))
                ),
                format!(
                    "through shim {}, rule {}",
                    escape_message(shim),
                    escape_message(rule)
                ),
            ]),
        }
    }
}

/// `content` escaped so every byte shows, line breaks and tabs included,
/// cut to its start and end when long.
fn preview(content: &[u8]) -> String {
    let escaped = escape_bytes(content);
    let count = escaped.chars().count();
    if count <= PREVIEW_HEAD + PREVIEW_TAIL {
        return escaped;
    }
    let head: String = escaped.chars().take(PREVIEW_HEAD).collect();
    let tail: String = escaped.chars().skip(count - PREVIEW_TAIL).collect();
    format!("{head} ... {tail}")
}

/// Which run asks, as the server knows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asker {
    /// The run number.
    pub run: u64,
    /// The profile the run's sandbox has.
    pub profile: String,
    /// The run's command, each argument quoted for a shell with every
    /// control character escaped.
    pub command: String,
}

/// The outcome of a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Allowed this once.
    Once,
    /// Allowed for the rest of the session, in the request's scope.
    Session,
    /// Denied by the user, so the scope is quiet for [`QUIET_AFTER_DENY`].
    DeniedByUser,
    /// Denied without the user's answer: no terminal, a timeout, a cancel,
    /// content that cannot be shown, or a denial still in effect.
    Denied,
}

impl Verdict {
    /// Whether the request may proceed.
    pub fn allows(self) -> bool {
        matches!(self, Verdict::Once | Verdict::Session)
    }
}

/// What the approver remembers.
#[derive(Default)]
struct State {
    /// Scopes allowed for the session.
    allowed: HashSet<String>,
    /// Scopes the user denied lately, with when that ends.
    quiet: HashMap<String, Instant>,
    /// Whether a prompt is on the terminal.
    prompting: bool,
    /// Log lines held back while a prompt is up.
    held: Vec<String>,
    /// Runs already told about in the log that the server cannot ask
    /// for them, so the log says it once per run.
    told_unasked: HashSet<u64>,
}

/// The server's prompter.
pub struct Approver {
    /// A non-blocking descriptor of the server's terminal of its own, read
    /// for keys and written with prompts. `None` when the server's stdin is
    /// not a terminal, and every request is denied.
    terminal: Option<OwnedFd>,
    timeout: ApprovalTimeout,
    quiet_after: Duration,
    /// How long a prompt ignores keys after it appears, [`ARMING_DELAY`]
    /// but in tests.
    arming_delay: Duration,
    /// Whether the server must be in the terminal's foreground to ask.
    /// Only tests, whose terminal is no controlling terminal, turn it off.
    require_foreground: bool,
    /// Held while a prompt is up, so prompts never overlap.
    prompt: Mutex<()>,
    state: Mutex<State>,
}

impl Approver {
    /// A prompter on the server's stdin, if it is a terminal, with
    /// `timeout` for each answer.
    pub fn on_stdio(timeout: ApprovalTimeout) -> Self {
        // A descriptor of its own, or none: a duplicate made non-blocking
        // would change the shell's stdin too.
        let terminal = match rustix::termios::isatty(io::stdin())
            .then(|| crate::pty::own_terminal_fd(io::stdin().as_fd()).ok())
            .flatten()
        {
            Some((fd, None)) => Some(fd),
            Some((fd, Some(flags))) => {
                let _ = rustix::fs::fcntl_setfl(&fd, flags);
                None
            }
            None => None,
        };
        Approver::with_terminal(terminal, timeout, QUIET_AFTER_DENY)
    }

    /// A prompter on the terminal `terminal`, non-blocking, with `timeout`
    /// for each answer and `quiet_after` after a denial.
    pub fn with_terminal(
        terminal: Option<OwnedFd>,
        timeout: ApprovalTimeout,
        quiet_after: Duration,
    ) -> Self {
        Approver {
            terminal,
            timeout,
            quiet_after,
            arming_delay: ARMING_DELAY,
            require_foreground: true,
            prompt: Mutex::new(()),
            state: Mutex::new(State::default()),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Prints `line` to stderr, or holds it until the prompt on the
    /// terminal is answered, so log lines never cut into a prompt.
    pub fn log(&self, line: &str) {
        {
            let mut state = self.state();
            if state.prompting {
                state.held.push(line.to_owned());
                return;
            }
        }
        // Printed without the lock, so a stalled stderr holds up no
        // prompt.
        print_line(line);
    }

    /// Logs once per run of `asker` that the server cannot ask, and why.
    fn tell_unasked(&self, asker: &Asker, why: &str) {
        if self.state().told_unasked.insert(asker.run) {
            self.log(&format!(
                "stopit: denied a request from run {} without asking: {why}",
                asker.run
            ));
        }
    }

    /// The verdict a remembered answer gives `scope`, if any.
    fn remembered(&self, scope: &str) -> Option<Verdict> {
        let state = self.state();
        if state.allowed.contains(scope) {
            return Some(Verdict::Session);
        }
        state
            .quiet
            .get(scope)
            .is_some_and(|until| Instant::now() < *until)
            .then_some(Verdict::Denied)
    }

    /// Decides `request` from `asker`'s sandbox. Asks on the terminal
    /// unless a remembered answer decides it. Gives up with a denial when
    /// `cancel` becomes readable, the client having gone away or the server
    /// stopping.
    pub fn decide(
        &self,
        asker: &Asker,
        request: &ApprovalRequest,
        cancel: BorrowedFd<'_>,
    ) -> Verdict {
        let scope = request.scope(&asker.profile);
        if let Some(verdict) = self.remembered(&scope) {
            return verdict;
        }
        let Some(description) = request.describe() else {
            return Verdict::Denied;
        };
        let _prompt = self.prompt.lock().unwrap_or_else(|e| e.into_inner());
        // Again under the lock: the answer to an earlier prompt may cover it,
        // and its client may have gone while it waited.
        if let Some(verdict) = self.remembered(&scope) {
            return verdict;
        }
        if readable(cancel) {
            return Verdict::Denied;
        }
        let Some(terminal) = &self.terminal else {
            self.tell_unasked(asker, "the server's stdin is not a terminal");
            return Verdict::Denied;
        };
        // In the background, touching the terminal would stop the server.
        // A terminal that is not the server's controlling terminal has no
        // foreground of the server's either.
        if self.require_foreground
            && rustix::termios::tcgetpgrp(terminal).ok() != Some(rustix::process::getpgrp())
        {
            self.tell_unasked(
                asker,
                "the server is not in the foreground of its controlling terminal",
            );
            return Verdict::Denied;
        }
        self.state().prompting = true;
        // Lets held log lines out even if asking panics.
        let prompting = Prompting(self);
        let verdict = self
            .ask(terminal.as_fd(), asker, &description, cancel)
            .unwrap_or(Verdict::Denied);
        let said = match verdict {
            Verdict::Once => "allowed once",
            Verdict::Session => "allowed for this session",
            Verdict::DeniedByUser | Verdict::Denied => "denied",
        };
        let _ = write_all(terminal.as_fd(), format!("{said}\r\n").as_bytes());
        {
            let mut state = self.state();
            match verdict {
                Verdict::Session => {
                    state.allowed.insert(scope);
                }
                Verdict::DeniedByUser => {
                    state.quiet.insert(scope, Instant::now() + self.quiet_after);
                }
                Verdict::Once | Verdict::Denied => {}
            }
        };
        drop(prompting);
        verdict
    }

    fn ask(
        &self,
        terminal: BorrowedFd<'_>,
        asker: &Asker,
        description: &[String],
        cancel: BorrowedFd<'_>,
    ) -> io::Result<Verdict> {
        let raw = RawMode::enter(terminal)?;
        let mut text = format!(
            "\x07\r\nstopit: run {} (profile {}, {}) asks to\r\n",
            asker.run,
            escape_message(&format!("{:?}", asker.profile)),
            asker.command
        );
        for line in description {
            text.push_str(&format!("  {line}\r\n"));
        }
        text.push_str("  [y] allow once  [s] allow for this session  [n] deny: ");
        write_all(terminal, text.as_bytes())?;
        // Keys typed before the prompt, and during its first moment, do not
        // count.
        flush_input(terminal);
        std::thread::sleep(self.arming_delay);
        flush_input(terminal);
        let deadline = match self.timeout {
            ApprovalTimeout::Off => None,
            ApprovalTimeout::After(after) => Some(Instant::now() + after),
        };
        let verdict = loop {
            let wait = match deadline {
                None => -1,
                Some(deadline) => {
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        break Verdict::Denied;
                    }
                    left.as_millis().min(i32::MAX as u128) as i32
                }
            };
            let mut fds = [
                libc::pollfd {
                    fd: terminal.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: cancel.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            // SAFETY: valid pollfds for the duration of the call.
            let n = unsafe { libc::poll(fds.as_mut_ptr(), 2, wait) };
            if n < 0 {
                if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                break Verdict::Denied;
            }
            if fds[1].revents != 0 {
                break Verdict::Denied;
            }
            if fds[0].revents == 0 {
                continue;
            }
            let mut key = [0u8; 1];
            match rustix::io::read(terminal, &mut key) {
                Ok(1) => match key[0] {
                    b'y' | b'Y' => break Verdict::Once,
                    b's' | b'S' => break Verdict::Session,
                    // Anything else denies, Ctrl-C and Escape included.
                    _ => break Verdict::DeniedByUser,
                },
                Ok(_) => break Verdict::Denied,
                // Another reader took the key: wait for the next one.
                Err(rustix::io::Errno::INTR | rustix::io::Errno::AGAIN) => {}
                Err(_) => break Verdict::Denied,
            }
        };
        drop(raw);
        Ok(verdict)
    }
}

/// Marks the end of a prompt when dropped, and prints the log lines held
/// meanwhile.
struct Prompting<'a>(&'a Approver);

impl Drop for Prompting<'_> {
    fn drop(&mut self) {
        let held = {
            let mut state = self.0.state();
            state.prompting = false;
            std::mem::take(&mut state.held)
        };
        for line in held {
            print_line(&line);
        }
    }
}

/// Prints `line` to stderr, ignoring errors: `eprintln!` would panic on a
/// hung-up terminal, and abort the server if that happened while a panic
/// unwinds through [`Prompting`].
fn print_line(line: &str) {
    use std::io::Write as _;
    let _ = writeln!(io::stderr(), "{line}");
}

/// Whether `fd` is readable now.
fn readable(fd: BorrowedFd<'_>) -> bool {
    let mut pollfd = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one valid pollfd for the duration of the call.
    unsafe { libc::poll(&mut pollfd, 1, 0) > 0 }
}

/// Discards keys waiting on the terminal `input`.
fn flush_input(input: BorrowedFd<'_>) {
    let _ = rustix::termios::tcflush(input, rustix::termios::QueueSelector::IFlush);
}

/// Writes all of `data` to the non-blocking terminal `fd`, waiting while it
/// is full.
fn write_all(fd: BorrowedFd<'_>, mut data: &[u8]) -> io::Result<()> {
    while !data.is_empty() {
        match rustix::io::write(fd, data) {
            Ok(n) => data = &data[n..],
            Err(rustix::io::Errno::INTR) => {}
            Err(rustix::io::Errno::AGAIN) => {
                let mut pollfd = libc::pollfd {
                    fd: fd.as_raw_fd(),
                    events: libc::POLLOUT,
                    revents: 0,
                };
                // SAFETY: one valid pollfd for the duration of the call.
                if unsafe { libc::poll(&mut pollfd, 1, 2000) } <= 0 {
                    return Err(io::Error::from(io::ErrorKind::TimedOut));
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// Whether `text` is strict standard base64: a length that is not 1 modulo
/// 4, `=` only as padding at the end, and the padding a whole group needs.
pub fn is_strict_base64(text: &str) -> bool {
    let body = text.trim_end_matches('=');
    let padding = text.len() - body.len();
    body.len() % 4 != 1
        && padding <= 2
        && (padding == 0 || text.len().is_multiple_of(4))
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

/// Decodes strict standard base64 ([`is_strict_base64`]). `None` on
/// anything else.
pub fn decode_base64(text: &str) -> Option<Vec<u8>> {
    if !is_strict_base64(text) {
        return None;
    }
    let value = |c: u8| -> u32 {
        (match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            _ => 63,
        }) as u32
    };
    let body = text.trim_end_matches('=');
    let mut out = Vec::with_capacity(body.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0;
    for c in body.bytes() {
        acc = (acc << 6) | value(c);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pty::Pty;

    #[test]
    fn base64_decodes_strictly() {
        assert_eq!(decode_base64("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(decode_base64("aGVsbG8").unwrap(), b"hello");
        assert_eq!(decode_base64("").unwrap(), b"");
        assert_eq!(decode_base64("/+8=").unwrap(), [0xff, 0xef]);
        for bad in [
            "a b",
            "aGk=cm0gLXJmIH4K",
            "aGVsbG8==",
            "a",
            "aGVsb",
            "aG=",
            "aGk===",
        ] {
            assert_eq!(decode_base64(bad), None, "{bad}");
            assert!(!is_strict_base64(bad), "{bad}");
        }
    }

    fn encode(bytes: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let n =
                chunk.iter().fold(0u32, |acc, &b| (acc << 8) | b as u32) << (8 * (3 - chunk.len()));
            for i in 0..=chunk.len() {
                out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
            }
        }
        while !out.len().is_multiple_of(4) {
            out.push('=');
        }
        out
    }

    fn write(content: &[u8]) -> ApprovalRequest {
        ApprovalRequest::ClipboardWrite {
            targets: "c".into(),
            data: encode(content),
        }
    }

    #[test]
    fn previews_show_every_byte_and_both_ends() {
        let lines = write(b"echo hi\n\tx\xff\x1b[2J").describe().unwrap();
        assert_eq!(
            lines[0],
            "write 15 bytes with 1 newline to the clipboard (c)"
        );
        assert_eq!(lines[1], "content: echo hi\\n\\tx\\xff\\u{1b}[2J");
        // Long content shows its start and its end.
        let mut long = vec![b' '; 300];
        long.extend_from_slice(b"rm -rf ~\n");
        let lines = write(&long).describe().unwrap();
        assert!(lines[1].contains(" ... "), "{}", lines[1]);
        assert!(lines[1].ends_with("rm -rf ~\\n"), "{}", lines[1]);
        assert_eq!(lines[1].chars().count(), "content: ".len() + 160 + 5 + 40);
        // At the limit nothing is cut; one more character cuts.
        let lines = write(&[b'a'; 200]).describe().unwrap();
        assert_eq!(lines[1], format!("content: {}", "a".repeat(200)));
        assert_eq!(
            lines[0],
            "write 200 bytes with 0 newlines to the clipboard (c)"
        );
        let lines = write(&[b'a'; 201]).describe().unwrap();
        assert!(lines[1].contains(" ... "), "{}", lines[1]);
        let lines = write(b"\n").describe().unwrap();
        assert_eq!(lines[0], "write 1 byte with 1 newline to the clipboard (c)");
        // Content that does not decode is not shown, and so not asked about.
        let bad = ApprovalRequest::ClipboardWrite {
            targets: "c".into(),
            data: "aGk=cm0gLXJmIH4K".into(),
        };
        assert_eq!(bad.describe(), None);
    }

    fn asker(profile: &str) -> Asker {
        Asker {
            run: 3,
            profile: profile.into(),
            command: "claude --x".into(),
        }
    }

    fn hi() -> ApprovalRequest {
        write(b"hi")
    }

    /// An approver on a fresh PTY's slave, and the master, where the test
    /// plays the user.
    struct OnPty {
        approver: Approver,
        master: OwnedFd,
        slave: OwnedFd,
        cancel: std::os::unix::net::UnixStream,
        /// Kept open, so `cancel` is never readable until dropped.
        cancel_peer: Option<std::os::unix::net::UnixStream>,
    }

    fn on_pty(timeout: ApprovalTimeout, quiet_after: Duration) -> OnPty {
        let pty = Pty::open(None, None).unwrap();
        let terminal = crate::pty::own_terminal_fd(pty.slave.as_fd()).unwrap().0;
        let mut approver = Approver::with_terminal(Some(terminal), timeout, quiet_after);
        // The PTY is not the test's controlling terminal.
        approver.require_foreground = false;
        let (cancel, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        OnPty {
            approver,
            master: pty.master,
            slave: pty.slave,
            cancel,
            cancel_peer: Some(peer),
        }
    }

    /// Reads from `master` until `needle` shows, within ten seconds.
    fn wait_for(master: &OwnedFd, needle: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut seen = Vec::new();
        let mut buf = [0u8; 1024];
        while !String::from_utf8_lossy(&seen).contains(needle) {
            assert!(
                Instant::now() < deadline,
                "{:?}",
                String::from_utf8_lossy(&seen)
            );
            let mut pollfd = libc::pollfd {
                fd: master.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one valid pollfd for the duration of the call.
            if unsafe { libc::poll(&mut pollfd, 1, 100) } > 0
                && let Ok(n) = rustix::io::read(master, &mut buf)
            {
                seen.extend_from_slice(&buf[..n]);
            }
        }
        String::from_utf8_lossy(&seen).into_owned()
    }

    /// Answers the next prompt on `master` with `key`, sending it again
    /// every 200 ms until a verdict shows, and returns what the terminal
    /// showed.
    fn answer(master: OwnedFd, key: &'static [u8]) -> std::thread::JoinHandle<String> {
        std::thread::spawn(move || {
            let mut shown = wait_for(&master, "[n] deny: ");
            let deadline = Instant::now() + Duration::from_secs(10);
            while !shown.contains("allowed") && !shown.contains("denied") {
                assert!(Instant::now() < deadline, "{shown:?}");
                rustix::io::write(&master, key).unwrap();
                let mut pollfd = libc::pollfd {
                    fd: master.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: one valid pollfd for the duration of the call.
                if unsafe { libc::poll(&mut pollfd, 1, 200) } > 0 {
                    let mut buf = [0u8; 1024];
                    if let Ok(n) = rustix::io::read(&master, &mut buf) {
                        shown.push_str(&String::from_utf8_lossy(&buf[..n]));
                    }
                }
            }
            shown
        })
    }

    #[test]
    fn the_answer_decides_and_session_answers_are_remembered() {
        let t = on_pty(
            ApprovalTimeout::After(Duration::from_secs(10)),
            QUIET_AFTER_DENY,
        );
        let before = rustix::termios::tcgetattr(&t.slave).unwrap();
        let user = answer(t.master.try_clone().unwrap(), b"y");
        assert_eq!(
            t.approver.decide(&asker("main"), &hi(), t.cancel.as_fd()),
            Verdict::Once
        );
        let shown = user.join().unwrap();
        assert!(
            shown.contains("run 3 (profile \"main\", claude --x) asks to"),
            "{shown:?}"
        );
        assert!(
            shown.contains("write 2 bytes with 0 newlines to the clipboard (c)"),
            "{shown:?}"
        );
        assert!(shown.contains("content: hi"), "{shown:?}");
        assert!(shown.contains("allowed once"), "{shown:?}");
        // The terminal's settings are back.
        let after = rustix::termios::tcgetattr(&t.slave).unwrap();
        assert_eq!(after.local_modes, before.local_modes);

        // A denial by the user quiets the scope.
        let user = answer(t.master.try_clone().unwrap(), b"n");
        assert_eq!(
            t.approver.decide(&asker("main"), &hi(), t.cancel.as_fd()),
            Verdict::DeniedByUser
        );
        assert!(user.join().unwrap().contains("denied"));
        let start = Instant::now();
        assert_eq!(
            t.approver.decide(&asker("main"), &hi(), t.cancel.as_fd()),
            Verdict::Denied
        );
        assert!(start.elapsed() < ARMING_DELAY);
        t.approver.state().quiet.clear();

        let user = answer(t.master.try_clone().unwrap(), b"s");
        assert_eq!(
            t.approver.decide(&asker("main"), &hi(), t.cancel.as_fd()),
            Verdict::Session
        );
        assert!(user.join().unwrap().contains("allowed for this session"));
        // Remembered for that profile, without a prompt; not for another.
        assert_eq!(
            t.approver.decide(&asker("main"), &hi(), t.cancel.as_fd()),
            Verdict::Session
        );
        let user = answer(t.master.try_clone().unwrap(), b"\x03");
        assert_eq!(
            t.approver
                .decide(&asker("harness"), &hi(), t.cancel.as_fd()),
            Verdict::DeniedByUser
        );
        assert!(user.join().unwrap().contains("denied"));
    }

    #[test]
    fn keys_typed_before_or_during_the_arming_delay_do_not_answer() {
        let mut t = on_pty(
            ApprovalTimeout::After(Duration::from_millis(500)),
            QUIET_AFTER_DENY,
        );
        // Long enough that the typist below always types within it.
        t.approver.arming_delay = Duration::from_secs(2);
        // Typed before the prompt.
        rustix::io::write(&t.master, b"y").unwrap();
        // And typed as soon as the prompt shows, within the arming delay.
        let master = t.master.try_clone().unwrap();
        let typist = std::thread::spawn(move || {
            wait_for(&master, "[n] deny: ");
            rustix::io::write(&master, b"y").unwrap();
            wait_for(&master, "denied")
        });
        let start = Instant::now();
        assert_eq!(
            t.approver.decide(&asker("main"), &hi(), t.cancel.as_fd()),
            Verdict::Denied
        );
        assert!(start.elapsed() >= Duration::from_millis(2500));
        assert!(typist.join().unwrap().contains("denied"));
        // A timeout is not the user's denial: no quiet period.
        assert_eq!(t.approver.remembered(&hi().scope("main")), None);
    }

    #[test]
    fn a_cancel_denies_and_skips_prompts_whose_client_left() {
        let mut t = on_pty(ApprovalTimeout::Off, QUIET_AFTER_DENY);
        // The client goes away while the prompt is up.
        let master = t.master.try_clone().unwrap();
        let peer = t.cancel_peer.take().unwrap();
        let closer = std::thread::spawn(move || {
            wait_for(&master, "[n] deny: ");
            drop(peer);
        });
        assert_eq!(
            t.approver.decide(&asker("main"), &hi(), t.cancel.as_fd()),
            Verdict::Denied
        );
        closer.join().unwrap();
        assert_eq!(t.approver.remembered(&hi().scope("main")), None);
        // Already gone: no prompt at all.
        let start = Instant::now();
        assert_eq!(
            t.approver.decide(&asker("main"), &hi(), t.cancel.as_fd()),
            Verdict::Denied
        );
        assert!(start.elapsed() < ARMING_DELAY);
    }

    #[test]
    fn prompts_are_one_at_a_time_and_a_session_answer_covers_the_queue() {
        let t = std::sync::Arc::new(on_pty(
            ApprovalTimeout::After(Duration::from_secs(10)),
            QUIET_AFTER_DENY,
        ));
        let user = answer(t.master.try_clone().unwrap(), b"s");
        let second = {
            let t = t.clone();
            std::thread::spawn(move || {
                // Starts while the first prompt is up.
                std::thread::sleep(Duration::from_millis(100));
                t.approver.decide(&asker("main"), &hi(), t.cancel.as_fd())
            })
        };
        assert_eq!(
            t.approver.decide(&asker("main"), &hi(), t.cancel.as_fd()),
            Verdict::Session
        );
        assert_eq!(second.join().unwrap(), Verdict::Session);
        let shown = user.join().unwrap();
        assert_eq!(shown.matches("asks to").count(), 1, "{shown:?}");
    }

    #[test]
    fn a_terminal_not_in_our_foreground_denies_without_asking() {
        // As for a server in the background: the PTY is not this process's
        // controlling terminal, so it is in no foreground of ours.
        let mut t = on_pty(ApprovalTimeout::Off, QUIET_AFTER_DENY);
        t.approver.require_foreground = true;
        let start = Instant::now();
        assert_eq!(
            t.approver.decide(&asker("main"), &hi(), t.cancel.as_fd()),
            Verdict::Denied
        );
        assert!(start.elapsed() < ARMING_DELAY);
    }

    #[test]
    fn without_a_terminal_or_unshowable_content_everything_is_denied() {
        let approver = Approver::with_terminal(None, ApprovalTimeout::Off, QUIET_AFTER_DENY);
        let (cancel, _other) = std::os::unix::net::UnixStream::pair().unwrap();
        assert_eq!(
            approver.decide(&asker("main"), &hi(), cancel.as_fd()),
            Verdict::Denied
        );
        let bad = ApprovalRequest::ClipboardWrite {
            targets: "c".into(),
            data: "a".into(),
        };
        assert_eq!(
            approver.decide(&asker("main"), &bad, cancel.as_fd()),
            Verdict::Denied
        );
    }

    #[test]
    fn remembered_answers_decide_without_the_lock_and_quiet_ends() {
        let approver = Approver::with_terminal(None, ApprovalTimeout::Off, QUIET_AFTER_DENY);
        let (cancel, _other) = std::os::unix::net::UnixStream::pair().unwrap();
        approver.state().allowed.insert(hi().scope("main"));
        // Long enough that a slow test thread cannot outlive it, which would
        // make `decide` wait for the lock this thread holds.
        approver.state().quiet.insert(
            hi().scope("other"),
            Instant::now() + Duration::from_secs(60),
        );
        // Held by a prompt elsewhere: remembered answers still come at once.
        let busy = approver.prompt.lock().unwrap();
        assert_eq!(
            approver.decide(&asker("main"), &hi(), cancel.as_fd()),
            Verdict::Session
        );
        assert_eq!(
            approver.decide(&asker("other"), &hi(), cancel.as_fd()),
            Verdict::Denied
        );
        drop(busy);
        // A quiet period that has ended no longer decides.
        approver
            .state()
            .quiet
            .insert(hi().scope("other"), Instant::now());
        assert_eq!(approver.remembered(&hi().scope("other")), None);
    }

    #[test]
    fn a_panicking_prompt_lets_held_lines_out() {
        let approver = Approver::with_terminal(None, ApprovalTimeout::Off, QUIET_AFTER_DENY);
        approver.state().prompting = true;
        approver.log("held");
        drop(Prompting(&approver));
        let state = approver.state();
        assert!(!state.prompting);
        assert!(state.held.is_empty());
    }

    #[test]
    fn log_lines_are_held_while_a_prompt_is_up() {
        let approver = Approver::with_terminal(None, ApprovalTimeout::Off, QUIET_AFTER_DENY);
        approver.state().prompting = true;
        approver.log("held");
        assert_eq!(approver.state().held, ["held"]);
    }
}
