//! Approval prompts on the `stopit server` terminal (DESIGN.md §5.4).
//!
//! A sandbox cannot draw on the server's terminal, so a prompt there cannot
//! be forged by what the sandbox prints. The server asks about one request
//! at a time. Before reading the answer it discards keys typed earlier and
//! waits a moment, so keystrokes meant for something else cannot answer it.
//! "For this session" answers are remembered until the server stops.

use std::collections::HashSet;
use std::io::{self, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::config::ApprovalTimeout;
use crate::escape::escape_message;
use crate::pty::RawMode;

/// How long a prompt ignores keys after it appears.
const ARMING_DELAY: Duration = Duration::from_millis(300);

/// How long requests in a scope are denied without a prompt after one in
/// it was denied, so a sandbox cannot bury the user in prompts.
const QUIET_AFTER_DENY: Duration = Duration::from_secs(5);

/// The most characters of clipboard content a prompt shows.
const PREVIEW_CHARS: usize = 200;

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
}

impl ApprovalRequest {
    /// What a "for this session" answer to this request covers in `profile`.
    fn scope(&self, profile: &str) -> String {
        match self {
            ApprovalRequest::ClipboardWrite { .. } => format!("{profile}\0clipboard"),
        }
    }

    /// What the prompt says about the request, escaped.
    fn describe(&self) -> Vec<String> {
        match self {
            ApprovalRequest::ClipboardWrite { targets, data } => {
                let content = decode_base64(data).unwrap_or_default();
                let text = String::from_utf8_lossy(&content);
                let mut preview: String = text.chars().take(PREVIEW_CHARS).collect();
                if text.chars().count() > PREVIEW_CHARS {
                    preview.push_str("...");
                }
                vec![
                    format!(
                        "write {} bytes to the clipboard ({})",
                        content.len(),
                        escape_message(targets)
                    ),
                    format!("content: {}", escape_message(&preview)),
                ]
            }
        }
    }
}

/// The answer to a prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// Allowed this once.
    Once,
    /// Allowed for the rest of the session, in this scope.
    Session,
    /// Denied, or no answer.
    Deny,
}

/// The server's prompter.
pub struct Approver {
    /// The terminal to ask on: where keys come from, and where the prompt
    /// goes. `None` when the server has no terminal, and every request is
    /// denied.
    terminal: Option<(OwnedFd, OwnedFd)>,
    timeout: ApprovalTimeout,
    /// Held while a prompt is up, so prompts never overlap.
    prompt: Mutex<()>,
    /// Scopes allowed for the session.
    allowed: Mutex<HashSet<String>>,
    /// Scopes denied lately, with when that ends.
    quiet: Mutex<std::collections::HashMap<String, Instant>>,
}

impl Approver {
    /// A prompter on the server's own stdin and stderr, if stdin is a
    /// terminal, with `timeout` for each answer.
    pub fn on_stdio(timeout: ApprovalTimeout) -> Self {
        let terminal = rustix::termios::isatty(io::stdin())
            .then(|| {
                let input = rustix::io::fcntl_dupfd_cloexec(io::stdin(), 3).ok()?;
                let output = rustix::io::fcntl_dupfd_cloexec(io::stderr(), 3).ok()?;
                Some((input, output))
            })
            .flatten();
        Approver::with_terminal(terminal, timeout)
    }

    /// A prompter reading keys from `terminal.0` and writing to
    /// `terminal.1`.
    pub fn with_terminal(terminal: Option<(OwnedFd, OwnedFd)>, timeout: ApprovalTimeout) -> Self {
        Approver {
            terminal,
            timeout,
            prompt: Mutex::new(()),
            allowed: Mutex::new(HashSet::new()),
            quiet: Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Whether `request` from a sandbox of `profile` is allowed. Asks on
    /// the terminal unless a "for this session" answer covers it. Gives up
    /// with a denial when `cancel` becomes readable, the client having gone
    /// away or the server stopping.
    pub fn decide(&self, profile: &str, request: &ApprovalRequest, cancel: BorrowedFd<'_>) -> bool {
        let scope = request.scope(profile);
        let _prompt = self.prompt.lock().unwrap_or_else(|e| e.into_inner());
        // After the lock: the answer to an earlier prompt may cover it.
        if self
            .allowed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&scope)
        {
            return true;
        }
        if self
            .quiet
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&scope)
            .is_some_and(|until| Instant::now() < *until)
        {
            return false;
        }
        let Some((input, output)) = &self.terminal else {
            return false;
        };
        let answer = self
            .ask(input.as_fd(), output.as_fd(), profile, request, cancel)
            .unwrap_or(Answer::Deny);
        let said = match answer {
            Answer::Once => "allowed once",
            Answer::Session => "allowed for this session",
            Answer::Deny => "denied",
        };
        let _ = write_all(output.as_fd(), format!("{said}\r\n").as_bytes());
        match answer {
            Answer::Session => {
                self.allowed
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(scope);
            }
            Answer::Deny => {
                self.quiet
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(scope, Instant::now() + QUIET_AFTER_DENY);
            }
            Answer::Once => {}
        }
        answer != Answer::Deny
    }

    fn ask(
        &self,
        input: BorrowedFd<'_>,
        output: BorrowedFd<'_>,
        profile: &str,
        request: &ApprovalRequest,
        cancel: BorrowedFd<'_>,
    ) -> io::Result<Answer> {
        let raw = RawMode::enter(input)?;
        let mut text = format!(
            "\x07\r\nstopit: a sandbox of profile {} asks to\r\n",
            escape_message(&format!("{profile:?}"))
        );
        for line in request.describe() {
            text.push_str(&format!("  {line}\r\n"));
        }
        text.push_str("  [y] allow once  [s] allow for this session  [n] deny: ");
        write_all(output, text.as_bytes())?;
        // Keys typed before the prompt, and during its first moment, do not
        // count.
        flush_input(input);
        std::thread::sleep(ARMING_DELAY);
        flush_input(input);
        let deadline = match self.timeout {
            ApprovalTimeout::Off => None,
            ApprovalTimeout::After(after) => Some(Instant::now() + after),
        };
        let answer = loop {
            let wait = match deadline {
                None => -1,
                Some(deadline) => {
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        break Answer::Deny;
                    }
                    left.as_millis().min(i32::MAX as u128) as i32
                }
            };
            let mut fds = [
                libc::pollfd {
                    fd: input.as_raw_fd(),
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
                break Answer::Deny;
            }
            if fds[1].revents != 0 {
                break Answer::Deny;
            }
            if fds[0].revents == 0 {
                continue;
            }
            let mut key = [0u8; 1];
            match rustix::io::read(input, &mut key) {
                Ok(1) => match key[0] {
                    b'y' | b'Y' => break Answer::Once,
                    b's' | b'S' => break Answer::Session,
                    // Anything else denies, Ctrl-C and Escape included.
                    _ => break Answer::Deny,
                },
                Ok(_) => break Answer::Deny,
                Err(rustix::io::Errno::INTR | rustix::io::Errno::AGAIN) => {}
                Err(_) => break Answer::Deny,
            }
        };
        drop(raw);
        Ok(answer)
    }
}

/// Discards keys waiting on the terminal `input`.
fn flush_input(input: BorrowedFd<'_>) {
    let _ = rustix::termios::tcflush(input, rustix::termios::QueueSelector::IFlush);
}

fn write_all(fd: BorrowedFd<'_>, mut data: &[u8]) -> io::Result<()> {
    while !data.is_empty() {
        match rustix::io::write(fd, data) {
            Ok(n) => data = &data[n..],
            Err(rustix::io::Errno::INTR) => {}
            Err(e) => return Err(e.into()),
        }
    }
    let _ = io::stderr().flush();
    Ok(())
}

/// Decodes standard base64, padded or not. `None` on anything else.
pub fn decode_base64(text: &str) -> Option<Vec<u8>> {
    let value = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    };
    let text = text.trim_end_matches('=');
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0;
    for c in text.bytes() {
        acc = (acc << 6) | value(c)?;
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
    fn base64_decodes() {
        assert_eq!(decode_base64("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(decode_base64("aGVsbG8").unwrap(), b"hello");
        assert_eq!(decode_base64("").unwrap(), b"");
        assert_eq!(decode_base64("/+8=").unwrap(), [0xff, 0xef]);
        assert_eq!(decode_base64("a b"), None);
    }

    #[test]
    fn clipboard_prompts_show_an_escaped_preview() {
        let request = ApprovalRequest::ClipboardWrite {
            targets: "c".into(),
            // "rm -rf ~\x1b[2J" followed by 300 x's.
            data: {
                let mut text = b"rm -rf ~\x1b[2J".to_vec();
                text.extend(std::iter::repeat_n(b'x', 300));
                encode(&text)
            },
        };
        let lines = request.describe();
        assert_eq!(lines[0], "write 312 bytes to the clipboard (c)");
        assert!(
            lines[1].starts_with("content: rm -rf ~\\u{1b}[2J"),
            "{}",
            lines[1]
        );
        assert!(lines[1].ends_with("x..."), "{}", lines[1]);
        assert!(!lines[1].contains('\x1b'));
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
        out
    }

    fn clipboard() -> ApprovalRequest {
        ApprovalRequest::ClipboardWrite {
            targets: "c".into(),
            data: "aGk=".into(),
        }
    }

    /// An approver on a fresh PTY, and the PTY's master, where the test
    /// plays the user.
    fn on_pty(timeout: ApprovalTimeout) -> (Approver, OwnedFd, std::os::unix::net::UnixStream) {
        let pty = Pty::open(None, None).unwrap();
        let output = pty.slave.try_clone().unwrap();
        let approver = Approver::with_terminal(Some((pty.slave, output)), timeout);
        let (cancel, _keep) = std::os::unix::net::UnixStream::pair().unwrap();
        std::mem::forget(_keep);
        (approver, pty.master, cancel)
    }

    /// Reads from `master` until `needle` shows, within a few seconds.
    fn wait_for(master: &OwnedFd, needle: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(5);
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

    /// Answers the next prompt on `master` with `key`, once it is armed.
    fn answer(master: OwnedFd, key: &'static [u8]) -> std::thread::JoinHandle<String> {
        std::thread::spawn(move || {
            let shown = wait_for(&master, "[n] deny: ");
            std::thread::sleep(ARMING_DELAY * 2);
            rustix::io::write(&master, key).unwrap();
            shown + &wait_for(&master, "\r\n")
        })
    }

    #[test]
    fn the_answer_decides_and_session_answers_are_remembered() {
        let (approver, master, cancel) = on_pty(ApprovalTimeout::Off);
        let user = answer(master.try_clone().unwrap(), b"y");
        assert!(approver.decide("main", &clipboard(), cancel.as_fd()));
        let shown = user.join().unwrap();
        assert!(
            shown.contains("a sandbox of profile \"main\" asks to"),
            "{shown:?}"
        );
        assert!(
            shown.contains("write 2 bytes to the clipboard (c)"),
            "{shown:?}"
        );
        assert!(shown.contains("content: hi"), "{shown:?}");
        assert!(shown.contains("allowed once"), "{shown:?}");

        let user = answer(master.try_clone().unwrap(), b"n");
        assert!(!approver.decide("main", &clipboard(), cancel.as_fd()));
        assert!(user.join().unwrap().contains("denied"));
        // Denied again at once, without a prompt.
        let start = Instant::now();
        assert!(!approver.decide("main", &clipboard(), cancel.as_fd()));
        assert!(start.elapsed() < ARMING_DELAY);
        approver.quiet.lock().unwrap().clear();

        let user = answer(master.try_clone().unwrap(), b"s");
        assert!(approver.decide("main", &clipboard(), cancel.as_fd()));
        assert!(user.join().unwrap().contains("allowed for this session"));
        // Remembered for that profile, without a prompt; not for another.
        assert!(approver.decide("main", &clipboard(), cancel.as_fd()));
        let user = answer(master.try_clone().unwrap(), b"\x03");
        assert!(!approver.decide("harness", &clipboard(), cancel.as_fd()));
        assert!(user.join().unwrap().contains("denied"));
    }

    #[test]
    fn typeahead_does_not_answer_and_no_answer_denies() {
        let (approver, master, cancel) = on_pty(ApprovalTimeout::After(Duration::from_secs(1)));
        // Typed before the prompt: discarded, so the prompt times out.
        rustix::io::write(&master, b"y").unwrap();
        let start = Instant::now();
        assert!(!approver.decide("main", &clipboard(), cancel.as_fd()));
        assert!(start.elapsed() >= Duration::from_secs(1));
        assert!(wait_for(&master, "denied").contains("denied"));
    }

    #[test]
    fn without_a_terminal_or_with_a_cancel_everything_is_denied() {
        let approver = Approver::with_terminal(None, ApprovalTimeout::Off);
        let (cancel, _other) = std::os::unix::net::UnixStream::pair().unwrap();
        assert!(!approver.decide("main", &clipboard(), cancel.as_fd()));
        // The client goes away while the prompt is up.
        let (approver, master, _) = on_pty(ApprovalTimeout::Off);
        let (cancel, other) = std::os::unix::net::UnixStream::pair().unwrap();
        let closer = std::thread::spawn(move || {
            wait_for(&master, "[n] deny: ");
            drop(other);
        });
        assert!(!approver.decide("main", &clipboard(), cancel.as_fd()));
        closer.join().unwrap();
    }
}
