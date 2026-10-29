//! The PTY between the sandbox and the host terminal (DESIGN.md §5.1).
//!
//! When any of the supervisor's stdio is a terminal, the sandbox gets a
//! pseudo-terminal of its own instead: each standard descriptor that is a
//! terminal becomes the PTY's slave, and `__init` makes the slave the
//! sandbox's controlling terminal. The host terminal never enters the
//! sandbox, so the sandbox cannot reach the host session's foreground
//! process group, its line discipline or its settings.
//!
//! The supervisor relays between the two ([`PtyRelay`]). Keys typed on the
//! host terminal go to the PTY master unchanged, with the host terminal in
//! raw mode so that Ctrl-C, Ctrl-Z and the rest reach the sandbox's own line
//! discipline. What the sandbox writes goes through the escape-sequence
//! filter ([`OutputFilter`]) to the host terminal. Window size changes are
//! copied to the PTY, which signals the sandbox's foreground process group.

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};

use rustix::io::Errno;
use rustix::pty::{OpenptFlags, grantpt, ioctl_tiocgptpeer, openpt, unlockpt};
use rustix::termios::{OptionalActions, Termios, tcgetattr, tcgetwinsize, tcsetattr, tcsetwinsize};

use crate::filter::OutputFilter;

/// How much the relay reads from either side at once.
const CHUNK: usize = 16 * 1024;

/// A new pseudo-terminal pair.
#[derive(Debug)]
pub struct Pty {
    /// The supervisor's side, non-blocking.
    pub master: OwnedFd,
    /// The sandbox's side.
    pub slave: OwnedFd,
}

impl Pty {
    /// Opens a pseudo-terminal whose slave starts with the settings
    /// `termios` and the window size of `size_from`, each when given and
    /// readable.
    ///
    /// The slave is opened from the master with `TIOCGPTPEER`, never by
    /// path, so no other process can swap it.
    pub fn open(termios: Option<&Termios>, size_from: Option<BorrowedFd<'_>>) -> io::Result<Pty> {
        let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC)?;
        grantpt(&master)?;
        unlockpt(&master)?;
        let slave = ioctl_tiocgptpeer(
            &master,
            OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC,
        )?;
        if let Some(termios) = termios {
            tcsetattr(&slave, OptionalActions::Now, termios)?;
        }
        if let Some(size) = size_from.and_then(|fd| tcgetwinsize(fd).ok()) {
            tcsetwinsize(&master, size)?;
        }
        set_nonblocking(master.as_fd())?;
        Ok(Pty { master, slave })
    }
}

fn set_nonblocking(fd: BorrowedFd<'_>) -> io::Result<()> {
    use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
    let flags = fcntl_getfl(fd)?;
    fcntl_setfl(fd, flags | OFlags::NONBLOCK)?;
    Ok(())
}

/// The host terminal in raw mode, restored to its earlier settings when
/// dropped.
#[derive(Debug)]
pub struct RawMode {
    fd: BorrowedFd<'static>,
    saved: Termios,
}

impl RawMode {
    /// Puts the terminal `fd` into raw mode: no echo, no line editing, and
    /// no signals from keys, all of which the sandbox's PTY does instead.
    pub fn enter(fd: BorrowedFd<'static>) -> io::Result<RawMode> {
        let saved = tcgetattr(fd)?;
        let mut raw = saved.clone();
        raw.make_raw();
        tcsetattr(fd, OptionalActions::Now, &raw)?;
        Ok(RawMode { fd, saved })
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        // Pending output is written before the change takes effect, so the
        // sandbox's last screen still renders as it expected.
        let _ = tcsetattr(self.fd, OptionalActions::Drain, &self.saved);
    }
}

/// What one round of [`PtyRelay::poll_fds`] asks to wait for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Interest {
    /// The master and its `poll` events, if it is still open.
    pub master: Option<(RawFd, i16)>,
    /// The host terminal's input and its `poll` events, if it is read now.
    pub input: Option<(RawFd, i16)>,
}

/// The relay between the PTY master and the host terminal.
#[derive(Debug)]
pub struct PtyRelay {
    master: OwnedFd,
    /// The host terminal read for keys, if stdin is one.
    input: Option<BorrowedFd<'static>>,
    /// The host terminal the sandbox's output goes to.
    output: BorrowedFd<'static>,
    filter: OutputFilter,
    /// Keys read from the host terminal and not yet written to the master.
    pending: Vec<u8>,
    master_open: bool,
    input_open: bool,
    output_open: bool,
}

impl PtyRelay {
    /// A relay for `master` that reads keys from `input`, if given, and
    /// writes the sandbox's output through `filter` to `output`.
    pub fn new(
        master: OwnedFd,
        input: Option<BorrowedFd<'static>>,
        output: BorrowedFd<'static>,
        filter: OutputFilter,
    ) -> Self {
        PtyRelay {
            master,
            input,
            output,
            filter,
            pending: Vec::new(),
            master_open: true,
            input_open: input.is_some(),
            output_open: true,
        }
    }

    /// The descriptors to wait on. The master is read whenever it is open,
    /// and waited on for writing while keys are pending; the host terminal
    /// is read only when no keys are pending, so a sandbox that stops
    /// reading cannot make the supervisor buffer without bound.
    pub fn poll_fds(&self) -> Interest {
        let master = self.master_open.then(|| {
            let mut events = libc::POLLIN;
            if !self.pending.is_empty() {
                events |= libc::POLLOUT;
            }
            (self.master.as_raw_fd(), events)
        });
        let input = self
            .input
            .filter(|_| self.input_open && self.pending.is_empty() && self.master_open)
            .map(|fd| (fd.as_raw_fd(), libc::POLLIN));
        Interest { master, input }
    }

    /// Acts on the `poll` results for the master and the host input, in
    /// the order [`poll_fds`](Self::poll_fds) gave them (0 when not polled).
    pub fn handle(&mut self, master_revents: i16, input_revents: i16) {
        if input_revents != 0 {
            self.read_input();
        }
        if master_revents & libc::POLLOUT != 0 {
            self.write_pending();
        }
        if master_revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            self.read_master();
        }
    }

    /// Copies the host terminal's window size to the PTY, which sends
    /// `SIGWINCH` to the sandbox's foreground process group if it changed.
    pub fn resize(&self) {
        let from = if rustix::termios::isatty(self.output) {
            Some(self.output)
        } else {
            self.input
        };
        if let Some(size) = from.and_then(|fd| tcgetwinsize(fd).ok()) {
            let _ = tcsetwinsize(&self.master, size);
        }
    }

    /// Ends the relay once the sandbox is gone: passes on what it wrote
    /// last, closes any sequence it left open, and turns off the terminal
    /// modes it left on.
    pub fn finish(mut self) {
        while self.master_open && self.read_master() {}
        let mut out = Vec::new();
        self.filter.finish(&mut out);
        out.extend_from_slice(&self.filter.restore_sequence());
        self.write_output(&out);
    }

    fn read_input(&mut self) {
        let Some(input) = self.input else { return };
        let mut buf = vec![0u8; CHUNK];
        match rustix::io::read(input, &mut buf) {
            Ok(0) => self.input_open = false,
            Ok(n) => {
                buf.truncate(n);
                self.pending = buf;
                self.write_pending();
            }
            Err(Errno::INTR | Errno::AGAIN) => {}
            // A hung-up terminal fails with `EIO`: nothing more to read.
            Err(_) => self.input_open = false,
        }
    }

    fn write_pending(&mut self) {
        while !self.pending.is_empty() {
            match rustix::io::write(&self.master, &self.pending) {
                Ok(n) => {
                    self.pending.drain(..n);
                }
                Err(Errno::INTR) => {}
                Err(Errno::AGAIN) => return,
                Err(_) => {
                    self.pending.clear();
                    self.master_open = false;
                }
            }
        }
    }

    /// Reads one chunk from the master and passes it on filtered. Returns
    /// whether there may be more to read right away.
    fn read_master(&mut self) -> bool {
        let mut buf = vec![0u8; CHUNK];
        match rustix::io::read(&self.master, &mut buf) {
            Ok(0) => {
                self.master_open = false;
                false
            }
            Ok(n) => {
                let mut out = Vec::with_capacity(n);
                self.filter.feed(&buf[..n], &mut out);
                self.write_output(&out);
                true
            }
            Err(Errno::INTR) => true,
            Err(Errno::AGAIN) => false,
            // `EIO` once no process has the slave open any more.
            Err(_) => {
                self.master_open = false;
                false
            }
        }
    }

    /// Writes `data` to the host terminal, waiting while it is full. A
    /// terminal that fails is given up on, and the output dropped, so the
    /// sandbox never blocks on it.
    fn write_output(&mut self, mut data: &[u8]) {
        while self.output_open && !data.is_empty() {
            match rustix::io::write(self.output, data) {
                Ok(n) => data = &data[n..],
                Err(Errno::INTR) => {}
                Err(Errno::AGAIN) => {
                    let mut pollfd = libc::pollfd {
                        fd: self.output.as_raw_fd(),
                        events: libc::POLLOUT,
                        revents: 0,
                    };
                    // SAFETY: one valid pollfd for the duration of the call.
                    unsafe { libc::poll(&mut pollfd, 1, -1) };
                }
                Err(_) => self.output_open = false,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsFd;

    use super::*;
    use crate::filter::ClipboardPolicy;

    /// Reads what is available on `fd` within a short time.
    fn read_some(fd: BorrowedFd<'_>) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        let mut pollfd = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd for the duration of the call.
        while unsafe { libc::poll(&mut pollfd, 1, 200) } > 0 {
            match rustix::io::read(fd, &mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
            }
        }
        out
    }

    #[test]
    fn the_slave_gets_the_settings_and_size_given() {
        let outer = Pty::open(None, None).unwrap();
        let size = rustix::termios::Winsize {
            ws_row: 33,
            ws_col: 101,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        tcsetwinsize(&outer.master, size).unwrap();
        let mut termios = tcgetattr(&outer.slave).unwrap();
        termios.make_raw();
        let pty = Pty::open(Some(&termios), Some(outer.slave.as_fd())).unwrap();
        let got = tcgetwinsize(&pty.slave).unwrap();
        assert_eq!((got.ws_row, got.ws_col), (33, 101));
        assert_eq!(
            tcgetattr(&pty.slave).unwrap().local_modes,
            termios.local_modes
        );
        assert!(rustix::termios::isatty(&pty.slave));
        // The master does not block.
        let mut buf = [0u8; 8];
        assert_eq!(rustix::io::read(&pty.master, &mut buf), Err(Errno::AGAIN));
    }

    #[test]
    fn raw_mode_is_restored_when_dropped() {
        let pty = Pty::open(None, None).unwrap();
        // SAFETY: the slave outlives the guard in this test.
        let fd = unsafe { BorrowedFd::borrow_raw(pty.slave.as_raw_fd()) };
        let before = tcgetattr(fd).unwrap();
        let guard = RawMode::enter(fd).unwrap();
        let raw = tcgetattr(fd).unwrap();
        assert!(
            !raw.local_modes
                .contains(rustix::termios::LocalModes::ICANON)
        );
        assert!(!raw.local_modes.contains(rustix::termios::LocalModes::ISIG));
        drop(guard);
        assert_eq!(tcgetattr(fd).unwrap().local_modes, before.local_modes);
    }

    #[test]
    fn the_relay_filters_output_and_forwards_keys() {
        // The host terminal is the slave of `host`; the test plays the
        // terminal emulator on its master.
        let host = Pty::open(None, None).unwrap();
        let mut termios = tcgetattr(&host.slave).unwrap();
        termios.make_raw();
        tcsetattr(&host.slave, OptionalActions::Now, &termios).unwrap();
        let sandbox = Pty::open(Some(&termios), Some(host.slave.as_fd())).unwrap();
        // SAFETY: `host.slave` outlives the relay in this test.
        let host_fd = unsafe { BorrowedFd::borrow_raw(host.slave.as_raw_fd()) };
        let mut relay = PtyRelay::new(
            sandbox.master,
            Some(host_fd),
            host_fd,
            OutputFilter::new(ClipboardPolicy::Block),
        );
        let step = |relay: &mut PtyRelay| {
            let interest = relay.poll_fds();
            let mut fds: Vec<libc::pollfd> = [interest.master, interest.input]
                .into_iter()
                .flatten()
                .map(|(fd, events)| libc::pollfd {
                    fd,
                    events,
                    revents: 0,
                })
                .collect();
            // SAFETY: valid pollfds for the duration of the call.
            unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, 200) };
            let master = interest.master.map_or(0, |_| fds[0].revents);
            let input = interest
                .input
                .map_or(0, |_| fds[usize::from(interest.master.is_some())].revents);
            relay.handle(master, input);
        };

        // The sandbox writes; the emulator sees it filtered.
        rustix::io::write(&sandbox.slave, b"hi\x1b]52;c;?\x07\x1b[1mthere\x1b[?1049h").unwrap();
        step(&mut relay);
        assert_eq!(read_some(host.master.as_fd()), b"hi\x1b[1mthere\x1b[?1049h");
        // Keys typed go to the sandbox unchanged.
        rustix::io::write(&host.master, b"ls\r\x03").unwrap();
        step(&mut relay);
        assert_eq!(read_some(sandbox.slave.as_fd()), b"ls\r\x03");
        // A resize reaches the sandbox's side.
        let size = rustix::termios::Winsize {
            ws_row: 50,
            ws_col: 132,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        tcsetwinsize(&host.master, size).unwrap();
        relay.resize();
        let got = tcgetwinsize(&sandbox.slave).unwrap();
        assert_eq!((got.ws_row, got.ws_col), (50, 132));
        // The sandbox's last output is passed on, and the modes it left on
        // turned off, once it is gone.
        rustix::io::write(&sandbox.slave, b"bye").unwrap();
        drop(sandbox.slave);
        relay.finish();
        assert_eq!(read_some(host.master.as_fd()), b"bye\x1b[0m\x1b[?1049l");
    }
}
