//! The PTY between the sandbox and the host terminal (DESIGN.md §5.1).
//!
//! When any of the supervisor's stdio is a terminal, the sandbox gets a
//! pseudo-terminal of its own instead. Each standard descriptor that is a
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

/// A non-blocking descriptor of the terminal `fd`, and whether it shares
/// its file description with `fd`.
///
/// The file description behind the supervisor's stdio is shared with the
/// shell that started it, so setting `O_NONBLOCK` there would change the
/// shell's too. Opening the terminal again through `/proc/self/fd` gives a
/// new file description. If that fails, a duplicate of `fd` is made
/// non-blocking instead, and [`HostTerminal`] makes it blocking again when
/// dropped.
fn own_terminal_fd(fd: BorrowedFd<'_>) -> io::Result<(OwnedFd, bool)> {
    use rustix::fs::{Mode, OFlags, open};
    match open(
        format!("/proc/self/fd/{}", fd.as_raw_fd()).as_str(),
        OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(own) if rustix::termios::isatty(&own) => Ok((own, false)),
        _ => {
            let dup = rustix::io::fcntl_dupfd_cloexec(fd, 3)?;
            set_nonblocking(dup.as_fd())?;
            Ok((dup, true))
        }
    }
}

fn set_blocking(fd: BorrowedFd<'_>) -> io::Result<()> {
    use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
    let flags = fcntl_getfl(fd)?;
    fcntl_setfl(fd, flags - OFlags::NONBLOCK)?;
    Ok(())
}

/// The host terminal in raw mode, restored to its earlier settings when
/// dropped.
#[derive(Debug)]
pub struct RawMode {
    fd: OwnedFd,
    saved: Termios,
}

impl RawMode {
    /// Puts the terminal `fd` into raw mode: no echo, no line editing, and
    /// no signals from keys, all of which the sandbox's PTY does instead.
    pub fn enter(fd: BorrowedFd<'_>) -> io::Result<RawMode> {
        let fd = rustix::io::fcntl_dupfd_cloexec(fd, 3)?;
        let saved = tcgetattr(&fd)?;
        let mut raw = saved.clone();
        raw.make_raw();
        tcsetattr(&fd, OptionalActions::Now, &raw)?;
        Ok(RawMode { fd, saved })
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        // Input still queued is the sandbox's: keys typed for it, or a
        // terminal's reply to a query it sent just before it ended. None of
        // it is meant for the shell. Restoring does not wait for output to
        // drain, which a stalled terminal could make take forever.
        let _ = rustix::termios::tcflush(&self.fd, rustix::termios::QueueSelector::IFlush);
        let _ = tcsetattr(&self.fd, OptionalActions::Now, &self.saved);
    }
}

/// The host terminal as the relay uses it: where keys come from, if stdin
/// is a terminal, and where the sandbox's output goes. Both are descriptors
/// of the relay's own ([`own_terminal_fd`]).
#[derive(Debug)]
pub struct HostTerminal {
    input: Option<OwnedFd>,
    output: OwnedFd,
    /// Descriptors sharing a file description with the supervisor's stdio,
    /// made blocking again when dropped.
    shared: Vec<BorrowedFd<'static>>,
}

impl HostTerminal {
    /// The host terminal reading keys from `input`, if given, and writing
    /// output to `output`.
    pub fn open(input: Option<BorrowedFd<'_>>, output: BorrowedFd<'_>) -> io::Result<Self> {
        let input = input.map(own_terminal_fd).transpose()?;
        let (output, output_shared) = own_terminal_fd(output)?;
        let mut terminal = HostTerminal {
            input: None,
            output,
            shared: Vec::new(),
        };
        // SAFETY: the descriptors are owned by `terminal`, which drops
        // `shared` before them.
        let borrow = |fd: &OwnedFd| unsafe { BorrowedFd::borrow_raw(fd.as_raw_fd()) };
        if output_shared {
            terminal.shared.push(borrow(&terminal.output));
        }
        if let Some((input, input_shared)) = input {
            if input_shared {
                terminal.shared.push(borrow(&input));
            }
            terminal.input = Some(input);
        }
        Ok(terminal)
    }
}

impl Drop for HostTerminal {
    fn drop(&mut self) {
        for fd in self.shared.drain(..) {
            let _ = set_blocking(fd);
        }
    }
}

/// What one round of [`PtyRelay::poll_fds`] asks to wait for, each as a
/// descriptor and its `poll` events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Interest {
    /// The master, while it is read or written.
    pub master: Option<(RawFd, i16)>,
    /// The host terminal's input, while keys are read.
    pub input: Option<(RawFd, i16)>,
    /// The host terminal's output, while output waits to be written.
    pub output: Option<(RawFd, i16)>,
}

/// The most filtered output queued for the host terminal before the relay
/// stops reading the master, so a terminal that stops reading slows the
/// sandbox down instead of growing the supervisor.
const MAX_QUEUED: usize = 4 * CHUNK;

/// How long [`PtyRelay::finish`] keeps trying to write to a host terminal
/// that does not take output.
const FINISH_TIMEOUT_MS: i32 = 2000;

/// The relay between the PTY master and the host terminal.
#[derive(Debug)]
pub struct PtyRelay {
    master: OwnedFd,
    /// A slave descriptor held until the sandbox ends, so the master never
    /// hangs up while the sandbox has its own copies closed for a while.
    slave: Option<OwnedFd>,
    host: HostTerminal,
    filter: OutputFilter,
    /// Keys read from the host terminal and not yet written to the master.
    pending: Vec<u8>,
    /// Filtered output not yet written to the host terminal.
    queued: Vec<u8>,
    master_open: bool,
    input_open: bool,
    output_open: bool,
}

impl PtyRelay {
    /// A relay for `master`, keeping `slave` open until
    /// [`finish`](Self::finish), that reads keys from and writes the
    /// sandbox's output through `filter` to `host`.
    pub fn new(master: OwnedFd, slave: OwnedFd, host: HostTerminal, filter: OutputFilter) -> Self {
        let input_open = host.input.is_some();
        PtyRelay {
            master,
            slave: Some(slave),
            host,
            filter,
            pending: Vec::new(),
            queued: Vec::new(),
            master_open: true,
            input_open,
            output_open: true,
        }
    }

    /// The descriptors to wait on. The master is read while little output
    /// is queued, and waited on for writing while keys are pending; the
    /// host terminal is read only while no keys are pending, and waited on
    /// for writing while output is queued. Neither side can make the
    /// supervisor buffer more than a bound, or block it.
    pub fn poll_fds(&self) -> Interest {
        let mut master_events = 0;
        if self.master_open && self.queued.len() < MAX_QUEUED {
            master_events |= libc::POLLIN;
        }
        if self.master_open && !self.pending.is_empty() {
            master_events |= libc::POLLOUT;
        }
        let master = (master_events != 0).then(|| (self.master.as_raw_fd(), master_events));
        let input = self
            .host
            .input
            .as_ref()
            .filter(|_| self.input_open && self.master_open && self.pending.is_empty())
            .map(|fd| (fd.as_raw_fd(), libc::POLLIN));
        let output = (self.output_open && !self.queued.is_empty())
            .then(|| (self.host.output.as_raw_fd(), libc::POLLOUT));
        Interest {
            master,
            input,
            output,
        }
    }

    /// Acts on the `poll` results for the master, the host input and the
    /// host output, as [`poll_fds`](Self::poll_fds) asked (0 when not
    /// polled).
    pub fn handle(&mut self, master_revents: i16, input_revents: i16, output_revents: i16) {
        if input_revents != 0 {
            self.read_input();
        }
        if master_revents & libc::POLLOUT != 0 {
            self.write_pending();
        }
        if master_revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            self.read_master();
        }
        if output_revents != 0 || !self.queued.is_empty() {
            self.write_queued();
        }
    }

    /// Copies the host terminal's window size to the PTY, which sends
    /// `SIGWINCH` to the sandbox's foreground process group if it changed.
    pub fn resize(&self) {
        let from = std::iter::once(&self.host.output).chain(&self.host.input);
        if let Some(size) = from.filter_map(|fd| tcgetwinsize(fd).ok()).next() {
            let _ = tcsetwinsize(&self.master, size);
        }
    }

    /// Ends the relay once the sandbox is gone: passes on what it wrote
    /// last, closes any sequence it left open, and turns off the terminal
    /// modes it left on. Gives up on a host terminal that takes nothing for
    /// [`FINISH_TIMEOUT_MS`].
    pub fn finish(mut self) {
        self.slave = None;
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_millis(FINISH_TIMEOUT_MS as u64);
        let left = || {
            deadline
                .saturating_duration_since(std::time::Instant::now())
                .as_millis() as i32
        };
        // What the sandbox wrote last, while the queue has room. A process
        // that outlives the sandbox can keep writing to the slave, so the
        // drain stops at the deadline too.
        while self.master_open && left() > 0 {
            if self.queued.len() >= MAX_QUEUED {
                if !self.wait_writable(left()) {
                    break;
                }
                self.write_queued();
                continue;
            }
            if !self.read_master() {
                break;
            }
            self.write_queued();
        }
        let mut tail = Vec::new();
        self.filter.finish(&mut tail);
        tail.extend_from_slice(&self.filter.restore_sequence());
        self.queued.extend_from_slice(&tail);
        while self.output_open && !self.queued.is_empty() {
            // The restore always gets a fresh chance at the terminal.
            let wait = left().max(FINISH_TIMEOUT_MS / 4);
            if !self.wait_writable(wait) {
                break;
            }
            self.write_queued();
        }
    }

    /// Waits up to `ms` for the host terminal to take output.
    fn wait_writable(&self, ms: i32) -> bool {
        let mut pollfd = libc::pollfd {
            fd: self.host.output.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        // SAFETY: one valid pollfd for the duration of the call.
        self.output_open && unsafe { libc::poll(&mut pollfd, 1, ms) } > 0
    }

    fn read_input(&mut self) {
        let Some(input) = &self.host.input else {
            return;
        };
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

    /// Reads one chunk from the master and queues it filtered. Returns
    /// whether there may be more to read right away.
    fn read_master(&mut self) -> bool {
        let mut buf = vec![0u8; CHUNK];
        match rustix::io::read(&self.master, &mut buf) {
            Ok(0) => {
                self.master_open = false;
                false
            }
            Ok(n) => {
                self.filter.feed(&buf[..n], &mut self.queued);
                true
            }
            Err(Errno::INTR) => true,
            Err(Errno::AGAIN) => false,
            // `EIO` once no process has the slave open any more, which only
            // happens after `finish` dropped the relay's own copy.
            Err(_) => {
                self.master_open = false;
                false
            }
        }
    }

    /// Writes as much queued output as the host terminal takes now. A
    /// terminal that fails is given up on, and the output dropped, so the
    /// sandbox never blocks on it.
    fn write_queued(&mut self) {
        while self.output_open && !self.queued.is_empty() {
            match rustix::io::write(&self.host.output, &self.queued) {
                Ok(n) => {
                    self.queued.drain(..n);
                }
                Err(Errno::INTR) => {}
                Err(Errno::AGAIN) => return,
                Err(_) => {
                    self.output_open = false;
                    self.queued.clear();
                }
            }
        }
        if !self.output_open {
            self.queued.clear();
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

    /// A host terminal played by the test on the master of `host`, in raw
    /// mode, and the sandbox's PTY with the same settings, relayed.
    fn relayed() -> (Pty, Pty, PtyRelay) {
        let host = Pty::open(None, None).unwrap();
        let mut termios = tcgetattr(&host.slave).unwrap();
        termios.make_raw();
        tcsetattr(&host.slave, OptionalActions::Now, &termios).unwrap();
        let sandbox = Pty::open(Some(&termios), Some(host.slave.as_fd())).unwrap();
        let terminal = HostTerminal::open(Some(host.slave.as_fd()), host.slave.as_fd()).unwrap();
        let relay = PtyRelay::new(
            sandbox.master.try_clone().unwrap(),
            sandbox.slave.try_clone().unwrap(),
            terminal,
            OutputFilter::new(ClipboardPolicy::Block),
        );
        (host, sandbox, relay)
    }

    /// One round of the supervisor's loop, waiting up to `ms`.
    fn step(relay: &mut PtyRelay, ms: i32) {
        let interest = relay.poll_fds();
        let wanted = [interest.master, interest.input, interest.output];
        let mut fds: Vec<libc::pollfd> = wanted
            .iter()
            .flatten()
            .map(|&(fd, events)| libc::pollfd {
                fd,
                events,
                revents: 0,
            })
            .collect();
        // SAFETY: valid pollfds for the duration of the call.
        unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, ms) };
        let mut it = fds.iter();
        let mut next = |w: Option<(RawFd, i16)>| w.map_or(0, |_| it.next().unwrap().revents);
        let (m, i, o) = (next(wanted[0]), next(wanted[1]), next(wanted[2]));
        relay.handle(m, i, o);
    }

    #[test]
    fn the_relay_filters_output_and_forwards_keys() {
        let (host, sandbox, mut relay) = relayed();
        // The sandbox writes; the emulator sees it filtered.
        rustix::io::write(&sandbox.slave, b"hi\x1b]52;c;?\x07\x1b[1mthere\x1b[?1049h").unwrap();
        step(&mut relay, 200);
        step(&mut relay, 0);
        assert_eq!(read_some(host.master.as_fd()), b"hi\x1b[1mthere\x1b[?1049h");
        // Keys typed go to the sandbox unchanged.
        rustix::io::write(&host.master, b"ls\r\x03").unwrap();
        step(&mut relay, 200);
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
        assert_eq!(read_some(host.master.as_fd()), b"bye\x1b[?1049l\x1b[0m");
    }

    #[test]
    fn the_relay_survives_the_sandbox_closing_its_terminal() {
        // The sandbox closes every copy of the slave, then opens its
        // terminal again: the relay's own copy keeps the master up.
        let (host, sandbox, mut relay) = relayed();
        drop(sandbox.slave);
        step(&mut relay, 100);
        assert!(relay.poll_fds().master.is_some());
        let reopened = rustix::fs::open(
            format!(
                "/proc/self/fd/{}",
                relay.slave.as_ref().unwrap().as_raw_fd()
            )
            .as_str(),
            rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOCTTY,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        rustix::io::write(&reopened, b"again").unwrap();
        step(&mut relay, 200);
        step(&mut relay, 0);
        assert_eq!(read_some(host.master.as_fd()), b"again");
        rustix::io::write(&host.master, b"k").unwrap();
        step(&mut relay, 200);
        assert_eq!(read_some(reopened.as_fd()), b"k");
    }

    #[test]
    fn neither_side_makes_the_relay_buffer_without_bound() {
        let (host, sandbox, mut relay) = relayed();
        // The emulator stops reading: the relay queues at most a bound, then
        // stops reading the master, and the sandbox blocks on its terminal.
        set_nonblocking(sandbox.slave.as_fd()).unwrap();
        let chunk = vec![b'x'; 4096];
        let mut written = 0;
        for _ in 0..2000 {
            match rustix::io::write(&sandbox.slave, &chunk) {
                Ok(n) => written += n,
                Err(Errno::AGAIN) => {}
                Err(e) => panic!("{e}"),
            }
            step(&mut relay, 0);
            assert!(
                relay.queued.len() <= MAX_QUEUED + CHUNK,
                "{}",
                relay.queued.len()
            );
        }
        assert!(
            relay
                .poll_fds()
                .master
                .is_none_or(|(_, e)| e & libc::POLLIN == 0)
        );
        assert!(written < 2000 * 4096, "the sandbox never blocked");
        // The emulator reads again: everything arrives, in order.
        let mut got = 0;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while got < written {
            assert!(std::time::Instant::now() < deadline, "{got} of {written}");
            got += read_some_nowait(host.master.as_fd()).len();
            step(&mut relay, 10);
        }
        assert_eq!(got, written);

        // Invalid UTF-8 grows threefold through U+FFFD, still bounded.
        let bad = vec![0xffu8; 4096];
        for _ in 0..200 {
            let _ = rustix::io::write(&sandbox.slave, &bad);
            step(&mut relay, 0);
            assert!(
                relay.queued.len() <= MAX_QUEUED + 3 * CHUNK,
                "{}",
                relay.queued.len()
            );
        }
        while !read_some_nowait(host.master.as_fd()).is_empty() || !relay.queued.is_empty() {
            step(&mut relay, 10);
        }

        // The sandbox stops reading: keys stay with the host terminal once
        // the PTY's input buffer is full, and the relay keeps one chunk.
        let keys = vec![b'k'; 4096];
        for _ in 0..200 {
            let _ = rustix::io::write(&host.master, &keys);
            step(&mut relay, 0);
            assert!(relay.pending.len() <= CHUNK);
        }
    }

    /// Reads what is available on `fd` now, without waiting.
    fn read_some_nowait(fd: BorrowedFd<'_>) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = [0u8; 65536];
        let mut pollfd = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd for the duration of the call.
        while unsafe { libc::poll(&mut pollfd, 1, 0) } > 0 {
            match rustix::io::read(fd, &mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
            }
        }
        out
    }

    #[test]
    fn finish_ends_while_a_leftover_process_keeps_writing() {
        // Without a pid namespace, a process of the sandbox can outlive it
        // and keep its terminal busy.
        let (host, sandbox, relay) = relayed();
        let writer = sandbox.slave.try_clone().unwrap();
        drop(sandbox.slave);
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_writer = stop.clone();
        let busy = std::thread::spawn(move || {
            let chunk = vec![b'y'; 4096];
            while !stop_writer.load(std::sync::atomic::Ordering::SeqCst) {
                let _ = rustix::io::write(&writer, &chunk);
            }
        });
        let reader = std::thread::spawn(move || {
            let mut buf = vec![0u8; 65536];
            while rustix::io::read(&host.master, &mut buf).is_ok_and(|n| n > 0) {}
        });
        let start = std::time::Instant::now();
        relay.finish();
        assert!(
            start.elapsed() < std::time::Duration::from_millis(FINISH_TIMEOUT_MS as u64 * 3),
            "{:?}",
            start.elapsed()
        );
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        busy.join().unwrap();
        drop(reader);
    }

    #[test]
    fn finish_gives_up_on_a_terminal_that_takes_nothing() {
        let (host, sandbox, mut relay) = relayed();
        set_nonblocking(sandbox.slave.as_fd()).unwrap();
        let chunk = vec![b'x'; 4096];
        for _ in 0..200 {
            let _ = rustix::io::write(&sandbox.slave, &chunk);
            step(&mut relay, 0);
        }
        drop(sandbox.slave);
        let start = std::time::Instant::now();
        relay.finish();
        assert!(start.elapsed() < std::time::Duration::from_secs(10));
        drop(host);
    }
}
