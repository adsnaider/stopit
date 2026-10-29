//! The broker (DESIGN.md §7.1): runs the commands a sandbox's shims ask
//! for, each in a sandbox of the profile its shim's rules name.
//!
//! The supervisor, or the server for an attached run, starts one broker
//! per sandbox whose profile has shims, on a socket in the session
//! directory that appears at [`crate::shim::SANDBOX_BROKER_SOCKET`]. A
//! connection carries a shim's stdin, stdout, stderr and working directory
//! ([`crate::shim`]). The broker trusts nothing the shim says that it
//! cannot check, since any program in the sandbox can talk to the socket.
//!
//! * It finds the shim in the caller's profile, and decides with the shim's
//!   rules ([`decide`]). Refused flags anywhere in the arguments deny.
//! * `ask` goes to the server's prompt (§5.4). A standalone run has no one
//!   to ask and denies.
//! * The working directory must be inside the workspace. The broker opens
//!   it on the host below the workspace without following links, and
//!   compares it with the directory the shim sent. The command's sandbox
//!   then enters it itself, from its root and again without following
//!   links ([`crate::init::InitSpec::cwd`]).
//! * The command runs with an environment built from the run's, as the
//!   target profile filters it, never the shim's.
//! * The broker passes on the signals the shim forwards, kills the command
//!   when the shim's connection closes, and sends back its exit status. A
//!   refused command exits with 126 and says why on its stderr.

use std::collections::HashMap;
use std::ffi::OsString;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use rustix::process::{Pid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal};

use crate::approval::{ApprovalRequest, Approver, Asker};
use crate::bwrap::{RunExtras, TerminalSession};
use crate::config::ProfileRef;
use crate::control::{read_frame, recv_fds, write_frame};
use crate::manifest::{ShimName, ShimSpec};
use crate::policy::Decision;
use crate::shim::{BrokerMessage, HELLO, PROTOCOL_VERSION, ShimMessage};
use crate::spec::CompiledSession;
use crate::supervisor::{
    LoadedSession, RunError, bwrap_exit_code, profile_in, read_nonblocking_status,
};

/// Status of a command the broker refused.
pub const EXIT_DENIED: u8 = 126;

/// How long a shim has to send its descriptors and request.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The most commands one broker runs at once.
const MAX_COMMANDS: usize = 64;

/// The signals a shim may pass to its command.
const FORWARDED: [libc::c_int; 4] = [libc::SIGINT, libc::SIGQUIT, libc::SIGTERM, libc::SIGHUP];

/// Numbers the sandboxes brokers start, for their socket names.
static NEXT_COMMAND: AtomicU64 = AtomicU64::new(1);

/// What a run gives its brokers.
#[derive(Clone)]
pub(crate) struct RunContext {
    /// The session.
    pub(crate) loaded: Arc<LoadedSession>,
    /// The profiles as compiled for the run.
    pub(crate) compiled: Arc<CompiledSession>,
    /// The environment the run started with, which target profiles filter.
    pub(crate) host_env: Vec<(OsString, OsString)>,
    /// The server's prompter, or `None` for a standalone run.
    pub(crate) approver: Option<Arc<Approver>>,
    /// The run's number, for prompts.
    pub(crate) run: u64,
    /// The run's command, each argument quoted for a shell, for prompts.
    pub(crate) command: String,
    /// How many shim calls deep this context is: 0 for the run's own
    /// sandbox.
    pub(crate) depth: usize,
    /// The commands the run's brokers run, at every depth.
    pub(crate) live: Arc<std::sync::atomic::AtomicUsize>,
}

impl RunContext {
    /// A context for `run`, whose command is `command`.
    pub(crate) fn new(
        loaded: Arc<LoadedSession>,
        compiled: Arc<CompiledSession>,
        host_env: Vec<(OsString, OsString)>,
        approver: Option<Arc<Approver>>,
        run: u64,
        command: &[OsString],
    ) -> Self {
        RunContext {
            loaded,
            compiled,
            host_env,
            approver,
            run,
            command: command
                .iter()
                .map(|a| crate::escape::shell_quote(a.as_bytes()))
                .collect::<Vec<_>>()
                .join(" "),
            depth: 0,
            live: Arc::default(),
        }
    }
}

/// How many shim calls deep a command may run: a shim in a command a shim
/// started, and so on.
const MAX_DEPTH: usize = 4;

/// The most commands a run's brokers run at once, at every depth.
const MAX_LIVE: usize = 128;

/// The outcome of [`decide`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Run in this profile.
    Allow(ProfileRef),
    /// Ask, and run in this profile on a yes.
    Ask(ProfileRef),
    /// Refuse, saying why.
    Deny(String),
}

/// What the rules of `spec` decide for `args`, and the rule that matched,
/// its subcommand pattern or `default`.
///
/// A refused flag anywhere in the arguments denies ([`flag_matches`]): the
/// shim's own, the matched rule's, and when `default` decides, every
/// rule's, since a flag before the subcommand sends a listed subcommand
/// there too. Otherwise the rule whose pattern matches the most of the
/// words before the first flag wins. A word beats a `*` in its place, and
/// among patterns alike the strictest decision wins. No match takes the
/// shim's `default`.
pub fn decide(spec: &ShimSpec, args: &[Vec<u8>]) -> (Outcome, String) {
    // The leading arguments up to the first flag. A flag before a word
    // may take a value that would read as one, so the pattern must match
    // from the start.
    let words: Vec<&[u8]> = args
        .iter()
        .map(Vec::as_slice)
        .take_while(|a| !a.starts_with(b"-"))
        .collect();
    // The best match so far, ranked by its words, then its tokens, then
    // its strictness.
    let mut best: Option<((usize, usize, u8), &crate::manifest::ShimRule, String)> = None;
    for rule in &spec.rules {
        for pattern in &rule.subcommand {
            let tokens: Vec<&str> = pattern.tokens().collect();
            let wildcard = tokens.last() == Some(&"*");
            let fixed = &tokens[..tokens.len() - usize::from(wildcard)];
            let matches = words.len() >= fixed.len() + usize::from(wildcard)
                && fixed.iter().zip(&words).all(|(t, w)| t.as_bytes() == *w);
            if !matches {
                continue;
            }
            let rank = (fixed.len(), tokens.len(), strictness(rule.decision));
            if best.as_ref().is_none_or(|(best, _, _)| rank > *best) {
                best = Some((rank, rule, pattern.as_str().to_owned()));
            }
        }
    }
    let (decision, profile, rule_flags, name) = match &best {
        Some((_, rule, name)) => (
            rule.decision,
            rule.profile.clone(),
            rule.deny_flags.iter().collect::<Vec<_>>(),
            name.clone(),
        ),
        None => (
            spec.default.decision,
            spec.default.profile.clone(),
            spec.rules.iter().flat_map(|r| &r.deny_flags).collect(),
            "default".to_owned(),
        ),
    };
    for flag in spec.deny_flags.iter().chain(rule_flags) {
        if let Some(arg) = args.iter().find(|a| flag_matches(flag.as_str(), a)) {
            return (
                Outcome::Deny(format!(
                    "the flag {} is refused",
                    crate::escape::escape_bytes(arg)
                )),
                name,
            );
        }
    }
    let outcome = match (decision, profile) {
        (Decision::Allow, Some(p)) => Outcome::Allow(p),
        (Decision::Ask, Some(p)) => Outcome::Ask(p),
        _ => Outcome::Deny(match name.as_str() {
            "default" => "the shim's rules deny it".to_owned(),
            rule => format!("the shim's rules deny `{rule}`"),
        }),
    };
    (outcome, name)
}

fn strictness(decision: Decision) -> u8 {
    match decision {
        Decision::Allow => 0,
        Decision::Ask => 1,
        Decision::Deny => 2,
    }
}

/// Whether the argument `arg` uses the refused flag `flag`. It does when
/// it equals the flag, starts with it and `=`, abbreviates a long flag to
/// three bytes or more as git and others accept (`--upl` for
/// `--upload-pack`), or, for a one-letter flag such as `-c`, is a cluster
/// of one-letter flags that holds its letter.
fn flag_matches(flag: &str, arg: &[u8]) -> bool {
    let flag = flag.as_bytes();
    if arg == flag || (arg.starts_with(flag) && arg.get(flag.len()) == Some(&b'=')) {
        return true;
    }
    if flag.starts_with(b"--") && arg.starts_with(b"--") {
        let name = arg.split(|&b| b == b'=').next().unwrap_or(arg);
        if name.len() >= 3 && flag.starts_with(name) {
            return true;
        }
    }
    // `-c` within a cluster such as `-xc`, or with its value attached.
    flag.len() == 2
        && flag[0] == b'-'
        && flag[1] != b'-'
        && arg.len() > 2
        && arg[0] == b'-'
        && arg[1] != b'-'
        && arg[1..].contains(&flag[1])
}

/// A broker serving one sandbox. Dropping it stops it, kills the commands
/// it runs and waits for them, and removes its socket.
pub struct Broker {
    path: PathBuf,
    shared: Arc<Shared>,
    wake: OwnedFd,
    thread: Option<JoinHandle<()>>,
}

struct Shared {
    ctx: Arc<RunContext>,
    /// The profile of the sandbox the shims are in.
    caller: ProfileRef,
    stop: AtomicBool,
    /// The connections served, to shut down on stop.
    conns: Mutex<HashMap<u64, UnixStream>>,
    /// The commands running, by connection, as pidfds of their bwrap.
    commands: Mutex<HashMap<u64, OwnedFd>>,
    /// The threads serving connections, to wait for on stop.
    workers: Mutex<Vec<JoinHandle<()>>>,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

impl Broker {
    /// Starts a broker for the shims of `caller`'s sandbox, on a new
    /// socket at `path`.
    pub(crate) fn start(
        path: PathBuf,
        ctx: Arc<RunContext>,
        caller: ProfileRef,
    ) -> io::Result<Broker> {
        let listener = UnixListener::bind(&path)?;
        let started = (|| {
            listener.set_nonblocking(true)?;
            let (woken, wake) = crate::proxy::cloexec_pipe()?;
            let shared = Arc::new(Shared {
                ctx,
                caller,
                stop: AtomicBool::new(false),
                conns: Mutex::default(),
                commands: Mutex::default(),
                workers: Mutex::default(),
            });
            let thread_shared = shared.clone();
            let thread = crate::proxy::spawn_without_signals("broker", move || {
                serve(listener, woken, thread_shared)
            })?;
            Ok((shared, wake, thread))
        })();
        match started {
            Ok((shared, wake, thread)) => Ok(Broker {
                path,
                shared,
                wake,
                thread: Some(thread),
            }),
            Err(e) => {
                let _ = std::fs::remove_file(&path);
                Err(e)
            }
        }
    }

    /// The socket's host path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Broker {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        let _ = rustix::io::write(&self.wake, b"x");
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        for pidfd in lock(&self.shared.commands).values() {
            let _ = pidfd_send_signal(pidfd, Signal::KILL);
        }
        for conn in lock(&self.shared.conns).values() {
            let _ = conn.shutdown(std::net::Shutdown::Both);
        }
        let workers = std::mem::take(&mut *lock(&self.shared.workers));
        for worker in workers {
            let _ = worker.join();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

fn serve(listener: UnixListener, woken: OwnedFd, shared: Arc<Shared>) {
    let mut number = 0u64;
    loop {
        if shared.stop.load(Ordering::SeqCst) {
            return;
        }
        let mut fds = [
            libc::pollfd {
                fd: listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: woken.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: valid pollfds for the duration of the call.
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
        if fds[1].revents != 0 {
            return;
        }
        if ready < 0 {
            continue;
        }
        let conn = match listener.accept() {
            Ok((conn, _)) => conn,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(_) => {
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
        };
        let _ = conn.set_nonblocking(false);
        let mut workers = lock(&shared.workers);
        workers.retain(|w| !w.is_finished());
        if workers.len() >= MAX_COMMANDS {
            let _ = write_frame(
                &conn,
                &BrokerMessage::Error {
                    message: format!("the broker already runs {MAX_COMMANDS} commands"),
                },
            );
            continue;
        }
        number += 1;
        let Ok(copy) = conn.try_clone() else {
            continue;
        };
        lock(&shared.conns).insert(number, copy);
        let worker_shared = shared.clone();
        let this = number;
        match std::thread::Builder::new()
            .name("broker command".into())
            .spawn(move || {
                serve_shim(&conn, &worker_shared, this);
                lock(&worker_shared.conns).remove(&this);
            }) {
            Ok(worker) => workers.push(worker),
            Err(_) => {
                lock(&shared.conns).remove(&number);
            }
        }
    }
}

/// Serves the shim on `conn`, connection number `number`, and tells it how
/// its command ended.
fn serve_shim(conn: &UnixStream, shared: &Shared, number: u64) {
    let reply = match run_shim(conn, shared, number) {
        Ok(code) => BrokerMessage::Exit { code },
        Err(message) => BrokerMessage::Error { message },
    };
    let _ = write_frame(conn, &reply);
}

/// Why a request cannot go on, for the shim.
type Failure = String;

fn run_shim(conn: &UnixStream, shared: &Shared, number: u64) -> Result<u8, Failure> {
    let deadline = std::time::Instant::now() + HANDSHAKE_TIMEOUT;
    let _ = conn.set_read_timeout(Some(HANDSHAKE_TIMEOUT));
    let fds = recv_fds(conn, HELLO, 4).map_err(|e| format!("bad shim request: {e}"))?;
    let [stdin, stdout, stderr, cwd_fd]: [OwnedFd; 4] =
        fds.try_into().map_err(|_| "bad shim request".to_owned())?;
    let request = crate::control::read_frame_by::<serde_json::Value>(conn, deadline)
        .map_err(|e| format!("bad shim request: {e}"))?
        .ok_or("bad shim request: no command")?;
    if request.get("type").and_then(|t| t.as_str()) != Some("run") {
        return Err("bad shim request: no command".to_owned());
    }
    let version = request.get("version").and_then(|v| v.as_u64()).unwrap_or(0);
    if version != u64::from(PROTOCOL_VERSION) {
        return Err(format!(
            "the shim speaks protocol {version} and the broker {PROTOCOL_VERSION}. They come \
             from different builds."
        ));
    }
    let Ok(ShimMessage::Run {
        version: _,
        shim,
        args,
        cwd,
    }) = serde_json::from_value::<ShimMessage>(request)
    else {
        return Err("bad shim request: no command".to_owned());
    };
    let _ = conn.set_read_timeout(None);
    let ctx = &shared.ctx;
    let (_, caller) =
        profile_in(&ctx.compiled, Some(shared.caller.as_str())).map_err(|e| e.to_string())?;
    let name: ShimName = shim
        .parse()
        .map_err(|_| format!("no shim {}", crate::escape::escape_message(&shim)))?;
    let Some((spec, _)) = caller.spec.shims.get(&name) else {
        return Err(format!("no shim {name} in this sandbox"));
    };
    let say = |text: &str| say_to(stderr.as_fd(), text);
    // The limits come first, so no one is asked about a call that cannot
    // run anyway.
    if ctx.depth >= MAX_DEPTH {
        say(&format!(
            "{name}: shims call each other more than {MAX_DEPTH} deep"
        ));
        return Ok(EXIT_DENIED);
    }
    let Some(_slot) = LiveSlot::take(&ctx.live) else {
        say(&format!(
            "{name}: the run already has {MAX_LIVE} shim commands"
        ));
        return Ok(EXIT_DENIED);
    };
    let (outcome, rule) = decide(spec, &args);
    let cwd = PathBuf::from(OsString::from_vec(cwd));
    let rel = workspace_relative(&cwd, ctx.loaded.workspace_mount()).ok_or_else(|| {
        format!(
            "shims run only from inside the workspace, not from {}",
            crate::escape::escape_bytes(cwd.as_os_str().as_bytes())
        )
    })?;
    // What runs, the shim's binary with the arguments.
    let command_line: String = std::iter::once(spec.binary.as_str().as_bytes())
        .chain(args.iter().map(Vec::as_slice))
        .map(crate::escape::shell_quote)
        .collect::<Vec<_>>()
        .join(" ");
    let target = match outcome {
        Outcome::Deny(why) => {
            say(&format!("{name}: {why}"));
            return Ok(EXIT_DENIED);
        }
        Outcome::Allow(profile) => profile,
        Outcome::Ask(profile) => {
            let Some(approver) = &ctx.approver else {
                say(&format!(
                    "{name}: this needs a yes on a stopit server's terminal; run `stopit server` \
                     in the workspace"
                ));
                return Ok(EXIT_DENIED);
            };
            let request = ApprovalRequest::Command {
                shim: name.to_string(),
                rule: match rule.as_str() {
                    "default" => "default, for calls no rule matches, including any with a flag \
                                  before the subcommand"
                        .to_owned(),
                    rule => rule.to_owned(),
                },
                profile: profile.as_str().to_owned(),
                command: command_line.clone(),
                cwd: crate::escape::escape_bytes(cwd.as_os_str().as_bytes()),
            };
            let asker = Asker {
                run: ctx.run,
                profile: shared.caller.as_str().to_owned(),
                command: ctx.command.clone(),
            };
            if !approver.decide(&asker, &request, conn.as_fd()).allows() {
                say(&format!("{name}: denied by user"));
                return Ok(EXIT_DENIED);
            }
            profile
        }
    };
    let (dev, ino) = check_cwd(ctx.loaded.workspace_dir(), &rel, cwd_fd.as_fd())?;
    drop(cwd_fd);
    let mut command = vec![OsString::from(spec.binary.as_str())];
    command.extend(args.into_iter().map(OsString::from_vec));
    let start = crate::init::StartDir {
        path: ctx.loaded.workspace_mount().join(&rel),
        dev,
        ino,
    };
    let mut launched = launch(ctx, &target, &command, [stdin, stdout, stderr], start)
        .map_err(|e| e.to_string())?;
    let tracked = match launched.pidfd.try_clone() {
        Ok(pidfd) => pidfd,
        Err(e) => {
            // Untracked, the sandbox would outlive the broker.
            let _ = pidfd_send_signal(&launched.pidfd, Signal::KILL);
            let _ = launched.child.wait();
            return Err(e.to_string());
        }
    };
    lock(&shared.commands).insert(number, tracked);
    // Stopping between the spawn and the line above would miss it.
    if shared.stop.load(Ordering::SeqCst) {
        let _ = pidfd_send_signal(&launched.pidfd, Signal::KILL);
    }
    let code = launched.wait(conn);
    lock(&shared.commands).remove(&number);
    Ok(code)
}

/// One of a run's [`MAX_LIVE`] shim commands, given back on drop.
struct LiveSlot<'a>(&'a std::sync::atomic::AtomicUsize);

impl<'a> LiveSlot<'a> {
    /// Takes a slot from `live`, unless all are taken.
    fn take(live: &'a std::sync::atomic::AtomicUsize) -> Option<Self> {
        live.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
            (n < MAX_LIVE).then_some(n + 1)
        })
        .ok()
        .map(|_| LiveSlot(live))
    }
}

impl Drop for LiveSlot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Writes `[stopit: <text>]` to the shim's stderr, `fd`, without ever
/// waiting on it, since a sandbox can fill a pipe or stop a terminal at
/// will. The sandbox shares the open file, so its flags stay as they
/// are: a socket gets a non-blocking send, and a pipe or terminal is
/// opened again, non-blocking, for one write. A regular file takes the
/// write as it is. Anything else gets no message.
///
/// Opening again checks only the file's mode bits, not the descriptor's
/// access mode, the mount's or Landlock's, so a pipe or terminal gets the
/// message only if the sandbox opened it for writing. Otherwise the
/// broker would write for the sandbox where it may only read.
fn say_to(fd: BorrowedFd<'_>, text: &str) {
    use rustix::fs::{FileType, Mode, OFlags};
    let line = message_line(text);
    let Ok(stat) = rustix::fs::fstat(fd) else {
        return;
    };
    let file_type = FileType::from_raw_mode(stat.st_mode);
    match file_type {
        FileType::Socket => {
            let _ = rustix::net::send(
                fd,
                line.as_bytes(),
                rustix::net::SendFlags::DONTWAIT | rustix::net::SendFlags::NOSIGNAL,
            );
        }
        FileType::RegularFile => {
            let _ = rustix::io::write(fd, line.as_bytes());
        }
        FileType::Fifo | FileType::CharacterDevice => {
            let writable = rustix::fs::fcntl_getfl(fd)
                .is_ok_and(|fl| matches!(fl & OFlags::RWMODE, OFlags::WRONLY | OFlags::RDWR));
            if !writable || (file_type == FileType::CharacterDevice && !rustix::termios::isatty(fd))
            {
                return;
            }
            let path = format!("/proc/self/fd/{}", fd.as_raw_fd());
            let flags = OFlags::WRONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
            if let Ok(own) = rustix::fs::open(path, flags, Mode::empty()) {
                let _ = rustix::io::write(&own, line.as_bytes());
            }
        }
        _ => {}
    }
}

/// `[stopit: <text>]` and a newline, with `text` cut to 500 bytes at a
/// character boundary, short enough that a pipe with room takes it whole.
fn message_line(text: &str) -> String {
    let mut end = text.len().min(500);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("[stopit: {}]\n", &text[..end])
}

/// `cwd` relative to the workspace `mount`, if it is inside it and holds no
/// `..`.
fn workspace_relative(cwd: &Path, mount: &Path) -> Option<PathBuf> {
    let rel = cwd.strip_prefix(mount).ok()?;
    rel.components()
        .all(|c| matches!(c, Component::Normal(_)))
        .then(|| rel.to_owned())
}

/// Checks that `dir`, a directory the shim sent, is `rel` below the host
/// workspace `workspace`, opened without following a link, and returns its
/// device and inode.
fn check_cwd(workspace: &Path, rel: &Path, dir: BorrowedFd<'_>) -> Result<(u64, u64), Failure> {
    use rustix::fs::{Mode, OFlags, ResolveFlags, fstat, open, openat2};
    let mismatch = || {
        "the shim's working directory is not the workspace's own directory at that path. Is \
         it in an ephemeral or masked directory?"
            .to_owned()
    };
    let root = open(
        workspace,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| format!("cannot open the workspace: {e}"))?;
    let rel = if rel.as_os_str().is_empty() {
        Path::new(".")
    } else {
        rel
    };
    let host = openat2(
        &root,
        rel,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| mismatch())?;
    let (a, b) = (
        fstat(&host).map_err(|_| mismatch())?,
        fstat(dir).map_err(|_| mismatch())?,
    );
    if (a.st_dev, a.st_ino) != (b.st_dev, b.st_ino) {
        return Err(mismatch());
    }
    Ok((a.st_dev, a.st_ino))
}

/// A command's sandbox, running.
struct Launched {
    child: std::process::Child,
    pidfd: OwnedFd,
    status: std::fs::File,
    /// Kept until the sandbox ends.
    _proxy: Option<crate::proxy::Proxy>,
    _broker: Option<Broker>,
}

impl Launched {
    /// Waits for the sandbox, passing on the signals the shim on `conn`
    /// forwards and killing it if the shim goes away, and returns its exit
    /// status.
    fn wait(mut self, conn: &UnixStream) -> u8 {
        let mut shim_open = true;
        loop {
            let mut fds = vec![libc::pollfd {
                fd: self.pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            }];
            if shim_open {
                fds.push(libc::pollfd {
                    fd: conn.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                });
            }
            // SAFETY: valid pollfds for the duration of the call.
            let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
            if n < 0 {
                if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                let _ = pidfd_send_signal(&self.pidfd, Signal::KILL);
                break;
            }
            if fds[0].revents != 0 {
                break;
            }
            if shim_open && fds[1].revents != 0 {
                match read_frame::<ShimMessage>(conn) {
                    Ok(Some(ShimMessage::Signal { signal })) if FORWARDED.contains(&signal) => {
                        // SAFETY: `signal` is one of `FORWARDED`, all valid.
                        let signal = unsafe { Signal::from_raw_unchecked(signal) };
                        let _ = pidfd_send_signal(&self.pidfd, signal);
                    }
                    Ok(Some(_)) => {}
                    Ok(None) | Err(_) => {
                        shim_open = false;
                        let _ = pidfd_send_signal(&self.pidfd, Signal::KILL);
                    }
                }
            }
        }
        match self.child.wait() {
            Ok(status) => bwrap_exit_code(status, &read_nonblocking_status(self.status)),
            Err(_) => crate::supervisor::EXIT_SUPERVISOR_FAILED,
        }
    }
}

/// Starts `command` in a sandbox of `profile` on `stdio`, entering
/// `cwd`. The sandbox gets a proxy in proxy mode, a broker of its own if
/// the profile has shims, and pasta with `network = "full"`. Its command
/// is never looked up among its own shims.
fn launch(
    ctx: &Arc<RunContext>,
    profile: &ProfileRef,
    command: &[OsString],
    stdio: [OwnedFd; 3],
    cwd: crate::init::StartDir,
) -> Result<Launched, RunError> {
    let loaded = &ctx.loaded;
    let (name, compiled) = profile_in(&ctx.compiled, Some(profile.as_str()))?;
    let label = format!("t{}", NEXT_COMMAND.fetch_add(1, Ordering::SeqCst));
    let proxy = loaded.start_proxy(compiled, &label)?;
    let deeper = Arc::new(RunContext {
        depth: ctx.depth + 1,
        ..(**ctx).clone()
    });
    let broker = start_broker(&deeper, &name, compiled, &label)?;
    let extras = RunExtras {
        proxy_socket: proxy.as_ref().map(|p| p.path().to_owned()),
        broker_socket: broker.as_ref().map(|b| b.path().to_owned()),
        shims: loaded.shim_binds(&name, compiled)?,
        cwd: Some(cwd),
        skip_shims: true,
    };
    let bwrap = loaded.command(
        compiled,
        command,
        ctx.host_env.iter().cloned(),
        TerminalSession::Detach,
        &extras,
    )?;
    let pasta = match bwrap.needs_pasta() {
        true => Some(crate::net::find_pasta()?),
        false => None,
    };
    let (mut child_command, status, block) = bwrap.into_command_with_status()?;
    let [stdin, stdout, stderr] = stdio;
    child_command
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    // SAFETY: `setsid` and `sigprocmask` are async-signal-safe.
    unsafe {
        child_command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut empty: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut empty);
            if libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut()) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = child_command
        .spawn()
        .map_err(|e| crate::supervisor::spawn_error(e, pasta.is_some()))?;
    drop(child_command);
    let pidfd = match pidfd_open(Pid::from_child(&child), PidfdFlags::empty()) {
        Ok(pidfd) => pidfd,
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(RunError::Spawn(e.into()));
        }
    };
    if let (Some(pasta), Some(block)) = (&pasta, &block)
        && let Err(e) = crate::net::start_pasta(pasta, child.id(), block)
    {
        let _ = pidfd_send_signal(&pidfd, Signal::KILL);
        let _ = child.wait();
        return Err(e.into());
    }
    drop(block);
    Ok(Launched {
        child,
        pidfd,
        status,
        _proxy: proxy,
        _broker: broker,
    })
}

/// The broker for a sandbox of `profile`, named `name`, if it has shims,
/// on a socket named for `label` in the session directory.
pub(crate) fn start_broker(
    ctx: &Arc<RunContext>,
    name: &ProfileRef,
    profile: &crate::spec::CompiledProfile,
    label: &str,
) -> Result<Option<Broker>, RunError> {
    if profile.spec.shims.is_empty() {
        return Ok(None);
    }
    let path = ctx
        .loaded
        .session
        .root()
        .join(format!("broker-{label}.sock"));
    crate::server::check_socket_path(&path)?;
    Broker::start(path.clone(), ctx.clone(), name.clone())
        .map(Some)
        .map_err(|source| RunError::Broker { path, source })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{Flag, ShimAction, ShimRule, SubcommandPattern};

    fn pr(s: &str) -> ProfileRef {
        s.parse().unwrap()
    }

    fn spec(deny: &[&str], rules: Vec<ShimRule>, default: (Decision, Option<&str>)) -> ShimSpec {
        ShimSpec {
            binary: "git".parse().unwrap(),
            deny_flags: deny.iter().map(|f| f.parse::<Flag>().unwrap()).collect(),
            default: ShimAction {
                decision: default.0,
                profile: default.1.map(pr),
            },
            rules,
        }
    }

    fn rule(subs: &[&str], decision: Decision, profile: Option<&str>, deny: &[&str]) -> ShimRule {
        ShimRule {
            subcommand: subs
                .iter()
                .map(|s| s.parse::<SubcommandPattern>().unwrap())
                .collect(),
            decision,
            profile: profile.map(pr),
            deny_flags: deny.iter().map(|f| f.parse::<Flag>().unwrap()).collect(),
        }
    }

    fn args(v: &[&str]) -> Vec<Vec<u8>> {
        v.iter().map(|a| a.as_bytes().to_vec()).collect()
    }

    #[test]
    fn the_longest_matching_rule_decides_and_ties_go_strict() {
        let s = spec(
            &["-c", "--config"],
            vec![
                rule(&["status", "log"], Decision::Allow, Some("ro"), &[]),
                rule(&["op *"], Decision::Ask, Some("local"), &[]),
                rule(&["op log"], Decision::Allow, Some("ro"), &[]),
                rule(&["push"], Decision::Allow, Some("remote"), &["--force"]),
                rule(&["push"], Decision::Deny, None, &[]),
            ],
            (Decision::Ask, Some("local")),
        );
        let d = |a: &[&str]| decide(&s, &args(a));
        assert_eq!(d(&["status"]), (Outcome::Allow(pr("ro")), "status".into()));
        // Flags after the words are fine; a flag before them, whose value
        // could read as a word, takes the default.
        assert_eq!(d(&["log", "-n", "3"]).0, Outcome::Allow(pr("ro")));
        assert_eq!(d(&["--no-pager", "log"]).1, "default");
        assert_eq!(
            d(&["op", "log"]),
            (Outcome::Allow(pr("ro")), "op log".into())
        );
        assert_eq!(
            d(&["op", "restore"]),
            (Outcome::Ask(pr("local")), "op *".into())
        );
        // `op *` needs a word after `op`.
        assert_eq!(d(&["op"]), (Outcome::Ask(pr("local")), "default".into()));
        assert_eq!(d(&["rebase"]).1, "default");
        // Two rules of one length: the stricter wins.
        assert!(matches!(d(&["push"]).0, Outcome::Deny(_)));
        // A word is matched whole.
        assert_eq!(d(&["statuses"]).1, "default");
    }

    #[test]
    fn refused_flags_deny_in_every_spelling() {
        let s = spec(
            &["-c", "--config", "-C"],
            vec![
                rule(&["commit"], Decision::Allow, Some("local"), &["--amend"]),
                rule(&["show"], Decision::Allow, Some("local"), &[]),
            ],
            (Decision::Allow, Some("local")),
        );
        for bad in [
            &["-c", "x=y", "status"][..],
            &["status", "-cx=y"],
            &["-xc", "status"],
            &["--config", "a"],
            &["--config=a"],
            &["-C", "/elsewhere", "status"],
            &["commit", "--amend"],
            &["commit", "--amend=x"],
            // `default` decides these, so every rule's flags apply: a flag
            // before `commit` must not shed its refusals.
            &["--no-pager", "commit", "--amend"],
            &["log", "--amend"],
        ] {
            assert!(
                matches!(decide(&s, &args(bad)).0, Outcome::Deny(_)),
                "{bad:?}"
            );
        }
        for ok in [
            &["status"][..],
            &["--configure"],
            &["commit", "-m", "x"],
            &["commit", "-am", "x"],
        ] {
            assert!(
                !matches!(decide(&s, &args(ok)).0, Outcome::Deny(_)),
                "{ok:?}"
            );
        }
        // A rule's own flags do not apply with another rule.
        assert!(matches!(
            decide(&s, &args(&["show", "--amend"])).0,
            Outcome::Allow(_)
        ));
    }

    #[test]
    fn a_flags_value_never_reads_as_a_subcommand() {
        // Appendix A's git and jj rules, without their refused flags.
        let git = spec(
            &[],
            vec![
                rule(&["status"], Decision::Allow, Some("local"), &[]),
                rule(&["reset"], Decision::Ask, Some("local"), &[]),
            ],
            (Decision::Ask, Some("local")),
        );
        for args_ in [
            &["-C", "status", "reset"][..],
            &["--git-dir", "x", "status"],
        ] {
            assert_eq!(decide(&git, &args(args_)).1, "default", "{args_:?}");
        }
        let jj = spec(
            &[],
            vec![
                rule(&["git fetch"], Decision::Ask, Some("remote"), &[]),
                rule(&["git push"], Decision::Deny, None, &[]),
            ],
            (Decision::Ask, Some("local")),
        );
        assert!(matches!(
            decide(&jj, &args(&["git", "push"])).0,
            Outcome::Deny(_)
        ));
        // `-R fetch` between the words cannot turn a push into a fetch.
        let (outcome, rule) = decide(&jj, &args(&["git", "-R", "fetch", "push"]));
        assert_eq!(rule, "default");
        assert_eq!(outcome, Outcome::Ask(pr("local")));
    }

    #[test]
    fn abbreviated_long_flags_are_refused_too() {
        let s = spec(
            &["--upload-pack", "--receive-pack", "-c"],
            vec![rule(
                &["commit"],
                Decision::Allow,
                Some("local"),
                &["--amend"],
            )],
            (Decision::Allow, Some("local")),
        );
        for bad in [
            &["fetch", "--upl=x"][..],
            &["fetch", "--upload-pa", "x"],
            &["push", "--rec=x"],
            &["commit", "--amen"],
            &["commit", "--ame"],
            &["status", "-c", "core.pager=x"],
            // An argument after `--` is still checked; refusing too much
            // is the safe side.
            &["commit", "--", "--amend"],
        ] {
            assert!(
                matches!(decide(&s, &args(bad)).0, Outcome::Deny(_)),
                "{bad:?}"
            );
        }
        // Even one letter after the dashes may abbreviate a flag, but `--`
        // alone ends the options, and other flags pass.
        assert!(matches!(
            decide(&s, &args(&["fetch", "--u"])).0,
            Outcome::Deny(_)
        ));
        for ok in [
            &["fetch", "--"][..],
            &["fetch", "--quiet"],
            &["push", "--all"],
        ] {
            assert!(
                !matches!(decide(&s, &args(ok)).0, Outcome::Deny(_)),
                "{ok:?}"
            );
        }
    }

    #[test]
    fn odd_arguments_are_matched_as_bytes() {
        let s = spec(
            &["--config"],
            vec![rule(&["status"], Decision::Allow, Some("ro"), &[])],
            (Decision::Ask, Some("local")),
        );
        assert_eq!(decide(&s, &[]).1, "default");
        assert_eq!(decide(&s, &[b"status\0x".to_vec()]).1, "default");
        assert_eq!(decide(&s, &[vec![0xff, b's']]).1, "default");
        assert!(matches!(
            decide(&s, &[b"status".to_vec(), b"--config=\xff".to_vec()]).0,
            Outcome::Deny(_)
        ));
    }

    #[test]
    fn a_denying_default_denies() {
        let s = spec(&[], vec![], (Decision::Deny, None));
        assert!(matches!(decide(&s, &args(&["x"])).0, Outcome::Deny(_)));
    }

    #[test]
    fn the_working_directory_must_be_inside_the_workspace() {
        let mount = Path::new("/workspace");
        assert_eq!(
            workspace_relative(Path::new("/workspace"), mount),
            Some(PathBuf::new())
        );
        assert_eq!(
            workspace_relative(Path::new("/workspace/a/b"), mount),
            Some(PathBuf::from("a/b"))
        );
        for outside in [
            "/",
            "/tmp",
            "/workspacex",
            "/workspace/../etc",
            "/workspace/a/../..",
        ] {
            assert_eq!(
                workspace_relative(Path::new(outside), mount),
                None,
                "{outside}"
            );
        }
    }

    #[test]
    fn messages_are_cut_by_bytes_at_a_character() {
        assert_eq!(message_line("no"), "[stopit: no]\n");
        let long = message_line(&"é".repeat(400));
        assert!(long.ends_with("é]\n"), "{long}");
        assert_eq!(long.len(), "[stopit: ".len() + 500 + 2);
        let odd = message_line(&format!("a{}", "é".repeat(400)));
        assert_eq!(odd.len(), "[stopit: ".len() + 499 + 2);
    }

    #[test]
    fn a_message_never_waits_on_the_shims_stderr() {
        use std::io::Read;
        use std::time::{Duration, Instant};
        let blocking = |fd: BorrowedFd<'_>| {
            !rustix::fs::fcntl_getfl(fd)
                .unwrap()
                .contains(rustix::fs::OFlags::NONBLOCK)
        };
        // A pipe with room gets the line.
        let (mut r, w) = std::io::pipe().unwrap();
        say_to(w.as_fd(), "hi");
        drop(w);
        let mut got = String::new();
        r.read_to_string(&mut got).unwrap();
        assert_eq!(got, "[stopit: hi]\n");
        // The read end of a pipe gets nothing, even though opening it
        // again for writing would work.
        let (r, w) = std::io::pipe().unwrap();
        say_to(r.as_fd(), "hi");
        drop(w);
        let mut got = String::new();
        let mut r = r;
        r.read_to_string(&mut got).unwrap();
        assert_eq!(got, "");
        // A full pipe gets nothing, at once, and keeps its flags.
        let (_r, w) = std::io::pipe().unwrap();
        rustix::fs::fcntl_setfl(&w, rustix::fs::OFlags::NONBLOCK).unwrap();
        while rustix::io::write(&w, &[0u8; 4096]).is_ok() {}
        rustix::fs::fcntl_setfl(&w, rustix::fs::OFlags::empty()).unwrap();
        let started = Instant::now();
        say_to(w.as_fd(), "hi");
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(blocking(w.as_fd()));
        // So does a full socket.
        let (a, _b) = UnixStream::pair().unwrap();
        a.set_nonblocking(true).unwrap();
        while rustix::io::write(&a, &[0u8; 4096]).is_ok() {}
        a.set_nonblocking(false).unwrap();
        let started = Instant::now();
        say_to(a.as_fd(), "hi");
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(blocking(a.as_fd()));
        // A socket with room gets the line.
        let (a, mut b) = UnixStream::pair().unwrap();
        say_to(a.as_fd(), "hi");
        drop(a);
        let mut got = String::new();
        b.read_to_string(&mut got).unwrap();
        assert_eq!(got, "[stopit: hi]\n");
        // A file gets it where its own offset is.
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("log");
        std::fs::write(&path, "before\n").unwrap();
        let file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        say_to(file.as_fd(), "hi");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "before\n[stopit: hi]\n"
        );
        // A directory, or a device that is not a terminal, gets nothing.
        let null = std::fs::File::options()
            .write(true)
            .open("/dev/null")
            .unwrap();
        say_to(null.as_fd(), "hi");
        say_to(std::fs::File::open(dir.path()).unwrap().as_fd(), "hi");
    }

    #[test]
    fn the_shims_directory_must_be_the_one_it_names() {
        let ws = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(ws.path().join("a/b")).unwrap();
        std::fs::create_dir(ws.path().join("c")).unwrap();
        std::os::unix::fs::symlink("a", ws.path().join("link")).unwrap();
        let open = |p: &Path| std::fs::File::open(p).unwrap();
        let ab = open(&ws.path().join("a/b"));
        assert!(check_cwd(ws.path(), Path::new("a/b"), ab.as_fd()).is_ok());
        assert!(check_cwd(ws.path(), Path::new(""), open(ws.path()).as_fd()).is_ok());
        // Another directory, or the right one through a link, is refused.
        assert!(check_cwd(ws.path(), Path::new("c"), ab.as_fd()).is_err());
        let a = open(&ws.path().join("a"));
        assert!(check_cwd(ws.path(), Path::new("link"), a.as_fd()).is_err());
        assert!(check_cwd(ws.path(), Path::new("missing"), a.as_fd()).is_err());
    }
}
