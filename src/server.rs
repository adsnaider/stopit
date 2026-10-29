//! `stopit server` and `stopit run` attaching to one (DESIGN.md §5.5).
//!
//! A server loads a workspace's session once. It checks the configuration,
//! runs the providers and provisions stopit, as a standalone run does. It
//! then listens on its control socket ([`crate::control`]) until it is
//! stopped, running one sandbox per client. It compiles the profiles again
//! for every run, so globs and masks see the filesystem as it is when the
//! sandbox starts. Every sandbox of the server shares the session, so
//! `ephemeral` directories such as `/tmp` and `~` carry over between them.
//!
//! The client is `stopit run` or `stopit shell`. It keeps the terminal side
//! to itself, with the PTY, raw mode and the output filter, and sends the
//! server the descriptors for the sandbox's stdio, the command and its
//! environment. The server never gives a sandbox its own terminal. A
//! sandbox runs on the client's PTY, or detached.

use std::collections::HashMap;
use std::ffi::OsString;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{ExitCode, Stdio};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use rustix::process::{Pid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal};

use crate::approval::{ApprovalRequest, Approver, Asker, QUIET_AFTER_DENY, Verdict};
use crate::bwrap::TerminalSession;
use crate::config::ClipboardWrite;
use crate::control::{
    ClientMessage, Hello, PROTOCOL_VERSION, ServerMessage, peer_uid, read_frame, read_request,
    recv_hello, send_approval_hello, send_stdio, write_frame,
};
use crate::escape::escape_message;
use crate::filter::ClipboardPolicy;
use crate::filter::ClipboardRequest;
use crate::session::{CONTROL_SOCKET, LiveServer, ServerRecord, live_servers};
use crate::supervisor::{
    BlockedSignals, EXIT_SUPERVISOR_FAILED, Invocation, LoadedSession, RunError, SandboxTerminal,
    blocked_writes, bwrap_exit_code, catch_signals, catch_winch, check_foreground,
    discover_workspace, ignore_job_control, print_error, profile_in, read_nonblocking_status,
    readable_unless_signal, relay_until, signal_exit_code, stdio_terminals, take_signal,
};

/// The signals a client may pass to its sandbox.
const FORWARDED: [libc::c_int; 4] = [libc::SIGINT, libc::SIGQUIT, libc::SIGTERM, libc::SIGHUP];

/// The most clients a server serves at once.
const MAX_CLIENTS: usize = 64;

/// How long a client has to send its descriptors and request.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The longest path a Unix socket address holds (`sun_path` less its NUL).
const MAX_SOCKET_PATH: usize = 107;

/// `stopit server [--workspace DIR] [-q]`: serves the workspace's session
/// until a signal stops it, and returns the status to exit with, `128 + N`
/// for signal `N`.
pub fn serve(workspace: Option<PathBuf>, quiet: bool) -> ExitCode {
    match run_server(workspace.as_deref(), quiet) {
        Ok(code) => code,
        Err(e) => {
            print_error(&e.to_string());
            match take_signal() {
                Some(signal) => ExitCode::from(signal_exit_code(signal)),
                None => ExitCode::from(EXIT_SUPERVISOR_FAILED),
            }
        }
    }
}

/// A run the server knows about.
struct Run {
    /// A descriptor of the client's connection, shut down to wake the
    /// worker when the server stops.
    conn: UnixStream,
    /// A pidfd of the run's bwrap while it runs. Signals sent through it
    /// can never reach another process, even once bwrap is reaped.
    pidfd: Option<OwnedFd>,
    /// Who the run is, for approval prompts, once its sandbox starts.
    asker: Option<Asker>,
}

/// What the server and its workers share.
#[derive(Default)]
struct Runs {
    /// Set once the server stops. No new sandbox starts after it.
    stopping: bool,
    by_number: HashMap<u64, Run>,
}

type SharedRuns = Arc<Mutex<Runs>>;

fn lock(runs: &SharedRuns) -> MutexGuard<'_, Runs> {
    runs.lock().unwrap_or_else(|e| e.into_inner())
}

fn run_server(workspace: Option<&Path>, quiet: bool) -> Result<ExitCode, RunError> {
    catch_signals().map_err(RunError::Signals)?;
    // The server holds every client's environment, so no process of the
    // user may read its memory through ptrace or /proc.
    // SAFETY: a plain prctl with integer arguments.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    let cwd = std::env::current_dir().map_err(RunError::Cwd)?;
    // One server per workspace, decided by a lock rather than by looking,
    // and before any provider runs.
    let workspace_dir = discover_workspace(&cwd, workspace)?.dir;
    let _workspace_lock = lock_workspace(&workspace_dir)?;
    let loaded = LoadedSession::load(&cwd, workspace)?;
    for line in loaded.warning_lines() {
        eprintln!("{line}");
    }
    // From here on, every line goes through the approver, which holds it
    // back while a prompt is up.
    let approver = Arc::new(Approver::on_stdio(loaded.approval_timeout()));
    let control = loaded.session.control_dir()?;
    let socket_path = control.join(CONTROL_SOCKET);
    check_socket_path(&socket_path)?;
    let listen_error = |source| RunError::Listen {
        path: socket_path.clone(),
        source,
    };
    let listener = UnixListener::bind(&socket_path).map_err(listen_error)?;
    listener.set_nonblocking(true).map_err(listen_error)?;
    let record_path = loaded.session.root().join(crate::session::SERVER_FILE);
    loaded
        .session
        .write_server_record(&ServerRecord::new(&loaded.workspace.dir))
        .map_err(|source| RunError::ServerRecord {
            path: record_path,
            source,
        })?;
    if !quiet {
        approver.log(&format!(
            "stopit: serving {} as session {}; `stopit run` and `stopit shell` there attach to it",
            escape_message(&format!("{:?}", loaded.workspace.dir)),
            loaded.session.id()
        ));
    }
    let loaded = Arc::new(loaded);
    // Blocked from here on in every thread, including the workers spawned
    // below, and only unblocked while the main thread waits.
    let mask = BlockedSignals::block().map_err(RunError::Signals)?;
    let runs: SharedRuns = Arc::default();
    let mut workers = Vec::new();
    let mut next_run = 1u64;
    let ended: Result<libc::c_int, RunError> = loop {
        if let Some(signal) = take_signal() {
            break Ok(signal);
        }
        let mut fds = [libc::pollfd {
            fd: listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        }];
        match mask.wait(&mut fds) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => break Err(listen_error(e)),
        }
        let conn = match listener.accept() {
            Ok((conn, _)) => conn,
            Err(e) if matches!(e.raw_os_error(), Some(libc::EMFILE | libc::ENFILE)) => {
                // Out of descriptors: give running sandboxes a chance to end
                // rather than spin.
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(_) => continue,
        };
        workers.retain(|w: &std::thread::JoinHandle<()>| !w.is_finished());
        // The control directory is private, which is what keeps sandboxes
        // out. The uid is checked as well, though a sandbox's user
        // namespace maps it to the user's own.
        if peer_uid(&conn).ok() != Some(rustix::process::getuid().as_raw()) {
            continue;
        }
        let _ = conn.set_nonblocking(false);
        let run = next_run;
        next_run += 1;
        let refused = match conn.try_clone() {
            Err(e) => Some(format!("the server cannot take the connection: {e}")),
            Ok(copy) => {
                let mut runs = lock(&runs);
                if runs.by_number.len() >= MAX_CLIENTS {
                    Some(format!("the server already runs {MAX_CLIENTS} sandboxes"))
                } else {
                    runs.by_number.insert(
                        run,
                        Run {
                            conn: copy,
                            pidfd: None,
                            asker: None,
                        },
                    );
                    None
                }
            }
        };
        if let Some(message) = refused {
            let _ = write_frame(&conn, &ServerMessage::Error { message });
            continue;
        }
        let worker_loaded = loaded.clone();
        let worker_runs = runs.clone();
        let worker_approver = approver.clone();
        match std::thread::Builder::new()
            .name(format!("run {run}"))
            .spawn(move || {
                serve_client(
                    conn,
                    &worker_loaded,
                    &worker_approver,
                    &worker_runs,
                    run,
                    quiet,
                )
            }) {
            Ok(worker) => workers.push(worker),
            Err(_) => {
                lock(&runs).by_number.remove(&run);
            }
        }
    };
    if !quiet {
        approver.log("stopit: stopping the server and its sandboxes");
    }
    {
        let mut runs = lock(&runs);
        runs.stopping = true;
        for run in runs.by_number.values() {
            if let Some(pidfd) = &run.pidfd {
                let _ = pidfd_send_signal(pidfd, Signal::KILL);
            }
            // Wakes a worker waiting to read from its client, which can
            // still tell the client how the run ended.
            let _ = run.conn.shutdown(std::net::Shutdown::Read);
        }
    }
    for worker in workers {
        let _ = worker.join();
    }
    // The last reference: removes the session directory.
    drop(loaded);
    Ok(ExitCode::from(signal_exit_code(ended?)))
}

/// Takes the lock that makes the server the only one for `workspace`. That
/// is an exclusive `flock` on `server-<hash>.lock` next to the session
/// directories, held until the server ends.
fn lock_workspace(workspace: &Path) -> Result<std::fs::File, RunError> {
    use rustix::fs::{FlockOperation, flock};
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::OpenOptionsExt;
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|d| !d.is_empty())
        .ok_or(RunError::Session(
            crate::session::SessionError::RuntimeDirUnset,
        ))?;
    let base = crate::session::runtime_base(Path::new(&runtime))?;
    let hash = Sha256::digest(workspace.as_os_str().as_bytes());
    let name: String = hash[..8].iter().map(|b| format!("{b:02x}")).collect();
    let path = base.join(format!("server-{name}.lock"));
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .map_err(|source| RunError::WorkspaceLock {
            path: path.clone(),
            source,
        })?;
    match flock(&file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(file),
        Err(rustix::io::Errno::WOULDBLOCK) => {
            let other = live_servers(Some(runtime.as_os_str()))
                .into_iter()
                .find(|s| s.record.workspace() == workspace);
            Err(RunError::ServerRunning {
                workspace: workspace.to_owned(),
                which: match other {
                    Some(s) => format!("as session {} (pid {})", s.id, s.record.pid),
                    None => "and is still starting".to_owned(),
                },
            })
        }
        Err(e) => Err(RunError::WorkspaceLock {
            path,
            source: e.into(),
        }),
    }
}

/// Fails when `path` does not fit in a Unix socket address.
pub(crate) fn check_socket_path(path: &Path) -> Result<(), RunError> {
    let len = path.as_os_str().len();
    if len > MAX_SOCKET_PATH {
        return Err(RunError::SocketPathTooLong {
            path: path.to_owned(),
            len,
        });
    }
    Ok(())
}

/// Serves client `conn` as connection number `run`: runs the sandbox it
/// asks for and reports how it ended, or answers its approval request.
/// Forgets the connection after. Every error goes back to the client.
fn serve_client(
    conn: UnixStream,
    loaded: &Arc<LoadedSession>,
    approver: &Arc<Approver>,
    runs: &SharedRuns,
    run: u64,
    quiet: bool,
) {
    // A client that connects and sends nothing must not hold a worker, or
    // the server's shutdown, for ever.
    let hello = conn
        .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
        .and_then(|()| recv_hello(&conn));
    let result = match hello {
        Ok(Hello::Run(stdio)) => run_for_client(&conn, stdio, loaded, approver, runs, run, quiet),
        Ok(Hello::Approve) => {
            approve_for_client(&conn, approver, runs);
            lock(runs).by_number.remove(&run);
            return;
        }
        Err(e) => Err(RunError::Client(e)),
    };
    match result {
        Ok(code) => {
            let _ = write_frame(&conn, &ServerMessage::Exit { code });
            // The client may still relay the sandbox's last output, and ask
            // about clipboard writes in it, so the run stays known until
            // the client hangs up. A stopping server shuts the connection
            // down, which ends this wait.
            let _ = conn.set_read_timeout(None);
            while let Ok(Some(_)) = read_frame::<ClientMessage>(&conn) {}
            lock(runs).by_number.remove(&run);
        }
        Err(e) => {
            lock(runs).by_number.remove(&run);
            if !quiet {
                approver.log(&format!(
                    "stopit: run {run} failed: {}",
                    escape_message(&e.to_string())
                ));
            }
            let _ = write_frame(
                &conn,
                &ServerMessage::Error {
                    message: e.to_string(),
                },
            );
        }
    }
}

/// Reads an approval request from `conn`, asks `approver`, and answers.
/// The request names its run, whose profile and command the server knows,
/// and a run the server does not know is denied. So is the request if the
/// client goes away or the server stops while the prompt is up.
fn approve_for_client(conn: &UnixStream, approver: &Approver, runs: &SharedRuns) {
    let request = read_request(conn);
    let _ = conn.set_read_timeout(None);
    let Ok(Some(ClientMessage::Approve { run, request })) = request else {
        return;
    };
    let asker = lock(runs).by_number.get(&run).and_then(|r| r.asker.clone());
    let verdict = match asker {
        Some(asker) => approver.decide(&asker, &request, conn.as_fd()),
        None => Verdict::Denied,
    };
    let _ = write_frame(
        conn,
        &ServerMessage::Decision {
            allow: verdict.allows(),
            session: verdict == Verdict::Session,
            quiet: verdict == Verdict::DeniedByUser,
        },
    );
}

fn run_for_client(
    conn: &UnixStream,
    stdio: [OwnedFd; 3],
    loaded: &Arc<LoadedSession>,
    approver: &Arc<Approver>,
    runs: &SharedRuns,
    run: u64,
    quiet: bool,
) -> Result<u8, RunError> {
    let protocol = RunError::Client;
    let Some(ClientMessage::Run {
        version: _,
        profile,
        command,
        env,
        pty,
        quiet: client_quiet,
    }) = read_request(conn).map_err(protocol)?
    else {
        return Err(protocol(io::Error::new(
            io::ErrorKind::InvalidData,
            "the client did not ask to run a command",
        )));
    };
    conn.set_read_timeout(None).map_err(protocol)?;
    let command: Vec<OsString> = command.into_iter().map(OsString::from_vec).collect();
    if command.is_empty() {
        return Err(protocol(io::Error::new(
            io::ErrorKind::InvalidData,
            "the client sent no command",
        )));
    }
    let env: Vec<(OsString, OsString)> = env
        .into_iter()
        .map(|(k, v)| (OsString::from_vec(k), OsString::from_vec(v)))
        .collect();
    // Compiled for this run, against the filesystem as it is now.
    let (compiled, compile_warnings) = loaded.recompile()?;
    let compiled = Arc::new(compiled);
    let (profile_name, profile) = profile_in(&compiled, profile.as_deref())?;
    let mut lines = loaded.warning_lines_with(&compile_warnings);
    if !client_quiet {
        lines.extend(loaded.summary_lines(&profile_name, profile));
    }
    // The server's own terminal never reaches a sandbox. On the client's
    // PTY `__init` starts a session, and otherwise bwrap detaches it.
    let terminal = if pty {
        TerminalSession::Pty
    } else {
        TerminalSession::Detach
    };
    let proxy = loaded.start_proxy(profile, &run.to_string())?;
    let ctx = Arc::new(crate::broker::RunContext {
        loaded: loaded.clone(),
        compiled: compiled.clone(),
        host_env: env,
        approver: Some(approver.clone()),
        run,
    });
    let broker = crate::broker::start_broker(&ctx, &profile_name, profile, &run.to_string())?;
    let extras = crate::bwrap::RunExtras {
        proxy_socket: proxy.as_ref().map(|p| p.path().to_owned()),
        broker_socket: broker.as_ref().map(|b| b.path().to_owned()),
        shims: loaded.shim_binds(&profile_name, profile)?,
        cwd: None,
    };
    let bwrap = loaded.command(
        profile,
        &command,
        ctx.host_env.iter().cloned(),
        terminal,
        &extras,
    )?;
    let pasta = match bwrap.needs_pasta() {
        true => Some(crate::net::find_pasta()?),
        false => None,
    };
    let (mut child_command, status_reader, block) = bwrap.into_command_with_status()?;
    let [stdin, stdout, stderr] = stdio;
    child_command
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    // SAFETY: `setsid` and `sigprocmask` are async-signal-safe.
    unsafe {
        child_command.pre_exec(|| {
            // Out of the server's session, so not even bwrap has the
            // server's terminal as its controlling terminal.
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            // The server's threads block the signals it catches, and bwrap
            // must be killable by them.
            let mut empty: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut empty);
            if libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut()) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    // Spawned under the lock, so a stopping server either sees the pidfd
    // and kills the sandbox, or this run sees `stopping` and starts none.
    let (mut child, pidfd, asker) = {
        let mut runs = lock(runs);
        if runs.stopping {
            return Err(RunError::ServerStopping);
        }
        let child = child_command
            .spawn()
            .map_err(|e| crate::supervisor::spawn_error(e, pasta.is_some()))?;
        let pidfd = match pidfd_open(Pid::from_child(&child), PidfdFlags::empty()) {
            Ok(pidfd) => pidfd,
            Err(e) => {
                let mut child = child;
                let _ = child.kill();
                let _ = child.wait();
                return Err(RunError::Spawn(e.into()));
            }
        };
        let asker = Asker {
            run,
            profile: profile_name.as_str().to_owned(),
            command: command
                .iter()
                .map(|a| crate::escape::shell_quote(a.as_bytes()))
                .collect::<Vec<_>>()
                .join(" "),
        };
        if let Some(entry) = runs.by_number.get_mut(&run) {
            entry.pidfd = pidfd.try_clone().ok();
            entry.asker = Some(asker.clone());
        }
        (child, pidfd, asker)
    };
    drop(child_command);
    if let (Some(pasta), Some(block)) = (&pasta, &block)
        && let Err(e) = crate::net::start_pasta(pasta, child.id(), block)
    {
        // Killed before `block` closes, which would let bwrap go on.
        let _ = pidfd_send_signal(&pidfd, Signal::KILL);
        let _ = child.wait();
        // A stopping server killed bwrap, which is what pasta found.
        if lock(runs).stopping {
            return Err(RunError::ServerStopping);
        }
        return Err(e.into());
    }
    drop(block);
    if !quiet {
        approver.log(&format!(
            "stopit: run {run} started: profile {}: {}",
            escape_message(&format!("{:?}", asker.profile)),
            asker.command
        ));
    }
    let started = write_frame(
        conn,
        &ServerMessage::Started {
            run,
            lines,
            clipboard: loaded.clipboard_write(),
        },
    );
    if started.is_err() {
        let _ = pidfd_send_signal(&pidfd, Signal::KILL);
    } else {
        wait_child_or_client(conn, pidfd.as_fd());
    }
    let status = child.wait().map_err(RunError::Spawn)?;
    let code = bwrap_exit_code(status, &read_nonblocking_status(status_reader));
    // The commands the shims started go with the sandbox.
    drop(broker);
    if let Some(proxy) = proxy {
        let (hosts, count) = proxy.denied();
        if let Some(report) = crate::proxy::denied_report(&hosts, count) {
            approver.log(&format!("stopit: run {run}: {}", escape_message(&report)));
        }
    }
    if !quiet {
        approver.log(&format!("stopit: run {run} ended with status {code}"));
    }
    Ok(code)
}

/// Waits until the process of `pidfd` exits, passing it the signals the
/// client sends, and killing it if the client goes away.
fn wait_child_or_client(conn: &UnixStream, pidfd: BorrowedFd<'_>) {
    let mut client_open = true;
    loop {
        let mut fds = vec![libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        }];
        if client_open {
            fds.push(libc::pollfd {
                fd: conn.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            });
        }
        // SAFETY: valid pollfds for the duration of the call. The thread
        // blocks every caught signal.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
        if n < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }
        if fds[0].revents != 0 {
            return;
        }
        if client_open && fds[1].revents != 0 {
            match read_frame::<ClientMessage>(conn) {
                Ok(Some(ClientMessage::Signal { signal })) if FORWARDED.contains(&signal) => {
                    // SAFETY: `signal` is one of `FORWARDED`, all valid.
                    let signal = unsafe { Signal::from_raw_unchecked(signal) };
                    let _ = pidfd_send_signal(pidfd, signal);
                }
                Ok(Some(_)) => {}
                // The client is gone, and so the sandbox goes too.
                Ok(None) | Err(_) => {
                    client_open = false;
                    let _ = pidfd_send_signal(pidfd, Signal::KILL);
                }
            }
        }
    }
}

/// A connection to the server a run attaches to.
pub(crate) struct Attached {
    conn: UnixStream,
    /// The server's control socket, for approval connections.
    socket: PathBuf,
}

/// Connects to the server a `stopit run` or `stopit shell` with
/// `invocation` attaches to. That is the one named with `--server`, or
/// else the live one for the workspace found from `cwd`. `None` with
/// `--standalone`, or when no server runs for the workspace. A server
/// found but not answering, one being removed say, counts as none unless
/// it was named.
pub(crate) fn pick_server(
    invocation: &Invocation,
    cwd: &Path,
) -> Result<Option<Attached>, RunError> {
    if invocation.standalone {
        return Ok(None);
    }
    let servers = live_servers(std::env::var_os("XDG_RUNTIME_DIR").as_deref());
    if let Some(id) = &invocation.server {
        let Some(server) = servers.into_iter().find(|s| &s.id == id) else {
            return Err(RunError::NoSuchServer { id: id.clone() });
        };
        if let Some(given) = &invocation.workspace {
            let workspace = discover_workspace(cwd, Some(given))?.dir;
            if workspace != server.record.workspace() {
                return Err(RunError::ServerWorkspace {
                    id: id.clone(),
                    given: workspace,
                    served: server.record.workspace(),
                });
            }
        }
        return connect(&server).map(Some);
    }
    let workspace = discover_workspace(cwd, invocation.workspace.as_deref())?.dir;
    let Some(server) = servers
        .into_iter()
        .find(|s| s.record.workspace() == workspace)
    else {
        return Ok(None);
    };
    match connect(&server) {
        Ok(attached) => Ok(Some(attached)),
        Err(RunError::Connect { source, .. })
            if matches!(
                source.raw_os_error(),
                Some(libc::ENOENT | libc::ECONNREFUSED)
            ) =>
        {
            eprintln!(
                "stopit: warning: the stopit server {} for this workspace does not answer; \
                 running without it",
                server.id
            );
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

fn connect(server: &LiveServer) -> Result<Attached, RunError> {
    let socket = server.socket();
    check_socket_path(&socket)?;
    let connect_error = |source| RunError::Connect {
        path: socket.clone(),
        source,
    };
    let conn = UnixStream::connect(&socket).map_err(connect_error)?;
    if peer_uid(&conn).map_err(connect_error)? != rustix::process::getuid().as_raw() {
        return Err(connect_error(io::Error::other(
            "the server runs as another user",
        )));
    }
    Ok(Attached {
        conn,
        socket: socket.clone(),
    })
}

/// What a client remembers of the server's answers for its run, so it
/// asks no more than it must.
#[derive(Default)]
struct Answers {
    /// The user allowed clipboard writes for the session.
    allowed: bool,
    /// The user denied one, and later ones are denied without asking until
    /// then.
    quiet_until: Option<Instant>,
}

/// Asks the server at `socket` whether the clipboard write `request` of
/// run `run` passes, unless `answers` decides it. The output relay waits
/// meanwhile. Anything but a yes from the server is a no: a lost
/// connection, and a caught signal, which stays pending for the relay to
/// pass on.
fn ask_server(socket: &Path, run: u64, request: &ClipboardRequest, answers: &mut Answers) -> bool {
    if answers.allowed {
        return true;
    }
    if answers
        .quiet_until
        .is_some_and(|until| Instant::now() < until)
    {
        return false;
    }
    let ask = || -> io::Result<Option<ServerMessage>> {
        let conn = UnixStream::connect(socket)?;
        if peer_uid(&conn)? != rustix::process::getuid().as_raw() {
            return Err(io::Error::other("the server runs as another user"));
        }
        send_approval_hello(&conn)?;
        write_frame(
            &conn,
            &ClientMessage::Approve {
                run,
                request: ApprovalRequest::ClipboardWrite {
                    targets: request.targets.clone(),
                    data: request.data.clone(),
                },
            },
        )?;
        // Dropping the connection on a signal cancels the prompt.
        if !readable_unless_signal(conn.as_fd())? {
            return Ok(None);
        }
        read_frame::<ServerMessage>(&conn)
    };
    match ask() {
        Ok(Some(ServerMessage::Decision {
            allow,
            session,
            quiet,
        })) => {
            answers.allowed = allow && session;
            if quiet {
                answers.quiet_until = Some(Instant::now() + QUIET_AFTER_DENY);
            }
            allow
        }
        _ => false,
    }
}

/// Waits until `fd` is readable, or a caught signal arrives (returned).
fn readable_or_signal(
    mask: &BlockedSignals,
    fd: BorrowedFd<'_>,
) -> io::Result<Option<libc::c_int>> {
    loop {
        if let Some(signal) = take_signal() {
            return Ok(Some(signal));
        }
        let mut fds = [libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        }];
        match mask.wait(&mut fds) {
            Ok(()) => return Ok(None),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

/// Runs `invocation` in the sandbox of the server `attached` connects to,
/// and returns the status to exit with.
pub(crate) fn attach(attached: Attached, invocation: &Invocation) -> Result<u8, RunError> {
    let Attached { conn, socket } = attached;
    let stdio = stdio_terminals();
    let mut terminal = if stdio.contains(&true) {
        ignore_job_control();
        check_foreground(stdio)?;
        Some(SandboxTerminal::open(stdio, ClipboardPolicy::Block).map_err(RunError::Pty)?)
    } else {
        None
    };
    if let Some(t) = &mut terminal {
        catch_winch().map_err(RunError::Signals)?;
        // Raw before the sandbox starts, so no key typed meanwhile is taken
        // by the host terminal's line discipline, as for a standalone run.
        t.enter_raw().map_err(RunError::Pty)?;
    }
    let own: [BorrowedFd<'static>; 3] = [
        // SAFETY: stdio stays open for the life of the process.
        unsafe { BorrowedFd::borrow_raw(0) },
        unsafe { BorrowedFd::borrow_raw(1) },
        unsafe { BorrowedFd::borrow_raw(2) },
    ];
    let fds: [BorrowedFd<'_>; 3] = std::array::from_fn(|i| match &terminal {
        Some(t) if stdio[i] => t
            .slave_fd()
            .expect("the slave is open until the relay starts"),
        _ => own[i],
    });
    let client = RunError::Client;
    let mask = BlockedSignals::block().map_err(RunError::Signals)?;
    send_stdio(&conn, fds).map_err(client)?;
    write_frame(
        &conn,
        &ClientMessage::Run {
            version: PROTOCOL_VERSION,
            profile: invocation.profile.clone(),
            command: invocation
                .command
                .iter()
                .map(|a| a.as_bytes().to_vec())
                .collect(),
            env: std::env::vars_os()
                .map(|(k, v)| (k.into_vec(), v.into_vec()))
                .collect(),
            pty: terminal.is_some(),
            quiet: invocation.quiet,
        },
    )
    .map_err(client)?;
    // A signal while the server prepares ends the client; dropping the
    // connection then ends the run.
    if let Some(signal) = readable_or_signal(&mask, conn.as_fd()).map_err(client)? {
        return Ok(signal_exit_code(signal));
    }
    match read_frame::<ServerMessage>(&conn).map_err(client)? {
        Some(ServerMessage::Started {
            run,
            lines,
            clipboard,
        }) => {
            // With the terminal raw, a line feed alone does not return the
            // cursor.
            let end = if terminal.is_some() { "\r\n" } else { "\n" };
            for line in lines {
                eprint!("{line}{end}");
            }
            if let Some(t) = &mut terminal {
                match clipboard {
                    ClipboardWrite::Block => t.set_clipboard(ClipboardPolicy::Block),
                    ClipboardWrite::Allow => t.set_clipboard(ClipboardPolicy::Allow),
                    ClipboardWrite::Ask => {
                        let socket = socket.clone();
                        let mut answers = Answers::default();
                        t.set_asker(Box::new(move |request| {
                            ask_server(&socket, run, request, &mut answers)
                        }));
                    }
                }
            }
        }
        Some(ServerMessage::Error { message }) => {
            return Err(RunError::Server(message));
        }
        Some(ServerMessage::Exit { .. } | ServerMessage::Decision { .. }) | None => {
            return Err(RunError::ServerGone);
        }
    }
    let mut relay = terminal.as_mut().and_then(SandboxTerminal::start_relay);
    if let Some(r) = &relay {
        r.resize();
    }
    let forward = |signal| {
        let _ = write_frame(&conn, &ClientMessage::Signal { signal });
    };
    let mut exit = None;
    while exit.is_none() {
        if let Err(e) = relay_until(&mask, conn.as_fd(), relay.as_mut(), forward) {
            if let Some(r) = relay {
                r.finish();
            }
            return Err(RunError::Client(e));
        }
        match read_frame::<ServerMessage>(&conn) {
            Ok(Some(ServerMessage::Exit { code })) => exit = Some(code),
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => {
                if let Some(r) = relay {
                    r.finish();
                }
                return Err(RunError::ServerGone);
            }
        }
    }
    let denied = relay.map_or(0, |r| r.finish());
    drop(terminal);
    if denied > 0 {
        eprintln!(
            "stopit: warning: {}; approve them on the stopit server's terminal",
            blocked_writes(denied)
        );
    }
    Ok(exit.unwrap_or(EXIT_SUPERVISOR_FAILED))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_paths_must_fit_an_address() {
        let fits = format!("/{}", "a".repeat(MAX_SOCKET_PATH - 1));
        assert!(check_socket_path(Path::new(&fits)).is_ok());
        let long = format!("/{}", "a".repeat(MAX_SOCKET_PATH));
        let e = check_socket_path(Path::new(&long)).unwrap_err();
        assert!(
            matches!(e, RunError::SocketPathTooLong { len: 108, .. }),
            "{e}"
        );
        assert!(
            e.to_string()
                .contains("set XDG_RUNTIME_DIR to a shorter path")
        );
    }
}
