//! `stopit server` and `stopit run` attaching to one (DESIGN.md §5.5).
//!
//! A server loads a workspace's session once: it checks the configuration,
//! runs the providers, compiles every profile, and provisions stopit, as a
//! standalone run does. It then listens on its control socket
//! ([`crate::control`]) until it is stopped, running one sandbox per
//! client. Every sandbox of the server shares the session, so `ephemeral`
//! directories such as `/tmp` and `~` carry over between them.
//!
//! The client is `stopit run` or `stopit shell` in the same workspace. It
//! keeps the terminal side to itself, the PTY, raw mode and the output
//! filter, and sends the server the descriptors for the sandbox's stdio,
//! the command and its environment. The server never gives a sandbox its
//! own terminal: a sandbox runs on the client's PTY or detached.

use std::collections::HashMap;
use std::ffi::OsString;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{ExitCode, Stdio};
use std::sync::{Arc, Mutex};

use rustix::process::Pid;

use crate::bwrap::TerminalSession;
use crate::control::{
    ClientMessage, ServerMessage, peer_uid, read_frame, recv_stdio, send_stdio, write_frame,
};
use crate::escape::escape_message;
use crate::filter::ClipboardPolicy;
use crate::session::{CONTROL_SOCKET, LiveServer, ServerRecord, live_servers};
use crate::supervisor::{
    BlockedSignals, EXIT_SUPERVISOR_FAILED, Invocation, LoadedSession, RunError, SandboxTerminal,
    bwrap_exit_code, catch_signals, catch_winch, check_foreground, discover_workspace,
    ignore_job_control, print_error, read_nonblocking_status, relay_until, signal_exit_code,
    stdio_terminals, take_signal,
};

/// The signals a client may pass to its sandbox.
const FORWARDED: [libc::c_int; 4] = [libc::SIGINT, libc::SIGQUIT, libc::SIGTERM, libc::SIGHUP];

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

/// The sandboxes a server runs, by run number, for stopping them all.
type Running = Arc<Mutex<HashMap<u64, Pid>>>;

fn run_server(workspace: Option<&Path>, quiet: bool) -> Result<ExitCode, RunError> {
    catch_signals().map_err(RunError::Signals)?;
    let cwd = std::env::current_dir().map_err(RunError::Cwd)?;
    let workspace_dir = discover_workspace(&cwd, workspace)?.dir;
    if let Some(other) = live_servers(std::env::var_os("XDG_RUNTIME_DIR").as_deref())
        .into_iter()
        .find(|s| s.record.workspace() == workspace_dir)
    {
        return Err(RunError::ServerRunning {
            workspace: workspace_dir,
            id: other.id,
            pid: other.record.pid,
        });
    }
    let loaded = Arc::new(LoadedSession::load(&cwd, workspace)?);
    for line in loaded.warning_lines() {
        eprintln!("{line}");
    }
    let control = loaded.session.control_dir()?;
    let socket_path = control.join(CONTROL_SOCKET);
    let listener = UnixListener::bind(&socket_path).map_err(|source| RunError::Listen {
        path: socket_path.clone(),
        source,
    })?;
    listener
        .set_nonblocking(true)
        .map_err(|source| RunError::Listen {
            path: socket_path.clone(),
            source,
        })?;
    loaded
        .session
        .write_server_record(&ServerRecord::new(&loaded.workspace.dir))
        .map_err(|source| RunError::Listen {
            path: socket_path.clone(),
            source,
        })?;
    if !quiet {
        eprintln!(
            "stopit: serving {} as session {}; `stopit run` and `stopit shell` there attach to it",
            escape_message(&format!("{:?}", loaded.workspace.dir)),
            loaded.session.id()
        );
    }
    // Blocked from here on in every thread, including the workers spawned
    // below, and only unblocked while the main thread waits.
    let mask = BlockedSignals::block().map_err(RunError::Signals)?;
    let running: Running = Arc::default();
    let mut workers = Vec::new();
    let mut next_run = 1u64;
    let stopped_by = loop {
        if let Some(signal) = take_signal() {
            break signal;
        }
        let mut fds = [libc::pollfd {
            fd: listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        }];
        match mask.wait(&mut fds) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                return Err(RunError::Listen {
                    path: socket_path,
                    source: e,
                });
            }
        }
        let conn = match listener.accept() {
            Ok((conn, _)) => conn,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(_) => continue,
        };
        // The control directory is private, but the socket is checked
        // anyway: only our own user may run sandboxes here.
        if peer_uid(&conn).ok() != Some(rustix::process::getuid().as_raw()) {
            continue;
        }
        let _ = conn.set_nonblocking(false);
        let run = next_run;
        next_run += 1;
        let loaded = loaded.clone();
        let running = running.clone();
        workers.push(std::thread::spawn(move || {
            serve_client(&conn, &loaded, &running, run, quiet);
        }));
        workers.retain(|w| !w.is_finished());
    };
    if !quiet {
        eprintln!("stopit: stopping the server and its sandboxes");
    }
    for pid in running.lock().unwrap_or_else(|e| e.into_inner()).values() {
        // SAFETY: a plain syscall. The worker reaps the child only after it
        // removed it from `running`, under this lock.
        unsafe { libc::kill(pid.as_raw_nonzero().get(), libc::SIGKILL) };
    }
    for worker in workers {
        let _ = worker.join();
    }
    // The last reference: removes the session directory.
    drop(loaded);
    Ok(ExitCode::from(signal_exit_code(stopped_by)))
}

/// Runs the one sandbox client `conn` asks for, as run number `run`, and
/// reports how it ended. Every error goes back to the client.
fn serve_client(
    conn: &UnixStream,
    loaded: &LoadedSession,
    running: &Running,
    run: u64,
    quiet: bool,
) {
    match run_for_client(conn, loaded, running, run, quiet) {
        Ok(code) => {
            let _ = write_frame(conn, &ServerMessage::Exit { code });
        }
        Err(e) => {
            if !quiet {
                eprintln!(
                    "stopit: run {run} failed: {}",
                    escape_message(&e.to_string())
                );
            }
            let _ = write_frame(
                conn,
                &ServerMessage::Error {
                    message: e.to_string(),
                },
            );
        }
    }
}

fn run_for_client(
    conn: &UnixStream,
    loaded: &LoadedSession,
    running: &Running,
    run: u64,
    quiet: bool,
) -> Result<u8, RunError> {
    let protocol = |source: io::Error| RunError::Client(source);
    let stdio = recv_stdio(conn).map_err(protocol)?;
    let Some(ClientMessage::Run {
        profile,
        command,
        env,
        pty,
        quiet: client_quiet,
    }) = read_frame::<ClientMessage>(conn).map_err(protocol)?
    else {
        return Err(protocol(io::Error::new(
            io::ErrorKind::InvalidData,
            "the client did not ask to run a command",
        )));
    };
    let command: Vec<OsString> = command.into_iter().map(OsString::from_vec).collect();
    if command.is_empty() {
        return Err(protocol(io::Error::new(
            io::ErrorKind::InvalidData,
            "the client sent no command",
        )));
    }
    let env = env
        .into_iter()
        .map(|(k, v)| (OsString::from_vec(k), OsString::from_vec(v)));
    let (profile_name, compiled) = loaded.profile(profile.as_deref())?;
    let mut lines = loaded.warning_lines();
    if !client_quiet {
        lines.extend(loaded.summary_lines(&profile_name, compiled));
    }
    // The server's own terminal never reaches a sandbox: on the client's
    // PTY `__init` starts a session, and otherwise bwrap detaches it.
    let terminal = if pty {
        TerminalSession::Pty
    } else {
        TerminalSession::Detach
    };
    let bwrap = loaded.command(compiled, &command, env, terminal)?;
    let (mut child_command, status_reader) = bwrap.into_command_with_status()?;
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
            // The server's threads block the signals it catches; bwrap
            // must be killable by them.
            let mut empty: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut empty);
            if libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut()) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = {
        let mut running = running.lock().unwrap_or_else(|e| e.into_inner());
        let child = child_command.spawn().map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                RunError::BwrapMissing
            } else {
                RunError::Spawn(e)
            }
        })?;
        running.insert(run, Pid::from_child(&child));
        child
    };
    drop(child_command);
    let pid = Pid::from_child(&child);
    if !quiet {
        eprintln!(
            "stopit: run {run} started: profile {:?}: {}",
            profile_name.as_str(),
            escape_message(
                &command
                    .iter()
                    .map(|a| String::from_utf8_lossy(a.as_bytes()).into_owned())
                    .collect::<Vec<_>>()
                    .join(" ")
            )
        );
    }
    let started = write_frame(
        conn,
        &ServerMessage::Started {
            lines,
            clipboard_allow: loaded.clipboard() == ClipboardPolicy::Allow,
        },
    );
    let kill = |signal| {
        // SAFETY: a plain syscall. The child is reaped only below, after it
        // left `running`.
        unsafe { libc::kill(pid.as_raw_nonzero().get(), signal) };
    };
    if started.is_err() {
        kill(libc::SIGKILL);
    } else {
        wait_child_or_client(conn, &child, kill);
    }
    let status = {
        let status = child.wait().map_err(RunError::Spawn);
        running
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&run);
        status?
    };
    let code = bwrap_exit_code(status, &read_nonblocking_status(status_reader));
    if !quiet {
        eprintln!("stopit: run {run} ended with status {code}");
    }
    Ok(code)
}

/// Waits until `child` exits, passing the signals the client sends to it
/// with `kill`, and killing it if the client goes away.
fn wait_child_or_client(
    conn: &UnixStream,
    child: &std::process::Child,
    kill: impl Fn(libc::c_int),
) {
    let Ok(pidfd) =
        rustix::process::pidfd_open(Pid::from_child(child), rustix::process::PidfdFlags::empty())
    else {
        // Waited for by the caller; the client cannot signal it meanwhile.
        return;
    };
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
        // blocks every caught signal, so nothing interrupts it but those
        // the kernel restarts.
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
                    kill(signal);
                }
                Ok(Some(_)) => {}
                // Gone: the sandbox goes too.
                Ok(None) | Err(_) => {
                    client_open = false;
                    kill(libc::SIGKILL);
                }
            }
        }
    }
}

/// The server a `stopit run` or `stopit shell` with `invocation` attaches
/// to: the one named with `--server`, or else the live one for the
/// workspace found from `cwd`. `None` with `--standalone`, or when no
/// server runs for the workspace.
pub(crate) fn pick_server(
    invocation: &Invocation,
    cwd: &Path,
) -> Result<Option<LiveServer>, RunError> {
    if invocation.standalone {
        return Ok(None);
    }
    let servers = live_servers(std::env::var_os("XDG_RUNTIME_DIR").as_deref());
    if let Some(id) = &invocation.server {
        return match servers.into_iter().find(|s| &s.id == id) {
            Some(server) => Ok(Some(server)),
            None => Err(RunError::NoSuchServer { id: id.clone() }),
        };
    }
    let workspace = discover_workspace(cwd, invocation.workspace.as_deref())?.dir;
    Ok(servers
        .into_iter()
        .find(|s| s.record.workspace() == workspace))
}

/// Runs `invocation` in the sandbox of `server` and returns the status to
/// exit with.
pub(crate) fn attach(server: &LiveServer, invocation: &Invocation) -> Result<u8, RunError> {
    let socket = server.socket();
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
    let stdio = stdio_terminals();
    let mut terminal = if stdio.contains(&true) {
        ignore_job_control();
        check_foreground(stdio)?;
        Some(SandboxTerminal::open(stdio, ClipboardPolicy::Block).map_err(RunError::Pty)?)
    } else {
        None
    };
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
    let client = |source| RunError::Client(source);
    send_stdio(&conn, fds).map_err(client)?;
    write_frame(
        &conn,
        &ClientMessage::Run {
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
    match read_frame::<ServerMessage>(&conn).map_err(client)? {
        Some(ServerMessage::Started {
            lines,
            clipboard_allow,
        }) => {
            for line in lines {
                eprintln!("{line}");
            }
            if let Some(t) = &mut terminal {
                t.set_clipboard(if clipboard_allow {
                    ClipboardPolicy::Allow
                } else {
                    ClipboardPolicy::Block
                });
            }
        }
        Some(ServerMessage::Error { message }) => {
            return Err(RunError::Server(message));
        }
        Some(ServerMessage::Exit { .. }) | None => {
            return Err(RunError::ServerGone);
        }
    }
    catch_winch().map_err(RunError::Signals)?;
    let mask = BlockedSignals::block().map_err(RunError::Signals)?;
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
    if let Some(r) = relay {
        r.finish();
    }
    drop(terminal);
    Ok(exit.unwrap_or(EXIT_SUPERVISOR_FAILED))
}
