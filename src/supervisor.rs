//! The supervisor: `stopit run` and `stopit shell` (DESIGN.md §2, §5).
//!
//! [`run`] runs one command in one sandbox, in the foreground:
//!
//! 1. finds the workspace and its `.stopit.toml` ([`discover_workspace`],
//!    §3.1), reads it, refuses it unless the user allowed exactly that
//!    content ([`check_allowed`], the trust store of [`crate::trust`]), and
//!    loads the configuration (the default one if there is no file, unless
//!    a configuration allowed where it looked is gone, [`check_missing`]);
//! 2. creates the session directory (§2.1), which the providers are told
//!    about;
//! 3. runs the providers, compiles every profile of the session
//!    (`spec::compile_session`), protecting the script providers' sources
//!    and the configuration file in each (§3, §3.6) and refusing mounts that
//!    would expose stopit's own state directories (§6.2, Reserved host
//!    paths), and prints its warnings ([`warning_lines`]);
//! 4. picks the profile (`main`, or `--profile`, §3.3) and, unless
//!    `--quiet`, prints the summary of what it grants beyond the default
//!    base ([`summary_lines`]), after the warnings;
//! 5. provisions itself into the session directory (§2.1), computes the
//!    target's environment from its own (§9), and runs bwrap with `__init`
//!    and the command on the supervisor's stdio, or on a PTY of its own
//!    relayed to the host terminal when any of that is a terminal
//!    ([`wait_foreground`], [`crate::pty`]);
//! 6. waits for it, restores the terminal's state, removes the session
//!    directory, and exits with the command's status ([`exit_code`]).
//!
//! `SIGINT`, `SIGQUIT`, `SIGTERM` and `SIGHUP` are caught from the start
//! ([`catch_signals`]): before bwrap is spawned, one ends the run (after
//! removing the session directory) with `128 + N`; while it runs, they are
//! forwarded to it.
//!
//! Errors are printed as `stopit: error: …` and exit with
//! [`EXIT_SUPERVISOR_FAILED`]; warnings as `stopit: warning: …`. Every line
//! is escaped ([`escape_message`]): configuration, scripts and the
//! filesystem (often sandbox-writable) put text in them. bwrap's own
//! messages are not stopit's, and are not escaped.
//!
//! Not done yet: approval prompts (§5.2), the broker, and the network proxy.

use std::collections::HashSet;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, IsTerminal, Read};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{ExitCode, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use rustix::io::Errno;
use rustix::process::Pid;
use thiserror::Error;

use crate::bwrap::{BwrapCommand, BwrapError, TerminalSession, working_dir};
use crate::config::{
    Base, ClipboardWrite, Config, ConfigError, ConfigLayer, LayeredConfig, ProfileRef,
    ProviderEntry, ProviderKind, ProviderName, ProviderOrigin,
};
use crate::escape::{escape_message, shell_quote};
use crate::expand::{ExpandError, ExpansionContext, ResolveWarning};
use crate::filter::{ClipboardPolicy, OutputFilter};
use crate::manifest::{Grants, Manifest, SandboxHome};
use crate::provider::{
    BASE_PROVIDER_NAME, ProtectedSource, ProviderContext, ProviderError, ProviderOutput,
    SUPERVISOR_PROVIDER_NAME, layered_session_providers, protected_sources, static_outputs,
};
use crate::provision::{ProvisionError, Provisioned, provision_self};
use crate::pty::{HostTerminal, Pty, PtyRelay, RawMode};
use crate::resolve::{PlanWarning, PlanWarningKind};
use crate::session::{SessionDir, SessionError};
use crate::spec::{
    CompileError, CompiledProfile, CompiledSession, ScriptPathError, SpecWarning, UntrustedRoot,
    compile_session, has_rewritable_hard_links, resolve_script_path, static_rw_roots,
};
use crate::state::{
    ConfigDirs, GLOBAL_CONFIG_FILE, StateDirs, StateError, config_dirs_from_host,
    data_dirs_from_host, resolve_allowing_missing, runtime_dir,
};
use crate::summary::{SummaryContext, summary_lines};
use crate::trust::{Allowed, Decision, TrustError, TrustStore};

/// The name of the configuration file that marks a workspace (§3.1).
pub const CONFIG_FILE: &str = ".stopit.toml";

/// The exit status when the supervisor itself fails, before or around the
/// command (bad configuration, no `XDG_RUNTIME_DIR`, bwrap missing), as
/// `env` and `timeout` report theirs. The command can exit with it too.
pub const EXIT_SUPERVISOR_FAILED: u8 = 125;

/// Error running a command in the sandbox.
#[derive(Debug, Error)]
pub enum RunError {
    /// The current directory cannot be determined.
    #[error("cannot determine the current directory: {0}")]
    Cwd(#[source] io::Error),

    /// The workspace directory cannot be resolved.
    #[error("cannot resolve the workspace {path:?}: {source}")]
    Workspace {
        /// The workspace as given.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },

    /// The workspace is not a directory.
    #[error("the workspace {0:?} is not a directory")]
    WorkspaceNotDir(PathBuf),

    /// Looking for the configuration file failed for another reason than
    /// its absence.
    #[error("cannot check for {path:?}: {source}")]
    Discover {
        /// The candidate configuration file.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },

    /// Walking up from the current directory found a configuration file
    /// below another one: a sandbox of the outer workspace could have
    /// written it ([`discover_workspace`]).
    #[error("{}", nested_config_message(inner, outer, outer_unusable.as_deref()))]
    NestedConfig {
        /// The configuration file found first, walking up.
        inner: PathBuf,
        /// The next one further up owned by the user.
        outer: PathBuf,
        /// Why `outer` would not load either (it fails the checks of
        /// [`check_config_trust`]), if so: it is then not suggested.
        outer_unusable: Option<String>,
    },

    /// `stopit allow` found no configuration file to allow.
    #[error(
        "no {CONFIG_FILE} in {}{}: there is nothing to allow",
        if *explicit { "the workspace " } else { "" },
        no_config_place(dir, *explicit)
    )]
    NothingToAllow {
        /// The directory searched from (walking up), or named by
        /// `--workspace`.
        dir: PathBuf,
        /// Whether `--workspace` named it.
        explicit: bool,
    },

    /// The configuration file is not in the trust store with its current
    /// content ([`check_allowed`]).
    #[error("{}", not_allowed_message(path, *changed, workspace.as_deref()))]
    NotAllowed {
        /// The configuration file.
        path: PathBuf,
        /// Whether it was allowed with other content (else not at all).
        changed: bool,
        /// The workspace, if `--workspace` named it, for the hint.
        workspace: Option<PathBuf>,
    },

    /// No configuration file was found, but the trust store has an entry
    /// for one where discovery looked, or past a link on the way there
    /// ([`check_missing`]).
    #[error("{}", missing_config_message(path, via.as_deref()))]
    MissingConfig {
        /// The configuration file allowed, now missing.
        path: PathBuf,
        /// The symbolic link on the way to the workspace that `path` lies
        /// at or below, if that is why: it was a directory when `path` was
        /// allowed.
        via: Option<PathBuf>,
    },

    /// `stopit revoke PATH` was given a directory.
    #[error(
        "{0:?} is a directory: give the path of a configuration file, as `stopit allowed` lists \
         it, or run `stopit revoke --workspace` with the directory"
    )]
    RevokeDir(PathBuf),

    /// The trust store cannot be used.
    #[error(transparent)]
    Trust(#[from] TrustError),

    /// The configuration file cannot be read.
    #[error("cannot read {path:?}: {source}")]
    ReadConfig {
        /// The configuration file.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },

    /// The configuration file, or its directory, could be changed by someone
    /// else than the user ([`check_config_trust`]).
    #[error("refusing to read {path:?}: {reason}")]
    UntrustedConfig {
        /// The configuration file.
        path: PathBuf,
        /// What is wrong with it.
        reason: String,
    },

    /// The configuration file is invalid.
    #[error("{path:?}: {source}")]
    Config {
        /// The configuration file.
        path: PathBuf,
        /// What is wrong with it.
        source: ConfigError,
    },

    /// `HOME` is not set, so `~` rules cannot be expanded.
    #[error("HOME is not set; stopit needs it to expand `~` in rules")]
    HomeUnset,

    /// `HOME` cannot be resolved.
    #[error("cannot resolve HOME {path:?}: {source}")]
    Home {
        /// The value of `HOME`.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },

    /// The workspace or `HOME` cannot be used to expand rules.
    #[error(transparent)]
    Expand(#[from] ExpandError),

    /// stopit's data or runtime directory cannot be found.
    #[error(transparent)]
    State(#[from] StateError),

    /// `stopit shell` without `SHELL` in the environment.
    #[error("SHELL is not set; run a shell explicitly with `stopit run <shell>`")]
    ShellUnset,

    /// `--profile` is not a profile name.
    #[error("invalid profile name {name:?}: {reason}")]
    ProfileName {
        /// The name as given.
        name: String,
        /// Why it is invalid.
        reason: String,
    },

    /// The session directory cannot be created.
    #[error(transparent)]
    Session(#[from] SessionError),

    /// A provider failed.
    #[error(transparent)]
    Provider(#[from] ProviderError),

    /// The profiles do not compile.
    #[error(transparent)]
    Compile(#[from] CompileError),

    /// `--profile` names no profile of the session.
    #[error("there is no profile {name:?}; the profiles are: {available}")]
    UnknownProfile {
        /// The profile asked for.
        name: String,
        /// Every profile of the session, comma-separated.
        available: String,
    },

    /// stopit cannot copy itself into the session directory.
    #[error("cannot provision stopit into the session directory: {0}")]
    Provision(#[from] ProvisionError),

    /// The bwrap command cannot be built.
    #[error(transparent)]
    Bwrap(#[from] BwrapError),

    /// bwrap is not installed.
    #[error("bwrap (bubblewrap) is not installed or not on PATH")]
    BwrapMissing,

    /// bwrap cannot be started or waited for.
    #[error("cannot run bwrap: {0}")]
    Spawn(#[source] io::Error),

    /// The signal handlers cannot be installed.
    #[error("cannot set up signal handling: {0}")]
    Signals(#[source] io::Error),

    /// stdio is the controlling terminal, and stopit is not in its
    /// foreground process group.
    #[error(
        "stopit is not in the foreground of its terminal (started in the background?); it \
         relays the terminal to the sandbox, so it only starts in the foreground"
    )]
    Background,

    /// The sandbox's PTY cannot be set up.
    #[error("cannot set up the sandbox's terminal: {0}")]
    Pty(#[source] io::Error),

    /// A server already serves the workspace.
    #[error(
        "a stopit server already serves {workspace:?} as session {id} (pid {pid}); stop it \
         first, or use it with `stopit run`"
    )]
    ServerRunning {
        /// The workspace.
        workspace: PathBuf,
        /// The other server's session id.
        id: String,
        /// The other server's process id.
        pid: u32,
    },

    /// The server's control socket cannot be set up or used.
    #[error("cannot listen on {path:?}: {source}")]
    Listen {
        /// The socket.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },

    /// `--server` names no live server.
    #[error(
        "no stopit server runs as session {id}; start one with `stopit server` in the workspace, \
         or leave out --server"
    )]
    NoSuchServer {
        /// The session id given.
        id: String,
    },

    /// The server's control socket cannot be reached.
    #[error("cannot reach the stopit server at {path:?}: {source}")]
    Connect {
        /// The socket.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },

    /// The other side of the control socket broke the protocol, or the
    /// socket failed.
    #[error("the stopit control connection failed: {0}")]
    Client(#[source] io::Error),

    /// The server refused or failed the request.
    #[error("the stopit server says: {0}")]
    Server(String),

    /// The server ended before the command did.
    #[error("the stopit server ended before the command did")]
    ServerGone,

    /// The server's record cannot be written.
    #[error("cannot write the server's record {path:?}: {source}")]
    ServerRecord {
        /// The record file.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },

    /// The server is stopping and starts no more sandboxes.
    #[error("the stopit server is stopping")]
    ServerStopping,

    /// `--server` and `--workspace` name different workspaces.
    #[error(
        "the stopit server {id} serves {served:?}, not {given:?}; leave out --workspace or \
         --server"
    )]
    ServerWorkspace {
        /// The session id given.
        id: String,
        /// The workspace `--workspace` found.
        given: PathBuf,
        /// The workspace the server serves.
        served: PathBuf,
    },

    /// A socket path does not fit in a Unix socket address.
    #[error(
        "the socket path {path:?} is {len} bytes, more than a Unix socket address holds; set \
         XDG_RUNTIME_DIR to a shorter path"
    )]
    SocketPathTooLong {
        /// The socket path.
        path: PathBuf,
        /// Its length in bytes.
        len: usize,
    },

    /// Whether stopit is in the foreground of its terminal cannot be told.
    #[error("cannot check that stopit is in the foreground of its terminal: {0}")]
    Foreground(#[source] io::Error),

    /// Effective `base = "default"` has no user provider granting tools.
    #[error("{}", no_tools_configured_message(global_config))]
    NoToolsConfigured {
        /// Active user-global configuration file path.
        global_config: PathBuf,
    },
}

/// What [`run`] runs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Invocation {
    /// `--workspace`, if given.
    pub workspace: Option<PathBuf>,
    /// `--profile`, if given.
    pub profile: Option<String>,
    /// `--quiet`: do not print the startup summary ([`summary_lines`]).
    pub quiet: bool,
    /// The command and its arguments.
    pub command: Vec<OsString>,
    /// `--server`: the session id of the server to attach to.
    pub server: Option<String>,
    /// `--standalone`: run without a server even if one serves the
    /// workspace.
    pub standalone: bool,
}

/// The command `stopit shell` runs: `$SHELL` from the host environment,
/// given as `shell`.
pub fn shell_command(shell: Option<OsString>) -> Result<Vec<OsString>, RunError> {
    match shell {
        Some(shell) if !shell.is_empty() => Ok(vec![shell]),
        _ => Err(RunError::ShellUnset),
    }
}

/// Prints `stopit: error: <message>` to stderr, escaped.
pub fn print_error(message: &str) {
    eprintln!("stopit: error: {}", escape_message(message));
}

/// The script providers of `config` with `protect = false`, in order.
fn unprotected_providers(config: &Config) -> Vec<&ProviderName> {
    config
        .providers
        .iter()
        .filter(|e| matches!(e.kind, ProviderKind::Script { protect: false, .. }))
        .map(|e| &e.name)
        .collect()
}

/// Runs `invocation` in the sandbox and returns the status to exit with:
/// the command's (see [`exit_code`]), `128 + N` if signal `N` stopped the
/// supervisor before the command started, or [`EXIT_SUPERVISOR_FAILED`]
/// after printing why the supervisor failed (`128 + N` instead if a signal
/// arrived meanwhile, which may be why: Ctrl-C during a script provider).
///
/// Returns rather than exiting, so that the session directory is removed
/// (dropped) before the process ends.
pub fn run(invocation: Invocation) -> ExitCode {
    match supervise(invocation) {
        Ok(code) => code,
        Err(RunError::Provider(ProviderError::Interrupted { signal, .. })) => {
            let _ = take_signal();
            ExitCode::from(signal_exit_code(signal))
        }
        Err(e) => {
            print_error(&e.to_string());
            match take_signal() {
                Some(signal) => ExitCode::from(signal_exit_code(signal)),
                None => ExitCode::from(EXIT_SUPERVISOR_FAILED),
            }
        }
    }
}

/// `stopit allow [--workspace DIR]`: records the workspace's configuration
/// file, found as [`run`] finds it ([`discover_workspace`], with the same
/// checks), with its current content in the trust store, replacing any
/// earlier entry for it. It is parsed, to catch mistakes now, but nothing
/// runs. Prints what it allowed and returns 0, or prints why not and
/// returns [`EXIT_SUPERVISOR_FAILED`].
pub fn allow(workspace: Option<PathBuf>) -> ExitCode {
    report(allow_config(workspace.as_deref()))
}

/// `stopit revoke [--workspace DIR]`: removes the workspace's configuration
/// file from the trust store, so that runs refuse it until it is allowed
/// again. `stopit revoke PATH`: removes the entry of the configuration file
/// `PATH`, found without discovery, so that the entry of a workspace that
/// is gone can be removed too ([`config_keys`]). Nothing to remove is not
/// an error.
pub fn revoke(workspace: Option<PathBuf>, config: Option<PathBuf>) -> ExitCode {
    report(match config {
        Some(config) => revoke_file(&config),
        None => revoke_config(workspace.as_deref()),
    })
}

/// `stopit allowed`: lists the trust store, one configuration a line, with
/// the start of the hash allowed, and `(missing)` after a file that is
/// gone.
pub fn allowed() -> ExitCode {
    report(list_allowed())
}

/// Prints `lines` to stdout, each escaped, and returns 0; or prints the
/// error and returns [`EXIT_SUPERVISOR_FAILED`].
fn report(result: Result<Vec<String>, RunError>) -> ExitCode {
    match result {
        Ok(lines) => {
            for line in lines {
                println!("{}", escape_message(&line));
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            print_error(&e.to_string());
            ExitCode::from(EXIT_SUPERVISOR_FAILED)
        }
    }
}

/// How many hex digits of a hash `allowed` prints.
const SHORT_HASH: usize = 12;

fn allow_config(workspace: Option<&Path>) -> Result<Vec<String>, RunError> {
    let cwd = std::env::current_dir().map_err(RunError::Cwd)?;
    let found = discover_workspace(&cwd, workspace)?;
    let Some(file) = found.read_config()? else {
        return Err(RunError::NothingToAllow {
            dir: found.dir,
            explicit: workspace.is_some(),
        });
    };
    file.parse()?;
    let store = TrustStore::open(&data_dirs_from_host()?.store.path)?;
    let hash = store.update(|allowed| allowed.allow(file.path.clone(), &file.bytes))?;
    Ok(vec![allowed_line(&file.path, file.bytes.len(), &hash)])
}

/// What `stopit allow` prints for the configuration file `path`, allowed
/// with `len` bytes hashing to `hash`: all of the hash, and the size, so
/// that the user can check that the version they reviewed is the one
/// allowed (`sha256sum`).
fn allowed_line(path: &Path, len: usize, hash: &str) -> String {
    let unit = if len == 1 { "byte" } else { "bytes" };
    format!("allowed {path:?} ({len} {unit}, sha256 {hash})")
}

fn revoke_config(workspace: Option<&Path>) -> Result<Vec<String>, RunError> {
    let cwd = std::env::current_dir().map_err(RunError::Cwd)?;
    let found = discover_workspace(&cwd, workspace)?;
    // Not read: one that fails the trust checks, or is gone, can be revoked
    // too.
    let path = found.config.unwrap_or_else(|| found.dir.join(CONFIG_FILE));
    let store = TrustStore::open(&data_dirs_from_host()?.store.path)?;
    Ok(vec![if store.update(|allowed| allowed.revoke(&path))? {
        format!("revoked {path:?}")
    } else {
        format!("{path:?} was not allowed: nothing to revoke")
    }])
}

fn revoke_file(given: &Path) -> Result<Vec<String>, RunError> {
    let cwd = std::env::current_dir().map_err(RunError::Cwd)?;
    let path = cwd.join(given);
    if fs::metadata(&path).is_ok_and(|meta| meta.is_dir()) {
        return Err(RunError::RevokeDir(path));
    }
    let keys = config_keys(&path);
    let store = TrustStore::open(&data_dirs_from_host()?.store.path)?;
    let revoked = store.update(|allowed| keys.iter().find(|key| allowed.revoke(key)).cloned())?;
    Ok(vec![match revoked {
        Some(key) => format!("revoked {key:?}"),
        None => format!("{:?} was not allowed: nothing to revoke", keys[0]),
    }])
}

/// The trust store entries the absolute configuration path `path` may
/// stand for, in the order tried: `path` as written, as `stopit allowed`
/// lists it (an entry whose directory is gone, or was replaced by a link
/// since, is only found so), then its directory resolved as far as it
/// exists ([`resolve_allowing_missing`]) joined with its file name, as
/// `allow` would have recorded it (canonical; the file itself is never a
/// link, so it is not followed).
pub fn config_keys(path: &Path) -> Vec<PathBuf> {
    let mut keys = vec![path.to_path_buf()];
    if let (Some(dir), Some(name)) = (path.parent(), path.file_name()) {
        if let Ok(dir) = resolve_allowing_missing(dir) {
            let resolved = dir.path.join(name);
            if resolved != path {
                keys.push(resolved);
            }
        }
    }
    keys
}

fn list_allowed() -> Result<Vec<String>, RunError> {
    let store = TrustStore::open(&data_dirs_from_host()?.store.path)?;
    Ok(store
        .read()?
        .iter()
        .map(|(path, hash)| allowed_entry_line(path, hash, is_gone(path)))
        .collect())
}

/// Whether nothing is at `path` any more (an error other than its absence
/// does not count).
fn is_gone(path: &Path) -> bool {
    fs::symlink_metadata(path).is_err_and(|e| e.kind() == io::ErrorKind::NotFound)
}

/// What `stopit allowed` prints for the entry of `path` with `hash`, whose
/// file is `missing` or not.
fn allowed_entry_line(path: &Path, hash: &str, missing: bool) -> String {
    let note = if missing { " (missing)" } else { "" };
    format!("{} {path:?}{note}", &hash[..SHORT_HASH])
}

fn supervise(invocation: Invocation) -> Result<ExitCode, RunError> {
    catch_signals().map_err(RunError::Signals)?;
    let cwd = std::env::current_dir().map_err(RunError::Cwd)?;
    // Before anything runs, as for every other mistake in the arguments.
    parse_profile(invocation.profile.as_deref())?;
    if let Some(conn) = crate::server::pick_server(&invocation, &cwd)? {
        return Ok(ExitCode::from(crate::server::attach(conn, &invocation)?));
    }
    let loaded = LoadedSession::load(&cwd, invocation.workspace.as_deref())?;
    for line in loaded.warning_lines() {
        eprintln!("{line}");
    }
    let (profile_name, profile) = loaded.profile(invocation.profile.as_deref())?;
    // After the warnings, right before the sandbox starts, so it is the
    // last thing above the command's own output.
    if !invocation.quiet {
        for line in loaded.summary_lines(&profile_name, profile) {
            eprintln!("{line}");
        }
    }
    let stdio = stdio_terminals();
    let terminal = terminal_session(stdio);
    let command = loaded.command(profile, &invocation.command, std::env::vars_os(), terminal)?;
    ignore_job_control();
    if terminal != TerminalSession::Keep {
        check_foreground(stdio)?;
    }
    let pty = if terminal == TerminalSession::Pty {
        Some(SandboxTerminal::open(stdio, loaded.clipboard()).map_err(RunError::Pty)?)
    } else {
        None
    };
    let status = wait_foreground(command, pty);
    // The sandbox is gone, or going: bwrap returns once its namespace's
    // init exits, and if bwrap itself was killed, `--die-with-parent` kills
    // the init and so the namespace. Its mounts go with it.
    drop(loaded);
    Ok(ExitCode::from(status?))
}

/// `--profile` `name` parsed (`main` if `None`).
pub(crate) fn parse_profile(name: Option<&str>) -> Result<ProfileRef, RunError> {
    match name {
        None => Ok(ProfileRef::main()),
        Some(name) => name.parse().map_err(|e| RunError::ProfileName {
            name: name.to_owned(),
            reason: format!("{e}"),
        }),
    }
}

/// The profile `name` (`main` if `None`) of `compiled`, with its name.
pub(crate) fn profile_in<'a>(
    compiled: &'a CompiledSession,
    name: Option<&str>,
) -> Result<(ProfileRef, &'a CompiledProfile), RunError> {
    let profile = parse_profile(name)?;
    match compiled.get(&profile) {
        Some(found) => Ok((profile, found)),
        None => Err(RunError::UnknownProfile {
            name: profile.as_str().to_owned(),
            available: compiled
                .order()
                .iter()
                .map(ProfileRef::as_str)
                .collect::<Vec<_>>()
                .join(", "),
        }),
    }
}

/// A workspace's session, ready to run sandboxes in: its configuration
/// checked and layered, its providers run, every profile compiled, and the
/// stopit binary provisioned into the session directory. Dropping it
/// removes the session directory.
pub(crate) struct LoadedSession {
    /// The workspace and its configuration file.
    pub(crate) workspace: Workspace,
    config: Config,
    home: PathBuf,
    /// The session compiled when it was loaded.
    pub(crate) compiled: CompiledSession,
    /// Warnings found before compiling, without the `stopit: warning:`
    /// prefix.
    load_warnings: Vec<String>,
    /// The compile warnings of [`compiled`](Self::compiled).
    compile_warnings: Vec<String>,
    /// What [`recompile`](Self::recompile) compiles again: the providers'
    /// outputs, the protected sources, the state directories and the
    /// expansion context.
    outputs: Vec<(ProviderName, ProviderOutput)>,
    protected: Vec<ProtectedSource>,
    state: StateDirs,
    ctx: ExpansionContext,
    provisioned: Provisioned,
    /// Dropped last.
    pub(crate) session: SessionDir,
}

impl LoadedSession {
    /// Finds the workspace from `cwd` or `explicit` (`--workspace`), checks
    /// and loads its configuration over the user-global one, runs the
    /// providers, compiles every profile, and provisions stopit into a new
    /// session directory.
    pub(crate) fn load(cwd: &Path, explicit_dir: Option<&Path>) -> Result<Self, RunError> {
        let workspace = discover_workspace(cwd, explicit_dir)?;
        let file = workspace.read_config()?;
        // No mount may expose them (§6.2, Reserved host paths), even before
        // they exist. From the password database, not `HOME`, plus
        // `STOPIT_STATE_DIR` if set. The store is created now if missing, so
        // that read-only views of it mask it.
        let data_dirs = data_dirs_from_host()?;
        let config_dirs = config_dirs_from_host()?;
        let store = TrustStore::open(&data_dirs.store.path)?;
        // Before anything runs or is created: only a configuration the user
        // allowed, in the exact bytes read, which are the bytes parsed; and
        // not the default one in place of an allowed one that is gone.
        let allowed = store.read()?;
        drop(store);
        let explicit = explicit_dir.is_some().then_some(&workspace.dir);
        let project_layer = match &file {
            None => {
                let links = discovery_links(cwd, explicit_dir, std::env::var_os("PWD"));
                check_missing(&allowed, &workspace.dir, explicit.is_some(), &links)?;
                None
            }
            Some(file) => {
                check_allowed(&allowed, file, explicit.map(PathBuf::as_path))?;
                Some(file.parse_layer()?)
            }
        };
        // Read, checked and parsed even when `.stopit.toml` sets
        // `base = "none"` and the layer goes unused: its target and its
        // script sources are protected in every session, or a sandbox of
        // this one could plant what every other workspace runs (§3, The
        // user-global configuration).
        let global_file = read_global_config(&config_dirs)?;
        let global_layer = match &global_file {
            Some(gf) => Some(gf.parse_layer()?),
            None => None,
        };
        let global_entries = global_layer
            .as_ref()
            .map(|layer| layer.providers.clone())
            .unwrap_or_default();
        let LayeredConfig {
            config,
            providers: layered_entries,
            replaced,
        } = ConfigLayer::layer(
            global_layer.map(|layer| (layer, config_dirs.active.path.as_path())),
            project_layer.map(|layer| (layer, workspace.dir.as_path())),
        );
        let mut warnings = Vec::new();
        if let Some(gf) = &global_file {
            for name in replaced.iter().filter(|n| is_default_provider_name(n)) {
                warnings.push(format!(
                    "the [[provider]] named \"{name}\" in {CONFIG_FILE} replaces the one of that \
                     name in {:?}; give one of them another `name` to keep both",
                    gf.path
                ));
            }
        }
        let home = host_home(std::env::var_os("HOME"))?;
        let mount = config.workspace.mount.clone();
        let ctx = ExpansionContext::new(
            workspace.dir.clone(),
            mount.clone(),
            home.clone(),
            SandboxHome::default(),
        )?;

        // Before the providers, which are told where it is. From here on,
        // returning removes it.
        let session = SessionDir::create_from_env()?;
        let providers = layered_session_providers(config.base, &layered_entries)?;
        // Script paths must not run through links in these (§3.6), nor the
        // way to the global configuration and its scripts.
        let rw_grants = static_rw_roots(&static_outputs(&providers), &ctx);
        let global_guarded = match &global_file {
            Some(gf) => guard_global_config(
                gf,
                &global_entries,
                &config_dirs.active.path,
                &workspace.dir,
                &rw_grants,
            )?,
            None => Vec::new(),
        };
        let pctx = ProviderContext {
            workspace: workspace.dir.clone(),
            workspace_mount: mount.clone(),
            home: home.clone(),
            session_dir: session.root().to_path_buf(),
            rw_grants,
        };
        let outputs = providers
            .iter()
            .map(|p| Ok((p.name().clone(), p.manifest(&pctx)?)))
            .collect::<Result<Vec<_>, ProviderError>>()?;
        let has_user_tools = outputs.iter().any(|(_, out)| {
            out.origin != ProviderOrigin::Builtin && manifest_grants_tools(&out.manifest)
        });
        // The script providers' sources, and the configuration files
        // themselves, protected in every profile whatever the base and rules
        // (§3, §3.6), the latter attributed to the name reserved for
        // stopit's own rules.
        let mut protected = protected_sources(&providers)?;
        let supervisor_name: ProviderName = SUPERVISOR_PROVIDER_NAME
            .parse()
            .expect("the supervisor's name is a valid provider name");
        if let Some(file) = &file {
            protected.push(ProtectedSource {
                provider: supervisor_name.clone(),
                path: file.path.clone(),
            });
        }
        for path in global_guarded {
            if !protected.iter().any(|p| p.path == path) {
                protected.push(ProtectedSource {
                    provider: supervisor_name.clone(),
                    path,
                });
            }
        }
        // stopit's own state, which no mount may expose (§6.2, Reserved host
        // paths): the parent of every session directory, the data
        // directories, and the configuration directories. `XDG_RUNTIME_DIR`
        // is set and absolute, or there would be no session.
        let runtime = runtime_dir(Path::new(
            &std::env::var_os("XDG_RUNTIME_DIR").unwrap_or_default(),
        ))?;
        debug_assert_eq!(Some(runtime.path.as_path()), session.root().parent());
        let global_config_path = config_dirs.active.path.join(GLOBAL_CONFIG_FILE);
        let state = StateDirs {
            runtime,
            data: data_dirs,
            config: config_dirs,
        };
        let compiled = compile_session(&config, outputs.clone(), &protected, &state, &ctx)?;
        if config.base == Base::Default && !has_user_tools {
            return Err(RunError::NoToolsConfigured {
                global_config: global_config_path,
            });
        }
        let compile_warnings = warning_lines(&compiled, config.base);
        let provisioned = provision_self(&session)?;
        Ok(LoadedSession {
            workspace,
            config,
            home,
            compiled,
            load_warnings: warnings,
            compile_warnings,
            outputs,
            protected,
            state,
            ctx,
            provisioned,
            session,
        })
    }

    /// Compiles every profile again from the providers' outputs of
    /// [`load`](Self::load), against the filesystem as it is now, with the
    /// compile warnings. A server does this for every run, so globs, masks
    /// and missing paths are decided when the sandbox starts, as for a
    /// standalone run. Script providers are not run again.
    pub(crate) fn recompile(&self) -> Result<(CompiledSession, Vec<String>), RunError> {
        let compiled = compile_session(
            &self.config,
            self.outputs.clone(),
            &self.protected,
            &self.state,
            &self.ctx,
        )?;
        let warnings = warning_lines(&compiled, self.config.base);
        Ok((compiled, warnings))
    }

    /// The warnings of loading and of `compile_warnings`, as printed,
    /// `stopit: warning: …` and escaped.
    pub(crate) fn warning_lines_with(&self, compile_warnings: &[String]) -> Vec<String> {
        self.load_warnings
            .iter()
            .chain(compile_warnings)
            .map(|w| format!("stopit: warning: {}", escape_message(w)))
            .collect()
    }

    /// The warnings of loading and compiling, as printed.
    pub(crate) fn warning_lines(&self) -> Vec<String> {
        self.warning_lines_with(&self.compile_warnings)
    }

    /// The profile `name` (`main` if `None`) of the session as loaded.
    pub(crate) fn profile(
        &self,
        name: Option<&str>,
    ) -> Result<(ProfileRef, &CompiledProfile), RunError> {
        profile_in(&self.compiled, name)
    }

    /// The startup summary of `profile`, named `name`, as printed
    /// (`stopit: …`, escaped).
    pub(crate) fn summary_lines(
        &self,
        name: &ProfileRef,
        profile: &CompiledProfile,
    ) -> Vec<String> {
        let unprotected = unprotected_providers(&self.config);
        let ctx = SummaryContext {
            profile: name.as_str(),
            workspace: &self.workspace.dir,
            workspace_mount: self.config.workspace.mount.as_path(),
            home: &self.home,
            base: self.config.base,
            unprotected: &unprotected,
        };
        summary_lines(&profile.spec, &ctx)
            .iter()
            .map(|line| format!("stopit: {}", escape_message(line)))
            .collect()
    }

    /// The bwrap command running `command` in `profile`, with the target
    /// environment built from `host_env` (§9).
    pub(crate) fn command(
        &self,
        profile: &CompiledProfile,
        command: &[OsString],
        host_env: impl IntoIterator<Item = (OsString, OsString)>,
        terminal: TerminalSession,
    ) -> Result<BwrapCommand, RunError> {
        let env = profile.spec.target_env(host_env);
        let sandbox_cwd = working_dir(&profile.spec, self.config.workspace.mount.as_path());
        Ok(BwrapCommand::for_init(
            &profile.spec,
            &self.session,
            &self.provisioned,
            &sandbox_cwd,
            &env,
            command,
            terminal,
        )?)
    }

    /// The OSC 52 policy for the session's output filter.
    pub(crate) fn clipboard(&self) -> ClipboardPolicy {
        match self.config.terminal.clipboard_write {
            ClipboardWrite::Allow => ClipboardPolicy::Allow,
            // TODO(§5.2): `ask` needs a prompt; until then it blocks.
            ClipboardWrite::Block | ClipboardWrite::Ask => ClipboardPolicy::Block,
        }
    }
}

// --- Signals ---

/// The signals the supervisor catches ([`catch_signals`]) and forwards to
/// bwrap.
const CAUGHT: [libc::c_int; 4] = [libc::SIGINT, libc::SIGQUIT, libc::SIGTERM, libc::SIGHUP];

/// The last caught signal not yet handled, or 0.
static RECEIVED: AtomicI32 = AtomicI32::new(0);

/// Whether the host terminal's window size changed since the relay last
/// copied it ([`record_winch`]).
static WINCH: AtomicBool = AtomicBool::new(false);

/// Signal handler for `SIGWINCH` while the sandbox runs on a PTY.
extern "C" fn record_winch(_: libc::c_int) {
    WINCH.store(true, Ordering::SeqCst);
}

/// Catches `SIGWINCH` with [`record_winch`]. Like [`CAUGHT`], it is blocked
/// except while waiting in `ppoll`, and goes back to its default on `exec`.
pub(crate) fn catch_winch() -> io::Result<()> {
    // SAFETY: `sigaction` on a zeroed, then filled, local struct; the
    // handler only stores to an atomic.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = record_winch as extern "C" fn(libc::c_int) as usize;
        action.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut action.sa_mask);
        if libc::sigaction(libc::SIGWINCH, &action, std::ptr::null_mut()) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Non-blocking self-pipe waking threads blocked in `poll` when a caught
/// signal arrives.
static SIGNAL_READ_FD: AtomicI32 = AtomicI32::new(-1);
static SIGNAL_WRITE_FD: AtomicI32 = AtomicI32::new(-1);
static SIGNAL_PIPE_INIT: std::sync::OnceLock<Result<(), i32>> = std::sync::OnceLock::new();

/// Signal handler for [`CAUGHT`] that records the signal and wakes [`signal_poll_fd`].
extern "C" fn record_signal(signal: libc::c_int) {
    // SAFETY: `__errno_location` returns this thread's valid `errno` slot.
    // Saving and restoring it keeps `write` from clobbering `errno` in the
    // interrupted code.
    let saved_errno = unsafe { *libc::__errno_location() };
    RECEIVED.store(signal, Ordering::SeqCst);
    let wfd = SIGNAL_WRITE_FD.load(Ordering::Relaxed);
    if wfd >= 0 {
        let byte: u8 = 1;
        // SAFETY: `write` is async-signal-safe, and `wfd` is non-blocking.
        unsafe {
            let _ = libc::write(wfd, (&raw const byte).cast(), 1);
        }
    }
    // SAFETY: restores the thread's saved `errno`.
    unsafe {
        *libc::__errno_location() = saved_errno;
    }
}

/// The last caught signal not yet handled, without consuming it.
pub(crate) fn pending_signal() -> Option<libc::c_int> {
    match RECEIVED.load(Ordering::SeqCst) {
        0 => None,
        signal => Some(signal),
    }
}

/// Read end of the signal wakeup pipe, if [`catch_signals`] has installed it.
pub(crate) fn signal_poll_fd() -> Option<libc::c_int> {
    let fd = SIGNAL_READ_FD.load(Ordering::Acquire);
    (fd >= 0).then_some(fd)
}

/// Drains all wakeup bytes currently buffered in [`SIGNAL_READ_FD`].
pub(crate) fn drain_signal_pipe() {
    let rfd = SIGNAL_READ_FD.load(Ordering::Acquire);
    if rfd >= 0 {
        let mut buf = [0u8; 64];
        // SAFETY: `rfd` is a valid non-blocking pipe descriptor owned for the
        // life of the process.
        while unsafe { libc::read(rfd, buf.as_mut_ptr().cast(), buf.len()) } > 0 {}
    }
}

/// The last caught signal not yet handled, if any, now handled.
pub(crate) fn take_signal() -> Option<libc::c_int> {
    let signal = RECEIVED.swap(0, Ordering::SeqCst);
    drain_signal_pipe();
    match signal {
        0 => None,
        signal => Some(signal),
    }
}

fn init_signal_pipe() -> io::Result<()> {
    match *SIGNAL_PIPE_INIT.get_or_init(|| {
        let mut raw = [0 as libc::c_int; 2];
        // SAFETY: `raw` holds two integers. `O_CLOEXEC | O_NONBLOCK` stops
        // child inheritance and keeps writes in `record_signal` from blocking.
        if unsafe { libc::pipe2(raw.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
            return Err(io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO));
        }
        SIGNAL_WRITE_FD.store(raw[1], Ordering::Release);
        SIGNAL_READ_FD.store(raw[0], Ordering::Release);
        Ok(())
    }) {
        Ok(()) => Ok(()),
        Err(errno) => Err(io::Error::from_raw_os_error(errno)),
    }
}

/// Catches [`CAUGHT`] with [`record_signal`], so that the supervisor is not
/// killed before it removes the session directory: while bwrap runs, they
/// are forwarded to it ([`wait_foreground`]); before, one ends the run.
///
/// A caught signal goes back to its default action on `exec`, so bwrap and
/// the script providers inherit nothing from this. A signal ignored when
/// stopit started (`nohup`'s `SIGHUP`) stays ignored, as shells leave it,
/// and is then inherited ignored.
pub(crate) fn catch_signals() -> io::Result<()> {
    init_signal_pipe()?;
    for signal in CAUGHT {
        // SAFETY: `sigaction` on a zeroed, then filled, local struct. The
        // handler saves and restores `errno`, stores to atomics, and writes a
        // byte to a non-blocking pipe, all of which are async-signal-safe.
        unsafe {
            let mut old: libc::sigaction = std::mem::zeroed();
            if libc::sigaction(signal, std::ptr::null(), &mut old) != 0 {
                return Err(io::Error::last_os_error());
            }
            if old.sa_sigaction == libc::SIG_IGN {
                continue;
            }
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = record_signal as extern "C" fn(libc::c_int) as usize;
            // Interrupted system calls elsewhere (script providers' pipes)
            // restart; `ppoll`, which `wait_foreground` relies on, never does.
            action.sa_flags = libc::SA_RESTART;
            libc::sigemptyset(&mut action.sa_mask);
            if libc::sigaction(signal, &action, std::ptr::null_mut()) != 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

/// Ignores `SIGTSTP`, `SIGTTIN` and `SIGTTOU` for the rest of the process's
/// life, and for bwrap, which inherits them ignored (`__init` resets them
/// for the command).
///
/// The supervisor holds the host terminal in raw mode and relays it to the
/// sandbox's PTY ([`SandboxTerminal`]). Stopped, or put in the background,
/// it would leave the terminal raw under the shell while the sandbox waits.
/// Keys such as Ctrl-Z go to the sandbox's own line discipline anyway, so
/// the supervisor cannot be stopped by the terminal, and refuses to start
/// in the background ([`check_foreground`]).
pub(crate) fn ignore_job_control() {
    for signal in [libc::SIGTSTP, libc::SIGTTIN, libc::SIGTTOU] {
        // SAFETY: `signal` with `SIG_IGN` installs no handler code; it only
        // changes this process's disposition. It cannot fail for these
        // signals.
        unsafe { libc::signal(signal, libc::SIG_IGN) };
    }
}

/// Fails unless the supervisor is in the foreground process group of every
/// stdio that is a terminal (`stdio`, see [`stdio_terminals`]) and its
/// controlling terminal. A terminal that is not its controlling terminal
/// has no foreground for it (the kernel's job control does not apply), and
/// passes.
pub(crate) fn check_foreground(stdio: [bool; 3]) -> Result<(), RunError> {
    let own = rustix::process::getpgrp();
    for fd in stdio_fds(stdio) {
        foreground(rustix::termios::tcgetpgrp(fd), own)?;
    }
    Ok(())
}

/// [`check_foreground`] for one terminal, whose foreground process group is
/// `tty_pgrp`, and the supervisor's process group `own`.
pub fn foreground(tty_pgrp: rustix::io::Result<Pid>, own: Pid) -> Result<(), RunError> {
    match tty_pgrp {
        Ok(pgrp) if pgrp == own => Ok(()),
        Ok(_) => Err(RunError::Background),
        // Not the controlling terminal.
        Err(Errno::NOTTY) => Ok(()),
        Err(e) => Err(RunError::Foreground(e.into())),
    }
}

/// The supervisor's stdio, among `stdio` (see [`stdio_terminals`]), that is
/// a terminal.
fn stdio_fds(stdio: [bool; 3]) -> impl Iterator<Item = BorrowedFd<'static>> {
    let fds = [
        io::stdin().as_fd().as_raw_fd(),
        io::stdout().as_fd().as_raw_fd(),
        io::stderr().as_fd().as_raw_fd(),
    ];
    fds.into_iter()
        .zip(stdio)
        .filter(|&(_, tty)| tty)
        // SAFETY: stdio stays open for the life of the process.
        .map(|(fd, _)| unsafe { BorrowedFd::borrow_raw(fd) })
}

/// The PTY a sandbox runs on when the supervisor's stdio includes a
/// terminal (DESIGN.md §5.1), with the host terminal it is relayed to.
pub(crate) struct SandboxTerminal {
    /// The PTY's master, until the relay takes it.
    master: Option<OwnedFd>,
    /// The PTY's slave, until the relay takes it once the sandbox has its
    /// copies.
    slave: Option<OwnedFd>,
    /// Which of stdin, stdout and stderr the slave replaces.
    stdio: [bool; 3],
    /// The host terminal, until the relay takes it.
    host: Option<HostTerminal>,
    /// stdin, when it is a terminal and the relay reads keys from it.
    keys_from: Option<BorrowedFd<'static>>,
    /// The host terminal's raw mode while the relay reads keys. Dropped
    /// last, after the relay's final output.
    raw: Option<RawMode>,
    clipboard: ClipboardPolicy,
}

impl SandboxTerminal {
    /// Opens the PTY for the supervisor's stdio, of which those `stdio`
    /// says are terminals (at least one). The slave starts with the host
    /// terminal's settings and window size. Keys are read from stdin when
    /// it is a terminal, which is put into raw mode before the sandbox
    /// starts; the sandbox's output goes to the first of stdout, stderr and
    /// stdin that is one.
    pub(crate) fn open(
        stdio: [bool; 3],
        clipboard: ClipboardPolicy,
    ) -> io::Result<SandboxTerminal> {
        let fds: Vec<BorrowedFd<'static>> = stdio_fds([true; 3]).collect();
        let input = stdio[0].then_some(fds[0]);
        let output = [1, 2, 0]
            .into_iter()
            .find(|&i| stdio[i])
            .map(|i| fds[i])
            .expect("at least one stdio is a terminal");
        let termios = rustix::termios::tcgetattr(input.unwrap_or(output)).ok();
        let pty = Pty::open(termios.as_ref(), Some(output))?;
        Ok(SandboxTerminal {
            master: Some(pty.master),
            slave: Some(pty.slave),
            stdio,
            host: Some(HostTerminal::open(input, output)?),
            keys_from: input,
            raw: None,
            clipboard,
        })
    }

    /// The slave, while the sandbox still needs copies of it.
    pub(crate) fn slave_fd(&self) -> Option<BorrowedFd<'_>> {
        self.slave.as_ref().map(AsFd::as_fd)
    }

    /// Puts the host terminal into raw mode, if keys are read from it, until
    /// the terminal is dropped.
    pub(crate) fn enter_raw(&mut self) -> io::Result<()> {
        if let Some(keys) = self.keys_from
            && self.raw.is_none()
        {
            self.raw = Some(RawMode::enter(keys)?);
        }
        Ok(())
    }

    /// Sets the OSC 52 policy of the output filter the relay will use.
    pub(crate) fn set_clipboard(&mut self, clipboard: ClipboardPolicy) {
        self.clipboard = clipboard;
    }

    /// Starts relaying once the sandbox has its copies of the slave. The
    /// relay takes the master, the slave and the host terminal.
    pub(crate) fn start_relay(&mut self) -> Option<PtyRelay> {
        Some(PtyRelay::new(
            self.master.take()?,
            self.slave.take()?,
            self.host.take()?,
            OutputFilter::new(self.clipboard),
        ))
    }
}

/// Spawns `command` (bwrap) on the supervisor's stdio, or on the slave of
/// `terminal` where that replaces it, and waits for it, returning the exit
/// status to exit with ([`exit_code`]). With a terminal, the supervisor
/// relays between the PTY master and the host terminal meanwhile
/// ([`PtyRelay`]), and copies window size changes.
///
/// The caught signals ([`CAUGHT`]) are blocked from just before the spawn
/// (bwrap starts with the mask the supervisor had before) and only
/// unblocked while waiting in `ppoll`, so none is missed between checking
/// for one and waiting. One that arrived before the spawn ends the run
/// with `128 + N` instead. One that arrives while bwrap runs is forwarded
/// to it, so that the sandbox ends and the supervisor goes on to clean up;
/// the supervisor then exits with bwrap's status, `128 + N` if the signal
/// killed it. A signal sent to the supervisor alone thus ends the sandbox,
/// which is in a session of its own whenever a terminal is involved.
fn wait_foreground(
    command: BwrapCommand,
    mut terminal: Option<SandboxTerminal>,
) -> Result<u8, RunError> {
    if terminal.is_some() {
        catch_winch().map_err(RunError::Signals)?;
    }
    let mask = BlockedSignals::block().map_err(RunError::Signals)?;
    if let Some(signal) = take_signal() {
        return Ok(signal_exit_code(signal));
    }
    let (mut command, status_reader) = command.into_command_with_status()?;
    if let Some(t) = &terminal {
        let slave = |i: usize| -> Result<Stdio, RunError> {
            match &t.slave {
                Some(slave) if t.stdio[i] => {
                    Ok(Stdio::from(slave.try_clone().map_err(RunError::Pty)?))
                }
                _ => Ok(Stdio::inherit()),
            }
        };
        command.stdin(slave(0)?).stdout(slave(1)?).stderr(slave(2)?);
    }
    let old = mask.old;
    let leave_session = terminal.is_some();
    // SAFETY: `pthread_sigmask` and `setsid` are async-signal-safe, and
    // `old` is a copy.
    unsafe {
        command.pre_exec(move || {
            // On a PTY, bwrap itself leaves the host terminal's session
            // too, so no process of the sandbox's tree keeps the host
            // terminal as its controlling terminal. `__init` then starts
            // its own session below bwrap's.
            if leave_session && libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            match libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut()) {
                0 => Ok(()),
                e => Err(io::Error::from_raw_os_error(e)),
            }
        });
    }
    // Raw before the spawn, so no key typed while the sandbox starts is
    // taken by the host terminal's line discipline.
    if let Some(t) = &mut terminal {
        t.enter_raw().map_err(RunError::Pty)?;
    }
    let mut child = command.spawn().map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            RunError::BwrapMissing
        } else {
            RunError::Spawn(e)
        }
    })?;
    // Close our copies of the status pipe's write end, so `status_reader`
    // sees EOF when bwrap finishes or execs `__init`, and of the slaves
    // given to the sandbox.
    drop(command);
    let mut relay = terminal.as_mut().and_then(SandboxTerminal::start_relay);
    if let Some(r) = &relay {
        r.resize();
    }
    let pid = Pid::from_child(&child);
    let kill_child = |signal| {
        // SAFETY: a plain syscall. The child is not reaped yet, so its pid
        // is still its own.
        unsafe { libc::kill(pid.as_raw_nonzero().get(), signal) };
    };
    // Waiting through a pidfd lets `ppoll` wait for the child, the signals
    // and the PTY at once.
    let pidfd = match rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()) {
        Ok(pidfd) => Some(pidfd),
        // Without the relay the sandbox would block on its terminal, and
        // keys would never arrive.
        Err(e) if relay.is_some() => {
            kill_child(libc::SIGKILL);
            let _ = child.wait();
            if let Some(r) = relay {
                r.finish();
            }
            return Err(RunError::Pty(io::Error::other(format!(
                "cannot wait for bwrap and relay its terminal: pidfd_open failed: {e}"
            ))));
        }
        // Signals are then only forwarded once bwrap is done.
        Err(_) => None,
    };
    if let Some(pidfd) = &pidfd
        && let Err(e) = relay_until(&mask, pidfd.as_fd(), relay.as_mut(), kill_child)
    {
        if let Some(r) = relay {
            kill_child(libc::SIGKILL);
            let _ = child.wait();
            r.finish();
            return Err(RunError::Pty(e));
        }
    }
    let status = child.wait().map_err(RunError::Spawn)?;
    if let Some(r) = relay {
        r.finish();
    }
    // Restores the host terminal's settings, after the last output.
    drop(terminal);
    let json_status = read_nonblocking_status(status_reader);
    Ok(bwrap_exit_code(status, &json_status))
}

/// Waits until `until` is ready, passing caught signals to `on_signal`
/// and relaying the PTY with `relay` meanwhile, if given. Only the caught
/// signals and `SIGWINCH` interrupt the wait, as `mask` arranges.
pub(crate) fn relay_until(
    mask: &BlockedSignals,
    until: BorrowedFd<'_>,
    mut relay: Option<&mut PtyRelay>,
    mut on_signal: impl FnMut(libc::c_int),
) -> io::Result<()> {
    loop {
        if let Some(signal) = take_signal() {
            on_signal(signal);
        }
        if WINCH.swap(false, Ordering::SeqCst)
            && let Some(r) = &relay
        {
            r.resize();
        }
        let mut fds = vec![libc::pollfd {
            fd: until.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        }];
        let mut slots = [None; 3];
        if let Some(interest) = relay.as_ref().map(|r| r.poll_fds()) {
            let wanted = [interest.master, interest.input, interest.output];
            for (slot, wanted) in slots.iter_mut().zip(wanted) {
                if let Some((fd, events)) = wanted {
                    *slot = Some(fds.len());
                    fds.push(libc::pollfd {
                        fd,
                        events,
                        revents: 0,
                    });
                }
            }
        }
        match mask.wait(&mut fds) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
        if let Some(r) = &mut relay {
            let revents = |slot: Option<usize>| slot.map_or(0, |i| fds[i].revents);
            r.handle(revents(slots[0]), revents(slots[1]), revents(slots[2]));
        }
        if fds[0].revents != 0 {
            return Ok(());
        }
    }
}

pub(crate) fn read_nonblocking_status(mut reader: File) -> String {
    let mut raw = Vec::new();
    let mut chunk = [0u8; 512];
    while raw.len() < 4096 {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&raw).into_owned()
}

/// Computes the exit status for bwrap given its process `status` and the JSON
/// lines read from `--json-status-fd`. When bwrap exits non-zero without
/// emitting both `"child-pid"` and `"exit-code"`, bwrap itself failed during
/// setup and we return [`EXIT_SUPERVISOR_FAILED`].
pub(crate) fn bwrap_exit_code(status: ExitStatus, json_status: &str) -> u8 {
    match status.code() {
        None => exit_code(status),
        Some(0) => 0,
        Some(_) => {
            let mut has_child_pid = false;
            let mut has_exit_code = false;
            for line in json_status.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
                    if val.get("child-pid").is_some() {
                        has_child_pid = true;
                    }
                    if val.get("exit-code").is_some() {
                        has_exit_code = true;
                    }
                }
            }
            if has_child_pid && has_exit_code {
                exit_code(status)
            } else {
                EXIT_SUPERVISOR_FAILED
            }
        }
    }
}

/// [`CAUGHT`] blocked, until dropped.
pub(crate) struct BlockedSignals {
    /// The mask before blocking them.
    old: libc::sigset_t,
}

impl BlockedSignals {
    pub(crate) fn block() -> io::Result<Self> {
        // SAFETY: plain libc calls on local, initialized signal sets.
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            for signal in CAUGHT.into_iter().chain([libc::SIGWINCH]) {
                libc::sigaddset(&mut set, signal);
            }
            let mut old: libc::sigset_t = std::mem::zeroed();
            match libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut old) {
                0 => Ok(BlockedSignals { old }),
                e => Err(io::Error::from_raw_os_error(e)),
            }
        }
    }

    /// Waits until one of `fds` is ready, with [`CAUGHT`] and `SIGWINCH`
    /// unblocked meanwhile: `Interrupted` if one of them (or another
    /// signal) arrived.
    pub(crate) fn wait(&self, fds: &mut [libc::pollfd]) -> io::Result<()> {
        // SAFETY: plain libc calls on a local signal set and valid pollfds.
        unsafe {
            let mut waiting = self.old;
            for signal in CAUGHT.into_iter().chain([libc::SIGWINCH]) {
                libc::sigdelset(&mut waiting, signal);
            }
            if libc::ppoll(
                fds.as_mut_ptr(),
                fds.len() as libc::nfds_t,
                std::ptr::null(),
                &waiting,
            ) < 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
}

impl Drop for BlockedSignals {
    fn drop(&mut self) {
        // SAFETY: restores the mask saved in `block`.
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &self.old, std::ptr::null_mut()) };
    }
}

/// The exit status for a process killed by `signal`: `128 + N`, as shells
/// report it.
pub(crate) fn signal_exit_code(signal: libc::c_int) -> u8 {
    u8::try_from(128 + signal).unwrap_or(u8::MAX)
}

/// The exit status for a command that ended with `status`: its exit code,
/// or `128 + N` if it was killed by signal `N`, as shells report it.
pub fn exit_code(status: ExitStatus) -> u8 {
    if let Some(code) = status.code() {
        // An exit code is the low 8 bits of what the process passed to
        // `exit`, so it always fits.
        return u8::try_from(code).unwrap_or(EXIT_SUPERVISOR_FAILED);
    }
    match status.signal() {
        Some(signal) => signal_exit_code(signal),
        None => EXIT_SUPERVISOR_FAILED,
    }
}

/// Whether the sandbox must leave the supervisor's session (see
/// [`TerminalSession`]): when any of its stdio is a terminal, or the
/// supervisor has a controlling terminal at all, which the sandbox could
/// open as `/dev/tty` (the minimal `/dev` has it) even with every stdio
/// redirected.
pub fn needs_new_session(stdio_is_terminal: [bool; 3], has_controlling_terminal: bool) -> bool {
    stdio_is_terminal.contains(&true) || has_controlling_terminal
}

/// Whether each of the supervisor's stdin, stdout and stderr is a terminal.
pub(crate) fn stdio_terminals() -> [bool; 3] {
    [
        io::stdin().is_terminal(),
        io::stdout().is_terminal(),
        io::stderr().is_terminal(),
    ]
}

/// How the sandbox relates to this process's terminal, whose stdio is a
/// terminal as `stdio` says: on a PTY of its own if any is
/// ([`TerminalSession::Pty`]), else detached if [`needs_new_session`].
fn terminal_session(stdio: [bool; 3]) -> TerminalSession {
    if stdio.contains(&true) {
        TerminalSession::Pty
    } else if needs_new_session(stdio, has_controlling_terminal()) {
        TerminalSession::Detach
    } else {
        TerminalSession::Keep
    }
}

/// Whether this process has a controlling terminal: `/dev/tty` opens only
/// then (`ENXIO` otherwise). Any other failure counts as having one, which
/// only costs job control.
fn has_controlling_terminal() -> bool {
    use rustix::fs::{Mode, OFlags, open};
    match open(
        "/dev/tty",
        OFlags::RDONLY | OFlags::NOCTTY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(_) => true,
        Err(e) => e != rustix::io::Errno::NXIO,
    }
}

/// The canonical host `HOME`, from its value `home`.
fn host_home(home: Option<OsString>) -> Result<PathBuf, RunError> {
    let home = match home {
        Some(home) if !home.is_empty() => PathBuf::from(home),
        _ => return Err(RunError::HomeUnset),
    };
    fs::canonicalize(&home).map_err(|source| RunError::Home { path: home, source })
}

/// The session's workspace and its configuration file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Workspace {
    /// The workspace directory, canonical.
    pub dir: PathBuf,
    /// Its `.stopit.toml`, if it has one: the workspace directory joined
    /// with [`CONFIG_FILE`], so canonical (the file itself is never a
    /// link, [`open_trusted`]).
    pub config: Option<PathBuf>,
}

impl Workspace {
    /// The configuration file's content, if there is one.
    ///
    /// The file must be the user's own and only theirs to change
    /// ([`check_config_trust`]): it decides what the sandbox may do and which
    /// script providers run on the host, as the user. The bytes returned
    /// are the ones both hashed ([`check_allowed`]) and parsed
    /// ([`ConfigFile::parse`]), so the file cannot change between the two.
    pub fn read_config(&self) -> Result<Option<ConfigFile>, RunError> {
        let Some(path) = &self.config else {
            return Ok(None);
        };
        Ok(Some(ConfigFile {
            path: path.clone(),
            bytes: read_trusted(path)?,
        }))
    }
}

/// A configuration file's content, as read once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigFile {
    /// The file, canonical.
    pub path: PathBuf,
    /// Its content.
    pub bytes: Vec<u8>,
}

impl ConfigFile {
    /// Parses the file as a [`Config`].
    pub fn parse(&self) -> Result<Config, RunError> {
        Ok(self.parse_layer()?.into_config())
    }

    /// Parses the file as a [`ConfigLayer`] keeping explicit field presence.
    pub fn parse_layer(&self) -> Result<ConfigLayer, RunError> {
        parse_layer(&self.path, &self.bytes)
    }
}

/// User-global configuration file content and canonical target path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalConfigFile {
    /// Declared path `<config_dir>/config.toml` used in error messages.
    pub path: PathBuf,
    /// Canonical path of the underlying file, protected against writable grants.
    pub canonical_path: PathBuf,
    /// Raw file bytes.
    pub bytes: Vec<u8>,
}

impl GlobalConfigFile {
    /// Parses the file as a [`ConfigLayer`] keeping explicit field presence.
    pub fn parse_layer(&self) -> Result<ConfigLayer, RunError> {
        parse_layer(&self.path, &self.bytes)
    }
}

/// Parses `bytes`, read from `path`, as a [`ConfigLayer`].
fn parse_layer(path: &Path, bytes: &[u8]) -> Result<ConfigLayer, RunError> {
    let text = std::str::from_utf8(bytes).map_err(|e| RunError::ReadConfig {
        path: path.to_owned(),
        source: io::Error::new(io::ErrorKind::InvalidData, e),
    })?;
    ConfigLayer::from_toml_str(text).map_err(|source| RunError::Config {
        path: path.to_owned(),
        source,
    })
}

/// Whether `manifest` grants tools in its top-level grants or any contributed profile.
pub fn manifest_grants_tools(manifest: &Manifest) -> bool {
    grants_tools(&manifest.grants) || manifest.profiles.values().any(|p| grants_tools(&p.grants))
}

fn grants_tools(grants: &Grants) -> bool {
    !grants.fs.ro.is_empty()
        || !grants.fs.rw.is_empty()
        || !grants.fs.bind.is_empty()
        || !grants.env.path_prepend.is_empty()
}

fn no_tools_configured_message(global_config: &Path) -> String {
    format!(
        "base = \"default\" mounts no tools, and no provider in {global_config:?} or {CONFIG_FILE} \
         grants any; configure a tool provider in {global_config:?} for every workspace or in \
         {CONFIG_FILE} for this workspace, for example:\n\
         \n\
         [[provider]]\n\
         type = \"config\"\n\
         name = \"tools\"\n\
         [provider.sandbox]\n\
         fs.ro = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\"]\n\
         env.path_prepend = [\"/usr/bin\", \"/bin\"]"
    )
}

/// Refuses `file` unless `allowed` (the trust store) allows its path with
/// exactly its content ([`RunError::NotAllowed`]): a sandbox can write a
/// `.stopit.toml` where a later run finds it (§3, §11), and only the user
/// can allow one. `workspace` is the workspace if `--workspace` named it,
/// for the hint to run `stopit allow --workspace` with it.
pub fn check_allowed(
    allowed: &Allowed,
    file: &ConfigFile,
    workspace: Option<&Path>,
) -> Result<(), RunError> {
    let changed = match allowed.decide(&file.path, &file.bytes) {
        Decision::Allowed => return Ok(()),
        Decision::Changed => true,
        Decision::Unknown => false,
    };
    Err(RunError::NotAllowed {
        path: file.path.clone(),
        changed,
        workspace: workspace.map(Path::to_path_buf),
    })
}

/// The message of [`RunError::NotAllowed`].
fn not_allowed_message(path: &Path, changed: bool, workspace: Option<&Path>) -> String {
    let what = if changed {
        "it changed since it was last allowed"
    } else {
        "it is new: it has not been allowed, or was revoked"
    };
    let command = match workspace {
        None => "stopit allow".to_owned(),
        Some(dir) => format!("stopit allow --workspace {}", quote_path(dir)),
    };
    format!(
        "refusing to use {path:?}: {what}. stopit only uses a configuration you allowed, as it \
         was when you allowed it, since it decides what the sandbox may do and which scripts \
         run on the host; review it, then run `{command}`"
    )
}

/// `path` quoted for the shell, for a command a message suggests
/// ([`shell_quote`]).
fn quote_path(path: &Path) -> String {
    shell_quote(path.as_os_str().as_bytes())
}

/// Refuses to run the default configuration in the workspace `dir`, which
/// has no configuration file, if `allowed` (the trust store) has an entry
/// for a `.stopit.toml` where discovery looked for one: in `dir` itself if
/// `--workspace` named it (`explicit`), else in `dir` (the current
/// directory) or any directory above it ([`RunError::MissingConfig`]).
/// Such a configuration was allowed, and is gone: deleted, or moved away
/// with a directory on its path (a sandbox can rename what its writable
/// grants contain), and the default configuration in its place may grant
/// what the user's did not. Revoking the entry (`stopit revoke PATH`) is
/// how the defaults are chosen there.
///
/// Also if an entry lies at or below one of `links`, the symbolic links
/// followed on the way to the workspace ([`discovery_links`]): entries are
/// canonical, so that path was a directory when it was allowed, and a
/// sandbox that can write the directory holding it can move the directory
/// away and put a link to one without a configuration in its place, so
/// that discovery, which resolves links, finds none. Such an entry may
/// also be stale (the user moved the project and left a link), and
/// refusing is the safe direction: the user allows the configuration again
/// at its new path, or revokes the entry.
pub fn check_missing(
    allowed: &Allowed,
    dir: &Path,
    explicit: bool,
    links: &[PathBuf],
) -> Result<(), RunError> {
    let searched = dir.ancestors().take(if explicit { 1 } else { usize::MAX });
    if let Some(path) = searched
        .map(|d| d.join(CONFIG_FILE))
        .find(|path| allowed.contains(path))
    {
        return Err(RunError::MissingConfig { path, via: None });
    }
    for (path, _) in allowed.iter() {
        if let Some(link) = links.iter().find(|link| path.starts_with(link)) {
            return Err(RunError::MissingConfig {
                path: path.to_path_buf(),
                via: Some(link.clone()),
            });
        }
    }
    Ok(())
}

/// The symbolic links followed on the way to the workspace, as the user
/// named it, for [`check_missing`]: resolving (with
/// [`resolve_allowing_missing`]) `--workspace` (`explicit`) against the
/// current directory `cwd`, or else the current directory as the shell
/// tracks it, `PWD` (`pwd`), if it is absolute and is the current directory
/// (the kernel's `cwd` has every link resolved already). None if neither
/// can be told, or resolving fails (discovery has resolved the same path
/// by then, so that is a race, which the trust store's checks cover).
pub fn discovery_links(cwd: &Path, explicit: Option<&Path>, pwd: Option<OsString>) -> Vec<PathBuf> {
    let start = match (explicit, pwd) {
        (Some(explicit), _) => cwd.join(explicit),
        (None, Some(pwd)) => {
            let pwd = PathBuf::from(pwd);
            let resolved = fs::canonicalize(&pwd).ok();
            if !pwd.is_absolute() || resolved.is_none() || resolved != fs::canonicalize(cwd).ok() {
                return Vec::new();
            }
            pwd
        }
        (None, None) => return Vec::new(),
    };
    resolve_allowing_missing(&start)
        .map(|resolved| resolved.links)
        .unwrap_or_default()
}

/// The message of [`RunError::MissingConfig`].
fn missing_config_message(path: &Path, via: Option<&Path>) -> String {
    let why = match via {
        None => format!("{path:?} was allowed but is missing"),
        Some(link) => format!(
            "{path:?} was allowed, but {link:?}, on the way to it, is now a symbolic link, so it \
             is not where it was allowed"
        ),
    };
    format!(
        "refusing to run the default configuration: {why}, and the defaults may grant what it \
         did not; restore it, or run `stopit revoke {}` to use the defaults there",
        quote_path(path)
    )
}

/// Where [`RunError::NothingToAllow`] looked.
fn no_config_place(dir: &Path, explicit: bool) -> String {
    if explicit {
        dir.display().to_string()
    } else {
        format!("{} or any directory above it", dir.display())
    }
}

/// The owner and mode (file type bits included) of a file, as `stat`
/// reports them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ownership {
    /// The owner's user id.
    pub uid: u32,
    /// `st_mode`.
    pub mode: u32,
}

impl Ownership {
    /// The owner and mode in `stat`.
    pub(crate) fn of(stat: &rustix::fs::Stat) -> Self {
        Ownership {
            uid: stat.st_uid,
            mode: stat.st_mode,
        }
    }
}

/// Reads the configuration file at `path` if [`check_config_trust`] allows
/// it, from the descriptor it checked ([`open_trusted`]).
fn read_trusted(path: &Path) -> Result<Vec<u8>, RunError> {
    let mut bytes = Vec::new();
    File::from(open_trusted(path)?)
        .read_to_end(&mut bytes)
        .map_err(|source| RunError::ReadConfig {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(bytes)
}

/// Opens the configuration file at `path` for reading if
/// [`check_config_trust`] allows it, and returns the descriptor it checked:
/// its directory is opened, then the file in it without following a
/// symlink (a symlink is refused, as the file it leads to could be
/// anyone's, anywhere).
///
/// `path` is canonical (discovery resolved it), and it is the trust
/// store's key for the file, so the directory is opened with
/// `openat2(RESOLVE_NO_SYMLINKS)`: a link swapped in on the way since
/// discovery would make the file read another than the one the key names,
/// and is refused (`ELOOP`). That needs Linux 5.6 (`ENOSYS` before it, and
/// `EPERM` under a seccomp profile that blocks it, both reported as such).
fn open_trusted(path: &Path) -> Result<rustix::fd::OwnedFd, RunError> {
    use rustix::fs::{CWD, Mode, OFlags, ResolveFlags, fstat, openat, openat2};
    let read_error = |source: io::Error| RunError::ReadConfig {
        path: path.to_path_buf(),
        source,
    };
    let untrusted = |reason: String| RunError::UntrustedConfig {
        path: path.to_path_buf(),
        reason,
    };
    let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(read_error(io::ErrorKind::InvalidInput.into()));
    };
    let dir_fd = match openat2(
        CWD,
        dir,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS,
    ) {
        Ok(fd) => fd,
        Err(Errno::LOOP) => {
            return Err(untrusted(format!(
                "the way to it, {dir:?}, runs through a symbolic link, though it was resolved \
                 without one: one was put there since, and the file it leads to is not the one \
                 its path names"
            )));
        }
        // `EPERM` is what seccomp profiles that block it return.
        Err(e @ (Errno::NOSYS | Errno::PERM)) => {
            return Err(read_error(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "openat2 failed ({e}); stopit needs it: Linux 5.6 or later, without a \
                     seccomp profile that blocks it"
                ),
            )));
        }
        Err(e) => return Err(read_error(e.into())),
    };
    // Non-blocking, so that a FIFO does not hang the open; it is refused as
    // not a regular file.
    let fd = match openat(
        &dir_fd,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NOCTTY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::LOOP) => return Err(untrusted("it is a symbolic link".into())),
        Err(e) => return Err(read_error(e.into())),
    };
    let file = fstat(&fd).map_err(|e| read_error(e.into()))?;
    let dir_stat = fstat(&dir_fd).map_err(|e| read_error(e.into()))?;
    check_config_trust(
        Ownership::of(&file),
        Ownership::of(&dir_stat),
        rustix::process::getuid().as_raw(),
    )
    .map_err(untrusted)?;
    Ok(fd)
}

/// Whether a configuration file `file` in the directory `dir` can be trusted
/// by the user `uid`, and why not: the file must be a regular file owned by
/// `uid` and writable by no one else (no group or other write bit), and
/// the directory owned by `uid` or root and not writable by group or
/// others, unless it is sticky (as `/tmp` is, where no one else can
/// replace the user's file). Otherwise another user could choose what the
/// sandbox may do and run their script providers as `uid`: walking up from
/// `/tmp/proj` finds a `/tmp/.stopit.toml` anyone can create.
pub fn check_config_trust(file: Ownership, dir: Ownership, uid: u32) -> Result<(), String> {
    if file.mode & libc::S_IFMT != libc::S_IFREG {
        return Err("it is not a regular file".into());
    }
    if file.uid != uid {
        return Err(format!(
            "it is owned by uid {}, not by you (uid {uid})",
            file.uid
        ));
    }
    if file.mode & 0o022 != 0 {
        return Err(format!(
            "it is writable by its group or others (mode {:04o}); run `chmod go-w` on it",
            file.mode & 0o7777
        ));
    }
    if dir.uid != uid && dir.uid != 0 {
        return Err(format!(
            "its directory is owned by uid {}, neither you (uid {uid}) nor root",
            dir.uid
        ));
    }
    if dir.mode & 0o022 != 0 && dir.mode & libc::S_ISVTX == 0 {
        return Err(format!(
            "its directory is writable by its group or others and not sticky (mode {:04o}), so \
             they could replace it",
            dir.mode & 0o7777
        ));
    }
    Ok(())
}

/// Whether `name` is the name a `[[provider]]` gets without `name`, its
/// type.
fn is_default_provider_name(name: &ProviderName) -> bool {
    matches!(name.as_str(), "config" | "script" | "vcs")
}

/// The paths to protect for the global configuration `file`, whose
/// `[[provider]]` entries are `entries`, declared in `config_dir`: its
/// canonical path and the canonical source of every protected `script`
/// entry, used in this session or not.
///
/// Each is resolved from its declared path and refused if the way runs
/// through a symbolic link inside `workspace` or one of `rw_grants`, which
/// a sandbox of this session could re-point. Protecting the target alone
/// would leave that link replaceable, and every later session would read
/// what it then names.
fn guard_global_config(
    file: &GlobalConfigFile,
    entries: &[ProviderEntry],
    config_dir: &Path,
    workspace: &Path,
    rw_grants: &[UntrustedRoot],
) -> Result<Vec<PathBuf>, RunError> {
    let untrusted = |reason: String| RunError::UntrustedConfig {
        path: file.path.clone(),
        reason,
    };
    let resolve =
        |declared: &Path, what: &str| match resolve_script_path(declared, workspace, rw_grants) {
            Ok(path) => Ok(path),
            Err(ScriptPathError::Link { link, root }) => Err(untrusted(format!(
                "the way to {what} {declared:?} runs through the symbolic link {link:?} inside \
             {root}, which a sandbox can write, so it could re-point the link; use a path \
             with no symbolic link inside that directory"
            ))),
            Err(ScriptPathError::Lookup(e)) => Err(untrusted(format!(
                "cannot resolve {what} {declared:?}: {e}"
            ))),
        };
    let mut paths = Vec::new();
    let resolved = resolve(&file.path, "the configuration")?;
    if resolved != file.canonical_path {
        return Err(untrusted(format!(
            "it resolved to {:?} when read, and now to {resolved:?}",
            file.canonical_path
        )));
    }
    paths.push(resolved);
    for entry in entries {
        let ProviderKind::Script {
            source,
            protect: true,
            ..
        } = &entry.kind
        else {
            continue;
        };
        let declared = config_dir.join(source.as_path());
        let script = resolve(
            &declared,
            &format!("script provider {:?}", entry.name.as_str()),
        )?;
        if !paths.contains(&script) {
            paths.push(script);
        }
    }
    Ok(paths)
}

/// Reads `<config_dir>/config.toml` when present and trusted for the current user.
pub fn read_global_config(config_dirs: &ConfigDirs) -> Result<Option<GlobalConfigFile>, RunError> {
    read_global_config_as(config_dirs, rustix::process::getuid().as_raw())
}

fn read_global_config_as(
    config_dirs: &ConfigDirs,
    uid: u32,
) -> Result<Option<GlobalConfigFile>, RunError> {
    use rustix::fs::{AtFlags, CWD, Mode, OFlags, ResolveFlags, fstat, openat, openat2, statat};

    let dir = &config_dirs.active.path;
    let declared_path = dir.join(GLOBAL_CONFIG_FILE);
    let read_error = |source: io::Error| RunError::ReadConfig {
        path: declared_path.clone(),
        source,
    };
    let untrusted = |reason: String| RunError::UntrustedConfig {
        path: declared_path.clone(),
        reason,
    };

    let dir_fd = match openat2(
        CWD,
        dir,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS,
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(None),
        Err(Errno::NOTDIR) => {
            return Err(untrusted(format!(
                "{dir:?} or a path on the way to it is not a directory"
            )));
        }
        Err(Errno::LOOP) => {
            return Err(untrusted(format!(
                "the way to it, {dir:?}, runs through a symbolic link, though it was resolved \
                 without one; a symbolic link was put there since"
            )));
        }
        Err(e @ (Errno::NOSYS | Errno::PERM)) => {
            return Err(read_error(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "openat2 failed with {e}; stopit needs Linux 5.6 or later without a seccomp \
                     profile that blocks openat2"
                ),
            )));
        }
        Err(e) => return Err(read_error(e.into())),
    };

    let check_way_and_dir = || -> Result<(), RunError> {
        for link in &config_dirs.active.links {
            let link_meta = fs::symlink_metadata(link).map_err(&read_error)?;
            check_global_link_trust(link_meta.uid(), uid).map_err(|why| {
                untrusted(format!(
                    "{link:?} on the way to it failed trust checks, {why}"
                ))
            })?;
            if let Some(link_parent) = link.parent() {
                let parent_meta = fs::metadata(link_parent).map_err(&read_error)?;
                check_global_dir_trust(
                    Ownership {
                        uid: parent_meta.uid(),
                        mode: parent_meta.mode(),
                    },
                    uid,
                )
                .map_err(|why| {
                    untrusted(format!(
                        "the directory {link_parent:?} holding the link {link:?} on the way to it \
                         {why}"
                    ))
                })?;
            }
        }
        let dir_stat = fstat(&dir_fd).map_err(|e| read_error(e.into()))?;
        check_global_dir_trust(Ownership::of(&dir_stat), uid)
            .map_err(|why| untrusted(format!("the directory {dir:?} holding it {why}")))
    };

    let (fd, canonical_path) = match openat(
        &dir_fd,
        GLOBAL_CONFIG_FILE,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NOCTTY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Err(Errno::NOENT) => return Ok(None),
        Ok(fd) => {
            check_way_and_dir()?;
            let file_stat = fstat(&fd).map_err(|e| read_error(e.into()))?;
            check_global_file_trust(Ownership::of(&file_stat), uid).map_err(&untrusted)?;
            (fd, declared_path.clone())
        }
        Err(Errno::LOOP) => {
            check_way_and_dir()?;
            let link_stat = statat(&dir_fd, GLOBAL_CONFIG_FILE, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|e| read_error(e.into()))?;
            if link_stat.st_mode & libc::S_IFMT != libc::S_IFLNK {
                return Err(untrusted(
                    "it stopped being a symbolic link between two opens; run stopit again".into(),
                ));
            }
            check_global_link_trust(link_stat.st_uid, uid).map_err(&untrusted)?;
            let fd = match openat(
                &dir_fd,
                GLOBAL_CONFIG_FILE,
                OFlags::RDONLY | OFlags::NOCTTY | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(fd) => fd,
                Err(Errno::NOENT) => {
                    return Err(untrusted("it is a dangling symbolic link".into()));
                }
                Err(e) => return Err(read_error(e.into())),
            };
            let target_stat = fstat(&fd).map_err(|e| read_error(e.into()))?;
            check_global_file_trust(Ownership::of(&target_stat), uid)
                .map_err(|why| untrusted(format!("its target failed trust checks, {why}")))?;
            let canonical_path =
                fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())).map_err(&read_error)?;
            let (Some(target_dir), Some(target_name)) =
                (canonical_path.parent(), canonical_path.file_name())
            else {
                return Err(untrusted(format!(
                    "its target {canonical_path:?} has no parent directory"
                )));
            };
            let target_dir_fd = match openat2(
                CWD,
                target_dir,
                OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::NO_SYMLINKS,
            ) {
                Ok(tfd) => tfd,
                Err(Errno::LOOP) => {
                    return Err(untrusted(format!(
                        "the directory {target_dir:?} holding its target {canonical_path:?} runs \
                         through a symbolic link"
                    )));
                }
                Err(e) => {
                    return Err(untrusted(format!(
                        "cannot inspect the directory {target_dir:?} holding its target \
                         {canonical_path:?}: {e}"
                    )));
                }
            };
            let target_dir_stat = fstat(&target_dir_fd).map_err(|e| read_error(e.into()))?;
            check_global_dir_trust(Ownership::of(&target_dir_stat), uid).map_err(|why| {
                untrusted(format!(
                    "the directory {target_dir:?} holding its target {canonical_path:?} {why}"
                ))
            })?;
            let verify_stat = statat(&target_dir_fd, target_name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|e| {
                    untrusted(format!(
                        "its target {canonical_path:?} could not be verified: {e}"
                    ))
                })?;
            if (verify_stat.st_dev, verify_stat.st_ino) != (target_stat.st_dev, target_stat.st_ino)
            {
                return Err(untrusted(format!(
                    "its target {canonical_path:?} was replaced or deleted while being opened"
                )));
            }
            (fd, canonical_path)
        }
        Err(e) => return Err(read_error(e.into())),
    };

    // Another name for the file inside a writable grant would let a sandbox
    // rewrite it whatever protects this one.
    let mut file = File::from(fd);
    let meta = file.metadata().map_err(&read_error)?;
    if has_rewritable_hard_links(&canonical_path, &meta) {
        return Err(untrusted(format!(
            "{canonical_path:?} has {} hard links, and a sandbox could rewrite it through \
             another one; give it a single name",
            meta.nlink()
        )));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(&read_error)?;
    Ok(Some(GlobalConfigFile {
        path: declared_path,
        canonical_path,
        bytes,
    }))
}

/// Checks ownership and mode of a global configuration file or symlink target.
pub fn check_global_file_trust(file: Ownership, uid: u32) -> Result<(), String> {
    if file.mode & libc::S_IFMT != libc::S_IFREG {
        return Err("it is not a regular file".into());
    }
    if file.uid != uid && file.uid != 0 {
        return Err(format!(
            "it is owned by uid {}, neither uid {uid} nor root",
            file.uid
        ));
    }
    if file.mode & 0o022 != 0 {
        return Err(format!(
            "it has mode {:04o} and is writable by its group or others; run `chmod go-w` on it",
            file.mode & 0o7777
        ));
    }
    Ok(())
}

/// Checks ownership and mode of a directory on the way to the global
/// configuration. The reason is a predicate for the caller to put after the
/// directory's name.
pub fn check_global_dir_trust(dir: Ownership, uid: u32) -> Result<(), String> {
    if dir.uid != uid && dir.uid != 0 {
        return Err(format!(
            "is owned by uid {}, neither uid {uid} nor root",
            dir.uid
        ));
    }
    if dir.mode & 0o022 != 0 && dir.mode & libc::S_ISVTX == 0 {
        return Err(format!(
            "has mode {:04o}, writable by its group or others and not sticky, so others could \
             replace what it holds",
            dir.mode & 0o7777
        ));
    }
    Ok(())
}

/// Checks ownership of a symlink naming the global configuration file.
pub fn check_global_link_trust(link_uid: u32, uid: u32) -> Result<(), String> {
    if link_uid != uid && link_uid != 0 {
        return Err(format!(
            "the symbolic link is owned by uid {link_uid}, neither uid {uid} nor root"
        ));
    }
    Ok(())
}

/// The message of [`RunError::NestedConfig`]: it suggests `--workspace`
/// with the outer configuration's directory only if that one would load.
fn nested_config_message(inner: &Path, outer: &Path, outer_unusable: Option<&str>) -> String {
    let dir = |p: &Path| quote_path(p.parent().unwrap_or(Path::new("/")));
    let head = format!(
        "refusing to use {inner:?}: {outer:?} is in a directory above it, so it lies inside that \
         configuration's workspace, where a sandbox could have written it, and nested \
         configurations found by walking up are refused"
    );
    match outer_unusable {
        None => format!(
            "{head}: run with `--workspace {}` to use the outer one, or, if you wrote the inner \
             one yourself, with `--workspace {}`",
            dir(outer),
            dir(inner)
        ),
        Some(why) => format!(
            "{head}; the outer one fails the trust checks too ({why}), so fix that, or, if you \
             wrote the inner one yourself, run with `--workspace {}`",
            dir(inner)
        ),
    }
}

/// Finds the workspace (§3.1), from the current directory `cwd`: the
/// directory `explicit` (`--workspace`, relative to `cwd`) if given, else
/// the nearest directory from `cwd` up that contains `.stopit.toml`, else
/// `cwd` itself. Its configuration file is its own `.stopit.toml`, if any;
/// `--workspace` does not look further up. A configuration file found is
/// only used if the user allowed it ([`check_allowed`]), so a sandbox
/// cannot plant one for the next run to load (§3).
///
/// A `.stopit.toml` found walking up is refused if a directory above it has
/// a `.stopit.toml` entry owned by the user ([`RunError::NestedConfig`]):
/// it lies inside that configuration's workspace, which a sandbox could
/// write, and a planted one would decide the grants and script providers of
/// the next `stopit run` from below it. The default base protects existing
/// nested ones, but a glob cannot keep a sandbox from creating one (§3,
/// §11). The sandbox cannot create or change the outer one, which the
/// supervisor protects in every profile of its sessions, so this blocks
/// that (defence in depth: such a file is not allowed either). Ownership
/// alone decides, not the trust checks of
/// [`check_config_trust`]: a sandbox can change modes in the workspace
/// (`chmod 0777` on its root) to make the outer one fail them, but not
/// owners. One owned by someone else is skipped: anyone may have created
/// it (`/tmp`), and it is never loaded. The error suggests `--workspace`
/// with the outer directory only if the outer one passes the trust checks.
/// `--workspace` names the directory explicitly, and is how a nested
/// configuration is used on purpose.
///
/// The workspace is canonical (no symlinks, `.` or `..`): it is the
/// session's identity, and rules below it are resolved against it.
pub fn discover_workspace(cwd: &Path, explicit: Option<&Path>) -> Result<Workspace, RunError> {
    discover_workspace_as(cwd, explicit, rustix::process::getuid().as_raw())
}

/// [`discover_workspace`] for the user `uid`, whose `.stopit.toml` files
/// above another one count as outer configurations.
fn discover_workspace_as(
    cwd: &Path,
    explicit: Option<&Path>,
    uid: u32,
) -> Result<Workspace, RunError> {
    let canonical = |path: PathBuf| {
        fs::canonicalize(&path).map_err(|source| RunError::Workspace { path, source })
    };
    if let Some(explicit) = explicit {
        let dir = canonical(cwd.join(explicit))?;
        if !dir.is_dir() {
            return Err(RunError::WorkspaceNotDir(dir));
        }
        let config = config_in(&dir)?;
        return Ok(Workspace { dir, config });
    }
    let start = canonical(cwd.to_path_buf())?;
    for dir in start.ancestors() {
        if let Some(config) = config_in(dir)? {
            for above in dir.ancestors().skip(1) {
                // The user's own counts whatever the modes, which a sandbox
                // can change; someone else's is skipped.
                let Some(outer) = config_in(above)? else {
                    continue;
                };
                let owner = fs::symlink_metadata(&outer).map_err(|source| RunError::Discover {
                    path: outer.clone(),
                    source,
                })?;
                if owner.uid() != uid {
                    continue;
                }
                let outer_unusable = open_trusted(&outer).err().map(|e| e.to_string());
                return Err(RunError::NestedConfig {
                    inner: config,
                    outer,
                    outer_unusable,
                });
            }
            return Ok(Workspace {
                dir: dir.to_path_buf(),
                config: Some(config),
            });
        }
    }
    Ok(Workspace {
        dir: start,
        config: None,
    })
}

/// `dir`'s `.stopit.toml`, if it has an entry of that name (a broken one
/// fails later, when read).
fn config_in(dir: &Path) -> Result<Option<PathBuf>, RunError> {
    let path = dir.join(CONFIG_FILE);
    match fs::symlink_metadata(&path) {
        Ok(_) => Ok(Some(path)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(RunError::Discover { path, source }),
    }
}

/// The session's warnings to print, in order: every profile's, each
/// distinct message once (an inherited rule is planned again in every
/// profile inheriting it, and warns again there), without the missing
/// paths of the built-in base's own rules ([`is_quiet`]).
pub fn warning_lines(session: &CompiledSession, base: Base) -> Vec<String> {
    distinct_messages(session.warnings().map(|(_, w)| w), base)
}

/// The messages of `warnings` not [`is_quiet`] under `base`, each distinct
/// one once, in order.
fn distinct_messages<'a>(
    warnings: impl IntoIterator<Item = &'a SpecWarning>,
    base: Base,
) -> Vec<String> {
    let mut seen = HashSet::new();
    warnings
        .into_iter()
        .filter(|w| !is_quiet(w, base))
        .map(ToString::to_string)
        .filter(|m| seen.insert(m.clone()))
        .collect()
}

/// Whether `warning` is not worth printing: a path missing for a rule of
/// the built-in `base` provider of `base = "default"`. Its rules name files
/// many workspaces lack (`.envrc`, `flake.lock`, `.vscode`, …), so these
/// would warn in nearly every workspace. Under `base = "none"` a user
/// provider may be named `base`, and is not quiet.
pub fn is_quiet(warning: &SpecWarning, base: Base) -> bool {
    base == Base::Default
        && matches!(
            warning,
            SpecWarning::Mount(PlanWarning {
                provider,
                kind: PlanWarningKind::Resolve(ResolveWarning::Missing { .. }),
                ..
            }) if provider.as_str() == BASE_PROVIDER_NAME
        )
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};

    use tempfile::TempDir;

    use super::*;
    use crate::policy::NetworkMode;

    // --- Workspace discovery ---

    /// A canonical temporary directory.
    fn tmp() -> (TempDir, PathBuf) {
        let dir = TempDir::new().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        (dir, root)
    }

    #[test]
    fn the_nearest_config_up_from_the_cwd_marks_the_workspace() {
        let (_d, root) = tmp();
        let deep = root.join("ws/a/b");
        fs::create_dir_all(&deep).unwrap();
        fs::write(root.join("ws").join(CONFIG_FILE), "").unwrap();
        let ws = discover_workspace(&deep, None).unwrap();
        assert_eq!(ws.dir, root.join("ws"));
        assert_eq!(ws.config, Some(root.join("ws").join(CONFIG_FILE)));
        // From the workspace itself.
        assert_eq!(
            discover_workspace(&root.join("ws"), None).unwrap().dir,
            root.join("ws")
        );
    }

    /// Writes an empty configuration file at `path` that
    /// [`check_config_trust`] allows whatever the umask.
    fn write_trusted(path: &Path) {
        fs::write(path, "").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
        let dir = path.parent().unwrap();
        fs::set_permissions(dir, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn a_config_below_another_is_refused_unless_named() {
        let (_d, root) = tmp();
        let deep = root.join("ws/sub/deeper");
        fs::create_dir_all(&deep).unwrap();
        write_trusted(&root.join("ws").join(CONFIG_FILE));
        // As a sandbox of `ws` could plant it; any entry counts.
        symlink("x", root.join("ws/sub").join(CONFIG_FILE)).unwrap();
        for cwd in [root.join("ws/sub"), deep] {
            let e = discover_workspace(&cwd, None).unwrap_err();
            let RunError::NestedConfig {
                inner,
                outer,
                outer_unusable,
            } = &e
            else {
                panic!("{e:?}");
            };
            assert_eq!(inner, &root.join("ws/sub").join(CONFIG_FILE));
            assert_eq!(outer, &root.join("ws").join(CONFIG_FILE));
            assert_eq!(outer_unusable, &None);
            let msg = e.to_string();
            assert!(msg.contains("nested configurations"), "{msg}");
            assert!(
                msg.contains(&format!("`--workspace {}`", root.join("ws").display())),
                "{msg}"
            );
            assert!(
                msg.contains(&format!("`--workspace {}`", root.join("ws/sub").display())),
                "{msg}"
            );
        }
        // Not when the outer one is further up either.
        fs::create_dir_all(root.join("top/mid/ws")).unwrap();
        write_trusted(&root.join("top").join(CONFIG_FILE));
        fs::write(root.join("top/mid/ws").join(CONFIG_FILE), "").unwrap();
        let e = discover_workspace(&root.join("top/mid/ws"), None).unwrap_err();
        assert!(matches!(e, RunError::NestedConfig { .. }), "{e:?}");
        // The outer workspace itself is fine.
        assert_eq!(
            discover_workspace(&root.join("ws"), None).unwrap().dir,
            root.join("ws")
        );
        // `--workspace` names the directory: either one is used as asked.
        for dir in ["ws/sub", "ws"] {
            let ws = discover_workspace(&root, Some(Path::new(dir))).unwrap();
            assert_eq!(ws.dir, root.join(dir));
            assert_eq!(ws.config, Some(root.join(dir).join(CONFIG_FILE)));
        }
    }

    #[test]
    fn an_outer_config_the_user_owns_counts_whatever_the_modes() {
        // A sandbox of `ws` can `chmod 0777` the workspace root it owns, so
        // that the outer configuration fails the trust checks: it still
        // counts, but is not suggested.
        let (_d, root) = tmp();
        fs::create_dir_all(root.join("ws/sub")).unwrap();
        let outer = root.join("ws").join(CONFIG_FILE);
        write_trusted(&outer);
        fs::write(root.join("ws/sub").join(CONFIG_FILE), "").unwrap();
        let unusable = |dir_mode: u32, file_mode: u32| {
            fs::set_permissions(root.join("ws"), fs::Permissions::from_mode(dir_mode)).unwrap();
            fs::set_permissions(&outer, fs::Permissions::from_mode(file_mode)).unwrap();
            let e = discover_workspace(&root.join("ws/sub"), None).unwrap_err();
            let RunError::NestedConfig {
                outer: found,
                outer_unusable,
                ..
            } = &e
            else {
                panic!("{e:?}");
            };
            assert_eq!(found, &outer);
            let msg = e.to_string();
            assert!(
                !msg.contains(&format!("`--workspace {}`", root.join("ws").display())),
                "{msg}"
            );
            assert!(
                msg.contains(&format!("`--workspace {}`", root.join("ws/sub").display())),
                "{msg}"
            );
            assert!(msg.contains("fails the trust checks"), "{msg}");
            outer_unusable.clone().expect("the outer one is unusable")
        };
        let why = unusable(0o777, 0o644);
        assert!(why.contains("its directory is writable"), "{why}");
        let why = unusable(0o755, 0o666);
        assert!(why.contains("writable by its group or others"), "{why}");
        // A symlink the user owns counts too, whatever it leads to.
        fs::set_permissions(root.join("ws"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::remove_file(&outer).unwrap();
        symlink("/nonexistent", &outer).unwrap();
        let e = discover_workspace(&root.join("ws/sub"), None).unwrap_err();
        assert!(matches!(e, RunError::NestedConfig { .. }), "{e:?}");
    }

    #[test]
    fn a_config_above_owned_by_someone_else_does_not_count_as_outer() {
        // As `/tmp/.stopit.toml` above `/tmp/proj`: anyone could have
        // created it. Here every file belongs to the test's user, so it is
        // someone else's for any other uid.
        let (_d, root) = tmp();
        fs::create_dir_all(root.join("proj/sub")).unwrap();
        write_trusted(&root.join(CONFIG_FILE));
        fs::write(root.join("proj").join(CONFIG_FILE), "").unwrap();
        let me = rustix::process::getuid().as_raw();
        let ws = discover_workspace_as(&root.join("proj/sub"), None, me.wrapping_add(1)).unwrap();
        assert_eq!(ws.dir, root.join("proj"));
        assert_eq!(ws.config, Some(root.join("proj").join(CONFIG_FILE)));
        // For its owner, it counts.
        let e = discover_workspace_as(&root.join("proj/sub"), None, me).unwrap_err();
        assert!(matches!(e, RunError::NestedConfig { .. }), "{e:?}");
    }

    #[test]
    fn without_a_config_the_cwd_is_the_workspace() {
        let (_d, root) = tmp();
        // Nothing above a fresh temporary directory is expected to hold a
        // `.stopit.toml`; if one does, the test says so.
        let found = discover_workspace(&root, None).unwrap();
        assert_eq!(found.config, None, "a {CONFIG_FILE} above {root:?}?");
        assert_eq!(found.dir, root);
        assert_eq!(found.read_config().unwrap(), None);
    }

    #[test]
    fn the_workspace_is_canonical() {
        let (_d, root) = tmp();
        fs::create_dir_all(root.join("real/sub")).unwrap();
        fs::write(root.join("real").join(CONFIG_FILE), "").unwrap();
        symlink(root.join("real"), root.join("link")).unwrap();
        let ws = discover_workspace(&root.join("link/sub/.."), None).unwrap();
        assert_eq!(ws.dir, root.join("real"));
        assert_eq!(ws.config, Some(root.join("real").join(CONFIG_FILE)));
        let ws = discover_workspace(&root, Some(Path::new("link/./sub"))).unwrap();
        assert_eq!(ws.dir, root.join("real/sub"));
    }

    #[test]
    fn workspace_option_overrides_discovery_and_does_not_walk_up() {
        let (_d, root) = tmp();
        fs::create_dir_all(root.join("a/b")).unwrap();
        fs::create_dir_all(root.join("c")).unwrap();
        fs::write(root.join("a").join(CONFIG_FILE), "").unwrap();
        fs::write(root.join("c").join(CONFIG_FILE), "").unwrap();
        // Relative to the cwd, or absolute.
        let ws = discover_workspace(&root.join("a/b"), Some(Path::new("../../c"))).unwrap();
        assert_eq!(ws.dir, root.join("c"));
        assert_eq!(ws.config, Some(root.join("c").join(CONFIG_FILE)));
        // `a/b` has no configuration of its own; `a`'s is not used.
        let ws = discover_workspace(&root, Some(&root.join("a/b"))).unwrap();
        assert_eq!(ws.dir, root.join("a/b"));
        assert_eq!(ws.config, None);
    }

    #[test]
    fn a_bad_workspace_option_is_an_error() {
        let (_d, root) = tmp();
        fs::write(root.join("file"), "").unwrap();
        let e = discover_workspace(&root, Some(Path::new("missing"))).unwrap_err();
        assert!(matches!(e, RunError::Workspace { .. }), "{e}");
        let e = discover_workspace(&root, Some(Path::new("file"))).unwrap_err();
        assert!(matches!(e, RunError::WorkspaceNotDir(_)), "{e}");
    }

    /// The workspace's configuration, read and parsed (the default one
    /// without a file), as `supervise` loads it, but without the trust
    /// store.
    fn load(ws: &Workspace) -> Result<Config, RunError> {
        match ws.read_config()? {
            None => Ok(Config::default()),
            Some(file) => file.parse(),
        }
    }

    #[test]
    fn configs_load_or_fail_with_their_path() {
        let (_d, root) = tmp();
        let none = Workspace {
            dir: root.clone(),
            config: None,
        };
        assert_eq!(load(&none).unwrap(), Config::default());
        assert_eq!(Config::default().base, Base::Default);
        let path = root.join(CONFIG_FILE);
        let with = Workspace {
            dir: root.clone(),
            config: Some(path.clone()),
        };
        // An empty file is the default configuration too.
        write_config(&path, "", 0o644);
        assert_eq!(load(&with).unwrap(), Config::default());
        write_config(&path, "base = \"none\"", 0o644);
        let file = with.read_config().unwrap().unwrap();
        assert_eq!(file.path, path);
        assert_eq!(file.bytes, b"base = \"none\"");
        assert_eq!(file.parse().unwrap().base, Base::None);
        write_config(&path, "bogus = 1", 0o644);
        let e = load(&with).unwrap_err();
        assert!(matches!(e, RunError::Config { .. }), "{e}");
        assert!(e.to_string().contains(".stopit.toml"), "{e}");
        fs::write(&path, b"base = \"\xff\"").unwrap();
        let e = load(&with).unwrap_err();
        assert!(matches!(e, RunError::ReadConfig { .. }), "{e}");
        assert!(e.to_string().contains("utf-8"), "{e}");
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        let e = load(&with).unwrap_err();
        assert!(matches!(e, RunError::UntrustedConfig { .. }), "{e}");
        assert!(e.to_string().contains("not a regular file"), "{e}");
    }

    #[test]
    fn only_an_allowed_config_with_its_exact_content_is_used() {
        let path = PathBuf::from("/ws/.stopit.toml");
        let file = |bytes: &[u8]| ConfigFile {
            path: path.clone(),
            bytes: bytes.to_vec(),
        };
        let mut allowed = Allowed::default();
        // Unknown.
        let e = check_allowed(&allowed, &file(b"x"), None).unwrap_err();
        assert!(
            matches!(&e, RunError::NotAllowed { changed: false, .. }),
            "{e:?}"
        );
        assert_eq!(
            e.to_string(),
            "refusing to use \"/ws/.stopit.toml\": it is new: it has not been allowed, or was \
             revoked. stopit only uses a configuration you allowed, as it was when you allowed \
             it, since it decides what the sandbox may do and which scripts run on the host; \
             review it, then run `stopit allow`"
        );
        // Allowed.
        allowed.allow(path.clone(), b"x");
        check_allowed(&allowed, &file(b"x"), None).unwrap();
        // Changed, by a single byte; the hint names `--workspace` if given.
        let e = check_allowed(&allowed, &file(b"x "), Some(Path::new("/ws"))).unwrap_err();
        assert!(
            matches!(&e, RunError::NotAllowed { changed: true, .. }),
            "{e:?}"
        );
        let msg = e.to_string();
        assert!(
            msg.starts_with(
                "refusing to use \"/ws/.stopit.toml\": it changed since it was last allowed."
            ),
            "{msg}"
        );
        assert!(
            msg.ends_with("review it, then run `stopit allow --workspace /ws`"),
            "{msg}"
        );
        // The same content at another path is not allowed.
        let other = ConfigFile {
            path: "/other/.stopit.toml".into(),
            bytes: b"x".to_vec(),
        };
        assert!(check_allowed(&allowed, &other, None).is_err());
        // Revoked.
        allowed.revoke(&path);
        let e = check_allowed(&allowed, &file(b"x"), None).unwrap_err();
        assert!(
            matches!(&e, RunError::NotAllowed { changed: false, .. }),
            "{e:?}"
        );
    }

    #[test]
    fn suggested_commands_quote_their_paths_for_the_shell() {
        let path = PathBuf::from("/my ws/.stopit.toml");
        let file = ConfigFile {
            path: path.clone(),
            bytes: b"x".to_vec(),
        };
        let msg = check_allowed(&Allowed::default(), &file, Some(Path::new("/my ws")))
            .unwrap_err()
            .to_string();
        assert!(
            msg.ends_with("review it, then run `stopit allow --workspace '/my ws'`"),
            "{msg}"
        );
        let msg = check_allowed(&Allowed::default(), &file, Some(Path::new("/a\x1bb")))
            .unwrap_err()
            .to_string();
        assert!(
            msg.ends_with("run `stopit allow --workspace $'/a\\x1bb'`"),
            "{msg}"
        );
        let msg = RunError::MissingConfig { path, via: None }.to_string();
        assert!(
            msg.contains("run `stopit revoke '/my ws/.stopit.toml'`"),
            "{msg}"
        );
        let msg = nested_config_message(
            Path::new("/o'k/in/.stopit.toml"),
            Path::new("/o'k/.stopit.toml"),
            None,
        );
        assert!(msg.contains("`--workspace '/o'\\''k'`"), "{msg}");
        assert!(msg.contains("`--workspace '/o'\\''k/in'`"), "{msg}");
    }

    #[test]
    fn a_missing_allowed_config_is_not_replaced_by_the_defaults() {
        let mut allowed = Allowed::default();
        allowed.allow("/a/.stopit.toml".into(), b"x");
        // Nothing allowed where it looked.
        check_missing(&allowed, Path::new("/b/c"), false, &[]).unwrap();
        check_missing(&Allowed::default(), Path::new("/a"), false, &[]).unwrap();
        // In the workspace, or in a directory above it when walking up.
        for (dir, explicit) in [("/a", false), ("/a/b/c", false), ("/a", true)] {
            let e = check_missing(&allowed, Path::new(dir), explicit, &[]).unwrap_err();
            let RunError::MissingConfig { path, via: None } = &e else {
                panic!("{dir}: {e:?}");
            };
            assert_eq!(path, Path::new("/a/.stopit.toml"), "{dir}");
        }
        // `--workspace` does not look up.
        check_missing(&allowed, Path::new("/a/b"), true, &[]).unwrap();
        // The nearest one is named.
        allowed.allow("/a/b/.stopit.toml".into(), b"y");
        let e = check_missing(&allowed, Path::new("/a/b/c"), false, &[]).unwrap_err();
        assert!(
            matches!(&e, RunError::MissingConfig { path, .. } if path == Path::new("/a/b/.stopit.toml")),
            "{e:?}"
        );
        assert_eq!(
            e.to_string(),
            "refusing to run the default configuration: \"/a/b/.stopit.toml\" was allowed but is \
             missing, and the defaults may grant what it did not; restore it, or run `stopit \
             revoke /a/b/.stopit.toml` to use the defaults there"
        );
    }

    #[test]
    fn an_allowed_config_past_a_link_on_the_way_is_missing_too() {
        // `/p/sub` was a directory when its configuration was allowed; a
        // sandbox with `rw /p` moved it away and put a link to `/x` in its
        // place, so discovery (which resolves links) finds no configuration.
        let mut allowed = Allowed::default();
        allowed.allow("/p/sub/.stopit.toml".into(), b"x");
        allowed.allow("/q/.stopit.toml".into(), b"x");
        let links = [PathBuf::from("/p/sub")];
        for (dir, explicit) in [("/x", false), ("/x", true), ("/x/deeper", false)] {
            let e = check_missing(&allowed, Path::new(dir), explicit, &links).unwrap_err();
            let RunError::MissingConfig { path, via } = &e else {
                panic!("{e:?}");
            };
            assert_eq!(
                (path.as_path(), via.as_deref()),
                (Path::new("/p/sub/.stopit.toml"), Some(Path::new("/p/sub")))
            );
            assert_eq!(
                e.to_string(),
                "refusing to run the default configuration: \"/p/sub/.stopit.toml\" was \
                 allowed, but \"/p/sub\", on the way to it, is now a symbolic link, so it is not \
                 where it was allowed, and the defaults may grant what it did not; restore it, or \
                 run `stopit revoke /p/sub/.stopit.toml` to use the defaults there"
            );
        }
        // Deeper below the link too.
        let links = [PathBuf::from("/p")];
        assert!(check_missing(&allowed, Path::new("/x"), false, &links).is_err());
        // Not for a link elsewhere, nor one that only shares a prefix.
        for link in ["/r", "/p/su", "/p/sub/.stopit.toml/x"] {
            check_missing(&allowed, Path::new("/x"), false, &[PathBuf::from(link)]).unwrap();
        }
    }

    #[test]
    fn discovery_links_are_those_on_the_way_the_user_named() {
        let (_d, root) = tmp();
        fs::create_dir_all(root.join("x/deeper")).unwrap();
        symlink(root.join("x"), root.join("sub")).unwrap();
        let cwd = root.join("x/deeper");
        // `PWD` through the link, which is the current directory.
        let pwd = Some(root.join("sub/deeper").into_os_string());
        assert_eq!(discovery_links(&cwd, None, pwd), [root.join("sub")]);
        // Not if it is another directory, relative, missing or unset.
        for pwd in [
            Some(root.join("sub").into_os_string()),
            Some("sub/deeper".into()),
            Some(root.join("gone").into_os_string()),
            None,
        ] {
            assert_eq!(
                discovery_links(&cwd, None, pwd.clone()),
                [] as [PathBuf; 0],
                "{pwd:?}"
            );
        }
        // `--workspace`, against the current directory, whatever `PWD`.
        assert_eq!(
            discovery_links(&root, Some(Path::new("sub/deeper")), None),
            [root.join("sub")]
        );
        assert_eq!(
            discovery_links(&cwd, Some(&root.join("sub")), Some("junk".into())),
            [root.join("sub")]
        );
        assert!(discovery_links(&root, Some(Path::new("x")), None).is_empty());
    }

    #[test]
    fn revoking_a_path_tries_it_as_written_then_resolved() {
        let (_d, root) = tmp();
        fs::create_dir(root.join("real")).unwrap();
        symlink(root.join("real"), root.join("link")).unwrap();
        // Through a link: as written (a stale entry, from before the link
        // was there), then resolved as `allow` would record it.
        let given = root.join("link/./.stopit.toml");
        assert_eq!(
            config_keys(&given),
            [given.clone(), root.join("real/.stopit.toml")]
        );
        // Canonical already: once.
        let canonical = root.join("real/.stopit.toml");
        assert_eq!(config_keys(&canonical), std::slice::from_ref(&canonical));
        // A directory that is gone resolves as far as it exists.
        let gone = root.join("link/gone/.stopit.toml");
        assert_eq!(
            config_keys(&gone),
            [gone.clone(), root.join("real/gone/.stopit.toml")]
        );
        // The file itself is not followed, being never a link in the store.
        symlink(root.join("elsewhere"), &canonical).unwrap();
        assert_eq!(config_keys(&canonical), std::slice::from_ref(&canonical));
    }

    #[test]
    fn allow_prints_the_whole_hash_and_the_size() {
        let hash = crate::trust::sha256_hex(b"abc");
        assert_eq!(
            allowed_line(Path::new("/ws/.stopit.toml"), 3, &hash),
            format!("allowed \"/ws/.stopit.toml\" (3 bytes, sha256 {hash})")
        );
        assert!(allowed_line(Path::new("/x"), 1, &hash).contains("(1 byte, "));
        assert_eq!(
            allowed_entry_line(Path::new("/ws/.stopit.toml"), &hash, false),
            format!("{} \"/ws/.stopit.toml\"", &hash[..12])
        );
        assert_eq!(
            allowed_entry_line(Path::new("/ws/.stopit.toml"), &hash, true),
            format!("{} \"/ws/.stopit.toml\" (missing)", &hash[..12])
        );
        let (_d, root) = tmp();
        assert!(is_gone(&root.join("nothing")));
        assert!(!is_gone(&root));
        // A dangling link is there.
        symlink(root.join("nothing"), root.join("dangling")).unwrap();
        assert!(!is_gone(&root.join("dangling")));
    }

    #[test]
    fn a_link_on_the_way_to_a_config_is_refused() {
        // Discovery resolves the workspace, so its path has no link; one
        // there was swapped in since, and the file read would not be the
        // one the trust store's key names.
        let (_d, root) = tmp();
        let ws = workspace_with_modes(&root, 0o755, 0o644);
        symlink(&ws.dir, root.join("link")).unwrap();
        for dir in [root.join("link"), root.join("link/../link")] {
            let swapped = Workspace {
                dir: dir.clone(),
                config: Some(dir.join(CONFIG_FILE)),
            };
            let e = swapped.read_config().unwrap_err();
            assert!(matches!(e, RunError::UntrustedConfig { .. }), "{e}");
            assert!(
                e.to_string().contains("runs through a symbolic link"),
                "{e}"
            );
        }
        // A link further up too.
        fs::create_dir(root.join("up")).unwrap();
        fs::rename(&ws.dir, root.join("up/ws")).unwrap();
        fs::remove_file(root.join("link")).unwrap();
        symlink(root.join("up"), root.join("link")).unwrap();
        let swapped = Workspace {
            dir: root.join("link/ws"),
            config: Some(root.join("link/ws").join(CONFIG_FILE)),
        };
        let e = swapped.read_config().unwrap_err();
        assert!(matches!(e, RunError::UntrustedConfig { .. }), "{e}");
        // Through the real path, it reads.
        let real = root.join("up/ws").join(CONFIG_FILE);
        assert_eq!(read_trusted(&real).unwrap(), b"base = \"none\"");
    }

    #[test]
    fn nothing_to_allow_names_where_it_looked() {
        let e = RunError::NothingToAllow {
            dir: "/a/b".into(),
            explicit: false,
        };
        assert_eq!(
            e.to_string(),
            "no .stopit.toml in /a/b or any directory above it: there is nothing to allow"
        );
        let e = RunError::NothingToAllow {
            dir: "/a/b".into(),
            explicit: true,
        };
        assert_eq!(
            e.to_string(),
            "no .stopit.toml in the workspace /a/b: there is nothing to allow"
        );
    }

    /// Writes `contents` to the configuration file `path`, with `mode`
    /// whatever the umask.
    fn write_config(path: &Path, contents: &str, mode: u32) {
        fs::write(path, contents).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    /// A workspace `root/ws` with mode `dir_mode` and a valid configuration
    /// file, with mode `file_mode`.
    fn workspace_with_modes(root: &Path, dir_mode: u32, file_mode: u32) -> Workspace {
        let dir = root.join("ws");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(CONFIG_FILE);
        write_config(&path, "base = \"none\"", file_mode);
        fs::set_permissions(&dir, fs::Permissions::from_mode(dir_mode)).unwrap();
        Workspace {
            dir,
            config: Some(path),
        }
    }

    #[test]
    fn a_private_config_in_a_private_or_sticky_directory_loads() {
        for (dir_mode, file_mode) in [
            (0o700, 0o600),
            (0o755, 0o644),
            (0o555, 0o444),
            // Sticky, as `/tmp`: no one else can replace the file.
            (0o1777, 0o644),
            (0o1770, 0o600),
        ] {
            let (_d, root) = tmp();
            let ws = workspace_with_modes(&root, dir_mode, file_mode);
            let loaded = load(&ws);
            assert!(loaded.is_ok(), "{dir_mode:o} {file_mode:o}: {loaded:?}");
            // Restore, so that the temporary directory can be removed.
            fs::set_permissions(&ws.dir, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    #[test]
    fn a_config_others_can_write_is_refused() {
        for file_mode in [0o664, 0o646, 0o666, 0o620] {
            let (_d, root) = tmp();
            let ws = workspace_with_modes(&root, 0o755, file_mode);
            let e = load(&ws).unwrap_err();
            assert!(matches!(e, RunError::UntrustedConfig { .. }), "{e}");
            let message = e.to_string();
            assert!(message.contains(".stopit.toml"), "{message}");
            assert!(
                message.contains("writable by its group or others"),
                "{message}"
            );
        }
    }

    #[test]
    fn a_config_in_a_directory_others_can_write_is_refused() {
        for dir_mode in [0o775, 0o757, 0o777] {
            let (_d, root) = tmp();
            let ws = workspace_with_modes(&root, dir_mode, 0o644);
            let e = load(&ws).unwrap_err();
            assert!(matches!(e, RunError::UntrustedConfig { .. }), "{e}");
            assert!(e.to_string().contains("not sticky"), "{e}");
            // Restore, so that the temporary directory can be removed.
            fs::set_permissions(&ws.dir, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    #[test]
    fn a_config_symlink_is_refused() {
        // Even to a private file of the user's: what it leads to could be
        // swapped, and is not where the workspace says.
        let (_d, root) = tmp();
        let ws = workspace_with_modes(&root, 0o755, 0o644);
        let real = root.join("real.toml");
        write_config(&real, "base = \"none\"", 0o644);
        let path = ws.config.clone().unwrap();
        fs::remove_file(&path).unwrap();
        symlink(&real, &path).unwrap();
        let e = load(&ws).unwrap_err();
        assert!(matches!(e, RunError::UntrustedConfig { .. }), "{e}");
        assert!(e.to_string().contains("symbolic link"), "{e}");
    }

    #[test]
    fn config_trust_checks_owners_and_modes() {
        const ME: u32 = 1000;
        let file = |uid, mode| Ownership {
            uid,
            mode: libc::S_IFREG | mode,
        };
        let dir = |uid, mode| Ownership {
            uid,
            mode: libc::S_IFDIR | mode,
        };
        let check = |f, d| check_config_trust(f, d, ME);
        assert_eq!(check(file(ME, 0o644), dir(ME, 0o755)), Ok(()));
        // A directory of root's, or a sticky one of anyone allowed to own it.
        assert_eq!(check(file(ME, 0o600), dir(0, 0o755)), Ok(()));
        assert_eq!(check(file(ME, 0o600), dir(0, 0o1777)), Ok(()));
        assert_eq!(check(file(ME, 0o600), dir(ME, 0o1777)), Ok(()));

        // Another user's file, even in the user's own directory.
        let e = check(file(1001, 0o644), dir(ME, 0o755)).unwrap_err();
        assert!(
            e.contains("owned by uid 1001, not by you (uid 1000)"),
            "{e}"
        );
        // Root's too: it is not the user's choice.
        assert!(check(file(0, 0o644), dir(0, 0o755)).is_err());
        // Writable by others.
        let e = check(file(ME, 0o664), dir(ME, 0o755)).unwrap_err();
        assert!(e.contains("mode 0664"), "{e}");
        assert!(check(file(ME, 0o602), dir(ME, 0o755)).is_err());
        // Not a regular file.
        let e = check(dir(ME, 0o755), dir(ME, 0o755)).unwrap_err();
        assert!(e.contains("not a regular file"), "{e}");
        let fifo = Ownership {
            uid: ME,
            mode: libc::S_IFIFO | 0o644,
        };
        assert!(check(fifo, dir(ME, 0o755)).is_err());

        // The directory: another user's (even sticky, as they may change
        // its mode), or writable by others without the sticky bit.
        let e = check(file(ME, 0o644), dir(1001, 0o755)).unwrap_err();
        assert!(e.contains("directory is owned by uid 1001"), "{e}");
        assert!(check(file(ME, 0o644), dir(1001, 0o1777)).is_err());
        let e = check(file(ME, 0o644), dir(ME, 0o775)).unwrap_err();
        assert!(e.contains("mode 0775"), "{e}");
        assert!(check(file(ME, 0o644), dir(0, 0o777)).is_err());
    }

    // --- Commands, home and exit status ---

    #[test]
    fn shell_runs_shell_or_fails_clearly() {
        assert_eq!(
            shell_command(Some("/bin/zsh".into())).unwrap(),
            [OsString::from("/bin/zsh")]
        );
        for unset in [None, Some(OsString::new())] {
            let e = shell_command(unset).unwrap_err();
            assert!(matches!(e, RunError::ShellUnset), "{e}");
            assert!(e.to_string().contains("SHELL is not set"), "{e}");
        }
    }

    #[test]
    fn home_must_be_set_and_resolvable() {
        let (_d, root) = tmp();
        symlink(&root, root.join("link")).unwrap();
        assert_eq!(host_home(Some(root.join("link").into())).unwrap(), root);
        for unset in [None, Some(OsString::new())] {
            assert!(matches!(host_home(unset), Err(RunError::HomeUnset)));
        }
        let e = host_home(Some(root.join("missing").into())).unwrap_err();
        assert!(matches!(e, RunError::Home { .. }), "{e}");
    }

    #[test]
    fn exit_codes_pass_through_and_signals_map_to_128_plus_n() {
        // Raw wait statuses: an exit code in the second byte, a signal in
        // the low 7 bits.
        for code in [0, 1, 2, 125, 126, 127, 255] {
            assert_eq!(exit_code(ExitStatus::from_raw(code << 8)), code as u8);
        }
        assert_eq!(exit_code(ExitStatus::from_raw(libc::SIGINT)), 130);
        assert_eq!(exit_code(ExitStatus::from_raw(libc::SIGKILL)), 137);
        assert_eq!(exit_code(ExitStatus::from_raw(libc::SIGTERM)), 143);
        // With a core dump (bit 7).
        assert_eq!(exit_code(ExitStatus::from_raw(libc::SIGSEGV | 0x80)), 139);
    }

    #[test]
    fn a_new_session_whenever_a_terminal_is_reachable() {
        assert!(!needs_new_session([false; 3], false));
        for i in 0..3 {
            let mut stdio = [false; 3];
            stdio[i] = true;
            assert!(needs_new_session(stdio, false), "{i}");
        }
        // All stdio redirected, but `/dev/tty` still reaches the terminal.
        assert!(needs_new_session([false; 3], true));
    }

    #[test]
    fn only_the_foreground_of_the_controlling_terminal_may_start() {
        let pid = |n| Pid::from_raw(n).unwrap();
        assert!(foreground(Ok(pid(42)), pid(42)).is_ok());
        let e = foreground(Ok(pid(7)), pid(42)).unwrap_err();
        assert!(matches!(e, RunError::Background), "{e}");
        assert!(e.to_string().contains("in the background"), "{e}");
        // A terminal that is not the controlling one has no foreground.
        assert!(foreground(Err(Errno::NOTTY), pid(42)).is_ok());
        let e = foreground(Err(Errno::IO), pid(42)).unwrap_err();
        assert!(matches!(e, RunError::Foreground(_)), "{e}");
    }

    // --- Warnings ---

    fn missing(provider: &str, pattern: &str) -> SpecWarning {
        SpecWarning::Mount(PlanWarning {
            provider: provider.parse().unwrap(),
            pattern: pattern.into(),
            kind: PlanWarningKind::Resolve(ResolveWarning::Missing {
                path: PathBuf::from(pattern),
            }),
        })
    }

    fn unreadable(provider: &str, pattern: &str) -> SpecWarning {
        SpecWarning::Mount(PlanWarning {
            provider: provider.parse().unwrap(),
            pattern: pattern.into(),
            kind: PlanWarningKind::Resolve(ResolveWarning::Io {
                path: PathBuf::from(pattern),
                error: io::Error::from_raw_os_error(libc::EACCES),
            }),
        })
    }

    #[test]
    fn missing_paths_of_the_default_base_are_quiet() {
        assert!(is_quiet(&missing("base", "/w/.envrc"), Base::Default));
        // Not under `base = "none"`, where `base` is a user's provider.
        assert!(!is_quiet(&missing("base", "/w/.envrc"), Base::None));
        // Not another provider's.
        assert!(!is_quiet(&missing("config", "/w/.envrc"), Base::Default));
        // Not another problem with a base rule.
        assert!(!is_quiet(&unreadable("base", "/w/.envrc"), Base::Default));
        let domains = SpecWarning::DomainsIgnored {
            mode: NetworkMode::Loopback,
            domains: ["example.com".parse().unwrap()].into_iter().collect(),
        };
        assert!(!is_quiet(&domains, Base::Default));
    }

    #[test]
    fn warnings_are_printed_once_each_in_order_without_quiet_ones() {
        let warnings = [
            missing("config", "/b"),
            missing("base", "/w/.envrc"),
            missing("config", "/a"),
            // The same rule, warned about again in an inheriting profile.
            missing("config", "/b"),
            unreadable("base", "/w/x"),
            missing("config", "/a"),
        ];
        let lines = distinct_messages(&warnings, Base::Default);
        assert_eq!(
            lines,
            [
                warnings[0].to_string(),
                warnings[2].to_string(),
                warnings[4].to_string()
            ]
        );
        assert!(lines[0].contains("\"/b\" does not exist"), "{lines:?}");
        // Under `base = "none"` nothing is quiet.
        assert_eq!(distinct_messages(&warnings, Base::None).len(), 4);
    }

    #[test]
    fn bwrap_exit_code_distinguishes_setup_failures_from_target_exits() {
        let exited = |code: i32| ExitStatus::from_raw(code << 8);
        assert_eq!(bwrap_exit_code(exited(0), ""), 0);
        // Pre-clone setup failure emits nothing and maps to 125.
        assert_eq!(bwrap_exit_code(exited(1), ""), EXIT_SUPERVISOR_FAILED);
        // Post-clone setup failure emits only child-pid without exit-code and maps to 125.
        assert_eq!(
            bwrap_exit_code(exited(1), "{ \"child-pid\": 42 }\n"),
            EXIT_SUPERVISOR_FAILED
        );
        // Normal target exit emits both child-pid and exit-code and preserves the exit status.
        assert_eq!(
            bwrap_exit_code(exited(1), "{ \"child-pid\": 42 }\n{ \"exit-code\": 1 }\n"),
            1
        );
        assert_eq!(
            bwrap_exit_code(
                exited(42),
                "{ \"child-pid\": 42, \"mnt-namespace\": 1 }\n{ \"exit-code\": 42 }\n"
            ),
            42
        );
        // Signal termination preserves 128 + signal.
        assert_eq!(
            bwrap_exit_code(ExitStatus::from_raw(libc::SIGTERM), ""),
            143
        );
    }

    #[test]
    fn record_signal_preserves_errno_when_pipe_is_full() {
        init_signal_pipe().unwrap();
        let wfd = SIGNAL_WRITE_FD.load(Ordering::Acquire);
        let fill = [1u8; 4096];
        // Fill the non-blocking pipe until `write` sets `EAGAIN`.
        // SAFETY: `wfd` is a valid non-blocking pipe descriptor.
        while unsafe { libc::write(wfd, fill.as_ptr().cast(), fill.len()) } > 0 {}

        // Store 0 so concurrent `script` tests never observe a fake signal.
        // SAFETY: thread-local `errno` slot is valid for this thread.
        unsafe {
            *libc::__errno_location() = libc::ENOENT;
        }
        record_signal(0);
        // SAFETY: reads this thread's `errno` slot.
        let after = unsafe { *libc::__errno_location() };
        drain_signal_pipe();
        assert_eq!(after, libc::ENOENT);
    }

    // --- The user-global configuration ---

    fn chmod(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    /// A trusted configuration directory `cfg` (`0755`) below `root`.
    fn global_dir(root: &Path) -> ConfigDirs {
        let dir = root.join("cfg");
        fs::create_dir_all(&dir).unwrap();
        chmod(&dir, 0o755);
        ConfigDirs::canonical(dir)
    }

    fn read_global(dirs: &ConfigDirs) -> Result<Option<GlobalConfigFile>, RunError> {
        read_global_config_as(dirs, rustix::process::getuid().as_raw())
    }

    #[track_caller]
    fn untrusted_reason(dirs: &ConfigDirs) -> String {
        match read_global(dirs) {
            Err(RunError::UntrustedConfig { path, reason }) => {
                assert_eq!(path, dirs.active.path.join(GLOBAL_CONFIG_FILE));
                reason
            }
            other => panic!("expected an untrusted configuration, got {other:?}"),
        }
    }

    #[test]
    fn a_missing_global_configuration_is_absent() {
        let (_d, root) = tmp();
        // Neither the directory nor the file.
        let dirs = ConfigDirs::canonical(root.join("nope/stopit"));
        assert_eq!(read_global(&dirs).unwrap(), None);
        // The directory without the file.
        let dirs = global_dir(&root);
        assert_eq!(read_global(&dirs).unwrap(), None);
    }

    #[test]
    fn an_owned_global_configuration_is_read() {
        let (_d, root) = tmp();
        let dirs = global_dir(&root);
        let path = dirs.active.path.join(GLOBAL_CONFIG_FILE);
        fs::write(&path, "base = \"none\"\n").unwrap();
        for mode in [0o644, 0o600, 0o400] {
            chmod(&path, mode);
            let file = read_global(&dirs).unwrap().unwrap();
            assert_eq!(
                file,
                GlobalConfigFile {
                    path: path.clone(),
                    canonical_path: path.clone(),
                    bytes: b"base = \"none\"\n".to_vec(),
                }
            );
            assert!(file.parse_layer().unwrap().sets_base_none());
        }
        // A sticky world-writable directory is fine, as for `/nix/store`.
        chmod(&dirs.active.path, 0o1777);
        assert!(read_global(&dirs).unwrap().is_some());
    }

    #[test]
    fn a_writable_or_odd_global_configuration_is_refused() {
        let (_d, root) = tmp();
        let dirs = global_dir(&root);
        let path = dirs.active.path.join(GLOBAL_CONFIG_FILE);
        fs::write(&path, "").unwrap();
        for mode in [0o664, 0o646, 0o666] {
            chmod(&path, mode);
            let reason = untrusted_reason(&dirs);
            assert_eq!(
                reason,
                format!(
                    "it has mode {mode:04o} and is writable by its group or others; run `chmod \
                     go-w` on it"
                )
            );
        }
        chmod(&path, 0o644);
        // A group-writable directory lets others swap the file.
        chmod(&dirs.active.path, 0o775);
        assert_eq!(
            untrusted_reason(&dirs),
            format!(
                "the directory {:?} holding it has mode 0775, writable by its group or others \
                 and not sticky, so others could replace what it holds",
                dirs.active.path
            )
        );
        chmod(&dirs.active.path, 0o755);
        // Not a regular file.
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert_eq!(untrusted_reason(&dirs), "it is not a regular file");
        fs::remove_dir(&path).unwrap();
        // Bytes that are not UTF-8 or not TOML fail when parsed.
        fs::write(&path, b"\xff").unwrap();
        let file = read_global(&dirs).unwrap().unwrap();
        assert!(matches!(
            file.parse_layer(),
            Err(RunError::ReadConfig { .. })
        ));
        fs::write(&path, "base = 1").unwrap();
        let file = read_global(&dirs).unwrap().unwrap();
        assert!(matches!(file.parse_layer(), Err(RunError::Config { .. })));
    }

    #[test]
    fn a_symlinked_global_configuration_is_read_through_its_target() {
        let (_d, root) = tmp();
        let dirs = global_dir(&root);
        let link = dirs.active.path.join(GLOBAL_CONFIG_FILE);
        // A Home Manager style store: a sticky shared directory holding a
        // read-only file.
        let store = root.join("store");
        fs::create_dir(&store).unwrap();
        chmod(&store, 0o1775);
        let target = store.join("abc-config.toml");
        fs::write(&target, "[limits]\npids = 7\n").unwrap();
        chmod(&target, 0o444);
        symlink(&target, &link).unwrap();
        let file = read_global(&dirs).unwrap().unwrap();
        assert_eq!(file.path, link);
        assert_eq!(file.canonical_path, target);
        assert_eq!(
            file.parse_layer().unwrap().limits.pids,
            std::num::NonZeroU32::new(7)
        );
        // A relative link into a dotfiles directory.
        let dotfiles = root.join("dotfiles");
        fs::create_dir(&dotfiles).unwrap();
        chmod(&dotfiles, 0o755);
        fs::write(dotfiles.join("stopit.toml"), "").unwrap();
        chmod(&dotfiles.join("stopit.toml"), 0o644);
        fs::remove_file(&link).unwrap();
        symlink("../dotfiles/stopit.toml", &link).unwrap();
        let file = read_global(&dirs).unwrap().unwrap();
        assert_eq!(file.canonical_path, dotfiles.join("stopit.toml"));
    }

    #[test]
    fn a_symlinked_global_configuration_with_a_bad_target_is_refused() {
        let (_d, root) = tmp();
        let dirs = global_dir(&root);
        let link = dirs.active.path.join(GLOBAL_CONFIG_FILE);
        let other = root.join("other");
        fs::create_dir(&other).unwrap();
        chmod(&other, 0o755);
        let target = other.join("config.toml");
        symlink(&target, &link).unwrap();
        // Dangling: refused rather than treated as absent.
        assert_eq!(untrusted_reason(&dirs), "it is a dangling symbolic link");
        // A writable target.
        fs::write(&target, "").unwrap();
        chmod(&target, 0o666);
        assert!(
            untrusted_reason(&dirs).starts_with("its target failed trust checks, it has mode 0666"),
        );
        // A target in a directory others can write without the sticky bit.
        chmod(&target, 0o644);
        chmod(&other, 0o777);
        let reason = untrusted_reason(&dirs);
        assert!(
            reason.starts_with(&format!("the directory {other:?} holding its target")),
            "{reason}"
        );
        assert!(reason.contains("not sticky"), "{reason}");
        chmod(&other, 0o755);
        // A link to a directory.
        fs::remove_file(&link).unwrap();
        symlink(&other, &link).unwrap();
        assert_eq!(
            untrusted_reason(&dirs),
            "its target failed trust checks, it is not a regular file"
        );
        // A link whose target directory path runs through another link.
        fs::remove_file(&link).unwrap();
        symlink(&other, root.join("other-link")).unwrap();
        symlink(root.join("other-link/config.toml"), &link).unwrap();
        // Read here: only the session knows which links a sandbox can write,
        // and `guard_global_config` checks them.
        assert!(read_global(&dirs).unwrap().is_some());
    }

    #[test]
    fn a_hard_linked_or_misplaced_global_configuration_is_refused() {
        let (_d, root) = tmp();
        let dirs = global_dir(&root);
        let path = dirs.active.path.join(GLOBAL_CONFIG_FILE);
        fs::write(&path, "").unwrap();
        chmod(&path, 0o644);
        fs::hard_link(&path, root.join("other-name.toml")).unwrap();
        assert_eq!(
            untrusted_reason(&dirs),
            format!(
                "{path:?} has 2 hard links, and a sandbox could rewrite it through another one; \
                 give it a single name"
            )
        );
        // The target of a link too.
        fs::remove_file(&path).unwrap();
        symlink(root.join("other-name.toml"), &path).unwrap();
        fs::hard_link(root.join("other-name.toml"), root.join("third.toml")).unwrap();
        assert!(untrusted_reason(&dirs).contains("has 2 hard links"));
        // A configuration directory that is a file.
        let file_dir = ConfigDirs::canonical(root.join("third.toml"));
        assert_eq!(
            untrusted_reason(&file_dir),
            format!(
                "{:?} or a path on the way to it is not a directory",
                root.join("third.toml")
            )
        );
    }

    /// A [`GlobalConfigFile`] read from `dirs`, which must succeed.
    fn read_ok(dirs: &ConfigDirs) -> GlobalConfigFile {
        read_global(dirs).unwrap().unwrap()
    }

    #[test]
    fn links_on_the_way_to_the_configuration_directory_are_checked() {
        let (_d, root) = tmp();
        // `<root>/links/cfg -> <root>/real`, with the configuration inside.
        let real = global_dir(&root.join("real-parent")).active.path;
        fs::write(real.join(GLOBAL_CONFIG_FILE), "").unwrap();
        chmod(&real.join(GLOBAL_CONFIG_FILE), 0o644);
        let links = root.join("links");
        fs::create_dir(&links).unwrap();
        chmod(&links, 0o755);
        symlink(&real, links.join("cfg")).unwrap();
        let dirs = crate::state::config_dirs(&root, Some(links.join("cfg").as_os_str())).unwrap();
        assert_eq!(dirs.active.path, real);
        assert_eq!(dirs.active.links, [links.join("cfg")]);
        assert!(read_global(&dirs).unwrap().is_some());
        // Others could replace the link.
        chmod(&links, 0o777);
        assert_eq!(
            untrusted_reason(&dirs),
            format!(
                "the directory {links:?} holding the link {:?} on the way to it has mode 0777, \
                 writable by its group or others and not sticky, so others could replace what \
                 it holds",
                links.join("cfg")
            )
        );
    }

    fn rw_root(path: &Path) -> UntrustedRoot {
        UntrustedRoot {
            path: path.to_owned(),
            kind: crate::spec::UntrustedKind::RwGrant {
                provider: "dots".parse().unwrap(),
                profile: None,
                host: path.to_owned(),
            },
        }
    }

    #[test]
    fn the_global_configuration_is_guarded_at_its_target_and_its_scripts() {
        let (_d, root) = tmp();
        let ws = root.join("ws");
        fs::create_dir(&ws).unwrap();
        let dirs = global_dir(&root);
        let dots = root.join("dots");
        fs::create_dir_all(dots.join("v1")).unwrap();
        chmod(&dots.join("v1"), 0o755);
        let target = dots.join("v1/stopit.toml");
        fs::write(&target, "").unwrap();
        chmod(&target, 0o644);
        // `config.toml -> dots/current/stopit.toml`, `current -> v1`.
        symlink("v1", dots.join("current")).unwrap();
        let link = dirs.active.path.join(GLOBAL_CONFIG_FILE);
        symlink(dots.join("current/stopit.toml"), &link).unwrap();
        let script = dots.join("v1/tools.sh");
        fs::write(&script, "#!/bin/sh\n").unwrap();
        let entries = ConfigLayer::from_toml_str(&format!(
            "[[provider]]\ntype = \"script\"\nname = \"a\"\nsource = {:?}\n\
             [[provider]]\ntype = \"script\"\nname = \"off\"\nsource = \"/nonexistent\"\n\
             protect = false\n",
            dots.join("current/tools.sh")
        ))
        .unwrap()
        .providers;
        let file = read_ok(&dirs);
        assert_eq!(file.canonical_path, target);
        // Nothing writable on the way: the target and the script, used or
        // not, are protected. A script with `protect = false` is not even
        // resolved.
        assert_eq!(
            guard_global_config(&file, &entries, &dirs.active.path, &ws, &[]).unwrap(),
            [target.clone(), script.clone()]
        );
        // With `dots` writable, the `current` link could be re-pointed.
        let e = guard_global_config(&file, &entries, &dirs.active.path, &ws, &[rw_root(&dots)])
            .unwrap_err();
        let RunError::UntrustedConfig { path, reason } = e else {
            panic!("{e:?}");
        };
        assert_eq!(path, link);
        assert!(
            reason.starts_with(&format!(
                "the way to the configuration {link:?} runs through the symbolic link {:?} \
                 inside {:?}",
                dots.join("current"),
                dots
            )),
            "{reason}"
        );
        // Without the link in the configuration's way, the script's way is
        // still checked.
        fs::remove_file(&link).unwrap();
        symlink(&target, &link).unwrap();
        let file = read_ok(&dirs);
        let e = guard_global_config(&file, &entries, &dirs.active.path, &ws, &[rw_root(&dots)])
            .unwrap_err();
        assert!(
            e.to_string().contains("the way to script provider \"a\""),
            "{e}"
        );
        // A target that changed since it was read.
        let moved = GlobalConfigFile {
            canonical_path: root.join("elsewhere.toml"),
            ..file
        };
        let e = guard_global_config(&moved, &[], &dirs.active.path, &ws, &[]).unwrap_err();
        assert!(e.to_string().contains("when read, and now to"), "{e}");
    }

    #[test]
    fn global_trust_checks_accept_only_the_user_or_root() {
        let uid = 1000;
        let file = |uid, mode| Ownership {
            uid,
            mode: libc::S_IFREG | mode,
        };
        let dir = |uid, mode| Ownership {
            uid,
            mode: libc::S_IFDIR | mode,
        };
        assert_eq!(check_global_file_trust(file(uid, 0o644), uid), Ok(()));
        assert_eq!(check_global_file_trust(file(0, 0o444), uid), Ok(()));
        assert_eq!(
            check_global_file_trust(file(1001, 0o644), uid),
            Err("it is owned by uid 1001, neither uid 1000 nor root".into())
        );
        assert_eq!(check_global_dir_trust(dir(0, 0o1775), uid), Ok(()));
        assert_eq!(check_global_dir_trust(dir(uid, 0o755), uid), Ok(()));
        assert_eq!(
            check_global_dir_trust(dir(1001, 0o755), uid),
            Err("is owned by uid 1001, neither uid 1000 nor root".into())
        );
        assert_eq!(check_global_link_trust(0, uid), Ok(()));
        assert_eq!(check_global_link_trust(uid, uid), Ok(()));
        assert_eq!(
            check_global_link_trust(1001, uid),
            Err("the symbolic link is owned by uid 1001, neither uid 1000 nor root".into())
        );
    }

    #[test]
    fn tool_grants_are_paths_or_a_search_path() {
        let grants = |src: &str| -> bool {
            manifest_grants_tools(&toml::from_str::<Manifest>(src).unwrap())
        };
        assert!(!grants(""));
        assert!(!grants(
            "fs.masked = [\"/x\"]\nenv.set = { EDITOR = \"vi\" }"
        ));
        assert!(!grants("fs.protected = [\"/x\"]\nnetwork.mode = \"full\""));
        // The host's `PATH` never reaches the sandbox, so passing it grants
        // nothing.
        assert!(!grants("env.pass = [\"PATH\", \"*\"]"));
        for src in [
            "fs.ro = [\"/usr\"]",
            "fs.rw = [\"~/data\"]",
            "fs.bind = [{ host = \"/opt/a\", sandbox = \"/opt/b\", mode = \"ro\" }]",
            "env.path_prepend = [\"/bin\"]",
            "[profiles.p]\nfs.ro = [\"/usr\"]",
        ] {
            assert!(grants(src), "{src}");
        }
    }
}
