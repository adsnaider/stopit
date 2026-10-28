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
//!    and the command, on the supervisor's own stdio ([`wait_foreground`]);
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
//! Not done yet: the PTY proxy (§5; until then the sandbox runs on the
//! host's terminal, see [`TerminalSession`]), the user-global configuration
//! layered under `.stopit.toml` (§3), the refusal of a default base with no
//! user provider granting tools (§3.2), the broker, protected files and the
//! network proxy.

use std::collections::HashSet;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, IsTerminal, Read};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{ExitCode, ExitStatus};
use std::sync::atomic::{AtomicI32, Ordering};

use rustix::io::Errno;
use rustix::process::Pid;
use rustix::termios::Termios;
use thiserror::Error;

use crate::bwrap::{BwrapCommand, BwrapError, TerminalSession, working_dir};
use crate::config::{Base, Config, ConfigError, ProfileRef, ProviderKind, ProviderName};
use crate::escape::{escape_message, shell_quote};
use crate::expand::{ExpandError, ExpansionContext, ResolveWarning};
use crate::manifest::SandboxHome;
use crate::provider::{
    BASE_PROVIDER_NAME, ProtectedSource, ProviderContext, ProviderError, SUPERVISOR_PROVIDER_NAME,
    protected_sources, session_providers, static_outputs,
};
use crate::provision::{ProvisionError, provision_self};
use crate::resolve::{PlanWarning, PlanWarningKind};
use crate::session::{SessionDir, SessionError};
use crate::spec::{CompileError, CompiledSession, SpecWarning, compile_session, static_rw_roots};
use crate::state::{
    StateDirs, StateError, data_dirs_from_host, resolve_allowing_missing, runtime_dir,
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
        "stopit is not in the foreground of its terminal (started in the background?); until \
         stopit runs the sandbox on a terminal of its own, it only starts in the foreground"
    )]
    Background,

    /// Whether stopit is in the foreground of its terminal cannot be told.
    #[error("cannot check that stopit is in the foreground of its terminal: {0}")]
    Foreground(#[source] io::Error),
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

/// Prints `stopit: warning: <message>` to stderr, escaped.
fn print_warning(message: &str) {
    eprintln!("stopit: warning: {}", escape_message(message));
}

/// Prints `stopit: <line>` of the startup summary to stderr, escaped (the
/// summary escapes its values already; this keeps its backslashes).
fn print_summary_line(line: &str) {
    eprintln!("stopit: {}", escape_message(line));
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
    let workspace = discover_workspace(&cwd, invocation.workspace.as_deref())?;
    let file = workspace.read_config()?;
    // No mount may expose them (§6.2, Reserved host paths), even before
    // they exist. From the password database, not `HOME`, plus
    // `STOPIT_STATE_DIR` if set. The store is created now if missing, so
    // that read-only views of it mask it.
    let data_dirs = data_dirs_from_host()?;
    let store = TrustStore::open(&data_dirs.store.path)?;
    // Before anything runs or is created: only a configuration the user
    // allowed, in the exact bytes read, which are the bytes parsed; and not
    // the default one in place of an allowed one that is gone.
    let allowed = store.read()?;
    drop(store);
    let explicit = invocation.workspace.is_some().then_some(&workspace.dir);
    let config = match &file {
        None => {
            let links = discovery_links(
                &cwd,
                invocation.workspace.as_deref(),
                std::env::var_os("PWD"),
            );
            check_missing(&allowed, &workspace.dir, explicit.is_some(), &links)?;
            Config::default()
        }
        Some(file) => {
            check_allowed(&allowed, file, explicit.map(PathBuf::as_path))?;
            file.parse()?
        }
    };
    // TODO(§3): layer `.stopit.toml` over the user-global configuration.
    let home = host_home(std::env::var_os("HOME"))?;
    let mount = config.workspace.mount.clone();
    let ctx = ExpansionContext::new(
        workspace.dir.clone(),
        mount.clone(),
        home.clone(),
        SandboxHome::default(),
    )?;
    let profile = match &invocation.profile {
        None => ProfileRef::main(),
        Some(name) => name.parse().map_err(|e| RunError::ProfileName {
            name: name.clone(),
            reason: format!("{e}"),
        })?,
    };

    // Before the providers, which are told where it is. From here on,
    // returning removes it.
    let session = SessionDir::create_from_env()?;
    // Relative script sources are resolved against the configuration
    // file's directory: the workspace, by construction.
    let providers = session_providers(&config, &workspace.dir)?;
    let pctx = ProviderContext {
        workspace: workspace.dir.clone(),
        workspace_mount: mount.clone(),
        home: home.clone(),
        session_dir: session.root().to_path_buf(),
        // Script paths must not run through links in these (§3.6).
        rw_grants: static_rw_roots(&static_outputs(&providers), &ctx),
    };
    let outputs = providers
        .iter()
        .map(|p| Ok((p.name().clone(), p.manifest(&pctx)?)))
        .collect::<Result<Vec<_>, ProviderError>>()?;
    // The script providers' sources, and the configuration file itself,
    // protected in every profile whatever the base and rules (§3, §3.6),
    // the latter attributed to the name reserved for stopit's own rules.
    let mut protected = protected_sources(&providers)?;
    if let Some(file) = &file {
        protected.push(ProtectedSource {
            provider: SUPERVISOR_PROVIDER_NAME
                .parse()
                .expect("the supervisor's name is a valid provider name"),
            path: file.path.clone(),
        });
    }
    // stopit's own state, which no mount may expose (§6.2, Reserved host
    // paths): the parent of every session directory, and the data
    // directories. `XDG_RUNTIME_DIR` is set and absolute, or there would be
    // no session.
    let runtime = runtime_dir(Path::new(
        &std::env::var_os("XDG_RUNTIME_DIR").unwrap_or_default(),
    ))?;
    debug_assert_eq!(Some(runtime.path.as_path()), session.root().parent());
    let state = StateDirs {
        runtime,
        data: data_dirs,
    };
    let compiled = compile_session(&config, outputs, &protected, &state, &ctx)?;
    for line in warning_lines(&compiled, config.base) {
        print_warning(&line);
    }
    // TODO(§3.2): refuse a default base with no user provider granting tools.
    let profile_name = profile.as_str().to_owned();
    let Some(profile) = compiled.get(&profile) else {
        return Err(RunError::UnknownProfile {
            name: profile.as_str().to_owned(),
            available: compiled
                .order()
                .iter()
                .map(ProfileRef::as_str)
                .collect::<Vec<_>>()
                .join(", "),
        });
    };
    // After the warnings, right before the sandbox starts, so it is the
    // last thing above the command's own output.
    if !invocation.quiet {
        let unprotected = unprotected_providers(&config);
        let ctx = SummaryContext {
            profile: &profile_name,
            workspace: &workspace.dir,
            workspace_mount: mount.as_path(),
            home: &home,
            base: config.base,
            unprotected: &unprotected,
        };
        for line in summary_lines(&profile.spec, &ctx) {
            print_summary_line(&line);
        }
    }

    let provisioned = provision_self(&session)?;
    let env = profile.spec.target_env(std::env::vars_os());
    let sandbox_cwd = working_dir(&profile.spec, mount.as_path());
    let stdio = stdio_terminals();
    let terminal = terminal_session(stdio);
    let command = BwrapCommand::for_init(
        &profile.spec,
        &session,
        &provisioned,
        &sandbox_cwd,
        &env,
        &invocation.command,
        terminal,
    )?;
    ignore_job_control();
    if terminal == TerminalSession::Detach {
        check_foreground(stdio)?;
    }
    let saved = TerminalState::save(stdio);
    let status = wait_foreground(command);
    saved.restore();
    // The sandbox is gone, or going: bwrap returns once its namespace's
    // init exits, and if bwrap itself was killed, `--die-with-parent` kills
    // the init and so the namespace. Its mounts go with it.
    drop(session);
    Ok(ExitCode::from(status?))
}

// --- Signals ---

/// The signals the supervisor catches ([`catch_signals`]) and forwards to
/// bwrap.
const CAUGHT: [libc::c_int; 4] = [libc::SIGINT, libc::SIGQUIT, libc::SIGTERM, libc::SIGHUP];

/// The last caught signal not yet handled, or 0.
static RECEIVED: AtomicI32 = AtomicI32::new(0);

/// Non-blocking self-pipe waking threads blocked in `poll` when a caught
/// signal arrives.
static SIGNAL_READ_FD: AtomicI32 = AtomicI32::new(-1);
static SIGNAL_WRITE_FD: AtomicI32 = AtomicI32::new(-1);
static SIGNAL_PIPE_INIT: std::sync::OnceLock<Result<(), i32>> = std::sync::OnceLock::new();

/// Signal handler for [`CAUGHT`] that records the signal and wakes [`signal_poll_fd`].
extern "C" fn record_signal(signal: libc::c_int) {
    RECEIVED.store(signal, Ordering::SeqCst);
    let wfd = SIGNAL_WRITE_FD.load(Ordering::Relaxed);
    if wfd >= 0 {
        let byte: u8 = 1;
        // SAFETY: `write` is async-signal-safe, and `wfd` is non-blocking.
        unsafe {
            let _ = libc::write(wfd, (&raw const byte).cast(), 1);
        }
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

/// The last caught signal not yet handled, if any, now handled.
fn take_signal() -> Option<libc::c_int> {
    let rfd = SIGNAL_READ_FD.load(Ordering::Acquire);
    if rfd >= 0 {
        let mut buf = [0u8; 64];
        // SAFETY: `rfd` is a valid non-blocking pipe descriptor owned for the
        // life of the process.
        while unsafe { libc::read(rfd, buf.as_mut_ptr().cast(), buf.len()) } > 0 {}
    }
    match RECEIVED.swap(0, Ordering::SeqCst) {
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
fn catch_signals() -> io::Result<()> {
    init_signal_pipe()?;
    for signal in CAUGHT {
        // SAFETY: `sigaction` on a zeroed, then filled, local struct. The
        // handler only stores to an atomic, which is async-signal-safe.
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
/// Until the PTY proxy exists, a sandbox detached from the terminal
/// ([`TerminalSession::Detach`]) still has it as its stdio, but the kernel's
/// job-control checks only apply to a process's controlling terminal: were
/// the supervisor stopped (Ctrl-Z) or put in the background, the sandbox
/// would go on reading and writing the terminal behind the shell's back. So
/// the supervisor cannot be stopped by the terminal, and refuses to start in
/// the background ([`check_foreground`]).
fn ignore_job_control() {
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
fn check_foreground(stdio: [bool; 3]) -> Result<(), RunError> {
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

/// The terminal settings of the supervisor's stdio, to restore after the
/// command: a sandbox detached from the terminal still has it as its stdio,
/// and can change them (raw mode, echo off) and exit without restoring
/// them.
struct TerminalState(Vec<(BorrowedFd<'static>, Termios)>);

impl TerminalState {
    /// The settings of every stdio among `stdio` that is a terminal, or of
    /// none if they cannot be read.
    fn save(stdio: [bool; 3]) -> Self {
        TerminalState(
            stdio_fds(stdio)
                .filter_map(|fd| Some((fd, rustix::termios::tcgetattr(fd).ok()?)))
                .collect(),
        )
    }

    /// Restores them, as far as possible: there is nothing to do about a
    /// failure but leave the terminal as the command left it.
    fn restore(self) {
        for (fd, termios) in self.0 {
            let _ = rustix::termios::tcsetattr(fd, rustix::termios::OptionalActions::Now, &termios);
        }
    }
}

/// Spawns `command` (bwrap) on the supervisor's stdio and waits for it,
/// returning the exit status to exit with ([`exit_code`]).
///
/// The caught signals ([`CAUGHT`]) are blocked from just before the spawn
/// (bwrap starts with the mask the supervisor had before) and only
/// unblocked while waiting in `ppoll`, so none is missed between checking
/// for one and waiting. One that arrived before the spawn ends the run
/// with `128 + N` instead. One that arrives while bwrap runs is forwarded
/// to it, so that the sandbox ends and the supervisor goes on to clean up;
/// the supervisor then exits with bwrap's status, `128 + N` if the signal
/// killed it. That includes `SIGINT` and `SIGQUIT`: a terminal's Ctrl-C
/// reaches bwrap through the process group anyway, but not the sandboxed
/// program, which is in a session of its own (§6.2 step 1), and a signal
/// sent to the supervisor alone should end the sandbox just the same.
fn wait_foreground(command: BwrapCommand) -> Result<u8, RunError> {
    let mask = BlockedSignals::block().map_err(RunError::Signals)?;
    if let Some(signal) = take_signal() {
        return Ok(signal_exit_code(signal));
    }
    let (mut command, status_reader) = command.into_command_with_status()?;
    let old = mask.old;
    // SAFETY: `pthread_sigmask` is async-signal-safe, and `old` a copy.
    unsafe {
        command.pre_exec(move || {
            match libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut()) {
                0 => Ok(()),
                e => Err(io::Error::from_raw_os_error(e)),
            }
        });
    }
    let mut child = command.spawn().map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            RunError::BwrapMissing
        } else {
            RunError::Spawn(e)
        }
    })?;
    // Close our copy of the status pipe's write end so `status_reader` sees EOF
    // when bwrap finishes or execs `__init`.
    drop(command);
    let pid = Pid::from_child(&child);
    // Waiting through a pidfd lets `ppoll` wait for the child and the
    // signals at once. Without one (impossible on the kernels stopit
    // supports), signals are only forwarded once bwrap is done.
    if let Ok(pidfd) = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()) {
        loop {
            if let Some(signal) = take_signal() {
                // SAFETY: a plain syscall. The child is not reaped yet, so
                // its pid is still its own.
                unsafe { libc::kill(pid.as_raw_nonzero().get(), signal) };
            }
            match mask.wait_readable(pidfd.as_fd()) {
                Ok(()) => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
    }
    let status = child.wait().map_err(RunError::Spawn)?;
    let json_status = read_nonblocking_status(status_reader);
    Ok(bwrap_exit_code(status, &json_status))
}

fn read_nonblocking_status(mut reader: File) -> String {
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
fn bwrap_exit_code(status: ExitStatus, json_status: &str) -> u8 {
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
struct BlockedSignals {
    /// The mask before blocking them.
    old: libc::sigset_t,
}

impl BlockedSignals {
    fn block() -> io::Result<Self> {
        // SAFETY: plain libc calls on local, initialized signal sets.
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            for signal in CAUGHT {
                libc::sigaddset(&mut set, signal);
            }
            let mut old: libc::sigset_t = std::mem::zeroed();
            match libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut old) {
                0 => Ok(BlockedSignals { old }),
                e => Err(io::Error::from_raw_os_error(e)),
            }
        }
    }

    /// Waits until `fd` is readable, with [`CAUGHT`] unblocked meanwhile:
    /// `Interrupted` if one of them (or another signal) arrived.
    fn wait_readable(&self, fd: BorrowedFd<'_>) -> io::Result<()> {
        let mut pollfd = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: plain libc calls on a local signal set and pollfd.
        unsafe {
            let mut waiting = self.old;
            for signal in CAUGHT {
                libc::sigdelset(&mut waiting, signal);
            }
            if libc::ppoll(&mut pollfd, 1, std::ptr::null(), &waiting) < 0 {
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
fn signal_exit_code(signal: libc::c_int) -> u8 {
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
fn stdio_terminals() -> [bool; 3] {
    [
        io::stdin().is_terminal(),
        io::stdout().is_terminal(),
        io::stderr().is_terminal(),
    ]
}

/// [`needs_new_session`] for this process, whose stdio is a terminal as
/// `stdio` says.
fn terminal_session(stdio: [bool; 3]) -> TerminalSession {
    if needs_new_session(stdio, has_controlling_terminal()) {
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
    /// The configuration it holds (an empty file is the default
    /// configuration: `base = "default"` and nothing else).
    pub fn parse(&self) -> Result<Config, RunError> {
        let text = std::str::from_utf8(&self.bytes).map_err(|e| RunError::ReadConfig {
            path: self.path.clone(),
            source: io::Error::new(io::ErrorKind::InvalidData, e),
        })?;
        Config::from_toml_str(text).map_err(|source| RunError::Config {
            path: self.path.clone(),
            source,
        })
    }
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
}
