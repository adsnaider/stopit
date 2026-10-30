//! The bubblewrap command line for one sandbox (DESIGN.md §6.2).
//!
//! [`BwrapCommand::new`] compiles a [`SandboxSpec`] into bwrap's arguments:
//! the namespaces (step 1), the system mounts (step 3), the synthesized
//! `/etc` files (step 4, see [`crate::etc`]), the filesystem mounts (step
//! 5), the runtime directory (step 6), the environment (step 7) and the
//! command (step 8). The sandbox-`HOME` stubs of step 4 are not generated
//! yet.
//!
//! Everything is pure generation except what the arguments need on the
//! host. [`SessionDir::ephemeral_dir`] creates each ephemeral mount's
//! session backing directory if missing, and `BwrapCommand` checks nested
//! mount destinations inside those backing directories against planted
//! symlinks. [`SandboxIds::current`] reads the caller's user and group ids.
//! Host mounts and pinned parent directories inside untrusted roots or
//! session `ephemeral/` directories are opened with `openat2` using
//! `O_PATH | O_CLOEXEC` and `RESOLVE_NO_SYMLINKS` and passed to bwrap via
//! `--bind-fd` or `--ro-bind-fd`. Host mounts outside untrusted roots stay
//! path strings so large read-only tool closures do not exhaust descriptor
//! limits.
//!
//! Sealed memfds carry the data bwrap reads from descriptors. The options
//! reach bwrap through `--args FD`, while each masked file's empty content
//! and each synthesized file's content use `--ro-bind-data FD`. A memfd
//! holds any amount of data without a reader, so writing it before bwrap
//! runs never blocks like a pipe above its buffer size.
//! [`BwrapCommand::into_command`] passes `--args FD --` and the command on
//! argv, and [`BwrapCommand::into_command_with_status`] prepends
//! `--json-status-fd FD` with a non-blocking pipe so the supervisor can tell
//! bwrap setup failures apart from the sandboxed command's exit status.
//!
//! In the forked child before `exec`, `pre_exec` first calls `close_range`
//! with `CLOSE_RANGE_CLOEXEC` on every open descriptor above stdio
//! (`3..=u32::MAX`) so parent descriptors never leak into bwrap. Next it
//! reopens each memfd through `/proc/self/fd/N` at offset 0 and moves it onto
//! its target number with `dup2`, clearing `FD_CLOEXEC`. Finally `fcntl` with
//! `F_SETFD` clears `FD_CLOEXEC` in place on each `O_PATH` bind descriptor and
//! any status pipe descriptor.
//!
//! [`BwrapCommand::for_init`] runs `stopit __init` (step 8). The target's
//! environment and the JSON [`init::InitSpec`] go into two more sealed memfds
//! that bwrap passes through to `__init`, named on its argv as
//! `__init --env-fd N --spec-fd M -- <cmd...>`. When `InitSpec::lo_down` is
//! set, `for_init` also passes `--cap-add CAP_SYS_ADMIN --cap-add CAP_NET_ADMIN
//! --cap-add CAP_SETPCAP` so `__init` can unshare into a fresh network
//! namespace inside bwrap's inner user namespace, verify `lo` is down, and
//! clear its capability bounding set before running the target.
//!
//! bwrap leaves its root tmpfs writable; the last option remounts it
//! read-only (step 2), so the sandbox writes only where a mount lets it.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::{CString, OsStr, OsString};
use std::fs::{self, File};
use std::io::{self, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use rustix::fs::{
    CWD, MemfdFlags, Mode, OFlags, ResolveFlags, SealFlags, fcntl_add_seals, memfd_create, mkdirat,
    openat2,
};
use rustix::io::{Errno, FdFlags, fcntl_dupfd_cloexec, fcntl_setfd};
use thiserror::Error;

use crate::config::ProviderName;
use crate::etc::{self, SandboxIds};
use crate::expand::EntryKind;
use crate::init::{self, EnvError, SpecError};
use crate::manifest::{DevMode, ShareableNamespace};
use crate::policy::PathMode;
use crate::provision::Provisioned;
use crate::resolve::{EphemeralKey, MountSource, PlannedMount};
use crate::session::{SessionDir, SessionError};
use crate::spec::{NetworkSpec, SANDBOX_RUNTIME_DIR, SandboxSpec};

/// The bubblewrap program, looked up in `PATH`.
pub const BWRAP: &str = "bwrap";

/// Directories of `/proc` hidden behind an empty read-only tmpfs (§6.2
/// step 3).
pub const PROC_MASKED_DIRS: [&str; 4] = ["/proc/sys", "/proc/bus", "/proc/fs", "/proc/irq"];

/// Files of `/proc` hidden behind an empty file with mode 0000 (§6.2 step 3).
pub const PROC_MASKED_FILES: [&str; 3] = ["/proc/kcore", "/proc/keys", "/proc/timer_list"];

/// The masks of [`PROC_MASKED_DIRS`] and [`PROC_MASKED_FILES`] whose entry
/// only exists with some kernel configurations (`/proc/kcore` needs
/// `CONFIG_PROC_KCORE`, `/proc/keys` `CONFIG_KEYS`, and `/proc/bus` and
/// `/proc/timer_list` depend on the bus and timer support built in). These
/// are left out when the host's `/proc` lacks
/// them, since bwrap cannot create a mount point in procfs. Every other
/// mask is always applied, so it fails closed: the host's `/proc` may be
/// mounted with `subset=pid` and show no `/proc/sys`, while the sandbox's
/// own procfs, a new full instance, has it.
pub const PROC_OPTIONAL_MASKS: [&str; 4] =
    ["/proc/bus", "/proc/kcore", "/proc/keys", "/proc/timer_list"];

/// The mode of an empty file masking a file (§3.4): nobody may open it, so
/// even reading it fails with `EACCES`, while `stat` shows an empty file.
const MASKED_FILE_PERMS: &str = "0000";

/// The mode of a synthesized `/etc` file: readable by everyone. It is
/// mounted read-only, so writing it fails with `EROFS` regardless.
const ETC_FILE_PERMS: &str = "0444";

/// The most arguments bwrap accepts, counting both those on its argv (after
/// the program name, the command included) and those read through
/// `--args`; more make it fail with "Exceeded maximum number of
/// arguments". So a sandbox holds about 3000 mounts at most (DESIGN.md
/// §6.2). Pinned against the bwrap on `PATH` by `tests/bwrap.rs`.
pub const BWRAP_MAX_ARGS: usize = 9000;

/// The arguments on bwrap's argv besides the command: `--args FD --`.
const ARGV_OVERHEAD: usize = 3;

/// Argument count added to bwrap's argv for `--json-status-fd FD`.
const STATUS_ARGV_OVERHEAD: usize = 2;

/// Argument count added to bwrap's argv for `--block-fd FD`.
const BLOCK_ARGV_OVERHEAD: usize = 2;

/// The lowest descriptor number handed to bwrap. Lower ones are stdio, which
/// the child's standard streams replace before the descriptors are
/// inherited.
const MIN_FD: RawFd = 3;

/// Error building the bwrap command.
#[derive(Debug, Error)]
pub enum BwrapError {
    /// An argument contains a NUL byte. `--args` separates arguments with
    /// NUL, and argv cannot hold one either.
    #[error("bwrap argument {arg:?} contains a NUL byte")]
    Nul {
        /// The argument.
        arg: OsString,
    },

    /// The sandbox working directory is not an absolute path.
    #[error("the sandbox working directory {0:?} is not an absolute path")]
    RelativeCwd(PathBuf),

    /// A masked mount's source is a symlink whose target could not be
    /// inspected, so the shape of the mask is unknown. The spec compiler
    /// refuses such a mount (DESIGN.md §3.4, Symlinks), so this is a bug.
    #[error(
        "internal error: masked mount at {sandbox:?} has the symlink {host:?} as its source, \
         so it is unknown whether to mask a file or a directory"
    )]
    MaskedSymlink {
        /// The sandbox path.
        sandbox: PathBuf,
        /// The host link.
        host: PathBuf,
    },

    /// A mount's mode and source do not fit together (an ephemeral mount
    /// with a host source, or the reverse). The spec compiler never plans
    /// one, so this is a bug.
    #[error("internal error: {mode} mount at {sandbox:?} cannot show {shown}")]
    Inconsistent {
        /// The sandbox path.
        sandbox: PathBuf,
        /// The mount's mode.
        mode: PathMode,
        /// What it was planned to show.
        shown: MountSource,
    },

    /// An ephemeral mount's backing directory could not be prepared.
    #[error("cannot prepare the ephemeral directory mounted at {sandbox:?}: {error}")]
    Ephemeral {
        /// The sandbox path of the mount.
        sandbox: PathBuf,
        /// What went wrong.
        #[source]
        error: SessionError,
    },

    /// A mount destination below an ephemeral mount traverses a symlink inside
    /// the session's ephemeral backing directory.
    #[error(
        "refusing mount at {sandbox:?} below ephemeral {ephemeral:?} because {link:?} in the \
         session ephemeral directory is a symbolic link"
    )]
    EphemeralDestinationLink {
        /// The sandbox path of the nested mount.
        sandbox: PathBuf,
        /// The sandbox path of the ancestor ephemeral mount.
        ephemeral: PathBuf,
        /// The symlink found in the ephemeral backing directory.
        link: PathBuf,
    },

    /// An entry inside an ephemeral backing directory on the way to a nested
    /// mount destination could not be inspected.
    #[error(
        "cannot inspect {path:?} in the ephemeral directory for {ephemeral:?} on the way to \
         {sandbox:?}: {error}"
    )]
    EphemeralDestinationInspect {
        /// The sandbox path of the nested mount.
        sandbox: PathBuf,
        /// The sandbox path of the ancestor ephemeral mount.
        ephemeral: PathBuf,
        /// The uninspectable host path.
        path: PathBuf,
        /// What went wrong.
        #[source]
        error: io::Error,
    },

    /// `openat2` with `RESOLVE_NO_SYMLINKS` rejected a symbolic link inside an
    /// untrusted root.
    #[error(
        "refusing mount of {path:?} at {sandbox:?} because a component inside an untrusted \
         directory is a symbolic link"
    )]
    UntrustedSymlink {
        /// The sandbox destination of the mount.
        sandbox: PathBuf,
        /// The host path being opened.
        path: PathBuf,
    },

    /// Opening a mount source descriptor failed.
    #[error("cannot open mount source {path:?} for {sandbox:?}: {error}")]
    MountOpen {
        /// The sandbox destination of the mount.
        sandbox: PathBuf,
        /// The host path being opened.
        path: PathBuf,
        /// What went wrong.
        #[source]
        error: io::Error,
    },

    /// Creating a status pipe for bwrap failed.
    #[error("cannot create a status pipe for bwrap: {0}")]
    StatusPipe(#[source] io::Error),

    /// The sandbox needs more arguments than bwrap accepts, because it has
    /// too many mounts.
    #[error(
        "the sandbox needs {count} bwrap arguments for its {mounts} mounts, but bwrap accepts \
         at most {max} (about 3 per mount){}: narrow the profile's globs or grant directories \
         instead of many single files",
        match provider {
            Some(p) => format!("; provider \"{p}\" contributes {provider_mounts} of the mounts"),
            None => String::new(),
        }
    )]
    TooManyArgs {
        /// The arguments needed, on argv and through `--args`.
        count: usize,
        /// [`BWRAP_MAX_ARGS`].
        max: usize,
        /// The number of filesystem mounts.
        mounts: usize,
        /// The provider contributing the most mounts, if any.
        provider: Option<ProviderName>,
        /// How many mounts it contributes.
        provider_mounts: usize,
    },

    /// A file descriptor holding data for bwrap could not be created or
    /// filled.
    #[error("cannot create a file descriptor for bwrap's arguments: {0}")]
    DataFd(#[source] io::Error),

    /// The target's environment cannot be handed to `__init`.
    #[error("cannot pass the environment to the sandbox: {0}")]
    Env(#[source] EnvError),

    /// The init policy specification cannot be handed to `__init`.
    #[error("cannot pass the init specification to the sandbox: {0}")]
    Spec(#[source] SpecError),

    /// `__init` was given no command to run.
    #[error("no command to run in the sandbox")]
    NoCommand,
}

/// How the sandbox relates to the caller's session and terminal.
///
/// When any of the supervisor's stdio is a terminal, the sandbox runs on a
/// PTY of the supervisor's (DESIGN.md §5.1, [`Pty`](Self::Pty)): `__init`
/// starts a session of its own with the slave as controlling terminal, so
/// the host terminal is never the sandbox's. When none is, but the
/// supervisor has a controlling terminal the sandbox could open as
/// `/dev/tty`, bwrap's `--new-session` detaches it ([`Detach`](Self::Detach)).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TerminalSession {
    /// Stay in the caller's session (no `--new-session`).
    #[default]
    Keep,
    /// A new session, detached from the caller's controlling terminal
    /// (`--new-session`).
    Detach,
    /// A new session that `__init` starts, whose controlling terminal is the
    /// supervisor's PTY slave on the sandbox's stdio (`InitSpec::pty_slave`).
    /// bwrap gets no `--new-session`, since `__init` must not already lead a
    /// session. Only [`BwrapCommand::for_init`] runs `__init`; for other
    /// commands it is [`Detach`](Self::Detach), so the host terminal stays
    /// out of reach either way.
    Pty,
}

/// Whether stopit makes the sandbox's network namespace itself, for pasta
/// to join ([`crate::net`]). It does with `network = "full"`, unless the
/// profile shares the host's.
pub fn own_network_namespace(spec: &SandboxSpec) -> bool {
    spec.network == NetworkSpec::Full && !spec.namespaces.is_shared(ShareableNamespace::Net)
}

/// The working directory a sandbox starts in: the workspace mount if the
/// spec mounts something there, else `/` (DESIGN.md §6.2).
pub fn working_dir(spec: &SandboxSpec, workspace_mount: &Path) -> PathBuf {
    if spec.mounts.iter().any(|m| m.sandbox == workspace_mount) {
        workspace_mount.to_path_buf()
    } else {
        PathBuf::from("/")
    }
}

/// A ready-to-run bwrap invocation for one sandbox.
///
/// It owns the file descriptors its arguments name, and hands them to the
/// [`Command`] that [`into_command`](Self::into_command) makes of it.
#[derive(Debug)]
pub struct BwrapCommand {
    /// The options, as passed through `--args`.
    args: Vec<OsString>,
    /// The command after `--`.
    command: Vec<OsString>,
    /// The memfd holding `args`, NUL-terminated.
    args_fd: OwnedFd,
    /// One memfd per data argument, in the order `args` names them.
    data_fds: Vec<OwnedFd>,
    /// One `O_PATH` descriptor per `--bind-fd` or `--ro-bind-fd` argument, in
    /// the order `args` names them.
    bind_fds: Vec<OwnedFd>,
    /// The memfd holding the target's environment for `__init`, if the
    /// command runs it ([`for_init`](Self::for_init)).
    env_fd: Option<OwnedFd>,
    /// The memfd holding the JSON [`init::InitSpec`] for `__init`, if the
    /// command runs it ([`for_init`](Self::for_init)).
    spec_fd: Option<OwnedFd>,
    /// Mount count and largest provider for [`BwrapError::TooManyArgs`].
    mounts_summary: (usize, Option<ProviderName>, usize),
    /// Whether bwrap runs in a user and network namespace of stopit's, for
    /// pasta to join ([`own_network_namespace`]).
    own_netns: bool,
}

impl BwrapCommand {
    /// Builds the bwrap invocation that runs `stopit __init` in the sandbox
    /// `spec` of `session`, through the stopit binary `provisioned` into the
    /// session directory, starting in `cwd` (see [`working_dir`]). `__init`
    /// then enforces [`init::InitSpec`] and runs `target` with the environment
    /// `env` (DESIGN.md §6.2 steps 7 and 8, §6.3).
    ///
    /// `env` and the compiled [`init::InitSpec`] are written to sealed memfds
    /// that bwrap passes through to `__init`, named on its argv as
    /// `<prefix> __init --env-fd N --spec-fd M -- <target...>`.
    ///
    /// `terminal` selects whether bwrap creates a new session (see
    /// [`TerminalSession`]).
    pub fn for_init(
        spec: &SandboxSpec,
        session: &SessionDir,
        provisioned: &Provisioned,
        cwd: &Path,
        env: &[(OsString, OsString)],
        target: &[OsString],
        terminal: TerminalSession,
    ) -> Result<BwrapCommand, BwrapError> {
        Self::for_init_with(
            spec,
            session,
            provisioned,
            cwd,
            env,
            target,
            terminal,
            &RunExtras::default(),
        )
    }

    /// [`for_init`](Self::for_init), with what a run adds ([`RunExtras`]).
    #[allow(clippy::too_many_arguments)]
    pub fn for_init_with(
        spec: &SandboxSpec,
        session: &SessionDir,
        provisioned: &Provisioned,
        cwd: &Path,
        env: &[(OsString, OsString)],
        target: &[OsString],
        terminal: TerminalSession,
        extras: &RunExtras,
    ) -> Result<BwrapCommand, BwrapError> {
        if target.is_empty() {
            return Err(BwrapError::NoCommand);
        }
        let encoded = init::encode_env(env.iter().map(|(k, v)| (k, v))).map_err(BwrapError::Env)?;
        let env_fd = sealed_memfd("stopit-init-env", &encoded).map_err(BwrapError::DataFd)?;
        let mut init_spec = init::InitSpec::from_sandbox_spec(spec);
        init_spec.pty_slave = terminal == TerminalSession::Pty;
        init_spec.cwd = extras.cwd.clone();
        init_spec.skip_shims = extras.skip_shims;
        // `__init` enters `extras.cwd` itself, from the root, with
        // `openat2(RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS)`.
        let cwd = if extras.cwd.is_some() {
            Path::new("/")
        } else {
            cwd
        };
        let encoded_spec = init::encode_spec(&init_spec).map_err(BwrapError::Spec)?;
        let spec_fd =
            sealed_memfd("stopit-init-spec", &encoded_spec).map_err(BwrapError::DataFd)?;
        let argv = init::init_argv(env_fd.as_raw_fd(), spec_fd.as_raw_fd(), target);
        let mut command = Self::build(
            spec,
            session,
            provisioned,
            cwd,
            &argv,
            terminal,
            init_spec.lo_down,
            extras,
        )?;
        command.env_fd = Some(env_fd);
        command.spec_fd = Some(spec_fd);
        Ok(command)
    }

    /// Builds the bwrap invocation that runs `argv_after_prefix` in the
    /// sandbox `spec` of `session`, through the binary `provisioned` into
    /// the session directory, starting in `cwd` (see [`working_dir`]).
    /// [`for_init`](Self::for_init) runs `stopit __init`, while `new` runs any
    /// provisioned binary directly without `--cap-add`.
    ///
    /// Creates each ephemeral mount's backing directory if missing, and the
    /// memfds the arguments name.
    pub fn new(
        spec: &SandboxSpec,
        session: &SessionDir,
        provisioned: &Provisioned,
        cwd: &Path,
        argv_after_prefix: &[OsString],
        terminal: TerminalSession,
    ) -> Result<BwrapCommand, BwrapError> {
        let terminal = match terminal {
            TerminalSession::Pty => TerminalSession::Detach,
            other => other,
        };
        Self::build(
            spec,
            session,
            provisioned,
            cwd,
            argv_after_prefix,
            terminal,
            false,
            &RunExtras::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        spec: &SandboxSpec,
        session: &SessionDir,
        provisioned: &Provisioned,
        cwd: &Path,
        argv_after_prefix: &[OsString],
        terminal: TerminalSession,
        retain_init_caps: bool,
        extras: &RunExtras,
    ) -> Result<BwrapCommand, BwrapError> {
        // A sandbox without shims gets the session's `bin`, which stays
        // empty: the profiles' shims live elsewhere in the session.
        let (bin, shim) = match &extras.shims {
            Some((bin, shim)) => (bin.clone(), Some(shim.clone())),
            None => (session.bin(), None),
        };
        let runtime = RuntimeBinds {
            exe: provisioned.exe().to_path_buf(),
            lib_dir: provisioned.lib_dir().to_path_buf(),
            bin,
            prefix: provisioned.command_prefix(Path::new(SANDBOX_RUNTIME_DIR)),
            proxy_socket: extras.proxy_socket.clone(),
            broker_socket: extras.broker_socket.clone(),
            shim,
        };
        let mut untrusted_roots = spec.untrusted_roots.clone();
        untrusted_roots.insert(session.ephemeral());
        for mount in &spec.mounts {
            if mount.mode == PathMode::Rw
                && let MountSource::Host { path, .. } = &mount.source
            {
                let canon = spec
                    .canonical_sources
                    .get(&mount.sandbox)
                    .cloned()
                    .or_else(|| fs::canonicalize(path).ok())
                    .unwrap_or_else(|| path.clone());
                untrusted_roots.insert(canon);
            }
        }
        ensure_ephemeral_parents(spec, session)?;
        let plan = plan_with_caps(
            spec,
            &untrusted_roots,
            &runtime,
            SandboxIds::current(),
            cwd,
            argv_after_prefix,
            terminal,
            retain_init_caps,
            &|path| path.symlink_metadata().is_ok(),
            &|path| Some(fs::symlink_metadata(path)),
            &mut |sandbox, key| {
                session
                    .ephemeral_dir(key)
                    .map_err(|error| BwrapError::Ephemeral {
                        sandbox: sandbox.to_path_buf(),
                        error,
                    })
            },
        )?;

        let data_fds = plan
            .data
            .iter()
            .map(|data| sealed_memfd("stopit-bwrap-data", data))
            .collect::<io::Result<Vec<_>>>()
            .map_err(BwrapError::DataFd)?;
        let bind_fds = open_bind_fds(&plan.binds)?;
        let args: Vec<OsString> = plan
            .args
            .into_iter()
            .map(|arg| match arg {
                Arg::Text(text) => text,
                Arg::Data(index) => data_fds[index].as_raw_fd().to_string().into(),
                Arg::Bind(index) => bind_fds[index].as_raw_fd().to_string().into(),
            })
            .collect();
        let args_fd = sealed_memfd("stopit-bwrap-args", &serialize_args(&args))
            .map_err(BwrapError::DataFd)?;
        let (provider, provider_mounts) = largest_provider(&spec.mounts);
        Ok(BwrapCommand {
            args,
            command: plan.command,
            args_fd,
            data_fds,
            bind_fds,
            env_fd: None,
            spec_fd: None,
            mounts_summary: (spec.mounts.len(), provider, provider_mounts),
            own_netns: own_network_namespace(spec),
        })
    }

    /// The options passed to bwrap through `--args`, in order.
    pub fn args(&self) -> &[OsString] {
        &self.args
    }

    /// The command bwrap runs in the sandbox, passed on argv after `--`.
    pub fn command(&self) -> &[OsString] {
        &self.command
    }

    /// Whether the sandbox needs pasta for its network. bwrap then waits on
    /// `--block-fd` until [`crate::net::start_pasta`] lets it go on.
    pub fn needs_pasta(&self) -> bool {
        self.own_netns
    }

    /// The descriptor `--args` names.
    pub fn args_fd(&self) -> RawFd {
        self.args_fd.as_raw_fd()
    }

    /// The descriptor holding the target's environment for `__init`, if the
    /// command runs it ([`for_init`](Self::for_init)).
    pub fn env_fd(&self) -> Option<RawFd> {
        self.env_fd.as_ref().map(AsRawFd::as_raw_fd)
    }

    /// The descriptor holding the JSON [`init::InitSpec`] for `__init`, if the
    /// command runs it ([`for_init`](Self::for_init)).
    pub fn spec_fd(&self) -> Option<RawFd> {
        self.spec_fd.as_ref().map(AsRawFd::as_raw_fd)
    }

    /// Every descriptor bwrap inherits: [`args_fd`](Self::args_fd), then the
    /// data descriptors in argument order, then the bind descriptors in
    /// argument order, then [`env_fd`](Self::env_fd) and
    /// [`spec_fd`](Self::spec_fd) if present.
    pub fn inherited_fds(&self) -> Vec<RawFd> {
        std::iter::once(&self.args_fd)
            .chain(&self.data_fds)
            .chain(&self.bind_fds)
            .chain(&self.env_fd)
            .chain(&self.spec_fd)
            .map(AsRawFd::as_raw_fd)
            .collect()
    }

    /// The process to spawn: `bwrap --args <fd> -- <command…>`, inheriting
    /// [`inherited_fds`](Self::inherited_fds) at their numbers. Its stdio,
    /// environment and working directory are left as `Command` defaults
    /// (bwrap's own; the sandbox's come from the arguments).
    ///
    /// The returned `Command` owns the descriptors and closes them when
    /// dropped. It may be spawned more than once, each time with the same
    /// arguments: bwrap reads its descriptors to the end, so each child
    /// gets fresh ones, opened anew on the same memfds after the fork.
    ///
    /// When the sandbox [needs pasta](Self::needs_pasta), bwrap runs in a
    /// network namespace of its own with no `--block-fd`, so the sandbox
    /// has no network but an `lo` that is down.
    pub fn into_command(self) -> Command {
        self.build_command(None, None)
    }

    /// Builds the `bwrap` command with `--json-status-fd <fd>` and returns the
    /// non-blocking read end of the status pipe. Drop the returned `Command`
    /// after spawning so the parent's write end closes.
    ///
    /// When the sandbox [needs pasta](Self::needs_pasta), bwrap also gets
    /// `--block-fd`, and the write end of that pipe is returned, for
    /// [`crate::net::start_pasta`]. bwrap goes on once a byte arrives, and
    /// also once every copy of the write end is closed. So if pasta fails,
    /// kill bwrap before dropping it. bwrap then has no network but an `lo`
    /// that is down, never the host's.
    pub fn into_command_with_status(self) -> Result<(Command, File, Option<OwnedFd>), BwrapError> {
        let block_overhead = if self.own_netns {
            BLOCK_ARGV_OVERHEAD
        } else {
            0
        };
        let count = self.args.len()
            + ARGV_OVERHEAD
            + STATUS_ARGV_OVERHEAD
            + block_overhead
            + self.command.len();
        if count > BWRAP_MAX_ARGS {
            let (mounts, provider, provider_mounts) = self.mounts_summary;
            return Err(BwrapError::TooManyArgs {
                count,
                max: BWRAP_MAX_ARGS,
                mounts,
                provider,
                provider_mounts,
            });
        }
        let (read_fd, write_fd) = cloexec_pipe().map_err(BwrapError::StatusPipe)?;
        let block = if self.own_netns {
            let (block_read, block_write) = cloexec_pipe().map_err(BwrapError::StatusPipe)?;
            // bwrap reads its end blocking.
            rustix::fs::fcntl_setfl(&block_read, OFlags::empty())
                .map_err(|e| BwrapError::StatusPipe(e.into()))?;
            let block_read = if block_read.as_raw_fd() < MIN_FD {
                fcntl_dupfd_cloexec(&block_read, MIN_FD)
                    .map_err(|e| BwrapError::StatusPipe(e.into()))?
            } else {
                block_read
            };
            Some((block_read, block_write))
        } else {
            None
        };
        let (block_read, block_write) = block.unzip();
        let command = self.build_command(Some(write_fd), block_read);
        Ok((command, File::from(read_fd), block_write))
    }

    fn build_command(
        self,
        status_write_fd: Option<OwnedFd>,
        block_read_fd: Option<OwnedFd>,
    ) -> Command {
        let mut command = Command::new(BWRAP);
        if let Some(ref sfd) = status_write_fd {
            command
                .arg("--json-status-fd")
                .arg(sfd.as_raw_fd().to_string());
        }
        if let Some(ref bfd) = block_read_fd {
            command.arg("--block-fd").arg(bfd.as_raw_fd().to_string());
        }
        // The id maps for the user namespace of `own_netns`, built before
        // the fork so the child never allocates. The kernel checks the
        // writer's effective ids.
        let netns_maps = self.own_netns.then(|| {
            let uid = rustix::process::geteuid().as_raw();
            let gid = rustix::process::getegid().as_raw();
            (
                CString::new(format!("{uid} {uid} 1")).expect("no NUL in numbers"),
                CString::new(format!("{gid} {gid} 1")).expect("no NUL in numbers"),
            )
        });
        // Whether this process is not dumpable, as `stopit server` makes
        // itself. Its `/proc/self` files then belong to root, and the child
        // cannot write its maps without being dumpable for that moment.
        // SAFETY: a plain prctl query.
        let undumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } == 0;
        command
            .arg("--args")
            .arg(self.args_fd.as_raw_fd().to_string())
            .arg("--")
            .args(&self.command);
        // Built before the fork so the child never allocates.
        let mut reopen_fds: Vec<(OwnedFd, CString)> = std::iter::once(self.args_fd)
            .chain(self.data_fds)
            .chain(self.env_fd)
            .chain(self.spec_fd)
            .map(|fd| {
                let path = CString::new(format!("/proc/self/fd/{}", fd.as_raw_fd()))
                    .expect("no NUL in a number");
                (fd, path)
            })
            .collect();
        let mut keep_fds = self.bind_fds;
        if let Some(sfd) = status_write_fd {
            keep_fds.push(sfd);
        }
        if let Some(bfd) = block_read_fd {
            keep_fds.push(bfd);
        }
        // SAFETY: the closure runs in the forked child before `exec`, where
        // only async-signal-safe operations are allowed. It allocates
        // nothing and takes no locks. First `close_range` marks every open
        // descriptor above stdio close-on-exec so descriptors leaked into the
        // supervisor never reach bwrap or the sandbox. Then the loop reopens
        // each memfd through `/proc/self/fd/N` at offset 0 and moves it onto
        // `N` with `dup2`, and clears close-on-exec on each `O_PATH` bind
        // descriptor and any status or block pipe descriptor. Last, for
        // `own_netns`, it enters a new user and network namespace, mapping
        // only the caller's ids, with `unshare`, `prctl`, `open` and
        // `write`.
        unsafe {
            command.pre_exec(move || {
                if libc::close_range(
                    MIN_FD as libc::c_uint,
                    libc::c_uint::MAX,
                    libc::CLOSE_RANGE_CLOEXEC as libc::c_int,
                ) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                for (fd, path) in &mut reopen_fds {
                    let fresh = rustix::fs::open(
                        path.as_c_str(),
                        OFlags::RDONLY | OFlags::CLOEXEC,
                        Mode::empty(),
                    )?;
                    rustix::io::dup2(&fresh, fd)?;
                }
                for fd in &keep_fds {
                    fcntl_setfd(fd, FdFlags::empty())?;
                }
                if let Some((uid_map, gid_map)) = &netns_maps {
                    if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    // Dumpable only for the three writes, so no process of
                    // the user can read the server's memory, which this
                    // child still holds a copy of, any longer than that.
                    if undumpable && libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    // A process without CAP_SETGID in the parent namespace
                    // may map its gid only once `setgroups` is denied.
                    let written = write_proc(c"/proc/self/setgroups", b"deny")
                        .and_then(|()| write_proc(c"/proc/self/uid_map", uid_map.as_bytes()))
                        .and_then(|()| write_proc(c"/proc/self/gid_map", gid_map.as_bytes()));
                    if undumpable && libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    written?;
                }
                Ok(())
            });
        }
        command
    }
}

/// Writes `data` to the `/proc` file `path` in one `write`, as files such
/// as `uid_map` need. It allocates nothing, so it is async-signal-safe.
fn write_proc(path: &std::ffi::CStr, data: &[u8]) -> io::Result<()> {
    let fd = rustix::fs::open(path, OFlags::WRONLY | OFlags::CLOEXEC, Mode::empty())?;
    if rustix::io::write(&fd, data)? != data.len() {
        return Err(io::Error::from_raw_os_error(libc::EIO));
    }
    Ok(())
}

/// Creates a close-on-exec pipe with a non-blocking read end and a write end at
/// least [`MIN_FD`].
fn cloexec_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut raw = [0 as RawFd; 2];
    // SAFETY: `raw` points to two writable integers, and `O_CLOEXEC` sets
    // close-on-exec atomically on both ends.
    let rc = unsafe { libc::pipe2(raw.as_mut_ptr(), libc::O_CLOEXEC) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `pipe2` initialized both descriptors and transferred ownership.
    let read_fd = unsafe { OwnedFd::from_raw_fd(raw[0]) };
    let write_fd = unsafe { OwnedFd::from_raw_fd(raw[1]) };
    // Mark only `read_fd` non-blocking so `write_fd` stays blocking for bwrap,
    // while reading after `child.wait()` never blocks even if a child in a
    // shared PID namespace inherited `write_fd`.
    let flags = unsafe { libc::fcntl(read_fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(read_fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let write_fd = if write_fd.as_raw_fd() < MIN_FD {
        fcntl_dupfd_cloexec(&write_fd, MIN_FD).map_err(io::Error::from)?
    } else {
        write_fd
    };
    Ok((read_fd, write_fd))
}

/// Opens each untrusted host mount source with `openat2(O_PATH | O_CLOEXEC,
/// RESOLVE_NO_SYMLINKS)` relative to its canonical untrusted root.
fn open_bind_fds(binds: &[BindOpen]) -> Result<Vec<OwnedFd>, BwrapError> {
    let mut root_fds: BTreeMap<PathBuf, OwnedFd> = BTreeMap::new();
    let mut out = Vec::with_capacity(binds.len());
    for b in binds {
        let full = if b.rel.as_os_str().is_empty() {
            b.root.clone()
        } else {
            b.root.join(&b.rel)
        };
        let map_err = |err: Errno| {
            if err == Errno::LOOP {
                BwrapError::UntrustedSymlink {
                    sandbox: b.sandbox.clone(),
                    path: full.clone(),
                }
            } else {
                BwrapError::MountOpen {
                    sandbox: b.sandbox.clone(),
                    path: full.clone(),
                    error: io::Error::from(err),
                }
            }
        };
        let fd = if b.rel.as_os_str().is_empty() {
            openat2(
                CWD,
                &b.root,
                OFlags::PATH | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::NO_SYMLINKS,
            )
            .map_err(map_err)?
        } else {
            let root_fd = match root_fds.get(&b.root) {
                Some(fd) => fd,
                None => {
                    let fd = openat2(
                        CWD,
                        &b.root,
                        OFlags::PATH | OFlags::CLOEXEC | OFlags::DIRECTORY,
                        Mode::empty(),
                        ResolveFlags::NO_SYMLINKS,
                    )
                    .map_err(|err| {
                        if err == Errno::LOOP {
                            BwrapError::UntrustedSymlink {
                                sandbox: b.sandbox.clone(),
                                path: b.root.clone(),
                            }
                        } else {
                            BwrapError::MountOpen {
                                sandbox: b.sandbox.clone(),
                                path: b.root.clone(),
                                error: io::Error::from(err),
                            }
                        }
                    })?;
                    root_fds.entry(b.root.clone()).or_insert(fd)
                }
            };
            openat2(
                root_fd,
                &b.rel,
                OFlags::PATH | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::NO_SYMLINKS,
            )
            .map_err(map_err)?
        };
        let fd = if fd.as_raw_fd() < MIN_FD {
            fcntl_dupfd_cloexec(&fd, MIN_FD).map_err(|err| BwrapError::MountOpen {
                sandbox: b.sandbox.clone(),
                path: full,
                error: io::Error::from(err),
            })?
        } else {
            fd
        };
        out.push(fd);
    }
    Ok(out)
}

/// Creates a memfd holding `data`, positioned at its start and sealed
/// against any change, at a descriptor number of at least [`MIN_FD`], with
/// close-on-exec set.
fn sealed_memfd(name: &str, data: &[u8]) -> io::Result<OwnedFd> {
    let fd = memfd_create(name, MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING)?;
    let fd = if fd.as_raw_fd() < MIN_FD {
        fcntl_dupfd_cloexec(&fd, MIN_FD)?
    } else {
        fd
    };
    let mut file = File::from(fd);
    file.write_all(data)?;
    // bwrap reads from the current offset, shared with this descriptor.
    file.seek(SeekFrom::Start(0))?;
    fcntl_add_seals(
        &file,
        SealFlags::SEAL | SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE,
    )?;
    Ok(file.into())
}

/// The `--args` format: every argument followed by a NUL byte.
fn serialize_args(args: &[OsString]) -> Vec<u8> {
    let mut out = Vec::with_capacity(args.iter().map(|a| a.len() + 1).sum());
    for arg in args {
        out.extend_from_slice(arg.as_bytes());
        out.push(0);
    }
    out
}

// --- Generation --------------------------------------------------------------

/// One bwrap option argument.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Arg {
    /// Literal text.
    Text(OsString),
    /// The descriptor number of the `n`th data blob.
    Data(usize),
    /// The descriptor number of the `n`th `O_PATH` mount source.
    Bind(usize),
}

/// An untrusted host mount source to open with `openat2` and `RESOLVE_NO_SYMLINKS`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BindOpen {
    sandbox: PathBuf,
    root: PathBuf,
    rel: PathBuf,
}

/// The host paths of the provisioned pieces bound into the runtime
/// directory, and the argv prefix that runs the provisioned binary there.
#[derive(Debug, Clone)]
struct RuntimeBinds {
    exe: PathBuf,
    lib_dir: PathBuf,
    bin: PathBuf,
    prefix: Vec<OsString>,
    /// The network proxy's socket on the host, if the sandbox has one.
    proxy_socket: Option<PathBuf>,
    /// The broker's socket on the host, if the sandbox has shims.
    broker_socket: Option<PathBuf>,
    /// The shim trampoline on the host, if the sandbox has shims.
    shim: Option<PathBuf>,
}

/// What a run adds to a sandbox beyond its spec.
#[derive(Debug, Clone, Default)]
pub struct RunExtras {
    /// The network proxy's socket on the host, mounted at
    /// [`crate::proxy::SANDBOX_PROXY_SOCKET`].
    pub proxy_socket: Option<PathBuf>,
    /// The broker's socket on the host, mounted at
    /// [`crate::shim::SANDBOX_BROKER_SOCKET`].
    pub broker_socket: Option<PathBuf>,
    /// The profile's shim directory and the trampoline on the host,
    /// mounted at [`crate::shim::SANDBOX_BIN`] and
    /// [`crate::shim::SANDBOX_SHIM`].
    pub shims: Option<(PathBuf, PathBuf)>,
    /// The directory the target starts in, which `__init` opens itself
    /// ([`init::InitSpec::cwd`]).
    pub cwd: Option<init::StartDir>,
    /// Look the command up without the shim directory
    /// ([`init::InitSpec::skip_shims`]).
    pub skip_shims: bool,
}

/// The generated invocation, before any descriptor exists.
#[derive(Debug, Default)]
struct Plan {
    /// The options.
    args: Vec<Arg>,
    /// The content of each [`Arg::Data`].
    data: Vec<Vec<u8>>,
    /// The open specification of each [`Arg::Bind`].
    binds: Vec<BindOpen>,
    /// The command after `--`.
    command: Vec<OsString>,
}

impl Plan {
    /// Appends literal arguments.
    fn push<S: AsRef<OsStr>>(
        &mut self,
        args: impl IntoIterator<Item = S>,
    ) -> Result<(), BwrapError> {
        for arg in args {
            self.args.push(Arg::Text(checked(arg.as_ref())?));
        }
        Ok(())
    }

    /// Masks `dst` with an empty file nobody may open (§3.4).
    fn empty_file(&mut self, dst: &Path) -> Result<(), BwrapError> {
        self.data_file(MASKED_FILE_PERMS, Vec::new(), dst)
    }

    /// Mounts a read-only file holding `data`, with mode `perms`, at `dst`.
    fn data_file(&mut self, perms: &str, data: Vec<u8>, dst: &Path) -> Result<(), BwrapError> {
        self.push(["--perms", perms, "--ro-bind-data"])?;
        // Each needs its own descriptor: bwrap closes it after reading.
        self.args.push(Arg::Data(self.data.len()));
        self.data.push(data);
        self.push([dst])
    }
}

/// `arg`, unless it contains a NUL byte.
fn checked(arg: &OsStr) -> Result<OsString, BwrapError> {
    if arg.as_bytes().contains(&0) {
        return Err(BwrapError::Nul {
            arg: arg.to_os_string(),
        });
    }
    Ok(arg.to_os_string())
}

/// Generates the invocation for `spec`, whose user has the ids `ids` inside
/// the sandbox. `proc_has` tells whether a `/proc` path exists (on the
/// host, whose kernel the sandbox's procfs shows), and `ephemeral_dir`
/// provides the backing directory of an ephemeral mount at a sandbox path.
// The host-dependent inputs are parameters so that the unit tests can fake
// them; grouping them would only rename the list.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn plan(
    spec: &SandboxSpec,
    untrusted_roots: &BTreeSet<PathBuf>,
    runtime: &RuntimeBinds,
    ids: SandboxIds,
    cwd: &Path,
    argv_after_prefix: &[OsString],
    terminal: TerminalSession,
    proc_has: &dyn Fn(&Path) -> bool,
    host_meta: &dyn Fn(&Path) -> Option<io::Result<fs::Metadata>>,
    ephemeral_dir: &mut dyn FnMut(&Path, &EphemeralKey) -> Result<PathBuf, BwrapError>,
) -> Result<Plan, BwrapError> {
    plan_with_caps(
        spec,
        untrusted_roots,
        runtime,
        ids,
        cwd,
        argv_after_prefix,
        terminal,
        false,
        proc_has,
        host_meta,
        ephemeral_dir,
    )
}

#[allow(clippy::too_many_arguments)]
fn plan_with_caps(
    spec: &SandboxSpec,
    untrusted_roots: &BTreeSet<PathBuf>,
    runtime: &RuntimeBinds,
    ids: SandboxIds,
    cwd: &Path,
    argv_after_prefix: &[OsString],
    terminal: TerminalSession,
    retain_init_caps: bool,
    proc_has: &dyn Fn(&Path) -> bool,
    host_meta: &dyn Fn(&Path) -> Option<io::Result<fs::Metadata>>,
    ephemeral_dir: &mut dyn FnMut(&Path, &EphemeralKey) -> Result<PathBuf, BwrapError>,
) -> Result<Plan, BwrapError> {
    if !cwd.is_absolute() {
        return Err(BwrapError::RelativeCwd(cwd.to_path_buf()));
    }
    let mut plan = Plan::default();

    // Step 1: namespaces. Listed one by one rather than `--unshare-all`,
    // which only tries the user and cgroup namespaces and so does not
    // satisfy `--disable-userns`, and can share nothing but the network.
    // The mount namespace is always new.
    plan.push(["--unshare-user"])?;
    // With `full`, the network namespace is stopit's own, made before bwrap
    // runs ([`own_network_namespace`]), so bwrap makes none.
    let share_net =
        spec.namespaces.is_shared(ShareableNamespace::Net) || own_network_namespace(spec);
    // A new UTS namespace starts with the host's hostname, so stopit gives it
    // its own (`hosts` names it too); a shared one is the host's, as chosen.
    let hostname =
        (!spec.namespaces.is_shared(ShareableNamespace::Uts)).then_some(etc::SANDBOX_HOSTNAME);
    for (ns, flag) in [
        (ShareableNamespace::Ipc, "--unshare-ipc"),
        (ShareableNamespace::Pid, "--unshare-pid"),
        (ShareableNamespace::Net, "--unshare-net"),
        (ShareableNamespace::Uts, "--unshare-uts"),
        (ShareableNamespace::Cgroup, "--unshare-cgroup"),
    ] {
        let shared = match ns {
            ShareableNamespace::Net => share_net,
            _ => spec.namespaces.is_shared(ns),
        };
        if !shared {
            plan.push([flag])?;
        }
    }
    plan.push(["--disable-userns", "--die-with-parent"])?;
    if retain_init_caps {
        plan.push([
            "--cap-add",
            "CAP_SYS_ADMIN",
            "--cap-add",
            "CAP_NET_ADMIN",
            "--cap-add",
            "CAP_SETPCAP",
        ])?;
    }
    // On a PTY, `__init` starts the session (see `TerminalSession`).
    if terminal == TerminalSession::Detach {
        plan.push(["--new-session"])?;
    }
    // bwrap refuses `--hostname` without `--unshare-uts`.
    if let Some(hostname) = hostname {
        plan.push(["--hostname", hostname])?;
    }

    // Step 7: environment. bwrap then sets only `PWD`, which `__init`
    // discards; the target's environment reaches `__init` through its own
    // descriptor (`BwrapCommand::for_init`).
    plan.push(["--clearenv"])?;
    plan.push([OsStr::new("--chdir"), cwd.as_os_str()])?;

    // Step 3: system mounts.
    if spec.system.proc {
        plan.push(["--proc", "/proc"])?;
        // An optional mask the kernel does not provide has nothing to hide,
        // and bwrap could not create a mount point for it in procfs. Every
        // other one is applied regardless, failing closed (see
        // `PROC_OPTIONAL_MASKS`).
        let wanted =
            |p: &&Path| !PROC_OPTIONAL_MASKS.iter().any(|o| Path::new(o) == *p) || proc_has(p);
        for dir in PROC_MASKED_DIRS.map(Path::new).into_iter().filter(wanted) {
            plan.push([OsStr::new("--tmpfs"), dir.as_os_str()])?;
            plan.push([OsStr::new("--remount-ro"), dir.as_os_str()])?;
        }
        for file in PROC_MASKED_FILES.map(Path::new).into_iter().filter(wanted) {
            plan.empty_file(file)?;
        }
    }
    match spec.system.dev {
        Some(DevMode::Minimal) => plan.push(["--dev", "/dev"])?,
        None => {}
    }

    // Step 4: synthesized `/etc` files, before the filesystem mounts. No
    // mount may equal or contain one (§6.2, Reserved paths), so none can
    // hide them, and mounts elsewhere in `/etc` (`/etc/ssl/certs`) are
    // unaffected: bwrap creates `/etc` and the mount points in its root
    // tmpfs, in whichever order.
    for &file in &spec.system.etc {
        let data =
            etc::contents(file, ids, &spec.system.home, &spec.system.groups, hostname).into_bytes();
        plan.data_file(ETC_FILE_PERMS, data, &etc::sandbox_path(file))?;
    }
    // TODO(§6.2 step 4): the sandbox-`HOME` stubs (`.gitconfig`, …), which
    // the spec has no content for yet. They go after the filesystem
    // mounts, so that an ephemeral or granted `HOME` does not hide them.

    // Step 5: filesystem mounts, parents first. A masked directory is an
    // empty tmpfs made read-only only after every mount below it, since
    // bwrap creates their mount points in it.
    debug_assert!(
        parents_first(&spec.mounts),
        "the spec's mounts are not ordered parents first"
    );
    let mut ephemeral_backs: HashMap<&Path, PathBuf> = HashMap::new();
    for mount in &spec.mounts {
        if let (MountSource::Ephemeral { key }, PathMode::Ephemeral) = (&mount.source, mount.mode) {
            let backing = ephemeral_dir(&mount.sandbox, key)?;
            ephemeral_backs.insert(mount.sandbox.as_path(), backing);
        }
    }
    let mount_by_sandbox: HashMap<&Path, &PlannedMount> = spec
        .mounts
        .iter()
        .map(|m| (m.sandbox.as_path(), m))
        .collect();
    for mount in &spec.mounts {
        let anc = mount
            .sandbox
            .ancestors()
            .skip(1)
            .find_map(|a| mount_by_sandbox.get(a).copied());
        if let Some(anc) = anc
            && let Some(backing) = ephemeral_backs.get(anc.sandbox.as_path())
        {
            let rel = mount
                .sandbox
                .strip_prefix(&anc.sandbox)
                .expect("ancestor is a prefix");
            check_ephemeral_destination(&mount.sandbox, &anc.sandbox, backing, rel, host_meta)?;
        }
    }
    let mut pinned = collect_pinned_parents(
        spec,
        untrusted_roots,
        &mount_by_sandbox,
        &ephemeral_backs,
        host_meta,
    )?;
    let mut masked_dirs = Vec::new();
    for mount in &spec.mounts {
        let ancestors: Vec<&Path> = mount.sandbox.ancestors().skip(1).collect();
        for anc in ancestors.into_iter().rev() {
            if let Some((host_dir, mode)) = pinned.remove(anc) {
                let rw = mode == PathMode::Rw;
                push_host_bind(&mut plan, rw, &host_dir, &host_dir, anc, untrusted_roots)?;
            }
        }
        mount_args(
            &mut plan,
            spec,
            mount,
            untrusted_roots,
            &ephemeral_backs,
            &mut masked_dirs,
        )?;
    }
    // Remounting is not recursive, so the order does not matter; deepest
    // first.
    for dir in masked_dirs.iter().rev() {
        plan.push([OsStr::new("--remount-ro"), dir.as_os_str()])?;
    }

    // Step 6: the runtime directory, after every other mount so none can
    // hide it (the reserved paths forbid mounts there anyway). Only the
    // provisioned pieces: the session directory also holds `ephemeral/`
    // and, later, sockets.
    let base = Path::new(SANDBOX_RUNTIME_DIR);
    for (host, name) in [
        (&runtime.exe, "stopit"),
        (&runtime.lib_dir, "lib"),
        (&runtime.bin, "bin"),
    ] {
        plan.push([
            OsStr::new("--ro-bind"),
            host.as_os_str(),
            base.join(name).as_os_str(),
        ])?;
    }
    // A socket connects through a read-only mount too.
    for (host, sandbox) in [
        (&runtime.shim, crate::shim::SANDBOX_SHIM),
        (&runtime.broker_socket, crate::shim::SANDBOX_BROKER_SOCKET),
        (&runtime.proxy_socket, crate::proxy::SANDBOX_PROXY_SOCKET),
    ] {
        if let Some(host) = host {
            plan.push([
                OsStr::new("--ro-bind"),
                host.as_os_str(),
                OsStr::new(sandbox),
            ])?;
        }
    }

    // Step 2: bwrap leaves its root tmpfs writable, so the sandbox could
    // create anything next to the mounts (`/x`, `/run/y`, the intermediate
    // directories bwrap made for mount points). The very last option, once
    // every mount point exists. Not recursive: the mounts on top keep their
    // own mode.
    plan.push(["--remount-ro", "/"])?;

    // Step 8: the command.
    for arg in runtime.prefix.iter().chain(argv_after_prefix) {
        plan.command.push(checked(arg)?);
    }

    let count = plan.args.len() + ARGV_OVERHEAD + plan.command.len();
    if count > BWRAP_MAX_ARGS {
        let (provider, provider_mounts) = largest_provider(&spec.mounts);
        return Err(BwrapError::TooManyArgs {
            count,
            max: BWRAP_MAX_ARGS,
            mounts: spec.mounts.len(),
            provider,
            provider_mounts,
        });
    }
    Ok(plan)
}

/// Whether every mount in `mounts` comes after the mounts of its ancestors,
/// as [`SandboxSpec::mounts`] promises.
fn parents_first(mounts: &[PlannedMount]) -> bool {
    let at: HashMap<&Path, usize> = mounts
        .iter()
        .enumerate()
        .map(|(i, m)| (m.sandbox.as_path(), i))
        .collect();
    mounts.iter().enumerate().all(|(i, m)| {
        m.sandbox
            .ancestors()
            .skip(1)
            .all(|a| at.get(a).is_none_or(|&j| j < i))
    })
}

/// The provider contributing the most mounts, and how many.
fn largest_provider(mounts: &[PlannedMount]) -> (Option<ProviderName>, usize) {
    let mut counts: BTreeMap<&ProviderName, usize> = BTreeMap::new();
    for mount in mounts {
        *counts.entry(&mount.provider).or_default() += 1;
    }
    counts
        .into_iter()
        .max_by_key(|&(_, n)| n)
        .map_or((None, 0), |(p, n)| (Some(p.clone()), n))
}

/// Creates missing intermediate directories inside session `ephemeral/`
/// backing directories for mounts nested below an `ephemeral` mount, refusing
/// symlinks and non-directories via `openat2(RESOLVE_NO_SYMLINKS)` so every
/// intermediate parent exists on Run 1 and is self-bound into a mount point by
/// [`collect_pinned_parents`].
fn ensure_ephemeral_parents(spec: &SandboxSpec, session: &SessionDir) -> Result<(), BwrapError> {
    let mut ephemeral_backs: HashMap<&Path, PathBuf> = HashMap::new();
    for mount in &spec.mounts {
        if let (MountSource::Ephemeral { key }, PathMode::Ephemeral) = (&mount.source, mount.mode) {
            let backing = session
                .ephemeral_dir(key)
                .map_err(|error| BwrapError::Ephemeral {
                    sandbox: mount.sandbox.clone(),
                    error,
                })?;
            ephemeral_backs.insert(mount.sandbox.as_path(), backing);
        }
    }
    if ephemeral_backs.is_empty() {
        return Ok(());
    }
    let mount_by_sandbox: HashMap<&Path, &PlannedMount> = spec
        .mounts
        .iter()
        .map(|m| (m.sandbox.as_path(), m))
        .collect();
    for mount in &spec.mounts {
        let anc = mount
            .sandbox
            .ancestors()
            .skip(1)
            .find_map(|a| mount_by_sandbox.get(a).copied());
        let Some(anc) = anc else {
            continue;
        };
        let Some(backing) = ephemeral_backs.get(anc.sandbox.as_path()) else {
            continue;
        };
        let rel = mount
            .sandbox
            .strip_prefix(&anc.sandbox)
            .expect("ancestor is a prefix");
        let Some(parent_rel) = rel.parent() else {
            continue;
        };
        if parent_rel.as_os_str().is_empty() {
            continue;
        }
        let mut dir_fd = openat2(
            CWD,
            backing,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS,
        )
        .map_err(|err| {
            if err == Errno::LOOP {
                BwrapError::EphemeralDestinationLink {
                    sandbox: mount.sandbox.clone(),
                    ephemeral: anc.sandbox.clone(),
                    link: backing.clone(),
                }
            } else {
                BwrapError::EphemeralDestinationInspect {
                    sandbox: mount.sandbox.clone(),
                    ephemeral: anc.sandbox.clone(),
                    path: backing.clone(),
                    error: io::Error::from(err),
                }
            }
        })?;
        let mut cur = backing.clone();
        for comp in parent_rel.components() {
            cur.push(comp);
            let name = comp.as_os_str();
            match mkdirat(&dir_fd, name, Mode::from_raw_mode(0o755)) {
                Ok(()) | Err(Errno::EXIST) => {}
                Err(err) => {
                    return Err(BwrapError::EphemeralDestinationInspect {
                        sandbox: mount.sandbox.clone(),
                        ephemeral: anc.sandbox.clone(),
                        path: cur,
                        error: io::Error::from(err),
                    });
                }
            }
            dir_fd = openat2(
                &dir_fd,
                name,
                OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::NO_SYMLINKS | ResolveFlags::BENEATH,
            )
            .map_err(|err| {
                if err == Errno::LOOP {
                    BwrapError::EphemeralDestinationLink {
                        sandbox: mount.sandbox.clone(),
                        ephemeral: anc.sandbox.clone(),
                        link: cur.clone(),
                    }
                } else {
                    BwrapError::EphemeralDestinationInspect {
                        sandbox: mount.sandbox.clone(),
                        ephemeral: anc.sandbox.clone(),
                        path: cur.clone(),
                        error: io::Error::from(err),
                    }
                }
            })?;
        }
    }
    Ok(())
}

/// Refuses symlinks or uninspectable entries inside `backing` on the way to a
/// mount destination `dst` nested below an ephemeral mount `eph_sandbox`.
fn check_ephemeral_destination(
    dst: &Path,
    eph_sandbox: &Path,
    backing: &Path,
    rel: &Path,
    host_meta: &dyn Fn(&Path) -> Option<io::Result<fs::Metadata>>,
) -> Result<(), BwrapError> {
    let mut cur = backing.to_path_buf();
    let mut comps = rel.components().peekable();
    while let Some(c) = comps.next() {
        cur.push(c);
        let Some(res) = host_meta(&cur) else {
            break;
        };
        match res {
            Err(err) if crate::error::is_missing(err.kind()) => break,
            Err(error) => {
                return Err(BwrapError::EphemeralDestinationInspect {
                    sandbox: dst.to_path_buf(),
                    ephemeral: eph_sandbox.to_path_buf(),
                    path: cur,
                    error,
                });
            }
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(BwrapError::EphemeralDestinationLink {
                    sandbox: dst.to_path_buf(),
                    ephemeral: eph_sandbox.to_path_buf(),
                    link: cur,
                });
            }
            Ok(meta) => {
                if comps.peek().is_some() && !meta.is_dir() {
                    break;
                }
            }
        }
    }
    Ok(())
}

/// Collects existing intermediate directories strictly between an
/// untrusted-root (or `ephemeral`) mount and a descendant mount so `plan` can
/// self-bind each into a mount point before mounting its children.
fn collect_pinned_parents(
    spec: &SandboxSpec,
    untrusted_roots: &BTreeSet<PathBuf>,
    mount_by_sandbox: &HashMap<&Path, &PlannedMount>,
    ephemeral_backs: &HashMap<&Path, PathBuf>,
    host_meta: &dyn Fn(&Path) -> Option<io::Result<fs::Metadata>>,
) -> Result<BTreeMap<PathBuf, (PathBuf, PathMode)>, BwrapError> {
    let ancestor_untrusted_dir = |anc: &PlannedMount| -> Option<(PathBuf, PathMode)> {
        if anc.mode == PathMode::Ephemeral {
            let backing = ephemeral_backs.get(anc.sandbox.as_path())?;
            return Some((backing.clone(), PathMode::Rw));
        }
        if anc.mode == PathMode::Masked {
            return None;
        }
        let MountSource::Host {
            path,
            kind: EntryKind::Dir,
        } = &anc.source
        else {
            return None;
        };
        let anc_host = spec.canonical_sources.get(&anc.sandbox).unwrap_or(path);
        let in_root =
            anc.mode == PathMode::Rw || untrusted_roots.iter().any(|r| anc_host.starts_with(r));
        in_root.then(|| (anc_host.clone(), anc.mode))
    };

    let mut pinned: BTreeMap<PathBuf, (PathBuf, PathMode)> = BTreeMap::new();
    for mount in &spec.mounts {
        let Some(parent) = mount.sandbox.parent() else {
            continue;
        };
        let mut cur_sandbox = PathBuf::from("/");
        let mut active_anc: Option<(PathBuf, PathMode)> = mount_by_sandbox
            .get(Path::new("/"))
            .and_then(|m| ancestor_untrusted_dir(m));
        for c in parent.components().skip(1) {
            cur_sandbox.push(c);
            if let Some(m) = mount_by_sandbox.get(cur_sandbox.as_path()) {
                active_anc = ancestor_untrusted_dir(m);
                continue;
            }
            let Some((ref mut anc_host, anc_mode)) = active_anc else {
                continue;
            };
            anc_host.push(c);
            if pinned.contains_key(&cur_sandbox) {
                continue;
            }
            let Some(res) = host_meta(anc_host) else {
                active_anc = None;
                continue;
            };
            match res {
                Err(err) if crate::error::is_missing(err.kind()) => {
                    active_anc = None;
                }
                Err(error) => {
                    return Err(BwrapError::MountOpen {
                        sandbox: mount.sandbox.clone(),
                        path: anc_host.clone(),
                        error,
                    });
                }
                Ok(meta) if meta.file_type().is_symlink() => {
                    return Err(BwrapError::UntrustedSymlink {
                        sandbox: mount.sandbox.clone(),
                        path: anc_host.clone(),
                    });
                }
                Ok(meta) if meta.is_dir() => {
                    pinned.insert(cur_sandbox.clone(), (anc_host.clone(), anc_mode));
                }
                Ok(_) => {
                    active_anc = None;
                }
            }
        }
    }
    Ok(pinned)
}

/// Emits `--bind-fd` / `--ro-bind-fd` when `canonical_host` lies inside one of
/// `untrusted_roots`, or `--bind` / `--ro-bind` with `planned_host` otherwise.
fn push_host_bind(
    plan: &mut Plan,
    rw: bool,
    planned_host: &Path,
    canonical_host: &Path,
    dst: &Path,
    untrusted_roots: &BTreeSet<PathBuf>,
) -> Result<(), BwrapError> {
    let _ = checked(planned_host.as_os_str())?;
    let root = untrusted_roots
        .iter()
        .filter(|r| canonical_host.starts_with(r.as_path()))
        .max_by_key(|r| r.components().count());
    match root {
        Some(root) => {
            let rel = canonical_host
                .strip_prefix(root)
                .expect("containing root is a prefix");
            let flag = if rw { "--bind-fd" } else { "--ro-bind-fd" };
            plan.push([flag])?;
            let idx = plan.binds.len();
            plan.args.push(Arg::Bind(idx));
            plan.binds.push(BindOpen {
                sandbox: dst.to_path_buf(),
                root: root.clone(),
                rel: rel.to_path_buf(),
            });
            plan.push([dst])
        }
        None => {
            let flag = if rw { "--bind" } else { "--ro-bind" };
            plan.push([OsStr::new(flag), planned_host.as_os_str(), dst.as_os_str()])
        }
    }
}

/// Appends the arguments of one filesystem mount, recording a masked
/// directory in `masked_dirs` to be made read-only later.
fn mount_args(
    plan: &mut Plan,
    spec: &SandboxSpec,
    mount: &PlannedMount,
    untrusted_roots: &BTreeSet<PathBuf>,
    ephemeral_backs: &HashMap<&Path, PathBuf>,
    masked_dirs: &mut Vec<PathBuf>,
) -> Result<(), BwrapError> {
    let dst = mount.sandbox.as_path();
    let inconsistent = || BwrapError::Inconsistent {
        sandbox: dst.to_path_buf(),
        mode: mount.mode,
        shown: mount.source.clone(),
    };
    match (&mount.source, mount.mode) {
        (MountSource::Host { path, .. }, PathMode::Rw) => {
            let canonical = spec.canonical_sources.get(dst).unwrap_or(path);
            push_host_bind(plan, true, path, canonical, dst, untrusted_roots)
        }
        // TODO(Phase 4): `protected` is served by the FUSE shadow (§4); it
        // is read-only until then.
        (MountSource::Host { path, .. }, PathMode::Ro | PathMode::Protected) => {
            let canonical = spec.canonical_sources.get(dst).unwrap_or(path);
            push_host_bind(plan, false, path, canonical, dst, untrusted_roots)
        }
        (MountSource::Host { path, kind }, PathMode::Masked) => match kind {
            EntryKind::Dir => {
                plan.push([OsStr::new("--tmpfs"), dst.as_os_str()])?;
                masked_dirs.push(dst.to_path_buf());
                Ok(())
            }
            // A masked socket is an empty file too: with mode 0000,
            // connecting to it fails with `EACCES` (and with
            // `ECONNREFUSED` past that, since it is no socket). So is a FIFO
            // or a device node.
            EntryKind::File | EntryKind::Socket | EntryKind::Other => plan.empty_file(dst),
            EntryKind::Symlink => Err(BwrapError::MaskedSymlink {
                sandbox: dst.to_path_buf(),
                host: path.clone(),
            }),
        },
        (MountSource::Host { .. }, PathMode::Ephemeral) => Err(inconsistent()),
        (MountSource::Ephemeral { .. }, PathMode::Ephemeral) => {
            let backing = &ephemeral_backs[dst];
            push_host_bind(plan, true, backing, backing, dst, untrusted_roots)
        }
        (MountSource::Ephemeral { .. }, _) => Err(inconsistent()),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs::{self, Permissions};
    use std::io::Read;
    use std::os::fd::BorrowedFd;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use tempfile::TempDir;

    use super::*;
    use crate::manifest::EtcFile;
    use crate::policy::PathMode::{Ephemeral, Masked, Protected, Ro, Rw};

    // --- Building specs ---

    fn host(sandbox: &str, path: &str, kind: EntryKind, mode: PathMode) -> PlannedMount {
        PlannedMount {
            sandbox: sandbox.into(),
            source: MountSource::Host {
                path: path.into(),
                kind,
            },
            mode,
            provider: "p".parse().unwrap(),
            glob_link: false,
        }
    }

    fn eph(sandbox: &str, pattern: &str) -> PlannedMount {
        PlannedMount {
            sandbox: sandbox.into(),
            source: MountSource::Ephemeral { key: key(pattern) },
            mode: Ephemeral,
            provider: "p".parse().unwrap(),
            glob_link: false,
        }
    }

    fn key(pattern: &str) -> EphemeralKey {
        EphemeralKey::new(&pattern.parse().unwrap())
    }

    fn spec(mounts: Vec<PlannedMount>) -> SandboxSpec {
        SandboxSpec {
            mounts,
            ..SandboxSpec::default()
        }
    }

    // --- Golden argument lists (pure generation) ---

    /// The sandbox user's ids in the golden tests.
    const IDS: SandboxIds = SandboxIds {
        uid: 1000,
        gid: 100,
    };

    fn runtime() -> RuntimeBinds {
        RuntimeBinds {
            exe: "/s/stopit".into(),
            lib_dir: "/s/lib".into(),
            bin: "/s/bin".into(),
            prefix: vec!["/run/stopit/stopit".into()],
            proxy_socket: None,
            broker_socket: None,
            shim: None,
        }
    }

    /// The arguments of `spec`, with every data descriptor shown as
    /// `<data N>` and ephemeral backing directories under `/eph`.
    fn try_golden(
        spec: &SandboxSpec,
        proc_has: &dyn Fn(&Path) -> bool,
    ) -> Result<Plan, BwrapError> {
        try_golden_in(spec, TerminalSession::Keep, proc_has)
    }

    /// [`try_golden`] with `terminal` as the session choice.
    fn try_golden_in(
        spec: &SandboxSpec,
        terminal: TerminalSession,
        proc_has: &dyn Fn(&Path) -> bool,
    ) -> Result<Plan, BwrapError> {
        plan(
            spec,
            &spec.untrusted_roots,
            &runtime(),
            IDS,
            Path::new("/"),
            &["arg".into()],
            terminal,
            proc_has,
            &|_| None,
            &mut |_, key| Ok(Path::new("/eph").join(key.dir_name())),
        )
    }

    fn strings(plan: &Plan) -> Vec<String> {
        plan.args
            .iter()
            .map(|arg| match arg {
                Arg::Text(text) => text.to_str().unwrap().to_owned(),
                Arg::Data(n) => format!("<data {n}>"),
                Arg::Bind(n) => format!("<bind {n}>"),
            })
            .collect()
    }

    fn golden(spec: &SandboxSpec) -> Vec<String> {
        strings(&try_golden(spec, &|_| true).unwrap())
    }

    /// The namespace options of a spec that shares nothing: the hostname
    /// goes with the new UTS namespace.
    const NAMESPACES: [&str; 10] = [
        "--unshare-user",
        "--unshare-ipc",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-uts",
        "--unshare-cgroup",
        "--disable-userns",
        "--die-with-parent",
        "--hostname",
        "stopit",
    ];

    const ENV: [&str; 3] = ["--clearenv", "--chdir", "/"];

    const RUNTIME: [&str; 9] = [
        "--ro-bind",
        "/s/stopit",
        "/run/stopit/stopit",
        "--ro-bind",
        "/s/lib",
        "/run/stopit/lib",
        "--ro-bind",
        "/s/bin",
        "/run/stopit/bin",
    ];

    const ROOT_RO: [&str; 2] = ["--remount-ro", "/"];

    /// The full golden list around `middle` (the system and fs mounts).
    fn around(middle: &[&str]) -> Vec<String> {
        NAMESPACES
            .iter()
            .chain(&ENV)
            .chain(middle)
            .chain(&RUNTIME)
            .chain(&ROOT_RO)
            .map(|s| s.to_string())
            .collect()
    }

    #[test]
    fn empty_spec() {
        let plan = try_golden(&SandboxSpec::default(), &|_| true).unwrap();
        assert_eq!(strings(&plan), around(&[]));
        assert!(plan.data.is_empty());
        assert_eq!(plan.command, ["/run/stopit/stopit", "arg"]);
    }

    #[test]
    fn root_is_remounted_read_only_last() {
        let mut spec = spec(vec![
            host("/w", "/h/w", EntryKind::Dir, Rw),
            host("/w/m", "/h/m", EntryKind::Dir, Masked),
            eph("/tmp", "/tmp"),
        ]);
        spec.system.proc = true;
        spec.system.dev = Some(DevMode::Minimal);
        let args = golden(&spec);
        assert_eq!(args[args.len() - 2..], ROOT_RO);
        // Exactly once, for `/` only: no other remount of a mount that
        // must stay writable.
        let remounts: Vec<&str> = args
            .windows(2)
            .filter(|w| w[0] == "--remount-ro")
            .map(|w| w[1].as_str())
            .collect();
        assert_eq!(
            remounts,
            [
                "/proc/sys",
                "/proc/bus",
                "/proc/fs",
                "/proc/irq",
                "/w/m",
                "/"
            ]
        );
    }

    #[test]
    fn shared_namespaces_are_left_out() {
        let shared = |names: &[ShareableNamespace]| {
            let mut spec = SandboxSpec::default();
            spec.namespaces.shared = names.iter().copied().collect::<BTreeSet<_>>();
            // Each shared namespace takes its flag, and the UTS one the
            // hostname's two arguments too.
            let len = NAMESPACES.len() - names.len() - 2 * names.contains(&Uts) as usize;
            golden(&spec)[..len].to_vec()
        };
        use ShareableNamespace::*;
        assert_eq!(
            shared(&[Pid]),
            [
                "--unshare-user",
                "--unshare-ipc",
                "--unshare-net",
                "--unshare-uts",
                "--unshare-cgroup",
                "--disable-userns",
                "--die-with-parent",
                "--hostname",
                "stopit",
            ]
        );
        assert_eq!(
            shared(&[Ipc, Uts, Cgroup]),
            [
                "--unshare-user",
                "--unshare-pid",
                "--unshare-net",
                "--disable-userns",
                "--die-with-parent",
            ]
        );
        assert_eq!(
            shared(&[Net, Pid, Ipc, Uts, Cgroup]),
            ["--unshare-user", "--disable-userns", "--die-with-parent"]
        );
    }

    #[test]
    fn hostname_is_set_only_in_a_new_uts_namespace() {
        let mut spec = SandboxSpec::default();
        let args = golden(&spec);
        assert!(args.contains(&"--unshare-uts".to_owned()));
        let at = args.iter().position(|a| a == "--hostname").unwrap();
        assert_eq!(args[at + 1], "stopit");
        assert_eq!(args[at + 1], etc::SANDBOX_HOSTNAME);

        // A shared one is the host's, as the user chose: nothing to set, and
        // bwrap would refuse `--hostname` without `--unshare-uts`.
        spec.namespaces.shared = [ShareableNamespace::Uts].into_iter().collect();
        let args = golden(&spec);
        assert!(!args.contains(&"--unshare-uts".to_owned()));
        assert!(!args.contains(&"--hostname".to_owned()));
        assert!(!args.contains(&"stopit".to_owned()));
        // Sharing another namespace leaves it.
        spec.namespaces.shared = [ShareableNamespace::Ipc].into_iter().collect();
        assert!(golden(&spec).contains(&"--hostname".to_owned()));
    }

    #[test]
    fn hosts_names_the_hostname_only_when_it_is_set() {
        let hosts = |shared: &[ShareableNamespace]| {
            let mut spec = SandboxSpec::default();
            spec.system.etc = [EtcFile::Hosts].into_iter().collect();
            spec.namespaces.shared = shared.iter().copied().collect();
            let plan = try_golden(&spec, &|_| true).unwrap();
            String::from_utf8(plan.data[0].clone()).unwrap()
        };
        assert_eq!(
            hosts(&[]),
            "127.0.0.1\tlocalhost stopit\n::1\tlocalhost stopit\n"
        );
        assert_eq!(
            hosts(&[ShareableNamespace::Uts]),
            "127.0.0.1\tlocalhost\n::1\tlocalhost\n"
        );
    }

    #[test]
    fn full_network_gets_a_namespace_of_stopits_own() {
        // bwrap makes the namespace in every mode but `full`, whose
        // namespace stopit makes before bwrap runs, for pasta.
        for (network, unshared) in [
            (NetworkSpec::None, true),
            (NetworkSpec::Loopback, true),
            (
                NetworkSpec::Proxy {
                    allow_domains: BTreeSet::new(),
                },
                true,
            ),
            (NetworkSpec::Full, false),
        ] {
            let spec = SandboxSpec {
                network: network.clone(),
                ..SandboxSpec::default()
            };
            let args = golden(&spec);
            assert_eq!(
                args.contains(&"--unshare-net".to_string()),
                unshared,
                "{network:?}"
            );
            // The user namespace is always new, and userns creation off.
            assert!(args.contains(&"--unshare-user".to_string()));
            assert!(args.contains(&"--disable-userns".to_string()));
            assert_eq!(own_network_namespace(&spec), !unshared, "{network:?}");
        }
        // Sharing the host's network namespace wins over `full`.
        let mut spec = SandboxSpec {
            network: NetworkSpec::Full,
            ..SandboxSpec::default()
        };
        spec.namespaces.shared = [ShareableNamespace::Net].into_iter().collect();
        assert!(!own_network_namespace(&spec));
        assert!(!golden(&spec).contains(&"--unshare-net".to_string()));
    }

    #[test]
    fn a_command_needing_pasta_blocks_on_a_pipe_of_its_own() {
        let f = Fixture::new();
        let full = SandboxSpec {
            network: NetworkSpec::Full,
            ..spec(vec![])
        };
        for (spec, pasta) in [(spec(vec![]), false), (full, true)] {
            let cmd = f.command(&spec);
            assert_eq!(cmd.needs_pasta(), pasta);
            let (command, _status, block) = cmd.into_command_with_status().unwrap();
            let argv: Vec<String> = command
                .get_args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect();
            let at = argv.iter().position(|a| a == "--block-fd");
            assert_eq!(at.is_some(), pasta, "{argv:?}");
            assert_eq!(block.is_some(), pasta);
            if let (Some(at), Some(block)) = (at, block) {
                // The read end is above stdio, blocking, and the other end
                // of the returned pipe.
                let fd: RawFd = argv[at + 1].parse().unwrap();
                assert!(fd >= MIN_FD);
                // SAFETY: the command owns `fd` and outlives this borrow.
                let read = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
                let flags = rustix::fs::fcntl_getfl(read).unwrap();
                assert!(!flags.contains(OFlags::NONBLOCK));
                rustix::io::write(&block, b"x").unwrap();
                let mut buf = [0u8; 1];
                assert_eq!(rustix::io::read(read, &mut buf).unwrap(), 1);
                // `--block-fd` comes before `--args`.
                let args_at = argv.iter().position(|a| a == "--args").unwrap();
                assert!(at < args_at, "{argv:?}");
            }
        }
    }

    #[test]
    fn never_unshare_all_and_a_new_session_only_when_detached() {
        let mut spec = SandboxSpec::default();
        spec.system.proc = true;
        spec.system.dev = Some(DevMode::Minimal);
        let args = golden(&spec);
        assert!(!args.contains(&"--new-session".to_string()));
        assert!(!args.contains(&"--unshare-all".to_string()));
        assert!(!args.contains(&"--share-net".to_string()));

        // Detached, `--new-session` comes right after the other process
        // options, and nothing else changes.
        let detached = try_golden_in(&SandboxSpec::default(), TerminalSession::Detach, &|_| true);
        let mut expected = around(&[]);
        let at = expected
            .iter()
            .position(|a| a == "--die-with-parent")
            .unwrap();
        expected.insert(at + 1, "--new-session".into());
        assert_eq!(strings(&detached.unwrap()), expected);
    }

    #[test]
    fn proc_with_its_masks() {
        let mut spec = SandboxSpec::default();
        spec.system.proc = true;
        let plan = try_golden(&spec, &|_| true).unwrap();
        assert_eq!(
            strings(&plan),
            around(&[
                "--proc",
                "/proc",
                "--tmpfs",
                "/proc/sys",
                "--remount-ro",
                "/proc/sys",
                "--tmpfs",
                "/proc/bus",
                "--remount-ro",
                "/proc/bus",
                "--tmpfs",
                "/proc/fs",
                "--remount-ro",
                "/proc/fs",
                "--tmpfs",
                "/proc/irq",
                "--remount-ro",
                "/proc/irq",
                "--perms",
                "0000",
                "--ro-bind-data",
                "<data 0>",
                "/proc/kcore",
                "--perms",
                "0000",
                "--ro-bind-data",
                "<data 1>",
                "/proc/keys",
                "--perms",
                "0000",
                "--ro-bind-data",
                "<data 2>",
                "/proc/timer_list",
            ])
        );
        assert_eq!(plan.data, vec![Vec::<u8>::new(); 3]);
    }

    #[test]
    fn proc_masks_skip_what_the_kernel_lacks() {
        let mut spec = SandboxSpec::default();
        spec.system.proc = true;
        let missing = |p: &Path| p != Path::new("/proc/kcore") && p != Path::new("/proc/bus");
        let args = strings(&try_golden(&spec, &missing).unwrap());
        assert!(!args.iter().any(|a| a == "/proc/kcore" || a == "/proc/bus"));
        assert!(args.iter().any(|a| a == "/proc/keys"));
        assert!(args.iter().any(|a| a == "/proc/sys"));
    }

    #[test]
    fn required_proc_masks_fail_closed() {
        // A host `/proc` mounted with `subset=pid` shows none of them, but
        // the sandbox's own procfs does: the required masks stay.
        let mut spec = SandboxSpec::default();
        spec.system.proc = true;
        let args = strings(&try_golden(&spec, &|_| false).unwrap());
        assert_eq!(
            args[NAMESPACES.len() + ENV.len()..args.len() - RUNTIME.len() - ROOT_RO.len()],
            [
                "--proc",
                "/proc",
                "--tmpfs",
                "/proc/sys",
                "--remount-ro",
                "/proc/sys",
                "--tmpfs",
                "/proc/fs",
                "--remount-ro",
                "/proc/fs",
                "--tmpfs",
                "/proc/irq",
                "--remount-ro",
                "/proc/irq",
            ]
        );
    }

    #[test]
    fn dev_and_no_system_mounts() {
        let mut spec = SandboxSpec::default();
        spec.system.dev = Some(DevMode::Minimal);
        assert_eq!(golden(&spec), around(&["--dev", "/dev"]));
        // Neither: no /proc, no /dev.
        let args = golden(&SandboxSpec::default());
        assert!(!args.iter().any(|a| a == "/proc" || a == "/dev"));
    }

    #[test]
    fn proc_comes_before_dev_and_both_before_fs_mounts() {
        let mut spec = spec(vec![host("/opt", "/h/opt", EntryKind::Dir, Ro)]);
        spec.system.proc = true;
        spec.system.dev = Some(DevMode::Minimal);
        let args = golden(&spec);
        let at = |s: &str| args.iter().position(|a| a == s).unwrap();
        assert!(at("--proc") < at("--dev"));
        assert!(at("--dev") < at("/opt"));
    }

    #[test]
    fn etc_files_are_read_only_data_files() {
        let mut spec = SandboxSpec::default();
        spec.system.etc = EtcFile::ALL.into_iter().collect();
        spec.system.home = "/home/agent".parse().unwrap();
        let plan = try_golden(&spec, &|_| true).unwrap();
        assert_eq!(
            strings(&plan),
            around(&[
                "--perms",
                "0444",
                "--ro-bind-data",
                "<data 0>",
                "/etc/passwd",
                "--perms",
                "0444",
                "--ro-bind-data",
                "<data 1>",
                "/etc/group",
                "--perms",
                "0444",
                "--ro-bind-data",
                "<data 2>",
                "/etc/hosts",
                "--perms",
                "0444",
                "--ro-bind-data",
                "<data 3>",
                "/etc/nsswitch.conf",
                "--perms",
                "0444",
                "--ro-bind-data",
                "<data 4>",
                "/etc/resolv.conf",
            ])
        );
        let data: Vec<String> = plan
            .data
            .iter()
            .map(|d| String::from_utf8(d.clone()).unwrap())
            .collect();
        assert_eq!(
            data,
            [
                "user:x:1000:100::/home/agent:/bin/sh\n\
                 nobody:x:65534:65534::/nonexistent:/bin/false\n",
                "user:x:100:\nnogroup:x:65534:\n",
                etc::hosts(Some(etc::SANDBOX_HOSTNAME)).as_str(),
                etc::NSSWITCH_CONF,
                "nameserver 169.254.1.1\n",
            ]
        );
    }

    #[test]
    fn each_subset_of_etc_files_gives_exactly_those_files() {
        let home: crate::manifest::SandboxHome = "/home/user".parse().unwrap();
        for bits in 0..1u32 << EtcFile::ALL.len() {
            let wanted: BTreeSet<EtcFile> = EtcFile::ALL
                .into_iter()
                .enumerate()
                .filter(|(i, _)| bits & 1 << i != 0)
                .map(|(_, f)| f)
                .collect();
            let mut spec = SandboxSpec::default();
            spec.system.etc = wanted.clone();
            let plan = try_golden(&spec, &|_| true).unwrap();
            let args = strings(&plan);
            let mounted: Vec<(String, Vec<u8>)> = args
                .windows(5)
                .filter(|w| w[2] == "--ro-bind-data")
                .map(|w| {
                    assert_eq!(w[..2], ["--perms", ETC_FILE_PERMS]);
                    let n: usize = w[3]
                        .strip_prefix("<data ")
                        .and_then(|s| s.strip_suffix('>'))
                        .unwrap()
                        .parse()
                        .unwrap();
                    (w[4].clone(), plan.data[n].clone())
                })
                .collect();
            let expected: Vec<(String, Vec<u8>)> = wanted
                .iter()
                .map(|&f| {
                    (
                        etc::sandbox_path(f).to_str().unwrap().to_owned(),
                        etc::contents(
                            f,
                            IDS,
                            &home,
                            &Default::default(),
                            Some(etc::SANDBOX_HOSTNAME),
                        )
                        .into_bytes(),
                    )
                })
                .collect();
            assert_eq!(mounted, expected, "{wanted:?}");
            assert_eq!(plan.data.len(), wanted.len(), "{wanted:?}");
        }
    }

    #[test]
    fn etc_files_come_after_system_mounts_and_before_fs_mounts() {
        let mut spec = spec(vec![
            host("/etc/ssl/certs", "/h/certs", EntryKind::Dir, Ro),
            host("/w", "/h/w", EntryKind::Dir, Masked),
        ]);
        spec.system.proc = true;
        spec.system.dev = Some(DevMode::Minimal);
        spec.system.etc = [EtcFile::Hosts, EtcFile::Passwd].into_iter().collect();
        let args = golden(&spec);
        let at = |s: &str| args.iter().position(|a| a == s).unwrap();
        assert!(at("/dev") < at("/etc/passwd"));
        // In `EtcFile` order, whatever the configuration's.
        assert!(at("/etc/passwd") < at("/etc/hosts"));
        assert!(at("/etc/hosts") < at("/etc/ssl/certs"));
        assert!(at("/etc/hosts") < at("/w"));
        // The masked `/proc` files' data come first.
        let data = |dst: &str| args[at(dst) - 1].clone();
        assert_eq!(data("/proc/timer_list"), "<data 2>");
        assert_eq!(data("/etc/passwd"), "<data 3>");
        assert_eq!(data("/etc/hosts"), "<data 4>");
    }

    #[test]
    fn etc_files_use_the_given_ids() {
        let mut spec = SandboxSpec::default();
        spec.system.etc = [EtcFile::Passwd, EtcFile::Group].into_iter().collect();
        let ids = SandboxIds { uid: 4242, gid: 77 };
        let plan = plan(
            &spec,
            &spec.untrusted_roots,
            &runtime(),
            ids,
            Path::new("/"),
            &[],
            TerminalSession::Keep,
            &|_| true,
            &|_| None,
            &mut |_, _| unreachable!(),
        )
        .unwrap();
        assert!(plan.data[0].starts_with(b"user:x:4242:77::/home/user:/bin/sh\n"));
        assert!(plan.data[1].starts_with(b"user:x:77:\n"));
    }

    #[test]
    fn each_mode() {
        let spec = spec(vec![
            host("/rw", "/h/rw", EntryKind::Dir, Rw),
            host("/ro", "/h/ro", EntryKind::Dir, Ro),
            host("/prot", "/h/prot", EntryKind::File, Protected),
            host("/tmp", "/h/ignored", EntryKind::Dir, Masked),
            eph("/e", "/e"),
        ]);
        let eph_dir = format!("/eph/{}", key("/e").dir_name());
        assert_eq!(
            golden(&spec),
            around(&[
                "--bind",
                "/h/rw",
                "/rw",
                "--ro-bind",
                "/h/ro",
                "/ro",
                "--ro-bind",
                "/h/prot",
                "/prot",
                "--tmpfs",
                "/tmp",
                "--bind",
                &eph_dir,
                "/e",
                "--remount-ro",
                "/tmp",
            ])
        );
    }

    #[test]
    fn masked_file_versus_masked_dir() {
        let plan = try_golden(
            &spec(vec![
                host("/w/.env", "/h/.env", EntryKind::File, Masked),
                host("/w/.git", "/h/.git", EntryKind::Dir, Masked),
            ]),
            &|_| true,
        )
        .unwrap();
        assert_eq!(
            strings(&plan),
            around(&[
                "--perms",
                "0000",
                "--ro-bind-data",
                "<data 0>",
                "/w/.env",
                "--tmpfs",
                "/w/.git",
                "--remount-ro",
                "/w/.git",
            ])
        );
        // The mask shows nothing of the host: the source is not named.
        assert!(!strings(&plan).iter().any(|a| a.starts_with("/h/")));
        assert_eq!(plan.data, [Vec::<u8>::new()]);
    }

    #[test]
    fn masked_sockets_and_other_entries_are_empty_files() {
        for kind in [EntryKind::Socket, EntryKind::Other] {
            assert_eq!(
                golden(&spec(vec![host("/s", "/h/s", kind, Masked)])),
                around(&["--perms", "0000", "--ro-bind-data", "<data 0>", "/s"]),
                "{kind:?}"
            );
        }
    }

    #[test]
    fn masked_symlink_is_an_internal_error() {
        let mut m = host("/l", "/h/l", EntryKind::Symlink, Masked);
        m.glob_link = true;
        let err = try_golden(&spec(vec![m]), &|_| true).unwrap_err();
        assert!(matches!(err, BwrapError::MaskedSymlink { .. }), "{err}");
        assert!(err.to_string().contains("/h/l"), "{err}");
    }

    #[test]
    fn symlink_sources_of_other_modes_are_bound() {
        // bwrap follows the link when binding; the spec compiler has
        // checked where it leads.
        assert_eq!(
            golden(&spec(vec![host("/l", "/h/l", EntryKind::Symlink, Ro)])),
            around(&["--ro-bind", "/h/l", "/l"])
        );
    }

    #[test]
    fn mismatched_source_and_mode_is_an_internal_error() {
        let mut m = eph("/e", "/e");
        m.mode = Rw;
        let err = try_golden(&spec(vec![m]), &|_| true).unwrap_err();
        assert!(matches!(err, BwrapError::Inconsistent { .. }), "{err}");
        let err = try_golden(
            &spec(vec![host("/x", "/h/x", EntryKind::Dir, Ephemeral)]),
            &|_| true,
        )
        .unwrap_err();
        assert!(matches!(err, BwrapError::Inconsistent { .. }), "{err}");
    }

    #[test]
    fn masked_dirs_are_made_read_only_after_the_mounts_below_them() {
        // Parents first, as the spec orders them: a masked directory, a
        // grant and a masked directory inside it, and a deeper mount still.
        let spec = spec(vec![
            host("/w/secret", "/h/secret", EntryKind::Dir, Masked),
            host("/w/secret/ok", "/h/secret/ok", EntryKind::Dir, Rw),
            host("/w/secret/ok/hidden", "/h/x", EntryKind::Dir, Masked),
            host("/w/secret/ok/hidden/f", "/h/f", EntryKind::File, Ro),
        ]);
        assert_eq!(
            golden(&spec),
            around(&[
                "--tmpfs",
                "/w/secret",
                "--bind",
                "/h/secret/ok",
                "/w/secret/ok",
                "--tmpfs",
                "/w/secret/ok/hidden",
                "--ro-bind",
                "/h/f",
                "/w/secret/ok/hidden/f",
                "--remount-ro",
                "/w/secret/ok/hidden",
                "--remount-ro",
                "/w/secret",
            ])
        );
    }

    #[test]
    fn runtime_binds_come_last() {
        let mut spec = spec(vec![
            host("/a", "/h/a", EntryKind::Dir, Masked),
            host("/run/user", "/h/run", EntryKind::Dir, Ro),
        ]);
        spec.system.proc = true;
        spec.system.dev = Some(DevMode::Minimal);
        let args = golden(&spec);
        // Followed only by the root's remount.
        let end = args.len() - ROOT_RO.len();
        assert_eq!(args[end - RUNTIME.len()..end], RUNTIME);
        // Only the provisioned pieces, never the session directory itself.
        assert!(!args.iter().any(|a| a == "/s" || a == "/run/stopit"));
    }

    #[test]
    fn the_proxy_socket_is_mounted_read_only_after_the_runtime() {
        let mut runtime = runtime();
        runtime.proxy_socket = Some("/s/proxy-3.sock".into());
        let plan = plan(
            &SandboxSpec::default(),
            &BTreeSet::new(),
            &runtime,
            IDS,
            Path::new("/"),
            &[],
            TerminalSession::Keep,
            &|_| true,
            &|_| None,
            &mut |_, _| unreachable!(),
        )
        .unwrap();
        let args = strings(&plan);
        let end = args.len() - ROOT_RO.len();
        assert_eq!(
            args[end - 3..end],
            ["--ro-bind", "/s/proxy-3.sock", "/run/stopit/proxy.sock"]
        );
        assert_eq!(args[end - 3 - RUNTIME.len()..end - 3], RUNTIME);
    }

    #[test]
    fn chdir_is_the_given_directory() {
        let plan = plan(
            &SandboxSpec::default(),
            &BTreeSet::new(),
            &runtime(),
            IDS,
            Path::new("/workspace"),
            &[],
            TerminalSession::Keep,
            &|_| true,
            &|_| None,
            &mut |_, _| unreachable!(),
        )
        .unwrap();
        let args = strings(&plan);
        let at = args.iter().position(|a| a == "--chdir").unwrap();
        assert_eq!(args[at + 1], "/workspace");
    }

    #[test]
    fn relative_cwd_is_an_error() {
        let err = plan(
            &SandboxSpec::default(),
            &BTreeSet::new(),
            &runtime(),
            IDS,
            Path::new("workspace"),
            &[],
            TerminalSession::Keep,
            &|_| true,
            &|_| None,
            &mut |_, _| unreachable!(),
        )
        .unwrap_err();
        assert!(matches!(err, BwrapError::RelativeCwd(_)), "{err}");
    }

    #[test]
    fn working_dir_is_the_workspace_mount_if_mounted() {
        let ws = Path::new("/workspace");
        assert_eq!(working_dir(&SandboxSpec::default(), ws), Path::new("/"));
        let below = spec(vec![host("/workspace/sub", "/h", EntryKind::Dir, Rw)]);
        assert_eq!(working_dir(&below, ws), Path::new("/"));
        let mounted = spec(vec![host("/workspace", "/h", EntryKind::Dir, Rw)]);
        assert_eq!(working_dir(&mounted, ws), ws);
    }

    #[test]
    fn nul_bytes_are_rejected_everywhere() {
        let nul = OsString::from_vec(b"/a\0b".to_vec());
        let path = PathBuf::from(&nul);
        let nul_err = |r: Result<Plan, BwrapError>| match r {
            Err(BwrapError::Nul { arg }) => assert_eq!(arg, nul),
            other => panic!("expected a NUL error, got {other:?}"),
        };
        // In a source, a destination, the cwd and the command.
        let mut m = host("/x", "/h", EntryKind::Dir, Ro);
        m.source = MountSource::Host {
            path: path.clone(),
            kind: EntryKind::Dir,
        };
        nul_err(try_golden(&spec(vec![m]), &|_| true));
        let mut m = host("/x", "/h", EntryKind::File, Masked);
        m.sandbox = path.clone();
        nul_err(try_golden(&spec(vec![m]), &|_| true));
        let run = |cwd: &Path, argv: &[OsString]| {
            plan(
                &SandboxSpec::default(),
                &BTreeSet::new(),
                &runtime(),
                IDS,
                cwd,
                argv,
                TerminalSession::Keep,
                &|_| true,
                &|_| None,
                &mut |_, _| unreachable!(),
            )
        };
        nul_err(run(&path, &[]));
        nul_err(run(Path::new("/"), &["ok".into(), nul.clone()]));
        let mut rt = runtime();
        rt.exe = path.clone();
        nul_err(plan(
            &SandboxSpec::default(),
            &BTreeSet::new(),
            &rt,
            IDS,
            Path::new("/"),
            &[],
            TerminalSession::Keep,
            &|_| true,
            &|_| None,
            &mut |_, _| unreachable!(),
        ));
    }

    #[test]
    fn non_utf8_paths_are_passed_unchanged() {
        let odd = PathBuf::from(OsString::from_vec(b"/h/\xff\xfe".to_vec()));
        let mut m = host("/x", "/", EntryKind::Dir, Ro);
        m.source = MountSource::Host {
            path: odd.clone(),
            kind: EntryKind::Dir,
        };
        let plan = try_golden(&spec(vec![m]), &|_| true).unwrap();
        assert!(plan.args.contains(&Arg::Text(odd.into_os_string())));
    }

    // --- Materialized commands (descriptors and the session) ---

    /// A session in a private temporary runtime directory, with a fake
    /// provisioned binary in it.
    struct Fixture {
        session: SessionDir,
        provisioned: Provisioned,
        _runtime: TempDir,
    }

    impl Fixture {
        fn new() -> Self {
            let tmp = fs::canonicalize(std::env::temp_dir()).unwrap();
            let runtime = TempDir::new_in(tmp).unwrap();
            fs::set_permissions(runtime.path(), Permissions::from_mode(0o700)).unwrap();
            let session = SessionDir::create(Some(runtime.path().as_os_str())).unwrap();
            let root = session.root();
            let provisioned = Provisioned::for_tests(
                root.join("stopit"),
                Some(root.join("lib/ld.so")),
                root.join("lib"),
            );
            Fixture {
                session,
                provisioned,
                _runtime: runtime,
            }
        }

        fn command(&self, spec: &SandboxSpec) -> BwrapCommand {
            BwrapCommand::new(
                spec,
                &self.session,
                &self.provisioned,
                Path::new("/"),
                &["__init".into()],
                TerminalSession::Keep,
            )
            .unwrap()
        }
    }

    /// Reads all of `fd` from its current offset, through a duplicate (so
    /// `fd` stays open, but its offset moves to the end).
    fn read_fd(fd: RawFd) -> Vec<u8> {
        // SAFETY: the caller owns `fd`, which stays open during the call.
        let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
        let mut file = File::from(borrowed.try_clone_to_owned().unwrap());
        let mut out = Vec::new();
        file.read_to_end(&mut out).unwrap();
        out
    }

    #[test]
    fn args_round_trip_through_their_descriptor() {
        let f = Fixture::new();
        let mut spec = spec(vec![
            host("/ro", "/h/ro", EntryKind::Dir, Ro),
            host("/m", "/h/m", EntryKind::File, Masked),
        ]);
        spec.system.proc = true;
        let cmd = f.command(&spec);
        let bytes = read_fd(cmd.args_fd());
        assert_eq!(bytes.last(), Some(&0), "every argument is NUL-terminated");
        let parsed: Vec<OsString> = bytes[..bytes.len() - 1]
            .split(|&b| b == 0)
            .map(|a| OsStr::from_bytes(a).to_os_string())
            .collect();
        assert_eq!(parsed, cmd.args());
        assert_eq!(
            cmd.command(),
            [
                "/run/stopit/lib/ld.so",
                "--library-path",
                "/run/stopit/lib",
                "/run/stopit/stopit",
                "__init",
            ]
        );
        // Runtime binds name the session's provisioned pieces; only the
        // root's remount follows.
        let n = cmd.args().len() - 2;
        assert_eq!(cmd.args()[n..], ["--remount-ro", "/"]);
        let root = f.session.root();
        assert_eq!(
            cmd.args()[n - 9..n - 6],
            [
                OsString::from("--ro-bind"),
                root.join("stopit").into(),
                "/run/stopit/stopit".into(),
            ]
        );
        assert_eq!(cmd.args()[n - 5], root.join("lib").into_os_string());
        assert_eq!(cmd.args()[n - 2], root.join("bin").into_os_string());
    }

    #[test]
    fn data_descriptors_are_named_by_number_and_empty() {
        let f = Fixture::new();
        let cmd = f.command(&spec(vec![
            host("/a", "/h/a", EntryKind::File, Masked),
            host("/b", "/h/b", EntryKind::File, Masked),
        ]));
        let fds = cmd.inherited_fds();
        assert_eq!(fds[0], cmd.args_fd());
        assert_eq!(fds.len(), 3);
        // Distinct descriptors, none of them stdio.
        assert_eq!(fds.iter().collect::<BTreeSet<_>>().len(), 3);
        assert!(fds.iter().all(|&fd| fd >= MIN_FD));
        let named: Vec<RawFd> = cmd
            .args()
            .windows(2)
            .filter(|w| w[0] == "--ro-bind-data")
            .map(|w| w[1].to_str().unwrap().parse().unwrap())
            .collect();
        assert_eq!(named, fds[1..]);
        for &fd in &fds[1..] {
            assert_eq!(read_fd(fd), b"");
        }
    }

    #[test]
    fn etc_descriptors_hold_the_files_for_the_current_user() {
        let f = Fixture::new();
        let mut spec = SandboxSpec::default();
        spec.system.etc = [EtcFile::Passwd, EtcFile::NsswitchConf]
            .into_iter()
            .collect();
        let cmd = f.command(&spec);
        let named: Vec<(RawFd, &OsString)> = cmd
            .args()
            .windows(3)
            .filter(|w| w[0] == "--ro-bind-data")
            .map(|w| (w[1].to_str().unwrap().parse().unwrap(), &w[2]))
            .collect();
        let ids = SandboxIds::current();
        assert_eq!(named.len(), 2);
        assert_eq!(named[0].1, "/etc/passwd");
        assert_eq!(
            read_fd(named[0].0),
            etc::passwd(ids, &spec.system.home).into_bytes()
        );
        assert_eq!(named[1].1, "/etc/nsswitch.conf");
        assert_eq!(read_fd(named[1].0), etc::NSSWITCH_CONF.as_bytes());
    }

    #[test]
    fn descriptors_are_sealed_and_close_on_exec() {
        let f = Fixture::new();
        let cmd = f.command(&spec(vec![host("/a", "/h/a", EntryKind::File, Masked)]));
        for fd in cmd.inherited_fds() {
            // SAFETY: `cmd` owns `fd` and outlives the borrow.
            let fd = unsafe { BorrowedFd::borrow_raw(fd) };
            assert!(
                rustix::io::fcntl_getfd(fd)
                    .unwrap()
                    .contains(rustix::io::FdFlags::CLOEXEC)
            );
            let seals = rustix::fs::fcntl_get_seals(fd).unwrap();
            assert!(seals.contains(SealFlags::WRITE | SealFlags::GROW | SealFlags::SEAL));
            let mut file = File::from(fd.try_clone_to_owned().unwrap());
            assert!(file.write_all(b"x").is_err(), "sealed against writes");
        }
    }

    #[test]
    fn large_argument_lists_fit_in_the_descriptor() {
        let f = Fixture::new();
        let dir = "some-rather-long-directory-name/with-a-subdirectory";
        let mounts = (0..2900)
            .map(|i| {
                host(
                    &format!("/many/{dir}/f{i:05}"),
                    &format!("/host/{dir}/f{i:05}"),
                    EntryKind::File,
                    Ro,
                )
            })
            .collect();
        let cmd = f.command(&spec(mounts));
        let bytes = read_fd(cmd.args_fd());
        // Far beyond what a pipe holds without a reader.
        assert!(bytes.len() > 256 * 1024, "{}", bytes.len());
        assert_eq!(bytes, serialize_args(cmd.args()));
    }

    /// `n` read-only file mounts.
    fn ro_files(n: usize) -> Vec<PlannedMount> {
        (0..n)
            .map(|i| host(&format!("/m/{i}"), &format!("/h/{i}"), EntryKind::File, Ro))
            .collect()
    }

    #[test]
    fn argument_count_is_limited_to_what_bwrap_accepts() {
        // The empty spec's options, `--args FD --`, and the command.
        let base = around(&[]).len() + ARGV_OVERHEAD + 2;
        let fit = (BWRAP_MAX_ARGS - base) / 3;
        try_golden(&spec(ro_files(fit)), &|_| true).unwrap();

        // A masked file is 5 arguments (2 more than 3): with up to two of
        // them, the read-only files fill the limit to the last argument.
        let masks = [0, 2, 1][(BWRAP_MAX_ARGS - base) % 3];
        let mut exact = ro_files((BWRAP_MAX_ARGS - base - 5 * masks) / 3);
        for i in 0..masks {
            exact.push(host(&format!("/x{i}"), "/h/x", EntryKind::File, Masked));
        }
        let full = try_golden(&spec(exact.clone()), &|_| true).unwrap();
        assert_eq!(
            full.args.len() + ARGV_OVERHEAD + full.command.len(),
            BWRAP_MAX_ARGS
        );

        // One more argument, here in the command, is too many.
        let mut exact_spec = spec(exact);
        exact_spec.mounts[0].provider = "big".parse().unwrap();
        exact_spec.mounts[1].provider = "big".parse().unwrap();
        let err = plan(
            &exact_spec,
            &exact_spec.untrusted_roots,
            &runtime(),
            IDS,
            Path::new("/"),
            &["arg".into(), "more".into()],
            TerminalSession::Keep,
            &|_| true,
            &|_| None,
            &mut |_, _| unreachable!(),
        )
        .unwrap_err();
        let total = exact_spec.mounts.len();
        match &err {
            BwrapError::TooManyArgs {
                count,
                max,
                mounts,
                provider,
                provider_mounts,
            } => {
                assert_eq!((*count, *max), (BWRAP_MAX_ARGS + 1, BWRAP_MAX_ARGS));
                assert_eq!(*mounts, total);
                // `p` has all but two of them.
                assert_eq!(provider.as_ref().unwrap().to_string(), "p");
                assert_eq!(*provider_mounts, total - 2);
            }
            other => panic!("expected too many arguments, got {other}"),
        }
        let msg = err.to_string();
        assert!(
            msg.contains(&format!(
                "provider \"p\" contributes {} of the mounts",
                total - 2
            )),
            "{msg}"
        );
        assert!(msg.contains(&format!("its {total} mounts")), "{msg}");
    }

    #[test]
    fn largest_provider_of_no_mounts_is_none() {
        assert_eq!(largest_provider(&[]), (None, 0));
    }

    #[test]
    fn parents_first_order_is_recognized() {
        let parent = host("/a", "/h/a", EntryKind::Dir, Rw);
        let child = host("/a/b/c", "/h/c", EntryKind::Dir, Masked);
        let other = host("/b", "/h/b", EntryKind::Dir, Ro);
        assert!(parents_first(&[]));
        assert!(parents_first(&[
            parent.clone(),
            other.clone(),
            child.clone()
        ]));
        assert!(parents_first(&[child.clone(), other.clone()]));
        assert!(!parents_first(&[child, other, parent]));
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "parents first")]
    fn children_before_parents_are_a_bug() {
        let _ = try_golden(
            &spec(vec![
                host("/a/b", "/h/b", EntryKind::Dir, Ro),
                host("/a", "/h/a", EntryKind::Dir, Masked),
            ]),
            &|_| true,
        );
    }

    #[test]
    fn ephemeral_backing_is_created_and_shared_by_commands_of_a_session() {
        let f = Fixture::new();
        let spec = spec(vec![eph("/tmp", "/tmp"), eph("/home/user", "~")]);
        let first = f.command(&spec);
        let tmp = f.session.ephemeral().join(key("/tmp").dir_name());
        let home = f.session.ephemeral().join(key("~").dir_name());
        for dir in [&tmp, &home] {
            let meta = fs::symlink_metadata(dir).unwrap();
            assert!(meta.is_dir(), "{dir:?}");
            assert_eq!(meta.mode() & 0o7777, 0o700, "{dir:?}");
        }
        let bind = |cmd: &BwrapCommand, dst: &str| {
            let at = cmd.args().iter().position(|a| a == dst).unwrap();
            assert_eq!(cmd.args()[at - 2], "--bind-fd");
            let fd: RawFd = cmd.args()[at - 1].to_str().unwrap().parse().unwrap();
            fs::read_link(format!("/proc/self/fd/{fd}")).unwrap()
        };
        assert_eq!(bind(&first, "/tmp"), tmp);
        assert_eq!(bind(&first, "/home/user"), home);

        // A second command of the same session reuses the directory and
        // what is in it.
        fs::write(tmp.join("left"), b"by the first").unwrap();
        let second = f.command(&spec);
        assert_eq!(bind(&second, "/tmp"), tmp);
        assert_eq!(fs::read(tmp.join("left")).unwrap(), b"by the first");

        // Another session gets its own.
        let other = Fixture::new();
        let third = other.command(&spec);
        assert_ne!(bind(&third, "/tmp"), tmp);
        assert_eq!(fs::read_dir(bind(&third, "/tmp")).unwrap().count(), 0);
    }

    #[test]
    fn ephemeral_backing_that_is_a_link_is_refused() {
        let f = Fixture::new();
        let outside = TempDir::new().unwrap();
        std::os::unix::fs::symlink(
            outside.path(),
            f.session.ephemeral().join(key("/tmp").dir_name()),
        )
        .unwrap();
        let err = BwrapCommand::new(
            &spec(vec![eph("/tmp", "/tmp")]),
            &f.session,
            &f.provisioned,
            Path::new("/"),
            &[],
            TerminalSession::Keep,
        )
        .unwrap_err();
        match &err {
            BwrapError::Ephemeral { sandbox, error } => {
                assert_eq!(sandbox, Path::new("/tmp"));
                assert!(
                    matches!(error, SessionError::NotDirectory { .. }),
                    "{error}"
                );
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn into_command_runs_bwrap_with_args_fd() {
        let f = Fixture::new();
        let cmd = f.command(&SandboxSpec::default());
        let fd = cmd.args_fd().to_string();
        let expected: Vec<OsString> = ["--args", &fd, "--"]
            .into_iter()
            .map(OsString::from)
            .chain(cmd.command().iter().cloned())
            .collect();
        let command = cmd.into_command();
        assert_eq!(command.get_program(), BWRAP);
        assert_eq!(command.get_args().collect::<Vec<_>>(), expected);
    }

    // --- `__init` ---

    fn vars(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        pairs.iter().map(|&(k, v)| (k.into(), v.into())).collect()
    }

    fn init_command(
        f: &Fixture,
        env: &[(OsString, OsString)],
        target: &[&str],
    ) -> Result<BwrapCommand, BwrapError> {
        let target: Vec<OsString> = target.iter().map(OsString::from).collect();
        BwrapCommand::for_init(
            &spec(vec![host("/a", "/h/a", EntryKind::File, Masked)]),
            &f.session,
            &f.provisioned,
            Path::new("/"),
            env,
            &target,
            TerminalSession::Keep,
        )
    }

    #[test]
    fn for_init_runs_init_with_env_and_spec_fds_on_its_argv() {
        let f = Fixture::new();
        let env = vars(&[("PATH", "/bin"), ("A", "x=y z")]);
        let sb = spec(vec![host("/a", "/h/a", EntryKind::File, Masked)]);
        let cmd = init_command(&f, &env, &["sh", "--", "-c"]).unwrap();
        let env_fd = cmd.env_fd().expect("an environment descriptor");
        let spec_fd = cmd.spec_fd().expect("a spec descriptor");
        assert_ne!(env_fd, spec_fd);
        assert_eq!(
            cmd.command(),
            [
                "/run/stopit/lib/ld.so",
                "--library-path",
                "/run/stopit/lib",
                "/run/stopit/stopit",
                "__init",
                "--env-fd",
                &env_fd.to_string(),
                "--spec-fd",
                &spec_fd.to_string(),
                "--",
                "sh",
                "--",
                "-c",
            ]
        );
        // Inherited last, after the `--args` and data descriptors, all
        // distinct.
        let fds = cmd.inherited_fds();
        assert_eq!(fds.len(), 4);
        assert_eq!(&fds[fds.len() - 2..], &[env_fd, spec_fd]);
        assert_eq!(fds.iter().collect::<BTreeSet<_>>().len(), 4);
        assert!(env_fd >= MIN_FD);
        assert!(spec_fd >= MIN_FD);
        // bwrap does not read either init descriptor.
        for init_fd in [env_fd, spec_fd] {
            let number = OsString::from(init_fd.to_string());
            assert!(!cmd.args().contains(&number));
        }
        // `network = "none"` with unshared `net` retains CAP_SYS_ADMIN,
        // CAP_NET_ADMIN, and CAP_SETPCAP for `__init` to create an inner netns
        // with `lo` down and clear its bounding set.
        assert!(cmd.args().windows(6).any(|w| {
            w == [
                OsStr::new("--cap-add"),
                OsStr::new("CAP_SYS_ADMIN"),
                OsStr::new("--cap-add"),
                OsStr::new("CAP_NET_ADMIN"),
                OsStr::new("--cap-add"),
                OsStr::new("CAP_SETPCAP"),
            ]
        }));

        assert_eq!(read_fd(env_fd), b"PATH=/bin\0A=x=y z\0");
        assert_eq!(
            init::decode_spec(&read_fd(spec_fd)).unwrap(),
            init::InitSpec::from_sandbox_spec(&sb)
        );
        for init_fd in [env_fd, spec_fd] {
            // SAFETY: `cmd` owns both descriptors and outlives the borrow.
            let borrowed = unsafe { BorrowedFd::borrow_raw(init_fd) };
            assert!(
                rustix::io::fcntl_getfd(borrowed)
                    .unwrap()
                    .contains(rustix::io::FdFlags::CLOEXEC)
            );
            let seals = rustix::fs::fcntl_get_seals(borrowed).unwrap();
            assert!(seals.contains(SealFlags::WRITE | SealFlags::GROW | SealFlags::SEAL));
        }

        // And it reaches the child with the others.
        let command = cmd.into_command();
        assert_eq!(
            command.get_args().nth(3),
            Some(OsStr::new("/run/stopit/lib/ld.so"))
        );
    }

    #[test]
    fn for_init_adds_caps_only_when_lo_down_is_needed() {
        let f = Fixture::new();
        let target = [OsString::from("/bin/true")];

        let mut loopback = SandboxSpec {
            network: NetworkSpec::Loopback,
            ..SandboxSpec::default()
        };
        let cmd_loopback = BwrapCommand::for_init(
            &loopback,
            &f.session,
            &f.provisioned,
            Path::new("/"),
            &[],
            &target,
            TerminalSession::Keep,
        )
        .unwrap();
        assert!(!cmd_loopback.args().contains(&OsString::from("--cap-add")));

        loopback.network = NetworkSpec::None;
        loopback.namespaces.shared.insert(ShareableNamespace::Net);
        let cmd_shared_net = BwrapCommand::for_init(
            &loopback,
            &f.session,
            &f.provisioned,
            Path::new("/"),
            &[],
            &target,
            TerminalSession::Keep,
        )
        .unwrap();
        assert!(!cmd_shared_net.args().contains(&OsString::from("--cap-add")));
    }

    #[test]
    fn a_pty_session_is_started_by_init_and_detaches_other_commands() {
        let f = Fixture::new();
        let target = [OsString::from("/bin/true")];
        let new_session = OsString::from("--new-session");
        let pty_slave = |cmd: &BwrapCommand| {
            init::decode_spec(&read_fd(cmd.spec_fd().unwrap()))
                .unwrap()
                .pty_slave
        };
        for (terminal, with_new_session, slave) in [
            (TerminalSession::Keep, false, false),
            (TerminalSession::Detach, true, false),
            (TerminalSession::Pty, false, true),
        ] {
            let cmd = BwrapCommand::for_init(
                &SandboxSpec::default(),
                &f.session,
                &f.provisioned,
                Path::new("/"),
                &[],
                &target,
                terminal,
            )
            .unwrap();
            assert_eq!(
                cmd.args().contains(&new_session),
                with_new_session,
                "{terminal:?}"
            );
            assert_eq!(pty_slave(&cmd), slave, "{terminal:?}");
        }
        // Without `__init` to start the session, a PTY session detaches.
        let cmd = BwrapCommand::new(
            &SandboxSpec::default(),
            &f.session,
            &f.provisioned,
            Path::new("/"),
            &target,
            TerminalSession::Pty,
        )
        .unwrap();
        assert!(cmd.args().contains(&new_session));
    }

    #[test]
    fn for_init_with_an_empty_environment() {
        let f = Fixture::new();
        let cmd = init_command(&f, &[], &["/bin/true"]).unwrap();
        assert_eq!(read_fd(cmd.env_fd().unwrap()), b"");
    }

    #[test]
    fn new_has_no_init_fds_or_caps() {
        let f = Fixture::new();
        let cmd = f.command(&SandboxSpec::default());
        assert_eq!(cmd.env_fd(), None);
        assert_eq!(cmd.spec_fd(), None);
        assert_eq!(cmd.inherited_fds(), [cmd.args_fd()]);
        assert!(!cmd.args().contains(&OsString::from("--cap-add")));
    }

    #[test]
    fn for_init_refuses_an_invalid_environment_or_no_command() {
        let f = Fixture::new();
        for (env, expected) in [
            (vars(&[("", "x")]), EnvError::EmptyKey),
            (vars(&[("A=B", "x")]), EnvError::KeyHasEquals("A=B".into())),
            (
                vars(&[("A", "1"), ("A", "2")]),
                EnvError::Duplicate("A".into()),
            ),
            (
                vec![("A".into(), OsString::from_vec(b"x\0y".to_vec()))],
                EnvError::Nul("A".into()),
            ),
        ] {
            match init_command(&f, &env, &["cmd"]) {
                Err(BwrapError::Env(e)) => assert_eq!(e, expected),
                other => panic!("expected an environment error, got {other:?}"),
            }
        }
        assert!(matches!(
            init_command(&f, &[], &[]),
            Err(BwrapError::NoCommand)
        ));
    }

    #[test]
    fn ephemeral_destination_refuses_symlinks_and_uninspectable_entries() {
        let f = Fixture::new();
        let mut s = spec(vec![
            eph("/tmp", "/tmp"),
            host("/tmp/sub/leaf", "/etc/hosts", EntryKind::File, Ro),
        ]);
        s.untrusted_roots.insert(f.session.ephemeral());

        // Missing intermediate components inside the ephemeral backing are
        // created and self-bound on Run 1.
        let first = BwrapCommand::new(
            &s,
            &f.session,
            &f.provisioned,
            Path::new("/"),
            &[],
            TerminalSession::Keep,
        )
        .unwrap();
        let first_args: Vec<&str> = first.args().iter().filter_map(|a| a.to_str()).collect();
        let pos_tmp = first_args.iter().position(|&a| a == "/tmp").unwrap();
        let pos_sub = first_args.iter().position(|&a| a == "/tmp/sub").unwrap();
        let pos_leaf = first_args
            .iter()
            .position(|&a| a == "/tmp/sub/leaf")
            .unwrap();
        assert!(pos_tmp < pos_sub && pos_sub < pos_leaf, "{first_args:?}");
        assert_eq!(first_args[pos_sub - 2], "--bind-fd", "{first_args:?}");

        let backing = f.session.ephemeral().join(key("/tmp").dir_name());
        assert!(backing.join("sub").is_dir());
        fs::remove_dir(backing.join("sub")).unwrap();
        std::os::unix::fs::symlink("/etc", backing.join("sub")).unwrap();
        let err = BwrapCommand::new(
            &s,
            &f.session,
            &f.provisioned,
            Path::new("/"),
            &[],
            TerminalSession::Keep,
        )
        .unwrap_err();
        match err {
            BwrapError::EphemeralDestinationLink {
                sandbox,
                ephemeral,
                link,
            } => {
                assert_eq!(sandbox, Path::new("/tmp/sub/leaf"));
                assert_eq!(ephemeral, Path::new("/tmp"));
                assert_eq!(link, backing.join("sub"));
            }
            other => panic!("expected EphemeralDestinationLink, got {other:?}"),
        }

        // A symlink at the leaf component itself is refused too.
        fs::remove_file(backing.join("sub")).unwrap();
        fs::create_dir(backing.join("sub")).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", backing.join("sub/leaf")).unwrap();
        let err = BwrapCommand::new(
            &s,
            &f.session,
            &f.provisioned,
            Path::new("/"),
            &[],
            TerminalSession::Keep,
        )
        .unwrap_err();
        assert!(
            matches!(err, BwrapError::EphemeralDestinationLink { .. }),
            "{err:?}"
        );

        // An unsearchable parent directory inside the ephemeral backing fails closed.
        fs::remove_file(backing.join("sub/leaf")).unwrap();
        fs::set_permissions(backing.join("sub"), fs::Permissions::from_mode(0o000)).unwrap();
        let err = BwrapCommand::new(
            &s,
            &f.session,
            &f.provisioned,
            Path::new("/"),
            &[],
            TerminalSession::Keep,
        )
        .unwrap_err();
        fs::set_permissions(backing.join("sub"), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            matches!(err, BwrapError::EphemeralDestinationInspect { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn pinned_parents_self_bind_intermediate_directories_once_parents_first() {
        let dir = TempDir::new().unwrap();
        let ws = dir.path().canonicalize().unwrap().join("ws");
        fs::create_dir_all(ws.join("a/b")).unwrap();
        fs::create_dir_all(ws.join("a/c")).unwrap();
        fs::write(ws.join("a/b/.env"), "secret").unwrap();
        fs::write(ws.join("a/b/flake.nix"), "{}").unwrap();
        fs::write(ws.join("a/c/ro.txt"), "ro").unwrap();

        let mut s = spec(vec![
            host("/nix/store/pkg", "/nix/store/pkg", EntryKind::Dir, Ro),
            host("/workspace", ws.to_str().unwrap(), EntryKind::Dir, Rw),
            host(
                "/workspace/a/b/.env",
                ws.join("a/b/.env").to_str().unwrap(),
                EntryKind::File,
                Masked,
            ),
            host(
                "/workspace/a/b/flake.nix",
                ws.join("a/b/flake.nix").to_str().unwrap(),
                EntryKind::File,
                Protected,
            ),
            host(
                "/workspace/a/c/ro.txt",
                ws.join("a/c/ro.txt").to_str().unwrap(),
                EntryKind::File,
                Ro,
            ),
            eph(
                "/workspace/missing_parent/scratch",
                "{workspace}/missing_parent/scratch",
            ),
        ]);
        s.untrusted_roots.insert(ws.clone());
        let eph_back = dir.path().canonicalize().unwrap().join("eph");
        fs::create_dir_all(&eph_back).unwrap();
        s.untrusted_roots.insert(eph_back.clone());

        let planned = plan(
            &s,
            &s.untrusted_roots,
            &runtime(),
            IDS,
            Path::new("/workspace"),
            &["arg".into()],
            TerminalSession::Keep,
            &|_| true,
            &|p| Some(fs::symlink_metadata(p)),
            &mut |_, key| Ok(eph_back.join(key.dir_name())),
        )
        .unwrap();

        let rendered = strings(&planned);
        // Outside untrusted roots, `--ro-bind` uses path strings without pinning `/nix`.
        assert!(
            rendered
                .windows(3)
                .any(|w| w == ["--ro-bind", "/nix/store/pkg", "/nix/store/pkg"]),
            "{rendered:?}"
        );
        assert!(
            !rendered.iter().any(|a| a == "/nix" || a == "/nix/store"),
            "{rendered:?}"
        );
        // Missing intermediate directory `/workspace/missing_parent` is not pinned.
        assert!(
            !rendered.iter().any(|a| a == "/workspace/missing_parent"),
            "{rendered:?}"
        );

        let pos = |dst: &str| {
            rendered
                .iter()
                .position(|a| a == dst)
                .unwrap_or_else(|| panic!("missing {dst} in {rendered:?}"))
        };
        let count_dst = |dst: &str| rendered.iter().filter(|a| a.as_str() == dst).count();
        assert_eq!(count_dst("/workspace/a"), 1, "{rendered:?}");
        assert_eq!(count_dst("/workspace/a/b"), 1, "{rendered:?}");
        assert_eq!(count_dst("/workspace/a/c"), 1, "{rendered:?}");
        assert!(pos("/workspace") < pos("/workspace/a"));
        assert!(pos("/workspace/a") < pos("/workspace/a/b"));
        assert!(pos("/workspace/a/b") < pos("/workspace/a/b/.env"));
        assert!(pos("/workspace/a/b") < pos("/workspace/a/b/flake.nix"));
        assert!(pos("/workspace/a") < pos("/workspace/a/c"));
        assert!(pos("/workspace/a/c") < pos("/workspace/a/c/ro.txt"));

        // Swapping the shallow ancestor `ws/a` for a symlink stops before
        // descending into `ws/a/b` and names `ws/a` immediately.
        let symlink_target = dir.path().canonicalize().unwrap().join("decoy");
        fs::create_dir_all(symlink_target.join("b")).unwrap();
        fs::remove_dir_all(ws.join("a")).unwrap();
        std::os::unix::fs::symlink(&symlink_target, ws.join("a")).unwrap();
        let inspected = std::cell::RefCell::new(Vec::new());
        let err = plan(
            &s,
            &s.untrusted_roots,
            &runtime(),
            IDS,
            Path::new("/workspace"),
            &["arg".into()],
            TerminalSession::Keep,
            &|_| true,
            &|p| {
                inspected.borrow_mut().push(p.to_path_buf());
                Some(fs::symlink_metadata(p))
            },
            &mut |_, key| Ok(eph_back.join(key.dir_name())),
        )
        .unwrap_err();
        assert!(
            matches!(&err, BwrapError::UntrustedSymlink { path, .. } if path == &ws.join("a")),
            "{err:?}"
        );
        assert!(
            !inspected.borrow().contains(&ws.join("a/b")),
            "must not traverse through symlinked parent: {:?}",
            inspected.borrow()
        );
    }

    #[test]
    fn open_bind_fds_rejects_symlinks_inside_untrusted_roots() {
        let f = Fixture::new();
        let dir = TempDir::new().unwrap();
        let ws = dir.path().canonicalize().unwrap().join("ws");
        fs::create_dir_all(ws.join("sub")).unwrap();
        fs::write(ws.join("sub/file"), "ok").unwrap();

        let mut s = spec(vec![
            host("/workspace", ws.to_str().unwrap(), EntryKind::Dir, Rw),
            host(
                "/workspace/sub/file",
                ws.join("sub/file").to_str().unwrap(),
                EntryKind::File,
                Ro,
            ),
        ]);
        s.untrusted_roots.insert(ws.clone());

        assert!(
            BwrapCommand::new(
                &s,
                &f.session,
                &f.provisioned,
                Path::new("/workspace"),
                &[],
                TerminalSession::Keep,
            )
            .is_ok()
        );

        // Swap the leaf file for a symlink before `BwrapCommand::new`.
        fs::remove_file(ws.join("sub/file")).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", ws.join("sub/file")).unwrap();
        let err = BwrapCommand::new(
            &s,
            &f.session,
            &f.provisioned,
            Path::new("/workspace"),
            &[],
            TerminalSession::Keep,
        )
        .unwrap_err();
        assert!(
            matches!(err, BwrapError::UntrustedSymlink { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn into_command_with_status_passes_json_status_fd_and_checks_arg_limit() {
        let f = Fixture::new();
        let cmd = f.command(&SandboxSpec::default());
        let base = cmd.args().len() + ARGV_OVERHEAD + cmd.command().len();
        let args_fd = cmd.args_fd().to_string();
        let (command, _status_reader, _block) = cmd.into_command_with_status().unwrap();
        let argv: Vec<String> = command
            .get_args()
            .map(|a| a.to_str().unwrap().to_owned())
            .collect();
        assert_eq!(argv[0], "--json-status-fd");
        let status_fd: RawFd = argv[1].parse().unwrap();
        assert!(status_fd >= MIN_FD);
        assert_eq!(argv[2], "--args");
        assert_eq!(argv[3], args_fd);
        assert_eq!(argv[4], "--");

        let spec_with_total_args = |target_total: usize| {
            let rem = target_total - base;
            let masks = [0, 2, 1][rem % 3];
            let mut mounts = ro_files((rem - 5 * masks) / 3);
            for i in 0..masks {
                mounts.push(host(&format!("/x{i}"), "/h/x", EntryKind::File, Masked));
            }
            spec(mounts)
        };

        // Right at `BWRAP_MAX_ARGS - STATUS_ARGV_OVERHEAD`, adding `--json-status-fd FD`
        // reaches `BWRAP_MAX_ARGS` and succeeds.
        let fits = f.command(&spec_with_total_args(BWRAP_MAX_ARGS - STATUS_ARGV_OVERHEAD));
        assert_eq!(
            fits.args().len() + ARGV_OVERHEAD + fits.command().len(),
            BWRAP_MAX_ARGS - STATUS_ARGV_OVERHEAD
        );
        assert!(fits.into_command_with_status().is_ok());

        // At `BWRAP_MAX_ARGS - 1` and `BWRAP_MAX_ARGS`, `BwrapCommand::new` succeeds,
        // and `into_command_with_status` rejects the extra two status arguments.
        for total in [BWRAP_MAX_ARGS - 1, BWRAP_MAX_ARGS] {
            let near_full = f.command(&spec_with_total_args(total));
            assert_eq!(
                near_full.args().len() + ARGV_OVERHEAD + near_full.command().len(),
                total
            );
            let err = near_full.into_command_with_status().unwrap_err();
            assert!(
                matches!(
                    err,
                    BwrapError::TooManyArgs { count, max, .. }
                        if count == total + STATUS_ARGV_OVERHEAD && max == BWRAP_MAX_ARGS
                ),
                "{err:?}"
            );
        }
    }

    #[test]
    fn rw_workspace_nested_inside_ephemeral_home_pins_intermediate_dirs_on_first_run() {
        let f = Fixture::new();
        let dir = TempDir::new().unwrap();
        let ws = dir.path().canonicalize().unwrap().join("ws");
        fs::create_dir_all(&ws).unwrap();

        let mut s = spec(vec![
            eph("/home/u", "~"),
            host(
                "/home/u/repos/proj",
                ws.to_str().unwrap(),
                EntryKind::Dir,
                Rw,
            ),
        ]);
        s.untrusted_roots.insert(ws);
        s.untrusted_roots.insert(f.session.ephemeral());

        let cmd = BwrapCommand::new(
            &s,
            &f.session,
            &f.provisioned,
            Path::new("/home/u/repos/proj"),
            &[],
            TerminalSession::Keep,
        )
        .unwrap();
        let backing = f.session.ephemeral().join(key("~").dir_name());
        assert!(backing.join("repos").is_dir());

        let args: Vec<&str> = cmd.args().iter().filter_map(|a| a.to_str()).collect();
        let pos_home = args.iter().position(|&a| a == "/home/u").unwrap();
        let pos_repos = args.iter().position(|&a| a == "/home/u/repos").unwrap();
        let pos_proj = args
            .iter()
            .position(|&a| a != "/home/u/repos/proj" || args[..].is_empty())
            .and_then(|_| {
                args.iter()
                    .enumerate()
                    .find(|&(i, &a)| {
                        a == "/home/u/repos/proj" && args.get(i.wrapping_sub(1)) != Some(&"--chdir")
                    })
                    .map(|(i, _)| i)
            })
            .unwrap();
        assert!(pos_home < pos_repos && pos_repos < pos_proj, "{args:?}");
        assert_eq!(args[pos_repos - 2], "--bind-fd", "{args:?}");
    }
}
