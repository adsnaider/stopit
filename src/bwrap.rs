//! The bubblewrap command line for one sandbox (DESIGN.md §6.2).
//!
//! [`BwrapCommand::new`] compiles a [`SandboxSpec`] into bwrap's arguments:
//! the namespaces (step 1), the system mounts (step 3), the filesystem
//! mounts (step 5), the runtime directory (step 6), the environment (step 7)
//! and the command (step 8). Synthesized `/etc` files and `HOME` stubs
//! (step 4) are not generated yet.
//!
//! Everything is pure generation except what the arguments need on the
//! host: each ephemeral mount's session backing directory is created if
//! missing ([`SessionDir::ephemeral_dir`]), and the data bwrap reads from
//! file descriptors is put in sealed memfds. The options reach bwrap through
//! `--args FD` (a profile's mounts can number thousands, beyond what argv
//! comfortably holds), and each masked file's empty content through its own
//! `--ro-bind-data FD`. A memfd holds any amount of data without a reader,
//! so nothing can block writing it before bwrap runs, as a pipe would above
//! its buffer size. Only the command after `--` is passed on argv.
//!
//! The descriptors are inherited at the numbers the arguments name:
//! [`BwrapCommand::into_command`] reopens each in the child, after the
//! fork, and moves it onto its number without close-on-exec, so no other
//! child of this process inherits them and every spawn reads them from the
//! start.
//!
//! bwrap leaves its root tmpfs writable; the last option remounts it
//! read-only (step 2), so the sandbox writes only where a mount lets it.

use std::collections::{BTreeMap, HashMap};
use std::ffi::{CString, OsStr, OsString};
use std::fs::File;
use std::io::{self, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use rustix::fs::{MemfdFlags, Mode, OFlags, SealFlags, fcntl_add_seals, memfd_create};
use rustix::io::fcntl_dupfd_cloexec;
use thiserror::Error;

use crate::config::ProviderName;
use crate::expand::EntryKind;
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

/// The most arguments bwrap accepts, counting both those on its argv (after
/// the program name, the command included) and those read through
/// `--args`; more make it fail with "Exceeded maximum number of
/// arguments". So a sandbox holds about 3000 mounts at most (DESIGN.md
/// §6.2). Pinned against the bwrap on `PATH` by `tests/bwrap.rs`.
pub const BWRAP_MAX_ARGS: usize = 9000;

/// The arguments on bwrap's argv besides the command: `--args FD --`.
const ARGV_OVERHEAD: usize = 3;

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
}

impl BwrapCommand {
    /// Builds the bwrap invocation that runs `argv_after_prefix` in the
    /// sandbox `spec` of `session`, through the binary `provisioned` into
    /// the session directory (normally stopit, which then runs
    /// `__init -- <cmd…>`), starting in `cwd` (see [`working_dir`]).
    ///
    /// Creates each ephemeral mount's backing directory if missing, and the
    /// memfds the arguments name.
    pub fn new(
        spec: &SandboxSpec,
        session: &SessionDir,
        provisioned: &Provisioned,
        cwd: &Path,
        argv_after_prefix: &[OsString],
    ) -> Result<BwrapCommand, BwrapError> {
        let runtime = RuntimeBinds {
            exe: provisioned.exe().to_path_buf(),
            lib_dir: provisioned.lib_dir().to_path_buf(),
            bin: session.bin(),
            prefix: provisioned.command_prefix(Path::new(SANDBOX_RUNTIME_DIR)),
        };
        let plan = plan(
            spec,
            &runtime,
            cwd,
            argv_after_prefix,
            &|path| path.symlink_metadata().is_ok(),
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
        let args: Vec<OsString> = plan
            .args
            .into_iter()
            .map(|arg| match arg {
                Arg::Text(text) => text,
                Arg::Data(index) => data_fds[index].as_raw_fd().to_string().into(),
            })
            .collect();
        let args_fd = sealed_memfd("stopit-bwrap-args", &serialize_args(&args))
            .map_err(BwrapError::DataFd)?;
        Ok(BwrapCommand {
            args,
            command: plan.command,
            args_fd,
            data_fds,
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

    /// The descriptor `--args` names.
    pub fn args_fd(&self) -> RawFd {
        self.args_fd.as_raw_fd()
    }

    /// Every descriptor bwrap inherits: [`args_fd`](Self::args_fd), then
    /// the data descriptors in the order the arguments name them.
    pub fn inherited_fds(&self) -> Vec<RawFd> {
        std::iter::once(&self.args_fd)
            .chain(&self.data_fds)
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
    pub fn into_command(self) -> Command {
        let mut command = Command::new(BWRAP);
        command
            .arg("--args")
            .arg(self.args_fd.as_raw_fd().to_string())
            .arg("--")
            .args(&self.command);
        // Built before the fork: the child must not allocate.
        let mut fds: Vec<(OwnedFd, CString)> = std::iter::once(self.args_fd)
            .chain(self.data_fds)
            .map(|fd| {
                let path = CString::new(format!("/proc/self/fd/{}", fd.as_raw_fd()))
                    .expect("no NUL in a number");
                (fd, path)
            })
            .collect();
        // SAFETY: the closure runs in the forked child before `exec`, where
        // only async-signal-safe operations are allowed. It allocates
        // nothing and takes no locks: it walks a vector built before the
        // fork and makes raw syscalls through rustix (`open` of a prepared
        // C string, `dup2`, `close`); an error becomes an `io::Error` from
        // its raw errno, which does not allocate either. Each descriptor is
        // reopened through `/proc/self/fd/N`, which gives the child a new
        // open file description of the same memfd at offset 0 (the parent's
        // is shared and would be at its end after a first spawn), and moved
        // onto `N` with `dup2`, which leaves close-on-exec clear there, so
        // bwrap inherits it at the number its arguments name. The temporary
        // descriptor is close-on-exec and closed right away. The originals
        // are owned by the closure, so they stay open for as long as the
        // `Command` does; they are close-on-exec in the parent and at least
        // `MIN_FD`, so the child's stdio setup, which runs before this,
        // leaves them alone, and no other child of this process inherits
        // them.
        unsafe {
            command.pre_exec(move || {
                for (fd, path) in &mut fds {
                    let fresh = rustix::fs::open(
                        path.as_c_str(),
                        OFlags::RDONLY | OFlags::CLOEXEC,
                        Mode::empty(),
                    )?;
                    rustix::io::dup2(&fresh, fd)?;
                }
                Ok(())
            });
        }
        command
    }
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
}

/// The host paths of the provisioned pieces bound into the runtime
/// directory, and the argv prefix that runs the provisioned binary there.
#[derive(Debug, Clone)]
struct RuntimeBinds {
    exe: PathBuf,
    lib_dir: PathBuf,
    bin: PathBuf,
    prefix: Vec<OsString>,
}

/// The generated invocation, before any descriptor exists.
#[derive(Debug, Default)]
struct Plan {
    /// The options.
    args: Vec<Arg>,
    /// The content of each [`Arg::Data`].
    data: Vec<Vec<u8>>,
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
        self.push(["--perms", MASKED_FILE_PERMS, "--ro-bind-data"])?;
        // Each needs its own descriptor: bwrap closes it after reading.
        self.args.push(Arg::Data(self.data.len()));
        self.data.push(Vec::new());
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

/// Generates the invocation for `spec`. `proc_has` tells whether a `/proc`
/// path exists (on the host, whose kernel the sandbox's procfs shows), and
/// `ephemeral_dir` provides the backing directory of an ephemeral mount at a
/// sandbox path.
fn plan(
    spec: &SandboxSpec,
    runtime: &RuntimeBinds,
    cwd: &Path,
    argv_after_prefix: &[OsString],
    proc_has: &dyn Fn(&Path) -> bool,
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
    let share_net = spec.namespaces.is_shared(ShareableNamespace::Net)
        // TODO(§8): `full` is to run through pasta with `--no-map-gw`, so
        // host localhost services stay unreachable; it shares the host's
        // network namespace until then.
        || matches!(spec.network, NetworkSpec::Full);
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
    // TODO(§8, §11): bwrap brings `lo` up in a new network namespace; for
    // `network = "none"` it must be taken down again (by `__init`, before
    // seccomp, or by a netlink call from the supervisor into the namespace).
    // Until then `none` behaves like `loopback`.
    //
    // No `--new-session`: `__init` sets up the controlling terminal (§6.3).
    plan.push(["--disable-userns", "--die-with-parent"])?;

    // Step 7: environment. bwrap then sets only `PWD`.
    // TODO(§6.2 step 8): hand the target's environment to `__init` over an
    // inherited descriptor once `__init` exists.
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
    // TODO(§6.2 step 4): synthesize `spec.system.etc` (`/etc/passwd`,
    // `/etc/group`, `/etc/hosts`, `/etc/nsswitch.conf`) and the sandbox
    // `HOME` stubs with `--ro-bind-data`. Until then they are absent.

    // Step 5: filesystem mounts, parents first. A masked directory is an
    // empty tmpfs made read-only only after every mount below it, since
    // bwrap creates their mount points in it.
    // TODO(§3.4): `spec.mask_sockets` (sockets found in `rw` grants).
    // TODO(§11): mount `O_PATH` descriptors (`--bind-fd`) and pin parent
    // directories (§3.4, Pinned parent directories).
    debug_assert!(
        parents_first(&spec.mounts),
        "the spec's mounts are not ordered parents first"
    );
    let mut masked_dirs = Vec::new();
    for mount in &spec.mounts {
        mount_args(&mut plan, mount, &mut masked_dirs, ephemeral_dir)?;
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

/// Appends the arguments of one filesystem mount, recording a masked
/// directory in `masked_dirs` to be made read-only later.
fn mount_args(
    plan: &mut Plan,
    mount: &PlannedMount,
    masked_dirs: &mut Vec<PathBuf>,
    ephemeral_dir: &mut dyn FnMut(&Path, &EphemeralKey) -> Result<PathBuf, BwrapError>,
) -> Result<(), BwrapError> {
    let dst = mount.sandbox.as_path();
    let inconsistent = || BwrapError::Inconsistent {
        sandbox: dst.to_path_buf(),
        mode: mount.mode,
        shown: mount.source.clone(),
    };
    match (&mount.source, mount.mode) {
        (MountSource::Host { path, .. }, PathMode::Rw) => {
            plan.push([OsStr::new("--bind"), path.as_os_str(), dst.as_os_str()])
        }
        // TODO(Phase 4): `protected` is served by the FUSE shadow (§4); it
        // is read-only until then.
        (MountSource::Host { path, .. }, PathMode::Ro | PathMode::Protected) => {
            plan.push([OsStr::new("--ro-bind"), path.as_os_str(), dst.as_os_str()])
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
        (MountSource::Ephemeral { key }, PathMode::Ephemeral) => {
            let backing = ephemeral_dir(dst, key)?;
            plan.push([OsStr::new("--bind"), backing.as_os_str(), dst.as_os_str()])
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

    fn runtime() -> RuntimeBinds {
        RuntimeBinds {
            exe: "/s/stopit".into(),
            lib_dir: "/s/lib".into(),
            bin: "/s/bin".into(),
            prefix: vec!["/run/stopit/stopit".into()],
        }
    }

    /// The arguments of `spec`, with every data descriptor shown as
    /// `<data N>` and ephemeral backing directories under `/eph`.
    fn try_golden(
        spec: &SandboxSpec,
        proc_has: &dyn Fn(&Path) -> bool,
    ) -> Result<Plan, BwrapError> {
        plan(
            spec,
            &runtime(),
            Path::new("/"),
            &["arg".into()],
            proc_has,
            &mut |_, key| Ok(Path::new("/eph").join(key.dir_name())),
        )
    }

    fn strings(plan: &Plan) -> Vec<String> {
        plan.args
            .iter()
            .map(|arg| match arg {
                Arg::Text(text) => text.to_str().unwrap().to_owned(),
                Arg::Data(n) => format!("<data {n}>"),
            })
            .collect()
    }

    fn golden(spec: &SandboxSpec) -> Vec<String> {
        strings(&try_golden(spec, &|_| true).unwrap())
    }

    const NAMESPACES: [&str; 8] = [
        "--unshare-user",
        "--unshare-ipc",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-uts",
        "--unshare-cgroup",
        "--disable-userns",
        "--die-with-parent",
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
            golden(&spec)[..NAMESPACES.len() - names.len()].to_vec()
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
    fn only_full_network_shares_the_network_namespace() {
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
        }
    }

    #[test]
    fn never_a_new_session_or_unshare_all() {
        let mut spec = SandboxSpec::default();
        spec.system.proc = true;
        spec.system.dev = Some(DevMode::Minimal);
        let args = golden(&spec);
        assert!(!args.contains(&"--new-session".to_string()));
        assert!(!args.contains(&"--unshare-all".to_string()));
        assert!(!args.contains(&"--share-net".to_string()));
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
    fn etc_files_are_not_synthesized_yet() {
        let mut spec = SandboxSpec::default();
        spec.system.etc = [crate::manifest::EtcFile::Passwd].into_iter().collect();
        assert_eq!(golden(&spec), around(&[]));
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
    fn chdir_is_the_given_directory() {
        let plan = plan(
            &SandboxSpec::default(),
            &runtime(),
            Path::new("/workspace"),
            &[],
            &|_| true,
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
            &runtime(),
            Path::new("workspace"),
            &[],
            &|_| true,
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
                &runtime(),
                cwd,
                argv,
                &|_| true,
                &mut |_, _| unreachable!(),
            )
        };
        nul_err(run(&path, &[]));
        nul_err(run(Path::new("/"), &["ok".into(), nul.clone()]));
        let mut rt = runtime();
        rt.exe = path.clone();
        nul_err(plan(
            &SandboxSpec::default(),
            &rt,
            Path::new("/"),
            &[],
            &|_| true,
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
            &runtime(),
            Path::new("/"),
            &["arg".into(), "more".into()],
            &|_| true,
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
            assert_eq!(cmd.args()[at - 2], "--bind");
            PathBuf::from(&cmd.args()[at - 1])
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
}
