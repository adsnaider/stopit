//! The init helper, `stopit __init`, which runs as the first process inside
//! every sandbox (DESIGN.md §6.3).
//!
//! bwrap starts it as `__init --env-fd N --spec-fd M -- <cmd...>`
//! ([`init_argv`]) with an empty environment apart from bwrap's own `PWD`.
//! `__init` then runs these steps in order:
//!
//! 1. Read the target's environment from descriptor `N` ([`decode_env`]) and
//!    the [`InitSpec`] policy from descriptor `M` ([`decode_spec`]), closing
//!    both descriptors as soon as they are read.
//! 2. Close every descriptor above stdio with `close_range`. Any error,
//!    including `ENOSYS`, aborts `__init` because Landlock requires a newer
//!    kernel than `close_range`.
//! 3. When `spec.pty_slave` is set, call `setsid` and `ioctl(TIOCSCTTY)` on
//!    the first standard descriptor that is a terminal, the supervisor's PTY
//!    slave, so it becomes the sandbox's controlling terminal.
//! 4. When `spec.lo_down` is set, clear `IFF_UP` on `lo` inside the new
//!    network namespace.
//! 5. Clear ambient, bounding, inheritable, permitted, and effective
//!    capabilities so the target starts with zero capabilities.
//! 6. Set `PR_SET_NO_NEW_PRIVS`, required before unprivileged Landlock and
//!    seccomp installation.
//! 7. Enforce the Landlock ruleset ([`crate::landlock::apply`]).
//! 8. Install the seccomp-BPF filter ([`crate::seccomp::install`]).
//! 9. Reset signal dispositions and unblock all signals, then `execve` the
//!    target with the decoded environment, searching that environment's `PATH`
//!    when the command name contains no `/`.
//!
//! If any step fails, `__init` writes `stopit __init: ...` to stderr and exits
//! with [`EXIT_INIT_FAILED`] for setup failures, [`EXIT_NOT_FOUND`] when the
//! command is missing, or [`EXIT_CANNOT_EXECUTE`] when `execve` fails for
//! another reason.
//!
//! `__init` runs from the provisioned copy with only the copied libraries, so
//! it never calls NSS or iconv routines that `dlopen` modules at runtime.

use std::collections::{BTreeSet, HashSet};
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::File;
use std::io::{self, Read, Write as _};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::escape::escape_bytes;
use crate::landlock::{self, LandlockSpec};
use crate::manifest::{OptInSyscall, ShareableNamespace};
use crate::seccomp;
use crate::spec::{NetworkSpec, SandboxSpec};

/// The subcommand that runs the init helper.
pub const SUBCOMMAND: &str = "__init";

/// The option naming the environment descriptor, `--env-fd N`.
pub const ENV_FD_OPTION: &str = "--env-fd";

/// The option naming the init specification descriptor, `--spec-fd M`.
pub const SPEC_FD_OPTION: &str = "--spec-fd";

/// Maximum encoded byte size accepted for the target environment.
pub const MAX_ENV_BYTES: usize = 16 << 20;

/// Maximum JSON byte size accepted for [`InitSpec`].
pub const MAX_SPEC_BYTES: usize = 4 << 20;

/// Exit status when `__init` fails before running `execve`.
pub const EXIT_INIT_FAILED: u8 = 125;

/// Exit status when the target exists but `execve` rejects it.
pub const EXIT_CANNOT_EXECUTE: u8 = 126;

/// Exit status when the target does not exist or is absent from `PATH`.
pub const EXIT_NOT_FOUND: u8 = 127;

/// Lowest allowed descriptor number for `--env-fd` and `--spec-fd`.
const MIN_INIT_FD: RawFd = 3;

/// First descriptor closed by `close_range` after reading the init inputs.
const FIRST_CLOSED_FD: u32 = 3;

// --- Environment encoding ----------------------------------------------------

/// Error encoding or decoding the target's environment.
///
/// Names variables by key only because values may hold secrets. Keys are
/// formatted with `{:?}`, which escapes control characters.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EnvError {
    /// A variable has an empty name.
    #[error("an environment variable has an empty name")]
    EmptyKey,

    /// A variable name contains `=`, which ends the name in `KEY=VALUE`.
    #[error("the environment variable name {0:?} contains '='")]
    KeyHasEquals(OsString),

    /// A variable's name or value contains a NUL byte, which ends an entry.
    #[error("the environment variable {0:?} contains a NUL byte")]
    Nul(OsString),

    /// A variable is set twice.
    #[error("the environment variable {0:?} is set more than once")]
    Duplicate(OsString),

    /// The encoded environment is larger than [`MAX_ENV_BYTES`].
    #[error("the environment is larger than {max} bytes")]
    TooLarge {
        /// [`MAX_ENV_BYTES`].
        max: usize,
    },

    /// An encoded entry has no `=`.
    #[error("environment entry {index} has no '='")]
    MissingEquals {
        /// Its position, from 0.
        index: usize,
    },

    /// The encoded environment does not end with a NUL byte.
    #[error("the environment's last entry is not NUL-terminated")]
    Unterminated,
}

/// Encodes an environment as `KEY=VALUE\0` entries in order, up to
/// [`MAX_ENV_BYTES`].
pub fn encode_env<K, V>(vars: impl IntoIterator<Item = (K, V)>) -> Result<Vec<u8>, EnvError>
where
    K: AsRef<OsStr>,
    V: AsRef<OsStr>,
{
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for (key, value) in vars {
        let (key, value) = (key.as_ref().as_bytes(), value.as_ref().as_bytes());
        let name = || OsStr::from_bytes(key).to_os_string();
        if key.is_empty() {
            return Err(EnvError::EmptyKey);
        }
        if key.contains(&b'=') {
            return Err(EnvError::KeyHasEquals(name()));
        }
        if key.contains(&0) || value.contains(&0) {
            return Err(EnvError::Nul(name()));
        }
        if !seen.insert(key.to_vec()) {
            return Err(EnvError::Duplicate(name()));
        }
        if out.len() + key.len() + value.len() + 2 > MAX_ENV_BYTES {
            return Err(EnvError::TooLarge { max: MAX_ENV_BYTES });
        }
        out.extend_from_slice(key);
        out.push(b'=');
        out.extend_from_slice(value);
        out.push(0);
    }
    Ok(out)
}

/// Decodes `KEY=VALUE\0` bytes produced by [`encode_env`] into `CString`s for
/// `execve`.
pub fn decode_env(bytes: &[u8]) -> Result<Vec<CString>, EnvError> {
    if bytes.len() > MAX_ENV_BYTES {
        return Err(EnvError::TooLarge { max: MAX_ENV_BYTES });
    }
    let Some(body) = bytes.strip_suffix(b"\0") else {
        return if bytes.is_empty() {
            Ok(Vec::new())
        } else {
            Err(EnvError::Unterminated)
        };
    };
    let mut entries = Vec::new();
    let mut seen = HashSet::new();
    for (index, entry) in body.split(|&b| b == 0).enumerate() {
        let eq = entry
            .iter()
            .position(|&b| b == b'=')
            .ok_or(EnvError::MissingEquals { index })?;
        if eq == 0 {
            return Err(EnvError::EmptyKey);
        }
        let key = &entry[..eq];
        if !seen.insert(key) {
            return Err(EnvError::Duplicate(OsStr::from_bytes(key).to_os_string()));
        }
        entries.push(CString::new(entry).expect("an entry holds no NUL byte"));
    }
    Ok(entries)
}

/// Returns the value of `key` in decoded `KEY=VALUE` entries.
pub fn env_value<'a>(entries: &'a [CString], key: &[u8]) -> Option<&'a [u8]> {
    entries.iter().find_map(|entry| {
        let entry = entry.as_bytes();
        let eq = entry.iter().position(|&b| b == b'=')?;
        (&entry[..eq] == key).then_some(&entry[eq + 1..])
    })
}

// --- InitSpec encoding -------------------------------------------------------

/// Hardening and session policy handed to `stopit __init` via `--spec-fd`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitSpec {
    /// Take `lo` down inside the sandbox's private network namespace.
    pub lo_down: bool,
    /// Become session leader and claim the first standard descriptor that
    /// is a terminal, the supervisor's PTY slave, as controlling terminal.
    pub pty_slave: bool,
    /// Landlock ruleset configuration.
    pub landlock: LandlockSpec,
    /// Opt-in syscall groups permitted through seccomp.
    pub allow_syscalls: BTreeSet<OptInSyscall>,
    /// Start the bridge to the network proxy ([`crate::proxy::run_bridge`]).
    pub proxy_bridge: bool,
}

impl InitSpec {
    /// Derives the `__init` specification for `spec`.
    pub fn from_sandbox_spec(spec: &SandboxSpec) -> Self {
        let own_net = !spec.namespaces.is_shared(ShareableNamespace::Net);
        InitSpec {
            lo_down: spec.network == NetworkSpec::None && own_net,
            pty_slave: false,
            landlock: LandlockSpec::from_sandbox_spec(spec),
            allow_syscalls: spec.allow_syscalls.clone(),
            proxy_bridge: matches!(spec.network, NetworkSpec::Proxy { .. }) && own_net,
        }
    }
}

/// Error encoding or decoding [`InitSpec`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SpecError {
    /// The encoded JSON exceeds [`MAX_SPEC_BYTES`].
    #[error("the init specification is larger than {max} bytes")]
    TooLarge {
        /// [`MAX_SPEC_BYTES`].
        max: usize,
    },

    /// JSON serialization or deserialization failed.
    #[error("invalid init specification JSON: {0}")]
    Json(String),
}

/// Serializes `spec` as JSON, enforcing [`MAX_SPEC_BYTES`].
pub fn encode_spec(spec: &InitSpec) -> Result<Vec<u8>, SpecError> {
    let bytes = serde_json::to_vec(spec).map_err(|e| SpecError::Json(e.to_string()))?;
    if bytes.len() > MAX_SPEC_BYTES {
        return Err(SpecError::TooLarge {
            max: MAX_SPEC_BYTES,
        });
    }
    Ok(bytes)
}

/// Deserializes an [`InitSpec`] from JSON `bytes`, enforcing [`MAX_SPEC_BYTES`].
pub fn decode_spec(bytes: &[u8]) -> Result<InitSpec, SpecError> {
    if bytes.len() > MAX_SPEC_BYTES {
        return Err(SpecError::TooLarge {
            max: MAX_SPEC_BYTES,
        });
    }
    serde_json::from_slice(bytes).map_err(|e| SpecError::Json(e.to_string()))
}

// --- Arguments ---------------------------------------------------------------

/// Builds the arguments after the provisioned binary's command prefix:
/// `__init --env-fd <env_fd> --spec-fd <spec_fd> -- <target...>`.
pub fn init_argv(env_fd: RawFd, spec_fd: RawFd, target: &[OsString]) -> Vec<OsString> {
    let mut argv: Vec<OsString> = vec![
        SUBCOMMAND.into(),
        ENV_FD_OPTION.into(),
        env_fd.to_string().into(),
        SPEC_FD_OPTION.into(),
        spec_fd.to_string().into(),
        "--".into(),
    ];
    argv.extend_from_slice(target);
    argv
}

/// Parsed command-line arguments of `stopit __init`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitArgs {
    /// Descriptor holding the encoded target environment.
    pub env_fd: RawFd,
    /// Descriptor holding the JSON [`InitSpec`].
    pub spec_fd: RawFd,
    /// Target argv, with `command[0]` naming the program.
    pub command: Vec<CString>,
}

/// Error parsing `stopit __init`'s arguments.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ArgsError {
    /// Arguments do not begin with `--env-fd N`.
    #[error("expected {ENV_FD_OPTION} N first")]
    MissingEnvFd,

    /// Arguments do not continue with `--spec-fd M` after `--env-fd N`.
    #[error("expected {SPEC_FD_OPTION} M after {ENV_FD_OPTION} N")]
    MissingSpecFd,

    /// A descriptor number is not decimal digits at least 3.
    #[error("{option} {value:?} is not a descriptor number of at least 3")]
    BadFd {
        /// Which option had the invalid value.
        option: &'static str,
        /// Raw argument value.
        value: OsString,
    },

    /// `--env-fd` and `--spec-fd` name the same descriptor.
    #[error("{ENV_FD_OPTION} and {SPEC_FD_OPTION} name the same descriptor {0}")]
    DuplicateFd(RawFd),

    /// `--` does not follow `--spec-fd M`.
    #[error("expected -- after {SPEC_FD_OPTION} M")]
    MissingSeparator,

    /// Nothing follows `--`.
    #[error("no command after --")]
    MissingCommand,
}

/// Parses the arguments after `__init`:
/// `--env-fd N --spec-fd M -- <cmd> [args...]`.
pub fn parse_args(args: &[OsString]) -> Result<InitArgs, ArgsError> {
    let [env_opt, env_val, rest @ ..] = args else {
        return Err(ArgsError::MissingEnvFd);
    };
    if env_opt != ENV_FD_OPTION {
        return Err(ArgsError::MissingEnvFd);
    }
    let env_fd = parse_fd(env_val).ok_or_else(|| ArgsError::BadFd {
        option: ENV_FD_OPTION,
        value: env_val.clone(),
    })?;

    let [spec_opt, spec_val, rest @ ..] = rest else {
        return Err(ArgsError::MissingSpecFd);
    };
    if spec_opt != SPEC_FD_OPTION {
        return Err(ArgsError::MissingSpecFd);
    }
    let spec_fd = parse_fd(spec_val).ok_or_else(|| ArgsError::BadFd {
        option: SPEC_FD_OPTION,
        value: spec_val.clone(),
    })?;
    if env_fd == spec_fd {
        return Err(ArgsError::DuplicateFd(env_fd));
    }

    let [separator, command @ ..] = rest else {
        return Err(ArgsError::MissingSeparator);
    };
    if separator != "--" {
        return Err(ArgsError::MissingSeparator);
    }
    if command.is_empty() {
        return Err(ArgsError::MissingCommand);
    }
    let command = command
        .iter()
        .map(|arg| CString::new(arg.clone().into_vec()).expect("argv holds no NUL byte"))
        .collect();
    Ok(InitArgs {
        env_fd,
        spec_fd,
        command,
    })
}

fn parse_fd(text: &OsStr) -> Option<RawFd> {
    let bytes = text.as_bytes();
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let fd: RawFd = std::str::from_utf8(bytes).ok()?.parse().ok()?;
    (fd >= MIN_INIT_FD).then_some(fd)
}

// --- Running -----------------------------------------------------------------

/// Runs `__init` with `args`, its arguments after `__init`. Returns only on
/// failure after writing the error to stderr.
pub fn run(args: &[OsString]) -> u8 {
    let args = match parse_args(args) {
        Ok(args) => args,
        Err(e) => {
            report(format_args!(
                "{e} (usage: stopit {SUBCOMMAND} {ENV_FD_OPTION} N {SPEC_FD_OPTION} M -- <cmd> [args...])"
            ));
            return EXIT_INIT_FAILED;
        }
    };

    let env = match read_env_fd(args.env_fd) {
        Ok(env) => env,
        Err(e) => {
            report(format_args!("{e}"));
            return EXIT_INIT_FAILED;
        }
    };
    let spec = match read_spec_fd(args.spec_fd) {
        Ok(spec) => spec,
        Err(e) => {
            report(format_args!("{e}"));
            return EXIT_INIT_FAILED;
        }
    };

    if let Err(e) = close_fds_from(FIRST_CLOSED_FD) {
        report(format_args!("cannot close inherited descriptors: {e}"));
        return EXIT_INIT_FAILED;
    }

    if spec.pty_slave
        && let Err(e) = setup_pty_slave()
    {
        report(format_args!("cannot set controlling terminal: {e}"));
        return EXIT_INIT_FAILED;
    }

    if spec.lo_down
        && let Err(e) = bring_loopback_down()
    {
        report(format_args!("cannot bring loopback interface down: {e}"));
        return EXIT_INIT_FAILED;
    }

    if let Err(e) = drop_all_capabilities() {
        report(format_args!("cannot clear process capabilities: {e}"));
        return EXIT_INIT_FAILED;
    }

    if let Err(e) = set_no_new_privs() {
        report(format_args!("cannot set no_new_privs: {e}"));
        return EXIT_INIT_FAILED;
    }

    if let Err(e) = landlock::apply(&spec.landlock) {
        report(format_args!("cannot apply Landlock policy: {e}"));
        return EXIT_INIT_FAILED;
    }

    if let Err(e) = seccomp::install(&spec.allow_syscalls) {
        report(format_args!("cannot install seccomp filter: {e}"));
        return EXIT_INIT_FAILED;
    }

    // After Landlock and seccomp, so the bridge has no more rights than
    // the target.
    if spec.proxy_bridge
        && let Err(e) = start_proxy_bridge()
    {
        report(format_args!(
            "cannot start the bridge to the network proxy: {e}"
        ));
        return EXIT_INIT_FAILED;
    }

    if let Err(e) = reset_signals() {
        report(format_args!("cannot reset the signal state: {e}"));
        return EXIT_INIT_FAILED;
    }

    let error = exec(&args.command, &env);
    report(format_args!(
        "{}: {error}",
        escape_bytes(args.command[0].as_bytes())
    ));
    error.exit_code()
}

fn report(message: std::fmt::Arguments<'_>) {
    let _ = writeln!(io::stderr(), "stopit {SUBCOMMAND}: {message}");
}

#[derive(Debug, Error)]
enum EnvFdError {
    #[error("cannot read the environment from descriptor {fd}: {source}")]
    Read { fd: RawFd, source: io::Error },
    #[error("invalid environment in descriptor {fd}: {source}")]
    Invalid { fd: RawFd, source: EnvError },
}

#[derive(Debug, Error)]
enum SpecFdError {
    #[error("cannot read the init specification from descriptor {fd}: {source}")]
    Read { fd: RawFd, source: io::Error },
    #[error("invalid init specification in descriptor {fd}: {source}")]
    Invalid { fd: RawFd, source: SpecError },
}

fn read_bounded_fd(fd: RawFd, max_bytes: usize) -> io::Result<Vec<u8>> {
    // SAFETY: `fcntl(F_GETFD)` takes no pointer and mutates nothing; it fails
    // with `EBADF` when `fd` is not open.
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was verified open above, and `__init` owns and closes it
    // here before any other code can touch inherited descriptors.
    let file = File::from(unsafe { OwnedFd::from_raw_fd(fd) });
    let mut bytes = Vec::new();
    file.take(max_bytes as u64 + 1).read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn read_env_fd(fd: RawFd) -> Result<Vec<CString>, EnvFdError> {
    let bytes =
        read_bounded_fd(fd, MAX_ENV_BYTES).map_err(|source| EnvFdError::Read { fd, source })?;
    decode_env(&bytes).map_err(|source| EnvFdError::Invalid { fd, source })
}

fn read_spec_fd(fd: RawFd) -> Result<InitSpec, SpecFdError> {
    let bytes =
        read_bounded_fd(fd, MAX_SPEC_BYTES).map_err(|source| SpecFdError::Read { fd, source })?;
    decode_spec(&bytes).map_err(|source| SpecFdError::Invalid { fd, source })
}

fn close_fds_from(first: u32) -> io::Result<()> {
    // SAFETY: `env_fd` and `spec_fd` are already closed, and std holds no
    // descriptors above stdio at this point.
    let ret = unsafe { libc::syscall(libc::SYS_close_range, first, u32::MAX, 0u32) };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn setup_pty_slave() -> io::Result<()> {
    // The supervisor replaces every standard descriptor that is a terminal
    // with the slave, and passes none of the host's terminals.
    // SAFETY: `isatty` takes a descriptor number only.
    let Some(fd) = (0..=2).find(|&fd| unsafe { libc::isatty(fd) } == 1) else {
        return Err(io::Error::other("no standard descriptor is a terminal"));
    };
    // SAFETY: `setsid` and `ioctl(TIOCSCTTY)` take no pointers.
    unsafe {
        if libc::setsid() < 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::ioctl(fd, libc::TIOCSCTTY as _, 0 as libc::c_int) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn bring_loopback_down() -> io::Result<()> {
    // bwrap's `--disable-userns` enters a nested child user namespace after
    // creating `--unshare-net`, so bwrap's network namespace is owned by the
    // outer user namespace and refuses `SIOCSIFFLAGS` from inside the inner
    // user namespace. Unsharing `CLONE_NEWNET` here creates a fresh network
    // namespace owned by the inner user namespace, where `lo` starts down.
    // SAFETY: `unshare(CLONE_NEWNET)` takes no pointers.
    if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: `socket` takes no pointers and returns a new close-on-exec fd or -1.
    let raw_sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if raw_sock < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `socket` returned a fresh file descriptor owned by this scope.
    let sock = unsafe { OwnedFd::from_raw_fd(raw_sock) };

    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    ifr.ifr_name[0] = b'l' as libc::c_char;
    ifr.ifr_name[1] = b'o' as libc::c_char;
    ifr.ifr_name[2] = 0;

    // SAFETY: `sock` is open and `ifr` names `"lo"`.
    if unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFFLAGS as _, &mut ifr) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `SIOCGIFFLAGS` initialized `ifr_ifru.ifru_flags`.
    let flags = unsafe { ifr.ifr_ifru.ifru_flags };
    if (flags & (libc::IFF_UP as libc::c_short)) != 0 {
        ifr.ifr_ifru.ifru_flags = flags & !(libc::IFF_UP as libc::c_short);
        // SAFETY: `sock` is open and `ifr` carries the updated flags.
        if unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFFLAGS as _, &ifr) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[repr(C)]
struct CapUserHeader {
    version: u32,
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapUserData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
const PR_CAP_AMBIENT_CLEAR_ALL_ARG: libc::c_ulong = libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong;

fn drop_all_capabilities() -> io::Result<()> {
    // SAFETY: `prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, ...)` takes no
    // pointers and clears ambient capabilities on the calling thread.
    if unsafe { libc::prctl(libc::PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL_ARG, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }

    for cap in 0..64u32 {
        // SAFETY: `PR_CAPBSET_READ` takes no pointers and returns 0, 1, or -1
        // with `EINVAL` for numbers past `cap_last_cap`.
        let present =
            unsafe { libc::prctl(libc::PR_CAPBSET_READ, libc::c_ulong::from(cap), 0, 0, 0) };
        if present < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINVAL) {
                break;
            }
            return Err(err);
        }
        if present > 0 {
            // SAFETY: `PR_CAPBSET_DROP` takes no pointers.
            if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, libc::c_ulong::from(cap), 0, 0, 0) } != 0
            {
                return Err(io::Error::last_os_error());
            }
        }
    }

    let hdr = CapUserHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [CapUserData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: `hdr` and `data` match `_LINUX_CAPABILITY_VERSION_3` and remain
    // valid across `SYS_capset`.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_capset,
            &hdr as *const CapUserHeader,
            data.as_ptr(),
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn set_no_new_privs() -> io::Result<()> {
    // SAFETY: `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)` takes no pointer and
    // only restricts this process.
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Starts the bridge to the network proxy in a process of its own, a
/// grandchild, so the target never sees it as a child. It listens on the
/// loopback addresses before this returns, so the target can connect at
/// once, and it ends when the target, which keeps this process's pid,
/// does.
fn start_proxy_bridge() -> io::Result<()> {
    use std::net::{Ipv4Addr, Ipv6Addr, TcpListener};
    let port = crate::proxy::BRIDGE_PORT;
    let mut listeners = vec![TcpListener::bind((Ipv4Addr::LOCALHOST, port))?];
    // A kernel without IPv6 has no `::1`; the IPv4 one is enough then.
    if let Ok(v6) = TcpListener::bind((Ipv6Addr::LOCALHOST, port)) {
        listeners.push(v6);
    }
    let target = rustix::process::pidfd_open(
        rustix::process::getpid(),
        rustix::process::PidfdFlags::empty(),
    )?;
    // SAFETY: `__init` is single-threaded here, so the child may do
    // anything the parent could.
    match unsafe { libc::fork() } {
        -1 => Err(io::Error::last_os_error()),
        0 => {
            // SAFETY: as above, in the single-threaded child.
            match unsafe { libc::fork() } {
                0 => {
                    for signal in [
                        libc::SIGINT,
                        libc::SIGQUIT,
                        libc::SIGHUP,
                        libc::SIGTSTP,
                        libc::SIGTTIN,
                        libc::SIGTTOU,
                        libc::SIGPIPE,
                    ] {
                        // SAFETY: setting a signal to be ignored.
                        unsafe { libc::signal(signal, libc::SIG_IGN) };
                    }
                    // The bridge has nothing to say, and must not keep the
                    // terminal open.
                    for fd in 0..3 {
                        // SAFETY: closing stdio, which nothing else uses.
                        unsafe { libc::close(fd) };
                    }
                    crate::proxy::run_bridge(
                        listeners,
                        std::path::Path::new(crate::proxy::SANDBOX_PROXY_SOCKET),
                        target,
                    )
                }
                // SAFETY: `_exit` skips the parent's atexit handlers and
                // buffers, which belong to `__init`.
                _ => unsafe { libc::_exit(0) },
            }
        }
        child => {
            drop(listeners);
            drop(target);
            let mut status = 0;
            // SAFETY: waits for the child just forked.
            if unsafe { libc::waitpid(child, &mut status, 0) } < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }
}

/// Signals ignored by the supervisor while sharing the host terminal, restored
/// to `SIG_DFL` before running the target.
const SUPERVISOR_IGNORED: [libc::c_int; 3] = [libc::SIGTSTP, libc::SIGTTIN, libc::SIGTTOU];

fn reset_signals() -> io::Result<()> {
    // SAFETY: plain libc calls on a local, initialized signal set.
    unsafe {
        for signal in std::iter::once(libc::SIGPIPE).chain(SUPERVISOR_IGNORED) {
            if libc::signal(signal, libc::SIG_DFL) == libc::SIG_ERR {
                return Err(io::Error::last_os_error());
            }
        }
        let mut empty: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut empty);
        let ret = libc::pthread_sigmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut());
        if ret != 0 {
            return Err(io::Error::from_raw_os_error(ret));
        }
    }
    Ok(())
}

/// Why the target could not be run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecError {
    /// The command has no `/`, and the environment has no `PATH`.
    NoPath,
    /// The command has no `/`, and no `PATH` entry has it.
    NotInPath,
    /// `execve` failed with this errno.
    Os(i32),
}

impl ExecError {
    /// Exit status `__init` reports for this error.
    pub fn exit_code(self) -> u8 {
        match self {
            ExecError::NoPath | ExecError::NotInPath => EXIT_NOT_FOUND,
            ExecError::Os(errno) if errno == libc::ENOENT => EXIT_NOT_FOUND,
            ExecError::Os(_) => EXIT_CANNOT_EXECUTE,
        }
    }
}

impl std::fmt::Display for ExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecError::NoPath => f.write_str("not found (the environment has no PATH)"),
            ExecError::NotInPath => f.write_str("not found in PATH"),
            ExecError::Os(errno) => io::Error::from_raw_os_error(*errno).fmt(f),
        }
    }
}

fn exec(command: &[CString], env: &[CString]) -> ExecError {
    let argv = null_terminated(command);
    let envp = null_terminated(env);
    let execve = |path: &CStr| {
        // SAFETY: `path` and every string in `argv` and `envp` are
        // NUL-terminated and outlive the call; both pointer arrays end with
        // null.
        unsafe { libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
        io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EINVAL)
    };
    let name = command[0].as_bytes();
    if name.contains(&b'/') {
        return ExecError::Os(execve(&command[0]));
    }
    if name.is_empty() {
        return ExecError::Os(libc::ENOENT);
    }
    match env_value(env, b"PATH") {
        None => ExecError::NoPath,
        Some(path) => search_path(name, path, execve),
    }
}

fn null_terminated(strings: &[CString]) -> Vec<*const libc::c_char> {
    strings
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect()
}

/// Searches `name` across `:`-separated `path` entries like musl's `execvpe`,
/// skipping empty segments and continuing past `ENOENT`, `ENOTDIR`, and
/// `EACCES`. Unlike glibc's `execvpe`, `ENOEXEC` is returned directly without
/// falling back to `/bin/sh`.
pub fn search_path(name: &[u8], path: &[u8], mut try_exec: impl FnMut(&CStr) -> i32) -> ExecError {
    let mut denied = false;
    for dir in path.split(|&b| b == b':').filter(|d| !d.is_empty()) {
        let mut candidate = Vec::with_capacity(dir.len() + 1 + name.len());
        candidate.extend_from_slice(dir);
        candidate.push(b'/');
        candidate.extend_from_slice(name);
        let candidate = CString::new(candidate).expect("a candidate holds no NUL byte");
        match try_exec(&candidate) {
            e if e == libc::ENOENT || e == libc::ENOTDIR => {}
            e if e == libc::EACCES => denied = true,
            e => return ExecError::Os(e),
        }
    }
    if denied {
        ExecError::Os(libc::EACCES)
    } else {
        ExecError::NotInPath
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, Permissions};
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    use rustix::fs::{Access, access};
    use tempfile::TempDir;

    use super::*;
    use crate::landlock::{LandlockPathRule, RO_ACCESS};

    fn os(s: &str) -> OsString {
        s.into()
    }

    fn os_bytes(b: &[u8]) -> OsString {
        OsStr::from_bytes(b).to_os_string()
    }

    // --- Environment encoding ---

    #[test]
    fn env_round_trips_with_odd_bytes() {
        let vars = vec![
            (os("PLAIN"), os("value")),
            (os("EMPTY"), os("")),
            (os("SPACES"), os("  a b  ")),
            (os("EQUALS"), os("a=b==c=")),
            (os("UNICODE"), os("héllo ✓ 日本")),
            (os("NEWLINE"), os("line1\nline2\r\n")),
            (os("CONTROL"), os_bytes(b"\x1b[31m\x07\x7f")),
            (os_bytes(b"NON\xffUTF8"), os_bytes(b"\xfe\xff\x80")),
            (os("lower.case-and spaces"), os("ok")),
        ];
        let encoded = encode_env(vars.clone()).unwrap();
        assert_eq!(encoded.last(), Some(&0));
        let decoded = decode_env(&encoded).unwrap();
        let expected: Vec<Vec<u8>> = vars
            .iter()
            .map(|(k, v)| [k.as_bytes(), b"=", v.as_bytes()].concat())
            .collect();
        let got: Vec<Vec<u8>> = decoded.iter().map(|c| c.as_bytes().to_vec()).collect();
        assert_eq!(got, expected);
        assert_eq!(env_value(&decoded, b"EQUALS"), Some(&b"a=b==c="[..]));
        assert_eq!(env_value(&decoded, b"EMPTY"), Some(&b""[..]));
        assert_eq!(env_value(&decoded, b"EQ"), None, "prefix of a name");
        assert_eq!(env_value(&decoded, b"MISSING"), None);
    }

    #[test]
    fn empty_env_round_trips() {
        let encoded = encode_env(Vec::<(OsString, OsString)>::new()).unwrap();
        assert!(encoded.is_empty());
        assert_eq!(decode_env(&encoded).unwrap(), Vec::<CString>::new());
    }

    #[test]
    fn encoding_refuses_bad_names_and_nul() {
        assert_eq!(encode_env([("", "v")]), Err(EnvError::EmptyKey));
        assert_eq!(
            encode_env([("A=B", "v")]),
            Err(EnvError::KeyHasEquals(os("A=B")))
        );
        assert_eq!(
            encode_env([("=A", "v")]),
            Err(EnvError::KeyHasEquals(os("=A")))
        );
        assert_eq!(
            encode_env([(os_bytes(b"A\0B"), os("v"))]),
            Err(EnvError::Nul(os_bytes(b"A\0B")))
        );
        assert_eq!(
            encode_env([(os("A"), os_bytes(b"x\0y"))]),
            Err(EnvError::Nul(os("A")))
        );
        assert_eq!(
            encode_env([("A", "1"), ("B", "2"), ("A", "3")]),
            Err(EnvError::Duplicate(os("A")))
        );
    }

    #[test]
    fn error_messages_name_the_key_but_not_the_value() {
        let err = encode_env([(os("TOKEN"), os_bytes(b"secret\0"))]).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("TOKEN"), "{msg}");
        assert!(!msg.contains("secret"), "{msg}");
        let err = encode_env([("\x1b[2J", ""), ("\x1b[2J", "")]).unwrap_err();
        assert!(!err.to_string().contains('\x1b'), "{err}");
    }

    #[test]
    fn encoding_is_limited_in_size() {
        let fits = "x".repeat(MAX_ENV_BYTES - 3);
        let encoded = encode_env([("A", fits.as_str())]).unwrap();
        assert_eq!(encoded.len(), MAX_ENV_BYTES);
        assert_eq!(decode_env(&encoded).unwrap().len(), 1);
        let over = "x".repeat(MAX_ENV_BYTES - 2);
        assert_eq!(
            encode_env([("A", over.as_str())]),
            Err(EnvError::TooLarge { max: MAX_ENV_BYTES })
        );
        let chunk = "x".repeat(1 << 20);
        let many: Vec<(String, &str)> =
            (0..17).map(|i| (format!("V{i}"), chunk.as_str())).collect();
        assert_eq!(
            encode_env(many),
            Err(EnvError::TooLarge { max: MAX_ENV_BYTES })
        );
    }

    #[test]
    fn decoding_refuses_what_encoding_does_not_produce() {
        assert_eq!(
            decode_env(b"A=1\0NOEQUALS\0"),
            Err(EnvError::MissingEquals { index: 1 })
        );
        assert_eq!(decode_env(b"=1\0"), Err(EnvError::EmptyKey));
        assert_eq!(decode_env(b"="), Err(EnvError::Unterminated));
        assert_eq!(decode_env(b"A=1\0B=2"), Err(EnvError::Unterminated));
        assert_eq!(
            decode_env(b"A=1\0\0B=2\0"),
            Err(EnvError::MissingEquals { index: 1 })
        );
        assert_eq!(decode_env(b"\0"), Err(EnvError::MissingEquals { index: 0 }));
        assert_eq!(decode_env(b"A=1\0A=2\0"), Err(EnvError::Duplicate(os("A"))));
        let mut huge = vec![b'x'; MAX_ENV_BYTES];
        huge[0] = b'A';
        huge[1] = b'=';
        huge.push(0);
        assert_eq!(
            decode_env(&huge),
            Err(EnvError::TooLarge { max: MAX_ENV_BYTES })
        );
    }

    #[test]
    fn decoding_splits_names_at_the_first_equals() {
        let decoded = decode_env(b"A=B=C\0").unwrap();
        assert_eq!(env_value(&decoded, b"A"), Some(&b"B=C"[..]));
        assert_eq!(env_value(&decoded, b"A=B"), None);
    }

    // --- InitSpec encoding ---

    #[test]
    fn only_proxy_mode_in_its_own_namespace_starts_the_bridge() {
        use crate::manifest::ShareableNamespace;
        let mut sb = SandboxSpec::default();
        for (network, bridge) in [
            (NetworkSpec::None, false),
            (NetworkSpec::Loopback, false),
            (NetworkSpec::Full, false),
            (
                NetworkSpec::Proxy {
                    allow_domains: Default::default(),
                },
                true,
            ),
        ] {
            sb.network = network;
            assert_eq!(InitSpec::from_sandbox_spec(&sb).proxy_bridge, bridge);
        }
        sb.namespaces.shared = [ShareableNamespace::Net].into();
        assert!(!InitSpec::from_sandbox_spec(&sb).proxy_bridge);
    }

    #[test]
    fn init_spec_round_trips_and_enforces_size_limit() {
        let mut sb = SandboxSpec::default();
        sb.allow_syscalls.insert(OptInSyscall::Ptrace);
        let spec = InitSpec::from_sandbox_spec(&sb);
        assert!(spec.lo_down);
        assert!(!spec.pty_slave);
        assert_eq!(spec.allow_syscalls, BTreeSet::from([OptInSyscall::Ptrace]));

        let encoded = encode_spec(&spec).unwrap();
        assert_eq!(decode_spec(&encoded).unwrap(), spec);

        let huge_bytes = vec![b' '; MAX_SPEC_BYTES + 1];
        assert_eq!(
            decode_spec(&huge_bytes),
            Err(SpecError::TooLarge {
                max: MAX_SPEC_BYTES
            })
        );

        let mut huge_spec = InitSpec::default();
        let big_path = PathBuf::from(format!("/{}", "a".repeat(2048)));
        for _ in 0..1100 {
            huge_spec.landlock.rules.push(LandlockPathRule {
                path: big_path.clone(),
                access: RO_ACCESS,
            });
        }
        assert_eq!(
            encode_spec(&huge_spec),
            Err(SpecError::TooLarge {
                max: MAX_SPEC_BYTES
            })
        );
    }

    // --- Arguments ---

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    fn cstrings(list: &[&str]) -> Vec<CString> {
        list.iter().map(|s| CString::new(*s).unwrap()).collect()
    }

    #[test]
    fn parses_the_env_fd_spec_fd_and_the_command() {
        assert_eq!(
            parse_args(&args(&[
                "--env-fd",
                "7",
                "--spec-fd",
                "8",
                "--",
                "/bin/sh",
                "-c",
                "x"
            ])),
            Ok(InitArgs {
                env_fd: 7,
                spec_fd: 8,
                command: cstrings(&["/bin/sh", "-c", "x"]),
            })
        );
    }

    #[test]
    fn everything_after_the_separator_is_the_command() {
        let parsed = parse_args(&args(&[
            "--env-fd",
            "3",
            "--spec-fd",
            "4",
            "--",
            "cmd",
            "--",
            "-x",
            "--env-fd",
            "5",
            "",
        ]))
        .unwrap();
        assert_eq!(
            parsed.command,
            cstrings(&["cmd", "--", "-x", "--env-fd", "5", ""])
        );
        let parsed = parse_args(&args(&[
            "--env-fd",
            "3",
            "--spec-fd",
            "4",
            "--",
            "--version",
        ]))
        .unwrap();
        assert_eq!(parsed.command, cstrings(&["--version"]));
    }

    #[test]
    fn non_utf8_arguments_are_kept() {
        let mut argv = args(&["--env-fd", "3", "--spec-fd", "4", "--"]);
        argv.push(os_bytes(b"/bin/\xff"));
        let parsed = parse_args(&argv).unwrap();
        assert_eq!(parsed.command[0].as_bytes(), b"/bin/\xff");
    }

    #[test]
    fn init_argv_round_trips() {
        let target = args(&["prog", "--", "-x"]);
        let argv = init_argv(9, 10, &target);
        assert_eq!(argv[0], SUBCOMMAND);
        assert_eq!(
            parse_args(&argv[1..]),
            Ok(InitArgs {
                env_fd: 9,
                spec_fd: 10,
                command: cstrings(&["prog", "--", "-x"]),
            })
        );
    }

    #[test]
    fn missing_pieces_are_errors() {
        let cases: &[(&[&str], ArgsError)] = &[
            (&[], ArgsError::MissingEnvFd),
            (&["--env-fd"], ArgsError::MissingEnvFd),
            (&["--", "cmd"], ArgsError::MissingEnvFd),
            (
                &["--envfd", "3", "--spec-fd", "4", "--", "cmd"],
                ArgsError::MissingEnvFd,
            ),
            (
                &["--env-fd=3", "--spec-fd", "4", "--", "cmd"],
                ArgsError::MissingEnvFd,
            ),
            (&["--env-fd", "3"], ArgsError::MissingSpecFd),
            (&["--env-fd", "3", "--", "cmd"], ArgsError::MissingSpecFd),
            (
                &["--env-fd", "3", "--specfd", "4", "--", "cmd"],
                ArgsError::MissingSpecFd,
            ),
            (
                &["--env-fd", "3", "--spec-fd", "3", "--", "cmd"],
                ArgsError::DuplicateFd(3),
            ),
            (
                &["--env-fd", "3", "--spec-fd", "4"],
                ArgsError::MissingSeparator,
            ),
            (
                &["--env-fd", "3", "--spec-fd", "4", "cmd"],
                ArgsError::MissingSeparator,
            ),
            (
                &["--env-fd", "3", "--spec-fd", "4", "-x", "--", "cmd"],
                ArgsError::MissingSeparator,
            ),
            (
                &["--env-fd", "3", "--spec-fd", "4", "--"],
                ArgsError::MissingCommand,
            ),
        ];
        for (argv, err) in cases {
            assert_eq!(parse_args(&args(argv)), Err(err.clone()), "{argv:?}");
        }
    }

    #[test]
    fn bad_fd_numbers_are_errors() {
        for fd in [
            "",
            "x",
            "-1",
            "+3",
            " 3",
            "3 ",
            "0x3",
            "3.0",
            "0",
            "1",
            "2",
            "99999999999",
        ] {
            assert_eq!(
                parse_args(&args(&["--env-fd", fd, "--spec-fd", "4", "--", "cmd"])),
                Err(ArgsError::BadFd {
                    option: ENV_FD_OPTION,
                    value: fd.into(),
                }),
                "{fd:?}"
            );
            assert_eq!(
                parse_args(&args(&["--env-fd", "3", "--spec-fd", fd, "--", "cmd"])),
                Err(ArgsError::BadFd {
                    option: SPEC_FD_OPTION,
                    value: fd.into(),
                }),
                "{fd:?}"
            );
        }
        for (fd, n) in [("3", 3), ("03", 3), ("1024", 1024)] {
            assert_eq!(
                parse_args(&args(&["--env-fd", fd, "--spec-fd", "4", "--", "cmd"]))
                    .map(|a| a.env_fd),
                Ok(n)
            );
        }
    }

    // --- PATH lookup ---

    struct Dirs {
        tmp: TempDir,
    }

    impl Dirs {
        fn new() -> Self {
            Dirs {
                tmp: TempDir::new().unwrap(),
            }
        }

        fn path(&self, rel: &str) -> String {
            self.tmp.path().join(rel).to_str().unwrap().to_owned()
        }

        fn file(&self, rel: &str, mode: u32) -> String {
            let path = self.tmp.path().join(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, b"#!/bin/false\n").unwrap();
            fs::set_permissions(&path, Permissions::from_mode(mode)).unwrap();
            self.path(rel)
        }

        fn dir(&self, rel: &str) -> String {
            fs::create_dir_all(self.tmp.path().join(rel)).unwrap();
            self.path(rel)
        }
    }

    fn lookup(name: &str, path: &str) -> (ExecError, Vec<String>) {
        let mut tried = Vec::new();
        let result = search_path(name.as_bytes(), path.as_bytes(), |candidate| {
            let candidate = candidate.to_str().unwrap().to_owned();
            tried.push(candidate.clone());
            match access(candidate.as_str(), Access::EXEC_OK) {
                Err(e) => e.raw_os_error(),
                Ok(()) if Path::new(&candidate).is_dir() => libc::EACCES,
                Ok(()) => 0,
            }
        });
        (result, tried)
    }

    #[test]
    fn path_is_searched_in_order_skipping_empty_entries() {
        let d = Dirs::new();
        let (a, b, c) = (d.dir("a"), d.dir("b"), d.dir("c"));
        d.file("b/tool", 0o755);
        d.file("c/tool", 0o755);
        let path = format!(":{a}::{b}:{c}:");
        let (result, tried) = lookup("tool", &path);
        assert_eq!(result, ExecError::Os(0));
        assert_eq!(tried, [format!("{a}/tool"), format!("{b}/tool")]);
    }

    #[test]
    fn not_found_anywhere_is_not_in_path() {
        let d = Dirs::new();
        let (a, b) = (d.dir("a"), d.dir("b"));
        let missing = d.path("missing");
        let file = d.file("file", 0o644);
        let (result, tried) = lookup("tool", &format!("{a}:{missing}:{file}:{b}"));
        assert_eq!(result, ExecError::NotInPath);
        assert_eq!(tried.len(), 4);
        assert_eq!(result.exit_code(), EXIT_NOT_FOUND);
        assert_eq!(result.to_string(), "not found in PATH");
    }

    #[test]
    fn a_non_executable_match_is_skipped_but_remembered() {
        let d = Dirs::new();
        let (a, b, c) = (d.dir("a"), d.dir("b"), d.dir("c"));
        d.file("a/tool", 0o644);
        d.file("b/tool", 0o755);
        let (result, tried) = lookup("tool", &format!("{a}:{b}"));
        assert_eq!(result, ExecError::Os(0));
        assert_eq!(tried.len(), 2);
        let (result, tried) = lookup("tool", &format!("{a}:{c}"));
        assert_eq!(result, ExecError::Os(libc::EACCES));
        assert_eq!(tried.len(), 2, "the search goes on past EACCES");
        assert_eq!(result.exit_code(), EXIT_CANNOT_EXECUTE);
        assert!(result.to_string().contains("Permission denied"), "{result}");
    }

    #[test]
    fn other_errors_end_the_search() {
        let calls = std::cell::Cell::new(0);
        let result = search_path(b"tool", b"/a:/b:/c", |_| {
            calls.set(calls.get() + 1);
            if calls.get() == 1 {
                libc::EACCES
            } else {
                libc::ENOEXEC
            }
        });
        assert_eq!(result, ExecError::Os(libc::ENOEXEC));
        assert_eq!(calls.get(), 2);
        assert_eq!(result.exit_code(), EXIT_CANNOT_EXECUTE);
    }

    #[test]
    fn only_empty_entries_find_nothing() {
        let (result, tried) = lookup("tool", "::");
        assert_eq!(result, ExecError::NotInPath);
        assert!(tried.is_empty());
        let (result, tried) = lookup("tool", "");
        assert_eq!(result, ExecError::NotInPath);
        assert!(tried.is_empty());
    }

    #[test]
    fn relative_entries_are_tried_as_written() {
        let mut tried = Vec::new();
        let result = search_path(b"tool", b"bin:./x/:../y", |candidate| {
            tried.push(candidate.to_str().unwrap().to_owned());
            libc::ENOENT
        });
        assert_eq!(result, ExecError::NotInPath);
        assert_eq!(tried, ["bin/tool", "./x//tool", "../y/tool"]);
    }

    #[test]
    fn exit_codes() {
        assert_eq!(ExecError::NoPath.exit_code(), 127);
        assert_eq!(ExecError::NotInPath.exit_code(), 127);
        assert_eq!(ExecError::Os(libc::ENOENT).exit_code(), 127);
        for errno in [libc::EACCES, libc::ENOEXEC, libc::E2BIG, libc::ENOTDIR] {
            assert_eq!(ExecError::Os(errno).exit_code(), 126, "{errno}");
        }
        assert!(
            ExecError::NoPath.to_string().contains("no PATH"),
            "{}",
            ExecError::NoPath
        );
    }

    // --- Descriptors ---

    #[test]
    fn closing_descriptors_from_a_high_number_succeeds() {
        close_fds_from(1 << 20).unwrap();
    }
}
