//! The init helper, `stopit __init`: the first process inside every sandbox
//! (DESIGN.md §6.3).
//!
//! bwrap starts it as `__init --env-fd N -- <cmd…>` ([`init_argv`]) with an
//! empty environment but for bwrap's own `PWD` (§6.2 steps 7 and 8). It
//! then:
//!
//! 1. reads the target's environment from the inherited descriptor `N`, a
//!    sealed memfd the supervisor filled with [`encode_env`], validates it
//!    ([`decode_env`]) and closes it;
//! 2. closes every descriptor but stdio with `close_range` (§6.3 step 2);
//!    any error, `ENOSYS` included, fails `__init`: Landlock needs a newer
//!    kernel than `close_range` does, so there is no fallback;
//! 3. sets `PR_SET_NO_NEW_PRIVS`, which the Landlock and seccomp steps need
//!    (§6.3 step 2);
//! 4. `execve`s the target with exactly the environment it read, looking a
//!    command without a `/` up in that environment's `PATH`
//!    ([`search_path`]). The environment `__init` itself started with is
//!    never passed on.
//!
//! If anything fails, it prints `stopit __init: …` to stderr and exits with
//! [`EXIT_INIT_FAILED`] for its own failures, [`EXIT_NOT_FOUND`] if the
//! command does not exist, and [`EXIT_CANNOT_EXECUTE`] if it cannot be run
//! for any other reason, as shells and `env` do.
//!
//! `__init` runs from the provisioned copy with only the copied libraries
//! (§2.1), so it must not use NSS or iconv, whose modules are `dlopen`ed and
//! not copied: nothing here resolves users, hosts or character sets. What it
//! reads from its descriptor is bounded by [`MAX_ENV_BYTES`].
//!
//! Not done yet (§6.3): the controlling terminal (step 1, with the PTY),
//! Landlock (step 3), seccomp (step 4) and handing the rename-notify
//! listener to the supervisor (step 4, §4.1).

use std::collections::HashSet;
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fmt::Write as _;
use std::fs::File;
use std::io::{self, Read, Write as _};
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};

use thiserror::Error;

/// The subcommand that runs the init helper: `stopit __init`.
pub const SUBCOMMAND: &str = "__init";

/// The option naming the environment descriptor: `--env-fd N`.
pub const ENV_FD_OPTION: &str = "--env-fd";

/// The largest environment `__init` accepts, in encoded bytes: far more than
/// `execve` takes (its arguments and environment together are limited to a
/// quarter of the stack limit, normally 2 MiB), yet a bound on what `__init`
/// allocates.
pub const MAX_ENV_BYTES: usize = 16 << 20;

/// `__init`'s own failure: bad arguments, an unreadable or invalid
/// environment, or a step before `execve` failing. As `env` and `chroot`
/// report theirs.
pub const EXIT_INIT_FAILED: u8 = 125;

/// The command exists but cannot be run (`EACCES`, `ENOEXEC`, …).
pub const EXIT_CANNOT_EXECUTE: u8 = 126;

/// The command does not exist, or is not in `PATH`.
pub const EXIT_NOT_FOUND: u8 = 127;

/// The lowest descriptor number the environment descriptor may have: 0 to 2
/// are stdio.
const MIN_ENV_FD: RawFd = 3;

/// The first descriptor `__init` closes: every one from here on.
// TODO(§6.3 step 2, Phase 3): the broker socket is preserved too. Move it
// (and any other preserved descriptor) to fixed numbers from 3 on, then
// close from the first number after them.
const FIRST_CLOSED_FD: u32 = 3;

// --- Environment encoding ----------------------------------------------------

/// Error encoding or decoding the target's environment.
///
/// Names variables by key only: values may hold secrets. Keys are printed
/// with `{:?}`, which escapes control characters.
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

/// Encodes an environment for `__init`'s descriptor: every variable as
/// `KEY=VALUE` followed by a NUL byte, in order. Names must be non-empty and
/// free of `=` and NUL, values free of NUL, names unique, and the whole at
/// most [`MAX_ENV_BYTES`]. Any other byte is fine, in names and values.
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

/// Decodes what [`encode_env`] produced into `KEY=VALUE` strings for
/// `execve`, in order. Refuses what `encode_env` would not produce: an entry
/// without `=` or with an empty name, a name set twice, a missing final NUL,
/// or more than [`MAX_ENV_BYTES`].
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
        // Split on NUL, so there is none inside.
        entries.push(CString::new(entry).expect("an entry holds no NUL byte"));
    }
    Ok(entries)
}

/// The value of `key` in decoded `KEY=VALUE` entries, whose name ends at
/// the first `=`.
pub fn env_value<'a>(entries: &'a [CString], key: &[u8]) -> Option<&'a [u8]> {
    entries.iter().find_map(|entry| {
        let entry = entry.as_bytes();
        let eq = entry.iter().position(|&b| b == b'=')?;
        (&entry[..eq] == key).then_some(&entry[eq + 1..])
    })
}

// --- Arguments ---------------------------------------------------------------

/// The arguments that run `__init` after the provisioned binary's command
/// prefix: `__init --env-fd <env_fd> -- <target…>`.
pub fn init_argv(env_fd: RawFd, target: &[OsString]) -> Vec<OsString> {
    let mut argv: Vec<OsString> = vec![
        SUBCOMMAND.into(),
        ENV_FD_OPTION.into(),
        env_fd.to_string().into(),
        "--".into(),
    ];
    argv.extend_from_slice(target);
    argv
}

/// `__init`'s parsed arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitArgs {
    /// The descriptor holding the target's environment.
    pub env_fd: RawFd,
    /// The target's argv, `argv[0]` being the command.
    pub command: Vec<CString>,
}

/// Error in `__init`'s arguments.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ArgsError {
    /// The arguments do not start with `--env-fd N`.
    #[error("expected {ENV_FD_OPTION} N first")]
    MissingEnvFd,

    /// The descriptor number is not a decimal number of at least 3.
    #[error("{ENV_FD_OPTION} {0:?} is not a descriptor number of at least 3")]
    BadFd(OsString),

    /// `--` does not follow `--env-fd N`.
    #[error("expected -- after {ENV_FD_OPTION} N")]
    MissingSeparator,

    /// Nothing follows `--`.
    #[error("no command after --")]
    MissingCommand,
}

/// Parses `__init`'s arguments, those after `__init`: exactly
/// `--env-fd N -- <cmd> [args…]`. Everything after `--` is the target's
/// argv, however it looks.
pub fn parse_args(args: &[OsString]) -> Result<InitArgs, ArgsError> {
    let [option, fd, rest @ ..] = args else {
        return Err(ArgsError::MissingEnvFd);
    };
    if option != ENV_FD_OPTION {
        return Err(ArgsError::MissingEnvFd);
    }
    let env_fd = parse_fd(fd).ok_or_else(|| ArgsError::BadFd(fd.clone()))?;
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
        // An argument from argv holds no NUL byte.
        .map(|arg| CString::new(arg.clone().into_vec()).expect("argv holds no NUL byte"))
        .collect();
    Ok(InitArgs { env_fd, command })
}

/// `text` as a descriptor number: plain decimal digits (no sign, no
/// spaces), at least [`MIN_ENV_FD`].
fn parse_fd(text: &OsStr) -> Option<RawFd> {
    let bytes = text.as_bytes();
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let fd: RawFd = std::str::from_utf8(bytes).ok()?.parse().ok()?;
    (fd >= MIN_ENV_FD).then_some(fd)
}

// --- Running -----------------------------------------------------------------

/// Runs `__init` with `args`, its arguments after `__init`. Returns only on
/// failure, with the exit status, after printing why to stderr; on success
/// the process is the target.
pub fn run(args: &[OsString]) -> u8 {
    let args = match parse_args(args) {
        Ok(args) => args,
        Err(e) => {
            report(format_args!(
                "{e} (usage: stopit {SUBCOMMAND} {ENV_FD_OPTION} N -- <cmd> [args…])"
            ));
            return EXIT_INIT_FAILED;
        }
    };
    // §6.3 step 2: the environment, then every descriptor but stdio.
    let env = match read_env_fd(args.env_fd) {
        Ok(env) => env,
        Err(e) => {
            report(format_args!("{e}"));
            return EXIT_INIT_FAILED;
        }
    };
    if let Err(e) = close_fds_from(FIRST_CLOSED_FD) {
        report(format_args!("cannot close inherited descriptors: {e}"));
        return EXIT_INIT_FAILED;
    }
    // TODO(§6.3 step 1, Phase 2): `setsid()` and `TIOCSCTTY` on the PTY
    // slave, which becomes stdio, once the supervisor allocates a PTY.

    // Before Landlock and seccomp, which need it. bwrap sets it too;
    // `__init` does not rely on that.
    if let Err(e) = set_no_new_privs() {
        report(format_args!("cannot set no_new_privs: {e}"));
        return EXIT_INIT_FAILED;
    }
    // TODO(§6.3 step 3): install the Landlock ruleset.
    // TODO(§6.3 step 4): install the seccomp filter, and send the
    // rename-notify listener's descriptor to the supervisor over the
    // broker socket (§4.1) before `execve`.

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

/// Prints `stopit __init: <message>` to stderr. A failure to write is
/// ignored: there is nowhere else to report it.
fn report(message: std::fmt::Arguments<'_>) {
    let _ = writeln!(io::stderr(), "stopit {SUBCOMMAND}: {message}");
}

/// Error reading the environment descriptor.
#[derive(Debug, Error)]
enum EnvFdError {
    #[error("cannot read the environment from descriptor {fd}: {source}")]
    Read { fd: RawFd, source: io::Error },
    #[error("invalid environment in descriptor {fd}: {source}")]
    Invalid { fd: RawFd, source: EnvError },
}

/// Reads and decodes the environment from `fd`, then closes it.
fn read_env_fd(fd: RawFd) -> Result<Vec<CString>, EnvFdError> {
    let read_error = |source| EnvFdError::Read { fd, source };
    // SAFETY: `fcntl(F_GETFD)` takes no pointer and changes nothing; on a
    // number that is not open it fails with `EBADF`.
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } == -1 {
        return Err(read_error(io::Error::last_os_error()));
    }
    // SAFETY: `fd` is open (checked above), and nothing else in this
    // process owns or uses it: `__init` takes it over and closes it here.
    let file = File::from(unsafe { OwnedFd::from_raw_fd(fd) });
    let mut bytes = Vec::new();
    // One byte past the limit tells whether there is more.
    file.take(MAX_ENV_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(read_error)?;
    decode_env(&bytes).map_err(|source| EnvFdError::Invalid { fd, source })
}

/// Closes every descriptor from `first` on with `close_range`. Every error
/// is final, `ENOSYS` (a kernel before 5.9) too: the sandbox needs Landlock,
/// so a kernel this old is unsupported, and a fallback would be code nothing
/// exercises.
fn close_fds_from(first: u32) -> io::Result<()> {
    // SAFETY: closing descriptors no Rust object in this process owns:
    // `__init` holds none open at this point (the environment descriptor is
    // closed already), and std keeps none.
    let ret = unsafe {
        // `unsigned int first, unsigned int last, unsigned int flags`.
        libc::syscall(libc::SYS_close_range, first, u32::MAX, 0u32)
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Sets `PR_SET_NO_NEW_PRIVS`, which Landlock and seccomp need to be
/// installed, and which `execve` then keeps.
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

/// Restores what `execve` would otherwise pass on from `__init` itself: the
/// Rust runtime ignores `SIGPIPE`, and an ignored signal stays ignored
/// across `execve`, so `SIGPIPE` goes back to its default action; and no
/// signal is blocked. `std::process::Command` does the same for its
/// children.
fn reset_signals() -> io::Result<()> {
    // SAFETY: plain libc calls on a local, initialized signal set.
    unsafe {
        if libc::signal(libc::SIGPIPE, libc::SIG_DFL) == libc::SIG_ERR {
            return Err(io::Error::last_os_error());
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
    /// The command has no `/`, and the environment no `PATH` to look it up
    /// in. There is no default path.
    NoPath,
    /// The command has no `/`, and no `PATH` entry has it.
    NotInPath,
    /// `execve` failed with this errno (for a command looked up in `PATH`,
    /// the error that ended the search, see [`search_path`]).
    Os(i32),
}

impl ExecError {
    /// The exit status `__init` reports this with.
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

/// `execve`s `command` with `env`; returns only if that fails. A command
/// without a `/` is looked up in `env`'s `PATH` ([`search_path`]).
fn exec(command: &[CString], env: &[CString]) -> ExecError {
    let argv = null_terminated(command);
    let envp = null_terminated(env);
    let execve = |path: &CStr| {
        // SAFETY: `path` and every string `argv` and `envp` point to are
        // NUL-terminated and outlive the call; both arrays end with a null
        // pointer.
        unsafe { libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
        io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EINVAL)
    };
    let name = command[0].as_bytes();
    if name.contains(&b'/') {
        return ExecError::Os(execve(&command[0]));
    }
    // An empty name would be looked up as each `PATH` directory itself.
    if name.is_empty() {
        return ExecError::Os(libc::ENOENT);
    }
    match env_value(env, b"PATH") {
        None => ExecError::NoPath,
        Some(path) => search_path(name, path, execve),
    }
}

/// Pointers to `strings`, followed by a null pointer.
fn null_terminated(strings: &[CString]) -> Vec<*const libc::c_char> {
    strings
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect()
}

/// Looks `name` up in `path` (a `PATH` value) as musl's `execvpe` does, calling
/// `try_exec` on `<dir>/<name>` for each entry in order, until one does not
/// fail with `ENOENT`, `ENOTDIR` or `EACCES` (`try_exec` returns the errno
/// it failed with; normally it does not return on success). Empty entries
/// are skipped, not taken as the working directory; a relative entry is
/// resolved against the working directory, by `try_exec`.
///
/// That error ends the search and is returned. If none does, the result is
/// `EACCES` if any entry failed with it (the command exists but cannot be
/// run), else [`ExecError::NotInPath`].
///
/// Unlike glibc's `execvpe`, a file the kernel refuses as `ENOEXEC` is not
/// run with `/bin/sh`: that error is returned.
pub fn search_path(name: &[u8], path: &[u8], mut try_exec: impl FnMut(&CStr) -> i32) -> ExecError {
    let mut denied = false;
    for dir in path.split(|&b| b == b':').filter(|d| !d.is_empty()) {
        let mut candidate = Vec::with_capacity(dir.len() + 1 + name.len());
        candidate.extend_from_slice(dir);
        candidate.push(b'/');
        candidate.extend_from_slice(name);
        // `PATH` comes from a decoded entry and `name` from argv: no NUL.
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

/// `bytes` as printable text: every character `char::escape_debug` escapes
/// (control characters, C0, DEL and C1, as `\u{1b}`; format characters such
/// as the bidi override U+202E and the zero-width space U+200B; U+2028 and
/// U+2029; unassigned and private-use ones), bytes that are not UTF-8 as
/// `\xff`, and `\` as `\\`, so the result is unambiguous and carries no
/// terminal escape sequence or text-direction trick. Everything else,
/// other Unicode included, is kept.
///
/// For text the sandbox controls (a command name) printed to the user's
/// terminal.
pub fn escape_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        for c in chunk.valid().chars() {
            // `escape_debug` also escapes `\`, and the quotes, which stay.
            if matches!(c, '\'' | '"') {
                out.push(c);
            } else {
                out.extend(c.escape_debug());
            }
        }
        for b in chunk.invalid() {
            let _ = write!(out, "\\x{b:02x}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::fs::{self, Permissions};
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use rustix::fs::{Access, access};
    use tempfile::TempDir;

    use super::*;

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
        // Control characters in a name are escaped.
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
        // Spread over many variables too.
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
        // An empty entry has no `=` either.
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

    // --- Arguments ---

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    fn cstrings(list: &[&str]) -> Vec<CString> {
        list.iter().map(|s| CString::new(*s).unwrap()).collect()
    }

    #[test]
    fn parses_the_env_fd_and_the_command() {
        assert_eq!(
            parse_args(&args(&["--env-fd", "7", "--", "/bin/sh", "-c", "x"])),
            Ok(InitArgs {
                env_fd: 7,
                command: cstrings(&["/bin/sh", "-c", "x"]),
            })
        );
    }

    #[test]
    fn everything_after_the_separator_is_the_command() {
        let parsed = parse_args(&args(&[
            "--env-fd", "3", "--", "cmd", "--", "-x", "--env-fd", "4", "",
        ]))
        .unwrap();
        assert_eq!(
            parsed.command,
            cstrings(&["cmd", "--", "-x", "--env-fd", "4", ""])
        );
        // Even a command that looks like an option.
        let parsed = parse_args(&args(&["--env-fd", "3", "--", "--version"])).unwrap();
        assert_eq!(parsed.command, cstrings(&["--version"]));
    }

    #[test]
    fn non_utf8_arguments_are_kept() {
        let mut argv = args(&["--env-fd", "3", "--"]);
        argv.push(os_bytes(b"/bin/\xff"));
        let parsed = parse_args(&argv).unwrap();
        assert_eq!(parsed.command[0].as_bytes(), b"/bin/\xff");
    }

    #[test]
    fn init_argv_round_trips() {
        let target = args(&["prog", "--", "-x"]);
        let argv = init_argv(9, &target);
        assert_eq!(argv[0], SUBCOMMAND);
        assert_eq!(
            parse_args(&argv[1..]),
            Ok(InitArgs {
                env_fd: 9,
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
            (&["--envfd", "3", "--", "cmd"], ArgsError::MissingEnvFd),
            (&["--env-fd=3", "--", "cmd"], ArgsError::MissingEnvFd),
            (&["--env-fd", "3"], ArgsError::MissingSeparator),
            (&["--env-fd", "3", "cmd"], ArgsError::MissingSeparator),
            (
                &["--env-fd", "3", "-x", "--", "cmd"],
                ArgsError::MissingSeparator,
            ),
            (&["--env-fd", "3", "--"], ArgsError::MissingCommand),
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
                parse_args(&args(&["--env-fd", fd, "--", "cmd"])),
                Err(ArgsError::BadFd(fd.into())),
                "{fd:?}"
            );
        }
        for (fd, n) in [("3", 3), ("03", 3), ("1024", 1024)] {
            assert_eq!(
                parse_args(&args(&["--env-fd", fd, "--", "cmd"])).map(|a| a.env_fd),
                Ok(n)
            );
        }
    }

    // --- PATH lookup ---

    /// A directory with executables and other entries to look commands up
    /// in.
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

    /// Looks `name` up in `path` with an `execve` stand-in that fails as
    /// `execve` would on the real files (`access(X_OK)`), and succeeds
    /// (with the made-up errno 0) on an executable file. Returns the result
    /// and every candidate tried, in order.
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
        // The first that runs ends the search; the stand-in reports it as
        // errno 0.
        assert_eq!(result, ExecError::Os(0));
        assert_eq!(tried, [format!("{a}/tool"), format!("{b}/tool")]);
    }

    #[test]
    fn not_found_anywhere_is_not_in_path() {
        let d = Dirs::new();
        let (a, b) = (d.dir("a"), d.dir("b"));
        let missing = d.path("missing");
        // A file where a directory is expected gives ENOTDIR, also skipped.
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
        // Later executable found: it runs.
        let (result, tried) = lookup("tool", &format!("{a}:{b}"));
        assert_eq!(result, ExecError::Os(0));
        assert_eq!(tried.len(), 2);
        // Only the non-executable one: EACCES, exit 126.
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
        // They resolve against the working directory when `execve` runs.
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

    // --- Escaping and descriptors ---

    #[test]
    fn escaping_makes_control_bytes_and_invalid_utf8_visible() {
        assert_eq!(escape_bytes(b"plain-name_1.2"), "plain-name_1.2");
        assert_eq!(escape_bytes("héllo ✓".as_bytes()), "héllo ✓");
        assert_eq!(escape_bytes(b"a\x1b[2Jb"), "a\\u{1b}[2Jb");
        assert_eq!(escape_bytes(b"a\nb\tc\rd"), "a\\nb\\tc\\rd");
        assert_eq!(escape_bytes(b"\x7f"), "\\u{7f}");
        // C1, as UTF-8.
        assert_eq!(escape_bytes("\u{9b}".as_bytes()), "\\u{9b}");
        assert_eq!(escape_bytes(b"x\xff\xfey"), "x\\xff\\xfey");
        assert_eq!(escape_bytes(b"back\\slash"), "back\\\\slash");
        for b in 0u8..=255 {
            let escaped = escape_bytes(&[b]);
            assert!(
                !escaped.chars().any(char::is_control),
                "{b:#x}: {escaped:?}"
            );
        }
    }

    #[test]
    fn escaping_covers_format_and_separator_characters() {
        // Bidi override, zero-width space, line and paragraph separators:
        // invisible or deceptive, so shown by code point.
        assert_eq!(escape_bytes("a\u{202e}b".as_bytes()), "a\\u{202e}b");
        assert_eq!(escape_bytes("a\u{200b}b".as_bytes()), "a\\u{200b}b");
        assert_eq!(escape_bytes("a\u{2028}b".as_bytes()), "a\\u{2028}b");
        assert_eq!(escape_bytes("a\u{2029}b".as_bytes()), "a\\u{2029}b");
        // Quotes are kept, as plain text.
        assert_eq!(escape_bytes(b"it's \"x\""), "it's \"x\"");
    }

    #[test]
    fn closing_descriptors_from_a_high_number_succeeds() {
        // Nothing this process uses is that high.
        close_fds_from(1 << 20).unwrap();
    }
}
