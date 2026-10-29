//! Shims (DESIGN.md §7.1): commands in a sandbox that hand each call to
//! the broker on the host ([`crate::broker`]).
//!
//! Every shim of a profile is a symbolic link in `/run/stopit/bin`, which
//! is first in the target's `PATH`, to the trampoline at
//! `/run/stopit/shim`. The trampoline (`shim/trampoline.rs`) is a tiny
//! static program, so it runs in any sandbox. It runs the provisioned
//! stopit as `stopit __shim <name> -- <args...>` ([`run`]), which sends the
//! call to the broker's socket, `/run/stopit/broker.sock`, with its stdio
//! and working directory, passes on the signals it catches, and exits with
//! the status the broker sends back.
//!
//! stopit writes the command that runs the provisioned copy into the
//! trampoline when it provisions a session ([`write_trampoline`]).

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{OpenOptionsExt, symlink};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::config::ProfileRef;
use crate::manifest::ShimName;
use crate::session::SessionDir;

/// The internal subcommand the trampoline runs.
pub const SUBCOMMAND: &str = "__shim";

/// Where the trampoline appears in the sandbox.
pub const SANDBOX_SHIM: &str = "/run/stopit/shim";

/// Where the profile's shims appear in the sandbox, first in `PATH`.
pub const SANDBOX_BIN: &str = "/run/stopit/bin";

/// Where the broker's socket appears in the sandbox.
pub const SANDBOX_BROKER_SOCKET: &str = "/run/stopit/broker.sock";

/// The trampoline as built, with [`MARKER`] where the prefix goes.
static TRAMPOLINE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/stopit-shim"));

/// What the trampoline's prefix buffer starts with until stopit fills it
/// in. It matches `shim/trampoline.rs`.
const MARKER: &[u8] = b"STOPIT-SHIM-PREFIX-V1\0\0\0";

/// The room for the prefix in the trampoline, marker included.
const PREFIX_LEN: usize = 4096;

/// The name of the trampoline in the session directory.
const TRAMPOLINE_FILE: &str = "shim";

/// The first byte of a shim's connection to the broker, which carries its
/// stdin, stdout, stderr and working directory.
pub const HELLO: u8 = b'S';

/// The version of the shim's messages. It changes whenever they do.
pub const PROTOCOL_VERSION: u32 = 2;

/// What a shim tells the broker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ShimMessage {
    /// Run the shim `shim` with `args`, from the sandbox directory `cwd`.
    Run {
        /// [`PROTOCOL_VERSION`].
        version: u32,
        /// The shim's name, as the shim was called.
        shim: String,
        /// The arguments after the name.
        #[serde(with = "crate::control::hex_list")]
        args: Vec<Vec<u8>>,
        /// The shim's working directory, as the sandbox sees it.
        #[serde(with = "crate::control::hex_bytes")]
        cwd: Vec<u8>,
        /// Whether the shim is in the foreground on a terminal.
        foreground: bool,
    },
    /// A signal the shim caught, for the broker to pass to the command.
    Signal {
        /// The signal number.
        signal: i32,
    },
    /// The shim's terminal changed size (`SIGWINCH`).
    Resize,
}

/// What the broker tells a shim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum BrokerMessage {
    /// The command runs on its own PTY, so the shim forwards window resizes.
    Tty,
    /// The command ended, or was refused. The shim exits with this status.
    Exit {
        /// The exit status.
        code: u8,
    },
    /// The broker could not run the command.
    Error {
        /// What went wrong, unescaped.
        message: String,
    },
}

/// Error setting up shims.
#[derive(Debug, Error)]
pub enum ShimError {
    /// The prefix cannot go into the trampoline.
    #[error("cannot write the command running stopit into the shim trampoline: {0}")]
    BadPrefix(String),
    /// The trampoline or a shim link cannot be written.
    #[error("cannot set up the shims at {path:?}: {source}")]
    Write {
        /// What was written.
        path: PathBuf,
        /// What went wrong.
        #[source]
        source: io::Error,
    },
}

/// The trampoline with `prefix`, the command that runs the provisioned
/// stopit, written in.
pub fn trampoline(prefix: &[OsString]) -> Result<Vec<u8>, ShimError> {
    let mut encoded = Vec::new();
    if prefix.iter().any(|a| a.is_empty()) {
        return Err(ShimError::BadPrefix("it has an empty argument".to_owned()));
    }
    // The trampoline refuses a prefix that does not start with `/`.
    if prefix
        .first()
        .is_some_and(|program| !program.as_bytes().starts_with(b"/"))
    {
        return Err(ShimError::BadPrefix(
            "its program is not an absolute path".to_owned(),
        ));
    }
    for arg in prefix {
        encoded.extend_from_slice(arg.as_bytes());
        encoded.push(0);
    }
    encoded.push(0);
    if encoded.len() > PREFIX_LEN || prefix.is_empty() {
        return Err(ShimError::BadPrefix(format!(
            "it is {} bytes long, or empty",
            encoded.len()
        )));
    }
    let mut bytes = TRAMPOLINE.to_vec();
    let at = prefix_slot(&bytes);
    bytes[at..at + PREFIX_LEN].fill(0);
    bytes[at..at + encoded.len()].copy_from_slice(&encoded);
    Ok(bytes)
}

/// Where the prefix buffer starts in `bytes`: the one place the marker
/// appears followed by zeros to the end of the buffer. The trampoline
/// carries no other copy of the marker today, but a stray one in its
/// constants must not be the one patched.
fn prefix_slot(bytes: &[u8]) -> usize {
    let mut slots = (0..bytes.len().saturating_sub(PREFIX_LEN - 1)).filter(|&at| {
        bytes[at..].starts_with(MARKER)
            && bytes[at + MARKER.len()..at + PREFIX_LEN]
                .iter()
                .all(|&b| b == 0)
    });
    let at = slots.next().expect("the trampoline has its prefix buffer");
    assert!(
        slots.next().is_none(),
        "the trampoline has one prefix buffer"
    );
    at
}

/// Writes the trampoline running `prefix` to the session directory, mode
/// 0555, and returns its path.
pub fn write_trampoline(session: &SessionDir, prefix: &[OsString]) -> Result<PathBuf, ShimError> {
    let path = session.root().join(TRAMPOLINE_FILE);
    let write = |path: &Path| -> io::Result<()> {
        use std::io::Write as _;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o555)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        file.write_all(&trampoline(prefix).map_err(io::Error::other)?)
    };
    write(&path).map_err(|source| ShimError::Write {
        path: path.clone(),
        source,
    })?;
    Ok(path)
}

/// The directory of `profile`'s shims, `names`, in the session
/// directory's `shims/`, made if missing: one link per name to
/// [`SANDBOX_SHIM`]. Profiles keep directories of their own, so a sandbox
/// sees only its own shims. The links are made in a temporary directory
/// that is renamed into place, so no sandbox ever sees part of them.
pub fn shim_dir<'a>(
    session: &SessionDir,
    profile: &ProfileRef,
    names: impl IntoIterator<Item = &'a ShimName>,
) -> Result<PathBuf, ShimError> {
    use std::os::unix::fs::DirBuilderExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let error = |path: &Path| {
        let path = path.to_owned();
        move |source| ShimError::Write { path, source }
    };
    let parent = session.root().join("shims");
    match fs::DirBuilder::new().mode(0o700).create(&parent) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(error(&parent)(e)),
    }
    // Named for the profile and the names in it, so two profiles called
    // alike with other shims (`stopit-grant`'s profile, made from each
    // caller's) never share a directory.
    let names: Vec<&ShimName> = names.into_iter().collect();
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in names.iter().flat_map(|n| n.as_str().bytes().chain([0])) {
        hash = (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3);
    }
    let dir = parent.join(format!("{}-{hash:016x}", profile.as_str()));
    if dir.is_dir() {
        return Ok(dir);
    }
    let temp = parent.join(format!(
        ".{}-{}-{}",
        profile.as_str(),
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&temp)
        .map_err(error(&temp))?;
    for name in names {
        let link = temp.join(name.as_str());
        symlink(SANDBOX_SHIM, &link).map_err(error(&link))?;
    }
    match fs::rename(&temp, &dir) {
        Ok(()) => Ok(dir),
        // Another run made it first.
        Err(_) if dir.is_dir() => {
            let _ = fs::remove_dir_all(&temp);
            Ok(dir)
        }
        Err(e) => {
            let _ = fs::remove_dir_all(&temp);
            Err(error(&dir)(e))
        }
    }
}

/// The signals a shim passes on to its command.
const FORWARDED: [libc::c_int; 4] = [libc::SIGINT, libc::SIGQUIT, libc::SIGTERM, libc::SIGHUP];

/// Status for a shim that cannot reach the broker or is refused by it.
pub const EXIT_SHIM_FAILED: u8 = 125;

/// `stopit __shim <name> -- <args...>`, in a sandbox: runs the call
/// through the broker and returns the status to exit with.
pub fn run(args: &[OsString]) -> u8 {
    let [name, separator, rest @ ..] = args else {
        eprintln!("stopit: usage: stopit {SUBCOMMAND} <name> -- <args...>");
        return EXIT_SHIM_FAILED;
    };
    if separator != "--" {
        eprintln!("stopit: usage: stopit {SUBCOMMAND} <name> -- <args...>");
        return EXIT_SHIM_FAILED;
    }
    match call(name, rest) {
        Ok(code) => code,
        Err(message) => {
            eprintln!(
                "stopit: {}: {}",
                crate::escape::escape_bytes(name.as_bytes()),
                crate::escape::escape_message(&message)
            );
            EXIT_SHIM_FAILED
        }
    }
}

fn call(name: &OsStr, args: &[OsString]) -> Result<u8, String> {
    use crate::supervisor::{
        BlockedSignals, catch_signals, catch_winch, check_foreground, ignore_job_control,
        stdio_terminals, take_signal, take_winch,
    };
    catch_signals().map_err(|e| format!("cannot set up signal handling: {e}"))?;
    let terms = stdio_terminals();
    let foreground = terms[0] && terms[1] && check_foreground(terms).is_ok();
    if foreground {
        catch_winch().map_err(|e| format!("cannot set up signal handling: {e}"))?;
    }
    let cwd =
        std::env::current_dir().map_err(|e| format!("cannot tell the current directory: {e}"))?;
    // `O_PATH`, which needs no right to read the directory.
    let here = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(".")
        .map_err(|e| format!("cannot open the current directory: {e}"))?;
    let conn = UnixStream::connect(SANDBOX_BROKER_SOCKET)
        .map_err(|e| format!("cannot reach the broker at {SANDBOX_BROKER_SOCKET}: {e}"))?;
    // SAFETY: stdio stays open for the life of the process.
    let stdio: [BorrowedFd<'static>; 3] = unsafe {
        [
            BorrowedFd::borrow_raw(0),
            BorrowedFd::borrow_raw(1),
            BorrowedFd::borrow_raw(2),
        ]
    };
    let fds = [stdio[0], stdio[1], stdio[2], here.as_fd()];
    let lost = |e: io::Error| format!("lost the broker: {e}");
    let mask = BlockedSignals::block().map_err(|e| format!("cannot block signals: {e}"))?;
    crate::control::send_fds(&conn, HELLO, &fds).map_err(lost)?;
    crate::control::write_frame(
        &conn,
        &ShimMessage::Run {
            version: PROTOCOL_VERSION,
            shim: name.to_string_lossy().into_owned(),
            args: args.iter().map(|a| a.as_bytes().to_vec()).collect(),
            cwd: cwd.into_os_string().into_vec(),
            foreground,
        },
    )
    .map_err(lost)?;
    drop(here);
    let mut tty_active = false;
    loop {
        if let Some(signal) = take_signal()
            && FORWARDED.contains(&signal)
        {
            let _ = crate::control::write_frame(&conn, &ShimMessage::Signal { signal });
        }
        if tty_active && take_winch() {
            let _ = crate::control::write_frame(&conn, &ShimMessage::Resize);
        }
        let mut fds = [libc::pollfd {
            fd: std::os::fd::AsRawFd::as_raw_fd(&conn),
            events: libc::POLLIN,
            revents: 0,
        }];
        match mask.wait(&mut fds) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(lost(e)),
        }
        match crate::control::read_frame::<BrokerMessage>(&conn).map_err(lost)? {
            Some(BrokerMessage::Tty) => {
                ignore_job_control();
                tty_active = true;
            }
            Some(BrokerMessage::Exit { code }) => return Ok(code),
            Some(BrokerMessage::Error { message }) => return Err(message),
            None => return Err("the broker closed the connection".to_owned()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::CommandExt;

    #[test]
    fn the_trampoline_gets_its_prefix_once() {
        let prefix: Vec<OsString> = ["/run/stopit/lib/ld.so", "--library-path", "/run/stopit/lib"]
            .map(OsString::from)
            .to_vec();
        let bytes = trampoline(&prefix).unwrap();
        assert_eq!(bytes.len(), TRAMPOLINE.len());
        assert!(!bytes.windows(MARKER.len()).any(|w| w == MARKER));
        let want = b"/run/stopit/lib/ld.so\0--library-path\0/run/stopit/lib\0\0";
        assert_eq!(bytes.windows(want.len()).filter(|w| w == want).count(), 1);
        // A static ELF executable.
        assert_eq!(&bytes[..4], b"\x7fELF");
        // Too long, or empty, is refused.
        let long = vec![OsString::from(format!("/{}", "x".repeat(PREFIX_LEN - 2)))];
        assert!(trampoline(&long).is_err());
        assert!(trampoline(&[]).is_err());
        // So is a program without an absolute path, or an empty argument.
        assert!(trampoline(&["stopit".into()]).is_err());
        assert!(trampoline(&["/bin/stopit".into(), "".into()]).is_err());
        // The longest prefix that fits, with its two closing NULs.
        let longest = vec![OsString::from(format!("/{}", "x".repeat(PREFIX_LEN - 3)))];
        let bytes = trampoline(&longest).unwrap();
        assert_eq!(bytes.len(), TRAMPOLINE.len());
    }

    #[test]
    fn only_the_prefix_buffer_is_patched() {
        // A copy of the marker among other bytes, then the real buffer.
        let mut bytes = b"junk".to_vec();
        bytes.extend_from_slice(MARKER);
        bytes.extend_from_slice(b"more");
        let real = bytes.len();
        bytes.extend_from_slice(MARKER);
        bytes.resize(real + PREFIX_LEN, 0);
        bytes.extend_from_slice(b"tail");
        assert_eq!(prefix_slot(&bytes), real);
        assert_eq!(prefix_slot(TRAMPOLINE), {
            TRAMPOLINE
                .windows(MARKER.len())
                .rposition(|w| w == MARKER)
                .unwrap()
        });
    }

    /// Runs `command`, trying again while the file is busy: another test
    /// thread forking at the moment the file was written holds a copy of
    /// its descriptor until it executes.
    fn run_retrying(command: &mut std::process::Command) -> std::process::Output {
        for _ in 0..50 {
            match command.output() {
                Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                result => return result.unwrap(),
            }
        }
        panic!("the file stays busy");
    }

    #[test]
    fn the_trampoline_runs_the_prefix_with_the_shim_call() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("shim");
        std::fs::write(
            &path,
            trampoline(&["/bin/echo".into(), "first".into()]).unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o555))
            .unwrap();
        let link = dir.path().join("mytool");
        symlink(&path, &link).unwrap();
        let out = run_retrying(
            std::process::Command::new(&link)
                .args(["a b", "", "-c"])
                .env_clear(),
        );
        assert!(out.status.success(), "{out:?}");
        assert_eq!(out.stdout, b"first __shim mytool -- a b  -c\n");
        // Found through PATH, with a made-up argv[0], the name is still the
        // link's.
        let out = run_retrying(
            std::process::Command::new("mytool")
                .arg0("othertool")
                .arg("x")
                .env_clear()
                .env("PATH", dir.path()),
        );
        assert!(out.status.success(), "{out:?}");
        assert_eq!(out.stdout, b"first __shim mytool -- x\n");
        // An unprovisioned copy says so.
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, TRAMPOLINE).unwrap();
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o555))
            .unwrap();
        let out = run_retrying(&mut std::process::Command::new(&link));
        assert_eq!(out.status.code(), Some(127));
        assert!(String::from_utf8_lossy(&out.stderr).contains("never provisioned"));
    }
}
