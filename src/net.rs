//! The sandbox's network with `network = "full"` (DESIGN.md §8).
//!
//! The sandbox gets a network namespace of its own, which pasta (from
//! passt) connects to the host's network. pasta forwards the sandbox's
//! TCP and UDP traffic through sockets on the host, so the sandbox reaches
//! whatever the host reaches. The exception is the host's loopback, since
//! `--no-map-gw` keeps the gateway address from standing for it. Only the
//! DNS forwarder reaches the host's resolver there. pasta forwards no
//! port of the host or of the sandbox to the other side.
//!
//! bwrap cannot create a network namespace pasta may join, because
//! `--disable-userns` puts the sandbox in a user namespace nested below the
//! one that owns bwrap's network namespace. So the bwrap process makes the
//! namespaces itself before it runs bwrap: a user namespace mapping only
//! the caller's ids, owning a new network namespace
//! ([`BwrapCommand`](crate::bwrap::BwrapCommand)). bwrap then waits on
//! `--block-fd` while [`start_pasta`] runs pasta against bwrap's pid. pasta
//! joins both namespaces, configures the sandbox's interface with the
//! host's addresses and routes, and goes to the background. It checks
//! every second whether bwrap still runs, and exits within a second or so
//! of bwrap. Only once pasta is in the background may bwrap go on.
//!
//! DNS goes to [`DNS_FORWARD`], which pasta passes to the host's first
//! nameserver from the host's side, so a resolver on the host's loopback
//! works too. The sandbox's `/etc/resolv.conf` names it ([`crate::etc`]).
//! The forwarder has an IPv4 address only.

use std::ffi::{OsStr, OsString};
use std::io::{self, Read, Seek};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use thiserror::Error;

/// The address the sandbox sends DNS queries to, which pasta forwards to
/// the host's resolver. It is link-local, so it never names a real host.
pub const DNS_FORWARD: &str = "169.254.1.1";

/// The pasta program, looked up in `PATH`.
pub const PASTA: &str = "pasta";

/// How long pasta has to set up the sandbox's network.
const PASTA_TIMEOUT: Duration = Duration::from_secs(10);

/// The most bytes of pasta's error output kept for a message.
const MAX_PASTA_OUTPUT: u64 = 4096;

/// Error setting up the sandbox's network.
#[derive(Debug, Error)]
pub enum NetError {
    /// pasta is not in `PATH`.
    #[error(
        "network = \"full\" needs pasta, from the passt package, and there is no `pasta` in \
         PATH; install passt, or choose another network mode"
    )]
    PastaMissing,

    /// The bwrap process cannot make its user and network namespaces.
    #[error(
        "cannot make the sandbox's network namespace: {0}; network = \"full\" needs \
         unprivileged user namespaces, which some systems restrict, Ubuntu's AppArmor among them"
    )]
    Namespace(#[source] io::Error),

    /// pasta could not be run or waited for.
    #[error("cannot run pasta {path:?}: {source}")]
    Spawn {
        /// The pasta found in `PATH`.
        path: PathBuf,
        /// What went wrong.
        #[source]
        source: io::Error,
    },

    /// pasta failed, or took too long.
    #[error("pasta could not set up the sandbox's network: {0}")]
    Failed(String),
}

/// The first executable regular file named [`PASTA`] in the directories of
/// `path`, a `PATH`-like list. Only absolute entries count, since a
/// relative one names a directory below the current one, often a
/// workspace a sandbox can write.
pub fn find_pasta_in(path: &OsStr) -> Option<PathBuf> {
    find_program_in(PASTA, path)
}

/// The first executable regular file named `name` in the absolute
/// directories of `path`, a `PATH`-like list.
pub fn find_program_in(name: &str, path: &OsStr) -> Option<PathBuf> {
    path.as_bytes()
        .split(|&b| b == b':')
        .filter(|dir| dir.starts_with(b"/"))
        .map(|dir| Path::new(OsStr::from_bytes(dir)).join(name))
        .find(|candidate| is_executable(candidate))
}

/// The pasta in stopit's own `PATH` ([`find_pasta_in`]).
pub fn find_pasta() -> Result<PathBuf, NetError> {
    std::env::var_os("PATH")
        .and_then(|path| find_pasta_in(&path))
        .ok_or(NetError::PastaMissing)
}

/// Whether `path` is a regular file this process may execute.
fn is_executable(path: &Path) -> bool {
    path.metadata().is_ok_and(|m| m.is_file())
        && rustix::fs::access(path, rustix::fs::Access::EXEC_OK).is_ok()
}

/// pasta's arguments for the namespaces of process `pid`.
pub fn pasta_args(pid: u32) -> Vec<OsString> {
    [
        // Configure the interface in the namespace from the host's.
        "--config-net",
        // The gateway address is only the gateway, never the host's
        // loopback.
        "--no-map-gw",
        // No port forwarding, from the host to the sandbox or back.
        "--tcp-ports",
        "none",
        "--udp-ports",
        "none",
        "--tcp-ns",
        "none",
        "--udp-ns",
        "none",
        "--dns-forward",
        DNS_FORWARD,
        "--quiet",
    ]
    .into_iter()
    .map(OsString::from)
    .chain([OsString::from(pid.to_string())])
    .collect()
}

/// Runs `pasta` for the namespaces of bwrap process `pid`, then lets bwrap
/// go on by writing to `block`, its `--block-fd`. pasta goes to the
/// background once the network is up, so its exit with status 0 is the
/// sign. Fails unless pasta exits with 0 within [`PASTA_TIMEOUT`]. bwrap is
/// then left blocked, for the caller to kill.
pub fn start_pasta(pasta: &Path, pid: u32, block: &OwnedFd) -> Result<(), NetError> {
    start_pasta_within(pasta, pid, block, PASTA_TIMEOUT)
}

fn start_pasta_within(
    pasta: &Path,
    pid: u32,
    block: &OwnedFd,
    timeout: Duration,
) -> Result<(), NetError> {
    let spawn_error = |source| NetError::Spawn {
        path: pasta.to_owned(),
        source,
    };
    // A memfd rather than a pipe for its messages: pasta in the
    // background keeps what it inherited open, and a pipe would never end.
    let output = rustix::fs::memfd_create("stopit-pasta", rustix::fs::MemfdFlags::CLOEXEC)
        .map_err(|e| spawn_error(e.into()))?;
    let mut command = Command::new(pasta);
    command
        .args(pasta_args(pid))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(output.try_clone().map_err(spawn_error)?))
        // Out of the terminal's process group, so a Ctrl-C meant for the
        // sandbox does not end pasta while it sets the network up.
        .process_group(0);
    // SAFETY: `close_range` is async-signal-safe.
    unsafe {
        command.pre_exec(|| {
            // Nothing of stopit's above stdio, as for bwrap.
            if libc::close_range(
                3,
                libc::c_uint::MAX,
                libc::CLOSE_RANGE_CLOEXEC as libc::c_int,
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().map_err(spawn_error)?;
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait().map_err(spawn_error)? {
            Some(status) => break Some(status),
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            None => std::thread::sleep(Duration::from_millis(5)),
        }
    };
    let said = read_output(output);
    match status {
        Some(status) if status.success() => {}
        Some(status) => {
            return Err(NetError::Failed(match said.is_empty() {
                true => format!("pasta exited with {status}"),
                false => format!("pasta exited with {status}: {said}"),
            }));
        }
        None => {
            return Err(NetError::Failed(format!(
                "pasta did not finish within {} ms",
                timeout.as_millis()
            )));
        }
    }
    rustix::io::write(block, b"x")
        .map_err(|e| NetError::Failed(format!("cannot let bwrap go on: {e}")))?;
    Ok(())
}

/// What pasta wrote to `output`, trimmed and cut to [`MAX_PASTA_OUTPUT`].
fn read_output(output: OwnedFd) -> String {
    let mut file = std::fs::File::from(output);
    let mut text = Vec::new();
    let _ = file.rewind();
    let _ = (&mut file).take(MAX_PASTA_OUTPUT).read_to_end(&mut text);
    String::from_utf8_lossy(&text).trim().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[test]
    fn pasta_is_the_first_executable_file_in_path() {
        let root = tempfile::TempDir::new().unwrap();
        let [dir_entry, not_exec, good, later] = ["a", "b", "c", "d"].map(|d| root.path().join(d));
        for dir in [&dir_entry, &not_exec, &good, &later] {
            std::fs::create_dir(dir).unwrap();
        }
        // A directory named pasta, and a file without execute bits, are
        // passed over.
        std::fs::create_dir(dir_entry.join(PASTA)).unwrap();
        std::fs::write(not_exec.join(PASTA), b"").unwrap();
        script(&good, PASTA, "exit 0");
        script(&later, PASTA, "exit 0");
        let path = [&dir_entry, &not_exec, &good, &later]
            .map(|d| d.to_str().unwrap().to_owned())
            .join(":");
        // Empty and relative entries do not mean the current directory.
        let relative = good.strip_prefix(root.path()).unwrap().to_owned();
        let path = format!("::{}:{path}:", relative.display());
        assert_eq!(find_pasta_in(relative.as_os_str()), None, "{relative:?}");
        assert_eq!(find_pasta_in(OsStr::new(&path)), Some(good.join(PASTA)));
        assert_eq!(find_pasta_in(OsStr::new("")), None);
        assert_eq!(find_pasta_in(OsStr::new(dir_entry.to_str().unwrap())), None);
    }

    #[test]
    fn pasta_forwards_no_ports_and_keeps_the_host_loopback_out() {
        let args: Vec<String> = pasta_args(42)
            .into_iter()
            .map(|a| a.into_string().unwrap())
            .collect();
        assert_eq!(args.last().unwrap(), "42");
        for flag in ["--tcp-ports", "--udp-ports", "--tcp-ns", "--udp-ns"] {
            let at = args.iter().position(|a| a == flag).unwrap();
            assert_eq!(args[at + 1], "none", "{flag}");
        }
        assert!(args.contains(&"--no-map-gw".to_owned()));
        assert!(args.contains(&"--config-net".to_owned()));
        let at = args.iter().position(|a| a == "--dns-forward").unwrap();
        assert_eq!(args[at + 1], DNS_FORWARD);
    }

    fn block_pipe() -> (OwnedFd, OwnedFd) {
        let (read, write) = std::io::pipe().unwrap();
        let read = OwnedFd::from(read);
        rustix::fs::fcntl_setfl(&read, rustix::fs::OFlags::NONBLOCK).unwrap();
        (read, OwnedFd::from(write))
    }

    fn unblocked(read: &OwnedFd) -> bool {
        let mut buf = [0u8; 1];
        rustix::io::read(read, &mut buf) == Ok(1)
    }

    #[test]
    fn bwrap_goes_on_only_once_pasta_succeeds() {
        let dir = tempfile::TempDir::new().unwrap();
        // pasta gets the pid last, and a background child of its own that
        // keeps its stderr open does not hold the start up.
        let ok = script(
            dir.path(),
            "ok",
            "[ \"$(eval echo \\${$#})\" = 7 ] || exit 9; sleep 5 & exit 0",
        );
        let (read, write) = block_pipe();
        let start = Instant::now();
        start_pasta(&ok, 7, &write).unwrap();
        assert!(start.elapsed() < Duration::from_secs(4));
        assert!(unblocked(&read));

        // A failure keeps bwrap blocked and says what pasta said.
        let fails = script(dir.path(), "fails", "echo 'no such netns' >&2; exit 1");
        let (read, write) = block_pipe();
        let e = start_pasta(&fails, 7, &write).unwrap_err();
        assert!(matches!(e, NetError::Failed(_)), "{e}");
        assert!(e.to_string().contains("no such netns"), "{e}");
        assert!(!unblocked(&read));

        // So does a pasta that hangs, after the timeout.
        let hangs = script(dir.path(), "hangs", "exec sleep 30");
        let (read, write) = block_pipe();
        let start = Instant::now();
        let e = start_pasta_within(&hangs, 7, &write, Duration::from_millis(300)).unwrap_err();
        assert!(e.to_string().contains("did not finish"), "{e}");
        assert!(start.elapsed() < Duration::from_secs(5));
        assert!(!unblocked(&read));

        // And one that cannot run.
        let e = start_pasta(&dir.path().join("missing"), 7, &write).unwrap_err();
        assert!(matches!(e, NetError::Spawn { .. }), "{e}");
    }
}
