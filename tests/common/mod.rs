//! Shared integration-test harness: provisioning binaries for sandbox runs,
//! running bwrap, and running `stopit-probe` in a sandbox with typed results.
//!
//! Each test file that uses it declares `mod common;`. Not every file uses
//! every part, hence the `dead_code` allowance.

#![allow(dead_code)]

#[path = "../../src/bin/stopit-probe/protocol.rs"]
pub mod protocol;

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Read, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use stopit::provision::{Provisioned, provision};

#[allow(unused_imports)]
pub use protocol::{Data, ExecOutput, FileKind, Ids, Op, OpError, OpResult, Stat};

/// The bwrap arguments every sandbox run starts with: every namespace
/// unshared, killed with its parent, and an empty environment.
pub const BASE_ARGS: [&str; 3] = ["--unshare-all", "--die-with-parent", "--clearenv"];

/// Where [`Sandbox`] mounts the provisioned probe, read-only.
pub const PROBE_DIR: &str = "/run/stopit-probe";

/// A binary provisioned once per test process (see [`provisioned_stopit`]).
pub struct ProvisionedBin {
    /// The directory it was provisioned into, on the host.
    pub dir: PathBuf,
    /// What was provisioned.
    pub provisioned: Provisioned,
}

impl ProvisionedBin {
    /// The argv prefix that runs it when [`dir`](Self::dir) is mounted at
    /// `base` (see [`Provisioned::command_prefix`]).
    pub fn command_prefix(&self, base: &Path) -> Vec<OsString> {
        self.provisioned.command_prefix(base)
    }
}

/// Provisions `exe` into `<CARGO_TARGET_TMPDIR>/<test crate>/<name>`.
///
/// The directory lives under Cargo's per-target scratch directory, since the
/// statics holding it are never dropped, and is recreated on every run so at
/// most one is left behind. It is keyed by the test crate, so under
/// `cargo test`, which runs each test binary once and its tests as threads
/// of one process, no two processes share it. That does not hold under
/// nextest, which runs every test in its own process, nor for two `cargo
/// test` runs at once: each process recreates the directory, possibly while
/// another one's sandbox is using it.
fn provision_into(exe: &Path, name: &str) -> ProvisionedBin {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(env!("CARGO_CRATE_NAME"))
        .join(name);
    match fs::remove_dir_all(&dir) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => panic!("cannot remove {dir:?} left by an earlier run: {e}"),
    }
    fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("cannot create {dir:?}: {e}"));
    let provisioned =
        provision(exe, &dir).unwrap_or_else(|e| panic!("provisioning {exe:?} failed: {e}"));
    ProvisionedBin { dir, provisioned }
}

/// The stopit binary, provisioned once per test process into a directory
/// the tests share (they only read it).
pub fn provisioned_stopit() -> &'static ProvisionedBin {
    static STOPIT: OnceLock<ProvisionedBin> = OnceLock::new();
    STOPIT.get_or_init(|| provision_into(Path::new(env!("CARGO_BIN_EXE_stopit")), "stopit"))
}

/// The `stopit-probe` binary, provisioned once per test process. The copy is
/// named `stopit` like any provisioned binary.
pub fn provisioned_probe() -> &'static ProvisionedBin {
    static PROBE: OnceLock<ProvisionedBin> = OnceLock::new();
    PROBE.get_or_init(|| {
        provision_into(
            Path::new(env!("CARGO_BIN_EXE_stopit-probe")),
            "stopit-probe",
        )
    })
}

/// How long [`bwrap`] lets a sandbox run before killing it.
pub const BWRAP_DEADLINE: Duration = Duration::from_secs(30);

/// How often [`bwrap`] checks whether the sandbox is done.
const POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Reads `pipe` to its end on a new thread, into a buffer that can be
/// inspected while it is still being filled.
fn drain(mut pipe: impl Read + Send + 'static) -> (Arc<Mutex<Vec<u8>>>, JoinHandle<()>) {
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&buffer);
    let handle = thread::spawn(move || {
        let mut chunk = [0u8; 8192];
        loop {
            match pipe.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => sink.lock().unwrap().extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
    });
    (buffer, handle)
}

/// Runs `bwrap <args…>`, feeding it `stdin` (an empty stdin if `None`), and
/// returns its output. Panics with a clear message if bwrap is not on
/// `PATH`, and kills it and panics with the output so far if it is not done
/// (exited, and its stdout and stderr closed) within [`BWRAP_DEADLINE`].
pub fn bwrap<I, S>(args: I, stdin: Option<&[u8]>) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let args: Vec<OsString> = args
        .into_iter()
        .map(|a| a.as_ref().to_os_string())
        .collect();
    let child = Command::new("bwrap")
        .args(&args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match child {
        Ok(child) => child,
        Err(e) if e.kind() == io::ErrorKind::NotFound => panic!(
            "bwrap (bubblewrap) is not on PATH; this test needs it. \
             Run the tests inside `nix develop`, which provides it."
        ),
        Err(e) => panic!("cannot run bwrap: {e}"),
    };
    // Every pipe is served by its own thread, so a sandbox that writes before
    // it has read all its input cannot deadlock against us. One that fails
    // before reading its input closes the pipe; its output says why.
    let writer = child.stdin.take().map(|mut pipe| {
        let input = stdin.unwrap_or_default().to_vec();
        thread::spawn(move || {
            let _ = pipe.write_all(&input);
        })
    });
    let (stdout, stdout_reader) = drain(child.stdout.take().expect("stdout is piped"));
    let (stderr, stderr_reader) = drain(child.stderr.take().expect("stderr is piped"));

    let deadline = Instant::now() + BWRAP_DEADLINE;
    let mut status = None;
    loop {
        if status.is_none() {
            status = child
                .try_wait()
                .unwrap_or_else(|e| panic!("cannot wait for bwrap: {e}"));
        }
        let done = stdout_reader.is_finished() && stderr_reader.is_finished();
        if let (Some(status), true) = (status, done) {
            for reader in [stdout_reader, stderr_reader] {
                reader.join().expect("a pipe reader does not panic");
            }
            if let Some(writer) = writer {
                writer.join().expect("the stdin writer does not panic");
            }
            let take = |buffer: Arc<Mutex<Vec<u8>>>| std::mem::take(&mut *buffer.lock().unwrap());
            return Output {
                status,
                stdout: take(stdout),
                stderr: take(stderr),
            };
        }
        if Instant::now() >= deadline {
            // Killing bwrap kills the sandbox (`--die-with-parent`, and its
            // pid namespace dies with its init). The readers may still be
            // blocked; they are left behind with what they read so far.
            let _ = child.kill();
            let _ = child.wait();
            let lossy = |buffer: &Mutex<Vec<u8>>| {
                String::from_utf8_lossy(&buffer.lock().unwrap()).into_owned()
            };
            panic!(
                "bwrap {args:?} did not finish within {BWRAP_DEADLINE:?} and was killed\n\
                 exit status before the kill: {status:?}\nstdout so far: {}\nstderr so far: {}",
                lossy(&stdout),
                lossy(&stderr),
            );
        }
        thread::sleep(POLL_INTERVAL);
    }
}

/// Runs a probe in a sandbox: `bwrap <bwrap_args…> -- <command…>`, with
/// `ops` as the probe's input. `command` is the argv that runs the probe
/// inside the sandbox, normally a provisioned probe's
/// [`command_prefix`](ProvisionedBin::command_prefix); `bwrap_args` must
/// mount it there.
///
/// This is the low-level entry point, below [`Sandbox`]: it takes a full
/// bwrap argument list passed on argv. FD-based arguments (`--args`,
/// `--ro-bind-data`) come with the bwrap-args commit. Panics if the probe
/// does not report one result per operation, with bwrap's and the probe's
/// output.
pub fn run_probe(bwrap_args: &[OsString], command: &[OsString], ops: &[Op]) -> Vec<OpResult> {
    let input = serde_json::to_vec(ops).expect("operations serialize");
    let mut argv = bwrap_args.to_vec();
    argv.push("--".into());
    argv.extend_from_slice(command);
    let out = bwrap(&argv, Some(&input));
    let describe = || {
        format!(
            "bwrap {argv:?}\nstatus: {}\nstdout: {}\nstderr: {}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        )
    };
    assert!(out.status.success(), "the probe failed:\n{}", describe());
    let results: Vec<OpResult> = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "the probe's output is not a result list ({e}):\n{}",
            describe()
        )
    });
    assert_eq!(
        results.len(),
        ops.len(),
        "one result per operation:\n{}",
        describe()
    );
    results
}

/// A bwrap sandbox to run the probe in, built up argument by argument.
///
/// [`run`](Self::run) always adds [`BASE_ARGS`] before the arguments given
/// here, and a read-only mount of the provisioned probe at [`PROBE_DIR`]
/// after them (so nothing given here can hide it), and runs the probe
/// through its copied loader. Without further arguments the sandbox sees
/// bwrap's empty root and the probe, with no `/proc` or `/dev`.
#[derive(Debug, Clone, Default)]
#[must_use]
pub struct Sandbox {
    args: Vec<OsString>,
}

impl Sandbox {
    /// A sandbox with no arguments beyond the fixed ones.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one raw bwrap argument.
    pub fn arg(mut self, arg: impl AsRef<OsStr>) -> Self {
        self.args.push(arg.as_ref().to_os_string());
        self
    }

    /// Adds raw bwrap arguments.
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.args
            .extend(args.into_iter().map(|a| a.as_ref().to_os_string()));
        self
    }

    /// `--ro-bind <src> <dst>`.
    pub fn ro_bind(self, src: impl AsRef<OsStr>, dst: impl AsRef<OsStr>) -> Self {
        self.arg("--ro-bind").arg(src).arg(dst)
    }

    /// `--bind <src> <dst>`.
    pub fn bind(self, src: impl AsRef<OsStr>, dst: impl AsRef<OsStr>) -> Self {
        self.arg("--bind").arg(src).arg(dst)
    }

    /// `--tmpfs <dst>`.
    pub fn tmpfs(self, dst: impl AsRef<OsStr>) -> Self {
        self.arg("--tmpfs").arg(dst)
    }

    /// `--proc /proc`.
    pub fn proc(self) -> Self {
        self.args(["--proc", "/proc"])
    }

    /// `--dev /dev`.
    pub fn dev(self) -> Self {
        self.args(["--dev", "/dev"])
    }

    /// `--setenv <name> <value>`.
    pub fn setenv(self, name: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> Self {
        self.arg("--setenv").arg(name).arg(value)
    }

    /// `--chdir <dir>`.
    pub fn chdir(self, dir: impl AsRef<OsStr>) -> Self {
        self.arg("--chdir").arg(dir)
    }

    /// The complete bwrap arguments before `--`: [`BASE_ARGS`], the
    /// arguments given, and the probe mount.
    pub fn bwrap_args(&self) -> Vec<OsString> {
        let mut args: Vec<OsString> = BASE_ARGS.iter().map(OsString::from).collect();
        args.extend(self.args.iter().cloned());
        args.push("--ro-bind".into());
        args.push(provisioned_probe().dir.clone().into_os_string());
        args.push(PROBE_DIR.into());
        args
    }

    /// The argv that runs the probe in the sandbox.
    pub fn probe_command() -> Vec<OsString> {
        provisioned_probe().command_prefix(Path::new(PROBE_DIR))
    }

    /// Runs the probe with `ops` in this sandbox and returns one result per
    /// operation.
    pub fn run(&self, ops: &[Op]) -> Vec<OpResult> {
        run_probe(&self.bwrap_args(), &Self::probe_command(), ops)
    }

    /// Runs the probe with the single operation `op`.
    pub fn run_one(&self, op: Op) -> OpResult {
        self.run(&[op]).pop().expect("one result per operation")
    }
}

// --- Building operations ---------------------------------------------------

/// The path argument of an operation.
fn path(p: impl AsRef<Path>) -> String {
    p.as_ref()
        .to_str()
        .unwrap_or_else(|| panic!("probe paths are UTF-8: {:?}", p.as_ref()))
        .to_owned()
}

/// [`Op::Stat`].
pub fn stat(p: impl AsRef<Path>) -> Op {
    Op::Stat { path: path(p) }
}

/// [`Op::StatFollow`].
pub fn stat_follow(p: impl AsRef<Path>) -> Op {
    Op::StatFollow { path: path(p) }
}

/// [`Op::Read`].
pub fn read(p: impl AsRef<Path>) -> Op {
    Op::Read { path: path(p) }
}

/// [`Op::Write`].
pub fn write(p: impl AsRef<Path>, contents: &str) -> Op {
    Op::Write {
        path: path(p),
        contents: contents.into(),
    }
}

/// [`Op::Append`].
pub fn append(p: impl AsRef<Path>, contents: &str) -> Op {
    Op::Append {
        path: path(p),
        contents: contents.into(),
    }
}

/// [`Op::Mkdir`].
pub fn mkdir(p: impl AsRef<Path>) -> Op {
    Op::Mkdir { path: path(p) }
}

/// [`Op::Remove`].
pub fn remove(p: impl AsRef<Path>) -> Op {
    Op::Remove { path: path(p) }
}

/// [`Op::Rename`].
pub fn rename(from: impl AsRef<Path>, to: impl AsRef<Path>) -> Op {
    Op::Rename {
        from: path(from),
        to: path(to),
    }
}

/// [`Op::Symlink`]: creates `link` with the text `target`.
pub fn symlink(target: impl AsRef<Path>, link: impl AsRef<Path>) -> Op {
    Op::Symlink {
        target: path(target),
        link: path(link),
    }
}

/// [`Op::Readlink`].
pub fn readlink(p: impl AsRef<Path>) -> Op {
    Op::Readlink { path: path(p) }
}

/// [`Op::List`].
pub fn list(p: impl AsRef<Path>) -> Op {
    Op::List { path: path(p) }
}

/// [`Op::Link`]: creates the hard link `link` to `original`.
pub fn link(original: impl AsRef<Path>, link: impl AsRef<Path>) -> Op {
    Op::Link {
        original: path(original),
        link: path(link),
    }
}

/// [`Op::Chmod`].
pub fn chmod(p: impl AsRef<Path>, mode: u32) -> Op {
    Op::Chmod {
        path: path(p),
        mode,
    }
}

/// [`Op::Connect`].
pub fn connect(p: impl AsRef<Path>) -> Op {
    Op::Connect { path: path(p) }
}

// --- Inspecting results ----------------------------------------------------

/// The data of a successful result; panics with the error otherwise.
#[track_caller]
pub fn ok(result: &OpResult) -> &Data {
    match result {
        Ok(data) => data,
        Err(e) => panic!("expected success, got {e:?}"),
    }
}

/// The errno name of a failed result; panics if it succeeded or has no name.
#[track_caller]
pub fn errno(result: &OpResult) -> &str {
    match result {
        Err(OpError {
            name: Some(name), ..
        }) => name,
        Err(e) => panic!("expected a named errno, got {e:?}"),
        Ok(data) => panic!("expected a failure, got {data:?}"),
    }
}

/// The contents a successful [`Op::Read`] returned.
#[track_caller]
pub fn contents(result: &OpResult) -> &str {
    match ok(result) {
        Data::Read { contents, .. } => contents,
        other => panic!("expected file contents, got {other:?}"),
    }
}

/// What a successful [`Op::Stat`] or [`Op::StatFollow`] returned.
#[track_caller]
pub fn stat_data(result: &OpResult) -> Stat {
    match ok(result) {
        Data::Stat(stat) => *stat,
        other => panic!("expected a stat, got {other:?}"),
    }
}

// --- Mount table -----------------------------------------------------------

/// One line of `/proc/<pid>/mountinfo` (proc(5)), the fields tests compare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountInfo {
    /// Where the mount is, relative to the process's root.
    pub mount_point: String,
    /// The per-mount options (`ro`, `nosuid`, `nodev`, …).
    pub options: Vec<String>,
    /// The filesystem type (`tmpfs`, `proc`, `ext4`, …).
    pub fs_type: String,
    /// The filesystem's source (a device, or a name such as `tmpfs`).
    pub source: String,
    /// The per-superblock options.
    pub super_options: Vec<String>,
}

impl MountInfo {
    /// Whether the per-mount options include `option`.
    pub fn has_option(&self, option: &str) -> bool {
        self.options.iter().any(|o| o == option)
    }
}

/// Undoes the octal escapes (`\040` for a space) the kernel writes in
/// mountinfo paths.
fn unescape_mountinfo(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let octal = bytes
            .get(i + 1..i + 4)
            .filter(|d| bytes[i] == b'\\' && d.iter().all(|b| (b'0'..=b'7').contains(b)));
        match octal {
            Some(digits) => {
                let value = digits.iter().fold(0u32, |v, d| v * 8 + u32::from(d - b'0'));
                out.push(value as u8);
                i += 4;
            }
            None => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parses the text of a mountinfo file, one record per line, in order (so
/// later records are mounted on top of earlier ones). Panics on a malformed
/// line.
pub fn parse_mountinfo(text: &str) -> Vec<MountInfo> {
    text.lines()
        .filter(|line| !line.is_empty())
        .map(|line| {
            // id parent major:minor root mount_point options [optional…] -
            // fs_type source super_options
            let fields: Vec<&str> = line.split(' ').collect();
            let separator = fields
                .iter()
                .position(|&f| f == "-")
                .filter(|&at| at >= 6 && fields.len() >= at + 4)
                .unwrap_or_else(|| panic!("malformed mountinfo line: {line:?}"));
            let list = |field: &str| field.split(',').map(str::to_owned).collect();
            MountInfo {
                mount_point: unescape_mountinfo(fields[4]),
                options: list(fields[5]),
                fs_type: fields[separator + 1].to_owned(),
                source: unescape_mountinfo(fields[separator + 2]),
                super_options: list(fields[separator + 3]),
            }
        })
        .collect()
}

/// The mount table a successful [`Op::Mounts`] returned.
#[track_caller]
pub fn mountinfo(result: &OpResult) -> Vec<MountInfo> {
    match ok(result) {
        Data::Mounts(text) => parse_mountinfo(text),
        other => panic!("expected mountinfo, got {other:?}"),
    }
}

/// The topmost mount at `mount_point` in `mounts`; panics if there is none.
#[track_caller]
pub fn mount_at<'a>(mounts: &'a [MountInfo], mount_point: &str) -> &'a MountInfo {
    mounts
        .iter()
        .rev()
        .find(|m| m.mount_point == mount_point)
        .unwrap_or_else(|| panic!("no mount at {mount_point} in {mounts:#?}"))
}
