//! Shared integration-test harness: provisioning binaries for sandbox runs,
//! running bwrap, running `stopit-probe` in a sandbox with typed results,
//! and compiling real specs into generated bwrap commands that run it.
//!
//! Each test file that uses it declares `mod common;`. Not every file uses
//! every part, hence the `dead_code` allowance.

#![allow(dead_code)]

#[path = "../../src/bin/stopit-probe/protocol.rs"]
pub mod protocol;

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Read, Write as _};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use stopit::bwrap::{BwrapCommand, TerminalSession, working_dir};
use stopit::config::{Config, ProfileRef};
use stopit::expand::ExpansionContext;
use stopit::provider::{ProviderContext, protected_sources, session_providers, static_outputs};
use stopit::provision::{Provisioned, provision};
use stopit::session::SessionDir;
use stopit::spec::{SandboxSpec, compile_session, static_rw_roots};
use stopit::state::{ConfigDirs, DataDirs, StateDirs, StatePath};
use tempfile::TempDir;

#[allow(unused_imports)]
pub use protocol::{Data, ExecOutput, FileKind, Ids, Op, OpError, OpResult, Stat, SyscallProbe};

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
    let mut command = Command::new("bwrap");
    command.args(args);
    run_bwrap(command, stdin)
}

/// Runs `command`, a bwrap invocation, as [`bwrap`] does: feeding it
/// `stdin`, collecting its output, and killing it at [`BWRAP_DEADLINE`].
pub fn run_bwrap(command: Command, stdin: Option<&[u8]>) -> Output {
    run_bwrap_within(command, stdin, BWRAP_DEADLINE)
}

/// [`run_bwrap`] with another deadline than [`BWRAP_DEADLINE`].
pub fn run_bwrap_within(mut command: Command, stdin: Option<&[u8]>, limit: Duration) -> Output {
    spawn_bwrap(&mut command, stdin, limit)
}

/// Spawns `command` once as [`run_bwrap_within`] does, leaving it to be
/// spawned again.
pub fn spawn_bwrap(command: &mut Command, stdin: Option<&[u8]>, limit: Duration) -> Output {
    command
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    spawn_with_stdio(command, stdin, limit)
}

/// [`spawn_bwrap`] with the stdio `command` was given: `stdin` is written
/// to its stdin if that is piped, and its stdout and stderr are collected
/// if they are piped (and empty otherwise).
pub fn spawn_with_stdio(command: &mut Command, stdin: Option<&[u8]>, limit: Duration) -> Output {
    let mut child = match command.spawn() {
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
    let pipe_or_nothing =
        |pipe: Option<Box<dyn Read + Send>>| drain(pipe.unwrap_or_else(|| Box::new(io::empty())));
    let (stdout, stdout_reader) = pipe_or_nothing(
        child
            .stdout
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let (stderr, stderr_reader) = pipe_or_nothing(
        child
            .stderr
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );

    let deadline = Instant::now() + limit;
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
                "{command:?} did not finish within {limit:?} and was killed\n\
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
/// bwrap argument list passed on argv. [`run_probe_command`] runs a
/// generated [`BwrapCommand`] instead. Panics if the probe does not report
/// one result per operation, with bwrap's and the probe's output.
pub fn run_probe(bwrap_args: &[OsString], command: &[OsString], ops: &[Op]) -> Vec<OpResult> {
    let input = serde_json::to_vec(ops).expect("operations serialize");
    let mut argv = bwrap_args.to_vec();
    argv.push("--".into());
    argv.extend_from_slice(command);
    let out = bwrap(&argv, Some(&input));
    probe_results(&format!("bwrap {argv:?}"), &out, ops)
}

/// Runs a probe through a generated bwrap invocation, with `ops` as its
/// input; `cmd` must run a provisioned probe (see [`ProbeSession`]). Panics
/// as [`run_probe`] does, naming the arguments passed through `--args`.
pub fn run_probe_command(cmd: BwrapCommand, ops: &[Op]) -> Vec<OpResult> {
    run_probe_command_within(cmd, BWRAP_DEADLINE, ops)
}

/// [`run_probe_command`] with another deadline than [`BWRAP_DEADLINE`].
pub fn run_probe_command_within(cmd: BwrapCommand, limit: Duration, ops: &[Op]) -> Vec<OpResult> {
    let input = serde_json::to_vec(ops).expect("operations serialize");
    let what = format!("bwrap --args {:?} -- {:?}", cmd.args(), cmd.command());
    let out = run_bwrap_within(cmd.into_command(), Some(&input), limit);
    probe_results(&what, &out, ops)
}

/// The probe's results from its output `out`, one per operation in `ops`.
/// Panics with `what` (the invocation) and the output otherwise.
pub fn probe_results(what: &str, out: &Output, ops: &[Op]) -> Vec<OpResult> {
    let describe = || {
        format!(
            "{what}\nstatus: {}\nstdout: {}\nstderr: {}",
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

// --- Compiled specs and generated commands -------------------------------------

/// The workspace mount every [`SpecFixture`] uses.
pub const WORKSPACE_MOUNT: &str = "/workspace";

/// The sandbox `HOME` every [`SpecFixture`] uses.
pub const SANDBOX_HOME: &str = "/home/user";

/// A temporary host layout to compile real [`SandboxSpec`]s against, through
/// the public pipeline (`stopit::spec::compile_session`): a workspace
/// (`ws/`, mounted at [`WORKSPACE_MOUNT`]), a host home (`home/`, with
/// `~` at [`SANDBOX_HOME`]) and a private runtime directory (`runtime/`)
/// for sessions. Everything is below one canonical temporary directory.
pub struct SpecFixture {
    root: PathBuf,
    _dir: TempDir,
}

impl SpecFixture {
    pub fn new() -> Self {
        let tmp = fs::canonicalize(std::env::temp_dir()).unwrap();
        let dir = TempDir::new_in(tmp).unwrap();
        let root = dir.path().to_path_buf();
        for sub in ["ws", "home", "runtime"] {
            fs::create_dir(root.join(sub)).unwrap();
        }
        fs::set_permissions(root.join("runtime"), fs::Permissions::from_mode(0o700)).unwrap();
        SpecFixture { root, _dir: dir }
    }

    /// The temporary directory everything is in.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The host workspace.
    pub fn workspace(&self) -> PathBuf {
        self.root.join("ws")
    }

    /// The host home.
    pub fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    /// Writes `contents` to `rel` below the root, creating its parents.
    pub fn file(&self, rel: &str, contents: &str) -> PathBuf {
        let path = self.root.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, contents).unwrap();
        path
    }

    /// Compiles the configuration `toml` (the contents of a `.stopit.toml`)
    /// and returns the `main` profile's spec. Panics on an error, and on any
    /// warning, so a test notices when its layout is not what it meant.
    pub fn compile(&self, toml: &str) -> SandboxSpec {
        let (spec, warnings) = self.compile_with_warnings(toml);
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:#?}");
        spec
    }

    /// Like [`compile`](Self::compile), but returns the warnings instead of
    /// panicking on them.
    pub fn compile_with_warnings(&self, toml: &str) -> (SandboxSpec, Vec<String>) {
        let config = Config::from_toml_str(toml).unwrap();
        let ctx = ExpansionContext::new(
            self.workspace(),
            WORKSPACE_MOUNT.parse().unwrap(),
            self.home(),
            SANDBOX_HOME.parse().unwrap(),
        )
        .unwrap();
        let providers = session_providers(&config, &self.root).unwrap();
        let pctx = ProviderContext {
            workspace: self.workspace(),
            workspace_mount: WORKSPACE_MOUNT.parse().unwrap(),
            home: self.home(),
            session_dir: self.root.join("runtime"),
            rw_grants: static_rw_roots(&static_outputs(&providers), &ctx),
        };
        let outputs = providers
            .iter()
            .map(|p| (p.name().clone(), p.manifest(&pctx).unwrap()))
            .collect();
        let protected = protected_sources(&providers).unwrap();
        // Sessions are created in `runtime` (`session`), and the data
        // directory is at its default location in the fixture's home.
        let state = StateDirs {
            runtime: StatePath::canonical(self.root.join("runtime/stopit")),
            data: DataDirs::canonical(self.home().join(".local/share/stopit")),
            config: ConfigDirs::canonical(self.home().join(".config/stopit")),
        };
        let session = compile_session(&config, outputs, &protected, &state, &ctx)
            .unwrap_or_else(|e| panic!("the configuration does not compile: {e}"));
        let main = session.get(&ProfileRef::main()).expect("main exists");
        let warnings = main.warnings.iter().map(|w| w.to_string()).collect();
        (main.spec.clone(), warnings)
    }

    /// A new session in the fixture's runtime directory, with the probe
    /// provisioned as its `stopit`.
    pub fn session(&self) -> ProbeSession {
        let session = SessionDir::create(Some(self.root.join("runtime").as_os_str())).unwrap();
        let probe = Path::new(env!("CARGO_BIN_EXE_stopit-probe"));
        let provisioned = provision(probe, session.root())
            .unwrap_or_else(|e| panic!("provisioning {probe:?} failed: {e}"));
        ProbeSession {
            session,
            provisioned,
        }
    }

    /// A new session in the fixture's runtime directory, with the real
    /// stopit provisioned as its `stopit`, so `__init` runs in the sandbox.
    pub fn init_session(&self) -> InitSession {
        let session = SessionDir::create(Some(self.root.join("runtime").as_os_str())).unwrap();
        let stopit = Path::new(env!("CARGO_BIN_EXE_stopit"));
        let provisioned = provision(stopit, session.root())
            .unwrap_or_else(|e| panic!("provisioning {stopit:?} failed: {e}"));
        InitSession {
            session,
            provisioned,
        }
    }
}

/// A session whose provisioned `stopit` is the real one: its commands run
/// `stopit __init`, which runs the target.
pub struct InitSession {
    pub session: SessionDir,
    pub provisioned: Provisioned,
}

impl InitSession {
    /// The generated invocation of `__init` in `spec`, running `target` with
    /// the environment `env`, starting in the workspace mount if `spec`
    /// mounts it (`stopit::bwrap::working_dir`).
    pub fn command(
        &self,
        spec: &SandboxSpec,
        env: &[(OsString, OsString)],
        target: &[OsString],
    ) -> BwrapCommand {
        let cwd = working_dir(spec, Path::new(WORKSPACE_MOUNT));
        BwrapCommand::for_init(
            spec,
            &self.session,
            &self.provisioned,
            &cwd,
            env,
            target,
            TerminalSession::Keep,
        )
        .unwrap_or_else(|e| panic!("cannot build the bwrap command: {e}"))
    }

    /// Runs `target` through `__init` in `spec` with `env` and `stdin`, and
    /// returns bwrap's output, whatever its status.
    pub fn run(
        &self,
        spec: &SandboxSpec,
        env: &[(OsString, OsString)],
        target: &[OsString],
        stdin: &[u8],
    ) -> Output {
        run_bwrap(self.command(spec, env, target).into_command(), Some(stdin))
    }

    /// Runs the probe command `probe` (see [`probe_at_host_path`]) through
    /// `__init` in `spec` with `env`, with `ops` as its input.
    pub fn run_probe(
        &self,
        spec: &SandboxSpec,
        env: &[(OsString, OsString)],
        probe: &[OsString],
        ops: &[Op],
    ) -> Vec<OpResult> {
        let cmd = self.command(spec, env, probe);
        let what = format!("bwrap --args {:?} -- {:?}", cmd.args(), cmd.command());
        let input = serde_json::to_vec(ops).expect("operations serialize");
        let out = run_bwrap(cmd.into_command(), Some(&input));
        probe_results(&what, &out, ops)
    }
}

/// The provisioned probe (see [`provisioned_probe`]) for running as an
/// `__init` target: its directory, canonical, which a test exposes to the
/// sandbox at the same path with an `ro` rule, and the argv that runs it
/// from there.
pub fn probe_at_host_path() -> (PathBuf, Vec<OsString>) {
    let dir = fs::canonicalize(&provisioned_probe().dir).unwrap();
    let prefix = provisioned_probe().command_prefix(&dir);
    (dir, prefix)
}

/// A session whose provisioned `stopit` is the probe. The layout is the
/// same as for stopit itself, so [`BwrapCommand`] runs the probe in its
/// place, with no arguments after the prefix.
pub struct ProbeSession {
    pub session: SessionDir,
    pub provisioned: Provisioned,
}

impl ProbeSession {
    /// The generated invocation of the probe in `spec`, starting in the
    /// workspace mount if `spec` mounts it (`stopit::bwrap::working_dir`).
    pub fn command(&self, spec: &SandboxSpec) -> BwrapCommand {
        let cwd = working_dir(spec, Path::new(WORKSPACE_MOUNT));
        BwrapCommand::new(
            spec,
            &self.session,
            &self.provisioned,
            &cwd,
            &[],
            TerminalSession::Keep,
        )
        .unwrap_or_else(|e| panic!("cannot build the bwrap command: {e}"))
    }

    /// Runs the probe with `ops` in `spec`.
    pub fn run(&self, spec: &SandboxSpec, ops: &[Op]) -> Vec<OpResult> {
        run_probe_command(self.command(spec), ops)
    }

    /// Runs the probe with the single operation `op` in `spec`.
    pub fn run_one(&self, spec: &SandboxSpec, op: Op) -> OpResult {
        self.run(spec, &[op])
            .pop()
            .expect("one result per operation")
    }
}

/// A configuration with `base = "none"` and one `config` provider whose
/// `[provider.sandbox]` table holds `body` (dotted keys such as
/// `fs.rw = ["{workspace}"]`).
pub fn config_none(body: &str) -> String {
    format!("base = \"none\"\n[[provider]]\ntype = \"config\"\n[provider.sandbox]\n{body}\n")
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
