//! Runs `stopit __init` for real: the real stopit is provisioned as each
//! session's `stopit`, and bwrap runs it through the generated command
//! (`BwrapCommand::for_init`), with `stopit-probe` as the target, run from
//! its provisioned directory at its host path (exposed with an `ro` rule).
//! Checks the environment, descriptors, `no_new_privs`, argv, exit status
//! and `PATH` lookup the target gets (DESIGN.md §6.2 steps 7 and 8, §6.3).

mod common;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use rustix::fs::{MemfdFlags, memfd_create};
use stopit::bwrap::BwrapCommand;
use stopit::init::{EXIT_CANNOT_EXECUTE, EXIT_INIT_FAILED, EXIT_NOT_FOUND, MAX_ENV_BYTES};
use stopit::spec::SandboxSpec;

use common::*;

/// A fixture, an `__init` session, and a spec with `/proc` and the probe's
/// directory, plus `body`.
struct Init {
    f: SpecFixture,
    session: InitSession,
    spec: SandboxSpec,
    /// The probe's directory, at the same path on the host and in the
    /// sandbox.
    probe_dir: PathBuf,
    /// The argv that runs the probe from there.
    probe: Vec<OsString>,
}

/// The configuration of [`Init`]: `/proc`, the probe's directory and
/// `extra_ro` read-only at their host paths, plus `body`.
fn init_config(extra_ro: &[&Path], body: &str) -> String {
    let (probe_dir, _) = probe_at_host_path();
    let ro: Vec<String> = std::iter::once(probe_dir.as_path())
        .chain(extra_ro.iter().copied())
        .map(|p| format!("\"{}\"", p.to_str().unwrap()))
        .collect();
    config_none(&format!(
        "system.proc = true\nfs.ro = [{}]\n{body}",
        ro.join(", ")
    ))
}

impl Init {
    fn new() -> Self {
        Self::in_fixture(SpecFixture::new(), &[])
    }

    /// With `extra_ro`, paths in `f`, exposed read-only at their host paths.
    fn in_fixture(f: SpecFixture, extra_ro: &[&Path]) -> Self {
        let (probe_dir, probe) = probe_at_host_path();
        let spec = f.compile(&init_config(extra_ro, ""));
        let session = f.init_session();
        Init {
            f,
            session,
            spec,
            probe_dir,
            probe,
        }
    }

    /// Runs the probe with `extra` arguments and `env`, with `ops` as input.
    fn probe(&self, env: &[(OsString, OsString)], extra: &[&str], ops: &[Op]) -> Vec<OpResult> {
        let mut argv = self.probe.clone();
        argv.extend(extra.iter().map(OsString::from));
        self.session.run_probe(&self.spec, env, &argv, ops)
    }

    /// Runs `target` with `env` and an empty stdin, whatever happens.
    fn run(&self, env: &[(OsString, OsString)], target: &[&str]) -> Output {
        let target: Vec<OsString> = target.iter().map(OsString::from).collect();
        self.session.run(&self.spec, env, &target, b"")
    }
}

fn vars(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
    pairs.iter().map(|&(k, v)| (k.into(), v.into())).collect()
}

fn env_data(pairs: &[(OsString, OsString)]) -> Data {
    Data::Env(
        pairs
            .iter()
            .map(|(k, v)| (k.to_str().unwrap().into(), v.to_str().unwrap().into()))
            .collect::<BTreeMap<_, _>>(),
    )
}

fn names(list: &[&str]) -> Data {
    Data::List(list.iter().map(|s| s.to_string()).collect())
}

/// The exit code of `out`, with its output if it has none.
#[track_caller]
fn code(out: &Output) -> i32 {
    out.status
        .code()
        .unwrap_or_else(|| panic!("killed: {out:?}"))
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

// --- Environment ---

#[test]
fn environment_is_exactly_what_was_passed() {
    // No `PWD` (bwrap sets it for `__init`, which discards it), and values
    // with spaces, `=`, newlines and Unicode, and empty ones, intact.
    let init = Init::new();
    let env = vars(&[
        ("SPACES", "  a b  c "),
        ("EQUALS", "x=y==z="),
        ("UNICODE", "héllo ✓ 日本"),
        ("EMPTY", ""),
        ("NEWLINES", "l1\nl2\r\n"),
        ("lower.case", "ok"),
    ]);
    let results = init.probe(&env, &[], &[Op::Env, Op::Cwd]);
    assert_eq!(ok(&results[0]), &env_data(&env));
    // The working directory is bwrap's, though `PWD` is gone.
    assert_eq!(ok(&results[1]), &Data::Cwd("/".into()));
}

#[test]
fn environment_computed_from_a_spec_and_a_host_environment_is_what_the_target_gets() {
    let mut init = Init::new();
    init.spec = init.f.compile(&init_config(
        &[],
        "env.pass = [\"TERM\", \"RUST_*\", \"*_TOKEN\", \"PATH\", \"HOME\", \"USER\"]\n\
         env.deny = [\"*_TOKEN\"]\n\
         env.set = { EDITOR = \"nvim\" }\n\
         env.path_prepend = [\"/run/a/bin\", \"/run/b/bin\"]",
    ));
    let host = vars(&[
        ("HOME", "/home/adam"),
        ("PATH", "/usr/bin:/home/adam/bin"),
        ("USER", "adam"),
        ("LOGNAME", "adam"),
        ("TERM", "xterm"),
        ("RUST_LOG", "debug"),
        ("GITHUB_TOKEN", "secret"),
        ("EDITOR", "emacs"),
        ("SSH_AUTH_SOCK", "/run/user/1000/agent"),
    ]);
    let env = init.spec.target_env(host);
    assert_eq!(
        env,
        vars(&[
            ("EDITOR", "nvim"),
            // The sandbox's identity, not the host's.
            ("HOME", SANDBOX_HOME),
            ("LOGNAME", "user"),
            ("PATH", "/run/a/bin:/run/b/bin"),
            ("RUST_LOG", "debug"),
            ("TERM", "xterm"),
            ("USER", "user"),
        ])
    );
    let results = init.probe(&env, &[], &[Op::Env]);
    assert_eq!(ok(&results[0]), &env_data(&env));
}

#[test]
fn empty_environment_stays_empty() {
    let init = Init::new();
    let result = init.probe(&[], &[], &[Op::Env]);
    assert_eq!(ok(&result[0]), &env_data(&[]));
}

#[test]
fn a_large_environment_passes() {
    // About 1 MiB, in variables of 64 KiB: each below the kernel's limit
    // for one string (128 KiB), all below `execve`'s total limit.
    let init = Init::new();
    let env: Vec<(OsString, OsString)> = (0..16u8)
        .map(|i| {
            let value = char::from(b'a' + i).to_string().repeat(64 * 1024);
            (format!("BIG_{i}").into(), value.into())
        })
        .collect();
    let total: usize = env.iter().map(|(k, v)| k.len() + v.len() + 2).sum();
    assert!(total > 1 << 20 && total < MAX_ENV_BYTES, "{total}");
    let result = init.probe(&env, &[], &[Op::Env]);
    assert_eq!(ok(&result[0]), &env_data(&env));
}

// --- Descriptors and privileges ---

#[test]
fn only_stdio_and_the_listing_are_open_in_the_target() {
    // The environment descriptor, which bwrap passes on and `__init` closes
    // once read, the masked file's `--ro-bind-data` one and `--args` (which
    // bwrap closes itself) are all gone. The fourth is the directory being
    // listed. (`close_range` itself is what the next test checks.)
    let init = Init::new();
    let secret = init.f.file("secret", "x");
    let spec = init.f.compile(&init_config(
        &[],
        &format!("fs.masked = [\"{}\"]", secret.to_str().unwrap()),
    ));
    let results = init
        .session
        .run_probe(&spec, &[], &init.probe, &[list("/proc/self/fd")]);
    assert_eq!(ok(&results[0]), &names(&["0", "1", "2", "3"]));
}

/// `command` made to pass `fd` open across `exec`, after `BwrapCommand`'s
/// `pre_exec` marks inherited descriptors close-on-exec.
fn leaking_fd(mut command: Command, fd: std::os::fd::RawFd) -> Command {
    // SAFETY: `fcntl` with `F_SETFD` is async-signal-safe.
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(fd, libc::F_SETFD, 0) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
    command
}

#[test]
fn descriptors_leaked_to_bwrap_reach_init_but_not_the_target() {
    // A descriptor left open past `BwrapCommand` reaches bwrap, which passes
    // it through to its command. The probe run directly sees it, while `__init`
    // closes it before running the target.
    let init = Init::new();
    let mem = memfd_create("stopit-test-leak", MemfdFlags::CLOEXEC).unwrap();
    let leaked = rustix::io::fcntl_dupfd_cloexec(&mem, 64).unwrap();
    let raw = leaked.as_raw_fd();
    let number = raw.to_string();

    let ops = [list("/proc/self/fd")];
    let input = serde_json::to_vec(&ops).unwrap();

    let direct = init.f.session();
    let spec = init.f.compile(&config_none("system.proc = true"));
    let out = run_bwrap(
        leaking_fd(direct.command(&spec).into_command(), raw),
        Some(&input),
    );
    let seen = probe_results("direct leaked fd", &out, &ops);
    let Data::List(fds) = ok(&seen[0]) else {
        panic!("{seen:?}")
    };
    assert!(fds.contains(&number), "{number} not in {fds:?}");

    let cmd = init.session.command(&init.spec, &[], &init.probe);
    let out = run_bwrap(leaking_fd(cmd.into_command(), raw), Some(&input));
    let results = probe_results("init leaked fd", &out, &ops);
    assert_eq!(ok(&results[0]), &names(&["0", "1", "2", "3"]));
    drop((leaked, mem));
}

#[test]
fn no_new_privs_is_set() {
    // bwrap sets it too, so this cannot tell which one did.
    let init = Init::new();
    let result = init.probe(&[], &[], &[read("/proc/self/status")]);
    let status = contents(&result[0]);
    assert!(status.lines().any(|l| l == "NoNewPrivs:\t1"), "{status}");
}

/// `command` made to start with `SIGUSR1` blocked, as a parent that blocks
/// signals would leave it. The mask is inherited through `exec`, bwrap
/// included.
fn blocking_sigusr1(mut command: Command) -> Command {
    // SAFETY: the closure only calls async-signal-safe functions
    // (`sigemptyset`, `sigaddset`, `sigprocmask`) on a local set.
    unsafe {
        command.pre_exec(|| {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGUSR1);
            if libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
    command
}

/// The `SigBlk` line of `/proc/self/status` as the probe sees it, when
/// `command` (bwrap running it) starts with `SIGUSR1` blocked.
fn sig_blk(command: BwrapCommand) -> String {
    let ops = [read("/proc/self/status")];
    let input = serde_json::to_vec(&ops).unwrap();
    let out = run_bwrap(blocking_sigusr1(command.into_command()), Some(&input));
    let results = probe_results("signal mask", &out, &ops);
    contents(&results[0])
        .lines()
        .find(|l| l.starts_with("SigBlk:"))
        .expect("a SigBlk line")
        .to_owned()
}

#[test]
fn the_signal_mask_is_cleared() {
    let init = Init::new();
    let direct = init.f.session();
    let spec = init.f.compile(&config_none("system.proc = true"));
    // bwrap passes the mask on (bit 9 is SIGUSR1), so the target having
    // none is `__init`'s doing.
    assert_eq!(sig_blk(direct.command(&spec)), "SigBlk:\t0000000000000200");
    let blk = sig_blk(init.session.command(&init.spec, &[], &init.probe));
    assert_eq!(blk, "SigBlk:\t0000000000000000");
}

/// `command` made to start with `SIGTSTP`, `SIGTTIN` and `SIGTTOU` ignored,
/// as the supervisor runs bwrap. Ignored dispositions survive `exec`.
fn ignoring_job_control(mut command: Command) -> Command {
    // SAFETY: the closure only calls `signal`, which is async-signal-safe,
    // with `SIG_IGN`.
    unsafe {
        command.pre_exec(|| {
            for signal in [libc::SIGTSTP, libc::SIGTTIN, libc::SIGTTOU] {
                if libc::signal(signal, libc::SIG_IGN) == libc::SIG_ERR {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    command
}

/// The ignored signals among `SIGTSTP`, `SIGTTIN` and `SIGTTOU` (bits 19 to
/// 21 of the `SigIgn` line of `/proc/self/status`) as the probe sees them,
/// when `command` (bwrap running it) starts with them ignored.
fn ignored_job_control(command: BwrapCommand) -> u64 {
    let ops = [read("/proc/self/status")];
    let input = serde_json::to_vec(&ops).unwrap();
    let out = run_bwrap(ignoring_job_control(command.into_command()), Some(&input));
    let results = probe_results("ignored signals", &out, &ops);
    let line = contents(&results[0])
        .lines()
        .find_map(|l| l.strip_prefix("SigIgn:\t"))
        .expect("a SigIgn line")
        .to_owned();
    u64::from_str_radix(&line, 16).unwrap() & 0x38_0000
}

#[test]
fn job_control_signals_ignored_by_the_supervisor_are_reset() {
    let init = Init::new();
    let direct = init.f.session();
    let spec = init.f.compile(&config_none("system.proc = true"));
    // bwrap passes them on ignored, so the target having them at their
    // default is `__init`'s doing.
    assert_eq!(ignored_job_control(direct.command(&spec)), 0x38_0000);
    let ignored = ignored_job_control(init.session.command(&init.spec, &[], &init.probe));
    assert_eq!(ignored, 0);
}

// --- Command, argv, stdio and exit status ---

#[test]
fn argv_is_passed_through_intact() {
    let init = Init::new();
    let extra = ["--", "-x", "--env-fd", "5", "", "with space", "ünï", "a=b"];
    let result = init.probe(&[], &extra, &[Op::Argv]);
    // Run through its loader or not, the probe sees its own path first.
    let mut expected = vec![init.probe_dir.join("stopit").to_str().unwrap().to_owned()];
    expected.extend(extra.iter().map(|s| s.to_string()));
    assert_eq!(ok(&result[0]), &Data::Argv(expected));
}

#[test]
fn stdin_and_stdout_are_the_targets() {
    // The probe reads its operations on stdin and writes its results to
    // stdout, through `__init` and bwrap, many of them.
    let init = Init::new();
    let ops: Vec<Op> = (0..200).map(|_| Op::Cwd).collect();
    let results = init.probe(&[], &[], &ops);
    assert!(results.iter().all(|r| ok(r) == &Data::Cwd("/".into())));
}

#[test]
fn the_targets_exit_status_reaches_the_host() {
    // The probe exits with 2 on input that is not an operation list.
    let init = Init::new();
    let out = init.session.run(&init.spec, &[], &init.probe, b"not json");
    assert_eq!(code(&out), 2, "{out:?}");
    assert!(
        stderr(&out).contains("stdin is not a JSON array"),
        "{out:?}"
    );
    assert!(out.stdout.is_empty(), "{out:?}");
}

// --- PATH lookup and failures ---

/// A directory below the fixture's root holding a non-executable file
/// named `name`.
fn shadow_dir(f: &SpecFixture, name: &str) -> PathBuf {
    let path = f.file(&format!("shadow/{name}"), "not a program");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    path.parent().unwrap().to_path_buf()
}

/// The bare name the probe's provisioned directory makes runnable through
/// `PATH`, the directory to put in `PATH`, and the arguments after the name
/// that run the probe.
///
/// The probe's copy is dynamically linked against host paths the sandbox
/// does not see (its `PT_INTERP`), so run by name it would fail with
/// `ENOENT`. The copied loader is static and runs it from its own
/// directory, so the loader's name is looked up instead. For a static probe
/// it is `stopit` itself.
fn bare_name() -> (String, PathBuf, Vec<String>) {
    let (probe_dir, probe) = probe_at_host_path();
    if probe.len() == 1 {
        return ("stopit".into(), probe_dir, Vec::new());
    }
    let loader = Path::new(&probe[0]);
    let name = loader.file_name().unwrap().to_str().unwrap().to_owned();
    let rest = probe[1..]
        .iter()
        .map(|a| a.to_str().unwrap().to_owned())
        .collect();
    (name, loader.parent().unwrap().to_path_buf(), rest)
}

#[test]
fn a_bare_command_is_looked_up_in_the_targets_path() {
    let (name, bin_dir, rest) = bare_name();
    // Searched in order: a missing directory, empty entries, a
    // non-executable file of that name (skipped, as `execvpe` does), then
    // the real one.
    let f = SpecFixture::new();
    let shadow = shadow_dir(&f, &name);
    let init = Init::in_fixture(f, &[&shadow]);
    let path = format!(
        "/nonexistent::{}:{}:",
        shadow.to_str().unwrap(),
        bin_dir.to_str().unwrap()
    );
    let env = vars(&[("PATH", &path), ("OTHER", "x")]);
    let mut argv = vec![OsString::from(&name)];
    argv.extend(rest.iter().map(OsString::from));
    argv.push("arg".into());
    let results = init
        .session
        .run_probe(&init.spec, &env, &argv, &[Op::Env, Op::Argv]);
    assert_eq!(ok(&results[0]), &env_data(&env));
    let Data::Argv(seen) = ok(&results[1]) else {
        panic!("{:?}", results[1])
    };
    assert_eq!(seen.last().map(String::as_str), Some("arg"), "{seen:?}");
}

#[test]
fn a_bare_command_found_only_unexecutable_cannot_be_executed() {
    let f = SpecFixture::new();
    let shadow = shadow_dir(&f, "tool");
    let init = Init::in_fixture(f, &[&shadow]);
    let path = format!("/nonexistent:{}", shadow.to_str().unwrap());
    let out = init.run(&vars(&[("PATH", &path)]), &["tool"]);
    assert_eq!(code(&out), i32::from(EXIT_CANNOT_EXECUTE), "{out:?}");
    assert!(
        stderr(&out).starts_with("stopit __init: tool: Permission denied"),
        "{out:?}"
    );
}

#[test]
fn a_missing_command_is_127_with_its_name_escaped() {
    let init = Init::new();
    let out = init.run(
        &vars(&[("PATH", "/nonexistent:/also-not")]),
        &["no\x1b[31msuch\nthing"],
    );
    assert_eq!(code(&out), i32::from(EXIT_NOT_FOUND), "{out:?}");
    assert_eq!(
        stderr(&out),
        "stopit __init: no\\u{1b}[31msuch\\nthing: not found in PATH\n"
    );
    assert!(out.stdout.is_empty(), "{out:?}");
}

#[test]
fn a_bare_command_without_path_is_not_found() {
    // There is no default search path.
    let init = Init::new();
    let (name, ..) = bare_name();
    let out = init.run(&vars(&[("HOME", "/")]), &[&name]);
    assert_eq!(code(&out), i32::from(EXIT_NOT_FOUND), "{out:?}");
    assert_eq!(
        stderr(&out),
        format!("stopit __init: {name}: not found (the environment has no PATH)\n")
    );
}

#[test]
fn a_command_with_a_slash_is_not_looked_up() {
    let init = Init::new();
    let (_, bin_dir, _) = bare_name();
    // A path is run as given, never looked up in `PATH`.
    let path = vars(&[("PATH", bin_dir.to_str().unwrap())]);
    let out = init.run(&path, &["./missing"]);
    assert_eq!(code(&out), i32::from(EXIT_NOT_FOUND), "{out:?}");
    assert!(
        stderr(&out).starts_with("stopit __init: ./missing: No such file or directory"),
        "{out:?}"
    );
    // A directory cannot be executed.
    let out = init.run(&path, &["/proc"]);
    assert_eq!(code(&out), i32::from(EXIT_CANNOT_EXECUTE), "{out:?}");
    assert!(stderr(&out).contains("Permission denied"), "{out:?}");
}

#[test]
fn bad_init_arguments_fail_before_running_anything() {
    // Through the generic constructor, which runs whatever follows the
    // provisioned binary's prefix.
    let init = Init::new();
    let run = |argv: &[&str]| {
        let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
        let cmd = stopit::bwrap::BwrapCommand::new(
            &init.spec,
            &init.session.session,
            &init.session.provisioned,
            Path::new("/"),
            &argv,
            stopit::bwrap::TerminalSession::Keep,
        )
        .unwrap();
        run_bwrap(cmd.into_command(), None)
    };
    let out = run(&["__init", "--env-fd", "x", "--spec-fd", "4", "--", "/proc"]);
    assert_eq!(code(&out), i32::from(EXIT_INIT_FAILED), "{out:?}");
    assert!(
        stderr(&out).starts_with("stopit __init: --env-fd \"x\" is not a descriptor number"),
        "{out:?}"
    );
    let out = run(&["__init", "--env-fd", "3", "--", "/proc"]);
    assert_eq!(code(&out), i32::from(EXIT_INIT_FAILED), "{out:?}");
    assert!(
        stderr(&out).contains("expected --spec-fd M after --env-fd N"),
        "{out:?}"
    );
    let out = run(&["__init", "--env-fd", "3", "--spec-fd", "3", "--", "/proc"]);
    assert_eq!(code(&out), i32::from(EXIT_INIT_FAILED), "{out:?}");
    assert!(
        stderr(&out).contains("name the same descriptor 3"),
        "{out:?}"
    );
    let out = run(&["__init", "--env-fd", "3", "--spec-fd", "4", "--"]);
    assert_eq!(code(&out), i32::from(EXIT_INIT_FAILED), "{out:?}");
    assert!(stderr(&out).contains("no command after --"), "{out:?}");
    // Descriptor numbers far above RLIMIT_NOFILE cannot collide with bwrap's
    // own inherited descriptors.
    let out = run(&[
        "__init",
        "--env-fd",
        "2147483646",
        "--spec-fd",
        "2147483647",
        "--",
        "/proc",
    ]);
    assert_eq!(code(&out), i32::from(EXIT_INIT_FAILED), "{out:?}");
    assert!(
        stderr(&out)
            .starts_with("stopit __init: cannot read the environment from descriptor 2147483646"),
        "{out:?}"
    );
}

#[test]
fn invalid_spec_json_and_missing_landlock_path_exit_125_without_running_target() {
    use std::io::{Seek, SeekFrom, Write};
    use stopit::init::{InitSpec, encode_spec};
    use stopit::landlock::{ACCESS_FS_READ_DIR, LandlockPathRule};

    let init = Init::new();
    let spec = init.f.compile(&init_config(
        &[],
        "fs.rw = [\"{workspace}\"]\nnetwork = { mode = \"loopback\" }",
    ));
    let marker = init.f.workspace().join("target-ran");
    let ops = [write("/workspace/target-ran", "ran")];
    let stdin = serde_json::to_vec(&ops).unwrap();

    let run_with_spec_bytes = |spec_bytes: &[u8]| -> Output {
        let env_mem = memfd_create("stopit-test-env", MemfdFlags::CLOEXEC).unwrap();
        let mut spec_mem =
            std::fs::File::from(memfd_create("stopit-test-spec", MemfdFlags::CLOEXEC).unwrap());
        spec_mem.write_all(spec_bytes).unwrap();
        spec_mem.seek(SeekFrom::Start(0)).unwrap();

        let env_fd = rustix::io::fcntl_dupfd_cloexec(&env_mem, 64).unwrap();
        let spec_fd = rustix::io::fcntl_dupfd_cloexec(&spec_mem, 65).unwrap();
        let mut argv: Vec<OsString> = vec![
            "__init".into(),
            "--env-fd".into(),
            env_fd.as_raw_fd().to_string().into(),
            "--spec-fd".into(),
            spec_fd.as_raw_fd().to_string().into(),
            "--".into(),
        ];
        argv.extend(init.probe.iter().cloned());
        let cmd = BwrapCommand::new(
            &spec,
            &init.session.session,
            &init.session.provisioned,
            Path::new("/workspace"),
            &argv,
            stopit::bwrap::TerminalSession::Keep,
        )
        .unwrap();
        let cmd = leaking_fd(
            leaking_fd(cmd.into_command(), env_fd.as_raw_fd()),
            spec_fd.as_raw_fd(),
        );
        run_bwrap(cmd, Some(&stdin))
    };

    let out = run_with_spec_bytes(b"{not valid json");
    assert_eq!(code(&out), i32::from(EXIT_INIT_FAILED), "{out:?}");
    assert!(
        stderr(&out).contains("invalid init specification JSON"),
        "{out:?}"
    );
    assert!(out.stdout.is_empty(), "{out:?}");
    assert!(!marker.exists(), "target ran despite invalid spec JSON");

    let mut missing_rule_spec = InitSpec::from_sandbox_spec(&spec);
    missing_rule_spec.landlock.rules.push(LandlockPathRule {
        path: PathBuf::from("/missing-sandbox-landlock-path"),
        access: ACCESS_FS_READ_DIR,
    });
    let out = run_with_spec_bytes(&encode_spec(&missing_rule_spec).unwrap());
    assert_eq!(code(&out), i32::from(EXIT_INIT_FAILED), "{out:?}");
    assert!(
        stderr(&out).starts_with("stopit __init: cannot apply Landlock policy:"),
        "{out:?}"
    );
    assert!(
        stderr(&out).contains("/missing-sandbox-landlock-path"),
        "{out:?}"
    );
    assert!(out.stdout.is_empty(), "{out:?}");
    assert!(
        !marker.exists(),
        "target ran despite missing Landlock rule path"
    );
}

// --- Network loopback teardown and capability zeroing ---

/// Asserts that all five capability masks in `/proc/self/status` are zero.
#[track_caller]
fn assert_all_capabilities_zero(status: &str) {
    for field in ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"] {
        let value = status
            .lines()
            .find_map(|line| line.strip_prefix(field))
            .unwrap_or_else(|| panic!("missing {field} in status:\n{status}"))
            .trim();
        assert_eq!(value, "0000000000000000", "{field} non-zero in:\n{status}");
    }
}

#[test]
fn network_none_takes_loopback_down_blocks_tcp_and_zeros_capabilities() {
    let init = Init::new();
    let results = init.probe(
        &[],
        &[],
        &[
            Op::LoFlags,
            Op::TcpLoopbackRoundtrip,
            read("/proc/self/status"),
        ],
    );
    let Data::Flags(flags) = ok(&results[0]) else {
        panic!("expected flags, got {:?}", results[0]);
    };
    assert_eq!(
        flags & libc::IFF_UP,
        0,
        "expected lo down for network = none, got flags {flags:#x}"
    );
    let tcp_err = errno(&results[1]);
    assert!(
        matches!(tcp_err, "EACCES" | "ENETUNREACH" | "EADDRNOTAVAIL"),
        "unexpected loopback TCP error: {:?}",
        results[1]
    );
    assert_all_capabilities_zero(contents(&results[2]));
}

#[test]
fn network_loopback_keeps_lo_up_allows_tcp_and_zeros_capabilities() {
    let mut init = Init::new();
    init.spec = init
        .f
        .compile(&init_config(&[], "network = { mode = \"loopback\" }"));
    let results = init.probe(
        &[],
        &[],
        &[
            Op::LoFlags,
            Op::TcpLoopbackRoundtrip,
            read("/proc/self/status"),
        ],
    );
    let Data::Flags(flags) = ok(&results[0]) else {
        panic!("expected flags, got {:?}", results[0]);
    };
    assert_ne!(
        flags & libc::IFF_UP,
        0,
        "expected lo up for network = loopback, got flags {flags:#x}"
    );
    assert_eq!(ok(&results[1]), &Data::Done);
    assert_all_capabilities_zero(contents(&results[2]));
}

// --- Seccomp enforcement ---

#[test]
fn seccomp_blocks_clone3_with_enosys_while_child_spawning_works() {
    let init = Init::new();
    let mut nested_cmd = init.probe.clone();
    let nested_prog = nested_cmd.remove(0).into_string().unwrap();
    let nested_args: Vec<String> = nested_cmd
        .into_iter()
        .map(|a| a.into_string().unwrap())
        .collect();
    let nested_stdin = serde_json::to_string(&[Op::Cwd]).unwrap();

    let results = init.probe(
        &[],
        &[],
        &[
            Op::Syscall {
                call: SyscallProbe::Clone3,
            },
            Op::Exec {
                path: nested_prog,
                args: nested_args,
                stdin: Some(nested_stdin),
            },
        ],
    );
    assert_eq!(errno(&results[0]), "ENOSYS");
    let Data::Exec(out) = ok(&results[1]) else {
        panic!("expected exec output, got {:?}", results[1]);
    };
    assert_eq!(out.code, Some(0), "{out:?}");
    let nested: Vec<OpResult> = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(nested, [Ok(Data::Cwd("/".into()))]);
}

#[test]
fn seccomp_blocks_namespace_and_mount_syscalls() {
    let init = Init::new();
    let probes = [
        SyscallProbe::UnshareUser,
        SyscallProbe::CloneNewuser,
        SyscallProbe::Setns,
        SyscallProbe::Mount,
        SyscallProbe::Umount2,
        SyscallProbe::OpenTree,
        SyscallProbe::Fsopen,
    ];
    let ops: Vec<Op> = probes.iter().map(|&call| Op::Syscall { call }).collect();
    let results = init.probe(&[], &[], &ops);
    for (call, result) in probes.iter().zip(&results) {
        assert_eq!(errno(result), "EPERM", "{call:?}: {result:?}");
    }
}

#[test]
fn seccomp_blocks_opt_in_syscalls_by_default_and_allows_selected_group_only() {
    let mut init = Init::new();
    let gated = [
        SyscallProbe::IoUringSetup,
        SyscallProbe::Bpf,
        SyscallProbe::PerfEventOpen,
        SyscallProbe::Userfaultfd,
        SyscallProbe::Keyctl,
        SyscallProbe::AddKey,
        SyscallProbe::RequestKey,
        SyscallProbe::PtraceTraceme,
    ];
    let ops: Vec<Op> = gated.iter().map(|&call| Op::Syscall { call }).collect();
    let default_results = init.probe(&[], &[], &ops);
    for (call, result) in gated.iter().zip(&default_results) {
        assert_eq!(errno(result), "EPERM", "{call:?}: {result:?}");
    }

    init.spec = init
        .f
        .compile(&init_config(&[], "sandbox.allow_syscalls = [\"ptrace\"]"));
    let ptrace_results = init.probe(&[], &[], &ops);
    for (call, result) in gated[..7].iter().zip(&ptrace_results[..7]) {
        assert_eq!(errno(result), "EPERM", "{call:?}: {result:?}");
    }
    assert_eq!(ok(&ptrace_results[7]), &Data::Done);
}

#[test]
fn seccomp_blocks_terminal_injection_ioctls_including_high_bit_stuffing() {
    let init = Init::new();
    let probes = [
        SyscallProbe::IoctlTiocsti,
        SyscallProbe::IoctlTiocstiHighBit,
        SyscallProbe::IoctlTioclinux,
        SyscallProbe::IoctlTioclinuxHighBit,
    ];
    let ops: Vec<Op> = probes.iter().map(|&call| Op::Syscall { call }).collect();
    let results = init.probe(&[], &[], &ops);
    for (call, result) in probes.iter().zip(&results) {
        assert_eq!(errno(result), "EPERM", "{call:?}: {result:?}");
    }
}

#[test]
fn seccomp_restricts_socket_families_and_netlink_protocols() {
    let init = Init::new();
    let results = init.probe(
        &[],
        &[],
        &[
            Op::Socket {
                domain: libc::AF_VSOCK,
                ty: libc::SOCK_STREAM,
                protocol: 0,
            },
            Op::Socket {
                domain: libc::AF_PACKET,
                ty: libc::SOCK_RAW,
                protocol: 0,
            },
            Op::Socket {
                domain: libc::AF_NETLINK,
                ty: libc::SOCK_RAW,
                protocol: libc::NETLINK_KOBJECT_UEVENT,
            },
            Op::Socket {
                domain: libc::AF_UNIX,
                ty: libc::SOCK_STREAM,
                protocol: 0,
            },
            Op::Socket {
                domain: libc::AF_INET,
                ty: libc::SOCK_DGRAM,
                protocol: 0,
            },
            Op::Socket {
                domain: libc::AF_INET6,
                ty: libc::SOCK_DGRAM,
                protocol: 0,
            },
            Op::Socket {
                domain: libc::AF_NETLINK,
                ty: libc::SOCK_RAW,
                protocol: libc::NETLINK_ROUTE,
            },
        ],
    );
    assert_eq!(errno(&results[0]), "EPERM", "{:?}", results[0]);
    assert_eq!(errno(&results[1]), "EPERM", "{:?}", results[1]);
    assert_eq!(errno(&results[2]), "EPERM", "{:?}", results[2]);
    for result in &results[3..] {
        assert_eq!(ok(result), &Data::Done, "{result:?}");
    }
}

// --- Landlock enforcement ---

#[test]
fn landlock_allows_cross_directory_rename_in_rw_workspace() {
    let mut init = Init::new();
    init.spec = init
        .f
        .compile(&init_config(&[], "fs.rw = [\"{workspace}\"]"));
    let results = init.probe(
        &[],
        &[],
        &[
            mkdir("/workspace/a"),
            mkdir("/workspace/b"),
            write("/workspace/a/file", "moved across directories"),
            rename("/workspace/a/file", "/workspace/b/file"),
            read("/workspace/b/file"),
        ],
    );
    for result in &results[..4] {
        assert_eq!(ok(result), &Data::Done, "{result:?}");
    }
    assert_eq!(contents(&results[4]), "moved across directories");
    assert_eq!(
        fs::read_to_string(init.f.workspace().join("b/file")).unwrap(),
        "moved across directories"
    );
    assert!(!init.f.workspace().join("a/file").exists());
}

#[test]
fn landlock_handles_single_file_ro_mount_and_minimal_dev_null_writes() {
    let f = SpecFixture::new();
    let single = f.file("outside/single.txt", "single file content");
    let unmounted = f.file("outside/unmounted.txt", "hidden");
    let spec = f.compile(&init_config(&[&single], "system.dev = \"minimal\""));
    let session = f.init_session();
    let (_, probe) = probe_at_host_path();
    let results = session.run_probe(
        &spec,
        &[],
        &probe,
        &[
            read(&single),
            write(&single, "blocked"),
            write("/dev/null", "discarded"),
            read(&unmounted),
        ],
    );
    assert_eq!(contents(&results[0]), "single file content");
    let write_err = errno(&results[1]);
    assert!(
        matches!(write_err, "EROFS" | "EACCES"),
        "expected read-only failure on single file mount, got {:?}",
        results[1]
    );
    assert_eq!(ok(&results[2]), &Data::Done);
    assert_eq!(errno(&results[3]), "ENOENT");
}

/// Binds an abstract Unix stream listener `\0<name>` on the host and keeps it
/// open until dropped.
fn bind_abstract_listener(name: &str) -> std::os::fd::OwnedFd {
    // SAFETY: `socket` creates a fresh descriptor or returns `-1`.
    let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    assert!(
        raw >= 0,
        "socket failed: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: `raw` is owned exclusively here.
    let sock = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
    // SAFETY: zeroed `sockaddr_un` sets `sun_path[0] = 0` for abstract names.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    unsafe {
        let base = std::ptr::addr_of_mut!(addr.sun_path).cast::<u8>();
        std::ptr::copy_nonoverlapping(name.as_ptr(), base.add(1), name.len());
    }
    let addrlen =
        (std::mem::offset_of!(libc::sockaddr_un, sun_path) + 1 + name.len()) as libc::socklen_t;
    // SAFETY: valid socket and abstract `sockaddr_un`.
    let bind_rc = unsafe {
        libc::bind(
            sock.as_raw_fd(),
            std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
            addrlen,
        )
    };
    assert_eq!(
        bind_rc,
        0,
        "bind abstract socket {name:?} failed: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: valid bound stream socket.
    let listen_rc = unsafe { libc::listen(sock.as_raw_fd(), 4) };
    assert_eq!(
        listen_rc,
        0,
        "listen abstract socket {name:?} failed: {}",
        std::io::Error::last_os_error()
    );
    sock
}

#[test]
fn landlock_and_netns_block_host_abstract_unix_socket() {
    let unique = format!(
        "stopit-abstract-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let _listener = bind_abstract_listener(&unique);

    let mut init = Init::new();
    init.spec = init
        .f
        .compile(&init_config(&[], "network = { mode = \"loopback\" }"));
    let loopback_res = init.probe(
        &[],
        &[],
        &[Op::ConnectAbstract {
            name: unique.clone(),
        }],
    );
    let loopback_err = errno(&loopback_res[0]);
    assert!(
        matches!(loopback_err, "ECONNREFUSED" | "EPERM"),
        "expected host abstract socket to be unreachable in loopback mode, got {:?}",
        loopback_res[0]
    );

    // Network mode `full` has a network namespace of its own, which pasta
    // connects (here, without pasta, it has no network at all). The host's
    // abstract sockets are not in it.
    init.spec = init
        .f
        .compile(&init_config(&[], "network = { mode = \"full\" }"));
    let full_res = init.probe(
        &[],
        &[],
        &[Op::ConnectAbstract {
            name: unique.clone(),
        }],
    );
    assert_eq!(
        errno(&full_res[0]),
        "ECONNREFUSED",
        "expected host abstract socket to be unreachable in full mode, got {:?}",
        full_res[0]
    );
}
