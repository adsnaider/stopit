//! `stopit run` end to end: the real binary, run as a user would, from a
//! temporary workspace, with a private `XDG_RUNTIME_DIR` and a minimal
//! environment. It finds the configuration, runs the providers, compiles
//! the session, provisions itself and runs `stopit-probe` in the sandbox
//! through bwrap and `__init`. The probe is run from its provisioned
//! directory at its host path, which each configuration grants `ro`.

mod common;

use std::collections::{BTreeMap, HashMap};
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use tempfile::TempDir;

use common::*;

/// A user's setup: a workspace, a home, and a private runtime directory,
/// all below one canonical temporary directory.
struct Setup {
    _dir: TempDir,
    root: PathBuf,
}

impl Setup {
    fn new() -> Self {
        let tmp = fs::canonicalize(std::env::temp_dir()).unwrap();
        let dir = TempDir::new_in(tmp).unwrap();
        let root = dir.path().to_path_buf();
        for sub in ["ws", "home", "runtime"] {
            fs::create_dir(root.join(sub)).unwrap();
        }
        fs::set_permissions(root.join("runtime"), fs::Permissions::from_mode(0o700)).unwrap();
        // Whatever the umask: stopit refuses a configuration in a directory
        // others can write.
        fs::set_permissions(root.join("ws"), fs::Permissions::from_mode(0o755)).unwrap();
        Setup { _dir: dir, root }
    }

    /// With `.stopit.toml` holding [`probe_config`] plus `extra`.
    fn with_config(extra: &str) -> Self {
        let s = Self::new();
        s.write_config(extra);
        s
    }

    fn ws(&self) -> PathBuf {
        self.root.join("ws")
    }

    fn runtime(&self) -> PathBuf {
        self.root.join("runtime")
    }

    fn write_config(&self, extra: &str) {
        self.write_raw_config(&probe_config(extra));
    }

    /// Writes `contents` as `.stopit.toml`, private to the user whatever the
    /// umask (stopit refuses one others can write).
    fn write_raw_config(&self, contents: &str) {
        let path = self.ws().join(".stopit.toml");
        fs::write(&path, contents).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    }

    /// `stopit <args…>` from the workspace, with only `XDG_RUNTIME_DIR`,
    /// `HOME` and `PATH` (to find bwrap) in its environment.
    fn stopit<S: AsRef<std::ffi::OsStr>>(&self, args: &[S]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_stopit"));
        command
            .args(args)
            .current_dir(self.ws())
            .env_clear()
            .env("XDG_RUNTIME_DIR", self.runtime())
            .env("HOME", self.root.join("home"))
            .env("PATH", std::env::var_os("PATH").unwrap_or_default());
        command
    }

    /// `stopit run <options…> <probe>`: [`stopit`](Self::stopit) with the
    /// probe's argv after `options`.
    fn run_probe_command(&self, options: &[&str]) -> Command {
        let mut command = self.stopit(&[&["run"][..], options].concat());
        command.args(probe_argv());
        command
    }

    /// Runs `command`, which runs the probe, with `ops` as its input, and
    /// checks that stopit printed nothing of its own.
    fn probe_with(&self, command: Command, ops: &[Op]) -> Vec<OpResult> {
        let what = format!("{command:?}");
        let input = serde_json::to_vec(ops).unwrap();
        let out = output(command, &input);
        let results = probe_results(&what, &out, ops);
        assert_eq!(stderr(&out), "", "{what}");
        results
    }

    /// `stopit run <options…> <probe>` from the workspace, with `ops`.
    fn probe(&self, options: &[&str], ops: &[Op]) -> Vec<OpResult> {
        self.probe_with(self.run_probe_command(options), ops)
    }

    /// Whether the runtime directory holds no session directory.
    fn no_session_left(&self) -> bool {
        let base = self.runtime().join("stopit");
        fs::read_dir(&base)
            .unwrap_or_else(|e| panic!("{base:?}: {e}"))
            .next()
            .is_none()
    }
}

/// A `.stopit.toml` under the default base with one more provider granting
/// the probe's directory `ro` at its host path, then `extra`.
fn probe_config(extra: &str) -> String {
    let (probe_dir, _) = probe_at_host_path();
    format!(
        "[[provider]]\ntype = \"config\"\nname = \"tools\"\n[provider.sandbox]\n\
         fs.ro = [\"{}\"]\n{extra}\n",
        probe_dir.to_str().unwrap()
    )
}

/// The argv that runs the probe from its host path.
fn probe_argv() -> Vec<OsString> {
    probe_at_host_path().1
}

/// Runs `command` with `stdin`, killing it at the usual deadline.
fn output(command: Command, stdin: &[u8]) -> Output {
    run_bwrap(command, Some(stdin))
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[track_caller]
fn code(out: &Output) -> i32 {
    out.status
        .code()
        .unwrap_or_else(|| panic!("killed: {out:?}"))
}

fn env_data(pairs: &[(&str, &str)]) -> Data {
    Data::Env(
        pairs
            .iter()
            .map(|&(k, v)| (k.to_owned(), v.to_owned()))
            .collect::<BTreeMap<_, _>>(),
    )
}

// --- Running, stdio, exit status ---

#[test]
fn stdin_and_stdout_reach_the_command_in_the_workspace() {
    let s = Setup::with_config("");
    fs::write(s.ws().join("a"), "host a").unwrap();
    let ops: Vec<Op> = std::iter::once(read("/workspace/a"))
        .chain((0..100).map(|_| Op::Cwd))
        .collect();
    let results = s.probe(&[], &ops);
    assert_eq!(contents(&results[0]), "host a");
    assert!(
        results[1..]
            .iter()
            .all(|r| ok(r) == &Data::Cwd("/workspace".into()))
    );
    assert!(s.no_session_left());
}

#[test]
fn the_commands_exit_status_is_stopits() {
    // The probe exits with 2 on input that is not an operation list.
    let s = Setup::with_config("");
    let out = output(s.run_probe_command(&[]), b"not json");
    assert_eq!(code(&out), 2, "{out:?}");
    assert!(
        stderr(&out).contains("stdin is not a JSON array"),
        "{out:?}"
    );
    assert!(s.no_session_left());
}

#[test]
fn arguments_after_the_command_are_the_commands() {
    let s = Setup::with_config("");
    // Flag-like arguments, stopit's own included, pass through unchanged.
    let extra = ["-la", "--profile", "x", "--", ""];
    let mut command = s.run_probe_command(&["--"]);
    command.args(extra);
    let results = s.probe_with(command, &[Op::Argv]);
    let Data::Argv(argv) = ok(&results[0]) else {
        panic!("{results:?}")
    };
    assert_eq!(argv[argv.len() - extra.len()..], extra);
}

#[test]
fn a_missing_command_is_127_with_an_escaped_message() {
    let s = Setup::with_config("");
    let out = output(s.stopit(&["run", "no\x1b[31msuch"]), b"");
    assert_eq!(code(&out), 127, "{out:?}");
    // The default base grants no `PATH`.
    assert_eq!(
        stderr(&out),
        "stopit __init: no\\u{1b}[31msuch: not found (the environment has no PATH)\n"
    );
    assert!(out.stdout.is_empty(), "{out:?}");
    assert!(s.no_session_left());
}

// --- What the sandbox sees ---

#[test]
fn the_workspace_is_mounted_writable_and_writes_persist() {
    let s = Setup::with_config("");
    let results = s.probe(
        &[],
        &[
            write("/workspace/new", "from the sandbox"),
            mkdir("/workspace/dir"),
            write("/workspace/dir/f", "nested"),
        ],
    );
    for r in &results {
        assert_eq!(ok(r), &Data::Done);
    }
    assert_eq!(
        fs::read_to_string(s.ws().join("new")).unwrap(),
        "from the sandbox"
    );
    assert_eq!(fs::read_to_string(s.ws().join("dir/f")).unwrap(), "nested");
}

#[test]
fn the_environment_is_filtered() {
    let s = Setup::with_config("");
    let mut command = s.run_probe_command(&[]);
    command
        .env("GITHUB_TOKEN", "ghp_secret")
        .env("TERM", "xterm-test")
        .env("EDITOR", "nvim");
    let results = s.probe_with(command, &[Op::Env]);
    // Not `GITHUB_TOKEN` (denied), `EDITOR` (not passed), nor the host's
    // `HOME`, `PATH` or `XDG_RUNTIME_DIR`; the sandbox's own identity.
    assert_eq!(
        ok(&results[0]),
        &env_data(&[
            ("HOME", "/home/user"),
            ("LOGNAME", "user"),
            ("TERM", "xterm-test"),
            ("USER", "user"),
        ])
    );
}

#[test]
fn profile_selects_another_profile() {
    let s = Setup::with_config(
        "env.set = { WHICH = \"main\" }\n\
         [profiles.other]\n\
         [[provider]]\ntype = \"config\"\nname = \"other\"\nprofile = \"other\"\n\
         [provider.sandbox]\nenv.set = { WHICH = \"other\" }\n",
    );
    let which = |options: &[&str]| {
        let results = s.probe(options, &[Op::Env]);
        let Data::Env(env) = ok(&results[0]) else {
            panic!("{results:?}")
        };
        env["WHICH"].clone()
    };
    assert_eq!(which(&[]), "main");
    assert_eq!(which(&["--profile", "main"]), "main");
    assert_eq!(which(&["--profile", "other"]), "other");
}

#[test]
fn an_unknown_profile_names_the_profiles() {
    let s = Setup::with_config("[profiles.other]\n");
    let out = output(s.run_probe_command(&["--profile", "nope"]), b"[]");
    assert_eq!(code(&out), 125, "{out:?}");
    assert_eq!(
        stderr(&out),
        "stopit: error: there is no profile \"nope\"; the profiles are: main, other\n"
    );
    assert!(out.stdout.is_empty(), "{out:?}");
    assert!(s.no_session_left());
}

// --- Workspace discovery ---

#[test]
fn a_subdirectory_finds_the_workspace_above_it() {
    let s = Setup::with_config("");
    fs::create_dir_all(s.ws().join("sub/deeper")).unwrap();
    fs::write(s.ws().join("marker"), "top").unwrap();
    let mut command = s.run_probe_command(&[]);
    command.current_dir(s.ws().join("sub/deeper"));
    let results = s.probe_with(command, &[Op::Cwd, read("/workspace/marker")]);
    // The workspace is the directory with the configuration, and the
    // sandbox starts at its mount.
    assert_eq!(ok(&results[0]), &Data::Cwd("/workspace".into()));
    assert_eq!(contents(&results[1]), "top");
}

#[test]
fn the_workspace_option_is_canonicalized() {
    // Given through a symlink, the workspace is still resolved to its real
    // path: were `{workspace}` a link, the default base's masking globs
    // would not walk below it, and `.env` would be readable.
    let s = Setup::with_config("");
    fs::create_dir(s.ws().join("sub")).unwrap();
    fs::write(s.ws().join("sub/.env"), "SECRET=1").unwrap();
    symlink(s.ws(), s.root.join("link")).unwrap();
    let mut command = s.run_probe_command(&["--workspace", "../link/./sub/.."]);
    command.current_dir(s.root.join("home"));
    let results = s.probe_with(
        command,
        &[read("/workspace/sub/.env"), stat("/workspace/sub/.env")],
    );
    assert_eq!(errno(&results[0]), "EACCES", "{results:?}");
    assert_eq!(stat_data(&results[1]).size, 0, "{results:?}");
}

#[test]
fn no_configuration_runs_the_default_base_in_the_cwd() {
    // Without a `.stopit.toml` the default base applies: nothing grants the
    // probe, so it is not found.
    let s = Setup::new();
    let out = output(s.run_probe_command(&[]), b"[]");
    assert_eq!(code(&out), 127, "{out:?}");
    assert!(stderr(&out).starts_with("stopit __init: "), "{out:?}");
    assert!(
        stderr(&out).contains("No such file or directory"),
        "{out:?}"
    );
}

// --- What runs on the host next session ---

#[test]
fn a_script_provider_in_the_workspace_cannot_be_rewritten_by_the_sandbox() {
    let s = Setup::new();
    let script = "#!/bin/sh\nprintf '{\"version\":1}'\n";
    fs::create_dir(s.ws().join("scripts")).unwrap();
    let path = s.ws().join("scripts/env.sh");
    fs::write(&path, script).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    s.write_config(
        "[[provider]]\ntype = \"script\"\nname = \"env\"\nsource = \"scripts/env.sh\"\n",
    );
    let results = s.probe(
        &[],
        &[
            write("/workspace/scripts/env.sh", "#!/bin/sh\necho pwned\n"),
            append("/workspace/scripts/env.sh", "echo pwned\n"),
            chmod("/workspace/scripts/env.sh", 0o777),
            remove("/workspace/scripts/env.sh"),
            rename("/workspace/scripts/env.sh", "/workspace/scripts/old.sh"),
            // Its directory is the workspace's, still writable.
            write("/workspace/scripts/notes", "x"),
            read("/workspace/scripts/env.sh"),
        ],
    );
    for r in &results[..3] {
        assert_eq!(errno(r), "EROFS", "{results:?}");
    }
    // It is a mount point.
    for r in &results[3..5] {
        assert_eq!(errno(r), "EBUSY", "{results:?}");
    }
    assert_eq!(ok(&results[5]), &Data::Done, "{results:?}");
    assert_eq!(contents(&results[6]), script);
    assert_eq!(fs::read_to_string(&path).unwrap(), script);
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
        0o755
    );
}

#[test]
fn a_script_provider_reached_through_a_workspace_link_is_refused() {
    // A sandbox could have replaced `scripts` with a link to code of its
    // own: the script is not run.
    let s = Setup::new();
    fs::create_dir(s.root.join("real")).unwrap();
    let path = s.root.join("real/env.sh");
    fs::write(&path, "#!/bin/sh\ntouch ran\nprintf '{\"version\":1}'\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    symlink(s.root.join("real"), s.ws().join("scripts")).unwrap();
    s.write_config(
        "[[provider]]\ntype = \"script\"\nname = \"env\"\nsource = \"scripts/env.sh\"\n",
    );
    let out = output(s.run_probe_command(&[]), b"[]");
    assert_eq!(code(&out), 125, "{out:?}");
    let err = stderr(&out);
    assert!(
        err.starts_with("stopit: error: refusing to run script provider \"env\""),
        "{err}"
    );
    assert!(
        err.contains(&format!("symlink {}", s.ws().join("scripts").display())),
        "{err}"
    );
    assert!(!s.ws().join("ran").exists());
    assert!(s.no_session_left());
}

#[test]
fn configurations_in_the_workspace_cannot_be_written_by_the_sandbox() {
    let s = Setup::with_config("");
    fs::create_dir(s.ws().join("sub")).unwrap();
    fs::write(s.ws().join("sub/.stopit.toml"), "base = \"none\"\n").unwrap();
    let top = fs::read_to_string(s.ws().join(".stopit.toml")).unwrap();
    let results = s.probe(
        &[],
        &[
            write("/workspace/.stopit.toml", "base = \"none\"\n"),
            write("/workspace/sub/.stopit.toml", "[[provider]]\n"),
        ],
    );
    for r in &results {
        assert_eq!(errno(r), "EROFS", "{results:?}");
    }
    assert_eq!(
        fs::read_to_string(s.ws().join(".stopit.toml")).unwrap(),
        top
    );
    assert_eq!(
        fs::read_to_string(s.ws().join("sub/.stopit.toml")).unwrap(),
        "base = \"none\"\n"
    );
}

#[test]
fn the_loaded_configuration_is_protected_without_the_default_base() {
    // No base rule protects it, and the workspace is granted `rw`: the
    // supervisor protects it anyway.
    let s = Setup::new();
    let config = format!(
        "base = \"none\"\n{}",
        probe_config("fs.rw = [\"{workspace}\"]")
    );
    s.write_raw_config(&config);
    let results = s.probe(
        &[],
        &[
            write("/workspace/.stopit.toml", "base = \"none\"\n"),
            append("/workspace/.stopit.toml", "[[provider]]\n"),
            write("/workspace/notes", "x"),
        ],
    );
    for r in &results[..2] {
        assert_eq!(errno(r), "EROFS", "{results:?}");
    }
    assert_eq!(ok(&results[2]), &Data::Done, "{results:?}");
    assert_eq!(
        fs::read_to_string(s.ws().join(".stopit.toml")).unwrap(),
        config
    );
}

#[test]
fn a_hard_linked_script_provider_is_refused() {
    let s = Setup::new();
    let path = s.ws().join("env.sh");
    // It marks the host when it runs.
    fs::write(&path, "#!/bin/sh\ntouch ran\nprintf '{\"version\":1}'\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    // Another name for it, which the sandbox could have written through.
    fs::hard_link(&path, s.ws().join("other.sh")).unwrap();
    s.write_config("[[provider]]\ntype = \"script\"\nname = \"env\"\nsource = \"env.sh\"\n");
    let out = output(s.run_probe_command(&[]), b"[]");
    assert_eq!(code(&out), 125, "{out:?}");
    let err = stderr(&out);
    assert!(
        err.starts_with("stopit: error: refusing to run script provider \"env\""),
        "{err}"
    );
    assert!(err.contains("2 hard links"), "{err}");
    assert!(!s.ws().join("ran").exists(), "the script ran");
    assert!(s.no_session_left());
    // With a single link, it runs.
    fs::remove_file(s.ws().join("other.sh")).unwrap();
    s.probe(&[], &[]);
    assert!(s.ws().join("ran").exists());
}

#[test]
fn a_configuration_planted_below_the_workspace_is_refused() {
    let s = Setup::with_config("");
    // The sandbox can create one where none exists: a glob protects only
    // what exists at the start.
    let planted = "[[provider]]\ntype = \"script\"\nsource = \"/bin/false\"\n";
    let results = s.probe(
        &[],
        &[
            mkdir("/workspace/sub"),
            write("/workspace/sub/.stopit.toml", planted),
        ],
    );
    for r in &results {
        assert_eq!(ok(r), &Data::Done, "{results:?}");
    }
    // A later run from there finds it first, and refuses it.
    let mut command = s.run_probe_command(&[]);
    command.current_dir(s.ws().join("sub"));
    let out = output(command, b"[]");
    assert_eq!(code(&out), 125, "{out:?}");
    let err = stderr(&out);
    assert!(err.starts_with("stopit: error: refusing to use "), "{err}");
    assert!(err.contains("nested configurations"), "{err}");
    assert!(
        err.contains(&format!("`--workspace {}`", s.ws().display())),
        "{err}"
    );
    assert!(out.stdout.is_empty(), "{out:?}");
    assert!(s.no_session_left());
    // Naming the outer workspace runs as usual.
    let mut command = s.run_probe_command(&["--workspace", s.ws().to_str().unwrap()]);
    command.current_dir(s.ws().join("sub"));
    let results = s.probe_with(command, &[Op::Cwd]);
    assert_eq!(ok(&results[0]), &Data::Cwd("/workspace".into()));
}

#[test]
fn a_sandbox_cannot_switch_the_nested_configuration_rule_off() {
    // Making the workspace root writable by others makes the outer
    // configuration fail the trust checks; it still counts as outer.
    let s = Setup::with_config("");
    let planted = "[[provider]]\ntype = \"script\"\nsource = \"/bin/false\"\n";
    let results = s.probe(
        &[],
        &[
            chmod("/workspace", 0o777),
            mkdir("/workspace/sub"),
            write("/workspace/sub/.stopit.toml", planted),
        ],
    );
    for r in &results {
        assert_eq!(ok(r), &Data::Done, "{results:?}");
    }
    assert_eq!(
        fs::metadata(s.ws()).unwrap().permissions().mode() & 0o7777,
        0o777
    );
    // From `sub/`: refused, without suggesting the outer one, which would
    // not load.
    let mut command = s.run_probe_command(&[]);
    command.current_dir(s.ws().join("sub"));
    let out = output(command, b"[]");
    assert_eq!(code(&out), 125, "{out:?}");
    let err = stderr(&out);
    assert!(err.starts_with("stopit: error: refusing to use "), "{err}");
    assert!(err.contains("nested configurations"), "{err}");
    assert!(err.contains("fails the trust checks"), "{err}");
    assert!(
        !err.contains(&format!("`--workspace {}`", s.ws().display())),
        "{err}"
    );
    assert!(s.no_session_left());
    // From the workspace itself: its configuration fails the trust checks,
    // so it is refused too.
    let out = output(s.run_probe_command(&[]), b"[]");
    assert_eq!(code(&out), 125, "{out:?}");
    let err = stderr(&out);
    assert!(err.starts_with("stopit: error: "), "{err}");
    assert!(err.contains("its directory is writable"), "{err}");
    assert!(s.no_session_left());
}

// --- Warnings and errors ---

#[test]
fn a_warning_is_printed_once_and_base_missing_paths_not_at_all() {
    // The missing path is planned, and warned about, in `main` and again in
    // `other`, which inherits it. The default base's own rules for
    // `.envrc`, `flake.lock`, … miss too, quietly.
    let s = Setup::new();
    // Not a whole escape sequence: `[` or `]` would make the rule a glob,
    // which warns about nothing when it matches nothing.
    let missing = s.root.join("missing\x1bc\x07");
    s.write_config(&format!(
        "fs.rw = [\"{}\"]\n[profiles.other]\n",
        missing
            .to_str()
            .unwrap()
            .replace('\x1b', "\\u001b")
            .replace('\x07', "\\u0007")
    ));
    let input = serde_json::to_vec(&[Op::Cwd]).unwrap();
    let out = output(s.run_probe_command(&[]), &input);
    assert_eq!(code(&out), 0, "{out:?}");
    let err = stderr(&out);
    let lines: Vec<&str> = err.lines().collect();
    assert_eq!(lines.len(), 1, "{err}");
    assert!(
        lines[0].starts_with("stopit: warning: provider \"tools\""),
        "{err}"
    );
    assert!(lines[0].contains("missing\\u{1b}c\\u{7}"), "{err}");
    assert!(lines[0].contains("does not exist"), "{err}");
    assert!(!err.contains('\x1b') && !err.contains('\x07'), "{err:?}");
    assert!(!err.contains(".envrc"), "{err}");
}

#[test]
fn an_invalid_configuration_is_an_error_naming_the_file() {
    let s = Setup::new();
    s.write_raw_config("bogus = \"\x1b]52;c;aGk=\x07\"\n");
    let out = output(s.stopit(&["run", "true"]), b"");
    assert_eq!(code(&out), 125, "{out:?}");
    let err = stderr(&out);
    assert!(err.starts_with("stopit: error: "), "{err}");
    assert!(err.contains(".stopit.toml"), "{err}");
    assert!(err.contains("bogus"), "{err}");
    // The file's control characters do not reach the terminal.
    assert!(!err.contains('\x1b') && !err.contains('\x07'), "{err:?}");
    // Nothing was created: the configuration is read first.
    assert!(!s.runtime().join("stopit").exists());
}

#[test]
fn a_configuration_others_can_write_is_refused() {
    let s = Setup::with_config("");
    let path = s.ws().join(".stopit.toml");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o664)).unwrap();
    let out = output(s.run_probe_command(&[]), b"[]");
    assert_eq!(code(&out), 125, "{out:?}");
    assert_eq!(
        stderr(&out),
        format!(
            "stopit: error: refusing to read {path:?}: it is writable by its group or others \
             (mode 0664); run `chmod go-w` on it\n"
        )
    );
    assert!(!s.runtime().join("stopit").exists());
}

#[test]
fn xdg_runtime_dir_unset_is_a_clear_error() {
    let s = Setup::with_config("");
    let mut command = s.run_probe_command(&[]);
    command.env_remove("XDG_RUNTIME_DIR");
    let out = output(command, b"[]");
    assert_eq!(code(&out), 125, "{out:?}");
    assert_eq!(
        stderr(&out),
        "stopit: error: XDG_RUNTIME_DIR is not set; stopit needs it for its per-session \
         directory\n"
    );
    assert!(out.stdout.is_empty(), "{out:?}");
}

#[test]
fn the_session_directory_is_removed_after_the_command() {
    // The command writes into its ephemeral `/tmp`, whose backing
    // directory is in the session directory; all of it goes.
    let s = Setup::with_config("");
    let results = s.probe(&[], &[write("/tmp/scratch", "x")]);
    assert_eq!(ok(&results[0]), &Data::Done);
    let base = s.runtime().join("stopit");
    assert!(base.is_dir());
    assert!(s.no_session_left());
}

// --- The terminal ---

/// A new pseudo-terminal: its master and its slave. `None` if the system
/// has none to give.
fn open_pty() -> Option<(File, File)> {
    use rustix::fs::{Mode, OFlags};
    use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
    let master = match openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC) {
        Ok(master) => master,
        Err(e) => {
            eprintln!("skipping: no pseudo-terminal: {e}");
            return None;
        }
    };
    grantpt(&master).unwrap();
    unlockpt(&master).unwrap();
    let name = ptsname(&master, Vec::new()).unwrap();
    let slave = rustix::fs::open(
        name.as_c_str(),
        OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .unwrap();
    Some((File::from(master), File::from(slave)))
}

/// `command` made to start in a new session whose controlling terminal is
/// `tty`, as a program started from an interactive shell has one.
fn with_controlling_terminal(command: &mut Command, tty: &File) {
    let fd = tty.as_raw_fd();
    // SAFETY: the closure only makes two raw syscalls through rustix
    // (`setsid`, `ioctl(TIOCSCTTY)`), which allocate nothing. `fd` is open
    // in the child until `exec` (it is close-on-exec), as `tty` outlives
    // the spawn.
    unsafe {
        command.pre_exec(move || {
            rustix::process::setsid()?;
            rustix::process::ioctl_tiocsctty(BorrowedFd::borrow_raw(fd))?;
            Ok(())
        });
    }
}

/// The controlling terminal (`tty_nr`, 0 for none) in the text of a
/// `/proc/<pid>/stat` file.
fn tty_nr(stat: &str) -> u64 {
    // The fields after the command name, which ends with the last `)`:
    // state, ppid, pgrp, session, tty_nr.
    let after = &stat[stat.rfind(')').unwrap() + 1..];
    after.split_whitespace().nth(4).unwrap().parse().unwrap()
}

#[test]
fn without_a_new_session_the_sandbox_shares_the_terminal() {
    // The control for the next test, showing it can tell: through a bwrap
    // command without `--new-session`, the sandbox has the terminal as its
    // controlling terminal.
    let Some((_master, slave)) = open_pty() else {
        return;
    };
    // (`InitSession::command` builds it with `TerminalSession::Keep`.)
    let f = SpecFixture::new();
    let (probe_dir, probe) = probe_at_host_path();
    let spec = f.compile(&config_none(&format!(
        "system.proc = true\nfs.ro = [\"{}\"]",
        probe_dir.to_str().unwrap()
    )));
    let session = f.init_session();
    let mut command = session.command(&spec, &[], &probe).into_command();
    with_controlling_terminal(&mut command, &slave);
    let ops = [read("/proc/self/stat")];
    let out = output(command, &serde_json::to_vec(&ops).unwrap());
    let results = probe_results("bwrap without --new-session", &out, &ops);
    assert_ne!(tty_nr(contents(&results[0])), 0, "{results:?}");
}

#[test]
fn the_sandbox_has_no_controlling_terminal() {
    let Some((_master, slave)) = open_pty() else {
        return;
    };
    let s = Setup::with_config("");
    let ops = [read("/proc/self/stat")];
    let input = serde_json::to_vec(&ops).unwrap();

    // Every stdio redirected, but the terminal still reachable as
    // `/dev/tty`: detached.
    let mut command = s.run_probe_command(&[]);
    with_controlling_terminal(&mut command, &slave);
    let out = output(command, &input);
    let results = probe_results("stopit run, a terminal but no tty stdio", &out, &ops);
    assert_eq!(tty_nr(contents(&results[0])), 0, "{results:?}");

    // The terminal as stderr: detached. (What goes there stays in the
    // terminal, which nothing reads; it is short.)
    let input_file = s.root.join("ops.json");
    fs::write(&input_file, &input).unwrap();
    let mut command = s.run_probe_command(&[]);
    command
        .stdin(File::open(&input_file).unwrap())
        .stdout(Stdio::piped())
        .stderr(slave.try_clone().unwrap());
    with_controlling_terminal(&mut command, &slave);
    let out = spawn_with_stdio(&mut command, None, BWRAP_DEADLINE);
    let results = probe_results("stopit run, the terminal as stderr", &out, &ops);
    assert_eq!(tty_nr(contents(&results[0])), 0, "{results:?}");
    assert!(s.no_session_left());
}

/// `command` made to start in a new session with no controlling terminal.
fn without_controlling_terminal(command: &mut Command) {
    // SAFETY: the closure only makes a raw syscall through rustix.
    unsafe {
        command.pre_exec(|| {
            rustix::process::setsid()?;
            Ok(())
        });
    }
}

#[test]
fn a_terminal_as_stdin_alone_detaches_the_sandbox() {
    // No controlling terminal: only stdin reaches the terminal.
    let Some((master, slave)) = open_pty() else {
        return;
    };
    let s = Setup::with_config("");
    let ops = [read("/proc/self/stat"), read("/proc/self/fdinfo/0")];
    let mut command = s.run_probe_command(&[]);
    command
        .stdin(slave.try_clone().unwrap())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    without_controlling_terminal(&mut command);
    // The operations, then end of file (Ctrl-D at the start of a line).
    let mut input = serde_json::to_vec(&ops).unwrap();
    input.extend_from_slice(b"\n\x04");
    (&master).write_all(&input).unwrap();
    let out = spawn_with_stdio(&mut command, None, BWRAP_DEADLINE);
    let results = probe_results("stopit run, the terminal as stdin", &out, &ops);
    assert_eq!(tty_nr(contents(&results[0])), 0, "{results:?}");
    assert!(stderr(&out).is_empty(), "{out:?}");
    assert!(s.no_session_left());
}

#[test]
fn a_terminal_as_stdout_alone_detaches_the_sandbox() {
    // No controlling terminal: only stdout reaches the terminal. The
    // results are read back from the terminal's master.
    let Some((master, slave)) = open_pty() else {
        return;
    };
    let s = Setup::with_config("");
    let ops = [read("/proc/self/stat")];
    let input_file = s.root.join("ops.json");
    fs::write(&input_file, serde_json::to_vec(&ops).unwrap()).unwrap();
    let mut command = s.run_probe_command(&[]);
    command
        .stdin(File::open(&input_file).unwrap())
        .stdout(slave)
        .stderr(Stdio::piped());
    without_controlling_terminal(&mut command);
    let out = spawn_with_stdio(&mut command, None, BWRAP_DEADLINE);
    // Every copy of the slave is closed now (the command held the last
    // one), so the master reads what was written, then fails with `EIO`.
    drop(command);
    let mut written = Vec::new();
    let _ = (&master).read_to_end(&mut written);
    let written: Vec<u8> = written.into_iter().filter(|&b| b != b'\r').collect();
    let out = Output {
        stdout: written,
        ..out
    };
    let results = probe_results("stopit run, the terminal as stdout", &out, &ops);
    assert_eq!(tty_nr(contents(&results[0])), 0, "{results:?}");
    assert!(s.no_session_left());
}

// --- Job control and signals ---

/// The `/proc/<pid>/stat` fields after the command name: state, ppid, ….
fn stat_fields(pid: i32) -> Option<Vec<String>> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after = &stat[stat.rfind(')')? + 1..];
    Some(after.split_whitespace().map(str::to_owned).collect())
}

/// The process state of `pid` (`R`, `S`, `T`, …), if it exists.
fn state(pid: i32) -> Option<String> {
    stat_fields(pid).map(|f| f[0].clone())
}

/// Every process descended from `root`.
fn descendants(root: i32) -> Vec<i32> {
    let mut children: HashMap<i32, Vec<i32>> = HashMap::new();
    for entry in fs::read_dir("/proc").unwrap().flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|n| n.parse().ok()) else {
            continue;
        };
        if let Some(ppid) = stat_fields(pid).and_then(|f| f[1].parse().ok()) {
            children.entry(ppid).or_default().push(pid);
        }
    }
    let mut found = Vec::new();
    let mut next = vec![root];
    while let Some(pid) = next.pop() {
        for &child in children.get(&pid).into_iter().flatten() {
            found.push(child);
            next.push(child);
        }
    }
    found
}

/// The host pid of the probe that the stopit process `stopit` runs, once it
/// runs: its descendant whose argv is the probe's.
fn wait_for_probe(stopit: i32) -> i32 {
    let mut argv = Vec::new();
    for arg in probe_argv() {
        argv.extend_from_slice(arg.as_bytes());
        argv.push(0);
    }
    let deadline = Instant::now() + BWRAP_DEADLINE;
    loop {
        for pid in descendants(stopit) {
            if fs::read(format!("/proc/{pid}/cmdline")).ok().as_ref() == Some(&argv) {
                return pid;
            }
        }
        assert!(
            Instant::now() < deadline,
            "the probe did not start within {BWRAP_DEADLINE:?}"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

/// Waits until `pid` no longer exists (or is a zombie), within the usual
/// deadline.
fn wait_gone(pid: i32) {
    let deadline = Instant::now() + BWRAP_DEADLINE;
    while state(pid).is_some_and(|s| s != "Z") {
        assert!(Instant::now() < deadline, "{pid} is still running");
        thread::sleep(Duration::from_millis(10));
    }
}

/// Waits for `child` and collects its output, killing it at the usual
/// deadline.
fn finish(child: Child) -> Output {
    let pid = child.id() as i32;
    let (send, receive) = mpsc::channel();
    thread::spawn(move || send.send(child.wait_with_output()));
    match receive.recv_timeout(BWRAP_DEADLINE) {
        Ok(out) => out.unwrap(),
        Err(_) => {
            // SAFETY: a plain syscall; the child is not reaped yet.
            unsafe { libc::kill(pid, libc::SIGKILL) };
            panic!("stopit did not finish within {BWRAP_DEADLINE:?} and was killed");
        }
    }
}

/// Sends `signal` to `pid` (a process group if negative).
fn kill(pid: i32, signal: libc::c_int) {
    // SAFETY: a plain syscall.
    assert_eq!(
        unsafe { libc::kill(pid, signal) },
        0,
        "kill({pid}, {signal})"
    );
}

/// `stopit run <probe>` with its stdin, stdout and stderr piped, spawned:
/// the probe waits for the end of its input meanwhile.
fn spawn_waiting_probe(s: &Setup, configure: impl FnOnce(&mut Command)) -> Child {
    let mut command = s.run_probe_command(&[]);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure(&mut command);
    command.spawn().unwrap()
}

#[test]
fn ctrl_z_does_not_stop_stopit_while_the_sandbox_has_the_terminal() {
    let Some((master, slave)) = open_pty() else {
        return;
    };
    let s = Setup::with_config("");
    let mut command = s.run_probe_command(&[]);
    command
        .stdin(slave.try_clone().unwrap())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    with_controlling_terminal(&mut command, &slave);
    let child = command.spawn().unwrap();
    let pid = child.id() as i32;
    // The probe reads the terminal, which is not its controlling one.
    let probe = wait_for_probe(pid);

    // Ctrl-Z: `SIGTSTP` to the terminal's foreground process group,
    // stopit's (it leads the session).
    kill(-pid, libc::SIGTSTP);
    thread::sleep(Duration::from_millis(200));
    for p in std::iter::once(pid).chain(descendants(pid)) {
        assert_ne!(state(p).as_deref(), Some("T"), "{p} is stopped");
    }
    assert_ne!(state(probe).as_deref(), Some("T"));

    // Still running, it ends normally: the operations, then end of file.
    (&master).write_all(b"[]\n\x04").unwrap();
    let out = finish(child);
    assert_eq!(code(&out), 0, "{out:?}");
    assert_eq!(out.stdout, b"[]\n", "{out:?}");
    assert!(s.no_session_left());
}

/// `command` made to start in the background of `tty`: in a new session
/// whose controlling terminal is `tty`, but in a process group of its own,
/// while the session leader's has the terminal's foreground. The session
/// leader waits for it and exits with its status (`128 + N` for a signal).
fn in_the_background_of(command: &mut Command, tty: &File) {
    let fd = tty.as_raw_fd();
    // SAFETY: the closure only makes async-signal-safe calls (`setsid`,
    // `ioctl`, `fork`, `setpgid`, `waitpid`, `_exit`), allocating nothing.
    // `fd` is open until `exec`, as `tty` outlives the spawn. The session
    // leader never returns from it, so only the forked child execs.
    unsafe {
        command.pre_exec(move || {
            rustix::process::setsid()?;
            rustix::process::ioctl_tiocsctty(BorrowedFd::borrow_raw(fd))?;
            match libc::fork() {
                -1 => Err(std::io::Error::last_os_error()),
                0 => {
                    if libc::setpgid(0, 0) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                }
                child => {
                    let mut status = 0;
                    while libc::waitpid(child, &mut status, 0) == -1 {
                        if *libc::__errno_location() != libc::EINTR {
                            libc::_exit(127);
                        }
                    }
                    if libc::WIFEXITED(status) {
                        libc::_exit(libc::WEXITSTATUS(status));
                    }
                    libc::_exit(128 + libc::WTERMSIG(status));
                }
            }
        });
    }
}

#[test]
fn a_background_start_on_the_terminal_is_refused() {
    let Some((_master, slave)) = open_pty() else {
        return;
    };
    let s = Setup::with_config("");
    let mut command = s.run_probe_command(&[]);
    // Not stdin: had stopit started the sandbox anyway, the probe would
    // fail on its empty input rather than wait.
    command
        .stdin(Stdio::null())
        .stdout(slave.try_clone().unwrap())
        .stderr(Stdio::piped());
    in_the_background_of(&mut command, &slave);
    let out = spawn_with_stdio(&mut command, None, BWRAP_DEADLINE);
    assert_eq!(code(&out), 125, "{out:?}");
    assert_eq!(
        stderr(&out),
        "stopit: error: stopit is not in the foreground of its terminal (started in the \
         background?); until stopit runs the sandbox on a terminal of its own, it only starts \
         in the foreground\n"
    );
    assert!(s.no_session_left());
}

#[test]
fn sigterm_ends_the_sandbox_and_removes_the_session() {
    let s = Setup::with_config("");
    let mut child = spawn_waiting_probe(&s, |_| {});
    let stdin = child.stdin.take();
    let pid = child.id() as i32;
    let probe = wait_for_probe(pid);
    // To stopit alone: it forwards the signal to bwrap, which dies of it.
    kill(pid, libc::SIGTERM);
    let out = finish(child);
    drop(stdin);
    assert_eq!(code(&out), 128 + libc::SIGTERM, "{out:?}");
    assert_eq!(stderr(&out), "", "{out:?}");
    assert!(s.no_session_left());
    wait_gone(probe);
}

#[test]
fn sighup_ends_the_sandbox_and_removes_the_session() {
    let s = Setup::with_config("");
    let mut child = spawn_waiting_probe(&s, |_| {});
    let stdin = child.stdin.take();
    let pid = child.id() as i32;
    let probe = wait_for_probe(pid);
    kill(pid, libc::SIGHUP);
    let out = finish(child);
    drop(stdin);
    assert_eq!(code(&out), 128 + libc::SIGHUP, "{out:?}");
    assert!(s.no_session_left());
    wait_gone(probe);
}

#[test]
fn sigint_to_the_process_group_is_130_and_removes_the_session() {
    // As Ctrl-C sends it: to stopit, bwrap and (without a terminal, so in
    // the same process group) the probe.
    let s = Setup::with_config("");
    let mut child = spawn_waiting_probe(&s, |command| {
        command.process_group(0);
    });
    let stdin = child.stdin.take();
    let pid = child.id() as i32;
    let probe = wait_for_probe(pid);
    kill(-pid, libc::SIGINT);
    let out = finish(child);
    drop(stdin);
    assert_eq!(code(&out), 130, "{out:?}");
    assert!(s.no_session_left());
    wait_gone(probe);
}

#[test]
fn a_command_killed_by_a_signal_is_128_plus_n() {
    let s = Setup::with_config("");
    let mut child = spawn_waiting_probe(&s, |_| {});
    let stdin = child.stdin.take();
    let probe = wait_for_probe(child.id() as i32);
    kill(probe, libc::SIGKILL);
    let out = finish(child);
    drop(stdin);
    assert_eq!(code(&out), 128 + libc::SIGKILL, "{out:?}");
    assert_eq!(stderr(&out), "", "{out:?}");
    assert!(s.no_session_left());
}

// --- stopit shell ---

#[test]
fn shell_runs_the_hosts_shell() {
    // `SHELL` is the provisioned probe, run directly rather than through
    // its copied loader: the loader it names is granted at its host path,
    // and the copied libraries through `LD_LIBRARY_PATH`.
    let (probe_dir, _) = probe_at_host_path();
    let exe = probe_dir.join("stopit");
    let loader = stopit::provision::read_interpreter(&fs::read(&exe).unwrap()).unwrap();
    let extra = match &loader {
        None => String::new(),
        Some(loader) => format!(
            "[[provider]]\ntype = \"config\"\nname = \"loader\"\n[provider.sandbox]\n\
             fs.ro = [\"{}\"]\nenv.set = {{ LD_LIBRARY_PATH = \"{}\" }}\n",
            loader.to_str().unwrap(),
            probe_dir.join("lib").to_str().unwrap()
        ),
    };
    let s = Setup::with_config(&extra);
    let mut command = s.stopit(&["shell"]);
    command.env("SHELL", &exe);
    let results = s.probe_with(command, &[Op::Argv, Op::Cwd]);
    assert_eq!(
        ok(&results[0]),
        &Data::Argv(vec![exe.to_str().unwrap().to_owned()])
    );
    assert_eq!(ok(&results[1]), &Data::Cwd("/workspace".into()));
    assert!(s.no_session_left());
}
