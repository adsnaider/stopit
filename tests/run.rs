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
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
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

    /// With `.stopit.toml` holding [`probe_config`] plus `extra`, allowed.
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

    fn config_path(&self) -> PathBuf {
        self.ws().join(".stopit.toml")
    }

    /// Writes [`probe_config`] plus `extra` as `.stopit.toml`, and allows
    /// it.
    fn write_config(&self, extra: &str) {
        self.write_raw_config(&probe_config(extra));
    }

    /// Writes `contents` as `.stopit.toml` ([`write_unallowed`]), and
    /// allows it with `stopit allow` ([`allow`](Self::allow)).
    fn write_raw_config(&self, contents: &str) {
        self.write_unallowed(contents);
        self.allow(&[]);
    }

    /// Writes `contents` as `.stopit.toml`, private to the user whatever the
    /// umask (stopit refuses one others can write), without allowing it.
    fn write_unallowed(&self, contents: &str) {
        let path = self.config_path();
        fs::write(&path, contents).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    }

    /// `stopit allow <options…>` from the workspace, which must succeed;
    /// returns what it printed.
    fn allow(&self, options: &[&str]) -> String {
        let out = output(self.stopit(&[&["allow"][..], options].concat()), b"");
        assert_eq!(code(&out), 0, "{out:?}");
        assert_eq!(stderr(&out), "", "{out:?}");
        String::from_utf8(out.stdout).unwrap()
    }

    /// The trust store's file.
    fn store_file(&self) -> PathBuf {
        self.state_dir().join(stopit::trust::STORE_FILE)
    }

    /// stopit's data directory, set with `STOPIT_STATE_DIR`, so that no test
    /// uses the real one in the user's home directory.
    fn state_dir(&self) -> PathBuf {
        self.root.join("state/stopit")
    }

    /// stopit's user-global configuration directory, set with
    /// `STOPIT_CONFIG_DIR`, so that no test reads the host user's real
    /// `~/.config/stopit/config.toml`.
    fn config_dir(&self) -> PathBuf {
        self.root.join("config/stopit")
    }

    /// Writes `contents` as `<config_dir>/config.toml` with trusted ownership
    /// and permissions (`0755` directory, `0644` file).
    fn write_global_config(&self, contents: &str) -> PathBuf {
        let dir = self.config_dir();
        fs::create_dir_all(&dir).unwrap();
        if let Some(parent) = dir.parent() {
            fs::set_permissions(parent, fs::Permissions::from_mode(0o755)).unwrap();
        }
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        let path = dir.join(stopit::state::GLOBAL_CONFIG_FILE);
        fs::write(&path, contents).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        path
    }

    /// `stopit <args…>` from the workspace, with only `XDG_RUNTIME_DIR`,
    /// `STOPIT_STATE_DIR` ([`state_dir`](Self::state_dir)),
    /// `STOPIT_CONFIG_DIR` ([`config_dir`](Self::config_dir)), `HOME` and
    /// `PATH` (to find bwrap) in its environment.
    fn stopit<S: AsRef<std::ffi::OsStr>>(&self, args: &[S]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_stopit"));
        command
            .args(args)
            .current_dir(self.ws())
            .env_clear()
            .env("XDG_RUNTIME_DIR", self.runtime())
            .env("STOPIT_STATE_DIR", self.state_dir())
            .env("STOPIT_CONFIG_DIR", self.config_dir())
            .env("HOME", self.root.join("home"))
            .env("PATH", std::env::var_os("PATH").unwrap_or_default());
        command
    }

    /// `stopit run --quiet <options…> <probe>`: [`stopit`](Self::stopit)
    /// with the probe's argv after `options`, without the startup summary,
    /// so that most tests see only warnings and errors on stderr.
    fn run_probe_command(&self, options: &[&str]) -> Command {
        self.run_probe_command_with_summary(&[&["--quiet"][..], options].concat())
    }

    /// [`run_probe_command`](Self::run_probe_command) without `--quiet`.
    fn run_probe_command_with_summary(&self, options: &[&str]) -> Command {
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

    /// Whether the runtime directory holds no session directory. A server's
    /// workspace lock file may stay.
    fn no_session_left(&self) -> bool {
        let base = self.runtime().join("stopit");
        fs::read_dir(&base)
            .unwrap_or_else(|e| panic!("{base:?}: {e}"))
            .flatten()
            .all(|e| e.file_name().to_string_lossy().starts_with("server-"))
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
    let out = output(s.stopit(&["run", "--quiet", "no\x1b[31msuch"]), b"");
    assert_eq!(code(&out), 127, "{out:?}");
    // The default base grants no `PATH`.
    assert_eq!(
        stderr(&out),
        "stopit __init: no\\u{1b}[31msuch: not found (the environment has no PATH)\n"
    );
    assert!(out.stdout.is_empty(), "{out:?}");
    assert!(s.no_session_left());
}

// --- The startup summary ---

/// The summary's header line for a workspace at `s.ws()`.
fn summary_header(s: &Setup) -> String {
    format!(
        "stopit: profile \"main\" (workspace {} rw at /workspace)\n",
        s.ws().display()
    )
}

#[test]
fn the_summary_lists_what_the_profile_grants_beyond_the_default_base() {
    let s = Setup::with_config(
        "fs.rw = [\"~/data\"]\nnetwork = { mode = \"proxy\", allow_domains = [\"example.org\"] }",
    );
    fs::create_dir(s.root.join("home/data")).unwrap();
    let out = output(s.run_probe_command_with_summary(&[]), b"[]");
    assert_eq!(code(&out), 0, "{out:?}");
    let (probe_dir, _) = probe_at_host_path();
    assert_eq!(
        stderr(&out),
        format!(
            "{}stopit:   rw       ~/data  (provider \"tools\")\n\
             stopit:   ro       {}  (provider \"tools\")\n\
             stopit:   network  proxy to example.org\n",
            summary_header(&s),
            probe_dir.display()
        )
    );
    assert!(s.no_session_left());
}

#[test]
fn quiet_suppresses_the_summary_but_not_warnings() {
    let s = Setup::with_config("fs.rw = [\"~/data\"]");
    fs::create_dir(s.root.join("home/data")).unwrap();
    let out = output(s.run_probe_command(&[]), b"[]");
    assert_eq!(code(&out), 0, "{out:?}");
    assert_eq!(stderr(&out), "", "{out:?}");
    // `-q` is the same; a missing `rw` path still warns.
    fs::remove_dir(s.root.join("home/data")).unwrap();
    let out = output(s.run_probe_command_with_summary(&["-q"]), b"[]");
    assert_eq!(code(&out), 0, "{out:?}");
    let err = stderr(&out);
    assert!(err.starts_with("stopit: warning: "), "{err}");
    assert!(!err.contains("profile \"main\""), "{err}");
}

#[test]
fn the_default_configuration_prints_only_the_header() {
    let s = Setup::new();
    s.write_global_config(GLOBAL_SEARCH_PATH);
    s.write_raw_config("");
    let out = output(s.stopit(&["run", "true"]), b"");
    assert_eq!(code(&out), 127, "{out:?}");
    // Then the missing command's own message: the global search path names
    // a directory nothing mounts.
    assert_eq!(
        stderr(&out),
        format!(
            "{}stopit __init: true: not found in PATH\n",
            summary_header(&s)
        )
    );
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

/// Checks that `out` is the default base failing to find the probe, which
/// it does not grant.
#[track_caller]
fn assert_default_base_ran(out: &Output) {
    assert_eq!(code(out), 127, "{out:?}");
    assert!(stderr(out).starts_with("stopit __init: "), "{out:?}");
    assert!(stderr(out).contains("No such file or directory"), "{out:?}");
}

#[test]
fn no_configuration_runs_the_default_base_in_the_cwd() {
    // Without a `.stopit.toml` the default base applies, with nothing to
    // allow.
    let s = Setup::new();
    s.write_global_config(GLOBAL_SEARCH_PATH);
    let out = output(s.run_probe_command(&[]), b"[]");
    assert_default_base_ran(&out);
    assert!(s.no_session_left());
    // `--workspace` does not look up: `sub` has none of its own, though the
    // directory above it has one, which is not allowed.
    s.write_unallowed("base = \"none\"\n");
    fs::create_dir(s.ws().join("sub")).unwrap();
    let out = output(s.run_probe_command(&["--workspace", "sub"]), b"[]");
    assert_default_base_ran(&out);
    assert!(s.no_session_left());
}

#[test]
fn an_empty_configuration_runs_the_default_base() {
    // The default base grants nothing for the probe, so it is not found.
    let s = Setup::new();
    s.write_global_config(GLOBAL_SEARCH_PATH);
    s.write_raw_config("");
    let out = output(s.run_probe_command(&[]), b"[]");
    assert_default_base_ran(&out);
    assert!(s.no_session_left());
}

// --- The user-global configuration ---

/// A user-global configuration whose only tool grant is a search path
/// naming a directory nothing mounts, so the default base runs and finds
/// nothing.
const GLOBAL_SEARCH_PATH: &str = "[[provider]]\ntype = \"config\"\nname = \"search\"\n\
                                  [provider.sandbox]\nenv.path_prepend = [\"/nowhere/bin\"]\n";

/// The refusal of a default base without tools, for a global configuration
/// at `global`.
fn no_tools_refusal(global: &Path) -> String {
    format!(
        "stopit: error: base = \"default\" mounts no tools, and no provider in {global:?} or \
         .stopit.toml grants any; configure a tool provider in {global:?} for every workspace or \
         in .stopit.toml for this workspace, for example:\n\
         \n\
         [[provider]]\n\
         type = \"config\"\n\
         name = \"tools\"\n\
         [provider.sandbox]\n\
         fs.ro = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\"]\n\
         env.path_prepend = [\"/usr/bin\", \"/bin\"]\n"
    )
}

#[test]
fn a_default_base_without_tools_is_refused() {
    let s = Setup::new();
    let global = s.config_dir().join("config.toml");
    let refused = no_tools_refusal(&global);
    let check = |what: &str| {
        let out = output(s.run_probe_command(&[]), b"[]");
        assert_eq!(code(&out), 125, "{what}: {out:?}");
        assert_eq!(stderr(&out), refused, "{what}");
        assert!(out.stdout.is_empty(), "{what}: {out:?}");
        assert!(s.no_session_left(), "{what}");
    };
    // No configuration at all, then an empty workspace configuration.
    check("no configuration");
    s.write_raw_config("");
    check("an empty .stopit.toml");
    // Restrictions and settings are not tools.
    s.write_raw_config(
        "[[provider]]\ntype = \"config\"\n[provider.sandbox]\n\
         fs.masked = [\"{workspace}/secret\"]\nenv.set = { EDITOR = \"vi\" }\n",
    );
    check("a provider granting no tools");
    s.write_global_config("[approval]\ntimeout = \"30s\"\n");
    check("a global configuration granting no tools");
    // `base = "none"` asks for an empty sandbox, so nothing is refused.
    s.write_raw_config("base = \"none\"\n");
    let out = output(s.stopit(&["run", "--quiet", "/nothing"]), b"");
    assert_eq!(code(&out), 127, "{out:?}");
}

#[test]
fn the_global_configuration_grants_tools_to_every_workspace() {
    let s = Setup::new();
    s.write_global_config(&probe_config("env.set = { WHICH = \"global\" }"));
    let which = |s: &Setup| {
        let results = s.probe(&[], &[Op::Env]);
        let Data::Env(env) = ok(&results[0]) else {
            panic!("{results:?}")
        };
        env.get("WHICH").cloned()
    };
    // Without a workspace configuration, and with an empty one.
    assert_eq!(which(&s).as_deref(), Some("global"));
    s.write_raw_config("");
    assert_eq!(which(&s).as_deref(), Some("global"));
    // A workspace provider overrides a global `env.set` variable.
    s.write_raw_config(
        "[[provider]]\ntype = \"config\"\nname = \"mine\"\n[provider.sandbox]\n\
         env.set = { WHICH = \"project\" }\n",
    );
    assert_eq!(which(&s).as_deref(), Some("project"));
    // A workspace provider with the global provider's name replaces it.
    s.write_raw_config(&probe_config(""));
    assert_eq!(which(&s), None);
    assert!(s.no_session_left());
}

#[test]
fn project_settings_override_global_settings() {
    let s = Setup::new();
    s.write_global_config(&format!(
        "[workspace]\nmount = \"/global-ws\"\n{}",
        probe_config("")
    ));
    let cwd = |s: &Setup| {
        let results = s.probe(&[], &[Op::Cwd]);
        ok(&results[0]).clone()
    };
    assert_eq!(cwd(&s), Data::Cwd("/global-ws".into()));
    s.write_raw_config("[workspace]\nmount = \"/project-ws\"\n");
    assert_eq!(cwd(&s), Data::Cwd("/project-ws".into()));
    // Writing the built-in default still overrides the global value.
    s.write_raw_config("[workspace]\nmount = \"/workspace\"\n");
    assert_eq!(cwd(&s), Data::Cwd("/workspace".into()));
}

#[test]
fn base_none_in_the_project_ignores_the_global_layer_but_still_checks_it() {
    let s = Setup::new();
    let (probe_dir, _) = probe_at_host_path();
    s.write_global_config(&probe_config("env.set = { WHICH = \"global\" }"));
    s.write_raw_config(&format!(
        "base = \"none\"\n[[provider]]\ntype = \"config\"\n[provider.sandbox]\n\
         fs.ro = [\"{}\"]\n",
        probe_dir.display()
    ));
    // Nothing of the global layer applies: no `WHICH`, no workspace mount.
    let results = s.probe(&[], &[Op::Cwd, Op::Env]);
    assert_eq!(ok(&results[0]), &Data::Cwd("/".into()));
    let Data::Env(env) = ok(&results[1]) else {
        panic!("{results:?}")
    };
    assert!(!env.contains_key("WHICH"), "{env:?}");
    // It is still read, checked and parsed, since its target and scripts
    // are protected in this session too: a broken one stops the run.
    let global = s.write_global_config("this is not toml");
    let out = output(s.run_probe_command(&[]), b"[]");
    assert_eq!(code(&out), 125, "{out:?}");
    let err = stderr(&out);
    assert!(
        err.starts_with(&format!("stopit: error: {global:?}")),
        "{err}"
    );
    assert!(s.no_session_left());
}

/// A dotfiles tree at `~/src/dotfiles` holding the global configuration's
/// target `stopit.toml` (`contents`) and a script `tools.sh` printing an
/// empty manifest, with `config.toml` linked to the target. Returns the
/// target and the script.
fn dotfiles_global_config(s: &Setup, contents: &str) -> (PathBuf, PathBuf) {
    let dotfiles = s.root.join("home/src/dotfiles");
    fs::create_dir_all(&dotfiles).unwrap();
    fs::set_permissions(&dotfiles, fs::Permissions::from_mode(0o755)).unwrap();
    let target = dotfiles.join("stopit.toml");
    fs::write(&target, contents).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
    let script = dotfiles.join("tools.sh");
    fs::write(&script, "#!/bin/sh\nprintf '{\"version\":1}'\n").unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    let global = s.write_global_config("");
    fs::remove_file(&global).unwrap();
    symlink(&target, &global).unwrap();
    (target, script)
}

#[test]
fn an_unused_global_configuration_stays_protected() {
    // The workspace grants `rw` on the tree holding the global
    // configuration and its script, and uses neither: `base = "none"`, then
    // a provider replacing the global one by name.
    let s = Setup::new();
    let global_body = |script: &Path| {
        format!(
            "[[provider]]\ntype = \"script\"\nname = \"tools\"\nsource = {script:?}\n{}",
            probe_config("").replace("name = \"tools\"", "name = \"probe\"")
        )
    };
    let (target, script) = dotfiles_global_config(&s, "");
    let body = global_body(&script);
    fs::write(&target, &body).unwrap();
    let (probe_dir, _) = probe_at_host_path();
    let rw_src = "[[provider]]\ntype = \"config\"\nname = \"src\"\n[provider.sandbox]\n\
                  fs.rw = [\"~/src\"]\n";
    for project in [
        format!(
            "base = \"none\"\n{rw_src}[[provider]]\ntype = \"config\"\nname = \"probe\"\n\
             [provider.sandbox]\nfs.ro = [\"{}\"]\n",
            probe_dir.display()
        ),
        format!(
            "{rw_src}[[provider]]\ntype = \"config\"\nname = \"tools\"\n\
             [provider.sandbox]\nfs.ro = [\"{}\"]\n",
            probe_dir.display()
        ),
    ] {
        s.write_raw_config(&project);
        let results = s.probe(
            &[],
            &[
                write("/home/user/src/dotfiles/stopit.toml", "pwned"),
                write("/home/user/src/dotfiles/tools.sh", "pwned"),
                link(
                    "/home/user/src/dotfiles/stopit.toml",
                    "/home/user/src/dotfiles/second-name",
                ),
                write("/home/user/src/dotfiles/other", "fine"),
            ],
        );
        assert_eq!(errno(&results[0]), "EROFS", "{project}: {results:?}");
        assert_eq!(errno(&results[1]), "EROFS", "{project}: {results:?}");
        assert_eq!(errno(&results[2]), "EXDEV", "{project}: {results:?}");
        assert_eq!(ok(&results[3]), &Data::Done, "{project}: {results:?}");
        assert_eq!(fs::read_to_string(&target).unwrap(), body);
    }
}

#[test]
fn a_global_configuration_reached_through_a_writable_link_is_refused() {
    // `config.toml -> ~/src/dotfiles/current/stopit.toml`, where `current`
    // is a link a sandbox with `rw ~/src` could re-point.
    let s = Setup::new();
    let (target, _) = dotfiles_global_config(&s, &probe_config(""));
    let dotfiles = target.parent().unwrap();
    symlink(".", dotfiles.join("current")).unwrap();
    let global = s.config_dir().join("config.toml");
    fs::remove_file(&global).unwrap();
    symlink(dotfiles.join("current/stopit.toml"), &global).unwrap();
    // Fine while nothing writable holds the link.
    let results = s.probe(&[], &[Op::Cwd]);
    assert_eq!(ok(&results[0]), &Data::Cwd("/workspace".into()));
    s.write_raw_config(
        "[[provider]]\ntype = \"config\"\nname = \"src\"\n[provider.sandbox]\n\
         fs.rw = [\"~/src\"]\n",
    );
    let out = output(s.run_probe_command(&[]), b"[]");
    assert_eq!(code(&out), 125, "{out:?}");
    let err = stderr(&out);
    assert!(err.contains(&format!("{global:?}")), "{err}");
    assert!(
        err.contains(&format!(
            "runs through the symbolic link {:?}",
            dotfiles.join("current")
        )),
        "{err}"
    );
    assert!(s.no_session_left());
}

#[test]
fn an_unnamed_provider_replacing_an_unnamed_global_one_warns() {
    let s = Setup::new();
    let global = s.write_global_config(&probe_config("").replace("name = \"tools\"\n", ""));
    s.write_raw_config(&probe_config("").replace("name = \"tools\"\n", ""));
    let out = output(s.run_probe_command(&[]), b"[]");
    assert_eq!(code(&out), 0, "{out:?}");
    assert_eq!(
        stderr(&out),
        format!(
            "stopit: warning: the [[provider]] named \"config\" in .stopit.toml replaces the one \
             of that name in {global:?}; give one of them another `name` to keep both\n"
        )
    );
}

#[test]
fn an_untrusted_global_configuration_is_refused() {
    let s = Setup::new();
    let global = s.write_global_config(&probe_config(""));
    fs::set_permissions(&global, fs::Permissions::from_mode(0o664)).unwrap();
    let out = output(s.run_probe_command(&[]), b"[]");
    assert_eq!(code(&out), 125, "{out:?}");
    let err = stderr(&out);
    assert!(err.contains(&format!("{global:?}")), "{err}");
    assert!(
        err.contains("it has mode 0664 and is writable by its group or others"),
        "{err}"
    );
    assert!(!s.runtime().join("stopit").exists());
    // A dangling symbolic link is refused, not skipped.
    fs::remove_file(&global).unwrap();
    symlink(s.root.join("missing.toml"), &global).unwrap();
    let out = output(s.run_probe_command(&[]), b"[]");
    assert_eq!(code(&out), 125, "{out:?}");
    assert!(
        stderr(&out).contains("it is a dangling symbolic link"),
        "{out:?}"
    );
}

#[test]
fn a_symlinked_global_configuration_is_protected_at_its_target() {
    // The global configuration lives in a dotfiles directory inside a tree
    // that the workspace grants `rw`.
    let s = Setup::new();
    let dotfiles = s.root.join("home/src/dotfiles");
    fs::create_dir_all(&dotfiles).unwrap();
    fs::set_permissions(&dotfiles, fs::Permissions::from_mode(0o755)).unwrap();
    let target = dotfiles.join("stopit.toml");
    let contents = probe_config("");
    fs::write(&target, &contents).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
    let global = s.write_global_config("");
    fs::remove_file(&global).unwrap();
    symlink(&target, &global).unwrap();
    s.write_raw_config(
        "[[provider]]\ntype = \"config\"\nname = \"src\"\n[provider.sandbox]\n\
         fs.rw = [\"~/src\"]\n",
    );
    let results = s.probe(
        &[],
        &[
            write("/home/user/src/dotfiles/stopit.toml", "pwned"),
            remove("/home/user/src/dotfiles/stopit.toml"),
            rename(
                "/home/user/src/dotfiles/stopit.toml",
                "/home/user/src/dotfiles/old.toml",
            ),
            rename("/home/user/src/dotfiles", "/home/user/src/moved"),
            write("/home/user/src/dotfiles/other", "fine"),
        ],
    );
    assert_eq!(errno(&results[0]), "EROFS", "{results:?}");
    assert_eq!(errno(&results[1]), "EBUSY", "{results:?}");
    assert_eq!(errno(&results[2]), "EBUSY", "{results:?}");
    assert_eq!(errno(&results[3]), "EBUSY", "{results:?}");
    assert_eq!(ok(&results[4]), &Data::Done, "{results:?}");
    assert_eq!(fs::read_to_string(&target).unwrap(), contents);
}

#[test]
fn a_relative_global_script_provider_runs_from_the_configuration_directory() {
    let s = Setup::new();
    let dir = s.config_dir();
    let (probe_dir, _) = probe_at_host_path();
    s.write_global_config(
        "[[provider]]\ntype = \"script\"\nname = \"tools\"\nsource = \"providers/tools.sh\"\n",
    );
    fs::create_dir(dir.join("providers")).unwrap();
    let script = dir.join("providers/tools.sh");
    fs::write(
        &script,
        format!(
            "#!/bin/sh\npwd > '{}'\nprintf '{{\"version\":1,\"fs\":{{\"ro\":[\"{}\"]}}}}'\n",
            s.root.join("cwd.txt").display(),
            probe_dir.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    let results = s.probe(&[], &[Op::Cwd]);
    assert_eq!(ok(&results[0]), &Data::Cwd("/workspace".into()));
    assert_eq!(
        fs::read_to_string(s.root.join("cwd.txt"))
            .unwrap()
            .trim_end(),
        dir.to_str().unwrap()
    );
}

#[test]
fn the_configuration_directory_is_reserved() {
    // The test sets `STOPIT_CONFIG_DIR`; the default location comes from the
    // password database, not `HOME`, so the spec tests cover it.
    let s = Setup::new();
    s.write_global_config(&probe_config(""));
    let parent = s.config_dir().parent().unwrap().to_owned();
    for rw in [parent.clone(), s.config_dir()] {
        s.write_raw_config(&format!(
            "[[provider]]\ntype = \"config\"\nname = \"cfg\"\n[provider.sandbox]\n\
             fs.rw = [\"{}\"]\n",
            rw.display()
        ));
        let out = output(s.run_probe_command(&[]), b"[]");
        assert_eq!(code(&out), 125, "{rw:?}: {out:?}");
        assert!(
            stderr(&out).contains("configuration directory"),
            "{rw:?}: {out:?}"
        );
        assert!(s.no_session_left());
    }
    // Shown read-only with its parent, it is masked quietly.
    s.write_raw_config(&format!(
        "[[provider]]\ntype = \"config\"\nname = \"cfg\"\n[provider.sandbox]\n\
         fs.ro = [\"{}\"]\n",
        parent.display()
    ));
    let inside = s.config_dir().join("config.toml");
    let results = s.probe(&[], &[read(&inside), list(s.config_dir())]);
    assert_eq!(errno(&results[0]), "ENOENT", "{results:?}");
    assert_eq!(ok(&results[1]), &Data::List(vec![]), "{results:?}");
}

// --- Trust on first use ---

/// A script provider at `script` that creates `marker` when it runs.
fn marking_script(script: &Path, marker: &Path) -> String {
    fs::write(
        script,
        format!(
            "#!/bin/sh\ntouch '{}'\nprintf '{{\"version\":1}}'\n",
            marker.display()
        ),
    )
    .unwrap();
    fs::set_permissions(script, fs::Permissions::from_mode(0o755)).unwrap();
    format!(
        "[[provider]]\ntype = \"script\"\nname = \"mark\"\nsource = \"{}\"\n",
        script.display()
    )
}

/// What `stopit` prints when it refuses `config` as not allowed: new (or
/// revoked), or `changed`, with the `allow` command to run.
fn not_allowed(config: &Path, changed: bool, allow: &str) -> String {
    let what = if changed {
        "it changed since it was last allowed"
    } else {
        "it is new: it has not been allowed, or was revoked"
    };
    format!(
        "stopit: error: refusing to use {config:?}: {what}. stopit only uses a configuration \
         you allowed, as it was when you allowed it, since it decides what the sandbox may do \
         and which scripts run on the host; review it, then run `{allow}`\n"
    )
}

#[test]
fn a_configuration_runs_only_once_allowed_and_as_allowed() {
    let s = Setup::new();
    let marker = s.root.join("ran");
    let script = marking_script(&s.root.join("mark.sh"), &marker);
    s.write_unallowed(&probe_config(&script));
    let config = s.config_path();

    // Not allowed: refused before any provider runs or the session
    // directory is created.
    let out = output(s.run_probe_command(&[]), b"[]");
    assert_eq!(code(&out), 125, "{out:?}");
    assert_eq!(stderr(&out), not_allowed(&config, false, "stopit allow"));
    assert!(out.stdout.is_empty(), "{out:?}");
    assert!(!marker.exists(), "the script provider ran");
    assert!(!s.runtime().join("stopit").exists());
    // The store's directory exists, private, but holds nothing yet.
    let mode = |p: &PathBuf| fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777;
    assert_eq!(mode(&s.state_dir()), 0o700);
    assert!(!s.store_file().exists());

    // Allowed, it runs.
    let bytes = fs::read(&config).unwrap();
    let hash = stopit::trust::sha256_hex(&bytes);
    // The whole hash and the size, to check against the version reviewed.
    assert_eq!(
        s.allow(&[]),
        format!(
            "allowed {config:?} ({} bytes, sha256 {hash})\n",
            bytes.len()
        )
    );
    assert_eq!(mode(&s.state_dir()), 0o700);
    assert_eq!(mode(&s.store_file()), 0o600);
    s.probe(&[], &[]);
    assert!(marker.exists());
    fs::remove_file(&marker).unwrap();
    // `allowed` lists it.
    let out = output(s.stopit(&["allowed"]), b"");
    assert_eq!(code(&out), 0, "{out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!("{} {config:?}\n", &hash[..12])
    );

    // Changed by a single byte, it is refused again.
    let mut edited = bytes.clone();
    edited.push(b'\n');
    fs::write(&config, &edited).unwrap();
    let out = output(s.run_probe_command(&[]), b"[]");
    assert_eq!(code(&out), 125, "{out:?}");
    assert_eq!(stderr(&out), not_allowed(&config, true, "stopit allow"));
    assert!(!marker.exists(), "the script provider ran");
    assert!(s.no_session_left());
    // Allowed again, it runs.
    s.allow(&[]);
    s.probe(&[], &[]);
    assert!(marker.exists());
    fs::remove_file(&marker).unwrap();

    // Revoked, it is refused again; a second revoke has nothing to do.
    let out = output(s.stopit(&["revoke"]), b"");
    assert_eq!(code(&out), 0, "{out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!("revoked {config:?}\n")
    );
    let out = output(s.run_probe_command(&[]), b"[]");
    assert_eq!(code(&out), 125, "{out:?}");
    assert_eq!(stderr(&out), not_allowed(&config, false, "stopit allow"));
    assert!(!marker.exists(), "the script provider ran");
    let out = output(s.stopit(&["revoke"]), b"");
    assert_eq!(code(&out), 0, "{out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!("{config:?} was not allowed: nothing to revoke\n")
    );
    let out = output(s.stopit(&["allowed"]), b"");
    assert_eq!(
        (code(&out), out.stdout.as_slice()),
        (0, &b""[..]),
        "{out:?}"
    );
}

#[test]
fn allow_needs_a_configuration_and_a_valid_one() {
    let s = Setup::new();
    let out = output(s.stopit(&["allow"]), b"");
    assert_eq!(code(&out), 125, "{out:?}");
    assert_eq!(
        stderr(&out),
        format!(
            "stopit: error: no .stopit.toml in {} or any directory above it: there is nothing \
             to allow\n",
            s.ws().display()
        )
    );
    // Invalid: refused, so that the mistake shows now.
    s.write_unallowed("bogus = 1\n");
    let out = output(s.stopit(&["allow"]), b"");
    assert_eq!(code(&out), 125, "{out:?}");
    assert!(stderr(&out).contains("bogus"), "{out:?}");
    assert!(!s.store_file().exists());
    // So is one others can write, as `run` refuses it.
    s.write_unallowed("");
    fs::set_permissions(s.config_path(), fs::Permissions::from_mode(0o666)).unwrap();
    let out = output(s.stopit(&["allow"]), b"");
    assert_eq!(code(&out), 125, "{out:?}");
    assert!(
        stderr(&out).contains("writable by its group or others"),
        "{out:?}"
    );
    assert!(!s.store_file().exists());
}

#[test]
fn a_configuration_planted_for_the_workspace_option_is_refused() {
    // `--workspace` does not check for nested configurations, but one the
    // sandbox wrote was never allowed.
    let s = Setup::with_config("");
    let marker = s.root.join("ran");
    let planted = marking_script(&s.root.join("mark.sh"), &marker);
    let results = s.probe(
        &[],
        &[
            mkdir("/workspace/sub"),
            chmod("/workspace/sub", 0o755),
            write("/workspace/sub/.stopit.toml", &planted),
            chmod("/workspace/sub/.stopit.toml", 0o644),
        ],
    );
    for r in &results {
        assert_eq!(ok(r), &Data::Done, "{results:?}");
    }
    let sub = s.ws().join("sub");
    let out = output(s.run_probe_command(&["--workspace", "sub"]), b"[]");
    assert_eq!(code(&out), 125, "{out:?}");
    assert_eq!(
        stderr(&out),
        not_allowed(
            &sub.join(".stopit.toml"),
            false,
            &format!("stopit allow --workspace {}", sub.display())
        )
    );
    assert!(!marker.exists(), "the planted script provider ran");
    assert!(s.no_session_left());
}

#[test]
fn a_configuration_planted_outside_any_workspace_is_refused() {
    // A writable grant of a directory that is no workspace: no outer
    // configuration protects it, so the nested-configuration rule does not
    // apply, but what the sandbox plants there was never allowed.
    let s = Setup::new();
    let other = s.root.join("other");
    fs::create_dir(&other).unwrap();
    fs::set_permissions(&other, fs::Permissions::from_mode(0o755)).unwrap();
    s.write_config(&format!("fs.rw = [{other:?}]"));
    let marker = s.root.join("ran");
    let planted = marking_script(&s.root.join("mark.sh"), &marker);
    // Private, whatever the umask, so that only the trust store refuses it.
    let results = s.probe(
        &[],
        &[
            write(other.join(".stopit.toml"), &planted),
            chmod(other.join(".stopit.toml"), 0o644),
        ],
    );
    for r in &results {
        assert_eq!(ok(r), &Data::Done, "{results:?}");
    }
    // The user later runs from there.
    let mut command = s.run_probe_command(&[]);
    command.current_dir(&other);
    let out = output(command, b"[]");
    assert_eq!(code(&out), 125, "{out:?}");
    assert_eq!(
        stderr(&out),
        not_allowed(&other.join(".stopit.toml"), false, "stopit allow")
    );
    assert!(!marker.exists(), "the planted script provider ran");
    assert!(s.no_session_left());
}

#[test]
fn a_deleted_allowed_configuration_is_not_replaced_by_the_defaults() {
    // The user's configuration may grant less than the default one: once
    // allowed, its absence is refused until the user says otherwise.
    let s = Setup::with_config("");
    s.write_global_config(GLOBAL_SEARCH_PATH);
    let config = s.config_path();
    fs::create_dir(s.ws().join("sub")).unwrap();
    fs::remove_file(&config).unwrap();
    let refused = format!(
        "stopit: error: refusing to run the default configuration: {config:?} was allowed but \
         is missing, and the defaults may grant what it did not; restore it, or run `stopit \
         revoke {}` to use the defaults there\n",
        config.display()
    );
    // From the workspace, from below it, and with `--workspace`.
    for (cwd, options) in [
        (s.ws(), &[][..]),
        (s.ws().join("sub"), &[]),
        (s.root.join("home"), &["--workspace", "../ws"]),
    ] {
        let mut command = s.run_probe_command(options);
        command.current_dir(&cwd);
        let out = output(command, b"[]");
        assert_eq!(code(&out), 125, "{cwd:?} {options:?}: {out:?}");
        assert_eq!(stderr(&out), refused, "{cwd:?} {options:?}");
        assert!(out.stdout.is_empty(), "{out:?}");
        assert!(!s.runtime().join("stopit").exists());
    }
    // `--workspace` does not look up: `sub` was never configured.
    let out = output(s.run_probe_command(&["--workspace", "sub"]), b"[]");
    assert_default_base_ran(&out);
    // `allowed` marks it.
    let out = output(s.stopit(&["allowed"]), b"");
    assert_eq!(code(&out), 0, "{out:?}");
    assert!(
        String::from_utf8_lossy(&out.stdout).ends_with(&format!("{config:?} (missing)\n")),
        "{out:?}"
    );
    // Revoked by its path, the defaults run.
    let out = output(
        s.stopit(&[OsString::from("revoke"), config.clone().into()]),
        b"",
    );
    assert_eq!(code(&out), 0, "{out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!("revoked {config:?}\n")
    );
    let out = output(s.run_probe_command(&[]), b"[]");
    assert_default_base_ran(&out);
    assert!(s.no_session_left());
}

#[test]
fn a_link_swapped_in_for_an_allowed_workspace_does_not_run_the_defaults() {
    // A sandbox with `rw` on the directory holding the workspace moves the
    // workspace away and puts a link to a directory without configuration
    // in its place: discovery resolves the link, and finds none.
    let s = Setup::with_config("");
    s.write_global_config(GLOBAL_SEARCH_PATH);
    let config = s.config_path();
    let ws = s.ws();
    let elsewhere = s.root.join("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    fs::rename(&ws, s.root.join("ws.old")).unwrap();
    symlink(&elsewhere, &ws).unwrap();
    let refused = format!(
        "stopit: error: refusing to run the default configuration: {config:?} was allowed, but \
         {ws:?}, on the way to it, is now a symbolic link, so it is not where it was allowed, \
         and the defaults may grant what it did not; restore it, or run `stopit revoke {}` to \
         use the defaults there\n",
        config.display()
    );
    // From the workspace as the shell names it (`PWD`), or with
    // `--workspace`.
    let mut from_ws = s.run_probe_command(&[]);
    from_ws.env("PWD", &ws);
    let mut named = s.run_probe_command(&["--workspace", "../ws"]);
    named.current_dir(s.root.join("home"));
    for command in [from_ws, named] {
        let what = format!("{command:?}");
        let out = output(command, b"[]");
        assert_eq!(code(&out), 125, "{what}: {out:?}");
        assert_eq!(stderr(&out), refused, "{what}");
        assert!(!s.runtime().join("stopit").exists());
    }
    // Revoked, the defaults run there.
    let out = output(
        s.stopit(&[OsString::from("revoke"), config.clone().into()]),
        b"",
    );
    assert_eq!(code(&out), 0, "{out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!("revoked {config:?}\n")
    );
    let mut command = s.run_probe_command(&[]);
    command.env("PWD", &ws);
    assert_default_base_ran(&output(command, b"[]"));
}

#[test]
fn the_entry_of_a_workspace_that_is_gone_can_be_revoked_by_its_path() {
    // No discovery: the workspace, and the directory above it, are gone.
    let s = Setup::new();
    let gone = s.root.join("gone/ws");
    fs::create_dir_all(&gone).unwrap();
    fs::set_permissions(&gone, fs::Permissions::from_mode(0o755)).unwrap();
    let config = gone.join(".stopit.toml");
    fs::write(&config, "").unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o644)).unwrap();
    s.allow(&["--workspace", gone.to_str().unwrap()]);
    fs::remove_dir_all(s.root.join("gone")).unwrap();
    let revoke = |path: &Path| output(s.stopit(&[Path::new("revoke"), path]), b"");
    // A path that does not name the entry has nothing to revoke.
    let other = s.root.join("gone/other/.stopit.toml");
    let out = revoke(&other);
    assert_eq!(code(&out), 0, "{out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!("{other:?} was not allowed: nothing to revoke\n")
    );
    // As `allowed` lists it, relative to the current directory too.
    let out = revoke(Path::new("../gone/./ws/.stopit.toml"));
    assert_eq!(code(&out), 0, "{out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!("revoked {config:?}\n")
    );
    let out = output(s.stopit(&["allowed"]), b"");
    assert_eq!(
        (code(&out), out.stdout.as_slice()),
        (0, &b""[..]),
        "{out:?}"
    );
    // A directory is not a configuration file; neither option goes with a
    // path.
    let out = revoke(&s.ws());
    assert_eq!(code(&out), 125, "{out:?}");
    assert!(stderr(&out).contains("is a directory"), "{out:?}");
    let out = output(s.stopit(&["revoke", "--workspace", ".", "x"]), b"");
    assert_eq!(code(&out), 2, "{out:?}");
}

#[test]
fn a_read_only_grant_containing_the_trust_store_masks_it_silently() {
    // It lists the user's projects; but `ro ~` is the recommended way to
    // show the home directory, and always contains it, so no warning.
    let s = Setup::new();
    let state = s.state_dir().parent().unwrap().to_path_buf();
    fs::create_dir(&state).unwrap();
    s.write_config(&format!(
        "[[provider]]\ntype = \"config\"\nname = \"state\"\n[provider.sandbox]\n\
         fs.ro = [{state:?}]"
    ));
    assert!(s.store_file().exists());
    let store = s.state_dir();
    let ops = [list(&state), list(&store)];
    let command = s.run_probe_command(&[]);
    let what = format!("{command:?}");
    let out = output(command, &serde_json::to_vec(&ops).unwrap());
    let results = probe_results(&what, &out, &ops);
    assert_eq!(ok(&results[0]), &Data::List(vec!["stopit".into()]));
    assert_eq!(ok(&results[1]), &Data::List(vec![]));
    assert_eq!(stderr(&out), "");
    assert!(s.no_session_left());
}

#[test]
fn a_trust_store_others_can_read_is_refused() {
    let s = Setup::with_config("");
    fs::set_permissions(s.store_file(), fs::Permissions::from_mode(0o644)).unwrap();
    let out = output(s.run_probe_command(&[]), b"[]");
    assert_eq!(code(&out), 125, "{out:?}");
    assert_eq!(
        stderr(&out),
        format!(
            "stopit: error: refusing to read the trust store {:?}: it is accessible to its \
             group or others (mode 0644); run `chmod 600` on it\n",
            s.store_file()
        )
    );
    assert!(!s.runtime().join("stopit").exists());
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
fn a_writable_grant_containing_the_data_directory_is_refused_and_nothing_runs() {
    // A sandbox could otherwise write stopit's own state, which decides
    // what the next session trusts. The data directory need not exist.
    let message = |grant: &PathBuf, sandbox: &str, data: &PathBuf| {
        format!(
            "stopit: error: cannot compile profile \"main\": provider \"tools\": rw mount of \
             {grant:?} at {sandbox:?} contains stopit's data directory {data:?}, which holds \
             stopit's persistent state, such as which configurations you allowed; a sandbox \
             could write it there, create it, or replace a directory or link on the way to it, \
             so no writable mount may contain it or the way to it: grant narrower rw paths that \
             leave them out, or make this mount ro\n"
        )
    };
    // The data directory is `STOPIT_STATE_DIR`, not in `HOME` (which points
    // elsewhere): a grant of its parent is refused. (It exists: `allow`
    // created it, as every run does.)
    let s = Setup::new();
    let data = s.state_dir();
    let parent = data.parent().unwrap().to_path_buf();
    s.write_config(&format!("fs.rw = [{parent:?}]"));
    let store = fs::read(s.store_file()).unwrap();
    let out = output(s.run_probe_command(&[]), b"[]");
    assert_eq!(code(&out), 125, "{out:?}");
    assert_eq!(
        stderr(&out),
        message(&parent, parent.to_str().unwrap(), &data)
    );
    assert!(out.stdout.is_empty(), "{out:?}");
    assert!(s.no_session_left());
    assert_eq!(fs::read(s.store_file()).unwrap(), store);
    // `~` is fine: the data directory is never taken from `HOME`. (The
    // default base's ephemeral `~` would win over it, so without it.)
    let home = s.root.join("home");
    s.write_raw_config(&format!(
        "base = \"none\"\n{}",
        probe_config("fs.rw = [\"~\"]")
    ));
    let results = s.probe(&[], &[write("/home/user/file", "x")]);
    assert!(matches!(ok(&results[0]), Data::Done), "{results:?}");
    assert_eq!(fs::read_to_string(home.join("file")).unwrap(), "x");
    assert!(!home.join(".local").exists());
}

#[test]
fn a_relative_state_dir_override_is_refused() {
    let s = Setup::with_config("");
    let mut command = s.run_probe_command(&[]);
    command.env("STOPIT_STATE_DIR", "state");
    let out = output(command, b"[]");
    assert_eq!(code(&out), 125, "{out:?}");
    assert_eq!(
        stderr(&out),
        "stopit: error: STOPIT_STATE_DIR \"state\" is not an absolute path; set it to the \
         absolute path of stopit's data directory, or unset it\n"
    );
    assert!(out.stdout.is_empty(), "{out:?}");
    // Before any session is created.
    assert!(!s.runtime().join("stopit").exists());
}

#[test]
fn a_read_only_grant_containing_the_runtime_directory_masks_it() {
    // It holds every session's sockets and ephemeral directories, this
    // one's included.
    let s = Setup::new();
    let runtime = s.runtime();
    s.write_config(&format!(
        "[[provider]]\ntype = \"config\"\nname = \"run\"\n[provider.sandbox]\n\
         fs.ro = [{runtime:?}]"
    ));
    let ops = [list(&runtime), list(runtime.join("stopit"))];
    let command = s.run_probe_command(&[]);
    let what = format!("{command:?}");
    let out = output(command, &serde_json::to_vec(&ops).unwrap());
    let results = probe_results(&what, &out, &ops);
    assert_eq!(ok(&results[0]), &Data::List(vec!["stopit".into()]));
    assert_eq!(ok(&results[1]), &Data::List(vec![]));
    let stopit = runtime.join("stopit");
    assert_eq!(
        stderr(&out),
        format!(
            "stopit: warning: provider \"run\": ro mount of {runtime:?} at {runtime:?} \
             contains stopit's session runtime directory {stopit:?}, which holds every \
             session's sockets, shims and ephemeral directories (other sessions' data \
             included), so it is masked at {stopit:?}; grant narrower paths that leave it out \
             to silence this\n"
        )
    );
    assert!(s.no_session_left());
}

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
    // `stopit allow` refuses an invalid configuration, so it is allowed
    // through the trust store directly, as if it had been valid.
    let s = Setup::new();
    let contents = "bogus = \"\x1b]52;c;aGk=\x07\"\n";
    s.write_unallowed(contents);
    stopit::trust::TrustStore::open(&s.state_dir())
        .unwrap()
        .update(|a| a.allow(s.config_path(), contents.as_bytes()))
        .unwrap();
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

/// The `tty_nr` that `/proc/<pid>/stat` shows for the terminal `tty`.
fn tty_nr_of(tty: &File) -> u64 {
    use std::os::unix::fs::MetadataExt;
    let rdev = tty.metadata().unwrap().rdev();
    let (major, minor) = (libc::major(rdev) as u64, libc::minor(rdev) as u64);
    (minor & 0xff) | (major << 8) | ((minor & !0xff) << 12)
}

#[test]
fn the_sandbox_never_has_the_host_terminal() {
    let Some((master, slave)) = open_pty() else {
        return;
    };
    let host = tty_nr_of(&slave);
    let s = Setup::with_config("");
    let ops = [read("/proc/self/stat")];
    let input = serde_json::to_vec(&ops).unwrap();

    // Every stdio redirected, but the terminal still reachable as
    // `/dev/tty`: detached, with no controlling terminal at all.
    let mut command = s.run_probe_command(&[]);
    with_controlling_terminal(&mut command, &slave);
    let out = output(command, &input);
    let results = probe_results("stopit run, a terminal but no tty stdio", &out, &ops);
    assert_eq!(tty_nr(contents(&results[0])), 0, "{results:?}");

    // The terminal as stderr: a PTY of its own, whose slave is the
    // sandbox's controlling terminal.
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
    let nr = tty_nr(contents(&results[0]));
    assert!(nr != 0 && nr != host, "{nr} {host} {results:?}");
    assert!(s.no_session_left());
    drop(master);
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
fn a_terminal_as_stdin_alone_gets_a_pty_of_its_own() {
    // No controlling terminal: only stdin reaches the terminal. stopit
    // reads the keys and passes them to the sandbox's PTY, whose line
    // discipline turns Ctrl-D into the end of the probe's input.
    let Some((master, slave)) = open_pty() else {
        return;
    };
    let host = tty_nr_of(&slave);
    let s = Setup::with_config("");
    let ops = [read("/proc/self/stat"), Op::Argv];
    let mut command = s.run_probe_command(&[]);
    command
        .stdin(slave.try_clone().unwrap())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    without_controlling_terminal(&mut command);
    let child = command.spawn().unwrap();
    wait_for_probe(child.id() as i32);
    let mut input = serde_json::to_vec(&ops).unwrap();
    input.extend_from_slice(b"\n\x04");
    (&master).write_all(&input).unwrap();
    let out = finish(child);
    let results = probe_results("stopit run, the terminal as stdin", &out, &ops);
    let nr = tty_nr(contents(&results[0]));
    assert!(nr != 0 && nr != host, "{nr} {host} {results:?}");
    assert!(stderr(&out).is_empty(), "{out:?}");
    assert!(s.no_session_left());
}

#[test]
fn a_terminal_as_stdout_alone_gets_a_pty_of_its_own() {
    // No controlling terminal: only stdout reaches the terminal. The
    // results are read back from the terminal's master.
    let Some((master, slave)) = open_pty() else {
        return;
    };
    let host = tty_nr_of(&slave);
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
    let nr = tty_nr(contents(&results[0]));
    assert!(nr != 0 && nr != host, "{nr} {host} {results:?}");
    assert!(s.no_session_left());
}

/// stopit run on the terminal `slave` (stdin, stdout, stderr and controlling
/// terminal), with everything written to the terminal collected from
/// `master` by a thread.
struct OnTerminal {
    child: Option<Child>,
    master: File,
    seen: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
}

impl OnTerminal {
    fn spawn(mut command: Command, master: File, slave: File) -> Self {
        command
            .stdin(slave.try_clone().unwrap())
            .stdout(slave.try_clone().unwrap())
            .stderr(slave.try_clone().unwrap());
        with_controlling_terminal(&mut command, &slave);
        let child = command.spawn().unwrap();
        drop(command);
        drop(slave);
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut reader = master.try_clone().unwrap();
        let sink = seen.clone();
        thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = reader.read(&mut buf) {
                if n == 0 {
                    break;
                }
                sink.lock().unwrap().extend_from_slice(&buf[..n]);
            }
        });
        OnTerminal {
            child: Some(child),
            master,
            seen,
        }
    }

    fn pid(&self) -> i32 {
        self.child.as_ref().unwrap().id() as i32
    }

    /// Waits for stopit to end, as [`finish`] does.
    fn finish(&mut self) -> Output {
        finish(self.child.take().unwrap())
    }

    fn type_keys(&self, keys: &[u8]) {
        (&self.master).write_all(keys).unwrap();
    }

    fn seen(&self) -> Vec<u8> {
        self.seen.lock().unwrap().clone()
    }

    /// Waits until the terminal has shown `needle` since byte `from`, and
    /// returns where it ends.
    #[track_caller]
    fn wait_for(&self, needle: &[u8], from: usize) -> usize {
        let deadline = Instant::now() + BWRAP_DEADLINE;
        loop {
            let seen = self.seen();
            if let Some(at) = seen[from.min(seen.len())..]
                .windows(needle.len())
                .position(|w| w == needle)
            {
                return from + at + needle.len();
            }
            assert!(
                Instant::now() < deadline,
                "{:?} not shown; the terminal shows {:?}",
                String::from_utf8_lossy(needle),
                String::from_utf8_lossy(&seen)
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
}

/// Polls `f` until it returns something, within the usual deadline.
#[track_caller]
fn wait_until<T>(mut f: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + BWRAP_DEADLINE;
    loop {
        if let Some(t) = f() {
            return t;
        }
        assert!(Instant::now() < deadline, "not within {BWRAP_DEADLINE:?}");
        thread::sleep(Duration::from_millis(20));
    }
}

/// A configuration granting the host's `/bin/sh` and coreutils, or `None`
/// (the test is skipped) if the host has no `/bin/sh` there.
fn shell_config() -> Option<String> {
    if !Path::new("/bin/sh").exists() || !Path::new("/usr/bin/stty").exists() {
        eprintln!("skipping: no /bin/sh or /usr/bin/stty on the host");
        return None;
    }
    let dirs: Vec<String> = ["/usr", "/bin", "/lib", "/lib64"]
        .into_iter()
        .filter(|d| Path::new(d).exists())
        .map(|d| format!("{d:?}"))
        .collect();
    Some(format!(
        "[[provider]]\ntype = \"config\"\nname = \"sh\"\n[provider.sandbox]\n\
         fs.ro = [{}]\nenv.path_prepend = [\"/usr/bin\", \"/bin\"]\n\
         env.set = {{ PS1 = \"sandbox$ \" }}\n",
        dirs.join(", ")
    ))
}

#[test]
fn job_control_works_inside_the_sandbox() {
    let Some(config) = shell_config() else {
        return;
    };
    let Some((master, slave)) = open_pty() else {
        return;
    };
    let s = Setup::with_config(&config);
    let command = s.stopit(&["run", "--quiet", "/bin/sh", "-i"]);
    let mut t = OnTerminal::spawn(command, master, slave);
    let at = t.wait_for(b"sandbox$ ", 0);
    // Ctrl-Z stops the foreground job, not stopit, nor the shell.
    t.type_keys(b"sleep 30\r");
    let pid = t.pid();
    let sleep = wait_until(|| {
        descendants(pid)
            .into_iter()
            .find(|&p| fs::read(format!("/proc/{p}/comm")).is_ok_and(|c| c == b"sleep\n"))
    });
    t.type_keys(b"\x1a");
    let at = t.wait_for(b"sandbox$ ", at);
    wait_until(|| (state(sleep).as_deref() == Some("T")).then_some(()));
    assert_ne!(state(pid).as_deref(), Some("T"));
    // `fg` resumes it, and Ctrl-C ends it, again without touching stopit.
    t.type_keys(b"fg\r");
    wait_until(|| (state(sleep).as_deref() != Some("T")).then_some(()));
    t.type_keys(b"\x03");
    let at = t.wait_for(b"sandbox$ ", at);
    wait_gone(sleep);
    t.type_keys(b"exit 7\r");
    let out = t.finish();
    assert_eq!(
        code(&out),
        7,
        "{:?}",
        String::from_utf8_lossy(&t.seen.lock().unwrap())
    );
    assert!(t.seen().len() >= at);
    assert!(s.no_session_left());
}

#[test]
fn window_size_changes_reach_the_sandbox() {
    let Some(config) = shell_config() else {
        return;
    };
    let Some((master, slave)) = open_pty() else {
        return;
    };
    let size = |rows, cols| rustix::termios::Winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    rustix::termios::tcsetwinsize(&slave, size(24, 80)).unwrap();
    let s = Setup::with_config(&config);
    let command = s.stopit(&["run", "--quiet", "/bin/sh", "-i"]);
    let mut t = OnTerminal::spawn(command, master, slave);
    let at = t.wait_for(b"sandbox$ ", 0);
    t.type_keys(b"stty size\r");
    let at = t.wait_for(b"24 80", at);
    // The terminal emulator resizes: the kernel signals stopit, which is in
    // the terminal's foreground, and stopit resizes the sandbox's PTY.
    rustix::termios::tcsetwinsize(&t.master, size(50, 132)).unwrap();
    // The signal may arrive after the next command runs: asked again until
    // the new size shows.
    let mut from = at;
    wait_until(|| {
        t.type_keys(b"stty size\r");
        from = t.wait_for(b"sandbox$ ", from);
        let seen = t.seen();
        String::from_utf8_lossy(&seen[at..])
            .contains("50 132")
            .then_some(())
    });
    t.type_keys(b"exit\r");
    let out = t.finish();
    assert_eq!(code(&out), 0, "{out:?}");
}

#[test]
fn escape_sequences_from_the_sandbox_are_filtered() {
    let Some(config) = shell_config() else {
        return;
    };
    let Some((master, slave)) = open_pty() else {
        return;
    };
    let s = Setup::with_config(&config);
    // The kitty keyboard protocol and the alternate screen pass; a
    // clipboard read, a title report, kitty graphics from a file, OSC 1337
    // and tmux passthrough do not. The modes left on are turned off.
    let script = "printf 'A\\033[>1uB\\033[?1049hC\\033]52;c;?\\007D\\033[21tE\
                  \\033_Gt=f;L2V0Yw==\\033\\\\F\\033]1337;File=x\\007G\\033Ptmux;x\\033\\\\H'";
    let command = s.stopit(&["run", "--quiet", "/bin/sh", "-c", script]);
    let mut t = OnTerminal::spawn(command, master, slave);
    let out = t.finish();
    assert_eq!(code(&out), 0, "{out:?}");
    let at = t.wait_for(b"\x1b[<1u", 0);
    let seen = t.seen();
    assert_eq!(
        String::from_utf8_lossy(&seen[..at]),
        "A\x1b[>1uB\x1b[?1049hCDEFGH\x1b[?1049l\x1b[<1u"
    );
}

#[test]
fn the_last_output_is_passed_on_in_full() {
    let Some(config) = shell_config() else {
        return;
    };
    let Some((master, slave)) = open_pty() else {
        return;
    };
    let s = Setup::with_config(&config);
    let command = s.stopit(&[
        "run",
        "--quiet",
        "/bin/sh",
        "-c",
        "head -c 1048576 /dev/zero | tr '\\0' x",
    ]);
    let mut t = OnTerminal::spawn(command, master, slave);
    let out = t.finish();
    assert_eq!(code(&out), 0, "{out:?}");
    let count = || t.seen().iter().filter(|&&b| b == b'x').count();
    wait_until(|| (count() == 1 << 20).then_some(()));
}

#[test]
fn a_sandbox_that_reopens_its_terminal_still_reaches_it() {
    let Some(config) = shell_config() else {
        return;
    };
    let Some((master, slave)) = open_pty() else {
        return;
    };
    let s = Setup::with_config(&config);
    // Every copy of the slave closed for a while, then `/dev/tty` opened,
    // as pinentry does after `exec </dev/null >/dev/null 2>&1`.
    let script = "exec </dev/null >/dev/null 2>&1; sleep 0.3; \
                  echo again >/dev/tty; read line </dev/tty; echo \"got $line\" >/dev/tty";
    let command = s.stopit(&["run", "--quiet", "/bin/sh", "-c", script]);
    let mut t = OnTerminal::spawn(command, master, slave);
    let at = t.wait_for(b"again", 0);
    t.type_keys(b"key\r");
    t.wait_for(b"got key", at);
    let out = t.finish();
    assert_eq!(code(&out), 0, "{out:?}");
}

#[test]
fn the_host_terminal_is_restored_when_stopit_is_killed() {
    let Some(config) = shell_config() else {
        return;
    };
    let Some((master, slave)) = open_pty() else {
        return;
    };
    let before = rustix::termios::tcgetattr(&slave).unwrap();
    let probe_slave = slave.try_clone().unwrap();
    let s = Setup::with_config(&config);
    let command = s.stopit(&["run", "--quiet", "/bin/sh", "-i"]);
    let mut t = OnTerminal::spawn(command, master, slave);
    t.wait_for(b"sandbox$ ", 0);
    // Raw while the sandbox runs.
    let raw = rustix::termios::tcgetattr(&probe_slave).unwrap();
    assert!(
        !raw.local_modes
            .contains(rustix::termios::LocalModes::ICANON)
    );
    kill(t.pid(), libc::SIGTERM);
    let out = t.finish();
    assert_eq!(code(&out), 128 + libc::SIGTERM, "{out:?}");
    let after = rustix::termios::tcgetattr(&probe_slave).unwrap();
    assert_eq!(after.local_modes, before.local_modes);
    assert_eq!(after.input_modes, before.input_modes);
    assert!(s.no_session_left());
}

#[test]
fn the_host_terminal_settings_survive_the_sandbox() {
    let Some(config) = shell_config() else {
        return;
    };
    let Some((master, slave)) = open_pty() else {
        return;
    };
    let before = rustix::termios::tcgetattr(&slave).unwrap();
    let s = Setup::with_config(&config);
    // The sandbox turns off echo on its terminal and exits.
    let command = s.stopit(&["run", "--quiet", "/bin/sh", "-c", "stty -echo raw; exit 3"]);
    let probe_slave = slave.try_clone().unwrap();
    let mut t = OnTerminal::spawn(command, master, slave);
    let out = t.finish();
    assert_eq!(code(&out), 3, "{out:?}");
    let after = rustix::termios::tcgetattr(&probe_slave).unwrap();
    assert_eq!(after.local_modes, before.local_modes);
    assert_eq!(after.input_modes, before.input_modes);
    assert_eq!(after.output_modes, before.output_modes);
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
         background?); it relays the terminal to the sandbox, so it only starts in the \
         foreground\n"
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
    let mut command = s.stopit(&["shell", "--quiet"]);
    command.env("SHELL", &exe);
    let results = s.probe_with(command, &[Op::Argv, Op::Cwd]);
    assert_eq!(
        ok(&results[0]),
        &Data::Argv(vec![exe.to_str().unwrap().to_owned()])
    );
    assert_eq!(ok(&results[1]), &Data::Cwd("/workspace".into()));
    assert!(s.no_session_left());
}

#[test]
fn bwrap_setup_failure_exits_125_while_target_failure_keeps_its_code() {
    let s = Setup::with_config(
        "[[provider]]\ntype = \"config\"\nname = \"bad_mount\"\n[provider.sandbox]\n\
         fs.ephemeral = [\"{workspace}/not_a_dir/sub\"]\n",
    );
    fs::write(s.ws().join("not_a_dir"), "regular file").unwrap();

    // Real bwrap fails after clone when mkdir tries to create `sub` below a
    // regular file, emitting `child-pid` without `exit-code`.
    let out = output(s.run_probe_command(&[]), b"[]");
    assert_eq!(code(&out), 125, "{out:?}");
    assert!(s.no_session_left());

    // Once `not_a_dir` is a directory, bwrap succeeds and target exit codes
    // pass through rather than turning into 125.
    fs::remove_file(s.ws().join("not_a_dir")).unwrap();
    fs::create_dir(s.ws().join("not_a_dir")).unwrap();
    let bad_input_out = output(s.run_probe_command(&[]), b"not valid json");
    assert_eq!(code(&bad_input_out), 2, "{bad_input_out:?}");
    assert!(s.no_session_left());
    let ok_out = output(s.run_probe_command(&[]), b"[]");
    assert_eq!(code(&ok_out), 0, "{ok_out:?}");
    assert!(s.no_session_left());
}

#[test]
fn signal_during_script_provider_kills_its_process_group_and_cleans_up() {
    for (sig, use_pgrp, expected_code) in [
        (libc::SIGTERM, false, 128 + libc::SIGTERM),
        (libc::SIGINT, true, 128 + libc::SIGINT),
    ] {
        let s = Setup::new();
        let script = s.root.join("provider.sh");
        let pids_file = s.root.join("pids.txt");
        let ready_file = s.root.join("ready.txt");
        fs::write(
            &script,
            format!(
                "#!/bin/sh\n\
                 sleep 60 &\n\
                 bg=$!\n\
                 printf '%s\\n%s\\n' \"$$\" \"$bg\" > \"{}\"\n\
                 printf 'ok' > \"{}\"\n\
                 wait \"$bg\"\n",
                pids_file.display(),
                ready_file.display(),
            ),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();

        s.write_config(&format!(
            "[[provider]]\ntype = \"script\"\nsource = \"{}\"\n",
            script.display()
        ));

        let mut command = s.run_probe_command(&[]);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if use_pgrp {
            command.process_group(0);
        }
        let child = command.spawn().unwrap();
        let stopit_pid = child.id() as i32;

        let deadline = Instant::now() + BWRAP_DEADLINE;
        while !ready_file.exists() {
            assert!(
                Instant::now() < deadline,
                "script provider did not start in time"
            );
            thread::sleep(Duration::from_millis(10));
        }
        let pids: Vec<i32> = fs::read_to_string(&pids_file)
            .unwrap()
            .lines()
            .map(|l| l.parse().unwrap())
            .collect();
        assert_eq!(pids.len(), 2);

        if use_pgrp {
            kill(-stopit_pid, sig);
        } else {
            kill(stopit_pid, sig);
        }
        let out = finish(child);
        assert_eq!(code(&out), expected_code, "{out:?}");
        assert_eq!(stderr(&out), "", "{out:?}");
        assert!(s.no_session_left());
        for pid in pids {
            wait_gone(pid);
        }
    }
}

// --- stopit server ---

/// A running `stopit server` for a setup's workspace, with everything it
/// writes to stderr collected.
struct Server {
    child: Option<Child>,
    log: std::sync::Arc<std::sync::Mutex<String>>,
    /// The session id it announced.
    id: String,
}

impl Server {
    /// Starts `stopit server` in `s`'s workspace and waits until it serves.
    fn start(s: &Setup) -> Server {
        let mut command = s.stopit(&["server"]);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let mut child = command.spawn().unwrap();
        let stderr = child.stderr.take().unwrap();
        Server::collect(child, File::from(OwnedFd::from(stderr)))
    }

    /// Starts `stopit server` with the terminal `slave` as its stdin and
    /// stderr, as from a terminal window, and collects what it shows from
    /// `master`, where the test also types.
    fn start_on_terminal(s: &Setup, master: &File, slave: File) -> Server {
        let mut command = s.stopit(&["server"]);
        command
            .stdin(slave.try_clone().unwrap())
            .stdout(Stdio::null())
            .stderr(slave.try_clone().unwrap());
        with_controlling_terminal(&mut command, &slave);
        let child = command.spawn().unwrap();
        drop(command);
        drop(slave);
        Server::collect(child, master.try_clone().unwrap())
    }

    fn collect(child: Child, mut stderr: File) -> Server {
        let log = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let sink = log.clone();
        thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = stderr.read(&mut buf) {
                if n == 0 {
                    break;
                }
                sink.lock()
                    .unwrap()
                    .push_str(&String::from_utf8_lossy(&buf[..n]));
            }
        });
        let mut server = Server {
            child: Some(child),
            log,
            id: String::new(),
        };
        let line = server.wait_for_log("serving ");
        let id = line
            .split(" as session ")
            .nth(1)
            .and_then(|rest| rest.split(';').next())
            .unwrap_or_else(|| panic!("no session id in {line:?}"));
        server.id = id.to_owned();
        server
    }

    fn pid(&self) -> i32 {
        self.child.as_ref().unwrap().id() as i32
    }

    fn log(&self) -> String {
        self.log.lock().unwrap().clone()
    }

    /// Waits until the log has a line containing `needle`, and returns it.
    #[track_caller]
    fn wait_for_log(&self, needle: &str) -> String {
        let deadline = Instant::now() + BWRAP_DEADLINE;
        loop {
            let log = self.log();
            if let Some(line) = log.lines().find(|l| l.contains(needle)) {
                return line.to_owned();
            }
            assert!(
                Instant::now() < deadline,
                "{needle:?} not logged; the log is {log:?}"
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    /// Stops the server with `SIGTERM` and returns its exit status.
    fn stop(&mut self) -> i32 {
        let child = self.child.take().unwrap();
        kill(child.id() as i32, libc::SIGTERM);
        code(&finish(child))
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[test]
fn runs_attached_to_a_server_share_its_session() {
    let s = Setup::with_config("");
    let mut server = Server::start(&s);
    // One run writes the session's `/tmp`, the next reads it.
    let results = s.probe(&[], &[write("/tmp/shared", "from run 1")]);
    assert_eq!(ok(&results[0]), &Data::Done);
    let results = s.probe(&[], &[read("/tmp/shared")]);
    assert_eq!(contents(&results[0]), "from run 1");
    // The same through `--server`, from outside the workspace.
    let mut command = s.run_probe_command(&["--server", &server.id]);
    command.current_dir(s.root.join("home"));
    let results = s.probe_with(command, &[read("/tmp/shared")]);
    assert_eq!(contents(&results[0]), "from run 1");
    // A standalone run has a session of its own.
    let results = s.probe(&["--standalone"], &[read("/tmp/shared")]);
    assert_eq!(errno(&results[0]), "ENOENT");
    server.wait_for_log("run 3 ended with status 0");
    // Stopped, it removes its session.
    assert_eq!(server.stop(), 128 + libc::SIGTERM);
    assert!(s.no_session_left());
}

#[test]
fn an_attached_run_reports_the_commands_status_and_the_servers_errors() {
    let s = Setup::with_config("[profiles.other]\n");
    let _server = Server::start(&s);
    // The probe's own failure.
    let out = output(s.run_probe_command(&[]), b"not json");
    assert_eq!(code(&out), 2, "{out:?}");
    assert!(
        stderr(&out).contains("stdin is not a JSON array"),
        "{out:?}"
    );
    // The summary comes from the server, unless quiet.
    let out = output(s.run_probe_command_with_summary(&[]), b"[]");
    assert_eq!(code(&out), 0, "{out:?}");
    assert!(stderr(&out).starts_with(&summary_header(&s)), "{out:?}");
    // An unknown profile.
    let out = output(s.run_probe_command(&["--profile", "nope"]), b"[]");
    assert_eq!(code(&out), 125, "{out:?}");
    assert_eq!(
        stderr(&out),
        "stopit: error: the stopit server says: there is no profile \"nope\"; the profiles \
         are: main, other\n"
    );
}

#[test]
fn server_lookup_errors() {
    let s = Setup::with_config("");
    let out = output(s.run_probe_command(&["--server", "0123"]), b"[]");
    assert_eq!(code(&out), 125, "{out:?}");
    assert_eq!(
        stderr(&out),
        "stopit: error: no stopit server runs as session 0123; start one with `stopit server` \
         in the workspace, or leave out --server\n"
    );
    let server = Server::start(&s);
    let out = output(s.stopit(&["server"]), b"");
    assert_eq!(code(&out), 125, "{out:?}");
    assert!(
        stderr(&out).contains(&format!(
            "a stopit server already serves {:?} as session {}",
            s.ws(),
            server.id
        )),
        "{out:?}"
    );
}

#[test]
fn signals_to_an_attached_client_end_only_its_sandbox() {
    let s = Setup::with_config("");
    let server = Server::start(&s);
    for signal in [libc::SIGTERM, libc::SIGKILL] {
        let mut child = spawn_waiting_probe(&s, |_| {});
        let stdin = child.stdin.take();
        let client = child.id() as i32;
        // The probe runs under the server, not the client.
        let probe = wait_for_probe(server.pid());
        assert!(!descendants(client).contains(&probe));
        kill(client, signal);
        let out = finish(child);
        drop(stdin);
        use std::os::unix::process::ExitStatusExt;
        let got = out.status.signal().or(out.status.code().map(|c| c - 128));
        assert_eq!(got, Some(signal), "{out:?}");
        wait_gone(probe);
    }
    // The server still serves.
    let results = s.probe(&[], &[Op::Cwd]);
    assert_eq!(ok(&results[0]), &Data::Cwd("/workspace".into()));
}

#[test]
fn stopping_the_server_ends_the_sandboxes_it_runs() {
    let s = Setup::with_config("");
    let mut server = Server::start(&s);
    let mut child = spawn_waiting_probe(&s, |_| {});
    let stdin = child.stdin.take();
    server.wait_for_log("run 1 started");
    assert_eq!(server.stop(), 128 + libc::SIGTERM);
    let out = finish(child);
    drop(stdin);
    assert_eq!(code(&out), 128 + libc::SIGKILL, "{out:?}");
    assert!(s.no_session_left());
}

#[test]
fn stale_session_directories_are_removed() {
    let s = Setup::with_config("");
    // A session killed with SIGKILL left its directory, lock file and all,
    // and one without a lock file may belong to an older stopit.
    let base = s.runtime().join("stopit");
    fs::create_dir_all(&base).unwrap();
    fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
    let stale = base.join("0123456789abcdef0123456789abcdef");
    let unlocked = base.join("fedcba9876543210fedcba9876543210");
    for dir in [&stale, &unlocked] {
        fs::create_dir(dir).unwrap();
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(dir.join("ephemeral")).unwrap();
    }
    fs::write(stale.join("lock"), "").unwrap();
    let results = s.probe(&[], &[Op::Cwd]);
    assert_eq!(ok(&results[0]), &Data::Cwd("/workspace".into()));
    assert!(!stale.exists());
    assert!(unlocked.exists());
    // A live server's session is not stale.
    let server = Server::start(&s);
    s.probe(&["--standalone"], &[Op::Cwd]);
    assert!(base.join(&server.id).exists());
}

#[test]
fn an_attached_run_gets_the_clients_terminal() {
    let Some(config) = shell_config() else {
        return;
    };
    let Some((master, slave)) = open_pty() else {
        return;
    };
    let s = Setup::with_config(&config);
    let server = Server::start(&s);
    // The client's PTY and filter: kitty keyboard passes, a clipboard read
    // does not, and the sandbox's controlling terminal is not the server's.
    let script = "printf 'A\\033[>1uB\\033]52;c;?\\007C'; [ -t 0 ] && echo ' tty'; exit 5";
    let command = s.stopit(&["run", "--quiet", "/bin/sh", "-c", script]);
    let mut t = OnTerminal::spawn(command, master, slave);
    let out = t.finish();
    assert_eq!(code(&out), 5, "{out:?}");
    t.wait_for(b" tty", 0);
    let seen = String::from_utf8_lossy(&t.seen()).into_owned();
    assert!(seen.starts_with("A\x1b[>1uBC tty"), "{seen:?}");
    assert!(
        server.log().contains("run 1 ended with status 5"),
        "{}",
        server.log()
    );
}

#[test]
fn an_attached_terminal_is_raw_and_keys_reach_the_sandbox() {
    let Some(config) = shell_config() else {
        return;
    };
    let Some((master, slave)) = open_pty() else {
        return;
    };
    let s = Setup::with_config(&config);
    let _server = Server::start(&s);
    let command = s.stopit(&["run", "--quiet", "/bin/sh", "-i"]);
    let mut t = OnTerminal::spawn(command, master, slave);
    let at = t.wait_for(b"sandbox$ ", 0);
    // Ctrl-C at the prompt reaches the sandbox's shell, which only prints a
    // new prompt; the client survives it.
    t.type_keys(b"\x03");
    let at = t.wait_for(b"sandbox$ ", at);
    t.type_keys(b"echo $((6*7))\r");
    let at = t.wait_for(b"42", at);
    t.wait_for(b"sandbox$ ", at);
    t.type_keys(b"exit 3\r");
    let out = t.finish();
    assert_eq!(code(&out), 3, "{:?}", String::from_utf8_lossy(&t.seen()));
    // Typed once and echoed once, by the sandbox's terminal.
    let seen = String::from_utf8_lossy(&t.seen()).into_owned();
    assert_eq!(seen.matches("echo $((6*7))").count(), 1, "{seen:?}");
}

#[test]
fn attached_runs_at_once_each_get_their_own_stdio() {
    let s = Setup::with_config("");
    let server = Server::start(&s);
    let mut a = spawn_waiting_probe(&s, |_| {});
    let mut b = spawn_waiting_probe(&s, |_| {});
    server.wait_for_log("run 2 started");
    let feed = |child: &mut Child, ops: &[Op]| {
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(&serde_json::to_vec(ops).unwrap()).unwrap();
    };
    // Different operations, so swapped stdio would show.
    feed(
        &mut b,
        &[write("/tmp/b", "from b"), read("/tmp/b"), Op::Cwd],
    );
    feed(&mut a, &[write("/tmp/a", "from a"), read("/tmp/a")]);
    let out_a = finish(a);
    let out_b = finish(b);
    for (out, name) in [(&out_a, "a"), (&out_b, "b")] {
        assert_eq!(code(out), 0, "{name}: {out:?}");
    }
    let results_a: Vec<OpResult> = serde_json::from_slice(&out_a.stdout).unwrap();
    let results_b: Vec<OpResult> = serde_json::from_slice(&out_b.stdout).unwrap();
    assert_eq!(results_a.len(), 2);
    assert_eq!(contents(&results_a[1]), "from a");
    assert_eq!(results_b.len(), 3);
    assert_eq!(contents(&results_b[1]), "from b");
    let results = s.probe(&[], &[read("/tmp/a"), read("/tmp/b")]);
    assert_eq!(contents(&results[0]), "from a");
    assert_eq!(contents(&results[1]), "from b");
}

#[test]
fn a_server_compiles_every_run_against_the_filesystem_as_it_is() {
    // A secret created after the server started is masked like one that was
    // there before.
    let s = Setup::with_config("");
    let _server = Server::start(&s);
    fs::write(s.ws().join(".env"), "SECRET=1").unwrap();
    let results = s.probe(&[], &[read("/workspace/.env")]);
    assert_eq!(errno(&results[0]), "EACCES", "{results:?}");
}

#[test]
fn a_sandbox_cannot_reach_the_servers_control_socket() {
    let s = Setup::new();
    let config = probe_config(&format!(
        "[[provider]]\ntype = \"config\"\nname = \"rt\"\n[provider.sandbox]\nfs.ro = [{:?}]\n",
        s.runtime()
    ));
    s.write_raw_config(&config);
    let server = Server::start(&s);
    let socket = s
        .runtime()
        .join("stopit")
        .join(&server.id)
        .join("control/socket");
    assert!(socket.exists());
    let ops = [stat(&socket), list(s.runtime().join("stopit"))];
    let out = output(s.run_probe_command(&[]), &serde_json::to_vec(&ops).unwrap());
    assert_eq!(code(&out), 0, "{out:?}");
    let results = probe_results("ro runtime dir", &out, &ops);
    assert_eq!(errno(&results[0]), "ENOENT", "{results:?}");
    assert_eq!(ok(&results[1]), &Data::List(vec![]), "{results:?}");
}

#[test]
fn a_server_stops_promptly_with_an_idle_client() {
    let s = Setup::with_config("");
    let mut server = Server::start(&s);
    let socket = s
        .runtime()
        .join("stopit")
        .join(&server.id)
        .join("control/socket");
    // Connected, but sends nothing.
    let idle = std::os::unix::net::UnixStream::connect(&socket).unwrap();
    thread::sleep(Duration::from_millis(100));
    let start = Instant::now();
    assert_eq!(server.stop(), 128 + libc::SIGTERM);
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "{:?}",
        start.elapsed()
    );
    drop(idle);
    assert!(s.no_session_left());
}

#[test]
fn server_and_workspace_options_must_agree() {
    let s = Setup::with_config("");
    let server = Server::start(&s);
    let other = s.root.join("home/other");
    fs::create_dir(&other).unwrap();
    let out = output(
        s.run_probe_command(&[
            "--server",
            &server.id,
            "--workspace",
            other.to_str().unwrap(),
        ]),
        b"[]",
    );
    assert_eq!(code(&out), 125, "{out:?}");
    assert!(
        stderr(&out).contains(&format!("serves {:?}, not {:?}", s.ws(), other)),
        "{out:?}"
    );
}

#[test]
fn a_server_that_does_not_answer_is_skipped_with_a_warning() {
    // A live-looking session for the workspace, whose lock this test holds,
    // with no socket to connect to.
    let s = Setup::with_config("");
    let base = s.runtime().join("stopit");
    fs::create_dir_all(&base).unwrap();
    fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
    let id = "0123456789abcdef0123456789abcdef";
    let dir = base.join(id);
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    let lock = File::create(dir.join("lock")).unwrap();
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive).unwrap();
    let record = serde_json::json!({
        "version": 1,
        "workspace": s.ws().as_os_str().as_bytes(),
        "pid": 1,
    });
    fs::write(dir.join("server.json"), record.to_string()).unwrap();
    fs::set_permissions(dir.join("server.json"), fs::Permissions::from_mode(0o600)).unwrap();
    let ops = [Op::Cwd];
    let out = output(s.run_probe_command(&[]), &serde_json::to_vec(&ops).unwrap());
    assert_eq!(code(&out), 0, "{out:?}");
    assert_eq!(
        stderr(&out),
        format!(
            "stopit: warning: the stopit server {id} for this workspace does not answer; \
             running without it\n"
        )
    );
    // Named, it is an error instead.
    let out = output(s.run_probe_command(&["--server", id]), b"[]");
    assert_eq!(code(&out), 125, "{out:?}");
    assert!(
        stderr(&out).contains("cannot reach the stopit server"),
        "{out:?}"
    );
}

/// A sandbox that writes "hi" to the clipboard with OSC 52, then `done`.
const CLIPBOARD_SCRIPT: &str = "printf 'A\\033]52;c;aGk=\\007B'; echo done";

/// A sandbox that writes "hi" to the clipboard twice, then `done`.
const TWO_WRITES_SCRIPT: &str = "printf 'A\\033]52;c;aGk=\\007B\\033]52;c;aGk=\\007C'; echo done";

#[test]
fn clipboard_writes_are_asked_about_on_the_server_terminal() {
    let Some(config) = shell_config() else {
        return;
    };
    let Some((server_master, server_slave)) = open_pty() else {
        return;
    };
    // A finite timeout, so a lost key fails the test rather than hangs it.
    let s = Setup::with_config(&format!(
        "{config}[terminal]\nclipboard_write = \"ask\"\n[approval]\ntimeout = \"20s\"\n"
    ));
    let server = Server::start_on_terminal(&s, &server_master, server_slave);
    // Runs `script` on a terminal of its own. With `key`, answers the
    // prompt on the server's terminal, sending the key again every 200 ms
    // until `verdict` shows. Returns what the run's terminal showed and the
    // server's log since the last call.
    let run = |script: &str, answer: Option<(&[u8], &str)>| {
        let (master, slave) = open_pty().unwrap();
        let command = s.stopit(&["run", "--quiet", "/bin/sh", "-c", script]);
        let mut t = OnTerminal::spawn(command, master, slave);
        if let Some((key, verdict)) = answer {
            server.wait_for_log("[n] deny: ");
            let deadline = Instant::now() + BWRAP_DEADLINE;
            while !server.log().contains(verdict) {
                assert!(Instant::now() < deadline, "{}", server.log());
                (&server_master).write_all(key).unwrap();
                thread::sleep(Duration::from_millis(200));
            }
        }
        let out = t.finish();
        assert_eq!(code(&out), 0, "{out:?}");
        t.wait_for(b"done", 0);
        let log = std::mem::take(&mut *server.log.lock().unwrap());
        (String::from_utf8_lossy(&t.seen()).into_owned(), log)
    };
    let write = "\x1b]52;c;aGk=\x07";

    // Allowed once: the write reaches the terminal. The prompt says which
    // run asks and shows what it writes.
    let (seen, log) = run(CLIPBOARD_SCRIPT, Some((b"y", "allowed once")));
    assert!(seen.starts_with(&format!("A{write}B")), "{seen:?}");
    assert!(
        log.contains("(profile \"main\", /bin/sh -c 'printf "),
        "{log}"
    );
    assert!(
        log.contains("write 2 bytes with 0 newlines to the clipboard (c)"),
        "{log}"
    );
    assert!(log.contains("content: hi"), "{log}");

    // Writes the run's last output holds are asked about even after the
    // sandbox has ended: here the second prompt comes after it ends.
    let (master, slave) = open_pty().unwrap();
    let command = s.stopit(&["run", "--quiet", "/bin/sh", "-c", TWO_WRITES_SCRIPT]);
    let mut t = OnTerminal::spawn(command, master, slave);
    for answered in 1..=2 {
        wait_until(|| (server.log().matches("asks to").count() >= answered).then_some(()));
        if answered == 1 {
            thread::sleep(Duration::from_secs(1));
        }
        let deadline = Instant::now() + BWRAP_DEADLINE;
        while server.log().matches("allowed once").count() < answered {
            assert!(Instant::now() < deadline, "{}", server.log());
            (&server_master).write_all(b"y").unwrap();
            thread::sleep(Duration::from_millis(200));
        }
    }
    let out = t.finish();
    assert_eq!(code(&out), 0, "{out:?}");
    t.wait_for(b"done", 0);
    let seen = String::from_utf8_lossy(&t.seen()).into_owned();
    assert!(seen.starts_with(&format!("A{write}B{write}C")), "{seen:?}");
    server.log.lock().unwrap().clear();

    // Denied: neither write passes, and the second is denied without a
    // prompt, as the denial quiets requests for a while. The run says so.
    let denied_at = Instant::now();
    let (seen, log) = run(TWO_WRITES_SCRIPT, Some((b"n", "denied")));
    assert!(seen.starts_with("ABC"), "{seen:?}");
    assert!(seen.contains("2 clipboard writes blocked"), "{seen:?}");
    assert_eq!(log.matches("asks to").count(), 1, "{log}");

    // Past the quiet period, allowed for the session: both writes pass with
    // one prompt, and a later run's write passes with none.
    thread::sleep(Duration::from_secs(6).saturating_sub(denied_at.elapsed()));
    let (seen, log) = run(TWO_WRITES_SCRIPT, Some((b"s", "allowed for this session")));
    assert!(seen.starts_with(&format!("A{write}B{write}C")), "{seen:?}");
    assert_eq!(log.matches("asks to").count(), 1, "{log}");
    let (seen, log) = run(CLIPBOARD_SCRIPT, None);
    assert!(seen.starts_with(&format!("A{write}B")), "{seen:?}");
    assert!(!log.contains("asks to"), "{log}");
}

#[test]
fn a_server_without_its_terminal_in_the_foreground_denies() {
    let Some(config) = shell_config() else {
        return;
    };
    let s = Setup::with_config(&format!("{config}[terminal]\nclipboard_write = \"ask\"\n"));
    // Three ways a server cannot ask. Each denies at once, and the server
    // says why. The default timeout is off, so a prompt would hang.
    let pidfile = s.root.join("server.pid");
    for case in ["background", "not controlling", "no terminal"] {
        // A terminal for each server, as each one's log reader reads it.
        let Some((server_master, server_slave)) = open_pty() else {
            return;
        };
        let stopit = s.stopit(&["server"]);
        let mut command = match case {
            // Moved to the background by a shell with job control: its
            // controlling terminal has another process group in front.
            "background" => {
                let mut sh = Command::new("/bin/sh");
                sh.args(["-c", "set -m; \"$0\" server & echo $! > \"$1\"; wait $!"])
                    .arg(stopit.get_program())
                    .arg(&pidfile)
                    .current_dir(s.ws())
                    .env_clear();
                for (k, v) in stopit.get_envs() {
                    if let Some(v) = v {
                        sh.env(k, v);
                    }
                }
                sh.stdin(server_slave.try_clone().unwrap());
                with_controlling_terminal(&mut sh, &server_slave);
                sh
            }
            // On the terminal, which is not its controlling terminal.
            "not controlling" => {
                let mut c = stopit;
                c.stdin(server_slave.try_clone().unwrap());
                without_controlling_terminal(&mut c);
                c
            }
            _ => {
                let mut c = stopit;
                c.stdin(Stdio::null());
                without_controlling_terminal(&mut c);
                c
            }
        };
        command
            .stdout(Stdio::null())
            .stderr(server_slave.try_clone().unwrap());
        let child = command.spawn().unwrap();
        drop(command);
        let mut server = Server::collect(child, server_master.try_clone().unwrap());
        let (master, slave) = open_pty().unwrap();
        let command = s.stopit(&["run", "--quiet", "/bin/sh", "-c", TWO_WRITES_SCRIPT]);
        let mut t = OnTerminal::spawn(command, master, slave);
        let out = t.finish();
        assert_eq!(code(&out), 0, "{case}: {out:?}");
        let at = t.wait_for(b"done", 0);
        t.wait_for(b"2 clipboard writes blocked", at);
        assert!(t.seen().starts_with(b"ABC"), "{case}");
        let log = server.log();
        assert!(!log.contains("asks to"), "{case}: {log}");
        let why = match case {
            "no terminal" => "the server's stdin is not a terminal",
            _ => "the server is not in the foreground of its controlling terminal",
        };
        assert_eq!(log.matches(why).count(), 1, "{case}: {log}");
        if case == "background" {
            let pid: i32 = fs::read_to_string(&pidfile)
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            kill(pid, libc::SIGTERM);
            let sh = server.child.take().unwrap();
            assert_eq!(code(&finish(sh)), 128 + libc::SIGTERM, "{case}");
        } else {
            assert_eq!(server.stop(), 128 + libc::SIGTERM, "{case}");
        }
    }
}

#[test]
fn a_standalone_run_blocks_clipboard_asks_and_says_so() {
    let Some(config) = shell_config() else {
        return;
    };
    let Some((master, slave)) = open_pty() else {
        return;
    };
    let s = Setup::with_config(&format!("{config}[terminal]\nclipboard_write = \"ask\"\n"));
    let command = s.stopit(&["run", "--quiet", "/bin/sh", "-c", CLIPBOARD_SCRIPT]);
    let mut t = OnTerminal::spawn(command, master, slave);
    let out = t.finish();
    assert_eq!(code(&out), 0, "{out:?}");
    let at = t.wait_for(b"done", 0);
    t.wait_for(b"1 clipboard write blocked", at);
    let seen = String::from_utf8_lossy(&t.seen()).into_owned();
    assert!(seen.starts_with("ABdone"), "{seen:?}");
    assert!(!seen.contains("]52;"), "{seen:?}");
}

// --- network = "full" through pasta ---

/// The host's `pasta`, or `None` if `PATH` has none, and the test is
/// skipped. With `STOPIT_REQUIRE_PASTA=1` the test fails instead.
fn host_pasta() -> Option<PathBuf> {
    let found = std::env::var_os("PATH").and_then(|p| stopit::net::find_pasta_in(&p));
    if found.is_none() {
        assert!(
            !pasta_required(),
            "no pasta in PATH, and STOPIT_REQUIRE_PASTA=1"
        );
        eprintln!("skipping: no pasta in PATH");
    }
    found
}

/// Whether the sandbox of [`shell_config`], which sees `/usr/bin` and
/// `/bin` in its `PATH`, has `name`.
fn sandbox_has(name: &str) -> bool {
    ["/usr/bin", "/bin"]
        .iter()
        .any(|dir| Path::new(dir).join(name).exists())
}

/// Whether `STOPIT_REQUIRE_PASTA=1` asks for the pasta tests to run.
fn pasta_required() -> bool {
    std::env::var_os("STOPIT_REQUIRE_PASTA").is_some_and(|v| v == "1")
}

/// [`shell_config`] with `network = "full"`, if the host has a shell,
/// bash and pasta.
fn full_network_config() -> Option<String> {
    let config = shell_config()?;
    if !sandbox_has("bash") || !sandbox_has("timeout") {
        assert!(
            !pasta_required(),
            "no bash or timeout, and STOPIT_REQUIRE_PASTA=1"
        );
        eprintln!("skipping: no bash or timeout in /usr/bin or /bin on the host");
        return None;
    }
    host_pasta()?;
    Some(format!("{config}network.mode = \"full\"\n"))
}

/// The host's default IPv4 gateway, from `/proc/net/route`.
fn default_gateway() -> Option<std::net::Ipv4Addr> {
    let routes = fs::read_to_string("/proc/net/route").ok()?;
    routes.lines().skip(1).find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        (fields.get(1) == Some(&"00000000"))
            .then(|| u32::from_str_radix(fields.get(2)?, 16).ok())
            .flatten()
            .map(|gw| std::net::Ipv4Addr::from(gw.swap_bytes()))
    })
}

/// A bash line that prints `<label> reached` or `<label> refused` for a TCP
/// connection to `host` and `port`, giving up after two seconds.
fn try_connect(label: &str, host: &str, port: u16) -> String {
    format!(
        "if timeout 2 bash -c 'exec 3<>/dev/tcp/{host}/{port}' 2>/dev/null; \
         then echo {label} reached; else echo {label} refused; fi; "
    )
}

#[test]
fn full_network_reaches_out_but_not_the_host_loopback() {
    let Some(config) = full_network_config() else {
        return;
    };
    let s = Setup::with_config(&config);
    // Services on the host's loopback, which the sandbox must not reach,
    // directly or through the gateway's address.
    let v4 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let v4_port = v4.local_addr().unwrap().port();
    let v6 = std::net::TcpListener::bind("[::1]:0").ok();
    let mut script = try_connect("v4", "127.0.0.1", v4_port);
    if let Some(v6) = &v6 {
        script += &try_connect("v6", "::1", v6.local_addr().unwrap().port());
    }
    let gateway = default_gateway();
    if let Some(gw) = gateway {
        script += &try_connect("gateway", &gw.to_string(), v4_port);
    }
    // UDP to the host's loopback goes nowhere either.
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    udp.set_nonblocking(true).unwrap();
    script += &format!(
        "echo hi > /dev/udp/127.0.0.1/{} 2>/dev/null; ",
        udp.local_addr().unwrap().port()
    );
    // Nor does a host abstract socket, the namespace's own.
    let abstract_name = format!("stopit-test-{}", std::process::id());
    let abstract_listener = std::os::unix::net::UnixListener::bind_addr(
        &<std::os::unix::net::SocketAddr as std::os::linux::net::SocketAddrExt>::from_abstract_name(
            abstract_name.as_bytes(),
        ).unwrap(),
    )
    .unwrap();
    abstract_listener.set_nonblocking(true).unwrap();
    if sandbox_has("python3") {
        // The namespace, not Landlock, keeps it out: no such socket here.
        script += &format!(
            "python3 -c 'import socket; s = socket.socket(socket.AF_UNIX)\n\
             try:\n s.connect(\"\\0{abstract_name}\"); print(\"abstract reached\")\n\
             except ConnectionRefusedError: print(\"abstract refused\")\n\
             except OSError as e: print(\"abstract error\", e.errno)'; "
        );
    }
    // The sandbox has no capability over its network.
    let ip = ["/usr/bin/ip", "/bin/ip"]
        .into_iter()
        .find(|p| Path::new(p).exists());
    if let Some(ip) = ip {
        script += &format!(
            "if {ip} link set lo down 2>/dev/null; then echo lo changed; \
             else echo lo kept; fi; "
        );
    }
    script += "cat /etc/resolv.conf; tail -n +3 /proc/net/dev | cut -d: -f1";
    let out = output(s.stopit(&["run", "--quiet", "bash", "-c", &script]), b"");
    assert_eq!(code(&out), 0, "{out:?}");
    let shown = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(shown.contains("v4 refused"), "{shown}");
    if v6.is_some() {
        assert!(shown.contains("v6 refused"), "{shown}");
    }
    if gateway.is_some() {
        assert!(shown.contains("gateway refused"), "{shown}");
    }
    // Nothing reached the listeners either.
    v4.set_nonblocking(true).unwrap();
    assert!(v4.accept().is_err());
    assert!(udp.recv(&mut [0u8; 16]).is_err());
    assert!(abstract_listener.accept().is_err());
    if sandbox_has("python3") {
        assert!(shown.contains("abstract refused"), "{shown}");
    }
    if ip.is_some() {
        assert!(shown.contains("lo kept"), "{shown}");
    }
    // The sandbox's resolver is pasta's forwarder, and it has an interface
    // besides `lo`.
    assert!(shown.contains("nameserver 169.254.1.1\n"), "{shown}");
    let interfaces: Vec<&str> = shown
        .lines()
        .skip_while(|l| !l.starts_with("nameserver"))
        .skip(1)
        .map(str::trim)
        .collect();
    assert!(interfaces.contains(&"lo"), "{shown}");
    assert!(interfaces.len() >= 2, "{shown}");
    assert!(s.no_session_left());
}

#[test]
fn full_network_is_in_the_summary() {
    let Some(config) = full_network_config() else {
        return;
    };
    let s = Setup::with_config(&config);
    let out = output(s.stopit(&["run", "/bin/sh", "-c", "true"]), b"");
    assert_eq!(code(&out), 0, "{out:?}");
    assert!(
        stderr(&out).contains("stopit:   network  full\n"),
        "{out:?}"
    );
}

#[test]
fn a_shared_network_namespace_keeps_the_hosts_resolver() {
    let Some(config) = shell_config() else {
        return;
    };
    let Ok(host) = fs::read_to_string("/etc/resolv.conf") else {
        return;
    };
    // No pasta needed: the sandbox is in the host's network namespace.
    let s = Setup::with_config(&format!(
        "{config}network.mode = \"full\"\nsandbox.share = [\"net\"]\n\
         [[provider]]\ntype = \"config\"\nname = \"dns\"\n[provider.sandbox]\n\
         fs.ro = [\"/etc/resolv.conf\"]\n"
    ));
    let out = output(
        s.stopit(&["run", "--quiet", "/bin/sh", "-c", "cat /etc/resolv.conf"]),
        b"",
    );
    assert_eq!(code(&out), 0, "{out:?}");
    assert_eq!(String::from_utf8_lossy(&out.stdout), host);
}

#[test]
fn full_network_resolves_and_connects_where_the_host_does() {
    let Some(config) = full_network_config() else {
        return;
    };
    // Only where the host itself reaches the outside.
    let host = "www.google.com";
    let reachable = std::net::ToSocketAddrs::to_socket_addrs(&(host, 443))
        .ok()
        .and_then(|mut addrs| addrs.next())
        .is_some_and(|addr| {
            std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(3)).is_ok()
        });
    if !reachable {
        eprintln!("skipping: the host does not reach {host}");
        return;
    }
    let s = Setup::with_config(&config);
    let script = try_connect("out", host, 443);
    let out = output(s.stopit(&["run", "--quiet", "bash", "-c", &script]), b"");
    assert_eq!(code(&out), 0, "{out:?}");
    assert_eq!(String::from_utf8_lossy(&out.stdout), "out reached\n");
}

#[test]
fn full_network_without_pasta_fails_before_the_sandbox_starts() {
    let Some(config) = shell_config() else {
        return;
    };
    let Ok(bwrap) = which_bwrap() else {
        return;
    };
    let s = Setup::with_config(&format!("{config}network.mode = \"full\"\n"));
    // A PATH with bwrap and no pasta.
    let bin = s.root.join("only-bwrap");
    fs::create_dir(&bin).unwrap();
    symlink(&bwrap, bin.join("bwrap")).unwrap();
    let mut command = s.stopit(&["run", "--quiet", "/bin/sh", "-c", "echo ran"]);
    command.env("PATH", &bin);
    let out = output(command, b"");
    assert_eq!(code(&out), 125, "{out:?}");
    assert!(out.stdout.is_empty(), "{out:?}");
    assert!(
        stderr(&out).contains("network = \"full\" needs pasta"),
        "{out:?}"
    );
    assert!(s.no_session_left());
}

/// The `bwrap` in `PATH`.
fn which_bwrap() -> Result<PathBuf, ()> {
    std::env::var_os("PATH")
        .and_then(|path| {
            std::env::split_paths(&path)
                .map(|dir| dir.join("bwrap"))
                .find(|p| p.is_file())
        })
        .ok_or(())
}

#[test]
fn pasta_failing_fails_the_run_and_pasta_ends_with_the_sandbox() {
    let Some(config) = full_network_config() else {
        return;
    };
    let pasta = host_pasta().unwrap();
    let s = Setup::with_config(&config);
    // A pasta that records the pid it is given, then runs the real one, or
    // fails when told to.
    let bin = s.root.join("pasta-bin");
    fs::create_dir(&bin).unwrap();
    let record = s.root.join("pasta-pid");
    let fail = s.root.join("pasta-fail");
    fs::write(
        bin.join("pasta"),
        format!(
            "#!/bin/sh\nfor last; do :; done\necho \"$last\" > {record:?}\n\
             if [ -e {fail:?} ]; then echo 'cannot join' >&2; exit 1; fi\n\
             exec {pasta:?} \"$@\"\n"
        ),
    )
    .unwrap();
    fs::set_permissions(bin.join("pasta"), fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let run = |script: &str| {
        let mut command = s.stopit(&["run", "--quiet", "/bin/sh", "-c", script]);
        command.env("PATH", &path);
        output(command, b"")
    };

    // The real pasta is gone soon after the sandbox.
    let out = run("echo ran");
    assert_eq!(code(&out), 0, "{out:?}");
    assert_eq!(String::from_utf8_lossy(&out.stdout), "ran\n");
    let pid = fs::read_to_string(&record).unwrap().trim().to_owned();
    wait_until(|| {
        let left = fs::read_dir("/proc").unwrap().flatten().any(|entry| {
            let Ok(cmdline) = fs::read(entry.path().join("cmdline")) else {
                return false;
            };
            let args: Vec<&[u8]> = cmdline
                .split(|&b| b == 0)
                .filter(|a| !a.is_empty())
                .collect();
            args.first()
                .is_some_and(|a| a.ends_with(b"pasta") || a.ends_with(b"passt"))
                && args.last() == Some(&pid.as_bytes())
        });
        (!left).then_some(())
    });

    // A failing pasta fails the run before the command runs.
    fs::write(&fail, b"").unwrap();
    let out = run("echo ran");
    assert_eq!(code(&out), 125, "{out:?}");
    assert!(out.stdout.is_empty(), "{out:?}");
    let err = stderr(&out);
    assert!(
        err.contains("pasta could not set up the sandbox's network"),
        "{err}"
    );
    assert!(err.contains("cannot join"), "{err}");
    assert!(s.no_session_left());
}

#[test]
fn an_attached_run_gets_the_full_network_too() {
    let Some(config) = full_network_config() else {
        return;
    };
    let s = Setup::with_config(&config);
    let mut server = Server::start(&s);
    let v4 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let script = format!(
        "{}cat /etc/resolv.conf",
        try_connect("v4", "127.0.0.1", v4.local_addr().unwrap().port())
    );
    let out = output(s.stopit(&["run", "--quiet", "bash", "-c", &script]), b"");
    assert_eq!(code(&out), 0, "{out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "v4 refused\nnameserver 169.254.1.1\n"
    );
    assert!(server.log().contains("run 1 started"), "{}", server.log());
    assert_eq!(server.stop(), 128 + libc::SIGTERM);
}

// --- network = "proxy" ---

/// [`shell_config`] in proxy mode allowing `domains`, if the host has a
/// shell and bash.
fn proxy_config(domains: &[&str]) -> Option<String> {
    let config = shell_config()?;
    if !sandbox_has("bash") {
        eprintln!("skipping: no bash in /usr/bin or /bin on the host");
        return None;
    }
    let list: Vec<String> = domains.iter().map(|d| format!("{d:?}")).collect();
    Some(format!(
        "{config}network = {{ mode = \"proxy\", allow_domains = [{}] }}\n",
        list.join(", ")
    ))
}

/// A bash line that sends `CONNECT host:443` to the bridge at `addr` and
/// prints the first line of the answer, prefixed with `label`.
fn connect_through(label: &str, addr: &str, host: &str) -> String {
    format!(
        "exec 3<>/dev/tcp/{addr}/1080 && printf 'CONNECT {host}:443 HTTP/1.1\\r\\n\\r\\n' >&3 \
         && read -r line <&3 && echo \"{label} ${{line%$'\\r'}}\"; exec 3>&-; "
    )
}

#[test]
fn proxy_mode_tunnels_through_the_bridge_and_reports_refusals() {
    let Some(config) = proxy_config(&["allowed.test"]) else {
        return;
    };
    let s = Setup::with_config(&config);
    let mut script = String::from("echo \"proxy $HTTPS_PROXY $ALL_PROXY\"; ");
    script += &connect_through("other", "127.0.0.1", "other.test");
    // Allowed, so the proxy tries to resolve it, which fails on the host.
    script += &connect_through("allowed", "127.0.0.1", "allowed.test");
    // A `kill 0` from the target does not reach the bridge.
    script += "trap '' TERM; kill -TERM 0; trap - TERM; ";
    script += &connect_through("after-kill", "127.0.0.1", "other.test");
    if Path::new("/proc/net/if_inet6").exists() {
        script += &connect_through("v6", "::1", "other.test");
    }
    // The sandbox has no other way out, and the bridge is no child of the
    // target's.
    script += "if timeout 2 bash -c 'exec 3<>/dev/tcp/192.0.2.1/443' 2>/dev/null; \
               then echo direct reached; else echo direct refused; fi; \
               read -r kids < /proc/$$/task/$$/children; echo \"children [$kids]\"";
    let out = output(s.stopit(&["run", "--quiet", "bash", "-c", &script]), b"");
    assert_eq!(code(&out), 0, "{out:?}");
    let shown = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        shown.contains("proxy http://127.0.0.1:1080 socks5h://127.0.0.1:1080\n"),
        "{shown}"
    );
    assert!(shown.contains("other HTTP/1.1 403 Forbidden\n"), "{shown}");
    assert!(
        shown.contains("allowed HTTP/1.1 502 Bad Gateway\nafter-kill HTTP/1.1 403 Forbidden\n"),
        "{shown}"
    );
    if Path::new("/proc/net/if_inet6").exists() {
        assert!(shown.contains("v6 HTTP/1.1 403 Forbidden\n"), "{shown}");
    }
    assert!(shown.contains("direct refused\n"), "{shown}");
    assert!(shown.contains("children []"), "{shown}");
    // Two refusals of one host, said once after the run.
    let err = stderr(&out);
    assert!(
        err.contains("the network proxy refused 3 connections, to other.test;"),
        "{err}"
    );
    assert!(s.no_session_left());
}

#[test]
fn proxy_mode_reaches_allowed_sites_where_the_host_does() {
    let host = "www.google.com";
    let Some(config) = proxy_config(&[host]) else {
        return;
    };
    if !sandbox_has("curl") {
        return;
    }
    let reachable = std::net::ToSocketAddrs::to_socket_addrs(&(host, 443))
        .ok()
        .and_then(|mut addrs| addrs.next())
        .is_some_and(|addr| {
            std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(3)).is_ok()
        });
    if !reachable {
        eprintln!("skipping: the host does not reach {host}");
        return;
    }
    let certs: Vec<String> = ["/etc/ssl", "/etc/ca-certificates", "/etc/pki"]
        .into_iter()
        .filter(|d| Path::new(d).exists())
        .map(|d| format!("{d:?}"))
        .collect();
    let s = Setup::with_config(&format!(
        "{config}[[provider]]\ntype = \"config\"\nname = \"certs\"\n[provider.sandbox]\n\
         fs.ro = [{}]\n",
        certs.join(", ")
    ));
    let script = format!(
        "curl -sS -o /dev/null -w 'https %{{http_code}}\\n' --max-time 20 https://{host}/; \
         curl -sS -o /dev/null -w 'socks %{{http_code}}\\n' --max-time 20 \
         --proxy socks5h://127.0.0.1:1080 https://{host}/"
    );
    let out = output(s.stopit(&["run", "--quiet", "bash", "-c", &script]), b"");
    assert_eq!(code(&out), 0, "{out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "https 200\nsocks 200\n",
        "{out:?}"
    );
}

#[test]
fn an_attached_run_gets_the_proxy_and_the_server_logs_refusals() {
    let Some(config) = proxy_config(&["allowed.test"]) else {
        return;
    };
    let s = Setup::with_config(&config);
    let mut server = Server::start(&s);
    let script = connect_through("other", "127.0.0.1", "other.test");
    let out = output(s.stopit(&["run", "--quiet", "bash", "-c", &script]), b"");
    assert_eq!(code(&out), 0, "{out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "other HTTP/1.1 403 Forbidden\n"
    );
    server.wait_for_log("run 1: the network proxy refused 1 connection, to other.test");
    assert_eq!(server.stop(), 128 + libc::SIGTERM);
    assert!(s.no_session_left());
}

// --- Shims and the broker ---

/// [`shell_config`] with `main` setting `WHICH=main` and having a shim
/// `cat` of `cat` in `main` itself, and a `harness` profile setting
/// `WHICH=harness` with three shims of `sh`: `sh-main` allowed in `main`,
/// `nope` denied, and `asking` asked about for `main`.
fn harness_config() -> Option<String> {
    let config = shell_config()?;
    Some(format!(
        "{config}[[provider]]\ntype = \"config\"\nname = \"which\"\n\
         [provider.sandbox]\nenv.set = {{ WHICH = \"main\" }}\n\
         shims.cat = {{ binary = \"cat\", default = {{ decision = \"allow\", profile = \"main\" }} }}\n\
         [profiles.harness]\n\
         [[provider]]\ntype = \"config\"\nname = \"harness\"\nprofile = \"harness\"\n\
         [provider.sandbox]\nenv.set = {{ WHICH = \"harness\" }}\n\
         shims.sh-main = {{ binary = \"sh\", default = {{ decision = \"allow\", profile = \"main\" }} }}\n\
         shims.nope = {{ binary = \"sh\", default = {{ decision = \"deny\" }} }}\n\
         shims.asking = {{ binary = \"sh\", default = {{ decision = \"ask\", profile = \"main\" }} }}\n"
    ))
}

#[test]
fn a_shim_runs_its_command_in_the_profile_its_rules_name() {
    let Some(config) = harness_config() else {
        return;
    };
    let s = Setup::with_config(&config);
    fs::create_dir(s.ws().join("sub")).unwrap();
    // `cat` in `main` is a shim running `cat` in `main`, which must run
    // the real `cat`, not the shim again.
    let script = "echo \"harness [$WHICH] $(command -v sh-main)\"; \
                  echo $(ls /run/stopit/bin); \
                  cd sub && sh-main -c 'echo \"tool [$WHICH] $(pwd)\"; \
                  command -v sh-main || echo \"no shims\"; exit 7'; echo \"rc=$?\"; \
                  echo piped | sh-main -c 'cat'";
    let out = output(
        s.stopit(&[
            "run",
            "--quiet",
            "--profile",
            "harness",
            "/bin/sh",
            "-c",
            script,
        ]),
        b"",
    );
    assert_eq!(code(&out), 0, "{out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "harness [harness] /run/stopit/bin/sh-main\n\
         asking cat nope sh-main\n\
         tool [main] /workspace/sub\n\
         no shims\n\
         rc=7\n\
         piped\n"
    );
    assert!(s.no_session_left());
}

#[test]
fn shims_calling_shims_stop_four_deep() {
    let Some(config) = harness_config() else {
        return;
    };
    let s = Setup::with_config(&format!(
        "{config}[[provider]]\ntype = \"config\"\nname = \"deep\"\n\
         [provider.sandbox]\n\
         shims.deep = {{ binary = \"sh\", default = {{ decision = \"allow\", profile = \"main\" }} }}\n"
    ));
    // Each level calls the shim again, and says how the call ended.
    fs::write(
        s.ws().join("again.sh"),
        "echo in; deep /workspace/again.sh; echo \"rc=$?\"\n",
    )
    .unwrap();
    let out = output(
        s.stopit(&["run", "--quiet", "/bin/sh", "/workspace/again.sh"]),
        b"",
    );
    assert_eq!(code(&out), 0, "{out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "in\nin\nin\nin\nin\nrc=126\nrc=0\nrc=0\nrc=0\nrc=0\n"
    );
    assert!(
        stderr(&out).contains("deep: shims call each other more than 4 deep"),
        "{out:?}"
    );
    assert!(s.no_session_left());
}

#[test]
fn a_profile_without_shims_sees_an_empty_bin() {
    let Some(config) = shell_config() else {
        return;
    };
    let s = Setup::with_config(&config);
    let out = output(
        s.stopit(&[
            "run",
            "--quiet",
            "/bin/sh",
            "-c",
            "echo \"[$(ls -A /run/stopit/bin)]\"; ls /run/stopit",
        ]),
        b"",
    );
    assert_eq!(code(&out), 0, "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.starts_with("[]\n"), "{stdout}");
    assert!(!stdout.contains("shim"), "{stdout}");
    assert!(!stdout.contains("broker"), "{stdout}");
}

#[test]
fn a_broker_turns_away_the_65th_waiting_connection() {
    use std::os::unix::net::UnixStream;
    let Some(config) = harness_config() else {
        return;
    };
    let s = Setup::with_config(&config);
    let started = Instant::now();
    let mut child = s
        .stopit(&["run", "--quiet", "/bin/sh", "-c", "sleep 3"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // The run's broker socket, in its session directory.
    let base = s.runtime().join("stopit");
    let deadline = Instant::now() + BWRAP_DEADLINE;
    let socket = loop {
        let found = fs::read_dir(&base).ok().and_then(|sessions| {
            sessions.flatten().find_map(|session| {
                fs::read_dir(session.path()).ok()?.flatten().find_map(|e| {
                    let name = e.file_name().to_string_lossy().into_owned();
                    (name.starts_with("broker-") && name.ends_with(".sock")).then(|| e.path())
                })
            })
        });
        if let Some(found) = found {
            break found;
        }
        assert!(Instant::now() < deadline, "no broker socket");
        thread::sleep(Duration::from_millis(50));
    };
    // Each connection that sends nothing holds a worker in the handshake.
    let mut held = Vec::new();
    for _ in 0..64 {
        held.push(UnixStream::connect(&socket).unwrap());
    }
    let mut extra = UnixStream::connect(&socket).unwrap();
    extra
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut reply = Vec::new();
    extra.read_to_end(&mut reply).unwrap();
    let text = String::from_utf8_lossy(&reply);
    assert!(
        text.contains("the broker already runs 64 commands"),
        "{text}"
    );
    // The run ends when its command does, without waiting out the
    // handshakes of the connections still open.
    assert!(child.wait().unwrap().success());
    assert!(
        started.elapsed() < Duration::from_secs(8),
        "{:?}",
        started.elapsed()
    );
    drop(held);
    assert!(s.no_session_left());
}

#[test]
fn refused_shim_calls_exit_126_and_say_why() {
    let Some(config) = harness_config() else {
        return;
    };
    let s = Setup::with_config(&config);
    let script = "nope -c 'echo ran'; echo \"nope=$?\"; \
                  asking -c 'echo ran'; echo \"asking=$?\"; \
                  cd /tmp && sh-main -c 'echo ran'; echo \"outside=$?\"";
    let out = output(
        s.stopit(&[
            "run",
            "--quiet",
            "--profile",
            "harness",
            "/bin/sh",
            "-c",
            script,
        ]),
        b"",
    );
    assert_eq!(code(&out), 0, "{out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "nope=126\nasking=126\noutside=125\n"
    );
    let err = stderr(&out);
    assert!(
        err.contains("[stopit: nope: the shim's rules deny it]"),
        "{err}"
    );
    assert!(
        err.contains("needs a yes on a stopit server's terminal"),
        "{err}"
    );
    assert!(
        err.contains("shims run only from inside the workspace"),
        "{err}"
    );
}

#[test]
fn an_asking_shim_runs_once_the_server_terminal_says_yes() {
    let Some(config) = harness_config() else {
        return;
    };
    let Some((server_master, server_slave)) = open_pty() else {
        return;
    };
    let s = Setup::with_config(&format!("{config}[approval]\ntimeout = \"20s\"\n"));
    let server = Server::start_on_terminal(&s, &server_master, server_slave);
    let command = s.stopit(&[
        "run",
        "--quiet",
        "--profile",
        "harness",
        "/bin/sh",
        "-c",
        "asking -c 'echo \"ran [$WHICH]\"'; echo \"rc=$?\"",
    ]);
    let child = command_output_async(command);
    server.wait_for_log("[n] deny: ");
    let deadline = Instant::now() + BWRAP_DEADLINE;
    while !server.log().contains("allowed once") {
        assert!(Instant::now() < deadline, "{}", server.log());
        (&server_master).write_all(b"y").unwrap();
        thread::sleep(Duration::from_millis(200));
    }
    let out = child.join().unwrap();
    assert_eq!(code(&out), 0, "{out:?}");
    assert_eq!(String::from_utf8_lossy(&out.stdout), "ran [main]\nrc=0\n");
    let log = server.log();
    assert!(log.contains("run sh -c 'echo \"ran [$WHICH]\"'"), "{log}");
    assert!(
        log.contains("in profile \"main\", from /workspace"),
        "{log}"
    );
    assert!(log.contains("through shim asking, rule default"), "{log}");
}

/// Runs `command` without a terminal in a thread, and returns its output
/// when joined.
fn command_output_async(command: Command) -> thread::JoinHandle<Output> {
    thread::spawn(move || output(command, b""))
}

#[test]
fn a_shims_signals_and_its_end_reach_the_command() {
    let Some(config) = harness_config() else {
        return;
    };
    let s = Setup::with_config(&config);
    // A command in `main` that counts in the session's shared `/tmp`, for
    // as long as it runs.
    let counter = "sh-main -c 'while :; do echo x >> /tmp/$0; sleep 0.05; done'";
    let script = format!(
        "{counter} term & pid=$!; sleep 1; kill -TERM $pid; wait $pid; echo \"term=$?\"; \
         {counter} kill & pid=$!; sleep 1; kill -KILL $pid; wait $pid; \
         sleep 1; a=$(wc -l < /tmp/kill); sleep 1; b=$(wc -l < /tmp/kill); \
         [ \"$a\" = \"$b\" ] && echo stopped; \
         a=$(wc -l < /tmp/term); sleep 1; b=$(wc -l < /tmp/term); \
         [ \"$a\" = \"$b\" ] && echo stopped"
    );
    let out = output(
        s.stopit(&[
            "run",
            "--quiet",
            "--profile",
            "harness",
            "/bin/sh",
            "-c",
            &script,
        ]),
        b"",
    );
    assert_eq!(code(&out), 0, "{out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "term=143\nstopped\nstopped\n",
        "{out:?}"
    );
    assert!(s.no_session_left());
}

// --- The vcs provider ---

/// Runs `git args` on the host in `dir`, with no user configuration.
fn host_git(dir: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@t")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@t")
        .stdout(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?}");
}

#[test]
fn git_runs_through_the_broker_while_main_sees_no_metadata() {
    let Some(config) = shell_config() else {
        return;
    };
    if !sandbox_has("git") {
        eprintln!("skipping: no git in /usr/bin or /bin");
        return;
    }
    let s = Setup::with_config(&config);
    // The host user's identity, which the provider hands to git.
    let home = s.root.join("home");
    fs::create_dir_all(&home).unwrap();
    fs::write(
        home.join(".gitconfig"),
        "[user]\n\tname = Host User\n\temail = host@example.com\n",
    )
    .unwrap();
    host_git(&s.ws(), &["init", "-q", "-b", "main"]);
    fs::write(s.ws().join("a.txt"), "a\n").unwrap();
    // A repository below the workspace, as `main` could make one, which git
    // would find first from `sub`.
    let sub = s.ws().join("sub");
    fs::create_dir(&sub).unwrap();
    host_git(&sub, &["init", "-q", "-b", "main"]);
    host_git(&sub, &["commit", "-q", "--allow-empty", "-m", "forged"]);
    let script = "ls -A .git | wc -l; \
                  git add a.txt && GIT_AUTHOR_NAME=x git -c user.name=x commit -qm one; \
                  echo \"inject=$?\"; \
                  git commit -qm one --author='A <a@a>'; echo \"commit=$?\"; \
                  git log --format=%s; \
                  (cd sub && git log --format=%s); \
                  git commit -q --allow-empty 2>/dev/null; echo \"editor=$?\"; \
                  git commit -q -S --allow-empty -m signed 2>/dev/null; echo \"sign=$?\"; \
                  git rebase main; echo \"rebase=$?\"; \
                  git push origin main; echo \"push=$?\"; \
                  echo 'x' > .git/config; echo \"write=$?\"";
    let out = output(s.stopit(&["run", "--quiet", "/bin/sh", "-c", script]), b"");
    assert_eq!(code(&out), 0, "{out:?}");
    let shown = String::from_utf8_lossy(&out.stdout).into_owned();
    // The mask: an empty `.git`, which cannot be written.
    assert!(shown.starts_with("0\n"), "{shown}");
    assert!(shown.contains("inject=126\n"), "{shown}");
    // From `sub`, git still uses the workspace's repository, and it starts
    // no editor.
    assert!(shown.contains("commit=0\none\none\neditor=1\n"), "{shown}");
    // Nor a signing program, which would read configuration from a home
    // `main` can write.
    assert!(shown.contains("sign=128\n"), "{shown}");
    // Asked about, with no server to ask; denied outright.
    assert!(shown.contains("rebase=126\n"), "{shown}");
    assert!(shown.contains("push=126\n"), "{shown}");
    assert!(!shown.contains("write=0"), "{shown}");
    let err = stderr(&out);
    assert!(
        err.contains("[stopit: git: the flag -c is refused]"),
        "{err}"
    );
    // The commit is on the host, and the host's config is untouched.
    let log = Command::new("git")
        .args(["log", "--format=%s, %an, %cn <%ce>"])
        .current_dir(s.ws())
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&log.stdout),
        "one, A, Host User <host@example.com>\n"
    );
    let config = fs::read_to_string(s.ws().join(".git/config")).unwrap();
    assert!(config.contains("[core]"), "{config}");
    assert!(s.no_session_left());
}

#[test]
fn the_vcs_profiles_have_a_home_main_cannot_write() {
    let Some(config) = shell_config() else {
        return;
    };
    if !sandbox_has("git") {
        eprintln!("skipping: no git in /usr/bin or /bin");
        return;
    }
    // A shim of the test's own into vcs.local, to look around there.
    let s = Setup::with_config(&format!(
        "{config}[[provider]]\ntype = \"config\"\nname = \"look\"\n[provider.sandbox]\n\
         shims.in-vcs = {{ binary = \"sh\", default = {{ decision = \"allow\", profile = \"vcs.local\" }} }}\n"
    ));
    host_git(&s.ws(), &["init", "-q", "-b", "main"]);
    let script = "echo \"main $HOME\"; echo planted > ~/.gitconfig; \
                  in-vcs -c 'echo \"vcs $HOME $(ls -A \"$HOME\" | wc -l)\"; \
                  grep -c \"^user:.*:/home/vcs:\" /etc/passwd'";
    let out = output(s.stopit(&["run", "--quiet", "/bin/sh", "-c", script]), b"");
    assert_eq!(code(&out), 0, "{out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "main /home/user\nvcs /home/vcs 0\n1\n"
    );
}

/// Runs `jj args` on the host in `dir`, with no user configuration.
fn host_jj(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("jj")
        .args(args)
        .current_dir(dir)
        .env("JJ_CONFIG", "/dev/null")
        .env("JJ_USER", "t")
        .env("JJ_EMAIL", "t@t")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(out.status.success(), "jj {args:?}: {out:?}");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn jj_runs_through_the_broker_while_main_sees_no_metadata() {
    let Some(config) = shell_config() else {
        return;
    };
    if !sandbox_has("jj") || !sandbox_has("git") {
        eprintln!("skipping: no jj or git in /usr/bin or /bin");
        return;
    }
    let s = Setup::with_config(&config);
    // Some builds of jj need more of the host than a sandbox has (`/sys`
    // for the CPU count, a group named `nobody`), so jj must run in one
    // first. Outside a repository, `jj root` exits with 1.
    let probe = output(s.stopit(&["run", "--quiet", "jj", "root"]), b"");
    if code(&probe) != 1 {
        eprintln!("skipping: jj does not run in a sandbox: {}", stderr(&probe));
        return;
    }
    let home = s.root.join("home");
    fs::create_dir_all(&home).unwrap();
    fs::write(
        home.join(".gitconfig"),
        "[user]\n\tname = Host User\n\temail = host@example.com\n",
    )
    .unwrap();
    host_jj(&s.ws(), &["git", "init", "--colocate", "--quiet"]);
    fs::write(s.ws().join("a.txt"), "a\n").unwrap();
    let script = "ls -A .jj | wc -l; \
                  jj log -r @ --no-graph -T 'change_id.short() ++ \"\\n\"' >/dev/null; \
                  echo \"log=$?\"; \
                  jj describe -m hello; echo \"describe=$?\"; \
                  jj --config ui.pager=sh log; echo \"config=$?\"; \
                  jj abandon; echo \"abandon=$?\"; \
                  jj git push; echo \"push=$?\"; \
                  jj new -A @; echo \"insert=$?\"";
    let out = output(s.stopit(&["run", "--quiet", "/bin/sh", "-c", script]), b"");
    assert_eq!(code(&out), 0, "{out:?}");
    let shown = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(
        shown,
        "0\nlog=0\ndescribe=0\nconfig=126\nabandon=126\npush=126\ninsert=126\n",
        "{}",
        stderr(&out)
    );
    // The description is on the host, with the host user's identity.
    let log = host_jj(
        &s.ws(),
        &[
            "log",
            "-r",
            "@",
            "--no-graph",
            "-T",
            "description ++ committer.name() ++ \"\\n\"",
        ],
    );
    assert_eq!(log, "hello\nHost User\n");
    assert!(s.no_session_left());
}

// --- Resource limits ---

/// Whether the user's systemd starts transient scopes through `busctl`.
fn user_systemd() -> bool {
    Command::new("busctl")
        .args([
            "--user",
            "call",
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1",
            "org.freedesktop.DBus.Peer",
            "Ping",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// `s` with `[limits]` set to `limits`, and the user's bus in its private
/// `XDG_RUNTIME_DIR`, where busctl looks for it.
fn limits_setup(config: &str, limits: &str) -> Setup {
    let s = Setup::with_config(&format!("{config}[limits]\n{limits}"));
    let runtime = PathBuf::from(std::env::var_os("XDG_RUNTIME_DIR").unwrap());
    symlink(runtime.join("bus"), s.runtime().join("bus")).unwrap();
    s
}

/// The cgroup v2 directory of process `pid`.
fn cgroup_of(pid: u32) -> PathBuf {
    let text = fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap_or_default();
    let path = text
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .unwrap_or("");
    PathBuf::from(format!("/sys/fs/cgroup{path}"))
}

/// Waits until process `pid` is in a stopit scope, and returns its
/// directory.
#[track_caller]
fn wait_for_scope(pid: u32) -> PathBuf {
    let deadline = Instant::now() + BWRAP_DEADLINE;
    loop {
        let cgroup = cgroup_of(pid);
        let name = cgroup.file_name().unwrap_or_default().to_string_lossy();
        if name.starts_with("stopit-") && name.ends_with(".scope") {
            return cgroup;
        }
        assert!(Instant::now() < deadline, "not in a scope: {cgroup:?}");
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn limits_put_the_session_in_a_scope_of_its_own() {
    let Some(config) = shell_config() else {
        return;
    };
    if !user_systemd() {
        eprintln!("skipping: the user's systemd does not answer on its bus");
        return;
    }
    let s = limits_setup(&config, "pids = 24\nmemory = \"512M\"\ncpu = \"50%\"\n");
    // The shell's message for a fork that fails differs (dash: "Cannot
    // fork", bash: "fork: retry"), but both say fork.
    let script =
        "sleep 2; i=0; while [ $i -lt 40 ]; do sleep 3 & i=$((i+1)); done; wait; echo ended";
    let child = s
        .stopit(&["run", "--quiet", "/bin/sh", "-c", script])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // stopit itself moves into the scope, keeping its pid, and the scope
    // has the limits asked.
    let cgroup = wait_for_scope(child.id());
    let read = |file: &str| {
        fs::read_to_string(cgroup.join(file))
            .unwrap()
            .trim()
            .to_owned()
    };
    assert_eq!(read("pids.max"), "24");
    assert_eq!(read("memory.max"), "536870912");
    assert_eq!(read("cpu.max"), "50000 100000");
    assert!(
        read("cgroup.procs")
            .lines()
            .any(|p| p == child.id().to_string()),
        "{}",
        read("cgroup.procs")
    );
    let out = child.wait_with_output().unwrap();
    // Forks beyond the limit fail, and the session still ends.
    assert_eq!(String::from_utf8_lossy(&out.stdout), "ended\n");
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .to_lowercase()
            .contains("fork"),
        "{out:?}"
    );
    assert!(s.no_session_left());
    // The command reaches the sandbox byte for byte.
    let out = output(
        s.stopit(&[
            "run", "--quiet", "printf", "%s|", "${HOME}", "$$", "$HOME", "$",
        ]),
        b"",
    );
    assert_eq!(code(&out), 0, "{out:?}");
    assert_eq!(String::from_utf8_lossy(&out.stdout), "${HOME}|$$|$HOME|$|");
}

#[test]
fn a_server_and_its_runs_share_one_scope() {
    let Some(config) = shell_config() else {
        return;
    };
    if !user_systemd() {
        eprintln!("skipping: the user's systemd does not answer on its bus");
        return;
    }
    let s = limits_setup(&config, "pids = 64\n");
    let mut server = Server::start(&s);
    let cgroup = wait_for_scope(server.pid() as u32);
    assert_eq!(
        fs::read_to_string(cgroup.join("pids.max")).unwrap().trim(),
        "64"
    );
    // An attached run's sandbox starts in the server's scope.
    let child = s
        .stopit(&["run", "--quiet", "/bin/sh", "-c", "sleep 2"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + BWRAP_DEADLINE;
    while fs::read_to_string(cgroup.join("cgroup.procs"))
        .unwrap()
        .lines()
        .count()
        < 2
    {
        assert!(Instant::now() < deadline, "the run is not in the scope");
        thread::sleep(Duration::from_millis(20));
    }
    // The client stays where it was.
    assert_ne!(cgroup_of(child.id()), cgroup);
    assert_eq!(code(&finish(child)), 0);
    assert_eq!(server.stop(), 128 + libc::SIGTERM);
}

/// A directory holding bwrap and a `busctl` script running `body`, for a
/// PATH of its own.
fn fake_busctl(body: &str) -> TempDir {
    let dir = TempDir::new().unwrap();
    let bwrap = std::env::var_os("PATH")
        .and_then(|path| {
            std::env::split_paths(&path)
                .map(|d| d.join("bwrap"))
                .find(|p| p.exists())
        })
        .unwrap();
    symlink(&bwrap, dir.path().join("bwrap")).unwrap();
    let script = dir.path().join("busctl");
    fs::write(&script, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    dir
}

#[test]
fn a_scope_systemd_refuses_or_never_starts_stops_the_session() {
    let Some(config) = shell_config() else {
        return;
    };
    if !Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        eprintln!("skipping: no cgroup v2 hierarchy at /sys/fs/cgroup");
        return;
    }
    let s = Setup::with_config(&format!("{config}[limits]\npids = 24\n"));
    // Refused, with an error that holds a terminal escape.
    let dir = fake_busctl("printf 'boom \\033]52;c;AAAA\\007\\n' >&2; exit 1");
    let mut command = s.stopit(&["run", "--quiet", "/bin/sh", "-c", "echo ran"]);
    command.env("PATH", dir.path());
    let out = output(command, b"");
    assert_eq!(code(&out), 125, "{out:?}");
    assert!(out.stdout.is_empty(), "{out:?}");
    let err = stderr(&out);
    assert!(err.contains("did not start the scope stopit-"), "{err}");
    assert!(err.contains("boom \\u{1b}]52"), "{err}");
    assert!(!err.contains('\u{1b}'), "{err:?}");
    assert!(!s.runtime().join("stopit").exists());
    // Accepted, but stopit never moves.
    let dir = fake_busctl("exit 0");
    let mut command = s.stopit(&["run", "--quiet", "/bin/sh", "-c", "echo ran"]);
    command.env("PATH", dir.path());
    let out = output(command, b"");
    assert_eq!(code(&out), 125, "{out:?}");
    assert!(
        stderr(&out).contains("did not move stopit into the scope"),
        "{out:?}"
    );
    assert!(!s.runtime().join("stopit").exists());
}

#[test]
fn limits_without_busctl_fail_before_the_session() {
    let Some(config) = shell_config() else {
        return;
    };
    let s = Setup::with_config(&format!("{config}[limits]\npids = 24\n"));
    // A PATH with bwrap but no busctl.
    let dir = TempDir::new().unwrap();
    let bwrap = std::env::var_os("PATH")
        .and_then(|path| {
            std::env::split_paths(&path)
                .map(|d| d.join("bwrap"))
                .find(|p| p.exists())
        })
        .unwrap();
    symlink(&bwrap, dir.path().join("bwrap")).unwrap();
    let mut command = s.stopit(&["run", "--quiet", "/bin/sh", "-c", "echo ran"]);
    command.env("PATH", dir.path());
    let out = output(command, b"");
    assert_eq!(code(&out), 125, "{out:?}");
    assert!(out.stdout.is_empty(), "{out:?}");
    assert!(stderr(&out).contains("[limits] needs busctl"), "{out:?}");
    // Before any session directory.
    assert!(!s.runtime().join("stopit").exists());
}
