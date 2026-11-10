use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::process::{Command, Output};

fn stopit() -> Command {
    Command::new(env!("CARGO_BIN_EXE_stopit"))
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn assert_usage_error(out: &Output) {
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(out.stdout.is_empty(), "{out:?}");
    assert!(stderr(out).contains("Usage: stopit"), "{out:?}");
}

fn assert_version(out: &Output) {
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        String::from_utf8(out.stdout.clone()).unwrap().trim_end(),
        format!("stopit {}", env!("CARGO_PKG_VERSION"))
    );
    assert!(out.stderr.is_empty());
}

#[test]
fn version_prints_and_exits_zero() {
    assert_version(&stopit().arg("--version").output().unwrap());
}

#[test]
fn version_ends_parsing() {
    // As in most command lines, `--version` answers at once, whatever
    // follows it.
    assert_version(&stopit().args(["--version", "extra"]).output().unwrap());
}

#[test]
fn help_prints_to_stdout_and_exits_zero() {
    let out = stopit().arg("--help").output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    let help = String::from_utf8(out.stdout).unwrap();
    for word in [
        "run",
        "shell",
        "init",
        "allow",
        "default-config",
        "--version",
    ] {
        assert!(help.contains(word), "{help}");
    }
    // The internal init helper is not advertised.
    assert!(!help.contains("__init"), "{help}");

    let init_help_out = stopit().args(["init", "--help"]).output().unwrap();
    assert_eq!(init_help_out.status.code(), Some(0));
    let init_help = String::from_utf8(init_help_out.stdout).unwrap();
    assert!(
        init_help.contains("[default: the current directory]"),
        "{init_help}"
    );
}

#[test]
fn no_args_prints_usage_and_exits_two() {
    assert_usage_error(&stopit().output().unwrap());
}

#[test]
fn unknown_argument_exits_two() {
    assert_usage_error(&stopit().arg("--bogus").output().unwrap());
    assert_usage_error(&stopit().arg("bogus").output().unwrap());
}

#[test]
fn non_utf8_argument_exits_two() {
    let out = stopit().arg(OsStr::from_bytes(b"\xff")).output().unwrap();
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(out.stdout.is_empty(), "{out:?}");
}

#[test]
fn run_without_a_command_exits_two() {
    assert_usage_error(&stopit().arg("run").output().unwrap());
    assert_usage_error(&stopit().args(["run", "--profile", "p"]).output().unwrap());
}

#[test]
fn a_mistyped_run_option_is_not_run_as_the_command() {
    let out = stopit()
        .args(["run", "--profle", "p", "ls"])
        .output()
        .unwrap();
    assert_usage_error(&out);
    assert!(stderr(&out).contains("--profle"), "{out:?}");
}

#[test]
fn shell_without_shell_fails_clearly() {
    let out = stopit().arg("shell").env_remove("SHELL").output().unwrap();
    assert_eq!(out.status.code(), Some(125), "{out:?}");
    assert!(out.stdout.is_empty(), "{out:?}");
    assert_eq!(
        stderr(&out),
        "stopit: error: SHELL is not set; run a shell explicitly with `stopit run <shell>`\n"
    );
}

#[test]
fn default_config_prints_valid_global_toml() {
    for args in [
        &["default-config"][..],
        &["default-config", "--format", "toml"][..],
    ] {
        let out = stopit().args(args).output().unwrap();
        assert_eq!(out.status.code(), Some(0), "{out:?}");
        assert!(out.stderr.is_empty(), "{out:?}");
        let text = String::from_utf8(out.stdout).unwrap();
        assert_eq!(text, stopit::config::DEFAULT_CONFIG_TOML);
        stopit::config::ConfigLayer::from_global_toml_str(&text).unwrap();
    }
}

#[test]
fn default_config_format_nix_matches_default_config_toml() {
    let out = stopit()
        .args(["default-config", "--format", "nix"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(out.stderr.is_empty(), "{out:?}");
    let nix_text = String::from_utf8(out.stdout).unwrap();
    assert_eq!(nix_text, stopit::config::default_config_nix());

    // When `nix` is installed on the host, evaluate the generated Nix expression
    // and assert structural equality with `builtins.fromTOML DEFAULT_CONFIG_TOML`.
    if Command::new("nix").arg("--version").output().is_ok() {
        let tmp = tempfile::tempdir().unwrap();
        let nix_path = tmp.path().join("default_config.nix");
        let toml_path = tmp.path().join("default_config.toml");
        std::fs::write(&nix_path, &nix_text).unwrap();
        std::fs::write(&toml_path, stopit::config::DEFAULT_CONFIG_TOML).unwrap();
        let expr = format!(
            "(import {}) == builtins.fromTOML (builtins.readFile {})",
            nix_path.display(),
            toml_path.display()
        );
        let eval = Command::new("nix")
            .args([
                "--extra-experimental-features",
                "nix-command",
                "eval",
                "--impure",
                "--expr",
                &expr,
            ])
            .output()
            .unwrap();
        assert_eq!(eval.status.code(), Some(0), "{eval:?}");
        assert_eq!(
            String::from_utf8_lossy(&eval.stdout).trim(),
            "true",
            "nix output disagreed with DEFAULT_CONFIG_TOML:\n{nix_text}"
        );
    }
}
