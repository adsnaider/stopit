//! Runs the provisioned stopit binary (DESIGN.md §2.1, §6.2) on the host and
//! inside a bwrap sandbox that sees nothing but the provisioned directory.
//! The sandbox run proves the copied closure is complete.

mod common;

use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use stopit::spec::SANDBOX_RUNTIME_DIR;

use common::{BASE_ARGS, bwrap, provisioned_stopit};

fn run(argv: &[OsString]) -> Output {
    Command::new(&argv[0])
        .args(&argv[1..])
        .env_clear()
        .output()
        .unwrap_or_else(|e| panic!("cannot run {:?}: {e}", argv[0]))
}

/// Runs `argv` in a sandbox with an empty root, only the provisioned
/// directory (read-only at `/run/stopit`), `/proc` and `/dev`, and no
/// environment.
fn run_in_bwrap(dir: &Path, argv: &[OsString]) -> Output {
    let mut args: Vec<OsString> = BASE_ARGS.iter().map(OsString::from).collect();
    args.extend([
        "--ro-bind".into(),
        dir.into(),
        SANDBOX_RUNTIME_DIR.into(),
        "--proc".into(),
        "/proc".into(),
        "--dev".into(),
        "/dev".into(),
        "--".into(),
    ]);
    args.extend_from_slice(argv);
    bwrap(&args, None)
}

fn assert_version(out: &Output) {
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim_end(),
        format!("stopit {}", env!("CARGO_PKG_VERSION")),
        "{out:?}"
    );
    assert!(out.stderr.is_empty(), "{out:?}");
}

#[test]
fn provisioned_binary_runs_on_the_host() {
    let stopit = provisioned_stopit();
    let mut argv = stopit.command_prefix(&stopit.dir);
    argv.push("--version".into());
    assert_version(&run(&argv));
}

#[test]
fn provisioned_binary_runs_in_a_sandbox_that_sees_only_it() {
    let stopit = provisioned_stopit();
    let mut argv = stopit.command_prefix(Path::new(SANDBOX_RUNTIME_DIR));
    argv.push("--version".into());
    assert_version(&run_in_bwrap(&stopit.dir, &argv));
}

#[test]
fn unprovisioned_binary_does_not_run_in_that_sandbox() {
    // The control for the test above: the copy at /run/stopit/stopit, run
    // directly, needs an interpreter and libraries the sandbox lacks. A
    // static build runs anyway, so there is nothing to check.
    let stopit = provisioned_stopit();
    if stopit.provisioned.loader().is_none() {
        return;
    }
    let exe = Path::new(SANDBOX_RUNTIME_DIR).join("stopit");
    let out = run_in_bwrap(&stopit.dir, &[exe.into_os_string(), "--version".into()]);
    assert!(!out.status.success(), "{out:?}");
    assert!(out.stdout.is_empty(), "{out:?}");
}

#[test]
fn provisioned_directory_holds_only_the_closure() {
    let stopit = provisioned_stopit();
    let mut top: Vec<_> = fs::read_dir(&stopit.dir)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    top.sort();
    assert_eq!(top, ["lib", "stopit"]);
    if let Some(loader) = stopit.provisioned.loader() {
        assert!(loader.is_file());
        assert!(fs::read_dir(stopit.provisioned.lib_dir()).unwrap().count() >= 2);
    }
}
