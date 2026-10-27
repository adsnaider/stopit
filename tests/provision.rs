//! Runs the provisioned stopit binary (DESIGN.md §2.1, §6.2) on the host and
//! inside a bwrap sandbox that sees nothing but the provisioned directory.
//! The sandbox run proves the copied closure is complete.

use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

use stopit::provision::{Provisioned, provision};
use stopit::spec::SANDBOX_RUNTIME_DIR;

/// The stopit binary, provisioned once into a directory shared by the tests
/// (they only read it). It lives under Cargo's per-target scratch directory,
/// since a static is never dropped, and is recreated on every run so at most
/// one is left behind.
fn provisioned() -> &'static (PathBuf, Provisioned) {
    static PROVISIONED: OnceLock<(PathBuf, Provisioned)> = OnceLock::new();
    PROVISIONED.get_or_init(|| {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("provisioned-stopit");
        match fs::remove_dir_all(&dir) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => panic!("cannot remove {dir:?} left by an earlier run: {e}"),
        }
        fs::create_dir(&dir).unwrap();
        let provisioned = provision(Path::new(env!("CARGO_BIN_EXE_stopit")), &dir)
            .unwrap_or_else(|e| panic!("provisioning failed: {e}"));
        (dir, provisioned)
    })
}

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
    let result = Command::new("bwrap")
        .args(["--unshare-all", "--die-with-parent", "--clearenv"])
        .arg("--ro-bind")
        .arg(dir)
        .arg(SANDBOX_RUNTIME_DIR)
        .args(["--proc", "/proc", "--dev", "/dev", "--"])
        .args(argv)
        .output();
    match result {
        Ok(out) => out,
        Err(e) if e.kind() == io::ErrorKind::NotFound => panic!(
            "bwrap (bubblewrap) is not on PATH; this test needs it. \
             Run the tests inside `nix develop`, which provides it."
        ),
        Err(e) => panic!("cannot run bwrap: {e}"),
    }
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
    let (dir, provisioned) = provisioned();
    let mut argv = provisioned.command_prefix(dir);
    argv.push("--version".into());
    assert_version(&run(&argv));
}

#[test]
fn provisioned_binary_runs_in_a_sandbox_that_sees_only_it() {
    let (dir, provisioned) = provisioned();
    let mut argv = provisioned.command_prefix(Path::new(SANDBOX_RUNTIME_DIR));
    argv.push("--version".into());
    assert_version(&run_in_bwrap(dir, &argv));
}

#[test]
fn unprovisioned_binary_does_not_run_in_that_sandbox() {
    // The control for the test above: the copy at /run/stopit/stopit, run
    // directly, needs an interpreter and libraries the sandbox lacks. A
    // static build runs anyway, so there is nothing to check.
    let (dir, provisioned) = provisioned();
    if provisioned.loader().is_none() {
        return;
    }
    let exe = Path::new(SANDBOX_RUNTIME_DIR).join("stopit");
    let out = run_in_bwrap(dir, &[exe.into_os_string(), "--version".into()]);
    assert!(!out.status.success(), "{out:?}");
    assert!(out.stdout.is_empty(), "{out:?}");
}

#[test]
fn provisioned_directory_holds_only_the_closure() {
    let (dir, provisioned) = provisioned();
    let mut top: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    top.sort();
    assert_eq!(top, ["lib", "stopit"]);
    if let Some(loader) = provisioned.loader() {
        assert!(loader.is_file());
        assert!(fs::read_dir(provisioned.lib_dir()).unwrap().count() >= 2);
    }
}
