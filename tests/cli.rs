use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::process::{Command, Output};

fn stopit() -> Command {
    Command::new(env!("CARGO_BIN_EXE_stopit"))
}

fn assert_usage_error(out: &Output) {
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("usage:"));
}

#[test]
fn version_prints_and_exits_zero() {
    let out = stopit().arg("--version").output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        String::from_utf8(out.stdout).unwrap().trim_end(),
        format!("stopit {}", env!("CARGO_PKG_VERSION"))
    );
    assert!(out.stderr.is_empty());
}

#[test]
fn no_args_prints_usage_and_exits_two() {
    assert_usage_error(&stopit().output().unwrap());
}

#[test]
fn unknown_argument_exits_two() {
    assert_usage_error(&stopit().arg("--bogus").output().unwrap());
}

#[test]
fn version_with_extra_argument_exits_two() {
    assert_usage_error(&stopit().args(["--version", "extra"]).output().unwrap());
}

#[test]
fn non_utf8_argument_exits_two() {
    let out = stopit().arg(OsStr::from_bytes(b"\xff")).output().unwrap();
    assert_usage_error(&out);
}
