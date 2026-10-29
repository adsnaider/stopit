//! Builds the shim trampoline (`shim/trampoline.rs`, DESIGN.md §7.1), a
//! static program without `std` that stopit embeds and provisions into
//! every session.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=shim/trampoline.rs");
    let out =
        PathBuf::from(env::var_os("OUT_DIR").expect("cargo sets OUT_DIR")).join("stopit-shim");
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let target = env::var("TARGET").expect("cargo sets TARGET");
    let mut command = Command::new(rustc);
    command
        .args([
            "--edition",
            "2024",
            "--crate-type",
            "bin",
            "--crate-name",
            "stopit_shim",
        ])
        .args([
            "-C",
            "opt-level=s",
            "-C",
            "panic=abort",
            "-C",
            "debuginfo=0",
        ])
        .args(["-C", "strip=symbols", "-C", "relocation-model=static"])
        .args(["-C", "target-feature=+crt-static"])
        .args(["-C", "link-arg=-nostartfiles", "-C", "link-arg=-nostdlib"])
        .args(["-C", "link-arg=-static", "-C", "link-arg=-no-pie"])
        .args(["--target", &target]);
    // The linker cargo uses for the target, if one is set.
    println!("cargo:rerun-if-env-changed=RUSTC_LINKER");
    if let Some(linker) = env::var_os("RUSTC_LINKER") {
        let mut arg = std::ffi::OsString::from("linker=");
        arg.push(linker);
        command.arg("-C").arg(arg);
    }
    command.arg("shim/trampoline.rs").arg("-o").arg(&out);
    let status = command
        .status()
        .unwrap_or_else(|e| panic!("cannot run rustc for the shim trampoline: {e}"));
    assert!(
        status.success(),
        "building the shim trampoline failed: {status}"
    );
}
