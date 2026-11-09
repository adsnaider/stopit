//! The target's environment (DESIGN.md §9) computed from real
//! configurations: the default base, merged with a user provider through
//! the public pipeline, against a representative host environment.

mod common;

use std::ffi::OsString;

use common::SpecFixture;

fn vars(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
    pairs.iter().map(|&(k, v)| (k.into(), v.into())).collect()
}

fn host() -> Vec<(OsString, OsString)> {
    vars(&[
        ("HOME", "/home/adam"),
        ("USER", "adam"),
        ("LOGNAME", "adam"),
        ("PATH", "/run/current-system/sw/bin:/home/adam/.cargo/bin"),
        ("PWD", "/home/adam/Projects/stopit"),
        ("TERM", "xterm-256color"),
        ("COLORTERM", "truecolor"),
        ("LANG", "en_US.UTF-8"),
        ("LC_ALL", "C"),
        ("SSH_AUTH_SOCK", "/run/user/1000/ssh-agent"),
        ("GITHUB_TOKEN", "ghp_secret"),
        ("github_token", "ghp_lower"),
        ("AWS_SECRET_ACCESS_KEY", "aws_secret"),
        ("AWS_PROFILE", "dev"),
        ("CARGO_REGISTRY_TOKEN", "crates_secret"),
        ("NIX_CONFIG", "access-tokens = github.com=ghp_secret"),
        ("RUST_LOG", "debug"),
        ("rust_log", "lowercase"),
        ("CARGO_HOME", "/home/adam/.cargo"),
        ("EDITOR", "nvim"),
    ])
}

#[test]
fn default_base_golden() {
    let f = SpecFixture::new();
    let (spec, _) = f.compile_with_warnings("");
    // The default base passes only `TERM`, `LANG` and `COLORTERM`: the
    // host's `HOME`, `USER` and `PATH` are not passed, and the sandbox gets
    // its own identity. No `RUST_*` or `CARGO_*`: that is a user provider's
    // job.
    assert_eq!(
        spec.target_env(host()),
        vars(&[
            ("COLORTERM", "truecolor"),
            ("HOME", "/home/stopit"),
            ("LANG", "en_US.UTF-8"),
            ("LOGNAME", "stopit"),
            // `stopit-grant`'s directory, which the default base gives.
            ("PATH", "/run/stopit/bin"),
            ("TERM", "xterm-256color"),
            ("USER", "stopit"),
        ])
    );
}

#[test]
fn default_base_merged_with_a_user_provider_golden() {
    let f = SpecFixture::new();
    // The user's `pass` widens the base's, `deny` (the base's, in any case)
    // still wins, `set` overrides, and `path_prepend` builds `PATH`.
    let (spec, _) = f.compile_with_warnings(
        r#"
[[provider]]
type = "config"
name = "user"
profile = "main"
[provider.sandbox]
env.pass = ["RUST_*", "CARGO_*", "NIX_CONFIG", "*_token", "PATH", "HOME", "EDITOR"]
env.set = { EDITOR = "vi", USER = "agent" }
env.path_prepend = ["/run/stopit/bin", "/usr/bin"]
"#,
    );
    // Not passed: `CARGO_REGISTRY_TOKEN` and `NIX_CONFIG` (denied by the
    // base), `github_token` (denied whatever its case), `rust_log` (`pass`
    // is case-sensitive), and the host's `HOME` and `PATH`.
    assert_eq!(
        spec.target_env(host()),
        vars(&[
            ("CARGO_HOME", "/home/adam/.cargo"),
            ("COLORTERM", "truecolor"),
            ("EDITOR", "vi"),
            ("HOME", "/home/stopit"),
            ("LANG", "en_US.UTF-8"),
            ("LOGNAME", "stopit"),
            ("PATH", "/run/stopit/bin:/usr/bin"),
            ("RUST_LOG", "debug"),
            ("TERM", "xterm-256color"),
            ("USER", "agent"),
        ])
    );
}

#[test]
fn system_user_updates_user_logname_and_default_home() {
    let f = SpecFixture::new();
    let (spec, _) = f.compile_with_warnings(
        r#"
[[provider]]
type = "config"
name = "user"
profile = "main"
[provider.sandbox]
system.user = { username = "alice" }
"#,
    );
    assert_eq!(
        spec.target_env(host()),
        vars(&[
            ("COLORTERM", "truecolor"),
            ("HOME", "/home/alice"),
            ("LANG", "en_US.UTF-8"),
            ("LOGNAME", "alice"),
            ("PATH", "/run/stopit/bin"),
            ("TERM", "xterm-256color"),
            ("USER", "alice"),
        ])
    );
}
