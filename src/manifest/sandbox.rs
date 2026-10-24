//! The `sandbox` manifest section: hardening opt-outs (DESIGN.md §6.2, §6.3).
//!
//! Hardening is on by default. A provider may only loosen it in the two ways
//! modelled here: sharing a namespace with the host, and re-enabling a
//! syscall from a short list.

use std::fmt;
use std::str::FromStr;

use serde::Deserialize;

use crate::error::ValueError;
use crate::serde_util::MapOnly;

/// The `sandbox` section.
///
/// Deserializes from a table or object only, never from a sequence. Both
/// lists are merged by union.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(from = "MapOnly<RawSandboxGrants>")]
pub struct SandboxGrants {
    /// Namespaces shared with the host instead of being unshared.
    pub share: Vec<ShareableNamespace>,
    /// Syscalls re-enabled in the seccomp filter.
    pub allow_syscalls: Vec<OptInSyscall>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawSandboxGrants {
    share: Vec<ShareableNamespace>,
    allow_syscalls: Vec<OptInSyscall>,
}

impl From<MapOnly<RawSandboxGrants>> for SandboxGrants {
    fn from(MapOnly(raw): MapOnly<RawSandboxGrants>) -> Self {
        SandboxGrants {
            share: raw.share,
            allow_syscalls: raw.allow_syscalls,
        }
    }
}

/// A namespace that a provider may share with the host.
///
/// The user and mount namespaces are not listed: they are always unshared
/// (bubblewrap requires them, and invariant I2 depends on them).
///
/// Ordered by declaration, so that merged sets iterate deterministically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(try_from = "String")]
pub enum ShareableNamespace {
    /// Network namespace.
    Net,
    /// PID namespace.
    Pid,
    /// IPC namespace.
    Ipc,
    /// UTS (hostname) namespace.
    Uts,
    /// Cgroup namespace.
    Cgroup,
}

impl ShareableNamespace {
    /// The lowercase spelling used in configuration.
    pub fn as_str(self) -> &'static str {
        match self {
            ShareableNamespace::Net => "net",
            ShareableNamespace::Pid => "pid",
            ShareableNamespace::Ipc => "ipc",
            ShareableNamespace::Uts => "uts",
            ShareableNamespace::Cgroup => "cgroup",
        }
    }
}

impl FromStr for ShareableNamespace {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        match s {
            "net" => Ok(ShareableNamespace::Net),
            "pid" => Ok(ShareableNamespace::Pid),
            "ipc" => Ok(ShareableNamespace::Ipc),
            "uts" => Ok(ShareableNamespace::Uts),
            "cgroup" => Ok(ShareableNamespace::Cgroup),
            "user" | "mount" => Err(ValueError::new(format!(
                "invalid namespace {s:?}: the user and mount namespaces are always unshared \
                 (bubblewrap requires them and the sandbox's privilege-drop and mount-locking \
                 invariants depend on them)"
            ))),
            _ => Err(ValueError::new(format!(
                "invalid namespace {s:?}: expected one of \"net\", \"pid\", \"ipc\", \"uts\", \"cgroup\""
            ))),
        }
    }
}

impl TryFrom<String> for ShareableNamespace {
    type Error = ValueError;

    fn try_from(s: String) -> Result<Self, ValueError> {
        s.parse()
    }
}

impl fmt::Display for ShareableNamespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A syscall (or group of syscalls) that a provider may re-enable in the
/// seccomp filter (DESIGN.md §6.3).
///
/// Only attack-surface reducers are listed. Everything the sandbox's
/// invariants depend on (`mount`, `unshare`, `setns`, `clone3`, `pivot_root`,
/// `kexec_load`, `open_by_handle_at`, …) can never be re-enabled.
///
/// Ordered by declaration, so that merged sets iterate deterministically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(try_from = "String")]
pub enum OptInSyscall {
    /// `ptrace`.
    Ptrace,
    /// `perf_event_open`.
    PerfEventOpen,
    /// `io_uring_setup`, `io_uring_enter` and `io_uring_register`.
    IoUring,
    /// `userfaultfd`.
    Userfaultfd,
    /// `bpf`.
    Bpf,
    /// `keyctl`, `add_key` and `request_key`.
    Keyctl,
}

impl OptInSyscall {
    /// The spelling used in configuration.
    pub fn as_str(self) -> &'static str {
        match self {
            OptInSyscall::Ptrace => "ptrace",
            OptInSyscall::PerfEventOpen => "perf_event_open",
            OptInSyscall::IoUring => "io_uring",
            OptInSyscall::Userfaultfd => "userfaultfd",
            OptInSyscall::Bpf => "bpf",
            OptInSyscall::Keyctl => "keyctl",
        }
    }
}

/// Syscalls the sandbox's invariants depend on (§6.3); naming one gets a
/// specific explanation.
const INVARIANT_SYSCALLS: [&str; 16] = [
    "mount",
    "umount2",
    "pivot_root",
    "fsopen",
    "fsconfig",
    "fsmount",
    "fspick",
    "open_tree",
    "move_mount",
    "mount_setattr",
    "unshare",
    "setns",
    "clone3",
    "kexec_load",
    "kexec_file_load",
    "open_by_handle_at",
];

impl FromStr for OptInSyscall {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        match s {
            "ptrace" => Ok(OptInSyscall::Ptrace),
            "perf_event_open" => Ok(OptInSyscall::PerfEventOpen),
            "io_uring" => Ok(OptInSyscall::IoUring),
            "userfaultfd" => Ok(OptInSyscall::Userfaultfd),
            "bpf" => Ok(OptInSyscall::Bpf),
            "keyctl" => Ok(OptInSyscall::Keyctl),
            _ if INVARIANT_SYSCALLS.contains(&s) => Err(ValueError::new(format!(
                "invalid syscall {s:?}: it cannot be re-enabled because the sandbox's invariants \
                 depend on it"
            ))),
            _ => Err(ValueError::new(format!(
                "invalid syscall {s:?}: only \"ptrace\", \"perf_event_open\", \"io_uring\", \
                 \"userfaultfd\", \"bpf\" and \"keyctl\" may be re-enabled"
            ))),
        }
    }
}

impl TryFrom<String> for OptInSyscall {
    type Error = ValueError;

    fn try_from(s: String) -> Result<Self, ValueError> {
        s.parse()
    }
}

impl fmt::Display for OptInSyscall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::super::Manifest;
    use super::super::test_util::*;
    use super::*;

    const NAMESPACES: [ShareableNamespace; 5] = [
        ShareableNamespace::Net,
        ShareableNamespace::Pid,
        ShareableNamespace::Ipc,
        ShareableNamespace::Uts,
        ShareableNamespace::Cgroup,
    ];
    // Adding a variant breaks the build here, reminding to extend the tests.
    const _: fn(ShareableNamespace) = |n| match n {
        ShareableNamespace::Net
        | ShareableNamespace::Pid
        | ShareableNamespace::Ipc
        | ShareableNamespace::Uts
        | ShareableNamespace::Cgroup => {}
    };

    const SYSCALLS: [OptInSyscall; 6] = [
        OptInSyscall::Ptrace,
        OptInSyscall::PerfEventOpen,
        OptInSyscall::IoUring,
        OptInSyscall::Userfaultfd,
        OptInSyscall::Bpf,
        OptInSyscall::Keyctl,
    ];
    const _: fn(OptInSyscall) = |s| match s {
        OptInSyscall::Ptrace
        | OptInSyscall::PerfEventOpen
        | OptInSyscall::IoUring
        | OptInSyscall::Userfaultfd
        | OptInSyscall::Bpf
        | OptInSyscall::Keyctl => {}
    };

    const NAMESPACE_NAMES: [&str; 5] = ["net", "pid", "ipc", "uts", "cgroup"];
    const SYSCALL_NAMES: [&str; 6] = [
        "ptrace",
        "perf_event_open",
        "io_uring",
        "userfaultfd",
        "bpf",
        "keyctl",
    ];

    #[test]
    fn empty_sandbox_section_is_default() {
        let want = SandboxGrants::default();
        assert!(want.share.is_empty() && want.allow_syscalls.is_empty());
        assert_eq!(Manifest::default().grants.sandbox, want);
        assert_eq!(toml_ok("").grants.sandbox, want);
        assert_eq!(toml_ok("[sandbox]").grants.sandbox, want);
        assert_eq!(jv_ok("").grants.sandbox, want);
        assert_eq!(jv_ok(r#""sandbox": {}"#).grants.sandbox, want);
        // §3.6 spells out empty lists.
        assert_eq!(
            jv_ok(r#""sandbox": { "share": [], "allow_syscalls": [] }"#)
                .grants
                .sandbox,
            want
        );
    }

    #[test]
    fn every_namespace_parses_and_round_trips() {
        for (ns, name) in NAMESPACES.iter().zip(NAMESPACE_NAMES) {
            assert_eq!(name.parse::<ShareableNamespace>().unwrap(), *ns);
            assert_eq!(ns.to_string(), name);
            assert_eq!(ns.as_str(), name);
            assert_eq!(ShareableNamespace::try_from(name.to_owned()).unwrap(), *ns);
            let m = toml_ok(&format!("sandbox.share = [{name:?}]"));
            assert_eq!(m.grants.sandbox.share, vec![*ns]);
            let j = jv_ok(&format!(r#""sandbox": {{"share": [{name:?}]}}"#));
            assert_eq!(j.grants.sandbox.share, vec![*ns]);
        }
        let all = r#"["net", "pid", "ipc", "uts", "cgroup"]"#;
        assert_eq!(
            toml_ok(&format!("sandbox.share = {all}"))
                .grants
                .sandbox
                .share,
            NAMESPACES.to_vec()
        );
        assert_eq!(
            jv_ok(&format!(r#""sandbox": {{"share": {all}}}"#))
                .grants
                .sandbox
                .share,
            NAMESPACES.to_vec()
        );
    }

    #[test]
    fn user_and_mount_namespaces_cannot_be_shared() {
        for bad in ["user", "mount"] {
            let msg = bad.parse::<ShareableNamespace>().unwrap_err().to_string();
            assert!(msg.contains(&format!("{bad:?}")), "{bad:?}: {msg}");
            assert!(msg.contains("always unshared"), "{bad:?}: {msg}");
            assert!(msg.contains("bubblewrap"), "{bad:?}: {msg}");
            let msg = toml_err(&format!("sandbox.share = [{bad:?}]"));
            assert!(
                msg.contains(bad) && msg.contains("always unshared"),
                "{msg}"
            );
            let msg = jv_err(&format!(r#""sandbox": {{"share": [{bad:?}]}}"#));
            assert!(
                msg.contains(bad) && msg.contains("always unshared"),
                "{msg}"
            );
        }
    }

    #[test]
    fn invalid_namespaces_are_rejected_naming_the_value() {
        for bad in [
            "", "all", "Net", "NET", "network", "time", "net ", " net", "uts\n", "cgroups", "mnt",
            "USER",
        ] {
            let msg = bad.parse::<ShareableNamespace>().unwrap_err().to_string();
            assert!(msg.contains("invalid namespace"), "{bad:?}: {msg}");
            assert!(msg.contains(&format!("{bad:?}")), "{bad:?}: {msg}");
            assert!(!msg.contains("always unshared"), "{bad:?}: {msg}");
            toml_err(&format!("sandbox.share = [{bad:?}]"));
            jv_err(&format!(r#""sandbox": {{"share": [{bad:?}]}}"#));
        }
        toml_err("sandbox.share = \"net\"");
        toml_err("sandbox.share = [1]");
        jv_err(r#""sandbox": {"share": "net"}"#);
    }

    #[test]
    fn every_opt_in_syscall_parses_and_round_trips() {
        for (sc, name) in SYSCALLS.iter().zip(SYSCALL_NAMES) {
            assert_eq!(name.parse::<OptInSyscall>().unwrap(), *sc);
            assert_eq!(sc.to_string(), name);
            assert_eq!(sc.as_str(), name);
            assert_eq!(OptInSyscall::try_from(name.to_owned()).unwrap(), *sc);
            let m = toml_ok(&format!("sandbox.allow_syscalls = [{name:?}]"));
            assert_eq!(m.grants.sandbox.allow_syscalls, vec![*sc]);
            let j = jv_ok(&format!(r#""sandbox": {{"allow_syscalls": [{name:?}]}}"#));
            assert_eq!(j.grants.sandbox.allow_syscalls, vec![*sc]);
        }
        let m = toml_ok("sandbox.allow_syscalls = [\"ptrace\", \"bpf\"]");
        assert_eq!(
            m.grants.sandbox.allow_syscalls,
            vec![OptInSyscall::Ptrace, OptInSyscall::Bpf]
        );
    }

    #[test]
    fn other_syscalls_cannot_be_re_enabled() {
        // Syscalls the invariants depend on get a specific explanation.
        assert_eq!(INVARIANT_SYSCALLS.len(), 16);
        for bad in INVARIANT_SYSCALLS {
            let msg = bad.parse::<OptInSyscall>().unwrap_err().to_string();
            assert!(msg.contains("invalid syscall"), "{bad:?}: {msg}");
            assert!(msg.contains(&format!("{bad:?}")), "{bad:?}: {msg}");
            assert!(
                msg.contains("cannot be re-enabled because the sandbox's invariants depend on it"),
                "{bad:?}: {msg}"
            );
            let msg = toml_err(&format!("sandbox.allow_syscalls = [{bad:?}]"));
            assert!(msg.contains("invariants depend on it"), "{bad:?}: {msg}");
            let msg = jv_err(&format!(r#""sandbox": {{"allow_syscalls": [{bad:?}]}}"#));
            assert!(msg.contains("invariants depend on it"), "{bad:?}: {msg}");
        }
        // Everything else is just not on the opt-in list.
        for bad in [
            "ptarce",
            "read",
            "clone",
            "io_uring_setup",
            "io_uring_enter",
            "add_key",
            "request_key",
            "rename",
            "socket",
            "Ptrace",
            "PTRACE",
            "",
        ] {
            let msg = bad.parse::<OptInSyscall>().unwrap_err().to_string();
            assert!(msg.contains("invalid syscall"), "{bad:?}: {msg}");
            assert!(msg.contains(&format!("{bad:?}")), "{bad:?}: {msg}");
            assert!(msg.contains("may be re-enabled"), "{bad:?}: {msg}");
            assert!(!msg.contains("invariants"), "{bad:?}: {msg}");
            let msg = toml_err(&format!("sandbox.allow_syscalls = [{bad:?}]"));
            assert!(msg.contains("may be re-enabled"), "{bad:?}: {msg}");
            let msg = jv_err(&format!(r#""sandbox": {{"allow_syscalls": [{bad:?}]}}"#));
            assert!(msg.contains("may be re-enabled"), "{bad:?}: {msg}");
        }
        toml_err("sandbox.allow_syscalls = \"ptrace\"");
        toml_err("sandbox.allow_syscalls = [1]");
    }

    #[test]
    fn sandbox_is_map_only_and_rejects_unknown_keys() {
        for src in [
            r#""sandbox": []"#,
            r#""sandbox": [["net"], ["ptrace"]]"#,
            r#""sandbox": [[], []]"#,
        ] {
            let msg = jv_err(src);
            assert!(msg.contains("expected a map"), "{src}: {msg}");
        }
        for src in ["sandbox = []", "sandbox = [[\"net\"], []]"] {
            let msg = toml_err(src);
            assert!(msg.contains("expected a map"), "{src}: {msg}");
        }
        let msg = toml_err("sandbox.shares = []");
        assert!(msg.contains("shares"), "{msg}");
        let msg = jv_err(r#""sandbox": {"syscalls": []}"#);
        assert!(msg.contains("syscalls"), "{msg}");
        let msg = toml_err("[sandbox]\nallow_syscall = []");
        assert!(msg.contains("allow_syscall"), "{msg}");
    }
}
