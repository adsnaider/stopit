//! The `system` manifest section: system mounts and synthesized files
//! (DESIGN.md §3.6, §6.2).

use std::fmt;
use std::str::FromStr;

use serde::Deserialize;

use super::check_plain_absolute;
use crate::error::ValueError;
use crate::serde_util::MapOnly;

/// The `system` section.
///
/// Deserializes from a table or object only, never from a sequence. Scalars
/// are `Option`s so that merging (logical OR / union, §3.5) can tell "unset"
/// from an explicit value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(from = "MapOnly<RawSystemGrants>")]
pub struct SystemGrants {
    /// Mount a masked-subset `/proc`.
    pub proc: Option<bool>,
    /// Mount a `/dev`.
    pub dev: Option<DevMode>,
    /// Synthesized `/etc` files.
    pub etc: Vec<EtcFile>,
    /// The sandbox `HOME`.
    pub home: Option<SandboxHome>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawSystemGrants {
    proc: Option<bool>,
    dev: Option<DevMode>,
    etc: Vec<EtcFile>,
    home: Option<SandboxHome>,
}

impl From<MapOnly<RawSystemGrants>> for SystemGrants {
    fn from(MapOnly(raw): MapOnly<RawSystemGrants>) -> Self {
        SystemGrants {
            proc: raw.proc,
            dev: raw.dev,
            etc: raw.etc,
            home: raw.home,
        }
    }
}

/// Which `/dev` to mount.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DevMode {
    /// `null`, `zero`, `full`, `random`, `urandom`, `tty` and a new `devpts`.
    Minimal,
}

impl DevMode {
    /// The lowercase spelling used in configuration.
    pub fn as_str(self) -> &'static str {
        match self {
            DevMode::Minimal => "minimal",
        }
    }
}

impl fmt::Display for DevMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A synthesized file under `/etc`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
pub enum EtcFile {
    /// `/etc/passwd`.
    #[serde(rename = "passwd")]
    Passwd,
    /// `/etc/group`.
    #[serde(rename = "group")]
    Group,
    /// `/etc/hosts`.
    #[serde(rename = "hosts")]
    Hosts,
    /// `/etc/nsswitch.conf`.
    #[serde(rename = "nsswitch.conf")]
    NsswitchConf,
}

impl EtcFile {
    /// The file name as written in configuration.
    pub fn as_str(self) -> &'static str {
        match self {
            EtcFile::Passwd => "passwd",
            EtcFile::Group => "group",
            EtcFile::Hosts => "hosts",
            EtcFile::NsswitchConf => "nsswitch.conf",
        }
    }
}

impl fmt::Display for EtcFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The sandbox `HOME`: an absolute sandbox path.
///
/// No `~`, no globs, no placeholders, the same component rules as
/// [`SandboxPath`](super::SandboxPath), and not `/`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct SandboxHome(String);

impl SandboxHome {
    /// The validated path text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for SandboxHome {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        check_plain_absolute(s)
            .map_err(|why| ValueError::new(format!("invalid sandbox home {s:?}: {why}")))?;
        Ok(SandboxHome(s.to_owned()))
    }
}

impl TryFrom<String> for SandboxHome {
    type Error = ValueError;

    fn try_from(s: String) -> Result<Self, ValueError> {
        s.parse()
    }
}

impl fmt::Display for SandboxHome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::super::Manifest;
    use super::super::test_util::*;
    use super::*;

    const ETC_FILES: [EtcFile; 4] = [
        EtcFile::Passwd,
        EtcFile::Group,
        EtcFile::Hosts,
        EtcFile::NsswitchConf,
    ];
    // Adding a variant breaks the build here, reminding to extend the tests.
    const _: fn(EtcFile) = |e| match e {
        EtcFile::Passwd | EtcFile::Group | EtcFile::Hosts | EtcFile::NsswitchConf => {}
    };
    const _: fn(DevMode) = |d| match d {
        DevMode::Minimal => {}
    };

    fn home(s: &str) -> SandboxHome {
        s.parse().unwrap()
    }

    #[test]
    fn empty_system_section_is_default() {
        let want = SystemGrants::default();
        assert_eq!(want.proc, None);
        assert_eq!(want.dev, None);
        assert!(want.etc.is_empty());
        assert_eq!(want.home, None);
        assert_eq!(Manifest::default().grants.system, want);
        assert_eq!(toml_ok("").grants.system, want);
        assert_eq!(toml_ok("[system]").grants.system, want);
        assert_eq!(jv_ok("").grants.system, want);
        assert_eq!(jv_ok(r#""system": {}"#).grants.system, want);
    }

    #[test]
    fn appendix_a_system_parses_from_toml_and_json() {
        let want = SystemGrants {
            proc: Some(true),
            dev: Some(DevMode::Minimal),
            etc: ETC_FILES.to_vec(),
            home: Some(home("/home/user")),
        };
        let toml = r#"
            system = { proc = true, dev = "minimal", etc = ["passwd", "group", "hosts", "nsswitch.conf"], home = "/home/user" }
        "#;
        assert_eq!(toml_ok(toml).grants.system, want);
        let json = r#""system": { "proc": true, "dev": "minimal", "etc": ["passwd", "group", "hosts", "nsswitch.conf"], "home": "/home/user" }"#;
        assert_eq!(jv_ok(json).grants.system, want);
        // As a standalone table too.
        let toml = "[system]\nproc = true\ndev = \"minimal\"\netc = [\"passwd\", \"group\", \"hosts\", \"nsswitch.conf\"]\nhome = \"/home/user\"";
        assert_eq!(toml_ok(toml).grants.system, want);
    }

    #[test]
    fn proc_is_tri_state() {
        assert_eq!(toml_ok("system.proc = true").grants.system.proc, Some(true));
        assert_eq!(
            toml_ok("system.proc = false").grants.system.proc,
            Some(false)
        );
        assert_eq!(
            jv_ok(r#""system": {"proc": false}"#).grants.system.proc,
            Some(false)
        );
        assert_eq!(jv_ok(r#""system": {}"#).grants.system.proc, None);
        toml_err("system.proc = \"yes\"");
        jv_err(r#""system": {"proc": 1}"#);
    }

    #[test]
    fn dev_mode_parses_and_displays() {
        assert_eq!(
            toml_ok("system.dev = \"minimal\"").grants.system.dev,
            Some(DevMode::Minimal)
        );
        assert_eq!(
            jv_ok(r#""system": {"dev": "minimal"}"#).grants.system.dev,
            Some(DevMode::Minimal)
        );
        assert_eq!(DevMode::Minimal.to_string(), "minimal");
        assert_eq!(DevMode::Minimal.as_str(), "minimal");
        for bad in ["full", "Minimal", "MINIMAL", "host", ""] {
            let msg = toml_err(&format!("system.dev = {bad:?}"));
            assert!(msg.contains(bad) || bad.is_empty(), "{bad:?}: {msg}");
            let msg = jv_err(&format!(r#""system": {{"dev": {bad:?}}}"#));
            assert!(msg.contains(bad) || bad.is_empty(), "{bad:?}: {msg}");
        }
        toml_err("system.dev = true");
    }

    #[test]
    fn every_etc_file_parses_and_round_trips() {
        let names = ["passwd", "group", "hosts", "nsswitch.conf"];
        for (file, name) in ETC_FILES.into_iter().zip(names) {
            assert_eq!(file.to_string(), name);
            assert_eq!(file.as_str(), name);
            let m = toml_ok(&format!("system.etc = [{name:?}]"));
            assert_eq!(m.grants.system.etc, vec![file]);
            let j = jv_ok(&format!(r#""system": {{"etc": [{name:?}]}}"#));
            assert_eq!(j.grants.system.etc, vec![file]);
        }
    }

    #[test]
    fn invalid_etc_files_are_rejected_naming_the_value() {
        for bad in [
            "shadow",
            "nsswitch",
            "Passwd",
            "/etc/passwd",
            "resolv.conf",
            "",
        ] {
            let msg = toml_err(&format!("system.etc = [{bad:?}]"));
            assert!(msg.contains(bad) || bad.is_empty(), "{bad:?}: {msg}");
            let msg = jv_err(&format!(r#""system": {{"etc": [{bad:?}]}}"#));
            assert!(msg.contains(bad) || bad.is_empty(), "{bad:?}: {msg}");
        }
        toml_err("system.etc = \"passwd\"");
    }

    #[test]
    fn valid_sandbox_homes() {
        for good in [
            "/home/user",
            "/root",
            "/h",
            "/a..b",
            "/.hidden",
            "/home/user name",
        ] {
            let h = good.parse::<SandboxHome>().unwrap();
            assert_eq!(h.as_str(), good);
            assert_eq!(h.to_string(), good);
            assert_eq!(SandboxHome::try_from(good.to_owned()).unwrap(), h);
            assert_eq!(
                toml_ok(&format!("system.home = {good:?}"))
                    .grants
                    .system
                    .home,
                Some(h.clone())
            );
            assert_eq!(
                jv_ok(&format!(r#""system": {{"home": {good:?}}}"#))
                    .grants
                    .system
                    .home,
                Some(h)
            );
        }
    }

    #[test]
    fn invalid_sandbox_homes() {
        for bad in [
            "",
            "/",
            "~",
            "~/x",
            "home/user",
            "./x",
            "{workspace}",
            "{workspace}/x",
            "/a/{x}",
            "/a/*",
            "/a/?",
            "/a/[x]",
            "/a/",
            "/a//b",
            "/a/./b",
            "/a/../b",
            "/..",
            "//",
            "/a\0b",
        ] {
            let msg = bad.parse::<SandboxHome>().unwrap_err().to_string();
            assert!(msg.contains("sandbox home"), "{bad:?}: {msg}");
            assert!(msg.contains(&format!("{bad:?}")), "{bad:?}: {msg}");
            if !bad.contains('\0') {
                toml_err(&format!("system.home = {bad:?}"));
                jv_err(&format!(r#""system": {{"home": {bad:?}}}"#));
            }
        }
        let msg = jv_err(r#""system": {"home": "/a\u0000b"}"#);
        assert!(msg.contains("NUL"), "{msg}");
        let msg = "/".parse::<SandboxHome>().unwrap_err().to_string();
        assert!(msg.contains("root"), "{msg}");
    }

    #[test]
    fn system_is_map_only_and_rejects_unknown_keys() {
        for src in [
            r#""system": []"#,
            r#""system": [true, "minimal", [], "/home/user"]"#,
        ] {
            let msg = jv_err(src);
            assert!(msg.contains("expected a map"), "{src}: {msg}");
        }
        for src in ["system = []", "system = [true]"] {
            let msg = toml_err(src);
            assert!(msg.contains("expected a map"), "{src}: {msg}");
        }
        let msg = toml_err("system.procs = true");
        assert!(msg.contains("procs"), "{msg}");
        let msg = jv_err(r#""system": {"devs": "minimal"}"#);
        assert!(msg.contains("devs"), "{msg}");
        let msg = toml_err("[system]\nhomes = \"/h\"");
        assert!(msg.contains("homes"), "{msg}");
    }
}
