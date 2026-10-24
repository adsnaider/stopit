//! Session-wide top-level configuration settings (DESIGN.md §3.1).
//!
//! Only the settings that are not grants live here: `base`, `[workspace]`,
//! `[limits]`, `[approval]` and `[terminal]`, plus the structure of
//! `[profiles.<name>]` declarations. Providers are not handled yet.
//!
//! This is security configuration, so every table rejects unknown keys:
//! a typo must fail loudly instead of silently falling back to a default.

mod profile;

pub use profile::{Inherit, ProfileDecl, ProfileName, ProfileRef};

use std::collections::BTreeMap;
use std::num::{IntErrorKind, NonZeroU32};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use serde::{Deserialize, Deserializer, de::Error as _};
use thiserror::Error;

/// Error produced while loading a configuration document.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The document is not valid TOML, or does not match the schema. The
    /// underlying message includes the line and column.
    #[error("invalid configuration: {0}")]
    Toml(#[from] toml::de::Error),
}

/// Error parsing one of the custom value types (`"8G"`, `"400%"`, `"5m"`).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{0}")]
pub struct ValueError(String);

/// The session-wide top-level settings (DESIGN.md §3.1).
///
/// Every field has the default given in the design, so an empty document is
/// valid.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// Starting set of built-in providers (§3.2).
    pub base: Base,
    /// Workspace identity and mount point.
    pub workspace: WorkspaceSettings,
    /// Resource limits (§10).
    pub limits: Limits,
    /// Approval settings (§4.3).
    pub approval: Approval,
    /// Terminal settings (§5).
    pub terminal: Terminal,
    /// User-declared profiles (§3.3). `main` is implicit and cannot be
    /// declared.
    pub profiles: BTreeMap<ProfileName, ProfileDecl>,
}

impl Config {
    /// Parses a configuration document from TOML text.
    pub fn from_toml_str(s: &str) -> Result<Config, ConfigError> {
        Ok(toml::from_str(s)?)
    }
}

/// The starting set of providers (DESIGN.md §3.2).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Base {
    /// Built-in default providers.
    #[default]
    Default,
    /// No built-in providers at all.
    None,
}

/// `[workspace]` table (DESIGN.md §3.1).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct WorkspaceSettings {
    /// Where `{workspace}` appears inside the sandbox.
    pub mount: WorkspaceMount,
}

/// Where the workspace is mounted inside the sandbox.
///
/// Guaranteed to be an absolute path that is not `/`, contains no NUL bytes
/// and has no `.` or `..` components. Whether it collides with other
/// sandbox mounts is checked later, when the sandbox is compiled.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct WorkspaceMount(PathBuf);

impl WorkspaceMount {
    /// The validated mount path.
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

impl Default for WorkspaceMount {
    fn default() -> Self {
        WorkspaceMount(PathBuf::from("/workspace"))
    }
}

impl FromStr for WorkspaceMount {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        let bad = |why: &str| ValueError(format!("invalid workspace mount {s:?}: {why}"));
        if !s.starts_with('/') {
            return Err(bad("must be an absolute path"));
        }
        if s.chars().all(|c| c == '/') {
            return Err(bad("must not be the root directory"));
        }
        if s.contains('\0') {
            return Err(bad("must not contain NUL bytes"));
        }
        // Checked on the raw string: `Path::components` silently drops
        // interior `.` components.
        if s.split('/').any(|c| c == "." || c == "..") {
            return Err(bad("must not contain `.` or `..` components"));
        }
        Ok(WorkspaceMount(PathBuf::from(s)))
    }
}

impl TryFrom<String> for WorkspaceMount {
    type Error = ValueError;

    fn try_from(s: String) -> Result<Self, ValueError> {
        s.parse()
    }
}

/// `[limits]` table (DESIGN.md §10). Every limit is off by default.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    /// Maximum number of processes; must be greater than zero.
    pub pids: Option<NonZeroU32>,
    /// Memory limit, e.g. `"8G"`.
    pub memory: Option<MemoryLimit>,
    /// CPU limit as a percentage of one CPU, e.g. `"400%"`.
    pub cpu: Option<CpuLimit>,
}

/// Splits a leading run of ASCII digits off `s`. `expected` describes the
/// accepted format for the error message when `s` does not start with a
/// number.
fn split_digits<'a>(what: &str, expected: &str, s: &'a str) -> Result<(u64, &'a str), ValueError> {
    let end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (digits, rest) = s.split_at(end);
    let n = digits.parse::<u64>().map_err(|e| match e.kind() {
        IntErrorKind::PosOverflow => {
            ValueError(format!("invalid {what} {s:?}: number is too large"))
        }
        _ => ValueError(format!("invalid {what} {s:?}: expected {expected}")),
    })?;
    Ok((n, rest))
}

/// A memory limit in bytes, parsed from `<integer><unit>`.
///
/// Units are `K`, `M`, `G` and `T` (binary, 1024-based). Units are
/// case-sensitive: only uppercase is accepted, so `"8g"` is rejected.
/// Zero and values that overflow `u64` bytes are rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct MemoryLimit(u64);

impl MemoryLimit {
    /// The limit in bytes.
    pub fn bytes(self) -> u64 {
        self.0
    }
}

impl FromStr for MemoryLimit {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        let (n, unit) = split_digits("memory limit", "<int>K|M|G|T", s)?;
        let shift = match unit {
            "K" => 10,
            "M" => 20,
            "G" => 30,
            "T" => 40,
            _ => {
                return Err(ValueError(format!(
                    "invalid memory limit {s:?}: expected <int>K|M|G|T (uppercase unit)"
                )));
            }
        };
        if n == 0 {
            return Err(ValueError(format!(
                "invalid memory limit {s:?}: must be greater than zero"
            )));
        }
        n.checked_mul(1u64 << shift)
            .map(MemoryLimit)
            .ok_or_else(|| ValueError(format!("invalid memory limit {s:?}: value overflows")))
    }
}

impl TryFrom<String> for MemoryLimit {
    type Error = ValueError;

    fn try_from(s: String) -> Result<Self, ValueError> {
        s.parse()
    }
}

/// A CPU limit in percent of one CPU, parsed from `<integer>%`.
///
/// `"400%"` means four full CPUs. Zero and non-integers are rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct CpuLimit(u32);

impl CpuLimit {
    /// The limit as a percentage of one CPU.
    pub fn percent(self) -> u32 {
        self.0
    }
}

impl FromStr for CpuLimit {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        let (n, rest) = split_digits("cpu limit", "<int>%", s)?;
        if rest != "%" {
            return Err(ValueError(format!(
                "invalid cpu limit {s:?}: expected <int>%"
            )));
        }
        if n == 0 {
            return Err(ValueError(format!(
                "invalid cpu limit {s:?}: must be greater than zero"
            )));
        }
        u32::try_from(n)
            .map(CpuLimit)
            .map_err(|_| ValueError(format!("invalid cpu limit {s:?}: value is too large")))
    }
}

impl TryFrom<String> for CpuLimit {
    type Error = ValueError;

    fn try_from(s: String) -> Result<Self, ValueError> {
        s.parse()
    }
}

/// `[approval]` table (DESIGN.md §4.3).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Approval {
    /// How long a pending approval waits before being auto-denied.
    pub timeout: ApprovalTimeout,
    /// What to do about writes to masked files.
    pub masked_writes: MaskedWrites,
}

/// Approval timeout: `"off"` (default) or `<integer><s|m|h>`.
///
/// Zero durations and bare integers are rejected.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub enum ApprovalTimeout {
    /// A pending approval blocks indefinitely.
    #[default]
    Off,
    /// A pending approval is denied after this long.
    After(Duration),
}

impl FromStr for ApprovalTimeout {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        if s == "off" {
            return Ok(ApprovalTimeout::Off);
        }
        let (n, unit) = split_digits("approval timeout", "\"off\" or <int>s|m|h", s)?;
        let mult = match unit {
            "s" => 1,
            "m" => 60,
            "h" => 3600,
            _ => {
                return Err(ValueError(format!(
                    "invalid approval timeout {s:?}: expected \"off\" or <int>s|m|h"
                )));
            }
        };
        if n == 0 {
            return Err(ValueError(format!(
                "invalid approval timeout {s:?}: must be greater than zero"
            )));
        }
        n.checked_mul(mult)
            .map(|secs| ApprovalTimeout::After(Duration::from_secs(secs)))
            .ok_or_else(|| ValueError(format!("invalid approval timeout {s:?}: value overflows")))
    }
}

impl TryFrom<String> for ApprovalTimeout {
    type Error = ValueError;

    fn try_from(s: String) -> Result<Self, ValueError> {
        s.parse()
    }
}

/// Policy for writes to masked files (DESIGN.md §4.3).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MaskedWrites {
    /// Deny without prompting.
    #[default]
    Deny,
    /// Prompt the user.
    Ask,
}

/// `[terminal]` table (DESIGN.md §5).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Terminal {
    /// Key that opens the supervisor menu. Not parsed yet; must be non-empty.
    #[serde(deserialize_with = "deserialize_hotkey")]
    pub hotkey: String,
    /// Policy for OSC 52 clipboard writes (§5.3).
    pub clipboard_write: ClipboardWrite,
}

impl Default for Terminal {
    fn default() -> Self {
        Terminal {
            hotkey: "ctrl-]".to_owned(),
            clipboard_write: ClipboardWrite::default(),
        }
    }
}

fn deserialize_hotkey<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    let s = String::deserialize(d)?;
    if s.is_empty() {
        return Err(D::Error::custom("invalid hotkey \"\": must not be empty"));
    }
    Ok(s)
}

/// Policy for OSC 52 clipboard writes from the sandbox (DESIGN.md §5.3).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClipboardWrite {
    /// Drop clipboard writes.
    #[default]
    Block,
    /// Pass clipboard writes through.
    Allow,
    /// Show the content and ask.
    Ask,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expected_defaults() -> Config {
        Config {
            base: Base::Default,
            workspace: WorkspaceSettings {
                mount: "/workspace".parse().unwrap(),
            },
            limits: Limits {
                pids: None,
                memory: None,
                cpu: None,
            },
            approval: Approval {
                timeout: ApprovalTimeout::Off,
                masked_writes: MaskedWrites::Deny,
            },
            terminal: Terminal {
                hotkey: "ctrl-]".to_owned(),
                clipboard_write: ClipboardWrite::Block,
            },
            profiles: BTreeMap::new(),
        }
    }

    /// Parses `src`, expecting failure, and returns the error message.
    fn err(src: &str) -> String {
        match Config::from_toml_str(src) {
            Ok(c) => panic!("expected an error for {src:?}, got {c:?}"),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn empty_document_is_all_defaults() {
        assert_eq!(Config::from_toml_str("").unwrap(), expected_defaults());
        assert_eq!(Config::default(), expected_defaults());
    }

    #[test]
    fn empty_tables_are_all_defaults() {
        let src = "[workspace]\n[limits]\n[approval]\n[terminal]\n";
        assert_eq!(Config::from_toml_str(src).unwrap(), expected_defaults());
    }

    #[test]
    fn full_document_parses() {
        let src = r#"
            base = "none"

            [workspace]
            mount = "/workspace"

            [limits]
            pids   = 4096
            memory = "8G"
            cpu    = "400%"

            [approval]
            timeout = "5m"
            masked_writes = "ask"

            [terminal]
            hotkey = "ctrl-]"
            clipboard_write = "ask"
        "#;
        let expected = Config {
            base: Base::None,
            workspace: WorkspaceSettings {
                mount: "/workspace".parse().unwrap(),
            },
            limits: Limits {
                pids: NonZeroU32::new(4096),
                memory: Some(MemoryLimit(8 * 1024 * 1024 * 1024)),
                cpu: Some(CpuLimit(400)),
            },
            approval: Approval {
                timeout: ApprovalTimeout::After(Duration::from_secs(300)),
                masked_writes: MaskedWrites::Ask,
            },
            terminal: Terminal {
                hotkey: "ctrl-]".to_owned(),
                clipboard_write: ClipboardWrite::Ask,
            },
            profiles: BTreeMap::new(),
        };
        assert_eq!(Config::from_toml_str(src).unwrap(), expected);
    }

    #[test]
    fn appendix_a_top_level_values_parse() {
        let src = r#"
            base = "none"
            [workspace]
            mount = "/workspace"
            [approval]
            timeout = "off"
            masked_writes = "deny"
            [terminal]
            hotkey = "ctrl-]"
            clipboard_write = "block"
        "#;
        let cfg = Config::from_toml_str(src).unwrap();
        assert_eq!(
            cfg,
            Config {
                base: Base::None,
                ..expected_defaults()
            }
        );
    }

    #[test]
    fn enum_values_parse() {
        for (s, v) in [("default", Base::Default), ("none", Base::None)] {
            let cfg = Config::from_toml_str(&format!("base = \"{s}\"")).unwrap();
            assert_eq!(cfg.base, v);
        }
        for (s, v) in [("deny", MaskedWrites::Deny), ("ask", MaskedWrites::Ask)] {
            let src = format!("[approval]\nmasked_writes = \"{s}\"");
            assert_eq!(
                Config::from_toml_str(&src).unwrap().approval.masked_writes,
                v
            );
        }
        for (s, v) in [
            ("block", ClipboardWrite::Block),
            ("allow", ClipboardWrite::Allow),
            ("ask", ClipboardWrite::Ask),
        ] {
            let src = format!("[terminal]\nclipboard_write = \"{s}\"");
            assert_eq!(
                Config::from_toml_str(&src)
                    .unwrap()
                    .terminal
                    .clipboard_write,
                v
            );
        }
    }

    #[test]
    fn unknown_enum_values_are_rejected() {
        for src in [
            "base = \"all\"",
            "base = \"Default\"",
            "[approval]\nmasked_writes = \"allow\"",
            "[approval]\nmasked_writes = \"Deny\"",
            "[terminal]\nclipboard_write = \"yes\"",
            "[terminal]\nclipboard_write = \"BLOCK\"",
        ] {
            err(src);
        }
    }

    #[test]
    fn invalid_workspace_mounts_are_rejected() {
        for bad in [
            "workspace",
            "./workspace",
            "",
            "/",
            "//",
            "/a/../b",
            "/a/./b",
            "/..",
            "/.",
            "/a/..",
        ] {
            let msg = err(&format!("[workspace]\nmount = \"{bad}\""));
            assert!(msg.contains("workspace mount"), "{bad:?}: {msg}");
            assert!(msg.contains(&format!("{bad:?}")), "{bad:?}: {msg}");
        }
        let msg = err("[workspace]\nmount = 5");
        assert!(msg.contains("string"), "{msg}");
    }

    #[test]
    fn valid_workspace_mounts_are_accepted() {
        for good in ["/workspace", "/a/b", "/work/", "/a..b", "/.hidden"] {
            let cfg = Config::from_toml_str(&format!("[workspace]\nmount = \"{good}\"")).unwrap();
            assert_eq!(cfg.workspace.mount.as_path(), Path::new(good));
        }
        assert_eq!(
            WorkspaceSettings::default().mount.as_path(),
            Path::new("/workspace")
        );
    }

    #[test]
    fn nul_in_workspace_mount_is_rejected() {
        let msg = err("[workspace]\nmount = \"/a\\u0000b\"");
        assert!(msg.contains("NUL"), "{msg}");
        let own = "/a\0b".parse::<WorkspaceMount>().unwrap_err().to_string();
        assert!(own.contains("NUL"), "{own}");
        for bad in ["workspace", "/", "/a/../b"] {
            let own = bad.parse::<WorkspaceMount>().unwrap_err().to_string();
            assert!(own.contains(&format!("{bad:?}")), "{own}");
        }
    }

    #[test]
    fn pids_must_be_positive() {
        let msg = err("[limits]\npids = 0");
        assert!(msg.contains("pids = 0"), "{msg}");
        assert!(msg.contains("nonzero"), "{msg}");
        err("[limits]\npids = -1");
        err("[limits]\npids = \"4096\"");
        err("[limits]\npids = 4294967296");
        let cfg = Config::from_toml_str("[limits]\npids = 1").unwrap();
        assert_eq!(cfg.limits.pids, NonZeroU32::new(1));
    }

    #[test]
    fn memory_units_are_binary() {
        for (s, bytes) in [
            ("1K", 1u64 << 10),
            ("1M", 1 << 20),
            ("1G", 1 << 30),
            ("1T", 1 << 40),
            ("512M", 512 << 20),
            ("8G", 8 << 30),
        ] {
            assert_eq!(s.parse::<MemoryLimit>().unwrap().bytes(), bytes, "{s}");
        }
        assert_eq!(
            "16777215T".parse::<MemoryLimit>().unwrap().bytes(),
            16777215u64 << 40
        );
    }

    #[test]
    fn invalid_memory_limits_are_rejected() {
        for bad in [
            "0G",
            "0K",
            "8",
            "8X",
            "8g",
            "8m",
            "8GB",
            "8 G",
            "G",
            "",
            "-8G",
            "+8G",
            "1.5G",
            "99999999999T",
            "16777216T",
            "99999999999999999999999999G",
        ] {
            let msg = err(&format!("[limits]\nmemory = \"{bad}\""));
            assert!(msg.contains("memory limit"), "{bad:?}: {msg}");
            // The value type's own message (not the TOML snippet) names it.
            let own = bad.parse::<MemoryLimit>().unwrap_err().to_string();
            assert!(own.contains(&format!("{bad:?}")), "{bad:?}: {own}");
        }
        let too_large = "99999999999999999999999999G".parse::<MemoryLimit>();
        assert!(too_large.unwrap_err().to_string().contains("too large"));
        let malformed = "8X".parse::<MemoryLimit>().unwrap_err().to_string();
        assert!(malformed.contains("<int>K|M|G|T"), "{malformed}");
        err("[limits]\nmemory = 8");
    }

    #[test]
    fn cpu_limits() {
        assert_eq!("400%".parse::<CpuLimit>().unwrap().percent(), 400);
        assert_eq!("1%".parse::<CpuLimit>().unwrap().percent(), 1);
        for bad in [
            "0%",
            "00%",
            "40",
            "1.5%",
            "%",
            "",
            "-1%",
            "10 %",
            "10%%",
            "4294967296%",
        ] {
            let msg = err(&format!("[limits]\ncpu = \"{bad}\""));
            assert!(msg.contains("cpu limit"), "{bad:?}: {msg}");
            let own = bad.parse::<CpuLimit>().unwrap_err().to_string();
            assert!(own.contains(&format!("{bad:?}")), "{bad:?}: {own}");
        }
        let malformed = "40".parse::<CpuLimit>().unwrap_err().to_string();
        assert!(malformed.contains("<int>%"), "{malformed}");
        let too_large = "99999999999999999999%".parse::<CpuLimit>();
        assert!(too_large.unwrap_err().to_string().contains("too large"));
        err("[limits]\ncpu = 400");
    }

    #[test]
    fn approval_timeouts() {
        let t = |s: &str| {
            Config::from_toml_str(&format!("[approval]\ntimeout = \"{s}\""))
                .unwrap()
                .approval
                .timeout
        };
        assert_eq!(t("off"), ApprovalTimeout::Off);
        assert_eq!(t("30s"), ApprovalTimeout::After(Duration::from_secs(30)));
        assert_eq!(t("5m"), ApprovalTimeout::After(Duration::from_secs(300)));
        assert_eq!(t("1h"), ApprovalTimeout::After(Duration::from_secs(3600)));
    }

    #[test]
    fn invalid_approval_timeouts_are_rejected() {
        for bad in [
            "0s",
            "0m",
            "0h",
            "5",
            "5d",
            "5S",
            "5 m",
            "m",
            "",
            "OFF",
            "Off",
            "1.5h",
            "-5m",
            "99999999999999999999s",
            "18446744073709551615h",
        ] {
            let msg = err(&format!("[approval]\ntimeout = \"{bad}\""));
            assert!(msg.contains("approval timeout"), "{bad:?}: {msg}");
            let own = bad.parse::<ApprovalTimeout>().unwrap_err().to_string();
            assert!(own.contains(&format!("{bad:?}")), "{bad:?}: {own}");
        }
        let malformed = "5".parse::<ApprovalTimeout>().unwrap_err().to_string();
        assert!(malformed.contains("<int>s|m|h"), "{malformed}");
        let too_large = "99999999999999999999s".parse::<ApprovalTimeout>();
        assert!(too_large.unwrap_err().to_string().contains("too large"));
        err("[approval]\ntimeout = 300");
    }

    #[test]
    fn empty_hotkey_is_rejected() {
        let msg = err("[terminal]\nhotkey = \"\"");
        assert!(msg.contains("hotkey"), "{msg}");
        let cfg = Config::from_toml_str("[terminal]\nhotkey = \"ctrl-a\"").unwrap();
        assert_eq!(cfg.terminal.hotkey, "ctrl-a");
    }

    #[test]
    fn unknown_keys_are_rejected() {
        for (src, key) in [
            ("bse = \"none\"", "bse"),
            ("[workspace]\nmoutn = \"/w\"", "moutn"),
            ("[limits]\npid = 4", "pid"),
            ("[approval]\ntimout = \"5m\"", "timout"),
            ("[terminal]\nhotkeys = \"x\"", "hotkeys"),
            ("[unknown]\nx = 1", "unknown"),
            // Not implemented yet, so rejected rather than ignored.
            ("[[provider]]\ntype = \"config\"", "provider"),
        ] {
            let msg = err(src);
            assert!(msg.contains(key), "{src:?}: {msg}");
        }
    }

    #[test]
    fn toml_errors_keep_line_and_column() {
        let msg = err("base = \"default\"\n[approval]\ntimeout = \"0s\"\n");
        assert!(msg.contains("line 3"), "{msg}");
        let msg = err("this is not toml");
        assert!(msg.contains("line 1"), "{msg}");
    }
}
