//! Session-wide top-level configuration settings (DESIGN.md §3.1).
//!
//! Only the settings that are not grants live here: `base`, `[workspace]`,
//! `[limits]`, `[approval]` and `[terminal]`, plus the structure of
//! `[profiles.<name>]` declarations and the syntax of `[[provider]]` entries.
//! Providers are only parsed and validated here, never run or merged.
//!
//! This is security configuration, so every table rejects unknown keys:
//! a typo must fail loudly instead of silently falling back to a default.

mod profile;
mod provider;

pub use profile::{Inherit, ProfileDecl, ProfileName, ProfileRef};
pub use provider::{ProviderEntry, ProviderKind, ProviderName, ScriptSource, VcsTool, VcsView};

#[cfg(test)]
pub(crate) use provider::APPENDIX_A_WITHOUT_VCS;

use std::collections::{BTreeMap, HashMap};
use std::num::{IntErrorKind, NonZeroU32};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use serde::Deserialize;
use thiserror::Error;

use crate::error::ValueError;
use crate::manifest::check_plain_absolute;
use crate::serde_util::MapOnly;

/// Error produced while loading a configuration document.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The document is not valid TOML, or does not match the schema. The
    /// underlying message includes the line and column.
    #[error("invalid configuration: {0}")]
    Toml(#[from] toml::de::Error),
}

/// Layer that declared a provider, ordered from lowest to highest precedence.
///
/// No `Default`: every construction names its layer, so a forgotten origin
/// never gets the highest precedence by accident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProviderOrigin {
    /// Built-in provider supplied by `base = "default"`.
    Builtin,
    /// Provider declared in `<config_dir>/config.toml`.
    Global,
    /// Provider declared in workspace `.stopit.toml`.
    Workspace,
}

/// One parsed configuration document before layering defaults.
///
/// Tracks which top-level fields were explicitly written so a project
/// `.stopit.toml` overrides only the fields it sets while falling back to the
/// user-global `config.toml` and then built-in defaults.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(try_from = "MapOnly<RawConfig>")]
pub struct ConfigLayer {
    /// Explicit `base`, if written.
    pub base: Option<Base>,
    /// Explicit `workspace.mount`, if written.
    pub workspace_mount: Option<WorkspaceMount>,
    /// Explicit `[limits]` values.
    pub limits: Limits,
    /// Explicit `approval.timeout`, if written.
    pub approval_timeout: Option<ApprovalTimeout>,
    /// Explicit `terminal.clipboard_write`, if written.
    pub terminal_clipboard_write: Option<ClipboardWrite>,
    /// User-declared profiles in this file.
    pub profiles: BTreeMap<ProfileName, ProfileDecl>,
    /// `[[provider]]` entries in file order, unique by effective name within
    /// this file.
    pub providers: Vec<ProviderEntry>,
}

/// A `[[provider]]` entry paired with the layer and base directory that
/// declared it.
#[derive(Debug, Clone, PartialEq)]
pub struct LayeredProviderEntry {
    /// Which configuration layer declared this entry.
    pub origin: ProviderOrigin,
    /// Directory of the declaring configuration file, used to resolve relative
    /// `script` provider `source` paths and set their working directory.
    pub base_dir: PathBuf,
    /// Parsed provider entry.
    pub entry: ProviderEntry,
}

/// Result of layering optional global and workspace configuration documents.
#[derive(Debug, Clone, PartialEq)]
pub struct LayeredConfig {
    /// Effective session configuration with defaults filled in.
    pub config: Config,
    /// Effective user providers in merge order with their origin and base
    /// directory.
    pub providers: Vec<LayeredProviderEntry>,
    /// Names of global providers that a workspace provider of the same name
    /// replaced, in global file order.
    pub replaced: Vec<ProviderName>,
}

/// The session-wide top-level settings (DESIGN.md §3.1).
///
/// Every field has the default given in the design, so an empty document is
/// valid.
///
/// Not `Eq`: script providers carry free-form TOML values, which may be
/// floats.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(try_from = "MapOnly<RawConfig>")]
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
    /// `[[provider]]` entries in file order. Effective names are unique.
    pub providers: Vec<ProviderEntry>,
}

/// Deserialization shape of [`ConfigLayer`] and [`Config`]; see [`MapOnly`].
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RawConfig {
    base: Option<Base>,
    workspace: MapOnly<RawWorkspaceSettings>,
    limits: Limits,
    approval: MapOnly<RawApproval>,
    terminal: MapOnly<RawTerminal>,
    profiles: BTreeMap<ProfileName, ProfileDecl>,
    provider: Vec<ProviderEntry>,
}

impl TryFrom<MapOnly<RawConfig>> for ConfigLayer {
    type Error = ValueError;

    fn try_from(MapOnly(raw): MapOnly<RawConfig>) -> Result<Self, ValueError> {
        let mut seen = HashMap::new();
        for (i, p) in raw.provider.iter().enumerate() {
            if let Some(first) = seen.insert(p.name.as_str(), i) {
                return Err(ValueError::new(format!(
                    "duplicate provider name {:?} ([[provider]] entries {} and {}): \
                     provider names must be unique (the default name is the type); \
                     set `name` on each entry",
                    p.name.as_str(),
                    first + 1,
                    i + 1
                )));
            }
        }
        Ok(ConfigLayer {
            base: raw.base,
            workspace_mount: raw.workspace.0.mount,
            limits: raw.limits,
            approval_timeout: raw.approval.0.timeout,
            terminal_clipboard_write: raw.terminal.0.clipboard_write,
            profiles: raw.profiles,
            providers: raw.provider,
        })
    }
}

impl TryFrom<MapOnly<RawConfig>> for Config {
    type Error = ValueError;

    fn try_from(raw: MapOnly<RawConfig>) -> Result<Self, ValueError> {
        Ok(ConfigLayer::try_from(raw)?.into_config())
    }
}

impl ConfigLayer {
    /// Parses a single configuration layer from TOML text.
    pub fn from_toml_str(s: &str) -> Result<ConfigLayer, ConfigError> {
        Ok(toml::from_str(s)?)
    }

    /// Returns true when this document explicitly sets `base = "none"`.
    pub fn sets_base_none(&self) -> bool {
        self.base == Some(Base::None)
    }

    /// Resolves this layer alone against built-in defaults.
    pub fn into_config(self) -> Config {
        Config {
            base: self.base.unwrap_or_default(),
            workspace: WorkspaceSettings {
                mount: self.workspace_mount.unwrap_or_default(),
            },
            limits: self.limits,
            approval: Approval {
                timeout: self.approval_timeout.unwrap_or_default(),
            },
            terminal: Terminal {
                clipboard_write: self.terminal_clipboard_write.unwrap_or_default(),
            },
            profiles: self.profiles,
            providers: self.providers,
        }
    }

    /// Layers optional global configuration under optional project
    /// configuration.
    ///
    /// When `project` explicitly sets `base = "none"`, `global` is ignored
    /// completely. Otherwise `project` fields override `global` fields where
    /// explicitly set, `[profiles.<name>]` declarations in `project` override
    /// matching names in `global`, and `[[provider]]` entries in `project`
    /// replace matching `ProviderName` entries from `global`.
    pub fn layer(
        global: Option<(ConfigLayer, &Path)>,
        project: Option<(ConfigLayer, &Path)>,
    ) -> LayeredConfig {
        if let Some((proj, proj_dir)) = project {
            if proj.sets_base_none() {
                let providers = proj
                    .providers
                    .iter()
                    .cloned()
                    .map(|entry| LayeredProviderEntry {
                        origin: ProviderOrigin::Workspace,
                        base_dir: proj_dir.to_path_buf(),
                        entry,
                    })
                    .collect();
                return LayeredConfig {
                    config: proj.into_config(),
                    providers,
                    replaced: Vec::new(),
                };
            }
            return Self::combine(global, Some((proj, proj_dir)));
        }
        Self::combine(global, None)
    }

    fn combine(
        global: Option<(ConfigLayer, &Path)>,
        project: Option<(ConfigLayer, &Path)>,
    ) -> LayeredConfig {
        let (g_layer, g_dir) = match global {
            Some((layer, dir)) => (layer, Some(dir)),
            None => (ConfigLayer::default(), None),
        };
        let (p_layer, p_dir) = match project {
            Some((layer, dir)) => (layer, Some(dir)),
            None => (ConfigLayer::default(), None),
        };

        let base = p_layer.base.or(g_layer.base).unwrap_or_default();
        let workspace = WorkspaceSettings {
            mount: p_layer
                .workspace_mount
                .or(g_layer.workspace_mount)
                .unwrap_or_default(),
        };
        let limits = Limits {
            pids: p_layer.limits.pids.or(g_layer.limits.pids),
            memory: p_layer.limits.memory.or(g_layer.limits.memory),
            cpu: p_layer.limits.cpu.or(g_layer.limits.cpu),
        };
        let approval = Approval {
            timeout: p_layer
                .approval_timeout
                .or(g_layer.approval_timeout)
                .unwrap_or_default(),
        };
        let terminal = Terminal {
            clipboard_write: p_layer
                .terminal_clipboard_write
                .or(g_layer.terminal_clipboard_write)
                .unwrap_or_default(),
        };

        let mut profiles = g_layer.profiles;
        profiles.extend(p_layer.profiles);

        let project_names: HashMap<&str, ()> = p_layer
            .providers
            .iter()
            .map(|e| (e.name.as_str(), ()))
            .collect();

        let mut layered_providers = Vec::new();
        let mut config_providers = Vec::new();
        let mut replaced = Vec::new();
        if let Some(dir) = g_dir {
            for entry in g_layer.providers {
                if project_names.contains_key(entry.name.as_str()) {
                    replaced.push(entry.name);
                } else {
                    config_providers.push(entry.clone());
                    layered_providers.push(LayeredProviderEntry {
                        origin: ProviderOrigin::Global,
                        base_dir: dir.to_path_buf(),
                        entry,
                    });
                }
            }
        }
        if let Some(dir) = p_dir {
            for entry in p_layer.providers {
                config_providers.push(entry.clone());
                layered_providers.push(LayeredProviderEntry {
                    origin: ProviderOrigin::Workspace,
                    base_dir: dir.to_path_buf(),
                    entry,
                });
            }
        }

        LayeredConfig {
            config: Config {
                base,
                workspace,
                limits,
                approval,
                terminal,
                profiles,
                providers: config_providers,
            },
            providers: layered_providers,
            replaced,
        }
    }
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
#[serde(from = "MapOnly<RawWorkspaceSettings>")]
pub struct WorkspaceSettings {
    /// Where `{workspace}` appears inside the sandbox.
    pub mount: WorkspaceMount,
}

/// Deserialization shape of [`WorkspaceSettings`]; see [`MapOnly`].
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RawWorkspaceSettings {
    mount: Option<WorkspaceMount>,
}

impl From<MapOnly<RawWorkspaceSettings>> for WorkspaceSettings {
    fn from(MapOnly(raw): MapOnly<RawWorkspaceSettings>) -> Self {
        WorkspaceSettings {
            mount: raw.mount.unwrap_or_default(),
        }
    }
}

/// Where the workspace is mounted inside the sandbox.
///
/// Guaranteed to be a plain absolute path, validated like the sandbox `HOME`:
/// not `/`, no NUL bytes, no `~`, placeholders or glob characters, and no
/// empty (so no `//` or trailing `/`), `.` or `..` components. Whether it
/// collides with other sandbox mounts is checked later, when the sandbox is
/// compiled.
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
        check_plain_absolute(s)
            .map_err(|why| ValueError::new(format!("invalid workspace mount {s:?}: {why}")))?;
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
#[serde(from = "MapOnly<RawLimits>")]
pub struct Limits {
    /// Maximum number of processes; must be greater than zero.
    pub pids: Option<NonZeroU32>,
    /// Memory limit, e.g. `"8G"`.
    pub memory: Option<MemoryLimit>,
    /// CPU limit as a percentage of one CPU, e.g. `"400%"`.
    pub cpu: Option<CpuLimit>,
}

/// Deserialization shape of [`Limits`]; see [`MapOnly`].
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RawLimits {
    pids: Option<NonZeroU32>,
    memory: Option<MemoryLimit>,
    cpu: Option<CpuLimit>,
}

impl From<MapOnly<RawLimits>> for Limits {
    fn from(MapOnly(raw): MapOnly<RawLimits>) -> Self {
        Limits {
            pids: raw.pids,
            memory: raw.memory,
            cpu: raw.cpu,
        }
    }
}

/// Splits a leading run of ASCII digits off `s`. `expected` describes the
/// accepted format for the error message when `s` does not start with a
/// number.
fn split_digits<'a>(what: &str, expected: &str, s: &'a str) -> Result<(u64, &'a str), ValueError> {
    let end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (digits, rest) = s.split_at(end);
    let n = digits.parse::<u64>().map_err(|e| match e.kind() {
        IntErrorKind::PosOverflow => {
            ValueError::new(format!("invalid {what} {s:?}: number is too large"))
        }
        _ => ValueError::new(format!("invalid {what} {s:?}: expected {expected}")),
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
                return Err(ValueError::new(format!(
                    "invalid memory limit {s:?}: expected <int>K|M|G|T (uppercase unit)"
                )));
            }
        };
        if n == 0 {
            return Err(ValueError::new(format!(
                "invalid memory limit {s:?}: must be greater than zero"
            )));
        }
        n.checked_mul(1u64 << shift)
            .map(MemoryLimit)
            .ok_or_else(|| ValueError::new(format!("invalid memory limit {s:?}: value overflows")))
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
            return Err(ValueError::new(format!(
                "invalid cpu limit {s:?}: expected <int>%"
            )));
        }
        if n == 0 {
            return Err(ValueError::new(format!(
                "invalid cpu limit {s:?}: must be greater than zero"
            )));
        }
        u32::try_from(n)
            .map(CpuLimit)
            .map_err(|_| ValueError::new(format!("invalid cpu limit {s:?}: value is too large")))
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
#[serde(from = "MapOnly<RawApproval>")]
pub struct Approval {
    /// How long a pending approval waits before being auto-denied.
    pub timeout: ApprovalTimeout,
}

/// Deserialization shape of [`Approval`]; see [`MapOnly`].
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RawApproval {
    timeout: Option<ApprovalTimeout>,
}

impl From<MapOnly<RawApproval>> for Approval {
    fn from(MapOnly(raw): MapOnly<RawApproval>) -> Self {
        Approval {
            timeout: raw.timeout.unwrap_or_default(),
        }
    }
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
                return Err(ValueError::new(format!(
                    "invalid approval timeout {s:?}: expected \"off\" or <int>s|m|h"
                )));
            }
        };
        if n == 0 {
            return Err(ValueError::new(format!(
                "invalid approval timeout {s:?}: must be greater than zero"
            )));
        }
        n.checked_mul(mult)
            .map(|secs| ApprovalTimeout::After(Duration::from_secs(secs)))
            .ok_or_else(|| {
                ValueError::new(format!("invalid approval timeout {s:?}: value overflows"))
            })
    }
}

impl TryFrom<String> for ApprovalTimeout {
    type Error = ValueError;

    fn try_from(s: String) -> Result<Self, ValueError> {
        s.parse()
    }
}

/// `[terminal]` table (DESIGN.md §5).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(from = "MapOnly<RawTerminal>")]
pub struct Terminal {
    /// Policy for OSC 52 clipboard writes (§5.3).
    pub clipboard_write: ClipboardWrite,
}

/// Deserialization shape of [`Terminal`]; see [`MapOnly`].
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RawTerminal {
    clipboard_write: Option<ClipboardWrite>,
}

impl From<MapOnly<RawTerminal>> for Terminal {
    fn from(MapOnly(raw): MapOnly<RawTerminal>) -> Self {
        Terminal {
            clipboard_write: raw.clipboard_write.unwrap_or_default(),
        }
    }
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
            },
            terminal: Terminal {
                clipboard_write: ClipboardWrite::Block,
            },
            profiles: BTreeMap::new(),
            providers: Vec::new(),
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

            [terminal]
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
            },
            terminal: Terminal {
                clipboard_write: ClipboardWrite::Ask,
            },
            profiles: BTreeMap::new(),
            providers: Vec::new(),
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
            [terminal]
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
            "/work/",
            "/a//b",
            "/w*",
            "/w?",
            "/w[x]",
            "/{x}",
            "/{workspace}",
            "~",
            "~/w",
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
        for good in ["/workspace", "/a/b", "/a..b", "/.hidden"] {
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
    fn unknown_keys_are_rejected() {
        for (src, key) in [
            ("bse = \"none\"", "bse"),
            ("[workspace]\nmoutn = \"/w\"", "moutn"),
            ("[limits]\npid = 4", "pid"),
            ("[approval]\ntimout = \"5m\"", "timout"),
            ("[approval]\nmasked_writes = \"deny\"", "masked_writes"),
            ("[terminal]\nhotkey = \"ctrl-]\"", "hotkey"),
            ("[terminal]\nhotkeys = \"x\"", "hotkeys"),
            ("[unknown]\nx = 1", "unknown"),
            ("[[providers]]\ntype = \"config\"", "providers"),
        ] {
            let msg = err(src);
            assert!(msg.contains(key), "{src:?}: {msg}");
        }
    }

    #[test]
    fn arrays_are_rejected_for_every_table() {
        for src in [
            "limits = []",
            "limits = [4096]",
            "workspace = [\"/w\"]",
            "workspace = []",
            "approval = []",
            "approval = [\"5m\"]",
            "terminal = []",
            "terminal = [\"block\"]",
            "profiles = []",
            "profiles = [\"harness\"]",
            "[profiles]\nharness = []",
            "[profiles]\nharness = [\"main\"]",
            "[[limits]]\npids = 1",
            "[[workspace]]\nmount = \"/w\"",
            "[[profiles.harness]]\ninherit = \"none\"",
            "provider = [[\"config\"]]",
        ] {
            let msg = err(src);
            assert!(msg.contains("expected a map"), "{src:?}: {msg}");
        }
    }

    #[test]
    fn toml_errors_keep_line_and_column() {
        let msg = err("base = \"default\"\n[approval]\ntimeout = \"0s\"\n");
        assert!(msg.contains("line 3"), "{msg}");
        let msg = err("this is not toml");
        assert!(msg.contains("line 1"), "{msg}");
        let msg = err("[workspace]\nmount = \"/a//b\"\n");
        assert!(msg.contains("line 2"), "{msg}");
    }

    // --- Layering the workspace configuration over the user-global one ---

    fn layer(src: &str) -> ConfigLayer {
        ConfigLayer::from_toml_str(src).unwrap()
    }

    fn layered(global: Option<&str>, project: Option<&str>) -> LayeredConfig {
        ConfigLayer::layer(
            global.map(|g| (layer(g), Path::new("/cfg"))),
            project.map(|p| (layer(p), Path::new("/w"))),
        )
    }

    const PROVIDER_A: &str = "[[provider]]\ntype = \"config\"\nname = \"a\"\n";

    /// Each provider as `(name, origin, base_dir)`.
    fn origins(l: &LayeredConfig) -> Vec<(String, ProviderOrigin, PathBuf)> {
        l.providers
            .iter()
            .map(|e| (e.entry.name.to_string(), e.origin, e.base_dir.clone()))
            .collect()
    }

    #[test]
    fn a_layer_records_only_what_was_written() {
        assert_eq!(layer(""), ConfigLayer::default());
        assert_eq!(
            layer("[workspace]\n[limits]\n[approval]\n[terminal]\n"),
            ConfigLayer::default()
        );
        let l = layer("[approval]\ntimeout = \"off\"\n[terminal]\nclipboard_write = \"block\"\n");
        // Written defaults count as written, so they override a lower layer.
        assert_eq!(l.approval_timeout, Some(ApprovalTimeout::Off));
        assert_eq!(l.terminal_clipboard_write, Some(ClipboardWrite::Block));
        assert_eq!(l.base, None);
        assert!(layer("base = \"none\"").sets_base_none());
        assert!(!layer("base = \"default\"").sets_base_none());
        assert!(!layer("").sets_base_none());
        assert_eq!(layer("").into_config(), expected_defaults());
    }

    #[test]
    fn project_fields_override_global_fields_field_by_field() {
        let global = "[workspace]\nmount = \"/global\"\n\
                      [limits]\npids = 10\nmemory = \"1G\"\n\
                      [approval]\ntimeout = \"30s\"\n\
                      [terminal]\nclipboard_write = \"allow\"\n";
        // Unset in the project: everything comes from the global layer.
        let l = layered(Some(global), Some(""));
        let want = Config::from_toml_str(global).unwrap();
        assert_eq!(l.config, want);
        // Set in the project, including to the built-in defaults.
        let project = "[workspace]\nmount = \"/workspace\"\n\
                       [limits]\npids = 20\n\
                       [terminal]\nclipboard_write = \"block\"\n";
        let l = layered(Some(global), Some(project));
        assert_eq!(l.config.workspace.mount, "/workspace".parse().unwrap());
        assert_eq!(l.config.limits.pids, std::num::NonZeroU32::new(20));
        assert_eq!(l.config.limits.memory, want.limits.memory);
        assert_eq!(l.config.limits.cpu, None);
        assert_eq!(l.config.approval.timeout, want.approval.timeout);
        assert_eq!(l.config.terminal.clipboard_write, ClipboardWrite::Block);
        // Neither layer sets a field: the built-in default.
        assert_eq!(layered(Some(""), Some("")).config, expected_defaults());
        assert_eq!(layered(None, None).config, expected_defaults());
        // Without a project file, the global layer alone.
        assert_eq!(layered(Some(global), None).config, want);
    }

    #[test]
    fn base_none_in_the_project_ignores_the_global_layer() {
        let global = format!(
            "[limits]\npids = 10\n[profiles.g]\n{PROVIDER_A}[provider.sandbox]\nfs.ro = [\"/usr\"]\n"
        );
        let l = layered(Some(&global), Some("base = \"none\""));
        assert_eq!(l.config.base, Base::None);
        assert_eq!(l.config.limits.pids, None);
        assert!(l.config.profiles.is_empty());
        assert!(l.providers.is_empty() && l.config.providers.is_empty());
        // `base` itself layers like any other field otherwise.
        assert_eq!(
            layered(Some("base = \"none\""), Some("")).config.base,
            Base::None
        );
        assert_eq!(
            layered(Some("base = \"none\""), Some("base = \"default\""))
                .config
                .base,
            Base::Default
        );
        // A global `base = "none"` does not drop the global layer's own
        // providers.
        let l = layered(Some(&format!("base = \"none\"\n{PROVIDER_A}")), None);
        assert_eq!(
            origins(&l),
            [(
                "a".to_owned(),
                ProviderOrigin::Global,
                PathBuf::from("/cfg")
            )]
        );
    }

    #[test]
    fn project_profiles_and_providers_replace_global_ones_by_name() {
        let global = format!(
            "[profiles.shared]\ninherit = \"none\"\n[profiles.g]\n\
             {PROVIDER_A}\
             [[provider]]\ntype = \"config\"\nname = \"g-only\"\n\
             [[provider]]\ntype = \"config\"\n"
        );
        let project = format!(
            "[profiles.shared]\n[profiles.p]\n\
             [[provider]]\ntype = \"config\"\n\
             [[provider]]\ntype = \"config\"\nname = \"p-only\"\n\
             {PROVIDER_A}"
        );
        let l = layered(Some(&global), Some(&project));
        assert_eq!(
            l.config
                .profiles
                .keys()
                .map(|p| p.as_str())
                .collect::<Vec<_>>(),
            ["g", "p", "shared"]
        );
        assert_eq!(
            l.config.profiles[&"shared".parse::<ProfileName>().unwrap()].inherit,
            Inherit::default()
        );
        // The implicit `config` name collides like an explicit one, and the
        // surviving global providers stay first, in file order.
        assert_eq!(
            origins(&l),
            [
                (
                    "g-only".to_owned(),
                    ProviderOrigin::Global,
                    PathBuf::from("/cfg")
                ),
                (
                    "config".to_owned(),
                    ProviderOrigin::Workspace,
                    PathBuf::from("/w")
                ),
                (
                    "p-only".to_owned(),
                    ProviderOrigin::Workspace,
                    PathBuf::from("/w")
                ),
                (
                    "a".to_owned(),
                    ProviderOrigin::Workspace,
                    PathBuf::from("/w")
                ),
            ]
        );
        assert_eq!(
            l.config.providers,
            l.providers
                .iter()
                .map(|e| e.entry.clone())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            l.replaced.iter().map(|n| n.as_str()).collect::<Vec<_>>(),
            ["a", "config"]
        );
        // Nothing is replaced without a project file, or under its
        // `base = "none"`.
        assert!(layered(Some(&global), None).replaced.is_empty());
        assert!(
            layered(
                Some(&global),
                Some(&format!("base = \"none\"\n{PROVIDER_A}"))
            )
            .replaced
            .is_empty()
        );
        // A duplicate within one file is still an error.
        let msg = ConfigLayer::from_toml_str(&format!("{PROVIDER_A}{PROVIDER_A}"))
            .unwrap_err()
            .to_string();
        assert!(msg.contains("duplicate provider name \"a\""), "{msg}");
    }
}
