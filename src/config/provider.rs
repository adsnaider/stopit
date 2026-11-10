//! `[[provider]]` entries (DESIGN.md §3.1, §3.6, §7.3).
//!
//! This module only parses and validates syntax. Providers are not run, their
//! manifests are not merged, and no path is resolved or touched: a script
//! `source` is stored as written, relative to the `.stopit.toml` it came from.
//!
//! The entry type is selected by the `type` key. Serde's internally tagged
//! enums cannot combine with `deny_unknown_fields` (and the tag is visible to
//! the variants), so the entry is deserialized through a raw struct holding
//! every key of every type as an `Option`, and [`TryFrom`] then validates per
//! type, naming any key that does not belong to it. Keys unknown to every type
//! are rejected by the raw struct itself.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::Deserialize;

use super::ProfileRef;
use super::profile::{NONE, check_segment};
use crate::error::ValueError;
use crate::manifest::{Manifest, ShimName, ShimSpec};
use crate::serde_util::MapOnly;

/// The provider types that exist, as spelled in `type`.
const TYPES: [&str; 4] = ["config", "script", "vcs", "nix"];

/// The explicit name of a provider: the prefix of its contributed profiles
/// (`vcs.local`) and its label in the startup summary.
///
/// Follows the profile segment rules: non-empty, ASCII lowercase letters,
/// digits, `-` and `_`, starting with a letter. No dots, and `none` is
/// rejected (it is the `inherit` keyword). Uniqueness across entries is
/// checked by [`Config`](super::Config).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct ProviderName(String);

impl ProviderName {
    /// The name as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for ProviderName {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        let bad = |why: &str| ValueError::new(format!("invalid provider name {s:?}: {why}"));
        if s == NONE {
            return Err(bad("`none` is reserved (it is the `inherit` keyword)"));
        }
        if s.contains('.') {
            return Err(bad(
                "must not contain `.` (dots separate the provider name from its profiles)",
            ));
        }
        check_segment(s).map_err(bad)?;
        Ok(ProviderName(s.to_owned()))
    }
}

impl TryFrom<String> for ProviderName {
    type Error = ValueError;

    fn try_from(s: String) -> Result<Self, ValueError> {
        s.parse()
    }
}

impl fmt::Display for ProviderName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Path of a script provider's executable.
///
/// Non-empty and free of NUL bytes. Relative paths are relative to the
/// `.stopit.toml` file; resolution happens later, and the filesystem is not
/// consulted here.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct ScriptSource(PathBuf);

impl ScriptSource {
    /// The path as written.
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

impl FromStr for ScriptSource {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        let bad = |why: &str| ValueError::new(format!("invalid script source {s:?}: {why}"));
        if s.is_empty() {
            return Err(bad("must not be empty"));
        }
        if s.contains('\0') {
            return Err(bad("must not contain NUL bytes"));
        }
        Ok(ScriptSource(PathBuf::from(s)))
    }
}

impl TryFrom<String> for ScriptSource {
    type Error = ValueError;

    fn try_from(s: String) -> Result<Self, ValueError> {
        s.parse()
    }
}

/// Shell attribute name selected by a `nix` provider (`shell = "agent"`).
///
/// Non-empty, free of NUL bytes, whitespace, control characters, `#`, `?` and
/// `/`, not starting with `-`, and not equal to `.` or `..`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct NixShell(String);

impl NixShell {
    /// The shell attribute name as written.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for NixShell {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        let bad = |why: &str| ValueError::new(format!("invalid nix shell {s:?}: {why}"));
        if s.is_empty() {
            return Err(bad("must not be empty"));
        }
        if s.contains('\0') {
            return Err(bad("must not contain NUL bytes"));
        }
        if s.starts_with('-') {
            return Err(bad("must not start with `-`"));
        }
        if s == "." || s == ".." {
            return Err(bad("must not be `.` or `..`"));
        }
        if s.contains('#') {
            return Err(bad(
                "must not contain `#` (set `flake` or `file` separately from `shell`)",
            ));
        }
        if s.contains('?') {
            return Err(bad("must not contain `?`"));
        }
        if s.contains('/') {
            return Err(bad("must not contain `/`"));
        }
        if s.chars().any(char::is_whitespace) {
            return Err(bad("must not contain whitespace"));
        }
        if s.chars().any(char::is_control) {
            return Err(bad("must not contain control characters"));
        }
        Ok(NixShell(s.to_owned()))
    }
}

impl TryFrom<String> for NixShell {
    type Error = ValueError;

    fn try_from(s: String) -> Result<Self, ValueError> {
        s.parse()
    }
}

impl fmt::Display for NixShell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// File or flake directory path configured on a `nix` provider (`file` or
/// `flake`).
///
/// Non-empty, free of NUL bytes, `#` and `?`, not starting with `-`, and a
/// local filesystem path rather than a flake URI. Supports `{workspace}`,
/// `{workspace}/…`, `~`, `~/…`, absolute paths, and paths relative to the
/// configuration file's directory.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct NixSource(String);

impl NixSource {
    /// The raw path string as written.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this path starts with `{workspace}`.
    pub fn uses_workspace_placeholder(&self) -> bool {
        self.0 == "{workspace}" || self.0.starts_with("{workspace}/")
    }

    /// Expands `{workspace}`, `~`, or joins a relative path against `base_dir`.
    pub fn expand(&self, base_dir: &Path, workspace: &Path, home: &Path) -> PathBuf {
        if self.0 == "{workspace}" {
            workspace.to_path_buf()
        } else if let Some(rest) = self.0.strip_prefix("{workspace}/") {
            workspace.join(rest)
        } else if self.0 == "~" {
            home.to_path_buf()
        } else if let Some(rest) = self.0.strip_prefix("~/") {
            home.join(rest)
        } else {
            let p = Path::new(&self.0);
            if p.is_absolute() {
                p.to_path_buf()
            } else {
                base_dir.join(p)
            }
        }
    }
}

impl FromStr for NixSource {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        let bad = |why: &str| ValueError::new(format!("invalid nix path {s:?}: {why}"));
        if s.is_empty() {
            return Err(bad("must not be empty"));
        }
        if s.contains('\0') {
            return Err(bad("must not contain NUL bytes"));
        }
        if s.starts_with('-') {
            return Err(bad("must not start with `-`"));
        }
        if s.contains('#') {
            return Err(bad(
                "must not contain `#` (set `shell` separately from `flake` or `file`)",
            ));
        }
        if s.contains('?') {
            return Err(bad("must not contain `?`"));
        }
        if let Some(rest) = s.strip_prefix("{workspace}/") {
            if rest.is_empty() {
                return Err(bad("must not end with a trailing `/` after `{workspace}`"));
            }
            if rest.contains("{workspace}") {
                return Err(bad(
                    "`{workspace}` may only appear once, as `{workspace}` or prefix `{workspace}/...`",
                ));
            }
        } else if s != "{workspace}" && s.contains("{workspace}") {
            return Err(bad(
                "`{workspace}` is only expanded as `{workspace}` or prefix `{workspace}/...`",
            ));
        }
        if s.starts_with('~') && s != "~" && !s.starts_with("~/") {
            return Err(bad(
                "`~` must stand alone or be followed by `/` (`~user` is not supported)",
            ));
        }
        if let Some((scheme, _)) = s.split_once(':')
            && !scheme.is_empty()
            && !scheme.contains('/')
            && !s.starts_with('/')
            && !s.starts_with('~')
            && !s.starts_with("{workspace}")
        {
            return Err(bad(
                "must be a local filesystem path, not a flake URI (write `./...` if a local path contains `:`)",
            ));
        }
        Ok(NixSource(s.to_owned()))
    }
}

impl TryFrom<String> for NixSource {
    type Error = ValueError;

    fn try_from(s: String) -> Result<Self, ValueError> {
        s.parse()
    }
}

impl fmt::Display for NixSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// How the `vcs` provider presents VCS metadata in its target profile (§7.3).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VcsView {
    /// `.git` / `.jj` exist but are masked.
    #[default]
    Masked,
    /// `.git` / `.jj` are visible read-only.
    Ro,
}

/// The type-specific part of a provider entry.
///
/// Not `Eq`: a script's free-form `config` may contain floats.
#[derive(Debug, Clone, PartialEq)]
pub enum ProviderKind {
    /// The manifest written inline.
    Config {
        /// Profile the grants apply to.
        profile: ProfileRef,
        /// The inline manifest (`[provider.sandbox]`); defaults to empty.
        sandbox: Box<Manifest>,
    },
    /// A host executable that prints a manifest.
    Script {
        /// Profile the top-level manifest grants apply to.
        profile: ProfileRef,
        /// The executable.
        source: ScriptSource,
        /// Whether `source` is automatically `protected`; defaults to true.
        protect: bool,
        /// Free-form parameters passed to the script (`[provider.config]`).
        config: toml::Table,
    },
    /// The built-in `vcs` provider (§7.3).
    Vcs {
        /// Profile the metadata view and shims apply to, and that `ro`,
        /// `local`, and `remote` inherit from.
        profile: ProfileRef,
        /// How `.git` / `.jj` appear in `profile`.
        view: VcsView,
        /// Explicit shims (`[provider.shims.<name>]`) attached when a
        /// supported repository is discovered.
        shims: BTreeMap<ShimName, ShimSpec>,
        /// Offer the signing key in `vcs.local` and `vcs.remote`.
        signing: bool,
    },
    /// The built-in `nix` provider (§3.6).
    Nix {
        /// Profile the grants apply to.
        profile: ProfileRef,
        /// Optional devShell or attribute name; defaults to the default shell.
        shell: Option<NixShell>,
        /// Optional classic Nix file (`--file`); mutually exclusive with `flake`.
        file: Option<NixSource>,
        /// Optional flake directory; mutually exclusive with `file`.
        flake: Option<NixSource>,
        /// Whether resolved manifests are cached under stopit's data directory;
        /// defaults to `true`.
        cache: bool,
        /// Whether the devShell's `shellHook` runs inside the sandbox before
        /// the target command; defaults to `true`.
        shell_hook: bool,
    },
}

impl ProviderKind {
    /// The `type` spelling of this kind.
    pub fn type_name(&self) -> &'static str {
        match self {
            ProviderKind::Config { .. } => "config",
            ProviderKind::Script { .. } => "script",
            ProviderKind::Vcs { .. } => "vcs",
            ProviderKind::Nix { .. } => "nix",
        }
    }
}

/// One `[[provider]]` entry (DESIGN.md §3.6).
///
/// Deserializes from a table only. Keys that belong to a different `type`
/// are rejected, naming the key and the type.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(try_from = "MapOnly<RawProviderEntry>")]
pub struct ProviderEntry {
    /// Explicit provider name.
    pub name: ProviderName,
    /// Whether this provider is enabled; defaults to `true`.
    pub enabled: bool,
    /// The type and its options.
    pub kind: ProviderKind,
}

/// Deserialization shape of [`ProviderEntry`]: the union of every type's keys.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProviderEntry {
    #[serde(rename = "type")]
    kind: Option<String>,
    name: Option<ProviderName>,
    enabled: Option<bool>,
    profile: Option<ProfileRef>,
    // config
    sandbox: Option<Manifest>,
    // script
    source: Option<ScriptSource>,
    protect: Option<bool>,
    config: Option<toml::Table>,
    // vcs
    view: Option<VcsView>,
    shims: Option<MapOnly<BTreeMap<ShimName, ShimSpec>>>,
    signing: Option<bool>,
    // nix
    shell: Option<NixShell>,
    file: Option<NixSource>,
    flake: Option<NixSource>,
    cache: Option<bool>,
    shell_hook: Option<bool>,
}

impl TryFrom<MapOnly<RawProviderEntry>> for ProviderEntry {
    type Error = ValueError;

    fn try_from(MapOnly(raw): MapOnly<RawProviderEntry>) -> Result<Self, ValueError> {
        let enabled = raw.enabled.unwrap_or(true);
        let name = raw
            .name
            .ok_or_else(|| ValueError::new("provider entry is missing the required key `name`"))?;
        let ty = match raw.kind.as_deref() {
            Some(ty) => ty,
            None if !enabled => "config",
            None => {
                return Err(ValueError::new(format!(
                    "provider {:?} is missing the required key `type` (one of {TYPES:?})",
                    name.as_str()
                )));
            }
        };

        if !TYPES.contains(&ty) {
            return Err(ValueError::new(format!(
                "unknown provider type {ty:?}: expected one of {TYPES:?}"
            )));
        }

        // Keys that are present, with the types that accept them.
        let present: [(&str, bool, &[&str]); 13] = [
            (
                "profile",
                raw.profile.is_some(),
                &["config", "script", "vcs", "nix"],
            ),
            ("sandbox", raw.sandbox.is_some(), &["config"]),
            ("source", raw.source.is_some(), &["script"]),
            ("protect", raw.protect.is_some(), &["script"]),
            ("config", raw.config.is_some(), &["script"]),
            ("view", raw.view.is_some(), &["vcs"]),
            ("shims", raw.shims.is_some(), &["vcs"]),
            ("signing", raw.signing.is_some(), &["vcs"]),
            ("shell", raw.shell.is_some(), &["nix"]),
            ("file", raw.file.is_some(), &["nix"]),
            ("flake", raw.flake.is_some(), &["nix"]),
            ("cache", raw.cache.is_some(), &["nix"]),
            ("shell_hook", raw.shell_hook.is_some(), &["nix"]),
        ];
        if let Some((key, _, owners)) = present
            .iter()
            .find(|(_, is_set, owners)| *is_set && !owners.contains(&ty))
        {
            let allowed_for = match owners {
                [only] => format!("type {only:?}"),
                many => format!("types {many:?}"),
            };
            return Err(ValueError::new(format!(
                "key {key:?} is not allowed for provider type {ty:?} (it applies to {allowed_for})"
            )));
        }

        let profile = match raw.profile {
            Some(p) => p,
            None if !enabled => "disabled".parse().expect("valid profile ref"),
            None => {
                return Err(ValueError::new(format!(
                    "provider {:?} is missing the required key `profile`",
                    name.as_str()
                )));
            }
        };

        let kind = match ty {
            "config" => ProviderKind::Config {
                profile,
                sandbox: Box::new(raw.sandbox.unwrap_or_default()),
            },
            "script" => ProviderKind::Script {
                profile,
                source: match raw.source {
                    Some(source) => source,
                    None if !enabled => ScriptSource(PathBuf::new()),
                    None => {
                        return Err(ValueError::new(
                            "provider type \"script\" requires the key `source` (path to the executable)",
                        ));
                    }
                },
                protect: raw.protect.unwrap_or(true),
                config: raw.config.unwrap_or_default(),
            },
            "nix" => {
                if raw.file.is_some() && raw.flake.is_some() {
                    return Err(ValueError::new(
                        "provider type \"nix\" cannot set both `file` and `flake`; \
                         set `flake` for a flake directory or `file` for a classic Nix file",
                    ));
                }
                ProviderKind::Nix {
                    profile,
                    shell: raw.shell,
                    file: raw.file,
                    flake: raw.flake,
                    cache: raw.cache.unwrap_or(true),
                    shell_hook: raw.shell_hook.unwrap_or(true),
                }
            }
            _ => ProviderKind::Vcs {
                profile,
                view: raw.view.unwrap_or_default(),
                shims: raw.shims.map(|m| m.0).unwrap_or_default(),
                signing: raw.signing.unwrap_or(false),
            },
        };
        Ok(ProviderEntry {
            name,
            enabled,
            kind,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, DEFAULT_CONFIG_TOML};
    use crate::policy::NetworkMode;

    fn providers(src: &str) -> Vec<ProviderEntry> {
        Config::from_toml_str(src).unwrap().providers
    }

    fn one(src: &str) -> ProviderEntry {
        let mut p = providers(src);
        assert_eq!(p.len(), 1, "{src:?}");
        p.remove(0)
    }

    fn err(src: &str) -> String {
        match Config::from_toml_str(src) {
            Ok(c) => panic!("expected an error for {src:?}, got {c:?}"),
            Err(e) => e.to_string(),
        }
    }

    fn name(s: &str) -> ProviderName {
        s.parse().unwrap()
    }

    fn pref(s: &str) -> ProfileRef {
        s.parse().unwrap()
    }

    #[test]
    fn no_providers_by_default() {
        assert!(providers("").is_empty());
        assert!(providers("provider = []").is_empty());
    }

    #[test]
    fn default_config_providers_parse() {
        let cfg = Config::from_toml_str(DEFAULT_CONFIG_TOML).unwrap();
        assert_eq!(cfg.default_profile, Some(pref("main")));
        assert!(cfg.profiles.contains_key(&"main".parse().unwrap()));
        let names: Vec<&str> = cfg.providers.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["base", "protect-nix", "vcs"]);

        let ProviderKind::Config { profile, sandbox } = &cfg.providers[0].kind else {
            panic!("{:?}", cfg.providers[0].kind);
        };
        assert_eq!(profile, &pref("main"));
        let g = &sandbox.grants;
        assert_eq!(g.fs.rw.len(), 1);
        assert_eq!(g.fs.masked.len(), 13);
        assert_eq!(g.fs.protected.len(), 22);
        assert_eq!(g.fs.ephemeral.len(), 2);
        assert_eq!(g.fs.mask_sockets, Some(true));
        assert_eq!(g.fs.warn_missing, Some(false));
        assert_eq!(g.system.proc, Some(true));
        assert_eq!(g.system.etc.len(), 4);
        assert_eq!(g.network.mode, Some(NetworkMode::Loopback));
        assert_eq!(g.env.pass.len(), 3);
        assert_eq!(g.env.deny.len(), 8);

        let ProviderKind::Config {
            profile: nix_prof,
            sandbox: nix_sb,
        } = &cfg.providers[1].kind
        else {
            panic!("{:?}", cfg.providers[1].kind);
        };
        assert_eq!(nix_prof, &pref("main"));
        assert_eq!(nix_sb.grants.fs.warn_missing, Some(false));
        assert_eq!(nix_sb.grants.fs.protected.len(), 2);

        let ProviderKind::Vcs {
            profile: vcs_prof,
            view,
            shims,
            signing,
        } = &cfg.providers[2].kind
        else {
            panic!("{:?}", cfg.providers[2].kind);
        };
        assert_eq!(vcs_prof, &pref("main"));
        assert_eq!(*view, VcsView::Masked);
        assert!(!*signing);
        assert!(shims.contains_key(&"jj".parse().unwrap()));
        assert!(shims.contains_key(&"git".parse().unwrap()));
    }

    #[test]
    fn all_provider_types_require_explicit_name_type_and_profile_when_enabled() {
        let p = providers(
            r#"
            [[provider]]
            name = "certs"
            type = "config"
            profile = "main"
            [provider.sandbox]
            fs.ro = ["/etc/ssl/certs"]
            env.pass = ["RUST_*", "CARGO_*"]

            [[provider]]
            name = "agent-env"
            type = "script"
            profile = "main"
            source = "scripts/agent-env.sh"
            protect = true
            [provider.config]
            devshell = "agent"

            [[provider]]
            name = "vcs"
            type = "vcs"
            profile = "main"
            view = "ro"
            signing = true
            "#,
        );
        assert_eq!(p.len(), 3);
        assert_eq!(p[0].name, name("certs"));
        assert_eq!(p[1].name, name("agent-env"));
        let ProviderKind::Script {
            profile,
            source,
            protect,
            config,
        } = &p[1].kind
        else {
            panic!("{:?}", p[1].kind);
        };
        assert_eq!(profile, &pref("main"));
        assert_eq!(source.as_path(), Path::new("scripts/agent-env.sh"));
        assert!(*protect);
        assert_eq!(config["devshell"].as_str(), Some("agent"));

        assert_eq!(
            p[2].kind,
            ProviderKind::Vcs {
                profile: pref("main"),
                view: VcsView::Ro,
                shims: BTreeMap::new(),
                signing: true,
            }
        );
    }

    #[test]
    fn disabled_provider_entry_needs_only_name() {
        let e = one("[[provider]]\nname = \"protect-nix\"\nenabled = false");
        assert_eq!(e.name, name("protect-nix"));
        assert!(!e.enabled);

        let e = one("[[provider]]\nname = \"vcs\"\ntype = \"vcs\"\nenabled = false");
        assert_eq!(e.name, name("vcs"));
        assert!(!e.enabled);
        assert_eq!(e.kind.type_name(), "vcs");

        let e = one("[[provider]]\nname = \"corp\"\ntype = \"script\"\nenabled = false");
        assert_eq!(e.name, name("corp"));
        assert!(!e.enabled);
    }

    #[test]
    fn missing_name_type_or_profile_is_rejected() {
        let msg = err("[[provider]]\ntype = \"config\"\nprofile = \"main\"");
        assert!(msg.contains("`name`"), "{msg}");

        for src in [
            "[[provider]]\nname = \"x\"",
            "[[provider]]\nname = \"x\"\nprofile = \"main\"",
        ] {
            let msg = err(src);
            assert!(msg.contains("`type`"), "{src:?}: {msg}");
        }

        for src in [
            "[[provider]]\nname = \"x\"\ntype = \"config\"",
            "[[provider]]\nname = \"x\"\ntype = \"script\"\nsource = \"x.sh\"",
            "[[provider]]\nname = \"x\"\ntype = \"vcs\"",
            "[[provider]]\nname = \"x\"\ntype = \"nix\"",
        ] {
            let msg = err(src);
            assert!(msg.contains("`profile`"), "{src:?}: {msg}");
        }
    }

    #[test]
    fn unknown_type() {
        for bad in ["bazel", "Config", "", "vcs "] {
            let msg = err(&format!(
                "[[provider]]\nname = \"p\"\ntype = \"{bad}\"\nprofile = \"main\""
            ));
            assert!(msg.contains(&format!("{bad:?}")), "{bad:?}: {msg}");
            assert!(msg.contains("unknown provider type"), "{bad:?}: {msg}");
        }
    }

    #[test]
    fn keys_not_allowed_for_type() {
        for (src, key, ty) in [
            ("type = \"config\"\nsource = \"x\"", "source", "config"),
            ("type = \"config\"\nprotect = true", "protect", "config"),
            ("type = \"config\"\nconfig = {}", "config", "config"),
            ("type = \"config\"\nview = \"ro\"", "view", "config"),
            ("type = \"config\"\nshims = {}", "shims", "config"),
            ("type = \"config\"\nsigning = true", "signing", "config"),
            (
                "type = \"script\"\nsource = \"x\"\nsandbox = {}",
                "sandbox",
                "script",
            ),
            (
                "type = \"script\"\nsource = \"x\"\nview = \"ro\"",
                "view",
                "script",
            ),
            (
                "type = \"script\"\nsource = \"x\"\nsigning = false",
                "signing",
                "script",
            ),
            ("type = \"vcs\"\nsource = \"x\"", "source", "vcs"),
            ("type = \"vcs\"\nsandbox = {}", "sandbox", "vcs"),
            ("type = \"vcs\"\nprotect = true", "protect", "vcs"),
            ("type = \"vcs\"\nconfig = {}", "config", "vcs"),
        ] {
            let msg = err(&format!(
                "[[provider]]\nname = \"p\"\nprofile = \"main\"\n{src}"
            ));
            assert!(msg.contains(&format!("{key:?}")), "{src:?}: {msg}");
            assert!(msg.contains(&format!("{ty:?}")), "{src:?}: {msg}");
            assert!(msg.contains("not allowed"), "{src:?}: {msg}");
        }
    }

    #[test]
    fn invalid_names() {
        for bad in ["Vcs", "none", "a.b", "1x", "", "-x", "a b", "a."] {
            let own = bad.parse::<ProviderName>().unwrap_err().to_string();
            assert!(own.contains(&format!("{bad:?}")), "{bad:?}: {own}");
            let msg = err(&format!(
                "[[provider]]\ntype = \"config\"\nname = \"{bad}\"\nprofile = \"main\""
            ));
            assert!(msg.contains("provider name"), "{bad:?}: {msg}");
        }
        // `main` is no longer reserved.
        assert_eq!("main".parse::<ProviderName>().unwrap().as_str(), "main");
    }

    #[test]
    fn nix_defaults_and_validation() {
        let e = one("[[provider]]\nname = \"nix\"\ntype = \"nix\"\nprofile = \"main\"");
        assert_eq!(e.name, name("nix"));
        assert!(e.enabled);
        assert_eq!(
            e.kind,
            ProviderKind::Nix {
                profile: pref("main"),
                shell: None,
                file: None,
                flake: None,
                cache: true,
                shell_hook: true,
            }
        );

        let e_no_hook = one(
            "[[provider]]\nname = \"nix\"\ntype = \"nix\"\nprofile = \"main\"\nshell_hook = false",
        );
        assert!(matches!(
            e_no_hook.kind,
            ProviderKind::Nix {
                shell_hook: false,
                ..
            }
        ));

        let msg = err(
            "[[provider]]\nname = \"nix\"\ntype = \"nix\"\nprofile = \"main\"\n\
             file = \"shell.nix\"\nflake = \".\"",
        );
        assert!(msg.contains("cannot set both `file` and `flake`"), "{msg}");
    }

    #[test]
    fn duplicate_names() {
        let msg = err(
            "[[provider]]\ntype = \"config\"\nname = \"x\"\nprofile = \"main\"\n\
             [[provider]]\ntype = \"script\"\nsource = \"a\"\nname = \"x\"\nprofile = \"main\"",
        );
        assert!(msg.contains("duplicate provider name \"x\""), "{msg}");
    }
}
