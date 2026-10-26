//! `[[provider]]` entries (DESIGN.md §3.1, §3.6, §7.3).
//!
//! This module only parses and validates syntax. Providers are not run, their
//! manifests are not merged, and no path is resolved or touched: a script
//! `source` is stored as written, relative to the `.stopit.toml` it came from.
//!
//! The entry type is selected by the required `type` key. Serde's internally
//! tagged enums cannot combine with `deny_unknown_fields` (and the tag is
//! visible to the variants), so the entry is deserialized through a raw struct
//! holding every key of every type as an `Option`, and [`TryFrom`] then
//! validates per type, naming any key that does not belong to it. Keys
//! unknown to every type are rejected by the raw struct itself.

use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::Deserialize;

use super::ProfileRef;
use super::profile::{MAIN, NONE, check_segment};
use crate::error::ValueError;
use crate::manifest::Manifest;
use crate::policy::Decision;
use crate::serde_util::MapOnly;

/// The provider types that exist, as spelled in `type`.
const TYPES: [&str; 3] = ["config", "script", "vcs"];

/// The effective name of a provider: the prefix of its contributed profiles
/// (`vcs.local`) and its label in the startup summary.
///
/// Follows the profile segment rules: non-empty, ASCII lowercase letters,
/// digits, `-` and `_`, starting with a letter. No dots, and `main` and `none`
/// are rejected (they are reserved profile words). Uniqueness across entries
/// is checked by [`Config`](super::Config).
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
        if s == MAIN {
            return Err(bad("`main` is reserved (it is the implicit profile)"));
        }
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

/// How the `vcs` provider presents VCS metadata in the main profile (§7.3).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VcsView {
    /// `.git` / `.jj` exist but are masked.
    #[default]
    Masked,
    /// `.git` / `.jj` are visible read-only.
    Ro,
}

/// A VCS tool the `vcs` provider brokers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VcsTool {
    /// Jujutsu.
    Jj,
    /// Git.
    Git,
}

impl VcsTool {
    /// The lowercase spelling used in configuration.
    pub fn as_str(self) -> &'static str {
        match self {
            VcsTool::Jj => "jj",
            VcsTool::Git => "git",
        }
    }
}

impl fmt::Display for VcsTool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The type-specific part of a provider entry.
///
/// Not `Eq`: a script's free-form `config` may contain floats.
#[derive(Debug, Clone, PartialEq)]
pub enum ProviderKind {
    /// The manifest written inline.
    Config {
        /// Profile the grants apply to; defaults to `main`.
        profile: ProfileRef,
        /// The inline manifest (`[provider.sandbox]`); defaults to empty.
        sandbox: Box<Manifest>,
    },
    /// A host executable that prints a manifest.
    Script {
        /// The executable.
        source: ScriptSource,
        /// Whether `source` is automatically `protected`; defaults to true.
        protect: bool,
        /// Free-form parameters passed to the script (`[provider.config]`).
        config: toml::Table,
    },
    /// The built-in `vcs` provider (§7.3).
    Vcs {
        /// How `.git` / `.jj` appear in the main profile.
        view: VcsView,
        /// Brokered tools: non-empty, no duplicates; defaults to `[jj, git]`.
        tools: Vec<VcsTool>,
        /// Policy for fetch-like commands; defaults to ask.
        fetch: Decision,
        /// Policy for push; defaults to ask.
        push: Decision,
        /// Offer the signing key in `vcs.local` and `vcs.remote`.
        signing: bool,
    },
}

impl ProviderKind {
    /// The `type` spelling of this kind.
    pub fn type_name(&self) -> &'static str {
        match self {
            ProviderKind::Config { .. } => "config",
            ProviderKind::Script { .. } => "script",
            ProviderKind::Vcs { .. } => "vcs",
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
    /// Effective name: the `name` key, or the type when absent.
    pub name: ProviderName,
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
    // config
    profile: Option<ProfileRef>,
    sandbox: Option<Manifest>,
    // script
    source: Option<ScriptSource>,
    protect: Option<bool>,
    config: Option<toml::Table>,
    // vcs
    view: Option<VcsView>,
    tools: Option<Vec<VcsTool>>,
    fetch: Option<Decision>,
    push: Option<Decision>,
    signing: Option<bool>,
}

impl TryFrom<MapOnly<RawProviderEntry>> for ProviderEntry {
    type Error = ValueError;

    fn try_from(MapOnly(raw): MapOnly<RawProviderEntry>) -> Result<Self, ValueError> {
        let Some(ty) = raw.kind.as_deref() else {
            return Err(ValueError::new(format!(
                "provider entry is missing the required key `type` (one of {TYPES:?})"
            )));
        };

        if !TYPES.contains(&ty) {
            return Err(ValueError::new(format!(
                "unknown provider type {ty:?}: expected one of {TYPES:?}"
            )));
        }

        // Keys that are present, with the types that accept them.
        let present: [(&str, bool, &str); 10] = [
            ("profile", raw.profile.is_some(), "config"),
            ("sandbox", raw.sandbox.is_some(), "config"),
            ("source", raw.source.is_some(), "script"),
            ("protect", raw.protect.is_some(), "script"),
            ("config", raw.config.is_some(), "script"),
            ("view", raw.view.is_some(), "vcs"),
            ("tools", raw.tools.is_some(), "vcs"),
            ("fetch", raw.fetch.is_some(), "vcs"),
            ("push", raw.push.is_some(), "vcs"),
            ("signing", raw.signing.is_some(), "vcs"),
        ];
        if let Some((key, _, owner)) = present
            .iter()
            .find(|(_, is_set, owner)| *is_set && *owner != ty)
        {
            return Err(ValueError::new(format!(
                "key {key:?} is not allowed for provider type {ty:?} (it applies to type {owner:?})"
            )));
        }

        let name = match raw.name {
            Some(n) => n,
            None => ty.parse()?,
        };
        let kind = match ty {
            "config" => ProviderKind::Config {
                profile: raw.profile.unwrap_or_else(ProfileRef::main),
                sandbox: Box::new(raw.sandbox.unwrap_or_default()),
            },
            "script" => ProviderKind::Script {
                source: raw.source.ok_or_else(|| {
                    ValueError::new(
                        "provider type \"script\" requires the key `source` (path to the executable)",
                    )
                })?,
                protect: raw.protect.unwrap_or(true),
                config: raw.config.unwrap_or_default(),
            },
            _ => {
                let tools = match raw.tools {
                    None => vec![VcsTool::Jj, VcsTool::Git],
                    Some(tools) => {
                        if tools.is_empty() {
                            return Err(ValueError::new(
                                "invalid vcs tools []: must name at least one of \"jj\", \"git\"",
                            ));
                        }
                        for (i, t) in tools.iter().enumerate() {
                            if tools[..i].contains(t) {
                                return Err(ValueError::new(format!(
                                    "invalid vcs tools: duplicate tool {:?}",
                                    t.as_str()
                                )));
                            }
                        }
                        tools
                    }
                };
                ProviderKind::Vcs {
                    view: raw.view.unwrap_or_default(),
                    tools,
                    fetch: raw.fetch.unwrap_or(Decision::Ask),
                    push: raw.push.unwrap_or(Decision::Ask),
                    signing: raw.signing.unwrap_or(false),
                }
            }
        };
        Ok(ProviderEntry { name, kind })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
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

    fn vcs_defaults() -> ProviderKind {
        ProviderKind::Vcs {
            view: VcsView::Masked,
            tools: vec![VcsTool::Jj, VcsTool::Git],
            fetch: Decision::Ask,
            push: Decision::Ask,
            signing: false,
        }
    }

    #[test]
    fn no_providers_by_default() {
        assert!(providers("").is_empty());
        assert!(providers("provider = []").is_empty());
    }

    #[test]
    fn section_3_1_example() {
        let p = providers(
            r#"
            [[provider]]
            type = "script"
            source = "scripts/agent-env.sh"

            [[provider]]
            type = "config"
            [provider.sandbox]
            fs.ro = ["/etc/ssl/certs"]
            network = { mode = "proxy", allow_domains = ["static.crates.io", "index.crates.io"] }
            "#,
        );
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].name, name("script"));
        assert_eq!(
            p[0].kind,
            ProviderKind::Script {
                source: "scripts/agent-env.sh".parse().unwrap(),
                protect: true,
                config: toml::Table::new(),
            }
        );
        assert_eq!(p[1].name, name("config"));
        let ProviderKind::Config { profile, sandbox } = &p[1].kind else {
            panic!("{:?}", p[1].kind);
        };
        assert_eq!(profile, &ProfileRef::main());
        assert_eq!(sandbox.grants.fs.ro.len(), 1);
        assert_eq!(sandbox.grants.network.mode, Some(NetworkMode::Proxy));
        assert_eq!(sandbox.grants.network.allow_domains.len(), 2);
    }

    #[test]
    fn section_3_6_example() {
        let p = providers(
            r#"
            [[provider]]
            type = "config"
            profile = "main"
            [provider.sandbox]
            fs.ro = ["/etc/ssl/certs"]
            env.pass = ["RUST_*", "CARGO_*"]

            [[provider]]
            type = "script"
            source = "scripts/agent-env.sh"
            protect = true
            [provider.config]
            devshell = "agent"

            [[provider]]
            type = "vcs"
            view = "masked"
            "#,
        );
        assert_eq!(p.len(), 3);
        let ProviderKind::Config { profile, sandbox } = &p[0].kind else {
            panic!("{:?}", p[0].kind);
        };
        assert_eq!(profile.as_str(), "main");
        assert_eq!(sandbox.grants.fs.ro.len(), 1);
        assert_eq!(sandbox.grants.env.pass.len(), 2);

        let mut table = toml::Table::new();
        table.insert("devshell".into(), "agent".into());
        assert_eq!(
            p[1].kind,
            ProviderKind::Script {
                source: "scripts/agent-env.sh".parse().unwrap(),
                protect: true,
                config: table,
            }
        );
        assert_eq!(p[2].kind, vcs_defaults());
    }

    #[test]
    fn section_7_3_example() {
        let e = one(r#"
            [[provider]]
            type    = "vcs"
            view    = "masked"
            tools   = ["jj", "git"]
            fetch   = "ask"
            push    = "ask"
            signing = false
            "#);
        assert_eq!(e.name, name("vcs"));
        assert_eq!(e.kind, vcs_defaults());
    }

    #[test]
    fn appendix_a_providers() {
        let p = providers(
            r#"
            base = "none"

            [[provider]]
            type = "config"
            name = "base"
            profile = "main"
            [provider.sandbox]
            system = { proc = true, dev = "minimal", etc = ["passwd", "group", "hosts", "nsswitch.conf"], home = "/home/user" }
            network = { mode = "loopback" }
            [provider.sandbox.fs]
            rw = ["{workspace}"]
            masked = [
              "{workspace}/**/.env", "{workspace}/**/.env.*", "{workspace}/**/*.pem",
              "{workspace}/**/*.key", "{workspace}/**/.npmrc", "{workspace}/**/.pypirc",
            ]
            mask_sockets = true
            protected = [
              "{workspace}/**/*.nix", "{workspace}/flake.lock", "{workspace}/.envrc",
              "{workspace}/.stopit.toml", "{workspace}/.vscode", "{workspace}/.idea",
              "{workspace}/.github/workflows",
            ]
            ephemeral = ["/tmp", "~"]
            [provider.sandbox.env]
            pass = ["TERM", "LANG", "COLORTERM"]
            deny = ["*_TOKEN", "*_KEY", "*_SECRET", "*_PASSWORD", "AWS_*", "GITHUB_*", "SSH_AUTH_SOCK", "NIX_CONFIG"]

            [[provider]]
            type    = "vcs"
            view    = "masked"
            tools   = ["jj", "git"]
            fetch   = "ask"
            push    = "ask"
            signing = false
            "#,
        );
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].name, name("base"));
        let ProviderKind::Config { profile, sandbox } = &p[0].kind else {
            panic!("{:?}", p[0].kind);
        };
        assert_eq!(profile, &ProfileRef::main());
        // The embedded default base is exactly Appendix A's config provider.
        assert_eq!(**sandbox, crate::provider::default_base_manifest().unwrap());
        let g = &sandbox.grants;
        assert_eq!(g.fs.rw.len(), 1);
        assert_eq!(g.fs.masked.len(), 6);
        assert_eq!(g.fs.protected.len(), 7);
        assert_eq!(g.fs.ephemeral.len(), 2);
        assert_eq!(g.fs.mask_sockets, Some(true));
        assert_eq!(g.system.proc, Some(true));
        assert_eq!(g.system.etc.len(), 4);
        assert_eq!(g.network.mode, Some(NetworkMode::Loopback));
        assert_eq!(g.env.pass.len(), 3);
        assert_eq!(g.env.deny.len(), 8);
        assert_eq!(p[1].name, name("vcs"));
        assert_eq!(p[1].kind, vcs_defaults());
    }

    #[test]
    fn config_defaults() {
        let e = one("[[provider]]\ntype = \"config\"");
        assert_eq!(e.name, name("config"));
        assert_eq!(
            e.kind,
            ProviderKind::Config {
                profile: ProfileRef::main(),
                sandbox: Box::default(),
            }
        );
        assert_eq!(e.kind.type_name(), "config");
    }

    #[test]
    fn config_targets_other_profiles() {
        for target in ["harness", "vcs.local"] {
            let e = one(&format!(
                "[[provider]]\ntype = \"config\"\nprofile = \"{target}\""
            ));
            let ProviderKind::Config { profile, .. } = e.kind else {
                panic!()
            };
            assert_eq!(profile.as_str(), target);
        }
    }

    #[test]
    fn script_defaults() {
        let e = one("[[provider]]\ntype = \"script\"\nsource = \"/usr/bin/env\"");
        assert_eq!(e.name, name("script"));
        let ProviderKind::Script {
            source,
            protect,
            config,
        } = &e.kind
        else {
            panic!("{:?}", e.kind);
        };
        assert_eq!(source.as_path(), Path::new("/usr/bin/env"));
        assert!(*protect);
        assert!(config.is_empty());
        assert_eq!(e.kind.type_name(), "script");
    }

    #[test]
    fn script_options() {
        let e = one(r#"
            [[provider]]
            type = "script"
            source = "../x.sh"
            protect = false
            [provider.config]
            n = 1
            nested = { a = [1, 2.5], b = "c" }
            "#);
        let ProviderKind::Script {
            source,
            protect,
            config,
        } = &e.kind
        else {
            panic!("{:?}", e.kind);
        };
        assert_eq!(source.as_path(), Path::new("../x.sh"));
        assert!(!*protect);
        assert_eq!(config["n"].as_integer(), Some(1));
        assert_eq!(config["nested"]["b"].as_str(), Some("c"));
    }

    #[test]
    fn vcs_defaults_when_bare() {
        let e = one("[[provider]]\ntype = \"vcs\"");
        assert_eq!(e.name, name("vcs"));
        assert_eq!(e.kind, vcs_defaults());
        assert_eq!(e.kind.type_name(), "vcs");
    }

    #[test]
    fn vcs_options() {
        let e = one(r#"
            [[provider]]
            type = "vcs"
            view = "ro"
            tools = ["git"]
            fetch = "allow"
            push = "deny"
            signing = true
            "#);
        assert_eq!(
            e.kind,
            ProviderKind::Vcs {
                view: VcsView::Ro,
                tools: vec![VcsTool::Git],
                fetch: Decision::Allow,
                push: Decision::Deny,
                signing: true,
            }
        );
        // Order is preserved.
        let e = one("[[provider]]\ntype = \"vcs\"\ntools = [\"git\", \"jj\"]");
        let ProviderKind::Vcs { tools, .. } = e.kind else {
            panic!()
        };
        assert_eq!(tools, [VcsTool::Git, VcsTool::Jj]);
    }

    #[test]
    fn explicit_names() {
        let p = providers(
            r#"
            [[provider]]
            type = "config"
            name = "a"
            [[provider]]
            type = "config"
            name = "b-1_x"
            [[provider]]
            type = "config"
            [[provider]]
            type = "vcs"
            name = "git-stuff"
            "#,
        );
        let names: Vec<&str> = p.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["a", "b-1_x", "config", "git-stuff"]);
        assert_eq!(p[3].name.to_string(), "git-stuff");
    }

    #[test]
    fn explicit_name_may_equal_another_types_default() {
        // Names are not tied to types: only effective names must be unique.
        let p = providers(
            "[[provider]]\ntype = \"config\"\nname = \"vcs\"\n[[provider]]\ntype = \"vcs\"\nname = \"v\"",
        );
        assert_eq!(p.len(), 2);
    }

    #[test]
    fn missing_type() {
        for src in [
            "[[provider]]",
            "[[provider]]\nname = \"x\"",
            "[[provider]]\nsource = \"x.sh\"",
        ] {
            let msg = err(src);
            assert!(msg.contains("`type`"), "{src:?}: {msg}");
        }
    }

    #[test]
    fn unknown_type() {
        for bad in ["nix", "Config", "", "vcs "] {
            let msg = err(&format!("[[provider]]\ntype = \"{bad}\""));
            assert!(msg.contains(&format!("{bad:?}")), "{bad:?}: {msg}");
            assert!(msg.contains("unknown provider type"), "{bad:?}: {msg}");
        }
        err("[[provider]]\ntype = 5");
        err("[[provider]]\ntype = [\"vcs\"]");
    }

    #[test]
    fn keys_not_allowed_for_type() {
        for (src, key, ty) in [
            ("type = \"config\"\nsource = \"x\"", "source", "config"),
            ("type = \"config\"\nprotect = true", "protect", "config"),
            ("type = \"config\"\nconfig = {}", "config", "config"),
            ("type = \"config\"\nview = \"ro\"", "view", "config"),
            ("type = \"config\"\ntools = [\"jj\"]", "tools", "config"),
            ("type = \"config\"\nfetch = \"ask\"", "fetch", "config"),
            ("type = \"config\"\npush = \"ask\"", "push", "config"),
            ("type = \"config\"\nsigning = true", "signing", "config"),
            (
                "type = \"script\"\nsource = \"x\"\nsandbox = {}",
                "sandbox",
                "script",
            ),
            (
                "type = \"script\"\nsource = \"x\"\nprofile = \"main\"",
                "profile",
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
            ("type = \"vcs\"\nprofile = \"main\"", "profile", "vcs"),
            ("type = \"vcs\"\nprotect = true", "protect", "vcs"),
            ("type = \"vcs\"\nconfig = {}", "config", "vcs"),
            (
                "type = \"vcs\"\n[provider.config]\nview = \"ro\"",
                "config",
                "vcs",
            ),
        ] {
            let msg = err(&format!("[[provider]]\n{src}"));
            assert!(msg.contains(&format!("{key:?}")), "{src:?}: {msg}");
            assert!(msg.contains(&format!("{ty:?}")), "{src:?}: {msg}");
            assert!(msg.contains("not allowed"), "{src:?}: {msg}");
        }
    }

    #[test]
    fn unknown_keys_are_rejected() {
        for (src, key) in [
            ("type = \"config\"\nprofle = \"main\"", "profle"),
            ("type = \"script\"\nsource = \"x\"\nprotec = true", "protec"),
            ("type = \"vcs\"\ndevshell = \"agent\"", "devshell"),
            ("type = \"vcs\"\nextra = 1", "extra"),
        ] {
            let msg = err(&format!("[[provider]]\n{src}"));
            assert!(msg.contains(key), "{src:?}: {msg}");
        }
        // The manifest's own unknown-key rejection applies inside `sandbox`.
        let msg = err("[[provider]]\ntype = \"config\"\n[provider.sandbox]\nbogus = 1");
        assert!(msg.contains("bogus"), "{msg}");
    }

    #[test]
    fn script_requires_source() {
        let msg = err("[[provider]]\ntype = \"script\"");
        assert!(msg.contains("`source`"), "{msg}");
        let msg = err("[[provider]]\ntype = \"script\"\nprotect = false");
        assert!(msg.contains("`source`"), "{msg}");
    }

    #[test]
    fn invalid_script_sources() {
        let msg = err("[[provider]]\ntype = \"script\"\nsource = \"\"");
        assert!(msg.contains("script source \"\""), "{msg}");
        assert!(msg.contains("empty"), "{msg}");
        let msg = err("[[provider]]\ntype = \"script\"\nsource = \"a\\u0000b\"");
        assert!(msg.contains("NUL"), "{msg}");
        let own = "a\0b".parse::<ScriptSource>().unwrap_err().to_string();
        assert!(
            own.contains("NUL") && own.contains("script source"),
            "{own}"
        );
        let own = "".parse::<ScriptSource>().unwrap_err().to_string();
        assert!(own.contains("\"\""), "{own}");
        err("[[provider]]\ntype = \"script\"\nsource = 5");
        err("[[provider]]\ntype = \"script\"\nsource = [\"a.sh\"]");
    }

    #[test]
    fn script_source_is_not_touched() {
        // Neither existence nor normalization matters here.
        let s: ScriptSource = "does/not/./exist/../x".parse().unwrap();
        assert_eq!(s.as_path(), Path::new("does/not/./exist/../x"));
    }

    #[test]
    fn invalid_names() {
        for bad in ["Vcs", "main", "none", "a.b", "1x", "", "-x", "a b", "a."] {
            let own = bad.parse::<ProviderName>().unwrap_err().to_string();
            assert!(own.contains(&format!("{bad:?}")), "{bad:?}: {own}");
            let msg = err(&format!(
                "[[provider]]\ntype = \"config\"\nname = \"{bad}\""
            ));
            assert!(msg.contains("provider name"), "{bad:?}: {msg}");
            assert!(msg.contains(&format!("{bad:?}")), "{bad:?}: {msg}");
        }
        let main = "main".parse::<ProviderName>().unwrap_err().to_string();
        assert!(main.contains("reserved"), "{main}");
        let dot = "a.b".parse::<ProviderName>().unwrap_err().to_string();
        assert!(dot.contains("`.`"), "{dot}");
        err("[[provider]]\ntype = \"config\"\nname = 5");
    }

    #[test]
    fn duplicate_implicit_names() {
        let msg = err("[[provider]]\ntype = \"config\"\n[[provider]]\ntype = \"config\"");
        assert!(msg.contains("duplicate provider name \"config\""), "{msg}");
        assert!(msg.contains("`name`"), "{msg}");
        let msg = err("[[provider]]\ntype = \"vcs\"\n[[provider]]\ntype = \"vcs\"");
        assert!(msg.contains("\"vcs\""), "{msg}");
        assert!(msg.contains("entries 1 and 2"), "{msg}");
        let msg = err(
            "[[provider]]\ntype = \"vcs\"\n[[provider]]\ntype = \"config\"\n[[provider]]\ntype = \"vcs\"",
        );
        assert!(
            msg.contains("duplicate provider name \"vcs\" ([[provider]] entries 1 and 3)"),
            "{msg}"
        );
    }

    #[test]
    fn reserved_words_as_name_prefixes_are_fine() {
        for good in ["main-x", "none_1", "mainx", "nonesuch"] {
            let e = one(&format!(
                "[[provider]]\ntype = \"config\"\nname = \"{good}\""
            ));
            assert_eq!(e.name.as_str(), good);
        }
    }

    #[test]
    fn unknown_type_is_reported_before_key_checks() {
        let msg = err("[[provider]]\ntype = \"nix\"\nview = \"ro\"");
        assert!(msg.contains("unknown provider type \"nix\""), "{msg}");
        assert!(!msg.contains("not allowed"), "{msg}");
    }

    #[test]
    fn duplicate_explicit_names() {
        let msg = err(
            "[[provider]]\ntype = \"config\"\nname = \"x\"\n[[provider]]\ntype = \"script\"\nsource = \"a\"\nname = \"x\"",
        );
        assert!(msg.contains("duplicate provider name \"x\""), "{msg}");
    }

    #[test]
    fn duplicate_implicit_vs_explicit() {
        let msg =
            err("[[provider]]\ntype = \"vcs\"\n[[provider]]\ntype = \"config\"\nname = \"vcs\"");
        assert!(msg.contains("duplicate provider name \"vcs\""), "{msg}");
        // Non-adjacent duplicates are found too.
        let msg = err(
            "[[provider]]\ntype = \"config\"\nname = \"a\"\n[[provider]]\ntype = \"vcs\"\n[[provider]]\ntype = \"config\"\nname = \"a\"",
        );
        assert!(msg.contains("\"a\""), "{msg}");
    }

    #[test]
    fn distinct_names_for_same_type_are_fine() {
        let p = providers(
            "[[provider]]\ntype = \"config\"\nname = \"a\"\n[[provider]]\ntype = \"config\"\nname = \"b\"\n[[provider]]\ntype = \"config\"",
        );
        assert_eq!(p.len(), 3);
    }

    #[test]
    fn invalid_vcs_tools() {
        let msg = err("[[provider]]\ntype = \"vcs\"\ntools = []");
        assert!(msg.contains("tools []"), "{msg}");
        assert!(msg.contains("at least one"), "{msg}");
        let msg = err("[[provider]]\ntype = \"vcs\"\ntools = [\"jj\", \"jj\"]");
        assert!(msg.contains("duplicate"), "{msg}");
        assert!(msg.contains("duplicate tool \"jj\""), "{msg}");
        assert!(!msg.contains("Jj"), "{msg}");
        assert_eq!(VcsTool::Git.to_string(), "git");
        let msg = err("[[provider]]\ntype = \"vcs\"\ntools = [\"git\", \"jj\", \"git\"]");
        assert!(msg.contains("duplicate"), "{msg}");
        let msg = err("[[provider]]\ntype = \"vcs\"\ntools = [\"hg\"]");
        assert!(msg.contains("hg"), "{msg}");
        err("[[provider]]\ntype = \"vcs\"\ntools = [\"JJ\"]");
        err("[[provider]]\ntype = \"vcs\"\ntools = \"jj\"");
        err("[[provider]]\ntype = \"vcs\"\ntools = [1]");
    }

    #[test]
    fn invalid_vcs_enums() {
        for (key, bad) in [
            ("view", "visible"),
            ("view", "Masked"),
            ("view", "rw"),
            ("fetch", "prompt"),
            ("fetch", "Allow"),
            ("push", "yes"),
            ("push", ""),
        ] {
            let msg = err(&format!("[[provider]]\ntype = \"vcs\"\n{key} = \"{bad}\""));
            assert!(msg.contains("unknown variant"), "{key}={bad:?}: {msg}");
        }
        err("[[provider]]\ntype = \"vcs\"\nsigning = \"yes\"");
        err("[[provider]]\ntype = \"vcs\"\nsigning = 1");
        err("[[provider]]\ntype = \"script\"\nsource = \"x\"\nprotect = \"yes\"");
    }

    #[test]
    fn invalid_config_profile() {
        let msg = err("[[provider]]\ntype = \"config\"\nprofile = \"none\"");
        assert!(msg.contains("profile reference \"none\""), "{msg}");
        let msg = err("[[provider]]\ntype = \"config\"\nprofile = \"Main\"");
        assert!(msg.contains("\"Main\""), "{msg}");
    }

    #[test]
    fn script_config_must_be_a_table() {
        for bad in ["5", "\"x\"", "[1, 2]", "[]", "[[1]]"] {
            err(&format!(
                "[[provider]]\ntype = \"script\"\nsource = \"x\"\nconfig = {bad}"
            ));
        }
        let msg =
            err("[[provider]]\ntype = \"script\"\nsource = \"x\"\n[[provider.config]]\na = 1");
        assert!(msg.contains("map"), "{msg}");
        // An empty inline table is fine.
        let e = one("[[provider]]\ntype = \"script\"\nsource = \"x\"\nconfig = {}");
        let ProviderKind::Script { config, .. } = e.kind else {
            panic!()
        };
        assert!(config.is_empty());
    }

    #[test]
    fn sandbox_must_be_a_table() {
        for bad in ["5", "\"x\"", "[]", "[1]"] {
            err(&format!("[[provider]]\ntype = \"config\"\nsandbox = {bad}"));
        }
        let msg = err("[[provider]]\ntype = \"config\"\n[[provider.sandbox]]\nversion = 1");
        assert!(msg.contains("map"), "{msg}");
    }

    #[test]
    fn array_forms_are_rejected() {
        for src in [
            // `provider` itself must be an array of tables.
            "provider = { type = \"vcs\" }",
            "provider = \"vcs\"",
            "provider = 5",
            "[provider]\ntype = \"vcs\"",
            // Each entry must be a table.
            "provider = [\"vcs\"]",
            "provider = [[\"vcs\"]]",
            "provider = [[]]",
            "provider = [5]",
        ] {
            err(src);
        }
        let msg = err("provider = [[\"vcs\"]]");
        assert!(msg.contains("expected a map"), "{msg}");
        let msg = err("provider = [[\"vcs\"]]\n");
        assert!(msg.contains("map"), "{msg}");
    }

    #[test]
    fn full_document() {
        let cfg = Config::from_toml_str(
            r#"
            base = "default"

            [workspace]
            mount = "/workspace"

            [limits]
            memory = "8G"
            pids = 4096

            [approval]
            timeout = "5m"

            [terminal]
            clipboard_write = "ask"

            [profiles.harness]
            [profiles.child]
            inherit = "vcs.local"

            [[provider]]
            type = "script"
            source = "scripts/agent-env.sh"
            [provider.config]
            devshell = "agent"

            [[provider]]
            type = "config"
            [provider.sandbox]
            fs.ro = ["/etc/ssl/certs"]
            network = { mode = "proxy", allow_domains = ["static.crates.io"] }

            [[provider]]
            type = "config"
            name = "harness-creds"
            profile = "harness"
            [provider.sandbox.env]
            pass = ["ANTHROPIC_API_KEY"]

            [[provider]]
            type = "vcs"
            fetch = "allow"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.profiles.len(), 2);
        assert_eq!(cfg.limits.pids.map(|n| n.get()), Some(4096));
        let names: Vec<&str> = cfg.providers.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["script", "config", "harness-creds", "vcs"]);
        let kinds: Vec<&str> = cfg.providers.iter().map(|p| p.kind.type_name()).collect();
        assert_eq!(kinds, ["script", "config", "config", "vcs"]);
        let ProviderKind::Config { profile, .. } = &cfg.providers[2].kind else {
            panic!()
        };
        assert_eq!(profile.as_str(), "harness");
        let ProviderKind::Vcs { fetch, push, .. } = &cfg.providers[3].kind else {
            panic!()
        };
        assert_eq!((*fetch, *push), (Decision::Allow, Decision::Ask));
    }
}
