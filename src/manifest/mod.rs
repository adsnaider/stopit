//! The manifest: the canonical grant structure produced by every provider
//! (DESIGN.md §3.6).
//!
//! The same schema is written inline as `[provider.sandbox]` in TOML and
//! printed as JSON by script providers. `version`, the grant sections `fs`,
//! `system`, `env`, `network`, `sandbox` and `shims`, and contributed
//! `profiles` exist; any other key is rejected as unknown.
//!
//! Path values are validated *syntactically* here. Expanding `{workspace}`
//! and `~`, expanding globs and mapping to sandbox paths happens later.
//!
//! Scalar settings that merge by "most permissive" or "OR" are `Option`s, so
//! that merging can tell "unset" from an explicit value. Merging itself is
//! not implemented here.

mod env;
mod network;
mod sandbox;
mod shim;
mod system;
#[cfg(test)]
mod test_util;

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use serde::Deserialize;
use serde::de::Error as _;
use serde_json::Value;
use thiserror::Error;

use crate::config::{Inherit, ProfileName};
use crate::error::ValueError;
use crate::policy::PathMode;
use crate::serde_util::MapOnly;

pub use env::{EnvGrants, EnvName, EnvPattern, EnvValue, SearchPathEntry};
pub use network::{Domain, NetworkGrants};
pub use sandbox::{OptInSyscall, SandboxGrants, ShareableNamespace};
pub use shim::{BinaryName, Flag, ShimAction, ShimName, ShimRule, ShimSpec, SubcommandPattern};
pub use system::{DevMode, EtcFile, SandboxHome, SystemGrants};

/// Error produced while loading a manifest document from JSON.
#[derive(Debug, Error)]
pub enum ManifestError {
    /// The document is not valid JSON, or does not match the schema. Syntax
    /// errors include the exact line and column; validation errors name the
    /// offending value and may point to the end of the document.
    #[error("invalid manifest: {0}")]
    Json(#[from] serde_json::Error),
}

/// The grant sections shared by a manifest and each profile it contributes
/// (DESIGN.md §3.6).
///
/// In a document these are direct keys of the enclosing table. `Grants` has
/// no `Deserialize` impl of its own: `#[serde(flatten)]` cannot be combined
/// with `deny_unknown_fields`, so [`Manifest`] and [`ContributedProfile`]
/// deserialize the sections themselves and assemble a `Grants`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Grants {
    /// Filesystem grants.
    pub fs: FsGrants,
    /// System mounts and synthesized files.
    pub system: SystemGrants,
    /// Environment filtering and explicit variables.
    pub env: EnvGrants,
    /// Network access.
    pub network: NetworkGrants,
    /// Hardening opt-outs.
    pub sandbox: SandboxGrants,
    /// Brokered commands, by the name they are installed under.
    pub shims: BTreeMap<ShimName, ShimSpec>,
}

/// A manifest (DESIGN.md §3.6). Every section is optional.
///
/// Deserializes from a table or object only, never from a sequence.
///
/// The grant sections are top-level keys of the document and are held in
/// [`Manifest::grants`]. `profiles` is not part of `Grants`: contributed
/// profiles cannot themselves contribute profiles. Inside a manifest,
/// contributed-profile keys are plain names; the provider-name prefix is
/// applied later, when the profiles are registered.
///
/// The generic `Deserialize` impl applies the inline-TOML rule: `version`
/// may be omitted and defaults to 1. JSON callers must use
/// [`Manifest::from_json_str`], which requires `version`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(from = "MapOnly<RawManifest>")]
pub struct Manifest {
    /// Schema version; only `1` exists.
    pub version: ManifestVersion,
    /// The grants applied to the profile this manifest is attached to.
    pub grants: Grants,
    /// Profiles contributed by this manifest. Keys are plain names; the
    /// provider prefix is added when the profile is registered.
    pub profiles: BTreeMap<ProfileName, ContributedProfile>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawManifest {
    version: Option<ManifestVersion>,
    fs: FsGrants,
    system: SystemGrants,
    env: EnvGrants,
    network: NetworkGrants,
    sandbox: SandboxGrants,
    shims: BTreeMap<ShimName, ShimSpec>,
    profiles: BTreeMap<ProfileName, ContributedProfile>,
}

impl From<MapOnly<RawManifest>> for Manifest {
    fn from(MapOnly(raw): MapOnly<RawManifest>) -> Self {
        Manifest {
            version: raw.version.unwrap_or_default(),
            grants: Grants {
                fs: raw.fs,
                system: raw.system,
                env: raw.env,
                network: raw.network,
                sandbox: raw.sandbox,
                shims: raw.shims,
            },
            profiles: raw.profiles,
        }
    }
}

/// A profile contributed by a manifest (DESIGN.md §3.3, §3.6): where it
/// starts from, plus grants for it.
///
/// The grant sections are direct keys alongside `inherit`. There is no
/// `profiles` or `version` key: contributed profiles do not nest. Whether
/// `inherit` resolves is checked later.
///
/// Deserializes from a table or object only, never from a sequence.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(from = "MapOnly<RawContributedProfile>")]
pub struct ContributedProfile {
    /// Parent profile; defaults to `main`.
    pub inherit: Inherit,
    /// The grants for this profile.
    pub grants: Grants,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawContributedProfile {
    inherit: Inherit,
    fs: FsGrants,
    system: SystemGrants,
    env: EnvGrants,
    network: NetworkGrants,
    sandbox: SandboxGrants,
    shims: BTreeMap<ShimName, ShimSpec>,
}

impl From<MapOnly<RawContributedProfile>> for ContributedProfile {
    fn from(MapOnly(raw): MapOnly<RawContributedProfile>) -> Self {
        ContributedProfile {
            inherit: raw.inherit,
            grants: Grants {
                fs: raw.fs,
                system: raw.system,
                env: raw.env,
                network: raw.network,
                sandbox: raw.sandbox,
                shims: raw.shims,
            },
        }
    }
}

impl Manifest {
    /// Parses a manifest from JSON text, as printed by script providers.
    ///
    /// Unlike inline TOML, where `version` defaults to 1, JSON output must
    /// declare `version` explicitly so that a future version 2 is detectable
    /// rather than silently read as version 1.
    pub fn from_json_str(s: &str) -> Result<Manifest, ManifestError> {
        // Check the version first, leniently: a document of an unsupported
        // version may well contain sections this version does not know, and
        // the version is the more useful thing to report.
        let MapOnly(probe) = serde_json::from_str::<MapOnly<serde_json::Map<String, Value>>>(s)?;
        match probe.get("version") {
            None => {
                return Err(serde_json::Error::custom(
                    "missing field `version`: a JSON manifest must declare its version",
                )
                .into());
            }
            Some(v) => match v.as_u64() {
                Some(n) => {
                    ManifestVersion::try_from(n).map_err(serde_json::Error::custom)?;
                }
                None => {
                    return Err(serde_json::Error::custom(format!(
                        "invalid manifest version {v}: must be the integer 1"
                    ))
                    .into());
                }
            },
        }
        let raw = serde_json::from_str::<MapOnly<RawManifest>>(s)?;
        Ok(raw.into())
    }
}

/// The manifest schema version. Only `1` is accepted; it is the default when
/// the field is omitted from inline TOML (it is required in JSON).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "u64")]
pub struct ManifestVersion(u64);

impl ManifestVersion {
    /// The only supported version.
    pub const V1: ManifestVersion = ManifestVersion(1);

    /// The version number.
    pub fn get(self) -> u64 {
        self.0
    }
}

impl Default for ManifestVersion {
    fn default() -> Self {
        ManifestVersion::V1
    }
}

impl TryFrom<u64> for ManifestVersion {
    type Error = ValueError;

    fn try_from(n: u64) -> Result<Self, ValueError> {
        if n == 1 {
            Ok(ManifestVersion::V1)
        } else {
            Err(ValueError::new(format!(
                "unsupported manifest version {n}: only version 1 is supported"
            )))
        }
    }
}

/// The `fs` section: filesystem grants (DESIGN.md §3.4).
///
/// Deserializes from a table or object only, never from a sequence.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(from = "MapOnly<RawFsGrants>")]
pub struct FsGrants {
    /// Real content, writes go to the host.
    pub rw: Vec<PathPattern>,
    /// Real content, read-only.
    pub ro: Vec<PathPattern>,
    /// Name exists but is empty.
    pub masked: Vec<PathPattern>,
    /// Real content; writes trigger an approval prompt.
    pub protected: Vec<PathPattern>,
    /// Writable scratch space, deleted at session end.
    pub ephemeral: Vec<PathPattern>,
    /// Explicit host-to-sandbox remappings.
    pub bind: Vec<Bind>,
    /// Mask sockets found in RW grants at startup. `None` means unset, so
    /// that merging can tell it apart from an explicit `false`.
    pub mask_sockets: Option<bool>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawFsGrants {
    rw: Vec<PathPattern>,
    ro: Vec<PathPattern>,
    masked: Vec<PathPattern>,
    protected: Vec<PathPattern>,
    ephemeral: Vec<PathPattern>,
    bind: Vec<Bind>,
    mask_sockets: Option<bool>,
}

impl From<MapOnly<RawFsGrants>> for FsGrants {
    fn from(MapOnly(raw): MapOnly<RawFsGrants>) -> Self {
        FsGrants {
            rw: raw.rw,
            ro: raw.ro,
            masked: raw.masked,
            protected: raw.protected,
            ephemeral: raw.ephemeral,
            bind: raw.bind,
            mask_sockets: raw.mask_sockets,
        }
    }
}

/// Characters that make a path component a glob.
const GLOB_CHARS: [char; 4] = ['*', '?', '[', ']'];

fn has_glob(s: &str) -> bool {
    s.contains(GLOB_CHARS)
}

/// Checks the components after the leading anchor: no empty components (so
/// no `//` and no trailing `/`), no `.` or `..`, and no braces.
fn check_components(rest: &str) -> Result<(), &'static str> {
    if rest.contains(['{', '}']) {
        return Err("placeholders are only allowed as the leading `{workspace}`");
    }
    for c in rest.split('/') {
        match c {
            "" => return Err("must not contain empty components or a trailing `/`"),
            "." | ".." => return Err("must not contain `.` or `..` components"),
            _ => {}
        }
    }
    Ok(())
}

/// A syntactically valid path rule.
///
/// One of: an absolute path, `~` or `~/…`, `{workspace}` or `{workspace}/…`.
/// Components after the leading anchor may contain the glob characters `*`,
/// `?`, `[` and `]`; glob syntax itself is not validated here. Below a `/` or
/// `~` anchor the first component must not be a glob (so `/*`, `/**` and
/// `~/*` are rejected, while `/nix/store/*-foo` is fine). This is only a
/// syntactic guard against glob accidents: broad grants such as
/// `rw = ["~"]` are flagged at startup (DESIGN.md §3).
/// The bare root `/` is rejected: granting the whole host root is never
/// intended.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct PathPattern(String);

impl PathPattern {
    /// The validated pattern text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for PathPattern {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        let bad = |why: &str| ValueError::new(format!("invalid path pattern {s:?}: {why}"));
        if s.contains('\0') {
            return Err(bad("must not contain NUL bytes"));
        }
        // Whether the anchor is the host root or HOME, where a glob directly
        // below the anchor would grant (or mask) far too much.
        let mut broad_anchor = true;
        let rest = if s == "~" || s == "{workspace}" {
            return Ok(PathPattern(s.to_owned()));
        } else if let Some(rest) = s.strip_prefix("~/") {
            rest
        } else if let Some(rest) = s.strip_prefix("{workspace}/") {
            broad_anchor = false;
            rest
        } else if let Some(rest) = s.strip_prefix('/') {
            rest
        } else if s.starts_with('{') {
            return Err(bad(
                "`{workspace}` is the only placeholder, and only as the leading component",
            ));
        } else {
            return Err(bad(
                "must be an absolute path, `~`, `~/…`, `{workspace}` or `{workspace}/…`",
            ));
        };
        check_components(rest).map_err(bad)?;
        if broad_anchor && has_glob(rest.split('/').next().unwrap_or_default()) {
            return Err(bad(
                "the first component below `/` or `~` must not be a glob",
            ));
        }
        Ok(PathPattern(s.to_owned()))
    }
}

impl TryFrom<String> for PathPattern {
    type Error = ValueError;

    fn try_from(s: String) -> Result<Self, ValueError> {
        s.parse()
    }
}

impl fmt::Display for PathPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A path on the sandbox side of a bind: an absolute path, or `~` / `~/…`
/// (the sandbox `HOME`). No globs and no placeholders.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct SandboxPath(String);

impl SandboxPath {
    /// The validated path text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for SandboxPath {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        let bad = |why: &str| ValueError::new(format!("invalid sandbox path {s:?}: {why}"));
        if s.contains('\0') {
            return Err(bad("must not contain NUL bytes"));
        }
        if s == "~" {
            return Ok(SandboxPath(s.to_owned()));
        }
        let Some(rest) = s.strip_prefix("~/").or_else(|| s.strip_prefix('/')) else {
            return Err(bad("must be an absolute path, `~` or `~/…`"));
        };
        if s.contains(['{', '}']) {
            return Err(bad("must not contain placeholders"));
        }
        if has_glob(s) {
            return Err(bad("must not contain glob characters"));
        }
        check_components(rest).map_err(bad)?;
        Ok(SandboxPath(s.to_owned()))
    }
}

impl TryFrom<String> for SandboxPath {
    type Error = ValueError;

    fn try_from(s: String) -> Result<Self, ValueError> {
        s.parse()
    }
}

impl fmt::Display for SandboxPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Checks an absolute sandbox-side path that is used verbatim: no `~`, no
/// placeholders, no globs, no empty or `.`/`..` components, and not the root.
/// Shared by [`SandboxHome`] and [`SearchPathEntry`].
fn check_plain_absolute(s: &str) -> Result<(), &'static str> {
    if s.contains('\0') {
        return Err("must not contain NUL bytes");
    }
    let Some(rest) = s.strip_prefix('/') else {
        return Err("must be an absolute path (`~` is not allowed here)");
    };
    if s.contains(['{', '}']) {
        return Err("must not contain placeholders");
    }
    if has_glob(s) {
        return Err("must not contain glob characters");
    }
    if rest.is_empty() {
        return Err("must not be the root `/`");
    }
    check_components(rest)
}

/// How a bind is presented. `masked` and `ephemeral` are not bind modes: a
/// masked or ephemeral path has no host content to map.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BindMode {
    /// Read-only.
    Ro,
    /// Writes go to the host.
    Rw,
    /// Writes trigger an approval prompt.
    Protected,
}

impl BindMode {
    /// The lowercase spelling used in configuration.
    pub fn as_str(self) -> &'static str {
        match self {
            BindMode::Ro => "ro",
            BindMode::Rw => "rw",
            BindMode::Protected => "protected",
        }
    }
}

impl fmt::Display for BindMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<BindMode> for PathMode {
    fn from(mode: BindMode) -> PathMode {
        match mode {
            BindMode::Ro => PathMode::Ro,
            BindMode::Rw => PathMode::Rw,
            BindMode::Protected => PathMode::Protected,
        }
    }
}

/// An explicit remapping of exactly one host path to a sandbox path.
///
/// Deserializes from a table or object only, never from a sequence.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "MapOnly<RawBind>")]
pub struct Bind {
    /// The host path. Must not contain glob characters.
    pub host: PathPattern,
    /// Where it appears in the sandbox.
    pub sandbox: SandboxPath,
    /// How it is presented.
    pub mode: BindMode,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBind {
    host: PathPattern,
    sandbox: SandboxPath,
    mode: BindMode,
}

impl TryFrom<MapOnly<RawBind>> for Bind {
    type Error = ValueError;

    fn try_from(MapOnly(raw): MapOnly<RawBind>) -> Result<Self, ValueError> {
        if has_glob(raw.host.as_str()) {
            return Err(ValueError::new(format!(
                "invalid bind host {:?}: a bind maps exactly one path, so glob characters are not allowed",
                raw.host.as_str()
            )));
        }
        Ok(Bind {
            host: raw.host,
            sandbox: raw.sandbox,
            mode: raw.mode,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::test_util::*;
    use super::*;

    fn pp(s: &str) -> PathPattern {
        s.parse().unwrap()
    }

    fn pps(v: &[&str]) -> Vec<PathPattern> {
        v.iter().map(|s| pp(s)).collect()
    }

    fn default_manifest() -> Manifest {
        Manifest {
            version: ManifestVersion::V1,
            grants: Grants::default(),
            profiles: BTreeMap::new(),
        }
    }

    #[test]
    fn empty_documents_are_default() {
        let m = toml_ok("");
        assert_eq!(m, default_manifest());
        assert_eq!(m.version.get(), 1);
        assert_eq!(m.grants.fs, FsGrants::default());
        assert_eq!(m.grants.fs.mask_sockets, None);
        assert_eq!(jv_ok(""), default_manifest());
        assert_eq!(Manifest::default(), default_manifest());
        assert_eq!(toml_ok("[fs]"), default_manifest());
        assert_eq!(jv_ok(r#""fs": {}"#), default_manifest());
    }

    #[test]
    fn explicit_version_one() {
        assert_eq!(toml_ok("version = 1"), default_manifest());
        assert_eq!(jv_ok(""), default_manifest());
    }

    #[test]
    fn version_is_required_in_json_but_not_in_toml() {
        for src in ["{}", r#"{"fs": {}}"#, r#"{"fs": {"rw": ["/a"]}}"#] {
            let msg = json_err(src);
            assert!(msg.contains("missing field `version`"), "{src}: {msg}");
        }
        // Inline TOML defaults to version 1.
        assert_eq!(toml_ok("[fs]\nrw = [\"/a\"]").version, ManifestVersion::V1);
    }

    #[test]
    fn other_versions_are_rejected() {
        for n in ["0", "2", "18446744073709551615"] {
            let msg = toml_err(&format!("version = {n}"));
            assert!(msg.contains(&format!("manifest version {n}")), "{msg}");
            let msg = json_err(&format!(r#"{{"version": {n}}}"#));
            assert!(msg.contains(&format!("manifest version {n}")), "{msg}");
        }
        toml_err("version = -1");
        toml_err("version = \"1\"");
        toml_err("version = 1.0");
        json_err(r#"{"version": "1"}"#);
        json_err(r#"{"version": 1.5}"#);
        let msg = json_err(r#"{"version": null}"#);
        assert!(msg.contains("invalid manifest version null"), "{msg}");
        assert!(!msg.contains("missing field"), "{msg}");
        let msg = json_err(r#"{"version": "1"}"#);
        assert!(msg.contains("invalid manifest version \"1\""), "{msg}");
        let msg = json_err(r#"{"version": -1}"#);
        assert!(msg.contains("invalid manifest version -1"), "{msg}");
    }

    #[test]
    fn unsupported_version_is_reported_before_unknown_sections() {
        let src = r#"{"shims": {"x": 1}, "fs2": [], "version": 2}"#;
        let msg = json_err(src);
        assert!(msg.contains("unsupported manifest version 2"), "{msg}");
        assert!(!msg.contains("unknown field"), "{msg}");
        // With a supported version the unknown section is the error.
        let msg = json_err(r#"{"limits": {}, "version": 1}"#);
        assert!(msg.contains("unknown field `limits`"), "{msg}");
        // A document that is not an object is still rejected up front.
        let msg = json_err("[2]");
        assert!(msg.contains("expected a map"), "{msg}");
    }

    #[test]
    fn sequences_are_rejected_everywhere() {
        // Serde-derived structs would accept these positionally.
        for src in [
            "[]",
            "[1]",
            "[1, {}]",
            r#"{"version": 1, "fs": []}"#,
            r#"{"version": 1, "fs": [["/a"]]}"#,
            r#"{"version": 1, "fs": {"bind": [["/a", "/a", "ro"]]}}"#,
            r#"{"version": 1, "fs": {"bind": [[]]}}"#,
        ] {
            let msg = json_err(src);
            assert!(msg.contains("expected a map"), "{src}: {msg}");
        }
        for src in [
            "fs = []",
            "fs = [[\"/a\"]]",
            "fs.bind = [[\"/a\", \"/a\", \"ro\"]]",
            "fs.bind = [[]]",
        ] {
            let msg = toml_err(src);
            assert!(msg.contains("expected a map"), "{src}: {msg}");
        }
        // The top level cannot be a sequence in TOML syntax, but `Manifest`
        // itself must still refuse one from any other format.
        let err = serde_json::from_str::<Manifest>("[1]")
            .unwrap_err()
            .to_string();
        assert!(err.contains("expected a map"), "{err}");
        let err = serde_json::from_str::<Manifest>("[]")
            .unwrap_err()
            .to_string();
        assert!(err.contains("expected a map"), "{err}");
    }

    #[test]
    fn mask_sockets_is_tri_state() {
        assert_eq!(toml_ok("").grants.fs.mask_sockets, None);
        assert_eq!(jv_ok("").grants.fs.mask_sockets, None);
        assert_eq!(jv_ok(r#""fs": {}"#).grants.fs.mask_sockets, None);
        assert_eq!(
            toml_ok("fs.mask_sockets = true").grants.fs.mask_sockets,
            Some(true)
        );
        assert_eq!(
            toml_ok("fs.mask_sockets = false").grants.fs.mask_sockets,
            Some(false)
        );
        assert_eq!(
            jv_ok(r#""fs": {"mask_sockets": true}"#)
                .grants
                .fs
                .mask_sockets,
            Some(true)
        );
        assert_eq!(
            jv_ok(r#""fs": {"mask_sockets": false}"#)
                .grants
                .fs
                .mask_sockets,
            Some(false)
        );
        toml_err("fs.mask_sockets = \"yes\"");
        jv_err(r#""fs": {"mask_sockets": 1}"#);
    }

    const APPENDIX_FS_TOML: &str = r#"
        [fs]
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
    "#;

    #[test]
    fn appendix_a_fs_table_parses() {
        let m = toml_ok(APPENDIX_FS_TOML);
        assert_eq!(
            m.grants.fs,
            FsGrants {
                rw: pps(&["{workspace}"]),
                ro: vec![],
                masked: pps(&[
                    "{workspace}/**/.env",
                    "{workspace}/**/.env.*",
                    "{workspace}/**/*.pem",
                    "{workspace}/**/*.key",
                    "{workspace}/**/.npmrc",
                    "{workspace}/**/.pypirc",
                ]),
                protected: pps(&[
                    "{workspace}/**/*.nix",
                    "{workspace}/flake.lock",
                    "{workspace}/.envrc",
                    "{workspace}/.stopit.toml",
                    "{workspace}/.vscode",
                    "{workspace}/.idea",
                    "{workspace}/.github/workflows",
                ]),
                ephemeral: pps(&["/tmp", "~"]),
                bind: vec![],
                mask_sockets: Some(true),
            }
        );
        assert_eq!(m.version, ManifestVersion::V1);
    }

    fn section_3_6_expected() -> Manifest {
        Manifest {
            version: ManifestVersion::V1,
            grants: Grants {
                fs: FsGrants {
                    rw: pps(&["{workspace}"]),
                    ro: vec![],
                    masked: vec![],
                    protected: vec![],
                    ephemeral: pps(&["/tmp", "~"]),
                    bind: vec![Bind {
                        host: pp("/etc/ssl/certs"),
                        sandbox: "/etc/ssl/certs".parse().unwrap(),
                        mode: BindMode::Ro,
                    }],
                    mask_sockets: Some(true),
                },
                ..Grants::default()
            },
            profiles: BTreeMap::new(),
        }
    }

    #[test]
    fn section_3_6_example_parses_identically_from_toml_and_json() {
        let json = r#"{
            "version": 1,
            "fs": {
                "rw": ["{workspace}"], "ro": [], "masked": [], "protected": [],
                "ephemeral": ["/tmp", "~"],
                "bind": [{ "host": "/etc/ssl/certs", "sandbox": "/etc/ssl/certs", "mode": "ro" }],
                "mask_sockets": true
            }
        }"#;
        let toml = r#"
            version = 1
            [fs]
            rw = ["{workspace}"]
            ro = []
            masked = []
            protected = []
            ephemeral = ["/tmp", "~"]
            mask_sockets = true
            bind = [{ host = "/etc/ssl/certs", sandbox = "/etc/ssl/certs", mode = "ro" }]
        "#;
        let from_json = Manifest::from_json_str(json).unwrap();
        assert_eq!(from_json, section_3_6_expected());
        assert_eq!(toml_ok(toml), from_json);
    }

    #[test]
    fn appendix_a_fs_as_json_matches_toml() {
        let json = r#"{"version": 1, "fs": {
            "rw": ["{workspace}"],
            "masked": ["{workspace}/**/.env", "{workspace}/**/.env.*", "{workspace}/**/*.pem",
                       "{workspace}/**/*.key", "{workspace}/**/.npmrc", "{workspace}/**/.pypirc"],
            "mask_sockets": true,
            "protected": ["{workspace}/**/*.nix", "{workspace}/flake.lock", "{workspace}/.envrc",
                          "{workspace}/.stopit.toml", "{workspace}/.vscode", "{workspace}/.idea",
                          "{workspace}/.github/workflows"],
            "ephemeral": ["/tmp", "~"]
        }}"#;
        assert_eq!(
            Manifest::from_json_str(json).unwrap(),
            toml_ok(APPENDIX_FS_TOML)
        );
    }

    #[test]
    fn valid_patterns() {
        for good in [
            "/etc/ssl/certs",
            "~",
            "~/.claude",
            "{workspace}",
            "{workspace}/**/*.nix",
            "{workspace}/.env.*",
            "/nix/store/abc-foo",
            "/a/b[0-9]/c?",
            "/a..b",
            "/.hidden",
            "~/.config/jj/repos/abc123",
            "/nix/store/*-foo",
            "/nix/store/*-foo/bin",
            "~/.cache/**",
            "~/.config/*/settings",
            "{workspace}/*",
            "{workspace}/**",
            "{workspace}/.git/modules/*/hooks",
        ] {
            let p = good
                .parse::<PathPattern>()
                .unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(p.as_str(), good);
            assert_eq!(p.to_string(), good);
            assert_eq!(PathPattern::try_from(good.to_owned()).unwrap(), p);
        }
    }

    #[test]
    fn invalid_patterns() {
        for bad in [
            "",
            "relative/path",
            "./x",
            "~user/x",
            "~x",
            "{repo}/.git",
            "{home}",
            "{workspace",
            "{workspace}x",
            "{workspace}/{workspace}",
            "/a/{workspace}/b",
            "/a/{repo}",
            "~/{workspace}",
            "/a/b}",
            "/a/../b",
            "/a/./b",
            "/a/..",
            "/a/.",
            "~/..",
            "{workspace}/../x",
            "/a//b",
            "{workspace}//x",
            "~//x",
            "//",
            "/a/",
            "~/",
            "{workspace}/",
            "/",
            "/a\0b",
            "\0",
            // A glob directly below `/` or `~` is far too broad.
            "/*",
            "/**",
            "/*/x",
            "/**/x",
            "/?",
            "/[ab]/x",
            "/*-foo",
            "~/*",
            "~/**",
            "~/*/x",
            "~/.[a]",
        ] {
            let msg = bad.parse::<PathPattern>().unwrap_err().to_string();
            assert!(msg.contains("path pattern"), "{bad:?}: {msg}");
            assert!(msg.contains(&format!("{bad:?}")), "{bad:?}: {msg}");
        }
        let msg = "/*/x".parse::<PathPattern>().unwrap_err().to_string();
        assert!(msg.contains("first component"), "{msg}");
        assert!(
            "a\0b"
                .parse::<PathPattern>()
                .unwrap_err()
                .to_string()
                .contains("NUL")
        );
    }

    #[test]
    fn invalid_patterns_are_rejected_in_documents() {
        let msg = toml_err("[fs]\nrw = [\"relative\"]");
        assert!(msg.contains("\"relative\""), "{msg}");
        let msg = jv_err(r#""fs": {"ro": ["{repo}/.git"]}"#);
        assert!(msg.contains("{repo}/.git"), "{msg}");
        let msg = jv_err(r#""fs": {"masked": ["/a\u0000b"]}"#);
        assert!(msg.contains("NUL"), "{msg}");
        let msg = jv_err(r#""fs": {"rw": ["/*"]}"#);
        assert!(msg.contains("first component"), "{msg}");
        toml_err("[fs]\nrw = \"/a\"");
        toml_err("[fs]\nrw = [5]");
        jv_err(r#""fs": {"rw": "/a"}"#);
    }

    #[test]
    fn valid_bind() {
        let m = toml_ok(
            r#"
            [[fs.bind]]
            host = "~/.cache/tool"
            sandbox = "~/.cache/tool"
            mode = "rw"
            [[fs.bind]]
            host = "{workspace}/vendor"
            sandbox = "/opt/vendor"
            mode = "protected"
            "#,
        );
        assert_eq!(
            m.grants.fs.bind,
            vec![
                Bind {
                    host: pp("~/.cache/tool"),
                    sandbox: "~/.cache/tool".parse().unwrap(),
                    mode: BindMode::Rw,
                },
                Bind {
                    host: pp("{workspace}/vendor"),
                    sandbox: "/opt/vendor".parse().unwrap(),
                    mode: BindMode::Protected,
                },
            ]
        );
        let m = jv_ok(r#""fs": {"bind": [{"host": "/a", "sandbox": "~", "mode": "ro"}]}"#);
        assert_eq!(m.grants.fs.bind[0].sandbox.as_str(), "~");
        assert_eq!(m.grants.fs.bind[0].mode, BindMode::Ro);
    }

    fn bind_json(host: &str, sandbox: &str, mode: &str) -> String {
        jv(&format!(
            r#""fs": {{"bind": [{{"host": "{host}", "sandbox": "{sandbox}", "mode": "{mode}"}}]}}"#
        ))
    }

    #[test]
    fn bind_mode_enum() {
        for (s, b, p) in [
            ("ro", BindMode::Ro, PathMode::Ro),
            ("rw", BindMode::Rw, PathMode::Rw),
            ("protected", BindMode::Protected, PathMode::Protected),
        ] {
            let m = Manifest::from_json_str(&bind_json("/a", "/a", s)).unwrap();
            assert_eq!(m.grants.fs.bind[0].mode, b);
            assert_eq!(b.to_string(), s);
            assert_eq!(b.as_str(), s);
            assert_eq!(PathMode::from(b), p);
        }
        // Masked and ephemeral paths have no host content to bind.
        for s in ["masked", "ephemeral"] {
            let msg = json_err(&bind_json("/a", "/a", s));
            assert!(msg.contains(s), "{s}: {msg}");
            assert!(msg.contains("ro"), "{s}: {msg}");
            let src = format!("[[fs.bind]]\nhost = \"/a\"\nsandbox = \"/a\"\nmode = \"{s}\"");
            toml_err(&src);
        }
    }

    #[test]
    fn bind_host_must_not_be_a_glob() {
        for host in ["/a/*", "/a/?", "/a/[x]", "{workspace}/**/x", "~/x/a]"] {
            let msg = json_err(&bind_json(host, "/x", "ro"));
            assert!(msg.contains("bind host"), "{host:?}: {msg}");
            assert!(msg.contains(host), "{host:?}: {msg}");
        }
        // A host that is not even a valid pattern is still reported.
        let msg = json_err(&bind_json("rel", "/x", "ro"));
        assert!(
            msg.contains("\\\"rel\\\"") || msg.contains("\"rel\""),
            "{msg}"
        );
    }

    #[test]
    fn bind_sandbox_path_validation() {
        for good in ["/a", "~", "~/a/b", "/a..b"] {
            assert_eq!(good.parse::<SandboxPath>().unwrap().as_str(), good);
        }
        for bad in [
            "rel",
            "./a",
            "~user",
            "/a/*",
            "/a/?",
            "/a/[x]",
            "{workspace}",
            "{workspace}/x",
            "/a/{workspace}",
            "/",
            "/a/",
            "/a//b",
            "/a/../b",
            "/a/./b",
            "~/",
            "/a\0b",
            "",
        ] {
            let msg = bad.parse::<SandboxPath>().unwrap_err().to_string();
            assert!(msg.contains("sandbox path"), "{bad:?}: {msg}");
            assert!(msg.contains(&format!("{bad:?}")), "{bad:?}: {msg}");
            if !bad.is_empty() && !bad.contains('\0') {
                json_err(&bind_json(
                    "/h",
                    &bad.replace('\\', "\\\\").replace('"', "\\\""),
                    "ro",
                ));
            }
        }
        let msg =
            toml_err("[[fs.bind]]\nhost = \"/a\"\nsandbox = \"{workspace}/x\"\nmode = \"ro\"");
        assert!(msg.contains("{workspace}/x"), "{msg}");
    }

    #[test]
    fn bind_mode_and_fields() {
        json_err(&bind_json("/a", "/a", "cow"));
        json_err(&bind_json("/a", "/a", "RO"));
        // Missing fields.
        for src in [
            r#""fs": {"bind": [{"sandbox": "/a", "mode": "ro"}]}"#,
            r#""fs": {"bind": [{"host": "/a", "mode": "ro"}]}"#,
            r#""fs": {"bind": [{"host": "/a", "sandbox": "/a"}]}"#,
            r#""fs": {"bind": [{}]}"#,
        ] {
            let msg = jv_err(src);
            assert!(msg.contains("missing field"), "{src}: {msg}");
        }
        let msg = toml_err("[[fs.bind]]\nhost = \"/a\"\nsandbox = \"/a\"");
        assert!(msg.contains("mode"), "{msg}");
    }

    #[test]
    fn unknown_keys_are_rejected() {
        for (src, key) in [
            ("verson = 1", "verson"),
            ("[limits]", "limits"),
            ("[fs]\nrww = []", "rww"),
            ("[fs]\nmask_socket = true", "mask_socket"),
            (
                "[[fs.bind]]\nhost = \"/a\"\nsandbox = \"/a\"\nmode = \"ro\"\nextra = 1",
                "extra",
            ),
        ] {
            let msg = toml_err(src);
            assert!(msg.contains(key), "{src:?}: {msg}");
        }
        for (src, key) in [
            (r#""verson": 1"#, "verson"),
            (r#""limits": {}"#, "limits"),
            (r#""fs": {"rww": []}"#, "rww"),
            (r#""fs": {"mask_socket": true}"#, "mask_socket"),
            (
                r#""fs": {"bind": [{"host": "/a", "sandbox": "/a", "mode": "ro", "extra": 1}]}"#,
                "extra",
            ),
        ] {
            let msg = jv_err(src);
            assert!(msg.contains(key), "{src}: {msg}");
        }
    }

    fn pname(s: &str) -> ProfileName {
        s.parse().unwrap()
    }

    fn inherit_ref(s: &str) -> Inherit {
        Inherit::Profile(s.parse().unwrap())
    }

    #[test]
    fn no_profiles_is_empty() {
        assert!(toml_ok("").profiles.is_empty());
        assert!(toml_ok("[profiles]").profiles.is_empty());
        assert!(jv_ok("").profiles.is_empty());
        assert!(jv_ok(r#""profiles": {}"#).profiles.is_empty());
    }

    #[test]
    fn empty_contributed_profile_inherits_main() {
        let m = toml_ok("[profiles.ro]");
        assert_eq!(m.profiles.len(), 1);
        assert_eq!(m.profiles[&pname("ro")], ContributedProfile::default());
        assert_eq!(m.profiles[&pname("ro")].inherit, inherit_ref("main"));
        assert_eq!(jv_ok(r#""profiles": {"ro": {}}"#), m);
    }

    const APPENDIX_PROFILES_TOML: &str = r#"
        [profiles.ro]       # inherits "main"
        fs.ro = ["{workspace}/.git", "{workspace}/.jj", "~/.config/jj/repos/abc123"]

        [profiles.local]
        fs.rw = ["{workspace}/.git", "{workspace}/.jj"]
        fs.ro = [
          "{workspace}/.git/config", "{workspace}/.git/config.worktree", "{workspace}/.git/info/attributes",
          "{workspace}/.git/modules/*/config", "{workspace}/.git/worktrees/*/config.worktree",
          "{workspace}/.jj/repo/config.toml", "~/.config/jj/repos/abc123",
        ]
        fs.masked = ["{workspace}/.git/hooks", "{workspace}/.git/modules/*/hooks"]

        [profiles.remote]
        inherit = "vcs.local"
        network.mode = "proxy"
    "#;

    #[test]
    fn appendix_a_contributed_profiles_parse() {
        let m = toml_ok(APPENDIX_PROFILES_TOML);
        let keys: Vec<&str> = m.profiles.keys().map(ProfileName::as_str).collect();
        assert_eq!(keys, ["local", "remote", "ro"]);

        let ro = &m.profiles[&pname("ro")];
        assert_eq!(ro.inherit, inherit_ref("main"));
        assert_eq!(
            ro.grants,
            Grants {
                fs: FsGrants {
                    ro: pps(&[
                        "{workspace}/.git",
                        "{workspace}/.jj",
                        "~/.config/jj/repos/abc123"
                    ]),
                    ..FsGrants::default()
                },
                ..Grants::default()
            }
        );

        let local = &m.profiles[&pname("local")];
        assert_eq!(local.inherit, inherit_ref("main"));
        assert_eq!(
            local.grants.fs.rw,
            pps(&["{workspace}/.git", "{workspace}/.jj"])
        );
        assert_eq!(
            local.grants.fs.ro,
            pps(&[
                "{workspace}/.git/config",
                "{workspace}/.git/config.worktree",
                "{workspace}/.git/info/attributes",
                "{workspace}/.git/modules/*/config",
                "{workspace}/.git/worktrees/*/config.worktree",
                "{workspace}/.jj/repo/config.toml",
                "~/.config/jj/repos/abc123",
            ])
        );
        assert_eq!(
            local.grants.fs.masked,
            pps(&["{workspace}/.git/hooks", "{workspace}/.git/modules/*/hooks"])
        );
        assert_eq!(local.grants.network, NetworkGrants::default());

        let remote = &m.profiles[&pname("remote")];
        assert_eq!(remote.inherit, inherit_ref("vcs.local"));
        assert_eq!(
            remote.grants,
            Grants {
                network: NetworkGrants {
                    mode: Some(crate::policy::NetworkMode::Proxy),
                    allow_domains: vec![],
                },
                ..Grants::default()
            }
        );
        // The manifest's own grants are untouched.
        assert_eq!(m.grants, Grants::default());
    }

    #[test]
    fn appendix_a_contributed_profiles_as_json_match_toml() {
        let json = r#"{"version": 1, "profiles": {
            "ro": {"fs": {"ro": ["{workspace}/.git", "{workspace}/.jj", "~/.config/jj/repos/abc123"]}},
            "local": {
                "fs": {
                    "rw": ["{workspace}/.git", "{workspace}/.jj"],
                    "ro": ["{workspace}/.git/config", "{workspace}/.git/config.worktree",
                           "{workspace}/.git/info/attributes", "{workspace}/.git/modules/*/config",
                           "{workspace}/.git/worktrees/*/config.worktree",
                           "{workspace}/.jj/repo/config.toml", "~/.config/jj/repos/abc123"],
                    "masked": ["{workspace}/.git/hooks", "{workspace}/.git/modules/*/hooks"]
                }
            },
            "remote": {"inherit": "vcs.local", "network": {"mode": "proxy"}}
        }}"#;
        assert_eq!(
            Manifest::from_json_str(json).unwrap(),
            toml_ok(APPENDIX_PROFILES_TOML)
        );
    }

    #[test]
    fn manifest_with_grants_shims_and_profiles_together() {
        let m = toml_ok(
            r#"
            fs.rw = ["{workspace}"]
            shims.sh = { binary = "fish", default = { decision = "allow", profile = "main" } }
            [profiles.a]
            inherit = "none"
            shims.sh = { binary = "bash", default = { decision = "deny" } }
            network.mode = "loopback"
            "#,
        );
        assert_eq!(m.grants.fs.rw, pps(&["{workspace}"]));
        assert_eq!(m.grants.shims.len(), 1);
        assert_eq!(
            m.grants.shims[&"sh".parse().unwrap()].binary.as_str(),
            "fish"
        );
        let a = &m.profiles[&pname("a")];
        assert_eq!(a.inherit, Inherit::None);
        assert_eq!(
            a.grants.shims[&"sh".parse().unwrap()].binary.as_str(),
            "bash"
        );
        assert_eq!(
            a.grants.network.mode,
            Some(crate::policy::NetworkMode::Loopback)
        );
    }

    #[test]
    fn contributed_profile_inherit_values() {
        let m = toml_ok(
            "[profiles.a]\ninherit = \"vcs.local\"\n[profiles.b]\ninherit = \"none\"\n[profiles.c]\ninherit = \"a\"",
        );
        assert_eq!(m.profiles[&pname("a")].inherit, inherit_ref("vcs.local"));
        assert_eq!(m.profiles[&pname("b")].inherit, Inherit::None);
        assert_eq!(m.profiles[&pname("c")].inherit, inherit_ref("a"));
        let m = jv_ok(r#""profiles": {"a": {"inherit": "vcs.local"}, "b": {"inherit": "none"}}"#);
        assert_eq!(m.profiles[&pname("a")].inherit, inherit_ref("vcs.local"));
        assert_eq!(m.profiles[&pname("b")].inherit, Inherit::None);
        // Unresolved references are accepted here.
        let m = toml_ok("[profiles.a]\ninherit = \"nope.nothing\"");
        assert_eq!(m.profiles[&pname("a")].inherit, inherit_ref("nope.nothing"));
        for bad in ["", "Vcs", "vcs.", "a b"] {
            let msg = toml_err(&format!("[profiles.a]\ninherit = {bad:?}"));
            assert!(msg.contains("profile reference"), "{bad:?}: {msg}");
        }
        toml_err("[profiles.a]\ninherit = 5");
    }

    #[test]
    fn invalid_contributed_profile_names() {
        for bad in ["main", "none", "vcs.local", "Local", "1a", "", "a b"] {
            let msg = toml_err(&format!("[profiles.\"{bad}\"]"));
            assert!(msg.contains("profile name"), "{bad:?}: {msg}");
            assert!(msg.contains(&format!("{bad:?}")), "{bad:?}: {msg}");
            let msg = jv_err(&format!(r#""profiles": {{"{bad}": {{}}}}"#));
            assert!(msg.contains("profile name"), "{bad:?}: {msg}");
        }
        let msg = toml_err("[profiles.main]");
        assert!(msg.contains("reserved"), "{msg}");
        let msg = toml_err("[profiles.none]");
        assert!(msg.contains("reserved"), "{msg}");
        // Unquoted, this is the nested table `profiles.vcs` with key `local`.
        toml_err("[profiles.vcs.local]");
    }

    #[test]
    fn contributed_profiles_do_not_nest_or_version() {
        let msg = toml_err("[profiles.a.profiles.b]");
        assert!(msg.contains("profiles"), "{msg}");
        let msg = toml_err("[profiles.a]\nprofiles = {}");
        assert!(msg.contains("unknown field `profiles`"), "{msg}");
        let msg = toml_err("[profiles.a]\nversion = 1");
        assert!(msg.contains("unknown field `version`"), "{msg}");
        let msg = jv_err(r#""profiles": {"a": {"profiles": {}}}"#);
        assert!(msg.contains("unknown field `profiles`"), "{msg}");
        let msg = jv_err(r#""profiles": {"a": {"version": 1}}"#);
        assert!(msg.contains("unknown field `version`"), "{msg}");
    }

    #[test]
    fn contributed_profiles_are_map_only_and_reject_unknown_keys() {
        for src in [
            r#""profiles": []"#,
            r#""profiles": {"a": []}"#,
            r#""profiles": {"a": ["none"]}"#,
            r#""profiles": {"a": {"fs": []}}"#,
            r#""profiles": {"a": {"shims": []}}"#,
        ] {
            let msg = jv_err(src);
            assert!(msg.contains("expected a map"), "{src}: {msg}");
        }
        for src in ["profiles = []", "profiles.a = []", "[profiles.a]\nfs = []"] {
            let msg = toml_err(src);
            assert!(msg.contains("expected a map"), "{src}: {msg}");
        }
        let msg = toml_err("[profiles.a]\ninheirt = \"none\"");
        assert!(msg.contains("unknown field `inheirt`"), "{msg}");
        let msg = toml_err("[profiles.a]\nfs.rww = []");
        assert!(msg.contains("rww"), "{msg}");
        let msg = jv_err(r#""profiles": {"a": {"inheirt": "none"}}"#);
        assert!(msg.contains("unknown field `inheirt`"), "{msg}");
        let msg = jv_err(r#""profiles": {"a": {"network": {"mod": "none"}}}"#);
        assert!(msg.contains("mod"), "{msg}");
    }

    #[test]
    fn json_syntax_errors_keep_line_and_column() {
        let msg = json_err("{\n  \"version\": 1,\n  oops\n}");
        assert!(msg.contains("line 3 column"), "{msg}");
        let msg = json_err("not json");
        assert!(msg.contains("line 1 column"), "{msg}");
        // Validation errors name the value but may point at the end of the
        // document.
        let msg = json_err("{\n  \"version\": 2\n}");
        assert!(msg.contains("manifest version 2"), "{msg}");
        json_err("");
        json_err("5");
        json_err("\"x\"");
    }
}
