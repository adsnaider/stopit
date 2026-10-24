//! The `env` manifest section: environment filtering and explicit variables
//! (DESIGN.md §9).

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use serde::Deserialize;

use super::check_plain_absolute;
use crate::error::ValueError;
use crate::serde_util::MapOnly;

/// The `env` section.
///
/// Deserializes from a table or object only, never from a sequence.
///
/// `PATH` is never set directly: it is built from `path_prepend`, so `set`
/// must not contain it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(try_from = "MapOnly<RawEnvGrants>")]
pub struct EnvGrants {
    /// Host variables to pass through. Union on merge.
    pub pass: Vec<EnvPattern>,
    /// Host variables to drop; always wins over `pass`.
    pub deny: Vec<EnvPattern>,
    /// Explicit variables. Conflicting values are a merge error.
    pub set: BTreeMap<EnvName, EnvValue>,
    /// Directories placed in front of `PATH`; on merge, later providers'
    /// entries come first (DESIGN.md §3.5).
    pub path_prepend: Vec<SearchPathEntry>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawEnvGrants {
    pass: Vec<EnvPattern>,
    deny: Vec<EnvPattern>,
    set: BTreeMap<EnvName, EnvValue>,
    path_prepend: Vec<SearchPathEntry>,
}

impl TryFrom<MapOnly<RawEnvGrants>> for EnvGrants {
    type Error = ValueError;

    fn try_from(MapOnly(raw): MapOnly<RawEnvGrants>) -> Result<Self, ValueError> {
        if raw.set.keys().any(|k| k.as_str() == "PATH") {
            return Err(ValueError::new(
                "invalid env.set key \"PATH\": PATH is built from env.path_prepend and cannot be set directly",
            ));
        }
        Ok(EnvGrants {
            pass: raw.pass,
            deny: raw.deny,
            set: raw.set,
            path_prepend: raw.path_prepend,
        })
    }
}

fn is_name_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

fn is_name_continue(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// An environment variable name: `[A-Za-z_][A-Za-z0-9_]*`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct EnvName(String);

impl EnvName {
    /// The validated name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for EnvName {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        let bad =
            |why: &str| ValueError::new(format!("invalid environment variable name {s:?}: {why}"));
        let mut chars = s.chars();
        match chars.next() {
            None => return Err(bad("must not be empty")),
            Some(c) if !is_name_start(c) => {
                return Err(bad("must start with a letter or `_`"));
            }
            Some(_) => {}
        }
        if !chars.all(is_name_continue) {
            return Err(bad("may only contain letters, digits and `_`"));
        }
        Ok(EnvName(s.to_owned()))
    }
}

impl TryFrom<String> for EnvName {
    type Error = ValueError;

    fn try_from(s: String) -> Result<Self, ValueError> {
        s.parse()
    }
}

impl fmt::Display for EnvName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A pattern over environment variable names: like [`EnvName`], but `*`
/// (matching any run of characters, including none) is also allowed anywhere,
/// e.g. `RUST_*`, `*_TOKEN` or `*`.
///
/// Nothing else is allowed: no `?`, no character classes. The first character
/// must be a letter, `_` or `*`. Runs such as `**` are accepted and mean the
/// same as `*`; a pattern made only of `*` matches every variable.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct EnvPattern(String);

impl EnvPattern {
    /// The validated pattern text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for EnvPattern {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        let bad = |why: &str| {
            ValueError::new(format!("invalid environment variable pattern {s:?}: {why}"))
        };
        let mut chars = s.chars();
        match chars.next() {
            None => return Err(bad("must not be empty")),
            Some(c) if !(is_name_start(c) || c == '*') => {
                return Err(bad("must start with a letter, `_` or `*`"));
            }
            Some(_) => {}
        }
        if !chars.all(|c| is_name_continue(c) || c == '*') {
            return Err(bad("may only contain letters, digits, `_` and `*`"));
        }
        Ok(EnvPattern(s.to_owned()))
    }
}

impl TryFrom<String> for EnvPattern {
    type Error = ValueError;

    fn try_from(s: String) -> Result<Self, ValueError> {
        s.parse()
    }
}

impl fmt::Display for EnvPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The value of an explicitly set variable: any string without NUL bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct EnvValue(String);

impl EnvValue {
    /// The validated value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for EnvValue {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        if s.contains('\0') {
            return Err(ValueError::new(format!(
                "invalid environment variable value {s:?}: must not contain NUL bytes"
            )));
        }
        Ok(EnvValue(s.to_owned()))
    }
}

impl TryFrom<String> for EnvValue {
    type Error = ValueError;

    fn try_from(s: String) -> Result<Self, ValueError> {
        s.parse()
    }
}

impl fmt::Display for EnvValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A directory prepended to the sandbox `PATH`: an absolute sandbox path
/// with no `~`, no globs, no placeholders and no `:` (the `PATH` separator),
/// and not `/`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct SearchPathEntry(String);

impl SearchPathEntry {
    /// The validated path text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for SearchPathEntry {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        let bad = |why: &str| ValueError::new(format!("invalid search path entry {s:?}: {why}"));
        if s.contains(':') {
            return Err(bad("must not contain `:`, the `PATH` separator"));
        }
        check_plain_absolute(s).map_err(bad)?;
        Ok(SearchPathEntry(s.to_owned()))
    }
}

impl TryFrom<String> for SearchPathEntry {
    type Error = ValueError;

    fn try_from(s: String) -> Result<Self, ValueError> {
        s.parse()
    }
}

impl fmt::Display for SearchPathEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_util::*;
    use super::super::{Manifest, ManifestVersion};
    use super::*;

    fn name(s: &str) -> EnvName {
        s.parse().unwrap()
    }

    fn pat(s: &str) -> EnvPattern {
        s.parse().unwrap()
    }

    fn val(s: &str) -> EnvValue {
        s.parse().unwrap()
    }

    fn sp(s: &str) -> SearchPathEntry {
        s.parse().unwrap()
    }

    fn pats(v: &[&str]) -> Vec<EnvPattern> {
        v.iter().map(|s| pat(s)).collect()
    }

    fn set(v: &[(&str, &str)]) -> BTreeMap<EnvName, EnvValue> {
        v.iter().map(|(k, v)| (name(k), val(v))).collect()
    }

    #[test]
    fn empty_env_section_is_default() {
        let want = EnvGrants::default();
        assert!(want.pass.is_empty() && want.deny.is_empty());
        assert!(want.set.is_empty() && want.path_prepend.is_empty());
        assert_eq!(Manifest::default().grants.env, want);
        assert_eq!(toml_ok("").grants.env, want);
        assert_eq!(toml_ok("[env]").grants.env, want);
        assert_eq!(jv_ok("").grants.env, want);
        assert_eq!(jv_ok(r#""env": {}"#).grants.env, want);
    }

    #[test]
    fn appendix_a_env_parses_from_toml_and_json() {
        let want = EnvGrants {
            pass: pats(&["TERM", "LANG", "COLORTERM"]),
            deny: pats(&[
                "*_TOKEN",
                "*_KEY",
                "*_SECRET",
                "*_PASSWORD",
                "AWS_*",
                "GITHUB_*",
                "SSH_AUTH_SOCK",
                "NIX_CONFIG",
            ]),
            set: BTreeMap::new(),
            path_prepend: vec![],
        };
        let toml = r#"
            [env]
            pass = ["TERM", "LANG", "COLORTERM"]
            deny = ["*_TOKEN", "*_KEY", "*_SECRET", "*_PASSWORD", "AWS_*", "GITHUB_*", "SSH_AUTH_SOCK", "NIX_CONFIG"]
        "#;
        assert_eq!(toml_ok(toml).grants.env, want);
        let json = r#""env": {
            "pass": ["TERM", "LANG", "COLORTERM"],
            "deny": ["*_TOKEN", "*_KEY", "*_SECRET", "*_PASSWORD", "AWS_*", "GITHUB_*", "SSH_AUTH_SOCK", "NIX_CONFIG"]
        }"#;
        assert_eq!(jv_ok(json).grants.env, want);
    }

    #[test]
    fn section_9_example_parses_from_toml_and_json() {
        let want = EnvGrants {
            pass: pats(&[
                "TERM",
                "LANG",
                "COLORTERM",
                "RUST_*",
                "CARGO_*",
                "PKG_CONFIG_*",
            ]),
            deny: pats(&[
                "*_TOKEN",
                "*_KEY",
                "*_SECRET",
                "*_PASSWORD",
                "AWS_*",
                "GITHUB_*",
                "SSH_AUTH_SOCK",
                "NIX_CONFIG",
            ]),
            set: set(&[("EDITOR", "nvim")]),
            path_prepend: vec![sp("/nix/store/abc-tools/bin")],
        };
        let toml = r#"
            [env]
            pass = ["TERM", "LANG", "COLORTERM", "RUST_*", "CARGO_*", "PKG_CONFIG_*"]
            deny = ["*_TOKEN", "*_KEY", "*_SECRET", "*_PASSWORD", "AWS_*", "GITHUB_*", "SSH_AUTH_SOCK", "NIX_CONFIG"]
            set  = { EDITOR = "nvim" }
            path_prepend = ["/nix/store/abc-tools/bin"]
        "#;
        assert_eq!(toml_ok(toml).grants.env, want);
        let json = r#""env": {
            "pass": ["TERM", "LANG", "COLORTERM", "RUST_*", "CARGO_*", "PKG_CONFIG_*"],
            "deny": ["*_TOKEN", "*_KEY", "*_SECRET", "*_PASSWORD", "AWS_*", "GITHUB_*", "SSH_AUTH_SOCK", "NIX_CONFIG"],
            "set": { "EDITOR": "nvim" },
            "path_prepend": ["/nix/store/abc-tools/bin"]
        }"#;
        assert_eq!(jv_ok(json).grants.env, want);
    }

    #[test]
    fn section_3_6_env_example_parses() {
        let m = jv_ok(
            r#""env": { "pass": ["TERM"], "deny": ["*_TOKEN"], "set": { "LANG": "C.UTF-8" }, "path_prepend": ["/nix/store/x/bin"] }"#,
        );
        assert_eq!(m.version, ManifestVersion::V1);
        assert_eq!(m.grants.env.pass, pats(&["TERM"]));
        assert_eq!(m.grants.env.deny, pats(&["*_TOKEN"]));
        assert_eq!(m.grants.env.set, set(&[("LANG", "C.UTF-8")]));
        assert_eq!(m.grants.env.path_prepend, vec![sp("/nix/store/x/bin")]);
    }

    #[test]
    fn valid_names() {
        for good in [
            "A", "_", "_a", "PATH", "RUST_LOG", "a1", "_1", "A_B_9", "LANG",
        ] {
            let n = good.parse::<EnvName>().unwrap();
            assert_eq!(n.as_str(), good);
            assert_eq!(n.to_string(), good);
            assert_eq!(EnvName::try_from(good.to_owned()).unwrap(), n);
        }
    }

    #[test]
    fn invalid_names() {
        for bad in [
            "", "1A", "9", "A-B", "A.B", "A B", "A=B", "A*", "*", "é", "A\0", " A", "A ", "$A",
            "A\n",
        ] {
            let msg = bad.parse::<EnvName>().unwrap_err().to_string();
            assert!(msg.contains("variable name"), "{bad:?}: {msg}");
            assert!(msg.contains(&format!("{bad:?}")), "{bad:?}: {msg}");
        }
    }

    #[test]
    fn valid_patterns() {
        for good in [
            "A",
            "_",
            "*",
            "**",
            "***_X",
            "RUST_*",
            "*_TOKEN",
            "A*B",
            "*A*",
            "*1",
            "A1*",
            "SSH_AUTH_SOCK",
            "*_*",
        ] {
            let p = good.parse::<EnvPattern>().unwrap();
            assert_eq!(p.as_str(), good);
            assert_eq!(p.to_string(), good);
            assert_eq!(EnvPattern::try_from(good.to_owned()).unwrap(), p);
        }
    }

    #[test]
    fn invalid_patterns() {
        for bad in [
            "", "1*", "9", "A-*", "A.*", "A B", "A=*", "A?", "?", "[A]", "A[0-9]", "{A}", "é*",
            "A\0", "*\n", "*/*", "$A",
        ] {
            let msg = bad.parse::<EnvPattern>().unwrap_err().to_string();
            assert!(msg.contains("variable pattern"), "{bad:?}: {msg}");
            assert!(msg.contains(&format!("{bad:?}")), "{bad:?}: {msg}");
        }
    }

    #[test]
    fn values() {
        for good in [
            "",
            "nvim",
            "C.UTF-8",
            "a b c",
            "with=equals",
            "multi\nline",
            "tab\t",
            "é€",
            "/a:/b",
            "$HOME",
        ] {
            let v = good.parse::<EnvValue>().unwrap();
            assert_eq!(v.as_str(), good);
            assert_eq!(v.to_string(), good);
            assert_eq!(EnvValue::try_from(good.to_owned()).unwrap(), v);
        }
        for bad in ["\0", "a\0", "\0b", "a\0b"] {
            let msg = bad.parse::<EnvValue>().unwrap_err().to_string();
            assert!(msg.contains("NUL"), "{bad:?}: {msg}");
            assert!(msg.contains(&format!("{bad:?}")), "{bad:?}: {msg}");
        }
    }

    #[test]
    fn valid_search_path_entries() {
        for good in [
            "/bin",
            "/usr/local/bin",
            "/nix/store/abc-foo-1.0/bin",
            "/a..b",
            "/run/stopit/bin",
        ] {
            let e = good.parse::<SearchPathEntry>().unwrap();
            assert_eq!(e.as_str(), good);
            assert_eq!(e.to_string(), good);
            assert_eq!(SearchPathEntry::try_from(good.to_owned()).unwrap(), e);
        }
    }

    #[test]
    fn invalid_search_path_entries() {
        for bad in [
            "",
            "/",
            "bin",
            "./bin",
            "~",
            "~/bin",
            "{workspace}/bin",
            "/a/{x}",
            "/a/*",
            "/a/?",
            "/a/[x]",
            "/a/",
            "/a//b",
            "/a/./b",
            "/a/../b",
            "/a:/b",
            ":",
            "/a:",
            ":/a",
            "/a\0b",
        ] {
            let msg = bad.parse::<SearchPathEntry>().unwrap_err().to_string();
            assert!(msg.contains("search path entry"), "{bad:?}: {msg}");
            assert!(msg.contains(&format!("{bad:?}")), "{bad:?}: {msg}");
        }
        let msg = "/a:/b".parse::<SearchPathEntry>().unwrap_err().to_string();
        assert!(msg.contains("`:`"), "{msg}");
    }

    #[test]
    fn invalid_values_are_rejected_in_documents() {
        let msg = toml_err("env.pass = [\"1X\"]");
        assert!(msg.contains("\"1X\""), "{msg}");
        let msg = jv_err(r#""env": {"deny": ["A B"]}"#);
        assert!(msg.contains("A B"), "{msg}");
        let msg = toml_err("env.set = { \"A-B\" = \"x\" }");
        assert!(msg.contains("A-B"), "{msg}");
        let msg = jv_err(r#""env": {"set": {"": "x"}}"#);
        assert!(msg.contains("must not be empty"), "{msg}");
        let msg = jv_err(r#""env": {"path_prepend": ["/a:/b"]}"#);
        assert!(msg.contains("/a:/b"), "{msg}");
        let msg = toml_err("env.path_prepend = [\"/a:/b\"]");
        assert!(msg.contains("/a:/b"), "{msg}");
        let msg = jv_err(r#""env": {"path_prepend": ["~/bin"]}"#);
        assert!(msg.contains("~/bin"), "{msg}");
        toml_err("env.pass = \"TERM\"");
        toml_err("env.set = [\"A\"]");
        jv_err(r#""env": {"set": {"A": 1}}"#);
        toml_err("env.set = { A = 1 }");
    }

    #[test]
    fn nul_in_set_value_is_rejected() {
        let msg = jv_err(r#""env": {"set": {"A": "x\u0000y"}}"#);
        assert!(msg.contains("NUL"), "{msg}");
        let msg = toml_err("env.set = { A = \"x\\u0000y\" }");
        assert!(msg.contains("NUL"), "{msg}");
    }

    #[test]
    fn set_must_not_contain_path() {
        let msg = toml_err("env.set = { PATH = \"/bin\" }");
        assert!(msg.contains("\"PATH\""), "{msg}");
        assert!(msg.contains("path_prepend"), "{msg}");
        let msg = toml_err("[env.set]\nEDITOR = \"nvim\"\nPATH = \"\"");
        assert!(msg.contains("path_prepend"), "{msg}");
        let msg = jv_err(r#""env": {"set": {"PATH": "/bin"}}"#);
        assert!(msg.contains("path_prepend"), "{msg}");
        // Only the exact name `PATH` is special; `pass`/`deny` may mention it.
        let m = toml_ok("env.set = { PATH_INFO = \"x\", path = \"y\" }");
        assert_eq!(m.grants.env.set, set(&[("PATH_INFO", "x"), ("path", "y")]));
        let m = toml_ok("env.pass = [\"PATH\"]\nenv.deny = [\"PATH\"]");
        assert_eq!(m.grants.env.pass, pats(&["PATH"]));
    }

    #[test]
    fn set_map_keys_deserialize_in_both_formats() {
        let m = jv_ok(r#""env": {"set": {"B": "2", "A": "1", "_C": ""}}"#);
        let keys: Vec<_> = m.grants.env.set.keys().map(EnvName::as_str).collect();
        assert_eq!(keys, ["A", "B", "_C"]);
        assert_eq!(m.grants.env.set[&name("_C")].as_str(), "");
        let m = toml_ok("[env.set]\nB = \"2\"\nA = \"1\"");
        assert_eq!(m.grants.env.set, set(&[("A", "1"), ("B", "2")]));
    }

    #[test]
    fn env_is_map_only_and_rejects_unknown_keys() {
        for src in [
            r#""env": []"#,
            r#""env": [[], [], {}, []]"#,
            r#""env": {"set": []}"#,
            r#""env": {"set": [["A", "1"]]}"#,
        ] {
            let msg = jv_err(src);
            assert!(msg.contains("expected a map"), "{src}: {msg}");
        }
        for src in ["env = []", "env.set = []", "env = [[\"x\"]]"] {
            let msg = toml_err(src);
            assert!(msg.contains("expected a map"), "{src}: {msg}");
        }
        let msg = toml_err("env.passs = []");
        assert!(msg.contains("passs"), "{msg}");
        let msg = jv_err(r#""env": {"path": ["/bin"]}"#);
        assert!(msg.contains("path"), "{msg}");
        let msg = toml_err("[env]\npathprepend = []");
        assert!(msg.contains("pathprepend"), "{msg}");
    }
}
