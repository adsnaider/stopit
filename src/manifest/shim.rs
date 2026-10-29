//! The `shims` manifest section (DESIGN.md §7.1, §7.4).
//!
//! A shim is a command installed in `/run/stopit/bin` that forwards each
//! invocation to the broker, which decides what to do with it. This module
//! only parses and validates the *syntax* of shim declarations: matching
//! subcommands against `argv`, merging and resolving profile references
//! happen later.

use std::fmt;
use std::str::FromStr;

use serde::Deserialize;

use crate::config::ProfileRef;
use crate::error::ValueError;
use crate::policy::Decision;
use crate::serde_util::MapOnly;

/// Shim names that belong to the built-in commands.
const RESERVED_SHIM_NAMES: [&str; 2] = ["stopit", "stopit-grant"];

/// The name a shim is installed under in `/run/stopit/bin`.
///
/// Non-empty; the first character is an ASCII lowercase letter or digit, the
/// rest are lowercase letters, digits or one of `.`, `_`, `+`, `-`. Never
/// contains `/`. The names `stopit` and `stopit-grant` are reserved for the
/// built-in commands.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct ShimName(String);

impl ShimName {
    /// The validated name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for ShimName {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        let bad = |why: &str| ValueError::new(format!("invalid shim name {s:?}: {why}"));
        if RESERVED_SHIM_NAMES.contains(&s) {
            return Err(bad("this name is reserved for a built-in command"));
        }
        let mut chars = s.chars();
        match chars.next() {
            None => return Err(bad("must not be empty")),
            Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit() => {}
            Some(_) => {
                return Err(bad("must start with a lowercase ASCII letter or digit"));
            }
        }
        if !chars.all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '+' | '-')
        }) {
            return Err(bad(
                "may only contain lowercase ASCII letters, digits, `.`, `_`, `+` and `-`",
            ));
        }
        Ok(ShimName(s.to_owned()))
    }
}

impl TryFrom<String> for ShimName {
    type Error = ValueError;

    fn try_from(s: String) -> Result<Self, ValueError> {
        s.parse()
    }
}

impl fmt::Display for ShimName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The program a shim runs in its target profile, resolved through that
/// profile's `PATH`.
///
/// Non-empty, and containing no `/`, NUL or whitespace.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct BinaryName(String);

impl BinaryName {
    /// The validated program name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for BinaryName {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        let bad = |why: &str| ValueError::new(format!("invalid binary name {s:?}: {why}"));
        if s.is_empty() {
            return Err(bad("must not be empty"));
        }
        if s.contains('/') {
            return Err(bad(
                "must be a bare program name resolved via `PATH`, without `/`",
            ));
        }
        if s == "." || s == ".." {
            return Err(bad("must not be `.` or `..`"));
        }
        if s.contains('\0') {
            return Err(bad("must not contain NUL bytes"));
        }
        if s.chars().any(char::is_whitespace) {
            return Err(bad("must not contain whitespace"));
        }
        Ok(BinaryName(s.to_owned()))
    }
}

impl TryFrom<String> for BinaryName {
    type Error = ValueError;

    fn try_from(s: String) -> Result<Self, ValueError> {
        s.parse()
    }
}

impl fmt::Display for BinaryName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A command-line flag that a shim refuses, such as `-c`, `--config` or `-A`.
///
/// Starts with `-`, is at least two characters long, contains no whitespace
/// or NUL, and is not `--` alone (the end-of-options marker).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct Flag(String);

impl Flag {
    /// The validated flag, including its leading dashes.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for Flag {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        let bad = |why: &str| ValueError::new(format!("invalid flag {s:?}: {why}"));
        if !s.starts_with('-') {
            return Err(bad("must start with `-`"));
        }
        if s.len() < 2 {
            return Err(bad("must be at least two characters long"));
        }
        if s == "--" {
            return Err(bad("`--` is the end-of-options marker, not a flag"));
        }
        if s.contains('\0') {
            return Err(bad("must not contain NUL bytes"));
        }
        if s.chars().any(char::is_whitespace) {
            return Err(bad("must not contain whitespace"));
        }
        Ok(Flag(s.to_owned()))
    }
}

impl TryFrom<String> for Flag {
    type Error = ValueError;

    fn try_from(s: String) -> Result<Self, ValueError> {
        s.parse()
    }
}

impl fmt::Display for Flag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An argument a shim puts before the caller's, such as `--no-pager`.
///
/// Non-empty, and containing no NUL.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct ShimArg(String);

impl ShimArg {
    /// The validated argument.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for ShimArg {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        let bad = |why: &str| ValueError::new(format!("invalid shim argument {s:?}: {why}"));
        if s.is_empty() {
            return Err(bad("must not be empty"));
        }
        if s.contains('\0') {
            return Err(bad("must not contain NUL bytes"));
        }
        Ok(ShimArg(s.to_owned()))
    }
}

impl TryFrom<String> for ShimArg {
    type Error = ValueError;

    fn try_from(s: String) -> Result<Self, ValueError> {
        s.parse()
    }
}

/// A subcommand to match, such as `status`, `op log`, `git push` or
/// `bookmark *`.
///
/// One or more tokens separated by single spaces. Each token matches
/// `[a-z0-9][a-z0-9_-]*`, except that the last token may be exactly `*`
/// (any subcommand below the preceding tokens). A lone `*` is rejected:
/// "everything else" is the shim's `default`. Flags are not subcommands, so
/// tokens starting with `-` are rejected.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct SubcommandPattern(String);

impl SubcommandPattern {
    /// The validated pattern text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The space-separated tokens; the last may be `*`.
    pub fn tokens(&self) -> impl Iterator<Item = &str> {
        self.0.split(' ')
    }
}

/// Checks one non-wildcard subcommand token.
fn check_subcommand_token(tok: &str) -> Result<(), &'static str> {
    let mut chars = tok.chars();
    match chars.next() {
        Some('-') => return Err("must not contain flags (tokens starting with `-`)"),
        Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit() => {}
        _ => {
            return Err("each token must start with a lowercase ASCII letter or digit");
        }
    }
    if chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-') {
        Ok(())
    } else {
        Err("tokens may only contain lowercase ASCII letters, digits, `_` and `-`")
    }
}

impl FromStr for SubcommandPattern {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        let bad = |why: &str| ValueError::new(format!("invalid subcommand pattern {s:?}: {why}"));
        if s.is_empty() {
            return Err(bad("must not be empty"));
        }
        let tokens: Vec<&str> = s.split(' ').collect();
        if tokens.iter().any(|t| t.is_empty()) {
            return Err(bad(
                "tokens must be separated by single spaces, with no leading or trailing space",
            ));
        }
        let last = tokens.len() - 1;
        for (i, tok) in tokens.iter().enumerate() {
            if *tok == "*" {
                if tokens.len() == 1 {
                    return Err(bad(
                        "a lone `*` is not allowed (use the shim's `default` instead)",
                    ));
                }
                if i != last {
                    return Err(bad("`*` is only allowed as the last token"));
                }
                continue;
            }
            check_subcommand_token(tok).map_err(bad)?;
        }
        Ok(SubcommandPattern(s.to_owned()))
    }
}

impl TryFrom<String> for SubcommandPattern {
    type Error = ValueError;

    fn try_from(s: String) -> Result<Self, ValueError> {
        s.parse()
    }
}

impl fmt::Display for SubcommandPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Checks the `profile` / `decision` pairing: a profile is required unless
/// the decision is `deny`, and is forbidden for `deny` (a deny never spawns a
/// sandbox).
fn check_profile(decision: Decision, profile: Option<&ProfileRef>) -> Result<(), ValueError> {
    match (decision, profile) {
        (Decision::Deny, Some(p)) => Err(ValueError::new(format!(
            "invalid shim decision: a `deny` never spawns a sandbox, so it must not name a profile, got {:?}",
            p.as_str()
        ))),
        (Decision::Ask | Decision::Allow, None) => Err(ValueError::new(format!(
            "invalid shim decision {:?}: a profile is required unless the decision is \"deny\"",
            decision.as_str()
        ))),
        _ => Ok(()),
    }
}

/// What to do with a command: a decision and, unless it is a deny, the
/// profile whose sandbox runs the command.
///
/// Deserializes from a table or object only, never from a sequence.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "MapOnly<RawShimAction>")]
pub struct ShimAction {
    /// The outcome.
    pub decision: Decision,
    /// The target profile. `None` exactly when `decision` is `deny`.
    pub profile: Option<ProfileRef>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawShimAction {
    decision: Decision,
    #[serde(default)]
    profile: Option<ProfileRef>,
}

impl TryFrom<MapOnly<RawShimAction>> for ShimAction {
    type Error = ValueError;

    fn try_from(MapOnly(raw): MapOnly<RawShimAction>) -> Result<Self, ValueError> {
        check_profile(raw.decision, raw.profile.as_ref())?;
        Ok(ShimAction {
            decision: raw.decision,
            profile: raw.profile,
        })
    }
}

/// A rule overriding a shim's default for specific subcommands.
///
/// Deserializes from a table or object only, never from a sequence.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "MapOnly<RawShimRule>")]
pub struct ShimRule {
    /// The subcommands this rule covers; never empty.
    pub subcommand: Vec<SubcommandPattern>,
    /// The outcome.
    pub decision: Decision,
    /// The target profile. `None` exactly when `decision` is `deny`.
    pub profile: Option<ProfileRef>,
    /// Flags refused in addition to the shim's own `deny_flags`.
    pub deny_flags: Vec<Flag>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawShimRule {
    subcommand: Vec<SubcommandPattern>,
    decision: Decision,
    #[serde(default)]
    profile: Option<ProfileRef>,
    #[serde(default)]
    deny_flags: Vec<Flag>,
}

impl TryFrom<MapOnly<RawShimRule>> for ShimRule {
    type Error = ValueError;

    fn try_from(MapOnly(raw): MapOnly<RawShimRule>) -> Result<Self, ValueError> {
        if raw.subcommand.is_empty() {
            return Err(ValueError::new(
                "invalid shim rule: `subcommand` must list at least one pattern",
            ));
        }
        check_profile(raw.decision, raw.profile.as_ref())?;
        Ok(ShimRule {
            subcommand: raw.subcommand,
            decision: raw.decision,
            profile: raw.profile,
            deny_flags: raw.deny_flags,
        })
    }
}

/// One shim declaration (DESIGN.md §7.1).
///
/// Deserializes from a table or object only, never from a sequence.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(from = "MapOnly<RawShimSpec>")]
pub struct ShimSpec {
    /// The program to run, resolved in the target profile's `PATH`.
    pub binary: BinaryName,
    /// Arguments put before the caller's, which the rules never see.
    pub args: Vec<ShimArg>,
    /// Flags refused for every invocation.
    pub deny_flags: Vec<Flag>,
    /// What to do with subcommands no rule covers.
    pub default: ShimAction,
    /// Per-subcommand rules.
    pub rules: Vec<ShimRule>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawShimSpec {
    binary: BinaryName,
    #[serde(default)]
    args: Vec<ShimArg>,
    #[serde(default)]
    deny_flags: Vec<Flag>,
    default: ShimAction,
    #[serde(default)]
    rules: Vec<ShimRule>,
}

impl From<MapOnly<RawShimSpec>> for ShimSpec {
    fn from(MapOnly(raw): MapOnly<RawShimSpec>) -> Self {
        ShimSpec {
            binary: raw.binary,
            args: raw.args,
            deny_flags: raw.deny_flags,
            default: raw.default,
            rules: raw.rules,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::Manifest;
    use super::super::test_util::*;
    use super::*;

    fn pr(s: &str) -> ProfileRef {
        s.parse().unwrap()
    }

    fn sn(s: &str) -> ShimName {
        s.parse().unwrap()
    }

    fn flags(v: &[&str]) -> Vec<Flag> {
        v.iter().map(|s| s.parse().unwrap()).collect()
    }

    fn subs(v: &[&str]) -> Vec<SubcommandPattern> {
        v.iter().map(|s| s.parse().unwrap()).collect()
    }

    fn act(decision: Decision, profile: Option<&str>) -> ShimAction {
        ShimAction {
            decision,
            profile: profile.map(pr),
        }
    }

    fn rule(sub: &[&str], decision: Decision, profile: Option<&str>, deny: &[&str]) -> ShimRule {
        ShimRule {
            subcommand: subs(sub),
            decision,
            profile: profile.map(pr),
            deny_flags: flags(deny),
        }
    }

    fn spec(binary: &str, deny: &[&str], default: ShimAction, rules: Vec<ShimRule>) -> ShimSpec {
        ShimSpec {
            binary: binary.parse().unwrap(),
            args: Vec::new(),
            deny_flags: flags(deny),
            default,
            rules,
        }
    }

    #[test]
    fn shim_args_go_before_the_callers() {
        let m = toml_ok(
            r#"
            [shims.jj]
            binary = "jj"
            args = ["--no-pager", "-R", "/workspace"]
            default = { decision = "ask", profile = "main" }
            "#,
        );
        let spec = &m.grants.shims[&"jj".parse::<ShimName>().unwrap()];
        assert_eq!(
            spec.args.iter().map(ShimArg::as_str).collect::<Vec<_>>(),
            ["--no-pager", "-R", "/workspace"]
        );
        // No arguments by default.
        assert!(cargo_publish_expected().args.is_empty());
        for bad in [r#"args = [""]"#, r#"args = ["a\u0000b"]"#, r#"args = "x""#] {
            let text = format!(
                "[shims.jj]\nbinary = \"jj\"\n{bad}\ndefault = {{ decision = \"deny\" }}\n"
            );
            assert!(toml::from_str::<Manifest>(&text).is_err(), "{bad}");
        }
    }

    #[test]
    fn no_shims_is_empty() {
        assert!(toml_ok("").grants.shims.is_empty());
        assert!(toml_ok("[shims]").grants.shims.is_empty());
        assert!(jv_ok("").grants.shims.is_empty());
        assert!(jv_ok(r#""shims": {}"#).grants.shims.is_empty());
    }

    fn cargo_publish_expected() -> ShimSpec {
        spec(
            "cargo",
            &["--config"],
            act(Decision::Ask, Some("publish")),
            vec![rule(&["publish"], Decision::Ask, Some("publish"), &[])],
        )
    }

    #[test]
    fn section_7_1_declaration_parses() {
        let m = toml_ok(
            r#"
            [shims.cargo-publish]
            binary     = "cargo"
            deny_flags = ["--config"]
            default    = { decision = "ask", profile = "publish" }
            rules      = [
              { subcommand = ["publish"], decision = "ask", profile = "publish" },
            ]
            "#,
        );
        assert_eq!(m.grants.shims.len(), 1);
        assert_eq!(
            m.grants.shims[&sn("cargo-publish")],
            cargo_publish_expected()
        );
        let j = jv_ok(
            r#""shims": {"cargo-publish": {
                "binary": "cargo",
                "deny_flags": ["--config"],
                "default": {"decision": "ask", "profile": "publish"},
                "rules": [{"subcommand": ["publish"], "decision": "ask", "profile": "publish"}]
            }}"#,
        );
        assert_eq!(j, m);
    }

    #[test]
    fn section_7_6_declaration_parses() {
        let m = toml_ok(
            r#"shims.sh-main = { binary = "fish", default = { decision = "allow", profile = "main" } }"#,
        );
        assert_eq!(
            m.grants.shims[&sn("sh-main")],
            spec("fish", &[], act(Decision::Allow, Some("main")), vec![])
        );
        let j = jv_ok(
            r#""shims": {"sh-main": {"binary": "fish", "default": {"decision": "allow", "profile": "main"}}}"#,
        );
        assert_eq!(j, m);
    }

    // Deliberately adds `binary` keys (and keeps `default` required) relative
    // to DESIGN.md Appendix A, which will be updated to match.
    const APPENDIX_SHIMS_TOML: &str = r#"
        [shims.jj]
        binary = "jj"
        deny_flags = ["--config", "--config-file", "--config-toml"]
        default = { decision = "ask", profile = "vcs.local" }
        rules = [
          { subcommand = ["status", "diff", "log", "show", "evolog", "op log"], decision = "allow", profile = "vcs.ro" },
          { subcommand = ["new", "commit", "describe"], decision = "allow", profile = "vcs.local", deny_flags = ["-A", "--insert-after", "-B", "--insert-before"] },
          { subcommand = ["git fetch", "git clone"], decision = "ask", profile = "vcs.remote" },
          { subcommand = ["git push"], decision = "ask", profile = "vcs.remote" },
        ]

        [shims.git]
        binary = "git"
        deny_flags = ["-c", "--config-env", "--exec-path", "--upload-pack", "--receive-pack"]
        default = { decision = "ask", profile = "vcs.local" }
        rules = [
          { subcommand = ["status", "diff", "log", "show", "add", "commit"], decision = "allow", profile = "vcs.local" },
          { subcommand = ["fetch", "pull", "ls-remote", "remote update", "clone"], decision = "ask", profile = "vcs.remote" },
          { subcommand = ["push"], decision = "ask", profile = "vcs.remote" },
        ]
    "#;

    fn appendix_shims_expected() -> [(ShimName, ShimSpec); 2] {
        [
            (
                sn("jj"),
                spec(
                    "jj",
                    &["--config", "--config-file", "--config-toml"],
                    act(Decision::Ask, Some("vcs.local")),
                    vec![
                        rule(
                            &["status", "diff", "log", "show", "evolog", "op log"],
                            Decision::Allow,
                            Some("vcs.ro"),
                            &[],
                        ),
                        rule(
                            &["new", "commit", "describe"],
                            Decision::Allow,
                            Some("vcs.local"),
                            &["-A", "--insert-after", "-B", "--insert-before"],
                        ),
                        rule(
                            &["git fetch", "git clone"],
                            Decision::Ask,
                            Some("vcs.remote"),
                            &[],
                        ),
                        rule(&["git push"], Decision::Ask, Some("vcs.remote"), &[]),
                    ],
                ),
            ),
            (
                sn("git"),
                spec(
                    "git",
                    &[
                        "-c",
                        "--config-env",
                        "--exec-path",
                        "--upload-pack",
                        "--receive-pack",
                    ],
                    act(Decision::Ask, Some("vcs.local")),
                    vec![
                        rule(
                            &["status", "diff", "log", "show", "add", "commit"],
                            Decision::Allow,
                            Some("vcs.local"),
                            &[],
                        ),
                        rule(
                            &["fetch", "pull", "ls-remote", "remote update", "clone"],
                            Decision::Ask,
                            Some("vcs.remote"),
                            &[],
                        ),
                        rule(&["push"], Decision::Ask, Some("vcs.remote"), &[]),
                    ],
                ),
            ),
        ]
    }

    #[test]
    fn appendix_a_shims_parse() {
        let m = toml_ok(APPENDIX_SHIMS_TOML);
        let want: std::collections::BTreeMap<_, _> =
            appendix_shims_expected().into_iter().collect();
        assert_eq!(m.grants.shims, want);
    }

    #[test]
    fn appendix_a_shims_as_json_match_toml() {
        let json = r#"{"version": 1, "shims": {
            "jj": {
              "binary": "jj",
              "deny_flags": ["--config", "--config-file", "--config-toml"],
              "default": {"decision": "ask", "profile": "vcs.local"},
              "rules": [
                {"subcommand": ["status", "diff", "log", "show", "evolog", "op log"], "decision": "allow", "profile": "vcs.ro"},
                {"subcommand": ["new", "commit", "describe"], "decision": "allow", "profile": "vcs.local",
                 "deny_flags": ["-A", "--insert-after", "-B", "--insert-before"]},
                {"subcommand": ["git fetch", "git clone"], "decision": "ask", "profile": "vcs.remote"},
                {"subcommand": ["git push"], "decision": "ask", "profile": "vcs.remote"}
              ]
            },
            "git": {
              "binary": "git",
              "deny_flags": ["-c", "--config-env", "--exec-path", "--upload-pack", "--receive-pack"],
              "default": {"decision": "ask", "profile": "vcs.local"},
              "rules": [
                {"subcommand": ["status", "diff", "log", "show", "add", "commit"], "decision": "allow", "profile": "vcs.local"},
                {"subcommand": ["fetch", "pull", "ls-remote", "remote update", "clone"], "decision": "ask", "profile": "vcs.remote"},
                {"subcommand": ["push"], "decision": "ask", "profile": "vcs.remote"}
              ]
            }
        }}"#;
        assert_eq!(
            Manifest::from_json_str(json).unwrap(),
            toml_ok(APPENDIX_SHIMS_TOML)
        );
    }

    #[test]
    fn deny_decisions_have_no_profile() {
        let m = toml_ok(
            r#"
            [shims.x]
            binary = "x"
            default = { decision = "deny" }
            rules = [{ subcommand = ["rm"], decision = "deny", deny_flags = ["-f"] }]
            "#,
        );
        assert_eq!(
            m.grants.shims[&sn("x")],
            spec(
                "x",
                &[],
                act(Decision::Deny, None),
                vec![rule(&["rm"], Decision::Deny, None, &["-f"])]
            )
        );
        let j = jv_ok(
            r#""shims": {"x": {"binary": "x", "default": {"decision": "deny"},
                "rules": [{"subcommand": ["rm"], "decision": "deny", "deny_flags": ["-f"]}]}}"#,
        );
        assert_eq!(j, m);
    }

    #[test]
    fn optional_fields_default_to_empty() {
        let m = toml_ok(
            "shims.x = { binary = \"x\", default = { decision = \"ask\", profile = \"main\" } }",
        );
        let s = &m.grants.shims[&sn("x")];
        assert!(s.deny_flags.is_empty());
        assert!(s.rules.is_empty());
        // `binary` and `default` are required.
        let msg = toml_err("shims.x = { default = { decision = \"deny\" } }");
        assert!(msg.contains("binary"), "{msg}");
        let msg = toml_err("shims.x = { binary = \"x\" }");
        assert!(msg.contains("default"), "{msg}");
        let msg = jv_err(r#""shims": {"x": {"binary": "x"}}"#);
        assert!(msg.contains("missing field `default`"), "{msg}");
        let msg = jv_err(r#""shims": {"x": {"default": {"decision": "deny"}}}"#);
        assert!(msg.contains("missing field `binary`"), "{msg}");
        let msg = jv_err(r#""shims": {"x": {"binary": "x", "default": {"profile": "a"}}}"#);
        assert!(msg.contains("missing field `decision`"), "{msg}");
        let msg = jv_err(
            r#""shims": {"x": {"binary": "x", "default": {"decision": "deny"}, "rules": [{"decision": "deny"}]}}"#,
        );
        assert!(msg.contains("missing field `subcommand`"), "{msg}");
        let msg = jv_err(
            r#""shims": {"x": {"binary": "x", "default": {"decision": "deny"}, "rules": [{"subcommand": ["a"]}]}}"#,
        );
        assert!(msg.contains("missing field `decision`"), "{msg}");
    }

    #[test]
    fn valid_shim_names() {
        for good in [
            "jj",
            "git",
            "sh-main",
            "cargo-publish",
            "a",
            "0",
            "7z",
            "g++",
            "python3.12",
            "a_b",
            "a.b",
            "stopit2",
            "stopit-grants",
            "xstopit",
        ] {
            let n: ShimName = good.parse().unwrap();
            assert_eq!(n.as_str(), good);
            assert_eq!(n.to_string(), good);
            assert_eq!(ShimName::try_from(good.to_owned()).unwrap(), n);
            let src =
                format!("[shims.\"{good}\"]\nbinary = \"x\"\ndefault = {{ decision = \"deny\" }}");
            assert!(toml_ok(&src).grants.shims.contains_key(&n), "{good}");
            let src = format!(
                r#""shims": {{"{good}": {{"binary": "x", "default": {{"decision": "deny"}}}}}}"#
            );
            assert!(jv_ok(&src).grants.shims.contains_key(&n), "{good}");
        }
    }

    #[test]
    fn invalid_shim_names() {
        for bad in [
            "stopit",
            "stopit-grant",
            "Git",
            "a/b",
            "-x",
            "",
            ".x",
            "_x",
            "+x",
            "a b",
            "a\u{e9}",
            "A",
            "a*",
            "a:b",
            "a\0b",
        ] {
            let msg = bad.parse::<ShimName>().unwrap_err().to_string();
            assert!(msg.contains("shim name"), "{bad:?}: {msg}");
            assert!(msg.contains(&format!("{bad:?}")), "{bad:?}: {msg}");
            if !bad.contains('\0') {
                let msg = toml_err(&format!(
                    "[shims.\"{bad}\"]\nbinary = \"x\"\ndefault = {{ decision = \"deny\" }}"
                ));
                assert!(msg.contains("shim name"), "{bad:?}: {msg}");
                let msg = jv_err(&format!(
                    r#""shims": {{"{bad}": {{"binary": "x", "default": {{"decision": "deny"}}}}}}"#
                ));
                assert!(msg.contains("shim name"), "{bad:?}: {msg}");
            }
        }
        for reserved in ["stopit", "stopit-grant"] {
            let msg = reserved.parse::<ShimName>().unwrap_err().to_string();
            assert!(msg.contains("reserved"), "{msg}");
        }
    }

    fn shim_with_binary_toml(bin: &str) -> String {
        format!("[shims.x]\nbinary = {bin:?}\ndefault = {{ decision = \"deny\" }}")
    }

    #[test]
    fn binary_names() {
        for good in [
            "git",
            "jj",
            "cargo",
            "python3.12",
            "g++",
            "x-y",
            "Foo",
            "\u{e9}",
        ] {
            let b: BinaryName = good.parse().unwrap();
            assert_eq!(b.as_str(), good);
            assert_eq!(b.to_string(), good);
            let m = toml_ok(&shim_with_binary_toml(good));
            assert_eq!(m.grants.shims[&sn("x")].binary, b);
        }
        for bad in [
            "/usr/bin/git",
            "a b",
            "",
            "a/b",
            ".",
            "..",
            "./git",
            "a\tb",
            "a\nb",
            "a\0b",
            " a",
            "a ",
        ] {
            let msg = bad.parse::<BinaryName>().unwrap_err().to_string();
            assert!(msg.contains("binary name"), "{bad:?}: {msg}");
            assert!(msg.contains(&format!("{bad:?}")), "{bad:?}: {msg}");
            if !bad.contains('\0') {
                let msg = toml_err(&shim_with_binary_toml(bad));
                assert!(msg.contains("binary name"), "{bad:?}: {msg}");
            }
        }
        let msg = jv_err(
            r#""shims": {"x": {"binary": "/usr/bin/git", "default": {"decision": "deny"}}}"#,
        );
        assert!(msg.contains("/usr/bin/git"), "{msg}");
        let msg =
            jv_err(r#""shims": {"x": {"binary": "a\u0000b", "default": {"decision": "deny"}}}"#);
        assert!(msg.contains("NUL"), "{msg}");
    }

    #[test]
    fn flags_validation() {
        for good in [
            "-c",
            "-A",
            "--config",
            "--config-toml",
            "--a",
            "-1",
            "---x",
            "--x=y",
        ] {
            let f: Flag = good.parse().unwrap();
            assert_eq!(f.as_str(), good);
            assert_eq!(f.to_string(), good);
            let src = format!(
                "[shims.x]\nbinary = \"x\"\ndeny_flags = [{good:?}]\ndefault = {{ decision = \"deny\" }}"
            );
            assert_eq!(toml_ok(&src).grants.shims[&sn("x")].deny_flags, vec![f]);
        }
        for bad in [
            "c", "-", "--", "-a b", "", "a-b", " -c", "-c ", "-a\tb", "-a\0b", "--a\n",
        ] {
            let msg = bad.parse::<Flag>().unwrap_err().to_string();
            assert!(msg.contains("invalid flag"), "{bad:?}: {msg}");
            assert!(msg.contains(&format!("{bad:?}")), "{bad:?}: {msg}");
            if !bad.contains('\0') {
                let src = format!(
                    "[shims.x]\nbinary = \"x\"\ndeny_flags = [{bad:?}]\ndefault = {{ decision = \"deny\" }}"
                );
                let msg = toml_err(&src);
                assert!(msg.contains("invalid flag"), "{bad:?}: {msg}");
            }
        }
        // Flags are also validated in rules.
        let msg = jv_err(
            r#""shims": {"x": {"binary": "x", "default": {"decision": "deny"},
                "rules": [{"subcommand": ["a"], "decision": "deny", "deny_flags": ["--"]}]}}"#,
        );
        assert!(msg.contains("invalid flag \"--\""), "{msg}");
        jv_err(
            r#""shims": {"x": {"binary": "x", "deny_flags": "-c", "default": {"decision": "deny"}}}"#,
        );
    }

    fn default_toml(inline: &str) -> String {
        format!("[shims.x]\nbinary = \"x\"\ndefault = {inline}")
    }

    fn rule_toml(inline: &str) -> String {
        format!(
            "[shims.x]\nbinary = \"x\"\ndefault = {{ decision = \"deny\" }}\nrules = [{inline}]"
        )
    }

    #[test]
    fn profile_is_forbidden_with_deny_and_required_otherwise() {
        // Defaults.
        let msg = toml_err(&default_toml("{ decision = \"deny\", profile = \"main\" }"));
        assert!(msg.contains("\"main\""), "{msg}");
        assert!(msg.contains("deny"), "{msg}");
        for d in ["allow", "ask"] {
            let msg = toml_err(&default_toml(&format!("{{ decision = \"{d}\" }}")));
            assert!(msg.contains(&format!("\"{d}\"")), "{msg}");
            assert!(msg.contains("profile is required"), "{msg}");
        }
        // Rules.
        let msg = toml_err(&rule_toml(
            "{ subcommand = [\"a\"], decision = \"deny\", profile = \"vcs.ro\" }",
        ));
        assert!(msg.contains("\"vcs.ro\""), "{msg}");
        for d in ["allow", "ask"] {
            let msg = toml_err(&rule_toml(&format!(
                "{{ subcommand = [\"a\"], decision = \"{d}\" }}"
            )));
            assert!(msg.contains("profile is required"), "{msg}");
        }
        // JSON.
        let msg = jv_err(
            r#""shims": {"x": {"binary": "x", "default": {"decision": "deny", "profile": "main"}}}"#,
        );
        assert!(msg.contains("\"main\""), "{msg}");
        let msg = jv_err(r#""shims": {"x": {"binary": "x", "default": {"decision": "allow"}}}"#);
        assert!(msg.contains("profile is required"), "{msg}");
        let msg = jv_err(
            r#""shims": {"x": {"binary": "x", "default": {"decision": "deny"},
                "rules": [{"subcommand": ["a"], "decision": "ask"}]}}"#,
        );
        assert!(msg.contains("profile is required"), "{msg}");
        // `null` is the same as absent.
        let m = jv_ok(
            r#""shims": {"x": {"binary": "x", "default": {"decision": "deny", "profile": null}}}"#,
        );
        assert_eq!(m.grants.shims[&sn("x")].default, act(Decision::Deny, None));
        // An invalid profile reference is still reported.
        let msg = toml_err(&default_toml("{ decision = \"ask\", profile = \"none\" }"));
        assert!(msg.contains("profile reference"), "{msg}");
        let msg = toml_err(&default_toml("{ decision = \"ask\", profile = \"Vcs\" }"));
        assert!(msg.contains("\"Vcs\""), "{msg}");
        // Unknown decisions.
        toml_err(&default_toml(
            "{ decision = \"Allow\", profile = \"main\" }",
        ));
        toml_err(&default_toml(
            "{ decision = \"prompt\", profile = \"main\" }",
        ));
    }

    #[test]
    fn subcommand_list_must_not_be_empty() {
        let msg = toml_err(&rule_toml("{ subcommand = [], decision = \"deny\" }"));
        assert!(msg.contains("at least one"), "{msg}");
        let msg = jv_err(
            r#""shims": {"x": {"binary": "x", "default": {"decision": "deny"},
                "rules": [{"subcommand": [], "decision": "deny"}]}}"#,
        );
        assert!(msg.contains("at least one"), "{msg}");
        // A bare string is not a list.
        toml_err(&rule_toml(
            "{ subcommand = \"status\", decision = \"deny\" }",
        ));
    }

    #[test]
    fn valid_subcommand_patterns() {
        for good in [
            "status",
            "op log",
            "git push",
            "bookmark *",
            "git remote *",
            "ls-remote",
            "a",
            "0",
            "a_b",
            "a-",
            "remote update",
            "x1 y2 z3",
        ] {
            let p: SubcommandPattern = good.parse().unwrap();
            assert_eq!(p.as_str(), good);
            assert_eq!(p.to_string(), good);
            assert_eq!(
                p.tokens().collect::<Vec<_>>(),
                good.split(' ').collect::<Vec<_>>()
            );
            let src = rule_toml(&format!(
                "{{ subcommand = [{good:?}], decision = \"deny\" }}"
            ));
            assert_eq!(
                toml_ok(&src).grants.shims[&sn("x")].rules[0].subcommand,
                vec![p]
            );
        }
    }

    #[test]
    fn invalid_subcommand_patterns() {
        for bad in [
            "",
            " status",
            "status ",
            "op  log",
            "*",
            "* log",
            "git --push",
            "Status",
            "-x",
            "--",
            "a * b",
            "**",
            "a**",
            "a*",
            "*a",
            "a\tb",
            "a/b",
            "_a",
            "a.b",
            " ",
        ] {
            let msg = bad.parse::<SubcommandPattern>().unwrap_err().to_string();
            assert!(msg.contains("subcommand pattern"), "{bad:?}: {msg}");
            assert!(msg.contains(&format!("{bad:?}")), "{bad:?}: {msg}");
            let src = rule_toml(&format!(
                "{{ subcommand = [{bad:?}], decision = \"deny\" }}"
            ));
            let msg = toml_err(&src);
            assert!(msg.contains("subcommand pattern"), "{bad:?}: {msg}");
        }
        let msg = jv_err(
            r#""shims": {"x": {"binary": "x", "default": {"decision": "deny"},
                "rules": [{"subcommand": ["status", "git --push"], "decision": "deny"}]}}"#,
        );
        assert!(msg.contains("git --push"), "{msg}");
        let msg = "git --push"
            .parse::<SubcommandPattern>()
            .unwrap_err()
            .to_string();
        assert!(msg.contains("flags"), "{msg}");
        let msg = "*".parse::<SubcommandPattern>().unwrap_err().to_string();
        assert!(msg.contains("lone"), "{msg}");
        let msg = "* log"
            .parse::<SubcommandPattern>()
            .unwrap_err()
            .to_string();
        assert!(msg.contains("last token"), "{msg}");
    }

    #[test]
    fn shim_specs_are_map_only() {
        for src in [
            r#""shims": {"x": []}"#,
            r#""shims": {"x": ["git", [], {"decision": "deny"}, []]}"#,
            r#""shims": {"x": {"binary": "x", "default": []}}"#,
            r#""shims": {"x": {"binary": "x", "default": ["deny", null]}}"#,
            r#""shims": {"x": {"binary": "x", "default": {"decision": "deny"}, "rules": [[]]}}"#,
            r#""shims": {"x": {"binary": "x", "default": {"decision": "deny"}, "rules": [[["a"], "deny", null, []]]}}"#,
            r#""shims": []"#,
        ] {
            let msg = jv_err(src);
            assert!(msg.contains("expected a map"), "{src}: {msg}");
        }
        for src in [
            "shims.x = []",
            "shims = []",
            "[shims.x]\nbinary = \"x\"\ndefault = []",
            "[shims.x]\nbinary = \"x\"\ndefault = [\"deny\"]",
            "[shims.x]\nbinary = \"x\"\ndefault = { decision = \"deny\" }\nrules = [[]]",
            "[shims.x]\nbinary = \"x\"\ndefault = { decision = \"deny\" }\nrules = [[[\"a\"], \"deny\"]]",
        ] {
            let msg = toml_err(src);
            assert!(msg.contains("expected a map"), "{src}: {msg}");
        }
    }

    #[test]
    fn unknown_shim_keys_are_rejected() {
        for (members, key) in [
            (
                r#""shims": {"x": {"binary": "x", "default": {"decision": "deny"}, "deny_flag": []}}"#,
                "deny_flag",
            ),
            (
                r#""shims": {"x": {"binary": "x", "default": {"decision": "deny"}, "rule": []}}"#,
                "rule",
            ),
            (
                r#""shims": {"x": {"binary": "x", "default": {"decision": "deny", "prof": "a"}}}"#,
                "prof",
            ),
            (
                r#""shims": {"x": {"binary": "x", "default": {"decision": "deny"},
                    "rules": [{"subcommand": ["a"], "decision": "deny", "subcommands": []}]}}"#,
                "subcommands",
            ),
            (
                r#""shims": {"x": {"binary": "x", "default": {"decision": "deny"},
                    "rules": [{"subcommand": ["a"], "decision": "deny", "deny_flag": []}]}}"#,
                "deny_flag",
            ),
        ] {
            let msg = jv_err(members);
            assert!(
                msg.contains(&format!("unknown field `{key}`")),
                "{members}: {msg}"
            );
        }
        for (src, key) in [
            (
                "[shims.x]\nbinary = \"x\"\ndefault = { decision = \"deny\" }\nextra = 1",
                "extra",
            ),
            (
                "[shims.x]\nbinary = \"x\"\ndefault = { decision = \"deny\", extra = 1 }",
                "extra",
            ),
            (
                "[shims.x]\nbinary = \"x\"\ndefault = { decision = \"deny\" }\nrules = [{ subcommand = [\"a\"], decision = \"deny\", extra = 1 }]",
                "extra",
            ),
        ] {
            let msg = toml_err(src);
            assert!(
                msg.contains(&format!("unknown field `{key}`")),
                "{src}: {msg}"
            );
        }
    }
}
