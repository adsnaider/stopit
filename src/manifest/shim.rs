//! The `shims` manifest section (DESIGN.md §7.1, §7.4).
//!
//! A shim is a command installed in `/run/stopit/bin` that forwards each
//! invocation to the broker, which decides what to do with it. A shim is
//! either:
//! * **Declarative (`cmd` + `default` + `rules`):** evaluates `rules` in
//!   first-match-wins order (`literal`, `prefix`, or `regex`) against the
//!   caller's space-joined arguments, falling back to `default`, and runs
//!   `cmd` followed by the caller's arguments in the chosen profile.
//! * **Proxy (`proxy`):** runs a host executable (protected across all
//!   profiles by default, like a `script` provider) with the caller's
//!   arguments as `argv` and `STOPIT_*` context environment variables, and
//!   reads a JSON [`ProxyResponse`] (`decision`, `cmd`, `profile`, `reason`)
//!   from its stdout.

use std::ffi::OsString;
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use regex_automata::meta::Regex;
use serde::Deserialize;
use serde::de::{self, Deserializer, SeqAccess, Visitor};

use super::{ContributedProfile, check_components};
use crate::config::ProfileRef;
use crate::error::ValueError;
use crate::policy::Decision;
use crate::serde_util::MapOnly;

/// The name of the built-in `stopit-grant` command (DESIGN.md §7.5).
pub const GRANT_SHIM: &str = "stopit-grant";

/// Shim names that belong to the built-in commands.
const RESERVED_SHIM_NAMES: [&str; 2] = ["stopit", GRANT_SHIM];

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

    /// The name of the built-in `stopit-grant`, which configuration cannot
    /// use.
    pub fn grant() -> Self {
        ShimName(GRANT_SHIM.to_owned())
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

/// An argument a shim puts before the caller's, such as `--no-pager` or
/// `"{workspace}"`.
///
/// Non-empty, containing no NUL. Exact `"{workspace}"` and `"{workspace}/…"`
/// expand to the sandbox workspace mount when the broker runs the shim;
/// relative components after `"{workspace}/"` must not be empty, `.`, `..`, or
/// contain further braces. Any other argument (including tool templates such
/// as `"{commit_id}"` or `"{workspace_id}"`) is passed literally.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct ShimArg(String);

impl ShimArg {
    /// The validated argument, before placeholder expansion.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Expands `"{workspace}"` and `"{workspace}/…"` against `workspace_mount`,
    /// leaving every other argument unchanged.
    pub fn expand(&self, workspace_mount: &Path) -> OsString {
        if self.0 == "{workspace}" {
            workspace_mount.as_os_str().to_os_string()
        } else if let Some(rest) = self.0.strip_prefix("{workspace}/") {
            workspace_mount.join(rest).into_os_string()
        } else {
            OsString::from(&self.0)
        }
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
        if let Some(rest) = s.strip_prefix("{workspace}/") {
            check_components(rest).map_err(bad)?;
        } else if s != "{workspace}" && s.contains("{workspace}") {
            return Err(bad(
                "{workspace} is only expanded as the whole argument \"{workspace}\" or prefix \
                 \"{workspace}/...\"; pass the flag and path as separate arguments",
            ));
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

/// The command a declarative shim or proxy response runs: a [`BinaryName`]
/// resolved via the target profile's `PATH`, plus any fixed [`ShimArg`]s
/// placed before (for a declarative shim) or comprising (for a proxy shim)
/// the arguments.
///
/// Deserializes from either a single string (`cmd = "cli"`) or a non-empty
/// array of strings (`cmd = ["jj", "--no-pager", "-R", "{workspace}"]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShimCmd {
    /// The program name, resolved in the target profile's `PATH`.
    pub binary: BinaryName,
    /// Arguments following `binary`.
    pub args: Vec<ShimArg>,
}

impl ShimCmd {
    /// Creates a command with `binary` and no extra arguments.
    pub fn new(binary: BinaryName) -> Self {
        ShimCmd {
            binary,
            args: Vec::new(),
        }
    }

    /// Creates a command with `binary` and `args`.
    pub fn with_args(binary: BinaryName, args: Vec<ShimArg>) -> Self {
        ShimCmd { binary, args }
    }
}

impl<'de> Deserialize<'de> for ShimCmd {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct CmdVisitor;

        impl<'de> Visitor<'de> for CmdVisitor {
            type Value = ShimCmd;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a program name string or a non-empty list of command arguments")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<ShimCmd, E> {
                let binary: BinaryName = v.parse().map_err(E::custom)?;
                Ok(ShimCmd::new(binary))
            }

            fn visit_string<E: de::Error>(self, v: String) -> Result<ShimCmd, E> {
                self.visit_str(&v)
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<ShimCmd, A::Error> {
                let Some(first) = seq.next_element::<String>()? else {
                    return Err(de::Error::custom(
                        "invalid shim `cmd`: command list must not be empty",
                    ));
                };
                let binary: BinaryName = first.parse().map_err(de::Error::custom)?;
                let mut args = Vec::new();
                while let Some(raw) = seq.next_element::<String>()? {
                    let arg: ShimArg = raw.parse().map_err(de::Error::custom)?;
                    args.push(arg);
                }
                Ok(ShimCmd { binary, args })
            }
        }

        deserializer.deserialize_any(CmdVisitor)
    }
}

/// A compiled regular expression used in a [`ShimRule`].
///
/// Compiled with `dot_matches_new_line(true)` and `utf8(false)` so `.` matches
/// across newlines in multi-line arguments and arbitrary byte slices in `argv`
/// can be matched without UTF-8 conversion failures.
#[derive(Debug, Clone)]
pub struct ShimRegex {
    pattern: String,
    compiled: Arc<Regex>,
}

impl ShimRegex {
    /// The original regex pattern string.
    pub fn as_str(&self) -> &str {
        &self.pattern
    }

    /// Whether `haystack` matches this regular expression.
    pub fn is_match(&self, haystack: &[u8]) -> bool {
        self.compiled.is_match(haystack)
    }
}

impl PartialEq for ShimRegex {
    fn eq(&self, other: &Self) -> bool {
        self.pattern == other.pattern
    }
}

impl Eq for ShimRegex {}

impl FromStr for ShimRegex {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        if s.is_empty() {
            return Err(ValueError::new(
                "invalid shim regex \"\": must not be empty",
            ));
        }
        if s.contains('\0') {
            return Err(ValueError::new(format!(
                "invalid shim regex {s:?}: must not contain NUL bytes"
            )));
        }
        let syntax = regex_automata::util::syntax::Config::new()
            .dot_matches_new_line(true)
            .unicode(false)
            .utf8(false);
        let compiled = Regex::builder()
            .syntax(syntax)
            .build(s)
            .map_err(|e| ValueError::new(format!("invalid shim regex {s:?}: {e}")))?;
        Ok(ShimRegex {
            pattern: s.to_owned(),
            compiled: Arc::new(compiled),
        })
    }
}

impl TryFrom<String> for ShimRegex {
    type Error = ValueError;

    fn try_from(s: String) -> Result<Self, ValueError> {
        s.parse()
    }
}

impl fmt::Display for ShimRegex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.pattern)
    }
}

/// A validated list of CLI short (`-x`) and long (`--name`) flags compiled
/// into a regex matching clustered short flags and unambiguous long-flag
/// prefix abbreviations on space-joined arguments.
#[derive(Debug, Clone)]
pub struct ShimFlags {
    flags: Vec<String>,
    compiled: ShimRegex,
}

impl PartialEq for ShimFlags {
    fn eq(&self, other: &Self) -> bool {
        self.flags == other.flags
    }
}

impl Eq for ShimFlags {}

impl ShimFlags {
    /// Parses and compiles a non-empty list of short (`-<char>`) and long
    /// (`--<name>`) flags.
    pub fn new(flags: Vec<String>) -> Result<Self, ValueError> {
        if flags.is_empty() {
            return Err(ValueError::new(
                "invalid shim flags []: must list at least one flag",
            ));
        }
        let mut short = String::new();
        let mut long = Vec::new();
        for flag in &flags {
            if flag.contains('\0') || flag.chars().any(char::is_whitespace) {
                return Err(ValueError::new(format!(
                    "invalid shim flag {flag:?}: must not contain whitespace or NUL bytes"
                )));
            }
            if let Some(name) = flag.strip_prefix("--") {
                if name.is_empty() || name.contains('=') {
                    return Err(ValueError::new(format!(
                        "invalid long shim flag {flag:?}: expected `--<name>` without `=`"
                    )));
                }
                long.push(long_flag_prefix_pattern(name));
            } else if let Some(rest) = flag.strip_prefix('-') {
                let mut chars = rest.chars();
                let Some(ch) = chars.next() else {
                    return Err(ValueError::new(
                        "invalid shim flag \"-\": expected `-<char>` or `--<name>`",
                    ));
                };
                if chars.next().is_some() || ch == '-' || ch == '=' {
                    return Err(ValueError::new(format!(
                        "invalid short shim flag {flag:?}: expected single-character `-<char>` or `--<name>`"
                    )));
                }
                short.push_str(&regex_escape_char(ch));
            } else {
                return Err(ValueError::new(format!(
                    "invalid shim flag {flag:?}: must start with `-` or `--`"
                )));
            }
        }
        let long_pat = long.join("|");
        let pattern = match (!short.is_empty(), !long_pat.is_empty()) {
            (true, true) => {
                format!(r"(?:^| )(?:-[^- =]*[{short}]|--(?:{long_pat})(?: |=|$))")
            }
            (true, false) => format!(r"(?:^| )-[^- =]*[{short}]"),
            (false, true) => format!(r"(?:^| )--(?:{long_pat})(?: |=|$)"),
            (false, false) => unreachable!("flags was checked non-empty"),
        };
        let compiled = pattern.parse()?;
        Ok(ShimFlags { flags, compiled })
    }

    /// The configured flag strings in order.
    pub fn flags(&self) -> &[String] {
        &self.flags
    }

    /// Whether `joined_args` contains any of the configured flags.
    pub fn is_match(&self, joined_args: &[u8]) -> bool {
        self.compiled.is_match(joined_args)
    }

    /// Compiled regex string.
    pub fn regex_str(&self) -> &str {
        self.compiled.as_str()
    }
}

fn long_flag_prefix_pattern(name: &str) -> String {
    let mut chars = name.chars().rev();
    let Some(last) = chars.next() else {
        return String::new();
    };
    let mut acc = regex_escape_char(last);
    for ch in chars {
        let escaped = regex_escape_char(ch);
        acc = format!("{escaped}(?:{acc})?");
    }
    acc
}

fn regex_escape_char(ch: char) -> String {
    match ch {
        '.' | '+' | '*' | '?' | '(' | ')' | '|' | '[' | ']' | '{' | '}' | '^' | '$' | '\\'
        | '-' => format!("\\{ch}"),
        _ => ch.to_string(),
    }
}

/// How a [`ShimRule`] matches the caller's space-joined arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShimMatcher {
    /// Matches when the space-joined arguments equal the string exactly.
    Literal(String),
    /// Matches when the space-joined arguments equal the prefix or start with
    /// `"{prefix} "` (argument boundary).
    Prefix(String),
    /// Matches when the regular expression matches the space-joined arguments.
    Regex(ShimRegex),
    /// Matches when any of the given short (`-x`, including clusters) or long
    /// (`--name`, including unambiguous prefix abbreviations) flags appear.
    Flags(ShimFlags),
}

impl ShimMatcher {
    /// Whether `joined_args` (the caller's arguments joined by single ASCII
    /// spaces) matches this rule.
    pub fn matches(&self, joined_args: &[u8]) -> bool {
        match self {
            ShimMatcher::Literal(lit) => joined_args == lit.as_bytes(),
            ShimMatcher::Prefix(pre) => {
                let p = pre.as_bytes();
                joined_args == p
                    || (joined_args.starts_with(p) && joined_args.get(p.len()) == Some(&b' '))
            }
            ShimMatcher::Regex(re) => re.is_match(joined_args),
            ShimMatcher::Flags(flags) => flags.is_match(joined_args),
        }
    }

    /// Canonical key string identifying this matcher in approval prompts,
    /// session caches, and persisted `.stopit.toml` updates.
    pub fn key(&self) -> String {
        match self {
            ShimMatcher::Literal(s) => format!("literal = {s:?}"),
            ShimMatcher::Prefix(s) => format!("prefix = {s:?}"),
            ShimMatcher::Regex(r) => format!("regex = {:?}", r.as_str()),
            ShimMatcher::Flags(f) => format!("flags = {:?}", f.flags()),
        }
    }

    /// Raw matcher pattern string.
    pub fn pattern(&self) -> &str {
        match self {
            ShimMatcher::Literal(s) | ShimMatcher::Prefix(s) => s.as_str(),
            ShimMatcher::Regex(r) => r.as_str(),
            ShimMatcher::Flags(f) => f.regex_str(),
        }
    }
}

/// Validates a `literal` matcher string.
pub fn validate_literal(s: &str) -> Result<String, ValueError> {
    if s.contains('\0') {
        return Err(ValueError::new(format!(
            "invalid shim literal {s:?}: must not contain NUL bytes"
        )));
    }
    Ok(s.to_owned())
}

/// Validates a `prefix` matcher string.
pub fn validate_prefix(s: &str) -> Result<String, ValueError> {
    let bad = |why: &str| ValueError::new(format!("invalid shim prefix {s:?}: {why}"));
    if s.is_empty() {
        return Err(bad("must not be empty"));
    }
    if s.contains('\0') {
        return Err(bad("must not contain NUL bytes"));
    }
    if s.starts_with(' ') || s.ends_with(' ') {
        return Err(bad("must not have leading or trailing spaces"));
    }
    Ok(s.to_owned())
}

/// A subcommand pattern for `stopit-grant --scope`, such as `status`,
/// `op log`, `git push` or `bookmark *`.
///
/// One or more tokens separated by single spaces. Each token matches
/// `[a-z0-9][a-z0-9_-]*`, except that the last token may be exactly `*`
/// (any subcommand below the preceding tokens). A lone `*` is rejected.
/// Flags are not subcommands, so tokens starting with `-` are rejected.
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

/// A first-match-wins rule in a declarative [`ShimSpec`].
///
/// Deserializes from a table or object only, never from a sequence.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "MapOnly<RawShimRule>")]
pub struct ShimRule {
    /// How this rule matches the caller's space-joined arguments.
    pub matcher: ShimMatcher,
    /// The outcome when `matcher` matches.
    pub decision: Decision,
    /// The target profile. `None` exactly when `decision` is `deny`.
    pub profile: Option<ProfileRef>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawShimRule {
    #[serde(default)]
    literal: Option<String>,
    #[serde(default)]
    prefix: Option<String>,
    #[serde(default)]
    regex: Option<String>,
    #[serde(default)]
    flags: Option<Vec<String>>,
    decision: Decision,
    #[serde(default)]
    profile: Option<ProfileRef>,
}

impl TryFrom<MapOnly<RawShimRule>> for ShimRule {
    type Error = ValueError;

    fn try_from(MapOnly(raw): MapOnly<RawShimRule>) -> Result<Self, ValueError> {
        let count = usize::from(raw.literal.is_some())
            + usize::from(raw.prefix.is_some())
            + usize::from(raw.regex.is_some())
            + usize::from(raw.flags.is_some());
        if count == 0 {
            return Err(ValueError::new(
                "invalid shim rule: must specify one of `literal`, `prefix`, `regex`, or `flags`",
            ));
        }
        if count > 1 {
            return Err(ValueError::new(
                "invalid shim rule: `literal`, `prefix`, `regex`, and `flags` are mutually exclusive",
            ));
        }
        let matcher = if let Some(lit) = raw.literal {
            ShimMatcher::Literal(validate_literal(&lit)?)
        } else if let Some(pre) = raw.prefix {
            ShimMatcher::Prefix(validate_prefix(&pre)?)
        } else if let Some(re) = raw.regex {
            ShimMatcher::Regex(re.parse()?)
        } else if let Some(flags) = raw.flags {
            ShimMatcher::Flags(ShimFlags::new(flags)?)
        } else {
            unreachable!("checked count == 1");
        };
        check_profile(raw.decision, raw.profile.as_ref())?;
        Ok(ShimRule {
            matcher,
            decision: raw.decision,
            profile: raw.profile,
        })
    }
}

/// The path to a proxy shim executable on the host (`proxy = "..."`).
///
/// May be an absolute path (`/path/to/proxy`), a home-anchored path
/// (`~/bin/proxy`), or a relative path (`scripts/proxy.sh`, resolved against
/// the declaring configuration file's directory). Must not be empty, contain
/// NUL bytes, trailing slashes, or `.` / `..` components.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct ProxySource(String);

impl ProxySource {
    /// The validated path string as written.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Expands `self` to a host path using `base_dir` (for relative paths) and
    /// `home` (for `~/...` paths).
    pub fn expand(&self, base_dir: &Path, home: &Path) -> PathBuf {
        if let Some(rest) = self.0.strip_prefix("~/") {
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

impl FromStr for ProxySource {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        let bad = |why: &str| ValueError::new(format!("invalid shim proxy path {s:?}: {why}"));
        if s.is_empty() {
            return Err(bad("must not be empty"));
        }
        if s.contains('\0') {
            return Err(bad("must not contain NUL bytes"));
        }
        if s == "/" || s == "~" || s == "~/" {
            return Err(bad("must name a file, not a root or home directory"));
        }
        if s.ends_with('/') {
            return Err(bad("must not end with `/`"));
        }
        let body = if let Some(rest) = s.strip_prefix("~/") {
            rest
        } else if let Some(rest) = s.strip_prefix('/') {
            rest
        } else if let Some(rest) = s.strip_prefix("./") {
            rest
        } else {
            s
        };
        check_components(body).map_err(bad)?;
        for comp in Path::new(body).components() {
            if matches!(comp, Component::CurDir | Component::ParentDir) {
                return Err(bad("must not contain `.` or `..` components"));
            }
        }
        Ok(ProxySource(s.to_owned()))
    }
}

impl TryFrom<String> for ProxySource {
    type Error = ValueError;

    fn try_from(s: String) -> Result<Self, ValueError> {
        s.parse()
    }
}

impl fmt::Display for ProxySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The mode-specific definition of a [`ShimSpec`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShimKind {
    /// A tombstone (`shims.<name> = false` or `{ enabled = false }`) that
    /// removes an inherited or lower-origin shim of the same name during merge.
    Disabled,
    /// A declarative shim with `cmd`, `default`, and first-match-wins `rules`.
    Declarative {
        /// The underlying binary and any fixed arguments prepended before the
        /// caller's arguments.
        cmd: ShimCmd,
        /// Fallback action when no rule in `rules` matches.
        default: ShimAction,
        /// Ordered rules evaluated first-match-wins.
        rules: Vec<ShimRule>,
    },
    /// A proxy shim backed by a host executable that outputs a JSON
    /// [`ProxyResponse`] on stdout.
    Proxy {
        /// The proxy executable path as written in configuration.
        proxy: ProxySource,
        /// Whether `proxy` is automatically `protected` across all profiles
        /// (default `true`).
        protect: bool,
        /// Canonical host path of `proxy`, resolved at session load time before
        /// any sandbox starts.
        resolved: Option<PathBuf>,
    },
}

/// One shim declaration (DESIGN.md §7.1).
///
/// Deserializes from a table or object, or `false` to tombstone/remove a shim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShimSpec {
    /// Whether foreground terminal calls run on a pseudo-terminal of their own.
    pub tty: bool,
    /// Declarative matching rules, proxy executable configuration, or disabled
    /// tombstone.
    pub kind: ShimKind,
}

impl ShimSpec {
    /// The declarative command (`cmd`) if this shim is [`ShimKind::Declarative`].
    pub fn cmd(&self) -> Option<&ShimCmd> {
        match &self.kind {
            ShimKind::Declarative { cmd, .. } => Some(cmd),
            ShimKind::Proxy { .. } | ShimKind::Disabled => None,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawShimSpec {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    cmd: Option<ShimCmd>,
    #[serde(default)]
    proxy: Option<ProxySource>,
    #[serde(default)]
    protect: Option<bool>,
    #[serde(default)]
    tty: bool,
    #[serde(default)]
    default: Option<ShimAction>,
    #[serde(default)]
    rules: Option<Vec<ShimRule>>,
}

impl TryFrom<MapOnly<RawShimSpec>> for ShimSpec {
    type Error = ValueError;

    fn try_from(MapOnly(raw): MapOnly<RawShimSpec>) -> Result<Self, ValueError> {
        if raw.enabled == Some(false) {
            if raw.cmd.is_some() && raw.proxy.is_some() {
                return Err(ValueError::new(
                    "invalid shim: `cmd` and `proxy` are mutually exclusive",
                ));
            }
            return Ok(ShimSpec {
                tty: false,
                kind: ShimKind::Disabled,
            });
        }
        match (raw.cmd, raw.proxy) {
            (Some(_), Some(_)) => Err(ValueError::new(
                "invalid shim: `cmd` and `proxy` are mutually exclusive",
            )),
            (None, None) => Err(ValueError::new(
                "invalid shim: missing field `cmd` (for a declarative shim) or `proxy` (for a proxy shim)",
            )),
            (Some(cmd), None) => {
                if raw.protect.is_some() {
                    return Err(ValueError::new(
                        "invalid shim: `protect` is only valid with `proxy`",
                    ));
                }
                let Some(default) = raw.default else {
                    return Err(ValueError::new(
                        "invalid shim: missing field `default` (required for a declarative shim)",
                    ));
                };
                Ok(ShimSpec {
                    tty: raw.tty,
                    kind: ShimKind::Declarative {
                        cmd,
                        default,
                        rules: raw.rules.unwrap_or_default(),
                    },
                })
            }
            (None, Some(proxy)) => {
                if raw.default.is_some() {
                    return Err(ValueError::new(
                        "invalid shim: `default` is not allowed with `proxy` (the proxy returns the decision)",
                    ));
                }
                if raw.rules.is_some() {
                    return Err(ValueError::new(
                        "invalid shim: `rules` is not allowed with `proxy` (the proxy returns the decision)",
                    ));
                }
                Ok(ShimSpec {
                    tty: raw.tty,
                    kind: ShimKind::Proxy {
                        proxy,
                        protect: raw.protect.unwrap_or(true),
                        resolved: None,
                    },
                })
            }
        }
    }
}

impl<'de> Deserialize<'de> for ShimSpec {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ShimSpecVisitor;

        impl<'de> Visitor<'de> for ShimSpecVisitor {
            type Value = ShimSpec;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a map or `false`")
            }

            fn visit_bool<E: de::Error>(self, v: bool) -> Result<ShimSpec, E> {
                if !v {
                    Ok(ShimSpec {
                        tty: false,
                        kind: ShimKind::Disabled,
                    })
                } else {
                    Err(E::custom(
                        "invalid shim: boolean `true` is not a shim definition; use `false` to disable a shim or a table with `cmd` or `proxy`",
                    ))
                }
            }

            fn visit_map<A: de::MapAccess<'de>>(self, map: A) -> Result<ShimSpec, A::Error> {
                let raw = RawShimSpec::deserialize(de::value::MapAccessDeserializer::new(map))?;
                ShimSpec::try_from(MapOnly(raw)).map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_any(ShimSpecVisitor)
    }
}

/// Target profile returned in a [`ProxyResponse`]: either the name of an
/// existing profile in the session or an inline profile definition compiled on
/// the fly for that invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyProfile {
    /// An existing profile in the session (e.g. `"main"`, `"vcs.remote"`).
    Named(ProfileRef),
    /// An inline profile (`{ "inherit": "...", "fs": ..., "env": ..., ... }`)
    /// compiled for this single command.
    Inline(Box<ContributedProfile>),
}

impl<'de> Deserialize<'de> for ProxyProfile {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        match value {
            serde_json::Value::String(s) => {
                let r: ProfileRef = s.parse().map_err(de::Error::custom)?;
                Ok(ProxyProfile::Named(r))
            }
            serde_json::Value::Object(_) => {
                let cp: ContributedProfile =
                    serde_json::from_value(value).map_err(de::Error::custom)?;
                Ok(ProxyProfile::Inline(Box::new(cp)))
            }
            _ => Err(de::Error::custom(
                "invalid proxy `profile`: expected a profile name string or an inline profile object",
            )),
        }
    }
}

/// The command returned in a [`ProxyResponse`]: a [`BinaryName`] resolved in
/// the target profile's `PATH`, plus literal arguments (which may include
/// empty strings, unlike [`ShimArg`], but must not contain NUL bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyCmd {
    /// The program name, resolved in the target profile's `PATH`.
    pub binary: BinaryName,
    /// Literal arguments passed to `binary`.
    pub args: Vec<String>,
}

impl<'de> Deserialize<'de> for ProxyCmd {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum RawCmd {
            Single(String),
            List(Vec<String>),
            Other(serde::de::IgnoredAny),
        }

        match RawCmd::deserialize(deserializer)? {
            RawCmd::Single(s) => {
                let binary: BinaryName = s.parse().map_err(de::Error::custom)?;
                Ok(ProxyCmd {
                    binary,
                    args: Vec::new(),
                })
            }
            RawCmd::List(mut items) => {
                if items.is_empty() {
                    return Err(de::Error::custom(
                        "invalid proxy `cmd`: list must not be empty",
                    ));
                }
                let first = items.remove(0);
                let binary: BinaryName = first.parse().map_err(de::Error::custom)?;
                for arg in &items {
                    if arg.contains('\0') {
                        return Err(de::Error::custom(format!(
                            "invalid proxy argument {arg:?}: must not contain NUL bytes"
                        )));
                    }
                }
                Ok(ProxyCmd {
                    binary,
                    args: items,
                })
            }
            RawCmd::Other(_) => Err(de::Error::custom(
                "invalid type for proxy `cmd`: expected a string or a non-empty list of strings",
            )),
        }
    }
}

/// The JSON decision printed to stdout by a proxy shim executable.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "MapOnly<RawProxyResponse>")]
pub struct ProxyResponse {
    /// Whether to allow, ask, or deny the command.
    pub decision: Decision,
    /// The command (`[binary, args...]`) to execute in the target sandbox.
    /// Required when `decision` is `allow` or `ask`.
    pub cmd: Option<ProxyCmd>,
    /// The target profile (existing profile name or inline profile object).
    /// Defaults to the caller's profile when omitted on `allow` or `ask`;
    /// `None` when `decision` is `deny`.
    pub profile: Option<ProxyProfile>,
    /// Optional human-readable reason for `deny` (printed to stderr) or `ask`
    /// (shown in the approval prompt).
    pub reason: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProxyResponse {
    decision: Decision,
    #[serde(default)]
    cmd: Option<ProxyCmd>,
    #[serde(default)]
    profile: Option<ProxyProfile>,
    #[serde(default)]
    reason: Option<String>,
}

impl TryFrom<MapOnly<RawProxyResponse>> for ProxyResponse {
    type Error = ValueError;

    fn try_from(MapOnly(raw): MapOnly<RawProxyResponse>) -> Result<Self, ValueError> {
        if let Some(reason) = &raw.reason
            && reason.contains('\0')
        {
            return Err(ValueError::new(
                "invalid proxy response `reason`: must not contain NUL bytes",
            ));
        }
        match raw.decision {
            Decision::Deny => {
                if raw.profile.is_some() {
                    return Err(ValueError::new(
                        "invalid proxy response: `profile` is not allowed when `decision` is \"deny\"",
                    ));
                }
                Ok(ProxyResponse {
                    decision: Decision::Deny,
                    cmd: raw.cmd,
                    profile: None,
                    reason: raw.reason,
                })
            }
            Decision::Allow | Decision::Ask => {
                if raw.cmd.is_none() {
                    return Err(ValueError::new(format!(
                        "invalid proxy response: `cmd` is required when `decision` is {:?}",
                        raw.decision.as_str()
                    )));
                }
                Ok(ProxyResponse {
                    decision: raw.decision,
                    cmd: raw.cmd,
                    profile: raw.profile,
                    reason: raw.reason,
                })
            }
        }
    }
}

impl ProxyResponse {
    /// Parses and validates a [`ProxyResponse`] from the proxy's stdout JSON.
    pub fn from_json_str(s: &str) -> Result<Self, String> {
        serde_json::from_str::<ProxyResponse>(s).map_err(|e| e.to_string())
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

    fn act(decision: Decision, profile: Option<&str>) -> ShimAction {
        ShimAction {
            decision,
            profile: profile.map(pr),
        }
    }

    fn cmd_of(binary: &str, args: &[&str]) -> ShimCmd {
        ShimCmd {
            binary: binary.parse().unwrap(),
            args: args.iter().map(|s| s.parse().unwrap()).collect(),
        }
    }

    fn rule_lit(lit: &str, decision: Decision, profile: Option<&str>) -> ShimRule {
        ShimRule {
            matcher: ShimMatcher::Literal(lit.to_owned()),
            decision,
            profile: profile.map(pr),
        }
    }

    fn rule_pre(pre: &str, decision: Decision, profile: Option<&str>) -> ShimRule {
        ShimRule {
            matcher: ShimMatcher::Prefix(pre.to_owned()),
            decision,
            profile: profile.map(pr),
        }
    }

    fn rule_re(re: &str, decision: Decision, profile: Option<&str>) -> ShimRule {
        ShimRule {
            matcher: ShimMatcher::Regex(re.parse().unwrap()),
            decision,
            profile: profile.map(pr),
        }
    }

    fn spec(cmd: ShimCmd, default: ShimAction, rules: Vec<ShimRule>) -> ShimSpec {
        ShimSpec {
            tty: false,
            kind: ShimKind::Declarative {
                cmd,
                default,
                rules,
            },
        }
    }

    #[test]
    fn shim_tty_defaults_to_false_and_parses_boolean() {
        let m = toml_ok(
            r#"
            [shims.tui]
            cmd = "tui"
            tty = true
            default = { decision = "allow", profile = "main" }

            [shims.plain]
            cmd = "plain"
            tty = false
            default = { decision = "allow", profile = "main" }
            "#,
        );
        assert!(m.grants.shims[&sn("tui")].tty);
        assert!(!m.grants.shims[&sn("plain")].tty);
        let j = jv_ok(
            r#""shims": {
                "tui": {"cmd": "tui", "tty": true, "default": {"decision": "allow", "profile": "main"}},
                "plain": {"cmd": "plain", "tty": false, "default": {"decision": "allow", "profile": "main"}}
            }"#,
        );
        assert_eq!(j, m);
        for bad in [r#"tty = "yes""#, r#"tty = 1"#, r#"tty = []"#, r#"tty = {}"#] {
            let text =
                format!("[shims.tui]\ncmd = \"tui\"\n{bad}\ndefault = {{ decision = \"deny\" }}\n");
            assert!(toml::from_str::<Manifest>(&text).is_err(), "{bad}");
        }
        for bad in [r#""yes""#, "1", "[]", "{}", "null"] {
            let msg = jv_err(&format!(
                r#""shims": {{"tui": {{"cmd": "tui", "tty": {bad}, "default": {{"decision": "deny"}}}}}}"#
            ));
            assert!(!msg.is_empty(), "{bad}");
        }
    }

    #[test]
    fn shim_cmd_accepts_string_or_list() {
        let m = toml_ok(
            r#"
            [shims.jj]
            cmd = ["jj", "--no-pager", "-R", "{workspace}"]
            default = { decision = "ask", profile = "main" }

            [shims.git]
            cmd = "git"
            default = { decision = "ask", profile = "main" }
            "#,
        );
        assert_eq!(
            m.grants.shims[&sn("jj")],
            spec(
                cmd_of("jj", &["--no-pager", "-R", "{workspace}"]),
                act(Decision::Ask, Some("main")),
                vec![]
            )
        );
        assert_eq!(
            m.grants.shims[&sn("git")],
            spec(cmd_of("git", &[]), act(Decision::Ask, Some("main")), vec![])
        );
        for bad in [
            r#"cmd = []"#,
            r#"cmd = [""]"#,
            r#"cmd = ["jj", ""]"#,
            r#"cmd = ["jj", "a\u0000b"]"#,
            r#"cmd = ["/usr/bin/jj"]"#,
            r#"cmd = 123"#,
        ] {
            let text = format!("[shims.jj]\n{bad}\ndefault = {{ decision = \"deny\" }}\n");
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

    #[test]
    fn disabled_shim_parses_from_false_or_enabled_false() {
        let want = ShimSpec {
            tty: false,
            kind: ShimKind::Disabled,
        };
        let m = toml_ok(
            r#"
            [shims]
            git = false
            jj = { enabled = false }
            "#,
        );
        assert_eq!(m.grants.shims[&sn("git")], want);
        assert_eq!(m.grants.shims[&sn("jj")], want);
        let j = jv_ok(r#""shims": { "git": false, "jj": { "enabled": false } }"#);
        assert_eq!(j.grants.shims[&sn("git")], want);
        assert_eq!(j.grants.shims[&sn("jj")], want);
        toml_err("[shims]\ngit = true");
        jv_err(r#""shims": { "git": true }"#);
    }

    #[test]
    fn declarative_rules_literal_prefix_and_regex_parse() {
        let m = toml_ok(
            r#"
            [shims.cargo-publish]
            cmd     = "cargo"
            default = { decision = "ask", profile = "publish" }
            rules   = [
              { regex = '(^|\s)--config(\s|=|$)', decision = "deny" },
              { literal = "publish --dry-run", decision = "allow", profile = "main" },
              { prefix = "publish", decision = "ask", profile = "publish" },
            ]
            "#,
        );
        assert_eq!(
            m.grants.shims[&sn("cargo-publish")],
            spec(
                cmd_of("cargo", &[]),
                act(Decision::Ask, Some("publish")),
                vec![
                    rule_re(r"(^|\s)--config(\s|=|$)", Decision::Deny, None),
                    rule_lit("publish --dry-run", Decision::Allow, Some("main")),
                    rule_pre("publish", Decision::Ask, Some("publish")),
                ],
            )
        );
    }

    #[test]
    fn proxy_shim_parses_and_validates() {
        let m = toml_ok(
            r#"
            [shims.git]
            proxy = "scripts/git-proxy.sh"
            tty = true

            [shims.jj]
            proxy = "~/bin/jj-proxy"
            protect = false
            "#,
        );
        assert_eq!(
            m.grants.shims[&sn("git")],
            ShimSpec {
                tty: true,
                kind: ShimKind::Proxy {
                    proxy: "scripts/git-proxy.sh".parse().unwrap(),
                    protect: true,
                    resolved: None,
                },
            }
        );
        assert_eq!(
            m.grants.shims[&sn("jj")],
            ShimSpec {
                tty: false,
                kind: ShimKind::Proxy {
                    proxy: "~/bin/jj-proxy".parse().unwrap(),
                    protect: false,
                    resolved: None,
                },
            }
        );
        // Mixing proxy with declarative fields is rejected.
        for bad in [
            r#"cmd = "git"
               proxy = "scripts/p.sh"
               default = { decision = "deny" }"#,
            r#"proxy = "scripts/p.sh"
               default = { decision = "deny" }"#,
            r#"proxy = "scripts/p.sh"
               rules = []"#,
            r#"cmd = "git"
               protect = true
               default = { decision = "deny" }"#,
        ] {
            let text = format!("[shims.x]\n{bad}\n");
            assert!(toml::from_str::<Manifest>(&text).is_err(), "{bad}");
        }
    }

    #[test]
    fn proxy_response_parses_named_and_inline_profiles() {
        let resp = ProxyResponse::from_json_str(
            r#"{"decision": "allow", "cmd": ["git", "status"], "profile": "vcs.local"}"#,
        )
        .unwrap();
        assert_eq!(resp.decision, Decision::Allow);
        assert_eq!(
            resp.cmd,
            Some(ProxyCmd {
                binary: "git".parse().unwrap(),
                args: vec!["status".to_owned()],
            })
        );
        assert_eq!(resp.profile, Some(ProxyProfile::Named(pr("vcs.local"))));

        // Omitted profile stays `None` (resolved to the caller's profile at runtime).
        let resp =
            ProxyResponse::from_json_str(r#"{"decision": "ask", "cmd": "jj", "reason": "push"}"#)
                .unwrap();
        assert_eq!(resp.decision, Decision::Ask);
        assert_eq!(
            resp.cmd,
            Some(ProxyCmd {
                binary: "jj".parse().unwrap(),
                args: Vec::new(),
            })
        );
        assert_eq!(resp.profile, None);
        assert_eq!(resp.reason.as_deref(), Some("push"));

        // Inline profile object.
        let resp = ProxyResponse::from_json_str(
            r#"{
                "decision": "allow",
                "cmd": ["git", "fetch"],
                "profile": {
                    "inherit": "vcs.local",
                    "network": { "mode": "full" }
                }
            }"#,
        )
        .unwrap();
        assert!(matches!(resp.profile, Some(ProxyProfile::Inline(_))));

        // Deny needs no cmd or profile.
        let resp =
            ProxyResponse::from_json_str(r#"{"decision": "deny", "reason": "no -c"}"#).unwrap();
        assert_eq!(resp.decision, Decision::Deny);
        assert_eq!(resp.reason.as_deref(), Some("no -c"));

        // Invalid responses.
        for bad in [
            r#"{"decision": "allow"}"#,
            r#"{"decision": "ask"}"#,
            r#"{"decision": "deny", "profile": "main"}"#,
            r#"{"decision": "allow", "cmd": [], "profile": "main"}"#,
            r#"{"decision": "allow", "cmd": ["git"], "extra": 1}"#,
        ] {
            assert!(ProxyResponse::from_json_str(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn matcher_semantics() {
        let lit = ShimMatcher::Literal("status".to_owned());
        assert!(lit.matches(b"status"));
        assert!(!lit.matches(b"status -v"));
        assert!(!lit.matches(b""));

        let empty_lit = ShimMatcher::Literal(String::new());
        assert!(empty_lit.matches(b""));
        assert!(!empty_lit.matches(b"status"));

        let pre = ShimMatcher::Prefix("git push".to_owned());
        assert!(pre.matches(b"git push"));
        assert!(pre.matches(b"git push --bookmark main"));
        assert!(!pre.matches(b"git pushover"));
        assert!(!pre.matches(b"git"));

        let re = ShimMatcher::Regex(r"^(--no-pager\s+)*git\s+push(\s|$)".parse().unwrap());
        assert!(re.matches(b"git push"));
        assert!(re.matches(b"--no-pager git push --bookmark main"));
        assert!(re.matches(b"git push -m line1\nline2"));
        assert!(!re.matches(b"git fetch"));

        let flags = ShimMatcher::Flags(
            ShimFlags::new(vec!["-R".to_owned(), "--config-file".to_owned()]).unwrap(),
        );
        assert!(flags.matches(b"-R /other status"));
        assert!(flags.matches(b"-R/other status"));
        assert!(flags.matches(b"-nR /other"));
        assert!(flags.matches(b"status --config-file /tmp/x"));
        assert!(flags.matches(b"status --conf=/tmp/x"));
        assert!(flags.matches(b"status --co /tmp/x"));
        assert!(!flags.matches(b"status --no-pager --color=never -n"));
        assert!(ShimFlags::new(Vec::new()).is_err());
        assert!(ShimFlags::new(vec!["--".to_owned()]).is_err());
        assert!(ShimFlags::new(vec!["-ab".to_owned()]).is_err());
        assert!(ShimFlags::new(vec!["status".to_owned()]).is_err());
    }

    #[test]
    fn profile_is_forbidden_with_deny_and_required_otherwise() {
        let msg = toml_err(
            "[shims.x]\ncmd = \"x\"\ndefault = { decision = \"deny\", profile = \"main\" }",
        );
        assert!(msg.contains("deny"), "{msg}");
        for d in ["allow", "ask"] {
            let msg = toml_err(&format!(
                "[shims.x]\ncmd = \"x\"\ndefault = {{ decision = \"{d}\" }}"
            ));
            assert!(msg.contains("profile is required"), "{msg}");
        }
        let msg = toml_err(
            "[shims.x]\ncmd = \"x\"\ndefault = { decision = \"deny\" }\nrules = [{ literal = \"a\", decision = \"deny\", profile = \"main\" }]",
        );
        assert!(msg.contains("deny"), "{msg}");
        for d in ["allow", "ask"] {
            let msg = toml_err(&format!(
                "[shims.x]\ncmd = \"x\"\ndefault = {{ decision = \"deny\" }}\nrules = [{{ literal = \"a\", decision = \"{d}\" }}]"
            ));
            assert!(msg.contains("profile is required"), "{msg}");
        }
    }

    #[test]
    fn rule_requires_exactly_one_matcher() {
        let msg = toml_err(
            "[shims.x]\ncmd = \"x\"\ndefault = { decision = \"deny\" }\nrules = [{ decision = \"deny\" }]",
        );
        assert!(msg.contains("must specify one of"), "{msg}");
        let msg = toml_err(
            "[shims.x]\ncmd = \"x\"\ndefault = { decision = \"deny\" }\nrules = [{ literal = \"a\", prefix = \"a\", decision = \"deny\" }]",
        );
        assert!(msg.contains("mutually exclusive"), "{msg}");
        let msg = toml_err(
            "[shims.x]\ncmd = \"x\"\ndefault = { decision = \"deny\" }\nrules = [{ regex = \"(\", decision = \"deny\" }]",
        );
        assert!(msg.contains("invalid shim regex"), "{msg}");
    }
}
