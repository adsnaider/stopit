//! Profile declarations (DESIGN.md §3.3, §3.6).
//!
//! This module only parses and validates syntax. References are not
//! resolved here: unknown targets, inheritance cycles and provider
//! contributed profiles are handled later.

use std::fmt;
use std::str::FromStr;

use serde::Deserialize;

use super::ProviderName;
use crate::error::ValueError;
use crate::serde_util::MapOnly;

/// Name of the implicit main profile.
pub(super) const MAIN: &str = "main";
/// The `inherit` keyword that starts from the empty sandbox.
pub(super) const NONE: &str = "none";

/// Checks one name segment: non-empty, ASCII lowercase letters, digits, `-`
/// and `_`, starting with a letter.
pub(super) fn check_segment(seg: &str) -> Result<(), &'static str> {
    let mut chars = seg.chars();
    match chars.next() {
        None => return Err("must not be empty"),
        Some(c) if c.is_ascii_lowercase() => {}
        Some(_) => return Err("must start with a lowercase ASCII letter"),
    }
    if chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_') {
        Ok(())
    } else {
        Err("may only contain lowercase ASCII letters, digits, `-` and `_`")
    }
}

/// A single-segment profile name: `main` or a user-declared profile.
///
/// Non-empty, ASCII lowercase letters, digits, `-` and `_`, starting with a
/// letter. Dots are not allowed: they separate the provider name from the
/// profile name in provider-contributed profiles such as `vcs.local`, which
/// therefore cannot be declared; they are configured through their provider.
/// Parsing rejects the names `main` and `none`: `main` is implicit (obtain it
/// with [`ProfileName::main`], the only way to get one) and `none` is the
/// `inherit` keyword.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct ProfileName(String);

impl ProfileName {
    /// The implicit `main` profile. This is the only way to obtain it.
    pub fn main() -> Self {
        ProfileName(MAIN.to_owned())
    }

    /// The name as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for ProfileName {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        let bad = |why: &str| ValueError::new(format!("invalid profile name {s:?}: {why}"));
        if s == MAIN {
            return Err(bad(
                "`main` is reserved (it is implicit and inherits from the base)",
            ));
        }
        if s == NONE {
            return Err(bad("`none` is reserved (it is the `inherit` keyword)"));
        }
        if s.contains('.') {
            return Err(bad(
                "must not contain `.` (dots separate provider-contributed profiles)",
            ));
        }
        check_segment(s).map_err(bad)?;
        Ok(ProfileName(s.to_owned()))
    }
}

impl TryFrom<String> for ProfileName {
    type Error = ValueError;

    fn try_from(s: String) -> Result<Self, ValueError> {
        s.parse()
    }
}

impl fmt::Display for ProfileName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A reference to any profile: user-declared, `main`, or contributed by a
/// provider.
///
/// One or more `.`-separated segments, each following the [`ProfileName`]
/// character rules (so `main`, `harness` and `vcs.local` are valid; `vcs.`,
/// `.x`, `a..b` and `Vcs` are not). Only the whole value `none` is the
/// `inherit` keyword and is not a valid reference; `none` as another segment
/// (e.g. `main.none`) is syntactically valid. Whether the target exists is
/// not checked here.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct ProfileRef(String);

impl ProfileRef {
    /// A reference to the implicit `main` profile.
    pub fn main() -> Self {
        ProfileRef(MAIN.to_owned())
    }

    /// The full name `<provider>.<profile>` of a profile contributed by a
    /// provider. Always valid: both parts are valid segments.
    pub fn contributed(provider: &ProviderName, profile: &ProfileName) -> Self {
        ProfileRef(format!("{provider}.{profile}"))
    }

    /// The reference as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for ProfileRef {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        let bad = |why: &str| ValueError::new(format!("invalid profile reference {s:?}: {why}"));
        if s == NONE {
            return Err(bad("`none` is the `inherit` keyword, not a profile"));
        }
        for seg in s.split('.') {
            check_segment(seg).map_err(|why| {
                if seg.is_empty() {
                    bad("segments separated by `.` must not be empty")
                } else if why == "must start with a lowercase ASCII letter" {
                    bad("each `.`-separated segment must start with a lowercase ASCII letter")
                } else {
                    bad("each `.`-separated segment may only contain lowercase ASCII letters, digits, `-` and `_`")
                }
            })?;
        }
        Ok(ProfileRef(s.to_owned()))
    }
}

impl TryFrom<String> for ProfileRef {
    type Error = ValueError;

    fn try_from(s: String) -> Result<Self, ValueError> {
        s.parse()
    }
}

impl From<ProfileName> for ProfileRef {
    fn from(name: ProfileName) -> Self {
        ProfileRef(name.0)
    }
}

impl fmt::Display for ProfileRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Where a profile starts from (DESIGN.md §3.3).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub enum Inherit {
    /// Start from the parent profile's fully merged grants.
    Profile(ProfileRef),
    /// Start from the empty sandbox, ignoring the base (`"none"`).
    None,
}

impl Default for Inherit {
    fn default() -> Self {
        Inherit::Profile(ProfileRef::main())
    }
}

impl FromStr for Inherit {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        if s == NONE {
            Ok(Inherit::None)
        } else {
            s.parse().map(Inherit::Profile)
        }
    }
}

impl TryFrom<String> for Inherit {
    type Error = ValueError;

    fn try_from(s: String) -> Result<Self, ValueError> {
        s.parse()
    }
}

/// A `[profiles.<name>]` declaration: structure only. Grants are attached by
/// providers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(from = "MapOnly<RawProfileDecl>")]
pub struct ProfileDecl {
    /// Parent profile; defaults to `main`.
    pub inherit: Inherit,
}

/// Deserialization shape of [`ProfileDecl`]; see [`MapOnly`].
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawProfileDecl {
    inherit: Inherit,
}

impl From<MapOnly<RawProfileDecl>> for ProfileDecl {
    fn from(MapOnly(raw): MapOnly<RawProfileDecl>) -> Self {
        ProfileDecl {
            inherit: raw.inherit,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::config::Config;

    fn name(s: &str) -> ProfileName {
        s.parse().unwrap()
    }

    fn profiles(src: &str) -> BTreeMap<ProfileName, ProfileDecl> {
        Config::from_toml_str(src).unwrap().profiles
    }

    fn err(src: &str) -> String {
        match Config::from_toml_str(src) {
            Ok(c) => panic!("expected an error for {src:?}, got {c:?}"),
            Err(e) => e.to_string(),
        }
    }

    fn inherit_main() -> Inherit {
        Inherit::Profile(ProfileRef::main())
    }

    #[test]
    fn no_profiles_table_is_empty_map() {
        assert!(profiles("").is_empty());
        assert!(profiles("[profiles]").is_empty());
    }

    #[test]
    fn empty_profile_inherits_main() {
        let p = profiles("[profiles.harness]");
        assert_eq!(p.len(), 1);
        assert_eq!(p[&name("harness")].inherit, inherit_main());
        assert_eq!(p[&name("harness")], ProfileDecl::default());
    }

    #[test]
    fn inherit_none() {
        let p = profiles("[profiles.bare]\ninherit = \"none\"");
        assert_eq!(p[&name("bare")].inherit, Inherit::None);
    }

    #[test]
    fn inherit_contributed_and_explicit_main() {
        let p = profiles("[profiles.a]\ninherit = \"vcs.local\"\n[profiles.b]\ninherit = \"main\"");
        assert_eq!(
            p[&name("a")].inherit,
            Inherit::Profile("vcs.local".parse().unwrap())
        );
        assert_eq!(p[&name("b")].inherit, inherit_main());
    }

    #[test]
    fn several_profiles_in_one_document() {
        let p = profiles(
            r#"
            [profiles.harness]
            [profiles.bare]
            inherit = "none"
            [profiles.child]
            inherit = "harness"
            "#,
        );
        let keys: Vec<&str> = p.keys().map(ProfileName::as_str).collect();
        assert_eq!(keys, ["bare", "child", "harness"]);
        assert_eq!(p[&name("bare")].inherit, Inherit::None);
        assert_eq!(
            p[&name("child")].inherit,
            Inherit::Profile("harness".parse().unwrap())
        );
        assert_eq!(p[&name("harness")].inherit, inherit_main());
    }

    #[test]
    fn references_are_not_resolved() {
        // Unknown targets are a later commit's concern.
        let p = profiles("[profiles.a]\ninherit = \"does-not-exist\"");
        assert_eq!(
            p[&name("a")].inherit,
            Inherit::Profile("does-not-exist".parse().unwrap())
        );
    }

    #[test]
    fn valid_declared_names() {
        for good in ["harness", "a", "my-profile", "my_profile", "a1", "x-1_y"] {
            let n = name(good);
            assert_eq!(n.as_str(), good);
            assert_eq!(n.to_string(), good);
            let p = profiles(&format!("[profiles.{good}]"));
            assert!(p.contains_key(&n), "{good}");
        }
    }

    #[test]
    fn invalid_declared_names_are_rejected() {
        for bad in [
            "main",
            "none",
            "vcs.local",
            "Harness",
            "1abc",
            "-x",
            "_x",
            "",
            "har ness",
            "harn\u{e9}ss",
            "a.",
        ] {
            let own = bad.parse::<ProfileName>().unwrap_err().to_string();
            assert!(own.contains(&format!("{bad:?}")), "{bad:?}: {own}");
            // As a (quoted) TOML table key.
            let msg = err(&format!("[profiles.\"{bad}\"]"));
            assert!(msg.contains("profile name"), "{bad:?}: {msg}");
        }
    }

    #[test]
    fn dotted_table_header_cannot_declare_contributed_profile() {
        // Unquoted, this is the nested table `profiles.vcs` with key `local`.
        let msg = err("[profiles.vcs.local]");
        assert!(msg.contains("local"), "{msg}");
    }

    #[test]
    fn invalid_ref_character_message() {
        let msg = "a b".parse::<ProfileRef>().unwrap_err().to_string();
        assert!(
            msg.contains(
                "each `.`-separated segment may only contain lowercase ASCII letters, digits, `-` and `_`"
            ),
            "{msg}"
        );
    }

    #[test]
    fn reserved_names_explain_why() {
        let main = "main".parse::<ProfileName>().unwrap_err().to_string();
        assert!(main.contains("reserved"), "{main}");
        let none = "none".parse::<ProfileName>().unwrap_err().to_string();
        assert!(none.contains("reserved"), "{none}");
        assert_eq!(ProfileName::main().as_str(), "main");
    }

    #[test]
    fn valid_inherit_values() {
        for good in [
            "main",
            "harness",
            "vcs.local",
            "a.b.c",
            "my-profile",
            // `none` is only the keyword as a whole value.
            "main.none",
            "none.x",
        ] {
            let r: ProfileRef = good.parse().unwrap();
            assert_eq!(r.as_str(), good);
            assert_eq!(r.to_string(), good);
            let p = profiles(&format!("[profiles.x]\ninherit = \"{good}\""));
            assert_eq!(p[&name("x")].inherit, Inherit::Profile(r));
        }
    }

    #[test]
    fn invalid_inherit_values_are_rejected() {
        for bad in [
            "",
            "vcs.",
            ".x",
            "a..b",
            "Main",
            "Vcs",
            "vcs.Local",
            "1a",
            "a b",
            "a.1b",
            ".",
            "a/b",
        ] {
            let own = bad.parse::<Inherit>().unwrap_err().to_string();
            assert!(own.contains(&format!("{bad:?}")), "{bad:?}: {own}");
            assert!(own.contains("profile reference"), "{bad:?}: {own}");
            let msg = err(&format!("[profiles.x]\ninherit = \"{bad}\""));
            assert!(msg.contains("profile reference"), "{bad:?}: {msg}");
        }
        err("[profiles.x]\ninherit = 5");
    }

    #[test]
    fn none_is_not_a_profile_ref() {
        let e = "none".parse::<ProfileRef>().unwrap_err().to_string();
        assert!(e.contains("\"none\""), "{e}");
        assert_eq!("none".parse::<Inherit>().unwrap(), Inherit::None);
    }

    #[test]
    fn unknown_key_in_profile_is_rejected() {
        let msg = err("[profiles.harness]\ninheirt = \"none\"");
        assert!(msg.contains("inheirt"), "{msg}");
    }

    #[test]
    fn profile_name_converts_to_ref() {
        let r: ProfileRef = name("harness").into();
        assert_eq!(r.as_str(), "harness");
    }

    #[test]
    fn contributed_ref_is_prefixed_and_valid() {
        let provider: ProviderName = "my-vcs".parse().unwrap();
        let r = ProfileRef::contributed(&provider, &name("local"));
        assert_eq!(r.as_str(), "my-vcs.local");
        assert_eq!(r, "my-vcs.local".parse().unwrap());
    }
}
