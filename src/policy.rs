//! Core policy enums shared by configuration, merging and enforcement.

use std::cmp::Ordering;
use std::fmt;

use serde::{Deserialize, Serialize};

/// How a path is presented to the sandbox (DESIGN.md §3.4).
///
/// Ordered by strictness (§3.5 rule 3, "strictest mode wins"): a greater
/// value is stricter, so `Rw < Ephemeral < Ro < Protected < Masked`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PathMode {
    /// Name exists but is empty.
    Masked,
    /// Real content; writes trigger an approval prompt.
    Protected,
    /// Real content, read-only.
    Ro,
    /// Writable, starts empty, deleted at session end.
    Ephemeral,
    /// Real content, writes go to the host.
    Rw,
}

impl PathMode {
    /// Strictness rank; greater is stricter. Kept explicit so that variant
    /// declaration order can never change policy semantics.
    fn rank(self) -> u8 {
        match self {
            PathMode::Rw => 0,
            PathMode::Ephemeral => 1,
            PathMode::Ro => 2,
            PathMode::Protected => 3,
            PathMode::Masked => 4,
        }
    }

    /// The lowercase spelling used in configuration.
    pub fn as_str(self) -> &'static str {
        match self {
            PathMode::Masked => "masked",
            PathMode::Protected => "protected",
            PathMode::Ro => "ro",
            PathMode::Ephemeral => "ephemeral",
            PathMode::Rw => "rw",
        }
    }

    /// Returns the stricter of the two modes.
    pub fn stricter(self, other: Self) -> Self {
        if other.rank() > self.rank() {
            other
        } else {
            self
        }
    }
}

impl PartialOrd for PathMode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PathMode {
    fn cmp(&self, other: &Self) -> Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl fmt::Display for PathMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Network access granted to a sandbox (DESIGN.md §8, merge rule in §3.5).
///
/// Ordered by permissiveness: `None < Loopback < Proxy < Full`. Within a
/// profile the most permissive granted mode wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkMode {
    /// No network at all.
    None,
    /// Loopback only.
    Loopback,
    /// Access through the filtering proxy.
    Proxy,
    /// Unrestricted host network.
    Full,
}

impl NetworkMode {
    /// Permissiveness rank; greater is more permissive.
    fn rank(self) -> u8 {
        match self {
            NetworkMode::None => 0,
            NetworkMode::Loopback => 1,
            NetworkMode::Proxy => 2,
            NetworkMode::Full => 3,
        }
    }

    /// The lowercase spelling used in configuration.
    pub fn as_str(self) -> &'static str {
        match self {
            NetworkMode::None => "none",
            NetworkMode::Loopback => "loopback",
            NetworkMode::Proxy => "proxy",
            NetworkMode::Full => "full",
        }
    }

    /// Returns the more permissive of the two modes.
    pub fn more_permissive(self, other: Self) -> Self {
        if other.rank() > self.rank() {
            other
        } else {
            self
        }
    }
}

impl PartialOrd for NetworkMode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NetworkMode {
    fn cmp(&self, other: &Self) -> Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl fmt::Display for NetworkMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Outcome of a policy rule for brokered tools (DESIGN.md §7.3.3 and §7.4):
/// shim rules and the `vcs` `fetch`/`push` settings.
///
/// Deliberately has no ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    /// Refuse the operation.
    Deny,
    /// Prompt the user.
    Ask,
    /// Permit the operation.
    Allow,
}

impl Decision {
    /// The lowercase spelling used in configuration.
    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Deny => "deny",
            Decision::Ask => "ask",
            Decision::Allow => "allow",
        }
    }
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Deserialize, Serialize)]
    struct Doc<T> {
        mode: T,
    }

    fn parse<T: for<'de> Deserialize<'de>>(s: &str) -> Result<T, toml::de::Error> {
        toml::from_str::<Doc<T>>(&format!("mode = \"{s}\"")).map(|d| d.mode)
    }

    // Keep the arrays below in sync with the enums: each guard is an
    // exhaustive match, so adding a variant breaks the build here.
    const PATH_MODES: [PathMode; 5] = [
        PathMode::Masked,
        PathMode::Protected,
        PathMode::Ro,
        PathMode::Ephemeral,
        PathMode::Rw,
    ];
    const _: fn(PathMode) = |m| match m {
        PathMode::Masked
        | PathMode::Protected
        | PathMode::Ro
        | PathMode::Ephemeral
        | PathMode::Rw => {}
    };

    const NETWORK_MODES: [NetworkMode; 4] = [
        NetworkMode::None,
        NetworkMode::Loopback,
        NetworkMode::Proxy,
        NetworkMode::Full,
    ];
    const _: fn(NetworkMode) = |m| match m {
        NetworkMode::None | NetworkMode::Loopback | NetworkMode::Proxy | NetworkMode::Full => {}
    };

    const DECISIONS: [Decision; 3] = [Decision::Deny, Decision::Ask, Decision::Allow];
    const _: fn(Decision) = |d| match d {
        Decision::Deny | Decision::Ask | Decision::Allow => {}
    };

    fn roundtrip<T>(variants: &[T], names: &[&str])
    where
        T: for<'de> Deserialize<'de> + Serialize + fmt::Display + fmt::Debug + PartialEq + Copy,
    {
        assert_eq!(variants.len(), names.len());
        for (v, name) in variants.iter().zip(names) {
            assert_eq!(parse::<T>(name).unwrap(), *v);
            assert_eq!(v.to_string(), *name);
            assert_eq!(
                toml::to_string(&Doc { mode: *v }).unwrap(),
                format!("mode = \"{name}\"\n")
            );
        }
    }

    #[test]
    fn variants_parse_and_display_lowercase() {
        roundtrip(
            &PATH_MODES,
            &["masked", "protected", "ro", "ephemeral", "rw"],
        );
        roundtrip(&NETWORK_MODES, &["none", "loopback", "proxy", "full"]);
        roundtrip(&DECISIONS, &["deny", "ask", "allow"]);
    }

    #[test]
    fn unknown_strings_are_rejected() {
        for bad in ["cow", "RO", "read-only", "", "Rw"] {
            assert!(parse::<PathMode>(bad).is_err(), "{bad:?}");
        }
        for bad in ["NONE", "Full", "host", ""] {
            assert!(parse::<NetworkMode>(bad).is_err(), "{bad:?}");
        }
        for bad in ["Allow", "prompt", "ALLOW", ""] {
            assert!(parse::<Decision>(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn path_mode_strictness_chain() {
        use PathMode::*;
        assert!(Rw < Ephemeral && Ephemeral < Ro && Ro < Protected && Protected < Masked);
    }

    #[test]
    fn network_mode_permissiveness_chain() {
        assert!(NetworkMode::None < NetworkMode::Loopback);
        assert!(NetworkMode::Loopback < NetworkMode::Proxy);
        assert!(NetworkMode::Proxy < NetworkMode::Full);
    }

    #[test]
    fn stricter_is_commutative_idempotent_and_consistent() {
        for a in PATH_MODES {
            assert_eq!(a.stricter(a), a);
            for b in PATH_MODES {
                assert_eq!(a == b, a.cmp(&b) == Ordering::Equal);
                assert_eq!(a.stricter(b), b.stricter(a));
                assert_eq!(a.stricter(b), a.max(b));
                assert!(a.stricter(b) >= a && a.stricter(b) >= b);
            }
        }
    }

    #[test]
    fn more_permissive_is_commutative_idempotent_and_consistent() {
        for a in NETWORK_MODES {
            assert_eq!(a.more_permissive(a), a);
            for b in NETWORK_MODES {
                assert_eq!(a == b, a.cmp(&b) == Ordering::Equal);
                assert_eq!(a.more_permissive(b), b.more_permissive(a));
                assert_eq!(a.more_permissive(b), a.max(b));
                assert!(a.more_permissive(b) >= a && a.more_permissive(b) >= b);
            }
        }
    }
}
