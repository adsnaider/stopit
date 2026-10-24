//! The `network` manifest section (DESIGN.md §8).

use std::fmt;
use std::str::FromStr;

use serde::Deserialize;

use crate::error::ValueError;
use crate::policy::NetworkMode;
use crate::serde_util::MapOnly;

/// The `network` section.
///
/// Deserializes from a table or object only, never from a sequence. `mode`
/// is an `Option` so that merging can tell "unset" from an explicit value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(from = "MapOnly<RawNetworkGrants>")]
pub struct NetworkGrants {
    /// Network mode.
    pub mode: Option<NetworkMode>,
    /// Hostnames reachable through the proxy (`mode = "proxy"`). Union on
    /// merge.
    pub allow_domains: Vec<Domain>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawNetworkGrants {
    mode: Option<NetworkMode>,
    allow_domains: Vec<Domain>,
}

impl From<MapOnly<RawNetworkGrants>> for NetworkGrants {
    fn from(MapOnly(raw): MapOnly<RawNetworkGrants>) -> Self {
        NetworkGrants {
            mode: raw.mode,
            allow_domains: raw.allow_domains,
        }
    }
}

/// Maximum length of a whole domain name, without a trailing dot.
const MAX_DOMAIN_LEN: usize = 253;
/// Maximum length of one label.
const MAX_LABEL_LEN: usize = 63;

/// A lowercase DNS hostname that the proxy may connect to.
///
/// 1–253 characters in total; dot-separated labels of 1–63 characters from
/// `[a-z0-9-]`, none starting or ending with `-`; at least two labels (so
/// `localhost` and a bare TLD are rejected). No trailing dot, no wildcards
/// (the design defines none), and no ports, schemes or paths. Uppercase is
/// rejected rather than normalised so that policy files are unambiguous;
/// internationalised names must be written in punycode (`xn--…`).
///
/// The final label must start with an ASCII letter (RFC 3696 §2), which
/// rejects IP literals: `1.2.3.4`, and also the short and hex IPv4 forms
/// that glibc accepts (`127.1`, `0x7f.1`, `0177.0.0.1`). TLS SNI cannot carry
/// an IP address, so the proxy could not match one anyway.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct Domain(String);

impl Domain {
    /// The validated hostname.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for Domain {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        let bad = |why: &str| ValueError::new(format!("invalid domain {s:?}: {why}"));
        if s.is_empty() {
            return Err(bad("must not be empty"));
        }
        if s.len() > MAX_DOMAIN_LEN {
            return Err(bad("must be at most 253 characters long"));
        }
        if s.ends_with('.') {
            return Err(bad("must not have a trailing dot"));
        }
        let mut labels = 0usize;
        for label in s.split('.') {
            labels += 1;
            if label.is_empty() {
                return Err(bad("must not contain empty labels"));
            }
            if label.len() > MAX_LABEL_LEN {
                return Err(bad("labels must be at most 63 characters long"));
            }
            for c in label.chars() {
                match c {
                    'a'..='z' | '0'..='9' | '-' => {}
                    'A'..='Z' => return Err(bad("must be lowercase")),
                    '*' => return Err(bad("wildcards are not supported")),
                    _ => {
                        return Err(bad(&format!(
                            "invalid character {c:?}: only a-z, 0-9, `-` and `.` are allowed \
                             (no ports, schemes or paths)"
                        )));
                    }
                }
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(bad("labels must not start or end with `-`"));
            }
        }
        if labels < 2 {
            return Err(bad("must have at least two labels, e.g. `example.com`"));
        }
        // RFC 3696 §2: the final label is never all-numeric, which keeps IP
        // literals (including short and hex IPv4 forms) out.
        let last = s.rsplit('.').next().unwrap_or_default();
        if !last.starts_with(|c: char| c.is_ascii_lowercase()) {
            return Err(bad(
                "must be a hostname, not an IP address: the last label must start with a letter",
            ));
        }
        Ok(Domain(s.to_owned()))
    }
}

impl TryFrom<String> for Domain {
    type Error = ValueError;

    fn try_from(s: String) -> Result<Self, ValueError> {
        s.parse()
    }
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::super::Manifest;
    use super::super::test_util::*;
    use super::*;

    fn dom(s: &str) -> Domain {
        s.parse().unwrap()
    }

    /// A hostname of exactly `n` characters made of 63-character labels
    /// (and a shorter last one), separated by dots.
    fn host_of_len(n: usize) -> String {
        let mut out = String::new();
        while out.len() < n {
            if !out.is_empty() {
                out.push('.');
            }
            let room = n - out.len();
            out.push_str(&"a".repeat(room.min(63)));
        }
        out
    }

    #[test]
    fn empty_network_section_is_default() {
        let want = NetworkGrants::default();
        assert_eq!(want.mode, None);
        assert!(want.allow_domains.is_empty());
        assert_eq!(Manifest::default().grants.network, want);
        assert_eq!(toml_ok("").grants.network, want);
        assert_eq!(toml_ok("[network]").grants.network, want);
        assert_eq!(jv_ok("").grants.network, want);
        assert_eq!(jv_ok(r#""network": {}"#).grants.network, want);
    }

    #[test]
    fn appendix_a_network_parses_from_toml_and_json() {
        let want = NetworkGrants {
            mode: Some(NetworkMode::Loopback),
            allow_domains: vec![],
        };
        assert_eq!(
            toml_ok("network = { mode = \"loopback\" }").grants.network,
            want
        );
        assert_eq!(
            jv_ok(r#""network": { "mode": "loopback" }"#).grants.network,
            want
        );
        // §3.6 spells out the empty domain list.
        assert_eq!(
            jv_ok(r#""network": { "mode": "loopback", "allow_domains": [] }"#)
                .grants
                .network,
            want
        );
    }

    #[test]
    fn proxy_example_parses_from_toml_and_json() {
        let want = NetworkGrants {
            mode: Some(NetworkMode::Proxy),
            allow_domains: vec![
                dom("cache.nixos.org"),
                dom("index.crates.io"),
                dom("static.crates.io"),
            ],
        };
        let toml = r#"
            [network]
            mode = "proxy"
            allow_domains = ["cache.nixos.org", "index.crates.io", "static.crates.io"]
        "#;
        assert_eq!(toml_ok(toml).grants.network, want);
        let json = r#""network": {"mode": "proxy", "allow_domains": ["cache.nixos.org", "index.crates.io", "static.crates.io"]}"#;
        assert_eq!(jv_ok(json).grants.network, want);
        // The inline form from §3.1.
        let toml = "network = { mode = \"proxy\", allow_domains = [\"cache.nixos.org\", \"index.crates.io\", \"static.crates.io\"] }";
        assert_eq!(toml_ok(toml).grants.network, want);
    }

    #[test]
    fn every_mode_parses() {
        for mode in ["none", "loopback", "proxy", "full"] {
            let m = toml_ok(&format!("network.mode = {mode:?}"));
            assert_eq!(m.grants.network.mode.unwrap().to_string(), mode);
            let j = jv_ok(&format!(r#""network": {{"mode": {mode:?}}}"#));
            assert_eq!(j.grants.network.mode, m.grants.network.mode);
        }
        for bad in ["host", "Proxy", "NONE", ""] {
            toml_err(&format!("network.mode = {bad:?}"));
            jv_err(&format!(r#""network": {{"mode": {bad:?}}}"#));
        }
        toml_err("network.mode = 1");
    }

    #[test]
    fn valid_domains() {
        let max_label = "a".repeat(63);
        let long_ok = host_of_len(253);
        assert_eq!(long_ok.len(), 253);
        for good in [
            "example.com",
            "a.b",
            "a.com",
            "cache.nixos.org",
            "static.crates.io",
            "api.anthropic.com",
            "a-b.com",
            "a--b.com",
            "0.com",
            "x1.y2.z3",
            "xn--bcher-kva.example",
            "a.b.c.d.e.f.g",
            &format!("{max_label}.com"),
            &format!("a.{max_label}"),
            &long_ok,
        ] {
            let d = good.parse::<Domain>().unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(d.as_str(), good);
            assert_eq!(d.to_string(), good);
            assert_eq!(Domain::try_from(good.to_owned()).unwrap(), d);
            let m = toml_ok(&format!("network.allow_domains = [{good:?}]"));
            assert_eq!(m.grants.network.allow_domains, vec![d.clone()]);
            let j = jv_ok(&format!(r#""network": {{"allow_domains": [{good:?}]}}"#));
            assert_eq!(j.grants.network.allow_domains, vec![d]);
        }
    }

    #[test]
    fn domain_length_limits() {
        let l63 = "a".repeat(63);
        let l64 = "a".repeat(64);
        assert!(format!("{l63}.com").parse::<Domain>().is_ok());
        let msg = format!("{l64}.com")
            .parse::<Domain>()
            .unwrap_err()
            .to_string();
        assert!(msg.contains("63"), "{msg}");
        assert!(msg.contains("invalid domain"), "{msg}");
        let msg = format!("a.{l64}")
            .parse::<Domain>()
            .unwrap_err()
            .to_string();
        assert!(msg.contains("63"), "{msg}");

        let ok = host_of_len(253);
        let too_long = host_of_len(254);
        assert_eq!((ok.len(), too_long.len()), (253, 254));
        assert!(ok.parse::<Domain>().is_ok());
        let msg = too_long.parse::<Domain>().unwrap_err().to_string();
        assert!(msg.contains("253"), "{msg}");
        assert!(msg.contains(&format!("{too_long:?}")), "{msg}");
        jv_err(&format!(
            r#""network": {{"allow_domains": ["{too_long}"]}}"#
        ));
        toml_err(&format!("network.allow_domains = [\"{too_long}\"]"));
    }

    #[test]
    fn invalid_domains() {
        for bad in [
            "",
            "localhost",
            "com",
            "a",
            "1.2.3.4",
            "127.1",
            "0x7f.1",
            "0177.0.0.1",
            "a.123",
            "a.1b",
            "-a.com",
            "a-.com",
            "a.-b.com",
            "a.b-.com",
            "a..com",
            ".a.com",
            ".",
            "..",
            "a.com.",
            "a.",
            "A.com",
            "a.COM",
            "Example.com",
            "a.com:443",
            "a.com:",
            "https://a.com",
            "a.com/path",
            "a.com/",
            "user@a.com",
            "*.a.com",
            "a.*.com",
            "a.c*m",
            "*",
            "*.com",
            "a_b.com",
            "a b.com",
            " a.com",
            "a.com ",
            "a.com\n",
            "bücher.example",
            "a.com?x=1",
            "a.com#x",
            "[::1]",
            "::1",
            "a.com\0",
            "a\0.com",
        ] {
            let msg = bad.parse::<Domain>().unwrap_err().to_string();
            assert!(msg.contains("invalid domain"), "{bad:?}: {msg}");
            assert!(msg.contains(&format!("{bad:?}")), "{bad:?}: {msg}");
            if !bad.contains('\0') {
                toml_err(&format!("network.allow_domains = [{bad:?}]"));
                jv_err(&format!(r#""network": {{"allow_domains": [{bad:?}]}}"#));
            }
        }
    }

    #[test]
    fn domain_error_reasons() {
        let reason = |s: &str| s.parse::<Domain>().unwrap_err().to_string();
        assert!(reason("A.com").contains("lowercase"));
        assert!(reason("*.a.com").contains("wildcard"));
        assert!(reason("localhost").contains("two labels"));
        for ip in ["1.2.3.4", "127.1", "0x7f.1", "0177.0.0.1", "a.123", "a.1b"] {
            assert!(reason(ip).contains("not an IP address"), "{ip}");
        }
        assert!(reason("a.com.").contains("trailing dot"));
        assert!(reason("a..com").contains("empty label"));
        assert!(reason("-a.com").contains("`-`"));
        assert!(reason("a.com:443").contains("':'"));
        assert!(reason("https://a.com").contains("':'"));
    }

    #[test]
    fn network_is_map_only_and_rejects_unknown_keys() {
        for src in [
            r#""network": []"#,
            r#""network": ["loopback", []]"#,
            r#""network": ["proxy", ["a.com"]]"#,
        ] {
            let msg = jv_err(src);
            assert!(msg.contains("expected a map"), "{src}: {msg}");
        }
        for src in ["network = []", "network = [\"none\"]"] {
            let msg = toml_err(src);
            assert!(msg.contains("expected a map"), "{src}: {msg}");
        }
        let msg = toml_err("network.modes = \"none\"");
        assert!(msg.contains("modes"), "{msg}");
        let msg = jv_err(r#""network": {"domains": []}"#);
        assert!(msg.contains("domains"), "{msg}");
        let msg = toml_err("[network]\nallow_domain = []");
        assert!(msg.contains("allow_domain"), "{msg}");
        toml_err("network.allow_domains = \"a.com\"");
    }
}
