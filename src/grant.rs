//! `stopit-grant` (DESIGN.md §7.5). A command in a sandbox asks for more
//! than its profile grants, for one command, and the user answers on the
//! server's terminal.
//!
//! ```text
//! stopit-grant [--scope '<program> [<words>]'] +net:<domain> +net:full
//!              +rw:<path> +ro:<path> -- <command...>
//! ```
//!
//! This module parses the request and builds what the broker needs: the
//! manifest of a temporary profile that inherits the caller's and adds the
//! grants, the lines the prompt shows, and the key a "for this session"
//! answer is remembered under. The broker compiles the profile with the
//! session's other providers, so every check a configuration rule passes
//! applies to a grant too.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::config::{ProfileName, ProfileRef, ProviderName, ProviderOrigin};
use crate::manifest::{BinaryName, Domain, Manifest, PathPattern, SubcommandPattern};
use crate::policy::NetworkMode;
use crate::provider::{ProviderOutput, SUPERVISOR_PROVIDER_NAME};
use crate::spec::NetworkSpec;

/// The usage line the broker prints with a refusal.
pub const USAGE: &str = "usage: stopit-grant [--scope '<program> [<words>]'] +net:<domain> \
                         +net:full +rw:<path> +ro:<path> -- <command...>";

/// The most grants one request may hold, so a prompt stays readable.
pub const MAX_GRANTS: usize = 16;

/// Which commands a "for this session" answer covers: `program`, with its
/// leading words matching `pattern` if there is one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    /// The program, as the command names it.
    pub program: BinaryName,
    /// The words after it, as in a shim rule.
    pub pattern: Option<SubcommandPattern>,
}

impl Scope {
    /// The scope as written, `cargo publish`.
    pub fn text(&self) -> String {
        match &self.pattern {
            Some(p) => format!("{} {}", self.program, p),
            None => self.program.to_string(),
        }
    }

    /// Whether `command`, program first, is in the scope.
    pub fn covers(&self, command: &[Vec<u8>]) -> bool {
        let Some((program, args)) = command.split_first() else {
            return false;
        };
        program.as_slice() == self.program.as_str().as_bytes()
            && self.pattern.as_ref().is_none_or(|p| {
                crate::broker::pattern_matches(p, &crate::broker::leading_words(args))
            })
    }
}

/// A parsed `stopit-grant` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRequest {
    /// Domains to reach through the proxy.
    pub net: BTreeSet<Domain>,
    /// Whether the command gets the full network.
    pub full: bool,
    /// Paths to mount read-write, as written: absolute or `~/…`.
    pub rw: BTreeSet<String>,
    /// Paths to mount read-only, as written.
    pub ro: BTreeSet<String>,
    /// What a session answer covers.
    pub scope: Scope,
    /// The command, program first.
    pub command: Vec<Vec<u8>>,
}

impl GrantRequest {
    /// Parses the arguments after `stopit-grant`.
    pub fn parse(args: &[Vec<u8>]) -> Result<GrantRequest, String> {
        let mut net = BTreeSet::new();
        let mut full = false;
        let mut rw = BTreeSet::new();
        let mut ro = BTreeSet::new();
        let mut scope_text: Option<String> = None;
        let mut grants = 0usize;
        let mut rest = args.iter();
        let command: Vec<Vec<u8>> = loop {
            let Some(arg) = rest.next() else {
                return Err("`--` and a command must follow the grants".to_owned());
            };
            if arg == b"--" {
                break rest.cloned().collect();
            }
            let text =
                std::str::from_utf8(arg).map_err(|_| format!("{} is not UTF-8", escape(arg)))?;
            if let Some(value) = text.strip_prefix("--scope=") {
                set_scope(&mut scope_text, value)?;
                continue;
            }
            if text == "--scope" {
                let value = rest.next().ok_or("--scope needs a value")?;
                let value = std::str::from_utf8(value)
                    .map_err(|_| format!("the scope {} is not UTF-8", escape(value)))?;
                set_scope(&mut scope_text, value)?;
                continue;
            }
            let Some((kind, value)) = text.strip_prefix('+').and_then(|g| g.split_once(':')) else {
                return Err(format!(
                    "{} is not a grant; grants are +net:, +rw: and +ro:, and `--` comes \
                     before the command",
                    escape(arg)
                ));
            };
            grants += 1;
            if grants > MAX_GRANTS {
                return Err(format!("at most {MAX_GRANTS} grants per command"));
            }
            match kind {
                "net" if value == "full" => full = true,
                "net" => {
                    net.insert(value.parse::<Domain>().map_err(|e| e.to_string())?);
                }
                "rw" => {
                    rw.insert(check_path(value)?);
                }
                "ro" => {
                    ro.insert(check_path(value)?);
                }
                _ => {
                    return Err(format!(
                        "unknown grant +{}:, expected +net:, +rw: or +ro:",
                        escape(kind.as_bytes())
                    ));
                }
            }
        };
        if grants == 0 {
            return Err("nothing to grant".to_owned());
        }
        if let Some(both) = rw.intersection(&ro).next() {
            return Err(format!("{both:?} is asked for both +rw: and +ro:"));
        }
        let (program, args) = command
            .split_first()
            .ok_or("`--` must be followed by a command")?;
        let program: BinaryName = std::str::from_utf8(program)
            .ok()
            .and_then(|p| p.parse().ok())
            .ok_or_else(|| {
                format!(
                    "the command {} must be a program name looked up in PATH",
                    escape(program)
                )
            })?;
        let scope = match scope_text {
            Some(text) => {
                let scope = parse_scope(&text)?;
                if !scope.covers(&command) {
                    return Err(format!(
                        "the command is not in the scope {:?}. The scope's words must match \
                         the command's words before its first flag.",
                        scope.text()
                    ));
                }
                scope
            }
            None => default_scope(program, args),
        };
        Ok(GrantRequest {
            net,
            full,
            rw,
            ro,
            scope,
            command,
        })
    }

    /// The paths, read-write ones first, each with whether it is
    /// read-write.
    pub fn paths(&self) -> impl Iterator<Item = (&str, bool)> {
        self.rw
            .iter()
            .map(|p| (p.as_str(), true))
            .chain(self.ro.iter().map(|p| (p.as_str(), false)))
    }

    /// The host path of `path`, a grant path, with `~` as `home`.
    pub fn host_path(path: &str, home: &Path) -> PathBuf {
        match path.strip_prefix("~/") {
            Some(rest) => home.join(rest),
            None => PathBuf::from(path),
        }
    }

    /// The network mode of the temporary profile, given the caller's mode
    /// and whether it shares the host's network namespace. `None` if the
    /// request does not change it. An error if `+net:` asks for nothing
    /// the caller lacks.
    pub fn network_mode(
        &self,
        caller: NetworkMode,
        shares_net: bool,
    ) -> Result<Option<NetworkMode>, String> {
        if !self.full && self.net.is_empty() {
            return Ok(None);
        }
        if shares_net {
            return Err("this sandbox shares the host's network already".to_owned());
        }
        if caller == NetworkMode::Full {
            return Err("this sandbox already has the full network".to_owned());
        }
        Ok(Some(if self.full {
            NetworkMode::Full
        } else {
            NetworkMode::Proxy
        }))
    }

    /// The provider output adding a profile that inherits `caller` with the
    /// grants, and that profile's full name. `mode` is its network mode
    /// from [`network_mode`](Self::network_mode). The profile has no
    /// `stopit-grant` of its own, so a granted command cannot ask for more
    /// on top of its grants.
    pub fn output(
        &self,
        caller: &ProfileRef,
        mode: Option<NetworkMode>,
    ) -> Result<(ProviderOutput, ProfileRef), String> {
        use toml::Value;
        let strings =
            |items: &mut dyn Iterator<Item = &str>| Value::Array(items.map(Value::from).collect());
        let mut profile = toml::Table::new();
        profile.insert("inherit".into(), caller.as_str().into());
        let mut sandbox = toml::Table::new();
        sandbox.insert("grant".into(), false.into());
        profile.insert("sandbox".into(), Value::Table(sandbox));
        let mut fs = toml::Table::new();
        if !self.rw.is_empty() {
            fs.insert(
                "rw".into(),
                strings(&mut self.rw.iter().map(String::as_str)),
            );
        }
        if !self.ro.is_empty() {
            fs.insert(
                "ro".into(),
                strings(&mut self.ro.iter().map(String::as_str)),
            );
        }
        if !fs.is_empty() {
            profile.insert("fs".into(), Value::Table(fs));
        }
        if let Some(mode) = mode {
            let mut network = toml::Table::new();
            network.insert("mode".into(), mode.as_str().into());
            if mode == NetworkMode::Proxy {
                network.insert(
                    "allow_domains".into(),
                    strings(&mut self.net.iter().map(Domain::as_str)),
                );
            }
            profile.insert("network".into(), Value::Table(network));
        }
        let local = profile_name(caller);
        let mut profiles = toml::Table::new();
        profiles.insert(local.as_str().into(), Value::Table(profile));
        let mut root = toml::Table::new();
        root.insert("profiles".into(), Value::Table(profiles));
        let manifest: Manifest = toml::from_str(&root.to_string()).map_err(|e| e.to_string())?;
        let provider: ProviderName = SUPERVISOR_PROVIDER_NAME
            .parse()
            .expect("the supervisor's name is a valid provider name");
        let full = ProfileRef::contributed(&provider, &local);
        let output = ProviderOutput {
            profile: ProfileRef::main(),
            manifest,
            origin: ProviderOrigin::Workspace,
        };
        Ok((output, full))
    }

    /// What the prompt lists for the grants, escaped: the network of the
    /// compiled temporary profile, `network`, which holds the domains it
    /// inherits too, and `paths`, the canonical host paths with whether
    /// each is read-write. Paths in or containing `home` say so.
    pub fn describe(
        home: &Path,
        network: Option<&NetworkSpec>,
        paths: &[(PathBuf, bool)],
    ) -> Vec<String> {
        let mut lines = Vec::new();
        match network {
            Some(NetworkSpec::Full) => lines
                .push("the full network, which reaches whatever this machine reaches".to_owned()),
            Some(NetworkSpec::Proxy { allow_domains }) => {
                let names: Vec<&str> = allow_domains.iter().map(Domain::as_str).collect();
                lines.push(format!("network through the proxy to {}", names.join(", ")));
            }
            _ => {}
        }
        for (host, rw) in paths {
            let mode = if *rw { "read-write" } else { "read-only" };
            let note = if host.starts_with(home) {
                " (in your home)"
            } else if home.starts_with(host) {
                " (holds your home)"
            } else {
                ""
            };
            lines.push(format!(
                "{mode} {}{note}",
                crate::escape::escape_bytes(host.as_os_str().as_encoded_bytes())
            ));
        }
        lines
    }

    /// The grants as one canonical string, for the session key: the same
    /// network and `paths` as [`describe`](Self::describe) shows.
    pub fn key(network: Option<&NetworkSpec>, paths: &[(PathBuf, bool)]) -> String {
        let mut parts: Vec<String> = Vec::new();
        match network {
            Some(NetworkSpec::Full) => parts.push("net:full".to_owned()),
            Some(NetworkSpec::Proxy { allow_domains }) => {
                parts.extend(allow_domains.iter().map(|d| format!("net:{d}")))
            }
            _ => {}
        }
        for (host, rw) in paths {
            let mode = if *rw { "rw" } else { "ro" };
            parts.push(format!("{mode}:{}", host.display()));
        }
        parts.join("\0")
    }
}

/// The local name of the temporary profile for `caller`: `grant`, unless a
/// user profile of that name asks, which `grant` would then name itself.
fn profile_name(caller: &ProfileRef) -> ProfileName {
    let name = if caller.as_str() == "grant" {
        "grant-for-grant"
    } else {
        "grant"
    };
    name.parse().expect("a valid profile name")
}

fn set_scope(scope: &mut Option<String>, value: &str) -> Result<(), String> {
    if scope.replace(value.to_owned()).is_some() {
        return Err("--scope is given twice".to_owned());
    }
    Ok(())
}

/// Parses `cargo publish` into a [`Scope`].
fn parse_scope(text: &str) -> Result<Scope, String> {
    let (program, words) = match text.split_once(' ') {
        Some((program, words)) => (program, Some(words)),
        None => (text, None),
    };
    let program: BinaryName = program
        .parse()
        .map_err(|e: crate::error::ValueError| format!("bad --scope: {e}"))?;
    let pattern = words
        .map(|w| {
            w.parse::<SubcommandPattern>()
                .map_err(|e| format!("bad --scope: {e}"))
        })
        .transpose()?;
    Ok(Scope { program, pattern })
}

/// The scope of a request without `--scope`: the program and its words
/// before the first flag, as far as they read as subcommand words.
fn default_scope(program: BinaryName, args: &[Vec<u8>]) -> Scope {
    let words: Vec<&str> = crate::broker::leading_words(args)
        .into_iter()
        .map_while(|w| std::str::from_utf8(w).ok())
        .take_while(|w| w.parse::<SubcommandPattern>().is_ok() && !w.contains(' ') && *w != "*")
        .collect();
    let pattern = (!words.is_empty()).then(|| {
        words
            .join(" ")
            .parse()
            .expect("words that parse alone parse together")
    });
    Scope { program, pattern }
}

/// Checks a grant path: absolute or `~/…` below the home, a valid path
/// rule, and no glob, `{workspace}`, `.`, `..` or control character, which
/// a prompt would have to show.
fn check_path(path: &str) -> Result<String, String> {
    if !(path.starts_with('/') || path.starts_with("~/")) {
        return Err(format!(
            "the path {path:?} must be absolute or start with `~/`"
        ));
    }
    if path.chars().any(char::is_control) {
        return Err(format!(
            "the path {path:?} must not hold a control character"
        ));
    }
    if path.contains(['*', '?', '[', ']', '{', '}', '\\']) {
        return Err(format!("the path {path:?} must not hold a glob character"));
    }
    let path = path.trim_end_matches('/');
    if path == "~" {
        return Err("a path under `~/` must name something below the home".to_owned());
    }
    if path.split('/').any(|c| c == "." || c == "..") {
        return Err(format!("the path {path:?} must not hold `.` or `..`"));
    }
    path.parse::<PathPattern>().map_err(|e| e.to_string())?;
    Ok(path.to_owned())
}

fn escape(bytes: &[u8]) -> String {
    crate::escape::escape_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(line: &[&str]) -> Vec<Vec<u8>> {
        line.iter().map(|a| a.as_bytes().to_vec()).collect()
    }

    fn parse(line: &[&str]) -> Result<GrantRequest, String> {
        GrantRequest::parse(&args(line))
    }

    #[test]
    fn grants_scope_and_command_parse() {
        let g = parse(&[
            "+net:crates.io",
            "+net:index.crates.io",
            "+rw:/var/cache/x/",
            "+ro:~/.cargo/credentials.toml",
            "--",
            "cargo",
            "publish",
            "--dry-run",
        ])
        .unwrap();
        assert_eq!(
            g.net.iter().map(Domain::as_str).collect::<Vec<_>>(),
            ["crates.io", "index.crates.io"]
        );
        assert!(!g.full);
        assert_eq!(g.rw.iter().collect::<Vec<_>>(), ["/var/cache/x"]);
        assert_eq!(
            g.ro.iter().collect::<Vec<_>>(),
            ["~/.cargo/credentials.toml"]
        );
        assert_eq!(g.scope.text(), "cargo publish");
        assert_eq!(g.command, args(&["cargo", "publish", "--dry-run"]));
        // `--scope`, either spelling, and `+net:full`.
        let g = parse(&["--scope", "cargo", "+net:full", "--", "cargo", "build"]).unwrap();
        assert!(g.full);
        assert_eq!(g.scope.text(), "cargo");
        let g = parse(&[
            "--scope=git remote *",
            "+net:full",
            "--",
            "git",
            "remote",
            "add",
        ])
        .unwrap();
        assert_eq!(g.scope.text(), "git remote *");
    }

    #[test]
    fn the_default_scope_is_the_program_and_its_subcommand_words() {
        let scope = |line: &[&str]| parse(line).unwrap().scope.text();
        assert_eq!(scope(&["+net:full", "--", "curl", "https://x.io"]), "curl");
        assert_eq!(
            scope(&["+net:full", "--", "npm", "run", "build", "--", "x"]),
            "npm run build"
        );
        assert_eq!(
            scope(&["+net:full", "--", "cargo", "-v", "publish"]),
            "cargo"
        );
        assert_eq!(scope(&["+net:full", "--", "make"]), "make");
        assert_eq!(scope(&["+net:full", "--", "a", "b", "C", "d"]), "a b");
    }

    #[test]
    fn a_scope_must_cover_the_command() {
        for (scope, command) in [
            ("cargo publish", &["cargo", "build"][..]),
            ("cargo publish", &["cargo", "--locked", "publish"]),
            ("cargo", &["curl", "x"]),
            ("git remote *", &["git", "remote"]),
        ] {
            let mut line = vec!["--scope", scope, "+net:full", "--"];
            line.extend(command);
            let e = parse(&line).unwrap_err();
            assert!(e.contains("not in the scope"), "{scope} {command:?}: {e}");
        }
        let covers =
            |scope: &str, command: &[&str]| parse_scope(scope).unwrap().covers(&args(command));
        assert!(covers("cargo publish", &["cargo", "publish", "--dry-run"]));
        assert!(covers("cargo publish", &["cargo", "publish", "x"]));
        assert!(!covers("cargo publish", &["cargo", "publisher"]));
        assert!(covers("cargo", &["cargo"]));
    }

    #[test]
    fn bad_requests_are_refused() {
        for (line, why) in [
            (&["--", "cargo"][..], "nothing to grant"),
            (&["+net:crates.io"], "`--` and a command"),
            (&["+net:crates.io", "--"], "followed by a command"),
            (&["+net:crates.io", "cargo"], "is not a grant"),
            (&["+disk:/x", "--", "a"], "unknown grant"),
            (&["+net:localhost", "--", "a"], "invalid domain"),
            (&["+net:1.2.3.4", "--", "a"], "invalid domain"),
            (&["+rw:x", "--", "a"], "absolute"),
            (&["+rw:~", "--", "a"], "absolute"),
            (&["+rw:{workspace}/x", "--", "a"], "absolute"),
            (&["+ro:/a/*", "--", "a"], "glob"),
            (&["+ro:/a/../b", "--", "a"], "`..`"),
            (&["+ro:~/./b", "--", "a"], "`..`"),
            (&["+ro:/", "--", "a"], "path"),
            (&["+ro:/a", "+rw:/a", "--", "a"], "both"),
            (&["+ro:/a", "--", "./tool"], "program name"),
            (&["+ro:/a", "--", "/bin/sh"], "program name"),
            (
                &["--scope", "x", "--scope", "x", "+ro:/a", "--", "x"],
                "twice",
            ),
            (
                &["--scope", "+ro:/a", "+net:full", "--", "x"],
                "bad --scope",
            ),
            (&["--scope", "x Y", "+ro:/a", "--", "x"], "bad --scope"),
            (&["--scope"], "needs a value"),
        ] {
            let e = parse(line).unwrap_err();
            assert!(e.contains(why), "{line:?}: {e}");
        }
        // Not UTF-8.
        let e = GrantRequest::parse(&[b"+ro:/\xff".to_vec(), b"--".to_vec(), b"a".to_vec()])
            .unwrap_err();
        assert!(e.contains("not UTF-8"), "{e}");
        // At most 16 grants.
        let mut line: Vec<String> = (0..17).map(|i| format!("+ro:/p{i}")).collect();
        line.extend(["--".into(), "a".into()]);
        let line: Vec<&str> = line.iter().map(String::as_str).collect();
        assert!(parse(&line).unwrap_err().contains("at most 16"));
        assert!(parse(&line[1..]).is_ok());
    }

    #[test]
    fn the_network_mode_follows_the_caller() {
        let net = parse(&["+net:crates.io", "--", "a"]).unwrap();
        assert_eq!(
            net.network_mode(NetworkMode::Loopback, false),
            Ok(Some(NetworkMode::Proxy))
        );
        assert_eq!(
            net.network_mode(NetworkMode::None, false),
            Ok(Some(NetworkMode::Proxy))
        );
        assert_eq!(
            net.network_mode(NetworkMode::Proxy, false),
            Ok(Some(NetworkMode::Proxy))
        );
        assert!(net.network_mode(NetworkMode::Full, false).is_err());
        let full = parse(&["+net:full", "+net:crates.io", "--", "a"]).unwrap();
        assert_eq!(
            full.network_mode(NetworkMode::Proxy, false),
            Ok(Some(NetworkMode::Full))
        );
        // A full caller has nothing more to get, `+net:full` included.
        let e = full.network_mode(NetworkMode::Full, false).unwrap_err();
        assert!(e.contains("already has the full network"), "{e}");
        // A sandbox in the host's network namespace is refused any `+net:`,
        // whatever its mode says.
        for mode in [NetworkMode::Loopback, NetworkMode::Proxy] {
            for g in [&net, &full] {
                let e = g.network_mode(mode, true).unwrap_err();
                assert!(e.contains("shares the host's network"), "{e}");
            }
        }
        // Paths alone leave the network alone, shared or not.
        let paths = parse(&["+ro:/x", "--", "a"]).unwrap();
        assert_eq!(paths.network_mode(NetworkMode::Full, false), Ok(None));
        assert_eq!(paths.network_mode(NetworkMode::Loopback, true), Ok(None));
    }

    #[test]
    fn the_temporary_profile_inherits_the_caller_and_adds_the_grants() {
        let g = parse(&["+net:crates.io", "+rw:/var/x", "+ro:~/.y", "--", "a"]).unwrap();
        let caller: ProfileRef = "vcs.local".parse().unwrap();
        let (output, name) = g.output(&caller, Some(NetworkMode::Proxy)).unwrap();
        assert_eq!(name.as_str(), "stopit.grant");
        assert_eq!(output.profile, ProfileRef::main());
        assert_eq!(output.origin, ProviderOrigin::Workspace);
        let profile = &output.manifest.profiles[&"grant".parse().unwrap()];
        assert_eq!(
            profile.inherit,
            crate::config::Inherit::Profile(caller.clone())
        );
        // No `stopit-grant` inside a granted command.
        assert_eq!(profile.grants.sandbox.grant, Some(false));
        let fs = &profile.grants.fs;
        assert_eq!(
            fs.rw.iter().map(PathPattern::as_str).collect::<Vec<_>>(),
            ["/var/x"]
        );
        assert_eq!(
            fs.ro.iter().map(PathPattern::as_str).collect::<Vec<_>>(),
            ["~/.y"]
        );
        assert_eq!(profile.grants.network.mode, Some(NetworkMode::Proxy));
        assert_eq!(
            profile
                .grants
                .network
                .allow_domains
                .iter()
                .map(|d| d.to_string())
                .collect::<Vec<_>>(),
            ["crates.io"]
        );
        // `+net:full` sets the mode and no domains.
        let full = parse(&["+net:full", "--", "a"]).unwrap();
        let (output, _) = full.output(&caller, Some(NetworkMode::Full)).unwrap();
        let profile = &output.manifest.profiles[&"grant".parse().unwrap()];
        assert_eq!(profile.grants.network.mode, Some(NetworkMode::Full));
        assert!(profile.grants.network.allow_domains.is_empty());
        assert!(profile.grants.fs.rw.is_empty() && profile.grants.fs.ro.is_empty());
        // Paths alone leave the network as the caller has it.
        let g = parse(&["+ro:/x", "--", "a"]).unwrap();
        let (output, _) = g.output(&caller, None).unwrap();
        let profile = &output.manifest.profiles[&"grant".parse().unwrap()];
        assert_eq!(profile.grants.network.mode, None);
        assert!(profile.grants.network.allow_domains.is_empty());
        // A user profile named `grant` does not inherit itself.
        let (output, name) = g.output(&"grant".parse().unwrap(), None).unwrap();
        assert_eq!(name.as_str(), "stopit.grant-for-grant");
        assert!(
            output
                .manifest
                .profiles
                .contains_key(&"grant-for-grant".parse().unwrap())
        );
    }

    fn proxy(domains: &[&str]) -> NetworkSpec {
        NetworkSpec::Proxy {
            allow_domains: domains.iter().map(|d| d.parse().unwrap()).collect(),
        }
    }

    #[test]
    fn prompts_and_keys_show_the_compiled_network_and_canonical_paths() {
        let home = Path::new("/home/me");
        let network = proxy(&["b.io", "a.io"]);
        let paths = [
            (PathBuf::from("/opt/x"), true),
            (PathBuf::from("/home/me/.cargo/c"), false),
            (PathBuf::from("/home"), false),
            (PathBuf::from("/home/me"), true),
            (PathBuf::from("/home/meet"), false),
        ];
        assert_eq!(
            GrantRequest::describe(home, Some(&network), &paths),
            [
                "network through the proxy to a.io, b.io",
                "read-write /opt/x",
                "read-only /home/me/.cargo/c (in your home)",
                "read-only /home (holds your home)",
                "read-write /home/me (in your home)",
                "read-only /home/meet",
            ]
        );
        assert_eq!(
            GrantRequest::key(Some(&network), &paths[..2]),
            "net:a.io\0net:b.io\0rw:/opt/x\0ro:/home/me/.cargo/c"
        );
        assert_eq!(
            GrantRequest::describe(home, Some(&NetworkSpec::Full), &[]),
            ["the full network, which reaches whatever this machine reaches"]
        );
        assert_eq!(GrantRequest::key(Some(&NetworkSpec::Full), &[]), "net:full");
        // A network the grant leaves alone is not listed.
        for network in [None, Some(&NetworkSpec::Loopback), Some(&NetworkSpec::None)] {
            assert_eq!(
                GrantRequest::describe(home, network, &paths[..1]),
                ["read-write /opt/x"]
            );
            assert_eq!(GrantRequest::key(network, &paths[..1]), "rw:/opt/x");
        }
        // Control bytes in a host path are escaped, not printed.
        let odd = [(PathBuf::from("/tmp/a\x1b[2Jb\nc"), false)];
        let line = &GrantRequest::describe(home, None, &odd)[0];
        assert!(!line.chars().any(char::is_control), "{line:?}");
        // A different domain set or mode gives a different key.
        assert_ne!(
            GrantRequest::key(Some(&proxy(&["a.io"])), &[]),
            GrantRequest::key(Some(&proxy(&["a.io", "b.io"])), &[])
        );
        assert_ne!(
            GrantRequest::key(None, &[(PathBuf::from("/x"), true)]),
            GrantRequest::key(None, &[(PathBuf::from("/x"), false)])
        );
    }

    #[test]
    fn grant_paths_are_plain_absolute_or_home_paths() {
        for (path, why) in [
            ("~/", "below the home"),
            ("~//", "below the home"),
            ("~", "absolute"),
            ("~user/x", "absolute"),
            ("/a/b\n/c", "control character"),
            ("/a\tb", "control character"),
            ("/a\x1bb", "control character"),
            ("/a/.", "`..`"),
            ("/a/./b", "`..`"),
            ("~/..", "`..`"),
            ("/a/..", "`..`"),
            ("/a?", "glob"),
            ("/a\\b", "glob"),
        ] {
            let e = parse(&[&format!("+ro:{path}"), "--", "a"]).unwrap_err();
            assert!(e.contains(why), "{path:?}: {e}");
        }
        // Trailing slashes go; dots inside a name are fine.
        let g = parse(&["+ro:~/.cargo/", "+rw:/a/b..c//", "+ro:/a/.x", "--", "a"]).unwrap();
        assert_eq!(g.ro.iter().collect::<Vec<_>>(), ["/a/.x", "~/.cargo"]);
        assert_eq!(g.rw.iter().collect::<Vec<_>>(), ["/a/b..c"]);
        // `~/x` maps onto the host home; absolute paths stay.
        let home = Path::new("/home/me");
        assert_eq!(
            GrantRequest::host_path("~/.cargo", home),
            Path::new("/home/me/.cargo")
        );
        assert_eq!(GrantRequest::host_path("/opt", home), Path::new("/opt"));
    }
}
