//! The startup summary of what a sandbox is granted beyond the default base
//! (DESIGN.md §3).
//!
//! [`summary_lines`] is a pure function of one profile's [`SandboxSpec`] and
//! a [`SummaryContext`]: it returns the lines `stopit run` and `stopit shell`
//! print to stderr before the sandbox starts, without the `stopit: ` prefix.
//! The first line names the profile and the workspace, with the mode of the
//! workspace mount (or `not mounted`). Each further line is a grant that
//! **widens** access beyond what the default base already gives:
//!
//! ```text
//! profile "main" (workspace ~/proj rw at /workspace)
//!   rw       ~/.cargo/registry  (provider "cache")
//!   ro       /nix/store  (provider "tools")
//!   network  full
//!   script   provider "env" runs unprotected (protect = false)
//! ```
//!
//! What counts: host content mounted `rw`, `protected` (`prot`) or `ro`
//! outside the workspace, or inside it with a mode wider than the workspace
//! mount's (`rw` over `protected` over `ro`: an `rw` `{workspace}/out` under
//! an `ro` workspace); sockets left unmasked in `rw` grants; the network
//! beyond loopback, shared namespaces, re-enabled syscalls, brokered shims,
//! script providers with `protect = false`, and environment `pass` patterns
//! and `set` names beyond the default base's. Masked and ephemeral mounts,
//! mounts inside the workspace no wider than its own, and stopit's own rules
//! show nothing of the host, or nothing new, and are left out. Environment
//! values are never printed, only names.
//!
//! Everything taken from configuration or the filesystem is escaped
//! ([`escape_bytes`]), and paths under the host `HOME` are written with `~`.
//! A provider with more than [`LIST_LIMIT`] mounts of one mode (a Nix closure
//! can have thousands) gets one line with their count instead, and a long
//! list of names is cut after [`LIST_LIMIT`] of them.

use std::collections::BTreeSet;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::config::{Base, ProviderName};
use crate::escape::escape_bytes;
use crate::manifest::{EnvName, EnvPattern};
use crate::policy::PathMode;
use crate::provider::{SUPERVISOR_PROVIDER_NAME, default_base_manifest};
use crate::resolve::{MountSource, PlannedMount};
use crate::spec::{NetworkSpec, SandboxSpec};

/// How many entries of one kind the summary lists before it counts them
/// instead (mounts of one provider and mode) or cuts the list (names).
pub const LIST_LIMIT: usize = 10;

/// What the summary needs besides the spec.
#[derive(Debug, Clone, Copy)]
pub struct SummaryContext<'a> {
    /// The profile's full name.
    pub profile: &'a str,
    /// The host workspace, canonical.
    pub workspace: &'a Path,
    /// Where the workspace appears in the sandbox.
    pub workspace_mount: &'a Path,
    /// The host `HOME`, canonical: paths below it are written with `~`.
    pub home: &'a Path,
    /// The configuration's base: what its provider already grants is not
    /// listed.
    pub base: Base,
    /// The names of the script providers with `protect = false`.
    pub unprotected: &'a [&'a ProviderName],
}

/// The summary of `spec`, one line each, the header first (see the module
/// documentation). Escaped, and without the `stopit: ` prefix.
pub fn summary_lines(spec: &SandboxSpec, ctx: &SummaryContext<'_>) -> Vec<String> {
    let workspace_mode = workspace_mode(spec, ctx.workspace_mount);
    let workspace = path_text(ctx.workspace, ctx.home, None);
    let placed = match workspace_mode {
        Some(mode) => format!(
            "{workspace} {} at {}",
            mode.as_str(),
            path_text(ctx.workspace_mount, ctx.home, None)
        ),
        None => format!("{workspace}, not mounted"),
    };
    let mut lines = vec![format!(
        "profile \"{}\" (workspace {placed})",
        escape_str(ctx.profile)
    )];
    mount_lines(spec, ctx, workspace_mode, &mut lines);
    if !spec.mask_sockets && spec.mounts.iter().any(is_rw_host) {
        lines.push(grant("sockets", "not masked in rw grants"));
    }
    network_line(&spec.network, &mut lines);
    if !spec.namespaces.shared.is_empty() {
        let names = spec.namespaces.shared.iter().map(|ns| ns.as_str());
        lines.push(grant("share", &name_list(names)));
    }
    if !spec.allow_syscalls.is_empty() {
        let names = spec.allow_syscalls.iter().map(|s| s.as_str());
        lines.push(grant("syscalls", &name_list(names)));
    }
    for (name, (_, provider)) in &spec.shims {
        lines.push(grant(
            "broker",
            &format!(
                "{}  (provider \"{}\")",
                escape_str(name.as_str()),
                escape_str(provider.as_str())
            ),
        ));
    }
    for provider in ctx.unprotected {
        lines.push(grant(
            "script",
            &format!(
                "provider \"{}\" runs unprotected (protect = false)",
                escape_str(provider.as_str())
            ),
        ));
    }
    env_lines(spec, ctx.base, &mut lines);
    lines
}

/// One grant line: `label` padded to a column, then `text`, indented.
fn grant(label: &str, text: &str) -> String {
    format!("  {label:<8} {text}")
}

fn escape_str(s: &str) -> String {
    escape_bytes(s.as_bytes())
}

/// `path`, escaped, with the host `home` written `~`; for a mount's
/// sandbox side, `sandbox_home` stands for `~` instead.
fn path_text(path: &Path, host_home: &Path, sandbox_home: Option<&Path>) -> String {
    let home = sandbox_home.unwrap_or(host_home);
    // A `HOME` of `/` would make every path `~/…`.
    if home != Path::new("/")
        && let Ok(rest) = path.strip_prefix(home)
    {
        return if rest.as_os_str().is_empty() {
            "~".to_owned()
        } else {
            format!("~/{}", escape_bytes(rest.as_os_str().as_bytes()))
        };
    }
    escape_bytes(path.as_os_str().as_bytes())
}

/// `names` (already printable) joined with commas, cut after
/// [`LIST_LIMIT`] with a count of the rest.
fn name_list<'a>(names: impl IntoIterator<Item = &'a str>) -> String {
    let names: Vec<String> = names.into_iter().map(escape_str).collect();
    let mut text = names
        .iter()
        .take(LIST_LIMIT)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if names.len() > LIST_LIMIT {
        text.push_str(&format!(" and {} more", names.len() - LIST_LIMIT));
    }
    text
}

/// The mode of the mount at the workspace mount point, if any.
fn workspace_mode(spec: &SandboxSpec, workspace_mount: &Path) -> Option<PathMode> {
    spec.mounts
        .iter()
        .find(|m| m.sandbox == workspace_mount)
        .map(|m| m.mode)
}

/// How much of the host a mode shows: `rw` over `protected` over `ro`; the
/// other modes show nothing.
fn reach(mode: PathMode) -> u8 {
    match mode {
        PathMode::Rw => 3,
        PathMode::Protected => 2,
        PathMode::Ro => 1,
        PathMode::Masked | PathMode::Ephemeral => 0,
    }
}

/// Whether `mount` is host content mounted `rw`.
fn is_rw_host(mount: &PlannedMount) -> bool {
    mount.mode == PathMode::Rw && matches!(mount.source, MountSource::Host { .. })
}

/// Whether `mount` shows host content that the summary lists: a host source
/// in a mode that shows it, not one of stopit's own rules, and not inside
/// the workspace unless its mode reaches further than the workspace
/// mount's (`workspace_mode`, `None` if the workspace is not mounted).
fn widening(mount: &PlannedMount, workspace: &Path, workspace_mode: Option<PathMode>) -> bool {
    let MountSource::Host { path, .. } = &mount.source else {
        return false;
    };
    reach(mount.mode) > 0
        && mount.provider.as_str() != SUPERVISOR_PROVIDER_NAME
        && (!path.starts_with(workspace) || reach(mount.mode) > workspace_mode.map_or(0, reach))
}

fn mount_lines(
    spec: &SandboxSpec,
    ctx: &SummaryContext<'_>,
    workspace_mode: Option<PathMode>,
    lines: &mut Vec<String>,
) {
    let sandbox_home = Path::new(spec.system.home.as_str());
    for (mode, label) in [
        (PathMode::Rw, "rw"),
        (PathMode::Protected, "prot"),
        (PathMode::Ro, "ro"),
    ] {
        // By provider, in order of first appearance.
        let mut groups: Vec<(&ProviderName, Vec<&PlannedMount>)> = Vec::new();
        for mount in &spec.mounts {
            if mount.mode != mode || !widening(mount, ctx.workspace, workspace_mode) {
                continue;
            }
            match groups.iter_mut().find(|(p, _)| **p == mount.provider) {
                Some((_, mounts)) => mounts.push(mount),
                None => groups.push((&mount.provider, vec![mount])),
            }
        }
        for (provider, mounts) in groups {
            let by = format!("(provider \"{}\")", escape_str(provider.as_str()));
            if mounts.len() > LIST_LIMIT {
                lines.push(grant(label, &format!("{} mounts  {by}", mounts.len())));
                continue;
            }
            for mount in mounts {
                let MountSource::Host { path, .. } = &mount.source else {
                    continue;
                };
                let host = path_text(path, ctx.home, None);
                let sandbox = path_text(&mount.sandbox, ctx.home, Some(sandbox_home));
                let at = if host == sandbox {
                    host
                } else {
                    format!("{host} -> {sandbox}")
                };
                lines.push(grant(label, &format!("{at}  {by}")));
            }
        }
    }
}

fn network_line(network: &NetworkSpec, lines: &mut Vec<String>) {
    match network {
        NetworkSpec::None | NetworkSpec::Loopback => {}
        NetworkSpec::Full => lines.push(grant("network", "full")),
        NetworkSpec::Proxy { allow_domains } if allow_domains.is_empty() => {
            lines.push(grant("network", "proxy (no domains)"));
        }
        NetworkSpec::Proxy { allow_domains } => {
            lines.push(grant(
                "network",
                &format!(
                    "proxy to {}",
                    name_list(allow_domains.iter().map(|d| d.as_str()))
                ),
            ));
            let uploads: Vec<&str> = allow_domains
                .iter()
                .map(|d| d.as_str())
                .filter(|d| crate::proxy::accepts_uploads(d))
                .collect();
            if !uploads.is_empty() {
                lines.push(grant("uploads", &name_list(uploads)));
            }
        }
    }
}

/// The `pass` patterns and `set` names beyond the base's, names only.
fn env_lines(spec: &SandboxSpec, base: Base, lines: &mut Vec<String>) {
    let (base_pass, base_set): (BTreeSet<EnvPattern>, BTreeSet<EnvName>) = match base {
        Base::Default => default_base_manifest()
            .map(|m| {
                (
                    m.grants.env.pass.into_iter().collect(),
                    m.grants.env.set.into_keys().collect(),
                )
            })
            .unwrap_or_default(),
        Base::None => Default::default(),
    };
    let pass: BTreeSet<&str> = spec
        .env
        .pass
        .iter()
        .filter(|p| !base_pass.contains(*p))
        .map(EnvPattern::as_str)
        .collect();
    if !pass.is_empty() {
        lines.push(grant("env pass", &name_list(pass)));
    }
    let set = spec
        .env
        .set
        .keys()
        .filter(|k| !base_set.contains(*k))
        .map(EnvName::as_str);
    let set: Vec<&str> = set.collect();
    if !set.is_empty() {
        lines.push(grant("env set", &name_list(set)));
    }
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::expand::EntryKind;
    use crate::manifest::{
        Domain, OptInSyscall, PathPattern, ShareableNamespace, ShimName, ShimSpec,
    };
    use crate::resolve::EphemeralKey;

    const WS: &str = "/home/u/proj";
    const HOME: &str = "/home/u";

    fn provider(name: &str) -> ProviderName {
        name.parse().unwrap()
    }

    fn ctx<'a>(base: Base, unprotected: &'a [&'a ProviderName]) -> SummaryContext<'a> {
        SummaryContext {
            profile: "main",
            workspace: Path::new(WS),
            workspace_mount: Path::new("/workspace"),
            home: Path::new(HOME),
            base,
            unprotected,
        }
    }

    fn mount(host: &str, sandbox: &str, mode: PathMode, by: &str) -> PlannedMount {
        PlannedMount {
            sandbox: PathBuf::from(sandbox),
            source: MountSource::Host {
                path: PathBuf::from(host),
                kind: EntryKind::Dir,
            },
            mode,
            provider: provider(by),
            glob_link: false,
        }
    }

    fn lines(spec: &SandboxSpec) -> Vec<String> {
        summary_lines(spec, &ctx(Base::None, &[]))
    }

    // The workspace is under the host home, so written with `~`.
    // For a spec with nothing at the workspace mount, and with the
    // workspace mounted `rw`.
    const HEADER: &str = "profile \"main\" (workspace ~/proj, not mounted)";
    const HEADER_RW: &str = "profile \"main\" (workspace ~/proj rw at /workspace)";

    #[test]
    fn the_empty_sandbox_has_only_the_header() {
        assert_eq!(lines(&SandboxSpec::default()), [HEADER]);
    }

    #[test]
    fn the_default_base_has_only_the_header() {
        // What the default base grants, as `compile_session` plans it:
        // the workspace and what is inside it, masks, ephemeral
        // directories, loopback and the base's `pass`.
        let mut spec = SandboxSpec::default();
        spec.mounts = vec![
            mount(WS, "/workspace", PathMode::Rw, "base"),
            mount(
                "/home/u/proj/flake.lock",
                "/workspace/flake.lock",
                PathMode::Protected,
                "base",
            ),
            mount(
                "/home/u/proj/.env",
                "/workspace/.env",
                PathMode::Masked,
                "base",
            ),
            PlannedMount {
                sandbox: "/tmp".into(),
                source: MountSource::Ephemeral {
                    key: EphemeralKey::new(&PathPattern::new_unchecked("/tmp")),
                },
                mode: PathMode::Ephemeral,
                provider: provider("base"),
                glob_link: false,
            },
            mount(
                "/home/u/proj/.stopit.toml",
                "/workspace/.stopit.toml",
                PathMode::Protected,
                SUPERVISOR_PROVIDER_NAME,
            ),
        ];
        spec.network = NetworkSpec::Loopback;
        let m = default_base_manifest().unwrap();
        spec.env.pass = m.grants.env.pass.clone();
        spec.env.deny = m.grants.env.deny.clone();
        spec.mask_sockets = true;
        assert_eq!(summary_lines(&spec, &ctx(Base::Default, &[])), [HEADER_RW]);
    }

    #[test]
    fn mounts_inside_the_workspace_are_listed_only_if_wider_than_its_mount() {
        // `ro {workspace}` with an `rw` part of it.
        let mut spec = SandboxSpec::default();
        spec.mask_sockets = true;
        spec.mounts = vec![
            mount(WS, "/workspace", PathMode::Ro, "p"),
            mount("/home/u/proj/out", "/workspace/out", PathMode::Rw, "p"),
            mount("/home/u/proj/docs", "/workspace/docs", PathMode::Ro, "p"),
        ];
        assert_eq!(
            lines(&spec),
            [
                "profile \"main\" (workspace ~/proj ro at /workspace)",
                "  rw       ~/proj/out -> /workspace/out  (provider \"p\")",
            ]
        );
        // `rw {workspace}` with `protected` and `ro` parts: nothing wider.
        spec.mounts[0].mode = PathMode::Rw;
        spec.mounts[1].mode = PathMode::Protected;
        assert_eq!(lines(&spec), [HEADER_RW]);
        // An unmounted workspace: everything of it that is bound is listed,
        // even to another path.
        spec.mounts = vec![mount("/home/u/proj/secrets", "/x", PathMode::Ro, "p")];
        assert_eq!(
            lines(&spec),
            [HEADER, "  ro       ~/proj/secrets -> /x  (provider \"p\")",]
        );
    }

    #[test]
    fn unmasked_sockets_in_rw_grants_are_listed() {
        let mut spec = SandboxSpec::default();
        spec.mounts = vec![mount("/opt/x", "/opt/x", PathMode::Ro, "p")];
        // No `rw` mount: nothing for a socket to be reached through.
        assert_eq!(lines(&spec).len(), 2);
        spec.mounts.push(mount(WS, "/workspace", PathMode::Rw, "p"));
        assert_eq!(
            lines(&spec)[1..],
            [
                "  ro       /opt/x  (provider \"p\")",
                "  sockets  not masked in rw grants"
            ]
        );
        spec.mask_sockets = true;
        assert_eq!(lines(&spec).len(), 2);
    }

    #[test]
    fn mounts_outside_the_workspace_are_listed_by_mode() {
        let mut spec = SandboxSpec::default();
        spec.mask_sockets = true;
        spec.mounts = vec![
            mount("/nix/store", "/nix/store", PathMode::Ro, "tools"),
            mount(
                "/home/u/.cargo/registry",
                "/home/user/.cargo/registry",
                PathMode::Rw,
                "cache",
            ),
            mount("/etc/ssl", "/etc/ssl", PathMode::Protected, "certs"),
            mount("/opt/x", "/opt/y", PathMode::Ro, "tools"),
        ];
        assert_eq!(
            lines(&spec),
            [
                HEADER,
                "  rw       ~/.cargo/registry  (provider \"cache\")",
                "  prot     /etc/ssl  (provider \"certs\")",
                "  ro       /nix/store  (provider \"tools\")",
                "  ro       /opt/x -> /opt/y  (provider \"tools\")",
            ]
        );
    }

    #[test]
    fn a_home_mount_is_abbreviated_on_both_sides() {
        let mut spec = SandboxSpec::default();
        spec.mounts = vec![
            mount("/home/u", "/home/user", PathMode::Ro, "h"),
            mount("/home/u/a", "/elsewhere/a", PathMode::Ro, "h"),
        ];
        let out = lines(&spec);
        assert_eq!(out[1], "  ro       ~  (provider \"h\")");
        assert_eq!(out[2], "  ro       ~/a -> /elsewhere/a  (provider \"h\")");
        // A sibling that merely starts with the same text is not below it.
        let mut spec = SandboxSpec::default();
        spec.mounts = vec![mount("/home/uu/a", "/home/uu/a", PathMode::Ro, "h")];
        assert_eq!(lines(&spec)[1], "  ro       /home/uu/a  (provider \"h\")");
    }

    #[test]
    fn long_lists_are_counted() {
        let many = |n: usize, by: &str, mode: PathMode| {
            (0..n)
                .map(|i| {
                    let p = format!("/nix/store/{i}");
                    mount(&p, &p, mode, by)
                })
                .collect::<Vec<_>>()
        };
        let mut spec = SandboxSpec::default();
        spec.mask_sockets = true;
        spec.mounts = many(LIST_LIMIT, "small", PathMode::Ro)
            .into_iter()
            .chain(many(LIST_LIMIT + 1, "big", PathMode::Ro))
            .chain(many(LIST_LIMIT + 5, "bigrw", PathMode::Rw))
            .collect();
        let out = lines(&spec);
        // `rw` first, counted; then the small group, listed; then the big.
        assert_eq!(out[1], "  rw       15 mounts  (provider \"bigrw\")");
        assert_eq!(out.len(), 2 + LIST_LIMIT + 1, "{out:#?}");
        assert!(out[2].starts_with("  ro       /nix/store/0  "), "{out:#?}");
        assert_eq!(
            out.last().unwrap(),
            "  ro       11 mounts  (provider \"big\")"
        );
    }

    #[test]
    fn a_long_name_list_is_cut() {
        let domains = (0..LIST_LIMIT + 3).map(|i| format!("d{i:02}.example").parse::<Domain>());
        let mut spec = SandboxSpec::default();
        spec.network = NetworkSpec::Proxy {
            allow_domains: domains.map(Result::unwrap).collect(),
        };
        let out = lines(&spec);
        assert!(out[1].starts_with("  network  proxy to d00.example, d01.example"));
        assert!(out[1].ends_with(", d09.example and 3 more"), "{}", out[1]);
    }

    #[test]
    fn network_beyond_loopback_is_listed() {
        let net = |network| {
            let spec = SandboxSpec {
                network,
                ..Default::default()
            };
            lines(&spec)[1..].to_vec()
        };
        assert_eq!(net(NetworkSpec::None), Vec::<String>::new());
        assert_eq!(net(NetworkSpec::Loopback), Vec::<String>::new());
        assert_eq!(net(NetworkSpec::Full), ["  network  full"]);
        assert_eq!(
            net(NetworkSpec::Proxy {
                allow_domains: BTreeSet::new()
            }),
            ["  network  proxy (no domains)"]
        );
        assert_eq!(
            net(NetworkSpec::Proxy {
                allow_domains: ["b.com", "a.com"].map(|d| d.parse().unwrap()).into()
            }),
            ["  network  proxy to a.com, b.com"]
        );
        // Domains a sandbox could send data out through get a line.
        assert_eq!(
            net(NetworkSpec::Proxy {
                allow_domains: ["static.crates.io", "api.anthropic.com", "github.com"]
                    .map(|d| d.parse().unwrap())
                    .into()
            }),
            [
                "  network  proxy to api.anthropic.com, github.com, static.crates.io",
                "  uploads  api.anthropic.com, github.com"
            ]
        );
    }

    #[test]
    fn namespaces_syscalls_shims_and_unprotected_providers_are_listed() {
        let mut spec = SandboxSpec::default();
        spec.namespaces.shared = [ShareableNamespace::Pid, ShareableNamespace::Net].into();
        spec.allow_syscalls = [OptInSyscall::Ptrace, OptInSyscall::IoUring].into();
        let shim: ShimSpec = toml::from_str(
            "binary = \"git\"\ndefault = { decision = \"allow\", profile = \"main\" }",
        )
        .unwrap();
        spec.shims
            .insert("git".parse::<ShimName>().unwrap(), (shim, provider("vcs")));
        let off = provider("env");
        let out = summary_lines(&spec, &ctx(Base::None, &[&off]));
        assert_eq!(
            out[1..],
            [
                "  share    net, pid",
                "  syscalls ptrace, io_uring",
                "  broker   git  (provider \"vcs\")",
                "  script   provider \"env\" runs unprotected (protect = false)",
            ]
        );
    }

    #[test]
    fn env_shows_names_beyond_the_base_never_values() {
        let mut spec = SandboxSpec::default();
        let m = default_base_manifest().unwrap();
        spec.env.pass = m.grants.env.pass.clone();
        spec.env.pass.push("RUST_*".parse().unwrap());
        spec.env
            .set
            .insert("API".parse().unwrap(), "hunter2".parse().unwrap());
        let out = summary_lines(&spec, &ctx(Base::Default, &[]));
        assert_eq!(out[1..], ["  env pass RUST_*", "  env set  API"]);
        assert!(!out.join("\n").contains("hunter2"));
        // Under `base = "none"` the base's patterns are the user's.
        let out = summary_lines(&spec, &ctx(Base::None, &[]));
        assert_eq!(
            out[1], "  env pass COLORTERM, LANG, RUST_*, TERM",
            "{out:#?}"
        );
    }

    #[test]
    fn everything_printed_is_escaped() {
        let mut spec = SandboxSpec::default();
        spec.mounts = vec![mount(
            "/x/\u{1b}[31mred",
            "/x/\u{1b}[31mred",
            PathMode::Ro,
            "evil",
        )];
        let off = provider("p");
        let unprotected = [&off];
        let mut c = ctx(Base::None, &unprotected);
        c.profile = "a\u{1b}b";
        let out = summary_lines(&spec, &c);
        let all = out.join("\n");
        assert!(!all.contains('\u{1b}'), "{all:?}");
        assert!(all.contains("/x/\\u{1b}[31mred"), "{all}");
        assert!(all.contains("profile \"a\\u{1b}b\""), "{all}");
    }
}
