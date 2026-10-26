//! The backend-independent sandbox description (DESIGN.md §6.1) and the
//! compilation of a session's profiles into it.
//!
//! A [`SandboxSpec`] is everything a sandbox engine needs to know about one
//! profile's policy: the concrete mounts, the system mounts, which
//! namespaces are shared, the network, the environment policy, the opt-in
//! syscalls and the brokered shims. It holds no host state beyond the mount
//! plan's resolved host paths, and no command: the command is supplied when
//! a sandbox is spawned.
//!
//! [`compile_session`] runs the whole pipeline for a session, from the
//! configuration and the providers' outputs to one compiled spec per
//! profile; [`compile_profile`] compiles a single profile's merged grants.
//!
//! Not yet checked here (separate steps): the reserved-path rules for the
//! workspace mount and the sandbox `HOME` (§6.2), and grants whose host
//! source overlaps the host workspace (§11).

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;

use crate::config::{Config, ProfileRef, ProviderName};
use crate::expand::ExpansionContext;
use crate::manifest::{
    DevMode, Domain, EtcFile, OptInSyscall, SandboxHome, ShareableNamespace, ShimName, ShimSpec,
};
use crate::policy::NetworkMode;
use crate::provider::ProviderOutput;
use crate::resolve::{
    EffectiveEnv, EffectiveGrants, EffectiveNetwork, MergeError, PathPlanError, PlanWarning,
    PlannedMount, ProfileError, build_profile_graph, merge_profiles, plan_mounts,
};

/// One profile's sandbox, independent of the engine that builds it.
///
/// The default value is the empty sandbox of `base = "none"`: no mounts,
/// no system mounts, every namespace unshared, no network, an empty
/// environment policy, full hardening and no shims.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SandboxSpec {
    /// The filesystem mounts, one per sandbox path, ordered so that every
    /// mount comes after the mounts of its ancestors (see
    /// [`MountPlan::mounts`](crate::resolve::MountPlan::mounts)).
    pub mounts: Vec<PlannedMount>,
    /// Mask unix sockets found in RW grants at startup (§3.4).
    pub mask_sockets: bool,
    /// System mounts, synthesized files and the sandbox `HOME`.
    pub system: SystemSpec,
    /// Namespace sharing.
    pub namespaces: Namespaces,
    /// Network access.
    pub network: NetworkSpec,
    /// The environment policy, as merged. Not yet applied to a real
    /// environment: `deny` still has to win over `pass` (§9).
    pub env: EffectiveEnv,
    /// Syscalls re-enabled in the seccomp filter (§6.3); every other
    /// hardening measure is always on.
    pub allow_syscalls: BTreeSet<OptInSyscall>,
    /// Brokered commands, each with the provider that granted it. Their
    /// profile references are resolved full names.
    pub shims: BTreeMap<ShimName, (ShimSpec, ProviderName)>,
}

/// System mounts and synthesized files (§6.2 steps 3 and 4).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SystemSpec {
    /// Mount a masked-subset `/proc`.
    pub proc: bool,
    /// Which `/dev` to mount, if any.
    pub dev: Option<DevMode>,
    /// The `/etc` files to synthesize.
    pub etc: BTreeSet<EtcFile>,
    /// The sandbox `HOME`: the profile's `system.home`, or `/home/user` when
    /// no provider sets one. It is where `~` rules are mounted; nothing is
    /// mounted there unless a rule grants it.
    pub home: SandboxHome,
}

/// Which namespaces are shared with the host (§6.2 step 1).
///
/// The user and mount namespaces are always unshared; every namespace not in
/// `shared` is unshared too.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Namespaces {
    /// The namespaces shared with the host.
    pub shared: BTreeSet<ShareableNamespace>,
}

impl Namespaces {
    /// Whether `ns` is shared with the host.
    pub fn is_shared(&self, ns: ShareableNamespace) -> bool {
        self.shared.contains(&ns)
    }
}

/// Network access (§8). Allowed domains exist only in proxy mode, the only
/// mode that enforces them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum NetworkSpec {
    /// No interfaces up at all.
    #[default]
    None,
    /// Loopback only.
    Loopback,
    /// Loopback plus the domain-filtering proxy.
    Proxy {
        /// The domains reachable through the proxy.
        allow_domains: BTreeSet<Domain>,
    },
    /// Unrestricted host network.
    Full,
}

impl NetworkSpec {
    /// The network mode.
    pub fn mode(&self) -> NetworkMode {
        match self {
            NetworkSpec::None => NetworkMode::None,
            NetworkSpec::Loopback => NetworkMode::Loopback,
            NetworkSpec::Proxy { .. } => NetworkMode::Proxy,
            NetworkSpec::Full => NetworkMode::Full,
        }
    }

    /// The domains reachable through the proxy; `None` unless in proxy mode.
    pub fn allow_domains(&self) -> Option<&BTreeSet<Domain>> {
        match self {
            NetworkSpec::Proxy { allow_domains } => Some(allow_domains),
            _ => None,
        }
    }
}

/// A non-fatal problem found compiling a profile.
#[derive(Debug, Error)]
pub enum SpecWarning {
    /// A filesystem rule (or part of it) was skipped while planning mounts.
    #[error(transparent)]
    Mount(#[from] PlanWarning),
    /// The profile itself granted `network.allow_domains` but its network
    /// mode is not `proxy`, the only mode that uses them, so the domains
    /// were dropped. Domains inherited from the parent are dropped without
    /// this warning.
    #[error(
        "network.allow_domains {:?} ignored: domains only apply with network mode \"proxy\", \
         and the mode is {:?}",
        .domains.iter().map(Domain::as_str).collect::<Vec<_>>(),
        .mode.as_str()
    )]
    DomainsIgnored {
        /// The effective network mode.
        mode: NetworkMode,
        /// The dropped domains the profile itself granted.
        domains: BTreeSet<Domain>,
    },
}

/// A compiled profile: its spec and the warnings found building it.
#[derive(Debug)]
pub struct CompiledProfile {
    /// The sandbox description.
    pub spec: SandboxSpec,
    /// Non-fatal problems: mount-planning warnings first (in the plan's
    /// order), then spec-level ones.
    pub warnings: Vec<SpecWarning>,
}

/// Error compiling one profile.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SpecError {
    /// Planning the filesystem mounts failed.
    #[error(transparent)]
    Mounts(#[from] PathPlanError),
}

/// Compiles one profile's merged grants into a [`SandboxSpec`].
///
/// `ctx` supplies the session's workspace and host home; its sandbox `HOME`
/// is replaced by the profile's own (see [`SystemSpec::home`]), so `~`
/// rules land under the `HOME` the profile actually gets.
///
/// `parent` is the effective grants of the profile's parent (`None` for
/// `main` and for `inherit = "none"`). `network.allow_domains` is kept only
/// in proxy mode; in any other mode the domains are dropped, with a
/// [`SpecWarning::DomainsIgnored`] naming the domains the profile itself
/// grants. Domains inherited from `parent` are dropped silently: a child
/// may validly narrow a proxy parent's network (say to `"none"`), and the
/// union of domains is not something it can opt out of.
pub fn compile_profile(
    grants: &EffectiveGrants,
    parent: Option<&EffectiveGrants>,
    ctx: &ExpansionContext,
) -> Result<CompiledProfile, SpecError> {
    let home = grants.system.home.clone().unwrap_or_default();
    let plan = plan_mounts(&grants.fs, &ctx.with_sandbox_home(&home))?;
    let mut warnings: Vec<SpecWarning> = plan.warnings.into_iter().map(Into::into).collect();
    let inherited_domains = parent.map(|p| &p.network.allow_domains);
    let network = network_spec(&grants.network, inherited_domains, &mut warnings);
    let spec = SandboxSpec {
        mounts: plan.mounts,
        mask_sockets: grants.mask_sockets,
        system: SystemSpec {
            proc: grants.system.proc,
            dev: grants.system.dev,
            etc: grants.system.etc.clone(),
            home,
        },
        namespaces: Namespaces {
            shared: grants.sandbox.share.clone(),
        },
        network,
        env: grants.env.clone(),
        allow_syscalls: grants.sandbox.allow_syscalls.clone(),
        shims: grants.shims.clone(),
    };
    Ok(CompiledProfile { spec, warnings })
}

/// The network spec for `network`, dropping `allow_domains` outside proxy
/// mode, with a warning for those not in `inherited`.
fn network_spec(
    network: &EffectiveNetwork,
    inherited: Option<&BTreeSet<Domain>>,
    warnings: &mut Vec<SpecWarning>,
) -> NetworkSpec {
    let mode = network.mode;
    if mode != NetworkMode::Proxy {
        let own: BTreeSet<Domain> = network
            .allow_domains
            .iter()
            .filter(|d| inherited.is_none_or(|i| !i.contains(*d)))
            .cloned()
            .collect();
        if !own.is_empty() {
            warnings.push(SpecWarning::DomainsIgnored { mode, domains: own });
        }
    }
    match mode {
        NetworkMode::None => NetworkSpec::None,
        NetworkMode::Loopback => NetworkSpec::Loopback,
        NetworkMode::Proxy => NetworkSpec::Proxy {
            allow_domains: network.allow_domains.clone(),
        },
        NetworkMode::Full => NetworkSpec::Full,
    }
}

/// Every profile of a session, compiled.
#[derive(Debug)]
pub struct CompiledSession {
    profiles: BTreeMap<ProfileRef, CompiledProfile>,
    /// Every profile exactly once, parents before children (the profile
    /// graph's order).
    order: Vec<ProfileRef>,
}

impl CompiledSession {
    /// The compiled profile with the given full name.
    pub fn get(&self, profile: &ProfileRef) -> Option<&CompiledProfile> {
        self.profiles.get(profile)
    }

    /// Every profile's full name, parents before children.
    pub fn order(&self) -> &[ProfileRef] {
        &self.order
    }

    /// Every compiled profile, parents before children.
    pub fn iter(&self) -> impl Iterator<Item = (&ProfileRef, &CompiledProfile)> {
        self.order.iter().map(|p| (p, &self.profiles[p]))
    }

    /// Every warning of every profile, with its profile, parents first.
    /// An inherited rule is planned again in every profile that inherits
    /// it, so its warnings repeat once per such profile.
    pub fn warnings(&self) -> impl Iterator<Item = (&ProfileRef, &SpecWarning)> {
        self.iter()
            .flat_map(|(p, c)| c.warnings.iter().map(move |w| (p, w)))
    }

    /// The number of profiles, including `main`.
    pub fn len(&self) -> usize {
        self.profiles.len()
    }

    /// Always false: `main` always exists.
    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }
}

/// Error compiling a session, naming the stage that failed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CompileError {
    /// Resolving the profile graph failed.
    #[error("cannot resolve the profiles: {0}")]
    Graph(#[from] ProfileError),
    /// Merging a profile's grants failed.
    #[error("cannot merge the profiles' grants: {0}")]
    Merge(#[from] MergeError),
    /// Compiling one profile failed.
    #[error("cannot compile profile {:?}: {error}", .profile.as_str())]
    Profile {
        /// The profile.
        profile: ProfileRef,
        /// What went wrong. Boxed to keep `CompileError` small.
        #[source]
        error: Box<SpecError>,
    },
}

/// Runs the whole pipeline for a session: builds the profile graph from
/// `config` and the providers' `outputs` (in merge order, each with its
/// provider's effective name; see [`build_profile_graph`]), merges every
/// profile's grants, and compiles each profile with [`compile_profile`].
///
/// Stops at the first failing stage, and among the profiles at the first
/// failing one in graph order.
pub fn compile_session(
    config: &Config,
    outputs: Vec<(ProviderName, ProviderOutput)>,
    ctx: &ExpansionContext,
) -> Result<CompiledSession, CompileError> {
    let graph = build_profile_graph(config, outputs)?;
    let merged = merge_profiles(&graph)?;
    let mut profiles = BTreeMap::new();
    for (profile, grants) in merged.iter() {
        let parent = graph
            .get(profile)
            .and_then(|node| node.parent.as_ref())
            .map(|p| merged.get(p).expect("every parent is a merged profile"));
        let compiled =
            compile_profile(grants, parent, ctx).map_err(|error| CompileError::Profile {
                profile: profile.clone(),
                error: Box::new(error),
            })?;
        profiles.insert(profile.clone(), compiled);
    }
    Ok(CompiledSession {
        profiles,
        order: merged.order().to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};

    use tempfile::TempDir;

    use super::*;
    use crate::expand::{EntryKind, ResolveWarning};
    use crate::policy::PathMode::{self, Ephemeral, Masked, Protected, Ro, Rw};
    use crate::provider::{ProviderContext, session_providers};
    use crate::resolve::{MountSource, PlanWarningKind};

    /// A temporary workspace and host home, with an expansion context
    /// mapping them to `/workspace` and `/home/user`.
    struct Fixture {
        _dir: TempDir,
        root: PathBuf,
        ctx: ExpansionContext,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = TempDir::new().unwrap();
            let root = dir.path().canonicalize().unwrap();
            fs::create_dir(root.join("ws")).unwrap();
            fs::create_dir(root.join("home")).unwrap();
            let ctx = ExpansionContext::new(
                root.join("ws"),
                "/workspace".parse().unwrap(),
                root.join("home"),
                "/home/user".parse().unwrap(),
            )
            .unwrap();
            Fixture {
                _dir: dir,
                root,
                ctx,
            }
        }

        fn ws(&self) -> PathBuf {
            self.root.join("ws")
        }

        /// Creates a file (and its parents) at `rel` below the temp root.
        fn file(&self, rel: &str) {
            let p = self.root.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, rel).unwrap();
        }

        fn mkdir(&self, rel: &str) {
            fs::create_dir_all(self.root.join(rel)).unwrap();
        }

        /// The outputs of the session providers of `src` (the base's, then
        /// the user's `config` providers).
        fn outputs(&self, cfg: &Config) -> Vec<(ProviderName, ProviderOutput)> {
            let pctx = ProviderContext {
                workspace: self.ws(),
                workspace_mount: "/workspace".parse().unwrap(),
                home: self.root.join("home"),
                session_dir: self.root.join("session"),
            };
            session_providers(cfg, Path::new("/cfg"))
                .unwrap()
                .iter()
                .map(|p| (p.name().clone(), p.manifest(&pctx).unwrap()))
                .collect()
        }

        fn try_compile(&self, src: &str) -> Result<CompiledSession, CompileError> {
            let cfg = Config::from_toml_str(src).unwrap();
            compile_session(&cfg, self.outputs(&cfg), &self.ctx)
        }

        fn compile(&self, src: &str) -> CompiledSession {
            self.try_compile(src).unwrap()
        }

        fn compile_err(&self, src: &str) -> CompileError {
            match self.try_compile(src) {
                Ok(s) => panic!("expected an error, got {s:?}"),
                Err(e) => e,
            }
        }
    }

    fn pr(s: &str) -> ProfileRef {
        s.parse().unwrap()
    }

    /// A `config` provider named `name` applying `body` (keys of
    /// `[provider.sandbox]`) to `profile`.
    fn prov(name: &str, profile: &str, body: &str) -> String {
        format!(
            "[[provider]]\ntype = \"config\"\nname = \"{name}\"\nprofile = \"{profile}\"\n\
             [provider.sandbox]\n{body}\n"
        )
    }

    fn get<'a>(s: &'a CompiledSession, p: &str) -> &'a CompiledProfile {
        s.get(&pr(p)).unwrap_or_else(|| panic!("no profile {p}"))
    }

    fn spec<'a>(s: &'a CompiledSession, p: &str) -> &'a SandboxSpec {
        &get(s, p).spec
    }

    fn strs<T: ToString>(items: impl IntoIterator<Item = T>) -> Vec<String> {
        items.into_iter().map(|t| t.to_string()).collect()
    }

    /// Each mount as `(sandbox path, mode, provider)`.
    fn mounts(spec: &SandboxSpec) -> Vec<(String, PathMode, String)> {
        spec.mounts
            .iter()
            .map(|m| {
                (
                    m.sandbox.to_string_lossy().into_owned(),
                    m.mode,
                    m.provider.to_string(),
                )
            })
            .collect()
    }

    fn row(sandbox: &str, mode: PathMode, provider: &str) -> (String, PathMode, String) {
        (sandbox.to_owned(), mode, provider.to_owned())
    }

    fn domains(v: &[&str]) -> BTreeSet<Domain> {
        v.iter().map(|d| d.parse().unwrap()).collect()
    }

    #[test]
    fn base_none_is_the_empty_sandbox() {
        let f = Fixture::new();
        let s = f.compile("base = \"none\"");
        assert_eq!(s.order(), [ProfileRef::main()]);
        assert_eq!(s.len(), 1);
        assert!(!s.is_empty());
        let main = get(&s, "main");
        assert!(main.warnings.is_empty(), "{:?}", main.warnings);
        assert_eq!(main.spec, SandboxSpec::default());
        let spec = &main.spec;
        assert!(spec.mounts.is_empty());
        assert!(!spec.mask_sockets);
        assert!(!spec.system.proc);
        assert_eq!(spec.system.dev, None);
        assert!(spec.system.etc.is_empty());
        // Nothing is mounted there, but `~` still has a sandbox location.
        assert_eq!(spec.system.home.as_str(), "/home/user");
        assert_eq!(spec.network, NetworkSpec::None);
        assert_eq!(spec.network.mode(), NetworkMode::None);
        assert_eq!(spec.network.allow_domains(), None);
        assert_eq!(spec.env, EffectiveEnv::default());
        assert!(spec.namespaces.shared.is_empty());
        assert!(spec.allow_syscalls.is_empty());
        assert!(spec.shims.is_empty());
    }

    #[test]
    fn base_default_on_an_empty_workspace() {
        let f = Fixture::new();
        let s = f.compile("");
        assert_eq!(s.order(), [ProfileRef::main()]);
        let main = get(&s, "main");
        let spec = &main.spec;
        assert_eq!(
            mounts(spec),
            [
                row("/tmp", Ephemeral, "base"),
                row("/workspace", Rw, "base"),
                row("/home/user", Ephemeral, "base"),
            ]
        );
        assert_eq!(
            spec.mounts[1].source,
            MountSource::Host {
                path: f.ws(),
                kind: EntryKind::Dir
            }
        );
        assert_eq!(spec.mounts[0].source, MountSource::Ephemeral);
        assert!(spec.mask_sockets);
        assert!(spec.system.proc);
        assert_eq!(spec.system.dev, Some(DevMode::Minimal));
        assert_eq!(
            strs(&spec.system.etc),
            ["passwd", "group", "hosts", "nsswitch.conf"]
        );
        assert_eq!(spec.system.home.as_str(), "/home/user");
        assert_eq!(spec.network, NetworkSpec::Loopback);
        assert_eq!(strs(&spec.env.pass), ["TERM", "LANG", "COLORTERM"]);
        assert_eq!(
            strs(&spec.env.deny),
            [
                "*_TOKEN",
                "*_KEY",
                "*_SECRET",
                "*_PASSWORD",
                "AWS_*",
                "GITHUB_*",
                "SSH_AUTH_SOCK",
                "NIX_CONFIG"
            ]
        );
        assert!(spec.env.set.is_empty() && spec.env.path_prepend.is_empty());
        assert!(spec.namespaces.shared.is_empty());
        assert!(spec.allow_syscalls.is_empty());
        assert!(spec.shims.is_empty());
        // The literal protected paths that do not exist are reported, not
        // dropped silently.
        let missing: Vec<&str> = main
            .warnings
            .iter()
            .map(|w| match w {
                SpecWarning::Mount(PlanWarning {
                    pattern,
                    kind: PlanWarningKind::Resolve(ResolveWarning::Missing { .. }),
                    ..
                }) => pattern.as_str(),
                other => panic!("unexpected warning {other:?}"),
            })
            .collect();
        assert_eq!(
            missing,
            [
                "{workspace}/flake.lock",
                "{workspace}/.envrc",
                "{workspace}/.stopit.toml",
                "{workspace}/.vscode",
                "{workspace}/.idea",
                "{workspace}/.github/workflows",
            ]
        );
    }

    #[test]
    fn base_default_masks_and_protects_matching_workspace_files() {
        let f = Fixture::new();
        for file in [
            "ws/.env",
            "ws/sub/key.pem",
            "ws/flake.nix",
            "ws/nix/a.nix",
            "ws/.stopit.toml",
            "ws/flake.lock",
            "ws/.envrc",
            "ws/.github/workflows/ci.yml",
            "ws/src/main.rs",
        ] {
            f.file(file);
        }
        f.mkdir("ws/.vscode");
        f.mkdir("ws/.idea");
        let s = f.compile("");
        let main = get(&s, "main");
        assert!(main.warnings.is_empty(), "{:?}", main.warnings);
        assert_eq!(
            mounts(&main.spec),
            [
                row("/tmp", Ephemeral, "base"),
                row("/workspace", Rw, "base"),
                row("/home/user", Ephemeral, "base"),
                row("/workspace/.env", Masked, "base"),
                row("/workspace/.envrc", Protected, "base"),
                row("/workspace/.idea", Protected, "base"),
                row("/workspace/.stopit.toml", Protected, "base"),
                row("/workspace/.vscode", Protected, "base"),
                row("/workspace/flake.lock", Protected, "base"),
                row("/workspace/flake.nix", Protected, "base"),
                row("/workspace/.github/workflows", Protected, "base"),
                row("/workspace/nix/a.nix", Protected, "base"),
                row("/workspace/sub/key.pem", Masked, "base"),
            ]
        );
    }

    /// The expressiveness golden test (DESIGN.md §3.2, §12 item 12):
    /// Appendix A under `base = "none"` compiles to the same spec as
    /// `base = "default"`, for every profile.
    ///
    /// Appendix A's `vcs` provider is left out on both sides: the provider
    /// itself is Phase 3, and `base = "default"` does not add it implicitly.
    #[test]
    fn appendix_a_matches_base_default() {
        let f = Fixture::new();
        for file in [
            "ws/.env",
            "ws/.env.local",
            "ws/sub/key.pem",
            "ws/sub/id.key",
            "ws/.npmrc",
            "ws/flake.nix",
            "ws/nix/a.nix",
            "ws/flake.lock",
            "ws/.envrc",
            "ws/.stopit.toml",
            "ws/.github/workflows/ci.yml",
            "ws/src/main.rs",
            "home/.config/tool/x",
        ] {
            f.file(file);
        }
        f.mkdir("ws/.vscode");
        // The same user profiles and providers on both sides, so that
        // inheritance from the base's `main` is compared too.
        let user = format!(
            "[profiles.child]\n[profiles.bare]\ninherit = \"none\"\n{}{}",
            prov(
                "u",
                "child",
                "fs.ro = [\"~/.config\"]\nnetwork = { mode = \"proxy\", allow_domains = [\"crates.io\"] }"
            ),
            prov("v", "bare", "fs.ro = [\"{workspace}/src\"]"),
        );
        let explicit = f.compile(&format!(
            "{}\n{user}",
            crate::config::APPENDIX_A_WITHOUT_VCS
        ));
        let default = f.compile(&format!("base = \"default\"\n{user}"));

        assert_eq!(strs(explicit.order()), ["bare", "main", "child"]);
        assert_eq!(explicit.order(), default.order());
        for p in explicit.order() {
            let (e, d) = (explicit.get(p).unwrap(), default.get(p).unwrap());
            assert_eq!(e.spec, d.spec, "profile {p}");
            assert_eq!(strs(&e.warnings), strs(&d.warnings), "profile {p}");
        }
        // Not vacuous: the base's masks and protections are in the spec.
        let main = mounts(spec(&explicit, "main"));
        for want in [
            row("/workspace/.env", Masked, "base"),
            row("/workspace/.env.local", Masked, "base"),
            row("/workspace/.npmrc", Masked, "base"),
            row("/workspace/sub/id.key", Masked, "base"),
            row("/workspace/flake.nix", Protected, "base"),
            row("/workspace/.vscode", Protected, "base"),
        ] {
            assert!(main.contains(&want), "{want:?} not in {main:?}");
        }
        assert!(spec(&explicit, "child").network.allow_domains().is_some());
    }

    #[test]
    fn allow_domains_are_kept_only_in_proxy_mode() {
        let f = Fixture::new();
        let s = f.compile(&format!(
            "base = \"none\"\n[profiles.lo]\n[profiles.unset]\n[profiles.full]\n[profiles.px]\n\
             [profiles.own]\n{}{}{}{}{}{}",
            prov("a", "main", "network.allow_domains = [\"b.example.com\", \"a.example.com\"]"),
            prov("b", "lo", "network.mode = \"loopback\""),
            prov("c", "full", "network.mode = \"full\""),
            prov("d", "px", "network.mode = \"proxy\""),
            prov("e", "px", "network.allow_domains = [\"crates.io\"]"),
            prov(
                "f",
                "own",
                "network = { mode = \"loopback\", allow_domains = [\"a.example.com\", \"crates.io\"] }"
            ),
        ));
        // Only the domains a profile grants itself are warned about: `main`
        // (a root) for all of its own, `own` only for the one it adds, and
        // the children that merely inherit `main`'s domains not at all.
        let want = [
            (
                "main",
                NetworkMode::None,
                &["a.example.com", "b.example.com"][..],
            ),
            ("own", NetworkMode::Loopback, &["crates.io"][..]),
        ];
        for (p, mode, own) in want {
            let c = get(&s, p);
            match c.warnings.as_slice() {
                [
                    SpecWarning::DomainsIgnored {
                        mode: m,
                        domains: d,
                    },
                ] => {
                    assert_eq!((*m, d), (mode, &domains(own)), "{p}");
                }
                other => panic!("{p}: expected one DomainsIgnored warning, got {other:?}"),
            }
        }
        for (p, spec_want) in [
            ("main", NetworkSpec::None),
            ("own", NetworkSpec::Loopback),
            ("unset", NetworkSpec::None),
            ("lo", NetworkSpec::Loopback),
            ("full", NetworkSpec::Full),
        ] {
            let c = get(&s, p);
            assert_eq!(c.spec.network, spec_want, "{p}");
            assert_eq!(c.spec.network.allow_domains(), None, "{p}");
            if !matches!(p, "main" | "own") {
                assert!(c.warnings.is_empty(), "{p}: {:?}", c.warnings);
            }
        }
        assert_eq!(
            get(&s, "own").warnings[0].to_string(),
            r#"network.allow_domains ["crates.io"] ignored: domains only apply with network mode "proxy", and the mode is "loopback""#
        );
        assert_eq!(s.warnings().count(), 2);

        let px = get(&s, "px");
        assert!(px.warnings.is_empty(), "{:?}", px.warnings);
        let all = domains(&["a.example.com", "b.example.com", "crates.io"]);
        assert_eq!(
            px.spec.network,
            NetworkSpec::Proxy {
                allow_domains: all.clone()
            }
        );
        assert_eq!(px.spec.network.mode(), NetworkMode::Proxy);
        assert_eq!(px.spec.network.allow_domains(), Some(&all));
        // Proxy mode without domains is not a warning.
        let s = f.compile(&format!(
            "base = \"none\"\n{}",
            prov("a", "main", "network.mode = \"proxy\"")
        ));
        let main = get(&s, "main");
        assert!(main.warnings.is_empty(), "{:?}", main.warnings);
        assert_eq!(main.spec.network.allow_domains(), Some(&BTreeSet::new()));
    }

    #[test]
    fn child_narrowing_a_proxy_parent_drops_inherited_domains_silently() {
        let f = Fixture::new();
        let s = f.compile(&format!(
            "base = \"none\"\n[profiles.offline]\n[profiles.below]\ninherit = \"offline\"\n{}{}",
            prov(
                "m",
                "main",
                "network = { mode = \"proxy\", allow_domains = [\"api.anthropic.com\"] }"
            ),
            prov("o", "offline", "network.mode = \"none\""),
        ));
        assert_eq!(
            s.warnings().count(),
            0,
            "{:?}",
            s.warnings().collect::<Vec<_>>()
        );
        assert_eq!(
            spec(&s, "main").network,
            NetworkSpec::Proxy {
                allow_domains: domains(&["api.anthropic.com"])
            }
        );
        // Dropped, and silently, both in the child that switches the mode
        // and in its own child, which inherits domains and mode alike.
        assert_eq!(spec(&s, "offline").network, NetworkSpec::None);
        assert_eq!(spec(&s, "below").network, NetworkSpec::None);
    }

    #[test]
    fn compile_profile_without_a_parent_warns_on_every_domain() {
        let f = Fixture::new();
        let mut grants = EffectiveGrants::default();
        grants.network.allow_domains = domains(&["crates.io"]);
        let c = compile_profile(&grants, None, &f.ctx).unwrap();
        assert_eq!(c.spec.network, NetworkSpec::None);
        assert!(
            matches!(c.warnings.as_slice(), [SpecWarning::DomainsIgnored { domains: d, .. }] if *d == grants.network.allow_domains),
            "{:?}",
            c.warnings
        );
        // The same grants with that domain inherited: no warning.
        let parent = grants.clone();
        let c = compile_profile(&grants, Some(&parent), &f.ctx).unwrap();
        assert!(c.warnings.is_empty(), "{:?}", c.warnings);
    }

    #[test]
    fn sharing_and_opt_in_syscalls_are_carried_through() {
        let f = Fixture::new();
        let s = f.compile(&format!(
            "{}{}",
            prov(
                "a",
                "main",
                "sandbox.share = [\"ipc\", \"net\"]\nsandbox.allow_syscalls = [\"keyctl\"]"
            ),
            prov("b", "main", "sandbox.allow_syscalls = [\"ptrace\"]"),
        ));
        let spec = spec(&s, "main");
        assert_eq!(strs(&spec.namespaces.shared), ["net", "ipc"]);
        assert!(spec.namespaces.is_shared(ShareableNamespace::Net));
        assert!(spec.namespaces.is_shared(ShareableNamespace::Ipc));
        assert!(!spec.namespaces.is_shared(ShareableNamespace::Pid));
        assert_eq!(strs(&spec.allow_syscalls), ["ptrace", "keyctl"]);
    }

    #[test]
    fn profiles_are_compiled_in_graph_order_with_inherited_grants() {
        let f = Fixture::new();
        f.mkdir("home/.claude");
        let s = f.compile(&format!(
            "base = \"none\"\n[profiles.harness]\n[profiles.bare]\ninherit = \"none\"\n{}{}{}",
            prov(
                "m",
                "main",
                "fs.rw = [\"{workspace}\"]\nfs.ephemeral = [\"~\"]\nsystem.proc = true\n\
                 env.pass = [\"TERM\"]\nenv.set = { EDITOR = \"vi\" }\n\
                 shims.jj = { binary = \"jj\", default = { decision = \"deny\" } }"
            ),
            prov(
                "h",
                "harness",
                "fs.ro = [\"~/.claude\"]\nsystem.home = \"/home/agent\"\n\
                 network = { mode = \"proxy\", allow_domains = [\"api.anthropic.com\"] }\n\
                 env.set = { SHELL = \"/run/stopit/bin/sh\" }"
            ),
            prov(
                "b",
                "bare",
                "fs.ro = [\"/nix/store\"]\nsystem.dev = \"minimal\""
            ),
        ));
        assert_eq!(strs(s.order()), ["bare", "main", "harness"]);
        let names: Vec<&str> = s.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(names, ["bare", "main", "harness"]);
        assert_eq!(s.len(), 3);
        assert_eq!(s.warnings().count(), 0);

        let main = spec(&s, "main");
        assert_eq!(
            mounts(main),
            [
                row("/workspace", Rw, "m"),
                row("/home/user", Ephemeral, "m")
            ]
        );
        assert!(main.system.proc);
        assert_eq!(main.network, NetworkSpec::None);

        // The harness gets main's grants plus its own; `~` (its own and the
        // inherited one) lands under its own HOME.
        let harness = spec(&s, "harness");
        assert_eq!(
            mounts(harness),
            [
                row("/workspace", Rw, "m"),
                row("/home/agent", Ephemeral, "m"),
                row("/home/agent/.claude", Ro, "h"),
            ]
        );
        assert_eq!(
            harness.mounts[2].source,
            MountSource::Host {
                path: f.root.join("home/.claude"),
                kind: EntryKind::Dir
            }
        );
        assert_eq!(harness.system.home.as_str(), "/home/agent");
        assert!(harness.system.proc);
        assert_eq!(
            harness.network,
            NetworkSpec::Proxy {
                allow_domains: domains(&["api.anthropic.com"])
            }
        );
        assert_eq!(strs(&harness.env.pass), ["TERM"]);
        assert_eq!(strs(harness.env.set.keys()), ["EDITOR", "SHELL"]);
        assert_eq!(strs(harness.shims.keys()), ["jj"]);
        assert_eq!(harness.shims, main.shims);

        // `inherit = "none"` gets nothing from main.
        let bare = spec(&s, "bare");
        assert_eq!(mounts(bare), [row("/nix/store", Ro, "b")]);
        assert!(!bare.system.proc);
        assert_eq!(bare.system.dev, Some(DevMode::Minimal));
        assert_eq!(bare.system.home.as_str(), "/home/user");
        assert_eq!(bare.env, EffectiveEnv::default());
        assert!(bare.shims.is_empty());
    }

    #[test]
    fn warnings_are_listed_per_profile() {
        let f = Fixture::new();
        let s = f.compile(&format!(
            "base = \"none\"\n[profiles.child]\n{}{}",
            prov("m", "main", "fs.ro = [\"~/missing\"]"),
            prov("c", "child", "network.allow_domains = [\"crates.io\"]"),
        ));
        let got: Vec<(&str, String)> = s
            .warnings()
            .map(|(p, w)| (p.as_str(), w.to_string()))
            .collect();
        let missing = format!(
            "provider \"m\", rule \"~/missing\": {:?} does not exist",
            f.root.join("home/missing")
        );
        assert_eq!(
            got,
            [
                ("main", missing.clone()),
                ("child", missing),
                (
                    "child",
                    r#"network.allow_domains ["crates.io"] ignored: domains only apply with network mode "proxy", and the mode is "none""#.to_owned()
                ),
            ]
        );
    }

    #[test]
    fn mount_planning_errors_name_the_profile() {
        let f = Fixture::new();
        f.file("ws/real/x");
        symlink("real", f.ws().join("link")).unwrap();
        let e = f.compile_err(&format!(
            "[profiles.harness]\n{}",
            prov("p", "harness", "fs.masked = [\"{workspace}/link/x\"]"),
        ));
        let CompileError::Profile { profile, error } = &e else {
            panic!("expected a profile error, got {e:?}");
        };
        assert_eq!(profile, &pr("harness"));
        assert_eq!(
            **error,
            SpecError::Mounts(PathPlanError::WorkspaceSymlink {
                provider: "p".parse().unwrap(),
                pattern: "{workspace}/link/x".into(),
                mode: Masked,
                path: f.ws().join("link/x"),
                link: f.ws().join("link"),
            })
        );
        let msg = e.to_string();
        assert!(
            msg.starts_with(
                r#"cannot compile profile "harness": provider "p", rule "{workspace}/link/x": "#
            ),
            "{msg}"
        );
        assert!(msg.contains("never followed"), "{msg}");
    }

    #[test]
    fn graph_and_merge_errors_name_their_stage() {
        let f = Fixture::new();
        let e = f.compile_err(&prov("a", "nope", ""));
        assert!(
            matches!(e, CompileError::Graph(ProfileError::UnknownTarget { .. })),
            "{e:?}"
        );
        assert_eq!(
            e.to_string(),
            r#"cannot resolve the profiles: provider "a" applies its grants to unknown profile "nope""#
        );

        let e = f.compile_err(&format!(
            "base = \"none\"\n{}{}",
            prov("a", "main", "system.home = \"/home/a\""),
            prov("b", "main", "system.home = \"/home/b\""),
        ));
        assert!(
            matches!(e, CompileError::Merge(MergeError::HomeConflict { .. })),
            "{e:?}"
        );
        assert_eq!(
            e.to_string(),
            r#"cannot merge the profiles' grants: profile "main": conflicting system.home values "/home/a" (provider "a") and "/home/b" (provider "b")"#
        );
    }
}
