//! Per-profile merging of grant sections (DESIGN.md §3.3, §3.5).
//!
//! Each profile's **effective** grants are its parent's effective grants
//! (or nothing, for `main` and for `inherit = "none"`) combined with its
//! **own** contributions, in contribution order. Two levels are
//! distinguished throughout:
//!
//! * *within a profile*: across that profile's own contributions;
//! * *own vs inherited*: the profile's own result against its parent's
//!   effective result.
//!
//! Every section except the path rules is merged into a fully defaulted
//! effective value here. Path rules need path precedence (§3.5 rules 1–3),
//! which is applied later; they are only collected, each tagged with its
//! provider and inheritance depth.

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;

use super::graph::{Contribution, ProfileGraph};
use crate::config::{ProfileRef, ProviderName, ProviderOrigin};
use crate::manifest::{
    Bind, DevMode, Domain, EnvName, EnvPattern, EnvValue, EtcFile, FsGrants, OptInSyscall,
    PathPattern, SandboxHome, SearchPathEntry, ShareableNamespace, ShimName, ShimSpec,
};
use crate::policy::{NetworkMode, PathMode};

/// What an [`FsRule`] grants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsRuleKind {
    /// A path rule (`fs.rw`, `fs.ro`, `fs.masked`, `fs.protected` or
    /// `fs.ephemeral`): the pattern and the mode of the list it came from.
    Path {
        /// The mode of the list the pattern was written in.
        mode: PathMode,
        /// The pattern, unexpanded.
        pattern: PathPattern,
    },
    /// An explicit remapping (`fs.bind`).
    Bind(Bind),
}

/// One filesystem rule of a profile, unmerged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsRule {
    /// The rule.
    pub kind: FsRuleKind,
    /// The provider that granted it.
    pub provider: ProviderName,
    /// Layer that declared the provider.
    pub origin: ProviderOrigin,
    /// How far up the inheritance chain the rule was granted: 0 for the
    /// profile's own contributions, 1 for its parent's own, 2 for its
    /// grandparent's, and so on. Used for "a profile's own rules beat
    /// inherited rules" (§3.5 rule 2) at any distance.
    pub depth: u32,
}

/// The effective `system` section.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EffectiveSystem {
    /// Mount a masked-subset `/proc`.
    pub proc: bool,
    /// Which `/dev` to mount, if any.
    pub dev: Option<DevMode>,
    /// Synthesized `/etc` files.
    pub etc: BTreeSet<EtcFile>,
    /// The sandbox `HOME`, if any provider set one.
    pub home: Option<SandboxHome>,
}

/// The effective `env` section.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EffectiveEnv {
    /// Host variables to pass through, without duplicates.
    pub pass: Vec<EnvPattern>,
    /// Host variables to drop (ignoring ASCII case), without duplicates. Not subtracted from
    /// `pass` here: `deny` always wins, which [`EffectiveEnv::apply`]
    /// enforces when the environment is built.
    pub deny: Vec<EnvPattern>,
    /// Explicit variables.
    pub set: BTreeMap<EnvName, EnvValue>,
    /// Directories placed in front of `PATH`, without duplicates. Earlier
    /// entries take precedence in `PATH`.
    pub path_prepend: Vec<SearchPathEntry>,
}

/// The effective `network` section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveNetwork {
    /// The network mode.
    pub mode: NetworkMode,
    /// Domains reachable through the proxy.
    pub allow_domains: BTreeSet<Domain>,
}

impl Default for EffectiveNetwork {
    /// No network at all.
    fn default() -> Self {
        EffectiveNetwork {
            mode: NetworkMode::None,
            allow_domains: BTreeSet::new(),
        }
    }
}

/// The effective `sandbox` section.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EffectiveSandbox {
    /// Namespaces shared with the host.
    pub share: BTreeSet<ShareableNamespace>,
    /// Syscalls re-enabled in the seccomp filter.
    pub allow_syscalls: BTreeSet<OptInSyscall>,
}

/// A profile's effective grants. The default value is the empty sandbox.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EffectiveGrants {
    /// Every filesystem rule of the profile and its ancestors, inherited
    /// rules first (outermost ancestor first), each list in contribution
    /// order. Path precedence is not applied yet.
    pub fs: Vec<FsRule>,
    /// Mask sockets found in RW grants at startup.
    pub mask_sockets: bool,
    /// System mounts and synthesized files.
    pub system: EffectiveSystem,
    /// Environment filtering and explicit variables.
    pub env: EffectiveEnv,
    /// Network access.
    pub network: EffectiveNetwork,
    /// Hardening opt-outs.
    pub sandbox: EffectiveSandbox,
    /// Brokered commands, each with the provider that granted it.
    pub shims: BTreeMap<ShimName, (ShimSpec, ProviderName)>,
}

/// Every profile's effective grants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergedProfiles {
    profiles: BTreeMap<ProfileRef, EffectiveGrants>,
    /// Every profile exactly once, parents before children (the graph's
    /// order).
    order: Vec<ProfileRef>,
}

impl MergedProfiles {
    /// The effective grants of the profile with the given full name.
    pub fn get(&self, profile: &ProfileRef) -> Option<&EffectiveGrants> {
        self.profiles.get(profile)
    }

    /// Every profile's full name, parents before children, as in
    /// [`ProfileGraph::order`].
    pub fn order(&self) -> &[ProfileRef] {
        &self.order
    }

    /// Every profile, parents before children (see
    /// [`MergedProfiles::order`]).
    pub fn iter(&self) -> impl Iterator<Item = (&ProfileRef, &EffectiveGrants)> {
        self.order.iter().map(|p| (p, &self.profiles[p]))
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

/// Error produced while merging a profile's own contributions.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MergeError {
    /// Two providers set different `system.home` values for one profile.
    #[error(
        "profile {:?}: conflicting system.home values {:?} (provider {:?}) and {:?} (provider {:?})",
        .profile.as_str(),
        .first.as_str(),
        .first_provider.as_str(),
        .second.as_str(),
        .second_provider.as_str()
    )]
    HomeConflict {
        /// The profile.
        profile: ProfileRef,
        /// The provider that set the first value.
        first_provider: ProviderName,
        /// The first value.
        first: SandboxHome,
        /// The provider that set the conflicting value.
        second_provider: ProviderName,
        /// The conflicting value.
        second: SandboxHome,
    },

    /// Two providers set different values for one variable in one profile.
    /// Boxed to keep `MergeError` small.
    #[error(transparent)]
    EnvSetConflict(Box<EnvSetConflict>),

    /// Two providers grant a shim of the same name to one profile.
    #[error(
        "profile {:?}: shim {:?} is granted by both provider {:?} and provider {:?}",
        .profile.as_str(),
        .shim.as_str(),
        .first_provider.as_str(),
        .second_provider.as_str()
    )]
    DuplicateShim {
        /// The profile.
        profile: ProfileRef,
        /// The shim.
        shim: ShimName,
        /// The provider that granted it first.
        first_provider: ProviderName,
        /// The provider that granted it again.
        second_provider: ProviderName,
    },
}

/// Two providers set different `env.set` values for one variable in one
/// profile (see [`MergeError::EnvSetConflict`]).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error(
    "profile {:?}: conflicting env.set values for {:?}: {:?} (provider {:?}) and {:?} (provider {:?})",
    .profile.as_str(),
    .name.as_str(),
    .first.as_str(),
    .first_provider.as_str(),
    .second.as_str(),
    .second_provider.as_str()
)]
pub struct EnvSetConflict {
    /// The profile.
    pub profile: ProfileRef,
    /// The variable.
    pub name: EnvName,
    /// The provider that set the first value.
    pub first_provider: ProviderName,
    /// The first value.
    pub first: EnvValue,
    /// The provider that set the conflicting value.
    pub second_provider: ProviderName,
    /// The conflicting value.
    pub second: EnvValue,
}

/// Computes every profile's effective grants, walking the profiles parents
/// first so that each parent's effective grants are known before its
/// children's.
pub fn merge_profiles(graph: &ProfileGraph) -> Result<MergedProfiles, MergeError> {
    let empty = EffectiveGrants::default();
    let mut profiles: BTreeMap<ProfileRef, EffectiveGrants> = BTreeMap::new();
    for (profile, node) in graph.iter() {
        // `inherit = "none"` (and `main`) start from the empty sandbox.
        let inherited = match &node.parent {
            Some(parent) => profiles
                .get(parent)
                .expect("the graph orders parents before children"),
            None => &empty,
        };
        let merged = merge_profile(profile, inherited, &node.contributions)?;
        profiles.insert(profile.clone(), merged);
    }
    Ok(MergedProfiles {
        profiles,
        order: graph.order().to_vec(),
    })
}

/// Combines a profile's inherited effective grants with its own
/// contributions.
fn merge_profile(
    profile: &ProfileRef,
    inherited: &EffectiveGrants,
    own: &[Contribution],
) -> Result<EffectiveGrants, MergeError> {
    Ok(EffectiveGrants {
        fs: merge_fs_rules(&inherited.fs, own),
        mask_sockets: merge_mask_sockets(inherited.mask_sockets, own),
        system: EffectiveSystem {
            proc: merge_proc(inherited.system.proc, own),
            dev: merge_dev(inherited.system.dev, own),
            etc: merge_etc(&inherited.system.etc, own),
            home: merge_home(profile, inherited.system.home.as_ref(), own)?,
        },
        env: EffectiveEnv {
            pass: union_ordered(&inherited.env.pass, own.iter().map(|c| &c.grants.env.pass)),
            deny: union_ordered(&inherited.env.deny, own.iter().map(|c| &c.grants.env.deny)),
            set: merge_env_set(profile, &inherited.env.set, own)?,
            path_prepend: merge_path_prepend(&inherited.env.path_prepend, own),
        },
        network: EffectiveNetwork {
            mode: merge_network_mode(inherited.network.mode, own),
            allow_domains: union(
                &inherited.network.allow_domains,
                own.iter().map(|c| &c.grants.network.allow_domains),
            ),
        },
        sandbox: EffectiveSandbox {
            share: union(
                &inherited.sandbox.share,
                own.iter().map(|c| &c.grants.sandbox.share),
            ),
            allow_syscalls: union(
                &inherited.sandbox.allow_syscalls,
                own.iter().map(|c| &c.grants.sandbox.allow_syscalls),
            ),
        },
        shims: merge_shims(profile, &inherited.shims, own)?,
    })
}

/// Combines the explicit values of a profile's own contributions with
/// `combine`; `None` when no contribution sets one.
fn within_profile<T: Copy>(
    values: impl IntoIterator<Item = Option<T>>,
    combine: impl Fn(T, T) -> T,
) -> Option<T> {
    values.into_iter().flatten().reduce(combine)
}

/// `system.proc` (§3.5): logical OR within a profile; a profile's own
/// explicit value (even `false`) overrides the inherited one. Default false.
fn merge_proc(inherited: bool, own: &[Contribution]) -> bool {
    within_profile(own.iter().map(|c| c.grants.system.proc), |a, b| a || b).unwrap_or(inherited)
}

/// `system.dev` (§3.5): logical OR within a profile (any `minimal` wins); a
/// profile's own explicit value overrides the inherited one. Default none.
fn merge_dev(inherited: Option<DevMode>, own: &[Contribution]) -> Option<DevMode> {
    // `minimal` is the only mode, so OR is "any explicit value".
    within_profile(own.iter().map(|c| c.grants.system.dev), |a, _| a).or(inherited)
}

/// `system.etc` (§3.5): union with the inherited files.
fn merge_etc(inherited: &BTreeSet<EtcFile>, own: &[Contribution]) -> BTreeSet<EtcFile> {
    union(inherited, own.iter().map(|c| &c.grants.system.etc))
}

/// `system.home` (§3.5): higher [`ProviderOrigin`] overrides lower within a
/// profile, while conflicting values within the same origin are an error and
/// identical values pass; a profile's own value overrides the inherited one.
fn merge_home(
    profile: &ProfileRef,
    inherited: Option<&SandboxHome>,
    own: &[Contribution],
) -> Result<Option<SandboxHome>, MergeError> {
    let mut found: Option<(&SandboxHome, &ProviderName, ProviderOrigin)> = None;
    for c in own {
        let Some(home) = &c.grants.system.home else {
            continue;
        };
        match found {
            None => found = Some((home, &c.provider, c.origin)),
            Some((_, _, first_origin)) if c.origin > first_origin => {
                found = Some((home, &c.provider, c.origin));
            }
            Some((_, _, first_origin)) if c.origin < first_origin => {}
            Some((first, _, _)) if first == home => {}
            Some((first, first_provider, _)) => {
                return Err(MergeError::HomeConflict {
                    profile: profile.clone(),
                    first_provider: first_provider.clone(),
                    first: first.clone(),
                    second_provider: c.provider.clone(),
                    second: home.clone(),
                });
            }
        }
    }
    Ok(found.map(|(home, _, _)| home).or(inherited).cloned())
}

/// `env.pass` / `env.deny` (§3.5): union with the inherited patterns,
/// keeping the first occurrence of each (inherited patterns first, then the
/// own ones in contribution order). `deny` is not applied to `pass` here.
fn union_ordered<'a, T: Clone + PartialEq + 'a>(
    inherited: &[T],
    own: impl IntoIterator<Item = &'a Vec<T>>,
) -> Vec<T> {
    let mut out = inherited.to_vec();
    dedup_extend(&mut out, own.into_iter().flatten());
    out
}

/// Appends each item not already in `out`, in order.
fn dedup_extend<'a, T: Clone + PartialEq + 'a>(
    out: &mut Vec<T>,
    items: impl IntoIterator<Item = &'a T>,
) {
    for item in items {
        if !out.contains(item) {
            out.push(item.clone());
        }
    }
}

/// `env.set` (§3.5, §9): higher [`ProviderOrigin`] overrides lower per
/// variable within a profile, while conflicting values within the same origin
/// are an error unless identical; a profile's own value overrides the
/// inherited one, variable by variable.
fn merge_env_set(
    profile: &ProfileRef,
    inherited: &BTreeMap<EnvName, EnvValue>,
    own: &[Contribution],
) -> Result<BTreeMap<EnvName, EnvValue>, MergeError> {
    let mut found: BTreeMap<&EnvName, (&EnvValue, &ProviderName, ProviderOrigin)> = BTreeMap::new();
    for c in own {
        for (name, value) in &c.grants.env.set {
            match found.get(name) {
                None => {
                    found.insert(name, (value, &c.provider, c.origin));
                }
                Some((_, _, first_origin)) if c.origin > *first_origin => {
                    found.insert(name, (value, &c.provider, c.origin));
                }
                Some((_, _, first_origin)) if c.origin < *first_origin => {}
                Some((first, _, _)) if *first == value => {}
                Some((first, first_provider, _)) => {
                    return Err(MergeError::EnvSetConflict(Box::new(EnvSetConflict {
                        profile: profile.clone(),
                        name: name.clone(),
                        first_provider: (*first_provider).clone(),
                        first: (*first).clone(),
                        second_provider: c.provider.clone(),
                        second: value.clone(),
                    })));
                }
            }
        }
    }
    let mut out = inherited.clone();
    out.extend(
        found
            .into_iter()
            .map(|(name, (value, _, _))| (name.clone(), value.clone())),
    );
    Ok(out)
}

/// `env.path_prepend` (§3.5): "more specific wins". Within a profile, later
/// contributions' entries come before earlier ones (so a user provider
/// overrides the base), each contribution's entries in written order; then
/// the inherited entries. Duplicates keep the first occurrence. Earlier
/// entries take precedence in `PATH`, so later providers' directories
/// shadow earlier ones, and a profile's own directories shadow inherited
/// ones.
fn merge_path_prepend(inherited: &[SearchPathEntry], own: &[Contribution]) -> Vec<SearchPathEntry> {
    let mut out = Vec::new();
    dedup_extend(
        &mut out,
        own.iter().rev().flat_map(|c| &c.grants.env.path_prepend),
    );
    dedup_extend(&mut out, inherited);
    out
}

/// `network.mode` (§3.5, §8): within a profile the most permissive explicit
/// mode; a profile's own explicit value overrides the inherited one, even
/// when it is less permissive. Default `none`.
fn merge_network_mode(inherited: NetworkMode, own: &[Contribution]) -> NetworkMode {
    within_profile(
        own.iter().map(|c| c.grants.network.mode),
        NetworkMode::more_permissive,
    )
    .unwrap_or(inherited)
}

/// `network.allow_domains`, `sandbox.share`, `sandbox.allow_syscalls` and
/// `system.etc` (§3.5): union with the inherited values.
fn union<'a, T: Clone + Ord + 'a>(
    inherited: &BTreeSet<T>,
    own: impl IntoIterator<Item = &'a Vec<T>>,
) -> BTreeSet<T> {
    let mut out = inherited.clone();
    out.extend(own.into_iter().flatten().cloned());
    out
}

/// `shims` (§3.5): higher [`ProviderOrigin`] replaces lower for the same shim
/// name within a profile, while the same shim name from two contributions in
/// the same origin is an error naming both providers; a profile's own shim
/// replaces an inherited one of the same name.
fn merge_shims(
    profile: &ProfileRef,
    inherited: &BTreeMap<ShimName, (ShimSpec, ProviderName)>,
    own: &[Contribution],
) -> Result<BTreeMap<ShimName, (ShimSpec, ProviderName)>, MergeError> {
    let mut found: BTreeMap<&ShimName, (&ShimSpec, &ProviderName, ProviderOrigin)> =
        BTreeMap::new();
    for c in own {
        for (shim, spec) in &c.grants.shims {
            match found.get(shim) {
                None => {
                    found.insert(shim, (spec, &c.provider, c.origin));
                }
                Some((_, _, first_origin)) if c.origin > *first_origin => {
                    found.insert(shim, (spec, &c.provider, c.origin));
                }
                Some((_, _, first_origin)) if c.origin < *first_origin => {}
                Some((_, first_provider, _)) => {
                    return Err(MergeError::DuplicateShim {
                        profile: profile.clone(),
                        shim: shim.clone(),
                        first_provider: (*first_provider).clone(),
                        second_provider: c.provider.clone(),
                    });
                }
            }
        }
    }
    let mut out = inherited.clone();
    out.extend(
        found
            .into_iter()
            .map(|(shim, (spec, provider, _))| (shim.clone(), (spec.clone(), provider.clone()))),
    );
    Ok(out)
}

/// `fs.mask_sockets` (§3.5): within a profile `true` wins over `false`
/// (strictest wins); a profile's own explicit value (even `false`)
/// overrides the inherited one. Default false.
fn merge_mask_sockets(inherited: bool, own: &[Contribution]) -> bool {
    within_profile(own.iter().map(|c| c.grants.fs.mask_sockets), |a, b| a || b).unwrap_or(inherited)
}

/// Path rules and binds (§3.5): not merged here, only collected. Inherited
/// rules are kept with their depth increased by one, followed by the
/// profile's own rules at depth 0. `inherit = "none"` cuts the chain, since
/// such a profile inherits nothing.
fn merge_fs_rules(inherited: &[FsRule], own: &[Contribution]) -> Vec<FsRule> {
    let mut out: Vec<FsRule> = inherited
        .iter()
        .map(|r| FsRule {
            depth: r.depth + 1,
            ..r.clone()
        })
        .collect();
    for c in own {
        out.extend(fs_rules(&c.grants.fs).map(|kind| FsRule {
            kind,
            provider: c.provider.clone(),
            origin: c.origin,
            depth: 0,
        }));
    }
    out
}

/// One contribution's path rules (`rw`, `ro`, `masked`, `protected`,
/// `ephemeral`, each in written order), then its binds.
fn fs_rules(fs: &FsGrants) -> impl Iterator<Item = FsRuleKind> + '_ {
    let lists = [
        (PathMode::Rw, &fs.rw),
        (PathMode::Ro, &fs.ro),
        (PathMode::Masked, &fs.masked),
        (PathMode::Protected, &fs.protected),
        (PathMode::Ephemeral, &fs.ephemeral),
    ];
    lists
        .into_iter()
        .flat_map(|(mode, patterns)| {
            patterns.iter().map(move |pattern| FsRuleKind::Path {
                mode,
                pattern: pattern.clone(),
            })
        })
        .chain(fs.bind.iter().cloned().map(FsRuleKind::Bind))
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::config::Config;
    use crate::manifest::BindMode;
    use crate::provider::{ProviderContext, from_entry};
    use crate::resolve::build_profile_graph;

    fn pr(s: &str) -> ProfileRef {
        s.parse().unwrap()
    }

    fn pn(s: &str) -> ProviderName {
        s.parse().unwrap()
    }

    /// The graph of `src`, built from its own (`config`) providers.
    fn graph(src: &str) -> ProfileGraph {
        let cfg = Config::from_toml_str(src).unwrap();
        let ctx = ProviderContext {
            workspace: PathBuf::from("/w"),
            workspace_mount: "/workspace".parse().unwrap(),
            home: PathBuf::from("/home/u"),
            session_dir: PathBuf::from("/run/s"),
            rw_grants: Vec::new(),
        };
        let outputs = cfg
            .providers
            .iter()
            .map(|e| {
                let p = from_entry(e, Path::new("/cfg")).unwrap();
                (p.name().clone(), p.manifest(&ctx).unwrap())
            })
            .collect();
        build_profile_graph(&cfg, outputs).unwrap()
    }

    fn merged(src: &str) -> MergedProfiles {
        merge_profiles(&graph(src)).unwrap()
    }

    fn merge_err(src: &str) -> MergeError {
        match merge_profiles(&graph(src)) {
            Ok(m) => panic!("expected an error, got {m:?}"),
            Err(e) => e,
        }
    }

    /// A `config` provider named `name` applying `body` (keys of
    /// `[provider.sandbox]`) to `profile`.
    fn prov(name: &str, profile: &str, body: &str) -> String {
        format!(
            "[[provider]]\ntype = \"config\"\nname = \"{name}\"\nprofile = \"{profile}\"\n\
             [provider.sandbox]\n{body}\n"
        )
    }

    fn eff<'a>(m: &'a MergedProfiles, p: &str) -> &'a EffectiveGrants {
        m.get(&pr(p)).unwrap_or_else(|| panic!("no profile {p}"))
    }

    fn strs<T: ToString>(items: impl IntoIterator<Item = T>) -> Vec<String> {
        items.into_iter().map(|t| t.to_string()).collect()
    }

    fn home<'a>(m: &'a MergedProfiles, p: &str) -> Option<&'a str> {
        eff(m, p).system.home.as_ref().map(SandboxHome::as_str)
    }

    fn set(m: &MergedProfiles, p: &str) -> Vec<(String, String)> {
        eff(m, p)
            .env
            .set
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// Each shim with its binary and provider.
    fn shims(m: &MergedProfiles, p: &str) -> Vec<(String, String, String)> {
        eff(m, p)
            .shims
            .iter()
            .map(|(name, (spec, provider))| {
                (
                    name.to_string(),
                    spec.binary.to_string(),
                    provider.to_string(),
                )
            })
            .collect()
    }

    /// Each fs rule as `(mode, pattern or host, provider, depth)`.
    fn fs(m: &MergedProfiles, p: &str) -> Vec<(String, String, String, u32)> {
        eff(m, p)
            .fs
            .iter()
            .map(|r| {
                let (mode, what) = match &r.kind {
                    FsRuleKind::Path { mode, pattern } => (mode.to_string(), pattern.to_string()),
                    FsRuleKind::Bind(b) => (format!("bind-{}", b.mode), b.host.to_string()),
                };
                (mode, what, r.provider.to_string(), r.depth)
            })
            .collect()
    }

    fn rule(mode: &str, what: &str, provider: &str, depth: u32) -> (String, String, String, u32) {
        (mode.to_owned(), what.to_owned(), provider.to_owned(), depth)
    }

    const CHAIN: &str = r#"
        [profiles.gp]
        [profiles.parent]
        inherit = "gp"
        [profiles.child]
        inherit = "parent"
    "#;

    #[test]
    fn defaults_are_the_empty_sandbox() {
        let m = merged("[profiles.harness]");
        for p in ["main", "harness"] {
            let e = eff(&m, p);
            assert_eq!(e, &EffectiveGrants::default());
            assert!(!e.system.proc);
            assert_eq!(e.system.dev, None);
            assert!(e.system.etc.is_empty());
            assert_eq!(e.system.home, None);
            assert_eq!(e.network.mode, NetworkMode::None);
            assert!(!e.mask_sockets);
            assert!(e.fs.is_empty() && e.shims.is_empty());
        }
        // Empty contributions change nothing either.
        let m = merged(&format!(
            "{}{}",
            prov("a", "main", ""),
            prov("b", "main", "")
        ));
        assert_eq!(eff(&m, "main"), &EffectiveGrants::default());
    }

    #[test]
    fn lookup_and_iteration_follow_the_graph() {
        let src = format!(
            "{CHAIN}\n[profiles.bare]\ninherit = \"none\"\n{}",
            prov(
                "v",
                "main",
                "[provider.sandbox.profiles.x]\ninherit = \"child\""
            )
        );
        let g = graph(&src);
        let m = merge_profiles(&g).unwrap();
        assert_eq!(m.order(), g.order());
        let names: Vec<&str> = m.iter().map(|(p, _)| p.as_str()).collect();
        let want: Vec<&str> = g.order().iter().map(ProfileRef::as_str).collect();
        assert_eq!(names, want);
        assert_eq!(m.len(), g.len());
        assert_eq!(m.len(), 6);
        assert!(!m.is_empty());
        assert!(m.get(&pr("v.x")).is_some());
        assert!(m.get(&pr("nope")).is_none());
    }

    #[test]
    fn proc_is_or_within_and_own_overrides_inherited() {
        let m = merged(&format!(
            "[profiles.off]\n[profiles.unset]\n[profiles.mixed]\n\
             [profiles.bare]\ninherit = \"none\"\n{}{}{}{}{}{}{}",
            prov("a", "main", "system.proc = true"),
            prov("b", "off", "system.proc = false"),
            prov("c", "mixed", "system.proc = false"),
            prov("d", "mixed", "system.proc = true"),
            prov("e", "mixed", "system.proc = false"),
            prov("f", "bare", "system.proc = false"),
            prov("g", "bare", ""),
        ));
        assert!(eff(&m, "main").system.proc);
        // Own explicit `false` overrides the inherited `true`.
        assert!(!eff(&m, "off").system.proc);
        // Unset inherits.
        assert!(eff(&m, "unset").system.proc);
        // Within a profile any `true` wins, wherever it is.
        assert!(eff(&m, "mixed").system.proc);
        // Only `false` (and unset) within a profile: false.
        assert!(!eff(&m, "bare").system.proc);
        // No contribution at all and nothing inherited: false.
        assert!(!merged("").get(&ProfileRef::main()).unwrap().system.proc);
    }

    #[test]
    fn dev_is_or_within_and_own_overrides_inherited() {
        let m = merged(&format!(
            "[profiles.unset]\n[profiles.bare]\ninherit = \"none\"\n{}{}{}{}",
            prov("a", "main", "system.dev = \"minimal\""),
            prov("b", "main", ""),
            prov("c", "bare", ""),
            prov("d", "bare", "system.dev = \"minimal\""),
        ));
        assert_eq!(eff(&m, "main").system.dev, Some(DevMode::Minimal));
        assert_eq!(eff(&m, "unset").system.dev, Some(DevMode::Minimal));
        // Any explicit value within a profile wins, wherever it is.
        assert_eq!(eff(&m, "bare").system.dev, Some(DevMode::Minimal));
        assert_eq!(
            merged("[profiles.p]").get(&pr("p")).unwrap().system.dev,
            None
        );
    }

    #[test]
    fn etc_is_a_union() {
        let m = merged(&format!(
            "[profiles.child]\n[profiles.bare]\ninherit = \"none\"\n{}{}{}{}",
            prov("a", "main", "system.etc = [\"passwd\", \"hosts\"]"),
            prov("b", "main", "system.etc = [\"group\", \"passwd\"]"),
            prov("c", "child", "system.etc = [\"nsswitch.conf\"]"),
            prov("d", "bare", "system.etc = [\"hosts\"]"),
        ));
        // Ordered by declaration: passwd, group, hosts, nsswitch.conf.
        assert_eq!(
            strs(&eff(&m, "main").system.etc),
            ["passwd", "group", "hosts"]
        );
        assert_eq!(
            strs(&eff(&m, "child").system.etc),
            ["passwd", "group", "hosts", "nsswitch.conf"]
        );
        assert_eq!(strs(&eff(&m, "bare").system.etc), ["hosts"]);
    }

    #[test]
    fn home_conflicts_within_and_own_overrides_inherited() {
        let m = merged(&format!(
            "[profiles.child]\n[profiles.unset]\n{}{}{}{}",
            prov("a", "main", "system.home = \"/home/user\""),
            // Identical values within a profile are fine.
            prov("b", "main", "system.home = \"/home/user\""),
            prov("c", "child", ""),
            prov("d", "child", "system.home = \"/home/agent\""),
        ));
        assert_eq!(home(&m, "main"), Some("/home/user"));
        assert_eq!(home(&m, "child"), Some("/home/agent"));
        assert_eq!(home(&m, "unset"), Some("/home/user"));
        assert_eq!(home(&merged("[profiles.p]"), "p"), None);
    }

    #[test]
    fn env_pass_and_deny_are_ordered_deduplicated_unions() {
        let m = merged(&format!(
            "[profiles.child]\n[profiles.bare]\ninherit = \"none\"\n{}{}{}{}",
            prov(
                "a",
                "main",
                "env.pass = [\"TERM\", \"LANG\", \"TERM\"]\nenv.deny = [\"*_TOKEN\"]"
            ),
            prov(
                "b",
                "main",
                "env.pass = [\"LANG\", \"CARGO_*\"]\nenv.deny = [\"AWS_*\", \"*_TOKEN\"]"
            ),
            prov(
                "c",
                "child",
                "env.pass = [\"RUST_*\", \"TERM\"]\nenv.deny = [\"CARGO_*\"]"
            ),
            prov("d", "bare", "env.pass = [\"X\"]"),
        ));
        assert_eq!(strs(&eff(&m, "main").env.pass), ["TERM", "LANG", "CARGO_*"]);
        assert_eq!(strs(&eff(&m, "main").env.deny), ["*_TOKEN", "AWS_*"]);
        assert_eq!(
            strs(&eff(&m, "child").env.pass),
            ["TERM", "LANG", "CARGO_*", "RUST_*"]
        );
        // `deny` is not applied to `pass` here: `CARGO_*` is in both.
        assert_eq!(
            strs(&eff(&m, "child").env.deny),
            ["*_TOKEN", "AWS_*", "CARGO_*"]
        );
        assert_eq!(strs(&eff(&m, "bare").env.pass), ["X"]);
        assert!(eff(&m, "bare").env.deny.is_empty());
    }

    #[test]
    fn env_set_merges_per_variable() {
        let m = merged(&format!(
            "[profiles.child]\n[profiles.bare]\ninherit = \"none\"\n{}{}{}{}",
            prov("a", "main", "env.set = { EDITOR = \"vi\", LANG = \"C\" }"),
            // Identical values within a profile are fine.
            prov("b", "main", "env.set = { LANG = \"C\", PAGER = \"less\" }"),
            prov("c", "child", "env.set = { EDITOR = \"nvim\", NEW = \"1\" }"),
            prov("d", "bare", "env.set = { ONLY = \"x\" }"),
        ));
        let pairs = |v: &[(&str, &str)]| -> Vec<(String, String)> {
            v.iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        };
        assert_eq!(
            set(&m, "main"),
            pairs(&[("EDITOR", "vi"), ("LANG", "C"), ("PAGER", "less")])
        );
        // Own overrides inherited per variable; other inherited ones stay.
        assert_eq!(
            set(&m, "child"),
            pairs(&[
                ("EDITOR", "nvim"),
                ("LANG", "C"),
                ("NEW", "1"),
                ("PAGER", "less")
            ])
        );
        assert_eq!(set(&m, "bare"), pairs(&[("ONLY", "x")]));
    }

    #[test]
    fn path_prepend_puts_later_and_own_entries_first() {
        let m = merged(&format!(
            "[profiles.child]\n[profiles.bare]\ninherit = \"none\"\n{}{}{}{}{}",
            prov("a", "main", "env.path_prepend = [\"/a\", \"/b\"]"),
            prov("b", "main", "env.path_prepend = [\"/c\", \"/a\"]"),
            prov("c", "child", "env.path_prepend = [\"/d\", \"/c\"]"),
            prov("d", "child", "env.path_prepend = [\"/e\", \"/d\"]"),
            prov("e", "bare", "env.path_prepend = [\"/x\"]"),
        ));
        // Within a profile the later provider's entries come first, each
        // contribution's entries in written order; duplicates keep the first
        // occurrence.
        assert_eq!(strs(&eff(&m, "main").env.path_prepend), ["/c", "/a", "/b"]);
        // Own entries (later providers first) shadow the inherited ones; an
        // inherited entry repeated by the child moves to the child's place.
        assert_eq!(
            strs(&eff(&m, "child").env.path_prepend),
            ["/e", "/d", "/c", "/a", "/b"]
        );
        assert_eq!(strs(&eff(&m, "bare").env.path_prepend), ["/x"]);
        // The target's `PATH` is those entries, in that order (§9).
        let path = |profile: &str| {
            let env = eff(&m, profile).env.apply(&Default::default(), []);
            let (_, path) = env.into_iter().find(|(k, _)| k == "PATH").unwrap();
            path
        };
        assert_eq!(path("child"), "/e:/d:/c:/a:/b");
        assert_eq!(path("main"), "/c:/a:/b");
    }

    #[test]
    fn network_mode_is_most_permissive_within_and_own_overrides() {
        let m = merged(&format!(
            "[profiles.strict]\n[profiles.unset]\n[profiles.bare]\ninherit = \"none\"\n{}{}{}{}{}",
            prov("a", "main", "network.mode = \"proxy\""),
            prov("b", "main", "network.mode = \"loopback\""),
            prov("c", "main", ""),
            prov("d", "strict", "network.mode = \"none\""),
            prov("e", "bare", "network.allow_domains = [\"crates.io\"]"),
        ));
        assert_eq!(eff(&m, "main").network.mode, NetworkMode::Proxy);
        // Own explicit overrides inherited, even when less permissive.
        assert_eq!(eff(&m, "strict").network.mode, NetworkMode::None);
        assert_eq!(eff(&m, "unset").network.mode, NetworkMode::Proxy);
        // Nothing explicit and nothing inherited: none.
        assert_eq!(eff(&m, "bare").network.mode, NetworkMode::None);

        let m = merged(&format!(
            "[profiles.child]\n{}{}",
            prov("a", "child", "network.mode = \"full\""),
            prov("b", "child", "network.mode = \"loopback\""),
        ));
        assert_eq!(eff(&m, "child").network.mode, NetworkMode::Full);
        assert_eq!(eff(&m, "main").network.mode, NetworkMode::None);
    }

    #[test]
    fn allow_domains_is_a_union() {
        let m = merged(&format!(
            "[profiles.child]\n[profiles.bare]\ninherit = \"none\"\n{}{}{}{}",
            prov(
                "a",
                "main",
                "network.allow_domains = [\"index.crates.io\", \"github.com\"]"
            ),
            prov("b", "main", "network.allow_domains = [\"github.com\"]"),
            prov(
                "c",
                "child",
                "network.allow_domains = [\"cache.nixos.org\"]"
            ),
            prov("d", "bare", "network.allow_domains = [\"pypi.org\"]"),
        ));
        assert_eq!(
            strs(&eff(&m, "main").network.allow_domains),
            ["github.com", "index.crates.io"]
        );
        assert_eq!(
            strs(&eff(&m, "child").network.allow_domains),
            ["cache.nixos.org", "github.com", "index.crates.io"]
        );
        assert_eq!(strs(&eff(&m, "bare").network.allow_domains), ["pypi.org"]);
    }

    #[test]
    fn sandbox_opt_outs_are_unions() {
        let m = merged(&format!(
            "[profiles.child]\n[profiles.bare]\ninherit = \"none\"\n{}{}{}{}",
            prov(
                "a",
                "main",
                "sandbox.share = [\"ipc\"]\nsandbox.allow_syscalls = [\"keyctl\"]"
            ),
            prov(
                "b",
                "main",
                "sandbox.share = [\"net\", \"ipc\"]\nsandbox.allow_syscalls = [\"ptrace\"]"
            ),
            prov(
                "c",
                "child",
                "sandbox.share = [\"pid\"]\nsandbox.allow_syscalls = [\"keyctl\", \"bpf\"]"
            ),
            prov("d", "bare", "sandbox.share = [\"uts\"]"),
        ));
        // Ordered by declaration.
        assert_eq!(strs(&eff(&m, "main").sandbox.share), ["net", "ipc"]);
        assert_eq!(
            strs(&eff(&m, "main").sandbox.allow_syscalls),
            ["ptrace", "keyctl"]
        );
        assert_eq!(strs(&eff(&m, "child").sandbox.share), ["net", "pid", "ipc"]);
        assert_eq!(
            strs(&eff(&m, "child").sandbox.allow_syscalls),
            ["ptrace", "bpf", "keyctl"]
        );
        assert_eq!(strs(&eff(&m, "bare").sandbox.share), ["uts"]);
        assert!(eff(&m, "bare").sandbox.allow_syscalls.is_empty());
    }

    fn shim(name: &str, binary: &str) -> String {
        format!("shims.{name} = {{ binary = \"{binary}\", default = {{ decision = \"deny\" }} }}")
    }

    fn triples(v: &[(&str, &str, &str)]) -> Vec<(String, String, String)> {
        v.iter()
            .map(|(a, b, c)| (a.to_string(), b.to_string(), c.to_string()))
            .collect()
    }

    #[test]
    fn shims_union_and_own_replaces_inherited() {
        let m = merged(&format!(
            "[profiles.child]\n[profiles.bare]\ninherit = \"none\"\n{}{}{}{}",
            prov("a", "main", &shim("jj", "jj")),
            prov(
                "b",
                "main",
                &format!("{}\n{}", shim("git", "git"), shim("gh", "gh"))
            ),
            prov("c", "child", &shim("jj", "jj-wrapped")),
            prov("d", "bare", &shim("x", "x")),
        ));
        assert_eq!(
            shims(&m, "main"),
            triples(&[("gh", "gh", "b"), ("git", "git", "b"), ("jj", "jj", "a")])
        );
        assert_eq!(
            shims(&m, "child"),
            triples(&[
                ("gh", "gh", "b"),
                ("git", "git", "b"),
                ("jj", "jj-wrapped", "c")
            ])
        );
        assert_eq!(shims(&m, "bare"), triples(&[("x", "x", "d")]));
        // The spec itself is carried over unchanged.
        let g = graph(&prov("a", "main", &shim("jj", "jj")));
        let m = merge_profiles(&g).unwrap();
        let own = &g.get(&ProfileRef::main()).unwrap().contributions[0]
            .grants
            .shims;
        let (spec, provider) = &eff(&m, "main").shims[&"jj".parse().unwrap()];
        assert_eq!(spec, &own[&"jj".parse().unwrap()]);
        assert_eq!(provider, &pn("a"));
    }

    #[test]
    fn mask_sockets_true_wins_within_and_own_overrides() {
        let m = merged(&format!(
            "[profiles.off]\n[profiles.unset]\n[profiles.mixed]\n\
             [profiles.bare]\ninherit = \"none\"\n{}{}{}{}{}{}",
            prov("a", "main", "fs.mask_sockets = true"),
            prov("b", "off", "fs.mask_sockets = false"),
            prov("c", "mixed", "fs.mask_sockets = true"),
            prov("d", "mixed", "fs.mask_sockets = false"),
            prov("e", "bare", "fs.mask_sockets = false"),
            prov("f", "bare", ""),
        ));
        assert!(eff(&m, "main").mask_sockets);
        // A profile can opt out of masking that `main` enables.
        assert!(!eff(&m, "off").mask_sockets);
        assert!(eff(&m, "unset").mask_sockets);
        assert!(eff(&m, "mixed").mask_sockets);
        assert!(!eff(&m, "bare").mask_sockets);
        assert!(!eff(&merged("[profiles.p]"), "p").mask_sockets);
    }

    #[test]
    fn fs_rules_are_collected_with_provider_and_depth() {
        let m = merged(&format!(
            "[profiles.child]\n{}{}{}",
            prov(
                "a",
                "main",
                r#"fs.ephemeral = ["/tmp"]
                fs.bind = [{ host = "/etc/ssl/certs", sandbox = "/etc/ssl/certs", mode = "ro" }]
                fs.protected = ["{workspace}/flake.nix"]
                fs.masked = ["{workspace}/.git", "{workspace}/**/.env"]
                fs.ro = ["/etc/x"]
                fs.rw = ["{workspace}"]"#
            ),
            prov("b", "main", "fs.ro = [\"/nix/store\"]"),
            prov(
                "c",
                "child",
                "fs.rw = [\"{workspace}/.git\"]\nfs.bind = [{ host = \"~/.gitconfig\", sandbox = \"~/.gitconfig\", mode = \"protected\" }]"
            ),
        ));
        let main = vec![
            rule("rw", "{workspace}", "a", 0),
            rule("ro", "/etc/x", "a", 0),
            rule("masked", "{workspace}/.git", "a", 0),
            rule("masked", "{workspace}/**/.env", "a", 0),
            rule("protected", "{workspace}/flake.nix", "a", 0),
            rule("ephemeral", "/tmp", "a", 0),
            rule("bind-ro", "/etc/ssl/certs", "a", 0),
            rule("ro", "/nix/store", "b", 0),
        ];
        assert_eq!(fs(&m, "main"), main);
        let mut child: Vec<_> = main.into_iter().map(|(a, b, c, _)| (a, b, c, 1)).collect();
        child.push(rule("rw", "{workspace}/.git", "c", 0));
        child.push(rule("bind-protected", "~/.gitconfig", "c", 0));
        assert_eq!(fs(&m, "child"), child);
        // The bind itself is carried over unchanged.
        let FsRuleKind::Bind(b) = &eff(&m, "child").fs[9].kind else {
            panic!("expected a bind");
        };
        assert_eq!(b.sandbox.as_str(), "~/.gitconfig");
        assert_eq!(b.mode, BindMode::Protected);
    }

    #[test]
    fn inherit_none_starts_empty() {
        let m = merged(&format!(
            "[profiles.bare]\ninherit = \"none\"\n[profiles.empty]\ninherit = \"none\"\n\
             [profiles.below]\ninherit = \"bare\"\n{}{}",
            prov(
                "a",
                "main",
                &format!(
                    "fs.rw = [\"{{workspace}}\"]\nfs.mask_sockets = true\n\
                     system = {{ proc = true, dev = \"minimal\", etc = [\"passwd\"], home = \"/home/user\" }}\n\
                     env = {{ pass = [\"TERM\"], deny = [\"*_TOKEN\"], set = {{ A = \"1\" }}, path_prepend = [\"/bin\"] }}\n\
                     network = {{ mode = \"loopback\", allow_domains = [\"crates.io\"] }}\n\
                     sandbox = {{ share = [\"ipc\"], allow_syscalls = [\"ptrace\"] }}\n{}",
                    shim("jj", "jj")
                )
            ),
            prov("b", "bare", "fs.ro = [\"/opt\"]\nenv.set = { B = \"2\" }"),
        ));
        assert_ne!(eff(&m, "main"), &EffectiveGrants::default());
        assert_eq!(eff(&m, "empty"), &EffectiveGrants::default());
        let bare = EffectiveGrants {
            fs: vec![FsRule {
                kind: FsRuleKind::Path {
                    mode: PathMode::Ro,
                    pattern: "/opt".parse().unwrap(),
                },
                provider: pn("b"),
                origin: ProviderOrigin::Workspace,
                depth: 0,
            }],
            env: EffectiveEnv {
                set: BTreeMap::from([("B".parse().unwrap(), "2".parse().unwrap())]),
                ..EffectiveEnv::default()
            },
            ..EffectiveGrants::default()
        };
        assert_eq!(eff(&m, "bare"), &bare);
        // The chain is cut: below `bare`, `main`'s rules never appear.
        assert_eq!(fs(&m, "below"), [rule("ro", "/opt", "b", 1)]);
        assert_eq!(set(&m, "below"), set(&m, "bare"));
    }

    #[test]
    fn three_level_chain() {
        let m = merged(&format!(
            "{CHAIN}{}{}{}{}{}",
            prov("m", "main", "fs.ro = [\"/m\"]"),
            prov(
                "g",
                "gp",
                &format!(
                    "network.mode = \"full\"\nsystem.home = \"/home/gp\"\n\
                     env.set = {{ A = \"gp\", B = \"gp\", C = \"gp\" }}\nfs.ro = [\"/gp\"]\n{}\n{}",
                    shim("s1", "gp1"),
                    shim("s2", "gp2")
                )
            ),
            prov(
                "p",
                "parent",
                &format!(
                    "network.mode = \"loopback\"\nenv.set = {{ B = \"parent\" }}\nfs.ro = [\"/parent\"]\n{}",
                    shim("s1", "parent1")
                )
            ),
            prov(
                "c",
                "child",
                &format!(
                    "system.home = \"/home/child\"\nenv.set = {{ C = \"child\" }}\nfs.ro = [\"/child\"]\n{}",
                    shim("s3", "child3")
                )
            ),
            prov("c2", "child", "fs.rw = [\"/child2\"]"),
        ));

        // network.mode: each explicit level overrides; unset inherits.
        assert_eq!(eff(&m, "main").network.mode, NetworkMode::None);
        assert_eq!(eff(&m, "gp").network.mode, NetworkMode::Full);
        assert_eq!(eff(&m, "parent").network.mode, NetworkMode::Loopback);
        assert_eq!(eff(&m, "child").network.mode, NetworkMode::Loopback);

        // system.home: unset in `parent` inherits from `gp`.
        assert_eq!(home(&m, "gp"), Some("/home/gp"));
        assert_eq!(home(&m, "parent"), Some("/home/gp"));
        assert_eq!(home(&m, "child"), Some("/home/child"));

        // env.set: per variable, the nearest level that sets it wins.
        let want = |a: &str, b: &str, c: &str| {
            vec![
                ("A".to_owned(), a.to_owned()),
                ("B".to_owned(), b.to_owned()),
                ("C".to_owned(), c.to_owned()),
            ]
        };
        assert_eq!(set(&m, "gp"), want("gp", "gp", "gp"));
        assert_eq!(set(&m, "parent"), want("gp", "parent", "gp"));
        assert_eq!(set(&m, "child"), want("gp", "parent", "child"));

        // shims: replaced by the nearest level that grants them.
        assert_eq!(
            shims(&m, "child"),
            triples(&[
                ("s1", "parent1", "p"),
                ("s2", "gp2", "g"),
                ("s3", "child3", "c")
            ])
        );

        // fs depth: 0 for own, then one more per level up.
        assert_eq!(
            fs(&m, "child"),
            [
                rule("ro", "/m", "m", 3),
                rule("ro", "/gp", "g", 2),
                rule("ro", "/parent", "p", 1),
                rule("ro", "/child", "c", 0),
                rule("rw", "/child2", "c2", 0),
            ]
        );
        assert_eq!(
            fs(&m, "parent"),
            [
                rule("ro", "/m", "m", 2),
                rule("ro", "/gp", "g", 1),
                rule("ro", "/parent", "p", 0),
            ]
        );
    }

    #[test]
    fn contributed_profiles_merge_like_any_other() {
        let m = merged(&format!(
            "{}{}",
            prov(
                "vcs",
                "main",
                "network.mode = \"loopback\"\nfs.masked = [\"{workspace}/.git\"]\n\
                 [provider.sandbox.profiles.local]\nfs.rw = [\"{workspace}/.git\"]\nnetwork.mode = \"none\""
            ),
            prov("extra", "vcs.local", "fs.ro = [\"/etc/gitconfig\"]"),
        ));
        assert_eq!(eff(&m, "vcs.local").network.mode, NetworkMode::None);
        assert_eq!(
            fs(&m, "vcs.local"),
            [
                rule("masked", "{workspace}/.git", "vcs", 1),
                rule("rw", "{workspace}/.git", "vcs", 0),
                rule("ro", "/etc/gitconfig", "extra", 0),
            ]
        );
    }

    #[test]
    fn conflicting_home_within_a_profile() {
        let e = merge_err(&format!(
            "{}{}{}",
            prov("a", "main", "system.home = \"/home/a\""),
            prov("b", "main", "system.home = \"/home/a\""),
            prov("c", "main", "system.home = \"/home/c\""),
        ));
        assert_eq!(
            e.to_string(),
            r#"profile "main": conflicting system.home values "/home/a" (provider "a") and "/home/c" (provider "c")"#
        );
        assert_eq!(
            e,
            MergeError::HomeConflict {
                profile: ProfileRef::main(),
                first_provider: pn("a"),
                first: "/home/a".parse().unwrap(),
                second_provider: pn("c"),
                second: "/home/c".parse().unwrap(),
            }
        );
        // In a child profile; the inherited value is not part of the
        // conflict.
        let e = merge_err(&format!(
            "[profiles.child]\n{}{}{}",
            prov("a", "main", "system.home = \"/home/a\""),
            prov("b", "child", "system.home = \"/home/b\""),
            prov("c", "child", "system.home = \"/home/c\""),
        ));
        assert_eq!(
            e.to_string(),
            r#"profile "child": conflicting system.home values "/home/b" (provider "b") and "/home/c" (provider "c")"#
        );
    }

    #[test]
    fn conflicting_env_set_within_a_profile() {
        let e = merge_err(&format!(
            "{}{}",
            prov("a", "main", "env.set = { EDITOR = \"vi\", LANG = \"C\" }"),
            prov("b", "main", "env.set = { LANG = \"C.UTF-8\" }"),
        ));
        assert_eq!(
            e.to_string(),
            r#"profile "main": conflicting env.set values for "LANG": "C" (provider "a") and "C.UTF-8" (provider "b")"#
        );
        assert_eq!(
            e,
            MergeError::EnvSetConflict(Box::new(EnvSetConflict {
                profile: ProfileRef::main(),
                name: "LANG".parse().unwrap(),
                first_provider: pn("a"),
                first: "C".parse().unwrap(),
                second_provider: pn("b"),
                second: "C.UTF-8".parse().unwrap(),
            }))
        );
        // In a contributed profile.
        let e = merge_err(&format!(
            "{}{}",
            prov(
                "vcs",
                "main",
                "[provider.sandbox.profiles.local]\nenv.set = { X = \"1\" }"
            ),
            prov("extra", "vcs.local", "env.set = { X = \"2\" }"),
        ));
        assert_eq!(
            e.to_string(),
            r#"profile "vcs.local": conflicting env.set values for "X": "1" (provider "vcs") and "2" (provider "extra")"#
        );
    }

    #[test]
    fn duplicate_shim_within_a_profile() {
        let e = merge_err(&format!(
            "[profiles.child]\n{}{}{}",
            prov("a", "child", &shim("jj", "jj")),
            prov("b", "child", &shim("git", "git")),
            prov("c", "child", &shim("jj", "jj2")),
        ));
        assert_eq!(
            e.to_string(),
            r#"profile "child": shim "jj" is granted by both provider "a" and provider "c""#
        );
        assert_eq!(
            e,
            MergeError::DuplicateShim {
                profile: pr("child"),
                shim: "jj".parse().unwrap(),
                first_provider: pn("a"),
                second_provider: pn("c"),
            }
        );
        // Even identical specs collide.
        let e = merge_err(&format!(
            "{}{}",
            prov("a", "main", &shim("jj", "jj")),
            prov("b", "main", &shim("jj", "jj")),
        ));
        assert_eq!(
            e.to_string(),
            r#"profile "main": shim "jj" is granted by both provider "a" and provider "b""#
        );
    }

    // --- Layering a workspace `.stopit.toml` over the user-global config ---

    /// The merge of `global` layered under `project` with
    /// [`ConfigLayer::layer`](crate::config::ConfigLayer::layer).
    fn layered(global: &str, project: &str) -> Result<MergedProfiles, MergeError> {
        use crate::config::ConfigLayer;
        use crate::provider::from_layered_entry;

        let layered = ConfigLayer::layer(
            Some((
                ConfigLayer::from_toml_str(global).unwrap(),
                Path::new("/cfg"),
            )),
            Some((
                ConfigLayer::from_toml_str(project).unwrap(),
                Path::new("/w"),
            )),
        );
        let ctx = ProviderContext {
            workspace: PathBuf::from("/w"),
            workspace_mount: "/workspace".parse().unwrap(),
            home: PathBuf::from("/home/u"),
            session_dir: PathBuf::from("/run/s"),
            rw_grants: Vec::new(),
        };
        let outputs = layered
            .providers
            .iter()
            .map(|e| {
                let p = from_layered_entry(e).unwrap();
                (p.name().clone(), p.manifest(&ctx).unwrap())
            })
            .collect();
        merge_profiles(&build_profile_graph(&layered.config, outputs).unwrap())
    }

    #[test]
    fn the_workspace_layer_overrides_single_valued_global_keys() {
        let global = format!(
            "{}{}",
            prov(
                "g1",
                "main",
                &format!(
                    "system.home = \"/home/global\"\nenv.set = {{ EDITOR = \"vi\", LANG = \"C\" }}\n{}",
                    shim("jj", "jj-global")
                )
            ),
            prov("g2", "main", "env.path_prepend = [\"/g/bin\"]"),
        );
        let project = format!(
            "{}{}",
            prov(
                "p1",
                "main",
                &format!(
                    "system.home = \"/home/project\"\nenv.set = {{ LANG = \"C.UTF-8\" }}\n{}",
                    shim("jj", "jj-project")
                )
            ),
            prov("p2", "main", "env.path_prepend = [\"/p/bin\", \"/g/bin\"]"),
        );
        let m = layered(&global, &project).unwrap();
        assert_eq!(home(&m, "main"), Some("/home/project"));
        // `EDITOR` only in the global layer survives; `LANG` is the project's.
        assert_eq!(
            set(&m, "main"),
            [
                ("EDITOR".to_owned(), "vi".to_owned()),
                ("LANG".to_owned(), "C.UTF-8".to_owned()),
            ]
        );
        assert_eq!(shims(&m, "main"), triples(&[("jj", "jj-project", "p1")]));
        // Workspace entries come first in `PATH`, and duplicates collapse.
        assert_eq!(
            strs(&eff(&m, "main").env.path_prepend),
            ["/p/bin", "/g/bin"]
        );

        // The order of the global and project providers within the profile
        // does not matter: a lower layer never overrides a higher one.
        let m = layered(
            &prov("g", "main", "system.home = \"/home/global\""),
            &format!(
                "[profiles.child]\n{}",
                prov("p", "main", "system.home = \"/home/project\"")
            ),
        )
        .unwrap();
        assert_eq!(home(&m, "main"), Some("/home/project"));
        assert_eq!(home(&m, "child"), Some("/home/project"));
    }

    #[test]
    fn conflicts_within_one_layer_are_still_errors() {
        // Two global providers conflicting, with no project value.
        let e = layered(
            &format!(
                "{}{}",
                prov("a", "main", "system.home = \"/home/a\""),
                prov("b", "main", "system.home = \"/home/b\"")
            ),
            "",
        )
        .unwrap_err();
        assert!(matches!(e, MergeError::HomeConflict { .. }), "{e}");
        // Two project providers conflicting over a global value.
        let e = layered(
            &prov("g", "main", "env.set = { X = \"0\" }"),
            &format!(
                "{}{}",
                prov("a", "main", "env.set = { X = \"1\" }"),
                prov("b", "main", "env.set = { X = \"2\" }")
            ),
        )
        .unwrap_err();
        assert_eq!(
            e.to_string(),
            r#"profile "main": conflicting env.set values for "X": "1" (provider "a") and "2" (provider "b")"#
        );
        let e = layered(
            &prov("g", "main", &shim("jj", "jj")),
            &format!(
                "{}{}",
                prov("a", "main", &shim("jj", "jj")),
                prov("b", "main", &shim("jj", "jj"))
            ),
        )
        .unwrap_err();
        assert_eq!(
            e.to_string(),
            r#"profile "main": shim "jj" is granted by both provider "a" and provider "b""#
        );
    }
}
