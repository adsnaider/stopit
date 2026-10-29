//! The profile graph: every profile, its parent and its own grant
//! contributions (DESIGN.md §3.3, §3.5, §3.6).
//!
//! Profiles are `main` (implicit), every user-declared profile, and every
//! profile contributed by a provider, registered under its full name
//! `<provider>.<name>`. User-declared names never contain a dot and
//! contributed names always do, so the two can never collide; provider names
//! are unique, so contributed names cannot collide with each other either.
//!
//! Reference rule (§3.6): references written in the configuration (a user
//! profile's `inherit`, a `config` provider's `profile`) are full names.
//! Inside a manifest (a contributed profile's `inherit`, every shim
//! `profile`), a single-segment name first resolves to the same manifest's
//! contributed profile of that name, then globally (a user-declared profile,
//! or `main`); a multi-segment name always resolves globally. Shim profile
//! references are rewritten to their resolved full names, so later stages
//! never need to know which provider declared a shim.
//!
//! Grant contents are not merged or inspected here.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt;

use thiserror::Error;

use crate::config::{Config, Inherit, ProfileName, ProfileRef, ProviderName, ProviderOrigin};
use crate::manifest::{Grants, ShimName};
use crate::provider::ProviderOutput;

/// Grants one provider contributes directly to one profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contribution {
    /// The provider the grants come from.
    pub provider: ProviderName,
    /// Layer that declared the provider.
    pub origin: ProviderOrigin,
    /// The grants. Every shim profile reference is a resolved full name.
    pub grants: Grants,
}

/// One profile of the graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileNode {
    /// The resolved full name of the parent: `None` for `main` and for
    /// profiles with `inherit = "none"`.
    pub parent: Option<ProfileRef>,
    /// The profile's own contributions (not its parent's), in merge order.
    pub contributions: Vec<Contribution>,
}

/// Every profile of a session, with resolved references.
///
/// Every parent is itself a profile of the graph, there are no inheritance
/// cycles, and every shim profile reference names a profile of the graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileGraph {
    profiles: BTreeMap<ProfileRef, ProfileNode>,
    /// Every profile exactly once, parents before children.
    order: Vec<ProfileRef>,
}

impl ProfileGraph {
    /// The profile with the given full name.
    pub fn get(&self, profile: &ProfileRef) -> Option<&ProfileNode> {
        self.profiles.get(profile)
    }

    /// Every profile's full name, parents before children. Deterministic:
    /// it depends only on the profiles and their parents.
    pub fn order(&self) -> &[ProfileRef] {
        &self.order
    }

    /// Every profile, parents before children (see [`ProfileGraph::order`]).
    pub fn iter(&self) -> impl Iterator<Item = (&ProfileRef, &ProfileNode)> {
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

/// Where in a shim a profile reference appears.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShimField {
    /// The shim's `default`.
    Default,
    /// The rule at this (zero-based) index of `rules`.
    Rule(usize),
}

impl fmt::Display for ShimField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShimField::Default => f.write_str("default"),
            ShimField::Rule(i) => write!(f, "rule {}", i + 1),
        }
    }
}

/// Error produced while building the profile graph.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProfileError {
    /// Two provider outputs carry the same provider name, so their
    /// contributed profiles would collide.
    #[error("duplicate provider name {:?}: provider names must be unique", .provider.as_str())]
    DuplicateProvider {
        /// The repeated name.
        provider: ProviderName,
    },

    /// A user-declared profile inherits from a profile that does not exist.
    #[error(
        "profile {:?} inherits from unknown profile {:?}{}",
        .profile.as_str(),
        .target.as_str(),
        did_you_mean(.suggestions)
    )]
    UnknownInherit {
        /// The user-declared profile.
        profile: ProfileName,
        /// Its `inherit` value.
        target: ProfileRef,
        /// Contributed profiles the target may have meant (see
        /// [`suggestions`]); possibly empty.
        suggestions: Vec<ProfileRef>,
    },

    /// A contributed profile inherits from a profile that does not exist.
    #[error(
        "profile {:?} (contributed by provider {:?}) inherits from unknown profile {:?}",
        .profile.as_str(),
        .provider.as_str(),
        .target.as_str()
    )]
    UnknownContributedInherit {
        /// The contributing provider.
        provider: ProviderName,
        /// The contributed profile's full name.
        profile: ProfileRef,
        /// Its `inherit` value, as written.
        target: ProfileRef,
    },

    /// A provider applies its top-level grants to a profile that does not
    /// exist (the `profile` of a `config` provider).
    #[error(
        "provider {:?} applies its grants to unknown profile {:?}{}",
        .provider.as_str(),
        .target.as_str(),
        did_you_mean(.suggestions)
    )]
    UnknownTarget {
        /// The provider.
        provider: ProviderName,
        /// Its target profile.
        target: ProfileRef,
        /// Contributed profiles the target may have meant (see
        /// [`suggestions`]); possibly empty.
        suggestions: Vec<ProfileRef>,
    },

    /// A shim targets a profile that does not exist.
    #[error(
        "shim {:?} ({field}) from provider {:?}, granted to profile {:?}, targets unknown profile {:?}",
        .shim.as_str(),
        .provider.as_str(),
        .profile.as_str(),
        .target.as_str()
    )]
    UnknownShimProfile {
        /// The provider that declared the shim.
        provider: ProviderName,
        /// The profile the shim is granted to.
        profile: ProfileRef,
        /// The shim.
        shim: ShimName,
        /// Where in the shim the reference is.
        field: ShimField,
        /// The reference, as written.
        target: ProfileRef,
    },

    /// Profiles inherit from each other in a cycle.
    #[error("profile inheritance cycle: {}", format_cycle(.cycle))]
    Cycle {
        /// The profiles of the cycle, each inheriting from the next; the
        /// first is repeated at the end.
        cycle: Vec<ProfileRef>,
    },
}

fn format_cycle(cycle: &[ProfileRef]) -> String {
    let names: Vec<&str> = cycle.iter().map(ProfileRef::as_str).collect();
    names.join(" -> ")
}

/// ` (did you mean "a.x", "b.x"?)`, or nothing when there is no suggestion.
fn did_you_mean(suggestions: &[ProfileRef]) -> String {
    if suggestions.is_empty() {
        return String::new();
    }
    let quoted: Vec<String> = suggestions
        .iter()
        .map(|s| format!("{:?}", s.as_str()))
        .collect();
    format!(" (did you mean {}?)", quoted.join(", "))
}

/// For a single-segment reference written where full names are required,
/// the contributed profiles (in name order) whose part after the provider
/// prefix equals it: the user probably meant one of them. Empty for a
/// multi-segment reference.
fn suggestions(target: &ProfileRef, known: &BTreeSet<ProfileRef>) -> Vec<ProfileRef> {
    if target.as_str().contains('.') {
        return Vec::new();
    }
    known
        .iter()
        .filter(|k| {
            k.as_str()
                .split_once('.')
                .is_some_and(|(_, name)| name == target.as_str())
        })
        .cloned()
        .collect()
}

/// Resolves references written inside one provider's manifest.
struct ManifestScope<'a> {
    provider: &'a ProviderName,
    /// The manifest's own contributed profiles (plain names).
    own: &'a BTreeSet<ProfileName>,
    /// Every profile's full name.
    known: &'a BTreeSet<ProfileRef>,
}

impl ManifestScope<'_> {
    /// Applies the reference rule: a single-segment name that is one of the
    /// manifest's own profiles resolves to it; anything else resolves
    /// globally. (`main` never parses as a [`ProfileName`] and is never a
    /// contributed profile, so it always resolves globally.)
    fn resolve(&self, r: &ProfileRef) -> Option<ProfileRef> {
        if let Ok(name) = r.as_str().parse::<ProfileName>()
            && self.own.contains(&name)
        {
            return Some(ProfileRef::contributed(self.provider, &name));
        }
        self.known.contains(r).then(|| r.clone())
    }

    /// Rewrites every shim profile reference in `grants` (granted to
    /// `profile`) to its resolved full name.
    fn resolve_shims(&self, grants: &mut Grants, profile: &ProfileRef) -> Result<(), ProfileError> {
        for (shim, spec) in &mut grants.shims {
            let fields = std::iter::once((ShimField::Default, &mut spec.default.profile)).chain(
                spec.rules
                    .iter_mut()
                    .enumerate()
                    .map(|(i, rule)| (ShimField::Rule(i), &mut rule.profile)),
            );
            for (field, target) in fields {
                let Some(target) = target else { continue };
                *target = self
                    .resolve(target)
                    .ok_or_else(|| ProfileError::UnknownShimProfile {
                        provider: self.provider.clone(),
                        profile: profile.clone(),
                        shim: shim.clone(),
                        field,
                        target: target.clone(),
                    })?;
            }
        }
        Ok(())
    }
}

/// Builds the profile graph from the configuration and the providers'
/// outputs.
///
/// `outputs` are in merge order (base providers first, then user providers
/// in file order), each with its provider's effective name. Contributions
/// are recorded in that order; within one provider, its top-level grants
/// (applied to `output.profile`) come before its contributed profiles. Every
/// provider records a contribution for its target profile and for each
/// profile it contributes, even when the grants are empty.
pub fn build_profile_graph(
    config: &Config,
    outputs: Vec<(ProviderName, ProviderOutput)>,
) -> Result<ProfileGraph, ProfileError> {
    let empty = || ProfileNode {
        parent: None,
        contributions: Vec::new(),
    };

    // Every profile first, so that references may point forward: a provider
    // can target or reference a profile contributed by a later provider.
    let mut profiles = BTreeMap::new();
    profiles.insert(ProfileRef::main(), empty());
    for name in config.profiles.keys() {
        profiles.insert(name.clone().into(), empty());
    }
    let mut providers = HashSet::new();
    for (provider, output) in &outputs {
        if !providers.insert(provider) {
            return Err(ProfileError::DuplicateProvider {
                provider: provider.clone(),
            });
        }
        for name in output.manifest.profiles.keys() {
            let prev = profiles.insert(ProfileRef::contributed(provider, name), empty());
            // Contributed names contain a dot and user-declared names never
            // do, and provider names were just checked to be unique.
            assert!(prev.is_none(), "profile {provider}.{name} registered twice");
        }
    }
    let known: BTreeSet<ProfileRef> = profiles.keys().cloned().collect();

    // User-declared parents: full names.
    for (name, decl) in &config.profiles {
        let parent = match &decl.inherit {
            Inherit::None => None,
            Inherit::Profile(target) if known.contains(target) => Some(target.clone()),
            Inherit::Profile(target) => {
                return Err(ProfileError::UnknownInherit {
                    profile: name.clone(),
                    target: target.clone(),
                    suggestions: suggestions(target, &known),
                });
            }
        };
        profiles
            .get_mut(&ProfileRef::from(name.clone()))
            .expect("registered above")
            .parent = parent;
    }

    // Provider outputs, in merge order.
    for (provider, output) in outputs {
        let ProviderOutput {
            profile,
            manifest,
            origin,
        } = output;
        if !known.contains(&profile) {
            return Err(ProfileError::UnknownTarget {
                suggestions: suggestions(&profile, &known),
                provider,
                target: profile,
            });
        }
        let own: BTreeSet<ProfileName> = manifest.profiles.keys().cloned().collect();
        let scope = ManifestScope {
            provider: &provider,
            own: &own,
            known: &known,
        };

        let mut grants = manifest.grants;
        scope.resolve_shims(&mut grants, &profile)?;
        let node = profiles.get_mut(&profile).expect("checked above");
        node.contributions.push(Contribution {
            provider: provider.clone(),
            origin,
            grants,
        });

        for (name, contributed) in manifest.profiles {
            let full = ProfileRef::contributed(&provider, &name);
            let parent = match contributed.inherit {
                Inherit::None => None,
                Inherit::Profile(target) => Some(scope.resolve(&target).ok_or_else(|| {
                    ProfileError::UnknownContributedInherit {
                        provider: provider.clone(),
                        profile: full.clone(),
                        target,
                    }
                })?),
            };
            let mut grants = contributed.grants;
            scope.resolve_shims(&mut grants, &full)?;
            let node = profiles.get_mut(&full).expect("registered above");
            node.parent = parent;
            node.contributions.push(Contribution {
                provider: provider.clone(),
                origin,
                grants,
            });
        }
    }

    let order = topological_order(&profiles)?;
    Ok(ProfileGraph { profiles, order })
}

/// Orders the profiles parents first, or reports a cycle.
///
/// Each profile has at most one parent, so the graph is a set of chains:
/// starting from each profile in name order, walk up the parents until a
/// profile that is already placed (or the root), then place the walked
/// chain top-down. Meeting a profile of the current walk again is a cycle.
fn topological_order(
    profiles: &BTreeMap<ProfileRef, ProfileNode>,
) -> Result<Vec<ProfileRef>, ProfileError> {
    let mut order = Vec::with_capacity(profiles.len());
    let mut placed = BTreeSet::new();
    for start in profiles.keys() {
        let mut path: Vec<&ProfileRef> = Vec::new();
        let mut cur = Some(start);
        while let Some(p) = cur {
            if placed.contains(p) {
                break;
            }
            if let Some(i) = path.iter().position(|q| *q == p) {
                let mut cycle: Vec<ProfileRef> = path[i..].iter().map(|q| (*q).clone()).collect();
                cycle.push(p.clone());
                return Err(ProfileError::Cycle { cycle });
            }
            path.push(p);
            cur = profiles[p].parent.as_ref();
        }
        for p in path.into_iter().rev() {
            placed.insert(p);
            order.push(p.clone());
        }
    }
    Ok(order)
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::manifest::Manifest;
    use crate::provider::{ProviderContext, from_entry};

    fn pr(s: &str) -> ProfileRef {
        s.parse().unwrap()
    }

    fn pn(s: &str) -> ProviderName {
        s.parse().unwrap()
    }

    fn config(src: &str) -> Config {
        Config::from_toml_str(src).unwrap()
    }

    fn manifest(src: &str) -> Manifest {
        toml::from_str(src).unwrap()
    }

    /// A hand-built output applying `src`'s top-level grants to `profile`.
    fn out(provider: &str, profile: &str, src: &str) -> (ProviderName, ProviderOutput) {
        (
            pn(provider),
            ProviderOutput {
                profile: pr(profile),
                manifest: manifest(src),
                origin: ProviderOrigin::Workspace,
            },
        )
    }

    /// The outputs of the configuration's (`config`) providers, in order.
    fn config_outputs(cfg: &Config) -> Vec<(ProviderName, ProviderOutput)> {
        let ctx = ProviderContext {
            workspace: PathBuf::from("/w"),
            workspace_mount: "/workspace".parse().unwrap(),
            home: PathBuf::from("/home/u"),
            session_dir: PathBuf::from("/run/s"),
            rw_grants: Vec::new(),
        };
        cfg.providers
            .iter()
            .map(|e| {
                let p = from_entry(e, Path::new("/cfg")).unwrap();
                (p.name().clone(), p.manifest(&ctx).unwrap())
            })
            .collect()
    }

    /// Builds the graph of `cfg_src` with its own providers' outputs.
    fn build_config(cfg_src: &str) -> Result<ProfileGraph, ProfileError> {
        let cfg = config(cfg_src);
        let outputs = config_outputs(&cfg);
        build_profile_graph(&cfg, outputs)
    }

    fn build(cfg_src: &str, outputs: Vec<(ProviderName, ProviderOutput)>) -> ProfileGraph {
        let g = build_profile_graph(&config(cfg_src), outputs).unwrap();
        check_invariants(&g);
        g
    }

    fn err(cfg_src: &str, outputs: Vec<(ProviderName, ProviderOutput)>) -> String {
        match build_profile_graph(&config(cfg_src), outputs) {
            Ok(g) => panic!("expected an error, got {g:?}"),
            Err(e) => e.to_string(),
        }
    }

    /// The order lists every profile once, parents first, and every parent
    /// and shim target exists.
    fn check_invariants(g: &ProfileGraph) {
        assert_eq!(g.order().len(), g.len());
        let mut seen = BTreeSet::new();
        for (p, node) in g.iter() {
            if let Some(parent) = &node.parent {
                assert!(
                    seen.contains(parent),
                    "{p} placed before its parent {parent}"
                );
            }
            assert!(seen.insert(p.clone()), "{p} listed twice");
            for c in &node.contributions {
                for spec in c.grants.shims.values() {
                    let targets = std::iter::once(&spec.default.profile)
                        .chain(spec.rules.iter().map(|r| &r.profile));
                    for t in targets.flatten() {
                        assert!(g.get(t).is_some(), "shim target {t} missing");
                    }
                }
            }
        }
        assert!(g.get(&ProfileRef::main()).unwrap().parent.is_none());
        assert!(!g.is_empty());
    }

    fn node<'a>(g: &'a ProfileGraph, p: &str) -> &'a ProfileNode {
        g.get(&pr(p)).unwrap_or_else(|| panic!("no profile {p}"))
    }

    fn parent<'a>(g: &'a ProfileGraph, p: &str) -> Option<&'a str> {
        node(g, p).parent.as_ref().map(ProfileRef::as_str)
    }

    fn order(g: &ProfileGraph) -> Vec<&str> {
        g.order().iter().map(ProfileRef::as_str).collect()
    }

    fn providers<'a>(g: &'a ProfileGraph, p: &str) -> Vec<&'a str> {
        node(g, p)
            .contributions
            .iter()
            .map(|c| c.provider.as_str())
            .collect()
    }

    /// The targets of shim `shim` (default, then each rule) in the
    /// contribution of `provider` to `profile`.
    fn shim_targets<'a>(
        g: &'a ProfileGraph,
        profile: &str,
        provider: &str,
        shim: &str,
    ) -> Vec<Option<&'a str>> {
        let c = node(g, profile)
            .contributions
            .iter()
            .find(|c| c.provider.as_str() == provider)
            .unwrap_or_else(|| panic!("no contribution of {provider} to {profile}"));
        let spec = &c.grants.shims[&shim.parse::<ShimName>().unwrap()];
        std::iter::once(&spec.default.profile)
            .chain(spec.rules.iter().map(|r| &r.profile))
            .map(|t| t.as_ref().map(ProfileRef::as_str))
            .collect()
    }

    /// A vcs-like manifest written with plain references.
    const VCS_PLAIN: &str = r#"
        [shims.jj]
        binary = "jj"
        default = { decision = "ask", profile = "local" }
        rules = [
          { subcommand = ["status"], decision = "allow", profile = "ro" },
          { subcommand = ["git push"], decision = "ask", profile = "remote" },
          { subcommand = ["rm"], decision = "deny" },
          { subcommand = ["x"], decision = "allow", profile = "main" },
        ]

        [profiles.ro]
        fs.ro = ["{workspace}/.git"]

        [profiles.local]
        fs.rw = ["{workspace}/.git"]
        [profiles.local.shims.jj-remote]
        binary = "jj"
        default = { decision = "ask", profile = "remote" }

        [profiles.remote]
        inherit = "local"
    "#;

    /// The same manifest, written with full names.
    const VCS_FULL: &str = r#"
        [shims.jj]
        binary = "jj"
        default = { decision = "ask", profile = "vcs.local" }
        rules = [
          { subcommand = ["status"], decision = "allow", profile = "vcs.ro" },
          { subcommand = ["git push"], decision = "ask", profile = "vcs.remote" },
          { subcommand = ["rm"], decision = "deny" },
          { subcommand = ["x"], decision = "allow", profile = "main" },
        ]

        [profiles.ro]
        fs.ro = ["{workspace}/.git"]

        [profiles.local]
        fs.rw = ["{workspace}/.git"]
        [profiles.local.shims.jj-remote]
        binary = "jj"
        default = { decision = "ask", profile = "vcs.remote" }

        [profiles.remote]
        inherit = "vcs.local"
    "#;

    #[test]
    fn only_main() {
        let g = build("", vec![]);
        assert_eq!(order(&g), ["main"]);
        assert_eq!(g.len(), 1);
        assert_eq!(
            node(&g, "main"),
            &ProfileNode {
                parent: None,
                contributions: vec![],
            }
        );
        assert!(g.get(&pr("harness")).is_none());
    }

    #[test]
    fn user_profiles_parents_and_order() {
        let g = build(
            r#"
            [profiles.a]
            [profiles.b]
            inherit = "a"
            [profiles.bare]
            inherit = "none"
            [profiles.child]
            inherit = "zeta"
            [profiles.zeta]
            inherit = "main"
            "#,
            vec![],
        );
        assert_eq!(parent(&g, "main"), None);
        assert_eq!(parent(&g, "a"), Some("main"));
        assert_eq!(parent(&g, "b"), Some("a"));
        assert_eq!(parent(&g, "bare"), None);
        assert_eq!(parent(&g, "child"), Some("zeta"));
        assert_eq!(parent(&g, "zeta"), Some("main"));
        // `child` sorts before its parent `zeta` but is placed after it.
        assert_eq!(order(&g), ["main", "a", "b", "bare", "zeta", "child"]);
        // No provider, no contributions.
        assert!(g.iter().all(|(_, n)| n.contributions.is_empty()));
    }

    #[test]
    fn contributed_profiles_resolve_plain_references() {
        let g = build("", vec![out("vcs", "main", VCS_PLAIN)]);
        assert_eq!(order(&g), ["main", "vcs.local", "vcs.remote", "vcs.ro"]);
        assert_eq!(parent(&g, "vcs.ro"), Some("main"));
        assert_eq!(parent(&g, "vcs.local"), Some("main"));
        assert_eq!(parent(&g, "vcs.remote"), Some("vcs.local"));
        // Top-level shims are rewritten to full names; `deny` stays empty and
        // `main` stays `main`.
        assert_eq!(
            shim_targets(&g, "main", "vcs", "jj"),
            [
                Some("vcs.local"),
                Some("vcs.ro"),
                Some("vcs.remote"),
                None,
                Some("main")
            ]
        );
        // So are shims inside contributed profiles.
        assert_eq!(
            shim_targets(&g, "vcs.local", "vcs", "jj-remote"),
            [Some("vcs.remote")]
        );
        // Each profile gets exactly the provider's grants meant for it.
        assert_eq!(providers(&g, "main"), ["vcs"]);
        let m = manifest(VCS_PLAIN);
        let ro = &node(&g, "vcs.ro").contributions[0].grants;
        assert_eq!(ro, &m.profiles[&"ro".parse().unwrap()].grants);
        let remote = &node(&g, "vcs.remote").contributions;
        assert_eq!(remote.len(), 1);
        assert_eq!(remote[0].grants, Grants::default());
    }

    #[test]
    fn full_names_inside_a_manifest_resolve_the_same() {
        let plain = build("", vec![out("vcs", "main", VCS_PLAIN)]);
        let full = build("", vec![out("vcs", "main", VCS_FULL)]);
        assert_eq!(plain, full);
    }

    #[test]
    fn plain_name_falls_back_to_user_profile() {
        let g = build(
            "[profiles.harness]",
            vec![out(
                "vcs",
                "main",
                r#"
                shims.h = { binary = "h", default = { decision = "allow", profile = "harness" } }
                [profiles.local]
                inherit = "harness"
                shims.l = { binary = "l", default = { decision = "allow", profile = "harness" } }
                "#,
            )],
        );
        assert_eq!(parent(&g, "vcs.local"), Some("harness"));
        assert_eq!(shim_targets(&g, "main", "vcs", "h"), [Some("harness")]);
        assert_eq!(shim_targets(&g, "vcs.local", "vcs", "l"), [Some("harness")]);
        assert_eq!(order(&g), ["main", "harness", "vcs.local"]);
    }

    #[test]
    fn own_contributed_profile_shadows_user_profile() {
        let g = build(
            "[profiles.local]\ninherit = \"none\"",
            vec![out(
                "vcs",
                "main",
                r#"
                shims.a = { binary = "a", default = { decision = "allow", profile = "local" } }
                [profiles.local]
                [profiles.child]
                inherit = "local"
                "#,
            )],
        );
        assert_eq!(parent(&g, "vcs.child"), Some("vcs.local"));
        assert_eq!(shim_targets(&g, "main", "vcs", "a"), [Some("vcs.local")]);
        // The user profile still exists, separately.
        assert_eq!(parent(&g, "local"), None);
        assert_eq!(parent(&g, "vcs.local"), Some("main"));
    }

    #[test]
    fn renamed_provider_resolves_its_own_plain_references() {
        let g = build("", vec![out("myvcs", "main", VCS_PLAIN)]);
        assert_eq!(
            order(&g),
            ["main", "myvcs.local", "myvcs.remote", "myvcs.ro"]
        );
        assert_eq!(parent(&g, "myvcs.remote"), Some("myvcs.local"));
        assert_eq!(
            shim_targets(&g, "main", "myvcs", "jj"),
            [
                Some("myvcs.local"),
                Some("myvcs.ro"),
                Some("myvcs.remote"),
                None,
                Some("main")
            ]
        );
        assert!(g.get(&pr("vcs.local")).is_none());
    }

    #[test]
    fn shims_may_target_profiles_of_later_providers() {
        let g = build(
            "",
            vec![
                out(
                    "early",
                    "main",
                    r#"
                    [shims.s]
                    binary = "s"
                    default = { decision = "ask", profile = "later.x" }
                    rules = [{ subcommand = ["a"], decision = "allow", profile = "later.x" }]
                    "#,
                ),
                out("later", "main", "[profiles.x]"),
            ],
        );
        assert_eq!(
            shim_targets(&g, "main", "early", "s"),
            [Some("later.x"), Some("later.x")]
        );
        assert_eq!(providers(&g, "main"), ["early", "later"]);
    }

    #[test]
    fn other_providers_profiles_need_full_names() {
        // `other` references `vcs.ro` by full name: fine.
        let g = build(
            "",
            vec![
                out("vcs", "main", VCS_PLAIN),
                out(
                    "other",
                    "main",
                    r#"shims.s = { binary = "s", default = { decision = "allow", profile = "vcs.ro" } }"#,
                ),
            ],
        );
        assert_eq!(shim_targets(&g, "main", "other", "s"), [Some("vcs.ro")]);
        // A plain `ro` from `other` does not see `vcs.ro`.
        let msg = err(
            "",
            vec![
                out("vcs", "main", VCS_PLAIN),
                out(
                    "other",
                    "main",
                    r#"shims.s = { binary = "s", default = { decision = "allow", profile = "ro" } }"#,
                ),
            ],
        );
        assert_eq!(
            msg,
            r#"shim "s" (default) from provider "other", granted to profile "main", targets unknown profile "ro""#
        );
    }

    #[test]
    fn config_provider_routes_grants_to_its_profile() {
        let cfg = config(
            r#"
            [profiles.harness]

            [[provider]]
            type = "config"
            name = "creds"
            profile = "harness"
            [provider.sandbox]
            env.pass = ["API_KEY"]
            shims.s = { binary = "s", default = { decision = "allow", profile = "harness" } }

            [[provider]]
            type = "config"
            name = "vcs-extra"
            profile = "vcs.local"
            [provider.sandbox]
            fs.ro = ["/etc/gitconfig"]
            "#,
        );
        let mut outputs = config_outputs(&cfg);
        // The contributing provider comes after the one targeting its
        // profile: forward references work.
        outputs.push(out("vcs", "main", VCS_PLAIN));
        let g = build_profile_graph(&cfg, outputs).unwrap();
        check_invariants(&g);
        assert_eq!(providers(&g, "harness"), ["creds"]);
        assert_eq!(
            node(&g, "harness").contributions[0].grants.env.pass.len(),
            1
        );
        assert_eq!(shim_targets(&g, "harness", "creds", "s"), [Some("harness")]);
        assert_eq!(providers(&g, "vcs.local"), ["vcs-extra", "vcs"]);
        let extra = &node(&g, "vcs.local").contributions[0].grants;
        assert_eq!(extra.fs.ro[0].as_str(), "/etc/gitconfig");
        // `main` gets only the providers that target it.
        assert_eq!(providers(&g, "main"), ["vcs"]);
    }

    #[test]
    fn contributions_keep_merge_order_and_provider_tags() {
        let cfg = config(
            r#"
            [profiles.harness]

            [[provider]]
            type = "config"
            name = "one"
            [provider.sandbox]
            fs.ro = ["/one"]

            [[provider]]
            type = "config"
            name = "two"
            profile = "harness"
            [provider.sandbox]
            fs.ro = ["/two"]

            [[provider]]
            type = "config"
            name = "three"
            [provider.sandbox]
            fs.ro = ["/three"]
            [provider.sandbox.profiles.p]
            fs.ro = ["/three-p"]

            [[provider]]
            type = "config"
            name = "four"
            profile = "three.p"
            [provider.sandbox]
            fs.ro = ["/four"]
            "#,
        );
        let mut outputs = vec![out("base", "main", "fs.ro = [\"/base\"]")];
        outputs.extend(config_outputs(&cfg));
        let g = build_profile_graph(&cfg, outputs).unwrap();
        check_invariants(&g);
        let ro = |p: &str| -> Vec<(&str, String)> {
            node(&g, p)
                .contributions
                .iter()
                .map(|c| (c.provider.as_str(), c.grants.fs.ro[0].to_string()))
                .collect()
        };
        assert_eq!(
            ro("main"),
            [
                ("base", "/base".to_owned()),
                ("one", "/one".to_owned()),
                ("three", "/three".to_owned()),
            ]
        );
        assert_eq!(ro("harness"), [("two", "/two".to_owned())]);
        assert_eq!(
            ro("three.p"),
            [
                ("three", "/three-p".to_owned()),
                ("four", "/four".to_owned()),
            ]
        );
    }

    #[test]
    fn empty_top_level_grants_are_still_recorded() {
        let g = build(
            "",
            vec![out("a", "main", ""), out("b", "main", "[profiles.p]")],
        );
        assert_eq!(providers(&g, "main"), ["a", "b"]);
        assert_eq!(providers(&g, "b.p"), ["b"]);
    }

    #[test]
    fn inherit_none_in_a_contributed_profile() {
        let g = build(
            "",
            vec![out("vcs", "main", "[profiles.bare]\ninherit = \"none\"")],
        );
        assert_eq!(parent(&g, "vcs.bare"), None);
    }

    #[test]
    fn user_profile_may_inherit_a_contributed_profile() {
        let g = build(
            "[profiles.agent]\ninherit = \"vcs.remote\"",
            vec![out("vcs", "main", VCS_PLAIN)],
        );
        assert_eq!(parent(&g, "agent"), Some("vcs.remote"));
        assert_eq!(
            order(&g),
            ["main", "vcs.local", "vcs.remote", "agent", "vcs.ro"]
        );
    }

    #[test]
    fn unknown_user_inherit() {
        for (target, outputs, hint) in [
            ("nope", vec![], ""),
            // No contributed profile is named `nope`: no suggestion.
            ("nope", vec![out("vcs", "main", VCS_PLAIN)], ""),
            // A multi-segment name never gets a suggestion.
            ("vcs.nope", vec![out("vcs", "main", VCS_PLAIN)], ""),
            ("x.local", vec![out("vcs", "main", VCS_PLAIN)], ""),
            // A plain name in the configuration is a full name: it does not
            // find a contributed profile, but suggests it.
            (
                "local",
                vec![out("vcs", "main", VCS_PLAIN)],
                r#" (did you mean "vcs.local"?)"#,
            ),
            (
                "local",
                vec![
                    out("vcs", "main", VCS_PLAIN),
                    out("alt", "main", "[profiles.local]\n[profiles.other]"),
                ],
                r#" (did you mean "alt.local", "vcs.local"?)"#,
            ),
        ] {
            let msg = err(&format!("[profiles.a]\ninherit = \"{target}\""), outputs);
            assert_eq!(
                msg,
                format!(r#"profile "a" inherits from unknown profile "{target}"{hint}"#)
            );
        }
        let e = build_profile_graph(
            &config("[profiles.a]\ninherit = \"ro\""),
            vec![out("vcs", "main", VCS_PLAIN)],
        )
        .unwrap_err();
        assert_eq!(
            e,
            ProfileError::UnknownInherit {
                profile: "a".parse().unwrap(),
                target: pr("ro"),
                suggestions: vec![pr("vcs.ro")],
            }
        );
    }

    fn other_and_vcs(vcs_src: &str) -> Vec<(ProviderName, ProviderOutput)> {
        vec![
            out("other", "main", "[profiles.local]"),
            out("vcs", "main", vcs_src),
        ]
    }

    #[test]
    fn contributed_profile_may_inherit_another_providers_profile() {
        let g = build(
            "",
            other_and_vcs("[profiles.remote]\ninherit = \"other.local\""),
        );
        assert_eq!(parent(&g, "vcs.remote"), Some("other.local"));
    }

    #[test]
    fn unknown_contributed_inherit() {
        // `local` is only contributed by `other`, so the plain name does not
        // find it from `vcs`.
        for target in ["nope", "vcs.nope", "local", "main.x"] {
            let msg = err(
                "",
                other_and_vcs(&format!("[profiles.remote]\ninherit = \"{target}\"")),
            );
            assert_eq!(
                msg,
                format!(
                    r#"profile "vcs.remote" (contributed by provider "vcs") inherits from unknown profile "{target}""#
                )
            );
        }
    }

    #[test]
    fn unknown_config_provider_target() {
        for (target, hint) in [
            ("harness", ""),
            ("vcs.nope", ""),
            ("local", r#" (did you mean "vcs.local"?)"#),
        ] {
            let cfg = config(&format!(
                "[[provider]]\ntype = \"config\"\nname = \"creds\"\nprofile = \"{target}\""
            ));
            let mut outputs = vec![out("vcs", "main", VCS_PLAIN)];
            outputs.extend(config_outputs(&cfg));
            let msg = build_profile_graph(&cfg, outputs).unwrap_err().to_string();
            assert_eq!(
                msg,
                format!(
                    r#"provider "creds" applies its grants to unknown profile "{target}"{hint}"#
                )
            );
        }
        // Through `from_entry` alone, too.
        let e = build_config("[[provider]]\ntype = \"config\"\nprofile = \"harness\"").unwrap_err();
        assert_eq!(
            e,
            ProfileError::UnknownTarget {
                provider: pn("config"),
                target: pr("harness"),
                suggestions: vec![],
            }
        );
    }

    #[test]
    fn unknown_shim_targets() {
        // In the default, in a rule (numbered from 1), and in a contributed
        // profile.
        let cases = [
            (
                r#"shims.s = { binary = "s", default = { decision = "allow", profile = "nope" } }"#,
                r#"shim "s" (default) from provider "vcs", granted to profile "main", targets unknown profile "nope""#,
            ),
            (
                r#"
                [shims.s]
                binary = "s"
                default = { decision = "deny" }
                rules = [
                  { subcommand = ["a"], decision = "deny" },
                  { subcommand = ["b"], decision = "ask", profile = "vcs.nope" },
                ]
                "#,
                r#"shim "s" (rule 2) from provider "vcs", granted to profile "main", targets unknown profile "vcs.nope""#,
            ),
            (
                r#"
                [profiles.p]
                shims.s = { binary = "s", default = { decision = "ask", profile = "q" } }
                "#,
                r#"shim "s" (default) from provider "vcs", granted to profile "vcs.p", targets unknown profile "q""#,
            ),
        ];
        for (src, want) in cases {
            assert_eq!(err("", vec![out("vcs", "main", src)]), want);
        }
        // The profile a shim is granted to is the provider's target.
        let msg = err(
            "[profiles.harness]",
            vec![out(
                "creds",
                "harness",
                r#"shims.s = { binary = "s", default = { decision = "allow", profile = "x.y" } }"#,
            )],
        );
        assert_eq!(
            msg,
            r#"shim "s" (default) from provider "creds", granted to profile "harness", targets unknown profile "x.y""#
        );
    }

    #[test]
    fn cycles_among_user_profiles() {
        let msg = err(
            r#"
            [profiles.a]
            inherit = "b"
            [profiles.b]
            inherit = "c"
            [profiles.c]
            inherit = "a"
            "#,
            vec![],
        );
        assert_eq!(msg, "profile inheritance cycle: a -> b -> c -> a");

        let e = build_profile_graph(&config("[profiles.a]\ninherit = \"a\""), vec![]).unwrap_err();
        assert_eq!(e.to_string(), "profile inheritance cycle: a -> a");
        assert_eq!(
            e,
            ProfileError::Cycle {
                cycle: vec![pr("a"), pr("a")],
            }
        );

        // A profile leading into a cycle is not part of it.
        let msg = err(
            r#"
            [profiles.aa]
            inherit = "b"
            [profiles.b]
            inherit = "c"
            [profiles.c]
            inherit = "b"
            "#,
            vec![],
        );
        assert_eq!(msg, "profile inheritance cycle: b -> c -> b");
    }

    #[test]
    fn cycles_through_contributed_profiles() {
        let msg = err(
            "[profiles.a]\ninherit = \"vcs.x\"",
            vec![out("vcs", "main", "[profiles.x]\ninherit = \"a\"")],
        );
        assert_eq!(msg, "profile inheritance cycle: a -> vcs.x -> a");

        let msg = err(
            "",
            vec![out(
                "vcs",
                "main",
                "[profiles.p]\ninherit = \"q\"\n[profiles.q]\ninherit = \"p\"",
            )],
        );
        assert_eq!(msg, "profile inheritance cycle: vcs.p -> vcs.q -> vcs.p");

        let msg = err(
            "",
            vec![out("vcs", "main", "[profiles.p]\ninherit = \"vcs.p\"")],
        );
        assert_eq!(msg, "profile inheritance cycle: vcs.p -> vcs.p");
    }

    #[test]
    fn duplicate_provider_names_in_outputs() {
        let e = build_profile_graph(
            &config(""),
            vec![
                out("vcs", "main", ""),
                out("x", "main", ""),
                out("vcs", "main", "[profiles.p]"),
            ],
        )
        .unwrap_err();
        assert_eq!(
            e.to_string(),
            r#"duplicate provider name "vcs": provider names must be unique"#
        );
    }

    #[test]
    fn shim_field_display() {
        assert_eq!(ShimField::Default.to_string(), "default");
        assert_eq!(ShimField::Rule(0).to_string(), "rule 1");
    }
}
