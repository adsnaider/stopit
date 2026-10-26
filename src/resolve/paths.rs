//! Path precedence: turning a profile's filesystem rules into a mount plan
//! (DESIGN.md §3.4, §3.5).
//!
//! Every rule is expanded and resolved against the host filesystem into
//! candidate mounts at concrete sandbox paths. Where several candidates land
//! on the same sandbox path, one wins, decided in order by:
//!
//! 1. an exact path beats a glob-derived one;
//! 2. a profile's own rule beats an inherited one (lower depth wins);
//! 3. the strictest mode wins (`masked` > `protected` > `ro` > `ephemeral`
//!    > `rw`).
//!
//! "A deeper path beats a shallower one" needs no comparison: different
//! sandbox paths are separate mounts, and the plan is ordered so that
//! children are mounted after, and therefore on top of, their parents.
//!
//! Every anchor is resolved alike (see [`resolve`]): symlinks on the way to
//! a rule's host path are followed, and a matched path is kept as written.
//! Whether a link may have been planted by a sandbox depends on the
//! untrusted roots of the whole session (DESIGN.md §3.4, Symlinks), so the
//! spec compiler checks host sources and mount destinations for such links
//! once every profile is planned (`crate::spec`; DESIGN.md §6.2, "Untrusted
//! links"), and skips links matched by a glob there. To that end each mount
//! records whether its winning rule is a glob that matched a link
//! ([`PlannedMount::glob_link`]). The one root known while planning, the
//! host workspace, is checked here for a glob's walk root, so that a planted
//! link there is refused before it is walked.
//!
//! Likewise, a restrictive rule that cannot be resolved because a path
//! cannot be inspected or a directory cannot be read (anything but a
//! missing path) is an error rather than skipped: the sandbox could
//! `chmod 000` a directory it owns to switch a mask off at the next start.
//!
//! Redundant nested mounts (a child with the same mode as its parent and the
//! host content the parent already shows) are kept; pruning them is a
//! possible optimisation.

use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;

use super::merge::{FsRule, FsRuleKind};
use crate::config::ProviderName;
use crate::expand::{
    EntryKind, ExpandError, ExpandedPattern, ExpansionContext, ResolveWarning, ResolvedPath,
    expand_bind, expand_pattern, resolve,
};
use crate::manifest::PathPattern;
use crate::policy::PathMode;
use crate::spec::first_link_inside;

/// What a planned mount shows at its sandbox path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountSource {
    /// An existing host entry.
    Host {
        /// The host path, as written in the rule (with globs expanded).
        path: PathBuf,
        /// The kind of entry at `path`; for `masked` it decides whether an
        /// empty file or an empty directory is shown, and for a masked
        /// symlink it is the kind of the link's target, except that a
        /// masked link matched by a glob whose target cannot be inspected
        /// keeps [`EntryKind::Symlink`] (see [`PlannedMount::glob_link`]).
        kind: EntryKind,
    },
    /// A fresh, empty, session-scoped directory (`fs.ephemeral`), with no
    /// host source.
    Ephemeral,
}

impl fmt::Display for MountSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MountSource::Host { path, .. } => write!(f, "{path:?}"),
            MountSource::Ephemeral => f.write_str("an ephemeral directory"),
        }
    }
}

/// One mount of the plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedMount {
    /// Where the mount appears in the sandbox.
    pub sandbox: PathBuf,
    /// What is mounted there.
    pub source: MountSource,
    /// How it is presented.
    pub mode: PathMode,
    /// The provider whose rule won at this path.
    pub provider: ProviderName,
    /// Whether the winning rule is a glob that matched a symlink here (the
    /// host source is the link itself; for `masked`, `source`'s kind is its
    /// target's, or [`EntryKind::Symlink`] if the target cannot be
    /// inspected). The spec compiler skips such a mount when the link lies
    /// inside an untrusted root: the walk never follows links and reaches
    /// the real files under their own names (DESIGN.md §3.4, Symlinks). A
    /// masked one it keeps must have had an inspectable target.
    pub glob_link: bool,
}

/// The outcome of [`plan_mounts`].
#[derive(Debug, Default)]
pub struct MountPlan {
    /// One mount per sandbox path, ordered by the number of components of
    /// the sandbox path and then lexicographically, so that every mount
    /// comes after the mounts of its ancestors.
    pub mounts: Vec<PlannedMount>,
    /// Non-fatal problems found resolving the rules, in rule order.
    pub warnings: Vec<PlanWarning>,
}

/// A non-fatal problem with one rule; the rule's affected paths are skipped.
#[derive(Debug, Error)]
#[error("provider {:?}, rule {:?}: {kind}", .provider.as_str(), .pattern)]
pub struct PlanWarning {
    /// The provider that granted the rule.
    pub provider: ProviderName,
    /// The rule's pattern as written; for a bind, its host path.
    pub pattern: String,
    /// What went wrong.
    pub kind: PlanWarningKind,
}

/// What a [`PlanWarning`] is about.
#[derive(Debug, Error)]
pub enum PlanWarningKind {
    /// Resolving the rule against the host filesystem found a problem: a
    /// missing path, or for an `rw` rule or a bind's host side, one that
    /// cannot be inspected.
    #[error(transparent)]
    Resolve(#[from] ResolveWarning),
    /// A `masked` rule matched a symlink whose target is missing (a
    /// dangling link), so whether to show an empty file or an empty
    /// directory is unknown; there is no content to hide either.
    #[error("cannot inspect the target of the symlink {path:?}: {error}")]
    SymlinkTarget {
        /// The symlink's host path.
        path: PathBuf,
        /// The error inspecting its target.
        #[source]
        error: io::Error,
    },
    /// An `rw` glob's walk root runs through a symlink inside the host
    /// workspace, which a sandbox may have planted (see
    /// [`PathPlanError::WalkRootLink`]); the rule is skipped, since dropping
    /// a grant only removes access.
    #[error(
        "the glob's walk root {root:?} runs through the symlink {link:?} inside the host \
         workspace {workspace:?}; a sandbox can write there, so links inside it are never \
         followed, and the rw rule is skipped"
    )]
    WalkRootLink {
        /// The walk root, as written.
        root: PathBuf,
        /// The first symlink inside the workspace on the way to it, named
        /// below its canonical parent directory.
        link: PathBuf,
        /// The host workspace.
        workspace: PathBuf,
    },
}

/// Error planning the mounts of a profile.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PathPlanError {
    /// Two candidates with equal precedence map different sources to one
    /// sandbox path. Boxed to keep `PathPlanError` small.
    #[error(transparent)]
    Conflict(Box<MountConflict>),
    /// Resolving a restrictive rule failed on a path that exists but cannot
    /// be inspected, or a directory that cannot be read during a glob walk
    /// (or, for a literal `masked` symlink, its target cannot be
    /// inspected). Skipping it would let the sandbox switch the rule off by
    /// making a directory it owns unreadable.
    #[error(
        "provider {:?}, rule {:?}: cannot inspect {path:?} ({kind}), and a {mode} rule is never \
         skipped",
        .provider.as_str(),
        .pattern
    )]
    Inaccessible {
        /// The provider that granted the rule.
        provider: ProviderName,
        /// The rule's pattern as written.
        pattern: String,
        /// The rule's mode.
        mode: PathMode,
        /// The host path that could not be inspected or read.
        path: PathBuf,
        /// What went wrong.
        kind: io::ErrorKind,
    },
    /// A restrictive glob's walk root runs through a symlink inside the
    /// host workspace. Boxed to keep `PathPlanError` small.
    #[error(transparent)]
    WalkRootLink(Box<WalkRootLink>),
    /// A rule could not be resolved.
    ///
    /// Unreachable for validated patterns (see [`ExpandError::InvalidGlob`]);
    /// kept as a defensive error.
    #[error("provider {:?}, rule {:?}: {error}", .provider.as_str(), .pattern.as_str())]
    Expand {
        /// The provider that granted the rule.
        provider: ProviderName,
        /// The rule's pattern.
        pattern: PathPattern,
        /// The underlying error.
        #[source]
        error: ExpandError,
    },
    /// An `fs.ephemeral` rule contains glob characters.
    ///
    /// Unreachable for validated grants, which reject such rules at load
    /// time; kept as a defensive error.
    #[error(
        "provider {:?}, rule {:?}: fs.ephemeral entries must be literal paths",
        .provider.as_str(),
        .pattern.as_str()
    )]
    EphemeralGlob {
        /// The provider that granted the rule.
        provider: ProviderName,
        /// The offending pattern.
        pattern: PathPattern,
    },
}

/// Two candidates of equal precedence disagree on what to mount at one
/// sandbox path (see [`PathPlanError::Conflict`]); e.g. two binds of
/// different host paths to the same sandbox path, with the same mode and
/// inheritance depth.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error(
    "sandbox path {sandbox:?} is mapped from both {first} (provider {:?}) and {second} \
     (provider {:?}) with equal precedence (mode {mode}, depth {depth})",
    .first_provider.as_str(),
    .second_provider.as_str()
)]
pub struct MountConflict {
    /// The contested sandbox path.
    pub sandbox: PathBuf,
    /// The mode both candidates have.
    pub mode: PathMode,
    /// The inheritance depth both candidates have.
    pub depth: u32,
    /// The provider of the first candidate, in rule order.
    pub first_provider: ProviderName,
    /// What the first candidate mounts.
    pub first: MountSource,
    /// The provider of the conflicting candidate.
    pub second_provider: ProviderName,
    /// What the conflicting candidate mounts.
    pub second: MountSource,
}

/// A restrictive glob's walk root runs through a symlink inside the host
/// workspace, which a sandbox may have planted (DESIGN.md §3.4, Symlinks;
/// see [`PathPlanError::WalkRootLink`]). It is refused before walking: the
/// walk would follow the link, which may lead anywhere (`config -> /` would
/// walk the whole host filesystem), and the spec compiler would refuse
/// whatever it matched there anyway.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error(
    "provider {:?}, rule {:?}: the glob's walk root {root:?} runs through the symlink {link:?} \
     inside the host workspace {workspace:?}; a sandbox can write there, so links inside it are \
     never followed, and a {mode} rule is never skipped: remove the link or change the rule",
    .provider.as_str(),
    .pattern
)]
pub struct WalkRootLink {
    /// The provider that granted the rule.
    pub provider: ProviderName,
    /// The rule's pattern as written.
    pub pattern: String,
    /// The rule's mode.
    pub mode: PathMode,
    /// The walk root, as written.
    pub root: PathBuf,
    /// The first symlink inside the workspace on the way to it, named below
    /// its canonical parent directory.
    pub link: PathBuf,
    /// The host workspace.
    pub workspace: PathBuf,
}

/// One rule's proposal for one concrete sandbox path.
struct Candidate<'a> {
    sandbox: PathBuf,
    source: MountSource,
    mode: PathMode,
    /// Whether the rule was an exact path rather than a glob.
    literal: bool,
    /// Whether the host entry is a symlink matched by a glob (see
    /// [`PlannedMount::glob_link`]).
    glob_link: bool,
    rule: &'a FsRule,
}

impl Candidate<'_> {
    /// Precedence; greater wins (§3.5 rules 1–3 at one sandbox path).
    fn rank(&self) -> (bool, Reverse<u32>, PathMode) {
        (self.literal, Reverse(self.rule.depth), self.mode)
    }

    fn into_mount(self) -> PlannedMount {
        PlannedMount {
            sandbox: self.sandbox,
            source: self.source,
            mode: self.mode,
            provider: self.rule.provider.clone(),
            glob_link: self.glob_link,
        }
    }
}

/// Applies path precedence (DESIGN.md §3.5) to a profile's filesystem rules
/// (as collected in [`EffectiveGrants::fs`](super::EffectiveGrants::fs)),
/// producing one mount per concrete sandbox path.
///
/// Path rules are resolved against the host filesystem as it is now (see
/// [`resolve`]): a missing path is skipped with a warning. A path that
/// exists but cannot be inspected, or a directory a glob walk cannot read,
/// is an error for a restrictive rule (any mode but `rw`) and skipped with
/// a warning for an `rw` rule. A bind's host side is resolved like a
/// literal `rw` path rule whatever its mode, so a missing or inaccessible
/// host skips the bind with a warning. `fs.ephemeral` rules have no host
/// source and always produce a candidate.
///
/// Symlinks are resolved alike for every anchor: links on the way are
/// followed and a matched path is kept as written. A `masked` rule matching
/// a symlink takes the kind of the link's target; it is dropped with a
/// warning if the target is missing, and if the target cannot be inspected
/// otherwise it is an error for a literal rule, while a glob match is left
/// to the spec compiler (see [`PlannedMount::glob_link`]). A glob whose walk
/// root runs through a symlink inside the host workspace is refused before
/// walking (an error, or for `rw` a warning; see `check_walk_root`). Host
/// sources running through links a sandbox may
/// have planted, links matched by globs inside such places, and mount
/// destinations are checked by the spec compiler once every profile of the
/// session is planned (DESIGN.md §3.4, Symlinks; §6.2, "Untrusted links").
///
/// Fails if two candidates of equal precedence map different sources to the
/// same sandbox path; identical candidates collapse into one mount, credited
/// to the first rule's provider.
pub fn plan_mounts(fs: &[FsRule], ctx: &ExpansionContext) -> Result<MountPlan, PathPlanError> {
    let mut warnings = Vec::new();
    let mut by_path: BTreeMap<PathBuf, Vec<Candidate<'_>>> = BTreeMap::new();
    for rule in fs {
        for c in rule_candidates(rule, ctx, &mut warnings)? {
            by_path.entry(c.sandbox.clone()).or_default().push(c);
        }
    }
    let mut mounts = Vec::with_capacity(by_path.len());
    for candidates in by_path.into_values() {
        mounts.push(pick(candidates)?.into_mount());
    }
    mounts.sort_by(|a, b| {
        depth(&a.sandbox)
            .cmp(&depth(&b.sandbox))
            .then_with(|| a.sandbox.cmp(&b.sandbox))
    });
    Ok(MountPlan { mounts, warnings })
}

/// The number of components of `path`.
fn depth(path: &Path) -> usize {
    path.components().count()
}

/// The mode of a rule that must fail rather than be skipped when it cannot
/// be applied safely: every mode but `rw` restricts access, and skipping it
/// would lift the restriction.
fn unskippable(mode: PathMode) -> Option<PathMode> {
    (mode != PathMode::Rw).then_some(mode)
}

/// The rule's pattern as written; for a bind, its host path.
fn rule_pattern(rule: &FsRule) -> String {
    match &rule.kind {
        FsRuleKind::Path { pattern, .. } => pattern.to_string(),
        FsRuleKind::Bind(bind) => bind.host.to_string(),
    }
}

fn plan_warning(rule: &FsRule, kind: PlanWarningKind) -> PlanWarning {
    PlanWarning {
        provider: rule.provider.clone(),
        pattern: rule_pattern(rule),
        kind,
    }
}

/// Whether an error inspecting a path means it is missing (it, or a
/// component on the way, does not exist or is not a directory), which
/// skips a rule with a warning whatever its mode.
fn is_missing(kind: io::ErrorKind) -> bool {
    matches!(kind, io::ErrorKind::NotFound | io::ErrorKind::NotADirectory)
}

/// Expands and resolves one rule into its candidates, recording warnings.
fn rule_candidates<'a>(
    rule: &'a FsRule,
    ctx: &ExpansionContext,
    warnings: &mut Vec<PlanWarning>,
) -> Result<Vec<Candidate<'a>>, PathPlanError> {
    let candidate = |sandbox, source, mode, literal, glob_link| Candidate {
        sandbox,
        source,
        mode,
        literal,
        glob_link,
        rule,
    };
    match &rule.kind {
        FsRuleKind::Path {
            mode: PathMode::Ephemeral,
            pattern,
        } => {
            let sandbox = expand_pattern(pattern, ctx).sandbox().ok_or_else(|| {
                PathPlanError::EphemeralGlob {
                    provider: rule.provider.clone(),
                    pattern: pattern.clone(),
                }
            })?;
            Ok(vec![candidate(
                sandbox,
                MountSource::Ephemeral,
                PathMode::Ephemeral,
                true,
                false,
            )])
        }
        FsRuleKind::Path { mode, pattern } => {
            let expanded = expand_pattern(pattern, ctx);
            let literal = !expanded.has_glob();
            let refused = unskippable(*mode);
            let Some(paths) = resolve_host(rule, pattern, &expanded, refused, ctx, warnings)?
            else {
                return Ok(Vec::new());
            };
            let mut out = Vec::with_capacity(paths.len());
            for p in paths {
                // A matched link is kept as it is, whatever the anchor; the
                // spec compiler refuses it, or for a glob skips it, if it
                // lies inside an untrusted root.
                let glob_link = !literal && p.kind == EntryKind::Symlink;
                let kind = if *mode == PathMode::Masked && p.kind == EntryKind::Symlink {
                    match p.host.metadata() {
                        Ok(meta) => EntryKind::from_file_type(meta.file_type()),
                        Err(error) if is_missing(error.kind()) => {
                            warnings.push(plan_warning(
                                rule,
                                PlanWarningKind::SymlinkTarget {
                                    path: p.host,
                                    error,
                                },
                            ));
                            continue;
                        }
                        // A link matched by a glob may have been planted
                        // inside an untrusted root, where the spec compiler
                        // skips it without looking at its target (DESIGN.md
                        // §3.4, Symlinks); only then are the roots known. So
                        // its own kind stands in for the target's, and the
                        // spec compiler fails closed if it keeps the mount
                        // (`SpecError::MaskTargetUninspectable`).
                        Err(_) if glob_link => EntryKind::Symlink,
                        Err(error) => {
                            return Err(PathPlanError::Inaccessible {
                                provider: rule.provider.clone(),
                                pattern: rule_pattern(rule),
                                mode: *mode,
                                path: p.host,
                                kind: error.kind(),
                            });
                        }
                    }
                } else {
                    p.kind
                };
                out.push(candidate(
                    p.sandbox,
                    host_source(p.host, kind),
                    *mode,
                    literal,
                    glob_link,
                ));
            }
            Ok(out)
        }
        FsRuleKind::Bind(bind) => {
            let pattern = bind.host.as_pattern();
            let expanded = expand_pattern(pattern, ctx);
            let sandbox = expand_bind(bind, ctx).sandbox;
            // A bind's host side is a grant of host content wherever it is
            // mounted, so a path that cannot be inspected only skips it. A
            // final link is kept: the bind follows it, as the spec compiler
            // does when checking the source.
            let Some(paths) = resolve_host(rule, pattern, &expanded, None, ctx, warnings)? else {
                return Ok(Vec::new());
            };
            let mut out = Vec::with_capacity(paths.len());
            for p in paths {
                out.push(candidate(
                    sandbox.clone(),
                    host_source(p.host, p.kind),
                    bind.mode.into(),
                    true,
                    false,
                ));
            }
            Ok(out)
        }
    }
}

fn host_source(path: PathBuf, kind: EntryKind) -> MountSource {
    MountSource::Host { path, kind }
}

/// Resolves `expanded` (the expansion of `rule`'s `pattern`), recording its
/// warnings. A path that cannot be inspected or read for any reason but
/// being missing is an error if `refused` (the rule's mode, see
/// [`unskippable`]).
///
/// A glob whose walk root runs through a symlink inside the host workspace
/// is not walked (see [`check_walk_root`]): an error if `refused`, and
/// otherwise `None` with a warning.
fn resolve_host(
    rule: &FsRule,
    pattern: &PathPattern,
    expanded: &ExpandedPattern,
    refused: Option<PathMode>,
    ctx: &ExpansionContext,
    warnings: &mut Vec<PlanWarning>,
) -> Result<Option<Vec<ResolvedPath>>, PathPlanError> {
    if let Some((root, link)) = check_walk_root(expanded, ctx) {
        let workspace = ctx.workspace_host().to_owned();
        return match refused {
            Some(mode) => Err(PathPlanError::WalkRootLink(Box::new(WalkRootLink {
                provider: rule.provider.clone(),
                pattern: rule_pattern(rule),
                mode,
                root,
                link,
                workspace,
            }))),
            None => {
                warnings.push(plan_warning(
                    rule,
                    PlanWarningKind::WalkRootLink {
                        root,
                        link,
                        workspace,
                    },
                ));
                Ok(None)
            }
        };
    }
    let res = resolve(expanded).map_err(|error| PathPlanError::Expand {
        provider: rule.provider.clone(),
        pattern: pattern.clone(),
        error,
    })?;
    for w in res.warnings {
        match w {
            // The resolver reports a missing path, including an entry that
            // vanished during a glob walk, as `Missing`, so this is
            // anything else (e.g. `EACCES`).
            ResolveWarning::Io { path, error } => match refused {
                Some(mode) => {
                    return Err(PathPlanError::Inaccessible {
                        provider: rule.provider.clone(),
                        pattern: rule_pattern(rule),
                        mode,
                        path,
                        kind: error.kind(),
                    });
                }
                None => warnings.push(plan_warning(
                    rule,
                    ResolveWarning::Io { path, error }.into(),
                )),
            },
            other @ ResolveWarning::Missing { .. } => {
                warnings.push(plan_warning(rule, other.into()))
            }
        }
    }
    Ok(Some(res.paths))
}

/// For a glob, the `(walk root, link)` if its walk root (as written) runs
/// through a symlink inside the host workspace, the walk root itself
/// included.
///
/// The walk follows its root, like every component before it, and the spec
/// compiler later refuses (or for `rw` drops) whatever was matched through
/// such a link. But a planted link may lead anywhere, and walking there
/// first can take very long: with `config` replaced by `config -> /`,
/// `{workspace}/config/**/*.env` would walk the whole host filesystem
/// before failing. So the link is refused before walking.
///
/// Of the session's untrusted roots (DESIGN.md §3.4, Symlinks) only the
/// workspace is known while a single profile is planned: the `rw` grants of
/// every profile are collected after planning. A walk root through a link
/// planted in an `rw` grant is walked, and its matches refused afterwards,
/// which can take long (DESIGN.md §11).
///
/// A walk root that cannot be resolved is left to the walk, which reports
/// it as missing or inaccessible.
fn check_walk_root(
    expanded: &ExpandedPattern,
    ctx: &ExpansionContext,
) -> Option<(PathBuf, PathBuf)> {
    let root = expanded.walk_root()?;
    let link = first_link_inside(&root, ctx.workspace_host()).ok()??;
    Some((root, link))
}

/// Picks the winner among the candidates for one sandbox path (non-empty,
/// in rule order).
fn pick(candidates: Vec<Candidate<'_>>) -> Result<Candidate<'_>, PathPlanError> {
    let best = candidates
        .iter()
        .map(Candidate::rank)
        .max()
        .expect("every sandbox path has at least one candidate");
    let mut top = candidates.into_iter().filter(|c| c.rank() == best);
    let winner = top.next().expect("the best rank is attained");
    if let Some(other) = top.find(|c| c.source != winner.source) {
        return Err(PathPlanError::Conflict(Box::new(MountConflict {
            sandbox: winner.sandbox,
            mode: winner.mode,
            depth: winner.rule.depth,
            first_provider: winner.rule.provider.clone(),
            first: winner.source,
            second_provider: other.rule.provider.clone(),
            second: other.source,
        })));
    }
    Ok(winner)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;

    use tempfile::TempDir;

    use super::*;
    use crate::manifest::{Bind, BindMode};
    use crate::policy::PathMode::{Ephemeral, Masked, Protected, Ro, Rw};

    /// A temporary workspace and home, with an expansion context mapping
    /// them to `/workspace` and `/home/user`.
    struct Fixture {
        _dir: TempDir,
        /// The canonical temp dir path, as `ExpansionContext` requires.
        root: PathBuf,
        ctx: ExpansionContext,
    }

    impl Fixture {
        fn new() -> Self {
            Self::with_mount("/workspace")
        }

        /// Like [`Fixture::new`], with the workspace mounted at `mount`.
        fn with_mount(mount: &str) -> Self {
            let dir = TempDir::new().unwrap();
            let root = dir.path().canonicalize().unwrap();
            fs::create_dir(root.join("ws")).unwrap();
            fs::create_dir(root.join("home")).unwrap();
            let ctx = ExpansionContext::new(
                root.join("ws"),
                mount.parse().unwrap(),
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

        fn home(&self) -> PathBuf {
            self.root.join("home")
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

        /// Creates a symlink at `rel` below the temp root.
        fn symlink(&self, target: impl AsRef<Path>, rel: &str) {
            symlink(target, self.root.join(rel)).unwrap();
        }

        fn plan(&self, rules: &[FsRule]) -> MountPlan {
            plan_mounts(rules, &self.ctx).unwrap()
        }

        fn plan_err(&self, rules: &[FsRule]) -> PathPlanError {
            match plan_mounts(rules, &self.ctx) {
                Ok(plan) => panic!("expected an error, got {plan:?}"),
                Err(e) => e,
            }
        }

        /// The plan, asserting that it has no warnings.
        fn clean(&self, rules: &[FsRule]) -> Vec<PlannedMount> {
            let plan = self.plan(rules);
            assert!(plan.warnings.is_empty(), "{:?}", plan.warnings);
            plan.mounts
        }
    }

    fn pn(s: &str) -> ProviderName {
        s.parse().unwrap()
    }

    fn p(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    fn rule(mode: PathMode, pattern: &str, provider: &str, depth: u32) -> FsRule {
        FsRule {
            kind: FsRuleKind::Path {
                mode,
                pattern: pattern.parse().unwrap(),
            },
            provider: pn(provider),
            depth,
        }
    }

    fn bind(host: &str, sandbox: &str, mode: BindMode, provider: &str, depth: u32) -> FsRule {
        FsRule {
            kind: FsRuleKind::Bind(Bind {
                host: host.parse().unwrap(),
                sandbox: sandbox.parse().unwrap(),
                mode,
            }),
            provider: pn(provider),
            depth,
        }
    }

    fn host(
        sandbox: &str,
        path: PathBuf,
        kind: EntryKind,
        mode: PathMode,
        p: &str,
    ) -> PlannedMount {
        PlannedMount {
            sandbox: sandbox.into(),
            source: MountSource::Host { path, kind },
            mode,
            provider: pn(p),
            glob_link: false,
        }
    }

    fn eph(sandbox: &str, p: &str) -> PlannedMount {
        PlannedMount {
            sandbox: sandbox.into(),
            source: MountSource::Ephemeral,
            mode: Ephemeral,
            provider: pn(p),
            glob_link: false,
        }
    }

    /// Each mount as `(sandbox path, mode, provider)`.
    fn summary(mounts: &[PlannedMount]) -> Vec<(String, PathMode, String)> {
        mounts
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

    fn kind_of(m: &PlannedMount) -> EntryKind {
        match &m.source {
            MountSource::Host { kind, .. } => *kind,
            MountSource::Ephemeral => panic!("unexpected ephemeral mount"),
        }
    }

    #[test]
    fn workspace_rw_with_masked_dotenv_files_on_top() {
        let f = Fixture::new();
        f.file("ws/.env");
        f.file("ws/a/b/.env");
        f.file("ws/src/main.rs");
        let mounts = f.clean(&[
            rule(Rw, "{workspace}", "base", 0),
            rule(Masked, "{workspace}/**/.env", "base", 0),
        ]);
        assert_eq!(
            mounts,
            vec![
                host("/workspace", f.ws(), EntryKind::Dir, Rw, "base"),
                host(
                    "/workspace/.env",
                    f.ws().join(".env"),
                    EntryKind::File,
                    Masked,
                    "base"
                ),
                host(
                    "/workspace/a/b/.env",
                    f.ws().join("a/b/.env"),
                    EntryKind::File,
                    Masked,
                    "base"
                ),
            ]
        );
    }

    #[test]
    fn masked_keeps_the_host_kind() {
        let f = Fixture::new();
        f.mkdir("ws/.git");
        f.file("ws/.env");
        let mounts = f.clean(&[
            rule(Masked, "{workspace}/.git", "a", 0),
            rule(Masked, "{workspace}/.env", "a", 0),
        ]);
        let kinds: Vec<_> = mounts.iter().map(kind_of).collect();
        assert_eq!(kinds, [EntryKind::File, EntryKind::Dir]);
    }

    #[test]
    fn masked_symlink_takes_the_kind_of_its_target() {
        let f = Fixture::new();
        f.file("home/file");
        f.mkdir("home/dir");
        f.symlink(f.home().join("file"), "home/filelink");
        f.symlink("dir", "home/dirlink");
        f.mkdir("home/sub");
        f.symlink("../file", "home/sub/glink");
        f.mkdir("ws/real");
        f.symlink("real", "ws/wslink");
        let abs = f.home().join("dirlink");
        let mounts = f.clean(&[
            rule(Masked, "~/filelink", "a", 0),
            rule(Masked, "~/dirlink", "a", 0),
            rule(Masked, abs.to_str().unwrap(), "a", 0),
            rule(Masked, "~/sub/*", "b", 0),
            // Every anchor alike: whether the link may have been planted is
            // the spec compiler's to decide.
            rule(Masked, "{workspace}/wslink", "w", 0),
            // Other modes keep the link itself, which a bind follows.
            bind("~/filelink", "/opt/f", BindMode::Ro, "c", 0),
        ]);
        let got: Vec<_> = mounts
            .iter()
            .map(|m| (m.sandbox.clone(), kind_of(m), m.mode))
            .collect();
        assert_eq!(
            got,
            [
                (p("/opt/f"), EntryKind::Symlink, Ro),
                (p("/workspace/wslink"), EntryKind::Dir, Masked),
                (p("/home/user/dirlink"), EntryKind::Dir, Masked),
                (p("/home/user/filelink"), EntryKind::File, Masked),
                (p("/home/user/sub/glink"), EntryKind::File, Masked),
                (abs.clone(), EntryKind::Dir, Masked),
            ]
        );
        // The source is still the link as written.
        assert_eq!(
            mounts[3].source,
            MountSource::Host {
                path: f.home().join("filelink"),
                kind: EntryKind::File
            }
        );
    }

    #[test]
    fn masked_dangling_home_symlink_is_dropped_with_a_warning() {
        let f = Fixture::new();
        f.symlink("nowhere", "home/dangling");
        let plan = f.plan(&[
            rule(Masked, "~/dangling", "a", 0),
            rule(Ro, "~/dangling", "b", 1),
        ]);
        // The masked candidate is gone, so the inherited ro one remains.
        assert_eq!(
            plan.mounts,
            vec![host(
                "/home/user/dangling",
                f.home().join("dangling"),
                EntryKind::Symlink,
                Ro,
                "b"
            )]
        );
        match plan.warnings.as_slice() {
            [
                PlanWarning {
                    provider,
                    pattern,
                    kind: PlanWarningKind::SymlinkTarget { path, error },
                },
            ] => {
                assert_eq!((provider.as_str(), pattern.as_str()), ("a", "~/dangling"));
                assert_eq!(path, &f.home().join("dangling"));
                assert_eq!(error.kind(), io::ErrorKind::NotFound);
            }
            other => panic!("expected one SymlinkTarget warning, got {other:?}"),
        }
        let msg = plan.warnings[0].to_string();
        assert!(msg.contains("target of the symlink"), "{msg}");
        assert!(
            msg.contains(&format!("{:?}", f.home().join("dangling"))),
            "{msg}"
        );
    }

    #[test]
    fn exact_path_beats_glob() {
        let f = Fixture::new();
        f.file("ws/flake.nix");
        f.file("ws/nix/a.nix");
        let mounts = f.clean(&[
            rule(Protected, "{workspace}/**/*.nix", "nix", 0),
            rule(Rw, "{workspace}/flake.nix", "user", 0),
        ]);
        assert_eq!(
            summary(&mounts),
            [
                row("/workspace/flake.nix", Rw, "user"),
                row("/workspace/nix/a.nix", Protected, "nix"),
            ]
        );
        // Exactness is decided before inheritance: an inherited exact path
        // still beats an own glob.
        let mounts = f.clean(&[
            rule(Rw, "{workspace}/flake.nix", "parent", 1),
            rule(Protected, "{workspace}/**/*.nix", "own", 0),
        ]);
        assert_eq!(mounts[0].sandbox, Path::new("/workspace/flake.nix"));
        assert_eq!(
            (mounts[0].mode, mounts[0].provider.as_str()),
            (Rw, "parent")
        );
    }

    #[test]
    fn own_beats_inherited_then_strictest_wins() {
        let f = Fixture::new();
        f.mkdir("ws/.git");
        // Own rw beats the parent's masked, whatever the rule order.
        for rules in [
            [
                rule(Masked, "{workspace}/.git", "base", 1),
                rule(Rw, "{workspace}/.git", "vcs", 0),
            ],
            [
                rule(Rw, "{workspace}/.git", "vcs", 0),
                rule(Masked, "{workspace}/.git", "base", 1),
            ],
        ] {
            assert_eq!(
                summary(&f.clean(&rules)),
                [row("/workspace/.git", Rw, "vcs")]
            );
        }
        // At the same depth the strictest mode wins.
        for (a, b, want) in [
            (Rw, Masked, Masked),
            (Ro, Protected, Protected),
            (Ro, Rw, Ro),
            (Protected, Masked, Masked),
        ] {
            for (first, second) in [(a, b), (b, a)] {
                let mounts = f.clean(&[
                    rule(first, "{workspace}/.git", "x", 2),
                    rule(second, "{workspace}/.git", "y", 2),
                ]);
                assert_eq!(mounts.len(), 1);
                assert_eq!(mounts[0].mode, want, "{first} vs {second}");
            }
        }
        // Deeper inheritance loses to shallower, at any distance.
        let mounts = f.clean(&[
            rule(Masked, "{workspace}/.git", "gp", 2),
            rule(Ro, "{workspace}/.git", "parent", 1),
        ]);
        assert_eq!(summary(&mounts), [row("/workspace/.git", Ro, "parent")]);
    }

    #[test]
    fn ephemeral_needs_no_host_source() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().canonicalize().unwrap();
        // Neither the workspace nor the home exist on the host.
        let ctx = ExpansionContext::new(
            root.join("no-ws"),
            "/workspace".parse().unwrap(),
            root.join("no-home"),
            "/home/user".parse().unwrap(),
        )
        .unwrap();
        let plan = plan_mounts(
            &[
                rule(Ephemeral, "/tmp", "base", 0),
                rule(Ephemeral, "~", "base", 0),
                rule(Ephemeral, "/stopit-test/does/not/exist", "base", 0),
                rule(Ephemeral, "{workspace}/target", "rust", 0),
            ],
            &ctx,
        )
        .unwrap();
        assert!(plan.warnings.is_empty(), "{:?}", plan.warnings);
        assert_eq!(
            plan.mounts,
            vec![
                eph("/tmp", "base"),
                eph("/home/user", "base"),
                eph("/workspace/target", "rust"),
                eph("/stopit-test/does/not/exist", "base"),
            ]
        );
    }

    #[test]
    fn ephemeral_competes_by_precedence() {
        let f = Fixture::new();
        // Same depth: ephemeral is stricter than rw, looser than ro.
        let mounts = f.clean(&[rule(Rw, "~", "a", 0), rule(Ephemeral, "~", "b", 0)]);
        assert_eq!(mounts, vec![eph("/home/user", "b")]);
        let mounts = f.clean(&[rule(Ephemeral, "~", "b", 0), rule(Ro, "~", "a", 0)]);
        assert_eq!(
            mounts,
            vec![host("/home/user", f.home(), EntryKind::Dir, Ro, "a")]
        );
        // Own rw beats an inherited ephemeral.
        let mounts = f.clean(&[rule(Ephemeral, "~", "parent", 1), rule(Rw, "~", "own", 0)]);
        assert_eq!(
            mounts,
            vec![host("/home/user", f.home(), EntryKind::Dir, Rw, "own")]
        );
        // An exact ephemeral path beats a glob match at the same path.
        f.mkdir("ws/target");
        let mounts = f.clean(&[
            rule(Ro, "{workspace}/*", "a", 0),
            rule(Ephemeral, "{workspace}/target", "b", 1),
        ]);
        assert_eq!(mounts, vec![eph("/workspace/target", "b")]);
    }

    #[test]
    fn binds_map_host_paths_to_sandbox_paths() {
        let f = Fixture::new();
        f.file("home/.gitconfig");
        f.file("ws/real/x");
        let mounts = f.clean(&[
            bind(
                "~/.gitconfig",
                "~/.gitconfig",
                BindMode::Protected,
                "git",
                0,
            ),
            bind("{workspace}/real/x", "/opt/x", BindMode::Ro, "v", 0),
        ]);
        assert_eq!(
            mounts,
            vec![
                host("/opt/x", f.ws().join("real/x"), EntryKind::File, Ro, "v"),
                host(
                    "/home/user/.gitconfig",
                    f.home().join(".gitconfig"),
                    EntryKind::File,
                    Protected,
                    "git"
                ),
            ]
        );
    }

    #[test]
    fn bind_with_missing_host_is_a_warning() {
        let f = Fixture::new();
        let plan = f.plan(&[bind("~/nope", "/opt/nope", BindMode::Ro, "p", 0)]);
        assert!(plan.mounts.is_empty());
        match plan.warnings.as_slice() {
            [
                PlanWarning {
                    provider,
                    pattern,
                    kind: PlanWarningKind::Resolve(ResolveWarning::Missing { path }),
                },
            ] => {
                assert_eq!(provider.as_str(), "p");
                assert_eq!(pattern, "~/nope");
                assert_eq!(path, &f.home().join("nope"));
            }
            other => panic!("expected one Missing warning, got {other:?}"),
        }
    }

    #[test]
    fn conflicting_binds_are_an_error() {
        let f = Fixture::new();
        f.file("home/a");
        f.file("home/b");
        let e = f.plan_err(&[
            bind("~/a", "/opt/x", BindMode::Ro, "p", 0),
            bind("~/a", "/opt/x", BindMode::Ro, "p2", 0),
            bind("~/b", "/opt/x", BindMode::Ro, "q", 0),
        ]);
        assert_eq!(
            e,
            PathPlanError::Conflict(Box::new(MountConflict {
                sandbox: "/opt/x".into(),
                mode: Ro,
                depth: 0,
                first_provider: pn("p"),
                first: MountSource::Host {
                    path: f.home().join("a"),
                    kind: EntryKind::File,
                },
                second_provider: pn("q"),
                second: MountSource::Host {
                    path: f.home().join("b"),
                    kind: EntryKind::File,
                },
            }))
        );
        let msg = e.to_string();
        for part in [
            "\"/opt/x\"".to_owned(),
            format!("{:?}", f.home().join("a")),
            format!("{:?}", f.home().join("b")),
            "provider \"p\"".to_owned(),
            "provider \"q\"".to_owned(),
            "mode ro".to_owned(),
            "depth 0".to_owned(),
        ] {
            assert!(msg.contains(&part), "{part}: {msg}");
        }
        // Differing depth or mode is resolved by precedence instead.
        let mounts = f.clean(&[
            bind("~/a", "/opt/x", BindMode::Ro, "p", 1),
            bind("~/b", "/opt/x", BindMode::Ro, "q", 0),
        ]);
        assert_eq!(summary(&mounts), [row("/opt/x", Ro, "q")]);
        let mounts = f.clean(&[
            bind("~/a", "/opt/x", BindMode::Rw, "p", 0),
            bind("~/b", "/opt/x", BindMode::Protected, "q", 0),
        ]);
        assert_eq!(summary(&mounts), [row("/opt/x", Protected, "q")]);
    }

    #[test]
    fn path_rule_and_bind_conflict_at_the_same_sandbox_path() {
        let f = Fixture::new();
        f.file("ws/x");
        f.file("home/x");
        let e = f.plan_err(&[
            rule(Ro, "{workspace}/x", "a", 0),
            bind("~/x", "/workspace/x", BindMode::Ro, "b", 0),
        ]);
        let PathPlanError::Conflict(c) = e else {
            panic!("expected a conflict, got {e:?}");
        };
        assert_eq!(c.sandbox, Path::new("/workspace/x"));
        assert_eq!(
            (c.first_provider.as_str(), c.second_provider.as_str()),
            ("a", "b")
        );
    }

    #[test]
    fn identical_rules_collapse() {
        let f = Fixture::new();
        f.file("ws/.env");
        f.file("home/c");
        let mounts = f.clean(&[
            rule(Masked, "{workspace}/.env", "a", 0),
            rule(Masked, "{workspace}/**/.env", "b", 0),
            rule(Masked, "{workspace}/.env", "c", 0),
            rule(Masked, "{workspace}/.env", "a", 0),
            rule(Ephemeral, "/tmp", "a", 0),
            rule(Ephemeral, "/tmp", "b", 0),
            bind("~/c", "/c", BindMode::Ro, "a", 0),
            bind("~/c", "/c", BindMode::Ro, "b", 0),
        ]);
        assert_eq!(
            mounts,
            vec![
                host("/c", f.home().join("c"), EntryKind::File, Ro, "a"),
                eph("/tmp", "a"),
                host(
                    "/workspace/.env",
                    f.ws().join(".env"),
                    EntryKind::File,
                    Masked,
                    "a"
                ),
            ]
        );
    }

    #[test]
    fn workspace_links_are_planned_like_any_anchor() {
        // The planner leaves links to the spec compiler, which refuses (or
        // for `rw` drops) those inside an untrusted root such as the
        // workspace, whatever the rule's anchor (DESIGN.md §6.2, Untrusted
        // links). So `{workspace}` rules and binds through links plan like
        // `~` ones, with their paths as written.
        let f = Fixture::new();
        f.file("ws/real/x");
        f.file("outside/secret");
        f.symlink("real", "ws/link");
        f.symlink(f.root.join("outside/secret"), "ws/.env");
        f.symlink(f.root.join("outside/secret"), "home/link");
        for mode in [Masked, Protected, Ro, Rw] {
            let mounts = f.clean(&[
                rule(Rw, "{workspace}", "base", 0),
                rule(mode, "{workspace}/link/x", "a", 0),
                rule(mode, "{workspace}/real/*", "g", 1),
                bind("{workspace}/link", "/opt/l", BindMode::Rw, "c", 0),
                bind("{workspace}/.env", "/opt/e", BindMode::Ro, "d", 0),
                rule(Ro, "~/link", "e", 0),
            ]);
            assert_eq!(
                mounts,
                vec![
                    host("/workspace", f.ws(), EntryKind::Dir, Rw, "base"),
                    host("/opt/e", f.ws().join(".env"), EntryKind::Symlink, Ro, "d"),
                    host("/opt/l", f.ws().join("link"), EntryKind::Symlink, Rw, "c"),
                    host(
                        "/home/user/link",
                        f.home().join("link"),
                        EntryKind::Symlink,
                        Ro,
                        "e"
                    ),
                    host(
                        "/workspace/link/x",
                        f.ws().join("link/x"),
                        EntryKind::File,
                        mode,
                        "a"
                    ),
                    host(
                        "/workspace/real/x",
                        f.ws().join("real/x"),
                        EntryKind::File,
                        mode,
                        "g"
                    ),
                ],
                "{mode}"
            );
        }
    }

    #[test]
    fn globs_walking_through_a_workspace_link_are_refused_before_walking() {
        let f = Fixture::new();
        f.file("ws/real/a.env");
        f.mkdir("ws/real/sub");
        f.file("outside/b.env");
        f.symlink("real", "ws/link");
        // Walking this would take the whole host filesystem.
        f.symlink("/", "ws/config");
        f.symlink(f.root.join("outside"), "home/hostlink");
        f.symlink(f.ws(), "home/current");
        // `(pattern, walk root, link)`: the walk root itself, a component
        // before it, and a link reached through a host link.
        let cases = [
            (
                "{workspace}/link/*.env",
                f.ws().join("link"),
                f.ws().join("link"),
            ),
            (
                "{workspace}/link/sub/*",
                f.ws().join("link/sub"),
                f.ws().join("link"),
            ),
            (
                "{workspace}/config/**/*.env",
                f.ws().join("config"),
                f.ws().join("config"),
            ),
            (
                "~/current/link/*",
                f.home().join("current/link"),
                f.ws().join("link"),
            ),
        ];
        for mode in [Masked, Protected, Ro] {
            for (pattern, root, link) in &cases {
                let e = f.plan_err(&[rule(mode, pattern, "p", 0)]);
                assert_eq!(
                    e,
                    PathPlanError::WalkRootLink(Box::new(WalkRootLink {
                        provider: pn("p"),
                        pattern: (*pattern).into(),
                        mode,
                        root: root.clone(),
                        link: link.clone(),
                        workspace: f.ws(),
                    })),
                    "{mode} {pattern}"
                );
            }
        }
        let e = f.plan_err(&[rule(Masked, "{workspace}/config/**/*.env", "p", 0)]);
        assert_eq!(
            e.to_string(),
            format!(
                "provider \"p\", rule \"{{workspace}}/config/**/*.env\": the glob's walk root {:?} \
                 runs through the symlink {:?} inside the host workspace {:?}; a sandbox can \
                 write there, so links inside it are never followed, and a masked rule is never \
                 skipped: remove the link or change the rule",
                f.ws().join("config"),
                f.ws().join("config"),
                f.ws()
            )
        );
        // `rw` rules are skipped with a warning instead.
        for (pattern, root, link) in &cases {
            let plan = f.plan(&[rule(Rw, pattern, "p", 0)]);
            assert!(plan.mounts.is_empty(), "{pattern}");
            match plan.warnings.as_slice() {
                [
                    PlanWarning {
                        kind:
                            PlanWarningKind::WalkRootLink {
                                root: r,
                                link: l,
                                workspace,
                            },
                        ..
                    },
                ] => assert_eq!((r, l, workspace), (root, link, &f.ws()), "{pattern}"),
                other => panic!("{pattern}: expected one WalkRootLink warning, got {other:?}"),
            }
        }
        // Host links on the way, and the workspace itself, are walked.
        assert_eq!(
            summary(&f.clean(&[
                rule(Masked, "~/hostlink/*.env", "p", 0),
                rule(Masked, "{workspace}/real/*.env", "p", 0),
            ])),
            [
                row("/workspace/real/a.env", Masked, "p"),
                row("/home/user/hostlink/b.env", Masked, "p"),
            ]
        );
    }

    #[test]
    fn glob_matched_links_are_flagged() {
        let f = Fixture::new();
        f.file("ws/bar.nix");
        f.file("ws/nix/real.nix");
        f.symlink("bar.nix", "ws/foo.nix");
        f.symlink("real.nix", "ws/nix/alias.nix");
        f.file("home/sub/file");
        f.symlink("file", "home/sub/glink");
        let mounts = f.clean(&[
            rule(Protected, "{workspace}/**/*.nix", "nix", 0),
            rule(Masked, "~/sub/*", "m", 0),
            // A literal rule at a matched link outranks the glob, and is no
            // glob match.
            rule(Ro, "{workspace}/foo.nix", "lit", 1),
        ]);
        let got: Vec<_> = mounts
            .iter()
            .map(|m| (m.sandbox.clone(), m.mode, kind_of(m), m.glob_link))
            .collect();
        assert_eq!(
            got,
            [
                (p("/workspace/bar.nix"), Protected, EntryKind::File, false),
                (p("/workspace/foo.nix"), Ro, EntryKind::Symlink, false),
                (
                    p("/workspace/nix/alias.nix"),
                    Protected,
                    EntryKind::Symlink,
                    true
                ),
                (
                    p("/workspace/nix/real.nix"),
                    Protected,
                    EntryKind::File,
                    false
                ),
                (p("/home/user/sub/file"), Masked, EntryKind::File, false),
                // A mask takes its target's kind, and is still a link.
                (p("/home/user/sub/glink"), Masked, EntryKind::File, true),
            ]
        );
    }

    /// Runs `body` with the directories `rels` (below the temp root) made
    /// unreadable (mode 000), restoring them before returning. Returns
    /// `None`, skipping `body`, when running as root, where permissions do
    /// not apply.
    fn with_locked<T>(f: &Fixture, rels: &[&str], body: impl FnOnce() -> T) -> Option<T> {
        use std::os::unix::fs::PermissionsExt;
        if rustix::process::geteuid().is_root() {
            eprintln!("skipping: permission checks do not apply to root");
            return None;
        }
        let set = |mode| {
            for rel in rels {
                fs::set_permissions(f.root.join(rel), fs::Permissions::from_mode(mode)).unwrap();
            }
        };
        set(0o000);
        let out = body();
        set(0o755);
        Some(out)
    }

    /// The `(mode, path, kind)` of an `Inaccessible` error.
    fn inaccessible(e: PathPlanError) -> (PathMode, PathBuf, io::ErrorKind) {
        match e {
            PathPlanError::Inaccessible {
                mode, path, kind, ..
            } => (mode, path, kind),
            other => panic!("expected an Inaccessible error, got {other:?}"),
        }
    }

    #[test]
    fn unreadable_paths_fail_restrictive_rules_closed() {
        let f = Fixture::new();
        f.file("ws/a/.env");
        f.file("ws/locked/.env");
        f.file("home/locked/secret");
        f.symlink(f.home().join("locked/secret"), "home/link");
        let locked = f.ws().join("locked");
        // Each pattern with the path it cannot inspect: a directory the walk
        // cannot read, or a literal path below an unsearchable directory.
        let cases = [
            ("{workspace}/**/.env", locked.clone()),
            ("{workspace}/locked/.env", locked.join(".env")),
            ("{workspace}/locked/*", locked.clone()),
            ("~/locked/secret", f.home().join("locked/secret")),
            ("~/locked/**", f.home().join("locked")),
        ];
        let Some((errors, warned)) = with_locked(&f, &["ws/locked", "home/locked"], || {
            let mut errors = Vec::new();
            for mode in [Masked, Protected, Ro] {
                for (pattern, want) in &cases {
                    let res = plan_mounts(&[rule(mode, pattern, "p", 0)], &f.ctx);
                    errors.push((mode, *pattern, want.clone(), res));
                }
            }
            // A masked `~` link whose target cannot be inspected.
            let res = plan_mounts(&[rule(Masked, "~/link", "p", 0)], &f.ctx);
            errors.push((Masked, "~/link", f.home().join("link"), res));
            let warned = plan_mounts(
                &[
                    rule(Rw, "{workspace}/**/.env", "a", 0),
                    rule(Rw, "~/locked/secret", "b", 0),
                    bind("{workspace}/locked/.env", "/opt/e", BindMode::Ro, "c", 0),
                ],
                &f.ctx,
            );
            (errors, warned)
        }) else {
            return;
        };
        for (mode, pattern, want, res) in errors {
            let e = res.unwrap_err();
            let msg = e.to_string();
            let (got_mode, path, kind) = inaccessible(e);
            assert_eq!(got_mode, mode, "{pattern}");
            assert_eq!(kind, io::ErrorKind::PermissionDenied, "{mode} {pattern}");
            assert_eq!(path, want, "{mode} {pattern}");
            for part in [
                format!(r#"provider "p", rule "{pattern}": "#),
                format!("{want:?}"),
                format!("{mode} rule is never skipped"),
                io::ErrorKind::PermissionDenied.to_string(),
            ] {
                assert!(msg.contains(&part), "{part}: {msg}");
            }
        }
        // rw rules and binds skip what they cannot read, and the rest of
        // the walk still applies.
        let plan = warned.unwrap();
        assert_eq!(summary(&plan.mounts), [row("/workspace/a/.env", Rw, "a")]);
        let got: Vec<_> = plan
            .warnings
            .iter()
            .map(|w| match &w.kind {
                PlanWarningKind::Resolve(ResolveWarning::Io { path, error }) => {
                    (w.provider.to_string(), path.clone(), error.kind())
                }
                other => panic!("unexpected warning {other:?}"),
            })
            .collect();
        assert_eq!(
            got,
            [
                ("a".into(), locked.clone(), io::ErrorKind::PermissionDenied),
                (
                    "b".into(),
                    f.home().join("locked/secret"),
                    io::ErrorKind::PermissionDenied
                ),
                (
                    "c".into(),
                    locked.join(".env"),
                    io::ErrorKind::PermissionDenied
                ),
            ]
        );
    }

    #[test]
    fn missing_paths_still_skip_restrictive_rules() {
        let f = Fixture::new();
        f.file("ws/file");
        for mode in [Masked, Protected, Ro] {
            let plan = f.plan(&[
                rule(mode, "{workspace}/nope", "p", 0),
                rule(mode, "{workspace}/nope/*", "p", 0),
                // A component on the way is not a directory.
                rule(mode, "{workspace}/file/x", "p", 0),
                rule(mode, "{workspace}/file/x/**", "p", 0),
                rule(mode, "~/nope", "p", 0),
            ]);
            assert!(plan.mounts.is_empty(), "{mode}: {:?}", plan.mounts);
            assert_eq!(plan.warnings.len(), 5, "{mode}: {:?}", plan.warnings);
            assert!(
                plan.warnings.iter().all(|w| matches!(
                    w.kind,
                    PlanWarningKind::Resolve(ResolveWarning::Missing { .. })
                )),
                "{mode}: {:?}",
                plan.warnings
            );
        }
    }

    #[test]
    fn ordered_by_depth_then_lexicographically() {
        let f = Fixture::new();
        f.file("ws/a/b/c");
        f.file("ws/b");
        f.file("home/z/y");
        let mounts = f.clean(&[
            rule(Ro, "{workspace}/a/b/c", "p", 0),
            rule(Ephemeral, "/aaa/bbb/ccc/ddd", "p", 0),
            rule(Ro, "~/z", "p", 0),
            rule(Ro, "{workspace}/a/b", "p", 0),
            rule(Rw, "{workspace}", "p", 0),
            rule(Ro, "~", "p", 0),
            rule(Ro, "{workspace}/b", "p", 0),
            rule(Ro, "{workspace}/a", "p", 0),
            rule(Ephemeral, "/tmp", "p", 0),
        ]);
        let order: Vec<_> = mounts
            .iter()
            .map(|m| m.sandbox.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            order,
            [
                "/tmp",
                "/workspace",
                "/home/user",
                "/workspace/a",
                "/workspace/b",
                "/home/user/z",
                "/workspace/a/b",
                "/aaa/bbb/ccc/ddd",
                "/workspace/a/b/c",
            ]
        );
    }

    #[test]
    fn warnings_carry_provider_and_pattern_in_rule_order() {
        let f = Fixture::new();
        let plan = f.plan(&[
            rule(Ro, "{workspace}/nope", "a", 0),
            rule(Masked, "~/missing/**/.env", "b", 1),
            rule(Rw, "{workspace}", "c", 0),
        ]);
        assert_eq!(summary(&plan.mounts), [row("/workspace", Rw, "c")]);
        let got: Vec<_> = plan
            .warnings
            .iter()
            .map(|w| (w.provider.to_string(), w.pattern.clone()))
            .collect();
        assert_eq!(
            got,
            [
                ("a".to_owned(), "{workspace}/nope".to_owned()),
                ("b".to_owned(), "~/missing/**/.env".to_owned()),
            ]
        );
        let msg = plan.warnings[1].to_string();
        assert!(
            msg.starts_with(r#"provider "b", rule "~/missing/**/.env": "#),
            "{msg}"
        );
        assert!(msg.contains("does not exist"), "{msg}");
    }

    #[test]
    fn empty_rules_give_an_empty_plan() {
        let f = Fixture::new();
        let plan = f.plan(&[]);
        assert!(plan.mounts.is_empty() && plan.warnings.is_empty());
    }

    #[test]
    fn defensive_errors_name_provider_and_pattern() {
        let f = Fixture::new();
        let unchecked = |mode, s: &str| FsRule {
            kind: FsRuleKind::Path {
                mode,
                pattern: PathPattern::new_unchecked(s),
            },
            provider: pn("p"),
            depth: 0,
        };
        let e = f.plan_err(&[unchecked(Ephemeral, "{workspace}/*.tmp")]);
        assert!(matches!(e, PathPlanError::EphemeralGlob { .. }), "{e:?}");
        let msg = e.to_string();
        assert!(msg.contains(r#""p""#) && msg.contains("*.tmp"), "{msg}");

        let e = f.plan_err(&[unchecked(Ro, "{workspace}/[a.nix")]);
        assert!(
            matches!(
                e,
                PathPlanError::Expand {
                    error: ExpandError::InvalidGlob { .. },
                    ..
                }
            ),
            "{e:?}"
        );
        let msg = e.to_string();
        assert!(msg.contains(r#""p""#) && msg.contains("[a.nix"), "{msg}");
    }
}
