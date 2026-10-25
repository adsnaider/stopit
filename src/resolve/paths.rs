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
//! Symlinks below the workspace are never followed (DESIGN.md §3.4,
//! Symlinks), neither on the way to a `{workspace}` rule's host path nor on
//! the way to a mount destination inside the workspace mount. A rule whose
//! literal part (a literal path, or a glob's literal prefix) or mount
//! destination runs into one is a startup error if it restricts access
//! (every mode but `rw`), since a planted link (e.g. a renamed directory
//! replaced by a link to it) would redirect the rule away from the real
//! file, and is skipped with a warning otherwise (an `rw` rule, or a bind's
//! host side), since dropping a grant only removes access. A link matched
//! by a glob is skipped with a warning whatever the mode: the walk never
//! follows links and visits the real files directly, so the rule still
//! reaches them under their real names.
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
    EntryKind, ExpandError, ExpandedPattern, ExpansionContext, NoSymlinksError, ResolveWarning,
    ResolvedPath, check_no_symlinks, expand_bind, expand_pattern, resolve,
};
use crate::manifest::{PathPattern, PatternAnchor};
use crate::policy::PathMode;

/// What a planned mount shows at its sandbox path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountSource {
    /// An existing host entry.
    Host {
        /// The host path, as written in the rule (with globs expanded).
        path: PathBuf,
        /// The kind of entry at `path`; for `masked` it decides whether an
        /// empty file or an empty directory is shown, and for a masked `~`
        /// or absolute symlink it is the kind of the link's target.
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
}

/// The outcome of [`plan_mounts`].
#[derive(Debug, Default)]
pub struct MountPlan {
    /// One mount per sandbox path, ordered by the number of components of
    /// the sandbox path and then lexicographically, so that every mount
    /// comes after the mounts of its ancestors.
    pub mounts: Vec<PlannedMount>,
    /// Non-fatal problems: those found resolving the rules, in rule order,
    /// then those found checking mount destinations, in sandbox path order.
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
    /// Resolving the rule against the host filesystem, or checking its
    /// mount destination, found a problem: a missing path, or for an `rw`
    /// rule or a bind's host side, one that cannot be inspected.
    #[error(transparent)]
    Resolve(#[from] ResolveWarning),
    /// An `rw` rule's path or mount destination, a bind's host path, or a
    /// path matched by a `{workspace}` glob of any mode, is or runs through
    /// a symlink below the workspace, which is never followed (DESIGN.md
    /// §3.4, Symlinks).
    #[error(
        "{path:?} is or runs through the symlink {link:?} in the workspace, which is never \
         followed; write a rule for the link's target if it needs one"
    )]
    WorkspaceSymlink {
        /// The host path that was to be mounted, or mounted over.
        path: PathBuf,
        /// The first symlink on the way to it (possibly `path` itself).
        link: PathBuf,
    },
    /// A `masked` rule outside the workspace matched a symlink whose target
    /// is missing (a dangling link), so whether to show an empty file or an
    /// empty directory is unknown; there is no content to hide either.
    #[error("cannot inspect the target of the symlink {path:?}: {error}")]
    SymlinkTarget {
        /// The symlink's host path.
        path: PathBuf,
        /// The error inspecting its target.
        #[source]
        error: io::Error,
    },
}

/// Error planning the mounts of a profile.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PathPlanError {
    /// Two candidates with equal precedence map different sources to one
    /// sandbox path. Boxed to keep `PathPlanError` small.
    #[error(transparent)]
    Conflict(Box<MountConflict>),
    /// A restrictive rule's literal path, glob literal prefix or mount
    /// destination is or runs through a symlink below the workspace. Such a
    /// rule is never skipped: a planted link (e.g. a renamed directory
    /// replaced by a link to it) must not switch a restriction off.
    #[error(
        "provider {:?}, rule {:?}: {path:?} is or runs through the symlink {link:?} in the \
         workspace, which is never followed, and a {mode} rule is never skipped",
        .provider.as_str(),
        .pattern
    )]
    WorkspaceSymlink {
        /// The provider that granted the rule.
        provider: ProviderName,
        /// The rule's pattern as written; for a bind, its host path.
        pattern: String,
        /// The rule's mode.
        mode: PathMode,
        /// The host path that was to be mounted, or mounted over.
        path: PathBuf,
        /// The first symlink on the way to it (possibly `path` itself).
        link: PathBuf,
    },
    /// A restrictive rule's mount destination inside the workspace could not
    /// be checked for symlinks (e.g. a directory on the way is unreadable),
    /// so the rule can neither be applied safely nor skipped.
    #[error(
        "provider {:?}, rule {:?}: cannot check {path:?} for symlinks ({kind}), and a {mode} \
         rule is never skipped",
        .provider.as_str(),
        .pattern
    )]
    DestinationUnchecked {
        /// The provider that granted the rule.
        provider: ProviderName,
        /// The rule's pattern as written; for a bind, its host path.
        pattern: String,
        /// The rule's mode.
        mode: PathMode,
        /// The host path that could not be inspected.
        path: PathBuf,
        /// What went wrong inspecting it.
        kind: io::ErrorKind,
    },
    /// Resolving a restrictive rule failed on a path that exists but cannot
    /// be inspected, or a directory that cannot be read during a glob walk
    /// (or, for a `masked` `~` or absolute symlink, its target cannot be
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

/// One rule's proposal for one concrete sandbox path.
struct Candidate<'a> {
    sandbox: PathBuf,
    source: MountSource,
    mode: PathMode,
    /// Whether the rule was an exact path rather than a glob.
    literal: bool,
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
/// Symlinks: the literal part of a `{workspace}` rule (a literal path, or a
/// glob's literal prefix), and the host path under every winning mount
/// destination inside the workspace mount (including its final component),
/// must contain no symlink below the workspace. Otherwise a restrictive
/// rule is an error and an `rw` rule is dropped with a warning; a bind
/// whose host is or runs through such a symlink is always dropped with a
/// warning. A symlink matched by a `{workspace}` glob is dropped with a
/// warning whatever the mode, before the winner at its sandbox path is
/// picked. A missing destination is fine. A `masked` `~` or absolute rule
/// matching a symlink takes the kind of the link's target; it is dropped
/// with a warning if the target is missing, and is an error if the target
/// cannot be inspected otherwise.
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
        let winner = pick(candidates)?;
        if destination_is_safe(&winner, ctx, &mut warnings)? {
            mounts.push(winner.into_mount());
        }
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

/// Handles `rule` running into the symlink `link` below the workspace on
/// the way to `path`: an error if `refused` (the rule's mode, see
/// [`unskippable`]), otherwise a warning, the caller skipping the path.
fn workspace_symlink(
    rule: &FsRule,
    refused: Option<PathMode>,
    path: PathBuf,
    link: PathBuf,
    warnings: &mut Vec<PlanWarning>,
) -> Result<(), PathPlanError> {
    match refused {
        Some(mode) => Err(PathPlanError::WorkspaceSymlink {
            provider: rule.provider.clone(),
            pattern: rule_pattern(rule),
            mode,
            path,
            link,
        }),
        None => {
            warnings.push(plan_warning(
                rule,
                PlanWarningKind::WorkspaceSymlink { path, link },
            ));
            Ok(())
        }
    }
}

/// Expands and resolves one rule into its candidates, recording warnings.
fn rule_candidates<'a>(
    rule: &'a FsRule,
    ctx: &ExpansionContext,
    warnings: &mut Vec<PlanWarning>,
) -> Result<Vec<Candidate<'a>>, PathPlanError> {
    let candidate = |sandbox, source, mode, literal| Candidate {
        sandbox,
        source,
        mode,
        literal,
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
            )])
        }
        FsRuleKind::Path { mode, pattern } => {
            let expanded = expand_pattern(pattern, ctx);
            let literal = !expanded.has_glob();
            let in_workspace = expanded.anchor() == PatternAnchor::Workspace;
            let refused = unskippable(*mode);
            let paths = resolve_host(rule, pattern, &expanded, refused, warnings)?;
            let mut out = Vec::with_capacity(paths.len());
            for p in paths {
                // A literal path's final link is left as it is: its sandbox
                // path is inside the workspace mount, so the destination
                // check refuses it. A link matched by the glob is dropped
                // whatever the mode: the walk never follows links and
                // reaches the real files under their real names, so a
                // planted link cannot make the rule miss them. Dropping it
                // before the winner is picked never lets a weaker candidate
                // win: every `{workspace}` glob matching this sandbox path
                // matched the same link and is dropped alike, any literal
                // candidate outranks globs anyway, and any other glob
                // candidate left is refused by the destination check.
                if in_workspace && !literal && p.kind == EntryKind::Symlink {
                    workspace_symlink(rule, None, p.host.clone(), p.host, warnings)?;
                    continue;
                }
                let kind =
                    if *mode == PathMode::Masked && p.kind == EntryKind::Symlink && !in_workspace {
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
                ));
            }
            Ok(out)
        }
        FsRuleKind::Bind(bind) => {
            let pattern = bind.host.as_pattern();
            let expanded = expand_pattern(pattern, ctx);
            let sandbox = expand_bind(bind, ctx).sandbox;
            let in_workspace = expanded.anchor() == PatternAnchor::Workspace;
            // A bind's host side is a grant of host content wherever it is
            // mounted, so running into a symlink only skips it.
            let paths = resolve_host(rule, pattern, &expanded, None, warnings)?;
            let mut out = Vec::with_capacity(paths.len());
            for p in paths {
                if in_workspace && p.kind == EntryKind::Symlink {
                    // A bind mount would follow it.
                    workspace_symlink(rule, None, p.host.clone(), p.host, warnings)?;
                    continue;
                }
                out.push(candidate(
                    sandbox.clone(),
                    host_source(p.host, p.kind),
                    bind.mode.into(),
                    true,
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
/// warnings. A literal part running through a symlink below the workspace
/// (see [`workspace_symlink`]), and a path that cannot be inspected or read
/// for any reason but being missing, are errors if `refused` (the rule's
/// mode, see [`unskippable`]).
fn resolve_host(
    rule: &FsRule,
    pattern: &PathPattern,
    expanded: &ExpandedPattern,
    refused: Option<PathMode>,
    warnings: &mut Vec<PlanWarning>,
) -> Result<Vec<ResolvedPath>, PathPlanError> {
    let res = resolve(expanded).map_err(|error| PathPlanError::Expand {
        provider: rule.provider.clone(),
        pattern: pattern.clone(),
        error,
    })?;
    for w in res.warnings {
        match w {
            ResolveWarning::SymlinkInWorkspace { path, link } => {
                workspace_symlink(rule, refused, path, link, warnings)?
            }
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
    Ok(res.paths)
}

/// Checks the host path under the winning mount destination, if it is
/// inside the workspace mount, for symlinks below the workspace, including
/// its final component: bwrap would follow one when mounting, so a planted
/// link could move the mount elsewhere (e.g. a mask onto a decoy). Returns
/// whether the mount is kept; see [`workspace_symlink`] for a link found.
///
/// Links matched by a `{workspace}` glob were dropped before the winner was
/// picked, so a link found here comes from a literal rule, a bind or an
/// ephemeral destination, from a `~` or absolute glob whose sandbox path
/// lies inside the workspace mount, or from a link planted since the rule
/// was resolved; it is an error for every restrictive winner.
///
/// A missing destination (or one below a non-directory) has nothing to
/// follow and is fine. One that cannot be inspected is an error for a
/// restrictive mount and skips an `rw` one with a warning.
fn destination_is_safe(
    winner: &Candidate<'_>,
    ctx: &ExpansionContext,
    warnings: &mut Vec<PlanWarning>,
) -> Result<bool, PathPlanError> {
    // Known limitation (DESIGN.md §11): this inspects the workspace host
    // tree even when an ancestor sandbox path is itself a bind or ephemeral
    // mount, whose real host directory is then a different one.
    let Ok(rel) = winner.sandbox.strip_prefix(ctx.workspace_sandbox()) else {
        return Ok(true);
    };
    let refused = unskippable(winner.mode);
    match check_no_symlinks(ctx.workspace_host(), rel, true) {
        Ok(()) => Ok(true),
        Err(NoSymlinksError::Io { error, .. }) if is_missing(error.kind()) => Ok(true),
        Err(NoSymlinksError::Symlink { link }) => {
            let path = ctx.workspace_host().join(rel);
            workspace_symlink(winner.rule, refused, path, link, warnings)?;
            Ok(false)
        }
        Err(NoSymlinksError::Io { path, error }) => match refused {
            Some(mode) => Err(PathPlanError::DestinationUnchecked {
                provider: winner.rule.provider.clone(),
                pattern: rule_pattern(winner.rule),
                mode,
                path,
                kind: error.kind(),
            }),
            None => {
                warnings.push(plan_warning(
                    winner.rule,
                    ResolveWarning::Io { path, error }.into(),
                ));
                Ok(false)
            }
        },
    }
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

        /// The `(mode, path, link)` of a `WorkspaceSymlink` error, with the
        /// paths relative to the workspace.
        fn symlink_err(&self, rules: &[FsRule]) -> (PathMode, PathBuf, PathBuf) {
            match self.plan_err(rules) {
                PathPlanError::WorkspaceSymlink {
                    mode, path, link, ..
                } => (mode, self.rel(&path), self.rel(&link)),
                other => panic!("expected a WorkspaceSymlink error, got {other:?}"),
            }
        }

        /// The `(provider, path, link)` of each `WorkspaceSymlink` warning,
        /// with the paths relative to the workspace; panics on any other
        /// warning.
        fn symlink_warnings(&self, plan: &MountPlan) -> Vec<(String, PathBuf, PathBuf)> {
            plan.warnings
                .iter()
                .map(|w| match &w.kind {
                    PlanWarningKind::WorkspaceSymlink { path, link } => {
                        (w.provider.to_string(), self.rel(path), self.rel(link))
                    }
                    other => panic!("unexpected warning {other:?}"),
                })
                .collect()
        }

        fn rel(&self, path: &Path) -> PathBuf {
            path.strip_prefix(self.ws()).unwrap().to_owned()
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
        }
    }

    fn eph(sandbox: &str, p: &str) -> PlannedMount {
        PlannedMount {
            sandbox: sandbox.into(),
            source: MountSource::Ephemeral,
            mode: Ephemeral,
            provider: pn(p),
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
    fn masked_home_symlink_takes_the_kind_of_its_target() {
        let f = Fixture::new();
        f.file("home/file");
        f.mkdir("home/dir");
        f.symlink(f.home().join("file"), "home/filelink");
        f.symlink("dir", "home/dirlink");
        f.mkdir("home/sub");
        f.symlink("../file", "home/sub/glink");
        let abs = f.home().join("dirlink");
        let mounts = f.clean(&[
            rule(Masked, "~/filelink", "a", 0),
            rule(Masked, "~/dirlink", "a", 0),
            rule(Masked, abs.to_str().unwrap(), "a", 0),
            rule(Masked, "~/sub/*", "b", 0),
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
                (p("/home/user/dirlink"), EntryKind::Dir, Masked),
                (p("/home/user/filelink"), EntryKind::File, Masked),
                (p("/home/user/sub/glink"), EntryKind::File, Masked),
                (abs.clone(), EntryKind::Dir, Masked),
            ]
        );
        // The source is still the link as written.
        assert_eq!(
            mounts[2].source,
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
    fn bind_host_through_a_workspace_symlink_is_skipped_whatever_its_mode() {
        let f = Fixture::new();
        f.file("ws/real/x");
        f.file("outside/secret");
        f.symlink("real", "ws/via");
        f.symlink(f.root.join("outside"), "ws/out");
        f.symlink(f.root.join("outside/secret"), "ws/final");
        for mode in [BindMode::Ro, BindMode::Rw, BindMode::Protected] {
            let plan = f.plan(&[
                bind("{workspace}/via/x", "/opt/x", mode, "a", 0),
                bind("{workspace}/out/secret", "/opt/s", mode, "b", 0),
                bind("{workspace}/final", "/opt/f", mode, "c", 0),
            ]);
            assert!(plan.mounts.is_empty(), "{mode}: {:?}", plan.mounts);
            assert_eq!(
                f.symlink_warnings(&plan),
                [
                    ("a".into(), p("via/x"), p("via")),
                    ("b".into(), p("out/secret"), p("out")),
                    ("c".into(), p("final"), p("final")),
                ],
                "{mode}"
            );
        }
        let plan = f.plan(&[bind("{workspace}/via/x", "/opt/x", BindMode::Ro, "a", 0)]);
        let msg = plan.warnings[0].to_string();
        assert!(
            msg.starts_with(r#"provider "a", rule "{workspace}/via/x": "#),
            "{msg}"
        );
        assert!(msg.contains(&format!("{:?}", f.ws().join("via"))), "{msg}");
        assert!(msg.contains("never followed"), "{msg}");
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
    fn rw_workspace_symlinks_are_dropped_but_home_symlinks_kept() {
        let f = Fixture::new();
        f.file("ws/real/x");
        f.file("outside/secret");
        f.symlink("real", "ws/link");
        f.symlink(f.root.join("outside/secret"), "ws/.env");
        f.symlink(f.root.join("outside/secret"), "home/link");
        let plan = f.plan(&[
            rule(Rw, "{workspace}", "base", 0),
            rule(Rw, "{workspace}/link", "a", 0),
            rule(Rw, "{workspace}/link/x", "b", 0),
            rule(Rw, "{workspace}/**/.env", "c", 0),
            bind("{workspace}/link", "/opt/l", BindMode::Rw, "d", 0),
            rule(Ro, "~/link", "e", 0),
            bind("~/link", "/opt/h", BindMode::Ro, "f", 0),
        ]);
        assert_eq!(
            plan.mounts,
            vec![
                host("/workspace", f.ws(), EntryKind::Dir, Rw, "base"),
                host("/opt/h", f.home().join("link"), EntryKind::Symlink, Ro, "f"),
                host(
                    "/home/user/link",
                    f.home().join("link"),
                    EntryKind::Symlink,
                    Ro,
                    "e"
                ),
            ]
        );
        // Resolution warnings in rule order (including the glob-matched
        // link), then destination warnings in sandbox path order.
        assert_eq!(
            f.symlink_warnings(&plan),
            [
                ("b".into(), p("link/x"), p("link")),
                ("c".into(), p(".env"), p(".env")),
                ("d".into(), p("link"), p("link")),
                ("a".into(), p("link"), p("link")),
            ]
        );
        let msg = plan.warnings[3].to_string();
        assert!(msg.contains("symlink"), "{msg}");
        assert!(msg.contains("in the workspace"), "{msg}");
        assert!(msg.contains("never followed"), "{msg}");
    }

    #[test]
    fn restrictive_rules_over_workspace_symlinks_are_errors() {
        let f = Fixture::new();
        f.file("ws/real/x");
        f.file("ws/real/.env");
        f.symlink("real", "ws/link");
        f.symlink("nowhere", "ws/.env");
        for mode in [Masked, Protected, Ro, Ephemeral] {
            // The final component (left to the destination check) and a
            // parent component (found by resolution, or for ephemeral by the
            // destination check).
            for (pattern, path, link) in [
                ("{workspace}/link", "link", "link"),
                ("{workspace}/link/x", "link/x", "link"),
                (
                    "{workspace}/link/target/deeper",
                    "link/target/deeper",
                    "link",
                ),
            ] {
                let got = f.symlink_err(&[
                    rule(Rw, "{workspace}", "base", 0),
                    rule(mode, pattern, "p", 0),
                ]);
                assert_eq!(got, (mode, p(path), p(link)), "{mode} {pattern}");
            }
        }
        // A glob whose literal prefix runs through a link (a glob matching
        // a link is only a warning, see below).
        for mode in [Masked, Protected, Ro] {
            for (pattern, path) in [
                ("{workspace}/link/*", "link"),
                ("{workspace}/link/**/*.env", "link"),
                ("{workspace}/link/x/*", "link/x"),
            ] {
                let got = f.symlink_err(&[rule(mode, pattern, "p", 0)]);
                assert_eq!(got, (mode, p(path), p("link")), "{mode} {pattern}");
            }
        }
        let e = f.plan_err(&[rule(Masked, "{workspace}/link/x", "p", 0)]);
        assert_eq!(
            e,
            PathPlanError::WorkspaceSymlink {
                provider: pn("p"),
                pattern: "{workspace}/link/x".into(),
                mode: Masked,
                path: f.ws().join("link/x"),
                link: f.ws().join("link"),
            }
        );
        let msg = e.to_string();
        for part in [
            r#"provider "p", rule "{workspace}/link/x": "#.to_owned(),
            format!("{:?}", f.ws().join("link/x")),
            format!("{:?}", f.ws().join("link")),
            "never followed".to_owned(),
            "masked rule is never skipped".to_owned(),
        ] {
            assert!(msg.contains(&part), "{part}: {msg}");
        }
    }

    #[test]
    fn restrictive_glob_matching_a_link_skips_it_with_a_warning() {
        let f = Fixture::new();
        f.file("ws/bar.nix");
        f.file("ws/nix/real.nix");
        f.symlink("bar.nix", "ws/foo.nix");
        f.symlink("real.nix", "ws/nix/alias.nix");
        for mode in [Masked, Protected, Ro] {
            let plan = f.plan(&[
                rule(Rw, "{workspace}", "base", 0),
                rule(mode, "{workspace}/**/*.nix", "nix", 0),
            ]);
            // The links are not mounted; their targets are matched directly.
            assert_eq!(
                summary(&plan.mounts),
                [
                    row("/workspace", Rw, "base"),
                    row("/workspace/bar.nix", mode, "nix"),
                    row("/workspace/nix/real.nix", mode, "nix"),
                ],
                "{mode}"
            );
            assert_eq!(
                f.symlink_warnings(&plan),
                [
                    ("nix".into(), p("foo.nix"), p("foo.nix")),
                    ("nix".into(), p("nix/alias.nix"), p("nix/alias.nix")),
                ],
                "{mode}"
            );
        }
        // The same for a glob with a literal prefix and a final `*`.
        let plan = f.plan(&[rule(Masked, "{workspace}/nix/*", "nix", 0)]);
        assert_eq!(
            summary(&plan.mounts),
            [row("/workspace/nix/real.nix", Masked, "nix")]
        );
        assert_eq!(
            f.symlink_warnings(&plan),
            [("nix".into(), p("nix/alias.nix"), p("nix/alias.nix"))]
        );
        let msg = plan.warnings[0].to_string();
        assert!(
            msg.starts_with(r#"provider "nix", rule "{workspace}/nix/*": "#),
            "{msg}"
        );
        assert!(msg.contains("never followed"), "{msg}");
        assert!(msg.contains("write a rule for the link's target"), "{msg}");
    }

    #[test]
    fn renamed_dir_replaced_by_a_link_is_still_masked_through_a_glob() {
        let f = Fixture::new();
        f.file("ws/config2/prod.env");
        f.symlink("config2", "ws/config");
        // `**` does not descend into the link, and the link's own name does
        // not match, so there is nothing to warn about.
        let mounts = f.clean(&[
            rule(Rw, "{workspace}", "base", 0),
            rule(Masked, "{workspace}/**/*.env", "base", 0),
        ]);
        assert_eq!(
            summary(&mounts),
            [
                row("/workspace", Rw, "base"),
                row("/workspace/config2/prod.env", Masked, "base"),
            ]
        );
        // A bare `**` matches the link itself, which is skipped; the real
        // directory and its files are masked.
        let plan = f.plan(&[rule(Masked, "{workspace}/**", "base", 0)]);
        assert_eq!(
            summary(&plan.mounts),
            [
                row("/workspace/config2", Masked, "base"),
                row("/workspace/config2/prod.env", Masked, "base"),
            ]
        );
        assert_eq!(
            f.symlink_warnings(&plan),
            [("base".into(), p("config"), p("config"))]
        );
    }

    #[test]
    fn glob_matched_link_is_dropped_for_every_candidate() {
        let f = Fixture::new();
        f.file("ws/real.env");
        f.symlink("real.env", "ws/link.env");
        // An inherited rw glob and an own masked glob both match the link:
        // both are dropped, so neither wins and nothing is mounted there.
        let plan = f.plan(&[
            rule(Rw, "{workspace}/*.env", "parent", 1),
            rule(Masked, "{workspace}/*.env", "own", 0),
        ]);
        assert_eq!(
            summary(&plan.mounts),
            [row("/workspace/real.env", Masked, "own")]
        );
        assert_eq!(
            f.symlink_warnings(&plan),
            [
                ("parent".into(), p("link.env"), p("link.env")),
                ("own".into(), p("link.env"), p("link.env")),
            ]
        );
        // A literal rule at the link still outranks the glob, and its
        // destination check still refuses the link.
        let got = f.symlink_err(&[
            rule(Rw, "{workspace}/*.env", "a", 0),
            rule(Ro, "{workspace}/link.env", "b", 1),
        ]);
        assert_eq!(got, (Ro, p("link.env"), p("link.env")));
        let plan = f.plan(&[
            rule(Masked, "{workspace}/*.env", "a", 0),
            rule(Rw, "{workspace}/link.env", "b", 0),
        ]);
        assert_eq!(
            summary(&plan.mounts),
            [row("/workspace/real.env", Masked, "a")]
        );
        assert_eq!(
            f.symlink_warnings(&plan),
            [
                ("a".into(), p("link.env"), p("link.env")),
                ("b".into(), p("link.env"), p("link.env")),
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
    fn ephemeral_over_a_planted_link_is_an_error() {
        let f = Fixture::new();
        f.mkdir("ws/target2");
        f.symlink("target2", "ws/target");
        let got = f.symlink_err(&[rule(Ephemeral, "{workspace}/target", "rust", 0)]);
        assert_eq!(got, (Ephemeral, p("target"), p("target")));
        f.mkdir("ws/real");
        f.symlink("real", "ws/sub");
        let got = f.symlink_err(&[rule(Ephemeral, "{workspace}/sub/target", "rust", 0)]);
        assert_eq!(got, (Ephemeral, p("sub/target"), p("sub")));
        // An absolute ephemeral path inside the workspace mount is checked
        // too.
        let got = f.symlink_err(&[rule(Ephemeral, "/workspace/sub/x", "p", 0)]);
        assert_eq!(got, (Ephemeral, p("sub/x"), p("sub")));
    }

    #[test]
    fn bind_destination_through_a_workspace_link() {
        let f = Fixture::new();
        f.file("home/cfg");
        f.mkdir("ws/decoy");
        f.symlink("decoy", "ws/cfg");
        f.symlink("decoy", "ws/dir");
        for (dest, path, link) in [
            ("/workspace/cfg", "cfg", "cfg"),
            ("/workspace/dir/cfg", "dir/cfg", "dir"),
        ] {
            for mode in [BindMode::Ro, BindMode::Protected] {
                let got = f.symlink_err(&[bind("~/cfg", dest, mode, "p", 0)]);
                assert_eq!(got, (mode.into(), p(path), p(link)), "{dest} {mode}");
            }
            let plan = f.plan(&[bind("~/cfg", dest, BindMode::Rw, "p", 0)]);
            assert!(plan.mounts.is_empty(), "{:?}", plan.mounts);
            assert_eq!(
                f.symlink_warnings(&plan),
                [("p".into(), p(path), p(link))],
                "{dest}"
            );
        }
        // A missing destination is fine, and one outside the workspace
        // mount is not checked.
        let mounts = f.clean(&[
            bind("~/cfg", "/workspace/new/cfg", BindMode::Ro, "p", 0),
            bind("~/cfg", "/workspacex/cfg", BindMode::Ro, "p", 0),
        ]);
        assert_eq!(
            summary(&mounts),
            [
                row("/workspacex/cfg", Ro, "p"),
                row("/workspace/new/cfg", Ro, "p"),
            ]
        );
    }

    #[test]
    fn home_rule_inside_a_workspace_mounted_under_home_is_checked() {
        let f = Fixture::with_mount("/home/user/proj");
        f.file("home/proj/cfg");
        f.file("home/proj/new");
        f.file("home/proj/real");
        f.file("ws/real");
        f.mkdir("ws/decoy");
        f.symlink("decoy", "ws/cfg");
        // `~/proj/cfg` mounts over `/home/user/proj/cfg`, which bwrap reaches
        // through the workspace mount, i.e. through the link `ws/cfg`.
        for mode in [Masked, Protected, Ro] {
            let got = f.symlink_err(&[
                rule(Rw, "{workspace}", "base", 0),
                rule(mode, "~/proj/cfg", "p", 0),
            ]);
            assert_eq!(got, (mode, p("cfg"), p("cfg")), "{mode}");
        }
        let plan = f.plan(&[rule(Rw, "~/proj/cfg", "p", 0)]);
        assert!(plan.mounts.is_empty(), "{:?}", plan.mounts);
        assert_eq!(
            f.symlink_warnings(&plan),
            [("p".into(), p("cfg"), p("cfg"))]
        );
        // A destination missing from the workspace, or a real file there,
        // is fine; `~` itself lies outside the workspace mount.
        let mounts = f.clean(&[
            rule(Ro, "~", "p", 0),
            rule(Rw, "{workspace}", "p", 0),
            rule(Masked, "~/proj/new", "p", 0),
            rule(Masked, "~/proj/real", "p", 0),
        ]);
        assert_eq!(
            summary(&mounts),
            [
                row("/home/user", Ro, "p"),
                row("/home/user/proj", Rw, "p"),
                row("/home/user/proj/new", Masked, "p"),
                row("/home/user/proj/real", Masked, "p"),
            ]
        );
    }

    #[test]
    fn destination_symlink_is_decided_by_the_winning_mode() {
        let f = Fixture::new();
        f.file("home/cfg");
        f.symlink("nowhere", "ws/cfg");
        // The masked rule wins over the ro bind, so the link is an error.
        let got = f.symlink_err(&[
            rule(Masked, "{workspace}/cfg", "a", 0),
            bind("~/cfg", "/workspace/cfg", BindMode::Ro, "b", 0),
        ]);
        assert_eq!(got, (Masked, p("cfg"), p("cfg")));
        // An own rw rule beats the inherited mask: the winner is dropped
        // with a warning, and nothing is mounted there.
        let plan = f.plan(&[
            rule(Masked, "{workspace}/cfg", "a", 1),
            rule(Rw, "{workspace}/cfg", "b", 0),
        ]);
        assert!(plan.mounts.is_empty(), "{:?}", plan.mounts);
        assert_eq!(
            f.symlink_warnings(&plan),
            [("b".into(), p("cfg"), p("cfg"))]
        );
    }

    #[test]
    fn destination_that_cannot_be_inspected() {
        use std::os::unix::fs::PermissionsExt;
        if rustix::process::geteuid().is_root() {
            eprintln!("skipping: permission checks do not apply to root");
            return;
        }
        let f = Fixture::new();
        f.file("home/x");
        f.mkdir("ws/locked/sub");
        let locked = f.ws().join("locked");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        let err = plan_mounts(&[rule(Ephemeral, "{workspace}/locked/sub", "p", 0)], &f.ctx);
        let warned = plan_mounts(
            &[bind("~/x", "/workspace/locked/sub/x", BindMode::Rw, "q", 0)],
            &f.ctx,
        );
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
        let e = err.unwrap_err();
        assert_eq!(
            e,
            PathPlanError::DestinationUnchecked {
                provider: pn("p"),
                pattern: "{workspace}/locked/sub".into(),
                mode: Ephemeral,
                path: f.ws().join("locked/sub"),
                kind: io::ErrorKind::PermissionDenied,
            }
        );
        let msg = e.to_string();
        assert!(msg.contains("cannot check"), "{msg}");
        assert!(msg.contains("ephemeral rule is never skipped"), "{msg}");
        let plan = warned.unwrap();
        assert!(plan.mounts.is_empty(), "{:?}", plan.mounts);
        assert!(
            matches!(
                plan.warnings.as_slice(),
                [PlanWarning {
                    kind: PlanWarningKind::Resolve(ResolveWarning::Io { error, .. }),
                    ..
                }] if error.kind() == io::ErrorKind::PermissionDenied
            ),
            "{:?}",
            plan.warnings
        );
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
