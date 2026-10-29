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
//! missing path) is not skipped: the sandbox could `chmod 000` a directory
//! it owns to switch a mask off at the next start. Instead the directory
//! that cannot be searched or read is masked as a whole (DESIGN.md §1.5),
//! which hides everything the rule could have applied to there, and more.
//! Such a synthesized mask outranks every other candidate at its sandbox
//! path. That includes `chmod a-x`: a glob walk lists the entries of a
//! directory that can be read but not searched without inspecting them, so
//! every match of a restrictive glob is inspected.
//!
//! Redundant nested mounts (a child with the same mode as its parent and the
//! host content the parent already shows) are kept; pruning them is a
//! possible optimisation.

use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use thiserror::Error;

use super::merge::{FsRule, FsRuleKind};
use crate::config::ProviderName;
use crate::error::is_missing;
use crate::escape::shell_quote;
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
    /// host source. Its backing directory is named by `key`.
    Ephemeral {
        /// Names the session's backing directory, shared by every sandbox.
        key: EphemeralKey,
    },
}

impl MountSource {
    /// Whether two rules of equal precedence at one sandbox path may share
    /// it without conflict: the same source, or any two ephemeral ones,
    /// since every ephemeral source is empty at startup. Which key the mount
    /// then keeps is the first rule's (an ephemeral tie, see [`pick`]), so it
    /// depends on rule order.
    fn interchangeable(&self, other: &MountSource) -> bool {
        match (self, other) {
            (MountSource::Ephemeral { .. }, MountSource::Ephemeral { .. }) => true,
            _ => self == other,
        }
    }
}

impl fmt::Display for MountSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MountSource::Host { path, .. } => write!(f, "{path:?}"),
            MountSource::Ephemeral { .. } => f.write_str("an ephemeral directory"),
        }
    }
}

/// Identifies the session-wide backing directory of an `ephemeral` rule: the
/// rule's pattern as written, before `~` or `{workspace}` expansion
/// (`/tmp`, `~`, `{workspace}/target`).
///
/// Every sandbox of a session shares one backing directory per key, so `~`
/// is the same directory in profiles with different `system.home`; an
/// absolute pattern keeps a profile's HOME separate. An ephemeral rule is
/// never a glob, so the pattern names exactly one path.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EphemeralKey(String);

impl EphemeralKey {
    /// The longest pattern, in bytes, whose directory name is its hex
    /// encoding; longer ones are named by a hash (see [`Self::dir_name`]).
    const MAX_HEX_PATTERN: usize = 100;

    /// The key of an ephemeral rule's `pattern`.
    pub fn new(pattern: &PathPattern) -> EphemeralKey {
        EphemeralKey(pattern.as_str().to_owned())
    }

    /// The pattern as written.
    #[cfg(test)]
    fn pattern(&self) -> &str {
        &self.0
    }

    /// The name of the key's backing directory under the session's
    /// `ephemeral/`: a single path component that is safe to create there
    /// (no `/`, no NUL, never `.` or `..`), deterministic, and at most 200
    /// bytes.
    ///
    /// A pattern of up to [`Self::MAX_HEX_PATTERN`] bytes is named by the
    /// lowercase hex of its bytes, which is injective. A longer one is named
    /// `h-` plus the 128-bit FNV-1a hash of its bytes in hex (34 bytes); the
    /// `-` cannot occur in a hex name, so the two forms never collide, and
    /// two distinct long patterns collide only by a hash collision (see
    /// [`fnv1a_128`]).
    pub fn dir_name(&self) -> String {
        let bytes = self.0.as_bytes();
        if bytes.len() <= Self::MAX_HEX_PATTERN {
            return bytes.iter().map(|b| format!("{b:02x}")).collect();
        }
        format!("h-{:032x}", fnv1a_128(bytes))
    }
}

/// The 128-bit FNV-1a hash of `bytes`.
///
/// Not collision-resistant against adversaries, which is fine here: only
/// the config's authors choose ephemeral patterns, and they gain nothing by
/// making two of them share a directory.
fn fnv1a_128(bytes: &[u8]) -> u128 {
    const OFFSET: u128 = 0x6c62_272e_07bb_0142_62b8_2175_6295_c58d;
    const PRIME: u128 = 0x0000_0000_0100_0000_0000_0000_0000_013b;
    bytes
        .iter()
        .fold(OFFSET, |h, &b| (h ^ u128::from(b)).wrapping_mul(PRIME))
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
    /// A restrictive rule (any mode but `rw`) could not inspect `path` (a
    /// directory on the way to it cannot be searched, or a glob walk cannot
    /// read it). A restrictive rule is never skipped, so the directory
    /// `dir` is masked instead: the deepest directory on the way that can
    /// be inspected, or the directory the walk cannot read. That hides
    /// everything in it, including whatever the rule would have applied to
    /// there, which is stricter than the rule (DESIGN.md §1.5).
    #[error(
        "cannot inspect {path:?} ({error}), and a {mode} rule is never skipped, so the directory \
         {dir:?} is masked at {sandbox:?} instead, hiding everything in it"
    )]
    InaccessibleMasked {
        /// The rule's mode.
        mode: PathMode,
        /// The host path that could not be inspected or read.
        path: PathBuf,
        /// The error inspecting or reading it.
        #[source]
        error: io::Error,
        /// The host directory masked, as written in the rule.
        dir: PathBuf,
        /// Where `dir` is masked in the sandbox.
        sandbox: PathBuf,
    },
    /// A mask synthesized over a directory a restrictive rule could not
    /// inspect ([`PlanWarningKind::InaccessibleMasked`]) outranks this
    /// rule's mount at the same sandbox path, so the grant is hidden
    /// entirely this session. Louder than the masking itself: with the
    /// workspace made unsearchable (`chmod 000`), say, the workspace mount
    /// is an empty directory.
    #[error("{}", hidden_note(*.workspace, *.mode, .sandbox, .dir))]
    GrantHidden {
        /// The hidden rule's mode.
        mode: PathMode,
        /// The sandbox path of the hidden mount, where the mask is.
        sandbox: PathBuf,
        /// The host directory that could not be inspected and is masked.
        dir: PathBuf,
        /// Whether `sandbox` is the workspace mount.
        workspace: bool,
    },
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

/// The message for a mount of a grant (`mode` at `sandbox`) hidden entirely
/// by a mask over the host directory `dir`, which cannot be inspected
/// (DESIGN.md §1.5): says what is lost this session and how to fix it.
/// `workspace` if `sandbox` is the workspace mount.
pub(crate) fn hidden_note(workspace: bool, mode: PathMode, sandbox: &Path, dir: &Path) -> String {
    let what = if workspace {
        format!("the workspace is hidden this session: its {mode} mount at {sandbox:?}")
    } else {
        format!("this {mode} grant is hidden this session: its mount at {sandbox:?}")
    };
    format!(
        "{what} is replaced by an empty masked directory, because {dir:?} cannot be inspected (a \
         sandbox may have removed its permissions); restore them (e.g. `chmod u+rwx {}`) to get \
         it back",
        shell_quote(dir.as_os_str().as_bytes())
    )
}

/// Error planning the mounts of a profile.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PathPlanError {
    /// Two candidates with equal precedence map different sources to one
    /// sandbox path. Boxed to keep `PathPlanError` small.
    #[error(transparent)]
    Conflict(Box<MountConflict>),
    /// A literal `masked` symlink's target exists but cannot be inspected,
    /// so the mask's shape (an empty file or an empty directory) is unknown,
    /// and a masked rule is never skipped. (Other paths a restrictive rule
    /// cannot inspect mask the directory that cannot be searched or read
    /// instead, [`PlanWarningKind::InaccessibleMasked`]; this is also the
    /// defensive fallback should that directory not be found.)
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
    /// Whether this is a mask synthesized over a directory a restrictive
    /// rule could not inspect ([`PlanWarningKind::InaccessibleMasked`]).
    synthesized: bool,
    rule: &'a FsRule,
}

impl Candidate<'_> {
    /// Precedence; greater wins (§3.5 rules 1–3 at one sandbox path).
    ///
    /// A synthesized mask outranks everything: it stands in for restrictive
    /// rules below its path that cannot be applied, so a less strict
    /// candidate winning there would lift them.
    fn rank(&self) -> (bool, bool, Reverse<u32>, PathMode) {
        (
            self.synthesized,
            self.literal,
            Reverse(self.rule.depth),
            self.mode,
        )
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
/// is skipped with a warning for an `rw` rule. A restrictive rule (any mode
/// but `rw`) is never skipped: the directory that cannot be searched or
/// read is masked instead, with a warning
/// ([`PlanWarningKind::InaccessibleMasked`]), and the rest of a glob's
/// matches still apply. Every match of a restrictive glob is inspected, so
/// that the entries the walk lists in a directory that can be read but not
/// searched mask it too. That mask outranks every other candidate at its
/// sandbox path, and one that hides a rule's mount there entirely (the
/// workspace mount, say) is reported louder
/// ([`PlanWarningKind::GrantHidden`]); mounts below it are kept (they show other host content,
/// since nothing below an unsearchable directory can be resolved, as they
/// would below any masked directory). A bind's host side is resolved like a
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
        mounts.push(pick(candidates, ctx, &mut warnings)?.into_mount());
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
        synthesized: false,
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
                MountSource::Ephemeral {
                    key: EphemeralKey::new(pattern),
                },
                PathMode::Ephemeral,
                true,
                false,
            )])
        }
        FsRuleKind::Path { mode, pattern } => {
            let expanded = expand_pattern(pattern, ctx);
            let literal = !expanded.has_glob();
            let refused = unskippable(*mode);
            let Some(HostResolution { paths, masks }) =
                resolve_host(rule, pattern, &expanded, refused, ctx, warnings)?
            else {
                return Ok(Vec::new());
            };
            let mut out = Vec::with_capacity(paths.len() + masks.len());
            for d in masks {
                out.push(Candidate {
                    synthesized: true,
                    ..candidate(
                        d.sandbox,
                        host_source(d.host, d.kind),
                        PathMode::Masked,
                        true,
                        false,
                    )
                });
            }
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
            let Some(HostResolution { paths, masks }) =
                resolve_host(rule, pattern, &expanded, None, ctx, warnings)?
            else {
                return Ok(Vec::new());
            };
            debug_assert!(masks.is_empty(), "only restrictive rules synthesize masks");
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

/// What [`resolve_host`] found for a rule.
struct HostResolution {
    /// The matching paths.
    paths: Vec<ResolvedPath>,
    /// The directories to mask because a restrictive rule could not inspect
    /// something on the way or read them (see [`unreadable_dir`]).
    masks: Vec<ResolvedPath>,
}

/// Resolves `expanded` (the expansion of `rule`'s `pattern`), recording its
/// warnings. A path that cannot be inspected or read for any reason but
/// being missing is skipped with a warning, unless `refused` (the rule's
/// mode, see [`unskippable`]): then the directory that cannot be searched
/// or read is to be masked instead ([`HostResolution::masks`], see
/// [`unreadable_dir`]), with a warning.
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
) -> Result<Option<HostResolution>, PathPlanError> {
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
    let mut masks = Vec::new();
    // Masks the directory a restrictive rule cannot inspect `path` below,
    // once per directory (a directory that can be read but not searched
    // fails every entry below it), with a warning.
    let mut mask = |mode, path: PathBuf, error: io::Error, warnings: &mut Vec<PlanWarning>| {
        let Some(dir) = unreadable_dir(expanded, &path) else {
            return Err(PathPlanError::Inaccessible {
                provider: rule.provider.clone(),
                pattern: rule_pattern(rule),
                mode,
                path,
                kind: error.kind(),
            });
        };
        if masks.iter().any(|m: &ResolvedPath| m.host == dir.host) {
            return Ok(());
        }
        warnings.push(plan_warning(
            rule,
            PlanWarningKind::InaccessibleMasked {
                mode,
                path,
                error,
                dir: dir.host.clone(),
                sandbox: dir.sandbox.clone(),
            },
        ));
        masks.push(dir);
        Ok(())
    };
    for w in res.warnings {
        match w {
            // The resolver reports a missing path, including an entry that
            // vanished during a glob walk, as `Missing`, so this is
            // anything else (e.g. `EACCES`).
            ResolveWarning::Io { path, error } => match refused {
                Some(mode) => mask(mode, path, error, warnings)?,
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
    let mut paths = res.paths;
    // A glob walk takes its matches' kinds from the directory listing, which
    // needs read permission only: the entries of a directory that can be
    // read but not searched (`chmod a-x`) are listed, but cannot be
    // inspected or mounted. So every match of a restrictive glob is
    // inspected, and one that cannot be is handled like a directory the
    // walk cannot read (a literal path has been inspected already).
    if let (Some(mode), true) = (refused, expanded.has_glob()) {
        let mut kept = Vec::with_capacity(paths.len());
        for p in paths {
            match p.host.symlink_metadata() {
                Ok(_) => kept.push(p),
                Err(error) if is_missing(error.kind()) => warnings.push(plan_warning(
                    rule,
                    ResolveWarning::Missing { path: p.host }.into(),
                )),
                Err(error) => mask(mode, p.host, error, warnings)?,
            }
        }
        paths = kept;
    }
    Ok(Some(HostResolution { paths, masks }))
}

/// The directory to mask when a restrictive rule cannot inspect `path`, a
/// host path (as written) at or below `expanded`'s host anchor, and where
/// it appears in the sandbox.
///
/// That is the deepest directory on the way to `path`, as written, that can
/// itself be inspected: the next component cannot, so this directory
/// cannot be searched (or, for a host symlink on the way, what it leads to
/// cannot be resolved). If `path` itself can be inspected (a directory a
/// glob walk could not read), it is `path`. Either way it is a directory
/// position on the way to everything the rule could match below it, so
/// masking it as an empty directory hides all of that, and more: stricter
/// than the rule, never less strict. If nothing below the anchor can be
/// inspected, the anchor itself is masked.
///
/// `None` if `path` is not below the anchor, or if a component is now
/// missing (the layout changed during resolution): the caller fails closed.
fn unreadable_dir(expanded: &ExpandedPattern, path: &Path) -> Option<ResolvedPath> {
    let anchor = expanded.host_anchor();
    let rel = path.strip_prefix(anchor).ok()?;
    let mut dir = anchor.to_owned();
    let mut depth = 0;
    for c in rel.components() {
        let next = dir.join(c);
        match next.symlink_metadata() {
            Ok(_) => {
                dir = next;
                depth += 1;
            }
            Err(error) if is_missing(error.kind()) => return None,
            Err(_) => break,
        }
    }
    let rel: PathBuf = rel.components().take(depth).collect();
    let sandbox = if rel.as_os_str().is_empty() {
        expanded.sandbox_anchor().to_owned()
    } else {
        expanded.sandbox_anchor().join(rel)
    };
    Some(ResolvedPath {
        host: dir,
        sandbox,
        kind: EntryKind::Dir,
    })
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
///
/// A synthesized mask that wins over a rule showing something at the same
/// path (any mode but `masked`) hides that rule's mount entirely, which
/// [`PlanWarningKind::GrantHidden`] reports (the workspace mount, say, when
/// a sandbox made the workspace itself unsearchable).
fn pick<'a>(
    candidates: Vec<Candidate<'a>>,
    ctx: &ExpansionContext,
    warnings: &mut Vec<PlanWarning>,
) -> Result<Candidate<'a>, PathPlanError> {
    let best = candidates
        .iter()
        .map(Candidate::rank)
        .max()
        .expect("every sandbox path has at least one candidate");
    // Synthesized masks show an empty directory whatever their source (two
    // anchors may name different host paths at one sandbox path), so they
    // never conflict: the first of the best stands for all.
    if best.0 {
        let mut winner = None;
        let mut hidden = Vec::new();
        for c in candidates {
            if c.rank() == best {
                winner.get_or_insert(c);
            } else if !c.synthesized && c.mode != PathMode::Masked {
                hidden.push(c);
            }
        }
        let winner = winner.expect("the best rank is attained");
        let MountSource::Host { path: dir, .. } = &winner.source else {
            unreachable!("a synthesized mask has a host source");
        };
        for c in hidden {
            let workspace = c.sandbox == ctx.workspace_sandbox();
            warnings.push(plan_warning(
                c.rule,
                PlanWarningKind::GrantHidden {
                    mode: c.mode,
                    sandbox: c.sandbox,
                    dir: dir.clone(),
                    workspace,
                },
            ));
        }
        return Ok(winner);
    }
    // Ephemeral ties (`~` and `/home/user`) never conflict: the first wins.
    let top: Vec<Candidate<'a>> = candidates
        .into_iter()
        .filter(|c| c.rank() == best)
        .collect();
    if best.3 == PathMode::Ephemeral {
        return Ok(top.into_iter().next().expect("the best rank is attained"));
    }
    let first_source = &top.first().expect("the best rank is attained").source;
    if top.iter().all(|c| c.source.interchangeable(first_source)) {
        return Ok(top.into_iter().next().expect("the best rank is attained"));
    }
    // Sources that differ at the same `(synthesized, literal, depth, mode)`
    // go to the highest `ProviderOrigin`, so a workspace `fs.bind` can
    // replace a global one at the same destination and mode. Two binds in
    // the winning layer still conflict.
    let max_origin = top
        .iter()
        .map(|c| c.rule.origin)
        .max()
        .expect("the best rank is attained");
    let mut top = top.into_iter().filter(|c| c.rule.origin == max_origin);
    let winner = top.next().expect("max_origin is attained");
    if let Some(other) = top.find(|c| !c.source.interchangeable(&winner.source)) {
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
            origin: crate::config::ProviderOrigin::Workspace,
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
            origin: crate::config::ProviderOrigin::Workspace,
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

    /// An ephemeral mount whose rule was written as `pattern`.
    fn eph(sandbox: &str, pattern: &str, p: &str) -> PlannedMount {
        PlannedMount {
            sandbox: sandbox.into(),
            source: MountSource::Ephemeral {
                key: EphemeralKey::new(&pattern.parse().unwrap()),
            },
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
            MountSource::Ephemeral { .. } => panic!("unexpected ephemeral mount"),
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
                eph("/tmp", "/tmp", "base"),
                eph("/home/user", "~", "base"),
                eph("/workspace/target", "{workspace}/target", "rust"),
                eph(
                    "/stopit-test/does/not/exist",
                    "/stopit-test/does/not/exist",
                    "base"
                ),
            ]
        );
    }

    #[test]
    fn ephemeral_competes_by_precedence() {
        let f = Fixture::new();
        // Same depth: ephemeral is stricter than rw, looser than ro.
        let mounts = f.clean(&[rule(Rw, "~", "a", 0), rule(Ephemeral, "~", "b", 0)]);
        assert_eq!(mounts, vec![eph("/home/user", "~", "b")]);
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
        assert_eq!(
            mounts,
            vec![eph("/workspace/target", "{workspace}/target", "b")]
        );
    }

    #[test]
    fn ephemeral_rules_at_one_path_keep_the_first_rules_key() {
        let f = Fixture::new();
        // `~` and `/home/user` are one sandbox path with different keys: no
        // conflict, and the first rule's key stands for both.
        let mounts = f.clean(&[
            rule(Ephemeral, "~", "a", 0),
            rule(Ephemeral, "/home/user", "b", 0),
        ]);
        assert_eq!(mounts, vec![eph("/home/user", "~", "a")]);
        let mounts = f.clean(&[
            rule(Ephemeral, "/home/user", "b", 0),
            rule(Ephemeral, "~", "a", 0),
        ]);
        assert_eq!(mounts, vec![eph("/home/user", "/home/user", "b")]);
        // A profile's own absolute rule beats an inherited `~` and keeps its
        // own key, so its HOME is separate from the inherited one's.
        let mounts = f.clean(&[
            rule(Ephemeral, "~", "parent", 1),
            rule(Ephemeral, "/home/user", "own", 0),
        ]);
        assert_eq!(mounts, vec![eph("/home/user", "/home/user", "own")]);
    }

    #[test]
    fn fnv1a_128_known_answers() {
        assert_eq!(fnv1a_128(b""), 0x6c62272e07bb014262b821756295c58d);
        assert_eq!(fnv1a_128(b"a"), 0xd228cb696f1a8caf78912b704e4a8964);
    }

    #[test]
    fn ephemeral_key_names_are_safe_and_distinct() {
        let key = |s: &str| EphemeralKey::new(&PathPattern::new_unchecked(s));
        assert_eq!(key("~").dir_name(), "7e");
        assert_eq!(key("/tmp").dir_name(), "2f746d70");
        assert_eq!(key("~").pattern(), "~");
        let long = format!("/{}", "a".repeat(EphemeralKey::MAX_HEX_PATTERN - 1));
        assert_eq!(
            key(&long).dir_name().len(),
            2 * EphemeralKey::MAX_HEX_PATTERN
        );
        let patterns = [
            "~",
            "/tmp",
            // `"/tmp/"`, `"/."` and `"/.."` are invalid patterns, included
            // for robustness.
            "/tmp/",
            "/Tmp",
            "{workspace}/target",
            "{workspace}",
            "~/.cache/x",
            "~/.cache_x",
            "/.",
            "/..",
            "/a/b",
            "/a\\b",
            "/é",
            "/e\u{301}",
            "/\u{1F980}",
            "/\n",
            &long,
            &format!("{long}b"),
            &format!("{long}c"),
            &format!("/{}", "a".repeat(5000)),
            &format!("/{}", "a".repeat(5001)),
        ];
        let mut seen = std::collections::HashSet::new();
        for p in patterns {
            let name = key(p).dir_name();
            assert_eq!(name, key(p).dir_name(), "{p:?} is deterministic");
            assert!(
                !name.is_empty() && name.len() <= 200,
                "{p:?} -> {} bytes",
                name.len()
            );
            assert!(
                name.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                "{p:?} -> {name:?}"
            );
            assert!(name != "." && name != "..");
            assert!(seen.insert(name.clone()), "{p:?} collides: {name:?}");
        }
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
    fn a_higher_layer_bind_replaces_a_lower_one_at_the_same_rank() {
        use crate::config::ProviderOrigin::{Builtin, Global, Workspace};

        let at = |mut r: FsRule, origin| {
            r.origin = origin;
            r
        };
        let f = Fixture::new();
        f.file("home/a");
        f.file("home/b");
        f.file("home/c");
        // Whatever the order, the workspace layer's bind wins.
        for rules in [
            [
                at(bind("~/a", "/opt/x", BindMode::Ro, "g", 0), Global),
                at(bind("~/b", "/opt/x", BindMode::Ro, "w", 0), Workspace),
            ],
            [
                at(bind("~/b", "/opt/x", BindMode::Ro, "w", 0), Workspace),
                at(bind("~/a", "/opt/x", BindMode::Ro, "g", 0), Global),
            ],
        ] {
            let mounts = f.clean(&rules);
            assert_eq!(
                mounts,
                [host("/opt/x", f.home().join("b"), EntryKind::File, Ro, "w")]
            );
        }
        // The global layer beats the built-in one.
        let mounts = f.clean(&[
            at(bind("~/a", "/opt/x", BindMode::Ro, "b", 0), Builtin),
            at(bind("~/c", "/opt/x", BindMode::Ro, "g", 0), Global),
        ]);
        assert_eq!(summary(&mounts), [row("/opt/x", Ro, "g")]);
        // The layer only breaks ties: a stricter mode from a lower layer
        // still wins, and so does a profile's own rule over an inherited one.
        let mounts = f.clean(&[
            at(bind("~/a", "/opt/x", BindMode::Protected, "g", 0), Global),
            at(bind("~/b", "/opt/x", BindMode::Ro, "w", 0), Workspace),
        ]);
        assert_eq!(summary(&mounts), [row("/opt/x", Protected, "g")]);
        let mounts = f.clean(&[
            at(bind("~/a", "/opt/x", BindMode::Ro, "g", 0), Global),
            at(bind("~/b", "/opt/x", BindMode::Ro, "w", 1), Workspace),
        ]);
        assert_eq!(summary(&mounts), [row("/opt/x", Ro, "g")]);
        // Two binds within the winning layer still conflict.
        let e = f.plan_err(&[
            at(bind("~/a", "/opt/x", BindMode::Ro, "g", 0), Global),
            at(bind("~/b", "/opt/x", BindMode::Ro, "w1", 0), Workspace),
            at(bind("~/c", "/opt/x", BindMode::Ro, "w2", 0), Workspace),
        ]);
        let PathPlanError::Conflict(c) = e else {
            panic!("expected a conflict, got {e:?}");
        };
        assert_eq!(
            (c.first_provider.as_str(), c.second_provider.as_str()),
            ("w1", "w2")
        );
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
                eph("/tmp", "/tmp", "a"),
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
        with_mode(f, rels, 0o000, body)
    }

    /// Like [`with_locked`], with the directories set to `mode`. They are
    /// restored even if `body` panics, so that the temp dir can be removed.
    fn with_mode<T>(f: &Fixture, rels: &[&str], mode: u32, body: impl FnOnce() -> T) -> Option<T> {
        use std::os::unix::fs::PermissionsExt;
        struct Restore(Vec<PathBuf>);
        impl Drop for Restore {
            fn drop(&mut self) {
                for dir in &self.0 {
                    let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o755));
                }
            }
        }
        if rustix::process::geteuid().is_root() {
            eprintln!("skipping: permission checks do not apply to root");
            return None;
        }
        let dirs: Vec<PathBuf> = rels.iter().map(|rel| f.root.join(rel)).collect();
        let _restore = Restore(dirs.clone());
        for dir in &dirs {
            fs::set_permissions(dir, fs::Permissions::from_mode(mode)).unwrap();
        }
        Some(body())
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

    /// Each `InaccessibleMasked` warning of `plan` as `(provider, mode, path,
    /// error kind, dir, sandbox)`; skips `GrantHidden` ones (see
    /// [`hidden_grants`]) and panics on any other warning.
    #[allow(clippy::type_complexity)]
    fn masked_instead(
        plan: &MountPlan,
    ) -> Vec<(String, PathMode, PathBuf, io::ErrorKind, PathBuf, PathBuf)> {
        plan.warnings
            .iter()
            .filter_map(|w| match &w.kind {
                PlanWarningKind::InaccessibleMasked {
                    mode,
                    path,
                    error,
                    dir,
                    sandbox,
                } => Some((
                    w.provider.to_string(),
                    *mode,
                    path.clone(),
                    error.kind(),
                    dir.clone(),
                    sandbox.clone(),
                )),
                PlanWarningKind::GrantHidden { .. } => None,
                other => panic!("unexpected warning {other:?}"),
            })
            .collect()
    }

    /// Each `GrantHidden` warning of `plan` as `(provider, rule, mode,
    /// sandbox, dir, workspace)`.
    #[allow(clippy::type_complexity)]
    fn hidden_grants(plan: &MountPlan) -> Vec<(String, String, PathMode, PathBuf, PathBuf, bool)> {
        plan.warnings
            .iter()
            .filter_map(|w| match &w.kind {
                PlanWarningKind::GrantHidden {
                    mode,
                    sandbox,
                    dir,
                    workspace,
                } => Some((
                    w.provider.to_string(),
                    w.pattern.clone(),
                    *mode,
                    sandbox.clone(),
                    dir.clone(),
                    *workspace,
                )),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn unreadable_paths_mask_the_directory_under_restrictive_rules() {
        let f = Fixture::new();
        f.file("ws/a/.env");
        f.file("ws/locked/.env");
        f.file("home/locked/secret");
        f.symlink(f.home().join("locked/secret"), "home/link");
        let locked = f.ws().join("locked");
        let home_locked = f.home().join("locked");
        // Each pattern with the path it cannot inspect (a directory the walk
        // cannot read, or a literal path below an unsearchable directory),
        // the directory masked instead and where, and the other match the
        // walk still finds.
        let cases = [
            (
                "{workspace}/**/.env",
                locked.clone(),
                locked.clone(),
                "/workspace/locked",
                Some("a/.env"),
            ),
            (
                "{workspace}/locked/.env",
                locked.join(".env"),
                locked.clone(),
                "/workspace/locked",
                None,
            ),
            (
                "{workspace}/locked/*",
                locked.clone(),
                locked.clone(),
                "/workspace/locked",
                None,
            ),
            (
                "~/locked/secret",
                home_locked.join("secret"),
                home_locked.clone(),
                "/home/user/locked",
                None,
            ),
            (
                "~/locked/**",
                home_locked.clone(),
                home_locked.clone(),
                "/home/user/locked",
                None,
            ),
        ];
        let modes = [Masked, Protected, Ro];
        let Some((plans, link, warned)) = with_locked(&f, &["ws/locked", "home/locked"], || {
            let mut plans = Vec::new();
            for mode in modes {
                for (pattern, ..) in &cases {
                    plans.push(plan_mounts(&[rule(mode, pattern, "p", 0)], &f.ctx));
                }
            }
            // A masked `~` link whose target cannot be inspected.
            let link = plan_mounts(&[rule(Masked, "~/link", "p", 0)], &f.ctx);
            let warned = plan_mounts(
                &[
                    rule(Rw, "{workspace}/**/.env", "a", 0),
                    rule(Rw, "~/locked/secret", "b", 0),
                    bind("{workspace}/locked/.env", "/opt/e", BindMode::Ro, "c", 0),
                ],
                &f.ctx,
            );
            (plans, link, warned)
        }) else {
            return;
        };
        let mut plans = plans.into_iter();
        for mode in modes {
            for (pattern, path, dir, sandbox, other) in &cases {
                let plan = plans
                    .next()
                    .unwrap()
                    .unwrap_or_else(|e| panic!("{mode} {pattern}: {e}"));
                let mut want = vec![host(sandbox, dir.clone(), EntryKind::Dir, Masked, "p")];
                if let Some(other) = other {
                    want.push(host(
                        &format!("/workspace/{other}"),
                        f.ws().join(other),
                        EntryKind::File,
                        mode,
                        "p",
                    ));
                }
                assert_eq!(plan.mounts, want, "{mode} {pattern}");
                assert_eq!(
                    masked_instead(&plan),
                    [(
                        "p".to_owned(),
                        mode,
                        path.clone(),
                        io::ErrorKind::PermissionDenied,
                        dir.clone(),
                        PathBuf::from(sandbox),
                    )],
                    "{mode} {pattern}"
                );
                let PlanWarningKind::InaccessibleMasked { error, .. } = &plan.warnings[0].kind
                else {
                    unreachable!("checked above");
                };
                assert_eq!(
                    plan.warnings[0].to_string(),
                    format!(
                        "provider \"p\", rule \"{pattern}\": cannot inspect {path:?} ({error}), \
                         and a {mode} rule is never skipped, so the directory {dir:?} is masked \
                         at \"{sandbox}\" instead, hiding everything in it"
                    ),
                    "{mode} {pattern}"
                );
            }
        }
        // A masked link whose target cannot be inspected has no known shape,
        // and stays an error.
        let e = link.unwrap_err();
        let msg = e.to_string();
        assert_eq!(
            inaccessible(e),
            (
                Masked,
                f.home().join("link"),
                io::ErrorKind::PermissionDenied
            )
        );
        assert!(msg.contains("masked rule is never skipped"), "{msg}");
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
    fn masks_of_unreadable_directories_outrank_every_candidate() {
        let f = Fixture::new();
        f.file("ws/locked/.env");
        f.file("home/x");
        let locked = f.ws().join("locked");
        let Some(plan) = with_locked(&f, &["ws/locked"], || {
            f.plan(&[
                rule(Rw, "{workspace}", "base", 1),
                // An own literal grant of the directory itself loses.
                rule(Rw, "{workspace}/locked", "own", 0),
                rule(Ro, "{workspace}/**/.env", "env", 1),
                // A second rule masking the same directory collapses into
                // one mount, credited by the usual precedence (an own rule
                // beats an inherited one).
                rule(Masked, "{workspace}/locked/.env", "lit", 0),
                // Mounts below it are kept: they show other content.
                bind("~/x", "/workspace/locked/x", BindMode::Ro, "b", 0),
                rule(Ephemeral, "{workspace}/locked/tmp", "e", 0),
            ])
        }) else {
            return;
        };
        assert_eq!(
            plan.mounts,
            vec![
                host("/workspace", f.ws(), EntryKind::Dir, Rw, "base"),
                host(
                    "/workspace/locked",
                    locked.clone(),
                    EntryKind::Dir,
                    Masked,
                    "lit"
                ),
                eph("/workspace/locked/tmp", "{workspace}/locked/tmp", "e"),
                host(
                    "/workspace/locked/x",
                    f.home().join("x"),
                    EntryKind::File,
                    Ro,
                    "b"
                ),
            ]
        );
        let denied = io::ErrorKind::PermissionDenied;
        let sandbox = p("/workspace/locked");
        assert_eq!(
            masked_instead(&plan),
            [
                (
                    "env".to_owned(),
                    Ro,
                    locked.clone(),
                    denied,
                    locked.clone(),
                    sandbox.clone()
                ),
                (
                    "lit".to_owned(),
                    Masked,
                    locked.join(".env"),
                    denied,
                    locked.clone(),
                    sandbox.clone()
                ),
            ]
        );
        // The grant it replaced is reported, louder.
        assert_eq!(
            hidden_grants(&plan),
            [(
                "own".to_owned(),
                "{workspace}/locked".to_owned(),
                Rw,
                sandbox,
                locked.clone(),
                false
            )]
        );
        let hidden = plan
            .warnings
            .iter()
            .find(|w| matches!(w.kind, PlanWarningKind::GrantHidden { .. }))
            .unwrap();
        assert_eq!(
            hidden.to_string(),
            format!(
                "provider \"own\", rule \"{{workspace}}/locked\": this rw grant is hidden this \
                 session: its mount at \"/workspace/locked\" is replaced by an empty masked \
                 directory, because {locked:?} cannot be inspected (a sandbox may have removed \
                 its permissions); restore them (e.g. `chmod u+rwx {}`) to get it back",
                locked.display()
            )
        );
    }

    #[test]
    fn an_unsearchable_workspace_hides_the_workspace_mount_loudly() {
        // A sandbox made the workspace itself unsearchable (`chmod 000`, or
        // `chmod 600`: readable but not searchable). The workspace rules
        // mask it as a whole, replacing the workspace mount, which is
        // reported as such.
        for mode in [0o000, 0o600] {
            let f = Fixture::new();
            f.file("ws/flake.nix");
            f.file("ws/.env");
            let Some(plan) = with_mode(&f, &["ws"], mode, || {
                f.plan(&[
                    rule(Rw, "{workspace}", "base", 0),
                    rule(Masked, "{workspace}/**/.env", "base", 0),
                    rule(Protected, "{workspace}/**/*.nix", "base", 0),
                    rule(Protected, "{workspace}/flake.lock", "base", 0),
                ])
            }) else {
                return;
            };
            assert_eq!(
                plan.mounts,
                vec![host("/workspace", f.ws(), EntryKind::Dir, Masked, "base")],
                "{mode:o}"
            );
            // Every restrictive rule masks the workspace once.
            let dirs: Vec<_> = masked_instead(&plan)
                .into_iter()
                .map(|(_, mode, _, _, dir, sandbox)| (mode, dir, sandbox))
                .collect();
            assert_eq!(
                dirs,
                [Masked, Protected, Protected].map(|m| (m, f.ws(), p("/workspace"))),
                "{mode:o}"
            );
            assert_eq!(
                hidden_grants(&plan),
                [(
                    "base".to_owned(),
                    "{workspace}".to_owned(),
                    Rw,
                    p("/workspace"),
                    f.ws(),
                    true
                )],
                "{mode:o}"
            );
            let hidden = plan
                .warnings
                .iter()
                .find(|w| matches!(w.kind, PlanWarningKind::GrantHidden { .. }))
                .unwrap();
            assert_eq!(
                hidden.to_string(),
                format!(
                    "provider \"base\", rule \"{{workspace}}\": the workspace is hidden this \
                     session: its rw mount at \"/workspace\" is replaced by an empty masked \
                     directory, because {:?} cannot be inspected (a sandbox may have removed its \
                     permissions); restore them (e.g. `chmod u+rwx {}`) to get it back",
                    f.ws(),
                    f.ws().display()
                ),
                "{mode:o}"
            );
        }
    }

    #[test]
    fn entries_of_a_readable_but_unsearchable_directory_mask_it() {
        // `chmod 600`: the walk lists the directory's entries (from the
        // listing alone), but none can be inspected or mounted. Each
        // restrictive glob masks the directory once, rather than mounting
        // its entries.
        let f = Fixture::new();
        f.file("ws/d/foo.nix");
        f.file("ws/d/bar.nix");
        f.file("ws/d/sub/baz.nix");
        f.file("ws/top.nix");
        let d = f.ws().join("d");
        let Some(plan) = with_mode(&f, &["ws/d"], 0o600, || {
            f.plan(&[
                rule(Rw, "{workspace}", "base", 0),
                rule(Protected, "{workspace}/**/*.nix", "base", 0),
            ])
        }) else {
            return;
        };
        assert_eq!(
            plan.mounts,
            vec![
                host("/workspace", f.ws(), EntryKind::Dir, Rw, "base"),
                host("/workspace/d", d.clone(), EntryKind::Dir, Masked, "base"),
                host(
                    "/workspace/top.nix",
                    f.ws().join("top.nix"),
                    EntryKind::File,
                    Protected,
                    "base"
                ),
            ]
        );
        match masked_instead(&plan).as_slice() {
            [(provider, Protected, path, kind, dir, sandbox)] => {
                assert_eq!(provider, "base");
                assert!(path.starts_with(&d) && *path != d, "{path:?}");
                assert_eq!(*kind, io::ErrorKind::PermissionDenied);
                assert_eq!((dir, sandbox.as_path()), (&d, Path::new("/workspace/d")));
            }
            other => panic!("unexpected warnings {other:?}"),
        }
        assert!(hidden_grants(&plan).is_empty());
    }

    #[test]
    fn an_unsearchable_anchor_is_masked_itself() {
        let f = Fixture::new();
        f.file("home/x");
        let Some(plan) = with_locked(&f, &["home"], || f.plan(&[rule(Ro, "~/x", "p", 0)])) else {
            return;
        };
        assert_eq!(
            plan.mounts,
            vec![host("/home/user", f.home(), EntryKind::Dir, Masked, "p")]
        );
        assert_eq!(
            masked_instead(&plan),
            [(
                "p".to_owned(),
                Ro,
                f.home().join("x"),
                io::ErrorKind::PermissionDenied,
                f.home(),
                p("/home/user"),
            )]
        );
    }

    #[test]
    fn a_link_loop_on_the_way_is_masked_under_restrictive_rules() {
        // A loop cannot be inspected either: the link on the way is masked
        // as a directory (the spec compiler refuses it if it lies inside an
        // untrusted root). An `rw` rule is skipped, and a masked rule for
        // the loop itself has no shape and stays an error.
        let f = Fixture::new();
        f.symlink("loop", "home/loop");
        let eloop = io::Error::from_raw_os_error(rustix::io::Errno::LOOP.raw_os_error()).kind();
        let plan = f.plan(&[rule(Ro, "~/loop/x", "p", 0), rule(Rw, "~/loop/y", "q", 0)]);
        assert_eq!(
            plan.mounts,
            vec![host(
                "/home/user/loop",
                f.home().join("loop"),
                EntryKind::Dir,
                Masked,
                "p"
            )]
        );
        match plan.warnings.as_slice() {
            [
                PlanWarning {
                    provider: p1,
                    kind:
                        PlanWarningKind::InaccessibleMasked {
                            mode: Ro,
                            path: masked_path,
                            error: masked_error,
                            dir,
                            sandbox,
                        },
                    ..
                },
                PlanWarning {
                    provider: p2,
                    kind: PlanWarningKind::Resolve(ResolveWarning::Io { path, error }),
                    ..
                },
            ] => {
                assert_eq!((p1.as_str(), p2.as_str()), ("p", "q"));
                assert_eq!(
                    (masked_path, masked_error.kind(), dir, sandbox.as_path()),
                    (
                        &f.home().join("loop/x"),
                        eloop,
                        &f.home().join("loop"),
                        Path::new("/home/user/loop")
                    )
                );
                assert_eq!((path, error.kind()), (&f.home().join("loop/y"), eloop));
            }
            other => panic!("unexpected warnings {other:?}"),
        }
        assert_eq!(
            inaccessible(f.plan_err(&[rule(Masked, "~/loop", "p", 0)])),
            (Masked, f.home().join("loop"), eloop)
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
            origin: crate::config::ProviderOrigin::Workspace,
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
