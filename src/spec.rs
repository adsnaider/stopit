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
//! profile.
//!
//! Each profile's workspace mount point and sandbox `HOME` are checked
//! against the reserved-path rules (§6.2) before any mounts are planned;
//! the planned mounts' destinations are checked against them afterwards.
//! Once every profile is planned, each profile's glob-matched links inside
//! the session's untrusted roots are skipped, its destinations are checked
//! for links into those roots on the way through the mount underneath them,
//! and its host sources against those roots (§3.4, Symlinks; §6.2,
//! "Untrusted links"), against the host workspace (§6.2, "Workspace
//! exposure") and against the profile's masked and protected mounts (§6.2,
//! "Restricted content exposure"). Then the paths providers asked to be
//! protected (script providers' sources, §3.6) are protected wherever the
//! profile would let the sandbox write them. Last, every mount's host source
//! is checked against stopit's own state directories (§6.2, "Reserved host
//! paths").

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use rustix::io::Errno;
use thiserror::Error;

use crate::config::{Config, ProfileRef, ProviderName};
use crate::error::is_missing;
use crate::expand::{EntryKind, ExpansionContext, expand_bind, expand_pattern};
use crate::manifest::{
    BindMode, DevMode, Domain, EtcFile, OptInSyscall, SandboxHome, ShareableNamespace, ShimName,
    ShimSpec,
};
use crate::policy::{NetworkMode, PathMode};
use crate::provider::{ProtectedSource, ProviderOutput, SUPERVISOR_PROVIDER_NAME};
use crate::resolve::{
    EffectiveEnv, EffectiveGrants, EffectiveNetwork, MergeError, MountPlan, MountSource,
    PathPlanError, PlanWarning, PlannedMount, ProfileError, build_profile_graph, hidden_note,
    merge_profiles, plan_mounts,
};
use crate::state::{StateDir, StateDirs};

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
    /// The environment policy, as merged. [`SandboxSpec::target_env`] applies
    /// it to a host environment (§9).
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
    /// An `rw` mount was skipped because its destination would be reached
    /// through a symlink inside an untrusted root (DESIGN.md §6.2,
    /// "Untrusted links"). Dropping a grant only removes access.
    #[error(
        "{0}; a sandbox can write there and bwrap follows links when mounting, so the rw mount is \
         skipped"
    )]
    DestinationLink(Box<DestinationLink>),
    /// An `rw` mount was skipped because its destination could not be
    /// checked for symlinks (a path on the way exists but cannot be
    /// inspected).
    #[error(
        "provider {:?}: rw mount at {sandbox:?} skipped: cannot check its destination for \
         symlinks, inspecting {path:?} failed: {error}",
        .provider.as_str()
    )]
    DestinationUnchecked {
        /// The provider whose rule produced the mount.
        provider: ProviderName,
        /// The mount's sandbox destination.
        sandbox: PathBuf,
        /// The host path that could not be inspected.
        path: PathBuf,
        /// The error inspecting it.
        #[source]
        error: io::Error,
    },
    /// A restrictive mount's destination could not be checked for symlinks
    /// (a directory on the way cannot be searched), so that directory is
    /// masked as a whole, and the mount is kept on top of the mask (DESIGN.md
    /// §1.5, §6.2, "Untrusted links").
    #[error(transparent)]
    DestinationMasked(Box<DestinationMasked>),
    /// A mask synthesized for a [`SpecWarning::DestinationMasked`] lies at
    /// the sandbox path of the mount underneath (that mount's own source
    /// cannot be searched), so it replaces that mount: the whole grant (the
    /// workspace mount, say) is hidden this session.
    #[error(transparent)]
    GrantHidden(Box<GrantHidden>),
    /// A mount was skipped because its host source cannot be resolved: for
    /// any mode, a final symlink whose target is missing (there is nothing
    /// to show or hide, as for a missing path), and for an `rw` mount any
    /// failure (dropping a grant only removes access). A restrictive mount
    /// whose source cannot be resolved otherwise is an error
    /// ([`SpecError::HostSourceUnresolved`]), unless it lies inside a masked
    /// directory ([`SpecWarning::SourceUnderMask`]).
    #[error("{0}, so the mount is skipped")]
    SourceUnresolved(Box<SourceUnresolved>),
    /// A restrictive mount was skipped because its host source cannot be
    /// inspected (not because it is missing, nor after following a link
    /// inside an untrusted root) and it lies inside a masked directory of
    /// the profile, at the second path: the mask hides everything there,
    /// which is stricter than the mount. A synthesized mask over a
    /// directory that cannot be searched does that (DESIGN.md §1.5).
    #[error(
        "{0}; it lies inside the directory masked at {1:?}, which hides everything there, so the \
         mount is skipped"
    )]
    SourceUnderMask(Box<SourceUnresolved>, PathBuf),
    /// A `masked` mount's host source cannot be resolved to a canonical path
    /// (it changed after planning, or it is a directory masked because a
    /// restrictive rule could not inspect below it, reached through a host
    /// symlink whose target cannot be resolved). The mask needs no host
    /// content and its shape was decided while planning, so it is kept,
    /// but whether the content it covers is visible at another sandbox path
    /// is not checked for it (DESIGN.md §6.2, "Restricted content
    /// exposure").
    #[error(
        "{0}; the mask is kept, but whether the content it covers is visible at another sandbox \
         path is not checked"
    )]
    MaskSourceUnresolved(Box<SourceUnresolved>),
    /// An `rw` mount was skipped because its host source runs through a
    /// symlink inside an untrusted root (DESIGN.md §3.4, Symlinks; §6.2,
    /// "Untrusted links"); a restrictive one is an error
    /// ([`SpecError::UntrustedLinkFollowed`]). Dropping a grant only
    /// removes access.
    #[error(
        "{0}; a sandbox can write there, so links inside it are never followed, and the rw \
         mount is skipped"
    )]
    SourceLink(Box<LinkFollowed>),
    /// A path matched by a glob rule is a symlink inside an untrusted root,
    /// so the match is skipped whatever the rule's mode (DESIGN.md §3.4,
    /// Symlinks).
    #[error(transparent)]
    GlobLink(Box<GlobLink>),
    /// A mount shows host content that a `masked` mount of the profile
    /// covers, or lets the sandbox write content that a `protected` mount
    /// covers, at another sandbox path, where that restriction does not
    /// apply (DESIGN.md §6.2, "Restricted content exposure"), so stopit
    /// covers it there too, with a `masked` or `protected` mount of that
    /// content added to the spec (DESIGN.md §1.5). Not an error: such
    /// content is commonly host-controlled (a home-manager file masked at
    /// `~/.config/foo` whose `/nix/store` target is mounted too), and the
    /// warning names where it was shown and how to fix the configuration.
    #[error(transparent)]
    RestrictedContentExposed(Box<Exposure>),
    /// A `masked` or `protected` rule matches the host workspace itself
    /// (`~/Projects/*` masked while the workspace is `~/Projects/stopit`),
    /// which the workspace mount shows at another sandbox path. The
    /// workspace's identity wins (DESIGN.md §6.2, "Restricted content
    /// exposure"): the workspace mount is never covered, and the rule
    /// applies only at its own path; restricted content inside the
    /// workspace is still covered at the workspace mount.
    #[error(transparent)]
    WorkspaceRestricted(Box<WorkspaceRestricted>),
    /// A mount's host source reaches, through a host symlink, into content
    /// a `masked` mount of the profile hides (or a `protected` one, for an
    /// `rw` mount), although the source as written lies outside it. A
    /// grant strictly inside restricted content is the more specific rule
    /// and is not covered (DESIGN.md §3.5), but the user may not realize
    /// that it lies under the restriction.
    #[error(transparent)]
    LinkedIntoRestricted(Box<LinkedIntoRestricted>),
    /// An `rw` mount's host source lies strictly inside a directory a
    /// provider asked to be protected (a script provider's source, DESIGN.md
    /// §3.6), so the mount is protected instead: no grant can lift that
    /// protection.
    #[error(transparent)]
    InsideProtectedSource(Box<InsideProtectedSource>),
    /// A read-only (or `protected`) mount's host source contains stopit's
    /// session runtime directory, which holds other sessions' sockets and
    /// ephemeral data, so stopit masks that directory where the mount shows
    /// it (DESIGN.md §6.2, "Reserved host paths").
    #[error(transparent)]
    RuntimeDirMasked(Box<RuntimeDirMasked>),
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
    /// The workspace mount or the sandbox `HOME` collides with a path
    /// stopit mounts itself, or with each other (§6.2, "Reserved paths").
    #[error("{which} {path:?} {reason}")]
    ReservedPath {
        /// Which of the two paths is at fault.
        which: PathRole,
        /// The offending path.
        path: PathBuf,
        /// The rule it breaks.
        reason: ReservedReason,
    },
    /// A planned mount's destination collides with a path stopit sets up
    /// itself (§6.2, "Reserved paths").
    #[error(
        "provider {:?}: mount destination {path:?} {reason}",
        .provider.as_str()
    )]
    ReservedMount {
        /// The provider whose rule produced the mount.
        provider: ProviderName,
        /// The mount's sandbox destination.
        path: PathBuf,
        /// What it collides with.
        reason: ReservedReason,
    },
    /// A mount's host source contains the host workspace, or lies inside it
    /// but is mounted away from the workspace mount, so it would show
    /// workspace files at a second sandbox path (§6.2, "Workspace
    /// exposure"): the workspace must appear only at its mount, where its
    /// restrictions, pinned parents and the supervisor's workspace-relative
    /// checks apply.
    #[error(
        "provider {:?}: {mode} mount of {host:?}{} at {sandbox:?} exposes the host workspace \
         {workspace:?} outside the workspace mount; the workspace must appear only at its mount, \
         where its restrictions, pinned parents and the supervisor's checks apply; grant \
         narrower paths that leave the workspace out, mask this one, or reach these files through \
         the workspace mount",
        .provider.as_str(),
        resolved_note(.host, .resolved)
    )]
    WorkspaceExposed {
        /// The provider whose rule produced the mount.
        provider: ProviderName,
        /// The mount's mode.
        mode: PathMode,
        /// The mount's host source, as planned.
        host: PathBuf,
        /// `host` with every symlink resolved.
        resolved: PathBuf,
        /// The mount's sandbox destination.
        sandbox: PathBuf,
        /// The host workspace.
        workspace: PathBuf,
    },
    /// A `masked` glob matched a symlink outside every untrusted root (one
    /// the host controls) whose target cannot be inspected, so whether to
    /// mask it as an empty file or an empty directory is unknown, and a
    /// masked rule is never skipped. (A literal rule fails the same way
    /// while planning, [`PathPlanError::Inaccessible`]; a glob match is
    /// decided here, since one inside an untrusted root is skipped with
    /// [`SpecWarning::GlobLink`] without looking at its target.)
    #[error(
        "provider {:?}: the masked glob match {host:?} at {sandbox:?} is a symlink whose target \
         cannot be inspected ({kind}), so its shape is unknown, and a masked rule is never skipped",
        .provider.as_str()
    )]
    MaskTargetUninspectable {
        /// The provider whose rule matched the link.
        provider: ProviderName,
        /// The matched link's host path, as planned.
        host: PathBuf,
        /// The mount's sandbox destination.
        sandbox: PathBuf,
        /// What went wrong inspecting the target.
        kind: io::ErrorKind,
    },
    /// A restrictive mount's host source runs through a symlink inside an
    /// untrusted root, a host directory some sandbox of the session can
    /// write (§3.4, Symlinks; §6.2, "Untrusted links"); an `rw` one is
    /// skipped with [`SpecWarning::SourceLink`] instead. Boxed to keep
    /// `SpecError` small.
    #[error(
        "{0}; a sandbox can write there, so links inside it are never followed, whatever the \
         rule's anchor or the links leading there: remove the link or change the rule"
    )]
    UntrustedLinkFollowed(Box<LinkFollowed>),
    /// A restrictive mount's host source could not be resolved to a
    /// canonical path, so whether it exposes the host workspace or follows a
    /// link the sandbox may have planted cannot be checked. This is a final
    /// symlink outside every untrusted root whose target exists but cannot
    /// be inspected (a loop, a directory that cannot be searched): the shape
    /// of a mask over it would be unknown. A missing target, or an `rw`
    /// mount, is skipped with [`SpecWarning::SourceUnresolved`] instead, a
    /// mount inside a masked directory with [`SpecWarning::SourceUnderMask`],
    /// and a lookup that followed a link inside an untrusted root first is
    /// [`SpecError::UntrustedLinkFollowed`].
    #[error(
        "provider {:?}: cannot resolve the host source {host:?} of the {mode} mount at \
         {sandbox:?} ({kind}) to check that it neither exposes the host workspace nor follows a \
         symlink a sandbox can write",
        .provider.as_str()
    )]
    HostSourceUnresolved {
        /// The provider whose rule produced the mount.
        provider: ProviderName,
        /// The mount's mode.
        mode: PathMode,
        /// The mount's host source, as planned.
        host: PathBuf,
        /// The mount's sandbox destination.
        sandbox: PathBuf,
        /// What went wrong resolving it.
        kind: io::ErrorKind,
    },
    /// A restrictive mount's destination would be reached through a symlink
    /// inside an untrusted root (§6.2, "Untrusted links"); an `rw` one is
    /// skipped with [`SpecWarning::DestinationLink`] instead. Boxed to keep
    /// `SpecError` small.
    #[error(
        "{0}; a sandbox can write there and bwrap follows links when mounting, so the mount \
         would land elsewhere, and a {mode} mount is never skipped: remove the link or change \
         the rule",
        mode = .0.mode
    )]
    DestinationLinkFollowed(Box<DestinationLink>),
    /// A mount's host source is, or lies inside, one of stopit's own state
    /// directories, or is a writable mount containing one (§6.2, "Reserved
    /// host paths"). Boxed to keep `SpecError` small.
    #[error(transparent)]
    ReservedHostSource(Box<ReservedHostSource>),
}

/// A restrictive mount's destination could not be checked for symlinks: a
/// path on the way, below the mount underneath it, exists but cannot be
/// inspected, because the directory containing it cannot be searched. A
/// restrictive mount is never skipped, so that directory is masked as a
/// whole (an empty read-only directory, which bwrap reaches without passing
/// through it), and the mount is kept on top of the mask, where nothing
/// needs checking (DESIGN.md §1.5; §6.2, "Untrusted links"). That is
/// stricter than the configuration: everything else in the directory is
/// hidden too.
#[derive(Debug, Error)]
#[error(
    "provider {:?}: cannot check the destination {sandbox:?} of the {mode} mount for symlinks: \
     inspecting {path:?} failed: {error}; a {mode} mount is never skipped, so the directory \
     {masked_host:?} is masked at {masked:?}, hiding everything in it, and the mount is kept on top",
    .provider.as_str()
)]
pub struct DestinationMasked {
    /// The provider whose rule produced the mount.
    pub provider: ProviderName,
    /// The mount's mode.
    pub mode: PathMode,
    /// The mount's sandbox destination.
    pub sandbox: PathBuf,
    /// The host path that could not be inspected.
    pub path: PathBuf,
    /// The error inspecting it.
    #[source]
    pub error: io::Error,
    /// The sandbox path of the directory masked.
    pub masked: PathBuf,
    /// The host directory masked there (canonical): the directory
    /// containing `path`.
    pub masked_host: PathBuf,
}

/// A mount replaced by a mask over a directory that cannot be searched (see
/// [`SpecWarning::GrantHidden`]).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error(
    "provider {:?}: {}",
    .provider.as_str(),
    hidden_note(*.workspace, *.mode, .sandbox, .dir)
)]
pub struct GrantHidden {
    /// The provider whose rule produced the hidden mount.
    pub provider: ProviderName,
    /// The hidden mount's mode.
    pub mode: PathMode,
    /// The hidden mount's sandbox path, where the mask is.
    pub sandbox: PathBuf,
    /// The host directory masked there (canonical), which cannot be
    /// searched.
    pub dir: PathBuf,
    /// Whether `sandbox` is the workspace mount.
    pub workspace: bool,
}

/// A mount's host source cannot be resolved to a canonical path (see
/// [`SpecWarning::SourceUnresolved`], [`SpecWarning::SourceUnderMask`] and
/// [`SpecWarning::MaskSourceUnresolved`]).
#[derive(Debug, Error)]
#[error(
    "provider {:?}: cannot resolve the host source {host:?} of the {mode} mount at {sandbox:?}: \
     {error}{}",
    .provider.as_str(),
    via_note(.link)
)]
pub struct SourceUnresolved {
    /// The provider whose rule produced the mount.
    pub provider: ProviderName,
    /// The mount's mode.
    pub mode: PathMode,
    /// The mount's host source, as planned.
    pub host: PathBuf,
    /// The mount's sandbox destination.
    pub sandbox: PathBuf,
    /// The first symlink inside an untrusted root the lookup followed
    /// before it failed (named below its canonical parent directory), and
    /// that root: a planted dangling link, say.
    pub link: Option<(PathBuf, UntrustedRoot)>,
    /// What went wrong resolving it.
    #[source]
    pub error: io::Error,
}

/// A mount's host source runs through a symlink inside an untrusted root, a
/// host directory some sandbox of the session can write, where the link may
/// have been planted to redirect the grant to any host path (§3.4,
/// Symlinks). This holds however the source reaches the root: written
/// inside it, or through symlinks outside it that lead there. For a
/// `masked` mount the link would decide the mask's shape (an empty file or
/// an empty directory), which a planted link must not either.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error(
    "provider {:?}: {mode} mount of {host:?} at {sandbox:?} runs through the symlink {link:?} \
     inside {root} (resolving to {resolved:?})",
    .provider.as_str()
)]
pub struct LinkFollowed {
    /// The provider whose rule produced the mount.
    pub provider: ProviderName,
    /// The mount's mode.
    pub mode: PathMode,
    /// The mount's host source, as planned.
    pub host: PathBuf,
    /// The first symlink inside an untrusted root that resolving `host`
    /// follows, named below its canonical parent directory.
    pub link: PathBuf,
    /// `host` with every symlink resolved; if the lookup fails after
    /// following `link`, the path it failed at.
    pub resolved: PathBuf,
    /// The mount's sandbox destination.
    pub sandbox: PathBuf,
    /// The untrusted root `link` lies in (the innermost one, see
    /// [`UntrustedRoot`]).
    pub root: UntrustedRoot,
}

/// A mount's sandbox destination lies inside an earlier mount (its nearest
/// ancestor in the plan), and the host path bwrap would traverse there to
/// reach the destination runs through a symlink inside an untrusted root.
/// bwrap follows links when it resolves a destination, so a planted link
/// would move the mount elsewhere: a mask or a read-only mount onto a
/// decoy, leaving the real path as it was, or any mount on top of another
/// one (DESIGN.md §6.2, "Untrusted links").
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error(
    "provider {:?}: the {mode} mount at {sandbox:?} lies inside the {ancestor_mode} mount at \
     {ancestor:?} of {ancestor_source:?}, where reaching it means following the symlink {link:?} \
     (on the way to {host:?}) inside {root}",
    .provider.as_str()
)]
pub struct DestinationLink {
    /// The provider whose rule produced the mount.
    pub provider: ProviderName,
    /// The mount's mode.
    pub mode: PathMode,
    /// The mount's sandbox destination.
    pub sandbox: PathBuf,
    /// The host path under the destination: the ancestor's canonical
    /// source joined with the destination's path below the ancestor.
    pub host: PathBuf,
    /// The first symlink on the way to `host` (possibly `host` itself),
    /// named below its canonical parent directory.
    pub link: PathBuf,
    /// The sandbox path of the ancestor mount.
    pub ancestor: PathBuf,
    /// The ancestor mount's mode.
    pub ancestor_mode: PathMode,
    /// The ancestor mount's host source, resolved to its canonical path.
    pub ancestor_source: PathBuf,
    /// The untrusted root `link` lies in (the innermost one).
    pub root: UntrustedRoot,
}

/// A path matched by a glob rule is a symlink inside an untrusted root, so
/// a sandbox may have planted it (DESIGN.md §3.4, Symlinks). The match is
/// skipped whatever the rule's mode: the glob walk never follows links and
/// reaches the real files under their own names, so a planted link can
/// neither redirect the rule nor make it miss them.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error(
    "provider {:?}: the {mode} glob match {host:?} at {sandbox:?} is the symlink {link:?} inside \
     {root}; a sandbox can write there, so links inside it are never followed, and the match is \
     skipped (write a rule for the link's target if it needs one)",
    .provider.as_str()
)]
pub struct GlobLink {
    /// The provider whose rule matched the link.
    pub provider: ProviderName,
    /// The rule's mode.
    pub mode: PathMode,
    /// The matched host path, as planned.
    pub host: PathBuf,
    /// The link, named below its canonical parent directory.
    pub link: PathBuf,
    /// The sandbox path the match would have been mounted at.
    pub sandbox: PathBuf,
    /// The untrusted root `link` lies in (the innermost one).
    pub root: UntrustedRoot,
}

/// A mount shows host content that a `masked` mount of the same profile
/// covers, or shows writable content that a `protected` mount covers, at a
/// sandbox path where that restriction does not apply (DESIGN.md §6.2,
/// "Restricted content exposure"), so stopit covers it there with a mount
/// of mode [`Exposure::covered`]. Masks and protected files apply to
/// sandbox paths, not to host content. Only a grant of the restricted
/// content itself or of an ancestor counts: one strictly inside it is a
/// more specific grant (DESIGN.md §3.5).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error(
    "provider {:?}: {mode} mount of {host:?}{} at {sandbox:?} shows {restricted_host:?} at \
     {shown_at:?}, where the {restricted_mode} mount of it by provider {:?} at \
     {restricted_sandbox:?} does not apply, so it would be {} there; stopit {} at {shown_at:?} \
     this session{}; to fix the configuration, narrow this grant to leave it out, add a rule for \
     {restricted_host:?} if this mount shows it at its own host path, or cover {shown_at:?} with \
     an ephemeral rule (an absolute rule names a host path, so one for a bind destination would \
     be skipped as missing)",
    .provider.as_str(),
    resolved_note(.host, .resolved),
    .restricted_provider.as_str(),
    if *.restricted_mode == PathMode::Protected { "writable" } else { "visible" },
    if *.covered == PathMode::Masked { "masks it" } else { "mounts it protected" },
    if .shown_at == .sandbox { ", replacing this mount" } else { "" }
)]
pub struct Exposure {
    /// The provider whose rule produced the exposing mount.
    pub provider: ProviderName,
    /// The exposing mount's mode.
    pub mode: PathMode,
    /// The exposing mount's host source, as planned.
    pub host: PathBuf,
    /// `host` with every symlink resolved.
    pub resolved: PathBuf,
    /// The exposing mount's sandbox destination.
    pub sandbox: PathBuf,
    /// Where in the sandbox it shows `restricted_host`: `sandbox` joined
    /// with `restricted_host`'s path below `resolved`.
    pub shown_at: PathBuf,
    /// The provider whose rule produced the restrictive mount.
    pub restricted_provider: ProviderName,
    /// The restrictive mount's mode (`masked` or `protected`).
    pub restricted_mode: PathMode,
    /// The restrictive mount's host source, resolved to its canonical path.
    pub restricted_host: PathBuf,
    /// The restrictive mount's sandbox destination.
    pub restricted_sandbox: PathBuf,
    /// The mode of the mount stopit adds at `shown_at` to cover it:
    /// `masked`, or `protected` for protected content, unless a mask of the
    /// same content lands there too.
    pub covered: PathMode,
}

/// A `masked` or `protected` rule matches the host workspace itself, which
/// the workspace mount shows elsewhere (see
/// [`SpecWarning::WorkspaceRestricted`]). The workspace's identity wins:
/// the workspace mount is kept, and the rule applies only at its own path.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error(
    "provider {:?}: the {restricted_mode} rule for {restricted_host:?}{} at \
     {restricted_sandbox:?} matches the host workspace itself, so it does not apply to the \
     workspace mount at {workspace_mount:?} this session: the workspace stays mounted there \
     (restricted content inside it is still covered); exclude the workspace from the rule, \
     narrowing the path or glob, to silence this",
    .restricted_provider.as_str(),
    resolved_note(.restricted_host, .workspace)
)]
pub struct WorkspaceRestricted {
    /// The provider whose rule produced the restrictive mount.
    pub restricted_provider: ProviderName,
    /// The restrictive mount's mode (`masked` or `protected`).
    pub restricted_mode: PathMode,
    /// The restrictive mount's host source, as planned.
    pub restricted_host: PathBuf,
    /// The restrictive mount's sandbox destination.
    pub restricted_sandbox: PathBuf,
    /// The host workspace (canonical), which `restricted_host` resolves to.
    pub workspace: PathBuf,
    /// The workspace mount.
    pub workspace_mount: PathBuf,
}

/// A mount's host source, as written, lies outside a `masked` or
/// `protected` path, but resolves through a host symlink to content
/// strictly inside it (see [`SpecWarning::LinkedIntoRestricted`]). As a
/// grant of part of the restricted content it is the more specific rule
/// and is mounted as configured, but the user may not have meant to reach
/// under the restriction.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error(
    "provider {:?}: {mode} mount of {host:?} (resolving to {resolved:?}) at {sandbox:?} \
     reaches, through a host symlink, into {restricted_host:?}, which the {restricted_mode} \
     mount by provider {:?} at {restricted_sandbox:?} restricts; as a narrower grant of part of \
     it, it is mounted as configured, so that content is {} at {sandbox:?}; if that is not \
     intended, remove this grant or the link",
    .provider.as_str(),
    .restricted_provider.as_str(),
    if *.restricted_mode == PathMode::Protected { "writable" } else { "visible" }
)]
pub struct LinkedIntoRestricted {
    /// The provider whose rule produced the mount.
    pub provider: ProviderName,
    /// The mount's mode.
    pub mode: PathMode,
    /// The mount's host source, as planned.
    pub host: PathBuf,
    /// `host` with every symlink resolved: strictly inside
    /// `restricted_host`.
    pub resolved: PathBuf,
    /// The mount's sandbox destination.
    pub sandbox: PathBuf,
    /// The provider whose rule produced the restrictive mount.
    pub restricted_provider: ProviderName,
    /// The restrictive mount's mode (`masked` or `protected`).
    pub restricted_mode: PathMode,
    /// The restrictive mount's host source, resolved to its canonical path.
    pub restricted_host: PathBuf,
    /// The restrictive mount's sandbox destination.
    pub restricted_sandbox: PathBuf,
}

/// An `rw` mount whose host source lies strictly inside a directory a
/// provider asked to be protected (see
/// [`SpecWarning::InsideProtectedSource`]), and which is mounted
/// `protected` instead.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error(
    "provider {:?}: rw mount of {host:?} (resolving to {resolved:?}) at {sandbox:?} lies inside \
     {protected:?}, the source of provider {:?}, which runs on the host and is protected in every \
     profile, so it is mounted protected instead; to make it writable, move it out of that \
     directory",
    .provider.as_str(),
    .protected_provider.as_str()
)]
pub struct InsideProtectedSource {
    /// The provider whose rule produced the mount.
    pub provider: ProviderName,
    /// The mount's host source, as planned.
    pub host: PathBuf,
    /// `host` with every symlink resolved: strictly inside `protected`.
    pub resolved: PathBuf,
    /// The mount's sandbox destination.
    pub sandbox: PathBuf,
    /// The provider whose source is protected.
    pub protected_provider: ProviderName,
    /// The protected source, canonical.
    pub protected: PathBuf,
}

/// A mount whose host source is, or lies inside, one of stopit's state
/// directories, or a writable (`rw`) mount whose source contains one (see
/// [`SpecError::ReservedHostSource`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservedHostSource {
    /// The provider whose rule produced the mount.
    pub provider: ProviderName,
    /// The mount's mode.
    pub mode: PathMode,
    /// The mount's host source, as planned.
    pub host: PathBuf,
    /// `host` with every symlink resolved.
    pub resolved: PathBuf,
    /// The mount's sandbox destination.
    pub sandbox: PathBuf,
    /// Which state directory it collides with.
    pub dir: StateDir,
    /// That directory's host path (resolved).
    pub reserved: PathBuf,
    /// Whether `resolved` contains `reserved`, or a symlink on the way to it
    /// (an `rw` mount), rather than being it or lying inside it.
    pub contains: bool,
    /// The symlink on the way to `reserved` that `resolved` contains, if
    /// it does not contain `reserved` itself.
    pub via: Option<PathBuf>,
    /// Whether the mount is the workspace's (the host workspace at the
    /// workspace mount), which no narrower grant can replace: another
    /// workspace must be picked.
    pub workspace: bool,
}

impl fmt::Display for ReservedHostSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ReservedHostSource {
            provider,
            mode,
            host,
            resolved,
            sandbox,
            dir,
            reserved,
            contains,
            via,
            workspace,
        } = self;
        write!(
            f,
            "provider {:?}: {mode} mount of {host:?}{} at {sandbox:?} ",
            provider.as_str(),
            resolved_note(host, resolved)
        )?;
        if let Some(link) = via {
            write!(f, "contains {link:?}, a symbolic link on the way to ")?;
        } else if *contains {
            f.write_str("contains ")?;
        } else if resolved == reserved {
            f.write_str("is ")?;
        } else {
            f.write_str("lies inside ")?;
        }
        write!(
            f,
            "stopit's {dir} {reserved:?}, which holds {}; ",
            dir.holds()
        )?;
        f.write_str(match (*contains, *workspace) {
            (true, false) => {
                "a sandbox could write it there, create it, or replace a directory or link on the \
                 way to it, so no writable mount may contain it or the way to it: grant narrower \
                 rw paths that leave them out, or make this mount ro"
            }
            (true, true) => {
                "a sandbox could write it there, create it, or replace a directory or link on the \
                 way to it, so no writable mount may contain it or the way to it; this mount is the \
                 workspace: use a workspace that leaves them out, such as a project directory \
                 below your home directory or elsewhere"
            }
            (false, false) => "no sandbox may see into it or write it: remove the rule",
            (false, true) => {
                "no sandbox may see into it or write it, and this mount is the workspace: use a \
                 workspace outside it"
            }
        })
    }
}

impl std::error::Error for ReservedHostSource {}

/// A read-only or `protected` mount whose host source contains stopit's
/// session runtime directory (see [`SpecWarning::RuntimeDirMasked`]): the
/// directory is masked where the mount shows it.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error(
    "provider {:?}: {mode} mount of {host:?}{} at {sandbox:?} contains stopit's {} {runtime:?}, \
     which holds {}, so it is masked at {masked_at:?}; grant narrower paths that leave it out to \
     silence this",
    .provider.as_str(),
    resolved_note(.host, .resolved),
    StateDir::Runtime,
    StateDir::Runtime.holds()
)]
pub struct RuntimeDirMasked {
    /// The provider whose rule produced the mount.
    pub provider: ProviderName,
    /// The mount's mode.
    pub mode: PathMode,
    /// The mount's host source, as planned.
    pub host: PathBuf,
    /// `host` with every symlink resolved: an ancestor of `runtime`.
    pub resolved: PathBuf,
    /// The mount's sandbox destination.
    pub sandbox: PathBuf,
    /// The session runtime directory, `$XDG_RUNTIME_DIR/stopit`.
    pub runtime: PathBuf,
    /// Where it is masked: `sandbox` joined with `runtime`'s path below
    /// `resolved`.
    pub masked_at: PathBuf,
}

/// A host directory that a sandbox of the session can write, so that any
/// symlink inside it may have been planted (DESIGN.md §3.4, Symlinks).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UntrustedRoot {
    /// The directory's canonical host path.
    pub path: PathBuf,
    /// What makes it writable by a sandbox.
    pub kind: UntrustedKind,
}

/// Why an [`UntrustedRoot`] is untrusted.
///
/// Ephemeral directories are writable too, but their session backing
/// directories do not exist yet; they become a variant here once the
/// session runtime directory does (DESIGN.md §2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UntrustedKind {
    /// The host workspace. Always untrusted, even when no profile of this
    /// session grants it `rw`: another session or an earlier one may have.
    Workspace,
    /// The host source of an `rw` mount (a path rule or a bind) of some
    /// profile of the session.
    RwGrant {
        /// The provider whose rule produced the mount.
        provider: ProviderName,
        /// The profile whose plan has the mount; `None` when a profile is
        /// compiled on its own (`compile_profile`, tests only), where it is that
        /// profile.
        profile: Option<ProfileRef>,
        /// The mount's host source, as planned (before resolving links).
        host: PathBuf,
    },
}

impl fmt::Display for UntrustedRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            UntrustedKind::Workspace => write!(f, "the host workspace {:?}", self.path),
            UntrustedKind::RwGrant {
                provider,
                profile,
                host,
            } => {
                write!(f, "{:?}, granted rw as {host:?}", self.path)?;
                write!(f, " by provider {:?}", provider.as_str())?;
                if let Some(p) = profile {
                    write!(f, " in profile {:?}", p.as_str())?;
                }
                Ok(())
            }
        }
    }
}

/// The untrusted roots of a session (DESIGN.md §3.4, Symlinks): the host
/// workspace and the canonical host source of every `rw` mount of every
/// profile. A sandbox in one profile can plant links that a rule of
/// another follows, so the roots are collected session-wide.
///
/// Roots may nest (`rw` grants of `~/.cache` and `~/.cache/tool`): a path
/// is attributed to the innermost root containing it, the narrowest
/// directory known to be writable there. Two sources with the same
/// canonical path are one root, credited to the first one added: the
/// workspace, then mounts in the order given (profiles in graph order).
#[derive(Debug, Clone)]
struct UntrustedRoots {
    roots: Vec<UntrustedRoot>,
}

impl UntrustedRoots {
    /// Just the host workspace (canonical).
    fn new(workspace: &Path) -> Self {
        UntrustedRoots {
            roots: vec![UntrustedRoot {
                path: workspace.to_owned(),
                kind: UntrustedKind::Workspace,
            }],
        }
    }

    /// No roots at all: resolving against them is plain canonicalisation.
    fn none() -> Self {
        UntrustedRoots { roots: Vec::new() }
    }

    /// Adds the host source of every `rw` mount of `mounts`, a plan of
    /// `profile`.
    ///
    /// Each source is canonicalised (it may be written through host links,
    /// such as `~/cachelink/tool` with `~/cachelink -> .cache`, and the
    /// sandbox writes the directory they lead to), following every link: a
    /// source that itself runs through a link inside a root is rejected by
    /// the host-source check of its own profile, so the root it adds here
    /// never matters. A source that cannot be resolved is not a root: bwrap
    /// could not mount it either, and the destination check drops it
    /// ([`SpecWarning::SourceUnresolved`]).
    fn add_rw_mounts(&mut self, profile: Option<&ProfileRef>, mounts: &[PlannedMount]) {
        let none = UntrustedRoots::none();
        for m in mounts {
            let MountSource::Host { path: host, .. } = &m.source else {
                continue;
            };
            if m.mode != PathMode::Rw {
                continue;
            }
            let Ok(resolved) = resolve_host_source(host, &none) else {
                continue;
            };
            if self.roots.iter().any(|r| r.path == resolved.path) {
                continue;
            }
            self.roots.push(UntrustedRoot {
                path: resolved.path,
                kind: UntrustedKind::RwGrant {
                    provider: m.provider.clone(),
                    profile: profile.cloned(),
                    host: host.clone(),
                },
            });
        }
    }

    /// The innermost root containing the canonical path `path` (or equal to
    /// it), compared by component.
    fn containing(&self, path: &Path) -> Option<&UntrustedRoot> {
        self.roots
            .iter()
            .filter(|r| path.starts_with(&r.path))
            .max_by_key(|r| r.path.components().count())
    }
}

/// `" (resolving to …)"` when a host source is not its own canonical path.
fn resolved_note(host: &Path, resolved: &Path) -> String {
    if host == resolved {
        String::new()
    } else {
        format!(" (resolving to {resolved:?})")
    }
}

/// `" (after following the symlink … inside …)"` for a lookup that followed
/// a link inside an untrusted root before it failed.
fn via_note(link: &Option<(PathBuf, UntrustedRoot)>) -> String {
    match link {
        Some((link, root)) => format!(" (after following the symlink {link:?} inside {root})"),
        None => String::new(),
    }
}

/// The path a [`SpecError::ReservedPath`] is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathRole {
    /// The workspace mount point.
    Workspace,
    /// The sandbox `HOME` (`system.home`).
    Home,
}

impl fmt::Display for PathRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PathRole::Workspace => "workspace mount",
            PathRole::Home => "sandbox home (system.home)",
        })
    }
}

/// Why a path is rejected by the reserved-path rules.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ReservedReason {
    /// The path is the reserved path or one of its ancestors, so it would
    /// cover it.
    #[error("is or contains the reserved path {0:?}")]
    CoversReserved(PathBuf),
    /// The path is inside a reserved directory.
    #[error("is inside the reserved path {0:?}")]
    InsideReserved(PathBuf),
    /// The sandbox home is the workspace mount.
    #[error("is the same as the workspace mount")]
    SameAsWorkspace,
    /// The sandbox home is inside the workspace mount.
    #[error("is inside the workspace mount {0:?}")]
    InsideWorkspace(PathBuf),
}

/// stopit's runtime directory inside the sandbox, where the session
/// directory's shims, sockets and provisioned binary appear (DESIGN.md §2.1).
pub const SANDBOX_RUNTIME_DIR: &str = "/run/stopit";

/// The directories stopit sets up itself and that nothing else may equal,
/// contain or be placed inside: the masked `/proc`, the `/dev`, and
/// stopit's own runtime directory.
const SYSTEM_DIRS: [&str; 3] = ["/proc", "/dev", SANDBOX_RUNTIME_DIR];

/// `/etc`: stopit synthesizes some files in it (every [`EtcFile`]), but the
/// rest of it is an ordinary place for mounts.
const ETC_DIR: &str = "/etc";

/// `/tmp`: the base's ephemeral directory. Nothing may contain it, but
/// mounting over a path inside it is fine.
const TMP_DIR: &str = "/tmp";

/// The paths the workspace mount and `HOME` may be neither equal to nor an
/// ancestor of.
fn reserved_paths() -> impl Iterator<Item = &'static str> {
    SYSTEM_DIRS.into_iter().chain([ETC_DIR, TMP_DIR])
}

/// The paths the workspace mount and `HOME` may not be inside.
fn reserved_dirs() -> impl Iterator<Item = &'static str> {
    SYSTEM_DIRS.into_iter().chain([ETC_DIR])
}

/// Checks every planned mount's sandbox destination (DESIGN.md §6.2,
/// "Reserved paths"): it must not equal, contain or be inside a
/// [`SYSTEM_DIRS`] directory, nor equal or contain a synthesized `/etc`
/// file. Other `/etc` paths and `/run` subtrees are fine.
///
/// Every synthesized `/etc` file is checked whether or not the profile
/// enables it (`system.etc`), so a mount's validity does not depend on it.
///
/// This runs after mount planning, because glob rules only have concrete
/// destinations then. It applies to every mode, `masked` and `protected`
/// included: allowing some modes would buy little, since these paths are
/// stopit's own and no rule has a reason to touch them, and one rule for all
/// modes is simpler to state and to check.
fn check_mount_destinations(mounts: &[PlannedMount]) -> Result<(), SpecError> {
    // Each reserved path, and whether nothing may be inside it (true for the
    // system directories, false for the synthesized files).
    let reserved: Vec<(PathBuf, bool)> = SYSTEM_DIRS
        .iter()
        .map(|r| (PathBuf::from(r), true))
        .chain(
            EtcFile::ALL
                .iter()
                .map(|f| (Path::new(ETC_DIR).join(f.as_str()), false)),
        )
        .collect();
    for m in mounts {
        let dest = m.sandbox.as_path();
        let collision = reserved.iter().find_map(|(r, is_dir)| {
            if r.starts_with(dest) {
                Some(ReservedReason::CoversReserved(r.clone()))
            } else if *is_dir && dest.starts_with(r) {
                Some(ReservedReason::InsideReserved(r.clone()))
            } else {
                None
            }
        });
        if let Some(reason) = collision {
            return Err(SpecError::ReservedMount {
                provider: m.provider.clone(),
                path: m.sandbox.clone(),
                reason,
            });
        }
    }
    Ok(())
}

/// Checks every planned mount's host source against the untrusted `roots`
/// (DESIGN.md §3.4, Symlinks; §6.2, "Untrusted links"), the host workspace
/// (§6.2, "Workspace exposure") and the profile's masked and protected
/// mounts (§6.2, "Restricted content exposure"; see
/// [`cover_restricted_exposure`], which adds the mounts covering such
/// content where another mount shows it).
///
/// The planner keeps host sources as written: `~` and absolute rules follow
/// symlinks on the way and binds follow a final symlink, as bwrap does when
/// mounting. Hence each source is resolved first (see
/// [`resolve_host_source`]). [`check_destination_links`] has already
/// dropped every non-masked mount whose source cannot be resolved for a
/// missing target, and every such `rw` one. What is left fails closed: a
/// restrictive source that cannot be resolved otherwise is an error
/// ([`SpecError::HostSourceUnresolved`]), or, if the lookup followed a link
/// inside an untrusted root first, [`SpecError::UntrustedLinkFollowed`];
/// one inside a masked directory of `mounts` is dropped instead, with
/// [`SpecWarning::SourceUnderMask`], since the mask hides it anyway (the
/// planner masks a directory a restrictive rule cannot inspect below, so
/// that is for a layout that changed since). Returns the mounts kept, plus
/// those covering restricted content shown elsewhere, in plan order. A
/// `masked` mount is kept even if its source cannot be resolved (it shows
/// nothing of it, and its shape was decided while planning), with
/// [`SpecWarning::MaskSourceUnresolved`], unless the lookup followed such a
/// link, which is refused as for any mask.
///
/// **Untrusted links.** No source may run through a symlink inside an
/// untrusted root, a host directory some sandbox of the session can write:
/// the workspace, or the source of any profile's `rw` mount. The sandbox can
/// plant links there, so a `~` or absolute rule such as `~/proj/x` with
/// `x -> ../.ssh` would otherwise mount `~/.ssh`. This holds however the
/// source reaches the root: written inside it, or through a link outside it
/// (`~/current/x` with `~/current -> proj`, or `~/.bashrc -> proj/bashrc`
/// replaced by a link in the workspace), where the planted link would turn
/// a rule that shows nothing or is rejected into a mount of any host path.
/// Links the host controls, outside every root, are followed. Such a
/// link is an error for a restrictive mount (every mode but `rw`); an `rw`
/// mount (rule or bind) through one has already been dropped with a warning
/// by [`check_destination_links`], since dropping a grant only removes
/// access. (When a mount lies inside a mount of its root, e.g. a `~` rule
/// below an `rw` grant of its parent, that check has also refused or
/// dropped it for a link written there.) Only links count: a literal `..`
/// may leave a root again, since the sandbox cannot change what it means.
/// Rule paths cannot contain `..`, but the
/// target of a link outside the roots can (`~/via -> proj/../.ssh` resolves
/// to `~/.ssh` like any other path), and only the user can write that.
///
/// `masked` mounts show nothing of their source, but the planner takes a
/// masked `~` or absolute symlink's kind (an empty file or an empty
/// directory) from its target, and any path's kind from the entry the
/// lookup ends at, so they are checked for untrusted links too: a planted
/// link must not decide a mask's shape.
///
/// **Workspace exposure.** The workspace must appear in the sandbox only at
/// its mount: its restrictions, the pinned parents below it and the
/// supervisor's workspace-relative checks all apply to sandbox paths inside
/// the workspace mount, not to host content. Every source except a
/// `masked` one must, resolved, not be the host workspace or an ancestor of
/// it, unless it is the workspace itself mounted at the workspace mount;
/// and if it lies inside the host workspace, the mount must be at the
/// aligned path, i.e. the workspace mount joined with the source's path
/// relative to the host workspace. A source through a link inside the
/// workspace has been refused above, so aligned ones resolve to
/// themselves. This runs mount by mount, before the restricted content
/// check, which covers the workspace's masks and protected files too.
///
/// A masked glob match whose target could not be inspected while planning
/// (see [`PlannedMount::glob_link`]) and that was not skipped as a link
/// inside an untrusted root fails closed: its shape is unknown
/// ([`SpecError::MaskTargetUninspectable`]), unless the way to it runs
/// through a planted link, which is reported instead.
///
/// Last, the mounts, covers and protected sources included, are checked
/// against stopit's state directories `state` ([`check_state_dirs`]).
///
/// `ctx`'s host workspace is canonical by contract, and is one of `roots`.
/// Paths are compared by component.
fn check_host_sources(
    mounts: Vec<PlannedMount>,
    ctx: &ExpansionContext,
    roots: &UntrustedRoots,
    protected: &[SourceToProtect<'_>],
    state: &StateDirs,
    warnings: &mut Vec<SpecWarning>,
) -> Result<Vec<PlannedMount>, SpecError> {
    let ws_host = ctx.workspace_host();
    let ws_sandbox = ctx.workspace_sandbox();
    // The sandbox paths of the masked directories, none of which is dropped
    // here.
    let masked_dirs: Vec<PathBuf> = mounts
        .iter()
        .filter(|m| {
            m.mode == PathMode::Masked
                && matches!(
                    m.source,
                    MountSource::Host {
                        kind: EntryKind::Dir,
                        ..
                    }
                )
        })
        .map(|m| m.sandbox.clone())
        .collect();
    let mut kept = Vec::with_capacity(mounts.len());
    // The canonical source of each kept mount and its kind, `None` for an
    // ephemeral one (or a mask whose source cannot be resolved).
    let mut sources = Vec::with_capacity(mounts.len());
    for m in mounts {
        let MountSource::Host { path: host, kind } = &m.source else {
            sources.push(None);
            kept.push(m);
            continue;
        };
        let unresolved = |error: io::Error| SpecError::HostSourceUnresolved {
            provider: m.provider.clone(),
            mode: m.mode,
            host: host.clone(),
            sandbox: m.sandbox.clone(),
            kind: error.kind(),
        };
        // The planner resolves every other masked link to its target's kind.
        if m.mode == PathMode::Masked && *kind == EntryKind::Symlink {
            let (Some(parent), Some(name)) = (host.parent(), host.file_name()) else {
                unreachable!("a matched link has a parent and a name");
            };
            // A lookup that failed after following a planted link is refused
            // for that link, as below.
            let way =
                resolve_host_source(parent, roots).map_err(|u| match u.untrusted.first() {
                    Some(followed) => {
                        SpecError::UntrustedLinkFollowed(link_followed(&m, host, &u.path, followed))
                    }
                    None => unresolved(u.error),
                })?;
            if let Some(followed) = way.untrusted.first() {
                return Err(SpecError::UntrustedLinkFollowed(link_followed(
                    &m,
                    host,
                    &way.path.join(name),
                    followed,
                )));
            }
            return Err(SpecError::MaskTargetUninspectable {
                provider: m.provider.clone(),
                host: host.clone(),
                sandbox: m.sandbox.clone(),
                kind: host
                    .metadata()
                    .err()
                    .map_or(io::ErrorKind::Other, |e| e.kind()),
            });
        }
        let source = match resolve_host_source(host, roots) {
            Ok(source) => source,
            Err(u) => {
                if let Some(followed) = u.untrusted.first() {
                    return Err(SpecError::UntrustedLinkFollowed(link_followed(
                        &m, host, &u.path, followed,
                    )));
                }
                if m.mode == PathMode::Masked {
                    warnings.push(SpecWarning::MaskSourceUnresolved(source_unresolved(
                        &m, host, u,
                    )));
                    sources.push(None);
                    kept.push(m);
                    continue;
                }
                // Below a masked directory the mask is stricter than the
                // mount: the content is hidden either way. (The planner
                // masks a directory a restrictive rule cannot inspect below,
                // so this is defensive, for a layout that changed since.)
                let mask = masked_dirs
                    .iter()
                    .find(|d| m.sandbox.starts_with(d) && m.sandbox != **d);
                if let Some(mask) = mask {
                    warnings.push(SpecWarning::SourceUnderMask(
                        source_unresolved(&m, host, u),
                        mask.clone(),
                    ));
                    continue;
                }
                return Err(unresolved(u.error));
            }
        };
        // Only a restrictive mount gets here with such a link:
        // `check_destination_links` has dropped every `rw` one.
        if let Some(followed) = source.untrusted.first() {
            return Err(SpecError::UntrustedLinkFollowed(link_followed(
                &m,
                host,
                &source.path,
                followed,
            )));
        }
        let (resolved, resolved_kind) = (source.path, source.kind);
        let exposed = m.mode != PathMode::Masked
            && match resolved.strip_prefix(ws_host) {
                // Inside the workspace (or the workspace itself): only the
                // aligned mapping is allowed.
                Ok(rel) => m.sandbox != join_rel(ws_sandbox, rel),
                // Elsewhere: it must not contain the workspace.
                Err(_) => ws_host.starts_with(&resolved),
            };
        if exposed {
            return Err(SpecError::WorkspaceExposed {
                provider: m.provider.clone(),
                mode: m.mode,
                host: host.clone(),
                resolved,
                sandbox: m.sandbox.clone(),
                workspace: ws_host.to_owned(),
            });
        }
        sources.push(Some((resolved, resolved_kind)));
        kept.push(m);
    }
    // Every `rw` mount has a canonical source; the covers added next are
    // never `rw`.
    let rw_sources: BTreeMap<PathBuf, PathBuf> = kept
        .iter()
        .zip(&sources)
        .filter(|(m, _)| m.mode == PathMode::Rw)
        .filter_map(|(m, s)| Some((m.sandbox.clone(), s.as_ref()?.0.clone())))
        .collect();
    // Every kept mount's canonical source, by sandbox path. A mount the
    // next two steps put at one of these paths in place of the kept one has
    // the same canonical source (it covers or protects the content the kept
    // one showed there); one at another path has a canonical source.
    let canonical: BTreeMap<PathBuf, PathBuf> = kept
        .iter()
        .zip(&sources)
        .filter_map(|(m, s)| Some((m.sandbox.clone(), s.as_ref()?.0.clone())))
        .collect();
    let mounts = cover_restricted_exposure(kept, &sources, ws_host, warnings);
    let mounts = protect_sources(mounts, &rw_sources, protected, warnings);
    let workspace = (ws_host, ctx.workspace_sandbox());
    check_state_dirs(mounts, &canonical, workspace, state, warnings)
}

/// Checks every mount's host source against stopit's own state directories
/// `state` (DESIGN.md §6.2, "Reserved host paths"), returning `mounts` with
/// a mask added wherever a read-only view shows the session runtime
/// directory, in plan order. `canonical` maps sandbox paths to the
/// canonical source of the mount there; a mount missing from it (a cover,
/// a protected source, or a mask whose source cannot be resolved) is taken
/// at its planned source, which is canonical (or, for that mask, shows
/// nothing anyway). `workspace` is the (canonical) host workspace and its
/// mount, so that an error about the workspace's own mount says to pick
/// another workspace.
///
/// This runs last, on the mounts as they will be mounted, covers and
/// protected sources included, whatever their mode:
///
/// * A source that is, or lies inside, a state directory is an error
///   ([`SpecError::ReservedHostSource`]), `masked` included: stopit's state
///   is no rule's business, and the runtime directory holds other sessions'
///   sockets and ephemeral data.
/// * An `rw` source containing one, or a symlink on the way to one (from
///   the path it was found at, see [`StatePath`](crate::state::StatePath)), is
///   an error too: the sandbox could write the state, or create the data
///   directory before stopit does, or rename a directory on the way, or
///   replace such a link, and plant another one in its place. Masking the
///   directory inside the grant would not prevent the last two (pinned
///   parents are still pending, DESIGN.md §11), and what the data directory
///   holds decides what the next session trusts, so this is refused rather
///   than covered. `rw` is the only writable mode with a host source:
///   `ephemeral` has none, and `protected` is read-only until protected
///   files are served by FUSE, whose writes will each need approval.
/// * A read-only (`ro` or `protected`) source containing the runtime
///   directory gets a mask over it where the mount shows it, attributed to
///   stopit's own provider name, with a [`SpecWarning::RuntimeDirMasked`]
///   (DESIGN.md §1.5). That is sound: no sandbox can write any directory on
///   the way to it (every `rw` grant containing it is refused), so what the
///   mask covers stays where it is. Unless another mount lies between the
///   mount's destination (exclusive) and that path (inclusive), mounted on
///   top: it is checked in turn.
/// * A read-only source containing the data directory is fine: it only
///   shows stopit's own records, and the sandbox cannot change them. A
///   `masked` one shows nothing.
fn check_state_dirs(
    mut mounts: Vec<PlannedMount>,
    canonical: &BTreeMap<PathBuf, PathBuf>,
    (ws_host, ws_sandbox): (&Path, &Path),
    state: &StateDirs,
    warnings: &mut Vec<SpecWarning>,
) -> Result<Vec<PlannedMount>, SpecError> {
    let mut masks: BTreeMap<PathBuf, PlannedMount> = BTreeMap::new();
    {
        let at: BTreeSet<&Path> = mounts.iter().map(|m| m.sandbox.as_path()).collect();
        for m in &mounts {
            let MountSource::Host { path: host, .. } = &m.source else {
                continue;
            };
            let resolved = canonical.get(&m.sandbox).unwrap_or(host);
            let workspace = m.sandbox == ws_sandbox && resolved == ws_host;
            for (dir, state_path) in state.iter() {
                let reserved = state_path.path.as_path();
                let fail = |contains, via: Option<&PathBuf>| {
                    SpecError::ReservedHostSource(Box::new(ReservedHostSource {
                        provider: m.provider.clone(),
                        mode: m.mode,
                        host: host.clone(),
                        resolved: resolved.clone(),
                        sandbox: m.sandbox.clone(),
                        dir,
                        reserved: reserved.to_owned(),
                        contains,
                        via: via.cloned(),
                        workspace,
                    }))
                };
                if resolved.starts_with(reserved) {
                    return Err(fail(false, None));
                }
                let rel = reserved.strip_prefix(resolved);
                if m.mode == PathMode::Rw {
                    if rel.is_ok() {
                        return Err(fail(true, None));
                    }
                    // Replacing a link on the way moves the directory.
                    if let Some(link) = state_path.links.iter().find(|l| l.starts_with(resolved)) {
                        return Err(fail(true, Some(link)));
                    }
                }
                let Ok(rel) = rel else {
                    continue;
                };
                match (m.mode, dir) {
                    (PathMode::Ro | PathMode::Protected, StateDir::Runtime) => {}
                    (PathMode::Ro | PathMode::Protected, StateDir::Data)
                    | (PathMode::Masked | PathMode::Ephemeral | PathMode::Rw, _) => continue,
                }
                let x = m.sandbox.join(rel);
                let overmounted = x
                    .ancestors()
                    .take_while(|a| *a != m.sandbox)
                    .any(|a| at.contains(a));
                if overmounted || masks.contains_key(&x) {
                    continue;
                }
                warnings.push(SpecWarning::RuntimeDirMasked(Box::new(RuntimeDirMasked {
                    provider: m.provider.clone(),
                    mode: m.mode,
                    host: host.clone(),
                    resolved: resolved.clone(),
                    sandbox: m.sandbox.clone(),
                    runtime: reserved.to_owned(),
                    masked_at: x.clone(),
                })));
                masks.insert(
                    x.clone(),
                    PlannedMount {
                        sandbox: x,
                        source: MountSource::Host {
                            path: reserved.to_owned(),
                            kind: EntryKind::Dir,
                        },
                        mode: PathMode::Masked,
                        provider: SUPERVISOR_PROVIDER_NAME
                            .parse()
                            .expect("the supervisor's name is a valid provider name"),
                        glob_link: false,
                    },
                );
            }
        }
    }
    if masks.is_empty() {
        return Ok(mounts);
    }
    let masks: Vec<PlannedMount> = masks.into_values().collect();
    debug_assert!(check_mount_destinations(&masks).is_ok());
    mounts.extend(masks);
    sort_plan(&mut mounts);
    Ok(mounts)
}

/// A host path a provider asked to be protected ([`ProtectedSource`]), with
/// the kind of entry there.
#[derive(Debug, Clone, Copy)]
struct SourceToProtect<'a> {
    provider: &'a ProviderName,
    /// Canonical.
    path: &'a Path,
    /// Never [`EntryKind::Symlink`], `path` being canonical.
    kind: EntryKind,
}

/// Protects the host paths providers asked to be protected (a script
/// provider's source, which runs on the host at the next start, DESIGN.md
/// §3.6) wherever `mounts` let the sandbox write them, returning `mounts`
/// with the protecting mounts added, in plan order. `rw_sources` maps the
/// sandbox path of every `rw` mount to its canonical host source.
///
/// This is the supervisor's rule, not a grant, so it runs last, on the
/// mounts as they will be mounted, rather than as a rule competing in path
/// precedence (DESIGN.md §3.5), where an exact `rw` rule of the same path,
/// or a profile's own rule, would beat it. It works like the protected
/// covers of [`cover_restricted_exposure`], with no protected mount of its
/// own to compare against: for every protected path P and every `rw` mount
/// M of the canonical source S at T_M, if S is P or an ancestor of it, M
/// lets the sandbox write P at X, T_M joined with P's path below S, unless
/// another mount lies between T_M (exclusive) and X (inclusive): it is
/// mounted on top (and is compared in turn if it is `rw`; any other mode
/// shows P read-only, or not at all). So X gets a `protected` mount of P,
/// attributed to the provider that asked; if X is T_M (S is P), it replaces
/// M. One mount is added per sandbox path, wherever P shows: at its aligned
/// path in the workspace, and at every other path an `rw` grant shows it.
/// Nothing is added where P is not writable: not visible at all, masked
/// (a mask on the way is mounted on top), or read-only. This runs after
/// the restricted-content covers, so that a mask covering P's directory
/// there is on top of M too, rather than below a protected mount added
/// first.
///
/// A source S strictly inside a protected directory P is not a narrower
/// grant that may lift it, as it would be for a protected rule (§3.5): M is
/// mounted `protected` instead, with a
/// [`SpecWarning::InsideProtectedSource`].
///
/// The mounts added need none of the other checks, for the reasons the
/// covers need none: P is canonical and lies inside S, and X lies below
/// T_M, reached through M's tree along P.
fn protect_sources(
    mut mounts: Vec<PlannedMount>,
    rw_sources: &BTreeMap<PathBuf, PathBuf>,
    protected: &[SourceToProtect<'_>],
    warnings: &mut Vec<SpecWarning>,
) -> Vec<PlannedMount> {
    let mut added: BTreeMap<PathBuf, PlannedMount> = BTreeMap::new();
    // The `rw` mounts inside a protected directory, by index, each with the
    // first such directory.
    let mut inside: BTreeMap<usize, &SourceToProtect<'_>> = BTreeMap::new();
    {
        let at: BTreeSet<&Path> = mounts.iter().map(|m| m.sandbox.as_path()).collect();
        for p in protected {
            for (i, m) in mounts.iter().enumerate() {
                if m.mode != PathMode::Rw {
                    continue;
                }
                let Some(s) = rw_sources.get(&m.sandbox) else {
                    continue;
                };
                let Ok(rel) = p.path.strip_prefix(s) else {
                    if s.starts_with(p.path) {
                        inside.entry(i).or_insert(p);
                    }
                    continue;
                };
                let x = join_rel(&m.sandbox, rel);
                let overmounted = x
                    .ancestors()
                    .take_while(|a| *a != m.sandbox)
                    .any(|a| at.contains(a));
                if overmounted {
                    continue;
                }
                added.entry(x.clone()).or_insert_with(|| PlannedMount {
                    sandbox: x,
                    source: MountSource::Host {
                        path: p.path.to_owned(),
                        kind: p.kind,
                    },
                    mode: PathMode::Protected,
                    provider: p.provider.clone(),
                    glob_link: false,
                });
            }
        }
    }
    for (i, p) in inside {
        let m = &mut mounts[i];
        let MountSource::Host { path: host, .. } = &m.source else {
            unreachable!("an rw mount has a host source");
        };
        warnings.push(SpecWarning::InsideProtectedSource(Box::new(
            InsideProtectedSource {
                provider: m.provider.clone(),
                host: host.clone(),
                resolved: rw_sources[&m.sandbox].clone(),
                sandbox: m.sandbox.clone(),
                protected_provider: p.provider.clone(),
                protected: p.path.to_owned(),
            },
        )));
        m.mode = PathMode::Protected;
    }
    if added.is_empty() {
        return mounts;
    }
    let added: Vec<PlannedMount> = added.into_values().collect();
    debug_assert!(check_mount_destinations(&added).is_ok());
    // Only the `rw` mount exposing P can lie at an added path: its own.
    mounts.retain(|m| added.iter().all(|a| a.sandbox != m.sandbox));
    mounts.extend(added);
    sort_plan(&mut mounts);
    mounts
}

/// `base` joined with the relative path `rel`, or `base` itself if `rel` is
/// empty (where `Path::join` would add a trailing `/`).
fn join_rel(base: &Path, rel: &Path) -> PathBuf {
    if rel.as_os_str().is_empty() {
        base.to_owned()
    } else {
        base.join(rel)
    }
}

/// Covers host content a `masked` or `protected` mount covers that another
/// mount shows at another sandbox path (DESIGN.md §6.2, "Restricted content
/// exposure"), returning `mounts` with the covering mounts added, in plan
/// order, and one [`SpecWarning::RestrictedContentExposed`] per pair of
/// mounts. `sources` holds each mount's canonical host source and its kind
/// (`None` for an ephemeral mount, or a mask whose source cannot be
/// resolved), as [`check_host_sources`] resolved it.
///
/// The safe outcome (DESIGN.md §1.5) rather than an error: such content is
/// commonly controlled by the host (a home-manager file masked at
/// `~/.config/foo` whose `/nix/store` target is mounted too), and the
/// warning says where it was shown and how to fix the configuration.
///
/// Masks and protected files apply to sandbox paths, not to host content.
/// So for every such mount R, of the canonical host path P at the sandbox
/// path T_R, every other mount M that shows something (any mode but
/// `masked`; for a `protected` R only `rw` mounts count, since protected
/// content is readable anyway), of the canonical source S at T_M, should
/// not show P away from T_R through a grant at least as broad as P: if S
/// is P or an ancestor of it, M shows P at X, T_M joined with P's path
/// below S. That is fine if X is T_R (R covers it there), or if another
/// mount lies between T_M (exclusive) and X (inclusive): it is mounted on
/// top and hides what M shows there (that mount is compared in turn).
/// Otherwise P is exposed: masked `~/.config/tool/token` with `~/.config`
/// also mounted at `/opt/cfg` shows the token at `/opt/cfg/tool/token`.
///
/// A source S strictly inside P (a directory) does not expose P: the most
/// specific rule wins (DESIGN.md §3.5), and a grant of part of a masked or
/// protected directory is a narrower, explicit grant of that part,
/// wherever it is mounted. Masking `~/Projects` to hide other projects
/// leaves the workspace `~/Projects/stopit` at its mount. Specificity is
/// decided on canonical paths, so a source written outside P (and outside
/// R's source as written) that reaches strictly inside P through a host
/// link (`ro ~/.toolrc` with `~/.toolrc -> .ssh/id_ed25519` and `~/.ssh`
/// masked) is not covered either, but is reported with
/// [`SpecWarning::LinkedIntoRestricted`]: the user may not realize it lies
/// under the restriction.
///
/// The workspace mount itself is never covered: if P is the host workspace
/// (`~/Projects/*` masked, matching the workspace `~/Projects/stopit`), the
/// workspace's identity wins, the workspace mount is kept and R applies
/// only at T_R, with [`SpecWarning::WorkspaceRestricted`]. Restricted
/// content inside the workspace, shown through the workspace mount, is
/// still covered there.
///
/// So M shows P at X, and no other mount shows anything at X: one at X
/// itself, other than M, or between M and X would be mounted on top. So X
/// is covered by a mount of P there, attributed to R's provider: `masked`
/// (of P's kind) for a masked R, `protected` for a protected one (a
/// read-only bind of P until protected files are served by FUSE, which
/// serves the same content). Restricted mounts of the same content (masked
/// `~/.config/foo` and `~/.config/bar` linking to one store path) meet at
/// the same X, which gets one mount, the stricter: `masked` over
/// `protected`. If X is M's own path (S is P), the cover replaces M, being
/// stricter: a mask hides it, and a protected mount shows the same content
/// read-only. An exposure through M below a cover that
/// already hides it (inside a masked directory X, or inside a protected one
/// for protected content) needs no mount of its own and is not reported.
/// Planned mounts deeper than X are kept on top of the cover, as below any
/// mount: they show what their own rules configure (and are compared in
/// turn).
///
/// The covers need none of the earlier checks. Their sources are canonical
/// paths, so they run through no link (§3.4, Symlinks), and lie inside M's
/// canonical source, which passed the workspace check (a protected cover
/// shows part of what M shows, at its aligned path within M). Their
/// destinations lie at or below T_M: bwrap reaches X through M's tree, at
/// S joined with X's path below T_M, which is P, canonical, so with no link
/// on the way (§6.2, "Untrusted links"); and a path at or below a valid
/// destination is valid too (§6.2, "Reserved paths", checked again in debug
/// builds).
///
/// Only one profile's mounts are compared, and covered: each sandbox is one
/// profile. A mount dropped earlier is not among `mounts`, so it neither
/// exposes nor covers anything.
fn cover_restricted_exposure(
    mut mounts: Vec<PlannedMount>,
    sources: &[Option<(PathBuf, EntryKind)>],
    ws_host: &Path,
    warnings: &mut Vec<SpecWarning>,
) -> Vec<PlannedMount> {
    // Every exposure, with the kind of the content it shows.
    let found = find_restricted_exposure(&mounts, sources, ws_host, warnings);
    // The mount covering each exposed sandbox path.
    let covers = |found: &[(Exposure, EntryKind)]| {
        let mut covers: BTreeMap<PathBuf, PlannedMount> = BTreeMap::new();
        for (x, kind) in found {
            let mode = match x.restricted_mode {
                PathMode::Masked => PathMode::Masked,
                _ => PathMode::Protected,
            };
            let cover = || PlannedMount {
                sandbox: x.shown_at.clone(),
                source: MountSource::Host {
                    path: x.restricted_host.clone(),
                    kind: *kind,
                },
                mode,
                provider: x.restricted_provider.clone(),
                glob_link: false,
            };
            let c = covers.entry(x.shown_at.clone()).or_insert_with(cover);
            // One host path shows at X, so only the mode can differ.
            debug_assert_eq!(c.source, cover().source);
            if mode == PathMode::Masked && c.mode != PathMode::Masked {
                *c = cover();
            }
        }
        covers
    };
    let all = covers(&found);
    // An exposure through M below a cover that hides it already: at most up
    // to M's own path, where nothing else is mounted, so that cover is M's.
    let hidden = |x: &Exposure| {
        x.shown_at
            .ancestors()
            .skip(1)
            .take_while(|a| a.starts_with(&x.sandbox))
            .filter_map(|a| all.get(a))
            .any(|c| c.mode == PathMode::Masked || x.restricted_mode == PathMode::Protected)
    };
    let found: Vec<_> = found.into_iter().filter(|(x, _)| !hidden(x)).collect();
    let covers = covers(&found);
    for (mut x, _) in found {
        x.covered = covers[&x.shown_at].mode;
        warnings.push(SpecWarning::RestrictedContentExposed(Box::new(x)));
    }
    let covers: Vec<PlannedMount> = covers.into_values().collect();
    debug_assert!(check_mount_destinations(&covers).is_ok());
    // Only an exposing mount can lie at a covered path: its own.
    mounts.retain(|m| covers.iter().all(|c| c.sandbox != m.sandbox));
    mounts.extend(covers);
    sort_plan(&mut mounts);
    mounts
}

/// Sorts mounts as the planner orders them (see
/// [`MountPlan::mounts`](crate::resolve::MountPlan::mounts)): by depth, so
/// that every mount comes after its ancestors, then by path.
fn sort_plan(mounts: &mut [PlannedMount]) {
    mounts.sort_by(|a, b| {
        let depth = |p: &Path| p.components().count();
        depth(&a.sandbox)
            .cmp(&depth(&b.sandbox))
            .then_with(|| a.sandbox.cmp(&b.sandbox))
    });
}

/// Every exposure [`cover_restricted_exposure`] covers, not yet attributed
/// a cover (its [`Exposure::covered`] is the restrictive mount's mode), with
/// the kind of the content it shows. Pushes the warnings for what is not
/// covered: a restrictive rule matching the host workspace `ws_host`
/// ([`SpecWarning::WorkspaceRestricted`]) and a grant reaching strictly
/// inside restricted content through a host link
/// ([`SpecWarning::LinkedIntoRestricted`]).
fn find_restricted_exposure(
    mounts: &[PlannedMount],
    sources: &[Option<(PathBuf, EntryKind)>],
    ws_host: &Path,
    warnings: &mut Vec<SpecWarning>,
) -> Vec<(Exposure, EntryKind)> {
    let mut found = Vec::new();
    let at: BTreeSet<&Path> = mounts.iter().map(|m| m.sandbox.as_path()).collect();
    // Whether a mount lies strictly below `top` and at or above `path` (a
    // path below `top`), hiding what the mount at `top` shows at `path`.
    let overmounted = |top: &Path, path: &Path| {
        path.ancestors()
            .take_while(|a| *a != top)
            .any(|a| at.contains(a))
    };
    for (i, (r, p)) in mounts.iter().zip(sources).enumerate() {
        let Some((p, p_kind)) = p else { continue };
        if !matches!(r.mode, PathMode::Masked | PathMode::Protected) {
            continue;
        }
        for (j, (m, s)) in mounts.iter().zip(sources).enumerate() {
            let Some((s, _)) = s else { continue };
            // A read-only view of protected content exposes nothing
            // protected: it is readable at its own path too.
            let shows = match r.mode {
                PathMode::Protected => m.mode == PathMode::Rw,
                _ => m.mode != PathMode::Masked,
            };
            if i == j || !shows {
                continue;
            }
            let (MountSource::Host { path: host, .. }, MountSource::Host { path: r_host, .. }) =
                (&m.source, &r.source)
            else {
                unreachable!("a mount with a canonical source has a host source");
            };
            let Ok(rel) = p.strip_prefix(s) else {
                // A source strictly inside P is a more specific grant of
                // that part of P, and exposes nothing (DESIGN.md §3.5); but
                // one written outside P that reaches there through a host
                // link is reported.
                if s.starts_with(p) && !host.starts_with(p) && !host.starts_with(r_host) {
                    warnings.push(SpecWarning::LinkedIntoRestricted(Box::new(
                        LinkedIntoRestricted {
                            provider: m.provider.clone(),
                            mode: m.mode,
                            host: host.clone(),
                            resolved: s.clone(),
                            sandbox: m.sandbox.clone(),
                            restricted_provider: r.provider.clone(),
                            restricted_mode: r.mode,
                            restricted_host: p.clone(),
                            restricted_sandbox: r.sandbox.clone(),
                        },
                    )));
                }
                continue;
            };
            let shown_at = join_rel(&m.sandbox, rel);
            if shown_at == r.sandbox || overmounted(&m.sandbox, &shown_at) {
                continue;
            }
            // The workspace's identity wins: the workspace mount (the only
            // mount whose source is the workspace) is never covered.
            if p == ws_host {
                warnings.push(SpecWarning::WorkspaceRestricted(Box::new(
                    WorkspaceRestricted {
                        restricted_provider: r.provider.clone(),
                        restricted_mode: r.mode,
                        restricted_host: r_host.clone(),
                        restricted_sandbox: r.sandbox.clone(),
                        workspace: ws_host.to_owned(),
                        workspace_mount: m.sandbox.clone(),
                    },
                )));
                continue;
            }
            let exposure = Exposure {
                provider: m.provider.clone(),
                mode: m.mode,
                host: host.clone(),
                resolved: s.clone(),
                sandbox: m.sandbox.clone(),
                shown_at,
                restricted_provider: r.provider.clone(),
                restricted_mode: r.mode,
                restricted_host: p.clone(),
                restricted_sandbox: r.sandbox.clone(),
                covered: r.mode,
            };
            found.push((exposure, *p_kind));
        }
    }
    found
}

/// The [`LinkFollowed`] for the mount `m` of `host`, resolving to
/// `resolved` through the untrusted link `followed`.
fn link_followed(
    m: &PlannedMount,
    host: &Path,
    resolved: &Path,
    followed: &UntrustedLink<'_>,
) -> Box<LinkFollowed> {
    Box::new(LinkFollowed {
        provider: m.provider.clone(),
        mode: m.mode,
        host: host.to_owned(),
        link: followed.link.clone(),
        resolved: resolved.to_owned(),
        sandbox: m.sandbox.clone(),
        root: followed.root.clone(),
    })
}

/// The [`SourceUnresolved`] for the mount `m` of `host`, whose lookup failed
/// with `u`.
fn source_unresolved(m: &PlannedMount, host: &Path, u: Unresolved<'_>) -> Box<SourceUnresolved> {
    Box::new(SourceUnresolved {
        provider: m.provider.clone(),
        mode: m.mode,
        host: host.to_owned(),
        sandbox: m.sandbox.clone(),
        link: u
            .untrusted
            .first()
            .map(|l| (l.link.clone(), l.root.clone())),
        error: u.error,
    })
}

/// What a kept mount puts underneath the sandbox paths below it, for
/// [`check_destination_links`].
enum Underneath {
    /// The host tree at `source`, the mount's canonical host source.
    Host {
        /// The mount's mode.
        mode: PathMode,
        /// The canonical host source.
        source: PathBuf,
    },
    /// A tree whose contents are not checked: a masked directory (an empty
    /// directory nothing written persists in), an ephemeral directory (not
    /// checkable yet), or a restrictive mount's host source that cannot be
    /// resolved (rejected by [`check_host_sources`] anyway, or dropped there
    /// inside a masked directory).
    Unchecked,
}

/// Checks every planned mount's destination against the mount underneath
/// it (DESIGN.md §6.2, "Untrusted links"), returning the mounts kept.
///
/// bwrap applies `mounts` in order, every mount after its ancestors, and
/// resolves each destination in the sandbox's mount tree as built so far,
/// following symlinks. So the host directory it traverses to reach a
/// destination is that of its nearest ancestor mount in the plan: the
/// ancestor's host source (resolved to its canonical path, as bwrap binds
/// it) joined with the destination's path below the ancestor. If a symlink
/// on that way (the final component included) lies inside an untrusted
/// root, a sandbox may have planted it to move the mount elsewhere: a mask
/// or a read-only mount onto a decoy, leaving the real path as it was. Then
/// a restrictive mount (every mode but `rw`) is an error and an `rw` one is
/// dropped with a warning.
///
/// The walk stops at the first symlink: one outside every root is the
/// host's (a home-manager link under an `ro ~`, say) and bwrap follows it
/// within the sandbox's tree, where the rest of the way is not checked
/// (DESIGN.md §11). A missing component is fine: bwrap creates the mount
/// point. A path on the way that exists but cannot be inspected drops an
/// `rw` mount with a warning. A restrictive mount is never skipped: the
/// directory containing that path, which cannot be searched, is masked
/// instead, replacing the ancestor if it is the ancestor's own source (with
/// [`SpecWarning::GrantHidden`] as well; `ws_sandbox`, the workspace mount,
/// tells whether that is the workspace), and the mount is kept on top of
/// the mask, with [`SpecWarning::DestinationMasked`] (DESIGN.md §1.5). That holds for
/// `ephemeral` too: its mount shows nothing of the host, and the mask hides
/// what the unsearchable directory held around it. A
/// destination with no ancestor mount lies on bwrap's own root `tmpfs`;
/// one inside a masked directory, nothing the sandbox writes persists in;
/// neither has anything to check. One inside an ephemeral mount is not
/// checked yet (see [`Underneath::Unchecked`]).
///
/// The workspace mount is no special case: a mount of the workspace, or of
/// anything inside an `rw` grant, is a host tree inside an untrusted root,
/// where every link is refused. Ancestors outside every root are checked
/// too, since an untrusted root may lie below them (`ro ~` with
/// `~/.cache/tool` granted `rw` by another profile).
///
/// A kept `rw` mount whose own host source runs through a symlink inside
/// an untrusted root is dropped here too, with [`SpecWarning::SourceLink`]:
/// that is [`check_host_sources`]'s rule (which refuses such a restrictive
/// mount), applied here so that the dropped mount is never an ancestor.
/// Likewise an `rw` mount whose host source cannot be resolved is dropped
/// with [`SpecWarning::SourceUnresolved`]. Before its destination is even
/// checked, a mount (of any mode but `masked`, which shows nothing of its
/// source) whose source cannot be resolved because a final link's target
/// is missing is dropped the same way: it mounts nothing, as for a missing
/// path, even if the link lies inside an untrusted root.
///
/// Before any of that, a mount of a link matched by a glob that lies inside
/// an untrusted root is dropped with [`SpecWarning::GlobLink`], whatever its
/// mode (see [`glob_link_in_root`]). It is dropped after the winner at its
/// sandbox path was picked, so nothing is mounted there: any literal rule
/// at that path would have won, and every other glob candidate there was
/// outranked. Nothing is lost by that: the sandbox path shows the link
/// through the mount underneath, and the glob walk reached the real files
/// under their own names.
///
/// A dropped mount is not an ancestor of later mounts: mounts are checked
/// in plan order, parents first, so those below it are checked against the
/// mount that is actually underneath them (for a destination link, they
/// meet the same link: an error for a restrictive one, a drop for an `rw`
/// one). A dropped `rw` mount's host source stays an untrusted root (the
/// roots were collected from the plans as planned): that only refuses more
/// links, never fewer.
fn check_destination_links(
    mounts: Vec<PlannedMount>,
    ws_sandbox: &Path,
    roots: &UntrustedRoots,
    warnings: &mut Vec<SpecWarning>,
) -> Result<Vec<PlannedMount>, SpecError> {
    let mut underneath: BTreeMap<PathBuf, Underneath> = BTreeMap::new();
    let mut kept = Vec::with_capacity(mounts.len());
    for m in mounts {
        if m.glob_link {
            if let Some(found) = glob_link_in_root(&m, roots) {
                warnings.push(SpecWarning::GlobLink(found));
                continue;
            }
        }
        // The canonical host source of a mount that shows one. A masked
        // mount shows nothing of its source; `check_host_sources` resolves
        // it.
        let resolved = match &m.source {
            MountSource::Host { path, .. } if m.mode != PathMode::Masked => {
                match resolve_host_source(path, roots) {
                    // A final link whose target is missing has nothing to
                    // show or hide, as for a missing path, whatever the mode
                    // and wherever the link lies (a planted dangling link
                    // too). Skipped before its destination is checked: it
                    // mounts nothing there.
                    Err(u) if is_missing(u.error.kind()) => {
                        let found = source_unresolved(&m, path, u);
                        warnings.push(SpecWarning::SourceUnresolved(found));
                        continue;
                    }
                    other => Some(other),
                }
            }
            _ => None,
        };
        let ancestor = m
            .sandbox
            .ancestors()
            .skip(1)
            .find_map(|a| match underneath.get_key_value(a)? {
                (a, Underneath::Host { mode, source }) => Some(Some((a, *mode, source))),
                (_, Underneath::Unchecked) => Some(None),
            })
            .flatten()
            .map(|(a, mode, source)| (a.clone(), mode, source.clone()));
        if let Some((ancestor, mode, source)) = ancestor {
            let rel = m
                .sandbox
                .strip_prefix(&ancestor)
                .expect("an ancestor is a prefix");
            let refused = m.mode != PathMode::Rw;
            match find_destination_link(&source, rel, roots) {
                Ok(()) => {}
                Err(DestinationProblem::Link { link, root }) => {
                    let found = Box::new(DestinationLink {
                        provider: m.provider.clone(),
                        mode: m.mode,
                        sandbox: m.sandbox.clone(),
                        host: source.join(rel),
                        link,
                        ancestor,
                        ancestor_mode: mode,
                        ancestor_source: source,
                        root: root.clone(),
                    });
                    if refused {
                        return Err(SpecError::DestinationLinkFollowed(found));
                    }
                    warnings.push(SpecWarning::DestinationLink(found));
                    continue;
                }
                Err(DestinationProblem::Unchecked { path, error }) if !refused => {
                    warnings.push(SpecWarning::DestinationUnchecked {
                        provider: m.provider.clone(),
                        sandbox: m.sandbox.clone(),
                        path,
                        error,
                    });
                    continue;
                }
                Err(DestinationProblem::Unchecked { path, error }) => {
                    // The walk inspects every directory before passing
                    // through it, so the one containing `path` can be
                    // inspected but not searched. Masking it hides `path`
                    // and the rest of the way, and bwrap reaches the mask's
                    // own mount point without searching it.
                    let masked_host = path
                        .parent()
                        .expect("the walk starts below the ancestor's source")
                        .to_owned();
                    let below = masked_host
                        .strip_prefix(&source)
                        .expect("the walk stays below the ancestor's source");
                    let masked = join_rel(&ancestor, below);
                    warnings.push(SpecWarning::DestinationMasked(Box::new(
                        DestinationMasked {
                            provider: m.provider.clone(),
                            mode: m.mode,
                            sandbox: m.sandbox.clone(),
                            path,
                            error,
                            masked: masked.clone(),
                            masked_host: masked_host.clone(),
                        },
                    )));
                    // Nothing kept lies below `masked` yet: every mount
                    // there would have met the same directory first. If it
                    // is the ancestor's own path (its source cannot be
                    // searched), the mask replaces the ancestor, which is
                    // reported louder: the whole grant is gone.
                    if let Some(i) = kept.iter().position(|k: &PlannedMount| k.sandbox == masked) {
                        let hidden = kept.remove(i);
                        warnings.push(SpecWarning::GrantHidden(Box::new(GrantHidden {
                            workspace: hidden.sandbox == ws_sandbox,
                            provider: hidden.provider,
                            mode: hidden.mode,
                            sandbox: hidden.sandbox,
                            dir: masked_host.clone(),
                        })));
                    }
                    kept.push(PlannedMount {
                        sandbox: masked.clone(),
                        source: MountSource::Host {
                            path: masked_host,
                            kind: EntryKind::Dir,
                        },
                        mode: PathMode::Masked,
                        provider: m.provider.clone(),
                        glob_link: false,
                    });
                    underneath.insert(masked, Underneath::Unchecked);
                    // `m` now lies inside the masked directory, where
                    // nothing needs checking, and is kept on top of it.
                }
            }
        }
        let under = match (resolved, &m.source) {
            (Some(Ok(resolved)), MountSource::Host { path, .. }) => {
                // An `rw` source through a link inside a root is dropped
                // here rather than by `check_host_sources`, so that it is
                // never an ancestor: the mounts below it are checked against
                // what is really underneath. A restrictive one is kept, and
                // refused there.
                if m.mode == PathMode::Rw {
                    if let Some(followed) = resolved.untrusted.first() {
                        let found = link_followed(&m, path, &resolved.path, followed);
                        warnings.push(SpecWarning::SourceLink(found));
                        continue;
                    }
                }
                Underneath::Host {
                    mode: m.mode,
                    source: resolved.path,
                }
            }
            // Dropping an `rw` grant only removes access. Dropped here, so
            // that it is never an ancestor.
            (Some(Err(u)), MountSource::Host { path, .. }) if m.mode == PathMode::Rw => {
                warnings.push(SpecWarning::SourceUnresolved(source_unresolved(
                    &m, path, u,
                )));
                continue;
            }
            // `check_host_sources` rejects this mount (or drops it inside a
            // masked directory), which is kept.
            (Some(Err(_)), _) => Underneath::Unchecked,
            (Some(Ok(_)), MountSource::Ephemeral { .. }) => {
                unreachable!("only a host source is resolved")
            }
            // A masked one.
            (None, MountSource::Host { .. }) => Underneath::Unchecked,
            // TODO(ephemeral backing directories, DESIGN.md §2.1, §11): an
            // ephemeral mount is backed by a session directory the sandbox
            // writes, so links in it are untrusted too, but it does not exist
            // yet. Once it does, check below it like a host tree inside a
            // root.
            (None, MountSource::Ephemeral { .. }) => Underneath::Unchecked,
        };
        underneath.insert(m.sandbox.clone(), under);
        kept.push(m);
    }
    // Masks synthesized over directories that cannot be searched were added
    // after deeper mounts; restore the plan's order.
    sort_plan(&mut kept);
    Ok(kept)
}

/// For the mount `m` of a link matched by a glob
/// ([`PlannedMount::glob_link`]), the [`GlobLink`] to skip it with if the
/// link lies inside one of `roots` and the way to it runs through no link
/// inside a root.
///
/// A link outside every root is the host's (a home-manager link matched by
/// `~/.config/*`), and is kept and followed. A way that runs through a link
/// inside a root (a glob whose literal prefix or walk root is a planted
/// link in an `rw` grant; in the workspace the planner refuses it before
/// walking), or that cannot be resolved, is left to the destination and
/// host-source checks, which refuse it like any rule's: the walk did not
/// reach the real files there, but whatever the planted link leads to.
fn glob_link_in_root(m: &PlannedMount, roots: &UntrustedRoots) -> Option<Box<GlobLink>> {
    let MountSource::Host { path: host, .. } = &m.source else {
        return None;
    };
    let name = host.file_name()?;
    let parent = resolve_host_source(host.parent()?, roots).ok()?;
    if !parent.untrusted.is_empty() {
        return None;
    }
    let root = roots.containing(&parent.path)?;
    Some(Box::new(GlobLink {
        provider: m.provider.clone(),
        mode: m.mode,
        host: host.clone(),
        link: parent.path.join(name),
        sandbox: m.sandbox.clone(),
        root: root.clone(),
    }))
}

/// What [`find_destination_link`] found on the way to a destination.
enum DestinationProblem<'r> {
    /// A symlink inside an untrusted root.
    Link {
        /// The link, named below its canonical parent directory.
        link: PathBuf,
        /// The innermost root containing it.
        root: &'r UntrustedRoot,
    },
    /// A path that exists but cannot be inspected.
    Unchecked {
        /// The path.
        path: PathBuf,
        /// The error inspecting it.
        error: io::Error,
    },
}

/// Walks `rel` below the canonical host directory `source`, one component
/// at a time and the final one included, up to the first symlink, and
/// reports that link if it lies inside one of `roots` (see
/// [`check_destination_links`]). A missing component, or one below a
/// non-directory, ends the walk.
fn find_destination_link<'r>(
    source: &Path,
    rel: &Path,
    roots: &'r UntrustedRoots,
) -> Result<(), DestinationProblem<'r>> {
    let mut path = source.to_owned();
    let mut components = rel.components().peekable();
    while let Some(c) = components.next() {
        path.push(c);
        let meta = match path.symlink_metadata() {
            Ok(meta) => meta,
            Err(error) if is_missing(error.kind()) => return Ok(()),
            Err(error) => return Err(DestinationProblem::Unchecked { path, error }),
        };
        if meta.is_symlink() {
            let parent = path.parent().expect("a link below `source` has a parent");
            return match roots.containing(parent) {
                Some(root) => Err(DestinationProblem::Link { link: path, root }),
                None => Ok(()),
            };
        }
        // Like the kernel, only a directory can be passed through.
        if components.peek().is_some() && !meta.is_dir() {
            return Ok(());
        }
    }
    Ok(())
}

/// The kernel's limit on symlinks followed in one path lookup
/// (`MAXSYMLINKS`).
const MAX_SYMLINKS: usize = 40;

/// A host source resolved by [`resolve_host_source`].
#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedSource<'r> {
    /// The canonical path.
    path: PathBuf,
    /// The kind of entry at `path` (never [`EntryKind::Symlink`]).
    kind: EntryKind,
    /// Every symlink followed that lies inside an untrusted root, in the
    /// order the lookup followed them.
    untrusted: Vec<UntrustedLink<'r>>,
}

/// A symlink inside an untrusted root that a lookup followed.
///
/// Every such link is reported with its root, not just the first, so that
/// a per-rule opt-in can later accept links whose targets stay inside
/// their own root.
#[derive(Debug, Clone, PartialEq, Eq)]
struct UntrustedLink<'r> {
    /// The link, named below its canonical parent directory.
    link: PathBuf,
    /// The innermost root containing it.
    root: &'r UntrustedRoot,
}

/// Why [`resolve_host_source`] failed.
#[derive(Debug)]
struct Unresolved<'r> {
    /// The lookup's error.
    error: io::Error,
    /// The path the lookup failed at: the entry it could not inspect or
    /// read, the link past the limit, or the non-directory it had to pass
    /// through.
    path: PathBuf,
    /// Every symlink inside an untrusted root the lookup followed before it
    /// failed, in order (see [`ResolvedSource::untrusted`]).
    untrusted: Vec<UntrustedLink<'r>>,
}

/// Resolves the absolute host path `path` as the kernel would, one
/// component at a time, following every symlink (the final one included).
/// Returns the canonical path and every symlink followed that lies inside
/// one of `roots` (each link is attributed to the innermost root containing
/// its canonical parent directory).
///
/// Walking by hand rather than canonicalising sees every link the lookup
/// passes, including ones a link outside the roots leads through (a link to
/// a path inside the workspace that has itself been replaced by a link):
/// checking prefixes of the path as written would miss those. It
/// costs one `lstat` per component and one `readlink` per link, the
/// components of link targets included. Errors are those of the lookup
/// (`ENOTDIR` for a component below a non-directory or a trailing `/` or
/// `/.` after one, `ELOOP` past [`MAX_SYMLINKS`] links), with the untrusted
/// links followed until then ([`Unresolved`]), so that a planted link the
/// lookup failed after is still known.
///
/// Links are followed by their text, so `/proc` magic links
/// (`/proc/<pid>/root`, `/proc/self/fd/N`), which the kernel follows to the
/// object they refer to rather than to the path `readlink` shows, resolve
/// differently here than when mounted (DESIGN.md §11).
fn resolve_host_source<'r>(
    path: &Path,
    roots: &'r UntrustedRoots,
) -> Result<ResolvedSource<'r>, Unresolved<'r>> {
    /// Pushes `path`'s components onto `pending` so they pop in order.
    /// `Path::components` drops a trailing `/` or `/.`, which requires a
    /// directory, so it is kept as a final `.`.
    fn push(pending: &mut Vec<OsString>, path: &Path) {
        let bytes = path.as_os_str().as_bytes();
        if bytes.len() > 1 && (bytes.ends_with(b"/") || bytes.ends_with(b"/.")) {
            pending.push(".".into());
        }
        pending.extend(path.components().rev().map(|c| c.as_os_str().to_owned()));
    }
    debug_assert!(path.is_absolute(), "{path:?} is not absolute");
    let mut resolved = PathBuf::from("/");
    // The kind of entry at `resolved`; any component after it requires a
    // directory.
    let mut kind = EntryKind::Dir;
    let mut pending = Vec::new();
    push(&mut pending, path);
    let mut links = 0;
    let mut untrusted = Vec::new();
    let fail = |error: io::Error, path: PathBuf, untrusted| Unresolved {
        error,
        path,
        untrusted,
    };
    while let Some(name) = pending.pop() {
        if name == "/" {
            (resolved, kind) = (PathBuf::from("/"), EntryKind::Dir);
            continue;
        }
        if kind != EntryKind::Dir {
            return Err(fail(Errno::NOTDIR.into(), resolved, untrusted));
        }
        // `resolved` is canonical, so `..` is its lexical parent. A `Normal`
        // component is never `/`, `.` or `..`.
        if name == "." {
            continue;
        } else if name == ".." {
            // Every ancestor of a canonical path is a directory.
            resolved.pop();
            continue;
        }
        let next = resolved.join(&name);
        let meta = match next.symlink_metadata() {
            Ok(meta) => meta,
            Err(error) => return Err(fail(error, next, untrusted)),
        };
        if !meta.is_symlink() {
            (resolved, kind) = (next, EntryKind::from_file_type(meta.file_type()));
            continue;
        }
        links += 1;
        if links > MAX_SYMLINKS {
            return Err(fail(Errno::LOOP.into(), next, untrusted));
        }
        let target = match fs::read_link(&next) {
            Ok(target) => target,
            Err(error) => return Err(fail(error, next, untrusted)),
        };
        if let Some(root) = roots.containing(&resolved) {
            untrusted.push(UntrustedLink { link: next, root });
        }
        push(&mut pending, &target);
    }
    Ok(ResolvedSource {
        path: resolved,
        kind,
        untrusted,
    })
}

/// The first symlink inside the host directory `root` (canonical) that
/// resolving the absolute host path `path` follows, as
/// [`resolve_host_source`] finds it, named below its canonical parent
/// directory. Errors are those of the lookup.
///
/// The planner uses it to refuse a glob's walk root running through a link
/// inside the host workspace before walking (see
/// [`plan_mounts`]).
pub(crate) fn first_link_inside(path: &Path, root: &Path) -> io::Result<Option<PathBuf>> {
    let roots = UntrustedRoots::new(root);
    let resolved = resolve_host_source(path, &roots).map_err(|u| u.error)?;
    Ok(resolved.untrusted.into_iter().next().map(|l| l.link))
}

/// Whether `path` (to protect, canonical), whose `meta` it is, is a regular
/// file with other hard links through which a sandbox could rewrite it: one
/// the user owns (who can make it writable whatever its mode) or can write
/// (`faccessat(W_OK, AT_EACCESS)`, so ACLs count). Files of other owners the
/// user cannot write, such as Nix store files deduplicated into hard links
/// by `auto-optimise-store`, cannot be rewritten through any name.
pub(crate) fn has_rewritable_hard_links(path: &Path, meta: &fs::Metadata) -> bool {
    use rustix::fs::{Access, AtFlags, CWD, accessat};
    meta.is_file()
        && meta.nlink() > 1
        && (meta.uid() == rustix::process::getuid().as_raw()
            || accessat(CWD, path, Access::WRITE_OK, AtFlags::EACCESS).is_ok())
}

/// Why [`resolve_script_path`] did not resolve a path.
#[derive(Debug)]
pub(crate) enum ScriptPathError {
    /// The lookup followed a symlink inside an untrusted root, whether it
    /// then succeeded or not.
    Link {
        /// The first such link, named below its canonical parent directory.
        link: PathBuf,
        /// The innermost root containing it.
        root: UntrustedRoot,
    },
    /// The lookup failed, without following a link inside a root first.
    Lookup(io::Error),
}

/// Resolves the absolute host path `path` (a script provider's source) to
/// its canonical path, as [`resolve_host_source`] does, unless the lookup
/// follows a symlink inside the host `workspace` (canonical) or one of
/// `rw_grants` (canonical roots): then the first such link is the error,
/// even if the lookup fails after following it, since a link a sandbox
/// planted may be what makes it fail.
pub(crate) fn resolve_script_path(
    path: &Path,
    workspace: &Path,
    rw_grants: &[UntrustedRoot],
) -> Result<PathBuf, ScriptPathError> {
    let mut roots = UntrustedRoots::new(workspace);
    for root in rw_grants {
        if !roots.roots.iter().any(|r| r.path == root.path) {
            roots.roots.push(root.clone());
        }
    }
    let link = |untrusted: Vec<UntrustedLink<'_>>| {
        untrusted.into_iter().next().map(|l| ScriptPathError::Link {
            link: l.link,
            root: l.root.clone(),
        })
    };
    match resolve_host_source(path, &roots) {
        Ok(resolved) => match link(resolved.untrusted) {
            Some(e) => Err(e),
            None => Ok(resolved.path),
        },
        Err(u) => Err(link(u.untrusted).unwrap_or(ScriptPathError::Lookup(u.error))),
    }
}

/// The host directories that the `rw` grants of `outputs` (the `config`
/// providers', known before any script runs) let a sandbox write, as
/// untrusted roots: every `fs.rw` path and the host side of every `rw`
/// bind, of the top-level grants and of every contributed profile, each
/// canonicalised. A glob counts as its walk root (its literal prefix), a
/// superset of what it matches. A path that cannot be resolved is not a
/// root, as in [`UntrustedRoots::add_rw_mounts`].
///
/// The supervisor refuses a script provider reached through a link inside
/// one of them (DESIGN.md §3.6); the session's other roots, those of script
/// providers' grants, are only known once the scripts have run.
pub fn static_rw_roots(
    outputs: &[(ProviderName, ProviderOutput)],
    ctx: &ExpansionContext,
) -> Vec<UntrustedRoot> {
    let none = UntrustedRoots::none();
    let mut roots: Vec<UntrustedRoot> = Vec::new();
    for (provider, output) in outputs {
        let manifest = &output.manifest;
        let profiles = std::iter::once((output.profile.clone(), &manifest.grants)).chain(
            manifest
                .profiles
                .iter()
                .map(|(name, p)| (ProfileRef::contributed(provider, name), &p.grants)),
        );
        for (profile, grants) in profiles {
            let rw = grants.fs.rw.iter().filter_map(|p| {
                let e = expand_pattern(p, ctx);
                e.host().or_else(|| e.walk_root())
            });
            let binds = grants
                .fs
                .bind
                .iter()
                .filter(|b| b.mode == BindMode::Rw)
                .map(|b| expand_bind(b, ctx).host);
            for host in rw.chain(binds) {
                let Ok(resolved) = resolve_host_source(&host, &none) else {
                    continue;
                };
                if roots.iter().any(|r| r.path == resolved.path) {
                    continue;
                }
                roots.push(UntrustedRoot {
                    path: resolved.path,
                    kind: UntrustedKind::RwGrant {
                        provider: provider.clone(),
                        profile: Some(profile.clone()),
                        host,
                    },
                });
            }
        }
    }
    roots
}

/// Checks the workspace mount point and sandbox `HOME` against the
/// reserved-path rules of DESIGN.md §6.2.
///
/// A workspace inside `home` or `/tmp`, and a `HOME` inside `/tmp`, are
/// allowed. Paths are compared by component, so `/procfs` is not inside
/// `/proc`.
fn check_reserved_paths(workspace: &Path, home: &Path) -> Result<(), SpecError> {
    for (which, path) in [(PathRole::Workspace, workspace), (PathRole::Home, home)] {
        let fail = |reason| SpecError::ReservedPath {
            which,
            path: path.to_owned(),
            reason,
        };
        if let Some(r) = reserved_paths().find(|r| Path::new(r).starts_with(path)) {
            return Err(fail(ReservedReason::CoversReserved(PathBuf::from(r))));
        }
        if let Some(r) = reserved_dirs().find(|r| path.starts_with(r)) {
            return Err(fail(ReservedReason::InsideReserved(PathBuf::from(r))));
        }
    }
    let fail = |reason| SpecError::ReservedPath {
        which: PathRole::Home,
        path: home.to_owned(),
        reason,
    };
    if home == workspace {
        return Err(fail(ReservedReason::SameAsWorkspace));
    }
    if home.starts_with(workspace) {
        return Err(fail(ReservedReason::InsideWorkspace(workspace.to_owned())));
    }
    Ok(())
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
///
/// Destinations and host sources are checked against the untrusted roots of
/// this profile alone: the host workspace and the profile's own `rw`
/// mounts. A session
/// must be compiled with [`compile_session`], which checks every profile
/// against the `rw` mounts of all of them. Only tests use this, to pin the
/// difference.
#[cfg(test)]
fn compile_profile(
    grants: &EffectiveGrants,
    parent: Option<&EffectiveGrants>,
    ctx: &ExpansionContext,
    state: &StateDirs,
) -> Result<CompiledProfile, SpecError> {
    let planned = plan_profile(grants, ctx)?;
    let mut roots = UntrustedRoots::new(ctx.workspace_host());
    roots.add_rw_mounts(None, &planned.plan.mounts);
    finish_profile(planned, grants, parent, ctx, &roots, &[], state)
}

/// A profile whose mounts are planned but not yet checked against the
/// session's untrusted roots.
struct PlannedProfile {
    home: SandboxHome,
    plan: MountPlan,
}

/// The first stage of compiling a profile: checks the workspace mount and
/// `HOME` against the reserved paths, plans the mounts and checks their
/// destinations against the reserved paths.
fn plan_profile(
    grants: &EffectiveGrants,
    ctx: &ExpansionContext,
) -> Result<PlannedProfile, SpecError> {
    let home = grants.system.home.clone().unwrap_or_default();
    check_reserved_paths(ctx.workspace_sandbox(), Path::new(home.as_str()))?;
    let plan = plan_mounts(&grants.fs, &ctx.with_sandbox_home(&home))?;
    check_mount_destinations(&plan.mounts)?;
    Ok(PlannedProfile { home, plan })
}

/// The second stage of compiling a profile: checks the planned mounts'
/// destinations, then the host sources of those kept, against `roots`,
/// protects the `protected` sources wherever the sandbox could write them
/// (see [`protect_sources`]), checks every host source against stopit's
/// state directories `state` (see [`check_state_dirs`]), and assembles the
/// spec.
///
/// Destinations come first because their check settles what is mounted
/// (it drops glob-matched links inside untrusted roots, and `rw` mounts for
/// a link on the way to their destination or in their source): a dropped
/// mount's source is not checked, and it exposes nothing. A restrictive mount
/// that fails both checks (a `~` rule below an `rw` grant of its parent,
/// through a planted link) is reported by the destination check.
fn finish_profile(
    planned: PlannedProfile,
    grants: &EffectiveGrants,
    parent: Option<&EffectiveGrants>,
    ctx: &ExpansionContext,
    roots: &UntrustedRoots,
    protected: &[SourceToProtect<'_>],
    state: &StateDirs,
) -> Result<CompiledProfile, SpecError> {
    let PlannedProfile { home, plan } = planned;
    let mut warnings: Vec<SpecWarning> = plan.warnings.into_iter().map(Into::into).collect();
    let mounts =
        check_destination_links(plan.mounts, ctx.workspace_sandbox(), roots, &mut warnings)?;
    let mounts = check_host_sources(mounts, ctx, roots, protected, state, &mut warnings)?;
    let inherited_domains = parent.map(|p| &p.network.allow_domains);
    let network = network_spec(&grants.network, inherited_domains, &mut warnings);
    let spec = SandboxSpec {
        mounts,
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
    /// A path a provider asked to be protected (a script provider's source)
    /// cannot be inspected, so it cannot be protected; it runs on the host,
    /// so this fails closed.
    #[error(
        "cannot inspect {path:?}, the source of provider {:?}, to protect it: {}",
        .provider.as_str(),
        io::Error::from(*.kind)
    )]
    ProtectedSource {
        /// The provider that asked.
        provider: ProviderName,
        /// The path.
        path: PathBuf,
        /// What went wrong.
        kind: io::ErrorKind,
    },
    /// A path a provider asked to be protected is a regular file with more
    /// than one hard link: the sandbox could rewrite it through another
    /// name, inside an `rw` tree, which protecting this one cannot prevent
    /// (DESIGN.md §3.6).
    #[error(
        "refusing to protect {path:?}, the source of provider {:?}: it has {links} hard links, so \
         a sandbox could rewrite it through another name that no protection covers; give it a \
         single link (copy it, then replace the original with the copy)",
        .provider.as_str()
    )]
    ProtectedSourceHardLinked {
        /// The provider that asked.
        provider: ProviderName,
        /// The path.
        path: PathBuf,
        /// Its number of hard links.
        links: u64,
    },
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
/// profile's grants, and compiles each profile as `compile_profile` does,
/// except that mount destinations and host sources are checked against the
/// untrusted roots of the whole session: the host workspace and the `rw`
/// mounts of every profile, since a sandbox of one profile can plant links
/// that a mount of another follows (DESIGN.md §3.4, Symlinks). So every
/// profile's mounts are planned first, then every profile's destinations
/// and host sources are checked.
///
/// `protected` are the paths providers asked to be protected (see
/// [`protected_sources`](crate::provider::protected_sources)): each is
/// protected in every profile, wherever the profile would let the sandbox
/// write it, whatever the providers grant (see [`protect_sources`]). One
/// that cannot be inspected is an error, and so is a regular file with more
/// than one hard link ([`CompileError::ProtectedSourceHardLinked`]). Hard
/// links to files inside a protected directory are not detected (DESIGN.md
/// §11).
///
/// `state` are stopit's own host state directories, which no mount may
/// show (see [`check_state_dirs`]); their paths must be resolved (see
/// [`StateDirs`]).
///
/// Stops at the first failing stage, and within each of the two profile
/// stages at the first failing profile in graph order.
pub fn compile_session(
    config: &Config,
    outputs: Vec<(ProviderName, ProviderOutput)>,
    protected: &[ProtectedSource],
    state: &StateDirs,
    ctx: &ExpansionContext,
) -> Result<CompiledSession, CompileError> {
    let graph = build_profile_graph(config, outputs)?;
    let merged = merge_profiles(&graph)?;
    let protected = protected
        .iter()
        .map(|p| match p.path.symlink_metadata() {
            Ok(meta) if has_rewritable_hard_links(&p.path, &meta) => {
                Err(CompileError::ProtectedSourceHardLinked {
                    provider: p.provider.clone(),
                    path: p.path.clone(),
                    links: meta.nlink(),
                })
            }
            Ok(meta) => Ok(SourceToProtect {
                provider: &p.provider,
                path: &p.path,
                kind: EntryKind::from_file_type(meta.file_type()),
            }),
            Err(e) => Err(CompileError::ProtectedSource {
                provider: p.provider.clone(),
                path: p.path.clone(),
                kind: e.kind(),
            }),
        })
        .collect::<Result<Vec<_>, _>>()?;
    debug_assert!(
        protected.iter().all(|p| p.kind != EntryKind::Symlink),
        "protected sources are canonical"
    );
    let fail = |profile: &ProfileRef| {
        let profile = profile.clone();
        move |error| CompileError::Profile {
            profile,
            error: Box::new(error),
        }
    };
    let mut planned = Vec::with_capacity(merged.order().len());
    let mut roots = UntrustedRoots::new(ctx.workspace_host());
    for (profile, grants) in merged.iter() {
        let p = plan_profile(grants, ctx).map_err(fail(profile))?;
        roots.add_rw_mounts(Some(profile), &p.plan.mounts);
        planned.push(p);
    }
    let mut profiles = BTreeMap::new();
    for ((profile, grants), p) in merged.iter().zip(planned) {
        let parent = graph
            .get(profile)
            .and_then(|node| node.parent.as_ref())
            .map(|p| merged.get(p).expect("every parent is a merged profile"));
        let compiled = finish_profile(p, grants, parent, ctx, &roots, &protected, state)
            .map_err(fail(profile))?;
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
    use crate::expand::ResolveWarning;
    use crate::policy::PathMode::{self, Ephemeral, Masked, Protected, Ro, Rw};
    use crate::provider::{ProviderContext, session_providers};
    use crate::resolve::{EphemeralKey, MountSource, PlanWarningKind};
    use crate::state::{DataDirs, StatePath};

    /// The source of an ephemeral mount whose rule was written as `pattern`.
    fn eph_source(pattern: &str) -> MountSource {
        MountSource::Ephemeral {
            key: EphemeralKey::new(&pattern.parse().unwrap()),
        }
    }

    /// A temporary workspace and host home, with an expansion context
    /// mapping them to the workspace mount (`/workspace` by default) and
    /// `/home/user`.
    struct Fixture {
        _dir: TempDir,
        root: PathBuf,
        /// The workspace, relative to `root`.
        ws_rel: &'static str,
        /// The workspace mount.
        ws_mount: &'static str,
        ctx: ExpansionContext,
        /// stopit's state directories: `run/stopit` (created) and the
        /// data directory at its default location in the fixture's home,
        /// `home/.local/share/stopit` (not created), with no override.
        state: StateDirs,
    }

    impl Fixture {
        fn new() -> Self {
            Self::with_workspace("ws", "/workspace")
        }

        /// A fixture whose workspace is `ws_rel` below the temp root (e.g.
        /// below `home`), mounted at `ws_mount`.
        fn with_workspace(ws_rel: &'static str, ws_mount: &'static str) -> Self {
            let dir = TempDir::new().unwrap();
            let root = dir.path().canonicalize().unwrap();
            fs::create_dir_all(root.join(ws_rel)).unwrap();
            fs::create_dir_all(root.join("home")).unwrap();
            let ctx = ExpansionContext::new(
                root.join(ws_rel),
                ws_mount.parse().unwrap(),
                root.join("home"),
                "/home/user".parse().unwrap(),
            )
            .unwrap();
            fs::create_dir_all(root.join("run/stopit")).unwrap();
            let state = StateDirs {
                runtime: StatePath::canonical(root.join("run/stopit")),
                data: DataDirs::canonical(root.join("home/.local/share/stopit")),
            };
            Fixture {
                _dir: dir,
                root,
                ws_rel,
                ws_mount,
                ctx,
                state,
            }
        }

        fn ws(&self) -> PathBuf {
            self.root.join(self.ws_rel)
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
                workspace_mount: self.ws_mount.parse().unwrap(),
                home: self.root.join("home"),
                session_dir: self.root.join("session"),
                rw_grants: Vec::new(),
            };
            session_providers(cfg, Path::new("/cfg"))
                .unwrap()
                .iter()
                .map(|p| (p.name().clone(), p.manifest(&pctx).unwrap()))
                .collect()
        }

        fn try_compile(&self, src: &str) -> Result<CompiledSession, CompileError> {
            self.try_compile_protecting(src, &[])
        }

        /// Compiles `src` with the paths below the temp root `protected`
        /// asked to be protected, each by the provider named with it.
        fn try_compile_protecting(
            &self,
            src: &str,
            protected: &[(&str, &str)],
        ) -> Result<CompiledSession, CompileError> {
            let cfg = Config::from_toml_str(src).unwrap();
            let protected: Vec<ProtectedSource> = protected
                .iter()
                .map(|(provider, rel)| ProtectedSource {
                    provider: provider.parse().unwrap(),
                    path: self.root.join(rel),
                })
                .collect();
            compile_session(&cfg, self.outputs(&cfg), &protected, &self.state, &self.ctx)
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
        assert_eq!(spec.mounts[0].source, eph_source("/tmp"));
        assert_eq!(spec.mounts[2].source, eph_source("~"));
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
    fn default_base_leaves_home_settable_by_user_providers() {
        let f = Fixture::new();
        // The default base does not set `system.home`; the spec defaults it.
        let s = f.compile("");
        assert_eq!(spec(&s, "main").system.home.as_str(), "/home/user");

        // So a user provider can move `main`'s HOME without a conflict, and
        // the base's ephemeral `~` follows it.
        let s = f.compile(&prov("u", "main", "system.home = \"/home/agent\""));
        let main = spec(&s, "main");
        assert_eq!(main.system.home.as_str(), "/home/agent");
        assert_eq!(
            mounts(main),
            [
                row("/tmp", Ephemeral, "base"),
                row("/workspace", Rw, "base"),
                row("/home/agent", Ephemeral, "base"),
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
            "ws/sub/.stopit.toml",
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
                row("/workspace/sub/.stopit.toml", Protected, "base"),
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
            "ws/sub/.stopit.toml",
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
            row("/workspace/.stopit.toml", Protected, "base"),
            row("/workspace/sub/.stopit.toml", Protected, "base"),
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
        let c = compile_profile(&grants, None, &f.ctx, &f.state).unwrap();
        assert_eq!(c.spec.network, NetworkSpec::None);
        assert!(
            matches!(c.warnings.as_slice(), [SpecWarning::DomainsIgnored { domains: d, .. }] if *d == grants.network.allow_domains),
            "{:?}",
            c.warnings
        );
        // The same grants with that domain inherited: no warning.
        let parent = grants.clone();
        let c = compile_profile(&grants, Some(&parent), &f.ctx, &f.state).unwrap();
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
        // Both HOMEs share one backing directory: the key is the pattern as
        // written, not its expansion.
        assert_eq!(main.mounts[1].source, eph_source("~"));
        assert_eq!(harness.mounts[1].source, main.mounts[1].source);
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
        f.file("home/a");
        f.file("home/b");
        let e = f.compile_err(&format!(
            "[profiles.harness]\n{}",
            prov(
                "p",
                "harness",
                "fs.bind = [\n\
                 { host = \"~/a\", sandbox = \"/opt/x\", mode = \"ro\" },\n\
                 { host = \"~/b\", sandbox = \"/opt/x\", mode = \"ro\" },\n]"
            ),
        ));
        let CompileError::Profile { profile, error } = &e else {
            panic!("expected a profile error, got {e:?}");
        };
        assert_eq!(profile, &pr("harness"));
        assert!(
            matches!(**error, SpecError::Mounts(PathPlanError::Conflict(ref c)) if c.sandbox == Path::new("/opt/x")),
            "{error:?}"
        );
        let msg = e.to_string();
        assert!(
            msg.starts_with(r#"cannot compile profile "harness": sandbox path "/opt/x" is mapped"#),
            "{msg}"
        );
    }

    #[test]
    fn reserved_path_check_accepts_and_rejects() {
        use ReservedReason::*;
        let p = |s: &str| PathBuf::from(s);
        let covers = |r: &str| CoversReserved(p(r));
        let inside = |r: &str| InsideReserved(p(r));

        for (w, h) in [
            ("/workspace", "/home/user"),
            ("/home/user/proj", "/home/user"),
            ("/tmp/ws", "/home/user"),
            ("/workspace", "/tmp/home"),
            ("/procfs", "/home/user"),
            ("/workspace", "/etcetera"),
            ("/srv/run/stopit", "/home/user"),
            ("/run/other", "/home/user"),
            ("/workspace", "/workspace2"),
            ("/tmp/h/ws", "/tmp/h"),
        ] {
            assert_eq!(check_reserved_paths(&p(w), &p(h)), Ok(()), "W={w} H={h}");
        }

        // (workspace, home, which, path, reason)
        let rejected = [
            ("/", "/home/user", PathRole::Workspace, "/", covers("/proc")),
            (
                "/proc",
                "/home/user",
                PathRole::Workspace,
                "/proc",
                covers("/proc"),
            ),
            (
                "/proc/x",
                "/home/user",
                PathRole::Workspace,
                "/proc/x",
                inside("/proc"),
            ),
            (
                "/dev/shm",
                "/home/user",
                PathRole::Workspace,
                "/dev/shm",
                inside("/dev"),
            ),
            (
                "/dev",
                "/home/user",
                PathRole::Workspace,
                "/dev",
                covers("/dev"),
            ),
            (
                "/etc",
                "/home/user",
                PathRole::Workspace,
                "/etc",
                covers("/etc"),
            ),
            (
                "/etc/foo",
                "/home/user",
                PathRole::Workspace,
                "/etc/foo",
                inside("/etc"),
            ),
            (
                "/tmp",
                "/home/user",
                PathRole::Workspace,
                "/tmp",
                covers("/tmp"),
            ),
            (
                "/run",
                "/home/user",
                PathRole::Workspace,
                "/run",
                covers("/run/stopit"),
            ),
            (
                "/run/stopit",
                "/home/user",
                PathRole::Workspace,
                "/run/stopit",
                covers("/run/stopit"),
            ),
            (
                "/run/stopit/x",
                "/home/user",
                PathRole::Workspace,
                "/run/stopit/x",
                inside("/run/stopit"),
            ),
            ("/workspace", "/", PathRole::Home, "/", covers("/proc")),
            (
                "/workspace",
                "/proc",
                PathRole::Home,
                "/proc",
                covers("/proc"),
            ),
            (
                "/workspace",
                "/dev/shm",
                PathRole::Home,
                "/dev/shm",
                inside("/dev"),
            ),
            (
                "/workspace",
                "/etc/x",
                PathRole::Home,
                "/etc/x",
                inside("/etc"),
            ),
            ("/workspace", "/tmp", PathRole::Home, "/tmp", covers("/tmp")),
            (
                "/workspace",
                "/run",
                PathRole::Home,
                "/run",
                covers("/run/stopit"),
            ),
            (
                "/workspace",
                "/run/stopit/x",
                PathRole::Home,
                "/run/stopit/x",
                inside("/run/stopit"),
            ),
            ("/same", "/same", PathRole::Home, "/same", SameAsWorkspace),
            (
                "/ws",
                "/ws/home",
                PathRole::Home,
                "/ws/home",
                InsideWorkspace(p("/ws")),
            ),
        ];
        for (w, h, which, path, reason) in rejected {
            assert_eq!(
                check_reserved_paths(&p(w), &p(h)),
                Err(SpecError::ReservedPath {
                    which,
                    path: p(path),
                    reason
                }),
                "W={w} H={h}"
            );
        }
    }

    #[test]
    fn reserved_path_messages_quote_the_path_and_name_the_rule() {
        let e = check_reserved_paths(Path::new("/workspace"), Path::new("/etc/x")).unwrap_err();
        assert_eq!(
            e.to_string(),
            r#"sandbox home (system.home) "/etc/x" is inside the reserved path "/etc""#
        );
        let e = check_reserved_paths(Path::new("/run"), Path::new("/home/user")).unwrap_err();
        assert_eq!(
            e.to_string(),
            r#"workspace mount "/run" is or contains the reserved path "/run/stopit""#
        );
        let e = check_reserved_paths(Path::new("/a"), Path::new("/a/b")).unwrap_err();
        assert_eq!(
            e.to_string(),
            r#"sandbox home (system.home) "/a/b" is inside the workspace mount "/a""#
        );
    }

    #[test]
    fn reserved_path_errors_name_the_profile() {
        let f = Fixture::new();
        // The fixture's workspace mount is `/workspace`.
        for (home, reason) in [
            ("/etc/x", ReservedReason::InsideReserved("/etc".into())),
            ("/workspace", ReservedReason::SameAsWorkspace),
            (
                "/workspace/home",
                ReservedReason::InsideWorkspace("/workspace".into()),
            ),
        ] {
            let e = f.compile_err(&format!(
                "[profiles.harness]\n{}",
                prov("p", "harness", &format!("system.home = \"{home}\"")),
            ));
            let CompileError::Profile { profile, error } = &e else {
                panic!("expected a profile error, got {e:?}");
            };
            assert_eq!(profile, &pr("harness"), "{home}");
            assert_eq!(
                **error,
                SpecError::ReservedPath {
                    which: PathRole::Home,
                    path: home.into(),
                    reason
                }
            );
            assert!(
                e.to_string()
                    .starts_with(r#"cannot compile profile "harness": sandbox home"#),
                "{e}"
            );
        }
        // `main` is unaffected by the child's home.
        f.compile(&format!(
            "[profiles.harness]\n{}",
            prov("p", "harness", "system.home = \"/tmp/h\""),
        ));
    }

    /// Compiles a `base = "none"` session whose only provider, `p`, targets
    /// `main` with `body` as its sandbox grants. Creates `~/x` first, as a
    /// host source for [`bind_at`].
    fn compile_with_rule(f: &Fixture, body: &str) -> Result<CompiledSession, CompileError> {
        f.mkdir("home/x");
        f.try_compile(&format!("base = \"none\"\n{}", prov("p", "main", body)))
    }

    /// A read-only bind of the host's `~/x` at `dest`.
    fn bind_at(dest: &str) -> String {
        format!("fs.bind = [{{ host = \"~/x\", sandbox = \"{dest}\", mode = \"ro\" }}]")
    }

    #[test]
    fn mount_destinations_colliding_with_system_paths_are_rejected() {
        use ReservedReason::*;
        let p = |s: &str| PathBuf::from(s);
        let f = Fixture::new();
        let rejected = [
            ("/proc", CoversReserved(p("/proc"))),
            ("/proc/self", InsideReserved(p("/proc"))),
            ("/dev", CoversReserved(p("/dev"))),
            ("/dev/shm", InsideReserved(p("/dev"))),
            ("/run/stopit/x", InsideReserved(p("/run/stopit"))),
            ("/run/stopit", CoversReserved(p("/run/stopit"))),
            ("/run", CoversReserved(p("/run/stopit"))),
            ("/etc", CoversReserved(p("/etc/passwd"))),
            ("/etc/passwd", CoversReserved(p("/etc/passwd"))),
            ("/etc/hosts", CoversReserved(p("/etc/hosts"))),
            ("/etc/group", CoversReserved(p("/etc/group"))),
            (
                "/etc/nsswitch.conf",
                CoversReserved(p("/etc/nsswitch.conf")),
            ),
        ];
        for (dest, reason) in rejected {
            let e = compile_with_rule(&f, &bind_at(dest)).unwrap_err();
            let CompileError::Profile { profile, error } = &e else {
                panic!("{dest}: expected a profile error, got {e:?}");
            };
            assert_eq!(profile, &pr("main"), "{dest}");
            assert_eq!(
                **error,
                SpecError::ReservedMount {
                    provider: "p".parse().unwrap(),
                    path: p(dest),
                    reason
                },
                "{dest}"
            );
        }
    }

    #[test]
    fn mount_destination_messages_name_provider_path_and_reserved_path() {
        let f = Fixture::new();
        let e = compile_with_rule(&f, &bind_at("/proc/self")).unwrap_err();
        assert_eq!(
            e.to_string(),
            r#"cannot compile profile "main": provider "p": mount destination "/proc/self" is inside the reserved path "/proc""#
        );
        let e = compile_with_rule(&f, &bind_at("/etc")).unwrap_err();
        assert_eq!(
            e.to_string(),
            r#"cannot compile profile "main": provider "p": mount destination "/etc" is or contains the reserved path "/etc/passwd""#
        );
    }

    #[test]
    fn every_mode_and_rule_kind_is_checked_at_the_destination() {
        let f = Fixture::new();
        // An ephemeral rule, and path rules matching the host's /proc and
        // /dev, in several modes.
        for body in [
            "fs.ephemeral = [\"/etc\"]",
            "fs.ro = [\"/proc\"]",
            "fs.rw = [\"/dev\"]",
            "fs.masked = [\"/proc\"]",
            "fs.protected = [\"/dev\"]",
        ] {
            let e = compile_with_rule(&f, body).unwrap_err();
            assert!(
                matches!(
                    e,
                    CompileError::Profile { ref error, .. }
                        if matches!(**error, SpecError::ReservedMount { .. })
                ),
                "{body}: {e:?}"
            );
        }
    }

    #[test]
    fn other_etc_run_and_lookalike_destinations_are_accepted() {
        let f = Fixture::new();
        for dest in [
            "/etc/ssl/certs",
            "/etc/static",
            "/run/user/1000",
            "/procfs",
            "/devices",
            "/run/stopitx",
            "/tmp",
            "/nix/store",
        ] {
            if let Err(e) = compile_with_rule(&f, &bind_at(dest)) {
                panic!("{dest}: {e}");
            }
        }
    }

    /// Compiles a `base = "none"` session whose only provider, `p`, targets
    /// `main` with `body` as its sandbox grants.
    fn compile_body(f: &Fixture, body: &str) -> Result<CompiledSession, CompileError> {
        f.try_compile(&format!("base = \"none\"\n{}", prov("p", "main", body)))
    }

    /// The `(mode, host, resolved, sandbox)` of a `WorkspaceExposed` error,
    /// checking its provider and workspace.
    fn exposure(f: &Fixture, e: CompileError) -> (PathMode, PathBuf, PathBuf, PathBuf) {
        let CompileError::Profile { error, .. } = e else {
            panic!("expected a profile error, got {e:?}");
        };
        match *error {
            SpecError::WorkspaceExposed {
                provider,
                mode,
                host,
                resolved,
                sandbox,
                workspace,
            } => {
                assert_eq!(provider.as_str(), "p");
                assert_eq!(workspace, f.ws());
                (mode, host, resolved, sandbox)
            }
            other => panic!("expected a WorkspaceExposed error, got {other:?}"),
        }
    }

    #[test]
    fn grants_containing_the_host_workspace_are_rejected() {
        let f = Fixture::with_workspace("home/Projects/stopit", "/workspace");
        let projects = f.root.join("home/Projects");
        for (body, mode) in [
            ("fs.ro = [\"~/Projects\"]", Ro),
            ("fs.rw = [\"~/Projects\"]", Rw),
            ("fs.protected = [\"~/Projects\"]", Protected),
        ] {
            let e = compile_body(&f, body).unwrap_err();
            assert_eq!(
                exposure(&f, e),
                (
                    mode,
                    projects.clone(),
                    projects.clone(),
                    PathBuf::from("/home/user/Projects")
                ),
                "{body}"
            );
        }
        // A mask over the workspace inside the grant does not excuse it.
        let body = "fs.ro = [\"~/Projects\"]\nfs.masked = [\"~/Projects/stopit\"]";
        let e = compile_body(&f, body).unwrap_err();
        assert_eq!(exposure(&f, e).1, projects);
        // A glob matching the workspace is caught too.
        let e = compile_body(&f, "fs.ro = [\"~/Projects/stop*\"]").unwrap_err();
        assert_eq!(exposure(&f, e).1, f.ws());
    }

    #[test]
    fn the_host_workspace_mounted_elsewhere_is_rejected() {
        let f = Fixture::with_workspace("home/Projects/stopit", "/workspace");
        let ws = f.ws();
        let e = compile_body(&f, &format!("fs.ro = [{:?}]", ws.to_str().unwrap())).unwrap_err();
        assert_eq!(
            exposure(&f, e),
            (Ro, ws.clone(), ws.clone(), ws.clone()),
            "an absolute rule naming the host workspace"
        );
        let bind = "fs.bind = [{ host = \"{workspace}\", sandbox = \"/opt/ws\", mode = \"rw\" }]";
        let e = compile_body(&f, bind).unwrap_err();
        assert_eq!(
            exposure(&f, e),
            (Rw, ws.clone(), ws, PathBuf::from("/opt/ws"))
        );
    }

    #[test]
    fn workspace_descendants_mounted_elsewhere_are_rejected() {
        let f = Fixture::with_workspace("home/Projects/stopit", "/workspace");
        f.mkdir("home/Projects/stopit/sub");
        let sub = f.ws().join("sub");
        let bind =
            "fs.bind = [{ host = \"{workspace}/sub\", sandbox = \"/opt/sub\", mode = \"ro\" }]";
        let e = compile_body(&f, bind).unwrap_err();
        assert_eq!(
            exposure(&f, e),
            (Ro, sub.clone(), sub.clone(), PathBuf::from("/opt/sub"))
        );
        // An absolute rule maps the host path to itself, not to the
        // workspace mount.
        let e = compile_body(&f, &format!("fs.rw = [{:?}]", sub.to_str().unwrap())).unwrap_err();
        assert_eq!(exposure(&f, e), (Rw, sub.clone(), sub.clone(), sub.clone()));
        // So does a `~` rule, when the workspace is not mounted under HOME.
        let e = compile_body(&f, "fs.ro = [\"~/Projects/stopit/sub\"]").unwrap_err();
        assert_eq!(
            exposure(&f, e),
            (
                Ro,
                sub.clone(),
                sub,
                PathBuf::from("/home/user/Projects/stopit/sub")
            )
        );
    }

    #[test]
    fn links_into_the_workspace_are_resolved_before_the_check() {
        let f = Fixture::with_workspace("home/Projects/stopit", "/workspace");
        f.mkdir("home/Projects/stopit/sub");
        symlink(f.ws(), f.root.join("home/ws-link")).unwrap();
        symlink(f.ws().join("sub"), f.root.join("home/sub-link")).unwrap();
        // A link to the workspace itself, and to a directory inside it.
        for (link, target) in [("ws-link", f.ws()), ("sub-link", f.ws().join("sub"))] {
            let e = compile_body(&f, &format!("fs.ro = [\"~/{link}\"]")).unwrap_err();
            assert_eq!(
                exposure(&f, e),
                (
                    Ro,
                    f.root.join("home").join(link),
                    target,
                    PathBuf::from("/home/user").join(link)
                )
            );
        }
        // A link on the way is followed too.
        let e = compile_body(&f, "fs.ro = [\"~/ws-link/sub\"]").unwrap_err();
        assert_eq!(exposure(&f, e).2, f.ws().join("sub"));
        // A bind's host side follows a final link.
        let bind = "fs.bind = [{ host = \"~/ws-link\", sandbox = \"/opt/ws\", mode = \"ro\" }]";
        let e = compile_body(&f, bind).unwrap_err();
        assert_eq!(exposure(&f, e).2, f.ws());
    }

    /// The `UntrustedLinkFollowed` payload of `e`, checking that it is for
    /// profile `profile`.
    fn untrusted_link(e: CompileError, profile: &str) -> LinkFollowed {
        let CompileError::Profile { profile: p, error } = e else {
            panic!("expected a profile error, got {e:?}");
        };
        assert_eq!(p, pr(profile));
        match *error {
            SpecError::UntrustedLinkFollowed(lf) => *lf,
            other => panic!("expected UntrustedLinkFollowed, got {other:?}"),
        }
    }

    /// The `DestinationLinkFollowed` payload of `e`, checking that it is for
    /// profile `profile`.
    fn destination_link(e: CompileError, profile: &str) -> DestinationLink {
        let CompileError::Profile { profile: p, error } = e else {
            panic!("expected a profile error, got {e:?}");
        };
        assert_eq!(p, pr(profile));
        match *error {
            SpecError::DestinationLinkFollowed(dl) => *dl,
            other => panic!("expected DestinationLinkFollowed, got {other:?}"),
        }
    }

    /// The `DestinationLink` of every `DestinationLink` warning of
    /// `profile`; panics on any other warning.
    fn destination_warnings(s: &CompiledSession, profile: &str) -> Vec<DestinationLink> {
        get(s, profile)
            .warnings
            .iter()
            .map(|w| match w {
                SpecWarning::DestinationLink(dl) => (**dl).clone(),
                other => panic!("unexpected warning {other:?}"),
            })
            .collect()
    }

    /// The `LinkFollowed` of every `SourceLink` warning of `profile`; panics
    /// on any other warning.
    fn source_warnings(s: &CompiledSession, profile: &str) -> Vec<LinkFollowed> {
        get(s, profile)
            .warnings
            .iter()
            .map(|w| match w {
                SpecWarning::SourceLink(lf) => (**lf).clone(),
                other => panic!("unexpected warning {other:?}"),
            })
            .collect()
    }

    /// The `(mode, host, link, resolved, sandbox)` of the
    /// `UntrustedLinkFollowed` error compiling `body` gives, checking its
    /// provider and that the link is attributed to the workspace.
    fn link_followed(f: &Fixture, body: &str) -> (PathMode, PathBuf, PathBuf, PathBuf, PathBuf) {
        let e = compile_body(f, body).unwrap_err();
        let LinkFollowed {
            provider,
            mode,
            host,
            link,
            resolved,
            sandbox,
            root,
        } = untrusted_link(e, "main");
        assert_eq!(provider.as_str(), "p", "{body}");
        assert_eq!(
            root,
            UntrustedRoot {
                path: f.ws(),
                kind: UntrustedKind::Workspace
            },
            "{body}"
        );
        (mode, host, link, resolved, sandbox)
    }

    #[test]
    fn links_inside_the_workspace_never_redirect_home_or_absolute_rules() {
        // The workspace is `~/proj`, mounted at `/workspace`; the sandbox has
        // planted `x -> ../.ssh` (and `d -> ../.ssh` on the way to a path).
        let f = Fixture::with_workspace("home/proj", "/workspace");
        f.file("home/.ssh/id_ed25519");
        symlink("../.ssh", f.ws().join("x")).unwrap();
        symlink("../.ssh", f.ws().join("d")).unwrap();
        let ssh = f.root.join("home/.ssh");
        let x = f.ws().join("x");
        assert_eq!(
            link_followed(&f, "fs.ro = [\"~/proj/x\"]"),
            (
                Ro,
                x.clone(),
                x.clone(),
                ssh.clone(),
                PathBuf::from("/home/user/proj/x")
            )
        );
        assert_eq!(
            link_followed(&f, "fs.protected = [\"~/proj/d/id_ed25519\"]"),
            (
                Protected,
                f.ws().join("d/id_ed25519"),
                f.ws().join("d"),
                ssh.join("id_ed25519"),
                PathBuf::from("/home/user/proj/d/id_ed25519")
            )
        );
        // An `rw` rule is dropped with a warning instead: dropping a grant
        // only removes access.
        let s = compile_body(&f, "fs.rw = [\"~/proj/d/id_ed25519\"]").unwrap();
        assert!(spec(&s, "main").mounts.is_empty());
        let lf = source_warnings(&s, "main");
        assert_eq!(
            lf.iter()
                .map(|l| (l.mode, &l.link, &l.resolved))
                .collect::<Vec<_>>(),
            [(Rw, &f.ws().join("d"), &ssh.join("id_ed25519"))]
        );
        assert_eq!(
            get(&s, "main").warnings[0].to_string(),
            format!(
                "provider \"p\": rw mount of {:?} at \"/home/user/proj/d/id_ed25519\" runs \
                 through the symlink {:?} inside the host workspace {:?} (resolving to {:?}); a \
                 sandbox can write there, so links inside it are never followed, and the rw \
                 mount is skipped",
                f.ws().join("d/id_ed25519"),
                f.ws().join("d"),
                f.ws(),
                ssh.join("id_ed25519"),
            )
        );
        let (_, host, link, resolved, sandbox) =
            link_followed(&f, &format!("fs.protected = [{:?}]", x.to_str().unwrap()));
        assert_eq!(
            (host, link, resolved, sandbox),
            (x.clone(), x.clone(), ssh.clone(), x.clone())
        );
        let bind = "fs.bind = [{ host = \"~/proj/x\", sandbox = \"/opt/x\", mode = \"ro\" }]";
        let (_, _, link, resolved, _) = link_followed(&f, bind);
        assert_eq!((link, resolved), (x.clone(), ssh.clone()));
        // Masked, it shows nothing of the target, but the planted link would
        // decide the mask's shape.
        let (mode, _, link, _, _) = link_followed(&f, "fs.masked = [\"~/proj/x\"]");
        assert_eq!((mode, link), (Masked, x.clone()));
        let e = compile_body(&f, "fs.ro = [\"~/proj/x\"]").unwrap_err();
        assert_eq!(
            e.to_string(),
            format!(
                "cannot compile profile \"main\": provider \"p\": ro mount of {x:?} at \
                 \"/home/user/proj/x\" runs through the symlink {x:?} inside the host workspace \
                 {:?} (resolving to {ssh:?}); a sandbox can write there, so links inside it are \
                 never followed, whatever the rule's anchor or the links leading there: remove \
                 the link or change the rule",
                f.ws()
            )
        );
    }

    #[test]
    fn links_inside_the_workspace_are_refused_when_reached_through_outside_links() {
        // The workspace is `~/Projects/stopit`, mounted at `/workspace`, and
        // the user has links leading into it. The sandbox has planted
        // `config -> ../../.ssh` and `d -> ../..` in it.
        let f = Fixture::with_workspace("home/Projects/stopit", "/workspace");
        let home = f.root.join("home");
        f.file("home/.ssh/id_ed25519");
        symlink("Projects/stopit", home.join("current")).unwrap();
        f.mkdir("home/links");
        symlink("../Projects/stopit/config", home.join("links/a")).unwrap();
        // A link whose target is a path inside the workspace (a dotfiles
        // repository as the workspace, say).
        symlink("Projects/stopit/config", home.join(".toolrc")).unwrap();
        // An absolute link to the workspace, whose target runs through it.
        symlink(f.ws().join("d/.ssh"), home.join("deep")).unwrap();
        symlink("../../.ssh", f.ws().join("config")).unwrap();
        symlink("../..", f.ws().join("d")).unwrap();
        // A `..` after the planted `d` applies to its target, not to `d`'s
        // parent: `current/d/../x` is `~/../x`, i.e. the temp root's `x`.
        f.file("x");
        symlink("current/d/../x", home.join("up-x")).unwrap();
        let ssh = home.join(".ssh");
        let config = f.ws().join("config");
        let d = f.ws().join("d");
        assert_eq!(
            link_followed(&f, "fs.ro = [\"~/current/config\"]"),
            (
                Ro,
                home.join("current/config"),
                config.clone(),
                ssh.clone(),
                PathBuf::from("/home/user/current/config")
            )
        );
        // A glob below an entering link: the walk follows its root link and
        // matches the planted link itself, which lies inside the workspace,
        // so the match is skipped with a warning (the walk reaches the real
        // files under their own names).
        let s = compile_body(&f, "fs.ro = [\"~/current/conf*\"]").unwrap();
        assert!(spec(&s, "main").mounts.is_empty());
        match get(&s, "main").warnings.as_slice() {
            [SpecWarning::GlobLink(gl)] => assert_eq!(
                (&gl.host, &gl.link, &gl.root.path),
                (&home.join("current/config"), &config, &f.ws())
            ),
            other => panic!("expected one GlobLink warning, got {other:?}"),
        }
        // `(rule, host, planted link, resolved)`.
        for (rule, host, link, resolved) in [
            // A glob matching a link into the workspace, whose target is the
            // planted link. (A glob walk does not descend through links
            // below its root, so `~/links/*/config` would match nothing.)
            ("~/links/*", "links/a", &config, ssh.clone()),
            // A planted link on the way.
            (
                "~/current/d/.ssh/id_ed25519",
                "current/d/.ssh/id_ed25519",
                &d,
                ssh.join("id_ed25519"),
            ),
            // Links whose targets run through the workspace, with nothing
            // written after them.
            ("~/.toolrc", ".toolrc", &config, ssh.clone()),
            ("~/deep", "deep", &d, ssh.clone()),
            ("~/up-x", "up-x", &d, f.root.join("x")),
        ] {
            let (_, got_host, got_link, got_resolved, _) =
                link_followed(&f, &format!("fs.ro = [\"{rule}\"]"));
            assert_eq!(
                (got_host, &got_link, got_resolved),
                (home.join(host), link, resolved),
                "{rule}"
            );
        }
        // Binds and absolute rules alike.
        let bind =
            "fs.bind = [{ host = \"~/current/config\", sandbox = \"/opt/c\", mode = \"ro\" }]";
        let (_, _, link, resolved, _) = link_followed(&f, bind);
        assert_eq!((link, resolved), (config.clone(), ssh.clone()));
        let abs = home.join("current/config");
        let (_, _, link, _, sandbox) =
            link_followed(&f, &format!("fs.protected = [{:?}]", abs.to_str().unwrap()));
        assert_eq!((link, sandbox), (config.clone(), abs));
        // Masked, the planted link would decide the mask's shape.
        let (mode, _, link, _, _) = link_followed(&f, "fs.masked = [\"~/current/config\"]");
        assert_eq!((mode, link), (Masked, config));
    }

    #[test]
    fn entering_links_without_planted_ones_get_the_alignment_check() {
        // Without the planted link, `~/current/config` resolves inside the
        // workspace but is not mounted at its aligned path: the existing
        // exposure check rejects it.
        let f = Fixture::with_workspace("home/Projects/stopit", "/workspace");
        let home = f.root.join("home");
        f.file("home/Projects/stopit/config");
        symlink("Projects/stopit", home.join("current")).unwrap();
        let e = compile_body(&f, "fs.ro = [\"~/current/config\"]").unwrap_err();
        assert_eq!(
            exposure(&f, e),
            (
                Ro,
                home.join("current/config"),
                f.ws().join("config"),
                PathBuf::from("/home/user/current/config")
            )
        );
        // Links outside the workspace on the way out of it are followed.
        f.mkdir("elsewhere");
        symlink(f.root.join("elsewhere"), home.join("out")).unwrap();
        symlink("Projects/stopit/../../out", home.join("via")).unwrap();
        if let Err(e) = compile_body(&f, "fs.ro = [\"~/via\"]") {
            panic!("~/via: {e}");
        }
    }

    #[test]
    fn entering_links_to_the_aligned_path_are_accepted() {
        // The workspace lives at `~/real/proj` but is mounted at
        // `/home/user/proj`, and `~/proj -> real/proj`: `~/proj/...` rules
        // land on the aligned path through a link outside the workspace.
        let f = Fixture::with_workspace("home/real/proj", "/home/user/proj");
        let home = f.root.join("home");
        f.mkdir("home/real/proj/x");
        f.mkdir("home/.ssh");
        symlink("real/proj", home.join("proj")).unwrap();
        for body in ["fs.ro = [\"~/proj/x\"]", "fs.protected = [\"~/proj\"]"] {
            if let Err(e) = compile_body(&f, body) {
                panic!("{body}: {e}");
            }
        }
        // A link planted there is refused: by the host-source check without
        // the workspace mount, and by the destination check first with it.
        symlink("../../.ssh", f.ws().join("y")).unwrap();
        let e = compile_body(&f, "fs.ro = [\"~/proj/y\"]").unwrap_err();
        assert_eq!(untrusted_link(e, "main").link, f.ws().join("y"));
        let e = compile_body(&f, "fs.rw = [\"{workspace}\"]\nfs.ro = [\"~/proj/y\"]").unwrap_err();
        assert_eq!(destination_link(e, "main").link, f.ws().join("y"));
    }

    /// Resolves `path` with the workspace `ws` as the only untrusted root:
    /// the canonical path and the first link followed inside `ws`.
    fn resolve_in(path: &Path, ws: &Path) -> io::Result<(PathBuf, Option<PathBuf>)> {
        let roots = UntrustedRoots::new(ws);
        resolve_host_source(path, &roots)
            .map(|s| (s.path, s.untrusted.first().map(|l| l.link.clone())))
            .map_err(|u| u.error)
    }

    #[test]
    fn resolve_host_source_matches_canonicalize_and_reports_loops() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let ws = root.join("ws");
        fs::create_dir_all(ws.join("a/b")).unwrap();
        fs::create_dir_all(root.join("out/c")).unwrap();
        symlink("../out", ws.join("up")).unwrap();
        symlink(root.join("ws/a"), root.join("abs")).unwrap();
        symlink("./ws/a/../a/b", root.join("rel")).unwrap();
        symlink("out/c", root.join("chain")).unwrap();
        symlink("chain", root.join("chain2")).unwrap();
        // Links outside the workspace leading into it, then through `up`.
        symlink("ws", root.join("cur")).unwrap();
        symlink("ws/up/c", root.join("to-up")).unwrap();
        // A planted `d`: a `..` after it applies to its target, so
        // `cur/d/../b` is `ws/a/b`, not the (missing) `ws/b`.
        symlink("a/b", ws.join("d")).unwrap();
        // `..` at `/` stays at `/`.
        let above_root = Path::new("/../..").join(root.strip_prefix("/").unwrap());
        for (path, link) in [
            (root.join("cur/d/../b"), Some(ws.join("d"))),
            (above_root.join("ws/a"), None),
            (above_root.join("cur/up"), Some(ws.join("up"))),
            // A trailing `/` or `/.` after a directory is fine.
            (root.join("ws/a/"), None),
            (root.join("ws/a/."), None),
            (root.join("cur/"), None),
            (root.join("cur/up/c"), Some(ws.join("up"))),
            (root.join("to-up"), Some(ws.join("up"))),
            (root.join("abs/b"), None),
            (root.join("rel"), None),
            (root.join("chain2"), None),
            (root.join("ws/a/b"), None),
            (root.join("ws/up/c"), Some(ws.join("up"))),
            (root.join("ws/a/../up"), Some(ws.join("up"))),
        ] {
            assert_eq!(
                resolve_in(&path, &ws).unwrap(),
                (path.canonicalize().unwrap(), link),
                "{path:?}"
            );
        }
        // Lookup errors are the kernel's.
        symlink("loop", root.join("loop")).unwrap();
        fs::write(root.join("file"), "").unwrap();
        symlink("file/..", root.join("through-file")).unwrap();
        symlink("file/", root.join("slash-target")).unwrap();
        symlink("file", root.join("file-link")).unwrap();
        for (path, errno) in [
            (root.join("loop"), Errno::LOOP),
            (root.join("file/x"), Errno::NOTDIR),
            (root.join("through-file"), Errno::NOTDIR),
            // A trailing `/` (or `/.`) requires a directory, after any link.
            (root.join("file/"), Errno::NOTDIR),
            (root.join("file/."), Errno::NOTDIR),
            (root.join("file-link/"), Errno::NOTDIR),
            (root.join("slash-target"), Errno::NOTDIR),
        ] {
            assert_eq!(
                resolve_in(&path, &ws).unwrap_err().raw_os_error(),
                Some(errno.raw_os_error()),
                "{path:?}"
            );
            assert_eq!(
                path.canonicalize().unwrap_err().raw_os_error(),
                Some(errno.raw_os_error()),
                "{path:?}"
            );
        }
        symlink("nowhere", ws.join("dangling")).unwrap();
        assert_eq!(
            resolve_in(&ws.join("dangling"), &ws).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        // The kind is that of the canonical entry, after every link.
        let roots = UntrustedRoots::new(&ws);
        let kind = |p: &Path| resolve_host_source(p, &roots).unwrap().kind;
        assert_eq!(kind(&root.join("chain2")), EntryKind::Dir);
        assert_eq!(kind(&root.join("file-link")), EntryKind::File);
        assert_eq!(kind(Path::new("/")), EntryKind::Dir);
        assert_eq!(kind(&root.join("ws/a/b/..")), EntryKind::Dir);
    }

    #[test]
    fn resolve_host_source_reports_every_untrusted_link_with_its_root() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let ws = root.join("ws");
        let rw = root.join("rw");
        fs::create_dir_all(ws.join("a")).unwrap();
        fs::create_dir_all(rw.join("b")).unwrap();
        // `ws/l1 -> l2 -> ../host -> rw/l3 -> b`, where `host` is outside
        // every root.
        symlink("l2", ws.join("l1")).unwrap();
        symlink("../host", ws.join("l2")).unwrap();
        symlink("rw/l3", root.join("host")).unwrap();
        symlink("b", rw.join("l3")).unwrap();
        let mut roots = UntrustedRoots::new(&ws);
        roots.add_rw_mounts(
            None,
            &[PlannedMount {
                sandbox: "/rw".into(),
                source: MountSource::Host {
                    path: rw.clone(),
                    kind: EntryKind::Dir,
                },
                mode: Rw,
                provider: "p".parse().unwrap(),
                glob_link: false,
            }],
        );
        let got = resolve_host_source(&ws.join("l1"), &roots).unwrap();
        assert_eq!(got.path, rw.join("b"));
        let links: Vec<(PathBuf, PathBuf)> = got
            .untrusted
            .iter()
            .map(|l| (l.link.clone(), l.root.path.clone()))
            .collect();
        assert_eq!(
            links,
            [
                (ws.join("l1"), ws.clone()),
                (ws.join("l2"), ws.clone()),
                (rw.join("l3"), rw.clone()),
            ]
        );
    }

    #[test]
    fn resolve_host_source_follows_at_most_40_links() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let ws = root.join("ws");
        fs::create_dir_all(root.join("out")).unwrap();
        fs::create_dir(&ws).unwrap();
        // `l0 -> out` and `l{i} -> l{i-1}`: resolving `l{i}` follows i + 1
        // links.
        symlink("out", root.join("l0")).unwrap();
        for i in 1..=MAX_SYMLINKS {
            symlink(format!("l{}", i - 1), root.join(format!("l{i}"))).unwrap();
        }
        let last_ok = root.join(format!("l{}", MAX_SYMLINKS - 1));
        assert_eq!(resolve_in(&last_ok, &ws).unwrap(), (root.join("out"), None));
        assert!(fs::metadata(&last_ok).unwrap().is_dir());
        let too_many = root.join(format!("l{MAX_SYMLINKS}"));
        let loop_errno = Some(Errno::LOOP.raw_os_error());
        assert_eq!(
            resolve_in(&too_many, &ws).unwrap_err().raw_os_error(),
            loop_errno
        );
        assert_eq!(
            fs::metadata(&too_many).unwrap_err().raw_os_error(),
            loop_errno
        );
    }

    #[test]
    fn resolve_host_source_fails_on_unreadable_directories() {
        use std::os::unix::fs::PermissionsExt;
        if rustix::process::geteuid().is_root() {
            // Root bypasses directory permissions.
            return;
        }
        let dir = TempDir::new().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let ws = root.join("ws");
        let locked = root.join("locked");
        fs::create_dir(&ws).unwrap();
        fs::create_dir_all(locked.join("d")).unwrap();
        symlink("locked/d", root.join("via")).unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        let results = [locked.join("d"), root.join("via")]
            .map(|path| resolve_in(&path, &ws).map_err(|e| e.raw_os_error()));
        // Restore permissions before asserting, so the tempdir can be
        // removed even if an assertion fails.
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
        for result in results {
            assert_eq!(result, Err(Some(Errno::ACCESS.raw_os_error())));
        }
    }

    #[test]
    fn aligned_rules_through_workspace_links_are_refused_by_the_destination_check() {
        // With the workspace mounted at its `~` path, a `~` rule inside it
        // lies inside the workspace mount, so the destination check refuses
        // the link first (a restrictive rule) or drops the mount (`rw`).
        let f = Fixture::with_workspace("home/proj", "/home/user/proj");
        f.mkdir("home/.ssh");
        symlink("../.ssh", f.ws().join("x")).unwrap();
        let ws = "fs.rw = [\"{workspace}\"]\n";
        let e = compile_body(&f, &format!("{ws}fs.ro = [\"~/proj/x\"]")).unwrap_err();
        let dl = destination_link(e, "main");
        assert_eq!(
            (&dl.link, &dl.ancestor, dl.root.kind),
            (
                &f.ws().join("x"),
                &PathBuf::from("/home/user/proj"),
                UntrustedKind::Workspace
            )
        );
        let s = compile_body(&f, "fs.rw = [\"{workspace}\", \"~/proj/x\"]").unwrap();
        assert_eq!(mounts(spec(&s, "main")), [row("/home/user/proj", Rw, "p")]);
        assert_eq!(destination_warnings(&s, "main")[0].link, f.ws().join("x"));
        // Without the workspace mount nothing is underneath (bwrap's root
        // tmpfs), and the host-source check refuses the link: an error for
        // `ro`, a dropped mount for `rw`.
        let lf = untrusted_link(
            compile_body(&f, "fs.ro = [\"~/proj/x\"]").unwrap_err(),
            "main",
        );
        assert_eq!(lf.link, f.ws().join("x"));
        let s = compile_body(&f, "fs.rw = [\"~/proj/x\"]").unwrap();
        assert!(spec(&s, "main").mounts.is_empty());
        assert_eq!(source_warnings(&s, "main")[0].link, f.ws().join("x"));
    }

    #[test]
    fn exposure_error_message_names_everything_and_hints() {
        let f = Fixture::with_workspace("home/Projects/stopit", "/workspace");
        symlink(f.ws(), f.root.join("home/ws-link")).unwrap();
        let home = f.root.join("home");
        let e = compile_body(&f, "fs.ro = [\"~/Projects\"]").unwrap_err();
        assert_eq!(
            e.to_string(),
            format!(
                "cannot compile profile \"main\": provider \"p\": ro mount of {:?} at \
                 \"/home/user/Projects\" exposes the host workspace {:?} outside the workspace \
                 mount; the workspace must appear only at its mount, where its restrictions, \
                 pinned parents and the supervisor's checks apply; grant narrower paths that \
                 leave the workspace out, mask this one, or reach these files through the \
                 workspace mount",
                home.join("Projects"),
                f.ws()
            )
        );
        let e = compile_body(&f, "fs.ro = [\"~/ws-link\"]").unwrap_err();
        assert_eq!(
            e.to_string(),
            format!(
                "cannot compile profile \"main\": provider \"p\": ro mount of {:?} (resolving to \
                 {:?}) at \"/home/user/ws-link\" exposes the host workspace {:?} outside the \
                 workspace mount; the workspace must appear only at its mount, where its \
                 restrictions, pinned parents and the supervisor's checks apply; grant narrower \
                 paths that leave the workspace out, mask this one, or reach these files through \
                 the workspace mount",
                home.join("ws-link"),
                f.ws(),
                f.ws()
            )
        );
    }

    #[test]
    fn aligned_masked_ephemeral_and_unrelated_grants_are_accepted() {
        let f = Fixture::with_workspace("home/Projects/stopit", "/workspace");
        f.mkdir("home/Projects/stopit/sub");
        f.mkdir("home/Projects/other");
        f.mkdir("home/Projects/stopit2");
        f.file("home/Projects/stopit/.env");
        for body in [
            // The workspace and paths inside it at their aligned paths.
            "fs.rw = [\"{workspace}\"]",
            "fs.ro = [\"{workspace}/sub\"]",
            "fs.protected = [\"{workspace}/**/.env\"]",
            "fs.bind = [{ host = \"{workspace}/sub\", sandbox = \"/workspace/sub\", mode = \"ro\" }]",
            // Masking or replacing an ancestor shows nothing of it.
            "fs.masked = [\"~/Projects\"]",
            "fs.ephemeral = [\"~/Projects\"]",
            // Siblings, including one sharing the workspace's name prefix.
            "fs.ro = [\"~/Projects/other\"]",
            "fs.rw = [\"~/Projects/stopit2\"]",
            "fs.ro = [\"~/Projects/stopit2\", \"~/Projects/other\"]",
        ] {
            if let Err(e) = compile_body(&f, body) {
                panic!("{body}: {e}");
            }
        }
        // The default base, which grants the workspace and masks and
        // protects files inside it.
        if let Err(e) = f.try_compile("") {
            panic!("base default: {e}");
        }
    }

    #[test]
    fn home_rules_resolving_to_the_aligned_path_are_accepted() {
        // The workspace is `~/proj`, mounted at the matching path under HOME,
        // so `~/proj/...` rules land exactly where the workspace mount shows
        // the same files.
        let f = Fixture::with_workspace("home/proj", "/home/user/proj");
        f.mkdir("home/proj/x");
        for body in [
            "fs.ro = [\"~/proj/x\"]",
            "fs.protected = [\"~/proj\"]",
            "fs.rw = [\"{workspace}\"]\nfs.ro = [\"~/proj/x\"]",
        ] {
            if let Err(e) = compile_body(&f, body) {
                panic!("{body}: {e}");
            }
        }
        // But not `~` itself, which contains the workspace.
        let e = compile_body(&f, "fs.ro = [\"~\"]").unwrap_err();
        assert_eq!(exposure(&f, e).3, PathBuf::from("/home/user"));
    }

    /// Each `SourceUnresolved` warning of `profile` as `(mode, host, sandbox,
    /// error kind, untrusted link followed)`; panics on any other warning.
    #[allow(clippy::type_complexity)]
    fn unresolved_warnings(
        s: &CompiledSession,
        profile: &str,
    ) -> Vec<(PathMode, PathBuf, PathBuf, io::ErrorKind, Option<PathBuf>)> {
        get(s, profile)
            .warnings
            .iter()
            .map(|w| match w {
                SpecWarning::SourceUnresolved(u) => (
                    u.mode,
                    u.host.clone(),
                    u.sandbox.clone(),
                    u.error.kind(),
                    u.link.as_ref().map(|(l, _)| l.clone()),
                ),
                other => panic!("unexpected warning {other:?}"),
            })
            .collect()
    }

    #[test]
    fn dangling_host_sources_are_skipped_for_every_mode() {
        // A final link whose target is missing has nothing to show or hide,
        // as for a missing path: the mount is skipped with a warning.
        let f = Fixture::new();
        let dangling = f.root.join("home/dangling");
        symlink(f.root.join("missing"), &dangling).unwrap();
        f.file("home/cfg");
        for mode in [Protected, Ro, Rw] {
            let s = compile_body(&f, &format!("fs.{mode} = [\"~/dangling\"]")).unwrap();
            assert!(spec(&s, "main").mounts.is_empty(), "{mode}");
            assert_eq!(
                unresolved_warnings(&s, "main"),
                [(
                    mode,
                    dangling.clone(),
                    PathBuf::from("/home/user/dangling"),
                    io::ErrorKind::NotFound,
                    None
                )],
                "{mode}"
            );
            let [SpecWarning::SourceUnresolved(u)] = get(&s, "main").warnings.as_slice() else {
                unreachable!("checked above");
            };
            assert_eq!(
                get(&s, "main").warnings[0].to_string(),
                format!(
                    "provider \"p\": cannot resolve the host source {dangling:?} of the {mode} \
                     mount at \"/home/user/dangling\": {}, so the mount is skipped",
                    u.error
                ),
                "{mode}"
            );
            // Mounts below it are not under it, so they are kept on bwrap's
            // root tmpfs.
            let s = compile_body(
                &f,
                &format!(
                    "fs.{mode} = [\"~/dangling\"]\n\
                     fs.bind = [{{ host = \"~/cfg\", sandbox = \"/home/user/dangling/cfg\", \
                     mode = \"ro\" }}]"
                ),
            )
            .unwrap();
            assert_eq!(
                mounts(spec(&s, "main")),
                [row("/home/user/dangling/cfg", Ro, "p")],
                "{mode}"
            );
        }
        // A masked dangling link is dropped by the planner (with a warning)
        // before it is ever resolved here.
        let s = compile_body(&f, "fs.masked = [\"~/dangling\"]").unwrap();
        assert!(spec(&s, "main").mounts.is_empty());
    }

    #[test]
    fn looping_host_sources_drop_rw_and_fail_restrictive_mounts() {
        // A final link that loops cannot be inspected: an `rw` mount is
        // dropped, while a restrictive one has no known shape to be masked
        // as, and stays an error (DESIGN.md §11).
        let f = Fixture::new();
        let looping = f.root.join("home/loop");
        symlink("loop", &looping).unwrap();
        let eloop = io::Error::from(Errno::LOOP).kind();
        let s = compile_body(&f, "fs.rw = [\"~/loop\"]").unwrap();
        assert!(spec(&s, "main").mounts.is_empty());
        assert_eq!(
            unresolved_warnings(&s, "main"),
            [(
                Rw,
                looping.clone(),
                PathBuf::from("/home/user/loop"),
                eloop,
                None
            )]
        );
        for mode in [Protected, Ro] {
            let e = compile_body(&f, &format!("fs.{mode} = [\"~/loop\"]")).unwrap_err();
            let CompileError::Profile { error, .. } = &e else {
                panic!("expected a profile error, got {e:?}");
            };
            assert_eq!(
                **error,
                SpecError::HostSourceUnresolved {
                    provider: "p".parse().unwrap(),
                    mode,
                    host: looping.clone(),
                    sandbox: PathBuf::from("/home/user/loop"),
                    kind: eloop,
                },
                "{mode}"
            );
        }
        // A masked one fails while planning, its target's shape unknown.
        let e = compile_body(&f, "fs.masked = [\"~/loop\"]").unwrap_err();
        let CompileError::Profile { error, .. } = &e else {
            panic!("expected a profile error, got {e:?}");
        };
        assert!(
            matches!(
                **error,
                SpecError::Mounts(PathPlanError::Inaccessible { mode: Masked, ref path, kind, .. })
                    if *path == looping && kind == eloop
            ),
            "{e:?}"
        );
    }

    #[test]
    fn planted_dangling_links_drop_grants_rather_than_fail() {
        // A sandbox planted dangling links in the workspace and in an `rw`
        // grant. With nothing mounted underneath, only the host-source check
        // sees them; a grant through one is dropped with a warning naming
        // the link, and a restrictive rule is skipped like a missing path.
        let f = Fixture::new();
        let home = f.root.join("home");
        f.mkdir("home/.cache/tool");
        symlink("nowhere", f.ws().join("link")).unwrap();
        symlink("nowhere", home.join(".cache/tool/cfg")).unwrap();
        let src = |mode: &str| {
            format!(
                "base = \"none\"\n[profiles.agent]\ninherit = \"none\"\n{}{}",
                prov("w", "main", "fs.rw = [\"~/.cache/tool\"]"),
                prov(
                    "p",
                    "agent",
                    &format!(
                        "fs.{mode} = [\"{{workspace}}/link\"]\nfs.bind = [{{ host = \
                         \"~/.cache/tool/cfg\", sandbox = \"/opt/cfg\", mode = \"{mode}\" }}]"
                    ),
                ),
            )
        };
        for mode in [Rw, Ro] {
            let s = f.compile(&src(mode.as_str()));
            assert!(spec(&s, "agent").mounts.is_empty(), "{mode}");
            assert_eq!(
                unresolved_warnings(&s, "agent"),
                [
                    (
                        mode,
                        home.join(".cache/tool/cfg"),
                        PathBuf::from("/opt/cfg"),
                        io::ErrorKind::NotFound,
                        Some(home.join(".cache/tool/cfg"))
                    ),
                    (
                        mode,
                        f.ws().join("link"),
                        PathBuf::from("/workspace/link"),
                        io::ErrorKind::NotFound,
                        Some(f.ws().join("link"))
                    ),
                ],
                "{mode}"
            );
            let [SpecWarning::SourceUnresolved(u), ..] = get(&s, "agent").warnings.as_slice()
            else {
                unreachable!("checked above");
            };
            let root = rw_root(
                home.join(".cache/tool"),
                "w",
                Some("main"),
                home.join(".cache/tool"),
            );
            assert_eq!(u.link.as_ref().map(|(_, r)| r), Some(&root), "{mode}");
            assert_eq!(
                get(&s, "agent").warnings[0].to_string(),
                format!(
                    "provider \"p\": cannot resolve the host source {:?} of the {mode} mount at \
                     \"/opt/cfg\": {} (after following the symlink {:?} inside {root}), so the \
                     mount is skipped",
                    home.join(".cache/tool/cfg"),
                    u.error,
                    home.join(".cache/tool/cfg"),
                ),
                "{mode}"
            );
        }
        // Under the workspace mount too: a dangling source mounts nothing,
        // so it is skipped before its destination (the same link) is
        // checked.
        for (mode, body) in [
            (Rw, "fs.rw = [\"{workspace}\", \"{workspace}/link\"]"),
            (
                Ro,
                "fs.rw = [\"{workspace}\"]\nfs.ro = [\"{workspace}/link\"]",
            ),
        ] {
            let s = compile_body(&f, body).unwrap();
            assert_eq!(
                mounts(spec(&s, "main")),
                [row("/workspace", Rw, "p")],
                "{mode}"
            );
            assert_eq!(
                unresolved_warnings(&s, "main"),
                [(
                    mode,
                    f.ws().join("link"),
                    PathBuf::from("/workspace/link"),
                    io::ErrorKind::NotFound,
                    Some(f.ws().join("link"))
                )],
                "{mode}"
            );
        }
    }

    #[test]
    fn masks_whose_source_cannot_be_resolved_are_kept() {
        // `~/docs` is a host link to a directory below one that cannot be
        // searched, so a masked rule below it masks `~/docs` itself, whose
        // source then cannot be resolved: the mask is kept with a warning.
        use std::os::unix::fs::PermissionsExt;
        if rustix::process::geteuid().is_root() {
            eprintln!("skipping: permission checks do not apply to root");
            return;
        }
        let f = Fixture::new();
        f.file("outside/sub/secret");
        let outside = f.root.join("outside");
        let docs = f.root.join("home/docs");
        symlink(outside.join("sub"), &docs).unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o000)).unwrap();
        let s = compile_body(&f, "fs.masked = [\"~/docs/secret\"]");
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o755)).unwrap();
        let s = s.unwrap();
        assert_eq!(
            spec(&s, "main").mounts,
            [PlannedMount {
                sandbox: "/home/user/docs".into(),
                source: MountSource::Host {
                    path: docs.clone(),
                    kind: EntryKind::Dir
                },
                mode: Masked,
                provider: "p".parse().unwrap(),
                glob_link: false,
            }]
        );
        match get(&s, "main").warnings.as_slice() {
            [
                SpecWarning::Mount(PlanWarning {
                    kind: PlanWarningKind::InaccessibleMasked { path, dir, .. },
                    ..
                }),
                w @ SpecWarning::MaskSourceUnresolved(u),
            ] => {
                assert_eq!((path, dir), (&docs.join("secret"), &docs));
                assert_eq!(
                    (u.mode, &u.host, u.error.kind(), &u.link),
                    (Masked, &docs, io::ErrorKind::PermissionDenied, &None)
                );
                assert_eq!(
                    w.to_string(),
                    format!(
                        "provider \"p\": cannot resolve the host source {docs:?} of the masked \
                         mount at \"/home/user/docs\": {}; the mask is kept, but whether the \
                         content it covers is visible at another sandbox path is not checked",
                        u.error
                    )
                );
            }
            other => panic!("unexpected warnings {other:?}"),
        }
    }

    #[test]
    fn a_directory_a_sandbox_made_unreadable_no_longer_blocks_startup() {
        // DESIGN.md §1.4: a sandbox can `chmod 000` a directory it owns, or
        // `chmod 600` it (readable but not searchable: the walk lists its
        // entries, none of which can be inspected). The default base's
        // workspace rules then mask it as a whole, once per restrictive
        // rule that could not inspect something there.
        let globs_masked = 6; // `**/.env`, `**/.env.*`, … in `fs.masked`.
        let globs_protected = 2; // `**/*.nix`, `**/.stopit.toml` in `fs.protected`.
        let literals_protected = 6; // `flake.lock`, `.envrc`, … in `fs.protected`.
        // Each case: the files, the directory made inaccessible and its
        // mode, and the rules expected to mask it (by mode, in rule order).
        let all_globs: Vec<PathMode> =
            [vec![Masked; globs_masked], vec![Protected; globs_protected]].concat();
        let globs_and_literals: Vec<PathMode> =
            [all_globs.clone(), vec![Protected; literals_protected]].concat();
        let nix_and_literals: Vec<PathMode> = vec![Protected; 1 + literals_protected];
        let cases: [(&[&str], &str, u32, Vec<PathMode>); 4] = [
            // Every `**` glob fails to read it.
            (
                &["ws/locked/.env", "ws/a/.env"],
                "ws/locked",
                0o000,
                all_globs,
            ),
            // Only `**/*.nix` lists a match in it.
            (
                &["ws/d/foo.nix", "ws/a/.env"],
                "ws/d",
                0o600,
                vec![Protected],
            ),
            // The workspace root: every glob and every literal rule below it.
            (
                &["ws/flake.nix", "ws/a/.env"],
                "ws",
                0o000,
                globs_and_literals,
            ),
            // `**/*.nix` lists `flake.nix`; the literals cannot be inspected.
            (&["ws/flake.nix"], "ws", 0o600, nix_and_literals),
        ];
        for (files, dir, mode, want) in cases {
            let f = Fixture::new();
            for file in files {
                f.file(file);
            }
            let host = f.root.join(dir);
            let sandbox = join_rel(Path::new("/workspace"), host.strip_prefix(f.ws()).unwrap());
            let Some(s) = with_mode(std::slice::from_ref(&host), mode, || f.try_compile("")) else {
                return;
            };
            let s = s.unwrap_or_else(|e| panic!("{dir} {mode:o}: {e}"));
            let main = mounts(spec(&s, "main"));
            let at = |path: &Path| {
                main.iter()
                    .find(|(p, ..)| Path::new(p) == path)
                    .map(|(_, mode, _)| *mode)
            };
            assert_eq!(at(&sandbox), Some(Masked), "{dir} {mode:o}");
            let root = dir == "ws";
            if !root {
                // The rest of the workspace is mounted and masked as usual.
                assert_eq!(at(Path::new("/workspace")), Some(Rw), "{dir} {mode:o}");
                assert_eq!(
                    at(Path::new("/workspace/a/.env")),
                    Some(Masked),
                    "{dir} {mode:o}"
                );
            }
            let mut masked = Vec::new();
            let mut hidden = Vec::new();
            for w in &get(&s, "main").warnings {
                match w {
                    SpecWarning::Mount(PlanWarning {
                        provider,
                        kind:
                            PlanWarningKind::InaccessibleMasked {
                                mode, dir, sandbox, ..
                            },
                        ..
                    }) => masked.push((provider.to_string(), *mode, dir.clone(), sandbox.clone())),
                    SpecWarning::Mount(PlanWarning {
                        provider,
                        pattern,
                        kind:
                            PlanWarningKind::GrantHidden {
                                mode,
                                dir,
                                workspace,
                                ..
                            },
                    }) => hidden.push((
                        provider.to_string(),
                        pattern.clone(),
                        *mode,
                        dir.clone(),
                        *workspace,
                    )),
                    _ => {}
                }
            }
            let want: Vec<_> = want
                .into_iter()
                .map(|m| ("base".to_owned(), m, host.clone(), sandbox.clone()))
                .collect();
            assert_eq!(masked, want, "{dir} {mode:o}");
            // Masking the workspace root hides the workspace mount, loudly.
            let want_hidden = if root {
                vec![(
                    "base".to_owned(),
                    "{workspace}".to_owned(),
                    Rw,
                    host.clone(),
                    true,
                )]
            } else {
                Vec::new()
            };
            assert_eq!(hidden, want_hidden, "{dir} {mode:o}");
        }
    }

    #[test]
    fn restrictive_sources_that_cannot_be_inspected_under_a_mask_are_dropped() {
        // Belt and braces for the planner: a protected file whose source
        // cannot be inspected (its directory was made unsearchable after
        // planning, say) inside a masked directory is dropped, since the
        // mask hides it anyway. Elsewhere it stays an error.
        let f = Fixture::new();
        f.file("ws/d/foo.nix");
        let d = f.ws().join("d");
        let foo = d.join("foo.nix");
        let mount = |sandbox: &str, path: &Path, kind, mode| PlannedMount {
            sandbox: sandbox.into(),
            source: MountSource::Host {
                path: path.to_owned(),
                kind,
            },
            mode,
            provider: "p".parse().unwrap(),
            glob_link: false,
        };
        let ws = mount("/workspace", &f.ws(), EntryKind::Dir, Rw);
        let mask = mount("/workspace/d", &d, EntryKind::Dir, Masked);
        let protected = mount("/workspace/d/foo.nix", &foo, EntryKind::File, Protected);
        let roots = UntrustedRoots::new(&f.ws());
        let Some((under, alone)) = with_mode(std::slice::from_ref(&d), 0o600, || {
            let mut warnings = Vec::new();
            let under = check_host_sources(
                vec![ws.clone(), mask.clone(), protected.clone()],
                &f.ctx,
                &roots,
                &[],
                &f.state,
                &mut warnings,
            )
            .map(|kept| (kept, warnings));
            let alone = check_host_sources(
                vec![ws.clone(), protected.clone()],
                &f.ctx,
                &roots,
                &[],
                &f.state,
                &mut Vec::new(),
            );
            (under, alone)
        }) else {
            return;
        };
        let (kept, warnings) = under.unwrap();
        assert_eq!(kept, [ws, mask]);
        match warnings.as_slice() {
            [w @ SpecWarning::SourceUnderMask(u, at)] => {
                assert_eq!(
                    (u.mode, &u.host, u.error.kind(), &u.link, at.as_path()),
                    (
                        Protected,
                        &foo,
                        io::ErrorKind::PermissionDenied,
                        &None,
                        Path::new("/workspace/d")
                    )
                );
                assert_eq!(
                    w.to_string(),
                    format!(
                        "provider \"p\": cannot resolve the host source {foo:?} of the protected \
                         mount at \"/workspace/d/foo.nix\": {}; it lies inside the directory \
                         masked at \"/workspace/d\", which hides everything there, so the mount \
                         is skipped",
                        u.error
                    )
                );
            }
            other => panic!("unexpected warnings {other:?}"),
        }
        assert_eq!(
            alone.unwrap_err(),
            SpecError::HostSourceUnresolved {
                provider: "p".parse().unwrap(),
                mode: Protected,
                host: foo,
                sandbox: "/workspace/d/foo.nix".into(),
                kind: io::ErrorKind::PermissionDenied,
            }
        );
    }

    #[test]
    fn masked_links_whose_way_fails_after_a_planted_link_are_refused_for_it() {
        // A masked glob match kept as a link (its target could not be
        // inspected while planning) whose parent directory cannot be
        // resolved after following a link inside the workspace (planted,
        // dangling) is refused for that link, not as unresolvable.
        let f = Fixture::new();
        let planted = f.ws().join("planted");
        symlink("nowhere", &planted).unwrap();
        let host = planted.join("x");
        let m = PlannedMount {
            sandbox: "/workspace/planted/x".into(),
            source: MountSource::Host {
                path: host.clone(),
                kind: EntryKind::Symlink,
            },
            mode: Masked,
            provider: "p".parse().unwrap(),
            glob_link: true,
        };
        let roots = UntrustedRoots::new(&f.ws());
        let e = check_host_sources(vec![m], &f.ctx, &roots, &[], &f.state, &mut Vec::new())
            .unwrap_err();
        let SpecError::UntrustedLinkFollowed(found) = &e else {
            panic!("expected an untrusted link, got {e:?}");
        };
        assert_eq!(
            **found,
            LinkFollowed {
                provider: "p".parse().unwrap(),
                mode: Masked,
                host,
                link: planted.clone(),
                resolved: f.ws().join("nowhere"),
                sandbox: "/workspace/planted/x".into(),
                root: UntrustedRoot {
                    path: f.ws(),
                    kind: UntrustedKind::Workspace,
                },
            }
        );
    }

    /// The untrusted root of an `rw` grant of `host` by `provider` in
    /// `profile`, at the canonical `path`.
    fn rw_root(
        path: PathBuf,
        provider: &str,
        profile: Option<&str>,
        host: PathBuf,
    ) -> UntrustedRoot {
        UntrustedRoot {
            path,
            kind: UntrustedKind::RwGrant {
                provider: provider.parse().unwrap(),
                profile: profile.map(pr),
                host,
            },
        }
    }

    /// A fixture with `~/.cache/tool` (to be granted `rw`), `~/.ssh` and a
    /// link `~/.cache/tool/cfg -> ../../.ssh`, as a sandbox with the grant
    /// could plant.
    fn planted_cache_link() -> Fixture {
        let f = Fixture::new();
        f.file("home/.ssh/id_ed25519");
        f.mkdir("home/.cache/tool");
        symlink("../../.ssh", f.root.join("home/.cache/tool/cfg")).unwrap();
        f
    }

    #[test]
    fn links_planted_in_an_rw_grant_are_refused() {
        let f = planted_cache_link();
        let home = f.root.join("home");
        let tool = home.join(".cache/tool");
        // Mounted outside the grant's mount, the host-source check refuses
        // the link.
        let e = compile_body(
            &f,
            "fs.rw = [\"~/.cache/tool\"]\n\
             fs.bind = [{ host = \"~/.cache/tool/cfg\", sandbox = \"/opt/c\", mode = \"ro\" }]",
        )
        .unwrap_err();
        assert_eq!(
            untrusted_link(e, "main"),
            LinkFollowed {
                provider: "p".parse().unwrap(),
                mode: Ro,
                host: tool.join("cfg"),
                link: tool.join("cfg"),
                resolved: home.join(".ssh"),
                sandbox: PathBuf::from("/opt/c"),
                root: rw_root(tool.clone(), "p", Some("main"), tool.clone()),
            }
        );
        // An absolute rule alike (it lands at the host path, outside the
        // grant's mount at `/home/user/.cache/tool`).
        let abs = format!("fs.ro = [{:?}]", tool.join("cfg").to_str().unwrap());
        let e = compile_body(&f, &format!("fs.rw = [\"~/.cache/tool\"]\n{abs}")).unwrap_err();
        let lf = untrusted_link(e, "main");
        assert_eq!((&lf.link, &lf.root.path), (&tool.join("cfg"), &tool));
        // A `~` rule inside the grant's mount fails both checks; the
        // destination check runs first. The link is the final component or
        // one on the way.
        for (rule, sandbox) in [
            ("fs.ro = [\"~/.cache/tool/cfg\"]", "cfg"),
            (
                "fs.protected = [\"~/.cache/tool/cfg/id_ed25519\"]",
                "cfg/id_ed25519",
            ),
        ] {
            let e = compile_body(&f, &format!("fs.rw = [\"~/.cache/tool\"]\n{rule}")).unwrap_err();
            assert_eq!(
                destination_link(e, "main"),
                DestinationLink {
                    provider: "p".parse().unwrap(),
                    mode: if sandbox == "cfg" { Ro } else { Protected },
                    sandbox: Path::new("/home/user/.cache/tool").join(sandbox),
                    host: tool.join(sandbox),
                    link: tool.join("cfg"),
                    ancestor: PathBuf::from("/home/user/.cache/tool"),
                    ancestor_mode: Rw,
                    ancestor_source: tool.clone(),
                    root: rw_root(tool.clone(), "p", Some("main"), tool.clone()),
                },
                "{rule}"
            );
        }
        // Every way of reaching the link through a source.
        for body in [
            "fs.bind = [{ host = \"~/.cache/tool/cfg\", sandbox = \"/opt/c\", mode = \"ro\" }]",
            &abs,
            "fs.bind = [{ host = \"~/.cache/tool/cfg/id_ed25519\", sandbox = \"/opt/k\", \
             mode = \"protected\" }]",
        ] {
            let e = compile_body(&f, &format!("fs.rw = [\"~/.cache/tool\"]\n{body}")).unwrap_err();
            let lf = untrusted_link(e, "main");
            assert_eq!(
                (&lf.link, &lf.root.path),
                (&tool.join("cfg"), &tool),
                "{body}"
            );
        }
        // Without the grant, the link is the host's own and is followed.
        let s = compile_body(&f, "fs.ro = [\"~/.cache/tool/cfg\"]").unwrap();
        assert_eq!(
            mounts(spec(&s, "main")),
            [row("/home/user/.cache/tool/cfg", Ro, "p")]
        );
    }

    #[test]
    fn links_planted_in_an_rw_bind_are_refused() {
        let f = planted_cache_link();
        let home = f.root.join("home");
        let tool = home.join(".cache/tool");
        let e = compile_body(
            &f,
            "fs.bind = [{ host = \"~/.cache/tool\", sandbox = \"/opt/t\", mode = \"rw\" }]\n\
             fs.ro = [\"~/.cache/tool/cfg\"]",
        )
        .unwrap_err();
        let lf = untrusted_link(e, "main");
        assert_eq!(lf.link, tool.join("cfg"));
        assert_eq!(lf.resolved, home.join(".ssh"));
        assert_eq!(lf.root, rw_root(tool.clone(), "p", Some("main"), tool));
    }

    #[test]
    fn links_planted_in_another_profiles_rw_grant_are_refused() {
        let f = planted_cache_link();
        let tool = f.root.join("home/.cache/tool");
        // The grant in a child profile, the rule in `main`, which is planned
        // and checked without the grant but in the same session.
        let e = f
            .try_compile(&format!(
                "base = \"none\"\n[profiles.agent]\n{}{}",
                prov("w", "agent", "fs.rw = [\"~/.cache/tool\"]"),
                prov("r", "main", "fs.ro = [\"~/.cache/tool/cfg\"]"),
            ))
            .unwrap_err();
        let lf = untrusted_link(e, "main");
        assert_eq!(lf.link, tool.join("cfg"));
        assert_eq!(
            lf.root,
            rw_root(tool.clone(), "w", Some("agent"), tool.clone())
        );
        // The grant in `main`, the rule in an unrelated profile.
        let src = format!(
            "base = \"none\"\n[profiles.bare]\ninherit = \"none\"\n{}{}",
            prov("w", "main", "fs.rw = [\"~/.cache/tool\"]"),
            prov("r", "bare", "fs.ro = [\"~/.cache/tool/cfg\"]"),
        );
        let e = f.try_compile(&src).unwrap_err();
        let lf = untrusted_link(e, "bare");
        assert_eq!(
            lf.root,
            rw_root(tool.clone(), "w", Some("main"), tool.clone())
        );
        assert_eq!(
            SpecError::UntrustedLinkFollowed(Box::new(lf)).to_string(),
            format!(
                "provider \"r\": ro mount of {:?} at \"/home/user/.cache/tool/cfg\" runs through \
                 the symlink {:?} inside {tool:?}, granted rw as {tool:?} by provider \"w\" in \
                 profile \"main\" (resolving to {:?}); a sandbox can write there, so links inside \
                 it are never followed, whatever the rule's anchor or the links leading there: \
                 remove the link or change the rule",
                tool.join("cfg"),
                tool.join("cfg"),
                f.root.join("home/.ssh")
            )
        );

        // Compiled on its own, a profile knows only its own grants: `bare`
        // passes, and `main`'s own grant is credited to no profile.
        let cfg = Config::from_toml_str(&src).unwrap();
        let graph = build_profile_graph(&cfg, f.outputs(&cfg)).unwrap();
        let merged = merge_profiles(&graph).unwrap();
        compile_profile(merged.get(&pr("bare")).unwrap(), None, &f.ctx, &f.state).unwrap();
        let mut main = merged.get(&pr("main")).unwrap().clone();
        main.fs
            .extend(merged.get(&pr("bare")).unwrap().fs.iter().cloned());
        // (The rule now lies inside the grant's mount, so the destination
        // check finds the link first.)
        let e = compile_profile(&main, None, &f.ctx, &f.state).unwrap_err();
        let SpecError::DestinationLinkFollowed(dl) = e else {
            panic!("expected DestinationLinkFollowed, got {e:?}");
        };
        assert_eq!(dl.root, rw_root(tool.clone(), "w", None, tool));
    }

    #[test]
    fn rw_grants_without_planted_links_and_host_links_are_accepted() {
        let f = Fixture::new();
        f.mkdir("home/.cache/tool/cfg");
        // A host-controlled link outside every root (home-manager style).
        f.file("store/foo/config");
        f.mkdir("home/.config");
        symlink(f.root.join("store/foo"), f.root.join("home/.config/foo")).unwrap();
        for src in [
            format!(
                "base = \"none\"\n{}",
                prov(
                    "p",
                    "main",
                    "fs.rw = [\"~/.cache/tool\"]\nfs.ro = [\"~/.cache/tool/cfg\", \"~/.config/foo\"]"
                )
            ),
            format!(
                "base = \"none\"\n[profiles.agent]\n{}{}",
                prov("w", "agent", "fs.rw = [\"~/.cache/tool\"]"),
                prov(
                    "r",
                    "main",
                    "fs.ro = [\"~/.cache/tool/cfg\", \"~/.config/foo/config\"]\n\
                     fs.masked = [\"~/.config/foo\"]"
                ),
            ),
            // The default base grants the workspace `rw` too.
            prov(
                "r",
                "main",
                "fs.rw = [\"~/.cache/tool\"]\nfs.ro = [\"~/.config/foo\"]",
            ),
        ] {
            if let Err(e) = f.try_compile(&src) {
                panic!("{src}: {e}");
            }
        }
    }

    #[test]
    fn rw_sources_written_through_host_links_make_their_target_a_root() {
        let f = planted_cache_link();
        let home = f.root.join("home");
        let tool = home.join(".cache/tool");
        symlink(".cache", home.join("cachelink")).unwrap();
        let e = compile_body(
            &f,
            "fs.rw = [\"~/cachelink/tool\"]\nfs.ro = [\"~/.cache/tool/cfg\"]",
        )
        .unwrap_err();
        let lf = untrusted_link(e, "main");
        assert_eq!(lf.link, tool.join("cfg"));
        assert_eq!(
            lf.root,
            rw_root(tool, "p", Some("main"), home.join("cachelink/tool"))
        );
    }

    #[test]
    fn nested_roots_attribute_links_to_the_innermost() {
        let f = Fixture::with_workspace("home/proj", "/workspace");
        let home = f.root.join("home");
        let cache = home.join(".cache");
        let tool = cache.join("tool");
        f.file("home/.ssh/id_ed25519");
        f.mkdir("home/.cache/tool");
        symlink("../../.ssh", tool.join("x")).unwrap();
        symlink("../.ssh", cache.join("y")).unwrap();
        symlink("../.ssh", f.ws().join("z")).unwrap();
        let grants = "fs.rw = [\"~/.cache\", \"~/.cache/tool\", \"{workspace}\"]\n";
        let cache_root = rw_root(cache.clone(), "p", Some("main"), cache.clone());
        let tool_root = rw_root(tool.clone(), "p", Some("main"), tool.clone());
        // An `rw` grant of the workspace is the same root as the workspace,
        // credited to the workspace.
        let ws_root = UntrustedRoot {
            path: f.ws(),
            kind: UntrustedKind::Workspace,
        };
        for (rule, link, root) in [
            ("~/.cache/tool/x", tool.join("x"), &tool_root),
            ("~/.cache/y", cache.join("y"), &cache_root),
            ("~/proj/z", f.ws().join("z"), &ws_root),
        ] {
            // Bound elsewhere, by the host-source check.
            let bind =
                format!("fs.bind = [{{ host = \"{rule}\", sandbox = \"/opt/r\", mode = \"ro\" }}]");
            let e = compile_body(&f, &format!("{grants}{bind}")).unwrap_err();
            let lf = untrusted_link(e, "main");
            assert_eq!((&lf.link, &lf.root), (&link, root), "{rule}");
            // At its `~` path, by the destination check, except for `~/proj/z`,
            // which no mount lies underneath (the workspace is mounted at
            // `/workspace`).
            let e = compile_body(&f, &format!("{grants}fs.ro = [\"{rule}\"]")).unwrap_err();
            let (got_link, got_root) = if rule == "~/proj/z" {
                let lf = untrusted_link(e, "main");
                (lf.link, lf.root)
            } else {
                let dl = destination_link(e, "main");
                (dl.link, dl.root)
            };
            assert_eq!((&got_link, &got_root), (&link, root), "{rule}");
        }
        // An inner grant replaced by a link through the outer one lies inside
        // the outer grant's mount, so its mount is dropped with a warning.
        fs::remove_dir_all(&tool).unwrap();
        symlink("../.ssh", &tool).unwrap();
        let s = compile_body(&f, grants).unwrap();
        assert_eq!(
            mounts(spec(&s, "main")),
            [
                row("/workspace", Rw, "p"),
                row("/home/user/.cache", Rw, "p")
            ]
        );
        let dl = destination_warnings(&s, "main");
        assert_eq!(dl.len(), 1);
        assert_eq!(
            (dl[0].mode, &dl[0].link, &dl[0].root),
            (Rw, &tool, &cache_root)
        );
        // Bound elsewhere, the host-source check refuses it: an `rw` bind is
        // dropped with a warning, an `ro` one is an error.
        let bind = |mode: &str| {
            format!(
                "fs.rw = [\"~/.cache\"]\n\
                 fs.bind = [{{ host = \"~/.cache/tool\", sandbox = \"/opt/t\", \
                 mode = \"{mode}\" }}]"
            )
        };
        let s = compile_body(&f, &bind("rw")).unwrap();
        assert_eq!(
            mounts(spec(&s, "main")),
            [row("/home/user/.cache", Rw, "p")]
        );
        let lf = source_warnings(&s, "main");
        assert_eq!(lf.len(), 1);
        assert_eq!(
            (lf[0].mode, &lf[0].link, &lf[0].root),
            (Rw, &tool, &cache_root)
        );
        let e = compile_body(&f, &bind("ro")).unwrap_err();
        let lf = untrusted_link(e, "main");
        assert_eq!((lf.mode, &lf.link, &lf.root.path), (Ro, &tool, &cache));
    }

    #[test]
    fn masks_shaped_by_planted_links_are_refused() {
        let f = planted_cache_link();
        let tool = f.root.join("home/.cache/tool");
        // With the grant in another profile, nothing is mounted underneath
        // the mask in `main`, and the host-source check refuses the link
        // (the final component, or one on the way).
        for mask in ["~/.cache/tool/cfg", "~/.cache/tool/cfg/id_ed25519"] {
            let e = f
                .try_compile(&format!(
                    "base = \"none\"\n[profiles.agent]\ninherit = \"none\"\n{}{}",
                    prov("w", "agent", "fs.rw = [\"~/.cache/tool\"]"),
                    prov("p", "main", &format!("fs.masked = [\"{mask}\"]")),
                ))
                .unwrap_err();
            let lf = untrusted_link(e, "main");
            assert_eq!(
                (lf.mode, &lf.link, &lf.root.path),
                (Masked, &tool.join("cfg"), &tool),
                "{mask}"
            );
            // With the grant in `main`, the mask lies inside the grant's
            // mount, and the destination check refuses it first: the link
            // would move the mask, leaving the real path visible.
            let e = compile_body(
                &f,
                &format!("fs.rw = [\"~/.cache/tool\"]\nfs.masked = [\"{mask}\"]"),
            )
            .unwrap_err();
            let dl = destination_link(e, "main");
            assert_eq!(
                (dl.mode, &dl.link, &dl.root.path),
                (Masked, &tool.join("cfg"), &tool),
                "{mask}"
            );
        }
        // Without the grant the link is the host's, and the mask takes the
        // target's kind.
        let s = compile_body(&f, "fs.masked = [\"~/.cache/tool/cfg\"]").unwrap();
        assert_eq!(
            spec(&s, "main").mounts[0].source,
            MountSource::Host {
                path: tool.join("cfg"),
                kind: EntryKind::Dir
            }
        );
    }

    /// The `DestinationLink` of an `rw` grant's mount at `ancestor` of the
    /// canonical `source`, for the mount of `mode` by `p` at `sandbox`
    /// reaching the host path `host` through `link` in `root`.
    fn dest_link(
        mode: PathMode,
        sandbox: &str,
        host: PathBuf,
        link: PathBuf,
        ancestor: &str,
        source: PathBuf,
        root: UntrustedRoot,
    ) -> DestinationLink {
        DestinationLink {
            provider: "p".parse().unwrap(),
            mode,
            sandbox: sandbox.into(),
            host,
            link,
            ancestor: ancestor.into(),
            ancestor_mode: Rw,
            ancestor_source: source,
            root,
        }
    }

    #[test]
    fn destinations_inside_an_rw_grant_never_follow_planted_links() {
        let f = planted_cache_link();
        let home = f.root.join("home");
        let tool = home.join(".cache/tool");
        let root = rw_root(tool.clone(), "p", Some("main"), tool.clone());
        let grant = "fs.rw = [\"~/.cache/tool\"]\n";
        // A bind whose source is fine, at the planted link: only the
        // destination check sees the link.
        f.file("home/cfg");
        for (name, mode) in [("ro", Ro), ("protected", Protected)] {
            let body = format!(
                "{grant}fs.bind = [{{ host = \"~/cfg\", sandbox = \"/home/user/.cache/tool/cfg\", \
                 mode = \"{name}\" }}]"
            );
            let e = compile_body(&f, &body).unwrap_err();
            assert_eq!(
                destination_link(e, "main"),
                DestinationLink {
                    mode,
                    ..dest_link(
                        Ro,
                        "/home/user/.cache/tool/cfg",
                        tool.join("cfg"),
                        tool.join("cfg"),
                        "/home/user/.cache/tool",
                        tool.clone(),
                        root.clone()
                    )
                },
                "{mode}"
            );
        }
        // A planted link on the way (`d -> ..`, so `d/cfg` is
        // `~/.cache/cfg`): the destination check refuses it first, though
        // the host-source check would too.
        f.file("home/.cache/cfg");
        symlink("..", tool.join("d")).unwrap();
        let e = compile_body(&f, &format!("{grant}fs.ro = [\"~/.cache/tool/d/cfg\"]")).unwrap_err();
        assert_eq!(
            destination_link(e, "main"),
            dest_link(
                Ro,
                "/home/user/.cache/tool/d/cfg",
                tool.join("d/cfg"),
                tool.join("d"),
                "/home/user/.cache/tool",
                tool.clone(),
                root.clone()
            )
        );
        let e = compile_body(&f, &format!("{grant}fs.ro = [\"~/.cache/tool/d/cfg\"]")).unwrap_err();
        assert_eq!(
            e.to_string(),
            format!(
                "cannot compile profile \"main\": provider \"p\": the ro mount at \
                 \"/home/user/.cache/tool/d/cfg\" lies inside the rw mount at \
                 \"/home/user/.cache/tool\" of {tool:?}, where reaching it means following the \
                 symlink {:?} (on the way to {:?}) inside {tool:?}, granted rw as {tool:?} by \
                 provider \"p\" in profile \"main\"; a sandbox can write there and bwrap follows \
                 links when mounting, so the mount would land elsewhere, and a ro mount is never \
                 skipped: remove the link or change the rule",
                tool.join("d"),
                tool.join("d/cfg"),
            )
        );
        // An `rw` mount there is dropped with a warning instead.
        let s = compile_body(&f, "fs.rw = [\"~/.cache/tool\", \"~/.cache/tool/cfg\"]").unwrap();
        assert_eq!(
            mounts(spec(&s, "main")),
            [row("/home/user/.cache/tool", Rw, "p")]
        );
        assert_eq!(
            destination_warnings(&s, "main"),
            [dest_link(
                Rw,
                "/home/user/.cache/tool/cfg",
                tool.join("cfg"),
                tool.join("cfg"),
                "/home/user/.cache/tool",
                tool.clone(),
                root.clone()
            )]
        );
        let msg = get(&s, "main").warnings[0].to_string();
        assert!(msg.ends_with("so the rw mount is skipped"), "{msg}");
        // A real directory, or a missing path, is fine.
        f.mkdir("home/.cache/tool/real");
        let s = compile_body(
            &f,
            &format!(
                "{grant}fs.masked = [\"~/.cache/tool/real\"]\n\
                 fs.bind = [{{ host = \"~/cfg\", sandbox = \"/home/user/.cache/tool/new/cfg\", \
                 mode = \"ro\" }}]"
            ),
        )
        .unwrap();
        assert_eq!(
            mounts(spec(&s, "main")),
            [
                row("/home/user/.cache/tool", Rw, "p"),
                row("/home/user/.cache/tool/real", Masked, "p"),
                row("/home/user/.cache/tool/new/cfg", Ro, "p"),
            ]
        );
    }

    #[test]
    fn destinations_below_host_controlled_mounts_follow_host_links() {
        // `~/.config` is the host's, with a home-manager style link in it;
        // bwrap follows that link to place a mount below it, as it should.
        let f = Fixture::new();
        f.file("store/foo/config");
        f.file("home/cfg");
        f.mkdir("home/.config");
        symlink(f.root.join("store/foo"), f.root.join("home/.config/foo")).unwrap();
        for (rule, sandbox, mode) in [
            (
                "fs.bind = [{ host = \"~/cfg\", sandbox = \"/home/user/.config/foo/config\", \
                 mode = \"protected\" }]",
                "/home/user/.config/foo/config",
                Protected,
            ),
            (
                "fs.masked = [\"~/.config/foo\"]",
                "/home/user/.config/foo",
                Masked,
            ),
        ] {
            let s = compile_body(&f, &format!("fs.ro = [\"~/.config\"]\n{rule}")).unwrap();
            assert_eq!(
                mounts(spec(&s, "main")),
                [row("/home/user/.config", Ro, "p"), row(sandbox, mode, "p")],
                "{rule}"
            );
        }
    }

    #[test]
    fn untrusted_roots_below_a_host_controlled_mount_are_checked() {
        // `ro ~` is the host's, but `~/.cache/tool` is granted `rw` by
        // another profile, whose sandbox planted `cfg`: a mask below `~`
        // reaching it is refused.
        let f = planted_cache_link();
        let home = f.root.join("home");
        let tool = home.join(".cache/tool");
        let e = f
            .try_compile(&format!(
                "base = \"none\"\n[profiles.agent]\ninherit = \"none\"\n{}{}",
                prov("w", "agent", "fs.rw = [\"~/.cache/tool\"]"),
                prov(
                    "p",
                    "main",
                    "fs.ro = [\"~\"]\nfs.masked = [\"~/.cache/tool/cfg\"]"
                ),
            ))
            .unwrap_err();
        assert_eq!(
            destination_link(e, "main"),
            DestinationLink {
                provider: "p".parse().unwrap(),
                mode: Masked,
                sandbox: "/home/user/.cache/tool/cfg".into(),
                host: tool.join("cfg"),
                link: tool.join("cfg"),
                ancestor: "/home/user".into(),
                ancestor_mode: Ro,
                ancestor_source: home.clone(),
                root: rw_root(tool.clone(), "w", Some("agent"), tool),
            }
        );
    }

    #[test]
    fn workspace_destinations_are_checked_against_the_workspace_mount() {
        let f = Fixture::new();
        f.file("home/cfg");
        f.mkdir("ws/decoy");
        symlink("decoy", f.ws().join("cfg")).unwrap();
        symlink("decoy", f.ws().join("dir")).unwrap();
        let ws_root = UntrustedRoot {
            path: f.ws(),
            kind: UntrustedKind::Workspace,
        };
        let grant = "fs.rw = [\"{workspace}\"]\n";
        // `(rule, sandbox, link)`: binds, an ephemeral rule (relative or
        // absolute) and a literal `{workspace}` rule's final link.
        for (rule, mode, sandbox, link) in [
            (
                "fs.bind = [{ host = \"~/cfg\", sandbox = \"/workspace/cfg\", mode = \"ro\" }]",
                Ro,
                "cfg",
                "cfg",
            ),
            (
                "fs.bind = [{ host = \"~/cfg\", sandbox = \"/workspace/dir/cfg\", \
                 mode = \"protected\" }]",
                Protected,
                "dir/cfg",
                "dir",
            ),
            (
                "fs.ephemeral = [\"{workspace}/cfg\"]",
                Ephemeral,
                "cfg",
                "cfg",
            ),
            (
                "fs.ephemeral = [\"/workspace/dir/x\"]",
                Ephemeral,
                "dir/x",
                "dir",
            ),
            ("fs.masked = [\"{workspace}/cfg\"]", Masked, "cfg", "cfg"),
        ] {
            let e = compile_body(&f, &format!("{grant}{rule}")).unwrap_err();
            assert_eq!(
                destination_link(e, "main"),
                DestinationLink {
                    mode,
                    ..dest_link(
                        Rw,
                        &format!("/workspace/{sandbox}"),
                        f.ws().join(sandbox),
                        f.ws().join(link),
                        "/workspace",
                        f.ws(),
                        ws_root.clone()
                    )
                },
                "{rule}"
            );
        }
        // `rw` mounts are dropped with a warning.
        let s = compile_body(
            &f,
            "fs.rw = [\"{workspace}\", \"{workspace}/cfg\"]\n\
             fs.bind = [{ host = \"~/cfg\", sandbox = \"/workspace/dir/cfg\", mode = \"rw\" }]",
        )
        .unwrap();
        assert_eq!(mounts(spec(&s, "main")), [row("/workspace", Rw, "p")]);
        let links: Vec<_> = destination_warnings(&s, "main")
            .into_iter()
            .map(|d| (d.sandbox, d.link))
            .collect();
        assert_eq!(
            links,
            [
                (PathBuf::from("/workspace/cfg"), f.ws().join("cfg")),
                (PathBuf::from("/workspace/dir/cfg"), f.ws().join("dir")),
            ]
        );
        // A missing destination is fine, and one outside the workspace
        // mount is not below it.
        let s = compile_body(
            &f,
            &format!(
                "{grant}fs.bind = [\n\
                 {{ host = \"~/cfg\", sandbox = \"/workspace/new/cfg\", mode = \"ro\" }},\n\
                 {{ host = \"~/cfg\", sandbox = \"/workspacex/cfg\", mode = \"ro\" }},\n]"
            ),
        )
        .unwrap();
        assert_eq!(
            mounts(spec(&s, "main")),
            [
                row("/workspace", Rw, "p"),
                row("/workspacex/cfg", Ro, "p"),
                row("/workspace/new/cfg", Ro, "p"),
            ]
        );
        // Without the workspace mount, the binds and the ephemeral rule land
        // on bwrap's root tmpfs and nothing is underneath to check (a
        // `{workspace}` rule's final link is still refused, by the
        // host-source check).
        let s = compile_body(
            &f,
            "fs.bind = [{ host = \"~/cfg\", sandbox = \"/workspace/cfg\", mode = \"ro\" }]\n\
             fs.ephemeral = [\"/workspace/dir/x\"]",
        )
        .unwrap();
        assert_eq!(
            mounts(spec(&s, "main")),
            [
                row("/workspace/cfg", Ro, "p"),
                row("/workspace/dir/x", Ephemeral, "p"),
            ]
        );
        let e = compile_body(&f, "fs.masked = [\"{workspace}/cfg\"]").unwrap_err();
        assert_eq!(untrusted_link(e, "main").link, f.ws().join("cfg"));
    }

    #[test]
    fn workspace_destination_links_are_decided_by_the_winning_mode() {
        let f = Fixture::new();
        f.file("home/cfg");
        // Not dangling: a mask of a dangling link is dropped by the planner,
        // whatever the anchor, as there is no target to take a shape from.
        f.file("ws/decoy");
        symlink("decoy", f.ws().join("cfg")).unwrap();
        // The masked rule wins over the ro bind, so the link is an error.
        let e = compile_body(
            &f,
            "fs.rw = [\"{workspace}\"]\nfs.masked = [\"{workspace}/cfg\"]\n\
             fs.bind = [{ host = \"~/cfg\", sandbox = \"/workspace/cfg\", mode = \"ro\" }]",
        )
        .unwrap_err();
        assert_eq!(destination_link(e, "main").mode, Masked);
        // In `child`, its own rw rule beats the mask inherited from `main`:
        // the winner is dropped with a warning, and nothing is mounted there.
        // (`main` itself has the masked winner, and fails.)
        let src = format!(
            "base = \"none\"\n[profiles.child]\n{}{}",
            prov(
                "p",
                "main",
                "fs.rw = [\"{workspace}\"]\nfs.masked = [\"{workspace}/cfg\"]"
            ),
            prov("c", "child", "fs.rw = [\"{workspace}/cfg\"]"),
        );
        let e = f.compile_err(&src);
        assert_eq!(destination_link(e, "main").mode, Masked);
        let cfg = Config::from_toml_str(&src).unwrap();
        let graph = build_profile_graph(&cfg, f.outputs(&cfg)).unwrap();
        let merged = merge_profiles(&graph).unwrap();
        let child =
            compile_profile(merged.get(&pr("child")).unwrap(), None, &f.ctx, &f.state).unwrap();
        assert_eq!(mounts(&child.spec), [row("/workspace", Rw, "p")]);
        assert!(
            matches!(
                child.warnings.as_slice(),
                [SpecWarning::DestinationLink(d)] if d.mode == Rw && d.provider.as_str() == "c"
            ),
            "{:?}",
            child.warnings
        );
    }

    #[test]
    fn workspace_rules_through_planted_links_are_refused() {
        // `{workspace}` rules are resolved like any other: a link on the
        // way is refused because the workspace is an untrusted root, by the
        // destination check when the workspace is mounted underneath and by
        // the host-source check otherwise.
        let f = Fixture::new();
        f.file("ws/real/x");
        f.file("ws/real/.env");
        symlink("real", f.ws().join("link")).unwrap();
        let link = f.ws().join("link");
        for (mode, pm) in [("masked", Masked), ("protected", Protected), ("ro", Ro)] {
            let rule = format!("fs.{mode} = [\"{{workspace}}/link/x\"]");
            let e = compile_body(&f, &format!("fs.rw = [\"{{workspace}}\"]\n{rule}")).unwrap_err();
            let dl = destination_link(e, "main");
            assert_eq!(
                (dl.mode, &dl.link, dl.ancestor.as_path(), dl.root.kind),
                (pm, &link, Path::new("/workspace"), UntrustedKind::Workspace),
                "{rule}"
            );
            let lf = untrusted_link(compile_body(&f, &rule).unwrap_err(), "main");
            assert_eq!((lf.mode, &lf.link), (pm, &link), "{rule}");
            // A glob whose walk root is the link, or below it, is refused by
            // the planner before walking, with or without the workspace
            // mount.
            for pattern in ["{workspace}/link/*", "{workspace}/link/**/*.env"] {
                let rule = format!("fs.{mode} = [\"{pattern}\"]");
                for body in [rule.clone(), format!("fs.rw = [\"{{workspace}}\"]\n{rule}")] {
                    let CompileError::Profile { error, .. } = compile_body(&f, &body).unwrap_err()
                    else {
                        panic!("{body}: expected a profile error");
                    };
                    match *error {
                        SpecError::Mounts(PathPlanError::WalkRootLink(ref w)) => {
                            assert_eq!((w.mode, &w.link), (pm, &link), "{body}")
                        }
                        ref other => panic!("{body}: expected WalkRootLink, got {other:?}"),
                    }
                }
            }
        }
        // Links escaping the workspace (`up -> ..`, an absolute link out of
        // it) are refused alike for restrictive rules, here without the
        // workspace mount, by the host-source check.
        f.file("outside/secret");
        symlink("..", f.ws().join("up")).unwrap();
        symlink(f.root.join("outside"), f.ws().join("out")).unwrap();
        for (pattern, via, resolved) in [
            (
                "{workspace}/up/outside/secret",
                "up",
                f.root.join("outside/secret"),
            ),
            (
                "{workspace}/out/secret",
                "out",
                f.root.join("outside/secret"),
            ),
        ] {
            for (mode, pm) in [("masked", Masked), ("protected", Protected), ("ro", Ro)] {
                let rule = format!("fs.{mode} = [\"{pattern}\"]");
                let lf = untrusted_link(compile_body(&f, &rule).unwrap_err(), "main");
                assert_eq!(
                    (
                        lf.mode,
                        &lf.link,
                        &lf.resolved,
                        lf.sandbox.as_path(),
                        lf.root.kind
                    ),
                    (
                        pm,
                        &f.ws().join(via),
                        &resolved,
                        Path::new("/workspace")
                            .join(pattern.trim_start_matches("{workspace}/"))
                            .as_path(),
                        UntrustedKind::Workspace
                    ),
                    "{rule}"
                );
            }
        }
        // `rw` rules are dropped with a warning instead.
        let s = compile_body(&f, "fs.rw = [\"{workspace}\", \"{workspace}/link/x\"]").unwrap();
        assert_eq!(mounts(spec(&s, "main")), [row("/workspace", Rw, "p")]);
        assert_eq!(destination_warnings(&s, "main")[0].link, link);
        let s = compile_body(&f, "fs.rw = [\"{workspace}/link/x\"]").unwrap();
        assert!(spec(&s, "main").mounts.is_empty());
        assert_eq!(source_warnings(&s, "main")[0].link, link);
        // A path through a link that leads nowhere is missing, like any
        // missing path: there is nothing to restrict.
        let s = compile_body(&f, "fs.masked = [\"{workspace}/link/nope/deeper\"]").unwrap();
        assert!(spec(&s, "main").mounts.is_empty());
        assert!(
            matches!(
                get(&s, "main").warnings.as_slice(),
                [SpecWarning::Mount(PlanWarning {
                    kind: PlanWarningKind::Resolve(ResolveWarning::Missing { .. }),
                    ..
                })]
            ),
            "{:?}",
            get(&s, "main").warnings
        );
    }

    #[test]
    fn masked_dangling_workspace_links_are_skipped() {
        // A masked link whose target is missing has nothing to hide and no
        // shape to take, whatever the anchor: it is skipped with a warning,
        // literal or matched by a glob, with or without the workspace mount.
        let f = Fixture::new();
        symlink("nowhere", f.ws().join("a.env")).unwrap();
        for body in [
            "fs.masked = [\"{workspace}/a.env\"]",
            "fs.masked = [\"{workspace}/*.env\"]",
            "fs.rw = [\"{workspace}\"]\nfs.masked = [\"{workspace}/a.env\"]",
        ] {
            let s = compile_body(&f, body).unwrap();
            assert!(
                spec(&s, "main")
                    .mounts
                    .iter()
                    .all(|m| m.sandbox == Path::new("/workspace")),
                "{body}"
            );
            match get(&s, "main").warnings.as_slice() {
                [
                    SpecWarning::Mount(PlanWarning {
                        kind: PlanWarningKind::SymlinkTarget { path, error },
                        ..
                    }),
                ] => assert_eq!(
                    (path, error.kind()),
                    (&f.ws().join("a.env"), io::ErrorKind::NotFound),
                    "{body}"
                ),
                other => panic!("{body}: expected one SymlinkTarget warning, got {other:?}"),
            }
        }
    }

    #[test]
    fn masked_glob_links_with_uninspectable_targets() {
        use std::os::unix::fs::PermissionsExt;
        if rustix::process::geteuid().is_root() {
            eprintln!("skipping: permission checks do not apply to root");
            return;
        }
        let f = Fixture::new();
        f.file("ws/locked/x");
        f.file("home/locked/x");
        f.mkdir("home/sub");
        symlink("locked/x", f.ws().join("a.env")).unwrap();
        symlink("../locked/x", f.root.join("home/sub/l")).unwrap();
        let locked = [f.ws().join("locked"), f.root.join("home/locked")];
        for l in &locked {
            fs::set_permissions(l, fs::Permissions::from_mode(0o000)).unwrap();
        }
        // Inside the workspace, the match is skipped like any glob-matched
        // link there, without looking at its target.
        let skipped = compile_body(&f, "fs.masked = [\"{workspace}/*.env\"]");
        // A host link outside every root must have an inspectable target:
        // a masked rule is never skipped.
        let host = compile_body(&f, "fs.masked = [\"~/sub/*\"]");
        // A literal rule fails while planning, as before.
        let literal = compile_body(&f, "fs.masked = [\"{workspace}/a.env\"]");
        for l in &locked {
            fs::set_permissions(l, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let s = skipped.unwrap();
        assert!(spec(&s, "main").mounts.is_empty());
        assert_eq!(glob_links(&s, "main")[0].2, f.ws().join("a.env"));
        let CompileError::Profile { error, .. } = host.unwrap_err() else {
            panic!("expected a profile error");
        };
        let msg = error.to_string();
        assert_eq!(
            *error,
            SpecError::MaskTargetUninspectable {
                provider: "p".parse().unwrap(),
                host: f.root.join("home/sub/l"),
                sandbox: "/home/user/sub/l".into(),
                kind: io::ErrorKind::PermissionDenied,
            }
        );
        assert!(msg.contains("a masked rule is never skipped"), "{msg}");
        let CompileError::Profile { error, .. } = literal.unwrap_err() else {
            panic!("expected a profile error");
        };
        assert!(
            matches!(
                *error,
                SpecError::Mounts(PathPlanError::Inaccessible { mode: Masked, .. })
            ),
            "{error:?}"
        );
    }

    #[test]
    fn workspace_binds_through_planted_links_are_refused() {
        // A bind's host side through a link inside the workspace is refused
        // like a `~` bind's: an error for `ro` and `protected`, a dropped
        // mount for `rw`. (The planner used to skip every such bind with a
        // warning; a restrictive bind now fails closed like any other.)
        let f = Fixture::new();
        f.file("ws/real/x");
        f.file("outside/secret");
        symlink("real", f.ws().join("via")).unwrap();
        symlink(f.root.join("outside"), f.ws().join("out")).unwrap();
        symlink(f.root.join("outside/secret"), f.ws().join("final")).unwrap();
        for (host, link) in [("via/x", "via"), ("out/secret", "out"), ("final", "final")] {
            for (mode, pm) in [("ro", Ro), ("protected", Protected)] {
                let bind = format!(
                    "fs.bind = [{{ host = \"{{workspace}}/{host}\", sandbox = \"/opt/b\", \
                     mode = \"{mode}\" }}]"
                );
                let lf = untrusted_link(compile_body(&f, &bind).unwrap_err(), "main");
                assert_eq!(
                    (lf.mode, &lf.link, lf.sandbox.as_path()),
                    (pm, &f.ws().join(link), Path::new("/opt/b")),
                    "{bind}"
                );
            }
            let bind = format!(
                "fs.bind = [{{ host = \"{{workspace}}/{host}\", sandbox = \"/opt/b\", \
                 mode = \"rw\" }}]"
            );
            let s = compile_body(&f, &bind).unwrap();
            assert!(spec(&s, "main").mounts.is_empty(), "{bind}");
            assert_eq!(
                source_warnings(&s, "main")[0].link,
                f.ws().join(link),
                "{bind}"
            );
        }
    }

    /// The `GlobLink` of every `GlobLink` warning of `profile` as
    /// `(provider, mode, link, sandbox)`; panics on any other warning.
    fn glob_links(s: &CompiledSession, profile: &str) -> Vec<(String, PathMode, PathBuf, PathBuf)> {
        get(s, profile)
            .warnings
            .iter()
            .map(|w| match w {
                SpecWarning::GlobLink(gl) => (
                    gl.provider.to_string(),
                    gl.mode,
                    gl.link.clone(),
                    gl.sandbox.clone(),
                ),
                other => panic!("unexpected warning {other:?}"),
            })
            .collect()
    }

    #[test]
    fn glob_matched_links_in_untrusted_roots_are_skipped_for_every_mode() {
        let f = Fixture::new();
        f.file("ws/bar.nix");
        f.file("ws/nix/real.nix");
        symlink("bar.nix", f.ws().join("foo.nix")).unwrap();
        symlink("real.nix", f.ws().join("nix/alias.nix")).unwrap();
        for (mode, pm) in [
            ("masked", Masked),
            ("protected", Protected),
            ("ro", Ro),
            ("rw", Rw),
        ] {
            let body = if pm == Rw {
                "fs.rw = [\"{workspace}\", \"{workspace}/**/*.nix\"]".to_owned()
            } else {
                format!("fs.rw = [\"{{workspace}}\"]\nfs.{mode} = [\"{{workspace}}/**/*.nix\"]")
            };
            let s = compile_body(&f, &body).unwrap();
            // The links are not mounted; their targets are matched directly.
            assert_eq!(
                mounts(spec(&s, "main")),
                [
                    row("/workspace", Rw, "p"),
                    row("/workspace/bar.nix", pm, "p"),
                    row("/workspace/nix/real.nix", pm, "p"),
                ],
                "{mode}"
            );
            assert_eq!(
                glob_links(&s, "main"),
                [
                    (
                        "p".into(),
                        pm,
                        f.ws().join("foo.nix"),
                        PathBuf::from("/workspace/foo.nix")
                    ),
                    (
                        "p".into(),
                        pm,
                        f.ws().join("nix/alias.nix"),
                        PathBuf::from("/workspace/nix/alias.nix")
                    ),
                ],
                "{mode}"
            );
        }
        // Without the workspace mount too: the workspace is always a root.
        let s = compile_body(&f, "fs.masked = [\"{workspace}/nix/*\"]").unwrap();
        assert_eq!(
            mounts(spec(&s, "main")),
            [row("/workspace/nix/real.nix", Masked, "p")]
        );
        assert_eq!(get(&s, "main").warnings.len(), 1);
        assert_eq!(
            get(&s, "main").warnings[0].to_string(),
            format!(
                "provider \"p\": the masked glob match {:?} at \"/workspace/nix/alias.nix\" is the \
                 symlink {:?} inside the host workspace {:?}; a sandbox can write there, so \
                 links inside it are never followed, and the match is skipped (write a rule for \
                 the link's target if it needs one)",
                f.ws().join("nix/alias.nix"),
                f.ws().join("nix/alias.nix"),
                f.ws()
            )
        );
    }

    #[test]
    fn glob_matched_links_are_skipped_whatever_the_anchor_or_root() {
        // Inside an rw grant, in this profile or another one.
        let f = planted_cache_link();
        let tool = f.root.join("home/.cache/tool");
        let s = compile_body(
            &f,
            "fs.rw = [\"~/.cache/tool\"]\nfs.masked = [\"~/.cache/tool/*\"]",
        )
        .unwrap();
        assert_eq!(
            mounts(spec(&s, "main")),
            [row("/home/user/.cache/tool", Rw, "p")]
        );
        assert_eq!(
            glob_links(&s, "main"),
            [(
                "p".into(),
                Masked,
                tool.join("cfg"),
                PathBuf::from("/home/user/.cache/tool/cfg")
            )]
        );
        let s = f
            .try_compile(&format!(
                "base = \"none\"\n[profiles.agent]\ninherit = \"none\"\n{}{}",
                prov("w", "agent", "fs.rw = [\"~/.cache/tool\"]"),
                prov("p", "main", "fs.ro = [\"~/.cache/*/cfg\"]"),
            ))
            .unwrap();
        assert!(spec(&s, "main").mounts.is_empty());
        assert_eq!(glob_links(&s, "main")[0].2, tool.join("cfg"));
        // A host link outside every root is kept, and followed.
        let f = Fixture::new();
        f.file("store/foo/config");
        f.mkdir("home/.config");
        symlink(f.root.join("store/foo"), f.root.join("home/.config/foo")).unwrap();
        let s = compile_body(&f, "fs.ro = [\"~/.config/*\"]").unwrap();
        assert!(get(&s, "main").warnings.is_empty());
        assert_eq!(
            mounts(spec(&s, "main")),
            [row("/home/user/.config/foo", Ro, "p")]
        );
    }

    #[test]
    fn glob_matched_links_behind_planted_links_are_refused() {
        // The walk root is a planted link, so the glob did not reach the
        // real files: a link matched there is no skip but an error for a
        // restrictive rule, like the files matched with it. Inside the
        // workspace the planner refuses such a walk root before walking;
        // inside an `rw` grant (not known while planning) it is walked and
        // its matches are refused afterwards.
        let f = planted_cache_link();
        f.file("home/.ssh/b.nix");
        symlink("b.nix", f.root.join("home/.ssh/a.nix")).unwrap();
        let tool = f.root.join("home/.cache/tool");
        let e = compile_body(
            &f,
            "fs.rw = [\"~/.cache/tool\"]\nfs.masked = [\"~/.cache/tool/cfg/a*\"]",
        )
        .unwrap_err();
        assert_eq!(destination_link(e, "main").link, tool.join("cfg"));
        let e = f
            .try_compile(&format!(
                "base = \"none\"\n[profiles.agent]\ninherit = \"none\"\n{}{}",
                prov("w", "agent", "fs.rw = [\"~/.cache/tool\"]"),
                prov("p", "main", "fs.masked = [\"~/.cache/tool/cfg/a*\"]"),
            ))
            .unwrap_err();
        assert_eq!(untrusted_link(e, "main").link, tool.join("cfg"));
    }

    #[test]
    fn a_skipped_glob_link_leaves_nothing_at_its_path() {
        let f = Fixture::new();
        f.file("ws/real.env");
        symlink("real.env", f.ws().join("link.env")).unwrap();
        // An inherited rw glob and an own masked glob both match the link:
        // the masked one wins and is skipped, so nothing is mounted there
        // (the link shows through whatever is underneath, and its target is
        // matched directly).
        let s = f
            .try_compile(&format!(
                "base = \"none\"\n[profiles.child]\n{}{}",
                prov("parent", "main", "fs.rw = [\"{workspace}/*.env\"]"),
                prov("own", "child", "fs.masked = [\"{workspace}/*.env\"]"),
            ))
            .unwrap();
        assert_eq!(
            mounts(spec(&s, "child")),
            [row("/workspace/real.env", Masked, "own")]
        );
        assert_eq!(
            glob_links(&s, "child"),
            [(
                "own".into(),
                Masked,
                f.ws().join("link.env"),
                PathBuf::from("/workspace/link.env")
            )]
        );
        // A literal rule at the link outranks the glob, and is refused like
        // any literal rule through a planted link: an error, or for `rw` a
        // dropped mount.
        let e = compile_body(
            &f,
            "fs.masked = [\"{workspace}/*.env\"]\nfs.ro = [\"{workspace}/link.env\"]",
        )
        .unwrap_err();
        assert_eq!(untrusted_link(e, "main").link, f.ws().join("link.env"));
        let s = compile_body(
            &f,
            "fs.masked = [\"{workspace}/*.env\"]\nfs.rw = [\"{workspace}/link.env\"]",
        )
        .unwrap();
        assert_eq!(
            mounts(spec(&s, "main")),
            [row("/workspace/real.env", Masked, "p")]
        );
        assert_eq!(source_warnings(&s, "main")[0].link, f.ws().join("link.env"));
    }

    #[test]
    fn renamed_dir_replaced_by_a_link_is_still_masked_through_a_glob() {
        let f = Fixture::new();
        f.file("ws/config2/prod.env");
        symlink("config2", f.ws().join("config")).unwrap();
        // `**` does not descend into the link, and the link's own name does
        // not match, so there is nothing to warn about.
        let s = compile_body(
            &f,
            "fs.rw = [\"{workspace}\"]\nfs.masked = [\"{workspace}/**/*.env\"]",
        )
        .unwrap();
        assert!(get(&s, "main").warnings.is_empty());
        assert_eq!(
            mounts(spec(&s, "main")),
            [
                row("/workspace", Rw, "p"),
                row("/workspace/config2/prod.env", Masked, "p"),
            ]
        );
        // A bare `**` matches the link itself, which is skipped; the real
        // directory and its files are masked.
        let s = compile_body(&f, "fs.masked = [\"{workspace}/**\"]").unwrap();
        assert_eq!(
            mounts(spec(&s, "main")),
            [
                row("/workspace/config2", Masked, "p"),
                row("/workspace/config2/prod.env", Masked, "p"),
            ]
        );
        assert_eq!(glob_links(&s, "main")[0].2, f.ws().join("config"));
    }

    /// The `Exposure` of every `RestrictedContentExposed` warning of `body`
    /// compiled for `main`, which must compile; panics on any other
    /// warning.
    fn exposures(f: &Fixture, body: &str) -> Vec<Exposure> {
        let s = compile_body(f, body).unwrap_or_else(|e| panic!("{body}: {e}"));
        get(&s, "main")
            .warnings
            .iter()
            .map(|w| match w {
                SpecWarning::RestrictedContentExposed(x) => (**x).clone(),
                other => panic!("{body}: unexpected warning {other:?}"),
            })
            .collect()
    }

    /// The only `Exposure` of `body` (see [`exposures`]), which must have
    /// exactly one.
    fn exposed(f: &Fixture, body: &str) -> Exposure {
        match exposures(f, body).as_slice() {
            [x] => x.clone(),
            other => panic!("{body}: expected one exposure, got {other:?}"),
        }
    }

    /// The host source of `main`'s mount at `sandbox` in `s`, which must
    /// exist.
    fn source_at(s: &CompiledSession, sandbox: &str) -> MountSource {
        spec(s, "main")
            .mounts
            .iter()
            .find(|m| m.sandbox == Path::new(sandbox))
            .unwrap_or_else(|| panic!("no mount at {sandbox:?}"))
            .source
            .clone()
    }

    fn host(path: &Path, kind: EntryKind) -> MountSource {
        MountSource::Host {
            path: path.to_owned(),
            kind,
        }
    }

    #[test]
    fn masked_content_shown_elsewhere_is_masked_there_too() {
        let f = Fixture::new();
        f.file("home/.config/tool/token");
        f.file("home/.config/other");
        let cfg = f.root.join("home/.config");
        let token = cfg.join("tool/token");
        let mask = "fs.masked = [\"~/.config/tool/token\"]\n";
        let elsewhere =
            "fs.bind = [{ host = \"~/.config\", sandbox = \"/opt/cfg\", mode = \"ro\" }]";
        let body = format!("{mask}{elsewhere}");
        let s = compile_body(&f, &body).unwrap();
        // Both mounts are kept, and the token is masked where the bind shows
        // it, in plan order.
        assert_eq!(
            mounts(spec(&s, "main")),
            [
                row("/opt/cfg", Ro, "p"),
                row("/opt/cfg/tool/token", Masked, "p"),
                row("/home/user/.config/tool/token", Masked, "p"),
            ]
        );
        assert_eq!(
            source_at(&s, "/opt/cfg/tool/token"),
            host(&token, EntryKind::File)
        );
        let msg = get(&s, "main").warnings[0].to_string();
        assert_eq!(
            exposed(&f, &body),
            Exposure {
                provider: "p".parse().unwrap(),
                mode: Ro,
                host: cfg.clone(),
                resolved: cfg.clone(),
                sandbox: "/opt/cfg".into(),
                shown_at: "/opt/cfg/tool/token".into(),
                restricted_provider: "p".parse().unwrap(),
                restricted_mode: Masked,
                restricted_host: token.clone(),
                restricted_sandbox: "/home/user/.config/tool/token".into(),
                covered: Masked,
            }
        );
        assert_eq!(
            msg,
            format!(
                "provider \"p\": ro mount of {cfg:?} at \"/opt/cfg\" shows {token:?} at \
                 \"/opt/cfg/tool/token\", where the masked mount of it by provider \"p\" at \
                 \"/home/user/.config/tool/token\" does not apply, so it would be visible there; \
                 stopit masks it at \"/opt/cfg/tool/token\" this session; to fix the \
                 configuration, narrow this grant to leave it out, add a rule for {token:?} if \
                 this mount shows it at its own host path, or cover \"/opt/cfg/tool/token\" with \
                 an ephemeral rule (an absolute rule names a host path, so one for a bind \
                 destination would be skipped as missing)"
            )
        );
        // The cover is attributed to the masking rule's provider.
        let s = f.compile(&format!(
            "base = \"none\"\n{}{}",
            prov("m", "main", mask),
            prov("b", "main", elsewhere)
        ));
        assert_eq!(
            mounts(spec(&s, "main")),
            [
                row("/opt/cfg", Ro, "b"),
                row("/opt/cfg/tool/token", Masked, "m"),
                row("/home/user/.config/tool/token", Masked, "m"),
            ]
        );
        // At its aligned path, the mask covers what the grant shows there.
        for ok in [
            format!("{mask}fs.ro = [\"~/.config\"]"),
            format!("{mask}fs.rw = [\"~/.config\"]"),
            // Something mounted on top of the exposing mount hides it too:
            // the fix the warning suggests for a bind destination.
            format!("{mask}{elsewhere}\nfs.ephemeral = [\"/opt/cfg/tool\"]"),
            // A masked ancestor shows nothing.
            "fs.masked = [\"~/.config\", \"~/.config/tool/token\"]".to_owned(),
            // Siblings are unrelated.
            format!("{mask}fs.ro = [\"~/.config/other\"]"),
        ] {
            assert_eq!(exposures(&f, &ok), [], "{ok}");
        }
        // A link to the grant is resolved first.
        symlink(&cfg, f.root.join("home/cfg-link")).unwrap();
        let body = format!("{mask}fs.ro = [\"~/cfg-link\"]");
        let x = exposed(&f, &body);
        assert_eq!(
            (x.resolved, x.shown_at),
            (cfg.clone(), PathBuf::from("/home/user/cfg-link/tool/token"))
        );
        let s = compile_body(&f, &body).unwrap();
        assert_eq!(
            mounts(spec(&s, "main")),
            [
                row("/home/user/cfg-link", Ro, "p"),
                row("/home/user/.config/tool/token", Masked, "p"),
                row("/home/user/cfg-link/tool/token", Masked, "p"),
            ]
        );
        assert_eq!(
            source_at(&s, "/home/user/cfg-link/tool/token"),
            host(&token, EntryKind::File)
        );
        // A source strictly inside a masked directory is a more specific
        // grant of that part (the most specific rule wins), at its aligned
        // path or elsewhere: nothing is exposed or added.
        let dir_mask = "fs.masked = [\"~/.config/tool\"]\n";
        assert_eq!(
            exposures(&f, &format!("{dir_mask}fs.ro = [\"~/.config/tool/token\"]")),
            []
        );
        let body = format!(
            "{dir_mask}fs.bind = [{{ host = \"~/.config/tool/token\", sandbox = \"/opt/token\", \
             mode = \"ro\" }}]"
        );
        assert_eq!(exposures(&f, &body), []);
        let s = compile_body(&f, &body).unwrap();
        assert_eq!(
            mounts(spec(&s, "main")),
            [
                row("/opt/token", Ro, "p"),
                row("/home/user/.config/tool", Masked, "p"),
            ]
        );
        assert_eq!(source_at(&s, "/opt/token"), host(&token, EntryKind::File));
        // A grant of the masked path itself elsewhere is not more specific:
        // it is replaced by a mask.
        let body = format!(
            "{mask}fs.bind = [{{ host = \"~/.config/tool/token\", sandbox = \"/opt/token\", mode \
             = \"ro\" }}]"
        );
        let x = exposed(&f, &body);
        assert_eq!(
            (x.shown_at, x.restricted_host, x.covered),
            (PathBuf::from("/opt/token"), token.clone(), Masked)
        );
        let s = compile_body(&f, &body).unwrap();
        assert_eq!(
            mounts(spec(&s, "main")),
            [
                row("/opt/token", Masked, "p"),
                row("/home/user/.config/tool/token", Masked, "p"),
            ]
        );
        assert_eq!(source_at(&s, "/opt/token"), host(&token, EntryKind::File));
    }

    #[test]
    fn a_workspace_inside_a_masked_directory_keeps_its_mount() {
        // Masking `~/Projects` to hide the other projects: the workspace
        // `~/Projects/stopit` lies strictly inside it, so its mount is a more
        // specific grant and is kept, with no warning.
        let f = Fixture::with_workspace("home/Projects/stopit", "/workspace");
        f.file("home/Projects/stopit/src/main.rs");
        f.file("home/Projects/other/secret");
        let s = compile_body(
            &f,
            "fs.rw = [\"{workspace}\"]\nfs.masked = [\"~/Projects\"]",
        )
        .unwrap();
        assert!(
            get(&s, "main").warnings.is_empty(),
            "{:?}",
            get(&s, "main").warnings
        );
        assert_eq!(
            mounts(spec(&s, "main")),
            [
                row("/workspace", Rw, "p"),
                row("/home/user/Projects", Masked, "p"),
            ]
        );
    }

    #[test]
    fn a_rule_restricting_the_workspace_itself_keeps_the_workspace_mount() {
        // A shared "hide other projects" config also matching the workspace:
        // the workspace's identity wins, its mount is kept (never covered),
        // and a distinct warning says the rule does not apply there.
        let f = Fixture::with_workspace("home/Projects/stopit", "/workspace");
        f.file("home/Projects/stopit/src/main.rs");
        f.file("home/Projects/stopit/.env");
        f.file("home/Projects/other/secret");
        let ws = f.root.join("home/Projects/stopit");
        for (rule, extra) in [
            ("\"~/Projects/stopit\"", vec![]),
            (
                "\"~/Projects/*\"",
                vec![row("/home/user/Projects/other", Masked, "p")],
            ),
        ] {
            let body = format!("fs.rw = [\"{{workspace}}\"]\nfs.masked = [{rule}]");
            let s = compile_body(&f, &body).unwrap();
            let mut want = vec![row("/workspace", Rw, "p")];
            want.extend(extra);
            want.push(row("/home/user/Projects/stopit", Masked, "p"));
            assert_eq!(mounts(spec(&s, "main")), want, "{rule}");
            assert_eq!(
                source_at(&s, "/workspace"),
                host(&ws, EntryKind::Dir),
                "{rule}"
            );
            match get(&s, "main").warnings.as_slice() {
                [w @ SpecWarning::WorkspaceRestricted(x)] => {
                    assert_eq!(
                        **x,
                        WorkspaceRestricted {
                            restricted_provider: "p".parse().unwrap(),
                            restricted_mode: Masked,
                            restricted_host: ws.clone(),
                            restricted_sandbox: "/home/user/Projects/stopit".into(),
                            workspace: ws.clone(),
                            workspace_mount: "/workspace".into(),
                        }
                    );
                    assert_eq!(
                        w.to_string(),
                        format!(
                            "provider \"p\": the masked rule for {ws:?} at \
                             \"/home/user/Projects/stopit\" matches the host workspace itself, so \
                             it does not apply to the workspace mount at \"/workspace\" this \
                             session: the workspace stays mounted there (restricted content \
                             inside it is still covered); exclude the workspace from the rule, \
                             narrowing the path or glob, to silence this"
                        )
                    );
                }
                other => panic!("{rule}: {other:?}"),
            }
        }
        // Restricted content inside the workspace, shown through the
        // workspace mount, is still covered there.
        let s = compile_body(
            &f,
            "fs.rw = [\"{workspace}\"]\nfs.masked = [\"~/Projects/stopit\", \
             \"~/Projects/stopit/.env\"]",
        )
        .unwrap();
        assert_eq!(
            mounts(spec(&s, "main")),
            [
                row("/workspace", Rw, "p"),
                row("/workspace/.env", Masked, "p"),
                row("/home/user/Projects/stopit", Masked, "p"),
                row("/home/user/Projects/stopit/.env", Masked, "p"),
            ]
        );
        let warnings = &get(&s, "main").warnings;
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert!(
            warnings
                .iter()
                .any(|w| matches!(w, SpecWarning::WorkspaceRestricted(_)))
        );
        assert!(warnings.iter().any(|w| matches!(
            w,
            SpecWarning::RestrictedContentExposed(x) if x.shown_at == Path::new("/workspace/.env")
        )));
    }

    #[test]
    fn masked_content_inside_a_workspace_inside_a_masked_directory_is_masked_at_the_workspace() {
        // `~/Projects` masked to hide the other projects, and the
        // workspace's `.env` masked at its host path: the workspace is a
        // more specific grant and is kept, and the `.env` it shows is
        // masked there.
        let f = Fixture::with_workspace("home/Projects/stopit", "/workspace");
        f.file("home/Projects/stopit/.env");
        f.file("home/Projects/other/secret");
        let env = f.root.join("home/Projects/stopit/.env");
        let body = "fs.rw = [\"{workspace}\"]\nfs.masked = [\"~/Projects\", \
                    \"~/Projects/stopit/.env\"]";
        let s = compile_body(&f, body).unwrap();
        assert_eq!(
            mounts(spec(&s, "main")),
            [
                row("/workspace", Rw, "p"),
                row("/workspace/.env", Masked, "p"),
                row("/home/user/Projects", Masked, "p"),
                row("/home/user/Projects/stopit/.env", Masked, "p"),
            ]
        );
        assert_eq!(
            source_at(&s, "/workspace/.env"),
            host(&env, EntryKind::File)
        );
        let x = exposed(&f, body);
        assert_eq!(
            (x.sandbox, x.shown_at, x.restricted_host, x.covered),
            (
                PathBuf::from("/workspace"),
                PathBuf::from("/workspace/.env"),
                env,
                Masked
            )
        );
    }

    #[test]
    fn a_grant_linking_into_restricted_content_is_kept_with_a_warning() {
        // `~/.toolrc -> .ssh/id_ed25519` with `~/.ssh` masked: the grant's
        // canonical source lies strictly inside the masked directory, so it
        // is the more specific rule and is not covered, but it reaches
        // there through a host link, which the user may not realize.
        let f = Fixture::new();
        f.file("home/.ssh/id_ed25519");
        symlink(".ssh/id_ed25519", f.root.join("home/.toolrc")).unwrap();
        let ssh = f.root.join("home/.ssh");
        let key = ssh.join("id_ed25519");
        let toolrc = f.root.join("home/.toolrc");
        let s = compile_body(&f, "fs.masked = [\"~/.ssh\"]\nfs.ro = [\"~/.toolrc\"]").unwrap();
        assert_eq!(
            mounts(spec(&s, "main")),
            [
                row("/home/user/.ssh", Masked, "p"),
                row("/home/user/.toolrc", Ro, "p"),
            ]
        );
        match get(&s, "main").warnings.as_slice() {
            [w @ SpecWarning::LinkedIntoRestricted(x)] => {
                assert_eq!(
                    **x,
                    LinkedIntoRestricted {
                        provider: "p".parse().unwrap(),
                        mode: Ro,
                        host: toolrc.clone(),
                        resolved: key.clone(),
                        sandbox: "/home/user/.toolrc".into(),
                        restricted_provider: "p".parse().unwrap(),
                        restricted_mode: Masked,
                        restricted_host: ssh.clone(),
                        restricted_sandbox: "/home/user/.ssh".into(),
                    }
                );
                assert_eq!(
                    w.to_string(),
                    format!(
                        "provider \"p\": ro mount of {toolrc:?} (resolving to {key:?}) at \
                         \"/home/user/.toolrc\" reaches, through a host symlink, into {ssh:?}, \
                         which the masked mount by provider \"p\" at \"/home/user/.ssh\" \
                         restricts; as a narrower grant of part of it, it is mounted as \
                         configured, so that content is visible at \"/home/user/.toolrc\"; if \
                         that is not intended, remove this grant or the link"
                    )
                );
            }
            other => panic!("{other:?}"),
        }
        // Written inside the restricted path, it is silent.
        let s = compile_body(
            &f,
            "fs.masked = [\"~/.ssh\"]\nfs.bind = [{ host = \"~/.ssh/id_ed25519\", sandbox = \
             \"/opt/key\", mode = \"ro\" }]",
        )
        .unwrap();
        assert!(get(&s, "main").warnings.is_empty());
        // So is one written inside the restricted rule's own link, which
        // resolves inside it.
        symlink(".ssh", f.root.join("home/ssh-link")).unwrap();
        let s = compile_body(
            &f,
            "fs.masked = [\"~/ssh-link\"]\nfs.bind = [{ host = \"~/ssh-link/id_ed25519\", \
             sandbox = \"/opt/key\", mode = \"ro\" }]",
        )
        .unwrap();
        assert!(
            get(&s, "main").warnings.is_empty(),
            "{:?}",
            get(&s, "main").warnings
        );
        // A read-only view of protected content is not reported.
        let s = compile_body(&f, "fs.protected = [\"~/.ssh\"]\nfs.ro = [\"~/.toolrc\"]").unwrap();
        assert!(get(&s, "main").warnings.is_empty());
        // A writable one is.
        let s = compile_body(&f, "fs.protected = [\"~/.ssh\"]\nfs.rw = [\"~/.toolrc\"]").unwrap();
        assert!(matches!(
            get(&s, "main").warnings.as_slice(),
            [SpecWarning::LinkedIntoRestricted(x)] if x.restricted_mode == Protected && x.mode == Rw
        ));
    }

    #[test]
    fn a_cover_takes_its_kind_from_a_host_link_to_a_file() {
        // `~/.toolrc -> .config/tool/rc` masked, with `~/.config` bound
        // elsewhere: the mask over the link is a file mask, and so is the
        // cover where the bind shows the target.
        let f = Fixture::new();
        f.file("home/.config/tool/rc");
        symlink(".config/tool/rc", f.root.join("home/.toolrc")).unwrap();
        let rc = f.root.join("home/.config/tool/rc");
        let body = "fs.masked = [\"~/.toolrc\"]\nfs.bind = [{ host = \"~/.config\", sandbox = \
                    \"/opt/cfg\", mode = \"ro\" }]";
        let s = compile_body(&f, body).unwrap();
        assert_eq!(
            mounts(spec(&s, "main")),
            [
                row("/opt/cfg", Ro, "p"),
                row("/home/user/.toolrc", Masked, "p"),
                row("/opt/cfg/tool/rc", Masked, "p"),
            ]
        );
        assert_eq!(
            source_at(&s, "/opt/cfg/tool/rc"),
            host(&rc, EntryKind::File)
        );
        let x = exposed(&f, body);
        assert_eq!(
            (x.restricted_host, x.shown_at),
            (rc, PathBuf::from("/opt/cfg/tool/rc"))
        );
    }

    #[test]
    fn masked_directory_shown_elsewhere_is_masked_there_with_deeper_mounts_on_top() {
        let f = Fixture::new();
        f.file("home/.config/tool/token");
        f.file("home/.config/other");
        let cfg = f.root.join("home/.config");
        let mask = "fs.masked = [\"~/.config/tool\"]\n";
        let elsewhere =
            "fs.bind = [{ host = \"~/.config\", sandbox = \"/opt/cfg\", mode = \"ro\" }]";
        let x = exposed(&f, &format!("{mask}{elsewhere}"));
        assert_eq!(
            (x.restricted_host, x.shown_at, x.covered),
            (cfg.join("tool"), PathBuf::from("/opt/cfg/tool"), Masked)
        );
        // A planned mount below the cover stays on top of it, in plan
        // order: it shows what its own rule configures.
        let both = "fs.bind = [{ host = \"~/.config\", sandbox = \"/opt/cfg\", mode = \"ro\" }, \
                    { host = \"~/.config/other\", sandbox = \"/opt/cfg/tool/other\", mode = \
                    \"ro\" }]";
        let s = compile_body(&f, &format!("{mask}{both}")).unwrap();
        assert_eq!(
            mounts(spec(&s, "main")),
            [
                row("/opt/cfg", Ro, "p"),
                row("/opt/cfg/tool", Masked, "p"),
                row("/home/user/.config/tool", Masked, "p"),
                row("/opt/cfg/tool/other", Ro, "p"),
            ]
        );
        assert_eq!(
            source_at(&s, "/opt/cfg/tool"),
            host(&cfg.join("tool"), EntryKind::Dir)
        );
        assert_eq!(get(&s, "main").warnings.len(), 1);
        // A mask inside the masked directory, shown inside the directory's
        // cover, is hidden by it already: one cover, one warning.
        let s = compile_body(
            &f,
            &format!("fs.masked = [\"~/.config/tool\", \"~/.config/tool/token\"]\n{elsewhere}"),
        )
        .unwrap();
        assert_eq!(
            mounts(spec(&s, "main")),
            [
                row("/opt/cfg", Ro, "p"),
                row("/opt/cfg/tool", Masked, "p"),
                row("/home/user/.config/tool", Masked, "p"),
                row("/home/user/.config/tool/token", Masked, "p"),
            ]
        );
        let xs = exposures(
            &f,
            &format!("fs.masked = [\"~/.config/tool\", \"~/.config/tool/token\"]\n{elsewhere}"),
        );
        assert_eq!(
            xs.iter().map(|x| x.shown_at.clone()).collect::<Vec<_>>(),
            [PathBuf::from("/opt/cfg/tool")]
        );
    }

    #[test]
    fn covers_belong_to_the_profile_whose_mask_is_exposed() {
        let f = Fixture::new();
        f.file("home/.config/tool/token");
        let elsewhere =
            "fs.bind = [{ host = \"~/.config\", sandbox = \"/opt/cfg\", mode = \"ro\" }]";
        let s = f.compile(&format!(
            "base = \"none\"\n[profiles.agent]\ninherit = \"none\"\n{}{}",
            prov(
                "p",
                "main",
                &format!("fs.masked = [\"~/.config/tool/token\"]\n{elsewhere}")
            ),
            prov("q", "agent", elsewhere),
        ));
        assert_eq!(
            mounts(spec(&s, "main")),
            [
                row("/opt/cfg", Ro, "p"),
                row("/opt/cfg/tool/token", Masked, "p"),
                row("/home/user/.config/tool/token", Masked, "p"),
            ]
        );
        assert_eq!(mounts(spec(&s, "agent")), [row("/opt/cfg", Ro, "q")]);
        assert!(get(&s, "agent").warnings.is_empty());
    }

    #[test]
    fn masked_host_link_whose_target_is_mounted_too_is_masked_in_the_store() {
        // A home-manager file masked at `~/.config/foo`, linking into a
        // store that is mounted read-only as well: the target would stay
        // visible in the store, which only the host controls, so it is
        // masked there too.
        let f = Fixture::new();
        f.file("store/abc-foo/config");
        f.mkdir("home/.config");
        let target = f.root.join("store/abc-foo");
        symlink(&target, f.root.join("home/.config/foo")).unwrap();
        symlink(&target, f.root.join("home/.config/bar")).unwrap();
        let store = f.root.join("store");
        let body = format!(
            "fs.masked = [\"~/.config/foo\"]\nfs.ro = [\"{}\"]",
            store.display()
        );
        let x = exposed(&f, &body);
        assert_eq!(
            (
                x.mode,
                x.restricted_host,
                x.shown_at,
                x.restricted_sandbox,
                x.covered
            ),
            (
                Ro,
                target.clone(),
                target.clone(),
                PathBuf::from("/home/user/.config/foo"),
                Masked
            )
        );
        let s = compile_body(&f, &body).unwrap();
        let at = |p: &Path| p.to_str().unwrap().to_owned();
        let sorted = |mut v: Vec<(String, PathMode, String)>| {
            v.sort_by_key(|(p, ..)| (Path::new(p).components().count(), p.clone()));
            v
        };
        let want = sorted(vec![
            row(&at(&store), Ro, "p"),
            row(&at(&target), Masked, "p"),
            row("/home/user/.config/foo", Masked, "p"),
        ]);
        assert_eq!(mounts(spec(&s, "main")), want);
        assert_eq!(source_at(&s, &at(&target)), host(&target, EntryKind::Dir));
        // Two masks of the same content meet at one path there, which gets
        // one mask; each is reported.
        let two = format!(
            "fs.masked = [\"~/.config/foo\", \"~/.config/bar\"]\nfs.ro = [\"{}\"]",
            store.display()
        );
        let s = compile_body(&f, &two).unwrap();
        assert_eq!(
            mounts(spec(&s, "main")),
            sorted(vec![
                row(&at(&store), Ro, "p"),
                row(&at(&target), Masked, "p"),
                row("/home/user/.config/bar", Masked, "p"),
                row("/home/user/.config/foo", Masked, "p"),
            ])
        );
        let xs = exposures(&f, &two);
        assert_eq!(
            xs.iter()
                .map(|x| (x.shown_at.clone(), x.restricted_sandbox.clone()))
                .collect::<Vec<_>>(),
            [
                (target.clone(), PathBuf::from("/home/user/.config/bar")),
                (target.clone(), PathBuf::from("/home/user/.config/foo")),
            ]
        );
        // A mask and a protected mount of the same content, shown writable
        // in the store: the stricter, the mask, covers it there, for both.
        // The protected mount shows the masked content too, so it is
        // replaced by a mask as well.
        let mixed = format!(
            "fs.masked = [\"~/.config/foo\"]\nfs.protected = [\"~/.config/bar\"]\nfs.rw = \
             [\"{}\"]",
            store.display()
        );
        let s = compile_body(&f, &mixed).unwrap();
        assert_eq!(
            mounts(spec(&s, "main")),
            sorted(vec![
                row(&at(&store), Rw, "p"),
                row(&at(&target), Masked, "p"),
                row("/home/user/.config/bar", Masked, "p"),
                row("/home/user/.config/foo", Masked, "p"),
            ])
        );
        let mut xs: Vec<_> = exposures(&f, &mixed)
            .into_iter()
            .map(|x| (x.restricted_mode, x.shown_at, x.covered))
            .collect();
        xs.sort();
        let mut want = vec![
            (Protected, target.clone(), Masked),
            (Masked, target.clone(), Masked),
            (Masked, PathBuf::from("/home/user/.config/bar"), Masked),
        ];
        want.sort();
        assert_eq!(xs, want);
        // Masking the target at its host path, where the aligned store mount
        // shows it, covers it.
        assert_eq!(
            exposures(
                &f,
                &format!(
                    "fs.masked = [\"~/.config/foo\", \"{}\"]\nfs.ro = [\"{}\"]",
                    target.display(),
                    store.display()
                )
            ),
            []
        );
    }

    #[test]
    fn protected_content_counts_only_writable_views() {
        let f = Fixture::new();
        f.file("home/proj2/flake.nix");
        let proj = f.root.join("home/proj2");
        let protect = "fs.protected = [\"~/proj2/flake.nix\"]\n";
        let bind = |mode: &str| {
            format!(
                "{protect}fs.bind = [{{ host = \"~/proj2\", sandbox = \"/src\", mode = \
                 \"{mode}\" }}]"
            )
        };
        // A read-only view of protected content exposes nothing protected:
        // it is readable at its own path too, and nothing is added.
        for (mode, want) in [("ro", Ro), ("protected", Protected)] {
            assert_eq!(exposures(&f, &bind(mode)), []);
            let s = compile_body(&f, &bind(mode)).unwrap();
            assert_eq!(
                mounts(spec(&s, "main")),
                [
                    row("/src", want, "p"),
                    row("/home/user/proj2/flake.nix", Protected, "p"),
                ]
            );
        }
        // A writable one does, and the file is protected there too.
        let body = bind("rw");
        let x = exposed(&f, &body);
        let msg = x.to_string();
        assert_eq!(
            (
                x.mode,
                x.restricted_mode,
                x.shown_at,
                x.restricted_host,
                x.covered
            ),
            (
                Rw,
                Protected,
                PathBuf::from("/src/flake.nix"),
                proj.join("flake.nix"),
                Protected
            )
        );
        assert!(
            msg.contains(
                "so it would be writable there; stopit mounts it protected at \"/src/flake.nix\" \
                 this session;"
            ),
            "{msg}"
        );
        let s = compile_body(&f, &body).unwrap();
        assert_eq!(
            mounts(spec(&s, "main")),
            [
                row("/src", Rw, "p"),
                row("/src/flake.nix", Protected, "p"),
                row("/home/user/proj2/flake.nix", Protected, "p"),
            ]
        );
        assert_eq!(
            source_at(&s, "/src/flake.nix"),
            host(&proj.join("flake.nix"), EntryKind::File)
        );
        // An `rw` grant strictly inside a protected directory, elsewhere,
        // is a more specific grant: kept, with no warning.
        f.file("home/proj2/sub/x");
        let inside = "fs.protected = [\"~/proj2\"]\nfs.bind = [{ host = \"~/proj2/sub\", \
                      sandbox = \"/sub\", mode = \"rw\" }]";
        assert_eq!(exposures(&f, inside), []);
        let s = compile_body(&f, inside).unwrap();
        assert_eq!(
            mounts(spec(&s, "main")),
            [
                row("/sub", Rw, "p"),
                row("/home/user/proj2", Protected, "p"),
            ]
        );
        // An `rw` grant of the protected directory itself, elsewhere, is
        // replaced by a protected mount of it.
        let itself = "fs.protected = [\"~/proj2\"]\nfs.bind = [{ host = \"~/proj2\", sandbox = \
                      \"/src\", mode = \"rw\" }]";
        let s = compile_body(&f, itself).unwrap();
        assert_eq!(
            mounts(spec(&s, "main")),
            [
                row("/src", Protected, "p"),
                row("/home/user/proj2", Protected, "p"),
            ]
        );
        assert_eq!(source_at(&s, "/src"), host(&proj, EntryKind::Dir));
        let msg = exposed(&f, itself).to_string();
        assert!(
            msg.contains(
                "stopit mounts it protected at \"/src\" this session, replacing this mount;"
            ),
            "{msg}"
        );
        // A masked file inside it still gets its own mask under the
        // protected cover that replaces the `rw` mount: a protected cover
        // does not hide masked content.
        f.file("home/proj2/secret");
        let body = "fs.protected = [\"~/proj2\"]\nfs.masked = [\"~/proj2/secret\"]\nfs.bind = [{ \
                    host = \"~/proj2\", sandbox = \"/src\", mode = \"rw\" }]";
        let s = compile_body(&f, body).unwrap();
        assert_eq!(
            mounts(spec(&s, "main")),
            [
                row("/src", Protected, "p"),
                row("/src/secret", Masked, "p"),
                row("/home/user/proj2", Protected, "p"),
                row("/home/user/proj2/secret", Masked, "p"),
            ]
        );
        assert_eq!(
            source_at(&s, "/src/secret"),
            host(&proj.join("secret"), EntryKind::File)
        );
        let mut xs: Vec<_> = exposures(&f, body)
            .into_iter()
            .map(|x| (x.shown_at, x.covered))
            .collect();
        xs.sort();
        assert_eq!(
            xs,
            [
                (PathBuf::from("/src"), Protected),
                (PathBuf::from("/src/secret"), Masked),
            ]
        );
        // At its aligned path, the protection applies.
        assert_eq!(
            exposures(&f, &format!("{protect}fs.rw = [\"~/proj2\"]")),
            []
        );
    }

    #[test]
    fn workspace_content_shown_elsewhere_is_still_a_workspace_error() {
        // The workspace rule runs first, so a grant containing the
        // workspace is reported as such even when it exposes masked files.
        let f = Fixture::with_workspace("home/Projects/stopit", "/workspace");
        f.file("home/Projects/stopit/.env");
        let e = f
            .try_compile(&prov("p", "main", "fs.ro = [\"~/Projects\"]"))
            .unwrap_err();
        assert_eq!(exposure(&f, e).1, f.root.join("home/Projects"));
        // Even without anything restricted in it.
        let e = compile_body(&f, "fs.ro = [\"~/Projects\"]").unwrap_err();
        assert_eq!(exposure(&f, e).1, f.root.join("home/Projects"));
    }

    #[test]
    fn destinations_under_ephemeral_and_masked_mounts_are_not_checked() {
        let f = Fixture::new();
        f.file("home/cfg");
        f.mkdir("ws/elsewhere");
        symlink("elsewhere", f.ws().join("target")).unwrap();
        // Under an ephemeral mount, the destination is in the session's
        // backing directory, which is not checked yet (DESIGN.md §11): the
        // planted `ws/target` is not what bwrap traverses there, and is not
        // looked at.
        let s = compile_body(
            &f,
            "fs.ephemeral = [\"{workspace}/target\"]\n\
             fs.bind = [{ host = \"~/cfg\", sandbox = \"/workspace/target/cfg\", mode = \"ro\" }]",
        )
        .unwrap();
        assert_eq!(
            mounts(spec(&s, "main")),
            [
                row("/workspace/target", Ephemeral, "p"),
                row("/workspace/target/cfg", Ro, "p"),
            ]
        );
        // Under a masked directory, nothing the sandbox writes persists:
        // with `~/.cache/tool` masked inside an `rw ~/.cache`, a link planted
        // at `~/.cache/tool/cfg` (by an earlier session, say) is not what
        // bwrap traverses.
        let f = planted_cache_link();
        let s = compile_body(
            &f,
            "fs.rw = [\"~/.cache\"]\nfs.masked = [\"~/.cache/tool\"]\n\
             fs.bind = [{ host = \"~/.ssh/id_ed25519\", sandbox = \"/home/user/.cache/tool/cfg\", \
             mode = \"ro\" }]",
        )
        .unwrap();
        assert_eq!(
            mounts(spec(&s, "main")),
            [
                row("/home/user/.cache", Rw, "p"),
                row("/home/user/.cache/tool", Masked, "p"),
                row("/home/user/.cache/tool/cfg", Ro, "p"),
            ]
        );
    }

    #[test]
    fn rw_sources_through_untrusted_links_are_dropped_with_no_mount_underneath() {
        // Nothing the destination check can see lies underneath these rules
        // (no workspace mount, or an ephemeral one), so only the host-source
        // check finds the link: an `rw` rule is dropped with a warning, a
        // restrictive one is an error.
        let f = Fixture::new();
        f.mkdir("scratch/target");
        f.mkdir("scratch/out");
        f.mkdir("ws/build");
        symlink(f.root.join("scratch/target"), f.ws().join("target")).unwrap();
        symlink(f.root.join("scratch/out"), f.ws().join("build/out")).unwrap();
        // `(rules, sandbox path of the linked rule, link)`: a profile that
        // inherits nothing, so has no workspace mount, and a rule under an
        // ephemeral one.
        for (rules, sandbox, link) in [
            (
                "fs.{mode} = [\"{workspace}/target\"]",
                "/workspace/target",
                "target",
            ),
            (
                "fs.ephemeral = [\"{workspace}/build\"]\nfs.{mode} = [\"{workspace}/build/out\"]",
                "/workspace/build/out",
                "build/out",
            ),
        ] {
            let src = |mode: &str| {
                format!(
                    "base = \"none\"\n[profiles.agent]\ninherit = \"none\"\n{}{}",
                    prov("w", "main", "fs.rw = [\"{workspace}\"]"),
                    prov("p", "agent", &rules.replace("{mode}", mode)),
                )
            };
            let s = f.compile(&src("rw"));
            let kept: Vec<_> = spec(&s, "agent")
                .mounts
                .iter()
                .map(|m| m.sandbox.clone())
                .collect();
            assert!(!kept.contains(&PathBuf::from(sandbox)), "{rules}: {kept:?}");
            let lf = source_warnings(&s, "agent");
            assert_eq!(
                lf.iter()
                    .map(|l| (l.mode, l.sandbox.as_path(), &l.link, l.root.kind.clone()))
                    .collect::<Vec<_>>(),
                [(
                    Rw,
                    Path::new(sandbox),
                    &f.ws().join(link),
                    UntrustedKind::Workspace
                )],
                "{rules}"
            );
            // `main` mounts the workspace, so its own copy would be caught by
            // the destination check; it has none here.
            assert!(get(&s, "main").warnings.is_empty(), "{rules}");
            let lf = untrusted_link(f.compile_err(&src("ro")), "agent");
            assert_eq!(
                (lf.mode, lf.sandbox.as_path(), &lf.link),
                (Ro, Path::new(sandbox), &f.ws().join(link)),
                "{rules}"
            );
        }
    }

    #[test]
    fn mounts_below_an_rw_mount_dropped_for_its_source_are_rechecked() {
        // `~/.cache` is granted `rw`, and a sandbox replaced `~/.cache/tool`
        // by a link and planted `~/.cache/sub/cfg`. An `rw` bind of
        // `~/.cache/tool` at `~/.cache/sub` is dropped for its source; a
        // mount at `~/.cache/sub/cfg` must then be checked against
        // `~/.cache`, where `sub/cfg` is the planted link, not against the
        // dropped bind's tree (`~/.ssh`, with no `cfg` in it).
        let f = Fixture::new();
        let home = f.root.join("home");
        let cache = home.join(".cache");
        f.mkdir("home/.ssh");
        f.mkdir("home/.cache/sub");
        f.file("home/cfg");
        symlink("../.ssh", cache.join("tool")).unwrap();
        symlink("../../.ssh", cache.join("sub/cfg")).unwrap();
        let cache_root = rw_root(cache.clone(), "p", Some("main"), cache.clone());
        let body = |mode: &str| {
            format!(
                "fs.rw = [\"~/.cache\"]\nfs.bind = [\n\
                 {{ host = \"~/.cache/tool\", sandbox = \"/home/user/.cache/sub\", \
                 mode = \"rw\" }},\n\
                 {{ host = \"~/cfg\", sandbox = \"/home/user/.cache/sub/cfg\", \
                 mode = \"{mode}\" }},\n]"
            )
        };
        let e = compile_body(&f, &body("ro")).unwrap_err();
        let dl = destination_link(e, "main");
        assert_eq!(
            (
                dl.mode,
                dl.sandbox.as_path(),
                &dl.link,
                dl.ancestor.as_path(),
                &dl.root
            ),
            (
                Ro,
                Path::new("/home/user/.cache/sub/cfg"),
                &cache.join("sub/cfg"),
                Path::new("/home/user/.cache"),
                &cache_root
            )
        );
        // An `rw` one is dropped too: one warning for each.
        let s = compile_body(&f, &body("rw")).unwrap();
        assert_eq!(
            mounts(spec(&s, "main")),
            [row("/home/user/.cache", Rw, "p")]
        );
        assert!(
            matches!(
                get(&s, "main").warnings.as_slice(),
                [SpecWarning::SourceLink(lf), SpecWarning::DestinationLink(dl)]
                    if lf.link == cache.join("tool")
                        && lf.sandbox == Path::new("/home/user/.cache/sub")
                        && dl.link == cache.join("sub/cfg")
                        && dl.ancestor == Path::new("/home/user/.cache")
            ),
            "{:?}",
            get(&s, "main").warnings
        );
    }

    #[test]
    fn mounts_below_a_dropped_rw_mount_meet_the_same_link() {
        // `~/.cache/tool`, inside an `rw ~/.cache`, was replaced by a link.
        // Its own `rw` mount is dropped; the mounts below it are checked
        // against `~/.cache`, which is what lies underneath them then, and
        // pass through the same link: a restrictive one is an error, an
        // `rw` one is dropped too.
        let f = Fixture::new();
        let home = f.root.join("home");
        let cache = home.join(".cache");
        f.mkdir("home/.cache");
        f.file("home/.ssh/sub/key");
        symlink("../.ssh", cache.join("tool")).unwrap();
        let grants = "fs.rw = [\"~/.cache\", \"~/.cache/tool\"]\n";
        let e = compile_body(&f, &format!("{grants}fs.ro = [\"~/.cache/tool/sub\"]")).unwrap_err();
        let dl = destination_link(e, "main");
        assert_eq!(
            (
                dl.mode,
                dl.sandbox.as_path(),
                &dl.link,
                dl.ancestor.as_path()
            ),
            (
                Ro,
                Path::new("/home/user/.cache/tool/sub"),
                &cache.join("tool"),
                Path::new("/home/user/.cache")
            )
        );
        let s = compile_body(
            &f,
            "fs.rw = [\"~/.cache\", \"~/.cache/tool\", \"~/.cache/tool/sub\", \
             \"~/.cache/tool/sub/key\"]",
        )
        .unwrap();
        assert_eq!(
            mounts(spec(&s, "main")),
            [row("/home/user/.cache", Rw, "p")]
        );
        let dropped: Vec<_> = destination_warnings(&s, "main")
            .into_iter()
            .map(|d| (d.sandbox, d.link, d.ancestor))
            .collect();
        let tool = cache.join("tool");
        let at = PathBuf::from("/home/user/.cache");
        assert_eq!(
            dropped,
            [
                ("/home/user/.cache/tool".into(), tool.clone(), at.clone()),
                (
                    "/home/user/.cache/tool/sub".into(),
                    tool.clone(),
                    at.clone()
                ),
                ("/home/user/.cache/tool/sub/key".into(), tool, at),
            ]
        );
    }

    #[test]
    fn destinations_that_cannot_be_inspected() {
        use std::os::unix::fs::PermissionsExt;
        if rustix::process::geteuid().is_root() {
            eprintln!("skipping: permission checks do not apply to root");
            return;
        }
        let f = Fixture::new();
        f.file("home/x");
        f.mkdir("home/.cache/locked/sub");
        let locked = f.root.join("home/.cache/locked");
        let bind = |mode: &str| {
            format!(
                "fs.rw = [\"~/.cache\"]\nfs.bind = [{{ host = \"~/x\", \
                 sandbox = \"/home/user/.cache/locked/sub/x\", mode = \"{mode}\" }}]"
            )
        };
        // An ephemeral rule's destination is checked alike (it has no host
        // source for the planner to resolve).
        let ephemeral = "fs.rw = [\"~/.cache\"]\nfs.ephemeral = [\"~/.cache/locked/sub/tmp\"]";
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        let masked = compile_body(&f, &bind("ro"));
        let masked_ephemeral = compile_body(&f, ephemeral);
        let warned = compile_body(&f, &bind("rw"));
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
        // A restrictive mount is never skipped: the directory that cannot
        // be searched is masked, and the mount is kept on top of the mask.
        for (s, mode, dest) in [
            (masked, Ro, "/home/user/.cache/locked/sub/x"),
            (
                masked_ephemeral,
                Ephemeral,
                "/home/user/.cache/locked/sub/tmp",
            ),
        ] {
            let s = s.unwrap();
            let spec = spec(&s, "main");
            assert_eq!(
                mounts(spec),
                [
                    row("/home/user/.cache", Rw, "p"),
                    row("/home/user/.cache/locked", Masked, "p"),
                    row(dest, mode, "p"),
                ],
                "{mode}"
            );
            assert_eq!(
                spec.mounts[1].source,
                MountSource::Host {
                    path: locked.clone(),
                    kind: EntryKind::Dir
                },
                "{mode}"
            );
            let [SpecWarning::DestinationMasked(dm)] = get(&s, "main").warnings.as_slice() else {
                panic!("{mode}: {:?}", get(&s, "main").warnings);
            };
            assert_eq!(
                (
                    dm.provider.as_str(),
                    dm.mode,
                    dm.sandbox.as_path(),
                    &dm.path,
                    dm.error.kind(),
                    dm.masked.as_path(),
                    &dm.masked_host,
                ),
                (
                    "p",
                    mode,
                    Path::new(dest),
                    &locked.join("sub"),
                    io::ErrorKind::PermissionDenied,
                    Path::new("/home/user/.cache/locked"),
                    &locked,
                ),
                "{mode}"
            );
            assert_eq!(
                dm.to_string(),
                format!(
                    "provider \"p\": cannot check the destination \"{dest}\" of the {mode} mount \
                     for symlinks: inspecting {:?} failed: {}; a {mode} mount is never skipped, \
                     so the directory {locked:?} is masked at \"/home/user/.cache/locked\", \
                     hiding everything in it, and the mount is kept on top",
                    locked.join("sub"),
                    dm.error,
                ),
            );
        }
        // An `rw` one is skipped.
        let s = warned.unwrap();
        assert_eq!(
            mounts(spec(&s, "main")),
            [row("/home/user/.cache", Rw, "p")]
        );
        assert!(
            matches!(
                get(&s, "main").warnings.as_slice(),
                [SpecWarning::DestinationUnchecked { path, error, .. }]
                    if *path == locked.join("sub")
                        && error.kind() == io::ErrorKind::PermissionDenied
            ),
            "{:?}",
            get(&s, "main").warnings
        );
    }

    #[test]
    fn an_unsearchable_ancestor_source_is_replaced_by_the_mask() {
        // The sandbox made the `rw` grant's own directory unsearchable. An
        // ephemeral rule below it (whose destination the planner does not
        // resolve) masks that directory, replacing the grant's mount.
        use std::os::unix::fs::PermissionsExt;
        if rustix::process::geteuid().is_root() {
            eprintln!("skipping: permission checks do not apply to root");
            return;
        }
        let f = Fixture::new();
        f.mkdir("home/.cache/sub");
        let cache = f.root.join("home/.cache");
        fs::set_permissions(&cache, fs::Permissions::from_mode(0o000)).unwrap();
        let s = compile_body(
            &f,
            "fs.rw = [\"~/.cache\"]\nfs.ephemeral = [\"~/.cache/sub/tmp\", \"~/.cache/eph\"]",
        );
        fs::set_permissions(&cache, fs::Permissions::from_mode(0o755)).unwrap();
        let s = s.unwrap();
        assert_eq!(
            mounts(spec(&s, "main")),
            [
                row("/home/user/.cache", Masked, "p"),
                row("/home/user/.cache/eph", Ephemeral, "p"),
                row("/home/user/.cache/sub/tmp", Ephemeral, "p"),
            ]
        );
        // The first mount below it meets the directory; the next one lies
        // inside the mask, where nothing is checked. The grant it replaced
        // is reported, louder.
        match get(&s, "main").warnings.as_slice() {
            [
                SpecWarning::DestinationMasked(dm),
                w @ SpecWarning::GrantHidden(hidden),
            ] => {
                assert_eq!(
                    (dm.sandbox.as_path(), &dm.path, dm.masked.as_path()),
                    (
                        Path::new("/home/user/.cache/eph"),
                        &cache.join("eph"),
                        Path::new("/home/user/.cache")
                    )
                );
                assert_eq!(
                    **hidden,
                    GrantHidden {
                        provider: "p".parse().unwrap(),
                        mode: Rw,
                        sandbox: "/home/user/.cache".into(),
                        dir: cache.clone(),
                        workspace: false,
                    }
                );
                assert_eq!(
                    w.to_string(),
                    format!(
                        "provider \"p\": this rw grant is hidden this session: its mount at \
                         \"/home/user/.cache\" is replaced by an empty masked directory, because \
                         {cache:?} cannot be inspected (a sandbox may have removed its \
                         permissions); restore them (e.g. `chmod u+rwx {cache:?}`) to get it back"
                    )
                );
            }
            other => panic!("unexpected warnings {other:?}"),
        }
    }

    /// Runs `body` with the directories `dirs` set to `mode`, restoring them
    /// (to 0755) even if `body` panics, so that the temp dir can be
    /// removed. Returns `None`, skipping `body`, when running as root, where
    /// permissions do not apply.
    fn with_mode<T>(dirs: &[PathBuf], mode: u32, body: impl FnOnce() -> T) -> Option<T> {
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
        let _restore = Restore(dirs.to_vec());
        for dir in dirs {
            fs::set_permissions(dir, fs::Permissions::from_mode(mode)).unwrap();
        }
        Some(body())
    }

    #[test]
    fn an_unsearchable_workspace_replaced_by_a_destination_mask_is_reported() {
        // The sandbox made the workspace unsearchable. An ephemeral rule
        // below the workspace mount (whose destination the planner does not
        // resolve) masks the workspace, replacing its mount: the warning
        // says the workspace is hidden.
        let f = Fixture::new();
        let ws = f.ws();
        let Some(s) = with_mode(std::slice::from_ref(&ws), 0o000, || {
            compile_body(
                &f,
                "fs.rw = [\"{workspace}\"]\nfs.ephemeral = [\"{workspace}/tmp\"]",
            )
        }) else {
            return;
        };
        let s = s.unwrap();
        assert_eq!(
            mounts(spec(&s, "main")),
            [
                row("/workspace", Masked, "p"),
                row("/workspace/tmp", Ephemeral, "p"),
            ]
        );
        match get(&s, "main").warnings.as_slice() {
            [
                SpecWarning::DestinationMasked(_),
                w @ SpecWarning::GrantHidden(hidden),
            ] => {
                assert_eq!(
                    **hidden,
                    GrantHidden {
                        provider: "p".parse().unwrap(),
                        mode: Rw,
                        sandbox: "/workspace".into(),
                        dir: ws.clone(),
                        workspace: true,
                    }
                );
                assert_eq!(
                    w.to_string(),
                    format!(
                        "provider \"p\": the workspace is hidden this session: its rw mount at \
                         \"/workspace\" is replaced by an empty masked directory, because {ws:?} \
                         cannot be inspected (a sandbox may have removed its permissions); \
                         restore them (e.g. `chmod u+rwx {ws:?}`) to get it back"
                    )
                );
            }
            other => panic!("unexpected warnings {other:?}"),
        }
    }

    #[test]
    fn untrusted_roots_skip_unresolvable_and_duplicate_rw_sources() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let ws = root.join("ws");
        fs::create_dir_all(root.join("a/b")).unwrap();
        fs::create_dir(&ws).unwrap();
        symlink("missing", root.join("dangling")).unwrap();
        symlink("a", root.join("alias")).unwrap();
        let mount = |host: PathBuf, mode, provider: &str| PlannedMount {
            sandbox: host.clone(),
            source: MountSource::Host {
                path: host,
                kind: EntryKind::Dir,
            },
            mode,
            provider: provider.parse().unwrap(),
            glob_link: false,
        };
        let mut roots = UntrustedRoots::new(&ws);
        roots.add_rw_mounts(
            Some(&pr("main")),
            &[
                mount(root.join("dangling"), Rw, "d"),
                mount(root.join("a/b"), Ro, "ro"),
                mount(root.join("alias"), Rw, "first"),
                mount(root.join("a"), Rw, "second"),
                mount(ws.clone(), Rw, "ws"),
                mount(root.join("a/b"), Rw, "inner"),
                PlannedMount {
                    sandbox: "/tmp".into(),
                    source: eph_source("/tmp"),
                    mode: Rw,
                    provider: "e".parse().unwrap(),
                    glob_link: false,
                },
            ],
        );
        assert_eq!(
            roots.roots,
            [
                UntrustedRoot {
                    path: ws.clone(),
                    kind: UntrustedKind::Workspace
                },
                rw_root(root.join("a"), "first", Some("main"), root.join("alias")),
                rw_root(root.join("a/b"), "inner", Some("main"), root.join("a/b")),
            ]
        );
        let at = |p: &Path| roots.containing(p).map(|r| r.path.clone());
        assert_eq!(at(&root.join("a/b/c")), Some(root.join("a/b")));
        assert_eq!(at(&root.join("a/b")), Some(root.join("a/b")));
        assert_eq!(at(&root.join("a/bc")), Some(root.join("a")));
        assert_eq!(at(&ws.join("x")), Some(ws.clone()));
        assert_eq!(at(&root.join("ab")), None);
        assert_eq!(at(&root), None);
    }

    // --- Providers' protected sources ---

    /// `base = "none"` with the workspace granted `rw` in `main` by
    /// provider `u`, then `extra`.
    fn ws_rw(extra: &str) -> String {
        format!(
            "base = \"none\"\n{}{extra}",
            prov("u", "main", "fs.rw = [\"{workspace}\"]")
        )
    }

    fn protected_row(sandbox: &str) -> (String, PathMode, String) {
        row(sandbox, Protected, "env")
    }

    #[test]
    fn a_provider_source_in_an_rw_workspace_is_protected_there() {
        let f = Fixture::new();
        f.file("ws/scripts/env.sh");
        let s = f
            .try_compile_protecting(&ws_rw(""), &[("env", "ws/scripts/env.sh")])
            .unwrap();
        let main = get(&s, "main");
        assert!(main.warnings.is_empty(), "{:?}", main.warnings);
        assert_eq!(
            mounts(&main.spec),
            [
                row("/workspace", Rw, "u"),
                protected_row("/workspace/scripts/env.sh")
            ]
        );
        assert_eq!(
            main.spec.mounts[1].source,
            host(&f.ws().join("scripts/env.sh"), EntryKind::File)
        );
        // Nothing asked to be protected (`protect = false`): nothing added.
        let s = f.try_compile_protecting(&ws_rw(""), &[]).unwrap();
        assert_eq!(mounts(spec(&s, "main")), [row("/workspace", Rw, "u")]);
    }

    #[test]
    fn a_provider_source_beats_exact_and_own_rw_rules_in_every_profile() {
        let f = Fixture::new();
        f.file("ws/scripts/env.sh");
        // An exact `rw` rule of the source in `main`, and another as the
        // own rule of a profile inheriting it: both would beat a protected
        // rule (§3.5), but not the supervisor's protection.
        let src = ws_rw(&format!(
            "[profiles.child]\n{}{}",
            prov("x", "main", "fs.rw = [\"{workspace}/scripts/env.sh\"]"),
            prov("c", "child", "fs.rw = [\"{workspace}/scripts/env.sh\"]"),
        ));
        let s = f
            .try_compile_protecting(&src, &[("env", "ws/scripts/env.sh")])
            .unwrap();
        for p in ["main", "child"] {
            let c = get(&s, p);
            assert!(c.warnings.is_empty(), "{p}: {:?}", c.warnings);
            assert_eq!(
                mounts(&c.spec),
                [
                    row("/workspace", Rw, "u"),
                    protected_row("/workspace/scripts/env.sh")
                ],
                "{p}"
            );
            assert_eq!(
                c.spec.mounts[1].source,
                host(&f.ws().join("scripts/env.sh"), EntryKind::File),
                "{p}"
            );
        }
    }

    #[test]
    fn a_provider_source_is_protected_wherever_an_rw_grant_shows_it() {
        let mut f = Fixture::new();
        // `~` is bound `rw`: keep the data directory out of it.
        f.state.data = DataDirs::canonical(f.root.join("data/stopit"));
        f.file("home/bin/env.sh");
        f.mkdir("home/other");
        let src = format!(
            "base = \"none\"\n[profiles.ro_view]\ninherit = \"none\"\n[profiles.hidden]\n\
             inherit = \"none\"\n{}{}{}",
            prov(
                "u",
                "main",
                "fs.rw = [\"~/bin\"]\nfs.bind = [{ host = \"~/bin\", sandbox = \"/opt/bin\", \
                 mode = \"rw\" }, { host = \"~\", sandbox = \"/opt/home\", mode = \"rw\" }]"
            ),
            prov("r", "ro_view", "fs.ro = [\"~/bin\"]"),
            prov("h", "hidden", "fs.rw = [\"~/other\"]"),
        );
        let s = f
            .try_compile_protecting(&src, &[("env", "home/bin/env.sh")])
            .unwrap();
        let main = get(&s, "main");
        assert!(main.warnings.is_empty(), "{:?}", main.warnings);
        assert_eq!(
            mounts(&main.spec),
            [
                row("/opt/bin", Rw, "u"),
                row("/opt/home", Rw, "u"),
                row("/home/user/bin", Rw, "u"),
                protected_row("/opt/bin/env.sh"),
                protected_row("/home/user/bin/env.sh"),
                protected_row("/opt/home/bin/env.sh"),
            ]
        );
        // Read-only, or not shown at all: nothing to add.
        assert_eq!(
            mounts(spec(&s, "ro_view")),
            [row("/home/user/bin", Ro, "r")]
        );
        assert_eq!(
            mounts(spec(&s, "hidden")),
            [row("/home/user/other", Rw, "h")]
        );
    }

    #[test]
    fn a_masked_or_read_only_provider_source_stays_so() {
        let f = Fixture::new();
        f.file("ws/scripts/env.sh");
        for (mode, rule) in [(Masked, "masked"), (Ro, "ro")] {
            let src = ws_rw(&prov(
                "x",
                "main",
                &format!("fs.{rule} = [\"{{workspace}}/scripts\"]"),
            ));
            let s = f
                .try_compile_protecting(&src, &[("env", "ws/scripts/env.sh")])
                .unwrap();
            assert_eq!(
                mounts(spec(&s, "main")),
                [
                    row("/workspace", Rw, "u"),
                    row("/workspace/scripts", mode, "x")
                ],
                "{rule}"
            );
        }
    }

    #[test]
    fn a_provider_source_inside_a_covered_mask_stays_hidden() {
        // `~/cfg` is masked at its own path and shown through an `rw` bind of
        // `~`, so it is masked at `/opt/home/cfg` too: the script inside
        // must not be shown read-only on top of that cover.
        let mut f = Fixture::new();
        f.state.data = DataDirs::canonical(f.root.join("data/stopit"));
        f.file("home/cfg/env.sh");
        let src = format!(
            "base = \"none\"\n{}",
            prov(
                "u",
                "main",
                "fs.masked = [\"~/cfg\"]\nfs.bind = [{ host = \"~\", sandbox = \"/opt/home\", \
                 mode = \"rw\" }]"
            ),
        );
        let s = f
            .try_compile_protecting(&src, &[("env", "home/cfg/env.sh")])
            .unwrap();
        let main = get(&s, "main");
        assert_eq!(
            mounts(&main.spec),
            [
                row("/opt/home", Rw, "u"),
                row("/home/user/cfg", Masked, "u"),
                row("/opt/home/cfg", Masked, "u"),
            ]
        );
        assert!(
            matches!(
                main.warnings.as_slice(),
                [SpecWarning::RestrictedContentExposed(_)]
            ),
            "{:?}",
            main.warnings
        );
    }

    #[test]
    fn a_provider_source_directory_is_protected_with_rw_grants_inside_it() {
        let f = Fixture::new();
        f.file("ws/scripts/env.sh");
        f.mkdir("ws/scripts/out");
        let src = ws_rw(&prov("x", "main", "fs.rw = [\"{workspace}/scripts/out\"]"));
        let s = f
            .try_compile_protecting(&src, &[("env", "ws/scripts")])
            .unwrap();
        let main = get(&s, "main");
        assert_eq!(
            mounts(&main.spec),
            [
                row("/workspace", Rw, "u"),
                protected_row("/workspace/scripts"),
                row("/workspace/scripts/out", Protected, "x"),
            ]
        );
        assert_eq!(
            main.spec.mounts[1].source,
            host(&f.ws().join("scripts"), EntryKind::Dir)
        );
        let [SpecWarning::InsideProtectedSource(w)] = main.warnings.as_slice() else {
            panic!("{:?}", main.warnings);
        };
        assert_eq!(w.provider.as_str(), "x");
        assert_eq!(w.protected_provider.as_str(), "env");
        assert_eq!(w.protected, f.ws().join("scripts"));
        assert_eq!(w.sandbox, Path::new("/workspace/scripts/out"));
        let msg = main.warnings[0].to_string();
        assert!(msg.contains("provider \"x\""), "{msg}");
        assert!(msg.contains("source of provider \"env\""), "{msg}");
    }

    #[test]
    fn a_provider_source_that_cannot_be_inspected_is_an_error() {
        let f = Fixture::new();
        let e = f
            .try_compile_protecting(&ws_rw(""), &[("env", "ws/gone.sh")])
            .unwrap_err();
        let CompileError::ProtectedSource {
            provider,
            path,
            kind,
        } = &e
        else {
            panic!("{e:?}");
        };
        assert_eq!(provider.as_str(), "env");
        assert_eq!(path, &f.ws().join("gone.sh"));
        assert_eq!(*kind, io::ErrorKind::NotFound);
        let msg = e.to_string();
        assert!(msg.contains("provider \"env\""), "{msg}");
        assert!(msg.contains("gone.sh"), "{msg}");
    }

    #[test]
    fn a_hard_linked_provider_source_is_an_error() {
        // The sandbox could rewrite it through its other name, in the `rw`
        // workspace, wherever the source itself is protected; or outside
        // every grant, through a name inside one.
        use std::os::unix::fs::PermissionsExt;
        let f = Fixture::new();
        f.file("ws/scripts/env.sh");
        // Read-only does not help: its owner, the user, can chmod it
        // through any name.
        fs::set_permissions(
            f.root.join("ws/scripts/env.sh"),
            fs::Permissions::from_mode(0o444),
        )
        .unwrap();
        f.mkdir("home/bin");
        fs::hard_link(f.root.join("ws/scripts/env.sh"), f.root.join("ws/copy.sh")).unwrap();
        fs::hard_link(
            f.root.join("ws/scripts/env.sh"),
            f.root.join("home/bin/env.sh"),
        )
        .unwrap();
        for source in ["ws/scripts/env.sh", "home/bin/env.sh"] {
            let e = f
                .try_compile_protecting(&ws_rw(""), &[("env", source)])
                .unwrap_err();
            let CompileError::ProtectedSourceHardLinked {
                provider,
                path,
                links,
            } = &e
            else {
                panic!("{source}: {e:?}");
            };
            assert_eq!(provider.as_str(), "env");
            assert_eq!(path, &f.root.join(source));
            assert_eq!(*links, 3);
            let msg = e.to_string();
            assert!(msg.contains("provider \"env\""), "{msg}");
            assert!(msg.contains(source), "{msg}");
            assert!(msg.contains("3 hard links"), "{msg}");
        }
        // A single link is fine again; a directory's link count is its
        // subdirectories', not hard links, and is not checked.
        fs::remove_file(f.root.join("ws/copy.sh")).unwrap();
        fs::remove_file(f.root.join("home/bin/env.sh")).unwrap();
        f.mkdir("ws/scripts/sub");
        f.try_compile_protecting(&ws_rw(""), &[("env", "ws/scripts/env.sh")])
            .unwrap();
        f.try_compile_protecting(&ws_rw(""), &[("env", "ws/scripts")])
            .unwrap();
    }

    #[test]
    fn static_rw_roots_are_the_config_providers_rw_grants() {
        let f = Fixture::new();
        for d in [
            "home/cache",
            "home/data",
            "home/real",
            "home/ro",
            "home/prof",
            "ws/out",
        ] {
            f.mkdir(d);
        }
        std::os::unix::fs::symlink(f.root.join("home/real"), f.root.join("home/link")).unwrap();
        let src = format!(
            "base = \"none\"\n[profiles.child]\n{}{}",
            prov(
                "a",
                "main",
                "fs.rw = [\"~/cache\", \"~/link\", \"{workspace}/out/*\", \"~/gone\", \"~/cache\"]\n\
                 fs.ro = [\"~/ro\"]\nfs.bind = [{ host = \"~/data\", sandbox = \"/d\", mode = \"rw\" \
                 }, { host = \"~/ro\", sandbox = \"/r\", mode = \"ro\" }]\n\
                 [provider.sandbox.profiles.extra]\nfs.rw = [\"~/prof\"]"
            ),
            prov("b", "child", "fs.rw = [\"{workspace}\"]"),
        );
        let cfg = Config::from_toml_str(&src).unwrap();
        let roots = static_rw_roots(&f.outputs(&cfg), &f.ctx);
        let got: Vec<(PathBuf, String, String)> = roots
            .iter()
            .map(|r| {
                let UntrustedKind::RwGrant {
                    provider, profile, ..
                } = &r.kind
                else {
                    panic!("{r:?}");
                };
                (
                    r.path.clone(),
                    provider.as_str().to_owned(),
                    profile.as_ref().unwrap().as_str().to_owned(),
                )
            })
            .collect();
        let home = f.root.join("home");
        let row = |p: PathBuf, provider: &str, profile: &str| {
            (p, provider.to_owned(), profile.to_owned())
        };
        // Canonical, once each; a glob as its walk root; a missing path and
        // read-only grants are no roots.
        assert_eq!(
            got,
            [
                row(home.join("cache"), "a", "main"),
                row(home.join("real"), "a", "main"),
                row(f.ws().join("out"), "a", "main"),
                row(home.join("data"), "a", "main"),
                row(home.join("prof"), "a", "a.extra"),
                row(f.ws(), "b", "child"),
            ]
        );
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

    // --- Reserved host paths ---

    /// `body` for `main` by provider `u` under `base = "none"`.
    fn none_with(body: &str) -> String {
        format!("base = \"none\"\n{}", prov("u", "main", body))
    }

    /// The reserved host source `e` is about.
    #[track_caller]
    fn reserved_host(e: CompileError) -> ReservedHostSource {
        match e {
            CompileError::Profile { error, .. } => match *error {
                SpecError::ReservedHostSource(r) => *r,
                e => panic!("{e:?}"),
            },
            e => panic!("{e:?}"),
        }
    }

    #[test]
    fn rw_grants_containing_the_data_directory_are_refused() {
        // The data directory need not exist: an `rw` grant above it could
        // create it.
        let f = Fixture::new();
        f.mkdir("home/.local/share");
        let home = f.root.join("home");
        for (body, host, sandbox) in [
            ("fs.rw = [\"~\"]", home.clone(), "/home/user"),
            (
                "fs.rw = [\"~/.local/share\"]",
                home.join(".local/share"),
                "/home/user/.local/share",
            ),
            (
                "fs.bind = [{ host = \"~/.local\", sandbox = \"/opt/local\", mode = \"rw\" }]",
                home.join(".local"),
                "/opt/local",
            ),
        ] {
            let r = reserved_host(f.compile_err(&none_with(body)));
            assert_eq!(
                r,
                ReservedHostSource {
                    provider: "u".parse().unwrap(),
                    mode: Rw,
                    host: host.clone(),
                    resolved: host.clone(),
                    sandbox: sandbox.into(),
                    dir: StateDir::Data,
                    reserved: f.state.data.store.path.clone(),
                    contains: true,
                    via: None,
                    workspace: false,
                },
                "{body}"
            );
        }
        let e = f.compile_err(&none_with("fs.rw = [\"~\"]"));
        assert_eq!(
            e.to_string(),
            format!(
                "cannot compile profile \"main\": provider \"u\": rw mount of {home:?} at \
                 \"/home/user\" contains stopit's data directory {:?}, which holds stopit's \
                 persistent state, such as which configurations you allowed; a sandbox could \
                 write it there, create it, or replace a directory or link on the way to it, so \
                 no writable mount may contain it or the way to it: grant narrower rw paths that \
                 leave them out, or make this mount ro",
                f.state.data.store.path
            )
        );
    }

    #[test]
    fn a_workspace_containing_the_data_directory_is_refused() {
        // A `.stopit.toml` in `~` makes it the workspace, which the default
        // base grants `rw`.
        let f = Fixture::with_workspace("home", "/workspace");
        let r = reserved_host(f.compile_err(""));
        assert_eq!(
            (&r.mode, &r.sandbox, r.dir, r.contains, r.workspace),
            (&Rw, &"/workspace".into(), StateDir::Data, true, true)
        );
        // No narrower grant can replace the workspace's own mount: the hint
        // is to pick another workspace, not to move the store.
        let msg = r.to_string();
        assert!(
            msg.ends_with(
                "no writable mount may contain it or the way to it; this mount is the workspace: \
                 use a workspace that leaves them out, such as a project directory below your \
                 home directory or elsewhere"
            ),
            "{msg}"
        );
        // A workspace inside the data directory.
        let f = Fixture::with_workspace("home/.local/share/stopit/ws", "/workspace");
        let r = reserved_host(f.compile_err(""));
        assert_eq!(
            (&r.sandbox, r.dir, r.contains, r.workspace),
            (&"/workspace".into(), StateDir::Data, false, true)
        );
        assert!(
            r.to_string()
                .ends_with("and this mount is the workspace: use a workspace outside it"),
            "{r}"
        );
    }

    #[test]
    fn sources_inside_a_state_directory_are_refused_whatever_the_mode() {
        let f = Fixture::new();
        f.mkdir("home/.local/share/stopit/x");
        f.mkdir("run/stopit/session");
        let data = f.state.data.store.path.clone();
        let runtime = f.state.runtime.path.clone();
        for (body, mode, host, dir) in [
            (
                "fs.rw = [\"~/.local/share/stopit/x\"]",
                Rw,
                data.join("x"),
                StateDir::Data,
            ),
            (
                "fs.ro = [\"~/.local/share/stopit\"]",
                Ro,
                data.clone(),
                StateDir::Data,
            ),
            (
                "fs.masked = [\"~/.local/share/stopit/x\"]",
                Masked,
                data.join("x"),
                StateDir::Data,
            ),
            (
                &format!("fs.ro = [{:?}]", runtime.join("session")),
                Ro,
                runtime.join("session"),
                StateDir::Runtime,
            ),
            (
                &format!(
                    "fs.bind = [{{ host = {:?}, sandbox = \"/opt/run\", mode = \"ro\" }}]",
                    runtime
                ),
                Ro,
                runtime.clone(),
                StateDir::Runtime,
            ),
        ] {
            let r = reserved_host(f.compile_err(&none_with(body)));
            assert_eq!(
                (r.mode, &r.resolved, r.dir, r.contains),
                (mode, &host, dir, false),
                "{body}"
            );
            let msg = r.to_string();
            let relation = if host == r.reserved {
                "is"
            } else {
                "lies inside"
            };
            assert!(
                msg.contains(&format!("{relation} stopit's {dir} {:?}", r.reserved)),
                "{msg}"
            );
            assert!(msg.ends_with("remove the rule"), "{msg}");
        }
    }

    #[test]
    fn read_only_grants_containing_the_data_directory_are_fine() {
        let f = Fixture::new();
        f.mkdir("home/.local/share/stopit");
        for body in [
            "fs.ro = [\"~\"]",
            "fs.masked = [\"~/.local\"]",
            "fs.bind = [{ host = \"~/.local\", sandbox = \"/opt/local\", mode = \"ro\" }]",
        ] {
            let s = f.compile(&none_with(body));
            let main = get(&s, "main");
            assert!(main.warnings.is_empty(), "{body}: {:?}", main.warnings);
            assert_eq!(main.spec.mounts.len(), 1, "{body}");
        }
    }

    #[test]
    fn read_only_grants_containing_the_runtime_directory_mask_it() {
        let f = Fixture::new();
        f.mkdir("run/stopit/session");
        let run = f.root.join("run");
        let runtime = f.state.runtime.path.clone();
        // At its own path, and bound elsewhere.
        for (body, sandbox) in [
            (format!("fs.ro = [{run:?}]"), run.clone()),
            (
                format!("fs.bind = [{{ host = {run:?}, sandbox = \"/opt/run\", mode = \"ro\" }}]"),
                PathBuf::from("/opt/run"),
            ),
        ] {
            let s = f.compile(&none_with(&body));
            let main = get(&s, "main");
            let masked_at = sandbox.join("stopit");
            assert_eq!(
                mounts(&main.spec),
                [
                    (sandbox.to_string_lossy().into_owned(), Ro, "u".to_owned()),
                    (
                        masked_at.to_string_lossy().into_owned(),
                        Masked,
                        "stopit".to_owned()
                    ),
                ],
                "{body}"
            );
            assert_eq!(
                main.spec.mounts[1].source,
                host(&runtime, EntryKind::Dir),
                "{body}"
            );
            let [SpecWarning::RuntimeDirMasked(w)] = main.warnings.as_slice() else {
                panic!("{body}: {:?}", main.warnings);
            };
            assert_eq!(
                **w,
                RuntimeDirMasked {
                    provider: "u".parse().unwrap(),
                    mode: Ro,
                    host: run.clone(),
                    resolved: run.clone(),
                    sandbox: sandbox.clone(),
                    runtime: runtime.clone(),
                    masked_at: masked_at.clone(),
                }
            );
            let msg = w.to_string();
            assert!(
                msg.contains(&format!(
                    "contains stopit's session runtime directory {runtime:?}"
                )),
                "{msg}"
            );
            assert!(
                msg.contains(&format!("so it is masked at {masked_at:?}")),
                "{msg}"
            );
        }
        // A mount on top of it hides it already: nothing to add.
        let s = f.compile(&none_with(&format!(
            "fs.ro = [{run:?}]\nfs.ephemeral = [{runtime:?}]"
        )));
        let main = get(&s, "main");
        assert!(main.warnings.is_empty(), "{:?}", main.warnings);
        assert_eq!(
            strs(main.spec.mounts.iter().map(|m| m.mode)),
            strs([Ro, Ephemeral])
        );
        // Writable, it is refused.
        let r = reserved_host(f.compile_err(&none_with(&format!("fs.rw = [{run:?}]"))));
        assert_eq!((r.mode, r.dir, r.contains), (Rw, StateDir::Runtime, true));
    }

    #[test]
    fn host_sources_and_state_directories_are_compared_canonically() {
        // `~/.local` is a link, so the data directory is not where the home
        // directory says; an `rw` grant of the link's target, or of a link to the
        // directory above it, still contains it.
        let mut f = Fixture::new();
        f.mkdir("real/local/share");
        f.mkdir("home/sub");
        symlink("../real/local", f.root.join("home/.local")).unwrap();
        symlink("real/local/share", f.root.join("share-link")).unwrap();
        f.state.data = crate::state::data_dirs(&f.root.join("home"), None).unwrap();
        assert_eq!(
            f.state.data.store.path,
            f.root.join("real/local/share/stopit")
        );
        for (rw, resolved) in [
            (f.root.join("real"), f.root.join("real")),
            (f.root.join("share-link"), f.root.join("real/local/share")),
        ] {
            let r = reserved_host(f.compile_err(&none_with(&format!("fs.rw = [{rw:?}]"))));
            assert_eq!((&r.host, &r.resolved), (&rw, &resolved));
            assert_eq!((r.dir, r.contains, r.via), (StateDir::Data, true, None));
        }
        let e = f.compile_err(&none_with(&format!(
            "fs.rw = [{:?}]",
            f.root.join("share-link")
        )));
        assert!(
            e.to_string().contains(&format!(
                "(resolving to {:?})",
                f.root.join("real/local/share")
            )),
            "{e}"
        );
        // `~` holds the link `~/.local`, which a sandbox could replace by a
        // directory holding a planted data directory.
        let r = reserved_host(f.compile_err(&none_with("fs.rw = [\"~\"]")));
        let link = f.root.join("home/.local");
        assert_eq!((r.contains, &r.via), (true, &Some(link.clone())));
        assert!(
            r.to_string().contains(&format!(
                "contains {link:?}, a symbolic link on the way to stopit's data directory {:?}",
                f.state.data.store.path
            )),
            "{r}"
        );
        // Beside the link, or read-only, it is fine.
        f.compile(&none_with("fs.rw = [\"~/sub\"]"));
        f.compile(&none_with("fs.ro = [\"~\"]"));
        f.compile(&none_with(&format!("fs.ro = [{:?}]", f.root.join("real"))));
    }

    #[test]
    fn a_mount_between_a_read_only_grant_and_the_runtime_directory_decides_it() {
        // The runtime directory two levels below the `ro` grant of `run`, so
        // that a mount can lie strictly between them.
        let mut f = Fixture::new();
        f.mkdir("run/user/stopit");
        f.mkdir("other");
        f.state.runtime = StatePath::canonical(f.root.join("run/user/stopit"));
        let run = f.root.join("run");
        let user = run.join("user");
        let other = f.root.join("other");
        // Mounted on top of `run`, an ephemeral directory, a mask or a grant
        // of other content hides the runtime directory: nothing to add.
        for (inner, mode) in [
            (format!("fs.ephemeral = [{user:?}]"), Ephemeral),
            (format!("fs.masked = [{user:?}]"), Masked),
            (
                format!("fs.bind = [{{ host = {other:?}, sandbox = {user:?}, mode = \"ro\" }}]"),
                Ro,
            ),
        ] {
            let body = format!("fs.ro = [{run:?}]\n{inner}");
            let s = f.compile(&none_with(&body));
            let main = get(&s, "main");
            assert!(main.warnings.is_empty(), "{body}: {:?}", main.warnings);
            assert_eq!(
                mounts(&main.spec),
                [
                    row(run.to_str().unwrap(), Ro, "u"),
                    row(user.to_str().unwrap(), mode, "u"),
                ],
                "{body}"
            );
        }
        // A read-only grant of `run/user` on top shows it in turn, so it is
        // masked there, once.
        let s = f.compile(&none_with(&format!("fs.ro = [{run:?}, {user:?}]")));
        let main = get(&s, "main");
        let masked_at = user.join("stopit");
        assert_eq!(
            mounts(&main.spec),
            [
                row(run.to_str().unwrap(), Ro, "u"),
                row(user.to_str().unwrap(), Ro, "u"),
                row(masked_at.to_str().unwrap(), Masked, "stopit"),
            ]
        );
        let [SpecWarning::RuntimeDirMasked(w)] = main.warnings.as_slice() else {
            panic!("{:?}", main.warnings);
        };
        assert_eq!((&w.sandbox, &w.masked_at), (&user, &masked_at));
    }

    #[test]
    fn a_protected_grant_containing_the_runtime_directory_masks_it() {
        let f = Fixture::new();
        let run = f.root.join("run");
        let runtime = f.state.runtime.path.clone();
        let s = f.compile(&none_with(&format!("fs.protected = [{run:?}]")));
        let main = get(&s, "main");
        assert_eq!(
            mounts(&main.spec),
            [
                row(run.to_str().unwrap(), Protected, "u"),
                row(runtime.to_str().unwrap(), Masked, "stopit"),
            ]
        );
        let [SpecWarning::RuntimeDirMasked(w)] = main.warnings.as_slice() else {
            panic!("{:?}", main.warnings);
        };
        assert_eq!((w.mode, &w.masked_at), (Protected, &runtime));
        assert!(
            w.to_string()
                .starts_with(&format!("provider \"u\": protected mount of {run:?}")),
            "{w}"
        );
    }

    #[test]
    fn a_cover_inside_a_state_directory_is_refused() {
        // `x` in the data directory is masked, and shown through a read-only
        // bind of `~/.local` (which may contain the data directory), so it
        // is covered at `/a/share/stopit/x`. That cover's source lies in the
        // data directory too, and it comes first.
        let f = Fixture::new();
        f.mkdir("home/.local/share/stopit/x");
        let data = f.state.data.store.path.clone();
        let r = reserved_host(f.compile_err(&none_with(
            "fs.masked = [\"~/.local/share/stopit/x\"]\n\
             fs.bind = [{ host = \"~/.local\", sandbox = \"/a\", mode = \"ro\" }]",
        )));
        assert_eq!(
            r,
            ReservedHostSource {
                provider: "u".parse().unwrap(),
                mode: Masked,
                host: data.join("x"),
                resolved: data.join("x"),
                sandbox: "/a/share/stopit/x".into(),
                dir: StateDir::Data,
                reserved: data.clone(),
                contains: false,
                via: None,
                workspace: false,
            }
        );
    }

    #[test]
    fn mounts_added_after_planning_are_checked_at_their_source() {
        // A protected source added by `protect_sources`, or a cover, is not
        // among the planned mounts' canonical sources: it is checked at its
        // own (canonical) source.
        let f = Fixture::new();
        let runtime = f.state.runtime.path.clone();
        let data = f.state.data.store.path.clone();
        let mount = |sandbox: &str, path: PathBuf, kind, mode| PlannedMount {
            sandbox: sandbox.into(),
            source: MountSource::Host { path, kind },
            mode,
            provider: "s".parse().unwrap(),
            glob_link: false,
        };
        for (m, dir, reserved) in [
            (
                mount(
                    "/src/env.sh",
                    runtime.join("session/env.sh"),
                    EntryKind::File,
                    Protected,
                ),
                StateDir::Runtime,
                &runtime,
            ),
            (
                mount("/opt/x", data.join("x"), EntryKind::Dir, Masked),
                StateDir::Data,
                &data,
            ),
        ] {
            let host = match &m.source {
                MountSource::Host { path, .. } => path.clone(),
                s => panic!("{s:?}"),
            };
            let e = check_state_dirs(
                vec![m],
                &BTreeMap::new(),
                (&f.ws(), Path::new("/workspace")),
                &f.state,
                &mut Vec::new(),
            )
            .unwrap_err();
            let SpecError::ReservedHostSource(r) = e else {
                panic!("{e:?}");
            };
            assert_eq!(
                (&r.resolved, r.dir, &r.reserved, r.contains),
                (&host, dir, reserved, false)
            );
        }
    }

    #[test]
    fn with_the_override_both_data_directories_are_reserved() {
        // `STOPIT_STATE_DIR` puts the store in `state`; the default location
        // in the (password database's) home stays reserved, so that a
        // sandbox cannot plant a store for sessions started without it.
        let mut f = Fixture::new();
        f.mkdir("var/state");
        f.mkdir("home/sub");
        let state = f.root.join("var/state");
        f.state.data =
            crate::state::data_dirs(&f.root.join("home"), Some(state.as_os_str())).unwrap();
        let home = f.root.join("home");
        for (body, reserved) in [
            (format!("fs.rw = [{:?}]", f.root.join("var")), state.clone()),
            (
                "fs.rw = [\"~\"]".to_owned(),
                home.join(".local/share/stopit"),
            ),
        ] {
            let r = reserved_host(f.compile_err(&none_with(&body)));
            assert_eq!(
                (r.dir, &r.reserved, r.contains),
                (StateDir::Data, &reserved, true),
                "{body}"
            );
        }
        f.compile(&none_with("fs.rw = [\"~/sub\"]"));
    }
}
