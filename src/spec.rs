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
//! Each profile's workspace mount point and sandbox `HOME` are checked
//! against the reserved-path rules (§6.2) before any mounts are planned;
//! the planned mounts' destinations are checked against them afterwards,
//! and their host sources against the host workspace (§6.2, "Workspace
//! exposure").

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use rustix::io::Errno;
use thiserror::Error;

use crate::config::{Config, ProfileRef, ProviderName};
use crate::expand::ExpansionContext;
use crate::manifest::{
    DevMode, Domain, EtcFile, OptInSyscall, SandboxHome, ShareableNamespace, ShimName, ShimSpec,
};
use crate::policy::{NetworkMode, PathMode};
use crate::provider::ProviderOutput;
use crate::resolve::{
    EffectiveEnv, EffectiveGrants, EffectiveNetwork, MergeError, MountSource, PathPlanError,
    PlanWarning, PlannedMount, ProfileError, build_profile_graph, merge_profiles, plan_mounts,
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
    /// workspace files where their masks and protections do not apply
    /// (§6.2, "Workspace exposure").
    #[error(
        "provider {:?}: {mode} mount of {host:?}{} at {sandbox:?} exposes the host workspace \
         {workspace:?} outside the workspace mount, where its masks and protected files do not \
         apply; grant narrower paths that leave the workspace out, mask this one, or reach these \
         files through the workspace mount",
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
    /// A mount's host source runs through a symlink inside the host
    /// workspace (§6.2, "Workspace exposure"). Boxed to keep `SpecError`
    /// small.
    #[error(transparent)]
    WorkspaceLinkFollowed(Box<LinkFollowed>),
    /// A mount's host source could not be resolved to a canonical path, so
    /// whether it exposes the host workspace cannot be checked.
    #[error(
        "provider {:?}: cannot resolve the host source {host:?} of the {mode} mount at \
         {sandbox:?} ({kind}) to check that it does not expose the host workspace",
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
}

/// A mount's host source runs through a symlink inside the host workspace,
/// which the sandbox may have planted to redirect the grant to any host
/// path (§6.2, "Workspace exposure"). This holds however the source
/// reaches the workspace: written inside it, or through symlinks outside
/// it that lead there.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error(
    "provider {:?}: {mode} mount of {host:?} at {sandbox:?} runs through the symlink {link:?} \
     inside the host workspace {workspace:?} (resolving to {resolved:?}); links inside the \
     workspace are never followed, whatever the rule's anchor or the links leading there: \
     remove the link or change the rule",
    .provider.as_str()
)]
pub struct LinkFollowed {
    /// The provider whose rule produced the mount.
    pub provider: ProviderName,
    /// The mount's mode.
    pub mode: PathMode,
    /// The mount's host source, as planned.
    pub host: PathBuf,
    /// The first symlink inside the host workspace that resolving `host`
    /// follows, named below its canonical parent directory.
    pub link: PathBuf,
    /// `host` with every symlink resolved.
    pub resolved: PathBuf,
    /// The mount's sandbox destination.
    pub sandbox: PathBuf,
    /// The host workspace.
    pub workspace: PathBuf,
}

/// `" (resolving to …)"` when a host source is not its own canonical path.
fn resolved_note(host: &Path, resolved: &Path) -> String {
    if host == resolved {
        String::new()
    } else {
        format!(" (resolving to {resolved:?})")
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

/// The directories stopit sets up itself and that nothing else may equal,
/// contain or be placed inside: the masked `/proc`, the `/dev`, and
/// stopit's own runtime directory.
const SYSTEM_DIRS: [&str; 3] = ["/proc", "/dev", "/run/stopit"];

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

/// Checks that no planned mount exposes the host workspace at a second
/// sandbox path (DESIGN.md §6.2, "Workspace exposure"): masks and protected
/// files apply to sandbox paths inside the workspace mount, not to host
/// content, so the same files shown elsewhere would escape them.
///
/// Every mount with a host source except a `masked` one (which shows
/// nothing of it) is checked. Its source, resolved to a canonical path,
/// must not be the host workspace or an ancestor of it, unless it is the
/// workspace itself mounted at the workspace mount; and if it lies inside
/// the host workspace, the mount must be at the aligned path, i.e. the
/// workspace mount joined with the source's path relative to the host
/// workspace.
///
/// The planner keeps host sources as written: `~` and absolute rules follow
/// symlinks on the way and binds follow a final symlink, as bwrap does when
/// mounting. Hence each source is resolved first (see
/// [`resolve_host_source`]), so a link outside the workspace pointing into
/// it is caught; a source that cannot be resolved fails closed.
/// `{workspace}` sources contain no symlinks below the workspace (the
/// planner refuses them), so aligned ones resolve to themselves.
///
/// No source may run through a symlink inside the host workspace: the
/// sandbox can plant links there, so a `~` or absolute rule such as
/// `~/proj/x` with `x -> ../.ssh` would otherwise mount `~/.ssh`, which
/// neither contains nor lies inside the workspace. This holds however the
/// source reaches the workspace: written inside it, or through a link
/// outside it (`~/current/x` with `~/current -> proj`, or `~/.bashrc ->
/// proj/bashrc` replaced by a link in the workspace), where the planted
/// link would turn a rule that shows nothing or is rejected into a mount
/// of any host path. This extends the `{workspace}` anchor's no-symlink
/// rule to every rule. (When such a mount's destination is inside the
/// workspace mount, the planner's destination check already refuses a link
/// written there.) Only links count: a literal `..` may leave the
/// workspace again, since the sandbox cannot change what it means. Rule
/// paths cannot contain `..`, but the target of a link outside the
/// workspace can (`~/via -> proj/../.ssh` resolves to `~/.ssh` like any
/// other path), and only the user can write that.
/// `ctx`'s host workspace is canonical by contract. Paths are compared by
/// component.
fn check_workspace_exposure(
    mounts: &[PlannedMount],
    ctx: &ExpansionContext,
) -> Result<(), SpecError> {
    let ws_host = ctx.workspace_host();
    let ws_sandbox = ctx.workspace_sandbox();
    for m in mounts {
        let MountSource::Host { path: host, .. } = &m.source else {
            continue;
        };
        if m.mode == PathMode::Masked {
            continue;
        }
        let (resolved, ws_link) = resolve_host_source(host, ws_host).map_err(|error| {
            SpecError::HostSourceUnresolved {
                provider: m.provider.clone(),
                mode: m.mode,
                host: host.clone(),
                sandbox: m.sandbox.clone(),
                kind: error.kind(),
            }
        })?;
        if let Some(link) = ws_link {
            return Err(SpecError::WorkspaceLinkFollowed(Box::new(LinkFollowed {
                provider: m.provider.clone(),
                mode: m.mode,
                host: host.clone(),
                link,
                resolved,
                sandbox: m.sandbox.clone(),
                workspace: ws_host.to_owned(),
            })));
        }
        let exposed = match resolved.strip_prefix(ws_host) {
            // Inside the workspace (or the workspace itself): only the
            // aligned mapping is allowed.
            Ok(rel) if rel.as_os_str().is_empty() => m.sandbox != ws_sandbox,
            Ok(rel) => m.sandbox != ws_sandbox.join(rel),
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
    }
    Ok(())
}

/// The kernel's limit on symlinks followed in one path lookup
/// (`MAXSYMLINKS`).
const MAX_SYMLINKS: usize = 40;

/// Resolves the absolute host path `path` as the kernel would, one
/// component at a time, following every symlink (the final one included).
/// Returns the canonical path and the first symlink followed that lies
/// inside `workspace` (canonical), if any, named below its canonical parent.
///
/// Walking by hand rather than canonicalising sees every link the lookup
/// passes, including ones a link outside the workspace leads through (a
/// link to a path inside the workspace that has itself been replaced by a
/// link): checking prefixes of the path as written would miss those. It
/// costs one `lstat` per component and one `readlink` per link, the
/// components of link targets included. Errors are those of the lookup
/// (`ENOTDIR` for a component below a non-directory or a trailing `/` or
/// `/.` after one, `ELOOP` past [`MAX_SYMLINKS`] links).
///
/// Links are followed by their text, so `/proc` magic links
/// (`/proc/<pid>/root`, `/proc/self/fd/N`), which the kernel follows to the
/// object they refer to rather than to the path `readlink` shows, resolve
/// differently here than when mounted (DESIGN.md §11).
fn resolve_host_source(path: &Path, workspace: &Path) -> io::Result<(PathBuf, Option<PathBuf>)> {
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
    // Whether `resolved` is a directory, which any component after it
    // requires.
    let mut is_dir = true;
    let mut pending = Vec::new();
    push(&mut pending, path);
    let mut links = 0;
    let mut ws_link = None;
    while let Some(name) = pending.pop() {
        if name == "/" {
            (resolved, is_dir) = (PathBuf::from("/"), true);
            continue;
        }
        if !is_dir {
            return Err(Errno::NOTDIR.into());
        }
        // `resolved` is canonical, so `..` is its lexical parent. A `Normal`
        // component is never `/`, `.` or `..`.
        if name == "." {
            continue;
        } else if name == ".." {
            resolved.pop();
            continue;
        }
        let next = resolved.join(&name);
        let meta = next.symlink_metadata()?;
        if !meta.is_symlink() {
            (resolved, is_dir) = (next, meta.is_dir());
            continue;
        }
        links += 1;
        if links > MAX_SYMLINKS {
            return Err(Errno::LOOP.into());
        }
        let target = fs::read_link(&next)?;
        if ws_link.is_none() && resolved.starts_with(workspace) {
            ws_link = Some(next);
        }
        push(&mut pending, &target);
    }
    Ok((resolved, ws_link))
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
pub fn compile_profile(
    grants: &EffectiveGrants,
    parent: Option<&EffectiveGrants>,
    ctx: &ExpansionContext,
) -> Result<CompiledProfile, SpecError> {
    let home = grants.system.home.clone().unwrap_or_default();
    check_reserved_paths(ctx.workspace_sandbox(), Path::new(home.as_str()))?;
    let plan = plan_mounts(&grants.fs, &ctx.with_sandbox_home(&home))?;
    check_mount_destinations(&plan.mounts)?;
    check_workspace_exposure(&plan.mounts, ctx)?;
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
            Fixture {
                _dir: dir,
                root,
                ws_rel,
                ws_mount,
                ctx,
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

    /// The `(mode, host, link, resolved, sandbox)` of the
    /// `WorkspaceLinkFollowed` error compiling `body` gives, checking its
    /// provider and workspace.
    fn link_followed(f: &Fixture, body: &str) -> (PathMode, PathBuf, PathBuf, PathBuf, PathBuf) {
        let e = compile_body(f, body).unwrap_err();
        let CompileError::Profile { error, .. } = e else {
            panic!("{body}: expected a profile error, got {e:?}");
        };
        match *error {
            SpecError::WorkspaceLinkFollowed(lf) => {
                let LinkFollowed {
                    provider,
                    mode,
                    host,
                    link,
                    resolved,
                    sandbox,
                    workspace,
                } = *lf;
                assert_eq!(provider.as_str(), "p", "{body}");
                assert_eq!(workspace, f.ws(), "{body}");
                (mode, host, link, resolved, sandbox)
            }
            other => panic!("{body}: expected WorkspaceLinkFollowed, got {other:?}"),
        }
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
            link_followed(&f, "fs.rw = [\"~/proj/d/id_ed25519\"]"),
            (
                Rw,
                f.ws().join("d/id_ed25519"),
                f.ws().join("d"),
                ssh.join("id_ed25519"),
                PathBuf::from("/home/user/proj/d/id_ed25519")
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
        // Masked, it shows nothing of the target.
        if let Err(e) = compile_body(&f, "fs.masked = [\"~/proj/x\"]") {
            panic!("masked: {e}");
        }
        let e = compile_body(&f, "fs.ro = [\"~/proj/x\"]").unwrap_err();
        assert_eq!(
            e.to_string(),
            format!(
                "cannot compile profile \"main\": provider \"p\": ro mount of {x:?} at \
                 \"/home/user/proj/x\" runs through the symlink {x:?} inside the host workspace \
                 {:?} (resolving to {ssh:?}); links inside the workspace are never followed, \
                 whatever the rule's anchor or the links leading there: remove the link or change \
                 the rule",
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
        // `(rule, host, planted link, resolved)`.
        for (rule, host, link, resolved) in [
            // A glob below an entering link: the walk follows its root link
            // and matches the planted link itself.
            ("~/current/conf*", "current/config", &config, ssh.clone()),
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
        assert_eq!((link, sandbox), (config, abs));
        // Masked, it shows nothing of the target.
        if let Err(e) = compile_body(&f, "fs.masked = [\"~/current/config\"]") {
            panic!("masked: {e}");
        }
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
        // A link planted there is refused by the planner's destination
        // check first, since the destination is inside the workspace mount.
        symlink("../../.ssh", f.ws().join("y")).unwrap();
        let e = compile_body(&f, "fs.ro = [\"~/proj/y\"]").unwrap_err();
        assert!(
            matches!(
                e,
                CompileError::Profile { ref error, .. }
                    if matches!(**error, SpecError::Mounts(PathPlanError::WorkspaceSymlink { .. }))
            ),
            "{e:?}"
        );
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
                resolve_host_source(&path, &ws).unwrap(),
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
                resolve_host_source(&path, &ws).unwrap_err().raw_os_error(),
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
            resolve_host_source(&ws.join("dangling"), &ws)
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
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
        assert_eq!(
            resolve_host_source(&last_ok, &ws).unwrap(),
            (root.join("out"), None)
        );
        assert!(fs::metadata(&last_ok).unwrap().is_dir());
        let too_many = root.join(format!("l{MAX_SYMLINKS}"));
        let loop_errno = Some(Errno::LOOP.raw_os_error());
        assert_eq!(
            resolve_host_source(&too_many, &ws)
                .unwrap_err()
                .raw_os_error(),
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
            .map(|path| resolve_host_source(&path, &ws).map_err(|e| e.raw_os_error()));
        // Restore permissions before asserting, so the tempdir can be
        // removed even if an assertion fails.
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
        for result in results {
            assert_eq!(result, Err(Some(Errno::ACCESS.raw_os_error())));
        }
    }

    #[test]
    fn aligned_rules_through_workspace_links_are_refused_by_the_planner() {
        // With the workspace mounted at its `~` path the destination is
        // inside the workspace mount, so the planner's destination check
        // refuses the link first (a restrictive rule) or drops it (`rw`).
        let f = Fixture::with_workspace("home/proj", "/home/user/proj");
        f.mkdir("home/.ssh");
        symlink("../.ssh", f.ws().join("x")).unwrap();
        let e = compile_body(&f, "fs.ro = [\"~/proj/x\"]").unwrap_err();
        assert!(
            matches!(
                e,
                CompileError::Profile { ref error, .. }
                    if matches!(**error, SpecError::Mounts(PathPlanError::WorkspaceSymlink { .. }))
            ),
            "{e:?}"
        );
        let s = compile_body(&f, "fs.rw = [\"~/proj/x\"]").unwrap();
        assert!(spec(&s, "main").mounts.is_empty());
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
                 mount, where its masks and protected files do not apply; grant narrower paths \
                 that leave the workspace out, mask this one, or reach these files through the \
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
                 workspace mount, where its masks and protected files do not apply; grant \
                 narrower paths that leave the workspace out, mask this one, or reach these files \
                 through the workspace mount",
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

    #[test]
    fn unresolvable_host_sources_fail_closed() {
        let f = Fixture::new();
        symlink(f.root.join("missing"), f.root.join("home/dangling")).unwrap();
        let e = compile_body(&f, "fs.ro = [\"~/dangling\"]").unwrap_err();
        let CompileError::Profile { error, .. } = &e else {
            panic!("expected a profile error, got {e:?}");
        };
        assert_eq!(
            **error,
            SpecError::HostSourceUnresolved {
                provider: "p".parse().unwrap(),
                mode: Ro,
                host: f.root.join("home/dangling"),
                sandbox: PathBuf::from("/home/user/dangling"),
                kind: std::io::ErrorKind::NotFound,
            }
        );
        // A masked one is not resolved, so the planner's handling stands.
        if let Err(e) = compile_body(&f, "fs.masked = [\"~/dangling\"]") {
            panic!("masked: {e}");
        }
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
