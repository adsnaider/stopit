//! The built-in `vcs` provider (DESIGN.md §7.3): keeps a sandbox's hands
//! off the repository's metadata, and brokers `jj` and `git` instead.
//!
//! At session start it finds the workspace's repository layout on the host
//! ([`discover`]), reading only files it validates, never running a VCS
//! tool on the workspace. It then contributes:
//!
//! * to `main`, a mask (or, with `view = "ro"`, a read-only view) of the
//!   workspace's `.git` and `.jj`;
//! * the profiles `ro`, `local` and (unless both `fetch` and `push` are
//!   `"deny"`) `remote`, which appear as `vcs.ro`, `vcs.local` and
//!   `vcs.remote`: the metadata and its backing storage read-only, or
//!   writable with the git config files and `.jj/repo/config.toml` that
//!   exist at session start read-only and the hooks directories that exist
//!   then masked. `vcs.ro` and `vcs.local` are offline, while `vcs.remote`
//!   has `network = { mode = "full" }`, binds the host's `SSH_AUTH_SOCK`
//!   and `~/.ssh/known_hosts` read-only when present, and sets
//!   `GIT_SSH_COMMAND` with `-F /dev/null` and `StrictHostKeyChecking=yes`.
//!   git gets no system or user configuration, no hooks, filesystem monitor,
//!   pager or editor, and the repository found here rather than one found
//!   from the caller's directory. jj gets no user configuration, editor or
//!   pager;
//! * the shims `jj` and `git` (per `tools`), with the policy of §7.4 written
//!   as declarative rules, routing remote fetch and push commands to
//!   `vcs.remote` according to `fetch` and `push`.
//!
//! Layouts it supports: a plain `.git` directory, a `.jj` directory with or
//! without a colocated `.git`, a `jj` secondary workspace (`jj workspace
//! add`) whose `.jj/repo` file names a primary `.jj/repo` directory outside
//! the workspace that names it back in `workspace_store/index`, and a git
//! worktree whose `.git` file names an admin directory outside the workspace
//! that names it back. Other layouts get the mask but no VCS profiles, with
//! a warning.

use std::fs;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::{Provider, ProviderContext, ProviderError, ProviderOutput};
use crate::config::{ProfileRef, ProviderName, ProviderOrigin, VcsTool, VcsView};
use crate::manifest::Manifest;
use crate::policy::Decision;

/// The name of the built-in `vcs` provider of `base = "default"`.
pub const VCS_PROVIDER_NAME: &str = "vcs";

/// The git configuration every brokered git command gets, over any file:
/// no hooks, no filesystem monitor, no pager, no `ext::` transport, no
/// bare repository git was not pointed at, and no signing or signature
/// checks, whose programs read their own configuration. Other keys of the
/// repository's own configuration still apply.
const SAFE_GIT_CONFIG: [(&str, &str); 11] = [
    ("core.hooksPath", "/dev/null"),
    ("core.fsmonitor", "false"),
    ("core.pager", "cat"),
    ("protocol.ext.allow", "never"),
    ("safe.bareRepository", "explicit"),
    ("gpg.program", "false"),
    ("gpg.ssh.program", "false"),
    ("gpg.x509.program", "false"),
    ("commit.gpgSign", "false"),
    ("tag.gpgSign", "false"),
    ("log.showSignature", "false"),
];

/// The `HOME` of the VCS profiles, an empty directory of their own, so no
/// program they start reads configuration `main` wrote to the session's
/// shared home.
const VCS_HOME: &str = "/home/vcs";

/// `XDG_CONFIG_HOME` in the VCS profiles: inside their own home, at a path
/// no `~` grant of `main` names, so jj's repository configuration
/// (`jj/repos`) and git's attributes and ignore files there are their own.
const VCS_XDG_CONFIG: &str = "/home/vcs/.xdg-config";

/// Where the host's `SSH_AUTH_SOCK` is bound read-only in `vcs.remote`.
const VCS_SSH_AGENT_SOCK: &str = "/home/vcs/.ssh/agent.sock";

/// Where the host's `~/.ssh/known_hosts` is bound read-only in `vcs.remote`.
const VCS_KNOWN_HOSTS: &str = "/home/vcs/.ssh/known_hosts";

/// Host SSH agent socket and `known_hosts` file for `vcs.remote`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SshRemote {
    /// Host path of `SSH_AUTH_SOCK`, bound read-only at
    /// [`VCS_SSH_AGENT_SOCK`] in `vcs.remote`.
    pub auth_sock: Option<PathBuf>,
    /// Host path of `~/.ssh/known_hosts`, bound read-only at
    /// [`VCS_KNOWN_HOSTS`] in `vcs.remote`.
    pub known_hosts: Option<PathBuf>,
}

impl SshRemote {
    /// Discovers the host's `SSH_AUTH_SOCK` and `~/.ssh/known_hosts` for
    /// `ctx`, refusing symlinks inside the workspace or static `rw` grants
    /// and paths inside the workspace or stopit's state directories.
    pub fn discover(ctx: &ProviderContext) -> Self {
        let sock = std::env::var_os("SSH_AUTH_SOCK").map(PathBuf::from);
        Self::discover_with_sock(ctx, sock.as_deref())
    }

    /// Like [`Self::discover`], taking the candidate `SSH_AUTH_SOCK` path
    /// explicitly.
    pub fn discover_with_sock(ctx: &ProviderContext, ssh_auth_sock: Option<&Path>) -> Self {
        let Ok(session_dir) = crate::state::resolve_allowing_missing(&ctx.session_dir) else {
            return SshRemote::default();
        };
        let runtime_dir = match ctx.session_dir.parent().filter(|rt| {
            rt.file_name() == Some(std::ffi::OsStr::new(crate::state::STATE_DIR_NAME))
        }) {
            Some(rt) => match crate::state::resolve_allowing_missing(rt) {
                Ok(resolved) => Some(resolved.path),
                Err(_) => return SshRemote::default(),
            },
            None => None,
        };
        let Ok(ctx_data) = crate::state::data_dirs(&ctx.home, None) else {
            return SshRemote::default();
        };
        let Ok(ctx_config) = crate::state::config_dirs(&ctx.home, None) else {
            return SshRemote::default();
        };
        let Ok(host_data) = crate::state::data_dirs_from_host() else {
            return SshRemote::default();
        };
        let Ok(host_config) = crate::state::config_dirs_from_host() else {
            return SshRemote::default();
        };
        let resolve = |candidate: &Path, is_kind: fn(&fs::FileType) -> bool| -> Option<PathBuf> {
            if !candidate.is_absolute() {
                return None;
            }
            let canon =
                crate::spec::resolve_script_path(candidate, &ctx.workspace, &ctx.rw_grants).ok()?;
            let allowed = !canon.starts_with(&ctx.workspace)
                && !ctx.rw_grants.iter().any(|r| canon.starts_with(&r.path))
                && !canon.starts_with(&session_dir.path)
                && runtime_dir.as_ref().is_none_or(|rt| !canon.starts_with(rt))
                && ctx_data.iter().all(|s| !canon.starts_with(&s.path))
                && ctx_config.iter().all(|s| !canon.starts_with(&s.path))
                && host_data.iter().all(|s| !canon.starts_with(&s.path))
                && host_config.iter().all(|s| !canon.starts_with(&s.path));
            if !allowed {
                return None;
            }
            let meta = fs::symlink_metadata(&canon).ok()?;
            if !is_kind(&meta.file_type()) {
                return None;
            }
            rule_path(&ctx.workspace, &canon)?;
            Some(canon)
        };
        let auth_sock = ssh_auth_sock.and_then(|p| resolve(p, FileTypeExt::is_socket));
        let known_hosts = resolve(&ctx.home.join(".ssh/known_hosts"), fs::FileType::is_file);
        SshRemote {
            auth_sock,
            known_hosts,
        }
    }
}

/// The `vcs` provider.
#[derive(Debug, Clone)]
pub struct VcsProvider {
    name: ProviderName,
    view: VcsView,
    tools: Vec<VcsTool>,
    fetch: Decision,
    push: Decision,
    /// Asked for, but not supported yet, so only warned about.
    signing: bool,
    origin: ProviderOrigin,
}

impl VcsProvider {
    /// A provider named `name` with these options.
    pub fn new(
        name: ProviderName,
        view: VcsView,
        tools: Vec<VcsTool>,
        fetch: Decision,
        push: Decision,
        origin: ProviderOrigin,
    ) -> Self {
        VcsProvider {
            name,
            view,
            tools,
            fetch,
            push,
            signing: false,
            origin,
        }
    }

    /// The provider with `signing` as configured.
    pub fn with_signing(self, signing: bool) -> Self {
        VcsProvider { signing, ..self }
    }

    /// Warnings for options the provider takes but cannot honour yet.
    fn unsupported_options(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.signing {
            out.push(
                "signing = true has no effect yet, and brokered commits are not signed".into(),
            );
        }
        out
    }

    /// The provider of `base = "default"`: the defaults of §7.3.
    pub fn builtin() -> Self {
        VcsProvider::new(
            VCS_PROVIDER_NAME.parse().expect("a valid provider name"),
            VcsView::Masked,
            vec![VcsTool::Jj, VcsTool::Git],
            Decision::Ask,
            Decision::Ask,
            ProviderOrigin::Builtin,
        )
    }
}

/// A repository's layout, as far as the provider supports it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Layout {
    /// The workspace's own `.git`, directory or file, if it has one.
    pub dot_git: Option<PathBuf>,
    /// The workspace's own `.jj`, if it has one.
    pub dot_jj: Option<PathBuf>,
    /// The git directories commands write: the `.git` directory, or a
    /// worktree's admin directory and common directory. Empty when git is
    /// not supported here.
    pub git_dirs: Vec<PathBuf>,
    /// External directories a jj secondary workspace writes: its primary
    /// `.jj/repo` directory, and its primary `.git` directory when the
    /// primary repository is colocated. Empty for a primary jj repository
    /// or when jj is not supported here.
    pub jj_dirs: Vec<PathBuf>,
    /// Whether `.jj/repo` is a secondary-workspace pointer file holding a
    /// relative path (which requires `mount == workspace` so `jj -R` can
    /// resolve it inside the sandbox).
    pub jj_relative_repo: bool,
    /// Whether the `.jj` directory is a repository or secondary workspace
    /// the provider supports.
    pub jj_supported: bool,
    /// What the provider could not support, for warnings.
    pub unsupported: Vec<String>,
}

/// Finds the layout of the repository at `workspace`, without running a
/// VCS tool and without trusting a path the workspace names unless what it
/// names points back. `workspace` is canonical.
pub fn discover(workspace: &Path) -> Layout {
    let mut layout = Layout::default();
    let dot_git = workspace.join(".git");
    let dot_jj = workspace.join(".jj");
    match fs::symlink_metadata(&dot_git) {
        Ok(m) if m.is_dir() => {
            // A `commondir` makes git take its configuration, hooks and
            // objects from the directory it names.
            if is_present(&dot_git.join("commondir")) {
                layout.unsupported.push(format!(
                    "{dot_git:?}, whose commondir file shares another repository's storage"
                ));
            } else {
                layout.git_dirs.push(dot_git.clone());
            }
            layout.dot_git = Some(dot_git);
        }
        Ok(m) if m.is_file() => {
            match worktree_dirs(workspace, &dot_git) {
                Ok(dirs) => layout.git_dirs = dirs,
                Err(why) => layout
                    .unsupported
                    .push(format!("the git worktree at {workspace:?}: {why}")),
            }
            layout.dot_git = Some(dot_git);
        }
        Ok(_) => {
            layout.unsupported.push(format!(
                "{dot_git:?}, which is neither a file nor a directory"
            ));
            layout.dot_git = Some(dot_git);
        }
        Err(_) => {}
    }
    match fs::symlink_metadata(&dot_jj) {
        Ok(m) if m.is_dir() => {
            match jj_repo(workspace, &dot_jj) {
                // jj writes the workspace's `.git` then, which must be a
                // layout git is brokered for, with its config locked.
                Ok(jj) if jj.colocated_with_own_git && layout.git_dirs.is_empty() => {
                    layout.unsupported.push(format!(
                        "the jj repository at {workspace:?}, whose colocated .git is not supported"
                    ));
                }
                Ok(jj)
                    if !jj.external_dirs.is_empty()
                        && layout.dot_git.is_some()
                        && layout.git_dirs.is_empty() =>
                {
                    layout.unsupported.push(format!(
                        "the jj secondary workspace at {workspace:?}, whose .git is not supported"
                    ));
                }
                Ok(jj) => {
                    layout.jj_dirs = jj.external_dirs;
                    layout.jj_relative_repo = jj.relative_pointer;
                    layout.jj_supported = true;
                }
                Err(why) => layout.unsupported.push(why),
            }
            layout.dot_jj = Some(dot_jj);
        }
        Ok(_) => {
            layout
                .unsupported
                .push(format!("{dot_jj:?}, which is not a directory"));
            layout.dot_jj = Some(dot_jj);
        }
        Err(_) => {}
    }
    if layout.dot_git.is_none()
        && layout.dot_jj.is_none()
        && let Some(root) = workspace
            .ancestors()
            .skip(1)
            .find(|a| is_present(&a.join(".git")) || is_present(&a.join(".jj")))
    {
        layout.unsupported.push(format!(
            "the checkout at {root:?}, which holds the workspace below its root"
        ));
    }
    layout
}

/// Whether anything is at `path`, a link included, without following one.
fn is_present(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

/// Whether `path` is a directory, not a link to one.
fn is_real_dir(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.is_dir())
}

struct JjRepo {
    /// Whether the repository's git store is the workspace's own `.git`
    /// directory (a colocated primary repository).
    colocated_with_own_git: bool,
    /// External directories a secondary workspace writes: the primary
    /// `.jj/repo` directory, followed by the primary `.git` directory when
    /// the primary repository is colocated. Empty for a primary repository.
    external_dirs: Vec<PathBuf>,
    /// Whether `.jj/repo` is a file holding a relative path.
    relative_pointer: bool,
}

/// Checks that the `.jj` directory `dot_jj` holds a primary repository or a
/// supported secondary workspace (`jj workspace add`).
fn jj_repo(workspace: &Path, dot_jj: &Path) -> Result<JjRepo, String> {
    let repo = dot_jj.join("repo");
    match fs::symlink_metadata(&repo) {
        Ok(m) if m.is_dir() => {}
        Ok(m) if m.is_file() => {
            return jj_secondary_repo(workspace, dot_jj, &repo)
                .map_err(|why| format!("the jj secondary workspace at {workspace:?}: {why}"));
        }
        Ok(_) => {
            return Err(format!(
                "{dot_jj:?}, whose repo is neither a file nor a directory"
            ));
        }
        Err(_) => return Err(format!("{dot_jj:?}, which has no repo directory")),
    }
    let store = repo.join("store");
    if !is_real_dir(&store) {
        return Err(format!("{dot_jj:?}, whose repo has no store directory"));
    }
    let target_file = store.join("git_target");
    if !is_present(&target_file) {
        return Ok(JjRepo {
            colocated_with_own_git: false,
            external_dirs: Vec::new(),
            relative_pointer: false,
        });
    }
    let target = read_small(&target_file).map_err(|why| format!("the jj repository: {why}"))?;
    let target = target.trim_end();
    let leading_parents = check_pointer_target(Path::new(target), 0)
        .map_err(|why| format!("the jj repository at {workspace:?}: {why}"))?;
    if leading_parents > 0 && target != "../../../.git" {
        return Err(format!(
            "the jj repository at {workspace:?}: its git_target traverses outside the store"
        ));
    }
    let workspace_canon = fs::canonicalize(workspace).map_err(|e| e.to_string())?;
    let joined = store.join(target);
    if crate::spec::first_link_inside(&joined, &workspace_canon)
        .map_err(|e| format!("the jj repository's git store cannot be resolved: {e}"))?
        .is_some()
    {
        return Err(format!(
            "the jj repository at {workspace:?}: its git_target traverses a symlink inside the workspace"
        ));
    }
    let resolved = fs::canonicalize(&joined)
        .map_err(|e| format!("the jj repository's git store cannot be resolved: {e}"))?;
    let store = fs::canonicalize(&store).map_err(|e| e.to_string())?;
    let dot_git = workspace.join(".git");
    let own_git = is_real_dir(&dot_git)
        .then(|| fs::canonicalize(&dot_git).ok())
        .flatten();
    if Some(&resolved) == own_git.as_ref() {
        Ok(JjRepo {
            colocated_with_own_git: true,
            external_dirs: Vec::new(),
            relative_pointer: false,
        })
    } else if resolved.starts_with(&store) {
        Ok(JjRepo {
            colocated_with_own_git: false,
            external_dirs: Vec::new(),
            relative_pointer: false,
        })
    } else {
        Err(format!(
            "the jj repository at {workspace:?}, whose git store {resolved:?} is elsewhere"
        ))
    }
}

/// Checks the lexical shape of a `.jj/repo` or `store/git_target` pointer
/// string: no `.` components, `..` components only as a leading prefix of a
/// relative path, at least `min_leading_parents` leading `..` components when
/// relative, and at least one normal component. Returns the number of leading
/// `..` components.
fn check_pointer_target(
    target: &Path,
    min_leading_parents: usize,
) -> Result<usize, &'static str> {
    use std::path::Component;
    let mut leading_parents = 0usize;
    let mut seen_normal_or_root = false;
    let mut has_normal = false;
    for comp in target.components() {
        match comp {
            Component::RootDir => {
                seen_normal_or_root = true;
            }
            Component::ParentDir => {
                if seen_normal_or_root {
                    return Err("its target path contains `..` after a path component");
                }
                leading_parents += 1;
            }
            Component::Normal(_) => {
                seen_normal_or_root = true;
                has_normal = true;
            }
            Component::CurDir | Component::Prefix(_) => {
                return Err("its target path contains `.` or an invalid prefix");
            }
        }
    }
    if !has_normal {
        return Err("its target path has no final component");
    }
    if target.is_relative() && leading_parents < min_leading_parents {
        return Err("its relative target path is inside the workspace");
    }
    Ok(leading_parents)
}

/// Validates a `jj` secondary workspace whose `.jj/repo` file is `repo_file`.
/// The primary `.jj/repo` directory must lie outside `workspace` and name
/// `workspace` back in `workspace_store/index`, so a `.jj/repo` file written
/// inside the sandbox cannot point to an unrelated repository.
fn jj_secondary_repo(workspace: &Path, dot_jj: &Path, repo_file: &Path) -> Result<JjRepo, String> {
    let text = read_small(repo_file)?;
    let target = text.trim_end();
    if target.is_empty() {
        return Err("its .jj/repo file is empty".to_owned());
    }
    check_pointer_target(Path::new(target), 2)?;
    let relative_pointer = Path::new(target).is_relative();
    let workspace = fs::canonicalize(workspace).map_err(|e| e.to_string())?;
    let joined = dot_jj.join(target);
    if crate::spec::first_link_inside(&joined, &workspace)
        .map_err(|e| format!("cannot resolve its repository: {e}"))?
        .is_some()
    {
        return Err("its .jj/repo path traverses a symlink inside the workspace".to_owned());
    }
    let repo_dir = fs::canonicalize(&joined)
        .map_err(|e| format!("cannot resolve its repository: {e}"))?;
    if repo_dir.starts_with(&workspace) {
        return Err("its repository is inside the workspace".to_owned());
    }
    if repo_dir.file_name() != Some(std::ffi::OsStr::new("repo"))
        || repo_dir.parent().and_then(Path::file_name) != Some(std::ffi::OsStr::new(".jj"))
    {
        return Err("its .jj/repo file does not point to a .jj/repo directory".to_owned());
    }
    let store = repo_dir.join("store");
    if !is_real_dir(&store) {
        return Err("its repository has no store directory".to_owned());
    }
    let ws_store = repo_dir.join("workspace_store");
    if !is_real_dir(&ws_store) {
        return Err("its repository has no workspace_store directory".to_owned());
    }
    let index_bytes = read_small_bytes(&ws_store.join("index"), 65536)?;
    let paths = parse_workspace_store_paths(&index_bytes)
        .ok_or_else(|| "its repository's workspace_store/index is invalid".to_owned())?;
    let names_us = paths.iter().any(|p| {
        !p.is_empty()
            && fs::canonicalize(repo_dir.join(p)).ok().as_deref() == Some(workspace.as_path())
    });
    if !names_us {
        return Err("its repository does not name this workspace back".to_owned());
    }
    let mut external_dirs = vec![repo_dir.clone()];
    let target_file = store.join("git_target");
    if is_present(&target_file) {
        let git_target = read_small(&target_file)?;
        let git_target = git_target.trim_end();
        let leading_parents = check_pointer_target(Path::new(git_target), 0)?;
        if leading_parents > 0 && git_target != "../../../.git" {
            return Err("its repository's git_target traverses outside the store".to_owned());
        }
        let git_joined = store.join(git_target);
        if crate::spec::first_link_inside(&git_joined, &workspace)
            .map_err(|e| format!("its repository's git store cannot be resolved: {e}"))?
            .is_some()
            || crate::spec::first_link_inside(&git_joined, &repo_dir)
                .map_err(|e| format!("its repository's git store cannot be resolved: {e}"))?
                .is_some()
        {
            return Err(
                "its repository's git_target traverses a symlink inside the workspace or repository"
                    .to_owned(),
            );
        }
        let resolved = fs::canonicalize(&git_joined)
            .map_err(|e| format!("its repository's git store cannot be resolved: {e}"))?;
        let store_canon = fs::canonicalize(&store).map_err(|e| e.to_string())?;
        if !resolved.starts_with(&store_canon) {
            let primary_git = repo_dir
                .parent()
                .and_then(Path::parent)
                .map(|p| p.join(".git"));
            let valid_colocated = primary_git.as_deref().is_some_and(|git| {
                is_real_dir(git)
                    && fs::canonicalize(git).ok().as_ref() == Some(&resolved)
                    && !resolved.starts_with(&workspace)
                    && is_real_dir(&resolved.join("objects"))
                    && fs::symlink_metadata(resolved.join("HEAD")).is_ok_and(|m| m.is_file())
                    && !is_present(&resolved.join("commondir"))
            });
            if !valid_colocated {
                return Err(format!(
                    "its repository's git store {resolved:?} is elsewhere"
                ));
            }
            external_dirs.push(resolved);
        }
    }
    Ok(JjRepo {
        colocated_with_own_git: false,
        external_dirs,
        relative_pointer,
    })
}

fn read_varint(buf: &mut &[u8]) -> Option<u64> {
    let mut val = 0u64;
    let mut shift = 0u32;
    loop {
        let (&b, rest) = buf.split_first()?;
        *buf = rest;
        if shift == 63 && b > 1 {
            return None;
        }
        val |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Some(val);
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
}

fn skip_protobuf_field<'a>(buf: &mut &'a [u8], wire_type: u64) -> Option<Option<&'a [u8]>> {
    match wire_type {
        0 => {
            read_varint(buf)?;
            Some(None)
        }
        1 => {
            if buf.len() < 8 {
                return None;
            }
            *buf = &buf[8..];
            Some(None)
        }
        2 => {
            let len = usize::try_from(read_varint(buf)?).ok()?;
            if buf.len() < len {
                return None;
            }
            let (slice, rest) = buf.split_at(len);
            *buf = rest;
            Some(Some(slice))
        }
        5 => {
            if buf.len() < 4 {
                return None;
            }
            *buf = &buf[4..];
            Some(None)
        }
        _ => None,
    }
}

/// Parses the workspace paths (field 2 of each repeated field 1 entry) from
/// a `jj` `simple_workspace_store` index file (`workspace_store/index`).
fn parse_workspace_store_paths(mut buf: &[u8]) -> Option<Vec<String>> {
    let mut paths = Vec::new();
    while !buf.is_empty() {
        let tag = read_varint(&mut buf)?;
        let field = tag >> 3;
        let wire_type = tag & 7;
        if field == 0 {
            return None;
        }
        let payload = skip_protobuf_field(&mut buf, wire_type)?;
        if field == 1 {
            let mut entry = payload?;
            while !entry.is_empty() {
                let entry_tag = read_varint(&mut entry)?;
                let entry_field = entry_tag >> 3;
                let entry_wire = entry_tag & 7;
                if entry_field == 0 {
                    return None;
                }
                let entry_payload = skip_protobuf_field(&mut entry, entry_wire)?;
                if entry_field == 2 {
                    let bytes = entry_payload?;
                    let path = std::str::from_utf8(bytes).ok()?;
                    paths.push(path.to_owned());
                }
            }
        }
    }
    Some(paths)
}

/// The admin and common directories of the git worktree whose `.git` file
/// is `dot_git`. The admin directory must name `dot_git` back, and sit in
/// the common directory's `worktrees`, so a file the sandbox wrote cannot
/// point anywhere else. Neither may be inside the workspace, where `main`
/// could have written them.
fn worktree_dirs(workspace: &Path, dot_git: &Path) -> Result<Vec<PathBuf>, String> {
    let text = read_small(dot_git)?;
    let target = text
        .strip_prefix("gitdir: ")
        .map(str::trim_end)
        .ok_or("its .git file does not start with `gitdir: `")?;
    let admin = fs::canonicalize(workspace.join(target))
        .map_err(|e| format!("cannot resolve its admin directory: {e}"))?;
    let back = read_small(&admin.join("gitdir"))?;
    let back = fs::canonicalize(admin.join(back.trim_end()))
        .map_err(|_| "its admin directory names no existing .git file".to_owned())?;
    let ours = fs::canonicalize(dot_git).map_err(|e| e.to_string())?;
    if back != ours {
        return Err("its admin directory names another worktree".to_owned());
    }
    let common = read_small(&admin.join("commondir"))?;
    let common = fs::canonicalize(admin.join(common.trim_end()))
        .map_err(|e| format!("cannot resolve its common directory: {e}"))?;
    if admin.parent() != Some(common.join("worktrees").as_path()) {
        return Err("its admin directory is not in the common directory's worktrees".to_owned());
    }
    if !is_real_dir(&common.join("objects"))
        || !fs::symlink_metadata(common.join("HEAD")).is_ok_and(|m| m.is_file())
    {
        return Err("its common directory is not a git directory".to_owned());
    }
    let workspace = fs::canonicalize(workspace).map_err(|e| e.to_string())?;
    if admin.starts_with(&workspace) || common.starts_with(&workspace) {
        return Err("its git directories are inside the workspace".to_owned());
    }
    Ok(vec![admin, common])
}

/// The bytes of the small regular file at `path` (up to `max_len` bytes),
/// opened without following a link and without opening anything else.
fn read_small_bytes(path: &Path, max_len: usize) -> Result<Vec<u8>, String> {
    use rustix::fs::{FileType, Mode, OFlags};
    use std::io::Read;
    let cannot = |e: &dyn std::fmt::Display| format!("cannot read {path:?}: {e}");
    let limit = u64::try_from(max_len).unwrap_or(u64::MAX);
    // An `O_PATH` descriptor first, which opens no device or FIFO, then
    // the file itself through it once it is known to be a regular one.
    let handle = rustix::fs::open(
        path,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| cannot(&e))?;
    let stat = rustix::fs::fstat(&handle).map_err(|e| cannot(&e))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || u64::try_from(stat.st_size).map_err(|_| format!("{path:?} is not a small file"))? > limit
    {
        return Err(format!("{path:?} is not a small file"));
    }
    let fd = rustix::fs::open(
        format!("/proc/self/fd/{}", std::os::fd::AsRawFd::as_raw_fd(&handle)),
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| cannot(&e))?;
    let mut bytes = Vec::new();
    fs::File::from(fd)
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| cannot(&e))?;
    if bytes.len() > max_len {
        return Err(format!("{path:?} is not a small file"));
    }
    Ok(bytes)
}

/// The text of the small regular file at `path`, opened without following
/// a link and without opening anything else.
fn read_small(path: &Path) -> Result<String, String> {
    let bytes = read_small_bytes(path, 4096)?;
    String::from_utf8(bytes).map_err(|e| format!("cannot read {path:?}: {e}"))
}

/// The host user's `user.name` and `user.email`, from the user's own git
/// configuration, never the workspace's.
fn host_identity() -> Vec<(String, String)> {
    ["user.name", "user.email"]
        .into_iter()
        .filter_map(|key| {
            let out = Command::new("git")
                .args(["config", "--global", "--get", key])
                .current_dir("/")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .stdin(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .output()
                .ok()?;
            let value = String::from_utf8(out.stdout).ok()?.trim().to_owned();
            (out.status.success() && !value.is_empty() && !value.contains(['\0', '\n']))
                .then(|| (key.to_owned(), value))
        })
        .collect()
}

/// A rule path for the host path `path`: below the workspace as
/// `{workspace}/...`, else absolute. `None` if it holds characters a rule
/// path cannot.
fn rule_path(workspace: &Path, path: &Path) -> Option<String> {
    let text = match path.strip_prefix(workspace) {
        Ok(rel) if rel.as_os_str().is_empty() => "{workspace}".to_owned(),
        Ok(rel) => format!("{{workspace}}/{}", rel.to_str()?),
        Err(_) => path.to_str()?.to_owned(),
    };
    let plain = !text
        .trim_start_matches("{workspace}")
        .contains(['*', '?', '[', ']', '{', '}', '\\', '~']);
    plain.then_some(text)
}

impl VcsProvider {
    /// The manifest for `layout` in `workspace`, which sandboxes see at
    /// `mount`, with `identity` for git and jj and `ssh` for `vcs.remote`.
    /// An error names a path no rule can hold.
    pub fn manifest_for(
        &self,
        workspace: &Path,
        mount: &Path,
        layout: &Layout,
        identity: &[(String, String)],
        ssh: &SshRemote,
    ) -> Result<Manifest, String> {
        use toml::Value;
        let path = |p: &Path| {
            rule_path(workspace, p).ok_or_else(|| {
                format!("{p:?} holds one of *?[]{{}}\\~ or is not UTF-8, so no rule can name it")
            })
        };
        let list =
            |items: Vec<String>| Value::Array(items.into_iter().map(Value::String).collect());
        let mut root = self.main_view(workspace, layout)?;
        let git = !layout.git_dirs.is_empty();
        let jj = layout.jj_supported && (!layout.jj_relative_repo || mount == workspace);
        if !git && !jj {
            return manifest_from(root);
        }
        // What the VCS profiles see: the metadata of the tools brokered
        // here and the backing storage. An unsupported `.git` stays out
        // even when jj is brokered, since nothing in it is locked.
        let metadata: Vec<String> = [
            layout.dot_git.as_ref().filter(|_| git),
            layout.dot_jj.as_ref().filter(|_| jj),
        ]
        .into_iter()
        .flatten()
        .map(|p| path(p))
        .collect::<Result<_, _>>()?;
        let push_unique = |vec: &mut Vec<String>, item: String| {
            if !vec.contains(&item) {
                vec.push(item);
            }
        };
        let mut storage = metadata;
        for dir in layout
            .git_dirs
            .iter()
            .chain(layout.jj_dirs.iter().filter(|_| jj))
        {
            push_unique(&mut storage, path(dir)?);
        }
        let mut locked = Vec::new();
        let mut masked = Vec::new();
        for dir in layout
            .git_dirs
            .iter()
            .chain(layout.jj_dirs.iter().skip(1).filter(|_| jj))
        {
            for file in ["config", "config.worktree", "info/attributes"] {
                if is_present(&dir.join(file)) {
                    push_unique(&mut locked, path(&dir.join(file))?);
                }
            }
            if is_real_dir(&dir.join("modules")) {
                push_unique(&mut locked, format!("{}/modules/*/config", path(dir)?));
                push_unique(&mut masked, format!("{}/modules/*/hooks", path(dir)?));
            }
            if is_real_dir(&dir.join("worktrees")) {
                push_unique(
                    &mut locked,
                    format!("{}/worktrees/*/config.worktree", path(dir)?),
                );
            }
            if is_present(&dir.join("hooks")) {
                push_unique(&mut masked, path(&dir.join("hooks"))?);
            }
        }
        if jj && let Some(dot_jj) = &layout.dot_jj {
            if let Some(repo_dir) = layout.jj_dirs.first() {
                push_unique(&mut locked, path(&dot_jj.join("repo"))?);
                for file in ["config.toml", "store/git_target"] {
                    let p = repo_dir.join(file);
                    if is_present(&p) {
                        push_unique(&mut locked, path(&p)?);
                    }
                }
            } else {
                for file in ["repo/config.toml", "repo/store/git_target"] {
                    let p = dot_jj.join(file);
                    if is_present(&p) {
                        push_unique(&mut locked, path(&p)?);
                    }
                }
            }
        }
        // Where a host path appears in the sandbox: below the workspace
        // mount, or at its own path.
        let in_sandbox = |p: &Path| match p.strip_prefix(workspace) {
            Ok(rel) => mount.join(rel),
            Err(_) => p.to_owned(),
        };
        let mut env = toml::Table::new();
        let mut set = |key: &str, value: String| env.insert(key.into(), value.into());
        set("GIT_CONFIG_NOSYSTEM", "1".into());
        set("GIT_CONFIG_GLOBAL", "/dev/null".into());
        // The repository is the one found here, never one git would find
        // by walking up from a directory the caller picked.
        if let Some(git_dir) = layout.git_dirs.first() {
            let git_dir = in_sandbox(git_dir);
            let git_dir_str = git_dir
                .to_str()
                .ok_or_else(|| format!("{git_dir:?}, whose sandbox path is not UTF-8"))?;
            let mount_str = mount
                .to_str()
                .ok_or_else(|| format!("{mount:?}, whose workspace mount is not UTF-8"))?;
            set("GIT_DIR", git_dir_str.to_owned());
            set("GIT_WORK_TREE", mount_str.to_owned());
        }
        // No editor or pager, which would hand the caller's terminal a
        // program that runs commands.
        set("GIT_EDITOR", "false".into());
        set("GIT_SEQUENCE_EDITOR", "false".into());
        set("GIT_PAGER", "cat".into());
        set("JJ_CONFIG", "/dev/null".into());
        set("JJ_EDITOR", "false".into());
        set("GNUPGHOME", format!("{VCS_HOME}/.gnupg-unused"));
        set("XDG_CONFIG_HOME", VCS_XDG_CONFIG.into());
        let mut config: Vec<(&str, &str)> = SAFE_GIT_CONFIG.to_vec();
        for (key, value) in identity {
            config.push((key, value));
            match key.as_str() {
                "user.name" => set("JJ_USER", value.clone()),
                "user.email" => set("JJ_EMAIL", value.clone()),
                _ => None,
            };
        }
        set("GIT_CONFIG_COUNT", config.len().to_string());
        for (i, (key, value)) in config.iter().enumerate() {
            set(&format!("GIT_CONFIG_KEY_{i}"), (*key).into());
            set(&format!("GIT_CONFIG_VALUE_{i}"), (*value).into());
        }
        let mut profiles = toml::Table::new();
        // `vcs.ro` and `vcs.local` have no network, so a call the rules miss
        // (`git --no-pager push` takes the default) still reaches no remote
        // over the network.
        let offline = || Value::Table(table([("mode", "none".into())]));
        // `system.home` sets `HOME` and the home in `/etc/passwd`, and
        // the profiles' own `ephemeral` rule for it beats the `~` they
        // inherit, whose backing directory `main` shares.
        let home = || list(vec![VCS_HOME.to_owned()]);
        let system = || Value::Table(table([("home", VCS_HOME.into())]));
        // A VCS command has no use for `stopit-grant`, and a grant on top
        // of these profiles would mount host paths beside the metadata.
        let no_grant = || Value::Table(table([("grant", false.into())]));
        let mut ro = toml::Table::new();
        ro.insert("network".into(), offline());
        ro.insert("system".into(), system());
        ro.insert("sandbox".into(), no_grant());
        ro.insert(
            "fs".into(),
            Value::Table(table([
                ("ro", list(storage.clone())),
                ("ephemeral", home()),
            ])),
        );
        ro.insert(
            "env".into(),
            Value::Table(table([("set", Value::Table(env.clone()))])),
        );
        profiles.insert("ro".into(), Value::Table(ro));
        let mut local_fs = table([("rw", list(storage)), ("ephemeral", home())]);
        if !locked.is_empty() {
            local_fs.insert("ro".into(), list(locked));
        }
        if !masked.is_empty() {
            local_fs.insert("masked".into(), list(masked));
        }
        let mut local = toml::Table::new();
        local.insert("network".into(), offline());
        local.insert("system".into(), system());
        local.insert("sandbox".into(), no_grant());
        local.insert("fs".into(), Value::Table(local_fs.clone()));
        local.insert(
            "env".into(),
            Value::Table(table([("set", Value::Table(env.clone()))])),
        );
        profiles.insert("local".into(), Value::Table(local));
        if self.fetch != Decision::Deny || self.push != Decision::Deny {
            let mut remote_fs = local_fs;
            remote_fs.insert(
                "ephemeral".into(),
                list(vec![VCS_HOME.to_owned(), format!("{VCS_HOME}/.ssh")]),
            );
            let mut binds = Vec::new();
            let sock_rule = ssh.auth_sock.as_deref().map(&path).transpose()?;
            if let Some(sock) = &sock_rule {
                binds.push(Value::Table(table([
                    ("host", sock.clone().into()),
                    ("sandbox", VCS_SSH_AGENT_SOCK.into()),
                    ("mode", "ro".into()),
                ])));
            }
            let kh_rule = ssh.known_hosts.as_deref().map(&path).transpose()?;
            if let Some(kh) = &kh_rule {
                binds.push(Value::Table(table([
                    ("host", kh.clone().into()),
                    ("sandbox", VCS_KNOWN_HOSTS.into()),
                    ("mode", "ro".into()),
                ])));
            }
            if !binds.is_empty() {
                remote_fs.insert("bind".into(), Value::Array(binds));
            }
            let mut remote_env = env;
            if sock_rule.is_some() {
                remote_env.insert("SSH_AUTH_SOCK".into(), VCS_SSH_AGENT_SOCK.into());
            }
            let known_hosts_arg = if kh_rule.is_some() {
                VCS_KNOWN_HOSTS
            } else {
                "/dev/null"
            };
            remote_env.insert(
                "GIT_SSH_COMMAND".into(),
                format!(
                    "ssh -F /dev/null -o IdentityFile=/dev/null -o StrictHostKeyChecking=yes -o UserKnownHostsFile={known_hosts_arg}"
                )
                .into(),
            );
            let mut remote = toml::Table::new();
            remote.insert(
                "network".into(),
                Value::Table(table([("mode", "full".into())])),
            );
            remote.insert("system".into(), system());
            remote.insert("sandbox".into(), no_grant());
            remote.insert("fs".into(), Value::Table(remote_fs));
            remote.insert(
                "env".into(),
                Value::Table(table([("set", Value::Table(remote_env))])),
            );
            profiles.insert("remote".into(), Value::Table(remote));
        }
        root.insert("profiles".into(), Value::Table(profiles));
        let mut shims = toml::Table::new();
        for tool in &self.tools {
            let shim = match tool {
                VcsTool::Jj if jj => jj_shim(self.fetch, self.push),
                VcsTool::Git if git => git_shim(self.fetch, self.push),
                _ => continue,
            };
            shims.insert(tool.as_str().into(), shim);
        }
        if !shims.is_empty() {
            root.insert("shims".into(), Value::Table(shims));
        }
        manifest_from(root)
    }

    /// The view of the workspace's own metadata in `main`, which every
    /// layout gets: masked, or read-only with `view = "ro"`.
    ///
    /// A worktree's admin and common directories and a jj secondary
    /// workspace's primary repository directories get the same view, so a
    /// grant of `main` that covers them does not expose them either. One
    /// whose path no rule can name is left out.
    fn main_view(&self, workspace: &Path, layout: &Layout) -> Result<toml::Table, String> {
        let mut metadata: Vec<toml::Value> = [&layout.dot_git, &layout.dot_jj]
            .into_iter()
            .flatten()
            .map(|p| {
                rule_path(workspace, p)
                    .map(toml::Value::String)
                    .ok_or_else(|| format!("no rule can name {p:?}"))
            })
            .collect::<Result<_, _>>()?;
        for dir in layout
            .git_dirs
            .iter()
            .chain(layout.jj_dirs.iter())
            .filter(|d| !d.starts_with(workspace))
        {
            if let Some(p) = rule_path(workspace, dir) {
                let v = toml::Value::String(p);
                if !metadata.contains(&v) {
                    metadata.push(v);
                }
            }
        }
        let mut root = toml::Table::new();
        if metadata.is_empty() {
            return Ok(root);
        }
        let mode = match self.view {
            VcsView::Masked => "masked",
            VcsView::Ro => "ro",
        };
        root.insert(
            "fs".into(),
            toml::Value::Table(table([(mode, toml::Value::Array(metadata))])),
        );
        Ok(root)
    }
}

fn table<const N: usize>(entries: [(&str, toml::Value); N]) -> toml::Table {
    entries
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect()
}

fn manifest_from(root: toml::Table) -> Result<Manifest, String> {
    toml::from_str(&root.to_string()).map_err(|e| e.to_string())
}

/// Builds a regex pattern matching any non-empty prefix of the long flag name
/// `name` (without the leading `--`).
fn long_flag_prefix_pattern(name: &str) -> String {
    let mut chars = name.chars().rev();
    let Some(last) = chars.next() else {
        return String::new();
    };
    let mut acc = regex_escape_char(last);
    for ch in chars {
        let escaped = regex_escape_char(ch);
        acc = format!("{escaped}(?:{acc})?");
    }
    acc
}

fn regex_escape_char(ch: char) -> String {
    match ch {
        '.' | '+' | '*' | '?' | '(' | ')' | '|' | '[' | ']' | '{' | '}' | '^' | '$' | '\\' => {
            format!("\\{ch}")
        }
        _ => ch.to_string(),
    }
}

/// Builds a regex matching any of `flags` (short flags in clusters or with
/// attached values, and long flags or their prefix abbreviations).
fn deny_flags_regex(flags: &[&str]) -> String {
    let mut short = String::new();
    let mut long = Vec::new();
    for flag in flags {
        if let Some(name) = flag.strip_prefix("--") {
            long.push(long_flag_prefix_pattern(name));
        } else if let Some(ch) = flag.strip_prefix('-') {
            short.push_str(ch);
        }
    }
    let long_pat = long.join("|");
    match (!short.is_empty(), !long_pat.is_empty()) {
        (true, true) => {
            format!(r"(?:^| )(?:-[^- =]*[{short}]|--(?:{long_pat})(?: |=|$))")
        }
        (true, false) => format!(r"(?:^| )-[^- =]*[{short}]"),
        (false, true) => format!(r"(?:^| )--(?:{long_pat})(?: |=|$)"),
        (false, false) => unreachable!("deny_flags_regex called with empty flags"),
    }
}

/// A `decision = "deny"` regex rule for `flags`.
fn deny_flags_rule(flags: &[&str]) -> toml::Value {
    let mut t = toml::Table::new();
    t.insert("regex".into(), deny_flags_regex(flags).into());
    t.insert("decision".into(), "deny".into());
    toml::Value::Table(t)
}

/// Rules for `subcommands` with `decision` and `profile` (`prefix` rules for
/// literal subcommands, `regex` rules for `<word> *` wildcards).
fn rules_for(subcommands: &[&str], decision: &str, profile: Option<&str>) -> Vec<toml::Value> {
    subcommands
        .iter()
        .map(|sub| {
            let mut t = toml::Table::new();
            if let Some(prefix) = sub.strip_suffix(" *") {
                t.insert("regex".into(), format!(r"^{prefix} [^-][^ ]*(?: |$)").into());
            } else {
                t.insert("prefix".into(), (*sub).into());
            }
            t.insert("decision".into(), decision.into());
            if let Some(p) = profile {
                t.insert("profile".into(), p.into());
            }
            toml::Value::Table(t)
        })
        .collect()
}

/// Rules for remote commands (`fetch` or `push`), routed to `vcs.remote`
/// unless `decision` is [`Decision::Deny`].
fn remote_rules(subcommands: &[&str], decision: Decision) -> Vec<toml::Value> {
    let profile = match decision {
        Decision::Allow | Decision::Ask => Some("remote"),
        Decision::Deny => None,
    };
    rules_for(subcommands, decision.as_str(), profile)
}

/// A declarative shim running `cmd` (`[binary, args...]`), with first-match-wins
/// `rules` and asking to run anything else in `vcs.local`.
fn shim(binary: &str, args: &[&str], rules: Vec<toml::Value>) -> toml::Value {
    let cmd: Vec<toml::Value> = std::iter::once(binary)
        .chain(args.iter().copied())
        .map(toml::Value::from)
        .collect();
    let mut t = toml::Table::new();
    t.insert("cmd".into(), toml::Value::Array(cmd));
    t.insert(
        "default".into(),
        toml::Value::Table(table([
            ("decision", "ask".into()),
            ("profile", "local".into()),
        ])),
    );
    t.insert("rules".into(), toml::Value::Array(rules));
    toml::Value::Table(t)
}

/// The `jj` shim of §7.4. It runs `jj --no-pager -R {workspace}`, which the
/// broker expands to the sandbox workspace mount so jj uses that repository
/// whatever directory the caller is in. Options that name another
/// repository, add configuration or run a diff or merge tool are refused.
/// Reading commands run in `vcs.local` too, since jj snapshots the working
/// copy first, which writes to `.jj`.
fn jj_shim(fetch: Decision, push: Decision) -> toml::Value {
    let mut rules = Vec::new();
    rules.push(deny_flags_rule(&[
        "--config",
        "--config-file",
        "--config-toml",
        "-R",
        "--repository",
        "--tool",
        "-i",
        "--interactive",
    ]));
    rules.extend(rules_for(
        &[
            "status",
            "st",
            "diff",
            "log",
            "show",
            "evolog",
            "op log",
            "file show",
        ],
        "allow",
        Some("local"),
    ));
    rules.extend(rules_for(
        &[
            "squash",
            "rebase",
            "abandon",
            "restore",
            "undo",
            "bookmark *",
            "op *",
        ],
        "ask",
        Some("local"),
    ));
    rules.extend(remote_rules(&["git fetch", "git clone"], fetch));
    rules.extend(remote_rules(&["git push"], push));
    rules.push(deny_flags_rule(&[
        "-A",
        "--insert-after",
        "--after",
        "-B",
        "--insert-before",
        "--before",
    ]));
    rules.extend(rules_for(
        &["new", "commit", "ci", "describe", "desc"],
        "allow",
        Some("local"),
    ));
    shim("jj", &["--no-pager", "-R", "{workspace}"], rules)
}

/// The `git` shim of §7.4. It runs `git --no-pager`, and the profiles'
/// `GIT_DIR` and `GIT_WORK_TREE` name the repository. Options that add
/// configuration, run other programs, write files outside git's control or
/// name another repository are refused. `--exec` is `push`'s and
/// `ls-remote`'s other name for `--receive-pack` and `--upload-pack`, and
/// `--output` makes `diff`, `log` and their kin write to any path the
/// profile can write.
fn git_shim(fetch: Decision, push: Decision) -> toml::Value {
    let mut rules = Vec::new();
    rules.push(deny_flags_rule(&[
        "-c",
        "--config-env",
        "--exec-path",
        "--upload-pack",
        "--receive-pack",
        "--exec",
        "--output",
        "-C",
        "--git-dir",
        "--work-tree",
        "--namespace",
    ]));
    rules.extend(rules_for(
        &["status", "diff", "log", "show", "add", "commit"],
        "allow",
        Some("local"),
    ));
    rules.extend(rules_for(
        &[
            "reset", "rebase", "checkout", "switch", "branch", "tag", "clean", "stash",
        ],
        "ask",
        Some("local"),
    ));
    rules.extend(remote_rules(
        &["fetch", "pull", "ls-remote", "remote update"],
        fetch,
    ));
    rules.extend(remote_rules(&["push"], push));
    rules.push(deny_flags_rule(&["-u", "--template"]));
    rules.extend(remote_rules(&["clone"], fetch));
    shim("git", &["--no-pager"], rules)
}

impl Provider for VcsProvider {
    fn name(&self) -> &ProviderName {
        &self.name
    }

    fn manifest(&self, ctx: &ProviderContext) -> Result<ProviderOutput, ProviderError> {
        for what in self.unsupported_options() {
            eprintln!(
                "stopit: warning: {}",
                crate::escape::escape_message(&format!("provider \"{}\": {what}", self.name))
            );
        }
        let warn = |what: &str| {
            eprintln!(
                "stopit: warning: {}",
                crate::escape::escape_message(&format!(
                    "provider \"{}\" does not broker VCS commands for {what}, so they need the \
                     host",
                    self.name
                ))
            );
        };
        let mut layout = discover(&ctx.workspace);
        if layout.jj_supported
            && layout.jj_relative_repo
            && ctx.resolved_workspace_mount() != ctx.workspace
        {
            layout.jj_supported = false;
            layout.unsupported.push(format!(
                "the jj secondary workspace at {:?}, whose relative .jj/repo pointer needs \
                 `mount = \"host\"` in `[workspace]`",
                ctx.workspace
            ));
        }
        for what in &layout.unsupported {
            warn(what);
        }
        let identity = if layout.git_dirs.is_empty() && !layout.jj_supported {
            Vec::new()
        } else {
            host_identity()
        };
        let ssh = if layout.git_dirs.is_empty() && !layout.jj_supported {
            SshRemote::default()
        } else {
            SshRemote::discover(ctx)
        };
        let manifest = match self.manifest_for(
            &ctx.workspace,
            ctx.resolved_workspace_mount(),
            &layout,
            &identity,
            &ssh,
        ) {
            Ok(manifest) => manifest,
            // A path no rule can name: the metadata view alone.
            Err(why) => {
                warn(&why);
                self.main_view(&ctx.workspace, &layout)
                    .and_then(manifest_from)
                    .map_err(|reason| ProviderError::Vcs {
                        name: self.name.clone(),
                        reason,
                    })?
            }
        };
        Ok(ProviderOutput {
            profile: ProfileRef::main(),
            manifest,
            origin: self.origin,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::{Outcome, decide};
    use crate::manifest::{BindMode, ContributedProfile, PathPattern, ShimName};

    const MOUNT: &str = "/workspace";

    fn provider() -> VcsProvider {
        VcsProvider::builtin()
    }

    fn git_init(dir: &Path) {
        fs::create_dir_all(dir.join(".git/objects")).unwrap();
        fs::create_dir_all(dir.join(".git/hooks")).unwrap();
        fs::write(dir.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        fs::write(dir.join(".git/config"), "[core]\n").unwrap();
    }

    /// A canonical temporary workspace.
    fn workspace() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::TempDir::new().unwrap();
        let path = fs::canonicalize(dir.path()).unwrap();
        (dir, path)
    }

    fn manifest(ws: &Path, identity: &[(String, String)]) -> Manifest {
        provider()
            .manifest_for(
                ws,
                Path::new(MOUNT),
                &discover(ws),
                identity,
                &SshRemote::default(),
            )
            .unwrap()
    }

    fn patterns(list: &[PathPattern]) -> Vec<&str> {
        list.iter().map(PathPattern::as_str).collect()
    }

    fn profile<'a>(m: &'a Manifest, name: &str) -> &'a ContributedProfile {
        &m.profiles[&name.parse().unwrap()]
    }

    fn env<'a>(p: &'a ContributedProfile, key: &str) -> Option<&'a str> {
        p.grants
            .env
            .set
            .get(&key.parse().unwrap())
            .map(|v| v.as_str())
    }

    fn shim<'a>(m: &'a Manifest, name: &str) -> &'a crate::manifest::ShimSpec {
        &m.grants.shims[&name.parse::<ShimName>().unwrap()]
    }

    #[test]
    fn a_plain_repository_is_masked_in_main_and_writable_in_local() {
        let (_d, ws) = workspace();
        git_init(&ws);
        let layout = discover(&ws);
        assert_eq!(layout.git_dirs, [ws.join(".git")]);
        assert!(layout.unsupported.is_empty());
        let m = manifest(&ws, &[("user.name".into(), "Ann".into())]);
        assert_eq!(patterns(&m.grants.fs.masked), ["{workspace}/.git"]);
        assert!(m.grants.fs.ro.is_empty() && m.grants.fs.rw.is_empty());
        let local = profile(&m, "local");
        assert_eq!(patterns(&local.grants.fs.rw), ["{workspace}/.git"]);
        assert_eq!(patterns(&local.grants.fs.ro), ["{workspace}/.git/config"]);
        assert_eq!(
            patterns(&local.grants.fs.masked),
            ["{workspace}/.git/hooks"]
        );
        let ro = profile(&m, "ro");
        assert_eq!(patterns(&ro.grants.fs.ro), ["{workspace}/.git"]);
        let remote = profile(&m, "remote");
        assert_eq!(patterns(&remote.grants.fs.rw), ["{workspace}/.git"]);
        assert_eq!(patterns(&remote.grants.fs.ro), ["{workspace}/.git/config"]);
        assert_eq!(
            patterns(&remote.grants.fs.masked),
            ["{workspace}/.git/hooks"]
        );
        assert_eq!(
            remote.grants.network.mode,
            Some(crate::policy::NetworkMode::Full)
        );
        assert_eq!(
            env(remote, "GIT_SSH_COMMAND"),
            Some(
                "ssh -F /dev/null -o IdentityFile=/dev/null -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/dev/null"
            )
        );
        assert_eq!(env(remote, "SSH_AUTH_SOCK"), None);
        assert_eq!(
            patterns(&remote.grants.fs.ephemeral),
            [VCS_HOME, "/home/vcs/.ssh"]
        );
        for p in [ro, local] {
            assert_eq!(
                p.grants.network.mode,
                Some(crate::policy::NetworkMode::None)
            );
            assert_eq!(patterns(&p.grants.fs.ephemeral), [VCS_HOME]);
        }
        for p in [ro, local, remote] {
            assert_eq!(env(p, "GIT_DIR"), Some("/workspace/.git"));
            assert_eq!(env(p, "GIT_WORK_TREE"), Some("/workspace"));
            assert_eq!(env(p, "GIT_CONFIG_GLOBAL"), Some("/dev/null"));
            assert_eq!(env(p, "GIT_EDITOR"), Some("false"));
            assert_eq!(env(p, "GIT_PAGER"), Some("cat"));
            assert_eq!(env(p, "JJ_EDITOR"), Some("false"));
            assert_eq!(env(p, "JJ_USER"), Some("Ann"));
            // The safe settings, then the identity.
            assert_eq!(env(p, "GIT_CONFIG_COUNT"), Some("12"));
            assert_eq!(env(p, "GIT_CONFIG_KEY_4"), Some("safe.bareRepository"));
            assert_eq!(env(p, "GIT_CONFIG_KEY_5"), Some("gpg.program"));
            assert_eq!(env(p, "GIT_CONFIG_VALUE_5"), Some("false"));
            assert_eq!(env(p, "GIT_CONFIG_KEY_11"), Some("user.name"));
            assert_eq!(env(p, "GIT_CONFIG_VALUE_11"), Some("Ann"));
            // A home of their own, which `main` never sees.
            assert_eq!(
                p.grants.system.home.as_ref().map(|h| h.as_str()),
                Some(VCS_HOME)
            );
            assert_eq!(env(p, "GNUPGHOME"), Some("/home/vcs/.gnupg-unused"));
            assert_eq!(env(p, "XDG_CONFIG_HOME"), Some(VCS_XDG_CONFIG));
            // No `stopit-grant` in a VCS command.
            assert_eq!(p.grants.sandbox.grant, Some(false));
        }
        // No jj repository, no jj shim.
        assert_eq!(
            m.grants
                .shims
                .keys()
                .map(|k| k.as_str())
                .collect::<Vec<_>>(),
            ["git"]
        );
        let git = shim(&m, "git").cmd().unwrap();
        assert_eq!(
            git.args.iter().map(|a| a.as_str()).collect::<Vec<_>>(),
            ["--no-pager"]
        );
    }

    #[test]
    fn no_repository_contributes_nothing() {
        let (_d, ws) = workspace();
        assert_eq!(discover(&ws), Layout::default());
        assert_eq!(manifest(&ws, &[]), Manifest::default());
    }

    /// A worktree at `root/wt` of the repository at `root/main`.
    fn worktree(root: &Path) -> (PathBuf, PathBuf) {
        let main = root.join("main");
        git_init(&main);
        let admin = main.join(".git/worktrees/wt");
        fs::create_dir_all(&admin).unwrap();
        let wt = root.join("wt");
        fs::create_dir(&wt).unwrap();
        fs::write(wt.join(".git"), format!("gitdir: {}\n", admin.display())).unwrap();
        fs::write(admin.join("commondir"), "../..\n").unwrap();
        fs::write(
            admin.join("gitdir"),
            format!("{}\n", wt.join(".git").display()),
        )
        .unwrap();
        (wt, admin)
    }

    #[test]
    fn a_worktree_must_be_named_back_by_its_admin_directory() {
        let (_d, root) = workspace();
        let (wt, admin) = worktree(&root);
        let layout = discover(&wt);
        assert!(layout.unsupported.is_empty(), "{:?}", layout.unsupported);
        assert_eq!(layout.git_dirs, [admin.clone(), root.join("main/.git")]);
        // GIT_DIR is the admin directory, at its own path, and `main`
        // gets both directories masked too.
        let m = manifest(&wt, &[]);
        assert_eq!(
            patterns(&m.grants.fs.masked),
            [
                "{workspace}/.git",
                admin.to_str().unwrap(),
                root.join("main/.git").to_str().unwrap()
            ]
        );
        assert_eq!(
            env(profile(&m, "local"), "GIT_DIR"),
            Some(admin.to_str().unwrap())
        );
        // A `.git` file pointing at a directory that does not name it back,
        // as a sandbox could write, gets no grant.
        let elsewhere = root.join("secret");
        fs::create_dir(&elsewhere).unwrap();
        fs::write(
            wt.join(".git"),
            format!("gitdir: {}\n", elsewhere.display()),
        )
        .unwrap();
        let layout = discover(&wt);
        assert!(layout.git_dirs.is_empty());
        assert_eq!(layout.dot_git, Some(wt.join(".git")));
        assert_eq!(layout.unsupported.len(), 1, "{:?}", layout.unsupported);
        // Nor one whose admin directory names it but sits elsewhere.
        fs::write(
            elsewhere.join("gitdir"),
            format!("{}\n", wt.join(".git").display()),
        )
        .unwrap();
        fs::write(elsewhere.join("commondir"), "..\n").unwrap();
        assert!(discover(&wt).git_dirs.is_empty());
        let m = manifest(&wt, &[]);
        assert!(m.profiles.is_empty() && m.grants.shims.is_empty());
        assert_eq!(patterns(&m.grants.fs.masked), ["{workspace}/.git"]);
    }

    #[test]
    fn a_worktree_made_inside_the_workspace_is_refused() {
        // Everything below the workspace, as `main` could write it.
        let (_d, ws) = workspace();
        let common = ws.join("evil");
        fs::create_dir_all(common.join("objects")).unwrap();
        fs::write(common.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        fs::write(common.join("config"), "[filter \"x\"]\n\tclean = sh\n").unwrap();
        let admin = common.join("worktrees/x");
        fs::create_dir_all(&admin).unwrap();
        fs::write(admin.join("commondir"), "../..\n").unwrap();
        fs::write(
            admin.join("gitdir"),
            format!("{}\n", ws.join(".git").display()),
        )
        .unwrap();
        fs::write(ws.join(".git"), format!("gitdir: {}\n", admin.display())).unwrap();
        let layout = discover(&ws);
        assert!(layout.git_dirs.is_empty());
        assert!(
            layout.unsupported[0].contains("inside the workspace"),
            "{:?}",
            layout.unsupported
        );
    }

    #[test]
    fn a_git_directory_sharing_another_is_refused() {
        let (_d, ws) = workspace();
        git_init(&ws);
        fs::write(ws.join(".git/commondir"), "/elsewhere\n").unwrap();
        let layout = discover(&ws);
        assert!(layout.git_dirs.is_empty());
        assert!(
            layout.unsupported[0].contains("commondir"),
            "{:?}",
            layout.unsupported
        );
        // Masked all the same.
        assert_eq!(
            patterns(&manifest(&ws, &[]).grants.fs.masked),
            ["{workspace}/.git"]
        );
    }

    #[test]
    fn pointer_files_are_read_only_when_small_and_regular() {
        let (_d, root) = workspace();
        let file = root.join("f");
        fs::write(&file, "gitdir: x\n").unwrap();
        assert_eq!(read_small(&file).unwrap(), "gitdir: x\n");
        // Too big.
        fs::write(&file, "x".repeat(4097)).unwrap();
        assert!(read_small(&file).is_err());
        // A link, even to a fine file.
        fs::write(root.join("target"), "gitdir: x\n").unwrap();
        std::os::unix::fs::symlink(root.join("target"), root.join("link")).unwrap();
        assert!(read_small(&root.join("link")).is_err());
        // A FIFO no one writes, which must not hang.
        let fifo = root.join("fifo");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();
        assert!(read_small(&fifo).is_err());
        // A device that never ends.
        assert!(read_small(Path::new("/dev/zero")).is_err());
    }

    #[test]
    fn jj_repositories_and_secondary_workspaces() {
        let (_d, ws) = workspace();
        fs::create_dir_all(ws.join(".jj/repo/store")).unwrap();
        git_init(&ws);
        // Colocated: the store names the workspace's `.git`.
        fs::write(ws.join(".jj/repo/store/git_target"), "../../../.git").unwrap();
        let layout = discover(&ws);
        assert!(layout.jj_supported, "{:?}", layout.unsupported);
        let m = manifest(&ws, &[]);
        assert_eq!(
            m.grants
                .shims
                .keys()
                .map(|k| k.as_str())
                .collect::<Vec<_>>(),
            ["git", "jj"]
        );
        assert_eq!(
            patterns(&m.grants.fs.masked),
            ["{workspace}/.git", "{workspace}/.jj"]
        );
        let jj = shim(&m, "jj").cmd().unwrap();
        assert_eq!(
            jj.args.iter().map(|a| a.as_str()).collect::<Vec<_>>(),
            ["--no-pager", "-R", "{workspace}"]
        );
        assert_eq!(jj.args[2].expand(Path::new(MOUNT)), MOUNT);
        // A git store inside the jj store is fine too.
        fs::create_dir_all(ws.join(".jj/repo/store/git")).unwrap();
        fs::write(ws.join(".jj/repo/store/git_target"), "git").unwrap();
        assert!(discover(&ws).jj_supported);
        // One elsewhere is not.
        let (_e, other_git) = workspace();
        fs::write(
            ws.join(".jj/repo/store/git_target"),
            other_git.to_str().unwrap(),
        )
        .unwrap();
        let layout = discover(&ws);
        assert!(!layout.jj_supported);
        assert!(
            layout.unsupported[0].contains("elsewhere"),
            "{:?}",
            layout.unsupported
        );
        // A store that is a link is not followed.
        fs::write(ws.join(".jj/repo/store/git_target"), "../../../.git").unwrap();
        fs::rename(ws.join(".jj/repo/store"), ws.join("real-store")).unwrap();
        std::os::unix::fs::symlink(ws.join("real-store"), ws.join(".jj/repo/store")).unwrap();
        assert!(!discover(&ws).jj_supported);
        fs::remove_file(ws.join(".jj/repo/store")).unwrap();
        fs::rename(ws.join("real-store"), ws.join(".jj/repo/store")).unwrap();
        assert!(discover(&ws).jj_supported);
        // Colocated with a `.git` git is not brokered for: jj would write it
        // with nothing locked, so jj is not brokered either.
        fs::write(ws.join(".git/commondir"), "/elsewhere\n").unwrap();
        let layout = discover(&ws);
        assert!(!layout.jj_supported && layout.git_dirs.is_empty());
        assert_eq!(layout.unsupported.len(), 2, "{:?}", layout.unsupported);
        let m = manifest(&ws, &[]);
        assert!(m.profiles.is_empty() && m.grants.shims.is_empty());
        // A secondary workspace pointing to a non-existent repo: masked,
        // nothing brokered.
        let (_o, other) = workspace();
        fs::create_dir_all(other.join(".jj")).unwrap();
        fs::write(other.join(".jj/repo"), "/somewhere/.jj/repo").unwrap();
        let layout = discover(&other);
        assert!(!layout.jj_supported);
        assert_eq!(layout.unsupported.len(), 1);
        let m = manifest(&other, &[]);
        assert!(m.grants.shims.is_empty());
        assert!(m.profiles.is_empty());
        assert_eq!(patterns(&m.grants.fs.masked), ["{workspace}/.jj"]);
    }

    fn encode_workspace_store_index(entries: &[(&str, &str)]) -> Vec<u8> {
        let push_varint = |buf: &mut Vec<u8>, mut v: usize| {
            while v >= 0x80 {
                buf.push((v as u8 & 0x7f) | 0x80);
                v >>= 7;
            }
            buf.push(v as u8);
        };
        let push_bytes = |buf: &mut Vec<u8>, tag: u8, bytes: &[u8]| {
            buf.push(tag);
            push_varint(buf, bytes.len());
            buf.extend_from_slice(bytes);
        };
        let mut out = Vec::new();
        for (name, path) in entries {
            let mut entry = Vec::new();
            push_bytes(&mut entry, 0x0a, name.as_bytes());
            push_bytes(&mut entry, 0x12, path.as_bytes());
            push_bytes(&mut out, 0x0a, &entry);
        }
        out
    }

    #[test]
    fn jj_secondary_workspace_requires_back_pointer_and_brokers_primary_storage() {
        let (_d, root) = workspace();
        let primary = root.join("primary");
        let secondary = root.join("secondary");
        let repo_dir = primary.join(".jj/repo");
        fs::create_dir_all(repo_dir.join("store/git")).unwrap();
        fs::create_dir_all(repo_dir.join("workspace_store")).unwrap();
        fs::write(repo_dir.join("store/git_target"), "git").unwrap();
        fs::write(repo_dir.join("config.toml"), "[user]\n").unwrap();
        fs::write(
            repo_dir.join("workspace_store/index"),
            encode_workspace_store_index(&[
                ("default", "../.."),
                ("secondary", "../../../secondary"),
            ]),
        )
        .unwrap();
        fs::create_dir_all(secondary.join(".jj")).unwrap();
        // Relative pointer (`../../primary/.jj/repo`), as `jj workspace add` writes.
        fs::write(secondary.join(".jj/repo"), "../../primary/.jj/repo").unwrap();

        let layout = discover(&secondary);
        assert!(layout.jj_supported, "{:?}", layout.unsupported);
        assert!(layout.jj_relative_repo);
        assert_eq!(layout.jj_dirs, vec![repo_dir.clone()]);

        // With `mount != workspace` (`/workspace`), a relative `.jj/repo` pointer
        // cannot resolve inside `/workspace`, so `jj` is not brokered unless
        // `mount = "host"` (`mount == workspace`) or `.jj/repo` is absolute.
        let m_rel_default_mount = manifest(&secondary, &[]);
        assert!(m_rel_default_mount.grants.shims.is_empty());
        assert_eq!(
            patterns(&m_rel_default_mount.grants.fs.masked),
            ["{workspace}/.jj", repo_dir.to_str().unwrap()]
        );

        // With `mount == workspace` (`mount = "host"`), the relative pointer works.
        let m_host_mount = provider()
            .manifest_for(
                &secondary,
                &secondary,
                &layout,
                &[],
                &SshRemote::default(),
            )
            .unwrap();
        assert_eq!(
            m_host_mount
                .grants
                .shims
                .keys()
                .map(|k| k.as_str())
                .collect::<Vec<_>>(),
            ["jj"]
        );
        let local = profile(&m_host_mount, "local");
        assert_eq!(
            patterns(&local.grants.fs.rw),
            ["{workspace}/.jj", repo_dir.to_str().unwrap()]
        );
        assert_eq!(
            patterns(&local.grants.fs.ro),
            [
                "{workspace}/.jj/repo",
                repo_dir.join("config.toml").to_str().unwrap(),
                repo_dir.join("store/git_target").to_str().unwrap(),
            ]
        );

        // A `.jj/repo` path that traverses a workspace subdirectory (`../sub/../../primary/.jj/repo`)
        // or a symlink inside the workspace is refused so `main` cannot swap it at runtime.
        fs::create_dir_all(secondary.join("sub")).unwrap();
        fs::write(
            secondary.join(".jj/repo"),
            "../sub/../../primary/.jj/repo",
        )
        .unwrap();
        let layout_traversal = discover(&secondary);
        assert!(!layout_traversal.jj_supported);
        assert!(
            layout_traversal.unsupported[0].contains("contains `..` after a path component"),
            "{:?}",
            layout_traversal.unsupported
        );
        std::os::unix::fs::symlink(&repo_dir, secondary.join("repo-link")).unwrap();
        fs::write(
            secondary.join(".jj/repo"),
            secondary.join("repo-link").to_str().unwrap(),
        )
        .unwrap();
        let layout_link = discover(&secondary);
        assert!(!layout_link.jj_supported);
        assert!(
            layout_link.unsupported[0].contains("traverses a symlink inside the workspace"),
            "{:?}",
            layout_link.unsupported
        );

        // With an absolute path in `.jj/repo`, even `mount = "/workspace"` works.
        fs::write(secondary.join(".jj/repo"), repo_dir.to_str().unwrap()).unwrap();
        let layout_abs = discover(&secondary);
        assert!(layout_abs.jj_supported);
        assert!(!layout_abs.jj_relative_repo);
        let m_abs = manifest(&secondary, &[]);
        assert_eq!(
            m_abs
                .grants
                .shims
                .keys()
                .map(|k| k.as_str())
                .collect::<Vec<_>>(),
            ["jj"]
        );

        // Colocated primary repository: `.jj/repo/store/git_target` points to
        // `primary/.git`, so its config and hooks are locked/masked too.
        git_init(&primary);
        fs::write(repo_dir.join("store/git_target"), "../../../.git").unwrap();
        let layout_colocated = discover(&secondary);
        assert!(
            layout_colocated.jj_supported,
            "{:?}",
            layout_colocated.unsupported
        );
        assert_eq!(
            layout_colocated.jj_dirs,
            vec![repo_dir.clone(), primary.join(".git")]
        );
        let m_colocated = manifest(&secondary, &[]);
        let local_colocated = profile(&m_colocated, "local");
        assert_eq!(
            patterns(&local_colocated.grants.fs.rw),
            [
                "{workspace}/.jj",
                repo_dir.to_str().unwrap(),
                primary.join(".git").to_str().unwrap()
            ]
        );
        assert_eq!(
            patterns(&local_colocated.grants.fs.ro),
            [
                primary.join(".git/config").to_str().unwrap(),
                "{workspace}/.jj/repo",
                repo_dir.join("config.toml").to_str().unwrap(),
                repo_dir.join("store/git_target").to_str().unwrap(),
            ]
        );
        assert_eq!(
            patterns(&local_colocated.grants.fs.masked),
            [primary.join(".git/hooks").to_str().unwrap()]
        );

        // If `workspace_store/index` does not name `secondary` back, it is refused.
        fs::write(
            repo_dir.join("workspace_store/index"),
            encode_workspace_store_index(&[("default", "../..")]),
        )
        .unwrap();
        let layout_unlisted = discover(&secondary);
        assert!(!layout_unlisted.jj_supported);
        assert!(
            layout_unlisted.unsupported[0].contains("does not name this workspace back"),
            "{:?}",
            layout_unlisted.unsupported
        );
    }

    #[test]
    fn a_workspace_below_a_checkout_root_is_reported() {
        let (_d, root) = workspace();
        git_init(&root);
        let sub = root.join("sub");
        fs::create_dir(&sub).unwrap();
        let layout = discover(&sub);
        assert!(layout.dot_git.is_none() && layout.git_dirs.is_empty());
        assert_eq!(layout.unsupported.len(), 1);
    }

    #[test]
    fn rule_paths_stay_below_the_workspace_or_absolute_and_plain() {
        let ws = Path::new("/w");
        assert_eq!(
            rule_path(ws, Path::new("/w/.git")).unwrap(),
            "{workspace}/.git"
        );
        assert_eq!(
            rule_path(ws, Path::new("/elsewhere/.git")).unwrap(),
            "/elsewhere/.git"
        );
        assert_eq!(rule_path(ws, Path::new("/w/a*b")), None);
        assert_eq!(rule_path(ws, Path::new("/x/{y}")), None);
    }

    #[test]
    fn a_git_directory_no_rule_can_name_falls_back_to_the_mask() {
        let (_d, root) = workspace();
        let (wt, _) = worktree(&root);
        // Move the main repository somewhere a rule cannot name.
        let odd = root.join("ma[in]");
        fs::rename(root.join("main"), &odd).unwrap();
        let admin = odd.join(".git/worktrees/wt");
        fs::write(wt.join(".git"), format!("gitdir: {}\n", admin.display())).unwrap();
        let layout = discover(&wt);
        assert_eq!(layout.git_dirs.len(), 2, "{:?}", layout.unsupported);
        let e = provider()
            .manifest_for(&wt, Path::new(MOUNT), &layout, &[], &SshRemote::default())
            .unwrap_err();
        assert!(e.contains("no rule can name it"), "{e}");
        let fallback = provider()
            .main_view(&wt, &layout)
            .and_then(manifest_from)
            .unwrap();
        assert_eq!(patterns(&fallback.grants.fs.masked), ["{workspace}/.git"]);
        assert!(fallback.profiles.is_empty());
    }

    #[test]
    fn view_ro_shows_the_metadata_in_main() {
        let (_d, ws) = workspace();
        git_init(&ws);
        let p = VcsProvider {
            view: VcsView::Ro,
            ..provider()
        };
        let m = p
            .manifest_for(&ws, Path::new(MOUNT), &discover(&ws), &[], &SshRemote::default())
            .unwrap();
        assert_eq!(patterns(&m.grants.fs.ro), ["{workspace}/.git"]);
        assert!(m.grants.fs.masked.is_empty());
    }

    #[test]
    fn options_without_effect_yet_are_warned_about() {
        assert!(provider().unsupported_options().is_empty());
        let p = VcsProvider {
            fetch: Decision::Allow,
            push: Decision::Deny,
            ..provider()
        }
        .with_signing(true);
        let warnings = p.unsupported_options();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].starts_with("signing = true"), "{warnings:?}");
    }

    #[test]
    fn vcs_remote_binds_ssh_agent_and_known_hosts_read_only_and_is_omitted_when_denied() {
        let (_d, ws) = workspace();
        git_init(&ws);
        let ssh = SshRemote {
            auth_sock: Some(PathBuf::from("/run/user/1000/ssh-agent.sock")),
            known_hosts: Some(PathBuf::from("/home/user/.ssh/known_hosts")),
        };
        let m = provider()
            .manifest_for(&ws, Path::new(MOUNT), &discover(&ws), &[], &ssh)
            .unwrap();
        let remote = profile(&m, "remote");
        assert_eq!(
            env(remote, "SSH_AUTH_SOCK"),
            Some("/home/vcs/.ssh/agent.sock")
        );
        assert_eq!(
            env(remote, "GIT_SSH_COMMAND"),
            Some(
                "ssh -F /dev/null -o IdentityFile=/dev/null -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/home/vcs/.ssh/known_hosts"
            )
        );
        assert_eq!(
            patterns(&remote.grants.fs.ephemeral),
            ["/home/vcs", "/home/vcs/.ssh"]
        );
        let binds: Vec<(&str, &str, BindMode)> = remote
            .grants
            .fs
            .bind
            .iter()
            .map(|b| (b.host.as_str(), b.sandbox.as_str(), b.mode))
            .collect();
        assert_eq!(
            binds,
            vec![
                (
                    "/run/user/1000/ssh-agent.sock",
                    "/home/vcs/.ssh/agent.sock",
                    BindMode::Ro
                ),
                (
                    "/home/user/.ssh/known_hosts",
                    "/home/vcs/.ssh/known_hosts",
                    BindMode::Ro
                ),
            ]
        );
        // Neither `ro` nor `local` sees `SSH_AUTH_SOCK` or `GIT_SSH_COMMAND`.
        for name in ["ro", "local"] {
            let p = profile(&m, name);
            assert_eq!(env(p, "SSH_AUTH_SOCK"), None);
            assert_eq!(env(p, "GIT_SSH_COMMAND"), None);
            assert!(p.grants.fs.bind.is_empty());
        }
        // When both `fetch` and `push` are `deny`, `vcs.remote` is not created.
        let denied = VcsProvider {
            fetch: Decision::Deny,
            push: Decision::Deny,
            ..provider()
        };
        let m_denied = denied
            .manifest_for(&ws, Path::new(MOUNT), &discover(&ws), &[], &ssh)
            .unwrap();
        assert!(!m_denied.profiles.contains_key(&"remote".parse().unwrap()));
    }

    #[test]
    fn ssh_remote_discover_checks_socket_and_known_hosts_and_refuses_workspace_links() {
        use std::os::unix::net::UnixListener;

        let (_d, root) = workspace();
        let ws = root.join("ws");
        let home = root.join("home");
        let session = root.join("runtime/stopit/s1");
        fs::create_dir_all(&ws).unwrap();
        fs::create_dir_all(home.join(".ssh")).unwrap();
        fs::create_dir_all(&session).unwrap();

        let sock_path = root.join("agent.sock");
        let _listener = UnixListener::bind(&sock_path).unwrap();
        let kh_path = home.join(".ssh/known_hosts");
        fs::write(&kh_path, "github.com ssh-ed25519 AAAA\n").unwrap();

        let ctx = ProviderContext {
            workspace: ws.clone(),
            workspace_mount: MOUNT.parse().unwrap(),
            home: home.clone(),
            session_dir: session.clone(),
            rw_grants: Vec::new(),
        };
        let discovered = SshRemote::discover_with_sock(&ctx, Some(&sock_path));
        assert_eq!(discovered.auth_sock.as_deref(), Some(sock_path.as_path()));
        assert_eq!(discovered.known_hosts.as_deref(), Some(kh_path.as_path()));

        // A symlink inside the workspace pointing to the real socket is refused.
        let ws_link = ws.join("planted.sock");
        std::os::unix::fs::symlink(&sock_path, &ws_link).unwrap();
        let via_ws_link = SshRemote::discover_with_sock(&ctx, Some(&ws_link));
        assert_eq!(via_ws_link.auth_sock, None);

        // A socket inside the stopit runtime directory is refused.
        let rt_sock = session.join("broker.sock");
        let _rt_listener = UnixListener::bind(&rt_sock).unwrap();
        let via_rt = SshRemote::discover_with_sock(&ctx, Some(&rt_sock));
        assert_eq!(via_rt.auth_sock, None);
    }

    #[test]
    fn the_shims_route_remote_commands_to_vcs_remote_and_refuse_unsafe_flags() {
        let (_d, ws) = workspace();
        fs::create_dir_all(ws.join(".jj/repo/store")).unwrap();
        git_init(&ws);
        let m = manifest(&ws, &[]);
        let run = |name: &str, line: &str| {
            let args: Vec<Vec<u8>> = line.split(' ').map(|a| a.as_bytes().to_vec()).collect();
            decide(shim(&m, name), &args).0
        };
        let local = || "local".parse::<ProfileRef>().unwrap();
        let remote = || "remote".parse::<ProfileRef>().unwrap();
        assert_eq!(run("git", "status"), Outcome::Allow(local()));
        assert_eq!(run("git", "commit -m x"), Outcome::Allow(local()));
        assert_eq!(run("git", "reset --hard"), Outcome::Ask(local()));
        assert_eq!(run("jj", "log -r @"), Outcome::Allow(local()));
        assert_eq!(run("jj", "describe -m x"), Outcome::Allow(local()));
        assert_eq!(run("jj", "abandon"), Outcome::Ask(local()));
        // Unknown subcommands, and known ones after a flag, ask in `local` (offline).
        assert_eq!(run("git", "gc"), Outcome::Ask(local()));
        assert_eq!(run("git", "--no-pager push"), Outcome::Ask(local()));
        // Remote commands default to `ask` in `remote`.
        for (name, line) in [
            ("git", "push origin main"),
            ("git", "fetch"),
            ("git", "pull --rebase"),
            ("git", "remote update"),
            ("git", "clone https://example.com/r.git"),
            ("jj", "git push"),
            ("jj", "git fetch"),
            ("jj", "git clone https://example.com/r.git"),
        ] {
            assert_eq!(run(name, line), Outcome::Ask(remote()), "{name} {line}");
        }
        // With `fetch = "allow"` and `push = "deny"`, fetch allows in `remote`
        // and push is denied.
        let p = VcsProvider {
            fetch: Decision::Allow,
            push: Decision::Deny,
            ..provider()
        };
        let m_custom = p
            .manifest_for(
                &ws,
                Path::new(MOUNT),
                &discover(&ws),
                &[],
                &SshRemote::default(),
            )
            .unwrap();
        let run_custom = |name: &str, line: &str| {
            let args: Vec<Vec<u8>> = line.split(' ').map(|a| a.as_bytes().to_vec()).collect();
            decide(shim(&m_custom, name), &args).0
        };
        assert_eq!(run_custom("git", "fetch"), Outcome::Allow(remote()));
        assert_eq!(run_custom("jj", "git fetch"), Outcome::Allow(remote()));
        assert!(matches!(run_custom("git", "push origin main"), Outcome::Deny(_)));
        assert!(matches!(run_custom("jj", "git push"), Outcome::Deny(_)));
        assert_eq!(run("git", "status -u"), Outcome::Allow(local()));
        assert_eq!(run("git", "add -u"), Outcome::Allow(local()));
        assert_eq!(run("git", "push -u origin main"), Outcome::Ask(remote()));
        for (name, line) in [
            ("git", "ls-remote --exec=/bin/sh origin"),
            ("git", "clone -u /bin/sh https://example.com/r.git"),
            ("git", "clone --template=/tmp/t https://example.com/r.git"),
            ("git", "log --output=.git/hooks/pre-commit"),
            ("git", "-c core.pager=sh status"),
            ("git", "status -ck=v"),
            ("git", "-C /elsewhere status"),
            ("git", "-C/elsewhere status"),
            ("git", "--git-dir=/elsewhere status"),
            ("git", "status --upl=x"),
            ("jj", "--config ui.pager=sh log"),
            ("jj", "-R /elsewhere log"),
            ("jj", "status -R/elsewhere"),
            ("jj", "new -A @"),
            ("jj", "new -Amain"),
            ("jj", "diff --tool=sh"),
            ("jj", "commit -i"),
            ("jj", "squash --interactive"),
        ] {
            assert!(matches!(run(name, line), Outcome::Deny(_)), "{name} {line}");
        }
    }

    #[test]
    fn non_utf8_workspace_mount_brokers_pure_jj_and_warns_grammatically_for_git() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let non_utf8_mount = Path::new(OsStr::from_bytes(b"/home/u/\xff"));
        let (_d, jj_ws) = workspace();
        fs::create_dir_all(jj_ws.join(".jj/repo/store")).unwrap();
        let m = provider()
            .manifest_for(
                &jj_ws,
                non_utf8_mount,
                &discover(&jj_ws),
                &[],
                &SshRemote::default(),
            )
            .unwrap();
        assert_eq!(
            shim(&m, "jj").cmd().unwrap().args[2].expand(non_utf8_mount),
            non_utf8_mount.as_os_str()
        );

        let (_d2, git_ws) = workspace();
        git_init(&git_ws);
        let err = provider()
            .manifest_for(
                &git_ws,
                non_utf8_mount,
                &discover(&git_ws),
                &[],
                &SshRemote::default(),
            )
            .unwrap_err();
        assert!(err.contains("whose sandbox path is not UTF-8"), "{err}");
    }
}
