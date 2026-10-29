//! The built-in `vcs` provider (DESIGN.md §7.3): keeps a sandbox's hands
//! off the repository's metadata, and brokers `jj` and `git` instead.
//!
//! At session start it finds the workspace's repository layout on the host
//! ([`discover`]), reading only files it validates, never running a VCS
//! tool on the workspace. It then contributes:
//!
//! * to `main`, a mask (or, with `view = "ro"`, a read-only view) of the
//!   workspace's `.git` and `.jj`;
//! * the profiles `ro` and `local`, which appear as `vcs.ro` and
//!   `vcs.local`: the metadata and its backing storage read-only, or
//!   writable with the git config files and `.jj/repo/config.toml` that
//!   exist at session start read-only and the hooks directories that exist
//!   then masked. Both are offline. git gets no system or user
//!   configuration, no hooks, filesystem monitor, pager or editor, and the
//!   repository found here rather than one found from the caller's
//!   directory. jj gets no user configuration, editor or pager;
//! * the shims `jj` and `git` (per `tools`), with the policy of §7.4 written
//!   as declarative rules. Remote commands are denied for now, so fetch and
//!   push happen on the host.
//!
//! Layouts it supports: a plain `.git` directory, a `.jj` directory with or
//! without a colocated `.git`, and a git worktree whose `.git` file names
//! an admin directory outside the workspace that names it back. Other
//! layouts get the mask but no VCS profiles, with a warning.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::{Provider, ProviderContext, ProviderError, ProviderOutput};
use crate::config::{ProfileRef, ProviderName, ProviderOrigin, VcsTool, VcsView};
use crate::manifest::Manifest;
use crate::policy::Decision;

/// The name of the built-in `vcs` provider of `base = "default"`.
pub const VCS_PROVIDER_NAME: &str = "vcs";

/// The git configuration every brokered git command gets, over any file:
/// no hooks, no filesystem monitor, no pager, no `ext::` transport, and no
/// bare repository git was not pointed at. Other keys of the repository's
/// own configuration still apply.
const SAFE_GIT_CONFIG: [(&str, &str); 5] = [
    ("core.hooksPath", "/dev/null"),
    ("core.fsmonitor", "false"),
    ("core.pager", "cat"),
    ("protocol.ext.allow", "never"),
    ("safe.bareRepository", "explicit"),
];

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
        for (option, setting) in [("fetch", self.fetch), ("push", self.push)] {
            if setting == Decision::Allow {
                out.push(format!(
                    "{option} = \"allow\" has no effect yet. Remote commands are refused, so \
                     run them on the host"
                ));
            }
        }
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
    /// Whether the `.jj` directory is a whole repository the provider
    /// supports, not a secondary workspace.
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
                Ok(()) => layout.jj_supported = true,
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

/// Checks that the `.jj` directory `dot_jj` holds a whole repository: a
/// `repo` directory, whose git store, if it has one, is the workspace's
/// own `.git` or inside the store.
fn jj_repo(workspace: &Path, dot_jj: &Path) -> Result<(), String> {
    let repo = dot_jj.join("repo");
    match fs::symlink_metadata(&repo) {
        Ok(m) if m.is_dir() => {}
        Ok(_) => {
            return Err(format!(
                "the jj secondary workspace at {workspace:?}, whose repository lives elsewhere"
            ));
        }
        Err(_) => return Err(format!("{dot_jj:?}, which has no repo directory")),
    }
    let store = repo.join("store");
    let target_file = store.join("git_target");
    if !is_present(&target_file) {
        return Ok(());
    }
    let target = read_small(&target_file).map_err(|why| format!("the jj repository: {why}"))?;
    let resolved = fs::canonicalize(store.join(target.trim_end()))
        .map_err(|e| format!("the jj repository's git store cannot be resolved: {e}"))?;
    let store = fs::canonicalize(&store).map_err(|e| e.to_string())?;
    let own_git = fs::canonicalize(workspace.join(".git")).ok();
    if Some(&resolved) == own_git.as_ref() || resolved.starts_with(&store) {
        Ok(())
    } else {
        Err(format!(
            "the jj repository at {workspace:?}, whose git store {resolved:?} is elsewhere"
        ))
    }
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

/// The text of the small regular file at `path`, opened without following
/// a link and without waiting on a FIFO.
fn read_small(path: &Path) -> Result<String, String> {
    use rustix::fs::{FileType, Mode, OFlags};
    use std::io::Read;
    let cannot = |e: &dyn std::fmt::Display| format!("cannot read {path:?}: {e}");
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| cannot(&e))?;
    let stat = rustix::fs::fstat(&fd).map_err(|e| cannot(&e))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile || stat.st_size > 4096 {
        return Err(format!("{path:?} is not a small file"));
    }
    let mut text = String::new();
    fs::File::from(fd)
        .take(4097)
        .read_to_string(&mut text)
        .map_err(|e| cannot(&e))?;
    if text.len() > 4096 {
        return Err(format!("{path:?} is not a small file"));
    }
    Ok(text)
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
    /// `mount`, with `identity` for git and jj. An error names a path no
    /// rule can hold.
    pub fn manifest_for(
        &self,
        workspace: &Path,
        mount: &Path,
        layout: &Layout,
        identity: &[(String, String)],
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
        let jj = layout.jj_supported;
        if !git && !jj {
            return manifest_from(root);
        }
        let metadata: Vec<String> = [&layout.dot_git, &layout.dot_jj]
            .into_iter()
            .flatten()
            .map(|p| path(p))
            .collect::<Result<_, _>>()?;
        // What the VCS profiles see: the metadata and the backing storage.
        let mut storage = metadata.clone();
        for dir in &layout.git_dirs {
            let p = path(dir)?;
            if !storage.contains(&p) {
                storage.push(p);
            }
        }
        let mut locked = Vec::new();
        let mut hooks = Vec::new();
        for dir in &layout.git_dirs {
            for file in ["config", "config.worktree", "info/attributes"] {
                if is_present(&dir.join(file)) {
                    locked.push(path(&dir.join(file))?);
                }
            }
            if is_real_dir(&dir.join("modules")) {
                locked.push(format!("{}/modules/*/config", path(dir)?));
                hooks.push(format!("{}/modules/*/hooks", path(dir)?));
            }
            if is_real_dir(&dir.join("worktrees")) {
                locked.push(format!("{}/worktrees/*/config.worktree", path(dir)?));
            }
            if is_present(&dir.join("hooks")) {
                hooks.push(path(&dir.join("hooks"))?);
            }
        }
        if let Some(dot_jj) = &layout.dot_jj {
            let config = dot_jj.join("repo/config.toml");
            if is_present(&config) {
                locked.push(path(&config)?);
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
            set(
                "GIT_DIR",
                in_sandbox(git_dir).to_string_lossy().into_owned(),
            );
            set("GIT_WORK_TREE", mount.to_string_lossy().into_owned());
        }
        // No editor or pager, which would hand the caller's terminal a
        // program that runs commands.
        set("GIT_EDITOR", "false".into());
        set("GIT_SEQUENCE_EDITOR", "false".into());
        set("GIT_PAGER", "cat".into());
        set("JJ_CONFIG", "/dev/null".into());
        set("JJ_EDITOR", "false".into());
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
        // Remote commands are refused by the shims' rules, and the
        // profiles have no network either, so a call the rules miss
        // (`git --no-pager push` takes the default) still reaches no remote
        // over the network.
        let offline = || Value::Table(table([("mode", "none".into())]));
        let mut ro = toml::Table::new();
        ro.insert("network".into(), offline());
        ro.insert(
            "fs".into(),
            Value::Table(table([("ro", list(storage.clone()))])),
        );
        ro.insert(
            "env".into(),
            Value::Table(table([("set", Value::Table(env.clone()))])),
        );
        profiles.insert("ro".into(), Value::Table(ro));
        let mut local_fs = table([("rw", list(storage))]);
        if !locked.is_empty() {
            local_fs.insert("ro".into(), list(locked));
        }
        if !hooks.is_empty() {
            local_fs.insert("masked".into(), list(hooks));
        }
        let mut local = toml::Table::new();
        local.insert("network".into(), offline());
        local.insert("fs".into(), Value::Table(local_fs));
        local.insert(
            "env".into(),
            Value::Table(table([("set", Value::Table(env))])),
        );
        profiles.insert("local".into(), Value::Table(local));
        root.insert("profiles".into(), Value::Table(profiles));
        let mut shims = toml::Table::new();
        let mount_text = mount
            .to_str()
            .ok_or_else(|| format!("the workspace mount {mount:?} is not UTF-8"))?;
        for tool in &self.tools {
            let shim = match tool {
                VcsTool::Jj if jj => jj_shim(mount_text),
                VcsTool::Git if git => git_shim(),
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
    fn main_view(&self, workspace: &Path, layout: &Layout) -> Result<toml::Table, String> {
        let metadata: Vec<toml::Value> = [&layout.dot_git, &layout.dot_jj]
            .into_iter()
            .flatten()
            .map(|p| {
                rule_path(workspace, p)
                    .map(toml::Value::String)
                    .ok_or_else(|| format!("no rule can name {p:?}"))
            })
            .collect::<Result<_, _>>()?;
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

/// A shim rule as TOML.
fn rule(subcommands: &[&str], decision: &str, profile: Option<&str>, deny: &[&str]) -> toml::Value {
    let mut t = toml::Table::new();
    t.insert(
        "subcommand".into(),
        toml::Value::Array(subcommands.iter().map(|s| (*s).into()).collect()),
    );
    t.insert("decision".into(), decision.into());
    if let Some(p) = profile {
        t.insert("profile".into(), p.into());
    }
    if !deny.is_empty() {
        t.insert(
            "deny_flags".into(),
            toml::Value::Array(deny.iter().map(|s| (*s).into()).collect()),
        );
    }
    toml::Value::Table(t)
}

/// The rule for remote commands. They are denied until the broker can open
/// a tunnel to a configured remote (§7.3.3), whatever `fetch` and `push`
/// say, so the policy never allows more than the provider can enforce.
fn remote_rule(subcommands: &[&str]) -> toml::Value {
    rule(subcommands, "deny", None, &[])
}

/// A shim running `binary` with `args` before the caller's, refusing
/// `deny` anywhere, with `rules`, and asking to run anything else in
/// `vcs.local`.
fn shim(binary: &str, args: &[&str], deny: &[&str], rules: Vec<toml::Value>) -> toml::Value {
    let strings = |items: &[&str]| toml::Value::Array(items.iter().map(|s| (*s).into()).collect());
    let mut t = toml::Table::new();
    t.insert("binary".into(), binary.into());
    t.insert("args".into(), strings(args));
    t.insert("deny_flags".into(), strings(deny));
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

/// The `jj` shim of §7.4, for the repository at the workspace mount
/// `mount`. It runs `jj --no-pager -R <mount>`, so jj uses that repository
/// whatever directory the caller is in. Options that name another
/// repository, add configuration or run a diff or merge tool are refused.
/// Reading commands run in `vcs.local` too, since jj snapshots the working
/// copy first, which writes to `.jj`.
fn jj_shim(mount: &str) -> toml::Value {
    shim(
        "jj",
        &["--no-pager", "-R", mount],
        &[
            "--config",
            "--config-file",
            "--config-toml",
            "-R",
            "--repository",
            "--tool",
            "-i",
            "--interactive",
        ],
        vec![
            rule(
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
                &[],
            ),
            rule(
                &["new", "commit", "ci", "describe", "desc"],
                "allow",
                Some("local"),
                &[
                    "-A",
                    "--insert-after",
                    "--after",
                    "-B",
                    "--insert-before",
                    "--before",
                ],
            ),
            rule(
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
                &[],
            ),
            remote_rule(&["git fetch", "git clone"]),
            remote_rule(&["git push"]),
        ],
    )
}

/// The `git` shim of §7.4. It runs `git --no-pager`, and the profiles'
/// `GIT_DIR` and `GIT_WORK_TREE` name the repository. Options that add
/// configuration, run other programs, write files outside git's control or
/// name another repository are refused. `--exec` is `push`'s and
/// `ls-remote`'s other name for `--receive-pack` and `--upload-pack`, and
/// `--output` makes `diff`, `log` and their kin write to any path the
/// profile can write.
fn git_shim() -> toml::Value {
    shim(
        "git",
        &["--no-pager"],
        &[
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
        ],
        vec![
            rule(
                &["status", "diff", "log", "show", "add", "commit"],
                "allow",
                Some("local"),
                &[],
            ),
            rule(
                &[
                    "reset", "rebase", "checkout", "switch", "branch", "tag", "clean", "stash",
                ],
                "ask",
                Some("local"),
                &[],
            ),
            remote_rule(&["fetch", "pull", "ls-remote", "remote update", "clone"]),
            remote_rule(&["push"]),
        ],
    )
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
        let layout = discover(&ctx.workspace);
        for what in &layout.unsupported {
            warn(what);
        }
        let identity = if layout.git_dirs.is_empty() && !layout.jj_supported {
            Vec::new()
        } else {
            host_identity()
        };
        let manifest = match self.manifest_for(
            &ctx.workspace,
            ctx.workspace_mount.as_path(),
            &layout,
            &identity,
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
    use crate::manifest::{ContributedProfile, PathPattern, ShimName};

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
            .manifest_for(ws, Path::new(MOUNT), &discover(ws), identity)
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
        for p in [ro, local] {
            assert_eq!(
                p.grants.network.mode,
                Some(crate::policy::NetworkMode::None)
            );
            assert_eq!(env(p, "GIT_DIR"), Some("/workspace/.git"));
            assert_eq!(env(p, "GIT_WORK_TREE"), Some("/workspace"));
            assert_eq!(env(p, "GIT_CONFIG_GLOBAL"), Some("/dev/null"));
            assert_eq!(env(p, "GIT_EDITOR"), Some("false"));
            assert_eq!(env(p, "GIT_PAGER"), Some("cat"));
            assert_eq!(env(p, "JJ_EDITOR"), Some("false"));
            assert_eq!(env(p, "JJ_USER"), Some("Ann"));
            // The safe settings, then the identity.
            assert_eq!(env(p, "GIT_CONFIG_COUNT"), Some("6"));
            assert_eq!(env(p, "GIT_CONFIG_KEY_4"), Some("safe.bareRepository"));
            assert_eq!(env(p, "GIT_CONFIG_KEY_5"), Some("user.name"));
            assert_eq!(env(p, "GIT_CONFIG_VALUE_5"), Some("Ann"));
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
        let git = shim(&m, "git");
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
        // GIT_DIR is the admin directory, at its own path.
        let m = manifest(&wt, &[]);
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
        let jj = shim(&m, "jj");
        assert_eq!(
            jj.args.iter().map(|a| a.as_str()).collect::<Vec<_>>(),
            ["--no-pager", "-R", MOUNT]
        );
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
        // A secondary workspace: masked, nothing brokered.
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
            .manifest_for(&wt, Path::new(MOUNT), &layout, &[])
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
            .manifest_for(&ws, Path::new(MOUNT), &discover(&ws), &[])
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
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert!(warnings[0].starts_with("fetch = \"allow\""), "{warnings:?}");
        assert!(warnings[1].starts_with("signing = true"), "{warnings:?}");
    }

    #[test]
    fn the_shims_keep_remote_and_unsafe_commands_off() {
        let (_d, ws) = workspace();
        fs::create_dir_all(ws.join(".jj/repo/store")).unwrap();
        git_init(&ws);
        let m = manifest(&ws, &[]);
        let run = |name: &str, line: &str| {
            let args: Vec<Vec<u8>> = line.split(' ').map(|a| a.as_bytes().to_vec()).collect();
            decide(shim(&m, name), &args).0
        };
        let local = || "local".parse::<ProfileRef>().unwrap();
        assert_eq!(run("git", "status"), Outcome::Allow(local()));
        assert_eq!(run("git", "commit -m x"), Outcome::Allow(local()));
        assert_eq!(run("git", "reset --hard"), Outcome::Ask(local()));
        assert_eq!(run("jj", "log -r @"), Outcome::Allow(local()));
        assert_eq!(run("jj", "describe -m x"), Outcome::Allow(local()));
        assert_eq!(run("jj", "abandon"), Outcome::Ask(local()));
        // Unknown subcommands, and known ones after a flag, ask.
        assert_eq!(run("git", "gc"), Outcome::Ask(local()));
        assert_eq!(run("git", "--no-pager push"), Outcome::Ask(local()));
        for (name, line) in [
            ("git", "push origin main"),
            ("git", "fetch"),
            ("git", "pull --rebase"),
            ("git", "remote update"),
            ("git", "ls-remote --exec=/bin/sh origin"),
            ("git", "log --output=.git/hooks/pre-commit"),
            ("git", "-c core.pager=sh status"),
            ("git", "-C /elsewhere status"),
            ("git", "--git-dir=/elsewhere status"),
            ("git", "status --upl=x"),
            ("jj", "git push"),
            ("jj", "git fetch"),
            ("jj", "--config ui.pager=sh log"),
            ("jj", "-R /elsewhere log"),
            ("jj", "new -A @"),
            ("jj", "diff --tool=sh"),
            ("jj", "commit -i"),
            ("jj", "squash --interactive"),
        ] {
            assert!(matches!(run(name, line), Outcome::Deny(_)), "{name} {line}");
        }
    }
}
