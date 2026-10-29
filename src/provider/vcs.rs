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
//!   writable with every git config file read-only and every hooks
//!   directory masked, and git and jj told to use no user, system or
//!   repository-supplied hooks, pager or external tools;
//! * the shims `jj` and `git` (per `tools`), with the policy of §7.4 written
//!   as declarative rules. Remote commands are denied for now, so fetch and
//!   push happen on the host.
//!
//! Layouts it supports: a plain `.git` directory, a `.jj` directory with or
//! without a colocated `.git`, and a git worktree whose `.git` file names
//! an admin directory that names it back. A jj secondary workspace, and a
//! workspace inside a checkout whose metadata is above it, get the mask
//! but no VCS profiles, with a warning.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::{Provider, ProviderContext, ProviderError, ProviderOutput};
use crate::config::{ProfileRef, ProviderName, ProviderOrigin, VcsTool, VcsView};
use crate::manifest::Manifest;
use crate::policy::Decision;

/// The name of the built-in `vcs` provider of `base = "default"`.
pub const VCS_PROVIDER_NAME: &str = "vcs";

/// The git configuration every brokered git command gets, ahead of any
/// file: no hooks, no filesystem monitor, no pager, no `ext::` transport.
const SAFE_GIT_CONFIG: [(&str, &str); 4] = [
    ("core.hooksPath", "/dev/null"),
    ("core.fsmonitor", "false"),
    ("core.pager", "cat"),
    ("protocol.ext.allow", "never"),
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
/// names points back.
pub fn discover(workspace: &Path) -> Layout {
    let mut layout = Layout::default();
    let dot_git = workspace.join(".git");
    let dot_jj = workspace.join(".jj");
    match fs::symlink_metadata(&dot_git) {
        Ok(m) if m.is_dir() => {
            layout.git_dirs.push(dot_git.clone());
            layout.dot_git = Some(dot_git);
        }
        Ok(m) if m.is_file() => {
            match worktree_dirs(workspace, &dot_git) {
                Ok(dirs) => layout.git_dirs = dirs,
                Err(why) => layout
                    .unsupported
                    .push(format!("the git worktree at {:?}: {why}", workspace)),
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
            match fs::symlink_metadata(dot_jj.join("repo")) {
                Ok(repo) if repo.is_dir() => layout.jj_supported = true,
                Ok(_) => layout.unsupported.push(format!(
                    "the jj secondary workspace at {workspace:?}, whose repository lives elsewhere"
                )),
                Err(_) => layout
                    .unsupported
                    .push(format!("{dot_jj:?}, which has no repo directory")),
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
            .find(|a| a.join(".git").exists() || a.join(".jj").exists())
    {
        layout.unsupported.push(format!(
            "the checkout at {root:?}, which holds the workspace below its root"
        ));
    }
    layout
}

/// The admin and common directories of the git worktree whose `.git` file
/// is `dot_git`. The admin directory must name `dot_git` back, and sit in
/// the common directory's `worktrees`, so a file the sandbox wrote cannot
/// point anywhere else.
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
    if !common.join("objects").is_dir() || !common.join("HEAD").is_file() {
        return Err("its common directory is not a git directory".to_owned());
    }
    Ok(vec![admin, common])
}

/// The text of the small file at `path`.
fn read_small(path: &Path) -> Result<String, String> {
    let meta = fs::symlink_metadata(path).map_err(|e| format!("cannot read {path:?}: {e}"))?;
    if !meta.is_file() || meta.len() > 4096 {
        return Err(format!("{path:?} is not a small file"));
    }
    fs::read_to_string(path).map_err(|e| format!("cannot read {path:?}: {e}"))
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
    /// The manifest for `layout` in `workspace`, with `identity` for git
    /// and jj.
    pub fn manifest_for(
        &self,
        workspace: &Path,
        layout: &Layout,
        identity: &[(String, String)],
    ) -> Result<Manifest, String> {
        use toml::Value;
        let path = |p: &Path| {
            rule_path(workspace, p).ok_or_else(|| format!("cannot write a rule for {p:?}"))
        };
        let list =
            |items: Vec<String>| Value::Array(items.into_iter().map(Value::String).collect());
        let mut root = toml::Table::new();
        // The workspace's own metadata, in `main`.
        let metadata: Vec<String> = [&layout.dot_git, &layout.dot_jj]
            .into_iter()
            .flatten()
            .map(|p| path(p))
            .collect::<Result<_, _>>()?;
        if metadata.is_empty() {
            return Ok(Manifest::default());
        }
        let mut main_fs = toml::Table::new();
        match self.view {
            VcsView::Masked => main_fs.insert("masked".into(), list(metadata.clone())),
            VcsView::Ro => main_fs.insert("ro".into(), list(metadata.clone())),
        };
        root.insert("fs".into(), Value::Table(main_fs));
        let git = !layout.git_dirs.is_empty();
        let jj = layout.jj_supported;
        if !git && !jj {
            return manifest_from(root);
        }
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
                if dir.join(file).exists() {
                    locked.push(path(&dir.join(file))?);
                }
            }
            if dir.join("modules").is_dir() {
                locked.push(format!("{}/modules/*/config", path(dir)?));
                hooks.push(format!("{}/modules/*/hooks", path(dir)?));
            }
            if dir.join("worktrees").is_dir() {
                locked.push(format!("{}/worktrees/*/config.worktree", path(dir)?));
            }
            if dir.join("hooks").exists() {
                hooks.push(path(&dir.join("hooks"))?);
            }
        }
        if let Some(dot_jj) = &layout.dot_jj {
            let config = dot_jj.join("repo/config.toml");
            if config.exists() {
                locked.push(path(&config)?);
            }
        }
        let mut env = toml::Table::new();
        env.insert("GIT_CONFIG_NOSYSTEM".into(), "1".into());
        env.insert("GIT_CONFIG_GLOBAL".into(), "/dev/null".into());
        env.insert("JJ_CONFIG".into(), "/dev/null".into());
        let mut config: Vec<(&str, &str)> = SAFE_GIT_CONFIG.to_vec();
        for (key, value) in identity {
            config.push((key, value));
            match key.as_str() {
                "user.name" => env.insert("JJ_USER".into(), value.clone().into()),
                "user.email" => env.insert("JJ_EMAIL".into(), value.clone().into()),
                _ => None,
            };
        }
        env.insert("GIT_CONFIG_COUNT".into(), config.len().to_string().into());
        for (i, (key, value)) in config.iter().enumerate() {
            env.insert(format!("GIT_CONFIG_KEY_{i}"), (*key).into());
            env.insert(format!("GIT_CONFIG_VALUE_{i}"), (*value).into());
        }
        let mut profiles = toml::Table::new();
        // Remote commands are refused by the shims' rules, and the
        // profiles have no network either, so a rule that misses one
        // (`git --no-pager push` takes the default) still cannot reach a
        // remote.
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
fn remote_rule(subcommands: &[&str], _setting: Decision) -> toml::Value {
    rule(subcommands, "deny", None, &[])
}

fn shim(binary: &str, deny: &[&str], rules: Vec<toml::Value>) -> toml::Value {
    let mut t = toml::Table::new();
    t.insert("binary".into(), binary.into());
    t.insert(
        "deny_flags".into(),
        toml::Value::Array(deny.iter().map(|s| (*s).into()).collect()),
    );
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

/// The `jj` shim of §7.4. Global options that name another repository or
/// add configuration are refused.
fn jj_shim(fetch: Decision, push: Decision) -> toml::Value {
    shim(
        "jj",
        &[
            "--config",
            "--config-file",
            "--config-toml",
            "-R",
            "--repository",
        ],
        vec![
            rule(
                &[
                    "status",
                    "diff",
                    "log",
                    "show",
                    "evolog",
                    "op log",
                    "st",
                    "file show",
                ],
                "allow",
                Some("ro"),
                &[],
            ),
            rule(
                &["new", "commit", "describe", "desc", "ci"],
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
            remote_rule(&["git fetch", "git clone"], fetch),
            remote_rule(&["git push"], push),
        ],
    )
}

/// The `git` shim of §7.4. Options that add configuration, run other
/// programs, write files outside git's control or name another repository
/// are refused. `--exec` is `push`'s and `ls-remote`'s other name for
/// `--receive-pack` and `--upload-pack`, and `--output` makes `diff`, `log`
/// and their kin write to any path the profile can write.
fn git_shim(fetch: Decision, push: Decision) -> toml::Value {
    shim(
        "git",
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
            remote_rule(
                &["fetch", "pull", "ls-remote", "remote update", "clone"],
                fetch,
            ),
            remote_rule(&["push"], push),
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
        let layout = discover(&ctx.workspace);
        for what in &layout.unsupported {
            eprintln!(
                "stopit: warning: {}",
                crate::escape::escape_message(&format!(
                    "provider \"{}\" does not broker VCS commands for {what}. Its metadata is \
                     masked, and VCS commands need the host",
                    self.name
                ))
            );
        }
        let identity = if layout.git_dirs.is_empty() && !layout.jj_supported {
            Vec::new()
        } else {
            host_identity()
        };
        let manifest = self
            .manifest_for(&ctx.workspace, &layout, &identity)
            .map_err(|reason| ProviderError::Vcs {
                name: self.name.clone(),
                reason,
            })?;
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

    fn provider() -> VcsProvider {
        VcsProvider::builtin()
    }

    fn git_init(dir: &Path) {
        fs::create_dir_all(dir.join(".git/objects")).unwrap();
        fs::create_dir_all(dir.join(".git/hooks")).unwrap();
        fs::write(dir.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        fs::write(dir.join(".git/config"), "[core]\n").unwrap();
    }

    #[test]
    fn a_plain_repository_is_masked_in_main_and_writable_in_local() {
        let ws = tempfile::TempDir::new().unwrap();
        git_init(ws.path());
        let layout = discover(ws.path());
        assert_eq!(layout.git_dirs, [ws.path().join(".git")]);
        assert!(layout.unsupported.is_empty());
        let m = provider()
            .manifest_for(ws.path(), &layout, &[("user.name".into(), "Ann".into())])
            .unwrap();
        let text = format!("{m:?}");
        for want in [
            "{workspace}/.git",
            "{workspace}/.git/config",
            "{workspace}/.git/hooks",
        ] {
            assert!(text.contains(want), "{want}: {text}");
        }
        assert_eq!(m.profiles.len(), 2);
        assert_eq!(
            m.grants
                .shims
                .keys()
                .map(|k| k.as_str())
                .collect::<Vec<_>>(),
            ["git"]
        );
        // No jj repository, no jj shim.
        assert!(!text.contains("JJ_USER: "), "{text}");
    }

    #[test]
    fn no_repository_contributes_nothing() {
        let ws = tempfile::TempDir::new().unwrap();
        let layout = discover(ws.path());
        assert_eq!(layout, Layout::default());
        let m = provider().manifest_for(ws.path(), &layout, &[]).unwrap();
        assert_eq!(m, Manifest::default());
    }

    #[test]
    fn a_worktree_must_be_named_back_by_its_admin_directory() {
        let root = tempfile::TempDir::new().unwrap();
        let main = root.path().join("main");
        git_init(&main);
        let admin = main.join(".git/worktrees/wt");
        fs::create_dir_all(&admin).unwrap();
        let wt = root.path().join("wt");
        fs::create_dir(&wt).unwrap();
        fs::write(wt.join(".git"), format!("gitdir: {}\n", admin.display())).unwrap();
        fs::write(admin.join("commondir"), "../..\n").unwrap();
        fs::write(
            admin.join("gitdir"),
            format!("{}\n", wt.join(".git").display()),
        )
        .unwrap();
        let layout = discover(&wt);
        assert!(layout.unsupported.is_empty(), "{:?}", layout.unsupported);
        assert_eq!(
            layout.git_dirs,
            [
                fs::canonicalize(&admin).unwrap(),
                fs::canonicalize(main.join(".git")).unwrap()
            ]
        );
        // A `.git` file pointing at a directory that does not name it back,
        // as a sandbox could write, gets no grant.
        let elsewhere = root.path().join("secret");
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
        let m = provider().manifest_for(&wt, &discover(&wt), &[]).unwrap();
        assert!(m.profiles.is_empty());
        assert!(format!("{m:?}").contains("{workspace}/.git"));
    }

    #[test]
    fn jj_repositories_and_secondary_workspaces() {
        let ws = tempfile::TempDir::new().unwrap();
        fs::create_dir_all(ws.path().join(".jj/repo/store")).unwrap();
        git_init(ws.path());
        let layout = discover(ws.path());
        assert!(layout.jj_supported);
        let m = provider().manifest_for(ws.path(), &layout, &[]).unwrap();
        assert_eq!(
            m.grants
                .shims
                .keys()
                .map(|k| k.as_str())
                .collect::<Vec<_>>(),
            ["git", "jj"]
        );
        // A secondary workspace: masked, nothing brokered.
        let other = tempfile::TempDir::new().unwrap();
        fs::create_dir_all(other.path().join(".jj")).unwrap();
        fs::write(other.path().join(".jj/repo"), "/somewhere/.jj/repo").unwrap();
        let layout = discover(other.path());
        assert!(!layout.jj_supported);
        assert_eq!(layout.unsupported.len(), 1);
        let m = provider().manifest_for(other.path(), &layout, &[]).unwrap();
        assert!(m.grants.shims.is_empty());
        assert!(m.profiles.is_empty());
    }

    #[test]
    fn a_workspace_below_a_checkout_root_is_reported() {
        let root = tempfile::TempDir::new().unwrap();
        git_init(root.path());
        let sub = root.path().join("sub");
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
    fn view_ro_shows_the_metadata_in_main() {
        let ws = tempfile::TempDir::new().unwrap();
        git_init(ws.path());
        let p = VcsProvider {
            view: VcsView::Ro,
            ..provider()
        };
        let m = p
            .manifest_for(ws.path(), &discover(ws.path()), &[])
            .unwrap();
        assert!(format!("{:?}", m.grants.fs).contains("ro"));
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
        use crate::broker::{Outcome, decide};
        let ws = tempfile::TempDir::new().unwrap();
        fs::create_dir_all(ws.path().join(".jj/repo/store")).unwrap();
        git_init(ws.path());
        let m = provider()
            .manifest_for(ws.path(), &discover(ws.path()), &[])
            .unwrap();
        // Neither profile reaches the network, whatever `main` has.
        for profile in m.profiles.values() {
            assert_eq!(
                profile.grants.network.mode,
                Some(crate::policy::NetworkMode::None)
            );
        }
        let shim =
            |name: &str| &m.grants.shims[&name.parse::<crate::manifest::ShimName>().unwrap()];
        let run = |name: &str, line: &str| {
            let args: Vec<Vec<u8>> = line.split(' ').map(|a| a.as_bytes().to_vec()).collect();
            decide(shim(name), &args).0
        };
        let profile = |p: &str| p.parse::<ProfileRef>().unwrap();
        assert_eq!(run("git", "status"), Outcome::Allow(profile("local")));
        assert_eq!(run("git", "reset --hard"), Outcome::Ask(profile("local")));
        assert_eq!(run("jj", "log -r @"), Outcome::Allow(profile("ro")));
        assert_eq!(run("jj", "abandon"), Outcome::Ask(profile("local")));
        // Unknown subcommands, and known ones after a flag, ask.
        assert_eq!(run("git", "gc"), Outcome::Ask(profile("local")));
        assert_eq!(
            run("git", "--no-pager push"),
            Outcome::Ask(profile("local"))
        );
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
        ] {
            assert!(matches!(run(name, line), Outcome::Deny(_)), "{name} {line}");
        }
    }
}
