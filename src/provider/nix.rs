//! The built-in `nix` provider (DESIGN.md §3.6).
//!
//! Resolves a project's Nix development environment on the host via
//! `nix print-dev-env --json` and `nix path-info --recursive`, granting only
//! the shell's runtime `/nix/store` closure read-only plus its exported `PATH`,
//! toolchain environment variables, and (by default) an in-sandbox `shellHook`
//! script without running `shellHook` on the host or exposing the Nix daemon
//! inside the sandbox.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use core::sync::atomic::{AtomicU64, Ordering};

use rustix::fs::{AtFlags, FileType, FlockOperation, Mode, OFlags};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use self::ignore::{IgnoreStack, RuleLayer};
use super::script::{
    HostCommandResult, STDOUT_LIMIT, describe_status, describe_stderr, run_host_command,
};
use super::{Provider, ProviderContext, ProviderError, ProviderOutput};
use crate::config::{
    NixIgnorePattern, NixShell, NixSource, ProfileRef, ProviderName, ProviderOrigin,
};
use crate::manifest::{
    EnvName, EnvValue, Manifest, PathPattern, SearchPathEntry, ShellHook, ShellHookSetting,
};
use crate::session::{check_private_dir, create_private_dir};
use crate::spec::{ScriptPathError, has_rewritable_hard_links, resolve_script_path};
use crate::supervisor::Ownership;
use crate::trust::check_store_file;

mod ignore;

/// Domain tag and schema version mixed into every persistent Nix cache key.
const CACHE_DOMAIN: &[u8] = b"stopit-nix-cache-v3\0";

/// Format version stored inside `cache.json`.
const CACHE_FORMAT_VERSION: u32 = 2;

/// Subdirectory inside `data_dir` holding cached Nix environments and GC roots.
const NIX_CACHE_DIR: &str = "nix";

/// File name of the serialized resolved environment in each cache entry dir.
const CACHE_FILE: &str = "cache.json";

/// Temporary file written under `flock` before atomic rename over [`CACHE_FILE`].
const CACHE_TEMP_FILE: &str = "cache.json.tmp";

/// Mode of [`CACHE_FILE`].
const CACHE_FILE_MODE: u32 = 0o600;

/// Maximum number of filesystem entries walked when hashing local `*.nix` and
/// `flake.lock` inputs; larger trees bypass persistent caching rather than
/// stalling startup.
const MAX_HASH_WALK_ENTRIES: usize = 50_000;

/// Maximum number of filesystem entries inspected when checking a project tree
/// for untrusted symlinks or rewritable hard links on `*.nix` and `flake.lock`.
const MAX_VALIDATE_WALK_ENTRIES: usize = 250_000;

/// Maximum size of a single `.nix` or `flake.lock` file hashed for caching.
const MAX_NIX_INPUT_BYTES: usize = 16 * 1024 * 1024;

/// VCS directory names skipped during untrusted symlink checks on directory targets.
const IGNORED_VCS_DIRS: &[&str] = &[".git", ".jj", ".hg"];

/// Host environment variables passed through to `nix` on the host. All other
/// host variables (including `NIX_CONFIG`, `SSH_AUTH_SOCK`, and secret tokens)
/// are stripped so they cannot influence evaluation or leak via `builtins.getEnv`
/// into `env.set` and `cache.json`.
const ALLOWED_NIX_HOST_ENV_VARS: &[&str] = &[
    "ALL_PROXY",
    "CURL_CA_BUNDLE",
    "GIT_SSL_CAINFO",
    "HOME",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LOCALE_ARCHIVE",
    "LOGNAME",
    "NIX_CONF_DIR",
    "NIX_DATA_DIR",
    "NIX_LOG_DIR",
    "NIX_PATH",
    "NIX_PROFILES",
    "NIX_REMOTE",
    "NIX_SSL_CERT_FILE",
    "NIX_STATE_DIR",
    "NIX_STORE_DIR",
    "NIX_USER_CONF_FILES",
    "NO_PROXY",
    "PATH",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    "TEMP",
    "TMP",
    "TMPDIR",
    "TZ",
    "USER",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
    "all_proxy",
    "http_proxy",
    "https_proxy",
    "no_proxy",
];

/// Exported variables from `nix print-dev-env --json` that belong to Nix's
/// isolated build sandbox, shell identity, proxy settings, or `mkDerivation`
/// recipe attributes rather than the runtime development toolchain.
const IGNORED_EXPORTED_VARS: &[&str] = &[
    // Sandbox / user / terminal / proxy / session identity managed by stopit.
    "ALL_PROXY",
    "COLORTERM",
    "DISPLAY",
    "EUID",
    "FTP_PROXY",
    "GROUPS",
    "HOME",
    "HOSTNAME",
    "HOST_PATH",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "LANG",
    "LC_ALL",
    "LOGNAME",
    "NIX_BUILD_TOP",
    "NIX_CONFIG",
    "NIX_LOG_FD",
    "NO_PROXY",
    "OLDPWD",
    "PATH",
    "PWD",
    "SHELL",
    "SHLVL",
    "SSH_AUTH_SOCK",
    "TEMP",
    "TEMPDIR",
    "TERM",
    "TMP",
    "TMPDIR",
    "TZ",
    "UID",
    "USER",
    "WAYLAND_DISPLAY",
    "_",
    // Internal stdenv / mkShell derivation attributes and lowercase proxy vars.
    "__structuredAttrs",
    "all_proxy",
    "allowSubstitutes",
    "buildInputs",
    "buildPhase",
    "builder",
    "cmakeFlags",
    "configureFlags",
    "depsBuildBuild",
    "depsBuildBuildPropagated",
    "depsBuildTarget",
    "depsBuildTargetPropagated",
    "depsHostHost",
    "depsHostHostPropagated",
    "depsTargetTarget",
    "depsTargetTargetPropagated",
    "doCheck",
    "doInstallCheck",
    "dontAddDisableDepTrack",
    "ftp_proxy",
    "http_proxy",
    "https_proxy",
    "mesonFlags",
    "name",
    "nativeBuildInputs",
    "no_proxy",
    "out",
    "outputs",
    "patches",
    "phases",
    "preferLocalBuild",
    "propagatedBuildInputs",
    "propagatedNativeBuildInputs",
    "shell",
    "shellHook",
    "stdenv",
    "strictDeps",
    "system",
];

/// Built-in provider that resolves a Nix flake or classic Nix file into a
/// read-only `/nix/store` closure and development environment.
#[derive(Debug, Clone)]
pub struct NixProvider {
    name: ProviderName,
    profile: ProfileRef,
    shell: Option<NixShell>,
    file: Option<NixSource>,
    flake: Option<NixSource>,
    cache: bool,
    shell_hook: bool,
    gitignore: bool,
    ignore: Vec<NixIgnorePattern>,
    base_dir: PathBuf,
    origin: ProviderOrigin,
    nix_program: Option<PathBuf>,
    #[cfg(test)]
    store_check_root: Option<PathBuf>,
    #[cfg(test)]
    path_env_override: Option<OsString>,
    #[cfg(test)]
    extra_host_env: Vec<(OsString, OsString)>,
    protected: OnceLock<Vec<PathBuf>>,
}

#[derive(Debug, Clone)]
enum NixTarget {
    Flake { dir: PathBuf },
    File { file: PathBuf },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CachedNixEnv {
    version: u32,
    store_paths: Vec<String>,
    path_prepend: Vec<String>,
    env_set: BTreeMap<String, String>,
    #[serde(default)]
    shell_bin: Option<String>,
    #[serde(default)]
    shell_hook: Option<String>,
}

#[derive(Deserialize)]
struct PrintDevEnvJson {
    #[serde(default)]
    variables: BTreeMap<String, DevEnvVariable>,
}

#[derive(Deserialize)]
struct DevEnvVariable {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    value: Value,
}

impl NixProvider {
    /// Creates a workspace-origin `nix` provider.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: ProviderName,
        profile: ProfileRef,
        shell: Option<NixShell>,
        file: Option<NixSource>,
        flake: Option<NixSource>,
        cache: bool,
        base_dir: &Path,
    ) -> Self {
        Self::with_origin(
            name,
            profile,
            shell,
            file,
            flake,
            cache,
            base_dir,
            ProviderOrigin::Workspace,
        )
    }

    /// Creates a `nix` provider declared in `base_dir` and tagged with `origin`.
    #[allow(clippy::too_many_arguments)]
    pub fn with_origin(
        name: ProviderName,
        profile: ProfileRef,
        shell: Option<NixShell>,
        file: Option<NixSource>,
        flake: Option<NixSource>,
        cache: bool,
        base_dir: &Path,
        origin: ProviderOrigin,
    ) -> Self {
        NixProvider {
            name,
            profile,
            shell,
            file,
            flake,
            cache,
            shell_hook: true,
            gitignore: true,
            ignore: Vec::new(),
            base_dir: base_dir.to_owned(),
            origin,
            nix_program: None,
            #[cfg(test)]
            store_check_root: None,
            #[cfg(test)]
            path_env_override: None,
            #[cfg(test)]
            extra_host_env: Vec::new(),
            protected: OnceLock::new(),
        }
    }

    /// Configures whether the devShell's `shellHook` is emitted as an
    /// in-sandbox `sandbox.shell_hook` grant (defaults to `true`).
    pub fn with_shell_hook(mut self, shell_hook: bool) -> Self {
        self.shell_hook = shell_hook;
        self
    }

    /// Configures whether `.gitignore` files inside the target tree exclude
    /// paths from validation, cache hashing, and flake staging (defaults to `true`).
    pub fn with_gitignore(mut self, gitignore: bool) -> Self {
        self.gitignore = gitignore;
        self
    }

    /// Configures additional gitignore-style glob patterns relative to the
    /// target root excluded from validation, cache hashing, and flake staging.
    pub fn with_ignore(mut self, ignore: Vec<NixIgnorePattern>) -> Self {
        self.ignore = ignore;
        self
    }

    /// Overrides the `nix` executable path for unit tests.
    #[cfg(test)]
    pub(crate) fn with_nix_program(mut self, program: impl Into<PathBuf>) -> Self {
        self.nix_program = Some(program.into());
        self
    }

    /// Overrides the host directory checked for store object existence in cache tests.
    #[cfg(test)]
    pub(crate) fn with_store_check_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.store_check_root = Some(root.into());
        self
    }

    /// Overrides the `PATH` searched by [`Self::resolve_nix_binary`] in unit tests.
    #[cfg(test)]
    pub(crate) fn with_path_env(mut self, path_env: impl Into<OsString>) -> Self {
        self.path_env_override = Some(path_env.into());
        self
    }

    /// Appends host environment entries prior to [`scrubbed_nix_host_env`] filtering in unit tests.
    #[cfg(test)]
    pub(crate) fn with_extra_host_env(
        mut self,
        vars: impl IntoIterator<Item = (impl Into<OsString>, impl Into<OsString>)>,
    ) -> Self {
        self.extra_host_env = vars
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        self
    }

    fn nix_err(&self, reason: impl Into<String>) -> ProviderError {
        ProviderError::Nix {
            name: self.name.clone(),
            reason: reason.into(),
        }
    }

    fn untrusted_link_err(
        &self,
        declared: &Path,
        link: &Path,
        root: &crate::spec::UntrustedRoot,
    ) -> ProviderError {
        self.nix_err(format!(
            "refusing to evaluate {}: path runs through symlink {} inside {root}, \
             which a sandbox can write",
            declared.display(),
            link.display()
        ))
    }

    fn hard_linked_err(&self, declared: &Path, resolved: &Path, links: u64) -> ProviderError {
        self.nix_err(format!(
            "refusing to evaluate {} ({}): file has {links} hard links and is writable, \
             so a sandbox could rewrite it through another name",
            declared.display(),
            resolved.display()
        ))
    }

    /// Resolves a candidate file or directory path through `resolve_script_path`,
    /// refusing symlinks inside untrusted roots (`ctx.workspace` or `ctx.rw_grants`).
    fn resolve_checked_path(
        &self,
        declared: &Path,
        check_base_dir: bool,
        ctx: &ProviderContext,
    ) -> Result<PathBuf, ProviderError> {
        let lookup_err = |error: io::Error| {
            if check_base_dir && let Err(dir_err) = fs::metadata(&self.base_dir) {
                return self.nix_err(format!(
                    "cannot resolve {} in {}: {dir_err}",
                    declared.display(),
                    self.base_dir.display()
                ));
            }
            self.nix_err(format!("cannot resolve {}: {error}", declared.display()))
        };
        let abs = std::path::absolute(declared).map_err(lookup_err)?;
        match resolve_script_path(&abs, &ctx.workspace, &ctx.rw_grants) {
            Ok(resolved) => Ok(resolved),
            Err(ScriptPathError::Link { link, root }) => {
                Err(self.untrusted_link_err(&abs, &link, &root))
            }
            Err(ScriptPathError::Lookup(error)) => Err(lookup_err(error)),
        }
    }

    /// Resolves an optional candidate path (`flake.nix`, `shell.nix`, or
    /// `flake.lock`), returning `Ok(None)` only when the entry itself is
    /// genuinely absent (`ErrorKind::NotFound` with no dangling symlink).
    fn resolve_optional_regular_file(
        &self,
        declared: &Path,
        ctx: &ProviderContext,
    ) -> Result<Option<PathBuf>, ProviderError> {
        let abs = std::path::absolute(declared)
            .map_err(|e| self.nix_err(format!("cannot resolve {}: {e}", declared.display())))?;
        match resolve_script_path(&abs, &ctx.workspace, &ctx.rw_grants) {
            Ok(resolved) => {
                self.check_regular_unlinked_file(&abs, &resolved)?;
                Ok(Some(resolved))
            }
            Err(ScriptPathError::Link { link, root }) => {
                Err(self.untrusted_link_err(&abs, &link, &root))
            }
            Err(ScriptPathError::Lookup(error)) => {
                let genuinely_missing = error.kind() == io::ErrorKind::NotFound
                    && fs::symlink_metadata(&abs)
                        .is_err_and(|m_err| m_err.kind() == io::ErrorKind::NotFound);
                if genuinely_missing {
                    Ok(None)
                } else {
                    Err(self.nix_err(format!("cannot resolve {}: {error}", abs.display())))
                }
            }
        }
    }

    /// Checks that `resolved` is a regular file without rewritable hard links.
    fn check_regular_unlinked_file(
        &self,
        declared: &Path,
        resolved: &Path,
    ) -> Result<(), ProviderError> {
        let meta = fs::symlink_metadata(resolved)
            .map_err(|e| self.nix_err(format!("cannot inspect {}: {e}", resolved.display())))?;
        if !meta.is_file() {
            return Err(self.nix_err(format!("{} is not a regular file", declared.display())));
        }
        if has_rewritable_hard_links(resolved, &meta) {
            return Err(self.hard_linked_err(declared, resolved, meta.nlink()));
        }
        Ok(())
    }

    /// Validates all `*.nix`, `flake.lock`, and consulted `.gitignore` entries in
    /// `target`'s directory tree (even when `cache = false`) so imported Nix files
    /// cannot run through untrusted symlinks or rewritable hard links, and verifies
    /// that every non-ignored symlink in a flake tree is a valid relative intra-flake symlink.
    fn validate_target_inputs(
        &self,
        target: &NixTarget,
        ctx: &ProviderContext,
        protected: &mut Vec<PathBuf>,
    ) -> Result<(), ProviderError> {
        let (root_to_walk, is_flake) = match target {
            NixTarget::Flake { dir } => (Some(dir.as_path()), true),
            NixTarget::File { file } => (
                file.parent()
                    .filter(|p| *p != Path::new("/") && *p != ctx.home),
                false,
            ),
        };
        if let Some(root) = root_to_walk {
            let mut visited = 0usize;
            let mut stack = IgnoreStack::new(&self.ignore);
            self.validate_nix_tree(
                root,
                root,
                is_flake,
                ctx,
                &mut stack,
                &mut visited,
                protected,
            )?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn validate_nix_tree(
        &self,
        root: &Path,
        dir: &Path,
        is_flake: bool,
        ctx: &ProviderContext,
        stack: &mut IgnoreStack,
        visited: &mut usize,
        protected: &mut Vec<PathBuf>,
    ) -> Result<(), ProviderError> {
        let read_dir = match fs::read_dir(dir) {
            Ok(rd) => rd,
            Err(e) if dir != root && e.kind() == io::ErrorKind::PermissionDenied => return Ok(()),
            Err(e) => {
                return Err(self.nix_err(format!("cannot read directory {}: {e}", dir.display())));
            }
        };
        let mut entries = Vec::new();
        for item in read_dir {
            *visited = visited.saturating_add(1);
            if *visited > MAX_VALIDATE_WALK_ENTRIES {
                return Err(self.nix_err(format!(
                    "cannot validate Nix inputs in {}: directory exceeds {MAX_VALIDATE_WALK_ENTRIES} entries",
                    root.display()
                )));
            }
            let entry = item.map_err(|e| {
                self.nix_err(format!(
                    "cannot read directory entry in {}: {e}",
                    dir.display()
                ))
            })?;
            entries.push(entry);
        }
        entries.sort_by_key(|e| e.file_name());

        let saved_layers = stack.layer_count();

        if self.gitignore
            && let Some(entry) = entries.iter().find(|e| e.file_name() == ".gitignore")
        {
            let full_path = entry.path();
            let ft = entry.file_type().map_err(|e| {
                self.nix_err(format!("cannot inspect {}: {e}", full_path.display()))
            })?;
            if ft.is_symlink()
                && let Some(untrusted) = innermost_untrusted_root(&full_path, ctx)
            {
                return Err(self.untrusted_link_err(&full_path, &full_path, &untrusted));
            }
            let resolved_gi = self.resolve_checked_path(&full_path, false, ctx)?;
            self.check_regular_unlinked_file(&full_path, &resolved_gi)?;
            if !protected.contains(&resolved_gi) {
                protected.push(resolved_gi.clone());
            }
            let bytes = read_bounded_regular_file(&resolved_gi).map_err(|e| self.nix_err(e))?;
            let content = String::from_utf8_lossy(&bytes);
            let base_rel = dir.strip_prefix(root).unwrap_or(Path::new(""));
            stack.push_layer(RuleLayer::from_gitignore_bytes(base_rel, &content));
        }

        for entry in entries {
            let file_name = entry.file_name();
            let name_str = file_name.to_str();
            let full_path = entry.path();
            let ft = entry.file_type().map_err(|e| {
                self.nix_err(format!("cannot inspect {}: {e}", full_path.display()))
            })?;

            if name_str == Some(".gitignore") && self.gitignore {
                continue;
            }

            let rel = full_path.strip_prefix(root).unwrap_or(&full_path);
            let is_root_flake_entry =
                is_flake && dir == root && matches!(name_str, Some("flake.nix" | "flake.lock"));

            if !is_root_flake_entry && stack.is_ignored(rel, name_str.unwrap_or(""), ft.is_dir()) {
                continue;
            }

            if ft.is_dir() {
                self.validate_nix_tree(
                    root,
                    &full_path,
                    is_flake,
                    ctx,
                    stack,
                    visited,
                    protected,
                )?;
                continue;
            }

            let is_nix_name = name_str.is_some_and(|n| n == "flake.lock" || n.ends_with(".nix"));

            if ft.is_symlink() {
                if let Some(untrusted) = innermost_untrusted_root(&full_path, ctx) {
                    if is_nix_name {
                        return Err(self.untrusted_link_err(&full_path, &full_path, &untrusted));
                    }
                    // Allow `nix build`'s `result* -> /nix/store/...` links, while
                    // refusing any directory symlink inside a writable root whose
                    // target tree holds `.nix` or `flake.lock` inputs.
                    let is_store_result_link = name_str
                        .is_some_and(|n| n == "result" || n.starts_with("result-"))
                        && fs::canonicalize(&full_path).is_ok_and(|c| c.starts_with("/nix/store/"));
                    if !is_store_result_link
                        && fs::metadata(&full_path).is_ok_and(|m| m.is_dir())
                        && dir_contains_nix_inputs(&full_path, visited)
                            .map_err(|r| self.nix_err(r))?
                    {
                        return Err(self.untrusted_link_err(&full_path, &full_path, &untrusted));
                    }
                }
                if is_flake {
                    validate_flake_symlink(root, &full_path).map_err(|r| self.nix_err(r))?;
                }
                continue;
            }

            if ft.is_file() && is_nix_name {
                self.check_regular_unlinked_file(&full_path, &full_path)?;
            }
        }

        stack.truncate(saved_layers);
        Ok(())
    }

    /// Checks whether `source` is relative to `self.base_dir`.
    fn uses_base_dir(source: &NixSource) -> bool {
        !source.uses_workspace_placeholder()
            && !source.as_str().starts_with('~')
            && !Path::new(source.as_str()).is_absolute()
    }

    /// Discovers and validates the Nix target and computes the canonical host
    /// paths that must be protected across all profiles.
    fn discover_target(
        &self,
        ctx: &ProviderContext,
    ) -> Result<(Option<NixTarget>, Vec<PathBuf>), ProviderError> {
        if let Some(file_src) = &self.file {
            let declared = file_src.expand(&self.base_dir, &ctx.workspace, &ctx.home);
            let resolved =
                self.resolve_checked_path(&declared, Self::uses_base_dir(file_src), ctx)?;
            self.check_regular_unlinked_file(&declared, &resolved)?;
            return Ok((
                Some(NixTarget::File {
                    file: resolved.clone(),
                }),
                vec![resolved],
            ));
        }

        if let Some(flake_src) = &self.flake {
            let declared_dir = flake_src.expand(&self.base_dir, &ctx.workspace, &ctx.home);
            let resolved_dir =
                self.resolve_checked_path(&declared_dir, Self::uses_base_dir(flake_src), ctx)?;
            let dir_meta = fs::symlink_metadata(&resolved_dir).map_err(|e| {
                self.nix_err(format!("cannot inspect {}: {e}", resolved_dir.display()))
            })?;
            if !dir_meta.is_dir() {
                return Err(self.nix_err(format!(
                    "flake path {} is not a directory",
                    declared_dir.display()
                )));
            }
            check_flake_dir_syntax(&resolved_dir).map_err(|r| self.nix_err(r))?;

            let declared_flake_nix = declared_dir.join("flake.nix");
            let flake_nix = self.resolve_checked_path(&declared_flake_nix, false, ctx)?;
            self.check_regular_unlinked_file(&declared_flake_nix, &flake_nix)?;
            let flake_lock =
                self.resolve_optional_regular_file(&declared_dir.join("flake.lock"), ctx)?;

            let mut protected = Vec::new();
            // Protect dedicated flake directories as directories while keeping
            // the workspace root itself editable around `flake.nix` and `flake.lock`.
            if resolved_dir != ctx.workspace {
                protected.push(resolved_dir.clone());
            }
            if !protected.contains(&flake_nix) {
                protected.push(flake_nix);
            }
            if let Some(lock) = flake_lock
                && !protected.contains(&lock)
            {
                protected.push(lock);
            }
            return Ok((Some(NixTarget::Flake { dir: resolved_dir }), protected));
        }

        // Auto-detect mode: check `{workspace}/flake.nix` first, then `{workspace}/shell.nix`.
        let ws_flake_nix = ctx.workspace.join("flake.nix");
        if let Some(flake_nix) = self.resolve_optional_regular_file(&ws_flake_nix, ctx)? {
            check_flake_dir_syntax(&ctx.workspace).map_err(|r| self.nix_err(r))?;
            let flake_lock =
                self.resolve_optional_regular_file(&ctx.workspace.join("flake.lock"), ctx)?;
            let mut protected = vec![flake_nix];
            if let Some(lock) = flake_lock
                && !protected.contains(&lock)
            {
                protected.push(lock);
            }
            return Ok((
                Some(NixTarget::Flake {
                    dir: ctx.workspace.clone(),
                }),
                protected,
            ));
        }

        let ws_shell_nix = ctx.workspace.join("shell.nix");
        if let Some(shell_nix) = self.resolve_optional_regular_file(&ws_shell_nix, ctx)? {
            return Ok((
                Some(NixTarget::File {
                    file: shell_nix.clone(),
                }),
                vec![shell_nix],
            ));
        }

        if let Some(shell) = &self.shell {
            return Err(self.nix_err(format!(
                "shell {:?} was requested, but neither flake.nix nor shell.nix exists in {}",
                shell.as_str(),
                ctx.workspace.display()
            )));
        }

        Ok((None, Vec::new()))
    }

    /// Resolves the `nix` executable to a canonical host file outside the
    /// workspace and static `rw` grants, returning its path and post-resolution
    /// metadata.
    fn resolve_nix_binary(
        &self,
        ctx: &ProviderContext,
    ) -> Result<(PathBuf, fs::Metadata), ProviderError> {
        let in_untrusted_root = |p: &Path| {
            p.starts_with(&ctx.workspace) || ctx.rw_grants.iter().any(|r| p.starts_with(&r.path))
        };
        let verify_resolved_bin = |declared: &Path,
                                   resolved: PathBuf|
         -> Result<(PathBuf, fs::Metadata), ProviderError> {
            if in_untrusted_root(&resolved) {
                return Err(self.nix_err(format!(
                    "refusing to execute nix binary {} inside a writable directory",
                    resolved.display()
                )));
            }
            let meta = fs::symlink_metadata(&resolved).map_err(|e| {
                self.nix_err(format!(
                    "cannot inspect nix binary {}: {e}",
                    resolved.display()
                ))
            })?;
            if !meta.is_file() {
                return Err(self.nix_err(format!(
                    "nix binary {} is not a regular file",
                    resolved.display()
                )));
            }
            if rustix::fs::access(&resolved, rustix::fs::Access::EXEC_OK).is_err() {
                return Err(self.nix_err(format!(
                    "nix binary {} is not executable",
                    resolved.display()
                )));
            }
            if has_rewritable_hard_links(&resolved, &meta) {
                return Err(self.hard_linked_err(declared, &resolved, meta.nlink()));
            }
            Ok((resolved, meta))
        };

        if let Some(explicit) = &self.nix_program {
            let abs = std::path::absolute(explicit).map_err(|e| {
                self.nix_err(format!(
                    "cannot resolve nix binary {}: {e}",
                    explicit.display()
                ))
            })?;
            let resolved = match resolve_script_path(&abs, &ctx.workspace, &ctx.rw_grants) {
                Ok(r) => r,
                Err(ScriptPathError::Link { link, root }) => {
                    return Err(self.untrusted_link_err(&abs, &link, &root));
                }
                Err(ScriptPathError::Lookup(e)) => {
                    return Err(
                        self.nix_err(format!("cannot resolve nix binary {}: {e}", abs.display()))
                    );
                }
            };
            return verify_resolved_bin(&abs, resolved);
        }

        #[cfg(test)]
        let path_os = self
            .path_env_override
            .clone()
            .or_else(|| std::env::var_os("PATH"));
        #[cfg(not(test))]
        let path_os = std::env::var_os("PATH");

        let Some(path_os) = path_os else {
            return Err(self.nix_err("could not find `nix` because PATH is not set on the host"));
        };
        for dir in std::env::split_paths(&path_os) {
            // Ignore empty or relative PATH segments so cwd is never searched,
            // and skip directories inside untrusted writable roots.
            if dir.as_os_str().is_empty() || !dir.is_absolute() || in_untrusted_root(&dir) {
                continue;
            }
            let candidate = dir.join("nix");
            let resolved = match resolve_script_path(&candidate, &ctx.workspace, &ctx.rw_grants) {
                Ok(r) => r,
                Err(ScriptPathError::Link { link, root }) => {
                    return Err(self.untrusted_link_err(&candidate, &link, &root));
                }
                Err(ScriptPathError::Lookup(_)) => continue,
            };
            if in_untrusted_root(&resolved) {
                continue;
            }
            let Ok(meta) = fs::symlink_metadata(&resolved) else {
                continue;
            };
            if !meta.is_file()
                || rustix::fs::access(&resolved, rustix::fs::Access::EXEC_OK).is_err()
            {
                continue;
            }
            if has_rewritable_hard_links(&resolved, &meta) {
                return Err(self.hard_linked_err(&candidate, &resolved, meta.nlink()));
            }
            return Ok((resolved, meta));
        }
        Err(self.nix_err("could not find an executable `nix` binary on the host PATH"))
    }

    fn host_env_for_nix(&self) -> Vec<(OsString, OsString)> {
        #[cfg(test)]
        if !self.extra_host_env.is_empty() {
            let mut combined: Vec<(OsString, OsString)> = std::env::vars_os().collect();
            combined.extend(self.extra_host_env.iter().cloned());
            return scrubbed_nix_host_env_from(combined);
        }
        scrubbed_nix_host_env_from(std::env::vars_os())
    }

    /// Runs `nix` on the host in `/` with a scrubbed environment and maps
    /// non-zero exit, signals, and output limits to [`ProviderError`].
    fn invoke_nix(&self, nix_bin: &Path, args: &[OsString]) -> HostCommandResult {
        #[cfg(test)]
        let _guard = super::script::EXEC_LOCK
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let env = self.host_env_for_nix();
        run_host_command(nix_bin, args, Path::new("/"), None, Some(&env))
    }

    fn finish_nix_result(
        &self,
        subcommand: &str,
        result: HostCommandResult,
    ) -> Result<Vec<u8>, ProviderError> {
        match result {
            HostCommandResult::Success(out) => Ok(out),
            HostCommandResult::StdoutTooLarge => Err(self.nix_err(format!(
                "`nix {subcommand}` printed more than {STDOUT_LIMIT} bytes on stdout"
            ))),
            HostCommandResult::Failed { status, stderr } => Err(self.nix_err(format!(
                "`nix {subcommand}` {}{}",
                describe_status(&status),
                describe_stderr(&stderr)
            ))),
            HostCommandResult::Interrupted(signal) => Err(ProviderError::NixInterrupted {
                name: self.name.clone(),
                signal,
            }),
            HostCommandResult::Spawn(e) => {
                Err(self.nix_err(format!("failed to start `nix {subcommand}`: {e}")))
            }
            HostCommandResult::Io(e) => {
                Err(self.nix_err(format!("i/o error while running `nix {subcommand}`: {e}")))
            }
        }
    }

    fn create_staged_flake_dir(
        &self,
        ctx: &ProviderContext,
    ) -> Result<StagedFlakeDir, ProviderError> {
        let pid = std::process::id();
        let parent_dir = if let Some(data_dir) = &ctx.data_dir {
            if let Some(parent) = data_dir.parent() {
                fs::create_dir_all(parent).map_err(|e| {
                    self.nix_err(format!("cannot create {}: {e}", parent.display()))
                })?;
            }
            ensure_private_subdir(data_dir).map_err(|e| self.nix_err(e))?;
            let nix_dir = data_dir.join(NIX_CACHE_DIR);
            ensure_private_subdir(&nix_dir).map_err(|e| self.nix_err(e))?;
            nix_dir
        } else {
            ctx.session_dir.clone()
        };

        for _ in 0..100 {
            let seq = STAGE_SEQ.fetch_add(1, Ordering::Relaxed);
            let dir_name = if ctx.data_dir.is_some() {
                format!(".stage-{pid}-{seq}")
            } else {
                format!("nix-stage-{pid}-{seq}")
            };
            let stage_path = parent_dir.join(dir_name);
            match create_private_dir(&stage_path) {
                Ok(()) => return Ok(StagedFlakeDir { path: stage_path }),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => {
                    return Err(self.nix_err(format!(
                        "cannot create staged flake directory {}: {e}",
                        stage_path.display()
                    )));
                }
            }
        }
        Err(self.nix_err("failed to create a unique temporary staged flake directory"))
    }

    fn stage_flake_tree(
        &self,
        root: &Path,
        src_dir: &Path,
        dst_dir: &Path,
        stack: &mut IgnoreStack,
        staged_entries: &mut usize,
        staged_symlinks: &mut Vec<PathBuf>,
    ) -> Result<(), ProviderError> {
        let read_dir = match fs::read_dir(src_dir) {
            Ok(rd) => rd,
            Err(e) if src_dir != root && e.kind() == io::ErrorKind::PermissionDenied => {
                return Ok(());
            }
            Err(e) => {
                return Err(self.nix_err(format!(
                    "cannot read directory {}: {e}",
                    src_dir.display()
                )));
            }
        };

        let mut entries = Vec::new();
        for item in read_dir {
            *staged_entries = staged_entries.saturating_add(1);
            if *staged_entries > MAX_VALIDATE_WALK_ENTRIES {
                return Err(self.nix_err(format!(
                    "cannot stage flake {}: directory exceeds {MAX_VALIDATE_WALK_ENTRIES} entries",
                    root.display()
                )));
            }
            let entry = item.map_err(|e| {
                self.nix_err(format!(
                    "cannot read directory entry in {}: {e}",
                    src_dir.display()
                ))
            })?;
            entries.push(entry);
        }
        entries.sort_by_key(|e| e.file_name());

        let saved_layers = stack.layer_count();
        let mut resolved_gi_path: Option<PathBuf> = None;

        if self.gitignore
            && let Some(entry) = entries.iter().find(|e| e.file_name() == ".gitignore")
        {
            let full_path = entry.path();
            let ft = entry.file_type().map_err(|e| {
                self.nix_err(format!("cannot inspect {}: {e}", full_path.display()))
            })?;
            let resolved_gi = if ft.is_symlink() {
                fs::canonicalize(&full_path).map_err(|e| {
                    self.nix_err(format!("cannot resolve symlink {}: {e}", full_path.display()))
                })?
            } else {
                full_path.clone()
            };
            let bytes = read_bounded_regular_file(&resolved_gi).map_err(|e| self.nix_err(e))?;
            let content = String::from_utf8_lossy(&bytes);
            let base_rel = src_dir.strip_prefix(root).unwrap_or(Path::new(""));
            stack.push_layer(RuleLayer::from_gitignore_bytes(base_rel, &content));
            resolved_gi_path = Some(resolved_gi);
        }

        for entry in entries {
            let file_name = entry.file_name();
            let name_str = file_name.to_str();
            let full_path = entry.path();
            let ft = entry.file_type().map_err(|e| {
                self.nix_err(format!("cannot inspect {}: {e}", full_path.display()))
            })?;

            let rel = full_path.strip_prefix(root).unwrap_or(&full_path);
            let is_root_flake_entry =
                src_dir == root && matches!(name_str, Some("flake.nix" | "flake.lock"));

            if !is_root_flake_entry && stack.is_ignored(rel, name_str.unwrap_or(""), ft.is_dir()) {
                continue;
            }

            let dst_path = dst_dir.join(&file_name);

            if name_str == Some(".gitignore") && self.gitignore {
                if let Some(ref resolved_gi) = resolved_gi_path {
                    stage_regular_file(resolved_gi, &dst_path).map_err(|r| self.nix_err(r))?;
                }
                continue;
            }

            if ft.is_dir() {
                create_private_dir(&dst_path).map_err(|e| {
                    self.nix_err(format!(
                        "cannot create staged directory {}: {e}",
                        dst_path.display()
                    ))
                })?;
                self.stage_flake_tree(
                    root,
                    &full_path,
                    &dst_path,
                    stack,
                    staged_entries,
                    staged_symlinks,
                )?;
                continue;
            }

            if ft.is_symlink() {
                let raw_target = validate_flake_symlink(root, &full_path)
                    .map_err(|r| self.nix_err(r))?;
                std::os::unix::fs::symlink(&raw_target, &dst_path).map_err(|e| {
                    self.nix_err(format!(
                        "cannot create staged symlink {}: {e}",
                        dst_path.display()
                    ))
                })?;
                staged_symlinks.push(dst_path);
                continue;
            }

            if ft.is_file() {
                stage_regular_file(&full_path, &dst_path).map_err(|r| self.nix_err(r))?;
            }
        }

        stack.truncate(saved_layers);
        Ok(())
    }

    /// Evaluates `target`, writing a GC root to `profile_path`, and returns the
    /// validated [`CachedNixEnv`].
    fn evaluate_uncached(
        &self,
        nix_bin: &Path,
        target: &NixTarget,
        profile_path: &Path,
        ctx: &ProviderContext,
    ) -> Result<CachedNixEnv, ProviderError> {
        let dev_env_bytes = match target {
            NixTarget::Flake { dir } => {
                let staged = self.create_staged_flake_dir(ctx)?;
                check_flake_dir_syntax(&staged.path).map_err(|r| self.nix_err(r))?;
                let staged_str = staged.path.to_str().ok_or_else(|| {
                    self.nix_err(format!(
                        "staged flake directory {:?} is not valid UTF-8",
                        staged.path
                    ))
                })?;

                let mut stack = IgnoreStack::new(&self.ignore);
                let mut staged_entries = 0usize;
                let mut staged_symlinks = Vec::new();
                self.stage_flake_tree(
                    dir,
                    dir,
                    &staged.path,
                    &mut stack,
                    &mut staged_entries,
                    &mut staged_symlinks,
                )?;

                let canonical_staged_root = fs::canonicalize(&staged.path).map_err(|e| {
                    self.nix_err(format!(
                        "cannot canonicalize staged flake directory {}: {e}",
                        staged.path.display()
                    ))
                })?;
                for dst_link in staged_symlinks {
                    let canonical_link = fs::canonicalize(&dst_link).map_err(|e| {
                        self.nix_err(format!(
                            "staged symlink {} failed post-stage resolution: {e}",
                            dst_link.display()
                        ))
                    })?;
                    if !canonical_link.starts_with(&canonical_staged_root) {
                        return Err(self.nix_err(format!(
                            "staged symlink {} escapes staged directory; resolves to {}",
                            dst_link.display(),
                            canonical_link.display()
                        )));
                    }
                }

                let installable = format!(
                    "path:{}",
                    format_flake_installable(staged_str, self.shell.as_ref())
                );
                let args = build_flake_print_dev_env_args(profile_path, &installable);
                self.finish_nix_result("print-dev-env", self.invoke_nix(nix_bin, &args))?
            }
            NixTarget::File { file } => {
                let mut args = vec![
                    OsString::from("--extra-experimental-features"),
                    OsString::from("nix-command flakes"),
                    OsString::from("print-dev-env"),
                    OsString::from("--profile"),
                    profile_path.as_os_str().to_owned(),
                    OsString::from("--json"),
                    OsString::from("--file"),
                    file.as_os_str().to_owned(),
                ];
                if let Some(shell) = &self.shell {
                    args.push(OsString::from(shell.as_str()));
                }
                self.finish_nix_result("print-dev-env", self.invoke_nix(nix_bin, &args))?
            }
        };

        let path_info_args = vec![
            OsString::from("--extra-experimental-features"),
            OsString::from("nix-command flakes"),
            OsString::from("path-info"),
            OsString::from("--recursive"),
            profile_path.as_os_str().to_owned(),
        ];
        let path_info_bytes =
            self.finish_nix_result("path-info", self.invoke_nix(nix_bin, &path_info_args))?;

        let store_paths =
            parse_and_validate_closure(&path_info_bytes).map_err(|reason| self.nix_err(reason))?;
        let parsed_env =
            parse_dev_env_json(&dev_env_bytes).map_err(|reason| self.nix_err(reason))?;

        Ok(CachedNixEnv {
            version: CACHE_FORMAT_VERSION,
            store_paths,
            path_prepend: parsed_env.path_prepend,
            env_set: parsed_env.env_set,
            shell_bin: parsed_env.shell_bin,
            shell_hook: parsed_env.shell_hook,
        })
    }

    /// Computes the SHA-256 cache key for `(nix_bin, nix_meta, target)`, or
    /// returns `Ok(None)` if the source directory exceeds
    /// [`MAX_HASH_WALK_ENTRIES`].
    fn compute_cache_key(
        &self,
        nix_bin: &Path,
        nix_meta: &fs::Metadata,
        target: &NixTarget,
        ctx: &ProviderContext,
    ) -> Result<Option<String>, ProviderError> {
        let mut hasher = Sha256::new();
        hasher.update(CACHE_DOMAIN);
        hash_len_bytes(&mut hasher, nix_bin.as_os_str().as_bytes());
        hasher.update(nix_meta.dev().to_le_bytes());
        hasher.update(nix_meta.ino().to_le_bytes());
        hasher.update(nix_meta.len().to_le_bytes());
        hasher.update(nix_meta.mtime().to_le_bytes());
        hasher.update(nix_meta.mtime_nsec().to_le_bytes());
        hash_len_bytes(&mut hasher, self.profile.as_str().as_bytes());
        match &self.shell {
            Some(s) => {
                hasher.update([1u8]);
                hash_len_bytes(&mut hasher, s.as_str().as_bytes());
            }
            None => hasher.update([0u8]),
        }
        hasher.update([u8::from(self.gitignore)]);
        hasher.update((self.ignore.len() as u64).to_le_bytes());
        for pat in &self.ignore {
            hash_len_bytes(&mut hasher, pat.as_str().as_bytes());
        }

        let mut stack = IgnoreStack::new(&self.ignore);
        let mut visited = 0usize;
        match target {
            NixTarget::Flake { dir } => {
                hasher.update(b"flake\0");
                hash_len_bytes(&mut hasher, dir.as_os_str().as_bytes());
                if !hash_nix_tree(
                    dir,
                    dir,
                    true,
                    self.gitignore,
                    &mut stack,
                    &mut visited,
                    &mut hasher,
                )
                .map_err(|reason| self.nix_err(reason))?
                {
                    return Ok(None);
                }
            }
            NixTarget::File { file } => {
                hasher.update(b"file\0");
                hash_len_bytes(&mut hasher, file.as_os_str().as_bytes());
                match std::env::var_os("NIX_PATH") {
                    Some(np) => {
                        hasher.update([1u8]);
                        hash_len_bytes(&mut hasher, np.as_bytes());
                    }
                    None => hasher.update([0u8]),
                }
                hash_regular_file(file, &mut hasher).map_err(|reason| self.nix_err(reason))?;
                if let Some(parent) = file.parent()
                    && parent != Path::new("/")
                    && parent != ctx.home
                    && !hash_nix_tree(
                        parent,
                        parent,
                        false,
                        self.gitignore,
                        &mut stack,
                        &mut visited,
                        &mut hasher,
                    )
                    .map_err(|reason| self.nix_err(reason))?
                {
                    return Ok(None);
                }
            }
        }

        Ok(Some(hex_encode(hasher.finalize().as_slice())))
    }

    /// Evaluates `target` using the persistent cache under `<data_dir>/nix` when
    /// enabled and available, falling back to a session-lifetime GC root.
    fn resolve_env(
        &self,
        nix_bin: &Path,
        nix_meta: &fs::Metadata,
        target: &NixTarget,
        ctx: &ProviderContext,
    ) -> Result<CachedNixEnv, ProviderError> {
        if self.cache
            && let Some(data_dir) = &ctx.data_dir
            && let Some(key) = self.compute_cache_key(nix_bin, nix_meta, target, ctx)?
        {
            return self.resolve_cached(data_dir, &key, nix_bin, target, ctx);
        }

        // Uncached path: keep the `--profile` GC root in `session_dir` so the
        // closure cannot be garbage-collected while the session is alive.
        let root_dir = ctx.session_dir.join(format!("nix-{}", self.name.as_str()));
        match create_private_dir(&root_dir) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => {
                return Err(self.nix_err(format!(
                    "cannot create session nix directory {}: {e}",
                    root_dir.display()
                )));
            }
        }
        let root_fd =
            open_verified_private_dir(&root_dir).map_err(|reason| self.nix_err(reason))?;
        clear_stale_profile_links_at(&root_dir, &root_fd).map_err(|reason| self.nix_err(reason))?;
        self.evaluate_uncached(nix_bin, target, &root_dir.join("profile"), ctx)
    }

    fn resolve_cached(
        &self,
        data_dir: &Path,
        key: &str,
        nix_bin: &Path,
        target: &NixTarget,
        ctx: &ProviderContext,
    ) -> Result<CachedNixEnv, ProviderError> {
        let entry_dir =
            ensure_cache_entry_dir(data_dir, key).map_err(|reason| self.nix_err(reason))?;
        let entry_fd =
            open_verified_private_dir(&entry_dir).map_err(|reason| self.nix_err(reason))?;

        rustix::fs::flock(&entry_fd, FlockOperation::LockExclusive).map_err(|e| {
            self.nix_err(format!(
                "cannot lock nix cache {}: {e}",
                entry_dir.display()
            ))
        })?;
        let result = self.resolve_cached_locked(&entry_dir, &entry_fd, nix_bin, target, ctx);
        let _ = rustix::fs::flock(&entry_fd, FlockOperation::Unlock);
        result
    }

    fn resolve_cached_locked(
        &self,
        entry_dir: &Path,
        entry_fd: &OwnedFd,
        nix_bin: &Path,
        target: &NixTarget,
        ctx: &ProviderContext,
    ) -> Result<CachedNixEnv, ProviderError> {
        #[cfg(test)]
        let store_root = self.store_check_root.as_deref();
        #[cfg(not(test))]
        let store_root: Option<&Path> = None;

        if let Some(cached) = read_cached_env(entry_dir, entry_fd, store_root)
            .map_err(|reason| self.nix_err(reason))?
        {
            return Ok(cached);
        }

        clear_stale_profile_links_at(entry_dir, entry_fd).map_err(|reason| self.nix_err(reason))?;
        let profile_path = entry_dir.join("profile");
        let fresh = self.evaluate_uncached(nix_bin, target, &profile_path, ctx)?;
        write_cached_env(entry_dir, entry_fd, &fresh).map_err(|reason| self.nix_err(reason))?;
        Ok(fresh)
    }
}

impl Provider for NixProvider {
    fn name(&self) -> &ProviderName {
        &self.name
    }

    fn manifest(&self, ctx: &ProviderContext) -> Result<ProviderOutput, ProviderError> {
        let (target, mut protected) = self.discover_target(ctx)?;

        let Some(target) = target else {
            let _ = self.protected.set(protected);
            return Ok(ProviderOutput {
                profile: self.profile.clone(),
                manifest: Manifest::default(),
                origin: self.origin,
            });
        };

        self.validate_target_inputs(&target, ctx, &mut protected)?;
        let _ = self.protected.set(protected);

        let (nix_bin, nix_meta) = self.resolve_nix_binary(ctx)?;
        let env = self.resolve_env(&nix_bin, &nix_meta, &target, ctx)?;
        let manifest =
            build_manifest(&env, self.shell_hook).map_err(|reason| self.nix_err(reason))?;

        Ok(ProviderOutput {
            profile: self.profile.clone(),
            manifest,
            origin: self.origin,
        })
    }

    fn protected_paths(&self) -> Result<Vec<PathBuf>, ProviderError> {
        self.protected
            .get()
            .cloned()
            .ok_or_else(|| self.nix_err("internal error: protected_paths called before manifest"))
    }
}

struct StagedFlakeDir {
    path: PathBuf,
}

impl Drop for StagedFlakeDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

static STAGE_SEQ: AtomicU64 = AtomicU64::new(0);

const MAX_SYMLINK_HOPS: u32 = 40;

fn resolve_flake_symlink_step(
    canonical_root: &Path,
    cur: &mut PathBuf,
    target: &Path,
    hops_left: &mut u32,
) -> Result<(), ()> {
    if !target.is_relative() || target.as_os_str().is_empty() {
        return Err(());
    }
    for comp in target.components() {
        match comp {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if cur.as_path() == canonical_root {
                    return Err(());
                }
                if !fs::metadata(&*cur).map_err(|_| ())?.is_dir() {
                    return Err(());
                }
                if !cur.pop() {
                    return Err(());
                }
            }
            std::path::Component::Normal(part) => {
                let next = cur.join(part);
                let meta = fs::symlink_metadata(&next).map_err(|_| ())?;
                if meta.is_symlink() {
                    if *hops_left == 0 {
                        return Err(());
                    }
                    *hops_left -= 1;
                    let link_target = fs::read_link(&next).map_err(|_| ())?;
                    resolve_flake_symlink_step(canonical_root, cur, &link_target, hops_left)?;
                } else {
                    *cur = next;
                }
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => return Err(()),
        }
    }
    Ok(())
}

fn validate_flake_symlink(root: &Path, full_path: &Path) -> Result<PathBuf, String> {
    let raw_target = fs::read_link(full_path)
        .map_err(|e| format!("cannot read symbolic link {}: {e}", full_path.display()))?;
    let fail = || {
        format!(
            "cannot stage flake {}: symlink {} -> {} points outside the flake directory or is dangling; remove it or exclude it via `.gitignore` or `ignore`",
            root.display(),
            full_path.display(),
            raw_target.display()
        )
    };
    if !raw_target.is_relative() || raw_target.as_os_str().is_empty() {
        return Err(fail());
    }

    let canonical_root = fs::canonicalize(root)
        .map_err(|e| format!("cannot canonicalize flake root {}: {e}", root.display()))?;
    let parent = full_path.parent().unwrap_or(root);
    let canonical_parent = fs::canonicalize(parent)
        .map_err(|e| format!("cannot canonicalize parent {}: {e}", parent.display()))?;

    let mut cur = canonical_parent;
    let mut hops_left = MAX_SYMLINK_HOPS;
    resolve_flake_symlink_step(&canonical_root, &mut cur, &raw_target, &mut hops_left)
        .map_err(|_| fail())?;

    if !cur.starts_with(&canonical_root) {
        return Err(fail());
    }

    let canonical_final = fs::canonicalize(full_path).map_err(|_| fail())?;
    if !canonical_final.starts_with(&canonical_root) {
        return Err(fail());
    }

    Ok(raw_target)
}

fn stage_regular_file(src_path: &Path, dst_path: &Path) -> Result<(), String> {
    let src_fd = rustix::fs::open(
        src_path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NOCTTY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| format!("cannot open source file {}: {e}", src_path.display()))?;
    let stat = rustix::fs::fstat(&src_fd)
        .map_err(|e| format!("cannot stat source file {}: {e}", src_path.display()))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(format!("{} is not a regular file", src_path.display()));
    }
    let mode = if stat.st_mode & 0o111 != 0 { 0o700 } else { 0o600 };
    let dst_fd = rustix::fs::open(
        dst_path,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(mode),
    )
    .map_err(|e| format!("cannot create staged file {}: {e}", dst_path.display()))?;

    if rustix::fs::ioctl_ficlone(&dst_fd, &src_fd).is_err() {
        let mut src_file = File::from(src_fd);
        let mut dst_file = File::from(dst_fd);
        io::copy(&mut src_file, &mut dst_file)
            .map_err(|e| format!("cannot copy staged file to {}: {e}", dst_path.display()))?;
    }
    Ok(())
}

fn check_flake_dir_syntax(dir: &Path) -> Result<(), String> {
    let s = dir
        .to_str()
        .ok_or_else(|| format!("flake directory {dir:?} is not valid UTF-8"))?;
    if s.contains(['#', '?']) {
        return Err(format!(
            "flake directory {dir:?} contains `#` or `?`, which Nix interprets as flakeref syntax"
        ));
    }
    Ok(())
}

fn format_flake_installable(dir_str: &str, shell: Option<&NixShell>) -> String {
    match shell {
        Some(shell) => format!("{dir_str}#{}", shell.as_str()),
        None => dir_str.to_owned(),
    }
}

fn build_flake_print_dev_env_args(profile_path: &Path, installable: &str) -> Vec<OsString> {
    vec![
        OsString::from("--extra-experimental-features"),
        OsString::from("nix-command flakes"),
        OsString::from("print-dev-env"),
        OsString::from("--no-write-lock-file"),
        OsString::from("--profile"),
        profile_path.as_os_str().to_owned(),
        OsString::from("--json"),
        OsString::from(installable),
    ]
}

/// Parses and validates `nix path-info --recursive` stdout, enforcing the
/// DESIGN.md §3.6 secret-store-path check (`*-etc`, `*-home-manager-files`,
/// `*nix.conf*`).
fn parse_and_validate_closure(bytes: &[u8]) -> Result<Vec<String>, String> {
    let text = std::str::from_utf8(bytes)
        .map_err(|e| format!("`nix path-info` printed invalid UTF-8: {e}"))?;
    let mut store_paths = Vec::new();
    for raw in text.lines() {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if line.is_empty() {
            continue;
        }
        validate_store_path(line)?;
        if !store_paths.iter().any(|p| p == line) {
            store_paths.push(line.to_owned());
        }
    }
    if store_paths.is_empty() {
        return Err("`nix path-info` returned an empty store closure".into());
    }
    Ok(store_paths)
}

fn validate_store_path(path: &str) -> Result<(), String> {
    let Some(entry) = path.strip_prefix("/nix/store/") else {
        return Err(format!(
            "refusing non-store path {path:?} in Nix closure (expected `/nix/store/<hash>-<name>`)"
        ));
    };
    if entry.contains('/') {
        return Err(format!(
            "refusing store subdirectory path {path:?} in Nix closure (expected top-level store object)"
        ));
    }
    let Some((hash, store_name)) = entry.split_once('-') else {
        return Err(format!(
            "refusing malformed store path {path:?} in Nix closure"
        ));
    };
    if store_name.contains('?') {
        return Err(format!(
            "refusing store path {path:?} containing '?' in Nix closure"
        ));
    }
    if hash.len() != 32
        || !hash
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        || store_name.is_empty()
        || !store_name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.' | b'_' | b'='))
    {
        return Err(format!(
            "refusing malformed store path {path:?} in Nix closure"
        ));
    }
    if is_secret_store_name(store_name) {
        return Err(format!(
            "refusing Nix closure containing {path:?} (store paths matching `*-etc`, \
             `*-home-manager-files`, or `*nix.conf*` can expose host secrets)"
        ));
    }
    Ok(())
}

fn is_secret_store_name(store_name: &str) -> bool {
    store_name == "etc"
        || store_name.ends_with("-etc")
        || store_name.contains("home-manager-files")
        || store_name.contains("nix.conf")
}

struct ParsedDevEnv {
    path_prepend: Vec<String>,
    env_set: BTreeMap<String, String>,
    shell_bin: Option<String>,
    shell_hook: Option<String>,
}

/// Parses `nix print-dev-env --json` stdout into [`ParsedDevEnv`].
fn parse_dev_env_json(bytes: &[u8]) -> Result<ParsedDevEnv, String> {
    let parsed: PrintDevEnvJson = serde_json::from_slice(bytes)
        .map_err(|e| format!("`nix print-dev-env --json` printed invalid JSON: {e}"))?;

    let mut path_prepend = Vec::new();
    let mut env_set = BTreeMap::new();
    let mut shell_bin = None;
    let mut shell_hook = None;

    for (name, var) in parsed.variables {
        if matches!(var.kind.as_str(), "exported" | "var") {
            if name == "shell" {
                let val = var.value.as_str().ok_or_else(|| {
                    "variable \"shell\" in `nix print-dev-env --json` does not have a string value"
                        .to_owned()
                })?;
                if !val.is_empty() {
                    ShellHook::new(val.to_owned(), String::new())
                        .map_err(|e| format!("invalid devShell `shell` from nix: {e}"))?;
                    shell_bin = Some(val.to_owned());
                }
                continue;
            }
            if name == "shellHook" {
                let val = var.value.as_str().ok_or_else(|| {
                    "variable \"shellHook\" in `nix print-dev-env --json` does not have a string value"
                        .to_owned()
                })?;
                if val.contains('\0') {
                    return Err("devShell `shellHook` from nix contains a NUL byte".into());
                }
                if !val
                    .trim_matches(|c: char| c.is_ascii_whitespace())
                    .is_empty()
                {
                    shell_hook = Some(val.to_owned());
                }
                continue;
            }
        }
        if var.kind != "exported" {
            continue;
        }
        let val = var.value.as_str().ok_or_else(|| {
            format!("exported variable {name:?} in `nix print-dev-env --json` does not have a string value")
        })?;
        if name == "PATH" {
            for raw_entry in val.split(':') {
                let entry = if raw_entry == "/" {
                    raw_entry
                } else {
                    raw_entry.trim_end_matches('/')
                };
                if entry.is_empty()
                    || entry == "/"
                    || entry == "/path-not-exists"
                    || entry == "/no-such-path"
                {
                    continue;
                }
                entry
                    .parse::<SearchPathEntry>()
                    .map_err(|e| format!("invalid PATH entry {raw_entry:?} from nix: {e}"))?;
                if !path_prepend.iter().any(|p| p == entry) {
                    path_prepend.push(entry.to_owned());
                }
            }
            continue;
        }
        if IGNORED_EXPORTED_VARS.binary_search(&name.as_str()).is_ok()
            || is_dummy_nix_env_value(&name, val)
        {
            continue;
        }
        name.parse::<EnvName>()
            .map_err(|e| format!("invalid exported variable name {name:?} from nix: {e}"))?;
        val.parse::<EnvValue>()
            .map_err(|e| format!("invalid value for exported variable {name:?} from nix: {e}"))?;
        env_set.insert(name, val.to_owned());
    }

    Ok(ParsedDevEnv {
        path_prepend,
        env_set,
        shell_bin,
        shell_hook,
    })
}

fn is_dummy_nix_env_value(name: &str, val: &str) -> bool {
    matches!(
        name,
        "SSL_CERT_FILE" | "NIX_SSL_CERT_FILE" | "GIT_SSL_CAINFO" | "CURL_CA_BUNDLE"
    ) && val == "/no-cert-file.crt"
}

fn scrubbed_nix_host_env_from(
    vars: impl IntoIterator<Item = (OsString, OsString)>,
) -> Vec<(OsString, OsString)> {
    let mut kept = BTreeMap::new();
    for (k, v) in vars {
        if let Some(name) = k.to_str()
            && ALLOWED_NIX_HOST_ENV_VARS.binary_search(&name).is_ok()
        {
            kept.insert(k, v);
        }
    }
    kept.into_iter().collect()
}

fn innermost_untrusted_root(
    path: &Path,
    ctx: &ProviderContext,
) -> Option<crate::spec::UntrustedRoot> {
    let mut best: Option<crate::spec::UntrustedRoot> = None;
    if path.starts_with(&ctx.workspace) {
        best = Some(crate::spec::UntrustedRoot {
            path: ctx.workspace.clone(),
            kind: crate::spec::UntrustedKind::Workspace,
        });
    }
    for root in &ctx.rw_grants {
        if path.starts_with(&root.path)
            && best
                .as_ref()
                .is_none_or(|cur| root.path.as_os_str().len() > cur.path.as_os_str().len())
        {
            best = Some(root.clone());
        }
    }
    best
}

fn dir_contains_nix_inputs(dir: &Path, visited: &mut usize) -> Result<bool, String> {
    let read_dir = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => return Ok(false),
        Err(e) => return Err(format!("cannot read directory {}: {e}", dir.display())),
    };
    for item in read_dir {
        *visited = visited.saturating_add(1);
        if *visited > MAX_VALIDATE_WALK_ENTRIES {
            return Err(format!(
                "cannot validate symlinked directory {}: exceeds {MAX_VALIDATE_WALK_ENTRIES} entries",
                dir.display()
            ));
        }
        let entry =
            item.map_err(|e| format!("cannot read directory entry in {}: {e}", dir.display()))?;
        let file_name = entry.file_name();
        let name_str = file_name.to_str();
        if name_str.is_some_and(|n| n == "flake.lock" || n.ends_with(".nix")) {
            return Ok(true);
        }
        let ft = entry
            .file_type()
            .map_err(|e| format!("cannot inspect {}: {e}", entry.path().display()))?;
        if ft.is_dir()
            && !name_str.is_some_and(|n| IGNORED_VCS_DIRS.contains(&n))
            && dir_contains_nix_inputs(&entry.path(), visited)?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn validate_shell_in_closure(shell: &str, store_paths: &[String]) -> Result<(), String> {
    let Some(after) = shell.strip_prefix("/nix/store/") else {
        return Ok(());
    };
    let top = match after.split_once('/') {
        Some((dir, _)) => format!("/nix/store/{dir}"),
        None => shell.to_owned(),
    };
    validate_store_path(&top)?;
    if !store_paths.iter().any(|sp| sp == &top) {
        return Err(format!(
            "devShell `shell` {shell:?} lies under {top:?}, which is absent from the `nix path-info` closure"
        ));
    }
    Ok(())
}

fn build_manifest(env: &CachedNixEnv, include_shell_hook: bool) -> Result<Manifest, String> {
    let mut manifest = Manifest::default();
    for sp in &env.store_paths {
        validate_store_path(sp)?;
        let pattern: PathPattern = sp
            .parse()
            .map_err(|e| format!("invalid store path rule {sp:?}: {e}"))?;
        manifest.grants.fs.ro.push(pattern);
    }
    for entry in &env.path_prepend {
        let sp: SearchPathEntry = entry
            .parse()
            .map_err(|e| format!("invalid cached PATH entry {entry:?}: {e}"))?;
        manifest.grants.env.path_prepend.push(sp);
    }
    for (k, v) in &env.env_set {
        if k == "PATH"
            || IGNORED_EXPORTED_VARS.binary_search(&k.as_str()).is_ok()
            || is_dummy_nix_env_value(k, v)
        {
            continue;
        }
        let name: EnvName = k
            .parse()
            .map_err(|e| format!("invalid cached env variable {k:?}: {e}"))?;
        let val: EnvValue = v
            .parse()
            .map_err(|e| format!("invalid cached value for {k:?}: {e}"))?;
        manifest.grants.env.set.insert(name, val);
    }
    if include_shell_hook
        && let Some(script) = &env.shell_hook
        && !script
            .trim_matches(|c: char| c.is_ascii_whitespace())
            .is_empty()
    {
        let shell = env.shell_bin.as_deref().unwrap_or("/bin/sh");
        validate_shell_in_closure(shell, &env.store_paths)?;
        let hook = ShellHook::new(shell.to_owned(), script.clone())
            .map_err(|e| format!("invalid cached shellHook: {e}"))?;
        manifest.grants.sandbox.shell_hook = Some(ShellHookSetting::Run(hook));
    }
    Ok(manifest)
}

fn hash_len_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from(DIGITS[usize::from(b >> 4)]));
        s.push(char::from(DIGITS[usize::from(b & 0xf)]));
    }
    s
}

/// Reads a regular file up to [`MAX_NIX_INPUT_BYTES`] without following symlinks or blocking on FIFOs.
fn read_bounded_regular_file(path: &Path) -> Result<Vec<u8>, String> {
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NOCTTY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    let stat = rustix::fs::fstat(&fd)
        .map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(format!("{} is not a regular file", path.display()));
    }
    let limit = u64::try_from(MAX_NIX_INPUT_BYTES).unwrap_or(u64::MAX);
    let mut bytes = Vec::new();
    File::from(fd)
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if bytes.len() > MAX_NIX_INPUT_BYTES {
        return Err(format!(
            "{} exceeds {MAX_NIX_INPUT_BYTES} bytes",
            path.display()
        ));
    }
    Ok(bytes)
}

/// Reads and hashes a regular file without following symlinks or blocking on FIFOs.
fn hash_regular_file(path: &Path, hasher: &mut Sha256) -> Result<(), String> {
    let bytes = read_bounded_regular_file(path)?;
    hash_len_bytes(hasher, &bytes);
    Ok(())
}

/// Walks `dir` deterministically without following symlinks, hashing the
/// relative path and content of every `*.nix`, `flake.lock`, and `.gitignore` entry. Returns
/// `Ok(false)` when [`MAX_HASH_WALK_ENTRIES`] is exceeded.
fn hash_nix_tree(
    root: &Path,
    dir: &Path,
    is_flake: bool,
    gitignore: bool,
    stack: &mut IgnoreStack,
    visited: &mut usize,
    hasher: &mut Sha256,
) -> Result<bool, String> {
    let read_dir = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if dir != root && e.kind() == io::ErrorKind::PermissionDenied => {
            let rel = dir.strip_prefix(root).unwrap_or(dir);
            hasher.update(b"unreadable_dir\0");
            hash_len_bytes(hasher, rel.as_os_str().as_bytes());
            return Ok(true);
        }
        Err(e) => return Err(format!("cannot read directory {}: {e}", dir.display())),
    };
    let mut entries = Vec::new();
    for item in read_dir {
        *visited = visited.saturating_add(1);
        if *visited > MAX_HASH_WALK_ENTRIES {
            return Ok(false);
        }
        let entry =
            item.map_err(|e| format!("cannot read directory entry in {}: {e}", dir.display()))?;
        entries.push(entry);
    }
    entries.sort_by_key(|e| e.file_name());

    let saved_layers = stack.layer_count();

    if gitignore
        && let Some(entry) = entries.iter().find(|e| e.file_name() == ".gitignore")
    {
        let full_path = entry.path();
        let ft = entry
            .file_type()
            .map_err(|e| format!("cannot inspect {}: {e}", full_path.display()))?;
        let resolved_gi = if ft.is_symlink() {
            fs::canonicalize(&full_path)
                .map_err(|e| format!("cannot resolve symlink {}: {e}", full_path.display()))?
        } else {
            full_path.clone()
        };
        let bytes = read_bounded_regular_file(&resolved_gi)?;
        let rel = full_path.strip_prefix(root).unwrap_or(&full_path);
        hasher.update(b"gitignore\0");
        hash_len_bytes(hasher, rel.as_os_str().as_bytes());
        hash_len_bytes(hasher, &bytes);
        let content = String::from_utf8_lossy(&bytes);
        let base_rel = dir.strip_prefix(root).unwrap_or(Path::new(""));
        stack.push_layer(RuleLayer::from_gitignore_bytes(base_rel, &content));
    }

    for entry in entries {
        let file_name = entry.file_name();
        let name_str = file_name.to_str();
        let full_path = entry.path();
        let ft = entry
            .file_type()
            .map_err(|e| format!("cannot inspect {}: {e}", full_path.display()))?;

        if name_str == Some(".gitignore") && gitignore {
            continue;
        }

        let rel = full_path.strip_prefix(root).unwrap_or(&full_path);
        let is_root_flake_entry =
            is_flake && dir == root && matches!(name_str, Some("flake.nix" | "flake.lock"));

        if !is_root_flake_entry && stack.is_ignored(rel, name_str.unwrap_or(""), ft.is_dir()) {
            continue;
        }

        if ft.is_dir() {
            if !hash_nix_tree(
                root,
                &full_path,
                is_flake,
                gitignore,
                stack,
                visited,
                hasher,
            )? {
                stack.truncate(saved_layers);
                return Ok(false);
            }
            continue;
        }

        let is_nix_input = name_str.is_some_and(|n| n == "flake.lock" || n.ends_with(".nix"));
        if !is_nix_input {
            continue;
        }

        hash_len_bytes(hasher, rel.as_os_str().as_bytes());
        if ft.is_symlink() {
            hasher.update(b"symlink\0");
            let target = fs::read_link(&full_path)
                .map_err(|e| format!("cannot read symbolic link {}: {e}", full_path.display()))?;
            hash_len_bytes(hasher, target.as_os_str().as_bytes());
        } else if ft.is_file() {
            hasher.update(b"file\0");
            hash_regular_file(&full_path, hasher)?;
        } else {
            hasher.update(b"other\0");
        }
    }

    stack.truncate(saved_layers);
    Ok(true)
}

fn ensure_private_subdir(dir: &Path) -> Result<(), String> {
    match create_private_dir(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(format!("cannot create {}: {e}", dir.display())),
    }
    check_private_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    Ok(())
}

fn ensure_cache_entry_dir(data_dir: &Path, key: &str) -> Result<PathBuf, String> {
    if let Some(parent) = data_dir.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }
    ensure_private_subdir(data_dir)?;
    let nix_dir = data_dir.join(NIX_CACHE_DIR);
    ensure_private_subdir(&nix_dir)?;
    let entry_dir = nix_dir.join(key);
    ensure_private_subdir(&entry_dir)?;
    Ok(entry_dir)
}

fn open_verified_private_dir(dir: &Path) -> Result<OwnedFd, String> {
    let checked = check_private_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let fd = rustix::fs::open(
        dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| format!("cannot open {}: {e}", dir.display()))?;
    let stat = rustix::fs::fstat(&fd).map_err(|e| format!("cannot stat {}: {e}", dir.display()))?;
    if (stat.st_dev, stat.st_ino) != (checked.dev(), checked.ino()) {
        return Err(format!(
            "{} was replaced while being checked",
            dir.display()
        ));
    }
    Ok(fd)
}

fn read_cached_env(
    entry_dir: &Path,
    entry_fd: &OwnedFd,
    store_check_root: Option<&Path>,
) -> Result<Option<CachedNixEnv>, String> {
    let cache_path = entry_dir.join(CACHE_FILE);
    let fd = match rustix::fs::openat(
        entry_fd,
        CACHE_FILE,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NOCTTY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(None),
        Err(Errno::LOOP) => {
            return Err(format!(
                "refusing to read nix cache {}: it is a symbolic link",
                cache_path.display()
            ));
        }
        Err(e) => {
            return Err(format!(
                "cannot read nix cache {}: {e}",
                cache_path.display()
            ));
        }
    };
    let stat = rustix::fs::fstat(&fd)
        .map_err(|e| format!("cannot stat nix cache {}: {e}", cache_path.display()))?;
    check_store_file(Ownership::of(&stat), rustix::process::getuid().as_raw()).map_err(
        |reason| {
            format!(
                "refusing to read nix cache {}: {reason}",
                cache_path.display()
            )
        },
    )?;

    let mut json = Vec::new();
    File::from(fd)
        .read_to_end(&mut json)
        .map_err(|e| format!("cannot read nix cache {}: {e}", cache_path.display()))?;
    let Ok(cached) = serde_json::from_slice::<CachedNixEnv>(&json) else {
        return Ok(None);
    };
    if cached.version != CACHE_FORMAT_VERSION || cached.store_paths.is_empty() {
        return Ok(None);
    }

    // Verify the GC root profile link and every closure store path still exist.
    if rustix::fs::statat(entry_fd, "profile", AtFlags::empty()).is_err() {
        return Ok(None);
    }
    for sp in &cached.store_paths {
        validate_store_path(sp)?;
        let host_sp = match store_check_root {
            Some(root) => root.join(sp.trim_start_matches("/nix/store/")),
            None => PathBuf::from(sp),
        };
        if fs::symlink_metadata(&host_sp).is_err() {
            return Ok(None);
        }
    }
    Ok(Some(cached))
}

fn write_cached_env(
    entry_dir: &Path,
    entry_fd: &OwnedFd,
    env: &CachedNixEnv,
) -> Result<(), String> {
    let cache_path = entry_dir.join(CACHE_FILE);
    match rustix::fs::unlinkat(entry_fd, CACHE_TEMP_FILE, AtFlags::empty()) {
        Ok(()) | Err(Errno::NOENT) => {}
        Err(e) => {
            return Err(format!(
                "cannot clean temporary nix cache in {}: {e}",
                entry_dir.display()
            ));
        }
    }
    let fd = rustix::fs::openat(
        entry_fd,
        CACHE_TEMP_FILE,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(CACHE_FILE_MODE),
    )
    .map_err(|e| format!("cannot create nix cache {}: {e}", cache_path.display()))?;

    let mut json = serde_json::to_vec_pretty(env).expect("CachedNixEnv serializes");
    json.push(b'\n');

    let written = (|| -> Result<(), String> {
        rustix::fs::fchmod(&fd, Mode::from_raw_mode(CACHE_FILE_MODE))
            .map_err(|e| format!("cannot set mode on nix cache {}: {e}", cache_path.display()))?;
        let mut file = File::from(fd);
        file.write_all(&json)
            .and_then(|()| file.sync_all())
            .map_err(|e| format!("cannot write nix cache {}: {e}", cache_path.display()))?;
        drop(file);

        rustix::fs::renameat(entry_fd, CACHE_TEMP_FILE, entry_fd, CACHE_FILE)
            .map_err(|e| format!("cannot finalize nix cache {}: {e}", cache_path.display()))?;
        rustix::fs::fsync(entry_fd).map_err(|e| {
            format!(
                "cannot sync nix cache directory {}: {e}",
                entry_dir.display()
            )
        })?;
        Ok(())
    })();

    if let Err(err) = written {
        let _ = rustix::fs::unlinkat(entry_fd, CACHE_TEMP_FILE, AtFlags::empty());
        return Err(err);
    }
    Ok(())
}

fn clear_stale_profile_links_at(entry_dir: &Path, entry_fd: &OwnedFd) -> Result<(), String> {
    let dir_fd = rustix::fs::openat(
        entry_fd,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| {
        format!(
            "cannot open {} for profile cleanup: {e}",
            entry_dir.display()
        )
    })?;
    let dir = rustix::fs::Dir::read_from(dir_fd).map_err(|e| {
        format!(
            "cannot read {} for profile cleanup: {e}",
            entry_dir.display()
        )
    })?;
    let mut names = Vec::new();
    for item in dir {
        let entry =
            item.map_err(|e| format!("cannot read entry in {}: {e}", entry_dir.display()))?;
        if let Ok(name) = entry.file_name().to_str()
            && (name == "profile" || name.starts_with("profile-"))
        {
            names.push(name.to_owned());
        }
    }
    for name in names {
        match rustix::fs::unlinkat(entry_fd, &name, AtFlags::empty()) {
            Ok(()) | Err(Errno::NOENT) => {}
            Err(e) => {
                return Err(format!(
                    "cannot remove stale nix profile entry {}/{name}: {e}",
                    entry_dir.display()
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};
    use tempfile::TempDir;

    use super::*;
    use crate::spec::{UntrustedKind, UntrustedRoot};

    const HASH_A: &str = "00000000000000000000000000000001";
    const HASH_B: &str = "00000000000000000000000000000002";

    fn write_fake_nix(dir: &Path, body: &str) -> PathBuf {
        let _guard = super::super::script::EXEC_LOCK
            .write()
            .unwrap_or_else(|e| e.into_inner());
        let path = dir.join("nix");
        fs::write(&path, format!("#!/bin/sh\nset -eu\n{body}")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    struct TestFixture {
        _tmp: TempDir,
        root: PathBuf,
        ws: PathBuf,
        home: PathBuf,
        session: PathBuf,
        data: PathBuf,
        bin: PathBuf,
    }

    impl TestFixture {
        fn new() -> Self {
            let tmp = TempDir::new().unwrap();
            let root = fs::canonicalize(tmp.path()).unwrap();
            let ws = root.join("ws");
            let home = root.join("home");
            let session = root.join("session");
            let data = root.join("data");
            let bin = root.join("bin");
            for d in [&ws, &home, &session, &bin] {
                fs::create_dir_all(d).unwrap();
                fs::set_permissions(d, fs::Permissions::from_mode(0o700)).unwrap();
            }
            TestFixture {
                _tmp: tmp,
                root,
                ws,
                home,
                session,
                data,
                bin,
            }
        }

        fn ctx(&self) -> ProviderContext {
            ProviderContext {
                workspace: self.ws.clone(),
                workspace_mount: "/workspace".parse().unwrap(),
                home: self.home.clone(),
                session_dir: self.session.clone(),
                data_dir: Some(self.data.clone()),
                rw_grants: Vec::new(),
            }
        }

        fn provider(&self, nix_bin: &Path) -> NixProvider {
            NixProvider::new(
                "nix".parse().unwrap(),
                "main".parse::<ProfileRef>().unwrap(),
                None,
                None,
                None,
                true,
                &self.ws,
            )
            .with_nix_program(nix_bin)
        }
    }

    #[test]
    fn sorted_tables_are_in_ascii_order_for_binary_search() {
        for pair in IGNORED_EXPORTED_VARS.windows(2) {
            assert!(
                pair[0] < pair[1],
                "IGNORED_EXPORTED_VARS out of order: {:?} >= {:?}",
                pair[0],
                pair[1]
            );
        }
        for pair in ALLOWED_NIX_HOST_ENV_VARS.windows(2) {
            assert!(
                pair[0] < pair[1],
                "ALLOWED_NIX_HOST_ENV_VARS out of order: {:?} >= {:?}",
                pair[0],
                pair[1]
            );
        }
    }

    #[test]
    fn noop_when_no_flake_or_shell_nix_and_errors_when_shell_is_explicit() {
        let f = TestFixture::new();
        // `default.nix` alone is not auto-detected unless `file = "default.nix"` is set.
        fs::write(f.ws.join("default.nix"), "{}").unwrap();
        let nix_bin = write_fake_nix(&f.bin, "exit 99\n");

        let p = f.provider(&nix_bin);
        let out = p.manifest(&f.ctx()).unwrap();
        assert_eq!(out.manifest, Manifest::default());
        assert!(p.protected_paths().unwrap().is_empty());

        // Requesting a specific `shell` without a `flake.nix` or `shell.nix` fails startup.
        let p_named = NixProvider::new(
            "nix".parse().unwrap(),
            "main".parse::<ProfileRef>().unwrap(),
            Some("agent".parse().unwrap()),
            None,
            None,
            true,
            &f.ws,
        )
        .with_nix_program(&nix_bin);
        let err = p_named.manifest(&f.ctx()).unwrap_err();
        assert!(
            err.to_string()
                .contains("neither flake.nix nor shell.nix exists"),
            "{err}"
        );
    }

    #[test]
    fn flake_default_and_named_shell_with_env_filtering_and_protection() {
        let f = TestFixture::new();
        fs::write(f.ws.join("flake.nix"), "{}").unwrap();
        fs::write(f.ws.join("flake.lock"), "{}").unwrap();
        // When both exist, `flake.nix` wins over `shell.nix`.
        fs::write(f.ws.join("shell.nix"), "{}").unwrap();

        let store_a = format!("/nix/store/{HASH_A}-rustc-1.90.0");
        let store_b = format!("/nix/store/{HASH_B}-gcc-wrapper-15.0");
        let args_log = f.root.join("args.log");
        let nix_bin = write_fake_nix(
            &f.bin,
            &format!(
                r#"printf '%s\n' "$*" >> {log:?}
if [ "$3" = "print-dev-env" ]; then
  staged="${{8#path:}}"
  staged="${{staged%#agent}}"
  if [ ! -f "$staged/flake.nix" ]; then
    echo "staged flake.nix not found in $staged" >&2
    exit 1
  fi
  # "$6" is the --profile target
  ln -s /bin/sh "$6"
  cat <<'JSON'
{{
  "variables": {{
    "PATH": {{"type": "exported", "value": "{store_a}/bin:{store_b}/bin/:{store_a}/bin:/path-not-exists"}},
    "CC": {{"type": "exported", "value": "gcc"}},
    "RUST_SRC_PATH": {{"type": "exported", "value": "{store_a}/lib/rustlib/src"}},
    "HOME": {{"type": "exported", "value": "/homeless-shelter"}},
    "TMPDIR": {{"type": "exported", "value": "/build"}},
    "SHELL": {{"type": "exported", "value": "/nix/store/x/bin/bash"}},
    "shellHook": {{"type": "exported", "value": "echo pwned"}},
    "out": {{"type": "exported", "value": "/nix/store/x-env"}},
    "postUnpackHooks": {{"type": "array", "value": ["hookA"]}},
    "localOnly": {{"type": "var", "value": "ignored"}}
  }}
}}
JSON
elif [ "$3" = "path-info" ]; then
  printf '%s\n%s\n' "{store_a}" "{store_b}"
else
  exit 2
fi
"#,
                log = args_log
            ),
        );

        let p = NixProvider::new(
            "nix".parse().unwrap(),
            "harness".parse().unwrap(),
            Some("agent".parse().unwrap()),
            None,
            None,
            false,
            &f.ws,
        )
        .with_nix_program(&nix_bin);

        let out = p.manifest(&f.ctx()).unwrap();
        assert_eq!(out.profile.as_str(), "harness");
        let ro: Vec<&str> = out
            .manifest
            .grants
            .fs
            .ro
            .iter()
            .map(|p| p.as_str())
            .collect();
        assert_eq!(ro, [store_a.as_str(), store_b.as_str()]);
        let path_prepend: Vec<&str> = out
            .manifest
            .grants
            .env
            .path_prepend
            .iter()
            .map(|p| p.as_str())
            .collect();
        assert_eq!(
            path_prepend,
            [
                format!("{store_a}/bin").as_str(),
                format!("{store_b}/bin").as_str()
            ]
        );
        let env_set: BTreeMap<&str, &str> = out
            .manifest
            .grants
            .env
            .set
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert_eq!(
            env_set,
            BTreeMap::from([
                ("CC", "gcc"),
                (
                    "RUST_SRC_PATH",
                    format!("{store_a}/lib/rustlib/src").as_str()
                ),
            ])
        );
        assert_eq!(
            p.protected_paths().unwrap(),
            [f.ws.join("flake.nix"), f.ws.join("flake.lock")]
        );

        let logged = fs::read_to_string(&args_log).unwrap();
        assert!(
            logged.contains(&format!(
                "print-dev-env --no-write-lock-file --profile {} --json path:",
                f.session.join("nix-nix/profile").display(),
            )) && logged.contains("#agent"),
            "{logged}"
        );

        let session_staged: Vec<_> = fs::read_dir(&f.session)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .filter(|n| n.starts_with(".stage-") || n.starts_with("nix-stage-"))
            .collect();
        assert!(session_staged.is_empty(), "{session_staged:?}");
        let data_nix = f.data.join(NIX_CACHE_DIR);
        if let Ok(rd) = fs::read_dir(&data_nix) {
            let data_staged: Vec<_> = rd
                .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
                .filter(|n| n.starts_with(".stage-") || n.starts_with("nix-stage-"))
                .collect();
            assert!(data_staged.is_empty(), "{data_staged:?}");
        }
    }

    #[test]
    fn reftable_flake_error_retries_with_path_prefix() {
        let f = TestFixture::new();
        fs::write(f.ws.join("flake.nix"), "{}").unwrap();
        let store_a = format!("/nix/store/{HASH_A}-hello-1.0");
        let call_count_file = f.root.join("calls.log");
        let nix_bin = write_fake_nix(
            &f.bin,
            &format!(
                r#"echo "$3 ${{8:-}}" >> {log:?}
if [ "$3" = "print-dev-env" ]; then
  case "$8" in
    path:*)
      ln -s /bin/sh "$6"
      printf '{{"variables": {{"PATH": {{"type": "exported", "value": "{store_a}/bin"}}}}}}'
      ;;
    *)
      echo "error: expected path: installable on first attempt" >&2
      exit 1
      ;;
  esac
elif [ "$3" = "path-info" ]; then
  printf '%s\n' "{store_a}"
fi
"#,
                log = call_count_file
            ),
        );

        let p = f.provider(&nix_bin);
        let out = p.manifest(&f.ctx()).unwrap();
        assert_eq!(out.manifest.grants.fs.ro.len(), 1);
        let calls = fs::read_to_string(&call_count_file).unwrap();
        let lines: Vec<&str> = calls.lines().collect();
        assert_eq!(lines.len(), 2, "{calls}");
        assert!(lines[0].starts_with("print-dev-env path:"), "{calls}");
        assert!(lines[1].starts_with("path-info"), "{calls}");
    }

    #[test]
    fn shell_nix_and_explicit_file_and_flake_options() {
        let f = TestFixture::new();
        fs::write(f.ws.join("shell.nix"), "{}").unwrap();
        fs::write(f.ws.join("default.nix"), "{}").unwrap();
        let ext_flake = f.root.join("ext-flake");
        fs::create_dir(&ext_flake).unwrap();
        fs::write(ext_flake.join("flake.nix"), "{}").unwrap();

        let store_a = format!("/nix/store/{HASH_A}-tools-1.0");
        let args_log = f.root.join("args.log");
        let nix_bin = write_fake_nix(
            &f.bin,
            &format!(
                r#"printf '%s\n' "$*" >> {log:?}
if [ "$3" = "print-dev-env" ]; then
  # Find --profile argument
  prev=""
  for a in "$@"; do
    if [ "$prev" = "--profile" ]; then
      ln -s /bin/sh "$a"
    fi
    prev="$a"
  done
  printf '{{"variables": {{"PATH": {{"type": "exported", "value": "{store_a}/bin"}}}}}}'
elif [ "$3" = "path-info" ]; then
  printf '%s\n' "{store_a}"
fi
"#,
                log = args_log
            ),
        );

        // 1. Auto-detect falls back to `shell.nix` when `flake.nix` is absent.
        let p_shell = NixProvider::new(
            "nix".parse().unwrap(),
            "main".parse::<ProfileRef>().unwrap(),
            None,
            None,
            None,
            false,
            &f.ws,
        )
        .with_nix_program(&nix_bin);
        p_shell.manifest(&f.ctx()).unwrap();
        assert_eq!(p_shell.protected_paths().unwrap(), [f.ws.join("shell.nix")]);

        // 2. Explicit `file = "default.nix"` with `shell = "ci"`.
        let p_file = NixProvider::new(
            "nix".parse().unwrap(),
            "main".parse::<ProfileRef>().unwrap(),
            Some("ci".parse().unwrap()),
            Some("default.nix".parse().unwrap()),
            None,
            false,
            &f.ws,
        )
        .with_nix_program(&nix_bin);
        p_file.manifest(&f.ctx()).unwrap();
        assert_eq!(
            p_file.protected_paths().unwrap(),
            [f.ws.join("default.nix")]
        );

        // 3. Explicit external `flake` protects both the directory and `flake.nix`.
        let p_ext = NixProvider::new(
            "nix".parse().unwrap(),
            "main".parse::<ProfileRef>().unwrap(),
            None,
            None,
            Some(ext_flake.to_str().unwrap().parse().unwrap()),
            false,
            &f.ws,
        )
        .with_nix_program(&nix_bin);
        p_ext.manifest(&f.ctx()).unwrap();
        assert_eq!(
            p_ext.protected_paths().unwrap(),
            [ext_flake.clone(), ext_flake.join("flake.nix")]
        );

        let logged = fs::read_to_string(&args_log).unwrap();
        assert!(
            logged.contains(&format!("--file {}", f.ws.join("shell.nix").display())),
            "{logged}"
        );
        assert!(
            logged.contains(&format!("--file {} ci", f.ws.join("default.nix").display())),
            "{logged}"
        );
    }

    #[test]
    fn secret_and_malformed_store_paths_are_refused() {
        for bad in [
            format!("/nix/store/{HASH_A}-etc"),
            format!("/nix/store/{HASH_A}-nixos-etc"),
            format!("/nix/store/{HASH_A}-home-manager-files"),
            format!("/nix/store/{HASH_A}-user-home-manager-files"),
            format!("/nix/store/{HASH_A}-nix.conf"),
            format!("/nix/store/{HASH_A}-custom-nix.conf-gen"),
            "/etc/passwd".to_owned(),
            format!("/nix/store/{HASH_A}-pkg/bin"),
            format!("/nix/store/{HASH_A}-bad?pkg"),
            "/nix/store/short-pkg".to_owned(),
        ] {
            let err = validate_store_path(&bad).unwrap_err();
            assert!(err.contains(&bad), "{bad}: {err}");
        }
        assert!(validate_store_path(&format!("/nix/store/{HASH_A}-etcetera-1.0")).is_ok());
    }

    #[test]
    fn symlinks_and_hard_links_on_nix_inputs_are_refused() {
        let f = TestFixture::new();
        let outside = f.root.join("outside.nix");
        fs::write(&outside, "{}").unwrap();
        let nix_bin = write_fake_nix(&f.bin, "exit 99\n");

        // Symlink `flake.nix` inside the workspace is refused with a `nix`-specific error.
        symlink(&outside, f.ws.join("flake.nix")).unwrap();
        let err = f.provider(&nix_bin).manifest(&f.ctx()).unwrap_err();
        assert!(matches!(err, ProviderError::Nix { .. }), "{err:?}");
        let msg = err.to_string();
        assert!(msg.contains("nix provider \"nix\""), "{msg}");
        assert!(!msg.contains("script provider"), "{msg}");
        assert!(msg.contains("runs through symlink"), "{msg}");
        fs::remove_file(f.ws.join("flake.nix")).unwrap();

        // Symlink inside a static `rw` grant on explicit `file` is refused.
        let rw = f.root.join("rw");
        fs::create_dir(&rw).unwrap();
        symlink(&outside, rw.join("shell.nix")).unwrap();
        let mut ctx = f.ctx();
        ctx.rw_grants.push(UntrustedRoot {
            path: rw.clone(),
            kind: UntrustedKind::RwGrant {
                provider: "cfg".parse().unwrap(),
                profile: Some("main".parse::<ProfileRef>().unwrap()),
                host: rw.clone(),
            },
        });
        let p_rw = NixProvider::new(
            "nix".parse().unwrap(),
            "main".parse::<ProfileRef>().unwrap(),
            None,
            Some(rw.join("shell.nix").to_str().unwrap().parse().unwrap()),
            None,
            false,
            &f.ws,
        )
        .with_nix_program(&nix_bin);
        let err = p_rw.manifest(&ctx).unwrap_err();
        assert!(matches!(err, ProviderError::Nix { .. }), "{err:?}");
        assert!(err.to_string().contains("runs through symlink"), "{err}");

        // Regular `flake.nix` with rewritable hard link is refused.
        let real = f.ws.join("flake.nix");
        fs::write(&real, "{}").unwrap();
        fs::hard_link(&real, f.ws.join("other-link.txt")).unwrap();
        let err = f.provider(&nix_bin).manifest(&f.ctx()).unwrap_err();
        assert!(matches!(err, ProviderError::Nix { .. }), "{err:?}");
        assert!(err.to_string().contains("hard links"), "{err}");
        fs::remove_file(f.ws.join("other-link.txt")).unwrap();

        // Imported subdirectory `.nix` symlink (`nix/dev.nix -> ../writable.txt`) is refused
        // even when `cache = false`.
        let p_uncached = NixProvider::new(
            "nix".parse().unwrap(),
            "main".parse::<ProfileRef>().unwrap(),
            None,
            None,
            None,
            false,
            &f.ws,
        )
        .with_nix_program(&nix_bin);
        fs::create_dir(f.ws.join("nix")).unwrap();
        fs::write(f.ws.join("writable.txt"), "{}").unwrap();
        symlink("../writable.txt", f.ws.join("nix/dev.nix")).unwrap();
        let err = p_uncached.manifest(&f.ctx()).unwrap_err();
        assert!(err.to_string().contains("runs through symlink"), "{err}");
        fs::remove_file(f.ws.join("nix/dev.nix")).unwrap();

        // Imported subdirectory `.nix` regular file with rewritable hard link is refused.
        fs::write(f.ws.join("nix/dev.nix"), "{}").unwrap();
        fs::hard_link(f.ws.join("nix/dev.nix"), f.ws.join("scratch.txt")).unwrap();
        let err = p_uncached.manifest(&f.ctx()).unwrap_err();
        assert!(err.to_string().contains("hard links"), "{err}");
        fs::remove_file(f.ws.join("scratch.txt")).unwrap();
        fs::remove_dir_all(f.ws.join("nix")).unwrap();

        // Directory symlink inside the workspace pointing to a directory containing `.nix`
        // files is refused, while a directory symlink with no `.nix` files is allowed.
        let ext_with_nix = f.root.join("ext-with-nix");
        fs::create_dir(&ext_with_nix).unwrap();
        fs::write(ext_with_nix.join("imported.nix"), "{}").unwrap();
        symlink(&ext_with_nix, f.ws.join("nix-link")).unwrap();
        let err = p_uncached.manifest(&f.ctx()).unwrap_err();
        assert!(err.to_string().contains("runs through symlink"), "{err}");
        fs::remove_file(f.ws.join("nix-link")).unwrap();
    }

    #[test]
    fn path_discovery_skips_untrusted_segments_and_scrubs_secrets_and_dummy_certs() {
        let f = TestFixture::new();
        fs::write(f.ws.join("flake.nix"), "{}").unwrap();

        // Place a poisoned `nix` inside the workspace and inside an `rw` grant, plus a
        // relative segment; none of them may execute.
        write_fake_nix(&f.ws, "echo poisoned-ws >&2; exit 91\n");
        let rw_dir = f.root.join("rw-bin");
        fs::create_dir(&rw_dir).unwrap();
        write_fake_nix(&rw_dir, "echo poisoned-rw >&2; exit 92\n");

        // Place the real `nix` behind a trusted symlink (`trusted-link/nix -> real-bin/nix`)
        // to verify post-resolution canonical path and metadata.
        let real_bin_dir = f.root.join("real-bin");
        let link_bin_dir = f.root.join("link-bin");
        fs::create_dir(&real_bin_dir).unwrap();
        fs::create_dir(&link_bin_dir).unwrap();
        let store_a = format!("/nix/store/{HASH_A}-ca-1.0");
        let env_dump = f.root.join("host-env.txt");
        let real_nix = write_fake_nix(
            &real_bin_dir,
            &format!(
                r#"env > {env_dump:?}
if [ "$3" = "print-dev-env" ]; then
  ln -sf /bin/sh "$6"
  cat <<'JSON'
{{
  "variables": {{
    "PATH": {{"type": "exported", "value": "{store_a}/bin"}},
    "SSL_CERT_FILE": {{"type": "exported", "value": "/no-cert-file.crt"}},
    "NIX_SSL_CERT_FILE": {{"type": "exported", "value": "/no-cert-file.crt"}},
    "CURL_CA_BUNDLE": {{"type": "exported", "value": "{store_a}/etc/ssl/certs/ca-bundle.crt"}},
    "HTTP_PROXY": {{"type": "exported", "value": "http://evil:8080"}},
    "https_proxy": {{"type": "exported", "value": "http://evil:8080"}},
    "CC": {{"type": "exported", "value": "clang"}}
  }}
}}
JSON
elif [ "$3" = "path-info" ]; then
  printf '%s\n' "{store_a}"
fi
"#,
                env_dump = env_dump,
                store_a = store_a,
            ),
        );
        symlink(&real_nix, link_bin_dir.join("nix")).unwrap();

        let mut ctx = f.ctx();
        ctx.rw_grants.push(UntrustedRoot {
            path: rw_dir.clone(),
            kind: UntrustedKind::RwGrant {
                provider: "cfg".parse().unwrap(),
                profile: Some("main".parse::<ProfileRef>().unwrap()),
                host: rw_dir.clone(),
            },
        });

        let custom_path = format!(
            ":relative/bin:{}:{}:{}",
            f.ws.display(),
            rw_dir.display(),
            link_bin_dir.display()
        );
        let p = NixProvider::new(
            "nix".parse().unwrap(),
            "main".parse::<ProfileRef>().unwrap(),
            None,
            None,
            None,
            false,
            &f.ws,
        )
        .with_path_env(custom_path)
        .with_extra_host_env([
            ("GITHUB_TOKEN", "ghp_supersecret"),
            ("AWS_SECRET_ACCESS_KEY", "aws_supersecret"),
            ("NIX_CONFIG", "access-tokens = github.com=secret"),
            ("SSH_AUTH_SOCK", "/tmp/agent.sock"),
            (
                "NIX_PATH",
                "nixpkgs=/nix/var/nix/profiles/per-user/root/channels/nixos",
            ),
        ]);

        let (resolved_bin, _) = p.resolve_nix_binary(&ctx).unwrap();
        assert_eq!(resolved_bin, real_nix);

        let out = p.manifest(&ctx).unwrap();
        let env_set: BTreeMap<&str, &str> = out
            .manifest
            .grants
            .env
            .set
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        // Dummy `/no-cert-file.crt` and proxy variables are stripped, while real cert paths remain.
        assert_eq!(
            env_set,
            BTreeMap::from([
                ("CC", "clang"),
                (
                    "CURL_CA_BUNDLE",
                    format!("{store_a}/etc/ssl/certs/ca-bundle.crt").as_str()
                ),
            ])
        );

        // Host secrets and `NIX_CONFIG` never reached the `nix` child process.
        let child_env = fs::read_to_string(&env_dump).unwrap();
        assert!(!child_env.contains("GITHUB_TOKEN"), "{child_env}");
        assert!(!child_env.contains("AWS_SECRET_ACCESS_KEY"), "{child_env}");
        assert!(!child_env.contains("NIX_CONFIG"), "{child_env}");
        assert!(!child_env.contains("SSH_AUTH_SOCK"), "{child_env}");
        assert!(child_env.contains("NIX_PATH="), "{child_env}");

        // Calling `protected_paths()` before `manifest()` returns an explicit error instead of
        // running `fs::canonicalize`.
        let fresh_p = NixProvider::new(
            "nix".parse().unwrap(),
            "main".parse::<ProfileRef>().unwrap(),
            None,
            Some("shell.nix".parse().unwrap()),
            None,
            false,
            &f.ws,
        );
        assert!(fresh_p.protected_paths().is_err());

        // A hard-linked `nix` binary is refused.
        fs::hard_link(&real_nix, f.ws.join("nix-hardlink")).unwrap();
        let err = p.resolve_nix_binary(&ctx).unwrap_err();
        assert!(err.to_string().contains("hard links"), "{err}");
    }

    #[test]
    fn persistent_cache_hits_invalidates_on_edits_and_recovers_from_gc() {
        let f = TestFixture::new();
        fs::write(f.ws.join("flake.nix"), "{ description = \"v1\"; }").unwrap();
        fs::create_dir(f.ws.join("nix")).unwrap();
        fs::write(f.ws.join("nix/dev.nix"), "{ a = 1; }").unwrap();

        let fake_store_root = f.root.join("nix-store");
        let obj_name = format!("{HASH_A}-hello-1.0");
        let host_obj = fake_store_root.join(&obj_name);
        fs::create_dir_all(&host_obj).unwrap();
        let store_path = format!("/nix/store/{obj_name}");

        let counter = f.root.join("calls");
        let nix_bin = write_fake_nix(
            &f.bin,
            &format!(
                r#"count=0
if [ -f {counter:?} ]; then
  count=$(cat {counter:?})
fi
count=$((count + 1))
printf '%s' "$count" > {counter:?}
if [ "$3" = "print-dev-env" ]; then
  ln -sf {host_obj:?} "$6"
  printf '{{"variables": {{"PATH": {{"type": "exported", "value": "{store}/bin"}}, "MY_VAR": {{"type": "exported", "value": "val"}}}}}}'
elif [ "$3" = "path-info" ]; then
  printf '%s\n' "{store}"
fi
"#,
                counter = counter,
                host_obj = host_obj,
                store = store_path
            ),
        );

        let make_provider = || f.provider(&nix_bin).with_store_check_root(&fake_store_root);
        let calls = || {
            fs::read_to_string(&counter)
                .ok()
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(0)
        };

        // 1. Cold evaluation runs `print-dev-env` + `path-info` (2 invocations).
        let out1 = make_provider().manifest(&f.ctx()).unwrap();
        assert_eq!(calls(), 2);

        // 2. Warm evaluation hits persistent cache (0 new nix invocations).
        let out2 = make_provider().manifest(&f.ctx()).unwrap();
        assert_eq!(calls(), 2);
        assert_eq!(out1, out2);

        // 3. Modifying an imported `nix/dev.nix` invalidates the cache.
        fs::write(f.ws.join("nix/dev.nix"), "{ a = 2; }").unwrap();
        make_provider().manifest(&f.ctx()).unwrap();
        assert_eq!(calls(), 4);

        // 4. Removing the cached GC root symlink triggers transparent re-evaluation.
        for entry in fs::read_dir(f.data.join("nix")).unwrap().flatten() {
            let prof = entry.path().join("profile");
            if prof.symlink_metadata().is_ok() {
                fs::remove_file(prof).unwrap();
            }
        }
        make_provider().manifest(&f.ctx()).unwrap();
        assert_eq!(calls(), 6);

        // 5. Removing the underlying store object also invalidates the cache.
        fs::remove_dir_all(&host_obj).unwrap();
        // Recreate right before nix runs? No: have fake nix recreate it on eval!
        let nix_bin_recreate = write_fake_nix(
            &f.bin,
            &format!(
                r#"count=$(cat {counter:?})
count=$((count + 1))
printf '%s' "$count" > {counter:?}
mkdir -p {host_obj:?}
if [ "$3" = "print-dev-env" ]; then
  ln -sf {host_obj:?} "$6"
  printf '{{"variables": {{"PATH": {{"type": "exported", "value": "{store}/bin"}}, "MY_VAR": {{"type": "exported", "value": "val"}}}}}}'
elif [ "$3" = "path-info" ]; then
  printf '%s\n' "{store}"
fi
"#,
                counter = counter,
                host_obj = host_obj,
                store = store_path
            ),
        );
        f.provider(&nix_bin_recreate)
            .with_store_check_root(&fake_store_root)
            .manifest(&f.ctx())
            .unwrap();
        assert_eq!(calls(), 8);

        // 6. Group-readable `cache.json` is refused as untrusted.
        for entry in fs::read_dir(f.data.join("nix")).unwrap().flatten() {
            let cache_json = entry.path().join("cache.json");
            if cache_json.exists() {
                fs::set_permissions(&cache_json, fs::Permissions::from_mode(0o644)).unwrap();
            }
        }
        let err = f
            .provider(&nix_bin_recreate)
            .with_store_check_root(&fake_store_root)
            .manifest(&f.ctx())
            .unwrap_err();
        assert!(
            err.to_string().contains("refusing to read nix cache"),
            "{err}"
        );
    }

    #[test]
    fn shell_hook_emitted_by_default_skipped_when_disabled_and_validates_store_shell() {
        let f = TestFixture::new();
        fs::write(f.ws.join("flake.nix"), "{}").unwrap();
        let store_bash = "/nix/store/00000000000000000000000000000001-bash-5.2";
        let missing_bash = "/nix/store/00000000000000000000000000000002-bash-5.2";

        let nix_bin = write_fake_nix(
            &f.bin,
            &format!(
                r#"if [ "$3" = "print-dev-env" ]; then
  ln -sf /bin/sh "$6"
  cat <<'JSON'
{{
  "variables": {{
    "PATH": {{"type": "exported", "value": "{store_bash}/bin"}},
    "shell": {{"type": "exported", "value": "{store_bash}/bin/bash"}},
    "shellHook": {{"type": "exported", "value": "export FOO=bar"}}
  }}
}}
JSON
elif [ "$3" = "path-info" ]; then
  printf '%s\n' "{store_bash}"
fi
"#
            ),
        );

        let p_on = NixProvider::new(
            "nix".parse().unwrap(),
            "main".parse().unwrap(),
            None,
            None,
            None,
            false,
            &f.ws,
        )
        .with_nix_program(&nix_bin);
        let out_on = p_on.manifest(&f.ctx()).unwrap();
        assert_eq!(
            out_on.manifest.grants.sandbox.shell_hook,
            Some(ShellHookSetting::Run(
                ShellHook::new(format!("{store_bash}/bin/bash"), "export FOO=bar".into()).unwrap()
            ))
        );

        let out_off = p_on.with_shell_hook(false).manifest(&f.ctx()).unwrap();
        assert_eq!(out_off.manifest.grants.sandbox.shell_hook, None);

        // Whitespace-only shellHook produces None.
        let parsed_ws = parse_dev_env_json(
            br#"{"variables": {"shellHook": {"type": "exported", "value": "  \n\t  "}}}"#,
        )
        .unwrap();
        assert_eq!(parsed_ws.shell_hook, None);

        // Store shell absent from `nix path-info` closure fails closed when enabled.
        let nix_bad_shell = write_fake_nix(
            &f.bin,
            &format!(
                r#"if [ "$3" = "print-dev-env" ]; then
  ln -sf /bin/sh "$6"
  printf '{{"variables": {{"shell": {{"type": "exported", "value": "{missing_bash}/bin/bash"}}, "shellHook": {{"type": "exported", "value": "export X=1"}}}}}}'
elif [ "$3" = "path-info" ]; then
  printf '%s\n' "{store_bash}"
fi
"#
            ),
        );
        let err = NixProvider::new(
            "nix".parse().unwrap(),
            "main".parse().unwrap(),
            None,
            None,
            None,
            false,
            &f.ws,
        )
        .with_nix_program(&nix_bad_shell)
        .manifest(&f.ctx())
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("absent from the `nix path-info` closure"),
            "{err}"
        );
    }

    #[test]
    fn gitignored_tree_skips_out_of_store_symlinks_and_protects_gitignore() {
        let f = TestFixture::new();
        fs::write(f.ws.join("flake.nix"), "{}").unwrap();
        fs::write(f.ws.join("flake.lock"), "{}").unwrap();
        fs::write(f.ws.join(".gitignore"), "buck-out/\n").unwrap();
        let sub = f.ws.join("sub");
        fs::create_dir(&sub).unwrap();
        fs::write(sub.join(".gitignore"), "ignored.txt\n").unwrap();
        fs::write(sub.join("kept.txt"), "hello").unwrap();
        symlink("../flake.nix", sub.join("rel-link")).unwrap();

        let buck_out = f.ws.join("buck-out");
        fs::create_dir(&buck_out).unwrap();
        // Populate buck-out with out-of-store, dangling, and symlinked .nix files:
        let outside = f.root.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("foo.nix"), "{}").unwrap();
        symlink(outside.join("foo.nix"), buck_out.join("foo.nix")).unwrap();
        symlink("/nix/store/dummy", buck_out.join("store-link")).unwrap();
        symlink("nonexistent", buck_out.join("dangling")).unwrap();

        // Also add .git and .jj
        fs::create_dir(f.ws.join(".git")).unwrap();
        fs::create_dir(f.ws.join(".jj")).unwrap();

        let store_a = format!("/nix/store/{HASH_A}-test-1.0");
        let nix_bin = write_fake_nix(
            &f.bin,
            &format!(
                r#"if [ "$3" = "print-dev-env" ]; then
  staged="${{8#path:}}"
  # Verify staged contents:
  [ -f "$staged/flake.nix" ] || exit 10
  [ -f "$staged/flake.lock" ] || exit 11
  [ -f "$staged/.gitignore" ] || exit 12
  [ -f "$staged/sub/kept.txt" ] || exit 13
  [ -L "$staged/sub/rel-link" ] || exit 14
  [ ! -e "$staged/sub/ignored.txt" ] || exit 15
  [ ! -e "$staged/buck-out" ] || exit 16
  [ ! -e "$staged/.git" ] || exit 17
  [ ! -e "$staged/.jj" ] || exit 18
  ln -s /bin/sh "$6"
  printf '{{"variables": {{"PATH": {{"type": "exported", "value": "{store_a}/bin"}}}}}}'
elif [ "$3" = "path-info" ]; then
  printf '%s\n' "{store_a}"
fi
"#
            ),
        );

        let p = f.provider(&nix_bin);
        let out = p.manifest(&f.ctx()).unwrap();
        assert_eq!(out.manifest.grants.fs.ro.len(), 1);

        // Verify protected_paths includes flake.nix, flake.lock, and both .gitignore files
        let prot = p.protected_paths().unwrap();
        assert!(prot.contains(&f.ws.join("flake.nix")));
        assert!(prot.contains(&f.ws.join("flake.lock")));
        assert!(prot.contains(&f.ws.join(".gitignore")));
        assert!(prot.contains(&sub.join(".gitignore")));

        // Verify no staging dir remained
        let data_nix = f.data.join(NIX_CACHE_DIR);
        if let Ok(rd) = fs::read_dir(&data_nix) {
            let data_staged: Vec<_> = rd
                .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
                .filter(|n| n.starts_with(".stage-") || n.starts_with("nix-stage-"))
                .collect();
            assert!(data_staged.is_empty(), "{data_staged:?}");
        }
    }

    #[test]
    fn gitignore_disabled_with_custom_ignore() {
        let f = TestFixture::new();
        fs::write(f.ws.join("flake.nix"), "{}").unwrap();
        fs::write(f.ws.join("flake.lock"), "{}").unwrap();
        fs::write(f.ws.join(".gitignore"), "buck-out/\n").unwrap();
        fs::write(f.ws.join("app.log"), "log").unwrap();
        let buck_out = f.ws.join("buck-out");
        fs::create_dir(&buck_out).unwrap();
        symlink("nonexistent", buck_out.join("dangling")).unwrap();

        let store_a = format!("/nix/store/{HASH_A}-test-1.0");
        let nix_bin = write_fake_nix(
            &f.bin,
            &format!(
                r#"if [ "$3" = "print-dev-env" ]; then
  staged="${{8#path:}}"
  [ -f "$staged/flake.nix" ] || exit 10
  [ ! -e "$staged/buck-out" ] || exit 11
  [ ! -e "$staged/app.log" ] || exit 12
  ln -s /bin/sh "$6"
  printf '{{"variables": {{"PATH": {{"type": "exported", "value": "{store_a}/bin"}}}}}}'
elif [ "$3" = "path-info" ]; then
  printf '%s\n' "{store_a}"
fi
"#
            ),
        );

        // 1. With gitignore = false and no ignore: buck-out/dangling causes manifest to fail
        let p_fail = f.provider(&nix_bin).with_gitignore(false);
        let err = p_fail.manifest(&f.ctx()).unwrap_err();
        assert!(err.to_string().contains("symlink"), "{err}");
        assert!(err.to_string().contains("dangling"), "{err}");

        // 2. With gitignore = false and ignore = ["buck-out", "*.log"]: manifest succeeds and excludes app.log
        let p_ok = f
            .provider(&nix_bin)
            .with_gitignore(false)
            .with_ignore(vec!["buck-out".parse().unwrap(), "*.log".parse().unwrap()]);
        let out = p_ok.manifest(&f.ctx()).unwrap();
        assert_eq!(out.manifest.grants.fs.ro.len(), 1);
    }

    #[test]
    fn non_ignored_invalid_symlinks_fail_closed_with_remedy() {
        let f = TestFixture::new();
        fs::write(f.ws.join("flake.nix"), "{}").unwrap();
        let store_a = format!("/nix/store/{HASH_A}-test-1.0");
        let nix_bin = write_fake_nix(
            &f.bin,
            &format!(
                r#"if [ "$3" = "print-dev-env" ]; then
  ln -s /bin/sh "$6"
  printf '{{"variables": {{"PATH": {{"type": "exported", "value": "{store_a}/bin"}}}}}}'
elif [ "$3" = "path-info" ]; then
  printf '%s\n' "{store_a}"
fi
"#
            ),
        );

        // Case A: absolute symlink
        let abs_link = f.ws.join("abs-link");
        symlink("/etc/hosts", &abs_link).unwrap();
        let err_abs = f.provider(&nix_bin).manifest(&f.ctx()).unwrap_err();
        assert!(
            err_abs.to_string().contains("points outside the flake directory or is dangling; remove it or exclude it via `.gitignore` or `ignore`"),
            "{err_abs}"
        );
        fs::remove_file(&abs_link).unwrap();

        // Case B: dangling relative symlink
        let dgl_link = f.ws.join("dgl-link");
        symlink("missing_file", &dgl_link).unwrap();
        let err_dgl = f.provider(&nix_bin).manifest(&f.ctx()).unwrap_err();
        assert!(
            err_dgl.to_string().contains("points outside the flake directory or is dangling; remove it or exclude it via `.gitignore` or `ignore`"),
            "{err_dgl}"
        );
        fs::remove_file(&dgl_link).unwrap();

        // Case C: parent-escaping relative symlink
        let sub = f.ws.join("sub");
        fs::create_dir(&sub).unwrap();
        let sneaky = sub.join("sneaky");
        symlink("../../outside", &sneaky).unwrap();
        let err_sneaky = f.provider(&nix_bin).manifest(&f.ctx()).unwrap_err();
        assert!(
            err_sneaky.to_string().contains("points outside the flake directory or is dangling; remove it or exclude it via `.gitignore` or `ignore`"),
            "{err_sneaky}"
        );
        fs::remove_file(&sneaky).unwrap();

        // Case D: trailing slash on a symlink to a regular file (kernel ENOTDIR)
        let slash_link = f.ws.join("link");
        symlink("flake.nix/", &slash_link).unwrap();
        let err_slash = f.provider(&nix_bin).manifest(&f.ctx()).unwrap_err();
        assert!(
            err_slash.to_string().contains("points outside the flake directory or is dangling; remove it or exclude it via `.gitignore` or `ignore`"),
            "{err_slash}"
        );
        fs::remove_file(&slash_link).unwrap();

        // Case E: `..` applied to a non-directory (kernel ENOTDIR)
        let link_a = f.ws.join("a");
        let link_b = f.ws.join("b");
        symlink("flake.nix", &link_a).unwrap();
        symlink("a/..", &link_b).unwrap();
        let err_notdir = f.provider(&nix_bin).manifest(&f.ctx()).unwrap_err();
        assert!(
            err_notdir.to_string().contains("points outside the flake directory or is dangling; remove it or exclude it via `.gitignore` or `ignore`"),
            "{err_notdir}"
        );
        fs::remove_file(&link_a).unwrap();
        fs::remove_file(&link_b).unwrap();

        // Staging directory must be cleaned up on failure
        let data_nix = f.data.join(NIX_CACHE_DIR);
        if let Ok(rd) = fs::read_dir(&data_nix) {
            let data_staged: Vec<_> = rd
                .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
                .filter(|n| n.starts_with(".stage-") || n.starts_with("nix-stage-"))
                .collect();
            assert!(data_staged.is_empty(), "{data_staged:?}");
        }
    }

    #[test]
    fn untrusted_gitignore_symlinks_and_hard_links_are_refused() {
        let f = TestFixture::new();
        fs::write(f.ws.join("flake.nix"), "{}").unwrap();
        let outside = f.root.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join(".gitignore"), "target/\n").unwrap();

        let store_a = format!("/nix/store/{HASH_A}-test-1.0");
        let nix_bin = write_fake_nix(
            &f.bin,
            &format!(
                r#"if [ "$3" = "print-dev-env" ]; then
  ln -s /bin/sh "$6"
  printf '{{"variables": {{"PATH": {{"type": "exported", "value": "{store_a}/bin"}}}}}}'
elif [ "$3" = "path-info" ]; then
  printf '%s\n' "{store_a}"
fi
"#
            ),
        );

        // Symlinked .gitignore inside workspace is refused
        symlink(outside.join(".gitignore"), f.ws.join(".gitignore")).unwrap();
        let err = f.provider(&nix_bin).manifest(&f.ctx()).unwrap_err();
        assert!(err.to_string().contains("runs through symlink"), "{err}");
        fs::remove_file(f.ws.join(".gitignore")).unwrap();

        // Hard-linked writable .gitignore (nlink > 1) is refused
        let gi = f.ws.join(".gitignore");
        fs::write(&gi, "target/\n").unwrap();
        let gi_alias = f.ws.join("gi_alias");
        fs::hard_link(&gi, &gi_alias).unwrap();
        let err_hl = f.provider(&nix_bin).manifest(&f.ctx()).unwrap_err();
        assert!(err_hl.to_string().contains("hard links"), "{err_hl}");
        fs::remove_file(&gi_alias).unwrap();
        fs::remove_file(&gi).unwrap();

        // A directory named .gitignore fails closed instead of being skipped
        let sub = f.ws.join("sub");
        fs::create_dir_all(sub.join(".gitignore")).unwrap();
        fs::write(sub.join(".gitignore").join("evil.nix"), "{}").unwrap();
        let err_dir = f.provider(&nix_bin).manifest(&f.ctx()).unwrap_err();
        assert!(err_dir.to_string().contains("not a regular file"), "{err_dir}");
    }

    #[test]
    fn cache_key_invalidated_by_gitignore_and_ignore_settings() {
        let f = TestFixture::new();
        fs::write(f.ws.join("flake.nix"), "{}").unwrap();
        fs::write(f.ws.join(".gitignore"), "target/\n").unwrap();

        let fake_store_root = f.root.join("nix-store");
        let obj_name = format!("{HASH_A}-test-1.0");
        let host_obj = fake_store_root.join(&obj_name);
        fs::create_dir_all(&host_obj).unwrap();
        let store_a = format!("/nix/store/{obj_name}");

        let call_count_file = f.root.join("calls.log");
        let nix_bin = write_fake_nix(
            &f.bin,
            &format!(
                r#"echo "$3" >> {log:?}
if [ "$3" = "print-dev-env" ]; then
  ln -sf {host_obj:?} "$6"
  printf '{{"variables": {{"PATH": {{"type": "exported", "value": "{store_a}/bin"}}}}}}'
elif [ "$3" = "path-info" ]; then
  printf '%s\n' "{store_a}"
fi
"#,
                log = call_count_file,
                host_obj = host_obj,
                store_a = store_a,
            ),
        );

        let make_provider = || f.provider(&nix_bin).with_store_check_root(&fake_store_root);

        // 1. Initial run: evaluates and caches
        let p1 = make_provider();
        let out1 = p1.manifest(&f.ctx()).unwrap();
        assert_eq!(out1.manifest.grants.fs.ro.len(), 1);
        let count1 = fs::read_to_string(&call_count_file).unwrap().lines().count();
        assert_eq!(count1, 2);

        // 2. Second run: cache hit, no nix commands run
        let p2 = make_provider();
        let out2 = p2.manifest(&f.ctx()).unwrap();
        assert_eq!(out2.manifest.grants.fs.ro.len(), 1);
        let count2 = fs::read_to_string(&call_count_file).unwrap().lines().count();
        assert_eq!(count2, 2);

        // 3. Edit .gitignore: cache invalidated, re-evaluates
        fs::write(f.ws.join(".gitignore"), "target/\nbuild/\n").unwrap();
        let p3 = make_provider();
        let out3 = p3.manifest(&f.ctx()).unwrap();
        assert_eq!(out3.manifest.grants.fs.ro.len(), 1);
        let count3 = fs::read_to_string(&call_count_file).unwrap().lines().count();
        assert_eq!(count3, 4);

        // 4. Toggle gitignore = false: cache invalidated, re-evaluates
        let p4 = make_provider().with_gitignore(false);
        let out4 = p4.manifest(&f.ctx()).unwrap();
        assert_eq!(out4.manifest.grants.fs.ro.len(), 1);
        let count4 = fs::read_to_string(&call_count_file).unwrap().lines().count();
        assert_eq!(count4, 6);

        // 5. Change ignore = [...]: cache invalidated, re-evaluates
        let p5 = make_provider()
            .with_ignore(vec!["buck-out".parse().unwrap()]);
        let out5 = p5.manifest(&f.ctx()).unwrap();
        assert_eq!(out5.manifest.grants.fs.ro.len(), 1);
        let count5 = fs::read_to_string(&call_count_file).unwrap().lines().count();
        assert_eq!(count5, 8);
    }

    #[test]
    fn trusted_symlink_gitignore_validates_protects_and_stages() {
        let f = TestFixture::new();
        let flake_dir = f.root.join("flake");
        fs::create_dir(&flake_dir).unwrap();
        fs::write(flake_dir.join("flake.nix"), "{}").unwrap();
        fs::write(flake_dir.join("ignored.txt"), "secret").unwrap();

        let shared_gi = f.root.join("shared.gitignore");
        fs::write(&shared_gi, "ignored.txt\n").unwrap();
        symlink("../shared.gitignore", flake_dir.join(".gitignore")).unwrap();

        let store_a = format!("/nix/store/{HASH_A}-test-1.0");
        let nix_bin = write_fake_nix(
            &f.bin,
            &format!(
                r#"if [ "$3" = "print-dev-env" ]; then
  staged="${{8#path:}}"
  [ -f "$staged/flake.nix" ] || exit 10
  [ ! -e "$staged/ignored.txt" ] || exit 11
  [ -f "$staged/.gitignore" ] || exit 12
  ln -s /bin/sh "$6"
  printf '{{"variables": {{"PATH": {{"type": "exported", "value": "{store_a}/bin"}}}}}}'
elif [ "$3" = "path-info" ]; then
  printf '%s\n' "{store_a}"
fi
"#
            ),
        );

        let p = NixProvider::new(
            "nix".parse().unwrap(),
            "main".parse().unwrap(),
            None,
            None,
            Some("flake".parse().unwrap()),
            true,
            &f.root,
        )
        .with_nix_program(&nix_bin);

        let out = p.manifest(&f.ctx()).unwrap();
        assert_eq!(out.manifest.grants.fs.ro.len(), 1);

        let protected = p.protected_paths().unwrap();
        let canonical_shared = fs::canonicalize(&shared_gi).unwrap();
        assert!(protected.contains(&canonical_shared), "{protected:?}");
    }

    #[test]
    fn symlink_chain_escape_via_parent_fails_closed() {
        let f = TestFixture::new();
        fs::write(f.ws.join("flake.nix"), "{}").unwrap();
        let sub = f.ws.join("sub");
        fs::create_dir(&sub).unwrap();
        symlink("..", sub.join("up")).unwrap();

        let ws_name = f.ws.file_name().unwrap().to_str().unwrap();
        let escape_target = format!("sub/up/../{ws_name}/flake.nix");
        symlink(&escape_target, f.ws.join("escape")).unwrap();

        let store_a = format!("/nix/store/{HASH_A}-test-1.0");
        let nix_bin = write_fake_nix(
            &f.bin,
            &format!(
                r#"if [ "$3" = "print-dev-env" ]; then
  ln -s /bin/sh "$6"
  printf '{{"variables": {{"PATH": {{"type": "exported", "value": "{store_a}/bin"}}}}}}'
elif [ "$3" = "path-info" ]; then
  printf '%s\n' "{store_a}"
fi
"#
            ),
        );

        let err = f.provider(&nix_bin).manifest(&f.ctx()).unwrap_err();
        assert!(
            err.to_string().contains("points outside the flake directory or is dangling"),
            "{err}"
        );
    }

    #[test]
    fn root_flake_nix_and_lock_never_ignored_by_gitignore() {
        let f = TestFixture::new();
        fs::write(f.ws.join("flake.nix"), "{}").unwrap();
        fs::write(f.ws.join("flake.lock"), "{ \"version\": 1 }").unwrap();
        fs::write(f.ws.join("other.nix"), "{}").unwrap();
        fs::write(f.ws.join(".gitignore"), "*\n").unwrap();

        let store_a = format!("/nix/store/{HASH_A}-test-1.0");
        let fake_store_root = f.root.join("nix-store");
        let obj_name = format!("{HASH_A}-test-1.0");
        let host_obj = fake_store_root.join(&obj_name);
        fs::create_dir_all(&host_obj).unwrap();

        let calls = f.root.join("calls.log");
        let nix_bin = write_fake_nix(
            &f.bin,
            &format!(
                r#"echo "$3" >> {calls:?}
if [ "$3" = "print-dev-env" ]; then
  staged="${{8#path:}}"
  [ -f "$staged/flake.nix" ] || exit 10
  [ -f "$staged/flake.lock" ] || exit 11
  [ ! -e "$staged/other.nix" ] || exit 12
  ln -sf {host_obj:?} "$6"
  printf '{{"variables": {{"PATH": {{"type": "exported", "value": "{store_a}/bin"}}}}}}'
elif [ "$3" = "path-info" ]; then
  printf '%s\n' "{store_a}"
fi
"#,
                calls = calls,
                host_obj = host_obj,
                store_a = store_a,
            ),
        );

        let make_p = || f.provider(&nix_bin).with_store_check_root(&fake_store_root);
        let out = make_p().manifest(&f.ctx()).unwrap();
        assert_eq!(out.manifest.grants.fs.ro.len(), 1);
        let c1 = fs::read_to_string(&calls).unwrap().lines().count();
        assert_eq!(c1, 2);

        // Cache hit
        make_p().manifest(&f.ctx()).unwrap();
        let c2 = fs::read_to_string(&calls).unwrap().lines().count();
        assert_eq!(c2, 2);

        // Invalidate by modifying flake.lock
        fs::write(f.ws.join("flake.lock"), "{ \"version\": 2 }").unwrap();
        make_p().manifest(&f.ctx()).unwrap();
        let c3 = fs::read_to_string(&calls).unwrap().lines().count();
        assert_eq!(c3, 4);
    }

    #[test]
    fn empty_gitignore_and_regular_file_dotgit_worktree_supported() {
        let f = TestFixture::new();
        fs::write(f.ws.join("flake.nix"), "{}").unwrap();
        fs::write(f.ws.join(".gitignore"), "").unwrap();
        fs::write(f.ws.join(".git"), "gitdir: /outside/worktrees/ws\n").unwrap();

        let store_a = format!("/nix/store/{HASH_A}-test-1.0");
        let nix_bin = write_fake_nix(
            &f.bin,
            &format!(
                r#"if [ "$3" = "print-dev-env" ]; then
  staged="${{8#path:}}"
  [ -f "$staged/flake.nix" ] || exit 10
  [ -f "$staged/.gitignore" ] || exit 11
  [ ! -e "$staged/.git" ] || exit 12
  ln -s /bin/sh "$6"
  printf '{{"variables": {{"PATH": {{"type": "exported", "value": "{store_a}/bin"}}}}}}'
elif [ "$3" = "path-info" ]; then
  printf '%s\n' "{store_a}"
fi
"#
            ),
        );

        let out = f.provider(&nix_bin).manifest(&f.ctx()).unwrap();
        assert_eq!(out.manifest.grants.fs.ro.len(), 1);
    }
}
