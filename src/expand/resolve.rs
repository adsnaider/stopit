//! Resolving expanded patterns against the host filesystem (DESIGN.md §3.4,
//! §11).
//!
//! Globs are evaluated once, at session start: [`resolve`] turns an
//! [`ExpandedPattern`] into the host/sandbox path pairs that exist right now.
//! Files created later are not picked up.
//!
//! Every anchor resolves alike. Symlinks on the way to a path are followed
//! as the kernel follows them, and the final component of a match is never
//! followed; whether a link was one a sandbox may have planted is decided
//! later, against the session's untrusted roots (`crate::spec`; DESIGN.md
//! §3.4, Symlinks). The walk never follows symlinks below the walk root (a
//! symlinked directory could point anywhere or form a loop) and never
//! consults `.gitignore` or other ignore files: secrets such as `.env` are
//! typically gitignored and must still be found.

use std::collections::HashMap;
use std::fs::FileType;
use std::io;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use thiserror::Error;
use walkdir::WalkDir;

use super::{ExpandError, ExpandedPattern, join};
use crate::error::is_missing;
use crate::manifest::{compile_glob, has_glob};

/// What kind of filesystem entry a resolved path is, as reported by
/// `symlink_metadata` (the final symlink is never followed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntryKind {
    /// A regular file.
    File,
    /// A directory.
    Dir,
    /// A symbolic link (never followed).
    Symlink,
    /// A unix socket.
    Socket,
    /// Anything else: FIFOs, device nodes.
    Other,
}

impl EntryKind {
    /// The kind of an entry of file type `ft`.
    pub(crate) fn from_file_type(ft: FileType) -> Self {
        if ft.is_symlink() {
            EntryKind::Symlink
        } else if ft.is_dir() {
            EntryKind::Dir
        } else if ft.is_file() {
            EntryKind::File
        } else if ft.is_socket() {
            EntryKind::Socket
        } else {
            EntryKind::Other
        }
    }
}

/// A concrete host path that exists, and where it appears in the sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPath {
    /// The host path.
    pub host: PathBuf,
    /// The sandbox path.
    pub sandbox: PathBuf,
    /// The kind of entry at `host`.
    pub kind: EntryKind,
}

fn clone_io_error(error: &io::Error) -> io::Error {
    match error.raw_os_error() {
        Some(code) => io::Error::from_raw_os_error(code),
        None => io::Error::new(error.kind(), error.to_string()),
    }
}

/// A non-fatal problem found while resolving a pattern.
#[derive(Debug, Error)]
pub enum ResolveWarning {
    /// A literal path, or the walk root of a glob, does not exist, or an
    /// entry vanished during a glob walk. The path is skipped.
    #[error("{path:?} does not exist")]
    Missing {
        /// The missing host path.
        path: PathBuf,
    },
    /// A path could not be inspected, or a directory could not be read
    /// during a walk. Resolution continues without it.
    #[error("cannot access {path:?}: {error}")]
    Io {
        /// The host path that could not be inspected or read.
        path: PathBuf,
        /// The underlying error.
        #[source]
        error: io::Error,
    },
}

impl Clone for ResolveWarning {
    fn clone(&self) -> Self {
        match self {
            ResolveWarning::Missing { path } => ResolveWarning::Missing { path: path.clone() },
            ResolveWarning::Io { path, error } => ResolveWarning::Io {
                path: path.clone(),
                error: clone_io_error(error),
            },
        }
    }
}

/// The outcome of [`resolve`].
#[derive(Debug, Clone, Default)]
pub struct Resolution {
    /// The matching paths, sorted by host path and deduplicated.
    pub paths: Vec<ResolvedPath>,
    /// Non-fatal problems, in the order they were found.
    pub warnings: Vec<ResolveWarning>,
}

/// Host-side identity of one expanded exclude pattern, used to key
/// [`ResolveCache`] entries.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum ExcludeKey {
    Literal(PathBuf),
    Glob { root: PathBuf, remainder: String },
}

impl ExcludeKey {
    fn from_expanded(pattern: &ExpandedPattern) -> Self {
        if pattern.has_glob() {
            let split = split_glob(pattern);
            ExcludeKey::Glob {
                root: split.root,
                remainder: split.remainder,
            }
        } else {
            ExcludeKey::Literal(join(pattern.host_anchor(), pattern.rest()))
        }
    }
}

fn exclude_keys(excludes: &[ExpandedPattern]) -> Vec<ExcludeKey> {
    if excludes.is_empty() {
        return Vec::new();
    }
    let mut keys: Vec<ExcludeKey> = excludes.iter().map(ExcludeKey::from_expanded).collect();
    keys.sort();
    keys.dedup();
    keys
}

enum CompiledExclude {
    Literal(PathBuf),
    Glob {
        root: PathBuf,
        matcher: globset::GlobMatcher,
    },
}

/// Compiled host-side exclude rules used to prune `WalkDir` traversal.
struct ExcludeSet {
    rules: Vec<CompiledExclude>,
}

impl ExcludeSet {
    fn compile(keys: &[ExcludeKey]) -> Result<Self, ExpandError> {
        let mut rules = Vec::with_capacity(keys.len());
        for key in keys {
            match key {
                ExcludeKey::Literal(host) => {
                    rules.push(CompiledExclude::Literal(host.clone()));
                }
                ExcludeKey::Glob { root, remainder } => {
                    let matcher =
                        compile_glob(remainder).map_err(|error| ExpandError::InvalidGlob {
                            pattern: join(root, Path::new(remainder)),
                            error,
                        })?;
                    rules.push(CompiledExclude::Glob {
                        root: root.clone(),
                        matcher,
                    });
                }
            }
        }
        Ok(ExcludeSet { rules })
    }

    /// Whether `entry_path` (lexical host path reported by `WalkDir`) matches
    /// an excluded path or lies inside an excluded directory subtree.
    fn is_excluded(&self, entry_path: &Path) -> bool {
        self.rules.iter().any(|rule| match rule {
            CompiledExclude::Literal(x_host) => entry_path.starts_with(x_host),
            CompiledExclude::Glob { root, matcher } => {
                let Ok(rel) = entry_path.strip_prefix(root) else {
                    return false;
                };
                rel.ancestors()
                    .take_while(|a| !a.as_os_str().is_empty())
                    .any(|a| matcher.is_match(a))
            }
        })
    }
}

struct SplitGlob {
    prefix: PathBuf,
    root: PathBuf,
    remainder: String,
    remainder_components: usize,
}

fn split_glob(pattern: &ExpandedPattern) -> SplitGlob {
    // `rest` comes from a validated UTF-8 pattern, so this is lossless.
    let rest = pattern.rest().to_string_lossy();
    let components: Vec<&str> = rest.split('/').collect();
    let split = components
        .iter()
        .position(|c| has_glob(c))
        .expect("split_glob is only called for glob patterns");
    let prefix = PathBuf::from(components[..split].join("/"));
    let root = join(pattern.host_anchor(), &prefix);
    debug_assert_eq!(pattern.walk_root().as_ref(), Some(&root));
    let remainder = components[split..].join("/");
    SplitGlob {
        prefix,
        root,
        remainder,
        remainder_components: components.len() - split,
    }
}

type WalkCacheKey = (PathBuf, Option<usize>, Vec<ExcludeKey>);
type ResolutionCacheKey = (ExpandedPattern, Vec<ExcludeKey>);

/// Per-compile cache of glob directory walks and pattern resolutions.
#[derive(Debug, Default)]
pub struct ResolveCache {
    walks: HashMap<WalkCacheKey, Arc<CachedWalk>>,
    resolutions: HashMap<ResolutionCacheKey, Resolution>,
    symlink_metas: HashMap<PathBuf, Result<EntryKind, io::Error>>,
}

impl Clone for ResolveCache {
    fn clone(&self) -> Self {
        let symlink_metas = self
            .symlink_metas
            .iter()
            .map(|(k, v)| {
                let cloned = match v {
                    Ok(kind) => Ok(*kind),
                    Err(err) => Err(clone_io_error(err)),
                };
                (k.clone(), cloned)
            })
            .collect();
        ResolveCache {
            walks: self.walks.clone(),
            resolutions: self.resolutions.clone(),
            symlink_metas,
        }
    }
}

#[derive(Debug)]
enum CachedWalk {
    RootError(io::Error),
    Steps(Vec<WalkStep>),
}

#[derive(Debug)]
enum WalkStep {
    Entry {
        host: PathBuf,
        relative: PathBuf,
        kind: EntryKind,
    },
    Error {
        path: PathBuf,
        error: io::Error,
    },
}

impl ResolveCache {
    /// Caches `path.symlink_metadata()` across rules and profiles within a
    /// single compile pass.
    pub(crate) fn symlink_metadata(&mut self, path: &Path) -> Result<EntryKind, io::Error> {
        if let Some(res) = self.symlink_metas.get(path) {
            return match res {
                Ok(kind) => Ok(*kind),
                Err(err) => Err(clone_io_error(err)),
            };
        }
        let res = path
            .symlink_metadata()
            .map(|meta| EntryKind::from_file_type(meta.file_type()));
        let stored = match &res {
            Ok(kind) => Ok(*kind),
            Err(err) => Err(clone_io_error(err)),
        };
        self.symlink_metas.insert(path.to_owned(), stored);
        res
    }

    fn walk(
        &mut self,
        root: &Path,
        max_depth: Option<usize>,
        excludes: &[ExcludeKey],
    ) -> Result<Arc<CachedWalk>, ExpandError> {
        let key = (root.to_owned(), max_depth, excludes.to_vec());
        if let Some(cached) = self.walks.get(&key) {
            return Ok(cached.clone());
        }
        let exclude_set = ExcludeSet::compile(excludes)?;
        let built = if exclude_set.is_excluded(root) {
            CachedWalk::Steps(Vec::new())
        } else {
            match root.metadata() {
                Err(error) => CachedWalk::RootError(error),
                Ok(_) => {
                    let mut walk = WalkDir::new(root)
                        .follow_links(false)
                        // The root is on the way to every match, like the components before
                        // it, so a link there is followed; links below it never are.
                        .follow_root_links(true)
                        .min_depth(1);
                    if let Some(d) = max_depth {
                        walk = walk.max_depth(d);
                    }
                    let mut steps = Vec::new();
                    let iter = walk
                        .into_iter()
                        .filter_entry(|entry| !exclude_set.is_excluded(entry.path()));
                    for entry in iter {
                        match entry {
                            Ok(entry) => {
                                let relative = entry
                                    .path()
                                    .strip_prefix(root)
                                    .expect("walkdir yields paths below its root")
                                    .to_owned();
                                let kind = EntryKind::from_file_type(entry.file_type());
                                let host = entry.into_path();
                                steps.push(WalkStep::Entry {
                                    host,
                                    relative,
                                    kind,
                                });
                            }
                            Err(err) => {
                                // Constructing a `DirEntry` can fail before `filter_entry`
                                // runs (for example, if `lstat` fails when `readdir` omits
                                // `d_type` or an entry vanishes concurrently).
                                if err.path().is_some_and(|path| exclude_set.is_excluded(path)) {
                                    continue;
                                }
                                let path = err.path().unwrap_or(root).to_owned();
                                steps.push(WalkStep::Error {
                                    path,
                                    error: err.into(),
                                });
                            }
                        }
                    }
                    CachedWalk::Steps(steps)
                }
            }
        };
        let arc = Arc::new(built);
        self.walks.insert(key, arc.clone());
        Ok(arc)
    }
}

impl Resolution {
    /// Records an error inspecting `failing` while resolving `original`:
    /// a missing path, or one that runs through a non-directory, is
    /// `Missing`; anything else is `Io`.
    fn warn_io(&mut self, original: PathBuf, failing: PathBuf, error: io::Error) {
        self.warnings.push(if is_missing(error.kind()) {
            ResolveWarning::Missing { path: original }
        } else {
            ResolveWarning::Io {
                path: failing,
                error,
            }
        });
    }

    #[cfg(test)]
    fn warn_walk(&mut self, walk_root: &Path, err: walkdir::Error) {
        let failing = err.path().unwrap_or(walk_root).to_owned();
        let error: io::Error = err.into();
        self.warn_io(failing.clone(), failing, error);
    }

    fn finish(mut self) -> Self {
        self.paths.sort_by(|a, b| a.host.cmp(&b.host));
        self.paths.dedup_by(|a, b| a.host == b.host);
        self
    }
}

/// Resolves `pattern` against the host filesystem as it is right now.
///
/// A literal pattern yields at most one path; a missing literal path (or
/// one running through a non-directory) yields a
/// [`ResolveWarning::Missing`] rather than an error. A glob is matched by
/// walking from its literal prefix (the components before the first one
/// containing a glob character) without following symlinks below the walk
/// root; `*` and `?` never match `/`, `**` matches zero or more components,
/// and dotfiles are not special. Unreadable directories become warnings and
/// the walk continues.
///
/// Symlinks: the final component of a match is never followed (it is
/// reported as [`EntryKind::Symlink`]), and a glob never descends into a
/// symlinked directory it meets during the walk. Symlinks on the way (in a
/// literal path before its final component, or in a glob's literal prefix,
/// the walk root included) are followed, whatever the anchor: home-manager
/// and `/etc/static` rely on it, and links a sandbox may have planted are
/// refused later, against the session's untrusted roots (DESIGN.md §3.4,
/// Symlinks; §6.2, "Untrusted links"). Paths are always reported as
/// written.
///
/// The only error is a glob that does not compile (e.g. an unclosed `[`).
/// A validated [`PathPattern`](crate::manifest::PathPattern) never has one,
/// so this is defensive.
pub fn resolve(pattern: &ExpandedPattern) -> Result<Resolution, ExpandError> {
    resolve_excluding(pattern, &[])
}

/// Resolves `pattern` against the host filesystem, pruning `excludes` during
/// glob directory traversal.
///
/// `excludes` applies only when `pattern` is a glob (`pattern.has_glob()`).
/// Literal patterns ignore `excludes` so an exact path always beats a glob
/// exclusion, and missing excluded paths never emit [`ResolveWarning::Missing`].
///
/// # Errors
///
/// Returns [`ExpandError::InvalidGlob`] if `pattern` or an entry in `excludes`
/// contains a glob that fails to compile (unreachable for validated
/// [`PathPattern`](crate::manifest::PathPattern)s).
///
/// # Examples
///
/// ```
/// # use std::fs;
/// # use tempfile::TempDir;
/// use stopit::expand::{ExpansionContext, expand_pattern, resolve_excluding};
/// # let tmp = TempDir::new().unwrap();
/// # let root = tmp.path().canonicalize().unwrap();
/// # let ws = root.join("ws");
/// # let home = root.join("home");
/// # fs::create_dir_all(ws.join("buck-out")).unwrap();
/// # fs::create_dir_all(&home).unwrap();
/// # fs::write(ws.join("flake.nix"), "").unwrap();
/// # fs::write(ws.join("buck-out/gen.nix"), "").unwrap();
/// # let ctx = ExpansionContext::new(
/// #     ws.clone(),
/// #     "/workspace".parse().unwrap(),
/// #     home,
/// #     "/home/user".parse().unwrap(),
/// # ).unwrap();
///
/// let pattern = expand_pattern(&"{workspace}/**/*.nix".parse().unwrap(), &ctx);
/// let exclude = expand_pattern(&"{workspace}/buck-out".parse().unwrap(), &ctx);
/// let res = resolve_excluding(&pattern, &[exclude]).unwrap();
/// assert_eq!(res.paths.len(), 1);
/// assert_eq!(res.paths[0].host, ws.join("flake.nix"));
/// ```
pub fn resolve_excluding(
    pattern: &ExpandedPattern,
    excludes: &[ExpandedPattern],
) -> Result<Resolution, ExpandError> {
    let mut cache = ResolveCache::default();
    resolve_excluding_with_cache(pattern, excludes, &mut cache)
}

/// Resolves `pattern` against the host filesystem, reusing walks and
/// pattern resolutions stored in `cache`.
pub fn resolve_with_cache(
    pattern: &ExpandedPattern,
    cache: &mut ResolveCache,
) -> Result<Resolution, ExpandError> {
    resolve_excluding_with_cache(pattern, &[], cache)
}

/// Resolves `pattern` against the host filesystem while pruning `excludes`
/// during glob walks, reusing cached walks and resolutions in `cache`.
///
/// Entries in `cache` are keyed by the normalized host-side exclude set so
/// rules with identical excludes share their pruned walk without colliding
/// with rules that use different excludes. Literal `pattern`s ignore
/// `excludes`.
///
/// # Errors
///
/// Returns [`ExpandError::InvalidGlob`] if `pattern` or an entry in `excludes`
/// contains a glob that fails to compile (unreachable for validated
/// [`PathPattern`](crate::manifest::PathPattern)s).
///
/// # Examples
///
/// ```
/// # use std::fs;
/// # use tempfile::TempDir;
/// use stopit::expand::{
///     ExpansionContext, ResolveCache, expand_pattern, resolve_excluding_with_cache,
/// };
/// # let tmp = TempDir::new().unwrap();
/// # let root = tmp.path().canonicalize().unwrap();
/// # let ws = root.join("ws");
/// # let home = root.join("home");
/// # fs::create_dir_all(ws.join("buck-out")).unwrap();
/// # fs::create_dir_all(&home).unwrap();
/// # fs::write(ws.join("buck-out/.env"), "").unwrap();
/// # let ctx = ExpansionContext::new(
/// #     ws.clone(),
/// #     "/workspace".parse().unwrap(),
/// #     home,
/// #     "/home/user".parse().unwrap(),
/// # ).unwrap();
///
/// let mut cache = ResolveCache::default();
/// let pat = expand_pattern(&"{workspace}/**/.env".parse().unwrap(), &ctx);
/// let excl = expand_pattern(&"{workspace}/buck-out".parse().unwrap(), &ctx);
/// assert!(resolve_excluding_with_cache(&pat, &[excl], &mut cache).unwrap().paths.is_empty());
/// assert_eq!(resolve_excluding_with_cache(&pat, &[], &mut cache).unwrap().paths.len(), 1);
/// ```
pub fn resolve_excluding_with_cache(
    pattern: &ExpandedPattern,
    excludes: &[ExpandedPattern],
    cache: &mut ResolveCache,
) -> Result<Resolution, ExpandError> {
    let keys = if pattern.has_glob() {
        exclude_keys(excludes)
    } else {
        Vec::new()
    };
    let cache_key = (pattern.clone(), keys);
    if let Some(cached) = cache.resolutions.get(&cache_key) {
        return Ok(cached.clone());
    }
    let res = if pattern.has_glob() {
        resolve_glob_with_cache(pattern, &cache_key.1, cache)?
    } else {
        resolve_literal_with_cache(pattern, cache)
    };
    let finished = res.finish();
    cache.resolutions.insert(cache_key, finished.clone());
    Ok(finished)
}

fn resolve_literal_with_cache(pattern: &ExpandedPattern, cache: &mut ResolveCache) -> Resolution {
    let mut res = Resolution::default();
    let rel = pattern.rest();
    let host = join(pattern.host_anchor(), rel);
    match cache.symlink_metadata(&host) {
        Ok(kind) => res.paths.push(ResolvedPath {
            sandbox: join(pattern.sandbox_anchor(), rel),
            kind,
            host,
        }),
        Err(error) => res.warn_io(join(pattern.host_anchor(), pattern.rest()), host, error),
    }
    res
}

fn resolve_glob_with_cache(
    pattern: &ExpandedPattern,
    excludes: &[ExcludeKey],
    cache: &mut ResolveCache,
) -> Result<Resolution, ExpandError> {
    let split = split_glob(pattern);

    // Validated patterns always compile; the error is purely defensive.
    let matcher = compile_glob(&split.remainder).map_err(|error| ExpandError::InvalidGlob {
        pattern: join(pattern.host_anchor(), pattern.rest()),
        error,
    })?;

    let mut res = Resolution::default();
    let sandbox_root = join(pattern.sandbox_anchor(), &split.prefix);
    // Without `**` every match has exactly this many components. This is
    // only an optimisation: matching alone is correct.
    let max_depth = (!split.remainder.contains("**")).then_some(split.remainder_components);
    let walk = cache.walk(&split.root, max_depth, excludes)?;
    match walk.as_ref() {
        CachedWalk::RootError(error) => {
            res.warn_io(
                join(pattern.host_anchor(), &split.prefix),
                split.root,
                clone_io_error(error),
            );
        }
        CachedWalk::Steps(steps) => {
            for step in steps {
                match step {
                    WalkStep::Error { path, error } => {
                        res.warn_io(path.clone(), path.clone(), clone_io_error(error));
                    }
                    WalkStep::Entry {
                        host,
                        relative,
                        kind,
                    } => {
                        if matcher.is_match(relative) {
                            res.paths.push(ResolvedPath {
                                host: host.clone(),
                                sandbox: sandbox_root.join(relative),
                                kind: *kind,
                            });
                        }
                    }
                }
            }
        }
    }
    Ok(res)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::os::unix::net::UnixListener;
    use std::path::Path;

    use tempfile::TempDir;

    use super::*;
    use crate::expand::{ExpansionContext, expand_pattern};
    use crate::manifest::PathPattern;

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

        /// A directory outside the workspace and home holding a `secret`.
        fn outside(&self) -> PathBuf {
            let outside = self.root.join("outside");
            fs::create_dir_all(&outside).unwrap();
            fs::write(outside.join("secret"), "secret").unwrap();
            outside
        }

        /// Creates a file (and its parents) below the workspace.
        fn file(&self, rel: &str) {
            let p = self.ws().join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, rel).unwrap();
        }

        fn mkdir(&self, rel: &str) {
            fs::create_dir_all(self.ws().join(rel)).unwrap();
        }

        fn symlink(&self, target: &Path, rel: &str) {
            symlink(target, self.ws().join(rel)).unwrap();
        }

        fn resolve(&self, pattern: &str) -> Resolution {
            let pattern: PathPattern = pattern.parse().unwrap();
            resolve(&expand_pattern(&pattern, &self.ctx)).unwrap()
        }

        /// The matched paths relative to the workspace.
        fn rels(&self, pattern: &str) -> Vec<String> {
            let res = self.resolve(pattern);
            assert!(res.warnings.is_empty(), "{pattern}: {:?}", res.warnings);
            res.paths
                .iter()
                .map(|p| {
                    p.host
                        .strip_prefix(self.ws())
                        .unwrap()
                        .to_string_lossy()
                        .into_owned()
                })
                .collect()
        }
    }

    fn missing_path(res: &Resolution) -> &Path {
        match res.warnings.as_slice() {
            [ResolveWarning::Missing { path }] => path,
            other => panic!("expected one Missing warning, got {other:?}"),
        }
    }

    #[test]
    fn literal_kinds() {
        let f = Fixture::new();
        f.file("a.txt");
        f.mkdir("d");
        f.symlink(Path::new("does-not-exist"), "dangling");
        f.symlink(&f.ws().join("d"), "dirlink");
        let _listener = UnixListener::bind(f.ws().join("sock")).unwrap();
        for (rel, kind) in [
            ("a.txt", EntryKind::File),
            ("d", EntryKind::Dir),
            ("dangling", EntryKind::Symlink),
            ("dirlink", EntryKind::Symlink),
            ("sock", EntryKind::Socket),
        ] {
            let res = f.resolve(&format!("{{workspace}}/{rel}"));
            assert!(res.warnings.is_empty(), "{rel}: {:?}", res.warnings);
            assert_eq!(
                res.paths,
                vec![ResolvedPath {
                    host: f.ws().join(rel),
                    sandbox: PathBuf::from("/workspace").join(rel),
                    kind,
                }],
                "{rel}"
            );
        }
    }

    #[test]
    fn literal_anchor_itself() {
        let f = Fixture::new();
        let res = f.resolve("{workspace}");
        assert_eq!(
            res.paths,
            vec![ResolvedPath {
                host: f.ws(),
                sandbox: PathBuf::from("/workspace"),
                kind: EntryKind::Dir,
            }]
        );
        let res = f.resolve("~");
        assert_eq!(res.paths[0].sandbox, PathBuf::from("/home/user"));
    }

    #[test]
    fn literal_missing_is_a_warning() {
        let f = Fixture::new();
        let res = f.resolve("{workspace}/nope/deeper");
        assert!(res.paths.is_empty());
        assert_eq!(missing_path(&res), f.ws().join("nope/deeper"));
        let msg = res.warnings[0].to_string();
        assert!(msg.contains("nope/deeper"), "{msg}");
    }

    #[test]
    fn dotenv_found_everywhere_including_hidden_and_gitignored_dirs() {
        let f = Fixture::new();
        f.file(".env");
        f.file("a/b/.env");
        f.file(".config/.env");
        f.file("target/.env");
        f.file("node_modules/pkg/.env");
        fs::write(f.ws().join(".gitignore"), ".env\ntarget/\nnode_modules/\n").unwrap();
        f.file("a/.envrc");
        f.file("a/x.env");
        f.mkdir(".git");
        fs::write(f.ws().join(".git/info"), "").unwrap();
        assert_eq!(
            f.rels("{workspace}/**/.env"),
            [
                ".config/.env",
                ".env",
                "a/b/.env",
                "node_modules/pkg/.env",
                "target/.env",
            ]
        );
    }

    #[test]
    fn star_star_and_star_and_literal_prefix() {
        let f = Fixture::new();
        f.file("flake.nix");
        f.file("nix/a.nix");
        f.file("nix/sub/b.nix");
        f.file("nix/readme.md");
        f.file("other/c.nix");
        assert_eq!(
            f.rels("{workspace}/**/*.nix"),
            ["flake.nix", "nix/a.nix", "nix/sub/b.nix", "other/c.nix"]
        );
        assert_eq!(f.rels("{workspace}/*.nix"), ["flake.nix"]);
        assert_eq!(f.rels("{workspace}/nix/*.nix"), ["nix/a.nix"]);
        assert_eq!(
            f.rels("{workspace}/nix/**/*.nix"),
            ["nix/a.nix", "nix/sub/b.nix"]
        );
        assert_eq!(
            f.rels("{workspace}/nix/**"),
            ["nix/a.nix", "nix/readme.md", "nix/sub", "nix/sub/b.nix"]
        );
    }

    #[test]
    fn literal_prefix_is_the_walk_root() {
        let f = Fixture::new();
        f.file("nix/a.nix");
        // A sibling of the walk root that would match if it were walked.
        f.file("nixx/a.nix");
        let res = f.resolve("{workspace}/nix/*.nix");
        assert_eq!(res.paths.len(), 1);
        assert_eq!(res.paths[0].host, f.ws().join("nix/a.nix"));
        assert_eq!(res.paths[0].sandbox, PathBuf::from("/workspace/nix/a.nix"));
    }

    #[test]
    fn question_mark_and_classes() {
        let f = Fixture::new();
        for name in ["a1", "a2", "a12", "xa", "yb", "zc", "a/1"] {
            f.file(name);
        }
        assert_eq!(f.rels("{workspace}/a?"), ["a1", "a2"]);
        assert_eq!(f.rels("{workspace}/[xy][ab]"), ["xa", "yb"]);
        assert_eq!(f.rels("{workspace}/[!xy]?"), ["a1", "a2", "zc"]);
        // `?` never matches `/`.
        assert_eq!(f.rels("{workspace}/a??"), ["a12"]);
    }

    #[test]
    fn star_does_not_cross_slash() {
        let f = Fixture::new();
        f.file("a/b/c.txt");
        f.file("a/c.txt");
        assert_eq!(f.rels("{workspace}/a/*.txt"), ["a/c.txt"]);
        assert_eq!(f.rels("{workspace}/a*c.txt"), Vec::<String>::new());
        assert_eq!(f.rels("{workspace}/*/c.txt"), ["a/c.txt"]);
        assert_eq!(f.rels("{workspace}/*"), ["a"]);
    }

    #[test]
    fn star_matches_dotfiles() {
        let f = Fixture::new();
        f.file(".hidden");
        f.file("shown");
        assert_eq!(f.rels("{workspace}/*"), [".hidden", "shown"]);
    }

    #[test]
    fn symlinked_dirs_are_reported_but_never_descended() {
        let f = Fixture::new();
        let outside = f.root.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join(".env"), "secret").unwrap();
        f.symlink(&outside, "link");
        f.symlink(&outside, ".env");
        f.file("real/.env");
        let res = f.resolve("{workspace}/**/.env");
        assert!(res.warnings.is_empty(), "{:?}", res.warnings);
        assert_eq!(
            res.paths,
            vec![
                ResolvedPath {
                    host: f.ws().join(".env"),
                    sandbox: PathBuf::from("/workspace/.env"),
                    kind: EntryKind::Symlink,
                },
                ResolvedPath {
                    host: f.ws().join("real/.env"),
                    sandbox: PathBuf::from("/workspace/real/.env"),
                    kind: EntryKind::File,
                },
            ]
        );
        // The link matches by its own name, and nothing below it is visited.
        let res = f.resolve("{workspace}/**");
        let rels: Vec<_> = res
            .paths
            .iter()
            .map(|p| (p.host.strip_prefix(f.ws()).unwrap().to_owned(), p.kind))
            .collect();
        assert_eq!(
            rels,
            [
                (PathBuf::from(".env"), EntryKind::Symlink),
                (PathBuf::from("link"), EntryKind::Symlink),
                (PathBuf::from("real"), EntryKind::Dir),
                (PathBuf::from("real/.env"), EntryKind::File),
            ]
        );
    }

    #[test]
    fn symlink_loop_does_not_hang() {
        let f = Fixture::new();
        f.mkdir("a");
        f.symlink(&f.ws(), "a/up");
        f.symlink(Path::new("self"), "self");
        f.file("a/.env");
        let res = f.resolve("{workspace}/**");
        assert!(res.warnings.is_empty(), "{:?}", res.warnings);
        let rels: Vec<_> = res
            .paths
            .iter()
            .map(|p| p.host.strip_prefix(f.ws()).unwrap().to_owned())
            .collect();
        assert_eq!(rels, ["a", "a/.env", "a/up", "self"].map(PathBuf::from));
    }

    /// The matches of `pattern` as `(host relative to the workspace,
    /// sandbox, kind)`, asserting that there are no warnings.
    fn matches(f: &Fixture, pattern: &str) -> Vec<(PathBuf, PathBuf, EntryKind)> {
        let res = f.resolve(pattern);
        assert!(res.warnings.is_empty(), "{pattern}: {:?}", res.warnings);
        res.paths
            .into_iter()
            .map(|p| {
                (
                    p.host.strip_prefix(f.ws()).unwrap().to_owned(),
                    p.sandbox,
                    p.kind,
                )
            })
            .collect()
    }

    #[test]
    fn workspace_links_on_the_way_are_followed_like_any_anchor() {
        // The resolver treats `{workspace}` like `~` and absolute anchors:
        // links on the way are followed, and the match is reported as
        // written. Whether such a link may have been planted is decided
        // against the session's untrusted roots (`crate::spec`), which
        // refuse every link inside the workspace.
        let f = Fixture::new();
        let outside = f.outside();
        f.file("real/.env");
        f.file("real/a.nix");
        f.symlink(&outside, "abs");
        f.symlink(Path::new("../outside"), "rel");
        f.symlink(Path::new("real"), "link");
        f.mkdir("sub");
        f.symlink(Path::new("../link"), "sub/chain");
        f.symlink(&f.ws(), "top");
        for (via, file) in [
            ("abs", "secret"),
            ("rel", "secret"),
            ("link", ".env"),
            ("sub/chain", ".env"),
            ("top/real", ".env"),
        ] {
            let rel = Path::new(via).join(file);
            assert_eq!(
                matches(&f, &format!("{{workspace}}/{via}/{file}")),
                [(
                    rel.clone(),
                    Path::new("/workspace").join(&rel),
                    EntryKind::File
                )],
                "{via}"
            );
            // A glob's literal prefix, the walk root included, too.
            assert_eq!(
                matches(&f, &format!("{{workspace}}/{via}/*")),
                matches(&f, &format!("{{workspace}}/{via}/**")),
                "{via}"
            );
            assert!(
                matches(&f, &format!("{{workspace}}/{via}/*"))
                    .iter()
                    .any(|(host, _, _)| *host == rel),
                "{via}"
            );
        }
        // Followed, `{workspace}/x/hooks` lands at `.git/hooks` on the host,
        // but is reported as written, at its own sandbox path.
        f.file(".git/hooks/pre-commit");
        f.symlink(Path::new(".git"), "x");
        assert_eq!(
            matches(&f, "{workspace}/x/hooks"),
            [(
                PathBuf::from("x/hooks"),
                PathBuf::from("/workspace/x/hooks"),
                EntryKind::Dir
            )]
        );
        // The link itself, as a final component, is reported unfollowed.
        assert_eq!(
            matches(&f, "{workspace}/x"),
            [(
                PathBuf::from("x"),
                PathBuf::from("/workspace/x"),
                EntryKind::Symlink
            )]
        );
    }

    #[test]
    fn dangling_links_on_the_way_are_missing() {
        let f = Fixture::new();
        f.symlink(Path::new("nowhere"), "dangling");
        for (pattern, missing) in [
            ("{workspace}/dangling/.env", "dangling/.env"),
            ("{workspace}/dangling/*", "dangling"),
        ] {
            let res = f.resolve(pattern);
            assert!(res.paths.is_empty(), "{pattern}");
            assert_eq!(missing_path(&res), f.ws().join(missing), "{pattern}");
        }
    }

    #[test]
    fn only_directories_can_be_passed_through() {
        let f = Fixture::new();
        f.file("file");
        for (pattern, missing) in [
            ("{workspace}/file/x", "file/x"),
            ("{workspace}/file/x/y", "file/x/y"),
            ("{workspace}/file/x/*", "file/x"),
            ("{workspace}/file/x/**/y", "file/x"),
        ] {
            let res = f.resolve(pattern);
            assert!(res.paths.is_empty(), "{pattern}");
            assert_eq!(missing_path(&res), f.ws().join(missing), "{pattern}");
        }
    }

    #[test]
    fn workspace_final_symlink_is_never_followed() {
        let f = Fixture::new();
        let outside = f.outside();
        f.symlink(&outside.join("secret"), "out");
        f.file("real");
        f.symlink(Path::new("real"), "in");
        for name in ["out", "in"] {
            let res = f.resolve(&format!("{{workspace}}/{name}"));
            assert!(res.warnings.is_empty(), "{:?}", res.warnings);
            assert_eq!(res.paths[0].host, f.ws().join(name));
            assert_eq!(res.paths[0].kind, EntryKind::Symlink);
        }
    }

    #[test]
    fn symlink_loop_on_the_way_is_an_io_warning() {
        let f = Fixture::new();
        f.symlink(Path::new("b"), "a");
        f.symlink(Path::new("a"), "b");
        // The lookup gives up with `ELOOP`: the path exists but cannot be
        // inspected, which a restrictive rule must not skip.
        for (pattern, path) in [("{workspace}/a/x", "a/x"), ("{workspace}/a/*", "a")] {
            let res = f.resolve(pattern);
            assert!(res.paths.is_empty(), "{pattern}");
            match res.warnings.as_slice() {
                [ResolveWarning::Io { path: got, error }] => {
                    assert_eq!(got, &f.ws().join(path), "{pattern}");
                    assert_eq!(
                        error.raw_os_error(),
                        Some(rustix::io::Errno::LOOP.raw_os_error()),
                        "{pattern}"
                    );
                }
                other => panic!("{pattern}: expected one Io warning, got {other:?}"),
            }
        }
    }

    #[test]
    fn home_and_absolute_anchors_follow_escaping_symlinks() {
        let f = Fixture::new();
        let outside = f.outside();
        symlink(&outside, f.home().join("docs")).unwrap();
        let res = f.resolve("~/docs/secret");
        assert!(res.warnings.is_empty(), "{:?}", res.warnings);
        assert_eq!(
            res.paths,
            vec![ResolvedPath {
                host: f.home().join("docs/secret"),
                sandbox: PathBuf::from("/home/user/docs/secret"),
                kind: EntryKind::File,
            }]
        );
        let res = f.resolve("~/docs/*");
        assert_eq!(res.paths[0].host, f.home().join("docs/secret"));
        assert_eq!(
            res.paths[0].sandbox,
            PathBuf::from("/home/user/docs/secret")
        );

        let abs = f.home().join("docs");
        let abs = abs.to_str().unwrap();
        for pattern in [format!("{abs}/secret"), format!("{abs}/*")] {
            let res = f.resolve(&pattern);
            assert!(res.warnings.is_empty(), "{:?}", res.warnings);
            let host = f.home().join("docs/secret");
            assert_eq!(
                res.paths,
                vec![ResolvedPath {
                    sandbox: host.clone(),
                    host,
                    kind: EntryKind::File,
                }],
                "{pattern}"
            );
        }
    }

    #[test]
    fn literal_through_a_file_is_missing() {
        let f = Fixture::new();
        f.file("file.txt");
        fs::write(f.home().join("file.txt"), "").unwrap();
        let res = f.resolve("{workspace}/file.txt/x");
        assert_eq!(missing_path(&res), f.ws().join("file.txt/x"));
        let res = f.resolve("{workspace}/file.txt/x/y");
        assert_eq!(missing_path(&res), f.ws().join("file.txt/x/y"));
        let res = f.resolve("~/file.txt/x");
        assert_eq!(missing_path(&res), f.home().join("file.txt/x"));
        assert!(res.paths.is_empty());
    }

    #[test]
    fn non_utf8_names_are_matched() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let f = Fixture::new();
        let name = OsStr::from_bytes(b"\xff\xfe.env");
        fs::write(f.ws().join(name), "").unwrap();
        for pattern in ["{workspace}/**", "{workspace}/*.env"] {
            let res = f.resolve(pattern);
            assert!(res.warnings.is_empty(), "{:?}", res.warnings);
            assert_eq!(
                res.paths,
                vec![ResolvedPath {
                    host: f.ws().join(name),
                    sandbox: Path::new("/workspace").join(name),
                    kind: EntryKind::File,
                }],
                "{pattern}"
            );
        }
    }

    #[test]
    fn absolute_glob_maps_to_itself() {
        let f = Fixture::new();
        f.file("nix/a.nix");
        f.file("nix/b.txt");
        let pattern = format!("{}/nix/*.nix", f.ws().to_str().unwrap());
        let res = f.resolve(&pattern);
        assert!(res.warnings.is_empty(), "{:?}", res.warnings);
        assert_eq!(
            res.paths,
            vec![ResolvedPath {
                host: f.ws().join("nix/a.nix"),
                sandbox: f.ws().join("nix/a.nix"),
                kind: EntryKind::File,
            }]
        );
    }

    #[test]
    fn glob_reports_sockets_and_fifos() {
        let f = Fixture::new();
        f.mkdir("state/pg");
        let _listener = UnixListener::bind(f.ws().join("state/pg/.s.PGSQL.5432")).unwrap();
        let status = std::process::Command::new("mkfifo")
            .arg(f.ws().join("state/fifo"))
            .status()
            .unwrap();
        assert!(status.success());
        let res = f.resolve("{workspace}/state/**");
        assert!(res.warnings.is_empty(), "{:?}", res.warnings);
        let kinds: Vec<_> = res
            .paths
            .iter()
            .map(|p| (p.host.strip_prefix(f.ws()).unwrap().to_owned(), p.kind))
            .collect();
        assert_eq!(
            kinds,
            [
                (PathBuf::from("state/fifo"), EntryKind::Other),
                (PathBuf::from("state/pg"), EntryKind::Dir),
                (PathBuf::from("state/pg/.s.PGSQL.5432"), EntryKind::Socket),
            ]
        );
        let res = f.resolve("{workspace}/state/fifo");
        assert_eq!(res.paths[0].kind, EntryKind::Other);
    }

    #[test]
    fn missing_walk_root_is_a_warning() {
        let f = Fixture::new();
        let res = f.resolve("{workspace}/nope/**/*.nix");
        assert!(res.paths.is_empty());
        assert_eq!(missing_path(&res), f.ws().join("nope"));
    }

    #[test]
    fn walk_root_that_is_a_file_yields_nothing() {
        let f = Fixture::new();
        f.file("nix");
        let res = f.resolve("{workspace}/nix/*.nix");
        assert!(res.paths.is_empty());
    }

    #[test]
    fn unreadable_directory_is_a_warning_and_the_walk_continues() {
        if rustix::process::geteuid().is_root() {
            eprintln!("skipping: permission checks do not apply to root");
            return;
        }
        let f = Fixture::new();
        f.file("a/.env");
        f.file("locked/.env");
        f.file("z/.env");
        let locked = f.ws().join("locked");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        let res = f.resolve("{workspace}/**/.env");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
        let hosts: Vec<_> = res.paths.iter().map(|p| p.host.clone()).collect();
        assert_eq!(hosts, [f.ws().join("a/.env"), f.ws().join("z/.env")]);
        match res.warnings.as_slice() {
            [ResolveWarning::Io { path, error }] => {
                assert_eq!(path, &locked);
                assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            }
            other => panic!("expected one Io warning, got {other:?}"),
        }
        let msg = res.warnings[0].to_string();
        assert!(msg.contains("locked"), "{msg}");
    }

    #[test]
    fn walk_errors_are_classified_like_other_io_errors() {
        // A walk error for an entry that vanished mid-walk cannot be raced
        // reliably, so produce the same walkdir errors directly: a missing
        // entry, one below a non-directory, and an unreadable directory.
        let f = Fixture::new();
        f.file("file");
        f.mkdir("locked");
        let walk_err = |path: PathBuf| {
            WalkDir::new(path)
                .min_depth(1)
                .into_iter()
                .find_map(Result::err)
                .expect("the walk fails")
        };
        let mut res = Resolution::default();
        res.warn_walk(&f.ws(), walk_err(f.ws().join("gone")));
        res.warn_walk(&f.ws(), walk_err(f.ws().join("file/x")));
        let locked = f.ws().join("locked");
        let is_root = rustix::process::geteuid().is_root();
        if !is_root {
            fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
            let err = walk_err(locked.clone());
            fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
            res.warn_walk(&f.ws(), err);
        }
        match res.warnings.as_slice() {
            [
                ResolveWarning::Missing { path: gone },
                ResolveWarning::Missing { path: below_file },
                rest @ ..,
            ] => {
                assert_eq!(gone, &f.ws().join("gone"));
                assert_eq!(below_file, &f.ws().join("file/x"));
                match rest {
                    [] => assert!(is_root),
                    [ResolveWarning::Io { path, error }] => {
                        assert_eq!(path, &locked);
                        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
                    }
                    other => panic!("expected one Io warning, got {other:?}"),
                }
            }
            other => panic!("expected two Missing warnings first, got {other:?}"),
        }
    }

    #[test]
    fn literal_below_unreadable_directory_is_a_warning() {
        if rustix::process::geteuid().is_root() {
            eprintln!("skipping: permission checks do not apply to root");
            return;
        }
        let f = Fixture::new();
        f.file("locked/x");
        let locked = f.ws().join("locked");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        let literal = f.resolve("{workspace}/locked/x");
        let glob = f.resolve("{workspace}/locked/x/*");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
        for res in [literal, glob] {
            assert!(res.paths.is_empty());
            assert!(
                matches!(
                    res.warnings.as_slice(),
                    [ResolveWarning::Io { error, .. }]
                        if error.kind() == io::ErrorKind::PermissionDenied
                ),
                "{:?}",
                res.warnings
            );
        }
    }

    #[test]
    fn output_sorted_deduplicated_and_mapped_to_a_custom_mount() {
        let f = Fixture::with_mount("/work/tree");
        for name in ["c", "a", "b/x", "b/a"] {
            f.file(name);
        }
        let res = f.resolve("{workspace}/**");
        assert!(res.warnings.is_empty(), "{:?}", res.warnings);
        let pairs: Vec<_> = res
            .paths
            .iter()
            .map(|p| (p.host.clone(), p.sandbox.clone()))
            .collect();
        let want: Vec<_> = ["a", "b", "b/a", "b/x", "c"]
            .iter()
            .map(|r| (f.ws().join(r), PathBuf::from("/work/tree").join(r)))
            .collect();
        assert_eq!(pairs, want);

        let mut r = Resolution::default();
        for host in ["/b", "/a", "/b"] {
            r.paths.push(ResolvedPath {
                host: host.into(),
                sandbox: host.into(),
                kind: EntryKind::File,
            });
        }
        let hosts: Vec<_> = r.finish().paths.into_iter().map(|p| p.host).collect();
        assert_eq!(hosts, [PathBuf::from("/a"), PathBuf::from("/b")]);
    }

    #[test]
    fn home_anchor_maps_to_sandbox_home() {
        let f = Fixture::new();
        let home = f.home();
        fs::create_dir_all(home.join(".config/tool")).unwrap();
        fs::write(home.join(".config/tool/settings"), "").unwrap();
        let res = f.resolve("~/.config/*/settings");
        assert_eq!(
            res.paths,
            vec![ResolvedPath {
                host: home.join(".config/tool/settings"),
                sandbox: PathBuf::from("/home/user/.config/tool/settings"),
                kind: EntryKind::File,
            }]
        );
    }

    #[test]
    fn depth_limit_does_not_change_results() {
        let f = Fixture::new();
        for name in ["x.nix", "d/x.nix", "d/e/x.nix", "d/e/f/x.nix", "q/r/x.nix"] {
            f.file(name);
        }
        // `*/x.nix` limits the walk to depth 2; a manual filter of the full
        // `**` walk must agree.
        let limited = f.rels("{workspace}/*/x.nix");
        let all = f.rels("{workspace}/**/x.nix");
        let filtered: Vec<_> = all
            .into_iter()
            .filter(|r| r.matches('/').count() == 1)
            .collect();
        assert_eq!(limited, filtered);
        assert_eq!(limited, ["d/x.nix"]);
        assert_eq!(f.rels("{workspace}/*/*/x.nix"), ["d/e/x.nix", "q/r/x.nix"]);
        assert_eq!(f.rels("{workspace}/*.nix"), ["x.nix"]);
    }

    #[test]
    fn backslash_is_an_ordinary_character() {
        let f = Fixture::new();
        f.file("a\\b");
        f.file("ab");
        assert_eq!(f.rels("{workspace}/a\\*"), ["a\\b"]);
    }

    #[test]
    fn invalid_glob_is_an_error_naming_the_pattern() {
        let f = Fixture::new();
        // Validation rejects this pattern, so it must be built unchecked.
        assert!("{workspace}/nix/[a.nix".parse::<PathPattern>().is_err());
        let pattern = PathPattern::new_unchecked("{workspace}/nix/[a.nix");
        let err = resolve(&expand_pattern(&pattern, &f.ctx)).unwrap_err();
        assert!(matches!(err, ExpandError::InvalidGlob { .. }), "{err:?}");
        let msg = err.to_string();
        assert!(msg.contains("nix/[a.nix"), "{msg}");
    }

    #[test]
    fn negated_class_does_not_match_across_components() {
        let f = Fixture::new();
        f.file("x/y");
        f.file("q/xby");
        f.file("xay");
        assert_eq!(f.rels("{workspace}/**/x[!a]y"), ["q/xby"]);
        assert_eq!(f.rels("{workspace}/**/x[^a]y"), ["q/xby"]);
    }

    #[test]
    fn classes_match_glob_characters_literally() {
        let f = Fixture::new();
        for name in ["*", "?", "a"] {
            f.file(name);
        }
        assert_eq!(f.rels("{workspace}/[*]"), ["*"]);
        assert_eq!(f.rels("{workspace}/[?]"), ["?"]);
    }

    #[test]
    fn patterns_accepted_at_load_always_compile_in_resolve() {
        // Validation and resolution share `compile_glob`, so nothing a
        // `PathPattern` accepts can hit `InvalidGlob` here.
        let f = Fixture::new();
        f.file("a.nix");
        f.file("ab/c");
        f.file("a]");
        for pattern in [
            "{workspace}/**/*.nix",
            "{workspace}/.env.*",
            "{workspace}/[ab]?/c",
            "{workspace}/a]",
            "{workspace}/[]]*",
            "{workspace}/[!a]*",
            "{workspace}/**",
            "~/.config/*/settings",
            "/nix/store/*-foo",
        ] {
            let parsed: PathPattern = pattern.parse().unwrap();
            resolve(&expand_pattern(&parsed, &f.ctx)).unwrap_or_else(|e| panic!("{pattern}: {e}"));
        }
        assert_eq!(f.rels("{workspace}/a]"), ["a]"]);
        assert_eq!(f.rels("{workspace}/[ab]?/c"), ["ab/c"]);
    }

    fn expand_list(ctx: &ExpansionContext, patterns: &[&str]) -> Vec<ExpandedPattern> {
        patterns
            .iter()
            .map(|s| expand_pattern(&s.parse().unwrap(), ctx))
            .collect()
    }

    fn rels_excluding(f: &Fixture, pattern: &str, excludes: &[&str]) -> Vec<String> {
        let pat = expand_pattern(&pattern.parse().unwrap(), &f.ctx);
        let ex = expand_list(&f.ctx, excludes);
        let res = resolve_excluding(&pat, &ex).unwrap();
        assert!(
            res.warnings.is_empty(),
            "{pattern} excluding {excludes:?}: {:?}",
            res.warnings
        );
        res.paths
            .iter()
            .map(|p| {
                p.host
                    .strip_prefix(f.ws())
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect()
    }

    #[test]
    fn exclude_prunes_literal_and_glob_subtrees_and_files() {
        let f = Fixture::new();
        f.file("flake.nix");
        f.file("nix/mod.nix");
        f.file("nix/generated.gen.nix");
        f.file("buck-out/v2/gen.nix");
        f.file("buck-out/.gitignore");
        f.file("sub/buck-out/nested.nix");
        f.symlink(Path::new("../flake.nix"), "buck-out/link.nix");

        // Literal directory exclude prunes `buck-out` and its contents.
        assert_eq!(
            rels_excluding(&f, "{workspace}/**/*.nix", &["{workspace}/buck-out"]),
            [
                "flake.nix",
                "nix/generated.gen.nix",
                "nix/mod.nix",
                "sub/buck-out/nested.nix",
            ]
        );

        // Glob excludes: `**/buck-out`, `buck-out/**`, and `**/*.gen.nix`.
        assert_eq!(
            rels_excluding(&f, "{workspace}/**/*.nix", &["{workspace}/**/buck-out"]),
            ["flake.nix", "nix/generated.gen.nix", "nix/mod.nix"]
        );
        assert_eq!(
            rels_excluding(&f, "{workspace}/**/*.nix", &["{workspace}/buck-out/**"]),
            [
                "flake.nix",
                "nix/generated.gen.nix",
                "nix/mod.nix",
                "sub/buck-out/nested.nix",
            ]
        );
        assert_eq!(
            rels_excluding(
                &f,
                "{workspace}/**/*.nix",
                &["{workspace}/**/buck-out", "{workspace}/**/*.gen.nix"]
            ),
            ["flake.nix", "nix/mod.nix"]
        );

        // Walk root itself equal to or strictly inside an excluded tree yields
        // an empty resolution without walking or warning, even when missing.
        assert!(
            rels_excluding(
                &f,
                "{workspace}/buck-out/**/*.nix",
                &["{workspace}/buck-out"]
            )
            .is_empty()
        );
        assert!(
            rels_excluding(
                &f,
                "{workspace}/buck-out/v2/*.nix",
                &["{workspace}/buck-out"]
            )
            .is_empty()
        );
        assert!(
            rels_excluding(
                &f,
                "{workspace}/sub/buck-out/*.nix",
                &["{workspace}/**/buck-out"]
            )
            .is_empty()
        );
        assert!(
            rels_excluding(
                &f,
                "{workspace}/buck-out/v2/*.nix",
                &["{workspace}/buck-out/**"]
            )
            .is_empty()
        );
        assert!(
            rels_excluding(
                &f,
                "{workspace}/missing-out/**/*.nix",
                &["{workspace}/missing-out"]
            )
            .is_empty()
        );

        // Non-existent excluded paths emit no `Missing` warning.
        assert_eq!(
            rels_excluding(&f, "{workspace}/*.nix", &["{workspace}/does-not-exist"]),
            ["flake.nix"]
        );

        // Literal patterns ignore `excludes` ("an exact path beats a glob").
        let lit = expand_pattern(&"{workspace}/buck-out/.gitignore".parse().unwrap(), &f.ctx);
        let ex = expand_list(&f.ctx, &["{workspace}/buck-out"]);
        let lit_res = resolve_excluding(&lit, &ex).unwrap();
        assert!(lit_res.warnings.is_empty());
        assert_eq!(lit_res.paths.len(), 1);
        assert_eq!(lit_res.paths[0].host, f.ws().join("buck-out/.gitignore"));
    }

    #[test]
    fn exclude_prunes_unreadable_dirs_and_resists_planted_symlinks() {
        let f = Fixture::new();
        f.file("nix/foo.nix");

        // Adversarial symlink: `buck-out -> nix` must not trick lexical exclude
        // matching into excluding real files under `nix/`.
        f.symlink(Path::new("nix"), "buck-out");
        assert_eq!(
            rels_excluding(&f, "{workspace}/**/*.nix", &["{workspace}/buck-out"]),
            ["nix/foo.nix"]
        );
        fs::remove_file(f.ws().join("buck-out")).unwrap();

        if rustix::process::geteuid().is_root() {
            eprintln!("skipping permission portion: permission checks do not apply to root");
            return;
        }

        f.file("buck-out/locked/hidden.nix");
        f.mkdir("locked-out");
        let inner_locked = f.ws().join("buck-out/locked");
        let self_locked = f.ws().join("locked-out");
        fs::set_permissions(&inner_locked, fs::Permissions::from_mode(0o000)).unwrap();
        fs::set_permissions(&self_locked, fs::Permissions::from_mode(0o000)).unwrap();

        let got = rels_excluding(
            &f,
            "{workspace}/**/*.nix",
            &["{workspace}/buck-out", "{workspace}/locked-out"],
        );
        let root_inside_locked = rels_excluding(
            &f,
            "{workspace}/buck-out/locked/*.nix",
            &["{workspace}/buck-out"],
        );

        fs::set_permissions(&inner_locked, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&self_locked, fs::Permissions::from_mode(0o755)).unwrap();

        assert_eq!(got, ["nix/foo.nix"]);
        assert!(root_inside_locked.is_empty());
    }

    #[test]
    fn resolve_cache_shares_pruned_walks_and_isolates_distinct_excludes() {
        let f = Fixture::new();
        f.file("flake.nix");
        f.file("Cargo.lock");
        f.file("buck-out/gen.nix");
        f.file("buck-out/Cargo.lock");

        let nix_pat = expand_pattern(&"{workspace}/**/*.nix".parse().unwrap(), &f.ctx);
        let lock_pat = expand_pattern(&"{workspace}/**/Cargo.lock".parse().unwrap(), &f.ctx);
        let excl_buck = expand_list(&f.ctx, &["{workspace}/buck-out"]);

        // Order 1: excluded first, then unexcluded on the same cache.
        let mut cache = ResolveCache::default();
        let nix_pruned = resolve_excluding_with_cache(&nix_pat, &excl_buck, &mut cache).unwrap();
        assert_eq!(cache.walks.len(), 1);
        assert_eq!(nix_pruned.paths.len(), 1);
        assert_eq!(nix_pruned.paths[0].host, f.ws().join("flake.nix"));

        // Creating a new Cargo.lock on disk after the first walk proves the
        // second glob with the identical exclude list reuses the cached walk.
        f.file("late/Cargo.lock");
        let lock_pruned = resolve_excluding_with_cache(&lock_pat, &excl_buck, &mut cache).unwrap();
        assert_eq!(cache.walks.len(), 1);
        assert_eq!(lock_pruned.paths.len(), 1);
        assert_eq!(lock_pruned.paths[0].host, f.ws().join("Cargo.lock"));

        // Same glob pattern (`**/*.nix`) with empty excludes does NOT collide
        // with the pruned resolution or walk.
        let nix_all = resolve_excluding_with_cache(&nix_pat, &[], &mut cache).unwrap();
        assert_eq!(cache.walks.len(), 2);
        assert_eq!(cache.resolutions.len(), 3);
        assert_eq!(nix_all.paths.len(), 2);

        // Order 2: unexcluded first, then excluded on a fresh cache.
        let mut cache2 = ResolveCache::default();
        let nix_all_first = resolve_excluding_with_cache(&nix_pat, &[], &mut cache2).unwrap();
        let nix_pruned_second =
            resolve_excluding_with_cache(&nix_pat, &excl_buck, &mut cache2).unwrap();
        assert_eq!(nix_all_first.paths.len(), 2);
        assert_eq!(nix_pruned_second.paths.len(), 1);
        assert_eq!(nix_pruned_second.paths[0].host, f.ws().join("flake.nix"));

        // Invalid unchecked glob in excludes returns `ExpandError::InvalidGlob`.
        let bad_excl = expand_pattern(&PathPattern::new_unchecked("{workspace}/[bad"), &f.ctx);
        let err = resolve_excluding_with_cache(&nix_pat, &[bad_excl], &mut cache2).unwrap_err();
        assert!(matches!(err, ExpandError::InvalidGlob { .. }), "{err:?}");
    }
}
