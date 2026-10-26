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

use std::fs::FileType;
use std::io;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

use thiserror::Error;
use walkdir::WalkDir;

use super::{ExpandError, ExpandedPattern, join};
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

/// The outcome of [`resolve`].
#[derive(Debug, Default)]
pub struct Resolution {
    /// The matching paths, sorted by host path and deduplicated.
    pub paths: Vec<ResolvedPath>,
    /// Non-fatal problems, in the order they were found.
    pub warnings: Vec<ResolveWarning>,
}

impl Resolution {
    /// Records an error inspecting `failing` while resolving `original`:
    /// a missing path, or one that runs through a non-directory, is
    /// `Missing`; anything else is `Io`.
    fn warn_io(&mut self, original: PathBuf, failing: PathBuf, error: io::Error) {
        self.warnings.push(match error.kind() {
            io::ErrorKind::NotFound | io::ErrorKind::NotADirectory => {
                ResolveWarning::Missing { path: original }
            }
            _ => ResolveWarning::Io {
                path: failing,
                error,
            },
        });
    }

    /// Records an error from the glob walk below `root`, classified like
    /// [`warn_io`](Self::warn_io): an entry that vanished during the walk
    /// (or whose directory was replaced by a non-directory) is `Missing`,
    /// anything else (e.g. an unreadable directory) is `Io`.
    fn warn_walk(&mut self, root: &Path, err: walkdir::Error) {
        let path = err.path().unwrap_or(root).to_owned();
        self.warn_io(path.clone(), path, err.into());
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
    let res = if pattern.has_glob() {
        resolve_glob(pattern)?
    } else {
        resolve_literal(pattern)
    };
    Ok(res.finish())
}

fn resolve_literal(pattern: &ExpandedPattern) -> Resolution {
    let mut res = Resolution::default();
    let rel = pattern.rest();
    let host = join(pattern.host_anchor(), rel);
    match host.symlink_metadata() {
        Ok(meta) => res.paths.push(ResolvedPath {
            sandbox: join(pattern.sandbox_anchor(), rel),
            kind: EntryKind::from_file_type(meta.file_type()),
            host,
        }),
        Err(error) => res.warn_io(join(pattern.host_anchor(), pattern.rest()), host, error),
    }
    res
}

fn resolve_glob(pattern: &ExpandedPattern) -> Result<Resolution, ExpandError> {
    // `rest` comes from a validated UTF-8 pattern, so this is lossless.
    let rest = pattern.rest().to_string_lossy();
    let components: Vec<&str> = rest.split('/').collect();
    let split = components
        .iter()
        .position(|c| has_glob(c))
        .expect("resolve_glob is only called for glob patterns");
    let prefix = PathBuf::from(components[..split].join("/"));
    let remainder = components[split..].join("/");

    // Validated patterns always compile; the error is purely defensive.
    let matcher = compile_glob(&remainder).map_err(|error| ExpandError::InvalidGlob {
        pattern: join(pattern.host_anchor(), pattern.rest()),
        error,
    })?;

    let mut res = Resolution::default();
    let root = join(pattern.host_anchor(), &prefix);
    debug_assert_eq!(pattern.walk_root().as_ref(), Some(&root));
    let sandbox_root = join(pattern.sandbox_anchor(), &prefix);
    if let Err(error) = root.metadata() {
        res.warn_io(join(pattern.host_anchor(), &prefix), root, error);
        return Ok(res);
    }

    let mut walk = WalkDir::new(&root)
        .follow_links(false)
        // The root is on the way to every match, like the components before
        // it, so a link there is followed; links below it never are.
        .follow_root_links(true)
        .min_depth(1);
    if !remainder.contains("**") {
        // Without `**` every match has exactly this many components. This is
        // only an optimisation: matching alone is correct.
        walk = walk.max_depth(components.len() - split);
    }
    for entry in walk {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                res.warn_walk(&root, err);
                continue;
            }
        };
        let relative = entry
            .path()
            .strip_prefix(&root)
            .expect("walkdir yields paths below its root");
        if matcher.is_match(relative) {
            res.paths.push(ResolvedPath {
                host: entry.path().to_owned(),
                sandbox: sandbox_root.join(relative),
                kind: EntryKind::from_file_type(entry.file_type()),
            });
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
}
