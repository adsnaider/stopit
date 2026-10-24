//! Placeholder expansion for path rules (DESIGN.md §3.4, §6.2).
//!
//! A syntactically valid [`PathPattern`] is turned into a host-side and a
//! sandbox-side location: `{workspace}` is the host workspace directory on the
//! host side and the workspace mount point on the sandbox side, `~` is the
//! host `$HOME` on the host side and the sandbox `HOME` on the sandbox side,
//! and absolute paths map to themselves.
//!
//! Everything here is pure: the filesystem is never consulted. Globs are
//! carried through unexpanded in [`ExpandedPattern::rest`]; expanding them
//! against the host filesystem is a separate step.

use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::config::WorkspaceMount;
use crate::manifest::{Bind, PathPattern, PatternAnchor, SandboxAnchor, SandboxHome, has_glob};

/// Error building an [`ExpansionContext`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ExpandError {
    /// A host path supplied by the environment is not absolute and normalised.
    #[error("invalid {what} {path:?}: {why}")]
    InvalidHostPath {
        /// Which input was rejected, e.g. `workspace directory`.
        what: &'static str,
        /// The offending value.
        path: PathBuf,
        /// Why it was rejected.
        why: &'static str,
    },
}

/// Checks that `path` is absolute and normalised: no `.`, `..` or empty
/// components, no trailing `/`, no NUL, and not `/`.
fn check_host_dir(what: &'static str, path: &Path) -> Result<(), ExpandError> {
    let bad = |why: &'static str| ExpandError::InvalidHostPath {
        what,
        path: path.to_owned(),
        why,
    };
    let bytes = path.as_os_str().as_bytes();
    if bytes.contains(&0) {
        return Err(bad("must not contain NUL bytes"));
    }
    let Some(rest) = bytes.strip_prefix(b"/") else {
        return Err(bad("must be an absolute path"));
    };
    if rest.is_empty() {
        return Err(bad("must not be the root directory"));
    }
    for c in rest.split(|&b| b == b'/') {
        match c {
            b"" => return Err(bad("must not contain empty components or a trailing `/`")),
            b"." | b".." => return Err(bad("must not contain `.` or `..` components")),
            _ => {}
        }
    }
    Ok(())
}

/// The session values needed to expand `{workspace}` and `~`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpansionContext {
    workspace_host: PathBuf,
    workspace_sandbox: PathBuf,
    host_home: PathBuf,
    sandbox_home: PathBuf,
}

impl ExpansionContext {
    /// Creates a context.
    ///
    /// `workspace_host` and `host_home` come from the environment rather than
    /// from user configuration, but a relative or odd `$HOME` must not
    /// silently produce wrong mappings, so both must be absolute and
    /// normalised (no `.`, `..` or empty components, no trailing `/`, not
    /// `/`).
    pub fn new(
        workspace_host: PathBuf,
        workspace_mount: WorkspaceMount,
        host_home: PathBuf,
        sandbox_home: SandboxHome,
    ) -> Result<Self, ExpandError> {
        check_host_dir("workspace directory", &workspace_host)?;
        check_host_dir("host home directory", &host_home)?;
        Ok(ExpansionContext {
            workspace_host,
            // A mount such as `/work/` is accepted by `WorkspaceMount`;
            // normalise it so joins and comparisons are uniform.
            workspace_sandbox: workspace_mount.as_path().components().collect(),
            host_home,
            sandbox_home: PathBuf::from(sandbox_home.as_str()),
        })
    }
}

/// Joins `rest` onto `anchor`, without adding a trailing `/` for an empty
/// `rest`.
fn join(anchor: &Path, rest: &Path) -> PathBuf {
    if rest.as_os_str().is_empty() {
        anchor.to_owned()
    } else {
        anchor.join(rest)
    }
}

/// A path rule with its leading part expanded.
///
/// The full host path is `host_anchor/rest` and the full sandbox path is
/// `sandbox_anchor/rest`; `rest` is relative (never begins with `/`), may be
/// empty, and may contain glob metacharacters.
///
/// The fields are private so that `rest` cannot be replaced by an absolute
/// path, which `Path::join` would treat as discarding the anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpandedPattern {
    host_anchor: PathBuf,
    sandbox_anchor: PathBuf,
    rest: PathBuf,
}

impl ExpandedPattern {
    /// What the leading part expanded to on the host.
    pub fn host_anchor(&self) -> &Path {
        &self.host_anchor
    }

    /// What the leading part expanded to inside the sandbox.
    pub fn sandbox_anchor(&self) -> &Path {
        &self.sandbox_anchor
    }

    /// The remaining relative path: possibly empty, never absolute, and
    /// possibly containing glob characters.
    pub fn rest(&self) -> &Path {
        &self.rest
    }

    /// Whether `rest` contains any of the glob characters `*`, `?`, `[`, `]`.
    pub fn has_glob(&self) -> bool {
        has_glob(&self.rest.to_string_lossy())
    }

    /// The host path, or `None` if the pattern is a glob (use
    /// [`has_glob`](Self::has_glob) to tell, and expand globs first).
    pub fn host(&self) -> Option<PathBuf> {
        (!self.has_glob()).then(|| join(&self.host_anchor, &self.rest))
    }

    /// The sandbox path, or `None` if the pattern is a glob.
    pub fn sandbox(&self) -> Option<PathBuf> {
        (!self.has_glob()).then(|| join(&self.sandbox_anchor, &self.rest))
    }
}

/// Expands the leading `{workspace}`, `~` or `/` of `pattern`.
pub fn expand_pattern(pattern: &PathPattern, ctx: &ExpansionContext) -> ExpandedPattern {
    let (anchor, rest) = pattern.split();
    let (host_anchor, sandbox_anchor) = match anchor {
        PatternAnchor::Workspace => (ctx.workspace_host.clone(), ctx.workspace_sandbox.clone()),
        PatternAnchor::Home => (ctx.host_home.clone(), ctx.sandbox_home.clone()),
        PatternAnchor::Root => (PathBuf::from("/"), PathBuf::from("/")),
    };
    ExpandedPattern {
        host_anchor,
        sandbox_anchor,
        rest: PathBuf::from(rest),
    }
}

/// A host path and where it appears in the sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathMapping {
    /// The host path.
    pub host: PathBuf,
    /// The sandbox path.
    pub sandbox: PathBuf,
}

/// Expands a bind: its `host` on the host side (`{workspace}`, `~` and
/// absolute paths) and its `sandbox` on the sandbox side (`~` is the sandbox
/// `HOME`, absolute paths map to themselves).
///
/// A bind's host is glob-free when deserialized; if a hand-built `Bind`
/// contains glob characters they are treated as literal path text.
pub fn expand_bind(bind: &Bind, ctx: &ExpansionContext) -> PathMapping {
    let host = expand_pattern(&bind.host, ctx);
    let (anchor, rest) = bind.sandbox.split();
    let sandbox_anchor = match anchor {
        SandboxAnchor::Home => ctx.sandbox_home.clone(),
        SandboxAnchor::Root => PathBuf::from("/"),
    };
    PathMapping {
        host: join(host.host_anchor(), host.rest()),
        sandbox: join(&sandbox_anchor, Path::new(rest)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pp(s: &str) -> PathPattern {
        s.parse().unwrap()
    }

    fn ctx() -> ExpansionContext {
        ExpansionContext::new(
            "/src/proj".into(),
            "/workspace".parse().unwrap(),
            "/home/alice".into(),
            "/home/user".parse().unwrap(),
        )
        .unwrap()
    }

    fn custom_ctx() -> ExpansionContext {
        ExpansionContext::new(
            "/data/my proj".into(),
            "/work/tree/".parse().unwrap(),
            "/root".into(),
            "/sbx/h".parse().unwrap(),
        )
        .unwrap()
    }

    fn p(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    fn exp(c: &ExpansionContext, s: &str) -> ExpandedPattern {
        expand_pattern(&pp(s), c)
    }

    fn anchors(e: &ExpandedPattern) -> (&Path, &Path, &Path) {
        (e.host_anchor(), e.sandbox_anchor(), e.rest())
    }

    #[test]
    fn workspace_anchor() {
        let c = ctx();
        let e = exp(&c, "{workspace}");
        assert_eq!(
            anchors(&e),
            (
                Path::new("/src/proj"),
                Path::new("/workspace"),
                Path::new("")
            )
        );
        let e = exp(&c, "{workspace}/a/*.nix");
        assert_eq!(
            anchors(&e),
            (
                Path::new("/src/proj"),
                Path::new("/workspace"),
                Path::new("a/*.nix")
            )
        );
        let e = exp(&c, "{workspace}/.git");
        assert_eq!(e.rest, p(".git"));
    }

    #[test]
    fn home_anchor() {
        let c = ctx();
        let e = exp(&c, "~");
        assert_eq!(
            anchors(&e),
            (
                Path::new("/home/alice"),
                Path::new("/home/user"),
                Path::new("")
            )
        );
        let e = exp(&c, "~/.claude");
        assert_eq!(
            anchors(&e),
            (
                Path::new("/home/alice"),
                Path::new("/home/user"),
                Path::new(".claude")
            )
        );
    }

    #[test]
    fn absolute_anchor() {
        let c = ctx();
        let e = exp(&c, "/etc/ssl/certs");
        assert_eq!(
            anchors(&e),
            (Path::new("/"), Path::new("/"), Path::new("etc/ssl/certs"))
        );
        let e = exp(&c, "/tmp");
        assert_eq!(
            anchors(&e),
            (Path::new("/"), Path::new("/"), Path::new("tmp"))
        );
    }

    #[test]
    fn deeply_nested_and_glob_rests() {
        let c = ctx();
        let e = exp(&c, "{workspace}/a/b/c/d/e/f.txt");
        assert_eq!(e.rest, p("a/b/c/d/e/f.txt"));
        assert!(!e.has_glob());
        let e = exp(&c, "{workspace}/**/.env");
        assert_eq!(e.rest, p("**/.env"));
        assert_eq!(e.host_anchor, p("/src/proj"));
        assert!(e.has_glob());
        let e = exp(&c, "/nix/store/*-foo");
        assert_eq!(e.rest, p("nix/store/*-foo"));
        assert!(e.has_glob());
        let e = exp(&c, "~/.config/*/settings");
        assert_eq!(e.rest, p(".config/*/settings"));
        assert!(e.has_glob());
    }

    #[test]
    fn rest_is_relative_and_never_starts_with_slash() {
        let c = ctx();
        for s in [
            "{workspace}",
            "{workspace}/a",
            "{workspace}/**",
            "~",
            "~/a/b",
            "~/.cache/**",
            "/a",
            "/a/b/c",
            "/nix/store/*-foo",
            "/.hidden",
        ] {
            let e = exp(&c, s);
            assert!(e.rest.is_relative(), "{s}: {:?}", e.rest);
            assert!(!e.rest.to_string_lossy().starts_with('/'), "{s}");
            assert!(!e.rest.to_string_lossy().ends_with('/'), "{s}");
        }
    }

    #[test]
    fn has_glob_on_every_glob_character() {
        let c = ctx();
        for s in [
            "{workspace}/*",
            "{workspace}/a?",
            "{workspace}/a[b",
            "{workspace}/a]b",
            "{workspace}/[ab]",
            "/a/b*",
        ] {
            assert!(exp(&c, s).has_glob(), "{s}");
        }
        for s in [
            "{workspace}",
            "~",
            "/a",
            "{workspace}/a.b-c_d",
            "~/.config/x",
        ] {
            assert!(!exp(&c, s).has_glob(), "{s}");
        }
    }

    #[test]
    fn host_and_sandbox_for_non_glob() {
        let c = ctx();
        let e = exp(&c, "{workspace}");
        assert_eq!(e.host(), Some(p("/src/proj")));
        assert_eq!(e.sandbox(), Some(p("/workspace")));
        let e = exp(&c, "{workspace}/a/b");
        assert_eq!(e.host(), Some(p("/src/proj/a/b")));
        assert_eq!(e.sandbox(), Some(p("/workspace/a/b")));
        let e = exp(&c, "~");
        assert_eq!(e.host(), Some(p("/home/alice")));
        assert_eq!(e.sandbox(), Some(p("/home/user")));
        let e = exp(&c, "~/.claude");
        assert_eq!(e.host(), Some(p("/home/alice/.claude")));
        assert_eq!(e.sandbox(), Some(p("/home/user/.claude")));
        let e = exp(&c, "/etc/ssl/certs");
        assert_eq!(e.host(), Some(p("/etc/ssl/certs")));
        assert_eq!(e.sandbox(), Some(p("/etc/ssl/certs")));
    }

    #[test]
    fn host_and_sandbox_are_none_for_globs() {
        let c = ctx();
        for s in ["{workspace}/**/.env", "/nix/store/*-foo", "~/.config/*/x"] {
            let e = exp(&c, s);
            assert_eq!(e.host(), None, "{s}");
            assert_eq!(e.sandbox(), None, "{s}");
        }
    }

    #[test]
    fn non_default_workspace_mount_and_sandbox_home() {
        let c = custom_ctx();
        let e = exp(&c, "{workspace}/a/*.nix");
        assert_eq!(e.host_anchor, p("/data/my proj"));
        assert_eq!(e.sandbox_anchor, p("/work/tree"));
        assert_eq!(e.rest, p("a/*.nix"));
        let e = exp(&c, "{workspace}/x");
        assert_eq!(e.host(), Some(p("/data/my proj/x")));
        assert_eq!(e.sandbox(), Some(p("/work/tree/x")));
        let e = exp(&c, "{workspace}");
        assert_eq!(e.sandbox(), Some(p("/work/tree")));
        assert!(!e.sandbox().unwrap().to_string_lossy().ends_with('/'));
        let e = exp(&c, "~/.claude");
        assert_eq!(e.host(), Some(p("/root/.claude")));
        assert_eq!(e.sandbox(), Some(p("/sbx/h/.claude")));
        let e = exp(&c, "~");
        assert_eq!(e.host(), Some(p("/root")));
        assert_eq!(e.sandbox(), Some(p("/sbx/h")));
    }

    fn bind(host: &str, sandbox: &str) -> Bind {
        Bind {
            host: pp(host),
            sandbox: sandbox.parse().unwrap(),
            mode: crate::manifest::BindMode::Ro,
        }
    }

    fn mapping(c: &ExpansionContext, host: &str, sandbox: &str) -> (PathBuf, PathBuf) {
        let m = expand_bind(&bind(host, sandbox), c);
        (m.host, m.sandbox)
    }

    #[test]
    fn bind_expansion_for_every_combination() {
        let c = ctx();
        for (host, want_host) in [
            ("{workspace}", "/src/proj"),
            ("{workspace}/vendor", "/src/proj/vendor"),
            ("~", "/home/alice"),
            ("~/.cache/tool", "/home/alice/.cache/tool"),
            ("/etc/ssl/certs", "/etc/ssl/certs"),
        ] {
            for (sandbox, want_sandbox) in [
                ("~", "/home/user"),
                ("~/.cache/tool", "/home/user/.cache/tool"),
                ("/opt/vendor", "/opt/vendor"),
                ("/etc/ssl/certs", "/etc/ssl/certs"),
            ] {
                assert_eq!(
                    mapping(&c, host, sandbox),
                    (p(want_host), p(want_sandbox)),
                    "{host} -> {sandbox}"
                );
            }
        }
    }

    #[test]
    fn bind_expansion_with_custom_context() {
        let c = custom_ctx();
        assert_eq!(
            mapping(&c, "{workspace}/vendor", "/opt/vendor"),
            (p("/data/my proj/vendor"), p("/opt/vendor"))
        );
        assert_eq!(
            mapping(&c, "~/.cache", "~/.cache"),
            (p("/root/.cache"), p("/sbx/h/.cache"))
        );
        assert_eq!(mapping(&c, "/a", "~"), (p("/a"), p("/sbx/h")));
    }

    #[test]
    fn bind_sandbox_side_never_uses_the_workspace_mount() {
        // `{workspace}` is not valid on the sandbox side, so a sandbox path
        // under the mount is spelled absolutely and maps to itself.
        let c = custom_ctx();
        assert_eq!(
            mapping(&c, "~/x", "/work/tree/x"),
            (p("/root/x"), p("/work/tree/x"))
        );
    }

    #[test]
    fn pattern_splitting_accessors() {
        assert_eq!(pp("{workspace}").split(), (PatternAnchor::Workspace, ""));
        assert_eq!(
            pp("{workspace}/a/b").split(),
            (PatternAnchor::Workspace, "a/b")
        );
        assert_eq!(pp("~").split(), (PatternAnchor::Home, ""));
        assert_eq!(pp("~/.x/*").split(), (PatternAnchor::Home, ".x/*"));
        assert_eq!(pp("/a/b").split(), (PatternAnchor::Root, "a/b"));
        let sp = |s: &str| s.parse::<crate::manifest::SandboxPath>().unwrap();
        assert_eq!(sp("~").split(), (SandboxAnchor::Home, ""));
        assert_eq!(sp("~/a").split(), (SandboxAnchor::Home, "a"));
        assert_eq!(sp("/a/b").split(), (SandboxAnchor::Root, "a/b"));
    }

    fn new_ctx(ws: &str, home: &str) -> Result<ExpansionContext, ExpandError> {
        ExpansionContext::new(
            ws.into(),
            "/workspace".parse().unwrap(),
            home.into(),
            "/home/user".parse().unwrap(),
        )
    }

    #[test]
    fn constructor_accepts_normalised_absolute_paths() {
        new_ctx("/a", "/b").unwrap();
        new_ctx("/a/b c/d", "/home/x..y").unwrap();
        new_ctx("/.hidden", "/h").unwrap();
    }

    #[test]
    fn constructor_rejects_bad_workspace_host() {
        for bad in [
            "", "rel", "./a", "a/b", "/", "//", "/a/", "/a//b", "/a/./b", "/a/..", "/../a", "/a/.",
            "/a\0b",
        ] {
            let err = new_ctx(bad, "/home/x").unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains("workspace directory"), "{bad:?}: {msg}");
            assert!(msg.contains(&format!("{bad:?}")), "{bad:?}: {msg}");
        }
    }

    #[test]
    fn constructor_rejects_bad_host_home() {
        for bad in [
            "",
            "rel",
            "~",
            "~/x",
            "/",
            "/home/",
            "/home//x",
            "/home/..",
            "/home/../x",
            "/./x",
            "/h\0",
        ] {
            let err = new_ctx("/ws", bad).unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains("host home directory"), "{bad:?}: {msg}");
            assert!(msg.contains(&format!("{bad:?}")), "{bad:?}: {msg}");
        }
    }

    #[test]
    fn non_utf8_host_paths_are_accepted_and_joined() {
        use std::ffi::OsStr;
        let ws = PathBuf::from(OsStr::from_bytes(b"/data/\xff\xfeproj"));
        let home = PathBuf::from(OsStr::from_bytes(b"/home/\xc3("));
        let c = ExpansionContext::new(
            ws,
            "/workspace".parse().unwrap(),
            home,
            "/home/user".parse().unwrap(),
        )
        .unwrap();
        let e = exp(&c, "{workspace}/a");
        assert_eq!(
            e.host().unwrap().as_os_str().as_bytes(),
            b"/data/\xff\xfeproj/a"
        );
        assert_eq!(e.sandbox(), Some(p("/workspace/a")));
        let e = exp(&c, "~/a");
        assert_eq!(e.host().unwrap().as_os_str().as_bytes(), b"/home/\xc3(/a");
        assert_eq!(e.sandbox(), Some(p("/home/user/a")));
    }

    #[test]
    fn workspace_inside_home_expands_independently() {
        let c = ExpansionContext::new(
            "/home/alice/proj".into(),
            "/workspace".parse().unwrap(),
            "/home/alice".into(),
            "/home/user".parse().unwrap(),
        )
        .unwrap();
        let e = exp(&c, "{workspace}/a");
        assert_eq!(e.host(), Some(p("/home/alice/proj/a")));
        assert_eq!(e.sandbox(), Some(p("/workspace/a")));
        let e = exp(&c, "~/a");
        assert_eq!(e.host(), Some(p("/home/alice/a")));
        assert_eq!(e.sandbox(), Some(p("/home/user/a")));
        let m = expand_bind(&bind("~/proj", "~/proj"), &c);
        assert_eq!(m.host, p("/home/alice/proj"));
        assert_eq!(m.sandbox, p("/home/user/proj"));
    }

    #[test]
    fn constructor_error_says_why() {
        let msg = new_ctx("rel", "/h").unwrap_err().to_string();
        assert!(msg.contains("absolute"), "{msg}");
        let msg = new_ctx("/", "/h").unwrap_err().to_string();
        assert!(msg.contains("root"), "{msg}");
        let msg = new_ctx("/a/", "/h").unwrap_err().to_string();
        assert!(msg.contains("trailing"), "{msg}");
        let msg = new_ctx("/a/../b", "/h").unwrap_err().to_string();
        assert!(msg.contains(".."), "{msg}");
        let msg = new_ctx("/a\0b", "/h").unwrap_err().to_string();
        assert!(msg.contains("NUL"), "{msg}");
    }
}
