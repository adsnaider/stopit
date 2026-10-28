//! stopit's own host state directories (DESIGN.md §2.1; §6.2, Reserved host
//! paths).
//!
//! stopit keeps state on the host in two directories:
//!
//! * the **runtime directory** `$XDG_RUNTIME_DIR/stopit`, which holds every
//!   session's directory (§2.1): its sockets, shims, provisioned binary and
//!   ephemeral backing directories;
//! * the **data directory**, which holds stopit's persistent state, such as
//!   the record of configurations the user allowed. It is
//!   `<home>/.local/share/stopit`, where `<home>` is the user's home
//!   directory from the password database, not `$HOME`, and `XDG_DATA_HOME`
//!   is not honoured: a location taken from the environment would let a
//!   sandbox of a session started with one value plant a store where a
//!   session started with another looks for it. `STOPIT_STATE_DIR` puts it
//!   elsewhere, for tests and special setups; the default location is then
//!   reserved too.
//!
//! No sandbox may see into either, nor write them or a directory on the way
//! to them: they decide what the next session trusts and runs. [`StateDirs`]
//! names them for a session, so that the spec compiler can refuse mounts
//! that would expose them (`spec::compile_session`). [`data_dirs_from_host`]
//! finds the data directory, as every command using it must.

use std::ffi::{CStr, OsStr, OsString};
use std::fmt;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use thiserror::Error;

/// The name of stopit's directory inside `XDG_RUNTIME_DIR` and
/// `~/.local/share`.
pub const STATE_DIR_NAME: &str = "stopit";

/// The environment variable that overrides where the data directory is
/// (see [`data_dirs`]).
pub const STATE_DIR_ENV: &str = "STOPIT_STATE_DIR";

/// The most symlinks [`resolve_allowing_missing`] follows, as the kernel
/// does (`ELOOP` past it).
const MAX_LINKS: usize = 40;

/// The largest buffer [`lookup_home`] gives `getpwuid_r`.
const MAX_PASSWD_BUFFER: usize = 1 << 20;

/// Error finding the data directory.
#[derive(Debug, Error)]
pub enum StateError {
    /// The password database has no entry for the user.
    #[error(
        "the password database has no entry for uid {uid}; stopit needs the user's home directory \
         for its data directory"
    )]
    NoPasswdEntry {
        /// The user's uid.
        uid: u32,
    },

    /// The password database could not be read.
    #[error("cannot look up uid {uid} in the password database: {source}")]
    Passwd {
        /// The user's uid.
        uid: u32,
        /// The underlying error.
        source: io::Error,
    },

    /// The user's home directory in the password database is not an
    /// absolute path.
    #[error(
        "the home directory of uid {uid} in the password database, {path:?}, is not an absolute \
         path; stopit needs it for its data directory"
    )]
    PasswdHomeRelative {
        /// The user's uid.
        uid: u32,
        /// The home directory found.
        path: PathBuf,
    },

    /// `STOPIT_STATE_DIR` is set to a path that is not absolute.
    #[error(
        "{STATE_DIR_ENV} {path:?} is not an absolute path; set it to the absolute path of stopit's \
         data directory, or unset it"
    )]
    OverrideRelative {
        /// The value of `STOPIT_STATE_DIR`.
        path: PathBuf,
    },

    /// A state directory's path cannot be resolved.
    #[error("cannot resolve stopit's state directory {path:?}: {source}")]
    Resolve {
        /// The directory, before resolving.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },
}

/// Which of stopit's state directories a path is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateDir {
    /// `$XDG_RUNTIME_DIR/stopit`, the parent of every session directory.
    Runtime,
    /// A data directory ([`DataDirs`]): stopit's persistent state.
    Data,
}

impl StateDir {
    /// What the directory holds, for messages.
    pub fn holds(self) -> &'static str {
        match self {
            StateDir::Runtime => {
                "every session's sockets, shims and ephemeral directories (other sessions' data \
                 included)"
            }
            StateDir::Data => "stopit's persistent state, such as which configurations you allowed",
        }
    }
}

impl fmt::Display for StateDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            StateDir::Runtime => "session runtime directory",
            StateDir::Data => "data directory",
        })
    }
}

/// Where a state directory is: its path with every symlink resolved, and
/// the symlinks on the way there from the path it was given as (see
/// [`resolve_allowing_missing`]). Replacing one of those links, or a
/// directory on the way, moves the directory, so a sandbox must not be
/// able to write any of them either.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatePath {
    /// The resolved path: canonical up to its deepest existing ancestor.
    pub path: PathBuf,
    /// Each symlink followed on the way, at its own resolved path (its
    /// parent directory canonical), in the order followed.
    pub links: Vec<PathBuf>,
}

impl StatePath {
    /// `path`, with no link on the way to it (it is canonical).
    pub fn canonical(path: PathBuf) -> Self {
        StatePath {
            path,
            links: Vec::new(),
        }
    }
}

/// stopit's data directories (see [`data_dirs`]): where this session keeps
/// its persistent state, and the default location when that is elsewhere.
/// Both are reserved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataDirs {
    /// Where stopit keeps its persistent state: `STOPIT_STATE_DIR` if set,
    /// else the default location `<home>/.local/share/stopit`.
    pub store: StatePath,
    /// The default location, when `STOPIT_STATE_DIR` puts the store
    /// elsewhere: sessions started without it use it.
    pub default: Option<StatePath>,
}

impl DataDirs {
    /// The data directory at `path`, the default location, with no link on
    /// the way to it.
    pub fn canonical(path: PathBuf) -> Self {
        DataDirs {
            store: StatePath::canonical(path),
            default: None,
        }
    }

    /// The store, then the default location if it is reserved too.
    pub fn iter(&self) -> impl Iterator<Item = &StatePath> {
        std::iter::once(&self.store).chain(&self.default)
    }
}

/// stopit's host state directories for a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateDirs {
    /// `$XDG_RUNTIME_DIR/stopit` ([`runtime_dir`]); it exists once a session
    /// directory does.
    pub runtime: StatePath,
    /// The data directories ([`data_dirs`]), which need not exist yet.
    pub data: DataDirs,
}

impl StateDirs {
    /// Each directory, with which one it is.
    pub fn iter(&self) -> impl Iterator<Item = (StateDir, &StatePath)> {
        std::iter::once((StateDir::Runtime, &self.runtime))
            .chain(self.data.iter().map(|d| (StateDir::Data, d)))
    }
}

/// stopit's runtime directory `$XDG_RUNTIME_DIR/stopit`, from the value of
/// `XDG_RUNTIME_DIR` (which the session directory has already checked:
/// set and absolute), resolved with [`resolve_allowing_missing`].
pub fn runtime_dir(xdg_runtime_dir: &Path) -> Result<StatePath, StateError> {
    resolve(xdg_runtime_dir.join(STATE_DIR_NAME))
}

/// stopit's data directories for the current user: [`data_dirs`] of the
/// user's home directory in the password database ([`passwd_home`]) and
/// `STOPIT_STATE_DIR` from the process environment.
pub fn data_dirs_from_host() -> Result<DataDirs, StateError> {
    let home = passwd_home(rustix::process::getuid().as_raw())?;
    data_dirs(&home, std::env::var_os(STATE_DIR_ENV).as_deref())
}

/// stopit's data directories, from the user's (absolute) home directory
/// `home` as the password database gives it, and the value of
/// `STOPIT_STATE_DIR` (`None` if unset).
///
/// The default location is `<home>/.local/share/stopit`. It never comes
/// from the environment (neither `HOME` nor `XDG_DATA_HOME`): if it did, a
/// sandbox of a session started with one value could plant a store where a
/// session started with another (from another shell, over ssh, from a
/// systemd unit) looks for it. `STOPIT_STATE_DIR`, an absolute path, puts
/// the store there instead, for tests and special setups; the default
/// location is then reserved too, so that a sandbox cannot plant a store
/// for sessions started without the override. A session started without it
/// does not reserve the override's directory, so it must be used
/// consistently.
///
/// The directories need not exist. Their paths are resolved with
/// [`resolve_allowing_missing`]: every symlink on the way that exists is
/// followed, so that a link (`~/.local -> /data/local`) does not hide where
/// one really is, and the rest is joined as written.
pub fn data_dirs(home: &Path, state_dir: Option<&OsStr>) -> Result<DataDirs, StateError> {
    let default = resolve(home.join(".local/share").join(STATE_DIR_NAME))?;
    let Some(state_dir) = state_dir else {
        return Ok(DataDirs {
            store: default,
            default: None,
        });
    };
    let state_dir = Path::new(state_dir);
    if !state_dir.is_absolute() {
        return Err(StateError::OverrideRelative {
            path: state_dir.to_owned(),
        });
    }
    let store = resolve(state_dir.to_owned())?;
    let default = (store.path != default.path).then_some(default);
    Ok(DataDirs { store, default })
}

/// [`resolve_allowing_missing`] for a state directory.
fn resolve(path: PathBuf) -> Result<StatePath, StateError> {
    resolve_allowing_missing(&path).map_err(|source| StateError::Resolve { path, source })
}

/// The home directory of the user `uid` in the password database
/// (`getpwuid_r`), which must be an absolute path. The supervisor runs on
/// the host, so NSS is available.
pub fn passwd_home(uid: u32) -> Result<PathBuf, StateError> {
    let home = lookup_home(uid).map_err(|source| StateError::Passwd { uid, source })?;
    checked_home(uid, home)
}

/// `home`, the home directory found for `uid` (`None` without an entry),
/// if it is absolute.
fn checked_home(uid: u32, home: Option<PathBuf>) -> Result<PathBuf, StateError> {
    match home {
        None => Err(StateError::NoPasswdEntry { uid }),
        Some(path) if !path.is_absolute() => Err(StateError::PasswdHomeRelative { uid, path }),
        Some(path) => Ok(path),
    }
}

/// The home directory of `uid` in the password database, or `None` if it
/// has no entry.
fn lookup_home(uid: u32) -> io::Result<Option<PathBuf>> {
    let mut buf: Vec<libc::c_char> = vec![0; 1024];
    loop {
        // SAFETY: `passwd` is plain data, for which all zeroes is valid.
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: every pointer is valid for the call, and `buf.len()` is
        // the length of `buf`.
        let rc =
            unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) };
        match rc {
            0 if result.is_null() => return Ok(None),
            0 if pwd.pw_dir.is_null() => return Ok(Some(PathBuf::new())),
            0 => {
                // SAFETY: on success `pw_dir` points to a NUL-terminated
                // string inside `buf`, which is still alive.
                let dir = unsafe { CStr::from_ptr(pwd.pw_dir) };
                return Ok(Some(PathBuf::from(OsStr::from_bytes(dir.to_bytes()))));
            }
            // Some implementations report a missing entry as an error.
            libc::ENOENT | libc::ESRCH => return Ok(None),
            libc::ERANGE if buf.len() < MAX_PASSWD_BUFFER => {
                let len = buf.len() * 2;
                buf.resize(len, 0);
            }
            e => return Err(io::Error::from_raw_os_error(e)),
        }
    }
}

/// The absolute `path` with every symlink resolved, as the kernel would,
/// except that a missing component is fine: it and everything after it are
/// joined as written (a `..` after it drops the previous component). So the
/// result is the canonical path of `path`'s deepest existing ancestor joined
/// with the rest, a dangling link included: its target is where the rest
/// would be created. Every link followed is recorded too.
///
/// Fails if a component that exists cannot be inspected or is not a
/// directory while more follow, or after more than 40 links (`ELOOP`).
pub fn resolve_allowing_missing(path: &Path) -> io::Result<StatePath> {
    fn push(pending: &mut Vec<OsString>, path: &Path) {
        let parts: Vec<OsString> = path
            .components()
            .filter_map(|c| match c {
                Component::Normal(s) => Some(s.to_owned()),
                Component::ParentDir => Some(OsString::from("..")),
                Component::RootDir | Component::CurDir | Component::Prefix(_) => None,
            })
            .collect();
        pending.extend(parts.into_iter().rev());
    }
    if !path.is_absolute() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    // The components still to walk, the next one last.
    let mut pending = Vec::new();
    push(&mut pending, path);
    let mut resolved = PathBuf::from("/");
    let mut links = Vec::new();
    let mut missing = false;
    while let Some(c) = pending.pop() {
        if c == ".." {
            // `resolved` has no links, so this is what the kernel does.
            resolved.pop();
            continue;
        }
        let next = resolved.join(&c);
        if missing {
            resolved = next;
            continue;
        }
        match fs::symlink_metadata(&next) {
            Ok(meta) if meta.file_type().is_symlink() => {
                if links.len() == MAX_LINKS {
                    return Err(io::Error::from_raw_os_error(libc::ELOOP));
                }
                let target = fs::read_link(&next)?;
                links.push(next);
                if target.is_absolute() {
                    resolved = PathBuf::from("/");
                }
                push(&mut pending, &target);
            }
            Ok(_) => resolved = next,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                missing = true;
                resolved = next;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(StatePath {
        path: resolved,
        links,
    })
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use tempfile::TempDir;

    use super::*;

    /// A canonical temporary directory.
    fn tmp() -> (TempDir, PathBuf) {
        let dir = TempDir::new().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        (dir, root)
    }

    fn os(p: &Path) -> Option<&OsStr> {
        Some(p.as_os_str())
    }

    #[test]
    fn without_the_override_the_store_is_in_the_home_directory() {
        let (_d, root) = tmp();
        assert_eq!(
            data_dirs(&root.join("home"), None).unwrap(),
            DataDirs {
                store: StatePath::canonical(root.join("home/.local/share/stopit")),
                default: None,
            }
        );
    }

    #[test]
    fn with_the_override_the_store_is_there_and_both_are_reserved() {
        let (_d, root) = tmp();
        let dirs = data_dirs(&root.join("home"), os(&root.join("state"))).unwrap();
        let default = StatePath::canonical(root.join("home/.local/share/stopit"));
        assert_eq!(
            dirs,
            DataDirs {
                store: StatePath::canonical(root.join("state")),
                default: Some(default.clone()),
            }
        );
        assert_eq!(
            dirs.iter().collect::<Vec<_>>(),
            [&StatePath::canonical(root.join("state")), &default]
        );
        let state = StateDirs {
            runtime: StatePath::canonical(root.join("run/stopit")),
            data: dirs,
        };
        assert_eq!(
            state
                .iter()
                .map(|(dir, p)| (dir, p.path.clone()))
                .collect::<Vec<_>>(),
            [
                (StateDir::Runtime, root.join("run/stopit")),
                (StateDir::Data, root.join("state")),
                (StateDir::Data, root.join("home/.local/share/stopit")),
            ]
        );
        // An override naming the default location (here through a link)
        // reserves it once.
        fs::create_dir_all(root.join("home/.local/share")).unwrap();
        symlink("home/.local/share", root.join("share")).unwrap();
        let dirs = data_dirs(&root.join("home"), os(&root.join("share/stopit"))).unwrap();
        assert_eq!(dirs.store.path, root.join("home/.local/share/stopit"));
        assert_eq!(dirs.default, None);
    }

    #[test]
    fn a_relative_override_is_an_error() {
        let (_d, root) = tmp();
        for value in ["rel/state", ""] {
            let e = data_dirs(&root, Some(OsStr::new(value))).unwrap_err();
            assert!(matches!(e, StateError::OverrideRelative { .. }), "{e}");
            assert_eq!(
                e.to_string(),
                format!(
                    "STOPIT_STATE_DIR {value:?} is not an absolute path; set it to the absolute \
                     path of stopit's data directory, or unset it"
                )
            );
        }
    }

    #[test]
    fn the_home_directory_comes_from_the_password_database() {
        let uid = rustix::process::getuid().as_raw();
        let home = passwd_home(uid).unwrap();
        assert!(home.is_absolute(), "{home:?}");
        assert_eq!(lookup_home(uid).unwrap(), Some(home));
    }

    #[test]
    fn a_missing_or_relative_passwd_home_is_an_error() {
        let e = checked_home(1000, None).unwrap_err();
        assert!(matches!(e, StateError::NoPasswdEntry { uid: 1000 }), "{e}");
        assert!(e.to_string().contains("no entry for uid 1000"), "{e}");
        for home in ["", "home/me"] {
            let e = checked_home(1000, Some(home.into())).unwrap_err();
            assert!(matches!(e, StateError::PasswdHomeRelative { .. }), "{e}");
            assert!(e.to_string().contains(&format!("{home:?}")), "{e}");
        }
        assert_eq!(
            checked_home(1000, Some("/home/me".into())).unwrap(),
            Path::new("/home/me")
        );
    }

    #[test]
    fn the_runtime_directory_is_resolved_too() {
        let (_d, root) = tmp();
        fs::create_dir(root.join("run")).unwrap();
        symlink("run", root.join("run-link")).unwrap();
        assert_eq!(
            runtime_dir(&root.join("run-link")).unwrap(),
            StatePath {
                path: root.join("run/stopit"),
                links: vec![root.join("run-link")],
            }
        );
    }

    #[test]
    fn links_on_the_way_are_resolved() {
        let (_d, root) = tmp();
        // `~/.local -> ../real/local`, which exists only partly.
        fs::create_dir_all(root.join("home")).unwrap();
        fs::create_dir_all(root.join("real/local")).unwrap();
        symlink("../real/local", root.join("home/.local")).unwrap();
        let expected = StatePath {
            path: root.join("real/local/share/stopit"),
            links: vec![root.join("home/.local")],
        };
        assert_eq!(data_dirs(&root.join("home"), None).unwrap().store, expected);
        // An existing data directory reached through a link.
        fs::create_dir_all(root.join("real/local/share/stopit")).unwrap();
        assert_eq!(data_dirs(&root.join("home"), None).unwrap().store, expected);
        // A dangling link: its target is where the rest would be created.
        symlink(root.join("elsewhere"), root.join("state")).unwrap();
        let dirs = data_dirs(&root.join("home"), os(&root.join("state/stopit"))).unwrap();
        assert_eq!(
            dirs,
            DataDirs {
                store: StatePath {
                    path: root.join("elsewhere/stopit"),
                    links: vec![root.join("state")],
                },
                default: Some(expected),
            }
        );
        // Links are recorded where they are, after the links before them.
        symlink("home", root.join("home-link")).unwrap();
        assert_eq!(
            data_dirs(&root.join("home-link"), None)
                .unwrap()
                .store
                .links,
            [root.join("home-link"), root.join("home/.local")]
        );
    }

    #[test]
    fn resolve_allowing_missing_handles_dots_loops_and_files() {
        let (_d, root) = tmp();
        fs::create_dir_all(root.join("a/b")).unwrap();
        symlink("a/b/..", root.join("up")).unwrap();
        let resolved = |p: &str| resolve_allowing_missing(&root.join(p)).unwrap().path;
        assert_eq!(resolved("up/x/y"), root.join("a/x/y"));
        assert_eq!(resolved("missing/../a"), root.join("a"));
        symlink("loop", root.join("loop")).unwrap();
        let e = resolve_allowing_missing(&root.join("loop/x")).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::ELOOP), "{e}");
        fs::write(root.join("file"), "").unwrap();
        assert!(resolve_allowing_missing(&root.join("file/x")).is_err());
        assert_eq!(resolved("file"), root.join("file"));
        assert!(resolve_allowing_missing(Path::new("rel")).is_err());
    }

    #[test]
    fn a_data_directory_that_cannot_be_resolved_is_an_error() {
        let (_d, root) = tmp();
        fs::write(root.join("home"), "").unwrap();
        let e = data_dirs(&root.join("home"), None).unwrap_err();
        assert!(matches!(e, StateError::Resolve { .. }), "{e}");
        assert!(e.to_string().contains(".local/share/stopit"), "{e}");
        // The override too.
        fs::write(root.join("file"), "").unwrap();
        let e = data_dirs(&root, os(&root.join("file/state"))).unwrap_err();
        assert!(e.to_string().contains("file/state"), "{e}");
    }
}
