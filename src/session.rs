//! The per-session host directory `$XDG_RUNTIME_DIR/stopit/<session-id>/`
//! (DESIGN.md §2.1).
//!
//! All per-session state lives under it. [`SessionDir`] creates it with a
//! fresh random id (never reusing an existing directory), makes its
//! `bin/` and `ephemeral/` subdirectories, and removes the whole tree again
//! when dropped. Sockets and `protected/` are added by later phases.
//!
//! The directories are private to the current user: `$XDG_RUNTIME_DIR` must
//! be owned by us and not writable by group or others, and
//! `$XDG_RUNTIME_DIR/stopit` must be a real directory
//! (not a link) owned by us that no one else can access. stopit never falls
//! back to a world-writable location such as `/tmp`.

use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs::{self, DirBuilder, File, Permissions};
use std::io::{self, Read};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::resolve::EphemeralKey;

/// Mode of every directory stopit creates for a session.
const PRIVATE_MODE: u32 = 0o700;

/// Number of random bytes in a session id (hex-encoded to twice as many
/// characters).
const ID_BYTES: usize = 16;

/// Error creating the session runtime directory.
#[derive(Debug, Error)]
pub enum SessionError {
    /// `XDG_RUNTIME_DIR` is not set, or is empty.
    #[error("XDG_RUNTIME_DIR is not set; stopit needs it for its per-session directory")]
    RuntimeDirUnset,

    /// `XDG_RUNTIME_DIR` is not an absolute path.
    #[error("XDG_RUNTIME_DIR {path:?} is not an absolute path")]
    RuntimeDirRelative {
        /// The value of the variable.
        path: PathBuf,
    },

    /// A directory that must exist could not be inspected.
    #[error("cannot inspect {path:?}: {source}")]
    Inspect {
        /// The directory.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },

    /// A path that must be a directory is something else, such as a
    /// symlink or a file.
    #[error("{path:?} is not a directory (a symlink or other file is not accepted)")]
    NotDirectory {
        /// The path.
        path: PathBuf,
    },

    /// A directory is owned by another user.
    #[error("{path:?} is owned by uid {owner}, not by the current user (uid {expected})")]
    WrongOwner {
        /// The directory.
        path: PathBuf,
        /// The uid that owns it.
        owner: u32,
        /// The current uid.
        expected: u32,
    },

    /// A directory is accessible to its group or to others.
    #[error("{path:?} has mode {mode:04o}, but must not be accessible to group or others")]
    Insecure {
        /// The directory.
        path: PathBuf,
        /// Its permission bits.
        mode: u32,
    },

    /// `XDG_RUNTIME_DIR` is writable by its group or by others, who could
    /// then replace what stopit puts in it.
    #[error("{path:?} has mode {mode:04o}, but must not be writable by group or others")]
    RuntimeDirWritable {
        /// The directory.
        path: PathBuf,
        /// Its permission bits.
        mode: u32,
    },

    /// A directory could not be created.
    #[error("cannot create {path:?}: {source}")]
    Create {
        /// The directory.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },

    /// The operating system's random source could not be read.
    #[error("cannot read random bytes for the session id: {0}")]
    Random(#[source] io::Error),
}

/// The host directory holding one session's state. Removed, with everything
/// in it, when dropped.
#[derive(Debug)]
pub struct SessionDir {
    id: String,
    root: PathBuf,
}

impl SessionDir {
    /// Creates a fresh session directory under the `XDG_RUNTIME_DIR` of the
    /// process environment.
    pub fn create_from_env() -> Result<Self, SessionError> {
        Self::create(std::env::var_os("XDG_RUNTIME_DIR").as_deref())
    }

    /// Creates a fresh session directory under `runtime_dir` (the value of
    /// `XDG_RUNTIME_DIR`; `None` or empty means it is unset).
    pub fn create(runtime_dir: Option<&OsStr>) -> Result<Self, SessionError> {
        let runtime_dir = match runtime_dir {
            None => return Err(SessionError::RuntimeDirUnset),
            Some(dir) if dir.is_empty() => return Err(SessionError::RuntimeDirUnset),
            Some(dir) => Path::new(dir),
        };
        if !runtime_dir.is_absolute() {
            return Err(SessionError::RuntimeDirRelative {
                path: runtime_dir.to_path_buf(),
            });
        }
        let id = random_id().map_err(SessionError::Random)?;
        Self::create_with_id(runtime_dir, id)
    }

    /// Creates the session directory `id` under `runtime_dir`. Fails if it
    /// already exists, so a session never reuses another one's directory.
    fn create_with_id(runtime_dir: &Path, id: String) -> Result<Self, SessionError> {
        // The runtime directory may legitimately be reached through a link.
        // It is resolved once, and everything below uses the canonical path,
        // so what is checked is what is used and `root()` is canonical.
        let runtime_dir =
            fs::canonicalize(runtime_dir).map_err(|source| SessionError::Inspect {
                path: runtime_dir.to_path_buf(),
                source,
            })?;
        let meta = fs::metadata(&runtime_dir).map_err(|source| SessionError::Inspect {
            path: runtime_dir.clone(),
            source,
        })?;
        if !meta.is_dir() {
            return Err(SessionError::NotDirectory { path: runtime_dir });
        }
        check_owner(&runtime_dir, &meta)?;
        let mode = meta.mode() & 0o7777;
        if mode & 0o022 != 0 {
            return Err(SessionError::RuntimeDirWritable {
                path: runtime_dir,
                mode,
            });
        }

        let base = runtime_dir.join("stopit");
        match create_private_dir(&base) {
            Ok(()) => {}
            // Left by an earlier session; verified below.
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
            Err(source) => return Err(SessionError::Create { path: base, source }),
        }
        check_private_dir(&base)?;

        let root = base.join(&id);
        // Not `create_dir_all`: an existing directory is an error.
        create_private_dir(&root).map_err(|source| SessionError::Create {
            path: root.clone(),
            source,
        })?;
        // From here on, dropping `session` cleans up after a failure.
        let session = SessionDir { id, root };
        for dir in [session.bin(), session.ephemeral()] {
            create_private_dir(&dir)
                .map_err(|source| SessionError::Create { path: dir, source })?;
        }
        Ok(session)
    }

    /// The session id: the name of the session directory.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The session directory, `$XDG_RUNTIME_DIR/stopit/<session-id>`.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The directory of shim symlinks, `bin/` (DESIGN.md §2.1).
    pub fn bin(&self) -> PathBuf {
        self.root.join("bin")
    }

    /// The directory of session-scoped scratch, `ephemeral/` (DESIGN.md §2.1).
    pub fn ephemeral(&self) -> PathBuf {
        self.root.join("ephemeral")
    }

    /// The backing directory of the ephemeral mounts keyed by `key`,
    /// `ephemeral/<key.dir_name()>` (DESIGN.md §3.4), created with mode 0700
    /// if it does not exist yet. Every sandbox of the session gets the same
    /// directory for the same key, so what one writes there the next sees.
    ///
    /// An existing entry must be a real directory (not a link) owned by us.
    /// Its mode is not checked: the sandbox owns the directory it sees
    /// mounted and may `chmod` it, which must not stop the next sandbox of
    /// the session from starting. Others cannot reach it anyway, since
    /// `ephemeral/` itself is private.
    pub fn ephemeral_dir(&self, key: &EphemeralKey) -> Result<PathBuf, SessionError> {
        let dir = self.ephemeral().join(key.dir_name());
        match create_private_dir(&dir) {
            Ok(()) => {}
            // Made by an earlier sandbox of this session.
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
                check_owned_dir(&dir)?;
            }
            Err(source) => return Err(SessionError::Create { path: dir, source }),
        }
        Ok(dir)
    }
}

impl Drop for SessionDir {
    /// Removes the session directory recursively, ignoring errors.
    ///
    /// `remove_dir_all` unlinks links rather than following them, and is
    /// race-free against concurrent swaps, so nothing outside the tree is
    /// deleted. It does cross mount points, though: callers must unmount
    /// anything mounted below the root, and wait for every sandbox to exit,
    /// before dropping. Content the sandbox made unremovable (a directory
    /// with mode 000, say) is left behind; there is deliberately no
    /// chmod-and-retry, since `set_permissions` follows symlinks and could
    /// change modes outside the tree.
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// Creates the directory `path` with mode 0700, failing if it exists. The mode
/// is set explicitly, so it holds whatever the umask is.
pub(crate) fn create_private_dir(path: &Path) -> io::Result<()> {
    DirBuilder::new().mode(PRIVATE_MODE).create(path)?;
    fs::set_permissions(path, Permissions::from_mode(PRIVATE_MODE))
}

/// Checks that `dir` is owned by the current user.
fn check_owner(dir: &Path, meta: &fs::Metadata) -> Result<(), SessionError> {
    let expected = rustix::process::getuid().as_raw();
    if meta.uid() != expected {
        return Err(SessionError::WrongOwner {
            path: dir.to_path_buf(),
            owner: meta.uid(),
            expected,
        });
    }
    Ok(())
}

/// Checks that `dir` is a real directory (not a link) owned by the current
/// user, and returns its metadata.
fn check_owned_dir(dir: &Path) -> Result<fs::Metadata, SessionError> {
    let meta = fs::symlink_metadata(dir).map_err(|source| SessionError::Inspect {
        path: dir.to_path_buf(),
        source,
    })?;
    if !meta.is_dir() {
        return Err(SessionError::NotDirectory {
            path: dir.to_path_buf(),
        });
    }
    check_owner(dir, &meta)?;
    Ok(meta)
}

/// Checks that `dir` is a real directory (not a link), owned by the current
/// user, and not accessible to group or others, and returns its metadata.
pub(crate) fn check_private_dir(dir: &Path) -> Result<fs::Metadata, SessionError> {
    let meta = check_owned_dir(dir)?;
    let mode = meta.mode() & 0o7777;
    if mode & 0o077 != 0 {
        return Err(SessionError::Insecure {
            path: dir.to_path_buf(),
            mode,
        });
    }
    Ok(meta)
}

/// A random session id: [`ID_BYTES`] bytes from the kernel, hex-encoded.
fn random_id() -> io::Result<String> {
    let mut bytes = [0u8; ID_BYTES];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    let mut id = String::with_capacity(ID_BYTES * 2);
    for byte in bytes {
        write!(id, "{byte:02x}").expect("writing to a String cannot fail");
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use tempfile::TempDir;

    use super::*;

    /// A fake `XDG_RUNTIME_DIR`: a private temporary directory. It is made
    /// under the canonical temporary directory, so its path equals the
    /// canonical path `root()` is built on even when `TMPDIR` is a link.
    fn runtime() -> TempDir {
        let tmp = fs::canonicalize(std::env::temp_dir()).unwrap();
        let dir = TempDir::new_in(tmp).unwrap();
        fs::set_permissions(dir.path(), Permissions::from_mode(0o700)).unwrap();
        dir
    }

    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().mode() & 0o7777
    }

    fn create(runtime: &TempDir) -> Result<SessionDir, SessionError> {
        SessionDir::create(Some(runtime.path().as_os_str()))
    }

    #[test]
    fn creates_layout_with_private_modes() {
        let rt = runtime();
        let session = create(&rt).unwrap();

        let base = rt.path().join("stopit");
        assert_eq!(session.root(), base.join(session.id()));
        assert_eq!(session.bin(), session.root().join("bin"));
        assert_eq!(session.ephemeral(), session.root().join("ephemeral"));
        for dir in [&base, session.root(), &session.bin(), &session.ephemeral()] {
            assert!(fs::symlink_metadata(dir).unwrap().is_dir(), "{dir:?}");
            assert_eq!(mode(dir), 0o700, "{dir:?}");
        }
        // Only what DESIGN.md §2.1 lists for this phase.
        let mut entries: Vec<_> = fs::read_dir(session.root())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        entries.sort();
        assert_eq!(entries, ["bin", "ephemeral"]);
    }

    #[test]
    fn id_is_32_hex_characters() {
        let rt = runtime();
        let session = create(&rt).unwrap();
        assert_eq!(session.id().len(), 32);
        assert!(session.id().bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn sessions_get_distinct_ids_and_dirs() {
        let rt = runtime();
        let a = create(&rt).unwrap();
        let b = create(&rt).unwrap();
        assert_ne!(a.id(), b.id());
        assert_ne!(a.root(), b.root());
        assert!(a.root().is_dir());
        assert!(b.root().is_dir());
    }

    #[test]
    fn reuses_existing_private_stopit_dir() {
        let rt = runtime();
        create_private_dir(&rt.path().join("stopit")).unwrap();
        let session = create(&rt).unwrap();
        assert!(session.bin().is_dir());
    }

    #[test]
    fn existing_stopit_dir_with_wrong_mode_is_an_error() {
        for wrong in [0o755, 0o750, 0o705, 0o770, 0o777] {
            let rt = runtime();
            let base = rt.path().join("stopit");
            fs::create_dir(&base).unwrap();
            fs::set_permissions(&base, Permissions::from_mode(wrong)).unwrap();
            let err = create(&rt).unwrap_err();
            assert!(
                matches!(err, SessionError::Insecure { mode, .. } if mode == wrong),
                "{wrong:o}: {err}"
            );
            assert!(err.to_string().contains("stopit"), "{err}");
            // Nothing was created in it.
            assert_eq!(fs::read_dir(&base).unwrap().count(), 0);
        }
    }

    #[test]
    fn stopit_symlink_is_an_error() {
        let rt = runtime();
        let outside = TempDir::new().unwrap();
        fs::set_permissions(outside.path(), Permissions::from_mode(0o700)).unwrap();
        symlink(outside.path(), rt.path().join("stopit")).unwrap();

        let err = create(&rt).unwrap_err();
        assert!(matches!(err, SessionError::NotDirectory { .. }), "{err}");
        assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
    }

    #[test]
    fn stopit_regular_file_is_an_error() {
        let rt = runtime();
        fs::write(rt.path().join("stopit"), b"").unwrap();
        let err = create(&rt).unwrap_err();
        assert!(matches!(err, SessionError::NotDirectory { .. }), "{err}");
    }

    #[test]
    fn missing_runtime_dir_variable_is_an_error() {
        assert!(matches!(
            SessionDir::create(None),
            Err(SessionError::RuntimeDirUnset)
        ));
        assert!(matches!(
            SessionDir::create(Some(OsStr::new(""))),
            Err(SessionError::RuntimeDirUnset)
        ));
    }

    #[test]
    fn relative_runtime_dir_is_an_error() {
        let err = SessionDir::create(Some(OsStr::new("run/user/1000"))).unwrap_err();
        assert!(
            matches!(err, SessionError::RuntimeDirRelative { .. }),
            "{err}"
        );
        assert!(err.to_string().contains("run/user/1000"), "{err}");
    }

    #[test]
    fn nonexistent_runtime_dir_is_an_error() {
        let rt = runtime();
        let missing = rt.path().join("missing");
        let err = SessionDir::create(Some(missing.as_os_str())).unwrap_err();
        assert!(matches!(err, SessionError::Inspect { .. }), "{err}");
        assert!(!missing.exists());
    }

    #[test]
    fn runtime_dir_that_is_a_file_is_an_error() {
        let rt = runtime();
        let file = rt.path().join("file");
        fs::write(&file, b"").unwrap();
        let err = SessionDir::create(Some(file.as_os_str())).unwrap_err();
        assert!(matches!(err, SessionError::NotDirectory { .. }), "{err}");
    }

    #[test]
    fn runtime_dir_owned_by_someone_else_is_an_error() {
        // `/proc` is root-owned; skip when the tests run as root.
        if rustix::process::getuid().is_root() {
            return;
        }
        let err = SessionDir::create(Some(OsStr::new("/proc"))).unwrap_err();
        assert!(matches!(err, SessionError::WrongOwner { .. }), "{err}");
    }

    #[test]
    fn runtime_dir_may_be_reached_through_a_symlink() {
        let rt = runtime();
        let link_parent = TempDir::new().unwrap();
        let link = link_parent.path().join("run");
        symlink(rt.path(), &link).unwrap();
        let session = SessionDir::create(Some(link.as_os_str())).unwrap();
        let canonical = fs::canonicalize(rt.path()).unwrap();
        assert_eq!(
            session.root(),
            canonical.join("stopit").join(session.id()),
            "root() is canonical"
        );
        assert!(session.root().is_dir());
    }

    #[test]
    fn runtime_dir_writable_by_group_or_others_is_an_error() {
        for wrong in [0o777, 0o770, 0o720, 0o702, 0o722] {
            let rt = runtime();
            fs::set_permissions(rt.path(), Permissions::from_mode(wrong)).unwrap();
            let err = create(&rt).unwrap_err();
            assert!(
                matches!(err, SessionError::RuntimeDirWritable { mode, .. } if mode == wrong),
                "{wrong:o}: {err}"
            );
            // Nothing was created in it.
            assert_eq!(fs::read_dir(rt.path()).unwrap().count(), 0);
        }
    }

    #[test]
    fn runtime_dir_readable_by_others_is_accepted() {
        // Only writability matters for the runtime dir itself.
        let rt = runtime();
        fs::set_permissions(rt.path(), Permissions::from_mode(0o755)).unwrap();
        assert!(create(&rt).is_ok());
    }

    #[test]
    fn drop_leaves_unremovable_content_behind_without_panicking() {
        // Documents the best-effort behaviour: no chmod-and-retry.
        if rustix::process::getuid().is_root() {
            return;
        }
        let rt = runtime();
        let session = create(&rt).unwrap();
        let root = session.root().to_path_buf();
        let locked = session.ephemeral().join("locked");
        fs::create_dir(&locked).unwrap();
        fs::write(session.ephemeral().join("other"), b"").unwrap();
        fs::set_permissions(&locked, Permissions::from_mode(0o000)).unwrap();

        drop(session);
        assert!(root.exists(), "content left behind");
        assert_eq!(mode(&locked), 0o000, "modes are not touched");

        // Restore so the temporary directory can be cleaned up.
        fs::set_permissions(&locked, Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn drop_removes_the_session_dir_only() {
        let rt = runtime();
        let session = create(&rt).unwrap();
        let root = session.root().to_path_buf();
        fs::write(session.ephemeral().join("scratch"), b"data").unwrap();
        drop(session);
        assert!(!root.exists());
        // The shared parent stays for other sessions.
        assert!(rt.path().join("stopit").is_dir());
    }

    #[test]
    fn drop_leaves_other_sessions_alone() {
        let rt = runtime();
        let a = create(&rt).unwrap();
        let b = create(&rt).unwrap();
        let b_root = b.root().to_path_buf();
        drop(a);
        assert!(b_root.is_dir());
    }

    #[test]
    fn drop_does_not_follow_symlinks_out_of_the_tree() {
        let rt = runtime();
        let outside = TempDir::new().unwrap();
        let target = outside.path().join("precious");
        fs::write(&target, b"keep me").unwrap();

        let session = create(&rt).unwrap();
        let root = session.root().to_path_buf();
        // A link to a directory and one to a file, at different depths.
        symlink(outside.path(), session.ephemeral().join("dir-link")).unwrap();
        symlink(&target, session.bin().join("file-link")).unwrap();
        drop(session);

        assert!(!root.exists());
        assert_eq!(fs::read(&target).unwrap(), b"keep me");
    }

    fn key(pattern: &str) -> EphemeralKey {
        EphemeralKey::new(&pattern.parse().unwrap())
    }

    #[test]
    fn ephemeral_dir_is_created_private_and_reused() {
        let rt = runtime();
        let session = create(&rt).unwrap();
        let tmp = session.ephemeral_dir(&key("/tmp")).unwrap();
        assert_eq!(tmp, session.ephemeral().join(key("/tmp").dir_name()));
        assert!(fs::symlink_metadata(&tmp).unwrap().is_dir());
        assert_eq!(mode(&tmp), 0o700);
        fs::write(tmp.join("kept"), b"data").unwrap();

        // The same key gets the same directory, content and all, even after
        // the sandbox changed its mode.
        fs::set_permissions(&tmp, Permissions::from_mode(0o777)).unwrap();
        assert_eq!(session.ephemeral_dir(&key("/tmp")).unwrap(), tmp);
        assert_eq!(fs::read(tmp.join("kept")).unwrap(), b"data");

        // Another key gets another directory.
        let home = session.ephemeral_dir(&key("~")).unwrap();
        assert_ne!(home, tmp);
        assert_eq!(fs::read_dir(&home).unwrap().count(), 0);
    }

    #[test]
    fn ephemeral_dir_that_is_not_a_real_directory_is_an_error() {
        let rt = runtime();
        let session = create(&rt).unwrap();
        let outside = TempDir::new().unwrap();
        let link = session.ephemeral().join(key("/tmp").dir_name());
        symlink(outside.path(), &link).unwrap();
        let err = session.ephemeral_dir(&key("/tmp")).unwrap_err();
        assert!(matches!(err, SessionError::NotDirectory { .. }), "{err}");

        let file = session.ephemeral().join(key("~").dir_name());
        fs::write(&file, b"").unwrap();
        let err = session.ephemeral_dir(&key("~")).unwrap_err();
        assert!(matches!(err, SessionError::NotDirectory { .. }), "{err}");
    }

    #[test]
    fn existing_session_dir_is_never_reused() {
        let rt = runtime();
        let first = SessionDir::create_with_id(rt.path(), "fixed".to_string()).unwrap();
        fs::write(first.root().join("marker"), b"").unwrap();

        let err = SessionDir::create_with_id(rt.path(), "fixed".to_string()).unwrap_err();
        match err {
            SessionError::Create { path, source } => {
                assert_eq!(path, first.root());
                assert_eq!(source.kind(), io::ErrorKind::AlreadyExists);
            }
            other => panic!("unexpected error: {other}"),
        }
        // The failed attempt neither touched nor removed the existing dir
        // (its guard is never built, so nothing is dropped).
        assert!(first.root().join("marker").exists());
        assert!(first.bin().is_dir());
    }

    #[test]
    fn error_messages_name_the_path() {
        let rt = runtime();
        let base = rt.path().join("stopit");
        fs::create_dir(&base).unwrap();
        fs::set_permissions(&base, Permissions::from_mode(0o755)).unwrap();
        let msg = create(&rt).unwrap_err().to_string();
        assert!(msg.contains(&format!("{base:?}")), "{msg}");
        assert!(msg.contains("0755"), "{msg}");
    }
}
