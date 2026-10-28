//! The trust store: the configurations the user allowed (DESIGN.md §3,
//! Trust on first use).
//!
//! A `.stopit.toml` decides every grant and which script providers run on
//! the host, and a sandbox can write one where a later `stopit run` finds
//! it. So, as direnv does, stopit only uses a configuration the user allowed
//! with `stopit allow`, in the exact content they allowed: the store maps
//! each allowed configuration's canonical path to the SHA-256 of its bytes.
//!
//! It lives in stopit's data directory ([`crate::state::DataDirs::store`]),
//! as [`STORE_FILE`]:
//!
//! * The directory is created if missing (its parents with
//!   `create_dir_all`, itself with mode 0700), then must be a real
//!   directory (not a link) owned by the user with no group or other
//!   access, as the runtime directory must (§2.1). It is opened without
//!   following a link, and the descriptor is checked to be the directory
//!   checked; the store file is only reached through it.
//! * The store file is opened without following a link, and must be a
//!   regular file owned by the user with no group or other access (0600),
//!   checked with `fstat` on the descriptor read. A missing file is an empty
//!   store; a file that cannot be parsed is an error naming it, never an
//!   empty store.
//! * Writes go to a new temporary file in the directory (`O_EXCL`, 0600),
//!   which is synced and renamed over the store, so a reader sees either
//!   the old store or the new one. Read-modify-write updates
//!   ([`TrustStore::update`]) hold an exclusive `flock` on the directory,
//!   so concurrent `stopit allow` runs do not lose each other's entries.
//!   Readers need no lock: the rename is atomic.
//!
//! The file is JSON: `{"version": 1, "allowed": {"<path>": "<sha256>"}}`.
//! Paths may hold any bytes but NUL, and JSON strings are Unicode, so each
//! path is written as the lowercase hex of its bytes; hashes are lowercase
//! hex too. The file is not meant to be edited by hand (`stopit allowed`
//! lists it).

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use rustix::fs::{AtFlags, FlockOperation, Mode, OFlags};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::session::{SessionError, check_private_dir, create_private_dir};
use crate::supervisor::Ownership;

/// The name of the store file in the data directory.
pub const STORE_FILE: &str = "allowed.json";

/// The temporary file a new store is written to before it is renamed over
/// [`STORE_FILE`]. Only written under the directory's lock.
const TEMP_FILE: &str = "allowed.json.tmp";

/// The version of the store file's format.
const FORMAT_VERSION: u32 = 1;

/// Mode of the store file.
const FILE_MODE: u32 = 0o600;

/// Error using the trust store.
#[derive(Debug, Error)]
pub enum TrustError {
    /// The data directory is not a private directory of the user's.
    #[error("stopit's data directory: {0}")]
    Dir(#[source] SessionError),

    /// The data directory, or a directory above it, cannot be created.
    #[error("cannot create stopit's data directory {path:?}: {source}")]
    CreateDir {
        /// The directory.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },

    /// The data directory cannot be opened, or is not the directory
    /// checked.
    #[error("cannot open stopit's data directory {path:?}: {source}")]
    OpenDir {
        /// The directory.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },

    /// The store cannot be locked.
    #[error("cannot lock stopit's data directory {path:?}: {source}")]
    Lock {
        /// The directory.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },

    /// The store file cannot be read.
    #[error("cannot read the trust store {path:?}: {source}")]
    Read {
        /// The store file.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },

    /// The store file could be changed by someone else than the user, or
    /// read by others ([`check_store_file`]).
    #[error("refusing to read the trust store {path:?}: {reason}")]
    Untrusted {
        /// The store file.
        path: PathBuf,
        /// What is wrong with it.
        reason: String,
    },

    /// The store file is not a valid store.
    #[error(
        "the trust store {path:?} is corrupt ({reason}); move it away and allow your \
         configurations again"
    )]
    Corrupt {
        /// The store file.
        path: PathBuf,
        /// What is wrong with it.
        reason: String,
    },

    /// The store file cannot be written.
    #[error("cannot write the trust store {path:?}: {source}")]
    Write {
        /// The store file.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },
}

/// The SHA-256 of `bytes`, as lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(Sha256::digest(bytes).as_slice())
}

/// Whether the store allows a configuration (see [`Allowed::decide`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Its path is allowed with exactly this content.
    Allowed,
    /// Its path is allowed, with other content.
    Changed,
    /// Its path is not allowed.
    Unknown,
}

/// The allowed configurations: canonical path to the SHA-256 (lowercase
/// hex) of the content allowed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Allowed {
    entries: BTreeMap<PathBuf, String>,
}

impl Allowed {
    /// Whether the configuration at the canonical `path`, holding `bytes`,
    /// is allowed.
    pub fn decide(&self, path: &Path, bytes: &[u8]) -> Decision {
        match self.entries.get(path) {
            None => Decision::Unknown,
            Some(hash) if *hash == sha256_hex(bytes) => Decision::Allowed,
            Some(_) => Decision::Changed,
        }
    }

    /// Allows the configuration at the canonical `path` with the content
    /// `bytes`, replacing any earlier entry for `path`, and returns the
    /// hash recorded.
    pub fn allow(&mut self, path: PathBuf, bytes: &[u8]) -> String {
        let hash = sha256_hex(bytes);
        self.entries.insert(path, hash.clone());
        hash
    }

    /// Removes `path`'s entry; whether there was one.
    pub fn revoke(&mut self, path: &Path) -> bool {
        self.entries.remove(path).is_some()
    }

    /// Every entry, path and hash, in path order.
    pub fn iter(&self) -> impl Iterator<Item = (&Path, &str)> {
        self.entries.iter().map(|(p, h)| (p.as_path(), h.as_str()))
    }

    /// Whether nothing is allowed.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The store file's content.
    fn to_json(&self) -> Vec<u8> {
        let file = StoreFile {
            version: FORMAT_VERSION,
            allowed: self
                .entries
                .iter()
                .map(|(p, h)| (hex(p.as_os_str().as_bytes()), h.clone()))
                .collect(),
        };
        let mut json = serde_json::to_vec_pretty(&file).expect("the store serializes");
        json.push(b'\n');
        json
    }

    /// The store in the store file's content `json`, or why it is not one.
    fn from_json(json: &[u8]) -> Result<Self, String> {
        let file: StoreFile = serde_json::from_slice(json).map_err(|e| e.to_string())?;
        if file.version != FORMAT_VERSION {
            return Err(format!(
                "unknown version {}, expected {FORMAT_VERSION}",
                file.version
            ));
        }
        let mut entries = BTreeMap::new();
        for (path, hash) in file.allowed {
            let bytes = unhex(&path).ok_or_else(|| format!("invalid path {path:?}"))?;
            if bytes.first() != Some(&b'/') || bytes.contains(&0) {
                return Err(format!("invalid path {path:?}"));
            }
            if hash.len() != 64 || unhex(&hash).is_none() {
                return Err(format!("invalid hash {hash:?}"));
            }
            entries.insert(PathBuf::from(OsString::from_vec(bytes)), hash);
        }
        Ok(Allowed { entries })
    }
}

/// The store file's format.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreFile {
    version: u32,
    /// Hex of each path's bytes to the hex SHA-256 of its content.
    allowed: BTreeMap<String, String>,
}

/// `bytes` as lowercase hex.
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from(DIGITS[usize::from(b >> 4)]));
        s.push(char::from(DIGITS[usize::from(b & 0xf)]));
    }
    s
}

/// The bytes the lowercase hex `s` encodes, if it is that.
fn unhex(s: &str) -> Option<Vec<u8>> {
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let s = s.as_bytes();
    if s.len() % 2 != 0 {
        return None;
    }
    s.chunks(2)
        .map(|pair| Some(digit(pair[0])? << 4 | digit(pair[1])?))
        .collect()
}

/// Whether a store file `file` can be trusted by the user `uid`, and why
/// not: it must be a regular file owned by `uid` with no group or other
/// access. Anyone else able to write it could allow configurations for the
/// user; anyone able to read it learns the user's projects.
pub fn check_store_file(file: Ownership, uid: u32) -> Result<(), String> {
    if file.mode & libc::S_IFMT != libc::S_IFREG {
        return Err("it is not a regular file".into());
    }
    if file.uid != uid {
        return Err(format!(
            "it is owned by uid {}, not by you (uid {uid})",
            file.uid
        ));
    }
    if file.mode & 0o077 != 0 {
        return Err(format!(
            "it is accessible to its group or others (mode {:04o}); run `chmod 600` on it",
            file.mode & 0o7777
        ));
    }
    Ok(())
}

/// The trust store's directory, checked and open.
#[derive(Debug)]
pub struct TrustStore {
    /// The data directory.
    dir: PathBuf,
    /// It, open for reading (so that it can be locked and synced).
    fd: OwnedFd,
}

impl TrustStore {
    /// Opens the store in the data directory `dir` (resolved, see
    /// [`crate::state::DataDirs`]), creating it if missing: its parents with
    /// `create_dir_all`, itself with mode 0700. It must then be a real
    /// directory owned by the user with no group or other access.
    pub fn open(dir: &Path) -> Result<Self, TrustError> {
        let create = |path: &Path, source| TrustError::CreateDir {
            path: path.to_path_buf(),
            source,
        };
        if let Some(parent) = dir.parent() {
            fs::create_dir_all(parent).map_err(|e| create(parent, e))?;
        }
        match create_private_dir(dir) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(create(dir, e)),
        }
        let checked = check_private_dir(dir).map_err(TrustError::Dir)?;
        let open_error = |source: io::Error| TrustError::OpenDir {
            path: dir.to_path_buf(),
            source,
        };
        let fd = rustix::fs::open(
            dir,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| open_error(e.into()))?;
        // The directory opened is the one checked.
        let stat = rustix::fs::fstat(&fd).map_err(|e| open_error(e.into()))?;
        if (stat.st_dev, stat.st_ino) != (checked.dev(), checked.ino()) {
            return Err(open_error(io::Error::other(
                "it was replaced while it was checked",
            )));
        }
        Ok(TrustStore {
            dir: dir.to_path_buf(),
            fd,
        })
    }

    /// The store file's path, for messages.
    pub fn file_path(&self) -> PathBuf {
        self.dir.join(STORE_FILE)
    }

    /// The allowed configurations: none if there is no store file yet.
    pub fn read(&self) -> Result<Allowed, TrustError> {
        let path = self.file_path();
        let read_error = |source: io::Error| TrustError::Read {
            path: path.clone(),
            source,
        };
        // Non-blocking, so that a FIFO does not hang the open; it is refused
        // as not a regular file.
        let fd = match rustix::fs::openat(
            &self.fd,
            STORE_FILE,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NOCTTY | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(Allowed::default()),
            Err(Errno::LOOP) => {
                return Err(TrustError::Untrusted {
                    path,
                    reason: "it is a symbolic link".into(),
                });
            }
            Err(e) => return Err(read_error(e.into())),
        };
        let stat = rustix::fs::fstat(&fd).map_err(|e| read_error(e.into()))?;
        check_store_file(Ownership::of(&stat), rustix::process::getuid().as_raw()).map_err(
            |reason| TrustError::Untrusted {
                path: path.clone(),
                reason,
            },
        )?;
        let mut json = Vec::new();
        File::from(fd).read_to_end(&mut json).map_err(read_error)?;
        Allowed::from_json(&json).map_err(|reason| TrustError::Corrupt { path, reason })
    }

    /// Reads the store, applies `change` to it, and writes it back if
    /// `change` changed it, all under an exclusive lock on the directory,
    /// so that concurrent updates do not lose each other's entries.
    /// Returns what `change` returned.
    pub fn update<R>(&self, change: impl FnOnce(&mut Allowed) -> R) -> Result<R, TrustError> {
        rustix::fs::flock(&self.fd, FlockOperation::LockExclusive).map_err(|e| {
            TrustError::Lock {
                path: self.dir.clone(),
                source: e.into(),
            }
        })?;
        // The lock goes with the descriptor's last close; unlock explicitly
        // so that it does not outlive the update.
        let result = self.locked_update(change);
        let _ = rustix::fs::flock(&self.fd, FlockOperation::Unlock);
        result
    }

    fn locked_update<R>(&self, change: impl FnOnce(&mut Allowed) -> R) -> Result<R, TrustError> {
        let mut allowed = self.read()?;
        let before = allowed.clone();
        let result = change(&mut allowed);
        if allowed != before {
            self.write(&allowed)?;
        }
        Ok(result)
    }

    /// Replaces the store file with `allowed`, atomically: a new file
    /// (`O_EXCL`, 0600) is written, synced and renamed over it, and the
    /// directory synced. Only called under the lock, so [`TEMP_FILE`] is
    /// no one else's; one left by a crashed update is removed first.
    fn write(&self, allowed: &Allowed) -> Result<(), TrustError> {
        let write_error = |source: io::Error| TrustError::Write {
            path: self.file_path(),
            source,
        };
        match rustix::fs::unlinkat(&self.fd, TEMP_FILE, AtFlags::empty()) {
            Ok(()) | Err(Errno::NOENT) => {}
            Err(e) => return Err(write_error(e.into())),
        }
        let fd = rustix::fs::openat(
            &self.fd,
            TEMP_FILE,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(FILE_MODE),
        )
        .map_err(|e| write_error(e.into()))?;
        let written = (|| {
            // Whatever the umask.
            rustix::fs::fchmod(&fd, Mode::from_raw_mode(FILE_MODE))?;
            let mut file = File::from(fd);
            file.write_all(&allowed.to_json())?;
            file.sync_all()?;
            rustix::fs::renameat(&self.fd, TEMP_FILE, &self.fd, STORE_FILE)?;
            rustix::fs::fsync(&self.fd)?;
            Ok::<(), io::Error>(())
        })();
        if let Err(e) = written {
            let _ = rustix::fs::unlinkat(&self.fd, TEMP_FILE, AtFlags::empty());
            return Err(write_error(e));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};

    use tempfile::TempDir;

    use super::*;

    /// A canonical temporary directory.
    fn tmp() -> (TempDir, PathBuf) {
        let dir = TempDir::new().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        (dir, root)
    }

    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().mode() & 0o7777
    }

    #[test]
    fn hashing_is_sha256_in_lowercase_hex() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hex_round_trips_and_rejects_anything_else() {
        assert_eq!(hex(&[0x00, 0xab, 0xff]), "00abff");
        assert_eq!(unhex("00abff"), Some(vec![0x00, 0xab, 0xff]));
        assert_eq!(unhex(""), Some(vec![]));
        for bad in ["0", "0g", "AB", "zz", "é0"] {
            assert_eq!(unhex(bad), None, "{bad}");
        }
    }

    #[test]
    fn allow_revoke_and_decide() {
        let mut allowed = Allowed::default();
        let path = Path::new("/ws/.stopit.toml");
        assert_eq!(allowed.decide(path, b"x"), Decision::Unknown);
        let hash = allowed.allow(path.to_path_buf(), b"x");
        assert_eq!(hash, sha256_hex(b"x"));
        assert_eq!(allowed.decide(path, b"x"), Decision::Allowed);
        assert_eq!(allowed.decide(path, b"x\n"), Decision::Changed);
        // Another path with the same content is not allowed.
        assert_eq!(
            allowed.decide(Path::new("/other/.stopit.toml"), b"x"),
            Decision::Unknown
        );
        // Allowing again replaces the entry.
        allowed.allow(path.to_path_buf(), b"y");
        assert_eq!(allowed.decide(path, b"x"), Decision::Changed);
        assert_eq!(allowed.decide(path, b"y"), Decision::Allowed);
        assert_eq!(allowed.iter().count(), 1);
        assert!(allowed.revoke(path));
        assert!(!allowed.revoke(path));
        assert_eq!(allowed.decide(path, b"y"), Decision::Unknown);
        assert!(allowed.is_empty());
    }

    #[test]
    fn the_json_round_trips_with_any_path_bytes() {
        let mut allowed = Allowed::default();
        allowed.allow("/a/.stopit.toml".into(), b"a");
        let odd = PathBuf::from(OsString::from_vec(
            b"/\xff\xfe/x\n\"y/.stopit.toml".to_vec(),
        ));
        allowed.allow(odd.clone(), b"b");
        let json = allowed.to_json();
        let text = String::from_utf8(json.clone()).unwrap();
        assert!(text.contains(&hex(b"/a/.stopit.toml")), "{text}");
        assert!(text.contains("\"version\": 1"), "{text}");
        let back = Allowed::from_json(&json).unwrap();
        assert_eq!(back, allowed);
        assert_eq!(back.decide(&odd, b"b"), Decision::Allowed);
    }

    #[test]
    fn invalid_json_is_refused_with_a_reason() {
        let h = sha256_hex(b"");
        let p = hex(b"/a");
        for (json, reason) in [
            ("", "EOF"),
            ("[]", "expected struct StoreFile"),
            ("{\"version\": 1, \"allowed\": []}", "invalid type"),
            ("{\"version\": 2, \"allowed\": {}}", "unknown version 2"),
            ("{\"version\": 1}", "missing field"),
            (
                "{\"version\": 1, \"allowed\": {}, \"x\": 1}",
                "unknown field",
            ),
            (
                &format!("{{\"version\": 1, \"allowed\": {{\"/a\": \"{h}\"}}}}"),
                "invalid path",
            ),
            (
                &format!(
                    "{{\"version\": 1, \"allowed\": {{\"{}\": \"{h}\"}}}}",
                    hex(b"rel")
                ),
                "invalid path",
            ),
            (
                &format!(
                    "{{\"version\": 1, \"allowed\": {{\"{}\": \"{h}\"}}}}",
                    hex(b"/a\0b")
                ),
                "invalid path",
            ),
            (
                &format!("{{\"version\": 1, \"allowed\": {{\"{p}\": \"abc\"}}}}"),
                "invalid hash",
            ),
            (
                &format!(
                    "{{\"version\": 1, \"allowed\": {{\"{p}\": \"{}\"}}}}",
                    h.to_uppercase()
                ),
                "invalid hash",
            ),
        ] {
            let e = Allowed::from_json(json.as_bytes()).unwrap_err();
            assert!(e.contains(reason), "{json}: {e}");
        }
    }

    #[test]
    fn the_store_round_trips_and_is_private() {
        let (_d, root) = tmp();
        let dir = root.join("a/b/stopit");
        let store = TrustStore::open(&dir).unwrap();
        // Created with its parents, private.
        assert_eq!(mode(&dir), 0o700);
        // No file yet: an empty store, and nothing is written for it.
        assert_eq!(store.read().unwrap(), Allowed::default());
        assert!(!store.file_path().exists());
        let hash = store
            .update(|a| a.allow("/ws/.stopit.toml".into(), b"x"))
            .unwrap();
        assert_eq!(hash, sha256_hex(b"x"));
        assert_eq!(mode(&store.file_path()), 0o600);
        assert_eq!(store.file_path(), dir.join(STORE_FILE));
        // Read again, from a store opened anew.
        let again = TrustStore::open(&dir).unwrap().read().unwrap();
        assert_eq!(
            again.decide(Path::new("/ws/.stopit.toml"), b"x"),
            Decision::Allowed
        );
        // No temporary file is left.
        let names: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, [STORE_FILE]);
    }

    #[test]
    fn an_update_keeps_the_other_entries() {
        let (_d, root) = tmp();
        let store = TrustStore::open(&root.join("stopit")).unwrap();
        store
            .update(|a| a.allow("/a/.stopit.toml".into(), b"a"))
            .unwrap();
        store
            .update(|a| a.allow("/b/.stopit.toml".into(), b"b"))
            .unwrap();
        // A stale temporary file of a crashed update is replaced.
        fs::write(root.join("stopit").join(TEMP_FILE), "junk").unwrap();
        store
            .update(|a| a.allow("/a/.stopit.toml".into(), b"a2"))
            .unwrap();
        let allowed = store.read().unwrap();
        assert_eq!(
            allowed.decide(Path::new("/a/.stopit.toml"), b"a2"),
            Decision::Allowed
        );
        assert_eq!(
            allowed.decide(Path::new("/b/.stopit.toml"), b"b"),
            Decision::Allowed
        );
        assert!(!root.join("stopit").join(TEMP_FILE).exists());
        // Revoking one keeps the other; revoking nothing writes nothing.
        assert!(
            store
                .update(|a| a.revoke(Path::new("/a/.stopit.toml")))
                .unwrap()
        );
        let before = fs::metadata(store.file_path()).unwrap().ino();
        assert!(
            !store
                .update(|a| a.revoke(Path::new("/a/.stopit.toml")))
                .unwrap()
        );
        assert_eq!(fs::metadata(store.file_path()).unwrap().ino(), before);
        let allowed = store.read().unwrap();
        assert_eq!(allowed.iter().count(), 1);
        assert_eq!(
            allowed.decide(Path::new("/b/.stopit.toml"), b"b"),
            Decision::Allowed
        );
    }

    #[test]
    fn concurrent_updates_lose_nothing() {
        let (_d, root) = tmp();
        let dir = root.join("stopit");
        TrustStore::open(&dir).unwrap();
        let threads: Vec<_> = (0..8)
            .map(|i| {
                let dir = dir.clone();
                std::thread::spawn(move || {
                    // Each its own descriptor, as separate processes have.
                    let store = TrustStore::open(&dir).unwrap();
                    for j in 0..5 {
                        store
                            .update(|a| a.allow(format!("/{i}/{j}").into(), b"x"))
                            .unwrap();
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(
            TrustStore::open(&dir)
                .unwrap()
                .read()
                .unwrap()
                .iter()
                .count(),
            40
        );
    }

    #[test]
    fn a_corrupt_store_is_an_error_naming_it() {
        let (_d, root) = tmp();
        let store = TrustStore::open(&root.join("stopit")).unwrap();
        let path = store.file_path();
        fs::write(&path, "{not json").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let e = store.read().unwrap_err();
        assert!(matches!(e, TrustError::Corrupt { .. }), "{e}");
        assert!(e.to_string().contains(&format!("{path:?}")), "{e}");
        // An update does not overwrite it either.
        let e = store.update(|a| a.allow("/x".into(), b"")).unwrap_err();
        assert!(matches!(e, TrustError::Corrupt { .. }), "{e}");
        assert_eq!(fs::read_to_string(&path).unwrap(), "{not json");
        // Nor is an empty file an empty store.
        fs::write(&path, "").unwrap();
        assert!(matches!(store.read(), Err(TrustError::Corrupt { .. })));
    }

    #[test]
    fn a_store_file_others_can_access_or_a_link_is_refused() {
        let (_d, root) = tmp();
        let store = TrustStore::open(&root.join("stopit")).unwrap();
        store.update(|a| a.allow("/x".into(), b"")).unwrap();
        let path = store.file_path();
        for bad in [0o644, 0o620, 0o602, 0o640] {
            fs::set_permissions(&path, fs::Permissions::from_mode(bad)).unwrap();
            let e = store.read().unwrap_err();
            assert!(matches!(e, TrustError::Untrusted { .. }), "{bad:o}: {e}");
            assert!(e.to_string().contains(&format!("mode {bad:04o}")), "{e}");
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(store.read().is_ok());
        // A link, even to a private file of the user's.
        fs::rename(&path, root.join("real.json")).unwrap();
        symlink(root.join("real.json"), &path).unwrap();
        let e = store.read().unwrap_err();
        assert!(matches!(e, TrustError::Untrusted { .. }), "{e}");
        assert!(e.to_string().contains("symbolic link"), "{e}");
        // A directory.
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        let e = store.read().unwrap_err();
        assert!(e.to_string().contains("not a regular file"), "{e}");
    }

    #[test]
    fn store_file_trust_checks_owner_type_and_mode() {
        const ME: u32 = 1000;
        let file = |uid, mode| Ownership {
            uid,
            mode: libc::S_IFREG | mode,
        };
        assert_eq!(check_store_file(file(ME, 0o600), ME), Ok(()));
        assert_eq!(check_store_file(file(ME, 0o400), ME), Ok(()));
        let e = check_store_file(file(1001, 0o600), ME).unwrap_err();
        assert!(
            e.contains("owned by uid 1001, not by you (uid 1000)"),
            "{e}"
        );
        // Root's too.
        assert!(check_store_file(file(0, 0o600), ME).is_err());
        let e = check_store_file(file(ME, 0o604), ME).unwrap_err();
        assert!(e.contains("mode 0604"), "{e}");
        let fifo = Ownership {
            uid: ME,
            mode: libc::S_IFIFO | 0o600,
        };
        let e = check_store_file(fifo, ME).unwrap_err();
        assert!(e.contains("not a regular file"), "{e}");
    }

    #[test]
    fn a_store_directory_that_is_not_private_is_refused() {
        // A link, even to a private directory of the user's.
        let (_d, root) = tmp();
        fs::create_dir(root.join("real")).unwrap();
        fs::set_permissions(root.join("real"), fs::Permissions::from_mode(0o700)).unwrap();
        symlink(root.join("real"), root.join("stopit")).unwrap();
        let e = TrustStore::open(&root.join("stopit")).unwrap_err();
        assert!(
            matches!(e, TrustError::Dir(SessionError::NotDirectory { .. })),
            "{e}"
        );
        assert_eq!(fs::read_dir(root.join("real")).unwrap().count(), 0);
        // Open to others.
        fs::remove_file(root.join("stopit")).unwrap();
        fs::create_dir(root.join("stopit")).unwrap();
        fs::set_permissions(root.join("stopit"), fs::Permissions::from_mode(0o750)).unwrap();
        let e = TrustStore::open(&root.join("stopit")).unwrap_err();
        assert!(
            matches!(
                e,
                TrustError::Dir(SessionError::Insecure { mode: 0o750, .. })
            ),
            "{e}"
        );
        assert!(e.to_string().contains("0750"), "{e}");
        // A file.
        let (_d, root) = tmp();
        fs::write(root.join("stopit"), "").unwrap();
        let e = TrustStore::open(&root.join("stopit")).unwrap_err();
        assert!(matches!(e, TrustError::Dir(_)), "{e}");
        // A parent that cannot be created.
        let e = TrustStore::open(&root.join("stopit/sub/stopit")).unwrap_err();
        assert!(matches!(e, TrustError::CreateDir { .. }), "{e}");
    }

    #[test]
    fn a_store_directory_of_someone_else_is_refused() {
        // `/proc` is root's; skip when the tests run as root.
        if rustix::process::getuid().is_root() {
            return;
        }
        let e = TrustStore::open(Path::new("/proc")).unwrap_err();
        assert!(
            matches!(e, TrustError::Dir(SessionError::WrongOwner { .. })),
            "{e}"
        );
    }
}
