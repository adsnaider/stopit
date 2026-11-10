//! The trust store: the workspace configurations the user allowed (DESIGN.md §3).
//!
//! Running a sandbox requires `.stopit.toml` to exist in the workspace, and the
//! supervisor mounts every allowed `.stopit.toml` read-only inside every
//! sandbox. To prevent a sandbox from planting a `.stopit.toml` in a writable
//! subdirectory (or a freshly cloned repository from running an unreviewed
//! `.stopit.toml`), stopit only loads a `.stopit.toml` whose canonical path and
//! file allocation identity (`dev`, `ino`, and `statx` `btime` creation
//! timestamp) match an entry recorded by `stopit init` or `stopit allow`.
//!
//! Editing `.stopit.toml` in place on the host preserves its `(dev, ino, btime)`
//! identity and needs no `stopit allow`, while deleting and recreating the file
//! (even if the filesystem reuses the inode number) or replacing it via
//! `rename` changes `(ino, btime)` and requires `stopit allow` again.
//!
//! The store lives in stopit's data directory ([`crate::state::DataDirs::store`]),
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
//!   so concurrent updates do not lose each other's entries.
//!   Readers need no lock: the rename is atomic.
//!
//! The file is JSON:
//! `{"version": 2, "allowed": {"<hex-path>": {"dev": ..., "ino": ..., "btime": {"sec": ..., "nsec": ...}}}}`.
//! Paths may hold any bytes but NUL, and JSON strings are Unicode, so each
//! path is written as the lowercase hex of its bytes. Legacy `version = 1`
//! stores (keyed by SHA-256) migrate entries whose on-disk regular file still
//! matches its recorded SHA-256.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use rustix::fs::{AtFlags, FlockOperation, Mode, OFlags, StatxFlags, makedev, statx};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::session::{SessionError, check_private_dir, create_private_dir};
use crate::state::STATE_DIR_ENV;
use crate::supervisor::Ownership;

/// The name of the store file in the data directory.
pub const STORE_FILE: &str = "allowed.json";

/// The temporary file a new store is written to before it is renamed over
/// [`STORE_FILE`]. Only written under the directory's lock.
const TEMP_FILE: &str = "allowed.json.tmp";

/// Legacy content-hash store format version.
const LEGACY_FORMAT_VERSION: u32 = 1;

/// Current store file format version.
const FORMAT_VERSION: u32 = 2;

/// Mode of the store file.
const FILE_MODE: u32 = 0o600;

/// Maximum `.stopit.toml` size read during `v1` store migration.
const MAX_MIGRATE_CONFIG_BYTES: u64 = 16 * 1024 * 1024;

/// Error using the trust store.
#[derive(Debug, Error)]
pub enum TrustError {
    /// The data directory is not a private directory of the user's.
    #[error("stopit's data directory: {0}")]
    Dir(#[source] SessionError),

    /// The data directory, or a directory above it, cannot be created: in
    /// the default location, when the home directory in the password
    /// database is missing or not the user's to write (`/nonexistent`,
    /// `/var/empty`), so the message says how to put it elsewhere.
    #[error(
        "cannot create stopit's data directory {path:?}: {source}; if your home directory cannot \
         hold it, set {STATE_DIR_ENV} to the absolute path of a directory you own"
    )]
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

/// Nanosecond inode birth timestamp from `statx` (`stx_btime`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BirthTime {
    /// Seconds since the Unix epoch.
    pub sec: i64,
    /// Nanoseconds within the second (`0..1_000_000_000`).
    pub nsec: u32,
}

/// Allocation identity of an allowed `.stopit.toml` regular file: device,
/// inode, and (when reported by the filesystem) creation timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileIdentity {
    /// Device number (`makedev(stx_dev_major, stx_dev_minor)`).
    pub dev: u64,
    /// Inode number (`stx_ino`).
    pub ino: u64,
    /// Creation timestamp (`stx_btime`), if supported by the filesystem.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub btime: Option<BirthTime>,
}

impl FileIdentity {
    /// Queries `(dev, ino, btime)` on an open descriptor with `statx(EMPTY_PATH)`.
    pub fn of_fd(fd: BorrowedFd<'_>) -> io::Result<Self> {
        let stx = statx(
            fd,
            "",
            AtFlags::EMPTY_PATH,
            StatxFlags::BASIC_STATS | StatxFlags::BTIME,
        )?;
        let dev = makedev(stx.stx_dev_major, stx.stx_dev_minor);
        let btime = if stx.stx_mask & StatxFlags::BTIME.bits() != 0 {
            Some(BirthTime {
                sec: stx.stx_btime.tv_sec,
                nsec: stx.stx_btime.tv_nsec,
            })
        } else {
            None
        };
        Ok(FileIdentity {
            dev,
            ino: stx.stx_ino,
            btime,
        })
    }
}

/// The SHA-256 of `bytes`, as lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(Sha256::digest(bytes).as_slice())
}

/// Whether the store allows a configuration (see [`Allowed::decide`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Its path is allowed with this exact file allocation identity.
    Allowed,
    /// Its path was allowed, but the file on disk has a different `(dev, ino, btime)`
    /// (deleted and recreated, or replaced by an atomic rename).
    Replaced,
    /// Its path is not allowed.
    Unknown,
}

/// The allowed configurations: canonical `.stopit.toml` path to its
/// [`FileIdentity`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Allowed {
    entries: BTreeMap<PathBuf, FileIdentity>,
}

impl Allowed {
    /// Whether the configuration at the canonical `path` with `identity` is
    /// allowed.
    pub fn decide(&self, path: &Path, identity: FileIdentity) -> Decision {
        match self.entries.get(path) {
            None => Decision::Unknown,
            Some(&stored) if stored == identity => Decision::Allowed,
            Some(_) => Decision::Replaced,
        }
    }

    /// Whether `path` has an entry in the store.
    pub fn contains(&self, path: &Path) -> bool {
        self.entries.contains_key(path)
    }

    /// Records `path` as allowed with `identity`, replacing any earlier entry.
    pub fn allow(&mut self, path: PathBuf, identity: FileIdentity) {
        self.entries.insert(path, identity);
    }

    /// Removes `path`'s entry; returns whether there was one.
    pub fn revoke(&mut self, path: &Path) -> bool {
        self.entries.remove(path).is_some()
    }

    /// Every entry (`(path, identity)`), in path order.
    pub fn iter(&self) -> impl Iterator<Item = (&Path, FileIdentity)> {
        self.entries.iter().map(|(p, &id)| (p.as_path(), id))
    }

    /// Whether nothing is allowed.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Serializes the store in `version = 2` JSON format.
    fn to_json(&self) -> Vec<u8> {
        let file = StoreFileV2 {
            version: FORMAT_VERSION,
            allowed: self
                .entries
                .iter()
                .map(|(p, &id)| (hex(p.as_os_str().as_bytes()), id))
                .collect(),
        };
        let mut json = serde_json::to_vec_pretty(&file).expect("the store serializes");
        json.push(b'\n');
        json
    }

    /// Parses the store from `json` (`version = 2`, or migrating valid
    /// `version = 1` entries whose on-disk file still matches its SHA-256).
    fn from_json(json: &[u8]) -> Result<Self, String> {
        let header: StoreVersionProbe = serde_json::from_slice(json).map_err(|e| e.to_string())?;
        match header.version {
            FORMAT_VERSION => Self::from_v2_json(json),
            LEGACY_FORMAT_VERSION => Self::from_v1_json(json),
            other => Err(format!(
                "unknown version {other}, expected {FORMAT_VERSION}"
            )),
        }
    }

    fn from_v2_json(json: &[u8]) -> Result<Self, String> {
        let file: StoreFileV2 = serde_json::from_slice(json).map_err(|e| e.to_string())?;
        let mut entries = BTreeMap::new();
        for (raw_path, id) in file.allowed {
            let path = decode_store_path(&raw_path)?;
            if let Some(bt) = id.btime
                && bt.nsec >= 1_000_000_000
            {
                return Err(format!("invalid btime.nsec {} for {raw_path:?}", bt.nsec));
            }
            entries.insert(path, id);
        }
        Ok(Allowed { entries })
    }

    fn from_v1_json(json: &[u8]) -> Result<Self, String> {
        let file: StoreFileV1 = serde_json::from_slice(json).map_err(|e| e.to_string())?;
        let uid = rustix::process::getuid().as_raw();
        let mut entries = BTreeMap::new();
        for (raw_path, hash) in file.allowed {
            let path = decode_store_path(&raw_path)?;
            if hash.len() != 64 || unhex(&hash).is_none() {
                return Err(format!("invalid hash {hash:?}"));
            }
            if let Some(id) = migrate_v1_entry(&path, &hash, uid) {
                entries.insert(path, id);
            }
        }
        Ok(Allowed { entries })
    }
}

fn decode_store_path(raw_path: &str) -> Result<PathBuf, String> {
    let bytes = unhex(raw_path).ok_or_else(|| format!("invalid path {raw_path:?}"))?;
    if bytes.first() != Some(&b'/') || bytes.contains(&0) {
        return Err(format!("invalid path {raw_path:?}"));
    }
    Ok(PathBuf::from(OsString::from_vec(bytes)))
}

/// Checks whether a legacy `v1` entry's file still exists as a trusted regular
/// file with the exact `expected_hash`, returning its current [`FileIdentity`]
/// if so.
fn migrate_v1_entry(path: &Path, expected_hash: &str, uid: u32) -> Option<FileIdentity> {
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NOCTTY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .ok()?;
    let stat = rustix::fs::fstat(&fd).ok()?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_uid != uid
        || stat.st_mode & 0o022 != 0
    {
        return None;
    }
    let id = FileIdentity::of_fd(fd.as_fd()).ok()?;
    let mut bytes = Vec::new();
    File::from(fd)
        .take(MAX_MIGRATE_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_MIGRATE_CONFIG_BYTES {
        return None;
    }
    (sha256_hex(&bytes) == expected_hash).then_some(id)
}

#[derive(Deserialize)]
struct StoreVersionProbe {
    version: u32,
}

/// Current (`version = 2`) store file format.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreFileV2 {
    version: u32,
    allowed: BTreeMap<String, FileIdentity>,
}

/// Legacy (`version = 1`) store file format.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreFileV1 {
    #[allow(dead_code)]
    version: u32,
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
    if !s.len().is_multiple_of(2) {
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
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    use tempfile::TempDir;

    use super::*;

    fn tmp() -> (TempDir, PathBuf) {
        let dir = TempDir::new().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        (dir, root)
    }

    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().mode() & 0o7777
    }

    fn sample_id(ino: u64, nsec: u32) -> FileIdentity {
        FileIdentity {
            dev: 42,
            ino,
            btime: Some(BirthTime {
                sec: 1_700_000_000,
                nsec,
            }),
        }
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
    fn allow_revoke_and_decide_by_file_identity() {
        let mut allowed = Allowed::default();
        let path = Path::new("/ws/.stopit.toml");
        let id1 = sample_id(10, 100);
        let id1_recreated_same_ino = sample_id(10, 200);
        let id2 = sample_id(11, 100);

        assert_eq!(allowed.decide(path, id1), Decision::Unknown);
        assert!(!allowed.contains(path));
        allowed.allow(path.to_path_buf(), id1);
        assert!(allowed.contains(path));
        assert!(!allowed.contains(Path::new("/ws")));
        assert_eq!(allowed.decide(path, id1), Decision::Allowed);
        // Same inode number with a newer btime (inode reuse after delete+recreate) is rejected.
        assert_eq!(
            allowed.decide(path, id1_recreated_same_ino),
            Decision::Replaced
        );
        assert_eq!(allowed.decide(path, id2), Decision::Replaced);
        assert_eq!(
            allowed.decide(Path::new("/other/.stopit.toml"), id1),
            Decision::Unknown
        );

        allowed.allow(path.to_path_buf(), id2);
        assert_eq!(allowed.decide(path, id1), Decision::Replaced);
        assert_eq!(allowed.decide(path, id2), Decision::Allowed);
        assert_eq!(allowed.iter().count(), 1);
        assert!(allowed.revoke(path));
        assert!(!allowed.revoke(path));
        assert_eq!(allowed.decide(path, id2), Decision::Unknown);
        assert!(allowed.is_empty());
    }

    #[test]
    fn file_identity_persists_across_in_place_edits_and_changes_on_recreate() {
        let (_d, root) = tmp();
        let path = root.join(".stopit.toml");
        fs::write(&path, "default_profile = \"main\"\n").unwrap();
        let f1 = File::open(&path).unwrap();
        let id_initial = FileIdentity::of_fd(f1.as_fd()).unwrap();
        drop(f1);

        // In-place truncation and write keeps `(dev, ino, btime)` unchanged.
        {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&path)
                .unwrap();
            f.write_all(b"default_profile = \"agent\"\n").unwrap();
        }
        let f2 = File::open(&path).unwrap();
        let id_after_in_place = FileIdentity::of_fd(f2.as_fd()).unwrap();
        drop(f2);
        assert_eq!(id_initial, id_after_in_place);

        // Deleting and recreating (sleeping briefly so `btime` advances even if `ino` is reused)
        // yields a distinct `FileIdentity`.
        fs::remove_file(&path).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        fs::write(&path, "default_profile = \"main\"\n").unwrap();
        let f3 = File::open(&path).unwrap();
        let id_recreated = FileIdentity::of_fd(f3.as_fd()).unwrap();
        assert_ne!(id_initial, id_recreated);
    }

    #[test]
    fn json_round_trips_and_migrates_matching_v1_entries() {
        let mut allowed = Allowed::default();
        allowed.allow("/a/.stopit.toml".into(), sample_id(1, 10));
        let odd = PathBuf::from(OsString::from_vec(
            b"/\xff\xfe/x\n\"y/.stopit.toml".to_vec(),
        ));
        allowed.allow(
            odd.clone(),
            FileIdentity {
                dev: 7,
                ino: 8,
                btime: None,
            },
        );
        let json = allowed.to_json();
        let text = String::from_utf8(json.clone()).unwrap();
        assert!(text.contains(&hex(b"/a/.stopit.toml")), "{text}");
        assert!(text.contains("\"version\": 2"), "{text}");
        let back = Allowed::from_json(&json).unwrap();
        assert_eq!(back, allowed);

        // Legacy v1 migration: unmodified file migrates; modified file is dropped.
        let (_d, root) = tmp();
        let good = root.join("good.toml");
        let modified = root.join("modified.toml");
        fs::write(&good, "ok").unwrap();
        fs::set_permissions(&good, fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(&modified, "changed").unwrap();
        fs::set_permissions(&modified, fs::Permissions::from_mode(0o644)).unwrap();
        let v1_json = format!(
            "{{\"version\": 1, \"allowed\": {{\"{}\": \"{}\", \"{}\": \"{}\"}}}}",
            hex(good.as_os_str().as_bytes()),
            sha256_hex(b"ok"),
            hex(modified.as_os_str().as_bytes()),
            sha256_hex(b"original"),
        );
        let migrated = Allowed::from_json(v1_json.as_bytes()).unwrap();
        let good_id = FileIdentity::of_fd(File::open(&good).unwrap().as_fd()).unwrap();
        assert_eq!(migrated.decide(&good, good_id), Decision::Allowed);
        assert!(!migrated.contains(&modified));
    }

    #[test]
    fn invalid_json_is_refused_with_a_reason() {
        let p = hex(b"/a");
        for (json, reason) in [
            ("", "EOF"),
            ("[]", "expected struct StoreVersionProbe"),
            ("{\"version\": 2, \"allowed\": []}", "invalid type"),
            ("{\"version\": 99, \"allowed\": {}}", "unknown version 99"),
            ("{\"version\": 2}", "missing field"),
            (
                "{\"version\": 2, \"allowed\": {}, \"x\": 1}",
                "unknown field",
            ),
            (
                "{\"version\": 2, \"allowed\": {\"/a\": {\"dev\": 1, \"ino\": 2}}}",
                "invalid path",
            ),
            (
                &format!(
                    "{{\"version\": 2, \"allowed\": {{\"{}\": {{\"dev\": 1, \"ino\": 2}}}}}}",
                    hex(b"rel")
                ),
                "invalid path",
            ),
            (
                &format!(
                    "{{\"version\": 2, \"allowed\": {{\"{}\": {{\"dev\": 1, \"ino\": 2}}}}}}",
                    hex(b"/a\0b")
                ),
                "invalid path",
            ),
            (
                &format!(
                    "{{\"version\": 2, \"allowed\": {{\"{p}\": {{\"dev\": 1, \"ino\": 2, \"btime\": {{\"sec\": 1, \"nsec\": 1000000000}}}}}}}}"
                ),
                "invalid btime.nsec",
            ),
            (
                &format!("{{\"version\": 1, \"allowed\": {{\"{p}\": \"abc\"}}}}"),
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
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(store.read().unwrap(), Allowed::default());
        assert!(!store.file_path().exists());
        let id = sample_id(10, 20);
        store
            .update(|a| a.allow("/ws/.stopit.toml".into(), id))
            .unwrap();
        assert_eq!(mode(&store.file_path()), 0o600);
        assert_eq!(store.file_path(), dir.join(STORE_FILE));
        let again = TrustStore::open(&dir).unwrap().read().unwrap();
        assert_eq!(
            again.decide(Path::new("/ws/.stopit.toml"), id),
            Decision::Allowed
        );
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
        let id_a1 = sample_id(1, 0);
        let id_a2 = sample_id(2, 0);
        let id_b = sample_id(3, 0);
        store
            .update(|a| a.allow("/a/.stopit.toml".into(), id_a1))
            .unwrap();
        store
            .update(|a| a.allow("/b/.stopit.toml".into(), id_b))
            .unwrap();
        fs::write(root.join("stopit").join(TEMP_FILE), "junk").unwrap();
        store
            .update(|a| a.allow("/a/.stopit.toml".into(), id_a2))
            .unwrap();
        let allowed = store.read().unwrap();
        assert_eq!(
            allowed.decide(Path::new("/a/.stopit.toml"), id_a2),
            Decision::Allowed
        );
        assert_eq!(
            allowed.decide(Path::new("/b/.stopit.toml"), id_b),
            Decision::Allowed
        );
        assert!(!root.join("stopit").join(TEMP_FILE).exists());
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
            allowed.decide(Path::new("/b/.stopit.toml"), id_b),
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
                    let store = TrustStore::open(&dir).unwrap();
                    for j in 0..5 {
                        store
                            .update(|a| {
                                a.allow(format!("/{i}/{j}").into(), sample_id(i * 10 + j, 0))
                            })
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
        let e = store
            .update(|a| a.allow("/x".into(), sample_id(1, 0)))
            .unwrap_err();
        assert!(matches!(e, TrustError::Corrupt { .. }), "{e}");
        assert_eq!(fs::read_to_string(&path).unwrap(), "{not json");
        fs::write(&path, "").unwrap();
        assert!(matches!(store.read(), Err(TrustError::Corrupt { .. })));
    }

    #[test]
    fn a_store_file_others_can_access_or_a_link_is_refused() {
        let (_d, root) = tmp();
        let store = TrustStore::open(&root.join("stopit")).unwrap();
        store
            .update(|a| a.allow("/x".into(), sample_id(1, 0)))
            .unwrap();
        let path = store.file_path();
        for bad in [0o644, 0o620, 0o602, 0o640] {
            fs::set_permissions(&path, fs::Permissions::from_mode(bad)).unwrap();
            let e = store.read().unwrap_err();
            assert!(matches!(e, TrustError::Untrusted { .. }), "{bad:o}: {e}");
            assert!(e.to_string().contains(&format!("mode {bad:04o}")), "{e}");
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(store.read().is_ok());
        fs::rename(&path, root.join("real.json")).unwrap();
        symlink(root.join("real.json"), &path).unwrap();
        let e = store.read().unwrap_err();
        assert!(matches!(e, TrustError::Untrusted { .. }), "{e}");
        assert!(e.to_string().contains("symbolic link"), "{e}");
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
        let (_d, root) = tmp();
        fs::write(root.join("stopit"), "").unwrap();
        let e = TrustStore::open(&root.join("stopit")).unwrap_err();
        assert!(matches!(e, TrustError::Dir(_)), "{e}");
        let e = TrustStore::open(&root.join("stopit/sub/stopit")).unwrap_err();
        assert!(matches!(e, TrustError::CreateDir { .. }), "{e}");
        assert!(
            e.to_string().ends_with(
                "if your home directory cannot hold it, set STOPIT_STATE_DIR to the absolute \
                 path of a directory you own"
            ),
            "{e}"
        );
    }

    #[test]
    fn a_store_directory_of_someone_else_is_refused() {
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
