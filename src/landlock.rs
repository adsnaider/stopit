//! Landlock filesystem, TCP, and IPC restrictions for `stopit __init`.
//!
//! `__init` installs a Landlock ruleset before the seccomp filter runs. The
//! ruleset restricts filesystem access to the paths in the compiled
//! [`SandboxSpec`], blocks TCP bind and connect when `network = "none"`, and
//! isolates abstract Unix sockets and signals on kernels with ABI v6 or newer.

use std::ffi::CString;
use std::fmt;
use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::etc;
use crate::manifest::ShareableNamespace;
use crate::policy::PathMode;
use crate::spec::{NetworkSpec, SANDBOX_RUNTIME_DIR, SandboxSpec};

const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;
const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;

pub const ACCESS_FS_EXECUTE: u64 = 1 << 0;
pub const ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
pub const ACCESS_FS_READ_FILE: u64 = 1 << 2;
pub const ACCESS_FS_READ_DIR: u64 = 1 << 3;
pub const ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
pub const ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
pub const ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
pub const ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
pub const ACCESS_FS_MAKE_REG: u64 = 1 << 8;
pub const ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
pub const ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
pub const ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
pub const ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
pub const ACCESS_FS_REFER: u64 = 1 << 13;
pub const ACCESS_FS_TRUNCATE: u64 = 1 << 14;
pub const ACCESS_FS_IOCTL_DEV: u64 = 1 << 15;

pub const ACCESS_NET_BIND_TCP: u64 = 1 << 0;
pub const ACCESS_NET_CONNECT_TCP: u64 = 1 << 1;

pub const SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0;
pub const SCOPE_SIGNAL: u64 = 1 << 1;

const ACCESS_FS_ABI_V1: u64 = ACCESS_FS_EXECUTE
    | ACCESS_FS_WRITE_FILE
    | ACCESS_FS_READ_FILE
    | ACCESS_FS_READ_DIR
    | ACCESS_FS_REMOVE_DIR
    | ACCESS_FS_REMOVE_FILE
    | ACCESS_FS_MAKE_CHAR
    | ACCESS_FS_MAKE_DIR
    | ACCESS_FS_MAKE_REG
    | ACCESS_FS_MAKE_SOCK
    | ACCESS_FS_MAKE_FIFO
    | ACCESS_FS_MAKE_BLOCK
    | ACCESS_FS_MAKE_SYM;

/// Rights accepted by `landlock_add_rule` when `parent_fd` is not a directory.
pub const ACCESS_FS_FILE_MASK: u64 = ACCESS_FS_EXECUTE
    | ACCESS_FS_WRITE_FILE
    | ACCESS_FS_READ_FILE
    | ACCESS_FS_TRUNCATE
    | ACCESS_FS_IOCTL_DEV;

/// Read and execute rights for `ro`, `protected`, and `/run/stopit`.
pub const RO_ACCESS: u64 = ACCESS_FS_READ_FILE | ACCESS_FS_READ_DIR | ACCESS_FS_EXECUTE;

/// Read, write, execute, link, rename, and node creation rights for `rw` and
/// `ephemeral` mounts. `MAKE_CHAR` and `MAKE_BLOCK` stay off so the sandbox
/// cannot create device nodes.
pub const RW_ACCESS: u64 = ACCESS_FS_EXECUTE
    | ACCESS_FS_WRITE_FILE
    | ACCESS_FS_READ_FILE
    | ACCESS_FS_READ_DIR
    | ACCESS_FS_REMOVE_DIR
    | ACCESS_FS_REMOVE_FILE
    | ACCESS_FS_MAKE_DIR
    | ACCESS_FS_MAKE_REG
    | ACCESS_FS_MAKE_SOCK
    | ACCESS_FS_MAKE_FIFO
    | ACCESS_FS_MAKE_SYM
    | ACCESS_FS_REFER
    | ACCESS_FS_TRUNCATE;

const PROC_ACCESS: u64 =
    ACCESS_FS_READ_FILE | ACCESS_FS_READ_DIR | ACCESS_FS_WRITE_FILE | ACCESS_FS_TRUNCATE;

const DEV_ACCESS: u64 = ACCESS_FS_READ_FILE
    | ACCESS_FS_READ_DIR
    | ACCESS_FS_WRITE_FILE
    | ACCESS_FS_TRUNCATE
    | ACCESS_FS_IOCTL_DEV;

/// Kernel `struct landlock_ruleset_attr`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LandlockRulesetAttr {
    pub handled_access_fs: u64,
    pub handled_access_net: u64,
    pub scoped: u64,
}

const _: () = assert!(size_of::<LandlockRulesetAttr>() == 24);

/// Kernel `struct landlock_path_beneath_attr`, which `<linux/landlock.h>`
/// marks `__attribute__((packed))`.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct LandlockPathBeneathAttr {
    pub allowed_access: u64,
    pub parent_fd: i32,
}

const _: () = assert!(size_of::<LandlockPathBeneathAttr>() == 12);

/// Kernel `struct landlock_net_port_attr` for ABI v4 and newer.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LandlockNetPortAttr {
    pub allowed_access: u64,
    pub port: u64,
}

const _: () = assert!(size_of::<LandlockNetPortAttr>() == 16);

/// One Landlock `PathBeneath` rule for a sandbox path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LandlockPathRule {
    /// Target path inside the sandbox, serialized as lowercase hex bytes so
    /// non-UTF-8 Unix paths survive JSON encoding.
    #[serde(
        serialize_with = "serialize_hex_path",
        deserialize_with = "deserialize_hex_path"
    )]
    pub path: PathBuf,
    /// Unmasked filesystem access bitmask requested for `path`.
    pub access: u64,
}

/// Landlock policy passed from the supervisor to `stopit __init`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LandlockSpec {
    /// Path rules in deterministic order.
    pub rules: Vec<LandlockPathRule>,
    /// Handle `BIND_TCP | CONNECT_TCP` with no port rules on ABI v4 and newer.
    pub block_tcp: bool,
    /// Scope abstract Unix sockets on ABI v6 and newer.
    pub scope_abstract_unix: bool,
    /// Scope signals on ABI v6 and newer.
    pub scope_signal: bool,
}

impl LandlockSpec {
    /// Builds the Landlock policy for `spec`.
    pub fn from_sandbox_spec(spec: &SandboxSpec) -> Self {
        let mut rules = Vec::new();
        rules.push(LandlockPathRule {
            path: PathBuf::from("/"),
            access: ACCESS_FS_READ_DIR,
        });
        rules.push(LandlockPathRule {
            path: PathBuf::from(SANDBOX_RUNTIME_DIR),
            access: RO_ACCESS,
        });
        if spec.system.proc {
            rules.push(LandlockPathRule {
                path: PathBuf::from("/proc"),
                access: PROC_ACCESS,
            });
        }
        if spec.system.dev.is_some() {
            rules.push(LandlockPathRule {
                path: PathBuf::from("/dev"),
                access: DEV_ACCESS,
            });
        }
        for &file in &spec.system.etc {
            rules.push(LandlockPathRule {
                path: etc::sandbox_path(file),
                access: ACCESS_FS_READ_FILE,
            });
        }
        for mount in &spec.mounts {
            let access = match mount.mode {
                PathMode::Masked => continue,
                PathMode::Ro | PathMode::Protected => RO_ACCESS,
                PathMode::Rw | PathMode::Ephemeral => RW_ACCESS,
            };
            rules.push(LandlockPathRule {
                path: mount.sandbox.clone(),
                access,
            });
        }

        let net_shared = spec.namespaces.is_shared(ShareableNamespace::Net);
        let pid_shared = spec.namespaces.is_shared(ShareableNamespace::Pid);
        let block_tcp = spec.network == NetworkSpec::None && !net_shared;

        LandlockSpec {
            rules,
            block_tcp,
            scope_abstract_unix: !net_shared,
            scope_signal: !pid_shared,
        }
    }
}

/// Computes the ruleset attribute struct and the byte size to pass to
/// `landlock_create_ruleset` for kernel Landlock `abi`.
///
/// Older kernels reject trailing fields they do not know with `E2BIG`, so ABI
/// 1 through 3 pass 8 bytes, ABI 4 and 5 pass 16 bytes, and ABI 6 and newer
/// pass all 24 bytes.
pub fn ruleset_attr_for_abi(spec: &LandlockSpec, abi: i32) -> Option<(LandlockRulesetAttr, usize)> {
    if abi < 1 {
        return None;
    }
    let mut handled_access_fs = ACCESS_FS_ABI_V1;
    if abi >= 2 {
        handled_access_fs |= ACCESS_FS_REFER;
    }
    if abi >= 3 {
        handled_access_fs |= ACCESS_FS_TRUNCATE;
    }
    if abi >= 5 {
        handled_access_fs |= ACCESS_FS_IOCTL_DEV;
    }

    let handled_access_net = if abi >= 4 && spec.block_tcp {
        ACCESS_NET_BIND_TCP | ACCESS_NET_CONNECT_TCP
    } else {
        0
    };

    let mut scoped = 0;
    if abi >= 6 {
        if spec.scope_abstract_unix {
            scoped |= SCOPE_ABSTRACT_UNIX_SOCKET;
        }
        if spec.scope_signal {
            scoped |= SCOPE_SIGNAL;
        }
    }

    let size = if abi < 4 {
        8
    } else if abi < 6 {
        16
    } else {
        size_of::<LandlockRulesetAttr>()
    };

    Some((
        LandlockRulesetAttr {
            handled_access_fs,
            handled_access_net,
            scoped,
        },
        size,
    ))
}

/// Failure while installing the Landlock ruleset in `stopit __init`.
#[derive(Debug, Error)]
pub enum LandlockError {
    /// Querying the kernel Landlock ABI version failed.
    #[error("cannot query Landlock ABI version: {0}")]
    QueryAbi(#[source] io::Error),

    /// The kernel returned a non-positive ABI version.
    #[error("unsupported Landlock ABI version {0}")]
    UnsupportedAbi(i32),

    /// Creating the Landlock ruleset failed.
    #[error("cannot create Landlock ruleset: {0}")]
    CreateRuleset(#[source] io::Error),

    /// A rule path contains an interior NUL byte.
    #[error("Landlock rule path {0:?} contains a NUL byte")]
    NulPath(PathBuf),

    /// Opening a sandbox path with `O_PATH` failed.
    #[error("cannot open {path:?} for Landlock rule: {source}")]
    OpenPath {
        /// Sandbox path.
        path: PathBuf,
        /// Underlying OS error.
        #[source]
        source: io::Error,
    },

    /// `fstat` on an opened `O_PATH` descriptor failed.
    #[error("cannot stat {path:?} for Landlock rule: {source}")]
    StatPath {
        /// Sandbox path.
        path: PathBuf,
        /// Underlying OS error.
        #[source]
        source: io::Error,
    },

    /// `landlock_add_rule` rejected a `PathBeneath` rule.
    #[error("cannot add Landlock rule for {path:?}: {source}")]
    AddRule {
        /// Sandbox path.
        path: PathBuf,
        /// Underlying OS error.
        #[source]
        source: io::Error,
    },

    /// `landlock_restrict_self` failed.
    #[error("cannot enforce Landlock ruleset: {0}")]
    RestrictSelf(#[source] io::Error),
}

/// Queries the running kernel's Landlock ABI version.
pub fn query_abi_version() -> Result<i32, LandlockError> {
    // SAFETY: passing a null attribute pointer and size 0 with
    // `LANDLOCK_CREATE_RULESET_VERSION` queries the ABI version without
    // reading memory or mutating state.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<LandlockRulesetAttr>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if ret < 0 {
        return Err(LandlockError::QueryAbi(io::Error::last_os_error()));
    }
    i32::try_from(ret).map_err(|_| LandlockError::UnsupportedAbi(i32::MAX))
}

/// Creates, populates, and enforces `spec` on the calling thread.
///
/// The caller must set `PR_SET_NO_NEW_PRIVS` before calling `apply`.
pub fn apply(spec: &LandlockSpec) -> Result<(), LandlockError> {
    let abi = query_abi_version()?;
    let (attr, attr_size) =
        ruleset_attr_for_abi(spec, abi).ok_or(LandlockError::UnsupportedAbi(abi))?;

    // SAFETY: `attr` is initialized and `attr_size` is at most
    // `size_of::<LandlockRulesetAttr>()`.
    let raw_ruleset = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr as *const LandlockRulesetAttr,
            attr_size,
            0u32,
        )
    };
    if raw_ruleset < 0 {
        return Err(LandlockError::CreateRuleset(io::Error::last_os_error()));
    }
    // SAFETY: `landlock_create_ruleset` returned a new open file descriptor.
    let ruleset_fd = unsafe { OwnedFd::from_raw_fd(raw_ruleset as i32) };

    for rule in &spec.rules {
        add_path_rule(&ruleset_fd, &attr, rule)?;
    }

    // SAFETY: `ruleset_fd` is a valid Landlock ruleset descriptor and flags
    // are 0.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_restrict_self,
            ruleset_fd.as_raw_fd(),
            0u32,
        )
    };
    if ret != 0 {
        return Err(LandlockError::RestrictSelf(io::Error::last_os_error()));
    }
    Ok(())
}

fn add_path_rule(
    ruleset_fd: &OwnedFd,
    attr: &LandlockRulesetAttr,
    rule: &LandlockPathRule,
) -> Result<(), LandlockError> {
    let c_path = CString::new(rule.path.as_os_str().as_bytes())
        .map_err(|_| LandlockError::NulPath(rule.path.clone()))?;

    // SAFETY: `c_path` is NUL-terminated. `O_PATH | O_CLOEXEC` opens a path
    // reference without opening device nodes or blocking on FIFOs.
    let raw_fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if raw_fd < 0 {
        return Err(LandlockError::OpenPath {
            path: rule.path.clone(),
            source: io::Error::last_os_error(),
        });
    }
    // SAFETY: `open` returned a fresh file descriptor owned by this scope.
    let path_fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `path_fd` is open and `st` is writable.
    if unsafe { libc::fstat(path_fd.as_raw_fd(), &mut st) } != 0 {
        return Err(LandlockError::StatPath {
            path: rule.path.clone(),
            source: io::Error::last_os_error(),
        });
    }

    let mut allowed_access = rule.access;
    if (st.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        allowed_access &= ACCESS_FS_FILE_MASK;
    }
    allowed_access &= attr.handled_access_fs;
    if allowed_access == 0 {
        return Ok(());
    }

    let path_beneath = LandlockPathBeneathAttr {
        allowed_access,
        parent_fd: path_fd.as_raw_fd(),
    };
    // SAFETY: `ruleset_fd` and `path_fd` are open, and `path_beneath` has the
    // exact packed 12-byte kernel layout.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset_fd.as_raw_fd(),
            LANDLOCK_RULE_PATH_BENEATH,
            &path_beneath as *const LandlockPathBeneathAttr,
            0u32,
        )
    };
    if ret != 0 {
        return Err(LandlockError::AddRule {
            path: rule.path.clone(),
            source: io::Error::last_os_error(),
        });
    }
    Ok(())
}

impl fmt::Debug for LandlockPathBeneathAttr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let allowed_access = self.allowed_access;
        let parent_fd = self.parent_fd;
        f.debug_struct("LandlockPathBeneathAttr")
            .field("allowed_access", &allowed_access)
            .field("parent_fd", &parent_fd)
            .finish()
    }
}

pub(crate) fn serialize_hex_path<S: Serializer>(
    path: &Path,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let bytes = path.as_os_str().as_bytes();
    let mut hex = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        hex.push(char::from(DIGITS[usize::from(b >> 4)]));
        hex.push(char::from(DIGITS[usize::from(b & 0xf)]));
    }
    serializer.serialize_str(&hex)
}

pub(crate) fn deserialize_hex_path<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<PathBuf, D::Error> {
    let s = String::deserialize(deserializer)?;
    let bytes = unhex(&s).ok_or_else(|| D::Error::custom("path is not lowercase hex"))?;
    if bytes.is_empty() {
        return Err(D::Error::custom("sandbox path must not be empty"));
    }
    if bytes.contains(&0) {
        return Err(D::Error::custom("sandbox path must not contain a NUL byte"));
    }
    if bytes[0] != b'/' {
        return Err(D::Error::custom("sandbox path must be absolute"));
    }
    Ok(PathBuf::from(std::ffi::OsString::from_vec(bytes)))
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    bytes
        .chunks(2)
        .map(|pair| Some(digit(pair[0])? << 4 | digit(pair[1])?))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::*;
    use crate::expand::EntryKind;
    use crate::manifest::{DevMode, EtcFile};
    use crate::resolve::{EphemeralKey, MountSource, PlannedMount};

    fn host_mount(sandbox: &str, mode: PathMode) -> PlannedMount {
        PlannedMount {
            sandbox: PathBuf::from(sandbox),
            mode,
            source: MountSource::Host {
                path: PathBuf::from(sandbox),
                kind: EntryKind::Dir,
            },
            provider: "test".parse().unwrap(),
            glob_link: false,
        }
    }

    #[test]
    fn kernel_abi_struct_layouts_match_uapi() {
        assert_eq!(size_of::<LandlockRulesetAttr>(), 24);
        assert_eq!(size_of::<LandlockPathBeneathAttr>(), 12);
        assert_eq!(size_of::<LandlockNetPortAttr>(), 16);
    }

    #[test]
    fn ruleset_attr_masks_and_sizes_match_each_abi() {
        let spec = LandlockSpec {
            rules: Vec::new(),
            block_tcp: true,
            scope_abstract_unix: true,
            scope_signal: true,
        };

        assert_eq!(ruleset_attr_for_abi(&spec, 0), None);
        assert_eq!(ruleset_attr_for_abi(&spec, -1), None);

        let (v1, sz1) = ruleset_attr_for_abi(&spec, 1).unwrap();
        assert_eq!(sz1, 8);
        assert_eq!(v1.handled_access_fs, 0x1fff);
        assert_eq!(v1.handled_access_net, 0);
        assert_eq!(v1.scoped, 0);

        let (v2, sz2) = ruleset_attr_for_abi(&spec, 2).unwrap();
        assert_eq!(sz2, 8);
        assert_eq!(v2.handled_access_fs, 0x1fff | ACCESS_FS_REFER);
        assert_eq!(v2.handled_access_net, 0);
        assert_eq!(v2.scoped, 0);

        let (v3, sz3) = ruleset_attr_for_abi(&spec, 3).unwrap();
        assert_eq!(sz3, 8);
        assert_eq!(
            v3.handled_access_fs,
            0x1fff | ACCESS_FS_REFER | ACCESS_FS_TRUNCATE
        );
        assert_eq!(v3.handled_access_net, 0);
        assert_eq!(v3.scoped, 0);

        let (v4, sz4) = ruleset_attr_for_abi(&spec, 4).unwrap();
        assert_eq!(sz4, 16);
        assert_eq!(v4.handled_access_fs, v3.handled_access_fs);
        assert_eq!(
            v4.handled_access_net,
            ACCESS_NET_BIND_TCP | ACCESS_NET_CONNECT_TCP
        );
        assert_eq!(v4.scoped, 0);

        let (v5, sz5) = ruleset_attr_for_abi(&spec, 5).unwrap();
        assert_eq!(sz5, 16);
        assert_eq!(
            v5.handled_access_fs,
            v4.handled_access_fs | ACCESS_FS_IOCTL_DEV
        );
        assert_eq!(
            v5.handled_access_net,
            ACCESS_NET_BIND_TCP | ACCESS_NET_CONNECT_TCP
        );
        assert_eq!(v5.scoped, 0);

        for abi in [6, 7, 8] {
            let (v6, sz6) = ruleset_attr_for_abi(&spec, abi).unwrap();
            assert_eq!(sz6, 24);
            assert_eq!(v6.handled_access_fs, v5.handled_access_fs);
            assert_eq!(
                v6.handled_access_net,
                ACCESS_NET_BIND_TCP | ACCESS_NET_CONNECT_TCP
            );
            assert_eq!(v6.scoped, SCOPE_ABSTRACT_UNIX_SOCKET | SCOPE_SIGNAL);
        }

        // When TCP is allowed or scopes are disabled, ABI v6+ leaves them at 0.
        let open_spec = LandlockSpec {
            rules: Vec::new(),
            block_tcp: false,
            scope_abstract_unix: false,
            scope_signal: true,
        };
        let (open_v6, open_sz) = ruleset_attr_for_abi(&open_spec, 6).unwrap();
        assert_eq!(open_sz, 24);
        assert_eq!(open_v6.handled_access_net, 0);
        assert_eq!(open_v6.scoped, SCOPE_SIGNAL);
    }

    #[test]
    fn from_sandbox_spec_derives_expected_rules_and_flags() {
        let mut sb = SandboxSpec::default();
        sb.system.proc = true;
        sb.system.dev = Some(DevMode::Minimal);
        sb.system.etc.insert(EtcFile::Passwd);
        sb.mounts = vec![
            host_mount("/workspace", PathMode::Rw),
            host_mount("/workspace/.env", PathMode::Masked),
            host_mount("/workspace/.stopit.toml", PathMode::Protected),
            host_mount("/usr", PathMode::Ro),
            PlannedMount {
                sandbox: PathBuf::from("/tmp"),
                mode: PathMode::Ephemeral,
                source: MountSource::Ephemeral {
                    key: EphemeralKey::new(&"/tmp".parse().unwrap()),
                },
                provider: "test".parse().unwrap(),
                glob_link: false,
            },
        ];

        let ll = LandlockSpec::from_sandbox_spec(&sb);
        assert!(ll.block_tcp);
        assert!(ll.scope_abstract_unix);
        assert!(ll.scope_signal);
        assert_eq!(
            ll.rules,
            vec![
                LandlockPathRule {
                    path: PathBuf::from("/"),
                    access: ACCESS_FS_READ_DIR,
                },
                LandlockPathRule {
                    path: PathBuf::from("/run/stopit"),
                    access: RO_ACCESS,
                },
                LandlockPathRule {
                    path: PathBuf::from("/proc"),
                    access: PROC_ACCESS,
                },
                LandlockPathRule {
                    path: PathBuf::from("/dev"),
                    access: DEV_ACCESS,
                },
                LandlockPathRule {
                    path: PathBuf::from("/etc/passwd"),
                    access: ACCESS_FS_READ_FILE,
                },
                LandlockPathRule {
                    path: PathBuf::from("/workspace"),
                    access: RW_ACCESS,
                },
                LandlockPathRule {
                    path: PathBuf::from("/workspace/.stopit.toml"),
                    access: RO_ACCESS,
                },
                LandlockPathRule {
                    path: PathBuf::from("/usr"),
                    access: RO_ACCESS,
                },
                LandlockPathRule {
                    path: PathBuf::from("/tmp"),
                    access: RW_ACCESS,
                },
            ]
        );
        assert_eq!(RW_ACCESS & (ACCESS_FS_MAKE_CHAR | ACCESS_FS_MAKE_BLOCK), 0);
        assert_ne!(RW_ACCESS & ACCESS_FS_REFER, 0);
    }

    #[test]
    fn from_sandbox_spec_respects_network_and_shared_namespaces() {
        let mut sb = SandboxSpec {
            network: NetworkSpec::Loopback,
            ..SandboxSpec::default()
        };
        let ll = LandlockSpec::from_sandbox_spec(&sb);
        assert!(!ll.block_tcp);
        assert!(ll.scope_abstract_unix);
        assert!(ll.scope_signal);

        sb.network = NetworkSpec::None;
        sb.namespaces.shared.insert(ShareableNamespace::Net);
        let ll_net = LandlockSpec::from_sandbox_spec(&sb);
        assert!(!ll_net.block_tcp);
        assert!(!ll_net.scope_abstract_unix);
        assert!(ll_net.scope_signal);

        sb.namespaces.shared.insert(ShareableNamespace::Pid);
        let ll_both = LandlockSpec::from_sandbox_spec(&sb);
        assert!(!ll_both.scope_signal);
    }

    #[test]
    fn non_utf8_rule_paths_round_trip_through_json() {
        let odd = PathBuf::from(OsString::from_vec(b"/workspace/\xff\xfe".to_vec()));
        let spec = LandlockSpec {
            rules: vec![LandlockPathRule {
                path: odd.clone(),
                access: RO_ACCESS,
            }],
            block_tcp: true,
            scope_abstract_unix: true,
            scope_signal: false,
        };
        let json = serde_json::to_string(&spec).unwrap();
        let decoded: LandlockSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, spec);

        // Empty, relative, non-hex, and NUL-containing paths are rejected.
        for bad in ["\"\"", "\"2f00\"", "\"776f726b\"", "\"2f0\""] {
            let src = format!(
                r#"{{"rules":[{{"path":{bad},"access":1}}],"block_tcp":false,"scope_abstract_unix":false,"scope_signal":false}}"#
            );
            assert!(serde_json::from_str::<LandlockSpec>(&src).is_err(), "{bad}");
        }
    }
}
