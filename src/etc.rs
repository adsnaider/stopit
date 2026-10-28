//! The synthesized `/etc` files (DESIGN.md §6.2 step 4): `/etc/passwd`,
//! `/etc/group`, `/etc/hosts` and `/etc/nsswitch.conf`.
//!
//! Their content comes from the spec (the sandbox `HOME`) and the ids the
//! sandbox user has, never from the host's `/etc`: the sandbox learns
//! nothing about host accounts, groups, host names or name services.
//!
//! * The sandbox user is named [`SANDBOX_USER`] whatever the host user is
//!   called: the host name is information the sandbox does not need. Its uid
//!   and gid are the caller's (bwrap's `--unshare-user` maps the caller's
//!   real ids to themselves), so files the sandbox creates in `rw` mounts
//!   belong to the user on the host as well. Its shell is [`SANDBOX_SHELL`],
//!   the conventional default (an empty field means the same), whether or
//!   not the sandbox has one.
//! * Inside the user namespace only that uid and gid are mapped; every other
//!   id, host root included, shows as the overflow id [`OVERFLOW_ID`]. So
//!   the files also name it (`nobody`, `nogroup`), which `ls -l` and `id`
//!   show for files owned by other host users and for supplementary groups.
//!   There is no `root` entry: host root is unmapped and shows as `nobody`,
//!   so uid 0 does not exist in the sandbox unless stopit runs as root.
//! * `hosts` maps `localhost`, and [`SANDBOX_HOSTNAME`] too when stopit sets
//!   it as the hostname of the new UTS namespace. With a shared UTS
//!   namespace the hostname is the host's, which `hosts` does not copy (that
//!   would leak it as well), so it names `localhost` only.
//! * `nsswitch.conf` uses the `files` service for every database and `dns`
//!   after it for `hosts`, both built into glibc (2.34+), so glibc never
//!   tries to load `systemd`, `sss`, `ldap` or `mymachines` modules, which
//!   the sandbox lacks. With `network = "proxy"` the proxy resolves names
//!   (§8) and DNS lookups fail fast; with `full` they work if a provider
//!   grants `/etc/resolv.conf`.

use std::fmt::Write as _;
use std::path::PathBuf;

use crate::manifest::{EtcFile, SandboxHome};

/// The name of the sandbox user and of its primary group.
pub const SANDBOX_USER: &str = "user";

/// The sandbox user's login shell.
pub const SANDBOX_SHELL: &str = "/bin/sh";

/// The kernel's default overflow uid and gid: what an id not mapped into
/// the user namespace shows as (`/proc/sys/kernel/overflowuid`).
pub const OVERFLOW_ID: u32 = 65534;

/// The user name of [`OVERFLOW_ID`].
pub const OVERFLOW_USER: &str = "nobody";

/// The group name of [`OVERFLOW_ID`].
pub const OVERFLOW_GROUP: &str = "nogroup";

/// The `HOME` and shell of [`OVERFLOW_USER`], as Debian has them: neither
/// exists.
const OVERFLOW_HOME: &str = "/nonexistent";
const OVERFLOW_SHELL: &str = "/bin/false";

/// The hostname of the sandbox's own UTS namespace (`--hostname`), which
/// `hosts` also names.
pub const SANDBOX_HOSTNAME: &str = "stopit";

/// The content of `/etc/nsswitch.conf`.
pub const NSSWITCH_CONF: &str = "\
passwd:    files
group:     files
shadow:    files
gshadow:   files
hosts:     files dns
networks:  files
protocols: files
services:  files
ethers:    files
rpc:       files
netgroup:  files
";

/// The uid and gid of the sandbox user, as seen inside the sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SandboxIds {
    /// The uid.
    pub uid: u32,
    /// The gid.
    pub gid: u32,
}

impl SandboxIds {
    /// The ids the sandbox user gets when this process runs bwrap: its real
    /// uid and gid, which `--unshare-user` maps to themselves (stopit passes
    /// no `--uid` or `--gid`).
    pub fn current() -> Self {
        SandboxIds {
            uid: rustix::process::getuid().as_raw(),
            gid: rustix::process::getgid().as_raw(),
        }
    }
}

/// The sandbox path of `file`: `/etc/<name>`.
pub fn sandbox_path(file: EtcFile) -> PathBuf {
    PathBuf::from("/etc").join(file.as_str())
}

/// The content of `file` for the sandbox user `ids` with the `HOME` `home`,
/// in a sandbox whose hostname is `hostname` (`None` if stopit does not set
/// one).
pub fn contents(
    file: EtcFile,
    ids: SandboxIds,
    home: &SandboxHome,
    hostname: Option<&str>,
) -> String {
    match file {
        EtcFile::Passwd => passwd(ids, home),
        EtcFile::Group => group(ids),
        EtcFile::Hosts => hosts(hostname),
        EtcFile::NsswitchConf => NSSWITCH_CONF.to_owned(),
    }
}

/// `/etc/hosts`: `localhost` for `127.0.0.1` and `::1`, which also name
/// `hostname` if there is one, so the sandbox's own name resolves.
///
/// `hostname` is interpolated as is: it is a constant of stopit's, not
/// configuration or the host's name.
pub fn hosts(hostname: Option<&str>) -> String {
    let names = match hostname {
        Some(name) => format!("localhost {name}"),
        None => "localhost".to_owned(),
    };
    format!("127.0.0.1\t{names}\n::1\t{names}\n")
}

/// `/etc/passwd`: the sandbox user, then `nobody` unless the user has its
/// uid.
///
/// `home` is interpolated as is: [`SandboxHome`] contains no `:` (the field
/// separator) and no control character (a newline would end the entry).
pub fn passwd(ids: SandboxIds, home: &SandboxHome) -> String {
    let mut out = String::new();
    let mut entry = |name: &str, uid: u32, gid: u32, home: &str, shell: &str| {
        writeln!(out, "{name}:x:{uid}:{gid}::{home}:{shell}").expect("writing to a String");
    };
    entry(SANDBOX_USER, ids.uid, ids.gid, home.as_str(), SANDBOX_SHELL);
    if ids.uid != OVERFLOW_ID {
        entry(
            OVERFLOW_USER,
            OVERFLOW_ID,
            OVERFLOW_ID,
            OVERFLOW_HOME,
            OVERFLOW_SHELL,
        );
    }
    out
}

/// `/etc/group`: the sandbox user's primary group, then `nogroup` unless
/// that group has its gid.
pub fn group(ids: SandboxIds) -> String {
    let mut out = format!("{SANDBOX_USER}:x:{}:\n", ids.gid);
    if ids.gid != OVERFLOW_ID {
        writeln!(out, "{OVERFLOW_GROUP}:x:{OVERFLOW_ID}:").expect("writing to a String");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const IDS: SandboxIds = SandboxIds {
        uid: 1000,
        gid: 100,
    };

    fn home(s: &str) -> SandboxHome {
        s.parse().unwrap()
    }

    #[test]
    fn passwd_golden() {
        assert_eq!(
            passwd(IDS, &home("/home/user")),
            "user:x:1000:100::/home/user:/bin/sh\n\
             nobody:x:65534:65534::/nonexistent:/bin/false\n"
        );
        // The configured `HOME`, with a space, verbatim.
        assert_eq!(
            passwd(IDS, &home("/srv/agent home")).lines().next(),
            Some("user:x:1000:100::/srv/agent home:/bin/sh")
        );
    }

    #[test]
    fn group_golden() {
        assert_eq!(group(IDS), "user:x:100:\nnogroup:x:65534:\n");
    }

    #[test]
    fn overflow_ids_are_not_listed_twice() {
        // A user whose own ids are the overflow ids keeps them, under its
        // own name.
        let ids = SandboxIds {
            uid: OVERFLOW_ID,
            gid: OVERFLOW_ID,
        };
        assert_eq!(
            passwd(ids, &home("/home/user")),
            "user:x:65534:65534::/home/user:/bin/sh\n"
        );
        assert_eq!(group(ids), "user:x:65534:\n");
        // Only the one that collides is left out.
        let ids = SandboxIds {
            uid: 1000,
            gid: OVERFLOW_ID,
        };
        assert_eq!(passwd(ids, &home("/h")).lines().count(), 2);
        assert_eq!(group(ids), "user:x:65534:\n");
    }

    #[test]
    fn root_is_not_listed() {
        let text = passwd(IDS, &home("/home/user")) + &group(IDS);
        assert!(!text.lines().any(|l| l.starts_with("root:")), "{text}");
        assert!(!text.contains(":0:"), "{text}");
    }

    #[test]
    fn every_entry_has_the_right_number_of_fields() {
        let ids = SandboxIds { uid: 0, gid: 0 };
        for line in passwd(ids, &home("/a b/c")).lines() {
            assert_eq!(line.split(':').count(), 7, "{line}");
        }
        for line in group(ids).lines() {
            assert_eq!(line.split(':').count(), 4, "{line}");
        }
    }

    #[test]
    fn hosts_golden() {
        assert_eq!(
            hosts(Some(SANDBOX_HOSTNAME)),
            "127.0.0.1\tlocalhost stopit\n::1\tlocalhost stopit\n"
        );
        assert_eq!(hosts(None), "127.0.0.1\tlocalhost\n::1\tlocalhost\n");
    }

    #[test]
    fn nsswitch_uses_only_builtin_services() {
        let mut databases = Vec::new();
        for line in NSSWITCH_CONF.lines() {
            let (db, services) = line.split_once(':').unwrap();
            let services: Vec<&str> = services.split_whitespace().collect();
            let expected: &[&str] = if db == "hosts" {
                &["files", "dns"]
            } else {
                &["files"]
            };
            assert_eq!(services, expected, "{line}");
            databases.push(db);
        }
        for db in ["passwd", "group", "shadow", "hosts", "services"] {
            assert!(databases.contains(&db), "{db}");
        }
    }

    #[test]
    fn contents_and_paths_of_every_file() {
        let h = home("/home/user");
        for hostname in [None, Some(SANDBOX_HOSTNAME)] {
            for file in EtcFile::ALL {
                let want = match file {
                    EtcFile::Passwd => passwd(IDS, &h),
                    EtcFile::Group => group(IDS),
                    EtcFile::Hosts => hosts(hostname),
                    EtcFile::NsswitchConf => NSSWITCH_CONF.to_owned(),
                };
                assert_eq!(contents(file, IDS, &h, hostname), want, "{file}");
                assert!(want.ends_with('\n'), "{file}");
            }
        }
        assert_eq!(
            EtcFile::ALL.map(sandbox_path),
            [
                "/etc/passwd",
                "/etc/group",
                "/etc/hosts",
                "/etc/nsswitch.conf"
            ]
            .map(PathBuf::from)
        );
    }

    #[test]
    fn current_ids_are_the_processes() {
        let ids = SandboxIds::current();
        assert_eq!(ids.uid, rustix::process::getuid().as_raw());
        assert_eq!(ids.gid, rustix::process::getgid().as_raw());
    }
}
