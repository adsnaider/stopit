//! Resource limits (DESIGN.md §10). With `[limits]` set, stopit runs itself
//! again in a transient systemd scope of its own, through
//! `systemd-run --user --scope`, before any provider runs. Everything the
//! session starts, its sandboxes, pasta and the proxy bridges, stays in
//! that scope, so the limits hold for the whole session, and the user's
//! other processes do not count against them.
//!
//! `systemd-run --scope` runs the command in its own process, so stopit
//! keeps its pid, its process group and its terminal. Once in the scope,
//! stopit reads the cgroup's `pids.max`, `memory.max` and `cpu.max` and
//! refuses to go on unless each configured limit is there.

use std::ffi::OsString;
use std::io;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use thiserror::Error;

use crate::config::Limits;

/// What the names of stopit's scopes start with.
const UNIT_PREFIX: &str = "stopit-";

/// Set in the environment of the stopit that runs in a scope, to the
/// scope's name, so a scope that did not take is an error, not a loop.
const SCOPE_ENV: &str = "STOPIT_SCOPE";

/// Where the cgroup v2 hierarchy is mounted.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Error applying `[limits]`.
#[derive(Debug, Error)]
pub enum LimitsError {
    /// No `systemd-run` in `PATH`.
    #[error("[limits] needs systemd-run to give the session a scope of its own, and PATH has none")]
    NoSystemdRun,
    /// stopit's own executable cannot be named.
    #[error("cannot find stopit's own executable to run it again in a scope: {0}")]
    OwnExe(#[source] io::Error),
    /// `systemd-run` did not start.
    #[error("cannot run {path:?}: {source}")]
    Exec {
        /// The `systemd-run` run.
        path: PathBuf,
        /// What went wrong.
        #[source]
        source: io::Error,
    },
    /// stopit runs again, but not in the scope it asked for.
    #[error(
        "systemd-run did not put stopit in the scope {0}; is cgroup v2 mounted at /sys/fs/cgroup?"
    )]
    NotInScope(String),
    /// A limit is missing from the scope.
    #[error(
        "the session's scope has {file} {got:?}, not the {want} of [limits]; your user's systemd \
         may not have that controller"
    )]
    NotApplied {
        /// The cgroup file.
        file: &'static str,
        /// What it holds, or `missing`.
        got: String,
        /// What the limit asks for.
        want: String,
    },
}

/// Runs stopit again in a scope with `limits`, unless it already runs in
/// one or no limit is set. Returns only when stopit is in its scope with
/// the limits applied, or when no limit is set.
pub fn enter_scope(limits: &Limits) -> Result<(), LimitsError> {
    if *limits == Limits::default() {
        return Ok(());
    }
    let cgroup = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
    if let Some(scope) = std::env::var_os(SCOPE_ENV) {
        let scope = scope.to_string_lossy().into_owned();
        let Some(path) = own_cgroup(&cgroup).filter(|p| p.ends_with(&format!("/{scope}"))) else {
            return Err(LimitsError::NotInScope(scope));
        };
        return check_applied(
            &Path::new(CGROUP_ROOT).join(path.trim_start_matches('/')),
            limits,
        );
    }
    let systemd_run = std::env::var_os("PATH")
        .and_then(|path| crate::net::find_program_in("systemd-run", &path))
        .ok_or(LimitsError::NoSystemdRun)?;
    let exe = std::env::current_exe().map_err(LimitsError::OwnExe)?;
    let unit = unit_name();
    let source = Command::new(&systemd_run)
        .args(scope_args(limits, &unit))
        .arg("--")
        .arg(exe)
        .args(std::env::args_os().skip(1))
        .env(SCOPE_ENV, &unit)
        .exec();
    Err(LimitsError::Exec {
        path: systemd_run,
        source,
    })
}

/// A unit name for a new scope: the prefix, the pid and the time, which
/// no other scope of this user has.
fn unit_name() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("{UNIT_PREFIX}{}-{nanos}.scope", std::process::id())
}

/// `systemd-run`'s arguments for the scope `unit` with `limits`, up to the
/// command.
fn scope_args(limits: &Limits, unit: &str) -> Vec<OsString> {
    let mut args: Vec<OsString> = ["--user", "--scope", "--quiet", "--collect", "--unit", unit]
        .map(OsString::from)
        .to_vec();
    let mut property = |p: String| {
        args.push("--property".into());
        args.push(p.into());
    };
    if let Some(pids) = limits.pids {
        property(format!("TasksMax={pids}"));
    }
    if let Some(memory) = limits.memory {
        property(format!("MemoryMax={}", memory.bytes()));
    }
    if let Some(cpu) = limits.cpu {
        property(format!("CPUQuota={}%", cpu.percent()));
    }
    args
}

/// The cgroup v2 path in `/proc/self/cgroup`'s contents, `cgroup`.
fn own_cgroup(cgroup: &str) -> Option<&str> {
    cgroup.lines().find_map(|line| line.strip_prefix("0::"))
}

/// Checks that the cgroup at `dir` holds every limit in `limits`.
fn check_applied(dir: &Path, limits: &Limits) -> Result<(), LimitsError> {
    let read = |file: &str| {
        std::fs::read_to_string(dir.join(file))
            .map_or_else(|_| "missing".to_owned(), |s| s.trim().to_owned())
    };
    if let Some(pids) = limits.pids {
        let got = read("pids.max");
        if got != pids.to_string() {
            return Err(LimitsError::NotApplied {
                file: "pids.max",
                got,
                want: pids.to_string(),
            });
        }
    }
    if let Some(memory) = limits.memory {
        let got = read("memory.max");
        // The kernel rounds down to a whole page.
        let want = memory.bytes();
        let ok = got
            .parse::<u64>()
            .is_ok_and(|n| n <= want && want - n < 65536);
        if !ok {
            return Err(LimitsError::NotApplied {
                file: "memory.max",
                got,
                want: want.to_string(),
            });
        }
    }
    if let Some(cpu) = limits.cpu {
        let got = read("cpu.max");
        let ok = got.split_once(' ').is_some_and(|(quota, period)| {
            match (quota.parse::<u64>(), period.parse::<u64>()) {
                (Ok(quota), Ok(period)) if period > 0 => {
                    quota * 100 == u64::from(cpu.percent()) * period
                }
                _ => false,
            }
        });
        if !ok {
            return Err(LimitsError::NotApplied {
                file: "cpu.max",
                got,
                want: format!("{}%", cpu.percent()),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(text: &str) -> Limits {
        toml::from_str(text).unwrap()
    }

    #[test]
    fn no_limit_needs_no_scope() {
        assert!(enter_scope(&Limits::default()).is_ok());
    }

    #[test]
    fn each_limit_becomes_a_property() {
        let args = scope_args(
            &limits("pids = 64\nmemory = \"2G\"\ncpu = \"150%\""),
            "stopit-1-2.scope",
        );
        let args: Vec<&str> = args.iter().map(|a| a.to_str().unwrap()).collect();
        assert_eq!(
            args,
            [
                "--user",
                "--scope",
                "--quiet",
                "--collect",
                "--unit",
                "stopit-1-2.scope",
                "--property",
                "TasksMax=64",
                "--property",
                "MemoryMax=2147483648",
                "--property",
                "CPUQuota=150%",
            ]
        );
        // Only what is set.
        let args = scope_args(&limits("pids = 1"), "u");
        assert_eq!(args.len(), 8);
        assert!(unit_name().starts_with(UNIT_PREFIX));
        assert!(unit_name().ends_with(".scope"));
    }

    #[test]
    fn the_v2_line_names_the_cgroup() {
        assert_eq!(
            own_cgroup("0::/user.slice/stopit-1-2.scope\n"),
            Some("/user.slice/stopit-1-2.scope")
        );
        // Hybrid hierarchies list v1 controllers too.
        assert_eq!(
            own_cgroup("12:pids:/user.slice\n0::/a.scope\n"),
            Some("/a.scope")
        );
        assert_eq!(own_cgroup("12:pids:/user.slice\n"), None);
    }

    #[test]
    fn every_limit_must_be_in_the_cgroup() {
        let dir = tempfile::TempDir::new().unwrap();
        let set = |file: &str, value: &str| std::fs::write(dir.path().join(file), value).unwrap();
        let all = limits("pids = 64\nmemory = \"1G\"\ncpu = \"150%\"");
        // Nothing there yet.
        let e = check_applied(dir.path(), &all).unwrap_err();
        assert!(e.to_string().contains("pids.max \"missing\""), "{e}");
        set("pids.max", "64\n");
        set("memory.max", "1073741824\n");
        set("cpu.max", "150000 100000\n");
        check_applied(dir.path(), &all).unwrap();
        // A memory limit a page short is the same limit.
        set("memory.max", "1073737728\n");
        check_applied(dir.path(), &all).unwrap();
        for (file, value) in [
            ("pids.max", "max"),
            ("pids.max", "65"),
            ("memory.max", "max"),
            ("memory.max", "1073741825"),
            ("memory.max", "536870912"),
            ("cpu.max", "max 100000"),
            ("cpu.max", "100000 100000"),
            ("cpu.max", "150000 0"),
        ] {
            let saved = std::fs::read_to_string(dir.path().join(file)).unwrap();
            set(file, value);
            let e = check_applied(dir.path(), &all).unwrap_err();
            assert!(
                matches!(e, LimitsError::NotApplied { .. }),
                "{file} {value}"
            );
            set(file, &saved);
        }
        // Limits not set are not looked at.
        set("pids.max", "max");
        check_applied(dir.path(), &limits("cpu = \"150%\"")).unwrap();
    }
}
