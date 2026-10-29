//! Resource limits (DESIGN.md §10). With `[limits]` set, stopit moves
//! itself into a transient systemd scope of its own before any provider
//! runs, by asking the user's systemd over D-Bus through `busctl`
//! (`StartTransientUnit` with its own pid). Its pid, descriptors, locks
//! and signal handlers stay as they are. What the session starts after
//! that, its sandboxes, the commands its brokers start, pasta and the
//! proxy bridges, inherits the scope, so the limits hold for the session
//! as a whole, and the user's other processes do not count against them.
//!
//! Once in the scope, stopit reads the cgroup's `pids.max`, `memory.max`
//! and `cpu.max` and refuses to go on unless each configured limit is
//! there.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use thiserror::Error;

use crate::config::Limits;

/// What the names of stopit's scopes start with.
const UNIT_PREFIX: &str = "stopit-";

/// Where the cgroup v2 hierarchy is mounted.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// How long systemd may take to move stopit into its scope.
const MOVE_TIMEOUT: Duration = Duration::from_secs(5);

/// Error applying `[limits]`.
#[derive(Debug, Error)]
pub enum LimitsError {
    /// No `busctl` in `PATH`.
    #[error(
        "[limits] needs busctl, from systemd, to give the session a scope of its own, and PATH has none"
    )]
    NoBusctl,
    /// `busctl` did not start, or systemd refused the scope.
    #[error("the user's systemd did not start the scope {unit}: {why}")]
    Refused {
        /// The scope's name.
        unit: String,
        /// What went wrong, escaped.
        why: String,
    },
    /// systemd took the scope but did not move stopit into it.
    #[error("systemd did not move stopit into the scope {unit}; it is in {got:?}")]
    NotInScope {
        /// The scope's name.
        unit: String,
        /// The cgroup stopit is in.
        got: String,
    },
    /// `/sys/fs/cgroup` is not a cgroup v2 hierarchy.
    #[error(
        "[limits] needs the cgroup v2 hierarchy at /sys/fs/cgroup, and it is not mounted there"
    )]
    NotCgroup2,
    /// A limit is missing from the scope.
    #[error(
        "the session's scope has {file} {got:?}, not the {want} of [limits]; the user's systemd \
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

/// Moves stopit into a new scope with `limits`, unless no limit is set,
/// and checks that the limits hold there.
pub fn enter_scope(limits: &Limits) -> Result<(), LimitsError> {
    if *limits == Limits::default() {
        return Ok(());
    }
    let busctl = std::env::var_os("PATH")
        .and_then(|path| crate::net::find_program_in("busctl", &path))
        .ok_or(LimitsError::NoBusctl)?;
    if !is_cgroup2(Path::new(CGROUP_ROOT)) {
        return Err(LimitsError::NotCgroup2);
    }
    let unit = unit_name();
    let refused = |why: String| LimitsError::Refused {
        unit: unit.clone(),
        why: crate::escape::escape_message(&why),
    };
    let out = Command::new(&busctl)
        .args(busctl_args(limits, &unit, std::process::id()))
        .stdin(Stdio::null())
        .output()
        .map_err(|e| refused(format!("cannot run {busctl:?}: {e}")))?;
    if !out.status.success() {
        return Err(refused(
            String::from_utf8_lossy(&out.stderr).trim().to_owned(),
        ));
    }
    // The job runs after the call returns.
    let deadline = Instant::now() + MOVE_TIMEOUT;
    let path = loop {
        let cgroup = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
        if let Some(path) = scope_path(&cgroup, &unit) {
            break path.to_owned();
        }
        if Instant::now() > deadline {
            return Err(LimitsError::NotInScope {
                unit,
                got: own_cgroup(&cgroup).unwrap_or("").to_owned(),
            });
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    check_applied(
        &Path::new(CGROUP_ROOT).join(path.trim_start_matches('/')),
        limits,
    )
}

/// Whether `path` is the root of a cgroup v2 hierarchy.
fn is_cgroup2(path: &Path) -> bool {
    rustix::fs::statfs(path).is_ok_and(|s| s.f_type as u64 == libc::CGROUP2_SUPER_MAGIC as u64)
}

/// A unit name for a new scope: the prefix, the pid and the time, which
/// are unlikely to clash. systemd refuses a name it already has.
fn unit_name() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("{UNIT_PREFIX}{}-{nanos}.scope", std::process::id())
}

/// `busctl`'s arguments to start the scope `unit` holding `pid`, with
/// `limits`. `CPUQuota=N%` is `CPUQuotaPerSecUSec` of N * 10000.
fn busctl_args(limits: &Limits, unit: &str, pid: u32) -> Vec<String> {
    let mut properties: Vec<[String; 3]> = vec![
        ["PIDs".into(), "au".into(), format!("1 {pid}")],
        [
            "CollectMode".into(),
            "s".into(),
            "inactive-or-failed".into(),
        ],
    ];
    if let Some(pids) = limits.pids {
        properties.push(["TasksMax".into(), "t".into(), pids.to_string()]);
    }
    if let Some(memory) = limits.memory {
        properties.push(["MemoryMax".into(), "t".into(), memory.bytes().to_string()]);
    }
    if let Some(cpu) = limits.cpu {
        properties.push([
            "CPUQuotaPerSecUSec".into(),
            "t".into(),
            (u64::from(cpu.percent()) * 10_000).to_string(),
        ]);
    }
    let mut args: Vec<String> = [
        "--user",
        "--timeout=10",
        "call",
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
        "StartTransientUnit",
        "ssa(sv)a(sa(sv))",
        unit,
        "fail",
    ]
    .map(String::from)
    .to_vec();
    args.push(properties.len().to_string());
    for [name, signature, value] in properties {
        args.push(name);
        args.push(signature);
        // `au` takes its count and items as separate arguments.
        args.extend(value.split(' ').map(String::from));
    }
    // No auxiliary units.
    args.push("0".into());
    args
}

/// The cgroup v2 path in `/proc/self/cgroup`'s contents, `cgroup`.
fn own_cgroup(cgroup: &str) -> Option<&str> {
    cgroup.lines().find_map(|line| line.strip_prefix("0::"))
}

/// The cgroup path in `cgroup` if it is the scope `unit`.
fn scope_path<'a>(cgroup: &'a str, unit: &str) -> Option<&'a str> {
    own_cgroup(cgroup).filter(|path| path.rsplit('/').next() == Some(unit))
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
        // Returns before looking for busctl or a cgroup.
        assert!(enter_scope(&Limits::default()).is_ok());
    }

    #[test]
    fn each_limit_becomes_a_property() {
        let args = busctl_args(
            &limits("pids = 64\nmemory = \"2G\"\ncpu = \"150%\""),
            "stopit-1-2.scope",
            42,
        );
        assert_eq!(
            args[..10],
            [
                "--user",
                "--timeout=10",
                "call",
                "org.freedesktop.systemd1",
                "/org/freedesktop/systemd1",
                "org.freedesktop.systemd1.Manager",
                "StartTransientUnit",
                "ssa(sv)a(sa(sv))",
                "stopit-1-2.scope",
                "fail",
            ]
        );
        assert_eq!(
            args[10..],
            [
                "5",
                "PIDs",
                "au",
                "1",
                "42",
                "CollectMode",
                "s",
                "inactive-or-failed",
                "TasksMax",
                "t",
                "64",
                "MemoryMax",
                "t",
                "2147483648",
                "CPUQuotaPerSecUSec",
                "t",
                "1500000",
                "0",
            ]
        );
        // Only what is set.
        let args = busctl_args(&limits("pids = 1"), "u", 7);
        assert_eq!(args[10], "3");
        assert_eq!(args.len(), 10 + 1 + 4 + 3 + 3 + 1);
        assert!(unit_name().starts_with(UNIT_PREFIX));
        assert!(unit_name().ends_with(".scope"));
    }

    #[test]
    fn the_scope_is_the_last_part_of_the_v2_path() {
        let unit = "stopit-1-2.scope";
        assert_eq!(
            scope_path("0::/user.slice/app.slice/stopit-1-2.scope\n", unit),
            Some("/user.slice/app.slice/stopit-1-2.scope")
        );
        // Hybrid hierarchies list v1 controllers too.
        assert_eq!(
            scope_path("12:pids:/user.slice\n0::/stopit-1-2.scope\n", unit),
            Some("/stopit-1-2.scope")
        );
        for other in [
            "0::/user.slice/tmux.scope\n",
            "0::/user.slice/stopit-1-2.scope/child\n",
            "0::/user.slice/xstopit-1-2.scope\n",
            "0::/\n",
            "12:pids:/stopit-1-2.scope\n",
            "",
        ] {
            assert_eq!(scope_path(other, unit), None, "{other:?}");
        }
    }

    #[test]
    fn the_hierarchy_must_be_cgroup2() {
        assert!(!is_cgroup2(Path::new("/proc")));
        assert!(!is_cgroup2(Path::new("/nonexistent")));
        if Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
            assert!(is_cgroup2(Path::new(CGROUP_ROOT)));
        }
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
