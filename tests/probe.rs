//! Proves `stopit-probe` and the test harness (`tests/common`) against real
//! bwrap, with hand-written bwrap arguments: what the probe reports must
//! match what those arguments are known to do.

mod common;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixListener;
use std::path::Path;

use tempfile::TempDir;

use common::*;

/// A host directory holding `file` (contents `host data`) and an empty
/// directory `sub`.
fn host_dir() -> TempDir {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("file"), "host data").unwrap();
    fs::create_dir(dir.path().join("sub")).unwrap();
    dir
}

fn host_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

// --- Visibility ---

#[test]
fn read_only_bind_is_readable_but_not_writable() {
    let host = host_dir();
    let results = Sandbox::new().ro_bind(host.path(), "/ro").run(&[
        read("/ro/file"),
        list("/ro"),
        write("/ro/file", "changed"),
        write("/ro/new", "new"),
        mkdir("/ro/dir"),
        remove("/ro/file"),
    ]);
    assert_eq!(contents(&results[0]), "host data");
    assert_eq!(
        ok(&results[1]),
        &Data::List(vec!["file".into(), "sub".into()])
    );
    for result in &results[2..] {
        assert_eq!(errno(result), "EROFS");
    }
    assert_eq!(
        fs::read_to_string(host.path().join("file")).unwrap(),
        "host data"
    );
    assert_eq!(host_names(host.path()), ["file", "sub"]);
}

#[test]
fn read_write_bind_writes_through_to_the_host() {
    let host = host_dir();
    let results = Sandbox::new().bind(host.path(), "/rw").run(&[
        write("/rw/new", "from the sandbox"),
        append("/rw/file", ", appended"),
        mkdir("/rw/dir"),
        rename("/rw/sub", "/rw/moved"),
    ]);
    for result in &results {
        assert_eq!(ok(result), &Data::Done);
    }
    let read = |name: &str| fs::read_to_string(host.path().join(name)).unwrap();
    assert_eq!(read("new"), "from the sandbox");
    assert_eq!(read("file"), "host data, appended");
    assert!(host.path().join("dir").is_dir());
    assert_eq!(host_names(host.path()), ["dir", "file", "moved", "new"]);
}

#[test]
fn stat_sees_the_host_entry_through_a_bind() {
    let host = host_dir();
    let meta = fs::metadata(host.path().join("file")).unwrap();
    let stat = stat_data(
        &Sandbox::new()
            .ro_bind(host.path(), "/ro")
            .run_one(stat("/ro/file")),
    );
    assert_eq!(stat.kind, FileKind::File);
    assert_eq!(stat.size, 9);
    assert_eq!(stat.ino, meta.ino());
}

// --- Isolation ---

#[test]
fn unbound_paths_do_not_exist() {
    let host = host_dir();
    let results = Sandbox::new().run(&[
        stat(host.path()),
        stat(host.path().join("file")),
        stat("/etc"),
        stat("/proc/self"),
        list("/"),
    ]);
    for result in &results[..4] {
        assert_eq!(errno(result), "ENOENT");
    }
    // The empty root holds only what bwrap made to mount the probe.
    assert_eq!(ok(&results[4]), &Data::List(vec!["run".into()]));
}

#[test]
fn tmpfs_is_writable_but_leaves_nothing_on_the_host() {
    let host = host_dir();
    // A tmpfs over a directory of a writable bind: without it, the writes
    // would land in the host's `sub`.
    let results = Sandbox::new()
        .bind(host.path(), "/rw")
        .tmpfs("/rw/sub")
        .run(&[
            write("/rw/sub/f", "scratch"),
            mkdir("/rw/sub/d"),
            read("/rw/sub/f"),
            list("/rw/sub"),
        ]);
    assert_eq!(ok(&results[0]), &Data::Done);
    assert_eq!(ok(&results[1]), &Data::Done);
    assert_eq!(contents(&results[2]), "scratch");
    assert_eq!(ok(&results[3]), &Data::List(vec!["d".into(), "f".into()]));
    assert_eq!(host_names(&host.path().join("sub")), Vec::<String>::new());
    assert_eq!(host_names(host.path()), ["file", "sub"]);
}

#[test]
fn mounts_are_visible_only_with_proc() {
    let host = host_dir();
    let sandbox = Sandbox::new().ro_bind(host.path(), "/ro");
    assert_eq!(errno(&sandbox.run_one(Op::Mounts)), "ENOENT");
    let mounts = mountinfo(&sandbox.proc().run_one(Op::Mounts));
    assert!(mount_at(&mounts, "/ro").has_option("ro"), "{mounts:#?}");
    assert_eq!(mount_at(&mounts, "/proc").fs_type, "proc");
    let probe = mount_at(&mounts, PROBE_DIR);
    assert!(probe.has_option("ro"), "{probe:?}");
}

#[test]
fn binds_are_nosuid_and_nodev() {
    let host = host_dir();
    let mounts = mountinfo(
        &Sandbox::new()
            .ro_bind(host.path(), "/ro")
            .bind(host.path(), "/rw")
            .tmpfs("/t")
            .proc()
            .run_one(Op::Mounts),
    );
    for at in ["/ro", "/rw"] {
        let mount = mount_at(&mounts, at);
        assert!(mount.has_option("nosuid"), "{mount:?}");
        assert!(mount.has_option("nodev"), "{mount:?}");
    }
    assert!(!mount_at(&mounts, "/rw").has_option("ro"));
    let tmpfs = mount_at(&mounts, "/t");
    assert_eq!(tmpfs.fs_type, "tmpfs");
    assert!(
        tmpfs.has_option("nosuid") && tmpfs.has_option("nodev"),
        "{tmpfs:?}"
    );
}

#[test]
fn parses_mountinfo_lines() {
    let text = "22 1 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc rw\n\
                40 22 8:1 /home/a\\040b /mnt/with\\040space ro,nosuid master:1 shared:2 - ext4 /dev/sda1 rw,errors=remount-ro\n";
    let mounts = parse_mountinfo(text);
    assert_eq!(
        mounts,
        [
            MountInfo {
                mount_point: "/proc".into(),
                options: vec![
                    "rw".into(),
                    "nosuid".into(),
                    "nodev".into(),
                    "noexec".into(),
                    "relatime".into()
                ],
                fs_type: "proc".into(),
                source: "proc".into(),
                super_options: vec!["rw".into()],
            },
            MountInfo {
                mount_point: "/mnt/with space".into(),
                options: vec!["ro".into(), "nosuid".into()],
                fs_type: "ext4".into(),
                source: "/dev/sda1".into(),
                super_options: vec!["rw".into(), "errors=remount-ro".into()],
            },
        ]
    );
    assert_eq!(mount_at(&mounts, "/mnt/with space").fs_type, "ext4");
}

// --- Persistence ---

#[test]
fn rw_bound_backing_dir_persists_across_sandboxes() {
    let host = host_dir();
    let sandbox = Sandbox::new().bind(host.path(), "/state");
    let first = sandbox.run(&[write("/state/note", "from run 1"), mkdir("/state/d")]);
    assert_eq!(first, [Ok(Data::Done), Ok(Data::Done)]);
    // A second, separate sandbox sees what the first left behind.
    let second = sandbox.run(&[read("/state/note"), list("/state")]);
    assert_eq!(contents(&second[0]), "from run 1");
    assert_eq!(
        ok(&second[1]),
        &Data::List(vec!["d".into(), "file".into(), "note".into(), "sub".into()])
    );
}

// --- Permissions, links and sockets ---

#[test]
fn chmod_fails_on_a_read_only_bind_and_works_on_a_writable_one() {
    let host = host_dir();
    let results = Sandbox::new()
        .ro_bind(host.path(), "/ro")
        .bind(host.path(), "/rw")
        .run(&[
            chmod("/ro/file", 0o600),
            chmod("/rw/file", 0o640),
            stat("/ro/file"),
        ]);
    assert_eq!(errno(&results[0]), "EROFS");
    assert_eq!(ok(&results[1]), &Data::Done);
    // The same inode, seen through the read-only bind.
    assert_eq!(stat_data(&results[2]).mode, 0o640);
    let meta = fs::metadata(host.path().join("file")).unwrap();
    assert_eq!(meta.mode() & 0o7777, 0o640);
}

#[test]
fn hard_links_work_within_a_writable_bind_only() {
    let host = host_dir();
    let results = Sandbox::new()
        .ro_bind(host.path(), "/ro")
        .bind(host.path(), "/rw")
        .tmpfs("/t")
        .run(&[
            link("/rw/file", "/rw/linked"),
            stat("/rw/linked"),
            link("/ro/file", "/ro/linked2"),
            // Across mounts, even of the same filesystem.
            link("/rw/file", "/t/linked"),
        ]);
    assert_eq!(ok(&results[0]), &Data::Done);
    assert_eq!(stat_data(&results[1]).nlink, 2);
    assert_eq!(errno(&results[2]), "EROFS");
    assert_eq!(errno(&results[3]), "EXDEV");
    let meta = |name: &str| fs::metadata(host.path().join(name)).unwrap();
    assert_eq!(meta("linked").ino(), meta("file").ino());
}

#[test]
fn unix_sockets_on_bound_paths_connect_despite_the_network_namespace() {
    // `--unshare-all` unshares the network namespace, which isolates
    // abstract sockets and IP but not sockets reached by path: a socket file
    // bound into the sandbox connects to its host listener. Recorded: this
    // holds on a read-only bind too (connecting needs write permission on
    // the socket, but EROFS applies only to files, directories and links).
    let host = host_dir();
    let _listener = UnixListener::bind(host.path().join("sock")).unwrap();
    let results = Sandbox::new()
        .bind(host.path(), "/rw")
        .ro_bind(host.path(), "/ro")
        .run(&[
            connect("/rw/sock"),
            connect("/ro/sock"),
            connect("/rw/missing"),
            connect("/rw/file"),
            stat("/rw/sock"),
        ]);
    assert_eq!(ok(&results[0]), &Data::Done);
    assert_eq!(ok(&results[1]), &Data::Done);
    assert_eq!(errno(&results[2]), "ENOENT");
    assert_eq!(errno(&results[3]), "ECONNREFUSED");
    assert_eq!(stat_data(&results[4]).kind, FileKind::Socket);
}

// --- Basic operations ---

#[test]
fn ids_are_the_callers_in_a_new_pid_namespace() {
    let result = Sandbox::new().run_one(Op::Ids);
    let Data::Ids(ids) = ok(&result) else {
        panic!("expected ids, got {result:?}")
    };
    // bwrap maps the caller's ids into the user namespace.
    assert_eq!(ids.uid, rustix::process::getuid().as_raw());
    assert_eq!(ids.gid, rustix::process::getgid().as_raw());
    // bwrap is the namespace's init and the probe its child.
    assert_eq!((ids.pid, ids.ppid), (2, 1), "{ids:?}");
}

#[test]
fn environment_holds_only_what_was_set_and_pwd() {
    // bwrap sets `PWD` to the directory it changed to, after applying
    // `--clearenv` and `--unsetenv`, so not even those remove it.
    let env = |pairs: &[(&str, &str)]| {
        Data::Env(
            pairs
                .iter()
                .map(|&(k, v)| (k.to_owned(), v.to_owned()))
                .collect::<BTreeMap<_, _>>(),
        )
    };
    let result = Sandbox::new().run_one(Op::Env);
    assert_eq!(ok(&result), &env(&[("PWD", "/")]));

    let result = Sandbox::new()
        .tmpfs("/work")
        .chdir("/work")
        .setenv("FOO", "bar")
        .setenv("EMPTY", "")
        .args(["--unsetenv", "PWD"])
        .run_one(Op::Env);
    assert_eq!(
        ok(&result),
        &env(&[("EMPTY", ""), ("FOO", "bar"), ("PWD", "/work")])
    );
}

#[test]
fn cwd_follows_chdir() {
    let result = Sandbox::new()
        .tmpfs("/work")
        .chdir("/work")
        .run_one(Op::Cwd);
    assert_eq!(ok(&result), &Data::Cwd("/work".into()));
}

#[test]
fn list_and_symlink_roundtrip_on_a_tmpfs() {
    let results = Sandbox::new().tmpfs("/t").run(&[
        write("/t/b", ""),
        mkdir("/t/a"),
        symlink("b", "/t/c"),
        symlink("/nowhere", "/t/dangling"),
        list("/t"),
        readlink("/t/c"),
        readlink("/t/dangling"),
        stat("/t/c"),
        stat_follow("/t/c"),
        stat_follow("/t/dangling"),
        remove("/t/c"),
        list("/t"),
    ]);
    for result in &results[..4] {
        assert_eq!(ok(result), &Data::Done);
    }
    assert_eq!(
        ok(&results[4]),
        &Data::List(vec!["a".into(), "b".into(), "c".into(), "dangling".into()])
    );
    assert_eq!(ok(&results[5]), &Data::Readlink("b".into()));
    assert_eq!(ok(&results[6]), &Data::Readlink("/nowhere".into()));
    assert_eq!(stat_data(&results[7]).kind, FileKind::Symlink);
    assert_eq!(stat_data(&results[8]).kind, FileKind::File);
    assert_eq!(errno(&results[9]), "ENOENT");
    assert_eq!(ok(&results[10]), &Data::Done);
    assert_eq!(
        ok(&results[11]),
        &Data::List(vec!["a".into(), "b".into(), "dangling".into()])
    );
}

#[test]
fn exec_runs_a_nested_probe() {
    // The probe runs a second copy of itself through the copied loader and
    // reports what the copy reported.
    let mut command = Sandbox::probe_command();
    let path = command.remove(0).into_string().unwrap();
    let args = command
        .into_iter()
        .map(|a| a.into_string().unwrap())
        .collect();
    let input = serde_json::to_string(&[Op::Cwd]).unwrap();
    let result = Sandbox::new()
        .tmpfs("/work")
        .chdir("/work")
        .run_one(Op::Exec {
            path,
            args,
            stdin: Some(input),
        });
    let Data::Exec(out) = ok(&result) else {
        panic!("expected exec output, got {result:?}")
    };
    assert_eq!(out.code, Some(0), "{out:?}");
    let nested: Vec<OpResult> = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(nested, [Ok(Data::Cwd("/work".into()))]);
}

// --- Failures are data ---

#[test]
fn a_failure_does_not_stop_later_operations() {
    let host = host_dir();
    let results = Sandbox::new()
        .ro_bind(host.path(), "/ro")
        .tmpfs("/t")
        .run(&[
            write("/t/before", "1"),
            write("/ro/x", "fails"),
            read("/missing"),
            Op::Exec {
                path: "/missing".into(),
                args: vec![],
                stdin: None,
            },
            write("/t/after", "2"),
            read("/t/after"),
            list("/t"),
        ]);
    assert_eq!(ok(&results[0]), &Data::Done);
    assert_eq!(errno(&results[1]), "EROFS");
    assert_eq!(errno(&results[2]), "ENOENT");
    assert_eq!(errno(&results[3]), "ENOENT");
    assert_eq!(ok(&results[4]), &Data::Done);
    assert_eq!(contents(&results[5]), "2");
    assert_eq!(
        ok(&results[6]),
        &Data::List(vec!["after".into(), "before".into()])
    );
}

#[test]
fn an_empty_operation_list_gives_an_empty_result_list() {
    assert_eq!(Sandbox::new().run(&[]), Vec::<OpResult>::new());
}

#[test]
fn bwrap_args_put_the_probe_mount_last() {
    let args = Sandbox::new().tmpfs("/run").bwrap_args();
    let n = args.len();
    assert_eq!(&args[..3], BASE_ARGS.map(OsString::from));
    assert_eq!(args[n - 3], "--ro-bind");
    assert_eq!(args[n - 2], provisioned_probe().dir.as_os_str());
    assert_eq!(args[n - 1], PROBE_DIR);
    // So a tmpfs over /run does not hide the probe.
    let result = Sandbox::new().tmpfs("/run").run_one(list("/run"));
    assert_eq!(ok(&result), &Data::List(vec!["stopit-probe".into()]));
}
