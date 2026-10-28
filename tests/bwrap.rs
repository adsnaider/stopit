//! Runs real specs, compiled from configuration, through the generated bwrap
//! command (`stopit::bwrap`), and checks with `stopit-probe` what the
//! sandbox sees. The probe is provisioned as each session's `stopit`, so it
//! runs at `/run/stopit/stopit` exactly as stopit would.

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use stopit::bwrap::{
    BWRAP_MAX_ARGS, BwrapCommand, BwrapError, PROC_MASKED_DIRS, PROC_MASKED_FILES,
    PROC_OPTIONAL_MASKS, TerminalSession,
};
use stopit::etc::{self, SandboxIds};
use stopit::manifest::EtcFile;

use common::*;

fn names(list: &[&str]) -> Data {
    Data::List(list.iter().map(|s| s.to_string()).collect())
}

fn env(pairs: &[(&str, &str)]) -> Data {
    Data::Env(
        pairs
            .iter()
            .map(|&(k, v)| (k.to_owned(), v.to_owned()))
            .collect::<BTreeMap<_, _>>(),
    )
}

/// Asserts that `result` failed because the path cannot be written.
#[track_caller]
fn not_writable(result: &OpResult) {
    let name = errno(result);
    assert!(name == "EROFS" || name == "EACCES", "{result:?}");
}

/// The workspace granted `rw`, plus `body`.
fn ws_rw(body: &str) -> String {
    config_none(&format!("fs.rw = [\"{{workspace}}\"]\n{body}"))
}

// --- Filesystem modes ---

#[test]
fn workspace_is_writable_at_its_mount_and_the_working_directory() {
    let f = SpecFixture::new();
    f.file("ws/a", "host a");
    let spec = f.compile(&ws_rw(""));
    let results = f.session().run(
        &spec,
        &[
            Op::Cwd,
            read("/workspace/a"),
            write("/workspace/new", "from the sandbox"),
            append("/workspace/a", ", appended"),
            mkdir("/workspace/dir"),
        ],
    );
    assert_eq!(ok(&results[0]), &Data::Cwd("/workspace".into()));
    assert_eq!(contents(&results[1]), "host a");
    for result in &results[2..] {
        assert_eq!(ok(result), &Data::Done);
    }
    let ws = f.workspace();
    assert_eq!(
        fs::read_to_string(ws.join("new")).unwrap(),
        "from the sandbox"
    );
    assert_eq!(
        fs::read_to_string(ws.join("a")).unwrap(),
        "host a, appended"
    );
    assert!(ws.join("dir").is_dir());
}

#[test]
fn ro_and_protected_rules_are_read_only() {
    let f = SpecFixture::new();
    f.file("ws/docs/readme", "docs");
    f.file("ws/flake.nix", "{ }");
    let spec = f.compile(&ws_rw(
        "fs.ro = [\"{workspace}/docs\"]\nfs.protected = [\"{workspace}/flake.nix\"]",
    ));
    let results = f.session().run(
        &spec,
        &[
            read("/workspace/docs/readme"),
            write("/workspace/docs/readme", "changed"),
            write("/workspace/docs/new", "new"),
            mkdir("/workspace/docs/dir"),
            remove("/workspace/docs/readme"),
            chmod("/workspace/docs/readme", 0o600),
            read("/workspace/flake.nix"),
            write("/workspace/flake.nix", "changed"),
            // Still writable around them.
            write("/workspace/other", "ok"),
        ],
    );
    assert_eq!(contents(&results[0]), "docs");
    for result in &results[1..6] {
        assert_eq!(errno(result), "EROFS", "{result:?}");
    }
    assert_eq!(contents(&results[6]), "{ }");
    assert_eq!(errno(&results[7]), "EROFS");
    assert_eq!(ok(&results[8]), &Data::Done);
    let ws = f.workspace();
    assert_eq!(fs::read_to_string(ws.join("docs/readme")).unwrap(), "docs");
    assert!(!ws.join("docs/new").exists());
    assert!(!ws.join("docs/dir").exists());
    assert_eq!(fs::read_to_string(ws.join("flake.nix")).unwrap(), "{ }");
}

#[test]
fn masked_file_is_empty_unreadable_and_read_only() {
    let f = SpecFixture::new();
    f.file("ws/.env", "SECRET=1");
    let spec = f.compile(&ws_rw("fs.masked = [\"{workspace}/.env\"]"));
    let results = f.session().run(
        &spec,
        &[
            stat("/workspace/.env"),
            read("/workspace/.env"),
            write("/workspace/.env", "x"),
            append("/workspace/.env", "x"),
            chmod("/workspace/.env", 0o644),
            remove("/workspace/.env"),
            rename("/workspace/.env", "/workspace/moved"),
        ],
    );
    let st = stat_data(&results[0]);
    assert_eq!(st.kind, FileKind::File);
    assert_eq!(st.size, 0);
    assert_eq!(st.mode, 0o000);
    assert_eq!(errno(&results[1]), "EACCES");
    not_writable(&results[2]);
    not_writable(&results[3]);
    assert_eq!(errno(&results[4]), "EROFS");
    // A mount point cannot be removed or renamed away.
    assert_eq!(errno(&results[5]), "EBUSY");
    assert_eq!(errno(&results[6]), "EBUSY");
    assert_eq!(
        fs::read_to_string(f.workspace().join(".env")).unwrap(),
        "SECRET=1"
    );
}

#[test]
fn masked_dir_is_empty_and_read_only_with_mounts_below_it_working() {
    let f = SpecFixture::new();
    f.file("ws/.git/config", "[core]");
    f.file("ws/secret/key", "private");
    f.file("ws/secret/allowed/f", "allowed content");
    let spec = f.compile(&ws_rw(
        "fs.masked = [\"{workspace}/.git\", \"{workspace}/secret\"]\n\
         fs.ro = [\"{workspace}/secret/allowed\"]",
    ));
    let results = f.session().run(
        &spec,
        &[
            list("/workspace/.git"),
            read("/workspace/.git/config"),
            write("/workspace/.git/config", "x"),
            mkdir("/workspace/.git/hooks"),
            // Only the nested mount's mount point shows.
            list("/workspace/secret"),
            read("/workspace/secret/key"),
            write("/workspace/secret/new", "x"),
            read("/workspace/secret/allowed/f"),
            write("/workspace/secret/allowed/g", "x"),
            stat("/workspace/.git"),
        ],
    );
    assert_eq!(ok(&results[0]), &names(&[]));
    assert_eq!(errno(&results[1]), "ENOENT");
    assert_eq!(errno(&results[2]), "EROFS");
    assert_eq!(errno(&results[3]), "EROFS");
    assert_eq!(ok(&results[4]), &names(&["allowed"]));
    assert_eq!(errno(&results[5]), "ENOENT");
    assert_eq!(errno(&results[6]), "EROFS");
    assert_eq!(contents(&results[7]), "allowed content");
    assert_eq!(errno(&results[8]), "EROFS");
    assert_eq!(stat_data(&results[9]).kind, FileKind::Dir);
    assert_eq!(
        fs::read_to_string(f.workspace().join(".git/config")).unwrap(),
        "[core]"
    );
}

#[test]
fn rw_mount_below_a_masked_dir_writes_through() {
    let f = SpecFixture::new();
    f.file("ws/secret/key", "private");
    f.file("ws/secret/cache/old", "old");
    let spec = f.compile(&config_none(
        "fs.rw = [\"{workspace}\", \"{workspace}/secret/cache\"]\n\
         fs.masked = [\"{workspace}/secret\"]",
    ));
    let results = f.session().run(
        &spec,
        &[
            read("/workspace/secret/cache/old"),
            write("/workspace/secret/cache/new", "written"),
            list("/workspace/secret"),
        ],
    );
    assert_eq!(contents(&results[0]), "old");
    assert_eq!(ok(&results[1]), &Data::Done);
    assert_eq!(ok(&results[2]), &names(&["cache"]));
    assert_eq!(
        fs::read_to_string(f.workspace().join("secret/cache/new")).unwrap(),
        "written"
    );
}

#[test]
fn ephemeral_mount_below_a_masked_dir_is_writable_and_persists() {
    let f = SpecFixture::new();
    f.file("ws/secret/key", "private");
    let spec = f.compile(&ws_rw(
        "fs.masked = [\"{workspace}/secret\"]\n\
         fs.ephemeral = [\"{workspace}/secret/scratch\"]",
    ));
    let session = f.session();
    let results = session.run(
        &spec,
        &[
            list("/workspace/secret"),
            read("/workspace/secret/key"),
            write("/workspace/secret/scratch/note", "kept"),
            write("/workspace/secret/new", "x"),
        ],
    );
    assert_eq!(ok(&results[0]), &names(&["scratch"]));
    assert_eq!(errno(&results[1]), "ENOENT");
    assert_eq!(ok(&results[2]), &Data::Done);
    assert_eq!(errno(&results[3]), "EROFS");
    // In the session's backing directory, not in the host workspace.
    assert!(!f.workspace().join("secret/scratch").exists());
    let backing = session.session.ephemeral();
    let dirs: Vec<_> = fs::read_dir(&backing).unwrap().collect();
    assert_eq!(dirs.len(), 1);
    let dir = dirs[0].as_ref().unwrap().path();
    assert_eq!(fs::read_to_string(dir.join("note")).unwrap(), "kept");
    // The next sandbox of the session sees it.
    let again = session.run_one(&spec, read("/workspace/secret/scratch/note"));
    assert_eq!(contents(&again), "kept");
}

#[test]
fn mask_nested_inside_a_mask() {
    let f = SpecFixture::new();
    f.file("ws/outer/inner/deep", "deep");
    f.file("ws/outer/inner/.env", "SECRET=1");
    f.file("ws/outer/visible", "x");
    f.file("ws/outer/allowed/inner/f", "nested secret");
    f.file("ws/outer/allowed/ok", "ok");
    // A masked directory whose `ro` grant holds a masked file and a masked
    // directory of its own.
    let spec = f.compile(&ws_rw(
        "fs.masked = [\"{workspace}/outer\", \"{workspace}/outer/allowed/inner\", \
         \"{workspace}/outer/allowed/ok\"]\n\
         fs.ro = [\"{workspace}/outer/allowed\"]",
    ));
    let results = f.session().run(
        &spec,
        &[
            list("/workspace/outer"),
            list("/workspace/outer/allowed"),
            list("/workspace/outer/allowed/inner"),
            read("/workspace/outer/allowed/inner/f"),
            mkdir("/workspace/outer/allowed/inner/d"),
            read("/workspace/outer/allowed/ok"),
            write("/workspace/outer/x", "x"),
        ],
    );
    assert_eq!(ok(&results[0]), &names(&["allowed"]));
    assert_eq!(ok(&results[1]), &names(&["inner", "ok"]));
    assert_eq!(ok(&results[2]), &names(&[]));
    assert_eq!(errno(&results[3]), "ENOENT");
    assert_eq!(errno(&results[4]), "EROFS");
    assert_eq!(errno(&results[5]), "EACCES");
    assert_eq!(errno(&results[6]), "EROFS");
}

#[test]
fn masked_socket_cannot_be_connected_to_or_read() {
    let f = SpecFixture::new();
    let path = f.workspace().join("app.sock");
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    let spec = f.compile(&ws_rw("fs.masked = [\"{workspace}/app.sock\"]"));
    let results = f.session().run(
        &spec,
        &[
            stat("/workspace/app.sock"),
            connect("/workspace/app.sock"),
            read("/workspace/app.sock"),
        ],
    );
    let st = stat_data(&results[0]);
    assert_eq!((st.kind, st.size, st.mode), (FileKind::File, 0, 0));
    // Mode 0000: no write permission, which connecting needs.
    assert_eq!(errno(&results[1]), "EACCES");
    assert_eq!(errno(&results[2]), "EACCES");
    // The host socket was listening all along.
    assert!(path.exists());
    drop(listener);
}

#[test]
fn root_and_bwraps_directories_are_read_only() {
    let f = SpecFixture::new();
    let spec = f.compile(&ws_rw("fs.ephemeral = [\"/tmp\", \"/home/foo/bar\"]"));
    let results = f.session().run(
        &spec,
        &[
            write("/x", "x"),
            mkdir("/y"),
            mkdir("/run/y"),
            mkdir("/run/stopit/x"),
            // `/home/foo` is an intermediate directory bwrap created for
            // the mount point below it.
            mkdir("/home/foo/x"),
            write("/home/foo/x", "x"),
            // The mounts on top stay writable.
            write("/tmp/ok", "ok"),
            write("/home/foo/bar/ok", "ok"),
            write("/workspace/ok", "ok"),
        ],
    );
    for result in &results[..6] {
        assert_eq!(errno(result), "EROFS", "{result:?}");
    }
    for result in &results[6..] {
        assert_eq!(ok(result), &Data::Done, "{result:?}");
    }
    assert_eq!(fs::read_to_string(f.workspace().join("ok")).unwrap(), "ok");
}

#[test]
fn root_is_mounted_read_only() {
    let f = SpecFixture::new();
    let spec = f.compile(&ws_rw("system.proc = true\nfs.ephemeral = [\"/tmp\"]"));
    let mounts = mountinfo(&f.session().run_one(&spec, Op::Mounts));
    assert!(mount_at(&mounts, "/").has_option("ro"), "{mounts:#?}");
    assert!(!mount_at(&mounts, "/tmp").has_option("ro"));
    assert!(!mount_at(&mounts, "/workspace").has_option("ro"));
}

#[test]
fn ephemeral_is_empty_writable_and_shared_within_a_session_only() {
    let f = SpecFixture::new();
    let spec = f.compile(&config_none("fs.ephemeral = [\"/tmp\"]"));
    let session = f.session();
    let first = session.run(
        &spec,
        &[list("/tmp"), write("/tmp/note", "first"), mkdir("/tmp/d")],
    );
    assert_eq!(ok(&first[0]), &names(&[]));
    assert_eq!(ok(&first[1]), &Data::Done);
    assert_eq!(ok(&first[2]), &Data::Done);

    // A second sandbox of the same session sees it.
    let second = session.run(&spec, &[read("/tmp/note"), list("/tmp")]);
    assert_eq!(contents(&second[0]), "first");
    assert_eq!(ok(&second[1]), &names(&["d", "note"]));

    // A new session starts empty.
    let other = f.session();
    let third = other.run(&spec, &[list("/tmp"), read("/tmp/note")]);
    assert_eq!(ok(&third[0]), &names(&[]));
    assert_eq!(errno(&third[1]), "ENOENT");

    // Nothing reached the host's /tmp: the writes are in the session.
    let backing = session.session.ephemeral();
    assert_eq!(fs::read_dir(&backing).unwrap().count(), 1);
    drop(session);
    assert!(!backing.exists(), "removed with the session");
}

#[test]
fn unmounted_host_paths_are_absent() {
    let f = SpecFixture::new();
    f.file("home/.ssh/id_ed25519", "key");
    f.file("outside", "x");
    let spec = f.compile(&ws_rw(""));
    let results = f.session().run(
        &spec,
        &[
            stat(f.home()),
            stat(f.home().join(".ssh/id_ed25519")),
            stat(f.root().join("outside")),
            // The host workspace shows only at its mount.
            stat(f.workspace()),
            stat("/home"),
            stat("/etc"),
            stat("/proc"),
            stat("/dev"),
            stat("/nix"),
            stat("/usr"),
            list("/"),
        ],
    );
    for result in &results[..10] {
        assert_eq!(errno(result), "ENOENT", "{result:?}");
    }
    // The empty root holds the mounts' parents only.
    assert_eq!(ok(&results[10]), &names(&["run", "workspace"]));
}

// --- System mounts ---

#[test]
fn proc_is_mounted_with_its_masks() {
    let f = SpecFixture::new();
    let spec = f.compile(&config_none("system.proc = true"));
    let mut ops = vec![stat("/proc/self"), read("/proc/self/status")];
    // Optional masks the host's kernel lacks are skipped; so are their
    // checks. The others are always there.
    let present = |p: &&str| !PROC_OPTIONAL_MASKS.contains(p) || Path::new(p).exists();
    let dirs: Vec<&str> = PROC_MASKED_DIRS.into_iter().filter(present).collect();
    let files: Vec<&str> = PROC_MASKED_FILES.into_iter().filter(present).collect();
    for required in ["/proc/sys", "/proc/fs", "/proc/irq"] {
        assert!(dirs.contains(&required), "{dirs:?}");
    }
    for dir in &dirs {
        ops.extend([
            list(dir),
            write(format!("{dir}/x"), "x"),
            mkdir(format!("{dir}/d")),
        ]);
    }
    for file in &files {
        ops.extend([stat(file), read(file), write(file, "x")]);
    }
    let results = f.session().run(&spec, &ops);
    assert_eq!(stat_data(&results[0]).kind, FileKind::Symlink);
    assert!(contents(&results[1]).contains("Pid:"), "{:?}", results[1]);
    let mut at = 2;
    for dir in &dirs {
        assert_eq!(ok(&results[at]), &names(&[]), "{dir}");
        assert_eq!(errno(&results[at + 1]), "EROFS", "{dir}");
        assert_eq!(errno(&results[at + 2]), "EROFS", "{dir}");
        at += 3;
    }
    for file in &files {
        let st = stat_data(&results[at]);
        assert_eq!(
            (st.kind, st.size, st.mode),
            (FileKind::File, 0, 0),
            "{file}"
        );
        assert_eq!(errno(&results[at + 1]), "EACCES", "{file}");
        not_writable(&results[at + 2]);
        at += 3;
    }
}

#[test]
fn without_proc_or_dev_there_is_neither() {
    let f = SpecFixture::new();
    let spec = f.compile(&config_none(""));
    let results = f.session().run(&spec, &[stat("/proc"), stat("/dev")]);
    assert_eq!(errno(&results[0]), "ENOENT");
    assert_eq!(errno(&results[1]), "ENOENT");
}

#[test]
fn dev_is_minimal() {
    let f = SpecFixture::new();
    let spec = f.compile(&config_none("system.dev = \"minimal\""));
    let results = f.session().run(
        &spec,
        &[
            stat("/dev/null"),
            write("/dev/null", "discarded"),
            read("/dev/zero"),
            stat("/dev/sda"),
            stat("/dev/nvme0n1"),
        ],
    );
    assert_eq!(stat_data(&results[0]).kind, FileKind::Other);
    assert_eq!(ok(&results[1]), &Data::Done);
    assert!(matches!(
        ok(&results[2]),
        Data::Read {
            truncated: true,
            ..
        }
    ));
    assert_eq!(errno(&results[3]), "ENOENT");
    assert_eq!(errno(&results[4]), "ENOENT");
}

// --- Synthesized `/etc` files ---

/// The ids of this process, which the sandbox user has.
fn host_ids() -> (u32, u32) {
    (
        rustix::process::getuid().as_raw(),
        rustix::process::getgid().as_raw(),
    )
}

#[test]
fn default_base_synthesizes_read_only_etc_files() {
    let f = SpecFixture::new();
    let (spec, _) = f.compile_with_warnings("");
    let files = ["passwd", "group", "hosts", "nsswitch.conf"];
    let mut ops = vec![list("/etc")];
    for name in files {
        let path = format!("/etc/{name}");
        ops.extend([
            stat(&path),
            read(&path),
            write(&path, "x"),
            append(&path, "x"),
            chmod(&path, 0o666),
            remove(&path),
            rename(&path, "/etc/moved"),
        ]);
    }
    ops.push(write("/etc/new", "x"));
    let results = f.session().run(&spec, &ops);
    assert_eq!(
        ok(&results[0]),
        &names(&["group", "hosts", "nsswitch.conf", "passwd"])
    );
    // For this process's ids, the sandbox user's (the line format is
    // checked against the probe's ids below, and golden in `stopit::etc`).
    let home = "/home/user".parse().unwrap();
    let expected = EtcFile::ALL
        .map(|f| etc::contents(f, SandboxIds::current(), &home, Some(etc::SANDBOX_HOSTNAME)));
    for (i, (name, want)) in files.iter().zip(&expected).enumerate() {
        let r = &results[1 + i * 7..1 + (i + 1) * 7];
        let st = stat_data(&r[0]);
        assert_eq!((st.kind, st.mode), (FileKind::File, 0o444), "{name}");
        assert_eq!(st.size, want.len() as u64, "{name}");
        assert_eq!(contents(&r[1]), want, "{name}");
        assert_eq!(errno(&r[2]), "EROFS", "{name}: {:?}", r[2]);
        not_writable(&r[3]);
        assert_eq!(errno(&r[4]), "EROFS", "{name}: {:?}", r[4]);
        for result in &r[5..] {
            let e = errno(result);
            assert!(e == "EROFS" || e == "EBUSY", "{name}: {result:?}");
        }
    }
    assert_eq!(errno(results.last().unwrap()), "EROFS");
}

#[test]
fn passwd_names_the_sandbox_users_ids() {
    let f = SpecFixture::new();
    let spec = f.compile(&config_none(
        "system.etc = [\"passwd\", \"group\"]\nsystem.home = \"/home/agent\"",
    ));
    let results = f
        .session()
        .run(&spec, &[Op::Ids, read("/etc/passwd"), read("/etc/group")]);
    let Data::Ids(ids) = ok(&results[0]) else {
        panic!("expected ids, got {:?}", results[0])
    };
    assert_eq!((ids.uid, ids.gid), host_ids());
    let user: Vec<&str> = contents(&results[1])
        .lines()
        .next()
        .unwrap()
        .split(':')
        .collect();
    assert_eq!(
        user,
        [
            "user",
            "x",
            &ids.uid.to_string(),
            &ids.gid.to_string(),
            "",
            "/home/agent",
            "/bin/sh"
        ]
    );
    let group = contents(&results[2]).lines().next().unwrap().to_owned();
    assert_eq!(group, format!("user:x:{}:", ids.gid));
}

#[test]
fn without_etc_files_there_is_no_etc() {
    let f = SpecFixture::new();
    let spec = f.compile(&config_none("system.etc = [\"hosts\"]"));
    let results = f.session().run(&spec, &[list("/etc"), stat("/etc/passwd")]);
    assert_eq!(ok(&results[0]), &names(&["hosts"]));
    assert_eq!(errno(&results[1]), "ENOENT");

    let spec = f.compile(&config_none("system.etc = []\nsystem.proc = true"));
    let results = f.session().run(&spec, &[stat("/etc/passwd"), stat("/etc")]);
    assert_eq!(errno(&results[0]), "ENOENT");
    assert_eq!(errno(&results[1]), "ENOENT");
}

#[test]
fn etc_files_coexist_with_a_grant_inside_etc() {
    let certs = Path::new("/etc/ssl/certs");
    if fs::metadata(certs).is_err() {
        eprintln!("skipped: the host has no {certs:?}");
        return;
    }
    let f = SpecFixture::new();
    let spec = f.compile(&config_none(
        "system.etc = [\"passwd\", \"group\", \"hosts\", \"nsswitch.conf\"]\n\
         fs.ro = [\"/etc/ssl/certs\"]",
    ));
    let results = f.session().run(
        &spec,
        &[
            list("/etc"),
            list("/etc/ssl"),
            stat_follow("/etc/ssl/certs"),
            read("/etc/hosts"),
            write("/etc/ssl/new", "x"),
        ],
    );
    assert_eq!(
        ok(&results[0]),
        &names(&["group", "hosts", "nsswitch.conf", "passwd", "ssl"])
    );
    assert_eq!(ok(&results[1]), &names(&["certs"]));
    assert_eq!(stat_data(&results[2]).kind, FileKind::Dir);
    assert_eq!(
        contents(&results[3]),
        etc::hosts(Some(etc::SANDBOX_HOSTNAME))
    );
    assert_eq!(errno(&results[4]), "EROFS");
}

/// The host directories that hold programs and the libraries they load,
/// among those that exist.
fn host_tool_dirs() -> Vec<&'static Path> {
    ["/nix/store", "/usr", "/lib", "/lib64", "/bin"]
        .map(Path::new)
        .into_iter()
        .filter(|d| d.symlink_metadata().is_ok())
        .collect()
}

/// The host's `name` program (`id`, `getent`, …) as a path the sandbox can
/// run once the existing ones of `dirs` are granted read-only, following
/// symlinks only until the path lies in one of them, so that a multi-call
/// binary still sees its name. `None` if there is no such program on
/// `PATH`, or it cannot be reached that way.
fn host_program(name: &str, dirs: &[&Path]) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let mut program = std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|p| p.is_file())?;
    for _ in 0..40 {
        if dirs.iter().any(|d| program.starts_with(d)) {
            return Some(program);
        }
        let target = fs::read_link(&program).ok()?;
        program = program.parent()?.join(target);
    }
    None
}

#[test]
fn glibc_resolves_the_sandbox_user_through_the_synthesized_files() {
    // Runs the host's `id`, which looks names up through glibc's NSS, so
    // `nsswitch.conf`, `passwd` and `group` all take part.
    let dirs = host_tool_dirs();
    let Some(id) = host_program("id", &dirs) else {
        eprintln!("skipped: no `id` reachable in {dirs:?}");
        return;
    };
    let ro: Vec<String> = dirs.iter().map(|d| format!("{d:?}")).collect();
    let f = SpecFixture::new();
    // `/dev` for the probe's `/dev/null` stdin.
    let spec = f.compile(&config_none(&format!(
        "system.dev = \"minimal\"\n\
         system.etc = [\"passwd\", \"group\", \"nsswitch.conf\"]\nfs.ro = [{}]",
        ro.join(", ")
    )));
    let exec = |args: &[&str]| Op::Exec {
        path: id.to_str().unwrap().to_owned(),
        args: args.iter().map(|a| a.to_string()).collect(),
        stdin: None,
    };
    let results = f.session().run(
        &spec,
        &[exec(&["-un"]), exec(&["-gn"]), exec(&["-un", "65534"])],
    );
    let (uid, gid) = host_ids();
    let stdout = |r: &OpResult| match ok(r) {
        Data::Exec(out) => {
            assert_eq!(out.code, Some(0), "{out:?}");
            out.stdout.clone()
        }
        other => panic!("expected exec output, got {other:?}"),
    };
    if uid != etc::OVERFLOW_ID {
        assert_eq!(stdout(&results[0]), "user\n");
        assert_eq!(stdout(&results[2]), "nobody\n");
    }
    if gid != etc::OVERFLOW_ID {
        assert_eq!(stdout(&results[1]), "user\n");
    }

    // Without them the name comes from nowhere else.
    let spec = f.compile(&config_none(&format!(
        "system.dev = \"minimal\"\nfs.ro = [{}]",
        ro.join(", ")
    )));
    let result = f.session().run_one(&spec, exec(&["-un"]));
    match ok(&result) {
        Data::Exec(out) => {
            assert_ne!(out.code, Some(0), "{out:?}");
            assert!(out.stderr.contains("cannot find name"), "{out:?}");
        }
        other => panic!("expected exec output, got {other:?}"),
    }
}

/// The node name `uname(2)` reports to this process: the host's hostname.
fn host_hostname() -> String {
    rustix::system::uname()
        .nodename()
        .to_string_lossy()
        .into_owned()
}

fn hostname_of(result: &OpResult) -> &str {
    match ok(result) {
        Data::Hostname(name) => name,
        other => panic!("expected a hostname, got {other:?}"),
    }
}

#[test]
fn sandbox_hostname_is_stopit_not_the_hosts() {
    let f = SpecFixture::new();
    let (spec, _) = f.compile_with_warnings("");
    let results = f.session().run(&spec, &[Op::Hostname, read("/etc/hosts")]);
    assert_eq!(hostname_of(&results[0]), etc::SANDBOX_HOSTNAME);
    assert_eq!(hostname_of(&results[0]), "stopit");
    // The synthesized `hosts` names it, and nothing of the host's.
    let hosts = contents(&results[1]);
    assert_eq!(hosts, etc::hosts(Some(etc::SANDBOX_HOSTNAME)));
    let host = host_hostname();
    if host != "localhost" && host != "stopit" {
        assert!(!hosts.contains(&host), "{hosts}");
    }
}

#[test]
fn shared_uts_namespace_keeps_the_hosts_hostname() {
    let f = SpecFixture::new();
    let spec = f.compile(&config_none(
        "sandbox.share = [\"uts\"]\nsystem.etc = [\"hosts\"]",
    ));
    let results = f.session().run(&spec, &[Op::Hostname, read("/etc/hosts")]);
    assert_eq!(hostname_of(&results[0]), host_hostname());
    // `hosts` does not name it, or copy the host's.
    assert_eq!(contents(&results[1]), etc::hosts(None));
}

#[test]
fn glibc_resolves_the_sandbox_hostname_through_the_synthesized_files() {
    // Runs the host's `getent`, which looks the name up through glibc's NSS,
    // so `nsswitch.conf` and `hosts` both take part.
    let dirs = host_tool_dirs();
    let Some(getent) = host_program("getent", &dirs) else {
        eprintln!("skipped: no `getent` reachable in {dirs:?}");
        return;
    };
    let ro: Vec<String> = dirs.iter().map(|d| format!("{d:?}")).collect();
    let f = SpecFixture::new();
    // `/dev` for the probe's `/dev/null` stdin.
    let spec = f.compile(&config_none(&format!(
        "system.dev = \"minimal\"\n\
         system.etc = [\"hosts\", \"nsswitch.conf\"]\nfs.ro = [{}]",
        ro.join(", ")
    )));
    let results = f.session().run(
        &spec,
        &[Op::Exec {
            path: getent.to_str().unwrap().to_owned(),
            args: ["hosts", etc::SANDBOX_HOSTNAME].map(str::to_owned).into(),
            stdin: None,
        }],
    );
    match ok(&results[0]) {
        Data::Exec(out) => {
            assert_eq!(out.code, Some(0), "{out:?}");
            let fields: Vec<&str> = out.stdout.split_whitespace().collect();
            assert!(
                fields.contains(&"127.0.0.1") || fields.contains(&"::1"),
                "{out:?}"
            );
            assert!(fields.contains(&etc::SANDBOX_HOSTNAME), "{out:?}");
        }
        other => panic!("expected exec output, got {other:?}"),
    }
}

// --- Runtime directory, environment, process ---

#[test]
fn runtime_dir_holds_only_the_provisioned_pieces_read_only() {
    let f = SpecFixture::new();
    let spec = f.compile(&config_none("system.proc = true"));
    let session = f.session();
    // The session directory holds more than is mounted.
    fs::write(session.session.ephemeral().join("marker"), "x").unwrap();
    let results = session.run(
        &spec,
        &[
            list("/run/stopit"),
            stat("/run/stopit/ephemeral"),
            mkdir("/run/stopit/lib/x"),
            mkdir("/run/stopit/bin/x"),
            write("/run/stopit/lib/new", "x"),
            chmod("/run/stopit/stopit", 0o700),
            Op::Mounts,
        ],
    );
    assert_eq!(ok(&results[0]), &names(&["bin", "lib", "stopit"]));
    assert_eq!(errno(&results[1]), "ENOENT");
    for result in &results[2..6] {
        assert_eq!(errno(result), "EROFS", "{result:?}");
    }
    let mounts = mountinfo(&results[6]);
    for at in ["/run/stopit/stopit", "/run/stopit/lib", "/run/stopit/bin"] {
        assert!(mount_at(&mounts, at).has_option("ro"), "{at}: {mounts:#?}");
    }
}

#[test]
fn environment_is_only_pwd() {
    let f = SpecFixture::new();
    let session = f.session();
    let with_ws = f.compile(&ws_rw(""));
    assert_eq!(
        ok(&session.run_one(&with_ws, Op::Env)),
        &env(&[("PWD", "/workspace")])
    );
    let without = f.compile(&config_none("system.proc = true"));
    assert_eq!(
        ok(&session.run_one(&without, Op::Env)),
        &env(&[("PWD", "/")])
    );
    assert_eq!(
        ok(&session.run_one(&without, Op::Cwd)),
        &Data::Cwd("/".into())
    );
}

#[test]
fn every_mount_is_nosuid_and_nodev() {
    let f = SpecFixture::new();
    f.file("ws/.env", "x");
    f.file("ws/.git/config", "x");
    f.file("ws/docs/readme", "x");
    let spec = f.compile(&ws_rw(
        "system = { proc = true, dev = \"minimal\" }\n\
         fs.masked = [\"{workspace}/.env\", \"{workspace}/.git\"]\n\
         fs.ro = [\"{workspace}/docs\"]\n\
         fs.ephemeral = [\"/tmp\", \"~\"]",
    ));
    let mounts = mountinfo(&f.session().run_one(&spec, Op::Mounts));
    for at in [
        "/",
        "/workspace",
        "/workspace/.env",
        "/workspace/.git",
        "/workspace/docs",
        "/tmp",
        "/home/user",
        "/proc",
        "/proc/sys",
        "/dev",
        "/run/stopit/stopit",
    ] {
        mount_at(&mounts, at);
    }
    for mount in &mounts {
        assert!(mount.has_option("nosuid"), "{mount:?}");
        // Inside the minimal /dev, bwrap binds the host's device nodes
        // (`null`, `zero`, …) and mounts a new devpts instance for the pty
        // slaves: those need device access by design. Every other mount,
        // /dev itself included, is nodev.
        let device = mount.mount_point.starts_with("/dev/")
            && matches!(mount.fs_type.as_str(), "devtmpfs" | "devpts");
        if !device {
            assert!(mount.has_option("nodev"), "{mount:?}");
        }
    }
    assert!(mount_at(&mounts, "/workspace/.git").has_option("ro"));
    assert!(mount_at(&mounts, "/workspace/.env").has_option("ro"));
    assert!(mount_at(&mounts, "/workspace/docs").has_option("ro"));
    assert!(!mount_at(&mounts, "/workspace").has_option("ro"));
    assert!(!mount_at(&mounts, "/tmp").has_option("ro"));
}

/// The total argument count of a generated invocation, as bwrap counts it:
/// everything after the program name on argv, plus what `--args` holds.
fn total_args(cmd: &BwrapCommand) -> usize {
    // `--args FD --` on argv.
    cmd.args().len() + 3 + cmd.command().len()
}

#[test]
fn many_mounts_pass_through_args_fd_up_to_bwraps_limit() {
    let f = SpecFixture::new();
    let session = f.session();
    // Fill the limit exactly: a read-only file grant is 3 arguments, a
    // masked file 5 (2 more than 3, so up to two of them make up the
    // remainder), and the rest of the invocation is what an empty spec
    // needs.
    let base = total_args(&session.command(&f.compile(&config_none(""))));
    let masks = [0, 2, 1][(BWRAP_MAX_ARGS - base) % 3];
    let n = (BWRAP_MAX_ARGS - base - 5 * masks) / 3;
    assert!(n > 2900, "{n}");
    let many = f.root().join("many");
    fs::create_dir(&many).unwrap();
    for i in 0..n {
        fs::write(many.join(format!("f{i:04}")), format!("file {i}")).unwrap();
    }
    let pads: Vec<String> = (0..masks)
        .map(|i| {
            let pad = f.file(&format!("pad{i}"), "secret");
            format!("\"{}\"", pad.to_str().unwrap())
        })
        .collect();
    let rules = format!(
        "fs.ro = [\"{}/*\"]\nfs.masked = [{}]",
        many.to_str().unwrap(),
        pads.join(", ")
    );
    let spec = f.compile(&config_none(&rules));
    assert_eq!(spec.mounts.len(), n + masks);
    let cmd = session.command(&spec);
    assert_eq!(total_args(&cmd), BWRAP_MAX_ARGS);
    let bytes: usize = cmd.args().iter().map(|a| a.len() + 1).sum();
    assert!(bytes > 64 * 1024, "more than a pipe holds: {bytes}");

    // One more file needs more than bwrap accepts, so it is refused before
    // bwrap runs.
    fs::write(many.join("one-more"), "x").unwrap();
    let over = f.compile(&config_none(&rules));
    let err = BwrapCommand::new(
        &over,
        &session.session,
        &session.provisioned,
        Path::new("/"),
        &[],
        TerminalSession::Keep,
    )
    .unwrap_err();
    assert!(matches!(err, BwrapError::TooManyArgs { .. }), "{err}");
    assert!(err.to_string().contains("provider \"config\""), "{err}");

    let last = n - 1;
    // bwrap rereads the mount table after each bind, so this many take
    // over ten seconds: allow more than the usual deadline.
    let results = run_probe_command_within(
        cmd,
        Duration::from_secs(120),
        &[
            read(many.join("f0000")),
            read(many.join(format!("f{last:04}"))),
            write(many.join("f1234"), "x"),
            list(&many),
            // The padding masks hold too.
            read(f.root().join("pad0")),
        ],
    );
    assert_eq!(contents(&results[0]), "file 0");
    assert_eq!(contents(&results[1]), format!("file {last}"));
    assert_eq!(errno(&results[2]), "EROFS");
    let Data::List(listed) = ok(&results[3]) else {
        panic!("{:?}", results[3])
    };
    // The mount points bwrap created, in an otherwise empty directory.
    assert_eq!(listed.len(), n);
    if masks > 0 {
        assert_eq!(errno(&results[4]), "EACCES");
    }
}

/// `count` bwrap arguments: no-op options, then `-- /nonexistent`.
fn filler(count: usize) -> Vec<&'static str> {
    // `--unsetenv X` is a no-op pair; `--clearenv` fixes the parity.
    let mut args = vec!["--unshare-user"];
    if (count - 3) % 2 == 1 {
        args.push("--clearenv");
    }
    while args.len() < count - 2 {
        args.extend(["--unsetenv", "X"]);
    }
    args.extend(["--", "/nonexistent"]);
    assert_eq!(args.len(), count);
    args
}

/// Asserts that bwrap, which wrote `stderr`, parsed its arguments and got
/// as far as running `/nonexistent`.
#[track_caller]
fn accepted(stderr: &[u8]) {
    let stderr = String::from_utf8_lossy(stderr);
    assert!(
        !stderr.contains("Exceeded maximum number of arguments"),
        "{stderr}"
    );
    assert!(stderr.contains("/nonexistent"), "{stderr}");
}

/// Asserts that bwrap, which wrote `stderr`, refused its arguments as too
/// many.
#[track_caller]
fn refused(stderr: &[u8]) {
    let stderr = String::from_utf8_lossy(stderr);
    assert!(
        stderr.contains("Exceeded maximum number of arguments"),
        "{stderr}"
    );
}

/// Pins [`BWRAP_MAX_ARGS`] against the bwrap on `PATH`: it accepts exactly
/// that many arguments after its program name, the command included, and
/// fails on one more, all on argv or split between argv and `--args`. Runs
/// of bwrap that fail fast either way.
#[test]
fn bwrap_accepts_exactly_max_args() {
    // On argv.
    accepted(&bwrap(filler(BWRAP_MAX_ARGS), None).stderr);
    refused(&bwrap(filler(BWRAP_MAX_ARGS + 1), None).stderr);

    // `--args 0 -- /nonexistent` on argv, the rest read from stdin.
    let through_args = |count: usize| {
        let options = &filler(count - 2)[..count - 4];
        let mut data = Vec::new();
        for arg in options {
            data.extend_from_slice(arg.as_bytes());
            data.push(0);
        }
        bwrap(["--args", "0", "--", "/nonexistent"], Some(&data))
    };
    accepted(&through_args(BWRAP_MAX_ARGS).stderr);
    refused(&through_args(BWRAP_MAX_ARGS + 1).stderr);
}

#[test]
fn a_command_can_be_spawned_twice() {
    // Each spawn reads the `--args` and data descriptors from the start,
    // so the second sandbox is set up like the first.
    let f = SpecFixture::new();
    f.file("ws/.env", "SECRET=1");
    let spec = f.compile(&ws_rw("fs.masked = [\"{workspace}/.env\"]"));
    let session = f.session();
    let mut command = session.command(&spec).into_command();
    let ops = [Op::Cwd, read("/workspace/.env"), write("/x", "x")];
    let input = serde_json::to_vec(&ops[..]).unwrap();
    for run in 0..2 {
        let out = spawn_bwrap(&mut command, Some(&input), BWRAP_DEADLINE);
        let results = probe_results(&format!("spawn {run}"), &out, &ops);
        assert_eq!(ok(&results[0]), &Data::Cwd("/workspace".into()), "{run}");
        assert_eq!(errno(&results[1]), "EACCES", "{run}");
        assert_eq!(errno(&results[2]), "EROFS", "{run}");
    }
}

#[test]
fn sandbox_is_in_a_new_pid_namespace() {
    let f = SpecFixture::new();
    let spec = f.compile(&config_none(""));
    let result = f.session().run_one(&spec, Op::Ids);
    let Data::Ids(ids) = ok(&result) else {
        panic!("expected ids, got {result:?}")
    };
    assert_eq!((ids.pid, ids.ppid), (2, 1), "{ids:?}");
    assert_eq!(ids.uid, rustix::process::getuid().as_raw());
}

#[test]
fn shared_pid_namespace_is_the_hosts() {
    let f = SpecFixture::new();
    let spec = f.compile(&config_none("sandbox.share = [\"pid\"]"));
    let result = f.session().run_one(&spec, Op::Ids);
    let Data::Ids(ids) = ok(&result) else {
        panic!("expected ids, got {result:?}")
    };
    assert!(ids.pid > 2, "{ids:?}");
}

#[test]
fn only_stdio_and_the_listing_are_open_in_the_sandbox() {
    // bwrap closes each `--ro-bind-data` descriptor after reading it, and
    // the `--args` one after parsing.
    let f = SpecFixture::new();
    f.file("ws/.env", "x");
    let spec = f.compile(&ws_rw(
        "system.proc = true\nfs.masked = [\"{workspace}/.env\"]",
    ));
    let result = f.session().run_one(&spec, list("/proc/self/fd"));
    // The fourth is the directory being listed.
    assert_eq!(ok(&result), &names(&["0", "1", "2", "3"]));
}

// --- The default base ---

#[test]
fn default_base_end_to_end() {
    let f = SpecFixture::new();
    f.file("ws/src/main.rs", "fn main() {}");
    f.file("ws/.env", "SECRET=1");
    f.file("ws/flake.nix", "{ }");
    // Warnings name the default rules whose paths do not exist here.
    let (spec, _) = f.compile_with_warnings("");
    let session = f.session();
    let results = session.run(
        &spec,
        &[
            Op::Cwd,
            Op::Env,
            read("/workspace/src/main.rs"),
            write("/workspace/src/lib.rs", "// new"),
            read("/workspace/.env"),
            write("/workspace/flake.nix", "x"),
            write("/tmp/scratch", "x"),
            write("/home/user/.cache", "x"),
            stat("/proc/self"),
            stat("/dev/null"),
            stat(f.home()),
        ],
    );
    assert_eq!(ok(&results[0]), &Data::Cwd("/workspace".into()));
    assert_eq!(ok(&results[1]), &env(&[("PWD", "/workspace")]));
    assert_eq!(contents(&results[2]), "fn main() {}");
    assert_eq!(ok(&results[3]), &Data::Done);
    assert_eq!(errno(&results[4]), "EACCES");
    assert_eq!(errno(&results[5]), "EROFS");
    assert_eq!(ok(&results[6]), &Data::Done);
    assert_eq!(ok(&results[7]), &Data::Done);
    assert_eq!(stat_data(&results[8]).kind, FileKind::Symlink);
    assert_eq!(stat_data(&results[9]).kind, FileKind::Other);
    assert_eq!(errno(&results[10]), "ENOENT");
    assert_eq!(
        fs::read_to_string(f.workspace().join("src/lib.rs")).unwrap(),
        "// new"
    );
    assert_eq!(
        fs::read_to_string(f.workspace().join("flake.nix")).unwrap(),
        "{ }"
    );
}
