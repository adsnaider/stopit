//! The wire format of `stopit-probe`: the operations it reads as a JSON array
//! on stdin, and the results it prints as a JSON array on stdout, one per
//! operation and in the same order.
//!
//! This file is shared: the probe includes it as a module, and the
//! integration-test harness (`tests/common`) includes it with `#[path]`, so
//! both sides use the same types without the probe being part of the library.
//! It must therefore depend on nothing but `std` and `serde`.
//!
//! Paths and strings are UTF-8: what the probe reports (file names, contents,
//! the environment, output) is converted lossily.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The most bytes [`Op::Read`] returns; longer files are truncated.
pub const MAX_READ: u64 = 1 << 20;

/// One operation for the probe to perform.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Op {
    /// `lstat`: the entry itself, a symlink included.
    Stat {
        /// The path.
        path: String,
    },
    /// `stat`: the entry a symlink leads to.
    StatFollow {
        /// The path.
        path: String,
    },
    /// Reads a file, at most [`MAX_READ`] bytes of it.
    Read {
        /// The path.
        path: String,
    },
    /// Creates or truncates a file, then writes `contents` to it.
    Write {
        /// The path.
        path: String,
        /// What to write.
        contents: String,
    },
    /// Appends `contents` to a file, creating it if needed.
    Append {
        /// The path.
        path: String,
        /// What to append.
        contents: String,
    },
    /// Creates one directory (not its parents).
    Mkdir {
        /// The path.
        path: String,
    },
    /// Removes a file, symlink or other non-directory entry, or an empty
    /// directory.
    Remove {
        /// The path.
        path: String,
    },
    /// Renames `from` to `to`, replacing `to` as `rename(2)` does.
    Rename {
        /// The entry to rename.
        from: String,
        /// Its new path.
        to: String,
    },
    /// Creates the symlink `link` with the text `target`.
    Symlink {
        /// The link's text.
        target: String,
        /// Where to create the link.
        link: String,
    },
    /// Creates the hard link `link` to the existing entry `original`.
    Link {
        /// The existing entry.
        original: String,
        /// Where to create the link.
        link: String,
    },
    /// Sets the permission bits of `path` (following symlinks).
    Chmod {
        /// The path.
        path: String,
        /// The new permission bits, `0o7777` at most.
        mode: u32,
    },
    /// Connects a Unix stream socket to the socket file `path`, then closes
    /// it. Reports only whether the connection succeeded.
    Connect {
        /// The socket's path.
        path: String,
    },
    /// Reads a symlink's text.
    Readlink {
        /// The path.
        path: String,
    },
    /// Lists a directory's entries, sorted, without `.` and `..`.
    List {
        /// The path.
        path: String,
    },
    /// The probe's whole environment.
    Env,
    /// The probe's arguments, `argv[0]` included.
    Argv,
    /// The probe's working directory.
    Cwd,
    /// The probe's uid, gid, pid and parent pid.
    Ids,
    /// The contents of `/proc/self/mountinfo`, read in full (not capped).
    Mounts,
    /// Runs `path` with `args` (and the probe's environment), feeding it
    /// `stdin` if given and an empty stdin otherwise, and waits for it. Its
    /// stdout and stderr are captured in full (not capped).
    Exec {
        /// The program. Like `execvp`, a name without a `/` is looked up in
        /// the probe's `PATH`; give a path to avoid that.
        path: String,
        /// Its arguments, after `argv[0]` (which is `path`).
        #[serde(default)]
        args: Vec<String>,
        /// What to write to its stdin.
        #[serde(default)]
        stdin: Option<String>,
    },
}

/// The result of one [`Op`]: what it observed, or why it failed.
pub type OpResult = Result<Data, OpError>;

/// What a successful [`Op`] observed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Data {
    /// [`Op::Write`], [`Op::Append`], [`Op::Mkdir`], [`Op::Remove`],
    /// [`Op::Rename`], [`Op::Symlink`], [`Op::Link`], [`Op::Chmod`] and
    /// [`Op::Connect`] report nothing but success.
    Done,
    /// [`Op::Stat`] and [`Op::StatFollow`].
    Stat(Stat),
    /// [`Op::Read`].
    Read {
        /// The bytes read, as UTF-8 (lossily).
        contents: String,
        /// The number of bytes read, at most [`MAX_READ`].
        len: u64,
        /// Whether the file is longer than [`MAX_READ`].
        truncated: bool,
    },
    /// [`Op::Readlink`]: the link's text.
    Readlink(String),
    /// [`Op::List`]: the entry names, sorted.
    List(Vec<String>),
    /// [`Op::Env`]: every variable.
    Env(BTreeMap<String, String>),
    /// [`Op::Argv`]: every argument, in order.
    Argv(Vec<String>),
    /// [`Op::Cwd`]: the working directory.
    Cwd(String),
    /// [`Op::Ids`].
    Ids(Ids),
    /// [`Op::Mounts`]: the raw contents of `/proc/self/mountinfo`.
    Mounts(String),
    /// [`Op::Exec`].
    Exec(ExecOutput),
}

/// The kind of a directory entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    /// A regular file.
    File,
    /// A directory.
    Dir,
    /// A symlink.
    Symlink,
    /// A Unix socket.
    Socket,
    /// A FIFO or a device.
    Other,
}

/// What [`Op::Stat`] and [`Op::StatFollow`] report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stat {
    /// The entry's kind.
    pub kind: FileKind,
    /// The permission bits, `st_mode & 0o7777`.
    pub mode: u32,
    /// The owner, as the probe's user namespace sees it.
    pub uid: u32,
    /// The group, as the probe's user namespace sees it.
    pub gid: u32,
    /// The size in bytes.
    pub size: u64,
    /// The number of hard links.
    pub nlink: u64,
    /// The device the entry is on.
    pub dev: u64,
    /// The inode number.
    pub ino: u64,
}

/// What [`Op::Ids`] reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ids {
    /// The real uid.
    pub uid: u32,
    /// The real gid.
    pub gid: u32,
    /// The pid, in the probe's pid namespace.
    pub pid: u32,
    /// The parent's pid, in the probe's pid namespace.
    pub ppid: u32,
}

/// What [`Op::Exec`] reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecOutput {
    /// The exit code, or `None` if the program was killed by a signal.
    pub code: Option<i32>,
    /// The signal that killed the program, if one did.
    pub signal: Option<i32>,
    /// Its stdout, as UTF-8 (lossily).
    pub stdout: String,
    /// Its stderr, as UTF-8 (lossily).
    pub stderr: String,
}

/// Why an [`Op`] failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpError {
    /// The OS error number, if the failure was one.
    pub errno: Option<i32>,
    /// Its symbolic name (`"ENOENT"`), if the probe knows it.
    pub name: Option<String>,
    /// A human-readable description.
    pub message: String,
}
