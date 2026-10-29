//! `stopit-probe`: a test-only observation tool. It runs inside a sandbox,
//! performs the filesystem and process operations it is given, and reports
//! what each one observed, so integration tests can check what a sandboxed
//! process can actually see and do.
//!
//! It reads a JSON array of [`Op`]s on stdin and prints a JSON array of
//! [`OpResult`]s on stdout, one per operation and in order (see
//! [`protocol`]). An operation that fails is reported as an [`OpError`] and
//! the next one runs anyway: failures are data, and the probe never panics on
//! one. Only input that is not a valid operation list, or output that cannot
//! be written, makes it exit unsuccessfully (with status 2 and 1).
//!
//! It is dynamically linked like stopit, so `stopit::provision` copies it the
//! same way.

mod protocol;

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt, symlink};
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};

use rustix::io::Errno;

use protocol::{
    Data, ExecOutput, FileKind, Ids, MAX_READ, Op, OpError, OpResult, Stat, SyscallProbe,
};

fn main() -> ExitCode {
    let mut input = Vec::new();
    if let Err(e) = io::stdin().read_to_end(&mut input) {
        eprintln!("stopit-probe: cannot read stdin: {e}");
        return ExitCode::from(2);
    }
    let ops: Vec<Op> = match serde_json::from_slice(&input) {
        Ok(ops) => ops,
        Err(e) => {
            eprintln!("stopit-probe: stdin is not a JSON array of operations: {e}");
            return ExitCode::from(2);
        }
    };
    let results: Vec<OpResult> = ops.iter().map(run).collect();
    let mut stdout = io::stdout().lock();
    let written = serde_json::to_writer(&mut stdout, &results)
        .map_err(io::Error::from)
        .and_then(|()| stdout.write_all(b"\n"))
        .and_then(|()| stdout.flush());
    match written {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("stopit-probe: cannot write the results: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Performs one operation.
fn run(op: &Op) -> OpResult {
    let done = |result: io::Result<()>| result.map(|()| Data::Done).map_err(op_error);
    match op {
        Op::Stat { path } => stat(fs::symlink_metadata(path)),
        Op::StatFollow { path } => stat(fs::metadata(path)),
        Op::Read { path } => read(Path::new(path), MAX_READ),
        Op::Write { path, contents } => done(fs::write(path, contents)),
        Op::Append { path, contents } => done(
            OpenOptions::new()
                .append(true)
                .create(true)
                .open(path)
                .and_then(|mut file| file.write_all(contents.as_bytes())),
        ),
        Op::Mkdir { path } => done(fs::create_dir(path)),
        Op::Remove { path } => done(remove(Path::new(path))),
        Op::Rename { from, to } => done(fs::rename(from, to)),
        Op::Symlink { target, link } => done(symlink(target, link)),
        Op::Link { original, link } => done(fs::hard_link(original, link)),
        Op::Chmod { path, mode } => {
            done(fs::set_permissions(path, fs::Permissions::from_mode(*mode)))
        }
        Op::Connect { path } => done(UnixStream::connect(path).map(drop)),
        Op::Readlink { path } => fs::read_link(path)
            .map(|target| Data::Readlink(target.to_string_lossy().into_owned()))
            .map_err(op_error),
        Op::List { path } => list(Path::new(path)),
        Op::Env => Ok(Data::Env(
            std::env::vars_os()
                .map(|(k, v)| {
                    (
                        k.to_string_lossy().into_owned(),
                        v.to_string_lossy().into_owned(),
                    )
                })
                .collect(),
        )),
        Op::Argv => Ok(Data::Argv(
            std::env::args_os()
                .map(|a| a.to_string_lossy().into_owned())
                .collect(),
        )),
        Op::Cwd => std::env::current_dir()
            .map(|cwd| Data::Cwd(cwd.to_string_lossy().into_owned()))
            .map_err(op_error),
        Op::Ids => Ok(Data::Ids(Ids {
            uid: rustix::process::getuid().as_raw(),
            gid: rustix::process::getgid().as_raw(),
            pid: std::process::id(),
            ppid: std::os::unix::process::parent_id(),
        })),
        Op::Hostname => Ok(Data::Hostname(
            rustix::system::uname()
                .nodename()
                .to_string_lossy()
                .into_owned(),
        )),
        Op::Mounts => fs::read("/proc/self/mountinfo")
            .map(|bytes| Data::Mounts(String::from_utf8_lossy(&bytes).into_owned()))
            .map_err(op_error),
        Op::Exec { path, args, stdin } => exec(path, args, stdin.as_deref()),
        Op::LoFlags => lo_flags(),
        Op::TcpLoopbackRoundtrip => done(tcp_loopback_roundtrip()),
        Op::ConnectAbstract { name } => done(connect_abstract(name)),
        Op::Socket {
            domain,
            ty,
            protocol,
        } => done(open_socket(*domain, *ty, *protocol).map(drop)),
        Op::Syscall { call } => done(syscall_probe(*call)),
    }
}

fn stat(meta: io::Result<fs::Metadata>) -> OpResult {
    let meta = meta.map_err(op_error)?;
    let file_type = meta.file_type();
    let kind = if file_type.is_file() {
        FileKind::File
    } else if file_type.is_dir() {
        FileKind::Dir
    } else if file_type.is_symlink() {
        FileKind::Symlink
    } else if file_type.is_socket() {
        FileKind::Socket
    } else {
        FileKind::Other
    };
    Ok(Data::Stat(Stat {
        kind,
        mode: meta.mode() & 0o7777,
        uid: meta.uid(),
        gid: meta.gid(),
        size: meta.size(),
        dev: meta.dev(),
        ino: meta.ino(),
        nlink: meta.nlink(),
    }))
}

/// Reads at most `cap` bytes of `path`.
fn read(path: &Path, cap: u64) -> OpResult {
    let mut bytes = Vec::new();
    // One byte past the cap tells whether there is more.
    File::open(path)
        .and_then(|file| file.take(cap.saturating_add(1)).read_to_end(&mut bytes))
        .map_err(op_error)?;
    let truncated = bytes.len() as u64 > cap;
    bytes.truncate(cap as usize);
    Ok(Data::Read {
        contents: String::from_utf8_lossy(&bytes).into_owned(),
        len: bytes.len() as u64,
        truncated,
    })
}

/// Unlinks `path`, or removes it as an empty directory if it is one.
/// Deciding by the error rather than by a prior `lstat` leaves no window in
/// which the entry could change kind.
fn remove(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.raw_os_error() == Some(Errno::ISDIR.raw_os_error()) => fs::remove_dir(path),
        result => result,
    }
}

fn list(path: &Path) -> OpResult {
    let mut names = Vec::new();
    for entry in fs::read_dir(path).map_err(op_error)? {
        let entry = entry.map_err(op_error)?;
        names.push(entry.file_name().to_string_lossy().into_owned());
    }
    names.sort();
    Ok(Data::List(names))
}

fn exec(path: &str, args: &[String], stdin: Option<&str>) -> OpResult {
    let mut child = Command::new(path)
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(op_error)?;
    // Written from another thread so a child that writes before it has read
    // all its input cannot deadlock against us. A child that exits without
    // reading it all closes the pipe; that is its business, not an error.
    let writer = child.stdin.take().map(|mut pipe| {
        let input = stdin.unwrap_or_default().to_owned();
        std::thread::spawn(move || {
            let _ = pipe.write_all(input.as_bytes());
        })
    });
    let output = child.wait_with_output().map_err(op_error)?;
    if let Some(writer) = writer {
        let _ = writer.join();
    }
    Ok(Data::Exec(ExecOutput {
        code: output.status.code(),
        signal: output.status.signal(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }))
}

fn open_socket(domain: i32, ty: i32, protocol: i32) -> io::Result<OwnedFd> {
    // SAFETY: `SYS_socket` takes three integer arguments and returns a fresh
    // file descriptor on non-negative return or `-1` with `errno` set.
    let raw = unsafe {
        libc::syscall(
            libc::SYS_socket,
            domain as libc::c_long,
            (ty | libc::SOCK_CLOEXEC) as libc::c_long,
            protocol as libc::c_long,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a newly created descriptor owned exclusively here.
    Ok(unsafe { OwnedFd::from_raw_fd(raw as i32) })
}

fn lo_flags() -> OpResult {
    let sock = open_socket(libc::AF_INET, libc::SOCK_DGRAM, 0).map_err(op_error)?;
    // SAFETY: zero-initializing `libc::ifreq` produces valid C storage.
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    ifr.ifr_name[0] = b'l' as libc::c_char;
    ifr.ifr_name[1] = b'o' as libc::c_char;
    // SAFETY: `sock` is a valid socket descriptor and `ifr` points to writable
    // `ifreq` storage for `SIOCGIFFLAGS`.
    let rc = unsafe {
        libc::ioctl(
            std::os::fd::AsRawFd::as_raw_fd(&sock),
            libc::SIOCGIFFLAGS as _,
            &mut ifr,
        )
    };
    if rc != 0 {
        return Err(op_error(io::Error::last_os_error()));
    }
    // SAFETY: `SIOCGIFFLAGS` populated the `ifru_flags` union member.
    let flags = unsafe { ifr.ifr_ifru.ifru_flags };
    Ok(Data::Flags(i32::from(flags)))
}

fn tcp_loopback_roundtrip() -> io::Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let addr = listener.local_addr()?;
    let mut client = TcpStream::connect(addr)?;
    let (mut server, _) = listener.accept()?;
    client.write_all(&[0x5a])?;
    let mut byte = [0u8; 1];
    server.read_exact(&mut byte)?;
    if byte != [0x5a] {
        return Err(io::Error::other("unexpected loopback payload"));
    }
    Ok(())
}

fn connect_abstract(name: &str) -> io::Result<()> {
    let sock = open_socket(libc::AF_UNIX, libc::SOCK_STREAM, 0)?;
    // SAFETY: zero-initializing `sockaddr_un` sets `sun_path[0] = 0` for the
    // Linux abstract socket namespace.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let max_name = addr.sun_path.len().saturating_sub(1);
    if name.len() > max_name {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    // SAFETY: `addr.sun_path` has room for the leading NUL plus `name.len()`
    // bytes.
    unsafe {
        let base = std::ptr::addr_of_mut!(addr.sun_path).cast::<u8>();
        std::ptr::copy_nonoverlapping(name.as_ptr(), base.add(1), name.len());
    }
    let addrlen =
        (std::mem::offset_of!(libc::sockaddr_un, sun_path) + 1 + name.len()) as libc::socklen_t;
    // SAFETY: `sock` is a valid `AF_UNIX` socket and `(addr, addrlen)` names a
    // valid abstract `sockaddr_un`.
    let rc = unsafe {
        libc::connect(
            std::os::fd::AsRawFd::as_raw_fd(&sock),
            std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
            addrlen,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn syscall_probe(call: SyscallProbe) -> io::Result<()> {
    let check = |rc: libc::c_long| {
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    };
    match call {
        SyscallProbe::Clone3 => {
            // SAFETY: passing `(NULL, 0)` makes the kernel reject `clone3`
            // with `EINVAL` if seccomp did not already reject it with `ENOSYS`.
            check(unsafe { libc::syscall(libc::SYS_clone3, std::ptr::null::<u8>(), 0usize) })
        }
        SyscallProbe::UnshareUser => {
            // SAFETY: `unshare` takes integer flags only.
            let rc = unsafe { libc::unshare(libc::CLONE_NEWUSER) };
            check(libc::c_long::from(rc))
        }
        SyscallProbe::CloneNewuser => {
            let flags = (libc::CLONE_NEWUSER | libc::SIGCHLD) as libc::c_ulong;
            // SAFETY: if `SYS_clone` were ever permitted outside a sandbox and
            // created a child (`rc == 0`), the child exits immediately via
            // `_exit(0)` without touching Rust state.
            let rc =
                unsafe { libc::syscall(libc::SYS_clone, flags, 0usize, 0usize, 0usize, 0usize) };
            if rc == 0 {
                // SAFETY: async-signal-safe immediate process exit in child.
                unsafe { libc::_exit(0) };
            }
            if rc > 0 {
                let mut status = 0;
                // SAFETY: `rc` is the child pid returned by `clone`.
                unsafe {
                    let _ = libc::waitpid(rc as libc::pid_t, &mut status, 0);
                }
                return Ok(());
            }
            Err(io::Error::last_os_error())
        }
        SyscallProbe::Setns => {
            // SAFETY: `setns` with `-1` has no side effects.
            let rc = unsafe { libc::setns(-1, 0) };
            check(libc::c_long::from(rc))
        }
        SyscallProbe::Mount => {
            // SAFETY: null pointers make `mount` fail without side effects.
            let rc = unsafe {
                libc::mount(
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                )
            };
            check(libc::c_long::from(rc))
        }
        SyscallProbe::Umount2 => {
            // SAFETY: `c"/"` is a valid NUL-terminated string.
            let rc = unsafe { libc::umount2(c"/".as_ptr(), 0) };
            check(libc::c_long::from(rc))
        }
        SyscallProbe::OpenTree => {
            // SAFETY: `-1` and `NULL` make `open_tree` fail without side effects.
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_open_tree,
                    -1i32,
                    std::ptr::null::<libc::c_char>(),
                    0u32,
                )
            };
            if rc >= 0 {
                // SAFETY: closes unexpected descriptor if ever returned.
                unsafe {
                    libc::close(rc as i32);
                }
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }
        SyscallProbe::Fsopen => {
            // SAFETY: `NULL` makes `fsopen` fail without side effects.
            let rc =
                unsafe { libc::syscall(libc::SYS_fsopen, std::ptr::null::<libc::c_char>(), 0u32) };
            if rc >= 0 {
                // SAFETY: closes unexpected descriptor if ever returned.
                unsafe {
                    libc::close(rc as i32);
                }
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }
        SyscallProbe::IoUringSetup => {
            // SAFETY: `0` entries and `NULL` params fail without side effects.
            check(unsafe {
                libc::syscall(libc::SYS_io_uring_setup, 0u32, std::ptr::null_mut::<u8>())
            })
        }
        SyscallProbe::Bpf => {
            // SAFETY: zero attr size fails without side effects.
            check(unsafe { libc::syscall(libc::SYS_bpf, 0i32, std::ptr::null::<u8>(), 0u32) })
        }
        SyscallProbe::PerfEventOpen => {
            // SAFETY: `NULL` attr fails without side effects.
            check(unsafe {
                libc::syscall(
                    libc::SYS_perf_event_open,
                    std::ptr::null::<u8>(),
                    0i32,
                    -1i32,
                    -1i32,
                    0usize,
                )
            })
        }
        SyscallProbe::Userfaultfd => {
            // SAFETY: `userfaultfd` takes integer flags and returns an fd or `-1`.
            let rc = unsafe { libc::syscall(libc::SYS_userfaultfd, libc::O_CLOEXEC) };
            if rc >= 0 {
                // SAFETY: `rc` is a newly created userfaultfd descriptor.
                unsafe {
                    libc::close(rc as i32);
                }
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }
        SyscallProbe::Keyctl => {
            // SAFETY: invalid command `-1` fails with `EOPNOTSUPP` without side
            // effects when allowed, and seccomp blocks `SYS_keyctl` first.
            check(unsafe { libc::syscall(libc::SYS_keyctl, -1i32, 0usize, 0usize, 0usize, 0usize) })
        }
        SyscallProbe::AddKey => {
            // SAFETY: `NULL` arguments fail without side effects.
            check(unsafe {
                libc::syscall(
                    libc::SYS_add_key,
                    std::ptr::null::<libc::c_char>(),
                    std::ptr::null::<libc::c_char>(),
                    std::ptr::null::<u8>(),
                    0usize,
                    0i32,
                )
            })
        }
        SyscallProbe::RequestKey => {
            // SAFETY: `NULL` arguments fail without side effects.
            check(unsafe {
                libc::syscall(
                    libc::SYS_request_key,
                    std::ptr::null::<libc::c_char>(),
                    std::ptr::null::<libc::c_char>(),
                    std::ptr::null::<libc::c_char>(),
                    0i32,
                )
            })
        }
        SyscallProbe::PtraceTraceme => ptrace_traceme_in_child(),
        SyscallProbe::IoctlTiocsti => raw_ioctl_byte(0x5412),
        SyscallProbe::IoctlTiocstiHighBit => raw_ioctl_byte((1u64 << 32) | 0x5412),
        SyscallProbe::IoctlTioclinux => raw_ioctl_byte(0x541c),
        SyscallProbe::IoctlTioclinuxHighBit => raw_ioctl_byte((1u64 << 32) | 0x541c),
    }
}

fn raw_ioctl_byte(request: u64) -> io::Result<()> {
    let byte = b'x';
    // SAFETY: passes a valid pointer to a local byte for `TIOCSTI`/`TIOCLINUX`
    // probing; seccomp rejects both requests before the kernel inspects fd 0.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_ioctl,
            0i32,
            request as libc::c_ulong,
            std::ptr::addr_of!(byte),
        )
    };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn ptrace_traceme_in_child() -> io::Result<()> {
    let mut fds = [0i32; 2];
    // SAFETY: `fds` is a valid two-element array for `pipe2`.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fds[0]` and `fds[1]` are fresh pipe descriptors.
    let (mut reader, writer) = unsafe { (File::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    // SAFETY: the child runs only async-signal-safe syscalls (`close`,
    // `syscall(SYS_ptrace, ...)`, `write`, `_exit`) before terminating.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        let write_fd = std::os::fd::AsRawFd::as_raw_fd(&writer);
        // SAFETY: async-signal-safe syscalls in the forked child.
        unsafe {
            libc::close(std::os::fd::AsRawFd::as_raw_fd(&reader));
            let rc = libc::syscall(
                libc::SYS_ptrace,
                libc::PTRACE_TRACEME as libc::c_long,
                0usize,
                0usize,
                0usize,
            );
            let err: i32 = if rc < 0 { *libc::__errno_location() } else { 0 };
            let bytes = err.to_ne_bytes();
            let _ = libc::write(write_fd, bytes.as_ptr().cast(), bytes.len());
            libc::_exit(0);
        }
    }
    drop(writer);
    let mut buf = [0u8; 4];
    let read_res = reader.read_exact(&mut buf);
    let mut status = 0;
    // SAFETY: `pid` is our child process.
    unsafe {
        let _ = libc::waitpid(pid, &mut status, 0);
    }
    read_res?;
    let err = i32::from_ne_bytes(buf);
    if err == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(err))
    }
}

/// Symbolic names of the error numbers tests are likely to meet.
const ERRNO_NAMES: &[(Errno, &str)] = &[
    (Errno::PERM, "EPERM"),
    (Errno::NOENT, "ENOENT"),
    (Errno::SRCH, "ESRCH"),
    (Errno::INTR, "EINTR"),
    (Errno::IO, "EIO"),
    (Errno::NXIO, "ENXIO"),
    (Errno::NOEXEC, "ENOEXEC"),
    (Errno::BADF, "EBADF"),
    (Errno::CHILD, "ECHILD"),
    (Errno::AGAIN, "EAGAIN"),
    (Errno::NOMEM, "ENOMEM"),
    (Errno::ACCESS, "EACCES"),
    (Errno::FAULT, "EFAULT"),
    (Errno::BUSY, "EBUSY"),
    (Errno::EXIST, "EEXIST"),
    (Errno::XDEV, "EXDEV"),
    (Errno::NODEV, "ENODEV"),
    (Errno::NOTDIR, "ENOTDIR"),
    (Errno::ISDIR, "EISDIR"),
    (Errno::INVAL, "EINVAL"),
    (Errno::NOTTY, "ENOTTY"),
    (Errno::TXTBSY, "ETXTBSY"),
    (Errno::FBIG, "EFBIG"),
    (Errno::NOSPC, "ENOSPC"),
    (Errno::SPIPE, "ESPIPE"),
    (Errno::ROFS, "EROFS"),
    (Errno::MLINK, "EMLINK"),
    (Errno::PIPE, "EPIPE"),
    (Errno::NAMETOOLONG, "ENAMETOOLONG"),
    (Errno::NOSYS, "ENOSYS"),
    (Errno::NOTEMPTY, "ENOTEMPTY"),
    (Errno::LOOP, "ELOOP"),
    (Errno::NODATA, "ENODATA"),
    (Errno::NOTSOCK, "ENOTSOCK"),
    (Errno::PROTONOSUPPORT, "EPROTONOSUPPORT"),
    (Errno::OPNOTSUPP, "EOPNOTSUPP"),
    (Errno::AFNOSUPPORT, "EAFNOSUPPORT"),
    (Errno::ADDRINUSE, "EADDRINUSE"),
    (Errno::ADDRNOTAVAIL, "EADDRNOTAVAIL"),
    (Errno::NETDOWN, "ENETDOWN"),
    (Errno::NETUNREACH, "ENETUNREACH"),
    (Errno::TIMEDOUT, "ETIMEDOUT"),
    (Errno::CONNREFUSED, "ECONNREFUSED"),
    (Errno::HOSTUNREACH, "EHOSTUNREACH"),
    (Errno::NOTCONN, "ENOTCONN"),
    (Errno::STALE, "ESTALE"),
    (Errno::DQUOT, "EDQUOT"),
];

/// The symbolic name of the error number `errno`, if it is in
/// [`ERRNO_NAMES`].
fn errno_name(errno: i32) -> Option<&'static str> {
    ERRNO_NAMES
        .iter()
        .find(|(e, _)| e.raw_os_error() == errno)
        .map(|&(_, name)| name)
}

fn op_error(error: io::Error) -> OpError {
    let errno = error.raw_os_error();
    OpError {
        errno,
        name: errno.and_then(errno_name).map(str::to_owned),
        message: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn link_shares_the_inode() {
        let dir = Dir::new();
        fs::write(dir.path("f"), b"x").unwrap();
        let op = Op::Link {
            original: dir.path("f"),
            link: dir.path("g"),
        };
        assert_eq!(run(&op), Ok(Data::Done));
        let f = stat_of(run(&Op::Stat {
            path: dir.path("f"),
        }));
        let g = stat_of(run(&Op::Stat {
            path: dir.path("g"),
        }));
        assert_eq!((f.ino, f.nlink), (g.ino, 2));
        assert_eq!(err_name(run(&op)), "EEXIST");
    }

    #[test]
    fn chmod_sets_the_mode_and_follows_links() {
        let dir = Dir::new();
        fs::write(dir.path("f"), b"").unwrap();
        symlink("f", dir.path("l")).unwrap();
        let chmod = |name: &str, mode| {
            run(&Op::Chmod {
                path: dir.path(name),
                mode,
            })
        };
        assert_eq!(chmod("l", 0o640), Ok(Data::Done));
        assert_eq!(
            stat_of(run(&Op::Stat {
                path: dir.path("f")
            }))
            .mode,
            0o640
        );
        assert_eq!(err_name(chmod("missing", 0o600)), "ENOENT");
    }

    #[test]
    fn connect_reports_success_or_errno() {
        let dir = Dir::new();
        let _listener = UnixListener::bind(dir.path("sock")).unwrap();
        fs::write(dir.path("file"), b"").unwrap();
        let connect = |name: &str| {
            run(&Op::Connect {
                path: dir.path(name),
            })
        };
        assert_eq!(connect("sock"), Ok(Data::Done));
        assert_eq!(err_name(connect("missing")), "ENOENT");
        assert_eq!(err_name(connect("file")), "ECONNREFUSED");
    }

    /// A temporary directory and a way to name paths in it.
    struct Dir(TempDir);

    impl Dir {
        fn new() -> Self {
            Dir(TempDir::new().unwrap())
        }

        fn path(&self, name: &str) -> String {
            self.0.path().join(name).to_str().unwrap().to_owned()
        }
    }

    fn err_name(result: OpResult) -> String {
        match result {
            Err(e) => e
                .name
                .clone()
                .unwrap_or_else(|| panic!("unnamed error: {e:?}")),
            Ok(data) => panic!("expected an error, got {data:?}"),
        }
    }

    fn stat_of(result: OpResult) -> Stat {
        match result {
            Ok(Data::Stat(stat)) => stat,
            other => panic!("expected a stat, got {other:?}"),
        }
    }

    fn contents(dir: &Dir, name: &str) -> String {
        match run(&Op::Read {
            path: dir.path(name),
        }) {
            Ok(Data::Read { contents, .. }) => contents,
            other => panic!("expected contents, got {other:?}"),
        }
    }

    #[test]
    fn write_append_and_read() {
        let dir = Dir::new();
        let f = dir.path("f");
        let write = |contents: &str| Op::Write {
            path: f.clone(),
            contents: contents.into(),
        };
        assert_eq!(run(&write("first, longer")), Ok(Data::Done));
        assert_eq!(run(&write("one")), Ok(Data::Done), "truncates");
        let append = Op::Append {
            path: f.clone(),
            contents: " two".into(),
        };
        assert_eq!(run(&append), Ok(Data::Done));
        assert_eq!(
            run(&Op::Read { path: f }),
            Ok(Data::Read {
                contents: "one two".into(),
                len: 7,
                truncated: false,
            })
        );
        // Append creates.
        let append = Op::Append {
            path: dir.path("g"),
            contents: "new".into(),
        };
        assert_eq!(run(&append), Ok(Data::Done));
        assert_eq!(contents(&dir, "g"), "new");
    }

    #[test]
    fn read_is_capped_and_lossy() {
        let dir = Dir::new();
        fs::write(dir.path("f"), b"abc\xffdef").unwrap();
        let path = dir.0.path().join("f");
        assert_eq!(
            read(&path, 3),
            Ok(Data::Read {
                contents: "abc".into(),
                len: 3,
                truncated: true,
            })
        );
        assert_eq!(
            read(&path, 7),
            Ok(Data::Read {
                contents: "abc\u{fffd}def".into(),
                len: 7,
                truncated: false,
            })
        );
        assert_eq!(
            read(&path, 0),
            Ok(Data::Read {
                contents: String::new(),
                len: 0,
                truncated: true,
            })
        );
    }

    #[test]
    fn stat_reports_kinds_and_follows_only_when_asked() {
        let dir = Dir::new();
        fs::write(dir.path("file"), b"12345").unwrap();
        fs::create_dir(dir.path("dir")).unwrap();
        symlink("file", dir.path("link")).unwrap();
        let _listener = UnixListener::bind(dir.path("sock")).unwrap();

        let lstat = |name: &str| {
            stat_of(run(&Op::Stat {
                path: dir.path(name),
            }))
        };
        let file = lstat("file");
        assert_eq!(file.kind, FileKind::File);
        assert_eq!(file.size, 5);
        assert_eq!(file.uid, rustix::process::getuid().as_raw());
        assert_eq!(lstat("dir").kind, FileKind::Dir);
        assert_eq!(lstat("link").kind, FileKind::Symlink);
        assert_eq!(lstat("sock").kind, FileKind::Socket);
        assert_eq!(
            stat_of(run(&Op::Stat {
                path: "/dev/null".into()
            }))
            .kind,
            FileKind::Other
        );

        let followed = stat_of(run(&Op::StatFollow {
            path: dir.path("link"),
        }));
        assert_eq!(followed, file);
        assert_ne!(lstat("link").ino, file.ino);
    }

    #[test]
    fn stat_reports_permission_bits() {
        let dir = Dir::new();
        fs::write(dir.path("f"), b"").unwrap();
        fs::set_permissions(dir.path("f"), fs::Permissions::from_mode(0o4751)).unwrap();
        assert_eq!(
            stat_of(run(&Op::Stat {
                path: dir.path("f")
            }))
            .mode,
            0o4751
        );
    }

    #[test]
    fn mkdir_list_rename_and_remove() {
        let dir = Dir::new();
        assert_eq!(
            run(&Op::Mkdir {
                path: dir.path("d")
            }),
            Ok(Data::Done)
        );
        assert_eq!(
            err_name(run(&Op::Mkdir {
                path: dir.path("d")
            })),
            "EEXIST"
        );
        fs::write(dir.path("b"), b"").unwrap();
        fs::write(dir.path("a"), b"").unwrap();
        let list = || run(&Op::List { path: dir.path("") });
        assert_eq!(
            list(),
            Ok(Data::List(vec!["a".into(), "b".into(), "d".into()]))
        );

        let rename = Op::Rename {
            from: dir.path("a"),
            to: dir.path("d/c"),
        };
        assert_eq!(run(&rename), Ok(Data::Done));
        assert_eq!(list(), Ok(Data::List(vec!["b".into(), "d".into()])));
        assert_eq!(
            err_name(run(&Op::Remove {
                path: dir.path("d")
            })),
            "ENOTEMPTY"
        );
        assert_eq!(
            run(&Op::Remove {
                path: dir.path("d/c")
            }),
            Ok(Data::Done)
        );
        assert_eq!(
            run(&Op::Remove {
                path: dir.path("d")
            }),
            Ok(Data::Done)
        );
        assert_eq!(list(), Ok(Data::List(vec!["b".into()])));
        assert_eq!(
            err_name(run(&Op::Remove {
                path: dir.path("d")
            })),
            "ENOENT"
        );
    }

    #[test]
    fn remove_unlinks_a_link_to_a_directory_not_the_directory() {
        let dir = Dir::new();
        fs::create_dir(dir.path("d")).unwrap();
        symlink("d", dir.path("link")).unwrap();
        assert_eq!(
            run(&Op::Remove {
                path: dir.path("link")
            }),
            Ok(Data::Done)
        );
        assert!(fs::symlink_metadata(dir.path("d")).unwrap().is_dir());
    }

    #[test]
    fn symlink_readlink_roundtrip() {
        let dir = Dir::new();
        let op = Op::Symlink {
            target: "../somewhere/else".into(),
            link: dir.path("l"),
        };
        assert_eq!(run(&op), Ok(Data::Done));
        assert_eq!(
            run(&Op::Readlink {
                path: dir.path("l")
            }),
            Ok(Data::Readlink("../somewhere/else".into()))
        );
        assert_eq!(err_name(run(&op)), "EEXIST");
        fs::write(dir.path("f"), b"").unwrap();
        assert_eq!(
            err_name(run(&Op::Readlink {
                path: dir.path("f")
            })),
            "EINVAL"
        );
    }

    #[test]
    fn failures_carry_errno_name_and_message() {
        let dir = Dir::new();
        let err = run(&Op::Read {
            path: dir.path("missing"),
        })
        .unwrap_err();
        assert_eq!(err.errno, Some(Errno::NOENT.raw_os_error()));
        assert_eq!(err.name.as_deref(), Some("ENOENT"));
        assert!(!err.message.is_empty());
        fs::write(dir.path("f"), b"").unwrap();
        assert_eq!(
            err_name(run(&Op::List {
                path: dir.path("f")
            })),
            "ENOTDIR"
        );
        assert_eq!(err_name(run(&Op::Read { path: dir.path("") })), "EISDIR");
    }

    #[test]
    fn unknown_errno_has_no_name() {
        assert_eq!(errno_name(Errno::NOENT.raw_os_error()), Some("ENOENT"));
        assert_eq!(errno_name(0), None);
        assert_eq!(errno_name(100_000), None);
        let err = op_error(io::Error::other("not an OS error"));
        assert_eq!(err.errno, None);
        assert_eq!(err.name, None);
        assert_eq!(err.message, "not an OS error");
    }

    #[test]
    fn process_state() {
        let Ok(Data::Ids(ids)) = run(&Op::Ids) else {
            panic!("ids failed")
        };
        assert_eq!(ids.pid, std::process::id());
        assert_eq!(ids.uid, rustix::process::getuid().as_raw());
        assert_eq!(ids.gid, rustix::process::getgid().as_raw());
        assert_eq!(
            run(&Op::Cwd),
            Ok(Data::Cwd(
                std::env::current_dir().unwrap().to_str().unwrap().into()
            ))
        );
        let Ok(Data::Env(env)) = run(&Op::Env) else {
            panic!("env failed")
        };
        assert_eq!(env.len(), std::env::vars_os().count());
        let Ok(Data::Argv(argv)) = run(&Op::Argv) else {
            panic!("argv failed")
        };
        assert_eq!(argv.len(), std::env::args_os().count());
        let Ok(Data::Mounts(mounts)) = run(&Op::Mounts) else {
            panic!("mounts failed")
        };
        assert!(mounts.contains(" / "), "{mounts}");
    }

    #[test]
    fn exec_reports_status_and_output() {
        let Ok(Data::Exec(out)) = run(&Op::Exec {
            path: "/proc/self/exe".into(),
            args: vec![
                "--list".into(),
                "--exact".into(),
                "tests::process_state".into(),
            ],
            stdin: Some("ignored".into()),
        }) else {
            panic!("exec failed")
        };
        assert_eq!(out.code, Some(0), "{out:?}");
        assert_eq!(out.signal, None);
        assert!(out.stdout.contains("process_state"), "{out:?}");

        let dir = Dir::new();
        let missing = Op::Exec {
            path: dir.path("missing"),
            args: vec![],
            stdin: None,
        };
        assert_eq!(err_name(run(&missing)), "ENOENT");
    }

    #[test]
    fn wire_format() {
        let ops: Vec<Op> = serde_json::from_str(
            r#"[{"op": "stat", "path": "/a"},
                {"op": "stat_follow", "path": "/a"},
                {"op": "write", "path": "/a", "contents": "x"},
                {"op": "rename", "from": "/a", "to": "/b"},
                {"op": "symlink", "target": "t", "link": "/l"},
                {"op": "env"},
                {"op": "exec", "path": "/bin/true"},
                {"op": "lo_flags"},
                {"op": "tcp_loopback_roundtrip"},
                {"op": "connect_abstract", "name": "sock"},
                {"op": "socket", "domain": 1, "ty": 1, "protocol": 0},
                {"op": "syscall", "call": "clone3"}]"#,
        )
        .unwrap();
        assert_eq!(ops[1], Op::StatFollow { path: "/a".into() });
        assert_eq!(ops[5], Op::Env);
        assert_eq!(
            ops[6],
            Op::Exec {
                path: "/bin/true".into(),
                args: vec![],
                stdin: None,
            }
        );
        assert_eq!(ops[7], Op::LoFlags);
        assert_eq!(ops[8], Op::TcpLoopbackRoundtrip);
        assert_eq!(
            ops[9],
            Op::ConnectAbstract {
                name: "sock".into()
            }
        );
        assert_eq!(
            ops[10],
            Op::Socket {
                domain: 1,
                ty: 1,
                protocol: 0,
            }
        );
        assert_eq!(
            ops[11],
            Op::Syscall {
                call: SyscallProbe::Clone3,
            }
        );
        // Typos are errors, not silently ignored fields.
        assert!(serde_json::from_str::<Op>(r#"{"op": "stat", "pth": "/a"}"#).is_err());
        assert!(serde_json::from_str::<Op>(r#"{"op": "frobnicate"}"#).is_err());

        let results: Vec<OpResult> = vec![
            Ok(Data::Done),
            Ok(Data::Readlink("t".into())),
            Ok(Data::Flags(0x49)),
            Err(OpError {
                errno: Some(2),
                name: Some("ENOENT".into()),
                message: "No such file or directory".into(),
            }),
        ];
        let json = serde_json::to_string(&results).unwrap();
        assert_eq!(
            json,
            r#"[{"Ok":"done"},{"Ok":{"readlink":"t"}},{"Ok":{"flags":73}},{"Err":{"errno":2,"name":"ENOENT","message":"No such file or directory"}}]"#
        );
        assert_eq!(
            serde_json::from_str::<Vec<OpResult>>(&json).unwrap(),
            results
        );
    }
}
