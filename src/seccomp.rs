//! Seccomp-BPF syscall filter for `stopit __init`.
//!
//! `__init` installs this classic BPF filter right before resetting signals and
//! calling `execve`. The filter enforces the target architecture, rejects x32
//! syscalls on `x86_64`, returns `ENOSYS` for `clone3` so libc falls back to
//! `clone`, blocks namespace and mount syscalls, blocks terminal input
//! injection ioctls, restricts `socket` families, and gates the six opt-in
//! syscall groups on `sandbox.allow_syscalls`.

use std::collections::BTreeSet;
use std::io;

use crate::manifest::OptInSyscall;

#[cfg(not(target_endian = "little"))]
compile_error!("seccomp filter requires a little-endian target");

#[cfg(target_arch = "x86_64")]
const EXPECTED_ARCH: u32 = 0xc000_003e;

#[cfg(target_arch = "aarch64")]
const EXPECTED_ARCH: u32 = 0xc000_00b7;

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("seccomp filter supports only x86_64 and aarch64");

#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;

pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

pub const RET_EPERM: u32 = SECCOMP_RET_ERRNO | (libc::EPERM as u32);
pub const RET_ENOSYS: u32 = SECCOMP_RET_ERRNO | (libc::ENOSYS as u32);

// Offsets inside `struct seccomp_data` on little-endian 64-bit Linux.
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;
const OFF_ARG0_LO: u32 = 16;
const OFF_ARG1_LO: u32 = 24;
const OFF_ARG2_LO: u32 = 32;

// Classic BPF opcodes (`<linux/filter.h>`).
const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
#[cfg(target_arch = "x86_64")]
const BPF_JMP_JGE_K: u16 = 0x35;
const BPF_JMP_JSET_K: u16 = 0x45;
const BPF_RET_K: u16 = 0x06;

/// Namespace creation flags in `clone`'s first argument. The low byte of
/// `clone` flags is `exit_signal`, so `CLONE_NEWTIME` (`0x80`) is excluded.
pub const CLONE_NS_MASK: u32 = (libc::CLONE_NEWNS
    | libc::CLONE_NEWCGROUP
    | libc::CLONE_NEWUTS
    | libc::CLONE_NEWIPC
    | libc::CLONE_NEWUSER
    | libc::CLONE_NEWPID
    | libc::CLONE_NEWNET) as u32;

const _: () = assert!(CLONE_NS_MASK == 0x7e02_0000);
const _: () = assert!(CLONE_NS_MASK & 0xff == 0);

const TIOCSTI_CMD: u32 = 0x5412;
const TIOCLINUX_CMD: u32 = 0x541c;

/// Kernel `struct sock_filter`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

const _: () = assert!(std::mem::size_of::<SockFilter>() == 8);

/// Kernel `struct sock_fprog`.
#[repr(C)]
struct SockFprog {
    len: libc::c_ushort,
    filter: *const SockFilter,
}

const fn stmt(code: u16, k: u32) -> SockFilter {
    SockFilter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

const fn sys_nr(nr: libc::c_long) -> u32 {
    nr as u32
}

/// Builds the classic BPF program for a sandbox with `allow_syscalls`.
pub fn build_filter(allow_syscalls: &BTreeSet<OptInSyscall>) -> Vec<SockFilter> {
    let mut prog = Vec::with_capacity(64);

    // 1. Kill the process if the syscall architecture does not match.
    prog.push(stmt(BPF_LD_W_ABS, OFF_ARCH));
    prog.push(jump(BPF_JMP_JEQ_K, EXPECTED_ARCH, 1, 0));
    prog.push(stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS));

    // Load `seccomp_data.nr` once for the dispatch chain below.
    prog.push(stmt(BPF_LD_W_ABS, OFF_NR));

    // 2. Block the x32 ABI bit on x86_64.
    #[cfg(target_arch = "x86_64")]
    {
        prog.push(jump(BPF_JMP_JGE_K, X32_SYSCALL_BIT, 0, 1));
        prog.push(stmt(BPF_RET_K, RET_EPERM));
    }

    // 3. Return ENOSYS for `clone3` so glibc falls back to `clone`.
    prog.push(jump(BPF_JMP_JEQ_K, sys_nr(libc::SYS_clone3), 0, 1));
    prog.push(stmt(BPF_RET_K, RET_ENOSYS));

    // 4a, 5, 6, 7. Syscalls denied unconditionally with EPERM.
    let denied = denied_syscalls(allow_syscalls);
    debug_assert!(!denied.is_empty());
    assert!(denied.len() <= usize::from(u8::MAX));
    let n = denied.len();
    for (idx, nr) in denied.into_iter().enumerate() {
        if idx + 1 < n {
            let jt = u8::try_from(n - 1 - idx).expect("denied list fits in u8");
            prog.push(jump(BPF_JMP_JEQ_K, nr, jt, 0));
        } else {
            prog.push(jump(BPF_JMP_JEQ_K, nr, 0, 1));
        }
    }
    prog.push(stmt(BPF_RET_K, RET_EPERM));

    // 4b. Inspect `clone` flags for namespace creation bits.
    prog.push(jump(BPF_JMP_JEQ_K, sys_nr(libc::SYS_clone), 0, 4));
    prog.push(stmt(BPF_LD_W_ABS, OFF_ARG0_LO));
    prog.push(jump(BPF_JMP_JSET_K, CLONE_NS_MASK, 0, 1));
    prog.push(stmt(BPF_RET_K, RET_EPERM));
    prog.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));

    // 8. Block `TIOCSTI` and `TIOCLINUX` on the low 32 bits of `ioctl` cmd.
    prog.push(jump(BPF_JMP_JEQ_K, sys_nr(libc::SYS_ioctl), 0, 5));
    prog.push(stmt(BPF_LD_W_ABS, OFF_ARG1_LO));
    prog.push(jump(BPF_JMP_JEQ_K, TIOCSTI_CMD, 1, 0));
    prog.push(jump(BPF_JMP_JEQ_K, TIOCLINUX_CMD, 0, 1));
    prog.push(stmt(BPF_RET_K, RET_EPERM));
    prog.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));

    // 9. Restrict `socket` domains and netlink protocols.
    prog.push(jump(BPF_JMP_JEQ_K, sys_nr(libc::SYS_socket), 0, 9));
    prog.push(stmt(BPF_LD_W_ABS, OFF_ARG0_LO));
    prog.push(jump(BPF_JMP_JEQ_K, libc::AF_UNIX as u32, 5, 0));
    prog.push(jump(BPF_JMP_JEQ_K, libc::AF_INET as u32, 4, 0));
    prog.push(jump(BPF_JMP_JEQ_K, libc::AF_INET6 as u32, 3, 0));
    prog.push(jump(BPF_JMP_JEQ_K, libc::AF_NETLINK as u32, 0, 3));
    prog.push(stmt(BPF_LD_W_ABS, OFF_ARG2_LO));
    prog.push(jump(BPF_JMP_JEQ_K, libc::NETLINK_ROUTE as u32, 0, 1));
    prog.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));
    prog.push(stmt(BPF_RET_K, RET_EPERM));

    // 10. Allow every other syscall.
    prog.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));

    prog
}

fn denied_syscalls(allow_syscalls: &BTreeSet<OptInSyscall>) -> Vec<u32> {
    let mut list = vec![
        // Namespace switching and unsharing.
        sys_nr(libc::SYS_unshare),
        sys_nr(libc::SYS_setns),
        // Mount table modification and new mount API.
        sys_nr(libc::SYS_mount),
        sys_nr(libc::SYS_umount2),
        sys_nr(libc::SYS_pivot_root),
        sys_nr(libc::SYS_fsopen),
        sys_nr(libc::SYS_fsconfig),
        sys_nr(libc::SYS_fsmount),
        sys_nr(libc::SYS_fspick),
        sys_nr(libc::SYS_open_tree),
        sys_nr(libc::SYS_move_mount),
        sys_nr(libc::SYS_mount_setattr),
        // Kernel image replacement and mount-bypassing file handle opens.
        sys_nr(libc::SYS_kexec_load),
        sys_nr(libc::SYS_kexec_file_load),
        sys_nr(libc::SYS_open_by_handle_at),
    ];

    if !allow_syscalls.contains(&OptInSyscall::Ptrace) {
        list.push(sys_nr(libc::SYS_ptrace));
    }
    if !allow_syscalls.contains(&OptInSyscall::PerfEventOpen) {
        list.push(sys_nr(libc::SYS_perf_event_open));
    }
    if !allow_syscalls.contains(&OptInSyscall::IoUring) {
        list.push(sys_nr(libc::SYS_io_uring_setup));
        list.push(sys_nr(libc::SYS_io_uring_enter));
        list.push(sys_nr(libc::SYS_io_uring_register));
    }
    if !allow_syscalls.contains(&OptInSyscall::Userfaultfd) {
        list.push(sys_nr(libc::SYS_userfaultfd));
    }
    if !allow_syscalls.contains(&OptInSyscall::Bpf) {
        list.push(sys_nr(libc::SYS_bpf));
    }
    if !allow_syscalls.contains(&OptInSyscall::Keyctl) {
        list.push(sys_nr(libc::SYS_keyctl));
        list.push(sys_nr(libc::SYS_add_key));
        list.push(sys_nr(libc::SYS_request_key));
    }

    list
}

/// Installs the seccomp filter for `allow_syscalls` on the calling thread.
///
/// The caller must set `PR_SET_NO_NEW_PRIVS` before calling `install`.
pub fn install(allow_syscalls: &BTreeSet<OptInSyscall>) -> io::Result<()> {
    let filter = build_filter(allow_syscalls);
    let len = libc::c_ushort::try_from(filter.len())
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    let prog = SockFprog {
        len,
        filter: filter.as_ptr(),
    };
    // SAFETY: `prog` points to `filter`, which stays valid for the duration of
    // the syscall.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            0 as libc::c_uint,
            &prog as *const SockFprog,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Kernel `struct seccomp_data` layout for the pure-Rust BPF interpreter.
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct SeccompData {
        nr: i32,
        arch: u32,
        instruction_pointer: u64,
        args: [u64; 6],
    }

    const _: () = assert!(std::mem::size_of::<SeccompData>() == 64);

    fn validate_and_eval(prog: &[SockFilter], data: &SeccompData) -> u32 {
        assert!(!prog.is_empty(), "empty BPF program");
        assert_eq!(prog.last().unwrap().code, BPF_RET_K);

        let raw: &[u8; 64] = unsafe { &*(data as *const SeccompData as *const [u8; 64]) };

        for (pc, insn) in prog.iter().enumerate() {
            match insn.code {
                BPF_LD_W_ABS => {
                    assert_eq!(insn.k % 4, 0, "unaligned load at pc {pc}");
                    assert!((insn.k as usize) + 4 <= raw.len(), "oob load at pc {pc}");
                }
                BPF_JMP_JEQ_K | BPF_JMP_JSET_K => {
                    assert!(pc + 1 + usize::from(insn.jt) < prog.len(), "oob jt at {pc}");
                    assert!(pc + 1 + usize::from(insn.jf) < prog.len(), "oob jf at {pc}");
                }
                #[cfg(target_arch = "x86_64")]
                BPF_JMP_JGE_K => {
                    assert!(pc + 1 + usize::from(insn.jt) < prog.len(), "oob jt at {pc}");
                    assert!(pc + 1 + usize::from(insn.jf) < prog.len(), "oob jf at {pc}");
                }
                BPF_RET_K => {}
                other => panic!("unexpected BPF opcode {other:#x} at pc {pc}"),
            }
        }

        let mut pc = 0usize;
        let mut acc = 0u32;
        while pc < prog.len() {
            let insn = prog[pc];
            match insn.code {
                BPF_LD_W_ABS => {
                    let off = insn.k as usize;
                    acc = u32::from_le_bytes(raw[off..off + 4].try_into().unwrap());
                    pc += 1;
                }
                BPF_JMP_JEQ_K => {
                    let step = if acc == insn.k { insn.jt } else { insn.jf };
                    pc += 1 + usize::from(step);
                }
                #[cfg(target_arch = "x86_64")]
                BPF_JMP_JGE_K => {
                    let step = if acc >= insn.k { insn.jt } else { insn.jf };
                    pc += 1 + usize::from(step);
                }
                BPF_JMP_JSET_K => {
                    let step = if (acc & insn.k) != 0 {
                        insn.jt
                    } else {
                        insn.jf
                    };
                    pc += 1 + usize::from(step);
                }
                BPF_RET_K => return insn.k,
                _ => unreachable!(),
            }
        }
        panic!("BPF execution fell off the end");
    }

    fn call(nr: libc::c_long, args: [u64; 6]) -> SeccompData {
        SeccompData {
            nr: nr as i32,
            arch: EXPECTED_ARCH,
            instruction_pointer: 0x7fff_0000_1000,
            args,
        }
    }

    #[test]
    fn wrong_architecture_kills_process() {
        let prog = build_filter(&BTreeSet::new());
        for bad_arch in [0, 0x4000_0003, EXPECTED_ARCH ^ 1] {
            let data = SeccompData {
                nr: libc::SYS_read as i32,
                arch: bad_arch,
                instruction_pointer: 0,
                args: [0; 6],
            };
            assert_eq!(validate_and_eval(&prog, &data), SECCOMP_RET_KILL_PROCESS);
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn x32_syscall_bit_is_rejected_with_eperm() {
        let prog = build_filter(&BTreeSet::new());
        for raw_nr in [
            X32_SYSCALL_BIT,
            X32_SYSCALL_BIT | (libc::SYS_read as u32),
            X32_SYSCALL_BIT | (libc::SYS_mount as u32),
            u32::MAX,
        ] {
            let data = SeccompData {
                nr: raw_nr as i32,
                arch: EXPECTED_ARCH,
                instruction_pointer: 0,
                args: [0; 6],
            };
            assert_eq!(validate_and_eval(&prog, &data), RET_EPERM, "{raw_nr:#x}");
        }
    }

    #[test]
    fn clone3_returns_enosys_and_clone_filters_namespace_flags() {
        let prog = build_filter(&BTreeSet::new());
        assert_eq!(
            validate_and_eval(&prog, &call(libc::SYS_clone3, [0; 6])),
            RET_ENOSYS
        );
        assert_eq!(
            validate_and_eval(&prog, &call(libc::SYS_unshare, [0; 6])),
            RET_EPERM
        );
        assert_eq!(
            validate_and_eval(&prog, &call(libc::SYS_setns, [0; 6])),
            RET_EPERM
        );

        // Normal fork and thread creation flags pass, including 0x80 in the
        // low exit-signal byte and arbitrary upper 32-bit garbage.
        for allowed_flags in [
            libc::SIGCHLD as u64,
            0x80u64,
            (libc::CLONE_VM
                | libc::CLONE_FS
                | libc::CLONE_FILES
                | libc::CLONE_SIGHAND
                | libc::CLONE_THREAD
                | libc::CLONE_SYSVSEM) as u64,
            (1u64 << 40) | (libc::SIGCHLD as u64),
        ] {
            assert_eq!(
                validate_and_eval(
                    &prog,
                    &call(libc::SYS_clone, [allowed_flags, 0, 0, 0, 0, 0])
                ),
                SECCOMP_RET_ALLOW,
                "flags {allowed_flags:#x}"
            );
        }

        for ns_flag in [
            libc::CLONE_NEWNS,
            libc::CLONE_NEWCGROUP,
            libc::CLONE_NEWUTS,
            libc::CLONE_NEWIPC,
            libc::CLONE_NEWUSER,
            libc::CLONE_NEWPID,
            libc::CLONE_NEWNET,
        ] {
            let flags = (1u64 << 35) | (ns_flag as u64) | (libc::SIGCHLD as u64);
            assert_eq!(
                validate_and_eval(&prog, &call(libc::SYS_clone, [flags, 0, 0, 0, 0, 0])),
                RET_EPERM,
                "ns_flag {ns_flag:#x}"
            );
        }
    }

    #[test]
    fn mount_and_kernel_integrity_syscalls_are_always_denied() {
        let all_opt_ins: BTreeSet<OptInSyscall> = [
            OptInSyscall::Ptrace,
            OptInSyscall::PerfEventOpen,
            OptInSyscall::IoUring,
            OptInSyscall::Userfaultfd,
            OptInSyscall::Bpf,
            OptInSyscall::Keyctl,
        ]
        .into_iter()
        .collect();
        let prog = build_filter(&all_opt_ins);

        for nr in [
            libc::SYS_mount,
            libc::SYS_umount2,
            libc::SYS_pivot_root,
            libc::SYS_fsopen,
            libc::SYS_fsconfig,
            libc::SYS_fsmount,
            libc::SYS_fspick,
            libc::SYS_open_tree,
            libc::SYS_move_mount,
            libc::SYS_mount_setattr,
            libc::SYS_kexec_load,
            libc::SYS_kexec_file_load,
            libc::SYS_open_by_handle_at,
            libc::SYS_unshare,
            libc::SYS_setns,
        ] {
            assert_eq!(
                validate_and_eval(&prog, &call(nr, [0; 6])),
                RET_EPERM,
                "syscall {nr}"
            );
        }
    }

    #[test]
    fn opt_in_syscall_groups_toggle_independently() {
        let groups: &[(OptInSyscall, &[libc::c_long])] = &[
            (OptInSyscall::Ptrace, &[libc::SYS_ptrace]),
            (OptInSyscall::PerfEventOpen, &[libc::SYS_perf_event_open]),
            (
                OptInSyscall::IoUring,
                &[
                    libc::SYS_io_uring_setup,
                    libc::SYS_io_uring_enter,
                    libc::SYS_io_uring_register,
                ],
            ),
            (OptInSyscall::Userfaultfd, &[libc::SYS_userfaultfd]),
            (OptInSyscall::Bpf, &[libc::SYS_bpf]),
            (
                OptInSyscall::Keyctl,
                &[libc::SYS_keyctl, libc::SYS_add_key, libc::SYS_request_key],
            ),
        ];

        let default_prog = build_filter(&BTreeSet::new());
        for (_, nrs) in groups {
            for &nr in *nrs {
                assert_eq!(
                    validate_and_eval(&default_prog, &call(nr, [0; 6])),
                    RET_EPERM
                );
            }
        }

        for (enabled, enabled_nrs) in groups {
            let allow = BTreeSet::from([*enabled]);
            let prog = build_filter(&allow);
            for &nr in *enabled_nrs {
                assert_eq!(
                    validate_and_eval(&prog, &call(nr, [0; 6])),
                    SECCOMP_RET_ALLOW,
                    "{enabled} -> {nr}"
                );
            }
            for (other, other_nrs) in groups {
                if other != enabled {
                    for &nr in *other_nrs {
                        assert_eq!(
                            validate_and_eval(&prog, &call(nr, [0; 6])),
                            RET_EPERM,
                            "{enabled} should not allow {other} ({nr})"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn ioctl_blocks_tiocsti_and_tioclinux_including_high_bit_stuffing() {
        let prog = build_filter(&BTreeSet::new());
        for cmd in [
            u64::from(TIOCSTI_CMD),
            u64::from(TIOCLINUX_CMD),
            (1u64 << 32) | u64::from(TIOCSTI_CMD),
            (0xdead_beef_u64 << 32) | u64::from(TIOCLINUX_CMD),
        ] {
            assert_eq!(
                validate_and_eval(&prog, &call(libc::SYS_ioctl, [0, cmd, 0, 0, 0, 0])),
                RET_EPERM,
                "cmd {cmd:#x}"
            );
        }

        for safe_cmd in [libc::TCGETS, libc::TIOCGWINSZ, libc::FIONBIO] {
            assert_eq!(
                validate_and_eval(&prog, &call(libc::SYS_ioctl, [0, safe_cmd, 0, 0, 0, 0])),
                SECCOMP_RET_ALLOW
            );
        }
    }

    #[test]
    fn socket_allows_unix_inet_inet6_and_netlink_route_only() {
        let prog = build_filter(&BTreeSet::new());

        for domain in [libc::AF_UNIX, libc::AF_INET, libc::AF_INET6] {
            assert_eq!(
                validate_and_eval(
                    &prog,
                    &call(
                        libc::SYS_socket,
                        [domain as u64, libc::SOCK_STREAM as u64, 0, 0, 0, 0]
                    )
                ),
                SECCOMP_RET_ALLOW
            );
        }

        assert_eq!(
            validate_and_eval(
                &prog,
                &call(
                    libc::SYS_socket,
                    [
                        libc::AF_NETLINK as u64,
                        libc::SOCK_RAW as u64,
                        libc::NETLINK_ROUTE as u64,
                        0,
                        0,
                        0
                    ]
                )
            ),
            SECCOMP_RET_ALLOW
        );

        for bad_proto in [
            libc::NETLINK_USERSOCK as u64,
            libc::NETLINK_AUDIT as u64,
            libc::NETLINK_KOBJECT_UEVENT as u64,
            (1u64 << 32) | 1,
        ] {
            assert_eq!(
                validate_and_eval(
                    &prog,
                    &call(
                        libc::SYS_socket,
                        [
                            libc::AF_NETLINK as u64,
                            libc::SOCK_RAW as u64,
                            bad_proto,
                            0,
                            0,
                            0
                        ]
                    )
                ),
                RET_EPERM
            );
        }

        for bad_domain in [
            0u64,
            libc::AF_PACKET as u64,
            libc::AF_VSOCK as u64,
            libc::AF_KEY as u64,
            (1u64 << 32) | (libc::AF_VSOCK as u64),
        ] {
            assert_eq!(
                validate_and_eval(
                    &prog,
                    &call(
                        libc::SYS_socket,
                        [bad_domain, libc::SOCK_STREAM as u64, 0, 0, 0, 0]
                    )
                ),
                RET_EPERM,
                "domain {bad_domain:#x}"
            );
        }
    }

    #[test]
    fn ordinary_syscalls_are_allowed() {
        let prog = build_filter(&BTreeSet::new());
        for nr in [
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_openat,
            libc::SYS_close,
            libc::SYS_mmap,
            libc::SYS_futex,
            libc::SYS_execve,
            libc::SYS_exit_group,
        ] {
            assert_eq!(
                validate_and_eval(&prog, &call(nr, [0; 6])),
                SECCOMP_RET_ALLOW
            );
        }
    }
}
