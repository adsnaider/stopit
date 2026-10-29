//! The shim trampoline (DESIGN.md §7.1): a tiny static program that every
//! shim in `/run/stopit/bin` links to. It needs no loader and no library,
//! so it runs in any sandbox. It turns `<name> <args...>` into
//! `<prefix...> __shim <name> -- <args...>` and executes that, where the
//! prefix runs the provisioned stopit (`/run/stopit/lib/<interp>
//! --library-path /run/stopit/lib /run/stopit/stopit`, or
//! `/run/stopit/stopit` alone for a static build).
//!
//! stopit writes the prefix over [`MARKER`] in [`PREFIX`] of its copy when
//! it provisions a session: arguments ending with NUL, then an empty one.
//! The program has no allocator, no unwinding and no `std`. It talks to
//! the kernel with raw system calls.

#![no_std]
#![no_main]

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("the shim trampoline supports x86_64 and aarch64 only");

use core::arch::global_asm;

/// What [`PREFIX`] starts with until stopit fills it in.
const MARKER: &[u8; 24] = b"STOPIT-SHIM-PREFIX-V1\0\0\0";

/// The room for the prefix, marker included.
const PREFIX_LEN: usize = 4096;

#[used]
#[unsafe(no_mangle)]
static mut PREFIX: [u8; PREFIX_LEN] = {
    let mut buf = [0u8; PREFIX_LEN];
    let mut i = 0;
    while i < MARKER.len() {
        buf[i] = MARKER[i];
        i += 1;
    }
    buf
};

#[cfg(target_arch = "x86_64")]
global_asm!(
    ".globl _start",
    "_start:",
    "xor rbp, rbp",
    "mov rdi, rsp",
    "and rsp, -16",
    "call {main}",
    "ud2",
    main = sym main,
);

#[cfg(target_arch = "aarch64")]
global_asm!(
    ".globl _start",
    "_start:",
    "mov x29, xzr",
    "mov x30, xzr",
    "mov x0, sp",
    "and sp, x0, #-16",
    "bl {main}",
    "brk #0",
    main = sym main,
);

#[cfg(target_arch = "x86_64")]
mod sys {
    pub const WRITE: usize = 1;
    pub const MMAP: usize = 9;
    pub const EXECVE: usize = 59;
    pub const EXIT_GROUP: usize = 231;

    pub unsafe fn call3(n: usize, a: usize, b: usize, c: usize) -> isize {
        let ret: isize;
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") n as isize => ret,
                in("rdi") a, in("rsi") b, in("rdx") c,
                lateout("rcx") _, lateout("r11") _,
                options(nostack),
            );
        }
        ret
    }

    pub unsafe fn call6(n: usize, a: usize, b: usize, c: usize, d: usize, e: usize, f: usize) -> isize {
        let ret: isize;
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") n as isize => ret,
                in("rdi") a, in("rsi") b, in("rdx") c,
                in("r10") d, in("r8") e, in("r9") f,
                lateout("rcx") _, lateout("r11") _,
                options(nostack),
            );
        }
        ret
    }
}

#[cfg(target_arch = "aarch64")]
mod sys {
    pub const WRITE: usize = 64;
    pub const MMAP: usize = 222;
    pub const EXECVE: usize = 221;
    pub const EXIT_GROUP: usize = 94;

    pub unsafe fn call3(n: usize, a: usize, b: usize, c: usize) -> isize {
        let ret: isize;
        unsafe {
            core::arch::asm!(
                "svc 0",
                in("x8") n,
                inlateout("x0") a as isize => ret,
                in("x1") b, in("x2") c,
                options(nostack),
            );
        }
        ret
    }

    pub unsafe fn call6(n: usize, a: usize, b: usize, c: usize, d: usize, e: usize, f: usize) -> isize {
        let ret: isize;
        unsafe {
            core::arch::asm!(
                "svc 0",
                in("x8") n,
                inlateout("x0") a as isize => ret,
                in("x1") b, in("x2") c, in("x3") d, in("x4") e, in("x5") f,
                options(nostack),
            );
        }
        ret
    }
}

/// Writes `msg` to stderr and exits with 127, as a missing command does.
fn fail(msg: &[u8]) -> ! {
    unsafe {
        sys::call3(sys::WRITE, 2, msg.as_ptr() as usize, msg.len());
        sys::call3(sys::EXIT_GROUP, 127, 0, 0);
    }
    loop {}
}

/// The length of the NUL-terminated string at `s`. The volatile reads
/// keep the compiler from calling a C `strlen` instead, which there is
/// none of.
unsafe fn strlen(s: *const u8) -> usize {
    let mut n = 0;
    unsafe {
        while core::ptr::read_volatile(s.add(n)) != 0 {
            n += 1;
        }
    }
    n
}

/// The `AT_EXECFN` entry of the auxiliary vector: the path the program was
/// run as.
const AT_EXECFN: usize = 31;

unsafe extern "C" fn main(sp: *const usize) -> ! {
    unsafe {
        let argc = *sp;
        let argv = sp.add(1) as *const *const u8;
        let envp = sp.add(2 + argc) as *const *const u8;
        if argc == 0 {
            fail(b"stopit shim: no program name\n");
        }
        // The auxiliary vector follows the environment's NULL.
        let mut env_end = envp;
        while !(*env_end).is_null() {
            env_end = env_end.add(1);
        }
        let mut aux = env_end.add(1) as *const usize;
        let mut execfn: *const u8 = core::ptr::null();
        while *aux != 0 {
            if *aux == AT_EXECFN {
                execfn = *aux.add(1) as *const u8;
            }
            aux = aux.add(2);
        }
        // The shim's name: what follows the last `/` of the path it was run
        // as, which the caller cannot set apart from the file, unlike
        // `argv[0]`.
        let arg0 = if execfn.is_null() { *argv } else { execfn };
        let len = strlen(arg0);
        let mut start = 0;
        let mut i = 0;
        while i < len {
            if *arg0.add(i) == b'/' {
                start = i + 1;
            }
            i += 1;
        }
        let name = arg0.add(start);

        // A provisioned prefix runs a program by its absolute path, so it
        // starts with `/`, which the marker does not. Comparing against the
        // whole marker would put a second copy of it into the program, and
        // stopit looks for the one in `PREFIX`.
        let prefix = core::ptr::addr_of!(PREFIX) as *const u8;
        if core::ptr::read_volatile(prefix) != b'/' {
            fail(b"stopit shim: this copy was never provisioned\n");
        }
        // Count the prefix's arguments.
        let mut count = 0;
        let mut at = 0;
        while at < PREFIX_LEN && *prefix.add(at) != 0 {
            at += strlen(prefix.add(at)) + 1;
            count += 1;
        }
        // prefix, "__shim", name, "--", the arguments, NULL.
        let slots = count + 3 + (argc - 1) + 1;
        let bytes = slots * core::mem::size_of::<usize>();
        // PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS.
        let mem = sys::call6(sys::MMAP, 0, bytes, 3, 0x22, usize::MAX, 0);
        if mem < 0 {
            fail(b"stopit shim: out of memory\n");
        }
        let out = mem as *mut *const u8;
        let mut n = 0;
        let mut at = 0;
        while at < PREFIX_LEN && *prefix.add(at) != 0 {
            *out.add(n) = prefix.add(at);
            n += 1;
            at += strlen(prefix.add(at)) + 1;
        }
        *out.add(n) = b"__shim\0".as_ptr();
        *out.add(n + 1) = name;
        *out.add(n + 2) = b"--\0".as_ptr();
        n += 3;
        // Volatile writes, so the compiler calls no `memcpy`, which there
        // is none of.
        let mut i = 1;
        while i < argc {
            core::ptr::write_volatile(out.add(n), *argv.add(i));
            n += 1;
            i += 1;
        }
        *out.add(n) = core::ptr::null();
        sys::call3(sys::EXECVE, *out as usize, out as usize, envp as usize);
        fail(b"stopit shim: cannot run stopit\n")
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    fail(b"stopit shim: panic\n")
}
