/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
//! Raw Darwin system calls — `svc #0x80`.
//!
//! Almost every app reaches the kernel through libc, and touchHLE meets it
//! there: `sysctl`, `open`, `read` and the rest are host functions linked in
//! place of the real ones. Some apps skip libc and issue the instruction
//! themselves, and those arrive here instead.
//!
//! The ARM calling convention Darwin uses for this is: the syscall number in
//! `r12`, the arguments where a normal call would put them (`r0`–`r3`, then
//! the stack), the result in `r0`, and the carry flag set to say the result is
//! an `errno` rather than a value.
//!
//! Disney Infinity 1 is why this exists. It asks for `__sysctl` this way, and
//! before this the instruction did nothing at all and execution resumed *on
//! the same instruction*, so it asked again — 4,294,967,296 times in 177
//! seconds, without ever drawing a frame.
//!
//! The calls implemented here are the ones apps inline rather than link, which
//! is a short and fairly predictable list: the checks that ask whether anyone
//! is watching (`__sysctl` for `p_flag`, `ptrace(PT_DENY_ATTACH)`,
//! `issetugid`), and the handful of file and time calls that turn up in code
//! that was written not to depend on libc. Each is the same host function the
//! linked entry point uses, so nothing here is a second implementation of
//! anything — only a second doorway to one.
//!
//! Anything else is named in the log with its number and failed with `ENOSYS`,
//! which is enough to add it: the numbers are XNU's `syscalls.master`.

use crate::cpu::Cpu;
use crate::libc::errno::ENOSYS;
use crate::mem::{ConstPtr, ConstVoidPtr, GuestUSize, MutPtr, MutVoidPtr, Ptr};
use crate::Environment;

/// `svc #0x80`, the instruction Darwin uses for a system call.
///
/// It falls inside the range touchHLE hands out for its own host functions, so
/// only an SVC that has no host function behind it can be one of these. The
/// converse is not guaranteed: once an app has linked enough host functions to
/// reach the slot 128 would name, a raw syscall would call that function
/// instead. Nothing here can tell them apart, which is a reason to link the
/// syscalls an app needs rather than to rely on this path.
pub const DARWIN_SYSCALL_SVC: u32 = 0x80;

// Numbers from XNU's `bsd/kern/syscalls.master`.
const SYS_EXIT: u32 = 1;
const SYS_READ: u32 = 3;
const SYS_WRITE: u32 = 4;
const SYS_OPEN: u32 = 5;
const SYS_CLOSE: u32 = 6;
const SYS_GETPID: u32 = 20;
const SYS_PTRACE: u32 = 26;
const SYS_ACCESS: u32 = 33;
const SYS_GETEUID: u32 = 25;
const SYS_GETUID: u32 = 24;
const SYS_GETGID: u32 = 47;
const SYS_GETPPID: u32 = 39;
const SYS_GETTIMEOFDAY: u32 = 116;
const SYS_SYSCTL: u32 = 202;
const SYS_ISSETUGID: u32 = 327;

/// The CPSR carry flag. Darwin's syscall convention sets it when `r0` holds an
/// `errno` instead of a result.
const CPSR_CARRY: u32 = 1 << 29;

/// Perform the system call the guest asked for with `svc #0x80`.
///
/// The program counter is already past the instruction when this is called,
/// which is what a real syscall does and what stops the guest from asking
/// again forever.
pub fn handle_darwin_syscall(env: &mut Environment, svc_pc: u32) {
    let regs = *env.cpu.regs();
    let number = regs[12];
    match number {
        SYS_SYSCTL => {
            // int __sysctl(int *name, u_int namelen, void *oldp,
            //              size_t *oldlenp, void *newp, size_t newlen);
            let newp: MutVoidPtr = Ptr::from_bits(arg(env, &regs, 4));
            let newlen: GuestUSize = arg(env, &regs, 5);
            let result = crate::libc::sysctl::sysctl(
                env,
                Ptr::from_bits(regs[0]),
                regs[1],
                Ptr::from_bits(regs[2]),
                Ptr::from_bits(regs[3]),
                newp,
                newlen,
            );
            finish_libc(env, result);
        }
        SYS_OPEN => {
            // int open(const char *path, int flags, mode_t mode);
            // `open_direct` is the entry point that takes the mode as a real
            // argument rather than through a `...`, which is what a syscall
            // hands us — the mode itself goes unused either way.
            let path: ConstPtr<u8> = Ptr::from_bits(regs[0]);
            let result = crate::libc::posix_io::open_direct(env, path, regs[1] as i32);
            finish_libc(env, result);
        }
        SYS_CLOSE => {
            let result = crate::libc::posix_io::close(env, regs[0] as i32);
            finish_libc(env, result);
        }
        SYS_READ => {
            let buffer: MutVoidPtr = Ptr::from_bits(regs[1]);
            let result = crate::libc::posix_io::read(env, regs[0] as i32, buffer, regs[2]);
            finish_libc(env, result);
        }
        SYS_WRITE => {
            let buffer: ConstVoidPtr = Ptr::from_bits(regs[1]);
            let result = crate::libc::posix_io::write(env, regs[0] as i32, buffer, regs[2]);
            finish_libc(env, result);
        }
        SYS_ACCESS => {
            let path: ConstPtr<u8> = Ptr::from_bits(regs[0]);
            let result = crate::libc::unistd::access(env, path, regs[1] as i32);
            finish_libc(env, result);
        }
        SYS_GETTIMEOFDAY => {
            // The kernel's `gettimeofday` also returns the seconds in `r0`, and
            // libc's wrapper only falls back on the struct when it doesn't.
            // Filling the struct and returning zero is the shape every caller
            // handles, so that is what we do.
            let result = crate::libc::time::gettimeofday(
                env,
                Ptr::from_bits(regs[0]),
                Ptr::from_bits(regs[1]),
            );
            finish_libc(env, result);
        }
        SYS_PTRACE => {
            // The one request that matters is PT_DENY_ATTACH, which apps use to
            // refuse a debugger. The host function decides what to do about it.
            let addr: MutPtr<u8> = Ptr::from_bits(regs[2]);
            let result = crate::libc::sys::ptrace::ptrace(
                env,
                regs[0] as i32,
                regs[1] as i32,
                addr,
                regs[3] as i32,
            );
            finish_libc(env, result);
        }
        SYS_GETPID => {
            let pid = crate::libc::unistd::getpid(env);
            finish(env, pid);
        }
        SYS_GETPPID => {
            // The process that launched us. touchHLE runs one process and there
            // is nothing above it, so it is launchd's pid, as on a device.
            finish(env, 1);
        }
        // Not root, and not setuid — the answers a sandboxed app on a
        // non-jailbroken device gets, which is what code asking these questions
        // is checking for.
        SYS_GETUID | SYS_GETEUID => finish(env, 501),
        SYS_GETGID => finish(env, 501),
        SYS_ISSETUGID => finish(env, 0),
        SYS_EXIT => {
            // Does not return.
            crate::libc::stdlib::exit(env, regs[0] as i32);
        }
        _ => {
            log_unimplemented(svc_pc, number);
            // Report failure rather than success: a caller told its call
            // succeeded goes on to use a result that was never written.
            fail(env, ENOSYS);
        }
    }
}

/// The `n`th argument of a system call. The first four are in registers and
/// the rest sit just above the stack pointer, in order.
fn arg(env: &Environment, regs: &[u32; 16], n: usize) -> u32 {
    if n < 4 {
        regs[n]
    } else {
        let sp: MutPtr<u32> = Ptr::from_bits(regs[Cpu::SP]);
        env.mem.read(sp + (n - 4) as u32)
    }
}

/// Finish a call whose host implementation reports failure the way libc does:
/// -1, with the reason in `errno`.
///
/// A raw syscall reports it the kernel's way instead: the `errno` itself in
/// `r0`, with the carry flag set. Translating between the two is the whole
/// difference between the two entry points, and getting it wrong hands the
/// caller -1 as a *successful* result.
fn finish_libc(env: &mut Environment, result: i32) {
    if result == -1 {
        let errno = crate::libc::errno::get_errno(env);
        fail(env, errno);
    } else {
        finish(env, result);
    }
}

/// Return a result: `r0` holds it, and the carry flag is clear.
fn finish(env: &mut Environment, result: i32) {
    env.cpu.regs_mut()[0] = result as u32;
    let cpsr = env.cpu.cpsr() & !CPSR_CARRY;
    env.cpu.set_cpsr(cpsr);
}

/// Report failure: `r0` holds the `errno`, and the carry flag is set.
fn fail(env: &mut Environment, errno: i32) {
    env.cpu.regs_mut()[0] = errno as u32;
    let cpsr = env.cpu.cpsr() | CPSR_CARRY;
    env.cpu.set_cpsr(cpsr);
}

/// Name an unimplemented syscall once per site, so a guest that asks in a loop
/// cannot fill the log.
fn log_unimplemented(svc_pc: u32, number: u32) {
    use std::collections::HashSet;
    use std::sync::Mutex;
    static REPORTED: Mutex<Option<HashSet<(u32, u32)>>> = Mutex::new(None);
    let Ok(mut reported) = REPORTED.lock() else {
        return;
    };
    if reported
        .get_or_insert_with(HashSet::new)
        .insert((svc_pc, number))
    {
        log!(
            "Unimplemented Darwin syscall {} at {:#x}, called directly with `svc #0x80` rather \
             than through libc; failing it with ENOSYS. [this site will only be reported once]",
            number,
            svc_pc,
        );
    }
}
