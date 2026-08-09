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

use crate::cpu::Cpu;
use crate::libc::errno::ENOSYS;
use crate::mem::{GuestUSize, MutPtr, MutVoidPtr, Ptr};
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

/// `__sysctl`, from XNU's `syscalls.master`.
const SYS_SYSCTL: u32 = 202;

/// The CPSR carry flag. Darwin's syscall convention sets it when `r0` holds an
/// `errno` instead of a result.
const CPSR_CARRY: u32 = 1 << 29;

/// Perform the system call the guest asked for with `svc #0x80`.
///
/// The program counter is already past the instruction when this is called,
/// which is what a real syscall does and what stops the guest from asking
/// again forever.
pub fn handle_darwin_syscall(env: &mut Environment, svc_pc: u32) {
    let number = env.cpu.regs()[12];
    match number {
        SYS_SYSCTL => {
            // int __sysctl(int *name, u_int namelen, void *oldp,
            //              size_t *oldlenp, void *newp, size_t newlen);
            // Four arguments in registers, the last two just above the stack
            // pointer.
            let regs = *env.cpu.regs();
            let sp: MutPtr<u32> = Ptr::from_bits(regs[Cpu::SP]);
            let newp: MutVoidPtr = Ptr::from_bits(env.mem.read(sp));
            let newlen: GuestUSize = env.mem.read(sp + 1);
            let result = crate::libc::sysctl::sysctl(
                env,
                Ptr::from_bits(regs[0]),
                regs[1],
                Ptr::from_bits(regs[2]),
                Ptr::from_bits(regs[3]),
                newp,
                newlen,
            );
            finish(env, result);
        }
        _ => {
            log_unimplemented(svc_pc, number);
            // Report failure rather than success: a caller told its call
            // succeeded goes on to use a result that was never written.
            fail(env, ENOSYS);
        }
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
