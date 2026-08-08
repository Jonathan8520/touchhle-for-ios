/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use crate::dyld::FunctionExports;
use crate::environment::Environment;
use crate::export_c_func;
use crate::libc::errno::{set_errno, EINVAL, EIO, ENOMEM};
use crate::libc::posix_io;
use crate::libc::posix_io::{off_t, open_direct, FileDescriptor, SEEK_SET};
use crate::mem::{ConstPtr, GuestUSize, MutVoidPtr, PAGE_SIZE_ALIGN_MASK};
use std::collections::HashMap;

#[allow(dead_code)]
const MAP_FILE: i32 = 0x0000;
const MAP_ANON: i32 = 0x1000;

/// What `mmap` returns when it fails. Not NULL: a caller that checks for NULL
/// instead is the one making the mistake, but a caller that correctly checks
/// for `MAP_FAILED` and is handed NULL goes on to read from address zero.
const MAP_FAILED: u32 = 0xFFFF_FFFF;

#[derive(Default)]
pub struct State {
    /// Keeping track of `mmap` allocations
    allocations: HashMap<MutVoidPtr, GuestUSize>,
}

/// For files, our implementation of mmap is really simple:
/// it's just load entirety of file in memory!
fn mmap(
    env: &mut Environment,
    addr: MutVoidPtr,
    len: GuestUSize,
    prot: i32,
    flags: i32,
    fd: FileDescriptor,
    offset: off_t,
) -> MutVoidPtr {
    // TODO: handle errno properly
    set_errno(env, 0);
    log_dbg!(
        "mmap({:?}, {}, {}, {}, {}, {})",
        addr,
        len,
        prot,
        flags,
        fd,
        offset
    );

    // TODO: use vm_allocate() instead
    let ptr = env.mem.calloc(len);
    if ptr.is_null() {
        // Handing back NULL here told a caller checking against MAP_FAILED
        // that the mapping had succeeded, and it then read from address zero.
        log!(
            "Warning: mmap: could not allocate {} bytes for the mapping; returning MAP_FAILED",
            len
        );
        set_errno(env, ENOMEM);
        return MutVoidPtr::from_bits(MAP_FAILED);
    }

    if (flags & MAP_ANON) != 0 {
        assert!(ptr.to_bits() & PAGE_SIZE_ALIGN_MASK == 0);

        // Убираем жесткие assert_eq!(fd, -1) и assert_eq!(offset, 0).
        // В реальной iOS/Darwin при наличии флага MAP_ANON аргументы fd и
        // offset
        // просто игнорируются ОС. Движки вроде Adobe AIR передают сюда мусор.
        if fd != -1 || offset != 0 {
            log_dbg!("Warning: mmap MAP_ANON called with fd={} and offset={}. Ignoring them as per OS behavior.", fd, offset);
        }

        if !addr.is_null() {
            // POSIX `mmap` documents the `addr` argument as a hint that
            // implementations may ignore. We always allocate from the
            // guest heap, so the actual placement is the heap allocator's
            // choice. Apps that genuinely require fixed-address mappings
            // would set MAP_FIXED, which we'd then need to honour
            // separately. Demoted to debug to keep Mono/Unity startup
            // logs readable; the host-vs-hint mismatch is not an error.
            log_dbg!(
                "mmap MAP_ANON ignoring hint for address {:?}, actual is {:?}",
                addr,
                ptr
            );
        }
    } else {
        // File-backed mmap: read file content into the allocated buffer.
        if !addr.is_null() {
            log_dbg!(
                "mmap file-backed ignoring hint for address {:?}, actual is {:?}",
                addr,
                ptr
            );
        }
        // mmap(2) does not disturb the descriptor's file offset, so whatever
        // the guest had set is put back before returning. Reading the file
        // through the descriptor is this implementation's own business, and
        // an app that mmaps a region and then carries on read()ing from where
        // it was should not find itself somewhere else.
        let saved_offset = posix_io::lseek(env, fd, 0, posix_io::SEEK_CUR);

        // Seek to the requested offset. If the seek fails (e.g. bad fd),
        // return MAP_FAILED instead of crashing.
        let new_offset = posix_io::lseek(env, fd, offset, SEEK_SET);
        if new_offset != offset {
            log!(
                "Warning: mmap: lseek to offset {} failed (returned {}); returning MAP_FAILED",
                offset, new_offset
            );
            env.mem.free(ptr);
            set_errno(env, EIO);
            return MutVoidPtr::from_bits(MAP_FAILED);
        }

        let read = posix_io::read(env, fd, ptr, len);
        if saved_offset >= 0 {
            posix_io::lseek(env, fd, saved_offset, SEEK_SET);
        }
        if read < 0 {
            // `(read as u32) < len` said no: -1 becomes 4294967295, so a read
            // that failed outright looked like one that had filled the whole
            // mapping, and the guest got a page of zeros with no way to tell.
            log!(
                "Warning: mmap: read from fd {} failed; returning MAP_FAILED",
                fd
            );
            env.mem.free(ptr);
            set_errno(env, EIO);
            return MutVoidPtr::from_bits(MAP_FAILED);
        }
        if (read as GuestUSize) < len {
            log!(
                "Warning: mmap: read only {} of {} bytes from fd {}; padding remainder with zeros",
                read, len, fd
            );
            // Remainder is already zeroed (calloc)
        }
    }

    assert!(!env.libc_state.mmap.allocations.contains_key(&ptr));
    env.libc_state.mmap.allocations.insert(ptr, len);

    ptr
}

fn munmap(env: &mut Environment, addr: MutVoidPtr, len: GuestUSize) -> i32 {
    // TODO: handle errno properly
    set_errno(env, 0);
    log_dbg!("munmap({:?}, {})", addr, len);

    if len == 0 {
        set_errno(env, EINVAL);
        // TODO: should we clear allocations for `addr` here too?
        log!("Warning: munmap({:?}, {}) failed, returning -1", addr, len);
        return -1;
    }

    if let Some(&expected_len) = env.libc_state.mmap.allocations.get(&addr) {
        if expected_len != len {
            log_dbg!(
                "munmap({:?}, {}): length mismatch (expected {}), proceeding anyway",
                addr, len, expected_len
            );
        }
        env.mem.free(addr);
        env.libc_state.mmap.allocations.remove(&addr);
        0 // success
    } else {
        log!(
            "Warning: munmap({:?}, {}): unknown mapping, returning -1",
            addr, len
        );
        set_errno(env, EINVAL);
        -1
    }
}

fn madvise(env: &mut Environment, addr: MutVoidPtr, len: GuestUSize, advice: i32) -> i32 {
    // Advice, as the name says: Darwin is free to do nothing with it and
    // still report success, and it does for most values. Failing instead told
    // an app that something was wrong with a mapping that is perfectly fine —
    // and an asset loader that treats a failed madvise as a failed mapping
    // gives up over nothing.
    log_dbg!("madvise({:?}, {}, {}) -> 0 (ignored)", addr, len, advice);
    set_errno(env, 0);
    0
}

fn shm_open(env: &mut Environment, name: ConstPtr<u8>, oflag: i32, mode: u32) -> i32 {
    set_errno(env, 0);

    let name_str = env.mem.cstr_at_utf8(name).unwrap_or("<invalid>");
    log_dbg!("shm_open({:?}, {:#x}, {:#x})", name_str, oflag, mode);

    // Используем open_direct! Параметр mode для эмулятора здесь не нужен,
    // поэтому просто передаем env, name и oflag.
    open_direct(env, name, oflag)
}

fn mprotect(env: &mut Environment, addr: MutVoidPtr, len: GuestUSize, prot: i32) -> i32 {
    // POSIX `int mprotect(void *addr, size_t len, int prot)`: returns 0
    // on success, -1 on failure with errno set.
    //
    // touchHLE doesn't enforce per-page memory protections — the entire
    // guest address space is treated as RW (and code pages as RX through
    // the JIT). However, returning -1 + ENOTSUP for every mprotect call
    // is wrong: it makes Mono/Boehm GC and Unity's runtime think the
    // protection change failed during JIT/GC initialization, which can
    // leave them in a broken state. Real Darwin kernels never fail
    // mprotect for the address ranges that mmap'd allocations sit in,
    // so the correct behavior is "succeed silently as a no-op".
    //
    // Reference: POSIX mprotect(2) — return value is 0 on success, -1 on
    // error; the only documented errors apply to invalid/non-mapped
    // address ranges, which our guest mmap allocator handles by always
    // returning a valid range.
    log_dbg!(
        "mprotect({:?}, {}, {:#x}) -> 0 (no-op; touchHLE does not enforce per-page protections)",
        addr,
        len,
        prot
    );
    set_errno(env, 0);
    0
}

/// `int mlock(const void *addr, size_t len)` — lock a region of memory
/// so it stays resident in physical RAM. touchHLE keeps the entire
/// guest address space resident in the host process at all times, so
/// there is nothing to pin: the memory is already non-pageable from the
/// guest's perspective. Real Darwin returns 0 on success, so we report
/// success as a no-op (returning -1 here would make guest code that
/// relies on mlock — e.g. crypto/keychain libraries protecting secrets,
/// or audio engines pinning buffers — treat initialization as failed).
///
/// Reference: POSIX/Darwin mlock(2) — returns 0 on success, -1 with
/// errno on failure.
fn mlock(env: &mut Environment, addr: ConstPtr<u8>, len: GuestUSize) -> i32 {
    log_dbg!(
        "mlock({:?}, {}) -> 0 (no-op; guest memory is always resident)",
        addr,
        len
    );
    set_errno(env, 0);
    0
}

/// `int munlock(const void *addr, size_t len)` — unlock a region
/// previously locked with `mlock`. Mirrors [mlock]: a no-op that
/// succeeds.
///
/// Reference: POSIX/Darwin munlock(2) — returns 0 on success.
fn munlock(env: &mut Environment, addr: ConstPtr<u8>, len: GuestUSize) -> i32 {
    log_dbg!(
        "munlock({:?}, {}) -> 0 (no-op; guest memory is always resident)",
        addr,
        len
    );
    set_errno(env, 0);
    0
}

pub const FUNCTIONS: FunctionExports = &[
    export_c_func!(mmap(_, _, _, _, _, _)),
    export_c_func!(munmap(_, _)),
    export_c_func!(madvise(_, _, _)),
    export_c_func!(shm_open(_, _, _)),
    export_c_func!(mprotect(_, _, _)),
    export_c_func!(mlock(_, _)),
    export_c_func!(munlock(_, _)),
];
