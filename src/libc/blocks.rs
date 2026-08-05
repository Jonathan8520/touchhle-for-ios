/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
//! `libBlocksRuntime` — Apple Blocks ABI helpers.
//!
//! These functions are called by the compiler-generated copy/dispose
//! helpers when an Objective-C block captures a `__strong` ObjC object,
//! a `__weak` reference, another block, or a `__block` storage variable.
//! They are documented in the
//! [Blocks ABI](https://clang.llvm.org/docs/Block-ABI-Apple.html#imported-variables-1).
//!
//! For touchHLE we provide working implementations of `_Block_copy`,
//! `_Block_release`, and `_Block_object_assign` / `_Block_object_dispose`
//! that perform the appropriate ARC retains/releases. Block copying itself
//! is not implemented — a captured-block "copy" returns the same pointer
//! (matching how _global_ blocks behave on iOS) — but the bookkeeping for
//! captured ObjC objects is correct, so games that simply use blocks as
//! callbacks (e.g. `MFMailComposeViewController` completion handlers,
//! `dispatch_async`) link and run.

use crate::abi::{CallFromHost, GuestFunction};
use crate::dyld::{export_c_func, FunctionExports};
use crate::mem::{ConstVoidPtr, MutPtr, MutVoidPtr, Ptr};
use crate::objc::{id, nil, release, retain};
use crate::Environment;

/// Bit-flag values passed to `_Block_object_assign` / `_Block_object_dispose`.
/// See the Blocks ABI document referenced above.
const BLOCK_FIELD_IS_OBJECT: i32 = 3;
const BLOCK_FIELD_IS_BLOCK: i32 = 7;
const BLOCK_FIELD_IS_BYREF: i32 = 8;
const BLOCK_FIELD_IS_WEAK: i32 = 16;
#[allow(dead_code)]
const BLOCK_BYREF_CALLER: i32 = 128;

/// `_Block_copy(block) -> block`. We don't actually duplicate the block
/// (block copies are reference-counted under-the-hood and stack blocks need
/// promotion to the heap, both of which require deeper Block ABI work),
/// so we just return the input pointer. Apps that store copied blocks for
/// later use will continue to see the same heap-resident block; this is
/// correct for blocks compiled as `__NSConcreteGlobalBlock` (the common
/// case for static literal blocks) and best-effort for stack blocks.
fn _Block_copy(_env: &mut Environment, block: ConstVoidPtr) -> ConstVoidPtr {
    block
}

fn _Block_release(_env: &mut Environment, _block: ConstVoidPtr) {}

/// `_Block_object_assign(destAddr, object, flags)`. Called by the
/// compiler-generated copy helper to retain `object` and store it at
/// `destAddr`. We perform the retain side-effect via `objc::retain`.
///
/// `flags` is a bitwise OR of `BLOCK_FIELD_IS_*` constants telling us what
/// the captured value is — an ObjC object, another block, or a `__block`
/// storage location. For ObjC objects and blocks we retain; for `__weak`
/// captures we do nothing (per the Blocks ABI).
fn _Block_object_assign(
    env: &mut Environment,
    dest_addr: MutVoidPtr,
    object: ConstVoidPtr,
    flags: i32,
) {
    if flags & BLOCK_FIELD_IS_WEAK != 0 {
        // __weak: no retain. Just store the pointer.
        env.mem.write(dest_addr.cast(), object);
        return;
    }
    let kind = flags & 0xFF & !BLOCK_FIELD_IS_WEAK;
    if kind == BLOCK_FIELD_IS_OBJECT || kind == BLOCK_FIELD_IS_BLOCK {
        let obj: id = Ptr::from_bits(object.to_bits());
        retain(env, obj);
    }
    // BLOCK_FIELD_IS_BYREF: caller already manages the byref structure.
    env.mem.write(dest_addr.cast(), object);
}

/// `_Block_object_dispose(object, flags)`. Called by the compiler-generated
/// dispose helper to release a captured object that was retained by
/// `_Block_object_assign`.
fn _Block_object_dispose(env: &mut Environment, object: ConstVoidPtr, flags: i32) {
    if flags & BLOCK_FIELD_IS_WEAK != 0 {
        return;
    }
    let kind = flags & 0xFF & !BLOCK_FIELD_IS_WEAK;
    if kind == BLOCK_FIELD_IS_OBJECT || kind == BLOCK_FIELD_IS_BLOCK {
        let obj: id = Ptr::from_bits(object.to_bits());
        release(env, obj);
    }
    // BLOCK_FIELD_IS_BYREF: caller manages.
}

// MARK: - Helpers for host code that has to hold on to, or call, a block

/// Word offset of a block literal's `invoke` function pointer. The layout is
/// `{ isa, flags, reserved, invoke, descriptor, captured variables… }`, and
/// every field before `invoke` is one word wide on 32-bit ARM, so `invoke` is
/// the fourth word. See the
/// [Blocks ABI](https://clang.llvm.org/docs/Block-ABI-Apple.html).
pub const BLOCK_INVOKE_WORD_OFFSET: u32 = 3;

/// Read a block's `invoke` function pointer.
///
/// Returns [None] for a nil block, or for one whose `invoke` pointer is zero.
/// The latter happens when the guest hands over a stack block that was never
/// copied and has already gone out of scope, so callers should treat it as
/// "there is nothing to call" rather than as a fatal error.
pub fn block_invoke(env: &Environment, block: id) -> Option<GuestFunction> {
    if block == nil {
        return None;
    }
    let block_ptr: MutPtr<u32> = Ptr::from_bits(block.to_bits());
    let invoke_addr: u32 = env.mem.read(block_ptr + BLOCK_INVOKE_WORD_OFFSET);
    if invoke_addr == 0 {
        return None;
    }
    Some(GuestFunction::from_addr_with_thumb_bit(invoke_addr))
}

/// Call a block whose underlying function has the signature `void (^)(void)`.
/// Does nothing if there is no function to call.
pub fn invoke_void_block(env: &mut Environment, block: id) {
    let Some(invoke) = block_invoke(env, block) else {
        return;
    };
    let block_arg: ConstVoidPtr = Ptr::from_bits(block.to_bits());
    <GuestFunction as CallFromHost<(), (ConstVoidPtr,)>>::call_from_host(
        &invoke,
        env,
        (block_arg,),
    );
}

/// `Block_copy()` for host code that needs to keep a block past the call it
/// was handed to. The returned block is owned by the caller and must be
/// passed to [block_release] when it is no longer needed.
///
/// This is the same operation the guest gets from `_Block_copy`, with the
/// same limitation: it does not yet promote a stack block to the heap, so a
/// block that has gone out of scope by the time it is called is still gone.
/// Routing through here rather than copying pointers around means callers
/// pick up a real implementation for free if one is added.
pub fn block_copy(env: &mut Environment, block: id) -> id {
    if block == nil {
        return nil;
    }
    let block_ptr: MutVoidPtr = Ptr::from_bits(block.to_bits());
    let copied = _Block_copy(env, block_ptr.cast_const());
    Ptr::from_bits(copied.to_bits())
}

/// `Block_release()`, pairing with [block_copy].
pub fn block_release(env: &mut Environment, block: id) {
    if block == nil {
        return;
    }
    let block_ptr: MutVoidPtr = Ptr::from_bits(block.to_bits());
    _Block_release(env, block_ptr.cast_const());
}

pub const FUNCTIONS: FunctionExports = &[
    export_c_func!(_Block_copy(_)),
    export_c_func!(_Block_release(_)),
    export_c_func!(_Block_object_assign(_, _, _)),
    export_c_func!(_Block_object_dispose(_, _)),
];
