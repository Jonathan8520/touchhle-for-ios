/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#![allow(dead_code)]
//! SCNetworkReachability

use crate::abi::GuestFunction;
use crate::dyld::{export_c_func, FunctionExports};
use crate::frameworks::core_foundation::cf_allocator::CFAllocatorRef;
use crate::frameworks::core_foundation::{CFRelease, CFRetain, CFTypeRef};
use crate::mem::{ConstPtr, MutPtr, MutVoidPtr};
use crate::objc::{objc_classes, ClassExports, HostObject};
use crate::Environment;

type SCNetworkReachabilityFlags = u32;
const kSCNetworkReachabilityFlagsTransientConnection: SCNetworkReachabilityFlags = 1 << 0;
const kSCNetworkReachabilityFlagsReachable: SCNetworkReachabilityFlags = 1 << 1;
const kSCNetworkReachabilityFlagsConnectionRequired: SCNetworkReachabilityFlags = 1 << 2;
const kSCNetworkReachabilityFlagsConnectionOnTraffic: SCNetworkReachabilityFlags = 1 << 3;
const kSCNetworkReachabilityFlagsInterventionRequired: SCNetworkReachabilityFlags = 1 << 4;
const kSCNetworkReachabilityFlagsConnectionOnDemand: SCNetworkReachabilityFlags = 1 << 5;
const kSCNetworkReachabilityFlagsIsLocalAddress: SCNetworkReachabilityFlags = 1 << 16;
const kSCNetworkReachabilityFlagsIsDirect: SCNetworkReachabilityFlags = 1 << 17;
const kSCNetworkReachabilityFlagsIsWWAN: SCNetworkReachabilityFlags = 1 << 18;

pub const CLASSES: ClassExports = objc_classes! {
    (env, this, _cmd);
    @implementation _touchHLE_SCNetworkReachability: NSObject
    - (())dealloc {
        env.objc.dealloc_object(this, &mut env.mem)
    }
    @end
};

#[derive(Default)]
struct SCNetworkReachabilityHostObject {
    name: Option<String>,
    callout: Option<GuestFunction>,
    context: MutVoidPtr,
}
impl HostObject for SCNetworkReachabilityHostObject {}

type SCNetworkReachabilityRef = CFTypeRef;

pub fn SCNetworkReachabilityRetain(
    env: &mut Environment,
    target: SCNetworkReachabilityRef,
) -> SCNetworkReachabilityRef {
    if !target.is_null() {
        CFRetain(env, target)
    } else {
        target
    }
}

pub fn SCNetworkReachabilityRelease(env: &mut Environment, target: SCNetworkReachabilityRef) {
    if !target.is_null() {
        CFRelease(env, target);
    }
}

fn SCNetworkReachabilityCreateWithName(
    env: &mut Environment,
    _allocator: CFAllocatorRef,
    name: ConstPtr<u8>,
) -> SCNetworkReachabilityRef {
    let name_str = env.mem.cstr_at_utf8(name).unwrap_or("").to_string();
    let isa = env
        .objc
        .get_known_class("_touchHLE_SCNetworkReachability", &mut env.mem);
    env.objc.alloc_object(
        isa,
        Box::new(SCNetworkReachabilityHostObject {
            name: Some(name_str),
            callout: None,
            context: MutVoidPtr::null(),
        }),
        &mut env.mem,
    )
}

fn SCNetworkReachabilityCreateWithAddress(
    env: &mut Environment,
    _allocator: CFAllocatorRef,
    _address: ConstPtr<u8>,
) -> SCNetworkReachabilityRef {
    let isa = env
        .objc
        .get_known_class("_touchHLE_SCNetworkReachability", &mut env.mem);
    env.objc.alloc_object(
        isa,
        Box::new(SCNetworkReachabilityHostObject {
            name: None,
            callout: None,
            context: MutVoidPtr::null(),
        }),
        &mut env.mem,
    )
}

fn SCNetworkReachabilityCreateWithAddressPair(
    env: &mut Environment,
    _allocator: CFAllocatorRef,
    _local: ConstPtr<u8>,
    _remote: ConstPtr<u8>,
) -> SCNetworkReachabilityRef {
    let isa = env
        .objc
        .get_known_class("_touchHLE_SCNetworkReachability", &mut env.mem);
    env.objc.alloc_object(
        isa,
        Box::new(SCNetworkReachabilityHostObject {
            name: None,
            callout: None,
            context: MutVoidPtr::null(),
        }),
        &mut env.mem,
    )
}

fn SCNetworkReachabilityGetFlags(
    env: &mut Environment,
    _target: SCNetworkReachabilityRef,
    flags: MutPtr<SCNetworkReachabilityFlags>,
) -> bool {
    // touchHLE has no network stack: every NSURLConnection and NSURLSession
    // request is failed with NSURLErrorNotConnectedToInternet. Telling an app
    // the network is reachable and then failing everything it sends is a story
    // that does not add up, and an app that believes the first half takes its
    // online path and waits for a reply that will never arrive. Disney
    // Infinity waits on "Connecting… Please Wait" for as long as it is left
    // running.
    //
    // Saying the network is unreachable is both true and what sends such an
    // app down the offline path it already has. `--claim-network-reachable`
    // restores the old answer for an app that will not start without it.
    let reachable = env.options.claim_network_reachable;
    if reachable {
        log_once!(
            "SCNetworkReachabilityGetFlags: reporting the network as reachable \
             because --claim-network-reachable was given, though touchHLE has \
             no network stack"
        );
    } else {
        log_once!(
            "SCNetworkReachabilityGetFlags: reporting the network as \
             unreachable, because touchHLE has no network stack. Pass \
             --claim-network-reachable to say otherwise"
        );
    }
    env.mem.write(
        flags,
        if reachable {
            kSCNetworkReachabilityFlagsReachable
        } else {
            0
        },
    );
    true
}

/// Targets that have been scheduled for monitoring and are still owed their
/// first callback.
///
/// The real API delivers one shortly after scheduling, carrying the current
/// flags. An app that puts up "Connecting…" and waits to be told the state of
/// the network waits forever without it, which looks exactly like a hang.
static AWAITING_FIRST_CALLBACK: std::sync::Mutex<Vec<SCNetworkReachabilityRef>> =
    std::sync::Mutex::new(Vec::new());

fn schedule_first_callback(target: SCNetworkReachabilityRef) {
    let Ok(mut awaiting) = AWAITING_FIRST_CALLBACK.lock() else {
        return;
    };
    if !awaiting.contains(&target) {
        awaiting.push(target);
    }
}

fn cancel_first_callback(target: SCNetworkReachabilityRef) {
    let Ok(mut awaiting) = AWAITING_FIRST_CALLBACK.lock() else {
        return;
    };
    awaiting.retain(|&t| t != target);
}

/// Deliver any callback owed to a scheduled target. Called once per iteration
/// of the main run loop, which is where the real API would deliver it.
pub fn deliver_pending_callbacks(env: &mut Environment) {
    let due: Vec<SCNetworkReachabilityRef> = match AWAITING_FIRST_CALLBACK.lock() {
        Ok(mut awaiting) if !awaiting.is_empty() => std::mem::take(&mut *awaiting),
        _ => return,
    };
    for target in due {
        let host = env
            .objc
            .borrow::<SCNetworkReachabilityHostObject>(target);
        let (Some(callout), context) = (host.callout, host.context) else {
            continue;
        };
        let flags: SCNetworkReachabilityFlags = if env.options.claim_network_reachable {
            kSCNetworkReachabilityFlagsReachable
        } else {
            0
        };
        log!(
            "SCNetworkReachability: telling {:?} the network is {}",
            target,
            if flags == 0 {
                "unreachable"
            } else {
                "reachable"
            }
        );
        <GuestFunction as crate::abi::CallFromHost<
            (),
            (SCNetworkReachabilityRef, SCNetworkReachabilityFlags, MutVoidPtr),
        >>::call_from_host(&callout, env, (target, flags, context));
    }
}

fn SCNetworkReachabilitySetCallback(
    env: &mut Environment,
    target: SCNetworkReachabilityRef,
    callout: GuestFunction,
    context: MutVoidPtr,
) -> bool {
    let host = env
        .objc
        .borrow_mut::<SCNetworkReachabilityHostObject>(target);
    host.callout = Some(callout);
    host.context = context;
    // Apple returns TRUE when the callback was set, and this did set it.
    // Returning FALSE told every caller that monitoring was unavailable.
    true
}

fn SCNetworkReachabilityScheduleWithRunLoop(
    _env: &mut Environment,
    target: SCNetworkReachabilityRef,
    _run_loop: CFTypeRef,
    _run_loop_mode: CFTypeRef,
) -> bool {
    schedule_first_callback(target);
    true
}
fn SCNetworkReachabilityUnscheduleFromRunLoop(
    _env: &mut Environment,
    target: SCNetworkReachabilityRef,
    _run_loop: CFTypeRef,
    _run_loop_mode: CFTypeRef,
) -> bool {
    cancel_first_callback(target);
    true
}
fn SCNetworkReachabilitySetDispatchQueue(
    _env: &mut Environment,
    target: SCNetworkReachabilityRef,
    queue: MutVoidPtr,
) -> bool {
    // A NULL queue is how an app stops monitoring.
    if queue.is_null() {
        cancel_first_callback(target);
    } else {
        schedule_first_callback(target);
    }
    true
}

pub const FUNCTIONS: FunctionExports = &[
    export_c_func!(SCNetworkReachabilityRetain(_)),
    export_c_func!(SCNetworkReachabilityRelease(_)),
    export_c_func!(SCNetworkReachabilityCreateWithName(_, _)),
    export_c_func!(SCNetworkReachabilityCreateWithAddress(_, _)),
    export_c_func!(SCNetworkReachabilityCreateWithAddressPair(_, _, _)),
    export_c_func!(SCNetworkReachabilityGetFlags(_, _)),
    export_c_func!(SCNetworkReachabilitySetCallback(_, _, _)),
    export_c_func!(SCNetworkReachabilityScheduleWithRunLoop(_, _, _)),
    export_c_func!(SCNetworkReachabilityUnscheduleFromRunLoop(_, _, _)),
    export_c_func!(SCNetworkReachabilitySetDispatchQueue(_, _)),
];
