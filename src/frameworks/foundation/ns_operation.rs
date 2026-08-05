/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use super::ns_array;
use super::ns_string::get_static_str;
use crate::libc::blocks::{block_copy, block_release, invoke_void_block};
use crate::objc::{
    autorelease, id, msg, msg_class, nil, objc_classes, release, retain, ClassExports, HostObject,
    NSZonePtr, SEL,
};
use crate::Environment;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[derive(Default)]
enum OperationState {
    #[default]
    Ready,
    Executing,
    Finished,
}

#[derive(Debug, Default)]
struct NSOperationHostObject {
    // State tracking
    state: OperationState,
    cancelled: bool,

    // Dependencies
    dependencies: id,

    // Completion block
    completion_block: id,

    // Properties
    name: id,
    queue_priority: i32,

    // NSInvocationOperation specific fields
    target: id,
    selector: Option<SEL>,
    arg: id,
    invocation: id,

    // NSBlockOperation specific field: the blocks to run in -main, in the
    // order they were added. Each one is owned by this object: copied on the
    // way in, released in -dealloc.
    execution_blocks: Vec<id>,
}


impl HostObject for NSOperationHostObject {}

#[derive(Debug, Default)]
struct NSOperationQueueHostObject {
    operations: id, // NSMutableArray of operations
    suspended: bool,
    max_concurrent_operations: i32,
    name: id,
    /// Set while [drain_queue] is running, so that an operation which adds
    /// more work to its own queue doesn't recurse into it.
    draining: bool,
}

impl HostObject for NSOperationQueueHostObject {}

/// Run everything in `queue` that is ready to run, and take the operations
/// that finished back out of it.
///
/// touchHLE runs the guest on a single thread, so there is no worker to hand
/// an operation to: whatever can run, runs here and now. The loop is needed
/// because finishing one operation can satisfy another's dependency, and
/// because an operation is allowed to add more work to its own queue.
fn drain_queue(env: &mut Environment, queue: id) {
    {
        let host_object = env.objc.borrow_mut::<NSOperationQueueHostObject>(queue);
        if host_object.suspended || host_object.draining {
            return;
        }
        host_object.draining = true;
    }

    // An operation is free to release the queue that is running it, so keep
    // the queue alive for as long as this function needs it.
    retain(env, queue);

    loop {
        // Re-read the operation list every pass: running one operation can
        // have changed it.
        let operations = env
            .objc
            .borrow::<NSOperationQueueHostObject>(queue)
            .operations;
        let count: usize = msg![env; operations count];

        let mut next = nil;
        for i in 0..count {
            let op: id = msg![env; operations objectAtIndex:i];
            if op == nil {
                continue;
            }
            let is_finished: bool = msg![env; op isFinished];
            let is_executing: bool = msg![env; op isExecuting];
            let is_ready: bool = msg![env; op isReady];
            if is_ready && !is_executing && !is_finished {
                next = op;
                break;
            }
        }
        if next == nil {
            break;
        }

        // Keep the operation alive across -start: it is removed from the
        // array, which owns the only other reference, right afterwards.
        retain(env, next);
        () = msg![env; next start];
        let is_finished: bool = msg![env; next isFinished];
        if is_finished {
            () = msg![env; operations removeObject:next];
        }
        release(env, next);

        // -start always drives a ready operation to isFinished (a cancelled
        // one included), so each pass removes one operation and the loop
        // terminates. Bail out anyway rather than spin if that ever changes.
        if !is_finished {
            log!(
                "Warning: NSOperationQueue: operation {:?} did not finish; leaving it queued",
                next
            );
            break;
        }
    }

    env.objc
        .borrow_mut::<NSOperationQueueHostObject>(queue)
        .draining = false;
    release(env, queue);
}

pub const CLASSES: ClassExports = objc_classes! {

(env, this, _cmd);

@implementation NSOperation: NSObject

+ (id)allocWithZone:(NSZonePtr)_zone {
    let host_object = Box::new(NSOperationHostObject::default());
    env.objc.alloc_object(this, host_object, &mut env.mem)
}

- (id)init {
    this
}

- (())dealloc {
    // Extract all properties to temporary variables to avoid borrow checker
    // conflicts
    let (deps, completion, name, target, arg, invocation, blocks) = {
        let host_object = env.objc.borrow_mut::<NSOperationHostObject>(this);
        (
            host_object.dependencies,
            host_object.completion_block,
            host_object.name,
            host_object.target,
            host_object.arg,
            host_object.invocation,
            std::mem::take(&mut host_object.execution_blocks),
        )
    };

    release(env, deps);
    release(env, name);
    release(env, target);
    release(env, arg);
    release(env, invocation);

    // Blocks are not Objective-C objects in touchHLE, so they are released
    // through the Blocks runtime rather than with -release.
    block_release(env, completion);
    for block in blocks {
        block_release(env, block);
    }

    env.objc.dealloc_object(this, &mut env.mem)
}

// MARK: - Execution

- (())start {
    // Check if already executing or finished
    let state = env.objc.borrow::<NSOperationHostObject>(this).state;
    if state != OperationState::Ready {
        return;
    }

    // Check if cancelled before starting
    let cancelled = env.objc.borrow::<NSOperationHostObject>(this).cancelled;
    if cancelled {
        let finished_str: id = get_static_str(env, "isFinished");

        () = msg![env; this willChangeValueForKey:finished_str];
        env.objc.borrow_mut::<NSOperationHostObject>(this).state = OperationState::Finished;
        () = msg![env; this didChangeValueForKey:finished_str];
        return;
    }

    // Wait for dependencies
    let deps = env.objc.borrow::<NSOperationHostObject>(this).dependencies;
    if deps != nil {
        let count: usize = msg![env; deps count];
        for i in 0..count {
            let dep: id = msg![env; deps objectAtIndex:i];
            if dep != nil {
                let is_finished: bool = msg![env; dep isFinished];
                if !is_finished {
                    log!("Warning: NSOperation starting with unfinished dependency");
                }
            }
        }
    }

    // Transition to executing
    let executing_str: id = get_static_str(env, "isExecuting");

    () = msg![env; this willChangeValueForKey:executing_str];
    env.objc.borrow_mut::<NSOperationHostObject>(this).state = OperationState::Executing;
    () = msg![env; this didChangeValueForKey:executing_str];

    // Execute main
    () = msg![env; this main];

    // Transition to finished
    let finished_str: id = get_static_str(env, "isFinished");
    let executing_str_2: id = get_static_str(env, "isExecuting");

    () = msg![env; this willChangeValueForKey:executing_str_2];
    () = msg![env; this willChangeValueForKey:finished_str];
    env.objc.borrow_mut::<NSOperationHostObject>(this).state = OperationState::Finished;
    () = msg![env; this didChangeValueForKey:executing_str_2];
    () = msg![env; this didChangeValueForKey:finished_str];

    // Call completion block if present. It is a `void (^)(void)` block, not
    // an object with an -invoke method, so it is called through the Blocks
    // ABI.
    let completion = env.objc.borrow::<NSOperationHostObject>(this).completion_block;
    invoke_void_block(env, completion);
}

- (())main {
    // Base implementation does nothing - subclasses override this
}

// MARK: - Cancellation

- (())cancel {
    let was_cancelled = env.objc.borrow::<NSOperationHostObject>(this).cancelled;
    if !was_cancelled {
        let cancelled_str: id = get_static_str(env, "isCancelled");

        () = msg![env; this willChangeValueForKey:cancelled_str];
        env.objc.borrow_mut::<NSOperationHostObject>(this).cancelled = true;
        () = msg![env; this didChangeValueForKey:cancelled_str];
    }
}

- (bool)isCancelled {
    env.objc.borrow::<NSOperationHostObject>(this).cancelled
}

// MARK: - State queries

- (bool)isReady {
    let state = env.objc.borrow::<NSOperationHostObject>(this).state;
    if state != OperationState::Ready {
        return false;
    }

    // Check if all dependencies are finished
    let deps = env.objc.borrow::<NSOperationHostObject>(this).dependencies;
    if deps != nil {
        let count: usize = msg![env; deps count];
        for i in 0..count {
            let dep: id = msg![env; deps objectAtIndex:i];
            if dep != nil {
                let is_finished: bool = msg![env; dep isFinished];
                if !is_finished {
                    return false;
                }
            }
        }
    }

    true
}

- (bool)isExecuting {
    env.objc.borrow::<NSOperationHostObject>(this).state == OperationState::Executing
}

- (bool)isFinished {
    env.objc.borrow::<NSOperationHostObject>(this).state == OperationState::Finished
}

- (bool)isConcurrent {
    false // We don't support concurrent operations in HLE
}

- (bool)isAsynchronous {
    false // We don't support async operations in HLE
}

// MARK: - Dependencies

- (())addDependency:(id)op {
    if op == nil {
        return;
    }

    // Don't add dependency if already executing or finished
    let state = env.objc.borrow::<NSOperationHostObject>(this).state;
    if state != OperationState::Ready {
        log!("Warning: Attempting to add dependency to operation that is not ready");
        return;
    }

    let deps = env.objc.borrow::<NSOperationHostObject>(this).dependencies;

    let deps_arr = if deps == nil {
        let new_arr: id = msg_class![env; NSMutableArray alloc];
        let new_arr: id = msg![env; new_arr init];
        env.objc.borrow_mut::<NSOperationHostObject>(this).dependencies = new_arr;
        new_arr
    } else {
        deps
    };

    // Check if dependency already exists
    let contains: bool = msg![env; deps_arr containsObject:op];
    if !contains {
        let _: () = msg![env; deps_arr addObject:op];
    }
}

- (())removeDependency:(id)op {
    if op == nil {
        return;
    }
    let deps = env.objc.borrow::<NSOperationHostObject>(this).dependencies;
    if deps != nil {
        let _: () = msg![env; deps removeObject:op];
    }
}

- (id)dependencies {
    let deps = env.objc.borrow::<NSOperationHostObject>(this).dependencies;
    if deps == nil {
        msg_class![env; NSArray array]
    } else {
        let copy: id = msg![env; deps copy];
        autorelease(env, copy)
    }
}

// MARK: - Completion block

- (())setCompletionBlock:(id)block {
    let old_block = env.objc.borrow::<NSOperationHostObject>(this).completion_block;
    block_release(env, old_block);

    // Apple's contract: the block is run after the operation finishes, which
    // can be long after the caller's stack frame is gone, so it is copied.
    let block = block_copy(env, block);
    env.objc.borrow_mut::<NSOperationHostObject>(this).completion_block = block;
}

- (id)completionBlock {
    let block = env.objc.borrow::<NSOperationHostObject>(this).completion_block;
    block // Already retained in our object
}

// MARK: - Properties

- (())setName:(id)name {
    let old_name = env.objc.borrow::<NSOperationHostObject>(this).name;
    release(env, old_name);

    if name != nil {
        retain(env, name);
    }
    env.objc.borrow_mut::<NSOperationHostObject>(this).name = name;
}

- (id)name {
    env.objc.borrow::<NSOperationHostObject>(this).name
}

- (())setQueuePriority:(i32)priority {
    env.objc.borrow_mut::<NSOperationHostObject>(this).queue_priority = priority;
}

- (i32)queuePriority {
    env.objc.borrow::<NSOperationHostObject>(this).queue_priority
}

// MARK: - Waiting

- (())waitUntilFinished {
    // In HLE, operations are synchronous, so this is a no-op
    // In a real implementation, this would block until isFinished is true
}

@end

@implementation NSInvocationOperation: NSOperation

// allocWithZone: and dealloc are now inherited from NSOperation

- (id)initWithTarget:(id)target selector:(SEL)sel object:(id)arg {
    let this: id = msg![env; this init];
    if this != nil {
        retain(env, target);
        if arg != nil {
            retain(env, arg);
        }

        let host_object = env.objc.borrow_mut::<NSOperationHostObject>(this);
        host_object.target = target;
        host_object.selector = Some(sel);
        host_object.arg = arg;
    }
    this
}

- (id)initWithInvocation:(id)invocation {
    let this: id = msg![env; this init];
    if this != nil && invocation != nil {
        retain(env, invocation);
        env.objc.borrow_mut::<NSOperationHostObject>(this).invocation = invocation;
    }
    this
}

- (())main {
    // Check for cancellation
    let cancelled = env.objc.borrow::<NSOperationHostObject>(this).cancelled;
    if cancelled {
        return;
    }

    let (target, sel_opt, arg, invocation) = {
        let host_object = env.objc.borrow::<NSOperationHostObject>(this);
        (
            host_object.target,
            host_object.selector,
            host_object.arg,
            host_object.invocation,
        )
    };

    if invocation != nil {
        () = msg![env; invocation invoke];
        return;
    }

    if target != nil {
        if let Some(sel) = sel_opt {
            if arg != nil {
                let _: id = msg![env; target performSelector:sel withObject:arg];
            } else {
                let _: id = msg![env; target performSelector:sel];
            }
        }
    }
}

- (id)result {
    // Would need to store the result from the invocation
    nil
}

@end

@implementation NSBlockOperation: NSOperation

// allocWithZone: and dealloc are inherited from NSOperation, which owns the
// execution block storage.

+ (id)blockOperationWithBlock:(id)block {
    let new: id = msg![env; this alloc];
    let new: id = msg![env; new init];
    () = msg![env; new addExecutionBlock:block];
    autorelease(env, new)
}

- (())addExecutionBlock:(id)block {
    if block == nil {
        return;
    }
    // The operation can be run long after the method that built it returned,
    // so the block must not be left in the caller's stack frame.
    let block = block_copy(env, block);
    env.objc.borrow_mut::<NSOperationHostObject>(this).execution_blocks.push(block);
}

- (id)executionBlocks {
    // The array holds the same blocks this operation owns. It can't hold its
    // own references to them: a block is not an Objective-C object here, so
    // the -retain and -release the array does are no-ops on one.
    let blocks = env.objc.borrow::<NSOperationHostObject>(this).execution_blocks.clone();
    let array = ns_array::from_vec(env, blocks);
    autorelease(env, array)
}

- (())main {
    // Check for cancellation
    let cancelled = env.objc.borrow::<NSOperationHostObject>(this).cancelled;
    if cancelled {
        return;
    }

    // Apple documents the blocks of one NSBlockOperation as possibly running
    // concurrently; with a single guest thread they run in the order they
    // were added, which is a valid ordering of that.
    let blocks = env.objc.borrow::<NSOperationHostObject>(this).execution_blocks.clone();
    for block in blocks {
        invoke_void_block(env, block);
    }
}

@end

@implementation NSOperationQueue: NSObject

+ (id)allocWithZone:(NSZonePtr)_zone {
    let host_object = Box::new(NSOperationQueueHostObject::default());
    env.objc.alloc_object(this, host_object, &mut env.mem)
}

+ (id)mainQueue {
    // Return a singleton main queue
    // In a real implementation, this would be a true singleton
    let queue: id = msg_class![env; NSOperationQueue alloc];
    let queue: id = msg![env; queue init];
    let name: id = get_static_str(env, "NSOperationQueue Main Queue");
    () = msg![env; queue setName:name];
    autorelease(env, queue)
}

+ (id)currentQueue {
    // In HLE, we don't track thread-local queues, so return nil
    nil
}

- (id)init {
    let operations: id = msg_class![env; NSMutableArray alloc];
    let operations: id = msg![env; operations init];
    env.objc.borrow_mut::<NSOperationQueueHostObject>(this).operations = operations;
    env.objc.borrow_mut::<NSOperationQueueHostObject>(this).max_concurrent_operations = -1; // Default: unlimited
    this
}

- (())dealloc {
    let (operations, name) = {
        let host_object = env.objc.borrow::<NSOperationQueueHostObject>(this);
        (host_object.operations, host_object.name)
    };

    release(env, operations);
    release(env, name);

    env.objc.dealloc_object(this, &mut env.mem)
}

// MARK: - Adding operations

- (())addOperation:(id)op {
    if op == nil {
        return;
    }

    let operations = env.objc.borrow::<NSOperationQueueHostObject>(this).operations;
    () = msg![env; operations addObject:op];

    // Runs the operation right away unless the queue is suspended or a
    // dependency is unfinished, in which case it stays queued until
    // -setSuspended:NO or -waitUntilAllOperationsAreFinished. It used to be
    // taken back out of the queue whether or not it had run, which lost the
    // work of anything added to a suspended queue.
    drain_queue(env, this);
}

- (())addOperations:(id)ops waitUntilFinished:(bool)wait {
    if ops == nil {
        return;
    }

    let count: usize = msg![env; ops count];
    for i in 0..count {
        let op: id = msg![env; ops objectAtIndex:i];
        () = msg![env; this addOperation:op];
    }

    if wait {
        () = msg![env; this waitUntilAllOperationsAreFinished];
    }
}

- (())addOperationWithBlock:(id)block {
    if block == nil {
        return;
    }

    let op: id = msg_class![env; NSBlockOperation blockOperationWithBlock:block];
    () = msg![env; this addOperation:op];
}

// MARK: - Queue control

- (())setSuspended:(bool)suspended {
    env.objc.borrow_mut::<NSOperationQueueHostObject>(this).suspended = suspended;

    // If resuming, run whatever was queued while suspended.
    if !suspended {
        drain_queue(env, this);
    }
}

- (bool)isSuspended {
    env.objc.borrow::<NSOperationQueueHostObject>(this).suspended
}

- (())setMaxConcurrentOperationCount:(i32)count {
    env.objc.borrow_mut::<NSOperationQueueHostObject>(this).max_concurrent_operations = count;
}

- (i32)maxConcurrentOperationCount {
    env.objc.borrow::<NSOperationQueueHostObject>(this).max_concurrent_operations
}

// MARK: - Cancellation

- (())cancelAllOperations {
    let operations = env.objc.borrow::<NSOperationQueueHostObject>(this).operations;
    let count: usize = msg![env; operations count];

    for i in 0..count {
        let op: id = msg![env; operations objectAtIndex:i];
        if op != nil {
            () = msg![env; op cancel];
        }
    }

    // A cancelled operation still has to be started to reach isFinished, so
    // that it leaves the queue and its dependents stop waiting on it.
    drain_queue(env, this);
}

// MARK: - Waiting

- (())waitUntilAllOperationsAreFinished {
    // Operations are synchronous here, so anything that could run already
    // has by the time -addOperation: returned. What may be left is work that
    // was queued while suspended, or that was waiting on a dependency, so
    // run that now. A queue that is still suspended keeps its operations:
    // real NSOperationQueue would block forever, which is not something
    // touchHLE can usefully reproduce.
    drain_queue(env, this);
}

// MARK: - Properties

- (id)operations {
    let operations = env.objc.borrow::<NSOperationQueueHostObject>(this).operations;
    let copy: id = msg![env; operations copy];
    autorelease(env, copy)
}

- (usize)operationCount {
    let operations = env.objc.borrow::<NSOperationQueueHostObject>(this).operations;
    msg![env; operations count]
}

- (())setName:(id)name {
    let old_name = env.objc.borrow::<NSOperationQueueHostObject>(this).name;
    release(env, old_name);

    if name != nil {
        retain(env, name);
    }
    env.objc.borrow_mut::<NSOperationQueueHostObject>(this).name = name;
}

- (id)name {
    env.objc.borrow::<NSOperationQueueHostObject>(this).name
}

// MARK: - Quality of service (stub)

- (())setQualityOfService:(i32)_qos {
    // Ignored in HLE
}

- (i32)qualityOfService {
    0 // NSQualityOfServiceDefault
}

@end

};
