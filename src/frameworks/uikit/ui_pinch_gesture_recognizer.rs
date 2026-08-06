/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
//! `UIPinchGestureRecognizer`.
//!
//! The base class `UIGestureRecognizer` is implemented in
//! `ui_gesture_recognizer.rs`. This module only provides the
//! `UIPinchGestureRecognizer` subclass with its `scale` and `velocity`
//! properties.
//!
//! Apple documentation:
//! - <https://developer.apple.com/documentation/uikit/uipinchgesturerecognizer>

use super::ui_gesture_recognizer::{GestureKind, UIGestureRecognizerHostObject};
use crate::frameworks::core_graphics::CGFloat;
use crate::objc::{id, impl_HostObject_with_superclass, objc_classes, ClassExports, NSZonePtr};

// MARK: - UIPinchGestureRecognizer host object

/// The superclass host object has to be embedded here, or every method
/// `UIPinchGestureRecognizer` inherits — its state, its view, its target and
/// action — fails to find the object it is asking for.
struct UIPinchGestureRecognizerHostObject {
    superclass: UIGestureRecognizerHostObject,
    scale: CGFloat,
    velocity: CGFloat,
}
impl_HostObject_with_superclass!(UIPinchGestureRecognizerHostObject);

impl Default for UIPinchGestureRecognizerHostObject {
    fn default() -> Self {
        Self {
            superclass: Default::default(),
            // A pinch that has not happened has not changed the scale.
            scale: 1.0,
            velocity: 0.0,
        }
    }
}

pub const CLASSES: ClassExports = objc_classes! {

(env, this, _cmd);

// =========================================================================
// MARK: - UIPinchGestureRecognizer
// =========================================================================

@implementation UIPinchGestureRecognizer: UIGestureRecognizer

+ (id)allocWithZone:(NSZonePtr)_zone {
    let host_object = Box::new(UIPinchGestureRecognizerHostObject {
        superclass: UIGestureRecognizerHostObject::new(GestureKind::Generic),
        ..Default::default()
    });
    env.objc.alloc_object(this, host_object, &mut env.mem)
}

// MARK: - Properties

- (CGFloat)scale {
    env.objc.borrow::<UIPinchGestureRecognizerHostObject>(this).scale
}

- (())setScale:(CGFloat)scale {
    env.objc.borrow_mut::<UIPinchGestureRecognizerHostObject>(this).scale = scale;
}

- (CGFloat)velocity {
    env.objc.borrow::<UIPinchGestureRecognizerHostObject>(this).velocity
}

@end

};
