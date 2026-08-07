/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
//! `CAEAGLLayer`.

use super::ca_layer::CALayerHostObject;
use crate::frameworks::core_graphics::{CGFloat, CGPoint, CGRect};
use crate::frameworks::foundation::ns_string;
use crate::objc::{id, msg, msg_class, nil, objc_classes, release, Class, ClassExports, ObjC};
use crate::Environment;

// MARK: - EAGLDrawable property key constants
//
// These are the keys apps put in the drawableProperties dictionary.
// We export them as static strings so other modules can reference them.
pub const kEAGLDrawablePropertyRetainedBacking: &str = "kEAGLDrawablePropertyRetainedBacking";
pub const kEAGLDrawablePropertyColorFormat: &str = "kEAGLDrawablePropertyColorFormat";

// kEAGLColorFormat values
pub const kEAGLColorFormatRGBA8: &str = "kEAGLColorFormatRGBA8";
pub const kEAGLColorFormatRGB565: &str = "kEAGLColorFormatRGB565";
pub const kEAGLColorFormatSRGBA8: &str = "kEAGLColorFormatSRGBA8";

pub const CLASSES: ClassExports = objc_classes! {

(env, this, _cmd);

@implementation CAEAGLLayer: CALayer

// =========================================================================
// MARK: - EAGLDrawable protocol
// =========================================================================

- (id)drawableProperties { // NSDictionary<NSString*, id>*
    env.objc.borrow::<CALayerHostObject>(this).drawable_properties
}

- (())setDrawableProperties:(id)props { // NSDictionary<NSString*, id>*
    // Store a copy — matches Apple's behaviour.
    let old = env.objc.borrow::<CALayerHostObject>(this).drawable_properties;
    let new_props: id = if props != nil { msg![env; props copy] } else { nil };
    release(env, old);
    env.objc.borrow_mut::<CALayerHostObject>(this).drawable_properties = new_props;

    // Log the properties the app is requesting so rendering issues are
    // easier to diagnose.
    if new_props != nil {
        let retained_key = ns_string::get_static_str(env, kEAGLDrawablePropertyRetainedBacking);
        let format_key    = ns_string::get_static_str(env, kEAGLDrawablePropertyColorFormat);

        let retained_val: id = msg![env; new_props objectForKey:retained_key];
        let format_val:   id = msg![env; new_props objectForKey:format_key];

        let retained_str = if retained_val != nil {
            let b: bool = msg![env; retained_val boolValue];
            if b { "YES" } else { "NO" }
        } else {
            "(not set)"
        };

        let format_str = if format_val != nil {
            ns_string::to_rust_string(env, format_val).into_owned()
        } else {
            "(not set)".to_string()
        };

        log_dbg!(
            "CAEAGLLayer setDrawableProperties: retainedBacking={} colorFormat={}",
            retained_str, format_str
        );
    }
}

// =========================================================================
// MARK: - Convenience helpers (read individual drawable properties)
// =========================================================================

// Returns YES if the backing store should be retained after presentation.
// Corresponds to kEAGLDrawablePropertyRetainedBacking.
- (bool)_touchHLE_retainedBacking {
    let props = env.objc.borrow::<CALayerHostObject>(this).drawable_properties;
    if props == nil { return false; }
    let key: id = ns_string::get_static_str(env, kEAGLDrawablePropertyRetainedBacking);
    let val: id = msg![env; props objectForKey:key];
    if val == nil { return false; }
    msg![env; val boolValue]
}

// Returns the requested color format string, or "kEAGLColorFormatRGBA8"
// as the default if not specified.
- (id)_touchHLE_colorFormat { // NSString*
    let props = env.objc.borrow::<CALayerHostObject>(this).drawable_properties;
    if props != nil {
        let key: id = ns_string::get_static_str(env, kEAGLDrawablePropertyColorFormat);
        let val: id = msg![env; props objectForKey:key];
        if val != nil { return val; }
    }
    ns_string::get_static_str(env, kEAGLColorFormatRGBA8)
}

// =========================================================================
// MARK: - CALayer overrides
// =========================================================================

// CAEAGLLayer is always opaque by default (unlike plain CALayer).
- (id)init {
    let _: () = msg![env; this setOpaque:true];
    this
}

// MARK: - Scale / Retina Support

- (CGFloat)contentScaleFactor {
    // Жестко задаем масштаб 1.0 (стандартный не-Retina экран)
    1.0
}

- (())setContentScaleFactor:(CGFloat)scale {
    // Заглушка, чтобы игра не упала, если попытается сама установить масштаб
    log_dbg!("CAEAGLLAYER setContentScaleFactor: {} (stubbed)", scale);
}

- (CGFloat)contentsScale {
    // Жестко задаем масштаб 1.0 (стандартный не-Retina экран)
    1.0
}

- (())setContentsScale:(CGFloat)scale {
    // Заглушка, чтобы игра не упала, если попытается сама установить масштаб
    log_dbg!("CAEAGLLAYER setContentsScale: {} (stubbed)", scale);
}

- (id)initWithLayer:(id)layer {
    let _: () = msg![env; this setOpaque:true];
    // Copy drawable properties from the source layer if it is also a
    // CAEAGLLayer.
    let ca_eagl_class: Class = msg_class![env; CAEAGLLayer class];
    let is_eagl: bool = msg![env; layer isKindOfClass:ca_eagl_class];
    if is_eagl {
        let src_props = env.objc.borrow::<CALayerHostObject>(layer).drawable_properties;
        if src_props != nil {
            let copy: id = msg![env; src_props copy];
            env.objc.borrow_mut::<CALayerHostObject>(this).drawable_properties = copy;
        }
    }
    this
}

// Prevent the layer from being drawn by Core Animation — its contents are
// managed exclusively by EAGL/OpenGL ES.
- (())display {
    // No-op: the layer is presented via EAGLContext presentRenderBuffer:.
}

- (())drawInContext:(id)_ctx { // CGContextRef
    // No-op: CAEAGLLayer content comes from OpenGL ES, not Core Graphics.
}

// =========================================================================
// MARK: - Description
// =========================================================================

- (id)description {
    let host = env.objc.borrow::<CALayerHostObject>(this);
    let opaque = host.opaque;
    let has_props = host.drawable_properties != nil;
    let s = format!(
        "<CAEAGLLayer: {:?}; opaque={}; drawableProperties={}>",
        this,
        opaque,
        if has_props { "(set)" } else { "(nil)" }
    );
    let cstr = env.mem.alloc_and_write_cstr(s.as_bytes());
    msg_class![env; NSString stringWithUTF8String:cstr]
}

@end

};

// =========================================================================
// MARK: - find_fullscreen_eagl_layer
// =========================================================================

/// One line describing a layer, for [find_fullscreen_eagl_layer]'s diagnostic
/// dump. A layer tree that fails this search is otherwise invisible: the only
/// symptom is a black screen, which looks exactly like a tree that never got
/// drawn at all.
fn describe_layer(env: &Environment, layer: id) -> String {
    let class_name = env
        .objc
        .get_class_name(ObjC::read_isa(layer, &env.mem))
        .to_string();
    let host_obj: &CALayerHostObject = env.objc.borrow(layer);
    let children: Vec<&str> = host_obj
        .sublayers
        .iter()
        .map(|&sublayer| env.objc.get_class_name(ObjC::read_isa(sublayer, &env.mem)))
        .collect();
    // CGRect and CGPoint are packed, so their fields can't be borrowed, which
    // is what passing them to format! would do. Each one has to be copied out
    // whole.
    let width = host_obj.bounds.size.width;
    let height = host_obj.bounds.size.height;
    let origin_x = host_obj.bounds.origin.x;
    let origin_y = host_obj.bounds.origin.y;
    let position_x = host_obj.position.x;
    let position_y = host_obj.position.y;
    let anchor_x = host_obj.anchor_point.x;
    let anchor_y = host_obj.anchor_point.y;
    format!(
        "{} {:?}: bounds {}x{} at ({}, {}), position ({}, {}), anchor ({}, {}), \
         hidden {}, opaque {}, opacity {}, transform {}, sublayers {:?}",
        class_name,
        layer,
        width,
        height,
        origin_x,
        origin_y,
        position_x,
        position_y,
        anchor_x,
        anchor_y,
        host_obj.hidden,
        host_obj.opaque,
        host_obj.opacity,
        if host_obj.affine_transform.is_identity() {
            "identity"
        } else {
            "not identity"
        },
        children,
    )
}

/// If there is an opaque `CAEAGLLayer` that covers the entire screen, this
/// returns a pointer to it. Otherwise, it returns [nil].
///
/// The first time this comes up empty it walks the tree a second time and says
/// what it saw and which condition turned it down. Falling back to composition
/// is a correctness-preserving choice on desktop, but on a device it is the
/// difference between a picture and a black screen, and until now it happened
/// in complete silence.
pub fn find_fullscreen_eagl_layer(env: &mut Environment) -> id {
    let layer = find_fullscreen_eagl_layer_inner(env, false);
    if layer == nil {
        use std::sync::atomic::{AtomicBool, Ordering};
        static REPORTED: AtomicBool = AtomicBool::new(false);
        if !REPORTED.swap(true, Ordering::Relaxed) {
            find_fullscreen_eagl_layer_inner(env, true);
        }
    }
    layer
}

fn find_fullscreen_eagl_layer_inner(env: &mut Environment, explain: bool) -> id {
    if env.options.force_composition {
        if explain {
            log!(
                "No fullscreen CAEAGLLayer: composition was forced with \
                 --force-composition. [this log will only be shown once]"
            );
        }
        return nil;
    }

    let windows = env.framework_state.uikit.ui_view.ui_window.windows.clone();
    let Some(top_window) = windows
        .into_iter()
        .rev()
        .find(|&window| !msg![env; window isHidden])
    else {
        if explain {
            log!(
                "No fullscreen CAEAGLLayer: not one UIWindow is visible. \
                 [this log will only be shown once]"
            );
        }
        return nil;
    };

    let screen_bounds: CGRect = {
        let screen: id = msg_class![env; UIScreen mainScreen];
        msg![env; screen bounds]
    };

    let mut layer: id = msg![env; top_window layer];

    if explain {
        let (screen_width, screen_height) = (screen_bounds.size.width, screen_bounds.size.height);
        log!(
            "Looking for a fullscreen CAEAGLLayer under UIWindow {:?}. The \
             screen is {}x{}, so every layer on the way down has to be that \
             size, centred, unrotated and fully opaque.",
            top_window,
            screen_width,
            screen_height,
        );
    }

    loop {
        // assert!(layer != nil);

        if explain {
            log!("  {}", describe_layer(env, layer));
        }

        let layer_host_obj: &CALayerHostObject = env.objc.borrow(layer);

        let rejected_because = if layer_host_obj.bounds.size != screen_bounds.size {
            Some("its bounds are not the size of the screen")
        } else if layer_host_obj.bounds.origin != (CGPoint { x: 0.0, y: 0.0 }) {
            Some("its bounds do not start at the origin")
        } else if layer_host_obj.anchor_point != (CGPoint { x: 0.5, y: 0.5 }) {
            Some("its anchor point is not the centre")
        } else if layer_host_obj.position
            != (CGPoint {
                x: screen_bounds.size.width / 2.0,
                y: screen_bounds.size.height / 2.0,
            })
        {
            Some("it is not positioned at the centre of the screen")
        } else if layer_host_obj.hidden {
            Some("it is hidden")
        } else if layer_host_obj.opacity != 1.0 {
            Some("it is not fully opaque")
        } else if !layer_host_obj.affine_transform.is_identity() {
            Some("it carries an affine transform")
        } else {
            None
        };

        if let Some(reason) = rejected_because {
            if explain {
                log!(
                    "  ...and that is where the search stops: {}. Frames will \
                     go through Core Animation composition instead of being \
                     presented directly. [this log will only be shown once]",
                    reason
                );
            }
            return nil;
        }

        if let Some(&next) = layer_host_obj.sublayers.last() {
            layer = next;
        } else {
            break;
        }
    }

    if !env.objc.borrow::<CALayerHostObject>(layer).opaque {
        if explain {
            log!(
                "  ...and that is where the search stops: the innermost layer \
                 is not opaque. [this log will only be shown once]"
            );
        }
        return nil;
    }

    let ca_eagl_layer_class: Class = msg_class![env; CAEAGLLayer class];
    if !msg![env; layer isKindOfClass:ca_eagl_layer_class] {
        if explain {
            log!(
                "  ...and that is where the search stops: the innermost layer \
                 is not a CAEAGLLayer, so something is covering the one that \
                 draws. [this log will only be shown once]"
            );
        }
        return nil;
    }

    layer
}

// =========================================================================
// MARK: - Pixel buffer helpers (used by EAGLContext)
// =========================================================================

/// Takes the pixel buffer out of the layer so it can be refilled by
/// `EAGLContext presentRenderBuffer:`. Pass the buffer back via
/// [present_pixels] once it is filled.
pub fn get_pixels_vec_for_presenting(env: &mut Environment, layer: id) -> Vec<u8> {
    env.objc
        .borrow_mut::<CALayerHostObject>(layer)
        .presented_pixels
        .take()
        .map(|(vec, _w, _h)| vec)
        .unwrap_or_default()
}

/// Stores the new rendered frame in the layer and marks the GLES texture as
/// stale. Data must be in RGBA8 format.
pub fn present_pixels(env: &mut Environment, layer: id, pixels: Vec<u8>, width: u32, height: u32) {
    let host_obj = env.objc.borrow_mut::<CALayerHostObject>(layer);
    host_obj.presented_pixels = Some((pixels, width, height));
    host_obj.gles_texture_is_up_to_date = false;
}

/// Returns whether the layer's backing store should be retained after
/// presentation (i.e. `kEAGLDrawablePropertyRetainedBacking` is YES).
/// Convenience wrapper for use by `EAGLContext`.
pub fn is_retained_backing(env: &mut Environment, layer: id) -> bool {
    msg![env; layer _touchHLE_retainedBacking]
}

/// Returns the drawable's pixel width (from the presented pixel buffer if
/// available, otherwise from the layer's bounds).
pub fn drawable_width(env: &mut Environment, layer: id) -> u32 {
    let host = env.objc.borrow::<CALayerHostObject>(layer);
    if let Some((_, w, _)) = host.presented_pixels {
        return w;
    }
    host.bounds.size.width as u32
}

/// Returns the drawable's pixel height.
pub fn drawable_height(env: &mut Environment, layer: id) -> u32 {
    let host = env.objc.borrow::<CALayerHostObject>(layer);
    if let Some((_, _, h)) = host.presented_pixels {
        return h;
    }
    host.bounds.size.height as u32
}
