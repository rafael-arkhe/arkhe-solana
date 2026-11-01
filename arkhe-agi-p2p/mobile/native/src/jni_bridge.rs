//! JNI bridge exposing Arkhe Mobile Rust verification functions to Android.

use jni::objects::{JClass, JString};
use jni::sys::jboolean;
use jni::JNIEnv;

#[no_mangle]
pub extern "system" fn Java_space_arkhe_mobile_wer_MobileWerManager_nativeVerifyBundle(
    mut env: JNIEnv,
    _class: JClass,
    bundle_json: JString,
) -> jboolean {
    let input: String = match env.get_string(&bundle_json) {
        Ok(s) => s.into(),
        Err(_) => return 0,
    };

    match arkhe_mobile_verify::verify_bundle_json(&input) {
        Ok(true) => 1,
        _ => 0,
    }
}
