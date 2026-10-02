//! Explicit do-e2e selection and bounded metadata extraction for SDK traces.
//!
//! `HUB_MANAGED_GC_SDK_OBSERVER` selects observation only:
//!
//! ```json
//! {"version":1,"capture_id":"32-lowercase-hex-capture-id","prefix":"dedicated/managed-gc"}
//! ```
//!
//! Console delivery is not a durable acknowledgement. The private collector
//! must retain every matching entry/invocation/result/terminal record before
//! describing the scoped bracket as complete.

use std::rc::Rc;

use wasm_bindgen::JsValue;
use worker::Env;

use super::{Call, Configuration, Outcome, RequestTrace, Scope};

/// Opens a selected trace without changing provider admission on recorder failure.
pub(crate) fn from_env(
    env: &Env,
    scope: Scope,
    key: &str,
    subject_id: &str,
) -> Option<RequestTrace> {
    let body = env.var("HUB_MANAGED_GC_SDK_OBSERVER").ok()?.to_string();
    if body.len() > 4_096 {
        return None;
    }
    let configuration: Configuration = serde_json::from_str(&body).ok()?;
    let request_id = uuid::Uuid::new_v4().simple().to_string();
    let sink = Rc::new(|body: &str| {
        worker::console_log!("managed_gc_sdk_observer {}", body);
        true
    });
    RequestTrace::new(
        configuration,
        request_id,
        scope,
        key.into(),
        subject_id.into(),
        sink,
    )
}

/// Records metadata from the actual GET result, without reading its body.
pub(crate) fn record_js_result(call: Option<Call>, result: &std::result::Result<JsValue, JsValue>) {
    let Some(call) = call else { return };
    let outcome = match result {
        Ok(object) if object.is_null() || object.is_undefined() => Outcome::Absent,
        Ok(object) => object_metadata(object).unwrap_or(Outcome::Unknown),
        Err(_) => Outcome::Unknown,
    };
    call.finish(outcome);
}

fn object_metadata(object: &JsValue) -> Option<Outcome> {
    let property = |name: &str| js_sys::Reflect::get(object, &JsValue::from_str(name)).ok();
    let size = property("size")?.as_f64()?;
    if !size.is_finite() || size < 0.0 || size.fract() != 0.0 || size > ((1_u64 << 53) - 1) as f64 {
        return None;
    }
    let etag = property("etag")?.as_string()?;
    let etag = aos_hub_core::surface_write::strong_if_match_etag(&etag).ok()?;
    let version = property("version")?.as_string()?;
    if etag.len() > 512 || !aos_hub_core::storage_work::valid_provider_version(&version) {
        return None;
    }
    Some(Outcome::Object {
        size: size as u64,
        etag,
        version,
    })
}
