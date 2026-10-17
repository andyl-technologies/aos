//! Native byte-stream handoff for bounded OCI Rust stream producers.
//!
//! Each caller already owns its fixed byte view and cancellation state. This
//! adapter changes neither authority nor lengths: it supplies workerd's native
//! BYOB-compatible byte stream without retaining a complete object. Raw JS
//! handles stay cancellable until the response handoff succeeds.

use anyhow::Result;
use js_sys::{Array, Function, Reflect};
use wasm_bindgen::{JsCast as _, JsValue};
use worker::{Response, ResponseBody};

pub(crate) fn adapt(response: Response) -> Result<Response> {
    let (builder, source) = response.into_parts();
    let ResponseBody::Stream(body) = source else {
        anyhow::bail!("OCI native bridge requires a streaming body");
    };
    let input: JsValue = body.into();
    let mut source_owner = UnhandedStream(Some(input.clone()));
    let constructor = Reflect::get(&js_sys::global(), &JsValue::from_str("IdentityTransformStream"))
        .map_err(|_| anyhow::anyhow!("native OCI byte adapter unavailable"))?
        .dyn_into::<Function>().map_err(|_| anyhow::anyhow!("native OCI byte adapter unavailable"))?;
    let transform = Reflect::construct(&constructor, &Array::new())
        .map_err(|_| anyhow::anyhow!("native OCI byte adapter construction failed"))?;
    let pipe = Reflect::get(&input, &JsValue::from_str("pipeThrough"))
        .map_err(|_| anyhow::anyhow!("native OCI byte bridge unavailable"))?
        .dyn_into::<Function>().map_err(|_| anyhow::anyhow!("native OCI byte bridge unavailable"))?;
    let body = pipe.call1(&input, &transform)
        .map_err(|_| anyhow::anyhow!("native OCI byte bridge refused"))?;
    let mut framed_owner = UnhandedStream(Some(body.clone()));
    let body = body.dyn_into::<worker::web_sys::ReadableStream>()
        .map_err(|_| anyhow::anyhow!("OCI byte adapter returned no stream"))?;
    let response = builder.stream(body);
    framed_owner.disarm();
    source_owner.disarm();
    Ok(response)
}

// Until request construction succeeds, raw JS stream handles need an explicit
// cancellation owner; dropping the handle alone does not release its reader.
pub(crate) struct UnhandedStream(Option<JsValue>);

impl UnhandedStream {
    pub(crate) fn new(stream: JsValue) -> Self { Self(Some(stream)) }

    pub(crate) fn disarm(&mut self) {
        self.0.take();
    }
}

impl Drop for UnhandedStream {
    fn drop(&mut self) {
        let Some(stream) = &self.0 else {
            return;
        };
        let Ok(cancel) = Reflect::get(stream, &JsValue::from_str("cancel")) else {
            return;
        };
        let Ok(cancel) = cancel.dyn_into::<Function>() else {
            return;
        };
        let Ok(completion) = cancel.call0(stream) else {
            return;
        };
        // A native rejection handler needs no Rust callback lifetime and emits
        // no provider values. The cancellation itself occurs before unwinding.
        let Ok(catch) = Reflect::get(&completion, &JsValue::from_str("catch")) else {
            return;
        };
        let Ok(catch) = catch.dyn_into::<Function>() else {
            return;
        };
        if let Ok(handler) = Reflect::get(&js_sys::global(), &JsValue::from_str("Boolean")) {
            let _ = catch.call1(&completion, &handler);
        }
    }
}
