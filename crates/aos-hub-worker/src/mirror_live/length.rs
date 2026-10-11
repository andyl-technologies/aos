//! Native outgoing length framing for already admitted live streams.
//!
//! A general ReadableStream does not establish an HTTP Content-Length merely by
//! setting that header. FixedLengthStream supplies native framing so truncated
//! sources fail at the client as well as at the independent Rust byte budget.
//! Native pipeThrough retains backpressure and propagates cancellation; it does
//! not tee, collect the body, or create another provider dispatch.

use anyhow::{ensure, Result};
use js_sys::{Array, Function, Reflect};
use wasm_bindgen::{JsCast as _, JsValue};
use worker::{Response, ResponseBody};

/// Retains native exact-length identity when the same source declared a length.
///
/// Unknown-length sources keep their independently bounded streaming budget.
///
/// # Errors
/// Refuses an inexact length or unavailable native stream framing interface.
pub(super) fn enforce(
    response: Response,
    declared: Option<u64>,
    client_signal: &worker::web_sys::AbortSignal,
) -> Result<Response> {
    let Some(length) = declared else {
        return Ok(response);
    };
    let (builder, body) = response.into_parts();
    let ResponseBody::Stream(source) = body else {
        anyhow::bail!("live outgoing native stream missing");
    };
    // Raw JS handles do not cancel their underlying Rust stream on Drop. Keep
    // an explicit cancellation owner until native framing accepts the handoff.
    let mut source_owner = UnhandedStream(Some(JsValue::from(source.clone())));
    ensure!(length <= (1_u64 << 53) - 1, "live length is not exact");

    let constructor = Reflect::get(&js_sys::global(), &JsValue::from_str("FixedLengthStream"))
        .map_err(|_| refused())?
        .dyn_into::<Function>()
        .map_err(|_| refused())?;
    let arguments = Array::new();
    arguments.push(&JsValue::from_f64(length as f64));
    let fixed = Reflect::construct(&constructor, &arguments).map_err(|_| refused())?;
    let pipe = Reflect::get(source.as_ref(), &JsValue::from_str("pipeThrough"))
        .map_err(|_| refused())?
        .dyn_into::<Function>()
        .map_err(|_| refused())?;
    let options = js_sys::Object::new();
    Reflect::set(&options, &JsValue::from_str("signal"), client_signal).map_err(|_| refused())?;
    let framed = pipe
        .call2(source.as_ref(), &fixed, &options)
        .map_err(|_| refused())?;
    let mut framed_owner = UnhandedStream(Some(framed.clone()));
    let framed = framed
        .dyn_into::<worker::web_sys::ReadableStream>()
        .map_err(|_| refused())?;

    let response = builder.stream(framed);
    framed_owner.disarm();
    source_owner.disarm();
    Ok(response)
}

struct UnhandedStream(Option<JsValue>);

impl UnhandedStream {
    fn disarm(&mut self) {
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

fn refused() -> anyhow::Error {
    anyhow::anyhow!("live native length framing refused")
}
