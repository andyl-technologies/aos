//! Exact-length native forwarding into the ordinary R2 UploadPart sink.
//!
//! R2 requires an incoming stream with native known-length identity. The native
//! FixedLengthStream checks both truncated and oversized input; pipeTo preserves
//! backpressure. The independent source hash remains a separate required proof.

use anyhow::{ensure, Context as _, Result};
use js_sys::{Array, Function, Object, Promise, Reflect};
use wasm_bindgen::{JsCast as _, JsValue};
use wasm_bindgen_futures::JsFuture;

use super::{invoke, refused};

pub(super) struct FixedPartStream {
    readable: worker::web_sys::ReadableStream,
    completion: Promise,
    cancellation: JsValue,
    settled: bool,
}

impl FixedPartStream {
    pub(super) fn new(source: worker::web_sys::ReadableStream, bytes: u64) -> Result<Self> {
        ensure!(
            bytes <= (1_u64 << 53) - 1,
            "native stage stream length exceeds exact integer"
        );
        let fixed_constructor = constructor("FixedLengthStream")?;
        let arguments = Array::new();
        arguments.push(&JsValue::from_f64(bytes as f64));
        let fixed = Reflect::construct(&fixed_constructor, &arguments)
            .map_err(|_| refused())
            .context("native stage fixed length constructor failed")?;
        let readable = Reflect::get(&fixed, &JsValue::from_str("readable"))
            .map_err(|_| refused())?
            .dyn_into::<worker::web_sys::ReadableStream>()
            .map_err(|_| refused())?;
        let writable =
            Reflect::get(&fixed, &JsValue::from_str("writable")).map_err(|_| refused())?;
        let cancellation = Reflect::construct(&constructor("AbortController")?, &Array::new())
            .map_err(|_| refused())?;
        let signal =
            Reflect::get(&cancellation, &JsValue::from_str("signal")).map_err(|_| refused())?;
        let options = Object::new();
        Reflect::set(&options, &JsValue::from_str("signal"), &signal).map_err(|_| refused())?;
        let completion = invoke(source.as_ref(), "pipeTo", &[writable, options.into()])?
            .dyn_into::<Promise>()
            .map_err(|_| refused())?;
        // Install a native rejection handler without retaining provider values
        // or allocating a Rust callback outside the proof's explicit owner.
        let boolean = Reflect::get(&js_sys::global(), &JsValue::from_str("Boolean"))
            .map_err(|_| refused())?;
        invoke(completion.as_ref(), "catch", &[boolean])?;
        Ok(Self {
            readable,
            completion,
            cancellation,
            settled: false,
        })
    }

    pub(super) fn readable(&self) -> worker::web_sys::ReadableStream {
        self.readable.clone()
    }

    pub(super) fn cancel(&mut self) {
        let _ = invoke(&self.cancellation, "abort", &[]);
    }

    pub(super) async fn finish(mut self) -> Result<()> {
        let result = JsFuture::from(self.completion.clone()).await;
        self.settled = true;
        result
            .map_err(|_| refused())
            .context("native stage fixed length forwarding failed")?;
        Ok(())
    }
}

impl Drop for FixedPartStream {
    fn drop(&mut self) {
        if !self.settled {
            self.cancel();
        }
    }
}

fn constructor(name: &str) -> Result<Function> {
    Reflect::get(&js_sys::global(), &JsValue::from_str(name))
        .map_err(|_| refused())?
        .dyn_into::<Function>()
        .map_err(|_| refused())
        .context("native stage fixed length interface unavailable")
}
