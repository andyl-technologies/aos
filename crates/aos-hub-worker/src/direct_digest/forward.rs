//! Backpressured native forwarding with an independent exact-byte completion.
//!
//! One pull reads at most 64 KiB, hashes before enqueueing, and returns its Promise
//! to the native stream. No tee or Rust body buffer exists. A provider's positive
//! UploadPart receipt and this completion are both required before terminal.
//! The caller separately verifies same-GET source version/range and guard intent.

use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

use anyhow::{ensure, Result};
use aos_hub_core::direct_upload::{DirectPart, DirectUploadIntent};
use js_sys::{Array, Function, Promise, Reflect};
use wasm_bindgen::{closure::Closure, JsCast as _, JsValue};
use wasm_bindgen_futures::{future_to_promise, JsFuture};

use super::{consume_rejection, invoke, refused, PartHash, Reader, CHUNK_BYTES};

/// Independent proof handle for one source stream sent to a private part sink.
///
/// Dropping an unfinished proof cancels its source. A failed proof leaves the
/// caller's provider turn pending; neither body EOF nor expiry settles that I/O.
pub(crate) struct PartStreamVerification {
    shared: Rc<Shared>,
    promise: Promise,
    verified: bool,
    callbacks: Callbacks,
}

impl PartStreamVerification {
    /// Cancels the exact source while retaining callback ownership for settlement.
    pub(crate) fn cancel(&self) {
        self.shared.cancel();
    }

    /// Waits for exact SHA, checksum, byte count and clean source EOF.
    ///
    /// The caller must also require its provider's positive UploadPart receipt.
    /// This is source-byte verification, not provider/session/guard settlement.
    ///
    /// # Errors
    /// Returns a constant error for cancellation, stream failure or wrong bytes.
    pub(crate) async fn verify(mut self) -> Result<()> {
        JsFuture::from(self.promise.clone())
            .await
            .map_err(|_| refused())?;
        ensure!(
            self.shared.completed.get() && !self.shared.canceled.get(),
            "part stream verification incomplete"
        );
        self.verified = true;
        Ok(())
    }
}

impl Drop for PartStreamVerification {
    fn drop(&mut self) {
        if !self.verified && !self.shared.completed.get() {
            self.shared.cancel();
        }
        // Native close/error prevents subsequent pull/cancel invocation before
        // owned Rust closures are dropped. No WeakRef/finalizer support is used.
        self.shared.controller.borrow_mut().take();
        let _ = &self.callbacks;
    }
}

/// Creates a native stream and separate verification handle for an exact part.
///
/// Source is an already guarded immutable same-GET range stream. Its declared
/// provider metadata is checked by the caller, not accepted as byte identity.
/// Native pull promises provide backpressure; no unbounded tee queue is used.
///
/// # Errors
/// Returns a value-free error for invalid part geometry or unavailable native
/// stream/BYOB/digest interfaces. A later mismatch rejects the proof and stream.
pub(crate) fn forward_part(
    source: worker::web_sys::ReadableStream,
    intent: &DirectUploadIntent,
    part: &DirectPart,
) -> Result<(worker::web_sys::ReadableStream, PartStreamVerification)> {
    part.validate(intent)?;
    let reader = Rc::new(Reader::new(source.into())?);
    let hasher = PartHash::new_part(part)?;
    let mut callbacks = None;
    let promise = Promise::new(&mut |resolve, reject| {
        callbacks = Some((resolve.clone(), reject.clone()));
    });
    consume_rejection(promise.clone().into());
    let (resolve, reject) = callbacks.ok_or_else(refused)?;
    let shared = Rc::new(Shared {
        reader,
        state: RefCell::new(Some(ForwardState {
            part: part.clone(),
            counted: 0,
            hasher: Some(hasher),
        })),
        canceled: Cell::new(false),
        completed: Cell::new(false),
        settled: Cell::new(false),
        controller: RefCell::new(None),
        resolve,
        reject,
    });

    let start_shared = Rc::clone(&shared);
    let start = Closure::<dyn FnMut(JsValue)>::new(move |controller| {
        *start_shared.controller.borrow_mut() = Some(controller);
    });

    let pull_shared = Rc::clone(&shared);
    let pull = Closure::<dyn FnMut(JsValue) -> Promise>::new(move |controller| {
        let shared = Rc::clone(&pull_shared);
        future_to_promise(async move {
            match pull_one(&shared, &controller).await {
                Ok(()) => Ok(JsValue::UNDEFINED),
                Err(_) => {
                    shared.cancel();
                    let failure = failure_value();
                    let _ = invoke(&controller, "error", &[failure.clone()]);
                    Err(failure)
                }
            }
        })
    });
    let cancel_shared = Rc::clone(&shared);
    let cancel = Closure::<dyn FnMut(JsValue)>::new(move |_| {
        cancel_shared.cancel();
    });
    let underlying = js_sys::Object::new();
    Reflect::set(&underlying, &JsValue::from_str("start"), start.as_ref())
        .map_err(|_| refused())?;
    Reflect::set(&underlying, &JsValue::from_str("pull"), pull.as_ref()).map_err(|_| refused())?;
    Reflect::set(&underlying, &JsValue::from_str("cancel"), cancel.as_ref())
        .map_err(|_| refused())?;
    let strategy = js_sys::Object::new();
    // One output chunk is queued. Every producer chunk is <=64 KiB; consumer
    // buffering beyond this native stream remains the provider SDK's contract.
    Reflect::set(
        &strategy,
        &JsValue::from_str("highWaterMark"),
        &JsValue::from_f64(1.0),
    )
    .map_err(|_| refused())?;
    let constructor = Reflect::get(&js_sys::global(), &JsValue::from_str("ReadableStream"))
        .map_err(|_| refused())?
        .dyn_into::<Function>()
        .map_err(|_| refused())?;
    let args = Array::new();
    args.push(&underlying);
    args.push(&strategy);
    let stream = (|| {
        let stream = Reflect::construct(&constructor, &args)
            .map_err(|_| refused())?
            .dyn_into::<worker::web_sys::ReadableStream>()
            .map_err(|_| refused())?;
        ensure!(
            shared.controller.borrow().is_some(),
            "native forwarding controller absent"
        );
        Ok::<_, anyhow::Error>(stream)
    })();
    let stream = match stream {
        Ok(stream) => stream,
        Err(error) => {
            // A constructor may have run start/pull before refusing its result.
            // Close that native owner before the local Rust callbacks drop.
            shared.cancel();
            shared.controller.borrow_mut().take();
            return Err(error);
        }
    };
    Ok((
        stream,
        PartStreamVerification {
            shared,
            promise,
            verified: false,
            callbacks: Callbacks {
                _start: start,
                _pull: pull,
                _cancel: cancel,
            },
        },
    ))
}

// Explicit ownership avoids the leak fallback of Closure::into_js_value on
// runtimes lacking WeakRef/FinalizationRegistry support.
struct Callbacks {
    _start: Closure<dyn FnMut(JsValue)>,
    _pull: Closure<dyn FnMut(JsValue) -> Promise>,
    _cancel: Closure<dyn FnMut(JsValue)>,
}

struct ForwardState {
    part: DirectPart,
    counted: u64,
    hasher: Option<PartHash>,
}

struct Shared {
    reader: Rc<Reader>,
    state: RefCell<Option<ForwardState>>,
    canceled: Cell<bool>,
    completed: Cell<bool>,
    settled: Cell<bool>,
    controller: RefCell<Option<JsValue>>,
    resolve: Function,
    reject: Function,
}

impl Shared {
    fn cancel(&self) {
        self.canceled.set(true);
        if let Some(controller) = self.controller.borrow().as_ref() {
            let _ = invoke(controller, "error", &[failure_value()]);
        }
        if let Ok(promise) = invoke(&self.reader.reader, "cancel", &[failure_value()]) {
            consume_rejection(promise);
        }
        // If an async pull owns the state, its canceled check drops the native
        // digests afterward. Otherwise cancellation releases them immediately.
        self.state.borrow_mut().take();
        if !self.settled.replace(true) {
            let _ = self.reject.call1(&JsValue::UNDEFINED, &failure_value());
        }
    }

    fn complete(&self) {
        self.completed.set(true);
        if !self.settled.replace(true) {
            let _ = self.resolve.call1(&JsValue::UNDEFINED, &JsValue::UNDEFINED);
        }
    }
}

async fn pull_one(shared: &Shared, controller: &JsValue) -> Result<()> {
    ensure!(
        !shared.canceled.get() && !shared.completed.get(),
        "part forwarding closed"
    );
    // Native ReadableStream serializes pull promises. A second concurrent pull
    // is nevertheless refused rather than creating an unbounded read queue.
    let mut state = shared.state.borrow_mut().take().ok_or_else(refused)?;
    let (bytes, done) = shared.reader.read().await?;
    ensure!(
        !shared.canceled.get() && bytes.length() <= CHUNK_BYTES,
        "part forwarding canceled or chunk oversized"
    );
    state.counted = state
        .counted
        .checked_add(u64::from(bytes.length()))
        .ok_or_else(|| anyhow::anyhow!("part forwarding count overflow"))?;
    ensure!(
        state.counted <= state.part.byte_size.get(),
        "part forwarding exceeds declared size"
    );
    if bytes.length() > 0 {
        state
            .hasher
            .as_ref()
            .ok_or_else(refused)?
            .write(&bytes)
            .await?;
        ensure!(
            !shared.canceled.get(),
            "part forwarding canceled after hash"
        );
    }
    if done {
        ensure!(
            state.counted == state.part.byte_size.get(),
            "part forwarding truncated"
        );
        state
            .hasher
            .take()
            .ok_or_else(refused)?
            .finish_part(&state.part)
            .await?;
        ensure!(
            !shared.canceled.get(),
            "part forwarding canceled after final hash"
        );
        if bytes.length() > 0 {
            invoke(controller, "enqueue", &[bytes.into()])?;
        }
        invoke(controller, "close", &[])?;
        shared.complete();
    } else {
        ensure!(bytes.length() > 0, "part forwarding unfinished empty chunk");
        invoke(controller, "enqueue", &[bytes.into()])?;
        *shared.state.borrow_mut() = Some(state);
    }
    Ok(())
}

fn failure_value() -> JsValue {
    JsValue::from_str("part stream verification refused")
}
