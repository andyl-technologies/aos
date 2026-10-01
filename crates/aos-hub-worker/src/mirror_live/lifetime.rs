//! Explicit ownership of one live source through native client cancellation.
//!
//! A FixedLengthStream can retain a pending Rust pull after its HTTP reader
//! disconnects. The request signal closes this owner directly: it stops the
//! exact source and BYOB reader, aborts the pending Rust read, and releases the
//! buffer and provider permits. Closed owners cannot attach or emit new views.

use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

use anyhow::{ensure, Result};
use futures_util::future::{abortable, AbortHandle};
use js_sys::{Function, Reflect, Uint8Array};
use wasm_bindgen::{closure::Closure, JsCast as _, JsValue};

use crate::{direct_digest::Reader, direct_upload::provider_capacity, mirror_import::buffers};

/// Retains one exact source and its capacity until closure.
pub(super) struct Lifetime {
    shared: Rc<Shared>,
    signal: worker::web_sys::AbortSignal,
    aborted: Closure<dyn FnMut(JsValue)>,
}

struct Shared {
    closed: Cell<bool>,
    attached: Cell<bool>,
    resources: RefCell<Option<Resources>>,
    read_abort: RefCell<Option<AbortHandle>>,
}

struct Resources {
    reader: Option<Rc<Reader>>,
    cancellation: super::SourceCancellation,
    _buffer: buffers::Permit,
    _capacity: provider_capacity::Permit,
}

impl Lifetime {
    /// Registers native client cancellation before the source is dispatched.
    ///
    /// # Errors
    /// Refuses a disconnected client or unavailable native listener interface.
    pub(super) fn new(
        signal: worker::web_sys::AbortSignal,
        cancellation: super::SourceCancellation,
        buffer: buffers::Permit,
        capacity: provider_capacity::Permit,
    ) -> Result<Rc<Self>> {
        let shared = Rc::new(Shared {
            closed: Cell::new(false),
            attached: Cell::new(false),
            resources: RefCell::new(Some(Resources {
                reader: None,
                cancellation,
                _buffer: buffer,
                _capacity: capacity,
            })),
            read_abort: RefCell::new(None),
        });
        // A weak capture avoids a cycle between the owner and its JS callback.
        let weak = Rc::downgrade(&shared);
        let aborted = Closure::<dyn FnMut(JsValue)>::new(move |_| {
            if let Some(shared) = weak.upgrade() {
                shared.close();
            }
        });
        let lifetime = Rc::new(Self {
            shared,
            signal,
            aborted,
        });
        listener(&lifetime.signal, "addEventListener", &lifetime.aborted)?;
        if lifetime.signal.aborted() {
            lifetime.close();
        }
        ensure!(!lifetime.closed(), "live client disconnected");
        Ok(lifetime)
    }

    /// Returns the cancellation signal for this owner's upstream request.
    ///
    /// # Errors
    /// Refuses a closed owner.
    pub(super) fn source_signal(&self) -> Result<worker::AbortSignal> {
        let resources = self.shared.resources.borrow();
        let resources = resources
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("live source closed"))?;
        Ok(worker::AbortSignal::from(resources.cancellation.0.signal()))
    }

    /// Attaches the exact same-response reader once, without new capacity.
    ///
    /// # Errors
    /// Refuses a closed owner or a second attachment.
    pub(super) fn attach_reader(&self, reader: Option<Reader>) -> Result<()> {
        ensure!(!self.closed(), "live source closed");
        ensure!(
            !self.shared.attached.replace(true),
            "live reader already attached"
        );
        let mut resources = self.shared.resources.borrow_mut();
        let resources = resources
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("live source closed"))?;
        resources.reader = reader.map(Rc::new);
        Ok(())
    }

    /// Reports whether this owner has irrevocably closed.
    pub(super) fn closed(&self) -> bool {
        self.shared.closed.get()
    }

    /// Stops the source and pending read before releasing their permits.
    pub(super) fn close(&self) {
        self.shared.close();
    }

    /// Reads at most one native 64 KiB view while the owner remains open.
    ///
    /// # Errors
    /// Refuses cancellation, concurrent reads, expired deadlines or source errors.
    pub(super) async fn read(&self, cutoff: i64, uncertainty: u64) -> Result<(Uint8Array, bool)> {
        ensure!(!self.closed(), "live source closed");
        let reader = {
            let resources = self.shared.resources.borrow();
            resources
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("live source closed"))?
                .reader
                .clone()
        };
        let Some(reader) = reader else {
            return Ok((Uint8Array::new_with_length(0), true));
        };
        // Reader::read allocates only its 64 KiB BYOB view. Native cancellation
        // stops that read; the abort handle wakes and short-circuits the Rust
        // future at its next poll. Permit cleanup does not wait for that poll.
        let (read, abort) = abortable(super::bounded(cutoff, uncertainty, reader.read()));
        ensure!(
            self.shared.read_abort.borrow().is_none(),
            "live source read already pending"
        );
        *self.shared.read_abort.borrow_mut() = Some(abort);
        let _pending = PendingRead(Rc::clone(&self.shared));
        let view = read
            .await
            .map_err(|_| anyhow::anyhow!("live source canceled"))??;
        ensure!(!self.closed(), "live source closed");
        Ok(view)
    }
}

impl Drop for Lifetime {
    fn drop(&mut self) {
        let _ = listener(&self.signal, "removeEventListener", &self.aborted);
        self.shared.close();
    }
}

impl Shared {
    fn close(&self) {
        if self.closed.replace(true) {
            return;
        }
        let abort = self.read_abort.borrow_mut().take();
        if let Some(abort) = abort {
            abort.abort();
        }
        // Mark closed and detach resources before any native callback can run.
        // Cancel the exact reader/source before releasing their capacity. No
        // pending completion can emit a view or attach another reader afterward.
        let resources = self.resources.borrow_mut().take();
        if let Some(resources) = resources {
            if let Some(reader) = &resources.reader {
                reader.cancel();
            }
            resources.cancellation.cancel();
            drop(resources);
        }
    }
}

impl Drop for Shared {
    fn drop(&mut self) {
        self.close();
    }
}

struct PendingRead(Rc<Shared>);

impl Drop for PendingRead {
    fn drop(&mut self) {
        self.0.read_abort.borrow_mut().take();
    }
}

fn listener(
    signal: &worker::web_sys::AbortSignal,
    method: &str,
    callback: &Closure<dyn FnMut(JsValue)>,
) -> Result<()> {
    let function = Reflect::get(signal, &JsValue::from_str(method))
        .map_err(|_| anyhow::anyhow!("live cancellation listener unavailable"))?
        .dyn_into::<Function>()
        .map_err(|_| anyhow::anyhow!("live cancellation listener unavailable"))?;
    function
        .call2(signal, &JsValue::from_str("abort"), callback.as_ref())
        .map_err(|_| anyhow::anyhow!("live cancellation listener unavailable"))?;
    Ok(())
}
