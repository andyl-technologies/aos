//! Seal-gated point-in-time recovery access for the HubDb Durable Object.
//!
//! workers-rs 0.8 does not yet wrap Cloudflare's SQLite Durable Object PITR
//! methods. This module calls the documented JavaScript methods on the exact
//! storage object while keeping all authorization and confirmation policy in
//! the HubDb request handler.

use js_sys::Promise;
use wasm_bindgen::JsCast as _;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use worker_sys::DurableObjectStorage;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "DurableObjectStorage")]
    type PitrStorage;

    #[wasm_bindgen(method, catch, js_name = getCurrentBookmark)]
    fn get_current_bookmark(this: &PitrStorage) -> Result<Promise, JsValue>;

    #[wasm_bindgen(method, catch, js_name = getBookmarkForTime)]
    fn get_bookmark_for_time(this: &PitrStorage, timestamp_ms: f64) -> Result<Promise, JsValue>;

    #[wasm_bindgen(method, catch, js_name = onNextSessionRestoreBookmark)]
    fn on_next_session_restore_bookmark(
        this: &PitrStorage,
        bookmark: &str,
    ) -> Result<Promise, JsValue>;
}

/// Narrow PITR handle for one exact Durable Object storage instance.
pub(crate) struct DurableObjectPitr {
    storage: Option<DurableObjectStorage>,
}

impl DurableObjectPitr {
    /// Creates a PITR handle from storage obtained from the HubDb state.
    #[must_use]
    pub(crate) const fn new(storage: Option<DurableObjectStorage>) -> Self {
        Self { storage }
    }

    /// Returns the current bookmark, or the nearest bookmark to `timestamp_ms`.
    ///
    /// # Errors
    ///
    /// Returns an error when storage is unavailable, the runtime lacks the
    /// requested PITR method, or Cloudflare rejects the timestamp.
    pub(crate) async fn bookmark(&self, timestamp_ms: Option<f64>) -> worker::Result<String> {
        let storage: &PitrStorage = self.storage()?.unchecked_ref();
        let promise = match timestamp_ms {
            Some(timestamp_ms) if timestamp_ms.is_finite() && timestamp_ms >= 0.0 => storage
                .get_bookmark_for_time(timestamp_ms)
                .map_err(|error| js_error("getBookmarkForTime", error))?,
            Some(_) => {
                return Err(worker_error(
                    "PITR timestamp must be a finite non-negative number",
                ));
            }
            None => storage
                .get_current_bookmark()
                .map_err(|error| js_error("getCurrentBookmark", error))?,
        };
        promise_string(promise, "recovery bookmark").await
    }

    /// Schedules a restore on the next Durable Object session.
    ///
    /// The returned bookmark identifies the point immediately before the
    /// restore and can undo it within Cloudflare's retention window.
    ///
    /// # Errors
    ///
    /// Returns an error when storage is unavailable, the runtime lacks PITR,
    /// or Cloudflare rejects the bookmark.
    pub(crate) async fn schedule_restore(&self, bookmark: &str) -> worker::Result<String> {
        let storage: &PitrStorage = self.storage()?.unchecked_ref();
        let promise = storage
            .on_next_session_restore_bookmark(bookmark)
            .map_err(|error| js_error("onNextSessionRestoreBookmark", error))?;
        promise_string(promise, "undo bookmark").await
    }

    fn storage(&self) -> worker::Result<&DurableObjectStorage> {
        self.storage
            .as_ref()
            .ok_or_else(|| worker_error("Durable Object PITR storage is unavailable"))
    }
}

async fn promise_string(promise: Promise, description: &str) -> worker::Result<String> {
    let value = JsFuture::from(promise)
        .await
        .map_err(|error| js_error(description, error))?;
    let value = value
        .as_string()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| worker_error(&format!("PITR returned an invalid {description}")))?;
    if value.len() > 4096 || value.chars().any(|character| character.is_control()) {
        return Err(worker_error(&format!(
            "PITR returned a malformed {description}"
        )));
    }
    Ok(value)
}

fn js_error(method: &str, error: JsValue) -> worker::Error {
    worker_error(&format!("Durable Object PITR {method} failed: {error:?}"))
}

fn worker_error(message: &str) -> worker::Error {
    worker::Error::RustError(message.to_owned())
}
