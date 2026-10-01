//! Bounded native SHA-256 for upload bytes already buffered by the Worker.
//!
//! The JavaScript array owns a copy; no borrowed WebAssembly memory survives an
//! await. This module does not fetch bodies or replace portable streaming state.

use js_sys::{ArrayBuffer, Promise, Uint8Array};
use wasm_bindgen::{prelude::wasm_bindgen, JsCast as _, JsValue};
use wasm_bindgen_futures::JsFuture;

/// Largest existing bounded upload chunk accepted by the Worker data plane.
const MAX_DIGEST_BYTES: usize = aos_hub_core::hybrid_ingress::MAX_HYBRID_OCI_CHUNK_BYTES;

#[wasm_bindgen(
    inline_js = "export function aosBufferedSha256(bytes) { return globalThis.crypto.subtle.digest('SHA-256', bytes); }"
)]
extern "C" {
    #[wasm_bindgen(catch, js_name = aosBufferedSha256)]
    fn native_sha256(bytes: &Uint8Array) -> Result<Promise, JsValue>;
}

/// Returns canonical lowercase SHA-256 for an already-buffered bounded body.
///
/// The route limit is checked before making an owned JavaScript copy. A zero
/// limit accepts only empty input. Native WebCrypto is required; failures never
/// fall back to software hashing or include JavaScript error values.
///
/// # Errors
/// Returns an error for an excessive limit or body, unavailable/failed native
/// crypto, or a digest result other than an exactly 32-byte array buffer.
pub(crate) async fn sha256_hex(bytes: &[u8], maximum_bytes: usize) -> worker::Result<String> {
    if maximum_bytes > MAX_DIGEST_BYTES || bytes.len() > maximum_bytes {
        return Err(worker::Error::RustError(
            "SHA-256 input exceeds its limit".into(),
        ));
    }

    // Uint8Array::from copies into JavaScript-owned storage. A view into Wasm
    // memory could be invalidated by unrelated allocations while awaiting.
    let owned_bytes = Uint8Array::from(bytes);
    let promise = native_sha256(&owned_bytes).map_err(|_| digest_failure())?;
    let result = JsFuture::from(promise)
        .await
        .map_err(|_| digest_failure())?;
    let buffer = result
        .dyn_into::<ArrayBuffer>()
        .map_err(|_| digest_failure())?;
    if buffer.byte_length() != 32 {
        return Err(digest_failure());
    }

    Ok(hex::encode(Uint8Array::new(&buffer).to_vec()))
}

fn digest_failure() -> worker::Error {
    worker::Error::RustError("native SHA-256 digest failed".into())
}
