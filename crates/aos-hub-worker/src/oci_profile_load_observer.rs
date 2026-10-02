//! Private do-e2e observations of the Managed OCI purpose loader.
//!
//! The physical caller opens this bracket after authentication and journal
//! checks under its existing key gate. It describes only the loader interval,
//! not other requests or provider settlement. Missing records, cancellation,
//! overflow or counter changes cannot establish a no-dispatch observation.
//!
//! Selection grants no authority and never changes a loader result:
//!
//! ```json
//! {"version":1,"capture_id":"0123456789abcdef0123456789abcdef","placement_prefix":"placement","document_digest":"sha256:64-lowercase-hex"}
//! ```

use std::{cell::Cell, rc::Rc};

use anyhow::Result;
use aos_hub_core::oci_sdk_emulation::OciSdkEmulationArtifact;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::direct_upload::provider_capacity::{self, Observation};

const MAX_RECORD_BYTES: usize = 8 * 1024;
const MAX_TRACE_BYTES: usize = 32 * 1024;

#[cfg(all(target_arch = "wasm32", feature = "do-e2e"))]
mod runtime;

#[cfg(all(target_arch = "wasm32", feature = "do-e2e"))]
pub(crate) use runtime::from_env;

#[cfg(test)]
mod tests;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    version: u32,
    capture_id: String,
    placement_prefix: String,
    document_digest: String,
}

#[derive(Serialize)]
struct Original {
    request_sha256: String,
    document_digest: String,
    nonce: String,
    key: String,
    issued_at: u64,
    expires_at: u64,
    clock_uncertainty_seconds: u64,
    source_digest: String,
    script_version: String,
    protected_profile_digest: String,
}

/// Retains one explicitly selected, non-authorizing loader observation.
pub(crate) struct Trace {
    configuration: Configuration,
    original: Original,
    before: Observation,
    sink: Rc<dyn Fn(&str) -> bool>,
    ordinal: Cell<usize>,
    bytes: Cell<usize>,
    healthy: Cell<bool>,
    finished: Cell<bool>,
}

impl Trace {
    fn new(
        configuration: Configuration,
        original: Original,
        sink: Rc<dyn Fn(&str) -> bool>,
    ) -> Option<Self> {
        if configuration.version != 1
            || configuration.capture_id.len() != 32
            || !configuration
                .capture_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || configuration.placement_prefix.is_empty()
            || configuration.placement_prefix.len() > 512
            || configuration.placement_prefix.ends_with('/')
            || !original
                .key
                .starts_with(&format!("{}/", configuration.placement_prefix))
            || configuration.document_digest != original.document_digest
            || original.key.len() > 2048
            || original.request_sha256.len() != 64
        {
            return None;
        }
        let trace = Self {
            configuration,
            original,
            before: provider_capacity::observation(),
            sink,
            ordinal: Cell::new(0),
            bytes: Cell::new(0),
            healthy: Cell::new(true),
            finished: Cell::new(false),
        };
        trace.emit(
            serde_json::json!({"kind":"entry", "original":trace.original, "before":trace.before}),
        );
        Some(trace)
    }

    fn emit(&self, event: serde_json::Value) {
        let ordinal = self.ordinal.get() + 1;
        self.ordinal.set(ordinal);
        let record = serde_json::json!({
            "version":1, "scope":"managed_oci_profile_load",
            "capture_id":self.configuration.capture_id, "ordinal":ordinal,
            "request_sha256":self.original.request_sha256,
            "observed_at":aos_hub_core::clock::now_unix_secs(), "event":event,
        });
        let Ok(body) = serde_json::to_string(&record) else {
            self.healthy.set(false);
            return;
        };
        let next = self.bytes.get().checked_add(body.len());
        if body.len() > MAX_RECORD_BYTES || next.is_none_or(|size| size > MAX_TRACE_BYTES) {
            self.healthy.set(false);
            return;
        }
        self.bytes.set(next.unwrap_or(MAX_TRACE_BYTES));
        if !(self.sink)(&body) {
            self.healthy.set(false);
        }
    }

    /// Ends the bracket with the unchanged actual loader result and counters.
    pub(crate) fn finish<T>(&self, result: &Result<T>) {
        if self.finished.replace(true) {
            return;
        }
        let (outcome, error) = match result {
            Ok(_) => ("accepted", None),
            Err(error) => ("refused", Some(format!("{error:#}"))),
        };
        self.emit(serde_json::json!({"kind":"result", "outcome":outcome, "error":error}));
        self.emit(serde_json::json!({
            "kind":"terminal", "outcome":outcome,
            "healthy":self.healthy.get(), "after":provider_capacity::observation(),
        }));
    }
}

impl Drop for Trace {
    fn drop(&mut self) {
        if !self.finished.replace(true) {
            self.emit(serde_json::json!({
                "kind":"terminal", "outcome":"unknown", "healthy":false,
                "after":provider_capacity::observation(),
            }));
        }
    }
}

/// Records the actual decoded bytes immediately before the existing verifier.
///
/// # Errors
/// Returns exactly the shared artifact verifier's admission error.
pub(crate) fn verify_artifact(
    trace: Option<&Trace>,
    artifact: &OciSdkEmulationArtifact,
    bytes: &[u8],
    deployment: &str,
    origin: &str,
    trusted_key: &str,
    now: u64,
) -> Result<()> {
    if let Some(trace) = trace {
        trace.emit(serde_json::json!({
            "kind":"artifact", "artifact_sha256":hex::encode(Sha256::digest(bytes)),
            "byte_size":bytes.len(), "deployment_id":deployment,
            "current_origin":origin, "artifact_origin":artifact.profile.public_origin,
            "source_digest":artifact.profile.worker_source_digest,
            "script_version":artifact.profile.worker_script_version,
            "profile_digest":artifact.profile.digest().ok(), "verification_now":now,
            "artifact_issued_at":artifact.issued_at, "artifact_expires_at":artifact.expires_at,
        }));
    }
    artifact.verify(deployment, origin, trusted_key, now)
}
