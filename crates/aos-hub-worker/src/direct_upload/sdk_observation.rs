//! Opt-in application facts for a pinned native R2 SDK invocation.
//!
//! A returned SDK promise is not an HTTP acknowledgement, consumed object body
//! or remote settlement. Original declarations and key commitments identify the
//! attempted operation; existing read observations own actual consumption.
//!
//! ```text
//! direct_sdk_application_observation {"version":1,"purpose":"direct_upload_sdk","outcome":"unknown",...}
//! ```

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{cell::Cell, future::Future};

use super::observation::Object;

const MAX_RECORD_BYTES: usize = 4096;
thread_local! { static NEXT: Cell<u64> = const { Cell::new(0) }; }

/// Selects an actual SDK method without serializing arbitrary method text.
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Operation {
    CreateMultipart,
    EmptyPut,
    Complete,
    Abort,
    Get,
    Head,
    Delete,
    UploadPart,
}

impl Operation {
    /// Maps only methods used by the pinned SDK API.
    pub(crate) fn method(method: &str) -> Option<Self> {
        Some(match method {
            "createMultipartUpload" => Self::CreateMultipart,
            "put" => Self::EmptyPut,
            "complete" => Self::Complete,
            "abort" => Self::Abort,
            "get" => Self::Get,
            "head" => Self::Head,
            "delete" => Self::Delete,
            "uploadPart" => Self::UploadPart,
            _ => return None,
        })
    }
}

/// Carries only typed original declarations and an actual SDK key commitment.
#[derive(Clone)]
pub(crate) struct Context {
    key_sha256: String,
    original: Option<Object>,
}

impl Context {
    /// Enables private capture only under its explicit initial test binding.
    #[cfg(target_arch = "wasm32")]
    pub(crate) fn configured(
        env: &worker::Env,
        key: &str,
        original: Option<Object>,
    ) -> Option<Self> {
        if env
            .var("HUB_DIRECT_APPLICATION_LEDGER")
            .ok()
            .is_none_or(|value| value.to_string() != "1")
        {
            return None;
        }
        Some(Self::new(key, original))
    }

    fn new(key: &str, original: Option<Object>) -> Self {
        Self {
            key_sha256: super::observation::digest(key),
            original,
        }
    }
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    DispatchAttempt,
    SdkReturned,
    Unknown,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Record {
    version: u32,
    purpose: &'static str,
    observer_source_sha256: String,
    source_digest: Option<&'static str>,
    isolate_sha256: String,
    attempt_ordinal: u64,
    at_millis: u64,
    operation: Operation,
    key_sha256: String,
    original: Option<Object>,
    outcome: Outcome,
}

struct Attempt {
    record: Record,
}

impl Attempt {
    fn new(context: Context, operation: Operation) -> Self {
        let mut source = Sha256::new();
        source.update(include_bytes!("managed.rs"));
        source.update(include_bytes!("sdk_observation.rs"));
        let mut attempt = Self {
            record: Record {
                version: 1,
                purpose: "direct_upload_sdk",
                observer_source_sha256: hex::encode(source.finalize()),
                source_digest: option_env!("AOS_HUB_WORKER_SOURCE_DIGEST")
                    .filter(|value| aos_hub_core::direct_upload::valid_direct_digest(value)),
                isolate_sha256: super::observation::digest(
                    &super::provider_capacity::observation().isolate_id,
                ),
                attempt_ordinal: NEXT.with(|next| {
                    let value = next.get();
                    next.set(value.saturating_add(1));
                    value
                }),
                at_millis: 0,
                operation,
                key_sha256: context.key_sha256,
                original: context.original,
                outcome: Outcome::DispatchAttempt,
            },
        };
        attempt.emit();
        attempt.record.outcome = Outcome::Unknown;
        attempt
    }

    fn emit(&mut self) {
        #[cfg(target_arch = "wasm32")]
        {
            self.record.at_millis = js_sys::Date::now().max(0.0) as u64;
        }
        if let Ok(json) = serde_json::to_string(&self.record) {
            if json.len() <= MAX_RECORD_BYTES {
                #[cfg(test)]
                CAPTURE.with(|capture| capture.borrow_mut().push(json.clone()));
                #[cfg(target_arch = "wasm32")]
                worker::console_log!("direct_sdk_application_observation {}", json);
                #[cfg(not(target_arch = "wasm32"))]
                let _ = json;
            }
        }
    }
}

impl Drop for Attempt {
    fn drop(&mut self) {
        self.emit();
    }
}

/// Preserves the exact SDK result and marks dropped or rejected promises unknown.
///
/// # Errors
/// Returns exactly the error produced by the supplied SDK operation.
pub(crate) async fn observe<T, E>(
    context: Option<Context>,
    operation: Option<Operation>,
    future: impl Future<Output = Result<T, E>>,
) -> Result<T, E> {
    let mut attempt = context
        .zip(operation)
        .map(|(context, operation)| Attempt::new(context, operation));
    let result = future.await;
    if result.is_ok() {
        if let Some(attempt) = &mut attempt {
            attempt.record.outcome = Outcome::SdkReturned;
        }
    }
    result
}

#[cfg(test)]
thread_local! { static CAPTURE: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) }; }

#[cfg(test)]
mod tests;
