//! Whole physical cleanup brackets over the existing SDK observation format.
//!
//! Ordinary builds keep this wrapper empty. Do-e2e captures bind an already
//! authenticated full-key SQL original to the exact received canonical body.
//! A successful signed response closes the span; every other exit is incomplete.

use aos_hub_core::oci_cleanup::ManagedOciCleanupRequest;
use wasm_bindgen::JsValue;
use worker::Env;

#[cfg(feature = "do-e2e")]
use crate::managed_gc_sdk_observer as observer;
#[cfg(feature = "do-e2e")]
use sha2::{Digest as _, Sha256};

pub(super) struct Trace {
    #[cfg(feature = "do-e2e")]
    inner: Option<observer::RequestTrace>,
}

impl Trace {
    pub(super) fn start(env: &Env, work: &ManagedOciCleanupRequest, body: &[u8]) -> Self {
        #[cfg(feature = "do-e2e")]
        {
            let inner = work.original.fingerprint().ok().and_then(|original| {
                // Both full digests fit the existing 128-byte subject bound.
                let subject = format!("{original}{}", hex::encode(Sha256::digest(body)));
                observer::from_env_selected(
                    env,
                    "HUB_MANAGED_OCI_CLEANUP_SDK_OBSERVER",
                    observer::Scope::ManagedTerminalCleanup,
                    &work.original.key(),
                    &subject,
                )
            });
            Self { inner }
        }
        #[cfg(not(feature = "do-e2e"))]
        {
            let _ = (env, work, body);
            Self {}
        }
    }

    pub(super) fn call(&self, method: &str) -> Call {
        #[cfg(feature = "do-e2e")]
        {
            let inner = self.inner.as_ref().and_then(|trace| {
                let method = match method {
                    "head" => observer::Method::Head,
                    "get" => observer::Method::Get,
                    "delete" => observer::Method::Delete,
                    _ => {
                        trace.invalidate();
                        return None;
                    }
                };
                trace.call(method)
            });
            Call { inner }
        }
        #[cfg(not(feature = "do-e2e"))]
        {
            let _ = method;
            Call {}
        }
    }

    pub(super) fn read_complete(
        &self,
        bytes: u64,
        sha256: &str,
        object: &aos_hub_core::storage_work::StorageObjectIdentity,
    ) {
        #[cfg(feature = "do-e2e")]
        if let Some(trace) = &self.inner {
            if let Some(version) = object.provider_version.as_deref() {
                trace.read_complete(bytes, sha256, &object.etag, version);
            } else {
                trace.invalidate();
            }
        }
        #[cfg(not(feature = "do-e2e"))]
        let _ = (bytes, sha256, object);
    }

    pub(super) fn finish(&self) {
        #[cfg(feature = "do-e2e")]
        if let Some(trace) = &self.inner {
            trace.finish();
        }
    }
}

pub(super) struct Call {
    #[cfg(feature = "do-e2e")]
    inner: Option<observer::Call>,
}

impl Call {
    pub(super) fn finish(self, deletion: bool, result: &Result<JsValue, JsValue>) {
        #[cfg(feature = "do-e2e")]
        if deletion {
            if let Some(call) = self.inner {
                call.finish(if result.is_ok() {
                    observer::Outcome::Resolved
                } else {
                    observer::Outcome::Unknown
                });
            }
        } else {
            observer::record_js_result(self.inner, result);
        }
        #[cfg(not(feature = "do-e2e"))]
        let _ = (deletion, result);
    }
}
