//! Authenticated read-only discovery of a guard-retained copy owner.
//!
//! The reply carries the actual stored original and compact progress. It never
//! exposes private continuation, provider receipts or a dispatch permit.
//!
//! ```text
//! request = {domain, nonce, scope, selector}
//! reply = {request_digest, retained: null | {original, progress}}
//! ```

use anyhow::{ensure, Result};
use aos_hub_core::{
    storage_authority::{
        control::StorageAuthorityObjectScope,
        external_object::copy::{
            control::CopyProgress, original_lookup::CopyOriginalSelector, ExternalCopyOriginal,
        },
    },
    storage_work::StorageWorkKey,
};
use serde::{Deserialize, Serialize};

use super::super::protocol::{digest, digest_string, MAX_MESSAGE};

pub(super) const PATH: &str = "/copy-original";
pub(super) const DOMAIN: &str = "aos.external-copy-original-lookup.v1";
const REPLY_DOMAIN: &[u8] = b"aos.external-copy-original-lookup-reply.v1\0";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub domain: String,
    pub nonce: String,
    pub scope: StorageAuthorityObjectScope,
    pub selector: CopyOriginalSelector,
}

impl Request {
    pub(super) fn validate(&self) -> Result<()> {
        self.selector.validate()?;
        self.scope.guard_name()?;
        ensure!(
            self.domain == DOMAIN
                && digest_string(&self.nonce)
                && serde_json::to_vec(self)?.len() <= MAX_MESSAGE,
            "copy original lookup domain, nonce or bound differs"
        );
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Retained {
    pub original: ExternalCopyOriginal,
    pub progress: CopyProgress,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    request_digest: String,
    retained: Option<Retained>,
}

/// Authenticates the canonical exact selector before reading durable state.
///
/// # Errors
/// Refuses another domain, changed bytes, unknown fields or oversized controls.
pub(super) fn authenticate(key: &StorageWorkKey, signature: &str, body: &[u8]) -> Result<Request> {
    ensure!(body.len() <= MAX_MESSAGE, "copy original lookup oversized");
    key.verify_body(signature, body)?;
    let request: Request = serde_json::from_slice(body)?;
    ensure!(
        serde_json::to_vec(&request)? == body,
        "copy lookup is noncanonical"
    );
    request.validate()?;
    Ok(request)
}

/// Signs only a genuine original matching every requested selector pin.
///
/// # Errors
/// Refuses changed original/progress pins or a reply exceeding its metadata bound.
pub(super) fn sign_reply(
    key: &StorageWorkKey,
    request: &Request,
    retained: Option<Retained>,
) -> Result<(Vec<u8>, String)> {
    request.validate()?;
    if let Some(value) = &retained {
        request
            .selector
            .validate_retained(&value.original, &value.progress)?;
    }
    let body = serde_json::to_vec(&Envelope {
        request_digest: digest(request)?,
        retained,
    })?;
    ensure!(body.len() <= MAX_MESSAGE, "copy original reply oversized");
    let signature = key.sign_body(&[REPLY_DOMAIN, &body].concat())?;
    Ok((body, signature))
}

/// Requires an exact independently authenticated read-only result.
///
/// # Errors
/// Refuses wrong key, nonce, physical selector, canonical encoding or current pins.
pub(super) fn verify_reply(
    key: &StorageWorkKey,
    request: &Request,
    signature: &str,
    body: &[u8],
) -> Result<Option<Retained>> {
    request.validate()?;
    ensure!(body.len() <= MAX_MESSAGE, "copy original reply oversized");
    key.verify_body(signature, &[REPLY_DOMAIN, body].concat())?;
    let value: Envelope = serde_json::from_slice(body)?;
    ensure!(
        value.request_digest == digest(request)? && serde_json::to_vec(&value)? == body,
        "copy original reply selector differs"
    );
    if let Some(retained) = &value.retained {
        request
            .selector
            .validate_retained(&retained.original, &retained.progress)?;
    }
    Ok(value.retained)
}

#[cfg(test)]
mod tests;
