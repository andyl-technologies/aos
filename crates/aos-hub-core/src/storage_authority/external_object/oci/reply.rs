//! Independently authenticated compact OCI progress and positive closure.
//!
//! A reply reports durable state for the exact original and request. It does
//! not replace the separate conditional canonical-document proof used by the
//! Native catalogue transaction. Provider bytes and credential material never
//! appear here.

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

use crate::db::OciSha256State;
use crate::storage_authority::canonical_digest;
use crate::storage_work::StorageWorkKey;

use super::{control::ExternalOciRequest, digest_string, OciBytes, OciProviderIncarnation};

/// Independent physical receipt signature, distinct from the application role.
pub const EXTERNAL_OCI_RECEIPT_HEADER: &str = "x-aos-external-oci-receipt-signature";
/// Maximum retained-state response, excluding all object bodies.
pub const MAX_EXTERNAL_OCI_REPLY_BYTES: usize = 16 * 1024;
const DOMAIN: &[u8] = b"aos.external-oci-retained-reply.v1\0";

/// Holds an independently authenticated response for its exact signed control.
#[derive(Clone, Debug)]
pub struct VerifiedExternalOciReply {
    request: ExternalOciRequest,
    reply: ExternalOciReply,
}

impl VerifiedExternalOciReply {
    /// Returns only matched positive progress for this immutable original.
    ///
    /// # Errors
    /// Refuses another retained business original or malformed progress.
    pub fn for_original(&self, original: &super::ExternalOciOriginal) -> Result<&ExternalOciReply> {
        ensure!(self.request.original == *original,
            "external OCI proof selected another original");
        self.reply.validate_for(&self.request)?;
        Ok(&self.reply)
    }
}

/// Positive closure of the exact counted byte stream and provider incarnation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OciClosedObject {
    /// Exact whole chunk or canonical blob content commitment.
    pub bytes: OciBytes,
    /// Actual strong provider ETag returned by positive completion.
    pub etag: String,
    /// Actual provider version and permanent guard incarnation remain distinct.
    pub incarnation: OciProviderIncarnation,
    /// Exact original/effect/positive-receipt canonical commitment.
    pub receipt_digest: String,
}

/// Reports bounded durable progress without granting a new physical effect.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalOciReply {
    /// Closed receipt version, currently one.
    pub version: u8,
    /// Canonical full application request commitment.
    pub request_digest: String,
    /// Exact original request correlation value.
    pub nonce: String,
    /// Exact retained immutable OCI original commitment.
    pub original_digest: String,
    /// Original selected on its first dispatch, supplied only by recovery lookup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retained_original: Option<super::ExternalOciOriginal>,
    /// Number of positively installed ordered source descriptors.
    pub source_count: u32,
    /// Next contiguous multipart part number, one-based.
    pub next_part: u32,
    /// Counted positively acknowledged payload bytes.
    pub accepted_bytes: u64,
    /// Portable whole-upload continuation; no opaque decoder is transported.
    pub upload_sha256: OciSha256State,
    /// Unknown physical effect remains held when present.
    pub pending_effect_digest: Option<String>,
    /// Exact positively closed object, otherwise no completion is asserted.
    pub closed: Option<OciClosedObject>,
}

impl ExternalOciReply {
    /// Authenticates a bounded physical reply into an opaque Native proof.
    ///
    /// # Errors
    /// Refuses a bad role MAC, changed full control or malformed retained facts.
    pub fn authenticate_verified(request: &ExternalOciRequest, guard: &StorageWorkKey,
        signature: &str, bytes: &[u8]) -> Result<VerifiedExternalOciReply> {
        let reply = Self::authenticate(request, guard, signature, bytes)?;
        Ok(VerifiedExternalOciReply { request: request.clone(), reply })
    }
    /// Checks exact request correlation and bounded retained progress shape.
    ///
    /// This observational check does not renew actor, lease or producer expiry.
    ///
    /// # Errors
    /// Refuses changed originals, excessive progress, malformed closure or bytes.
    pub fn validate_for(&self, request: &ExternalOciRequest) -> Result<()> {
        request.original.validate()?;
        let original = match (&request.operation, &self.retained_original) {
            (super::control::OciControl::RecoverOriginal, Some(retained)) => {
                ensure!(retained.selection_digest()? == request.original.selection_digest()?,
                    "external OCI recovery selected another business original");
                retained
            }
            (super::control::OciControl::RecoverOriginal, None) => &request.original,
            (_, None) => &request.original,
            _ => anyhow::bail!("external OCI mutation reply substituted a retained original"),
        };
        self.upload_sha256.validate()?;
        let (offset, maximum, expected, sources) = match &request.original.object {
            super::OciObjectOriginal::Chunk {
                offset,
                maximum_bytes,
                expected,
                ..
            } => (*offset, *maximum_bytes, expected.as_ref(), 0),
            super::OciObjectOriginal::Compose { expected, sources } => {
                (0, expected.size, Some(expected), sources.count)
            }
        };
        ensure!(
            self.version == 1
                && self.request_digest == canonical_digest(request)?
                && self.nonce == request.nonce
                && self.original_digest == original.fingerprint()?
                && self.source_count <= sources
                && (1..=2049).contains(&self.next_part)
                && self.accepted_bytes <= maximum
                && offset.checked_add(self.accepted_bytes) == Some(self.upload_sha256.total_bytes)
                && self
                    .pending_effect_digest
                    .as_ref()
                    .is_none_or(|value| digest_string(value)),
            "external OCI retained reply differs from original"
        );
        if let Some(closed) = &self.closed {
            closed.bytes.validate()?;
            closed
                .incarnation
                .validate(request.original.scope.physical_authority_id.as_str())?;
            ensure!(
                self.pending_effect_digest.is_none()
                    && closed.bytes.size == self.accepted_bytes
                    && expected.is_none_or(|expected| expected == &closed.bytes)
                    && digest_string(&closed.receipt_digest)
                    && crate::surface_write::strong_if_match_etag(&closed.etag)? == closed.etag,
                "external OCI positive closure differs from original"
            );
            if offset == 0 {
                ensure!(
                    self.upload_sha256.final_digest()?.encoded() == closed.bytes.sha256,
                    "external OCI positive bytes differ from full hash"
                );
            }
        }
        ensure!(
            serde_json::to_vec(self)?.len() <= MAX_EXTERNAL_OCI_REPLY_BYTES,
            "external OCI reply oversized"
        );
        Ok(())
    }

    /// Signs exact reply bytes under the independently installed physical role.
    ///
    /// # Errors
    /// Refuses invalid correlation, oversized replies or signing errors.
    pub fn sign(
        &self,
        request: &ExternalOciRequest,
        guard: &StorageWorkKey,
    ) -> Result<(Vec<u8>, String)> {
        self.validate_for(request)?;
        let bytes = serde_json::to_vec(self)?;
        Ok((bytes.clone(), guard.sign_body(&[DOMAIN, &bytes].concat())?))
    }

    /// Authenticates and correlates an exact physical response without body data.
    ///
    /// # Errors
    /// Refuses bad MAC, changed originals, noncanonical JSON or excessive bytes.
    pub fn authenticate(
        request: &ExternalOciRequest,
        guard: &StorageWorkKey,
        signature: &str,
        bytes: &[u8],
    ) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_EXTERNAL_OCI_REPLY_BYTES,
            "external OCI reply oversized"
        );
        guard.verify_body(signature, &[DOMAIN, bytes].concat())?;
        let reply: Self = serde_json::from_slice(bytes)?;
        ensure!(
            serde_json::to_vec(&reply)? == bytes,
            "external OCI reply is noncanonical"
        );
        reply.validate_for(request)?;
        Ok(reply)
    }
}
