//! Compact read-only facts from a still-visible permanent source closure.
//!
//! The metadata projection does not authenticate itself or issue a read permit.
//! Its producer must load and validate the actual current head and immutable
//! receipt on the exact source key. Range execution must check that same closure
//! while retaining the source guard through EOF or cancellation.
//!
//! ```text
//! closure = {guard_stamp, receipt_digest, sha256, bytes, etag?: strong quoted tag}
//! ```

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

use super::{digest_string, ExternalCopyOriginal};
use crate::storage_authority::{lease::LeaseInteger, StorageGuardStamp};

/// Projects one actual positive source receipt without granting provider access.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CopySourceClosure {
    /// Permanent physical-key incarnation retained by the source guard.
    pub guard_stamp: StorageGuardStamp,
    /// Canonical immutable positive receipt commitment.
    pub receipt_digest: String,
    /// Whole-object SHA-256 retained by its original producer.
    pub sha256: String,
    /// Exact positive object length.
    pub bytes: LeaseInteger,
    /// Actual completion tag when the producer receipt retains it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
}

impl CopySourceClosure {
    /// Checks intrinsic closure shape without establishing receipt custody.
    ///
    /// # Errors
    /// Returns an error for malformed commitments, excessive size or a weak tag.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            digest_string(&self.receipt_digest)
                && digest_string(&self.sha256)
                && self.bytes.get() as u64 <= crate::storage_work::MAX_VERIFY_SOURCE_BYTES,
            "invalid protected copy source closure"
        );
        if let Some(etag) = &self.etag {
            ensure!(
                crate::surface_write::strong_if_match_etag(etag)? == *etag,
                "protected copy source tag is not strong"
            );
        }
        Ok(())
    }

    /// Checks the exact retained v2 source and trusted catalogue declaration.
    ///
    /// # Errors
    /// Refuses another incarnation, receipt, tag, byte count or trusted hash.
    pub fn validate_for(&self, original: &ExternalCopyOriginal) -> Result<()> {
        self.validate()?;
        original.validate()?;
        ensure!(
            original.version == 2
                && original.source_object.guard_stamp.as_ref() == Some(&self.guard_stamp)
                && original.source_receipt_digest.as_ref() == Some(&self.receipt_digest)
                && original.expected_sha256.as_ref() == Some(&self.sha256)
                && original.source_object.bytes == self.bytes
                && self
                    .etag
                    .as_ref()
                    .is_none_or(|etag| etag == &original.source_object.etag),
            "protected copy source closure changed"
        );
        Ok(())
    }
}
