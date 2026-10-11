//! Native-prepared OCI staging controls and independent positive readback port.
//!
//! The application signature authenticates an already reserved upload and
//! current IAM/writer decision. The signature contains neither credential
//! material nor a provider URL. Returning a permit creates no physical receipt.

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use super::{
    OciActorOriginal, OciBytes, OciUploadOriginal, OciWriterOriginal,
    control::{ExternalOciRequest, OciControl},
};
use crate::db::{Database, OciSha256State, OciUploadRecord};

mod current;

/// Exact real reservation and current actor prepared before any Worker body read.
#[derive(Clone, Debug)]
pub struct ExternalOciStagePreparation {
    /// Current existing upload; staging writer was atomically reserved first.
    pub upload: OciUploadRecord,
    /// Fresh genuinely authenticated current OCI grant, not an upload owner label.
    pub actor: OciActorOriginal,
    /// Exact ready SQL writer selected and checked in the reservation transaction.
    pub writer: OciWriterOriginal,
    /// Immutable placement-relative private key selected for this chunk attempt.
    pub staging_key: String,
    /// Zero-based current chunk position.
    pub ordinal: u32,
    /// Contiguous full-upload byte count before this chunk.
    pub offset: u64,
    /// Existing portable full-upload continuation before consuming this chunk.
    pub prior_sha256: OciSha256State,
    /// Largest permitted public chunk, never more than the remaining upload bound.
    pub maximum_bytes: u64,
    /// Full bytes already committed by manifest preflight, when applicable.
    pub expected: Option<OciBytes>,
}

impl ExternalOciStagePreparation {
    /// Derives the private key for one genuine reserved upload position.
    ///
    /// Current IAM grants and writer authority stay in the separately checked
    /// original. They never select a fresh guard when an earlier effect at
    /// this upload position is unresolved.
    ///
    /// # Errors
    /// Refuses an invalid live upload or canonical commitment failure.
    pub fn chunk_key(upload: &OciUploadRecord, ordinal: u32) -> Result<String> {
        OciUploadOriginal::from_record(upload)?;
        let attempt = crate::storage_authority::canonical_digest(&(
            "aos.external-oci-chunk-key.v2",
            &upload.id,
            upload.resource_version,
            ordinal,
        ))?;
        Ok(format!(
            "oci/uploads/{}/chunks/{ordinal}-{}",
            upload.id,
            &attempt[..32]
        ))
    }

    /// Checks the reserved real writer and exact bounded upload continuation.
    ///
    /// # Errors
    /// Refuses a missing reservation, changed writer or excessive geometry.
    pub fn validate(&self) -> Result<()> {
        OciUploadOriginal::from_record(&self.upload)?;
        self.actor.validate()?;
        self.writer.validate()?;
        self.prior_sha256.validate()?;
        ensure!(
            self.upload.staging_placement_id == Some(self.writer.placement_id.get())
                && self.upload.staging_placement_resource_version
                    == Some(self.writer.placement_resource_version.get())
                && self.upload.staging_binding_id == Some(self.writer.binding_id.get())
                && self.upload.staging_binding_write_revision
                    == Some(self.writer.binding_write_revision.get())
                && self.prior_sha256.total_bytes == self.offset
                && self.maximum_bytes > 0
                && self.maximum_bytes <= super::MAX_EXTERNAL_OCI_CHUNK_BYTES
                && self
                    .offset
                    .checked_add(self.maximum_bytes)
                    .is_some_and(|end| end <= self.upload.maximum_size),
            "external OCI staging differs from its actual writer reservation"
        );
        if let Some(expected) = &self.expected {
            expected.validate()?;
            ensure!(
                expected.size > 0 && expected.size <= self.maximum_bytes,
                "external OCI staging exceeds its exact original bytes"
            );
        }
        Ok(())
    }
}

/// Carries a Native-generated exact short-lived Stage control to the Worker.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalOciStagePermit {
    /// Exact application original and independently current phase grant.
    pub request: ExternalOciRequest,
    /// Application-role MAC of the canonical full request.
    pub signature: String,
}

impl ExternalOciStagePermit {
    /// Checks the exact public admission shape without accepting its MAC.
    ///
    /// # Errors
    /// Refuses another phase, malformed signature or excessive metadata.
    pub fn validate_shape(&self) -> Result<()> {
        self.request.original.validate()?;
        ensure!(
            matches!(self.request.operation, OciControl::Stage)
                && self.signature.len() == 64
                && self
                    .signature
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                && serde_json::to_vec(self)?.len() <= 16 * 1024,
            "external OCI stage permit has invalid shape or exceeds metadata bound"
        );
        Ok(())
    }
}
