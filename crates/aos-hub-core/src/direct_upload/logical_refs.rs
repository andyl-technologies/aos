//! Exact compact references to retained stages and paired baseline witness bindings.
//!
//! These references save repeated metadata bytes. Current independent readback,
//! source correlation, original Complete intent and authority checks still apply.
//!
//! ```json
//! {"session":{"sessionId":"original","logicalFingerprint":"..."},"placementId":"1","recordDigest":"..."}
//! ```

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::*;

/// Exact canonical commitment to a Native-retained verified stage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectRetainedStageDigest {
    /// Original logical session and admission commitment.
    pub session: DirectSessionRef,
    /// Immutable Complete operation that produced this stage.
    pub operation_id: String,
    /// SHA-256 of the complete canonical typed stage document.
    pub evidence_digest: String,
}

impl DirectRetainedStageDigest {
    /// Commits every field of an exact parsed stage document.
    ///
    /// # Errors
    /// Returns an error for malformed stage evidence or serialization failure.
    pub fn from_evidence(evidence: &DirectVerifiedStageEvidence) -> Result<Self> {
        evidence.validate()?;
        Ok(Self {
            session: DirectSessionRef {
                session_id: evidence.session_id.clone(),
                logical_fingerprint: evidence.logical_fingerprint.clone(),
            },
            operation_id: evidence.operation_id.clone(),
            evidence_digest: hex::encode(Sha256::digest(serde_json::to_vec(evidence)?)),
        })
    }

    /// Checks closed reference structure without authorizing physical effects.
    ///
    /// # Errors
    /// Returns an error for malformed session or digest fields.
    pub fn validate(&self) -> Result<()> {
        self.session.validate()?;
        ensure!(
            valid_direct_digest(&self.operation_id) && valid_direct_digest(&self.evidence_digest),
            "direct retained stage reference malformed"
        );
        Ok(())
    }

    /// Expands only the exact immutable stage independently retained by Native.
    ///
    /// # Errors
    /// Returns an error for any substituted stage field or original identity.
    pub fn expand(
        &self,
        retained: &DirectVerifiedStageEvidence,
    ) -> Result<DirectVerifiedStageEvidence> {
        self.validate()?;
        ensure!(
            *self == Self::from_evidence(retained)?,
            "direct retained stage commitment changed"
        );
        Ok(retained.clone())
    }
}

/// Fresh witness whose full original binding is carried by its paired baseline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectBaselineWitnessRef {
    /// Exact original baseline commitment, including its reservation and source.
    pub baseline_digest: String,
    /// Canonical commitment to the omitted full original binding.
    pub binding_digest: String,
    /// Exact signed current observation operation, including its request nonce binding.
    pub observation_operation_id: String,
    /// Inclusive original observation time, never renewed by reference expansion.
    pub issued_at: WireInteger,
    /// Exclusive original current witness deadline.
    pub expires_at: WireInteger,
}

impl DirectBaselineWitnessRef {
    /// Removes only a repeated binding from an exact current witness.
    ///
    /// # Errors
    /// Returns an error for malformed witness fields or serialization failure.
    pub fn from_witness(witness: &DirectDestinationBaselineWitness) -> Result<Self> {
        witness.validate()?;
        Ok(Self {
            baseline_digest: witness.baseline_digest.clone(),
            binding_digest: hex::encode(Sha256::digest(serde_json::to_vec(&witness.binding)?)),
            observation_operation_id: witness.observation_operation_id.clone(),
            issued_at: witness.issued_at,
            expires_at: witness.expires_at,
        })
    }

    /// Restores the exact full witness from its uniquely committed first baseline.
    ///
    /// # Errors
    /// Returns an error for foreign baseline/binding, changed deadlines or malformed fields.
    pub fn expand(
        &self,
        baseline: &DirectDestinationBaselineEvidence,
    ) -> Result<DirectDestinationBaselineWitness> {
        baseline.validate()?;
        ensure!(
            self.baseline_digest == baseline.fingerprint()?
                && self.binding_digest
                    == hex::encode(Sha256::digest(serde_json::to_vec(&baseline.binding)?)),
            "direct compact witness original binding changed"
        );
        let witness = DirectDestinationBaselineWitness {
            binding: baseline.binding.clone(),
            baseline_digest: self.baseline_digest.clone(),
            observation_operation_id: self.observation_operation_id.clone(),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
        };
        witness.validate()?;
        Ok(witness)
    }
}

/// Exact canonical commitment to a final guard record whose originals Native retains.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectFinalGuardRef {
    /// Exact original logical session and admission commitment.
    pub session: DirectSessionRef,
    /// Required original destination whose reservation Native retained.
    pub placement_id: WireInteger,
    /// SHA-256 of every field of the canonical full positive guard record.
    pub record_digest: String,
}

impl DirectFinalGuardRef {
    /// Commits an exact full positive publication record without granting authority.
    ///
    /// # Errors
    /// Returns an error for malformed record structure or serialization failure.
    pub fn from_record(record: &DirectFinalGuardRecord) -> Result<Self> {
        record.validate()?;
        Ok(Self {
            session: record.selected.session.clone(),
            placement_id: record.selected.manifest.placement.placement_id,
            record_digest: hex::encode(Sha256::digest(serde_json::to_vec(record)?)),
        })
    }

    /// Checks reference structure without interpreting its digest as provenance.
    ///
    /// # Errors
    /// Returns an error for malformed original identity, destination or digest.
    pub fn validate(&self) -> Result<()> {
        self.session.validate()?;
        ensure!(
            (1..=i64::MAX as u64).contains(&self.placement_id.get())
                && valid_direct_digest(&self.record_digest),
            "direct final guard reference malformed"
        );
        Ok(())
    }

    /// Restores every record field from Native originals and exact completion evidence.
    ///
    /// The returned record still requires independently fresh authenticated guard
    /// readback. Its digest establishes exact byte correlation, never authority.
    ///
    /// # Errors
    /// Returns an error for missing retained originals, foreign evidence or a changed digest.
    pub fn expand(
        &self,
        admission: &DirectUploadAdmission,
        complete: &DirectCompleteRequest,
        evidence: &DirectCompletionEvidence,
        baselines: &[DirectDestinationBaselineEvidence],
        deployment: &str,
    ) -> Result<DirectFinalGuardRecord> {
        self.validate()?;
        evidence.validate_against(admission, deployment)?;
        ensure!(
            self.session == complete.session
                && self.session.session_id == admission.session_id
                && self.session.logical_fingerprint == admission.logical_fingerprint,
            "direct final guard reference original mismatch"
        );
        let placement = admission
            .placements
            .iter()
            .find(|placement| placement.placement_id == self.placement_id)
            .ok_or_else(|| anyhow::anyhow!("direct final guard placement absent"))?;
        let manifest = complete
            .manifests
            .iter()
            .find(|manifest| manifest.placement.placement_id == self.placement_id)
            .ok_or_else(|| anyhow::anyhow!("direct final guard manifest absent"))?;
        let destination = evidence
            .placements
            .iter()
            .find(|destination| destination.placement_id == self.placement_id)
            .ok_or_else(|| anyhow::anyhow!("direct final guard destination absent"))?;
        let baseline = baselines
            .iter()
            .find(|baseline| {
                baseline.binding.session == self.session
                    && baseline.binding.placement.placement_id == self.placement_id
            })
            .ok_or_else(|| anyhow::anyhow!("direct final guard retained baseline absent"))?;
        baseline.validate_for(
            admission,
            complete,
            deployment,
            &placement.protected_profile_digest,
        )?;
        let record = DirectFinalGuardRecord {
            version: 1,
            reservation: baseline.binding.clone(),
            selected: DirectSelectedCompleteCommitment {
                version: 1,
                session: complete.session.clone(),
                operation_id: complete.operation_id.clone(),
                expected_resource_version: complete.expected_resource_version,
                complete_intent_digest: complete.fingerprint()?,
                manifest: manifest.clone(),
                protected_profile_digest: placement.protected_profile_digest.clone(),
            },
            sha256: evidence.sha256.clone(),
            byte_size: evidence.byte_size,
            source_incarnation: destination.staging_incarnation.clone(),
            final_incarnation: destination.final_incarnation.clone(),
            final_etag: destination.final_etag.clone(),
        };
        record.validate_for(admission, complete, evidence, deployment)?;
        ensure!(
            *self == Self::from_record(&record)?,
            "direct final guard full record changed"
        );
        Ok(record)
    }
}
