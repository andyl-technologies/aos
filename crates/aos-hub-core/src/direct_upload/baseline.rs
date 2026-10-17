//! Immutable destination baselines and separately refreshed held-read witnesses.
//!
//! These metadata contracts describe provider observations made under a retained
//! physical reservation. Validation cannot establish provider or guard provenance.
//! A fresh witness never rewrites the first observation or settles unknown writes.
//!
//! ```json
//! {"kind":"missing"}
//! ```

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::storage_authority::{PhysicalStorageAuthorityId, StorageGuardStamp};

use super::*;

/// Physical reservation domain independently checked against protected configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum DirectDestinationReservationScope {
    /// Managed guard whose address remains deployment plus full-key digest.
    Managed {
        /// Independently configured permanent bucket namespace, not inferred from the address.
        bucket_namespace: String,
    },
    /// External authority whose profile also pins the actual guard namespace.
    External {
        /// Permanent physical authority of the admitted destination.
        physical_authority_id: PhysicalStorageAuthorityId,
    },
}

/// Exact original completion and physical reservation shared by all baseline proofs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectDestinationBaselineBinding {
    /// Actual deployment audience from protected admission.
    pub deployment_id: String,
    /// Original session and immutable admission fingerprint.
    pub session: DirectSessionRef,
    /// Original immutable admission horizon, never renewed by transport or witness.
    pub admission_expires_at: WireInteger,
    /// Original Complete operation, unchanged across private steps.
    pub complete_operation_id: String,
    /// Canonical exact original Complete intent commitment, including CAS and manifests.
    pub complete_intent_digest: String,
    /// Complete original placement, writer, binding, profile and policy commitments.
    pub placement: DirectPlacementRef,
    /// Exact independently reviewed whole protected profile, including guard namespace and timing.
    pub protected_profile_digest: String,
    /// Domain-separated digest of the canonical full physical final key.
    pub final_key_digest: String,
    /// Actual configured physical reservation domain.
    pub scope: DirectDestinationReservationScope,
    /// Original retained destination reservation operation, distinct from observation operations.
    pub reservation_operation_id: String,
    /// Guard-issued receipt commitment; this is not an authentication secret.
    pub reservation_nonce: String,
    /// Positive reservation counter, distinct from an object incarnation or Missing stamp.
    pub reservation_revision: WireInteger,
}

/// First observed destination state under the held reservation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum DirectDestinationBaselineState {
    /// Positive same-action provider not-found; carries no object identity or digest.
    Missing {},
    /// Whole-object identity from a qualified held read or matching original receipt.
    Present {
        /// Exact actual object size, independently of the intended replacement size.
        byte_size: WireInteger,
        /// Full measured SHA-256; ETag and length cannot manufacture this field.
        sha256: String,
        /// Strong provider ETag of the exact held object observation.
        etag: String,
        /// Actual unique provider object version when supplied, never a multipart UploadId.
        provider_version: Option<String>,
        /// Existing independently proven object guard stamp, never synthesized for legacy bytes.
        guard_stamp: Option<StorageGuardStamp>,
    },
}

/// Immutable first baseline document retained before Native quota activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectDestinationBaselineEvidence {
    /// Original completion and actual retained physical reservation.
    pub binding: DirectDestinationBaselineBinding,
    /// Stable original baseline observation operation.
    pub observation_operation_id: String,
    /// Original inclusive observation issue time; retries never replace it.
    pub issued_at: WireInteger,
    /// Original exclusive observation deadline; a later witness cannot renew it.
    pub expires_at: WireInteger,
    /// Exact immutable first Missing or Present result.
    pub state: DirectDestinationBaselineState,
}

/// Fresh observation that the same reservation and original baseline remain held.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectDestinationBaselineWitness {
    /// Exact unchanged original reservation and Complete intent.
    pub binding: DirectDestinationBaselineBinding,
    /// Digest of the first immutable baseline document.
    pub baseline_digest: String,
    /// Separately retained current witness operation, not the first read operation.
    pub observation_operation_id: String,
    /// Inclusive time of this invocation's actual held reservation/incarnation check.
    pub issued_at: WireInteger,
    /// Exclusive current check deadline, bounded by fresh authorization.
    pub expires_at: WireInteger,
}

/// Native permission returned only after the exact baseline activation transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectDestinationBaselinePermission {
    /// Exact original completion, placement and retained reservation.
    pub binding: DirectDestinationBaselineBinding,
    /// First immutable baseline document retained by Native activation.
    pub baseline_digest: String,
    /// Exact fresh witness checked for this authorization invocation.
    pub witness_digest: String,
    /// Fresh private request nonce; earlier permissions cannot authorize another invocation.
    pub request_nonce: String,
    /// Exclusive permission deadline clipped to the fresh request and witness.
    pub expires_at: WireInteger,
}

impl DirectDestinationBaselineBinding {
    /// Checks structural scope without asserting a live reservation or provider fact.
    ///
    /// # Errors
    /// Returns a value-free error for malformed identity, counters or commitments.
    pub fn validate(&self) -> Result<()> {
        self.session.validate()?;
        self.placement.validate()?;
        ensure!(
            valid_direct_identity(&self.deployment_id)
                && [
                    &self.complete_operation_id,
                    &self.complete_intent_digest,
                    &self.protected_profile_digest,
                    &self.final_key_digest,
                    &self.reservation_operation_id,
                    &self.reservation_nonce
                ]
                .iter()
                .all(|value| valid_direct_digest(value))
                && (1..=i64::MAX as u64).contains(&self.reservation_revision.get())
                && (1..=i64::MAX as u64).contains(&self.admission_expires_at.get()),
            "invalid direct baseline binding"
        );
        if let DirectDestinationReservationScope::Managed { bucket_namespace } = &self.scope {
            ensure!(
                valid_direct_identity(bucket_namespace),
                "invalid direct baseline namespace"
            );
        }
        ensure!(
            self.reservation_operation_id
                == direct_destination_promotion_operation_id(
                    &self.session,
                    self.placement.placement_id,
                    &self.complete_operation_id
                )?,
            "direct baseline original reservation operation mismatch"
        );
        Ok(())
    }

    /// Correlates the original intent, placement and independently selected protected profile.
    ///
    /// # Errors
    /// Returns an error for changed audience, admission, complete intent, key or physical domain.
    pub fn validate_for(
        &self,
        admission: &DirectUploadAdmission,
        complete: &DirectCompleteRequest,
        deployment: &str,
        protected_profile_digest: &str,
    ) -> Result<()> {
        self.validate()?;
        admission.validate(deployment)?;
        ensure!(
            self.deployment_id == deployment
                && valid_direct_digest(protected_profile_digest)
                && self.protected_profile_digest == protected_profile_digest
                && self.session.session_id == admission.session_id
                && self.session.logical_fingerprint == admission.logical_fingerprint
                && self.admission_expires_at == admission.expires_at
                && self.session == complete.session
                && self.complete_operation_id == complete.operation_id
                && self.complete_intent_digest == complete.fingerprint()?,
            "direct baseline original intent mismatch"
        );
        let expected_part_count = admission.intent.part_count()?;
        ensure!(
            complete
                .manifests
                .iter()
                .all(|manifest| manifest.part_count == expected_part_count),
            "direct baseline complete geometry mismatch"
        );
        let placement = admission
            .placements
            .iter()
            .find(|value| value.placement_id == self.placement.placement_id)
            .ok_or_else(|| anyhow::anyhow!("direct baseline placement absent"))?;
        ensure!(
            self.protected_profile_digest == placement.protected_profile_digest
                && self.placement == placement.public_ref(deployment)?
                && self.final_key_digest == direct_destination_key_digest(&placement.final_key)?
                && complete
                    .manifests
                    .iter()
                    .any(|manifest| manifest.placement == self.placement),
            "direct baseline placement mismatch"
        );
        let matches_scope = match (&self.scope, &placement.physical) {
            (
                DirectDestinationReservationScope::Managed { bucket_namespace },
                DirectPhysicalContext::DeploymentR2 {
                    deployment_id,
                    bucket_namespace: original,
                },
            ) => deployment_id == deployment && bucket_namespace == original,
            (
                DirectDestinationReservationScope::External {
                    physical_authority_id,
                },
                DirectPhysicalContext::External { write_cohort, .. },
            ) => physical_authority_id == &write_cohort.authority.authority_id,
            _ => false,
        };
        ensure!(matches_scope, "direct baseline physical scope mismatch");
        Ok(())
    }
}

impl DirectDestinationBaselineEvidence {
    /// Checks the immutable document's structure; historical expiry is not freshness proof.
    ///
    /// # Errors
    /// Returns an error for malformed state, identity, deadlines or excessive encoding.
    pub fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        observation(
            &self.observation_operation_id,
            self.issued_at,
            self.expires_at,
        )?;
        ensure!(
            self.observation_operation_id != self.binding.reservation_operation_id
                && self.expires_at.get() <= self.binding.admission_expires_at.get(),
            "direct baseline original observation or admission horizon mismatch"
        );
        if let DirectDestinationBaselineState::Present {
            byte_size,
            sha256,
            etag,
            provider_version,
            guard_stamp,
        } = &self.state
        {
            ensure!(
                byte_size.get() <= MAX_DIRECT_OBJECT_BYTES
                    && valid_direct_digest(sha256)
                    && (byte_size.get() > 0 || *sha256 == hex::encode(Sha256::digest(b"")))
                    && valid_direct_etag(etag),
                "invalid direct present baseline"
            );
            ensure!(
                provider_version
                    .as_ref()
                    .is_none_or(|version| !version.is_empty()
                        && version.len() <= 1024
                        && !version.chars().any(char::is_control)),
                "invalid direct baseline provider version"
            );
            if let Some(stamp) = guard_stamp {
                ensure!(
                    matches!(&self.binding.scope, DirectDestinationReservationScope::External { physical_authority_id }
                    if physical_authority_id == &stamp.physical_authority_id),
                    "direct baseline guard authority mismatch"
                );
            }
        }
        ensure!(
            encode_direct_control(self)?.len() <= 64 * 1024,
            "direct baseline evidence exceeds limit"
        );
        Ok(())
    }

    /// Checks exact original admission and eligibility without renewing the first read.
    ///
    /// # Errors
    /// Returns an error for changed scope or an original deadline beyond admission eligibility.
    pub fn validate_for(
        &self,
        admission: &DirectUploadAdmission,
        complete: &DirectCompleteRequest,
        deployment: &str,
        protected_profile_digest: &str,
    ) -> Result<()> {
        self.validate()?;
        self.binding
            .validate_for(admission, complete, deployment, protected_profile_digest)?;
        ensure!(
            self.expires_at.get() <= admission.expires_at.get(),
            "direct baseline admission deadline mismatch"
        );
        Ok(())
    }

    /// Returns the bounded domain-separated commitment of the first immutable document.
    ///
    /// # Errors
    /// Returns an error for invalid evidence or excessive encoding.
    pub fn fingerprint(&self) -> Result<String> {
        self.validate()?;
        document_digest(b"aos.direct-upload.destination-baseline.v1\0", self)
    }
}

impl DirectDestinationBaselineWitness {
    /// Checks structural fields without treating archived data as a current observation.
    ///
    /// # Errors
    /// Returns an error for malformed commitment, binding or observation interval.
    pub fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        ensure!(
            valid_direct_digest(&self.baseline_digest),
            "invalid direct baseline witness digest"
        );
        ensure!(
            self.observation_operation_id != self.binding.reservation_operation_id
                && self.expires_at.get() <= self.binding.admission_expires_at.get(),
            "direct baseline witness operation or admission horizon mismatch"
        );
        observation(
            &self.observation_operation_id,
            self.issued_at,
            self.expires_at,
        )
    }

    /// Checks exact original baseline and this invocation's conservative current bound.
    ///
    /// The adapter must actually check the held reservation and original incarnation;
    /// these fields and a signature cannot establish that provenance.
    ///
    /// # Errors
    /// Returns an error for changed original proof or a future/expired current witness.
    pub fn validate_for(
        &self,
        baseline: &DirectDestinationBaselineEvidence,
        context: &DirectRequestContext,
        latest_now: u64,
    ) -> Result<()> {
        self.validate()?;
        context.validate(
            &self.binding.deployment_id,
            &context.executor_public_origin,
            latest_now,
        )?;
        ensure!(
            self.binding == baseline.binding
                && self.baseline_digest == baseline.fingerprint()?
                && self.observation_operation_id != baseline.observation_operation_id
                && context.issued_at.get() <= self.issued_at.get()
                && self.issued_at.get() <= latest_now
                && latest_now < self.expires_at.get()
                && self.expires_at.get() <= context.expires_at.get(),
            "direct baseline witness correlation or expiry mismatch"
        );
        Ok(())
    }

    /// Returns the domain-separated commitment of this distinct witness document.
    ///
    /// # Errors
    /// Returns an error for malformed witness or excessive encoding.
    pub fn fingerprint(&self) -> Result<String> {
        self.validate()?;
        document_digest(b"aos.direct-upload.destination-baseline-witness.v1\0", self)
    }
}

impl DirectDestinationBaselinePermission {
    /// Checks structural permission fields; only Native's actual commit grants permission.
    ///
    /// # Errors
    /// Returns an error for malformed binding, digests, nonce or deadline.
    pub fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        ensure!(
            [
                &self.baseline_digest,
                &self.witness_digest,
                &self.request_nonce
            ]
            .iter()
            .all(|value| valid_direct_digest(value))
                && (1..=i64::MAX as u64).contains(&self.expires_at.get())
                && self.expires_at.get() <= self.binding.admission_expires_at.get(),
            "invalid direct baseline permission"
        );
        Ok(())
    }

    /// Correlates the permission with the first baseline and exact fresh witness/context.
    ///
    /// # Errors
    /// Returns an error for changed reservation, proof, request nonce or exclusive expiry.
    pub fn validate_for(
        &self,
        baseline: &DirectDestinationBaselineEvidence,
        witness: &DirectDestinationBaselineWitness,
        context: &DirectRequestContext,
        latest_now: u64,
    ) -> Result<()> {
        self.validate()?;
        witness.validate_for(baseline, context, latest_now)?;
        ensure!(
            self.binding == baseline.binding
                && self.baseline_digest == baseline.fingerprint()?
                && self.witness_digest == witness.fingerprint()?
                && self.request_nonce == context.request_nonce
                && self.expires_at == witness.expires_at,
            "direct baseline permission correlation mismatch"
        );
        Ok(())
    }
}

/// Derives the original logical destination owner from the exact retained completion.
///
/// The historical managed domain and typed JSON tuple remain unchanged so existing
/// retained addresses survive this extraction. External reservations may use the
/// same logical owner only after independently validating original admission and
/// physical scope. The digest grants no provider authority; SDK effects keep
/// distinct operation IDs and durable reservations.
///
/// # Errors
/// Returns an error for malformed original session, placement or Complete identity.
pub fn direct_destination_promotion_operation_id(
    session: &DirectSessionRef,
    placement_id: WireInteger,
    complete_operation_id: &str,
) -> Result<String> {
    session.validate()?;
    ensure!(
        (1..=i64::MAX as u64).contains(&placement_id.get())
            && valid_direct_digest(complete_operation_id),
        "invalid direct destination logical owner"
    );
    let address = encode_direct_control(&(session, placement_id, complete_operation_id))?;
    let mut digest = Sha256::new();
    digest.update(b"aos.direct-upload.managed-promotion-operation.v1\0");
    digest.update(address);
    Ok(hex::encode(digest.finalize()))
}

/// Commits the existing canonical full-key representation without URL decoding.
///
/// # Errors
/// Returns an error for a noncanonical or oversized physical key.
pub fn direct_destination_key_digest(key: &str) -> Result<String> {
    ensure!(
        valid_direct_path(key),
        "invalid direct baseline physical key"
    );
    let mut digest = Sha256::new();
    digest.update(b"aos.direct-upload.destination-key.v1\0");
    digest.update((key.len() as u64).to_be_bytes());
    digest.update(key.as_bytes());
    Ok(hex::encode(digest.finalize()))
}

fn observation(operation: &str, issued_at: WireInteger, expires_at: WireInteger) -> Result<()> {
    ensure!(
        valid_direct_digest(operation)
            && issued_at.get() > 0
            && issued_at.get() < expires_at.get()
            && expires_at.get() <= i64::MAX as u64,
        "invalid direct baseline observation interval"
    );
    Ok(())
}

fn document_digest<T: Serialize>(domain: &[u8], value: &T) -> Result<String> {
    let bytes = encode_direct_control(value)?;
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
    Ok(hex::encode(digest.finalize()))
}

#[cfg(test)]
mod tests;
