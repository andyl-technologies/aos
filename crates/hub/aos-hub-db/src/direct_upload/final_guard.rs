//! Independently authenticated final publication records from physical guards.
//!
//! The publication producer commits the original selected Complete and verified
//! source before dispatch. A fresh lookup reads that durable record and refuses
//! every unresolved physical effect. Broker authentication and provider HEAD
//! observations cannot mint this record.
//!
//! ```text
//! reservation -> pending provider effect -> acknowledged exact incarnation
//! Native fresh challenge -> physical guard record -> independent authentication
//! ```

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

use crate::storage_work::StorageWorkKey;

use super::*;

/// Internal endpoint for independently authenticated final publication lookup.
pub const DIRECT_FINAL_GUARD_PATH: &str = "/_internal/storage/direct-upload-final-guard";
/// Dedicated final guard challenge/reply signature header.
pub const DIRECT_FINAL_GUARD_SIGNATURE_HEADER: &str = "x-aos-direct-final-guard-signature";

const REQUEST_DOMAIN: &[u8] = b"aos.direct-upload.final-guard-request.v1\0";
const REPLY_DOMAIN: &[u8] = b"aos.direct-upload.final-guard-reply.v1\0";

/// Exact source, original Complete and final physical identity retained by a guard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectFinalGuardRecord {
    /// Closed record version, currently one.
    pub version: u32,
    /// Original reservation and complete intent, including permanent physical scope.
    pub reservation: DirectDestinationBaselineBinding,
    /// Compact selected destination binding plus digest of the entire Complete.
    pub selected: DirectSelectedCompleteCommitment,
    /// Full independently streamed original source SHA-256.
    pub sha256: String,
    /// Exact independently counted source bytes.
    pub byte_size: WireInteger,
    /// Positively closed immutable source incarnation.
    pub source_incarnation: DirectObjectIncarnation,
    /// Exact final incarnation from the positive publication acknowledgement.
    pub final_incarnation: DirectObjectIncarnation,
    /// Strong ETag from the positive publication acknowledgement.
    pub final_etag: String,
}

impl DirectFinalGuardRecord {
    /// Checks exact original binding and acknowledged incarnation structure.
    ///
    /// # Errors
    /// Returns an error for inconsistent scope, original Complete or source identity.
    pub fn validate(&self) -> Result<()> {
        self.reservation.validate()?;
        self.selected.validate()?;
        ensure!(
            self.version == 1
                && self.selected.session == self.reservation.session
                && self.selected.operation_id == self.reservation.complete_operation_id
                && self.selected.complete_intent_digest == self.reservation.complete_intent_digest
                && self.selected.manifest.placement == self.reservation.placement
                && self.selected.protected_profile_digest
                    == self.reservation.protected_profile_digest
                && valid_direct_digest(&self.sha256)
                && self.byte_size.get() <= MAX_DIRECT_OBJECT_BYTES
                && valid_direct_etag(&self.final_etag),
            "direct final guard original identity mismatch"
        );
        for incarnation in [&self.source_incarnation, &self.final_incarnation] {
            match (incarnation, &self.reservation.scope) {
                (
                    DirectObjectIncarnation::ProviderVersion { version },
                    DirectDestinationReservationScope::Managed { .. },
                ) => {
                    ensure!(
                        crate::storage_work::valid_provider_version(version),
                        "direct final guard provider incarnation invalid"
                    );
                }
                (
                    DirectObjectIncarnation::GuardStamp { stamp },
                    DirectDestinationReservationScope::External {
                        physical_authority_id,
                    },
                ) => {
                    ensure!(
                        &stamp.physical_authority_id == physical_authority_id,
                        "direct final guard authority mismatch"
                    );
                }
                _ => anyhow::bail!("direct final guard incarnation scope differs"),
            }
        }
        encode_direct_control(self)?;
        Ok(())
    }

    /// Correlates a guard record with Native's retained originals and broker evidence.
    ///
    /// # Errors
    /// Returns an error for changed admission, Complete, placement or evidence.
    pub fn validate_for(
        &self,
        admission: &DirectUploadAdmission,
        complete: &DirectCompleteRequest,
        evidence: &DirectCompletionEvidence,
        deployment: &str,
    ) -> Result<()> {
        self.validate()?;
        evidence.validate_against(admission, deployment)?;
        ensure!(
            self.selected.expected_resource_version == complete.expected_resource_version
                && self.selected.complete_intent_digest == complete.fingerprint()?
                && evidence.operation_id == complete.operation_id
                && self.sha256 == evidence.sha256
                && self.byte_size == evidence.byte_size,
            "direct final guard evidence identity differs"
        );
        let placement = evidence
            .placements
            .iter()
            .find(|item| item.placement_id == self.reservation.placement.placement_id)
            .ok_or_else(|| anyhow::anyhow!("direct final guard evidence destination absent"))?;
        self.validate_placement_for(admission, complete, placement, deployment)
    }

    /// Correlates one settled placement without fabricating unpublished destinations.
    ///
    /// The full original Complete binds the required set. This method checks the
    /// exact selected placement, immutable source and acknowledged final identity.
    ///
    /// # Errors
    /// Returns an error for changed originals, source bytes or placement evidence.
    pub fn validate_placement_for(
        &self,
        admission: &DirectUploadAdmission,
        complete: &DirectCompleteRequest,
        placement: &DirectPlacementEvidence,
        deployment: &str,
    ) -> Result<()> {
        self.validate()?;
        self.reservation.validate_for(
            admission,
            complete,
            deployment,
            &self.selected.protected_profile_digest,
        )?;
        ensure!(
            self.selected.expected_resource_version == complete.expected_resource_version
                && self.selected.complete_intent_digest == complete.fingerprint()?
                && self.sha256 == admission.intent.expected_sha256
                && self.byte_size == admission.intent.byte_size
                && placement.placement_id == self.reservation.placement.placement_id,
            "direct final guard selected source or destination differs"
        );
        ensure!(
            placement.manifest == self.selected.manifest
                && placement.promotion_operation_id == self.reservation.reservation_operation_id
                && placement.staging_incarnation == self.source_incarnation
                && placement.final_incarnation == self.final_incarnation
                && placement.final_etag == self.final_etag,
            "direct final guard publication evidence differs"
        );
        Ok(())
    }
}

/// Fresh exact lookup challenge, independent of the broker result signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectFinalGuardLookup {
    /// Original Native admission used to address the permanent physical-key guard.
    pub admission: DirectUploadAdmission,
    /// Exact original full Complete used to validate the selected final binding.
    pub complete: DirectCompleteRequest,
    /// Exact expected durable record, constructed from retained Native originals.
    pub expected: DirectFinalGuardRecord,
    /// Fresh challenge identity, never a provider operation identity.
    pub request_nonce: String,
    /// Inclusive issue time from an independently qualified clock.
    pub issued_at: WireInteger,
    /// Exclusive lookup deadline of at most thirty seconds.
    pub expires_at: WireInteger,
}

impl DirectFinalGuardLookup {
    /// Checks a bounded fresh exact physical guard challenge.
    ///
    /// # Errors
    /// Returns an error for malformed identity or an expired/future challenge.
    pub fn validate(&self, deployment: &str, latest_now: u64) -> Result<()> {
        self.validate_context(deployment, Some(latest_now))
    }

    /// Checks retained final-guard structure without asserting current authority.
    ///
    /// The original admission, Complete, record and bounded challenge lifetime
    /// remain exact. This observation-only check does not authenticate captures
    /// or establish freshness; execution must use [`Self::validate`].
    ///
    /// # Errors
    /// Returns an error for malformed records, originals, lifetime or encoding.
    pub fn validate_observation_shape(&self, deployment: &str) -> Result<()> {
        self.validate_context(deployment, None)
    }

    fn validate_context(&self, deployment: &str, latest_now: Option<u64>) -> Result<()> {
        self.expected.validate()?;
        self.expected.reservation.validate_for(
            &self.admission,
            &self.complete,
            deployment,
            &self.expected.selected.protected_profile_digest,
        )?;
        ensure!(
            self.expected.selected.expected_resource_version
                == self.complete.expected_resource_version,
            "direct final guard original Complete CAS differs"
        );
        ensure!(
            self.expected.reservation.deployment_id == deployment
                && valid_direct_digest(&self.request_nonce)
                && latest_now.is_none_or(|now| {
                    self.issued_at.get() <= now && now < self.expires_at.get()
                })
                && self
                    .expires_at
                    .get()
                    .checked_sub(self.issued_at.get())
                    .is_some_and(|ttl| (1..=30).contains(&ttl)),
            "direct final guard challenge audience or time differs"
        );
        encode_direct_control(self)?;
        Ok(())
    }
}

/// Fresh exact challenge response minted only after reading settled guard state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectFinalGuardReply {
    /// Exact challenge including expected original incarnation and nonce.
    pub request: DirectFinalGuardLookup,
    /// Independently retained acknowledged publication record.
    pub record: DirectFinalGuardRecord,
}

impl DirectFinalGuardReply {
    /// Correlates retained final-guard metadata with the complete original challenge.
    ///
    /// This observation-only check does not authenticate a reply, establish live
    /// authority or prove publication. Production verification and independently
    /// retained transport evidence remain necessary for those facts.
    ///
    /// # Errors
    /// Returns an error for malformed records, changed originals or oversized encoding.
    pub fn validate_observation_for(&self, expected: &DirectFinalGuardLookup) -> Result<()> {
        expected.validate_observation_shape(&expected.expected.reservation.deployment_id)?;
        self.validate_original(expected)?;
        encode_direct_control(self)?;
        Ok(())
    }

    fn validate_original(&self, expected: &DirectFinalGuardLookup) -> Result<()> {
        self.record.validate()?;
        ensure!(
            self.request == *expected && self.record == expected.expected,
            "direct final guard reply correlation differs"
        );
        Ok(())
    }
}

/// Signs an exact fresh guard challenge under a dedicated authentication domain.
///
/// # Errors
/// Returns an error for encoding or signing failure.
pub fn sign_direct_final_guard_lookup(
    key: &StorageWorkKey,
    request: &DirectFinalGuardLookup,
) -> Result<SignedDirectControl> {
    request.expected.validate()?;
    sign(key, REQUEST_DOMAIN, request)
}

/// Authenticates a fresh guard challenge before parsing any supplied identity.
///
/// # Errors
/// Returns an error for authentication, noncanonical bytes or stale challenge.
pub fn verify_direct_final_guard_lookup(
    key: &StorageWorkKey,
    signature: &str,
    body: &[u8],
    deployment: &str,
    latest_now: u64,
) -> Result<DirectFinalGuardLookup> {
    let value: DirectFinalGuardLookup = verify(key, REQUEST_DOMAIN, signature, body)?;
    value.validate(deployment, latest_now)?;
    Ok(value)
}

/// Signs the exact guard response after the producer checks durable settled state.
///
/// # Errors
/// Returns an error for inconsistent records, encoding or signing failure.
pub fn sign_direct_final_guard_reply(
    key: &StorageWorkKey,
    reply: &DirectFinalGuardReply,
) -> Result<SignedDirectControl> {
    reply.record.validate()?;
    ensure!(
        reply.record == reply.request.expected,
        "direct final guard stored record differs"
    );
    sign(key, REPLY_DOMAIN, reply)
}

/// Authenticates and correlates the independent guard response with a fresh challenge.
///
/// # Errors
/// Returns an error for authentication, stale context or changed durable record.
pub fn verify_direct_final_guard_reply(
    key: &StorageWorkKey,
    signature: &str,
    body: &[u8],
    expected: &DirectFinalGuardLookup,
    latest_now: u64,
) -> Result<DirectFinalGuardReply> {
    expected.validate(&expected.expected.reservation.deployment_id, latest_now)?;
    let value: DirectFinalGuardReply = verify(key, REPLY_DOMAIN, signature, body)?;
    value.validate_original(expected)?;
    Ok(value)
}

fn sign<T: Serialize>(
    key: &StorageWorkKey,
    domain: &[u8],
    value: &T,
) -> Result<SignedDirectControl> {
    let body = encode_direct_control(value)?;
    let signature = key.sign_body(&[domain, body.as_slice()].concat())?;
    Ok(SignedDirectControl { body, signature })
}

fn verify<T: serde::de::DeserializeOwned + Serialize>(
    key: &StorageWorkKey,
    domain: &[u8],
    signature: &str,
    body: &[u8],
) -> Result<T> {
    ensure!(
        body.len() <= MAX_DIRECT_CONTROL_BYTES,
        "direct final guard control exceeds bound"
    );
    key.verify_body(signature, &[domain, body].concat())?;
    let value = decode_direct_control(body)?;
    ensure!(
        encode_direct_control(&value)? == body,
        "direct final guard control noncanonical"
    );
    Ok(value)
}
