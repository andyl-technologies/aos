//! Fresh physical readback for stage integrity and held destination baselines.
//!
//! Authentication uses the independent guard key and distinct request/reply
//! domains. Lookup compares the exact durable originals; it performs no provider
//! mutation and cannot turn an unknown effect into a settled outcome.
//!
//! ```text
//! Stage { admission, complete, evidence }
//! Baseline { admission, complete, evidence, witness }
//! Abort { admission, abort, evidence }
//! ```

use super::*;
use crate::storage_work::StorageWorkKey;
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

/// Protected exact stage/baseline readback endpoint.
pub const DIRECT_AUTHORITY_LOOKUP_PATH: &str = "/_internal/storage/direct-upload-authority";
/// Dedicated stage/baseline request and reply signature header.
pub const DIRECT_AUTHORITY_LOOKUP_SIGNATURE_HEADER: &str = "x-aos-direct-authority-signature";

/// Exact retained original proof to read from storage authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum DirectAuthorityLookupOperation {
    /// Independently computed positively closed original stage evidence.
    Stage {
        /// Original Native logical admission.
        admission: DirectUploadAdmission,
        /// Original exact Complete including every required destination.
        complete: DirectCompleteRequest,
        /// Expected independently retained integrity evidence.
        evidence: DirectVerifiedStageEvidence,
    },
    /// Immutable original baseline and this invocation's separate held witness.
    Baseline {
        /// Original Native logical admission.
        admission: DirectUploadAdmission,
        /// Original exact Complete including every required destination.
        complete: DirectCompleteRequest,
        /// Expected first immutable baseline document.
        evidence: DirectDestinationBaselineEvidence,
        /// Exact current separate physical held-reservation witness.
        witness: DirectDestinationBaselineWitness,
    },
    /// Positive terminal provider abort correlated to the immutable Native CAS.
    Abort {
        /// Complete original Native admission, including required placements.
        admission: DirectUploadAdmission,
        /// First immutable Abort operation and original logical CAS.
        abort: DirectAbortRequest,
        /// Expected exact terminal positive abort receipt commitment.
        evidence: DirectAbortEvidence,
    },
}

/// Fresh exact stage/baseline lookup capsule with independent authentication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectAuthorityLookup {
    /// Exact deployment of the retained physical records.
    pub deployment_id: String,
    /// Fresh random challenge identity.
    pub request_nonce: String,
    /// Inclusive independently qualified issue time.
    pub issued_at: WireInteger,
    /// Exclusive short freshness deadline.
    pub expires_at: WireInteger,
    /// Exact durable originals to read and compare.
    pub operation: DirectAuthorityLookupOperation,
}

impl DirectAuthorityLookup {
    /// Checks the bounded exact challenge and original proof correlations.
    ///
    /// # Errors
    /// Returns an error for malformed or expired challenge or changed originals.
    pub fn validate(&self, deployment: &str, latest_now: u64) -> Result<()> {
        self.validate_context(deployment, Some(latest_now))
    }

    /// Checks retained challenge structure without asserting current authority.
    ///
    /// This observation-only check preserves the original audience, bounded
    /// lifetime and proof correlations. It neither authenticates a capture nor
    /// establishes freshness; execution must use [`Self::validate`].
    ///
    /// # Errors
    /// Returns an error for malformed identity, lifetime, encoding or originals.
    pub fn validate_observation_shape(&self, deployment: &str) -> Result<()> {
        self.validate_context(deployment, None)
    }

    fn validate_context(&self, deployment: &str, latest_now: Option<u64>) -> Result<()> {
        ensure!(
            self.deployment_id == deployment
                && valid_direct_identity(deployment)
                && valid_direct_digest(&self.request_nonce)
                && latest_now.is_none_or(|now| {
                    self.issued_at.get() <= now && now < self.expires_at.get()
                })
                && self
                    .expires_at
                    .get()
                    .checked_sub(self.issued_at.get())
                    .is_some_and(|ttl| (1..=30).contains(&ttl)),
            "direct authority lookup audience or time differs"
        );
        match &self.operation {
            DirectAuthorityLookupOperation::Stage {
                admission,
                complete,
                evidence,
            } => {
                evidence.validate_against(admission, deployment)?;
                ensure!(
                    complete.session.session_id == evidence.session_id
                        && complete.session.logical_fingerprint == evidence.logical_fingerprint
                        && complete.operation_id == evidence.operation_id
                        && complete
                            .manifests
                            .iter()
                            .eq(evidence.placements.iter().map(|item| &item.manifest)),
                    "direct authority original stage differs"
                );
                complete.fingerprint()?;
            }
            DirectAuthorityLookupOperation::Baseline {
                admission,
                complete,
                evidence,
                witness,
            } => {
                evidence.validate_for(
                    admission,
                    complete,
                    deployment,
                    &evidence.binding.protected_profile_digest,
                )?;
                witness.validate()?;
                ensure!(
                    witness.binding == evidence.binding
                        && witness.baseline_digest == evidence.fingerprint()?
                        && latest_now.is_none_or(|now| {
                            witness.issued_at.get() <= now && now < witness.expires_at.get()
                        }),
                    "direct authority current baseline witness differs"
                );
            }
            DirectAuthorityLookupOperation::Abort {
                admission,
                abort,
                evidence,
            } => {
                admission.validate(deployment)?;
                abort.session.validate()?;
                ensure!(
                    abort.session.session_id == admission.session_id
                        && abort.session.logical_fingerprint == admission.logical_fingerprint
                        && valid_direct_digest(&abort.operation_id)
                        && (1..=i64::MAX as u64).contains(&abort.expected_resource_version.get())
                        && evidence.session == abort.session
                        && evidence.operation_id == abort.operation_id
                        && evidence.outcome == DirectAbortOutcome::Aborted
                        && evidence
                            .receipt_digest
                            .as_ref()
                            .is_some_and(|digest| valid_direct_digest(digest)),
                    "direct authority original terminal abort differs"
                );
            }
        }
        encode_direct_control(self)?;
        Ok(())
    }
}

/// Exact fresh lookup echoed only after actual durable guard readback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectAuthorityLookupReply {
    /// Full exact original challenge and retained proof identity.
    pub request: DirectAuthorityLookup,
}

impl DirectAuthorityLookupReply {
    /// Correlates bounded retained metadata with an independently selected original.
    ///
    /// This observation-only check provides no authentication, live authority or
    /// positive physical readback. Those facts require the production verifier
    /// and independently retained transport evidence.
    ///
    /// # Errors
    /// Returns an error for malformed originals, changed challenges or oversized encoding.
    pub fn validate_observation_for(&self, expected: &DirectAuthorityLookup) -> Result<()> {
        expected.validate_observation_shape(&expected.deployment_id)?;
        self.validate_original(expected)?;
        encode_direct_control(self)?;
        Ok(())
    }

    fn validate_original(&self, expected: &DirectAuthorityLookup) -> Result<()> {
        ensure!(
            self.request == *expected,
            "direct authority reply original challenge differs"
        );
        Ok(())
    }
}

/// Signs a stage/baseline challenge under a distinct independent guard domain.
///
/// # Errors
/// Returns an error for encoding or signing failure.
pub fn sign_direct_authority_lookup(
    key: &StorageWorkKey,
    request: &DirectAuthorityLookup,
) -> Result<SignedDirectControl> {
    sign(key, b"aos.direct-upload.authority-request.v1\0", request)
}

/// Authenticates before parsing and validates the fresh original proof challenge.
///
/// # Errors
/// Returns an error for authentication, canonical encoding or original scope/time.
pub fn verify_direct_authority_lookup(
    key: &StorageWorkKey,
    signature: &str,
    body: &[u8],
    deployment: &str,
    latest_now: u64,
) -> Result<DirectAuthorityLookup> {
    let request: DirectAuthorityLookup = verify(
        key,
        b"aos.direct-upload.authority-request.v1\0",
        signature,
        body,
    )?;
    request.validate(deployment, latest_now)?;
    Ok(request)
}

/// Signs an exact response after the storage producer checks its durable originals.
///
/// # Errors
/// Returns an error for encoding or signing failure.
pub fn sign_direct_authority_lookup_reply(
    key: &StorageWorkKey,
    reply: &DirectAuthorityLookupReply,
) -> Result<SignedDirectControl> {
    sign(key, b"aos.direct-upload.authority-reply.v1\0", reply)
}

/// Authenticates and correlates fresh readback with the complete original challenge.
///
/// # Errors
/// Returns an error for authentication, canonical encoding, staleness or changed proof.
pub fn verify_direct_authority_lookup_reply(
    key: &StorageWorkKey,
    signature: &str,
    body: &[u8],
    expected: &DirectAuthorityLookup,
    latest_now: u64,
) -> Result<DirectAuthorityLookupReply> {
    expected.validate(&expected.deployment_id, latest_now)?;
    let reply: DirectAuthorityLookupReply = verify(
        key,
        b"aos.direct-upload.authority-reply.v1\0",
        signature,
        body,
    )?;
    reply.validate_original(expected)?;
    Ok(reply)
}

fn sign<T: Serialize>(
    key: &StorageWorkKey,
    domain: &[u8],
    value: &T,
) -> Result<SignedDirectControl> {
    let body = encode_direct_control(value)?;
    let signature = key.sign_body(&[domain, &body].concat())?;
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
        "direct authority control exceeds bound"
    );
    key.verify_body(signature, &[domain, body].concat())?;
    let value = decode_direct_control(body)?;
    ensure!(
        encode_direct_control(&value)? == body,
        "direct authority control noncanonical"
    );
    Ok(value)
}
