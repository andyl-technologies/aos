//! Metadata-only versioned deletion under a genuine frozen SQL cleanup claim.
//!
//! ```text
//! request = {claim: <existing frozen custody original>, expected_provider_version}
//! reply = {request, outcome, observed_at}
//! ```
//!
//! The held material is resolved only inside Worker custody. A fresh challenge
//! cannot replace the stable action identity or close an unknown provider turn.

use super::*;
use crate::storage_authority::external_object::ExternalObjectOutcome;
use crate::storage_work::{valid_provider_version, StorageFrozenCleanupOperation};

/// Native metadata route for one exact frozen versioned deletion.
pub const STORAGE_FROZEN_DELETE_CUSTODY_PATH: &str = "/_internal/storage/v1/frozen-delete-custody";
const REQUEST: &[u8] = b"aos.storage-frozen-delete-custody.request.v1\0";
const REPLY: &[u8] = b"aos.storage-frozen-delete-custody.reply.v1\0";

/// Binds the existing full frozen claim to its reviewed provider incarnation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageFrozenDeleteCustodyRequest {
    /// Fresh existing claim, held delete reference and exact physical address.
    pub claim: StorageFrozenCleanupCustodyRequest,
    /// Actual immutable provider version from this claim's reviewed inventory.
    pub expected_provider_version: String,
}

impl StorageFrozenDeleteCustodyRequest {
    /// Validates the bounded live claim and exact version selector.
    ///
    /// # Errors
    /// Returns an error for stale or changed scope, another operation, absent
    /// version, or a provider's nonversioned `null` sentinel.
    pub fn validate(&self, deployment: &str, now: i64) -> Result<(), StorageWorkError> {
        self.claim.validate(deployment, now)?;
        if self.claim.operation != StorageFrozenCleanupOperation::DeleteIfMatches
            || !valid_provider_version(&self.expected_provider_version)
            || self.expected_provider_version == "null"
        {
            return Err(StorageWorkError::InvalidPlan);
        }
        Ok(())
    }
}

/// Authenticated terminal evidence for the original frozen deletion turn.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageFrozenDeleteCustodyReply {
    /// Exact current challenge and unchanged full original claim.
    pub request: StorageFrozenDeleteCustodyRequest,
    /// Positive exact-version receipt, absence, or precondition refusal.
    pub outcome: ExternalObjectOutcome,
    /// Actual reply observation time, before the original application cutoff.
    pub observed_at: i64,
}

requests!(
    sign_storage_frozen_delete_custody,
    verify_storage_frozen_delete_custody,
    StorageFrozenDeleteCustodyRequest,
    REQUEST
);

/// Signs a bounded metadata-only frozen deletion reply.
///
/// # Errors
/// Returns an error for encoding or response bounds.
pub fn sign_storage_frozen_delete_custody_reply(
    key: &StorageWorkKey,
    reply: &StorageFrozenDeleteCustodyReply,
) -> Result<SignedStorageCustodyControl, StorageWorkError> {
    sign(key, REPLY, reply)
}

/// Verifies exact original correlation and positive deletion evidence.
///
/// # Errors
/// Returns an error for signature, changed claim/version/ETag, wrong effect,
/// expiry, future observations, or malformed provider evidence.
pub fn verify_storage_frozen_delete_custody_reply(
    key: &StorageWorkKey,
    signature: &str,
    body: &[u8],
    request: &StorageFrozenDeleteCustodyRequest,
    now: i64,
) -> Result<StorageFrozenDeleteCustodyReply, StorageWorkError> {
    request.validate(&request.claim.snapshot.deployment_id, now)?;
    let reply: StorageFrozenDeleteCustodyReply = verify(key, REPLY, signature, body)?;
    let valid_outcome = match &reply.outcome {
        ExternalObjectOutcome::DeleteAcknowledged {
            provider_version,
            etag,
        } => {
            provider_version == &request.expected_provider_version
                && request.claim.expected_etag.as_ref() == Some(etag)
        }
        ExternalObjectOutcome::DeleteAbsent | ExternalObjectOutcome::DeletePreconditionFailed => {
            true
        }
        _ => false,
    };
    if reply.request != *request
        || !valid_outcome
        || reply.observed_at < request.claim.issued_at
        || reply.observed_at > now
        || reply.observed_at >= request.claim.expires_at
    {
        return Err(StorageWorkError::InvalidPlan);
    }
    Ok(reply)
}
