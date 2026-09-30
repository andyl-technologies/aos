//! Metadata-only frozen cleanup controls and exact historical material recovery.

use super::*;
use crate::storage_work::{
    StorageFrozenCleanupAccess, StorageFrozenCleanupHeadResult, StorageFrozenCleanupOperation,
    StorageFrozenCleanupRequest, MAX_VERIFY_SOURCE_BYTES,
};
use aos_oci_types::Sha256Digest;

/// Metadata-only route for a current SQL frozen cleanup claim.
pub const STORAGE_FROZEN_CLEANUP_CUSTODY_PATH: &str =
    "/_internal/storage/v1/frozen-cleanup-custody";
/// Protected operator route for an exact held historical cleanup credential.
pub const STORAGE_FROZEN_CLEANUP_CREDENTIAL_STAGE_PATH: &str =
    "/_internal/storage/v1/frozen-cleanup-credential";
const CLEANUP_REQUEST: &[u8] = b"aos.storage-frozen-cleanup-custody.request.v1\0";
const CLEANUP_REPLY: &[u8] = b"aos.storage-frozen-cleanup-custody.reply.v1\0";
const CLEANUP_STAGE_REQUEST: &[u8] = b"aos.storage-frozen-cleanup-custody.stage-request.v1\0";
const CLEANUP_STAGE_REPLY: &[u8] = b"aos.storage-frozen-cleanup-custody.stage-reply.v1\0";

/// Exact frozen claim carrying only coordinates and held credential metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageFrozenCleanupCustodyRequest {
    /// Schema version, currently one.
    pub version: u8,
    /// Fresh challenge nonce.
    pub nonce: String,
    /// Request issue time.
    pub issued_at: i64,
    /// Exclusive deadline, bounded to thirty seconds.
    pub expires_at: i64,
    /// Exact current invocation identity.
    pub request_id: String,
    /// Original durable placement action identity.
    pub action_id: String,
    /// Current SQL claim token.
    pub claim_token: String,
    /// Exclusive current SQL claim lease expiry.
    pub lease_expires_at: i64,
    /// Full original frozen placement and capability fence.
    pub access: StorageFrozenCleanupAccess,
    /// Exact historical coordinates and held delete reference, without material.
    pub snapshot: StorageBindingSnapshot,
    /// One canonical OCI object path.
    pub path: String,
    /// Original reviewed content hash.
    pub expected_hash: Sha256Digest,
    /// Original reviewed physical size.
    pub expected_size: u64,
    /// Original reviewed strong provider ETag.
    pub expected_etag: Option<String>,
    /// Exact frozen operation.
    pub operation: StorageFrozenCleanupOperation,
}

impl StorageFrozenCleanupCustodyRequest {
    /// Validates fresh claim scope independently of private provider material.
    ///
    /// # Errors
    /// Returns an error for stale, changed, malformed or overbroad claim metadata.
    pub fn validate(&self, deployment: &str, now: i64) -> Result<(), StorageWorkError> {
        fresh(
            self.version,
            &self.nonce,
            self.issued_at,
            self.expires_at,
            now,
        )?;
        self.snapshot.validate(deployment, now)?;
        self.access.validate()?;
        let identity = |value: &str| {
            !value.is_empty()
                && value.len() <= 64
                && value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
        };
        if self.request_id.len() != 32
            || !self.request_id.bytes().all(|b| b.is_ascii_hexdigit())
            || !identity(&self.action_id)
            || !identity(&self.claim_token)
            || self.path != crate::db::oci_blob_object_key(self.expected_hash)
            || self.expected_size > MAX_VERIFY_SOURCE_BYTES
            || self.expected_etag.as_ref().is_some_and(|etag| {
                etag.len() > 1024 || crate::surface_write::strong_if_match_etag(etag).is_err()
            })
            || (self.operation == StorageFrozenCleanupOperation::DeleteIfMatches
                && self.expected_etag.is_none())
            || self.snapshot.binding_id != self.access.binding_id
            || self.snapshot.binding_resource_version != self.access.binding_resource_version
            || self.snapshot.access_mode != "private"
            || self.snapshot.credentials.len() != 1
            || self.snapshot.credentials[0].purpose != "delete"
            || self.snapshot.credentials[0].generation != self.access.delete_credential_generation
            || self.snapshot.issued_at > now
            || self.snapshot.expires_at <= now
            || self.snapshot.expires_at > self.expires_at
            || self.expires_at > self.lease_expires_at
        {
            return Err(StorageWorkError::InvalidPlan);
        }
        Ok(())
    }

    /// Constructs the existing physical executor envelope inside Worker custody.
    ///
    /// # Errors
    /// Returns an error when retained material differs from the exact held reference.
    pub fn with_material(
        &self,
        material: StorageCredentialMaterial,
        now: i64,
    ) -> Result<StorageFrozenCleanupRequest, StorageWorkError> {
        self.validate(&self.snapshot.deployment_id, now)?;
        let request = StorageFrozenCleanupRequest {
            version: self.version,
            request_id: self.request_id.clone(),
            action_id: self.action_id.clone(),
            claim_token: self.claim_token.clone(),
            lease_expires_at: self.lease_expires_at,
            access: self.access.clone(),
            publication: StorageBindingPublication {
                snapshot: self.snapshot.clone(),
                materials: vec![material],
            },
            path: self.path.clone(),
            expected_hash: self.expected_hash,
            expected_size: self.expected_size,
            expected_etag: self.expected_etag.clone(),
            operation: self.operation,
        };
        request.validate(&self.snapshot.deployment_id, now)?;
        Ok(request)
    }

    /// Returns permanent action identity independently of renewal times or secret bytes.
    ///
    /// # Errors
    /// Returns an error if the canonical frozen scope cannot be encoded.
    pub fn claim_fingerprint(&self) -> Result<String, serde_json::Error> {
        Ok(hex::encode(Sha256::digest(serde_json::to_vec(&(
            &self.snapshot.deployment_id,
            &self.action_id,
            &self.access,
            self.snapshot.binding_spec_revision()?,
            &self.snapshot.credentials,
            &self.path,
            &self.expected_hash,
            self.expected_size,
            &self.expected_etag,
        ))?)))
    }
}

/// Fresh authenticated metadata reply for the complete frozen original.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageFrozenCleanupCustodyReply {
    /// Complete metadata-only original challenge.
    pub request: StorageFrozenCleanupCustodyRequest,
    /// Exact physical HEAD result.
    pub result: StorageFrozenCleanupHeadResult,
    /// Fresh result readback time.
    pub observed_at: i64,
}

/// Protected recovery of exact historical material under a live frozen SQL hold.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageFrozenCleanupCredentialStage {
    /// Complete live frozen claim; the operator must independently check its SQL hold.
    pub request: StorageFrozenCleanupCustodyRequest,
    /// Exact delete material matching the held reference and fingerprint.
    pub material: StorageCredentialMaterial,
    /// Exclusive independent retention horizon, bounded to twenty-four hours.
    pub material_not_after: i64,
}

impl StorageFrozenCleanupCredentialStage {
    /// Validates exact historical recovery without authorizing a provider effect.
    ///
    /// # Errors
    /// Returns an error for stale claim, changed material, or excessive retention.
    pub fn validate(&self, deployment: &str, now: i64) -> Result<(), StorageWorkError> {
        self.request.validate(deployment, now)?;
        if self.material_not_after <= now
            || self
                .material_not_after
                .saturating_sub(self.request.issued_at)
                > MAX_CREDENTIAL_CUSTODY_SECONDS
        {
            return Err(StorageWorkError::InvalidTime);
        }
        let encoded = zeroize::Zeroizing::new(
            serde_json::to_vec(self).map_err(|_| StorageWorkError::InvalidSnapshot)?,
        );
        let duplicate: Self =
            serde_json::from_slice(&encoded).map_err(|_| StorageWorkError::InvalidSnapshot)?;
        duplicate.request.with_material(duplicate.material, now)?;
        Ok(())
    }
}

/// Nonsecret acknowledgement of an exact frozen historical recovery control.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageFrozenCleanupCredentialStageReply {
    /// Complete original metadata; secret material is absent.
    pub request: StorageFrozenCleanupCustodyRequest,
    /// Exact accepted retention horizon.
    pub material_not_after: i64,
    /// Hash of the complete canonical recovery control.
    pub stage_body_sha256: String,
}

requests!(
    sign_storage_frozen_cleanup_custody,
    verify_storage_frozen_cleanup_custody,
    StorageFrozenCleanupCustodyRequest,
    CLEANUP_REQUEST
);
requests!(
    sign_storage_frozen_cleanup_credential_stage,
    verify_storage_frozen_cleanup_credential_stage,
    StorageFrozenCleanupCredentialStage,
    CLEANUP_STAGE_REQUEST
);

/// Signs a metadata-only physical cleanup reply.
///
/// # Errors
/// Returns an error for oversized or unencodable metadata.
pub fn sign_storage_frozen_cleanup_custody_reply(
    key: &StorageWorkKey,
    reply: &StorageFrozenCleanupCustodyReply,
) -> Result<SignedStorageCustodyControl, StorageWorkError> {
    sign(key, CLEANUP_REPLY, reply)
}

/// Authenticates the exact fresh frozen claim and observed object identity.
///
/// # Errors
/// Returns an error for another nonce, claim, scope, object, signature or expiry.
pub fn verify_storage_frozen_cleanup_custody_reply(
    key: &StorageWorkKey,
    signature: &str,
    body: &[u8],
    request: &StorageFrozenCleanupCustodyRequest,
    now: i64,
) -> Result<StorageFrozenCleanupCustodyReply, StorageWorkError> {
    request.validate(&request.snapshot.deployment_id, now)?;
    let reply: StorageFrozenCleanupCustodyReply = verify(key, CLEANUP_REPLY, signature, body)?;
    let result = &reply.result;
    let object_key = crate::keymap::r2_key(
        &request.snapshot.object_prefix,
        &crate::keymap::r2_key(&request.access.placement_prefix, &request.path),
    );
    if reply.request != *request
        || reply.observed_at < request.issued_at
        || reply.observed_at > now
        || reply.observed_at >= request.expires_at
        || request.operation != StorageFrozenCleanupOperation::Head
        || result.version != 1
        || result.request_id != request.request_id
        || result.action_id != request.action_id
        || result.claim_token != request.claim_token
        || result.claim_fingerprint
            != request
                .claim_fingerprint()
                .map_err(|_| StorageWorkError::InvalidPlan)?
        || result.object.as_ref().is_some_and(|object| {
            object.key != object_key
                || object.size > MAX_VERIFY_SOURCE_BYTES
                || object.etag.len() > 1024
                || crate::surface_write::strong_if_match_etag(&object.etag).is_err()
        })
    {
        return Err(StorageWorkError::InvalidPlan);
    }
    Ok(reply)
}

/// Signs acknowledgement without echoing recovered historical material.
///
/// # Errors
/// Returns an error for oversized or unencodable metadata.
pub fn sign_storage_frozen_cleanup_credential_stage_reply(
    key: &StorageWorkKey,
    reply: &StorageFrozenCleanupCredentialStageReply,
) -> Result<SignedStorageCustodyControl, StorageWorkError> {
    sign(key, CLEANUP_STAGE_REPLY, reply)
}

/// Verifies exact original recovery bytes without returning secret material.
///
/// # Errors
/// Returns an error for changed scope, material hash, nonce, signature or expiry.
pub fn verify_storage_frozen_cleanup_credential_stage_reply(
    key: &StorageWorkKey,
    signature: &str,
    body: &[u8],
    request: &StorageFrozenCleanupCredentialStage,
    now: i64,
) -> Result<StorageFrozenCleanupCredentialStageReply, StorageWorkError> {
    request.validate(&request.request.snapshot.deployment_id, now)?;
    let reply: StorageFrozenCleanupCredentialStageReply =
        verify(key, CLEANUP_STAGE_REPLY, signature, body)?;
    if reply.request != request.request
        || reply.material_not_after != request.material_not_after
        || reply.stage_body_sha256
            != hex::encode(Sha256::digest(
                serde_json::to_vec(request).map_err(|_| StorageWorkError::InvalidPlan)?,
            ))
    {
        return Err(StorageWorkError::InvalidPlan);
    }
    Ok(reply)
}
