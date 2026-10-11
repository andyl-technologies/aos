//! Exact-key grants for external storage cleanup after a durable SQL claim.
//!
//! A grant carries a retained delete credential independently of the binding's
//! current publication. It cannot publish a credential, select another key, or
//! authorize a write. Native must validate the applying claim, credential hold,
//! and frozen capability before issuing it; wire validation establishes scope
//! and integrity, not those SQL facts or provider deletion semantics.
//!
//! ```text
//! FrozenCleanupRequest v1
//!   request/action/claim identities and claim lease
//!   frozen placement access and external binding publication
//!   one OCI object path, reviewed hash/size/ETag
//!   operation = head | delete_if_matches
//! ```

use aos_oci_types::Sha256Digest;
use hmac::{Hmac, Mac as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::surface_write::FrozenSurfaceAccess;

use super::{
    admitted_oci_blob_path, valid_relative_path, StorageBindingPublication, StorageWorkError,
    StorageWorkKey, MAX_PLAN_LIFETIME_SECONDS, MAX_VERIFY_SOURCE_BYTES,
};

/// Internal route for one signed, claim-scoped external cleanup operation.
pub const STORAGE_FROZEN_CLEANUP_PATH: &str = "/_internal/storage/v1/frozen-cleanup";

/// Maximum JSON bytes, including the separately scoped retained credential.
pub const MAX_FROZEN_CLEANUP_BYTES: usize = 16 * 1024;

const SIGNATURE_DOMAIN: &[u8] = b"aos-storage-frozen-cleanup-v1\0";

/// Wire representation of an exact durable cleanup access fence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageFrozenCleanupAccess {
    /// Registry owning the reviewed object.
    pub registry_id: i64,
    /// Frozen placement database identity.
    pub placement_id: i64,
    /// Frozen display name retained for bounded diagnostics.
    pub placement_name: String,
    /// Frozen binding-relative prefix; it is never reselected by the executor.
    pub placement_prefix: String,
    /// Frozen placement resource version.
    pub placement_resource_version: i64,
    /// Frozen writer-critical topology version.
    pub placement_write_spec_version: i64,
    /// Minimum ready/complete placement observation version.
    pub placement_observation_version: i64,
    /// Frozen storage binding identity.
    pub binding_id: i64,
    /// Frozen storage binding resource version.
    pub binding_resource_version: i64,
    /// Retained immutable binding write revision.
    pub binding_write_revision: i64,
    /// Exact held delete credential generation.
    pub delete_credential_generation: i64,
    /// Fingerprint of the reviewed conditional-delete capability.
    pub delete_capability_fingerprint: String,
    /// Frozen capability observation resource version.
    pub delete_capability_resource_version: i64,
}

impl StorageFrozenCleanupAccess {
    /// Copies an external claim fence without reading current credential heads.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid fence or missing exact delete credential.
    pub fn from_access(access: &FrozenSurfaceAccess) -> Result<Self, StorageWorkError> {
        access
            .validate()
            .map_err(|_| StorageWorkError::InvalidPlan)?;
        if access.delete_credential_purpose.as_deref() != Some("delete") {
            return Err(StorageWorkError::InvalidPlan);
        }
        let generation = access
            .delete_credential_generation
            .ok_or(StorageWorkError::InvalidPlan)?;
        Ok(Self {
            registry_id: access.registry_id,
            placement_id: access.placement_id,
            placement_name: access.placement_name.clone(),
            placement_prefix: access.placement_prefix.clone(),
            placement_resource_version: access.placement_resource_version,
            placement_write_spec_version: access.placement_write_spec_version,
            placement_observation_version: access.placement_observation_version,
            binding_id: access.binding_id,
            binding_resource_version: access.binding_resource_version,
            binding_write_revision: access.binding_write_revision,
            delete_credential_generation: generation,
            delete_capability_fingerprint: access.delete_capability_fingerprint.clone(),
            delete_capability_resource_version: access.delete_capability_resource_version,
        })
    }

    pub(crate) fn validate(&self) -> Result<(), StorageWorkError> {
        FrozenSurfaceAccess {
            registry_id: self.registry_id,
            placement_id: self.placement_id,
            placement_name: self.placement_name.clone(),
            placement_prefix: self.placement_prefix.clone(),
            placement_resource_version: self.placement_resource_version,
            placement_write_spec_version: self.placement_write_spec_version,
            placement_observation_version: self.placement_observation_version,
            binding_id: self.binding_id,
            binding_resource_version: self.binding_resource_version,
            binding_write_revision: self.binding_write_revision,
            delete_credential_purpose: Some("delete".into()),
            delete_credential_generation: Some(self.delete_credential_generation),
            delete_capability_fingerprint: self.delete_capability_fingerprint.clone(),
            delete_capability_resource_version: self.delete_capability_resource_version,
        }
        .validate()
        .map_err(|_| StorageWorkError::InvalidPlan)?;
        if !valid_relative_path(&self.placement_prefix, true) {
            return Err(StorageWorkError::InvalidPlan);
        }
        Ok(())
    }
}

/// Closed operations permitted by a frozen external cleanup grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageFrozenCleanupOperation {
    /// Observes metadata for the exact reviewed key without returning its body.
    Head,
    /// Deletes the reviewed object only under its exact provider condition.
    DeleteIfMatches,
}

/// One short-lived external cleanup request carrying exact retained access.
///
/// The publication is private credential transport, not current binding state.
/// Executors must not pass it to ordinary binding publication or cache its
/// secret material. A terminal per-action receipt and a persistent pending
/// operation must fence visible writes; request expiry never resolves an
/// ambiguous provider mutation. The retained credential must support HEAD and
/// conditional DELETE under the capability Native validated for this claim.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageFrozenCleanupRequest {
    /// Wire schema version; only version 1 is accepted.
    pub version: u8,
    /// Unique request identity; renewing a grant does not change its action.
    pub request_id: String,
    /// Stable SQL placement-action identity used for physical deletion receipts.
    pub action_id: String,
    /// Current SQL claim token, used by Native to accept completion evidence.
    pub claim_token: String,
    /// Claim lease expiry; grant expiry may not exceed it.
    pub lease_expires_at: i64,
    /// Exact frozen placement and capability fence.
    pub access: StorageFrozenCleanupAccess,
    /// Frozen external coordinates and exactly one retained delete credential.
    pub publication: StorageBindingPublication,
    /// One canonical surface-relative OCI blob key; prefixes and lists are forbidden.
    pub path: String,
    /// Reviewed content hash matching the digest encoded in the OCI key.
    pub expected_hash: Sha256Digest,
    /// Reviewed physical byte length.
    pub expected_size: u64,
    /// Reviewed strong provider ETag; required for deletion, optional for absence HEAD.
    pub expected_etag: Option<String>,
    /// Metadata observation or exact conditional deletion, never another operation.
    pub operation: StorageFrozenCleanupOperation,
}

/// Bounded metadata reply bound to one exact frozen cleanup claim and request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageFrozenCleanupHeadResult {
    /// Reply schema version; only version 1 is accepted.
    pub version: u8,
    /// Exact request identity issued by Native.
    pub request_id: String,
    /// Stable SQL placement-action identity.
    pub action_id: String,
    /// Current SQL claim token from the request.
    pub claim_token: String,
    /// Nonsecret fingerprint of the complete frozen claim scope.
    pub claim_fingerprint: String,
    /// Observed metadata for the exact key, or `None` for provider-confirmed absence.
    pub object: Option<super::StorageObjectIdentity>,
}

impl StorageFrozenCleanupHeadResult {
    /// Checks reply correlation and exact provider metadata before Native accepts it.
    ///
    /// # Errors
    ///
    /// Returns an error for another request, claim, scope, or object key, an
    /// unsupported reply version, or malformed provider metadata. Native must
    /// also reload the live SQL claim before committing absence evidence.
    pub fn validate_for(
        &self,
        request: &StorageFrozenCleanupRequest,
    ) -> Result<(), StorageWorkError> {
        if self.version != 1
            || request.operation != StorageFrozenCleanupOperation::Head
            || self.request_id != request.request_id
            || self.action_id != request.action_id
            || self.claim_token != request.claim_token
            || self.claim_fingerprint
                != request
                    .claim_fingerprint()
                    .map_err(|_| StorageWorkError::InvalidPlan)?
            || self.object.as_ref().is_some_and(|object| {
                request.object_key().ok().as_deref() != Some(object.key.as_str())
                    || object.size > MAX_VERIFY_SOURCE_BYTES
                    || object.etag.len() > 1024
                    || crate::surface_write::strong_if_match_etag(&object.etag).is_err()
            })
        {
            return Err(StorageWorkError::InvalidPlan);
        }
        Ok(())
    }
}

impl StorageFrozenCleanupRequest {
    /// Validates exact scope, credential material, and the bounded claim lifetime.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed claim or object identity, a mismatched
    /// access fence, deployment, retained credential, secret fingerprint, or
    /// validity window. Callers must separately verify the request signature,
    /// SQL hold, claim state, and provider capability before performing I/O.
    pub fn validate(&self, deployment_id: &str, now: i64) -> Result<(), StorageWorkError> {
        self.access.validate()?;
        self.publication.validate(deployment_id, now)?;
        let snapshot = &self.publication.snapshot;
        if self.version != 1
            || self.request_id.len() != 32
            || !self.request_id.bytes().all(|byte| byte.is_ascii_hexdigit())
            || !valid_claim_identity(&self.action_id)
            || !valid_claim_identity(&self.claim_token)
            || !admitted_oci_blob_path(&self.path)
            || self.path != crate::db::oci_blob_object_key(self.expected_hash)
            || self.expected_size > MAX_VERIFY_SOURCE_BYTES
            || self.expected_etag.as_ref().is_some_and(|etag| {
                etag.len() > 1024 || crate::surface_write::strong_if_match_etag(etag).is_err()
            })
            || (self.operation == StorageFrozenCleanupOperation::DeleteIfMatches
                && self.expected_etag.is_none())
        {
            return Err(StorageWorkError::InvalidPlan);
        }
        if snapshot.binding_id != self.access.binding_id
            || snapshot.binding_resource_version != self.access.binding_resource_version
            || snapshot.access_mode != "private"
            || snapshot.credentials.len() != 1
            || snapshot.credentials[0].purpose != "delete"
            || snapshot.credentials[0].generation != self.access.delete_credential_generation
        {
            return Err(StorageWorkError::InvalidSnapshot);
        }
        if now < 0
            || snapshot.issued_at < 0
            || snapshot.expires_at <= snapshot.issued_at
            || snapshot.expires_at.saturating_sub(snapshot.issued_at) > MAX_PLAN_LIFETIME_SECONDS
            || self.lease_expires_at < snapshot.expires_at
        {
            return Err(StorageWorkError::InvalidTime);
        }
        Ok(())
    }

    /// Returns the exact bucket key, including binding and placement prefixes.
    ///
    /// # Errors
    ///
    /// Returns an error for a noncanonical prefix or a path outside OCI blobs.
    pub fn object_key(&self) -> Result<String, StorageWorkError> {
        let prefix = &self.publication.snapshot.object_prefix;
        if !valid_relative_path(prefix, true)
            || !valid_relative_path(&self.access.placement_prefix, true)
            || !admitted_oci_blob_path(&self.path)
        {
            return Err(StorageWorkError::InvalidPlan);
        }
        let relative = crate::keymap::r2_key(&self.access.placement_prefix, &self.path);
        Ok(crate::keymap::r2_key(prefix, &relative))
    }

    /// Computes stable nonsecret receipt identity across request and lease renewal.
    ///
    /// Request IDs, claim tokens, times, and secret bytes are excluded. Executors
    /// must reject a reused action ID with a different fingerprint, and keep
    /// receipts or a durable retirement fence after credential material expires.
    ///
    /// # Errors
    ///
    /// Returns an error if the canonical scope cannot be serialized.
    pub fn claim_fingerprint(&self) -> Result<String, serde_json::Error> {
        let body = serde_json::to_vec(&(
            &self.publication.snapshot.deployment_id,
            &self.action_id,
            &self.access,
            self.publication.snapshot.binding_spec_revision()?,
            &self.publication.snapshot.credentials,
            &self.path,
            &self.expected_hash,
            self.expected_size,
            &self.expected_etag,
        ))?;
        Ok(hex::encode(Sha256::digest(body)))
    }
}

impl StorageWorkKey {
    /// Signs exact cleanup JSON with a domain distinct from ordinary storage work.
    ///
    /// # Errors
    ///
    /// Returns an error when the body exceeds the cleanup wire cap.
    pub fn sign_frozen_cleanup_body(&self, body: &[u8]) -> Result<String, StorageWorkError> {
        if body.len() > MAX_FROZEN_CLEANUP_BYTES {
            return Err(StorageWorkError::InvalidPlan);
        }
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.bytes).map_err(|_| StorageWorkError::WeakKey)?;
        mac.update(SIGNATURE_DOMAIN);
        mac.update(body);
        Ok(hex::encode(mac.finalize().into_bytes()))
    }

    /// Authenticates bounded cleanup bytes before parsing and validating their scope.
    ///
    /// # Errors
    ///
    /// Returns an error for an oversized body, invalid signature, malformed or
    /// overbroad cleanup request, expired grant, or different deployment.
    pub fn verify_frozen_cleanup(
        &self,
        signature: &str,
        body: &[u8],
        deployment_id: &str,
        now: i64,
    ) -> Result<StorageFrozenCleanupRequest, StorageWorkError> {
        if body.len() > MAX_FROZEN_CLEANUP_BYTES {
            return Err(StorageWorkError::InvalidPlan);
        }
        let signature = hex::decode(signature).map_err(|_| StorageWorkError::InvalidSignature)?;
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.bytes).map_err(|_| StorageWorkError::WeakKey)?;
        mac.update(SIGNATURE_DOMAIN);
        mac.update(body);
        mac.verify_slice(&signature)
            .map_err(|_| StorageWorkError::InvalidSignature)?;

        let request: StorageFrozenCleanupRequest =
            serde_json::from_slice(body).map_err(|_| StorageWorkError::InvalidPlan)?;
        request.validate(deployment_id, now)?;
        Ok(request)
    }
}

fn valid_claim_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

#[cfg(test)]
mod tests;
