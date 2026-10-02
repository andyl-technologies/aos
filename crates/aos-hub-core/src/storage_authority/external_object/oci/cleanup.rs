//! Terminal private-chunk cleanup, separate from upload and GC authority.
//!
//! A fresh application request binds real terminal SQL and current Delete
//! custody. The permanent guard binds its retained OCI closure before deletion.
//! Its independently signed positive receipt is replayable without redispatch.
//!
//! ```text
//! request = {original: {terminal_upload, chunk, binding, placement, delete},
//!            scope, issuer, nonce, issued_at, expires_at}
//! reply = {request_digest, original_digest, nonce, closure, delete_receipt}
//! ```

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use super::{OciBytes, digest_string, hex_id, identifier, reply::OciClosedObject};
use crate::{
    db::OciTerminalChunkCleanupClaim,
    mirror_guard::MirrorGuardIssuer,
    storage_authority::{canonical_digest, control::StorageAuthorityObjectScope},
    storage_work::StorageWorkKey,
};

/// Protected terminal-upload cleanup route; no body bytes are accepted.
pub const OCI_CLEANUP_PATH: &str = "/_internal/storage/external-oci-cleanup/v1";
/// Purpose-specific application request and independent guard reply MAC header.
pub const OCI_CLEANUP_SIGNATURE_HEADER: &str = "x-aos-external-oci-cleanup-signature";
/// Fixed metadata limit for either direction, excluding all provider bytes.
pub const MAX_OCI_CLEANUP_BYTES: usize = 16 * 1024;
const REQUEST: &[u8] = b"aos.external-oci-terminal-cleanup-request.v1\0";
const REPLY: &[u8] = b"aos.external-oci-terminal-cleanup-reply.v1\0";

/// Binds one real terminal upload and immutable SQL chunk, never a GC action.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OciCleanupOriginal {
    /// Actual terminal SQL upload identifier.
    pub upload_id: String,
    /// Terminal SQL resource version; chunk deletion never advances it.
    pub upload_resource_version: i64,
    /// Original registry and repository identities.
    pub registry_id: i64,
    /// Original repository identity.
    pub repository_id: i64,
    /// Original SQL owner label, independently compared to the retained chunk.
    pub writer_id: String,
    /// Original SQL authentication owner label, not a current mutation grant.
    pub token_id: String,
    /// Actual terminal lifecycle state.
    pub terminal_state: String,
    /// Actual terminal transition time.
    pub finished_at: i64,
    /// Immutable contiguous chunk ordinal.
    pub ordinal: u32,
    /// Immutable chunk byte offset.
    pub offset: u64,
    /// Exact positively admitted chunk bytes.
    pub bytes: OciBytes,
    /// Full placement-relative private SQL key.
    pub staging_key: String,
    /// Frozen staging placement identity.
    pub placement_id: i64,
    /// Frozen staging placement version.
    pub placement_resource_version: i64,
    /// Exact retained placement prefix.
    pub placement_prefix: String,
    /// Frozen staging binding identity.
    pub binding_id: i64,
    /// Exact current binding resource version, refusing rotation.
    pub binding_resource_version: i64,
    /// Immutable staging write revision, never reselected.
    pub binding_write_revision: i64,
    /// Independently selected exact provider-coordinate commitment.
    pub binding_spec_revision: String,
    /// Independently current validated Delete credential generation.
    pub delete_generation: i64,
    /// Independently observed conditional-delete capability commitment.
    pub delete_capability_fingerprint: String,
    /// Exact capability observation version.
    pub delete_capability_resource_version: i64,
}

impl OciCleanupOriginal {
    /// Projects only an opaque database claim; adapters fill current physical custody.
    ///
    /// # Errors
    /// Refuses malformed terminal SQL or chunk identity.
    pub fn from_claim(
        claim: &OciTerminalChunkCleanupClaim,
        placement_prefix: String,
        binding_resource_version: i64,
        binding_spec_revision: String,
        delete_generation: i64,
        delete_capability_fingerprint: String,
        delete_capability_resource_version: i64,
    ) -> Result<Self> {
        let upload = claim.upload();
        let chunk = claim.chunk();
        let value = Self {
            upload_id: upload.id.clone(),
            upload_resource_version: upload.resource_version,
            registry_id: upload.registry_id,
            repository_id: upload.repository_id,
            writer_id: upload.writer_id.clone(),
            token_id: upload.token_id.clone(),
            terminal_state: upload.state.clone(),
            finished_at: upload
                .finished_at
                .ok_or_else(|| anyhow::anyhow!("terminal cleanup transition missing"))?,
            ordinal: chunk.ordinal,
            offset: chunk.byte_offset,
            bytes: OciBytes {
                sha256: chunk.digest.encoded(),
                size: chunk.byte_size,
            },
            staging_key: chunk.staging_object_key.clone(),
            placement_id: upload.staging_placement_id.unwrap_or(0),
            placement_resource_version: upload.staging_placement_resource_version.unwrap_or(0),
            placement_prefix,
            binding_id: upload.staging_binding_id.unwrap_or(0),
            binding_resource_version,
            binding_write_revision: upload.staging_binding_write_revision.unwrap_or(0),
            binding_spec_revision,
            delete_generation,
            delete_capability_fingerprint,
            delete_capability_resource_version,
        };
        value.validate()?;
        Ok(value)
    }

    /// Checks terminal SQL shape without granting deletion or renewed upload permission.
    ///
    /// # Errors
    /// Refuses foreign private keys, unsupported bounds or missing custody pins.
    pub fn validate(&self) -> Result<()> {
        self.bytes.validate()?;
        ensure!(
            hex_id(&self.upload_id, 32)
                && identifier(&self.writer_id)
                && identifier(&self.token_id)
                && matches!(
                    self.terminal_state.as_str(),
                    "complete" | "cancelled" | "failed"
                )
                && self.finished_at > 0
                && self.bytes.size > 0
                && self.bytes.size <= super::MAX_EXTERNAL_OCI_CHUNK_BYTES
                && self.offset.checked_add(self.bytes.size).is_some()
                && [
                    self.upload_resource_version,
                    self.registry_id,
                    self.repository_id,
                    self.placement_id,
                    self.placement_resource_version,
                    self.binding_id,
                    self.binding_resource_version,
                    self.binding_write_revision,
                    self.delete_generation,
                    self.delete_capability_resource_version
                ]
                .into_iter()
                .all(|value| value > 0 && value <= 9_007_199_254_740_991)
                && digest_string(&self.binding_spec_revision)
                && !self.delete_capability_fingerprint.is_empty()
                && self.delete_capability_fingerprint.len() <= 255
                && (self.placement_prefix.is_empty()
                    || crate::storage_work::valid_relative_path(&self.placement_prefix, true))
                && crate::storage_work::valid_relative_path(&self.staging_key, false)
                && self
                    .staging_key
                    .strip_prefix(&format!("oci/uploads/{}/chunks/", self.upload_id))
                    .is_some_and(|suffix| suffix.starts_with(&format!("{}-", self.ordinal))
                        && !suffix.contains('/')),
            "terminal OCI cleanup original is malformed or outside its private chunk"
        );
        Ok(())
    }

    /// Returns stable per-chunk physical-operation identity, excluding fresh request time.
    ///
    /// # Errors
    /// Refuses malformed identity or canonical serialization failure.
    pub fn fingerprint(&self) -> Result<String> {
        self.validate()?;
        canonical_digest(&("aos.oci-terminal-chunk-cleanup.v1", self))
    }
}

/// Fresh Native-authenticated cleanup control, never client upload permission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OciCleanupRequest {
    /// Shared installed deployment.
    pub deployment_id: String,
    /// Exact terminal SQL and independently current Delete custody.
    pub original: OciCleanupOriginal,
    /// Existing full-key guard namespace and physical authority.
    pub scope: StorageAuthorityObjectScope,
    /// Independently pinned actual guard implementation.
    pub issuer: MirrorGuardIssuer,
    /// Installed conservative UTC uncertainty.
    pub clock_uncertainty_seconds: u64,
    /// Original request correlation digest.
    pub nonce: String,
    /// Fresh cleanup request issue time, unrelated to the upload write window.
    pub issued_at: i64,
    /// Exclusive cleanup deadline, at most thirty seconds.
    pub expires_at: i64,
}

impl OciCleanupRequest {
    /// Checks exact cleanup context and the immutable fresh request deadline.
    ///
    /// # Errors
    /// Refuses expired, foreign, unbounded or malformed requests.
    pub fn validate(&self, deployment: &str, latest: i64) -> Result<()> {
        self.original.validate()?;
        self.scope.guard_name()?;
        ensure!(
            self.deployment_id == deployment
                && identifier(&self.deployment_id)
                && digest_string(&self.issuer.source_digest)
                && identifier(&self.issuer.script_version)
                && (1..30).contains(&self.clock_uncertainty_seconds)
                && digest_string(&self.nonce)
                && self.issued_at > 0
                && self.issued_at <= latest
                && latest < self.expires_at
                && self
                    .expires_at
                    .checked_sub(self.issued_at)
                    .is_some_and(|age| (1..=30).contains(&age))
                && serde_json::to_vec(self)?.len() <= MAX_OCI_CLEANUP_BYTES,
            "terminal OCI cleanup request identity or deadline differs"
        );
        Ok(())
    }

    /// Signs only canonical cleanup control bytes under the application role.
    ///
    /// # Errors
    /// Refuses invalid request shape or signing failure.
    pub fn sign(&self, key: &StorageWorkKey) -> Result<(Vec<u8>, String)> {
        self.validate(&self.deployment_id, self.issued_at)?;
        let body = serde_json::to_vec(self)?;
        Ok((body.clone(), key.sign_body(&[REQUEST, &body].concat())?))
    }

    /// Authenticates a fresh canonical application request.
    ///
    /// # Errors
    /// Refuses invalid MAC, changed bytes, excessive metadata or expiry.
    pub fn authenticate(
        key: &StorageWorkKey,
        signature: &str,
        body: &[u8],
        deployment: &str,
        latest: i64,
    ) -> Result<Self> {
        ensure!(
            body.len() <= MAX_OCI_CLEANUP_BYTES,
            "OCI cleanup request oversized"
        );
        key.verify_body(signature, &[REQUEST, body].concat())?;
        let request: Self = serde_json::from_slice(body)?;
        ensure!(
            serde_json::to_vec(&request)? == body,
            "OCI cleanup request noncanonical"
        );
        request.validate(deployment, latest)?;
        Ok(request)
    }
}

/// Independently authenticated exact positive version deletion, including cold replay.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OciCleanupReply {
    /// Full fresh request commitment.
    pub request_digest: String,
    /// Stable exact terminal cleanup original commitment.
    pub original_digest: String,
    /// Exact request nonce.
    pub nonce: String,
    /// Retained positive chunk closure; never a substituted HEAD incarnation.
    pub closed: OciClosedObject,
    /// Permanent exact pending/conditional DELETE receipt commitment.
    pub delete_receipt_digest: String,
}

impl OciCleanupReply {
    /// Checks exact original, positive chunk version and delete receipt correlation.
    ///
    /// # Errors
    /// Refuses missing/versionless closure, changed bytes or another request.
    pub fn validate_for(&self, request: &OciCleanupRequest) -> Result<()> {
        request.original.validate()?;
        self.closed.bytes.validate()?;
        self.closed
            .incarnation
            .validate(request.scope.physical_authority_id.as_str())?;
        ensure!(
            self.request_digest == canonical_digest(request)?
                && self.original_digest == request.original.fingerprint()?
                && self.nonce == request.nonce
                && self.closed.bytes == request.original.bytes
                && digest_string(&self.closed.receipt_digest)
                && digest_string(&self.delete_receipt_digest)
                && matches!(
                    self.closed.incarnation,
                    super::OciProviderIncarnation::Versioned { .. }
                )
                && crate::surface_write::strong_if_match_etag(&self.closed.etag)?
                    == self.closed.etag
                && serde_json::to_vec(self)?.len() <= MAX_OCI_CLEANUP_BYTES,
            "OCI cleanup reply lacks the exact positive version deletion"
        );
        Ok(())
    }

    /// Signs the exact positive receipt using the independent physical role.
    ///
    /// # Errors
    /// Refuses malformed correlation or signing failure.
    pub fn sign(
        &self,
        request: &OciCleanupRequest,
        key: &StorageWorkKey,
    ) -> Result<(Vec<u8>, String)> {
        self.validate_for(request)?;
        let body = serde_json::to_vec(self)?;
        Ok((body.clone(), key.sign_body(&[REPLY, &body].concat())?))
    }

    /// Authenticates exact canonical positive deletion; absence never qualifies.
    ///
    /// # Errors
    /// Refuses bad independent role MAC, malformed bytes or another original.
    pub fn authenticate(
        request: &OciCleanupRequest,
        key: &StorageWorkKey,
        signature: &str,
        body: &[u8],
    ) -> Result<Self> {
        ensure!(
            body.len() <= MAX_OCI_CLEANUP_BYTES,
            "OCI cleanup reply oversized"
        );
        key.verify_body(signature, &[REPLY, body].concat())?;
        let reply: Self = serde_json::from_slice(body)?;
        ensure!(
            serde_json::to_vec(&reply)? == body,
            "OCI cleanup reply noncanonical"
        );
        reply.validate_for(request)?;
        Ok(reply)
    }
}
