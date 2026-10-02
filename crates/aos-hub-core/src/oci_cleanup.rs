//! Terminal OCI chunk cleanup under the existing Managed R2 physical guard.
//!
//! The original comes from actual terminal SQL and separately current Delete
//! capability. A fresh request window never renews upload permission. Replies
//! bind an actual opaque R2 version; they never treat it as an S3 version ID.
//!
//! ```text
//! request = {original, deployment, profile, issuer, nonce, issued, expires}
//! reply = {original_digest, request_digest, nonce, actual_r2_object, receipt}
//! ```

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use crate::{
    db::OciTerminalChunkCleanupClaim,
    mirror_guard::MirrorGuardIssuer,
    storage_authority::canonical_digest,
    storage_work::{StorageObjectIdentity, StorageWorkKey},
};

/// Purpose-specific metadata route for real terminal private chunks.
pub const MANAGED_OCI_CLEANUP_PATH: &str = "/_internal/storage/managed-oci-cleanup/v1";
/// Application request or independent physical reply signature header.
pub const MANAGED_OCI_CLEANUP_HEADER: &str = "x-aos-managed-oci-cleanup-signature";
/// Closed metadata bound, with no encoded object content in either direction.
pub const MAX_MANAGED_OCI_CLEANUP_BYTES: usize = 16 * 1024;
/// Decodes bounded retained metadata without authenticating or renewing cleanup.
pub mod observation;

const REQUEST_DOMAIN: &[u8] = b"aos.managed-oci-terminal-cleanup-request.v1\0";
const REPLY_DOMAIN: &[u8] = b"aos.managed-oci-terminal-cleanup-reply.v1\0";

/// Identifies one immutable SQL chunk of an actually terminal upload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedOciCleanupOriginal {
    /// Original SQL upload identifier.
    pub upload_id: String,
    /// Exact terminal upload resource version.
    pub upload_resource_version: i64,
    /// Terminal lifecycle state, never an inferred provider observation.
    pub terminal_state: String,
    /// Actual terminal SQL transition time.
    pub finished_at: i64,
    /// Actual registry owning the private upload.
    pub registry_id: i64,
    /// Actual repository owning the private upload.
    pub repository_id: i64,
    /// Frozen upload writer label, without credentials.
    pub writer_id: String,
    /// Frozen upload owner label, without credentials.
    pub token_id: String,
    /// Exact retained SQL chunk ordinal.
    pub ordinal: u32,
    /// Exact retained SQL byte offset.
    pub offset: u64,
    /// Placement-relative private chunk key.
    pub path: String,
    /// Exact SQL chunk SHA-256, excluding its algorithm prefix.
    pub sha256: String,
    /// Exact SQL chunk byte size.
    pub size: u64,
    /// Frozen staging placement identifier.
    pub placement_id: i64,
    /// Frozen staging placement resource version.
    pub placement_resource_version: i64,
    /// Frozen physical placement prefix.
    pub placement_prefix: String,
    /// Frozen staging binding identifier.
    pub binding_id: i64,
    /// Current exact binding resource version, refusing authority substitution.
    pub binding_resource_version: i64,
    /// Frozen staging write revision.
    pub binding_write_revision: i64,
    /// Exact independently validated Delete capability commitment.
    pub delete_capability_fingerprint: String,
    /// Exact capability record version.
    pub delete_capability_resource_version: i64,
}

impl ManagedOciCleanupOriginal {
    /// Projects an opaque terminal SQL claim with separately selected custody.
    ///
    /// # Errors
    /// Refuses absent locators, malformed private paths or unsupported bounds.
    pub fn from_claim(
        claim: &OciTerminalChunkCleanupClaim,
        placement_prefix: String,
        binding_resource_version: i64,
        capability_fingerprint: String,
        capability_resource_version: i64,
    ) -> Result<Self> {
        let upload = claim.upload();
        let chunk = claim.chunk();
        let value = Self {
            upload_id: upload.id.clone(),
            upload_resource_version: upload.resource_version,
            terminal_state: upload.state.clone(),
            finished_at: upload.finished_at.unwrap_or(0),
            registry_id: upload.registry_id,
            repository_id: upload.repository_id,
            writer_id: upload.writer_id.clone(),
            token_id: upload.token_id.clone(),
            ordinal: chunk.ordinal,
            offset: chunk.byte_offset,
            path: chunk.staging_object_key.clone(),
            sha256: chunk.digest.encoded(),
            size: chunk.byte_size,
            placement_id: upload.staging_placement_id.unwrap_or(0),
            placement_resource_version: upload.staging_placement_resource_version.unwrap_or(0),
            placement_prefix,
            binding_id: upload.staging_binding_id.unwrap_or(0),
            binding_resource_version,
            binding_write_revision: upload.staging_binding_write_revision.unwrap_or(0),
            delete_capability_fingerprint: capability_fingerprint,
            delete_capability_resource_version: capability_resource_version,
        };
        value.validate()?;
        Ok(value)
    }

    /// Checks the terminal private-key shape without granting provider permission.
    ///
    /// # Errors
    /// Refuses malformed or nonterminal SQL, foreign keys and oversized chunks.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.upload_id.len() == 32
                && self.upload_id.bytes().all(|b| b.is_ascii_hexdigit())
                && matches!(
                    self.terminal_state.as_str(),
                    "complete" | "cancelled" | "failed"
                )
                && self.finished_at > 0
                && !self.writer_id.is_empty()
                && self.writer_id.len() <= 128
                && !self.token_id.is_empty()
                && self.token_id.len() <= 128
                && [
                    self.upload_resource_version,
                    self.registry_id,
                    self.repository_id,
                    self.placement_id,
                    self.placement_resource_version,
                    self.binding_id,
                    self.binding_resource_version,
                    self.binding_write_revision,
                    self.delete_capability_resource_version
                ]
                .into_iter()
                .all(|value| value > 0 && value <= 9_007_199_254_740_991)
                && self.size > 0
                && self.size <= crate::hybrid_ingress::MAX_HYBRID_OCI_CHUNK_BYTES as u64
                && self.offset.checked_add(self.size).is_some()
                && digest(&self.sha256)
                && !self.delete_capability_fingerprint.is_empty()
                && self.delete_capability_fingerprint.len() <= 255
                && crate::storage_work::valid_relative_path(&self.placement_prefix, true)
                && crate::storage_work::valid_relative_path(&self.path, false)
                && self
                    .path
                    .strip_prefix(&format!("oci/uploads/{}/chunks/", self.upload_id))
                    .is_some_and(|suffix| suffix.starts_with(&format!("{}-", self.ordinal))
                        && !suffix.contains('/')),
            "Managed terminal OCI cleanup original is malformed or foreign"
        );
        Ok(())
    }

    /// Returns the exact R2 key under its frozen placement prefix.
    pub fn key(&self) -> String {
        crate::keymap::r2_key(&self.placement_prefix, &self.path)
    }

    /// Returns stable physical cleanup identity, excluding fresh request time.
    ///
    /// # Errors
    /// Refuses an invalid original or canonical serialization failure.
    pub fn fingerprint(&self) -> Result<String> {
        self.validate()?;
        canonical_digest(&("aos.managed-oci-terminal-chunk.v1", self))
    }
}

/// Fresh application-authenticated request for one real terminal SQL chunk.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedOciCleanupRequest {
    /// Installed deployment audience.
    pub deployment_id: String,
    /// Actual terminal SQL and independently current Delete capability.
    pub original: ManagedOciCleanupOriginal,
    /// Independently accepted ordinary Managed provider profile, not OCI-only acceptance.
    pub protected_profile_digest: String,
    /// Independently pinned current physical guard implementation.
    pub issuer: MirrorGuardIssuer,
    /// Installed conservative UTC uncertainty.
    pub clock_uncertainty_seconds: u64,
    /// Fresh challenge nonce.
    pub nonce: String,
    /// Fresh control issue time.
    pub issued_at: u64,
    /// Exclusive cleanup cutoff, never the old upload write cutoff.
    pub expires_at: u64,
}

impl ManagedOciCleanupRequest {
    /// Checks the exact audience and immutable thirty-second control window.
    ///
    /// # Errors
    /// Refuses malformed, expired or foreign requests.
    pub fn validate(&self, deployment: &str, latest: u64) -> Result<()> {
        self.validate_checked(deployment, Some(latest))
    }

    /// Checks intrinsic retained request shape without accepting a current window.
    ///
    /// This observation does not verify a MAC, SQL claim, provider profile or
    /// current Delete capability. It cannot grant or renew cleanup permission.
    ///
    /// # Errors
    /// Refuses invalid originals, audience, issuer, uncertainty, nonce or an
    /// impossible control window exceeding the original thirty-second bound.
    pub fn validate_observation_shape(&self, deployment: &str) -> Result<()> {
        self.validate_checked(deployment, None)
    }

    fn validate_checked(&self, deployment: &str, latest: Option<u64>) -> Result<()> {
        self.original.validate()?;
        ensure!(
            self.deployment_id == deployment
                && !deployment.is_empty()
                && deployment.len() <= 128
                && digest(&self.protected_profile_digest)
                && digest(&self.issuer.source_digest)
                && !self.issuer.script_version.is_empty()
                && self.issuer.script_version.len() <= 128
                && (1..30).contains(&self.clock_uncertainty_seconds)
                && digest(&self.nonce)
                && self.issued_at > 0
                && latest.is_none_or(|latest| self.issued_at <= latest)
                && latest.is_none_or(|latest| latest < self.expires_at)
                && self
                    .expires_at
                    .checked_sub(self.issued_at)
                    .is_some_and(|span| span > 0 && span <= 30),
            "Managed OCI cleanup audience, shape or cutoff refused"
        );
        Ok(())
    }

    /// Signs a canonical bounded request with application authority.
    ///
    /// # Errors
    /// Refuses oversize or serialization/signing failure.
    pub fn sign(&self, key: &StorageWorkKey) -> Result<(Vec<u8>, String)> {
        signed(self, key, REQUEST_DOMAIN)
    }

    /// Authenticates canonical request bytes and checks its current cutoff.
    ///
    /// # Errors
    /// Refuses foreign MAC, noncanonical encoding, oversize or stale controls.
    pub fn authenticate(
        key: &StorageWorkKey,
        signature: &str,
        bytes: &[u8],
        deployment: &str,
        latest: u64,
    ) -> Result<Self> {
        let value: Self = authenticated(key, signature, bytes, REQUEST_DOMAIN)?;
        value.validate(deployment, latest)?;
        Ok(value)
    }
}

/// Independently authenticated positive receipt for one exact physical R2 delete.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedOciCleanupReply {
    /// Canonical whole request commitment, including fresh nonce and cutoff.
    pub request_digest: String,
    /// Stable terminal SQL original commitment.
    pub original_digest: String,
    /// Exact current challenge nonce.
    pub nonce: String,
    /// Actual conditional readback identity; provider_version is an opaque R2 version.
    pub object: StorageObjectIdentity,
    /// Exact durable positive mutation receipt commitment.
    pub receipt_digest: String,
}

impl ManagedOciCleanupReply {
    /// Checks correlation and actual R2 identity without treating absence as success.
    ///
    /// # Errors
    /// Refuses foreign originals, substituted keys or invalid positive identities.
    pub fn validate(&self, request: &ManagedOciCleanupRequest) -> Result<()> {
        ensure!(
            self.request_digest == canonical_digest(request)?
                && self.original_digest == request.original.fingerprint()?
                && self.nonce == request.nonce
                && self.object.key == request.original.key()
                && self.object.size == request.original.size
                && self
                    .object
                    .provider_version
                    .as_deref()
                    .is_some_and(crate::storage_work::valid_provider_version)
                && digest(&self.receipt_digest),
            "Managed OCI cleanup reply substituted its original or R2 identity"
        );
        crate::surface_write::strong_if_match_etag(&self.object.etag)?;
        Ok(())
    }

    /// Signs a positive reply with independently installed physical guard authority.
    ///
    /// # Errors
    /// Refuses invalid correlation, oversize or signing failure.
    pub fn sign(
        &self,
        request: &ManagedOciCleanupRequest,
        key: &StorageWorkKey,
    ) -> Result<(Vec<u8>, String)> {
        self.validate(request)?;
        signed(self, key, REPLY_DOMAIN)
    }

    /// Authenticates the physical reply; application request authority cannot substitute.
    ///
    /// # Errors
    /// Refuses wrong role/domain, noncanonical encoding or changed correlation.
    pub fn authenticate(
        request: &ManagedOciCleanupRequest,
        key: &StorageWorkKey,
        signature: &str,
        bytes: &[u8],
    ) -> Result<Self> {
        let value: Self = authenticated(key, signature, bytes, REPLY_DOMAIN)?;
        value.validate(request)?;
        Ok(value)
    }
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn signed(
    value: &impl Serialize,
    key: &StorageWorkKey,
    domain: &[u8],
) -> Result<(Vec<u8>, String)> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(
        bytes.len() <= MAX_MANAGED_OCI_CLEANUP_BYTES,
        "Managed OCI cleanup metadata exceeds bound"
    );
    let signature = key.sign_body(&[domain, bytes.as_slice()].concat())?;
    Ok((bytes, signature))
}

fn authenticated<T: serde::de::DeserializeOwned + Serialize>(
    key: &StorageWorkKey,
    signature: &str,
    bytes: &[u8],
    domain: &[u8],
) -> Result<T> {
    ensure!(
        bytes.len() <= MAX_MANAGED_OCI_CLEANUP_BYTES,
        "Managed OCI cleanup metadata exceeds bound"
    );
    key.verify_body(signature, &[domain, bytes].concat())?;
    decode_canonical(bytes)
}

fn decode_canonical<T: serde::de::DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T> {
    ensure!(
        bytes.len() <= MAX_MANAGED_OCI_CLEANUP_BYTES,
        "Managed OCI cleanup metadata exceeds bound"
    );
    let value: T = serde_json::from_slice(bytes)?;
    ensure!(
        serde_json::to_vec(&value)? == bytes,
        "Managed OCI cleanup encoding is noncanonical"
    );
    Ok(value)
}

/// Commits the actual secret-free descriptor for a confined cleanup fixture.
///
/// This identity is neither provider acceptance nor Delete permission. Only
/// the do-e2e Worker and test-only Native selector consume it; production
/// permission continues to require the ordinary accepted protected profile.
///
/// # Errors
/// Refuses malformed descriptor coordinates or canonical encoding failure.
pub fn managed_cleanup_fixture_profile_digest(
    profile: &crate::oci_sdk_emulation::OciSdkEmulationProfile,
) -> Result<String> {
    profile.validate()?;
    canonical_digest(&("aos.managed-oci-cleanup-fixture-raw-profile.v1", profile))
}

/// Names the distinct owner-installed local cleanup fixture identity slot.
///
/// Ordinary Worker builds never read this key. Its value grants no Delete
/// permission and is separate from the signed OCI SDK acceptance artifact.
pub const MANAGED_OCI_CLEANUP_FIXTURE_KEY: &str = "managed-oci-terminal-cleanup-fixture-v1";

/// Bounds a closed cleanup selection together with its raw observed SDK profile.
///
/// A typical full raw profile and selection occupy approximately 2 KiB. Longer
/// records are refused rather than increasing the isolate's metadata budget.
pub const MAX_MANAGED_OCI_CLEANUP_FIXTURE_BYTES: usize = 4096;
