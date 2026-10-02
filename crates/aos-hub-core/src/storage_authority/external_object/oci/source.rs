//! Independent read-only discovery of a positively closed OCI original.
//!
//! A fresh guard-role challenge selects current writer and expected SQL bytes.
//! The reply identifies the retained original; it does not create an upload,
//! grant a provider mutation or infer completion from HEAD or absence.

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

use crate::{mirror_guard::MirrorGuardIssuer, storage_authority::{canonical_digest,
    control::StorageAuthorityObjectScope}, storage_work::StorageWorkKey};
use super::{digest_string, ExternalOciOriginal, OciBytes, OciWriterOriginal,
    reply::OciClosedObject};

/// Public protected metadata endpoint on the existing external object guard.
pub const OCI_SOURCE_PATH: &str = "/_internal/storage/external-oci-source/v1";
/// Independent guard-role MAC, never a client upload credential.
pub const OCI_SOURCE_SIGNATURE_HEADER: &str = "x-aos-external-oci-source-signature";
/// Maximum original discovery request and response, excluding payload bodies.
pub const MAX_OCI_SOURCE_BYTES: usize = 32 * 1024;
const REQUEST: &[u8] = b"aos.external-oci-source-request.v1\0";
const REPLY: &[u8] = b"aos.external-oci-source-reply.v1\0";

/// Selects exact current physical coordinates and expected catalogue bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OciSourceLookup {
    /// Closed wire version.
    pub version: u8,
    /// Installed shared deployment.
    pub deployment_id: String,
    /// Independently selected actual guard implementation.
    pub issuer: MirrorGuardIssuer,
    /// Installed conservative UTC uncertainty.
    pub clock_uncertainty_seconds: u64,
    /// Exact current binding and placement authority.
    pub writer: OciWriterOriginal,
    /// Exact raw binding coordinates.
    pub binding_spec_revision: String,
    /// Independently reviewed OCI producer profile.
    pub profile_digest: String,
    /// Permanent physical key and authority namespace.
    pub scope: StorageAuthorityObjectScope,
    /// Exact expected SQL descriptor or chunk bytes.
    pub expected: OciBytes,
    /// Optional bounded conditional provider range, only for storage-local composition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub range: Option<OciSourceRange>,
    /// Real upload ID required for every private staged chunk.
    pub upload_id: Option<String>,
    /// Original request correlation value.
    pub nonce: String,
    /// Original issue time.
    pub issued_at: i64,
    /// Exclusive fixed request deadline, at most thirty seconds.
    pub expires_at: i64,
}

/// Bounds one actual source range independently of provider framing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OciSourceRange {
    /// Inclusive source byte offset.
    pub start: u64,
    /// Exact positive range length, at most one part.
    pub length: u64,
}

impl OciSourceLookup {
    /// Validates current request shape and its immutable read-only deadline.
    ///
    /// # Errors
    /// Refuses unsafe paths, foreign identity, expiry or excessive metadata.
    pub fn validate(&self, deployment: &str, latest_now: i64) -> Result<()> {
        self.writer.validate()?;
        self.expected.validate()?;
        self.scope.guard_name()?;
        ensure!(self.version == 1 && self.deployment_id == deployment
            && digest_string(&self.issuer.source_digest)
            && super::identifier(&self.issuer.script_version)
            && (1..30).contains(&self.clock_uncertainty_seconds)
            && digest_string(&self.binding_spec_revision) && digest_string(&self.profile_digest)
            && digest_string(&self.nonce) && self.issued_at > 0
            && self.issued_at <= latest_now && latest_now < self.expires_at
            && self.expires_at.checked_sub(self.issued_at).is_some_and(|age| age > 0 && age <= 30),
            "external OCI source identity or deadline differs");
        let prefix = crate::keymap::r2_key(&self.writer.binding_prefix, &self.writer.placement_prefix);
        let relative = if prefix.is_empty() { self.scope.full_key.as_str() } else {
            self.scope.full_key.strip_prefix(&format!("{prefix}/"))
                .ok_or_else(|| anyhow::anyhow!("OCI source escapes current writer"))?
        };
        if let Some(upload_id) = &self.upload_id {
            ensure!(super::hex_id(upload_id, 32)
                && relative.strip_prefix(&format!("oci/uploads/{upload_id}/chunks/"))
                    .is_some_and(|tail| !tail.is_empty() && !tail.contains('/')),
                "OCI source does not match its real private upload");
        } else {
            ensure!(relative == format!("oci/blobs/sha256/{}", self.expected.sha256),
                "OCI source is not the exact canonical content path");
        }
        if let Some(range) = &self.range {
            ensure!(self.upload_id.is_some() && range.length > 0
                && range.length <= super::EXTERNAL_OCI_PART_BYTES
                && range.start.checked_add(range.length).is_some_and(|end| end <= self.expected.size),
                "OCI source range escapes exact private bytes");
        }
        ensure!(serde_json::to_vec(self)?.len() <= MAX_OCI_SOURCE_BYTES,
            "OCI source lookup exceeds metadata budget");
        Ok(())
    }

    /// Authenticates canonical bytes under an independently installed guard role.
    ///
    /// # Errors
    /// Refuses invalid shape, noncanonical JSON, bad MAC or expired requests.
    pub fn authenticate(key: &StorageWorkKey, signature: &str, body: &[u8],
        deployment: &str, latest_now: i64) -> Result<Self> {
        ensure!(body.len() <= MAX_OCI_SOURCE_BYTES, "OCI source lookup oversized");
        key.verify_body(signature, &[REQUEST, body].concat())?;
        let lookup: Self = serde_json::from_slice(body)?;
        ensure!(serde_json::to_vec(&lookup)? == body, "OCI source lookup noncanonical");
        lookup.validate(deployment, latest_now)?;
        Ok(lookup)
    }

    /// Signs a bounded read-only request with the installed guard role.
    ///
    /// # Errors
    /// Refuses malformed request shape or signing failure.
    pub fn sign(&self, key: &StorageWorkKey) -> Result<(Vec<u8>, String)> {
        self.validate(&self.deployment_id, self.issued_at)?;
        let body = serde_json::to_vec(self)?;
        let signature = key.sign_body(&[REQUEST, &body].concat())?;
        Ok((body, signature))
    }
}

/// Reports an actual still-visible positive original and its provider receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OciSourceReply {
    /// Exact whole lookup commitment.
    pub request_digest: String,
    /// Exact original nonce.
    pub nonce: String,
    /// Full retained original, never a reconstruction from current upload RV.
    pub original: ExternalOciOriginal,
    /// Exact durable positive closure.
    pub closed: OciClosedObject,
    /// Actual observation time in this permanent physical guard.
    pub observed_at: i64,
}

impl OciSourceReply {
    /// Checks full original, expected bytes and current physical coordinates.
    ///
    /// # Errors
    /// Refuses another writer, source, upload, implementation or positive receipt.
    pub fn validate_for(&self, lookup: &OciSourceLookup, latest_now: i64) -> Result<()> {
        lookup.validate(&lookup.deployment_id, latest_now)?;
        self.original.validate()?;
        self.closed.bytes.validate()?;
        self.closed.incarnation.validate(lookup.scope.physical_authority_id.as_str())?;
        ensure!(self.request_digest == canonical_digest(lookup)? && self.nonce == lookup.nonce
            && self.original.deployment_id == lookup.deployment_id
            && self.original.writer == lookup.writer
            && self.original.scope == lookup.scope
            && self.original.binding_spec_revision == lookup.binding_spec_revision
            && self.original.profile_digest == lookup.profile_digest
            && lookup.upload_id.as_ref().is_none_or(|id| id == &self.original.upload.upload_id)
            && self.closed.bytes == lookup.expected && digest_string(&self.closed.receipt_digest)
            && crate::surface_write::strong_if_match_etag(&self.closed.etag)? == self.closed.etag
            && self.observed_at >= lookup.issued_at && self.observed_at <= latest_now,
            "OCI source reply differs from exact current selection");
        ensure!(serde_json::to_vec(self)?.len() <= MAX_OCI_SOURCE_BYTES,
            "OCI source reply exceeds budget");
        Ok(())
    }

    /// Signs only the exact observed reply under the independent physical role.
    ///
    /// # Errors
    /// Refuses malformed correlation or signing failure.
    pub fn sign(&self, lookup: &OciSourceLookup, key: &StorageWorkKey,
        latest_now: i64) -> Result<(Vec<u8>, String)> {
        self.validate_for(lookup, latest_now)?;
        let body = serde_json::to_vec(self)?;
        let signature = key.sign_body(&[REPLY, &body].concat())?;
        Ok((body, signature))
    }

    /// Authenticates retained positive facts without granting an effect.
    ///
    /// # Errors
    /// Refuses bad MAC, noncanonical bytes, drift, stale request or false closure.
    pub fn authenticate(lookup: &OciSourceLookup, key: &StorageWorkKey,
        signature: &str, body: &[u8], latest_now: i64) -> Result<Self> {
        ensure!(body.len() <= MAX_OCI_SOURCE_BYTES, "OCI source reply oversized");
        key.verify_body(signature, &[REPLY, body].concat())?;
        let reply: Self = serde_json::from_slice(body)?;
        ensure!(serde_json::to_vec(&reply)? == body, "OCI source reply noncanonical");
        reply.validate_for(lookup, latest_now)?;
        Ok(reply)
    }
}
