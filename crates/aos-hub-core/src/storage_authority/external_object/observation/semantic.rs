//! Paired metadata observations without a Native lease-renewal role.
//!
//! The Native signs a fresh semantic HEAD plan and an exact SQL guard stamp.
//! The Worker resolves the independently configured profile and acquires its
//! read lease. Replies bind the original semantic bytes, not the internal lease.
//!
//! ```text
//! POST /_internal/storage/external-observation-plan/v1
//! {version,domain,operation_id,binding_write_revision,plan,expected_guard_stamp,
//!  profile_selector,expected_profile_fingerprint}
//! ```

use std::io::{self, Write};

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{ExternalObservationOutcome, MAX_OBSERVATION_REPLY_BYTES};
use crate::direct_upload::DirectExternalProfileSelector;
use crate::storage_authority::{lease::LeaseInteger, StorageGuardStamp};
use crate::storage_work::{StorageWorkKey, StorageWorkOperation, StorageWorkPlan};

/// Paired semantic route; older executors reject the unknown path.
pub const SEMANTIC_OBSERVATION_PATH: &str = "/_internal/storage/external-observation-plan/v1";
/// Bounds the complete semantic plan before authentication and decoding.
pub const MAX_SEMANTIC_OBSERVATION_BYTES: usize = 64 * 1024;
/// Separates Native semantic authorization from token-bearing provider requests.
pub const SEMANTIC_OBSERVATION_DOMAIN: &str = "aos.external-observation-plan.v1";
/// Separates replies bound to original semantic requests from other receipts.
pub const SEMANTIC_OBSERVATION_REPLY_DOMAIN: &str = "aos.external-observation-plan-reply.v1";

/// A fresh paired HEAD authorization with mandatory retained identity and pins.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticExternalObservationRequest {
    /// Closed wire version, currently one.
    pub version: u8,
    /// Exact authenticated purpose domain.
    pub domain: String,
    /// New retained observation identity for this transport invocation.
    pub operation_id: String,
    /// Exact current binding writer revision, separate from binding resource RV.
    pub binding_write_revision: LeaseInteger,
    /// Original HEAD plan, including the caller's unchanged permission deadline.
    pub plan: StorageWorkPlan,
    /// Exact positive stamp retained by SQL; missing identity cannot be repaired.
    pub expected_guard_stamp: StorageGuardStamp,
    /// Server-selected association and credential references, never client URLs.
    pub profile_selector: DirectExternalProfileSelector,
    /// Exact canonical profile commitment from independently reviewed setup.
    pub expected_profile_fingerprint: String,
}

impl SemanticExternalObservationRequest {
    /// Checks closed semantic scope and the original application permission.
    ///
    /// This supplies no epoch lease or provider execution permission.
    ///
    /// # Errors
    /// Returns an error for identity, profile, deployment, HEAD scope or expiry.
    pub fn validate(&self, deployment: &str, now: i64) -> Result<()> {
        self.validate_shape()?;
        self.plan.validate(deployment, now)?;
        Ok(())
    }

    /// Encodes and authenticates the complete bounded original semantic request.
    ///
    /// # Errors
    /// Returns an error for invalid permission, encoding or request size.
    pub fn sign(
        &self,
        key: &StorageWorkKey,
        deployment: &str,
        now: i64,
    ) -> Result<(Vec<u8>, String)> {
        self.validate(deployment, now)?;
        let bytes = encode(self, MAX_SEMANTIC_OBSERVATION_BYTES)?;
        let mac = key.sign_body(&bytes)?;
        Ok((bytes, mac))
    }

    /// Authenticates bounded exact bytes before closed canonical decoding.
    ///
    /// # Errors
    /// Returns an error for bounds, MAC, canonical closure, scope or time.
    pub fn authenticate(
        key: &StorageWorkKey,
        mac: &str,
        bytes: &[u8],
        deployment: &str,
        now: i64,
    ) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_SEMANTIC_OBSERVATION_BYTES,
            "semantic request oversized"
        );
        key.verify_body(mac, bytes)?;
        let value: Self = serde_json::from_slice(bytes)?;
        ensure!(
            encode(&value, MAX_SEMANTIC_OBSERVATION_BYTES)? == bytes,
            "noncanonical semantic request"
        );
        value.validate(deployment, now)?;
        Ok(value)
    }

    fn validate_shape(&self) -> Result<()> {
        ensure!(
            self.version == 1 && self.domain == SEMANTIC_OBSERVATION_DOMAIN,
            "invalid semantic observation domain"
        );
        ensure!(
            !self.operation_id.is_empty()
                && self.operation_id.len() <= 128
                && self
                    .operation_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':')),
            "invalid semantic observation identity"
        );
        self.profile_selector.validate()?;
        let association = &self.profile_selector.association;
        let read = &self.profile_selector.read_credential;
        ensure!(
            matches!(self.plan.operation, StorageWorkOperation::Head { .. })
                && matches!(self.plan.binding_kind.as_str(), "s3" | "r2")
                && self.binding_write_revision.get() > 0
                && association.binding_id.get() == self.plan.binding_id
                && association.binding_resource_version.get() == self.plan.binding_resource_version
                && association.binding_write_revision == self.binding_write_revision
                && self.expected_guard_stamp.physical_authority_id
                    == self.profile_selector.physical_authority_id
                && self.plan.credential_references.len() == 1
                && self.plan.credential_references[0].purpose == "read"
                && u64::try_from(self.plan.credential_references[0].generation).ok()
                    == Some(read.generation.get()),
            "semantic observation profile or HEAD scope differs"
        );
        ensure!(
            valid_digest(&self.expected_profile_fingerprint),
            "invalid semantic profile commitment"
        );
        // Validate structural plan facts without rejecting an exact historical
        // reply merely because its original grant has since expired.
        self.plan
            .validate(&self.plan.deployment_id, self.plan.issued_at)?;
        Ok(())
    }
}

/// Authenticated outcome bound to the exact original semantic request bytes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticExternalObservationReply {
    /// Closed wire version, currently one.
    pub version: u8,
    /// Exact semantic reply domain.
    pub domain: String,
    /// SHA-256 of the original authenticated semantic request.
    pub request_digest: String,
    /// Newly acknowledged interval or explicitly historical replay.
    pub outcome: ExternalObservationOutcome,
}

impl SemanticExternalObservationReply {
    /// Constructs a reply for one exact original semantic request.
    ///
    /// # Errors
    /// Returns an error for malformed request, outcome or identity mismatch.
    pub fn new(request: &[u8], outcome: ExternalObservationOutcome) -> Result<Self> {
        ensure!(
            request.len() <= MAX_SEMANTIC_OBSERVATION_BYTES,
            "semantic request oversized"
        );
        let value = Self {
            version: 1,
            domain: SEMANTIC_OBSERVATION_REPLY_DOMAIN.into(),
            request_digest: hex::encode(Sha256::digest(request)),
            outcome,
        };
        value.validate(request)?;
        Ok(value)
    }

    /// Signs the closed bounded reply without converting history to freshness.
    ///
    /// # Errors
    /// Returns an error for context, outcome or encoded reply bounds.
    pub fn sign(&self, key: &StorageWorkKey, request: &[u8]) -> Result<(Vec<u8>, String)> {
        self.validate(request)?;
        let bytes = encode(self, MAX_OBSERVATION_REPLY_BYTES)?;
        let mac = key.sign_body(&bytes)?;
        Ok((bytes, mac))
    }

    /// Authenticates an exact bounded reply to the original semantic bytes.
    ///
    /// This proves correlation, not recipient-time authority or a body-read grant.
    ///
    /// # Errors
    /// Returns an error for bounds, MAC, canonical shape or changed request/stamp.
    pub fn authenticate(
        key: &StorageWorkKey,
        mac: &str,
        bytes: &[u8],
        request: &[u8],
    ) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_OBSERVATION_REPLY_BYTES,
            "semantic reply oversized"
        );
        key.verify_body(mac, bytes)?;
        let value: Self = serde_json::from_slice(bytes)?;
        ensure!(
            encode(&value, MAX_OBSERVATION_REPLY_BYTES)? == bytes,
            "noncanonical semantic reply"
        );
        value.validate(request)?;
        Ok(value)
    }

    fn validate(&self, request: &[u8]) -> Result<()> {
        ensure!(
            request.len() <= MAX_SEMANTIC_OBSERVATION_BYTES
                && self.version == 1
                && self.domain == SEMANTIC_OBSERVATION_REPLY_DOMAIN
                && self.request_digest == hex::encode(Sha256::digest(request)),
            "semantic reply context differs"
        );
        let original: SemanticExternalObservationRequest = serde_json::from_slice(request)?;
        original.validate_shape()?;
        ensure!(
            encode(&original, MAX_SEMANTIC_OBSERVATION_BYTES)? == request,
            "noncanonical original semantic request"
        );
        let value = match &self.outcome {
            ExternalObservationOutcome::ObservedThisInvocation(value)
            | ExternalObservationOutcome::HistoricalObservation(value) => value,
        };
        value.validate()?;
        ensure!(
            value.operation_id == original.operation_id
                && value.guard_stamp == original.expected_guard_stamp,
            "semantic reply operation or stamp differs"
        );
        Ok(())
    }
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn encode<T: Serialize>(value: &T, maximum: usize) -> Result<Vec<u8>> {
    let mut writer = BoundedEncoding {
        bytes: Vec::new(),
        maximum,
    };
    serde_json::to_writer(&mut writer, value)?;
    Ok(writer.bytes)
}

struct BoundedEncoding {
    bytes: Vec<u8>,
    maximum: usize,
}

impl Write for BoundedEncoding {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes
            .len()
            .checked_add(bytes.len())
            .filter(|length| *length <= self.maximum)
            .ok_or_else(|| io::Error::other("semantic encoding oversized"))?;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
