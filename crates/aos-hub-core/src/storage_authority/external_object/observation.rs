//! Source-bound guarded HEAD observations and explicitly historical replay.
//!
//! A new observation reserves the addressed physical object's read slot. Its
//! receipt covers one HEAD interval and never authorizes a later mutable GET.
//! Missing legacy identity cannot be repaired through this wire implicitly.
//!
//! ```text
//! POST /_internal/storage/external-observation/v1
//! {version,domain,authorization,expectation}
//! ```

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{ExternalObjectHead, ExternalObjectRequest};
use crate::storage_authority::StorageGuardStamp;
use crate::storage_work::{StorageWorkKey, StorageWorkOperation};

/// Paired semantic requests whose read lease is acquired only by the Worker.
pub mod semantic;

/// Closed metadata-only endpoint, rejected by older executors.
pub const EXTERNAL_OBSERVATION_PATH: &str = "/_internal/storage/external-observation/v1";
/// Maximum whole canonical request before authentication or decoding.
pub const MAX_OBSERVATION_REQUEST_BYTES: usize = 256 * 1024;
/// Maximum whole signed reply, including exact request commitment.
pub const MAX_OBSERVATION_REPLY_BYTES: usize = 16 * 1024;
/// Application authentication domain for a fresh observation.
pub const OBSERVATION_APPLICATION_DOMAIN: &str = "aos.external-observation-application.v1";
/// Separates authenticated replies from request envelopes and other receipts.
pub const OBSERVATION_REPLY_DOMAIN: &str = "aos.external-observation-reply.v1";

/// Explicit identity policy; an absent legacy stamp is never upgraded implicitly.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObservationExpectation {
    /// Captures an already positive managed identity for a new observation run.
    CaptureCurrentIdentity,
    /// Requires the caller's exact previously retained managed identity.
    KnownStamp {
        /// Permanent authority and positive incarnation, never an ETag surrogate.
        stamp: StorageGuardStamp,
    },
}

/// Fresh bounded application and read-lease permission for one retained HEAD.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalObservationRequest {
    /// Closed format version, currently one.
    pub version: u8,
    /// Exact application domain, covered by the whole-body MAC.
    pub domain: String,
    /// Retained operation identity, exact binding revisions and fresh permission.
    pub authorization: ExternalObjectRequest,
    /// Explicit caller policy, covered by authentication and immutable intent.
    pub expectation: ObservationExpectation,
}

impl ExternalObservationRequest {
    /// Validates a HEAD-only request without granting provider permission.
    ///
    /// # Errors
    /// Returns an error for domain, operation, identity, size or permission time.
    pub fn validate(&self, deployment: &str, now: i64) -> Result<()> {
        ensure!(
            self.version == 1 && self.domain == OBSERVATION_APPLICATION_DOMAIN,
            "invalid observation application domain"
        );
        self.authorization.validate(deployment, now)?;
        ensure!(
            matches!(
                self.authorization.plan.operation,
                StorageWorkOperation::Head { .. }
            ),
            "observation requires HEAD"
        );
        Ok(())
    }

    /// Signs the complete closed request under the application plan key.
    ///
    /// # Errors
    /// Returns an error for invalid permission or a whole request above the cap.
    pub fn sign(
        &self,
        key: &StorageWorkKey,
        deployment: &str,
        now: i64,
    ) -> Result<(Vec<u8>, String)> {
        self.validate(deployment, now)?;
        let bytes = serde_json::to_vec(self)?;
        ensure!(
            bytes.len() <= MAX_OBSERVATION_REQUEST_BYTES,
            "oversized observation request"
        );
        let mac = key.sign_body(&bytes)?;
        Ok((bytes, mac))
    }

    /// Authenticates exact bounded bytes before parsing and checking permission.
    ///
    /// # Errors
    /// Returns an error for signature, canonical closure, operation or time.
    pub fn authenticate(
        key: &StorageWorkKey,
        mac: &str,
        bytes: &[u8],
        deployment: &str,
        now: i64,
    ) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_OBSERVATION_REQUEST_BYTES,
            "oversized observation request"
        );
        key.verify_body(mac, bytes)?;
        let value: Self = serde_json::from_slice(bytes)?;
        ensure!(
            serde_json::to_vec(&value)? == bytes,
            "noncanonical observation request"
        );
        value.validate(deployment, now)?;
        Ok(value)
    }
}

/// One guarded HEAD interval, with no permission for independent body access.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalObservation {
    /// Original retained business observation identity.
    pub operation_id: String,
    /// Exact permanent semantic context commitment retained by the guard.
    pub intent_digest: String,
    /// Exact one-dispatch turn commitment, including its original nonce.
    pub turn_digest: String,
    /// Positive identity locked throughout this HEAD interval.
    pub guard_stamp: StorageGuardStamp,
    /// Canonical nonnegative time immediately before actual provider HEAD.
    pub observed_at: String,
    /// Positive present metadata or explicit HEAD 404 for this interval.
    pub object: Option<ExternalObjectHead>,
}

impl ExternalObservation {
    /// Checks bounded metadata and closed receipt commitments.
    ///
    /// # Errors
    /// Returns an error for malformed identity, digest, time, size or ETag.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.operation_id.is_empty()
                && self.operation_id.len() <= 128
                && self
                    .operation_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':')),
            "invalid observation identity"
        );
        for digest in [&self.intent_digest, &self.turn_digest] {
            ensure!(
                digest.len() == 64
                    && digest
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "invalid observation commitment"
            );
        }
        let time = self.observed_at.parse::<i64>()?;
        ensure!(
            time >= 0 && time.to_string() == self.observed_at,
            "invalid observation time"
        );
        if let Some(object) = &self.object {
            let size = object.bytes.parse::<u64>()?;
            ensure!(
                size.to_string() == object.bytes && object.etag.len() <= 1024,
                "invalid observation metadata"
            );
            crate::surface_write::strong_if_match_etag(&object.etag)?;
        }
        Ok(())
    }
}

/// Distinguishes newly executed HEAD from immutable terminal history.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "observation",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ExternalObservationOutcome {
    /// This invocation executed and acknowledged the exact guarded HEAD turn.
    ObservedThisInvocation(ExternalObservation),
    /// Exact terminal replay, with no provider I/O and no renewed freshness.
    HistoricalObservation(ExternalObservation),
}

/// Authenticated exact-request-correlated observation response.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalObservationReply {
    /// Closed reply version, currently one.
    pub version: u8,
    /// Exact reply authentication domain.
    pub domain: String,
    /// SHA-256 of the exact authenticated application request bytes.
    pub request_digest: String,
    /// Fresh interval evidence or explicitly historical receipt.
    pub outcome: ExternalObservationOutcome,
}

impl ExternalObservationReply {
    /// Constructs a closed reply for these exact request bytes.
    ///
    /// # Errors
    /// Returns an error for invalid observation metadata or request size.
    pub fn new(request: &[u8], outcome: ExternalObservationOutcome) -> Result<Self> {
        ensure!(
            request.len() <= MAX_OBSERVATION_REQUEST_BYTES,
            "oversized observation request"
        );
        let reply = Self {
            version: 1,
            domain: OBSERVATION_REPLY_DOMAIN.into(),
            request_digest: hex::encode(Sha256::digest(request)),
            outcome,
        };
        reply.validate(request)?;
        Ok(reply)
    }

    /// Signs bounded exact reply bytes; history remains explicitly historical.
    ///
    /// # Errors
    /// Returns an error for invalid context or an oversized encoded reply.
    pub fn sign(&self, key: &StorageWorkKey, request: &[u8]) -> Result<(Vec<u8>, String)> {
        self.validate(request)?;
        let bytes = serde_json::to_vec(self)?;
        ensure!(
            bytes.len() <= MAX_OBSERVATION_REPLY_BYTES,
            "oversized observation reply"
        );
        let mac = key.sign_body(&bytes)?;
        Ok((bytes, mac))
    }

    /// Authenticates a bounded canonical reply to one exact request.
    ///
    /// # Errors
    /// Returns an error for MAC, domain, canonical encoding or request mismatch.
    pub fn authenticate(
        key: &StorageWorkKey,
        mac: &str,
        bytes: &[u8],
        request: &[u8],
    ) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_OBSERVATION_REPLY_BYTES,
            "oversized observation reply"
        );
        key.verify_body(mac, bytes)?;
        let value: Self = serde_json::from_slice(bytes)?;
        ensure!(
            serde_json::to_vec(&value)? == bytes,
            "noncanonical observation reply"
        );
        value.validate(request)?;
        Ok(value)
    }

    fn validate(&self, request: &[u8]) -> Result<()> {
        ensure!(
            request.len() <= MAX_OBSERVATION_REQUEST_BYTES
                && self.version == 1
                && self.domain == OBSERVATION_REPLY_DOMAIN
                && self.request_digest == hex::encode(Sha256::digest(request)),
            "observation reply context mismatch"
        );
        let original: ExternalObservationRequest = serde_json::from_slice(request)?;
        ensure!(
            original.version == 1
                && original.domain == OBSERVATION_APPLICATION_DOMAIN
                && matches!(
                    original.authorization.plan.operation,
                    StorageWorkOperation::Head { .. }
                ),
            "reply requires exact closed HEAD request"
        );
        let value = match &self.outcome {
            ExternalObservationOutcome::ObservedThisInvocation(value)
            | ExternalObservationOutcome::HistoricalObservation(value) => value,
        };
        value.validate()?;
        ensure!(
            value.operation_id == original.authorization.operation_id,
            "reply operation differs"
        );
        if let ObservationExpectation::KnownStamp { stamp } = original.expectation {
            ensure!(value.guard_stamp == stamp, "reply incarnation differs");
        }
        Ok(())
    }
}
