//! Separate reviewer purpose for fresh uncached upstream client delivery.
//!
//! Mirror publication and pack parsing approval do not cover this streaming
//! response path. The existing reviewer role signs actual request, response,
//! cancellation, memory and capacity observations for the exact release pack.
//! Controlled reports never enable production.
//!
//! ```text
//! live review = exact signed mirror artifact + fixed stream geometry + reports
//! ```

use anyhow::{ensure, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use super::{MirrorAcceptanceArtifact, MirrorAcceptanceExecution};
use crate::{direct_upload::valid_direct_digest, mirror_work::digest};

const DOMAIN: &[u8] = b"aos.hub.accepted-managed-mirror-live-delivery.v1\0";

/// Maximum independently installed live delivery review document.
pub const LIVE_ACCEPTANCE_MAX_BYTES: usize = 32 * 1024;

/// Names the uncached streaming purpose independently of publication or parsing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MirrorLivePurpose {
    /// Fresh GET/HEAD, bounded metadata and uncached release pack responses.
    ManagedMirrorLiveDeliveryV1,
}

/// Names the actual boundary exercised by an independently reviewed raw report.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MirrorLiveCase {
    /// Two reads observe an upstream pointer change without a stored cache hit.
    FreshPointer,
    /// HEAD forwards no upstream body and retains the exact response length.
    Head,
    /// The full maximum admitted pack streams directly to the client.
    FullPack,
    /// An upstream 404 emits absence without creating a storage object.
    Missing,
    /// Redirects are refused rather than following a foreign origin.
    RedirectRefusal,
    /// An unsafe source is refused before upstream dispatch.
    UnsafeSourceRefusal,
    /// An expired request dispatches no source read, including after a wait.
    ExpiredDispatchRefusal,
    /// Foreign signed request context refuses before source dispatch.
    ForeignContextRefusal,
    /// Unexpected content encoding refuses before delivering content.
    EncodingRefusal,
    /// A truncated or oversized source errors the client stream.
    LengthRefusal,
    /// Client cancellation releases source capacity and cancels the source reader.
    Cancellation,
    /// Two metadata streams complete while a bulk stream owns reserved capacity.
    MetadataDuringBulk,
    /// A signed bounded metadata query returns exact output without Native source fetch.
    BoundedMetadataQuery,
}

/// Commits an actual closed control/body observation, not a configured assertion.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MirrorLiveMeasurement {
    /// Exact case exercised by the raw evidence.
    pub case: MirrorLiveCase,
    /// Raw report commitment, including failure history.
    pub report_sha256: String,
    /// Exact authorized query or request commitment.
    pub request_sha256: String,
    /// Exact delivered response or refusal transcript commitment.
    pub response_sha256: String,
    /// Actual samples observed.
    pub samples: u64,
    /// Actual violations; acceptance requires zero.
    pub violations: u64,
    /// Actual provider dispatch count.
    pub provider_dispatches: u64,
    /// Actual response body bytes consumed by clients.
    pub client_bytes: u64,
}

/// Independently signs the exact fresh-delivery implementation and measured bounds.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MirrorLiveAcceptanceArtifact {
    /// Closed document version.
    pub version: u32,
    /// Separate reviewer signing purpose.
    pub purpose: MirrorLivePurpose,
    /// Actual hosted or controlled environment; controlled grants no admission.
    pub execution: MirrorAcceptanceExecution,
    /// Full signed prerequisite artifact commitment, including profile and source.
    pub mirror_artifact_sha256: String,
    /// Maximum actual full response size measured and accepted.
    pub maximum_bytes: u64,
    /// Fixed native input and Rust output chunk bound, exactly 64 KiB.
    pub reader_bytes: u64,
    /// Fixed absolute stream lifetime, exactly 600 seconds from ingress issue.
    pub stream_seconds: u64,
    /// All thirteen closed streaming and bounded-query reports.
    pub measurements: Vec<MirrorLiveMeasurement>,
    /// Whole-worker memory observation including Rust, JS, SDK and live streams.
    pub memory_report_sha256: String,
    /// Actual whole-worker peak under bulk plus two metadata streams.
    pub peak_worker_bytes: u64,
    /// Actual samples of that simultaneous workload.
    pub memory_samples: u64,
    /// Actual bytes received by Native from the bulk source; must be zero.
    pub native_bulk_bytes: u64,
    /// Actual destination provider mutations; this path must issue none.
    pub destination_mutations: u64,
    /// Same complete release pack as the prerequisite mirror review.
    pub release_pack_sha256: String,
    /// Original review issue time.
    pub issued_at: u64,
    /// Original exclusive acceptance cutoff.
    pub valid_until: u64,
    /// Reviewer Ed25519 signature in the live-specific domain.
    pub signature: String,
}

impl MirrorLiveAcceptanceArtifact {
    /// Rechecks immutable acceptance before a new source dispatch.
    ///
    /// # Errors
    /// Returns an error for a future or expired original review.
    pub fn validate_dispatch_time(&self, now: u64) -> Result<()> {
        ensure!(
            self.issued_at <= now && now < self.valid_until,
            "live review expired"
        );
        Ok(())
    }

    /// Checks exact prerequisite, geometry and actual evidence closure.
    ///
    /// # Errors
    /// Returns an error for foreign builds, incomplete reports or unsafe observations.
    pub fn validate_unsigned(&self, mirror: &MirrorAcceptanceArtifact, now: u64) -> Result<()> {
        mirror.validate_unsigned(now)?;
        self.validate_dispatch_time(now)?;
        ensure!(
            self.version == 1
                && self.execution == mirror.execution
                && self.mirror_artifact_sha256 == digest(mirror)?
                && self.maximum_bytes > 0
                && self.maximum_bytes <= mirror.maximum_object_bytes
                && self.reader_bytes == 64 * 1024
                && self.stream_seconds == 600
                && self.release_pack_sha256 == mirror.evidence.release.release_pack_sha256
                && valid_direct_digest(&self.memory_report_sha256)
                && self.peak_worker_bytes > 0
                && self.peak_worker_bytes < 128 * 1024 * 1024
                && self.memory_samples > 0
                && self.native_bulk_bytes == 0
                && self.destination_mutations == 0
                && self.measurements.len() == 13,
            "live source, geometry or memory evidence differs"
        );

        let mut cases = std::collections::BTreeSet::new();
        for report in &self.measurements {
            ensure!(
                cases.insert(report.case)
                    && report.samples > 0
                    && report.violations == 0
                    && [
                        &report.report_sha256,
                        &report.request_sha256,
                        &report.response_sha256
                    ]
                    .into_iter()
                    .all(|hash| valid_direct_digest(hash)),
                "live report incomplete"
            );
            if matches!(
                report.case,
                MirrorLiveCase::ExpiredDispatchRefusal
                    | MirrorLiveCase::ForeignContextRefusal
                    | MirrorLiveCase::UnsafeSourceRefusal
            ) {
                ensure!(
                    report.provider_dispatches == 0,
                    "refused live request dispatched"
                );
            }
            if report.case == MirrorLiveCase::Head {
                ensure!(report.client_bytes == 0, "HEAD delivered body bytes");
            }
            if report.case == MirrorLiveCase::FullPack {
                ensure!(
                    report.client_bytes == self.maximum_bytes && report.provider_dispatches > 0,
                    "live full streaming boundary not observed"
                );
            }
            if report.case == MirrorLiveCase::BoundedMetadataQuery {
                ensure!(
                    report.provider_dispatches > 0
                        && report.client_bytes > 0
                        && report.client_bytes <= 256 * 1024,
                    "bounded signed metadata query not observed"
                );
            }
        }
        ensure!(
            serde_json::to_vec(self)?.len() <= LIVE_ACCEPTANCE_MAX_BYTES,
            "live review exceeds bound"
        );
        Ok(())
    }

    /// Encodes the canonical separately purposed reviewer statement.
    ///
    /// # Errors
    /// Returns an error if the closed review exceeds its control bound.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        let bytes = serde_json::to_vec(&unsigned)?;
        ensure!(
            bytes.len() <= LIVE_ACCEPTANCE_MAX_BYTES,
            "live signing payload too large"
        );
        Ok([DOMAIN, bytes.as_slice()].concat())
    }

    /// Verifies the existing reviewer role and exact hosted prerequisite.
    ///
    /// # Errors
    /// Returns an error for a foreign signature, controlled report or changed release.
    pub fn require_production(
        &self,
        mirror: &MirrorAcceptanceArtifact,
        public_hex: &str,
        now: u64,
    ) -> Result<()> {
        mirror.verify(public_hex, now)?;
        self.validate_unsigned(mirror, now)?;
        ensure!(
            self.execution == MirrorAcceptanceExecution::Hosted
                && valid_direct_digest(public_hex)
                && self.signature.len() == 128
                && self
                    .signature
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "controlled or foreign live review cannot authorize production"
        );
        let public: [u8; 32] = hex::decode(public_hex)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("live reviewer key malformed"))?;
        let signature = Signature::from_slice(&hex::decode(&self.signature)?)?;
        VerifyingKey::from_bytes(&public)?
            .verify_strict(&self.signing_bytes()?, &signature)
            .map_err(|_| anyhow::anyhow!("live review signature invalid"))?;
        Ok(())
    }
}

/// Addresses one installed live purpose document for an exact accepted mirror build.
///
/// # Errors
/// Returns an error for an invalid prerequisite commitment.
pub fn mirror_live_acceptance_key(mirror_artifact_sha256: &str) -> Result<String> {
    ensure!(
        valid_direct_digest(mirror_artifact_sha256),
        "live prerequisite absent"
    );
    Ok(format!("accepted-mirror-live-v1/{mirror_artifact_sha256}"))
}

#[cfg(test)]
mod tests;
