//! Closed controlled authority for the production bounded metadata executor.
//!
//! This protocol exercises query output independently of the stream experiment.
//! Its dedicated key and domains cannot authorize production ingress, storage
//! mutations or hosted acceptance. Replies bind the complete original and nonce.
//!
//! ```text
//! request = {version, nonce, candidate: exact reserved source context}
//! reply = {request_sha256, nonce, observed_at, outcome, source_bytes}
//! ```

use anyhow::{ensure, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use super::MirrorLiveCandidateRequest;
use crate::hybrid_ingress::live::HybridLiveDeliveryClass;
use crate::storage_work::{StorageWorkKey, StorageWorkOutcome};

/// Fixture-only endpoint, absent from ordinary Worker execution.
pub const LIVE_QUERY_CANDIDATE_PATH: &str = "/__hub/mirror-live-query-candidate";
/// Maximum exact encoded query response, distinct from source stream bytes.
pub const LIVE_QUERY_CANDIDATE_REPLY_BYTES: usize = 256 * 1024;
const REQUEST_DOMAIN: &[u8] = b"aos.hub.mirror-live-query-controlled-candidate.v1\0";
const REPLY_DOMAIN: &[u8] = b"aos.hub.mirror-live-query-controlled-candidate.reply.v1\0";

/// Selects one bounded metadata read under a fresh closed experiment context.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorLiveQueryCandidateRequest {
    /// Closed query protocol version.
    pub version: u8,
    /// Fresh independent lowercase 32-hex challenge.
    pub nonce: String,
    /// Actual source, script, raw profile and reserved run namespace.
    pub candidate: MirrorLiveCandidateRequest,
}

impl MirrorLiveQueryCandidateRequest {
    /// Checks the original fixture context and strictly metadata-only geometry.
    ///
    /// # Errors
    /// Refuses expired controls, foreign namespace, HEAD, bulk or excessive bytes.
    pub fn validate(&self, deployment: &str, latest_now: i64) -> Result<()> {
        self.candidate.validate(deployment, latest_now)?;
        ensure!(
            self.version == 1
                && self.nonce.len() == 32
                && self
                    .nonce
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                && self.candidate.request.method == "GET"
                && self.candidate.target.class == HybridLiveDeliveryClass::Metadata
                && self.candidate.target.maximum_bytes <= 128 * 1024
                && serde_json::to_vec(self)?.len() <= super::LIVE_CANDIDATE_CONTROL_BYTES,
            "controlled live query geometry differs"
        );
        Ok(())
    }
}

/// Records actual bounded query output without supplying a production proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorLiveQueryCandidateReply {
    /// Closed reply version.
    pub version: u8,
    /// Canonical commitment to the complete request, including all original pins.
    pub request_sha256: String,
    /// Exact request challenge; a foreign nonce cannot correlate.
    pub nonce: String,
    /// Actual qualified completion clock.
    pub observed_at: i64,
    /// Actual metadata output or positive upstream 404; no other result kind.
    pub outcome: StorageWorkOutcome,
    /// Actual source bytes consumed by the common production executor.
    pub source_bytes: u64,
}

impl MirrorLiveQueryCandidateReply {
    /// Checks exact original correlation, current freshness and actual output bytes.
    ///
    /// # Errors
    /// Refuses substitutions, stale replies, nonquery results or inconsistent bytes.
    pub fn validate_for(
        &self,
        request: &MirrorLiveQueryCandidateRequest,
        latest_now: i64,
    ) -> Result<()> {
        request.validate(&request.candidate.request.deployment_id, latest_now)?;
        ensure!(
            self.version == 1
                && self.nonce == request.nonce
                && self.request_sha256 == crate::mirror_work::digest(request)?
                && request.candidate.request.issued_at <= self.observed_at
                && self.observed_at <= latest_now
                && serde_json::to_vec(self)?.len() <= LIVE_QUERY_CANDIDATE_REPLY_BYTES,
            "controlled live query reply differs"
        );
        match &self.outcome {
            StorageWorkOutcome::MirrorLiveMetadata {
                sha256,
                size,
                content_base64,
            } => {
                ensure!(
                    *size <= request.candidate.target.maximum_bytes
                        && *size <= 128 * 1024
                        && content_base64.len() <= (128 * 1024_usize).div_ceil(3) * 4,
                    "controlled query output exceeds bound"
                );
                let bytes = base64::engine::general_purpose::STANDARD.decode(content_base64)?;
                ensure!(
                    bytes.len() as u64 == *size
                        && self.source_bytes == *size
                        && crate::hybrid_ingress::body_sha256(&bytes) == *sha256,
                    "controlled query bytes differ"
                );
            }
            StorageWorkOutcome::NotFound => {
                ensure!(self.source_bytes == 0, "absence carried bytes")
            }
            _ => anyhow::bail!("controlled query result kind refused"),
        }
        Ok(())
    }
}

/// Signs only the independently purposed controlled query request.
///
/// # Errors
/// Refuses malformed original controls or signing failure.
pub fn sign_mirror_live_query_candidate(
    key: &StorageWorkKey,
    request: &MirrorLiveQueryCandidateRequest,
) -> Result<String> {
    request.validate(
        &request.candidate.request.deployment_id,
        request.candidate.request.issued_at,
    )?;
    Ok(key.sign_body(&[REQUEST_DOMAIN, &serde_json::to_vec(request)?].concat())?)
}

/// Authenticates actual bounded request bytes before query admission.
///
/// # Errors
/// Refuses invalid signatures, oversized controls or expired originals.
pub fn verify_mirror_live_query_candidate(
    key: &StorageWorkKey,
    signature: &str,
    bytes: &[u8],
    deployment: &str,
    latest_now: i64,
) -> Result<MirrorLiveQueryCandidateRequest> {
    ensure!(
        bytes.len() <= super::LIVE_CANDIDATE_CONTROL_BYTES,
        "controlled query request exceeds bound"
    );
    key.verify_body(signature, &[REQUEST_DOMAIN, bytes].concat())?;
    let request: MirrorLiveQueryCandidateRequest = serde_json::from_slice(bytes)?;
    request.validate(deployment, latest_now)?;
    Ok(request)
}

/// Signs the actual original-bound query completion under its reply domain.
///
/// # Errors
/// Refuses malformed results, stale completion or signing failure.
pub fn sign_mirror_live_query_candidate_reply(
    key: &StorageWorkKey,
    request: &MirrorLiveQueryCandidateRequest,
    reply: &MirrorLiveQueryCandidateReply,
) -> Result<String> {
    reply.validate_for(request, reply.observed_at)?;
    Ok(key.sign_body(&[REPLY_DOMAIN, &serde_json::to_vec(reply)?].concat())?)
}

/// Authenticates and correlates actual query output without minting admission.
///
/// # Errors
/// Refuses foreign signatures, nonce/original substitutions or expired replies.
pub fn verify_mirror_live_query_candidate_reply(
    key: &StorageWorkKey,
    signature: &str,
    bytes: &[u8],
    request: &MirrorLiveQueryCandidateRequest,
    latest_now: i64,
) -> Result<MirrorLiveQueryCandidateReply> {
    ensure!(
        bytes.len() <= LIVE_QUERY_CANDIDATE_REPLY_BYTES,
        "controlled query reply exceeds bound"
    );
    key.verify_body(signature, &[REPLY_DOMAIN, bytes].concat())?;
    let reply: MirrorLiveQueryCandidateReply = serde_json::from_slice(bytes)?;
    reply.validate_for(request, latest_now)?;
    Ok(reply)
}

#[cfg(test)]
mod tests;
