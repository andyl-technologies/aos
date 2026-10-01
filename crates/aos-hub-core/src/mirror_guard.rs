//! Independent, fresh readback of a held physical mirror publication.
//!
//! The guard authenticates a complete immutable original and positive provider
//! receipt. This readback grants no provider dispatch or archive resurrection.
//! Producer acceptance and the guard key have separate authority roles.
//!
//! ```text
//! lookup = original + expected_progress + issuer + nonce + bounded_deadline
//! reply = SHA256(canonical_lookup) + nonce + retained_progress + observed_at
//! ```

use anyhow::{ensure, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    mirror_work::{digest, MirrorOriginal, MirrorProgress},
    storage_work::StorageWorkKey,
};

pub mod batch;

/// Identifies the independent production physical guard lookup.
pub const MIRROR_GUARD_LOOKUP_PATH: &str = "/_internal/storage/mirror-final-guard";
/// Identifies the controlled, reserved-namespace guard lookup.
pub const MIRROR_CANDIDATE_GUARD_LOOKUP_PATH: &str = "/__hub/mirror-candidate-guard";
/// Authenticates a mirror guard control with its independent role key.
pub const MIRROR_GUARD_SIGNATURE_HEADER: &str = "x-aos-mirror-guard-signature";
/// Bounds both canonical lookup and reply envelopes.
pub const MIRROR_GUARD_MAX_BYTES: usize = 256 * 1024;

const REQUEST_DOMAIN: &[u8] = b"aos.hub.mirror-final-guard-request.v1\0";
const REPLY_DOMAIN: &[u8] = b"aos.hub.mirror-final-guard-reply.v1\0";

/// Separates production proof from a reserved controlled experiment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MirrorGuardExecution {
    /// Proves a currently held ordinary managed publication.
    Hosted,
    /// Proves only a reserved controlled destination, never hosted acceptance.
    ControlledCandidate,
}

/// Pins the actual independently selected guard implementation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorGuardIssuer {
    /// SHA-256 of the actual compiled Worker source.
    pub source_digest: String,
    /// Exact deployed script version, or source-derived emulator identity.
    pub script_version: String,
}

/// Challenges the held guard with the full final publication identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorGuardLookup {
    /// Closed wire version.
    pub version: u32,
    /// Exact configured Native and Worker deployment.
    pub deployment_id: String,
    /// Expected execution authority and namespace.
    pub execution: MirrorGuardExecution,
    /// Independently selected actual guard code identity.
    pub issuer: MirrorGuardIssuer,
    /// Exact independently selected bounded UTC uncertainty of this issuer.
    pub clock_uncertainty_seconds: u64,
    /// Complete retained Native original, including its business operation.
    pub original: MirrorOriginal,
    /// Complete positive destination progress expected by Native.
    pub expected: MirrorProgress,
    /// Fresh random 32-byte challenge encoded as lowercase hexadecimal.
    pub request_nonce: String,
    /// Original challenge issue time in UTC seconds.
    pub issued_at: u64,
    /// Original exclusive deadline, at most 30 seconds after issue.
    pub expires_at: u64,
}

impl MirrorGuardLookup {
    /// Checks the exact publication, issuer, namespace and fresh deadline.
    ///
    /// # Errors
    /// Returns an error for malformed pins, nonpositive progress or stale time.
    pub fn validate(&self, deployment: &str, latest_now: u64) -> Result<()> {
        ensure!(
            self.version == 1
                && !self.deployment_id.is_empty()
                && self.deployment_id.len() <= 256
                && self.deployment_id == deployment
                && !self.deployment_id.chars().any(char::is_control)
                && hex(&self.request_nonce, 64)
                && (1..30).contains(&self.clock_uncertainty_seconds)
                && self.issued_at <= latest_now
                && latest_now < self.expires_at
                && self
                    .expires_at
                    .checked_sub(self.issued_at)
                    .is_some_and(|ttl| (1..=30).contains(&ttl)),
            "mirror guard challenge is invalid or stale"
        );
        validate_issuer(&self.issuer, self.execution)?;
        validate_execution(&self.original, self.execution)?;
        self.expected.commit_digest(&self.original)?;
        bounded(self)?;
        Ok(())
    }
}

/// Returns one retained final progress under the exact fresh challenge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorGuardReply {
    /// Closed wire version.
    pub version: u32,
    /// SHA-256 of the complete canonical lookup, including issuer and deadline.
    pub request_digest: String,
    /// Exact fresh original challenge nonce.
    pub request_nonce: String,
    /// SHA-256 of the full independently retained original.
    pub original_digest: String,
    /// Actual compiled guard source and deployed script.
    pub issuer: MirrorGuardIssuer,
    /// Full independently retained positive final provider progress.
    pub progress: MirrorProgress,
    /// Latest bounded clock at the guard's read-only observation.
    pub observed_at: u64,
}

/// Preserves the canonical authenticated control body and signature.
#[derive(Clone, Debug)]
pub struct SignedMirrorGuardControl {
    /// Canonical bounded JSON bytes.
    pub body: Vec<u8>,
    /// Purpose-separated MAC under the independent guard role key.
    pub signature: String,
}

/// Holds a cryptographically verified proof with no public constructor.
#[derive(Clone, Debug)]
pub struct VerifiedMirrorGuardProof {
    request: MirrorGuardLookup,
    reply: MirrorGuardReply,
}

impl VerifiedMirrorGuardProof {
    /// Rechecks the publication at raw SQL UTC time using the pinned uncertainty.
    ///
    /// # Errors
    /// Returns an error for changed original, progress, execution or stale time.
    pub fn validate_for(
        &self,
        original: &MirrorOriginal,
        progress: &MirrorProgress,
        now: u64,
    ) -> Result<()> {
        ensure!(
            self.request.original == *original && self.request.expected == *progress,
            "mirror guard proof changed the complete original or progress"
        );
        let latest_now = now
            .checked_add(self.request.clock_uncertainty_seconds)
            .ok_or_else(|| anyhow::anyhow!("mirror guard proof clock overflow"))?;
        validate_reply(&self.reply, &self.request, latest_now)
    }

    /// Returns the independently bound original.
    pub fn original(&self) -> &MirrorOriginal {
        &self.request.original
    }

    /// Returns the independently retained complete positive progress.
    pub fn progress(&self) -> &MirrorProgress {
        &self.reply.progress
    }

    /// Returns the proof's production or controlled authority.
    pub fn execution(&self) -> MirrorGuardExecution {
        self.request.execution
    }

    /// Returns the actual independently selected implementation identity.
    pub fn issuer(&self) -> &MirrorGuardIssuer {
        &self.reply.issuer
    }

    /// Returns the latest bounded observation time of the held receipt.
    pub fn observed_at(&self) -> u64 {
        self.reply.observed_at
    }

    /// Returns the exclusive remaining deadline at raw UTC time.
    ///
    /// The retained uncertainty is projected exactly once. A caller can bound
    /// SQL capacity and execution waits without renewing the signed challenge.
    ///
    /// # Errors
    /// Returns an error for stale proof, clock overflow or future observation.
    pub fn remaining_validity_seconds(&self, now: u64) -> Result<u64> {
        let latest_now = now
            .checked_add(self.request.clock_uncertainty_seconds)
            .ok_or_else(|| anyhow::anyhow!("mirror guard proof clock overflow"))?;
        validate_reply(&self.reply, &self.request, latest_now)?;
        self.request
            .expires_at
            .checked_sub(latest_now)
            .ok_or_else(|| anyhow::anyhow!("mirror guard proof deadline elapsed"))
    }
}

/// Signs one canonical fresh mirror guard challenge.
///
/// # Errors
/// Returns an error for an invalid challenge, encoding or control bound.
pub fn sign_mirror_guard_lookup(
    key: &StorageWorkKey,
    request: &MirrorGuardLookup,
) -> Result<SignedMirrorGuardControl> {
    request.validate(&request.deployment_id, request.issued_at)?;
    sign(key, REQUEST_DOMAIN, request)
}

/// Authenticates and validates a canonical fresh challenge before guard lookup.
///
/// # Errors
/// Returns an error for a foreign MAC purpose, body, deployment or stale challenge.
pub fn verify_mirror_guard_lookup(
    key: &StorageWorkKey,
    signature: &str,
    body: &[u8],
    deployment: &str,
    latest_now: u64,
) -> Result<MirrorGuardLookup> {
    let request: MirrorGuardLookup = verify(key, REQUEST_DOMAIN, signature, body)?;
    request.validate(deployment, latest_now)?;
    Ok(request)
}

/// Signs one exact independently retained progress under its original challenge.
///
/// # Errors
/// Returns an error for a changed original, issuer, progress or stale observation.
pub fn sign_mirror_guard_reply(
    key: &StorageWorkKey,
    reply: &MirrorGuardReply,
    request: &MirrorGuardLookup,
) -> Result<SignedMirrorGuardControl> {
    validate_reply(reply, request, reply.observed_at)?;
    sign(key, REPLY_DOMAIN, reply)
}

/// Produces an opaque final SQL proof after independent reply authentication.
///
/// # Errors
/// Returns an error for a changed nonce, body, incarnation, issuer or stale proof.
pub fn verify_mirror_guard_reply(
    key: &StorageWorkKey,
    signature: &str,
    body: &[u8],
    request: &MirrorGuardLookup,
    latest_now: u64,
) -> Result<VerifiedMirrorGuardProof> {
    let reply: MirrorGuardReply = verify(key, REPLY_DOMAIN, signature, body)?;
    validate_reply(&reply, request, latest_now)?;
    Ok(VerifiedMirrorGuardProof {
        request: request.clone(),
        reply,
    })
}

/// Checks a retained reply's exact correlation and original observation horizon.
///
/// The recorded observation time checks internal consistency, not current
/// freshness. This does not authenticate the reply or create an opaque guard
/// proof. Observers must independently correlate the exact body digest and
/// original request with an authenticated handler's accepted response.
///
/// # Errors
/// Returns an error for changed originals, issuer, nonce, progress, observation
/// time or canonical control bounds.
pub fn validate_mirror_guard_reply_observation(
    request: &MirrorGuardLookup,
    reply: &MirrorGuardReply,
) -> Result<()> {
    validate_reply(reply, request, reply.observed_at)
}

fn validate_reply(
    reply: &MirrorGuardReply,
    request: &MirrorGuardLookup,
    latest_now: u64,
) -> Result<()> {
    request.validate(&request.deployment_id, latest_now)?;
    ensure!(
        reply.version == 1
            && reply.request_digest == digest(request)?
            && reply.request_nonce == request.request_nonce
            && reply.original_digest == digest(&request.original)?
            && reply.issuer == request.issuer
            && reply.progress == request.expected
            && request.issued_at <= reply.observed_at
            && reply.observed_at <= latest_now
            && reply.observed_at < request.expires_at,
        "mirror guard reply changed the challenge or held final receipt"
    );
    reply.progress.commit_digest(&request.original)?;
    bounded(reply)?;
    Ok(())
}

fn validate_execution(original: &MirrorOriginal, execution: MirrorGuardExecution) -> Result<()> {
    original.validate()?;
    // Legacy committed originals replay in SQL; new final publication proves a
    // distinct business operation, independently of scheduler delivery leases.
    ensure!(
        original.copy_operation_id.is_some(),
        "mirror guard requires a retained copy operation"
    );
    let segments: Vec<_> = original.placement_prefix.split('/').collect();
    let reserved = segments.first() == Some(&".aos-mirror-qualification");
    match execution {
        MirrorGuardExecution::Hosted => ensure!(
            !reserved,
            "controlled mirror proof cannot authorize production"
        ),
        MirrorGuardExecution::ControlledCandidate => ensure!(
            reserved && segments.len() == 3 && hex(segments[1], 32) && segments[2] == "final",
            "controlled mirror guard escaped its reserved namespace"
        ),
    }
    Ok(())
}

fn validate_issuer(issuer: &MirrorGuardIssuer, execution: MirrorGuardExecution) -> Result<()> {
    ensure!(
        hex(&issuer.source_digest, 64)
            && !issuer.script_version.is_empty()
            && issuer.script_version.len() <= 256
            && !issuer.script_version.chars().any(char::is_control),
        "mirror guard issuer is invalid"
    );
    match execution {
        MirrorGuardExecution::Hosted => ensure!(
            !issuer.script_version.starts_with("emulated-"),
            "emulated guard cannot issue hosted proof"
        ),
        MirrorGuardExecution::ControlledCandidate => ensure!(
            issuer.script_version == format!("emulated-{}", issuer.source_digest),
            "controlled guard script differs from compiled source"
        ),
    }
    Ok(())
}

fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn bounded<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let body = serde_json::to_vec(value)?;
    ensure!(
        body.len() <= MIRROR_GUARD_MAX_BYTES,
        "mirror guard control exceeds its bound"
    );
    Ok(body)
}

fn domain_body(domain: &[u8], body: &[u8]) -> Vec<u8> {
    let mut signed = Vec::with_capacity(domain.len() + body.len());
    signed.extend_from_slice(domain);
    signed.extend_from_slice(body);
    signed
}

fn sign<T: Serialize>(
    key: &StorageWorkKey,
    domain: &[u8],
    value: &T,
) -> Result<SignedMirrorGuardControl> {
    let body = bounded(value)?;
    let signature = key.sign_body(&domain_body(domain, &body))?;
    Ok(SignedMirrorGuardControl { body, signature })
}

fn verify<T: Serialize + DeserializeOwned>(
    key: &StorageWorkKey,
    domain: &[u8],
    signature: &str,
    body: &[u8],
) -> Result<T> {
    ensure!(
        body.len() <= MIRROR_GUARD_MAX_BYTES,
        "mirror guard control exceeds its bound"
    );
    key.verify_body(signature, &domain_body(domain, body))?;
    let value: T = serde_json::from_slice(body)?;
    ensure!(
        bounded(&value)? == body,
        "mirror guard control is not canonical"
    );
    Ok(value)
}

#[cfg(test)]
mod tests;
