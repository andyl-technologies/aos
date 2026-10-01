//! Bounded independent guard readback for an ordered publication phase batch.
//!
//! One canonical outer challenge binds all originals and expected progress.
//! Physical observations authenticate that challenge and their selected index;
//! the final outer reply yields opaque proofs without per-item re-signing.
//!
//! ```text
//! lookup = common_issuer_and_deadline + ordered(original, expected_progress)
//! observation = SHA256(lookup) + selected_index + actual_retained_result
//! reply = SHA256(lookup) + ordered(positive_progress | explicit_refusal)
//! ```

use std::collections::BTreeSet;

use super::*;

/// Identifies the independent production batch guard lookup.
pub const MIRROR_GUARD_BATCH_LOOKUP_PATH: &str = "/_internal/storage/mirror-final-guard-batch";
/// Identifies the reserved controlled batch guard lookup.
pub const MIRROR_CANDIDATE_GUARD_BATCH_LOOKUP_PATH: &str = "/__hub/mirror-candidate-guard-batch";
/// Bounds the ordered number of independently checked publications.
pub const MIRROR_GUARD_BATCH_MAX_ITEMS: usize = 64;

const REQUEST_DOMAIN: &[u8] = b"aos.hub.mirror-final-guard-batch-request.v1\0";
const OBSERVATION_DOMAIN: &[u8] = b"aos.hub.mirror-final-guard-batch-observation.v1\0";
const REPLY_DOMAIN: &[u8] = b"aos.hub.mirror-final-guard-batch-reply.v1\0";

/// Selects one complete original and its expected positive destination progress.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorGuardBatchItem {
    /// Complete retained original, including its distinct copy operation.
    pub original: MirrorOriginal,
    /// Complete positive progress expected by Native.
    pub expected: MirrorProgress,
}

/// Challenges an ordered batch under one fresh independent guard horizon.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorGuardBatchLookup {
    /// Closed wire version.
    pub version: u32,
    /// Exact configured Native and Worker deployment.
    pub deployment_id: String,
    /// Expected production or reserved controlled execution.
    pub execution: MirrorGuardExecution,
    /// Independently selected actual compiled source and script.
    pub issuer: MirrorGuardIssuer,
    /// Exact independently selected bounded UTC uncertainty.
    pub clock_uncertainty_seconds: u64,
    /// Ordered originals with no repeated job or destination key.
    pub items: Vec<MirrorGuardBatchItem>,
    /// Fresh random 32-byte challenge in lowercase hexadecimal.
    pub request_nonce: String,
    /// Original challenge issue time in UTC seconds.
    pub issued_at: u64,
    /// Original exclusive deadline, at most 30 seconds after issue.
    pub expires_at: u64,
}

impl MirrorGuardBatchLookup {
    /// Checks all exact originals, expected positives, bounds and fresh pins.
    ///
    /// # Errors
    /// Returns an error for invalid, repeated, excessive or stale publications.
    pub fn validate(&self, deployment: &str, latest_now: u64) -> Result<()> {
        ensure!(
            !self.items.is_empty() && self.items.len() <= MIRROR_GUARD_BATCH_MAX_ITEMS,
            "mirror guard batch item count invalid"
        );
        let mut jobs = BTreeSet::new();
        let mut destinations = BTreeSet::new();
        for (index, item) in self.items.iter().enumerate() {
            self.item_lookup(index)?.validate(deployment, latest_now)?;
            ensure!(
                jobs.insert(&item.original.job_id)
                    && destinations.insert(crate::keymap::r2_key(
                        &item.original.placement_prefix,
                        &item.original.path,
                    )),
                "mirror guard batch repeats a job or destination"
            );
        }
        bounded(self)?;
        Ok(())
    }

    /// Projects one selected original without minting a new challenge or authority.
    ///
    /// Physical callers must authenticate the complete outer request first.
    ///
    /// # Errors
    /// Returns an error when the selected index is absent.
    pub fn item_lookup(&self, index: usize) -> Result<MirrorGuardLookup> {
        let item = self
            .items
            .get(index)
            .ok_or_else(|| anyhow::anyhow!("mirror guard batch selected index absent"))?;
        Ok(MirrorGuardLookup {
            version: self.version,
            deployment_id: self.deployment_id.clone(),
            execution: self.execution,
            issuer: self.issuer.clone(),
            clock_uncertainty_seconds: self.clock_uncertainty_seconds,
            original: item.original.clone(),
            expected: item.expected.clone(),
            request_nonce: self.request_nonce.clone(),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
        })
    }
}

/// Refuses one selected original without implying settlement or retry permission.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MirrorGuardBatchRefusal {
    /// The exact held positive original could not be independently established.
    Unavailable,
}

/// Returns an exact positive or explicit refusal at its original batch position.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MirrorGuardBatchResult {
    /// Proves the complete retained positive progress.
    Positive {
        /// SHA-256 of the complete independently retained original.
        original_digest: String,
        /// Full retained positive destination and provider incarnation.
        progress: MirrorProgress,
        /// Latest bounded clock of this actual physical observation.
        observed_at: u64,
    },
    /// Retains the failed original correlation without granting permission.
    Refused {
        /// SHA-256 of the exact selected challenged original.
        original_digest: String,
        /// Closed value-free refusal.
        refusal: MirrorGuardBatchRefusal,
    },
}

/// Authenticates one actual physical read against the full outer challenge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorGuardBatchObservation {
    /// Closed wire version.
    pub version: u32,
    /// SHA-256 of the complete canonical batch lookup.
    pub request_digest: String,
    /// Exact fresh batch nonce.
    pub request_nonce: String,
    /// Actual compiled guard source and deployed script.
    pub issuer: MirrorGuardIssuer,
    /// Exact selected position in the authenticated outer request.
    pub item_index: usize,
    /// Actual held progress or explicit refusal for that original.
    pub result: MirrorGuardBatchResult,
    /// Latest bounded clock after the physical durable reads.
    pub observed_at: u64,
}

/// Returns one ordered independently authenticated publication phase result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorGuardBatchReply {
    /// Closed wire version.
    pub version: u32,
    /// SHA-256 of the complete canonical batch lookup.
    pub request_digest: String,
    /// Exact fresh batch nonce.
    pub request_nonce: String,
    /// Actual compiled guard source and deployed script.
    pub issuer: MirrorGuardIssuer,
    /// Ordered results, including every refusal without dropping positions.
    pub results: Vec<MirrorGuardBatchResult>,
    /// Latest bounded clock after all selected physical lookups.
    pub observed_at: u64,
}

/// Preserves a verified positive proof or explicit refused original.
#[derive(Clone, Debug)]
pub enum VerifiedMirrorGuardBatchItem {
    /// Carries the existing opaque proof accepted by checked final SQL.
    Positive(VerifiedMirrorGuardProof),
    /// Carries no publication or provider permission.
    Refused {
        /// Exact full challenged original digest.
        original_digest: String,
        /// Closed refusal under the authenticated outer response.
        refusal: MirrorGuardBatchRefusal,
    },
}

/// Signs a canonical bounded fresh batch challenge.
///
/// # Errors
/// Returns an error for invalid originals, duplicates, bounds or encoding.
pub fn sign_mirror_guard_batch_lookup(
    key: &StorageWorkKey,
    request: &MirrorGuardBatchLookup,
) -> Result<SignedMirrorGuardControl> {
    request.validate(&request.deployment_id, request.issued_at)?;
    sign(key, REQUEST_DOMAIN, request)
}

/// Authenticates the whole canonical outer request before selecting physical work.
///
/// # Errors
/// Returns an error for foreign purpose, body, deployment or stale challenge.
pub fn verify_mirror_guard_batch_lookup(
    key: &StorageWorkKey,
    signature: &str,
    body: &[u8],
    deployment: &str,
    latest_now: u64,
) -> Result<MirrorGuardBatchLookup> {
    let request: MirrorGuardBatchLookup = verify(key, REQUEST_DOMAIN, signature, body)?;
    request.validate(deployment, latest_now)?;
    Ok(request)
}

/// Signs one actual read-only physical observation of a selected original.
///
/// # Errors
/// Returns an error for changed challenge, index, original, progress or time.
pub fn sign_mirror_guard_batch_observation(
    key: &StorageWorkKey,
    observation: &MirrorGuardBatchObservation,
    request: &MirrorGuardBatchLookup,
) -> Result<SignedMirrorGuardControl> {
    validate_observation(observation, request, observation.observed_at)?;
    sign(key, OBSERVATION_DOMAIN, observation)
}

/// Authenticates the selected physical response against the complete outer request.
///
/// # Errors
/// Returns an error for foreign MAC, changed index, original, progress or time.
pub fn verify_mirror_guard_batch_observation(
    key: &StorageWorkKey,
    signature: &str,
    body: &[u8],
    request: &MirrorGuardBatchLookup,
    selected_index: usize,
    latest_now: u64,
) -> Result<MirrorGuardBatchObservation> {
    let observation: MirrorGuardBatchObservation =
        verify(key, OBSERVATION_DOMAIN, signature, body)?;
    ensure!(
        observation.item_index == selected_index,
        "mirror guard physical response changed selected position"
    );
    validate_observation(&observation, request, latest_now)?;
    Ok(observation)
}

/// Signs the ordered actual batch readback under its distinct reply purpose.
///
/// # Errors
/// Returns an error for changed correlation, missing positions or stale time.
pub fn sign_mirror_guard_batch_reply(
    key: &StorageWorkKey,
    reply: &MirrorGuardBatchReply,
    request: &MirrorGuardBatchLookup,
) -> Result<SignedMirrorGuardControl> {
    validate_batch_reply(reply, request, reply.observed_at)?;
    sign(key, REPLY_DOMAIN, reply)
}

/// Verifies the outer guard MAC and yields ordered opaque proofs or refusals.
///
/// No per-item signature is manufactured. Each opaque proof is normalized only
/// after the complete outer MAC, request digest and every position are verified.
///
/// # Errors
/// Returns an error for any altered, omitted, reordered or stale batch position.
pub fn verify_mirror_guard_batch_reply(
    key: &StorageWorkKey,
    signature: &str,
    body: &[u8],
    request: &MirrorGuardBatchLookup,
    latest_now: u64,
) -> Result<Vec<VerifiedMirrorGuardBatchItem>> {
    let reply: MirrorGuardBatchReply = verify(key, REPLY_DOMAIN, signature, body)?;
    validate_batch_reply(&reply, request, latest_now)?;
    reply
        .results
        .into_iter()
        .enumerate()
        .map(|(index, result)| match result {
            MirrorGuardBatchResult::Positive {
                original_digest,
                progress,
                observed_at,
            } => {
                let item = request.item_lookup(index)?;
                let retained = MirrorGuardReply {
                    version: 1,
                    request_digest: digest(&item)?,
                    request_nonce: request.request_nonce.clone(),
                    original_digest,
                    issuer: reply.issuer.clone(),
                    progress,
                    observed_at,
                };
                validate_reply(&retained, &item, latest_now)?;
                Ok(VerifiedMirrorGuardBatchItem::Positive(
                    VerifiedMirrorGuardProof {
                        request: item,
                        reply: retained,
                    },
                ))
            }
            MirrorGuardBatchResult::Refused {
                original_digest,
                refusal,
            } => Ok(VerifiedMirrorGuardBatchItem::Refused {
                original_digest,
                refusal,
            }),
        })
        .collect()
}

fn validate_common(
    version: u32,
    request_digest: &str,
    request_nonce: &str,
    issuer: &MirrorGuardIssuer,
    observed_at: u64,
    request: &MirrorGuardBatchLookup,
    latest_now: u64,
) -> Result<()> {
    request.validate(&request.deployment_id, latest_now)?;
    ensure!(
        version == 1
            && request_digest == digest(request)?
            && request_nonce == request.request_nonce
            && issuer == &request.issuer
            && request.issued_at <= observed_at
            && observed_at <= latest_now
            && observed_at < request.expires_at,
        "mirror guard batch response changed challenge, issuer or time"
    );
    Ok(())
}

fn validate_result(
    result: &MirrorGuardBatchResult,
    item: &MirrorGuardBatchItem,
    issued_at: u64,
    latest_observation: u64,
) -> Result<()> {
    let original = match result {
        MirrorGuardBatchResult::Positive {
            original_digest,
            progress,
            observed_at,
        } => {
            ensure!(
                progress == &item.expected
                    && issued_at <= *observed_at
                    && *observed_at <= latest_observation,
                "mirror guard batch changed positive progress"
            );
            progress.commit_digest(&item.original)?;
            original_digest
        }
        MirrorGuardBatchResult::Refused {
            original_digest, ..
        } => original_digest,
    };
    ensure!(
        original == &digest(&item.original)?,
        "mirror guard batch changed original position"
    );
    Ok(())
}

fn validate_observation(
    observation: &MirrorGuardBatchObservation,
    request: &MirrorGuardBatchLookup,
    latest_now: u64,
) -> Result<()> {
    validate_common(
        observation.version,
        &observation.request_digest,
        &observation.request_nonce,
        &observation.issuer,
        observation.observed_at,
        request,
        latest_now,
    )?;
    let item = request
        .items
        .get(observation.item_index)
        .ok_or_else(|| anyhow::anyhow!("mirror guard observation index absent"))?;
    validate_result(
        &observation.result,
        item,
        request.issued_at,
        observation.observed_at,
    )?;
    bounded(observation)?;
    Ok(())
}

/// Checks retained ordered results against their original batch observation.
///
/// This checks exact original, issuer, nonce, progress and per-item times under
/// the recorded aggregate observation horizon. It does not authenticate the
/// reply, assert present freshness or create opaque proofs. Observers must
/// independently correlate exact body digests and the original challenge with
/// an authenticated handler's accepted response.
///
/// # Errors
/// Returns an error for changed or missing items, invalid observation ordering,
/// malformed refusals, changed challenge fields or exceeded canonical bounds.
pub fn validate_mirror_guard_batch_reply_observation(
    request: &MirrorGuardBatchLookup,
    reply: &MirrorGuardBatchReply,
) -> Result<()> {
    validate_batch_reply(reply, request, reply.observed_at)
}

fn validate_batch_reply(
    reply: &MirrorGuardBatchReply,
    request: &MirrorGuardBatchLookup,
    latest_now: u64,
) -> Result<()> {
    validate_common(
        reply.version,
        &reply.request_digest,
        &reply.request_nonce,
        &reply.issuer,
        reply.observed_at,
        request,
        latest_now,
    )?;
    ensure!(
        reply.results.len() == request.items.len(),
        "mirror guard batch omitted or added result positions"
    );
    for (result, item) in reply.results.iter().zip(&request.items) {
        validate_result(result, item, request.issued_at, reply.observed_at)?;
    }
    bounded(reply)?;
    Ok(())
}

#[cfg(test)]
mod tests;
