//! Closed independent reviews and retained receipts for journal format 3.
//!
//! Recovery changes only one unresolved clock session. It neither resets issuer
//! history nor establishes provider settlement. The pinned policy qualifies the
//! exact durable file, filesystem locking and external clock; copying that file
//! to another inode or host is outside this protocol.
//!
//! ```json
//! {"version":1,"plan_digest":"...","signature":"..."}
//! ```
//! This abbreviated review omits its mandatory complete canonical plan.

use anyhow::{ensure, Context as _, Result};
use ed25519_dalek::Signer as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use aos_hub_core::storage_authority::lease::{control::IssuerHead, LeaseInteger};

#[cfg(test)]
pub(crate) mod tests;

/// Maximum canonical plan, review or receipt size.
pub const MAX_CLOCK_RECOVERY_BYTES: usize = 32 * 1024;

/// Immutable reviewer and deployment qualification selected at fresh installation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClockRecoveryPolicy {
    /// Closed policy version, currently one.
    pub version: u8,
    /// Independent reviewer identity, distinct from the issuer signing identity.
    pub reviewer_key_id: String,
    /// Lowercase hex Ed25519 verification key; never supplied by a review.
    pub reviewer_public_key: String,
    /// Independent commitment to this retained filesystem and locking boundary.
    pub resource_qualification_digest: String,
    /// Independent commitment to the clock's qualified absolute uncertainty.
    pub clock_qualification_digest: String,
    /// Maximum lifetime of a review, between one and thirty seconds.
    pub maximum_review_seconds: LeaseInteger,
    /// Exact qualified uncertainty of the actual UTC clock.
    pub clock_uncertainty: LeaseInteger,
    /// Exact reviewed observation and commit latency, excluding rounding.
    pub clock_commit_latency: LeaseInteger,
}

impl ClockRecoveryPolicy {
    /// Validates closed structure without independently qualifying a deployment.
    ///
    /// # Errors
    /// Returns an error for unsupported versions, keys, commitments or time bounds.
    pub fn validate(&self) -> Result<()> {
        ensure!(self.version == 1, "unsupported clock recovery policy");
        ensure!(
            !self.reviewer_key_id.is_empty() && self.reviewer_key_id.len() <= 255,
            "invalid recovery reviewer identity"
        );
        for value in [
            &self.reviewer_public_key,
            &self.resource_qualification_digest,
            &self.clock_qualification_digest,
        ] {
            hex_identity(value)?;
        }
        self.verifier()?;
        ensure!(
            (1..=30).contains(&self.maximum_review_seconds.get())
                && self.clock_commit_latency.get() > 0,
            "invalid recovery time bounds"
        );
        self.total_uncertainty()?;
        Ok(())
    }

    pub(super) fn total_uncertainty(&self) -> Result<i64> {
        self.clock_uncertainty
            .get()
            .checked_add(self.clock_commit_latency.get())
            .and_then(|value| value.checked_add(1))
            .context("recovery clock interval overflow")
    }

    fn verifier(&self) -> Result<ed25519_dalek::VerifyingKey> {
        let bytes: [u8; 32] = hex::decode(&self.reviewer_public_key)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid reviewer verification key"))?;
        Ok(ed25519_dalek::VerifyingKey::from_bytes(&bytes)?)
    }
}

/// Exact pinned filesystem coordinates, excluding automatic cross-host recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClockRecoveryFile {
    /// Actual journal device number encoded without JSON integer loss.
    pub device: String,
    /// Actual journal inode number.
    pub inode: String,
    /// Actual owner-private parent device number.
    pub parent_device: String,
    /// Actual owner-private parent inode number.
    pub parent_inode: String,
}

/// Exact retained state nominated for one independently reviewed successor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClockRecoveryPlan {
    /// Closed plan version, currently one.
    pub version: u8,
    /// Actual durable file coordinates selected during locked inspection.
    pub file: ClockRecoveryFile,
    /// Full immutable installation and current issuance/publication history.
    pub expected_head: IssuerHead,
    /// Exact unresolved old session; never replaced with NULL.
    pub expected_session: String,
    /// Actual retained observation floor.
    pub expected_floor: LeaseInteger,
    /// Largest conservative upper bound retained by the old observer.
    pub expected_ceiling: LeaseInteger,
    /// Commitment of the immutable installed recovery policy.
    pub policy_digest: String,
    /// One exact nominated successor session, different from the old session.
    pub successor_session: String,
    /// Fresh independent review nonce.
    pub nonce: String,
    /// Actual inspection UTC, without advancing the old clock session.
    pub issued_at: LeaseInteger,
    /// Strict deadline for initial resolution and uncertain-ACK readback.
    pub expires_at: LeaseInteger,
}

impl ClockRecoveryPlan {
    pub(super) fn validate(&self, policy: &ClockRecoveryPolicy) -> Result<()> {
        policy.validate()?;
        self.expected_head.validate()?;
        ensure!(self.version == 1, "unsupported clock recovery plan");
        for value in [
            &self.expected_session,
            &self.successor_session,
            &self.nonce,
            &self.policy_digest,
        ] {
            hex_identity(value)?;
        }
        for value in [
            &self.file.device,
            &self.file.inode,
            &self.file.parent_device,
            &self.file.parent_inode,
        ] {
            ensure!(
                value.parse::<u64>()?.to_string() == *value,
                "noncanonical file identity"
            );
        }
        ensure!(
            self.expected_session != self.successor_session
                && self.policy_digest == canonical_digest(policy)?
                && self.expected_ceiling >= self.expected_floor
                && self.expected_floor >= self.expected_head.journal.clock_floor
                && self.expires_at > self.issued_at
                && self.expires_at.get() - self.issued_at.get()
                    <= policy.maximum_review_seconds.get(),
            "clock recovery plan differs from installed policy or retained bounds"
        );
        Ok(())
    }
}

/// Independently authenticated complete recovery original.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClockRecoveryReview {
    /// Closed review version, currently one.
    pub version: u8,
    /// Exact complete reviewed plan; no issuer key or provider permission.
    pub plan: ClockRecoveryPlan,
    /// Canonical full-plan commitment.
    pub plan_digest: String,
    /// Pinned independent reviewer identity.
    pub reviewer_key_id: String,
    /// Lowercase hex signature under the distinct recovery-review domain.
    pub signature: String,
}

impl ClockRecoveryReview {
    /// Signs an exact plan with an independently held reviewer seed.
    ///
    /// # Errors
    /// Returns an error for invalid plans or a seed not matching the pinned policy.
    pub fn sign(
        plan: ClockRecoveryPlan,
        policy: &ClockRecoveryPolicy,
        seed: &[u8; 32],
    ) -> Result<Self> {
        plan.validate(policy)?;
        let signer = ed25519_dalek::SigningKey::from_bytes(seed);
        ensure!(
            signer.verifying_key() == policy.verifier()?,
            "recovery signing seed differs from installed reviewer"
        );
        let plan_digest = canonical_digest(&plan)?;
        let signature = signer.sign(&review_message(&plan)?);
        Ok(Self {
            version: 1,
            plan,
            plan_digest,
            reviewer_key_id: policy.reviewer_key_id.clone(),
            signature: hex::encode(signature.to_bytes()),
        })
    }

    pub(super) fn validate(&self, policy: &ClockRecoveryPolicy) -> Result<()> {
        self.plan.validate(policy)?;
        ensure!(
            self.version == 1
                && self.plan_digest == canonical_digest(&self.plan)?
                && self.reviewer_key_id == policy.reviewer_key_id,
            "recovery review commitment or reviewer differs"
        );
        let signature = ed25519_dalek::Signature::from_slice(&hex::decode(&self.signature)?)?;
        ensure!(
            hex::encode(signature.to_bytes()) == self.signature,
            "noncanonical review signature"
        );
        policy
            .verifier()?
            .verify_strict(&review_message(&self.plan)?, &signature)?;
        Ok(())
    }
}

/// Append-only positive resolution, permitting one explicitly requested successor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClockRecoveryReceipt {
    /// Closed receipt version, currently one.
    pub version: u8,
    /// Exact independently signed original retained before acknowledgment.
    pub review: ClockRecoveryReview,
    /// Actual precommit clock sample, not a manufactured future observation.
    pub observed_at: LeaseInteger,
    /// Complete qualified uncertainty including commit latency and rounding.
    pub uncertainty: LeaseInteger,
}

impl ClockRecoveryReceipt {
    pub(super) fn validate(&self, policy: &ClockRecoveryPolicy) -> Result<()> {
        self.review.validate(policy)?;
        ensure!(
            self.version == 1 && self.uncertainty.get() == policy.total_uncertainty()?,
            "invalid recovery receipt interval"
        );
        validate_observation(&self.review.plan, policy, self.observed_at.get())
    }
}

pub(super) fn validate_observation(
    plan: &ClockRecoveryPlan,
    policy: &ClockRecoveryPolicy,
    observed_at: i64,
) -> Result<()> {
    let uncertainty = policy.total_uncertainty()?;
    let earliest = observed_at
        .checked_sub(uncertainty)
        .context("clock recovery lower bound overflow")?;
    let latest = observed_at
        .checked_add(uncertainty)
        .context("clock recovery upper bound overflow")?;
    ensure!(
        observed_at >= plan.issued_at.get()
            && earliest
                >= plan
                    .expected_ceiling
                    .get()
                    .max(plan.expected_head.journal.largest_issued_expiry.get())
            && latest < plan.expires_at.get(),
        "clock recovery observation is stale, uncertain or before retained admission bounds"
    );
    Ok(())
}

fn review_message(plan: &ClockRecoveryPlan) -> Result<Vec<u8>> {
    let mut message = b"aos.hub.authority-clock-review.v1\0".to_vec();
    message.extend(encode(plan)?);
    Ok(message)
}

pub(super) fn hex_identity(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "invalid clock recovery identity"
    );
    Ok(())
}

pub(super) fn canonical_digest(value: &impl Serialize) -> Result<String> {
    Ok(hex::encode(Sha256::digest(encode(value)?)))
}

/// Encodes a bounded canonical recovery document for private operator transfer.
///
/// # Errors
/// Returns an error for serialization failure or a document exceeding the bound.
pub fn encode(value: &impl Serialize) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(
        bytes.len() <= MAX_CLOCK_RECOVERY_BYTES,
        "clock recovery document exceeds bound"
    );
    Ok(bytes)
}

/// Decodes exact closed canonical recovery JSON without executing an operation.
///
/// # Errors
/// Returns an error for oversized, unknown, duplicate or noncanonical fields.
pub fn decode<T: serde::de::DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T> {
    ensure!(
        bytes.len() <= MAX_CLOCK_RECOVERY_BYTES,
        "clock recovery document exceeds bound"
    );
    let value: T = serde_json::from_slice(bytes)?;
    ensure!(
        encode(&value)? == bytes,
        "noncanonical clock recovery document"
    );
    Ok(value)
}

impl super::AuthorityJournal {
    /// Verifies the immutable recovery policy and exact journal format.
    ///
    /// # Errors
    /// Returns an error for policy mismatch, unsupported format or corrupt state.
    pub fn verify_recovery_policy(&self, policy: Option<&ClockRecoveryPolicy>) -> Result<()> {
        super::sqlite::recovery::verify_policy(self, policy)
    }

    /// Inspects an inactive format 3 journal and nominates one fresh successor.
    ///
    /// Inspection changes no SQL state. An independent pinned reviewer must sign
    /// the complete plan before resolution; inspection alone authorizes nothing.
    ///
    /// # Errors
    /// Returns an error for active owners, format 2, missing sessions, changed
    /// files, invalid policy, unqualified structure or clock read failure.
    pub fn inspect_clock_session(&self, policy: &ClockRecoveryPolicy) -> Result<ClockRecoveryPlan> {
        let _lock = self.file.lock_exclusive()?;
        super::sqlite::recovery::inspect(self, policy, sample()?)
    }

    /// Commits or exactly reads back one independently reviewed clock resolution.
    ///
    /// Acknowledgment follows a qualified actual postcommit sample under the
    /// reviewed latency bound. Any error leaves the old session unresolved;
    /// possibly committed originals are never undone or automatically consumed.
    /// An exact retry requires a fresh qualified sample before the review expires.
    ///
    /// # Errors
    /// Returns an error for active owners, stale reviews, changed originals,
    /// clock rollback/uncertainty/latency, policy mismatch or indeterminate I/O.
    pub fn resolve_clock_session(
        &self,
        policy: &ClockRecoveryPolicy,
        review: &ClockRecoveryReview,
    ) -> Result<ClockRecoveryReceipt> {
        let _lock = self.file.lock_exclusive()?;
        let monotonic = std::time::Instant::now();
        let observed_at = sample()?;
        let receipt = super::sqlite::recovery::resolve(self, policy, review, observed_at)?;
        let final_sample = sample()?;
        ensure!(
            final_sample >= observed_at
                && monotonic.elapsed() <= std::time::Duration::from_secs(u64::try_from(policy.clock_commit_latency.get())?)
                && final_sample <= observed_at.checked_add(policy.clock_commit_latency.get())
                    .and_then(|value| value.checked_add(1)).context("recovery postcommit interval overflow")?,
            "clock recovery postcommit observation exceeded qualification; outcome may be indeterminate"
        );
        validate_observation(&review.plan, policy, final_sample)?;
        Ok(receipt)
    }
}

fn sample() -> Result<i64> {
    Ok(i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
    )?)
}
