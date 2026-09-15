//! Dormant advanced-policy worker handoff.
//!
//! The handoff is only constructed from a protected owner-sealed recovery
//! checkpoint whose phase already records that effect authority escaped. It
//! contains canonical policy inputs and durable recovery commitments, but no
//! descriptor, socket, kernel authority, clock, or worker implementation.

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use super::replacement::{
    AdvancedNetworkRecoveryCompanionsV1, AdvancedNetworkRecoveryRecordV1,
    NetworkPolicyReplacementPhaseV1, NetworkPolicyReplacementStateV1,
};
use super::{AdvancedNetworkPolicyError, CompiledAdvancedNetworkPolicyV1};

const HANDOFF_MAGIC: &[u8; 8] = b"AOSANWH1";
const HANDOFF_VERSION: u16 = 1;
const HANDOFF_DOMAIN: &[u8] = b"aos.sandbox.network.advanced-worker-handoff.v1\0";
const MAXIMUM_HANDOFF_BYTES: usize = 24 * 1024 * 1024;

/// Selects the sole policy operation released by one durable reducer phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdvancedNetworkPolicyWorkerOperationV1 {
    /// Applies the exact fully compiled candidate policy.
    ApplyCandidate,
    /// Restores the exact retained predecessor after fail-closed fencing.
    RestorePredecessor,
}

/// Proves a complete advanced-policy recovery checkpoint was protected.
///
/// Construction remains crate-private so portable callers cannot turn an
/// in-memory reducer value into effect authority.
#[must_use]
struct DurablyCommittedAdvancedNetworkPolicyV1 {
    state: NetworkPolicyReplacementStateV1,
    index: AdvancedNetworkRecoveryRecordV1,
    companions: AdvancedNetworkRecoveryCompanionsV1,
    checkpoint_digest: ObjectDigest,
}

/// Carries exact canonical inputs for a future fixed advanced-policy worker.
///
/// This move-only value is intentionally not wired to a process, service, or
/// kernel mutator in the source-only tranche.
#[must_use]
pub struct AdvancedNetworkPolicyWorkerHandoffV1 {
    operation: AdvancedNetworkPolicyWorkerOperationV1,
    generation: u64,
    policy: CompiledAdvancedNetworkPolicyV1,
    policy_digest: ObjectDigest,
    protected_transaction_digest: ObjectDigest,
    checkpoint_digest: ObjectDigest,
    canonical_bytes: Vec<u8>,
}

impl DurablyCommittedAdvancedNetworkPolicyV1 {
    /// Seals one state after a protected owner atomically commits its checkpoint.
    ///
    /// The protected owner calls this only after exact commit and readback. The
    /// returned value remains non-authorizing until converted into a phase-bound
    /// worker handoff.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError`] when the complete state cannot be
    /// represented by the bounded canonical recovery format.
    fn from_protected_readback(
        state: NetworkPolicyReplacementStateV1,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        let index = AdvancedNetworkRecoveryRecordV1::encode(&state);
        let companions = AdvancedNetworkRecoveryCompanionsV1::seal(state.clone())?;
        let checkpoint_digest = checkpoint_digest(index.as_bytes(), companions.as_bytes());
        Ok(Self {
            state,
            index,
            companions,
            checkpoint_digest,
        })
    }

    /// Consumes durable state and emits the only policy permitted by its phase.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError::InvalidTransition`] unless the
    /// protected state is exactly `EffectReleased` or `RecoveryEffectReleased`.
    fn into_worker_handoff(
        self,
    ) -> Result<AdvancedNetworkPolicyWorkerHandoffV1, AdvancedNetworkPolicyError> {
        let (operation, policy) = match self.state.phase() {
            NetworkPolicyReplacementPhaseV1::EffectReleased => (
                AdvancedNetworkPolicyWorkerOperationV1::ApplyCandidate,
                self.state
                    .candidate()
                    .ok_or(AdvancedNetworkPolicyError::InvalidTransition)?,
            ),
            NetworkPolicyReplacementPhaseV1::RecoveryEffectReleased => (
                AdvancedNetworkPolicyWorkerOperationV1::RestorePredecessor,
                self.state.active(),
            ),
            _ => return Err(AdvancedNetworkPolicyError::InvalidTransition),
        };
        encode_handoff(
            operation,
            self.state.generation(),
            policy,
            self.state.protected_transaction().digest(),
            self.checkpoint_digest,
            &self.index,
            &self.companions,
        )
    }
}

impl AdvancedNetworkPolicyWorkerHandoffV1 {
    /// Returns the closed worker operation.
    #[must_use]
    pub const fn operation(&self) -> AdvancedNetworkPolicyWorkerOperationV1 {
        self.operation
    }

    /// Returns the exact durable reducer generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the exact compiled policy commitment.
    #[must_use]
    pub const fn policy_digest(&self) -> ObjectDigest {
        self.policy_digest
    }

    /// Returns the exact compiled policy selected by the durable phase.
    #[must_use]
    pub const fn policy(&self) -> &CompiledAdvancedNetworkPolicyV1 {
        &self.policy
    }

    /// Returns the combined protected registry/quota transaction commitment.
    #[must_use]
    pub const fn protected_transaction_digest(&self) -> ObjectDigest {
        self.protected_transaction_digest
    }

    /// Returns the durable checkpoint commitment preceding worker handoff.
    #[must_use]
    pub const fn checkpoint_digest(&self) -> ObjectDigest {
        self.checkpoint_digest
    }

    /// Borrows the exact bounded canonical worker payload.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

#[allow(clippy::too_many_arguments)]
fn encode_handoff(
    operation: AdvancedNetworkPolicyWorkerOperationV1,
    generation: u64,
    policy: &CompiledAdvancedNetworkPolicyV1,
    protected_transaction_digest: ObjectDigest,
    checkpoint_digest: ObjectDigest,
    index: &AdvancedNetworkRecoveryRecordV1,
    companions: &AdvancedNetworkRecoveryCompanionsV1,
) -> Result<AdvancedNetworkPolicyWorkerHandoffV1, AdvancedNetworkPolicyError> {
    let policy_bytes = policy.encode_recovery();
    let policy_length =
        u32::try_from(policy_bytes.len()).map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?;
    let companion_length = u32::try_from(companions.as_bytes().len())
        .map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?;
    let operation_code = match operation {
        AdvancedNetworkPolicyWorkerOperationV1::ApplyCandidate => 1,
        AdvancedNetworkPolicyWorkerOperationV1::RestorePredecessor => 2,
    };
    let total_length = 8usize
        .checked_add(2)
        .and_then(|value| value.checked_add(1 + 1 + 4 + 8))
        .and_then(|value| value.checked_add(32 * 4))
        .and_then(|value| value.checked_add(AdvancedNetworkRecoveryRecordV1::ENCODED_LEN))
        .and_then(|value| value.checked_add(4 + policy_bytes.len()))
        .and_then(|value| value.checked_add(4 + companions.as_bytes().len()))
        .and_then(|value| value.checked_add(32))
        .ok_or(AdvancedNetworkPolicyError::NonCanonical)?;
    if total_length > MAXIMUM_HANDOFF_BYTES {
        return Err(AdvancedNetworkPolicyError::NonCanonical);
    }
    let encoded_length =
        u32::try_from(total_length).map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?;
    let companion_digest = ObjectDigest::from_bytes(Sha256::digest(companions.as_bytes()).into());

    let mut bytes = Vec::with_capacity(total_length);
    bytes.extend_from_slice(HANDOFF_MAGIC);
    bytes.extend_from_slice(&HANDOFF_VERSION.to_be_bytes());
    bytes.push(operation_code);
    bytes.push(0);
    bytes.extend_from_slice(&encoded_length.to_be_bytes());
    bytes.extend_from_slice(&generation.to_be_bytes());
    bytes.extend_from_slice(policy.digest().as_bytes());
    bytes.extend_from_slice(protected_transaction_digest.as_bytes());
    bytes.extend_from_slice(checkpoint_digest.as_bytes());
    bytes.extend_from_slice(companion_digest.as_bytes());
    bytes.extend_from_slice(index.as_bytes());
    bytes.extend_from_slice(&policy_length.to_be_bytes());
    bytes.extend_from_slice(&policy_bytes);
    bytes.extend_from_slice(&companion_length.to_be_bytes());
    bytes.extend_from_slice(companions.as_bytes());
    let handoff_digest = handoff_digest(&bytes);
    bytes.extend_from_slice(handoff_digest.as_bytes());
    if bytes.len() != total_length {
        return Err(AdvancedNetworkPolicyError::NonCanonical);
    }

    Ok(AdvancedNetworkPolicyWorkerHandoffV1 {
        operation,
        generation,
        policy: policy.clone(),
        policy_digest: policy.digest(),
        protected_transaction_digest,
        checkpoint_digest,
        canonical_bytes: bytes,
    })
}

fn checkpoint_digest(index: &[u8], companions: &[u8]) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.network.advanced-checkpoint.v1\0");
    digest.update(index);
    digest.update(Sha256::digest(companions));
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn handoff_digest(bytes: &[u8]) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(HANDOFF_DOMAIN);
    digest.update(bytes);
    ObjectDigest::from_bytes(digest.finalize().into())
}
