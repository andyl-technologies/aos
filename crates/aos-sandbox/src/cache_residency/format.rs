//! Current authority gates for Cache idempotency, using the sole passive codecs.
//!
//! Records are fixed-width binary values with closed kind/state registries,
//! explicit reserved zero bytes, exact predecessors, and domain-separated
//! digests. Checkpoints and floors are separate formats so compaction cannot
//! reinterpret an event as authority. None of these formats contains a host
//! path, file descriptor, device number, inode number, or backend command.

use std::collections::BTreeMap;

pub use aos_sandbox_protocol::cache_state::durable_format::{
    CacheRecordKindV1, CacheDurableRecordV1, CacheCheckpointV1, CacheHistoryFloorV1,
    CacheMethodV1, CacheIdempotencyBindingV1, CacheFormatError,
    CacheIdempotencyCompactionFloorV1, encode_idempotency_floor,
    encode_record, decode_record, encode_checkpoint, decode_checkpoint,
    encode_floor, decode_floor, encode_idempotency, decode_idempotency,
    atomic_projection_digest,
};
pub(crate) use aos_sandbox_protocol::cache_state::durable_format::{
    RECORD_BYTES, CHECKPOINT_BYTES, IDEMPOTENCY_FLOOR_BYTES,
    decode_idempotency_floor_persisted,
};
use aos_sandbox_protocol::cache_state::durable_format::{
    idempotency_scope,
};

use aos_sandbox_core::{ObjectDigest, PrincipalId};
use sha2::{Digest as _, Sha256};

use super::domain::{
    CacheAuthorityOwner, CacheAuthorityPurposeV1, CacheAuthorityScopeV1, VerifiedCacheCapabilityV1,
};
use aos_sandbox_protocol::cache_state::PhysicalPartitionId;


/// Reports whether an accepted idempotent request was installed or replayed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheIdempotencyOutcomeV1 {
    /// The initial accepted result was installed.
    Accepted,
    /// The exact request already has a retained result.
    Replay(CacheIdempotencyBindingV1),
}

/// Binds a retained result replay to a fresh current disclosure decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizedIdempotencyReplayV1 {
    binding: CacheIdempotencyBindingV1,
    current_authority: ObjectDigest,
    digest: ObjectDigest,
}

/// Recovers an idempotency floor under exact current protected authority.
///
/// # Errors
///
/// Returns [`CacheFormatError`] for malformed bytes, stale scope, or expiry.
pub fn decode_idempotency_floor(
    owner: &CacheAuthorityOwner<'_, '_>,
    capability: &VerifiedCacheCapabilityV1,
    partition: PhysicalPartitionId,
    bytes: &[u8],
    now: u64,
) -> Result<CacheIdempotencyCompactionFloorV1, CacheFormatError> {
    let floor = decode_idempotency_floor_persisted(partition, bytes)?;
    let scope = idempotency_compaction_scope(
        partition,
        floor.scope(),
        floor.checkpoint(),
        floor.generation_data_v1(),
        capability.scope().valid_until(),
    )?;
    owner
        .validate_for_effect_at(capability, CacheAuthorityPurposeV1::Replay, scope, now)
        .map_err(|_| CacheFormatError::InvalidFloor)?;
    Ok(floor)
}

impl AuthorizedIdempotencyReplayV1 {
    /// Returns the retained result whose disclosure was freshly authorized.
    #[must_use]
    pub const fn binding(self) -> CacheIdempotencyBindingV1 {
        self.binding
    }

    /// Returns the canonical authorized-replay commitment.
    #[must_use]
    pub const fn digest(self) -> ObjectDigest {
        self.digest
    }
}

/// Materializes bounded principal/method/idempotency-key bindings.
#[derive(Clone, Debug)]
pub struct CacheIdempotencyIndexV1 {
    maximum_bindings: usize,
    bindings: BTreeMap<([u8; 16], u16, [u8; 16]), CacheIdempotencyBindingV1>,
    compacted_through: Option<CacheIdempotencyCompactionFloorV1>,
}

impl CacheIdempotencyIndexV1 {
    /// Replays all retained generations into one exact latest-result index.
    ///
    /// # Errors
    ///
    /// Returns [`CacheFormatError`] for invalid limits, malformed bindings,
    /// broken predecessor chains, or bound exhaustion.
    pub fn replay(
        maximum_bindings: usize,
        compacted_through: Option<CacheIdempotencyCompactionFloorV1>,
        bindings: impl IntoIterator<Item = CacheIdempotencyBindingV1>,
    ) -> Result<Self, CacheFormatError> {
        if maximum_bindings == 0 || maximum_bindings > 1_000_000 {
            return Err(CacheFormatError::InvalidIdempotency);
        }
        let mut index = Self {
            maximum_bindings,
            bindings: BTreeMap::new(),
            compacted_through,
        };
        for binding in bindings {
            binding.validate()?;
            let scope = idempotency_scope(&binding);
            if index
                .compacted_through
                .is_some_and(|floor| scope <= floor.scope())
            {
                return Err(CacheFormatError::InvalidIdempotency);
            }
            if let Some(previous) = index.bindings.get(&scope) {
                if binding.generation
                    != previous
                        .generation
                        .checked_add(1)
                        .ok_or(CacheFormatError::InvalidIdempotency)?
                    || binding.predecessor != previous.digest
                    || binding.request != previous.request
                    || binding.operation != previous.operation
                    || previous.terminal
                {
                    return Err(CacheFormatError::InvalidIdempotency);
                }
            } else if binding.generation != 1
                || binding.predecessor.as_bytes() != &[0; 32]
                || index.bindings.len() >= maximum_bindings
            {
                return Err(CacheFormatError::InvalidIdempotency);
            }
            index.bindings.insert(scope, binding);
        }
        Ok(index)
    }

    /// Accepts an initial result or returns the exact retained replay.
    ///
    /// Reusing a scoped key with a different normalized request always fails.
    /// Validation/CAS failures before this call do not consume a key.
    ///
    /// # Errors
    ///
    /// Returns [`CacheFormatError::IdempotencyConflict`] for request mismatch,
    /// or [`CacheFormatError::InvalidIdempotency`] for capacity/shape failure.
    pub fn accept(
        &mut self,
        binding: CacheIdempotencyBindingV1,
    ) -> Result<CacheIdempotencyOutcomeV1, CacheFormatError> {
        binding.validate()?;
        if binding.generation != 1 || binding.predecessor.as_bytes() != &[0; 32] {
            return Err(CacheFormatError::InvalidIdempotency);
        }
        let scope = idempotency_scope(&binding);
        if self
            .compacted_through
            .is_some_and(|floor| scope <= floor.scope())
        {
            return Err(CacheFormatError::IdempotencyConflict);
        }
        if let Some(existing) = self.bindings.get(&scope) {
            return if existing.request == binding.request {
                Ok(CacheIdempotencyOutcomeV1::Replay(*existing))
            } else {
                Err(CacheFormatError::IdempotencyConflict)
            };
        }
        if self.bindings.len() >= self.maximum_bindings {
            return Err(CacheFormatError::InvalidIdempotency);
        }
        self.bindings.insert(scope, binding);
        Ok(CacheIdempotencyOutcomeV1::Accepted)
    }

    /// Advances the nonterminal retained result for an exact scoped request.
    ///
    /// # Errors
    ///
    /// Returns [`CacheFormatError`] when the binding is absent, the request
    /// differs, or the retained result is already terminal.
    pub fn advance(
        &mut self,
        principal: PrincipalId,
        method: CacheMethodV1,
        key: [u8; 16],
        request: ObjectDigest,
        result: ObjectDigest,
        terminal: bool,
    ) -> Result<CacheIdempotencyBindingV1, CacheFormatError> {
        let scope = (*principal.as_bytes(), method as u16, key);
        let current = self
            .bindings
            .get(&scope)
            .ok_or(CacheFormatError::InvalidIdempotency)?;
        if current.request != request {
            return Err(CacheFormatError::IdempotencyConflict);
        }
        let successor = current.successor(result, terminal)?;
        self.bindings.insert(scope, successor);
        Ok(successor)
    }

    /// Resolves an exact replay only after a fresh current authority decision.
    ///
    /// The trusted caller supplies a nonzero digest of the current protected
    /// disclosure decision. This method never treats the historical decision
    /// that accepted the operation as present read authority.
    ///
    /// # Errors
    ///
    /// Returns [`CacheFormatError`] when the binding is absent, the normalized
    /// request differs, or current authority was not established.
    pub fn authorize_replay(
        &self,
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        partition: PhysicalPartitionId,
        principal: PrincipalId,
        method: CacheMethodV1,
        key: [u8; 16],
        request: ObjectDigest,
        valid_until: u64,
        now: u64,
    ) -> Result<AuthorizedIdempotencyReplayV1, CacheFormatError> {
        let binding = *self
            .bindings
            .get(&(*principal.as_bytes(), method as u16, key))
            .ok_or(CacheFormatError::InvalidIdempotency)?;
        if binding.request != request {
            return Err(CacheFormatError::IdempotencyConflict);
        }
        let scope = crate::cache_residency::domain::new_cache_authority_scope_v1(
            partition,
            replay_subject(&binding),
            Some(binding.operation),
            binding.request,
            partition.backing().root(),
            binding.generation,
            valid_until,
        )
        .map_err(|_| CacheFormatError::InvalidIdempotency)?;
        owner
            .validate_for_effect_at(capability, CacheAuthorityPurposeV1::Replay, scope, now)
            .map_err(|_| CacheFormatError::InvalidIdempotency)?;
        let current_authority = capability.record_digest();
        let mut hasher = Sha256::new();
        hasher.update(b"aos.sandbox.cache.authorized-idempotency-replay.v1\0");
        hasher.update(binding.digest.as_bytes());
        hasher.update(current_authority.as_bytes());
        let digest = ObjectDigest::from_bytes(hasher.finalize().into());
        Ok(AuthorizedIdempotencyReplayV1 {
            binding,
            current_authority,
            digest,
        })
    }

    /// Compacts a terminal key prefix while retaining a non-reuse floor.
    ///
    /// # Errors
    ///
    /// Returns [`CacheFormatError`] for nonterminal records, a stale floor, or
    /// protected replay capability mismatch.
    pub fn compact_terminal_through(
        &mut self,
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        partition: PhysicalPartitionId,
        principal: PrincipalId,
        method: CacheMethodV1,
        key: [u8; 16],
        checkpoint: ObjectDigest,
        generation: u64,
        valid_until: u64,
        now: u64,
    ) -> Result<CacheIdempotencyCompactionFloorV1, CacheFormatError> {
        let floor_scope = (*principal.as_bytes(), method as u16, key);
        if principal.as_bytes() == &[0; 16]
            || key == [0; 16]
            || checkpoint.as_bytes() == &[0; 32]
            || self
                .compacted_through
                .is_some_and(|floor| floor_scope <= floor.scope())
            || self
                .bindings
                .range(..=floor_scope)
                .any(|(_, binding)| !binding.terminal)
        {
            return Err(CacheFormatError::InvalidIdempotency);
        }
        let authority_scope = idempotency_compaction_scope(
            partition,
            floor_scope,
            checkpoint,
            generation,
            valid_until,
        )?;
        owner
            .validate_for_effect_at(
                capability,
                CacheAuthorityPurposeV1::Replay,
                authority_scope,
                now,
            )
            .map_err(|_| CacheFormatError::InvalidIdempotency)?;
        self.bindings.retain(|scope, _| *scope > floor_scope);
        let floor = CacheIdempotencyCompactionFloorV1::from_data_v1(
            floor_scope,
            partition.digest(),
            checkpoint,
            generation,
        );
        self.compacted_through = Some(floor);
        Ok(floor)
    }
}

fn replay_subject(binding: &CacheIdempotencyBindingV1) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.cache.idempotency-replay-subject.v1\0");
    hasher.update(binding.digest.as_bytes());
    hasher.update(binding.result.as_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn idempotency_compaction_scope(
    partition: PhysicalPartitionId,
    floor_scope: ([u8; 16], u16, [u8; 16]),
    checkpoint: ObjectDigest,
    generation: u64,
    valid_until: u64,
) -> Result<CacheAuthorityScopeV1, CacheFormatError> {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.cache.idempotency-compaction-subject.v1\0");
    hasher.update(floor_scope.0);
    hasher.update(floor_scope.1.to_be_bytes());
    hasher.update(floor_scope.2);
    hasher.update(checkpoint.as_bytes());
    let subject = ObjectDigest::from_bytes(hasher.finalize().into());
    crate::cache_residency::domain::new_cache_authority_scope_v1(
        partition,
        subject,
        None,
        checkpoint,
        partition.backing().root(),
        generation,
        valid_until,
    )
    .map_err(|_| CacheFormatError::InvalidFloor)
}
