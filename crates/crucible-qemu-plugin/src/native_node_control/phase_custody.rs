//! Original native phase projection and immutable timer-birth evidence custody.
//!
//! An authentic native getter/stop owns sampling. The socket reader can recover
//! only cached slices; it never queries a native list, chooses an instruction
//! position or reclassifies an unknown arm. Phase registration compares the
//! original early policy and does not authorize callbacks or all-owner readiness.

use std::collections::BTreeMap;
use std::sync::{
    Mutex, TryLockError,
    atomic::{AtomicBool, Ordering},
};

use crucible_node_contract::U64;
use crucible_protocol::node_control::{
    NATIVE_PHASE_TIMER_OBJECT_MAX_BYTES, NativeCommandError, NativePhasePreparation,
    NativePhaseTimerChunk, NativePhaseTimerQuery,
};

use super::abi::NativeTimerList;
use super::phase_abi::{
    self, NativePhasePolicyAbi, NativeTimerBirthAbi, NativeTimerBirthInventoryAbi,
    QueryTimerBirths, RegisterPhaseProjection,
};

const MAXIMUM_ORIGINAL_OBSERVATIONS: usize = 16;

struct OriginalBirths {
    original_digest: [u8; 32],
    expected_time: U64,
    hold_generation: u64,
    bytes: Vec<u8>,
}

#[cfg(test)]
#[path = "phase_custody_tests.rs"]
mod tests;

/// Retains genuine native projection registration and complete original evidence.
pub(crate) struct PhaseProjectionCustody {
    preparation: NativePhasePreparation,
    policy: NativePhasePolicyAbi,
    query: QueryTimerBirths,
    registered: AtomicBool,
    originals: Mutex<BTreeMap<u64, OriginalBirths>>,
}

impl PhaseProjectionCustody {
    /// Pins the complete inactive Realize companion before source registration.
    ///
    /// # Errors
    /// Refuses malformed preparation or a policy outside the closed source mapping.
    pub(crate) fn new(
        preparation: NativePhasePreparation,
        query: QueryTimerBirths,
    ) -> Result<Self, NativeCommandError> {
        let policy = NativePhasePolicyAbi::from_policy(&preparation.policy()?)?;
        Ok(Self {
            preparation,
            policy,
            query,
            registered: AtomicBool::new(false),
            originals: Mutex::new(BTreeMap::new()),
        })
    }

    /// Registers the exact original early source pin after native controller install.
    ///
    /// # Errors
    /// Refuses a second registration or any native source mismatch. No capability
    /// is published from portable field equality without actual native success.
    pub(crate) fn register(
        &self,
        register: RegisterPhaseProjection,
    ) -> Result<(), NativeCommandError> {
        if self.registered.load(Ordering::Acquire) || register(&self.policy) != 0 {
            return Err(NativeCommandError::Conflict);
        }
        self.registered.store(true, Ordering::Release);
        Ok(())
    }

    /// Returns a commitment only after actual native policy registration succeeds.
    pub(crate) fn registered_commitment(&self) -> Option<[u8; 32]> {
        self.registered
            .load(Ordering::Acquire)
            .then_some(self.policy.phase_preparation_commitment)
    }

    /// Retains the first genuine source callback observation for an original request.
    ///
    /// The caller supplies expectation fields from its authentic stopped journal,
    /// not caller-provided stop JSON. A cached retry validates the original digest
    /// and reads no live source. Native EAGAIN/unsupported leaves evidence absent.
    ///
    /// # Errors
    /// Refuses malformed source facts, foreign original identity, incomplete
    /// registration, concurrent custody, or finite retention/allocation exhaustion.
    pub(crate) fn observe_original(
        &self,
        sequence: U64,
        original_digest: [u8; 32],
        expected_time: U64,
        hold_generation: u64,
    ) -> Result<(), NativeCommandError> {
        if !self.registered.load(Ordering::Acquire) || hold_generation == 0 {
            return Err(NativeCommandError::Conflict);
        }
        let mut originals = match self.originals.try_lock() {
            Ok(originals) => originals,
            Err(TryLockError::WouldBlock | TryLockError::Poisoned(_)) => {
                return Err(NativeCommandError::Conflict);
            }
        };
        if let Some(original) = originals.get(&sequence.get()) {
            return if original.original_digest == original_digest
                && original.expected_time == expected_time
                && original.hold_generation == hold_generation
            {
                Ok(())
            } else {
                Err(NativeCommandError::Conflict)
            };
        }
        if originals.len() >= MAXIMUM_ORIGINAL_OBSERVATIONS {
            return Err(NativeCommandError::ResourceLimit);
        }
        let mut lists = Vec::new();
        lists
            .try_reserve_exact(64)
            .map_err(|_| NativeCommandError::ResourceLimit)?;
        lists.resize(64, NativeTimerList::default());
        let mut timers = Vec::new();
        timers
            .try_reserve_exact(4096)
            .map_err(|_| NativeCommandError::ResourceLimit)?;
        timers.resize(4096, NativeTimerBirthAbi::default());
        let mut summary = NativeTimerBirthInventoryAbi::default();
        if (self.query)(
            self.policy.prepared_scope_hash.as_ptr(),
            hold_generation,
            &mut summary,
            lists.as_mut_ptr(),
            64,
            timers.as_mut_ptr(),
            4096,
        ) != 0
        {
            return Ok(());
        }
        if summary.list_count > 64
            || summary.timer_count > 4096
            || summary.prepared_scope_hash != self.policy.prepared_scope_hash
            || summary.gate_generation != hold_generation
            || summary.current_ps != expected_time.get()
            || summary.source_original_sequence != sequence.get()
            || summary.source_original_digest != original_digest
        {
            return Err(NativeCommandError::Conflict);
        }
        let observation = phase_abi::decode_native_inventory(
            &summary,
            &lists[..summary.list_count as usize],
            &timers[..summary.timer_count as usize],
        )?;
        observation.validate_against(&self.preparation)?;
        let bytes = observation.encode()?;
        if bytes.len() > NATIVE_PHASE_TIMER_OBJECT_MAX_BYTES {
            return Err(NativeCommandError::ResourceLimit);
        }
        originals.insert(
            sequence.get(),
            OriginalBirths {
                original_digest,
                expected_time,
                hold_generation,
                bytes,
            },
        );
        Ok(())
    }

    /// Returns an exact cached slice without resampling or releasing native custody.
    ///
    /// # Errors
    /// Refuses foreign scope, invalid offsets or concurrent/poisoned original custody.
    pub(crate) fn chunk(
        &self,
        query: &NativePhaseTimerQuery,
    ) -> Result<Option<NativePhaseTimerChunk>, NativeCommandError> {
        query.validate()?;
        if query.prepared_scope_hash != self.policy.prepared_scope_hash {
            return Err(NativeCommandError::Conflict);
        }
        let originals = self
            .originals
            .try_lock()
            .map_err(|_| NativeCommandError::Conflict)?;
        let Some(original) = originals.get(&query.sequence.get()) else {
            return Ok(None);
        };
        let offset =
            usize::try_from(query.offset.get()).map_err(|_| NativeCommandError::ResourceLimit)?;
        if offset >= original.bytes.len() {
            return Err(NativeCommandError::Conflict);
        }
        let end = offset.saturating_add(3000).min(original.bytes.len());
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(end - offset)
            .map_err(|_| NativeCommandError::ResourceLimit)?;
        bytes.extend_from_slice(&original.bytes[offset..end]);
        let chunk = NativePhaseTimerChunk {
            prepared_scope_hash: self.policy.prepared_scope_hash,
            sequence: query.sequence,
            object_digest: *blake3::hash(&original.bytes).as_bytes(),
            total_bytes: U64::new(original.bytes.len() as u64),
            offset: query.offset,
            bytes,
        };
        chunk.validate()?;
        Ok(Some(chunk))
    }
}
