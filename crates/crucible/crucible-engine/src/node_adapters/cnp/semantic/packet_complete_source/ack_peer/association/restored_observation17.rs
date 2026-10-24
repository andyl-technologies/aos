//! Retains distinct signed Observe17 custody and its nonrenewing completion.
//!
//! A separate pending owner lets a genuine latest-checkpoint borrower retain
//! the next attempt without mutating the completed history it currently lends.
//! Failure preserves that owner and blocks new current-proof selection. Only
//! the actual Root Window17 completion fence can publish a new checkpoint.

use super::*;
use crate::node_contract::{NodeRuntime, RuntimeError};
use crate::node_scheduling::NativeSchedulingObservation;
use crucible_node_format::{ContentRef, Id, U64};
use crucible_node_transport::{
    bodies::ObserveRequest,
    client::{CnpController, OriginalRestoredSuffixHostAttempt},
    envelope::Envelope,
    reference_packet::{
        control::PacketNative5UnderlyingRecord,
        service::{
            complete_restore::PacketNativeRestoredRecord,
            restored_input_reactive17::{
                PacketRestoredInputReactive17Artifact, PacketRestoredInputReactive17Command,
                PacketRestoredInputReactive17Context, PacketRestoredInputReactive17Request,
                PacketRestoredInputReactive17RetainedData,
            },
        },
    },
};
use std::{cell::RefCell, mem::size_of, thread::ThreadId};

#[path = "restored_observation17/checkpoint_cache17.rs"]
mod checkpoint_cache17;
#[path = "restored_observation17/retained.rs"]
mod retained;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage {
    Preparing,
    Assigned,
    Published,
    SourceVerified,
    Complete,
    Failed,
}

struct Observation17Attempt {
    ordinal: u64,
    id: Option<Id>,
    body: Option<ObserveRequest>,
    request: Option<PacketRestoredInputReactive17Request>,
    context: Option<PacketRestoredInputReactive17Context>,
    artifact: Option<PacketRestoredInputReactive17Artifact>,
    sdk: Option<OriginalRestoredSuffixHostAttempt>,
    previous_measurement: Option<ContentRef>,
    previous_model: Option<ContentRef>,
    previous_frontier: Option<U64>,
    measurement: Option<ContentRef>,
    record: Option<PacketNativeRestoredRecord>,
    underlying: Option<PacketNative5UnderlyingRecord>,
    record_value: Option<serde_json::Value>,
    model_value: Option<serde_json::Value>,
    record_bytes: Option<Vec<u8>>,
    model_bytes: Option<Vec<u8>>,
    scheduling: Option<NativeSchedulingObservation>,
    previous: [u8; 32],
    signature: Option<[u8; 32]>,
    stage: Stage,
}

/// Keeps pending/failure ownership distinct from borrowed completed history.
pub(super) struct Observation17Owner {
    process: u32,
    thread: ThreadId,
    pending: RefCell<Option<Observation17Attempt>>,
    completed: RefCell<Vec<Observation17Attempt>>,
}

impl Observation17Owner {
    pub(super) fn new_data() -> Self {
        Self {
            process: std::process::id(),
            thread: std::thread::current().id(),
            pending: RefCell::new(None),
            completed: RefCell::new(Vec::new()),
        }
    }

    fn authenticate_origin_data(&self) -> Result<(), RuntimeError> {
        if self.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        Ok(())
    }

    fn require_idle_data(&self) -> Result<(), RuntimeError> {
        self.authenticate_origin_data()?;
        if self
            .pending
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .is_some()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        let completed = self
            .completed
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if completed
            .iter()
            .any(|attempt| attempt.stage != Stage::Complete)
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }

    fn begin_pending_data(&self, ordinal: u64, previous: [u8; 32]) -> Result<(), RuntimeError> {
        self.require_idle_data()?;
        let completed = self
            .completed
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if u64::try_from(completed.len())
            .map_err(|_| RuntimeError::ResourceLimit)?
            .checked_add(1)
            != Some(ordinal)
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        drop(completed);
        let mut pending = self
            .pending
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if pending.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        *pending = Some(Observation17Attempt {
            ordinal,
            id: None,
            body: None,
            request: None,
            context: None,
            artifact: None,
            sdk: None,
            previous_measurement: None,
            previous_model: None,
            previous_frontier: None,
            measurement: None,
            record: None,
            underlying: None,
            record_value: None,
            model_value: None,
            record_bytes: None,
            model_bytes: None,
            scheduling: None,
            previous,
            signature: None,
            stage: Stage::Preparing,
        });
        Ok(())
    }

    pub(super) fn is_used_data(&self) -> Result<bool, RuntimeError> {
        self.authenticate_origin_data()?;
        Ok(self
            .pending
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .is_some()
            || self
                .completed
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?
                .capacity()
                != 0)
    }

    pub(super) fn retained_heap_bytes_with_error<E: StorageError>(
        &self,
        maximum: usize,
    ) -> Result<usize, E> {
        let pending = self
            .pending
            .try_borrow()
            .map_err(|_| E::unknown("Observe17 pending owner busy"))?;
        let completed = self
            .completed
            .try_borrow()
            .map_err(|_| E::unknown("Observe17 completed owner busy"))?;
        let mut bytes = completed
            .capacity()
            .checked_mul(size_of::<Observation17Attempt>())
            .filter(|bytes| *bytes <= maximum)
            .ok_or_else(|| E::limit("Observe17 history capacity"))?;
        for attempt in completed.iter().chain(pending.iter()) {
            bytes = retained::retained_attempt_bytes_with_error::<E>(attempt, bytes, maximum)?;
        }
        Ok(bytes)
    }
}

struct PendingGuard<'a>(&'a Observation17Owner);

impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut pending) = self.0.pending.try_borrow_mut()
            && let Some(attempt) = pending.as_mut()
            && !matches!(attempt.stage, Stage::SourceVerified | Stage::Complete)
        {
            attempt.stage = Stage::Failed;
        }
    }
}

impl PacketCompleteSemanticSource {
    /// Refuses omission of any initialized signed Observe17 state from an old writer.
    ///
    /// A complete new17 logical history writer must replace this narrow unused
    /// guard before an active signed observation can be captured. No portable
    /// cache, old observation proof or schema selection can clear the owner.
    ///
    /// # Errors
    /// Refuses another Source origin, unavailable/busy association, or any
    /// initialized, pending, failed or completed signed Observe17 custody.
    pub(in crate::node_adapters::cnp::semantic) fn authenticate_unused_signed_observation17_owner_data(
        &self,
    ) -> Result<(), RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let association = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let original = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        original.authenticate_transfer_ready_data()?;
        if original.restored_observations17.is_used_data()? {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }
}

// crucible-lint: allow panic-shortcut -- these tests inspect actual private DATA custody, not a Source/Window/native grant.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dropping_a_pending_attempt_keeps_same_failed_ordinal_and_blocks_reentry() {
        let owner = Observation17Owner::new_data();
        assert!(!owner.is_used_data().unwrap());
        owner.begin_pending_data(1, [19; 32]).unwrap();
        let guard = PendingGuard(&owner);

        drop(guard);

        assert!(owner.is_used_data().unwrap());
        let pending = owner.pending.borrow();
        let attempt = pending.as_ref().unwrap();
        assert_eq!(attempt.ordinal, 1);
        assert_eq!(attempt.previous, [19; 32]);
        assert_eq!(attempt.stage, Stage::Failed);
        drop(pending);
        assert!(matches!(
            owner.require_idle_data(),
            Err(RuntimeError::OutstandingObligations)
        ));
        assert!(owner.begin_pending_data(1, [0; 32]).is_err());
        assert_eq!(owner.pending.borrow().as_ref().unwrap().previous, [19; 32]);
    }

    #[test]
    fn partial_owned_banks_and_reserved_history_remain_in_exact_census() {
        let owner = Observation17Owner::new_data();
        owner.completed.borrow_mut().try_reserve_exact(2).unwrap();
        owner.begin_pending_data(1, [0; 32]).unwrap();
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(71).unwrap();
        bytes.extend_from_slice(b"retained partial proof");
        let capacity = bytes.capacity();
        owner.pending.borrow_mut().as_mut().unwrap().model_bytes = Some(bytes);
        let slots = owner.completed.borrow().capacity() * size_of::<Observation17Attempt>();
        let total = slots + capacity;
        assert_eq!(
            owner
                .retained_heap_bytes_with_error::<RuntimeError>(total)
                .unwrap(),
            total
        );
        assert!(
            owner
                .retained_heap_bytes_with_error::<RuntimeError>(total - 1)
                .is_err()
        );
        assert!(owner.is_used_data().unwrap());
        drop(PendingGuard(&owner));
        assert_eq!(
            owner
                .pending
                .borrow()
                .as_ref()
                .unwrap()
                .model_bytes
                .as_deref(),
            Some(b"retained partial proof".as_slice())
        );
    }
}
