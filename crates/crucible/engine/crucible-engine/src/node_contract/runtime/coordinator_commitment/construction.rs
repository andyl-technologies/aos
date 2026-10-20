//! Binds independently funded fresh log storage to a genuine imported checkpoint.
//!
//! The row is constructor DATA. The owning Window retains and whole-admits it
//! before its private installation callback can reserve either bank. The signed
//! Source supplies inherited policy and consumed counters; caller coordinates,
//! native receive credit and a freshly allocated Vec cannot renew them.

use super::*;
use crate::node_state::{CompleteOriginalRestorationSource, CompleteOriginalSource};

/// Prices the same original fresh bank without granting dispatch or Capture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OriginalRestoredCoordinator17ConstructionData {
    runtime: *const NodeRuntime,
    source: *const CompleteOriginalSource,
    parent: *const ContentRef,
    policy: CoordinatorCommitmentPolicy17,
    first_sequence: U64,
    first_event_ordinal: U64,
    retained: usize,
    scratch: usize,
    maximum: usize,
}

impl OriginalRestoredCoordinator17ConstructionData {
    pub(crate) fn quote(
        runtime: &NodeRuntime,
        source: &CompleteOriginalRestorationSource,
        target: &ActivationRecord,
        maximum: usize,
    ) -> Result<Self, RuntimeError> {
        if !runtime.has_original_activation_proposal(target) {
            return Err(RuntimeError::ForeignAuthority);
        }
        let (parent, checkpoint) = source.historical_coordinator_checkpoint17_data()?;
        if checkpoint.activation.world_binding != target.world_binding_hash
            || checkpoint.safe_point.position != target.boundary
            || source.original_runtime_record_data()?.capture_ordinal
                != checkpoint.safe_point.event_ordinal
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let policy = CoordinatorCommitmentPolicy17::new(
            usize::try_from(checkpoint.maximum_records.get())
                .map_err(|_| RuntimeError::ResourceLimit)?,
        )?;
        let retained = policy
            .requested_bytes_data()?
            .checked_add(NodeRuntime::capture_reference_storage(parent)?)
            .ok_or(RuntimeError::ResourceLimit)?;
        let scratch = construction_counter_scratch_data();
        retained
            .checked_add(scratch)
            .filter(|bytes| *bytes <= maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        Ok(Self {
            runtime,
            source: Rc::as_ptr(&source.inner),
            parent,
            policy,
            first_sequence: checkpoint.next_sequence,
            first_event_ordinal: checkpoint.safe_point.event_ordinal,
            retained,
            scratch,
            maximum,
        })
    }

    /// Requeries real immutable owners without allocating or treating axes as rights.
    pub(crate) fn authenticate_original_data(
        &self,
        runtime: &NodeRuntime,
        source: &CompleteOriginalRestorationSource,
        target: &ActivationRecord,
    ) -> Result<(), RuntimeError> {
        if !std::ptr::eq(self.runtime, runtime)
            || !std::ptr::eq(self.source, Rc::as_ptr(&source.inner))
            || *self != Self::quote(runtime, source, target, self.maximum)?
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    pub(crate) fn counter_scratch_data() -> usize {
        construction_counter_scratch_data()
    }

    pub(crate) fn requested_bytes_data(&self) -> Result<usize, RuntimeError> {
        self.retained
            .checked_add(self.scratch)
            .filter(|bytes| *bytes <= self.maximum)
            .ok_or(RuntimeError::ResourceLimit)
    }
}

impl NodeRuntime {
    /// Installs the admitted imported bank before any fresh World publication.
    /// The actual Window calls this only after its complete owner census.
    pub(crate) fn initialize_restored_coordinator17_before_activation_data(
        &self,
        source: &CompleteOriginalRestorationSource,
        target: &ActivationRecord,
        row: &OriginalRestoredCoordinator17ConstructionData,
    ) -> Result<(), RuntimeError> {
        row.authenticate_original_data(self, source, target)?;
        if self.activated || !self.barrier.can_arm() || self.barrier.record() != target {
            return Err(RuntimeError::ForeignAuthority);
        }
        let (reference, checkpoint) = source.historical_coordinator_checkpoint17_data()?;
        if !std::ptr::eq(reference, row.parent) {
            return Err(RuntimeError::ForeignAuthority);
        }
        let log =
            CoordinatorCommitments17::unallocated_for_checkpoint_data(row.policy, checkpoint)?;
        self.scheduler
            .as_ref()
            .ok_or(RuntimeError::NotActivated)?
            .initialize_coordinator17_data(log, row.maximum, reference)?;
        row.authenticate_original_data(self, source, target)
    }

    /// Rechecks the original prepublication owner after actual fresh activation.
    /// A missing owner refuses; this phase never allocates or renews the bank.
    pub(crate) fn initialize_restored_coordinator17_data(
        &self,
        source: &CompleteOriginalRestorationSource,
        target: &ActivationRecord,
        world: &WorldActivation,
        row: &OriginalRestoredCoordinator17ConstructionData,
    ) -> Result<(), RuntimeError> {
        row.authenticate_original_data(self, source, target)?;
        self.validate_activation(world)?;
        if world.record() != target {
            return Err(RuntimeError::ForeignAuthority);
        }
        let (reference, checkpoint) = source.historical_coordinator_checkpoint17_data()?;
        self.scheduler
            .as_ref()
            .ok_or(RuntimeError::NotActivated)?
            .with_coordinator17_data(|log| {
                let log = log.ok_or(RuntimeError::UnsupportedFacet)?;
                if log.parent.as_ref() != Some(reference)
                    || log.policy != row.policy
                    || log.first_sequence != checkpoint.next_sequence
                    || log.first_event_ordinal != checkpoint.safe_point.event_ordinal
                    || log.activation_attempt.is_none()
                {
                    return Err(RuntimeError::ForeignAuthority);
                }
                let attempt = log
                    .activation_attempt
                    .ok_or(RuntimeError::ForeignAuthority)?;
                if log.entries.get(attempt.index).is_none_or(|entry| {
                    entry.sequence != attempt.sequence
                        || entry.kind != CoordinatorCommitmentKind17::Activation
                        || entry.state != CoordinatorCommitmentState17::Committed
                        || entry.event_ordinal.is_some()
                }) {
                    return Err(RuntimeError::OutstandingObligations);
                }
                Ok(())
            })?;
        row.authenticate_original_data(self, source, target)?;
        self.validate_activation(world)
    }
}

/// Names the defining row, genuine Source loans and private installer results.
pub(crate) fn construction_counter_scratch_data() -> usize {
    size_of::<OriginalRestoredCoordinator17ConstructionData>()
        + size_of::<&OriginalRestoredCoordinator17ConstructionData>()
        + size_of::<Option<OriginalRestoredCoordinator17ConstructionData>>()
        + size_of::<Result<OriginalRestoredCoordinator17ConstructionData, RuntimeError>>()
        + size_of::<&NodeRuntime>()
        + size_of::<&CompleteOriginalRestorationSource>()
        + size_of::<&ActivationRecord>()
        + size_of::<&WorldActivation>()
        + size_of::<(&ContentRef, &CoordinatorCommitmentCheckpoint17)>()
        + size_of::<Result<(&ContentRef, &CoordinatorCommitmentCheckpoint17), RuntimeError>>()
        + size_of::<Result<(), RuntimeError>>()
        + size_of::<Result<usize, RuntimeError>>()
        + size_of::<Result<usize, std::num::TryFromIntError>>()
        + counter_scratch_data()
}
