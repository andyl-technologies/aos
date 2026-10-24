//! Joins preconstructed current checkpoints to the actual archive owner loop.
//!
//! Construction happens under a fully admitted Window before the unchanged
//! ConformanceRuntime reobservation. The writer callback performs only current
//! owner and complete-object comparisons, before any native owner submits.

use super::*;
use crate::node_contract::{HostSchedulingSource, OriginalInputLineageLimits};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WriterJoinStage {
    Waiting,
    Checking,
    Verified,
    Failed,
}

impl CompleteOriginalRestorationWindow {
    /// Constructs current snapshots and checkpoint beneath the admitted attempt.
    ///
    /// The caller repeats the unchanged whole-owner observation after this
    /// method, before lending Runtime mutably to the archive/native owner loop.
    ///
    /// # Errors
    /// Refuses foreign owners, wrong phase, existing native submissions,
    /// incomplete construction or any actual constructor-bank excess.
    pub(crate) fn construct_restored_capture_checkpoint_data(
        &self,
        slot: usize,
        runtime: &NodeRuntime,
        world: &WorldActivation,
        host: &HostSchedulingSource,
        lineage_limits: OriginalInputLineageLimits,
        maximum_record_bytes: usize,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        self.whole_observation.authenticate_dispatch_data()?;
        let mut ledger = self
            .restored_captures
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if slot.checked_add(1) != Some(ledger.attempts.len()) {
            return Err(RuntimeError::ForeignAuthority);
        }
        let attempt = ledger
            .attempts
            .get_mut(slot)
            .ok_or(RuntimeError::ForeignAuthority)?;
        if attempt.stage.get() != Stage::Admitted
            || !std::ptr::eq(attempt.runtime, runtime)
            || attempt.members.iter().any(|member| member.get() != 0)
            || attempt.writer_join.get() != WriterJoinStage::Waiting
        {
            return Err(RuntimeError::ForeignAuthority);
        }

        let result = (|| {
            attempt
                .boundary
                .authenticate_runtime_data(runtime, world, host)?;
            attempt.checkpoint_inputs.construct_data(
                runtime,
                world,
                host,
                &attempt.boundary,
                &attempt.runtime_row,
                lineage_limits,
                maximum_record_bytes,
            )?;
            if attempt
                .checkpoint_inputs
                .retained_requested_storage_data()?
                > attempt
                    .runtime_row
                    .checkpoint_inputs_construction_requested_bytes_data()
            {
                return Err(RuntimeError::ResourceLimit);
            }
            let (runtime_object, scheduling_object) = attempt.checkpoint_inputs.objects_data()?;
            attempt.checkpoint.construct_data(
                runtime,
                world,
                host,
                &attempt.boundary,
                &runtime_object.reference,
                &scheduling_object.reference,
            )?;
            if attempt.checkpoint.retained_requested_storage_data()?
                > attempt.boundary.construction_requested_bytes_data()
            {
                return Err(RuntimeError::ResourceLimit);
            }
            attempt
                .boundary
                .authenticate_runtime_data(runtime, world, host)
        })();
        if result.is_err() {
            attempt.stage.set(Stage::Failed);
        }
        self.whole_observation.require_observation();
        result
    }

    /// Joins real writer objects once before any owner is submitted.
    ///
    /// The generic writer has already checked its actual prepared Host snapshot
    /// against its own Scheduling object. These complete bytes must match the
    /// independently retained objects used by this same sealed checkpoint.
    ///
    /// # Errors
    /// Refuses reuse, changed Runtime/World/Host/boundary, incomplete constructor,
    /// differing bytes or any prior owner effect. Refusal poisons this attempt.
    pub(crate) fn join_restored_capture_writer_objects_data(
        &self,
        slot: usize,
        runtime: &NodeRuntime,
        world: &WorldActivation,
        host: &HostSchedulingSource,
        runtime_object: &InputPayload,
        scheduling_object: &InputPayload,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        self.whole_observation.authenticate_dispatch_data()?;
        let ledger = self
            .restored_captures
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let attempt = ledger.active(slot)?;
        if attempt.stage.get() != Stage::Admitted
            || !std::ptr::eq(attempt.runtime, runtime)
            || attempt.members.iter().any(|member| member.get() != 0)
            || attempt.writer_join.replace(WriterJoinStage::Checking) != WriterJoinStage::Waiting
        {
            attempt.writer_join.set(WriterJoinStage::Failed);
            attempt.stage.set(Stage::Failed);
            return Err(RuntimeError::ForeignAuthority);
        }

        let result = (|| {
            attempt
                .boundary
                .authenticate_runtime_data(runtime, world, host)?;
            attempt.runtime_row.authenticate_original_data(
                runtime,
                world,
                attempt.cut,
                attempt.ordinal,
            )?;
            attempt
                .checkpoint_inputs
                .authenticate_writer_objects_data(runtime_object, scheduling_object)?;
            attempt.checkpoint.object_for_runtime_data(runtime_object)?;
            attempt
                .boundary
                .authenticate_runtime_data(runtime, world, host)
        })();
        if result.is_ok() {
            attempt.writer_join.set(WriterJoinStage::Verified);
        } else {
            attempt.writer_join.set(WriterJoinStage::Failed);
            attempt.stage.set(Stage::Failed);
        }
        result
    }
}
