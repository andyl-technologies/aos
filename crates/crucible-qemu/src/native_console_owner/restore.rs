//! Exact stopped QMP load custody joined to the original mapped restore request.
//!
//! Checkpoint origins never become runnable permission. The fresh launch keeps
//! its physical process and increasing AUTH incarnations. Native acceptance
//! must independently join its whole-loader receipt, loaded canonical prefix,
//! installed resource owner and original CLOSED restore callback.

use super::*;

#[cfg(test)]
mod tests;
use crucible_protocol::native_console::{NativeConsoleClamp, NativeConsolePhase};
use crucible_shmem::MappedSetupRegion;

/// Retains the exact fields committed by the stopped request producer.
///
/// These identifiers describe local publication custody, not native load,
/// CLOSED or execution authority. The frontier comes from the same pair that
/// precedes both original request releases.
pub(crate) struct ConsoleRestorePublication {
    generation: u32,
    request: u32,
    fault_frontier: u64,
}

impl ConsoleRestorePublication {
    pub(crate) const fn generation(&self) -> u32 {
        self.generation
    }

    pub(crate) const fn request(&self) -> u32 {
        self.request
    }

    pub(crate) const fn fault_frontier(&self) -> u64 {
        self.fault_frontier
    }
}

impl ConsoleLaunchCustody {
    pub(crate) fn accept_restored(
        &self,
        region: &MappedSetupRegion,
        boundary: crate::mapped_quantum::restore::QemuLogicalTimeRestoreBoundary,
        calibration: crate::QemuLogicalTimeCalibration,
    ) -> Result<(), ConsoleOwnerError> {
        self.validate_mapping(region, self.slot_index())?;
        self.lock()?.accept_restored(region, boundary, calibration)
    }

    /// Arms Restore only after the factory's authenticated load and IO restore.
    pub(crate) fn arm_stopped_restore(
        &self,
        region: &MappedSetupRegion,
        node: &crucible::NodeId,
        saved: &ConsoleOriginContinuation,
        loaded: crate::qmp::QmpCheckpointRestore,
        expected: crate::qmp::QmpCheckpointIdentity,
        target: u64,
    ) -> Result<ConsoleRestorePublication, ConsoleOwnerError> {
        if loaded.identity() != expected {
            return Err(NativeConsoleError::Binding.into());
        }
        self.arm_bound_stopped_restore(region, node, saved, target)
    }

    /// Publishes logical custody through the sole claimed Restore transaction.
    ///
    /// Callers retain either the actual QMP load receipt or the admitted private
    /// child handoff. This helper grants no native phase: the native loaded or
    /// INITIALIZE owner must independently authenticate the paired body.
    pub(super) fn arm_bound_stopped_restore(
        &self,
        region: &MappedSetupRegion,
        node: &crucible::NodeId,
        saved: &ConsoleOriginContinuation,
        target: u64,
    ) -> Result<ConsoleRestorePublication, ConsoleOwnerError> {
        self.validate_mapping(region, self.slot_index())?;
        if node != &saved.node {
            return Err(NativeConsoleError::Binding.into());
        }
        let saved = ConsoleOriginContinuation::decode(&saved.encode()?)?;
        let mut owner = self.lock()?;
        let mut plan = owner.accepted.checkpoint_plan();
        plan.slot = 0;
        if plan.encode()? != saved.plan
            || !owner.issued.is_empty()
            || owner.clamp.is_some()
            || owner.pending_node_restore.is_some()
        {
            return Err(NativeConsoleError::Binding.into());
        }
        let slot = region
            .node_slot(self.slot_index())
            .map_err(|_| NativeConsoleError::Binding)?;
        let snapshot = slot.try_snapshot().ok_or(ConsoleOwnerError::Unavailable)?;
        let frontier = region
            .fault_command_write_index(self.slot_index())
            .map_err(|_| NativeConsoleError::Binding)?;
        let segment = region.native_console_segment(self.slot_index())?;
        let mut body = owner.reserve(self.original_launch_body())?;
        body.phase = NativeConsolePhase::Restore;
        body.phase_token = 0;
        body.prior_sequence = saved.sequence;
        body.prior_ring_end = saved.ring_end;
        let authorization = segment.authorization.prepare_for_restore(body)?;
        let publication = owner.next_clamp_publication;
        let next_publication = publication
            .checked_add(2)
            .ok_or(NativeConsoleError::Sequence)?;
        let paired = segment.clamp.prepare(NativeConsoleClamp {
            publication,
            advance: 0,
            request: 0,
            capture: 0,
            fault_frontier: frontier,
            ceiling: snapshot.max_advance_icount,
            stop: crucible_shmem::ADVANCE_STOP_CONDITION_CEILING,
            kind: crucible_protocol::native_console::NativeConsoleControlKind::Acceptance,
            last_issued: Some(body),
        })?;
        // Preallocate the retained checkpoint and all logical vectors before
        // changing the physical ring. Native loaded state must independently
        // match this captured endpoint before it accepts the new Restore body.
        let retained = ConsoleOriginContinuation::decode(&saved.encode()?)?;
        let ordinal = owner.next_ordinal;
        let projection = saved.projection.clone();
        let restored_projection = projection.clone();
        let cursor = segment
            .ring
            .prepare_drained_cursor_while_stopped(saved.ring_end)?;
        let binding = ConsoleLaunchBinding {
            slot: owner.owner.slot,
            region: owner.owner.region,
            process: owner.owner.process,
            logical_generation: owner.logical_generation,
        };

        let (generation, request) = slot
            .request_logical_time_restore_with_prepared_fields(
                target,
                frontier,
                snapshot.max_advance_icount,
                |request, generation, advance| {
                    // The original request claim has passed its fallible preflight.
                    // Cursor and logical custody now commit with the prepared AUTH
                    // before either request is exposed to the native reader.
                    cursor.commit();
                    owner.accepted.restore_owned_parts(
                        saved.sequence,
                        saved.ring_end,
                        saved.stream_sequences,
                        saved.pending,
                    );
                    owner.projection = restored_projection;
                    owner.pending_node_restore = Some(retained);
                    let body = authorization.commit(advance, generation);
                    paired.commit_restore_before_request(request, advance, generation);
                    owner.issued.push(IssuedConsoleAuthorization {
                        ordinal,
                        body,
                        projection,
                    });
                    owner.next_ordinal += 1;
                    owner.next_incarnation += 1;
                    owner.next_publication += 2;
                    owner.next_clamp_publication = next_publication;
                    owner.control_observation = None;
                    owner.clamp = Some(HostConsoleClampFence {
                        binding,
                        issued_through: ordinal,
                        last_issued: Some(body),
                        advance: advance.get(),
                        ceiling: snapshot.max_advance_icount,
                        publication,
                        request: Some(request.get()),
                        request_frontier: Some(frontier),
                        request_capture: None,
                    });
                },
            )
            .map_err(ConsoleOwnerError::Clamp)?;
        Ok(ConsoleRestorePublication {
            generation,
            request,
            fault_frontier: frontier,
        })
    }
}
