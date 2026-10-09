//! Control-only completion over an unchanged, genuinely accepted native prefix.
//!
//! Observation joins a new paired control to the original completed runtime
//! boundary. Its native CLOSED owner retains the old accepted frontier and
//! authorization floor; this host path neither consumes bytes nor invents AUTH.

use crucible_protocol::native_console::{
    NativeConsoleClamp, NativeConsoleControlKind, NativeConsoleFrontier,
};
use crucible_shmem::MappedSetupRegion;

use super::*;

impl HostConsoleOwner {
    /// Requires previously consumed physical custody, not empty genesis counters.
    ///
    /// # Errors
    ///
    /// Refuses unaccepted, restored, prepared, pending-restore or issued custody,
    /// or a retained receipt belonging to another physical owner or logical prefix.
    pub(super) fn require_empty_clamp_observation(
        &self,
    ) -> Result<NativeConsoleFrontier, ConsoleOwnerError> {
        if !self.accepted.has_accepted_control()
            || self.pending_node_restore.is_some()
            || !self.issued.is_empty()
        {
            return Err(NativeConsoleError::Binding.into());
        }
        let frontier = self
            .accepted
            .accepted_frontier()
            .ok_or(NativeConsoleError::Binding)?;
        if frontier.owner.slot != self.owner.slot
            || frontier.owner.region != self.owner.region
            || frontier.owner.process != self.owner.process
            || frontier.logical_generation != self.logical_generation
            || Some(frontier.request) != self.accepted.accepted_request
            || frontier.sequence != self.accepted.node_sequence()
            || frontier.ring_end != self.accepted.ring_end()
            || frontier.plan_hash != self.accepted.canonical_plan_hash()
        {
            return Err(NativeConsoleError::Binding.into());
        }
        Ok(frontier)
    }

    /// Rechecks the exact old frontier and drained physical ring without consuming.
    ///
    /// # Errors
    ///
    /// Refuses missing custody, inaccessible tables, a changed sealed frontier,
    /// or any ring cursor outside the original consumed end.
    pub(super) fn validate_observation_prefix(
        &self,
        region: &MappedSetupRegion,
    ) -> Result<NativeConsoleFrontier, ConsoleOwnerError> {
        let accepted = self.require_empty_clamp_observation()?;
        let segment = region.native_console_segment(self.owner.slot)?;
        if segment.frontier.copy()? != accepted
            || segment.ring.read_index() != accepted.ring_end
            || segment.ring.write_index() != accepted.ring_end
        {
            return Err(NativeConsoleError::Binding.into());
        }
        Ok(accepted)
    }

    /// Completes only the matching control fence over its unchanged accepted prefix.
    ///
    /// # Errors
    ///
    /// Refuses foreign or missing custody, a changed prefix or stop, a different
    /// pair, or a current boundary without its exact original odd ACK and clock.
    /// A changing node publication remains unavailable without clearing the fence.
    pub(super) fn complete_observation_clamp(
        &mut self,
        region: &MappedSetupRegion,
        boundary: crate::QemuCompletedQuantumBoundary,
        stop: Option<ConsoleStoppedOperation>,
    ) -> Result<CompletedConsoleControl, ConsoleOwnerError> {
        let accepted = self.require_empty_clamp_observation()?;
        let fence = self.clamp.ok_or(NativeConsoleError::Binding)?;
        if fence.last_issued.is_some()
            || fence.binding.slot != self.owner.slot
            || fence.binding.region != self.owner.region
            || fence.binding.process != self.owner.process
            || fence.binding.logical_generation != self.logical_generation
        {
            return Err(NativeConsoleError::Binding.into());
        }
        let expected = NativeConsoleClamp {
            publication: fence.publication,
            advance: fence.advance,
            request: fence.request.ok_or(NativeConsoleError::Binding)?,
            capture: fence.request_capture.unwrap_or(0),
            fault_frontier: fence.request_frontier.ok_or(NativeConsoleError::Binding)?,
            ceiling: fence.ceiling,
            stop: crucible_shmem::ADVANCE_STOP_CONDITION_CEILING,
            kind: NativeConsoleControlKind::Observation,
            last_issued: None,
        };
        // A previous stopped occurrence can validate only its original prefix;
        // it must never become a new output-completion reason after observation.
        if let Some(stop) = stop {
            stop.validate_frontier(accepted)?;
        }
        let slot = region
            .node_slot(self.owner.slot)
            .map_err(|_| NativeConsoleError::Binding)?;
        let before = slot.try_snapshot().ok_or(ConsoleOwnerError::Unavailable)?;
        let pair = region
            .native_console_segment(self.owner.slot)?
            .clamp
            .snapshot()?;
        self.validate_observation_prefix(region)?;
        let after = slot.try_snapshot().ok_or(ConsoleOwnerError::Unavailable)?;
        if before != after {
            return Err(ConsoleOwnerError::Unavailable);
        }
        if pair != expected
            || after.current_icount < accepted.logical_ps
            || after.logical_time_raw_icount < accepted.raw_prefix
        {
            return Err(NativeConsoleError::Binding.into());
        }
        boundary.validate_console_observation(
            region.backing_identity(),
            self.owner.slot,
            pair,
            after,
        )?;

        // No byte consumption, issuance retirement, or accepted-request update
        // follows this control-only suffix. The next Grant keeps its real floor.
        self.clamp = None;
        self.control_observation = Some(pair);
        Ok(CompletedConsoleControl::Observed)
    }
}
