//! Same-owner observation requests after genuine completed-prefix retirement.
//!
//! This publisher provides framing and request custody only. Native READY,
//! CLOSED, clock, resource and drained-prefix checks remain independent. It
//! never issues AUTH, changes the accepted prefix or republishes an advance.

use crucible_protocol::native_console::{NativeConsoleClamp, NativeConsoleControlKind};
use crucible_shmem::native_console::NativeConsoleClampTable;

use super::*;

impl HostConsoleOwner {
    pub(super) fn request_control_observation(
        &mut self,
        publication: crucible_shmem::HostControlBoundaryPublication<'_>,
        table: &NativeConsoleClampTable,
        frontier: u64,
        capture: Option<u32>,
    ) -> Result<u32, ConsoleOwnerError> {
        // Fresh setup and a pending Restore require their original full-body
        // acceptance. No empty-prefix label may fabricate bootstrap custody.
        if !self.accepted.has_accepted_control()
            || self.pending_node_restore.is_some()
            || !self.issued.is_empty()
        {
            return Err(NativeConsoleError::Binding.into());
        }
        let before = publication
            .try_snapshot()
            .ok_or(ConsoleOwnerError::Unavailable)?;
        let mut paired = NativeConsoleClamp {
            publication: self.next_clamp_publication,
            advance: before.advance_publication_sequence,
            request: before.control_boundary_ack.wrapping_add(1),
            capture: capture.unwrap_or(0),
            fault_frontier: frontier,
            ceiling: before.max_advance_icount,
            stop: before.advance_stop_condition,
            kind: NativeConsoleControlKind::Observation,
            last_issued: None,
        };
        if before.control_boundary_ack & 1 == 0 {
            let retained = self
                .control_observation
                .ok_or(NativeConsoleError::Binding)?;
            paired.publication = retained.publication;
            paired.request = before.control_boundary_ack;
            if paired != retained || table.snapshot()? != retained {
                return Err(NativeConsoleError::Binding.into());
            }
            return publication
                .request_with_effect(frontier, capture, |_| {})
                .map_err(ConsoleOwnerError::Clamp);
        }
        let next_publication = paired
            .publication
            .checked_add(2)
            .ok_or(NativeConsoleError::Sequence)?;
        let fields = table.prepare(paired)?;
        let after = publication
            .try_snapshot()
            .ok_or(ConsoleOwnerError::Unavailable)?;
        if before != after {
            return Err(ConsoleOwnerError::Unavailable);
        }
        publication
            .request_with_prepared_fields(
                frontier,
                capture,
                |request| fields.commit_before_request(request),
                |request| {
                    self.control_observation = Some(NativeConsoleClamp { request, ..paired });
                    self.next_clamp_publication = next_publication;
                },
            )
            .map_err(ConsoleOwnerError::Clamp)
    }
}

impl ConsoleLaunchCustody {
    /// Joins the latest odd ACK to its current control-only checkpoint pair.
    ///
    /// Native publication commits its observation before releasing this exact
    /// ACK. This finite framing check neither accepts a console prefix nor
    /// authorizes RUN; a changed advance or request must settle again.
    ///
    /// # Errors
    ///
    /// Refuses a foreign mapping, inaccessible console tables, or malformed
    /// paired custody. An unavailable publication remains unsettled.
    pub(crate) fn checkpoint_observation_is_settled(
        &self,
        region: &crucible_shmem::MappedSetupRegion,
        snapshot: &crucible_shmem::NodeSlotSnapshot,
    ) -> Result<bool, ConsoleOwnerError> {
        self.validate_mapping(region, self.slot)?;
        let paired = match region.native_console_segment(self.slot)?.clamp.snapshot() {
            Ok(paired) => paired,
            Err(NativeConsoleError::Sequence) => return Ok(false),
            Err(source) => return Err(source.into()),
        };
        Ok(paired.kind == NativeConsoleControlKind::Observation
            && snapshot.control_boundary_ack == paired.request.wrapping_add(1)
            && snapshot.control_boundary_ack & 1 != 0
            && snapshot.control_boundary_fault_command_frontier == paired.fault_frontier
            && snapshot.control_boundary_capture_request == paired.capture
            && snapshot.advance_publication_sequence == paired.advance
            && snapshot.max_advance_icount == paired.ceiling
            && snapshot.advance_stop_condition == paired.stop)
    }
}

#[cfg(test)]
mod tests;
