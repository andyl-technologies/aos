//! Same-coordinate terminal preflight over original console grant custody.
//!
//! This read-only join never changes AUTH, accepted origins or an existing
//! clamp. Retirement remains the ordinary full-body Acceptance transaction.

use super::*;
use crucible_protocol::native_console::NativeConsolePhase;
use crucible_shmem::{MappedSetupRegion, NodeSlotSnapshot};

impl HostConsoleOwner {
    pub(super) fn validate_terminal_regrant(
        &self,
        region: &MappedSetupRegion,
        authorization: &NativeConsoleAuthorizationTable,
        snapshot: NodeSlotSnapshot,
    ) -> Result<bool, ConsoleOwnerError> {
        if self.clamp.is_some() || self.pending_node_restore.is_some() {
            return Err(NativeConsoleError::Binding.into());
        }
        if self.issued.is_empty() {
            return Ok(false);
        }
        if !self.accepted.has_accepted_control() {
            return Err(NativeConsoleError::Binding.into());
        }

        let accepted = self
            .accepted
            .accepted_frontier()
            .ok_or(NativeConsoleError::Binding)?;
        let segment = region.native_console_segment(self.owner.slot)?;
        let last = self.issued.last().ok_or(NativeConsoleError::Binding)?.body;
        if segment.frontier.copy()? != accepted
            || segment.ring.read_index() != accepted.ring_end
            || segment.ring.write_index() != accepted.ring_end
            || accepted.owner.slot != self.owner.slot
            || accepted.owner.region != self.owner.region
            || accepted.owner.process != self.owner.process
            || accepted.logical_generation != self.logical_generation
            || Some(accepted.request) != self.accepted.accepted_request
            || accepted.sequence != self.accepted.node_sequence()
            || accepted.ring_end != self.accepted.ring_end()
            || accepted.plan_hash != self.accepted.canonical_plan_hash()
            || accepted.logical_ps != snapshot.current_icount
            || accepted.raw_prefix != snapshot.logical_time_raw_icount
            || authorization.snapshot()? != last
            || snapshot.advance_publication_sequence != last.advance
        {
            return Err(NativeConsoleError::Binding.into());
        }
        for receipt in &self.issued {
            let body = receipt.body;
            if body.phase != NativeConsolePhase::Grant
                || body.owner.slot != self.owner.slot
                || body.owner.region != self.owner.region
                || body.owner.process != self.owner.process
                || body.logical_generation != self.logical_generation
                || body.prior_sequence != accepted.sequence
                || body.prior_ring_end != accepted.ring_end
                || body.phase_token != u64::from(accepted.request)
            {
                return Err(NativeConsoleError::Binding.into());
            }
        }
        let live = region
            .node_slot(self.owner.slot)
            .map_err(|_| NativeConsoleError::Binding)?
            .try_snapshot()
            .ok_or(ConsoleOwnerError::Unavailable)?;
        if live != snapshot {
            return Err(ConsoleOwnerError::Unavailable);
        }
        Ok(true)
    }
}
