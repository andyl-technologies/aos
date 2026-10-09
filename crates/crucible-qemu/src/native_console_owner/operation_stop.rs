//! Private discovery custody for a genuinely accounted native UART stop.
//!
//! The installed producer retains the original stopped occurrence and may
//! republish its unchanged coordinates inside a later original node writer.
//! Discovery joins that exact framing, an unconsumed byte and the retained
//! issuing body. It never consumes bytes, retires grants or substitutes for
//! the original device settlement and accepted control clamp.

use crucible_protocol::native_console::NativeConsoleOperationStop;
use crucible_shmem::{MappedSetupRegion, NodeSlotSnapshot, STATUS_IDLE};

use super::*;

/// Keeps authenticated discovery private until the original clamp accepts it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ConsoleStoppedOperation {
    stop: NativeConsoleOperationStop,
}

impl ConsoleStoppedOperation {
    pub(crate) const fn node_sequence(self) -> u64 {
        self.stop.node_sequence
    }

    pub(crate) fn validate_frontier(
        self,
        frontier: crucible_protocol::native_console::NativeConsoleFrontier,
    ) -> Result<(), NativeConsoleError> {
        if frontier.owner != self.stop.owner
            || frontier.logical_generation != self.stop.logical_generation
            || frontier.sequence != self.stop.node_sequence
            || frontier.ring_end != self.stop.ring_end
            || !self.matches_coordinate(frontier.logical_ps, frontier.raw_prefix)
        {
            return Err(NativeConsoleError::Binding);
        }
        Ok(())
    }

    pub(crate) fn matches_coordinate(self, logical: u64, raw: u64) -> bool {
        self.stop.logical_ps == logical && self.stop.raw_prefix == raw
    }
}

impl ConsoleLaunchCustody {
    /// Keeps an unconsumed native prefix pending until its stop is discovered.
    ///
    /// Cursor presence supplies no stop or completion authority. In particular,
    /// a coherent pause publication without the accounted stop row cannot turn
    /// queued bytes into an ordinary idle completion.
    pub(crate) fn has_unconsumed_operation(
        &self,
        region: &MappedSetupRegion,
    ) -> Result<bool, ConsoleOwnerError> {
        self.validate_mapping(region, self.slot_index())?;
        let segment = region.native_console_segment(self.slot_index())?;
        let read = segment.ring.read_index();
        let write = segment.ring.write_index();
        let live = write
            .checked_sub(read)
            .ok_or(NativeConsoleError::Sequence)?;
        if live > u64::from(crucible_protocol::native_console::NATIVE_CONSOLE_CAPACITY) {
            return Err(NativeConsoleError::Sequence.into());
        }
        Ok(live != 0)
    }

    /// Attempts one coherent stopped-operation discovery without consuming it.
    pub(crate) fn observe_operation_stop(
        &self,
        region: &MappedSetupRegion,
        snapshot: NodeSlotSnapshot,
    ) -> Result<Option<ConsoleStoppedOperation>, ConsoleOwnerError> {
        self.validate_mapping(region, self.slot_index())?;
        if snapshot.status != STATUS_IDLE
            || snapshot.idle_wake_icount != snapshot.current_icount
            || snapshot.device_io_active != 0
        {
            return Ok(None);
        }
        let segment = region.native_console_segment(self.slot_index())?;
        let stop = match segment.operation_stop.try_snapshot() {
            Ok(Some(stop)) => stop,
            Ok(None) | Err(NativeConsoleError::Sequence) => return Ok(None),
            Err(source) => return Err(source.into()),
        };
        // A native owner must republish after intervening node/advance/control
        // publications. Arbitrarily later framing cannot authenticate this row.
        if stop.closed_generation != snapshot.publish_gen
            || stop.control_boundary_ack != snapshot.control_boundary_ack
            || stop.stopped_advance != snapshot.advance_publication_sequence
            || stop.logical_ps != snapshot.current_icount
            || stop.raw_prefix != snapshot.logical_time_raw_icount
        {
            return Ok(None);
        }
        let owner = self.lock()?;
        if stop.node_sequence <= owner.accepted.node_sequence()
            || stop.ring_end == owner.accepted.ring_end()
        {
            return Ok(None);
        }
        let body = owner
            .original_authorization(stop.owner.authorization)
            .ok_or(NativeConsoleError::Binding)?;
        if body.owner != stop.owner
            || body.advance != stop.authorization_advance
            || body.logical_generation != stop.logical_generation
            || body.prior_sequence != owner.accepted.node_sequence()
            || body.prior_ring_end != owner.accepted.ring_end()
            || stop.node_sequence.checked_sub(body.prior_sequence)
                != stop.ring_end.checked_sub(body.prior_ring_end)
            || stop.node_sequence - body.prior_sequence > u64::from(body.allowance)
        {
            return Err(NativeConsoleError::Binding.into());
        }
        let Some(tail) = segment
            .ring
            .peek_native_console_operation_tail(segment.records, stop.ring_end)?
        else {
            return Ok(None);
        };
        let plan = owner.accepted.plan();
        let stream = plan
            .streams
            .iter()
            .find(|stream| stream.stream == tail.origin.stream)
            .ok_or(NativeConsoleError::Plan)?;
        if tail.owner != body.owner
            || tail.phase != body.phase
            || tail.authorization_advance != body.advance
            || tail.origin.logical_generation != plan.logical_generation
            || tail.origin.node_sequence != stop.node_sequence
            || tail.origin.vcpu != stop.vcpu
            || stream.owner_mask & (1_u64 << stop.vcpu) == 0
            || tail.origin.logical_ps > stop.logical_ps
            || tail.origin.raw_prefix > stop.raw_prefix
        {
            return Err(NativeConsoleError::Binding.into());
        }
        let live = region
            .node_slot(self.slot_index())
            .map_err(|_| NativeConsoleError::Binding)?
            .try_snapshot();
        if live != Some(snapshot) {
            return Ok(None);
        }
        Ok(Some(ConsoleStoppedOperation { stop }))
    }
}
