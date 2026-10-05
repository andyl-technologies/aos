//! Immutable evidence from the original accepted completed-quantum clamp.

use crucible::Icount;
use crucible_shmem::{NodeSlotSnapshot, SetupRegionBackingIdentity};

use crate::{
    QemuLogicalTimeCalibration, QemuNodeChannelError, QemuNodeIdleState, QemuPendingQuantum,
};

/// Retains one live runtime's accepted control-boundary publication.
///
/// This host-local value does not grant execution or replace the final live
/// scheduler observation. Its raw/logical pair and retained idle deadline come
/// from the same coherent snapshot accepted by the original clamp handshake.
/// Modeled providers without that handshake report no such evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuCompletedQuantumBoundary {
    backing: SetupRegionBackingIdentity,
    vm_slot: u32,
    discovery: NodeSlotSnapshot,
    request_generation: u32,
    snapshot: NodeSlotSnapshot,
}

impl QemuCompletedQuantumBoundary {
    pub(crate) fn accepted(
        backing: SetupRegionBackingIdentity,
        vm_slot: u32,
        discovery: NodeSlotSnapshot,
        request_generation: u32,
        request_frontier: u64,
        snapshot: NodeSlotSnapshot,
    ) -> Option<Self> {
        // The original control callback publishes its exact-ceiling IDLE
        // boundary before this odd successor. RUNNING can then replace only
        // the phase label while the same request and dispatch fence remain.
        if snapshot.control_boundary_ack != request_generation.wrapping_add(1)
            || snapshot.control_boundary_fault_command_frontier != request_frontier
            || snapshot.control_boundary_capture_request != 0
        {
            return None;
        }
        Some(Self {
            backing,
            vm_slot,
            discovery,
            request_generation,
            snapshot,
        })
    }

    /// Returns the original coherent logical/raw retirement pair.
    #[must_use]
    pub const fn calibration(self) -> QemuLogicalTimeCalibration {
        QemuLogicalTimeCalibration {
            logical_icount: self.snapshot.current_icount,
            raw_icount: self.snapshot.logical_time_raw_icount,
        }
    }

    /// Returns the exact idle deadline retained by the accepted clamp.
    ///
    /// The original ceiling-control publication establishes this deadline even
    /// if its unchanged acknowledged fence is subsequently labeled RUNNING.
    /// Genuine future or tightened deadlines remain their original values.
    #[must_use]
    pub const fn idle_state(self) -> QemuNodeIdleState {
        QemuNodeIdleState {
            current_icount: Icount {
                retired: self.snapshot.current_icount,
            },
            next_deadline: Some(Icount {
                retired: self.snapshot.idle_wake_icount,
            }),
        }
    }

    pub(crate) fn validate(
        self,
        backing: SetupRegionBackingIdentity,
        vm_slot: u32,
        pending: &QemuPendingQuantum,
        live: NodeSlotSnapshot,
    ) -> Result<(), QemuNodeChannelError> {
        // The discovery must follow the original pending advance publication,
        // not merely share a coordinate with a previous completed quantum.
        let publication_distance = self
            .discovery
            .advance_publication_sequence
            .wrapping_sub(pending.advance_publication_sequence);
        let request_distance = self
            .request_generation
            .wrapping_sub(pending.initial_control_boundary_ack);
        if self.backing != backing
            || self.vm_slot != vm_slot
            || publication_distance == 0
            || publication_distance >= (1_u64 << 63)
            || request_distance >= (1_u32 << 31)
            || self.discovery.current_icount < pending.initial_state.current_icount.retired
            || self.discovery.current_icount > pending.ceiling.retired
            || self.snapshot.current_icount != self.discovery.current_icount
            || self.snapshot.max_advance_icount != self.snapshot.current_icount
            || live.logical_time_raw_icount != self.snapshot.logical_time_raw_icount
            || live.current_icount != self.snapshot.current_icount
            || live.advance_publication_sequence != self.snapshot.advance_publication_sequence
            || live.control_boundary_fault_command_frontier
                != self.snapshot.control_boundary_fault_command_frontier
            || live.control_boundary_capture_request
                != self.snapshot.control_boundary_capture_request
            || live.control_boundary_ack != self.snapshot.control_boundary_ack
        {
            return Err(QemuNodeChannelError::new(
                "validate completed-quantum boundary",
                "accepted clamp does not belong to this pending mapped quantum",
            ));
        }
        self.calibration().offset()?;
        Ok(())
    }
}
