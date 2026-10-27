//! Bounded controller effects dispatched only after native receipt validation.
//!
//! Native owns the endpoint, ancillary aliases, stack and service role. The
//! independent reader invokes these effects after canonical session/sequence
//! validation and an actual zero-descriptor loan check for ordinary requests.
// SPDX-License-Identifier: GPL-2.0-or-later

use super::source::SourceOperationFactory;
use crucible_qemu_protocol::ram_control::{
    RamControlOuterCap, RamControlPolicy, RamControlReply, RamControlResources, RamControlTarget,
};

/// Actual paging owner; methods must never wait for guest locks or backing I/O.
pub(crate) trait PagerControl: SourceOperationFactory + 'static {
    /// Returns the exact admitted target without guest locks or backing I/O.
    fn identity(&self) -> RamControlTarget;

    fn apply(
        &self,
        expected_revision: u64,
        policy_revision: u64,
        reservation_revision: u64,
        policy: RamControlPolicy,
        resources: RamControlResources,
    ) -> RamControlReply;

    fn status(&self) -> RamControlReply;

    fn performance(
        &self,
        _: crucible_qemu_protocol::ram_control::RamControlPerformanceAction,
    ) -> RamControlReply {
        let mut reply = self.status();
        reply.disposition = crucible_qemu_protocol::ram_control::RamControlDisposition::Unsupported;
        reply
    }

    fn test_fault_actor(
        &self,
        entitlement: [u8; 32],
        worker_generation: u64,
        action: crucible_qemu_protocol::ram_control::RamControlFaultActorAction,
    ) -> RamControlReply;

    fn inventory_region(&self, topology_generation: u64, ordinal: u32) -> RamControlReply;

    fn grant_inventory(
        &self,
        topology_generation: u64,
        resources: RamControlResources,
        spill_quota_bytes: u64,
    ) -> RamControlReply;

    fn sync_outer_cap(&self, cap: RamControlOuterCap) -> RamControlReply;

    fn cancel(&self, operation_generation: u64) -> RamControlReply;
}
