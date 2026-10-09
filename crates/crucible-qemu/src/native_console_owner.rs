//! Inactive original-publisher custody for issued console authorizations.
//!
//! The bounded inventory is separate from the byte ring. Its prepared writer
//! runs in the original NodeSlot transaction, retaining published receipts even
//! when a later wake fails. Phase authentication, native closed-RR retirement,
//! checkpoint/profile cutover remain unjoined. Installed launch custody uses
//! the committed setup and physical backing; fixture phase providers remain
//! explicitly test-only. Issuance does not authenticate native execution.

use crucible_protocol::native_console::{
    NativeConsoleAuthorization, NativeConsoleError, NativeConsoleOwner,
};
use crucible_shmem::native_console::NativeConsoleAuthorizationTable;
use crucible_shmem::{
    AdvanceCeiling, AdvanceStopCondition, FrameEntry, NodeSlot, RingHeader,
    SchedulerWakePublication, SchedulerWakePublicationError,
};
use std::num::NonZeroU32;

mod acceptance;
#[cfg(test)]
pub(crate) use acceptance::{AcceptedConsoleStopFixture, accepted_console_stop_fixture};
mod continuation;
mod hot_fork;
#[cfg(test)]
pub(crate) use hot_fork::tests::ChildFixture;
mod clamp_observation;
mod control_observation;
mod observation;
mod operation_stop;
pub(crate) use operation_stop::ConsoleStoppedOperation;
mod restore;
pub(crate) use continuation::ConsoleOriginContinuation;
pub(crate) use restore::ConsoleRestorePublication;
mod launch;
#[cfg(test)]
pub(crate) mod tests;
pub(crate) use launch::ConsoleLaunchCustody;

/// Maximum accepted console bytes retained between observation drains.
pub(crate) const MAX_CONSOLE_OBSERVATION_BYTES: usize = 16 * 1024 * 1024;

/// Required profile policy, retained separately from transport record capacity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct ConsoleAdmission {
    issued_authorization_capacity: NonZeroU32,
    receipt_storage_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct IssuedConsoleAuthorization {
    ordinal: u64,
    body: NativeConsoleAuthorization,
    projection: observation::ConsoleProjection,
}

/// Launch identity without an authorization incarnation masquerading as a fence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ConsoleLaunchBinding {
    slot: u32,
    region: [u8; 16],
    process: u64,
    logical_generation: u64,
}

/// Factual host publication fence; it is not native retirement permission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HostConsoleClampFence {
    binding: ConsoleLaunchBinding,
    issued_through: u64,
    last_issued: Option<NativeConsoleAuthorization>,
    advance: u64,
    ceiling: u64,
    publication: u64,
    request: Option<u32>,
    request_frontier: Option<u64>,
    request_capture: Option<u32>,
}

struct PreparedConsoleRequest<'a> {
    owner: &'a mut HostConsoleOwner,
    fence: HostConsoleClampFence,
}

impl PreparedConsoleRequest<'_> {
    fn commit(self, generation: u32, frontier: u64, capture: Option<u32>) {
        self.owner.clamp = Some(HostConsoleClampFence {
            request: Some(generation),
            request_frontier: Some(frontier),
            request_capture: capture,
            ..self.fence
        });
    }
}

/// Distinguishes new prefix consumption from control-only settlement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompletedConsoleControl {
    /// The original full-body clamp accepted and consumed its prefix.
    Accepted,
    /// The original empty clamp observed the unchanged already accepted prefix.
    Observed,
}

/// One launch-owned inventory, not one independently reconstructed per mapping.
struct HostConsoleOwner {
    admission: ConsoleAdmission,
    owner: NativeConsoleOwner,
    logical_generation: u64,
    issued: Vec<IssuedConsoleAuthorization>,
    next_ordinal: u64,
    next_incarnation: u64,
    next_publication: u64,
    next_clamp_publication: u64,
    clamp: Option<HostConsoleClampFence>,
    control_observation: Option<crucible_protocol::native_console::NativeConsoleClamp>,
    accepted: acceptance::ConsoleAcceptedContinuation,
    projection: observation::ConsoleProjection,
    pending_node_restore: Option<ConsoleOriginContinuation>,
}

pub(crate) struct ConsoleInputPublication<'a> {
    pub(crate) slot: &'a NodeSlot,
    pub(crate) dst_slot: u32,
    pub(crate) src_slot: u32,
    pub(crate) inbox: &'a RingHeader,
    pub(crate) entries: &'a mut [FrameEntry],
    pub(crate) inputs: &'a [FrameEntry],
    pub(crate) ceiling: AdvanceCeiling,
    pub(crate) stop: AdvanceStopCondition,
}

/// Refuses setup-owned bounded console publication before unowned effects.
#[derive(Debug, thiserror::Error)]
pub enum ConsoleOwnerError {
    /// The launch-local custody lock was poisoned.
    #[error("console launch custody is poisoned")]
    Poisoned,
    /// An original publication changed during the bounded acceptance read.
    #[error("console accepted publication is temporarily unavailable")]
    Unavailable,
    /// The original native stopped-output publisher temporarily owns the claim.
    #[error("console native control publication is temporarily unavailable")]
    PublicationUnavailable,
    /// The original launch descriptor could not be mapped.
    #[error("console setup mapping failed: {0}")]
    Mapping(crucible_shmem::SetupRegionMapError),
    /// The configured issued-body inventory is full.
    #[error("console authorization inventory is full")]
    Capacity,
    /// The admitted storage budget cannot hold the inventory.
    #[error("console authorization storage exceeds admitted policy")]
    Storage,
    /// Preallocation of the bounded inventory failed.
    #[error("console authorization allocation failed: {0}")]
    Allocation(#[from] std::collections::TryReserveError),
    /// A retained logical origin was malformed.
    #[error("console logical origin differs: {0}")]
    Origin(#[from] crucible::NativeConsoleOriginError),
    /// An origin could not be projected through its retained semantic owner.
    #[error("console scheduler projection differs: {0}")]
    Projection(#[from] crucible::SchedulerError),
    /// Stopped physical cursor rebinding refused its admission or drained state.
    #[error("console stopped ring rebinding failed: {0}")]
    RestoreRing(#[from] crucible_shmem::SpscRingError),
    /// The complete native prefix failed bounded ring or origin validation.
    #[error("console accepted prefix differs: {0}")]
    Prefix(#[from] crucible_shmem::native_console::NativeConsoleRingError),
    /// A console body or physical binding was malformed.
    #[error("console authorization shape differs: {0}")]
    Shape(#[from] NativeConsoleError),
    /// The original inbox/advance transaction refused.
    #[error("console publisher failed: {0}")]
    Publication(#[from] SchedulerWakePublicationError),
    /// The original clamp or paired request refused.
    #[error("console clamp failed: {0}")]
    Clamp(#[from] crucible_shmem::NodeSlotError),
}

impl HostConsoleOwner {
    fn new(
        admission: ConsoleAdmission,
        original: NativeConsoleAuthorization,
        plan: crucible_protocol::native_console::NativeConsolePlan,
    ) -> Result<Self, ConsoleOwnerError> {
        original.encode()?;
        let owner = original.owner;
        let logical_generation = original.logical_generation;
        let capacity = usize::try_from(admission.issued_authorization_capacity.get())
            .map_err(|_| ConsoleOwnerError::Storage)?;
        let bytes = capacity
            .checked_mul(std::mem::size_of::<IssuedConsoleAuthorization>())
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ConsoleOwnerError::Storage)?;
        if bytes > admission.receipt_storage_bytes {
            return Err(ConsoleOwnerError::Storage);
        }
        let mut issued = Vec::new();
        issued.try_reserve_exact(capacity)?;
        let allocated = issued
            .capacity()
            .checked_mul(std::mem::size_of::<IssuedConsoleAuthorization>())
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ConsoleOwnerError::Storage)?;
        if allocated > admission.receipt_storage_bytes {
            return Err(ConsoleOwnerError::Storage);
        }
        Ok(Self {
            admission,
            owner,
            logical_generation,
            issued,
            next_ordinal: 1,
            next_incarnation: owner.authorization,
            next_publication: 2,
            next_clamp_publication: 2,
            clamp: None,
            control_observation: None,
            accepted: acceptance::ConsoleAcceptedContinuation::new(plan)?,
            projection: observation::ConsoleProjection::Boot,
            pending_node_restore: None,
        })
    }

    /// Reserves all receipt storage before even reserving the AUTH table writer.
    fn reserve(
        &self,
        mut body: NativeConsoleAuthorization,
    ) -> Result<NativeConsoleAuthorization, ConsoleOwnerError> {
        if self.issued.len() >= self.admission.issued_authorization_capacity.get() as usize {
            return Err(ConsoleOwnerError::Capacity);
        }
        self.next_ordinal
            .checked_add(1)
            .ok_or(NativeConsoleError::Sequence)?;
        self.next_incarnation
            .checked_add(1)
            .ok_or(NativeConsoleError::Sequence)?;
        self.next_publication
            .checked_add(2)
            .ok_or(NativeConsoleError::Sequence)?;
        if body.owner.slot != self.owner.slot
            || body.owner.region != self.owner.region
            || body.owner.process != self.owner.process
            || body.logical_generation != self.logical_generation
        {
            return Err(NativeConsoleError::Binding.into());
        }
        body.owner.authorization = self.next_incarnation;
        self.accepted.prepare_body(&mut body)?;
        body.publication = self.next_publication;
        // The actual original writer supplies this field at commit. Zero-even
        // is only a prepared shape, never a usable execution authorization.
        body.advance = 0;
        body.encode()?;
        Ok(body)
    }

    /// Invokes the real inbox/advance transaction after bounded owner reservation.
    fn publish_inputs(
        &mut self,
        table: &NativeConsoleAuthorizationTable,
        body: NativeConsoleAuthorization,
        publication: ConsoleInputPublication<'_>,
    ) -> Result<SchedulerWakePublication, ConsoleOwnerError> {
        if publication.dst_slot != self.owner.slot {
            return Err(NativeConsoleError::Binding.into());
        }
        let body = self.reserve(body)?;
        let prepared = table.prepare_for_advance(body)?;
        let ordinal = self.next_ordinal;
        let projection = self.projection.clone();
        let result = publication
            .slot
            .publish_scheduler_inbox_and_advance_with_effect(
                publication.dst_slot,
                publication.src_slot,
                publication.inbox,
                publication.entries,
                publication.inputs,
                publication.ceiling,
                publication.stop,
                |advance| {
                    let body = prepared.commit_for_advance(advance);
                    // Capacity and all checked increments were reserved before
                    // inbox/AUTH/advance/wake effects. This push cannot allocate.
                    self.issued.push(IssuedConsoleAuthorization {
                        ordinal,
                        body,
                        projection,
                    });
                    self.next_ordinal += 1;
                    self.next_incarnation += 1;
                    self.next_publication += 2;
                    self.control_observation = None;
                },
            );
        // A wake failure occurs after this closure; retain its published body.
        // A preflight failure never invokes it and drops the unchanged writer.
        result.map_err(ConsoleOwnerError::from)
    }

    /// Captures issuance custody inside the original clamp writer, not afterward.
    fn publish_clamp(
        &mut self,
        slot: &NodeSlot,
        ceiling: AdvanceCeiling,
    ) -> Result<(), ConsoleOwnerError> {
        if self.clamp.is_some() {
            return Err(NativeConsoleError::Sequence.into());
        }
        if self.issued.is_empty() {
            self.require_empty_clamp_observation()?;
        }
        let binding = ConsoleLaunchBinding {
            slot: self.owner.slot,
            region: self.owner.region,
            process: self.owner.process,
            logical_generation: self.logical_generation,
        };
        let publication = self.next_clamp_publication;
        let next_publication = publication
            .checked_add(2)
            .ok_or(NativeConsoleError::Sequence)?;
        let issued_through = self.next_ordinal - 1;
        let last_issued = self.issued.last().map(|receipt| receipt.body);
        slot.publish_scheduler_advance_with_effect(
            ceiling,
            AdvanceStopCondition::Ceiling,
            |advance| {
                self.clamp = Some(HostConsoleClampFence {
                    binding,
                    issued_through,
                    last_issued,
                    advance: advance.get(),
                    ceiling: ceiling.max_advance_icount(),
                    publication,
                    request: None,
                    request_frontier: None,
                    request_capture: None,
                });
                self.next_clamp_publication = next_publication;
                self.control_observation = None;
            },
        )?;
        Ok(())
    }

    /// Prepares custody for the original runtime's request publication effect.
    fn prepare_request_custody(
        &mut self,
        publication: &crucible_shmem::HostControlBoundaryPublication<'_>,
    ) -> Result<PreparedConsoleRequest<'_>, ConsoleOwnerError> {
        let fence = self.clamp.ok_or(NativeConsoleError::Binding)?;
        let observed = publication
            .try_snapshot()
            .ok_or(NativeConsoleError::Binding)?;
        if observed.advance_publication_sequence != fence.advance
            || fence
                .request
                .is_some_and(|request| observed.control_boundary_ack != request)
            || (observed.control_boundary_ack & 1 == 0 && fence.request.is_none())
        {
            return Err(NativeConsoleError::Binding.into());
        }
        Ok(PreparedConsoleRequest { owner: self, fence })
    }

    fn original_authorization(&self, incarnation: u64) -> Option<NativeConsoleAuthorization> {
        self.issued
            .iter()
            .find(|receipt| receipt.body.owner.authorization == incarnation)
            .map(|receipt| receipt.body)
    }
}
