//! Borrows the actual completed J parent and its original Controller/Source.
//!
//! This closed association entrance is not Ready, a live B cut, a receiving
//! budget or permission to append/sign/send. The owning producer must extend
//! the same J demand and supply exact Intent/Held/Ownership/Inventory/Input
//! results before its complete schema or Root exchange can become positive.

use super::*;
use super::history::CreateStorageWriterPositionV1;

pub(super) mod cache_receiving;
pub(super) mod inventory;
pub(in crate::controller_resource_reservation) use inventory::preparation_io_receiving_demand_v1;
pub use inventory::{OriginalCreateStorageInventoryV1, CreateStorageInventoryClosedV1, CreateStorageInventoryShapeDataV1, CreateStorageInventoryPendingDisposalV1};
pub(super) mod client_session;
pub use client_session::{CreateStorageClientSessionClosedV1, CreateStorageClientSessionShapeDataV1,
    CreateStorageEndpointRevalidationShapeDataV1,
    OriginalCreateStorageClientSessionV1, CreateStorageClientPositiveDisposalV1};

mod production;
mod terminal;
pub(super) mod use_reserved;
pub(in crate::controller_resource_reservation) use use_reserved::commit_receiving_demand_v1;
pub use use_reserved::preparation::CreateStoragePrepareInputsDataV1;
pub(in crate::controller_resource_reservation) use use_reserved::preparation::preparation_originals_receiving_demand_v1;
pub(crate) use use_reserved::{CreateStorageUseBankOriginalsV1, CreateStorageUseBankAppendV1,
    CreateStorageUseHistoryReceivingLoanV1};
pub(in crate::controller_resource_reservation) use use_reserved::UseReceivingOriginalsV1;
pub(super) mod root_exchange;
mod cache_current_proof;
pub(crate) use use_reserved::release::CacheReleaseReceivingLoanV1;
pub(crate) use use_reserved::cache_terminal::CacheTerminalReceivingLoanV1;
pub use use_reserved::release::create_storage_held_release_receiving_demand_v1;
pub use root_exchange::create_storage_cache_current_fixed_receiving_demand_v1;
pub use root_exchange::create_storage_cache_current_dynamic_receiving_demand_v1;
pub use root_exchange::{OriginalCreateStorageUseSigningV1, CreateStorageUseSigningInputsDataV1};
pub(in crate::controller_resource_reservation) use root_exchange::signing_originals_receiving_demand_v1;
pub use root_exchange::{CreateStorageRootUseTailShapeDataV1, create_storage_root_use_tail_shape_v1};
pub use root_exchange::{CreateStorageRootExchangeClosedV1, CreateStorageControllerDriverShapeDataV1, OriginalCreateStorageRootExchangeV1};
pub(super) mod bundle;
mod outcome_receiving;
#[doc(hidden)]
pub use bundle::{CreateStorageReadyNativeInputsV1, CreateStorageBundleShapeDataV1,
    CreateStorageBundleClosedV1, OriginalCreateStorageBundleV1};
pub(super) mod ownership;
pub use ownership::CreateStorageOwnershipProgressV1;

pub use production::{OriginalCreateStorageReadyV1, CreateStorageReadyClosedV1};

/// Holds fixed accepted identity copied only from the retained original parent.
#[derive(Clone, Copy)]
pub(in crate::controller_resource_reservation) struct CreateStorageAcceptedIdentityV1 {
    pub(in crate::controller_resource_reservation) operation: [u8; 16],
    pub(in crate::controller_resource_reservation) project: [u8; 16],
    pub(in crate::controller_resource_reservation) sandbox: [u8; 16],
    pub(in crate::controller_resource_reservation) accepted_request: [u8; 32],
    pub(in crate::controller_resource_reservation) coissuance_binding: [u8; 32],
    pub(in crate::controller_resource_reservation) original_cutoff: u64,
}

/// Keeps the same real writers borrowed while the closed producer runs.
///
/// No raw Journal or caller-built identity can be extracted. Private child
/// producer stages must hold this loan through the whole actual Root exchange,
/// adding their own paid exact native suffix/currentness requirements.
pub(crate) struct CreateStorageOriginalLoanV1<'original> {
    owner: &'original mut CreateContinuationIntakeAttemptV1,
    controller: &'original mut Journal,
    source: &'original mut ProtectedSourceDomainJournalOwnerV1,
    profile: &'original ProductionControllerNormalRootProfileV1,
    completed: bool,
}

impl CreateContinuationIntakeAttemptV1 {
    // This pure identity/native association entrance is private to the actual
    // owning coordinator. It does not pay or enter any later variable capture.
    pub(in crate::controller_resource_reservation) fn borrow_create_storage_original_once<'original>(
        &'original mut self,
        controller: &'original mut Journal,
        source: &'original mut ProtectedSourceDomainJournalOwnerV1,
        profile: &'original ProductionControllerNormalRootProfileV1,
    ) -> Result<CreateStorageOriginalLoanV1<'original>, ResourceReservationErrorV1> {
        if self.ready_loan_borrowed || self.ready_after.is_some()
            || self.histories.source_held_data_v1(self.intake.create_lane()?).is_err() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.parent.require_create_storage_association(controller, source, profile)?;
        self.intake.require_retained_capture()?;
        if !matches!(self.ready_before, Some(Ok(_))) {
            self.intake.close();
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.ready_loan_borrowed = true;
        Ok(CreateStorageOriginalLoanV1 { owner: self, controller, source, profile, completed: false })
    }
}

impl CreateStorageOriginalLoanV1<'_> {
    // This pure closed check lends no new amount or authority. The real
    // exclusive purpose still admits its additional backing and runs all
    // currentness posts before IO; earlier failure prevents any peak reuse.
    pub(super) fn require_operation_currentness_peak_v1(
        &self, cache: &crate::cache_programmes::OriginalCreateStorageCacheLoanV1<'_>,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.owner.failure().is_some() || cache.failure().is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.owner.assignment.planned_manifest_v1()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        self.owner.cache_capture.require_held_join_v1()?;
        cache.require_same_controller_original_v1(self.profile)?;
        let cut = cache.original_q04_identity_data_v1()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        if !self.owner.parent.matches_create_continuation_identity(&cut) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.owner.parent.require_create_storage_association(self.controller, self.source, self.profile)?;
        self.owner.intake.require_create_history_names_peak_v1()
    }

    pub(crate) fn create_storage_lane_v1(&self) -> Result<[u8; 16], ResourceReservationErrorV1> {
        self.owner.intake.create_lane()
    }

    pub(crate) fn source_held_data_v1(&self) -> Result<
        aos_sandbox_protocol::domain_ledger::create_storage_history::source_held::SourceHeldReceiptDataV1<'_>,
        ResourceReservationErrorV1,
    > {
        self.owner.intake.require_retained_capture()?;
        self.owner.histories.source_held_data_v1(self.owner.intake.create_lane()?)
    }

    pub(crate) fn require_preparation_profile_original_v1(
        &self,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if !std::ptr::eq(self.profile, profile) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.owner.intake.require_retained_capture()?;
        self.owner.parent.require_create_storage_association(
            self.controller, self.source, profile,
        )?;
        self.owner.cache_capture.require_held_join_v1()
    }

    // Later AssignmentPlanned/InputsReady owners must extend this PRIVATE
    // actual-return roster; arbitrary Controller advances remain forbidden.
    pub(super) fn current_controller_history_position_v1(&self)
        -> Result<CreateStorageWriterPositionV1, ResourceReservationErrorV1>
    {
        if self.owner.storage_use.started() {
            self.owner.storage_use.position()
        } else if self.owner.root_exchange.inputs_started() {
            self.owner.root_exchange.position()
        } else if self.owner.assignment.started() {
            self.owner.assignment.position()
        } else {
            self.owner.histories.controller_position_v1()
        }
    }

    // These copied identities are DATA while the original writers stay held.
    fn accepted(&self) -> Result<CreateStorageAcceptedIdentityV1, ResourceReservationErrorV1> {
        self.owner.ready_before.as_ref().and_then(|result| result.as_ref().ok()).copied()
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    // This association post alone never validates a new B or an allowed native
    // suffix. The actual producer must complete those stronger retained checks
    // before it can call this final fixed crossing; no raw callback is exposed.
    fn finish_association_once(&mut self) -> Result<(), ResourceReservationErrorV1> {
        if let Some(previous) = self.owner.ready_after.as_mut() {
            // Preserve every native positive result while refusing another
            // logical seal. An earlier actual error is never overwritten.
            if previous.is_ok() { *previous = Err(ResourceReservationErrorV1::Conflict); }
            self.owner.intake.close();
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.owner.ready_after = Some((|| {
            self.owner.storage_use.require_completed_cache_terminal_v1()?;
            let handoff = self.owner.storage_use.borrow_handoff_v1()?;
            self.owner.root_exchange.borrow_closed_v1(&handoff)?;
            self.owner.parent.require_terminal_retention()?;
            self.owner.intake.require_retained_capture()?;
            self.owner.parent.require_create_continuation_owners(
                self.controller, self.source, self.profile,
            )
        })());
        if matches!(self.owner.ready_after, Some(Ok(()))) {
            self.completed = true;
            Ok(())
        } else {
            self.owner.intake.close();
            Err(ResourceReservationErrorV1::Conflict)
        }
    }
}

impl Drop for CreateStorageOriginalLoanV1<'_> {
    fn drop(&mut self) {
        if !self.completed {
            // The actual owners remain in their parent/worker destinations.
            // Abandoning this private once-only entrance cannot rearm J or
            // turn copied accepted identities into a later capture permit.
            self.owner.intake.close();
        }
    }
}
