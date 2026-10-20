//! Closes the original Cache custody only after actual C10 and Root6.
//!
//! Its actual control destination is prepaid and allocated at the earlier
//! Cache release entry. No final debt can suppress its independently owed IO.

use super::*;
use super::super::cache_receiving::{CacheControlOriginalsV1, CacheCurrentnessOriginalV1, OriginalCacheAssociationV1};

#[derive(Default)]
pub(super) struct CacheTerminalControlOriginalsV1 {
    control: CacheCurrentnessOriginalV1,
    returned: Option<Result<(), ResourceReservationErrorV1>>,
    native: Option<Result<(), crate::cache_residency::CacheHeldClosedV1>>,
    selected_control: bool,
}

impl CacheTerminalControlOriginalsV1 {
    pub(super) fn selected_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.selected_control.then(|| self.control.failure().or_else(|| self.returned.as_ref()
            .and_then(|result| result.as_ref().err()).map(|cause| cause as _))).flatten()
    }

    fn require_complete_v1(&self) -> Result<(), ResourceReservationErrorV1> {
        if !matches!(self.native, Some(Ok(()))) || !matches!(self.returned, Some(Ok(())))
            || self.failure().is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.selected_failure_v1().or_else(|| self.native.as_ref()
            .and_then(|result| result.as_ref().err()).map(|cause| cause as _))
    }
}

pub(super) fn receiving_demand_v1() -> Result<aos_sandbox_core::ResourceVector, ResourceReservationErrorV1> {
    use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
    let bytes = std::mem::size_of::<CacheTerminalControlOriginalsV1>().checked_mul(2)
        .and_then(|bytes| bytes.checked_add(std::mem::align_of::<CacheTerminalControlOriginalsV1>()))
        .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<CacheTerminalReceivingLoanV1<'_, '_>>()))
        .ok_or(ResourceReservationErrorV1::Conflict)?;
    let (wire, logs) = ProductionControllerNormalRootProfileV1::create_storage_producer_traffic_bound_v1(1)
        .ok_or(ResourceReservationErrorV1::Conflict)?;
    ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| ResourceReservationErrorV1::Conflict)?)
        .with(D::NetworkBytes, wire).with(D::LogBytes, logs)
        .checked_add(CacheCurrentnessOriginalV1::receiving_backing_demand_v1(1)?)?
        .checked_add(crate::cache_residency::cache_terminal_receiving_demand_v1()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?)
        .map_err(ResourceReservationErrorV1::from)
}

/// Borrows only the actual original releases, C10, Root6 and prepaid post.
///
/// The private Ready entry is the sole constructor. No caller-supplied result,
/// position, amount or decoded terminal can construct this native borrower.
pub(crate) struct CacheTerminalReceivingLoanV1<'borrow, 'held> {
    handoff: &'borrow OriginalCreateStorageHandoffV1<'held>,
    closed: &'borrow super::super::root_exchange::OriginalCreateStorageRootClosedV1<'borrow>,
    state: &'borrow mut CacheTerminalControlOriginalsV1,
    parent: &'borrow ProjectPreparationReservationAttemptV1,
    intake: &'borrow mut Q04OriginalIntakeAttemptV1,
    controller: &'borrow Journal,
    source: &'borrow ProtectedSourceDomainJournalOwnerV1,
    profile: &'borrow ProductionControllerNormalRootProfileV1,
    expected: OriginalCacheAssociationV1,
}

impl CacheTerminalReceivingLoanV1<'_, '_> {
    pub(crate) fn released_original_v1(&self) -> Result<&crate::cache_residency::CacheReleasedOriginalsV1, ResourceReservationErrorV1> {
        self.handoff.released_v1().cache_original_v1()
    }

    pub(crate) fn require_original_v1(&self, identity: crate::cache_residency::CacheHeldIdentityDataV1)
        -> Result<(), ResourceReservationErrorV1> {
        self.closed.require_handoff_v1(self.handoff)?;
        self.handoff.released_v1().committed_v1()
            .require_current_state_v1(self.controller.controller_resource_state_v1()?)?;
        self.parent.require_create_storage_association(self.controller, self.source, self.profile)?;
        self.intake.require_retained_capture()?;
        self.expected.require_identity_v1(identity)?;
        if self.released_original_v1()?.identity_v1().map_err(|_| ResourceReservationErrorV1::Conflict)? != identity {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    pub(crate) fn clock_v1(&self) -> Result<aos_sandbox_core::RawPairedClockSample, ResourceReservationErrorV1> {
        self.closed.clock_v1()
    }

    pub(crate) fn cutoff_v1(&self) -> Result<u64, ResourceReservationErrorV1> { self.closed.cutoff_v1() }

    pub(crate) fn observe_currentness_once(&mut self, cache: &crate::cache_residency::OriginalCreateStorageCacheLoanV1<'_>)
        -> Result<(), ResourceReservationErrorV1> {
        if self.state.returned.is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        self.state.returned = Some(self.state.control.observe_operation_once(CacheControlOriginalsV1 {
            parent: self.parent, intake: self.intake, controller: self.controller,
            source: self.source, profile: self.profile,
        }, cache, self.expected, self.handoff.position_v1()));
        if matches!(self.state.returned, Some(Ok(()))) { Ok(()) }
        else { Err(ResourceReservationErrorV1::Conflict) }
    }
}

impl OriginalCreateStorageReadyV1<'_, '_> {
    /// Completes the actual final Cache post beside the same C10 and Root6.
    ///
    /// # Errors
    /// Retains an absent/failed actual terminal, changed original, reentry,
    /// native Cache names/physical/clock/selection or C/Source/profile refusal.
    #[doc(hidden)]
    pub fn finish_original_storage_cache_after_root_once(&mut self) -> Result<(), CreateStorageReadyClosedV1> {
        if self.failure().is_some() { return Err(CreateStorageReadyClosedV1); }
        let owner = &mut *self.original.owner;
        let actual = &mut owner.storage_use;
        let reserved = completed_reserved_view_v1(&actual.reservation, &actual.reserved)
            .map_err(|_| CreateStorageReadyClosedV1)?;
        let handoff = handoff::completed_handoff_view_v1(reserved, &actual.outcome, &actual.commit,
            &actual.release, &actual.handoff).map_err(|_| CreateStorageReadyClosedV1)?;
        let closed = owner.root_exchange.borrow_closed_v1(&handoff).map_err(|_| CreateStorageReadyClosedV1)?;
        let expected = owner.cache_capture.currentness_association_v1().map_err(|_| CreateStorageReadyClosedV1)?;
        let state = actual.terminal.as_deref_mut().ok_or(CreateStorageReadyClosedV1)?;
        let mut loan = CacheTerminalReceivingLoanV1 { handoff: &handoff, closed: &closed, state,
            parent: &owner.parent, intake: &mut owner.intake, controller: self.original.controller,
            source: self.original.source, profile: self.original.profile, expected };
        let returned = self.cache.finish_original_create_storage_after_root_v1(&mut loan);
        loan.state.selected_control = self.cache.terminal_control_is_selected_v1();
        loan.state.native = Some(returned);
        loan.state.require_complete_v1().map_err(|_| CreateStorageReadyClosedV1)
    }
}

impl CreateStorageUseOriginalsV1 {
    // This pure retained-result gate is shared by the actual final Cache
    // caller, fixed crossing and operation terminal getter. It grants no IO.
    pub(in crate::controller_resource_reservation::create_intake)
    fn require_completed_cache_terminal_v1(&self) -> Result<(), ResourceReservationErrorV1> {
        self.terminal.as_deref().ok_or(ResourceReservationErrorV1::Conflict)?.require_complete_v1()
    }
}
