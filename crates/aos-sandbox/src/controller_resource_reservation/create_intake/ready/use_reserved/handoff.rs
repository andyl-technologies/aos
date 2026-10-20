//! Publishes C10 from the same positive U and both original held releases.
//!
//! The returned view borrows these exact completed owners for Root6 transport;
//! decoded release receipts cannot construct a handoff or terminal completion.

use super::*;
use super::release::OriginalCreateStorageReleasedV1;
use super::super::super::history::handoff::HandoffOriginalsV1;
use aos_sandbox_protocol::domain_ledger::create_storage_history::continuation::ContinuationNativeReceiptDataV1;

impl OriginalCreateStorageReadyV1<'_, '_> {
    /// Records the actual committed U and both original held releases on C10.
    ///
    /// Its same atomic pair performs the native append, exact readback and
    /// independent posts. Earlier positive U and releases remain permanent if
    /// any later observation or this publication fails.
    ///
    /// # Errors
    /// Refuses reentry, incomplete original releases or commit, changed native
    /// association, exhausted U, or append, readback and owed-post failures.
    #[doc(hidden)]
    pub fn produce_original_storage_handoff_once(&mut self) -> Result<(), CreateStorageReadyClosedV1> {
        if self.failure().is_some() {
            return Err(CreateStorageReadyClosedV1);
        }
        self.original.owner.storage_use.handoff.enter_once()
            .map_err(|_| CreateStorageReadyClosedV1)?;
        let entry = self.original.require_operation_currentness_peak_v1(&self.cache);
        let owner = &mut *self.original.owner;
        let actual = &mut owner.storage_use;
        actual.handoff.entry = Some(entry);
        actual.handoff.primary = Some((|| {
            if !matches!(actual.handoff.entry, Some(Ok(()))) {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            let (_, append, width, receiving) = actual.reservation.split_commit_inputs_v1()?;
            let reserved = OriginalCreateStorageUseReservedV1 { append,
                request_shape_bytes: width, record: &actual.reserved };
            let committed = commit::completed_committed_view_v1(reserved, &actual.outcome, &actual.commit)?;
            let released = actual.release.borrow_released_v1(committed)?;
            let inputs = owner.root_exchange.inputs_ready_receipt_v1()?;
            actual.handoff.produce_once(&owner.parent, &mut owner.intake,
                &owner.histories, &owner.assignment, &actual.validated, &actual.reserved,
                &actual.signed, &actual.dispatch, &actual.session, &released, receiving,
                self.original.controller, self.original.source, self.original.profile, inputs)
        })());
        if !matches!(actual.handoff.primary, Some(Ok(()))) || actual.handoff.position().is_err() {
            // The final Cache release prepaid this one next-purpose refusal.
            // Preserve the earlier C10/native cause and run the actual Root
            // post even when an ambiguous attempt has no completed position.
            if let Ok((_, receiving)) = actual.reservation.split_retained_root_receiving_after_debt_v1() {
                let _ = owner.root_exchange.observe_handoff_entry_refusal_once(
                    &owner.parent, &mut owner.intake, self.original.controller,
                    self.original.source, self.original.profile, &mut self.cache,
                    &actual.handoff, receiving);
            }
            return Err(CreateStorageReadyClosedV1);
        }
        Ok(())
    }
}

/// Borrows the actual C10 pair beside both original releases and positive U.
pub(in crate::controller_resource_reservation::create_intake)
struct OriginalCreateStorageHandoffV1<'held> {
    handoff: &'held HandoffOriginalsV1,
    released: OriginalCreateStorageReleasedV1<'held>,
}

impl CreateStorageUseOriginalsV1 {
    pub(in crate::controller_resource_reservation::create_intake)
    fn split_handoff_receiving_v1(&mut self)
        -> Result<(OriginalCreateStorageHandoffV1<'_>, &mut UseReceivingOriginalsV1), ResourceReservationErrorV1> {
        if self.failure().is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        self.handoff.position()?;
        let (_, append, width, receiving) = self.reservation.split_commit_inputs_v1()?;
        let reserved = OriginalCreateStorageUseReservedV1 { append,
            request_shape_bytes: width, record: &self.reserved };
        let handoff = completed_handoff_view_v1(reserved, &self.outcome, &self.commit,
            &self.release, &self.handoff)?;
        Ok((handoff, receiving))
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn borrow_handoff_v1(&self) -> Result<OriginalCreateStorageHandoffV1<'_>, ResourceReservationErrorV1> {
        if self.failure().is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        let reserved = completed_reserved_view_v1(&self.reservation, &self.reserved)?;
        completed_handoff_view_v1(reserved, &self.outcome, &self.commit, &self.release, &self.handoff)
    }
}

// Only the same returned native C10, positive U and both released originals
// can form this view. This constructor performs no allocation or native work.
pub(super) fn completed_handoff_view_v1<'held>(reserved: OriginalCreateStorageUseReservedV1<'held>,
    outcome: &'held super::super::super::history::outcome::OutcomeOriginalsV1,
    committed: &'held commit::UseCommitOriginalsV1,
    released: &'held release::ReleaseOriginalsV1,
    handoff: &'held HandoffOriginalsV1,
) -> Result<OriginalCreateStorageHandoffV1<'held>, ResourceReservationErrorV1> {
    handoff.position()?;
    let committed = commit::completed_committed_view_v1(reserved, outcome, committed)?;
    let released = released.borrow_released_v1(committed)?;
    Ok(OriginalCreateStorageHandoffV1 { handoff, released })
}

impl<'held> OriginalCreateStorageHandoffV1<'held> {
    pub(in crate::controller_resource_reservation::create_intake)
    fn receipt_v1(&self) -> Result<ContinuationNativeReceiptDataV1<'held>, ResourceReservationErrorV1> {
        self.handoff.receipt_v1()
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn position_v1(&self) -> Result<CreateStorageWriterPositionV1, ResourceReservationErrorV1> {
        self.handoff.position()
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn released_v1(&self) -> &OriginalCreateStorageReleasedV1<'held> { &self.released }

    pub(in crate::controller_resource_reservation::create_intake)
    fn cutoff_v1(&self) -> Result<u64, ResourceReservationErrorV1> { self.released.cutoff_v1() }

    pub(in crate::controller_resource_reservation::create_intake)
    fn clock_v1(&self) -> Result<aos_sandbox_core::RawPairedClockSample, ResourceReservationErrorV1> {
        self.released.clock_v1()
    }
}
