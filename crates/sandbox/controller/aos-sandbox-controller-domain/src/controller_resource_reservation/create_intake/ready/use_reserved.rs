//! Retains the actual Controller RootValidated and later same-bank U stages.
//!
//! The completed Root turn lends its original frame and negotiated cutoff;
//! this sibling owns every Controller append destination while that original
//! stream, Cache loan and accepted J remain continuously resident.

mod bank_append;
pub(in crate::controller_resource_reservation::create_intake) mod commit;
pub(in crate::controller_resource_reservation) use commit::commit_receiving_demand_v1;
pub(in crate::controller_resource_reservation::create_intake) use commit::OriginalCreateStorageUseCommittedV1;
mod receiving;
mod signed;
mod dispatch;
mod outcome;
mod handoff;
pub(in crate::controller_resource_reservation::create_intake) use handoff::OriginalCreateStorageHandoffV1;
pub(in crate::controller_resource_reservation::create_intake) mod release;
pub(super) mod cache_terminal;
pub(in crate::controller_resource_reservation::create_intake) use outcome::OriginalCreateStorageOutcomeV1;
pub(in crate::controller_resource_reservation::create_intake) mod preparation;
pub(in crate::controller_resource_reservation::create_intake) use signed::{OriginalCreateStorageSignedV1, completed_signed_view_v1};
pub(in crate::controller_resource_reservation::create_intake) mod reservation;
pub(crate) use bank_append::{CreateStorageUseBankOriginalsV1, CreateStorageUseBankAppendV1};
pub(in crate::controller_resource_reservation) use receiving::UseReceivingOriginalsV1;
pub(crate) use receiving::CreateStorageUseHistoryReceivingLoanV1;

use super::*;
use super::super::history::{root_validated::RootValidatedOriginalsV1,
    CreateStorageWriterPositionV1};

#[derive(Default)]
pub(in crate::controller_resource_reservation::create_intake) struct CreateStorageUseOriginalsV1 {
    validated: RootValidatedOriginalsV1,
    closed: Option<ResourceReservationErrorV1>,
    pub(super) reservation: reservation::UseReservationOriginalsV1,
    pub(super) reserved: super::super::history::use_reserved::UseReservedOriginalsV1,
    pub(super) signed: super::super::history::signed::SignedOriginalsV1,
    pub(super) dispatch: super::super::history::dispatch::DispatchOriginalsV1,
    preparation: preparation::PreparationOriginalsV1,
    pub(super) session: super::super::history::session::SessionOriginalsV1,
    pub(super) outcome: super::super::history::outcome::OutcomeOriginalsV1,
    commit: commit::UseCommitOriginalsV1,
    pub(super) release: release::ReleaseOriginalsV1,
    pub(super) terminal: Option<Box<cache_terminal::CacheTerminalControlOriginalsV1>>,
    handoff: super::super::history::handoff::HandoffOriginalsV1,
    pub(super) io: super::inventory::InventoryOriginalsV1,
}

impl CreateStorageUseOriginalsV1 {
    pub(in crate::controller_resource_reservation::create_intake) fn started(&self) -> bool {
        self.validated.started()
    }

    pub(in crate::controller_resource_reservation::create_intake) fn position(&self)
        -> Result<CreateStorageWriterPositionV1, ResourceReservationErrorV1>
    {
        if self.closed.is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        if self.handoff.started() { return self.handoff.position(); }
        if self.commit.started() { return self.commit.position(); }
        if self.outcome.started() { return self.outcome.position(); }
        if self.session.started() { return self.session.position(); }
        if self.dispatch.started() { return self.dispatch.position(); }
        if self.signed.started() { return self.signed.position(); }
        if self.reserved.started() { return self.reserved.position(); }
        if self.reservation.started() { return self.reservation.position(); }
        self.validated.position()
    }

    // C10 cannot enter after an earlier Ready refusal. Its retained primary
    // therefore precedes only the independently owed following Root refusal;
    // a positive C10 must not hide a later genuine Root16 failure.
    pub(in crate::controller_resource_reservation::create_intake)
    fn selected_handoff_primary_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if self.handoff.started() && self.handoff.failure().is_some() {
            self.failure()
        } else {
            None
        }
    }

    // These diagnostic borrows preserve the private release owner and its
    // actual selected cause without exposing a mutable stage or constructor.
    pub(in crate::controller_resource_reservation::create_intake)
    fn release_funding_failure_is_selected_v1(&self) -> bool {
        self.release.funding_failure_is_selected_v1()
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn selected_release_primary_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.release.selected_primary_failure_v1()
    }

    pub(in crate::controller_resource_reservation::create_intake) fn failure(&self)
        -> Option<&(dyn std::error::Error + 'static)>
    {
        self.validated.failure().or_else(|| self.reservation.failure())
            .or_else(|| self.reserved.failure()).or_else(|| self.signed.failure())
            .or_else(|| self.dispatch.failure()).or_else(|| self.preparation.failure())
            .or_else(|| self.session.failure()).or_else(|| self.io.failure()).or_else(|| self.outcome.failure()).or_else(|| self.commit.failure()).or_else(|| self.release.failure()).or_else(|| self.handoff.failure()).or_else(|| self.terminal.as_deref().and_then(cache_terminal::CacheTerminalControlOriginalsV1::failure)).or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

impl OriginalCreateStorageReadyV1<'_, '_> {
    /// Appends Controller RootValidated from the same completed Root exchange.
    ///
    /// The original authenticated authorization remains borrowed through the
    /// actual append, full readback and independent native/profile/clock posts.
    /// This records Root validation; it does not reserve or issue U15.
    ///
    /// # Errors
    /// Refuses reentry, incomplete Root/Cache/J association, changed history,
    /// exceeded negotiated cutoff, or any funding/native/readback/post failure.
    /// Every reached original and its first cause remain in the same intake.
    #[doc(hidden)]
    pub fn produce_root_validated_once(&mut self) -> Result<(), CreateStorageReadyClosedV1> {
        if self.failure().is_some() || self.original.owner.storage_use.started() {
            self.original.owner.storage_use.closed.get_or_insert(ResourceReservationErrorV1::Conflict);
            return Err(CreateStorageReadyClosedV1);
        }
        if let Err(cause) = self.original.require_operation_currentness_peak_v1(&self.cache) {
            self.original.owner.storage_use.closed.get_or_insert(cause);
            return Err(CreateStorageReadyClosedV1);
        }
        let owner = &mut *self.original.owner;
        let authorization = match owner.root_exchange.borrow_use_authorization_v1() {
            Ok(authorization) => authorization,
            Err(cause) => {
                owner.storage_use.closed.get_or_insert(cause);
                return Err(CreateStorageReadyClosedV1);
            }
        };
        owner.storage_use.validated.produce_once(&owner.parent, &mut owner.intake,
            &owner.histories, &owner.assignment, &authorization,
            self.original.controller, self.original.source, self.original.profile)
            .map_err(|_| CreateStorageReadyClosedV1)
    }
}

// The Root transport borrows this actual completed native owner. No decoded
// receipt, position, head or resource amount constructs a successful lender.
pub(in crate::controller_resource_reservation::create_intake) struct OriginalCreateStorageUseReservedV1<'held> {
    pub(super) append: &'held crate::controller_resource_reservation::ReturnedAppend,
    pub(super) request_shape_bytes: usize,
    pub(super) record: &'held super::super::history::use_reserved::UseReservedOriginalsV1,
}

impl CreateStorageUseOriginalsV1 {
    pub(in crate::controller_resource_reservation::create_intake) fn borrow_reserved_v1(&self)
        -> Result<OriginalCreateStorageUseReservedV1<'_>, ResourceReservationErrorV1>
    {
        if self.failure().is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        completed_reserved_view_v1(&self.reservation, &self.reserved)
    }
}

// Only genuine completed Native U and the same C5 original can form this view.
pub(in crate::controller_resource_reservation::create_intake)
fn completed_reserved_view_v1<'held>(
    reservation: &'held reservation::UseReservationOriginalsV1,
    record: &'held super::super::history::use_reserved::UseReservedOriginalsV1,
) -> Result<OriginalCreateStorageUseReservedV1<'held>, ResourceReservationErrorV1> {
    reservation.position()?;
    record.position()?;
    Ok(OriginalCreateStorageUseReservedV1 {
        append: reservation.returned_append_v1()?,
        request_shape_bytes: reservation.request_shape_bytes_v1()?, record,
    })
}

impl OriginalCreateStorageUseReservedV1<'_> {
    pub(in crate::controller_resource_reservation::create_intake) fn request_shape_bytes_v1(&self)
        -> Result<usize, ResourceReservationErrorV1> {
        self.append.require_committed()?;
        self.record.position()?;
        Ok(self.request_shape_bytes)
    }

    pub(in crate::controller_resource_reservation::create_intake) fn position_v1(&self)
        -> Result<CreateStorageWriterPositionV1, ResourceReservationErrorV1> { self.record.position() }

    pub(in crate::controller_resource_reservation::create_intake) fn receipt_v1(&self)
        -> Result<aos_sandbox_protocol::domain_ledger::create_storage_history::use_reserved::UseReservedNativeReceiptDataV1<'_>, ResourceReservationErrorV1>
    {
        self.append.require_committed()?;
        self.record.native_receipt_v1()
    }

    pub(in crate::controller_resource_reservation::create_intake) fn completed_clock_v1(&self)
        -> Result<aos_sandbox_model::RawPairedClockSample, ResourceReservationErrorV1>
    {
        self.append.require_committed()?;
        self.record.completed_clock_v1()
    }

    pub(in crate::controller_resource_reservation::create_intake) fn claim_v1(&self)
        -> Result<crate::controller_resource_reservation::bank::Claim, ResourceReservationErrorV1>
    {
        self.record.position()?;
        Ok(self.append.require_committed()?.claim)
    }
}

impl OriginalCreateStorageReadyV1<'_, '_> {
    /// Records the actual returned U reservation on the same Controller lane.
    ///
    /// # Errors
    /// Refuses an incomplete/failed U, reentry, changed original Root turn,
    /// bank/history predecessor, resource admission or native/readback/post.
    #[doc(hidden)]
    pub fn produce_use_reserved_once(&mut self) -> Result<(), CreateStorageReadyClosedV1> {
        if self.failure().is_some() || self.original.owner.storage_use.reserved.started() {
            self.original.owner.storage_use.closed.get_or_insert(ResourceReservationErrorV1::Conflict);
            return Err(CreateStorageReadyClosedV1);
        }
        let owner = &mut *self.original.owner;
        let authorization = match owner.root_exchange.borrow_use_authorization_v1() {
            Ok(value) => value,
            Err(cause) => { owner.storage_use.closed.get_or_insert(cause); return Err(CreateStorageReadyClosedV1); }
        };
        let actual = &mut owner.storage_use;
        actual.reserved.produce_once(&owner.parent, &mut owner.intake, &owner.histories,
            &owner.assignment, &actual.validated, &mut actual.reservation, &authorization,
            self.original.controller, self.original.source, self.original.profile)
            .map_err(|_| CreateStorageReadyClosedV1)
    }
}

// Native Root transport alone borrows this split actual U owner. It retains
// the native reserve and actual UseReserved row while charging only this U.
// Its constructor cannot be reached from parsed receipts or numeric vectors.
pub(in crate::controller_resource_reservation::create_intake) struct OriginalCreateStorageUseRootReceivingV1<'held> {
    reserved: OriginalCreateStorageUseReservedV1<'held>,
    receiving: &'held mut receiving::UseReceivingOriginalsV1,
}

impl CreateStorageUseOriginalsV1 {
    pub(in crate::controller_resource_reservation::create_intake) fn borrow_root_receiving_once_v1(&mut self)
        -> Result<OriginalCreateStorageUseRootReceivingV1<'_>, ResourceReservationErrorV1>
    {
        let (reserved, receiving) = self.split_reserved_receiving_v1()?;
        Ok(OriginalCreateStorageUseRootReceivingV1 { reserved, receiving })
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn split_reserved_receiving_v1(&mut self)
        -> Result<(OriginalCreateStorageUseReservedV1<'_>, &mut receiving::UseReceivingOriginalsV1), ResourceReservationErrorV1>
    {
        if self.failure().is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        self.reserved.position()?;
        self.reservation.position()?;
        let request_shape_bytes = self.reservation.request_shape_bytes_v1()?;
        let (append, receiving) = self.reservation.split_root_receiving_v1()?;
        let reserved = OriginalCreateStorageUseReservedV1 {
            append, request_shape_bytes, record: &self.reserved,
        };
        receiving.require_reserved_v1()?;
        if receiving.claim_data_v1()? != reserved.claim_v1()? {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok((reserved, receiving))
    }

}

impl OriginalCreateStorageUseRootReceivingV1<'_> {
    // Holds the actual positive native row beside its own mutable ledger.
    // The caller can fund before encoding that borrowed receipt and retain
    // the same loan through independently owed posts after later debt.
    pub(in crate::controller_resource_reservation::create_intake) fn split_original_and_receiving_v1(
        &mut self,
    ) -> Result<(&OriginalCreateStorageUseReservedV1<'_>, &mut receiving::UseReceivingOriginalsV1), ResourceReservationErrorV1> {
        self.receiving_mut_v1()?;
        Ok((&self.reserved, &mut *self.receiving))
    }

    // Diagnostics remain available after debt closes receiving_mut_v1. This
    // borrows the actual retained U cause without IO, admission or a new loan.
    pub(in crate::controller_resource_reservation::create_intake) fn failure_v1(&self)
        -> Option<&(dyn std::error::Error + 'static)>
    {
        self.receiving.failure()
    }

    pub(in crate::controller_resource_reservation::create_intake) fn original_v1(&self)
        -> &OriginalCreateStorageUseReservedV1<'_> { &self.reserved }

    pub(in crate::controller_resource_reservation::create_intake) fn receiving_mut_v1(&mut self)
        -> Result<&mut receiving::UseReceivingOriginalsV1, ResourceReservationErrorV1>
    {
        self.reserved.position_v1()?;
        let claim = self.reserved.claim_v1()?;
        self.receiving.require_reserved_v1()?;
        if self.receiving.claim_data_v1()? != claim { return Err(ResourceReservationErrorV1::Conflict); }
        Ok(self.receiving)
    }
}

/// Borrows original comparison inputs for nonissuing normalized request sizing.
///
/// The lease remains on its genuine contacted owner. These fields convey no
/// current policy, signing, dispatch or receiving permission; Root's later
/// admitted plan must be independently checked before actual signing.
#[doc(hidden)]
pub struct CreateStorageUsePlanInputsV1<'held> {
    /// The actual cryptographically verified original lease, without a clone.
    pub lease: &'held aos_sandbox_ownership_protocol::SignedOwnershipLease,
    /// The exact original assignment's effective Policy descriptor digest.
    pub policy_digest: aos_sandbox_model::ObjectDigest,
    /// The original J clock used only by the separate normalized shape.
    pub sizing_clock: aos_sandbox_model::RawPairedClockSample,
    /// The minimum original accepted and actual retained RootHello cutoff.
    pub cutoff: u64,
}

impl OriginalCreateStorageReadyV1<'_, '_> {
    /// Borrows immutable originals for the shared unsigned request shape.
    ///
    /// # Errors
    /// Refuses failed originals, an incomplete RootValidated/Root turn or a
    /// missing actual verified Ownership lease. Performs no allocation or IO.
    #[doc(hidden)]
    pub fn borrow_storage_use_plan_inputs_v1(&self)
        -> Result<CreateStorageUsePlanInputsV1<'_>, CreateStorageReadyClosedV1>
    {
        if self.failure().is_some() { return Err(CreateStorageReadyClosedV1); }
        let owner = &self.original.owner;
        owner.storage_use.validated.position().map_err(|_| CreateStorageReadyClosedV1)?;
        let authorization = owner.root_exchange.borrow_use_authorization_v1()
            .map_err(|_| CreateStorageReadyClosedV1)?;
        let held = self.verified_ownership_v1().map_err(|_| CreateStorageReadyClosedV1)?;
        held.require_original().map_err(|_| CreateStorageReadyClosedV1)?;
        Ok(CreateStorageUsePlanInputsV1 { lease: held.lease(),
            policy_digest: held.manifest().manifest().policy().digest(),
            sizing_clock: owner.intake.create_storage_j_data_v1().map_err(|_| CreateStorageReadyClosedV1)?.clock,
            cutoff: authorization.cutoff_v1().map_err(|_| CreateStorageReadyClosedV1)? })
    }
}

impl OriginalCreateStorageReadyV1<'_, '_> {
    /// Admits the fixed nonissuing local plan construction before its clones.
    ///
    /// The actual original lease lengths and B proposal fix dominant buffers.
    /// The supplied public authority comes from the installed retained signer;
    /// it contains no private key and creates no permission to sign or send.
    ///
    /// # Errors
    /// Refuses reentry, changed completed B/RootValidated/lease, fixed receiving
    /// overflow or unavailable original J acquisition funding.
    #[doc(hidden)]
    pub fn admit_storage_use_plan_once(&mut self, bundle_bytes: &[u8],
        authority: &aos_sandbox_protocol::authorization_artifact::SigningAuthority,
    ) -> Result<(), CreateStorageReadyClosedV1> {
        if self.failure().is_some() || self.original.owner.storage_use.reservation.plan_funding.is_some() {
            self.original.owner.storage_use.closed.get_or_insert(ResourceReservationErrorV1::Conflict);
            return Err(CreateStorageReadyClosedV1);
        }
        let actual = (|| {
            self.original.owner.bundle.require_completed_bytes_v1(bundle_bytes)?;
            self.original.owner.storage_use.validated.position()?;
            let bundle = aos_sandbox_protocol::domain_ledger::create_storage_history::ready::ReadyBundleDataV1::decode(bundle_bytes)
                .map_err(|_| ResourceReservationErrorV1::Conflict)?;
            let held = self.verified_ownership_v1()?;
            held.require_original()?;
            type Models = (aos_sandbox_protocol::authorization_artifact::StorageCreatePlanPreparationDataV1,
                aos_sandbox_protocol::authorization_artifact::SigningAuthority,
                aos_sandbox_protocol::semantics::ProtectedStorageCreatePreparationV1,
                aos_sandbox_model::model::Signature, aos_sandbox_model::BrokerAuthorizationPlan);
            // The distinct dominant lanes are the body plus its protobuf
            // re-encode, canonical plan/statement, signature shape, full request
            // shape and their constructor copies. Policy owns a separate
            // original/decoder/authority/preparation byte peak. Pure parser
            // bookkeeping stays under its existing decoder/cgroup backstops.
            let wire = [bundle.proposed_storage.len(), held.lease().canonical_lease().len(),
                held.lease().canonical_signature().len()]
                .into_iter().try_fold(0_usize, usize::checked_add)
                .and_then(|n| n.checked_add(4096))
                .and_then(|n| n.checked_mul(8)).ok_or(ResourceReservationErrorV1::Conflict)?;
            let policy = usize::try_from(authority.policy_descriptor().encoded_size())
                .ok().and_then(|n| n.checked_mul(4)).ok_or(ResourceReservationErrorV1::Conflict)?;
            let bytes = std::mem::size_of::<Models>().checked_mul(2)
                .and_then(|n| n.checked_add(wire)).and_then(|n| n.checked_add(policy))
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            Ok(aos_sandbox_model::ResourceVector::ZERO.with(aos_sandbox_model::ResourceDimension::MemoryBytes,
                u64::try_from(bytes).map_err(|_| ResourceReservationErrorV1::Conflict)?))
        })();
        let funded = actual.and_then(|demand| self.original.owner.intake.reserve_root_validated_capture_once(demand));
        self.original.owner.storage_use.reservation.plan_funding = Some(funded);
        if matches!(self.original.owner.storage_use.reservation.plan_funding, Some(Ok(()))) {
            Ok(())
        } else {
            Err(CreateStorageReadyClosedV1)
        }
    }
}

impl OriginalCreateStorageReadyV1<'_, '_> {
    /// Borrows the actual native U cause without opening or mutating a loan.
    #[doc(hidden)]
    #[must_use]
    pub fn storage_use_original_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.owner.storage_use.failure()
    }
}

impl CreateStorageUseOriginalsV1 {
    pub(in crate::controller_resource_reservation::create_intake)
    fn borrow_completed_signed_v1(&self) -> Result<OriginalCreateStorageSignedV1<'_>, ResourceReservationErrorV1> {
        if self.failure().is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        completed_signed_view_v1(&self.reservation, &self.reserved, &self.signed)
    }
}

#[cfg(test)]
mod handoff_diagnostic_tests {
    use super::*;

    #[test]
    fn entered_handoff_retains_its_original_cause_before_following_root_refusal() {
        let mut actual = CreateStorageUseOriginalsV1::default();
        actual.handoff.enter_once().unwrap();
        actual.handoff.entry = Some(Err(ResourceReservationErrorV1::BootstrapIo(
            std::io::Error::from_raw_os_error(5))));
        let original = actual.handoff.entry.as_ref().unwrap().as_ref().unwrap_err();

        let returned = actual.selected_handoff_primary_failure_v1().unwrap()
            .downcast_ref::<ResourceReservationErrorV1>().unwrap();

        assert!(std::ptr::eq(returned, original));
        assert!(matches!(returned, ResourceReservationErrorV1::BootstrapIo(error)
            if error.raw_os_error() == Some(5)));
    }

    #[test]
    fn unentered_handoff_does_not_reorder_an_earlier_root_failure() {
        let mut actual = CreateStorageUseOriginalsV1::default();
        actual.closed = Some(ResourceReservationErrorV1::Conflict);

        assert!(actual.failure().is_some());
        assert!(actual.selected_handoff_primary_failure_v1().is_none());
    }
}

impl CreateStorageUseOriginalsV1 {
    pub(in crate::controller_resource_reservation::create_intake)
    fn selected_terminal_control_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.terminal.as_deref().and_then(cache_terminal::CacheTerminalControlOriginalsV1::selected_failure_v1)
    }
}
