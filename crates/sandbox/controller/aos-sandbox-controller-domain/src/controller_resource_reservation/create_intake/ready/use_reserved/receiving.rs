//! Charges later Create work only against its actual returned U reservation.
//!
//! The numeric Core ledger is inert by itself. This private carrier can be
//! initialized only by borrowing the actual successful typed ReturnedAppend;
//! decoded bank bytes or a proposed Root vector cannot construct it.

use aos_sandbox_model::ResourceVector;
use aos_sandbox_broker::controller_receiving::bank_launch::{
    ControllerCreateStorageUseReceivingOriginalV1 as NativeUse,
    ControllerCreateStorageUseFundingLoanV1,
};
use crate::controller_resource_reservation::{ReturnedAppend, Claim, ClaimPurpose,
    ClaimState, ResourceReservationErrorV1};
use crate::{Journal, normal_root::ProductionControllerNormalRootProfileV1};
use crate::controller_resource_reservation::q04_intake::Q04OriginalIntakeAttemptV1;

pub(in crate::controller_resource_reservation) struct UseReceivingOriginalsV1 {
    native: NativeUse,
}

impl UseReceivingOriginalsV1 {
    // Upper typed append/readback/posts remain necessary before the actual
    // native writer can consume its private publication's one-shot origin.
    pub(super) fn from_returned_reserve_v1(
        actual: &ReturnedAppend,
        controller: &mut Journal,
        intake: &mut Q04OriginalIntakeAttemptV1,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<Self, ResourceReservationErrorV1> {
        let original = actual.require_committed()?;
        if original.claim.native_fields().purpose != ClaimPurpose::CreateStorageUse
            || original.claim.native_fields().state != ClaimState::Reserved
            || original.previous_claim.is_some() || original.child.is_some()
            || original.preparation.is_some() || original.terminal.is_some()
            || original.create_storage_use.is_none() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let binding = original.create_storage_use.ok_or(ResourceReservationErrorV1::Conflict)?;
        let native = intake.begin_returned_storage_use_receiving_v1(controller, profile, binding)?;
        if native.claim_data_v1().map_err(|_| ResourceReservationErrorV1::Conflict)? != original.claim {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(Self { native })
    }

    pub(in crate::controller_resource_reservation) fn reserve_once(&mut self, demand: ResourceVector)
        -> Result<(), ResourceReservationErrorV1> {
        self.native.reserve_additional_v1(demand).map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation) fn require_reserved_v1(&self)
        -> Result<(), ResourceReservationErrorV1> {
        self.native.require_reserved_v1().map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake) fn claim_data_v1(&self)
        -> Result<Claim, ResourceReservationErrorV1> {
        self.native.claim_data_v1().map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake) fn charged_v1(&self) -> ResourceVector {
        self.native.charged_v1()
    }

    pub(in crate::controller_resource_reservation::create_intake) fn failure(&self)
        -> Option<&(dyn std::error::Error + 'static)> { self.native.failure_v1() }

    pub(in crate::controller_resource_reservation) fn borrow_cache_funding_v1<'funding, 'profile>(
        &'funding mut self, profile: &'profile ProductionControllerNormalRootProfileV1,
    ) -> Result<ControllerCreateStorageUseFundingLoanV1<'funding, 'profile>, ResourceReservationErrorV1> {
        self.native.borrow_cache_funding_v1(profile.lower_original_v1())
            .map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation) fn prepare_observer_growth_v1<'funding, 'profile>(
        &'funding mut self,
        profile: &'profile ProductionControllerNormalRootProfileV1,
        lifetime: &aos_sandbox_broker::receiving::ObservationLifetimeV1,
        previous: usize,
        additional: usize,
    ) -> Result<aos_sandbox_broker::controller_receiving::profile::
        ControllerCreateIntakeObserverGrowthLoanV1<'funding, 'profile>, ResourceReservationErrorV1> {
        profile.lower_original_v1().prepare_create_intake_growth_from_storage_use_v1(
            &mut self.native, lifetime, previous, additional,
        ).map_err(Into::into)
    }

}

/// Borrows only the actual returned U for one native bank-history readback.
pub(crate) struct CreateStorageUseHistoryReceivingLoanV1<'turn> {
    original: &'turn mut UseReceivingOriginalsV1,
    parent: &'turn crate::controller_resource_reservation::ProjectPreparationReservationAttemptV1,
    intake: &'turn crate::controller_resource_reservation::q04_intake::Q04OriginalIntakeAttemptV1,
    authorization: &'turn super::super::root_exchange::OriginalCreateStorageRootUseAuthorizationV1<'turn>,
    entered: bool,
}

impl UseReceivingOriginalsV1 {
    pub(super) fn borrow_native_history_once<'turn>(
        &'turn mut self,
        parent: &'turn crate::controller_resource_reservation::ProjectPreparationReservationAttemptV1,
        intake: &'turn crate::controller_resource_reservation::q04_intake::Q04OriginalIntakeAttemptV1,
        authorization: &'turn super::super::root_exchange::OriginalCreateStorageRootUseAuthorizationV1<'turn>,
    ) -> Result<CreateStorageUseHistoryReceivingLoanV1<'turn>, ResourceReservationErrorV1> {
        self.require_reserved_v1()?;
        intake.require_retained_capture()?;
        if authorization.body_v1()?.receiving != self.claim_data_v1()?.native_fields().amount
            || authorization.body_v1()?.association.operation
                != parent.create_storage_original_identity_v1()?.operation {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(CreateStorageUseHistoryReceivingLoanV1 {
            original: self, parent, intake, authorization, entered: false,
        })
    }
}

impl CreateStorageUseHistoryReceivingLoanV1<'_> {
    pub(crate) fn admit_actual_history_once(
        &mut self,
        state: &std::collections::BTreeMap<(crate::RecordNamespace, Vec<u8>), Vec<u8>>,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.entered { return Err(ResourceReservationErrorV1::Conflict); }
        self.entered = true;
        self.intake.require_retained_capture()?;
        if self.authorization.body_v1()?.association.operation
            != self.parent.create_storage_original_identity_v1()?.operation {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let demand = aos_sandbox_protocol::domain_ledger::resource_bank::PhysicalHistory::
            additional_use_receiving_demand_v1(state)?;
        self.original.reserve_once(demand)
    }
}

impl Drop for CreateStorageUseHistoryReceivingLoanV1<'_> {
    fn drop(&mut self) {
        if !self.entered && self.original.failure().is_none() {
            self.original.native.retain_refusal_v1();
        }
    }
}

impl From<aos_sandbox_broker::controller_receiving::profile::
    ControllerCreateIntakeObserverGrowthPreparationErrorV1> for ResourceReservationErrorV1 {
    fn from(cause: aos_sandbox_broker::controller_receiving::profile::
        ControllerCreateIntakeObserverGrowthPreparationErrorV1) -> Self {
        use aos_sandbox_broker::controller_receiving::profile::
            ControllerCreateIntakeObserverGrowthPreparationErrorV1 as Cause;
        match cause {
            Cause::Geometry(cause) => Self::BootstrapProfile(cause.into()),
            Cause::Arithmetic | Cause::Funding => Self::Conflict,
        }
    }
}
