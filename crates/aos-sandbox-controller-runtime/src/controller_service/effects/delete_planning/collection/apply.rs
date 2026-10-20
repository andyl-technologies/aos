//! Continues actual completed26 into Root's distinct signed7 exchange.
//!
//! The same exclusive Storage Session and all earlier native originals remain
//! resident. Destructive7 is sequenced only by the enclosing cleanup pipeline.

use super::*;
use super::storage_flight::{ActualFlight, First, FlightState};
use aos_sandbox_broker_session_security::controller_composition::{
    DeleteStorageApplySessionIoOriginalV3, DeleteStoragePreparationSessionIoOriginalV3,
    OutputPreparationClosedV1,
};

#[derive(Default)]
pub(super) struct ControllerDeleteStorageApplyOriginalV3 {
    sdk: DeleteStorageApplySessionIoOriginalV3,
    flight: FlightState,
    acknowledgement: Option<Result<(), OutputPreparationClosedV1>>,
}

impl ControllerDeleteStorageApplyOriginalV3 {
    pub(super) fn completed_sdk_v4(&self)
        -> Result<&DeleteStorageApplySessionIoOriginalV3, ResourceReservationErrorV1> {
        if self.flight.first.is_some() || !matches!(self.flight.complete, Some(Ok(())))
            || !matches!(self.flight.retirement, Some(Ok(())))
            || !matches!(self.acknowledgement, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.sdk.require_completed_v3().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        self.sdk.completed_apply_response_data_v3().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        Ok(&self.sdk)
    }

    pub(super) fn failed(&self) -> bool { self.flight.first.is_some() }

    pub(super) fn original_selected(&self) -> bool {
        self.flight.original_selected(self.sdk.original_failure_selected_v3())
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.flight.first? {
            First::Sdk | First::Retirement => self.sdk.failure_v3(),
            First::Acknowledgement => self.acknowledgement.as_ref()?.as_ref().err().map(|cause| cause as _),
            _ => self.flight.failure(),
        }
    }
}

impl ControllerDeletePlanningCollectionV2<'_, '_, '_> {
    pub(super) fn prepare_storage_apply_resources_once_v3(&mut self,
        pending: &mut aos_sandbox::ControllerDeletePendingOriginalV2<'_, '_>,
        client: &mut aos_sandbox::ControllerDeletePendingRootClientOriginalV2<'_>,
        bank: &aos_sandbox::ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
        local: &ControllerDeleteLocalRuntimeFieldsV1<'_>,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.apply_resource_exchange.is_some() || self.apply_approval.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.apply_resource_exchange = Some((|| {
            let predecessor = self.storage_preparation.sdk_v3()?;
            let (outcome, _) = predecessor.require_completed_v3()
                .map_err(|_| ResourceReservationErrorV1::Conflict)?;
            let response = predecessor.completed_preparation_response_data_v3()
                .map_err(|_| ResourceReservationErrorV1::Conflict)?;
            bank.exchange_retained_delete_apply_resource_draft_once_v3(pending,
                client, controller, profile, outcome, response)
        })());
        if !matches!(self.apply_resource_exchange, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        // These are the same retained Inventory/model originals used by26.
        // The actual current352/catalog and accepted Controller are rejoined
        // inside the genuine Bank signer; no fresh answer is manufactured.
        let session = session_preimage_from_originals_v2(&self.fresh_sessions, &self.fresh_models, 2)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let model = self.fresh_models[2].as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        self.apply_resource_signing.sign_apply_once_v3(bank, pending, client,
            controller, profile, local, model, session)?;
        self.apply_approval = Some(bank.receive_retained_delete_apply_approval_once_v3(
            pending, client, controller, profile));
        if matches!(self.apply_approval, Some(Ok(()))) { Ok(()) }
        else { Err(ResourceReservationErrorV1::Conflict) }
    }

    // The enclosing cleanup pipeline supplies the only call after genuine9 and
    // Mount reap acknowledgements; this component does not yet dispatch it.
    pub(super) fn apply_storage_once_v3(&mut self,
        pending: &mut aos_sandbox::ControllerDeletePendingOriginalV2<'_, '_>,
        client: &mut aos_sandbox::ControllerDeletePendingRootClientOriginalV2<'_>,
        bank: &aos_sandbox::ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let state = &mut self.storage_apply;
        if state.flight.started || !matches!(self.apply_approval, Some(Ok(())))
            || self.mount_reap.completed_sdk_v4().is_err() {
            state.flight.first.get_or_insert(First::Reentry);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        state.flight.started = true;
        let predecessor = self.storage_preparation.sdk_v3()?;
        let storage = self.session_writers.storage.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?;
        let shape = bank.retained_delete_apply_request_bound_v3(client)
            .and_then(|bound| storage.delete_apply_shape_v3(bound)).ok_or(ResourceReservationErrorV1::Conflict)?;
        let mut loan = match bank.borrow_retained_delete_storage_apply_once_v3(
            pending, client, controller, profile, shape) {
            Ok(loan) => { state.flight.entry = Some(Ok(())); loan }
            Err(cause) => {
                state.flight.entry = Some(Err(cause)); state.flight.first = Some(First::Entry);
                return Err(ResourceReservationErrorV1::Conflict);
            }
        };
        let mut flight = ApplyFlight { storage, sdk: &mut state.sdk, loan: &mut loan, predecessor };
        state.flight.run_once(&mut flight);
        drop(flight);
        drop(loan);
        if state.flight.first.is_none() {
            // Use the same successful decoder, without rebuilding a Storage
            // result or treating native transport completion as destruction.
            state.acknowledgement = Some(state.sdk.completed_apply_response_data_v3().map(|_| ()));
            if !matches!(state.acknowledgement, Some(Ok(()))) {
                state.flight.first = Some(First::Acknowledgement);
            }
        }
        if state.flight.first.is_none() { Ok(()) }
        else { Err(ResourceReservationErrorV1::Conflict) }
    }
}

struct ApplyFlight<'borrow, 'held> {
    storage: &'borrow mut crate::DormantStorageLifecycleInventoryOwnerV1,
    sdk: &'borrow mut DeleteStorageApplySessionIoOriginalV3,
    loan: &'borrow mut aos_sandbox::OriginalDeleteStorageApplyLoanV3<'held>,
    predecessor: &'borrow DeleteStoragePreparationSessionIoOriginalV3,
}

impl ActualFlight for ApplyFlight<'_, '_> {
    fn run(&mut self) -> Result<(), OutputPreparationClosedV1> {
        self.storage.run_delete_storage_apply_once_v3(self.sdk, self.loan, self.predecessor)
    }

    fn refuse_sdk(&mut self) { self.loan.refuse_sdk_primary_v3(); }

    fn after(&mut self) -> Result<(), ResourceReservationErrorV1> {
        self.loan.finish_after_sdk_once_v3()
    }

    fn retire(&mut self) -> Result<(), OutputPreparationClosedV1> {
        self.storage.retire_delete_storage_apply_window_once_v3(self.sdk, self.loan)
    }

    fn complete(&mut self) -> Result<(), ResourceReservationErrorV1> {
        self.loan.complete_apply_once_v3()
    }
}
