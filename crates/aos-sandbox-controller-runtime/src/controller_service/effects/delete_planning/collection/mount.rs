//! Signs distinct Reap62 while retaining actual post9 Host and Mount Sessions.

use super::*;
use super::storage_flight::{ActualFlight, First, FlightState};
use aos_sandbox_broker_session_security::controller_composition::{
    DeleteMountReapSessionIoOriginalV4, OutputPreparationClosedV1,
};

#[derive(Default)]
pub(super) struct ControllerDeleteMountReapOriginalV4 {
    sdk: DeleteMountReapSessionIoOriginalV4,
    flight: FlightState,
    acknowledgement: Option<Result<(), OutputPreparationClosedV1>>,
    entry_original_selected: bool,
}

impl ControllerDeleteMountReapOriginalV4 {
    pub(super) fn failed(&self) -> bool { self.flight.first.is_some() }

    pub(super) fn original_selected(&self) -> bool {
        if matches!(self.flight.first, Some(First::Entry)) {
            return self.entry_original_selected;
        }
        self.flight.original_selected(self.sdk.original_failure_selected_v4())
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.flight.first? {
            First::Sdk | First::Retirement => self.sdk.failure_v4(),
            First::Acknowledgement => self.acknowledgement.as_ref()?.as_ref().err().map(|cause| cause as _),
            _ => self.flight.failure(),
        }
    }

    pub(super) fn completed_sdk_v4(&self)
        -> Result<&DeleteMountReapSessionIoOriginalV4, ResourceReservationErrorV1> {
        if self.flight.first.is_some() || !matches!(self.flight.complete, Some(Ok(())))
            || !matches!(self.flight.retirement, Some(Ok(())))
            || !matches!(self.acknowledgement, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.sdk.require_completed_v4().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        Ok(&self.sdk)
    }
}

impl ControllerDeletePlanningCollectionV2<'_, '_, '_> {
    pub(super) fn reap_mount_once_v4(
        &mut self,
        pending: &mut aos_sandbox::ControllerDeletePendingOriginalV2<'_, '_>,
        client: &mut aos_sandbox::ControllerDeletePendingRootClientOriginalV2<'_>,
        bank: &aos_sandbox::ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let state = &mut self.mount_reap;
        if state.flight.started || !matches!(self.mount_approval, Some(Ok(()))) {
            state.flight.first.get_or_insert(First::Reentry);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        state.flight.started = true;
        let inputs = (|| {
            self.host_confirmation.completed_current_answer_v4()?;
            self.network_apply.completed_sdk_v4()?;
            let cut = session_preimage_from_originals_v2(&self.fresh_sessions, &self.fresh_models, 1)
                .map_err(|_| ResourceReservationErrorV1::Conflict)?;
            let answer = self.fresh_sessions[1].as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
            let mount = self.session_writers.mount.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
            let shape = bank.retained_delete_mount_request_bound_v4(client)
                .and_then(|bound| mount.delete_mount_reap_shape_v4(bound))
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            Ok::<_, ResourceReservationErrorV1>((cut, answer, shape))
        })();
        let (cut, answer, shape) = match inputs {
            Ok(inputs) => inputs,
            Err(cause) => {
                state.flight.entry = Some(Err(cause));
                state.flight.first = Some(First::Entry);
                return Err(ResourceReservationErrorV1::Conflict);
            }
        };
        let Some(mount) = self.session_writers.mount.as_mut() else {
            state.flight.entry = Some(Err(ResourceReservationErrorV1::Conflict));
            state.flight.first = Some(First::Entry);
            return Err(ResourceReservationErrorV1::Conflict);
        };
        state.entry_original_selected = true;
        let mut loan = match bank.borrow_retained_delete_mount_reap_once_v4(
            pending, client, controller, profile, cut, shape) {
            Ok(loan) => { state.flight.entry = Some(Ok(())); loan }
            Err(cause) => {
                state.flight.entry = Some(Err(cause));
                state.flight.first = Some(First::Entry);
                return Err(ResourceReservationErrorV1::Conflict);
            }
        };
        let mut flight = MountFlight { mount, sdk: &mut state.sdk, loan: &mut loan, answer };
        state.flight.run_once(&mut flight);
        drop(flight);
        drop(loan);
        if state.flight.first.is_none() {
            state.acknowledgement = Some(state.sdk.completed_reap_response_data_v4().map(|_| ()));
            if !matches!(state.acknowledgement, Some(Ok(()))) {
                state.flight.first = Some(First::Acknowledgement);
            }
        }
        state.completed_sdk_v4().map(|_| ())
    }

    pub(super) fn prepare_mount_resources_once_v4(
        &mut self,
        pending: &mut aos_sandbox::ControllerDeletePendingOriginalV2<'_, '_>,
        client: &mut aos_sandbox::ControllerDeletePendingRootClientOriginalV2<'_>,
        bank: &aos_sandbox::ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
        local: &ControllerDeleteLocalRuntimeFieldsV1<'_>,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.mount_resource_exchange.is_some() || self.mount_approval.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.mount_resource_exchange = Some((|| {
            self.network_apply.completed_sdk_v4()?;
            let host = self.host_confirmation.completed_current_answer_v4()?;
            let native = host
                .native_position_data_v4()
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            bank.exchange_retained_delete_mount_resource_draft_once_v4(
                pending,
                client,
                controller,
                profile,
                (native, host.outcome_v1()),
            )
        })());
        if !matches!(self.mount_resource_exchange, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let session =
            session_preimage_from_originals_v2(&self.fresh_sessions, &self.fresh_models, 1)
                .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let model = self.fresh_models[1]
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        self.mount_resource_signing.sign_mount_once_v4(
            bank, pending, client, controller, profile, local, model, session,
        )?;
        self.mount_approval =
            Some(bank.receive_retained_delete_mount_approval_once_v4(
                pending, client, controller, profile,
            ));
        if matches!(self.mount_approval, Some(Ok(()))) {
            Ok(())
        } else {
            Err(ResourceReservationErrorV1::Conflict)
        }
    }
}

struct MountFlight<'borrow, 'held> {
    mount: &'borrow mut crate::DormantMountLifecycleInventoryOwnerV1,
    sdk: &'borrow mut DeleteMountReapSessionIoOriginalV4,
    loan: &'borrow mut aos_sandbox::OriginalDeleteMountReapLoanV4<'held>,
    answer: &'borrow DeleteInventoryAnswerOriginalsV1,
}

impl ActualFlight for MountFlight<'_, '_> {
    fn run(&mut self) -> Result<(), OutputPreparationClosedV1> {
        self.mount.run_delete_mount_reap_once_v4(self.sdk, self.loan, self.answer)
    }

    fn refuse_sdk(&mut self) { self.loan.refuse_sdk_primary_v3(); }

    fn after(&mut self) -> Result<(), ResourceReservationErrorV1> {
        self.loan.finish_after_sdk_once_v3()
    }

    fn retire(&mut self) -> Result<(), OutputPreparationClosedV1> {
        self.mount.retire_delete_mount_reap_window_once_v4(self.sdk, self.loan)
    }

    fn complete(&mut self) -> Result<(), ResourceReservationErrorV1> {
        self.loan.complete_mount_once_v4()
    }
}
