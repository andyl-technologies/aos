//! Retains actual signed Destroy9 through the same Runtime flight/post engine.
//!
//! The enclosing effect route stays closed until the genuine Source9 physical
//! dispatcher qualifies. This lexical caller contains no lifecycle fallback.

use super::*;
use super::storage_flight::{ActualFlight, First, FlightState};
use aos_sandbox_broker_session_security::controller_composition::{
    DeleteNetworkApplySessionIoOriginalV4, OutputPreparationClosedV1,
};

#[derive(Default)]
pub(super) struct ControllerDeleteNetworkApplyOriginalV4 {
    sdk: DeleteNetworkApplySessionIoOriginalV4,
    flight: FlightState,
    acknowledgement: Option<Result<(), OutputPreparationClosedV1>>,
    entry_original_selected: bool,
}

impl ControllerDeleteNetworkApplyOriginalV4 {
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
        -> Result<&DeleteNetworkApplySessionIoOriginalV4, ResourceReservationErrorV1> {
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
    // Only the completed genuine Source9 dispatcher join may connect this
    // method to the public continuation. Signed DATA alone cannot open it.
    pub(super) fn apply_network_once_v4<'profile>(&mut self,
        pending: &mut aos_sandbox::ControllerDeletePendingOriginalV2<'_, '_>,
        client: &mut aos_sandbox::ControllerDeletePendingRootClientOriginalV2<'profile>,
        bank: &aos_sandbox::ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &'profile aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let state = &mut self.network_apply;
        if state.flight.started || !matches!(self.network_approval, Some(Ok(()))) {
            state.flight.first.get_or_insert(First::Reentry);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        state.flight.started = true;
        let inputs = (|| {
            let cut = session_preimage_from_originals_v2(&self.fresh_sessions, &self.fresh_models, 3)
                .map_err(|_| ResourceReservationErrorV1::Conflict)?;
            let answer = self.fresh_sessions[3].as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
            let network = self.session_writers.network.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
            let shape = bank.retained_delete_network_request_bound_v4(client)
                .and_then(|bound| network.delete_network_shape_v4(bound))
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
        let Some(network) = self.session_writers.network.as_mut() else {
            state.flight.entry = Some(Err(ResourceReservationErrorV1::Conflict));
            state.flight.first = Some(First::Entry);
            return Err(ResourceReservationErrorV1::Conflict);
        };
        state.entry_original_selected = true;
        let mut loan = match bank.borrow_retained_delete_network_apply_once_v4(
            pending, client, controller, profile, cut, shape) {
            Ok(loan) => { state.flight.entry = Some(Ok(())); loan }
            Err(cause) => {
                state.flight.entry = Some(Err(cause));
                state.flight.first = Some(First::Entry);
                return Err(ResourceReservationErrorV1::Conflict);
            }
        };
        let mut flight = NetworkFlight { network, sdk: &mut state.sdk, loan: &mut loan, answer };
        state.flight.run_once(&mut flight);
        drop(flight);
        drop(loan);
        if state.flight.first.is_none() {
            state.acknowledgement = Some(state.sdk.completed_apply_response_data_v4().map(|_| ()));
            if !matches!(state.acknowledgement, Some(Ok(()))) {
                state.flight.first = Some(First::Acknowledgement);
            }
        }
        state.completed_sdk_v4()?;
        self.confirm_host_after_network_once_v4(pending, client, bank, controller, profile)
    }
}

struct NetworkFlight<'borrow, 'held> {
    network: &'borrow mut crate::DormantNetworkLifecycleInventoryOwnerV1,
    sdk: &'borrow mut DeleteNetworkApplySessionIoOriginalV4,
    loan: &'borrow mut aos_sandbox::OriginalDeleteNetworkApplyLoanV4<'held>,
    answer: &'borrow DeleteInventoryAnswerOriginalsV1,
}

impl ActualFlight for NetworkFlight<'_, '_> {
    fn run(&mut self) -> Result<(), OutputPreparationClosedV1> {
        self.network.run_delete_network_apply_once_v4(self.sdk, self.loan, self.answer)
    }

    fn refuse_sdk(&mut self) { self.loan.refuse_sdk_primary_v3(); }

    fn after(&mut self) -> Result<(), ResourceReservationErrorV1> {
        self.loan.finish_after_sdk_once_v3()
    }

    fn retire(&mut self) -> Result<(), OutputPreparationClosedV1> {
        self.network.retire_delete_network_apply_window_once_v4(self.sdk, self.loan)
    }

    fn complete(&mut self) -> Result<(), ResourceReservationErrorV1> {
        self.loan.complete_network_once_v4()
    }
}
