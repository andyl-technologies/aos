//! Retains a new Host3 answer after genuine Network9 on the same Delete turn.
//!
//! This separate destination preserves all four older planning/preaccept cuts.
//! Root62 consumes this completed native answer; those older answers cannot
//! stand in for the fresh post-Network census and authenticated terminal.

use super::*;

#[derive(Default)]
pub(super) struct ControllerDeleteHostConfirmationOriginalV4 {
    started: bool,
    entry: Option<Result<(), ResourceReservationErrorV1>>,
    answer: Option<DeleteInventoryAnswerOriginalsV1>,
    current_send: Option<Result<(), ResourceReservationErrorV1>>,
}

impl ControllerDeleteHostConfirmationOriginalV4 {
    pub(super) fn failed_v4(&self) -> bool {
        matches!(self.entry, Some(Err(_))) || matches!(self.current_send, Some(Err(_)))
    }

    pub(super) fn failure_v4(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.entry
            .as_ref()
            .and_then(|value| value.as_ref().err())
            .or_else(|| self.current_send.as_ref()?.as_ref().err())
            .map(|cause| cause as _)
    }

    pub(super) fn completed_current_answer_v4(
        &self,
    ) -> Result<&DeleteInventoryAnswerOriginalsV1, ResourceReservationErrorV1> {
        if !matches!(self.current_send, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.completed_answer_v4()
    }

    pub(super) fn completed_answer_v4(
        &self,
    ) -> Result<&DeleteInventoryAnswerOriginalsV1, ResourceReservationErrorV1> {
        if !matches!(self.entry, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let answer = self
            .answer
            .as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        answer
            .native_position_data_v4()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        Ok(answer)
    }
}

impl ControllerDeletePlanningCollectionV2<'_, '_, '_> {
    pub(super) fn confirm_host_after_network_once_v4<'profile>(
        &mut self,
        pending: &mut aos_sandbox_controller_domain::ControllerDeletePendingOriginalV2<'_, '_>,
        client: &mut aos_sandbox_controller_domain::ControllerDeletePendingRootClientOriginalV2<'profile>,
        bank: &aos_sandbox_controller_domain::ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &'profile aos_sandbox_controller_domain::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let state = &mut self.host_confirmation;
        if state.started {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        state.started = true;
        let query = (|| {
            let network = self.network_apply.completed_sdk_v4()?;
            self.session_writers
                .host
                .as_mut()
                .ok_or(ResourceReservationErrorV1::Conflict)?
                .query_delete_host_confirmation_once_v4(
                    pending, client, bank, controller, profile, network,
                )
        })();
        // The destination is populated before any upper admission can fail.
        state.entry = Some(match query {
            Ok(answer) => {
                state.answer = Some(answer);
                Ok(())
            }
            Err(cause) => Err(cause),
        });
        let answer = state.completed_answer_v4()?;
        let sdk = self.network_apply.completed_sdk_v4()?;
        let (outcome, native) = sdk
            .require_completed_v4()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let host_native = answer
            .native_position_data_v4()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        state.current_send = Some(bank.send_delete_cleanup_current_once_v4(
            pending,
            client,
            controller,
            profile,
            (native, outcome),
            (host_native, answer.outcome_v1()),
        ));
        if matches!(state.current_send, Some(Ok(()))) {
            Ok(())
        } else {
            Err(ResourceReservationErrorV1::Conflict)
        }
    }
}
