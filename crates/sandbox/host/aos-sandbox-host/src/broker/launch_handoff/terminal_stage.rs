//! Disposes a positively completed execution Stage before Stop or next method58.
//!
//! The earlier native terminal constructor, real Storage Complete and every
//! independent post remain continuously owned here. A fresh verified Stop
//! selects this frontier; it grants no Capture public result or Delete proof.
//! Ambiguous or aliased originals stay on the same resident Launch.

use std::sync::Arc;
use aos_sandbox_model::BrokerVerb;
use aos_sandbox_broker::VerifiedBrokerAdmission;
use crate::plan::{HostCatalog, HostExecutionRequestBindingV2};
use crate::state::HostStateStore;
use crate::worker::HostWorker;
use crate::{HostError, Result};
use super::super::argument_handoff::ArgumentStageOriginalV2;
use super::super::HostBroker;
use super::HostLaunchOriginalV2;

/// Borrows genuine positive native owners before their physical disposition.
pub(crate) struct HostTerminalStagePositiveV3<'original> {
    _stage: &'original ArgumentStageOriginalV2,
    launch: HostExecutionRequestBindingV2,
    accept: HostExecutionRequestBindingV2,
    observe: HostExecutionRequestBindingV2,
}

impl HostTerminalStagePositiveV3<'_> {
    pub(crate) fn retained_availability_binding_v2(&self) -> Option<HostExecutionRequestBindingV2> {
        self._stage.retained_availability_binding_v2()
    }

    pub(crate) fn retained_availability_observation_rounds_v2(&self)
        -> impl Iterator<Item = usize> + '_ {
        self._stage.retained_availability_observation_rounds_v2()
    }

    pub(crate) fn original_bindings_v3(&self) -> (HostExecutionRequestBindingV2,
        HostExecutionRequestBindingV2, HostExecutionRequestBindingV2) {
        (self.launch, self.accept, self.observe)
    }
}

impl<C: HostCatalog, S: HostStateStore, W: HostWorker> HostBroker<C, S, W> {
    pub(in crate::broker) fn dispose_terminal_stage_before_stop_v3(
        &mut self,
        launch: &Arc<std::sync::Mutex<HostLaunchOriginalV2>>,
        admitted: &VerifiedBrokerAdmission,
    ) -> Result<()> {
        if admitted.effect.verb() != BrokerVerb::HostStop {
            return Err(refused());
        }
        self.dispose_terminal_stage_v5(launch, TerminalDisposalAuthorizerV5::Stop(admitted))
    }

    pub(in crate::broker) fn dispose_terminal_stage_before_next_execution_v5(
        &mut self,
        launch: &Arc<std::sync::Mutex<HostLaunchOriginalV2>>,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    ) -> Result<()> {
        self.dispose_terminal_stage_v5(launch, TerminalDisposalAuthorizerV5::NextExecution(request))
    }

    fn dispose_terminal_stage_v5(
        &mut self,
        launch: &Arc<std::sync::Mutex<HostLaunchOriginalV2>>,
        authorizer: TerminalDisposalAuthorizerV5<'_>,
    ) -> Result<()> {
        let mut held = launch.lock().map_err(|_| refused())?;
        let assignment = held.lease.as_ref().ok_or_else(refused)?.lease().assignment();
        match authorizer {
            TerminalDisposalAuthorizerV5::Stop(admitted) => {
                if held.next_execution.is_some()
                    || admitted.verified_lease.lease().assignment() != assignment
                { return Err(refused()); }
            }
            TerminalDisposalAuthorizerV5::NextExecution(request) => {
                let transition = held.next_execution.as_ref().ok_or_else(refused)?;
                transition.require_request_v5(request)?;
                let reservation = transition.reservation_v5()?;
                if reservation.verified_lease.lease().assignment() != assignment
                    || reservation.effect.verb() != BrokerVerb::HostPrepareExecutionArgumentV2
                    || reservation.session_binding != request.session_binding()
                    || reservation.signed_request_digest != request.signed_request_digest()
                { return Err(refused()); }
            }
        }
        let Some(resident) = held.capture.as_ref() else { return Ok(()); };
        if !held.authenticated_sent || held.first.is_some()
            || resident.monitor_failed_data_v5()
            || self.argument_stages.iter().any(Option::is_some)
            || self.active_argument_writes.is_some() || self.active_launch_writes.is_some()
        { return Err(refused()); }
        let stage = resident.stage_for_terminal_disposal_v3();
        let original = stage.lock().map_err(|_| refused())?;
        original.require_terminal_storage_disposal_v3()?;
        // try_unwrap below is the actual atomic uniqueness proof. This check
        // avoids retiring a manager interval when a known alias is still live.
        if Arc::strong_count(stage) != 1 { return Err(refused()); }
        let launch_binding = HostExecutionRequestBindingV2 {
            id: held.request.0, session: held.request.1, signed: held.request.2,
        };
        let (accept, observe) = resident.terminal_bindings_v3()?;
        let posts = HostTerminalStagePositiveV3 { _stage: &original,
            launch: launch_binding, accept, observe };
        let mut component = self.component_control.as_ref().ok_or_else(refused)?
            .lock().map_err(|_| refused())?;
        let disposal = component.prepare_terminal_stage_disposal_v3(&posts)?;
        drop(original);
        let Some(resident) = held.capture.take() else { std::process::abort(); };
        match resident.dispose_unique_terminal_stage_v3() {
            Ok(()) => {
                disposal.complete_after_disposal_v3();
                Ok(())
            }
            Err(resident) => {
                resident.retain_monitor_unknown_v5();
                held.capture = Some(resident);
                // The same component disposal token closes on Drop; no native
                // owner or financial operation is released on alias ambiguity.
                Err(refused())
            }
        }
    }
}

enum TerminalDisposalAuthorizerV5<'request> {
    Stop(&'request VerifiedBrokerAdmission),
    NextExecution(&'request aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1),
}

fn refused() -> HostError {
    HostError::Fence("terminal Stage cannot physically dispose before Stop")
}
