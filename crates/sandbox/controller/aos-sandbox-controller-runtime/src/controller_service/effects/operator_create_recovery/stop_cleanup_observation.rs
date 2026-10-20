//! Collects actual passive Host3 before the kind-2 Recover financial handoff.
//!
//! A successful query is copied only into the original's fixed comparison
//! receipt. Every successful SDK, Session and cold native owner then physically
//! drops before the enclosing Source/C posts. A failed graph stays resident;
//! neither this observation nor completed Recover grants a later Host effect.

use super::*;
use aos_sandbox_broker_session_security::{
    OperatorStopCleanupInventoryOriginalV1, OperatorStopCleanupSessionOpenV1,
};

#[derive(Default)]
pub(super) struct StopCleanupObservationRuntimeOriginalV1 {
    entered: bool,
    image: Option<Result<Pid1LaunchImageV1, Closed>>,
    cold: Option<Box<OperatorStopCleanupSessionOpenV1>>,
    opened: Option<Result<(), BrokerSessionSecurityError>>,
    session: Option<Box<DormantAuthenticatedBrokerSessionV1>>,
    inventory: Option<Box<OperatorStopCleanupInventoryOriginalV1>>,
    inventoried: Option<Result<(), InventoryClosed>>,
    bound: Option<Result<(), InventoryClosed>>,
    body: Option<Result<(), Closed>>,
}

impl StopCleanupObservationRuntimeOriginalV1 {
    pub(in crate::controller_service) fn inactive_receiving_bytes_v1() -> Option<usize> {
        use crate::controller_service::effects::resident_geometry::{boxed_bytes, sum_bytes};
        sum_bytes([
            boxed_bytes::<OperatorStopCleanupSessionOpenV1>(),
            boxed_bytes::<OperatorStopCleanupInventoryOriginalV1>(),
            boxed_bytes::<DormantAuthenticatedBrokerSessionV1>(),
        ])
    }

    fn selected_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.image.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.cold.as_ref().and_then(|cold| cold.failure_v1()))
            .or_else(|| self.opened.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.inventory.as_ref().zip(self.session.as_ref())
                .and_then(|(inventory, session)| inventory.failure_v2(session)))
            .or_else(|| self.inventoried.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.bound.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.body.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
    }

    fn drop_completed_prefix(&mut self) -> Result<(), Closed> {
        if !matches!(self.opened, Some(Ok(())))
            || !matches!(self.inventoried, Some(Ok(())))
            || !matches!(self.bound, Some(Ok(())))
            || !matches!(self.body, Some(Ok(())))
            || self.selected_failure().is_some()
        {
            return Err(Closed);
        }
        // All fallible native/SDK/query posts completed. The actual final
        // Session retention identity and the cold receiving original remain
        // held until these real native graph owners have physically dropped.
        drop(self.inventory.take());
        drop(self.session.take());
        drop(self.cold.take());
        drop(self.image.take());
        Ok(())
    }
}

impl ProductionEffectExecutor {
    pub(super) fn observe_stop_cleanup_passive_once_v1(
        &mut self,
        controller: &mut Journal,
        original: &mut OperatorCreateRecoveryOriginalV1,
    ) -> Result<(), Closed> {
        let state = &mut self.operator_recover.stop_cleanup;
        if state.entered { return Err(Closed); }
        state.entered = true;

        state.body = Some((|| {
            original.observe_stop_cleanup_source_once_v1(controller, &mut self.source_domains)
                .map_err(|_| Closed)?;
            let mut loan = original.borrow_stop_cleanup_observation_v1(controller, &self.source_domains)
                .map_err(|_| Closed)?;
            state.image = Some((|| {
                let sessions = self.sessions.lock().map_err(|_| Closed)?;
                sessions.launch_image.clone().ok_or(Closed)
            })());
            let image = state.image.as_ref().and_then(|value| value.as_ref().ok())
                .cloned().ok_or(Closed)?;

            state.cold = Some(Default::default());
            state.opened = Some(state.cold.as_mut().ok_or(Closed)?
                .open_once_v1(&mut loan, image));
            if !matches!(state.opened, Some(Ok(()))) {
                loan.retain_sdk_refusal_once_v1();
                return Err(Closed);
            }
            state.session = state.cold.as_mut().ok_or(Closed)?.take_completed_once_v1().map(Box::new);
            let session = state.session.as_mut().ok_or(Closed)?;
            state.inventory = Some(Default::default());
            state.inventoried = Some(state.inventory.as_mut().ok_or(Closed)?
                .observe_once_v1(&mut loan, state.cold.as_ref().ok_or(Closed)?, session));
            if !matches!(state.inventoried, Some(Ok(()))) {
                loan.retain_sdk_refusal_once_v1();
                return Err(Closed);
            }
            state.bound = Some(state.inventory.as_ref().ok_or(Closed)?
                .borrow_completed_inventory_data_v1(&mut loan, &self.source_domains, session)
                .map(|_| ()));
            if !matches!(state.bound, Some(Ok(()))) {
                loan.retain_sdk_refusal_once_v1();
                return Err(Closed);
            }
            Ok(())
        })());

        if !matches!(state.body, Some(Ok(()))) {
            if let Some(cause) = state.selected_failure() {
                eprintln!("aos-sandboxd: Stop cleanup passive observation: {cause}");
            }
            return Err(Closed);
        }
        state.drop_completed_prefix()
    }
}
