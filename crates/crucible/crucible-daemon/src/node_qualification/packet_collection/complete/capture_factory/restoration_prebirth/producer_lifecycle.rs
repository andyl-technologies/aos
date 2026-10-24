//! Drives real recurrent Producer operations while all failed owners stay local.
//!
//! The outer capsule is borrowed shared across the real Core census. Only its
//! independently loaned Runtime is mutable; the genuine scope supplies that
//! exact Runtime to the raw observer. Action and publisher banks are unopened
//! during preparation. Begin, Poll, durable ACK/Retire and final Observe then
//! retain their actual owners before the next fallible boundary.

use super::*;
use crucible_engine::node_adapters::cnp::PacketCompleteOriginalHostSdk;
use crucible_engine::node_admission::CompleteOriginalRestorationWindow;
use crucible_engine::node_contract::{
    BeginResult, OperationOutcome, RuntimeError, RuntimePollFailure,
};
use crucible_node_format::{Id, U64};
use crucible_node_transport::reference_packet::service::PacketNative5SourceLaunch;

impl PacketCompleteRestorationPrebirth {
    pub(in crate::node_qualification::packet_collection::complete) fn execute_original_producer_lifecycle_data(
        &self,
        window: &Rc<CompleteOriginalRestorationWindow>,
        plan: &InstalledConformancePlan,
        sdks: [&PacketCompleteOriginalHostSdk; 3],
        launches: &[PacketNative5SourceLaunch; 3],
        canonical_launch5: [&[u8]; 3],
        node: &Id,
        operation: Id,
        horizon: U64,
        inspect: &mut dyn FnMut(&OperationOutcome) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimePollFailure> {
        self.authenticate_creator()
            .map_err(|_| RuntimePollFailure::Admission(RuntimeError::ForeignAuthority))?;
        let mut runtime = self
            .runtime_mut_loan_data()
            .map_err(RuntimePollFailure::Admission)?;
        // No action or C bank is loaned while the real Core admission performs
        // its full callback and exact current-owner census.
        let admission = runtime
            .prepare_original_restored_producer_execution(
                window,
                plan,
                sdks,
                launches,
                canonical_launch5,
                node,
                operation,
                horizon,
            )
            .map_err(RuntimePollFailure::Admission)?;
        let selected = admission.selected_data();
        let slot = admission.slot_data();
        let launch = launches.get(selected).ok_or(RuntimePollFailure::Admission(
            RuntimeError::ForeignAuthority,
        ))?;
        let canonical = *canonical_launch5
            .get(selected)
            .ok_or(RuntimePollFailure::Admission(
                RuntimeError::ForeignAuthority,
            ))?;
        let actions = self
            .restored_actions
            .try_borrow()
            .map_err(|_| RuntimePollFailure::Admission(RuntimeError::OwnerBusy))?;
        let owner = actions.get(slot).ok_or(RuntimePollFailure::Admission(
            RuntimeError::OwnerUnavailable,
        ))?;
        let mut action = owner
            .try_borrow_mut()
            .map_err(|_| RuntimePollFailure::Admission(RuntimeError::OwnerBusy))?;
        if action.admission.is_some()
            || action.begin.is_some()
            || action.outcome.is_some()
            || action.completed
        {
            return Err(RuntimePollFailure::Admission(
                RuntimeError::OutstandingObligations,
            ));
        }
        // Retain the real once handle before any native action is dispatched.
        action.admission = Some(admission);
        let begin = runtime
            .begin_original_restored_producer_execution(
                action
                    .admission
                    .as_mut()
                    .ok_or(RuntimePollFailure::Admission(
                        RuntimeError::OwnerUnavailable,
                    ))?,
                launch,
                canonical,
            )
            .map_err(RuntimePollFailure::Admission)?;
        action.begin = Some(begin);
        // Destructure only disjoint retained fields; neither the token nor
        // admission is cloned or extracted from this stable owner.
        let super::super::super::restored_publication::RestoredProducerAction {
            admission,
            begin,
            outcome,
            completed: _,
        } = &mut *action;
        let admission = admission.as_mut().ok_or(RuntimePollFailure::Admission(
            RuntimeError::OwnerUnavailable,
        ))?;
        let token = match begin.as_ref().ok_or(RuntimePollFailure::Admission(
            RuntimeError::OwnerUnavailable,
        ))? {
            BeginResult::Accepted(token) => token,
            BeginResult::Refused(_) | BeginResult::Uncertain { .. } => {
                return Err(RuntimePollFailure::Admission(
                    RuntimeError::OutstandingObligations,
                ));
            }
        };
        *outcome = Some(
            runtime
                .poll_original_restored_producer_execution(admission, token, launch, canonical)?,
        );
        self.finish_original_producer_action_data(
            &mut runtime,
            &mut action,
            launch,
            canonical,
            inspect,
        )
    }
}

impl PacketCompleteRestorationPrebirth {
    pub(in crate::node_qualification::packet_collection::complete) fn acknowledge_original_producer_stored_data(
        &self,
        launches: &[PacketNative5SourceLaunch; 3],
        canonical_launch5: [&[u8]; 3],
        slot: usize,
        inspect: &mut dyn FnMut(&OperationOutcome) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimePollFailure> {
        self.authenticate_creator()
            .map_err(|_| RuntimePollFailure::Admission(RuntimeError::ForeignAuthority))?;
        let mut runtime = self
            .runtime_mut_loan_data()
            .map_err(RuntimePollFailure::Admission)?;
        let actions = self
            .restored_actions
            .try_borrow()
            .map_err(|_| RuntimePollFailure::Admission(RuntimeError::OwnerBusy))?;
        let owner = actions.get(slot).ok_or(RuntimePollFailure::Admission(
            RuntimeError::OwnerUnavailable,
        ))?;
        let mut action = owner
            .try_borrow_mut()
            .map_err(|_| RuntimePollFailure::Admission(RuntimeError::OwnerBusy))?;
        let admission = action
            .admission
            .as_ref()
            .ok_or(RuntimePollFailure::Admission(
                RuntimeError::OwnerUnavailable,
            ))?;
        if admission.slot_data() != slot {
            return Err(RuntimePollFailure::Admission(
                RuntimeError::ForeignAuthority,
            ));
        }
        let selected = admission.selected_data();
        let launch = launches.get(selected).ok_or(RuntimePollFailure::Admission(
            RuntimeError::ForeignAuthority,
        ))?;
        let canonical = *canonical_launch5
            .get(selected)
            .ok_or(RuntimePollFailure::Admission(
                RuntimeError::ForeignAuthority,
            ))?;
        self.finish_original_producer_action_data(
            &mut runtime,
            &mut action,
            launch,
            canonical,
            inspect,
        )
    }

    fn finish_original_producer_action_data(
        &self,
        runtime: &mut ConformanceRuntime,
        action: &mut super::super::super::restored_publication::RestoredProducerAction,
        launch: &PacketNative5SourceLaunch,
        canonical: &[u8],
        inspect: &mut dyn FnMut(&OperationOutcome) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimePollFailure> {
        if action.completed || action.outcome.is_none() {
            return Err(RuntimePollFailure::Admission(
                RuntimeError::OutstandingObligations,
            ));
        }
        let super::super::super::restored_publication::RestoredProducerAction {
            admission,
            begin,
            outcome,
            completed,
        } = action;
        let admission = admission.as_mut().ok_or(RuntimePollFailure::Admission(
            RuntimeError::OwnerUnavailable,
        ))?;
        let token = match begin.as_ref().ok_or(RuntimePollFailure::Admission(
            RuntimeError::OwnerUnavailable,
        ))? {
            BeginResult::Accepted(token) => token,
            BeginResult::Refused(_) | BeginResult::Uncertain { .. } => {
                return Err(RuntimePollFailure::Admission(
                    RuntimeError::OutstandingObligations,
                ));
            }
        };
        {
            let mut publisher = self
                .restored_results
                .as_ref()
                .ok_or(RuntimePollFailure::Admission(
                    RuntimeError::OwnerUnavailable,
                ))?
                .try_borrow_mut()
                .map_err(|_| RuntimePollFailure::Admission(RuntimeError::OwnerBusy))?;
            // Core checks the retained admission/phase, same Source-read report,
            // actual completion and registered pointer. Retry stays on this
            // placement and can never repeat Begin or Poll through this method.
            runtime.publish_and_acknowledge_original_restored_producer(
                token,
                admission,
                &mut *publisher,
                launch,
                canonical,
            )?;
        }
        runtime
            .observe_original_restored_producer_execution(admission, token, launch, canonical)?;
        *completed = true;
        inspect(outcome.as_ref().ok_or(RuntimePollFailure::Admission(
            RuntimeError::OwnerUnavailable,
        ))?)
        .map_err(RuntimePollFailure::Admission)
    }
}
