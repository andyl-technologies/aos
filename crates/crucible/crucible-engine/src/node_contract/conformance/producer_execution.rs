//! Admits each real restored Producer attempt before its native action phases.
//!
//! Constructor credit precedes the actual scheduler reservation. The same grant
//! remains in the Window through Source quotation, full owner census, append
//! and dispatch; no request DTO or publisher result manufactures permission.

use super::*;
use crate::node_adapters::cnp::PacketCompleteOriginalHostSdk;
use crate::node_admission::{
    CompleteOriginalRestorationWindow, InstalledConformancePlan,
    OriginalRestoredProducerExecutionAdmission,
};
use crucible_node_transport::reference_packet::service::PacketNative5SourceLaunch;

impl ConformanceRuntime {
    /// Admits a new no-input restored Producer attempt under the actual group.
    ///
    /// Each invocation spends a new global slot and retains the genuine grant,
    /// construction work and every future action row through failure. Capacity
    /// is the separately funded publisher/Source/native capacity, bounded again
    /// by the real Runtime limit. No original or restored input is submitted.
    ///
    /// # Errors
    /// Refuses foreign/currentness/ownership changes, an incomplete earlier
    /// attempt, exhausted real limits, unsupported actual grants, a failed full
    /// quote/census or any allocation error before native Begin.
    pub fn prepare_original_restored_producer_execution(
        &mut self,
        window: &Rc<CompleteOriginalRestorationWindow>,
        plan: &InstalledConformancePlan,
        sdks: [&PacketCompleteOriginalHostSdk; 3],
        launches: &[PacketNative5SourceLaunch; 3],
        canonical_launch5: [&[u8]; 3],
        node: &Id,
        operation: Id,
        horizon: U64,
    ) -> Result<OriginalRestoredProducerExecutionAdmission, RuntimeError> {
        self.current()?;
        let world = self.activation.as_ref().ok_or(RuntimeError::NotActivated)?;
        let (maximum, _) = window.current_observation_policy_data()?;
        let work = self
            .runtime
            .original_restored_producer_dispatch_construction_data(
                world, node, &operation, maximum,
            )?;
        let selected =
            window.retain_original_producer_grant_work_data(self, plan, world, node, work)?;
        window.recheck_original_transaction_inputs_data(
            plan,
            sdks,
            launches,
            canonical_launch5,
            self,
            world.record(),
        )?;
        window.begin_original_producer_grant_construction_data(self, plan, world, selected)?;
        let grant = self
            .runtime
            .scheduler(&self.graph.graph, world)?
            .admit_exact(node, operation, horizon)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        if let Err(error) =
            self.graph
                .authenticate_operation(node, grant.operation(), &grant.request())
        {
            self.runtime
                .scheduler(&self.graph.graph, world)?
                .reconcile_no_effect(&grant)
                .map_err(|_| RuntimeError::InvalidReceipt)?;
            return Err(RuntimeError::SchedulerRefused(error.message));
        }
        let slot = match window.retain_original_producer_pending_grant_data(
            &self.runtime,
            selected,
            grant,
        ) {
            Ok(slot) => slot,
            Err((error, grant)) => {
                self.runtime
                    .scheduler(&self.graph.graph, world)?
                    .reconcile_no_effect(&grant)
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
                return Err(error);
            }
        };
        let row = window.with_original_pending_producer_grant_data(selected, |grant| {
            self.runtime
                .quote_original_restored_producer_execution_data(
                    grant,
                    &launches[selected],
                    canonical_launch5[selected],
                    maximum,
                )
        })?;
        window.retain_original_producer_execution_quote_data(&self.runtime, selected, row)?;
        window.recheck_original_transaction_inputs_data(
            plan,
            sdks,
            launches,
            canonical_launch5,
            self,
            world.record(),
        )?;
        if window.append_original_admitted_producer_execution_data(selected)? != slot {
            return Err(RuntimeError::ForeignAuthority);
        }
        // The new actual bank is now visible independently beside its still
        // outstanding future commitment. No allocator-capacity refund occurs.
        window.recheck_original_transaction_inputs_data(
            plan,
            sdks,
            launches,
            canonical_launch5,
            self,
            world.record(),
        )?;
        OriginalRestoredProducerExecutionAdmission::after_original_census_data(
            window,
            &self.runtime,
            selected,
            slot,
        )
    }

    /// Dispatches only the real grant retained by a complete action admission.
    ///
    /// # Errors
    /// Refuses changed/spent ownership before callback. Native uncertainties
    /// retain the same used operation and every actual partial owner.
    pub fn begin_original_restored_producer_execution(
        &mut self,
        admission: &mut OriginalRestoredProducerExecutionAdmission,
        launch: &PacketNative5SourceLaunch,
        canonical_launch5: &[u8],
    ) -> Result<BeginResult, RuntimeError> {
        self.current()?;
        let world = self.activation.as_ref().ok_or(RuntimeError::NotActivated)?;
        let claim = admission.begin_phase_data(
            &self.runtime,
            world,
            launch,
            canonical_launch5,
            crate::node_admission::ProducerExecutionPhase::Begin,
        )?;
        let result = self
            .runtime
            .begin_original_restored_producer_admitted(&claim)?;
        if let BeginResult::Accepted(token) = &result {
            claim.complete_runtime_phase_data(&self.runtime, token)?;
        }
        Ok(result)
    }
}

impl ConformanceRuntime {
    /// Polls one actual admitted restored Producer without renewing its Begin.
    ///
    /// # Errors
    /// Refuses changed/spent claim or token, a native/SDK/proof failure, or an
    /// unexpected pending result. Original resources remain retained on failure.
    pub fn poll_original_restored_producer_execution(
        &mut self,
        admission: &mut OriginalRestoredProducerExecutionAdmission,
        token: &OperationToken,
        launch: &PacketNative5SourceLaunch,
        canonical_launch5: &[u8],
    ) -> Result<OperationOutcome, RuntimePollFailure> {
        self.current_operation(token)
            .map_err(RuntimePollFailure::Admission)?;
        let world = self
            .activation
            .as_ref()
            .ok_or(RuntimePollFailure::Admission(RuntimeError::NotActivated))?;
        let claim = admission
            .begin_phase_data(
                &self.runtime,
                world,
                launch,
                canonical_launch5,
                crate::node_admission::ProducerExecutionPhase::Poll,
            )
            .map_err(RuntimePollFailure::Admission)?;
        let mut context = Context::from_waker(std::task::Waker::noop());
        match self
            .runtime
            .poll_with_producer_claim(token, &mut context, Some(&claim))
        {
            Poll::Ready(Ok(outcome)) => {
                claim
                    .complete_runtime_phase_data(&self.runtime, token)
                    .map_err(RuntimePollFailure::Admission)?;
                Ok(outcome)
            }
            Poll::Ready(Err(error)) => Err(error),
            Poll::Pending => Err(RuntimePollFailure::Admission(
                RuntimeError::OutstandingObligations,
            )),
        }
    }
}

impl ConformanceRuntime {
    /// Verifies a fresh post-retirement checkpoint before admitting another slot.
    ///
    /// The Source retains immutable imported ancestry and all used action owners.
    /// Only its distinct current checkpoint updates the real common scheduler.
    ///
    /// # Errors
    /// Refuses changed custody, missing retirement, incomplete native proof,
    /// scheduling regression, failed currentness or a previously spent phase.
    pub fn observe_original_restored_producer_execution(
        &mut self,
        admission: &mut OriginalRestoredProducerExecutionAdmission,
        token: &OperationToken,
        launch: &PacketNative5SourceLaunch,
        canonical_launch5: &[u8],
    ) -> Result<(), RuntimePollFailure> {
        self.current_operation(token)
            .map_err(RuntimePollFailure::Admission)?;
        let world = self
            .activation
            .as_ref()
            .ok_or(RuntimePollFailure::Admission(RuntimeError::NotActivated))?;
        let claim = admission
            .begin_phase_data(
                &self.runtime,
                world,
                launch,
                canonical_launch5,
                crate::node_admission::ProducerExecutionPhase::Observation,
            )
            .map_err(RuntimePollFailure::Admission)?;
        self.runtime
            .accept_original_restored_producer_checkpoint_data(token, &claim)?;
        claim
            .complete_runtime_phase_data(&self.runtime, token)
            .map_err(RuntimePollFailure::Admission)
    }
}
