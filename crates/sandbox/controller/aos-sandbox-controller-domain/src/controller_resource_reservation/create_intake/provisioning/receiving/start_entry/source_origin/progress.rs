//! Borrows the actual completed Host material for the same Start Source reducer.

use super::*;
use crate::lifecycle::{
    LifecycleProtectedJournalErrorV1, LifecycleProtectedJournalOwnerV1,
    PreparedSourceLifecycleAdmissionV1,
};

impl StartSourceAdmissionAuthorizationV1<'_> {
    pub(crate) fn purpose_v2(&self) -> StartSourcePurposeV2 {
        self.state.purpose
    }

    pub(crate) fn parent_operation_v2(&self) -> aos_sandbox_model::OperationId {
        self.plan.operation_id()
    }

    pub(super) fn prepare_turn_v2(
        &self,
        owner: &LifecycleProtectedJournalOwnerV1<'_>,
    ) -> Result<PreparedSourceLifecycleAdmissionV1, LifecycleProtectedJournalErrorV1> {
        owner.prepare_original_start_source_turn_v2(self)
    }

    pub(crate) fn actual_started_at_v2(
        &self,
    ) -> Result<crate::lifecycle::LifecycleTimeV1, crate::JournalError> {
        let sample = self
            .state
            .before
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(crate::JournalError::ProtectedBoundary)?;
        let nanos = u64::try_from(sample.wall_seconds())
            .ok()
            .and_then(|seconds| seconds.checked_mul(1_000_000_000))
            .ok_or(crate::JournalError::ProtectedBoundary)?;
        crate::lifecycle::LifecycleTimeV1::new(nanos)
            .map_err(|_| crate::JournalError::ProtectedBoundary)
    }

    pub(crate) fn anchor_commitments_v2(
        &self,
    ) -> Result<
        (
            aos_sandbox_model::ObjectDigest,
            aos_sandbox_model::ObjectDigest,
        ),
        crate::JournalError,
    > {
        let material = self
            .completion
            .ok_or(crate::JournalError::ProtectedBoundary)?;
        material.require_original_v2(self.plan, self.origin)?;
        let context = self
            .state
            .context
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(crate::JournalError::ProtectedBoundary)?;
        Ok((aos_sandbox_protocol::domain_ledger::provisioning_resources::
            provisioning_public_request_digest_v1(context.canonical_request()),
            material.plan_commitment_v2()))
    }

    pub(crate) fn bound_step_v2(
        &self,
    ) -> Result<crate::lifecycle::LifecycleStepV1, crate::JournalError> {
        let [step] = self.expected_operation_v1().steps() else {
            return Err(crate::JournalError::ProtectedBoundary);
        };
        let (request, plan) = self.anchor_commitments_v2()?;
        let forward = crate::lifecycle::LifecyclePhase6EffectPlanV1::new(
            crate::lifecycle::LifecycleEffectDomainV1::Controller,
            1,
            self.q04_v1().sandbox().into_bytes(),
            request,
            plan,
        )
        .map_err(|_| crate::JournalError::ProtectedBoundary)?;
        crate::lifecycle::lifecycle_phase6_bind_controller_anchor_v1(
            self.plan.operation_id(),
            step,
            forward,
        )
        .map_err(|_| crate::JournalError::ProtectedBoundary)
    }

    pub(crate) fn semantic_commit_v2(
        &self,
    ) -> Result<crate::lifecycle::LifecycleMethodSemanticCommitV1, crate::JournalError> {
        self.state
            .semantic
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .cloned()
            .ok_or(crate::JournalError::ProtectedBoundary)
    }

    pub(crate) fn completed_readback_v2(
        &self,
    ) -> Result<
        (
            aos_sandbox_model::ObjectDigest,
            aos_sandbox_model::ObjectDigest,
        ),
        crate::JournalError,
    > {
        let material = self
            .completion
            .ok_or(crate::JournalError::ProtectedBoundary)?;
        material.require_original_v2(self.plan, self.origin)?;
        Ok(material.completed_readback_v2())
    }
}
