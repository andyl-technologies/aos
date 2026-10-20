//! Joins accepted execution DATA to the genuine Root Environment model cut.
//!
//! The actual R stage admits the whole decoder/model peak before either
//! canonical selector runs. A wire OperationId selects a comparison only;
//! current protected operation, projection and bound assignment supply every
//! returned identity. This owner grants neither a lease nor Host authorization.

use std::error::Error;
use std::mem::size_of;
use aos_sandbox_core::{ExecutionId, NodeId, OperationId, ProjectId, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::effect_history::PublicMutationEffectHistoryV1;
use crate::controller_resource_reservation::RootContinuationDemandV1;
use crate::execution_parent_resource::{ExecutionParentResourceSourceV1,
    current_execution_parent_resource_from_journal_v1};
use crate::journal::JournalError;
use crate::normal_root::{NormalRootStartupErrorV1, RootEnvironmentStageReceivingV1};
use crate::policy_compiler::provisioning_current::RootEnvironmentReadonlyContextV1;
use crate::policy_compiler::provisioning_current::current_compiler_complete_receiving_demand_v1;
use crate::policy_compiler::continuation_policy::RootEnvironmentPolicyOriginalV1;
use crate::reconciler::{accepted_create_execution_effect_from_journal_v1,
    accepted_execution_target_from_journal_v1};

type Cause = Box<dyn Error>;

#[derive(Debug, thiserror::Error)]
#[error("current accepted execution does not bind this Environment request")]
struct Changed;

struct ValuesV1 {
    operation: OperationId,
    execution: ExecutionId,
    accepted: PublicMutationEffectHistoryV1,
    parent: ExecutionParentResourceSourceV1,
}

/// Retains the actual accepted selectors and their original first cause.
pub(crate) struct RootEnvironmentAcceptedOriginalV1 {
    demand: Option<Result<ResourceVector, JournalError>>,
    funding: Option<Result<(), NormalRootStartupErrorV1>>,
    result: Option<Result<Box<ValuesV1>, Cause>>,
    closed: Option<JournalError>,
}

impl RootEnvironmentAcceptedOriginalV1 {
    pub(crate) fn new() -> Self {
        Self { demand: None, funding: None, result: None, closed: None }
    }

    pub(crate) fn observe_once_v1(&mut self,
        stage: &mut RootEnvironmentStageReceivingV1<'_, '_>,
        readonly: &mut RootEnvironmentReadonlyContextV1,
        operation: OperationId,
        policy: &RootEnvironmentPolicyOriginalV1,
    ) -> Result<(), JournalError> {
        if self.demand.is_some() || self.closed.is_some() {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        self.demand = Some((|| {
            let input = readonly.compiler_input_bytes_v1()?;
            let bytes = size_of::<ValuesV1>().checked_mul(3)
                .and_then(|bytes| bytes.checked_add(size_of::<Self>().checked_mul(2)?))
                .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
            let signed = policy.verified_v1().ok_or(JournalError::ProtectedBoundary)?;
            current_compiler_complete_receiving_demand_v1(
                input, readonly.compiler_controller_state_v1()?, signed)?
                .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
                .map_err(|_| JournalError::JournalTooLarge)
        })());
        let demand = self.demand.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or(JournalError::ProtectedBoundary)?;
        self.funding = Some(stage.admit_environment_accepted_once_v1(
            RootContinuationDemandV1::from_demand_v1(demand)));
        if !matches!(self.funding, Some(Ok(()))) { return Err(JournalError::ProtectedBoundary); }
        self.result = Some((|| {
            let node = NodeId::from_bytes(stage.enrolled_node_v1()?);
            let (controller, _) = readonly.models_mut_v1()?;
            let accepted = accepted_create_execution_effect_from_journal_v1(controller, operation)?
                .ok_or(Changed)?;
            let (sandbox, execution) = accepted_execution_target_from_journal_v1(controller, operation, &accepted)?;
            let parent = current_execution_parent_resource_from_journal_v1(
                controller, accepted.project(), sandbox, node)?;
            if parent.assignment().manifest().node() != node { return Err(Changed.into()); }
            Ok(Box::new(ValuesV1 { operation, execution, accepted, parent }))
        })());
        self.values_v1().map(|_| ())
    }

    fn values_v1(&self) -> Result<&ValuesV1, JournalError> {
        if self.closed.is_some() || !matches!(self.funding, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.result.as_ref().and_then(|value| value.as_ref().ok()).map(Box::as_ref)
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(crate) fn operation_v1(&self) -> Result<OperationId, JournalError> { Ok(self.values_v1()?.operation) }
    pub(crate) fn execution_v1(&self) -> Result<ExecutionId, JournalError> { Ok(self.values_v1()?.execution) }
    pub(crate) fn project_v1(&self) -> Result<ProjectId, JournalError> { Ok(self.values_v1()?.accepted.project()) }
    pub(crate) fn parent_v1(&self) -> Result<&ExecutionParentResourceSourceV1, JournalError> { Ok(&self.values_v1()?.parent) }
    pub(crate) fn accepted_v1(&self) -> Result<&PublicMutationEffectHistoryV1, JournalError> { Ok(&self.values_v1()?.accepted) }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.demand.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.funding.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.result.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause.as_ref()))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}
