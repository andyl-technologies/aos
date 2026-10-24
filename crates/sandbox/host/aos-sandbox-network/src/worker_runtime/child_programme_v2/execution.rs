//! Executes only the actual signed P authorization through the shared recipe.
//!
//! The enclosing protected issuer already debited the finite whole programme.
//! This recipient compares its real typed plan against that issued fee before
//! allocating helper arrays. The comparison can only refuse; it creates no
//! account, Source, namespace, effect permit, deadline or refund.

use super::signed_admission::{PreparationClockOriginalV2, PreparationSignedOriginalV2};
use super::*;
use crate::kernel_mutator::{
    MutationProgrammeDataV2, NetworkDestroyEffectsOriginalV2, NetworkPrepareEffectsOriginalV2,
    NetworkSourceArtifactOriginalV2, NetworkSourceHelperOriginalV2, mutation_programme_data_v2,
};
use crate::namespace_pin::NetworkNamespacePublicationOriginalV2;
use crate::worker_protocol::NetworkWorkerProtocolError;
use aos_sandbox_model::BrokerVerb;

#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("the genuine P effect programme retained its refusal")]
pub(super) struct PreparationExecutionClosedV2;

#[derive(Clone, Copy)]
enum First {
    Order,
    Inputs,
    Geometry,
    Paid,
    Allocation,
    Prepare,
    Step(usize),
    Effect(usize),
    Complete(usize),
}

pub(super) struct PreparationExecutionOriginalV2 {
    entered: bool,
    first: Option<First>,
    geometry: Option<MutationProgrammeDataV2>,
    paid: Option<ResourceVector>,
    gate: Option<Result<(), PreparationExecutionClosedV2>>,
    helpers: Vec<NetworkSourceHelperOriginalV2>,
    artifacts: Vec<NetworkSourceArtifactOriginalV2>,
    publication: NetworkNamespacePublicationOriginalV2,
    preparation: NetworkPrepareEffectsOriginalV2,
    preparation_result: Option<Result<(), crate::kernel_mutator::NetworkKernelMutationError>>,
    destroy: NetworkDestroyEffectsOriginalV2,
    step_issued: [Option<Result<(), NetworkWorkerProtocolError>>; 3],
    step_completed: [Option<Result<(), NetworkWorkerProtocolError>>; 3],
    step_effects: [Option<Result<(), crate::kernel_mutator::NetworkKernelMutationError>>; 3],
    step_clocks: [PreparationClockOriginalV2; 6],
}

impl PreparationExecutionOriginalV2 {
    pub(super) fn new() -> Self {
        Self {
            entered: false,
            first: None,
            geometry: None,
            paid: None,
            gate: None,
            helpers: Vec::new(),
            artifacts: Vec::new(),
            publication: NetworkNamespacePublicationOriginalV2::new(),
            preparation: NetworkPrepareEffectsOriginalV2::new(),
            preparation_result: None,
            destroy: NetworkDestroyEffectsOriginalV2::new(),
            step_issued: std::array::from_fn(|_| None),
            step_completed: std::array::from_fn(|_| None),
            step_effects: std::array::from_fn(|_| None),
            step_clocks: std::array::from_fn(|_| PreparationClockOriginalV2::new()),
        }
    }

    pub(super) fn execute_once_v2(
        &mut self,
        source: &mut NetworkChildSourceLoanV2<'_>,
        signed: &mut PreparationSignedOriginalV2,
        startup: &PreparationStartupOriginalV2,
        trusted_current_fence: &[u8],
        maximum_table: usize,
    ) -> Result<(), PreparationExecutionClosedV2> {
        if self.entered || self.first.is_some() {
            self.first.get_or_insert(First::Order);
            return Err(PreparationExecutionClosedV2);
        }
        self.entered = true;
        let Some(binding) = source.operation_binding_data_v2() else {
            self.first = Some(First::Inputs);
            return Err(PreparationExecutionClosedV2);
        };
        let Some(method) = signed.method_data_v2() else {
            self.first = Some(First::Inputs);
            return Err(PreparationExecutionClosedV2);
        };
        let verb = match method {
            63 => BrokerVerb::NetworkPrepare,
            9 => BrokerVerb::NetworkDestroy,
            _ => {
                self.first = Some(First::Inputs);
                return Err(PreparationExecutionClosedV2);
            }
        };
        self.paid = source.prepaid_fee_data_v2();
        self.geometry = signed.receiving_plan_data_v2().and_then(|plan| {
            mutation_programme_data_v2(plan, verb, binding.native_limits[1], maximum_table)
        });
        let Some(geometry) = self.geometry.as_ref() else {
            self.first = Some(First::Geometry);
            return Err(PreparationExecutionClosedV2);
        };
        self.gate = Some(match self.paid {
            Some(paid)
                if paid
                    .checked_sub(geometry.receiving_obligations_data_v2())
                    .is_ok() =>
            {
                Ok(())
            }
            _ => Err(PreparationExecutionClosedV2),
        });
        if !matches!(self.gate, Some(Ok(()))) {
            self.first = Some(First::Paid);
            return Err(PreparationExecutionClosedV2);
        }
        let Some(helpers) = geometry.helper_originals_data_v2() else {
            self.first = Some(First::Allocation);
            return Err(PreparationExecutionClosedV2);
        };
        self.helpers = helpers;
        self.artifacts = geometry.artifact_originals_data_v2();
        let (Some(mutator), Some(authority), Some(bootstrap), Some(worker)) = (
            startup.mutator.as_ref(),
            startup.authority.as_ref(),
            startup.namespace.as_ref(),
            startup.worker.as_ref(),
        ) else {
            self.first = Some(First::Inputs);
            return Err(PreparationExecutionClosedV2);
        };
        if method == 63 {
            let Some((authorization, host)) = signed.preparation_parts_v2() else {
                self.first = Some(First::Inputs);
                return Err(PreparationExecutionClosedV2);
            };
            self.preparation_result = Some(self.preparation.execute_with_source_once_v2(
                source,
                mutator,
                authority,
                authorization,
                &startup.kernel,
                &mut self.helpers,
                &mut self.artifacts,
                &mut self.publication,
                bootstrap,
                host,
                worker,
            ));
            if !matches!(self.preparation_result, Some(Ok(()))) {
                self.first = Some(First::Prepare);
                return Err(PreparationExecutionClosedV2);
            }
            return Ok(());
        }
        let Some((authorization, target, host)) = signed.destroy_parts_v2() else {
            self.first = Some(First::Inputs);
            return Err(PreparationExecutionClosedV2);
        };
        if trusted_current_fence.is_empty() {
            self.first = Some(First::Inputs);
            return Err(PreparationExecutionClosedV2);
        }
        for index in 0..3 {
            let before = &mut self.step_clocks[2 * index];
            let step = authorization.authorize_next_step(
                authority,
                &mut || Ok(trusted_current_fence.to_vec()),
                &mut || before.observe_once_v2(binding.boot),
            );
            let mut step = match step {
                Ok(Some(step)) => {
                    self.step_issued[index] = Some(Ok(()));
                    step
                }
                Ok(None) => {
                    self.first = Some(First::Step(index));
                    return Err(PreparationExecutionClosedV2);
                }
                Err(cause) => {
                    self.step_issued[index] = Some(Err(cause));
                    self.first = Some(First::Step(index));
                    return Err(PreparationExecutionClosedV2);
                }
            };
            self.step_effects[index] = Some(self.destroy.execute_step_with_source_once_v2(
                source,
                mutator,
                authority,
                &mut step,
                trusted_current_fence,
                &startup.kernel,
                &mut self.helpers,
                &mut self.artifacts,
                target,
                host,
                bootstrap,
                worker,
            ));
            if !matches!(self.step_effects[index], Some(Ok(()))) {
                self.first = Some(First::Effect(index));
                // The genuine unresolved token poisons that SAME execution.
                // All helper/error owners remain on this actor through ACK.
                return Err(PreparationExecutionClosedV2);
            }
            let after = &mut self.step_clocks[2 * index + 1];
            self.step_completed[index] = Some(step.complete_success(
                authority,
                &mut || Ok(trusted_current_fence.to_vec()),
                &mut || after.observe_once_v2(binding.boot),
            ));
            if !matches!(self.step_completed[index], Some(Ok(()))) {
                self.first = Some(First::Complete(index));
                return Err(PreparationExecutionClosedV2);
            }
        }
        if !authorization.is_complete() || !self.destroy.completed_data_v2() {
            self.first = Some(First::Complete(2));
            return Err(PreparationExecutionClosedV2);
        }
        Ok(())
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let cause: Option<&(dyn Error + 'static)> = match self.first? {
            First::Prepare => self
                .preparation
                .failure_with_helpers_v2(&self.helpers, &self.artifacts, &self.publication)
                .or_else(|| failed(&self.preparation_result)),
            First::Step(index) => self.step_clocks[2 * index]
                .failure()
                .or_else(|| failed(&self.step_issued[index])),
            First::Effect(index) => self
                .destroy
                .failure_with_helpers_v2(&self.helpers, &self.artifacts)
                .or_else(|| failed(&self.step_effects[index])),
            First::Complete(index) => self.step_clocks[2 * index + 1]
                .failure()
                .or_else(|| failed(&self.step_completed[index])),
            First::Order | First::Inputs | First::Geometry | First::Paid | First::Allocation => {
                None
            }
        };
        cause.or(Some(&PreparationExecutionClosedV2))
    }

    pub(super) fn receiving_obligations_data_v2() -> Option<ResourceVector> {
        let mut demand = ResourceVector::ZERO.with(
            D::MemoryBytes,
            u64::try_from(std::mem::size_of::<Self>().checked_mul(2)?).ok()?,
        );
        for _ in 0..6 {
            demand = demand
                .checked_add(PreparationClockOriginalV2::receiving_obligations_data_v2()?)
                .ok()?;
        }
        Some(demand)
    }
}
