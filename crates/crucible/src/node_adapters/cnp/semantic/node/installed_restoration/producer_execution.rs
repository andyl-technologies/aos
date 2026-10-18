//! Retains genuine new action owners beside immutable imported custody.
//!
//! The inline pending admission survives failed growth. Each successful Source
//! callback seals a distinct Window phase before its retained result is usable.

use super::*;
use crate::node_admission::{
    OriginalRestoredProducerExecutionClaim, OriginalRestoredProducerExecutionConstructionData,
};
use crate::node_contract::{
    OperationOutcome, OperationToken, OriginalRestoredProducerReportReadScope,
    OriginalRuntimeOperationDispatch,
};
use crate::node_scheduling::{ExecutionAdmission, NativeSchedulingObservation};
use crucible_node_provider::reference_packet::service::PacketNative5SourceLaunch;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Beginning,
    Begun,
    Polling,
    Completed,
    Retiring,
    Retired,
    Observing,
    Verified,
    Failed,
}

struct Attempt {
    admission: OperationAdmission,
    slot: usize,
    stage: Stage,
    retained: Option<OperationOutcome>,
    returned: Option<OperationOutcome>,
    scheduling: Option<NativeSchedulingObservation>,
    scheduling_return: Option<NativeSchedulingObservation>,
}

pub(super) struct ProducerNodeHistory {
    pending: Option<Attempt>,
    attempts: Vec<Attempt>,
}

impl ProducerNodeHistory {
    pub(super) fn new() -> Self {
        Self {
            pending: None,
            attempts: Vec::new(),
        }
    }

    fn last_data(
        &mut self,
        token: &OperationToken,
        claim: &OriginalRestoredProducerExecutionClaim<'_>,
    ) -> Result<&mut Attempt, RuntimeError> {
        let attempt = self
            .attempts
            .last_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if self.pending.is_some()
            || !attempt.admission.token().same_authority(token)
            || attempt.slot != claim.slot_data()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(attempt)
    }
}

impl super::super::super::CnpSemanticNode {
    pub(in crate::node_adapters::cnp::semantic) fn requires_installed_producer_claim_data(
        &self,
        token: &OperationToken,
    ) -> bool {
        self.preparation
            .guard
            .custody
            .as_ref()
            .and_then(|native| native.runtime.as_ref())
            .and_then(|runtime| runtime.installed_restoration.as_ref())
            .is_some_and(|selected| {
                selected
                    .producer_executions
                    .pending
                    .iter()
                    .chain(selected.producer_executions.attempts.iter())
                    .any(|attempt| attempt.admission.token().operation() == token.operation())
            })
    }

    pub(in crate::node_adapters::cnp::semantic) fn quote_installed_producer_execution_data(
        &self,
        grant: &ExecutionAdmission,
        launch: &PacketNative5SourceLaunch,
        raw5: &[u8],
        maximum: usize,
    ) -> Result<OriginalRestoredProducerExecutionConstructionData, RuntimeError> {
        self.current().map_err(|_| RuntimeError::OwnerUnavailable)?;
        let native = self
            .preparation
            .guard
            .custody
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let source = native
            .source
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let controller = native
            .controller
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let selected = native
            .runtime
            .as_ref()
            .and_then(|runtime| runtime.installed_restoration.as_ref())
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let history = &selected.producer_executions;
        if !selected.installed
            || !selected.observation_attempted
            || history.pending.is_some()
            || history
                .attempts
                .last()
                .is_some_and(|attempt| attempt.stage != Stage::Verified)
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        let mut row = selected
            .association
            .quote_original_producer_execution_data(
                source.as_ref(),
                controller,
                Rc::as_ptr(&native.read_owner).cast(),
                grant,
                launch,
                raw5,
                maximum,
            )?;
        let bank = history
            .attempts
            .len()
            .checked_add(1)
            .and_then(|count| count.checked_mul(size_of::<Attempt>()))
            .ok_or(RuntimeError::ResourceLimit)?;
        row.runtime_work.0 = row
            .runtime_work
            .0
            .checked_add(bank)
            .ok_or(RuntimeError::ResourceLimit)?;
        row.runtime_work.1 = row
            .runtime_work
            .1
            .checked_add(bank)
            .ok_or(RuntimeError::ResourceLimit)?;
        row.runtime_work.2 = row
            .runtime_work
            .2
            .checked_add(counter_scratch_data())
            .ok_or(RuntimeError::ResourceLimit)?;
        row.complete_scratch = row
            .scratch
            .checked_add(row.runtime_work.2)
            .ok_or(RuntimeError::ResourceLimit)?;
        row.requested_bytes_data()?;
        Ok(row)
    }

    pub(in crate::node_adapters::cnp::semantic) fn begin_installed_producer_execution_data(
        &mut self,
        dispatch: &OriginalRuntimeOperationDispatch<'_>,
        claim: &OriginalRestoredProducerExecutionClaim<'_>,
    ) -> Result<(), RuntimeError> {
        self.current().map_err(|_| RuntimeError::OwnerUnavailable)?;
        claim.authenticate_original_dispatch_data(dispatch, &self.route)?;
        let native = self
            .preparation
            .guard
            .custody
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let source = native
            .source
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let controller = native
            .controller
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let selected = native
            .runtime
            .as_mut()
            .and_then(|runtime| runtime.installed_restoration.as_mut())
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let history = &mut selected.producer_executions;
        if history.pending.is_some()
            || history
                .attempts
                .last()
                .is_some_and(|attempt| attempt.stage != Stage::Verified)
            || history.attempts.iter().any(|attempt| {
                attempt.admission.token().operation()
                    == dispatch.admission_data().token().operation()
            })
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        history.pending = Some(Attempt {
            admission: dispatch.admission_data().clone(),
            slot: claim.slot_data(),
            stage: Stage::Beginning,
            retained: None,
            returned: None,
            scheduling: None,
            scheduling_return: None,
        });
        history
            .attempts
            .try_reserve_exact(1)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        history.attempts.push(
            history
                .pending
                .take()
                .ok_or(RuntimeError::OwnerUnavailable)?,
        );
        let attempt = history
            .attempts
            .last_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let result = selected
            .association
            .with_original_producer_execution_source_data(
                source.as_ref(),
                controller as *const _,
                Rc::as_ptr(&native.read_owner).cast(),
                claim,
                |source, inputs| {
                    source.call_original_restored_producer_begin_data(
                        controller, inputs, claim, dispatch,
                    )
                },
            );
        attempt.stage = if result.is_ok() {
            Stage::Begun
        } else {
            Stage::Failed
        };
        result
    }

    pub(in crate::node_adapters::cnp::semantic) fn poll_installed_producer_execution_data(
        &mut self,
        token: &OperationToken,
        claim: &OriginalRestoredProducerExecutionClaim<'_>,
    ) -> Result<OperationOutcome, OperationFailure> {
        self.try_poll_installed_producer_execution_data(token, claim)
            .map_err(failure)
    }

    fn try_poll_installed_producer_execution_data(
        &mut self,
        token: &OperationToken,
        claim: &OriginalRestoredProducerExecutionClaim<'_>,
    ) -> Result<OperationOutcome, RuntimeError> {
        self.current().map_err(|_| RuntimeError::OwnerUnavailable)?;
        let native = self
            .preparation
            .guard
            .custody
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let source = native
            .source
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let controller = native
            .controller
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let selected = native
            .runtime
            .as_mut()
            .and_then(|runtime| runtime.installed_restoration.as_mut())
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let attempt = selected.producer_executions.last_data(token, claim)?;
        if attempt.stage != Stage::Begun {
            return Err(RuntimeError::OutstandingObligations);
        }
        attempt.stage = Stage::Polling;
        let result = selected
            .association
            .with_original_producer_execution_source_data(
                source.as_ref(),
                controller as *const _,
                Rc::as_ptr(&native.read_owner).cast(),
                claim,
                |source, inputs| {
                    source.call_original_restored_producer_poll_into(
                        controller,
                        inputs,
                        claim,
                        &attempt.admission,
                        &mut attempt.retained,
                        &mut attempt.returned,
                    )
                },
            );
        attempt.stage = if result.is_ok() {
            Stage::Completed
        } else {
            Stage::Failed
        };
        result?;
        attempt.returned.take().ok_or(RuntimeError::InvalidReceipt)
    }

    pub(in crate::node_adapters::cnp::semantic) fn validate_installed_producer_outcome_data(
        &self,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
    ) -> Result<(), OperationFailure> {
        let selected = self
            .preparation
            .guard
            .custody
            .as_ref()
            .and_then(|native| native.runtime.as_ref())
            .and_then(|runtime| runtime.installed_restoration.as_ref())
            .ok_or_else(|| failure(RuntimeError::OwnerUnavailable))?;
        let attempt = selected
            .producer_executions
            .attempts
            .last()
            .ok_or_else(|| failure(RuntimeError::OwnerUnavailable))?;
        if attempt.stage != Stage::Completed
            || !attempt.admission.token().same_authority(original.token())
            || attempt.admission.request() != original.request()
            || !attempt
                .admission
                .activation()
                .same_authority(original.activation())
            || attempt.retained.as_ref() != Some(outcome)
        {
            return Err(failure(RuntimeError::InvalidReceipt));
        }
        Ok(())
    }

    pub(in crate::node_adapters::cnp::semantic) fn with_installed_producer_report_data(
        &mut self,
        original: &OperationAdmission,
        claim: &OriginalRestoredProducerExecutionClaim<'_>,
        inspect: &mut dyn FnMut(
            &OriginalRestoredProducerReportReadScope<'_>,
        ) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        self.current().map_err(|_| RuntimeError::OwnerUnavailable)?;
        let native = self
            .preparation
            .guard
            .custody
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let source = native
            .source
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let controller = native
            .controller
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let selected = native
            .runtime
            .as_mut()
            .and_then(|runtime| runtime.installed_restoration.as_mut())
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let attempt = selected
            .producer_executions
            .last_data(original.token(), claim)?;
        if attempt.stage != Stage::Completed {
            return Err(RuntimeError::OutstandingObligations);
        }
        selected
            .association
            .with_original_producer_execution_source_data(
                source.as_ref(),
                controller as *const _,
                Rc::as_ptr(&native.read_owner).cast(),
                claim,
                |source, inputs| {
                    source.with_original_restored_producer_report_data(
                        controller, inputs, claim, original, inspect,
                    )
                },
            )
    }

    pub(in crate::node_adapters::cnp::semantic) fn retire_installed_producer_execution_data(
        &mut self,
        token: &OperationToken,
        outputs: &[crucible_node_contract::Id],
        claim: &OriginalRestoredProducerExecutionClaim<'_>,
    ) -> Result<(), OperationFailure> {
        self.try_retire_installed_producer_execution_data(token, outputs, claim)
            .map_err(failure)
    }

    fn try_retire_installed_producer_execution_data(
        &mut self,
        token: &OperationToken,
        outputs: &[crucible_node_contract::Id],
        claim: &OriginalRestoredProducerExecutionClaim<'_>,
    ) -> Result<(), RuntimeError> {
        self.current().map_err(|_| RuntimeError::OwnerUnavailable)?;
        let native = self
            .preparation
            .guard
            .custody
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let source = native
            .source
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let controller = native
            .controller
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let selected = native
            .runtime
            .as_mut()
            .and_then(|runtime| runtime.installed_restoration.as_mut())
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let attempt = selected.producer_executions.last_data(token, claim)?;
        if attempt.stage != Stage::Completed
            || attempt
                .retained
                .as_ref()
                .is_none_or(|outcome| outcome.retained_outputs != outputs)
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        attempt.stage = Stage::Retiring;
        let result = selected
            .association
            .with_original_producer_execution_source_data(
                source.as_ref(),
                controller as *const _,
                Rc::as_ptr(&native.read_owner).cast(),
                claim,
                |source, inputs| {
                    source.call_original_restored_producer_retire_data(
                        controller,
                        inputs,
                        claim,
                        &attempt.admission,
                    )
                },
            );
        attempt.stage = if result.is_ok() {
            Stage::Retired
        } else {
            Stage::Failed
        };
        result
    }

    pub(in crate::node_adapters::cnp::semantic) fn observe_installed_producer_checkpoint_data(
        &mut self,
        original: &OperationAdmission,
        claim: &OriginalRestoredProducerExecutionClaim<'_>,
    ) -> Result<NativeSchedulingObservation, OperationFailure> {
        self.try_observe_installed_producer_checkpoint_data(original, claim)
            .map_err(failure)
    }

    fn try_observe_installed_producer_checkpoint_data(
        &mut self,
        original: &OperationAdmission,
        claim: &OriginalRestoredProducerExecutionClaim<'_>,
    ) -> Result<NativeSchedulingObservation, RuntimeError> {
        self.current().map_err(|_| RuntimeError::OwnerUnavailable)?;
        let native = self
            .preparation
            .guard
            .custody
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let source = native
            .source
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let controller = native
            .controller
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let selected = native
            .runtime
            .as_mut()
            .and_then(|runtime| runtime.installed_restoration.as_mut())
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let attempt = selected
            .producer_executions
            .last_data(original.token(), claim)?;
        if attempt.stage != Stage::Retired {
            return Err(RuntimeError::OutstandingObligations);
        }
        attempt.stage = Stage::Observing;
        let result = selected
            .association
            .with_original_producer_execution_source_data(
                source.as_ref(),
                controller as *const _,
                Rc::as_ptr(&native.read_owner).cast(),
                claim,
                |source, inputs| {
                    source.call_original_restored_producer_observe_into(
                        controller,
                        inputs,
                        claim,
                        &attempt.admission,
                        &mut attempt.scheduling,
                        &mut attempt.scheduling_return,
                    )
                },
            );
        attempt.stage = if result.is_ok() {
            Stage::Verified
        } else {
            Stage::Failed
        };
        result?;
        attempt
            .scheduling_return
            .take()
            .ok_or(RuntimeError::InvalidReceipt)
    }
}

fn failure(_error: RuntimeError) -> OperationFailure {
    OperationFailure {
        effects: crate::node_contract::EffectKnowledge::MayHaveProgressed,
        reason: "restored Producer action failed under retained native custody".into(),
    }
}

pub(super) fn retained_data(
    history: &ProducerNodeHistory,
    maximum: usize,
) -> Result<usize, RuntimeError> {
    let mut bytes = history
        .attempts
        .capacity()
        .checked_mul(size_of::<Attempt>())
        .ok_or(RuntimeError::ResourceLimit)?;
    for attempt in history.pending.iter().chain(history.attempts.iter()) {
        let facts = attempt.admission.retained_requested_storage_data(maximum)?;
        bytes = storage::sum(&[bytes, facts.independent_bytes()], maximum)?;
        for allocation in facts.shared_allocations() {
            bytes = storage::sum(&[bytes, allocation.requested_bytes()], maximum)?;
        }
        for outcome in [&attempt.retained, &attempt.returned].into_iter().flatten() {
            bytes = storage::sum(
                &[
                    bytes,
                    crate::node_contract::NodeRuntime::capture_outcome_storage_data(
                        outcome, maximum,
                    )?,
                ],
                maximum,
            )?;
        }
        for observation in [&attempt.scheduling, &attempt.scheduling_return]
            .into_iter()
            .flatten()
        {
            bytes = storage::sum(
                &[
                    bytes,
                    crate::node_contract::NodeRuntime::capture_scheduling_observation_storage_data(
                        observation,
                        maximum,
                    )?,
                ],
                maximum,
            )?;
        }
    }
    Ok(bytes)
}

pub(super) fn counter_scratch_data() -> usize {
    use crate::node_contract::{
        NodeRuntime, RetainedCoreOwnerStorage, RetainedCoreSharedAllocation,
    };
    use std::{iter::Chain, option, slice};
    type Attempts = Chain<option::Iter<'static, Attempt>, slice::Iter<'static, Attempt>>;
    NodeRuntime::capture_opaque_owner_observer_scratch_data()
        + size_of::<ProducerNodeHistory>()
        + size_of::<Attempt>()
        + size_of::<Stage>()
        + size_of::<Vec<Attempt>>()
        + size_of::<Option<Attempt>>()
        + size_of::<Attempts>()
        + size_of::<Option<&Attempt>>()
        + size_of::<Option<&mut Attempt>>()
        + size_of::<Result<&mut Attempt, RuntimeError>>()
        + size_of::<&OperationAdmission>()
        + size_of::<&OperationToken>()
        + size_of::<&ExecutionAdmission>()
        + size_of::<&OriginalRuntimeOperationDispatch<'static>>()
        + size_of::<&OriginalRestoredProducerExecutionClaim<'static>>()
        + size_of::<&PacketNative5SourceLaunch>()
        + size_of::<&[u8]>()
        + size_of::<
            &mut dyn FnMut(
                &OriginalRestoredProducerReportReadScope<'_>,
            ) -> Result<(), RuntimeError>,
        >()
        + size_of::<OriginalRestoredProducerExecutionConstructionData>()
        + size_of::<Result<OriginalRestoredProducerExecutionConstructionData, RuntimeError>>()
        + size_of::<[&Option<OperationOutcome>; 2]>()
        + size_of::<std::array::IntoIter<&Option<OperationOutcome>, 2>>()
        + size_of::<std::iter::Flatten<std::array::IntoIter<&Option<OperationOutcome>, 2>>>()
        + size_of::<[&Option<NativeSchedulingObservation>; 2]>()
        + size_of::<std::array::IntoIter<&Option<NativeSchedulingObservation>, 2>>()
        + size_of::<std::iter::Flatten<std::array::IntoIter<&Option<NativeSchedulingObservation>, 2>>>(
        )
        + size_of::<RetainedCoreOwnerStorage<'static>>()
        + size_of::<Result<RetainedCoreOwnerStorage<'static>, RuntimeError>>()
        + size_of::<&RetainedCoreSharedAllocation>()
        + size_of::<Result<(), RuntimeError>>()
        + size_of::<Result<usize, RuntimeError>>()
        + size_of::<Option<usize>>()
        + size_of::<[usize; 2]>()
        + size_of::<Result<OperationOutcome, RuntimeError>>()
        + size_of::<Result<OperationOutcome, OperationFailure>>()
        + size_of::<Result<NativeSchedulingObservation, RuntimeError>>()
        + size_of::<Result<NativeSchedulingObservation, OperationFailure>>()
}

impl super::super::super::CnpSemanticNode {
    pub(crate) fn original_producer_execution_node_counter_scratch_data() -> usize {
        counter_scratch_data()
    }
}

impl super::super::super::CnpSemanticNode {
    pub(in crate::node_adapters::cnp::semantic) fn validate_installed_producer_deferred_data(
        &self,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
        publication: &crate::node_scheduling::NativePublication,
        prior: &OperationAdmission,
        prior_outcome: &OperationOutcome,
    ) -> Result<(), OperationFailure> {
        self.current()?;
        self.validate_installed_producer_outcome_data(original, outcome)?;
        let native = self
            .preparation
            .guard
            .custody
            .as_ref()
            .ok_or_else(|| failure(RuntimeError::OwnerUnavailable))?;
        let source = native
            .source
            .as_ref()
            .ok_or_else(|| failure(RuntimeError::OwnerUnavailable))?;
        let controller = native
            .controller
            .as_ref()
            .ok_or_else(|| failure(RuntimeError::OwnerUnavailable))?;
        let selected = native
            .runtime
            .as_ref()
            .and_then(|runtime| runtime.installed_restoration.as_ref())
            .ok_or_else(|| failure(RuntimeError::OwnerUnavailable))?;
        let current = selected
            .producer_executions
            .attempts
            .last()
            .ok_or_else(|| failure(RuntimeError::OwnerUnavailable))?;
        let mut matched = None;
        for attempt in &selected.producer_executions.attempts {
            if attempt.admission.token().same_authority(prior.token()) {
                if matched.replace(attempt).is_some() {
                    return Err(failure(RuntimeError::ForeignAuthority));
                }
            }
        }
        let old = matched.ok_or_else(|| failure(RuntimeError::ForeignAuthority))?;
        if old.stage != Stage::Verified
            || old.slot >= current.slot
            || old.retained.as_ref() != Some(prior_outcome)
            || old.admission.request() != prior.request()
            || !old
                .admission
                .activation()
                .same_authority(prior.activation())
            || !original.activation().same_authority(prior.activation())
        {
            return Err(failure(RuntimeError::InvalidReceipt));
        }
        selected
            .association
            .with_original_producer_deferred_source_data(
                source.as_ref(),
                controller,
                Rc::as_ptr(&native.read_owner).cast(),
                original.activation(),
                |source| {
                    source.authenticate_original_restored_producer_deferred_data(
                        controller,
                        original,
                        outcome,
                        publication,
                        prior,
                        prior_outcome,
                    )
                },
            )
            .map_err(failure)
    }
}

#[path = "producer_execution/capture_history.rs"]
mod capture_history;
pub(crate) use capture_history::OriginalRestoredSettledNodeHistoryView;

pub(crate) use capture_history::original_restored_settled_semantic_history_counter_scratch_data;

#[path = "producer_execution/capture17.rs"]
mod capture17;
