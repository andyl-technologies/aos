//! Checks completed controls against the source's predeclared request recipes.
//!
//! This check owns method semantics and native adapter phase. The separate typed
//! evidence reader authenticates original body closure; payload bytes remain
//! opaque and are compared with the independently computed checksum input.

use crucible::node_adapters::cnp::{CnpCompletedLifecyclePhase, CnpCompletedLifecycleScope};
use crucible_node_contract::{ContentRef, OperatingMode, OwnerBinding, Phase, Position, U64};
use crucible_node_provider::{
    ProviderError,
    bodies::{BeginArguments, BudgetOutcome, RequestBody, RetirementDisposition},
    client::RecordedReferenceObservation,
    reference_device::DeviceStatus,
};

use super::source_lifecycle_resend_plan::{OriginalLifecycleTarget, original_id};

/// Borrows exact source recipes and the independently retained original scope.
pub(super) struct SourceLifecycleRequestContext<'a> {
    pub(super) profile: &'a crucible_node_provider::reference_service::ReferenceProfile,
    pub(super) bootstrap: &'a crucible_node_provider::reference_service::ReferenceServiceBootstrap,
    pub(super) owner: &'a OwnerBinding,
    pub(super) target: &'a OriginalLifecycleTarget,
    pub(super) scope: &'a CnpCompletedLifecycleScope,
    pub(super) original: &'a RecordedReferenceObservation,
}

pub(super) struct SourceLifecycleRequests {
    input_bytes: Vec<u8>,
}

impl SourceLifecycleRequests {
    /// Reserves the fixed native input scratch space before process creation.
    ///
    /// # Errors
    /// Refuses failure to reserve the installed 4096-byte input ceiling.
    pub(super) fn reserve() -> Result<Self, ProviderError> {
        let mut input_bytes = Vec::new();
        input_bytes
            .try_reserve_exact(4096)
            .map_err(|_| ProviderError::ResourceExhausted("lifecycle input scratch"))?;
        Ok(Self { input_bytes })
    }

    /// Checks the original request against its fixed source recipe and phase.
    ///
    /// # Errors
    /// Refuses changed method, binding, window, sampling, native phase or input
    /// bytes. This data check cannot authorize progress or manufacture a receipt.
    pub(super) fn verify(
        &mut self,
        body: &RequestBody,
        context: SourceLifecycleRequestContext<'_>,
    ) -> Result<(), ProviderError> {
        let SourceLifecycleRequestContext {
            profile,
            bootstrap,
            owner,
            target,
            scope,
            original,
        } = context;
        let expected_status = match target.phase {
            CnpCompletedLifecyclePhase::Prepared
            | CnpCompletedLifecyclePhase::WorldActivated
            | CnpCompletedLifecyclePhase::InputAccepted
            | CnpCompletedLifecyclePhase::PublicationConsumed => DeviceStatus::Parked,
            CnpCompletedLifecyclePhase::WindowCompleted => DeviceStatus::Active,
            CnpCompletedLifecyclePhase::PublicationClosed => DeviceStatus::ClosedPending,
        };
        if scope.native_status != expected_status {
            return Err(changed());
        }
        match body {
            RequestBody::Activate(request)
                if target.phase == CnpCompletedLifecyclePhase::Prepared =>
            {
                if request.admission_id != bootstrap.admission_id
                    || request.activation_id != bootstrap.activation_id
                    || request.world_generation != bootstrap.world_generation
                    || request.prepared_token != bootstrap.prepared_token
                    || request.world_binding_hash != bootstrap.world_binding_hash
                    || request.gate_id != bootstrap.gate_id
                    || !request.extensions.is_empty()
                {
                    return Err(changed());
                }
            }
            RequestBody::WorldActivate(request)
                if target.phase == CnpCompletedLifecyclePhase::WorldActivated =>
            {
                if request.transaction_id != bootstrap.transaction_id
                    || request.activation_id != bootstrap.activation_id
                    || request.world_generation != bootstrap.world_generation
                    || request.prepared_token != bootstrap.prepared_token
                    || request.world_binding_hash != bootstrap.world_binding_hash
                    || request.gate_id != bootstrap.gate_id
                    || !request.extensions.is_empty()
                {
                    return Err(changed());
                }
            }
            RequestBody::Input(request)
                if target.phase == CnpCompletedLifecyclePhase::InputAccepted =>
            {
                let window = target.window.as_ref().ok_or_else(changed)?;
                if request.binding_hash != owner.identity()?
                    || request.owner_generation != window.grant.generation
                    || request.batch_id != window.grant.input_batch_id
                    || request.batch_sequence != window.input_sequence
                    || request.input_epoch != bootstrap.authority.input_epoch
                    || !request.extensions.is_empty()
                    || request.events.len() != usize::from(window.expected_input.length.get() != 0)
                {
                    return Err(changed());
                }
                self.input_bytes.clear();
                for event in &request.events {
                    if event
                        .delivery_position
                        .is_none_or(|delivery| delivery >= window.input_cut)
                        || !event.causal_parent_ids.is_empty()
                        || !event.extensions.is_empty()
                    {
                        return Err(changed());
                    }
                    let bytes = object(&event.payload, original)?;
                    if self
                        .input_bytes
                        .len()
                        .checked_add(bytes.len())
                        .is_none_or(|len| len > 4096)
                    {
                        return Err(ProviderError::ResourceExhausted("lifecycle native input"));
                    }
                    self.input_bytes.extend_from_slice(bytes);
                }
                window.expected_input.verify(&self.input_bytes)?;
            }
            RequestBody::Begin(request)
                if target.phase == CnpCompletedLifecyclePhase::WindowCompleted =>
            {
                let window = target.window.as_ref().ok_or_else(changed)?;
                let BeginArguments::QuantumBegin(arguments) = request.decoded_arguments()? else {
                    return Err(changed());
                };
                if request.binding_hash != owner.identity()?
                    || request.owner_generation != window.grant.generation
                    || request.activation_id.0.as_ref() != Some(&bootstrap.activation_id)
                    || request.world_generation != bootstrap.world_generation
                    || !request.extensions.is_empty()
                    || arguments.grant_id != window.grant.window_id
                    || arguments.participant_ids != profile.owner.participant_ids
                    || arguments.realization_id != bootstrap.authority.realization_id
                    || arguments.activation_id != bootstrap.activation_id
                    || arguments.world_generation != bootstrap.world_generation
                    || arguments.owner_generation != window.grant.generation
                    || arguments.input_epoch != bootstrap.authority.input_epoch
                    || arguments.mode != OperatingMode::Quantized
                    || arguments.ordering_profile != "superdense-v1"
                    || arguments.quantum_index != window.grant.quantum
                    || arguments.from_ps != window.grant.start.time_ps
                    || arguments.until_ps != window.grant.publication.time_ps
                    || arguments.input_watermark != window.input_sequence
                    || arguments.policy_hash != profile.operating_contract.policy_ref.hash
                    || arguments.wall_budget_ns != window.grant.host_budget_ns
                {
                    return Err(changed());
                }
            }
            RequestBody::QuantumClose(request)
                if target.phase == CnpCompletedLifecyclePhase::PublicationClosed =>
            {
                let window = target.window.as_ref().ok_or_else(changed)?;
                if request.grant_id != window.grant.window_id
                    || request.activation_id != bootstrap.activation_id
                    || request.world_generation != bootstrap.world_generation
                    || request.owner_generation != window.grant.generation
                    || request.input_epoch != bootstrap.authority.input_epoch
                    || request.quantum_index != window.grant.quantum
                    || request.participant_ids != profile.owner.participant_ids
                    || request.cut
                        != Position::new(
                            window.grant.publication.time_ps,
                            U64::new(0),
                            Phase::BoundaryControl,
                        )
                    || request.policy_hash != profile.operating_contract.policy_ref.hash
                    || request.input_watermark != window.input_sequence
                    || request.deadline_disposition != BudgetOutcome::WithinBudget
                    || !request.extensions.is_empty()
                {
                    return Err(changed());
                }
            }
            RequestBody::Retire(request)
                if target.phase == CnpCompletedLifecyclePhase::PublicationConsumed =>
            {
                let operation = target.operation.as_ref().ok_or_else(changed)?;
                if request.request_ids != [original_id("begin", operation)?]
                    || request.operation_ids != [operation.clone()]
                    || request.disposition != RetirementDisposition::Consumed
                    || request.custody_receipt.0.as_ref() != scope.evidence_roots.first()
                    || !request.extensions.is_empty()
                {
                    return Err(changed());
                }
            }
            _ => return Err(changed()),
        }
        Ok(())
    }
}

fn object<'a>(
    reference: &ContentRef,
    original: &'a RecordedReferenceObservation,
) -> Result<&'a [u8], ProviderError> {
    let mut selected = original
        .evidence
        .objects
        .iter()
        .filter(|object| &object.reference == reference);
    let object = selected.next().ok_or(ProviderError::Correlation(
        "original native input body absent",
    ))?;
    if selected.next().is_some() {
        return Err(ProviderError::Correlation(
            "original native input body duplicated",
        ));
    }
    reference.verify(object.bytes.as_slice())?;
    Ok(object.bytes.as_slice())
}

fn changed() -> ProviderError {
    ProviderError::Correlation("completed original source request or phase differs")
}
