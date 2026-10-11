//! Pairs owning source windows with original opaque common-runtime permissions.
//!
//! The borrowed association preserves producer-local IDs, native FIFO, source
//! scope and every ordered input range. It grants no installed source class or
//! readiness. Cumulative checksum ancestry remains distinct from actual same-time
//! causal parents; unsupported parent-ID mappings still refuse.

use std::rc::Rc;

use crucible_node_contract::{EventStage, Validate};
use crucible_node_provider::{
    ProviderError,
    client::{LineageWindowRequests, OriginalLineageWindow},
    reference_lineage::LineageSourceGuard,
};

use crate::{
    node_contract::{
        OperationAdmission, OperationRequest, OriginalCompletedOperation, ProgressEvidence,
    },
    node_scheduling::RuntimeInputBatch,
};

/// Borrows genuine source custody paired with its original common permission.
///
/// Only the original owning guard can provide the source window. Its original
/// native command, received output, public input and native byte ranges must all
/// agree with the opaque coordinator-issued input and operation handles. This
/// association is historical evidence for a separately installed source adopter;
/// a portable relation or matching position cannot construct it.
pub struct OriginalRuntimeLineage<'a> {
    operation: &'a OperationAdmission,
    input: &'a RuntimeInputBatch,
    source: OriginalLineageWindow<'a>,
}

impl OriginalRuntimeLineage<'_> {
    /// Returns the original local operation authority and complete world activation.
    pub fn operation(&self) -> &OperationAdmission {
        self.operation
    }

    /// Returns the exact frozen input roster, including original producer scope.
    pub fn input(&self) -> &RuntimeInputBatch {
        self.input
    }

    /// Borrows the owning source's original raw native and public evidence.
    pub fn source(&self) -> &OriginalLineageWindow<'_> {
        &self.source
    }
}

/// Runs a trusted read-only adopter against genuine original runtime/source custody.
///
/// Original semantic IDs are compared under the installed request mapping;
/// none are replaced to match a current owner or a parsed source label. Native
/// output stays beneath the owning guard throughout callback execution/unwind.
/// The callback must independently authenticate the distinct installed package,
/// native kernel/limit closure and enrolled profile before issuing source class.
///
/// # Errors
/// Refuses another local activation, absent original input, changed original
/// request identity, owner, full grant, ordered public events or native ranges.
/// Existing ambiguous same-time parent mappings refuse explicitly. Original
/// source-custody and callback errors propagate without releasing either group.
pub fn with_original_runtime_lineage<T>(
    guard: &LineageSourceGuard,
    requests: LineageWindowRequests<'_>,
    operation: &OperationAdmission,
    adopt: impl FnOnce(OriginalRuntimeLineage<'_>) -> Result<T, ProviderError>,
) -> Result<T, ProviderError> {
    let input = operation.inputs().ok_or_else(invalid)?;
    if requests.input != &super::control::original_id("input", input.stage_operation())?
        || requests.begin != &super::control::original_id("begin", operation.token().operation())?
        || !Rc::ptr_eq(
            &input.activation().authority,
            &operation.activation().authority,
        )
        || input.activation().record() != operation.activation().record()
        || input.node() != &operation.token().route().node
        || input.owners() != operation.token().route().owners
        || input.deliveries().len() > 64
    {
        return Err(invalid());
    }
    guard.with_original_window(requests, |source| {
        validate_operation(operation, input, &source)?;
        validate_input(input, &source)?;
        adopt(OriginalRuntimeLineage {
            operation,
            input,
            source,
        })
    })
}

fn validate_operation(
    operation: &OperationAdmission,
    input: &RuntimeInputBatch,
    source: &OriginalLineageWindow<'_>,
) -> Result<(), ProviderError> {
    let OperationRequest::QuantumBegin {
        window,
        start,
        end,
        input_batch,
        host_budget,
    } = operation.request()
    else {
        return Err(invalid());
    };
    let [owner] = operation.token().route().owners.as_slice() else {
        return Err(invalid());
    };
    let grant = &source.native_receipt().grant;
    let stop = source.stop();
    let activation = operation.activation().record();
    if grant.owner_id != owner.owner
        || grant.incarnation_id != owner.incarnation
        || grant.generation != owner.generation
        || &grant.window_id != window
        || grant.start != *start
        || grant.publication != *end
        || &grant.input_batch_id != input_batch
        || input_batch != input.batch()
        || u64::try_from(host_budget.as_nanos()).ok() != Some(grant.host_budget_ns.get())
        || &stop.operation_id != operation.token().operation()
        || stop.activation_id != activation.activation_id
        || stop.world_generation != activation.generation
        || stop.world_binding_hash != activation.world_binding_hash
        || source.input_batch().execution_owner_id != owner.owner
        || &source.input_batch().batch_id != input.batch()
    {
        return Err(invalid());
    }
    Ok(())
}

fn validate_input(
    input: &RuntimeInputBatch,
    source: &OriginalLineageWindow<'_>,
) -> Result<(), ProviderError> {
    let public = source.input_batch();
    public.validate()?;
    let stage = source.native_stage();
    if public.events.len() != input.deliveries().len()
        || stage.entries.len() != public.events.len()
        || &stage.original_batch != source.input_batch_reference()
    {
        return Err(invalid());
    }
    for ((delivery, event), range) in input
        .deliveries()
        .iter()
        .zip(&public.events)
        .zip(&stage.entries)
    {
        // No producer-local scalar ID is inferred from a Position. This selected
        // path supports genuine empty native same-time parent sets until a
        // separately authenticated scoped association codec can represent them.
        if !delivery.causal_parents.is_empty()
            || !event.causal_parent_ids.is_empty()
            || delivery.producer != event.source.node_id
            || delivery.consumer != event.destination.node_id
            || &delivery.consumer != input.node()
            || event.id != delivery.publication_id
            || event.source != delivery.producer_endpoint
            || event.destination != delivery.consumer_endpoint
            || event.source_sequence != delivery.native_sequence
            || event.stage != EventStage::Delivery
            || event.position != delivery.delivery
            || event.publication_position != delivery.publication
            || event.delivery_position != Some(delivery.delivery)
            || event.payload != delivery.payload
            || event.provenance_ref != delivery.provenance_ref
            || range.payload != delivery.payload
        {
            return Err(invalid());
        }
        let payload = input
            .payloads()
            .iter()
            .find(|payload| payload.reference == delivery.payload)
            .ok_or_else(invalid)?;
        payload.reference.verify(&payload.bytes)?;
        let start = usize::try_from(range.byte_start.get()).map_err(|_| invalid())?;
        let end = usize::try_from(range.byte_end.get()).map_err(|_| invalid())?;
        if stage.input.get(start..end) != Some(payload.bytes.as_slice()) {
            return Err(invalid());
        }
    }
    Ok(())
}

fn invalid() -> ProviderError {
    ProviderError::Correlation("original runtime lineage/source association differs")
}

/// Pairs an actual runtime-retained completion with its owning native source window.
///
/// The runtime view selects the original accepted terminal outcome, rather than
/// accepting a caller-provided observation DTO. Native source/kernel custody and
/// the installed adopter remain mandatory. Cumulative input ancestry does not
/// supply same-time scalar causal parents or current readiness.
///
/// # Errors
/// Refuses a nonquantized completion or changed original operation, output,
/// measurement proof, payload bytes, source endpoint, publication or native FIFO.
/// Original input/native range checks and installed callback refusals propagate.
pub fn with_completed_runtime_lineage<T>(
    guard: &LineageSourceGuard,
    requests: LineageWindowRequests<'_>,
    completed: &OriginalCompletedOperation<'_>,
    adopt: impl FnOnce(OriginalRuntimeLineage<'_>) -> Result<T, ProviderError>,
) -> Result<T, ProviderError> {
    with_original_runtime_lineage(guard, requests, completed.admission(), |original| {
        let outcome = completed.outcome();
        let source = original.source();
        let ProgressEvidence::Quantized {
            window,
            publication,
            ..
        } = &outcome.progress
        else {
            return Err(invalid());
        };
        let scheduling = outcome.scheduling.as_ref().ok_or_else(invalid)?;
        let [event] = source.observation().events.as_slice() else {
            return Err(invalid());
        };
        let [native] = scheduling.publications.as_slice() else {
            return Err(invalid());
        };
        if outcome.operation != *original.operation().token().operation()
            || outcome.node != original.operation().token().route().node
            || outcome.owners != original.operation().token().route().owners
            || window != &source.native_receipt().grant.window_id
            || publication != &source.native_receipt().grant.publication
            || scheduling.proof_ref != *source.measurement_reference()
            || scheduling.node != outcome.node
            || scheduling.owners != outcome.owners
            || native.publication_id != event.id
            || native.endpoint != event.source
            || native.native_sequence != event.source_sequence
            || native.publication != event.publication_position
            || native.payload != event.payload
            || !native.causal_parents.is_empty()
            || !event.causal_parent_ids.is_empty()
            || outcome.retained_outputs != [native.publication_id.clone()]
        {
            return Err(invalid());
        }
        native.payload.verify(&native.payload_bytes)?;
        if guard.content(&event.payload)? != native.payload_bytes {
            return Err(invalid());
        }
        adopt(original)
    })
}
