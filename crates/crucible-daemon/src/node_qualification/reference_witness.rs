//! Collects original common-runtime checksum windows for the installed issuer.
//!
//! Collection uses the already activated, sealed graph and original runtime
//! operation/input tokens. It does not create native permission from receipt
//! bytes. The complete-world publisher, native installer and finite controller
//! observation archive remain separate, mandatory issuance prerequisites.

use std::task::{Context, Poll};

use crucible::{
    node_admission::AdmittedGraph,
    node_contract::{BeginResult, NodeRuntime, ProgressEvidence, Submission, WorldActivation},
    node_scheduling::ExecutionPolicy,
};
use crucible_node_contract::{Bytes, Id, Position, U64};
use crucible_node_provider::reference_device::DeviceGrant;

use super::{QualificationError, ReferenceWindowObservation};

/// Fixes original control identities before the corresponding native effect.
pub struct ReferenceWindowCase {
    /// Names the actual enrolled public reference node in the sealed graph.
    pub node: Id,
    /// Names the original input-staging operation.
    pub stage: Id,
    /// Names the immutable original input batch.
    pub batch: Id,
    /// Names the original runtime execution operation.
    pub operation: Id,
    /// Specifies the complete predeclared native window and installed budget.
    pub grant: DeviceGrant,
    /// Specifies the original exclusive input sampling cut.
    pub input_cut: Position,
}

/// Collects one installed synchronous reference window under actual custody.
///
/// Input preparation and original acknowledgments use the single retained
/// coordinator. The result carries raw original proof and payload bytes read
/// under the authentic runtime token before native output acknowledgment.
/// Any uncertain or unexpected result refuses collection while the caller's
/// runtime retains all original native, operation and input custody.
///
/// # Errors
/// Refuses changed native owner or original case identity, unsafe input/grant
/// admission, incomplete staging, unresolved begin/close/acknowledgment, missing
/// original receipt bodies, changed publication metadata or exhausted credits.
pub fn collect_reference_window(
    runtime: &mut NodeRuntime,
    graph: &AdmittedGraph,
    activation: &WorldActivation,
    case: &ReferenceWindowCase,
    context: &mut Context<'_>,
) -> Result<ReferenceWindowObservation, QualificationError> {
    let binding = graph
        .binding(&case.node)
        .ok_or(QualificationError::Refused(
            "installed witness node unavailable",
        ))?;
    if binding.compatibility.execution_owner.id != case.grant.owner_id
        || binding.authority.incarnation_id != case.grant.incarnation_id
        || binding.authority.owner_generation != case.grant.generation
        || case.batch != case.grant.input_batch_id
        || activation.record().world_binding_hash != *graph.world_binding_hash()
    {
        return Err(QualificationError::Refused(
            "changed installed witness case scope",
        ));
    }
    let Some(ExecutionPolicy::Quantized {
        quantum_ps,
        host_budget_ns,
        ..
    }) = graph.operating_policy(&case.node)
    else {
        return Err(QualificationError::Refused(
            "installed witness requires quantized policy",
        ));
    };
    let cursor = runtime
        .scheduler(graph, activation)
        .map_err(native_failure)?
        .position(&case.node)
        .map_err(native_failure)?;
    if cursor.time_ps != case.grant.start.time_ps
        || case.grant.start.time_ps.checked_add(*quantum_ps)? != case.grant.publication.time_ps
        || *host_budget_ns != case.grant.host_budget_ns
    {
        return Err(QualificationError::Refused(
            "changed predeclared witness clock or budget",
        ));
    }

    let staged = runtime
        .scheduler(graph, activation)
        .map_err(native_failure)?
        .prepare_input_batch(
            &case.node,
            case.stage.clone(),
            case.batch.clone(),
            case.input_cut,
        )
        .map_err(native_failure)?;
    let mut bytes = Vec::new();
    for delivery in staged.deliveries() {
        let payload = staged
            .payloads()
            .iter()
            .find(|object| object.reference == delivery.payload)
            .ok_or(QualificationError::Refused(
                "original witness input unavailable",
            ))?;
        payload.reference.verify(&payload.bytes)?;
        let total = bytes
            .len()
            .checked_add(payload.bytes.len())
            .ok_or(QualificationError::Refused("witness native input overflow"))?;
        if total > 4096 {
            return Err(QualificationError::Refused("witness native input ceiling"));
        }
        bytes
            .try_reserve_exact(payload.bytes.len())
            .map_err(|_| QualificationError::Refused("witness input allocation"))?;
        bytes.extend_from_slice(&payload.bytes);
    }
    runtime.stage_inputs(staged).map_err(native_failure)?;
    let retained = runtime
        .recover_input_staging(activation, &case.stage)
        .map_err(native_failure)?;
    let input_commit = runtime
        .commit_input_acknowledgement(retained)
        .map_err(native_failure)?;
    runtime
        .commit_input_staging(&input_commit)
        .map_err(native_failure)?;

    let grant = runtime
        .scheduler(graph, activation)
        .map_err(native_failure)?
        .admit_quantum(
            &case.node,
            case.operation.clone(),
            case.grant.window_id.clone(),
            case.batch.clone(),
        )
        .map_err(native_failure)?;
    if grant.start() != case.grant.start || grant.limit() != case.grant.publication {
        return Err(QualificationError::Refused(
            "original witness grant differs from fixture",
        ));
    }
    let BeginResult::Accepted(token) = runtime.begin_admitted(grant).map_err(native_failure)?
    else {
        return Err(QualificationError::Refused(
            "original witness begin unresolved",
        ));
    };
    if !matches!(runtime.poll(&token, context), Poll::Pending)
        || runtime.close_quantum(&token).map_err(native_failure)? != Submission::Accepted
    {
        return Err(QualificationError::Refused(
            "original witness close unresolved",
        ));
    }
    let outcome = match runtime.poll(&token, context) {
        Poll::Ready(Ok(outcome)) => outcome,
        Poll::Ready(Err(error)) => return Err(native_failure(error)),
        Poll::Pending => {
            return Err(QualificationError::Refused(
                "original witness outcome pending",
            ));
        }
    };
    let ProgressEvidence::Quantized {
        window,
        publication,
        closure,
        ..
    } = &outcome.progress
    else {
        return Err(QualificationError::Refused(
            "original witness lacks quantum closure",
        ));
    };
    let scheduling = outcome
        .scheduling
        .as_ref()
        .ok_or(QualificationError::Refused(
            "original witness scheduling unavailable",
        ))?;
    if window != &case.grant.window_id
        || publication != &case.grant.publication
        || closure.input_batch != case.batch
        || scheduling.publications.len() != 1
    {
        return Err(QualificationError::Refused(
            "changed original witness publication",
        ));
    }
    let publication = &scheduling.publications[0];
    if publication.publication != case.grant.publication {
        return Err(QualificationError::Refused(
            "changed original witness birth",
        ));
    }
    let references = [closure.close_receipt.clone(), publication.payload.clone()];
    let objects = runtime
        .operation_evidence(&token, &references, U64::new(69_632))
        .map_err(native_failure)?;
    if objects.len() != 2
        || objects[0].reference != references[0]
        || objects[1].reference != references[1]
    {
        return Err(QualificationError::Refused(
            "original witness proof unavailable",
        ));
    }
    let observation = ReferenceWindowObservation {
        original_grant: case.grant.clone(),
        input: Bytes::new(bytes),
        receipt: objects[0].reference.clone(),
        receipt_bytes: Bytes::new(objects[0].bytes.clone()),
        payload: objects[1].reference.clone(),
        payload_bytes: Bytes::new(objects[1].bytes.clone()),
    };

    let receipt = runtime.scheduling_receipt(&token).map_err(native_failure)?;
    let committed = runtime
        .commit_scheduling_receipt(receipt)
        .map_err(native_failure)?;
    runtime
        .acknowledge_scheduled(&token, &committed)
        .map_err(native_failure)?;
    Ok(observation)
}

fn native_failure(error: impl std::fmt::Display) -> QualificationError {
    QualificationError::Evidence(format!("original installed witness: {error}"))
}
