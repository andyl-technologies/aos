//! Checks recovered original runtime custody after a real native window.
//!
//! This cohort exercises host caching and the original opaque committed ACK.
//! It does not resend a cached control across the socket and therefore supplies
//! no evidence of provider-side duplicate handling or reconnect recovery.

use std::task::{Context, Poll};

use crucible::{
    node_admission::AdmittedGraph,
    node_contract::{NodeRuntime, OperationOutcome, WorldActivation},
};
use crucible_node_contract::{Bytes, ContentRef, Id, U64, canonical};
use crucible_node_provider::ProviderError;
use serde::Serialize;

use crate::node_qualification::{ReferenceWindowCase, ReferenceWindowObservation};

/// Declares host recovery observations and their limits before native creation.
pub(super) fn fixture() -> serde_json::Value {
    serde_json::json!({
        "schema":"crucible.reference.runtime-cached-recovery-fixture.v1",
        "steps":["recover original operation token", "read original cached outcome and proof bodies after ACK", "recover original scheduling commit", "repeat the same acknowledged commit", "compare retained outcome/proofs and visible coordinator cursor/input roster"],
        "maximum_windows_per_owner":3,
        "maximum_proof_bytes":"69632",
        "maximum_visible_coordinator_bytes":1048576,
        "limitations":["host cached custody only", "no duplicate provider RPC or reconnect proof", "visible cursor/input comparison is not a complete coordinator capture", "no ordinary qualification or whole-clause verdict"]
    })
}

/// Retains exact observed commitments, without granting fresh native permission.
#[derive(Serialize)]
pub(super) struct RuntimeCachedRecovery {
    schema: &'static str,
    operation: Id,
    outcome: ContentRef,
    outcome_bytes: Bytes,
    original_receipt: ContentRef,
    original_payload: ContentRef,
    visible_coordinator: ContentRef,
    visible_coordinator_bytes: Bytes,
    acknowledged_outputs: Vec<Id>,
}

/// Checks an original acknowledged operation under its genuine recovered token.
///
/// # Errors
/// Refuses unavailable tokens, changed original outcome/proof/commit scopes,
/// incomplete reads, failed repeated ACKs or changed visible coordinator state.
/// The caller retains the original native runtime on every failure.
pub(super) fn collect(
    runtime: &mut NodeRuntime,
    graph: &AdmittedGraph,
    activation: &WorldActivation,
    case: &ReferenceWindowCase,
    window: &ReferenceWindowObservation,
    context: &mut Context<'_>,
) -> Result<RuntimeCachedRecovery, ProviderError> {
    let original = runtime.recover(&case.operation).map_err(diagnostic)?;
    let recovered = runtime.recover(&case.operation).map_err(diagnostic)?;
    if !original.same_authority(&recovered)
        || recovered.route().node != case.node
        || recovered.operation() != &case.operation
        || window.original_grant != case.grant
    {
        return Err(refused());
    }
    let before = outcome(runtime, &original, context)?;
    let references = [window.receipt.clone(), window.payload.clone()];
    let proof = runtime
        .operation_evidence(&original, &references, U64::new(69_632))
        .map_err(diagnostic)?;
    if proof.len() != 2
        || proof[0].reference != window.receipt
        || proof[0].bytes != window.receipt_bytes.as_slice()
        || proof[1].reference != window.payload
        || proof[1].bytes != window.payload_bytes.as_slice()
    {
        return Err(refused());
    }
    let visible = coordinator(runtime, graph, activation)?;
    let committed = runtime
        .recover_scheduling_commit(&original)
        .map_err(diagnostic)?;
    if committed.operation() != &case.operation
        || committed.retained_outputs() != before.retained_outputs
    {
        return Err(refused());
    }
    runtime
        .acknowledge_scheduled(&recovered, &committed)
        .map_err(diagnostic)?;
    let retained = outcome(runtime, &recovered, context)?;
    let after = runtime
        .operation_evidence(&recovered, &references, U64::new(69_632))
        .map_err(diagnostic)?;
    let recovered_commit = runtime
        .recover_scheduling_commit(&recovered)
        .map_err(diagnostic)?;
    if retained != before
        || after != proof
        || recovered_commit.operation() != committed.operation()
        || recovered_commit.retained_outputs() != committed.retained_outputs()
        || coordinator(runtime, graph, activation)? != visible
    {
        return Err(refused());
    }
    let bytes = canonical::canonical_json(
        &serde_json::to_value(before).map_err(crucible_node_contract::ContractError::from)?,
    )?;
    Ok(RuntimeCachedRecovery {
        schema: "crucible.reference.runtime-cached-recovery.v1",
        operation: case.operation.clone(),
        outcome: canonical::content_ref(&bytes, "application/json")?,
        outcome_bytes: Bytes::new(bytes),
        original_receipt: window.receipt.clone(),
        original_payload: window.payload.clone(),
        visible_coordinator: canonical::content_ref(&visible, "application/json")?,
        visible_coordinator_bytes: Bytes::new(visible),
        acknowledged_outputs: committed.retained_outputs().to_vec(),
    })
}

fn outcome(
    runtime: &mut NodeRuntime,
    token: &crucible::node_contract::OperationToken,
    context: &mut Context<'_>,
) -> Result<OperationOutcome, ProviderError> {
    match runtime.poll(token, context) {
        Poll::Ready(Ok(original)) => Ok(original),
        Poll::Ready(Err(error)) => Err(diagnostic(error)),
        Poll::Pending => Err(refused()),
    }
}

fn coordinator(
    runtime: &mut NodeRuntime,
    graph: &AdmittedGraph,
    activation: &WorldActivation,
) -> Result<Vec<u8>, ProviderError> {
    let scheduler = runtime.scheduler(graph, activation).map_err(diagnostic)?;
    let mut rows = Vec::with_capacity(2);
    for node in graph.node_ids() {
        if rows.len() >= 2 {
            return Err(refused());
        }
        rows.push(serde_json::json!({
            "node":node,
            "cursor":scheduler.position(node).map_err(diagnostic)?,
            "pending_inputs":scheduler.pending_inputs(node).map_err(diagnostic)?,
        }));
    }
    let bytes = canonical::canonical_json(&serde_json::json!({
        "schema":"crucible.reference.visible-coordinator-recovery.v1",
        "world":activation.record().world_binding_hash,
        "rows":rows,
    }))?;
    if bytes.len() > 1024 * 1024 {
        return Err(refused());
    }
    Ok(bytes)
}

fn diagnostic(error: impl std::fmt::Display) -> ProviderError {
    ProviderError::Io(std::io::Error::other(format!(
        "original runtime cached recovery: {error}"
    )))
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original runtime cached recovery differs")
}
