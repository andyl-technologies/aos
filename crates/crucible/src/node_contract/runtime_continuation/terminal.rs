//! Closed terminal-bearing runtime ledger validation without minting authority.

use super::*;
use crate::node_contract::ProgressEvidence;
use crucible_node_contract::canonical;

pub(super) fn validate(snapshot: &RuntimeSnapshot) -> Result<(), RuntimeError> {
    let terminal_operations: Vec<_> = snapshot
        .operations
        .iter()
        .filter(|operation| {
            matches!(
                operation.request,
                OperationRequest::FinalizeAssertions { .. }
            ) || matches!(&operation.result,
                SavedRuntimeResult::Complete(outcome) | SavedRuntimeResult::Acknowledged(outcome)
                if matches!(outcome.progress, ProgressEvidence::AssertionsFinalized { .. }))
        })
        .collect();
    let Some(saved) = &snapshot.terminal else {
        return if terminal_operations.is_empty() {
            Ok(())
        } else {
            Err(RuntimeError::InvalidReceipt)
        };
    };
    let record = &saved.record;
    let bytes = canonical::canonical_json(
        &serde_json::to_value(record).map_err(|_| RuntimeError::InvalidReceipt)?,
    )
    .map_err(|_| RuntimeError::InvalidReceipt)?;
    saved
        .reference
        .verify(&bytes)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    if snapshot.schema_version != 3
        || record.version != 1
        || record.source.world_binding_hash != snapshot.source_activation.world_binding_hash
        || record.source.generation > snapshot.source_activation.generation
        || record.cut != snapshot.capture_cut
        || record
            .native
            .windows(2)
            .any(|pair| pair[0].node >= pair[1].node)
        || saved.report.is_some() != saved.publication.is_some()
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    for inventory in &record.native {
        inventory
            .receipt
            .reference
            .verify(&inventory.receipt.bytes)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        if inventory.boundary > record.cut || inventory.receipt.bytes.is_empty() {
            return Err(RuntimeError::InvalidReceipt);
        }
    }
    let owners: Vec<_> = record
        .native
        .iter()
        .flat_map(|inventory| &inventory.owners)
        .cloned()
        .collect();
    let mut owners_sorted = owners.clone();
    owners_sorted.sort();
    owners_sorted.dedup();
    if owners_sorted != record.source.owners
        || record
            .native
            .iter()
            .any(|inventory| inventory.owners.windows(2).any(|pair| pair[0] >= pair[1]))
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    if !saved.submitted {
        return if terminal_operations.is_empty() && saved.report.is_none() && !saved.acknowledged {
            Ok(())
        } else {
            Err(RuntimeError::InvalidReceipt)
        };
    }
    if terminal_operations.len() != 1 {
        return Err(RuntimeError::InvalidReceipt);
    }
    let original = terminal_operations[0];
    if original.operation != record.operation
        || original.route.node != record.node
        || original.input_batch.is_some()
        || original.scheduling_commit.is_some()
        || !matches!(&original.request, OperationRequest::FinalizeAssertions { barrier, receipt }
            if **barrier == *record && *receipt == saved.reference)
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    let outcome = match &original.result {
        SavedRuntimeResult::Complete(outcome) | SavedRuntimeResult::Acknowledged(outcome) => {
            outcome
        }
        _ if saved.report.is_none() && !saved.acknowledged => return Ok(()),
        _ => return Err(RuntimeError::InvalidReceipt),
    };
    let ProgressEvidence::AssertionsFinalized {
        reached,
        barrier,
        report,
    } = &outcome.progress
    else {
        return Err(RuntimeError::InvalidReceipt);
    };
    if *reached != record.cut
        || *barrier != saved.reference
        || !outcome.retained_outputs.is_empty()
        || outcome.scheduling.is_some()
        || saved.acknowledged != matches!(original.result, SavedRuntimeResult::Acknowledged(_))
        || (saved.acknowledged
            && saved.publication != Some(crate::node_contract::TerminalPublicationState::Committed))
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    if let Some(payload) = &saved.report {
        payload
            .reference
            .verify(&payload.bytes)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        if payload.reference != *report || payload.bytes.is_empty() {
            return Err(RuntimeError::InvalidReceipt);
        }
    }
    Ok(())
}
