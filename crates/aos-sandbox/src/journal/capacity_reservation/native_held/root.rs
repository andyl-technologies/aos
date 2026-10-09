//! DATA framing of the actual native Root proposal and its exact capacity edge.
//!
//! This module uses Protocol's concrete namespace-40 reducer output rather than
//! reimplementing its canonical graph. Protected origin, hot cuts, signing and
//! actual commit/readback remain unavailable in this pure adapter.

use aos_sandbox_protocol::mount_source_acquisition_state::native_held_completion::{
    RootNativeHeldTransitionV1, RootNativeTransitionKindV1 as Kind,
};

use super::super::super::{
    JournalError, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace,
    validate_transaction,
};
use super::{
    NativeHeldCapacityAppendV3, NativeHeldCapacityChangeV3, NativeHeldCapacityPurposeV3,
    NativeHeldCapacityRecordV3, NativeHeldCapacityRequestV3, NativeHeldCapacityStepV3 as Step,
    invalid,
};

/// Frames the complete original Root reservation and native8 row in one append.
///
/// The proposal must be freshly derived by Protocol's complete native Root
/// graph reducer. This produces DATA only; no protected method admits it and
/// no descriptor, currentness, signing or manager authority is returned.
///
/// # Errors
///
/// Rejects a late sidecar-only admission, wrong original concrete binding,
/// missing before-images, changed transaction identity, count or journal bound.
pub fn root_native_capacity_admission_v3(
    proposal: &RootNativeHeldTransitionV1,
    capacity: &NativeHeldCapacityRecordV3,
    limits: JournalLimits,
) -> Result<JournalTransaction, JournalError> {
    let binding = proposal
        .admission_binding
        .as_ref()
        .ok_or(invalid("native Root admission binding absent"))?;
    let request = capacity.request();
    let mut widths = proposal.puts.keys().map(Vec::len).collect::<Vec<_>>();
    widths.sort_unstable();
    if proposal.kind != Kind::PreparedAssertionRecorded
        || (widths != [52, 64, 66, 68, 75] && widths != [52, 64, 66, 68, 69, 75])
        || proposal.maximum_remaining_transactions != 7
        || request.purpose != NativeHeldCapacityPurposeV3::Root
        || request.owner_id != binding.mount_attempt
        || request.owner_digest != binding.reserved_attempt_digest
        || request.operation_id != binding.mount_operation.operation_id
        || request.artifact_digest != binding.signed_request_digest
        || request.checkpoint_digest != *binding.prepared_root_digest.as_bytes()
        || request.chain_head_digest != binding.reserved_head_digest
        || request.future_transactions != 7
        || capacity.admission_transaction_id() != proposal.transaction_id
    {
        return Err(invalid(
            "native Root capacity does not join atomic original admission",
        ));
    }
    let mut records = proposal_records(proposal)?;
    records.push(capacity.to_journal_record());
    let transaction = JournalTransaction::new(proposal.transaction_id, records)?;
    validate_transaction(&transaction, limits)?;
    Ok(transaction)
}

/// Adapts exact Root proposal before/after bytes for complete suffix measurement.
///
/// # Errors
///
/// Rejects admission/duplicate rather than counting another transaction, missing
/// or unchanged before-images, or a wrong concrete native row shape.
pub fn root_native_capacity_append_v3(
    proposal: &RootNativeHeldTransitionV1,
) -> Result<NativeHeldCapacityAppendV3, JournalError> {
    let step = match proposal.kind {
        Kind::PreparedStored => Step::RootPreparedStored,
        Kind::HeldStored => Step::RootHeldStored,
        Kind::ResponseDispositionRecorded => Step::RootDispositionCas,
        Kind::AcceptedAssertionRecorded | Kind::ClosedAssertionRecorded => {
            Step::RootDispositionPrepared
        }
        Kind::DispositionStored => Step::RootDispositionStored,
        Kind::TerminalRecorded => Step::RootTerminalProofStored,
        Kind::TerminalAckStored => Step::RootTerminalAckStored,
        Kind::PreparedAssertionRecorded | Kind::Duplicate => {
            return Err(JournalError::InvalidTransaction);
        }
    };
    proposal_records(proposal)?;
    let changes = proposal
        .puts
        .iter()
        .map(|(key, value)| {
            NativeHeldCapacityChangeV3::new(
                key.clone(),
                proposal
                    .before_images
                    .get(key)
                    .ok_or(invalid("native Root exact before-image absent"))?
                    .clone(),
                Some(value.clone()),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    NativeHeldCapacityAppendV3::new(step, proposal.transaction_id, changes)
}

/// Frames one native Root continuation or its actual final capacity deletion.
///
/// All immutable original bindings and admission identity stay unchanged. The
/// next count is compared with the actual Root reducer's closed remaining
/// ceiling; budgets must include the consumed fully framed capacity edge.
/// This DATA function grants no protected transfer or settlement scope.
///
/// # Errors
///
/// Rejects a foreign/rewritten old row, fresh admission or duplicate, unproved
/// count reduction, missing successor floor, premature deletion, enlarged
/// budgets, or unchanged journal transaction-limit violations.
pub fn root_native_capacity_transition_v3(
    proposal: &RootNativeHeldTransitionV1,
    old: &NativeHeldCapacityRecordV3,
    next: Option<&NativeHeldCapacityRecordV3>,
    limits: JournalLimits,
) -> Result<JournalTransaction, JournalError> {
    root_native_capacity_append_v3(proposal)?;
    let old_request = old.request();
    if old_request.purpose != NativeHeldCapacityPurposeV3::Root
        || proposal.admission_binding.is_some()
        || proposal.maximum_remaining_transactions >= old_request.future_transactions
    {
        return Err(invalid("native Root continuation old floor or count"));
    }
    let records = proposal_records(proposal)?;
    match next {
        Some(next) => {
            let request = next.request();
            if proposal.maximum_remaining_transactions == 0
                || request.future_transactions != proposal.maximum_remaining_transactions
                || !same_binding(old_request, request)
                || next.admission_transaction_id() != old.admission_transaction_id()
            {
                return Err(invalid(
                    "native Root successor does not preserve original floor",
                ));
            }
        }
        None if proposal.maximum_remaining_transactions == 0
            && proposal.kind == Kind::TerminalAckStored => {}
        None => return Err(invalid("native Root premature capacity deletion")),
    }
    super::transfer::frame_transfer(
        proposal.transaction_id,
        records,
        old,
        next,
        limits,
        (
            "native Root consumed records",
            "native Root complete transferred suffix",
        ),
    )
}

fn proposal_records(
    proposal: &RootNativeHeldTransitionV1,
) -> Result<Vec<JournalRecord>, JournalError> {
    if proposal.transaction_id == [0; 16]
        || proposal.puts.is_empty()
        || proposal.puts.len() != proposal.before_images.len()
        || proposal.puts.keys().ne(proposal.before_images.keys())
    {
        return Err(invalid(
            "native Root complete proposal keys or transaction identity",
        ));
    }
    proposal
        .puts
        .iter()
        .map(|(key, value)| {
            if value.is_empty()
                || proposal.before_images.get(key).and_then(Option::as_ref) == Some(value)
            {
                return Err(invalid("native Root empty or unchanged proposed put"));
            }
            Ok(JournalRecord::put(
                RecordNamespace::MountSourceAcquisition,
                key.clone(),
                value.clone(),
            ))
        })
        .collect()
}

fn same_binding(old: NativeHeldCapacityRequestV3, next: NativeHeldCapacityRequestV3) -> bool {
    old.purpose == next.purpose
        && old.owner_id == next.owner_id
        && old.owner_digest == next.owner_digest
        && old.operation_id == next.operation_id
        && old.artifact_digest == next.artifact_digest
        && old.checkpoint_digest == next.checkpoint_digest
        && old.chain_head_digest == next.chain_head_digest
}

#[cfg(test)]
mod tests;
