//! Reconciles inert common cache data with the complete original native journal.

use std::collections::{BTreeMap, BTreeSet};

use crucible_node_contract::{ContentRef, Id, U64, canonical};
use crucible_node_provider::gem5::Gem5Completion;

use crate::{
    node_contract::*,
    node_scheduling::{InputPayload, NativeOutputBound},
};

use super::continuation::{SavedNativeOperation, Wire};
use super::{positions::callback_positions, refusal};

pub(super) fn reconcile_native_cache(
    wire: &Wire,
    prefixes: &BTreeMap<Id, Gem5Completion>,
    prefix_ids: &BTreeMap<ContentRef, Id>,
    objects: &BTreeMap<ContentRef, InputPayload>,
) -> Result<(), OperationFailure> {
    let mut births = BTreeSet::new();
    for prefix in prefixes.values() {
        if prefix.publications.len() > 1 {
            return Err(refusal(
                "gem5 native prefix exceeds the installed single stdout write policy",
            ));
        }
        let mut output_extent = 0usize;
        for birth in &prefix.publications {
            if birth.output_id.get() == 0
                || !births.insert(birth.output_id)
                || birth.guest_pid != U64::new(100)
                || birth.context_id != U64::new(0)
                || birth.guest_fd != 1
                || birth.causal_parent.get() != 0
            {
                return Err(refusal(
                    "gem5 native stdout birth identity or closed guest scope changed",
                ));
            }
            let end = output_extent
                .checked_add(birth.payload.len())
                .filter(|end| *end <= prefix.output.len())
                .ok_or_else(|| refusal("gem5 native stdout birth byte extent differs"))?;
            if prefix.output[output_extent..end] != birth.payload {
                return Err(refusal(
                    "gem5 native stdout birth bytes differ from original output",
                ));
            }
            output_extent = end;
        }
        if output_extent != prefix.output.len() {
            return Err(refusal(
                "gem5 native output has no complete original birth inventory",
            ));
        }
    }
    if births.len() as u64 != wire.output_sequence.get()
        || births
            .iter()
            .enumerate()
            .any(|(index, id)| id.get() != index as u64 + 1)
    {
        return Err(refusal(
            "gem5 captured stdout FIFO cursor differs from complete native births",
        ));
    }

    let mut claimed = BTreeSet::new();
    for operation in &wire.operations {
        let mut receipts = Vec::with_capacity(operation.prefixes.len());
        for reference in &operation.prefixes {
            let prefix = prefix_ids
                .get(reference)
                .and_then(|id| prefixes.get(id))
                .ok_or_else(|| refusal("gem5 original prefix dependency body is absent"))?;
            if !claimed.insert(prefix.operation.clone()) {
                return Err(refusal(
                    "gem5 native prefix was assigned to multiple common operations",
                ));
            }
            receipts.push((reference, prefix));
        }
        let terminal = match &operation.original.result {
            SavedRuntimeResult::Pending => None,
            SavedRuntimeResult::Complete(outcome) | SavedRuntimeResult::Acknowledged(outcome) => {
                Some(outcome)
            }
            SavedRuntimeResult::Failed(_) => {
                return Err(refusal(
                    "gem5 failed original operation lacks supported exact continuation",
                ));
            }
        };
        let progress_count = receipts
            .len()
            .saturating_sub(usize::from(terminal.is_some()));
        for (_, prefix) in receipts.iter().take(progress_count) {
            if prefix.reason != "event_budget"
                || !prefix.output.is_empty()
                || !prefix.publications.is_empty()
                || wire.native_pending.as_ref() == Some(&prefix.operation)
                || prefix
                    .original
                    .exact_range
                    .as_ref()
                    .is_none_or(|range| prefix.after.logical_position >= range.limit)
            {
                return Err(refusal(
                    "gem5 intermediate Poll prefix was not empty acknowledged budget progress",
                ));
            }
        }
        match terminal {
            None => {
                if operation.original.scheduling_commit.is_some()
                    || receipts.last().is_some_and(|(_, prefix)| {
                        wire.native_acknowledged.as_ref() != Some(&prefix.operation)
                    })
                {
                    return Err(refusal(
                        "gem5 pending common operation lost original progress ACK custody",
                    ));
                }
            }
            Some(outcome) => {
                let (reference, prefix) = receipts.last().ok_or_else(|| {
                    refusal("gem5 cached terminal result lacks its original native receipt")
                })?;
                reconcile_terminal(wire, operation, reference, prefix, outcome, objects)?;
            }
        }
    }
    if wire
        .native_pending
        .as_ref()
        .is_some_and(|identity| !claimed.contains(identity))
    {
        return Err(refusal(
            "gem5 held native terminal prefix lacks original common operation custody",
        ));
    }
    Ok(())
}

fn reconcile_terminal(
    wire: &Wire,
    saved: &SavedNativeOperation,
    proof: &ContentRef,
    prefix: &Gem5Completion,
    outcome: &OperationOutcome,
    objects: &BTreeMap<ContentRef, InputPayload>,
) -> Result<(), OperationFailure> {
    let limit = match &saved.original.request {
        OperationRequest::ExactRun { limit, .. }
        | OperationRequest::BoundarySettle { limit, .. } => *limit,
        _ => {
            return Err(refusal(
                "gem5 cached outcome has unsupported original request",
            ));
        }
    };
    let reached = prefix.after.logical_position;
    let stop = if reached == limit {
        StopReason::HorizonPark
    } else if !prefix.publications.is_empty() {
        StopReason::Output
    } else if prefix.reason == "guest_exit" {
        StopReason::Lifecycle
    } else {
        return Err(refusal(
            "gem5 cached terminal stop lacks qualified native classification",
        ));
    };
    let scheduling = outcome
        .scheduling
        .as_ref()
        .ok_or_else(|| refusal("gem5 cached terminal result omits native scheduling evidence"))?;
    let complete = matches!(saved.original.result, SavedRuntimeResult::Complete(_));
    if outcome.operation != saved.original.operation
        || outcome.node != wire.node
        || outcome.owners != wire.owners
        || outcome.progress != (ProgressEvidence::Exact { reached, stop })
        || scheduling.node != wire.node
        || scheduling.owners != wire.owners
        || scheduling.reached != reached
        || scheduling.closed_prefix != reached
        || scheduling.proof_ref != *proof
        || scheduling.input_progress.is_some()
        || !scheduling.external_inputs.is_empty()
        || scheduling.publications.len() != prefix.publications.len()
        || complete != (wire.native_pending.as_ref() == Some(&prefix.operation))
        || (complete && wire.native_acknowledged.as_ref() == Some(&prefix.operation))
    {
        return Err(refusal(
            "gem5 cached terminal scope, progress or ACK custody differs from original native receipt",
        ));
    }
    let expected_bound = if let Some(birth) = prefix.publications.first() {
        NativeOutputBound::At(
            callback_positions(birth.tick, birth.tick_ordinal, wire.maximum_microsteps)?.1,
        )
    } else {
        match prefix
            .after
            .next_reaction(wire.maximum_microsteps)
            .map_err(|error| refusal(&error.to_string()))?
        {
            Some(reaction) => NativeOutputBound::At(
                reaction
                    .reaction_publication(wire.maximum_microsteps)
                    .map_err(|error| refusal(&error.to_string()))?,
            ),
            None => NativeOutputBound::AfterInstant(U64::new(u64::MAX)),
        }
    };
    if scheduling.bounds.len() != 1
        || scheduling.bounds[0].producer != wire.node
        || scheduling.bounds[0].proof_ref != *proof
        || scheduling.bounds[0].bound != expected_bound
    {
        return Err(refusal(
            "gem5 cached producer bound differs from native held birth or future heap",
        ));
    }
    for (publication, birth) in scheduling.publications.iter().zip(&prefix.publications) {
        let (evaluation, position) =
            callback_positions(birth.tick, birth.tick_ordinal, wire.maximum_microsteps)?;
        let range = prefix
            .original
            .exact_range
            .as_ref()
            .ok_or_else(|| refusal("gem5 cached birth lacks original exact range"))?;
        let payload = canonical::content_ref(&birth.payload, "application/octet-stream")
            .map_err(|error| refusal(&error.to_string()))?;
        if evaluation < range.start
            || evaluation >= range.limit
            || publication.publication_id.as_str()
                != format!("gem5/output/{}", birth.output_id.get())
            || publication.endpoint.node_id != wire.node
            || publication.native_sequence != birth.output_id
            || publication.publication != position
            || publication.evaluation != Some(evaluation)
            || !publication.causal_parents.is_empty()
            || publication.payload != payload
            || publication.payload_bytes != birth.payload
            || objects
                .get(&payload)
                .is_none_or(|object| object.bytes != birth.payload)
        {
            return Err(refusal(
                "gem5 cached publication changed original native FIFO, birth or payload",
            ));
        }
    }
    let inventory: Vec<_> = scheduling
        .publications
        .iter()
        .map(|publication| publication.publication_id.clone())
        .collect();
    if outcome.retained_outputs != inventory
        || saved
            .original
            .scheduling_commit
            .as_ref()
            .is_some_and(|commit| {
                commit.node != wire.node
                    || commit.operation != saved.original.operation
                    || commit.retained_outputs != inventory
            })
    {
        return Err(refusal(
            "gem5 cached output inventory differs from original publication custody",
        ));
    }
    Ok(())
}
