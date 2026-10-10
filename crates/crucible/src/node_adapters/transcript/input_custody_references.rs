//! Exact dependency roles of an explicitly selected replay-model input receipt.
//!
//! These closed codec objects retain source state, original acknowledgement and
//! ordered input inventory. Parsing their roles provides no source authority;
//! an installed archive policy must independently authenticate their provenance.

use crucible_node_contract::{ContentRef, Validate, canonical};

use crate::node_scheduling::InputPayload;

use super::{
    TranscriptError,
    codec::invalid,
    node::continuation::{MAXIMUM_STATE_BYTES, ReplayInputCustody},
};

/// Names the three positive dependency roles in a replay-model input receipt.
///
/// Equal full references may occupy multiple roles. Archive adjacency may
/// deduplicate those references while retaining the original receipt bytes.
/// This projection is data only and cannot grant readiness or input custody.
pub struct ReplayInputCustodyReferences {
    /// Names the authenticated original transcript or preceding model state.
    pub source_state: ContentRef,
    /// Names the exact preceding acknowledgement proof, retaining its owners.
    pub source_acknowledgement: ContentRef,
    /// Names the original ordered delivery inventory.
    pub inventory: ContentRef,
}

/// Projects a known replay-model input receipt under an explicit byte credit.
///
/// The caller selects this codec only for an independently authenticated input
/// custody role. This function does not classify arbitrary JSON objects or
/// establish that a parsed receipt was produced by an owning replay model.
/// Original receipt fields and bytes remain unchanged.
///
/// # Errors
/// Refuses an exceeded byte credit, changed full content reference, unsupported
/// media or schema, noncanonical or open JSON, or inconsistent input identity.
pub fn replay_input_custody_references(
    object: &InputPayload,
    maximum_bytes: usize,
) -> Result<ReplayInputCustodyReferences, TranscriptError> {
    let limit = maximum_bytes.min(MAXIMUM_STATE_BYTES);
    if object.bytes.len() > limit || object.reference.media_type != "application/json" {
        return Err(invalid(
            "replay input receipt exceeds its selected codec credit",
        ));
    }
    object.reference.verify(&object.bytes).map_err(invalid)?;
    let value = canonical::parse_json(&object.bytes, limit).map_err(invalid)?;
    if canonical::canonical_json(&value).map_err(invalid)? != object.bytes {
        return Err(invalid("replay input receipt bytes are not canonical"));
    }
    let receipt: ReplayInputCustody = serde_json::from_value(value).map_err(invalid)?;
    if !matches!(
        receipt.schema.as_str(),
        "crucible.transcript-replay.input-admission.v1"
            | "crucible.transcript-replay.input-custody.v1"
    ) || receipt.node != receipt.source_ack.node
        || receipt.batch != receipt.source_ack.batch
        || receipt.stage_operation != receipt.source_ack.stage_operation
        || receipt.inventory != receipt.source_ack.inventory
        || receipt.cutoff != receipt.source_ack.cutoff
        || receipt.owners.is_empty()
        || receipt.owners.len() != receipt.source_ack.owners.len()
        || !receipt
            .owners
            .iter()
            .all(|owner| receipt.target.owners.contains(owner))
    {
        return Err(invalid(
            "replay input receipt codec or original identity differs",
        ));
    }
    receipt.source_state.validate().map_err(invalid)?;
    receipt.source_ack.proof_ref.validate().map_err(invalid)?;
    receipt.inventory.validate().map_err(invalid)?;

    Ok(ReplayInputCustodyReferences {
        source_state: receipt.source_state,
        source_acknowledgement: receipt.source_ack.proof_ref,
        inventory: receipt.inventory,
    })
}

#[cfg(test)]
#[path = "input_custody_references_tests.rs"]
mod tests;
