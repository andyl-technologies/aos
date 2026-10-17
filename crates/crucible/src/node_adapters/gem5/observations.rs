//! Exact historical stopped-observation bodies beneath authenticated archives.
//!
//! Decoding these records preserves provenance only. Fresh live observations
//! still require the actual native adapter and independently sealed authority.

use crucible_node_contract::{ContentRef, Id, canonical};
use crucible_node_provider::gem5::Gem5Boundary;
use serde::Deserialize;

use crate::node_contract::{OperationFailure, OwnerIdentity};

use super::{continuation::Gem5ContinuationRecord, ledger::OperationLedger, refusal};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoppedObservation {
    schema: String,
    boundary: Gem5Boundary,
    closure: ContentRef,
    owners: Vec<OwnerIdentity>,
    activation_id: Id,
}

pub(super) fn retain_historical_observations(
    ledger: &mut OperationLedger,
    source: &Gem5ContinuationRecord,
) -> Result<(), OperationFailure> {
    for object in source.evidence.values() {
        if object.reference.media_type != "application/json" {
            continue;
        }
        let value = canonical::parse_json(&object.bytes, 16 * 1024 * 1024)
            .map_err(|error| refusal(&error.to_string()))?;
        if value.get("schema").and_then(serde_json::Value::as_str)
            != Some("crucible.gem5.common-observation.v1")
        {
            continue;
        }
        let record: StoppedObservation =
            serde_json::from_value(value).map_err(|error| refusal(&error.to_string()))?;
        if record.schema != "crucible.gem5.common-observation.v1"
            || record.owners.len() != 1
            || source
                .wire
                .owners
                .first()
                .is_none_or(|owner| owner.owner != record.owners[0].owner)
            || record.boundary.logical_position.microstep >= source.wire.maximum_microsteps
        {
            return Err(refusal(
                "gem5 historical stopped observation changes original owner or schema",
            ));
        }
        let closure = source
            .evidence
            .get(&record.closure)
            .ok_or_else(|| refusal("gem5 original stopped observation closure body is absent"))?;
        // The original activation and boundary stay in their original bytes.
        // They are historical provenance, never current readiness authority.
        let _original_activation = record.activation_id;
        ledger.retain_standalone(&[
            (&object.reference, &object.bytes),
            (&closure.reference, &closure.bytes),
        ])?;
    }
    Ok(())
}
