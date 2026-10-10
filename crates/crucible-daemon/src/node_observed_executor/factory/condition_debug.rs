//! Independently enrolled event-condition programs and inactive native evaluators.
//!
//! Portable selections carry immutable content identities only. The operator
//! registry owns actual source paths and expected bytes; this module accepts no
//! client-issued qualification or diagnostic stop claim.

use std::collections::BTreeMap;

use crucible::node_adapters::{
    ConditionDebugDefinition, ConditionDebugModel, HostSemanticInputKind,
};
use crucible_node_contract::{ContentRef, Validate, canonical};
use serde::{Deserialize, Serialize};

use super::io::{InstalledHostIoProfile, InstalledIoArtifact, read_artifact};
use super::{InstalledNodeKind, InstalledNodeSelection, NodeObservedError, refused};

/// Selects an independently installed immutable event-condition program.
///
/// ```text
/// {"program":{"hash":{...},"length":"512","media_type":"application/json"}}
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledConditionDebugProfile {
    /// Binds the exact condition, compact properties and real native input lane.
    pub program: ContentRef,
}

/// Pins the source-owned bounded codec policy independently of a schema label.
pub(super) const PRESERVATION_SCHEMA: &[u8] = b"Selected stopped condition native6: exact original live4 byte-bearing DAG; complete original native model, stop/report/control ACK, operation/request/outcome, staged and consumed input, payload/sequence/provenance custody; signed Runtime6 and exact Scheduler4 marker; source-regenerated whole installed Block/Script/Clock/observer world; fresh isolated construction and current durable root reconciliation before resume; acknowledged unresumed common cut only; live4 unchanged, no guest mutation, external controller, replay or fork";

pub(super) const MAXIMUM_PROGRAM_BYTES: usize = 4 * 1024 * 1024;
pub(super) const MAXIMUM_STATE_BYTES: usize = 16 * 1024 * 1024;
pub(super) const MAXIMUM_EVENTS: usize = 4096;

pub(super) fn read_program(
    profile: &InstalledConditionDebugProfile,
    artifacts: &BTreeMap<String, InstalledIoArtifact>,
) -> Result<(ConditionDebugDefinition, Vec<u8>), NodeObservedError> {
    profile.program.validate()?;
    if profile.program.media_type != "application/json"
        || profile.program.length.get() > MAXIMUM_PROGRAM_BYTES as u64
    {
        return Err(refused(
            "condition program type or finite byte ceiling refused",
        ));
    }
    let artifact = artifacts
        .get(&profile.program.hash.digest)
        .filter(|artifact| artifact.expected == profile.program)
        .ok_or_else(|| refused("condition program has no independently installed artifact"))?;
    let bytes = read_artifact(artifact)?;
    let definition: ConditionDebugDefinition =
        serde_json::from_value(canonical::parse_json(&bytes, MAXIMUM_PROGRAM_BYTES)?)?;
    if canonical::canonical_json(&serde_json::to_value(&definition)?)? != bytes {
        return Err(refused(
            "condition program is not the exact canonical definition",
        ));
    }
    Ok((definition, bytes))
}

pub(super) fn build_model(
    selected: &InstalledNodeSelection,
    selections: &[InstalledNodeSelection],
    profile: &InstalledConditionDebugProfile,
    artifacts: &BTreeMap<String, InstalledIoArtifact>,
) -> Result<ConditionDebugModel, NodeObservedError> {
    let (definition, _) = read_program(profile, artifacts)?;
    for input in &definition.evaluation.inputs {
        if input.source.node_id == selected.node
            || input.source.port_id.as_str() != "data"
            || input.source.lane_id.as_str() != "output"
        {
            return Err(refused(
                "condition observation requires a real original native response lane",
            ));
        }
        let source = selections
            .iter()
            .find(|entry| entry.node == input.source.node_id)
            .ok_or_else(|| refused("condition source is absent from complete selected world"))?;
        if !matches!(
            (&input.kind, &source.kind),
            (
                HostSemanticInputKind::BlockCompletion,
                InstalledNodeKind::HostIo {
                    profile: InstalledHostIoProfile::Block { .. }
                }
            )
        ) {
            return Err(refused(
                "condition input projection lacks actual native source support",
            ));
        }
    }
    ConditionDebugModel::new(definition, MAXIMUM_STATE_BYTES, MAXIMUM_EVENTS)
        .map_err(|error| refused(&error.reason))
}

// This format names the actual bounded native control decoder. Enrollment binds
// its complete bytes and requires the actual owned ConditionObserver variant.
pub(super) const CONTROL_SCHEMA: &[u8] = b"DebugConditionV1: original opaque whole-runtime Stop barrier and exact native report; separately admitted original Resume after current-root durability and actual stop ACK; complete stop/control journal, original input/condition/outcome/cut and native token lineage; guest mutation unsupported";
