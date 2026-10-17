//! Independently enrolled assertion programs and inactive owned evaluators.
//!
//! Portable selection binds only immutable content. The installed registry
//! supplies its independently expected identity and local source; program
//! routes must name actual selected native storage output lanes. No constructor
//! in this module certifies execution or grants native continuation authority.

use std::collections::BTreeMap;

use crucible::node_adapters::{HostSemanticDefinition, HostSemanticInputKind, HostSemanticModel};
use crucible_node_contract::{ContentRef, Validate, canonical};
use serde::{Deserialize, Serialize};

use super::io::{InstalledHostIoProfile, InstalledIoArtifact, read_artifact};
use super::{InstalledNodeKind, InstalledNodeSelection, NodeObservedError, refused};

/// Selects an operator-enrolled complete assertion program.
///
/// ```json
/// {"program":{"hash":{},"length":"512","media_type":"application/json"}}
/// ```
/// The abbreviated hash represents the complete public content identity.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledHostSemanticProfile {
    /// Binds exact canonical definition, compact properties and original routes.
    pub program: ContentRef,
}

pub(super) const MAXIMUM_SEMANTIC_PROGRAM_BYTES: usize = 4 * 1024 * 1024;
pub(super) const MAXIMUM_SEMANTIC_STATE_BYTES: usize = 16 * 1024 * 1024;
pub(super) const MAXIMUM_SEMANTIC_EVENTS: usize = 4096;

pub(super) fn read_program(
    profile: &InstalledHostSemanticProfile,
    artifacts: &BTreeMap<String, InstalledIoArtifact>,
) -> Result<(HostSemanticDefinition, Vec<u8>), NodeObservedError> {
    profile.program.validate()?;
    if profile.program.media_type != "application/json"
        || profile.program.length.get() > MAXIMUM_SEMANTIC_PROGRAM_BYTES as u64
    {
        return Err(refused(
            "semantic program type or finite byte ceiling refused",
        ));
    }
    let artifact = artifacts
        .get(&profile.program.hash.digest)
        .filter(|artifact| artifact.expected == profile.program)
        .ok_or_else(|| refused("semantic program has no independently installed artifact"))?;
    let bytes = read_artifact(artifact)?;
    let value = canonical::parse_json(&bytes, MAXIMUM_SEMANTIC_PROGRAM_BYTES)?;
    let definition: HostSemanticDefinition = serde_json::from_value(value)?;
    if canonical::canonical_json(&serde_json::to_value(&definition)?)? != bytes {
        return Err(refused(
            "semantic program is not the exact canonical definition",
        ));
    }
    Ok((definition, bytes))
}

pub(super) fn build_model(
    selected: &InstalledNodeSelection,
    selections: &[InstalledNodeSelection],
    profile: &InstalledHostSemanticProfile,
    artifacts: &BTreeMap<String, InstalledIoArtifact>,
) -> Result<HostSemanticModel, NodeObservedError> {
    let (definition, _) = read_program(profile, artifacts)?;
    for input in &definition.inputs {
        if input.source.node_id == selected.node
            || input.source.port_id.as_str() != "data"
            || input.source.lane_id.as_str() != "output"
        {
            return Err(refused(
                "semantic projection requires an original native output route",
            ));
        }
        let source = selections
            .iter()
            .find(|entry| entry.node == input.source.node_id)
            .ok_or_else(|| refused("semantic source is absent from complete selected world"))?;
        match (&input.kind, &source.kind) {
            (
                HostSemanticInputKind::BlockCompletion,
                InstalledNodeKind::HostIo {
                    profile: InstalledHostIoProfile::Block { .. },
                },
            ) => {}
            _ => {
                return Err(refused(
                    "semantic projection is unavailable for this actual source implementation",
                ));
            }
        }
    }
    let model = HostSemanticModel::new(
        definition,
        MAXIMUM_SEMANTIC_STATE_BYTES,
        MAXIMUM_SEMANTIC_EVENTS,
    )
    .map_err(|error| refused(&error.reason))?;
    // Each property has one terminal result. The finite installed output lane
    // can retain the complete simultaneous result set before any input effect.
    if model.properties().assertions().len() > 16 {
        return Err(refused(
            "semantic property set exceeds original result custody credit",
        ));
    }
    Ok(model)
}
