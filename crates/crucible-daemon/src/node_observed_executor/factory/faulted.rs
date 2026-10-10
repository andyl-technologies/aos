//! Independently installed faulted transport programs and inactive native models.
//!
//! Portable selections carry immutable references and endpoint names. Only the
//! operator registry supplies complete program bytes; a matching seed label
//! cannot establish native implementation or continuation authority.

use std::collections::BTreeMap;

use crucible::node_adapters::{FaultedLinkDefinition, HostModel};
use crucible_node_contract::{ContentRef, Id, canonical};
use serde::{Deserialize, Serialize};

use super::{InstalledIoArtifact, InstalledNodeSelection, NodeObservedError, io, refused};

/// Selects an enrolled static loss/duplication/corruption program and its exact endpoints.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledFaultedLinkProfile {
    /// Binds the independently enrolled canonical faulted transport definition.
    pub program: ContentRef,
    /// Names the immutable scripted request producer connected to ingress.
    pub producer: Id,
    /// Names the native storage consumer connected to egress.
    pub consumer: Id,
}

pub(super) fn definition(
    profile: &InstalledFaultedLinkProfile,
    artifacts: &BTreeMap<String, InstalledIoArtifact>,
) -> Result<(FaultedLinkDefinition, Vec<u8>), NodeObservedError> {
    let artifact = artifacts
        .get(&profile.program.hash.digest)
        .filter(|entry| entry.expected == profile.program)
        .ok_or_else(|| refused("faulted transport program is not independently installed"))?;
    let bytes = io::read_artifact(artifact)?;
    let parsed = canonical::parse_json(&bytes, 64 * 1024)?;
    let definition: FaultedLinkDefinition = serde_json::from_value(parsed.clone())?;
    if canonical::canonical_json(&parsed)? != bytes {
        return Err(refused("faulted transport program is not canonical"));
    }
    definition
        .instantiate()
        .map_err(|error| refused(&error.reason))?;
    Ok((definition, bytes))
}

pub(super) fn build_model(
    selected: &InstalledNodeSelection,
    profile: &InstalledFaultedLinkProfile,
    artifacts: &BTreeMap<String, InstalledIoArtifact>,
) -> Result<HostModel, NodeObservedError> {
    if selected.node == profile.producer
        || selected.node == profile.consumer
        || profile.producer == profile.consumer
    {
        return Err(refused(
            "faulted transport requires three distinct original nodes",
        ));
    }
    let (definition, _) = definition(profile, artifacts)?;
    Ok(HostModel::FaultedLink {
        link: Box::new(
            definition
                .instantiate()
                .map_err(|error| refused(&error.reason))?,
        ),
        definition,
        decisions: Vec::new(),
    })
}
