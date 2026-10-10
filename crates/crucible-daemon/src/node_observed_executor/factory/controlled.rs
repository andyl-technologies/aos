//! Independently installed immutable native coefficient-controller programs.
//!
//! Remote selections contain only artifact references and endpoint identities.
//! Complete authored decisions are read from the operator's authenticated
//! registry. Neither request-provided hashes nor fault facet descriptions can
//! install a native controller or change its immutable timing contract.

use std::collections::BTreeMap;

use crucible::node_adapters::{ControlledFaultLink, ControlledFaultProgram, HostModel};
use crucible_node_contract::{ContentRef, Id, canonical};
use serde::{Deserialize, Serialize};

use super::{InstalledIoArtifact, InstalledNodeSelection, NodeObservedError, io, refused};

/// Selects an enrolled coefficient-controller program and its exact endpoints.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledControlledFaultProfile {
    /// Binds the complete canonical independently enrolled controller program.
    pub program: ContentRef,
    /// Names the immutable original scripted request producer.
    pub producer: Id,
    /// Names the original Block or opaque packet receiver.
    pub consumer: Id,
}

pub(super) fn definition(
    profile: &InstalledControlledFaultProfile,
    artifacts: &BTreeMap<String, InstalledIoArtifact>,
) -> Result<(ControlledFaultProgram, Vec<u8>), NodeObservedError> {
    let artifact = artifacts
        .get(&profile.program.hash.digest)
        .filter(|artifact| artifact.expected == profile.program)
        .ok_or_else(|| refused("controller program is not independently installed"))?;
    let bytes = io::read_artifact(artifact)?;
    let parsed = canonical::parse_json(&bytes, 1024 * 1024)?;
    let program: ControlledFaultProgram = serde_json::from_value(parsed.clone())?;
    if canonical::canonical_json(&parsed)? != bytes
        || program
            .reference()
            .map_err(|error| refused(&error.reason))?
            != profile.program
    {
        return Err(refused(
            "controller program differs from complete canonical enrollment",
        ));
    }
    Ok((program, bytes))
}

pub(super) fn build_model(
    selected: &InstalledNodeSelection,
    profile: &InstalledControlledFaultProfile,
    artifacts: &BTreeMap<String, InstalledIoArtifact>,
) -> Result<HostModel, NodeObservedError> {
    if selected.node == profile.producer
        || selected.node == profile.consumer
        || profile.producer == profile.consumer
    {
        return Err(refused(
            "native controller requires three distinct original endpoints",
        ));
    }
    let (program, _) = definition(profile, artifacts)?;
    Ok(HostModel::ControlledFaultLink(Box::new(
        ControlledFaultLink::new(program).map_err(|error| refused(&error.reason))?,
    )))
}
