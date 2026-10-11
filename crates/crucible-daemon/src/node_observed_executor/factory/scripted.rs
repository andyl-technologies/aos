//! Operator-enrolled immutable scripts and their actual inactive native sources.
//!
//! Portable configuration names content and its ordinary public consumer. The
//! independently installed artifact registry alone associates content with a
//! local path; the native source retains all original request octets.

use std::collections::BTreeMap;

use crucible::node_adapters::{HostModel, ScriptedSource};
use crucible_node_contract::{ContentRef, Id, Validate};
use serde::{Deserialize, Serialize};

use super::io::{InstalledIoArtifact, read_artifact};
use super::{InstalledNodeSelection, NodeObservedError, refused};

#[cfg(test)]
#[path = "scripted_tests.rs"]
mod tests;

/// Selects an enrolled finite immutable request script and its public consumer.
///
/// ```json
/// {"script":{"hash":{},"length":"64","media_type":"application/octet-stream"},
///  "consumer":"disk"}
/// ```
/// The abbreviated hash stands for the complete public content identity.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledScriptedSourceProfile {
    /// Binds the independently enrolled complete canonical script bytes.
    pub script: ContentRef,
    /// Names the node connected through its ordinary public request input lane.
    pub consumer: Id,
}

impl InstalledScriptedSourceProfile {
    pub(super) fn artifact(&self) -> &ContentRef {
        &self.script
    }
}

pub(super) fn build_model(
    selected: &InstalledNodeSelection,
    profile: &InstalledScriptedSourceProfile,
    artifacts: &BTreeMap<String, InstalledIoArtifact>,
) -> Result<HostModel, NodeObservedError> {
    profile.script.validate()?;
    profile.consumer.validate()?;
    if profile.consumer == selected.node {
        return Err(refused(
            "scripted request source cannot consume its own outputs",
        ));
    }
    let artifact = artifacts
        .get(&profile.artifact().hash.digest)
        .filter(|artifact| &artifact.expected == profile.artifact())
        .ok_or_else(|| refused("script has no independently enrolled immutable artifact"))?;
    let bytes = read_artifact(artifact)?;
    let source =
        ScriptedSource::from_script_bytes(&bytes).map_err(|error| refused(&error.reason))?;
    if source
        .script_bytes()
        .map_err(|error| refused(&error.reason))?
        != bytes
    {
        return Err(refused(
            "installed script differs from its canonical native edition",
        ));
    }
    // A fresh source starts with its entire immutable future retained and no
    // publication. No input payload or execution grant is synthesized here.
    Ok(HostModel::ScriptedSource(Box::new(source)))
}
