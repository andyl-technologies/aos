//! Independently enrolled finite logical-input sources for installed Block models.
//!
//! A source artifact contains original FIFO records, not native authority. The
//! installed catalog remeasures its bytes, regenerates the exact binding
//! projection and compiled recipe, then owns those arrivals under the ordinary
//! runtime barrier. Live physical sampling and source-cursor restoration refuse.

use std::collections::BTreeMap;

use crucible::node_adapters::{RecordedIngressDefinition, RecordedLogicalInputSource};
use crucible::node_scheduling::InputPayload;
use crucible_node_contract::{ContentRef, Endpoint, Id, NodeDescriptor, canonical};
use serde::{Deserialize, Serialize};

use crate::node_scenario::{NodeRunConfiguration, NodeScenario, ScenarioContent};

use super::{
    InstalledHostIoProfile, InstalledIoArtifact, InstalledNodeSelection, NodeObservedError, refused,
};

/// Selects the exact immutable logical source and native storage recipe.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledRecordedIngressProfile {
    /// Binds the independently enrolled original input-record file.
    pub source: ContentRef,
    /// Selects the ordinary actual Block implementation and immutable base image.
    pub storage: InstalledHostIoProfile,
    /// Binds the finite original run independently of any live nonce or owner.
    pub configuration: NodeRunConfiguration,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Configuration {
    pub(super) schema_version: u16,
    pub(super) native_profile: InstalledHostIoProfile,
    pub(super) recorded_source: ContentRef,
    pub(super) run_configuration: NodeRunConfiguration,
    pub(super) record_root: Option<ContentRef>,
    pub(super) native_configuration: ContentRef,
}

pub(super) fn endpoint(node: &Id) -> Result<Endpoint, NodeObservedError> {
    Ok(Endpoint {
        node_id: node.clone(),
        port_id: Id::new("data")?,
        lane_id: Id::new("input")?,
    })
}

pub(super) fn source(
    selection: &InstalledNodeSelection,
    profile: &InstalledRecordedIngressProfile,
    artifacts: &BTreeMap<String, InstalledIoArtifact>,
) -> Result<InputPayload, NodeObservedError> {
    if !matches!(profile.storage, InstalledHostIoProfile::Block { .. }) {
        return Err(refused(
            "recorded ingress requires the exact installed Block codec",
        ));
    }
    let enrolled = artifacts
        .get(&profile.source.hash.digest)
        .filter(|artifact| artifact.expected == profile.source)
        .ok_or_else(|| refused("recorded ingress source has no independent operator enrollment"))?;
    if profile.source.length.get() > 65536 {
        return Err(refused("recorded ingress source exceeds pre-read credit"));
    }
    let bytes = super::io::read_artifact(enrolled)?;
    if bytes.len() > 65536 {
        return Err(refused(
            "recorded ingress source exceeds its complete 64KiB credit",
        ));
    }
    let document: RecordedLogicalInputSource =
        crucible::node_adapters::validate_recorded_input_source(&InputPayload {
            reference: profile.source.clone(),
            bytes: bytes.clone(),
        })
        .map_err(super::native)?;
    if document.endpoint != endpoint(&selection.node)?
        || document.closed_before.time_ps <= profile.configuration.horizon_ps
        || profile.configuration.version != 1
        || profile.configuration.format != "crucible.node-run-configuration"
        || profile.configuration.maximum_rounds.get() == 0
    {
        return Err(refused(
            "recorded ingress lane or finite run/source interval differs",
        ));
    }
    let mut correlations = std::collections::BTreeSet::new();
    for input in &document.inputs {
        let request =
            crucible_device::BlockRequest::decode(&input.payload.bytes).map_err(super::native)?;
        if !correlations.insert(request.request_id) {
            return Err(refused(
                "recorded ingress reuses an original Block correlation",
            ));
        }
        let output = match request.op {
            crucible_device::BlockOp::Read => u64::from(request.count),
            crucible_device::BlockOp::GetLength => 8,
            _ => 1,
        }
        .checked_add(crucible_device::block::RESPONSE_HEADER_LEN as u64)
        .ok_or_else(|| refused("recorded Block response geometry overflows"))?;
        if output > crucible_shmem::MAX_FRAME_DATA as u64 {
            return Err(refused(
                "recorded Block input outruns the selected response lane",
            ));
        }
    }
    Ok(InputPayload {
        reference: profile.source.clone(),
        bytes,
    })
}

pub(super) fn recipe(
    host: &ContentRef,
    profile: &InstalledRecordedIngressProfile,
) -> Result<InputPayload, NodeObservedError> {
    let bytes = canonical::canonical_json(&serde_json::json!({
        "format":"crucible.installed-recorded-block-recipe","version":1,
        "host":host,"storage":profile.storage,"source":profile.source,
        "coordinate":"authored logical Publication microstep0; exact Delivery conversion; original common Reaction grant",
        "ownership":"complete immutable source and unconsumed original FIFO; staging is not consumption",
        "maximum_events":16,"maximum_source_bytes":65536,
        "capture":"refused until source cursor and queue codec qualified",
        "physical_sampling":false,"faults":[]
    }))?;
    let reference = canonical::content_ref(&bytes, "application/json")?;
    Ok(InputPayload { reference, bytes })
}

/// Regenerates the exact projection with only the designated root slot absent.
pub(super) fn projection(
    scenario: &NodeScenario,
    configuration: &NodeRunConfiguration,
) -> Result<InputPayload, NodeObservedError> {
    let bytes = canonical::canonical_json(&serde_json::json!({
        "format":"crucible.recorded-input-binding-projection","version":1,
        "designated_slot":"single selected Block configuration.record_root",
        "world":scenario,"configuration":configuration
    }))?;
    let reference = canonical::content_ref(&bytes, "application/json")?;
    Ok(InputPayload { reference, bytes })
}

pub(super) fn insert_definition(
    definition: &RecordedIngressDefinition,
    content: &mut BTreeMap<String, ScenarioContent>,
) {
    for object in definition.objects() {
        content.insert(
            object.reference.hash.digest.clone(),
            ScenarioContent {
                reference: object.reference.clone(),
                bytes: object.bytes.clone(),
            },
        );
    }
}

pub(super) fn configuration(
    descriptor: &NodeDescriptor,
    content: &BTreeMap<String, (ContentRef, Vec<u8>)>,
) -> Result<Configuration, NodeObservedError> {
    let (reference, bytes) = content
        .get(&descriptor.configuration_ref.hash.digest)
        .filter(|(reference, _)| reference == &descriptor.configuration_ref)
        .ok_or_else(|| refused("recorded input original configuration absent"))?;
    reference.verify(bytes)?;
    Ok(serde_json::from_slice(bytes)?)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordRoot {
    format: String,
    version: u16,
    source: ContentRef,
    projection: ContentRef,
    recipe: ContentRef,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingProjection {
    format: String,
    version: u16,
    designated_slot: String,
    world: NodeScenario,
    configuration: NodeRunConfiguration,
}

fn object(
    content: &BTreeMap<String, (ContentRef, Vec<u8>)>,
    reference: &ContentRef,
) -> Result<InputPayload, NodeObservedError> {
    let (actual, bytes) = content
        .get(&reference.hash.digest)
        .filter(|(actual, _)| actual == reference)
        .ok_or_else(|| refused("recorded input complete original object is absent"))?;
    actual.verify(bytes)?;
    Ok(InputPayload {
        reference: actual.clone(),
        bytes: bytes.clone(),
    })
}

pub(super) fn from_content(
    descriptor: &NodeDescriptor,
    content: &BTreeMap<String, (ContentRef, Vec<u8>)>,
) -> Result<RecordedIngressDefinition, NodeObservedError> {
    let configuration = configuration(descriptor, content)?;
    if configuration.schema_version != 1 {
        return Err(refused("recorded input configuration edition differs"));
    }
    let root = configuration
        .record_root
        .ok_or_else(|| refused("recorded input configuration has no complete source root"))?;
    let root_object = object(content, &root)?;
    let document: RecordRoot = serde_json::from_slice(&root_object.bytes)?;
    if document.format != "crucible.recorded-input-root"
        || document.version != 1
        || document.source != configuration.recorded_source
    {
        return Err(refused(
            "recorded input root codec or original source differs",
        ));
    }
    let definition = RecordedIngressDefinition::new(
        object(content, &document.source)?,
        object(content, &document.projection)?,
        object(content, &document.recipe)?,
    )
    .map_err(super::native)?;
    if definition.root() != &root {
        return Err(refused("recorded input original root bytes differ"));
    }
    check_configuration(&configuration.run_configuration, &definition)?;
    Ok(definition)
}

pub(in crate::node_observed_executor) fn from_scenario(
    scenario: &NodeScenario,
    node: &Id,
) -> Result<RecordedIngressDefinition, NodeObservedError> {
    let descriptor = scenario
        .descriptors
        .iter()
        .find(|descriptor| &descriptor.id == node)
        .ok_or_else(|| refused("recorded input node is absent"))?;
    let content = scenario
        .content
        .iter()
        .map(|object| {
            (
                object.reference.hash.digest.clone(),
                (object.reference.clone(), object.bytes.clone()),
            )
        })
        .collect();
    from_content(descriptor, &content)
}

pub(in crate::node_observed_executor) fn check_configuration(
    configuration: &NodeRunConfiguration,
    definition: &RecordedIngressDefinition,
) -> Result<(), NodeObservedError> {
    let projection: BindingProjection = serde_json::from_slice(&definition.objects()[1].bytes)?;
    if projection.format != "crucible.recorded-input-binding-projection"
        || projection.version != 1
        || projection.designated_slot != "single selected Block configuration.record_root"
        || canonical::canonical_json(&serde_json::to_value(&projection.configuration)?)?
            != canonical::canonical_json(&serde_json::to_value(configuration)?)?
        || projection.world.descriptors.len() != 1
        || projection.world.descriptors[0].id != definition.source().endpoint.node_id
        || definition.source().closed_before.time_ps <= configuration.horizon_ps
    {
        return Err(refused(
            "recorded input original world/run projection differs",
        ));
    }
    // The first pass is a complete independently regenerated world. Only its
    // designated record-root field is absent; none of its other policy is elided.
    let content = projection
        .world
        .content
        .iter()
        .map(|object| {
            (
                object.reference.hash.digest.clone(),
                (object.reference.clone(), object.bytes.clone()),
            )
        })
        .collect();
    let projected = self::configuration(&projection.world.descriptors[0], &content)?;
    if projected.record_root.is_some()
        || projected.recorded_source != definition.objects()[0].reference
        || canonical::canonical_json(&serde_json::to_value(&projected.run_configuration)?)?
            != canonical::canonical_json(&serde_json::to_value(configuration)?)?
    {
        return Err(refused(
            "recorded input projection excluded more than its designated root",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "recorded_ingress_tests.rs"]
mod tests;
