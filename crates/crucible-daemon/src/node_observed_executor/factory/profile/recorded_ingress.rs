//! Distinct exact Block profile with complete original logical input ownership.

use super::*;
use crate::node_observed_executor::factory::recorded_ingress::{
    self, InstalledRecordedIngressProfile,
};
use crucible::node_adapters::{HOST_PRESERVATION_PROFILE, RecordedIngressDefinition};
use crucible::node_scheduling::InputPayload;

pub(super) fn profile(
    selected: &InstalledNodeSelection,
    source: &InstalledRecordedIngressProfile,
    artifacts: &BTreeMap<String, super::super::InstalledIoArtifact>,
    host: &ContentRef,
    qualification: &ContentRef,
    projection: Option<&InputPayload>,
    contents: &mut BTreeMap<String, ScenarioContent>,
) -> Result<(NodeDescriptor, BindingCompatibility, OwnerBinding, bool), NodeObservedError> {
    let original = recorded_ingress::source(selected, source, artifacts)?;
    contents.insert(
        original.reference.hash.digest.clone(),
        ScenarioContent {
            reference: original.reference.clone(),
            bytes: original.bytes.clone(),
        },
    );
    let recipe = if matches!(
        &selected.kind,
        InstalledNodeKind::HostRecordedBlockPreserving { .. }
    ) {
        recorded_ingress::preserving_recipe(host, source)?
    } else {
        recorded_ingress::recipe(host, source)?
    };
    contents.insert(
        recipe.reference.hash.digest.clone(),
        ScenarioContent {
            reference: recipe.reference.clone(),
            bytes: recipe.bytes.clone(),
        },
    );
    let root = match projection {
        Some(projection) => {
            let definition = RecordedIngressDefinition::new(original, projection.clone(), recipe)
                .map_err(native)?;
            recorded_ingress::insert_definition(&definition, contents);
            Some(definition.root().clone())
        }
        None => None,
    };
    let (mut descriptor, mut binding, owner, _) = io::io_profile(
        selected,
        &source.storage,
        artifacts,
        host,
        qualification,
        contents,
    )?;
    let native_configuration = descriptor.configuration_ref.clone();
    descriptor.configuration_ref = put_json(
        contents,
        &recorded_ingress::Configuration {
            schema_version: 1,
            native_profile: source.storage.clone(),
            recorded_source: source.source.clone(),
            run_configuration: source.configuration.clone(),
            record_root: root,
            native_configuration,
        },
    )?;
    descriptor.model_ref = put(contents,
        b"crucible installed recorded Block ingress v1: actual ScheduledIoNode owns native Block state plus the complete immutable authored logical input source, original event identities and FIFO ordinals, remaining arrival prefix and semantic consumption cursor; no physical sampling or host-clock conversion; exact selected endpoint and request codec; staging is not consumption; source cursor capture and restoration are unqualified".to_vec(), "text/plain")?;
    binding.descriptor_hash = descriptor.identity()?;
    binding.configuration_ref = descriptor.configuration_ref.clone();
    binding.implementation.implementation_id = Id::new("crucible-host-recorded-block-v1")?;
    binding.implementation.model_definitions = vec![descriptor.model_ref.clone()];
    binding
        .implementation
        .formats
        .retain(|schema| schema.id.as_str() != "host/native-continuation-v1");
    binding.operating_contract.facets.retain(|facet| {
        !matches!(
            facet.id.as_str(),
            HOST_PRESERVATION_PROFILE | "host/physical-pause-v1"
        )
    });
    let mut guarantees: GuaranteeProfile =
        serde_json::from_slice(&contents[&binding.guarantees_ref.hash.digest].bytes)?;
    guarantees.limitations_ref = put(contents,
        b"recorded Block v1: immutable authored logical arrivals only; source-owned complete FIFO and semantic consumption cursor; physical sampling, pause, capture, restore, replay, fork and live external effects remain unqualified".to_vec(), "text/plain")?;
    guarantees.capture_scope = CaptureScope::None;
    guarantees.durable_restart = false;
    guarantees.continuation = Continuation::Unsupported;
    binding.guarantees_ref = put_json(contents, &guarantees)?;
    for facet in &mut binding.operating_contract.facets {
        facet.configuration_ref = descriptor.configuration_ref.clone();
        facet.guarantees_ref = binding.guarantees_ref.clone();
    }
    let mut capabilities: CapabilityProfile =
        serde_json::from_slice(&contents[&binding.capabilities_ref.hash.digest].bytes)?;
    capabilities.facets = binding.operating_contract.facets.clone();
    capabilities.devices_ref = put_json(
        contents,
        &serde_json::json!({
            "schema_version":1,"native_model":"recorded-block-v1","complete_ports":descriptor.ports,
            "immutable_base":source.storage.artifact(),"original_records":source.source,
            "source_cursor_capture":"unqualified","physical_sampling":false
        }),
    )?;
    binding.capabilities_ref = put_json(contents, &capabilities)?;
    binding.profile_ref = put_json(
        contents,
        &serde_json::json!({
            "schema_version":1,"descriptor":descriptor,"implementation":binding.implementation,
            "operating_contract":binding.operating_contract,"capabilities":capabilities,"guarantees":guarantees
        }),
    )?;
    Ok((descriptor, binding, owner, false))
}

/// Builds the distinct complete cursor codec without changing live format one.
pub(super) fn preserving_profile(
    selected: &InstalledNodeSelection,
    source: &InstalledRecordedIngressProfile,
    artifacts: &BTreeMap<String, super::super::InstalledIoArtifact>,
    host: &ContentRef,
    qualification: &ContentRef,
    projection: Option<&InputPayload>,
    contents: &mut BTreeMap<String, ScenarioContent>,
) -> Result<(NodeDescriptor, BindingCompatibility, OwnerBinding, bool), NodeObservedError> {
    let (mut descriptor, mut binding, owner, _) = profile(
        selected,
        source,
        artifacts,
        host,
        qualification,
        projection,
        contents,
    )?;
    // The projection owns the entire first-pass world. Its original configuration
    // and profile bodies remain distinct dependencies after the root slot is filled.
    if let Some(projection) = projection {
        for object in recorded_ingress::projection_contents(projection)? {
            contents.insert(object.reference.hash.digest.clone(), object);
        }
    }
    let original_source = recorded_ingress::source(selected, source, artifacts)?;
    let document = crucible::node_adapters::validate_recorded_input_source(&original_source)
        .map_err(native)?;
    for input in document.inputs {
        contents.insert(
            input.payload.reference.hash.digest.clone(),
            ScenarioContent {
                reference: input.payload.reference,
                bytes: input.payload.bytes,
            },
        );
    }
    let (_, original, _, _) = io::io_profile(
        selected,
        &source.storage,
        artifacts,
        host,
        qualification,
        contents,
    )?;
    let mut configuration: recorded_ingress::Configuration =
        serde_json::from_slice(&contents[&descriptor.configuration_ref.hash.digest].bytes)?;
    configuration.schema_version = 2;
    descriptor.configuration_ref = put_json(contents, &configuration)?;
    descriptor.model_ref = put(contents,
        b"crucible installed recorded Block preservation v1: native Block overlay, original staged request and response FIFO plus operation and input ACK ledgers; authenticated original consumed source cursor and activation proof history in complete native envelope edition5; signed whole runtime and scheduler required; current fresh target authority distinct from historical proofs; no physical ingress or 9p".to_vec(), "text/plain")?;
    binding.descriptor_hash = descriptor.identity()?;
    binding.configuration_ref = descriptor.configuration_ref.clone();
    binding.implementation.implementation_id =
        Id::new("crucible-host-recorded-block-preserving-v1")?;
    binding.implementation.model_definitions = vec![descriptor.model_ref.clone()];
    binding.implementation.formats.push(crucible_node_contract::SchemaRef {
        id: Id::new("host/native-recorded-block-v1")?, version: 1, extensions: Extensions::new(),
        definition: put(contents, b"Complete native Host envelope edition5: unchanged Block state and original operation/input/ACK ledgers, exact source/projection/recipe/root bodies, native consumed FIFO cursor and original activation proof histories. Requires signed complete runtime/scheduling and independently regenerated installed policy before fresh allocation.".to_vec(), "text/plain")?,
    });
    let mut guarantees: GuaranteeProfile =
        serde_json::from_slice(&contents[&original.guarantees_ref.hash.digest].bytes)?;
    guarantees.limitations_ref = put(contents, b"Single independently installed finite recorded Block owner: complete unchanged-cut preservation of native CoW/FIFO and original source consumption ledger at proof-bearing runtime2 cuts; initial no-provenance runtime1 capture is unsupported; no 9p, physical sampling, replay, fork, terminal or debug authority.".to_vec(), "text/plain")?;
    binding.guarantees_ref = put_json(contents, &guarantees)?;
    binding.operating_contract.facets = original.operating_contract.facets;
    for facet in &mut binding.operating_contract.facets {
        facet.configuration_ref = descriptor.configuration_ref.clone();
        facet.guarantees_ref = binding.guarantees_ref.clone();
    }
    let mut capabilities: CapabilityProfile =
        serde_json::from_slice(&contents[&binding.capabilities_ref.hash.digest].bytes)?;
    capabilities.facets = binding.operating_contract.facets.clone();
    capabilities.devices_ref = put_json(
        contents,
        &serde_json::json!({
            "schema_version":2,"native_model":"recorded-block-preserving-v1","complete_ports":descriptor.ports,
            "immutable_base":source.storage.artifact(),"original_records":source.source,
            "source_cursor_capture":"complete-original-consumed-ledger","physical_sampling":false
        }),
    )?;
    binding.capabilities_ref = put_json(contents, &capabilities)?;
    binding.profile_ref = put_json(
        contents,
        &serde_json::json!({
            "schema_version":2,"descriptor":descriptor,"implementation":binding.implementation,
            "operating_contract":binding.operating_contract,"capabilities":capabilities,"guarantees":guarantees
        }),
    )?;
    Ok((descriptor, binding, owner, true))
}
