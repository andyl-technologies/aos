//! Exact opaque storage-request transport with selected seeded fault custody.

use super::*;
use crucible_node_contract::Direction;

pub(super) fn profile(
    selected: &InstalledNodeSelection,
    selections: &[InstalledNodeSelection],
    profile: &super::super::seeded::InstalledSeededLinkProfile,
    artifacts: &BTreeMap<String, super::super::InstalledIoArtifact>,
    host: &ContentRef,
    qualification: &ContentRef,
    contents: &mut BTreeMap<String, ScenarioContent>,
) -> Result<(NodeDescriptor, BindingCompatibility, OwnerBinding, bool), NodeObservedError> {
    let source = selections
        .iter()
        .find(|entry| entry.node == profile.producer)
        .ok_or_else(|| refused("seeded transport original source missing"))?;
    if !matches!(&source.kind, InstalledNodeKind::HostScripted {profile:source_profile}
        if source_profile.consumer == selected.node)
    {
        return Err(refused(
            "seeded transport requires its enrolled immutable source",
        ));
    }
    let sink = selections
        .iter()
        .find(|entry| entry.node == profile.consumer)
        .ok_or_else(|| refused("seeded transport storage consumer missing"))?;
    let InstalledNodeKind::HostIo {
        profile: io_profile,
    } = &sink.kind
    else {
        return Err(refused(
            "seeded transport only qualifies native storage requests",
        ));
    };
    if !matches!(
        io_profile,
        super::super::InstalledHostIoProfile::Block { .. }
    ) {
        return Err(refused(
            "selected seeded transport edition qualifies only native block requests",
        ));
    }
    let (definition, program) = super::super::seeded::definition(profile, artifacts)?;
    put(contents, program, &profile.program.media_type)?;
    let native = super::super::seeded::build_model(selected, profile, artifacts)?;
    let (sink_descriptor, _, _, _) =
        io::io_profile(sink, io_profile, artifacts, host, qualification, contents)?;
    let (mut descriptor, mut binding, owner, _) =
        clock_profile(selected, host, qualification, contents)?;
    descriptor.roles = vec![Id::new("seeded_byte_transport")?];
    descriptor.model_ref = put(contents,
        b"crucible seeded storage-request transport v1: existing NetLink exact integer static jitter and reorder; five original seeded decision draws per frame; opaque original request bytes and correlations; seed/name/fault table/native clock/sequence/pending frames plus complete original runtime/input/ACK and coordinator FIFO custody; finite 16-frame Block source, no Ethernet interpretation, loss, duplication, corruption, external input or dynamic fault controller".to_vec(), "text/plain")?;
    descriptor.configuration_ref = put_json(
        contents,
        &serde_json::json!({
            "version":1,"program_ref":profile.program,"definition":definition,
            "producer":profile.producer,"consumer":profile.consumer,"stream_domain":"crucible/seeded-link-v1"
        }),
    )?;
    descriptor.initialization_ref = put(
        contents,
        native
            .initialization_bytes(16 * 1024 * 1024)
            .map_err(|error| refused(&error.reason))?,
        "application/octet-stream",
    )?;
    let mut port = sink_descriptor
        .ports
        .first()
        .cloned()
        .ok_or_else(|| refused("actual storage port inventory missing"))?;
    let mut lane = port
        .lanes
        .iter()
        .find(|lane| lane.direction == Direction::Input)
        .cloned()
        .ok_or_else(|| refused("actual storage request lane missing"))?;
    let request_schema = lane.payload_schema.clone();
    lane.id = Id::new("output")?;
    lane.direction = Direction::Output;
    port.lanes.retain(|lane| lane.direction == Direction::Input);
    port.lanes.push(lane);
    let mut policy: crucible::node_admission::PortPolicy =
        serde_json::from_slice(&contents[&port.configuration_ref.hash.digest].bytes)?;
    policy.execution_owner_id = selected.owner.clone();
    policy.state_domain_ids = vec![Id::new(format!("{}/state", selected.owner))?];
    for lane in &mut policy.lanes {
        lane.minimum_lookahead_ps = definition.floor_ps;
    }
    port.configuration_ref = put_json(contents, &policy)?;
    descriptor.ports = vec![port];
    binding.descriptor_hash = descriptor.identity()?;
    binding.configuration_ref = descriptor.configuration_ref.clone();
    binding.implementation.implementation_id = Id::new("crucible-host-seeded-storage-link")?;
    binding.implementation.model_definitions = vec![descriptor.model_ref.clone()];
    binding
        .implementation
        .formats
        .retain(|format| format.id.as_str() != "host/native-continuation-v1");
    binding.implementation.formats.extend([
        crucible_node_contract::SchemaRef {
            id: Id::new("host/native-seeded-link-v1")?, version:1,
            definition: put(contents, b"seeded link native envelope v1: original definition plus existing canonical LinkSnapshot and full host custody; selected seed/name/timing/faults must remain exact; never decoded as legacy fault-free link".to_vec(), "text/plain")?,
            extensions: Extensions::new(),
        }, request_schema,
    ]);
    binding
        .implementation
        .formats
        .sort_by(|left, right| left.id.cmp(&right.id));
    binding.operating_contract.policy_ref = put_json(
        contents,
        &serde_json::json!({
            "mode":"exact","schema_version":1,"execution_proof_ref":qualification,
            "ceiling":{"kind":"input_blocked","proof_ref":qualification},
            "boundary_settlement_ref":qualification
        }),
    )?;
    let mut guarantees: GuaranteeProfile =
        serde_json::from_slice(&contents[&binding.guarantees_ref.hash.digest].bytes)?;
    guarantees.durable_restart = true;
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
            "version":1,"native_model":"seeded_storage_link","program_ref":profile.program,
            "complete_ports":descriptor.ports,"static_faults":{"jitter_ps":definition.jitter_ps,"reorder_ps":definition.reorder_ps,"loss":"never","duplicate":"never","corrupt":"never","partitioned":false,"bandwidth_caps":[]},"dynamic_faults":[],"stream_domain":"crucible/seeded-link-v1"
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
    Ok((descriptor, binding, owner, true))
}
