//! Source-qualified coefficient controllers with immutable timing and original mutation custody.

use super::*;
use crucible_node_contract::Direction;

pub(super) fn profile(
    selected: &InstalledNodeSelection,
    selections: &[InstalledNodeSelection],
    profile: &super::super::controlled::InstalledControlledFaultProfile,
    artifacts: &BTreeMap<String, super::super::InstalledIoArtifact>,
    host: &ContentRef,
    qualification: &ContentRef,
    contents: &mut BTreeMap<String, ScenarioContent>,
) -> Result<(NodeDescriptor, BindingCompatibility, OwnerBinding, bool), NodeObservedError> {
    let source = selections
        .iter()
        .find(|entry| entry.node == profile.producer)
        .ok_or_else(|| refused("faulted transport original source missing"))?;
    if !matches!(&source.kind, InstalledNodeKind::HostScripted {profile:source_profile}
        if source_profile.consumer == selected.node)
    {
        return Err(refused(
            "faulted transport requires its enrolled immutable source",
        ));
    }
    let sink = selections
        .iter()
        .find(|entry| entry.node == profile.consumer)
        .ok_or_else(|| refused("faulted transport storage consumer missing"))?;
    let (definition, program) = super::super::controlled::definition(profile, artifacts)?;
    put(contents, program, &profile.program.media_type)?;
    let native = super::super::controlled::build_model(selected, profile, artifacts)?;
    let (sink_descriptor, _, _, _) = match &sink.kind {
        InstalledNodeKind::HostIo {
            profile: io_profile,
        } if matches!(
            io_profile,
            super::super::InstalledHostIoProfile::Block { .. }
        ) =>
        {
            if definition.initial.corrupt.numerator.get() != 0
                || definition
                    .transitions
                    .iter()
                    .any(|transition| transition.coefficients.corrupt.numerator.get() != 0)
            {
                return Err(refused(
                    "Block request transport refuses arbitrary byte corruption",
                ));
            }
            io::io_profile(sink, io_profile, artifacts, host, qualification, contents)?
        }
        InstalledNodeKind::HostPacketReceiver {
            source_node,
            latency_ps,
        } => super::packet::profile(
            sink,
            *source_node,
            *latency_ps,
            host,
            qualification,
            contents,
        )?,
        _ => {
            return Err(refused(
                "adverse transport requires native Block or opaque packet receiver",
            ));
        }
    };
    let (mut descriptor, mut binding, owner, _) =
        clock_profile(selected, host, qualification, contents)?;
    descriptor.roles = vec![Id::new("controlled_fault_transport")?];
    descriptor.model_ref = put(contents,
        b"crucible controlled byte transport v1: immutable authored BoundaryControl loss/duplicate/corrupt coefficients; actual original runtime operation and native decision receipts; unchanged positive timing/floor/topology and retained already-resolved outputs; complete controller/input/draw/table/native/FIFO/ACK histories; distinct explicit fault operation and selected continuation editions".to_vec(), "text/plain")?;
    descriptor.configuration_ref = put_json(
        contents,
        &serde_json::json!({
            "version": 1,
            "program_ref": profile.program,
            "controller": definition,
            "producer": profile.producer,
            "consumer": profile.consumer,
            "stream_domain": "crucible/controlled-fault-link-v1"
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
        lane.minimum_lookahead_ps = definition.initial.floor_ps;
    }
    port.configuration_ref = put_json(contents, &policy)?;
    descriptor.ports = vec![port];
    binding.descriptor_hash = descriptor.identity()?;
    binding.configuration_ref = descriptor.configuration_ref.clone();
    binding.implementation.implementation_id = Id::new("crucible-host-controlled-fault-link")?;
    binding.implementation.model_definitions = vec![descriptor.model_ref.clone()];
    binding
        .implementation
        .formats
        .retain(|format| format.id.as_str() != "host/native-continuation-v1");
    binding.implementation.formats.extend([
        crucible_node_contract::SchemaRef {
            id: Id::new("host/native-controlled-fault-link-v1")?,
            version: 1,
            definition: put(contents, b"controlled fault native v1: Host envelope3 plus immutable controller and complete native mutation/input journals; runtime4 and selected coordinator3 preserve original contexts and receipts; later inputs only receive changed coefficients; old native/control codecs refuse".to_vec(), "text/plain")?,
            extensions: Extensions::new(),
        },
        request_schema,
    ]);
    binding
        .implementation
        .formats
        .sort_by(|left, right| left.id.cmp(&right.id));
    binding.operating_contract.policy_ref = put_json(
        contents,
        &serde_json::json!({
            "mode": "exact",
            "schema_version": 1,
            "execution_proof_ref": qualification,
            "ceiling": {"kind": "input_blocked", "proof_ref": qualification},
            "boundary_settlement_ref": qualification
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
    binding
        .operating_contract
        .facets
        .push(crucible_node_contract::FacetSelection {
            id: Id::new(crucible::node_adapters::HOST_FAULT_INJECTION_PROFILE)?,
            version: 1,
            configuration_ref: descriptor.configuration_ref.clone(),
            guarantees_ref: binding.guarantees_ref.clone(),
            extensions: Extensions::new(),
        });
    binding
        .operating_contract
        .facets
        .sort_by(|left, right| left.id.cmp(&right.id));
    capabilities.facets = binding.operating_contract.facets.clone();
    capabilities.devices_ref = put_json(
        contents,
        &serde_json::json!({
            "version":1,
            "native_model":"controlled_fault_transport",
            "program_ref":profile.program,
            "controller":definition,
            "complete_ports":descriptor.ports,
            "operation":"FaultInjectionV1",
            "runtime_schema_version":4,
            "coordinator_schema_version":3,
            "unchanged_timing":true,
            "debug_operations":[],
            "stream_domain":"crucible/controlled-fault-link-v1"
        }),
    )?;
    binding.capabilities_ref = put_json(contents, &capabilities)?;
    binding.profile_ref = put_json(
        contents,
        &serde_json::json!({
            "schema_version": 1,
            "descriptor": descriptor,
            "implementation": binding.implementation,
            "operating_contract": binding.operating_contract,
            "capabilities": capabilities,
            "guarantees": guarantees
        }),
    )?;
    Ok((descriptor, binding, owner, true))
}
