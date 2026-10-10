//! Distinct installed live event-condition operation and frontier scope.

use super::super::condition_debug::{
    InstalledConditionDebugProfile, MAXIMUM_EVENTS, MAXIMUM_STATE_BYTES, build_model, read_program,
};
use super::*;
use crucible::node_admission::{FlowControl, LanePolicy, LaneVisibility, PortPolicy};
use crucible_node_contract::{Direction, LaneDescriptor, PortDescriptor, SchemaRef};

pub(super) fn selected(selections: &[InstalledNodeSelection]) -> Result<bool, NodeObservedError> {
    let count = selections
        .iter()
        .filter(|selected| matches!(selected.kind, InstalledNodeKind::HostConditionDebug { .. }))
        .count();
    if count == 0 {
        return Ok(false);
    }
    if count != 1
        || selections.iter().any(|selected| {
            !matches!(
                selected.kind,
                InstalledNodeKind::HostClock
                    | InstalledNodeKind::HostConditionDebug { .. }
                    | InstalledNodeKind::HostScripted { .. }
                    | InstalledNodeKind::HostIo {
                        profile: super::super::io::InstalledHostIoProfile::Block { .. }
                    }
            )
        })
    {
        return Err(refused(
            "condition frontier scope requires one observer and qualified finite Source/Block/Clock nodes",
        ));
    }
    Ok(true)
}

pub(super) fn profile(
    selected: &InstalledNodeSelection,
    selections: &[InstalledNodeSelection],
    profile: &InstalledConditionDebugProfile,
    artifacts: &BTreeMap<String, super::super::InstalledIoArtifact>,
    host: &ContentRef,
    qualification: &ContentRef,
    contents: &mut BTreeMap<String, ScenarioContent>,
) -> Result<(NodeDescriptor, BindingCompatibility, OwnerBinding, bool), NodeObservedError> {
    let (definition, program) = read_program(profile, artifacts)?;
    put(contents, program, &profile.program.media_type)?;
    let model = build_model(selected, selections, profile, artifacts)?;
    let (mut descriptor, mut binding, owner, _) =
        clock_profile(selected, host, qualification, contents)?;
    descriptor.roles = vec![Id::new("condition_observer")?];
    descriptor.model_ref = put(contents,
        b"crucible original event-condition observer v1: actual existing host evaluator and compact immutable Sometimes IoAny program over a decoded native Block terminal reply; full original input/proof/event/checkpoint and first hit; independently authenticated common native/coordinator stop fence may retain future work; original diagnostic report and once-only stop/ACK/resume control journal; no retrospective stop, EOF, terminal finalization, guest PC/register/memory mutation or gdb claim".to_vec(), "text/plain")?;
    descriptor.configuration_ref = put_json(
        contents,
        &serde_json::json!({
            "schema_version": 1, "native_profile": profile, "definition": definition,
            "maximum_events": MAXIMUM_EVENTS.to_string(), "maximum_state_bytes": MAXIMUM_STATE_BYTES.to_string(),
            "stop_policy": "authentic_common_cut_with_future_work_retained", "publication": "diagnostic_out_of_band_original_roots_before_ack",
        }),
    )?;
    descriptor.initialization_ref = put(
        contents,
        model.capture().map_err(|error| refused(&error.reason))?,
        "application/octet-stream",
    )?;
    let response = super::io::wire_schema("block", "response", contents)?;
    let ordering = super::io::ordering(contents)?;
    let domain = Id::new(format!("{}/state", selected.owner))?;
    let policy = PortPolicy {
        schema_version: 1,
        lanes: vec![LanePolicy {
            lane_id: Id::new("input")?,
            ordering_ref: ordering.clone(),
            correlation_ref: ordering.clone(),
            flow_control: FlowControl::Credit,
            maximum_pending_bytes: (crucible_shmem::MAX_FRAME_DATA as u64 * 16).into(),
            visibility: LaneVisibility::Exact,
            effect_phases: vec![1],
            minimum_lookahead_ps: 0.into(),
        }],
        maximum_producers: 1.into(),
        maximum_consumers: 0.into(),
        arbitration_ref: ordering,
        execution_owner_id: selected.owner.clone(),
        state_domain_ids: vec![domain],
        internal: false,
    };
    descriptor.ports = vec![PortDescriptor {
        id: Id::new("data")?,
        interface_id: Id::new("crucible/block-v1")?,
        features: Vec::new(),
        configuration_ref: put_json(contents, &policy)?,
        lanes: vec![LaneDescriptor {
            id: Id::new("input")?,
            direction: Direction::Input,
            payload_schema: response.clone(),
            maximum_payload_bytes: (crucible_shmem::MAX_FRAME_DATA as u64).into(),
            maximum_pending_events: 16.into(),
            extensions: Extensions::new(),
        }],
        extensions: Extensions::new(),
    }];
    let control = SchemaRef {
        id: Id::new("crucible/host-condition-control-v1")?,
        version: 1,
        definition: put(
            contents,
            super::super::condition_debug::CONTROL_SCHEMA.to_vec(),
            "text/plain",
        )?,
        extensions: Extensions::new(),
    };
    binding.descriptor_hash = descriptor.identity()?;
    binding.configuration_ref = descriptor.configuration_ref.clone();
    binding.implementation.implementation_id = Id::new("crucible-host-condition-debug")?;
    binding.implementation.model_definitions = vec![descriptor.model_ref.clone()];
    binding.implementation.formats.extend([response, control]);
    binding
        .implementation
        .formats
        .sort_by(|left, right| left.id.cmp(&right.id));
    binding.operating_contract.policy_ref = put_json(
        contents,
        &serde_json::json!({
            "mode": "exact", "schema_version": 1, "execution_proof_ref": qualification,
            "ceiling": {"kind":"input_blocked", "proof_ref":qualification}, "boundary_settlement_ref": qualification,
        }),
    )?;
    // The initial live control profile makes no archive or cold-continuation
    // claim. A separately selected preservation codec must qualify those facts.
    install_scope(&descriptor, &mut binding, contents, true)?;
    Ok((descriptor, binding, owner, false))
}

pub(super) fn install_scope(
    descriptor: &NodeDescriptor,
    binding: &mut BindingCompatibility,
    contents: &mut BTreeMap<String, ScenarioContent>,
    observer: bool,
) -> Result<(), NodeObservedError> {
    let mut template = binding
        .operating_contract
        .facets
        .first()
        .cloned()
        .ok_or_else(|| refused("host operation template absent"))?;
    binding
        .operating_contract
        .facets
        .retain(|facet| facet.id.as_str() != "host/preservation-v1");
    template.id = Id::new("host/condition-inventory-v1")?;
    template.version = 1;
    binding.operating_contract.facets.push(template.clone());
    if observer {
        template.id = Id::new("host/condition-debug-v1")?;
        binding.operating_contract.facets.push(template);
    }
    binding
        .operating_contract
        .facets
        .sort_by(|left, right| left.id.cmp(&right.id));
    binding
        .operating_contract
        .facets
        .dedup_by(|left, right| left.id == right.id);
    let mut guarantees: GuaranteeProfile =
        serde_json::from_slice(&contents[&binding.guarantees_ref.hash.digest].bytes)?;
    guarantees.capture_scope = CaptureScope::None;
    guarantees.continuation = Continuation::Unsupported;
    guarantees.durable_restart = false;
    binding.guarantees_ref = put_json(contents, &guarantees)?;
    for facet in &mut binding.operating_contract.facets {
        facet.configuration_ref = descriptor.configuration_ref.clone();
        facet.guarantees_ref = binding.guarantees_ref.clone();
    }
    let mut capabilities: CapabilityProfile =
        serde_json::from_slice(&contents[&binding.capabilities_ref.hash.digest].bytes)?;
    capabilities.facets = binding.operating_contract.facets.clone();
    if observer {
        capabilities.devices_ref = put_json(
            contents,
            &serde_json::json!({
                "schema_version": 1, "native_model": "condition_observer", "complete_ports": descriptor.ports,
                "observations": ["decoded_terminal_block_io_any"], "control": "original_stop_report_ack_resume",
                "guest_state_mutation": false, "architectural_debugger": false, "capture": "unsupported",
            }),
        )?;
    }
    binding.capabilities_ref = put_json(contents, &capabilities)?;
    binding.profile_ref = put_json(
        contents,
        &serde_json::json!({
            "schema_version": 1, "descriptor": descriptor, "implementation": binding.implementation,
            "operating_contract": binding.operating_contract, "capabilities": capabilities, "guarantees": guarantees,
            "scope": "synchronous_local_event_condition_control_with_future_native_work",
        }),
    )?;
    Ok(())
}
