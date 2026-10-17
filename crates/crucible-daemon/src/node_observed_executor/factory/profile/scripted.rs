//! Exact output-only profiles bound to measured finite immutable request scripts.

use super::*;
use crate::node_observed_executor::factory::{
    io::{InstalledIoArtifact, read_artifact},
    scripted::{InstalledScriptedSourceProfile, build_model},
};
use crucible::node_adapters::{HostModel, ScriptedRequestKind};
use crucible::node_admission::{FlowControl, LanePolicy, LaneVisibility, PortPolicy};
use crucible_node_contract::{Direction, LaneDescriptor, PortDescriptor};

pub(super) fn scripted_profile(
    selected: &InstalledNodeSelection,
    profile: &InstalledScriptedSourceProfile,
    artifacts: &BTreeMap<String, InstalledIoArtifact>,
    host: &ContentRef,
    qualification: &ContentRef,
    contents: &mut BTreeMap<String, ScenarioContent>,
) -> Result<(NodeDescriptor, BindingCompatibility, OwnerBinding, bool), NodeObservedError> {
    let artifact = artifacts
        .get(&profile.script.hash.digest)
        .filter(|artifact| artifact.expected == profile.script)
        .ok_or_else(|| refused("source profile has no enrolled complete immutable script"))?;
    let script = read_artifact(artifact)?;
    put(contents, script, &profile.script.media_type)?;
    let model = build_model(selected, profile, artifacts)?;
    let HostModel::ScriptedSource(source) = &model else {
        return Err(refused(
            "installed source factory returned another native model",
        ));
    };
    let role = match source.kind() {
        ScriptedRequestKind::Block => "block",
        ScriptedRequestKind::Ninep => "filesystem",
        ScriptedRequestKind::Packet => "packet",
        ScriptedRequestKind::RateAlarmClock => "rate_alarm_clock",
    };
    // Payloads are retained independently in the archive closure as well as in
    // the original script. Content identity does not fabricate input authority.
    for request in source.requests() {
        put(
            contents,
            request.payload.clone(),
            "application/octet-stream",
        )?;
    }
    let (mut descriptor, mut binding, owner, _) =
        clock_profile(selected, host, qualification, contents)?;
    descriptor.roles = vec![Id::new("scripted_source")?];
    descriptor.model_ref = put(contents,
        b"crucible finite scripted public source v1: one immutable ordered script of at most 16 complete native requests; original Reaction microstep zero births Publication microstep one exactly once, including future publication beyond the original cut; native cursor advances atomically with the retained original outcome; native clock, original publication sequence and complete runtime/coordinator publication and receipt/ACK custody are captured; no ingress, timers, worker, cancellation or faults".to_vec(), "text/plain")?;
    descriptor.configuration_ref = put_json(
        contents,
        &serde_json::json!({
            "schema_version":1,"native_profile":profile,"request_kind":role,
            "maximum_requests":"16","evaluation_microstep":"0","publication_microstep":"1"
        }),
    )?;
    descriptor.initialization_ref = put(
        contents,
        model
            .initialization_bytes(16 * 1024 * 1024)
            .map_err(|error| refused(&error.reason))?,
        "application/octet-stream",
    )?;
    let request = if source.kind() == ScriptedRequestKind::RateAlarmClock {
        super::rate_alarm_clock::payload_schema(contents)?
    } else if source.kind() == ScriptedRequestKind::Packet {
        super::packet::schema(contents)?
    } else {
        super::io::wire_schema(role, "request", contents)?
    };
    let ordering = if source.kind() == ScriptedRequestKind::RateAlarmClock {
        super::rate_alarm_clock::ordering(contents)?
    } else if source.kind() == ScriptedRequestKind::Packet {
        super::packet::ordering(contents)?
    } else {
        super::io::ordering(contents)?
    };
    let maximum = if source.kind() == ScriptedRequestKind::RateAlarmClock {
        512
    } else {
        crucible_shmem::MAX_FRAME_DATA as u64
    };
    let port_policy = PortPolicy {
        schema_version: 1,
        lanes: vec![LanePolicy {
            lane_id: Id::new("output")?,
            ordering_ref: ordering.clone(),
            correlation_ref: ordering.clone(),
            flow_control: FlowControl::Credit,
            maximum_pending_bytes: (maximum * 16).into(),
            visibility: LaneVisibility::Exact,
            effect_phases: vec![1],
            minimum_lookahead_ps: 0.into(),
        }],
        maximum_producers: 1.into(),
        maximum_consumers: 1.into(),
        arbitration_ref: ordering,
        execution_owner_id: selected.owner.clone(),
        state_domain_ids: vec![Id::new(format!("{}/state", selected.owner))?],
        internal: false,
    };
    descriptor.ports = vec![PortDescriptor {
        id: Id::new("data")?,
        interface_id: Id::new(format!("crucible/{role}-v1"))?,
        features: Vec::new(),
        configuration_ref: put_json(contents, &port_policy)?,
        lanes: vec![LaneDescriptor {
            id: Id::new("output")?,
            direction: Direction::Output,
            payload_schema: request.clone(),
            maximum_payload_bytes: maximum.into(),
            maximum_pending_events: 16.into(),
            extensions: Extensions::new(),
        }],
        extensions: Extensions::new(),
    }];
    binding.descriptor_hash = descriptor.identity()?;
    binding.configuration_ref = descriptor.configuration_ref.clone();
    binding.implementation.implementation_id = Id::new("crucible-host-scripted-source")?;
    binding.implementation.model_definitions = vec![descriptor.model_ref.clone()];
    if source.kind() == ScriptedRequestKind::Packet {
        descriptor.model_ref = put(contents,b"crucible finite opaque packet source v1: at most 16 independently installed original bounded byte vectors at exact ordered Reaction births; no protocol decoder/validity claim; native kind3 script and cursor, original publication/input/ACK custody preserved".to_vec(),"text/plain")?;
        binding.implementation.model_definitions = vec![descriptor.model_ref.clone()];
        binding.implementation.implementation_id = Id::new("crucible-host-scripted-packet-source")?;
        binding.descriptor_hash = descriptor.identity()?;
    }
    binding.implementation.formats.push(request);
    binding
        .implementation
        .formats
        .sort_by(|left, right| left.id.cmp(&right.id));
    let mut guarantees: GuaranteeProfile =
        serde_json::from_slice(&contents[&binding.guarantees_ref.hash.digest].bytes)?;
    // The installed signed archive binds the original script and native cursor
    // to coordinator-owned future publications and every connected custody
    // domain before fresh owners may resume the saved continuation.
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
            "schema_version":1,"native_model":"scripted_source","complete_ports":descriptor.ports,
            "immutable_script_ref":profile.script,"input_ports":[],"workers":[],"faults":[],"timers":[]
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
