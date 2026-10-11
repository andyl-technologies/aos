//! Distinct measured rational-clock model, causal request lane and alarm FIFO.

use super::*;
use crucible::node_adapters::{
    HostModel, RateAlarmClock, RateAlarmClockDefinition, host_rate_alarm_clock_schema,
};
use crucible::node_admission::{FlowControl, LanePolicy, LaneVisibility, PortPolicy};
use crucible_node_contract::{Direction, LaneDescriptor, PortDescriptor, SchemaRef};

pub(super) fn profile(
    selected: &InstalledNodeSelection,
    definition: &RateAlarmClockDefinition,
    host: &ContentRef,
    qualification: &ContentRef,
    contents: &mut BTreeMap<String, ScenarioContent>,
) -> Result<(NodeDescriptor, BindingCompatibility, OwnerBinding, bool), NodeObservedError> {
    let model = RateAlarmClock::new(definition.clone()).map_err(|error| refused(&error.reason))?;
    let (mut descriptor, mut binding, owner, _) =
        clock_profile(selected, host, qualification, contents)?;
    descriptor.roles = vec![Id::new("rate_alarm_clock")?];
    descriptor.model_ref = put(contents, b"crucible host rational alarm clock v1: checked fixed rational rate/epoch/drift changes only unsigned 64-bit visible counter readings; overflow refuses without wrapping; shared clock is never rebased; read, future-only alarm and before-reaction cancel use authentic input Reaction coordinates; threshold inverse rounds upwards; native original requests, pending and issued responses retain full Position and once-only FIFO; alarms publish data events without guest interrupt or delivery authority; no wall clock, guest CPU or dynamic rate".to_vec(), "text/plain")?;
    descriptor.configuration_ref = put_json(
        contents,
        &serde_json::json!({"version":1,"definition":definition,"maximum_original_inputs":"64","maximum_pending_events":"64","maximum_native_state_bytes":"65536","counter_width_bits":64,"wrap_policy":"refuse_overflow","read_coordinate":"authorized_reaction","alarm_rounding":"up_to_shared_picosecond","alarm_semantics":"once_only_data_event","dynamic_rate":false}),
    )?;
    descriptor.initialization_ref = put(
        contents,
        HostModel::RateAlarmClock(Box::new(model))
            .initialization_bytes(4 * 1024 * 1024)
            .map_err(|error| refused(&error.reason))?,
        "application/octet-stream",
    )?;
    let schema = payload_schema(contents)?;
    let ordering = ordering(contents)?;
    let policy = PortPolicy {
        schema_version: 1,
        lanes: vec![Direction::Input, Direction::Output]
            .into_iter()
            .map(|direction| {
                Ok(LanePolicy {
                    lane_id: Id::new(if direction == Direction::Input {
                        "input"
                    } else {
                        "output"
                    })?,
                    ordering_ref: ordering.clone(),
                    correlation_ref: ordering.clone(),
                    flow_control: FlowControl::Credit,
                    maximum_pending_bytes: (512u64 * 64).into(),
                    visibility: LaneVisibility::Exact,
                    effect_phases: vec![1],
                    minimum_lookahead_ps: 0.into(),
                })
            })
            .collect::<Result<Vec<_>, crucible_node_contract::ContractError>>()?,
        maximum_producers: 1.into(),
        maximum_consumers: 1.into(),
        arbitration_ref: ordering,
        execution_owner_id: selected.owner.clone(),
        state_domain_ids: vec![Id::new(format!("{}/state", selected.owner))?],
        internal: false,
    };
    descriptor.ports = vec![PortDescriptor {
        id: Id::new("data")?,
        interface_id: Id::new("crucible/rate_alarm_clock-v1")?,
        features: Vec::new(),
        configuration_ref: put_json(contents, &policy)?,
        lanes: vec![Direction::Input, Direction::Output]
            .into_iter()
            .map(|direction| {
                Ok(LaneDescriptor {
                    id: Id::new(if direction == Direction::Input {
                        "input"
                    } else {
                        "output"
                    })?,
                    direction,
                    payload_schema: schema.clone(),
                    maximum_payload_bytes: 512u64.into(),
                    maximum_pending_events: 64.into(),
                    extensions: Extensions::new(),
                })
            })
            .collect::<Result<Vec<_>, crucible_node_contract::ContractError>>()?,
        extensions: Extensions::new(),
    }];
    binding.descriptor_hash = descriptor.identity()?;
    binding.configuration_ref = descriptor.configuration_ref.clone();
    binding.implementation.implementation_id = Id::new("crucible-host-rate-alarm-clock")?;
    binding.implementation.model_definitions = vec![descriptor.model_ref.clone()];
    binding
        .implementation
        .formats
        .retain(|format| format.id.as_str() != "host/native-continuation-v1");
    let native_schema = host_rate_alarm_clock_schema().map_err(|e| refused(&e.reason))?;
    let original_spec = crucible::node_adapters::rate_alarm_clock_specification();
    if put(contents, original_spec.as_bytes().to_vec(), "text/plain")? != native_schema.definition {
        return Err(refused("source-owned clock native specification differs"));
    }
    binding
        .implementation
        .formats
        .extend([schema, native_schema]);
    binding
        .implementation
        .formats
        .sort_by(|left, right| left.id.cmp(&right.id));
    binding.operating_contract.policy_ref = put_json(
        contents,
        &serde_json::json!({"mode":"exact","schema_version":1,"execution_proof_ref":qualification,"ceiling":{"kind":"input_blocked","proof_ref":qualification},"boundary_settlement_ref":qualification}),
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
        &serde_json::json!({"version":1,"native_model":"rational_alarm_clock","complete_ports":descriptor.ports,"faults":[],"debug":[],"controllers":[]}),
    )?;
    binding.capabilities_ref = put_json(contents, &capabilities)?;
    binding.profile_ref = put_json(
        contents,
        &serde_json::json!({"schema_version":1,"descriptor":descriptor,"implementation":binding.implementation,"operating_contract":binding.operating_contract,"capabilities":capabilities,"guarantees":guarantees}),
    )?;
    Ok((descriptor, binding, owner, true))
}

pub(super) fn payload_schema(
    contents: &mut BTreeMap<String, ScenarioContent>,
) -> Result<SchemaRef, NodeObservedError> {
    Ok(SchemaRef {
        id: Id::new("crucible/rate-alarm-message-v1")?,
        version: 1,
        definition: put(
            contents,
            RATE_ALARM_MESSAGE_SPECIFICATION.as_bytes().to_vec(),
            "text/plain",
        )?,
        extensions: Extensions::new(),
    })
}

pub(super) fn ordering(
    contents: &mut BTreeMap<String, ScenarioContent>,
) -> Result<ContentRef, NodeObservedError> {
    put(contents, b"rational clock original input/reaction FIFO v1: Delivery maps to same-microstep Reaction; all equal-Reaction requests precede local responses, original input order remains stable; equal-time alarms retain arm sequence; due alarm cancellation refuses; original delivery parents determine later Publication without time substitution".to_vec(), "text/plain")
}

/// Adds only the independently selected original producer-history policy.
pub(super) fn install_producer_scope(
    descriptor: &mut NodeDescriptor,
    binding: &mut BindingCompatibility,
    contents: &mut BTreeMap<String, ScenarioContent>,
) -> Result<(), NodeObservedError> {
    let schema = crucible::node_adapters::host_rate_alarm_producer_schema()
        .map_err(|error| refused(&error.reason))?;
    if put(
        contents,
        crucible::node_adapters::RATE_ALARM_PRODUCER_SPECIFICATION
            .as_bytes()
            .to_vec(),
        "text/plain",
    )? != schema.definition
    {
        return Err(refused("original producer schema body differs"));
    }
    let mut model = contents
        .get(&descriptor.model_ref.hash.digest)
        .ok_or_else(|| refused("original selected model body absent"))?
        .bytes
        .clone();
    model.extend_from_slice(b"\nSelected original producer receipt history v2: exact stopped root/native/causes retained before observation; finite64 associations/128KiB roles; opaque current activation and full installed source authentication; native8 with Runtime1 only.");
    descriptor.model_ref = put(contents, model, "text/plain")?;
    let mut configuration: serde_json::Value = serde_json::from_slice(
        &contents
            .get(&descriptor.configuration_ref.hash.digest)
            .ok_or_else(|| refused("original selected configuration absent"))?
            .bytes,
    )?;
    configuration["producer_evidence"] = serde_json::json!("host/rate-alarm-producer-native-v2");
    descriptor.configuration_ref = put_json(contents, &configuration)?;
    binding.descriptor_hash = descriptor.identity()?;
    binding.configuration_ref = descriptor.configuration_ref.clone();
    binding.implementation.model_definitions = vec![descriptor.model_ref.clone()];
    binding.implementation.formats.push(schema);
    binding
        .implementation
        .formats
        .sort_by(|left, right| left.id.cmp(&right.id));
    for facet in &mut binding.operating_contract.facets {
        facet.configuration_ref = descriptor.configuration_ref.clone();
    }
    let mut capabilities: CapabilityProfile = serde_json::from_slice(
        &contents
            .get(&binding.capabilities_ref.hash.digest)
            .ok_or_else(|| refused("original selected capability body absent"))?
            .bytes,
    )?;
    capabilities.facets = binding.operating_contract.facets.clone();
    binding.capabilities_ref = put_json(contents, &capabilities)?;
    let guarantees: GuaranteeProfile = serde_json::from_slice(
        &contents
            .get(&binding.guarantees_ref.hash.digest)
            .ok_or_else(|| refused("original selected guarantee body absent"))?
            .bytes,
    )?;
    binding.profile_ref = put_json(
        contents,
        &serde_json::json!({
            "schema_version":1,"descriptor":descriptor,"implementation":binding.implementation,
            "operating_contract":binding.operating_contract,"capabilities":capabilities,"guarantees":guarantees
        }),
    )?;
    Ok(())
}
