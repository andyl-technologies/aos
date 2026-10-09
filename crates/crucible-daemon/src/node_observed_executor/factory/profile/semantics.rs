//! Distinct installed assertion-node profiles with original native input routes.

use super::*;
use crate::node_observed_executor::factory::semantics::{
    InstalledHostSemanticProfile, MAXIMUM_SEMANTIC_EVENTS, MAXIMUM_SEMANTIC_STATE_BYTES,
    build_model, read_program,
};
use crucible::node_admission::{FlowControl, LanePolicy, LaneVisibility, PortPolicy};
use crucible_node_contract::{Direction, LaneDescriptor, PortDescriptor, SchemaRef};

pub(super) fn semantic_profile(
    selected: &InstalledNodeSelection,
    selections: &[InstalledNodeSelection],
    profile: &InstalledHostSemanticProfile,
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
    descriptor.roles = vec![Id::new("host_assertions")?];
    descriptor.model_ref = put(
        contents,
        if definition.version == 2 {
            b"crucible host assertion model v2: original host evaluator and checked event-log prefix; complete Eventually/once/lifecycle/outcome state; explicit whole-world terminal barrier finalizes once, preserving original report, emitted-result registry and ACK history without reevaluation; no guest markers, console, coverage, RAM, opaque oracle or clock faults".to_vec()
        } else {
            b"crucible host assertion model v1: unchanged compact property program; actual host assertion evaluator and checked original event-log prefix; terminal block completion projection exposes only IoAny; complete original Eventually obligations, once latches, assertion lifecycle and terminal state; exact input lineage/full superdense reaction and original outcome queue; no guest markers, console, coverage, RAM, opaque named oracle, clock faults or terminal-quiescence projection".to_vec()
        },
        "text/plain",
    )?;
    descriptor.configuration_ref = put_json(
        contents,
        &serde_json::json!({
            "schema_version": 1,
            "native_profile": profile,
            "definition": definition,
            "maximum_events": MAXIMUM_SEMANTIC_EVENTS.to_string(),
            "maximum_state_bytes": MAXIMUM_SEMANTIC_STATE_BYTES.to_string(),
            "deadline_expiry": "after_complete_physical_deadline_instant"
        }),
    )?;
    descriptor.initialization_ref = put(
        contents,
        model.capture().map_err(|error| refused(&error.reason))?,
        "application/octet-stream",
    )?;
    let response = super::io::wire_schema("block", "response", contents)?;
    let outcome = SchemaRef {
        id: Id::new("crucible/host-assertion-outcome-v1")?,
        version: 1,
        definition: put(
            contents,
            b"crucible.host-assertion-outcome v1: closed canonical JSON; assertion, quantifier, outcome_time_ps, full evaluation Position, kind, lifecycle, exact declared message and engine reason; original publication parents retain authentic consumed delivery; deadline outcome time does not replace actual evaluation/emission position".to_vec(),
            "text/plain",
        )?,
        extensions: Extensions::new(),
    };
    let continuation = SchemaRef {
        id: Id::new(if definition.version == 2 {
            "crucible/host-semantic-continuation-v2"
        } else {
            "crucible/host-semantic-continuation-v1"
        })?,
        version: definition.version,
        definition: put(
            contents,
            if definition.version == 2 {
                concat!(
                    "crucible.host-semantic-continuation v2: closed canonical JSON; ",
                    "immutable definition digest, full saved position, exact grouped original ",
                    "event-log prefix and input Delivery lineage, unchanged host assertion ",
                    "checkpoint v2 bytes, original pending outcome bytes/evaluation/parents; ",
                    "original terminal barrier/context, finalized marker, report and emitted ",
                    "result registry survive without prefix reevaluation; complete native ",
                    "operation/report ACK and scheduler/runtime custody are independently ",
                    "authenticated by the selected signed terminal archive codec"
                )
                .as_bytes()
                .to_vec()
            } else {
                b"crucible.host-semantic-continuation v1: closed canonical JSON; immutable definition digest, full saved position, exact grouped original event-log prefix and input Delivery lineage, unchanged host assertion checkpoint v2 bytes, original pending outcome bytes/evaluation/parents; bounded decode reconstructs log storage and installs original checkpoint without prefix reevaluation; native signed capture and whole scheduler/runtime custody are independently authenticated".to_vec()
            },
            "text/plain",
        )?,
        extensions: Extensions::new(),
    };
    let ordering = super::io::ordering(contents)?;
    let domain = Id::new(format!("{}/state", selected.owner))?;
    let definitions = [
        (
            "data",
            "input",
            "crucible/block-v1",
            Direction::Input,
            response.clone(),
            crucible_shmem::MAX_FRAME_DATA as u64,
            64,
        ),
        (
            "assertions",
            "output",
            "crucible/host-assertion-outcome-v1",
            Direction::Output,
            outcome.clone(),
            MAXIMUM_SEMANTIC_STATE_BYTES as u64,
            1,
        ),
    ];
    let mut ports = Vec::new();
    for (port, lane, interface, direction, schema, maximum, producers) in definitions {
        if definition.version == 2 && direction == Direction::Input && definition.inputs.is_empty()
        {
            continue;
        }
        let policy = PortPolicy {
            schema_version: 1,
            lanes: vec![LanePolicy {
                lane_id: Id::new(lane)?,
                ordering_ref: ordering.clone(),
                correlation_ref: ordering.clone(),
                flow_control: FlowControl::Credit,
                maximum_pending_bytes: (maximum * 16).into(),
                visibility: LaneVisibility::Exact,
                effect_phases: vec![1],
                minimum_lookahead_ps: 0.into(),
            }],
            maximum_producers: producers.into(),
            maximum_consumers: 64.into(),
            arbitration_ref: ordering.clone(),
            execution_owner_id: selected.owner.clone(),
            state_domain_ids: vec![domain.clone()],
            internal: false,
        };
        ports.push(PortDescriptor {
            id: Id::new(port)?,
            interface_id: Id::new(interface)?,
            features: Vec::new(),
            configuration_ref: put_json(contents, &policy)?,
            lanes: vec![LaneDescriptor {
                id: Id::new(lane)?,
                direction,
                payload_schema: schema,
                maximum_payload_bytes: maximum.into(),
                maximum_pending_events: 16.into(),
                extensions: Extensions::new(),
            }],
            extensions: Extensions::new(),
        });
    }
    // Every edition hashes the canonical port roster. Sorting the generated
    // v1 roster does not repair or retag an imported compatibility tuple.
    ports.sort_by(|left, right| left.id.cmp(&right.id));
    descriptor.ports = ports;
    if definition.version == 2 {
        let mut terminal = binding
            .operating_contract
            .facets
            .first()
            .cloned()
            .ok_or_else(|| refused("semantic preservation facet absent"))?;
        terminal.id = Id::new("host/terminal-assertions-v1")?;
        terminal.version = 1;
        terminal.extensions = Extensions::new();
        binding.operating_contract.facets.push(terminal);
        binding
            .operating_contract
            .facets
            .sort_by(|left, right| left.id.cmp(&right.id));
    }
    for schema in &mut binding.implementation.formats {
        if definition.version == 2 && schema.id.as_str() == "host/native-continuation-v1" {
            schema.id = Id::new("host/native-semantic-continuation-v2")?;
            schema.version = 2;
            schema.definition = put(contents,
                b"host semantic native envelope v2: complete original evaluator model, operation outcomes/evidence/report/ACK ledgers, exact input provenance and full position; terminal runtime custody selects coordinator v2 and runtime v3 separately".to_vec(),
                "text/plain")?;
        }
    }
    binding.descriptor_hash = descriptor.identity()?;
    binding.configuration_ref = descriptor.configuration_ref.clone();
    binding.implementation.implementation_id = Id::new("crucible-host-assertions")?;
    binding.implementation.model_definitions = vec![descriptor.model_ref.clone()];
    binding
        .implementation
        .formats
        .extend([response, outcome, continuation]);
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
            "ceiling": {"kind":"input_blocked", "proof_ref":qualification},
            "boundary_settlement_ref": qualification
        }),
    )?;
    // Archive qualification is separate from execution. The richer continuation
    // cannot inherit the integer clock's installed durable-restart claim.
    let mut guarantees: GuaranteeProfile =
        serde_json::from_slice(&contents[&binding.guarantees_ref.hash.digest].bytes)?;
    guarantees.durable_restart = definition.version == 2 && definition.inputs.is_empty();
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
            "schema_version": 1,
            "native_model": "host_assertions",
            "complete_ports": descriptor.ports,
            "immutable_program_ref": profile.program,
            "observations": ["decoded_terminal_block_io_any"],
            "faults": [],
            "external_oracles": []
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
