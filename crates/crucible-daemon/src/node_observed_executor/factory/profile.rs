//! Regenerates installed native profiles and complete directed-owner inventories.

#[cfg(test)]
mod direct_recording_pair;

mod io;
mod linked;
mod recorded_ingress;
mod scripted;
mod seeded;
mod semantic_connections;
mod semantics;
mod storage_connections;
mod terminal;

use super::{InstalledNodeKind, InstalledNodeSelection, NodeObservedError, native, refused};
use crate::node_scenario::{NodeScenario, ScenarioContent};
use crucible::{
    node_adapters::host_clock_initial_bytes,
    node_admission::{
        CoordinatorPolicy, ObjectState, OwnerCapturePolicy, OwnershipPolicy, ScenarioRequirements,
        StateDomain, StateObject,
    },
};
use crucible_node_contract::{
    ArtifactIdentity, BindingCompatibility, CapabilityProfile, CaptureScope, ContentRef,
    Continuation, Extensions, FacetSelection, GuaranteeProfile, Id, ImplementationIdentity,
    LiveAuthority, NodeBindingRef, NodeDescriptor, OperatingContract, OperatingMode, OwnerBinding,
    OwnerRef, Repeatability, SchedulingRole, U64, WorldBinding, canonical,
};
use crucible_node_provider::reference_service::ReferenceProfile;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

pub(super) struct ResolvedWorld {
    pub(super) scenario: NodeScenario,
}

pub(super) fn build_world(
    selections: &[InstalledNodeSelection],
    host: &ContentRef,
    device: &ContentRef,
    artifacts: &BTreeMap<String, super::InstalledIoArtifact>,
) -> Result<ResolvedWorld, NodeObservedError> {
    let selected: Vec<_> = selections
        .iter()
        .filter_map(|selected| match &selected.kind {
            InstalledNodeKind::HostRecordedBlock { profile } => Some((selected, profile)),
            _ => None,
        })
        .collect();
    if selected.is_empty() {
        return build_world_once(selections, host, device, artifacts, None);
    }
    if selections.len() != 1 || selected.len() != 1 {
        return Err(refused(
            "recorded ingress currently requires one complete installed Block owner",
        ));
    }
    let original = build_world_once(selections, host, device, artifacts, None)?;
    let projection =
        super::recorded_ingress::projection(&original.scenario, &selected[0].1.configuration)?;
    build_world_once(selections, host, device, artifacts, Some(&projection))
}

fn build_world_once(
    selections: &[InstalledNodeSelection],
    host: &ContentRef,
    device: &ContentRef,
    artifacts: &BTreeMap<String, super::InstalledIoArtifact>,
    projection: Option<&crucible::node_scheduling::InputPayload>,
) -> Result<ResolvedWorld, NodeObservedError> {
    if selections.is_empty()
        || selections.len() > 64
        || selections
            .windows(2)
            .any(|pair| pair[0].node >= pair[1].node)
        || selections
            .iter()
            .map(|selection| &selection.owner)
            .collect::<BTreeSet<_>>()
            .len()
            != selections.len()
    {
        return Err(refused(
            "installed selection requires 1–64 sorted nodes with distinct owners",
        ));
    }
    let mut contents = BTreeMap::new();
    let terminal = terminal::selected(selections, artifacts)?;
    let qualification = put(
        &mut contents,
        if selections
            .iter()
            .any(|selection| matches!(selection.kind, InstalledNodeKind::HostRecordedBlock { .. }))
        {
            b"crucible installed recorded Block ingress v1: independently measured host implementation and enrolled immutable base/source record; complete original logical FIFO, source IDs/ordinals, exact Publication0 conversion and actual native semantic consumption; all-owner durable activation; no physical capture, live append, host-time conversion, cursor capture/restore, faults, debug or fork".to_vec()
        } else if selections
            .iter()
            .any(|selection| matches!(selection.kind, InstalledNodeKind::HostSeededLink { .. }))
        {
            b"crucible installed seeded storage transport v1: independently measured program and host implementation; complete original NetLink RNG/fault/queue state, native endpoint envelopes and coordinator FIFO/input/ACK custody; finite immutable storage scripts, static jitter/reorder only, no guest CPU, external inputs or dynamic fault control".to_vec()
        } else if terminal {
            b"crucible installed closed terminal profile v2: one independently enrolled host assertion program plus integer clock peers; actual evaluator/event prefix/emitted-result registry/finalization context/report and ACK custody; original full native envelopes and coordinator/runtime terminal codecs; immutable program and measured host code; no nonempty input provenance, external ingress, mutable faults/controllers/debug state, guest CPU or RAM, or fork".to_vec()
        } else {
            b"crucible installed clock/checksum profiles v1: exact regenerated semantics; private measured native custody; installed clock complete runtime envelopes support authenticated durable restart; no guest CPU, external ingress, native RAM capture or fork; connected transfer custody and reference native state have no installed durable archive".to_vec()
        },
        "text/plain",
    )?;
    let mut descriptors = Vec::new();
    let mut compatibility = Vec::new();
    let mut owners = Vec::new();
    let mut domains = Vec::new();
    let mut objects = Vec::new();
    let mut captures = Vec::new();
    let mut accepted_quantized = Vec::new();
    let mut accepted_nondeterministic = Vec::new();
    let mut accepted_limited = Vec::new();
    for selection in selections {
        let (descriptor, mut binding, mut owner, complete) = match &selection.kind {
            InstalledNodeKind::ReferenceDevice {
                quantum_ps,
                host_budget_ns,
            }
            | InstalledNodeKind::ReferenceNativeLinked {
                quantum_ps,
                host_budget_ns,
                ..
            } => {
                if host_budget_ns.get() > 60_000_000_000 {
                    return Err(refused("checksum host budget exceeds installed maximum"));
                }
                let profile = match &selection.kind {
                    InstalledNodeKind::ReferenceNativeLinked { closed_ingress, .. } => {
                        ReferenceProfile::build_native_linked(
                            selection.node.clone(),
                            selection.owner.clone(),
                            host.clone(),
                            device.clone(),
                            *quantum_ps,
                            *host_budget_ns,
                            *closed_ingress,
                        )
                    }
                    _ => ReferenceProfile::build_closed(
                        selection.node.clone(),
                        selection.owner.clone(),
                        host.clone(),
                        device.clone(),
                        *quantum_ps,
                        *host_budget_ns,
                    ),
                }
                .map_err(native)?;
                for object in profile.content_objects() {
                    contents.insert(
                        object.reference.hash.digest.clone(),
                        ScenarioContent {
                            reference: object.reference.clone(),
                            bytes: object.bytes.clone(),
                        },
                    );
                }
                let authority = placeholder_authority(&qualification)?;
                let (binding, owner) = profile.bind(authority).map_err(native)?;
                accepted_quantized.push(selection.node.clone());
                accepted_nondeterministic.push(selection.node.clone());
                accepted_limited.push(selection.node.clone());
                (profile.descriptor, binding.compatibility, owner, false)
            }
            InstalledNodeKind::HostNetLink { .. } => {
                accepted_limited.push(selection.node.clone());
                linked::link_profile(
                    selection,
                    selections,
                    host,
                    device,
                    &qualification,
                    &mut contents,
                )?
            }
            InstalledNodeKind::HostSeededLink { profile } => {
                accepted_limited.push(selection.node.clone());
                seeded::profile(
                    selection,
                    selections,
                    profile,
                    artifacts,
                    host,
                    &qualification,
                    &mut contents,
                )?
            }
            InstalledNodeKind::HostRecordedBlock { profile } => {
                accepted_limited.push(selection.node.clone());
                recorded_ingress::profile(
                    selection,
                    profile,
                    artifacts,
                    host,
                    &qualification,
                    projection,
                    &mut contents,
                )?
            }
            InstalledNodeKind::HostIo { profile } => {
                accepted_limited.push(selection.node.clone());
                io::io_profile(
                    selection,
                    profile,
                    artifacts,
                    host,
                    &qualification,
                    &mut contents,
                )?
            }
            InstalledNodeKind::HostScripted { profile } => {
                accepted_limited.push(selection.node.clone());
                scripted::scripted_profile(
                    selection,
                    profile,
                    artifacts,
                    host,
                    &qualification,
                    &mut contents,
                )?
            }
            InstalledNodeKind::Gem5ArmRoot
            | InstalledNodeKind::Gem5Closed { .. }
            | InstalledNodeKind::Gem5ClosedPreserving { .. }
            | InstalledNodeKind::Gem5ClosedEpochPreserving { .. } => {
                return Err(refused(
                    "closed gem5 requires its distinct public profile compiler",
                ));
            }
            InstalledNodeKind::HostClock => {
                clock_profile(selection, host, &qualification, &mut contents)?
            }
            InstalledNodeKind::HostSemantics { profile } => semantics::semantic_profile(
                selection,
                selections,
                profile,
                artifacts,
                host,
                &qualification,
                &mut contents,
            )?,
        };
        if terminal {
            terminal::install_inventory(&descriptor, &mut binding, &mut contents)?;
        }
        binding.qualification_refs = vec![qualification.clone()];
        owner.node_bindings = vec![NodeBindingRef {
            node_id: selection.node.clone(),
            binding_hash: binding.identity()?,
            extensions: Extensions::new(),
        }];
        let domain = owner
            .owner
            .state_domain_ids
            .first()
            .cloned()
            .ok_or_else(|| refused("installed profile omitted owned state domain"))?;
        domains.push(StateDomain {
            id: domain.clone(),
            capture_owner_id: selection.owner.clone(),
            execution_owner_ids: vec![selection.owner.clone()],
            future_affecting: true,
        });
        objects.push(StateObject {
            id: selection.node.clone(),
            node_ids: vec![selection.node.clone()],
            future_affecting: true,
            // Ownership remains complete even when serialization is unsupported.
            // The separate capture policy below advertises that limitation.
            state: ObjectState::Mutable { domain_id: domain },
        });
        captures.push(OwnerCapturePolicy {
            owner_id: selection.owner.clone(),
            complete_model: complete,
            unchanged_cut: complete,
            exact_continuation: complete,
            durable_restart: matches!(
                selection.kind,
                InstalledNodeKind::HostClock
                    | InstalledNodeKind::HostIo { .. }
                    | InstalledNodeKind::HostScripted { .. }
                    | InstalledNodeKind::HostSeededLink { .. }
                    | InstalledNodeKind::HostSemantics { .. }
            ),
            isolated_fork: false,
            dependencies: Vec::new(),
            cut_procedure_ref: qualification.clone(),
        });
        descriptors.push(descriptor);
        compatibility.push(binding);
        owners.push(owner);
    }
    let mut connections = linked::connections(
        selections,
        &mut compatibility,
        &mut owners,
        (&mut domains, &mut objects, &mut captures),
        &qualification,
        &mut contents,
    )?;
    connections.extend(storage_connections::connections(
        selections,
        &descriptors,
        &mut compatibility,
        &mut owners,
        (&mut domains, &mut objects, &mut captures),
        &mut contents,
        &qualification,
    )?);
    connections.extend(semantic_connections::connections(
        selections,
        &descriptors,
        &mut compatibility,
        &mut owners,
        (&mut domains, &mut objects, &mut captures),
        &mut contents,
        &qualification,
    )?);
    #[cfg(test)]
    connections.extend(direct_recording_pair::connections(
        selections,
        &compatibility,
        &mut objects,
        &mut contents,
    )?);
    connections.sort_by(|left, right| left.id.cmp(&right.id));
    // Semantic routes append transfer custody after the storage helper. The
    // complete inventory must be canonical before deriving its world identity.
    objects.sort_by(|left, right| left.id.cmp(&right.id));
    owners.sort_by(|left, right| left.owner.id.cmp(&right.owner.id));
    domains.sort_by(|left, right| left.id.cmp(&right.id));
    captures.sort_by(|left, right| left.owner_id.cmp(&right.owner_id));
    let ownership = OwnershipPolicy {
        schema_version: 1,
        domains,
        objects,
        internal_dependencies: Vec::new(),
        capture_owners: captures,
        inventory_proof_ref: qualification.clone(),
    };
    let ownership_ref = put_json(&mut contents, &ownership)?;
    let external_inputs = selections
        .iter()
        .filter_map(|selection| match selection.kind {
            InstalledNodeKind::HostRecordedBlock { .. } => {
                Some(super::recorded_ingress::endpoint(&selection.node))
            }
            _ => None,
        })
        .collect::<Result<Vec<_>, _>>()?;
    let coordinator = CoordinatorPolicy {
        schema_version: 1,
        state_closure_ref: qualification.clone(),
        maximum_microsteps_per_instant: U64::new(1024),
        same_time_closure: Vec::new(),
        operational_policy_ref: qualification.clone(),
        external_inputs: external_inputs.clone(),
    };
    let coordinator_ref = put_json(&mut contents, &coordinator)?;
    let scenario_ref = put_json(
        &mut contents,
        &serde_json::json!({"format":"crucible.installed-node-selection",
        "version":1,"nodes":selections,"connections":connections,"external_inputs":external_inputs,"faults":[]}),
    )?;
    let initialization_ref = put_json(
        &mut contents,
        &descriptors
            .iter()
            .map(|descriptor| (&descriptor.id, &descriptor.initialization_ref))
            .collect::<Vec<_>>(),
    )?;
    let world = WorldBinding {
        schema_version: 1,
        scenario_ref,
        node_bindings: compatibility
            .iter()
            .map(|binding| {
                Ok(NodeBindingRef {
                    node_id: binding.node_id.clone(),
                    binding_hash: binding.identity()?,
                    extensions: Extensions::new(),
                })
            })
            .collect::<Result<Vec<_>, crucible_node_contract::ContractError>>()?,
        connections: connections.clone(),
        ownership_ref,
        coordinator_contract_ref: coordinator_ref,
        ordering_profile: "superdense-v1".into(),
        initialization_ref,
        extensions: Extensions::new(),
    };
    let requirements = ScenarioRequirements {
        accepted_quantized_nodes: accepted_quantized,
        accepted_nondeterministic_nodes: accepted_nondeterministic,
        accepted_limited_state_nodes: accepted_limited,
        accepted_visibility_conversions: connections
            .iter()
            .map(|connection| connection.id.clone())
            .collect(),
        ..ScenarioRequirements::default()
    };
    let mut content = contents.into_values().collect::<Vec<_>>();
    content.sort_by(|left, right| {
        (&left.reference.hash.domain, &left.reference.hash.digest)
            .cmp(&(&right.reference.hash.domain, &right.reference.hash.digest))
    });
    Ok(ResolvedWorld {
        scenario: NodeScenario {
            format: "crucible.node-scenario".into(),
            version: 1,
            world,
            descriptors,
            compatibility,
            owners,
            requirements,
            content,
        },
    })
}

pub(super) fn clock_profile(
    selection: &InstalledNodeSelection,
    host: &ContentRef,
    qualification: &ContentRef,
    contents: &mut BTreeMap<String, ScenarioContent>,
) -> Result<(NodeDescriptor, BindingCompatibility, OwnerBinding, bool), NodeObservedError> {
    let model=put(contents,b"crucible host clock v1: owned monotone integer picosecond cursor; no ports, timers, callbacks or autonomous execution; complete state is one u64".to_vec(),"text/plain")?;
    let configuration = put_json(
        contents,
        &serde_json::json!({"schema_version":1,"resolution_ps":"1","phase_ps":"0","initial_time_ps":"0"}),
    )?;
    let initial = put(
        contents,
        host_clock_initial_bytes(0),
        "application/octet-stream",
    )?;
    let descriptor = NodeDescriptor {
        schema_version: 1,
        id: selection.node.clone(),
        roles: vec![Id::new("clock")?],
        model_ref: model.clone(),
        configuration_ref: configuration.clone(),
        initialization_ref: initial,
        ports: Vec::new(),
        extensions: Extensions::new(),
    };
    let guarantees = GuaranteeProfile {
        schema_version: 1,
        repeatability: Repeatability::Qualified,
        capture_scope: CaptureScope::CompleteModel,
        continuation: Continuation::Exact,
        durable_restart: true,
        isolated_fork: false,
        conditional_replay: false,
        limitations_ref: qualification.clone(),
        extensions: Extensions::new(),
    };
    let guarantees_ref = put_json(contents, &guarantees)?;
    let mut facets = Vec::new();
    for name in [
        "host/exact-v1",
        "host/physical-pause-v1",
        "host/preservation-v1",
    ] {
        facets.push(FacetSelection {
            id: Id::new(name)?,
            version: 1,
            configuration_ref: configuration.clone(),
            guarantees_ref: guarantees_ref.clone(),
            extensions: Extensions::new(),
        });
    }
    let devices = put_json(
        contents,
        &serde_json::json!({"schema_version":1,"devices":[],"timers":[],"ports":[],"state":"one exact owned integer clock"}),
    )?;
    let capability = CapabilityProfile {
        schema_version: 1,
        facets: facets.clone(),
        devices_ref: devices,
        requirements_ref: qualification.clone(),
        extensions: Extensions::new(),
    };
    let capabilities_ref = put_json(contents, &capability)?;
    let policy = put_json(
        contents,
        &serde_json::json!({"mode":"exact","schema_version":1,
        "execution_proof_ref":qualification,"ceiling":{"kind":"strict_predecessor"},
        "boundary_settlement_ref":qualification}),
    )?;
    let operating = OperatingContract {
        schema_version: 1,
        mode: OperatingMode::Exact,
        scheduling_role: SchedulingRole::Active,
        ordering_profile: "superdense-v1".into(),
        policy_ref: policy,
        resolution_ps: Some(U64::new(1)),
        phase_ps: Some(U64::new(0)),
        facets,
        extensions: Extensions::new(),
    };
    let continuation_schema = crucible_node_contract::SchemaRef {
        id: Id::new("host/native-continuation-v1")?,
        version: 1,
        definition: put(contents, b"crucible installed host native continuation envelope v1: bounded complete host model cursor and codec; original native request/outcome/input/evidence receipt registries; causal cut, publication FIFO sequence and pending progress; authentic whole-world runtime/scheduler closure retained separately; no raw imported JSON grants authority".to_vec(),"text/plain")?,
        extensions: Extensions::new(),
    };
    let implementation = ImplementationIdentity {
        schema_version: 1,
        implementation_id: Id::new("crucible-host-clock")?,
        artifacts: vec![ArtifactIdentity {
            id: Id::new("host")?,
            role: Id::new("host-executable")?,
            content: host.clone(),
            extensions: Extensions::new(),
        }],
        model_definitions: vec![model],
        formats: vec![continuation_schema],
        extensions: Extensions::new(),
    };
    let owner = OwnerRef {
        id: selection.owner.clone(),
        participant_ids: vec![selection.node.clone()],
        state_domain_ids: vec![Id::new(format!("{}/state", selection.owner))?],
    };
    let profile_ref = put_json(
        contents,
        &serde_json::json!({"schema_version":1,"descriptor":descriptor,
        "implementation":implementation,"operating_contract":operating,"capabilities":capability,"guarantees":guarantees}),
    )?;
    let ownership_ref = put_json(contents, &owner)?;
    let binding = BindingCompatibility {
        schema_version: 1,
        node_id: selection.node.clone(),
        descriptor_hash: descriptor.identity()?,
        implementation,
        profile_ref,
        configuration_ref: configuration,
        operating_contract: operating,
        execution_owner: owner.clone(),
        capture_owner: owner.clone(),
        capabilities_ref,
        guarantees_ref,
        qualification_refs: vec![qualification.clone()],
        extensions: Extensions::new(),
    };
    let owner = OwnerBinding {
        schema_version: 1,
        owner,
        owner_roles: vec![Id::new("capture")?, Id::new("execution")?],
        node_bindings: Vec::new(),
        ownership_ref,
        extensions: Extensions::new(),
    };
    Ok((descriptor, binding, owner, true))
}

fn placeholder_authority(receipt: &ContentRef) -> Result<LiveAuthority, NodeObservedError> {
    let id = Id::new("uncommitted")?;
    Ok(LiveAuthority {
        schema_version: 1,
        session_id: id.clone(),
        incarnation_id: id.clone(),
        realization_id: id.clone(),
        activation_id: None,
        world_generation: U64::new(0),
        owner_generation: U64::new(1),
        input_epoch: id,
        host_receipt: receipt.clone(),
        extensions: Extensions::new(),
    })
}

pub(super) fn put_json(
    contents: &mut BTreeMap<String, ScenarioContent>,
    value: &impl Serialize,
) -> Result<ContentRef, NodeObservedError> {
    put(
        contents,
        canonical::canonical_json(&serde_json::to_value(value)?)?,
        "application/json",
    )
}

pub(super) fn put(
    contents: &mut BTreeMap<String, ScenarioContent>,
    bytes: Vec<u8>,
    media_type: &str,
) -> Result<ContentRef, NodeObservedError> {
    let reference = canonical::content_ref(&bytes, media_type)?;
    contents.insert(
        reference.hash.digest.clone(),
        ScenarioContent {
            reference: reference.clone(),
            bytes,
        },
    );
    Ok(reference)
}

pub(super) fn authenticate_recorded(
    scenario: &NodeScenario,
    configuration: &crate::node_scenario::NodeRunConfiguration,
    request: &crucible_campaign::observed_node_attempt::ObservedAttemptRequest,
) -> Result<(), NodeObservedError> {
    use crucible_campaign::{
        CampaignHash,
        executor_node_capabilities::{
            ExecutorNodeCapabilities, ExecutorNodeRoster, ExecutorOwnerRole,
            NodeExecutionGuarantee, NodeMaterializationStrategy, OwnerImplementationBinding,
        },
    };

    let scenario_artifact = scenario.artifact()?;
    let configuration_artifact = configuration.artifact(scenario)?;
    let mut owners = BTreeMap::new();
    for owner in &scenario.owners {
        let node = owner
            .owner
            .participant_ids
            .first()
            .ok_or_else(|| refused("recorded installed owner has no participant"))?;
        let binding = scenario
            .compatibility
            .iter()
            .find(|binding| &binding.node_id == node)
            .ok_or_else(|| refused("recorded installed owner has no complete node binding"))?;
        let guarantees: GuaranteeProfile = serde_json::from_slice(
            &scenario
                .content_bytes(&binding.guarantees_ref, 4 * 1024 * 1024)
                .map_err(|error| refused(&error.message))?,
        )?;
        let guarantee = match guarantees.repeatability {
            Repeatability::Qualified => NodeExecutionGuarantee::Repeatable,
            Repeatability::Nondeterministic => NodeExecutionGuarantee::Nondeterministic,
            Repeatability::Unqualified => NodeExecutionGuarantee::Unqualified,
        };
        let roles = BTreeSet::from([ExecutorOwnerRole::Capture, ExecutorOwnerRole::Execution]);
        owners.insert(
            owner.owner.id.as_str().to_owned(),
            OwnerImplementationBinding::new_with_roles(
                binding.implementation.implementation_id.as_str().to_owned(),
                CampaignHash::parse(&owner.identity()?.digest)?,
                owner
                    .owner
                    .participant_ids
                    .iter()
                    .map(|node| node.as_str().to_owned())
                    .collect(),
                guarantee,
                roles,
            )?,
        );
    }
    let roster = ExecutorNodeRoster::new(
        scenario_artifact.id()?,
        configuration_artifact.id()?,
        CampaignHash::parse(&scenario.world.identity()?.digest)?,
        owners,
    )?;
    let capabilities = ExecutorNodeCapabilities::new(
        roster,
        BTreeSet::from([NodeMaterializationStrategy::FreshExecution]),
    )?;
    let context = super::super::backend::input_context_bytes(scenario, configuration)?;
    let inputs = crucible_cas::content_store::ContentId::for_bytes(
        crucible_cas::content_store::ObjectKind::Trace,
        1,
        &context,
    );
    if request.capabilities() != &capabilities || request.inputs() != inputs {
        return Err(refused(
            "retained observation differs from exact authored installed world and input closure",
        ));
    }
    // This authenticates only the original immutable observation namespace. It
    // cannot recover a native permit, mint new live authority, or change bytes.
    Ok(())
}
