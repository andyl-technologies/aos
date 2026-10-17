//! Regenerates the distinct installed parent-zero Root and public Clock world.
//!
//! The profile binds genuine typed Serial and every installed launch role. It
//! supplies immutable selection data; admission additionally authenticates actual
//! native or reserved-image custody. Mechanism flags never become common Ready.

use std::{collections::BTreeMap, fs::OpenOptions, io::Read, os::unix::fs::OpenOptionsExt};

use crucible::{
    node_adapters::arm_root::{
        ARM_ROOT_CONTINUATION_SPECIFICATION, ARM_ROOT_DIALECT, ARM_ROOT_EXACT_PROFILE,
        ARM_ROOT_IMPLEMENTATION, ARM_ROOT_MODEL, ARM_ROOT_PRESERVATION_PROFILE,
        ARM_ROOT_SERIAL_INTERFACE, ARM_ROOT_SERIAL_SCHEMA, ARM_ROOT_SERIAL_SPECIFICATION,
        ArmRootNodeResources, arm_root_continuation_schema,
    },
    node_admission::{
        CoordinatorPolicy, FlowControl, LanePolicy, LaneVisibility, ObjectState,
        OwnerCapturePolicy, OwnershipPolicy, PortPolicy, ScenarioRequirements, StateDomain,
        StateObject,
    },
};
use crucible_node_contract::{
    ArtifactIdentity, BindingCompatibility, CapabilityProfile, ContentRef, Direction, Extensions,
    FacetSelection, GuaranteeProfile, Id, LaneDescriptor, NodeBindingRef, NodeDescriptor,
    OwnerBinding, PortDescriptor, SchemaRef, WorldBinding,
};
use crucible_node_provider::gem5::{ArmRootLaunch, InstalledArmRootMechanism};

use super::super::{
    InstalledNodeKind, InstalledNodeSelection, NodeObservedError,
    native_state::profile::select_public_preparation,
    profile::{clock_profile, put, put_json},
    refused,
};
use crate::node_scenario::{NodeScenario, ScenarioContent};

pub(super) struct RootWorldProfile {
    pub(super) scenario: NodeScenario,
    pub(super) qualification: ContentRef,
    pub(super) installed: ContentRef,
    pub(super) bindings: BTreeMap<String, ContentRef>,
}

impl RootWorldProfile {
    pub(super) fn build(
        launch: &ArmRootLaunch,
        host: &ContentRef,
    ) -> Result<Self, NodeObservedError> {
        let mechanism = InstalledArmRootMechanism::load().map_err(error)?;
        if launch.owner().as_str() != "owner/root"
            || mechanism.document() != launch.installed_model()
            || launch.model_id() != ARM_ROOT_MODEL
            || launch.native_dialect() != ARM_ROOT_DIALECT
        {
            return Err(refused(
                "Root profile differs from independently measured installed source",
            ));
        }
        let selected = RootProfileSelection::installed()?;
        if launch.profile() != &selected.profile
            || !launch.bindings().eq(selected
                .bindings
                .iter()
                .map(|(role, reference)| (role.as_str(), reference)))
        {
            return Err(refused(
                "Root launch bindings differ from independently measured catalogue selection",
            ));
        }
        Self::build_selection(&selected, host)
    }

    pub(super) fn build_installed(host: &ContentRef) -> Result<Self, NodeObservedError> {
        Self::build_selection(&RootProfileSelection::installed()?, host)
    }

    fn build_selection(
        launch: &RootProfileSelection,
        host: &ContentRef,
    ) -> Result<Self, NodeObservedError> {
        let mut contents = BTreeMap::new();
        let document = original_manifest(launch.profile())?;
        if put(&mut contents, document, &launch.profile().media_type)? != *launch.profile() {
            return Err(refused("Root original installed manifest changed"));
        }
        let qualification = put_json(
            &mut contents,
            &serde_json::json!({
                "schema":"crucible.installed-root-clock-procedure.v1",
                "installed":launch.profile(),"model":ARM_ROOT_MODEL,"dialect":ARM_ROOT_DIALECT,
                "native":"actual privately supervised parent-zero Serial root; current complete task/FD/maps/images/files certificate",
                "preparation":"exact actual raw Ready/session and complete public owner/coordinator publication",
                "continuation":"original native model/config/image/control/Ready/adminACK and unchanged common operation custody; independently audited fresh Restored sessions",
                "clock":"owned integer HostClock with original common grant/commit/ACK history",
                "mechanical_poll_events":"262144",
                "time_mapping":{"native_tick_picoseconds":"1","native_initial_tick":"0","common_initial_picoseconds":"0","affine_offset_picoseconds":"0","logical_idle":"authorized exclusive park preserves actual raw native tick and next wake independently","bootstrap":"actual original common permission; no hidden native prefix"},
                "public_ancestry_codec":"crucible/gem5-arm-root-public-native-continuation-v2",
                "connections":[],"external_inputs":[],"faults":[],
                "timing_fidelity":false,"general_linux_devices":false,
            }),
        )?;
        let clock_selection = InstalledNodeSelection {
            node: Id::new("clock")?,
            owner: Id::new("owner/clock")?,
            kind: InstalledNodeKind::HostClock,
        };
        let root_selection = InstalledNodeSelection {
            node: Id::new("root")?,
            owner: launch.owner().clone(),
            kind: InstalledNodeKind::HostClock,
        };
        let (mut clock, mut clock_binding, clock_owner, _) =
            clock_profile(&clock_selection, host, &qualification, &mut contents)?;
        // Root ancestry keeps its closed scheduler-one policy; generic scheduling
        // epochs are independently qualified by the separate Clock/SE profile.
        select_public_preparation(&mut clock, &mut clock_binding, &mut contents, true, false)?;
        let (root, root_binding, root_owner) =
            root_node_profile(&root_selection, host, launch, &qualification, &mut contents)?;
        let descriptors = vec![clock, root];
        let compatibility = vec![clock_binding, root_binding];
        let mut owners = vec![clock_owner, root_owner];
        for (owner, binding) in owners.iter_mut().zip(&compatibility) {
            owner.node_bindings = vec![NodeBindingRef {
                node_id: binding.node_id.clone(),
                binding_hash: binding.identity()?,
                extensions: Extensions::new(),
            }];
        }
        let mut domains = Vec::new();
        let mut objects = Vec::new();
        let mut capture_owners = Vec::new();
        for (descriptor, owner) in descriptors.iter().zip(&owners) {
            let domain = owner
                .owner
                .state_domain_ids
                .first()
                .cloned()
                .ok_or_else(|| refused("Root world owner lacks a complete mutable domain"))?;
            domains.push(StateDomain {
                id: domain.clone(),
                capture_owner_id: owner.owner.id.clone(),
                execution_owner_ids: vec![owner.owner.id.clone()],
                future_affecting: true,
            });
            objects.push(StateObject {
                id: Id::new(format!("{}/complete-model", descriptor.id))?,
                node_ids: vec![descriptor.id.clone()],
                future_affecting: true,
                state: ObjectState::Mutable { domain_id: domain },
            });
            capture_owners.push(OwnerCapturePolicy {
                owner_id: owner.owner.id.clone(),
                complete_model: true,
                unchanged_cut: true,
                exact_continuation: true,
                durable_restart: true,
                isolated_fork: false,
                dependencies: Vec::new(),
                cut_procedure_ref: qualification.clone(),
            });
        }
        let ownership_ref = put_json(
            &mut contents,
            &OwnershipPolicy {
                schema_version: 1,
                domains,
                objects,
                internal_dependencies: Vec::new(),
                capture_owners,
                inventory_proof_ref: qualification.clone(),
            },
        )?;
        let coordinator_contract_ref = put_json(
            &mut contents,
            &CoordinatorPolicy {
                schema_version: 1,
                state_closure_ref: qualification.clone(),
                maximum_microsteps_per_instant: 1_000_000.into(),
                same_time_closure: Vec::new(),
                operational_policy_ref: qualification.clone(),
                external_inputs: Vec::new(),
            },
        )?;
        let scenario_ref = put_json(
            &mut contents,
            &serde_json::json!({
                "schema":"crucible.installed-root-clock-scenario.v1","installed":launch.profile(),
                "model":ARM_ROOT_MODEL,"dialect":ARM_ROOT_DIALECT,"nodes":["clock","root"],
                "connections":[],"external_inputs":[],"faults":[],
            }),
        )?;
        let initialization_ref = put_json(
            &mut contents,
            &descriptors
                .iter()
                .map(|node| (&node.id, &node.initialization_ref))
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
                .collect::<Result<_, crucible_node_contract::ContractError>>()?,
            connections: Vec::new(),
            ownership_ref,
            coordinator_contract_ref,
            ordering_profile: "superdense-v1".into(),
            initialization_ref,
            extensions: Extensions::new(),
        };
        let mut content = contents.into_values().collect::<Vec<_>>();
        content.sort_by(|a, b| {
            (&a.reference.hash.domain, &a.reference.hash.digest)
                .cmp(&(&b.reference.hash.domain, &b.reference.hash.digest))
        });
        let scenario = NodeScenario {
            format: "crucible.node-scenario".into(),
            version: 1,
            world,
            descriptors,
            compatibility,
            owners,
            requirements: ScenarioRequirements {
                deterministic: true,
                exact_capture: true,
                exact_continuation: true,
                durable_restart: true,
                ..ScenarioRequirements::default()
            },
            content,
        };
        scenario.canonical_bytes()?;
        Ok(Self {
            scenario,
            qualification,
            installed: launch.profile().clone(),
            bindings: launch
                .bindings()
                .map(|(role, content)| (role.to_owned(), content.clone()))
                .collect(),
        })
    }
}

/// Holds independently measured immutable selection bytes, not native authority.
struct RootProfileSelection {
    owner: Id,
    profile: ContentRef,
    bindings: BTreeMap<String, ContentRef>,
}

impl RootProfileSelection {
    fn installed() -> Result<Self, NodeObservedError> {
        let installed = InstalledArmRootMechanism::load().map_err(error)?;
        let mut bindings = BTreeMap::new();
        for role in [
            "native_executable",
            "controller",
            "entrypoint",
            "model",
            "board_model",
            "publication_model",
            "asset_checker",
            "auditor",
            "auditor_core",
            "python",
            "kernel",
            "initramfs",
            "firmware",
            "image_guard",
            "dmtcp_launch",
            "dmtcp_restart",
            "mtcp_restart",
        ] {
            bindings.insert(
                role.to_owned(),
                installed.artifact_binding(role).map_err(error)?.content,
            );
        }
        Ok(Self {
            owner: Id::new("owner/root")?,
            profile: installed.manifest_binding().map_err(error)?,
            bindings,
        })
    }

    fn owner(&self) -> &Id {
        &self.owner
    }

    fn profile(&self) -> &ContentRef {
        &self.profile
    }

    fn bindings(&self) -> impl Iterator<Item = (&str, &ContentRef)> {
        self.bindings
            .iter()
            .map(|(role, content)| (role.as_str(), content))
    }
}

fn root_node_profile(
    selected: &InstalledNodeSelection,
    host: &ContentRef,
    launch: &RootProfileSelection,
    qualification: &ContentRef,
    contents: &mut BTreeMap<String, ScenarioContent>,
) -> Result<(NodeDescriptor, BindingCompatibility, OwnerBinding), NodeObservedError> {
    let (mut descriptor, mut binding, owner, _) =
        clock_profile(selected, host, qualification, contents)?;
    descriptor.roles = vec![Id::new("compute")?];
    descriptor.model_ref = put_json(
        contents,
        &serde_json::json!({
            "schema":"crucible.installed-arm-root-model.v1","model":ARM_ROOT_MODEL,
            "dialect":ARM_ROOT_DIALECT,"installed":launch.profile(),"causal_parent":"0",
            "native_configuration":"source-owned VExpress Atomic root kernel/initramfs/firmware and board tree",
            "outputs":"actual typed PL011 Serial bytes; no guest PID/fd substitution",
            "inputs":[],"general_devices":false,"timing_fidelity":false,
        }),
    )?;
    let resources = ArmRootNodeResources::default();
    descriptor.configuration_ref = put_json(
        contents,
        &serde_json::json!({
            "schema":"crucible.installed-arm-root-configuration.v1","installed":launch.profile(),
            "model":ARM_ROOT_MODEL,"dialect":ARM_ROOT_DIALECT,"resolution_ps":"1","phase_ps":"0",
            "maximum_microsteps":"1000000",
            "native_poll":{"maximum_operations":resources.maximum_operations.to_string(),
                "maximum_prefixes":resources.maximum_prefixes.to_string(),"maximum_retained_bytes":resources.maximum_retained_bytes.to_string(),
                "maximum_events_per_poll":resources.maximum_events_per_poll},
        }),
    )?;
    descriptor.initialization_ref = put_json(
        contents,
        &serde_json::json!({
            "schema":"crucible.installed-arm-root-initialization.v1","installed":launch.profile(),
            "native_tick":"0","logical_position":{"time_ps":"0","microstep":"0","phase":"boundary_control"},
            "causal_parent":"0","prefixes":[],"inputs":[],"source":"actual original native constructor before any callback",
        }),
    )?;
    let specification = put(
        contents,
        ARM_ROOT_SERIAL_SPECIFICATION.as_bytes().to_vec(),
        "text/plain",
    )?;
    let policy = PortPolicy {
        schema_version: 1,
        lanes: vec![LanePolicy {
            lane_id: Id::new("output")?,
            ordering_ref: specification.clone(),
            correlation_ref: specification.clone(),
            flow_control: FlowControl::Credit,
            maximum_pending_bytes: 1.into(),
            visibility: LaneVisibility::Exact,
            effect_phases: vec![1],
            minimum_lookahead_ps: 0.into(),
        }],
        maximum_producers: 1.into(),
        maximum_consumers: 1.into(),
        arbitration_ref: specification.clone(),
        execution_owner_id: selected.owner.clone(),
        state_domain_ids: owner.owner.state_domain_ids.clone(),
        internal: false,
    };
    descriptor.ports = vec![PortDescriptor {
        id: Id::new("serial")?,
        interface_id: Id::new(ARM_ROOT_SERIAL_INTERFACE)?,
        features: Vec::new(),
        configuration_ref: put_json(contents, &policy)?,
        lanes: vec![LaneDescriptor {
            id: Id::new("output")?,
            direction: Direction::Output,
            payload_schema: SchemaRef {
                id: Id::new(ARM_ROOT_SERIAL_SCHEMA)?,
                version: 1,
                definition: specification,
                extensions: Extensions::new(),
            },
            maximum_payload_bytes: 1.into(),
            maximum_pending_events: 1.into(),
            extensions: Extensions::new(),
        }],
        extensions: Extensions::new(),
    }];
    binding.configuration_ref = descriptor.configuration_ref.clone();
    binding.descriptor_hash = descriptor.identity()?;
    binding.implementation.implementation_id = Id::new(ARM_ROOT_IMPLEMENTATION)?;
    binding.implementation.artifacts = launch
        .bindings()
        .map(|(role, content)| {
            Ok(ArtifactIdentity {
                id: Id::new(format!("arm-root/{role}"))?,
                role: Id::new(role)?,
                content: content.clone(),
                extensions: Extensions::new(),
            })
        })
        .collect::<Result<_, crucible_node_contract::ContractError>>()?;
    binding.implementation.artifacts.push(ArtifactIdentity {
        id: Id::new("arm-root/profile")?,
        role: Id::new("installed-profile")?,
        content: launch.profile().clone(),
        extensions: Extensions::new(),
    });
    binding
        .implementation
        .artifacts
        .sort_by(|a, b| a.id.cmp(&b.id));
    binding.implementation.model_definitions = vec![descriptor.model_ref.clone()];
    let continuation =
        arm_root_continuation_schema().map_err(|failure| refused(&failure.reason))?;
    if put(
        contents,
        ARM_ROOT_CONTINUATION_SPECIFICATION.as_bytes().to_vec(),
        "text/plain",
    )? != continuation.definition
    {
        return Err(refused("Root continuation specification identity changed"));
    }
    binding.implementation.formats = vec![continuation];
    let guarantee: GuaranteeProfile =
        serde_json::from_slice(&contents[&binding.guarantees_ref.hash.digest].bytes)?;
    binding.operating_contract.facets = [ARM_ROOT_EXACT_PROFILE, ARM_ROOT_PRESERVATION_PROFILE]
        .into_iter()
        .map(|profile| {
            Ok(FacetSelection {
                id: Id::new(profile)?,
                version: 1,
                configuration_ref: descriptor.configuration_ref.clone(),
                guarantees_ref: binding.guarantees_ref.clone(),
                extensions: Extensions::new(),
            })
        })
        .collect::<Result<_, crucible_node_contract::ContractError>>()?;
    binding
        .operating_contract
        .facets
        .sort_by(|left, right| left.id.cmp(&right.id));
    let devices_ref = put_json(
        contents,
        &serde_json::json!({"schema_version":1,"ports":descriptor.ports,"input_ports":[],"installed":launch.profile(),"model":descriptor.model_ref}),
    )?;
    let capabilities = CapabilityProfile {
        schema_version: 1,
        facets: binding.operating_contract.facets.clone(),
        devices_ref,
        requirements_ref: qualification.clone(),
        extensions: Extensions::new(),
    };
    binding.capabilities_ref = put_json(contents, &capabilities)?;
    binding.operating_contract.policy_ref = put_json(
        contents,
        &serde_json::json!({
            "schema_version":1,"mode":"exact","execution_proof_ref":qualification,
            "ceiling":{"kind":"strict_predecessor"},"boundary_settlement_ref":qualification,
        }),
    )?;
    binding.profile_ref = put_json(
        contents,
        &serde_json::json!({
            "schema":"crucible.installed-arm-root-profile.v1","descriptor":descriptor,"implementation":binding.implementation,
            "operating_contract":binding.operating_contract,"capabilities":capabilities,"guarantees":guarantee,
        }),
    )?;
    Ok((descriptor, binding, owner))
}

fn original_manifest(expected: &ContentRef) -> Result<Vec<u8>, NodeObservedError> {
    let path = option_env!("CRUCIBLE_GEM5_ARM_ROOT_MODEL_MANIFEST")
        .ok_or_else(|| refused("Root common factory lacks an installed source manifest"))?;
    if expected.length.get() > 4 * 1024 * 1024 {
        return Err(refused(
            "Root original manifest exceeds finite metadata credit",
        ));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(error)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(expected.length.get() as usize)
        .map_err(error)?;
    file.by_ref()
        .take(expected.length.get() + 1)
        .read_to_end(&mut bytes)
        .map_err(error)?;
    expected.verify(&bytes)?;
    Ok(bytes)
}

fn error(error: impl std::fmt::Display) -> NodeObservedError {
    refused(&error.to_string())
}
