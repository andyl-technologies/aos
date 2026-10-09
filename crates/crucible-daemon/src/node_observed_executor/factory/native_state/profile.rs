//! Immutable candidate profiles for the installed Clock and closed gem5 world.
//!
//! Profile construction describes a selected model; it grants no qualification,
//! native custody or readiness. Admission separately measures the real resources
//! and fresh execution authority. This child remains confined to integration
//! tests until the complete mixed cold-world witness has qualified its bridge.

use std::{collections::BTreeMap, rc::Rc};

use crucible::node_adapters::gem5::{
    GEM5_CLOSED_EXACT_PROFILE, GEM5_NATIVE_CONTINUATION_SPECIFICATION,
    GEM5_OPAQUE_PRESERVATION_PROFILE, Gem5NodeResources, gem5_native_continuation_schema,
};
use crucible::node_admission::{
    CoordinatorPolicy, FlowControl, LanePolicy, LaneVisibility, ObjectState, OwnerCapturePolicy,
    OwnershipPolicy, PortPolicy, ScenarioRequirements, StateDomain, StateObject,
};
use crucible_node_contract::{
    ArtifactIdentity, BindingCompatibility, CapabilityProfile, ContentRef, Direction, Extensions,
    FacetSelection, GuaranteeProfile, Id, LaneDescriptor, NodeBindingRef, NodeDescriptor,
    OwnerBinding, PortDescriptor, SchemaRef, WorldBinding,
};
use crucible_node_provider::reference_service::profile::{
    NATIVE_OCTET_INTERFACE_ID, NATIVE_OCTET_SCHEMA_ID, NATIVE_OCTET_SPECIFICATION,
};

use super::super::{
    InstalledGem5ClosedProfile, InstalledNodeKind, InstalledNodeSelection, NodeObservedError,
    profile::{clock_profile, put, put_json},
};
use crate::node_scenario::{NodeScenario, ScenarioContent};

/// Retains one regenerated candidate and its independently installed package.
pub(super) struct MixedProfile {
    pub(super) scenario: NodeScenario,
    pub(super) installed: Rc<InstalledGem5ClosedProfile>,
    pub(super) qualification: ContentRef,
    pub(super) isa: String,
    pub(super) public_preparation: bool,
}

impl MixedProfile {
    /// Regenerates the complete fixed no-ingress Clock and gem5 model selection.
    ///
    /// # Errors
    /// Refuses unknown installed guests or invalid artifact, schema and policy
    /// identities. The returned portable profile alone authorizes no execution.
    pub(super) fn build(
        installed: Rc<InstalledGem5ClosedProfile>,
        host: &ContentRef,
        isa: &str,
    ) -> Result<Self, NodeObservedError> {
        Self::build_selected(installed, host, isa, false)
    }

    pub(super) fn build_public(
        installed: Rc<InstalledGem5ClosedProfile>,
        host: &ContentRef,
        isa: &str,
    ) -> Result<Self, NodeObservedError> {
        Self::build_selected(installed, host, isa, true)
    }

    fn build_selected(
        installed: Rc<InstalledGem5ClosedProfile>,
        host: &ContentRef,
        isa: &str,
        public_preparation: bool,
    ) -> Result<Self, NodeObservedError> {
        let guest = installed.guest(isa)?;
        let mut contents = BTreeMap::new();
        let (document_ref, document_bytes) = installed.document();
        let retained_document = put(
            &mut contents,
            document_bytes.to_vec(),
            &document_ref.media_type,
        )?;
        if &retained_document != document_ref {
            return Err(super::super::refused(
                "installed gem5 policy document identity changed",
            ));
        }
        let mut qualification_body = serde_json::json!({
            "schema":"crucible.installed-mixed-native-procedure.v1",
            "installed_package":installed.identity(),"isa":isa,"guest":guest.content,
            "clock":"complete owned host integer clock",
            "gem5":"complete fixed O3/classic-DDR3 opaque process and resource closure",
            "coordinator":"complete original runtime, prefix, output, reservations and ACK custody",
            "restart":"signed backend-bound original images; genuine fresh native certificate; no drain or operation replay",
            "external_inputs":[],"connections":[],"faults":[],
        });
        if public_preparation {
            qualification_body["schema"] = "crucible.installed-public-native-preparation.v1".into();
            qualification_body["restart"] =
                "unsupported: preparation-bearing archive codec not selected".into();
            qualification_body["public_preparation"] = true.into();
        }
        let qualification = put_json(&mut contents, &qualification_body)?;
        let clock = InstalledNodeSelection {
            node: Id::new("clock")?,
            owner: Id::new("owner/clock")?,
            kind: InstalledNodeKind::HostClock,
        };
        let cpu = InstalledNodeSelection {
            node: Id::new("cpu")?,
            owner: Id::new("owner/cpu")?,
            // The selection is passed only to the shared pure owner constructor.
            // Actual native realization is exclusively the fixed gem5 package.
            kind: InstalledNodeKind::HostClock,
        };
        let clock_profile = clock_profile(&clock, host, &qualification, &mut contents)?;
        let cpu_profile = gem5_profile(&cpu, host, isa, &installed, &qualification, &mut contents)?;
        let mut descriptors = Vec::new();
        let mut compatibility = Vec::new();
        let mut owners = Vec::new();
        let mut domains = Vec::new();
        let mut objects = Vec::new();
        let mut captures = Vec::new();
        for (mut descriptor, mut binding, mut owner, _) in [clock_profile, cpu_profile] {
            if public_preparation {
                select_public_preparation(&mut descriptor, &mut binding, &mut contents)?;
            }
            let domain = owner
                .owner
                .state_domain_ids
                .first()
                .cloned()
                .ok_or_else(|| {
                    super::super::refused("installed mixed owner omitted its native state domain")
                })?;
            owner.node_bindings = vec![NodeBindingRef {
                node_id: descriptor.id.clone(),
                binding_hash: binding.identity()?,
                extensions: Extensions::new(),
            }];
            domains.push(StateDomain {
                id: domain.clone(),
                capture_owner_id: owner.owner.id.clone(),
                execution_owner_ids: vec![owner.owner.id.clone()],
                future_affecting: true,
            });
            objects.push(StateObject {
                id: descriptor.id.clone(),
                node_ids: vec![descriptor.id.clone()],
                future_affecting: true,
                state: ObjectState::Mutable { domain_id: domain },
            });
            captures.push(OwnerCapturePolicy {
                owner_id: owner.owner.id.clone(),
                complete_model: !public_preparation,
                unchanged_cut: !public_preparation,
                exact_continuation: !public_preparation,
                durable_restart: !public_preparation,
                isolated_fork: false,
                dependencies: Vec::new(),
                cut_procedure_ref: qualification.clone(),
            });
            descriptors.push(descriptor);
            compatibility.push(binding);
            owners.push(owner);
        }
        let ownership_ref = put_json(
            &mut contents,
            &OwnershipPolicy {
                schema_version: 1,
                domains,
                objects,
                internal_dependencies: Vec::new(),
                capture_owners: captures,
                inventory_proof_ref: qualification.clone(),
            },
        )?;
        let coordinator_ref = put_json(
            &mut contents,
            &CoordinatorPolicy {
                schema_version: 1,
                state_closure_ref: qualification.clone(),
                maximum_microsteps_per_instant: installed.maximum_microsteps(),
                same_time_closure: Vec::new(),
                operational_policy_ref: qualification.clone(),
                external_inputs: Vec::new(),
            },
        )?;
        let mut scenario_body = serde_json::json!({
            "schema":"crucible.installed-mixed-native-scenario.v1",
            "isa":isa,"package":installed.identity(),"nodes":["clock","cpu"],
            "connections":[],"external_inputs":[],"faults":[],
        });
        if public_preparation {
            scenario_body["schema"] = "crucible.installed-public-native-scenario.v1".into();
            scenario_body["public_preparation"] = true.into();
        }
        let scenario_ref = put_json(&mut contents, &scenario_body)?;
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
            coordinator_contract_ref: coordinator_ref,
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
                exact_capture: !public_preparation,
                exact_continuation: !public_preparation,
                durable_restart: !public_preparation,
                accepted_limited_state_nodes: if public_preparation {
                    vec![Id::new("clock")?, Id::new("cpu")?]
                } else {
                    Vec::new()
                },
                ..ScenarioRequirements::default()
            },
            content,
        };
        scenario.canonical_bytes()?;
        Ok(Self {
            scenario,
            installed,
            qualification,
            isa: isa.to_owned(),
            public_preparation,
        })
    }
}

/// Selects live public readiness while explicitly refusing every preservation capability.
fn select_public_preparation(
    descriptor: &mut NodeDescriptor,
    binding: &mut BindingCompatibility,
    contents: &mut BTreeMap<String, ScenarioContent>,
) -> Result<(), NodeObservedError> {
    use crucible::node_adapters::{
        HOST_PUBLIC_CLOCK_PREPARATION_SPECIFICATION,
        gem5::{GEM5_PUBLIC_PREPARATION_SPECIFICATION, gem5_public_preparation_schema},
        host_public_clock_preparation_schema,
    };
    let (schema, specification) = if descriptor.id.as_str() == "clock" {
        (
            host_public_clock_preparation_schema(),
            HOST_PUBLIC_CLOCK_PREPARATION_SPECIFICATION,
        )
    } else {
        (
            gem5_public_preparation_schema(),
            GEM5_PUBLIC_PREPARATION_SPECIFICATION,
        )
    };
    let schema = schema.map_err(|error| super::super::refused(&error.reason))?;
    if put(contents, specification.as_bytes().to_vec(), "text/plain")? != schema.definition {
        return Err(super::super::refused(
            "public preparation schema bytes differ",
        ));
    }
    let mut guarantee: GuaranteeProfile =
        serde_json::from_slice(&contents[&binding.guarantees_ref.hash.digest].bytes)?;
    guarantee.capture_scope = crucible_node_contract::CaptureScope::None;
    guarantee.continuation = crucible_node_contract::Continuation::Unsupported;
    guarantee.durable_restart = false;
    guarantee.isolated_fork = false;
    guarantee.conditional_replay = false;
    binding.guarantees_ref = put_json(contents, &guarantee)?;
    let mut configuration: serde_json::Value =
        serde_json::from_slice(&contents[&descriptor.configuration_ref.hash.digest].bytes)?;
    configuration["public_preparation_schema"] = serde_json::to_value(&schema)?;
    descriptor.configuration_ref = put_json(contents, &configuration)?;
    binding.configuration_ref = descriptor.configuration_ref.clone();
    binding.implementation.formats = vec![schema];
    binding
        .operating_contract
        .facets
        .retain(|facet| facet.id.as_str() != GEM5_OPAQUE_PRESERVATION_PROFILE);
    for facet in &mut binding.operating_contract.facets {
        facet.guarantees_ref = binding.guarantees_ref.clone();
        facet.configuration_ref = descriptor.configuration_ref.clone();
    }
    let original: CapabilityProfile =
        serde_json::from_slice(&contents[&binding.capabilities_ref.hash.digest].bytes)?;
    let capabilities = CapabilityProfile {
        facets: binding.operating_contract.facets.clone(),
        ..original
    };
    binding.capabilities_ref = put_json(contents, &capabilities)?;
    binding.descriptor_hash = descriptor.identity()?;
    binding.profile_ref = put_json(
        contents,
        &serde_json::json!({
            "schema":"crucible.installed-live-public-preparation.v1",
            "descriptor":descriptor,"implementation":binding.implementation,
            "operating_contract":binding.operating_contract,
            "capabilities":capabilities,"guarantees":guarantee,
            "preservation":"unsupported until original preparation-bearing codec qualification",
        }),
    )?;
    Ok(())
}

/// Fixes the bounded mechanical prefix policy before native realization.
///
/// Full original diagnostic inventories are retained for each prefix. The
/// selected callback budget funds the known guest's suffix within the existing
/// native byte ceiling; it changes neither the common grant nor native order.
pub(super) fn native_resources(isa: &str) -> Result<Gem5NodeResources, NodeObservedError> {
    let maximum_events_per_poll = match isa {
        "x86_64" => 65_536,
        "aarch64" => 262_144,
        _ => {
            return Err(super::super::refused(
                "unsupported native poll architecture",
            ));
        }
    };

    Ok(Gem5NodeResources {
        maximum_operations: 4096,
        maximum_prefixes: 65_536,
        maximum_retained_bytes: 256 * 1024 * 1024,
        maximum_events_per_poll: maximum_events_per_poll.into(),
    })
}

fn gem5_profile(
    selected: &InstalledNodeSelection,
    host: &ContentRef,
    isa: &str,
    installed: &InstalledGem5ClosedProfile,
    qualification: &ContentRef,
    contents: &mut BTreeMap<String, ScenarioContent>,
) -> Result<(NodeDescriptor, BindingCompatibility, OwnerBinding, bool), NodeObservedError> {
    let (mut descriptor, mut binding, owner, complete) =
        clock_profile(selected, host, qualification, contents)?;
    descriptor.roles = vec![Id::new("compute")?];
    descriptor.model_ref = put_json(
        contents,
        &serde_json::json!({
            "schema":"crucible.installed-gem5-model.v1","package":installed.identity(),
            "isa":isa,"guest":installed.guest(isa)?.content,
            "cpu":"O3","memory":"classic DDR3","clock":"one picosecond native tick",
            "mapping":"even native Reaction, odd native Publication",
            "complete_state":"CPU, RAM, caches, predictor, devices, native event heap, full resource and administrative prefix/output/ACK state",
            "ingress":[],"devices":["native syscall stdout/exit"],
        }),
    )?;
    let resources = native_resources(isa)?;
    descriptor.configuration_ref = put_json(
        contents,
        &serde_json::json!({
            "schema_version":1,"installed_package":installed.identity(),"isa":isa,
            "resolution_ps":"1","phase_ps":"0","maximum_microsteps":installed.maximum_microsteps(),
            "native_poll":{
                "maximum_operations":resources.maximum_operations.to_string(),
                "maximum_prefixes":resources.maximum_prefixes.to_string(),
                "maximum_retained_bytes":resources.maximum_retained_bytes.to_string(),
                "maximum_events_per_poll":resources.maximum_events_per_poll,
            },
        }),
    )?;
    descriptor.initialization_ref = put_json(
        contents,
        &serde_json::json!({
            "schema":"crucible.installed-gem5-initialization.v1",
            "guest":installed.guest(isa)?.content,"native_tick":"0","prefixes":[],
            "launch":"source-qualified fixed no-ingress guest model before native events",
        }),
    )?;
    let ordering = put(contents,
        b"installed gem5 stdout v1: original syscall write birth in Reaction; immutable raw octets published once in Publication; native prefix and ACK journal remain exact; no host ingress or external roots".to_vec(),"text/plain")?;
    let octet_schema = SchemaRef {
        id: Id::new(NATIVE_OCTET_SCHEMA_ID)?,
        version: 1,
        definition: put(
            contents,
            NATIVE_OCTET_SPECIFICATION.as_bytes().to_vec(),
            "text/plain",
        )?,
        extensions: Extensions::new(),
    };
    let policy = PortPolicy {
        schema_version: 1,
        lanes: vec![LanePolicy {
            lane_id: Id::new("output")?,
            ordering_ref: ordering.clone(),
            correlation_ref: ordering.clone(),
            flow_control: FlowControl::Credit,
            maximum_pending_bytes: (4 * 1024 * 1024).into(),
            visibility: LaneVisibility::Exact,
            effect_phases: vec![1],
            minimum_lookahead_ps: 0.into(),
        }],
        maximum_producers: 1.into(),
        maximum_consumers: 1.into(),
        arbitration_ref: ordering,
        execution_owner_id: selected.owner.clone(),
        state_domain_ids: owner.owner.state_domain_ids.clone(),
        internal: false,
    };
    descriptor.ports = vec![PortDescriptor {
        id: Id::new("stdout")?,
        interface_id: Id::new(NATIVE_OCTET_INTERFACE_ID)?,
        features: Vec::new(),
        configuration_ref: put_json(contents, &policy)?,
        lanes: vec![LaneDescriptor {
            id: Id::new("output")?,
            direction: Direction::Output,
            payload_schema: octet_schema,
            maximum_payload_bytes: (4 * 1024 * 1024).into(),
            maximum_pending_events: 16.into(),
            extensions: Extensions::new(),
        }],
        extensions: Extensions::new(),
    }];
    binding.descriptor_hash = descriptor.identity()?;
    binding.configuration_ref = descriptor.configuration_ref.clone();
    binding.implementation.implementation_id = Id::new("gem5/native-process-v1")?;
    binding.implementation.artifacts = Vec::new();
    for (id, role, key) in [
        ("gem5", "emulator", "native_executable"),
        ("model", "model-definition", "model"),
        ("owner", "native-controller", "controller"),
        ("image-launcher", "image-launcher", "dmtcp_launch"),
        ("image-restarter", "image-restarter", "dmtcp_restart"),
        ("image-runtime", "image-runtime", "mtcp_restart"),
        ("resource-helper", "resource-helper", "image_guard"),
    ] {
        binding.implementation.artifacts.push(ArtifactIdentity {
            id: Id::new(id)?,
            role: Id::new(role)?,
            content: installed.artifact(key)?.content,
            extensions: Extensions::new(),
        });
    }
    binding.implementation.artifacts.push(ArtifactIdentity {
        id: Id::new("guest")?,
        role: Id::new("guest-image")?,
        content: installed.guest(isa)?.content,
        extensions: Extensions::new(),
    });
    binding
        .implementation
        .artifacts
        .sort_by(|a, b| a.id.cmp(&b.id));
    binding.implementation.model_definitions = vec![descriptor.model_ref.clone()];
    let schema =
        gem5_native_continuation_schema().map_err(|error| super::super::refused(&error.reason))?;
    put(
        contents,
        GEM5_NATIVE_CONTINUATION_SPECIFICATION.as_bytes().to_vec(),
        "text/plain",
    )?;
    binding.implementation.formats = vec![schema];
    let guarantees: GuaranteeProfile =
        serde_json::from_slice(&contents[&binding.guarantees_ref.hash.digest].bytes)?;
    binding.operating_contract.facets =
        [GEM5_CLOSED_EXACT_PROFILE, GEM5_OPAQUE_PRESERVATION_PROFILE]
            .into_iter()
            .map(|name| {
                Ok(FacetSelection {
                    id: Id::new(name)?,
                    version: 1,
                    configuration_ref: descriptor.configuration_ref.clone(),
                    guarantees_ref: binding.guarantees_ref.clone(),
                    extensions: Extensions::new(),
                })
            })
            .collect::<Result<_, crucible_node_contract::ContractError>>()?;
    let devices = put_json(
        contents,
        &serde_json::json!({
            "schema_version":1,"ports":descriptor.ports,"input_ports":[],
            "installed_package":installed.identity(),"model":descriptor.model_ref,
        }),
    )?;
    let capabilities = CapabilityProfile {
        schema_version: 1,
        facets: binding.operating_contract.facets.clone(),
        devices_ref: devices,
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
            "schema_version":1,"descriptor":descriptor,"implementation":binding.implementation,
            "operating_contract":binding.operating_contract,"capabilities":capabilities,"guarantees":guarantees,
        }),
    )?;
    Ok((descriptor, binding, owner, complete))
}

#[cfg(test)]
mod tests {
    // Candidate profile checks intentionally panic when exact identity changes.
    // crucible-lint: allow panic-shortcut -- These profile tests deliberately panic on invalid fixtures or failed invariants.
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crucible_node_contract::canonical;

    #[test]
    fn native_poll_credit_is_selected_by_architecture_without_widening_byte_limits() {
        let x86 = native_resources("x86_64").unwrap();
        let arm = native_resources("aarch64").unwrap();

        assert_eq!(x86.maximum_events_per_poll, 65_536.into());
        assert_eq!(arm.maximum_events_per_poll, 262_144.into());
        assert_eq!(x86.maximum_retained_bytes, 256 * 1024 * 1024);
        assert_eq!(arm.maximum_retained_bytes, x86.maximum_retained_bytes);
        assert_eq!(arm.maximum_operations, x86.maximum_operations);
        assert_eq!(arm.maximum_prefixes, x86.maximum_prefixes);
        assert!(native_resources("foreign-isa").is_err());
    }

    #[test]
    #[ignore = "requires the compiled source-built gem5 closed profile"]
    fn fixed_guest_isa_and_backend_keys_are_bound_into_the_complete_world() {
        let installed = InstalledGem5ClosedProfile::built_in().unwrap();
        let host =
            canonical::content_ref(b"fixture host identity", "application/octet-stream").unwrap();
        let x86 = MixedProfile::build(installed.clone(), &host, "x86_64").unwrap();
        let arm = MixedProfile::build(installed.clone(), &host, "aarch64").unwrap();

        assert_eq!(x86.scenario.descriptors.len(), 2);
        assert_eq!(x86.scenario.owners.len(), 2);
        assert_eq!(x86.installed.identity(), installed.identity());
        assert_eq!(x86.isa, "x86_64");
        assert_ne!(
            x86.scenario.world.identity().unwrap(),
            arm.scenario.world.identity().unwrap()
        );
        assert_ne!(x86.qualification, arm.qualification);
        let cpu = &x86.scenario.compatibility[1];
        assert_eq!(
            cpu.implementation.implementation_id.as_str(),
            "gem5/native-process-v1"
        );
        assert_eq!(cpu.operating_contract.facets.len(), 2);
        assert_eq!(
            cpu.implementation.formats,
            vec![gem5_native_continuation_schema().unwrap()]
        );
        let guest = cpu
            .implementation
            .artifacts
            .iter()
            .find(|artifact| artifact.id.as_str() == "guest")
            .unwrap();
        assert_eq!(guest.content, installed.guest("x86_64").unwrap().content);
        assert!(MixedProfile::build(installed, &host, "foreign-isa").is_err());
    }
}
