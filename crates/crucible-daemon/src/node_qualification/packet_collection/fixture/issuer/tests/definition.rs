//! Builds bounded model-only packet objects for independent policy controls.
//!
//! This geometry derives from the original common packet test selection.
//! It does not launch a peer or authenticate native behavior/classes.

// crucible-lint: allow panic-shortcut -- Failures of the controlled object builder are test failures.
#![allow(clippy::unwrap_used)]
#![cfg(test)]

use std::collections::BTreeMap;

use crucible_node_contract::*;
use crucible_node_provider::bodies::RealizeRequest;
use serde::Serialize;

use crucible::node_adapters::cnp::CnpSemanticInstallation;
use crucible::node_admission::*;

pub(super) struct Definition {
    pub installation: CnpSemanticInstallation,
    pub world: WorldBinding,
    pub requirements: ScenarioRequirements,
    pub content: BTreeMap<ContentRef, Vec<u8>>,
}

pub(super) fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

pub(super) fn encoded(value: &impl Serialize) -> Vec<u8> {
    canonical::canonical_json(&serde_json::to_value(value).unwrap()).unwrap()
}

fn put(content: &mut BTreeMap<ContentRef, Vec<u8>>, value: &impl Serialize) -> ContentRef {
    let bytes = encoded(value);
    let reference = canonical::content_ref(&bytes, "application/json").unwrap();
    content.insert(reference.clone(), bytes);
    reference
}

impl Definition {
    pub(super) fn new(executable: ContentRef, model: &impl Serialize) -> Self {
        let version = 2;
        let installed = true;
        let mut content = BTreeMap::new();
        let model = put(&mut content, model);
        let proof = put(
            &mut content,
            &serde_json::json!({
                "schema":"cnp.packet-mechanism-test.v1",
                "scope":"controlled actual packet process and common original custody",
                "qualification":"not a normative behavioral acceptance certificate",
                "physical_stop":"unknown", "clock_compute_capture":"unsupported"
            }),
        );
        let guarantees = GuaranteeProfile {
            schema_version: 1,
            repeatability: Repeatability::Nondeterministic,
            capture_scope: CaptureScope::None,
            continuation: Continuation::Unsupported,
            durable_restart: false,
            isolated_fork: false,
            conditional_replay: false,
            limitations_ref: proof.clone(),
            extensions: Extensions::new(),
        };
        let guarantees_ref = put(&mut content, &guarantees);
        let facet = FacetSelection {
            id: id(&format!("source-owned.packet-exact/{version}")),
            version,
            configuration_ref: model.clone(),
            guarantees_ref: guarantees_ref.clone(),
            extensions: Extensions::new(),
        };
        let semantic_definition = if version == 2 {
            let bytes =
                crucible_node_provider::reference_packet::contracts::immediate_packet_contract()
                    .unwrap();
            put(
                &mut content,
                &canonical::parse_json(&bytes, 65_536).unwrap(),
            )
        } else {
            model.clone()
        };
        let schema = SchemaRef {
            id: id(&format!("source-owned.packet-receipt/{version}")),
            version,
            definition: semantic_definition.clone(),
            extensions: Extensions::new(),
        };
        let payload_schema = if version == 2 {
            SchemaRef {
                id: id("source-owned.packet-octets/1"),
                version: 1,
                definition: semantic_definition.clone(),
                extensions: Extensions::new(),
            }
        } else {
            schema.clone()
        };
        let configuration_schema = if version == 2 {
            SchemaRef {
                id: id("source-owned.packet-program/1"),
                version: 1,
                definition: semantic_definition,
                extensions: Extensions::new(),
            }
        } else {
            schema.clone()
        };
        let mut formats = if version == 2 {
            vec![
                payload_schema.clone(),
                configuration_schema.clone(),
                schema.clone(),
            ]
        } else {
            vec![schema.clone()]
        };
        if installed {
            let bytes =
                crucible_node_provider::reference_packet::contracts::installed_ingress_contract()
                    .unwrap();
            let definition = canonical::content_ref(&bytes, "application/json").unwrap();
            content.insert(definition.clone(), bytes);
            formats.push(SchemaRef {
                id: id("source-owned.packet-ingress/1"),
                version: 1,
                definition,
                extensions: Extensions::new(),
            });
        }
        formats.sort_by(|a, b| a.id.cmp(&b.id));
        let owner_ref = OwnerRef {
            id: id("packet-owner"),
            participant_ids: vec![id("packet")],
            state_domain_ids: vec![id("packet-native-state")],
        };
        let port_policy = PortPolicy {
            schema_version: 1,
            lanes: vec![LanePolicy {
                lane_id: id("output"),
                ordering_ref: model.clone(),
                correlation_ref: model.clone(),
                flow_control: FlowControl::Credit,
                maximum_pending_bytes: U64::new(32),
                visibility: LaneVisibility::Exact,
                effect_phases: vec![1],
                minimum_lookahead_ps: U64::new(0),
            }],
            maximum_producers: U64::new(0),
            maximum_consumers: U64::new(1),
            arbitration_ref: model.clone(),
            execution_owner_id: owner_ref.id.clone(),
            state_domain_ids: owner_ref.state_domain_ids.clone(),
            internal: false,
        };
        let descriptor = NodeDescriptor {
            schema_version: 1,
            id: id("packet"),
            roles: vec![id("external_device")],
            model_ref: model.clone(),
            configuration_ref: model.clone(),
            initialization_ref: model.clone(),
            ports: vec![PortDescriptor {
                id: id("wire_tx"),
                lanes: vec![LaneDescriptor {
                    id: id("output"),
                    direction: Direction::Output,
                    payload_schema: payload_schema.clone(),
                    maximum_payload_bytes: U64::new(32),
                    maximum_pending_events: U64::new(1),
                    extensions: Extensions::new(),
                }],
                interface_id: id("source-owned.packet-octets/1"),
                features: vec![],
                configuration_ref: put(&mut content, &port_policy),
                extensions: Extensions::new(),
            }],
            extensions: Extensions::new(),
        };
        let operating_contract = OperatingContract {
            schema_version: 1,
            mode: OperatingMode::Exact,
            scheduling_role: SchedulingRole::Active,
            ordering_profile: "superdense-v1".into(),
            policy_ref: model.clone(),
            resolution_ps: None,
            phase_ps: None,
            facets: vec![facet.clone()],
            extensions: Extensions::new(),
        };
        let capabilities = CapabilityProfile {
            schema_version: 1,
            facets: vec![facet.clone()],
            devices_ref: model.clone(),
            requirements_ref: proof.clone(),
            extensions: Extensions::new(),
        };
        let profile = NodeManifest {
            schema_version: 1,
            profile_id: id(&format!("source-owned.packet-emitter/{version}")),
            roles: descriptor.roles.clone(),
            configuration_schema,
            allowed_combinations_ref: model.clone(),
            port_templates_ref: put(&mut content, &descriptor.ports),
            state_formats: vec![],
            operation_facets: vec![facet.clone()],
            extensions: Extensions::new(),
        };
        let provider = ProviderManifest {
            schema_version: 1,
            provider_id: id("source-owned.packet-provider"),
            implementation: ImplementationIdentity {
                schema_version: 1,
                implementation_id: id(&format!("source-owned.packet-native/{version}")),
                artifacts: vec![ArtifactIdentity {
                    id: id("original-provider"),
                    role: id("executable"),
                    content: executable,
                    extensions: Extensions::new(),
                }],
                model_definitions: vec![model.clone()],
                formats,
                extensions: Extensions::new(),
            },
            protocol_versions: vec![id("CNP/1")],
            supported_profiles: vec![profile.clone()],
            extensions_supported: vec![id("cnp.control-evidence/1")],
            qualification_refs: vec![proof.clone()],
            extensions: Extensions::new(),
        };
        let binding = NodeBinding {
            compatibility: BindingCompatibility {
                schema_version: 1,
                node_id: descriptor.id.clone(),
                descriptor_hash: descriptor.identity().unwrap(),
                implementation: provider.implementation.clone(),
                profile_ref: put(&mut content, &profile),
                configuration_ref: model.clone(),
                operating_contract,
                execution_owner: owner_ref.clone(),
                capture_owner: owner_ref.clone(),
                capabilities_ref: put(&mut content, &capabilities),
                guarantees_ref,
                qualification_refs: vec![proof.clone()],
                extensions: Extensions::new(),
            },
            authority: LiveAuthority {
                schema_version: 1,
                session_id: id("packet-session"),
                incarnation_id: id("packet-incarnation"),
                realization_id: id("packet-realization"),
                activation_id: None,
                world_generation: U64::new(0),
                owner_generation: U64::new(1),
                input_epoch: id("packet-input-epoch"),
                host_receipt: proof.clone(),
                extensions: Extensions::new(),
            },
            extensions: Extensions::new(),
        };
        let node_bindings = vec![NodeBindingRef {
            node_id: descriptor.id.clone(),
            binding_hash: binding.identity().unwrap(),
            extensions: Extensions::new(),
        }];
        let owner = OwnerBinding {
            schema_version: 1,
            owner: owner_ref.clone(),
            owner_roles: vec![id("capture"), id("execution")],
            node_bindings: node_bindings.clone(),
            ownership_ref: model.clone(),
            extensions: Extensions::new(),
        };
        let ownership = OwnershipPolicy {
            schema_version: 1,
            domains: vec![StateDomain {
                id: owner_ref.state_domain_ids[0].clone(),
                capture_owner_id: owner_ref.id.clone(),
                execution_owner_ids: vec![owner_ref.id.clone()],
                future_affecting: true,
            }],
            objects: vec![StateObject {
                id: descriptor.id.clone(),
                node_ids: vec![descriptor.id.clone()],
                future_affecting: true,
                state: ObjectState::Mutable {
                    domain_id: owner_ref.state_domain_ids[0].clone(),
                },
            }],
            internal_dependencies: vec![],
            capture_owners: vec![OwnerCapturePolicy {
                owner_id: owner_ref.id.clone(),
                complete_model: false,
                unchanged_cut: false,
                exact_continuation: false,
                durable_restart: false,
                isolated_fork: false,
                dependencies: vec![],
                cut_procedure_ref: proof.clone(),
            }],
            inventory_proof_ref: proof.clone(),
        };
        let coordinator = CoordinatorPolicy {
            schema_version: 1,
            state_closure_ref: proof.clone(),
            maximum_microsteps_per_instant: U64::new(1024),
            same_time_closure: vec![],
            operational_policy_ref: proof.clone(),
            external_inputs: vec![],
        };
        let requirements = ScenarioRequirements {
            accepted_nondeterministic_nodes: vec![descriptor.id.clone()],
            accepted_limited_state_nodes: vec![descriptor.id.clone()],
            ..ScenarioRequirements::default()
        };
        let world = WorldBinding {
            schema_version: 1,
            scenario_ref: put(&mut content, &requirements),
            node_bindings,
            connections: vec![],
            ownership_ref: put(&mut content, &ownership),
            coordinator_contract_ref: put(&mut content, &coordinator),
            ordering_profile: "superdense-v1".into(),
            initialization_ref: model.clone(),
            extensions: Extensions::new(),
        };
        let realize = RealizeRequest {
            realization_id: binding.authority.realization_id.clone(),
            configuration: model,
            requested_node_ids: vec![descriptor.id.clone()],
            resource_limits: ResourceLimits {
                cpu_budget_ns: U64::new(3_000_000_000),
                memory_bytes: U64::new(256 * 1024 * 1024),
                writable_bytes: U64::new(1024 * 1024),
                processes: U64::new(1),
                descriptors: U64::new(32),
                pending_events: U64::new(1),
                content_bytes: U64::new(256 * 1024 * 1024),
                maximum_operations: U64::new(64),
                extensions: Extensions::new(),
            },
            extensions: Extensions::new(),
        };
        let installation = CnpSemanticInstallation {
            provider,
            profile,
            descriptor,
            binding,
            capabilities,
            exact_facet: facet,
            guarantees,
            owner,
            realize,
            admission: id("packet-admission"),
            transaction: id("packet-transaction"),
            gate: id("packet-gate"),
            admission_receipt: proof,
            world_binding_hash: world.identity().unwrap(),
            facets: vec![crucible::node_contract::FacetKind::ExactExecution],
            receipt_schema: schema,
            maximum_operations: 64,
            maximum_result_bytes: if version == 2 { 65_536 } else { 16 * 1024 },
            maximum_authorization_bytes: if version == 2 { 8192 } else { 4096 },
            maximum_semantic_bytes: 4 * 1024 * 1024,
        };
        Self {
            installation,
            world,
            requirements,
            content,
        }
    }
}
