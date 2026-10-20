//! Builds the exact finite source data for the actual three-peer collecting fixture.
//!
//! Provider and program bodies are data only. The separately compiled independent
//! issuer, measured executables, actual registrar and kernel/native source records
//! must authenticate them before any common effects. No accepted class is built.

// crucible-lint: allow panic-shortcut -- Failures of the controlled object builder are test failures.
// crucible-lint: allow panic-shortcut -- Invalid static test fixture construction is an assertion failure.
#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;

use crucible_node_format::*;
use crucible_node_transport::bodies::RealizeRequest;
use serde::Serialize;

use crucible_engine::node_adapters::cnp::CnpSemanticInstallation;
use crucible_engine::node_admission::*;

pub(super) struct Definition {
    pub installation: CnpSemanticInstallation,
    pub world: WorldBinding,
    pub content: BTreeMap<ContentRef, Vec<u8>>,
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
    pub(super) fn with_native_fixture(
        executable: ContentRef,
        model: &impl Serialize,
        member: usize,
        proof_bytes: Vec<u8>,
        effect_phases: &[u16],
        confirmation: Option<
            crucible_node_transport::reference_packet::service::PacketNative5ConfirmationSelection,
        >,
        ack: Option<crucible_node_transport::reference_packet::service::ack_emitter::PacketNative5AckEmitterSelection>,
        report_startup: bool,
        full_restore: bool,
    ) -> Self {
        let id = |value: &str| match value {
            "packet"
            | "packet-owner"
            | "packet-native-state"
            | "packet-session"
            | "packet-incarnation"
            | "packet-realization"
            | "packet-input-epoch"
            | "packet-admission"
            | "packet-transaction"
            | "packet-gate" => super::id(&format!("{value}-{member}")),
            _ => super::id(value),
        };
        let version = 5;
        let installed = true;
        let mut content = BTreeMap::new();
        let model = put(&mut content, model);
        let proof = canonical::content_ref(&proof_bytes, "application/json").unwrap();
        content.insert(proof.clone(), proof_bytes);
        let guarantees = GuaranteeProfile {
            schema_version: 1,
            repeatability: Repeatability::Unqualified,
            capture_scope: CaptureScope::CompleteModel,
            continuation: Continuation::Exact,
            durable_restart: true,
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
        let semantic_bytes = crucible_node_transport::reference_packet::continuation_contracts::complete_packet_contract().unwrap();
        let semantic_definition =
            canonical::content_ref(&semantic_bytes, "application/json").unwrap();
        content.insert(semantic_definition.clone(), semantic_bytes);
        let preservation = FacetSelection {
            id: id("source-owned.packet-complete-original-lineage/5"),
            version: 5,
            configuration_ref: model.clone(),
            guarantees_ref: guarantees_ref.clone(),
            extensions: Extensions::new(),
        };
        let facets = vec![preservation, facet.clone()];
        let connected_bytes =
            crucible_node_transport::reference_packet::contracts::connected_packet_contract()
                .unwrap();
        content.insert(
            canonical::content_ref(&connected_bytes, "application/json").unwrap(),
            connected_bytes,
        );
        let schema = SchemaRef {
            id: id(&format!("source-owned.packet-receipt/{version}")),
            version,
            definition: semantic_definition.clone(),
            extensions: Extensions::new(),
        };
        let octets =
            crucible_node_transport::reference_packet::contracts::immediate_packet_contract()
                .unwrap();
        let octets_definition = canonical::content_ref(&octets, "application/json").unwrap();
        content.insert(octets_definition.clone(), octets);
        let payload_schema = SchemaRef {
            id: id("source-owned.packet-octets/1"),
            version: 1,
            definition: octets_definition,
            extensions: Extensions::new(),
        };
        let configuration_schema = SchemaRef {
            id: id(if member == 0 {
                "source-owned.packet-program/1"
            } else {
                "source-owned.packet-connected-program/4"
            }),
            version: if member == 0 { 1 } else { 4 },
            definition: semantic_definition,
            extensions: Extensions::new(),
        };
        let mut formats = vec![
            payload_schema.clone(),
            configuration_schema.clone(),
            schema.clone(),
        ];
        if installed {
            let bytes =
                crucible_node_transport::reference_packet::continuation_contracts::complete_ingress_contract()
                    .unwrap();
            let definition = canonical::content_ref(&bytes, "application/json").unwrap();
            content.insert(definition.clone(), bytes);
            formats.push(SchemaRef {
                id: id("source-owned.packet-ingress/5"),
                version: 5,
                definition,
                extensions: Extensions::new(),
            });
        }
        formats.push(crucible_node_transport::reference_packet::continuation_contracts::complete_packet_continuation_schema().unwrap());
        formats.sort_by(|a, b| a.id.cmp(&b.id));
        let owner_ref = OwnerRef {
            id: id("packet-owner"),
            participant_ids: vec![id("packet")],
            state_domain_ids: vec![id("packet-native-state")],
        };
        let directions: Vec<(Direction, &str, &str)> = match member {
            0 => vec![(Direction::Output, "wire_tx", "output")],
            1 => vec![
                (Direction::Input, "wire_rx", "input"),
                (Direction::Output, "wire_tx", "output"),
            ],
            2 => vec![(Direction::Input, "wire_rx", "input")],
            _ => panic!("connected fixture contains exactly three native participants"),
        };
        let ports = directions
            .into_iter()
            .map(|(direction, port, lane)| {
                let policy = PortPolicy {
                    schema_version: 1,
                    lanes: vec![LanePolicy {
                        lane_id: id(lane),
                        ordering_ref: proof.clone(),
                        correlation_ref: proof.clone(),
                        flow_control: FlowControl::Credit,
                        maximum_pending_bytes: U64::new(32),
                        visibility: LaneVisibility::Exact,
                        // Both endpoints share the admitted publication/delivery
                        // lifecycle, independently of local native emission.
                        effect_phases: effect_phases.to_vec(),
                        minimum_lookahead_ps: U64::new(0),
                    }],
                    maximum_producers: U64::new(u64::from(direction == Direction::Input)),
                    maximum_consumers: U64::new(u64::from(direction == Direction::Output)),
                    arbitration_ref: proof.clone(),
                    execution_owner_id: owner_ref.id.clone(),
                    state_domain_ids: owner_ref.state_domain_ids.clone(),
                    internal: false,
                };
                PortDescriptor {
                    id: id(port),
                    lanes: vec![LaneDescriptor {
                        id: id(lane),
                        direction,
                        payload_schema: payload_schema.clone(),
                        maximum_payload_bytes: U64::new(32),
                        maximum_pending_events: U64::new(if member == 0 { 1 } else { 4 }),
                        extensions: Extensions::new(),
                    }],
                    interface_id: id("source-owned.packet-octets/1"),
                    features: vec![],
                    configuration_ref: put(&mut content, &policy),
                    extensions: Extensions::new(),
                }
            })
            .collect();
        let descriptor = NodeDescriptor {
            schema_version: 1,
            id: id("packet"),
            roles: vec![id("external_device")],
            model_ref: model.clone(),
            configuration_ref: model.clone(),
            initialization_ref: model.clone(),
            ports,
            extensions: Extensions::new(),
        };
        let operating_policy = put(
            &mut content,
            &crucible_engine::node_scheduling::ExecutionPolicy::Exact {
                schema_version: 1,
                execution_proof_ref: proof.clone(),
                ceiling: crucible_engine::node_scheduling::ExactCeiling::StrictPredecessor,
                boundary_settlement_ref: Some(proof.clone()),
            },
        );
        let operating_contract = OperatingContract {
            schema_version: 1,
            mode: OperatingMode::Exact,
            scheduling_role: SchedulingRole::Active,
            ordering_profile: "superdense-v1".into(),
            policy_ref: operating_policy,
            resolution_ps: Some(U64::new(1)),
            phase_ps: Some(U64::new(0)),
            facets: facets.clone(),
            extensions: Extensions::new(),
        };
        let capabilities = CapabilityProfile {
            schema_version: 1,
            facets: facets.clone(),
            devices_ref: model.clone(),
            requirements_ref: proof.clone(),
            extensions: Extensions::new(),
        };
        let profile = NodeManifest {
            schema_version: 1,
            profile_id: id("source-owned.packet-complete-original-lineage/5"),
            roles: descriptor.roles.clone(),
            configuration_schema,
            allowed_combinations_ref: model.clone(),
            port_templates_ref: put(&mut content, &descriptor.ports),
            state_formats: vec![crucible_node_transport::reference_packet::continuation_contracts::complete_packet_continuation_schema().unwrap()],
            operation_facets: facets.clone(),
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
            extensions_supported: vec![
                id("cnp.control-evidence/1"),
                id("packet-complete-original-lineage/5"),
                id("source-owned.packet-input/4"),
            ],
            qualification_refs: vec![proof.clone()],
            extensions: Extensions::new(),
        };
        let (declaration, report_contracts) = if report_startup {
            use crucible_node_transport::reference_packet::{
                continuation_contracts::complete_packet_capture_allocation_declaration,
                service::capture_allocation::PacketNative5CaptureAllocationSelection,
            };
            let selected = PacketNative5CaptureAllocationSelection::OriginalObserve12;
            let declaration = if full_restore {
                super::native_roundtrip::restore_declaration(
                    &provider,
                    confirmation.as_ref(),
                    ack.as_ref(),
                )
            } else {
                complete_packet_capture_allocation_declaration(
                    &provider,
                    confirmation.as_ref(),
                    ack.as_ref(),
                    None,
                    None,
                    Some(&selected),
                )
                .unwrap()
            };
            (declaration.peer, declaration.restoration)
        } else {
            (crucible_node_transport::reference_packet::continuation_contracts::complete_packet_ack_emitter_declaration(
                &provider, confirmation.as_ref(), ack.as_ref(),
            ).unwrap(), Vec::new())
        };
        for (_, reference, bytes) in declaration
            .confirmation
            .into_iter()
            .chain(declaration.ack_emitter)
            .chain(declaration.admission)
        {
            content.insert(reference, bytes);
        }
        for (schema, bytes) in report_contracts {
            let reference = canonical::content_ref(&bytes, "application/json").unwrap();
            assert_eq!(reference, schema.definition);
            content.insert(reference, bytes);
        }
        let provider = declaration.provider;
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
                complete_model: true,
                unchanged_cut: true,
                exact_continuation: true,
                durable_restart: true,
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
            facets: vec![
                crucible_engine::node_contract::FacetKind::ExactExecution,
                crucible_engine::node_contract::FacetKind::Preservation,
            ],
            receipt_schema: schema,
            maximum_operations: 64,
            maximum_result_bytes: 65_536,
            maximum_authorization_bytes: 65_536,
            maximum_semantic_bytes: 4 * 1024 * 1024,
        };
        Self {
            installation,
            world,
            content,
        }
    }
}
