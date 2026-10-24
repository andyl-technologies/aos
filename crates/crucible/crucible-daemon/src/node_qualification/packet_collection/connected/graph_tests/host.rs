//! Builds source-selected host ownership data for the actual common scheduler.
//!
//! The factory will authenticate these records and retain its original source.
//! They predict no readiness and select no preservation or execution facet.

// crucible-lint: allow panic-shortcut -- Invalid static test fixture construction is an assertion failure.
#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;

use crucible_engine::node_admission::{
    ObjectState, OwnerCapturePolicy, OwnershipPolicy, StateDomain, StateObject,
};
use crucible_engine::node_contract::{
    HostSchedulingConnectionDomain, HostSchedulingDomains, HostSchedulingSelection,
    host_scheduling_owner_configuration, host_scheduling_owner_definition,
    host_scheduling_owner_preparation_schema,
};
use crucible_engine::node_scheduling::{ExactCeiling, ExecutionPolicy};
use crucible_node_format::*;
use serde::Serialize;

use super::id;

pub(super) struct Host {
    pub selection: HostSchedulingSelection,
    pub ownership: OwnershipPolicy,
    pub content: BTreeMap<ContentRef, Vec<u8>>,
}

fn put(content: &mut BTreeMap<ContentRef, Vec<u8>>, value: &impl Serialize) -> ContentRef {
    let bytes = canonical::canonical_json(&serde_json::to_value(value).unwrap()).unwrap();
    let reference = canonical::content_ref(&bytes, "application/json").unwrap();
    content.insert(reference.clone(), bytes);
    reference
}

impl Host {
    pub(super) fn new(executable: ContentRef, proof: ContentRef) -> Self {
        let mut content = BTreeMap::new();
        let definition_bytes = host_scheduling_owner_definition().unwrap();
        let definition = canonical::content_ref(&definition_bytes, "application/json").unwrap();
        content.insert(definition.clone(), definition_bytes);
        let preparation = host_scheduling_owner_preparation_schema().unwrap();
        let domains = HostSchedulingDomains {
            coordinator: id("zz-packet-coordinator-state"),
            connections: (0..2)
                .map(|index| HostSchedulingConnectionDomain {
                    connection: id(&format!("packet-connection-{index}")),
                    domain: id(&format!("zz-packet-link-{index}-state")),
                })
                .collect(),
        };
        let configuration_bytes = host_scheduling_owner_configuration(&domains).unwrap();
        let configuration =
            canonical::content_ref(&configuration_bytes, "application/json").unwrap();
        content.insert(configuration.clone(), configuration_bytes);
        let descriptor = NodeDescriptor {
            schema_version: 1,
            id: id("zz-packet-scheduler"),
            roles: vec![id("coordinator-state")],
            model_ref: definition.clone(),
            configuration_ref: configuration.clone(),
            initialization_ref: configuration.clone(),
            ports: vec![],
            extensions: Extensions::new(),
        };
        let owner_ref = OwnerRef {
            id: id("zz-packet-scheduler-owner"),
            participant_ids: vec![descriptor.id.clone()],
            state_domain_ids: vec![
                id("zz-packet-coordinator-state"),
                id("zz-packet-link-0-state"),
                id("zz-packet-link-1-state"),
            ],
        };
        let guarantees = GuaranteeProfile {
            schema_version: 1,
            repeatability: Repeatability::Unqualified,
            capture_scope: CaptureScope::None,
            continuation: Continuation::Unsupported,
            durable_restart: false,
            isolated_fork: false,
            conditional_replay: false,
            limitations_ref: proof.clone(),
            extensions: Extensions::new(),
        };
        let operating_policy = ExecutionPolicy::Exact {
            schema_version: 1,
            execution_proof_ref: proof.clone(),
            ceiling: ExactCeiling::StrictPredecessor,
            boundary_settlement_ref: None,
        };
        let policy_ref = put(&mut content, &operating_policy);
        let guarantees_ref = put(&mut content, &guarantees);
        let capabilities = CapabilityProfile {
            schema_version: 1,
            facets: vec![],
            devices_ref: definition.clone(),
            requirements_ref: proof.clone(),
            extensions: Extensions::new(),
        };
        let binding = NodeBinding {
            compatibility: BindingCompatibility {
                schema_version: 1,
                node_id: descriptor.id.clone(),
                descriptor_hash: descriptor.identity().unwrap(),
                implementation: ImplementationIdentity {
                    schema_version: 1,
                    implementation_id: id("source-owned.host-scheduling-owner/1"),
                    artifacts: vec![ArtifactIdentity {
                        id: id("original-host-runtime"),
                        role: id("executable"),
                        content: executable,
                        extensions: Extensions::new(),
                    }],
                    model_definitions: vec![definition.clone()],
                    formats: vec![preparation],
                    extensions: Extensions::new(),
                },
                profile_ref: definition.clone(),
                configuration_ref: configuration,
                operating_contract: OperatingContract {
                    schema_version: 1,
                    mode: OperatingMode::Exact,
                    scheduling_role: SchedulingRole::EventDriven,
                    ordering_profile: "superdense-v1".into(),
                    policy_ref,
                    resolution_ps: Some(U64::new(1)),
                    phase_ps: Some(U64::new(0)),
                    facets: vec![],
                    extensions: Extensions::new(),
                },
                execution_owner: owner_ref.clone(),
                capture_owner: owner_ref.clone(),
                capabilities_ref: put(&mut content, &capabilities),
                guarantees_ref,
                qualification_refs: vec![proof.clone()],
                extensions: Extensions::new(),
            },
            authority: LiveAuthority {
                schema_version: 1,
                session_id: id("zz-packet-scheduler-session"),
                incarnation_id: id("zz-packet-scheduler-incarnation"),
                realization_id: id("zz-packet-scheduler-realization"),
                activation_id: None,
                world_generation: U64::new(0),
                owner_generation: U64::new(1),
                input_epoch: id("zz-packet-scheduler-input-epoch"),
                host_receipt: proof.clone(),
                extensions: Extensions::new(),
            },
            extensions: Extensions::new(),
        };
        let owner = OwnerBinding {
            schema_version: 1,
            owner: owner_ref.clone(),
            owner_roles: vec![id("capture"), id("execution")],
            node_bindings: vec![NodeBindingRef {
                node_id: descriptor.id.clone(),
                binding_hash: binding.identity().unwrap(),
                extensions: Extensions::new(),
            }],
            ownership_ref: definition,
            extensions: Extensions::new(),
        };
        let mut ownership = OwnershipPolicy {
            schema_version: 1,
            domains: owner_ref
                .state_domain_ids
                .iter()
                .map(|domain| StateDomain {
                    id: domain.clone(),
                    capture_owner_id: owner_ref.id.clone(),
                    execution_owner_ids: vec![owner_ref.id.clone()],
                    future_affecting: true,
                })
                .collect(),
            objects: owner_ref
                .state_domain_ids
                .iter()
                .enumerate()
                .map(|(index, domain)| StateObject {
                    id: id(&format!("zz-packet-host-object-{index}")),
                    node_ids: vec![descriptor.id.clone()],
                    future_affecting: true,
                    state: ObjectState::Mutable {
                        domain_id: domain.clone(),
                    },
                })
                .collect(),
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
            inventory_proof_ref: proof,
        };
        // Every modeled connection itself is inventoried separately in the
        // complete world builder; the three core host state objects stay here.
        ownership.objects.sort_by(|a, b| a.id.cmp(&b.id));
        Self {
            selection: HostSchedulingSelection {
                descriptor,
                binding,
                owner,
                operating_policy,
                guarantees,
                domains,
            },
            ownership,
            content,
        }
    }
}
