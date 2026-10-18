//! Builds source-selected host ownership data for the actual common scheduler.
//!
//! The factory will authenticate these records and retain its original source.
//! They predict no readiness and select no preservation or execution facet.

// crucible-lint: allow panic-shortcut -- Invalid static test fixture construction is an assertion failure.
#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;

use crucible::node_admission::{
    ObjectState, OwnerCapturePolicy, OwnershipPolicy, StateDomain, StateObject,
};
use crucible::node_contract::{
    HostSchedulingConnectionDomain, HostSchedulingDomains, HostSchedulingSelection,
    host_scheduling_complete_owner_configuration, host_scheduling_complete_owner_definition,
    host_scheduling_complete_owner_preparation_schema,
};
use crucible::node_scheduling::{ExactCeiling, ExecutionPolicy};
use crucible_node_contract::*;
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
        Self::with_capture17_selection(executable, proof, false)
    }

    pub(super) fn new_restored17(executable: ContentRef, proof: ContentRef) -> Self {
        Self::with_capture17_selection(executable, proof, true)
    }

    fn with_capture17_selection(
        executable: ContentRef,
        proof: ContentRef,
        selected17: bool,
    ) -> Self {
        let mut content = BTreeMap::new();
        let definition_bytes = host_scheduling_complete_owner_definition().unwrap();
        let definition = canonical::content_ref(&definition_bytes, "application/json").unwrap();
        content.insert(definition.clone(), definition_bytes);
        let preparation = host_scheduling_complete_owner_preparation_schema().unwrap();
        let continuation =
            crucible::node_contract::host_scheduling_complete_continuation_schema().unwrap();
        // This versioned fixture body must match the actual advertised codec.
        // A future codec change must update these bytes rather than drop its pin.
        let continuation_bytes = canonical::canonical_json(&serde_json::json!({
            "schema":"source-owned.host-scheduling-continuation/2",
            "fields":["schema_version","source","runtime","scheduling","objects"],
            "runtime":"closed original-lineage Runtime7; complete native ancestry and typed original bodies",
            "administration":"separate runtime-original-capture-journal/1 in index3; unchanged Runtime7 and Coordinator7"
        }))
        .unwrap();
        let continuation_reference =
            canonical::content_ref(&continuation_bytes, "application/json").unwrap();
        assert_eq!(
            continuation_reference, continuation.definition,
            "versioned Host2 continuation fixture differs from its actual schema"
        );
        content.insert(continuation_reference, continuation_bytes);
        let mut formats = vec![preparation, continuation];
        if selected17 {
            let schema =
                crucible::node_contract::host_scheduling_restored_continuation_schema17().unwrap();
            let bytes =
                crucible::node_contract::host_scheduling_restored_continuation_definition17()
                    .unwrap();
            schema.definition.verify(&bytes).unwrap();
            content.insert(schema.definition.clone(), bytes);
            formats.push(schema);
            formats
                .sort_by(|left, right| (&left.id, left.version).cmp(&(&right.id, right.version)));
        }
        let domains = HostSchedulingDomains {
            coordinator: id("zz-packet-coordinator-state"),
            connections: (0..2)
                .map(|index| HostSchedulingConnectionDomain {
                    connection: id(&format!("packet-connection-{index}")),
                    domain: id(&format!("zz-packet-link-{index}-state")),
                })
                .collect(),
        };
        let configuration_bytes = host_scheduling_complete_owner_configuration(&domains).unwrap();
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
            capture_scope: CaptureScope::CompleteModel,
            continuation: Continuation::Exact,
            durable_restart: true,
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
        let preservation = crucible::node_contract::host_scheduling_complete_preservation_facet(
            configuration.clone(),
            guarantees_ref.clone(),
        )
        .unwrap();
        let capabilities = CapabilityProfile {
            schema_version: 1,
            facets: vec![preservation.clone()],
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
                    implementation_id: id("source-owned.host-scheduling-owner/2"),
                    artifacts: vec![ArtifactIdentity {
                        id: id("original-host-runtime"),
                        role: id("executable"),
                        content: executable,
                        extensions: Extensions::new(),
                    }],
                    model_definitions: vec![definition.clone()],
                    formats,
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
                    facets: vec![preservation.clone()],
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
                complete_model: true,
                unchanged_cut: true,
                exact_continuation: true,
                durable_restart: true,
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

#[test]
fn explicit17_fixture_emits_definition_and_binding_before_world_birth() {
    let proof = canonical::content_ref(b"inert proof", "text/plain").unwrap();
    let old = Host::new(proof.clone(), proof.clone());
    let new = Host::new_restored17(proof.clone(), proof);
    let old_formats = &old.selection.binding.compatibility.implementation.formats;
    let new_formats = &new.selection.binding.compatibility.implementation.formats;
    assert_eq!(old_formats.len(), 2);
    assert_eq!(new_formats[0], old_formats[0]);
    assert_eq!(new_formats[2], old_formats[1]);
    assert_eq!(new_formats.len(), 3);
    new.selection
        .binding
        .compatibility
        .implementation
        .validate()
        .unwrap();
    assert!(new.content.contains_key(&new_formats[1].definition));
    assert_ne!(
        old.selection.binding.identity().unwrap(),
        new.selection.binding.identity().unwrap()
    );
    assert_eq!(
        new.selection.owner.node_bindings[0].binding_hash,
        new.selection.binding.identity().unwrap()
    );
}
