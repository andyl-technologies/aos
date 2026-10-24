//! Model-only controls for original preparation, full owners and retained bodies.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- Fixture or custody mismatches must fail these data-only assertions.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::node_adapters::{ScriptedRequest, ScriptedRequestKind, ScriptedSource};

struct ModelPolicy;

impl HostModelQualification for ModelPolicy {
    fn authenticate_model(
        &self,
        model: &HostModel,
        descriptor: &NodeDescriptor,
        _: &NodeBinding,
    ) -> Result<(), OperationFailure> {
        if descriptor.roles.as_slice() == [Id::new(model.role()).unwrap()] {
            Ok(())
        } else {
            Err(failure("synthetic model role differs"))
        }
    }
}

struct SelectedModelPolicy;

impl HostModelQualification for SelectedModelPolicy {
    fn authenticate_model(
        &self,
        model: &HostModel,
        descriptor: &NodeDescriptor,
        binding: &NodeBinding,
    ) -> Result<(), OperationFailure> {
        ModelPolicy.authenticate_model(model, descriptor, binding)
    }

    fn authenticate_initial_owned_model(
        &self,
        model: &HostModel,
        graph: &AdmittedGraph,
        descriptor: &NodeDescriptor,
        binding: &NodeBinding,
    ) -> Result<(), OperationFailure> {
        // This is synthetic model authority, never installed native evidence.
        if graph.descriptor(&descriptor.id) != Some(descriptor)
            || graph.binding(&descriptor.id) != Some(binding)
        {
            return Err(failure("synthetic source graph differs"));
        }
        self.authenticate_model(model, descriptor, binding)
    }
}

fn fixture() -> (HostModelNode, AdmittedGraph, ActivationRecord) {
    let source = ScriptedSource::new(
        ScriptedRequestKind::Block,
        vec![ScriptedRequest {
            time_ps: 10,
            payload: crucible_device::BlockRequest::get_length(9)
                .encode()
                .unwrap(),
        }],
    )
    .unwrap();
    let model = HostModel::ScriptedSource(Box::new(source));
    let initial = model.initialization_bytes(1 << 20).unwrap();
    let (graph, _) = crate::node_admission::test_fixture_host_model(model.role(), initial);
    let node = Id::new("a").unwrap();
    let adapter = HostModelNode::new(
        &graph,
        &node,
        model,
        &ModelPolicy,
        HostModelResources::default(),
    )
    .unwrap();
    let mut owners = graph
        .node_ids()
        .map(|node| {
            let binding = graph.binding(node).unwrap();
            OwnerIdentity {
                owner: binding.compatibility.execution_owner.id.clone(),
                incarnation: binding.authority.incarnation_id.clone(),
                generation: binding.authority.owner_generation,
            }
        })
        .collect::<Vec<_>>();
    owners.sort();
    let record = ActivationRecord {
        generation: 1.into(),
        activation_id: Id::new("activation/original-model").unwrap(),
        world_binding_hash: graph.world_binding_hash().clone(),
        owners,
        boundary: adapter.boundary,
    };
    (adapter, graph, record)
}

#[test]
fn model_qualification_cannot_replace_installed_continuation_refusal() {
    let (adapter, _, target) = fixture();
    let model = adapter.model.as_ref().unwrap();
    let original = RuntimeSnapshot {
        schema_version: 1,
        source_activation: (&target).into(),
        capture_cut: target.boundary,
        capture_ordinal: 0.into(),
        owners: Vec::new(),
        operations: Vec::new(),
        inputs: Vec::new(),
        terminal: None,
        condition_stop: None,
    };
    ModelPolicy
        .authenticate_model(model, &adapter.descriptor, &adapter.binding)
        .unwrap();

    let refusal = continuation::InstalledContinuationRequest {
        model,
        descriptor: &adapter.descriptor,
        binding: &adapter.binding,
        native: &adapter.initial,
        runtime: &original,
        target: &target,
    }
    .authenticate(&ModelPolicy)
    .unwrap_err();
    assert_eq!(refusal.effects, EffectKnowledge::None);
    assert!(refusal.reason.contains("continuation"));
    assert!(adapter.public_model_history.is_none());
    assert!(adapter.prepared_continuation.is_none());
}

#[test]
fn retained_data_capsule_without_native_preparation_cannot_mint_ready_or_owner() {
    let (mut adapter, _, record) = fixture();
    let before = adapter.capture().unwrap();
    let bytes = b"data-only source label".to_vec();
    adapter.public_model_history = Some(continuation::PreservedOwnedModelPreparation {
        original: crate::node_scheduling::InputPayload {
            reference: canonical::content_ref(&bytes, "application/json").unwrap(),
            bytes,
        },
        evidence: Vec::new(),
        target: record.clone(),
        target_credit: 4096,
    });
    adapter.preparation_origin = HostPreparationOrigin::Restored;

    assert!(adapter.arm(&record).is_err());
    assert!(adapter.readiness.is_none());
    assert!(adapter.public_model_preparation.is_none());
    let unattached = ReadyAttestation {
        owners: adapter.route.owners.clone(),
        boundary: adapter.boundary,
        state_inventory: adapter.readiness_inventory.clone(),
        ready_receipt: canonical::content_ref(b"data-only Ready label", "application/json")
            .unwrap(),
    };
    assert!(adapter.prepared_owners(&record, &unattached).is_err());
    assert!(
        adapter
            .validate_initial_preparation(&record, &unattached)
            .is_err()
    );
    assert_eq!(adapter.capture().unwrap(), before);
}

#[test]
fn ordinary_model_qualification_does_not_select_public_preparation() {
    let (mut adapter, graph, _) = fixture();
    let before = adapter.capture().unwrap();
    assert!(
        adapter
            .qualify_public_initial_owned_model(&graph, &ModelPolicy)
            .is_err()
    );
    assert!(adapter.public_model_preparation.is_none());
    assert!(adapter.readiness.is_none());
    assert_eq!(adapter.capture().unwrap(), before);
}

#[test]
fn original_ready_mapping_rechecks_full_owner_and_body_custody() {
    let (mut adapter, graph, record) = fixture();
    adapter
        .qualify_public_initial_owned_model(&graph, &SelectedModelPolicy)
        .unwrap();
    let mut foreign = record.clone();
    foreign.owners[0].incarnation = Id::new("foreign/original-owner").unwrap();
    assert!(adapter.arm(&foreign).is_err());
    assert!(adapter.readiness.is_none());

    let ready = adapter.arm(&record).unwrap();
    let owners = adapter.prepared_owners(&record, &ready).unwrap().unwrap();
    adapter
        .validate_prepared_owners(&record, &ready, &owners)
        .unwrap();
    adapter
        .validate_initial_preparation(&record, &ready)
        .unwrap();
    let mut changed = ready.clone();
    changed.ready_receipt = canonical::content_ref(b"changed", "application/json").unwrap();
    assert!(adapter.prepared_owners(&record, &changed).is_err());
    let original_initial = Rc::clone(&adapter.initial);
    adapter.initial = Rc::new(b"changed initialized native state".to_vec());
    assert!(adapter.prepared_owners(&record, &ready).is_err());
    adapter.initial = original_initial;
    adapter
        .public_model_preparation
        .as_mut()
        .unwrap()
        .native_ready_bytes[0] ^= 1;
    assert!(adapter.prepared_owners(&record, &ready).is_err());
    adapter
        .public_model_preparation
        .as_mut()
        .unwrap()
        .native_ready_bytes[0] ^= 1;
    assert_eq!(
        adapter.prepared_owners(&record, &ready).unwrap().unwrap(),
        owners
    );
    assert!(adapter.continuation_bytes().is_err());
}

#[test]
fn original_history_keeps_same_model_and_preparation_after_retained_move() {
    let (mut adapter, graph, record) = fixture();
    adapter
        .qualify_public_initial_owned_model(&graph, &SelectedModelPolicy)
        .unwrap();
    adapter.arm(&record).unwrap();
    let original = adapter.retirement_history(1 << 20).unwrap();
    original[0].reference.verify(&original[0].bytes).unwrap();

    // This is an inert model move, not physical reclamation or release proof.
    adapter.retired_model = adapter.model.take();
    assert_eq!(adapter.retirement_history(1 << 20).unwrap(), original);
    assert!(adapter.continuation_bytes().is_err());
    assert!(
        adapter
            .retirement_history(original[0].bytes.len() - 1)
            .is_err()
    );
    assert_eq!(
        adapter.retirement_history(original[0].bytes.len()).unwrap(),
        original
    );

    adapter
        .public_model_preparation
        .as_mut()
        .unwrap()
        .session_bytes[0] ^= 1;
    assert!(adapter.retirement_history(1 << 20).is_err());
    adapter
        .public_model_preparation
        .as_mut()
        .unwrap()
        .session_bytes[0] ^= 1;
    assert_eq!(adapter.retirement_history(1 << 20).unwrap(), original);
}

#[test]
fn ordinary_unselected_host_cannot_supply_complete_failure_preparation() {
    let (adapter, _, _) = fixture();
    assert!(adapter.retirement_history(1 << 20).is_err());
}

#[test]
fn restored_or_already_armed_model_cannot_mint_original_mapping() {
    let (mut restored, graph, _) = fixture();
    restored.preparation_origin = HostPreparationOrigin::Restored;
    assert!(
        restored
            .qualify_public_initial_owned_model(&graph, &SelectedModelPolicy)
            .is_err()
    );
    assert!(restored.public_model_preparation.is_none());

    let (mut armed, graph, record) = fixture();
    let ready = armed.arm(&record).unwrap();
    assert!(
        armed
            .qualify_public_initial_owned_model(&graph, &SelectedModelPolicy)
            .is_err()
    );
    assert_eq!(armed.readiness.as_ref(), Some(&(record, ready)));
    assert!(armed.public_model_preparation.is_none());
}

#[test]
fn original_session_tiny_credit_refuses_before_owner_retention() {
    let (mut adapter, graph, _) = fixture();
    let before = adapter.capture().unwrap();
    adapter.limits.maximum_capture_bytes = before.len() + 16;

    let error = adapter
        .qualify_public_initial_owned_model(&graph, &SelectedModelPolicy)
        .unwrap_err();

    assert!(
        error
            .reason
            .contains("original preparation serialized budget"),
        "{error:?}"
    );
    assert!(adapter.public_model_preparation.is_none());
    assert!(adapter.readiness.is_none());
    assert_eq!(adapter.capture().unwrap(), before);
}

#[test]
fn readiness_enforces_exact_remaining_original_body_credit() {
    for exact in [false, true] {
        let (mut adapter, graph, record) = fixture();
        adapter
            .qualify_public_initial_owned_model(&graph, &SelectedModelPolicy)
            .unwrap();
        let original = ReadyAttestation {
            owners: adapter.route.owners.clone(),
            boundary: adapter.boundary,
            state_inventory: adapter.readiness_inventory.clone(),
            ready_receipt: adapter.receipt("host-model-owned-inactive-v1").unwrap(),
        };
        let preparation = adapter.public_model_preparation.as_ref().unwrap();
        let required = credit::ready_length(&record, &original, preparation, 1 << 20).unwrap()
            + preparation.session_bytes.len()
            + preparation.native_ready_bytes.len();
        adapter.limits.maximum_capture_bytes = required - usize::from(!exact);

        let result = adapter.arm(&record);

        if exact {
            let ready = result.unwrap();
            assert!(adapter.prepared_owners(&record, &ready).unwrap().is_some());
        } else {
            assert!(
                result
                    .unwrap_err()
                    .reason
                    .contains("original preparation serialized budget")
            );
            assert!(adapter.readiness.is_none());
            assert!(
                adapter
                    .public_model_preparation
                    .as_ref()
                    .unwrap()
                    .ready
                    .is_none()
            );
        }
    }
}
