//! Checks real Clock codec closure within model-only admission fixtures.

use super::*;

fn stopped_clock() -> (HostModelNode, WorldActivation) {
    let (graph, _) = crate::node_admission::test_fixture_host_clock_execution();
    let node = graph.node_ids().next().unwrap();
    let mut adapter = HostModelNode::new(
        &graph,
        node,
        HostModel::Clock(VirtualClock::new()),
        &ClockQualification,
        HostModelResources::default(),
    )
    .unwrap();
    let record = ActivationRecord {
        generation: 1.into(),
        activation_id: Id::new("closed-clock/model-activation").unwrap(),
        world_binding_hash: graph.world_binding_hash().clone(),
        owners: graph
            .node_ids()
            .map(|node| {
                let binding = graph.binding(node).unwrap();
                OwnerIdentity {
                    owner: binding.compatibility.execution_owner.id.clone(),
                    incarnation: binding.authority.incarnation_id.clone(),
                    generation: binding.authority.owner_generation,
                }
            })
            .collect(),
        boundary: adapter.boundary,
    };
    adapter.arm(&record).unwrap();
    let activation = admission(&adapter, &record, OperationRequest::Capture).activation;
    (adapter, activation)
}

#[test]
fn stopped_clock_returns_exact_declared_bodies_and_rejects_changed_roles() {
    let (mut adapter, activation) = stopped_clock();
    let observation = adapter.observe_scheduling(&activation).unwrap();
    let dependencies = adapter
        .input_provenance_dependencies(
            &activation,
            &observation.proof_ref,
            InputProvenanceLimits::default(),
        )
        .unwrap();
    assert_eq!(dependencies.len(), 2);
    let references: Vec<_> = std::iter::once(observation.proof_ref.clone())
        .chain(dependencies.clone())
        .collect();
    let objects = adapter
        .read_boundary_evidence(&activation, &references, 1 << 20)
        .unwrap();
    assert_eq!(objects, state::state_receipt_objects(&adapter).unwrap());
    adapter
        .validate_boundary_evidence(&activation, &references, &objects)
        .unwrap();
    adapter
        .validate_input_provenance_dependencies(&activation, &observation.proof_ref, &dependencies)
        .unwrap();

    let mut changed = objects.clone();
    changed[1].bytes.push(0);
    assert!(
        adapter
            .validate_boundary_evidence(&activation, &references, &changed)
            .is_err()
    );
    let mut reversed = dependencies;
    reversed.reverse();
    assert!(
        adapter
            .validate_input_provenance_dependencies(&activation, &observation.proof_ref, &reversed)
            .is_err()
    );
    let unknown = canonical::content_ref(b"unowned proof body", "application/json").unwrap();
    assert!(
        adapter
            .read_boundary_evidence(&activation, std::slice::from_ref(&unknown), 1 << 20)
            .is_err()
    );
    assert!(
        adapter
            .input_provenance_dependencies(
                &activation,
                &objects[1].reference,
                InputProvenanceLimits::default()
            )
            .is_err()
    );
}

#[test]
fn clock_proofs_require_original_ownership_complete_credit_and_unchanged_native_value() {
    let (mut adapter, activation) = stopped_clock();
    let observation = adapter.observe_scheduling(&activation).unwrap();
    let objects = state::state_receipt_objects(&adapter).unwrap();
    let complete_bytes = objects
        .iter()
        .map(|object| object.bytes.len())
        .sum::<usize>();
    let mut foreign = activation.clone();
    foreign.record.owners[0].incarnation = Id::new("foreign-incarnation").unwrap();
    assert!(
        adapter
            .input_provenance_dependencies(
                &foreign,
                &observation.proof_ref,
                InputProvenanceLimits::default()
            )
            .is_err()
    );
    assert!(
        adapter
            .input_provenance_dependencies(
                &activation,
                &observation.proof_ref,
                InputProvenanceLimits {
                    maximum_objects: 2,
                    maximum_bytes: complete_bytes
                }
            )
            .is_err()
    );
    assert!(
        adapter
            .input_provenance_dependencies(
                &activation,
                &observation.proof_ref,
                InputProvenanceLimits {
                    maximum_objects: 3,
                    maximum_bytes: complete_bytes - 1
                }
            )
            .is_err()
    );
    assert_eq!(adapter.model.as_ref().unwrap().time_ps().unwrap(), 0);

    let Some(HostModel::Clock(clock)) = adapter.model.as_mut() else {
        panic!("model fixture lost actual Clock")
    };
    clock.advance_to(10).unwrap();
    assert!(
        adapter
            .input_provenance_dependencies(
                &activation,
                &observation.proof_ref,
                InputProvenanceLimits::default()
            )
            .is_err()
    );
    assert_eq!(adapter.model.as_ref().unwrap().time_ps().unwrap(), 10);
}

#[test]
fn nonclosed_clock_and_another_real_host_family_receive_no_clock_codec_fallback() {
    let (mut adapter, activation) = stopped_clock();
    let original = adapter.observe_scheduling(&activation).unwrap().proof_ref;
    adapter
        .pending_causes
        .insert((0, 0, 0), vec![activation.record.boundary]);
    assert!(
        adapter
            .input_provenance_dependencies(&activation, &original, InputProvenanceLimits::default())
            .is_err()
    );
    adapter.pending_causes.clear();
    adapter.quarantined = true;
    assert!(
        adapter
            .read_boundary_evidence(&activation, std::slice::from_ref(&original), 1 << 20)
            .is_err()
    );

    let source = crate::node_adapters::ScriptedSource::new(
        crate::node_adapters::ScriptedRequestKind::Block,
        vec![crate::node_adapters::ScriptedRequest {
            time_ps: 10,
            payload: crucible_device::BlockRequest::get_length(77)
                .encode()
                .unwrap(),
        }],
    )
    .unwrap();
    let (mut scripted, record) = model_fixture(HostModel::ScriptedSource(Box::new(source)));
    scripted.arm(&record).unwrap();
    let activation = admission(&scripted, &record, OperationRequest::Capture).activation;
    let original = scripted.observe_scheduling(&activation).unwrap().proof_ref;
    assert!(
        scripted
            .input_provenance_dependencies(&activation, &original, InputProvenanceLimits::default())
            .is_err()
    );
}
