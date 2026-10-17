//! Original source grants retain future publications across cuts and cold retries.

use super::*;
use crucible_device::BlockRequest;

#[test]
fn scripted_source_split_cut_and_original_retry_preserve_actual_output_custody() {
    use crate::node_adapters::{ScriptedRequest, ScriptedRequestKind, ScriptedSource};

    let source = ScriptedSource::new(
        ScriptedRequestKind::Block,
        vec![ScriptedRequest {
            time_ps: 10,
            payload: BlockRequest::get_length(77).encode().unwrap(),
        }],
    )
    .unwrap();
    let (mut adapter, record) = model_fixture(HostModel::ScriptedSource(Box::new(source)));
    adapter.arm(&record).unwrap();
    let activation = WorldActivation {
        nodes: std::rc::Rc::from([]),
        preparation: None,
        authority: Rc::new(()),
        record,
    };
    let limit = Position::new(10.into(), 1.into(), Phase::BoundaryControl);
    let evaluation = OperationAdmission {
        token: OperationToken {
            authority: Rc::clone(&activation.authority),
            operation: Id::new("script/evaluate").unwrap(),
            route: adapter.route.clone(),
        },
        request: OperationRequest::ExactRun {
            start: adapter.boundary,
            limit,
            boundary_policy: ExactBoundaryPolicy::HorizonPark,
        },
        activation: activation.clone(),
        inputs: None,
    };
    assert_eq!(adapter.begin_operation(&evaluation), Submission::Accepted);
    let mut context = Context::from_waker(Waker::noop());
    let Poll::Ready(Ok(evaluated)) = adapter.poll_operation(evaluation.token(), &mut context)
    else {
        panic!("source evaluation failed")
    };
    adapter.validate_outcome(&evaluation, &evaluated).unwrap();
    assert_eq!(evaluated.retained_outputs.len(), 1);
    let observation = evaluated.scheduling.as_ref().unwrap();
    let original = &observation.publications[0];
    assert_eq!(
        original.publication,
        Position::new(10.into(), 1.into(), Phase::Publication)
    );
    assert!(original.publication >= limit);
    assert_eq!(
        original.evaluation,
        Some(Position::new(10.into(), 0.into(), Phase::Reaction))
    );
    assert!(original.causal_parents.is_empty());
    assert!(observation.external_inputs.is_empty());
    assert_eq!(original.native_sequence.get(), 0);
    assert_eq!(
        original.payload_bytes,
        BlockRequest::get_length(77).encode().unwrap()
    );
    let HostModel::ScriptedSource(native) = adapter.model.as_ref().unwrap() else {
        unreachable!()
    };
    assert!(!native.evaluated());
    assert_eq!(native.cursor(), 1);
    let captured_pending = adapter.continuation_bytes().unwrap();
    let script = native.script_bytes().unwrap();
    let snapshot = RuntimeSnapshot {
        terminal: None,
        condition_stop: None,
        schema_version: 1,
        source_activation: activation.record().into(),
        capture_cut: limit,
        capture_ordinal: 1.into(),
        owners: vec![SavedRuntimeOwner {
            identity: adapter.route.owners[0].clone(),
            lifecycle: Lifecycle::Stopped,
            operation: None,
            domains: adapter
                .binding
                .compatibility
                .execution_owner
                .state_domain_ids
                .clone(),
        }],
        operations: vec![SavedRuntimeOperation {
            operation: evaluation.token().operation().clone(),
            route: adapter.route.clone(),
            request: evaluation.request().clone(),
            input_batch: None,
            result: SavedRuntimeResult::Complete(evaluated.clone()),
            close_submission: None,
            submission_effects: None,
            scheduling_commit: None,
        }],
        inputs: Vec::new(),
    };
    let captured = adapter
        .capture_host_continuation(&activation, &snapshot, 1_048_576)
        .unwrap();
    assert_eq!(captured.state().bytes, captured_pending);
    assert!(matches!(
        adapter.begin_operation(&evaluation),
        Submission::Refused(_)
    ));
    let Poll::Ready(Ok(evaluation_retry)) =
        adapter.poll_operation(evaluation.token(), &mut context)
    else {
        panic!("source original evaluation retry failed")
    };
    assert_eq!(evaluation_retry, evaluated);
    assert_eq!(adapter.continuation_bytes().unwrap(), captured_pending);

    let publication = OperationAdmission {
        token: OperationToken {
            authority: Rc::clone(&activation.authority),
            operation: Id::new("script/publish").unwrap(),
            route: adapter.route.clone(),
        },
        request: OperationRequest::BoundarySettle {
            start: limit,
            limit: Position::new(11.into(), 0.into(), Phase::BoundaryControl),
        },
        activation: activation.clone(),
        inputs: None,
    };
    assert!(matches!(
        adapter.begin_operation(&publication),
        Submission::Refused(_)
    ));
    adapter
        .acknowledge_publication(evaluation.token(), &evaluated.retained_outputs)
        .unwrap();
    assert_eq!(adapter.begin_operation(&publication), Submission::Accepted);
    let Poll::Ready(Ok(published)) = adapter.poll_operation(publication.token(), &mut context)
    else {
        panic!("source publication failed")
    };
    adapter.validate_outcome(&publication, &published).unwrap();
    let suffix_observation = published.scheduling.as_ref().unwrap();
    assert!(suffix_observation.publications.is_empty());
    assert_eq!(
        suffix_observation.bounds[0].bound,
        crate::node_scheduling::NativeOutputBound::AfterInstant(u64::MAX.into())
    );
    let captured_published = adapter.continuation_bytes().unwrap();
    assert!(matches!(
        adapter.begin_operation(&publication),
        Submission::Refused(_)
    ));
    let Poll::Ready(Ok(retried)) = adapter.poll_operation(publication.token(), &mut context) else {
        panic!("source retry failed")
    };
    assert_eq!(retried, published);
    assert_eq!(adapter.continuation_bytes().unwrap(), captured_published);

    // Construct two independently owned fresh adapters from the frozen source.
    // No original model or receipt registry is shared.
    for _ in 0..2 {
        let fresh_model = HostModel::ScriptedSource(Box::new(
            ScriptedSource::from_script_bytes(&script).unwrap(),
        ));
        let (graph, _) = crate::node_admission::test_restore_fixture_host_model(
            "scripted_source",
            fresh_model.initialization_bytes(1_048_576).unwrap(),
        );
        let mut restored = HostModelNode::new(
            &graph,
            &Id::new("a").unwrap(),
            fresh_model,
            &ModelQualification,
            HostModelResources::default(),
        )
        .unwrap();
        assert_eq!(
            graph.world_binding_hash(),
            &activation.record().world_binding_hash
        );
        let target = ActivationRecord {
            generation: 2.into(),
            activation_id: Id::new("script/restored").unwrap(),
            world_binding_hash: graph.world_binding_hash().clone(),
            owners: restored.route.owners.clone(),
            boundary: limit,
        };
        let qualifier = ContinuationQualification {
            source: snapshot.clone(),
            native: captured_pending.clone(),
        };
        restored
            .prepare_continuation(&captured_pending, &snapshot, &target, &qualifier)
            .unwrap();
        restored.arm(&target).unwrap();
        let fresh_activation = WorldActivation {
            nodes: std::rc::Rc::from([]),
            preparation: None,
            authority: Rc::new(()),
            record: target,
        };
        let mut fresh_evaluation = evaluation.clone();
        fresh_evaluation.activation = fresh_activation.clone();
        fresh_evaluation.token.authority = Rc::clone(&fresh_activation.authority);
        fresh_evaluation.token.route = restored.route.clone();
        restored
            .install_restored_custody(
                &fresh_activation,
                &snapshot,
                std::slice::from_ref(&fresh_evaluation),
                &[],
            )
            .unwrap();
        let before = restored.continuation_bytes().unwrap();
        let Poll::Ready(Ok(original_retry)) =
            restored.poll_operation(fresh_evaluation.token(), &mut context)
        else {
            panic!("restored source future-publication receipt disappeared")
        };
        let mut rebound_original = evaluated.clone();
        rebound_original.owners = restored.route.owners.clone();
        rebound_original.scheduling.as_mut().unwrap().owners = restored.route.owners.clone();
        assert_eq!(original_retry, rebound_original);
        assert_eq!(restored.continuation_bytes().unwrap(), before);
        let mut suffix = publication.clone();
        suffix.activation = fresh_activation.clone();
        suffix.token.authority = Rc::clone(&fresh_activation.authority);
        suffix.token.route = restored.route.clone();
        assert!(matches!(
            restored.begin_operation(&suffix),
            Submission::Refused(_)
        ));
        restored
            .acknowledge_publication(fresh_evaluation.token(), &original_retry.retained_outputs)
            .unwrap();
        assert_eq!(restored.begin_operation(&suffix), Submission::Accepted);
        let Poll::Ready(Ok(outcome)) = restored.poll_operation(suffix.token(), &mut context) else {
            panic!("restored source publication failed")
        };
        restored.validate_outcome(&suffix, &outcome).unwrap();
        assert!(outcome.scheduling.unwrap().publications.is_empty());
    }
}
