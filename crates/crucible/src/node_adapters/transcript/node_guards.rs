//! Node-level applicability and original custody regressions using model fixtures.

#![allow(clippy::unwrap_used, clippy::expect_used)] // Failed test invariants deliberately panic.

use super::super::{
    TranscriptArchive,
    tests::{capture, cursor},
};
use super::*;

static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

struct Publisher;
impl ActivationPublisher for Publisher {
    fn publish(&mut self, _: &ActivationRecord) -> PublicationStatus {
        PublicationStatus::Committed
    }
    fn reconcile(&mut self, _: &ActivationRecord) -> PublicationStatus {
        PublicationStatus::Committed
    }
}

fn model() -> (
    TranscriptReplayNode,
    NodeRuntime,
    WorldActivation,
    OperationAdmission,
) {
    // This is a behavioral model, not native qualification. The model runtime
    // issues genuine opaque activation/token identities; direct node construction
    // isolates guards without claiming an installed physical-source profile.
    let capture = capture();
    let path = std::env::temp_dir().join(format!(
        "crucible-transcript-guard-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let archive = TranscriptArchive::open(&path, capture.transcript().limits.clone()).unwrap();
    let source = archive.persist(capture).unwrap();
    drop(archive);
    std::fs::remove_dir_all(path).unwrap();
    let (graph, _) = crate::node_admission::test_fixture_isolated_execution(false);
    let mut owners: Vec<_> = graph
        .node_ids()
        .map(|node| {
            let binding = graph.binding(node).unwrap();
            OwnerIdentity {
                owner: binding.compatibility.execution_owner.id.clone(),
                incarnation: binding.authority.incarnation_id.clone(),
                generation: binding.authority.owner_generation,
            }
        })
        .collect();
    owners.sort();
    owners.dedup();
    let record = ActivationRecord {
        generation: 1.into(),
        activation_id: id("model/activation"),
        world_binding_hash: graph.world_binding_hash().clone(),
        owners,
        boundary: source.transcript().origin.activation.boundary,
    };
    let mut runtime = NodeRuntime::new(
        &graph,
        crate::node_contract::test_nodes(&graph),
        record,
        RuntimeLimits::default(),
        crate::node_contract::test_custody_slot(),
    )
    .unwrap_or_else(|failure| panic!("model runtime preparation failed: {}", failure.error));
    runtime.arm_all().unwrap();
    let activation = runtime.activate(&mut Publisher).unwrap();
    let route = source.transcript().origin.route.clone();
    let request = OperationRequest::ExactRun {
        start: activation.record().boundary,
        limit: Position::new(
            50.into(),
            0.into(),
            crucible_node_contract::Phase::BoundaryControl,
        ),
        boundary_policy: ExactBoundaryPolicy::HorizonPark,
    };
    let token = match runtime
        .begin(
            &activation,
            &route.node,
            id("original/operation"),
            request.clone(),
        )
        .unwrap()
    {
        BeginResult::Accepted(token) => token,
        other => panic!("model original operation refused: {other:?}"),
    };
    let admission = OperationAdmission {
        token,
        request,
        activation: activation.clone(),
        inputs: None,
    };
    let cursor = cursor(source);
    let mut node = TranscriptReplayNode {
        descriptor: graph.descriptor(&route.node).unwrap().clone(),
        binding: graph.binding(&route.node).unwrap().clone(),
        route: route.clone(),
        boundary: activation.record().boundary,
        cursor: Some(cursor),
        facets: vec![FacetKind::ExactExecution, FacetKind::Replay],
        profile: ReplayFacet(id(TRANSCRIPT_REPLAY_PROFILE)),
        thread: std::thread::current().id(),
        ready: None,
        inputs: BTreeMap::new(),
        operations: BTreeMap::new(),
        observations: Vec::new(),
        quarantined: false,
        reclamations: BTreeMap::new(),
        owner_binding_hashes: BTreeMap::new(),
    };
    node.arm(activation.record()).unwrap();
    let outcome = OperationOutcome {
        operation: admission.token().operation().clone(),
        node: route.node,
        owners: route.owners,
        progress: ProgressEvidence::Administrative,
        retained_outputs: vec![id("original/output")],
        scheduling: None,
    };
    node.operations.insert(
        admission.token().operation().clone(),
        ReplayOperation {
            admission: admission.clone(),
            outcome: Some(outcome),
            evidence: Vec::new(),
            acknowledged: false,
            close_submission: None,
        },
    );
    (node, runtime, activation, admission)
}

#[test]
fn changed_ack_inventory_poisoned_branch_cannot_accept_original_ack() {
    let (mut node, _runtime, _activation, original) = model();
    let before = node.boundary;
    assert!(
        node.acknowledge_publication(original.token(), &[id("counterfactual/output")])
            .is_err()
    );
    assert!(node.cursor_snapshot().unwrap().diverged);
    assert!(
        node.acknowledge_publication(original.token(), &[id("original/output")])
            .is_err()
    );
    assert_eq!(node.cursor_snapshot().unwrap().next_record.get(), 0);
    assert_eq!(node.boundary, before);
    assert!(!node.original(original.token()).unwrap().acknowledged);
}

#[test]
fn unrecorded_observation_is_sticky_but_settled_ack_retry_does_not_progress() {
    let (mut node, _runtime, activation, original) = model();
    let outputs = [id("original/output")];
    node.acknowledge_publication(original.token(), &outputs)
        .unwrap();
    let after = node.boundary;
    assert!(node.observe_scheduling(&activation).is_err());
    assert!(node.cursor_snapshot().unwrap().diverged);
    node.acknowledge_publication(original.token(), &outputs)
        .unwrap();
    assert_eq!(node.cursor_snapshot().unwrap().next_record.get(), 1);
    assert_eq!(node.boundary, after);
}

#[test]
fn foreign_cancellation_does_not_taint_but_original_counterfactual_does() {
    let (mut node, _runtime, _activation, original) = model();
    let mut foreign = original.token().clone();
    foreign.authority = Rc::new(());
    assert!(node.request_cancel(&foreign).is_err());
    assert!(!node.cursor_snapshot().unwrap().diverged);
    assert!(node.request_cancel(original.token()).is_err());
    assert!(node.cursor_snapshot().unwrap().diverged);
    assert_eq!(node.cursor_snapshot().unwrap().next_record.get(), 0);
}

#[test]
fn unrecorded_duplicate_begin_retains_original_outcome_and_cursor() {
    let (mut node, _runtime, _activation, original) = model();
    let outcome = node.original(original.token()).unwrap().outcome.clone();
    assert!(matches!(
        node.begin_operation(&original),
        Submission::Refused(_)
    ));
    assert!(node.cursor_snapshot().unwrap().diverged);
    assert_eq!(node.cursor_snapshot().unwrap().next_record.get(), 0);
    assert_eq!(node.original(original.token()).unwrap().outcome, outcome);
}
