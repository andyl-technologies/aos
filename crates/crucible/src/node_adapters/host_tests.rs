//! Adversarial tests of real host-model state and opaque operation custody.

// Assertion panics expose changes to original model state and custody contracts.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::task::Waker;

use super::*;

#[path = "host_scripted_tests.rs"]
mod scripted;

struct ClockQualification;

impl HostModelQualification for ClockQualification {
    fn authenticate_model(
        &self,
        model: &HostModel,
        descriptor: &NodeDescriptor,
        _binding: &NodeBinding,
    ) -> Result<(), OperationFailure> {
        // This test is deliberately model-only. It checks the actual value;
        // production qualification additionally measures installed code.
        if matches!(model, HostModel::Clock(_)) && descriptor.roles[0].as_str() == "clock" {
            Ok(())
        } else {
            Err(failure("clock model mismatch"))
        }
    }
}

fn fixture() -> (HostModelNode, ActivationRecord) {
    let (graph, _) = crate::node_admission::test_fixture_host_clocks();
    let node = Id::new("a").unwrap();
    let adapter = HostModelNode::new(
        &graph,
        &node,
        HostModel::Clock(VirtualClock::new()),
        &ClockQualification,
        HostModelResources::default(),
    )
    .unwrap();
    let mut owners = Vec::new();
    for node in graph.node_ids() {
        let binding = graph.binding(node).unwrap();
        owners.push(OwnerIdentity {
            owner: binding.compatibility.execution_owner.id.clone(),
            incarnation: binding.authority.incarnation_id.clone(),
            generation: binding.authority.owner_generation,
        });
    }
    let record = ActivationRecord {
        generation: 1.into(),
        activation_id: Id::new("activation/test").unwrap(),
        world_binding_hash: graph.world_binding_hash().clone(),
        owners,
        boundary: adapter.boundary,
    };
    (adapter, record)
}

fn admission(
    adapter: &HostModelNode,
    record: &ActivationRecord,
    request: OperationRequest,
) -> OperationAdmission {
    OperationAdmission {
        token: OperationToken {
            authority: Rc::new(()),
            operation: Id::new("original/op").unwrap(),
            route: adapter.route.clone(),
        },
        request,
        inputs: None,
        activation: WorldActivation {
            nodes: std::rc::Rc::from([]),
            preparation: None,
            authority: Rc::new(()),
            record: record.clone(),
        },
    }
}

#[test]
fn empty_native_causes_do_not_alias_original_empty_input_inventory() {
    let (adapter, _) = fixture();
    let [receipt, _, causes] = state::state_receipt_objects(&adapter).unwrap();
    let empty_inventory =
        canonical::content_ref(b"[]", "application/vnd.crucible.input-inventory+json").unwrap();

    assert_eq!(
        causes.bytes,
        br#"{"schema":"crucible.host-pending-causes.v1","causes":[]}"#
    );
    assert_ne!(causes.reference.hash, empty_inventory.hash);
    causes.reference.verify(&causes.bytes).unwrap();

    let body: serde_json::Value = serde_json::from_slice(&receipt.bytes).unwrap();
    assert_eq!(
        body["pending_causes"],
        serde_json::to_value(&causes.reference).unwrap()
    );
}

#[test]
fn actual_initial_state_and_authentic_qualification_are_required() {
    let (graph, _) = crate::node_admission::test_fixture_host_clocks();
    let mut moved = VirtualClock::new();
    moved.advance_to(1).unwrap();
    assert!(
        HostModelNode::new(
            &graph,
            &Id::new("a").unwrap(),
            HostModel::Clock(moved),
            &ClockQualification,
            HostModelResources::default()
        )
        .is_err()
    );

    let limits = HostModelResources {
        maximum_capture_bytes: 1,
        ..Default::default()
    };
    assert!(
        HostModelNode::new(
            &graph,
            &Id::new("a").unwrap(),
            HostModel::Clock(VirtualClock::new()),
            &ClockQualification,
            limits
        )
        .is_err()
    );
}

#[test]
fn capture_keeps_exact_bytes_original_authority_and_unchanged_cut() {
    let (mut adapter, record) = fixture();
    let ready = adapter.arm(&record).unwrap();
    adapter.validate_readiness(&record, &ready).unwrap();
    let original = admission(&adapter, &record, OperationRequest::Capture);
    assert_eq!(adapter.begin_operation(&original), Submission::Accepted);
    let mut context = Context::from_waker(Waker::noop());
    let Poll::Ready(Ok(outcome)) = adapter.poll_operation(original.token(), &mut context) else {
        panic!("capture incomplete")
    };
    adapter.validate_outcome(&original, &outcome).unwrap();
    assert_eq!(
        adapter.captured_bytes(original.token()).unwrap(),
        adapter.initial.as_slice()
    );
    assert_eq!(adapter.boundary, record.boundary);

    let mut forged = original.token().clone();
    forged.authority = Rc::new(());
    assert!(adapter.captured_bytes(&forged).is_err());
    assert!(matches!(
        adapter.poll_operation(&forged, &mut context),
        Poll::Ready(Err(_))
    ));
    let mut altered = outcome;
    altered
        .retained_outputs
        .push(Id::new("invented/output").unwrap());
    assert!(adapter.validate_outcome(&original, &altered).is_err());
    assert!(matches!(
        adapter.begin_operation(&original),
        Submission::Refused(_)
    ));
}

#[test]
fn scalar_tick_advance_cannot_impersonate_semantic_execution() {
    let (mut adapter, record) = fixture();
    adapter.arm(&record).unwrap();
    let original = admission(
        &adapter,
        &record,
        OperationRequest::ExactRun {
            start: record.boundary,
            limit: Position::new(100.into(), 0.into(), Phase::BoundaryControl),
            boundary_policy: ExactBoundaryPolicy::HorizonPark,
        },
    );
    assert!(matches!(
        adapter.begin_operation(&original),
        Submission::Refused(_)
    ));
    assert_eq!(adapter.model.as_ref().unwrap().time_ps().unwrap(), 0);
    assert_eq!(
        adapter.facets(),
        &[FacetKind::PhysicalPause, FacetKind::Preservation]
    );
}

#[test]
fn quarantine_reclaims_actual_model_and_authenticates_original_receipt() {
    let (mut adapter, _) = fixture();
    let owner = adapter.route.owners[0].clone();
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(
        adapter.poll_reclamation(&owner, &mut context),
        Poll::Ready(Err(_))
    ));
    adapter.quarantine_resources();
    let Poll::Ready(Ok(receipt)) = adapter.poll_reclamation(&owner, &mut context) else {
        panic!("model unreclaimed")
    };
    assert!(adapter.model.is_none());
    adapter.validate_reclamation(&receipt).unwrap();
    let mut forged = receipt;
    forged.owner.generation = 7.into();
    assert!(adapter.validate_reclamation(&forged).is_err());
}

#[test]
fn network_capture_preserves_future_delivery_and_native_fifo_suffix() {
    use crucible_device::netlink::{
        Frame, FrameDraws, LinkFaults, LinkSnapshot, PastDeliveryPolicy,
    };
    let mut link = NetLink::new(7, 10, 1, LinkFaults::none()).unwrap();
    link.emit(
        &Frame::new(3, 42, vec![1, 2, 3]),
        &FrameDraws::default(),
        PastDeliveryPolicy::FailLoud,
    )
    .unwrap();
    let snapshot = link.snapshot();
    let expected = link.advance_to(13).unwrap();
    let retained = NetLink::restore(&snapshot).unwrap();
    let model = HostModel::Link(Box::new(retained));
    let bytes = model.capture(1024 * 1024).unwrap();
    assert_eq!(bytes, snapshot.canonical_bytes().unwrap());
    assert_eq!(model.time_ps().unwrap(), 0);
    let restored = LinkSnapshot::from_canonical_bytes(&bytes).unwrap();
    let mut replay = NetLink::restore(&restored).unwrap();
    assert_eq!(replay.advance_to(13).unwrap(), expected);
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

#[test]
fn exact_clock_runs_two_real_admitted_half_open_intervals() {
    let (graph, _) = crate::node_admission::test_fixture_host_clock_execution();
    let mut nodes: Vec<Box<dyn SimulationNode>> = Vec::new();
    let mut owners = Vec::new();
    for node in graph.node_ids() {
        let adapter = HostModelNode::new(
            &graph,
            node,
            HostModel::Clock(VirtualClock::new()),
            &ClockQualification,
            HostModelResources::default(),
        )
        .unwrap();
        owners.extend(adapter.route.owners.clone());
        nodes.push(Box::new(adapter));
    }
    let record = ActivationRecord {
        generation: 1.into(),
        activation_id: Id::new("activation/host-exact").unwrap(),
        world_binding_hash: graph.world_binding_hash().clone(),
        owners,
        boundary: Position::new(0.into(), 0.into(), Phase::BoundaryControl),
    };
    let mut runtime = NodeRuntime::new(
        &graph,
        nodes,
        record,
        RuntimeLimits::default(),
        crate::node_contract::test_custody_slot(),
    )
    .ok()
    .unwrap();
    runtime.arm_all().unwrap();
    let activation = runtime.activate(&mut Publisher).unwrap();
    let node = Id::new("a").unwrap();
    runtime.scheduler(&graph, &activation).unwrap();
    let observation = runtime.observe_scheduling(&activation, &node).unwrap();
    runtime
        .scheduler(&graph, &activation)
        .unwrap()
        .accept_boundary_observation(observation)
        .unwrap();
    for end in [100u64, 200] {
        let grant = runtime
            .scheduler(&graph, &activation)
            .unwrap()
            .admit_exact(
                &node,
                Id::new(format!("host-run/{end}")).unwrap(),
                end.into(),
            )
            .unwrap();
        let BeginResult::Accepted(token) = runtime.begin_admitted(grant).unwrap() else {
            panic!("real host clock refused admitted grant")
        };
        let mut context = Context::from_waker(Waker::noop());
        let Poll::Ready(Ok(outcome)) = runtime.poll(&token, &mut context) else {
            panic!("host model did not complete")
        };
        assert_eq!(
            outcome.progress,
            ProgressEvidence::Exact {
                reached: Position::new(end.into(), 0.into(), Phase::BoundaryControl),
                stop: StopReason::HorizonPark
            }
        );
        let native = outcome.scheduling.as_ref().unwrap();
        assert!(native.publications.is_empty());
        assert!(native.external_inputs.is_empty());
        assert_eq!(
            native.bounds[0].bound,
            crate::node_scheduling::NativeOutputBound::AfterInstant(u64::MAX.into())
        );
        let receipt = runtime.scheduling_receipt(&token).unwrap();
        let committed = runtime.commit_scheduling_receipt(receipt).unwrap();
        runtime.acknowledge_scheduled(&token, &committed).unwrap();
    }
    let status = runtime.status(&node).unwrap();
    assert_eq!(status.boundary.unwrap().time_ps.get(), 200);
}

struct ModelQualification;

impl HostModelQualification for ModelQualification {
    fn authenticate_model(
        &self,
        model: &HostModel,
        descriptor: &NodeDescriptor,
        _: &NodeBinding,
    ) -> Result<(), OperationFailure> {
        // The synthetic sealed test graph explicitly trusts the source model;
        // production additionally authenticates installed code and base/tree.
        if descriptor.roles[0].as_str() == model.role() {
            Ok(())
        } else {
            Err(failure("actual model role differs"))
        }
    }
}

fn model_fixture(model: HostModel) -> (HostModelNode, ActivationRecord) {
    let initial = model.initialization_bytes(1_048_576).unwrap();
    let (graph, _) = crate::node_admission::test_fixture_host_model(model.role(), initial);
    let adapter = HostModelNode::new(
        &graph,
        &Id::new("a").unwrap(),
        model,
        &ModelQualification,
        HostModelResources::default(),
    )
    .unwrap();
    let owners = graph
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
    let record = ActivationRecord {
        generation: 1.into(),
        activation_id: Id::new("activation/host-model").unwrap(),
        world_binding_hash: graph.world_binding_hash().clone(),
        owners,
        boundary: adapter.boundary,
    };
    (adapter, record)
}

fn input_batch(
    adapter: &HostModelNode,
    activation: &WorldActivation,
    bytes: Vec<u8>,
    tick: u64,
) -> Rc<crate::node_scheduling::RuntimeInputBatch> {
    use crate::node_scheduling::{InputPayload, RuntimeInputBatch, event::Delivery};
    let payload = canonical::content_ref(&bytes, "application/octet-stream").unwrap();
    let endpoint = adapter.input_endpoint.clone().unwrap();
    let publication = Position::new(tick.into(), 0.into(), Phase::Publication);
    let delivery = Delivery {
        connection_id: None,
        connection_policy_ref: None,
        external_root: Some(endpoint.clone()),
        provenance_ref: payload.clone(),
        publication_id: Id::new("native-root/1").unwrap(),
        producer: adapter.route.node.clone(),
        consumer: adapter.route.node.clone(),
        producer_endpoint: endpoint.clone(),
        consumer_endpoint: endpoint,
        source_sequence: 0.into(),
        native_sequence: 0.into(),
        evaluation: None,
        causal_parents: Vec::new(),
        publication,
        delivery: Position::new(tick.into(), 0.into(), Phase::Delivery),
        payload: payload.clone(),
    };
    let inventory = canonical::content_ref(
        &canonical::canonical_json(&serde_json::to_value(std::slice::from_ref(&delivery)).unwrap())
            .unwrap(),
        "application/json",
    )
    .unwrap();
    Rc::new(RuntimeInputBatch {
        activation: activation.clone(),
        node: adapter.route.node.clone(),
        stage_operation: Id::new("stage/original").unwrap(),
        batch: Id::new("batch/original").unwrap(),
        owners: adapter.route.owners.clone(),
        cutoff: Position::new((tick + 1).into(), 0.into(), Phase::BoundaryControl),
        inventory,
        deliveries: vec![delivery],
        payloads: vec![InputPayload {
            reference: payload,
            bytes,
        }],
    })
}

fn run_model(
    adapter: &mut HostModelNode,
    activation: &WorldActivation,
    input: &Rc<crate::node_scheduling::RuntimeInputBatch>,
    identity: &str,
    limit: u64,
) -> (OperationAdmission, OperationOutcome) {
    let original = OperationAdmission {
        token: OperationToken {
            authority: Rc::clone(&activation.authority),
            operation: Id::new(identity).unwrap(),
            route: adapter.route.clone(),
        },
        request: OperationRequest::ExactRun {
            start: adapter.boundary,
            limit: Position::new(limit.into(), 0.into(), Phase::BoundaryControl),
            boundary_policy: ExactBoundaryPolicy::HorizonPark,
        },
        activation: activation.clone(),
        inputs: Some(Rc::clone(input)),
    };
    assert_eq!(adapter.begin_operation(&original), Submission::Accepted);
    let mut context = Context::from_waker(Waker::noop());
    let Poll::Ready(Ok(outcome)) = adapter.poll_operation(original.token(), &mut context) else {
        panic!("actual host model did not complete")
    };
    adapter.validate_outcome(&original, &outcome).unwrap();
    (original, outcome)
}

fn exercise_half_open_model(model: HostModel, bytes: Vec<u8>, due: u64) -> OperationOutcome {
    let (mut adapter, record) = model_fixture(model);
    adapter.arm(&record).unwrap();
    let activation = WorldActivation {
        nodes: std::rc::Rc::from([]),
        preparation: None,
        authority: Rc::new(()),
        record,
    };
    let input = input_batch(&adapter, &activation, bytes, 10);
    let before = adapter.capture().unwrap();
    let acknowledgement = adapter.stage_inputs(&input).unwrap();
    adapter
        .validate_input_acknowledgement(&input, &acknowledgement)
        .unwrap();
    assert_eq!(
        adapter.capture().unwrap(),
        before,
        "staging mutated the actual model"
    );
    let (_, stopped) = run_model(&mut adapter, &activation, &input, "run/predecessor", 10);
    assert!(
        stopped
            .scheduling
            .as_ref()
            .unwrap()
            .input_progress
            .as_ref()
            .unwrap()
            .consumed
            .is_empty()
    );
    let (_, prepared) = run_model(&mut adapter, &activation, &input, "run/compute", due);
    assert!(
        prepared.retained_outputs.is_empty(),
        "output at exclusive ceiling escaped"
    );
    assert_eq!(
        prepared
            .scheduling
            .as_ref()
            .unwrap()
            .input_progress
            .as_ref()
            .unwrap()
            .consumed
            .len(),
        1
    );
    assert_eq!(adapter.next_local_event(), Some(due));
    let capture: serde_json::Value =
        serde_json::from_slice(&adapter.capture_continuation().unwrap()).unwrap();
    assert_eq!(capture["pending_causes"].as_array().unwrap().len(), 1);
    let (original, published) =
        run_model(&mut adapter, &activation, &input, "run/publish", due + 1);
    let publication = &published.scheduling.as_ref().unwrap().publications[0];
    assert_eq!(
        publication.publication,
        Position::new(due.into(), 1.into(), Phase::Publication)
    );
    assert_eq!(
        publication.evaluation,
        Some(Position::new(due.into(), 0.into(), Phase::Reaction))
    );
    assert_eq!(
        publication.causal_parents,
        vec![Position::new(10.into(), 0.into(), Phase::Delivery)]
    );
    assert!(adapter.next_local_event().is_none());
    let mut changed = published.clone();
    changed.scheduling.as_mut().unwrap().publications[0]
        .payload_bytes
        .push(0);
    assert!(adapter.validate_outcome(&original, &changed).is_err());
    assert!(
        adapter
            .acknowledge_publication(original.token(), &[])
            .is_err()
    );
    adapter
        .acknowledge_publication(original.token(), &published.retained_outputs)
        .unwrap();
    adapter
        .acknowledge_publication(original.token(), &published.retained_outputs)
        .unwrap();
    let references = vec![
        published.scheduling.as_ref().unwrap().proof_ref.clone(),
        publication.payload.clone(),
    ];
    let objects = adapter
        .read_operation_evidence(&original, &references)
        .unwrap();
    adapter
        .validate_operation_evidence(&original, &references, &objects)
        .unwrap();
    assert_eq!(objects[1].bytes, publication.payload_bytes);
    let mut changed_objects = objects.clone();
    changed_objects[0].bytes.push(0);
    assert!(
        adapter
            .validate_operation_evidence(&original, &references, &changed_objects)
            .is_err()
    );
    let foreign =
        canonical::content_ref(b"foreign native receipt", "application/octet-stream").unwrap();
    assert!(
        adapter
            .read_operation_evidence(&original, &[foreign])
            .is_err()
    );
    published
}

#[test]
fn real_block_request_preserves_pending_response_until_half_open_settlement() {
    use crucible_device::{
        BaseImage, BlockDevice, BlockLatency, BlockRequest, BlockResponse, IoCore,
    };
    let device = BlockDevice::new(
        IoCore::new(7, 16, 16).unwrap(),
        BaseImage::new(vec![0xab; 4096]),
        BlockLatency::new(1, 1, 1, 1, 0),
    );
    let model = HostModel::Io(Box::new(ScheduledIoNode::new(
        crate::SchedulerNodeId {
            node: crate::NodeId { name: "a".into() },
            kind: crate::SchedulingNodeKind::Disk,
        },
        crate::NodeId { name: "vm".into() },
        crate::DeviceId {
            name: "disk".into(),
        },
        device,
        crate::Seed::from_u64(42),
    )));
    let outcome =
        exercise_half_open_model(model, BlockRequest::get_length(9).encode().unwrap(), 1010);
    let response =
        BlockResponse::decode(&outcome.scheduling.unwrap().publications[0].payload_bytes).unwrap();
    assert_eq!(response.request_id, 9);
    assert_eq!(response.data, 4096u64.to_le_bytes());
}

#[test]
fn real_network_link_preserves_frame_bytes_and_causal_publication() {
    use crucible_device::netlink::LinkFaults;
    let model = HostModel::Link(Box::new(
        NetLink::new(7, 20, 1, LinkFaults::none()).unwrap(),
    ));
    let outcome = exercise_half_open_model(model, vec![1, 2, 3, 4], 30);
    assert_eq!(
        outcome.scheduling.unwrap().publications[0].payload_bytes,
        vec![1, 2, 3, 4]
    );
}

#[test]
fn host_input_limits_refuse_before_native_model_mutation() {
    use crucible_device::netlink::LinkFaults;
    let model = HostModel::Link(Box::new(
        NetLink::new(7, 20, 1, LinkFaults::none()).unwrap(),
    ));
    let (mut adapter, record) = model_fixture(model);
    adapter.arm(&record).unwrap();
    let activation = WorldActivation {
        nodes: std::rc::Rc::from([]),
        preparation: None,
        authority: Rc::new(()),
        record,
    };
    let before = adapter.capture().unwrap();
    let oversized = input_batch(&adapter, &activation, vec![0; 65], 10);
    assert!(adapter.stage_inputs(&oversized).is_err());
    assert_eq!(adapter.capture().unwrap(), before);
    assert!(adapter.staged.is_none());

    let original = input_batch(&adapter, &activation, vec![1], 10);
    let mut crowded = original.retained_copy();
    crowded.deliveries = (0..3)
        .map(|sequence| {
            let mut delivery = original.deliveries()[0].clone();
            delivery.publication_id = Id::new(format!("input/{sequence}")).unwrap();
            delivery.source_sequence = sequence.into();
            delivery.native_sequence = sequence.into();
            delivery
        })
        .collect();
    assert!(adapter.stage_inputs(&crowded).is_err());
    assert_eq!(adapter.capture().unwrap(), before);
    assert!(adapter.staged.is_none());

    let mut corrupted = original.retained_copy();
    corrupted.payloads[0].bytes.push(0);
    assert!(adapter.stage_inputs(&corrupted).is_err());
    assert_eq!(adapter.capture().unwrap(), before);
    assert!(adapter.staged.is_none());
}

#[test]
fn host_link_refuses_an_uninstalled_native_tick_rate() {
    use crucible_device::netlink::LinkFaults;
    let original = NetLink::new(7, 20, 1, LinkFaults::none()).unwrap();
    let before = original.snapshot();
    let mut snapshot = before.clone();
    snapshot.ticks_per_ns = 50;

    // The native codec rejects the unsupported grid before an adapter or
    // activation can be constructed. The original pending state is untouched.
    assert!(NetLink::restore(&snapshot).is_err());
    assert_eq!(original.snapshot(), before);
}

#[test]
fn real_ninep_negotiation_preserves_complete_session_and_future_reply() {
    use crucible_device::{FsTree, IoCore, NinepDevice, NinepLatency};
    let tree = FsTree::try_new(crucible_device::ninep::tree::Node::Directory {
        children: BTreeMap::new(),
    })
    .unwrap();
    let device = NinepDevice::new(
        IoCore::new(9, 16, 16).unwrap(),
        tree,
        NinepLatency::new(1, 1, 0),
    );
    let model = HostModel::Io(Box::new(ScheduledIoNode::new_ninep(
        crate::SchedulerNodeId {
            node: crate::NodeId { name: "a".into() },
            kind: crate::SchedulingNodeKind::NineP,
        },
        crate::NodeId { name: "vm".into() },
        crate::DeviceId { name: "fs".into() },
        device,
        crate::Seed::from_u64(42),
    )));
    let mut frame = vec![21, 0, 0, 0, 100, 0xff, 0xff];
    frame.extend_from_slice(&4608u32.to_le_bytes());
    frame.extend_from_slice(&8u16.to_le_bytes());
    frame.extend_from_slice(b"9P2000.L");
    let outcome = exercise_half_open_model(model, frame, 1010);
    assert_eq!(
        outcome.scheduling.unwrap().publications[0].payload_bytes[4],
        101
    );
}

struct ContinuationQualification {
    source: RuntimeSnapshot,
    native: Vec<u8>,
}

impl HostModelQualification for ContinuationQualification {
    fn authenticate_model(
        &self,
        model: &HostModel,
        descriptor: &NodeDescriptor,
        binding: &NodeBinding,
    ) -> Result<(), OperationFailure> {
        ModelQualification.authenticate_model(model, descriptor, binding)
    }

    fn authenticate_continuation(
        &self,
        model: &HostModel,
        _: &NodeDescriptor,
        binding: &NodeBinding,
        native: &[u8],
        source: &RuntimeSnapshot,
        target: &ActivationRecord,
    ) -> Result<(), OperationFailure> {
        if native != self.native
            || source != &self.source
            || binding.authority.owner_generation.get() != 2
            || !matches!(model, HostModel::Link(_) | HostModel::ScriptedSource(_))
            || target.generation.get() != 2
        {
            return Err(failure(
                "actual source capture or isolated native lineage unavailable",
            ));
        }
        Ok(())
    }
}

#[test]
fn actual_host_restore_preserves_original_input_and_pending_reply_without_reexecution() {
    use crucible_device::netlink::LinkFaults;
    let fresh_link = || {
        HostModel::Link(Box::new(
            NetLink::new(7, 20, 1, LinkFaults::none()).unwrap(),
        ))
    };
    let (mut original, record) = model_fixture(fresh_link());
    original.arm(&record).unwrap();
    let activation = WorldActivation {
        nodes: std::rc::Rc::from([]),
        preparation: None,
        authority: Rc::new(()),
        record: record.clone(),
    };
    let inputs = input_batch(&original, &activation, vec![4, 3, 2, 1], 10);
    let acknowledgement = original.stage_inputs(&inputs).unwrap();
    let (operation, outcome) = run_model(
        &mut original,
        &activation,
        &inputs,
        "run/original-compute",
        30,
    );
    assert!(outcome.retained_outputs.is_empty());
    let capture = original.continuation_bytes().unwrap();
    let source = RuntimeSnapshot {
        schema_version: 1,
        source_activation: (&record).into(),
        capture_cut: original.boundary,
        capture_ordinal: 1.into(),
        owners: vec![SavedRuntimeOwner {
            identity: original.route.owners[0].clone(),
            lifecycle: Lifecycle::Stopped,
            operation: None,
            domains: original
                .binding
                .compatibility
                .execution_owner
                .state_domain_ids
                .clone(),
        }],
        operations: vec![SavedRuntimeOperation {
            operation: operation.token().operation().clone(),
            route: original.route.clone(),
            request: operation.request().clone(),
            input_batch: Some(inputs.batch().clone()),
            result: SavedRuntimeResult::Complete(outcome.clone()),
            close_submission: None,
            submission_effects: None,
            scheduling_commit: None,
        }],
        inputs: vec![SavedRuntimeInput {
            provenance: None,
            node: original.route.node.clone(),
            stage_operation: inputs.stage_operation().clone(),
            batch: inputs.batch().clone(),
            owners: original.route.owners.clone(),
            cutoff: inputs.cutoff(),
            inventory: inputs.inventory().clone(),
            deliveries: inputs.deliveries().to_vec(),
            payloads: inputs.payloads().to_vec(),
            acknowledgement: Some(acknowledgement),
            failure: None,
            committed: true,
            coordinator_committed: true,
        }],
    };
    let fresh_model = fresh_link();
    let live_capture = original
        .capture_host_continuation(&activation, &source, 1_048_576)
        .unwrap();
    assert_eq!(live_capture.state().bytes, capture);
    assert!(
        live_capture.evidence().iter().any(|object| object.reference
            == source.inputs[0].acknowledgement.as_ref().unwrap().proof_ref)
    );
    assert!(
        live_capture
            .evidence()
            .iter()
            .any(|object| object.reference == source.inputs[0].inventory)
    );
    assert!(
        original
            .capture_host_continuation(&activation, &source, capture.len())
            .is_err()
    );
    let mut false_cut = source.clone();
    false_cut.capture_cut = Position::new(31.into(), 0.into(), Phase::BoundaryControl);
    assert!(
        original
            .capture_host_continuation(&activation, &false_cut, 1_048_576)
            .is_err()
    );
    let inventory = validate_host_continuation(
        &capture,
        &source,
        &original.descriptor,
        &original.binding,
        original.limits,
    )
    .unwrap();
    assert_eq!(inventory.boundary, source.capture_cut);
    let mut native_limits = crate::node_contract::NativeCaptureLimits {
        maximum_record_bytes: 1_048_576,
        maximum_total_record_bytes: 1_048_576,
        maximum_objects: 128,
        maximum_artifact_bytes: 1,
        maximum_total_artifact_bytes: 1,
    };
    let native_capture = original
        .capture_native_continuation(&activation, &source, native_limits)
        .unwrap();
    assert_eq!(native_capture.state().bytes, capture);
    let model_objects: Vec<_> = native_capture
        .evidence()
        .iter()
        .filter(|object| object.reference == inventory.native_model.reference)
        .collect();
    assert_eq!(model_objects.len(), 1);
    assert_eq!(model_objects[0].bytes, inventory.native_model.bytes);
    assert_eq!(live_capture.evidence(), inventory.evidence);

    let charged_bytes = native_capture
        .evidence()
        .iter()
        .fold(native_capture.state().bytes.len(), |total, object| {
            total + object.bytes.len()
        });
    native_limits.maximum_total_record_bytes = charged_bytes - 1;
    assert!(
        original
            .capture_native_continuation(&activation, &source, native_limits)
            .is_err()
    );
    native_limits.maximum_total_record_bytes = charged_bytes;
    native_limits.maximum_objects = native_capture.evidence().len();
    assert!(
        original
            .capture_native_continuation(&activation, &source, native_limits)
            .is_err()
    );
    assert_eq!(original.continuation_bytes().unwrap(), capture);

    assert_eq!(
        inventory.operations,
        vec![operation.token().operation().clone()]
    );
    assert!(
        inventory
            .evidence
            .iter()
            .any(|object| object.reference == outcome.scheduling.as_ref().unwrap().proof_ref)
    );
    let mut incomplete_capture: serde_json::Value = serde_json::from_slice(&capture).unwrap();
    incomplete_capture["operations"][0]["evidence"] = serde_json::json!([]);
    assert!(
        validate_host_continuation(
            &serde_json::to_vec(&incomplete_capture).unwrap(),
            &source,
            &original.descriptor,
            &original.binding,
            original.limits
        )
        .is_err()
    );
    let (graph, _) = crate::node_admission::test_restore_fixture_host_model(
        "network_link",
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
    assert_eq!(graph.world_binding_hash(), &record.world_binding_hash);
    let target = ActivationRecord {
        generation: 2.into(),
        activation_id: Id::new("activation/restored-native-host").unwrap(),
        world_binding_hash: graph.world_binding_hash().clone(),
        owners: restored.route.owners.clone(),
        boundary: source.capture_cut,
    };
    assert!(
        restored
            .prepare_continuation(&capture, &source, &target, &ModelQualification)
            .is_err(),
        "raw saved data self-issued native restore authority"
    );
    let qualification = ContinuationQualification {
        source: source.clone(),
        native: capture.clone(),
    };
    let mut changed_source = source.clone();
    changed_source.inputs[0].payloads[0].bytes.push(0);
    assert!(
        validate_host_continuation(
            &capture,
            &changed_source,
            &original.descriptor,
            &original.binding,
            original.limits
        )
        .is_err()
    );
    assert!(
        restored
            .prepare_continuation(&capture, &changed_source, &target, &qualification)
            .is_err()
    );
    let evidence = restored
        .prepare_continuation(&capture, &source, &target, &qualification)
        .unwrap();
    assert_eq!(evidence.input_acknowledgements.len(), 1);
    assert_eq!(restored.next_local_event(), Some(30));
    restored.arm(&target).unwrap();
    let fresh_activation = WorldActivation {
        nodes: std::rc::Rc::from([]),
        preparation: None,
        authority: Rc::new(()),
        record: target,
    };
    let mut fresh_input = inputs.retained_copy();
    fresh_input.activation = fresh_activation.clone();
    fresh_input.owners = restored.route.owners.clone();
    let fresh_input = Rc::new(fresh_input);
    let mut fresh_operation = operation;
    fresh_operation.activation = fresh_activation.clone();
    fresh_operation.token.authority = Rc::clone(&fresh_activation.authority);
    fresh_operation.token.route = restored.route.clone();
    fresh_operation.inputs = Some(Rc::clone(&fresh_input));
    restored
        .install_restored_custody(
            &fresh_activation,
            &source,
            std::slice::from_ref(&fresh_operation),
            std::slice::from_ref(&fresh_input),
        )
        .unwrap();
    restored
        .validate_input_acknowledgement(&fresh_input, &evidence.input_acknowledgements[0])
        .unwrap();
    let mut rebound_outcome = outcome;
    rebound_outcome.owners = restored.route.owners.clone();
    rebound_outcome.scheduling.as_mut().unwrap().owners = restored.route.owners.clone();
    restored
        .validate_outcome(&fresh_operation, &rebound_outcome)
        .unwrap();
    let mut context = Context::from_waker(Waker::noop());
    assert_eq!(
        restored.poll_operation(fresh_operation.token(), &mut context),
        Poll::Ready(Ok(rebound_outcome))
    );
    let (_, suffix) = run_model(
        &mut restored,
        &fresh_activation,
        &fresh_input,
        "run/original-suffix",
        31,
    );
    let publication = &suffix.scheduling.as_ref().unwrap().publications[0];
    assert_eq!(
        publication.native_sequence.get(),
        0,
        "restoration repeated the original request"
    );
    assert_eq!(publication.payload_bytes, vec![4, 3, 2, 1]);
    assert_eq!(
        suffix
            .scheduling
            .as_ref()
            .unwrap()
            .input_progress
            .as_ref()
            .unwrap()
            .consumed
            .len(),
        1
    );
    assert!(restored.next_local_event().is_none());
}
