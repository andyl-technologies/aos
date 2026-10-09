//! Direct native CoW and original-prefix tests under synthetic admission.
//!
//! These tests execute real Block and Link models, while their admission fixture
//! remains model-only. The separate ordinary installed pipeline authenticates
//! production enrollment; these records do not qualify a native archive.

// crucible-lint: allow panic-shortcut -- Each assertion checks one original native execution attempt and retained state.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crucible_device::netlink::LinkFaults;
use crucible_device::{BaseImage, BlockDevice, BlockLatency, BlockRequest, BlockResponse, IoCore};

fn block_model() -> HostModel {
    HostModel::Io(Box::new(ScheduledIoNode::new(
        crate::SchedulerNodeId {
            node: crate::NodeId { name: "a".into() },
            kind: crate::SchedulingNodeKind::Disk,
        },
        crate::NodeId { name: "vm".into() },
        crate::DeviceId {
            name: "disk".into(),
        },
        BlockDevice::new(
            IoCore::new(7, 16, 16).unwrap(),
            BaseImage::new(vec![7, 8, 9]),
            BlockLatency::new(1, 1, 1, 1, 0),
        ),
        crate::Seed::from_u64(42),
    )))
}

fn two_original_inputs(
    adapter: &HostModelNode,
    activation: &WorldActivation,
    first: Vec<u8>,
    second: Vec<u8>,
) -> Rc<crate::node_scheduling::RuntimeInputBatch> {
    let original = input_batch(adapter, activation, first, 10);
    let mut batch = original.retained_copy();
    let payload = canonical::content_ref(&second, "application/octet-stream").unwrap();
    let mut delivery = batch.deliveries[0].clone();
    delivery.publication_id = Id::new("native-root/2").unwrap();
    delivery.source_sequence = 1.into();
    delivery.native_sequence = 1.into();
    delivery.publication.microstep = 1.into();
    delivery.delivery.microstep = 1.into();
    delivery.payload = payload.clone();
    delivery.provenance_ref = payload.clone();
    batch.deliveries.push(delivery);
    batch.payloads.push(crate::node_scheduling::InputPayload {
        reference: payload,
        bytes: second,
    });
    batch
        .payloads
        .sort_by(|left, right| left.reference.cmp(&right.reference));
    batch.inventory = canonical::content_ref(
        &canonical::canonical_json(&serde_json::to_value(&batch.deliveries).unwrap()).unwrap(),
        "application/json",
    )
    .unwrap();
    Rc::new(batch)
}

fn check_whole_original_prefix(
    model: HostModel,
    first: Vec<u8>,
    second: Vec<u8>,
) -> OperationOutcome {
    let (mut adapter, record) = model_fixture(model);
    adapter.arm(&record).unwrap();
    let activation = WorldActivation {
        nodes: Rc::from([]),
        preparation: None,
        authority: Rc::new(()),
        record,
    };
    let inputs = two_original_inputs(&adapter, &activation, first, second);
    let acknowledgement = adapter.stage_inputs(&inputs).unwrap();
    adapter
        .validate_input_acknowledgement(&inputs, &acknowledgement)
        .unwrap();
    run_model(&mut adapter, &activation, &inputs, "run/phase-park", 10);
    let native_before = adapter.continuation_bytes().unwrap();
    let model_before = adapter.capture().unwrap();
    let original = OperationAdmission {
        token: OperationToken {
            authority: Rc::clone(&activation.authority),
            operation: Id::new("run/excluded-reaction").unwrap(),
            route: adapter.route.clone(),
        },
        request: OperationRequest::BoundarySettle {
            start: adapter.boundary,
            limit: Position::new(10.into(), 1.into(), Phase::Reaction),
        },
        activation: activation.clone(),
        inputs: Some(Rc::clone(&inputs)),
    };

    let Submission::Refused(refusal) = adapter.begin_operation(&original) else {
        panic!("excluded second reaction did not refuse before the first native effect");
    };
    assert!(
        refusal
            .reason
            .contains("exclusive cut excludes the original input reaction")
    );
    assert_eq!(adapter.capture().unwrap(), model_before);
    assert_eq!(adapter.continuation_bytes().unwrap(), native_before);
    assert_eq!(adapter.staged.as_ref().unwrap().consumed, 0);
    assert!(adapter.failed.is_empty());
    assert!(!adapter.completed.contains_key(original.token.operation()));
    assert_eq!(adapter.stage_inputs(&inputs).unwrap(), acknowledgement);
    adapter
        .validate_input_acknowledgement(&inputs, &acknowledgement)
        .unwrap();

    let mut allowed = original.clone();
    allowed.token.operation = Id::new("run/included-reactions").unwrap();
    allowed.request = OperationRequest::BoundarySettle {
        start: adapter.boundary,
        limit: Position::new(10.into(), 2.into(), Phase::BoundaryControl),
    };
    assert_eq!(adapter.begin_operation(&allowed), Submission::Accepted);
    let mut context = Context::from_waker(Waker::noop());
    let Poll::Ready(Ok(outcome)) = adapter.poll_operation(allowed.token(), &mut context) else {
        panic!("original included reactions did not complete");
    };
    adapter.validate_outcome(&allowed, &outcome).unwrap();
    assert_eq!(
        outcome
            .scheduling
            .as_ref()
            .unwrap()
            .input_progress
            .as_ref()
            .unwrap()
            .consumed
            .len(),
        2
    );
    assert_eq!(adapter.staged.as_ref().unwrap().consumed, 2);
    let consumed = adapter.continuation_bytes().unwrap();
    assert_eq!(
        adapter.poll_operation(allowed.token(), &mut context),
        Poll::Ready(Ok(outcome))
    );
    assert_eq!(adapter.continuation_bytes().unwrap(), consumed);

    run_model(
        &mut adapter,
        &activation,
        &inputs,
        "run/publish-original",
        1_011,
    )
    .1
}

#[test]
fn excluded_second_block_reaction_leaves_first_write_and_full_native_batch_unchanged() {
    let outcome = check_whole_original_prefix(
        block_model(),
        BlockRequest::write(72, 0, vec![42]).encode().unwrap(),
        BlockRequest::read(73, 0, 3).encode().unwrap(),
    );
    let publications = &outcome.scheduling.as_ref().unwrap().publications;
    assert_eq!(publications.len(), 2);
    let responses: Vec<_> = publications
        .iter()
        .map(|publication| BlockResponse::decode(&publication.payload_bytes).unwrap())
        .collect();
    assert_eq!(responses[0].request_id, 72);
    assert_eq!(responses[1].request_id, 73);
    assert_eq!(responses[1].data, vec![42, 8, 9]);
}

#[test]
fn excluded_second_link_reaction_leaves_first_frame_and_native_queue_unchanged() {
    let outcome = check_whole_original_prefix(
        HostModel::Link(Box::new(
            NetLink::new(7, 20, 1, LinkFaults::none()).unwrap(),
        )),
        vec![1, 2],
        vec![3, 4],
    );
    let publications = &outcome.scheduling.as_ref().unwrap().publications;
    assert_eq!(publications.len(), 2);
    assert_eq!(publications[0].payload_bytes, vec![1, 2]);
    assert_eq!(publications[1].payload_bytes, vec![3, 4]);
}
