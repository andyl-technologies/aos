//! Integration tests for the uniform I/O sub-node lifecycle (CS-IO-1).
//!
//! These drive an [`IoCore`] through the in-process double pattern of spec
//! §15.7: construct a sub-node, enqueue requests, advance the clock, and assert
//! the emitted responses and their delivery icounts — with no real QEMU. The
//! `EchoDevice` below is a minimal [`IoSubNode`] whose `compute` deliberately
//! consults a host-timing-like counter to prove that COMPUTE wall-clock never
//! leaks into the delivery icount or any payload byte ([IO-4], [IO-31]).

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test fixture construction must fail loudly.
#![allow(clippy::expect_used)]

use std::collections::BTreeMap;
use std::fmt::Debug;

use crucible_device::{
    AdditionalCompletion, AffineLatency, BaseImage, BlockDevice, BlockLatency, BlockRequest,
    BlockResponse, BlockStatus, ComputedResponse, DeviceError, FsTree, IoCore, IoCoreSnapshot,
    IoCoreSnapshotCodecError, IoSubNode, NinepDevice, NinepLatency, Node, Request, Response,
    ResponseStatus,
};
use crucible_shmem::{
    FrameEntry, KIND_9P, KIND_BLK, KIND_VM, NodeSlot, RingHeader, SLOT_9P_IO, SLOT_BLK_IO,
    SpscRingError,
};

#[path = "io_subnode_lifecycle/tail_cases.rs"]
mod tail_cases;

use crucible_device::ninep::codec;

/// Unwraps a result in tests, panicking with the error on failure.
fn ok<T, E: Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| panic!("expected Ok, got {error:?}"))
}

/// A minimal echo device: the response payload is the request payload reversed.
///
/// `host_compute_ticks` simulates host wall-clock advancing during COMPUTE; it
/// is read on every `compute` call to prove it influences no observable output.
struct EchoDevice {
    latency: AffineLatency,
    host_compute_ticks: u64,
}

impl EchoDevice {
    fn new(base_ns: u64, per_byte_ns: u64) -> Self {
        Self {
            latency: AffineLatency::new(base_ns, per_byte_ns),
            host_compute_ticks: 0,
        }
    }
}

impl IoSubNode for EchoDevice {
    type Latency = AffineLatency;
    type ComputeCheckpoint = u64;

    fn latency_model(&self) -> &Self::Latency {
        &self.latency
    }

    fn compute_checkpoint(&self) -> Self::ComputeCheckpoint {
        self.host_compute_ticks
    }

    fn restore_compute_checkpoint(&mut self, checkpoint: Self::ComputeCheckpoint) {
        self.host_compute_ticks = checkpoint;
    }

    fn compute(&mut self, request: &Request) -> Result<ComputedResponse, DeviceError> {
        // Simulate variable host wall-clock spent in COMPUTE. This MUST NOT
        // affect the delivery icount or the payload.
        self.host_compute_ticks += 1 + u64::from(request.request_id);
        let mut payload = request.payload.clone();
        payload.reverse();
        Ok(ComputedResponse::primary(Response::new(
            request.request_id,
            ResponseStatus::Ok,
            payload,
        )))
    }
}

struct PerturbedCompletionDevice {
    latency: AffineLatency,
    retain_primary: bool,
    additional_latency_nanos: u64,
    duplicate_gap_nanos: u64,
    compute_calls: u64,
}

impl IoSubNode for PerturbedCompletionDevice {
    type Latency = AffineLatency;
    type ComputeCheckpoint = u64;

    fn latency_model(&self) -> &Self::Latency {
        &self.latency
    }

    fn compute_checkpoint(&self) -> Self::ComputeCheckpoint {
        self.compute_calls
    }

    fn restore_compute_checkpoint(&mut self, checkpoint: Self::ComputeCheckpoint) {
        self.compute_calls = checkpoint;
    }

    fn compute(&mut self, request: &Request) -> Result<ComputedResponse, DeviceError> {
        self.compute_calls += 1;
        let response = Response::new(
            request.request_id,
            ResponseStatus::Ok,
            request.payload.clone(),
        );
        Ok(ComputedResponse {
            primary: (!self.retain_primary).then(|| response.clone()),
            additional_latency_nanos: self.additional_latency_nanos,
            additional: vec![AdditionalCompletion {
                gap_nanos: self.duplicate_gap_nanos,
                response,
            }],
        })
    }
}

const SHIFT: u8 = 8;
const NODE: u32 = 7;

fn drive(requests: &[Request]) -> Vec<(u64, Response)> {
    // Returns (delivery_icount, response) in delivery order.
    let mut core = ok(IoCore::new(SHIFT, NODE, 16, 16));
    let mut device = EchoDevice::new(1000, 4);

    for request in requests {
        ok(core.enqueue_request(request.clone()));
    }
    ok(core.process_inbox(&mut device));

    let mut delivered = Vec::new();
    // Advance step by step to each pending event, draining as we go.
    while let Some(next) = core.next_exact_local_event() {
        let delivered_count = ok(core.advance_to(next));
        assert!(
            delivered_count >= 1,
            "advancing to an event must deliver it"
        );
        while let Some(pending) = core.pop_response() {
            delivered.push((pending.delivery_icount(), pending.response));
        }
    }
    delivered
}

fn sample_requests() -> Vec<Request> {
    vec![
        Request::new(0, 0, b"alpha".to_vec()),
        Request::new(5, 1, b"bravo-bravo".to_vec()),
        Request::new(2, 2, b"c".to_vec()),
        Request::new(10, 3, b"delta".to_vec()),
    ]
}

fn frame(delivery_icount: u64, src_node: u32, seq: u32, payload: &[u8]) -> FrameEntry {
    ok(FrameEntry::new(delivery_icount, src_node, seq, payload))
}

fn frame_payload(frame: &FrameEntry) -> Vec<u8> {
    ok(frame.payload()).to_vec()
}

fn block_device(inbox_capacity: u64, outbox_capacity: u64) -> BlockDevice {
    let src = SLOT_BLK_IO as u32;
    let core = ok(IoCore::new(SHIFT, src, inbox_capacity, outbox_capacity));
    let base = BaseImage::new((0..4096u32).map(|value| (value % 251) as u8).collect());
    BlockDevice::new(core, base, BlockLatency::default())
}

fn sample_tree() -> FsTree {
    let mut root = BTreeMap::new();
    root.insert(
        "alpha".to_string(),
        Node::File {
            content: b"alpha".to_vec(),
        },
    );
    FsTree::try_new(Node::Directory { children: root }).expect("test 9p tree components are valid")
}

fn ninep_frame(msg_type: u8, tag: u16, body: &[u8]) -> Vec<u8> {
    let size = (7 + body.len()) as u32;
    let mut frame = Vec::new();
    frame.extend_from_slice(&size.to_le_bytes());
    frame.push(msg_type);
    frame.extend_from_slice(&tag.to_le_bytes());
    frame.extend_from_slice(body);
    frame
}

fn string_bytes(value: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(value.len() as u16).to_le_bytes());
    bytes.extend_from_slice(value.as_bytes());
    bytes
}

fn tversion(tag: u16, msize: u32, version: &str) -> Vec<u8> {
    let mut body = msize.to_le_bytes().to_vec();
    body.extend_from_slice(&string_bytes(version));
    ninep_frame(codec::TVERSION, tag, &body)
}

#[test]
fn compute_then_deliver_pins_delivery_to_virtual_time() {
    // base_ns=1000, per_byte=4, shift=8 (256 ns/icount).
    // request at icount t with payload len L:
    //   completion_ns = t*256 + 1000 + 4*L ; delivery = ceil(completion_ns/256)
    let core = ok(IoCore::new(SHIFT, NODE, 16, 16));
    let latency = AffineLatency::new(1000, 4);

    let req = Request::new(0, 0, b"alpha".to_vec()); // L=5
    // completion_ns = 0 + 1000 + 20 = 1020 ; ceil(1020/256) = 4
    assert_eq!(ok(core.compute_delivery_icount(&req, &latency)), 4);

    let req = Request::new(5, 1, vec![0u8; 11]); // t=5, L=11
    // completion_ns = 5*256 + 1000 + 44 = 1280+1044 = 2324 ; ceil(2324/256)=10
    assert_eq!(ok(core.compute_delivery_icount(&req, &latency)), 10);
}

#[test]
fn computed_dynamic_delay_and_duplicates_enter_exact_delivery_order() {
    let mut core = ok(IoCore::new(SHIFT, NODE, 4, 4));
    let mut device = PerturbedCompletionDevice {
        latency: AffineLatency::new(256, 0),
        retain_primary: false,
        additional_latency_nanos: 257,
        duplicate_gap_nanos: 256,
        compute_calls: 0,
    };
    ok(core.enqueue_request(Request::new(0, 9, b"payload".to_vec())));
    ok(core.process_inbox(&mut device));

    let snapshot = core.snapshot();
    assert_eq!(snapshot.inflight.len(), 2);
    assert_eq!(snapshot.inflight[0].delivery_icount(), 3);
    assert_eq!(snapshot.inflight[1].delivery_icount(), 4);
    assert_eq!(snapshot.inflight[0].response, snapshot.inflight[1].response);
}

#[test]
fn dynamic_delay_is_added_before_the_single_ceil_conversion() {
    let mut core = ok(IoCore::new(SHIFT, NODE, 4, 4));
    let mut device = PerturbedCompletionDevice {
        latency: AffineLatency::new(1, 0),
        retain_primary: false,
        additional_latency_nanos: 255,
        duplicate_gap_nanos: 256,
        compute_calls: 0,
    };
    ok(core.enqueue_request(Request::new(0, 10, b"payload".to_vec())));
    ok(core.process_inbox(&mut device));

    let snapshot = core.snapshot();
    assert_eq!(snapshot.inflight[0].delivery_icount(), 1);
}

#[test]
fn late_duplicate_overflow_rolls_back_device_and_inflight_state() {
    let mut core = ok(IoCore::new(SHIFT, NODE, 4, 4));
    let mut device = PerturbedCompletionDevice {
        latency: AffineLatency::new(1, 0),
        retain_primary: false,
        additional_latency_nanos: 0,
        duplicate_gap_nanos: u64::MAX,
        compute_calls: 0,
    };
    ok(core.enqueue_request(Request::new(0, 11, b"payload".to_vec())));
    assert!(matches!(
        core.process_inbox(&mut device),
        Err(DeviceError::CompletionOverflow { .. })
    ));
    assert_eq!(device.compute_calls, 0);
    assert!(core.snapshot().inflight.is_empty());
}

#[test]
fn additional_completion_without_primary_fails_closed() {
    let mut core = ok(IoCore::new(SHIFT, NODE, 4, 4));
    let mut device = PerturbedCompletionDevice {
        latency: AffineLatency::new(256, 0),
        retain_primary: true,
        additional_latency_nanos: 257,
        duplicate_gap_nanos: 256,
        compute_calls: 0,
    };
    ok(core.enqueue_request(Request::new(0, 9, b"payload".to_vec())));
    assert_eq!(
        core.process_inbox(&mut device),
        Err(DeviceError::InvalidComputedResponse)
    );
    assert!(core.snapshot().inflight.is_empty());
}

#[test]
fn next_exact_local_event_is_inflight_head() {
    let mut core = ok(IoCore::new(SHIFT, NODE, 16, 16));
    let mut device = EchoDevice::new(1000, 4);
    for request in sample_requests() {
        ok(core.enqueue_request(request));
    }
    ok(core.process_inbox(&mut device));

    // The smallest delivery icount across all four requests is the head.
    let head = ok(core
        .next_exact_local_event()
        .ok_or("expected an in-flight head"));
    // Compute the minimum independently.
    let latency = AffineLatency::new(1000, 4);
    let probe = ok(IoCore::new(SHIFT, NODE, 16, 16));
    let min = ok(sample_requests()
        .iter()
        .map(|r| probe.compute_delivery_icount(r, &latency))
        .collect::<Result<Vec<u64>, _>>())
    .into_iter()
    .min();
    assert_eq!(Some(head), min);
}

#[test]
fn advance_to_drains_only_due_responses() {
    let mut core = ok(IoCore::new(SHIFT, NODE, 16, 16));
    let mut device = EchoDevice::new(1000, 4);
    for request in sample_requests() {
        ok(core.enqueue_request(request));
    }
    ok(core.process_inbox(&mut device));

    let head = ok(core
        .next_exact_local_event()
        .ok_or("expected an in-flight head"));
    // Advance to exactly the head: only responses due at `head` come out.
    let delivered = ok(core.advance_to(head));
    assert!(delivered >= 1);
    while let Some(p) = core.pop_response() {
        assert!(p.delivery_icount() <= head);
    }
    // There is still future work pending.
    let next = ok(core.next_exact_local_event().ok_or("expected future work"));
    assert!(next > head);
}

#[test]
fn responses_emerge_in_delivery_icount_order() {
    let delivered = drive(&sample_requests());
    let icounts: Vec<u64> = delivered.iter().map(|(ic, _)| *ic).collect();
    let mut sorted = icounts.clone();
    sorted.sort_unstable();
    assert_eq!(icounts, sorted, "responses must emerge in delivery order");
    assert_eq!(delivered.len(), 4);
}

#[test]
fn run_twice_is_byte_identical() {
    let first = drive(&sample_requests());
    let second = drive(&sample_requests());
    assert_eq!(first, second);
}

#[test]
fn host_compute_timing_does_not_change_outputs() {
    // Drive once normally.
    let baseline = drive(&sample_requests());

    // Drive again but burn arbitrary host-compute ticks first. Because the
    // device's compute ticks are not consulted for delivery or payload, the
    // observable result is identical.
    let mut core = ok(IoCore::new(SHIFT, NODE, 16, 16));
    let mut device = EchoDevice::new(1000, 4);
    device.host_compute_ticks = 999_999; // arbitrary host wall-clock skew
    for request in sample_requests() {
        ok(core.enqueue_request(request));
    }
    ok(core.process_inbox(&mut device));
    let mut skewed = Vec::new();
    while let Some(next) = core.next_exact_local_event() {
        ok(core.advance_to(next));
        while let Some(p) = core.pop_response() {
            skewed.push((p.delivery_icount(), p.response));
        }
    }
    assert_eq!(baseline, skewed);
}

#[test]
fn snapshot_restore_round_trips_mid_flight() {
    let mut core = ok(IoCore::new(SHIFT, NODE, 16, 16));
    let mut device = EchoDevice::new(1000, 4);
    for request in sample_requests() {
        ok(core.enqueue_request(request));
    }
    ok(core.process_inbox(&mut device));

    // Deliver the first event, leaving responses in flight.
    let head = ok(core
        .next_exact_local_event()
        .ok_or("expected an in-flight head"));
    ok(core.advance_to(head));

    let snapshot = core.snapshot();
    let snapshot_bytes = ok(snapshot.canonical_bytes());
    let snapshot = ok(IoCoreSnapshot::from_canonical_bytes(&snapshot_bytes));
    assert_eq!(ok(snapshot.canonical_bytes()), snapshot_bytes);
    let mut trailing = snapshot_bytes;
    trailing.push(0);
    assert_eq!(
        IoCoreSnapshot::from_canonical_bytes(&trailing),
        Err(IoCoreSnapshotCodecError::Noncanonical)
    );
    let mut restored = ok(IoCore::restore(&snapshot));
    assert_eq!(restored.snapshot(), snapshot);

    // Draining the original and the restored core must produce identical tails.
    fn drain(core: &mut IoCore) -> Vec<(u64, Response)> {
        let mut out = Vec::new();
        while let Some(p) = core.pop_response() {
            out.push((p.delivery_icount(), p.response));
        }
        while let Some(next) = core.next_exact_local_event() {
            ok(core.advance_to(next));
            while let Some(p) = core.pop_response() {
                out.push((p.delivery_icount(), p.response));
            }
        }
        out
    }
    assert_eq!(drain(&mut core), drain(&mut restored));
}

#[test]
fn full_inbox_blocks_producer_without_drop() {
    let mut core = ok(IoCore::new(SHIFT, NODE, 2, 16));
    ok(core.enqueue_request(Request::new(0, 0, vec![])));
    ok(core.enqueue_request(Request::new(0, 1, vec![])));
    // Inbox capacity 2 is now full: the producer must block, never drop. The
    // rejected request is handed back inside the error for a lossless re-push.
    let blocked = Request::new(0, 2, vec![]);
    let rejected = match core.enqueue_request(blocked.clone()) {
        Err(error) => error,
        Ok(()) => panic!("a full inbox must reject the request"),
    };
    assert_eq!(rejected.item, blocked, "the exact request is handed back");

    // Draining the inbox frees space; re-pushing the handed-back request lands
    // without cloning.
    let mut device = EchoDevice::new(1000, 4);
    ok(core.process_inbox(&mut device));
    ok(core.enqueue_request(rejected.into_item()));
}

#[test]
fn block_shmem_lifecycle_uses_real_rings_and_wakes() {
    let vm_slot_id = 0;
    let block_slot_id = SLOT_BLK_IO as u32;
    let vm_slot = NodeSlot::new(KIND_VM);
    let block_slot = NodeSlot::new(KIND_BLK);
    let inbox = RingHeader::new();
    let mut inbox_entries = vec![FrameEntry::default(); 1];
    let outbox = RingHeader::new();
    let mut outbox_entries = vec![FrameEntry::default(); 2];
    let mut device = block_device(4, 4);

    let first = BlockRequest::read(1, 0, 4);
    let second = BlockRequest::read(2, 4, 4);
    let first_frame = frame(0, vm_slot_id, 10, &ok(first.encode()));
    let second_frame = frame(1, vm_slot_id, 11, &ok(second.encode()));
    ok(inbox.enqueue(&mut inbox_entries, &first_frame));
    assert_eq!(
        inbox.enqueue(&mut inbox_entries, &second_frame),
        Err(SpscRingError::QueueFull { capacity: 1 })
    );

    let first_process = ok(device.process_shmem_inbox(&inbox, &inbox_entries, &vm_slot));
    assert_eq!(first_process.processed, 1);
    assert_eq!(first_process.producer_wakes.len(), 1);
    assert_eq!(vm_slot.snapshot().wake_signal, 1);
    assert_eq!(inbox.dequeue(&inbox_entries), Ok(None));

    ok(inbox.enqueue(&mut inbox_entries, &second_frame));
    let second_process = ok(device.process_shmem_inbox(&inbox, &inbox_entries, &vm_slot));
    assert_eq!(second_process.processed, 1);
    assert_eq!(vm_slot.snapshot().wake_signal, 2);

    let limit = ok(device
        .core()
        .snapshot()
        .inflight
        .iter()
        .map(|pending| pending.delivery_icount())
        .max()
        .ok_or("expected in-flight block responses"));
    let delivered = ok(device.advance_to_shmem(limit, &outbox, &mut outbox_entries, &vm_slot));
    assert_eq!(delivered.delivered, 2);
    assert!(delivered.consumer_wake.is_some());
    assert_eq!(vm_slot.snapshot().wake_signal, 3);

    let first_out = ok(IoCore::dequeue_shmem_frame_and_wake_producer(
        &outbox,
        &outbox_entries,
        &block_slot,
    ))
    .frame
    .unwrap_or_else(|| panic!("first response frame should be present"));
    let second_out = ok(IoCore::dequeue_shmem_frame_and_wake_producer(
        &outbox,
        &outbox_entries,
        &block_slot,
    ))
    .frame
    .unwrap_or_else(|| panic!("second response frame should be present"));
    assert_eq!(block_slot.snapshot().wake_signal, 2);
    assert_eq!(first_out.src_node, block_slot_id);
    assert_eq!(second_out.src_node, block_slot_id);

    let first_response = ok(BlockResponse::decode(&frame_payload(&first_out)));
    let second_response = ok(BlockResponse::decode(&frame_payload(&second_out)));
    assert_eq!(first_response.status, BlockStatus::Ok);
    assert_eq!(second_response.status, BlockStatus::Ok);
    assert_eq!(first_response.request_id, 1);
    assert_eq!(second_response.request_id, 2);
    assert_eq!(first_response.data, vec![0, 1, 2, 3]);
    assert_eq!(second_response.data, vec![4, 5, 6, 7]);
}

#[test]
fn block_shmem_single_request_compute_preserves_next_head_for_dispatch() {
    let vm_slot = NodeSlot::new(KIND_VM);
    let inbox = RingHeader::new();
    let mut inbox_entries = vec![FrameEntry::default(); 4];
    let mut device = block_device(4, 4);
    let first = frame(10, 0, 0, &ok(BlockRequest::read(1, 0, 4).encode()));
    let second = frame(20, 0, 1, &ok(BlockRequest::read(2, 4, 4).encode()));
    ok(inbox.enqueue(&mut inbox_entries, &first));
    ok(inbox.enqueue(&mut inbox_entries, &second));

    let processed = ok(device.process_one_shmem_request(&inbox, &inbox_entries, &vm_slot));
    assert_eq!(processed.processed, 1);
    assert_eq!(processed.first_request_icount, Some(10));
    assert_eq!(
        ok(inbox.peek(&inbox_entries)).map(|frame| frame.delivery_icount),
        Some(20),
        "the next request must remain observable for its own pre-dispatch pin"
    );

    let processed = ok(device.process_one_shmem_request(&inbox, &inbox_entries, &vm_slot));
    assert_eq!(processed.processed, 1);
    assert_eq!(processed.first_request_icount, Some(20));
    assert_eq!(ok(inbox.peek(&inbox_entries)), None);
    assert_eq!(vm_slot.snapshot().wake_signal, 2);
}

#[test]
fn block_shmem_full_response_ring_preserves_inflight_order() {
    let vm_slot = NodeSlot::new(KIND_VM);
    let block_slot = NodeSlot::new(KIND_BLK);
    let inbox = RingHeader::new();
    let mut inbox_entries = vec![FrameEntry::default(); 4];
    let outbox = RingHeader::new();
    let mut outbox_entries = vec![FrameEntry::default(); 1];
    let mut device = block_device(4, 4);

    for (seq, request) in [
        BlockRequest::read(10, 0, 1),
        BlockRequest::read(11, 1, 1),
        BlockRequest::read(12, 2, 1),
    ]
    .into_iter()
    .enumerate()
    {
        let request_frame = frame(0, 0, seq as u32, &ok(request.encode()));
        ok(inbox.enqueue(&mut inbox_entries, &request_frame));
    }
    assert_eq!(
        ok(device.process_shmem_inbox(&inbox, &inbox_entries, &vm_slot)).processed,
        3
    );
    let limit = ok(device
        .core()
        .next_exact_local_event()
        .ok_or("expected response event"));

    assert_eq!(
        ok(device.advance_to_shmem(limit, &outbox, &mut outbox_entries, &vm_slot)).delivered,
        1
    );
    assert_eq!(
        device.core().next_exact_local_event(),
        Some(limit),
        "remaining due responses must stay in flight at the same icount"
    );
    let first = ok(IoCore::dequeue_shmem_frame_and_wake_producer(
        &outbox,
        &outbox_entries,
        &block_slot,
    ))
    .frame
    .unwrap_or_else(|| panic!("first response should be present"));
    assert_eq!(
        ok(BlockResponse::decode(&frame_payload(&first))).request_id,
        10
    );

    assert_eq!(
        ok(device.advance_to_shmem(limit, &outbox, &mut outbox_entries, &vm_slot)).delivered,
        1
    );
    let second = ok(IoCore::dequeue_shmem_frame_and_wake_producer(
        &outbox,
        &outbox_entries,
        &block_slot,
    ))
    .frame
    .unwrap_or_else(|| panic!("second response should be present"));
    assert_eq!(
        ok(BlockResponse::decode(&frame_payload(&second))).request_id,
        11
    );

    assert_eq!(
        ok(device.advance_to_shmem(limit, &outbox, &mut outbox_entries, &vm_slot)).delivered,
        1
    );
    let third = ok(IoCore::dequeue_shmem_frame_and_wake_producer(
        &outbox,
        &outbox_entries,
        &block_slot,
    ))
    .frame
    .unwrap_or_else(|| panic!("third response should be present"));
    assert_eq!(
        ok(BlockResponse::decode(&frame_payload(&third))).request_id,
        12
    );
    assert!(device.core().next_exact_local_event().is_none());
}

#[test]
fn ninep_shmem_lifecycle_uses_real_rings_and_wakes() {
    let vm_slot = NodeSlot::new(KIND_VM);
    let ninep_slot = NodeSlot::new(KIND_9P);
    let inbox = RingHeader::new();
    let mut inbox_entries = vec![FrameEntry::default(); 2];
    let outbox = RingHeader::new();
    let mut outbox_entries = vec![FrameEntry::default(); 2];
    let src = SLOT_9P_IO as u32;
    let core = ok(IoCore::new(SHIFT, src, 4, 4));
    let mut device = NinepDevice::new(core, sample_tree(), NinepLatency::default());

    let request = tversion(1, 4096, codec::PROTOCOL_VERSION);
    ok(inbox.enqueue(&mut inbox_entries, &frame(0, 0, 0, &request)));
    let processed = ok(device.process_shmem_inbox(&inbox, &inbox_entries, &vm_slot));
    assert_eq!(processed.processed, 1);
    assert_eq!(vm_slot.snapshot().wake_signal, 1);

    let next = ok(device
        .core()
        .next_exact_local_event()
        .ok_or("expected 9p response event"));
    let delivered = ok(device.advance_to_shmem(next, &outbox, &mut outbox_entries, &vm_slot));
    assert_eq!(delivered.delivered, 1);
    assert!(delivered.consumer_wake.is_some());
    assert_eq!(vm_slot.snapshot().wake_signal, 2);

    let reply = ok(IoCore::dequeue_shmem_frame_and_wake_producer(
        &outbox,
        &outbox_entries,
        &ninep_slot,
    ))
    .frame
    .unwrap_or_else(|| panic!("9p reply frame should be present"));
    assert_eq!(reply.src_node, src);
    let payload = frame_payload(&reply);
    assert_eq!(payload.get(4), Some(&codec::RVERSION));
    assert_eq!(ninep_slot.snapshot().wake_signal, 1);
}

#[test]
fn full_outbox_backpressures_delivery_without_reorder() {
    // Tiny outbox: deliveries beyond capacity stay in flight at their exact
    // icounts and emerge in order once the consumer drains.
    let mut core = ok(IoCore::new(SHIFT, NODE, 16, 1));
    let mut device = EchoDevice::new(1000, 4);
    // Three requests with distinct delivery icounts (different request icounts).
    for (i, t) in [0u64, 4, 8].into_iter().enumerate() {
        ok(core.enqueue_request(Request::new(t, i as u32, vec![0u8; 1])));
    }
    ok(core.process_inbox(&mut device));

    let mut order = Vec::new();
    // Advance to the last event; the outbox (capacity 1) holds at most one at a
    // time, so the rest stay in flight. Re-running advance after each pop frees
    // the next response from flight in order — never dropped, never reordered.
    let last = ok(core
        .snapshot()
        .inflight
        .iter()
        .map(|p| p.delivery_icount())
        .max()
        .ok_or("expected in-flight responses"));
    loop {
        ok(core.advance_to(last));
        match core.pop_response() {
            Some(p) => order.push(p.delivery_icount()),
            None => break,
        }
    }
    let mut sorted = order.clone();
    sorted.sort_unstable();
    assert_eq!(order, sorted, "backpressured delivery must stay in order");
    assert_eq!(
        order.len(),
        3,
        "no response may be dropped under backpressure"
    );
}
