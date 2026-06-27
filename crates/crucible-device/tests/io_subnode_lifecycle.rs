//! Integration tests for the uniform I/O sub-node lifecycle (CS-IO-1).
//!
//! These drive an [`IoCore`] through the in-process double pattern of spec
//! §15.7: construct a sub-node, enqueue requests, advance the clock, and assert
//! the emitted responses and their delivery icounts — with no real QEMU. The
//! `EchoDevice` below is a minimal [`IoSubNode`] whose `compute` deliberately
//! consults a host-timing-like counter to prove that COMPUTE wall-clock never
//! leaks into the delivery icount or any payload byte ([IO-4], [IO-31]).

#![forbid(unsafe_code)]

use std::fmt::Debug;

use crucible_device::{
    AffineLatency, DeviceError, IoCore, IoSubNode, Request, Response, ResponseStatus,
};

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

    fn latency_model(&self) -> &Self::Latency {
        &self.latency
    }

    fn compute(&mut self, request: &Request) -> Result<Response, DeviceError> {
        // Simulate variable host wall-clock spent in COMPUTE. This MUST NOT
        // affect the delivery icount or the payload.
        self.host_compute_ticks += 1 + u64::from(request.request_id);
        let mut payload = request.payload.clone();
        payload.reverse();
        Ok(Response::new(
            request.request_id,
            ResponseStatus::Ok,
            payload,
        ))
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

#[test]
fn stale_request_delivering_in_the_past_fails_loudly() {
    // Advance the clock well past where a stale request would complete, then
    // submit that stale request. Its computed delivery icount lands in the
    // consumer's past, so process_inbox MUST fail loudly ([IO-31], [IO-34])
    // rather than enqueue an out-of-order response.
    let mut core = ok(IoCore::new(SHIFT, NODE, 16, 16));
    let mut device = EchoDevice::new(1000, 4);

    // base_ns=1000, shift=8 => a request at icount 0 completes at icount 4.
    let stale = Request::new(0, 0, b"alpha".to_vec());
    let probe = ok(IoCore::new(SHIFT, NODE, 16, 16));
    let stale_delivery = ok(probe.compute_delivery_icount(&stale, device.latency_model()));
    assert_eq!(stale_delivery, 4);

    // Move the clock past the stale completion.
    ok(core.advance_to(1000));
    ok(core.enqueue_request(stale));

    let result = core.process_inbox(&mut device);
    assert!(
        matches!(
            result,
            Err(DeviceError::DeliveryInPast {
                delivery_icount: 4,
                current_icount: 1000
            })
        ),
        "expected DeliveryInPast, got {result:?}"
    );
    // Nothing was enqueued in flight: the guard rejected before insertion.
    assert!(core.next_exact_local_event().is_none());
}

#[test]
fn clock_never_moves_backward() {
    let mut core = ok(IoCore::new(SHIFT, NODE, 16, 16));
    ok(core.advance_to(100));
    assert!(matches!(
        core.advance_to(99),
        Err(DeviceError::ClockRegression { .. })
    ));
}
