//! Live TX callback publication and native-stop admission regressions.

use super::*;

#[path = "network_output/retained_stop.rs"]
mod retained_stop;

#[path = "network_output/failure_context.rs"]
mod failure_context;

struct OutputFixture {
    slot: NodeSlot,
    outbound: RingHeader,
    inbound: RingHeader,
    outbound_entries: Vec<FrameEntry>,
    inbound_entries: Vec<FrameEntry>,
}

impl OutputFixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        TEST_REQUEST_VMSTOP_CALLS.set(0);
        TEST_REQUEST_VMSTOP_STATUS.set(0);
        let slot = NodeSlot::new(KIND_VM);
        let ceiling = authorize_advance_ceiling(0, 2_000, None)?;
        slot.publish_scheduler_advance(ceiling, AdvanceStopCondition::Ceiling)?;

        Ok(Self {
            slot,
            outbound: RingHeader::new(),
            inbound: RingHeader::new(),
            outbound_entries: vec![FrameEntry::default(); 4],
            inbound_entries: vec![FrameEntry::default(); 4],
        })
    }

    fn state(&mut self) -> Result<LiveVcpuTimeCallbackState, Box<dyn std::error::Error>> {
        let outbound = MappedDirectedRingMut {
            descriptor: DirectedRing {
                index: 0,
                src_slot: 0,
                dst_slot: SLOT_NET_ROUTER as u32,
            },
            header: &self.outbound,
            entries: &mut self.outbound_entries,
        };
        let inbound = MappedDirectedRingMut {
            descriptor: DirectedRing {
                index: 1,
                src_slot: SLOT_NET_ROUTER as u32,
                dst_slot: 0,
            },
            header: &self.inbound,
            entries: &mut self.inbound_entries,
        };
        Ok(test_live_state(150, 1, 0, &self.slot)?.attach_network(
            0,
            outbound,
            inbound,
            QemuCanonicalNetworkRx::require(Some(test_net_inject))?,
            0,
        )?)
    }
}

#[test]
fn live_tx_batch_publishes_its_original_coordinate_and_requests_native_stop()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = OutputFixture::new()?;
    let state = fixture.state()?;
    let initial_control_ack = fixture.slot.snapshot().control_boundary_ack;

    state.on_network_tx(20, b"first")?;
    TEST_REQUEST_VMSTOP_STATUS.set(-libc::EALREADY);
    state.on_network_tx(20, b"second")?;

    let stopped = fixture.slot.snapshot();
    assert_eq!(stopped.status, STATUS_IDLE);
    assert_eq!(stopped.current_icount, 1_000);
    assert_eq!(stopped.idle_wake_icount, 1_000);
    assert_eq!(stopped.logical_time_raw_icount, 20);
    assert_eq!(stopped.control_boundary_ack, initial_control_ack);
    assert_eq!(fixture.outbound.write_index(), 2);
    for (sequence, frame) in fixture.outbound_entries[..2].iter().enumerate() {
        assert_eq!(frame.delivery_icount, 1_000);
        assert_eq!(frame.seq, sequence as u32);
    }
    assert_eq!(fixture.outbound_entries[0].payload()?, b"first");
    assert_eq!(fixture.outbound_entries[1].payload()?, b"second");
    assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), 2);
    TEST_REQUEST_VMSTOP_STATUS.set(0);
    Ok(())
}

#[test]
fn live_tx_refuses_when_native_exact_stop_is_not_admitted() -> Result<(), Box<dyn std::error::Error>>
{
    let mut fixture = OutputFixture::new()?;
    let state = fixture.state()?;
    TEST_REQUEST_VMSTOP_STATUS.set(-libc::EPERM);

    let result = state.on_network_tx(20, b"frame");

    assert!(matches!(
        result,
        Err(LiveVcpuTimeCallbackError::CheckpointVmStopRejected {
            boundary: "network-output",
            status,
        }) if status == -libc::EPERM
    ));
    assert_eq!(fixture.outbound.write_index(), 1);
    assert_eq!(fixture.outbound_entries[0].delivery_icount, 1_000);
    assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), 1);
    TEST_REQUEST_VMSTOP_STATUS.set(0);
    Ok(())
}

#[test]
fn network_output_stop_survives_a_resume_before_original_frame_consumption()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = OutputFixture::new()?;
    let state = fixture.state()?;
    state.on_vcpu_init(0)?;
    state.try_halted_vcpus()?.mark_halted(0)?;
    let original_ack = fixture.slot.snapshot().control_boundary_ack;

    // The SDK callback models successful native admission only. The selected
    // native RR ordering is audited separately; this exercises the real Rust
    // producer and registered resume implementation over their original slot.
    state.on_network_tx(20, b"frame")?;
    state.on_vcpu_resume(0, 20)?;

    let stopped = fixture.slot.snapshot();
    assert_eq!(stopped.status, STATUS_IDLE);
    assert_eq!(stopped.current_icount, 1_000);
    assert_eq!(stopped.idle_wake_icount, 1_000);
    assert_eq!(stopped.logical_time_raw_icount, 20);
    assert_eq!(stopped.max_advance_icount, 2_000);
    assert_eq!(stopped.control_boundary_ack, original_ack);
    assert_eq!(fixture.outbound.read_index(), 0);
    assert_eq!(fixture.outbound.write_index(), 1);
    assert_eq!(fixture.outbound_entries[0].src_node, 0);
    assert_eq!(fixture.outbound_entries[0].delivery_icount, 1_000);
    assert_eq!(fixture.outbound_entries[0].seq, 0);
    assert_eq!(fixture.outbound_entries[0].payload()?, b"frame");
    assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), 1);
    Ok(())
}

#[test]
fn network_output_resume_retries_a_busy_idle_reservation_after_the_control_ack()
-> Result<(), Box<dyn std::error::Error>> {
    let _runtime_state = crate::runtime::isolate_runtime_state_for_test();
    let mut fixture = OutputFixture::new()?;
    let state = fixture.state()?;
    state.on_vcpu_init(0)?;
    TEST_ICOUNT_RAW.set(20);
    TEST_CLOCK_DEADLINE_PS.set(-1);
    LAST_QUEUED_ADVANCE_TICK.set(-1);
    state.on_network_tx(20, b"reply")?;

    // The host consumes the authenticated output report before publishing a
    // new RUN. The native runstate stop can still await its own release below.
    let consumed = fixture.outbound.dequeue(&fixture.outbound_entries)?;
    assert!(consumed.is_some());
    let next_ceiling = authorize_advance_ceiling(1_000, 2_500, None)?;
    fixture
        .slot
        .publish_scheduler_advance(next_ceiling, AdvanceStopCondition::Ceiling)?;
    fixture.slot.store_device_completion_deadline_tick(1_500);
    fixture.slot.mark_device_io_active();

    // Native stop is still retained when the next ceiling becomes visible.
    // Its busy reservation must roll back without losing the original frame.
    TEST_QUEUED_ADVANCE_STATUS.set(-libc::EBUSY);
    state.on_vcpu_idle(0, 20)?;
    assert_eq!(LAST_QUEUED_ADVANCE_TICK.get(), 1_500);
    assert!(!state.idle_advance_is_pending());
    assert_eq!(fixture.slot.snapshot().current_icount, 1_000);
    let request = fixture.slot.request_control_boundary(0, None)?;
    state.on_control_boundary(20)?;
    assert_eq!(
        fixture.slot.snapshot().control_boundary_ack,
        request.wrapping_add(1)
    );

    // RR consumes the native resume fence before this registered callback.
    // The callback re-arms the real all-halted edge; its next invocation owns
    // the deterministic retry, rather than replaying the rejected token.
    TEST_QUEUED_ADVANCE_STATUS.set(0);
    state.on_vcpu_resume(0, 20)?;
    state.on_vcpu_idle(0, 20)?;
    assert!(state.idle_advance_is_pending());
    state.complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, 1_500))?;

    assert!(!state.idle_advance_is_pending());
    assert_eq!(fixture.slot.snapshot().current_icount, 1_500);
    assert_eq!(fixture.outbound.write_index(), 1);
    assert_eq!(fixture.outbound_entries[0].delivery_icount, 1_000);
    assert_eq!(fixture.outbound_entries[0].payload()?, b"reply");
    assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), 1);
    TEST_ICOUNT_RAW.set(0);
    Ok(())
}
