//! Prefix cleanup and stable final-allocation construction controls.
// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};

struct PlacementFixture {
    header: RegionHeader,
    slot: NodeSlot,
    initial_ack: u32,
    quiescence: Arc<LiveCallbackQuiescence>,
    teardown: Arc<LiveRuntimeTeardownRouter>,
    _receiver: mpsc::Receiver<LiveRuntimeTeardownTrigger>,
    observation: Arc<Mutex<TestFaultCommandObservation>>,
    commands: Option<Box<dyn LiveFaultCommandControl>>,
}

impl PlacementFixture {
    fn new() -> Self {
        let layout = RegionLayout::for_config(RegionConfig::new(1, 2))
            .unwrap_or_else(|error| panic!("test layout should validate: {error}"));
        let (sender, receiver) = mpsc::channel();
        let (commands, observation) = TestFaultCommandBridge::observed();
        let slot = NodeSlot::new(KIND_VM);
        let initial_ack = slot.snapshot().control_boundary_ack;
        Self {
            header: RegionHeader::new(layout),
            slot,
            initial_ack,
            quiescence: Arc::new(LiveCallbackQuiescence::new()),
            teardown: LiveRuntimeTeardownRouter::new(sender),
            _receiver: receiver,
            observation,
            commands: Some(Box::new(commands)),
        }
    }

    fn construct(
        &mut self,
        vcpu_count: u32,
        raw_icount: u64,
        hook: &mut dyn FnMut(usize),
    ) -> Result<Box<LiveVcpuTimeCallbackState>, LiveVcpuTimeCallbackError> {
        let commands = self
            .commands
            .take()
            .unwrap_or_else(|| panic!("fixture constructor runs only once"));
        LiveVcpuTimeCallbackState::new_boxed_with_hook(
            test_icount_raw,
            test_force_vcpu_exit,
            QemuIdleWakeWait::test_stub(test_wait_idle_wake),
            test_request_vmstop,
            test_support::test_preemption_injector(),
            vcpu_count,
            raw_icount,
            ExactDeadlineReader::require(Some(test_clock_deadline_ps))
                .unwrap_or_else(|error| panic!("test deadline should bind: {error}")),
            QueuedIdleAdvance::require(Some(test_queue_idle_advance))
                .unwrap_or_else(|error| panic!("test advance should bind: {error}")),
            test_support::test_virtual_timer_witness(),
            commands,
            &self.header,
            &self.slot,
            Arc::clone(&self.quiescence),
            Arc::clone(&self.teardown),
            hook,
        )
    }

    fn assert_custody_closed(&self) {
        assert_eq!(Arc::strong_count(&self.quiescence), 1);
        assert_eq!(Arc::strong_count(&self.teardown), 1);
        assert_eq!(Arc::strong_count(&self.observation), 1);
        assert_eq!(self.slot.snapshot().control_boundary_ack, self.initial_ack);
    }
}

#[test]
fn final_placement_unwind_closes_every_initialized_prefix_once() {
    for boundary in 1..=40 {
        let mut fixture = PlacementFixture::new();
        let mut reached = 0;
        let unwind = catch_unwind(AssertUnwindSafe(|| {
            fixture.construct(1, 0, &mut |initialized| {
                reached = initialized;
                if initialized == boundary {
                    panic!("post-marker initialization control");
                }
            })
        }));

        assert!(unwind.is_err(), "boundary {boundary} must unwind");
        assert_eq!(reached, boundary);
        fixture.assert_custody_closed();
    }
}

#[test]
fn final_placement_validation_keeps_first_cause_and_closes_unmoved_custody() {
    let mut raw_fixture = PlacementFixture::new();
    let mut raw_fields = 0;
    let raw_error = raw_fixture.construct(1, 1, &mut |count| raw_fields = count);
    assert!(matches!(
        raw_error,
        Err(LiveVcpuTimeCallbackError::InitialRawIcountBeyondLogical {
            raw_icount: 1,
            logical_icount: 0,
        })
    ));
    assert_eq!(raw_fields, 0);
    raw_fixture.assert_custody_closed();

    let mut halt_fixture = PlacementFixture::new();
    let mut halt_fields = 0;
    let halt_error = halt_fixture.construct(0, 0, &mut |count| halt_fields = count);
    assert!(matches!(
        halt_error,
        Err(LiveVcpuTimeCallbackError::VcpuHaltTracking {
            source: crate::round_robin::RoundRobinError::ZeroVcpuCount,
        })
    ));
    assert_eq!(halt_fields, 17);
    halt_fixture.assert_custody_closed();
}

#[test]
fn final_placement_pointer_survives_attachment_pin_and_worker_cleanup() {
    let mut fixture = PlacementFixture::new();
    let mut initialized = 0;
    let mut state = fixture
        .construct(1, 0, &mut |count| initialized = count)
        .unwrap_or_else(|error| panic!("final state should build: {error}"));
    assert_eq!(initialized, 40);
    let pointer = std::ptr::from_ref(state.as_ref());
    assert_eq!(state.header.get() as *const _, &fixture.header as *const _);
    assert_eq!(Arc::strong_count(&fixture.quiescence), 2);
    assert_eq!(Arc::strong_count(&fixture.observation), 2);

    let fingerprint_slot = FingerprintSampleSlot::new();
    let worker_quiescence =
        LiveWorkerQuiescence::new(crate::runtime::worker_quiescence::WORKER_ALL);
    let introspector = crate::PluginVcpuIntrospector::require(
        Some(test_fingerprint_read_vcpu_regs),
        Some(test_fingerprint_read_rr_cursor),
    )
    .unwrap_or_else(|error| panic!("test introspector should bind: {error}"));
    let sampling = crate::fingerprint_sampler::PluginFingerprintSampling::from_test_exports(
        introspector,
        test_fingerprint_capture,
    );
    attach_test_fingerprint_in_place(
        &mut state,
        sampling,
        &fingerprint_slot,
        Arc::clone(&worker_quiescence),
    )
    .unwrap_or_else(|error| panic!("fingerprint worker should attach: {error}"));
    assert_eq!(std::ptr::from_ref(state.as_ref()), pointer);

    let pinned = std::pin::Pin::from(state);
    assert_eq!(std::ptr::from_ref(pinned.as_ref().get_ref()), pointer);
    assert_eq!(fingerprint_slot.snapshot(), None);
    drop(pinned);

    // Dropping the completed owner closes and joins the actual worker before
    // the retained quiescence owner can lose its last external reference.
    assert_eq!(Arc::strong_count(&worker_quiescence), 1);
    assert_eq!(fingerprint_slot.snapshot(), None);
    fixture.assert_custody_closed();
}
