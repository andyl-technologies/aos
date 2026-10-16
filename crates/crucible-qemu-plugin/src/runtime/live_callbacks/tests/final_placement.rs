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
        self.construct_with_allocation(
            vcpu_count,
            raw_icount,
            || Ok(Box::<LiveVcpuTimeCallbackState>::new_uninit()),
            hook,
        )
    }

    fn construct_with_allocation<S: super::super::initialization::CallbackAllocation>(
        &mut self,
        vcpu_count: u32,
        raw_icount: u64,
        allocation: impl FnOnce() -> Result<S, LiveVcpuTimeCallbackError>,
        hook: &mut dyn FnMut(usize),
    ) -> Result<S::Initialized, LiveVcpuTimeCallbackError> {
        let commands = self
            .commands
            .take()
            .unwrap_or_else(|| panic!("fixture constructor runs only once"));
        LiveVcpuTimeCallbackState::initialize_with_allocation(
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
            allocation,
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

#[test]
fn borrowed_child_uses_the_existing_backing_and_requires_separate_typed_drop() {
    let mut fixture = PlacementFixture::new();
    let mut backing = Box::<LiveVcpuTimeCallbackState>::new_uninit();
    let address = backing.as_mut_ptr();
    let mut initialized = 0;
    let span = backing.as_mut();
    let child = fixture
        .construct_with_allocation(1, 0, || Ok(span), &mut |count| initialized = count)
        .unwrap_or_else(|error| panic!("borrowed fixture span should construct: {error}"));

    assert_eq!(initialized, 40);
    assert_eq!(std::ptr::from_ref(child), address.cast_const());
    assert_eq!(Arc::strong_count(&fixture.quiescence), 2);
    // SAFETY: all fields are initialized and no callback escaped this fixture.
    // This drops T only; the original Box<MaybeUninit<T>> still owns raw backing.
    unsafe {
        std::ptr::drop_in_place(child);
    }
    assert_eq!(backing.as_mut_ptr(), address);
    fixture.assert_custody_closed();
}

#[test]
fn borrowed_child_unwind_rolls_back_each_prefix_without_freeing_external_storage() {
    for boundary in 1..=40 {
        let mut fixture = PlacementFixture::new();
        let mut backing = Box::<LiveVcpuTimeCallbackState>::new_uninit();
        let address = backing.as_mut_ptr();
        let mut reached = 0;
        let span = backing.as_mut();
        let unwind = catch_unwind(AssertUnwindSafe(|| {
            fixture.construct_with_allocation(1, 0, || Ok(span), &mut |initialized| {
                reached = initialized;
                if initialized == boundary {
                    panic!("borrowed prefix control");
                }
            })
        }));

        assert!(unwind.is_err(), "boundary {boundary} must unwind");
        drop(unwind);
        assert_eq!(reached, boundary);
        assert_eq!(backing.as_mut_ptr(), address);
        fixture.assert_custody_closed();
    }
}

/// Observes the actual final prefix drop without owning or freeing its backing.
struct ObservedSpan<'a> {
    span: &'a mut std::mem::MaybeUninit<LiveVcpuTimeCallbackState>,
    returned: &'a std::cell::Cell<usize>,
    quiescence: &'a std::sync::Weak<LiveCallbackQuiescence>,
    teardown: &'a std::sync::Weak<LiveRuntimeTeardownRouter>,
}

// SAFETY: the component fixture uniquely retains this exact initialized span;
// conversion keeps its borrow, and the observer never frees the external Box.
unsafe impl<'a> super::super::initialization::CallbackAllocation for ObservedSpan<'a> {
    type Initialized = &'a mut LiveVcpuTimeCallbackState;

    fn pointer(&mut self) -> *mut LiveVcpuTimeCallbackState {
        self.span.as_mut_ptr()
    }

    /// Borrows the complete fixture span without transferring its external Box.
    ///
    /// # Safety
    /// Every field is initialized, prefix cleanup has ended, and the unique span
    /// and its external allocation owner remain live for the returned lifetime.
    unsafe fn initialized(self) -> Self::Initialized {
        // SAFETY: the common guard has recorded all forty complete fields.
        unsafe { self.span.assume_init_mut() }
    }

    fn prefix_rollback_completed(&mut self) {
        // Both first fields are actual strong owners. The last reverse drop is
        // quiescence: observing its release distinguishes an early false ACK.
        assert_eq!(self.quiescence.strong_count(), 1);
        assert_eq!(self.teardown.strong_count(), 1);
        self.returned.set(self.returned.get() + 1);
    }
}

#[test]
fn prefix_return_marker_follows_the_last_actual_field_drop() {
    for boundary in [17, 40] {
        let mut fixture = PlacementFixture::new();
        let mut backing = Box::<LiveVcpuTimeCallbackState>::new_uninit();
        let returned = std::cell::Cell::new(0);
        let quiescence = Arc::downgrade(&fixture.quiescence);
        let teardown = Arc::downgrade(&fixture.teardown);
        let span = ObservedSpan {
            span: backing.as_mut(),
            returned: &returned,
            quiescence: &quiescence,
            teardown: &teardown,
        };
        let result = catch_unwind(AssertUnwindSafe(|| {
            fixture.construct_with_allocation(1, 0, || Ok(span), &mut |initialized| {
                if initialized == boundary {
                    panic!("actual prefix return control");
                }
            })
        }));

        assert!(result.is_err());
        drop(result);
        assert_eq!(returned.get(), 1);
        fixture.assert_custody_closed();
    }
}

#[test]
fn complete_child_does_not_acknowledge_partial_prefix_return() {
    let mut fixture = PlacementFixture::new();
    let mut backing = Box::<LiveVcpuTimeCallbackState>::new_uninit();
    let returned = std::cell::Cell::new(0);
    let quiescence = Arc::downgrade(&fixture.quiescence);
    let teardown = Arc::downgrade(&fixture.teardown);
    let span = ObservedSpan {
        span: backing.as_mut(),
        returned: &returned,
        quiescence: &quiescence,
        teardown: &teardown,
    };
    let mut initialized = 0;
    let child = fixture
        .construct_with_allocation(1, 0, || Ok(span), &mut |count| initialized = count)
        .unwrap_or_else(|error| panic!("complete component child should build: {error}"));

    assert_eq!(initialized, 40);
    assert_eq!(returned.get(), 0);
    // SAFETY: the complete body has no escaped callbacks; this drops T only.
    unsafe { std::ptr::drop_in_place(child) };
    assert_eq!(returned.get(), 0);
    fixture.assert_custody_closed();
}
