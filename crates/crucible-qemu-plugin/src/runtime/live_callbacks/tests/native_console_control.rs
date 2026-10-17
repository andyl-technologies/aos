//! Real slot/worker/ACK effects with explicitly modeled native control custody.
//!
//! These controls share the actual GPL callback, writer and fingerprint worker.
//! Their native prepare/commit implementations are external fixture authorities;
//! they do not establish actual RR/READY/closed scope or inventory admission.

use super::*;
use crate::runtime::live_callbacks::console_effect::{
    ConsoleControlDisposition, ConsoleControlEffect, ConsoleControlPreparation,
    NativeConsoleControlOwner, SettledConsoleControl,
};
use crucible_protocol::native_console::NativeConsoleError;
use crucible_shmem::{NodeBoundaryPublication, SchedulerAdvancePublication};

#[derive(Clone, Copy)]
enum Outcome {
    Busy,
    Prepared,
    Observed,
    ChangedDisposition,
    PrepareRefused,
    CommitRefused,
    CommitPanics,
}

struct ModeledNativeOwner<'a> {
    node: &'a NodeSlot,
    sample: &'a FingerprintSampleSlot,
    request: u32,
    capture: u32,
    outcome: Outcome,
    commits: u32,
    clears: u32,
}

impl NativeConsoleControlOwner for ModeledNativeOwner<'_> {
    fn prepare(
        &mut self,
        settled: SettledConsoleControl,
        logical: u64,
    ) -> Result<ConsoleControlPreparation, NativeConsoleError> {
        assert!(self.node.try_snapshot().is_some());
        assert_eq!(settled.request, self.request);
        assert_eq!(settled.capture_request, self.capture);
        assert_eq!(settled.raw, 7);
        assert_eq!(
            settled.advance,
            self.node.snapshot().advance_publication_sequence
        );
        assert_eq!(logical, 350);
        assert_eq!(self.sample.published_generation(), 0);
        assert_eq!(self.sample.pending_capture_request_v1(), Some(self.capture));
        match self.outcome {
            Outcome::Busy => Ok(ConsoleControlPreparation::Pending),
            Outcome::PrepareRefused => Err(NativeConsoleError::Binding),
            Outcome::Observed => Ok(ConsoleControlPreparation::Prepared(
                ConsoleControlDisposition::Observed,
            )),
            _ => Ok(ConsoleControlPreparation::Prepared(
                ConsoleControlDisposition::Accepted,
            )),
        }
    }

    fn commit(
        &mut self,
        fields: NodeBoundaryPublication,
        advance: SchedulerAdvancePublication,
    ) -> Result<ConsoleControlDisposition, NativeConsoleError> {
        // The actual writer is odd; no shared sample or capture ACK precedes it.
        assert!(self.node.try_snapshot().is_none());
        assert_eq!(fields.raw(), 7);
        assert_eq!(fields.logical(), 350);
        assert_eq!(advance.sequence() & 1, 0);
        assert_eq!(self.sample.published_generation(), 0);
        self.commits += 1;
        match self.outcome {
            Outcome::CommitRefused => Err(NativeConsoleError::Binding),
            Outcome::CommitPanics => panic!("modeled commit unwind"),
            Outcome::Observed | Outcome::ChangedDisposition => {
                Ok(ConsoleControlDisposition::Observed)
            }
            _ => Ok(ConsoleControlDisposition::Accepted),
        }
    }

    fn clear(&mut self) {
        assert!(self.node.try_snapshot().is_some());
        assert_eq!(self.node.control_boundary_token(), self.request);
        assert_eq!(self.sample.published_generation(), 0);
        assert_eq!(self.sample.pending_capture_request_v1(), Some(self.capture));
        self.clears += 1;
    }
}

fn fingerprint_state(
    node: &NodeSlot,
    sample: &FingerprintSampleSlot,
) -> Result<LiveVcpuTimeCallbackState, LiveVcpuTimeCallbackError> {
    node.publish_scheduler_advance(
        authorize_advance_ceiling(0, 350, None)
            .unwrap_or_else(|error| panic!("fixture ceiling must validate: {error}")),
        crucible_shmem::AdvanceStopCondition::Ceiling,
    )
    .unwrap_or_else(|error| panic!("fixture advance must publish: {error}"));
    let introspector = crate::PluginVcpuIntrospector::require(
        Some(test_fingerprint_read_vcpu_regs),
        Some(test_fingerprint_read_rr_cursor),
    )
    .unwrap_or_else(|error| panic!("fixture introspector must bind: {error}"));
    let sampling = crate::fingerprint_sampler::PluginFingerprintSampling::from_test_exports(
        introspector,
        test_fingerprint_capture,
    );
    test_live_state(316, 1, 0, node)?.attach_fingerprint(
        sampling,
        sample,
        LiveWorkerQuiescence::new(crate::runtime::worker_quiescence::WORKER_ALL),
    )
}

fn run_with_owner(
    state: &LiveVcpuTimeCallbackState,
    owner: &mut ModeledNativeOwner<'_>,
) -> Result<(), LiveVcpuTimeCallbackError> {
    let expected = match owner.outcome {
        Outcome::Observed => ConsoleControlDisposition::Observed,
        _ => ConsoleControlDisposition::Accepted,
    };
    let mut effect = ConsoleControlEffect::new(owner);
    let result = state.on_control_boundary_with_console(7, None, &mut |_| {}, Some(&mut effect));
    if effect.is_committed() {
        assert_eq!(effect.committed_disposition(), Some(expected));
        assert_eq!(effect.require_committed(), Ok(expected));
    }
    result
}

fn busy_then_success(paused: bool, outcome: Outcome) -> Result<(), LiveVcpuTimeCallbackError> {
    let node = NodeSlot::new(KIND_VM);
    let sample = FingerprintSampleSlot::new();
    let state = fingerprint_state(&node, &sample)?;
    if paused {
        state
            .header
            .get()
            .request_pause([&node])
            .unwrap_or_else(|error| panic!("fixture pause must publish: {error}"));
    }
    let capture = sample.request_capture_v1();
    let request = node
        .request_control_boundary(0, Some(capture))
        .unwrap_or_else(|error| panic!("fixture request must publish: {error}"));
    let before = node.snapshot();
    let mut owner = ModeledNativeOwner {
        node: &node,
        sample: &sample,
        request,
        capture,
        outcome: Outcome::Busy,
        commits: 0,
        clears: 0,
    };
    TEST_FINGERPRINT_CAPTURE_COUNT.set(0);
    TEST_REQUEST_VMSTOP_CALLS.set(0);
    TEST_REQUEST_VMSTOP_STATUS.set(0);

    run_with_owner(&state, &mut owner)?;

    assert_eq!(node.snapshot(), before);
    assert_eq!(sample.pending_capture_request_v1(), Some(capture));
    assert_eq!(sample.published_generation(), 0);
    assert_eq!(owner.commits, 0);
    assert_eq!(owner.clears, 0);
    assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), 0);
    // One private material copy was dropped without a worker enqueue/ACK.
    assert_eq!(TEST_FINGERPRINT_CAPTURE_COUNT.get(), 1);
    owner.outcome = outcome;

    run_with_owner(&state, &mut owner)?;
    let captured = wait_for_fingerprint_sample(&sample, capture);
    // Joining the original worker makes the exact publication count final;
    // a duplicate queued capture cannot pass by remaining unscheduled.
    drop(state);

    assert_eq!(captured.sample_icount, 350);
    assert_eq!(sample.published_generation(), 2);
    assert_eq!(sample.capture_request_generation(), capture.wrapping_add(1));
    assert_eq!(node.control_boundary_token(), request.wrapping_add(1));
    assert_eq!(owner.commits, 1);
    assert_eq!(owner.clears, 1);
    assert_eq!(TEST_FINGERPRINT_CAPTURE_COUNT.get(), 2);
    assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), u64::from(paused));
    Ok(())
}

#[test]
fn original_ordinary_busy_preserves_capture_then_worker_and_control_ack_once()
-> Result<(), LiveVcpuTimeCallbackError> {
    busy_then_success(false, Outcome::Prepared)
}

#[test]
fn original_pause_busy_preserves_capture_then_worker_and_control_ack_once()
-> Result<(), LiveVcpuTimeCallbackError> {
    busy_then_success(true, Outcome::Prepared)
}

#[test]
fn original_writer_refusal_and_unwind_release_without_sample_or_control_ack()
-> Result<(), LiveVcpuTimeCallbackError> {
    for paused in [false, true] {
        for outcome in [
            Outcome::PrepareRefused,
            Outcome::CommitRefused,
            Outcome::CommitPanics,
            Outcome::ChangedDisposition,
        ] {
            let node = NodeSlot::new(KIND_VM);
            let sample = FingerprintSampleSlot::new();
            let state = fingerprint_state(&node, &sample)?;
            if paused {
                state
                    .header
                    .get()
                    .request_pause([&node])
                    .unwrap_or_else(|error| panic!("fixture pause must publish: {error}"));
            }
            let capture = sample.request_capture_v1();
            let request = node
                .request_control_boundary(0, Some(capture))
                .unwrap_or_else(|error| panic!("fixture request must publish: {error}"));
            let mut owner = ModeledNativeOwner {
                node: &node,
                sample: &sample,
                request,
                capture,
                outcome,
                commits: 0,
                clears: 0,
            };
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run_with_owner(&state, &mut owner)
            }));
            match outcome {
                Outcome::CommitPanics => assert!(result.is_err()),
                _ => assert!(matches!(
                    result,
                    Ok(Err(LiveVcpuTimeCallbackError::ConsoleControl { .. }))
                )),
            }
            drop(state);
            assert!(node.try_snapshot().is_some());
            assert_eq!(node.control_boundary_token(), request);
            assert_eq!(sample.pending_capture_request_v1(), Some(capture));
            assert_eq!(sample.published_generation(), 0);
            assert_eq!(
                owner.clears,
                u32::from(!matches!(outcome, Outcome::PrepareRefused))
            );
        }
    }
    Ok(())
}

#[test]
fn original_checkpoint_stop_refusal_keeps_committed_effect_but_no_control_ack()
-> Result<(), LiveVcpuTimeCallbackError> {
    let node = NodeSlot::new(KIND_VM);
    let sample = FingerprintSampleSlot::new();
    let state = fingerprint_state(&node, &sample)?;
    state
        .header
        .get()
        .request_pause([&node])
        .unwrap_or_else(|error| panic!("fixture pause must publish: {error}"));
    let capture = sample.request_capture_v1();
    let request = node
        .request_control_boundary(0, Some(capture))
        .unwrap_or_else(|error| panic!("fixture request must publish: {error}"));
    let mut owner = ModeledNativeOwner {
        node: &node,
        sample: &sample,
        request,
        capture,
        outcome: Outcome::Prepared,
        commits: 0,
        clears: 0,
    };
    TEST_REQUEST_VMSTOP_STATUS.set(-17);

    let result = run_with_owner(&state, &mut owner);
    TEST_REQUEST_VMSTOP_STATUS.set(0);
    assert!(matches!(
        result,
        Err(LiveVcpuTimeCallbackError::CheckpointVmStopRejected { status: -17, .. })
    ));
    let captured = wait_for_fingerprint_sample(&sample, capture);
    // Joining the original worker makes the exact publication count final;
    // a duplicate queued capture cannot pass by remaining unscheduled.
    drop(state);

    assert_eq!(captured.sample_icount, 350);
    assert_eq!(node.control_boundary_token(), request);
    assert_eq!(owner.commits, 1);
    assert_eq!(owner.clears, 1);
    assert!(node.try_snapshot().is_some());
    Ok(())
}

/// External native phase provider; the callback/worker/writer/ACKs are real.
struct ModeledRestoreOwner<'a> {
    state: &'a LiveVcpuTimeCallbackState,
    node: &'a NodeSlot,
    sample: &'a FingerprintSampleSlot,
    generation: u32,
    request: u32,
    restored: bool,
    restore_calls: u32,
    commits: u32,
}

impl NativeConsoleControlOwner for ModeledRestoreOwner<'_> {
    fn restore_prefix(
        &mut self,
        generation: u32,
        raw: u64,
        logical: u64,
    ) -> Result<bool, NativeConsoleError> {
        assert_eq!(generation, self.generation);
        assert_eq!((raw, logical), (5, 350));
        assert_eq!(
            self.state.logical_icount_offset.load(Ordering::Acquire),
            100
        );
        assert_ne!(self.node.snapshot().logical_time_restore_ack, generation);
        assert_eq!(self.node.control_boundary_token(), self.request);
        assert_eq!(self.sample.published_generation(), 0);
        self.restore_calls += 1;
        Ok(self.restored)
    }

    fn prepare(
        &mut self,
        settled: SettledConsoleControl,
        logical: u64,
    ) -> Result<ConsoleControlPreparation, NativeConsoleError> {
        assert_eq!(
            (settled.request, settled.raw, logical),
            (self.request, 5, 350)
        );
        assert_eq!(
            self.node.snapshot().logical_time_restore_ack,
            self.generation
        );
        assert_eq!(self.sample.published_generation(), 0);
        Ok(ConsoleControlPreparation::Prepared(
            ConsoleControlDisposition::Accepted,
        ))
    }

    fn commit(
        &mut self,
        fields: NodeBoundaryPublication,
        _advance: SchedulerAdvancePublication,
    ) -> Result<ConsoleControlDisposition, NativeConsoleError> {
        assert!(self.node.try_snapshot().is_none());
        assert_eq!((fields.raw(), fields.logical()), (5, 350));
        assert_eq!(self.node.control_boundary_token(), self.request);
        self.commits += 1;
        Ok(ConsoleControlDisposition::Accepted)
    }

    fn clear(&mut self) {
        assert!(self.node.try_snapshot().is_some());
        assert_eq!(self.node.control_boundary_token(), self.request);
    }
}

#[test]
fn original_restore_busy_then_success_keeps_both_acks_until_prefix_owner()
-> Result<(), LiveVcpuTimeCallbackError> {
    let node = NodeSlot::new(KIND_VM);
    let sample = FingerprintSampleSlot::new();
    let state = fingerprint_state(&node, &sample)?;
    let generation = node
        .arm_logical_time_restore(350)
        .unwrap_or_else(|error| panic!("fixture stopped restore: {error}"));
    state
        .header
        .get()
        .request_pause([&node])
        .unwrap_or_else(|error| panic!("fixture stopped pause: {error}"));
    let capture = sample.request_capture_v1();
    let request = node
        .request_control_boundary(0, Some(capture))
        .unwrap_or_else(|error| panic!("fixture stopped request: {error}"));
    let mut owner = ModeledRestoreOwner {
        state: &state,
        node: &node,
        sample: &sample,
        generation,
        request,
        restored: false,
        restore_calls: 0,
        commits: 0,
    };
    TEST_REQUEST_VMSTOP_STATUS.set(0);
    TEST_REQUEST_VMSTOP_CALLS.set(0);

    {
        let mut effect = ConsoleControlEffect::new(&mut owner);
        state.on_control_boundary_with_console(5, None, &mut |_| {}, Some(&mut effect))?;
        assert!(effect.is_pending());
        assert_eq!(node.snapshot().logical_time_restore_ack, 0);
        assert_eq!(node.control_boundary_token(), request);
        assert_eq!(sample.published_generation(), 0);
        assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), 0);
    }

    owner.restored = true;
    {
        let mut effect = ConsoleControlEffect::new(&mut owner);
        state.on_control_boundary_with_console(5, None, &mut |_| {}, Some(&mut effect))?;
        assert!(effect.is_committed());
    }
    let captured = wait_for_fingerprint_sample(&sample, capture);
    assert_eq!(owner.restore_calls, 2);
    assert_eq!(owner.commits, 1);
    assert_eq!(node.snapshot().logical_time_restore_ack, generation);
    assert_eq!(node.control_boundary_token(), request.wrapping_add(1));
    assert_eq!(captured.sample_icount, 350);
    assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), 1);
    drop(state);
    Ok(())
}

#[test]
fn observation_busy_then_ordinary_commit_preserves_typed_disposition_and_capture_order()
-> Result<(), LiveVcpuTimeCallbackError> {
    busy_then_success(false, Outcome::Observed)
}

#[test]
fn observation_busy_then_pause_commit_preserves_original_advance_and_capture_order()
-> Result<(), LiveVcpuTimeCallbackError> {
    busy_then_success(true, Outcome::Observed)
}
