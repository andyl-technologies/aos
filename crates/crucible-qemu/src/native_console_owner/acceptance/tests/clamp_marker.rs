//! A RUN that starts at the zero-length idle a settled clamp left behind.
//!
//! The runtime clamp, custody and acceptance are real host implementations;
//! the provider thread models the plugin's slot writes as production makes
//! them. A console RUN publishes no control request, so the RUN's doorbell
//! reaches the plugin's control callback with an odd token, which only pumps
//! fault commands and publishes nothing, and a late budget-query answer to
//! the clamp's advance rolls back. The host must keep waiting on the marker
//! until the vCPU's own idle pass reports the RUN.

use super::*;

#[test]
fn native_run_waits_past_the_clamp_marker_for_the_vcpu_report() -> Result<(), FixtureError> {
    let fixture = LaunchFixture::cold(2)?;
    let region = mapped(&fixture)?;
    let mut channel = fixture.hot_path()?;
    let custody = custody(&fixture)?;
    start(&mut channel, 50)?;
    let cold = custody.authorization_snapshot()?;
    settle_real_runtime(&fixture, &region, cold, 50)?;
    // The settled clamp leaves the zero-length idle marker at 50.
    let marker = region.node_slot(0)?.snapshot();
    assert_eq!(marker.status, crucible_shmem::STATUS_IDLE);
    assert_eq!(marker.idle_wake_icount, 50);
    let marker_advance = marker.advance_publication_sequence;
    let accepted = custody
        .lock()?
        .accepted
        .accepted_request
        .ok_or(ConsoleOwnerError::Storage)?;
    let (mut notifications, wake) = UnixStream::pair()?;
    notifications.set_read_timeout(Some(Duration::from_secs(3)))?;
    let mut runtime = crate::QemuLiveHostIoRuntime::from_shmem_fd(
        fixture.setup.shmem_as_fd(),
        wake.as_fd(),
        fixture.setup.region().region_len,
        0,
    )?;
    runtime.retain_console_launch(&fixture.setup)?;
    runtime.prepare_advance_completion(Duration::from_secs(3))?;
    let pending = QemuShmemHotPathChannel::start_quantum(
        &mut channel,
        crucible::ExecutionHorizon {
            icount: crucible::Icount { retired: 200 },
        },
        AdvanceStopCondition::Ceiling,
    )?;
    runtime.retain_advance_initial_state(pending.initial_state());
    runtime.arm_advance_completion_fence(pending.completion_fence())?;
    runtime.set_advance_completion_poll_slice(Some(Duration::from_millis(200)))?;
    let body = custody.authorization_snapshot()?;
    let native = mapped(&fixture)?;
    let plan_hash = custody.lock()?.accepted.plan.digest()?;
    let unanswered = region.node_slot(0)?.snapshot();
    assert!(unanswered.advance_publication_sequence > marker_advance);
    let (resume, resumed) = std::sync::mpsc::channel::<()>();
    let provider = std::thread::spawn(move || -> Result<(), FixtureError> {
        let slot = native.node_slot(0)?;
        let mut wake = [0; 8];
        notifications.read_exact(&mut wake)?;
        // No request rides the RUN: the control callback sees an odd token
        // and, as control_callback_stage does, publishes nothing.
        assert_eq!(slot.control_boundary_token(), accepted + 1);
        // A budget query that loaded the clamp's advance before the RUN's
        // replaced it answers too late: the advance-bound writer rolls back.
        assert!(!slot.publish_reached_icount_retaining_idle_for_advance(50, marker_advance)?);
        assert_eq!(slot.snapshot().publish_gen, unanswered.publish_gen);
        resumed
            .recv_timeout(Duration::from_secs(3))
            .map_err(|_| FixtureError::Peer("host never resumed the provider".into()))?;
        // The halted vCPU's idle pass publishes its boundary at 50, then parks
        // on its real timer beyond the ceiling.
        slot.publish_reached_icount(50)?;
        let _wait = slot.publish_idle(50, 300)?;
        // Re-wake doorbells from the pending poll interleave with the clamp
        // request. The clamp publishes its pair before its own wake, so the
        // provider checks the pair before each notification it reads; a pair
        // still being written is not yet the clamp's, and the read timeout
        // bounds the wait.
        let segment = native.native_console_segment(0)?;
        let pair = loop {
            match segment.clamp.snapshot() {
                Ok(pair) if pair.last_issued == Some(body) => break pair,
                Ok(_) | Err(NativeConsoleError::Sequence) => {}
                Err(error) => return Err(ConsoleOwnerError::from(error).into()),
            }
            notifications.read_exact(&mut wake)?;
        };
        assert_eq!(
            pair.kind,
            crucible_protocol::native_console::NativeConsoleControlKind::Acceptance
        );
        segment.frontier.store(NativeConsoleFrontier {
            sequence: 0,
            ring_end: 0,
            logical_ps: 50,
            raw_prefix: 1,
            owner: body.owner,
            accepted_advance: pair.advance,
            logical_generation: body.logical_generation,
            request: pair.request,
            plan_hash,
        })?;
        slot.publish_control_boundary(50, 1)?;
        slot.acknowledge_control_boundary();
        Ok(())
    });

    let early = runtime.await_child(
        crate::QemuAsyncWait::AdvanceCompletion,
        Duration::from_secs(3),
    );
    let resumed = resume.send(());
    let early = early?;
    assert_eq!(early, crate::QemuAsyncWaitOutcome::Pending);
    assert!(runtime.completed_quantum_boundary().is_none());
    resumed.map_err(|_| FixtureError::Peer("provider exited early".into()))?;

    let completed = (|| -> Result<crate::QemuAsyncWaitOutcome, FixtureError> {
        for _ in 0..15 {
            let outcome = runtime.await_child(
                crate::QemuAsyncWait::AdvanceCompletion,
                Duration::from_secs(3),
            )?;
            if outcome != crate::QemuAsyncWaitOutcome::Pending {
                return Ok(outcome);
            }
        }
        Ok(crate::QemuAsyncWaitOutcome::Pending)
    })();
    // The provider's own refusal explains a host wait that never completed.
    let peer = provider.join().map_err(|_| FixtureError::PeerPanicked)?;
    peer?;
    let completed = completed?;
    assert_eq!(completed, crate::QemuAsyncWaitOutcome::Completed);
    let boundary = runtime
        .completed_quantum_boundary()
        .ok_or(ConsoleOwnerError::Storage)?;
    assert_eq!(boundary.calibration().logical_icount, 50);
    assert_eq!(region.node_slot(0)?.snapshot().idle_wake_icount, 300);
    fixture.finish()
}
