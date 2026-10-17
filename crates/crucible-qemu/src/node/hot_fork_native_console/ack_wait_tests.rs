//! Original mapped Restore receipts with explicitly modeled native completion.
//!
//! The installer custody, paired body, slot decoder and wait are actual host
//! paths. Native INITIALIZE/CLOSED/Restore and source-parent process status are
//! fixture providers; these controls execute neither a QEMU child nor a fork.

use std::error::Error;
use std::num::NonZeroU32;
use std::time::Duration;

use crate::native_console_owner::ChildFixture;

use super::*;

type TestResult = Result<(), Box<dyn Error>>;

fn with_restore(
    budget: Duration,
    control: impl FnOnce(
        &ChildFixture,
        &mut QemuHotForkConsoleRestore,
        &mut dyn QemuNodeExternalProcessControl,
    ) -> TestResult,
) -> TestResult {
    let (mut source, scheduler, mut process, mut diagnostics) =
        crate::node::tests::console_reattempt_scheduler_continuation(None)?;
    let mut fixture = ChildFixture::with_request(scheduler.request())?;
    fixture.publish_capability()?;
    let deadline =
        HostSupervisionAbsoluteDeadline::checked_after(budget).ok_or("test deadline overflows")?;
    let mut restore = fixture.prepare_with_deadline(deadline)?;
    restore.arm()?;

    let result = control(&fixture, &mut restore, process.as_mut());
    drop(scheduler);
    source.release_hot_fork_plugin_endpoints()?;
    source.release_hot_fork_child_qmp()?;
    source.release_hot_fork_child_diagnostics_with_consumer(&mut diagnostics)?;
    drop(source.release_hot_fork_private_ring_mapping()?);
    source.shutdown_child()?;
    result
}

#[test]
fn genuine_restore_ack_before_wait_keeps_original_body_and_accepts_once() -> TestResult {
    with_restore(Duration::from_secs(1), |fixture, restore, process| {
        let segment = fixture.region.native_console_segment(0)?;
        let original_body = segment.authorization.snapshot()?;
        let original_pair = segment.clamp.snapshot()?;
        let original_deadline = restore.deadline;
        let frontier = fixture.modeled_ack(2)?;

        await_restore_ack(restore, process)?;
        restore.accept()?;
        restore.accept()?;

        assert_eq!(restore.deadline, original_deadline);
        assert!(restore.accepted_ready.is_some());
        assert_eq!(segment.authorization.snapshot()?, original_body);
        assert_eq!(segment.clamp.snapshot()?, original_pair);
        assert_eq!(segment.frontier.copy()?, frontier);
        assert_eq!(
            fixture.region.node_slot(0)?.control_boundary_token(),
            original_pair.request.wrapping_add(1)
        );
        assert_eq!(
            (segment.ring.read_index(), segment.ring.write_index()),
            (23, 23)
        );
        Ok(())
    })
}

#[test]
fn missing_ack_and_completion_after_expiry_never_renew_or_accept_restore() -> TestResult {
    with_restore(Duration::from_millis(5), |fixture, restore, process| {
        let deadline = restore.deadline;
        let slot = fixture.region.node_slot(0)?;
        let segment = fixture.region.native_console_segment(0)?;
        let body = segment.authorization.snapshot()?;
        let pair = segment.clamp.snapshot()?;

        let error = await_restore_ack(restore, process)
            .err()
            .ok_or("absent ACK was accepted")?;
        assert!(error.to_string().contains("original absolute deadline"));
        assert_eq!(slot.control_boundary_token(), pair.request);
        assert_eq!(restore.deadline, deadline);
        assert!(restore.accepted_ready.is_none());
        assert_eq!(segment.authorization.snapshot()?, body);
        assert_eq!(segment.clamp.snapshot()?, pair);

        // A genuine late provider cannot retroactively enlarge the first budget.
        fixture.modeled_ack(2)?;
        let error = await_restore_ack(restore, process)
            .err()
            .ok_or("late ACK renewed the budget")?;
        assert!(error.to_string().contains("original absolute deadline"));
        assert!(restore.accepted_ready.is_none());
        assert_eq!(
            (segment.ring.read_index(), segment.ring.write_index()),
            (23, 23)
        );
        Ok(())
    })
}

#[test]
fn completed_ack_cannot_hide_high_word_raw_or_logical_mismatch() -> TestResult {
    for raw_mismatch in [false, true] {
        with_restore(Duration::from_secs(1), |fixture, restore, process| {
            let segment = fixture.region.native_console_segment(0)?;
            let body = segment.authorization.snapshot()?;
            let pair = segment.clamp.snapshot()?;
            fixture.modeled_ack(2)?;
            let slot = fixture.region.node_slot(0)?;
            let error = if raw_mismatch {
                // The real producer first refuses an impossible raw/logical
                // pair. Separately exercise the decoder on an altered COPY;
                // that copy is never published or treated as native authority.
                let original = slot.snapshot();
                assert!(slot.publish_pause_quiesced(100, 2 + (1_u64 << 32)).is_err());
                assert_eq!(slot.snapshot(), original);
                let mut malformed = original;
                malformed.logical_time_raw_icount += 1_u64 << 32;
                restore
                    .boundary
                    .ok_or("Restore boundary absent")?
                    .acknowledged(malformed, restore.calibration)
                    .err()
                    .ok_or("raw high-word mismatch was accepted")?
            } else {
                slot.publish_pause_quiesced(100 + (1_u64 << 32), 2)?;
                await_restore_ack(restore, process)
                    .err()
                    .ok_or("logical high-word mismatch was accepted")?
            };
            assert!(error.to_string().contains("inconsistent boundary"));
            assert!(restore.accepted_ready.is_none());
            assert_eq!(segment.authorization.snapshot()?, body);
            assert_eq!(segment.clamp.snapshot()?, pair);
            assert_eq!(
                (segment.ring.read_index(), segment.ring.write_index()),
                (23, 23)
            );
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn changed_ack_under_a_foreign_publication_claim_refuses_without_parking() -> TestResult {
    with_restore(Duration::from_secs(1), |fixture, restore, process| {
        let segment = fixture.region.native_console_segment(0)?;
        let body = segment.authorization.snapshot()?;
        let pair = segment.clamp.snapshot()?;
        fixture.modeled_ack(2)?;
        let slot = fixture.region.node_slot(0)?;
        let claim = slot.try_claim_control_boundary_publication_for_test(
            NonZeroU32::new(2).ok_or("modeled claim is zero")?,
        )?;

        let error = await_restore_ack(restore, process)
            .err()
            .ok_or("foreign publication was accepted")?;
        assert!(error.is_publication_unavailable());
        assert!(restore.deadline.has_not_elapsed());
        assert!(restore.accepted_ready.is_none());
        assert_eq!(segment.authorization.snapshot()?, body);
        assert_eq!(segment.clamp.snapshot()?, pair);
        assert_eq!(
            (segment.ring.read_index(), segment.ring.write_index()),
            (23, 23)
        );
        drop(claim);
        Ok(())
    })
}

/// Preserves the actual loan while modeling only its parent's terminal observation.
#[derive(Debug)]
struct TerminalParent<'a>(&'a mut dyn QemuNodeExternalProcessControl);

impl QemuNodeExternalProcessControl for TerminalParent<'_> {
    fn hot_fork_process_basis(&self) -> QemuHotForkChildProcessBasis {
        self.0.hot_fork_process_basis()
    }

    fn process_id(&self) -> u32 {
        self.0.process_id()
    }

    fn reaped(&self) -> bool {
        true
    }

    fn try_wait_natural_exit(
        &mut self,
    ) -> Result<Option<std::process::ExitStatus>, QemuShutdownTargetError> {
        self.0.try_wait_natural_exit()
    }

    fn send_sigterm(&mut self) -> Result<(), QemuShutdownTargetError> {
        self.0.send_sigterm()
    }

    fn send_sigkill(&mut self) -> Result<(), QemuShutdownTargetError> {
        self.0.send_sigkill()
    }

    fn wait_for_exit(
        &mut self,
        rung: QemuShutdownRung,
        timeout: Duration,
    ) -> Result<QemuChildWait, QemuShutdownTargetError> {
        self.0.wait_for_exit(rung, timeout)
    }

    fn reap(&mut self, timeout: Duration) -> Result<QemuReap, QemuShutdownTargetError> {
        self.0.reap(timeout)
    }
}

#[test]
fn original_process_loan_terminal_status_refuses_before_restore_acceptance() -> TestResult {
    with_restore(Duration::from_secs(1), |fixture, restore, process| {
        let segment = fixture.region.native_console_segment(0)?;
        let body = segment.authorization.snapshot()?;
        let pair = segment.clamp.snapshot()?;
        fixture.modeled_ack(2)?;
        let mut terminal = TerminalParent(process);

        let error = await_restore_ack(restore, &mut terminal)
            .err()
            .ok_or("terminal child was accepted")?;
        assert!(error.to_string().contains("child process exited"));
        assert!(restore.accepted_ready.is_none());
        assert_eq!(segment.authorization.snapshot()?, body);
        assert_eq!(segment.clamp.snapshot()?, pair);
        assert_eq!(
            (segment.ring.read_index(), segment.ring.write_index()),
            (23, 23)
        );
        Ok(())
    })
}
