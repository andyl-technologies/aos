//! Exercises immutable reports and actual last-header financial closure.
//!
//! These component accounts and returned errors supply no native Main, Source,
//! child-process, operation, or physical-return authority.

use super::*;
use crate::launch_cleanup::tests::allocation::{Fixture, fixture_observing};
use crate::shutdown::{QemuChildWait, QemuShutdownRung};
use crucible_host_resources::test_support::TestAllocationObserver;
use std::error::Error;
use std::time::Duration;

fn failure(index: usize) -> QemuShutdownFailure {
    QemuShutdownFailure {
        rung: QemuShutdownRung::Reap,
        source: QemuShutdownTargetError::new(
            "component refusal",
            format!("original error {index}"),
        ),
    }
}

#[test]
fn reports_freeze_selection_and_retain_every_original_error_without_copying() {
    let journal = ShutdownJournal::component();
    let errors: [_; FAILURES] = std::array::from_fn(failure);
    let pointers: [_; FAILURES] =
        std::array::from_fn(|index| errors[index].source.message.as_ptr());

    let ((early, complete, cloned, first), counts) = TestAllocationObserver::count(|| {
        let early = journal.report(false, false);
        for index in 0..ATTEMPTS {
            journal.record_attempt(
                index,
                QemuShutdownAttempt {
                    rung: QemuShutdownRung::Sigkill,
                    wait: Duration::from_millis(1),
                    child: QemuChildWait::StillRunning,
                },
            );
        }
        for (index, error) in errors.into_iter().enumerate() {
            journal.record_failure(index, error);
        }
        let complete = journal.report(true, false);
        let cloned = complete.clone();
        let first = journal.refusal(0).unwrap();
        (early, complete, cloned, first)
    });

    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    assert!(early.attempts.is_empty());
    assert!(early.failures.is_empty());
    assert!(!early.reaped);
    assert_eq!(complete.attempts.len(), ATTEMPTS);
    assert_eq!(complete.failures.len(), FAILURES);
    assert!(complete.reaped);
    assert_eq!(complete, cloned);
    for (index, error) in complete.failures.iter().enumerate() {
        assert_eq!(error.source.message.as_ptr(), pointers[index]);
    }
    assert!(std::ptr::eq(
        first
            .source()
            .unwrap()
            .downcast_ref::<QemuShutdownTargetError>()
            .unwrap(),
        &complete.failures[0].source,
    ));
    assert_eq!(std::mem::size_of::<QemuShutdownAttempts>(), 16);
    assert_eq!(std::mem::size_of::<QemuShutdownFailures>(), 16);
    assert_eq!(std::mem::size_of::<QemuShutdownRefusal>(), 16);
    assert!(std::mem::size_of::<QemuShutdownReport>() <= 48);
}

#[test]
fn prepaid_storage_claim_moves_the_original_once_without_allocating() {
    let Fixture { cleanup, .. } = fixture_observing(ShutdownJournal::allocation_layout().unwrap());

    let ((original, repeated), counts) = TestAllocationObserver::count(|| {
        (
            cleanup.claim_shutdown_journal(),
            cleanup.claim_shutdown_journal(),
        )
    });

    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    assert!(original.unwrap().available());
    assert!(repeated.is_none());
}

#[test]
fn last_report_frees_its_actual_header_before_paired_credit_returns() {
    let Fixture {
        cleanup,
        accounts,
        bytes,
        allocation,
    } = fixture_observing(ShutdownJournal::allocation_layout().unwrap());
    let journal = cleanup.claim_shutdown_journal().unwrap();
    let report = journal.report(false, false);
    drop(journal);
    drop(cleanup);

    for account in &accounts {
        assert!(account.reserve_resources(0, 0, 1).is_err());
    }
    let (_, observations) = TestAllocationObserver::observe_controls(
        [&accounts[0], &accounts[1]],
        None,
        [Some(allocation), None, None],
        || drop(report),
    );

    let observed = observations[0].unwrap();
    assert_eq!(observed.before.original_bytes, [Some(bytes); 2]);
    assert_eq!(observed.after.original_bytes, [Some(bytes); 2]);
    for account in &accounts {
        drop(account.reserve_resources(0, 0, bytes).unwrap());
    }
}

#[test]
fn journal_peak_covers_allocation_extraction_output_and_receipts() {
    let minimum = ShutdownJournal::allocation_layout().unwrap().size()
        + std::mem::size_of::<JournalAllocation>()
        + std::mem::size_of::<QemuShutdownFailure>()
        + std::mem::size_of::<QemuShutdownReport>()
        + std::mem::size_of::<ShutdownJournal>();

    assert_eq!(ShutdownJournal::peak_bytes().unwrap(), minimum as u64);
    assert!(
        crate::launch_cleanup::LaunchCleanup::retained_control_bytes().unwrap() >= minimum as u64
    );
}

struct RefusingTarget {
    errors: [Option<QemuShutdownTargetError>; 5],
    commands: usize,
    waits: usize,
    reaps: usize,
}

impl RefusingTarget {
    fn new() -> Self {
        Self {
            errors: std::array::from_fn(|index| Some(failure(index).source)),
            commands: 0,
            waits: 0,
            reaps: 0,
        }
    }
}

impl crate::shutdown::QemuShutdownTarget for RefusingTarget {
    fn send_control_quit(&mut self) -> Result<(), QemuShutdownTargetError> {
        self.commands += 1;
        Ok(())
    }

    fn send_qmp_quit(&mut self) -> Result<(), QemuShutdownTargetError> {
        self.commands += 1;
        Ok(())
    }

    fn send_sigterm(&mut self) -> Result<(), QemuShutdownTargetError> {
        self.commands += 1;
        Ok(())
    }

    fn send_sigkill(&mut self) -> Result<(), QemuShutdownTargetError> {
        self.commands += 1;
        Ok(())
    }

    fn wait_for_exit_observed(
        &mut self,
        _rung: QemuShutdownRung,
        _timeout: Duration,
    ) -> (Option<QemuChildWait>, Result<(), QemuShutdownTargetError>) {
        let first = self.errors[self.waits].take().unwrap();
        self.waits += 1;
        (Some(QemuChildWait::StillRunning), Err(first))
    }

    fn reap(
        &mut self,
        _timeout: Duration,
    ) -> Result<crate::shutdown::QemuReap, QemuShutdownTargetError> {
        self.reaps += 1;
        Err(self.errors[4].take().unwrap())
    }
}

#[test]
fn actual_ladder_reports_move_owned_errors_and_preserve_prior_snapshots() {
    let mut progress = crate::shutdown::QemuShutdownProgress::new();
    let mut target = RefusingTarget::new();
    let original = target.errors[4].as_ref().unwrap().message.as_ptr();
    let observation = failure(5).source;
    let observation_pointer = observation.message.as_ptr();

    let ((first, repeated), counts) = TestAllocationObserver::count(|| {
        let first = progress
            .run(&mut target, crate::QemuShutdownPolicy::fast_test())
            .unwrap_err();
        assert!(progress.retain_observation_failure(observation));
        let repeated = progress.failure().unwrap();
        (first, repeated)
    });

    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    assert_eq!((target.commands, target.waits, target.reaps), (4, 4, 1));
    let crate::QemuShutdownError::Target { source, report, .. } = first else {
        panic!("the original final-reap refusal remains typed");
    };
    assert_eq!(source.message.as_ptr(), original);
    assert_eq!(report.attempts.len(), 4);
    assert_eq!(report.failures.len(), 5);
    assert!(!report.reaped);
    let crate::QemuShutdownError::Target { source, report, .. } = repeated else {
        panic!("later observation cannot replace the original final-reap failure");
    };
    assert_eq!(source.message.as_ptr(), original);
    assert_eq!(report.failures.len(), 6);
    assert_eq!(
        report.failures[5].source.message.as_ptr(),
        observation_pointer
    );
}

#[test]
fn unavailable_prepaid_storage_cannot_enter_a_target_effect() {
    let Fixture { cleanup, .. } = fixture_observing(ShutdownJournal::allocation_layout().unwrap());
    let _canonical = crate::shutdown::QemuShutdownProgress::from_launch(&cleanup);
    let mut refused = crate::shutdown::QemuShutdownProgress::from_launch(&cleanup);
    let mut target = RefusingTarget::new();

    let (result, counts) = TestAllocationObserver::count(|| {
        refused.run(&mut target, crate::QemuShutdownPolicy::fast_test())
    });

    assert!(matches!(
        result,
        Err(crate::QemuShutdownError::StorageUnavailable)
    ));
    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    assert_eq!((target.commands, target.waits, target.reaps), (0, 0, 0));
}
