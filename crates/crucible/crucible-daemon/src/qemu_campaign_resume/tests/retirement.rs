//! Exercises the real runner boundary with owned component failure values.
//!
//! These tests issue no Main, native process, receipt or resource authority.
//! Drop counters witness the exact typed values moved through real execute.

use super::*;
use std::error::Error;

#[derive(Debug)]
struct TrackedFailure {
    name: &'static str,
    dropped: Arc<AtomicUsize>,
    formatted: Arc<AtomicUsize>,
}

impl std::fmt::Display for TrackedFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.formatted.fetch_add(1, Ordering::SeqCst);
        formatter.write_str(self.name)
    }
}

impl Error for TrackedFailure {}

impl Drop for TrackedFailure {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

#[derive(Clone, Copy)]
enum DriveClass {
    Retryable,
    Canceled,
    Terminal,
}

impl DriveClass {
    fn wrap(self, first: TrackedFailure) -> AttemptWorkerFailure<TrackedFailure> {
        match self {
            Self::Retryable => AttemptWorkerFailure::Retryable(first),
            Self::Canceled => AttemptWorkerFailure::Canceled(first),
            Self::Terminal => AttemptWorkerFailure::Terminal(first),
        }
    }
}

struct RetiringFactory {
    inner: FakeResumeFactory,
    shutdown: Option<SchedulerError>,
    retirement: Option<TrackedFailure>,
    calls: Arc<AtomicUsize>,
    order: Arc<Mutex<Vec<&'static str>>>,
}

impl QemuProductionExactResumeLifecycleFactory for RetiringFactory {
    type Lifecycle = FakeResumeLifecycle;
    type Error = TrackedFailure;

    fn authenticate_resume_boundary(
        &mut self,
        _checkpoints: &ExactCheckpointStore,
        _checkpoint: ExactCheckpointId,
        _basis: QemuExactResumeBasis<'_>,
        _context: &AttemptExecutionContext,
    ) -> Result<
        Option<crate::qemu_campaign_driver::QemuSelectedResumeBoundary>,
        AttemptWorkerFailure<Self::Error>,
    > {
        panic!("ordinary component resume must not authenticate a selected boundary");
    }

    fn start_resume_lifecycle(
        &mut self,
        checkpoints: &ExactCheckpointStore,
        checkpoint: ExactCheckpointId,
        basis: QemuExactResumeBasis<'_>,
        context: &AttemptExecutionContext,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>> {
        let mut lifecycle = self
            .inner
            .start_resume_lifecycle(checkpoints, checkpoint, basis, context)
            .expect("one component resume construction");
        lifecycle.shutdown_failure = self.shutdown.take();
        lifecycle.boundary_order = Some(Arc::clone(&self.order));
        Ok(lifecycle)
    }

    fn retire_lifecycle(&mut self, lifecycle: Self::Lifecycle) -> Result<(), Self::Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.order
            .lock()
            .expect("boundary order")
            .push("retirement");
        assert_eq!(lifecycle.calls.shutdowns.load(Ordering::SeqCst), 1);
        drop(lifecycle);
        match self.retirement.take() {
            Some(first) => Err(first),
            None => Ok(()),
        }
    }
}

struct BoundaryDriver {
    inner: FakeResumeDriver,
    failure: Option<TrackedFailure>,
    class: DriveClass,
    order: Arc<Mutex<Vec<&'static str>>>,
}

impl QemuFreshAttemptDriver for BoundaryDriver {
    type Pending = ();
    type Error = TrackedFailure;

    fn drive(
        &mut self,
        lifecycle: &mut QemuFreshAttemptLifecycle<'_>,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        materialization: QemuFreshStartMaterialization,
    ) -> Result<QemuFreshDriveOutcome<Self::Pending>, AttemptWorkerFailure<Self::Error>> {
        self.order.lock().expect("boundary order").push("drive");
        if let Some(first) = self.failure.take() {
            self.inner.calls.drives.fetch_add(1, Ordering::SeqCst);
            return Err(self.class.wrap(first));
        }
        Ok(self
            .inner
            .drive(lifecycle, input, context, materialization)
            .expect("component driver succeeds without an injected failure"))
    }

    fn seal(
        &mut self,
        pending: Self::Pending,
        events: Vec<SchedulerEventLogEntry>,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
        self.order.lock().expect("boundary order").push("seal");
        Ok(self.inner.seal(pending, events).expect("component seal"))
    }
}

fn tracked(
    name: &'static str,
    dropped: &Arc<AtomicUsize>,
    formatted: &Arc<AtomicUsize>,
) -> TrackedFailure {
    TrackedFailure {
        name,
        dropped: Arc::clone(dropped),
        formatted: Arc::clone(formatted),
    }
}

fn find_tracked<'cause>(
    mut error: &'cause (dyn Error + 'static),
) -> Option<&'cause TrackedFailure> {
    loop {
        if let Some(first) = error.downcast_ref::<TrackedFailure>() {
            return Some(first);
        }
        error = error.source()?;
    }
}

fn run_case(drive: bool, shutdown: bool, retirement: bool, class: DriveClass) {
    let _metadata = crate::exact_checkpoint_store::test_support::fixture_decode_scope();
    let calls = Arc::new(ResumeCalls::default());
    let retirement_calls = Arc::new(AtomicUsize::new(0));
    let order = Arc::new(Mutex::new(Vec::new()));
    let dropped: [Arc<AtomicUsize>; 3] = std::array::from_fn(|_| Arc::new(AtomicUsize::new(0)));
    let formatted = Arc::new(AtomicUsize::new(0));
    let shutdown_failure = shutdown.then(|| {
        SchedulerError::Backend(crucible_engine::BackendError::RetainedOperationalFailure {
            kind: crucible_engine::BackendOperationalFailureKind::Unavailable,
            source: crucible_engine::BackendOperationalCause::new(tracked(
                "shutdown",
                &dropped[1],
                &formatted,
            )),
        })
    });
    let factory = RetiringFactory {
        inner: FakeResumeFactory {
            calls: Arc::clone(&calls),
            state: Some(ProductionVmLifecycleResumeState::new(
                test_configuration(),
                Vec::new(),
                0,
                0,
                VirtualTime::default(),
                SchedulerQuiescence::default(),
                None,
            )),
            final_events: Vec::new(),
        },
        shutdown: shutdown_failure,
        retirement: retirement.then(|| tracked("retirement", &dropped[2], &formatted)),
        calls: Arc::clone(&retirement_calls),
        order: Arc::clone(&order),
    };
    let driver = BoundaryDriver {
        inner: FakeResumeDriver {
            calls: Arc::clone(&calls),
            observed: Arc::new(Mutex::new(None)),
        },
        failure: drive.then(|| tracked("drive", &dropped[0], &formatted)),
        class,
        order: Arc::clone(&order),
    };
    let mut runner =
        QemuProductionExactResumeExecutionRunner::new(test_checkpoint_store(), factory, driver);

    let result = runner.execute(
        &test_input(),
        &test_context(Some(checkpoint_id("resume-boundary-outcomes"))),
    );

    assert_eq!(calls.starts.load(Ordering::SeqCst), 1);
    assert_eq!(calls.drives.load(Ordering::SeqCst), 1);
    assert_eq!(calls.shutdowns.load(Ordering::SeqCst), 1);
    assert_eq!(retirement_calls.load(Ordering::SeqCst), 1);
    assert_eq!(formatted.load(Ordering::SeqCst), 0);
    for count in &dropped {
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }
    let failed = drive || shutdown || retirement;
    assert_eq!(calls.seals.load(Ordering::SeqCst), usize::from(!failed));
    let expected_order = if failed {
        vec!["drive", "shutdown", "retirement"]
    } else {
        vec!["drive", "shutdown", "retirement", "seal"]
    };
    assert_eq!(*order.lock().expect("boundary order"), expected_order);
    if !failed {
        assert!(result.is_ok());
        return;
    }

    let error = result.expect_err("one or more boundary outcomes failed");
    assert_eq!(
        matches!(&error, AttemptWorkerFailure::Terminal(_)),
        shutdown || retirement || matches!(class, DriveClass::Terminal)
    );
    assert_eq!(
        matches!(&error, AttemptWorkerFailure::Retryable(_)),
        drive && !shutdown && !retirement && matches!(class, DriveClass::Retryable)
    );
    assert_eq!(
        matches!(&error, AttemptWorkerFailure::Canceled(_)),
        drive && !shutdown && !retirement && matches!(class, DriveClass::Canceled)
    );
    let record = match &error {
        AttemptWorkerFailure::Retryable(record)
        | AttemptWorkerFailure::Canceled(record)
        | AttemptWorkerFailure::Terminal(record) => record,
    };
    assert_eq!(record.first.is_some(), drive);
    assert_eq!(record.shutdown.is_some(), shutdown);
    assert_eq!(record.retirement.is_some(), retirement);
    if drive {
        let Some(ResumeFailure::Driver(first)) = &record.first else {
            panic!("the initiating driver cause must stay typed");
        };
        assert_eq!(first.name, "drive");
        assert!(Arc::ptr_eq(&first.dropped, &dropped[0]));
    }
    if let Some(first) = &record.shutdown {
        let first = find_tracked(first).expect("original typed shutdown cause");
        assert_eq!(first.name, "shutdown");
        assert!(Arc::ptr_eq(&first.dropped, &dropped[1]));
    }
    if let Some(first) = &record.retirement {
        assert_eq!(first.name, "retirement");
        assert!(Arc::ptr_eq(&first.dropped, &dropped[2]));
    }
    let first_name = if drive {
        "drive"
    } else if shutdown {
        "shutdown"
    } else {
        "retirement"
    };
    assert_eq!(
        find_tracked(record).expect("first cause chain").name,
        first_name
    );
    let _diagnostic = format!("{record}");
    for count in &dropped {
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }

    drop(error);
    for (count, failed) in dropped.iter().zip([drive, shutdown, retirement]) {
        assert_eq!(count.load(Ordering::SeqCst), usize::from(failed));
    }
}

macro_rules! outcome_case {
    ($name:ident, $drive:literal, $shutdown:literal, $retirement:literal) => {
        #[test]
        fn $name() {
            run_case($drive, $shutdown, $retirement, DriveClass::Retryable);
        }
    };
}

outcome_case!(all_success_seals_after_both_boundaries, false, false, false);
outcome_case!(drive_failure_stays_retryable, true, false, false);
outcome_case!(shutdown_failure_is_owned_and_terminal, false, true, false);
outcome_case!(retirement_failure_is_owned_and_terminal, false, false, true);
outcome_case!(drive_and_shutdown_both_stay_owned, true, true, false);
outcome_case!(drive_and_retirement_both_stay_owned, true, false, true);
outcome_case!(shutdown_and_retirement_both_stay_owned, false, true, true);
outcome_case!(all_three_failures_stay_owned, true, true, true);

#[test]
fn drive_only_cancellation_is_not_reclassified() {
    run_case(true, false, false, DriveClass::Canceled);
}

#[test]
fn drive_only_terminal_failure_is_not_reclassified() {
    run_case(true, false, false, DriveClass::Terminal);
}

#[test]
fn canceled_drive_with_retirement_failure_is_terminal_and_retains_both() {
    run_case(true, false, true, DriveClass::Canceled);
}

#[test]
fn actual_source_history_moves_as_the_retirement_value() {
    // This is the real history type and native error payload, without claiming
    // a Main receipt or a funded provider that this component cannot issue.
    let native = crucible_qemu_host::QemuVmRealizationError::ExecutorUnavailable {
        operation: "component retirement history transport",
        message: String::from("original retirement allocation"),
    };
    let crucible_qemu_host::QemuVmRealizationError::ExecutorUnavailable { message, .. } = &native
    else {
        panic!("component native cause");
    };
    let original_pointer = message.as_ptr();
    let history = crate::SourceCleanupHistory::from_native(native);
    let dropped = Arc::new(AtomicUsize::new(0));
    let formatted = Arc::new(AtomicUsize::new(0));
    let driven = Err(AttemptWorkerFailure::Retryable(ResumeFailure::Driver(
        tracked("drive", &dropped, &formatted),
    )));
    let result = finish_resume_outcomes::<(), (), _, _>(driven, Ok(()), Err(history));

    let AttemptWorkerFailure::Terminal(record) =
        result.expect_err("independent retirement failure")
    else {
        panic!("retirement failure must be terminal");
    };
    let history = record
        .retirement
        .as_ref()
        .expect("original history retained");
    let native = history
        .source()
        .expect("native first")
        .downcast_ref::<crucible_qemu_host::QemuVmRealizationError>()
        .expect("actual native type");
    let crucible_qemu_host::QemuVmRealizationError::ExecutorUnavailable { message, .. } = native
    else {
        panic!("the same native cause must be retained");
    };
    assert_eq!(message.as_ptr(), original_pointer);
    assert_eq!(message, "original retirement allocation");
    assert_eq!(formatted.load(Ordering::SeqCst), 0);
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    drop(record);
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
}

#[test]
fn reports_actual_resume_outcome_type_layouts_for_later_qualification() {
    // cfg(test) can affect nested production types. These emitted observations
    // are test-layout evidence only, never a production stack or funding grant.
    type FactoryError =
        QemuObservedFreshAttemptLifecycleFactoryError<crate::QemuAttemptProductionVmLifecycleError>;
    type DriverError = crate::QemuFreshModeledDriverError;
    type Cause = ResumeFailure<FactoryError, DriverError>;
    type Record = QemuProductionExactResumeExecutionRunnerError<FactoryError, DriverError>;
    type Driven = Result<
        ResumeRunnerResult<<crate::QemuFreshModeledDriver as QemuFreshAttemptDriver>::Pending>,
        AttemptWorkerFailure<Cause>,
    >;
    type Shutdown = Result<Vec<SchedulerEventLogEntry>, SchedulerError>;
    type Retirement = Result<(), FactoryError>;
    let layouts = [
        ("cause", std::alloc::Layout::new::<Cause>()),
        ("record", std::alloc::Layout::new::<Record>()),
        ("driven", std::alloc::Layout::new::<Driven>()),
        ("shutdown", std::alloc::Layout::new::<Shutdown>()),
        ("retirement", std::alloc::Layout::new::<Retirement>()),
        (
            "boundary_inputs",
            std::alloc::Layout::new::<(Driven, Shutdown, Retirement)>(),
        ),
    ];
    for (name, layout) in layouts {
        println!(
            "RESUME_OUTCOME_TEST_LAYOUT {name} size={} align={}",
            layout.size(),
            layout.align()
        );
    }
    assert!(std::mem::needs_drop::<Record>());
}
