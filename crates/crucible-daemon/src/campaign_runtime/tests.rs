//! Campaign runtime lifecycle regressions.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts.
// crucible-lint: allow clippy-disallowed-method -- bounded channel deadlines localize background failures.
#![allow(clippy::expect_used, clippy::disallowed_methods)]

use std::collections::VecDeque;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::*;

const TEST_TIMEOUT: Duration = Duration::from_secs(10);

#[test]
fn exhausted_planner_allowance_waits_instead_of_stopping_the_runtime() {
    let content = crucible_cas::content_store::ContentId::for_bytes(
        crucible_cas::content_store::ObjectKind::CampaignSnapshot,
        3,
        b"runtime-budget-snapshot",
    );
    let snapshot = crucible_campaign::CampaignSnapshotId::parse(&format!(
        "crucible.campaign.snapshot@{content}"
    ))
    .expect("typed snapshot identity");
    let outcome =
        CampaignSupervisorStepOutcome::Planner(CampaignPlannerStepOutcome::BudgetBlocked {
            snapshot,
            reason: crucible_campaign::CampaignBudgetError::AttemptAllowanceExhausted,
        });
    assert_eq!(
        supervisor_step_disposition(&outcome),
        CampaignRuntimeStepDisposition::Wait
    );
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FakeError {
    Failed,
}

struct FakeDriver {
    steps: Arc<Mutex<VecDeque<Result<CampaignRuntimeStepDisposition, FakeError>>>>,
    entered: Sender<()>,
    observed: Sender<CampaignRuntimeStepDisposition>,
}

impl CampaignRuntimeDriver for FakeDriver {
    type Error = FakeError;

    fn step(&mut self) -> Result<CampaignRuntimeStepDisposition, Self::Error> {
        self.entered.send(()).expect("runtime step entry");
        let step = self
            .steps
            .lock()
            .expect("fake step queue")
            .pop_front()
            .unwrap_or(Ok(CampaignRuntimeStepDisposition::Wait))?;
        self.observed.send(step).expect("runtime observation");
        Ok(step)
    }
}

#[test]
fn runtime_continues_bounded_progress_then_waits_for_explicit_wake() {
    let steps = Arc::new(Mutex::new(VecDeque::from([
        Ok(CampaignRuntimeStepDisposition::Continue),
        Ok(CampaignRuntimeStepDisposition::Continue),
        Ok(CampaignRuntimeStepDisposition::Wait),
    ])));
    let (entered_tx, _entered_rx) = mpsc::channel();
    let (observed_tx, observed_rx) = mpsc::channel();
    let runtime = CampaignRuntime::start(
        FakeDriver {
            steps: Arc::clone(&steps),
            entered: entered_tx,
            observed: observed_tx,
        },
        CampaignRuntimeConfig::new(Duration::from_secs(60)).expect("valid interval"),
    )
    .expect("start runtime");

    assert_eq!(
        observed_rx.recv_timeout(TEST_TIMEOUT).expect("first step"),
        CampaignRuntimeStepDisposition::Continue
    );
    assert_eq!(
        observed_rx.recv_timeout(TEST_TIMEOUT).expect("second step"),
        CampaignRuntimeStepDisposition::Continue
    );
    assert_eq!(
        observed_rx
            .recv_timeout(TEST_TIMEOUT)
            .expect("quiescent step"),
        CampaignRuntimeStepDisposition::Wait
    );
    assert!(observed_rx.try_recv().is_err());

    steps
        .lock()
        .expect("fake step queue")
        .push_back(Ok(CampaignRuntimeStepDisposition::Wait));
    runtime.wake_handle().wake();
    assert_eq!(
        observed_rx
            .recv_timeout(TEST_TIMEOUT)
            .expect("explicitly woken step"),
        CampaignRuntimeStepDisposition::Wait
    );

    let report = runtime.shutdown_and_join().expect("clean shutdown");
    assert_eq!(report.steps(), 4);
    assert_eq!(report.immediate_continuations(), 2);
    assert_eq!(report.explicit_wakes(), 1);
    assert_eq!(report.fallback_polls(), 0);
    assert_eq!(report.fairness_pauses(), 0);
}

#[test]
fn shutdown_interrupts_the_maximum_quiescent_wait() {
    for _ in 0..64 {
        let steps = Arc::new(Mutex::new(VecDeque::from([Ok(
            CampaignRuntimeStepDisposition::Wait,
        )])));
        let (entered_tx, _entered_rx) = mpsc::channel();
        let (observed_tx, observed_rx) = mpsc::channel();
        let runtime = CampaignRuntime::start(
            FakeDriver {
                steps,
                entered: entered_tx,
                observed: observed_tx,
            },
            CampaignRuntimeConfig::new(MAX_CAMPAIGN_RUNTIME_POLL_INTERVAL)
                .expect("maximum interval"),
        )
        .expect("start runtime");
        observed_rx
            .recv_timeout(TEST_TIMEOUT)
            .expect("runtime entered quiescence");

        let report = runtime.shutdown_and_join().expect("shutdown wakes runtime");
        assert_eq!(report.steps(), 1);
        assert_eq!(report.fallback_polls(), 0);
    }
}

#[test]
fn driver_failure_stops_and_is_returned_to_the_owner() {
    let steps = Arc::new(Mutex::new(VecDeque::from([Err(FakeError::Failed)])));
    let (entered_tx, entered_rx) = mpsc::channel();
    let (observed_tx, _observed_rx) = mpsc::channel();
    let runtime = CampaignRuntime::start(
        FakeDriver {
            steps,
            entered: entered_tx,
            observed: observed_tx,
        },
        CampaignRuntimeConfig::default(),
    )
    .expect("start runtime");
    let completion = runtime.completion_handle();
    entered_rx
        .recv_timeout(TEST_TIMEOUT)
        .expect("failing step entered");
    completion.wait();
    assert!(completion.is_finished());

    assert!(matches!(
        runtime.shutdown_and_join(),
        Err(CampaignRuntimeJoinError::Driver(FakeError::Failed))
    ));
}

#[test]
fn runtime_poll_interval_is_strictly_bounded() {
    assert_eq!(
        CampaignRuntimeConfig::new(Duration::ZERO),
        Err(CampaignRuntimeConfigError::InvalidPollInterval)
    );
    assert!(CampaignRuntimeConfig::new(MIN_CAMPAIGN_RUNTIME_POLL_INTERVAL).is_ok());
    assert!(CampaignRuntimeConfig::new(MAX_CAMPAIGN_RUNTIME_POLL_INTERVAL).is_ok());
    assert_eq!(
        CampaignRuntimeConfig::new(MAX_CAMPAIGN_RUNTIME_POLL_INTERVAL + Duration::from_nanos(1)),
        Err(CampaignRuntimeConfigError::InvalidPollInterval)
    );
}

#[test]
fn immediate_progress_is_throttled_after_one_fixed_burst() {
    let mut queued = VecDeque::new();
    for _ in 0..MAX_CAMPAIGN_RUNTIME_IMMEDIATE_BURST {
        queued.push_back(Ok(CampaignRuntimeStepDisposition::Continue));
    }
    queued.push_back(Ok(CampaignRuntimeStepDisposition::Wait));
    let steps = Arc::new(Mutex::new(queued));
    let (entered_tx, _entered_rx) = mpsc::channel();
    let (observed_tx, observed_rx) = mpsc::channel();
    let runtime = CampaignRuntime::start(
        FakeDriver {
            steps,
            entered: entered_tx,
            observed: observed_tx,
        },
        CampaignRuntimeConfig::new(Duration::from_secs(60)).expect("valid interval"),
    )
    .expect("start runtime");

    for _ in 0..=MAX_CAMPAIGN_RUNTIME_IMMEDIATE_BURST {
        observed_rx
            .recv_timeout(TEST_TIMEOUT)
            .expect("bounded progress step");
    }
    let report = runtime.shutdown_and_join().expect("clean shutdown");
    assert_eq!(report.steps(), MAX_CAMPAIGN_RUNTIME_IMMEDIATE_BURST + 1);
    assert_eq!(report.fairness_pauses(), 1);
}
