//! Report and entered-effect preservation for the shared ladder engine.

use super::*;

#[derive(Default)]
struct Target {
    calls: Vec<QemuShutdownRung>,
    panic_control: bool,
}

impl QemuShutdownTarget for Target {
    fn send_control_quit(&mut self) -> Result<(), QemuShutdownTargetError> {
        self.calls.push(QemuShutdownRung::ControlQuit);
        assert!(!self.panic_control, "entered control panic");
        Err(QemuShutdownTargetError::new(
            "control write",
            "retained failure",
        ))
    }

    fn send_qmp_quit(&mut self) -> Result<(), QemuShutdownTargetError> {
        self.calls.push(QemuShutdownRung::QmpQuit);
        Ok(())
    }

    fn send_sigterm(&mut self) -> Result<(), QemuShutdownTargetError> {
        self.calls.push(QemuShutdownRung::Sigterm);
        Ok(())
    }

    fn send_sigkill(&mut self) -> Result<(), QemuShutdownTargetError> {
        self.calls.push(QemuShutdownRung::Sigkill);
        Ok(())
    }

    fn wait_for_exit_observed(
        &mut self,
        _: QemuShutdownRung,
        _: Duration,
    ) -> (Option<QemuChildWait>, Result<(), QemuShutdownTargetError>) {
        (Some(QemuChildWait::StillRunning), Ok(()))
    }

    fn reap(&mut self, _: Duration) -> Result<QemuReap, QemuShutdownTargetError> {
        self.calls.push(QemuShutdownRung::Reap);
        Err(QemuShutdownTargetError::new(
            "final reap",
            "independent failure",
        ))
    }
}

#[test]
fn final_reap_failure_retains_earlier_report_and_never_replays_effects() {
    let mut progress = QemuShutdownProgress::new();
    let mut target = Target::default();
    let first = progress
        .run(&mut target, QemuShutdownPolicy::fast_test())
        .unwrap_err();
    let QemuShutdownError::Target { source, report, .. } = first else {
        panic!("reap failure")
    };
    assert_eq!(source.operation, "final reap");
    assert_eq!(report.failures[0].source.operation, "control write");
    assert_eq!(report.failures[1].source.operation, "final reap");
    let before = target.calls.clone();

    assert!(
        progress
            .run(&mut target, QemuShutdownPolicy::fast_test())
            .is_err()
    );
    assert_eq!(target.calls, before);
    progress.observe_reaped();
    assert!(progress.report().reaped);
    assert!(progress.failure().is_some());
    assert_eq!(target.calls, before);
}

#[test]
fn interrupted_entered_rung_is_not_replayed_after_unwind_or_physical_observation() {
    let mut progress = QemuShutdownProgress::new();
    let mut target = Target {
        panic_control: true,
        ..Target::default()
    };
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = progress.run(&mut target, QemuShutdownPolicy::fast_test());
    }));
    assert!(outcome.is_err());
    assert!(matches!(
        progress.run(&mut target, QemuShutdownPolicy::fast_test()),
        Err(QemuShutdownError::Uncertain {
            rung: QemuShutdownRung::ControlQuit
        })
    ));
    progress.observe_reaped();
    assert!(progress.failure().is_some());
    assert_eq!(target.calls, [QemuShutdownRung::ControlQuit]);
}
