//! Checks original custody against a real external parent status observation.
//!
//! The fixture owns an ordinary subprocess outside the node adapter. It does
//! not issue a hot-fork basis, native request, stop receipt, or final journal.

use super::*;
use crate::node::process_control::{QemuNodeExternalProcessControl, QemuNodeProcessControl};
use crate::{
    QemuChildWait, QemuHotForkChildProcessBasis, QemuReap, QemuShutdownRung,
    QemuShutdownTargetError,
};
use std::io::Read;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Mutex;
use std::time::Instant;

#[derive(Debug)]
struct ParentStatus {
    child: Child,
    terminal: Option<ExitStatus>,
}

#[derive(Debug)]
struct ParentLoan(Arc<Mutex<ParentStatus>>);

impl ParentLoan {
    fn observe(&self) -> Result<Option<ExitStatus>, QemuShutdownTargetError> {
        let mut parent = self.0.lock().unwrap();
        if parent.terminal.is_none() {
            parent.terminal = parent.child.try_wait().map_err(|error| {
                QemuShutdownTargetError::new("fixture parent status", error.to_string())
            })?;
        }
        Ok(parent.terminal)
    }

    // crucible-lint: allow clippy-disallowed-method -- actual subprocess containment cannot affect modeled execution.
    #[allow(
        clippy::disallowed_methods,
        reason = "The fixture bounds actual subprocess containment using host wall time."
    )]
    fn wait(&self, timeout: Duration) -> Result<bool, QemuShutdownTargetError> {
        let began = Instant::now();
        loop {
            if self.observe()?.is_some() {
                return Ok(true);
            }
            if began.elapsed() >= timeout {
                return Ok(false);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

impl QemuNodeExternalProcessControl for ParentLoan {
    fn hot_fork_process_basis(&self) -> QemuHotForkChildProcessBasis {
        panic!("this process-status fixture never issues a hot-fork basis")
    }

    fn process_id(&self) -> u32 {
        self.0.lock().unwrap().child.id()
    }

    fn reaped(&self) -> bool {
        self.0.lock().unwrap().terminal.is_some()
    }

    fn try_wait_natural_exit(&mut self) -> Result<Option<ExitStatus>, QemuShutdownTargetError> {
        self.observe()
    }

    fn send_sigterm(&mut self) -> Result<(), QemuShutdownTargetError> {
        Err(QemuShutdownTargetError::new(
            "fixture SIGTERM",
            "unused fixture operation",
        ))
    }

    fn send_sigkill(&mut self) -> Result<(), QemuShutdownTargetError> {
        self.0
            .lock()
            .unwrap()
            .child
            .kill()
            .map_err(|error| QemuShutdownTargetError::new("fixture SIGKILL", error.to_string()))
    }

    fn wait_for_exit(
        &mut self,
        _rung: QemuShutdownRung,
        timeout: Duration,
    ) -> Result<QemuChildWait, QemuShutdownTargetError> {
        Ok(if self.wait(timeout)? {
            QemuChildWait::Exited
        } else {
            QemuChildWait::StillRunning
        })
    }

    fn reap(&mut self, timeout: Duration) -> Result<QemuReap, QemuShutdownTargetError> {
        Ok(if self.wait(timeout)? {
            QemuReap::Reaped
        } else {
            QemuReap::StillAlive
        })
    }
}

fn receiving_process(
    account: &HostServiceAllocator,
) -> (QemuNodeProcessControl, Arc<Mutex<ParentStatus>>) {
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "node::exact_snapshot::capture_original::tests::external::held_child_fixture",
            "--ignored",
            "--nocapture",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let parent = Arc::new(Mutex::new(ParentStatus {
        child,
        terminal: None,
    }));
    let mut process = QemuNodeProcessControl::external(Box::new(ParentLoan(Arc::clone(&parent))));
    let supervisor = supervisor();
    let mut original =
        CheckpointOriginal::allocate_registered_owner(&supervisor, account, target()).unwrap();
    original.enter(&event()).unwrap();
    let refused = original
        .prepare_receiving(&registration(account, Arc::new(UnavailableRegistrar)))
        .unwrap_err();
    assert_eq!(
        refused.source,
        CheckpointOriginalCause::NativeReceiverUnavailable
    );
    *process.checkpoint_original_slot() = Some(original);
    (process, parent)
}

#[test]
#[ignore = "subprocess-only stdin hold"]
fn held_child_fixture() {
    let mut bytes = [0; 1];
    let _ = std::io::stdin().read(&mut bytes).unwrap();
}

#[test]
fn external_signal_retains_custody_until_actual_parent_reap() {
    let account = HostServiceAllocator::new(1, 2, 16384).unwrap();
    let (mut process, parent) = receiving_process(&account);
    assert_eq!(process.try_wait_natural_exit().unwrap(), None);
    process.send_sigkill().unwrap();

    assert!(!process.reaped());
    assert!(process.checkpoint_original().unwrap().body.is_some());
    assert!(account.reserve_resources(0, 2, 16384).is_err());

    assert_eq!(
        process.reap(Duration::from_secs(3)).unwrap(),
        QemuReap::Reaped
    );
    assert!(parent.lock().unwrap().terminal.is_some());
    assert!(process.checkpoint_original().unwrap().body.is_none());
    assert!(account.reserve_resources(0, 2, 16384).is_ok());
    assert_eq!(process.reap(Duration::ZERO).unwrap(), QemuReap::Reaped);
}

#[test]
fn unreaped_external_drop_does_not_refund_original_custody() {
    let account = HostServiceAllocator::new(1, 2, 16384).unwrap();
    let (mut process, parent) = receiving_process(&account);
    assert_eq!(process.try_wait_natural_exit().unwrap(), None);

    drop(process);

    assert!(parent.lock().unwrap().terminal.is_none());
    assert!(account.reserve_resources(0, 2, 16384).is_err());
    // Only the fixture's real parent owns cleanup after adapter containment.
    let mut parent = parent.lock().unwrap();
    parent.child.kill().unwrap();
    parent.terminal = Some(parent.child.wait().unwrap());
    assert!(account.reserve_resources(0, 2, 16384).is_err());
}
