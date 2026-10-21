//! Causal cleanup controls; these model no Source or Native admission.

use super::*;
use crucible_host_resources::host_supervision::{HostOperationBudget, HostOperationBudgets};
use std::error::Error;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Debug)]
struct ControlledChild {
    closed: Arc<AtomicBool>,
    signals: Arc<Mutex<Vec<QemuShutdownRung>>>,
    initial_observation: bool,
    expire_and_refuse_term: Option<HostOperationSupervisor>,
    reap_and_expire_on_poll: Option<HostOperationSupervisor>,
}

impl QemuNodeExternalProcessControl for ControlledChild {
    fn hot_fork_process_basis(&self) -> crate::QemuHotForkChildProcessBasis {
        panic!("component shutdown must not invent a hot-fork basis")
    }

    fn process_id(&self) -> u32 {
        999_999
    }

    fn reaped(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    fn try_wait_natural_exit(
        &mut self,
    ) -> Result<Option<std::process::ExitStatus>, QemuShutdownTargetError> {
        if self.reaped() {
            return Ok(None);
        }
        if self.initial_observation {
            // The factual entry poll observes a live child. The later poll is
            // inside the actual rung's independent Original pre/post bracket.
            self.initial_observation = false;
            return Ok(None);
        }
        if let Some(supervisor) = &self.reap_and_expire_on_poll {
            use std::os::unix::process::ExitStatusExt;

            self.closed.store(true, Ordering::Release);
            let (revision, mut budgets) = supervisor.budgets().unwrap();
            budgets.classes[HostOperationClass::Cleanup as usize] =
                HostOperationBudget::finite(Duration::from_nanos(1));
            supervisor.update_budgets(revision, budgets).unwrap();
            return Ok(Some(std::process::ExitStatus::from_raw(0)));
        }
        // Advance the containment ladder through a real returned parent-query
        // error, without a timing-dependent wait or fabricated exited receipt.
        Err(QemuShutdownTargetError::new(
            "modeled parent query",
            "not yet observable",
        ))
    }

    fn send_sigterm(&mut self) -> Result<(), QemuShutdownTargetError> {
        self.signals.lock().unwrap().push(QemuShutdownRung::Sigterm);
        if let Some(supervisor) = &self.expire_and_refuse_term {
            let (revision, mut budgets) = supervisor.budgets().unwrap();
            budgets.classes[HostOperationClass::Cleanup as usize] =
                HostOperationBudget::finite(Duration::from_nanos(1));
            supervisor.update_budgets(revision, budgets).unwrap();
            return Err(QemuShutdownTargetError::new(
                "modeled SIGTERM",
                "actual entered refusal",
            ));
        }
        self.closed.store(true, Ordering::Release);
        Ok(())
    }

    fn send_sigkill(&mut self) -> Result<(), QemuShutdownTargetError> {
        self.signals.lock().unwrap().push(QemuShutdownRung::Sigkill);
        Ok(())
    }

    fn wait_for_exit(
        &mut self,
        _: QemuShutdownRung,
        _: Duration,
    ) -> Result<QemuChildWait, QemuShutdownTargetError> {
        Ok(if self.reaped() {
            QemuChildWait::Exited
        } else {
            QemuChildWait::StillRunning
        })
    }

    fn reap(&mut self, _: Duration) -> Result<QemuReap, QemuShutdownTargetError> {
        Ok(if self.reaped() {
            QemuReap::Reaped
        } else {
            QemuReap::StillAlive
        })
    }
}

fn fixture(
    expire: bool,
) -> Result<
    (
        QemuNode,
        HostOperationSupervisor,
        Arc<AtomicBool>,
        Arc<Mutex<Vec<QemuShutdownRung>>>,
    ),
    Box<dyn Error>,
> {
    fixture_with_poll_expiry(expire, false)
}

fn fixture_with_poll_expiry(
    expire: bool,
    expire_poll: bool,
) -> Result<
    (
        QemuNode,
        HostOperationSupervisor,
        Arc<AtomicBool>,
        Arc<Mutex<Vec<QemuShutdownRung>>>,
    ),
    Box<dyn Error>,
> {
    let mut node = super::super::tests::shutdown_continuation_fixture()?;
    // Dispose the real fixture child before installing a distinct modeled
    // generation. The new child gets its own unentered journal, never a copy.
    assert!(node.shutdown_child()?.reaped);
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(5)),
    )?;
    let closed = Arc::new(AtomicBool::new(false));
    let signals = Arc::new(Mutex::new(Vec::new()));
    node.child = QemuNodeProcessControl::external(Box::new(ControlledChild {
        closed: Arc::clone(&closed),
        signals: Arc::clone(&signals),
        initial_observation: true,
        expire_and_refuse_term: expire.then(|| supervisor.clone()),
        reap_and_expire_on_poll: expire_poll.then(|| supervisor.clone()),
    }));
    node.child_shutdown = ChildShutdown::new();
    Ok((node, supervisor, closed, signals))
}

fn close(
    node: &mut QemuNode,
    supervisor: &HostOperationSupervisor,
) -> Result<QemuShutdownReport, QemuNodeError> {
    let process = node.child_shutdown.close(
        &mut node.child,
        &mut node.channels,
        &mut node.lifecycle_state,
        node.shutdown_policy,
        Some(supervisor),
    );
    node.finish_shutdown(process)
}

#[test]
fn shutdown_diagnostics_borrow_static_text_and_retain_typed_original() -> Result<(), Box<dyn Error>>
{
    use crucible_host_resources::test_support::TestAllocationObserver;
    use std::borrow::Cow;

    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
    let original = supervisor.begin(HostOperationClass::Cleanup)?;
    original.complete()?;
    let source = original.wait_slice().unwrap_err();

    let (errors, counts) = TestAllocationObserver::count(|| {
        let first = QemuShutdownTargetError::new("cleanup", "fixed refusal");
        let alias = first.clone();
        let channel = super::super::channel_error_to_shutdown_error(QemuNodeChannelError::new(
            "channel cleanup",
            "bounded writer absent",
        ));
        let typed = QemuShutdownTargetError::operational_supervision("cleanup", source);
        [first, alias, channel, typed.clone(), typed]
    });

    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    assert!(
        errors
            .iter()
            .all(|error| matches!(error.message, Cow::Borrowed(_)))
    );
    assert_eq!(errors[0], errors[1]);
    assert_eq!(errors[2].message, "bounded writer absent");
    assert_eq!(errors[3].operational_supervision_source(), Some(source));
    assert_eq!(errors[3], errors[4]);
    assert_eq!(
        errors[3]
            .source()
            .and_then(|source| source.downcast_ref::<HostSupervisionError>()),
        Some(&source),
    );
    assert_eq!(errors[3].to_string(), format!("cleanup failed: {source}"));

    let message = String::from("original owned shutdown diagnostic");
    let allocation = message.as_ptr();
    let (owned, counts) =
        TestAllocationObserver::count(|| QemuShutdownTargetError::new("cleanup", message));

    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    assert!(matches!(owned.message, Cow::Owned(_)));
    assert_eq!(owned.message.as_ptr(), allocation);
    Ok(())
}

#[test]
fn actual_shutdown_bracket_retains_refused_entry_without_diagnostic_allocation()
-> Result<(), Box<dyn Error>> {
    use crucible_host_resources::test_support::TestAllocationObserver;

    let (mut node, supervisor, closed, _) = fixture(false)?;
    let original = supervisor.begin(HostOperationClass::Cleanup)?;
    original.complete()?;
    let first = original.wait_slice().unwrap_err();
    let mut observations = [(None, None); 5];
    let mut pending = false;
    let mut entered = false;
    let mut target = QemuNodeShutdownTarget {
        child: &mut node.child,
        plugin_control: None,
        qmp_machine_control: None,
        supervisor: Some(&supervisor),
        guard: Some(&original),
        observations: &mut observations,
        history_pending: &mut pending,
    };

    let ((output, status), counts) = TestAllocationObserver::count(|| {
        target.under_original_observed(QemuShutdownRung::ControlQuit, |_| {
            entered = true;
            Ok(())
        })
    });

    assert!(output.is_none());
    assert!(!entered);
    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    assert_eq!(
        status.unwrap_err().operational_supervision_source(),
        Some(first)
    );
    assert_eq!(observations[0], (Some(first), Some(first)));
    assert!(pending);
    closed.store(true, Ordering::Release);
    Ok(())
}

#[test]
fn actual_shutdown_bracket_retains_first_and_post_without_diagnostic_allocation()
-> Result<(), Box<dyn Error>> {
    use crucible_host_resources::test_support::TestAllocationObserver;

    for work_refuses in [false, true] {
        let (mut node, supervisor, closed, _) = fixture(false)?;
        let original = supervisor.begin(HostOperationClass::Cleanup)?;
        let (revision, mut budgets) = supervisor.budgets()?;
        budgets.classes[HostOperationClass::Cleanup as usize] =
            HostOperationBudget::finite(Duration::from_nanos(1));
        let mut observations = [(None, None); 5];
        let mut pending = false;
        let mut target = QemuNodeShutdownTarget {
            child: &mut node.child,
            plugin_control: None,
            qmp_machine_control: None,
            supervisor: Some(&supervisor),
            guard: Some(&original),
            observations: &mut observations,
            history_pending: &mut pending,
        };

        let ((output, status), counts) = TestAllocationObserver::count(|| {
            target.under_original_observed(QemuShutdownRung::ControlQuit, |_| {
                // Amend the real class allowance from its original start
                // after entry. This effect claims no child return.
                supervisor.update_budgets(revision, budgets).unwrap();
                if work_refuses {
                    Err(QemuShutdownTargetError::new(
                        "entered effect",
                        "actual refusal",
                    ))
                } else {
                    Ok(17_u8)
                }
            })
        });

        let post = original.wait_slice().unwrap_err();
        let error = status.unwrap_err();
        assert_eq!(counts.allocations, 0);
        assert_eq!(counts.reallocations, 0);
        assert!(!counts.overflow);
        assert_eq!(observations[0], (None, Some(post)));
        assert!(pending);
        if work_refuses {
            assert!(output.is_none());
            assert_eq!(error.operation, "entered effect");
            assert_eq!(error.message, "actual refusal");
            assert!(error.operational_supervision_source().is_none());
        } else {
            assert_eq!(output, Some(17));
            assert_eq!(error.operation, "post child cleanup rung");
            assert_eq!(error.operational_supervision_source(), Some(post));
        }
        closed.store(true, Ordering::Release);
    }
    Ok(())
}

#[test]
fn entered_refusal_and_independent_posts_survive_same_original_until_factual_close()
-> Result<(), Box<dyn Error>> {
    let (mut node, supervisor, closed, signals) = fixture(true)?;
    let first = close(&mut node, &supervisor).unwrap_err();
    let QemuNodeError::ShutdownOriginal {
        report,
        observations,
        completion,
        ..
    } = first
    else {
        panic!("actual original history must be returned")
    };
    assert!(
        report
            .failures
            .iter()
            .any(|failure| failure.source.operation == "modeled SIGTERM")
    );
    assert!(observations[2].1.is_some());
    // Later rung entry refuses before its signal, but each same-Original
    // bracket still records its independently executed postcheck.
    assert!(observations[3].0.is_some());
    assert!(observations[3].1.is_some());
    assert!(observations[4].0.is_some());
    assert!(observations[4].1.is_some());
    assert!(completion.is_none());
    let status = supervisor.operation_statuses()?;
    let identity = status[0].operation_id;
    assert_eq!(status[0].completed_work_units, 0);
    let before = signals.lock().unwrap().clone();

    assert!(close(&mut node, &supervisor).is_err());
    assert_eq!(supervisor.operation_statuses()?[0].operation_id, identity);
    assert_eq!(*signals.lock().unwrap(), before);
    assert_eq!(before, [QemuShutdownRung::Sigterm]);

    // The real retained process observer supplies closure. Expiry grants no
    // further signal, wait or replacement Original, but cannot hide this fact.
    closed.store(true, Ordering::Release);
    let completed = close(&mut node, &supervisor).unwrap_err();
    assert!(matches!(
        completed,
        QemuNodeError::ShutdownOriginal {
            completion: Some(_),
            completion_effect: false,
            ..
        }
    ));
    assert!(supervisor.operation_statuses()?.is_empty());
    assert_eq!(*signals.lock().unwrap(), before);

    // Only after BOTH histories were delivered can the existing used caller
    // finish actual RAM/body closure. Its independent health remains failed.
    assert!(node.shutdown_child()?.reaped);
    assert!(node.shutdown_health().is_err());
    assert!(
        node.advance_to_ceiling_report(Icount { retired: 31 })
            .is_err()
    );
    assert_eq!(*signals.lock().unwrap(), before);
    let unrelated = supervisor.begin(HostOperationClass::Cleanup)?;
    assert_eq!(unrelated.status()?.operation_id, identity + 1);
    Ok(())
}

#[test]
fn healthy_closure_returns_the_same_operation_record_without_restarting_on_reentry()
-> Result<(), Box<dyn Error>> {
    let (mut node, supervisor, _, signals) = fixture(false)?;
    assert!(close(&mut node, &supervisor)?.reaped);
    assert!(node.child_shutdown.completion_effect);
    assert!(node.child_shutdown.completion_failure.is_none());
    assert!(supervisor.operation_statuses()?.is_empty());
    let before = signals.lock().unwrap().clone();

    let repeated = node.shutdown_child()?;
    assert!(repeated.reaped);
    assert!(repeated.attempts.is_empty());
    assert_eq!(*signals.lock().unwrap(), before);
    assert!(node.shutdown_health().is_ok());
    let unrelated = supervisor.begin(HostOperationClass::Cleanup)?;
    assert_eq!(unrelated.status()?.operation_id, 2);
    Ok(())
}

#[test]
fn partial_nodeset_shutdown_keeps_both_actual_nodes_without_replaying_closed_peer()
-> Result<(), Box<dyn Error>> {
    let (healthy, _, _, healthy_signals) = fixture(false)?;
    let (refused, _, closed, refused_signals) = fixture(true)?;
    let first = NodeId {
        name: String::from("a-closed"),
    };
    let second = NodeId {
        name: String::from("b-retained"),
    };
    let mut nodes = crate::QemuNodeSet::new();
    nodes.insert(first.clone(), healthy);
    nodes.insert(second.clone(), refused);

    assert!(SimulationBackend::shutdown(&mut nodes).is_err());
    assert!(nodes.contains(&first));
    assert!(nodes.contains(&second));
    let healthy_before = healthy_signals.lock().unwrap().clone();
    let refused_before = refused_signals.lock().unwrap().clone();
    assert!(SimulationBackend::shutdown(&mut nodes).is_err());
    assert_eq!(*healthy_signals.lock().unwrap(), healthy_before);
    assert_eq!(*refused_signals.lock().unwrap(), refused_before);

    closed.store(true, Ordering::Release);
    assert!(SimulationBackend::shutdown(&mut nodes).is_err());
    assert!(nodes.contains(&first));
    assert!(nodes.contains(&second));
    SimulationBackend::shutdown(&mut nodes)?;
    assert!(!nodes.contains(&first));
    assert!(!nodes.contains(&second));
    assert_eq!(*healthy_signals.lock().unwrap(), healthy_before);
    assert_eq!(*refused_signals.lock().unwrap(), refused_before);
    Ok(())
}

#[test]
fn channel_timeout_preserves_actual_initiator_and_independent_shutdown_report()
-> Result<(), Box<dyn Error>> {
    let (mut node, _, _, _) = fixture(true)?;
    let first = QemuNodeChannelError::bounded_await_timeout(
        "component channel",
        "actual first failure",
        Duration::from_millis(1),
    );
    let failure = node
        .handle_qmp_channel_error::<()>(first.clone())
        .unwrap_err();
    let QemuNodeError::ShutdownAfterChannelFailure {
        first: retained,
        shutdown,
        ..
    } = failure
    else {
        panic!("the actual channel first must not be replaced by cleanup")
    };
    assert_eq!(retained, first);
    assert!(matches!(
        *shutdown,
        QemuNodeError::Shutdown {
            source: crate::QemuShutdownError::LeakedChild { .. }
        }
    ));
    assert!(node.shutdown_health().is_err());
    Ok(())
}

#[test]
fn actual_wait_exit_survives_post_refusal_and_stops_every_later_effect()
-> Result<(), Box<dyn Error>> {
    let (mut node, supervisor, _, signals) = fixture_with_poll_expiry(false, true)?;
    let failure = close(&mut node, &supervisor).unwrap_err();
    let QemuNodeError::ShutdownAndRam { first, ram } = failure else {
        panic!("process post and whole-body completion must both be returned");
    };
    let QemuNodeError::ShutdownOriginal {
        observations: process_observations,
        completion: process_completion,
        report: process_report,
        ..
    } = *first
    else {
        panic!("the actual wait post must survive whole-body completion");
    };
    assert!(process_report.reaped);
    assert!(process_observations[0].1.is_some());
    assert!(process_completion.is_none());
    let QemuNodeError::ShutdownOriginal {
        observations,
        completion,
        report,
        ..
    } = *ram
    else {
        panic!("actual wait output and independent Original refusal must survive")
    };
    assert!(report.reaped);
    assert_eq!(report.attempts.len(), 1);
    assert_eq!(report.attempts[0].rung, QemuShutdownRung::ControlQuit);
    assert_eq!(report.attempts[0].child, QemuChildWait::Exited);
    assert!(observations[0].1.is_some());
    assert!(completion.is_some());
    assert!(
        observations[1..]
            .iter()
            .all(|(before, after)| before.is_none() && after.is_none())
    );
    assert!(signals.lock().unwrap().is_empty());
    assert!(supervisor.operation_statuses()?.is_empty());

    assert!(node.shutdown_child()?.reaped);
    assert!(node.shutdown_health().is_err());
    assert!(signals.lock().unwrap().is_empty());
    let unrelated = supervisor.begin(HostOperationClass::Cleanup)?;
    assert_eq!(unrelated.status()?.operation_id, 2);
    Ok(())
}
