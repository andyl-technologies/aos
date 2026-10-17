//! Exercises pending-quantum refusal using a real page-source worker and socket.
//!
//! The quantum target is scripted; this component makes no native guest claim.

use super::*;
use crate::{
    QemuAsyncCrashEscalationTarget, QemuAsyncDriverError, QemuAsyncDriverHealthError,
    QemuAsyncDriverPolicy, QemuAsyncDriverRuntimeError, QemuAsyncDriverTargetError,
    QemuAsyncNodeStepTarget, QemuAsyncQuantumCompletion, QemuAsyncWait, QemuAsyncWaitOutcome,
    QemuCrashDetector, QemuHostIoRuntime, QemuNodeChannelError, QemuShutdownReport,
    run_bounded_qemu_node_step,
};
use crucible::{ExecutionHorizon, Icount};

use crate::qmp::checkpoint_paged_source_support as support;

struct PendingTarget {
    source: Arc<Mutex<QemuRamSourceService>>,
    started: bool,
    finished: bool,
    reaped: bool,
}

impl QemuAsyncCrashEscalationTarget for PendingTarget {
    fn shutdown_after_crash(&mut self) -> Result<QemuShutdownReport, QemuAsyncDriverTargetError> {
        self.reaped = true;
        panic!("a source-health failure must retain physical process disposition")
    }
}

impl QemuAsyncNodeStepTarget for PendingTarget {
    type PendingQuantum = ();

    fn operational_health(&self) -> Result<(), QemuAsyncDriverHealthError> {
        self.source
            .lock()
            .unwrap_or_else(|_| panic!("source inventory poisoned"))
            .check_health()
            .map_err(QemuAsyncDriverHealthError::ram_source)
    }

    fn start_quantum(&mut self, _: ExecutionHorizon) -> Result<(), QemuNodeChannelError> {
        self.started = true;
        Ok(())
    }

    fn finish_quantum(
        &mut self,
        _: &mut (),
    ) -> Result<QemuAsyncQuantumCompletion, QemuNodeChannelError> {
        self.finished = true;
        panic!("a failed source must not publish a guest cut")
    }
}

struct SourceRuntime {
    source: Arc<Mutex<QemuRamSourceService>>,
    socket: UnixStream,
    supervisor: HostOperationSupervisor,
    request: RamPageRequest,
    cancel_pending: bool,
    await_failure: bool,
}

impl QemuHostIoRuntime for SourceRuntime {
    fn host_operation_supervisor(&self) -> Option<&HostOperationSupervisor> {
        Some(&self.supervisor)
    }

    fn yield_to_control_plane(&mut self) -> Result<(), QemuAsyncDriverRuntimeError> {
        Ok(())
    }

    fn publish_current_execution_fingerprint(
        &mut self,
        _: Duration,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        panic!("a source failure must not publish a fingerprint")
    }

    fn repoll_child(
        &mut self,
        _: QemuAsyncWait,
        _: Duration,
    ) -> Result<QemuAsyncWaitOutcome, QemuAsyncDriverRuntimeError> {
        panic!("terminal source refusal must not renew a pending quantum")
    }

    fn await_child(
        &mut self,
        _: QemuAsyncWait,
        _: Duration,
    ) -> Result<QemuAsyncWaitOutcome, QemuAsyncDriverRuntimeError> {
        let map = |error: &dyn Error| {
            QemuAsyncDriverRuntimeError::new("real source refusal", error.to_string())
        };
        if self.cancel_pending {
            self.source
                .lock()
                .unwrap_or_else(|_| panic!("source inventory poisoned"))
                .cancel();
        } else {
            self.socket
                .write_all(&self.request.encode().map_err(|error| map(&error))?)
                .map_err(|error| map(&error))?;
        }
        let boundary = self
            .supervisor
            .begin(HostOperationClass::Preparation)
            .map_err(|error| map(&error))?;
        loop {
            if self
                .source
                .lock()
                .unwrap_or_else(|_| panic!("source inventory poisoned"))
                .worker
                .as_ref()
                .is_some_and(|worker| worker.is_finished())
            {
                break;
            }
            let slice = boundary.wait_slice().map_err(|error| map(&error))?;
            thread::sleep(slice.min(Duration::from_millis(1)));
        }
        boundary.complete().map_err(|error| map(&error))?;
        if self.await_failure {
            return Err(QemuAsyncDriverRuntimeError::new(
                "await actual source socket",
                "the failed source closed its transport",
            ));
        }
        // A real source refusal wins over a concurrent missing-report timeout.
        Ok(QemuAsyncWaitOutcome::TimedOut)
    }
}

#[test]
fn pending_quantum_preserves_real_source_failure_before_timeout_or_guest_cut()
-> Result<(), Box<dyn Error>> {
    pending_failure(false, false)
}

#[test]
fn canceling_real_source_during_pending_quantum_does_not_publish_a_guest_cut()
-> Result<(), Box<dyn Error>> {
    pending_failure(true, false)
}

#[test]
fn pending_quantum_preserves_original_source_cause_over_concurrent_transport_failure()
-> Result<(), Box<dyn Error>> {
    pending_failure(false, true)
}

fn pending_failure(cancel_pending: bool, await_failure: bool) -> Result<(), Box<dyn Error>> {
    let backing = Arc::new(support::ImmutableBacking::new(2)?);
    let binding = RamPageBinding {
        session: [1; 16],
        owner_incarnation: [2; 16],
        source_generation: 1,
        root_digest: *backing.root_record().digest().as_bytes(),
    };
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(5)),
    )?;
    let original = supervisor.outer_cap_binding()?;
    let (server, socket) = UnixStream::pair()?;
    let service = QemuRamSourceService::start(
        server,
        backing,
        binding,
        supervisor.clone(),
        crucible_linux_resource::host_services::HostServiceAllocator::new(1, 4, 8 * 1024 * 1024)?,
    )?;
    let source = Arc::new(Mutex::new(service));
    let mut target = PendingTarget {
        source: Arc::clone(&source),
        started: false,
        finished: false,
        reaped: false,
    };
    let mut runtime = SourceRuntime {
        cancel_pending,
        await_failure,
        source: Arc::clone(&source),
        socket,
        supervisor: supervisor.clone(),
        request: RamPageRequest {
            binding: RamPageBinding {
                source_generation: 2,
                ..binding
            },
            sequence: 1,
            region_ordinal: 0,
            page_index: 0,
        },
    };

    let error = run_bounded_qemu_node_step(
        &mut target,
        &mut runtime,
        QemuAsyncDriverPolicy::fast_test(),
        &QemuCrashDetector::new("source-component"),
        ExecutionHorizon {
            icount: Icount { retired: 1 },
        },
    )
    .err()
    .ok_or_else(|| io::Error::other("failed source unexpectedly completed"))?;
    assert!(
        matches!(error, QemuAsyncDriverError::OperationalHealth(ref error)
        if if cancel_pending {
            matches!(error.source_failure(), QemuRamSourceError::Canceled)
        } else {
            matches!(error.source_failure(), QemuRamSourceError::Ownership)
        })
    );
    assert!(target.started);
    assert!(!target.finished);
    assert!(!target.reaped);
    assert_eq!(supervisor.outer_cap_binding()?, original);

    drop(target);
    drop(runtime);
    let service = Arc::try_unwrap(source)
        .map_err(|_| io::Error::other("source borrower retained"))?
        .into_inner()
        .map_err(|_| io::Error::other("source inventory poisoned"))?;
    if cancel_pending {
        // Stopping an intentionally canceled idle source remains ordinary
        // cleanup. The pending quantum already observed its cancellation.
        service.stop()?;
        return Ok(());
    }
    let terminal = service
        .stop()
        .err()
        .ok_or_else(|| io::Error::other("original worker failure disappeared"))?;
    assert!(
        matches!(terminal.source, QemuRamSourceError::WorkerFailed(ref source)
        if matches!(source.as_ref(), QemuRamSourceError::Ownership))
    );
    terminal.service.stop()?;
    Ok(())
}
