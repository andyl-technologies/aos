//! Tests for live QEMU node lifecycle and fault transport.

use std::collections::VecDeque;
use std::error::Error;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::os::fd::{AsFd, FromRawFd, OwnedFd};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crucible::{
    CheckpointKind, ContentHash, EventLogCoverageObservation, ExecutionHorizon, GdbListen, NodeId,
    event_log_coverage_projection,
};
use crucible_shmem::{
    CoverageEntry, FAULT_COMMAND_ABI_MAJOR, FAULT_COMMAND_ABI_MINOR,
    FAULT_COMMAND_SEMANTIC_VERSION, FaultBoundaryPhase, FaultCapabilityScope, FaultCommandKind,
    FaultEventHeaderV1, FaultEventOutcomeV1, FaultResultHeaderV1, RegionAllocation, RegionConfig,
    mmap_setup_region,
};

use crate::{
    QemuAsyncDriverRuntimeError, QemuAsyncWait, QemuAsyncWaitOutcome, QemuNodeSet,
    QemuQuantumOperation,
};

use super::*;

#[path = "node/tests/child_exit.rs"]
mod child_exit;
#[path = "node/tests/fault_command.rs"]
mod fault_command;
#[path = "node/tests/host_io_runtime.rs"]
pub(crate) mod host_io_runtime;
#[path = "node/tests/hot_fork.rs"]
mod hot_fork;
#[path = "node/tests/sequence_restore.rs"]
mod sequence_restore;
#[path = "node/tests/shutdown_and_preemption.rs"]
mod shutdown_and_preemption;

type SharedLog = Arc<Mutex<Vec<ChannelCall>>>;
type SharedFaultCommands = Arc<Mutex<Vec<(FaultCommandHeaderV1, Vec<u8>)>>>;
type SharedFaultEvents = Arc<Mutex<VecDeque<DequeuedFaultEvent>>>;
type SharedRetainedStreamState = Arc<Mutex<Option<(crate::QmpDescriptorName, u64, u64, bool)>>>;
type SharedChildFilesState = Arc<Mutex<Option<(Vec<crate::QmpHotForkChildFile>, u64, u64, u64)>>>;
type SharedProcessContractState = Arc<
    Mutex<
        Option<(
            crate::QmpHotForkChildProcessContractNames,
            crate::QmpHotForkChildProcessContractIdentity,
            u64,
            u64,
        )>,
    >,
>;

#[derive(Clone, Debug, PartialEq, Eq)]
enum ChannelCall {
    ShmemCurrentIcount,
    ShmemHotForkIdentity,
    ShmemHotForkBarrier,
    ShmemHotForkCapture,
    HostYield,
    HostAwait {
        wait: QemuAsyncWait,
        timeout: Duration,
        outcome: QemuAsyncWaitOutcome,
    },
    ShmemStart(u64),
    ShmemFinish(u64),
    ShmemPreemption(SchedulerPreemptionCommand),
    ShmemDeliver {
        node: String,
        payload: Vec<u8>,
    },
    ShmemEmit,
    ShmemIdle,
    ShmemFingerprint,
    ShmemSelectableReply(u64),
    HostFingerprintBoundary,
    HostCheckpointClearWhileStopped,
    HostCheckpointAbort,
    HostFaultEventLimit {
        maximum_local_records: usize,
        canonical_current_offset: usize,
        configured_event_records: usize,
    },
    QmpStop,
    QmpContinue,
    QmpHotForkReadiness,
    QmpHotForkThreadInventory,
    QmpHotForkRcuInventory,
    QmpHotForkAioInventory,
    QmpHotForkAioHandlerInventory,
    QmpHotForkBlockBackendInventory,
    QmpHotForkPluginResourceInventory,
    QmpHotForkPluginBarrier,
    QmpHotForkInstallDescriptor(String, crucible_shmem::SetupRegionBackingIdentity),
    QmpHotForkCloseDescriptor(String, crucible_shmem::SetupRegionBackingIdentity),
    QmpHotForkInstallDiagnostics {
        name: String,
        socket_cookie: u64,
        template_generation: u64,
    },
    QmpHotForkCloseDiagnostics {
        name: String,
        socket_cookie: u64,
    },
    QmpHotForkInstallChildQmp {
        name: String,
        socket_cookie: u64,
        template_generation: u64,
    },
    QmpHotForkCloseChildQmp {
        name: String,
        socket_cookie: u64,
    },
    QmpHotForkInstallChildConsole {
        name: String,
        socket_cookie: u64,
        template_generation: u64,
    },
    QmpHotForkCloseChildConsole {
        name: String,
        socket_cookie: u64,
    },
    QmpHotForkInstallPluginEndpoints {
        control_name: String,
        wake_name: String,
        identity: crate::QmpHotForkPluginEndpointIdentity,
        private_ring_generation: u64,
    },
    QmpHotForkClosePluginEndpoints {
        control_name: String,
        wake_name: String,
        identity: crate::QmpHotForkPluginEndpointIdentity,
    },
    QmpHotForkBottomHalfInventory,
    QmpHotForkMutexInventory,
    QmpHotForkTimerInventory,
    QmpHotForkMonitorInventory,
    QmpHotForkTemplate,
    QmpHotForkInstallProcessContract,
    QmpHotForkReleaseProcessContract,
    QmpHotForkChildProcessContract,
    QmpHotForkInstallChildFiles,
    QmpHotForkReleaseChildFiles,
    QmpHotForkChildFiles,
    HostHotForkContinuationClone,
    QmpHotFork,
    QmpTerminalLifecycle {
        action: ContentHash,
        evidence: ContentHash,
        process_generation: u64,
    },
    QmpExactSave(ContentHash),
    QmpExactDelete(ContentHash),
    QmpActivateDebugGuest,
    PluginQuit,
    QmpQuit,
}

#[derive(Clone)]
struct ScriptedPluginControl {
    log: SharedLog,
    fail_quit: bool,
}

#[derive(Clone)]
struct ScriptedShmemHotPath {
    log: SharedLog,
    fail_advance: bool,
    coverage_enabled: bool,
    quantum_coverage: Arc<Mutex<VecDeque<Vec<ObservableEvent>>>>,
    teardown_coverage: Arc<Mutex<Vec<ObservableEvent>>>,
    fault_commands: SharedFaultCommands,
    stale_fault_results: Arc<Mutex<VecDeque<DequeuedFaultResult>>>,
    fault_events: SharedFaultEvents,
    fingerprint_retry_countdown: Arc<Mutex<u8>>,
    hot_fork_setup_identity: Option<crucible_shmem::SetupRegionBackingIdentity>,
    hot_fork_ring_image: Option<(
        crucible_shmem::MappedRingIoBarrierSnapshot,
        crucible_shmem::HotForkRingImage,
    )>,
}

#[derive(Clone)]
struct ScriptedHostIoRuntime {
    log: SharedLog,
    outcomes: VecDeque<QemuAsyncWaitOutcome>,
    fault_results: VecDeque<DequeuedFaultResult>,
    staged_fault_events: Vec<DequeuedFaultEvent>,
    fingerprint_fault_events: VecDeque<DequeuedFaultEvent>,
    fail_hot_fork_clone: bool,
}

#[derive(Clone)]
struct ScriptedQmpMachineControl {
    log: SharedLog,
    process_id: u32,
    fail_stop: bool,
    fail_snapshot: bool,
    timeout_snapshot: bool,
    plugin_resources: Option<crate::QmpHotForkPluginResourceInventory>,
    plugin_barriers: Option<Arc<Mutex<VecDeque<crate::QmpHotForkPluginBarrierState>>>>,
    last_plugin_barrier: Arc<Mutex<Option<crate::QmpHotForkPluginBarrierState>>>,
    private_ring_state: Arc<
        Mutex<
            Option<(
                crate::QmpDescriptorName,
                crucible_shmem::SetupRegionBackingIdentity,
                u64,
            )>,
        >,
    >,
    diagnostic_state: SharedRetainedStreamState,
    child_qmp_state: SharedRetainedStreamState,
    child_console_state: SharedRetainedStreamState,
    process_contract_state: SharedProcessContractState,
    child_files_state: SharedChildFilesState,
    fail_descriptor_install: bool,
    fail_descriptor_close: bool,
    fail_endpoint_install: bool,
    mismatch_endpoint_disposition: bool,
    mismatch_request_basis: bool,
    serve_child_qmp: bool,
    template_query_count: Arc<Mutex<u64>>,
    hot_fork_script: HotForkScript,
}

#[derive(Clone, Copy)]
enum DescriptorScript {
    Success,
    SchedulerContinuation,
    InstallFailure,
    CloseFailure,
    EndpointInstallFailure,
    EndpointDispositionMismatch,
    ForkRejected,
    ForkIndeterminate,
    ForkParentDispositionFailed,
    HostIoCloneFailure,
    RequestBasisMismatch,
}

#[derive(Clone, Copy)]
enum HotForkScript {
    Forked,
    Rejected,
    Indeterminate,
    ParentDispositionFailed,
}

#[derive(Debug, PartialEq, Eq)]
struct ScriptedHotForkChildAuthority {
    basis: crate::QemuHotForkChildProcessBasis,
}

#[derive(Debug)]
struct ScriptedExternalProcessControl {
    basis: crate::QemuHotForkChildProcessBasis,
}

impl crate::QemuNodeExternalProcessControl for ScriptedExternalProcessControl {
    fn hot_fork_process_basis(&self) -> crate::QemuHotForkChildProcessBasis {
        self.basis
    }

    fn process_id(&self) -> u32 {
        self.basis.child_process_id()
    }

    fn reaped(&self) -> bool {
        false
    }

    fn try_wait_natural_exit(
        &mut self,
    ) -> Result<Option<std::process::ExitStatus>, crate::QemuShutdownTargetError> {
        Ok(None)
    }

    fn send_sigterm(&mut self) -> Result<(), crate::QemuShutdownTargetError> {
        Ok(())
    }

    fn send_sigkill(&mut self) -> Result<(), crate::QemuShutdownTargetError> {
        Ok(())
    }

    fn wait_for_exit(
        &mut self,
        _rung: crate::QemuShutdownRung,
        _timeout: Duration,
    ) -> Result<crate::QemuChildWait, crate::QemuShutdownTargetError> {
        Ok(crate::QemuChildWait::StillRunning)
    }

    fn reap(
        &mut self,
        _timeout: Duration,
    ) -> Result<crate::QemuReap, crate::QemuShutdownTargetError> {
        Ok(crate::QemuReap::StillAlive)
    }
}

#[derive(Default)]
struct ScriptedHotForkChildOwner {
    fail: bool,
    retained: Vec<crate::QemuHotForkChildProcessBasis>,
}

struct ScriptedHotForkTargetOwner {
    contract: crate::QemuChildProcessContract,
    retained: Vec<crate::QemuHotForkChildProcessBasis>,
}

impl crate::QemuHotForkChildProcessOwner for ScriptedHotForkChildOwner {
    type Authority = ScriptedHotForkChildAuthority;

    fn retain_hot_fork_child(
        &mut self,
        basis: crate::QemuHotForkChildProcessBasis,
    ) -> Result<Self::Authority, QemuNodeChannelError> {
        self.retained.push(basis);
        if self.fail {
            return Err(QemuNodeChannelError::new(
                "retain forked child process",
                "injected child process authentication failure",
            ));
        }
        Ok(ScriptedHotForkChildAuthority { basis })
    }
}

impl crate::QemuHotForkChildProcessOwner for ScriptedHotForkTargetOwner {
    type Authority = ScriptedHotForkChildAuthority;

    fn retain_hot_fork_child(
        &mut self,
        basis: crate::QemuHotForkChildProcessBasis,
    ) -> Result<Self::Authority, QemuNodeChannelError> {
        self.retained.push(basis);
        Ok(ScriptedHotForkChildAuthority { basis })
    }
}

#[cfg(target_os = "linux")]
fn serve_scripted_hot_fork_child_qmp(
    descriptor: std::os::fd::BorrowedFd<'_>,
    name: &crate::QmpDescriptorName,
    socket_cookie: u64,
    template_generation: u64,
) -> Result<(), QemuNodeChannelError> {
    let descriptor = descriptor.try_clone_to_owned().map_err(|source| {
        QemuNodeChannelError::new("clone scripted child QMP endpoint", source.to_string())
    })?;
    let mut stream = std::os::unix::net::UnixStream::from(descriptor);
    let response = format!(
        r#"{{"return":{{"schema-version":8,"generation":1,"template-generation":{template_generation},"monitor-generation":7,"staged":true,"fdname":"{}","socket-cookie":{socket_cookie},"retained-fd":33,"resource-plan-bound":true,"nonblocking-unix-stream":true,"monitor-basis-bound":true,"monitor-disposition-bound":true,"monitor-socket-resources-bound":true,"reinitializer-prepared":true,"reinitialized":true,"disposition-complete":true,"readiness-proof-acknowledged":true}}}}"#,
        name.as_str(),
    );
    std::thread::Builder::new()
        .name(String::from("scripted-hot-fork-child-qmp"))
        .spawn(move || {
            if stream.set_nonblocking(false).is_err() {
                return;
            }
            if stream
                .write_all(b"{\"QMP\":{\"version\":{},\"capabilities\":[]}}\r\n")
                .is_err()
            {
                return;
            }
            let reader_stream = match stream.try_clone() {
                Ok(stream) => stream,
                Err(_) => return,
            };
            let mut reader = BufReader::new(reader_stream);
            let mut request = String::new();
            if reader
                .read_line(&mut request)
                .ok()
                .filter(|read| *read > 0)
                .is_none()
            {
                return;
            }
            if stream.write_all(b"{\"return\":{}}\r\n").is_err() {
                return;
            }
            request.clear();
            if reader
                .read_line(&mut request)
                .ok()
                .filter(|read| *read > 0)
                .is_none()
            {
                return;
            }
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.write_all(b"\r\n");
        })
        .map(|_handle| ())
        .map_err(|source| {
            QemuNodeChannelError::new("spawn scripted child QMP endpoint", source.to_string())
        })
}

impl QemuPluginIpcControlChannel for ScriptedPluginControl {
    fn send_quit(&mut self) -> Result<(), QemuNodeChannelError> {
        self.log.lock().unwrap().push(ChannelCall::PluginQuit);
        if self.fail_quit {
            return Err(QemuNodeChannelError::new("send_quit", "control closed"));
        }
        Ok(())
    }
}

impl QemuShmemHotPathChannel for ScriptedShmemHotPath {
    #[cfg(target_os = "linux")]
    fn clone_hot_fork_host_continuation(
        &self,
        _mapping: &crate::QemuHotForkPrivateRingMapping,
    ) -> Result<Box<dyn QemuShmemHotPathChannel>, QemuNodeChannelError> {
        Ok(Box::new(self.clone()))
    }

    fn arm_hot_fork_child_ceiling(
        &mut self,
        _inherited_icount: u64,
    ) -> Result<(), QemuNodeChannelError> {
        // The scripted channel has no slot to arm; installation proceeds.
        Ok(())
    }

    fn hot_fork_setup_region_identity(
        &mut self,
    ) -> Result<crucible_shmem::SetupRegionBackingIdentity, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::ShmemHotForkIdentity);
        self.hot_fork_setup_identity.ok_or_else(|| {
            QemuNodeChannelError::new(
                "query hot-fork setup-region identity",
                "scripted setup identity is unavailable",
            )
        })
    }

    fn hot_fork_ring_io_snapshot(
        &mut self,
    ) -> Result<crucible_shmem::MappedRingIoBarrierSnapshot, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::ShmemHotForkBarrier);
        self.hot_fork_ring_image
            .as_ref()
            .map(|(snapshot, _image)| *snapshot)
            .ok_or_else(|| {
                QemuNodeChannelError::new(
                    "query hot-fork ring I/O barrier",
                    "scripted ring image is unavailable",
                )
            })
    }

    fn capture_hot_fork_ring_image(
        &mut self,
        maximum_bytes: usize,
    ) -> Result<crucible_shmem::HotForkRingImage, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::ShmemHotForkCapture);
        let image = self
            .hot_fork_ring_image
            .as_ref()
            .map(|(_snapshot, image)| image)
            .ok_or_else(|| {
                QemuNodeChannelError::new(
                    "capture hot-fork ring image",
                    "scripted ring image is unavailable",
                )
            })?;
        let required = image.canonical_len().map_err(|source| {
            QemuNodeChannelError::new("measure hot-fork ring image", source.to_string())
        })?;
        if required > maximum_bytes {
            return Err(QemuNodeChannelError::new(
                "capture hot-fork ring image",
                "scripted ring image exceeds its bound",
            ));
        }
        Ok(image.clone())
    }

    fn checkpoint_network_transport(
        &mut self,
    ) -> Result<crate::QemuNetworkTransportCheckpoint, QemuNodeChannelError> {
        Ok(crate::QemuNetworkTransportCheckpoint {
            inbound: crucible_shmem::SpscRingSnapshot { frames: Vec::new() },
            outbound: crucible_shmem::SpscRingSnapshot { frames: Vec::new() },
            queue_capacity: crucible_shmem::DEFAULT_QUEUE_CAPACITY,
            router_slot: crucible_shmem::SLOT_NET_ROUTER as u32,
            next_router_inbound_sequence: 0,
            next_host_outbound_sequence: 0,
            next_plugin_outbound_sequence: 0,
        })
    }

    fn restore_network_transport(
        &mut self,
        _checkpoint: &crate::QemuNetworkTransportCheckpoint,
    ) -> Result<(), QemuNodeChannelError> {
        Ok(())
    }

    fn coverage_enabled(&self) -> bool {
        self.coverage_enabled
    }

    fn current_icount(&mut self) -> Result<Icount, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::ShmemCurrentIcount);
        Ok(Icount { retired: 11 })
    }

    fn logical_time_calibration(
        &mut self,
    ) -> Result<QemuLogicalTimeCalibration, QemuNodeChannelError> {
        Ok(QemuLogicalTimeCalibration {
            logical_icount: 11,
            raw_icount: 11,
        })
    }

    fn start_quantum(
        &mut self,
        horizon: ExecutionHorizon,
    ) -> Result<QemuNodePendingQuantum, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::ShmemStart(horizon.icount.retired));
        if self.fail_advance {
            return Err(QemuNodeChannelError::new(
                "advance_to_horizon",
                "futex wake failed",
            ));
        }
        Ok(QemuNodePendingQuantum::new(horizon.icount.retired))
    }

    fn poll_quantum(
        &mut self,
        pending: &mut QemuNodePendingQuantum,
    ) -> Result<QemuAsyncQuantumCompletion, QemuNodeChannelError> {
        let horizon = *pending.downcast_mut::<u64>("finish_quantum")?;
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::ShmemFinish(horizon));
        if let Some(events) = self.quantum_coverage.lock().unwrap().pop_front() {
            self.teardown_coverage.lock().unwrap().extend(events);
        }
        Ok(QemuAsyncQuantumCompletion {
            ceiling: Icount { retired: horizon },
            outcome: AdvanceOutcome::ReachedHorizon,
            final_state: QemuNodeIdleState {
                current_icount: Icount { retired: horizon },
                next_deadline: None,
            },
            inbound_frames_consumed: 0,
            emitted_frames: Vec::new(),
            operations: vec![
                QemuQuantumOperation::StoreSchedulerCeiling,
                QemuQuantumOperation::FutexWake,
                QemuQuantumOperation::ObservePluginReport,
            ],
        })
    }

    fn publish_preemption_command(
        &mut self,
        command: SchedulerPreemptionCommand,
    ) -> Result<(), QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::ShmemPreemption(command));
        Ok(())
    }

    fn enqueue_selectable_reply(
        &mut self,
        _pending: &crucible_protocol::selectable_catalog_plan::SelectablePlanPendingRequest,
        reply: &crucible_protocol::SelectionReply,
    ) -> Result<(), QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::ShmemSelectableReply(reply.sequence()));
        Ok(())
    }

    fn enqueue_fault_command(
        &mut self,
        header: FaultCommandHeaderV1,
        payload: &[u8],
    ) -> Result<(), QemuNodeChannelError> {
        self.fault_commands
            .lock()
            .unwrap()
            .push((header, payload.to_vec()));
        Ok(())
    }

    fn dequeue_fault_result(
        &mut self,
    ) -> Result<Option<DequeuedFaultResult>, QemuNodeChannelError> {
        Ok(self.stale_fault_results.lock().unwrap().pop_front())
    }

    fn dequeue_fault_event(&mut self) -> Result<Option<DequeuedFaultEvent>, QemuNodeChannelError> {
        Ok(self.fault_events.lock().unwrap().pop_front())
    }

    fn fault_event_pending(&mut self) -> Result<bool, QemuNodeChannelError> {
        Ok(!self.fault_events.lock().unwrap().is_empty())
    }

    fn fault_event_count(&mut self) -> Result<usize, QemuNodeChannelError> {
        Ok(self.fault_events.lock().unwrap().len())
    }

    fn snapshot_fault_events(
        &mut self,
        destination: &mut Vec<DequeuedFaultEvent>,
        canonical_payload_bytes: &mut usize,
        configured_payload_bytes: usize,
        configured_inline_payload_bytes: usize,
    ) -> Result<(), QemuNodeError> {
        let events = self.fault_events.lock().unwrap();
        fault_event_budget::snapshot_scripted_fault_events(
            &events,
            destination,
            canonical_payload_bytes,
            configured_payload_bytes,
            configured_inline_payload_bytes,
        )
    }

    fn drain_observable_events(&mut self) -> Result<Vec<ObservableEvent>, QemuNodeChannelError> {
        Ok(std::mem::take(&mut *self.teardown_coverage.lock().unwrap()))
    }

    fn deliver_frame(&mut self, input: BackendInput) -> Result<(), QemuNodeChannelError> {
        self.log.lock().unwrap().push(ChannelCall::ShmemDeliver {
            node: input.node.name,
            payload: input.payload,
        });
        Ok(())
    }

    fn emit_frame(&mut self) -> Result<Option<QemuNodeEmittedFrame>, QemuNodeChannelError> {
        self.log.lock().unwrap().push(ChannelCall::ShmemEmit);
        Ok(Some(QemuNodeEmittedFrame {
            source: node_id("vm-a"),
            destination: node_id("vm-b"),
            emit_icount: Icount { retired: 17 },
            sequence: 7,
            payload: vec![8, 9],
        }))
    }

    fn idle_state(&mut self) -> Result<QemuNodeIdleState, QemuNodeChannelError> {
        self.log.lock().unwrap().push(ChannelCall::ShmemIdle);
        Ok(QemuNodeIdleState {
            current_icount: Icount { retired: 13 },
            next_deadline: Some(Icount { retired: 21 }),
        })
    }

    fn execution_fingerprint(&mut self) -> Result<ExecutionFingerprint, QemuNodeChannelError> {
        self.log.lock().unwrap().push(ChannelCall::ShmemFingerprint);
        let mut retry_countdown = self.fingerprint_retry_countdown.lock().unwrap();
        if *retry_countdown > 0 {
            *retry_countdown -= 1;
            return Err(QemuNodeChannelError::retryable(
                "execution_fingerprint",
                "scripted sample is stale",
            ));
        }
        Ok(ExecutionFingerprint {
            hash: content_hash("fingerprint", "vm-a"),
        })
    }

    fn fingerprint_sample(&mut self) -> Result<QemuFingerprintSample, QemuNodeChannelError> {
        let mut sample = QemuFingerprintSample {
            sample_icount: 11,
            vcpu_count: 1,
            rr_switch_quantum: 4_096,
            ..QemuFingerprintSample::default()
        };
        sample.vcpus[0].register_file_bytes = 1;
        Ok(sample)
    }
}

impl QemuQmpMachineControlChannel for ScriptedQmpMachineControl {
    fn stop_for_checkpoint(&mut self) -> Result<(), QemuNodeChannelError> {
        self.log.lock().unwrap().push(ChannelCall::QmpStop);
        if self.fail_stop {
            return Err(QemuNodeChannelError::new(
                "stop_for_checkpoint",
                "injected QMP stop failure",
            ));
        }
        Ok(())
    }

    fn resume_after_checkpoint(&mut self) -> Result<(), QemuNodeChannelError> {
        self.log.lock().unwrap().push(ChannelCall::QmpContinue);
        Ok(())
    }

    fn query_hot_fork_readiness(
        &mut self,
    ) -> Result<crate::QmpHotForkReadiness, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkReadiness);
        crate::QmpHotForkReadiness::from_acknowledged_proofs(7).ok_or_else(|| {
            QemuNodeChannelError::new(
                "query_hot_fork_readiness",
                "scripted readiness bitmap is invalid",
            )
        })
    }

    fn query_hot_fork_thread_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkThreadInventory, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkThreadInventory);
        Ok(crate::QmpHotForkThreadInventory::one_coordinator(
            self.process_id,
        ))
    }

    fn query_hot_fork_rcu_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkRcuInventory, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkRcuInventory);
        Ok(crate::QmpHotForkRcuInventory::from_reader_ids(&[
            self.process_id
        ]))
    }

    fn query_hot_fork_aio_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkAioInventory, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkAioInventory);
        Ok(crate::QmpHotForkAioInventory::one_idle(1, self.process_id))
    }

    fn query_hot_fork_aio_handler_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkAioHandlerInventory, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkAioHandlerInventory);
        Ok(crate::QmpHotForkAioHandlerInventory::one_read(1, 1, 0))
    }

    fn query_hot_fork_block_backend_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkBlockBackendInventory, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkBlockBackendInventory);
        Ok(crate::QmpHotForkBlockBackendInventory::one_hidden(1, 1))
    }

    fn query_hot_fork_plugin_resource_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkPluginResourceInventory, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkPluginResourceInventory);
        self.plugin_resources.clone().ok_or_else(|| {
            QemuNodeChannelError::new(
                "query_hot_fork_plugin_resource_inventory",
                "scripted plugin-resource inventory is unavailable",
            )
        })
    }

    fn query_hot_fork_plugin_barrier(
        &mut self,
    ) -> Result<crate::QmpHotForkPluginBarrierState, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkPluginBarrier);
        let barrier = self
            .plugin_barriers
            .as_ref()
            .ok_or_else(|| {
                QemuNodeChannelError::new(
                    "query_hot_fork_plugin_barrier",
                    "scripted plugin barrier is unavailable",
                )
            })?
            .lock()
            .unwrap()
            .pop_front()
            .ok_or_else(|| {
                QemuNodeChannelError::new(
                    "query_hot_fork_plugin_barrier",
                    "scripted plugin barrier sequence is exhausted",
                )
            })?;
        *self.last_plugin_barrier.lock().unwrap() = Some(barrier);
        Ok(barrier)
    }

    fn install_hot_fork_private_ring_descriptor(
        &mut self,
        name: &crate::QmpDescriptorName,
        _descriptor: std::os::fd::BorrowedFd<'_>,
        identity: crucible_shmem::SetupRegionBackingIdentity,
    ) -> Result<(), QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkInstallDescriptor(
                name.as_str().to_owned(),
                identity,
            ));
        if self.fail_descriptor_install {
            return Err(QemuNodeChannelError::new(
                "install hot-fork private ring descriptor",
                "injected descriptor transfer failure",
            ));
        }
        *self.private_ring_state.lock().unwrap() = Some((name.clone(), identity, 1));
        Ok(())
    }

    fn close_hot_fork_private_ring_descriptor(
        &mut self,
        name: &crate::QmpDescriptorName,
        identity: crucible_shmem::SetupRegionBackingIdentity,
    ) -> Result<(), QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkCloseDescriptor(
                name.as_str().to_owned(),
                identity,
            ));
        if self.fail_descriptor_close {
            return Err(QemuNodeChannelError::new(
                "close hot-fork private ring descriptor",
                "injected descriptor close failure",
            ));
        }
        *self.private_ring_state.lock().unwrap() = None;
        Ok(())
    }

    fn query_hot_fork_private_rings(
        &mut self,
    ) -> Result<crate::QmpHotForkPrivateRingState, QemuNodeChannelError> {
        let state = self.private_ring_state.lock().unwrap();
        let (name, identity, generation) = state.as_ref().ok_or_else(|| {
            QemuNodeChannelError::new(
                "query hot-fork private rings",
                "scripted private-ring stage is absent",
            )
        })?;
        Ok(crate::QmpHotForkPrivateRingState::one_template_staged(
            *generation,
            1,
            name.clone(),
            identity.device(),
            identity.inode(),
            identity.length(),
        ))
    }

    fn install_hot_fork_plugin_endpoints(
        &mut self,
        control_name: &crate::QmpDescriptorName,
        _control: std::os::fd::BorrowedFd<'_>,
        wake_name: &crate::QmpDescriptorName,
        _wake: std::os::fd::BorrowedFd<'_>,
        identity: crate::QmpHotForkPluginEndpointIdentity,
        private_ring_generation: u64,
    ) -> Result<crate::QmpHotForkPluginEndpointState, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkInstallPluginEndpoints {
                control_name: control_name.as_str().to_owned(),
                wake_name: wake_name.as_str().to_owned(),
                identity,
                private_ring_generation,
            });
        if self.fail_endpoint_install {
            return Err(QemuNodeChannelError::new(
                "install hot-fork plugin endpoints",
                "injected endpoint transfer failure",
            ));
        }
        let plugin_barrier = self.last_plugin_barrier.lock().unwrap().ok_or_else(|| {
            QemuNodeChannelError::new(
                "install hot-fork plugin endpoints",
                "scripted plugin barrier was not queried before endpoint staging",
            )
        })?;
        let endpoint_barrier = if self.mismatch_endpoint_disposition {
            crate::QmpHotForkPluginBarrierState::one_quiescent(
                plugin_barrier.generation() + 1,
                plugin_barrier.ring_count(),
            )
        } else {
            plugin_barrier
        };
        let mut diagnostics = self.diagnostic_state.lock().unwrap();
        let Some((_name, _socket_cookie, _template_generation, bound)) = diagnostics.as_mut()
        else {
            return Err(QemuNodeChannelError::new(
                "install hot-fork plugin endpoints",
                "scripted diagnostics stage is absent",
            ));
        };
        *bound = true;
        let mut child_qmp = self.child_qmp_state.lock().unwrap();
        let Some((_name, _socket_cookie, _template_generation, bound)) = child_qmp.as_mut() else {
            return Err(QemuNodeChannelError::new(
                "install hot-fork plugin endpoints",
                "scripted child QMP stage is absent",
            ));
        };
        *bound = true;
        let mut child_console = self.child_console_state.lock().unwrap();
        let Some((_name, _socket_cookie, _template_generation, bound)) = child_console.as_mut()
        else {
            return Err(QemuNodeChannelError::new(
                "install hot-fork plugin endpoints",
                "scripted child console stage is absent",
            ));
        };
        *bound = true;
        Ok(crate::QmpHotForkPluginEndpointState::one_template_staged(
            1,
            1,
            control_name.clone(),
            wake_name.clone(),
            identity,
            private_ring_generation,
            endpoint_barrier,
        ))
    }

    fn close_hot_fork_plugin_endpoints(
        &mut self,
        control_name: &crate::QmpDescriptorName,
        wake_name: &crate::QmpDescriptorName,
        identity: crate::QmpHotForkPluginEndpointIdentity,
    ) -> Result<(), QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkClosePluginEndpoints {
                control_name: control_name.as_str().to_owned(),
                wake_name: wake_name.as_str().to_owned(),
                identity,
            });
        if self.fail_descriptor_close {
            return Err(QemuNodeChannelError::new(
                "close hot-fork plugin endpoints",
                "injected endpoint close failure",
            ));
        }
        if let Some((_name, _socket_cookie, _template_generation, bound)) =
            self.diagnostic_state.lock().unwrap().as_mut()
        {
            *bound = false;
        }
        if let Some((_name, _socket_cookie, _template_generation, bound)) =
            self.child_qmp_state.lock().unwrap().as_mut()
        {
            *bound = false;
        }
        if let Some((_name, _socket_cookie, _template_generation, bound)) =
            self.child_console_state.lock().unwrap().as_mut()
        {
            *bound = false;
        }
        Ok(())
    }

    fn install_hot_fork_child_diagnostics(
        &mut self,
        name: &crate::QmpDescriptorName,
        descriptor: std::os::fd::BorrowedFd<'_>,
        socket_cookie: u64,
        template_generation: u64,
    ) -> Result<crate::QmpHotForkChildDiagnosticState, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkInstallDiagnostics {
                name: name.as_str().to_owned(),
                socket_cookie,
                template_generation,
            });
        if self.fail_descriptor_install {
            return Err(QemuNodeChannelError::new(
                "install hot-fork child diagnostics",
                "injected descriptor transfer failure",
            ));
        }
        let mut diagnostic_writer = std::os::unix::net::UnixStream::from(
            descriptor.try_clone_to_owned().map_err(|source| {
                QemuNodeChannelError::new(
                    "install hot-fork child diagnostics",
                    format!("clone scripted child diagnostics endpoint failed: {source}"),
                )
            })?,
        );
        diagnostic_writer
            .write_all(b"scripted child diagnostics")
            .map_err(|source| {
                QemuNodeChannelError::new(
                    "install hot-fork child diagnostics",
                    format!("write scripted child diagnostics failed: {source}"),
                )
            })?;
        let state = crate::QmpHotForkChildDiagnosticState::one_template_staged(
            1,
            template_generation,
            name.clone(),
            socket_cookie,
            32,
            false,
        );
        *self.diagnostic_state.lock().unwrap() =
            Some((name.clone(), socket_cookie, template_generation, false));
        Ok(state)
    }

    fn close_hot_fork_child_diagnostics(
        &mut self,
        name: &crate::QmpDescriptorName,
        socket_cookie: u64,
    ) -> Result<(), QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkCloseDiagnostics {
                name: name.as_str().to_owned(),
                socket_cookie,
            });
        if self.fail_descriptor_close {
            return Err(QemuNodeChannelError::new(
                "close hot-fork child diagnostics",
                "injected descriptor close failure",
            ));
        }
        *self.diagnostic_state.lock().unwrap() = None;
        Ok(())
    }

    fn query_hot_fork_child_diagnostics(
        &mut self,
    ) -> Result<crate::QmpHotForkChildDiagnosticState, QemuNodeChannelError> {
        let state = self.diagnostic_state.lock().unwrap();
        let (name, socket_cookie, template_generation, bound) =
            state.as_ref().ok_or_else(|| {
                QemuNodeChannelError::new(
                    "query hot-fork child diagnostics",
                    "scripted diagnostics stage is absent",
                )
            })?;
        Ok(crate::QmpHotForkChildDiagnosticState::one_template_staged(
            1,
            *template_generation,
            name.clone(),
            *socket_cookie,
            32,
            *bound,
        ))
    }

    fn install_hot_fork_child_qmp(
        &mut self,
        name: &crate::QmpDescriptorName,
        descriptor: std::os::fd::BorrowedFd<'_>,
        socket_cookie: u64,
        template_generation: u64,
    ) -> Result<crate::QmpHotForkChildQmpState, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkInstallChildQmp {
                name: name.as_str().to_owned(),
                socket_cookie,
                template_generation,
            });
        if self.fail_descriptor_install {
            return Err(QemuNodeChannelError::new(
                "install hot-fork child QMP",
                "injected descriptor transfer failure",
            ));
        }
        let state = crate::QmpHotForkChildQmpState::one_template_staged(
            1,
            template_generation,
            7,
            name.clone(),
            socket_cookie,
            33,
            false,
            true,
        );
        *self.child_qmp_state.lock().unwrap() =
            Some((name.clone(), socket_cookie, template_generation, false));
        if self.serve_child_qmp {
            serve_scripted_hot_fork_child_qmp(
                descriptor,
                name,
                socket_cookie,
                template_generation,
            )?;
        }
        Ok(state)
    }

    fn close_hot_fork_child_qmp(
        &mut self,
        name: &crate::QmpDescriptorName,
        socket_cookie: u64,
    ) -> Result<(), QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkCloseChildQmp {
                name: name.as_str().to_owned(),
                socket_cookie,
            });
        if self.fail_descriptor_close {
            return Err(QemuNodeChannelError::new(
                "close hot-fork child QMP",
                "injected descriptor close failure",
            ));
        }
        *self.child_qmp_state.lock().unwrap() = None;
        Ok(())
    }

    fn query_hot_fork_child_qmp(
        &mut self,
    ) -> Result<crate::QmpHotForkChildQmpState, QemuNodeChannelError> {
        let state = self.child_qmp_state.lock().unwrap();
        let (name, socket_cookie, template_generation, bound) =
            state.as_ref().ok_or_else(|| {
                QemuNodeChannelError::new(
                    "query hot-fork child QMP",
                    "scripted child QMP stage is absent",
                )
            })?;
        Ok(crate::QmpHotForkChildQmpState::one_template_staged(
            1,
            *template_generation,
            7,
            name.clone(),
            *socket_cookie,
            33,
            *bound,
            true,
        ))
    }

    fn install_hot_fork_child_console(
        &mut self,
        name: &crate::QmpDescriptorName,
        _descriptor: std::os::fd::BorrowedFd<'_>,
        socket_cookie: u64,
        template_generation: u64,
    ) -> Result<crate::QmpHotForkChildConsoleState, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkInstallChildConsole {
                name: name.as_str().to_owned(),
                socket_cookie,
                template_generation,
            });
        if self.fail_descriptor_install {
            return Err(QemuNodeChannelError::new(
                "install hot-fork child console",
                "injected descriptor transfer failure",
            ));
        }
        let state = crate::QmpHotForkChildConsoleState::one_template_staged(
            1,
            template_generation,
            name.clone(),
            socket_cookie,
            34,
            false,
        );
        *self.child_console_state.lock().unwrap() =
            Some((name.clone(), socket_cookie, template_generation, false));
        Ok(state)
    }

    fn close_hot_fork_child_console(
        &mut self,
        name: &crate::QmpDescriptorName,
        socket_cookie: u64,
    ) -> Result<(), QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkCloseChildConsole {
                name: name.as_str().to_owned(),
                socket_cookie,
            });
        if self.fail_descriptor_close {
            return Err(QemuNodeChannelError::new(
                "close hot-fork child console",
                "injected descriptor close failure",
            ));
        }
        if self.child_qmp_state.lock().unwrap().is_none() {
            return Err(QemuNodeChannelError::new(
                "close hot-fork child console",
                "scripted predecessor child QMP stage was already released",
            ));
        }
        *self.child_console_state.lock().unwrap() = None;
        Ok(())
    }

    fn query_hot_fork_child_console(
        &mut self,
    ) -> Result<crate::QmpHotForkChildConsoleState, QemuNodeChannelError> {
        let state = self.child_console_state.lock().unwrap();
        let (name, socket_cookie, template_generation, bound) =
            state.as_ref().ok_or_else(|| {
                QemuNodeChannelError::new(
                    "query hot-fork child console",
                    "scripted child console stage is absent",
                )
            })?;
        Ok(crate::QmpHotForkChildConsoleState::one_template_staged(
            1,
            *template_generation,
            name.clone(),
            *socket_cookie,
            34,
            *bound,
        ))
    }

    fn query_hot_fork_template(
        &mut self,
    ) -> Result<crate::QmpHotForkTemplateState, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkTemplate);
        let mut template_query_count = self.template_query_count.lock().unwrap();
        *template_query_count += 1;
        let request = if self.mismatch_request_basis && *template_query_count > 2 {
            crate::QmpHotForkRequest::for_test(1, 2, 1, 1, 1, 7, 1, 15, 8, 9, 10, 11, 12, 13, 0)
        } else {
            exact_hot_fork_request()
        };
        let resources_are_sealed = self
            .child_console_state
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|(_name, _cookie, _generation, bound)| *bound);
        Ok(if resources_are_sealed {
            crate::QmpHotForkTemplateState::one_prepared(request)
        } else {
            crate::QmpHotForkTemplateState::one_draining_without_resources(request)
        })
    }

    fn query_hot_fork_child_process_contract(
        &mut self,
    ) -> Result<crate::QmpHotForkChildProcessContractState, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkChildProcessContract);
        if let Some((names, identity, generation, template_generation)) =
            self.process_contract_state.lock().unwrap().as_ref()
        {
            return Ok(
                crate::QmpHotForkChildProcessContractState::one_template_staged(
                    *generation,
                    *template_generation,
                    names,
                    *identity,
                ),
            );
        }
        let identity = crate::QmpHotForkChildProcessContractIdentity::new(1, 2, 9, 3, 4)
            .map_err(QemuNodeChannelError::from)?;
        Ok(
            crate::QmpHotForkChildProcessContractState::one_template_staged(
                13,
                1,
                &test_hot_fork_contract_names()?,
                identity,
            ),
        )
    }

    fn install_hot_fork_child_process_contract(
        &mut self,
        names: &crate::QmpHotForkChildProcessContractNames,
        _cgroup: std::os::fd::BorrowedFd<'_>,
        _cgroup_procs: std::os::fd::BorrowedFd<'_>,
        _cancellation: std::os::fd::BorrowedFd<'_>,
        identity: crate::QmpHotForkChildProcessContractIdentity,
        template_generation: u64,
    ) -> Result<crate::QmpHotForkChildProcessContractState, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkInstallProcessContract);
        let generation = 13;
        *self.process_contract_state.lock().unwrap() =
            Some((names.clone(), identity, generation, template_generation));
        Ok(
            crate::QmpHotForkChildProcessContractState::one_template_staged(
                generation,
                template_generation,
                names,
                identity,
            ),
        )
    }

    fn release_hot_fork_child_process_contract(
        &mut self,
        names: &crate::QmpHotForkChildProcessContractNames,
        identity: crate::QmpHotForkChildProcessContractIdentity,
    ) -> Result<crate::QmpHotForkChildProcessContractState, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkReleaseProcessContract);
        let retained = self.process_contract_state.lock().unwrap().take();
        let Some((retained_names, retained_identity, generation, _)) = retained else {
            return Err(QemuNodeChannelError::new(
                "release hot-fork child process contract",
                "scripted process contract is absent",
            ));
        };
        if retained_names != *names || retained_identity != identity {
            return Err(QemuNodeChannelError::new(
                "release hot-fork child process contract",
                "scripted process contract basis changed",
            ));
        }
        Ok(crate::QmpHotForkChildProcessContractState::one_released(
            generation,
        ))
    }

    fn query_hot_fork_child_files(
        &mut self,
    ) -> Result<crate::QmpHotForkChildFilesState, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkChildFiles);
        if let Some((files, maximum_bytes, generation, template_generation)) =
            self.child_files_state.lock().unwrap().as_ref()
        {
            return Ok(crate::QmpHotForkChildFilesState::one_template_staged(
                *generation,
                *template_generation,
                *maximum_bytes,
                files.clone(),
            ));
        }
        Ok(crate::QmpHotForkChildFilesState::one_released(0))
    }

    fn install_hot_fork_child_files(
        &mut self,
        files: &[crate::QmpHotForkChildFile],
        descriptors: &[std::os::fd::BorrowedFd<'_>],
        maximum_bytes: u64,
        template_generation: u64,
    ) -> Result<crate::QmpHotForkChildFilesState, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkInstallChildFiles);
        if files.len() != descriptors.len() {
            return Err(QemuNodeChannelError::new(
                "install hot-fork child files",
                "scripted child file plan received mismatched descriptors",
            ));
        }
        let generation = 17;
        *self.child_files_state.lock().unwrap() = Some((
            files.to_vec(),
            maximum_bytes,
            generation,
            template_generation,
        ));
        Ok(crate::QmpHotForkChildFilesState::one_template_staged(
            generation,
            template_generation,
            maximum_bytes,
            files.to_vec(),
        ))
    }

    fn release_hot_fork_child_files(
        &mut self,
        generation: u64,
    ) -> Result<crate::QmpHotForkChildFilesState, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkReleaseChildFiles);
        let retained = self.child_files_state.lock().unwrap().take();
        let Some((_files, _maximum_bytes, retained_generation, _template)) = retained else {
            return Err(QemuNodeChannelError::new(
                "release hot-fork child files",
                "scripted child file plan is absent",
            ));
        };
        if retained_generation != generation {
            return Err(QemuNodeChannelError::new(
                "release hot-fork child files",
                "scripted child file plan generation changed",
            ));
        }
        Ok(crate::QmpHotForkChildFilesState::one_released(generation))
    }

    fn hot_fork(
        &mut self,
        request: crate::QmpHotForkRequest,
    ) -> Result<crate::QmpHotForkState, crate::QemuHotForkCommandError> {
        self.log.lock().unwrap().push(ChannelCall::QmpHotFork);
        match self.hot_fork_script {
            HotForkScript::Forked => Ok(crate::QmpHotForkState::for_test(
                request,
                crate::QmpHotForkOutcome::Forked,
                321,
            )),
            HotForkScript::Rejected => Err(crate::QemuHotForkCommandError::Rejected {
                source: QemuNodeChannelError::new(
                    "fork retained hot-fork template",
                    "injected pre-fork rejection",
                ),
            }),
            HotForkScript::Indeterminate => Err(crate::QemuHotForkCommandError::Indeterminate {
                source: QemuNodeChannelError::new(
                    "fork retained hot-fork template",
                    "injected indeterminate exchange",
                ),
            }),
            HotForkScript::ParentDispositionFailed => Ok(crate::QmpHotForkState::for_test(
                request,
                crate::QmpHotForkOutcome::ParentDispositionFailed,
                321,
            )),
        }
    }

    fn query_hot_fork_bottom_half_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkBottomHalfInventory, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkBottomHalfInventory);
        Ok(crate::QmpHotForkBottomHalfInventory::one_idle(1, 1))
    }

    fn query_hot_fork_mutex_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkMutexInventory, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkMutexInventory);
        Ok(crate::QmpHotForkMutexInventory::one_owned(
            1,
            self.process_id,
        ))
    }

    fn query_hot_fork_timer_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkTimerInventory, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkTimerInventory);
        Ok(crate::QmpHotForkTimerInventory::empty())
    }

    fn query_hot_fork_monitor_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkMonitorInventory, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkMonitorInventory);
        Ok(crate::QmpHotForkMonitorInventory::one_supported())
    }

    fn complete_terminal_lifecycle_exit(
        &mut self,
        action: ContentHash,
        evidence: ContentHash,
        process_generation: u64,
    ) -> Result<(), QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpTerminalLifecycle {
                action,
                evidence,
                process_generation,
            });
        Ok(())
    }

    fn save_checkpoint_vmstate(
        &mut self,
        checkpoint: &Checkpoint,
    ) -> Result<(), QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpExactSave(checkpoint.id));
        if self.timeout_snapshot {
            return Err(QemuNodeChannelError::bounded_await_timeout(
                "save_checkpoint_vmstate",
                "QMP command timed out",
                Duration::from_millis(2),
            ));
        }
        if self.fail_snapshot {
            return Err(QemuNodeChannelError::new(
                "save_checkpoint_vmstate",
                "QMP error",
            ));
        }
        Ok(())
    }

    fn delete_checkpoint_vmstate(
        &mut self,
        checkpoint: &Checkpoint,
    ) -> Result<(), QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpExactDelete(checkpoint.id));
        Ok(())
    }

    fn quit(&mut self) -> Result<(), QemuNodeChannelError> {
        self.log.lock().unwrap().push(ChannelCall::QmpQuit);
        Ok(())
    }

    fn activate_debug_guest(&mut self) -> Result<(), QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpActivateDebugGuest);
        Ok(())
    }
}

impl QemuHostIoRuntime for ScriptedHostIoRuntime {
    #[cfg(target_os = "linux")]
    fn clone_hot_fork_host_io_continuation(
        &mut self,
        _execution_binding: ContentHash,
        _shmem_fd: std::os::fd::BorrowedFd<'_>,
        _wake_fd: std::os::fd::BorrowedFd<'_>,
        _region_len: u64,
        _console: Option<crate::QemuHotForkChildConsoleObservation>,
    ) -> Result<Box<dyn QemuHostIoRuntime>, QemuAsyncDriverRuntimeError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::HostHotForkContinuationClone);
        if self.fail_hot_fork_clone {
            return Err(QemuAsyncDriverRuntimeError::new(
                "clone scripted hot-fork host continuation",
                "injected unsupported live endpoint",
            ));
        }
        Ok(Box::new(self.clone()))
    }

    fn set_fault_event_staging_limit(
        &mut self,
        maximum_local_records: usize,
        canonical_current_offset: usize,
        configured_event_records: usize,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        if self.staged_fault_events.len() > maximum_local_records {
            return Err(QemuAsyncDriverRuntimeError::fault_event_storage(
                canonical_current_offset.saturating_add(self.staged_fault_events.len()),
                0,
                configured_event_records,
            ));
        }
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::HostFaultEventLimit {
                maximum_local_records,
                canonical_current_offset,
                configured_event_records,
            });
        Ok(())
    }

    fn publish_current_execution_fingerprint(
        &mut self,
        _timeout: Duration,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::HostFingerprintBoundary);
        if let Some(event) = self.fingerprint_fault_events.pop_front() {
            self.staged_fault_events.push(event);
        }
        Ok(())
    }

    fn clear_checkpoint_pause_while_stopped(&mut self) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::HostCheckpointClearWhileStopped);
        Ok(())
    }

    fn abort_checkpoint_pause(&mut self) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::HostCheckpointAbort);
        Ok(())
    }

    fn yield_to_control_plane(&mut self) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.log.lock().unwrap().push(ChannelCall::HostYield);
        Ok(())
    }

    fn await_child(
        &mut self,
        wait: QemuAsyncWait,
        timeout: Duration,
    ) -> Result<QemuAsyncWaitOutcome, QemuAsyncDriverRuntimeError> {
        let outcome = self.outcomes.pop_front().ok_or_else(|| {
            QemuAsyncDriverRuntimeError::new("await child", "no scripted outcome")
        })?;
        self.log.lock().unwrap().push(ChannelCall::HostAwait {
            wait,
            timeout,
            outcome,
        });
        Ok(outcome)
    }

    fn repoll_child(
        &mut self,
        wait: QemuAsyncWait,
        timeout: Duration,
    ) -> Result<QemuAsyncWaitOutcome, QemuAsyncDriverRuntimeError> {
        self.await_child(wait, timeout)
    }
    fn await_fault_result(
        &mut self,
        _timeout: Duration,
        payload_buffer: Vec<u8>,
        _maximum_event_records: usize,
    ) -> Result<DequeuedFaultResult, QemuAsyncDriverRuntimeError> {
        let result = self.fault_results.pop_front().ok_or_else(|| {
            QemuAsyncDriverRuntimeError::new("await fault result", "no scripted fault result")
        })?;
        let required = match &result {
            DequeuedFaultResult::Valid { payload, .. } => payload.len(),
            DequeuedFaultResult::Invalid { .. } => 0,
        };
        if payload_buffer.capacity() < required {
            return Err(QemuAsyncDriverRuntimeError::new(
                "await fault result",
                format!(
                    "scripted result buffer capacity {} is smaller than {required}",
                    payload_buffer.capacity()
                ),
            ));
        }
        Ok(result)
    }

    fn await_fault_preparation_result(
        &mut self,
        _timeout: Duration,
        maximum_payload_bytes: usize,
        _maximum_event_records: usize,
    ) -> Result<DequeuedFaultResult, QemuAsyncDriverRuntimeError> {
        let result = self.fault_results.front().ok_or_else(|| {
            QemuAsyncDriverRuntimeError::new(
                "await fault preparation result",
                "no scripted fault result",
            )
        })?;
        let required = match result {
            DequeuedFaultResult::Valid { payload, .. } => payload.len(),
            DequeuedFaultResult::Invalid { .. } => 0,
        };
        if required > maximum_payload_bytes {
            return Err(QemuAsyncDriverRuntimeError::fault_result_storage(
                required,
                maximum_payload_bytes,
            ));
        }
        self.fault_results.pop_front().ok_or_else(|| {
            QemuAsyncDriverRuntimeError::new(
                "await fault preparation result",
                "scripted fault result disappeared after admission",
            )
        })
    }

    fn take_staged_fault_events(
        &mut self,
    ) -> Result<Vec<DequeuedFaultEvent>, QemuAsyncDriverRuntimeError> {
        Ok(std::mem::take(&mut self.staged_fault_events))
    }

    fn staged_fault_events(&self) -> &[DequeuedFaultEvent] {
        &self.staged_fault_events
    }

    fn staged_fault_events_pending(&self) -> bool {
        !self.staged_fault_events.is_empty()
    }

    fn staged_fault_event_count(&self) -> usize {
        self.staged_fault_events.len()
    }
}

#[test]
fn qemu_node_owns_one_child_and_exactly_three_channel_roles() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node(Arc::clone(&log), false, false, false)?;

    assert_eq!(
        node.channel_roles(),
        [
            QemuNodeChannelPlane::PluginIpcControl,
            QemuNodeChannelPlane::ShmemHotPath,
            QemuNodeChannelPlane::QmpMachineControl,
        ]
    );
    assert_eq!(node.lifecycle_state(), QemuNodeLifecycleState::Running);
    assert!(!node.child_reaped());
    assert!(recorded(&log).is_empty());

    let report = node.shutdown_child()?;
    assert!(report.reaped);
    assert!(node.child_reaped());
    assert_eq!(
        report
            .attempts
            .iter()
            .map(|attempt| attempt.rung)
            .collect::<Vec<_>>(),
        [
            QemuShutdownRung::ControlQuit,
            QemuShutdownRung::QmpQuit,
            QemuShutdownRung::Sigterm,
        ]
    );
    assert_eq!(
        node.lifecycle_state(),
        QemuNodeLifecycleState::ShutdownRequested
    );

    Ok(())
}

#[test]
#[cfg(unix)]
fn hot_fork_ring_capture_binds_one_unchanged_plugin_barrier() -> Result<(), Box<dyn Error>> {
    let (setup_identity, host_barrier, image) = held_hot_fork_ring_image()?;
    let barrier = crate::QmpHotForkPluginBarrierState::one_quiescent(9, host_barrier.ring_count());
    let log = shared_log();
    let mut node = scripted_hot_fork_capture_node(
        Arc::clone(&log),
        setup_identity,
        setup_identity,
        host_barrier,
        image.clone(),
        [barrier, barrier, barrier, barrier, barrier],
        DescriptorScript::Success,
    )?;

    let capture = node.capture_hot_fork_plugin_ring_image(image.canonical_len()?)?;
    assert_eq!(capture.setup_region(), setup_identity);
    assert_eq!(
        capture.plugin_resources().shmem_inode(),
        setup_identity.inode()
    );
    assert_eq!(capture.plugin_barrier(), barrier);
    assert_eq!(capture.host_barrier(), host_barrier);
    assert_eq!(capture.image(), &image);
    let private = node.materialize_hot_fork_private_ring_mapping(capture)?;
    assert_eq!(private.source_setup_region(), setup_identity);
    assert_eq!(private.source_plugin_barrier(), barrier);
    assert_eq!(private.host_barrier(), host_barrier);
    assert_eq!(private.image_digest(), image.digest());
    assert_ne!(private.backing_identity(), setup_identity);
    assert_eq!(private.backing_identity().length(), setup_identity.length());
    assert_eq!(private.capture_ring_image(image.canonical_len()?)?, image);
    let expected_name = private.descriptor_name().clone();
    let mapping_identity = private.backing_identity();
    let proof = node.stage_hot_fork_private_ring_mapping(private)?;
    assert_eq!(
        proof.state(),
        crate::QemuHotForkPrivateRingStageState::Installed
    );
    assert_eq!(proof.descriptor_name(), &expected_name);
    assert_eq!(proof.image_digest(), image.digest());
    assert_eq!(node.hot_fork_private_ring_stage(), Some(proof));
    let private = node.release_hot_fork_private_ring_mapping()?;
    assert_eq!(private.descriptor_name(), &expected_name);
    assert!(node.hot_fork_private_ring_stage().is_none());
    assert_eq!(
        recorded(&log),
        [
            ChannelCall::QmpHotForkPluginResourceInventory,
            ChannelCall::QmpHotForkPluginBarrier,
            ChannelCall::ShmemHotForkIdentity,
            ChannelCall::ShmemHotForkBarrier,
            ChannelCall::ShmemHotForkCapture,
            ChannelCall::ShmemHotForkBarrier,
            ChannelCall::QmpHotForkPluginResourceInventory,
            ChannelCall::QmpHotForkPluginBarrier,
            ChannelCall::QmpHotForkPluginResourceInventory,
            ChannelCall::QmpHotForkPluginBarrier,
            ChannelCall::ShmemHotForkIdentity,
            ChannelCall::ShmemHotForkBarrier,
            ChannelCall::QmpHotForkPluginResourceInventory,
            ChannelCall::ShmemHotForkIdentity,
            ChannelCall::ShmemHotForkBarrier,
            ChannelCall::QmpHotForkPluginBarrier,
            ChannelCall::QmpHotForkPluginResourceInventory,
            ChannelCall::ShmemHotForkIdentity,
            ChannelCall::ShmemHotForkBarrier,
            ChannelCall::QmpHotForkPluginBarrier,
            ChannelCall::QmpHotForkInstallDescriptor(
                expected_name.as_str().to_owned(),
                mapping_identity,
            ),
            ChannelCall::QmpHotForkCloseDescriptor(
                expected_name.as_str().to_owned(),
                mapping_identity,
            ),
        ]
    );
    node.shutdown_child()?;

    let changed = crate::QmpHotForkPluginBarrierState::one_quiescent(
        barrier.generation() + 1,
        host_barrier.ring_count(),
    );
    let mut drifting = scripted_hot_fork_capture_node(
        shared_log(),
        setup_identity,
        setup_identity,
        host_barrier,
        image.clone(),
        [barrier, changed],
        DescriptorScript::Success,
    )?;
    let error = drifting
        .capture_hot_fork_plugin_ring_image(image.canonical_len()?)
        .expect_err("changed plugin barrier must reject capture");
    assert!(error.to_string().contains("changed across image capture"));
    drifting.shutdown_child()?;

    let mut stale = scripted_hot_fork_capture_node(
        shared_log(),
        setup_identity,
        setup_identity,
        host_barrier,
        image.clone(),
        [barrier, barrier, changed],
        DescriptorScript::Success,
    )?;
    let stale_capture = stale.capture_hot_fork_plugin_ring_image(image.canonical_len()?)?;
    let error = stale
        .materialize_hot_fork_private_ring_mapping(stale_capture)
        .err()
        .ok_or("stale capture unexpectedly materialized")?;
    assert!(error.to_string().contains("no longer current"));
    stale.shutdown_child()?;

    let mut changing_during_materialization = scripted_hot_fork_capture_node(
        shared_log(),
        setup_identity,
        setup_identity,
        host_barrier,
        image.clone(),
        [barrier, barrier, barrier, changed],
        DescriptorScript::Success,
    )?;
    let capture = changing_during_materialization
        .capture_hot_fork_plugin_ring_image(image.canonical_len()?)?;
    let error = changing_during_materialization
        .materialize_hot_fork_private_ring_mapping(capture)
        .err()
        .ok_or("source drift during materialization unexpectedly succeeded")?;
    assert!(error.to_string().contains("changed during"));
    changing_during_materialization.shutdown_child()?;

    let (_other_identity, _other_barrier, wrong_length_image) =
        held_hot_fork_ring_image_for(RegionConfig::new(2, 4, 0))?;
    let mut wrong_length = scripted_hot_fork_capture_node(
        shared_log(),
        setup_identity,
        setup_identity,
        host_barrier,
        wrong_length_image.clone(),
        [barrier, barrier],
        DescriptorScript::Success,
    )?;
    let error = wrong_length
        .capture_hot_fork_plugin_ring_image(wrong_length_image.canonical_len()?)
        .expect_err("foreign image length must reject capture");
    assert!(error.to_string().contains("image length differs"));
    wrong_length.shutdown_child()?;

    let (foreign_identity, _foreign_barrier, _foreign_image) = held_hot_fork_ring_image()?;
    let mut mismatched = scripted_hot_fork_capture_node(
        shared_log(),
        setup_identity,
        foreign_identity,
        host_barrier,
        image.clone(),
        [barrier, barrier],
        DescriptorScript::Success,
    )?;
    let error = mismatched
        .capture_hot_fork_plugin_ring_image(image.canonical_len()?)
        .expect_err("foreign setup-region identity must reject capture");
    assert!(error.to_string().contains("resource identity disagree"));
    mismatched.shutdown_child()?;
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn hot_fork_private_ring_stage_retains_ambiguous_transfer_and_close_failures()
-> Result<(), Box<dyn Error>> {
    let (setup_identity, host_barrier, image) = held_hot_fork_ring_image()?;
    let barrier = crate::QmpHotForkPluginBarrierState::one_quiescent(11, host_barrier.ring_count());

    let mut transfer_failure = scripted_hot_fork_capture_node(
        shared_log(),
        setup_identity,
        setup_identity,
        host_barrier,
        image.clone(),
        [barrier, barrier, barrier, barrier, barrier],
        DescriptorScript::InstallFailure,
    )?;
    let capture = transfer_failure.capture_hot_fork_plugin_ring_image(image.canonical_len()?)?;
    let private = transfer_failure.materialize_hot_fork_private_ring_mapping(capture)?;
    let error = transfer_failure
        .stage_hot_fork_private_ring_mapping(private)
        .expect_err("descriptor transfer failure must remain ownership-ambiguous");
    assert!(matches!(
        error,
        crate::QemuHotForkPrivateRingStageError::TransferUncertain { .. }
    ));
    assert_eq!(
        transfer_failure.lifecycle_state(),
        QemuNodeLifecycleState::Quarantined
    );
    assert_eq!(
        transfer_failure
            .hot_fork_private_ring_stage()
            .ok_or("ambiguous mapping was not retained")?
            .state(),
        crate::QemuHotForkPrivateRingStageState::TransferUncertain
    );
    assert!(
        transfer_failure
            .release_hot_fork_private_ring_mapping()
            .is_err()
    );
    transfer_failure.shutdown_child()?;

    let mut close_failure = scripted_hot_fork_capture_node(
        shared_log(),
        setup_identity,
        setup_identity,
        host_barrier,
        image.clone(),
        [barrier, barrier, barrier, barrier, barrier],
        DescriptorScript::CloseFailure,
    )?;
    let capture = close_failure.capture_hot_fork_plugin_ring_image(image.canonical_len()?)?;
    let private = close_failure.materialize_hot_fork_private_ring_mapping(capture)?;
    close_failure.stage_hot_fork_private_ring_mapping(private)?;
    assert!(
        close_failure
            .release_hot_fork_private_ring_mapping()
            .is_err()
    );
    assert_eq!(
        close_failure.lifecycle_state(),
        QemuNodeLifecycleState::Quarantined
    );
    assert_eq!(
        close_failure
            .hot_fork_private_ring_stage()
            .ok_or("failed close discarded its mapping")?
            .state(),
        crate::QemuHotForkPrivateRingStageState::Installed
    );
    close_failure.shutdown_child()?;
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn hot_fork_plugin_endpoints_bind_the_installed_private_ring_generation()
-> Result<(), Box<dyn Error>> {
    let (setup_identity, host_barrier, image) = held_hot_fork_ring_image()?;
    let barrier = crate::QmpHotForkPluginBarrierState::one_quiescent(12, host_barrier.ring_count());
    let log = shared_log();
    let mut node = scripted_hot_fork_capture_node(
        Arc::clone(&log),
        setup_identity,
        setup_identity,
        host_barrier,
        image.clone(),
        [barrier; 8],
        DescriptorScript::Success,
    )?;
    let capture = node.capture_hot_fork_plugin_ring_image(image.canonical_len()?)?;
    let private = node.materialize_hot_fork_private_ring_mapping(capture)?;
    node.stage_hot_fork_private_ring_mapping(private)?;
    let diagnostics = node.stage_hot_fork_child_diagnostics()?;
    assert_eq!(
        diagnostics.state(),
        crate::QemuHotForkChildDiagnosticStageState::Installed
    );
    assert!(!diagnostics.replacement_plan_bound());
    let child_qmp = node.stage_hot_fork_child_qmp()?;
    assert_eq!(
        child_qmp.state(),
        crate::QemuHotForkChildQmpStageState::Installed
    );
    assert_eq!(child_qmp.qmp_generation(), 1);
    assert_eq!(child_qmp.monitor_generation(), 7);
    assert!(!child_qmp.resource_plan_bound());
    assert!(node.take_hot_fork_child_qmp_host_endpoint().is_err());
    let child_console = node.stage_hot_fork_child_console()?;
    assert_eq!(
        child_console.state(),
        crate::QemuHotForkChildConsoleStageState::Installed
    );
    assert_eq!(child_console.console_generation(), 1);
    assert!(!child_console.resource_plan_bound());
    let diagnostic_drain = node.drain_hot_fork_child_diagnostics()?;
    assert_eq!(diagnostic_drain.bytes_read(), 26);
    assert_eq!(diagnostic_drain.total_retained(), 26);
    assert!(!diagnostic_drain.eof());

    let proof = node.stage_hot_fork_plugin_endpoints()?;
    assert_eq!(
        proof.state(),
        crate::QemuHotForkPluginEndpointStageState::Installed
    );
    assert_eq!(proof.private_ring_generation(), 1);
    assert_eq!(proof.template_generation(), 1);
    assert_eq!(proof.plugin_barrier_generation(), barrier.generation());
    assert_eq!(proof.worker_mask(), barrier.worker_mask());
    let replacement = proof
        .replacement_plan()
        .ok_or("installed endpoint proof omitted the replacement plan")?;
    assert_eq!(replacement.control_source(), 30);
    assert_eq!(replacement.wake_source(), 31);
    assert_eq!(replacement.control_target(), 3);
    assert_eq!(replacement.wake_target(), 4);
    assert_ne!(proof.control_name(), proof.wake_name());
    assert_ne!(proof.identity().control_socket_cookie(), 0);
    assert_ne!(proof.identity().wake_eventfd_id(), 0);
    assert_eq!(node.hot_fork_plugin_endpoint_stage(), Some(proof.clone()));
    assert!(
        node.hot_fork_child_qmp_stage()
            .ok_or("child QMP stage disappeared after plugin seal")?
            .resource_plan_bound()
    );
    assert!(
        node.hot_fork_child_console_stage()
            .ok_or("child console stage disappeared after plugin seal")?
            .resource_plan_bound()
    );
    let child_console_observation = node.clone_hot_fork_child_console_observation()?;
    drop(child_console_observation);
    let child_qmp_host = node.take_hot_fork_child_qmp_host_endpoint()?;
    assert_eq!(
        child_qmp_host.descriptor_name(),
        child_qmp.descriptor_name()
    );
    assert_eq!(child_qmp_host.socket_cookie(), child_qmp.socket_cookie());
    assert_eq!(
        child_qmp_host.template_generation(),
        child_qmp.template_generation()
    );
    assert_eq!(child_qmp_host.qmp_generation(), child_qmp.qmp_generation());
    assert_eq!(
        child_qmp_host.monitor_generation(),
        child_qmp.monitor_generation()
    );
    assert!(node.take_hot_fork_child_qmp_host_endpoint().is_err());
    drop(child_qmp_host);
    assert!(node.release_hot_fork_private_ring_mapping().is_err());

    node.release_hot_fork_plugin_endpoints()?;
    assert!(node.hot_fork_plugin_endpoint_stage().is_none());
    assert!(
        !node
            .hot_fork_child_diagnostic_stage()
            .ok_or("diagnostics stage disappeared after plugin release")?
            .replacement_plan_bound()
    );
    assert!(
        !node
            .hot_fork_child_qmp_stage()
            .ok_or("child QMP stage disappeared after plugin release")?
            .resource_plan_bound()
    );
    assert!(
        !node
            .hot_fork_child_console_stage()
            .ok_or("child console stage disappeared after plugin release")?
            .resource_plan_bound()
    );
    node.release_hot_fork_child_console()?;
    node.release_hot_fork_child_qmp()?;
    let diagnostic_capture = node.release_hot_fork_child_diagnostics()?;
    assert_eq!(
        diagnostic_capture.descriptor_name(),
        diagnostics.descriptor_name()
    );
    assert_eq!(
        diagnostic_capture.socket_cookie(),
        diagnostics.socket_cookie()
    );
    assert_eq!(
        diagnostic_capture.template_generation(),
        diagnostics.template_generation()
    );
    assert_eq!(diagnostic_capture.bytes(), b"scripted child diagnostics");
    node.release_hot_fork_private_ring_mapping()?;
    let calls = recorded(&log);
    assert!(calls.iter().any(|call| {
        matches!(
            call,
            ChannelCall::QmpHotForkInstallPluginEndpoints {
                control_name,
                wake_name,
                identity,
                private_ring_generation: 1,
            } if control_name == proof.control_name().as_str()
                && wake_name == proof.wake_name().as_str()
                && *identity == proof.identity()
        )
    }));
    assert!(calls.iter().any(|call| {
        matches!(
            call,
            ChannelCall::QmpHotForkClosePluginEndpoints {
                control_name,
                wake_name,
                identity,
            } if control_name == proof.control_name().as_str()
                && wake_name == proof.wake_name().as_str()
                && *identity == proof.identity()
        )
    }));
    let console_close = calls
        .iter()
        .position(|call| matches!(call, ChannelCall::QmpHotForkCloseChildConsole { .. }))
        .ok_or("child console close was not recorded")?;
    let qmp_close = calls
        .iter()
        .position(|call| matches!(call, ChannelCall::QmpHotForkCloseChildQmp { .. }))
        .ok_or("child QMP close was not recorded")?;
    assert!(console_close < qmp_close);
    node.shutdown_child()?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn sealed_hot_fork_node(script: DescriptorScript) -> Result<QemuNode, Box<dyn Error>> {
    sealed_hot_fork_node_with_log(script).map(|(node, _log)| node)
}

#[cfg(target_os = "linux")]
fn sealed_hot_fork_node_with_log(
    script: DescriptorScript,
) -> Result<(QemuNode, SharedLog), Box<dyn Error>> {
    let (mut node, log) = prepared_hot_fork_node_with_log(script)?;
    node.install_test_hot_fork_child_process_contract_stage(13, 1)?;
    Ok((node, log))
}

#[cfg(target_os = "linux")]
fn prepared_hot_fork_node_with_log(
    script: DescriptorScript,
) -> Result<(QemuNode, SharedLog), Box<dyn Error>> {
    let (setup_identity, host_barrier, image) = held_hot_fork_ring_image()?;
    let barrier = crate::QmpHotForkPluginBarrierState::one_quiescent(15, host_barrier.ring_count());
    let log = shared_log();
    let mut node = scripted_hot_fork_capture_node(
        Arc::clone(&log),
        setup_identity,
        setup_identity,
        host_barrier,
        image.clone(),
        [barrier; 8],
        script,
    )?;
    node.prepare_hot_fork_child_resources(image.canonical_len()?)?;
    Ok((node, log))
}

#[cfg(target_os = "linux")]
fn exact_hot_fork_request() -> crate::QmpHotForkRequest {
    crate::QmpHotForkRequest::for_test(1, 1, 1, 1, 1, 7, 1, 15, 8, 9, 10, 11, 12, 13, 0)
}

#[cfg(target_os = "linux")]
fn test_hot_fork_contract_names()
-> Result<crate::QmpHotForkChildProcessContractNames, QemuNodeChannelError> {
    crate::QmpHotForkChildProcessContractNames::new(
        crate::QmpDescriptorName::new("test-hot-fork-cgroup")
            .map_err(QemuNodeChannelError::from)?,
        crate::QmpDescriptorName::new("test-hot-fork-cgroup-procs")
            .map_err(QemuNodeChannelError::from)?,
        crate::QmpDescriptorName::new("test-hot-fork-cancellation")
            .map_err(QemuNodeChannelError::from)?,
    )
    .map_err(QemuNodeChannelError::from)
}

fn unvalidated_hot_fork_process_contract() -> Result<crate::QemuChildProcessContract, Box<dyn Error>>
{
    let directory = tempfile::tempdir()?;
    let cgroup_directory: OwnedFd = std::fs::File::open(directory.path())?.into();
    // Staging authenticates `cgroup.procs` as a writable regular file on the
    // directory's device; a real cgroup is not needed for that shape.
    let cgroup_procs: OwnedFd = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(directory.path().join("cgroup.procs"))?
        .into();
    // SAFETY: eventfd returns a fresh owned descriptor or -1; this test adopts
    // the successful descriptor exactly once into OwnedFd.
    let cancellation = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if cancellation == -1 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: the successful eventfd result is fresh and uniquely owned here.
    let cancellation = unsafe { OwnedFd::from_raw_fd(cancellation) };
    Ok(
        crate::QemuChildProcessContract::from_unvalidated_hot_fork_test_descriptors(
            cgroup_directory,
            cgroup_procs,
            cancellation,
            1,
            4096,
            4096,
        ),
    )
}

#[test]
fn failed_node_surrenders_its_direct_child_wait_authority() -> Result<(), Box<dyn Error>> {
    let node = scripted_node(shared_log(), false, false, false)?;
    let process_id = node.child.process_id();

    let mut child = node
        .into_direct_child_for_quarantine()
        .expect("fixture node owns a direct child");

    assert_eq!(child.process_id(), process_id);
    assert!(!child.reaped());
    child.force_kill_and_reap_failed_realization()?;
    assert!(child.reaped());
    Ok(())
}

#[test]
fn live_fault_sequences_continue_after_capability_admission() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node(Arc::clone(&log), false, false, false)?;

    assert_eq!(node.reserve_fault_command_sequence()?, 2);
    assert_eq!(node.reserve_fault_command_sequence()?, 3);

    Ok(())
}

#[test]
fn qemu_node_routes_scheduler_operations_over_strict_channels() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node(Arc::clone(&log), false, false, false)?;

    assert_eq!(node.current_icount()?, Icount { retired: 11 });
    assert_eq!(
        Backend::advance_to_horizon(
            &mut node,
            ExecutionHorizon {
                icount: Icount { retired: 19 },
            },
        )?,
        AdvanceOutcome::ReachedHorizon
    );
    Backend::deliver_input(
        &mut node,
        BackendInput {
            node: node_id("vm-a"),
            payload: vec![1, 2, 3],
        },
    )?;
    assert_eq!(
        node.emit_frame()?,
        Some(QemuNodeEmittedFrame {
            source: node_id("vm-a"),
            destination: node_id("vm-b"),
            emit_icount: Icount { retired: 17 },
            sequence: 7,
            payload: vec![8, 9],
        })
    );
    assert_eq!(
        node.idle_state()?,
        QemuNodeIdleState {
            current_icount: Icount { retired: 13 },
            next_deadline: Some(Icount { retired: 21 }),
        }
    );
    assert_eq!(
        Backend::fingerprint(&mut node)?,
        ExecutionFingerprint {
            hash: content_hash("fingerprint", "vm-a"),
        }
    );

    assert!(matches!(
        Backend::snapshot(&mut node),
        Err(BackendError::Rejected { message })
            if message.contains("capture_exact_snapshot")
    ));
    let report = node.shutdown_child()?;

    assert!(report.reaped);
    assert_eq!(
        node.lifecycle_state(),
        QemuNodeLifecycleState::ShutdownRequested
    );
    assert_eq!(
        recorded(&log),
        vec![
            ChannelCall::ShmemCurrentIcount,
            ChannelCall::HostYield,
            ChannelCall::ShmemStart(19),
            ChannelCall::HostAwait {
                wait: QemuAsyncWait::AdvanceCompletion,
                timeout: Duration::from_millis(4),
                outcome: QemuAsyncWaitOutcome::Completed,
            },
            ChannelCall::ShmemFinish(19),
            ChannelCall::HostYield,
            ChannelCall::ShmemDeliver {
                node: String::from("vm-a"),
                payload: vec![1, 2, 3],
            },
            ChannelCall::ShmemEmit,
            ChannelCall::ShmemIdle,
            ChannelCall::ShmemFingerprint,
            ChannelCall::PluginQuit,
            ChannelCall::QmpQuit,
        ]
    );

    Ok(())
}

#[test]
fn selectable_reply_is_published_before_qemu_resumes() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node(Arc::clone(&log), false, false, false)?;
    let request = crucible_protocol::SelectionRequest::new(
        7,
        "product.test.selectable",
        "instance-a",
        None,
        128,
    )?;
    let pending = crucible_protocol::selectable_catalog_plan::SelectablePlanPendingRequest::new(
        request, 41, 0, 0x1000,
    );
    let reply = crucible_protocol::SelectionReply::rejected(
        7,
        crucible_protocol::SelectionReplyStatus::Unavailable,
        [0; 32],
        [0; 32],
    )?;

    node.enqueue_selectable_reply(&pending, &reply)?;

    assert_eq!(
        recorded(&log),
        vec![
            ChannelCall::ShmemSelectableReply(7),
            ChannelCall::QmpContinue,
        ]
    );
    node.shutdown_child()?;
    Ok(())
}

#[path = "node_tests/exact_lifecycle_tests.rs"]
mod exact_lifecycle;
#[path = "node_tests/fault_event_budget.rs"]
mod fault_event_budget;
#[path = "node_tests/fingerprint.rs"]
mod fingerprint;

#[cfg(unix)]
fn held_hot_fork_ring_image() -> Result<
    (
        crucible_shmem::SetupRegionBackingIdentity,
        crucible_shmem::MappedRingIoBarrierSnapshot,
        crucible_shmem::HotForkRingImage,
    ),
    Box<dyn Error>,
> {
    held_hot_fork_ring_image_for(RegionConfig::new(1, 4, 0))
}

#[cfg(unix)]
fn held_hot_fork_ring_image_for(
    config: RegionConfig,
) -> Result<
    (
        crucible_shmem::SetupRegionBackingIdentity,
        crucible_shmem::MappedRingIoBarrierSnapshot,
        crucible_shmem::HotForkRingImage,
    ),
    Box<dyn Error>,
> {
    let mut allocation = RegionAllocation::new_model(config)?;
    let retained = CoverageEntry::new(17, 0, 0x4000, 4, 9)?;
    allocation.enqueue_coverage_entry(0, retained)?;
    let mut shmem = tempfile::tempfile()?;
    shmem.write_all(&allocation.setup_region_bytes()?)?;
    let region_len = allocation.layout().region_size;
    let mapped = mmap_setup_region(shmem.as_fd(), region_len)?;
    let identity = mapped.backing_identity();
    let host_barrier = mapped.hold_hot_fork_ring_io()?;
    let image = mapped.capture_hot_fork_ring_image(usize::MAX)?;
    Ok((identity, host_barrier, image))
}

#[cfg(unix)]
fn scripted_hot_fork_capture_node(
    log: SharedLog,
    setup_identity: crucible_shmem::SetupRegionBackingIdentity,
    resource_identity: crucible_shmem::SetupRegionBackingIdentity,
    host_barrier: crucible_shmem::MappedRingIoBarrierSnapshot,
    image: crucible_shmem::HotForkRingImage,
    plugin_barriers: impl IntoIterator<Item = crate::QmpHotForkPluginBarrierState>,
    descriptor_script: DescriptorScript,
) -> Result<QemuNode, Box<dyn Error>> {
    let child = Command::new("sleep").arg("60").spawn()?;
    let process_id = child.id();
    let channels = QemuNodeChannels::new(
        ScriptedPluginControl {
            log: Arc::clone(&log),
            fail_quit: false,
        },
        ScriptedShmemHotPath {
            log: Arc::clone(&log),
            fail_advance: false,
            coverage_enabled: false,
            quantum_coverage: Arc::new(Mutex::new(VecDeque::new())),
            teardown_coverage: Arc::new(Mutex::new(Vec::new())),
            fault_commands: Arc::new(Mutex::new(Vec::new())),
            stale_fault_results: Arc::new(Mutex::new(VecDeque::new())),
            fault_events: Arc::new(Mutex::new(VecDeque::new())),
            fingerprint_retry_countdown: Arc::new(Mutex::new(0)),
            hot_fork_setup_identity: Some(setup_identity),
            hot_fork_ring_image: Some((host_barrier, image)),
        },
        ScriptedQmpMachineControl {
            log: Arc::clone(&log),
            process_id,
            fail_stop: false,
            fail_snapshot: false,
            timeout_snapshot: false,
            plugin_resources: Some(
                crate::QmpHotForkPluginResourceInventory::one_complete_with_bindings(
                    1,
                    resource_identity.device(),
                    resource_identity.inode(),
                    resource_identity.length(),
                    0,
                    1,
                ),
            ),
            plugin_barriers: Some(Arc::new(Mutex::new(plugin_barriers.into_iter().collect()))),
            last_plugin_barrier: Arc::new(Mutex::new(None)),
            private_ring_state: Arc::new(Mutex::new(None)),
            diagnostic_state: Arc::new(Mutex::new(None)),
            child_qmp_state: Arc::new(Mutex::new(None)),
            child_console_state: Arc::new(Mutex::new(None)),
            process_contract_state: Arc::new(Mutex::new(None)),
            child_files_state: Arc::new(Mutex::new(None)),
            fail_descriptor_install: matches!(descriptor_script, DescriptorScript::InstallFailure),
            fail_descriptor_close: matches!(descriptor_script, DescriptorScript::CloseFailure),
            fail_endpoint_install: matches!(
                descriptor_script,
                DescriptorScript::EndpointInstallFailure
            ),
            mismatch_endpoint_disposition: matches!(
                descriptor_script,
                DescriptorScript::EndpointDispositionMismatch
            ),
            mismatch_request_basis: matches!(
                descriptor_script,
                DescriptorScript::RequestBasisMismatch
            ),
            serve_child_qmp: matches!(descriptor_script, DescriptorScript::SchedulerContinuation),
            template_query_count: Arc::new(Mutex::new(0)),
            hot_fork_script: match descriptor_script {
                DescriptorScript::ForkRejected => HotForkScript::Rejected,
                DescriptorScript::ForkIndeterminate => HotForkScript::Indeterminate,
                DescriptorScript::ForkParentDispositionFailed => {
                    HotForkScript::ParentDispositionFailed
                }
                DescriptorScript::Success
                | DescriptorScript::SchedulerContinuation
                | DescriptorScript::InstallFailure
                | DescriptorScript::CloseFailure
                | DescriptorScript::EndpointInstallFailure
                | DescriptorScript::EndpointDispositionMismatch
                | DescriptorScript::HostIoCloneFailure
                | DescriptorScript::RequestBasisMismatch => HotForkScript::Forked,
            },
        },
    );
    Ok(QemuNode::new(
        QemuNodeChild::new(child),
        channels,
        node_shutdown_policy(),
        QemuAsyncDriverPolicy::fast_test(),
        QemuCrashDetector::new("vm-a"),
        ScriptedHostIoRuntime {
            log,
            outcomes: VecDeque::new(),
            fault_results: VecDeque::new(),
            staged_fault_events: Vec::new(),
            fingerprint_fault_events: VecDeque::new(),
            fail_hot_fork_clone: matches!(descriptor_script, DescriptorScript::HostIoCloneFailure),
        },
        2,
    ))
}

fn scripted_node(
    log: SharedLog,
    fail_plugin_quit: bool,
    fail_shmem_advance: bool,
    fail_qmp_snapshot: bool,
) -> Result<QemuNode, Box<dyn Error>> {
    scripted_node_with_runtime(
        log,
        fail_plugin_quit,
        fail_shmem_advance,
        fail_qmp_snapshot,
        [QemuAsyncWaitOutcome::Completed],
    )
}

fn scripted_node_with_runtime(
    log: SharedLog,
    fail_plugin_quit: bool,
    fail_shmem_advance: bool,
    fail_qmp_snapshot: bool,
    runtime_outcomes: impl IntoIterator<Item = QemuAsyncWaitOutcome>,
) -> Result<QemuNode, Box<dyn Error>> {
    scripted_node_with_options(
        log,
        ScriptedNodeOptions {
            fail_plugin_quit,
            fail_shmem_advance,
            fail_qmp_stop: false,
            fail_qmp_snapshot,
            qmp_snapshot_timeout: false,
            fingerprint_retry_countdown: 0,
            fingerprint_fault_event_count: 0,
        },
        runtime_outcomes,
    )
}

#[derive(Clone, Copy, Debug, Default)]
struct ScriptedNodeOptions {
    fail_plugin_quit: bool,
    fail_shmem_advance: bool,
    fail_qmp_stop: bool,
    fail_qmp_snapshot: bool,
    qmp_snapshot_timeout: bool,
    fingerprint_retry_countdown: u8,
    fingerprint_fault_event_count: u8,
}

fn scripted_node_with_options(
    log: SharedLog,
    options: ScriptedNodeOptions,
    runtime_outcomes: impl IntoIterator<Item = QemuAsyncWaitOutcome>,
) -> Result<QemuNode, Box<dyn Error>> {
    scripted_node_with_coverage(
        log,
        options,
        runtime_outcomes,
        std::iter::empty(),
        std::iter::empty(),
    )
}

fn scripted_node_with_fault_events(
    log: SharedLog,
    events: impl IntoIterator<Item = DequeuedFaultEvent>,
) -> Result<QemuNode, Box<dyn Error>> {
    let mut events = events.into_iter();
    let staged_fault_events = events.next().into_iter().collect();
    let child = Command::new("sleep").arg("60").spawn()?;
    let process_id = child.id();
    let channels = QemuNodeChannels::new(
        ScriptedPluginControl {
            log: Arc::clone(&log),
            fail_quit: false,
        },
        ScriptedShmemHotPath {
            log: Arc::clone(&log),
            fail_advance: false,
            coverage_enabled: false,
            quantum_coverage: Arc::new(Mutex::new(VecDeque::new())),
            teardown_coverage: Arc::new(Mutex::new(Vec::new())),
            fault_commands: Arc::new(Mutex::new(Vec::new())),
            stale_fault_results: Arc::new(Mutex::new(VecDeque::new())),
            fault_events: Arc::new(Mutex::new(events.collect())),
            fingerprint_retry_countdown: Arc::new(Mutex::new(0)),
            hot_fork_setup_identity: None,
            hot_fork_ring_image: None,
        },
        ScriptedQmpMachineControl {
            log: Arc::clone(&log),
            process_id,
            fail_stop: false,
            fail_snapshot: false,
            timeout_snapshot: false,
            plugin_resources: Some(
                crate::QmpHotForkPluginResourceInventory::one_complete_with_bindings(
                    1, 1, 2, 4096, 0, 1,
                ),
            ),
            plugin_barriers: None,
            last_plugin_barrier: Arc::new(Mutex::new(None)),
            private_ring_state: Arc::new(Mutex::new(None)),
            diagnostic_state: Arc::new(Mutex::new(None)),
            child_qmp_state: Arc::new(Mutex::new(None)),
            child_console_state: Arc::new(Mutex::new(None)),
            process_contract_state: Arc::new(Mutex::new(None)),
            child_files_state: Arc::new(Mutex::new(None)),
            fail_descriptor_install: false,
            fail_descriptor_close: false,
            fail_endpoint_install: false,
            mismatch_endpoint_disposition: false,
            mismatch_request_basis: false,
            serve_child_qmp: false,
            template_query_count: Arc::new(Mutex::new(0)),
            hot_fork_script: HotForkScript::Rejected,
        },
    );
    Ok(QemuNode::new(
        QemuNodeChild::new(child),
        channels,
        node_shutdown_policy(),
        QemuAsyncDriverPolicy::fast_test(),
        QemuCrashDetector::new("vm-a"),
        ScriptedHostIoRuntime {
            log,
            outcomes: VecDeque::new(),
            fault_results: VecDeque::new(),
            staged_fault_events,
            fingerprint_fault_events: VecDeque::new(),
            fail_hot_fork_clone: false,
        },
        2,
    ))
}

fn fault_event_with_sequence(event_sequence: u64) -> DequeuedFaultEvent {
    let payload = Vec::new();
    DequeuedFaultEvent {
        header: FaultEventHeaderV1 {
            command_kind: FaultCommandKind::CpuService,
            outcome: FaultEventOutcomeV1::Applied,
            event_sequence,
            rule_command_sequence: 1,
            observed_icount: 1,
            model_phase: 1,
            target_kind: 1,
            generation: 1,
            binding_hash: [1; 32],
            opportunity_hash: [2; 32],
            action_hash: [3; 32],
            target_hash: [4; 32],
            before_hash: [5; 32],
            after_hash: [6; 32],
            evidence_hash: [7; 32],
            payload_hash: *blake3::hash(&payload).as_bytes(),
            payload_offset: 0,
            payload_length: 0,
        },
        payload,
    }
}

fn scripted_node_with_coverage(
    log: SharedLog,
    options: ScriptedNodeOptions,
    runtime_outcomes: impl IntoIterator<Item = QemuAsyncWaitOutcome>,
    quantum_coverage: impl IntoIterator<Item = Vec<ObservableEvent>>,
    teardown_coverage: impl IntoIterator<Item = ObservableEvent>,
) -> Result<QemuNode, Box<dyn Error>> {
    let quantum_coverage = quantum_coverage.into_iter().collect::<VecDeque<_>>();
    let teardown_coverage = teardown_coverage.into_iter().collect::<Vec<_>>();
    let coverage_enabled = !quantum_coverage.is_empty() || !teardown_coverage.is_empty();
    let child = Command::new("sleep").arg("60").spawn()?;
    let process_id = child.id();
    let channels = QemuNodeChannels::new(
        ScriptedPluginControl {
            log: Arc::clone(&log),
            fail_quit: options.fail_plugin_quit,
        },
        ScriptedShmemHotPath {
            log: Arc::clone(&log),
            fail_advance: options.fail_shmem_advance,
            coverage_enabled,
            quantum_coverage: Arc::new(Mutex::new(quantum_coverage)),
            teardown_coverage: Arc::new(Mutex::new(teardown_coverage)),
            fault_commands: Arc::new(Mutex::new(Vec::new())),
            stale_fault_results: Arc::new(Mutex::new(VecDeque::new())),
            fault_events: Arc::new(Mutex::new(VecDeque::new())),
            fingerprint_retry_countdown: Arc::new(Mutex::new(options.fingerprint_retry_countdown)),
            hot_fork_setup_identity: None,
            hot_fork_ring_image: None,
        },
        ScriptedQmpMachineControl {
            log: Arc::clone(&log),
            process_id,
            fail_stop: options.fail_qmp_stop,
            fail_snapshot: options.fail_qmp_snapshot,
            timeout_snapshot: options.qmp_snapshot_timeout,
            plugin_resources: Some(
                crate::QmpHotForkPluginResourceInventory::one_complete_with_bindings(
                    1, 1, 2, 4096, 0, 1,
                ),
            ),
            plugin_barriers: None,
            last_plugin_barrier: Arc::new(Mutex::new(None)),
            private_ring_state: Arc::new(Mutex::new(None)),
            diagnostic_state: Arc::new(Mutex::new(None)),
            child_qmp_state: Arc::new(Mutex::new(None)),
            child_console_state: Arc::new(Mutex::new(None)),
            process_contract_state: Arc::new(Mutex::new(None)),
            child_files_state: Arc::new(Mutex::new(None)),
            fail_descriptor_install: false,
            fail_descriptor_close: false,
            fail_endpoint_install: false,
            mismatch_endpoint_disposition: false,
            mismatch_request_basis: false,
            serve_child_qmp: false,
            template_query_count: Arc::new(Mutex::new(0)),
            hot_fork_script: HotForkScript::Rejected,
        },
    );
    Ok(QemuNode::new(
        QemuNodeChild::new(child),
        channels,
        node_shutdown_policy(),
        QemuAsyncDriverPolicy::fast_test(),
        QemuCrashDetector::new("vm-a"),
        ScriptedHostIoRuntime {
            log,
            outcomes: runtime_outcomes.into_iter().collect(),
            fault_results: VecDeque::new(),
            staged_fault_events: Vec::new(),
            fingerprint_fault_events: (1..=options.fingerprint_fault_event_count)
                .map(|sequence| fault_event_with_sequence(u64::from(sequence)))
                .collect(),
            fail_hot_fork_clone: false,
        },
        2,
    ))
}

fn node_shutdown_policy() -> QemuShutdownPolicy {
    let mut policy = QemuShutdownPolicy::fast_test();
    policy.sigterm_wait = Duration::from_secs(2);
    policy.sigkill_wait = Duration::from_secs(1);
    policy.reap_wait = Duration::from_secs(1);
    policy
}

fn shared_log() -> SharedLog {
    Arc::new(Mutex::new(Vec::new()))
}

fn recorded(log: &SharedLog) -> Vec<ChannelCall> {
    log.lock().unwrap().clone()
}

fn node_id(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn checkpoint(name: &str) -> Checkpoint {
    Checkpoint::new(
        content_hash("checkpoint", name),
        content_hash("configuration", name),
        CheckpointKind::Fat,
    )
}

fn content_hash(domain: &str, material: &str) -> ContentHash {
    ContentHash::from_canonical_material(domain, material)
}
