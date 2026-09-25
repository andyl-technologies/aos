//! Scripted retained-template transport for cross-crate hot-fork tests.

use std::collections::{BTreeMap, VecDeque};
use std::io::{BufRead, BufReader, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::process::ExitStatusExt as _;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
#[cfg(feature = "test-support")]
use std::time::Instant;

use crucible::{AdvanceOutcome, Checkpoint, ExecutionFingerprint, Icount, ObservableEvent};
// crucible-lint: allow host-nondeterminism-state -- the scripted transport forwards fixed test input into the same validated node boundary as the production channel.
use crucible::BackendInput;
// crucible-lint: allow host-nondeterminism-state -- the fixed fixture horizon is an untrusted transport response consumed by scheduler validation.
use crucible::ExecutionHorizon;
use crucible_shmem::{
    CoverageEntry, DequeuedFaultEvent, DequeuedFaultResult, FaultCommandHeaderV1,
    FingerprintSample as QemuFingerprintSample, RegionAllocation, RegionConfig, mmap_setup_region,
};

use super::super::*;
use crate::{QemuAsyncDriverRuntimeError, QemuAsyncWait, QemuAsyncWaitOutcome};

const TEMPLATE_GENERATION: u64 = 1;
const PROCESS_CONTRACT_GENERATION: u64 = 13;
const CHILD_FILES_GENERATION: u64 = 17;

fn spawn_scripted_process() -> std::io::Result<std::process::Child> {
    // Quarantine tests deliberately retain live children, so the fixture must
    // not retain the test harness's input or output pipes with them.
    Command::new("sleep")
        .arg("60")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
}

#[cfg(feature = "test-support")]
// crucible-lint: allow clippy-disallowed-method -- host time bounds scripted process teardown only and never enters modeled state.
#[allow(clippy::disallowed_methods)]
fn wait_for_scripted_process_termination(process_id: u32) -> std::io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(2);
    let stat_path = format!("/proc/{process_id}/stat");
    loop {
        match std::fs::read_to_string(&stat_path) {
            Ok(stat) => {
                let state = stat
                    .rsplit_once(") ")
                    .and_then(|(_identity, fields)| fields.chars().next())
                    .ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "scripted source process status is malformed",
                        )
                    })?;
                if state == 'Z' {
                    return Ok(());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        }
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "scripted source did not terminate within two seconds",
            ));
        }
        thread::sleep(Duration::from_millis(1));
    }
}

/// Scripted parent outcome used by cross-crate hot-fork ownership tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QemuTestHotForkOutcome {
    /// Returns a complete fork result.
    Forked,
    /// Rejects the first fork before creating a child, then allows a retry.
    #[cfg(feature = "test-support")]
    RejectedOnce,
    /// Rejects before creating a child after terminating the scripted source.
    #[cfg(feature = "test-support")]
    RejectedAfterSourceExit,
    /// Rejects one deliberately corrupted isolation class before child creation.
    #[cfg(feature = "test-support")]
    IsolationRejected(QemuTestHotForkIsolationFault),
    /// Loses the command disposition after QEMU may have forked.
    Indeterminate,
}

/// Resource-class corruption injected into the production hot-fork acceptance path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(feature = "test-support")]
pub enum QemuTestHotForkIsolationFault {
    /// Omits the branch-private setup ring.
    PrivateRingOmitted,
    /// Aliases the child QMP endpoint with inherited control authority.
    ControlAliased,
    /// Aliases the child console and diagnostics streams.
    ConsoleDiagnosticsAliased,
    /// Aliases the writable child disk with its immutable backing.
    WritableDiskBackingAliased,
    /// Omits the branch-private deterministic network continuation.
    NetworkOmitted,
    /// Aliases the child 9p continuation with its source.
    NinepAliased,
    /// Aliases the child to a foreign host-continuation identity.
    HostContinuationIdentityAliased,
}

#[cfg(feature = "test-support")]
impl QemuTestHotForkIsolationFault {
    /// Returns the stable evidence label used by the native isolation gate.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::PrivateRingOmitted => "private-ring-omitted",
            Self::ControlAliased => "qmp-control-aliased",
            Self::ConsoleDiagnosticsAliased => "console-diagnostics-aliased",
            Self::WritableDiskBackingAliased => "writable-disk-backing-aliased",
            Self::NetworkOmitted => "network-omitted",
            Self::NinepAliased => "ninep-aliased",
            Self::HostContinuationIdentityAliased => "host-continuation-identity-aliased",
        }
    }
}

/// One scripted QEMU quantum boundary for node-set tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QemuTestQuantumBoundary {
    /// Reaches the requested scheduler ceiling.
    Reached,
    /// Parks before the requested ceiling with an optional exact wake.
    Paused {
        /// Physical instruction count at the park point.
        at: u64,
        /// Exact next wake instruction count, when one exists.
        next_deadline: Option<u64>,
    },
}

#[derive(Clone)]
struct ScriptedShmemHotPath {
    setup_identity: crucible_shmem::SetupRegionBackingIdentity,
    host_barrier: crucible_shmem::MappedRingIoBarrierSnapshot,
    image: crucible_shmem::HotForkRingImage,
    observable_events: VecDeque<ObservableEvent>,
    selectable_catalog_plan:
        Option<crucible_protocol::selectable_catalog_plan::SelectableCatalogPlan>,
    deferred_selectable_requests:
        VecDeque<crucible_protocol::selectable_catalog_plan::SelectablePlanPendingRequest>,
    quantum_boundaries: VecDeque<QemuTestQuantumBoundary>,
    quantum_completed: bool,
}

#[derive(Clone, Copy)]
struct ScriptedPluginControl;

#[derive(Clone, Copy)]
struct ScriptedHostIoRuntime;

struct ScriptedChildFiles {
    generation: u64,
    files: Vec<crate::QmpHotForkChildFile>,
    descriptors: Vec<OwnedFd>,
    maximum_bytes: u64,
}

struct ScriptedProcessContract {
    generation: u64,
    names: crate::QmpHotForkChildProcessContractNames,
    identity: crate::QmpHotForkChildProcessContractIdentity,
}

struct ScriptedRetainedChild {
    process: std::process::Child,
    process_id: u32,
    terminal: Option<(crate::QmpHotForkChildProcessPhase, u8)>,
}

type RetainedStream = (crate::QmpDescriptorName, u64, bool);

struct ScriptedQmpMachineControl {
    #[cfg(feature = "test-support")]
    process_id: u32,
    resource_identity: crucible_shmem::SetupRegionBackingIdentity,
    plugin_barriers: VecDeque<crate::QmpHotForkPluginBarrierState>,
    last_plugin_barrier: Option<crate::QmpHotForkPluginBarrierState>,
    private_ring: Option<(
        crate::QmpDescriptorName,
        crucible_shmem::SetupRegionBackingIdentity,
        u64,
    )>,
    diagnostics: Option<RetainedStream>,
    child_qmp: Option<RetainedStream>,
    child_qmp_endpoint: Option<std::os::unix::net::UnixStream>,
    child_console: Option<RetainedStream>,
    process_contract: Option<ScriptedProcessContract>,
    child_files: Option<ScriptedChildFiles>,
    retained_children: BTreeMap<u64, ScriptedRetainedChild>,
    next_process_contract_generation: u64,
    next_child_files_generation: u64,
    aborted: bool,
    outcome: QemuTestHotForkOutcome,
}

/// Builds one live scripted source with the complete QMP hot-fork protocol.
///
/// # Errors
///
/// Returns an error when the fixture cannot allocate its process, descriptors,
/// shared-memory image, or scripted transport state.
pub fn scripted_hot_fork_source_for_test(
    outcome: QemuTestHotForkOutcome,
) -> Result<QemuNode, QemuTestHotForkSourceError> {
    scripted_hot_fork_source_with_observations_for_test(outcome, Vec::new())
}

/// Builds one live scripted source whose forked child emits fixed observations.
///
/// # Errors
///
/// Returns an error when the fixture cannot allocate its process, descriptors,
/// shared-memory image, or scripted transport state.
pub fn scripted_hot_fork_source_with_observations_for_test(
    outcome: QemuTestHotForkOutcome,
    observable_events: Vec<ObservableEvent>,
) -> Result<QemuNode, QemuTestHotForkSourceError> {
    scripted_hot_fork_source_with_state_for_test(outcome, observable_events, None)
}

/// Builds one live scripted source with fixed observations and selectable state.
///
/// # Errors
///
/// Returns an error when the fixture cannot allocate its process, descriptors,
/// shared-memory image, or scripted transport state.
pub fn scripted_hot_fork_source_with_state_for_test(
    outcome: QemuTestHotForkOutcome,
    observable_events: Vec<ObservableEvent>,
    selectable_state: Option<(
        crucible_protocol::selectable_catalog_plan::SelectableCatalogPlan,
        crucible_protocol::selectable_catalog_plan::SelectablePlanPendingRequest,
    )>,
) -> Result<QemuNode, QemuTestHotForkSourceError> {
    let (selectable_catalog_plan, deferred_selectable_requests) = selectable_state
        .map_or((None, VecDeque::new()), |(plan, request)| {
            (Some(plan), VecDeque::from([request]))
        });
    scripted_hot_fork_source_with_script_for_test(
        outcome,
        observable_events,
        selectable_catalog_plan,
        deferred_selectable_requests,
        VecDeque::new(),
    )
}

/// Builds one live scripted source with exact quantum and selectable sequences.
///
/// # Errors
///
/// Returns an error when the fixture cannot allocate its process, descriptors,
/// shared-memory image, or scripted transport state.
pub fn scripted_hot_fork_source_with_script_for_test(
    outcome: QemuTestHotForkOutcome,
    observable_events: Vec<ObservableEvent>,
    selectable_catalog_plan: Option<
        crucible_protocol::selectable_catalog_plan::SelectableCatalogPlan,
    >,
    deferred_selectable_requests: VecDeque<
        crucible_protocol::selectable_catalog_plan::SelectablePlanPendingRequest,
    >,
    quantum_boundaries: VecDeque<QemuTestQuantumBoundary>,
) -> Result<QemuNode, QemuTestHotForkSourceError> {
    let (setup_identity, host_barrier, image) = held_hot_fork_ring_image()?;
    let plugin_barrier =
        crate::QmpHotForkPluginBarrierState::one_quiescent(15, host_barrier.ring_count());
    let child = spawn_scripted_process()
        .map_err(|source| QemuTestHotForkSourceError::new("spawn scripted source", source))?;
    #[cfg(feature = "test-support")]
    let process_id = child.id();
    let channels = QemuNodeChannels::new(
        ScriptedPluginControl,
        ScriptedShmemHotPath {
            setup_identity,
            host_barrier,
            image,
            observable_events: observable_events.into(),
            selectable_catalog_plan,
            deferred_selectable_requests,
            quantum_boundaries,
            quantum_completed: false,
        },
        ScriptedQmpMachineControl {
            #[cfg(feature = "test-support")]
            process_id,
            resource_identity: setup_identity,
            plugin_barriers: [plugin_barrier; 32].into_iter().collect(),
            last_plugin_barrier: None,
            private_ring: None,
            diagnostics: None,
            child_qmp: None,
            child_qmp_endpoint: None,
            child_console: None,
            process_contract: None,
            child_files: None,
            retained_children: BTreeMap::new(),
            next_process_contract_generation: PROCESS_CONTRACT_GENERATION,
            next_child_files_generation: CHILD_FILES_GENERATION,
            aborted: false,
            outcome,
        },
    );

    let mut shutdown_policy = QemuShutdownPolicy::fast_test();
    shutdown_policy.sigterm_wait = Duration::from_secs(2);
    shutdown_policy.sigkill_wait = Duration::from_secs(1);
    shutdown_policy.reap_wait = Duration::from_secs(1);

    Ok(QemuNode::new(
        QemuNodeChild::new(child),
        channels,
        shutdown_policy,
        QemuAsyncDriverPolicy::fast_test(),
        QemuCrashDetector::new("scripted-hot-fork-source"),
        ScriptedHostIoRuntime,
        2,
    ))
}

fn held_hot_fork_ring_image() -> Result<
    (
        crucible_shmem::SetupRegionBackingIdentity,
        crucible_shmem::MappedRingIoBarrierSnapshot,
        crucible_shmem::HotForkRingImage,
    ),
    QemuTestHotForkSourceError,
> {
    let mut allocation =
        RegionAllocation::new_model(RegionConfig::new(1, 4)).map_err(|source| {
            QemuTestHotForkSourceError::new("allocate scripted shared memory", source)
        })?;
    let entry = CoverageEntry::new(17, 0, 0x4000, 4, 9).map_err(|source| {
        QemuTestHotForkSourceError::new("construct scripted coverage entry", source)
    })?;
    allocation
        .enqueue_coverage_entry(0, entry)
        .map_err(|source| {
            QemuTestHotForkSourceError::new("enqueue scripted coverage entry", source)
        })?;
    let mut shmem = tempfile::tempfile().map_err(|source| {
        QemuTestHotForkSourceError::new("create scripted shared-memory file", source)
    })?;
    let bytes = allocation.setup_region_bytes().map_err(|source| {
        QemuTestHotForkSourceError::new("encode scripted shared-memory region", source)
    })?;
    shmem.write_all(&bytes).map_err(|source| {
        QemuTestHotForkSourceError::new("write scripted shared-memory region", source)
    })?;
    let mapped =
        mmap_setup_region(shmem.as_fd(), allocation.layout().region_size).map_err(|source| {
            QemuTestHotForkSourceError::new("map scripted shared-memory region", source)
        })?;
    let identity = mapped.backing_identity();
    let host_barrier = mapped.hold_hot_fork_ring_io().map_err(|source| {
        QemuTestHotForkSourceError::new("hold scripted hot-fork ring I/O", source)
    })?;
    let image = mapped
        .capture_hot_fork_ring_image(usize::MAX)
        .map_err(|source| {
            QemuTestHotForkSourceError::new("capture scripted hot-fork ring image", source)
        })?;

    Ok((identity, host_barrier, image))
}

/// Typed failure while constructing a scripted retained-template source.
#[derive(Debug, thiserror::Error)]
#[error("{operation}: {message}")]
pub struct QemuTestHotForkSourceError {
    operation: &'static str,
    message: String,
}

impl QemuTestHotForkSourceError {
    fn new(operation: &'static str, source: impl std::error::Error) -> Self {
        Self {
            operation,
            message: source.to_string(),
        }
    }
}

impl QemuPluginIpcControlChannel for ScriptedPluginControl {
    fn send_quit(&mut self) -> Result<(), QemuNodeChannelError> {
        Ok(())
    }
}

impl ScriptedQmpMachineControl {
    fn fork_child_state(
        &mut self,
        generation: u64,
    ) -> Result<crate::QmpHotForkChildProcessState, QemuNodeChannelError> {
        let child = self.retained_children.get_mut(&generation).ok_or_else(|| {
            QemuNodeChannelError::new(
                "query scripted hot-fork child",
                "scripted child process-contract generation is absent",
            )
        })?;
        if child.terminal.is_none() {
            let status = child.process.try_wait().map_err(|source| {
                QemuNodeChannelError::new("query scripted hot-fork child", source.to_string())
            })?;
            if let Some(status) = status {
                let terminal = if let Some(code) = status.code() {
                    (
                        crate::QmpHotForkChildProcessPhase::Exited,
                        u8::try_from(code).unwrap_or(u8::MAX),
                    )
                } else {
                    (
                        crate::QmpHotForkChildProcessPhase::Signaled,
                        status
                            .signal()
                            .and_then(|signal| u8::try_from(signal).ok())
                            .unwrap_or(u8::MAX),
                    )
                };
                child.terminal = Some(terminal);
            }
        }

        let process_id = child.process_id;
        let (phase, status) = child
            .terminal
            .unwrap_or((crate::QmpHotForkChildProcessPhase::Running, 0));
        Ok(crate::QmpHotForkChildProcessState::for_test(
            generation, process_id, phase, status, true,
        ))
    }
}

impl QemuShmemHotPathChannel for ScriptedShmemHotPath {
    fn hot_fork_setup_region_identity(
        &mut self,
    ) -> Result<crucible_shmem::SetupRegionBackingIdentity, QemuNodeChannelError> {
        Ok(self.setup_identity)
    }

    fn hot_fork_ring_io_snapshot(
        &mut self,
    ) -> Result<crucible_shmem::MappedRingIoBarrierSnapshot, QemuNodeChannelError> {
        Ok(self.host_barrier)
    }

    fn capture_hot_fork_ring_image(
        &mut self,
        maximum_bytes: usize,
    ) -> Result<crucible_shmem::HotForkRingImage, QemuNodeChannelError> {
        let required = self.image.canonical_len().map_err(|source| {
            QemuNodeChannelError::new("measure scripted hot-fork ring image", source.to_string())
        })?;
        if required > maximum_bytes {
            return Err(QemuNodeChannelError::new(
                "capture scripted hot-fork ring image",
                "scripted ring image exceeds its bound",
            ));
        }
        Ok(self.image.clone())
    }

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
        Ok(())
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

    fn current_icount(&mut self) -> Result<Icount, QemuNodeChannelError> {
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

    fn virtual_timer_fire_witness(
        &mut self,
    ) -> Result<Option<QemuVirtualTimerFireWitness>, QemuNodeChannelError> {
        Ok(None)
    }

    fn start_quantum(
        &mut self,
        // crucible-lint: allow host-nondeterminism-state -- this test source returns a scripted horizon without making a scheduler decision.
        horizon: ExecutionHorizon,
        _stop_condition: crate::QemuQuantumStopCondition,
    ) -> Result<QemuNodePendingQuantum, QemuNodeChannelError> {
        self.quantum_completed = true;
        Ok(QemuNodePendingQuantum::new(horizon.icount.retired))
    }

    fn poll_quantum(
        &mut self,
        pending: &mut QemuNodePendingQuantum,
    ) -> Result<QemuAsyncQuantumCompletion, QemuNodeChannelError> {
        let horizon = *pending.downcast_mut::<u64>("finish scripted quantum")?;
        let boundary = self
            .quantum_boundaries
            .pop_front()
            .unwrap_or(QemuTestQuantumBoundary::Reached);
        let (outcome, final_state) = match boundary {
            QemuTestQuantumBoundary::Reached => (
                AdvanceOutcome::ReachedHorizon,
                QemuNodeIdleState {
                    current_icount: Icount { retired: horizon },
                    next_deadline: None,
                },
            ),
            QemuTestQuantumBoundary::Paused { at, next_deadline } => (
                AdvanceOutcome::Paused {
                    at: Icount { retired: at },
                },
                QemuNodeIdleState {
                    current_icount: Icount { retired: at },
                    next_deadline: next_deadline.map(|retired| Icount { retired }),
                },
            ),
        };
        Ok(QemuAsyncQuantumCompletion {
            ceiling: Icount { retired: horizon },
            outcome,
            final_state,
            inbound_frames_consumed: 0,
            emitted_frames: Vec::new(),
            operations: Vec::new(),
        })
    }

    fn publish_preemption_command(
        &mut self,
        _command: crucible_shmem::SchedulerPreemptionCommand,
    ) -> Result<(), QemuNodeChannelError> {
        Ok(())
    }

    fn enqueue_fault_command(
        &mut self,
        _header: FaultCommandHeaderV1,
        _payload: &[u8],
    ) -> Result<(), QemuNodeChannelError> {
        Ok(())
    }

    fn dequeue_fault_result(
        &mut self,
    ) -> Result<Option<DequeuedFaultResult>, QemuNodeChannelError> {
        Ok(None)
    }

    fn dequeue_fault_event(&mut self) -> Result<Option<DequeuedFaultEvent>, QemuNodeChannelError> {
        Ok(None)
    }

    fn fault_event_pending(&mut self) -> Result<bool, QemuNodeChannelError> {
        Ok(false)
    }

    fn fault_event_count(&mut self) -> Result<usize, QemuNodeChannelError> {
        Ok(0)
    }

    fn snapshot_fault_events(
        &mut self,
        _destination: &mut Vec<DequeuedFaultEvent>,
        _canonical_payload_bytes: &mut usize,
        _configured_payload_bytes: usize,
        _configured_inline_payload_bytes: usize,
    ) -> Result<(), QemuNodeError> {
        Ok(())
    }

    fn drain_observable_events(&mut self) -> Result<Vec<ObservableEvent>, QemuNodeChannelError> {
        Ok(self.observable_events.drain(..).collect())
    }

    fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<
        Vec<crucible_protocol::selectable_catalog_plan::SelectablePlanPendingRequest>,
        QemuNodeChannelError,
    > {
        if !self.quantum_completed {
            return Ok(Vec::new());
        }
        self.quantum_completed = false;
        let Some(pending) = self.deferred_selectable_requests.pop_front() else {
            return Ok(Vec::new());
        };
        let plan = self.selectable_catalog_plan.as_mut().ok_or_else(|| {
            QemuNodeChannelError::new(
                "publish scripted selectable request",
                "scripted selectable catalog is absent",
            )
        })?;
        plan.apply_pending_request(pending.clone())
            .map_err(|error| {
                QemuNodeChannelError::new("publish scripted selectable request", error.to_string())
            })?;
        Ok(vec![pending])
    }

    fn enqueue_selectable_reply(
        &mut self,
        pending: &crucible_protocol::selectable_catalog_plan::SelectablePlanPendingRequest,
        reply: &crucible_protocol::SelectionReply,
    ) -> Result<(), QemuNodeChannelError> {
        let plan = self.selectable_catalog_plan.as_mut().ok_or_else(|| {
            QemuNodeChannelError::new(
                "complete scripted selectable request",
                "scripted selectable catalog is absent",
            )
        })?;
        if plan.continuation().pending() != Some(pending) {
            return Err(QemuNodeChannelError::new(
                "complete scripted selectable request",
                "scripted pending request changed",
            ));
        }
        plan.apply_completed_reply(reply).map_err(|error| {
            QemuNodeChannelError::new("complete scripted selectable request", error.to_string())
        })
    }

    fn selectable_catalog_plan(
        &self,
    ) -> Option<&crucible_protocol::selectable_catalog_plan::SelectableCatalogPlan> {
        self.selectable_catalog_plan.as_ref()
    }

    // crucible-lint: allow host-nondeterminism-state -- this test source deliberately discards the already-modeled frame input.
    fn deliver_frame(&mut self, _input: BackendInput) -> Result<(), QemuNodeChannelError> {
        Ok(())
    }

    fn deliver_frame_at(
        &mut self,
        input: BackendInput,
        _delivery_icount: Icount,
    ) -> Result<(), QemuNodeChannelError> {
        self.deliver_frame(input)
    }

    fn emit_frame(&mut self) -> Result<Option<QemuNodeEmittedFrame>, QemuNodeChannelError> {
        Ok(None)
    }

    fn idle_state(&mut self) -> Result<QemuNodeIdleState, QemuNodeChannelError> {
        Ok(QemuNodeIdleState {
            current_icount: Icount { retired: 11 },
            next_deadline: None,
        })
    }

    fn execution_fingerprint(&mut self) -> Result<ExecutionFingerprint, QemuNodeChannelError> {
        Ok(ExecutionFingerprint {
            hash: crucible::model::ContentHash::from_bytes(b"scripted-hot-fork-source"),
        })
    }

    fn fingerprint_sample(&mut self) -> Result<QemuFingerprintSample, QemuNodeChannelError> {
        Ok(QemuFingerprintSample::default())
    }
}

impl QemuHostIoRuntime for ScriptedHostIoRuntime {
    fn clone_hot_fork_host_io_continuation(
        &mut self,
        _execution_binding: crucible::model::ContentHash,
        _shmem_fd: BorrowedFd<'_>,
        _wake_fd: BorrowedFd<'_>,
        _region_len: u64,
        _console: Option<crate::QemuHotForkChildConsoleObservation>,
    ) -> Result<Box<dyn QemuHostIoRuntime>, QemuAsyncDriverRuntimeError> {
        Ok(Box::new(*self))
    }

    fn publish_current_execution_fingerprint(
        &mut self,
        _timeout: Duration,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        Ok(())
    }

    fn yield_to_control_plane(&mut self) -> Result<(), QemuAsyncDriverRuntimeError> {
        Ok(())
    }

    fn await_child(
        &mut self,
        _wait: QemuAsyncWait,
        _timeout: Duration,
    ) -> Result<QemuAsyncWaitOutcome, QemuAsyncDriverRuntimeError> {
        Ok(QemuAsyncWaitOutcome::Completed)
    }

    fn repoll_child(
        &mut self,
        wait: QemuAsyncWait,
        timeout: Duration,
    ) -> Result<QemuAsyncWaitOutcome, QemuAsyncDriverRuntimeError> {
        self.await_child(wait, timeout)
    }
}

impl QemuQmpMachineControlChannel for ScriptedQmpMachineControl {
    #[cfg(unix)]
    fn install_exact_checkpoint_descriptor(
        &mut self,
        _name: &crate::QmpDescriptorName,
        _descriptor: BorrowedFd<'_>,
    ) -> Result<(), QemuNodeChannelError> {
        reject_out_of_scope_scripted_hot_fork_qmp("install exact checkpoint descriptor")
    }

    fn capture_exact_checkpoint(
        &mut self,
        _request: &crate::QmpCheckpointCaptureRequest,
    ) -> Result<crate::QmpCheckpointCapture, QemuNodeChannelError> {
        reject_out_of_scope_scripted_hot_fork_qmp("capture exact checkpoint")
    }

    fn commit_exact_checkpoint(
        &mut self,
        _identity: crate::QmpCheckpointIdentity,
    ) -> Result<crate::QmpCheckpointEpochState, QemuNodeChannelError> {
        reject_out_of_scope_scripted_hot_fork_qmp("commit exact checkpoint")
    }

    fn abort_exact_checkpoint(
        &mut self,
        _identity: crate::QmpCheckpointIdentity,
        _expected_committed: Option<crate::QmpCheckpointIdentity>,
    ) -> Result<crate::QmpCheckpointEpochState, QemuNodeChannelError> {
        reject_out_of_scope_scripted_hot_fork_qmp("abort exact checkpoint")
    }

    fn query_exact_checkpoint_epoch(
        &mut self,
    ) -> Result<crate::QmpCheckpointEpochState, QemuNodeChannelError> {
        reject_out_of_scope_scripted_hot_fork_qmp("query exact checkpoint epoch")
    }

    fn query_hot_fork_child_runtime(
        &mut self,
    ) -> Result<crate::QmpHotForkChildRuntimeState, QemuNodeChannelError> {
        reject_out_of_scope_scripted_hot_fork_qmp("query hot-fork child runtime")
    }

    fn prepare_hot_fork_template(
        &mut self,
        _block_snapshot_bindings: &[crate::QmpHotForkBlockSnapshotBinding],
    ) -> Result<crate::QmpHotForkTemplateState, QemuNodeChannelError> {
        reject_out_of_scope_scripted_hot_fork_qmp("prepare hot-fork template")
    }

    fn stop_for_checkpoint(&mut self) -> Result<(), QemuNodeChannelError> {
        Ok(())
    }

    fn resume_after_checkpoint(&mut self) -> Result<(), QemuNodeChannelError> {
        Ok(())
    }

    fn query_hot_fork_plugin_resource_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkPluginResourceInventory, QemuNodeChannelError> {
        Ok(
            crate::QmpHotForkPluginResourceInventory::one_complete_with_bindings(
                1,
                self.resource_identity.device(),
                self.resource_identity.inode(),
                self.resource_identity.length(),
                0,
                1,
            ),
        )
    }

    fn query_hot_fork_plugin_barrier(
        &mut self,
    ) -> Result<crate::QmpHotForkPluginBarrierState, QemuNodeChannelError> {
        let barrier = self.plugin_barriers.pop_front().ok_or_else(|| {
            QemuNodeChannelError::new(
                "query scripted hot-fork plugin barrier",
                "scripted plugin barrier sequence is exhausted",
            )
        })?;
        self.last_plugin_barrier = Some(barrier);
        Ok(barrier)
    }

    fn prepare_hot_fork_template_barriers(
        &mut self,
        _block_snapshot_bindings: &[crate::QmpHotForkBlockSnapshotBinding],
    ) -> Result<crate::QmpHotForkTemplateState, QemuNodeChannelError> {
        self.aborted = false;
        Ok(crate::QmpHotForkTemplateState::one_draining_without_resources(exact_hot_fork_request()))
    }

    fn query_hot_fork_template(
        &mut self,
    ) -> Result<crate::QmpHotForkTemplateState, QemuNodeChannelError> {
        let resources_are_sealed = self
            .child_console
            .as_ref()
            .is_some_and(|(_name, _cookie, bound)| *bound);
        Ok(if self.aborted {
            crate::QmpHotForkTemplateState::one_aborted(exact_hot_fork_request())
        } else if resources_are_sealed {
            crate::QmpHotForkTemplateState::one_prepared(exact_hot_fork_request())
        } else {
            crate::QmpHotForkTemplateState::one_draining_without_resources(exact_hot_fork_request())
        })
    }

    fn abort_hot_fork_template(
        &mut self,
    ) -> Result<crate::QmpHotForkTemplateState, QemuNodeChannelError> {
        self.aborted = true;
        Ok(crate::QmpHotForkTemplateState::one_aborted(
            exact_hot_fork_request(),
        ))
    }

    fn install_hot_fork_private_ring_descriptor(
        &mut self,
        name: &crate::QmpDescriptorName,
        _descriptor: BorrowedFd<'_>,
        identity: crucible_shmem::SetupRegionBackingIdentity,
    ) -> Result<(), QemuNodeChannelError> {
        self.private_ring = Some((name.clone(), identity, 1));
        Ok(())
    }

    fn close_hot_fork_private_ring_descriptor(
        &mut self,
        _name: &crate::QmpDescriptorName,
        _identity: crucible_shmem::SetupRegionBackingIdentity,
    ) -> Result<(), QemuNodeChannelError> {
        self.private_ring = None;
        Ok(())
    }

    fn query_hot_fork_private_rings(
        &mut self,
    ) -> Result<crate::QmpHotForkPrivateRingState, QemuNodeChannelError> {
        let (name, identity, generation) = self.private_ring.as_ref().ok_or_else(|| {
            QemuNodeChannelError::new(
                "query scripted hot-fork private rings",
                "scripted private-ring stage is absent",
            )
        })?;
        Ok(crate::QmpHotForkPrivateRingState::one_template_staged(
            *generation,
            TEMPLATE_GENERATION,
            name.clone(),
            identity.device(),
            identity.inode(),
            identity.length(),
        ))
    }

    fn install_hot_fork_child_diagnostics(
        &mut self,
        name: &crate::QmpDescriptorName,
        descriptor: BorrowedFd<'_>,
        socket_cookie: u64,
        template_generation: u64,
    ) -> Result<crate::QmpHotForkChildDiagnosticState, QemuNodeChannelError> {
        let descriptor = descriptor.try_clone_to_owned().map_err(|source| {
            QemuNodeChannelError::new(
                "install scripted hot-fork child diagnostics",
                source.to_string(),
            )
        })?;
        let mut writer = std::os::unix::net::UnixStream::from(descriptor);
        writer
            .write_all(b"scripted child diagnostics")
            .map_err(|source| {
                QemuNodeChannelError::new(
                    "write scripted hot-fork child diagnostics",
                    source.to_string(),
                )
            })?;
        self.diagnostics = Some((name.clone(), socket_cookie, false));

        Ok(crate::QmpHotForkChildDiagnosticState::one_template_staged(
            1,
            template_generation,
            name.clone(),
            socket_cookie,
            32,
            false,
        ))
    }

    fn close_hot_fork_child_diagnostics(
        &mut self,
        _name: &crate::QmpDescriptorName,
        _socket_cookie: u64,
    ) -> Result<(), QemuNodeChannelError> {
        self.diagnostics = None;
        Ok(())
    }

    fn query_hot_fork_child_diagnostics(
        &mut self,
    ) -> Result<crate::QmpHotForkChildDiagnosticState, QemuNodeChannelError> {
        let (name, socket_cookie, bound) = self.diagnostics.as_ref().ok_or_else(|| {
            QemuNodeChannelError::new(
                "query scripted hot-fork child diagnostics",
                "scripted diagnostics stage is absent",
            )
        })?;
        Ok(crate::QmpHotForkChildDiagnosticState::one_template_staged(
            1,
            TEMPLATE_GENERATION,
            name.clone(),
            *socket_cookie,
            32,
            *bound,
        ))
    }

    fn install_hot_fork_child_qmp(
        &mut self,
        name: &crate::QmpDescriptorName,
        descriptor: BorrowedFd<'_>,
        socket_cookie: u64,
        template_generation: u64,
    ) -> Result<crate::QmpHotForkChildQmpState, QemuNodeChannelError> {
        let descriptor = descriptor.try_clone_to_owned().map_err(|source| {
            QemuNodeChannelError::new("install scripted hot-fork child QMP", source.to_string())
        })?;
        self.child_qmp_endpoint = Some(std::os::unix::net::UnixStream::from(descriptor));
        self.child_qmp = Some((name.clone(), socket_cookie, false));
        Ok(crate::QmpHotForkChildQmpState::one_template_staged(
            1,
            template_generation,
            7,
            name.clone(),
            socket_cookie,
            33,
            false,
            true,
        ))
    }

    fn close_hot_fork_child_qmp(
        &mut self,
        _name: &crate::QmpDescriptorName,
        _socket_cookie: u64,
    ) -> Result<(), QemuNodeChannelError> {
        self.child_qmp = None;
        Ok(())
    }

    fn query_hot_fork_child_qmp(
        &mut self,
    ) -> Result<crate::QmpHotForkChildQmpState, QemuNodeChannelError> {
        let (name, socket_cookie, bound) = self.child_qmp.as_ref().ok_or_else(|| {
            QemuNodeChannelError::new(
                "query scripted hot-fork child QMP",
                "scripted child-QMP stage is absent",
            )
        })?;
        Ok(crate::QmpHotForkChildQmpState::one_template_staged(
            1,
            TEMPLATE_GENERATION,
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
        _descriptor: BorrowedFd<'_>,
        socket_cookie: u64,
        template_generation: u64,
    ) -> Result<crate::QmpHotForkChildConsoleState, QemuNodeChannelError> {
        self.child_console = Some((name.clone(), socket_cookie, false));
        Ok(crate::QmpHotForkChildConsoleState::one_template_staged(
            1,
            template_generation,
            name.clone(),
            socket_cookie,
            34,
            false,
        ))
    }

    fn close_hot_fork_child_console(
        &mut self,
        _name: &crate::QmpDescriptorName,
        _socket_cookie: u64,
    ) -> Result<(), QemuNodeChannelError> {
        if self.child_qmp.is_none() {
            return Err(QemuNodeChannelError::new(
                "close scripted hot-fork child console",
                "child QMP stage was released out of order",
            ));
        }
        self.child_console = None;
        Ok(())
    }

    fn query_hot_fork_child_console(
        &mut self,
    ) -> Result<crate::QmpHotForkChildConsoleState, QemuNodeChannelError> {
        let (name, socket_cookie, bound) = self.child_console.as_ref().ok_or_else(|| {
            QemuNodeChannelError::new(
                "query scripted hot-fork child console",
                "scripted child-console stage is absent",
            )
        })?;
        Ok(crate::QmpHotForkChildConsoleState::one_template_staged(
            1,
            TEMPLATE_GENERATION,
            name.clone(),
            *socket_cookie,
            34,
            *bound,
        ))
    }

    fn install_hot_fork_plugin_endpoints(
        &mut self,
        control_name: &crate::QmpDescriptorName,
        _control: BorrowedFd<'_>,
        wake_name: &crate::QmpDescriptorName,
        _wake: BorrowedFd<'_>,
        identity: crate::QmpHotForkPluginEndpointIdentity,
        private_ring_generation: u64,
    ) -> Result<crate::QmpHotForkPluginEndpointState, QemuNodeChannelError> {
        let barrier = self.last_plugin_barrier.ok_or_else(|| {
            QemuNodeChannelError::new(
                "install scripted hot-fork plugin endpoints",
                "plugin barrier was not observed before endpoint staging",
            )
        })?;
        mark_stream_bound(&mut self.diagnostics, "child diagnostics")?;
        mark_stream_bound(&mut self.child_qmp, "child QMP")?;
        mark_stream_bound(&mut self.child_console, "child console")?;

        Ok(crate::QmpHotForkPluginEndpointState::one_template_staged(
            1,
            TEMPLATE_GENERATION,
            control_name.clone(),
            wake_name.clone(),
            identity,
            private_ring_generation,
            barrier,
        ))
    }

    fn close_hot_fork_plugin_endpoints(
        &mut self,
        _control_name: &crate::QmpDescriptorName,
        _wake_name: &crate::QmpDescriptorName,
        _identity: crate::QmpHotForkPluginEndpointIdentity,
    ) -> Result<(), QemuNodeChannelError> {
        for stream in [
            &mut self.diagnostics,
            &mut self.child_qmp,
            &mut self.child_console,
        ] {
            if let Some((_name, _cookie, bound)) = stream.as_mut() {
                *bound = false;
            }
        }
        Ok(())
    }

    fn install_hot_fork_child_process_contract(
        &mut self,
        names: &crate::QmpHotForkChildProcessContractNames,
        _cgroup: BorrowedFd<'_>,
        _cgroup_procs: BorrowedFd<'_>,
        _cancellation: BorrowedFd<'_>,
        identity: crate::QmpHotForkChildProcessContractIdentity,
        _template_generation: u64,
    ) -> Result<crate::QmpHotForkChildProcessContractState, QemuNodeChannelError> {
        let generation = self.next_process_contract_generation;
        self.next_process_contract_generation = generation.checked_add(1).ok_or_else(|| {
            QemuNodeChannelError::new(
                "install scripted hot-fork child process contract",
                "scripted process-contract generation overflowed",
            )
        })?;
        self.process_contract = Some(ScriptedProcessContract {
            generation,
            names: names.clone(),
            identity,
        });
        Ok(
            crate::QmpHotForkChildProcessContractState::one_template_staged(
                generation,
                TEMPLATE_GENERATION,
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
        let retained = self.process_contract.take().ok_or_else(|| {
            QemuNodeChannelError::new(
                "release scripted hot-fork child process contract",
                "scripted process contract is absent",
            )
        })?;
        if retained.names != *names || retained.identity != identity {
            return Err(QemuNodeChannelError::new(
                "release scripted hot-fork child process contract",
                "scripted process contract basis changed",
            ));
        }
        Ok(crate::QmpHotForkChildProcessContractState::one_released(
            retained.generation,
        ))
    }

    fn query_hot_fork_child_process_contract(
        &mut self,
    ) -> Result<crate::QmpHotForkChildProcessContractState, QemuNodeChannelError> {
        let contract = self.process_contract.as_ref().ok_or_else(|| {
            QemuNodeChannelError::new(
                "query scripted hot-fork child process contract",
                "scripted process contract is absent",
            )
        })?;
        Ok(
            crate::QmpHotForkChildProcessContractState::one_template_staged(
                contract.generation,
                TEMPLATE_GENERATION,
                &contract.names,
                contract.identity,
            ),
        )
    }

    fn install_hot_fork_child_files(
        &mut self,
        files: &[crate::QmpHotForkChildFile],
        descriptors: &[BorrowedFd<'_>],
        maximum_bytes: u64,
        _template_generation: u64,
    ) -> Result<crate::QmpHotForkChildFilesState, QemuNodeChannelError> {
        if files.len() != descriptors.len() {
            return Err(QemuNodeChannelError::new(
                "install scripted hot-fork child files",
                "child-file roots and descriptors differ in length",
            ));
        }
        let descriptors = descriptors
            .iter()
            .map(|descriptor| descriptor.try_clone_to_owned())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| {
                QemuNodeChannelError::new(
                    "install scripted hot-fork child files",
                    source.to_string(),
                )
            })?;
        let generation = self.next_child_files_generation;
        self.next_child_files_generation = generation.checked_add(1).ok_or_else(|| {
            QemuNodeChannelError::new(
                "install scripted hot-fork child files",
                "scripted child-file generation overflowed",
            )
        })?;
        self.child_files = Some(ScriptedChildFiles {
            generation,
            files: files.to_vec(),
            descriptors,
            maximum_bytes,
        });
        Ok(crate::QmpHotForkChildFilesState::one_template_staged(
            generation,
            TEMPLATE_GENERATION,
            maximum_bytes,
            files.to_vec(),
        ))
    }

    fn release_hot_fork_child_files(
        &mut self,
        generation: u64,
    ) -> Result<crate::QmpHotForkChildFilesState, QemuNodeChannelError> {
        let matching = self
            .child_files
            .as_ref()
            .is_some_and(|files| files.generation == generation);
        if !matching {
            return Err(QemuNodeChannelError::new(
                "release scripted hot-fork child files",
                "scripted child-file generation is absent or changed",
            ));
        }
        self.child_files = None;
        Ok(crate::QmpHotForkChildFilesState::one_released(generation))
    }

    fn query_hot_fork_child_files(
        &mut self,
    ) -> Result<crate::QmpHotForkChildFilesState, QemuNodeChannelError> {
        let Some(plan) = self.child_files.as_ref() else {
            return Ok(crate::QmpHotForkChildFilesState::one_released(0));
        };
        Ok(crate::QmpHotForkChildFilesState::one_template_staged(
            plan.generation,
            TEMPLATE_GENERATION,
            plan.maximum_bytes,
            plan.files.clone(),
        ))
    }

    fn hot_fork(
        &mut self,
        request: crate::QmpHotForkRequest,
    ) -> Result<crate::QmpHotForkState, crate::QemuHotForkCommandError> {
        match self.outcome {
            QemuTestHotForkOutcome::Forked => {
                write_child_file_payloads(self.child_files.as_ref())?;
                let child = spawn_scripted_process().map_err(|source| {
                    crate::QemuHotForkCommandError::Rejected {
                        source: QemuNodeChannelError::new(
                            "fork scripted hot-fork template",
                            source.to_string(),
                        ),
                    }
                })?;
                let child_process_id = child.id();
                let record_generation = request.child_process_contract_generation();
                if self
                    .retained_children
                    .insert(
                        record_generation,
                        ScriptedRetainedChild {
                            process: child,
                            process_id: child_process_id,
                            terminal: None,
                        },
                    )
                    .is_some()
                {
                    return Err(crate::QemuHotForkCommandError::Rejected {
                        source: QemuNodeChannelError::new(
                            "fork scripted hot-fork template",
                            "scripted process-contract generation is already retained",
                        ),
                    });
                }
                let endpoint = self.child_qmp_endpoint.take().ok_or_else(|| {
                    crate::QemuHotForkCommandError::Rejected {
                        source: QemuNodeChannelError::new(
                            "fork scripted hot-fork template",
                            "scripted child QMP endpoint is absent",
                        ),
                    }
                })?;
                let (name, socket_cookie, _bound) = self.child_qmp.as_ref().ok_or_else(|| {
                    crate::QemuHotForkCommandError::Rejected {
                        source: QemuNodeChannelError::new(
                            "fork scripted hot-fork template",
                            "scripted child QMP basis is absent",
                        ),
                    }
                })?;
                spawn_scripted_child_qmp(
                    endpoint,
                    name.clone(),
                    *socket_cookie,
                    TEMPLATE_GENERATION,
                    1,
                    7,
                );
                Ok(crate::QmpHotForkState::for_test(
                    request,
                    crate::QmpHotForkOutcome::Forked,
                    i64::from(child_process_id),
                ))
            }
            #[cfg(feature = "test-support")]
            QemuTestHotForkOutcome::RejectedOnce => {
                self.outcome = QemuTestHotForkOutcome::Forked;
                Err(crate::QemuHotForkCommandError::Rejected {
                    source: QemuNodeChannelError::new(
                        "fork scripted hot-fork template",
                        "injected no-child rejection",
                    ),
                })
            }
            #[cfg(feature = "test-support")]
            QemuTestHotForkOutcome::RejectedAfterSourceExit => {
                let process = rustix::process::Pid::from_raw(
                    i32::try_from(self.process_id).map_err(|error| {
                        crate::QemuHotForkCommandError::Rejected {
                            source: QemuNodeChannelError::new(
                                "terminate scripted hot-fork source",
                                error.to_string(),
                            ),
                        }
                    })?,
                )
                .ok_or_else(|| crate::QemuHotForkCommandError::Rejected {
                    source: QemuNodeChannelError::new(
                        "terminate scripted hot-fork source",
                        "scripted source PID must be positive",
                    ),
                })?;
                rustix::process::kill_process(process, rustix::process::Signal::KILL).map_err(
                    |error| crate::QemuHotForkCommandError::Rejected {
                        source: QemuNodeChannelError::new(
                            "terminate scripted hot-fork source",
                            error.to_string(),
                        ),
                    },
                )?;
                wait_for_scripted_process_termination(self.process_id).map_err(|error| {
                    crate::QemuHotForkCommandError::Rejected {
                        source: QemuNodeChannelError::new(
                            "await scripted hot-fork source termination",
                            error.to_string(),
                        ),
                    }
                })?;
                Err(crate::QemuHotForkCommandError::Rejected {
                    source: QemuNodeChannelError::new(
                        "fork scripted hot-fork template",
                        "injected no-child rejection after source exit",
                    ),
                })
            }
            #[cfg(feature = "test-support")]
            QemuTestHotForkOutcome::IsolationRejected(fault) => {
                Err(crate::QemuHotForkCommandError::Rejected {
                    source: QemuNodeChannelError::new(
                        "authenticate scripted hot-fork child isolation",
                        format!("injected isolation rejection: {}", fault.label()),
                    ),
                })
            }
            QemuTestHotForkOutcome::Indeterminate => {
                Err(crate::QemuHotForkCommandError::Indeterminate {
                    source: QemuNodeChannelError::new(
                        "fork scripted hot-fork template",
                        "injected indeterminate exchange",
                    ),
                })
            }
        }
    }

    fn query_hot_fork_child_process(
        &mut self,
        generation: u64,
    ) -> Result<crate::QmpHotForkChildProcessState, QemuNodeChannelError> {
        self.fork_child_state(generation)
    }

    fn release_hot_fork_child_process(
        &mut self,
        generation: u64,
    ) -> Result<crate::QmpHotForkChildProcessState, QemuNodeChannelError> {
        let state = self.fork_child_state(generation)?;
        if state.phase() == crate::QmpHotForkChildProcessPhase::Running {
            return Err(QemuNodeChannelError::new(
                "release scripted hot-fork child",
                "scripted child remains live",
            ));
        }

        self.retained_children.remove(&generation).ok_or_else(|| {
            QemuNodeChannelError::new(
                "release scripted hot-fork child",
                "scripted child record disappeared before release",
            )
        })?;
        Ok(crate::QmpHotForkChildProcessState::for_test(
            generation,
            state.child_process_id(),
            state.phase(),
            state.status(),
            false,
        ))
    }

    fn complete_terminal_lifecycle_exit(
        &mut self,
        _action: crucible::model::ContentHash,
        _evidence: crucible::model::ContentHash,
        _process_generation: u64,
    ) -> Result<(), QemuNodeChannelError> {
        Ok(())
    }

    fn save_checkpoint_vmstate(
        &mut self,
        _checkpoint: &Checkpoint,
    ) -> Result<(), QemuNodeChannelError> {
        Ok(())
    }

    fn delete_checkpoint_vmstate(
        &mut self,
        _checkpoint: &Checkpoint,
    ) -> Result<(), QemuNodeChannelError> {
        Ok(())
    }

    fn quit(&mut self) -> Result<(), QemuNodeChannelError> {
        Ok(())
    }

    fn activate_debug_guest(&mut self) -> Result<(), QemuNodeChannelError> {
        Ok(())
    }
}

fn reject_out_of_scope_scripted_hot_fork_qmp<T>(
    operation: &'static str,
) -> Result<T, QemuNodeChannelError> {
    Err(QemuNodeChannelError::new(
        operation,
        "operation is outside this scripted hot-fork test channel",
    ))
}

mod scripted_child;
use scripted_child::*;

fn exact_hot_fork_request() -> crate::QmpHotForkRequest {
    crate::QmpHotForkRequest::for_test(
        1,
        1,
        1,
        1,
        1,
        7,
        1,
        15,
        8,
        9,
        10,
        11,
        12,
        PROCESS_CONTRACT_GENERATION,
        0,
    )
}
