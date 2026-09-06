//! Scripted retained-template transport for cross-crate hot-fork tests.

use std::collections::VecDeque;
use std::error::Error;
use std::io::Write;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::process::Command;
use std::time::Duration;

use crucible::{
    AdvanceOutcome, BackendInput, Checkpoint, ExecutionFingerprint, ExecutionHorizon, Icount,
    ObservableEvent,
};
use crucible_shmem::{
    CoverageEntry, DequeuedFaultEvent, DequeuedFaultResult, FaultCommandHeaderV1,
    FingerprintSample as QemuFingerprintSample, RegionAllocation, RegionConfig, mmap_setup_region,
};

use super::super::*;
use crate::{QemuAsyncDriverRuntimeError, QemuAsyncWait, QemuAsyncWaitOutcome};

const TEMPLATE_GENERATION: u64 = 1;
const PROCESS_CONTRACT_GENERATION: u64 = 13;
const CHILD_FILES_GENERATION: u64 = 17;

/// Scripted parent outcome used by cross-crate hot-fork ownership tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QemuTestHotForkOutcome {
    /// Returns a complete fork result.
    Forked,
    /// Loses the command disposition after QEMU may have forked.
    Indeterminate,
}

#[derive(Clone)]
struct ScriptedShmemHotPath {
    setup_identity: crucible_shmem::SetupRegionBackingIdentity,
    host_barrier: crucible_shmem::MappedRingIoBarrierSnapshot,
    image: crucible_shmem::HotForkRingImage,
}

#[derive(Clone, Copy)]
struct ScriptedPluginControl;

#[derive(Clone, Copy)]
struct ScriptedHostIoRuntime;

struct ScriptedChildFiles {
    files: Vec<crate::QmpHotForkChildFile>,
    descriptors: Vec<OwnedFd>,
    maximum_bytes: u64,
}

type RetainedStream = (crate::QmpDescriptorName, u64, bool);

struct ScriptedQmpMachineControl {
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
    child_console: Option<RetainedStream>,
    process_contract: Option<(
        crate::QmpHotForkChildProcessContractNames,
        crate::QmpHotForkChildProcessContractIdentity,
    )>,
    child_files: Option<ScriptedChildFiles>,
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
) -> Result<QemuNode, Box<dyn Error>> {
    let (setup_identity, host_barrier, image) = held_hot_fork_ring_image()?;
    let plugin_barrier =
        crate::QmpHotForkPluginBarrierState::one_quiescent(15, host_barrier.ring_count());
    let child = Command::new("sleep").arg("60").spawn()?;
    let process_id = child.id();
    let channels = QemuNodeChannels::new(
        ScriptedPluginControl,
        ScriptedShmemHotPath {
            setup_identity,
            host_barrier,
            image,
        },
        ScriptedQmpMachineControl {
            process_id,
            resource_identity: setup_identity,
            plugin_barriers: [plugin_barrier; 8].into_iter().collect(),
            last_plugin_barrier: None,
            private_ring: None,
            diagnostics: None,
            child_qmp: None,
            child_console: None,
            process_contract: None,
            child_files: None,
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
    Box<dyn Error>,
> {
    let mut allocation = RegionAllocation::new_model(RegionConfig::new(1, 4, 0))?;
    allocation.enqueue_coverage_entry(0, CoverageEntry::new(17, 0, 0x4000, 4, 9)?)?;
    let mut shmem = tempfile::tempfile()?;
    shmem.write_all(&allocation.setup_region_bytes()?)?;
    let mapped = mmap_setup_region(shmem.as_fd(), allocation.layout().region_size)?;
    let identity = mapped.backing_identity();
    let host_barrier = mapped.hold_hot_fork_ring_io()?;
    let image = mapped.capture_hot_fork_ring_image(usize::MAX)?;

    Ok((identity, host_barrier, image))
}

impl QemuPluginIpcControlChannel for ScriptedPluginControl {
    fn send_quit(&mut self) -> Result<(), QemuNodeChannelError> {
        Ok(())
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

    fn start_quantum(
        &mut self,
        horizon: ExecutionHorizon,
    ) -> Result<QemuNodePendingQuantum, QemuNodeChannelError> {
        Ok(QemuNodePendingQuantum::new(horizon.icount.retired))
    }

    fn poll_quantum(
        &mut self,
        pending: &mut QemuNodePendingQuantum,
    ) -> Result<QemuAsyncQuantumCompletion, QemuNodeChannelError> {
        let horizon = *pending.downcast_mut::<u64>("finish scripted quantum")?;
        Ok(QemuAsyncQuantumCompletion {
            ceiling: Icount { retired: horizon },
            outcome: AdvanceOutcome::ReachedHorizon,
            final_state: QemuNodeIdleState {
                current_icount: Icount { retired: horizon },
                next_deadline: None,
            },
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
        Ok(Vec::new())
    }

    fn deliver_frame(&mut self, _input: BackendInput) -> Result<(), QemuNodeChannelError> {
        Ok(())
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
    fn stop_for_checkpoint(&mut self) -> Result<(), QemuNodeChannelError> {
        Ok(())
    }

    fn resume_after_checkpoint(&mut self) -> Result<(), QemuNodeChannelError> {
        Ok(())
    }

    fn query_hot_fork_readiness(
        &mut self,
    ) -> Result<crate::QmpHotForkReadiness, QemuNodeChannelError> {
        crate::QmpHotForkReadiness::from_acknowledged_proofs(7).ok_or_else(|| {
            QemuNodeChannelError::new(
                "query scripted hot-fork readiness",
                "scripted readiness bitmap is invalid",
            )
        })
    }

    fn query_hot_fork_thread_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkThreadInventory, QemuNodeChannelError> {
        Ok(crate::QmpHotForkThreadInventory::one_coordinator(
            self.process_id,
        ))
    }

    fn query_hot_fork_rcu_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkRcuInventory, QemuNodeChannelError> {
        Ok(crate::QmpHotForkRcuInventory::from_reader_ids(&[
            self.process_id
        ]))
    }

    fn query_hot_fork_aio_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkAioInventory, QemuNodeChannelError> {
        Ok(crate::QmpHotForkAioInventory::one_idle(1, self.process_id))
    }

    fn query_hot_fork_aio_handler_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkAioHandlerInventory, QemuNodeChannelError> {
        Ok(crate::QmpHotForkAioHandlerInventory::one_read(1, 1, 0))
    }

    fn query_hot_fork_block_backend_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkBlockBackendInventory, QemuNodeChannelError> {
        Ok(crate::QmpHotForkBlockBackendInventory::one_hidden(1, 1))
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
        _descriptor: BorrowedFd<'_>,
        socket_cookie: u64,
        template_generation: u64,
    ) -> Result<crate::QmpHotForkChildQmpState, QemuNodeChannelError> {
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
        self.process_contract = Some((names.clone(), identity));
        Ok(
            crate::QmpHotForkChildProcessContractState::one_template_staged(
                PROCESS_CONTRACT_GENERATION,
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
        if retained != (names.clone(), identity) {
            return Err(QemuNodeChannelError::new(
                "release scripted hot-fork child process contract",
                "scripted process contract basis changed",
            ));
        }
        Ok(crate::QmpHotForkChildProcessContractState::one_released(
            PROCESS_CONTRACT_GENERATION,
        ))
    }

    fn query_hot_fork_child_process_contract(
        &mut self,
    ) -> Result<crate::QmpHotForkChildProcessContractState, QemuNodeChannelError> {
        let (names, identity) = self.process_contract.as_ref().ok_or_else(|| {
            QemuNodeChannelError::new(
                "query scripted hot-fork child process contract",
                "scripted process contract is absent",
            )
        })?;
        Ok(
            crate::QmpHotForkChildProcessContractState::one_template_staged(
                PROCESS_CONTRACT_GENERATION,
                TEMPLATE_GENERATION,
                names,
                *identity,
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
        self.child_files = Some(ScriptedChildFiles {
            files: files.to_vec(),
            descriptors,
            maximum_bytes,
        });
        Ok(crate::QmpHotForkChildFilesState::one_template_staged(
            CHILD_FILES_GENERATION,
            TEMPLATE_GENERATION,
            maximum_bytes,
            files.to_vec(),
        ))
    }

    fn release_hot_fork_child_files(
        &mut self,
        generation: u64,
    ) -> Result<crate::QmpHotForkChildFilesState, QemuNodeChannelError> {
        if generation != CHILD_FILES_GENERATION || self.child_files.take().is_none() {
            return Err(QemuNodeChannelError::new(
                "release scripted hot-fork child files",
                "scripted child-file generation is absent or changed",
            ));
        }
        Ok(crate::QmpHotForkChildFilesState::one_released(generation))
    }

    fn query_hot_fork_child_files(
        &mut self,
    ) -> Result<crate::QmpHotForkChildFilesState, QemuNodeChannelError> {
        let Some(plan) = self.child_files.as_ref() else {
            return Ok(crate::QmpHotForkChildFilesState::one_released(0));
        };
        Ok(crate::QmpHotForkChildFilesState::one_template_staged(
            CHILD_FILES_GENERATION,
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
                Ok(crate::QmpHotForkState::for_test(
                    request,
                    crate::QmpHotForkOutcome::Forked,
                    321,
                ))
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

    fn query_hot_fork_bottom_half_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkBottomHalfInventory, QemuNodeChannelError> {
        Ok(crate::QmpHotForkBottomHalfInventory::one_idle(1, 1))
    }

    fn query_hot_fork_mutex_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkMutexInventory, QemuNodeChannelError> {
        Ok(crate::QmpHotForkMutexInventory::one_owned(
            1,
            self.process_id,
        ))
    }

    fn query_hot_fork_timer_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkTimerInventory, QemuNodeChannelError> {
        Ok(crate::QmpHotForkTimerInventory::empty())
    }

    fn query_hot_fork_monitor_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkMonitorInventory, QemuNodeChannelError> {
        Ok(crate::QmpHotForkMonitorInventory::one_supported())
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

fn mark_stream_bound(
    stream: &mut Option<RetainedStream>,
    description: &'static str,
) -> Result<(), QemuNodeChannelError> {
    let Some((_name, _cookie, bound)) = stream.as_mut() else {
        return Err(QemuNodeChannelError::new(
            "seal scripted hot-fork child stream",
            format!("scripted {description} stage is absent"),
        ));
    };
    *bound = true;
    Ok(())
}

fn write_child_file_payloads(
    child_files: Option<&ScriptedChildFiles>,
) -> Result<(), crate::QemuHotForkCommandError> {
    let Some(plan) = child_files else {
        return Ok(());
    };
    for (index, descriptor) in plan.descriptors.iter().enumerate() {
        let descriptor =
            descriptor
                .try_clone()
                .map_err(|source| crate::QemuHotForkCommandError::Rejected {
                    source: QemuNodeChannelError::new(
                        "clone scripted hot-fork child-file destination",
                        source.to_string(),
                    ),
                })?;
        let file = std::fs::File::from(descriptor);
        let bytes = if index == 0 {
            b"scripted-hot-fork-vmstate-v1\n".as_slice()
        } else {
            b"scripted-hot-fork-root-overlay-v1\n".as_slice()
        };
        std::os::unix::fs::FileExt::write_all_at(&file, bytes, 0).map_err(|source| {
            crate::QemuHotForkCommandError::Rejected {
                source: QemuNodeChannelError::new(
                    "write scripted hot-fork child-file destination",
                    source.to_string(),
                ),
            }
        })?;
    }
    Ok(())
}

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
