//! Live hot-fork child execution: a forked child runs a quantum that an exact
//! restore of the same checkpoint must reproduce.
//!
//! The source pauses at an exact snapshot, retains a template, and forks a
//! child with a private VMState copy. The child is installed as an
//! externally parented scheduler node, proven to stand at the captured
//! boundary, resumed, and advanced through an observable suffix. A fresh
//! process then restores the same snapshot and advances to the child's
//! suffix boundary, and a second fresh process boots from genesis and
//! executes straight to that boundary with no snapshot in between; all three
//! must report the same execution fingerprint and round-robin sample. This is
//! the child-side half of the RFC's exact-restore and thin-replay comparison,
//! run against the same guest the child-file flight uses.
//!
//! The flight is three phases, each a value the next consumes: a captured
//! source, an installed child, and the executed comparison. The single-source
//! gate chains them once; the world flight holds several sources at each
//! phase so every child is alive at the same time.

use std::fs;
use std::os::fd::AsFd as _;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::child_files::{
    ChildDebuggerWatch, GuardedSource, MAXIMUM_RING_IMAGE_BYTES, SOURCE_BUSY_CEILING,
    SourcePlacement, attempt_disk_bytes, attempt_memory_bytes, describe_child_diagnostics,
    describe_forked_child, describe_reaped_child, describe_retained_child_diagnostics,
    file_identity, invariant, launch_guarded_source_placed, qmp_operation, realization,
    verify_child_placement, wait_for_child_exit,
};
use super::child_measure::{elapsed_milliseconds, monotonic_nanoseconds};
use super::{
    advance_to_observable_suffix, copy_exact_gate_artifact, exact_gate_checkpoint,
    fingerprint_sample_mismatch_components, source_set::require_vmstate_source, *,
};
use crate::{
    DEFAULT_VMSTATE_FILE_NAME, DEFAULT_VMSTATE_NODE_NAME, LinuxQemuAttemptHostFactory,
    LinuxQemuAttemptHostOwner, LinuxQemuHotForkChildProcessAuthority, QemuChildWait,
    QemuCrashDetector, QemuHotForkChildDiagnosticConsumer, QemuHotForkChildFileDestination,
    QemuHotForkLaunchError, QemuNodeExternalProcessControl, QemuPreparedRunDirectory, QemuReap,
    QemuShutdownRung, QemuShutdownTargetError, QmpHotForkChildFileRoot,
    QmpHotForkChildProcessPhase, QmpHotForkOutcome,
};

/// Instructions the child executes past the captured boundary before the
/// comparison; the exact-snapshot gate uses the same order of magnitude.
const CHILD_SUFFIX_INCREMENT: u64 = 250_000;
/// Bounded polls of the source's child-status record during a shutdown wait.
const CHILD_STATUS_POLL_INTERVAL: Duration = Duration::from_millis(50);
/// Node name the child scheduler node is installed under.
const CHILD_NODE: &str = "hot-fork-child";

/// Records a forked child that executed a quantum an exact restore reproduced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuLiveHotForkChildExecutionReport {
    /// Retained template generation that was forked.
    pub template_generation: u64,
    /// Positive child process identifier reported by the source.
    pub child_process_id: u32,
    /// Raw icount at the captured boundary the template was retained at.
    pub capture_icount: u64,
    /// Raw icount the child reported before it executed anything.
    pub child_boundary_icount: u64,
    /// Raw icount at the child's observable suffix boundary.
    pub suffix_icount: u64,
    /// Execution fingerprint the child reported at its suffix boundary.
    pub child_suffix_fingerprint: String,
    /// Execution fingerprint the exact restore reported at the same boundary.
    pub restore_suffix_fingerprint: String,
    /// Execution fingerprint a fresh process that booted from genesis and
    /// executed to the same boundary reported, the thin-replay oracle.
    pub genesis_replay_suffix_fingerprint: String,
    /// Milliseconds from the fork call until the child stood installed at the
    /// captured boundary with its fingerprint read.
    pub fork_ready_ms: u64,
    /// Milliseconds the fresh process took to launch and restore the same
    /// snapshot to the captured boundary.
    pub exact_restore_ms: u64,
    /// Milliseconds the genesis process took to boot and execute to the
    /// suffix boundary.
    pub genesis_replay_ms: u64,
}

/// Process control for a flight-owned child whose status the source reaps.
///
/// The source node is shared behind a lock because the child node's shutdown
/// path polls the source's child-status record while the flight itself
/// still drives the source.
struct GateChildProcessControl {
    source: Arc<Mutex<QemuNode>>,
    authority: LinuxQemuHotForkChildProcessAuthority,
    generation: u64,
    reaped: bool,
}

impl std::fmt::Debug for GateChildProcessControl {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GateChildProcessControl")
            .field("basis", &self.authority.basis())
            .field("reaped", &self.reaped)
            .finish_non_exhaustive()
    }
}

impl GateChildProcessControl {
    fn observe_exit(&mut self) -> Result<Option<ExitStatus>, QemuShutdownTargetError> {
        let mut source = self.source.lock().map_err(|_poisoned| {
            QemuShutdownTargetError::new(
                "query source-owned hot-fork child status",
                "source node lock poisoned",
            )
        })?;
        let state = source
            .query_hot_fork_child_process(self.generation)
            .map_err(|source| {
                QemuShutdownTargetError::new(
                    "query source-owned hot-fork child status",
                    source.to_string(),
                )
            })?;
        match state.phase() {
            QmpHotForkChildProcessPhase::Running => Ok(None),
            QmpHotForkChildProcessPhase::Exited => {
                self.reaped = true;
                Ok(Some(ExitStatus::from_raw(i32::from(state.status()) << 8)))
            }
            QmpHotForkChildProcessPhase::Signaled if state.status() != 0 => {
                self.reaped = true;
                Ok(Some(ExitStatus::from_raw(i32::from(state.status()))))
            }
            QmpHotForkChildProcessPhase::Signaled => Err(QemuShutdownTargetError::new(
                "query source-owned hot-fork child status",
                "source parent reported a zero terminating signal",
            )),
        }
    }

    /// Polls the source until the child is reaped or the bounded polls end.
    fn wait_until(&mut self, timeout: Duration) -> Result<bool, QemuShutdownTargetError> {
        let polls = timeout.as_millis() / CHILD_STATUS_POLL_INTERVAL.as_millis().max(1);
        let polls = u64::try_from(polls).unwrap_or(u64::MAX).max(1);
        for poll in 0..polls {
            if self.observe_exit()?.is_some() {
                return Ok(true);
            }
            if poll + 1 < polls {
                std::thread::sleep(CHILD_STATUS_POLL_INTERVAL);
            }
        }
        Ok(false)
    }
}

impl QemuNodeExternalProcessControl for GateChildProcessControl {
    fn hot_fork_process_basis(&self) -> crate::QemuHotForkChildProcessBasis {
        self.authority.basis()
    }

    fn process_id(&self) -> u32 {
        self.authority.basis().child_process_id()
    }

    fn reaped(&self) -> bool {
        self.reaped
    }

    fn try_wait_natural_exit(&mut self) -> Result<Option<ExitStatus>, QemuShutdownTargetError> {
        self.observe_exit()
    }

    fn send_sigterm(&mut self) -> Result<(), QemuShutdownTargetError> {
        self.authority.terminate().map_err(|source| {
            QemuShutdownTargetError::new("terminate retained hot-fork child", source.to_string())
        })
    }

    fn send_sigkill(&mut self) -> Result<(), QemuShutdownTargetError> {
        self.authority.kill().map_err(|source| {
            QemuShutdownTargetError::new("kill retained hot-fork child", source.to_string())
        })
    }

    fn wait_for_exit(
        &mut self,
        _rung: QemuShutdownRung,
        timeout: Duration,
    ) -> Result<QemuChildWait, QemuShutdownTargetError> {
        self.wait_until(timeout).map(|exited| {
            if exited {
                QemuChildWait::Exited
            } else {
                QemuChildWait::StillRunning
            }
        })
    }

    fn reap(&mut self, timeout: Duration) -> Result<QemuReap, QemuShutdownTargetError> {
        self.wait_until(timeout).map(|reaped| {
            if reaped {
                QemuReap::Reaped
            } else {
                QemuReap::StillAlive
            }
        })
    }
}

/// Reads the child's boundary icount, fingerprint, and sample before it runs.
fn read_child_boundary(
    child: &mut QemuNode,
) -> Result<
    (
        u64,
        crucible::ExecutionFingerprint,
        crucible_shmem::FingerprintSample,
    ),
    QemuLiveNodeStepGateError,
> {
    // The fingerprint read requests the child's first control boundary,
    // which publishes the inherited counter into the fresh slot; the counter
    // is read only after that publication.
    let fingerprint = child
        .execution_fingerprint()
        .map_err(|source| QemuLiveNodeStepGateError::ExecutionFingerprint { source })?;
    let icount = child
        .current_icount()
        .map_err(|source| QemuLiveNodeStepGateError::node_op("read child icount", source))?
        .retired;
    let sample = child.fingerprint_sample().map_err(|source| {
        QemuLiveNodeStepGateError::node_op("read child boundary fingerprint sample", source)
    })?;
    Ok((icount, fingerprint, sample))
}

fn with_source<T>(
    source: &Arc<Mutex<QemuNode>>,
    operation: impl FnOnce(&mut QemuNode) -> T,
) -> Result<T, QemuLiveNodeStepGateError> {
    let mut node = source
        .lock()
        .map_err(|_poisoned| invariant("source node lock poisoned"))?;
    Ok(operation(&mut node))
}

/// A source paused at its captured boundary with its template retained.
pub(super) struct CapturedSource {
    factory: LinuxQemuAttemptHostFactory,
    source_owner: LinuxQemuAttemptHostOwner,
    source_directory: QemuPreparedRunDirectory,
    node: QemuNode,
    /// Run root of this source's placement; the oracles launch under it.
    run_root: PathBuf,
    capture_icount: u64,
    snapshot: crate::QemuVmSnapshot,
    capture_fingerprint: crucible::ContentHash,
    capture_sample: crucible_shmem::FingerprintSample,
    source_vmstate_bytes: u64,
    restore_directory: PathBuf,
    template_generation: u64,
}

/// A child forked from a captured source, installed as a scheduler node and
/// proven to stand at the captured boundary.
pub(super) struct InstalledChild {
    factory: LinuxQemuAttemptHostFactory,
    source_owner: LinuxQemuAttemptHostOwner,
    source_directory: QemuPreparedRunDirectory,
    source: Arc<Mutex<QemuNode>>,
    child: QemuNode,
    diagnostics: QemuHotForkChildDiagnosticConsumer,
    private_file: fs::File,
    target_directory: QemuPreparedRunDirectory,
    target_owner: LinuxQemuAttemptHostOwner,
    run_root: PathBuf,
    snapshot: crate::QemuVmSnapshot,
    restore_directory: PathBuf,
    template_generation: u64,
    child_process_id: u32,
    child_generation: u64,
    capture_icount: u64,
    child_boundary_icount: u64,
    fork_ready_ms: u64,
}

impl InstalledChild {
    /// Returns the child's process identifier.
    pub(super) const fn child_process_id(&self) -> u32 {
        self.child_process_id
    }
}

/// Launches a source, advances it to the busy ceiling, captures the exact
/// boundary, copies the container for the exact-restore oracle, and retains
/// the template with child resources staged.
pub(super) fn capture_source(
    config: &QemuLiveNodeStepGateConfig,
    cgroup_root: &Path,
    placement: SourcePlacement<'_>,
) -> Result<CapturedSource, QemuLiveNodeStepGateError> {
    if config.root_image.is_some() || config.shmem_block.is_some() {
        return Err(invariant(
            "hot-fork child execution flight requires only the native VMState graph",
        ));
    }
    let run_root = placement.run_root.to_path_buf();
    let GuardedSource {
        factory,
        source_owner,
        source_directory,
        mut node,
        source_vmstate_path,
    } = launch_guarded_source_placed(config, cgroup_root, placement)?;
    let identity = node_id(GATE_NODE);

    // Capture: the source pauses at an exact boundary and records what any
    // continuation of that boundary must report.
    let quantum = advance_to_busy_ceiling(&mut node, SOURCE_BUSY_CEILING)?;
    let capture_icount = quantum.completion_icount;
    let checkpoint = exact_gate_checkpoint(&identity, capture_icount, false);
    let snapshot = node
        .capture_exact_snapshot_paused(&identity, checkpoint)
        .map_err(|source| QemuLiveNodeStepGateError::node_op("save source VMState", source))?;
    let capture_fingerprint = node
        .execution_fingerprint()
        .map_err(|source| QemuLiveNodeStepGateError::ExecutionFingerprint { source })?
        .hash;
    let capture_sample = node.fingerprint_sample().map_err(|source| {
        QemuLiveNodeStepGateError::node_op("read capture fingerprint sample", source)
    })?;
    let source_before = file_identity(&source_vmstate_path)?;
    if source_before.length == 0 {
        return Err(invariant("source VMState container stayed empty"));
    }

    // The exact restore reads the captured container from its own directory,
    // copied while the frozen source cannot change it.
    let restore_directory = run_root.join("exact-restore");
    fs::create_dir_all(&restore_directory).map_err(|source| {
        QemuLiveNodeStepGateError::PrepareRunDirectory {
            path: restore_directory.clone(),
            source,
        }
    })?;
    copy_exact_gate_artifact(
        &source_vmstate_path,
        &restore_directory.join(DEFAULT_VMSTATE_FILE_NAME),
    )?;

    let held = node
        .prepare_hot_fork_template_barriers(&[])
        .map_err(|source| qmp_operation("prepare retained template", source))?;
    require_vmstate_source(&held)?;
    let template_generation = held.generation();
    if let Err(source) = node.prepare_hot_fork_child_resources(MAXIMUM_RING_IMAGE_BYTES) {
        let template = node.query_hot_fork_template();
        return Err(invariant(&format!(
            "prepare child resources failed: {source}; retained template: {template:?}"
        )));
    }

    Ok(CapturedSource {
        factory,
        source_owner,
        source_directory,
        node,
        run_root,
        capture_icount,
        snapshot,
        capture_fingerprint,
        capture_sample,
        source_vmstate_bytes: source_before.length,
        restore_directory,
        template_generation,
    })
}

/// Stages a private VMState destination, forks the retained template into a
/// child in its target cgroup, installs the child as a scheduler node, and
/// proves it stands at the captured boundary.
pub(super) fn fork_and_install_child(
    captured: CapturedSource,
    config: &QemuLiveNodeStepGateConfig,
    cgroup_root: &Path,
) -> Result<InstalledChild, QemuLiveNodeStepGateError> {
    let CapturedSource {
        mut factory,
        source_owner,
        source_directory,
        mut node,
        run_root,
        capture_icount,
        snapshot,
        capture_fingerprint,
        capture_sample,
        source_vmstate_bytes,
        restore_directory,
        template_generation,
    } = captured;

    let mut target_owner = factory
        .begin(1, attempt_memory_bytes(config), attempt_disk_bytes(config))
        .map_err(|source| realization("create target attempt owner", source))?;
    let target_directory = target_owner
        .prepare_generation_run_directory(config.resource_requirements())
        .map_err(|source| realization("prepare target run directory", source))?;
    let private_vmstate_path = target_directory.path().join(DEFAULT_VMSTATE_FILE_NAME);
    let private_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&private_vmstate_path)
        .map_err(|source| QemuLiveNodeStepGateError::PrepareRunDirectory {
            path: private_vmstate_path.clone(),
            source,
        })?;
    let vmstate_root = QmpHotForkChildFileRoot::node_name(DEFAULT_VMSTATE_NODE_NAME)
        .map_err(|source| invariant(&format!("VMState root selector: {source}")))?;
    let destinations = [QemuHotForkChildFileDestination::new(
        &vmstate_root,
        private_file.as_fd(),
    )];
    let plan = node
        .stage_hot_fork_child_files(
            &destinations,
            source_vmstate_bytes.saturating_mul(4).max(1 << 20),
            template_generation,
        )
        .map_err(|source| qmp_operation("stage child-private VMState destination", source))?;

    let fork_started = monotonic_nanoseconds();
    let forked = node.fork_prepared_hot_fork_template_into(&mut target_owner, |owner| {
        owner.process_contract().map_err(|source| {
            QemuNodeChannelError::new(
                "obtain target hot-fork process contract",
                source.to_string(),
            )
        })
    });
    let launch = match forked {
        Ok(launch) => launch,
        Err(QemuHotForkLaunchError::Rejected { source }) => {
            return Err(qmp_operation("fork retained template", source));
        }
        Err(QemuHotForkLaunchError::ProcessRetention {
            parent_state,
            source,
        }) => {
            let child = describe_forked_child(parent_state.child_pid());
            let reaped =
                describe_reaped_child(&mut node, parent_state.request().child_process_generation());
            let diagnostics = describe_retained_child_diagnostics(&mut node);
            return Err(invariant(&format!(
                "hot fork left the source quarantined: child retention failed: {source}; \
                 {child}; {reaped}; {diagnostics}"
            )));
        }
        Err(other) => {
            return Err(invariant(&format!(
                "hot fork left the source quarantined: {other}"
            )));
        }
    };
    let parent_state = launch.parent_state();
    if parent_state.outcome() != QmpHotForkOutcome::Forked
        || parent_state.request().template_generation() != template_generation
        || parent_state.request().child_files_generation() != plan.generation()
    {
        return Err(invariant(&format!(
            "fork result does not match the staged basis: {parent_state:?}"
        )));
    }
    let child_process_id = launch.child_process_id();
    let child_generation = parent_state.request().child_process_generation();
    verify_child_placement(child_process_id, cgroup_root)?;

    // The child becomes a scheduler node; from here the source is shared
    // with the child's process control.
    let (_parent, authority, child_qmp, mut diagnostics, continuation) = launch.into_parts();
    let source = Arc::new(Mutex::new(node));
    let scheduler = match continuation.into_scheduler_node_continuation(child_qmp) {
        Ok(scheduler) => scheduler,
        Err(error) => {
            let child = describe_forked_child(i64::from(child_process_id));
            let reaped = with_source(&source, |node| {
                describe_reaped_child(node, child_generation)
            })?;
            let written = describe_child_diagnostics(&mut diagnostics);
            return Err(invariant(&format!(
                "child scheduler continuation failed: {error}; {child}; {reaped}; {written}"
            )));
        }
    };
    let control = GateChildProcessControl {
        source: Arc::clone(&source),
        authority,
        generation: child_generation,
        reaped: false,
    };
    let mut child = scheduler
        .into_qemu_node(
            node_id(CHILD_NODE),
            control,
            gate_shutdown_policy(),
            gate_async_policy(config.completion_timeout),
            QemuCrashDetector::new("live-hot-fork-child-execution"),
        )
        .map_err(|error| invariant(&format!("install child scheduler node: {error}")))?;

    // The child stands at the captured boundary before it executes anything.
    // A child that dies here leaves its last words on the diagnostics
    // stream, so every read reports through it.
    let boundary = read_child_boundary(&mut child);
    let fork_ready_ms = elapsed_milliseconds(fork_started);
    let (child_boundary_icount, child_boundary_fingerprint, child_boundary_sample) = match boundary
    {
        Ok((icount, fingerprint, sample)) => (icount, fingerprint.hash, sample),
        Err(failure) => {
            let child_state = describe_forked_child(i64::from(child_process_id));
            let reaped = with_source(&source, |node| {
                describe_reaped_child(node, child_generation)
            })?;
            let written = describe_child_diagnostics(&mut diagnostics);
            return Err(invariant(&format!(
                "child boundary read failed: {failure}; {child_state}; {reaped}; {written}"
            )));
        }
    };
    if child_boundary_icount != capture_icount
        || child_boundary_fingerprint != capture_fingerprint
        || child_boundary_sample != capture_sample
    {
        let components =
            fingerprint_sample_mismatch_components(&child_boundary_sample, &capture_sample)
                .join(",");
        return Err(invariant(&format!(
            "child boundary differs from the captured boundary: icount \
             {child_boundary_icount}/{capture_icount}, fingerprint {}/{}, differing \
             components [{components}]",
            child_boundary_fingerprint.to_hex(),
            capture_fingerprint.to_hex(),
        )));
    }

    Ok(InstalledChild {
        factory,
        source_owner,
        source_directory,
        source,
        child,
        diagnostics,
        private_file,
        target_directory,
        target_owner,
        run_root,
        snapshot,
        restore_directory,
        template_generation,
        child_process_id,
        child_generation,
        capture_icount,
        child_boundary_icount,
        fork_ready_ms,
    })
}

/// Executes the child's observable suffix, proves the exact-restore and
/// genesis-replay oracles reproduce it, and tears everything down.
pub(super) fn execute_and_compare(
    installed: InstalledChild,
    config: &QemuLiveNodeStepGateConfig,
) -> Result<QemuLiveHotForkChildExecutionReport, QemuLiveNodeStepGateError> {
    let InstalledChild {
        factory: _factory,
        mut source_owner,
        source_directory,
        source,
        mut child,
        mut diagnostics,
        private_file,
        target_directory,
        mut target_owner,
        run_root,
        snapshot,
        restore_directory,
        template_generation,
        child_process_id,
        child_generation,
        capture_icount,
        child_boundary_icount,
        fork_ready_ms,
    } = installed;

    // The child executes an observable suffix under the debugger's watch.
    let requested_suffix = capture_icount
        .checked_add(CHILD_SUFFIX_INCREMENT)
        .ok_or_else(|| invariant("child suffix ceiling overflowed"))?;
    let watch = ChildDebuggerWatch::attach(child_process_id);
    let executed = child
        .resume_after_exact_snapshot()
        .map_err(|source| QemuLiveNodeStepGateError::node_op("resume child guest", source))
        .and_then(|()| advance_to_observable_suffix(&mut child, requested_suffix));
    let watched = watch.map(ChildDebuggerWatch::finish).unwrap_or_default();
    let suffix_icount = match executed {
        Ok(suffix_icount) => suffix_icount,
        Err(failure) => {
            let child_state = describe_forked_child(i64::from(child_process_id));
            let reaped = with_source(&source, |node| {
                describe_reaped_child(node, child_generation)
            })?;
            let written = describe_child_diagnostics(&mut diagnostics);
            return Err(invariant(&format!(
                "child execution failed: {failure}; {child_state}; {reaped}; {written}{watched}"
            )));
        }
    };
    let child_suffix_fingerprint = child
        .execution_fingerprint()
        .map_err(|source| QemuLiveNodeStepGateError::ExecutionFingerprint { source })?
        .hash;
    let child_suffix_sample = child.fingerprint_sample().map_err(|source| {
        QemuLiveNodeStepGateError::node_op("read child suffix fingerprint sample", source)
    })?;

    // Oracle: a fresh process restores the captured snapshot and advances to
    // the child's suffix boundary.
    let restore_config = config.clone().with_run_directory(&restore_directory);
    let restore_started = monotonic_nanoseconds();
    let mut restored = launch_qemu_live_node_exact_snapshot(
        &restore_config,
        &restore_directory,
        GATE_NODE,
        GATE_ROUTER,
        "live-hot-fork-exact-restore",
        &snapshot,
    )?;
    let restored_icount = restored
        .current_icount()
        .map_err(|source| QemuLiveNodeStepGateError::node_op("read restored icount", source))?
        .retired;
    let exact_restore_ms = elapsed_milliseconds(restore_started);
    if restored_icount != capture_icount {
        return Err(invariant(&format!(
            "exact restore boundary {restored_icount} differs from capture {capture_icount}"
        )));
    }
    advance_to_busy_ceiling(&mut restored, suffix_icount)?;
    let restore_suffix_fingerprint = restored
        .execution_fingerprint()
        .map_err(|source| QemuLiveNodeStepGateError::ExecutionFingerprint { source })?
        .hash;
    let restore_suffix_sample = restored.fingerprint_sample().map_err(|source| {
        QemuLiveNodeStepGateError::node_op("read restored suffix fingerprint sample", source)
    })?;
    if child_suffix_fingerprint != restore_suffix_fingerprint
        || child_suffix_sample != restore_suffix_sample
    {
        let components =
            fingerprint_sample_mismatch_components(&child_suffix_sample, &restore_suffix_sample)
                .join(",");
        return Err(invariant(&format!(
            "child suffix fingerprint {} differs from the exact restore's {}; differing \
             components [{components}]",
            child_suffix_fingerprint.to_hex(),
            restore_suffix_fingerprint.to_hex(),
        )));
    }
    restored
        .force_crash_and_reap_for_gate()
        .map_err(|source| QemuLiveNodeStepGateError::node_op("reap exact restore", source))?;
    drop(restored);

    // Thin oracle: a fresh process boots from genesis and executes straight
    // to the child's suffix boundary with no snapshot in between.
    let replay_directory = run_root.join("genesis-replay");
    fs::create_dir_all(&replay_directory).map_err(|source| {
        QemuLiveNodeStepGateError::PrepareRunDirectory {
            path: replay_directory.clone(),
            source,
        }
    })?;
    let replay_config = config.clone().with_run_directory(&replay_directory);
    let replay_started = monotonic_nanoseconds();
    let mut replayed = launch_qemu_live_node(
        &replay_config,
        &replay_directory,
        GATE_NODE,
        GATE_ROUTER,
        "live-hot-fork-genesis-replay",
    )?;
    advance_to_busy_ceiling(&mut replayed, suffix_icount)?;
    let genesis_replay_ms = elapsed_milliseconds(replay_started);
    let genesis_replay_suffix_fingerprint = replayed
        .execution_fingerprint()
        .map_err(|source| QemuLiveNodeStepGateError::ExecutionFingerprint { source })?
        .hash;
    let genesis_replay_suffix_sample = replayed.fingerprint_sample().map_err(|source| {
        QemuLiveNodeStepGateError::node_op("read genesis replay suffix fingerprint sample", source)
    })?;
    if child_suffix_fingerprint != genesis_replay_suffix_fingerprint
        || child_suffix_sample != genesis_replay_suffix_sample
    {
        let components = fingerprint_sample_mismatch_components(
            &child_suffix_sample,
            &genesis_replay_suffix_sample,
        )
        .join(",");
        return Err(invariant(&format!(
            "child suffix fingerprint {} differs from the genesis replay's {}; differing \
             components [{components}]",
            child_suffix_fingerprint.to_hex(),
            genesis_replay_suffix_fingerprint.to_hex(),
        )));
    }
    replayed
        .force_crash_and_reap_for_gate()
        .map_err(|source| QemuLiveNodeStepGateError::node_op("reap genesis replay", source))?;
    drop(replayed);

    // Teardown: the child node ends through its external process control,
    // the source reaps it, and every stage is released in order.
    child
        .force_crash_and_reap_for_gate()
        .map_err(|source| QemuLiveNodeStepGateError::node_op("reap hot-fork child node", source))?;
    drop(child);
    let mut node = Arc::try_unwrap(source)
        .map_err(|_shared| invariant("child process control outlived the child node"))?
        .into_inner()
        .map_err(|_poisoned| invariant("source node lock poisoned"))?;
    wait_for_child_exit(&mut node, child_generation)?;
    node.release_hot_fork_plugin_endpoints()
        .map_err(|source| qmp_operation("release plugin endpoints", source))?;
    node.release_hot_fork_child_console()
        .map_err(|source| qmp_operation("release child console", source))?;
    node.release_hot_fork_child_qmp()
        .map_err(|source| qmp_operation("release child QMP", source))?;
    let _capture = node
        .release_hot_fork_child_diagnostics_with_consumer(&mut diagnostics)
        .map_err(|source| qmp_operation("release child diagnostics", source))?;
    drop(
        node.release_hot_fork_private_ring_mapping()
            .map_err(|source| qmp_operation("release private ring", source))?,
    );
    node.release_hot_fork_child_process(child_generation)
        .map_err(|source| qmp_operation("release reaped child record", source))?;
    node.release_hot_fork_child_process_contract()
        .map_err(|source| qmp_operation("release child process contract", source))?;
    node.release_hot_fork_child_files()
        .map_err(|source| qmp_operation("release child file plan", source))?;
    drop(private_file);
    drop(target_directory);
    target_owner
        .finish()
        .map_err(|source| realization("finish target attempt owner", source))?;
    node.force_crash_and_reap_for_gate().map_err(|source| {
        QemuLiveNodeStepGateError::node_op("reap hot-fork execution flight source", source)
    })?;
    drop(node);
    drop(source_directory);
    source_owner
        .finish()
        .map_err(|source| realization("finish source attempt owner", source))?;

    Ok(QemuLiveHotForkChildExecutionReport {
        template_generation,
        child_process_id,
        capture_icount,
        child_boundary_icount,
        suffix_icount,
        child_suffix_fingerprint: child_suffix_fingerprint.to_hex(),
        restore_suffix_fingerprint: restore_suffix_fingerprint.to_hex(),
        genesis_replay_suffix_fingerprint: genesis_replay_suffix_fingerprint.to_hex(),
        fork_ready_ms,
        exact_restore_ms,
        genesis_replay_ms,
    })
}

/// Forks a retained template into a child, runs a quantum in the child, and
/// proves an exact restore and a genesis replay of the same boundary
/// reproduce it.
///
/// # Errors
///
/// Returns [`QemuLiveNodeStepGateError`] when the configuration carries a
/// disk or mediated block device, or any launch, capture, fork, child
/// installation, execution, restore, comparison, or cleanup step fails.
pub fn run_qemu_live_hot_fork_child_execution_gate(
    config: &QemuLiveNodeStepGateConfig,
    cgroup_root: &Path,
    run_root: &Path,
) -> Result<QemuLiveHotForkChildExecutionReport, QemuLiveNodeStepGateError> {
    let captured = capture_source(config, cgroup_root, SourcePlacement::flight(run_root))?;
    let installed = fork_and_install_child(captured, config, cgroup_root)?;
    execute_and_compare(installed, config)
}
