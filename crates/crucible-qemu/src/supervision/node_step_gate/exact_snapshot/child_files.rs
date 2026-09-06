//! Forks one retained VMState-only template into a real child that adopts a
//! child-private VMState copy.
//!
//! The flight runs the complete production staging chain against a live QEMU:
//! guarded source launch inside a dedicated cgroup-v2 and project-quota
//! namespace, exact snapshot pause, retained template with a frozen native
//! VMState source, private ring and child endpoint staging, the child-private
//! file plan bound to the target attempt's empty VMState container, the target
//! process contract, and `crucible-hot-fork`. It then proves that the child
//! holds only the private inode, that the child can write new VMState through
//! it, and that the source container never changes. Invoke only with dedicated
//! empty cgroup-v2 and ext4 project-quota roots.

use std::fs;
use std::os::fd::AsFd as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::child_measure::{ProcessFootprint, elapsed_milliseconds, monotonic_nanoseconds};
use super::{exact_gate_checkpoint, source_set::require_vmstate_source, *};
use crate::{
    DEFAULT_VMSTATE_FILE_NAME, DEFAULT_VMSTATE_NODE_NAME, LinuxQemuAttemptHostConfig,
    LinuxQemuAttemptHostFactory, LinuxQemuAttemptHostOwner, QemuGuardedFreshNodeLaunch,
    QemuHotForkChildFileDestination, QemuHotForkLaunchError, QemuPreparedRunDirectory,
    QmpHotForkChildFileRoot, QmpHotForkOutcome, launch_qemu_live_node_guarded,
};

pub(super) const FLIGHT_NAMESPACE: &str = "hot-fork-child-flight";
pub(super) const FIRST_PROJECT_ID: u32 = 20000;
pub(super) const PROJECT_ID_COUNT: u32 = 2;
pub(super) const CHILD_USER_ID: u32 = 65534;
pub(super) const CHILD_GROUP_ID: u32 = 65534;
pub(super) const MAXIMUM_TASKS: u32 = 64;
pub(super) const MAXIMUM_INODES: u64 = 4096;
pub(super) const FINISH_TIMEOUT: Duration = Duration::from_secs(15);
/// Memory an attempt may use beyond the guest-proportional part of its
/// budget: QEMU's own heap, the plugin, page tables, and the private VMState
/// copy.
pub(super) const ATTEMPT_MEMORY_HEADROOM_BYTES: u64 = 512 * 1024 * 1024;
/// Writable storage an attempt may use beyond its VMState containers.
pub(super) const ATTEMPT_DISK_HEADROOM_BYTES: u64 = 1024 * 1024 * 1024;
pub(super) const MAXIMUM_RING_IMAGE_BYTES: usize = 64 * 1024 * 1024;
pub(super) const SOURCE_BUSY_CEILING: u64 = 3_000_001;
pub(super) const CHILD_REAP_POLLS: u32 = 400;
pub(super) const CHILD_REAP_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Memory budget for one attempt: four times the configured guest RAM plus
/// headroom. Under the plugin's instrumentation the source alone reached
/// 2.8 times its guest RAM while booting a 512 MiB guest to the busy
/// ceiling, and a forked child that touches all of its RAM adds up to a
/// second guest image of private copies.
pub(super) fn attempt_memory_bytes(config: &QemuLiveNodeStepGateConfig) -> u64 {
    u64::from(config.memory_mib())
        .saturating_mul(4 * 1024 * 1024)
        .saturating_add(ATTEMPT_MEMORY_HEADROOM_BYTES)
}

/// Writable-storage budget for one attempt: twice the configured guest RAM
/// plus headroom, since a VMState container grows with the guest image and
/// a child saves a second one through its private copy.
pub(super) fn attempt_disk_bytes(config: &QemuLiveNodeStepGateConfig) -> u64 {
    u64::from(config.memory_mib())
        .saturating_mul(2 * 1024 * 1024)
        .saturating_add(ATTEMPT_DISK_HEADROOM_BYTES)
}
/// Children forked in sequence from the one retained template, so the flight
/// exercises the stage releases and restaging that template reuse requires.
const CHILD_FORK_COUNT: u32 = 3;

/// Records a live hot fork that adopted a child-private VMState copy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuLiveHotForkChildReport {
    /// Retained template generation that was forked.
    pub template_generation: u64,
    /// Child-private file plan generation consumed by the fork.
    pub child_files_generation: u64,
    /// Positive child process identifier reported by the source.
    pub child_process_id: u32,
    /// Source VMState container length before the fork.
    pub source_vmstate_bytes: u64,
    /// Private copy length observed after the fork prepared the plan.
    pub private_vmstate_bytes: u64,
    /// Private copy length after the child saved new VMState through it.
    pub child_saved_vmstate_bytes: u64,
    /// Children forked in sequence from the one retained template; the
    /// fields above describe the last of them.
    pub children_forked: u32,
    /// Source threads before the first child was staged.
    pub source_threads: u64,
    /// Source descriptors before the first child was staged.
    pub source_descriptors: u64,
    /// Threads the source still held beyond that baseline after the last
    /// child's release; a nonzero value fails the flight.
    pub source_threads_leaked: u64,
    /// Descriptors the source still held beyond that baseline after the
    /// last child's release; a nonzero value fails the flight.
    pub source_descriptors_leaked: u64,
    /// Growth of the source's private dirty memory in KiB across every child.
    pub source_private_dirty_growth_kib: i64,
    /// Longest fork call among the children, in milliseconds.
    pub max_fork_ms: u64,
    /// Longest fork-to-private-QMP-handshake among the children, in ms.
    pub max_ready_ms: u64,
    /// The last child's threads after its handshake.
    pub child_threads: u64,
    /// The last child's descriptors after its handshake.
    pub child_descriptors: u64,
    /// The last child's private dirty memory in KiB after its handshake.
    pub child_private_dirty_kib: u64,
}

/// Forks a retained VMState-only template into a sequence of children, each
/// with private VMState.
///
/// The source and each target own one attempt slot in the supplied cgroup and
/// project-quota roots. A target's provisioned empty VMState container is the
/// sole child-private destination. After each fork the flight verifies that
/// the child process lives in its target cgroup, references the private inode
/// and not the source container, reports no inherited plan through its private
/// QMP channel, and can save additional VMState that grows only the private
/// copy; it then terminates the child, releases every child stage in the
/// reconciliation's order, and restages the template for the next child. The
/// source is terminated and every owner finishes before return.
///
/// # Errors
///
/// Returns [`QemuLiveNodeStepGateError`] when the configuration contains a disk
/// or mediated block device, any namespace, launch, staging, fork, child
/// verification, or cleanup step fails.
pub fn run_qemu_live_hot_fork_child_gate(
    config: &QemuLiveNodeStepGateConfig,
    cgroup_root: &Path,
    run_root: &Path,
) -> Result<QemuLiveHotForkChildReport, QemuLiveNodeStepGateError> {
    if config.root_image.is_some() || config.shmem_block.is_some() {
        return Err(invariant(
            "hot-fork child flight requires only the native VMState graph",
        ));
    }
    let GuardedSource {
        mut factory,
        mut source_owner,
        source_directory,
        mut node,
        source_vmstate_path,
    } = launch_guarded_source(config, cgroup_root, run_root)?;
    let identity = node_id(GATE_NODE);

    let quantum = advance_to_busy_ceiling(&mut node, SOURCE_BUSY_CEILING)?;
    node.capture_exact_snapshot_paused(
        &identity,
        exact_gate_checkpoint(&identity, quantum.completion_icount, false),
    )
    .map_err(|source| QemuLiveNodeStepGateError::node_op("save source VMState", source))?;
    let source_before = file_identity(&source_vmstate_path)?;
    if source_before.length == 0 {
        return Err(invariant("source VMState container stayed empty"));
    }

    let held = node
        .prepare_hot_fork_template_barriers(&[])
        .map_err(|source| qmp_operation("prepare retained template", source))?;
    require_vmstate_source(&held)?;
    let template_generation = held.generation();

    // The baseline is the retained template with no child staged; every
    // child must return the source to it.
    let source_baseline = ProcessFootprint::read(node.process_id())?;
    let mut last = None;
    let mut max_fork_ms = 0;
    let mut max_ready_ms = 0;
    let mut source_after = source_baseline;
    for child_index in 0..CHILD_FORK_COUNT {
        let context = ChildForkContext {
            config,
            identity: &identity,
            completion_icount: quantum.completion_icount,
            template_generation,
            source_vmstate_path: &source_vmstate_path,
            source_before,
            cgroup_root,
            child_index,
        };
        let outcome = fork_one_child(&mut node, &mut factory, &context)?;
        max_fork_ms = max_fork_ms.max(outcome.fork_ms);
        max_ready_ms = max_ready_ms.max(outcome.ready_ms);
        source_after = ProcessFootprint::read(node.process_id())?;
        if source_after.threads != source_baseline.threads
            || source_after.descriptors != source_baseline.descriptors
        {
            return Err(invariant(&format!(
                "source did not return to its baseline after child {child_index}: threads {}/{}, descriptors {}/{}",
                source_after.threads,
                source_baseline.threads,
                source_after.descriptors,
                source_baseline.descriptors
            )));
        }
        last = Some(outcome);
    }
    let Some(last) = last else {
        return Err(invariant("no child was forked"));
    };
    let private_dirty_growth_kib = i64::try_from(source_after.private_dirty_kib)
        .unwrap_or(i64::MAX)
        .saturating_sub(i64::try_from(source_baseline.private_dirty_kib).unwrap_or(0));

    node.force_crash_and_reap_for_gate().map_err(|source| {
        QemuLiveNodeStepGateError::node_op("reap hot-fork child flight source", source)
    })?;
    drop(node);
    drop(source_directory);
    source_owner
        .finish()
        .map_err(|source| realization("finish source attempt owner", source))?;

    Ok(QemuLiveHotForkChildReport {
        template_generation,
        child_files_generation: last.child_files_generation,
        child_process_id: last.child_process_id,
        source_vmstate_bytes: source_before.length,
        private_vmstate_bytes: last.private_vmstate_bytes,
        child_saved_vmstate_bytes: last.child_saved_vmstate_bytes,
        children_forked: CHILD_FORK_COUNT,
        source_threads: source_baseline.threads,
        source_descriptors: source_baseline.descriptors,
        source_threads_leaked: source_after.threads.saturating_sub(source_baseline.threads),
        source_descriptors_leaked: source_after
            .descriptors
            .saturating_sub(source_baseline.descriptors),
        source_private_dirty_growth_kib: private_dirty_growth_kib,
        max_fork_ms,
        max_ready_ms,
        child_threads: last.child_footprint.threads,
        child_descriptors: last.child_footprint.descriptors,
        child_private_dirty_kib: last.child_footprint.private_dirty_kib,
    })
}

/// What one child of the sequence is forked against.
struct ChildForkContext<'a> {
    config: &'a QemuLiveNodeStepGateConfig,
    identity: &'a NodeId,
    completion_icount: u64,
    template_generation: u64,
    source_vmstate_path: &'a Path,
    source_before: FileIdentity,
    cgroup_root: &'a Path,
    child_index: u32,
}

/// What one child of the sequence proved before it was torn down.
struct ForkedChildOutcome {
    child_files_generation: u64,
    child_process_id: u32,
    private_vmstate_bytes: u64,
    child_saved_vmstate_bytes: u64,
    /// Milliseconds the fork call took until the parent returned.
    fork_ms: u64,
    /// Milliseconds from the fork call until the child answered on QMP.
    ready_ms: u64,
    /// The child's footprint right after its handshake.
    child_footprint: ProcessFootprint,
}

/// Stages, forks, verifies, and tears down one child of the sequence.
///
/// On return the source retains its template with no child stage, ready for
/// the next child; every failure leaves the source quarantined for the gate's
/// final reap.
fn fork_one_child(
    node: &mut QemuNode,
    factory: &mut LinuxQemuAttemptHostFactory,
    context: &ChildForkContext<'_>,
) -> Result<ForkedChildOutcome, QemuLiveNodeStepGateError> {
    let config = context.config;
    let identity = context.identity;
    let template_generation = context.template_generation;
    let source_vmstate_path = context.source_vmstate_path;
    let source_before = context.source_before;
    let cgroup_root = context.cgroup_root;
    if let Err(source) = node.prepare_hot_fork_child_resources(MAXIMUM_RING_IMAGE_BYTES) {
        // The retained template report carries every barrier, worker, and
        // resource-stage field QEMU checks, so keep it with the rejection.
        let template = node.query_hot_fork_template();
        return Err(invariant(&format!(
            "prepare child resources failed: {source}; retained template: {template:?}"
        )));
    }

    // Target attempt: its provisioned empty VMState container becomes the
    // child's private copy. No image helper runs for the target.
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
            source_before.length.saturating_mul(4).max(1 << 20),
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
    let fork_ms = elapsed_milliseconds(fork_started);
    let launch = match forked {
        Ok(launch) => launch,
        Err(QemuHotForkLaunchError::Rejected { source }) => {
            return Err(qmp_operation("fork retained template", source));
        }
        Err(QemuHotForkLaunchError::ParentDispositionFailed {
            child_pid,
            parent_status,
        }) => {
            return Err(invariant(&format!(
                "hot fork created child {child_pid} but the parent disposition failed with \
                 status {parent_status}; {}",
                describe_forked_child(child_pid)
            )));
        }
        Err(QemuHotForkLaunchError::ProcessRetention {
            parent_state,
            source,
        }) => {
            let child = describe_forked_child(parent_state.child_pid());
            let reaped =
                describe_reaped_child(node, parent_state.request().child_process_generation());
            let diagnostics = describe_retained_child_diagnostics(node);
            return Err(invariant(&format!(
                "hot fork left the source quarantined: child retention failed: {source}; \
                 parent outcome {:?} status {} child {}; {child}; {reaped}; {diagnostics}",
                parent_state.outcome(),
                parent_state.parent_status(),
                parent_state.child_pid(),
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
    if !node
        .hot_fork_child_files_stage()
        .is_some_and(|stage| stage.consumed())
    {
        return Err(invariant("child file plan was not consumed by the fork"));
    }

    // Child verification: process placement, descriptor identity, private QMP,
    // and a VMState save that must grow only the private copy.
    let child_process_id = launch.child_process_id();
    verify_child_placement(child_process_id, cgroup_root)?;
    let source_after_fork = file_identity(source_vmstate_path)?;
    let private_after_fork = file_identity(&private_vmstate_path)?;
    // Freezing the source drains and flushes its qcow2 metadata caches, which
    // rewrites existing bytes in place and moves the modification time. The
    // fork itself must not replace or grow the container; only the child's
    // later save is held to the strict identity captured here.
    if source_after_fork.device != source_before.device
        || source_after_fork.inode != source_before.inode
        || source_after_fork.length != source_before.length
    {
        return Err(invariant(&format!(
            "source VMState container changed during the fork: before {source_before:?}, \
             after {source_after_fork:?}"
        )));
    }
    if private_after_fork.length != source_before.length {
        return Err(invariant(&format!(
            "private copy length {} differs from source length {}",
            private_after_fork.length, source_before.length
        )));
    }
    let child_process_generation = launch.parent_state().request().child_process_generation();
    let (_parent, authority, child_qmp, mut diagnostics, continuation) = launch.into_parts();
    let mut child_channel = match child_qmp.connect() {
        Ok(channel) => channel,
        Err(source) => {
            // The parent completes the fork before the child finishes its
            // reconstruction, so the child may have died since the checks above.
            let child = describe_forked_child(i64::from(child_process_id));
            let reaped = describe_reaped_child(node, child_process_generation);
            let written = describe_child_diagnostics(&mut diagnostics);
            return Err(invariant(&format!(
                "child QMP handshake failed: {source}; {child}; {reaped}; {written}"
            )));
        }
    };
    let ready_ms = elapsed_milliseconds(fork_started);
    let child_footprint = ProcessFootprint::read(child_process_id)?;
    // The child adopts its private files and closes the source's descriptors
    // during its reconstruction, which the handshake above proves complete;
    // only then is its descriptor table held to the plan.
    let child_files = child_open_files(child_process_id)?;
    if !child_files.contains(&(private_after_fork.device, private_after_fork.inode)) {
        return Err(invariant("child does not hold the private VMState inode"));
    }
    if child_files.contains(&(source_before.device, source_before.inode)) {
        return Err(invariant("child still holds the source VMState inode"));
    }
    let inherited_plan = child_channel
        .query_hot_fork_child_files()
        .map_err(|source| qmp_operation("query child-file plan in child", source))?;
    if inherited_plan.staged() || inherited_plan.consumed() {
        return Err(invariant("child inherited a retained child-file plan"));
    }
    // A debugger riding the child across the save reports a death by signal
    // with a backtrace, which the reaped status alone cannot.
    let watch = ChildDebuggerWatch::attach(child_process_id);
    let saved = child_channel.save_checkpoint_vmstate(&exact_gate_checkpoint(
        identity,
        context
            .completion_icount
            .saturating_add(1)
            .saturating_add(u64::from(context.child_index)),
        false,
    ));
    let watched = watch.map(ChildDebuggerWatch::finish).unwrap_or_default();
    if let Err(source) = saved {
        let child = describe_forked_child(i64::from(child_process_id));
        let reaped = describe_reaped_child(node, child_process_generation);
        let written = describe_child_diagnostics(&mut diagnostics);
        return Err(invariant(&format!(
            "save VMState through the child failed: {source}; {child}; {reaped}; {written}\
             {watched}"
        )));
    }
    let source_after_save = file_identity(source_vmstate_path)?;
    let private_after_save = file_identity(&private_vmstate_path)?;
    if source_after_save != source_after_fork {
        return Err(invariant(&format!(
            "child VMState save changed the source container: before {source_after_fork:?}, \
             after {source_after_save:?}"
        )));
    }
    if private_after_save.length <= private_after_fork.length
        && private_after_save.modified == private_after_fork.modified
    {
        return Err(invariant(
            "child VMState save did not change the private copy",
        ));
    }

    // Teardown: kill the child through its retained pidfd, let the source
    // parent reap it, release every child stage in the reconciliation's
    // order, then release the target owner so the template can be restaged.
    drop(child_channel);
    drop(continuation);
    authority
        .kill()
        .map_err(|source| realization("kill hot-fork child", source))?;
    let child_generation = parent_state.request().child_process_generation();
    wait_for_child_exit(node, child_generation)?;
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
    drop(authority);
    drop(private_file);
    drop(target_directory);
    target_owner
        .finish()
        .map_err(|source| realization("finish target attempt owner", source))?;

    Ok(ForkedChildOutcome {
        child_files_generation: plan.generation(),
        child_process_id,
        private_vmstate_bytes: private_after_fork.length,
        child_saved_vmstate_bytes: private_after_save.length,
        fork_ms,
        ready_ms,
        child_footprint,
    })
}

/// Where one source of a flight lives: its own cgroup and project-quota
/// namespace, its own project-id range, and its own run root, so several
/// sources can share a flight without sharing any resource authority.
#[derive(Clone, Copy, Debug)]
pub(super) struct SourcePlacement<'a> {
    pub(super) namespace: &'a str,
    pub(super) first_project_id: u32,
    pub(super) run_root: &'a Path,
}

impl<'a> SourcePlacement<'a> {
    /// The single-source flight's placement under `run_root`.
    pub(super) const fn flight(run_root: &'a Path) -> Self {
        Self {
            namespace: FLIGHT_NAMESPACE,
            first_project_id: FIRST_PROJECT_ID,
            run_root,
        }
    }
}

/// A guarded source launched for a hot-fork flight, still running.
pub(super) struct GuardedSource {
    pub(super) factory: LinuxQemuAttemptHostFactory,
    pub(super) source_owner: LinuxQemuAttemptHostOwner,
    pub(super) source_directory: QemuPreparedRunDirectory,
    pub(super) node: QemuNode,
    pub(super) source_vmstate_path: PathBuf,
}

/// Launches the flight's source under attempt credentials in its own cgroup
/// and project-quota namespace, retaining a failed child with its owner.
pub(super) fn launch_guarded_source(
    config: &QemuLiveNodeStepGateConfig,
    cgroup_root: &Path,
    run_root: &Path,
) -> Result<GuardedSource, QemuLiveNodeStepGateError> {
    launch_guarded_source_placed(config, cgroup_root, SourcePlacement::flight(run_root))
}

/// Launches one source at the given placement; see [`launch_guarded_source`].
pub(super) fn launch_guarded_source_placed(
    config: &QemuLiveNodeStepGateConfig,
    cgroup_root: &Path,
    placement: SourcePlacement<'_>,
) -> Result<GuardedSource, QemuLiveNodeStepGateError> {
    let host = LinuxQemuAttemptHostConfig::new(
        cgroup_root,
        placement.run_root,
        placement.namespace,
        placement.first_project_id,
        PROJECT_ID_COUNT,
        CHILD_USER_ID,
        CHILD_GROUP_ID,
        MAXIMUM_TASKS,
        MAXIMUM_INODES,
        FINISH_TIMEOUT,
    )
    .map_err(|source| realization("configure attempt host namespace", source))?;
    let mut factory = LinuxQemuAttemptHostFactory::open(host)
        .map_err(|source| realization("open attempt host allocator", source))?;

    // Source attempt: fresh guarded launch, exact pause, retained template.
    let mut source_owner = factory
        .begin(1, attempt_memory_bytes(config), attempt_disk_bytes(config))
        .map_err(|source| realization("create source attempt owner", source))?;
    let mut source_directory = source_owner
        .prepare_generation_run_directory(config.resource_requirements())
        .map_err(|source| realization("prepare source run directory", source))?;
    let source_contract = source_owner
        .process_contract()
        .map_err(|source| realization("obtain source process contract", source))?;
    if let Err(mut error) = source_directory.prepare_fresh_artifacts_guarded(
        &config.qemu_executable,
        None,
        source_contract,
    ) {
        if let Some(child) = error.take_unreaped_child() {
            source_owner.retain_failed_child(child);
        }
        return Err(invariant(&format!(
            "guarded source artifact preparation failed: {error}"
        )));
    }
    let launch_config = config.clone().with_run_directory(source_directory.path());
    let node = match launch_qemu_live_node_guarded(
        &launch_config,
        QemuGuardedFreshNodeLaunch::new(
            &source_directory,
            source_contract,
            QemuLiveNodeIdentity {
                node: GATE_NODE,
                router: GATE_ROUTER,
                crash_detector: "live-hot-fork-child",
            },
        ),
    ) {
        Ok(node) => node,
        Err(mut error) => {
            if let Some(child) = error.take_unreaped_child() {
                source_owner.retain_failed_child(child);
            }
            return Err(error);
        }
    };
    let source_vmstate_path = source_directory.path().join(DEFAULT_VMSTATE_FILE_NAME);
    Ok(GuardedSource {
        factory,
        source_owner,
        source_directory,
        node,
        source_vmstate_path,
    })
}

pub(super) use super::child_support::{
    ChildDebuggerWatch, FileIdentity, child_open_files, describe_child_diagnostics,
    describe_forked_child, describe_reaped_child, describe_retained_child_diagnostics,
    file_identity, invariant, qmp_operation, realization, verify_child_placement,
    wait_for_child_exit,
};
