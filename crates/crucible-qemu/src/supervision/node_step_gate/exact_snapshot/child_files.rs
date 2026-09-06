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

use std::collections::BTreeSet;
use std::fs;
use std::os::fd::AsFd as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::{exact_gate_checkpoint, source_set::require_vmstate_source, *};
use crate::{
    DEFAULT_VMSTATE_FILE_NAME, DEFAULT_VMSTATE_NODE_NAME, LinuxQemuAttemptHostConfig,
    LinuxQemuAttemptHostFactory, LinuxQemuAttemptHostOwner, QemuGuardedFreshNodeLaunch,
    QemuHotForkChildDiagnosticConsumer, QemuHotForkChildFileDestination, QemuHotForkLaunchError,
    QemuPreparedRunDirectory, QmpHotForkChildFileRoot, QmpHotForkChildProcessPhase,
    QmpHotForkOutcome, launch_qemu_live_node_guarded,
};

pub(super) const FLIGHT_NAMESPACE: &str = "hot-fork-child-flight";
pub(super) const FIRST_PROJECT_ID: u32 = 20000;
pub(super) const PROJECT_ID_COUNT: u32 = 2;
pub(super) const CHILD_USER_ID: u32 = 65534;
pub(super) const CHILD_GROUP_ID: u32 = 65534;
pub(super) const MAXIMUM_TASKS: u32 = 64;
pub(super) const MAXIMUM_INODES: u64 = 4096;
pub(super) const FINISH_TIMEOUT: Duration = Duration::from_secs(15);
pub(super) const MEMORY_BYTES: u64 = 512 * 1024 * 1024;
pub(super) const DISK_BYTES: u64 = 1024 * 1024 * 1024;
pub(super) const MAXIMUM_RING_IMAGE_BYTES: usize = 64 * 1024 * 1024;
pub(super) const SOURCE_BUSY_CEILING: u64 = 3_000_001;
pub(super) const CHILD_REAP_POLLS: u32 = 400;
pub(super) const CHILD_REAP_POLL_INTERVAL: Duration = Duration::from_millis(50);
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

    let mut last = None;
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
        last = Some(fork_one_child(&mut node, &mut factory, &context)?);
    }
    let Some(last) = last else {
        return Err(invariant("no child was forked"));
    };

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
        .begin(1, MEMORY_BYTES, DISK_BYTES)
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
    })
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
    let host = LinuxQemuAttemptHostConfig::new(
        cgroup_root,
        run_root,
        FLIGHT_NAMESPACE,
        FIRST_PROJECT_ID,
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
        .begin(1, MEMORY_BYTES, DISK_BYTES)
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct FileIdentity {
    pub(super) device: u64,
    pub(super) inode: u64,
    pub(super) length: u64,
    pub(super) modified: Option<std::time::SystemTime>,
}

pub(super) fn file_identity(path: &Path) -> Result<FileIdentity, QemuLiveNodeStepGateError> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata =
        fs::metadata(path).map_err(|source| QemuLiveNodeStepGateError::PrepareRunDirectory {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        modified: metadata.modified().ok(),
    })
}

pub(super) fn child_open_files(
    process_id: u32,
) -> Result<BTreeSet<(u64, u64)>, QemuLiveNodeStepGateError> {
    use std::os::unix::fs::MetadataExt as _;

    let directory = PathBuf::from(format!("/proc/{process_id}/fd"));
    let entries = fs::read_dir(&directory).map_err(|source| {
        QemuLiveNodeStepGateError::PrepareRunDirectory {
            path: directory.clone(),
            source,
        }
    })?;
    let mut files = BTreeSet::new();
    for entry in entries {
        let entry = entry.map_err(|source| QemuLiveNodeStepGateError::PrepareRunDirectory {
            path: directory.clone(),
            source,
        })?;
        // Descriptors the child is closing race with this scan; skip the ones
        // that vanish and keep every regular file that remains open.
        if let Ok(metadata) = fs::metadata(entry.path())
            && metadata.is_file()
        {
            files.insert((metadata.dev(), metadata.ino()));
        }
    }
    Ok(files)
}

/// Summarizes a forked child's state and cgroup for a failure report.
///
/// The child may already be a zombie or gone; every field degrades to the
/// error that prevented reading it rather than failing the report.
pub(super) fn describe_forked_child(process_id: i64) -> String {
    let process = PathBuf::from(format!("/proc/{process_id}"));
    let status = fs::read_to_string(process.join("status"))
        .map(|status| {
            status
                .lines()
                .filter(|line| {
                    line.starts_with("State:")
                        || line.starts_with("PPid:")
                        || line.starts_with("Uid:")
                })
                .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_else(|source| format!("status unavailable: {source}"));
    let cgroup = fs::read_to_string(process.join("cgroup"))
        .map(|membership| membership.trim().to_owned())
        .unwrap_or_else(|source| format!("cgroup unavailable: {source}"));
    let tasks = describe_child_tasks(&process);
    let backtraces = describe_child_backtraces(process_id);
    format!("child {process_id}: {status}; cgroup {cgroup}; tasks [{tasks}]{backtraces}")
}

/// Quotes what the child wrote on its diagnostics stream while the source
/// still retains the consumer, as it does when retention itself failed.
pub(super) fn describe_retained_child_diagnostics(node: &mut QemuNode) -> String {
    match node.retained_hot_fork_child_diagnostics() {
        Ok(bytes) => format!("child diagnostics: {:?}", String::from_utf8_lossy(&bytes)),
        Err(source) => format!("child diagnostics unavailable: {source}"),
    }
}

/// Quotes what the child wrote on its diagnostics stream through the consumer
/// the launch transferred to this owner.
pub(super) fn describe_child_diagnostics(
    diagnostics: &mut QemuHotForkChildDiagnosticConsumer,
) -> String {
    match diagnostics.drain_available() {
        Ok(_drained) => format!(
            "child diagnostics: {:?}",
            String::from_utf8_lossy(diagnostics.retained())
        ),
        Err(source) => format!("child diagnostics unavailable: {source}"),
    }
}

/// Environment variable naming a debugger that can attach to the child.
///
/// The flight's failure report then carries every child thread's backtrace,
/// which is the only view into a reconstruction that stalls before the
/// child's private QMP greeting.
const CHILD_DEBUGGER_ENVIRONMENT: &str = "CRUCIBLE_HOT_FORK_CHILD_DEBUGGER";

/// A debugger attached to the live child and continued, so that a death by
/// signal during the watched operation is reported with a backtrace.
pub(super) struct ChildDebuggerWatch {
    debugger: std::process::Child,
}

impl ChildDebuggerWatch {
    /// Attaches the configured debugger to the child and lets it run.
    ///
    /// Returns `None` when no debugger is configured or it cannot start.
    pub(super) fn attach(process_id: u32) -> Option<Self> {
        let debugger = std::env::var_os(CHILD_DEBUGGER_ENVIRONMENT)?;
        let debugger = std::process::Command::new(&debugger)
            .args(["--nx", "--batch", "-p", &process_id.to_string()])
            .args(["-ex", "set pagination off"])
            .args(["-ex", "continue"])
            .args(["-ex", "thread apply all bt 24"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .ok()?;
        Some(Self { debugger })
    }

    /// Waits briefly for the debugger to report, detaches it otherwise, and
    /// returns whatever it printed.
    pub(super) fn finish(mut self) -> String {
        // A bounded poll rather than a clock: host monotonic time stays out
        // of this crate, and the debugger reports within moments of a death.
        for _poll in 0..100 {
            match self.debugger.try_wait() {
                Ok(Some(_status)) => break,
                Ok(None) => std::thread::sleep(Duration::from_millis(100)),
                Err(_source) => break,
            }
        }
        let _killed = self.debugger.kill();
        match self.debugger.wait_with_output() {
            Ok(output) => format!(
                "; debugger watch (status {}):\n{}{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
            Err(source) => format!("; debugger watch unavailable: {source}"),
        }
    }
}

/// Collects every child thread's backtrace through the configured debugger.
///
/// Returns an empty string when no debugger is configured; a debugger that
/// fails to attach reports its output rather than failing the report.
fn describe_child_backtraces(process_id: i64) -> String {
    let Some(debugger) = std::env::var_os(CHILD_DEBUGGER_ENVIRONMENT) else {
        return String::new();
    };
    let output = std::process::Command::new(&debugger)
        .args(["--nx", "--batch", "-p", &process_id.to_string()])
        .args(["-ex", "set pagination off"])
        .args(["-ex", "thread apply all bt 24"])
        .output();
    match output {
        Ok(output) => format!(
            "; backtraces (status {}):\n{}{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
        Err(source) => format!("; backtraces unavailable: {source}"),
    }
}

/// Lists a child's threads with their state, wait channel, and current syscall.
///
/// The flight runs with enough privilege to read these, and a child that
/// never greets on its private QMP endpoint is otherwise opaque.
fn describe_child_tasks(process: &Path) -> String {
    let Ok(entries) = fs::read_dir(process.join("task")) else {
        return String::from("tasks unavailable");
    };
    let maps = fs::read_to_string(process.join("maps")).unwrap_or_default();
    // Names the mapping that holds a syscall argument such as a futex word,
    // which separates the binary's own statics from heap and thread arenas.
    let locate = |argument: &str| {
        let Some(address) = argument
            .strip_prefix("0x")
            .and_then(|digits| u64::from_str_radix(digits, 16).ok())
        else {
            return String::from("?");
        };
        maps.lines()
            .find_map(|line| {
                let mut fields = line.split_whitespace();
                let range = fields.next()?;
                let (start, end) = range.split_once('-')?;
                let start = u64::from_str_radix(start, 16).ok()?;
                let end = u64::from_str_radix(end, 16).ok()?;
                (start <= address && address < end).then(|| {
                    let offset = fields.nth(1).unwrap_or("?");
                    let path = fields.nth(2).unwrap_or("[anon]");
                    format!("{path}+{offset}+{:#x}", address - start)
                })
            })
            .unwrap_or_else(|| String::from("unmapped"))
    };
    let mut tasks = Vec::new();
    for entry in entries.flatten() {
        let task = entry.path();
        let read = |name: &str| {
            fs::read_to_string(task.join(name))
                .map(|value| {
                    value
                        .split_whitespace()
                        .take(6)
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .unwrap_or_else(|_source| String::from("?"))
        };
        // Fields after the command name: state is the first and the start
        // time in clock ticks is the twentieth, which orders unnamed threads
        // by creation.
        let (state, started) = fs::read_to_string(task.join("stat"))
            .ok()
            .and_then(|stat| {
                let tail = stat.rsplit(')').next()?;
                let fields: Vec<&str> = tail.split_whitespace().collect();
                Some((
                    fields.first().copied().unwrap_or("?").to_owned(),
                    fields.get(19).copied().unwrap_or("?").to_owned(),
                ))
            })
            .unwrap_or_else(|| (String::from("?"), String::from("?")));
        let syscall = read("syscall");
        let waited_on = syscall
            .split_whitespace()
            .nth(1)
            .map(locate)
            .unwrap_or_else(|| String::from("?"));
        tasks.push(format!(
            "{} {} {} started={} wchan={} syscall={} at={}",
            entry.file_name().to_string_lossy(),
            read("comm"),
            state,
            started,
            read("wchan"),
            syscall,
            waited_on
        ));
    }
    tasks.join("; ")
}

/// Reports how the source reaped a child that could not be retained.
///
/// A child that failed reconstruction exits with 64 plus its failed step
/// index; the source owns `waitpid` and reports it through the child-process
/// query on its own nonblocking cadence, so this polls with the same bound as
/// the teardown path.
pub(super) fn describe_reaped_child(node: &mut QemuNode, generation: u64) -> String {
    for poll in 0..CHILD_REAP_POLLS {
        let state = match node.query_hot_fork_child_process(generation) {
            Ok(state) => state,
            Err(source) => return format!("child status query failed: {source}"),
        };
        if state.phase() != QmpHotForkChildProcessPhase::Running {
            return format!(
                "source reaped child as {:?} with status {}",
                state.phase(),
                state.status()
            );
        }
        if poll + 1 < CHILD_REAP_POLLS {
            thread::sleep(CHILD_REAP_POLL_INTERVAL);
        }
    }
    String::from("source did not reap the child in time")
}

pub(super) fn verify_child_placement(
    process_id: u32,
    cgroup_root: &Path,
) -> Result<(), QemuLiveNodeStepGateError> {
    let process = PathBuf::from(format!("/proc/{process_id}"));
    let membership = fs::read_to_string(process.join("cgroup")).map_err(|source| {
        QemuLiveNodeStepGateError::PrepareRunDirectory {
            path: process.join("cgroup"),
            source,
        }
    })?;
    let relative = membership
        .trim()
        .strip_prefix("0::/")
        .ok_or_else(|| invariant("child is not in a unified cgroup"))?;
    let group = Path::new("/sys/fs/cgroup").join(relative);
    if group.parent() != Some(cgroup_root) {
        return Err(invariant(&format!(
            "child escaped the dedicated cgroup root: {}",
            group.display()
        )));
    }
    let status = fs::read_to_string(process.join("status")).map_err(|source| {
        QemuLiveNodeStepGateError::PrepareRunDirectory {
            path: process.join("status"),
            source,
        }
    })?;
    let expected = CHILD_USER_ID.to_string();
    for key in ["Uid:", "Gid:"] {
        let unprivileged = status
            .lines()
            .find(|line| line.starts_with(key))
            .is_some_and(|line| line.split_whitespace().skip(1).all(|id| id == expected));
        if !unprivileged {
            return Err(invariant(
                "child does not run with the unprivileged credentials",
            ));
        }
    }
    Ok(())
}

pub(super) fn wait_for_child_exit(
    node: &mut QemuNode,
    generation: u64,
) -> Result<(), QemuLiveNodeStepGateError> {
    // Bounded polling keeps host wall time out of the state path; the source
    // parent reaps the killed child on its own nonblocking waitpid cadence.
    for poll in 0..CHILD_REAP_POLLS {
        let state = node
            .query_hot_fork_child_process(generation)
            .map_err(|source| qmp_operation("query hot-fork child status", source))?;
        if state.phase() != QmpHotForkChildProcessPhase::Running {
            return Ok(());
        }
        if poll + 1 < CHILD_REAP_POLLS {
            thread::sleep(CHILD_REAP_POLL_INTERVAL);
        }
    }
    Err(invariant("killed hot-fork child was not reaped in time"))
}

pub(super) fn realization(
    operation: &'static str,
    source: crate::QemuVmRealizationError,
) -> QemuLiveNodeStepGateError {
    invariant(&format!("{operation} failed: {source}"))
}

pub(super) fn invariant(reason: &str) -> QemuLiveNodeStepGateError {
    QemuLiveNodeStepGateError::ExactSnapshotInvariant {
        reason: reason.to_owned(),
    }
}

pub(super) fn qmp_operation(
    operation: &'static str,
    source: QemuNodeChannelError,
) -> QemuLiveNodeStepGateError {
    QemuLiveNodeStepGateError::node_op(
        operation,
        QemuNodeError::from_channel(crate::QemuNodeChannelPlane::QmpMachineControl, source),
    )
}
