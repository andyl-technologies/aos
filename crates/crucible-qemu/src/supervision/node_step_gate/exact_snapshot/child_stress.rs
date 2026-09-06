//! Live hot-fork lifecycle stress: many children from one retained template
//! without the source growing.
//!
//! The source pauses at an exact snapshot and retains a template once. Each
//! lifecycle then stages child resources, forks a child with a private
//! VMState copy, waits for the child's private QMP greeting, kills it, lets
//! the source reap it, releases every child stage, and finishes the target
//! attempt so the next lifecycle restages against the same template. The
//! flight holds the source to its baseline thread and descriptor counts at
//! every sample and reports how its private dirty memory moved after a
//! warm-up, which is the leak evidence the RFC's stress task asks for.

use std::fs;
use std::os::fd::AsFd as _;
use std::path::Path;

use super::child_files::{
    DISK_BYTES, GuardedSource, MAXIMUM_RING_IMAGE_BYTES, MEMORY_BYTES, SOURCE_BUSY_CEILING,
    describe_child_diagnostics, describe_forked_child, describe_reaped_child, file_identity,
    invariant, launch_guarded_source, qmp_operation, realization, wait_for_child_exit,
};
use super::child_measure::{ProcessFootprint, elapsed_milliseconds, monotonic_nanoseconds};
use super::{exact_gate_checkpoint, source_set::require_vmstate_source, *};
use crate::{
    DEFAULT_VMSTATE_FILE_NAME, DEFAULT_VMSTATE_NODE_NAME, LinuxQemuAttemptHostFactory,
    QemuHotForkChildFileDestination, QemuHotForkLaunchError, QmpHotForkChildFileRoot,
    QmpHotForkOutcome,
};

/// Lifecycles completed before the private-dirty baseline is taken, so
/// first-touch page faults and allocator warm-up do not count as growth.
const WARMUP_LIFECYCLES: u32 = 10;
/// Lifecycles between source footprint samples; the counts are also sampled
/// after the final lifecycle.
const SAMPLE_INTERVAL: u32 = 25;

/// Records a lifecycle stress run against one retained template.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuLiveHotForkChildStressReport {
    /// Retained template generation every child was forked from.
    pub template_generation: u64,
    /// Child lifecycles completed.
    pub lifecycles: u32,
    /// Child-file plan generation the last lifecycle consumed; monotonic
    /// across the run, so it also counts every plan QEMU admitted.
    pub last_child_files_generation: u64,
    /// Source threads with the template retained and no child staged.
    pub source_threads: u64,
    /// Source descriptors with the template retained and no child staged.
    pub source_descriptors: u64,
    /// Threads the source held beyond that baseline at the final sample; the
    /// flight fails at the first sample where this is nonzero.
    pub source_threads_leaked: u64,
    /// Descriptors the source held beyond that baseline at the final sample;
    /// the flight fails at the first sample where this is nonzero.
    pub source_descriptors_leaked: u64,
    /// Source private dirty memory in KiB after the warm-up lifecycles.
    pub source_private_dirty_after_warmup_kib: u64,
    /// Source private dirty memory in KiB after the final lifecycle.
    pub source_private_dirty_final_kib: u64,
    /// Growth of the source's private dirty memory in KiB from the warm-up
    /// sample to the final one.
    pub source_private_dirty_growth_kib: i64,
    /// Longest fork call across the run, in milliseconds.
    pub max_fork_ms: u64,
    /// Longest fork-to-private-QMP-handshake across the run, in milliseconds.
    pub max_ready_ms: u64,
    /// Wall time of the whole lifecycle loop, in milliseconds.
    pub total_ms: u64,
    /// Directory entries under the run root after the last target finished;
    /// bounded by the source's slot, so a growing count means leaked attempts.
    pub run_root_entries: u64,
    /// Source private dirty memory in KiB at each sample, paired with the
    /// lifecycles completed at that sample, so growth has a shape and not
    /// only a total.
    pub private_dirty_samples: Vec<(u32, u64)>,
}

/// Runs `lifecycles` child lifecycles against one retained template.
///
/// Each lifecycle stages child resources and a private VMState destination,
/// forks, waits for the child's private QMP greeting, kills the child,
/// releases every child stage in the reconciliation's order, and finishes the
/// target attempt. The source's thread and descriptor counts are sampled
/// every few lifecycles and at the end and must equal the baseline taken with
/// the template retained and no child staged.
///
/// # Errors
///
/// Returns [`QemuLiveNodeStepGateError`] when the configuration contains a
/// disk or mediated block device, `lifecycles` is zero, or any launch,
/// staging, fork, handshake, release, or leak check fails; the error names the
/// lifecycle it failed on.
pub fn run_qemu_live_hot_fork_child_stress_gate(
    config: &QemuLiveNodeStepGateConfig,
    cgroup_root: &Path,
    run_root: &Path,
    lifecycles: u32,
) -> Result<QemuLiveHotForkChildStressReport, QemuLiveNodeStepGateError> {
    if config.root_image.is_some() || config.shmem_block.is_some() {
        return Err(invariant(
            "hot-fork lifecycle stress requires only the native VMState graph",
        ));
    }
    if lifecycles == 0 {
        return Err(invariant("lifecycle stress needs at least one lifecycle"));
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

    let source_baseline = ProcessFootprint::read(node.process_id())?;
    let mut sampled = source_baseline;
    let mut after_warmup = None;
    let mut max_fork_ms = 0;
    let mut max_ready_ms = 0;
    let mut last_child_files_generation = 0;
    let mut private_dirty_samples = Vec::new();
    let loop_started = monotonic_nanoseconds();
    for lifecycle in 0..lifecycles {
        let outcome = run_one_lifecycle(
            &mut node,
            &mut factory,
            config,
            source_before.length,
            template_generation,
        )
        .map_err(|error| lifecycle_error(lifecycle, error))?;
        max_fork_ms = max_fork_ms.max(outcome.fork_ms);
        max_ready_ms = max_ready_ms.max(outcome.ready_ms);
        last_child_files_generation = outcome.child_files_generation;

        let completed = lifecycle.saturating_add(1);
        if completed == WARMUP_LIFECYCLES {
            after_warmup = Some(ProcessFootprint::read(node.process_id())?);
        }
        if completed % SAMPLE_INTERVAL == 0 || completed == lifecycles {
            sampled = ProcessFootprint::read(node.process_id())?;
            require_baseline_counts(&sampled, &source_baseline, completed)?;
            private_dirty_samples.push((completed, sampled.private_dirty_kib));
        }
    }
    let total_ms = elapsed_milliseconds(loop_started);
    // A run shorter than the warm-up measures growth from its own baseline.
    let after_warmup = after_warmup.unwrap_or(source_baseline);
    let growth_kib = i64::try_from(sampled.private_dirty_kib)
        .unwrap_or(i64::MAX)
        .saturating_sub(i64::try_from(after_warmup.private_dirty_kib).unwrap_or(0));
    let run_root_entries = fs::read_dir(run_root)
        .map_err(|source| QemuLiveNodeStepGateError::PrepareRunDirectory {
            path: run_root.to_path_buf(),
            source,
        })?
        .count();
    let run_root_entries = u64::try_from(run_root_entries).unwrap_or(u64::MAX);

    node.force_crash_and_reap_for_gate().map_err(|source| {
        QemuLiveNodeStepGateError::node_op("reap hot-fork stress source", source)
    })?;
    drop(node);
    drop(source_directory);
    source_owner
        .finish()
        .map_err(|source| realization("finish source attempt owner", source))?;

    Ok(QemuLiveHotForkChildStressReport {
        template_generation,
        lifecycles,
        last_child_files_generation,
        source_threads: source_baseline.threads,
        source_descriptors: source_baseline.descriptors,
        source_threads_leaked: sampled.threads.saturating_sub(source_baseline.threads),
        source_descriptors_leaked: sampled
            .descriptors
            .saturating_sub(source_baseline.descriptors),
        source_private_dirty_after_warmup_kib: after_warmup.private_dirty_kib,
        source_private_dirty_final_kib: sampled.private_dirty_kib,
        source_private_dirty_growth_kib: growth_kib,
        max_fork_ms,
        max_ready_ms,
        total_ms,
        run_root_entries,
        private_dirty_samples,
    })
}

/// What one lifecycle reports back to the loop.
struct LifecycleOutcome {
    child_files_generation: u64,
    fork_ms: u64,
    ready_ms: u64,
}

/// Stages, forks, greets, kills, reaps, and releases one child.
fn run_one_lifecycle(
    node: &mut QemuNode,
    factory: &mut LinuxQemuAttemptHostFactory,
    config: &QemuLiveNodeStepGateConfig,
    source_vmstate_bytes: u64,
    template_generation: u64,
) -> Result<LifecycleOutcome, QemuLiveNodeStepGateError> {
    node.prepare_hot_fork_child_resources(MAXIMUM_RING_IMAGE_BYTES)
        .map_err(|source| invariant(&format!("prepare child resources failed: {source}")))?;

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
    let fork_ms = elapsed_milliseconds(fork_started);
    let launch = match forked {
        Ok(launch) => launch,
        Err(QemuHotForkLaunchError::Rejected { source }) => {
            return Err(qmp_operation("fork retained template", source));
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
    let (_parent, authority, child_qmp, mut diagnostics, continuation) = launch.into_parts();

    // The greeting proves the child finished its reconstruction; nothing
    // else is asked of it before it is torn down.
    let child_channel = match child_qmp.connect() {
        Ok(channel) => channel,
        Err(source) => {
            let child = describe_forked_child(i64::from(child_process_id));
            let reaped = describe_reaped_child(node, child_generation);
            let written = describe_child_diagnostics(&mut diagnostics);
            return Err(invariant(&format!(
                "child QMP handshake failed: {source}; {child}; {reaped}; {written}"
            )));
        }
    };
    let ready_ms = elapsed_milliseconds(fork_started);

    drop(child_channel);
    drop(continuation);
    authority
        .kill()
        .map_err(|source| realization("kill hot-fork child", source))?;
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

    Ok(LifecycleOutcome {
        child_files_generation: plan.generation(),
        fork_ms,
        ready_ms,
    })
}

/// Fails the run at the first sample where the source holds more threads or
/// descriptors than it did with no child staged.
fn require_baseline_counts(
    sampled: &ProcessFootprint,
    baseline: &ProcessFootprint,
    completed: u32,
) -> Result<(), QemuLiveNodeStepGateError> {
    if sampled.threads != baseline.threads || sampled.descriptors != baseline.descriptors {
        return Err(invariant(&format!(
            "source left its baseline after {completed} lifecycles: threads {}/{}, \
             descriptors {}/{}",
            sampled.threads, baseline.threads, sampled.descriptors, baseline.descriptors
        )));
    }
    Ok(())
}

/// Prefixes a lifecycle failure with the lifecycle it happened in.
fn lifecycle_error(lifecycle: u32, error: QemuLiveNodeStepGateError) -> QemuLiveNodeStepGateError {
    invariant(&format!("lifecycle {lifecycle}: {error}"))
}
