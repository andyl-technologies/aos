//! Exercises native VMState source freezing and coordinator-owned restoration.
//!
//! This flight uses the real plugin, typed QMP, and a named native QCOW2
//! VMState root. It does not install child-private graphs or fork a guest.

use super::{exact_gate_checkpoint, *};
use crate::{QmpHotForkProof, QmpHotForkTemplateState};

/// Records a live native-source prepare/abort and resumed-save flight.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuLiveSourceSetReport {
    /// Distinct retained-template generations exercised in order.
    pub template_generations: Vec<u64>,
    /// Number of successful VMState saves after source restoration.
    pub restored_vmstate_saves: u32,
    /// Exact guest coordinate reached after the last restoration.
    pub suffix_icount: u64,
}

/// Freezes and restores a native VMState source through two live transactions.
///
/// Each transaction follows an exact snapshot pause, requires the frozen-source
/// and native-worker proofs, and explicitly aborts the same retained generation.
/// The source then resumes to another exact boundary and successfully saves new
/// VMState, proving its restored write access. All QMP waits are bounded and
/// preserve transaction ownership; a failed flight terminates its owned guest.
/// This does not attest child graph installation or whole-world hot fork.
///
/// # Errors
///
/// Returns [`QemuLiveNodeStepGateError`] when the configuration contains a disk
/// or mediated block device, launch or execution fails, native source provenance
/// differs from the sole VMState root, rollback remains pending, or a resumed
/// VMState save fails.
pub fn run_qemu_live_source_set_gate(
    config: &QemuLiveNodeStepGateConfig,
) -> Result<QemuLiveSourceSetReport, QemuLiveNodeStepGateError> {
    if config.root_image.is_some() || config.shmem_block.is_some() {
        return Err(invariant(
            "source-set flight requires only the native VMState graph",
        ));
    }
    let directory = config.run_directory.join("source-set");
    fs::create_dir_all(&directory).map_err(|source| {
        QemuLiveNodeStepGateError::PrepareRunDirectory {
            path: directory.clone(),
            source,
        }
    })?;
    let identity = node_id(GATE_NODE);
    let mut node = build_live_node(
        config,
        &directory,
        QemuLiveNodeIdentity {
            node: GATE_NODE,
            router: GATE_ROUTER,
            crash_detector: "live-source-set",
        },
        None,
        true,
    )?;
    let mut generations = Vec::with_capacity(2);

    for ceiling in [3_000_001, 6_000_001] {
        let quantum = advance_to_busy_ceiling(&mut node, ceiling)?;
        node.capture_exact_snapshot_paused(
            &identity,
            exact_gate_checkpoint(&identity, quantum.completion_icount, false),
        )
        .map_err(|source| QemuLiveNodeStepGateError::node_op("save source VMState", source))?;
        let held = node
            .prepare_hot_fork_template_barriers(&[])
            .map_err(|source| qmp_operation("prepare native source-set barriers", source))?;
        require_vmstate_source(&held)?;
        if generations
            .last()
            .is_some_and(|previous| *previous >= held.generation())
        {
            return Err(invariant(
                "source-set transaction generation did not advance",
            ));
        }
        generations.push(held.generation());
        let observed = node
            .query_hot_fork_template()
            .map_err(|source| qmp_operation("query retained native source set", source))?;
        require_vmstate_source(&observed)?;
        if observed.generation() != held.generation() {
            return Err(invariant("source-set query changed transaction generation"));
        }
        abort_sources(&mut node, held.generation())?;
        node.resume_after_exact_snapshot().map_err(|source| {
            QemuLiveNodeStepGateError::node_op("resume restored native source", source)
        })?;
    }

    let suffix = advance_to_busy_ceiling(&mut node, 9_000_001)?;
    node.capture_exact_snapshot_paused(
        &identity,
        exact_gate_checkpoint(&identity, suffix.completion_icount, false),
    )
    .map_err(|source| QemuLiveNodeStepGateError::node_op("save restored native VMState", source))?;
    node.force_crash_and_reap_for_gate().map_err(|source| {
        QemuLiveNodeStepGateError::node_op("reap source-set flight guest", source)
    })?;
    Ok(QemuLiveSourceSetReport {
        template_generations: generations,
        restored_vmstate_saves: 2,
        suffix_icount: suffix.completion_icount,
    })
}

pub(super) fn require_vmstate_source(
    state: &QmpHotForkTemplateState,
) -> Result<(), QemuLiveNodeStepGateError> {
    let block = state.block_barrier();
    let source = block.snapshot_sources();
    if !state.transaction_active()
        || !block.snapshot_complete()
        || !block.quiescent()
        || !source.frozen()
        || source.root_count() != 1
        || source.node_count() != 2
        || source.originally_writable_root_count() != 1
        || source.originally_writable_backend_count() != 0
        || block.backend_count() != 0
        || block.writable_backends() != 0
        || !block.snapshot_roots().is_empty()
        || !state.acknowledges(QmpHotForkProof::BlockSnapshot)
        || !state.acknowledges(QmpHotForkProof::AioBottomHalvesAndTimers)
    {
        return Err(invariant(&format!(
            "unexpected native VMState source proof: {state:?}"
        )));
    }
    Ok(())
}

fn abort_sources(node: &mut QemuNode, generation: u64) -> Result<(), QemuLiveNodeStepGateError> {
    for poll in 0..100 {
        let state = node
            .abort_hot_fork_template()
            .map_err(|source| qmp_operation("abort retained native source set", source))?;
        if state.generation() != generation {
            return Err(invariant(
                "source restoration changed its transaction generation",
            ));
        }
        if state.rollback_complete() {
            if state.block_barrier().snapshot_sources().frozen() {
                return Err(invariant("source provenance survived completed rollback"));
            }
            return Ok(());
        }
        if poll < 99 {
            // Native reopen runs on the main loop. Keep its pending transaction
            // owned and give that loop time before the next explicit abort.
            thread::sleep(Duration::from_millis(10));
        }
    }
    Err(invariant(
        "native source restoration exceeded the bounded abort exchanges",
    ))
}

fn invariant(reason: &str) -> QemuLiveNodeStepGateError {
    QemuLiveNodeStepGateError::ExactSnapshotInvariant {
        reason: reason.to_owned(),
    }
}

fn qmp_operation(
    operation: &'static str,
    source: QemuNodeChannelError,
) -> QemuLiveNodeStepGateError {
    QemuLiveNodeStepGateError::node_op(
        operation,
        QemuNodeError::from_channel(crate::QemuNodeChannelPlane::QmpMachineControl, source),
    )
}
