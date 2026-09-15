//! Native VMState source validation shared by guarded hot-fork flights.

use super::*;
use crate::{QmpHotForkProof, QmpHotForkTemplateState};

const SOURCE_ROLLBACK_POLLS: u32 = 100;
const SOURCE_ROLLBACK_POLL_INTERVAL: Duration = Duration::from_millis(10);

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
        return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: format!("unexpected native VMState source proof: {state:?}"),
        });
    }
    Ok(())
}

/// Boundedly restores the native VMState source owned by `generation`.
pub(super) fn abort_vmstate_source_transaction(
    node: &mut QemuNode,
    generation: u64,
) -> Result<(), QemuLiveNodeStepGateError> {
    for poll in 0..SOURCE_ROLLBACK_POLLS {
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
        if poll + 1 < SOURCE_ROLLBACK_POLLS {
            // Native reopen runs on the main loop. Keep its pending transaction
            // owned and give that loop time before the next explicit abort.
            thread::sleep(SOURCE_ROLLBACK_POLL_INTERVAL);
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
