//! Exact snapshot/restore production gate and its checkpoint helpers.

use super::*;
mod child_files;
mod child_measure;
mod child_stress;
mod child_support;
mod source_set;
pub use child_files::{QemuLiveHotForkChildReport, run_qemu_live_hot_fork_child_gate};
pub use child_stress::{
    QemuLiveHotForkChildStressReport, run_qemu_live_hot_fork_child_stress_gate,
};
fn exact_gate_checkpoint(node: &NodeId, icount: u64, block: bool) -> Checkpoint {
    let identity = ContentHash::from_canonical_material(
        "crucible.qemu.live-exact-snapshot-gate.v1",
        &format!("node={}\nicount={icount}\nblock={block}", node.name),
    );
    let mut checkpoint = Checkpoint::new(identity, identity, CheckpointKind::Fat);
    checkpoint.virtual_time = VirtualTime { ticks: icount };
    checkpoint
        .node_icounts
        .insert(node.clone(), Icount { retired: icount });
    checkpoint
}
