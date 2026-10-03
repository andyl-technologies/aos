//! Native QMP block-seal exchanges for a stopped source node.

use std::path::Path;

use super::{QemuNode, QemuNodeChannelPlane, QemuNodeError};
use crate::{QmpHotForkBlockBarrierState, QmpHotForkBlockSealRequest, QmpHotForkBlockSealState};

impl QemuNode {
    pub(crate) fn query_hot_fork_source_graph(
        &mut self,
        expected_qemu_pid: i64,
        expected_template_generation: u64,
    ) -> Result<crate::QmpHotForkSourceGraphReceipt, QemuNodeError> {
        self.channels
            .qmp_machine_control
            .query_hot_fork_source_graph(expected_qemu_pid, expected_template_generation)
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::QmpMachineControl, source)
            })
    }

    pub(crate) fn query_hot_fork_block_seal(
        &mut self,
    ) -> Result<QmpHotForkBlockSealState, QemuNodeError> {
        self.channels
            .qmp_machine_control
            .query_hot_fork_block_seal()
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::QmpMachineControl, source)
            })
    }

    pub(crate) fn add_hot_fork_detached_root_overlay(
        &mut self,
        request: &QmpHotForkBlockSealRequest,
        file_path: &Path,
    ) -> Result<(), QemuNodeError> {
        self.channels
            .qmp_machine_control
            .add_hot_fork_detached_root_overlay(request, file_path)
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::QmpMachineControl, source)
            })
    }

    pub(crate) fn hold_hot_fork_block_barrier(
        &mut self,
    ) -> Result<QmpHotForkBlockBarrierState, QemuNodeError> {
        self.channels
            .qmp_machine_control
            .hold_hot_fork_block_barrier()
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::QmpMachineControl, source)
            })
    }

    pub(crate) fn seal_hot_fork_block_roots(
        &mut self,
        inventory: &QmpHotForkBlockSealState,
        roots: &[QmpHotForkBlockSealRequest],
    ) -> Result<QmpHotForkBlockSealState, QemuNodeError> {
        self.channels
            .qmp_machine_control
            .seal_hot_fork_block_roots(inventory, roots)
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::QmpMachineControl, source)
            })
    }
}
