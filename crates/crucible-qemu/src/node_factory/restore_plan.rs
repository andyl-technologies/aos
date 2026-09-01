//! Authorized VMState restore plans for warm QEMU node realization.

use crucible::{Checkpoint, ContentHash};

use crate::{
    QemuBakedGenesisRestoreAdmission, QemuHostIoCheckpoint, QemuLoadvmCommandAuthorization,
    QemuLoadvmRealizationAdmission, QemuNodeContinuationCheckpoint, QemuVmSnapshot,
};

/// Authorized VMState restore inputs for warm QEMU node realization.
pub struct QemuNodeRestorePlan<'a> {
    pub(super) checkpoint: &'a Checkpoint,
    pub(super) authorization: QemuLoadvmCommandAuthorization,
    pub(super) admission: QemuNodeRestoreAdmission,
    pub(super) host_io_checkpoint: Option<&'a QemuHostIoCheckpoint>,
    pub(super) node_continuation: Option<&'a QemuNodeContinuationCheckpoint>,
}

/// Admission proof for the VMState snapshot restored before node assembly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QemuNodeRestoreAdmission {
    /// The trusted baked ready-point snapshot produced by QEMU genesis baking.
    BakedGenesis {
        /// World identity whose baked genesis was validated.
        world_id: ContentHash,
    },
    /// A replay-oracle-validated exact fat checkpoint runtime.
    ReplayOracle(QemuLoadvmRealizationAdmission),
    /// A complete snapshot emitted by a live scheduler-facing node.
    CapturedExact {
        /// Identity shared by VMState and both Apache continuation halves.
        execution_binding: ContentHash,
    },
    /// A probe-only exact snapshot that cannot be admitted as a runtime.
    ReplayOracleProbe,
}

impl<'a> QemuNodeRestorePlan<'a> {
    /// Creates a warm-restore plan for an exact fat checkpoint.
    #[must_use]
    pub const fn new(
        checkpoint: &'a Checkpoint,
        authorization: QemuLoadvmCommandAuthorization,
        admission: QemuLoadvmRealizationAdmission,
    ) -> Self {
        Self {
            checkpoint,
            authorization,
            admission: QemuNodeRestoreAdmission::ReplayOracle(admission),
            host_io_checkpoint: None,
            node_continuation: None,
        }
    }

    /// Creates a probe-only warm-restore plan for snapshot-completeness comparison.
    #[must_use]
    pub const fn snapshot_completeness_probe(
        checkpoint: &'a Checkpoint,
        authorization: QemuLoadvmCommandAuthorization,
    ) -> Self {
        Self {
            checkpoint,
            authorization,
            admission: QemuNodeRestoreAdmission::ReplayOracleProbe,
            host_io_checkpoint: None,
            node_continuation: None,
        }
    }

    /// Creates a warm-restore plan for a baked genesis ready-point checkpoint.
    #[must_use]
    pub fn baked_genesis(admission: QemuBakedGenesisRestoreAdmission<'a>) -> Self {
        Self {
            checkpoint: admission.checkpoint(),
            authorization: admission.authorization(),
            admission: QemuNodeRestoreAdmission::BakedGenesis {
                world_id: admission.world_id(),
            },
            host_io_checkpoint: None,
            node_continuation: None,
        }
    }

    pub(crate) fn captured_exact(snapshot: &'a QemuVmSnapshot) -> Self {
        Self {
            checkpoint: snapshot.checkpoint(),
            authorization: crate::QemuExactSnapshotPolicy::production().authorize_loadvm_runtime(),
            admission: QemuNodeRestoreAdmission::CapturedExact {
                execution_binding: snapshot.checkpoint().id,
            },
            host_io_checkpoint: Some(snapshot.host_io()),
            node_continuation: Some(snapshot.node_continuation()),
        }
    }

    /// Pairs the QEMU VMState restore with its complete host-I/O continuation.
    #[must_use]
    pub const fn with_host_io_checkpoint(mut self, checkpoint: &'a QemuHostIoCheckpoint) -> Self {
        self.host_io_checkpoint = Some(checkpoint);
        self
    }

    /// Pairs the restore with scheduler-facing node continuation state.
    #[must_use]
    pub const fn with_node_continuation(
        mut self,
        checkpoint: &'a QemuNodeContinuationCheckpoint,
    ) -> Self {
        self.node_continuation = Some(checkpoint);
        self
    }

    /// Returns the checkpoint whose VMState will be restored.
    #[must_use]
    pub const fn checkpoint(&self) -> &'a Checkpoint {
        self.checkpoint
    }

    /// Returns the low-level QMP `loadvm` authorization token.
    #[must_use]
    pub const fn authorization(&self) -> QemuLoadvmCommandAuthorization {
        self.authorization
    }

    /// Returns the admission proof paired with the restore authorization.
    #[must_use]
    pub const fn admission(&self) -> QemuNodeRestoreAdmission {
        self.admission
    }

    /// Returns the paired host-I/O continuation, when the topology owns one.
    #[must_use]
    pub const fn host_io_checkpoint(&self) -> Option<&'a QemuHostIoCheckpoint> {
        self.host_io_checkpoint
    }
}
