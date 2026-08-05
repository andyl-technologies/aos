//! Errors raised while binding or operating the mapped quantum hot path.

use crucible_shmem::{
    FaultTransportError, MappedSetupRegionAccessError, PreemptionMailboxError, RegionControlError,
};
use thiserror::Error;

use crate::{QemuCoverageError, QemuNodeChannelError, QemuQuantumError};

/// Reports a failure while binding a mapped QEMU quantum hot path.
#[derive(Debug, Error)]
pub enum QemuMappedQuantumShmemHotPathError {
    /// The mapped shared-memory region could not expose the requested node rings.
    #[error("mapped QEMU quantum shared-memory access failed")]
    RegionAccess {
        /// Underlying mapped-region access error.
        source: MappedSetupRegionAccessError,
    },
    /// Publishing a mapped shared-memory control action failed.
    #[error("mapped QEMU quantum shared-memory control failed")]
    RegionControl {
        /// Underlying shared-memory control wake error.
        source: RegionControlError,
    },
    /// The live plugin preemption mailbox rejected a host command.
    #[error("mapped QEMU preemption mailbox failed: {source}")]
    PreemptionMailbox {
        /// Underlying scheduler-to-plugin mailbox error.
        source: PreemptionMailboxError,
    },
    /// The lossless fault command or result transport rejected an operation.
    #[error("mapped QEMU fault transport failed: {source}")]
    FaultTransport {
        /// Exact ring, arena, or envelope failure.
        source: FaultTransportError,
    },
    /// The borrowed quantum adapter rejected the selected view.
    #[error("mapped QEMU quantum hot-path binding failed")]
    Quantum {
        /// Underlying quantum hot-path error.
        source: QemuQuantumError,
    },
    /// Coverage policy or consumer construction failed.
    #[error("mapped QEMU coverage bridge configuration failed")]
    Coverage {
        /// Underlying coverage bridge error.
        source: QemuCoverageError,
    },
    /// The ABI queue cardinality differed from the configured coverage map.
    #[error("coverage map has {map_entries} entries but mapped queue has {queue_capacity}")]
    CoverageQueueCapacity {
        /// Engine map cardinality.
        map_entries: usize,
        /// Mapped queue cardinality.
        queue_capacity: usize,
    },
}

impl QemuMappedQuantumShmemHotPathError {
    pub(super) fn into_channel_error(self, operation: &'static str) -> QemuNodeChannelError {
        QemuNodeChannelError::new(operation, self.to_string())
    }
}
