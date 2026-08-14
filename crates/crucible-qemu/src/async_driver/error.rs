//! Errors produced by the bounded asynchronous QEMU driver.

use super::*;

/// Error returned by the bounded async driver.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum QemuAsyncDriverError {
    /// A host-I/O await timeout was zero.
    #[error("QEMU async driver wait {wait:?} has a zero timeout")]
    UnboundedAwait {
        /// Wait class with no timeout budget.
        wait: QemuAsyncWait,
    },
    /// A runtime adapter operation failed.
    #[error("QEMU async runtime failed: {0}")]
    Runtime(QemuAsyncDriverRuntimeError),
    /// A node-step target operation failed.
    #[error("QEMU async target failed: {0}")]
    Target(QemuAsyncDriverTargetError),
    /// A shared-memory channel operation failed.
    #[error("QEMU async shared-memory channel failed: {0}")]
    Channel(QemuNodeChannelError),
    /// Lifecycle helper was asked to run the per-quantum completion wait.
    #[error("QEMU async lifecycle helper cannot await quantum completion")]
    LifecycleAdvanceWait,
    /// A non-shared-memory operation appeared in a quantum hot path.
    #[error("QEMU async quantum hot path used forbidden plane {plane:?}")]
    ForbiddenHotPathOperation {
        /// Forbidden operation plane.
        plane: QemuQuantumOperationPlane,
    },
}
