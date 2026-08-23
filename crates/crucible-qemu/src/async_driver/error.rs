//! Errors produced by the bounded asynchronous QEMU driver.

use super::*;
use thiserror::Error;

/// Error returned by a host-I/O runtime adapter.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("{operation} failed: {message}")]
pub struct QemuAsyncDriverRuntimeError {
    /// Operation being attempted.
    pub operation: &'static str,
    /// Deterministic failure detail.
    pub message: String,
    /// Exact PREPARE result allocation that failed, when applicable.
    pub fault_result_storage_requested: Option<u64>,
}

impl QemuAsyncDriverRuntimeError {
    /// Creates a runtime adapter error.
    #[must_use]
    pub fn new(operation: &'static str, message: impl Into<String>) -> Self {
        Self {
            operation,
            message: message.into(),
            fault_result_storage_requested: None,
        }
    }

    /// Creates an exact PREPARE result allocation failure.
    #[must_use]
    pub fn fault_result_storage(requested: usize) -> Self {
        Self {
            operation: "reserve fault preparation result",
            message: format!("cannot reserve exact published result length {requested}"),
            fault_result_storage_requested: Some(u64::try_from(requested).unwrap_or(u64::MAX)),
        }
    }
}

/// Error returned by a node-step target adapter.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("{operation} failed: {message}")]
pub struct QemuAsyncDriverTargetError {
    /// Operation being attempted.
    pub operation: &'static str,
    /// Deterministic failure detail.
    pub message: String,
}

impl QemuAsyncDriverTargetError {
    /// Creates a target adapter error.
    #[must_use]
    pub fn new(operation: &'static str, message: impl Into<String>) -> Self {
        Self {
            operation,
            message: message.into(),
        }
    }
}

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
