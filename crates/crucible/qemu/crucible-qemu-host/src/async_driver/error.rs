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
    detail: QemuAsyncDriverRuntimeErrorDetail,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum QemuAsyncDriverRuntimeErrorDetail {
    #[default]
    Message,
    FaultResultStorage(u32, u32),
    FaultEventStorage(u64, u64, u64),
    ResourceLimit(&'static str, u64, u64, u64, u64),
}

impl QemuAsyncDriverRuntimeError {
    /// Creates a runtime adapter error.
    #[must_use]
    pub fn new(operation: &'static str, message: impl Into<String>) -> Self {
        Self {
            operation,
            message: message.into(),
            detail: QemuAsyncDriverRuntimeErrorDetail::Message,
        }
    }

    /// Creates an exact PREPARE result allocation failure.
    #[must_use]
    pub fn fault_result_storage(requested: usize, configured: usize) -> Self {
        Self {
            operation: "reserve fault preparation result",
            // This constructor is itself used after allocation refusal. Keep
            // its diagnostic storage empty so propagating typed LIMIT-2 never
            // attempts another heap allocation.
            message: String::new(),
            detail: QemuAsyncDriverRuntimeErrorDetail::FaultResultStorage(
                u32::try_from(requested).unwrap_or(u32::MAX),
                u32::try_from(configured).unwrap_or(u32::MAX),
            ),
        }
    }

    /// Creates an allocation-free fault-event staging limit failure.
    #[must_use]
    pub fn fault_event_storage(current: usize, requested: usize, configured: usize) -> Self {
        Self {
            operation: "stage fault occurrence event",
            message: String::new(),
            detail: QemuAsyncDriverRuntimeErrorDetail::FaultEventStorage(
                u64::try_from(current).unwrap_or(u64::MAX),
                u64::try_from(requested).unwrap_or(u64::MAX),
                u64::try_from(configured).unwrap_or(u64::MAX),
            ),
        }
    }

    /// Creates an allocation-free scenario resource-limit failure.
    #[must_use]
    pub const fn resource_limit(
        field: &'static str,
        current: u64,
        requested: u64,
        configured: u64,
        hard: u64,
    ) -> Self {
        Self {
            operation: "reserve host I/O resource",
            message: String::new(),
            detail: QemuAsyncDriverRuntimeErrorDetail::ResourceLimit(
                field, current, requested, configured, hard,
            ),
        }
    }

    /// Returns an exact PREPARE result-storage refusal, when present.
    #[must_use]
    pub const fn fault_result_storage_coordinates(&self) -> Option<(u32, u32)> {
        match self.detail {
            QemuAsyncDriverRuntimeErrorDetail::FaultResultStorage(requested, configured) => {
                Some((requested, configured))
            }
            _ => None,
        }
    }

    /// Returns an exact fault-event staging refusal, when present.
    #[must_use]
    pub const fn fault_event_storage_coordinates(&self) -> Option<(u64, u64, u64)> {
        match self.detail {
            QemuAsyncDriverRuntimeErrorDetail::FaultEventStorage(
                current,
                requested,
                configured,
            ) => Some((current, requested, configured)),
            _ => None,
        }
    }

    /// Returns an exact scenario resource refusal, when present.
    #[must_use]
    pub const fn resource_limit_coordinates(&self) -> Option<(&'static str, u64, u64, u64, u64)> {
        match self.detail {
            QemuAsyncDriverRuntimeErrorDetail::ResourceLimit(
                field,
                current,
                requested,
                configured,
                hard,
            ) => Some((field, current, requested, configured, hard)),
            _ => None,
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
