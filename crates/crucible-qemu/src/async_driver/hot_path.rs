//! Shared-memory-only quantum hot-path conformance.

use super::*;

/// Asserts that a quantum completion used only the shared-memory hot path.
///
/// # Errors
///
/// Returns [`QemuAsyncDriverError::ForbiddenHotPathOperation`] when a QMP or
/// plugin-IPC operation appears in the supplied quantum operations.
pub fn assert_async_driver_quantum_hot_path_is_shmem_only(
    operations: &[QemuQuantumOperation],
) -> Result<(), QemuAsyncDriverError> {
    for operation in operations {
        let plane = operation.plane();
        if plane != QemuQuantumOperationPlane::SharedMemory {
            return Err(QemuAsyncDriverError::ForbiddenHotPathOperation { plane });
        }
    }
    Ok(())
}
