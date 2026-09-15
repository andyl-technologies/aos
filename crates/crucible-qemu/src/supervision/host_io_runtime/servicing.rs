//! Bound device servicers retained by the host I/O runtime.

use super::*;

/// The participant half of the runtime: a block servicer plus its diagnostic sink.
pub(super) struct BlockIoServicing {
    pub(super) servicer: Arc<std::sync::Mutex<QemuLiveBlockIoServicer>>,
    pub(super) worker: super::super::QemuLiveBlockHostWorkPool,
    pub(super) diagnostics: Arc<BlockIoDiagnostics>,
    /// Whether production servicing must wait for a fresh branch-local owner.
    pub(super) coordinator_required: bool,
}

impl BlockIoServicing {
    pub(super) fn lock_servicer(
        &self,
        operation: &'static str,
    ) -> Result<std::sync::MutexGuard<'_, QemuLiveBlockIoServicer>, QemuAsyncDriverRuntimeError>
    {
        self.servicer.lock().map_err(|_poisoned| {
            QemuAsyncDriverRuntimeError::new(operation, "block host worker state is poisoned")
        })
    }
}

/// The participant half of the runtime for one shared-memory 9p device.
pub(super) struct NinepIoServicing {
    pub(super) servicer: QemuLive9pIoServicer,
    pub(super) diagnostics: Arc<NinepIoDiagnostics>,
    pub(super) coordinator: Option<Box<dyn QemuNinepFaultCoordinator>>,
    /// Whether production servicing must wait for a fresh branch-local owner.
    pub(super) coordinator_required: bool,
}
