//! Read-only CPU scalars and fixed oracle windows at paused node boundaries.

use super::*;

impl QemuNode {
    /// Controls opt-in spill measurements through the original admitted registrar.
    ///
    /// # Errors
    /// Refuses missing admission, stale ownership or bounded control failure.
    /// Absence means measurements are unavailable, never an inferred zero.
    #[cfg(any(test, feature = "test-support"))]
    pub fn ram_performance(
        &self,
        action: crucible_protocol::ram_control::RamControlPerformanceAction,
    ) -> Result<
        Option<crucible_protocol::ram_control::RamControlPerformance>,
        crucible_protocol::ram_control::RamControlError,
    > {
        let registration = self
            .host_io_runtime
            .ram_control_registration()
            .ok_or(crucible_protocol::ram_control::RamControlError::AuthorityMismatch)?;
        registration
            .registrar
            .performance(registration.target, action)
    }

    /// Reads fixed BIOS/ROM oracle windows while the admitted machine stays paused.
    ///
    /// The caller retains actual original resident credit for the bounded QMP
    /// response/parser and returned sample. The operation borrows the caller's
    /// original guard throughout every exchange; it never starts a new deadline.
    ///
    /// # Errors
    /// Refuses unavailable supervision, running QEMU, oversized/invalid responses,
    /// expired original ownership, or any transport uncertainty.
    #[cfg(any(test, feature = "test-support"))]
    pub fn observe_performance_fixture(
        &mut self,
        guard: &crucible_linux_resource::host_supervision::HostOperationGuard,
        resident: std::sync::Arc<dyn Send + Sync>,
    ) -> Result<crate::qmp::QemuPerformanceObservation, QemuNodeError> {
        self.channels
            .qmp_machine_control
            .performance_observation(guard, resident)
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::QmpMachineControl, source)
            })
    }

    pub(crate) fn paused_cpu(
        &mut self,
        vcpu: u32,
        generation: Option<u64>,
    ) -> Result<crate::qmp::QmpPausedCpu, QemuNodeError> {
        self.channels
            .qmp_machine_control
            .query_paused_cpu(vcpu, generation)
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::QmpMachineControl, source)
            })
    }
}
