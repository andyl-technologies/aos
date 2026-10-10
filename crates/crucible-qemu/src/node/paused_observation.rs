//! Read-only CPU scalars and fixed oracle windows at paused node boundaries.

use super::*;

impl QemuNode {
    /// Discovers the sealed RAM identity through this node's QMP connection.
    ///
    /// The caller supplies this machine's actual paused VM-stop generation,
    /// retains the owned VM row and original funding, and lends its published
    /// cancellation owner. Fixed-name exclusivity and uncertain descriptor
    /// retirement remain caller obligations, as for residency observations.
    /// This method grants no memory, swap or placement authority.
    ///
    /// # Errors
    /// Returns the original QMP error for unavailable channel support, refused
    /// supervision, import, dispatch or sealed response validation.
    #[cfg(feature = "kernel-swap-measurement")]
    pub fn discover_kernel_swap_admission(
        &mut self,
        cancellation: &mut crate::qmp::QmpKernelSwapCancellation,
        generation: u64,
        original: &crucible_linux_resource::host_supervision::HostOperationGuard,
    ) -> Result<crate::qmp::QmpKernelSwapAdmission, crate::qmp::QmpError> {
        self.channels
            .qmp_machine_control
            .discover_kernel_swap_admission(cancellation, generation, original)
    }

    /// Observes experimental RAM residency through this node's QMP connection.
    ///
    /// The caller retains the actual VM row and its original funding, lends its
    /// published cancellation owner, and owns exclusive use of the fixed name
    /// on this exact connection and generation. This method grants no swap or
    /// paging capability; admission and physical retirement remain caller duties.
    ///
    /// # Errors
    /// Returns the original QMP error for unavailable channel support, refused
    /// supervision, descriptor transfer, dispatch or interval response validation.
    #[cfg(feature = "kernel-swap-measurement")]
    pub fn observe_kernel_swap_residency(
        &mut self,
        cancellation: &mut crate::qmp::QmpKernelSwapCancellation,
        generation: u64,
        topology_generation: u64,
        original: &crucible_linux_resource::host_supervision::HostOperationGuard,
    ) -> Result<crate::qmp::QmpKernelSwapResidency, crate::qmp::QmpError> {
        self.channels
            .qmp_machine_control
            .observe_kernel_swap_residency(cancellation, generation, topology_generation, original)
    }

    /// Attempts one experimental descriptor closure on this node's connection.
    ///
    /// The caller preserves its primary failure separately and supplies Cleanup
    /// from the same original supervisor. Uncertain closure retains the actual
    /// VM row through physical retirement; this method cannot certify retirement.
    ///
    /// # Errors
    /// Returns the original QMP error for unavailable channel support, reused
    /// custody, refused Cleanup, dispatch failure or uncertain transport.
    #[cfg(feature = "kernel-swap-measurement")]
    pub fn close_kernel_swap_cancellation(
        &mut self,
        cancellation: &mut crate::qmp::QmpKernelSwapCancellation,
        cleanup: &crucible_linux_resource::host_supervision::HostOperationGuard,
    ) -> Result<crate::qmp::QmpCommandComplete, crate::qmp::QmpError> {
        self.channels
            .qmp_machine_control
            .close_kernel_swap_cancellation(cancellation, cleanup)
    }

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
        resident: crucible_ram::ResourceLoan,
    ) -> Result<crate::qmp::QemuPerformanceObservation, QemuNodeError> {
        self.channels
            .qmp_machine_control
            .performance_observation(guard, resident)
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::QmpMachineControl, source)
            })
    }

    /// Reads the fixed two-page CPU writer arena under the existing original.
    ///
    /// The caller retains its prepaid reply/parser/sample loan. This closed
    /// fixture method neither accepts an address nor starts another deadline.
    ///
    /// # Errors
    /// Refuses running/unadmitted QEMU, original refusal, malformed or oversized
    /// replies, and uncertain transport.
    #[cfg(any(test, feature = "test-support"))]
    pub fn observe_cpu_write_fixture(
        &mut self,
        guard: &crucible_linux_resource::host_supervision::HostOperationGuard,
        resident: crucible_ram::ResourceLoan,
    ) -> Result<crate::qmp::QemuCpuWriteObservation, QemuNodeError> {
        self.channels
            .qmp_machine_control
            .cpu_write_observation(guard, resident)
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
