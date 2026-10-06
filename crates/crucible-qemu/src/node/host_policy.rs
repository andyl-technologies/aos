//! Host-only attachment of independent node budgets to existing live transports.

use super::*;

impl QemuNode {
    pub(super) fn finish_host_ram_cleanup(&mut self) -> Result<(), QemuNodeError> {
        #[cfg(target_os = "linux")]
        if let Some(ram) = &mut self.hot_fork_ram_continuation {
            ram.finish().map_err(|source| QemuNodeError::Channel {
                plane: QemuNodeChannelPlane::PluginIpcControl,
                operation: "join hot-fork RAM source",
                message: source.to_string(),
            })?;
        }
        #[cfg(target_os = "linux")]
        if let QemuNodeProcessControl::Direct(child) = &mut self.child
            && let Some(source) = child.ram_source.take()
            && let Err(error) = source.stop()
        {
            child.ram_source = Some(error.service);
            return Err(QemuNodeError::Channel {
                plane: QemuNodeChannelPlane::PluginIpcControl,
                operation: "join retained RAM source",
                message: error.source.to_string(),
            });
        }
        self.host_io_runtime
            .retire_host_ram_after_cleanup()
            .map_err(|error| QemuNodeError::Channel {
                plane: QemuNodeChannelPlane::PluginIpcControl,
                operation: "retire host RAM resources",
                message: error.to_string(),
            })
    }

    /// Attaches one operational owner before a reconstructed node is released.
    ///
    /// Both QMP and host I/O retain the same owner; no guest or modeled state is
    /// changed. Native paging admission remains a separate readiness obligation.
    ///
    /// # Errors
    /// Returns a channel error if either existing live transport cannot retain
    /// the independently admitted operational supervision owner.
    pub fn attach_host_operation_supervisor(
        &mut self,
        supervisor: crucible_linux_resource::host_supervision::HostOperationSupervisor,
    ) -> Result<(), QemuNodeChannelError> {
        self.channels
            .qmp_machine_control
            .set_host_operation_supervisor(supervisor.clone())?;
        self.host_io_runtime
            .set_host_operation_supervisor(supervisor)
            .map_err(|source| {
                QemuNodeChannelError::new("attach host operation supervisor", source.to_string())
            })
    }
}
