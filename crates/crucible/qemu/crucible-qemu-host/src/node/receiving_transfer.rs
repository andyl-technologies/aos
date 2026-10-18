//! Live process and paused-runstate checks without changing execution state.

use super::*;
use crucible_host_resources::host_supervision::{HostOperationGuard, HostSupervisionError};

/// Preserves the initiating physical or original stopped-receiver refusal.
#[derive(Debug, thiserror::Error)]
pub enum QemuStoppedTransferError {
    /// The same Transfer original refused before or after native observation.
    #[error("stopped receiver original refused")]
    Original(#[from] HostSupervisionError),
    /// The retained RAM Source failed its real health check.
    #[error("stopped receiver RAM source refused")]
    Source(#[from] crate::ram_source::QemuRamSourceError),
    /// The child's current Linux identity could not be read.
    #[error("stopped receiver process observation failed")]
    Process(#[source] QemuNodeError),
    /// The existing QMP channel failed without changing guest execution.
    #[error("stopped receiver QMP observation failed")]
    Channel(#[source] QemuNodeChannelError),
    /// A live process, generation or paused runstate no longer matches.
    #[error("stopped receiver ownership or runstate differs")]
    Binding,
}

impl QemuNode {
    fn check_receiving_ram_source(&self) -> Result<(), QemuStoppedTransferError> {
        match &self.child {
            #[cfg(target_os = "linux")]
            QemuNodeProcessControl::Direct(child) => {
                // Receiving requires the actual retained Source, not an absent
                // service or an external process whose Source was not observed.
                if child.ram_source.is_none() {
                    return Err(QemuStoppedTransferError::Binding);
                }
                child.check_ram_source()?;
                Ok(())
            }
            _ => Err(QemuStoppedTransferError::Binding),
        }
    }

    /// Verifies the retained RAM Source, process generation and paused runstate.
    ///
    /// # Errors
    ///
    /// Returns the initiating original, Source, process or channel refusal, or
    /// a binding error when a direct Source-bearing child or its paused identity
    /// no longer matches the stopped receiver.
    pub(crate) fn verify_stopped_transfer(
        &mut self,
        expected: &crate::QemuProcessIdentity,
        original: &HostOperationGuard,
    ) -> Result<(), QemuStoppedTransferError> {
        original.verify_operation_class(
            crucible_host_resources::host_supervision::HostOperationClass::Transfer,
        )?;
        self.check_receiving_ram_source()?;
        if self.child_reaped()
            || self
                .process_identity()
                .map_err(QemuStoppedTransferError::Process)?
                != *expected
        {
            return Err(QemuStoppedTransferError::Binding);
        }
        if !self
            .channels
            .qmp_machine_control
            .is_stopped_for_transfer(original)
            .map_err(QemuStoppedTransferError::Channel)?
        {
            return Err(QemuStoppedTransferError::Binding);
        }
        self.check_receiving_ram_source()?;
        if self
            .process_identity()
            .map_err(QemuStoppedTransferError::Process)?
            != *expected
        {
            return Err(QemuStoppedTransferError::Binding);
        }
        original.wait_slice()?;
        Ok(())
    }
}
