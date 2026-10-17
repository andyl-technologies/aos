//! Retains a test observer on the actual admitted node and its sole QMP owner.

use super::*;

impl QemuNode {
    /// Observes a genuine block completion without changing native admission.
    ///
    /// # Errors
    /// Refuses an unregistered node, missing original supervisor, or replacement
    /// of an existing observer while it may retain physical borrowers.
    pub fn install_block_completion_observer_for_test(
        &mut self,
        observer: std::sync::Arc<dyn crate::QemuTestBlockCompletionObserver>,
    ) -> Result<(), QemuNodeError> {
        if self.block_completion_observer.is_some()
            || self.host_io_runtime.ram_control_registration().is_none()
            || self.host_io_runtime.host_operation_supervisor().is_none()
        {
            return Err(QemuNodeError::from_channel(
                QemuNodeChannelPlane::QmpMachineControl,
                QemuNodeChannelError::new(
                    "install block completion observer",
                    "observer requires the original live admitted node",
                ),
            ));
        }
        self.block_completion_observer = Some(observer);
        Ok(())
    }
}

pub(super) fn observe_pending_completion(
    channels: &mut QemuNodeChannels,
    observer: Option<&dyn crate::QemuTestBlockCompletionObserver>,
) -> Result<(), QemuNodeChannelError> {
    let Some(observer) = observer else {
        return Ok(());
    };
    let Some(guard) = observer.observation_guard() else {
        return Ok(());
    };
    let report = channels
        .qmp_machine_control
        .query_block_borrowers_for_test(&guard)?;
    observer.observe_native(&report)
}
