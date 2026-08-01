//! Live-only registration stages backed by QEMU and the owned setup mapping.

use crate::{
    BootBarrierRelease, PluginReadySetupAck, PluginRegistrationSequence,
    PluginRegistrationSequenceError, PluginRegistrationStep, PluginSetupBootBarrierError,
    PluginSetupError, PluginTimeControlOwnership, PluginTimeControlRequestError,
    QemuRegisterWakeFdFn, QemuRequestTimeControlFn, RequiredOwnedCallbacksRegistered,
};

use std::io::Write;

impl PluginRegistrationSequence {
    /// Acquires QEMU virtual-time control as the third registration step.
    ///
    /// The request is made only after argument parsing and the control
    /// handshake have completed. A missing capability or rejected ownership
    /// poisons the sequence and prevents setup from being consumed.
    ///
    /// # Errors
    ///
    /// Returns [`PluginRegistrationSequenceError`] when the request is out of
    /// order, QEMU does not expose the request API, ownership is rejected, or
    /// registration had already failed.
    pub fn request_time_control(
        &mut self,
        request_time_control: Option<QemuRequestTimeControlFn>,
    ) -> Result<PluginTimeControlOwnership, PluginRegistrationSequenceError> {
        self.ensure_next_step(PluginRegistrationStep::RequestTimeControl)?;
        let ownership = PluginTimeControlOwnership::request(request_time_control)
            .map_err(|source| self.fail_time_control_request(source))?;
        self.record_step_unchecked(PluginRegistrationStep::RequestTimeControl)?;
        Ok(ownership)
    }

    /// Waits for the initial ceiling through the setup mapping owned by the plugin.
    ///
    /// # Errors
    ///
    /// Returns [`PluginRegistrationSequenceError`] when registration has not
    /// reached the barrier, the mapped VM slot cannot be borrowed, or the
    /// scheduler ceiling wait fails.
    pub fn wait_mapped_boot_barrier(
        &mut self,
        setup_ack: PluginReadySetupAck,
        owned_callbacks: &mut RequiredOwnedCallbacksRegistered,
        slot_index: u32,
    ) -> Result<BootBarrierRelease, PluginRegistrationSequenceError> {
        self.ensure_next_step(PluginRegistrationStep::WaitBootBarrier)?;
        let release = owned_callbacks
            .wait_boot_barrier(setup_ack, slot_index)
            .map_err(|source| self.fail_mapped_boot_barrier(source))?;
        self.record_step_unchecked(PluginRegistrationStep::WaitBootBarrier)?;
        Ok(release)
    }

    /// Registers the armed wake fd after the complete callback proof exists.
    ///
    /// # Errors
    ///
    /// Returns [`PluginRegistrationSequenceError`] unless callbacks are the
    /// last completed step, or when QEMU rejects wake-fd registration.
    pub fn register_wake_fd_after_callbacks<W>(
        &mut self,
        writer: &mut W,
        owned_callbacks: &mut RequiredOwnedCallbacksRegistered,
        register_wake_fd: QemuRegisterWakeFdFn,
    ) -> Result<(), PluginRegistrationSequenceError>
    where
        W: Write,
    {
        self.ensure_next_step(PluginRegistrationStep::SendSetupAck)?;
        owned_callbacks
            .register_wake_fd_after_callbacks(writer, register_wake_fd)
            .map_err(|source| self.fail_late_wake_registration(source))
    }

    fn fail_time_control_request(
        &mut self,
        source: PluginTimeControlRequestError,
    ) -> PluginRegistrationSequenceError {
        self.fail_step(
            PluginRegistrationStep::RequestTimeControl,
            format!("time-control ownership request failed: {source}"),
        )
    }

    fn fail_mapped_boot_barrier(
        &mut self,
        source: PluginSetupBootBarrierError,
    ) -> PluginRegistrationSequenceError {
        self.fail_step(
            PluginRegistrationStep::WaitBootBarrier,
            format!("mapped setup boot barrier failed: {source}"),
        )
    }

    fn fail_late_wake_registration(
        &mut self,
        source: PluginSetupError,
    ) -> PluginRegistrationSequenceError {
        self.fail_step(
            PluginRegistrationStep::SendSetupAck,
            format!("post-callback wake-fd registration failed: {source}"),
        )
    }
}
