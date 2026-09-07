//! Nonzero setup acknowledgements and their failure-stage taxonomy.

use std::io::Write;

use crate::QemuRegisterWakeFdFn;

use super::{PluginSetupCompletion, PluginSetupError, WakeFdRegisterError, send_setup_failure_ack};

/// Setup stage whose failure triggered a nonzero `SetupAck`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PluginSetupFailureStage {
    /// Receiving the setup frame or descriptors failed.
    ReceiveSetup,
    /// Mapping the shared-memory region failed.
    MapRegion,
    /// Validating the mapped shared-memory header failed.
    ValidateRegion,
    /// Validating the immutable version-negotiated plugin plan failed.
    ValidatePluginSetupPlan,
    /// Cross-checking the handshake assignment against the mapped header failed.
    CrossCheckSlot,
    /// Arming the wake fd failed.
    ArmWakeFd,
    /// Registering the armed wake fd with QEMU failed.
    RegisterWakeFd,
    /// Registering the complete required callback set failed.
    RegisterCallbacks,
}

/// Sends a nonzero setup acknowledgement after callback registration fails.
///
/// # Errors
///
/// Returns [`PluginSetupError::SendFailureAck`] when the failure acknowledgement
/// cannot be written and flushed.
pub fn send_callback_registration_failure_ack<W>(writer: &mut W) -> Result<(), PluginSetupError>
where
    W: Write,
{
    send_setup_failure_ack(writer, PluginSetupFailureStage::RegisterCallbacks)
}

impl PluginSetupCompletion {
    /// Registers the locally armed wake fd only after owned callbacks are proven.
    ///
    /// # Errors
    ///
    /// Returns [`PluginSetupError::RegisterWakeFd`] when registration was
    /// already performed or QEMU rejects the descriptor. A first failure is
    /// acknowledged with a nonzero `SetupAck` before returning.
    pub(crate) fn register_wake_fd_after_callbacks<W>(
        &mut self,
        writer: &mut W,
        register_wake_fd: QemuRegisterWakeFdFn,
    ) -> Result<(), PluginSetupError>
    where
        W: Write,
    {
        if self.registered_wake_fd.is_some() {
            return Err(PluginSetupError::RegisterWakeFd {
                source: WakeFdRegisterError::AlreadyRegistered,
            });
        }
        let registered_wake_fd = match self.wake_fd.register_with_qemu(register_wake_fd) {
            Ok(registered_wake_fd) => registered_wake_fd,
            Err(source) => {
                send_setup_failure_ack(writer, PluginSetupFailureStage::RegisterWakeFd)?;
                return Err(PluginSetupError::RegisterWakeFd { source });
            }
        };
        self.registered_wake_fd = Some(registered_wake_fd);
        Ok(())
    }
}
