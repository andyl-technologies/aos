//! Lifecycle-aware plugin control channel adapters.

use std::io::Write;

use crucible_protocol::ControlLifecycleStream;

use crate::{QemuNodeChannelError, QemuPluginIpcControlChannel};

impl<S> QemuPluginIpcControlChannel for ControlLifecycleStream<S>
where
    S: Write,
{
    fn send_quit(&mut self) -> Result<(), QemuNodeChannelError> {
        self.host_send_quit().map_err(|source| {
            QemuNodeChannelError::new("send plugin control Quit", source.to_string())
        })
    }
}
