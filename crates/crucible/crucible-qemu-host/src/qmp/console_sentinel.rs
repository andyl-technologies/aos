//! Fixed RAM observation for the real UART causal libtest only.
//!
//! The original node retains this QMP client. The probe runs while the original
//! completed worker still owns the stopped node, before core can regrant it.
//! It neither stops the VM nor supplies any native execution/phase authority.

use crate::spawn::ConsoleSentinelOutput;

use super::{QmpClient, QmpCommand, QmpCommandKind, QmpError, QmpRunStateKind, QmpTimeoutStream};

impl<S: QmpTimeoutStream> QmpClient<S> {
    pub(crate) fn read_console_sentinel_for_test(
        &mut self,
        output: &ConsoleSentinelOutput,
    ) -> Result<u8, QmpError> {
        let before = self.query_status()?;
        if before.running || before.status != QmpRunStateKind::Paused {
            return Err(QmpError::UnexpectedRunState {
                command: QmpCommandKind::ConsoleSentinel,
                status: before.status,
                running: before.running,
            });
        }

        self.send_command(QmpCommand::ConsoleSentinel {
            filename: output.filename(),
        })?;
        let sample = output.read_byte().map_err(|error| {
            QmpError::from_io(
                "authenticate console fixture memory sample",
                std::io::Error::other(error),
            )
        })?;

        let after = self.query_status()?;
        if after != before {
            return Err(QmpError::UnexpectedRunState {
                command: QmpCommandKind::ConsoleSentinel,
                status: after.status,
                running: after.running,
            });
        }
        Ok(sample)
    }
}
