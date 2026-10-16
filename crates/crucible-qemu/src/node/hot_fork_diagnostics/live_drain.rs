//! Bounded live drainage by the exact retained child diagnostics consumer.
//!
//! One turn reads at most eight 8192-byte chunks without blocking, bounding the
//! work per execution quantum rather than the stream length. A failed live read
//! remains sticky: teardown cannot attest a complete capture after bytes might
//! have been lost. Ordinary full teardown drainage is unchanged.

use super::*;

const MAXIMUM_READ_ATTEMPTS: usize = 8;
const READ_BYTES: usize = 8192;
const MAXIMUM_ERROR_CHARS: usize = 256;

impl QemuHotForkChildDiagnosticConsumer {
    /// Drains at most 64 KiB in eight nonblocking reads during execution.
    ///
    /// Every byte joins the same counted, folded, tail-bounded retention as a
    /// full drain. The first live-drain failure is retained, prevents later
    /// reads, and refuses complete capture during ordered release, so no retry
    /// can hide a byte that a failed read may have consumed.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] after stream failure, a prior
    /// live-drain failure, or ordered capture consumption.
    pub fn drain_available_bounded(
        &mut self,
    ) -> Result<QemuHotForkChildDiagnosticDrain, QemuNodeChannelError> {
        if self.captured {
            return Err(QemuNodeChannelError::new(
                "drain live hot-fork child diagnostics",
                "diagnostic capture was already consumed",
            ));
        }
        if let Some(error) = &self.live_drain_error {
            return Err(QemuNodeChannelError::new(
                "drain live hot-fork child diagnostics",
                error.clone(),
            ));
        }

        match self.drain_bounded_inner() {
            Ok(drain) => Ok(drain),
            Err(source) => {
                let message = source
                    .to_string()
                    .chars()
                    .take(MAXIMUM_ERROR_CHARS)
                    .map(|character| {
                        if character == ' ' || character.is_ascii_graphic() {
                            character
                        } else {
                            '?'
                        }
                    })
                    .collect::<String>();
                self.live_drain_error = Some(message.clone());
                Err(QemuNodeChannelError::new(
                    "drain live hot-fork child diagnostics",
                    message,
                ))
            }
        }
    }

    /// Returns the first bounded live-drain failure without touching the stream.
    #[must_use]
    pub fn live_drain_error(&self) -> Option<&str> {
        self.live_drain_error.as_deref()
    }

    fn drain_bounded_inner(
        &mut self,
    ) -> Result<QemuHotForkChildDiagnosticDrain, QemuHotForkChildDiagnosticConsumeError> {
        let mut bytes_read = 0_usize;
        let mut buffer = [0_u8; READ_BYTES];
        for _ in 0..MAXIMUM_READ_ATTEMPTS {
            if self.eof {
                break;
            }
            match self.host.read(&mut buffer) {
                Ok(0) => self.eof = true,
                Ok(count) => {
                    self.retention.ingest(&buffer[..count]);
                    bytes_read = bytes_read.saturating_add(count);
                }
                Err(source) if source.kind() == io::ErrorKind::WouldBlock => break,
                // Interrupted is an original read failure, not an unbounded retry.
                Err(source) => {
                    return Err(QemuHotForkChildDiagnosticConsumeError::Read { source });
                }
            }
        }
        Ok(self.drain_result(bytes_read))
    }
}

#[cfg(test)]
#[path = "live_drain/tests.rs"]
mod tests;
