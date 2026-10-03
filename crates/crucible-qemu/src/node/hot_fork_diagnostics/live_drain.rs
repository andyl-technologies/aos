//! Bounded live drainage by the exact retained child diagnostics consumer.
//!
//! One turn reads at most eight 8192-byte chunks without blocking. A failed
//! live read remains sticky: teardown cannot attest a complete capture after
//! bytes might have been lost. Ordinary full teardown drainage is unchanged.

use super::*;

const MAXIMUM_READ_ATTEMPTS: usize = 8;
const READ_BYTES: usize = 8192;
const MAXIMUM_ERROR_CHARS: usize = 256;

impl QemuHotForkChildDiagnosticConsumer {
    /// Retains at most 64 KiB in eight nonblocking reads during execution.
    ///
    /// Every byte remains in this consumer's original 16 MiB cumulative
    /// capture. The first live-drain failure is retained, prevents later reads,
    /// and refuses complete capture during ordered release. No retry can hide
    /// a consumed byte that exceeded the capture limit.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] after stream failure, cumulative capture
    /// exhaustion, a prior live-drain failure, or ordered capture consumption.
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
        let before = self.retained.len();
        let mut buffer = [0_u8; READ_BYTES];
        for _ in 0..MAXIMUM_READ_ATTEMPTS {
            if self.eof {
                break;
            }
            match self.host.read(&mut buffer) {
                Ok(0) => self.eof = true,
                Ok(count) => {
                    let attempted = self.retained.len().checked_add(count).ok_or(
                        QemuHotForkChildDiagnosticConsumeError::Capacity {
                            attempted: usize::MAX,
                            limit: MAX_QEMU_HOT_FORK_CHILD_DIAGNOSTIC_BYTES,
                        },
                    )?;
                    if attempted > MAX_QEMU_HOT_FORK_CHILD_DIAGNOSTIC_BYTES {
                        return Err(QemuHotForkChildDiagnosticConsumeError::Capacity {
                            attempted,
                            limit: MAX_QEMU_HOT_FORK_CHILD_DIAGNOSTIC_BYTES,
                        });
                    }
                    self.retained.extend_from_slice(&buffer[..count]);
                }
                Err(source) if source.kind() == io::ErrorKind::WouldBlock => break,
                // Interrupted is an original read failure, not an unbounded retry.
                Err(source) => {
                    return Err(QemuHotForkChildDiagnosticConsumeError::Read { source });
                }
            }
        }
        Ok(QemuHotForkChildDiagnosticDrain {
            bytes_read: self.retained.len() - before,
            total_retained: self.retained.len(),
            eof: self.eof,
        })
    }
}

#[cfg(test)]
#[path = "live_drain/tests.rs"]
mod tests;
