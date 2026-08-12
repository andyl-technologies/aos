//! Boundary-safe staging for output-only guest console observations.
//!
//! Live QEMU can emit more console output than a Unix socket can buffer before
//! it reaches one scheduler ceiling. The host-I/O poller therefore drains the
//! socket while the quantum is in flight, while this spool withholds the bytes
//! until [`crate::QemuNode`] assigns the completed scheduler boundary.

use std::io::Read;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};

use thiserror::Error;

use crate::QemuAsyncDriverRuntimeError;

/// Maximum console output retained between scheduler observation boundaries.
///
/// The limit prevents a guest from turning one long quantum into unbounded host
/// memory growth. Exceeding it aborts the bounded node step instead of silently
/// losing observational evidence.
pub(crate) const MAX_CONSOLE_OBSERVATION_BYTES: usize = 16 * 1024 * 1024;

/// Owns the output-only console descriptor drained between scheduler polls.
pub(crate) struct QemuConsoleObservationReader {
    output: UnixStream,
    spool: QemuConsoleObservationSpool,
}

impl QemuConsoleObservationReader {
    /// Configures an output-only console stream for non-blocking observation.
    pub(crate) fn new(
        output: UnixStream,
        spool: QemuConsoleObservationSpool,
    ) -> Result<Self, std::io::Error> {
        output.set_nonblocking(true)?;
        Ok(Self { output, spool })
    }

    /// Drains currently available bytes without assigning scheduler time.
    pub(crate) fn drain_available(&mut self) -> Result<(), QemuAsyncDriverRuntimeError> {
        let mut buffer = [0_u8; 8192];
        loop {
            match self.output.read(&mut buffer) {
                Ok(0) => return Ok(()),
                Ok(count) => self.spool.append(&buffer[..count]).map_err(|source| {
                    QemuAsyncDriverRuntimeError::new(
                        "stage QEMU console output",
                        source.to_string(),
                    )
                })?,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) => {
                    return Err(QemuAsyncDriverRuntimeError::new(
                        "read QEMU console output",
                        error.to_string(),
                    ));
                }
            }
        }
    }
}

/// Shared console bytes staged by host-I/O polling for the next boundary.
#[derive(Clone, Default)]
pub(crate) struct QemuConsoleObservationSpool {
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl QemuConsoleObservationSpool {
    /// Creates an empty boundary staging spool.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Appends one socket-read batch without exceeding the retention limit.
    pub(crate) fn append(&self, batch: &[u8]) -> Result<(), QemuConsoleObservationSpoolError> {
        let mut bytes = self
            .bytes
            .lock()
            .map_err(|_poisoned| QemuConsoleObservationSpoolError::Poisoned)?;
        let retained = bytes.len();
        let attempted = retained.checked_add(batch.len()).ok_or(
            QemuConsoleObservationSpoolError::Capacity {
                attempted: usize::MAX,
                limit: MAX_CONSOLE_OBSERVATION_BYTES,
            },
        )?;
        if attempted > MAX_CONSOLE_OBSERVATION_BYTES {
            return Err(QemuConsoleObservationSpoolError::Capacity {
                attempted,
                limit: MAX_CONSOLE_OBSERVATION_BYTES,
            });
        }
        bytes.extend_from_slice(batch);
        Ok(())
    }

    /// Takes every byte staged for the completed boundary.
    pub(crate) fn take(&self) -> Result<Vec<u8>, QemuConsoleObservationSpoolError> {
        let mut bytes = self
            .bytes
            .lock()
            .map_err(|_poisoned| QemuConsoleObservationSpoolError::Poisoned)?;
        Ok(std::mem::take(&mut *bytes))
    }
}

/// Failure while staging console evidence for a scheduler boundary.
#[derive(Debug, Error)]
pub(crate) enum QemuConsoleObservationSpoolError {
    /// The staged output exceeded the deterministic per-boundary limit.
    #[error(
        "console output reached {attempted} bytes before one scheduler boundary; limit is {limit}"
    )]
    Capacity {
        /// Bytes that retaining the complete batch would require.
        attempted: usize,
        /// Maximum bytes retained per scheduler boundary.
        limit: usize,
    },
    /// A panic poisoned the shared staging buffer.
    #[error("console observation staging buffer is poisoned")]
    Poisoned,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn spool_preserves_order_and_clears_at_boundary() -> Result<(), Box<dyn std::error::Error>> {
        let spool = QemuConsoleObservationSpool::new();
        spool.append(b"first")?;
        spool.append(b" second")?;

        assert_eq!(spool.take()?, b"first second");
        assert!(spool.take()?.is_empty());
        Ok(())
    }

    #[test]
    fn spool_fails_before_discarding_retained_evidence() -> Result<(), Box<dyn std::error::Error>> {
        let spool = QemuConsoleObservationSpool::new();
        let retained = vec![0x5a; MAX_CONSOLE_OBSERVATION_BYTES];
        spool.append(&retained)?;

        assert!(matches!(
            spool.append(&[0x00]),
            Err(QemuConsoleObservationSpoolError::Capacity { .. })
        ));
        assert_eq!(spool.take()?, retained);
        Ok(())
    }

    #[test]
    fn reader_releases_backpressure_and_preserves_bytes() -> Result<(), Box<dyn std::error::Error>>
    {
        let (mut writer, output) = UnixStream::pair()?;
        writer.set_nonblocking(true)?;
        let payload = (0..(1024 * 1024))
            .map(|index| u8::try_from(index % 251))
            .collect::<Result<Vec<_>, _>>()?;
        let spool = QemuConsoleObservationSpool::new();
        let mut reader = QemuConsoleObservationReader::new(output, spool.clone())?;
        let mut written = 0;
        let mut observed_backpressure = false;

        while written < payload.len() {
            match writer.write(&payload[written..]) {
                Ok(0) => {
                    return Err(std::io::Error::other(
                        "console writer made no progress without WouldBlock",
                    )
                    .into());
                }
                Ok(count) => written += count,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    observed_backpressure = true;
                    reader.drain_available()?;
                }
                Err(error) => return Err(error.into()),
            }
        }
        reader.drain_available()?;

        assert!(observed_backpressure);
        assert_eq!(spool.take()?, payload);
        Ok(())
    }
}
