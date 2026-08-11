//! Boundary-safe staging for output-only guest console observations.
//!
//! Live QEMU can emit more console output than a Unix socket can buffer before
//! it reaches one scheduler ceiling. The host-I/O poller therefore drains the
//! socket while the quantum is in flight, while this spool withholds the bytes
//! until [`crate::QemuNode`] assigns the completed scheduler boundary.

use std::sync::{Arc, Mutex};

use thiserror::Error;

/// Maximum console output retained between scheduler observation boundaries.
///
/// The limit prevents a guest from turning one long quantum into unbounded host
/// memory growth. Exceeding it aborts the bounded node step instead of silently
/// losing observational evidence.
pub(crate) const MAX_CONSOLE_OBSERVATION_BYTES: usize = 16 * 1024 * 1024;

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
}
