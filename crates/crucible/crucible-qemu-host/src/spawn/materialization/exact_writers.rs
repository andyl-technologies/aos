//! Linear writers for an atomic exact-checkpoint materialization.

use super::*;

impl Write for AtomicExactDeviceStateWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let remaining = self.expected_bytes.saturating_sub(self.written_bytes);
        let requested = u64::try_from(bytes.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "exact device-state write length cannot be represented",
            )
        })?;
        if requested > remaining {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "exact device-state write exceeds the declared checkpoint length",
            ));
        }
        let written = self.destination.write(bytes)?;
        self.verifier.update(&bytes[..written]);
        self.written_bytes = self
            .written_bytes
            .checked_add(u64::try_from(written).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "exact device-state write count cannot be represented",
                )
            })?)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "exact device-state write overflow",
                )
            })?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.destination.flush()
    }
}

impl Write for AtomicExactRootOverlayWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let remaining = self.expected_bytes.saturating_sub(self.written_bytes);
        let requested = u64::try_from(bytes.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "exact root-overlay write length cannot be represented",
            )
        })?;
        if requested > remaining {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "exact root-overlay write exceeds the declared checkpoint length",
            ));
        }
        let written = self.destination.write(bytes)?;
        self.verifier.update(&bytes[..written]).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("exact root-overlay identity authentication failed: {error}"),
            )
        })?;
        self.written_bytes = self
            .written_bytes
            .checked_add(u64::try_from(written).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "exact root-overlay write count cannot be represented",
                )
            })?)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "exact root-overlay write overflow",
                )
            })?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.destination.flush()
    }
}

impl AtomicExactDeviceStateWriter<'_> {
    /// Authenticates and seals the complete materialized device state.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSpawnError`] if the caller wrote fewer than the declared
    /// bytes or sealing fails. Failure leaves the run-directory authority
    /// unlaunchable until a new materialization succeeds.
    pub(super) fn finish(self) -> Result<(), QemuSpawnError> {
        if self.written_bytes != self.expected_bytes {
            return Err(QemuSpawnError::PreparedExactInputIncomplete {
                expected: self.expected_bytes,
                actual: self.written_bytes,
            });
        }
        self.verifier.finish()?;
        let input = self
            .destination
            .finish()
            .map_err(|source| QemuSpawnError::Io {
                operation: "seal exact device-state input",
                source,
            })?;
        self.prepared.exact_device_state = Some(input);
        self.prepared.exact_device_state_materialization =
            PreparedDeviceStateMaterialization::Exact {
                binding: self.binding,
                bytes: self.expected_bytes,
            };
        Ok(())
    }
}

impl AtomicExactRootOverlayWriter<'_> {
    /// Authenticates and durably commits the complete root overlay.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSpawnError`] if the caller wrote a different length,
    /// synchronization fails, or the retained inode changes. Failure leaves the
    /// prepared directory unlaunchable.
    pub(super) fn finish(mut self) -> Result<(), QemuSpawnError> {
        if self.written_bytes != self.expected_bytes {
            return Err(QemuSpawnError::PreparedRootOverlayIncomplete {
                expected: self.expected_bytes,
                actual: self.written_bytes,
            });
        }
        self.verifier.finish().map_err(|_| {
            super::super::invalid_input(
                "authenticate exact root-overlay materialization",
                "materialized bytes differ from the repository-bound sparse overlay",
            )
        })?;
        self.destination
            .flush()
            .map_err(|source| QemuSpawnError::Io {
                operation: "flush materialized exact root overlay",
                source,
            })?;
        self.destination
            .sync_all()
            .map_err(|source| QemuSpawnError::Io {
                operation: "synchronize materialized exact root overlay",
                source,
            })?;
        fsync(&self.prepared.directory).map_err(|source| QemuSpawnError::Io {
            operation: "synchronize materialized exact root-overlay directory",
            source: source.into(),
        })?;
        let metadata = self.prepared.revalidate_root_overlay_identity()?;
        let actual = u64::try_from(metadata.st_size).map_err(|_| {
            QemuSpawnError::PreparedRootOverlayIncomplete {
                expected: self.expected_bytes,
                actual: u64::MAX,
            }
        })?;
        if actual != self.expected_bytes {
            return Err(QemuSpawnError::PreparedRootOverlayIncomplete {
                expected: self.expected_bytes,
                actual,
            });
        }
        self.prepared.root_overlay_materialization = PreparedRootOverlayMaterialization::Exact {
            binding: self.binding,
            bytes: self.expected_bytes,
        };
        Ok(())
    }
}
