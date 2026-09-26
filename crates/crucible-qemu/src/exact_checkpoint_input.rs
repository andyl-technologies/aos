//! Immutable descriptor materialization for exact checkpoint restore.
//!
//! QEMU accepts restore inputs from sealed Linux memfds. This module owns the
//! linear writer that fills one memfd to its authenticated length and applies
//! the complete shrink, grow, write, and seal lock before QMP receives it.

use std::fs::File;
use std::io::{self, Seek, SeekFrom, Write};

use rustix::fs::{MemfdFlags, SealFlags, fcntl_add_seals, fcntl_get_seals, memfd_create};

fn complete_input_seals() -> SealFlags {
    SealFlags::SEAL | SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE
}

/// Linear writer for one exact-length immutable QEMU restore input.
#[derive(Debug)]
#[must_use = "finish and retain the sealed exact checkpoint input"]
pub(crate) struct QemuExactCheckpointInputMaterialization {
    file: File,
    expected_bytes: u64,
    written_bytes: u64,
}

impl QemuExactCheckpointInputMaterialization {
    /// Creates an empty sealable memfd for one exact restore input.
    ///
    /// The caller supplies the authenticated artifact length. The writer
    /// enforces that length independently of the source representation.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] when `expected_bytes` is zero or Linux cannot
    /// create the sealable memfd.
    pub(crate) fn new(expected_bytes: u64) -> Result<Self, io::Error> {
        if expected_bytes == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "exact checkpoint input has zero bytes",
            ));
        }
        let file = File::from(memfd_create(
            "crucible-exact-checkpoint-input",
            MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
        )?);
        Ok(Self {
            file,
            expected_bytes,
            written_bytes: 0,
        })
    }

    /// Finishes the exact-length input and permanently seals its bytes.
    ///
    /// The returned descriptor is rewound to offset zero and carries
    /// `F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE`, matching
    /// QEMU's restore admission contract.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] when the stream is short, flushing or rewinding
    /// fails, or Linux does not install the complete immutable seal set.
    pub(crate) fn finish(mut self) -> Result<File, io::Error> {
        if self.written_bytes != self.expected_bytes {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "exact checkpoint input wrote {} of {} bytes",
                    self.written_bytes, self.expected_bytes
                ),
            ));
        }
        self.file.flush()?;
        let required_seals = complete_input_seals();
        fcntl_add_seals(&self.file, required_seals)?;
        let installed = fcntl_get_seals(&self.file)?;
        if !installed.contains(required_seals) {
            return Err(io::Error::other(
                "exact checkpoint input lacks the complete immutable seal set",
            ));
        }
        self.file.seek(SeekFrom::Start(0))?;
        Ok(self.file)
    }
}

impl Write for QemuExactCheckpointInputMaterialization {
    fn write(&mut self, buffer: &[u8]) -> Result<usize, io::Error> {
        let remaining = self.expected_bytes.saturating_sub(self.written_bytes);
        if u64::try_from(buffer.len()).map_or(true, |bytes| bytes > remaining) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "exact checkpoint input exceeds its authenticated length",
            ));
        }
        let written = self.file.write(buffer)?;
        self.written_bytes = self
            .written_bytes
            .checked_add(written as u64)
            .ok_or_else(|| io::Error::other("exact checkpoint input byte count overflowed"))?;
        Ok(written)
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        self.file.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finished_input_has_complete_immutable_seals() -> Result<(), Box<dyn std::error::Error>> {
        let mut input = QemuExactCheckpointInputMaterialization::new(4)?;
        input.write_all(b"aos!")?;

        let mut file = input.finish()?;

        assert!(fcntl_get_seals(&file)?.contains(complete_input_seals()));
        assert_eq!(file.stream_position()?, 0);
        assert!(file.set_len(0).is_err());
        assert!(file.write_all(b"x").is_err());
        Ok(())
    }

    #[test]
    fn input_rejects_a_short_finished_stream() -> Result<(), Box<dyn std::error::Error>> {
        let mut input = QemuExactCheckpointInputMaterialization::new(4)?;
        input.write_all(b"aos")?;

        let error = match input.finish() {
            Ok(_) => panic!("short input must not be sealed"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        Ok(())
    }

    #[test]
    fn input_rejects_bytes_beyond_authenticated_length() -> Result<(), Box<dyn std::error::Error>> {
        let mut input = QemuExactCheckpointInputMaterialization::new(3)?;

        let error = match input.write_all(b"four") {
            Ok(()) => panic!("oversized input must fail before writing"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        Ok(())
    }
}
