//! Fallible, byte-capped private staging for compiler-generated Cache indexes.

use std::io::{self, Seek, SeekFrom, Write};

pub(super) struct CacheIndexBuffer {
    bytes: Vec<u8>,
    position: u64,
    maximum_bytes: u64,
    maximum_capacity: u64,
}

impl CacheIndexBuffer {
    pub(super) fn new(maximum_bytes: u64) -> Option<Self> {
        // Geometric Vec growth stays within this independently preflighted cap.
        Some(Self {
            bytes: Vec::new(),
            position: 0,
            maximum_bytes,
            maximum_capacity: maximum_bytes.checked_mul(2)?,
        })
    }

    pub(super) fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    fn invalid_position() -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "cache index position exceeds its byte limit",
        )
    }

    fn allocation_refused() -> io::Error {
        io::Error::new(
            io::ErrorKind::OutOfMemory,
            "cache index staging allocation was refused",
        )
    }
}

impl Write for CacheIndexBuffer {
    fn write(&mut self, source: &[u8]) -> io::Result<usize> {
        let added = u64::try_from(source.len()).map_err(|_| Self::invalid_position())?;
        let end = self
            .position
            .checked_add(added)
            .ok_or_else(Self::invalid_position)?;
        if end > self.maximum_bytes {
            return Err(Self::invalid_position());
        }
        let start = usize::try_from(self.position).map_err(|_| Self::invalid_position())?;
        let end = usize::try_from(end).map_err(|_| Self::invalid_position())?;
        if end > self.bytes.len() {
            self.bytes
                .try_reserve(end - self.bytes.len())
                .map_err(|_| Self::allocation_refused())?;
            if u64::try_from(self.bytes.capacity()).map_err(|_| Self::allocation_refused())?
                > self.maximum_capacity
            {
                return Err(Self::allocation_refused());
            }
            self.bytes.resize(end, 0);
        }

        self.bytes[start..end].copy_from_slice(source);
        self.position = u64::try_from(end).map_err(|_| Self::invalid_position())?;
        Ok(source.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Seek for CacheIndexBuffer {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let absolute = match from {
            SeekFrom::Start(position) => i128::from(position),
            SeekFrom::Current(delta) => i128::from(self.position) + i128::from(delta),
            SeekFrom::End(delta) => {
                i128::try_from(self.bytes.len()).map_err(|_| Self::invalid_position())?
                    + i128::from(delta)
            }
        };
        let position = u64::try_from(absolute).map_err(|_| Self::invalid_position())?;
        if position > self.maximum_bytes {
            return Err(Self::invalid_position());
        }
        self.position = position;
        Ok(position)
    }
}
