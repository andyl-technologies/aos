//! Hashes one exact admitted descriptor prefix with a fixed positional buffer.
//!
//! This shared mechanical reader supplies no path, executable, immutability,
//! role or resource authority. Callers keep their own size and metadata checks.
//! Failed reads retain the actual native errno, last buffer and byte progress.

use std::os::fd::BorrowedFd;

use sha2::{Digest as _, Sha256};

/// Fixes the single working buffer used by the shared positional hash engine.
pub const POSITIONAL_HASH_BUFFER_BYTES_V2: usize = 64 * 1024;

/// Describes an exact prefix read's original failure, without role projection.
#[derive(Debug, thiserror::Error)]
pub enum PositionalHashFailureV2 {
    /// Preserves the native error from the actual positioned read.
    #[error("positioned hash read failed: {0}")]
    Read(#[source] rustix::io::Errno),
    /// The descriptor ended before the caller's admitted prefix was complete.
    #[error("positioned hash read ended before the admitted prefix")]
    EarlyEnd,
    /// A read count or offset did not fit the already-admitted prefix.
    #[error("positioned hash read exceeded its admitted extent")]
    Extent,
}

/// Stops a negative or repeated attempt while its actual original stays owned.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("positioned hash attempt remains closed with its original")]
pub struct PositionalHashClosedV2;

/// Owns one exact prefix hash, its fixed buffer and every reached native error.
///
/// Construction performs no IO, allocation, descriptor adoption or admission.
/// The enclosing caller prepays the representation and holds the input itself.
#[derive(Debug)]
pub struct PositionalHashOriginalV2 {
    buffer: [u8; POSITIONAL_HASH_BUFFER_BYTES_V2],
    confirmed_bytes: u64,
    failure: Option<PositionalHashFailureV2>,
    digest: Option<[u8; 32]>,
    entered: bool,
}

impl PositionalHashOriginalV2 {
    /// Creates one inert fixed-buffer destination without allocation or IO.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buffer: [0; POSITIONAL_HASH_BUFFER_BYTES_V2],
            confirmed_bytes: 0,
            failure: None,
            digest: None,
            entered: false,
        }
    }

    /// Bounds the held original and simultaneous constructor/reader bytes.
    ///
    /// The reader opens no descriptor and creates no namespace entry. The
    /// caller's actual input descriptor and metadata owners remain separate.
    #[must_use]
    pub fn receiving_bytes_v2() -> Option<usize> {
        std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(std::mem::size_of::<Sha256>())
    }

    /// Reads and hashes exactly one admitted prefix of the same descriptor.
    ///
    /// `after_chunk` is a progress observer; production role callers use a
    /// no-op. It supplies no permission or alternate reader. The callback runs
    /// after the same successful read/hash/checked-offset interval as Nspawn's
    /// original fixed-buffer reader.
    ///
    /// # Errors
    /// Refuses reentry, an actual native read error, early EOF or invalid read
    /// extent. The first native/error owner remains borrowed by [`Self::failure`].
    pub fn hash_once_v2(
        &mut self,
        descriptor: BorrowedFd<'_>,
        expected_bytes: u64,
        after_chunk: impl FnMut(u64),
    ) -> Result<[u8; 32], PositionalHashClosedV2> {
        self.hash_with(expected_bytes, |buffer, offset| {
            rustix::io::pread(descriptor, buffer, offset)
        }, after_chunk)
    }

    fn hash_with(
        &mut self,
        expected_bytes: u64,
        mut read: impl FnMut(&mut [u8], u64) -> rustix::io::Result<usize>,
        mut after_chunk: impl FnMut(u64),
    ) -> Result<[u8; 32], PositionalHashClosedV2> {
        if self.entered {
            return Err(PositionalHashClosedV2);
        }
        self.entered = true;
        let mut hash = Sha256::new();
        while self.confirmed_bytes < expected_bytes {
            let remaining = expected_bytes - self.confirmed_bytes;
            let limit = match usize::try_from(remaining) {
                Ok(remaining) => remaining.min(self.buffer.len()),
                Err(_) => return self.stop(PositionalHashFailureV2::Extent),
            };
            let count = match read(&mut self.buffer[..limit], self.confirmed_bytes) {
                Ok(0) => return self.stop(PositionalHashFailureV2::EarlyEnd),
                Ok(count) if count <= limit => count,
                Ok(_) => return self.stop(PositionalHashFailureV2::Extent),
                Err(cause) => return self.stop(PositionalHashFailureV2::Read(cause)),
            };
            hash.update(&self.buffer[..count]);
            self.confirmed_bytes = match u64::try_from(count).ok()
                .and_then(|count| self.confirmed_bytes.checked_add(count))
            {
                Some(offset) => offset,
                None => return self.stop(PositionalHashFailureV2::Extent),
            };
            after_chunk(self.confirmed_bytes);
        }
        let digest = hash.finalize().into();
        self.digest = Some(digest);
        Ok(digest)
    }

    fn stop<T>(&mut self, cause: PositionalHashFailureV2) -> Result<T, PositionalHashClosedV2> {
        self.failure = Some(cause);
        Err(PositionalHashClosedV2)
    }

    /// Borrows the exact first native/read failure without performing IO.
    #[must_use]
    pub const fn failure(&self) -> Option<&PositionalHashFailureV2> {
        self.failure.as_ref()
    }

    /// Borrows the actual native errno when the prefix stopped on a syscall.
    #[must_use]
    pub fn native_errno_v2(&self) -> Option<rustix::io::Errno> {
        match self.failure.as_ref()? {
            PositionalHashFailureV2::Read(cause) => Some(*cause),
            PositionalHashFailureV2::EarlyEnd | PositionalHashFailureV2::Extent => None,
        }
    }

    /// Reports bytes actually read and incorporated before completion/failure.
    #[must_use]
    pub const fn confirmed_bytes_v2(&self) -> u64 {
        self.confirmed_bytes
    }
}

impl Default for PositionalHashOriginalV2 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::os::fd::AsFd as _;
    use super::*;

    #[test]
    fn interrupted_chunk_is_retained_once_without_a_hidden_retry() {
        let mut original = PositionalHashOriginalV2::new();
        let mut entered = 0;
        let returned = original.hash_with(3, |buffer, _| {
            entered += 1;
            if entered == 1 {
                buffer[0] = 17;
                Ok(1)
            } else {
                // Deterministic injection into the SAME native read reducer;
                // the Network wrapper separately exercises a real EBADF read.
                Err(rustix::io::Errno::INTR)
            }
        }, |_| {});

        assert!(returned.is_err());
        assert_eq!(entered, 2);
        assert_eq!(original.confirmed_bytes_v2(), 1);
        assert_eq!(original.native_errno_v2(), Some(rustix::io::Errno::INTR));
        let first = original.failure().unwrap() as *const PositionalHashFailureV2;
        assert!(original.hash_with(3, |_, _| panic!("closed read cannot retry"), |_| {}).is_err());
        assert_eq!(first, original.failure().unwrap() as *const PositionalHashFailureV2);
    }

    #[test]
    fn hashes_actual_multiple_chunks_without_changing_the_file_position() {
        let mut file = tempfile::tempfile().unwrap();
        let bytes = vec![17; POSITIONAL_HASH_BUFFER_BYTES_V2 * 2 + 137];
        file.write_all(&bytes).unwrap();
        let mut original = PositionalHashOriginalV2::new();

        let actual = original.hash_once_v2(file.as_fd(), bytes.len() as u64, |_| {}).unwrap();

        assert_eq!(actual, <[u8; 32]>::from(Sha256::digest(&bytes)));
        assert_eq!(original.confirmed_bytes_v2(), bytes.len() as u64);
        assert!(original.failure().is_none());
        assert_eq!(rustix::fs::seek(&file, rustix::fs::SeekFrom::Current(0)).unwrap(), bytes.len() as u64);
    }

    #[test]
    fn actual_truncation_keeps_completed_prefix_and_refuses_healing() {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&vec![13; POSITIONAL_HASH_BUFFER_BYTES_V2 + 1]).unwrap();
        let mut original = PositionalHashOriginalV2::new();

        let result = original.hash_once_v2(file.as_fd(), (POSITIONAL_HASH_BUFFER_BYTES_V2 + 1) as u64,
            |_| file.set_len(POSITIONAL_HASH_BUFFER_BYTES_V2 as u64).unwrap());

        assert!(result.is_err());
        assert!(matches!(original.failure(), Some(PositionalHashFailureV2::EarlyEnd)));
        assert_eq!(original.confirmed_bytes_v2(), POSITIONAL_HASH_BUFFER_BYTES_V2 as u64);
        assert_eq!(original.buffer[0], 13);
        assert!(original.hash_once_v2(file.as_fd(), 0, |_| {}).is_err());
    }

    #[test]
    fn the_same_loop_keeps_a_midstream_native_error_and_its_exact_progress() {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&vec![29; POSITIONAL_HASH_BUFFER_BYTES_V2 + 1]).unwrap();
        let mut original = PositionalHashOriginalV2::new();

        let result = original.hash_with((POSITIONAL_HASH_BUFFER_BYTES_V2 + 1) as u64,
            |buffer, offset| if offset == 0 { rustix::io::pread(&file, buffer, offset) }
                else { Err(rustix::io::Errno::IO) }, |_| {});

        assert!(result.is_err());
        assert_eq!(original.native_errno_v2(), Some(rustix::io::Errno::IO));
        assert_eq!(original.confirmed_bytes_v2(), POSITIONAL_HASH_BUFFER_BYTES_V2 as u64);
        assert_eq!(original.buffer[0], 29);
    }
}
