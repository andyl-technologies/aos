//! Measures one exact immutable artifact through the shared bounded hash reader.
//!
//! The caller retains the actual input File and its native ancestry/metadata
//! through every expected-snapshot comparison and owed post. This owner adds
//! no descriptor or path authority. Unlike the former full-file buffer, the
//! shared reader retains one fixed 64 KiB chunk and the first native errno.

use super::{File, NetworkKernelReaderError, ObjectDigest};
use std::os::fd::AsFd as _;

use aos_linux_descriptors::positional_hash::PositionalHashFailureV2;
use aos_linux_descriptors::positional_hash::PositionalHashOriginalV2;

#[derive(Clone, Copy)]
enum First {
    HashNative,
    TailNative,
    Result,
    Closed,
}

/// Retains the prefix, trailing byte and exact original native/read refusal.
pub(crate) struct NetworkArtifactHashOriginalV4 {
    hash: PositionalHashOriginalV2,
    trailing: [u8; 1],
    trailing_read: Option<rustix::io::Result<usize>>,
    returned: Option<Result<ObjectDigest, NetworkKernelReaderError>>,
    first: Option<First>,
    closed: Option<NetworkKernelReaderError>,
}

impl NetworkArtifactHashOriginalV4 {
    pub(crate) fn new() -> Self {
        Self {
            hash: PositionalHashOriginalV2::new(),
            trailing: [0],
            trailing_read: None,
            returned: None,
            first: None,
            closed: None,
        }
    }

    /// Bounds both retained/constructor frames and the shared SHA-256 state.
    pub(crate) fn receiving_bytes_v4() -> Option<usize> {
        let hash_frames = std::mem::size_of::<PositionalHashOriginalV2>().checked_mul(2)?;
        let additional =
            PositionalHashOriginalV2::receiving_bytes_v2()?.checked_sub(hash_frames)?;
        std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(additional)
    }

    /// Measures the same admitted descriptor once, preserving all failed state.
    ///
    /// The fixed shared kernel makes no hidden EINTR retry. An interrupted
    /// prefix or trailing read becomes the actual first retained refusal.
    ///
    /// # Errors
    /// Returns a coarse marker while failure() borrows the original errno or
    /// semantic failure. Reentry replaces no existing result or buffer.
    pub(crate) fn measure_once_v4(
        &mut self,
        file: &File,
        size: u64,
    ) -> Result<ObjectDigest, NetworkKernelReaderError> {
        if self.returned.is_some() || self.closed.is_some() {
            self.closed.get_or_insert_with(marker);
            self.first.get_or_insert(First::Closed);
            return Err(marker());
        }
        self.returned = Some(self.measure(file, size));
        match self.returned.as_ref() {
            Some(Ok(digest)) => Ok(*digest),
            _ => {
                self.first.get_or_insert(First::Result);
                Err(marker())
            }
        }
    }

    fn measure(
        &mut self,
        file: &File,
        size: u64,
    ) -> Result<ObjectDigest, NetworkKernelReaderError> {
        // Preserve the old address-space predicate before the first read.
        let _ = usize::try_from(size).map_err(|_| {
            NetworkKernelReaderError::InvalidArtifact("artifact size exceeds address space")
        })?;
        let digest = match self.hash.hash_once_v2(file.as_fd(), size, |_| {}) {
            Ok(digest) => digest,
            Err(_) => {
                if self.hash.native_errno_v2().is_some() {
                    self.first = Some(First::HashNative);
                }
                return Err(project_hash_failure(&self.hash));
            }
        };
        self.trailing_read = Some(rustix::io::pread(file.as_fd(), &mut self.trailing, size));
        match self.trailing_read.as_ref() {
            Some(Ok(0)) => Ok(ObjectDigest::from_bytes(digest)),
            Some(Ok(_)) => Err(NetworkKernelReaderError::InvalidArtifact(
                "artifact read was not exact",
            )),
            Some(Err(errno)) => {
                self.first = Some(First::TailNative);
                Err(NetworkKernelReaderError::Io(
                    std::io::Error::from_raw_os_error(errno.raw_os_error()),
                ))
            }
            None => std::process::abort(),
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            First::HashNative => self.hash.failure().map(|cause| cause as _),
            First::TailNative => self
                .trailing_read
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Result => self
                .returned
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Closed => self.closed.as_ref().map(|cause| cause as _),
        }
    }

    // Ordinary immediate facades move the original projection; retained
    // callers keep it and borrow the exact native source through failure().
    pub(super) fn take_returned_error_v4(&mut self) -> Option<NetworkKernelReaderError> {
        self.returned.take()?.err()
    }

    pub(crate) fn native_errno_v4(&self) -> Option<rustix::io::Errno> {
        match self.first? {
            First::HashNative => self.hash.native_errno_v2(),
            First::TailNative => self.trailing_read.as_ref()?.as_ref().err().copied(),
            _ => None,
        }
    }
}

fn project_hash_failure(original: &PositionalHashOriginalV2) -> NetworkKernelReaderError {
    match original.failure() {
        Some(PositionalHashFailureV2::Read(errno)) => {
            NetworkKernelReaderError::Io(std::io::Error::from_raw_os_error(errno.raw_os_error()))
        }
        Some(PositionalHashFailureV2::EarlyEnd) => {
            NetworkKernelReaderError::InvalidArtifact("artifact became shorter while measured")
        }
        Some(PositionalHashFailureV2::Extent) | None => {
            NetworkKernelReaderError::InvalidArtifact("artifact read exceeded its admitted extent")
        }
    }
}

fn marker() -> NetworkKernelReaderError {
    NetworkKernelReaderError::InvalidArtifact("artifact hash original is incomplete or refused")
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_linux_descriptors::positional_hash::POSITIONAL_HASH_BUFFER_BYTES_V2;
    use sha2::{Digest as _, Sha256};
    use std::io::Write as _;

    #[test]
    fn hashes_multiple_actual_chunks_and_retains_the_positioned_eof_check() {
        let mut file = tempfile::tempfile().unwrap();
        let bytes = vec![37; POSITIONAL_HASH_BUFFER_BYTES_V2 * 2 + 17];
        file.write_all(&bytes).unwrap();
        let mut original = NetworkArtifactHashOriginalV4::new();

        let digest = original.measure_once_v4(&file, bytes.len() as u64).unwrap();

        assert_eq!(digest.as_bytes(), &<[u8; 32]>::from(Sha256::digest(&bytes)));
        assert!(matches!(original.trailing_read, Some(Ok(0))));
        assert_eq!(original.hash.confirmed_bytes_v2(), bytes.len() as u64);
        assert_eq!(
            rustix::fs::seek(&file, rustix::fs::SeekFrom::Current(0)).unwrap(),
            bytes.len() as u64
        );
        assert!(original.failure().is_none());
    }

    #[test]
    fn short_and_long_artifacts_keep_the_real_prefix_and_trailing_byte() {
        let mut file = tempfile::tempfile().unwrap();
        let bytes = vec![53; POSITIONAL_HASH_BUFFER_BYTES_V2 + 7];
        file.write_all(&bytes).unwrap();
        let mut short = NetworkArtifactHashOriginalV4::new();
        let mut long = NetworkArtifactHashOriginalV4::new();

        assert!(
            short
                .measure_once_v4(&file, bytes.len() as u64 + 1)
                .is_err()
        );
        assert_eq!(short.hash.confirmed_bytes_v2(), bytes.len() as u64);
        assert!(short.trailing_read.is_none());
        assert!(matches!(
            short.hash.failure(),
            Some(PositionalHashFailureV2::EarlyEnd)
        ));
        assert!(long.measure_once_v4(&file, bytes.len() as u64 - 1).is_err());
        assert!(matches!(long.trailing_read, Some(Ok(1))));
        assert_eq!(long.trailing, [53]);
        assert!(matches!(
            long.returned,
            Some(Err(NetworkKernelReaderError::InvalidArtifact(
                "artifact read was not exact"
            )))
        ));
    }

    #[test]
    fn actual_pread_failure_stays_first_across_refused_reentry() {
        let path = rustix::fs::open(
            "/dev/null",
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let file = File::from(path);
        let identity = rustix::fs::fstat(file.as_fd()).unwrap();
        let mut original = NetworkArtifactHashOriginalV4::new();

        assert!(original.measure_once_v4(&file, 1).is_err());
        assert_eq!(original.native_errno_v4(), Some(rustix::io::Errno::BADF));
        let first = original.hash.failure().unwrap() as *const PositionalHashFailureV2;
        assert!(original.measure_once_v4(&file, 0).is_err());
        assert_eq!(
            first,
            original.hash.failure().unwrap() as *const PositionalHashFailureV2
        );
        let retained = rustix::fs::fstat(file.as_fd()).unwrap();
        assert_eq!(
            (identity.st_dev, identity.st_ino),
            (retained.st_dev, retained.st_ino)
        );
        assert!(original.trailing_read.is_none());
    }
}
