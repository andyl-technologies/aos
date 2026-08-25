//! Bounded file I/O for durable checkpoint objects.

use std::fs::File;
use std::io::Read as _;
use std::path::Path;
use thiserror::Error;

use crate::LifecycleApiError;

/// Maximum regular-file work between attempt operational-boundary checks.
pub(super) const MAX_BOUNDED_READ_CHUNK_BYTES: usize = 1024 * 1024;

/// Failure while reading one pre-admitted checkpoint file.
#[derive(Debug, Error)]
pub(super) enum BoundedReadError {
    /// File metadata or contents could not be read exactly.
    #[error("checkpoint file I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// The file exceeded its role-specific read ceiling.
    #[error("checkpoint file length {length} exceeds read limit {limit}")]
    Limit {
        /// Observed file length.
        length: u64,
        /// Role-specific maximum.
        limit: u64,
    },
    /// The file length cannot be represented by the host collection type.
    #[error("checkpoint file length {length} is not representable")]
    Representation {
        /// Observed file length.
        length: u64,
    },
    /// Exact owned storage could not be reserved.
    #[error("checkpoint file allocation of {requested} bytes failed")]
    Allocation {
        /// Refused reservation size.
        requested: u64,
    },
    /// An attempt operational boundary stopped the admitted read.
    #[error(transparent)]
    Boundary(#[from] Box<LifecycleApiError>),
}

/// Reads an exact file whose resource ownership was admitted by the caller.
///
/// # Errors
///
/// Returns [`BoundedReadError`] for file I/O, role-limit, representation, or
/// allocation failures, and when the file grows during the read.
#[cfg(test)]
pub(super) fn read_bounded_file(path: &Path, limit: u64) -> Result<Vec<u8>, BoundedReadError> {
    read_bounded_file_with_boundary(path, limit, &mut || Ok(()))
}

/// Reads an exact admitted file while observing an operational boundary.
///
/// The callback runs before path access, after metadata and allocation, before
/// every at-most-one-MiB regular-file read, and after EOF authentication. This
/// keeps cancellation latency proportional to one bounded local read rather
/// than the complete role limit.
///
/// # Errors
///
/// Returns [`BoundedReadError`] for the same conditions as
/// [`read_bounded_file`], or [`BoundedReadError::Boundary`] when `boundary`
/// stops the operation.
pub(super) fn read_bounded_file_with_boundary(
    path: &Path,
    limit: u64,
    boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
) -> Result<Vec<u8>, BoundedReadError> {
    boundary().map_err(|error| BoundedReadError::Boundary(Box::new(error)))?;
    let mut file = File::open(path)?;
    let length = file.metadata()?.len();
    boundary().map_err(|error| BoundedReadError::Boundary(Box::new(error)))?;
    if length > limit {
        return Err(BoundedReadError::Limit { length, limit });
    }
    let requested = length;
    let length =
        usize::try_from(length).map_err(|_| BoundedReadError::Representation { length })?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| BoundedReadError::Allocation { requested })?;
    bytes.resize(length, 0);
    boundary().map_err(|error| BoundedReadError::Boundary(Box::new(error)))?;
    for chunk in bytes.chunks_mut(MAX_BOUNDED_READ_CHUNK_BYTES) {
        boundary().map_err(|error| BoundedReadError::Boundary(Box::new(error)))?;
        file.read_exact(chunk)?;
    }
    let mut trailing = [0_u8; 1];
    boundary().map_err(|error| BoundedReadError::Boundary(Box::new(error)))?;
    if file.read(&mut trailing)? != 0 {
        return Err(BoundedReadError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "checkpoint file changed while it was read",
        )));
    }
    boundary().map_err(|error| BoundedReadError::Boundary(Box::new(error)))?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::fs;

    use super::*;

    #[test]
    fn bounded_file_read_accepts_exact_limit_and_rejects_larger_input() {
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| panic!("create bounded-read directory: {error}"));
        let path = directory.path().join("checkpoint");
        fs::write(&path, b"12345678")
            .unwrap_or_else(|error| panic!("write bounded-read fixture: {error}"));

        assert_eq!(
            read_bounded_file(&path, 8)
                .unwrap_or_else(|error| panic!("read exact-limit checkpoint: {error}")),
            b"12345678"
        );
        let error = match read_bounded_file(&path, 7) {
            Ok(_) => panic!("over-limit checkpoint should be rejected"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            BoundedReadError::Limit {
                length: 8,
                limit: 7
            }
        ));
    }

    #[test]
    fn bounded_file_read_observes_boundary_between_bounded_chunks() {
        use crucible::SchedulerOperationalFailureClass;

        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| panic!("create bounded-read directory: {error}"));
        let path = directory.path().join("checkpoint");
        let length = MAX_BOUNDED_READ_CHUNK_BYTES * 3;
        fs::write(&path, vec![0x5a; length])
            .unwrap_or_else(|error| panic!("write bounded-read fixture: {error}"));

        let mut checks = 0_u8;
        let error = read_bounded_file_with_boundary(
            &path,
            u64::try_from(length).unwrap_or(u64::MAX),
            &mut || {
                checks = checks.saturating_add(1);
                if checks == 6 {
                    return Err(LifecycleApiError::AttemptOperational {
                        class: SchedulerOperationalFailureClass::Canceled,
                        message: String::from("checkpoint read canceled"),
                    });
                }
                Ok(())
            },
        )
        .expect_err("boundary must stop a multi-chunk read");

        assert!(matches!(
            error,
            BoundedReadError::Boundary(error)
                if matches!(
                    *error,
                    LifecycleApiError::AttemptOperational {
                        class: SchedulerOperationalFailureClass::Canceled,
                        ..
                    }
                )
        ));
        assert_eq!(checks, 6);
    }
}
