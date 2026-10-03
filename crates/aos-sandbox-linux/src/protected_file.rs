//! Shared descriptor operations for fixed protected files.
//!
//! Callers retain responsibility for root resolution, file ownership, mode,
//! size, and content policy. These operations only reject ambiguous absolute
//! paths, open one literal child without following its final symlink, and read
//! an already admitted descriptor at fixed offsets.

use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

use rustix::fs::{Mode, OFlags};
use zeroize::Zeroizing;

/// Reports whether a path is an absolute sequence of non-special components.
pub fn is_absolute_fixed_path(path: &Path) -> bool {
    let bytes = path.as_os_str().as_bytes();
    bytes.len() >= 2
        && bytes[0] == b'/'
        && bytes[1] != b'/'
        && bytes.last() != Some(&b'/')
        && !bytes.contains(&0)
        && !bytes[1..]
            .split(|byte| *byte == b'/')
            .any(|component| component.is_empty() || matches!(component, b"." | b".."))
}

/// Opens a single literal child of a caller-pinned directory without following its symlink.
///
/// # Errors
///
/// Returns `EINVAL` for a name that is not one component, or a kernel error
/// when the child cannot be opened with the fixed flags.
pub fn open_nofollow_child(directory: impl AsFd, name: &str) -> rustix::io::Result<OwnedFd> {
    if name.is_empty()
        || matches!(name, "." | "..")
        || name.as_bytes().contains(&b'/')
        || name.as_bytes().contains(&0)
    {
        return Err(rustix::io::Errno::INVAL);
    }
    rustix::fs::openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
}

/// Distinguishes an incomplete positioned read from bytes beyond the expected size.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExactReadError {
    /// The positioned read failed, ended early, or returned an invalid count.
    Read,
    /// A positioned read found bytes after the expected end.
    TrailingBytes,
}

/// Retains a positioned reader's native failure or exact-length refusal.
///
/// This error describes a DATA read only. It authenticates no descriptor,
/// content, owner, currentness or authority.
#[derive(Debug, thiserror::Error)]
pub enum ExactReadFailure {
    /// A positioned read failed with the original native error.
    #[error("positioned read failed")]
    Io(#[source] rustix::io::Errno),
    /// The read ended early, returned an invalid count or exceeded offset bounds.
    #[error("positioned read was incomplete or invalid")]
    Read,
    /// A positioned read found bytes after the expected end.
    #[error("positioned read found trailing bytes")]
    TrailingBytes,
}

impl ExactReadFailure {
    /// Reports the legacy classification, which omits the native cause.
    #[must_use]
    pub fn legacy_classification(&self) -> ExactReadError {
        match self {
            Self::Io(_) | Self::Read => ExactReadError::Read,
            Self::TrailingBytes => ExactReadError::TrailingBytes,
        }
    }
}

/// Reads exactly the output length at fixed offsets and checks for trailing bytes.
///
/// The caller owns the output buffer, allowing secret readers to fill their
/// final zeroizing allocation directly.
///
/// # Errors
///
/// Returns [`ExactReadError::Read`] for an incomplete or failed read and
/// [`ExactReadError::TrailingBytes`] when the file exceeds the output length.
pub fn read_exact_positioned(
    descriptor: impl AsFd,
    output: &mut [u8],
) -> Result<(), ExactReadError> {
    read_exact_positioned_with(output, |buffer, position| {
        rustix::io::pread(&descriptor, buffer, position)
    })
}

/// Reads exactly the output length using a supplied positioned reader.
///
/// The supplied reader is useful when a caller must test partial reads and
/// failures without depending on filesystem timing.
///
/// # Errors
///
/// Returns [`ExactReadError::Read`] for an incomplete or failed read and
/// [`ExactReadError::TrailingBytes`] when the reader reports trailing bytes.
pub fn read_exact_positioned_with(
    output: &mut [u8],
    mut read_at: impl FnMut(&mut [u8], u64) -> rustix::io::Result<usize>,
) -> Result<(), ExactReadError> {
    read_exact_positioned_core(output, &mut read_at)
        .map_err(|failure| failure.legacy_classification())
}

/// Reads the exact output length while retaining the original native read cause.
///
/// The caller owns the partial output buffer. Pass a borrowed descriptor to
/// retain its ownership; owned descriptor arguments are consumed and dropped
/// normally. The caller owns admission, bounds and custody; this reader adds
/// no retry, allocation or authority.
///
/// # Errors
///
/// Returns the original native error from either the content read or EOF probe,
/// or an exact-length refusal. Interrupted reads fail immediately, without retry.
pub fn read_exact_positioned_retaining_cause(
    descriptor: impl AsFd,
    output: &mut [u8],
) -> Result<(), ExactReadFailure> {
    read_exact_positioned_core(output, |buffer, position| {
        rustix::io::pread(&descriptor, buffer, position)
    })
}

// Both classified legacy entrypoints and the native-cause entry share this
// exact read/EOF sequence. Only the legacy boundary discards native errors.
fn read_exact_positioned_core(
    output: &mut [u8],
    mut read_at: impl FnMut(&mut [u8], u64) -> rustix::io::Result<usize>,
) -> Result<(), ExactReadFailure> {
    let mut offset = 0;
    while offset < output.len() {
        let position = u64::try_from(offset).map_err(|_| ExactReadFailure::Read)?;
        let remaining = output.len() - offset;
        let read = read_at(&mut output[offset..], position).map_err(ExactReadFailure::Io)?;
        if read == 0 || read > remaining {
            return Err(ExactReadFailure::Read);
        }
        offset += read;
    }

    let position = u64::try_from(output.len()).map_err(|_| ExactReadFailure::Read)?;
    let mut trailing = Zeroizing::new([0_u8; 1]);
    if read_at(&mut trailing[..], position).map_err(ExactReadFailure::Io)? != 0 {
        return Err(ExactReadFailure::TrailingBytes);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;

    use super::*;

    #[test]
    fn fixed_paths_reject_ambiguous_components() {
        assert!(is_absolute_fixed_path(Path::new("/tmp/protected/files")));
        for path in [
            "",
            "/",
            "relative",
            "//tmp/file",
            "/tmp//file",
            "/tmp/./file",
            "/tmp/../file",
            "/tmp/file/",
            "/tmp/\0file",
        ] {
            assert!(!is_absolute_fixed_path(Path::new(path)), "{path:?}");
        }
    }

    #[test]
    fn child_open_rejects_symlinks_and_non_child_names() {
        let temporary = tempfile::tempdir().unwrap();
        fs::write(temporary.path().join("secret"), [0x41_u8; 4]).unwrap();
        symlink("secret", temporary.path().join("link")).unwrap();
        let directory = rustix::fs::open(
            temporary.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();

        assert!(open_nofollow_child(&directory, "secret").is_ok());
        assert!(open_nofollow_child(&directory, "link").is_err());
        for name in ["", ".", "..", "sub/secret", "bad\0name"] {
            assert_eq!(
                open_nofollow_child(&directory, name).unwrap_err(),
                rustix::io::Errno::INVAL
            );
        }
    }

    #[test]
    fn positioned_read_rejects_truncation_and_extra_bytes() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("record");
        fs::write(&path, [1_u8, 2, 3, 4]).unwrap();
        let descriptor = rustix::fs::open(&path, OFlags::RDONLY, Mode::empty()).unwrap();

        let mut exact = [0_u8; 4];
        assert_eq!(read_exact_positioned(&descriptor, &mut exact), Ok(()));
        assert_eq!(exact, [1, 2, 3, 4]);
        assert_eq!(
            read_exact_positioned(&descriptor, &mut [0_u8; 3]),
            Err(ExactReadError::TrailingBytes)
        );
        assert_eq!(
            read_exact_positioned(&descriptor, &mut [0_u8; 5]),
            Err(ExactReadError::Read)
        );
    }

    #[test]
    fn native_causes_survive_first_partial_and_eof_failures() {
        for errno in [
            rustix::io::Errno::ACCESS,
            rustix::io::Errno::IO,
            rustix::io::Errno::INTR,
        ] {
            for failure_call in 0..3 {
                let mut output = [0_u8; 4];
                let mut calls = Vec::new();

                let failure = read_exact_positioned_core(&mut output, |buffer, position| {
                    let call = calls.len();
                    calls.push((position, buffer.len()));
                    if call == failure_call {
                        return Err(errno);
                    }
                    buffer[..2].copy_from_slice(&[7, 8]);
                    Ok(2)
                })
                .unwrap_err();

                assert!(matches!(&failure, ExactReadFailure::Io(actual) if *actual == errno));
                assert_eq!(failure.legacy_classification(), ExactReadError::Read);
                assert_eq!(
                    std::error::Error::source(&failure)
                        .unwrap()
                        .downcast_ref::<rustix::io::Errno>(),
                    Some(&errno),
                );
                assert_eq!(calls, [(0, 4), (2, 2), (4, 1)][..=failure_call]);
                assert_eq!(
                    output,
                    match failure_call {
                        0 => [0, 0, 0, 0],
                        1 => [7, 8, 0, 0],
                        _ => [7, 8, 7, 8],
                    },
                );
            }
        }
    }

    #[test]
    fn legacy_callback_keeps_native_failures_classified_as_read() {
        for failure_call in 0..3 {
            let mut output = [0_u8; 4];
            let mut calls = Vec::new();

            let result = read_exact_positioned_with(&mut output, |buffer, position| {
                let call = calls.len();
                calls.push((position, buffer.len()));
                if call == failure_call {
                    return Err(rustix::io::Errno::INTR);
                }
                buffer[..2].copy_from_slice(&[7, 8]);
                Ok(2)
            });

            assert_eq!(result, Err(ExactReadError::Read));
            assert_eq!(calls, [(0, 4), (2, 2), (4, 1)][..=failure_call]);
        }
    }

    #[test]
    fn shape_refusals_keep_their_legacy_classification() {
        for invalid_count in [0, 5] {
            let mut output = [0_u8; 4];
            let mut calls = 0;

            let failure = read_exact_positioned_core(&mut output, |_, _| {
                calls += 1;
                Ok(invalid_count)
            })
            .unwrap_err();

            assert!(matches!(&failure, ExactReadFailure::Read));
            assert_eq!(failure.legacy_classification(), ExactReadError::Read);
            assert!(std::error::Error::source(&failure).is_none());
            assert_eq!(calls, 1);
        }

        let mut output = [0_u8; 4];
        let mut calls = Vec::new();
        let failure = read_exact_positioned_core(&mut output, |buffer, position| {
            calls.push((position, buffer.len()));
            if position == 0 {
                buffer.fill(7);
                Ok(4)
            } else {
                Ok(1)
            }
        })
        .unwrap_err();

        assert!(matches!(&failure, ExactReadFailure::TrailingBytes));
        assert_eq!(failure.legacy_classification(), ExactReadError::TrailingBytes);
        assert_eq!(calls, [(0, 4), (4, 1)]);
        assert_eq!(output, [7; 4]);
    }

    #[test]
    fn empty_output_still_probes_eof_and_retains_its_native_error() {
        for errno in [rustix::io::Errno::IO, rustix::io::Errno::INTR] {
            let mut output = [];
            let mut calls = Vec::new();

            let failure = read_exact_positioned_core(&mut output, |buffer, position| {
                calls.push((position, buffer.len()));
                Err(errno)
            })
            .unwrap_err();

            assert!(matches!(failure, ExactReadFailure::Io(actual) if actual == errno));
            assert_eq!(calls, [(0, 1)]);
        }
    }

    #[test]
    fn successful_partial_reads_keep_the_exact_offset_and_eof_sequence() {
        let mut output = [0_u8; 4];
        let mut calls = Vec::new();

        let result = read_exact_positioned_core(&mut output, |buffer, position| {
            calls.push((position, buffer.len()));
            if position == 4 {
                return Ok(0);
            }
            buffer[..2].copy_from_slice(&[7, 8]);
            Ok(2)
        });

        assert!(result.is_ok());
        assert_eq!(output, [7, 8, 7, 8]);
        assert_eq!(calls, [(0, 4), (2, 2), (4, 1)]);
    }
}
