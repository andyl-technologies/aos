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
    let mut offset = 0;
    while offset < output.len() {
        let position = u64::try_from(offset).map_err(|_| ExactReadError::Read)?;
        let remaining = output.len() - offset;
        let read = read_at(&mut output[offset..], position).map_err(|_| ExactReadError::Read)?;
        if read == 0 || read > remaining {
            return Err(ExactReadError::Read);
        }
        offset += read;
    }

    let position = u64::try_from(output.len()).map_err(|_| ExactReadError::Read)?;
    let mut trailing = Zeroizing::new([0_u8; 1]);
    if read_at(&mut trailing[..], position).map_err(|_| ExactReadError::Read)? != 0 {
        return Err(ExactReadError::TrailingBytes);
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
}
