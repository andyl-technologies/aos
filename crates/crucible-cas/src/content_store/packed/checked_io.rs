//! Original descriptor custody and supervised bounded Packed filesystem steps.

use super::*;
use crate::content_store::{batch, checked_reader};
use crate::owned_decode::{DecodeBudget, DecodeDescriptorLoan, DecodeScratch};

pub(super) const READ_BYTES: usize = 64 * 1024;

pub(super) struct OwnedFile {
    file: File,
    _descriptor: DecodeDescriptorLoan,
}

impl OwnedFile {
    pub(super) fn file(&self) -> &File {
        &self.file
    }

    pub(super) fn into_parts(self) -> (File, DecodeDescriptorLoan) {
        (self.file, self._descriptor)
    }
}

pub(super) struct OwnedPath {
    path: PathBuf,
    _credit: DecodeScratch,
}

impl OwnedPath {
    pub(super) fn as_path(&self) -> &Path {
        &self.path
    }
}

pub(super) fn path(
    parent: &Path,
    name: &str,
    original: &DecodeBudget,
) -> Result<OwnedPath, StoreError> {
    let capacity = parent
        .as_os_str()
        .len()
        .checked_add(1)
        .and_then(|length| length.checked_add(name.len()))
        .ok_or(StoreError::Quota)?;
    let credit = original
        .reserve_scratch_bytes(capacity as u64)
        .map_err(|error| batch::admission_under(original, error))?;
    let mut path = PathBuf::new();
    path.try_reserve_exact(capacity)
        .map_err(|error| batch::allocation_under(original, error))?;
    path.push(parent);
    path.push(name);
    Ok(OwnedPath {
        path,
        _credit: credit,
    })
}

pub(super) fn open_file(
    path: &Path,
    flags: OFlags,
    operation: &'static str,
    original: &DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<OwnedFile, StoreError> {
    let file = open_retained(path, flags, operation, original, boundary)?;
    checked_reader::check(original, boundary)?;
    Ok(file)
}

pub(super) fn create_staging(
    path: &Path,
    original: &DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<OwnedFile, StoreError> {
    // The caller installs exclusive name custody before checking the post-open
    // boundary. Its first write check is inside the cleanup-owning work scope.
    open_retained(
        path,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
        "create-packed-checked-staging",
        original,
        boundary,
    )
}

fn open_retained(
    path: &Path,
    flags: OFlags,
    operation: &'static str,
    original: &DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<OwnedFile, StoreError> {
    checked_reader::check(original, boundary)?;
    let descriptor = original
        .reserve_descriptors(1)
        .map_err(|error| batch::admission_under(original, error))?;
    let file = loop {
        checked_reader::check(original, boundary)?;
        match open(
            path,
            flags | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::RUSR | Mode::WUSR,
        ) {
            Ok(file) => break File::from(file),
            Err(rustix::io::Errno::INTR) => continue,
            Err(source) => {
                return Err(StoreError::StreamIo {
                    operation,
                    source: source.into(),
                });
            }
        }
    };
    let owned = OwnedFile {
        file,
        _descriptor: descriptor,
    };
    Ok(owned)
}

pub(super) fn length(
    file: &OwnedFile,
    original: &DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<u64, StoreError> {
    checked_reader::check(original, boundary)?;
    let metadata = file
        .file
        .metadata()
        .map_err(|source| StoreError::StreamIo {
            operation: "inspect-packed-checked-file",
            source,
        })?;
    if !metadata.is_file() {
        return Err(StoreError::InvalidComposition {
            reason: "packed path is not a regular file",
        });
    }
    checked_reader::check(original, boundary)?;
    Ok(metadata.len())
}

pub(super) fn lock(
    backend: &PackedBlobBackend,
    name: &str,
    shared: bool,
    original: &DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<OwnedFile, StoreError> {
    let path = path(&backend.admin, name, original)?;
    let file = open_file(
        path.as_path(),
        OFlags::RDWR,
        "open-packed-checked-lock",
        original,
        boundary,
    )?;
    length(&file, original, boundary)?;
    let operation = if shared {
        FlockOperation::NonBlockingLockShared
    } else {
        FlockOperation::NonBlockingLockExclusive
    };
    loop {
        checked_reader::check(original, boundary)?;
        match flock(file.file(), operation) {
            Ok(()) => break,
            Err(rustix::io::Errno::INTR) => continue,
            Err(rustix::io::Errno::WOULDBLOCK) => {
                // This is only a polling slice of the existing supervisor.
                // No new timeout or operation account is created.
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err(source) => {
                return Err(StoreError::StreamIo {
                    operation: "lock-packed-checked-backend",
                    source: source.into(),
                });
            }
        }
    }
    checked_reader::check(original, boundary)?;
    Ok(file)
}

pub(super) fn read_at(
    file: &File,
    output: &mut [u8],
    offset: u64,
    original: &DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<usize, StoreError> {
    read_at_checked(file, output, offset, &mut || {
        checked_reader::check(original, boundary)
    })
}

pub(super) fn read_at_checked(
    file: &File,
    output: &mut [u8],
    offset: u64,
    check: &mut impl FnMut() -> Result<(), StoreError>,
) -> Result<usize, StoreError> {
    let limit = output.len().min(READ_BYTES);
    loop {
        check()?;
        match file.read_at(&mut output[..limit], offset) {
            Err(source) if source.kind() == io::ErrorKind::Interrupted => continue,
            Err(source) => {
                return Err(StoreError::StreamIo {
                    operation: "read-packed-checked-file",
                    source,
                });
            }
            Ok(read) => {
                check()?;
                return Ok(read);
            }
        }
    }
}

pub(super) fn read_exact_at(
    file: &File,
    mut output: &mut [u8],
    mut offset: u64,
    original: &DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    while !output.is_empty() {
        let read = read_at(file, output, offset, original, boundary)?;
        if read == 0 {
            return Err(StoreError::Incompatible);
        }
        offset = offset.checked_add(read as u64).ok_or(StoreError::Quota)?;
        output = &mut output[read..];
    }
    Ok(())
}

pub(super) fn sync_directory(
    path: &Path,
    original: &DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    let directory = open_file(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY,
        "open-packed-checked-directory",
        original,
        boundary,
    )?;
    checked_reader::check(original, boundary)?;
    directory
        .file
        .sync_all()
        .map_err(|source| StoreError::StreamIo {
            operation: "sync-packed-checked-directory",
            source,
        })?;
    checked_reader::check(original, boundary)
}
