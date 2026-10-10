//! Original-owned, bounded page buffers and filesystem access for Packed indexes.

use super::*;
use crate::content_store::{batch, checked_reader};
use crate::owned_decode::{DecodeBudget, DecodeScratch};
use std::os::unix::fs::FileExt;

use super::index_format::PAGE_BYTES;

pub(super) struct Bytes {
    pub(super) value: Vec<u8>,
    _credit: Option<DecodeScratch>,
}

pub(super) enum IndexFile {
    Checked(checked_io::OwnedFile),
    Ordinary(File),
}

impl IndexFile {
    pub(super) fn file(&self) -> &File {
        match self {
            Self::Checked(file) => file.file(),
            Self::Ordinary(file) => file,
        }
    }
}

/// Borrows the caller supplied by the existing checked entry, or ordinary IO.
/// Ordinary callers never acquire checked capability through this operation.
pub(super) struct Operation<'a> {
    pub(super) original: Option<&'a DecodeBudget>,
    pub(super) boundary: &'a mut dyn FnMut() -> Result<(), StoreError>,
}

impl Operation<'_> {
    pub(super) fn check(&mut self) -> Result<(), StoreError> {
        match self.original {
            Some(original) => checked_reader::check(original, self.boundary),
            None => (self.boundary)(),
        }
    }

    pub(super) fn buffer(&self, capacity: usize) -> Result<Bytes, StoreError> {
        if capacity > PAGE_BYTES {
            return Err(StoreError::Quota);
        }
        let credit = self
            .original
            .map(|original| {
                original
                    .reserve_scratch_bytes(capacity as u64)
                    .map_err(|error| batch::admission_under(original, error))
            })
            .transpose()?;
        let mut value = Vec::new();
        value
            .try_reserve_exact(capacity)
            .map_err(|error| match self.original {
                Some(original) => batch::allocation_under(original, error),
                None => StoreError::StreamIo {
                    operation: "allocate-packed-index-page",
                    source: io::Error::other(error),
                },
            })?;
        if value.capacity() > capacity {
            return Err(StoreError::Quota);
        }
        Ok(Bytes {
            value,
            _credit: credit,
        })
    }

    pub(super) fn reserve_array<T>(
        &self,
        count: usize,
    ) -> Result<Option<DecodeScratch>, StoreError> {
        self.original
            .map(|original| {
                original
                    .reserve_scratch_array::<T>(count)
                    .map_err(|error| batch::admission_under(original, error))
            })
            .transpose()
    }

    pub(super) fn manifest_bytes(&self, capacity: usize) -> Result<Bytes, StoreError> {
        if capacity as u64 > MAX_PACK_MANIFEST_BYTES + pack_fixed_header_length() {
            return Err(StoreError::Quota);
        }
        let credit = self.reserve_array::<u8>(capacity)?;
        let mut value = Vec::new();
        value.try_reserve_exact(capacity).map_err(|error| {
            self.original.map_or(StoreError::Quota, |original| {
                batch::allocation_under(original, error)
            })
        })?;
        if value.capacity() > capacity {
            return Err(StoreError::Quota);
        }
        Ok(Bytes {
            value,
            _credit: credit,
        })
    }

    pub(super) fn read_exact(
        &mut self,
        file: &File,
        output: &mut [u8],
        offset: u64,
    ) -> Result<(), StoreError> {
        if let Some(original) = self.original {
            return checked_io::read_header_exact_at(file, output, offset, original, self.boundary);
        }
        let mut observed = 0;
        while observed < output.len() {
            self.check()?;
            let limit = (output.len() - observed).min(checked_io::READ_BYTES);
            let read = match file.read_at(
                &mut output[observed..observed + limit],
                offset + observed as u64,
            ) {
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(source) => {
                    return Err(StoreError::StreamIo {
                        operation: "read-packed-metadata",
                        source,
                    });
                }
            };
            self.check()?;
            if read == 0 {
                return Err(StoreError::Incompatible);
            }
            observed += read;
        }
        Ok(())
    }

    pub(super) fn with_path<T>(
        &mut self,
        parent: &Path,
        name: &str,
        action: impl FnOnce(&mut Self, &Path) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        if let Some(original) = self.original {
            let path = checked_io::path(parent, name, original)?;
            action(self, path.as_path())
        } else {
            let path = parent.join(name);
            action(self, &path)
        }
    }

    pub(super) fn open(&mut self, path: &Path, writing: bool) -> Result<IndexFile, StoreError> {
        match self.original {
            Some(original) => checked_io::open_file(
                path,
                if writing {
                    OFlags::RDWR
                } else {
                    OFlags::RDONLY
                },
                "open-packed-index-arena",
                original,
                self.boundary,
            )
            .map(IndexFile::Checked),
            None => {
                self.check()?;
                let descriptor = open(
                    path,
                    (if writing {
                        OFlags::RDWR
                    } else {
                        OFlags::RDONLY
                    }) | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC
                        | OFlags::NONBLOCK,
                    Mode::empty(),
                )
                .map_err(|source| StoreError::StreamIo {
                    operation: "open-packed-index-arena",
                    source: source.into(),
                })?;
                let file = File::from(descriptor);
                self.check()?;
                Ok(IndexFile::Ordinary(file))
            }
        }
    }

    pub(super) fn create(&mut self, path: &Path) -> Result<IndexFile, StoreError> {
        // The caller installs name custody before the next supervised effect.
        match self.original {
            Some(original) => {
                checked_io::create_staging(path, original, self.boundary).map(IndexFile::Checked)
            }
            None => {
                self.check()?;
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .open(path)
                    .map(IndexFile::Ordinary)
                    .map_err(|source| StoreError::StreamIo {
                        operation: "create-packed-index-arena",
                        source,
                    })
            }
        }
    }

    pub(super) fn length(&mut self, file: &IndexFile) -> Result<u64, StoreError> {
        match (self.original, file) {
            (Some(original), IndexFile::Checked(file)) => {
                checked_io::length(file, original, self.boundary)
            }
            _ => {
                self.check()?;
                let metadata = file
                    .file()
                    .metadata()
                    .map_err(|source| StoreError::StreamIo {
                        operation: "inspect-packed-index-arena",
                        source,
                    })?;
                if !metadata.is_file() {
                    return Err(StoreError::Incompatible);
                }
                self.check()?;
                Ok(metadata.len())
            }
        }
    }

    pub(super) fn read(
        &mut self,
        file: &File,
        offset: u64,
        length: usize,
    ) -> Result<Bytes, StoreError> {
        let mut bytes = self.buffer(length)?;
        bytes.value.resize(length, 0);
        if let Some(original) = self.original {
            checked_io::read_exact_at(file, &mut bytes.value, offset, original, self.boundary)?;
        } else {
            let mut observed = 0;
            while observed < length {
                self.check()?;
                let count =
                    match file.read_at(&mut bytes.value[observed..], offset + observed as u64) {
                        Ok(count) => count,
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        Err(source) => {
                            return Err(StoreError::StreamIo {
                                operation: "read-packed-index-page",
                                source,
                            });
                        }
                    };
                self.check()?;
                if count == 0 {
                    return Err(StoreError::Incompatible);
                }
                observed += count;
            }
        }
        Ok(bytes)
    }

    pub(super) fn write(
        &mut self,
        file: &File,
        offset: u64,
        bytes: &[u8],
    ) -> Result<(), StoreError> {
        offset
            .checked_add(bytes.len() as u64)
            .ok_or(StoreError::Quota)?;
        let mut observed = 0;
        while observed < bytes.len() {
            self.check()?;
            let count = match file.write_at(&bytes[observed..], offset + observed as u64) {
                Ok(count) => count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(source) => {
                    return Err(StoreError::StreamIo {
                        operation: "write-packed-index-page",
                        source,
                    });
                }
            };
            if count == 0 {
                return Err(StoreError::StreamIo {
                    operation: "write-packed-index-page",
                    source: io::ErrorKind::WriteZero.into(),
                });
            }
            self.check()?;
            observed += count;
        }
        Ok(())
    }

    pub(super) fn sync(&mut self, file: &File) -> Result<(), StoreError> {
        self.check()?;
        file.sync_all().map_err(|source| StoreError::StreamIo {
            operation: "sync-packed-index-arena",
            source,
        })?;
        self.check()
    }

    pub(super) fn require_eof(&mut self, file: &File, offset: u64) -> Result<(), StoreError> {
        let mut byte = [0];
        loop {
            self.check()?;
            let count = match file.read_at(&mut byte, offset) {
                Ok(count) => count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(source) => {
                    return Err(StoreError::StreamIo {
                        operation: "finish-packed-index-root",
                        source,
                    });
                }
            };
            self.check()?;
            return if count == 0 {
                Ok(())
            } else {
                Err(StoreError::Incompatible)
            };
        }
    }

    pub(super) fn sync_admin(&mut self, backend: &PackedBlobBackend) -> Result<(), StoreError> {
        match self.original {
            Some(original) => checked_io::sync_directory(&backend.admin, original, self.boundary),
            None => {
                self.check()?;
                sync_directory(&backend.admin)?;
                self.check()
            }
        }
    }
}

pub(super) fn arena_name(arena: [u8; 32]) -> [u8; 70] {
    let mut name = [0; 70];
    name[..6].copy_from_slice(b"arena-");
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (position, byte) in arena.into_iter().enumerate() {
        name[6 + position * 2] = HEX[(byte >> 4) as usize];
        name[7 + position * 2] = HEX[(byte & 15) as usize];
    }
    name
}

pub(super) fn pack_name(pack: PackId) -> [u8; 69] {
    let mut name = [0; 69];
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (position, byte) in pack.0.into_iter().enumerate() {
        name[position * 2] = HEX[(byte >> 4) as usize];
        name[position * 2 + 1] = HEX[(byte & 15) as usize];
    }
    name[64..].copy_from_slice(PACK_SUFFIX.as_bytes());
    name
}

impl Operation<'_> {
    pub(super) fn lock(
        &mut self,
        backend: &PackedBlobBackend,
        name: &str,
        shared: bool,
    ) -> Result<IndexFile, StoreError> {
        match self.original {
            Some(original) => checked_io::lock(backend, name, shared, original, self.boundary)
                .map(IndexFile::Checked),
            None => {
                self.check()?;
                let file = backend.lock_file(
                    name,
                    if shared {
                        FlockOperation::LockShared
                    } else {
                        FlockOperation::LockExclusive
                    },
                )?;
                self.check()?;
                Ok(IndexFile::Ordinary(file))
            }
        }
    }

    fn directory(&mut self, path: &Path) -> Result<IndexFile, StoreError> {
        match self.original {
            Some(original) => checked_io::open_file(
                path,
                OFlags::RDONLY | OFlags::DIRECTORY,
                "open-packed-maintenance-directory",
                original,
                self.boundary,
            )
            .map(IndexFile::Checked),
            None => {
                self.check()?;
                let descriptor = open(
                    path,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|source| StoreError::StreamIo {
                    operation: "open-packed-maintenance-directory",
                    source: source.into(),
                })?;
                self.check()?;
                Ok(IndexFile::Ordinary(File::from(descriptor)))
            }
        }
    }

    pub(super) fn require_headroom(
        &mut self,
        backend: &PackedBlobBackend,
        additional_bytes: u64,
        additional_names: u64,
    ) -> Result<(), StoreError> {
        let file = self.directory(&backend.admin)?;
        self.check()?;
        let available =
            rustix::fs::fstatvfs(file.file()).map_err(|source| StoreError::StreamIo {
                operation: "measure-packed-publication-headroom",
                source: source.into(),
            })?;
        self.check()?;
        let bytes = available
            .f_bavail
            .checked_mul(available.f_frsize)
            .ok_or(StoreError::Quota)?;
        if bytes < additional_bytes || available.f_favail < additional_names {
            return Err(StoreError::Quota);
        }
        // This is current filesystem headroom, not a transferable disk loan.
        // The pinned namespace quota still decides each actual write/link;
        // competing use and ENOSPC remain real typed publication failures.
        Ok(())
    }

    pub(super) fn visit_names(
        &mut self,
        parent: &Path,
        visitor: &mut impl FnMut(
            &mut Self,
            &std::ffi::CStr,
            rustix::fs::FileType,
        ) -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        let file = self.directory(parent)?;
        let mut bytes = self.buffer(PAGE_BYTES)?;
        let mut directory = rustix::fs::RawDir::new(file.file(), bytes.value.spare_capacity_mut());
        loop {
            self.check()?;
            let entry = directory.next();
            self.check()?;
            let Some(entry) = entry else {
                return Ok(());
            };
            let entry = entry.map_err(|source| StoreError::StreamIo {
                operation: "read-packed-directory-entry",
                source: source.into(),
            })?;
            if matches!(entry.file_name().to_bytes(), b"." | b"..") {
                continue;
            }
            self.check()?;
            let metadata = rustix::fs::statat(
                file.file(),
                entry.file_name(),
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            )
            .map_err(|source| StoreError::StreamIo {
                operation: "inspect-packed-directory-entry",
                source: source.into(),
            })?;
            self.check()?;
            visitor(
                self,
                entry.file_name(),
                rustix::fs::FileType::from_raw_mode(metadata.st_mode),
            )?;
        }
    }

    pub(super) fn remove_name(&mut self, parent: &Path, name: &str) -> Result<bool, StoreError> {
        self.with_path(parent, name, |operation, path| {
            operation.check()?;
            let result = match operation.original {
                Some(original) => checked_io::with_native_path(
                    path,
                    original,
                    "remove-packed-unreferenced-name",
                    |native| {
                        rustix::fs::unlinkat(rustix::fs::CWD, native, rustix::fs::AtFlags::empty())
                            .map_err(|source| StoreError::StreamIo {
                                operation: "remove-packed-unreferenced-name",
                                source: source.into(),
                            })
                    },
                ),
                None => fs::remove_file(path).map_err(|source| StoreError::StreamIo {
                    operation: "remove-packed-unreferenced-name",
                    source,
                }),
            };
            match result {
                Ok(()) => {
                    operation.check()?;
                    Ok(true)
                }
                Err(StoreError::StreamIo { source, .. })
                    if source.kind() == io::ErrorKind::NotFound =>
                {
                    operation.check()?;
                    Ok(false)
                }
                Err(error) => Err(error),
            }
        })
    }

    pub(super) fn sync_directory(&mut self, path: &Path) -> Result<(), StoreError> {
        match self.original {
            Some(original) => checked_io::sync_directory(path, original, self.boundary),
            None => {
                self.check()?;
                sync_directory(path)?;
                self.check()
            }
        }
    }
}

/// Keeps the real staging file and its name ahead of their original credits.
pub(super) enum Temporary {
    Checked(checked_publication::io::Staging),
    Ordinary { file: Option<File>, path: PathBuf },
}

impl Temporary {
    pub(super) fn new(
        backend: &PackedBlobBackend,
        parent: &Path,
        label: &str,
        operation: &mut Operation<'_>,
    ) -> Result<Self, StoreError> {
        match operation.original {
            Some(original) => {
                checked_publication::io::Staging::new(parent, label, original, operation.boundary)
                    .map(Self::Checked)
            }
            None => {
                operation.check()?;
                let (path, file) = backend.create_temporary(parent, label)?;
                Ok(Self::Ordinary {
                    file: Some(file),
                    path,
                })
            }
        }
    }

    pub(super) fn file(&self) -> Result<&File, StoreError> {
        match self {
            Self::Checked(stage) => stage.file(),
            Self::Ordinary { file, .. } => file.as_ref().ok_or(StoreError::Unavailable),
        }
    }

    fn path(&self) -> &Path {
        match self {
            Self::Checked(stage) => stage.path(),
            Self::Ordinary { path, .. } => path,
        }
    }

    pub(super) fn link(
        &self,
        target: &Path,
        operation: &mut Operation<'_>,
    ) -> Result<(), StoreError> {
        operation.check()?;
        match self {
            Self::Checked(stage) => {
                stage.with_native("publish-packed-maintenance-pack", |source| {
                    let original = operation.original.ok_or(StoreError::Unavailable)?;
                    checked_io::with_native_path(
                        target,
                        original,
                        "publish-packed-maintenance-pack",
                        |target| {
                            rustix::fs::linkat(
                                rustix::fs::CWD,
                                source,
                                rustix::fs::CWD,
                                target,
                                rustix::fs::AtFlags::empty(),
                            )
                            .map_err(|source| StoreError::StreamIo {
                                operation: "publish-packed-maintenance-pack",
                                source: source.into(),
                            })
                        },
                    )
                })
            }
            Self::Ordinary { path, .. } => {
                fs::hard_link(path, target).map_err(|source| StoreError::StreamIo {
                    operation: "publish-packed-maintenance-pack",
                    source,
                })
            }
        }
    }

    pub(super) fn cleanup(&mut self) -> Result<(), StoreError> {
        match self {
            Self::Checked(stage) => stage.cleanup(),
            Self::Ordinary { file, path } => {
                drop(file.take());
                match fs::remove_file(&*path) {
                    Ok(()) => Ok(()),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                    Err(source) => Err(StoreError::StreamIo {
                        operation: "remove-packed-index-builder",
                        source,
                    }),
                }
            }
        }
    }

    pub(super) fn compare(
        &self,
        target: &Path,
        operation: &mut Operation<'_>,
    ) -> Result<(), StoreError> {
        if let Some(original) = operation.original {
            return checked_publication::io::compare(
                self.file(),
                target,
                original,
                operation.boundary,
            );
        }
        if files_equal(self.path(), target, MAX_PACK_BYTES)? {
            Ok(())
        } else {
            Err(StoreError::Incompatible)
        }
    }
}

impl Drop for Temporary {
    fn drop(&mut self) {
        if let Self::Ordinary { file, path } = self {
            drop(file.take());
            let _cleanup = fs::remove_file(path);
        }
    }
}
