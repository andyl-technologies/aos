//! Prepaid staging names, bounded checked copy, and physical pack collision IO.

use super::*;
use crate::content_store::BlobSource;
use std::fmt::Write as _;

pub(super) struct Manifest {
    bytes: Vec<u8>,
    pub(super) entry: PackManifestEntry,
    pub(super) pack: PackId,
    _credit: DecodeScratch,
}

impl Manifest {
    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(super) fn one(
        configuration: [u8; 32],
        id: ContentId,
        length: u64,
        original: &DecodeBudget,
    ) -> Result<Self, StoreError> {
        id.with_encoded_text(|encoded| {
            let manifest_length = 2 + encoded.len() + 8 + 8;
            let header_length = PACK_MAGIC.len() + 32 + 4 + 4 + manifest_length + 32;
            if (header_length as u64)
                .checked_add(length)
                .is_none_or(|end| end > MAX_PACK_BYTES)
            {
                return Err(StoreError::Quota);
            }
            let credit = original
                .reserve_scratch_bytes(header_length as u64)
                .map_err(|error| batch::admission_under(original, error))?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(header_length)
                .map_err(|error| batch::allocation_under(original, error))?;
            bytes.extend_from_slice(PACK_MAGIC);
            bytes.extend_from_slice(&configuration);
            bytes.extend_from_slice(&1_u32.to_be_bytes());
            bytes.extend_from_slice(
                &u32::try_from(manifest_length)
                    .map_err(|_| StoreError::Quota)?
                    .to_be_bytes(),
            );
            let manifest_offset = bytes.len();
            bytes.extend_from_slice(
                &u16::try_from(encoded.len())
                    .map_err(|_| StoreError::Quota)?
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(encoded);
            bytes.extend_from_slice(&(header_length as u64).to_be_bytes());
            bytes.extend_from_slice(&length.to_be_bytes());
            let pack = pack_id(configuration, &bytes[manifest_offset..]);
            let mut checksum = blake3::Hasher::new();
            checksum.update(PACK_MANIFEST_DOMAIN);
            checksum.update(&bytes);
            bytes.extend_from_slice(checksum.finalize().as_bytes());
            Ok(Self {
                bytes,
                pack,
                entry: PackManifestEntry {
                    id,
                    offset: header_length as u64,
                    length,
                },
                _credit: credit,
            })
        })
    }
}

struct StackName {
    bytes: [u8; 96],
    length: usize,
}

impl std::fmt::Write for StackName {
    fn write_str(&mut self, value: &str) -> std::fmt::Result {
        let end = self
            .length
            .checked_add(value.len())
            .filter(|end| *end <= self.bytes.len())
            .ok_or(std::fmt::Error)?;
        self.bytes[self.length..end].copy_from_slice(value.as_bytes());
        self.length = end;
        Ok(())
    }
}

pub(super) struct Staging {
    file: Option<checked_io::OwnedFile>,
    path: checked_io::OwnedPath,
    removed: bool,
}

impl Staging {
    pub(super) fn new(
        parent: &Path,
        label: &str,
        original: &DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<Self, StoreError> {
        for _ in 0..1024 {
            checked_reader::check(original, boundary)?;
            let mut name = StackName {
                bytes: [0; 96],
                length: 0,
            };
            write!(
                &mut name,
                ".{label}.tmp-{}-{}",
                std::process::id(),
                TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            )
            .map_err(|_| StoreError::Quota)?;
            let name = std::str::from_utf8(&name.bytes[..name.length])
                .map_err(|_| StoreError::Incompatible)?;
            let path = checked_io::path(parent, name, original)?;
            match checked_io::create_staging(path.as_path(), original, boundary) {
                Ok(file) => {
                    return Ok(Self {
                        file: Some(file),
                        path,
                        removed: false,
                    });
                }
                Err(StoreError::StreamIo { source, .. })
                    if source.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(StoreError::Quota)
    }

    pub(super) fn file(&self) -> Result<&File, StoreError> {
        self.file
            .as_ref()
            .map(checked_io::OwnedFile::file)
            .ok_or(StoreError::Unavailable)
    }

    pub(super) fn path(&self) -> &Path {
        self.path.as_path()
    }

    pub(super) fn cleanup(&mut self) -> Result<(), StoreError> {
        drop(self.file.take());
        match fs::remove_file(self.path()) {
            Ok(()) => {
                self.removed = true;
                Ok(())
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                self.removed = true;
                Ok(())
            }
            Err(source) => Err(StoreError::StreamIo {
                operation: "remove-packed-checked-staging",
                source,
            }),
        }
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        drop(self.file.take());
        if !self.removed {
            // Unwinding still owns this exclusive temporary name and its path
            // credit. Ordinary return records any failed cleanup explicitly.
            let _cleanup = fs::remove_file(self.path());
        }
    }
}

pub(super) fn write_all(
    file: Result<&File, StoreError>,
    mut bytes: &[u8],
    mut offset: u64,
    original: &DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    let file = file?;
    while !bytes.is_empty() {
        checked_reader::check(original, boundary)?;
        let chunk = &bytes[..bytes.len().min(checked_io::READ_BYTES)];
        match file.write_at(chunk, offset) {
            Ok(0) => {
                return Err(StoreError::StreamIo {
                    operation: "write-packed-checked-staging",
                    source: std::io::ErrorKind::WriteZero.into(),
                });
            }
            Ok(written) => {
                checked_reader::check(original, boundary)?;
                offset = offset
                    .checked_add(written as u64)
                    .ok_or(StoreError::Quota)?;
                bytes = &bytes[written..];
            }
            Err(source) if source.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(source) => {
                return Err(StoreError::StreamIo {
                    operation: "write-packed-checked-staging",
                    source,
                });
            }
        }
    }
    Ok(())
}

pub(super) fn sync(
    file: Result<&File, StoreError>,
    original: &DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    checked_reader::check(original, boundary)?;
    file?.sync_all().map_err(|source| StoreError::StreamIo {
        operation: "sync-packed-checked-staging",
        source,
    })?;
    checked_reader::check(original, boundary)
}

pub(super) fn copy(
    original: &DecodeBudget,
    id: ContentId,
    source: &BlobHandle,
    output: Option<(Result<&File, StoreError>, u64)>,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    checked_reader::check(original, boundary)?;
    let mut reader = BlobSource::open_with_boundary(source, original, boundary)?;
    let source_original = reader.original_account().clone();
    let _credit = source_original
        .reserve_scratch_bytes(checked_io::READ_BYTES as u64)
        .map_err(|error| batch::admission_under(&source_original, error))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(checked_io::READ_BYTES)
        .map_err(|error| batch::allocation_under(&source_original, error))?;
    bytes.resize(checked_io::READ_BYTES, 0);
    let mut hasher = (source.authenticated_id != Some(id)
        || reader.full_eof_identity() != Some(id))
    .then(|| content_hasher(id.kind(), id.schema_version(), source.logical_length()));
    let output = output
        .map(|(file, offset)| file.map(|file| (file, offset)))
        .transpose()?;
    let mut length = 0_u64;
    loop {
        checked_reader::check_pair(original, &source_original, boundary)?;
        let read = reader.read_with_boundary(&mut bytes, boundary)?;
        checked_reader::check_pair(original, &source_original, boundary)?;
        if read == 0 {
            break;
        }
        let offset = length;
        length = length.checked_add(read as u64).ok_or(StoreError::Quota)?;
        if length > source.logical_length() {
            return Err(StoreError::Corrupt { id });
        }
        if let Some(hasher) = &mut hasher {
            hasher.update(&bytes[..read]);
        }
        if let Some((file, start)) = output {
            write_all(
                Ok(file),
                &bytes[..read],
                start.checked_add(offset).ok_or(StoreError::Quota)?,
                original,
                &mut || checked_reader::check_pair(original, &source_original, boundary),
            )?;
        }
    }
    if length != source.logical_length()
        || hasher.is_some_and(|hasher| *hasher.finalize().as_bytes() != id.digest())
    {
        return Err(StoreError::Corrupt { id });
    }
    checked_reader::check_pair(original, &source_original, boundary)
}

pub(super) fn pack_path(
    backend: &PackedBlobBackend,
    pack: PackId,
    original: &DecodeBudget,
) -> Result<checked_io::OwnedPath, StoreError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut name = [0_u8; 64 + PACK_SUFFIX.len()];
    for (position, byte) in pack.0.iter().copied().enumerate() {
        name[position * 2] = HEX[(byte >> 4) as usize];
        name[position * 2 + 1] = HEX[(byte & 15) as usize];
    }
    name[64..].copy_from_slice(PACK_SUFFIX.as_bytes());
    checked_io::path(
        &backend.packs,
        std::str::from_utf8(&name).map_err(|_| StoreError::Incompatible)?,
        original,
    )
}

pub(super) fn compare(
    staged: Result<&File, StoreError>,
    target: &Path,
    original: &DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    let staged = staged?;
    let target = checked_io::open_file(
        target,
        OFlags::RDONLY,
        "open-packed-checked-collision",
        original,
        boundary,
    )?;
    let target_length = checked_io::length(&target, original, boundary)?;
    checked_reader::check(original, boundary)?;
    let staged_length = staged
        .metadata()
        .map_err(|source| StoreError::StreamIo {
            operation: "inspect-packed-checked-collision",
            source,
        })?
        .len();
    checked_reader::check(original, boundary)?;
    if target_length != staged_length || target_length > MAX_PACK_BYTES {
        return Err(StoreError::Incompatible);
    }
    let _credit = original
        .reserve_scratch_bytes((checked_io::READ_BYTES * 2) as u64)
        .map_err(|error| batch::admission_under(original, error))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(checked_io::READ_BYTES * 2)
        .map_err(|error| batch::allocation_under(original, error))?;
    bytes.resize(checked_io::READ_BYTES * 2, 0);
    let (left, right) = bytes.split_at_mut(checked_io::READ_BYTES);
    let mut offset = 0;
    while offset < target_length {
        let length = (target_length - offset).min(checked_io::READ_BYTES as u64) as usize;
        checked_io::read_exact_at(staged, &mut left[..length], offset, original, boundary)?;
        checked_io::read_exact_at(
            target.file(),
            &mut right[..length],
            offset,
            original,
            boundary,
        )?;
        if left[..length] != right[..length] {
            return Err(StoreError::Incompatible);
        }
        offset += length as u64;
    }
    let mut extra = [0_u8; 1];
    if checked_io::read_at(target.file(), &mut extra, target_length, original, boundary)? != 0 {
        return Err(StoreError::Incompatible);
    }
    checked_reader::check(original, boundary)
}
