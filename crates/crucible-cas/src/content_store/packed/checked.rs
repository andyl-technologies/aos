//! Original-account pack lookup, pinned aliases, and full logical EOF identity.

use super::*;
use crate::content_store::checked_reader::{self, AuditedCheckedBlobReader};
use crate::content_store::directory::file_pin::FilePin;
use crate::content_store::{CheckedBlobReader, CheckedReadAccess, CheckedReader, batch};
use crate::owned_decode::{DecodeBudget, DecodeDescriptorLoan, ResourceLoanSlot};

use super::checked_io::READ_BYTES;

type PackPin = FilePin<DecodeDescriptorLoan>;

pub(super) fn lookup(
    backend: &PackedBlobBackend,
    original: &DecodeBudget,
    id: ContentId,
    range: Option<ByteRange>,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<BlobHandle, StoreError> {
    checked_reader::check(original, boundary)?;
    let _lifecycle = checked_io::lock(backend, LIFECYCLE_LOCK_FILE, true, original, boundary)?;
    let _state = checked_io::lock(backend, STATE_LOCK_FILE, false, original, boundary)?;
    let index = index_snapshot::IndexSnapshot::load(backend, original, boundary)?;
    if index.header.count == 0 {
        return Err(StoreError::NotFound { id });
    }
    let entry = index
        .find(backend, id, original, boundary)?
        .ok_or(StoreError::NotFound { id })?;
    open_entry(backend, original, id, entry, range, boundary)
}

pub(super) fn open_entry(
    backend: &PackedBlobBackend,
    original: &DecodeBudget,
    id: ContentId,
    entry: IndexEntry,
    range: Option<ByteRange>,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<BlobHandle, StoreError> {
    // Source and file controls share one credit. Every source/reader alias
    // retains that pin until both actual controls and the actual file close.
    let credit = original
        .reserve_scratch_bytes(
            BlobHandle::source_allocation_bytes::<Source>()
                .checked_add(PackPin::allocation_bytes())
                .ok_or(StoreError::Quota)?,
        )
        .map_err(|error| batch::admission_under(original, error))?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut name = [0_u8; 64 + PACK_SUFFIX.len()];
    for (position, byte) in entry.pack.0.iter().copied().enumerate() {
        name[position * 2] = HEX[(byte >> 4) as usize];
        name[position * 2 + 1] = HEX[(byte & 15) as usize];
    }
    name[64..].copy_from_slice(PACK_SUFFIX.as_bytes());
    let name = std::str::from_utf8(&name).map_err(|_| StoreError::Incompatible)?;
    let path = checked_io::path(&backend.packs, name, original)?;
    let file = checked_io::open_file(
        path.as_path(),
        OFlags::RDONLY,
        "open-packed-checked-object",
        original,
        boundary,
    )
    .map_err(|error| {
        if matches!(&error, StoreError::StreamIo { source, .. }
                if source.kind() == io::ErrorKind::NotFound)
        {
            StoreError::Corrupt { id }
        } else {
            error
        }
    })?;
    let file_length = checked_io::length(&file, original, boundary)?;
    authenticate_manifest(
        file.file(),
        backend.configuration,
        id,
        entry,
        file_length,
        original,
        boundary,
    )?;
    let range = range.unwrap_or(ByteRange {
        offset: 0,
        length: entry.length,
    });
    if range
        .offset
        .checked_add(range.length)
        .is_none_or(|end| end > entry.length)
    {
        return Err(StoreError::InvalidRange {
            offset: range.offset,
            length: range.length,
        });
    }
    // Keep File before its descriptor loan through the final fallible step;
    // split pattern bindings would drop the loan first on refusal or unwind.
    checked_reader::check(original, boundary)?;
    let (file, descriptor) = file.into_parts();
    let source = Source {
        file: PackPin::with_resources(file, credit, descriptor),
        original: original.clone(),
        id,
        offset: entry.offset,
        length: entry.length,
        range,
    };
    let handle = if range.offset == 0 && range.length == entry.length {
        BlobHandle::authenticated(id, source)
    } else {
        BlobHandle::integrity_checked(id, source)
    };
    checked_reader::check(original, boundary)?;
    Ok(handle)
}

fn authenticate_manifest(
    file: &File,
    configuration: [u8; 32],
    id: ContentId,
    entry: IndexEntry,
    file_length: u64,
    original: &DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    let mut fixed = [0_u8; PACK_MAGIC.len() + 32 + 4 + 4];
    checked_io::read_exact_at(file, &mut fixed, 0, original, boundary)?;
    let mut cursor = format::PackedCursor::new(&fixed);
    if cursor.fixed(PACK_MAGIC.len())? != PACK_MAGIC || cursor.array_32()? != configuration {
        return Err(StoreError::Incompatible);
    }
    let count = usize::try_from(cursor.u32()?).map_err(|_| StoreError::Quota)?;
    let length = usize::try_from(cursor.u32()?).map_err(|_| StoreError::Quota)?;
    if count == 0 || count > MAX_PACK_ENTRIES || length as u64 > MAX_INDEX_BYTES {
        return Err(StoreError::Incompatible);
    }
    let _credit = original
        .reserve_scratch_bytes(length as u64)
        .map_err(|error| batch::admission_under(original, error))?;
    let mut manifest = Vec::new();
    manifest
        .try_reserve_exact(length)
        .map_err(|error| batch::allocation_under(original, error))?;
    manifest.resize(length, 0);
    checked_io::read_exact_at(file, &mut manifest, fixed.len() as u64, original, boundary)?;
    let mut checksum = [0_u8; 32];
    checked_io::read_exact_at(
        file,
        &mut checksum,
        (fixed.len() + length) as u64,
        original,
        boundary,
    )?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(PACK_MANIFEST_DOMAIN);
    hasher.update(&fixed);
    for chunk in manifest.chunks(READ_BYTES) {
        checked_reader::check(original, boundary)?;
        hasher.update(chunk);
    }
    checked_reader::check(original, boundary)?;
    if *hasher.finalize().as_bytes() != checksum {
        return Err(StoreError::Incompatible);
    }

    let header_length = (fixed.len() + length + 32) as u64;
    let mut first_offset = None;
    let mut expected_length = None;
    let mut found = false;
    format::scan_pack_manifest(
        &manifest,
        count,
        &mut || checked_reader::check(original, boundary),
        &mut |candidate| {
            first_offset.get_or_insert(candidate.offset);
            expected_length = candidate.offset.checked_add(candidate.length);
            found |= candidate.id == id
                && candidate.offset == entry.offset
                && candidate.length == entry.length;
            Ok(())
        },
    )?;
    if first_offset != Some(header_length) {
        return Err(StoreError::Incompatible);
    }
    let mut identity = blake3::Hasher::new();
    identity.update(PACK_ID_DOMAIN);
    identity.update(&configuration);
    for chunk in manifest.chunks(READ_BYTES) {
        checked_reader::check(original, boundary)?;
        identity.update(chunk);
    }
    checked_reader::check(original, boundary)?;
    if *identity.finalize().as_bytes() != entry.pack.0
        || !found
        || expected_length != Some(file_length)
        || file_length > MAX_PACK_BYTES
        || entry
            .offset
            .checked_add(entry.length)
            .is_none_or(|end| end > file_length)
    {
        return Err(StoreError::Corrupt { id });
    }
    Ok(())
}

struct Source {
    file: PackPin,
    original: DecodeBudget,
    id: ContentId,
    offset: u64,
    length: u64,
    range: ByteRange,
}

impl BlobSource for Source {
    fn logical_length(&self) -> u64 {
        self.range.length
    }

    fn checked_read_access(&self) -> CheckedReadAccess {
        CheckedReadAccess::Owning
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        Err(StoreError::Unsupported {
            capability: "owning-packed-source-requires-original",
        })
    }

    fn open_with_boundary(
        &self,
        caller: &DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<CheckedReader, StoreError> {
        checked_reader::check_pair(caller, &self.original, boundary)?;
        let scratch_bytes = if self.range.offset == 0 && self.range.length == self.length {
            0
        } else {
            READ_BYTES
        };
        let credit = caller
            .reserve_scratch_bytes((std::mem::size_of::<Reader>() + scratch_bytes) as u64)
            .map_err(|error| batch::admission_under(caller, error))?;
        let mut scratch = Vec::new();
        scratch
            .try_reserve_exact(scratch_bytes)
            .map_err(|error| batch::allocation_under(caller, error))?;
        scratch.resize(scratch_bytes, 0);
        let reader = Reader {
            file: self.file.clone(),
            source_original: self.original.clone(),
            caller: caller.clone(),
            id: self.id,
            offset: self.offset,
            length: self.length,
            range: self.range,
            scan_offset: 0,
            output_offset: 0,
            hasher: content_hasher(self.id.kind(), self.id.schema_version(), self.length),
            scratch,
            finalized: false,
            failed: false,
        };
        checked_reader::check_pair(caller, &self.original, boundary)?;
        Ok(CheckedReader::admitted(
            Box::new(reader),
            credit,
            ResourceLoanSlot::default(),
        ))
    }
}

struct Reader {
    file: PackPin,
    source_original: DecodeBudget,
    caller: DecodeBudget,
    id: ContentId,
    offset: u64,
    length: u64,
    range: ByteRange,
    scan_offset: u64,
    output_offset: u64,
    hasher: blake3::Hasher,
    scratch: Vec<u8>,
    finalized: bool,
    failed: bool,
}

impl Reader {
    fn check(
        &self,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        checked_reader::check_pair(&self.caller, &self.source_original, boundary)
    }

    fn scan_until(
        &mut self,
        target: u64,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        while self.scan_offset < target {
            self.check(boundary)?;
            let limit = (target - self.scan_offset).min(READ_BYTES as u64) as usize;
            let file = self
                .file
                .file()
                .ok_or(StoreError::Corrupt { id: self.id })?;
            let read = checked_io::read_at_checked(
                file,
                &mut self.scratch[..limit],
                self.offset + self.scan_offset,
                &mut || checked_reader::check_pair(&self.caller, &self.source_original, boundary),
            )?;
            self.check(boundary)?;
            if read == 0 {
                return Err(StoreError::Corrupt { id: self.id });
            }
            self.hasher.update(&self.scratch[..read]);
            self.scan_offset += read as u64;
        }
        Ok(())
    }

    fn read_checked(
        &mut self,
        output: &mut [u8],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<usize, StoreError> {
        self.check(boundary)?;
        if output.is_empty() || self.finalized {
            return Ok(0);
        }
        self.scan_until(self.range.offset, boundary)?;
        if self.output_offset < self.range.length {
            let limit = (self.range.length - self.output_offset)
                .min(output.len().min(READ_BYTES) as u64) as usize;
            let file = self
                .file
                .file()
                .ok_or(StoreError::Corrupt { id: self.id })?;
            let read = checked_io::read_at_checked(
                file,
                &mut output[..limit],
                self.offset + self.range.offset + self.output_offset,
                &mut || checked_reader::check_pair(&self.caller, &self.source_original, boundary),
            )?;
            self.check(boundary)?;
            if read == 0 {
                return Err(StoreError::Corrupt { id: self.id });
            }
            self.hasher.update(&output[..read]);
            self.scan_offset += read as u64;
            self.output_offset += read as u64;
            return Ok(read);
        }
        self.scan_until(self.length, boundary)?;
        if *self.hasher.finalize().as_bytes() != self.id.digest() {
            return Err(StoreError::Corrupt { id: self.id });
        }
        self.check(boundary)?;
        self.finalized = true;
        Ok(0)
    }
}

impl AuditedCheckedBlobReader for Reader {}

impl CheckedBlobReader for Reader {
    fn original_account(&self) -> &DecodeBudget {
        &self.caller
    }

    fn full_eof_identity(&self) -> Option<ContentId> {
        Some(self.id)
    }

    fn read_with_boundary(
        &mut self,
        output: &mut [u8],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<usize, StoreError> {
        if self.failed {
            return Err(checked_reader::failed());
        }
        let result = self.read_checked(output, boundary);
        self.failed = result.is_err();
        result
    }
}

#[cfg(test)]
mod tests;
