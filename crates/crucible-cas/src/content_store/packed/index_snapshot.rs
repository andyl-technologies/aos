//! Length-admitted canonical index snapshots without decoded map allocations.

use super::*;
use crate::content_store::{batch, checked_reader};
use crate::owned_decode::{DecodeBudget, DecodeScratch};

pub(super) struct IndexSnapshot {
    bytes: Vec<u8>,
    pub(super) header: format::IndexHeader,
    _credit: DecodeScratch,
}

pub(super) struct EncodedIndex {
    bytes: Vec<u8>,
    _credit: DecodeScratch,
}

impl EncodedIndex {
    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl IndexSnapshot {
    pub(super) fn inserted(
        &self,
        backend: &PackedBlobBackend,
        id: ContentId,
        entry: IndexEntry,
        original: &DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<EncodedIndex, StoreError> {
        let generation = self
            .header
            .generation
            .checked_add(1)
            .ok_or(StoreError::Quota)?;
        let count = self
            .header
            .count
            .checked_add(1)
            .filter(|count| *count <= MAX_LOGICAL_OBJECTS)
            .ok_or(StoreError::Quota)?;
        id.with_encoded_text(|encoded| {
            let added = 2 + encoded.len() + 32 + 8 + 8;
            let removed = if self.header.last_repack_plan.is_some() {
                32
            } else {
                0
            };
            let capacity = self
                .bytes
                .len()
                .checked_sub(removed)
                .and_then(|length| length.checked_add(added))
                .ok_or(StoreError::Quota)?;
            if capacity as u64 > MAX_INDEX_BYTES {
                return Err(StoreError::Quota);
            }
            let credit = original
                .reserve_scratch_bytes(capacity as u64)
                .map_err(|error| batch::admission_under(original, error))?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(capacity)
                .map_err(|error| batch::allocation_under(original, error))?;
            bytes.extend_from_slice(INDEX_MAGIC);
            bytes.extend_from_slice(&backend.configuration);
            bytes.extend_from_slice(&self.header.instance);
            bytes.extend_from_slice(&generation.to_be_bytes());
            bytes.push(0);
            bytes.extend_from_slice(
                &u32::try_from(count)
                    .map_err(|_| StoreError::Quota)?
                    .to_be_bytes(),
            );
            let mut inserted = false;
            format::scan_index_payload(
                &self.bytes[..self.bytes.len() - 32],
                backend.configuration,
                &mut || checked_reader::check(original, boundary),
                &mut |candidate, value| {
                    if candidate == id {
                        return Err(StoreError::InvalidComposition {
                            reason: "Packed insertion requires confirmed absence",
                        });
                    }
                    if !inserted && id < candidate {
                        append_entry(&mut bytes, id, entry)?;
                        inserted = true;
                    }
                    append_entry(&mut bytes, candidate, value)
                },
            )?;
            if !inserted {
                append_entry(&mut bytes, id, entry)?;
            }
            let mut hasher = blake3::Hasher::new();
            hasher.update(INDEX_CHECKSUM_DOMAIN);
            for chunk in bytes.chunks(checked_io::READ_BYTES) {
                checked_reader::check(original, boundary)?;
                hasher.update(chunk);
            }
            checked_reader::check(original, boundary)?;
            bytes.extend_from_slice(hasher.finalize().as_bytes());
            if bytes.len() != capacity {
                return Err(StoreError::Incompatible);
            }
            Ok(EncodedIndex {
                bytes,
                _credit: credit,
            })
        })
    }
    pub(super) fn load(
        backend: &PackedBlobBackend,
        original: &DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<Self, StoreError> {
        let path = checked_io::path(&backend.admin, INDEX_FILE, original)?;
        let file = checked_io::open_file(
            path.as_path(),
            OFlags::RDONLY,
            "open-packed-checked-index",
            original,
            boundary,
        )?;
        let length = checked_io::length(&file, original, boundary)?;
        if length > MAX_INDEX_BYTES {
            return Err(StoreError::Quota);
        }
        let minimum = INDEX_MAGIC.len() + 32 + 32 + 8 + 1 + 4 + 32;
        let capacity = usize::try_from(length).map_err(|_| StoreError::Quota)?;
        if capacity < minimum {
            return Err(StoreError::Incompatible);
        }
        let credit = original
            .reserve_scratch_bytes(length)
            .map_err(|error| batch::admission_under(original, error))?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|error| batch::allocation_under(original, error))?;
        bytes.resize(capacity, 0);
        checked_io::read_exact_at(file.file(), &mut bytes, 0, original, boundary)?;
        let mut extra = [0_u8; 1];
        if checked_io::read_at(file.file(), &mut extra, length, original, boundary)? != 0 {
            return Err(StoreError::Incompatible);
        }
        let (payload, checksum) = bytes.split_at(capacity - 32);
        let mut hasher = blake3::Hasher::new();
        hasher.update(INDEX_CHECKSUM_DOMAIN);
        for chunk in payload.chunks(checked_io::READ_BYTES) {
            checked_reader::check(original, boundary)?;
            hasher.update(chunk);
        }
        checked_reader::check(original, boundary)?;
        if hasher.finalize().as_bytes() != checksum {
            return Err(StoreError::Incompatible);
        }
        let header = format::scan_index_payload(
            payload,
            backend.configuration,
            &mut || checked_reader::check(original, boundary),
            &mut |_, _| Ok(()),
        )?;
        // Ordinary load_index synchronizes this directory after authentication.
        // The checked path keeps exactly that phase before any referenced pack.
        checked_io::sync_directory(&backend.admin, original, boundary)?;
        Ok(Self {
            bytes,
            header,
            _credit: credit,
        })
    }

    pub(super) fn find(
        &self,
        backend: &PackedBlobBackend,
        id: ContentId,
        original: &DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<Option<IndexEntry>, StoreError> {
        let mut entry = None;
        format::scan_index_payload(
            &self.bytes[..self.bytes.len() - 32],
            backend.configuration,
            &mut || checked_reader::check(original, boundary),
            &mut |candidate, value| {
                if candidate == id {
                    entry = Some(value);
                }
                Ok(())
            },
        )?;
        Ok(entry)
    }
}

fn append_entry(bytes: &mut Vec<u8>, id: ContentId, entry: IndexEntry) -> Result<(), StoreError> {
    id.with_encoded_text(|encoded| {
        let required = bytes
            .len()
            .checked_add(2 + encoded.len() + 32 + 8 + 8)
            .ok_or(StoreError::Quota)?;
        if required > bytes.capacity() {
            return Err(StoreError::Incompatible);
        }
        bytes.extend_from_slice(
            &u16::try_from(encoded.len())
                .map_err(|_| StoreError::Quota)?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(encoded);
        bytes.extend_from_slice(&entry.pack.0);
        bytes.extend_from_slice(&entry.offset.to_be_bytes());
        bytes.extend_from_slice(&entry.length.to_be_bytes());
        Ok(())
    })
}
