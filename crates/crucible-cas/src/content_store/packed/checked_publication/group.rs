//! Bounded ordered publication groups sharing one physical and root commit.
//!
//! Sources open once in supplied order. Canonical manifest order determines
//! their positional writes, independently of that validation order. The old
//! singleton path remains the small publication fast path.

use super::*;
use crate::content_store::packed::index_io::Operation;

pub(super) fn publish_prefix(
    backend: &PackedBlobBackend,
    original: &DecodeBudget,
    objects: &[(ContentId, BlobHandle)],
    progress: &mut Progress,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<usize, StoreError> {
    if objects.len() == 1 {
        publish_one(
            backend,
            original,
            objects[0].0,
            &objects[0].1,
            progress,
            boundary,
        )?;
        return Ok(1);
    }
    let _state = checked_io::lock(backend, STATE_LOCK_FILE, false, original, boundary)?;
    let index = index_snapshot::IndexSnapshot::load(backend, original, boundary)?;
    let mut presence = None;
    let first = index.find_for_group(backend, objects[0].0, original, &mut presence, boundary)?;
    if first.is_some() {
        drop(presence);
        publish_one_locked(
            backend,
            original,
            objects[0].0,
            &objects[0].1,
            &index,
            first,
            progress,
            boundary,
        )?;
        return Ok(1);
    }
    let mut selected = [0_usize; 64];
    let mut count = 0;
    let mut length = pack_fixed_header_length();
    // This selection reads only declared IDs and lengths. Each later physical
    // placement is checked after its preceding incoming source authenticates.
    for (position, (id, source)) in objects.iter().enumerate() {
        if selected[..count]
            .iter()
            .any(|prior| objects[*prior].0 == *id)
        {
            break;
        }
        let candidate = id.with_encoded_text(|text| {
            (text.len() as u64)
                .checked_add(18)
                .and_then(|bytes| bytes.checked_add(source.logical_length()))
                .and_then(|bytes| length.checked_add(bytes))
        });
        let candidate = match candidate {
            Some(candidate) => candidate,
            None if count != 0 => break,
            None => return Err(StoreError::Quota),
        };
        if count != 0 && candidate > backend.target_pack_bytes {
            break;
        }
        if candidate > MAX_PACK_BYTES {
            return Err(StoreError::Quota);
        }
        selected[count] = position;
        count += 1;
        length = candidate;
    }
    if count < 2 {
        drop(presence);
        publish_one_locked(
            backend,
            original,
            objects[0].0,
            &objects[0].1,
            &index,
            first,
            progress,
            boundary,
        )?;
        return Ok(1);
    }
    let credit = original
        .reserve_scratch_array::<PackManifestEntry>(count)
        .map_err(|error| batch::admission_under(original, error))?;
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(count)
        .map_err(|error| batch::allocation_under(original, error))?;
    let mut ordered = selected;
    ordered[..count].sort_unstable_by_key(|position| objects[*position].0);
    let manifest_length = ordered[..count].iter().try_fold(0_usize, |sum, position| {
        objects[*position]
            .0
            .with_encoded_text(|text| sum.checked_add(text.len() + 18).ok_or(StoreError::Quota))
    })?;
    let header_length = pack_fixed_header_length()
        .checked_add(manifest_length as u64)
        .ok_or(StoreError::Quota)?;
    let mut offset = header_length;
    for position in &ordered[..count] {
        let (id, source) = &objects[*position];
        entries.push(PackManifestEntry {
            id: *id,
            offset,
            length: source.logical_length(),
        });
        offset = offset
            .checked_add(source.logical_length())
            .ok_or(StoreError::Quota)?;
    }
    let bytes_credit = original
        .reserve_scratch_bytes(header_length)
        .map_err(|error| batch::admission_under(original, error))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(header_length as usize)
        .map_err(|error| batch::allocation_under(original, error))?;
    let mut pack = encode_manifest(backend.configuration, &entries, &mut bytes)?;
    maintenance::publication_headroom(
        backend,
        &index,
        count as u64,
        offset,
        &mut Operation {
            original: Some(original),
            boundary,
        },
    )?;
    let mut staging = io::Staging::new(&backend.packs, "pack", original, boundary)?;
    let work = (|| {
        io::write_all(staging.file(), &bytes, 0, original, boundary)?;
        let prospective_count = count;
        for (position, (id, source)) in objects[..prospective_count].iter().enumerate() {
            if position != 0
                && index
                    .find_for_group(backend, *id, original, &mut presence, boundary)?
                    .is_some()
            {
                count = position;
                break;
            }
            let entry = entries
                .iter()
                .find(|entry| entry.id == *id)
                .ok_or(StoreError::Incompatible)?;
            io::copy(
                original,
                *id,
                source,
                Some((staging.file(), entry.offset)),
                boundary,
            )?;
        }
        // This buffer overlaps source copying, but never prefix compaction or
        // the replacement traversal's independently admitted page buffers.
        drop(presence.take());
        if count != prospective_count {
            entries.retain(|entry| objects[..count].iter().any(|(id, _)| *id == entry.id));
            let header_bytes =
                entries
                    .iter()
                    .try_fold(pack_fixed_header_length(), |sum, entry| {
                        entry.id.with_encoded_text(|text| {
                            sum.checked_add(text.len() as u64 + 18)
                                .ok_or(StoreError::Quota)
                        })
                    })?;
            compact_prefix(&staging, &mut entries, header_bytes, original, boundary)?;
            pack = encode_manifest(backend.configuration, &entries, &mut bytes)?;
            io::write_all(staging.file(), &bytes, 0, original, boundary)?;
            offset = entries
                .last()
                .and_then(|entry| entry.offset.checked_add(entry.length))
                .ok_or(StoreError::Quota)?;
            checked_reader::check(original, boundary)?;
            staging
                .file()?
                .set_len(offset)
                .map_err(|source| StoreError::StreamIo {
                    operation: "truncate-packed-checked-prefix",
                    source,
                })?;
            checked_reader::check(original, boundary)?;
        }
        io::sync(staging.file(), original, boundary)?;
        let mut rows = [(objects[0].0, entries[0].to_index_entry(pack)); 64];
        for (slot, entry) in entries.iter().enumerate() {
            rows[slot] = (entry.id, entry.to_index_entry(pack));
        }
        let replacement = super::super::maintenance::replacement(
            backend,
            &index,
            &rows[..count],
            offset,
            &mut Operation {
                original: Some(original),
                boundary,
            },
            progress,
        )?;
        let target = io::pack_path(backend, pack, original)?;
        checked_reader::check(original, boundary)?;
        match fs::hard_link(staging.path(), target.as_path()) {
            Ok(()) => {
                progress.outcome.published_packs += 1;
                progress.outcome.pack_visibility_uncertain = true;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                io::compare(staging.file(), target.as_path(), original, boundary)?
            }
            Err(source) => {
                progress.outcome.pack_visibility_uncertain = true;
                return Err(StoreError::StreamIo {
                    operation: "publish-packed-checked-group",
                    source,
                });
            }
        }
        checked_reader::check(original, boundary)?;
        checked_io::sync_directory(&backend.packs, original, boundary)?;
        progress.outcome.pack_visibility_uncertain = false;
        publish_index(
            backend,
            original,
            &replacement,
            progress,
            boundary,
            count as u64,
        )?;
        checked_reader::check(original, boundary)
    })();
    // Preserve the actual work result while storage closes before cleanup.
    drop(presence);
    let cleanup = staging.cleanup();
    let result = record_cleanup(work, cleanup, progress);
    drop(bytes);
    drop(bytes_credit);
    drop(entries);
    drop(credit);
    result.map(|()| count)
}

fn encode_manifest(
    configuration: [u8; 32],
    entries: &[PackManifestEntry],
    bytes: &mut Vec<u8>,
) -> Result<PackId, StoreError> {
    let manifest_length = entries.iter().try_fold(0_u32, |sum, entry| {
        entry.id.with_encoded_text(|text| {
            sum.checked_add(u32::try_from(text.len() + 18).map_err(|_| StoreError::Quota)?)
                .ok_or(StoreError::Quota)
        })
    })?;
    bytes.clear();
    bytes.extend_from_slice(PACK_MAGIC);
    bytes.extend_from_slice(&configuration);
    bytes.extend_from_slice(
        &u32::try_from(entries.len())
            .map_err(|_| StoreError::Quota)?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&manifest_length.to_be_bytes());
    let manifest_offset = bytes.len();
    for entry in entries {
        entry.id.with_encoded_text(|text| {
            bytes.extend_from_slice(&(text.len() as u16).to_be_bytes());
            bytes.extend_from_slice(text);
            bytes.extend_from_slice(&entry.offset.to_be_bytes());
            bytes.extend_from_slice(&entry.length.to_be_bytes());
        });
    }
    let pack = pack_id(configuration, &bytes[manifest_offset..]);
    let mut checksum = blake3::Hasher::new();
    checksum.update(PACK_MANIFEST_DOMAIN);
    checksum.update(bytes);
    bytes.extend_from_slice(checksum.finalize().as_bytes());
    Ok(pack)
}

/// Removes prospective unused slots using only already authenticated staged bytes.
fn compact_prefix(
    staging: &io::Staging,
    entries: &mut [PackManifestEntry],
    header_bytes: u64,
    original: &DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    let credit = original
        .reserve_scratch_bytes(checked_io::READ_BYTES as u64)
        .map_err(|error| batch::admission_under(original, error))?;
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(checked_io::READ_BYTES)
        .map_err(|error| batch::allocation_under(original, error))?;
    buffer.resize(checked_io::READ_BYTES, 0);
    let mut target = header_bytes;
    for entry in entries {
        if target > entry.offset {
            return Err(StoreError::Incompatible);
        }
        if target != entry.offset {
            let mut copied = 0;
            while copied < entry.length {
                let bytes =
                    usize::try_from((entry.length - copied).min(checked_io::READ_BYTES as u64))
                        .map_err(|_| StoreError::Quota)?;
                checked_io::read_header_exact_at(
                    staging.file()?,
                    &mut buffer[..bytes],
                    entry.offset.checked_add(copied).ok_or(StoreError::Quota)?,
                    original,
                    boundary,
                )?;
                io::write_all(
                    staging.file(),
                    &buffer[..bytes],
                    target.checked_add(copied).ok_or(StoreError::Quota)?,
                    original,
                    boundary,
                )?;
                copied = copied.checked_add(bytes as u64).ok_or(StoreError::Quota)?;
            }
        }
        entry.offset = target;
        target = target.checked_add(entry.length).ok_or(StoreError::Quota)?;
    }
    drop(buffer);
    drop(credit);
    Ok(())
}
