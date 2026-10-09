//! Streaming validation and counters for one fenced placement generation.
//!
//! A cursor owns one page buffer. Each physical manifest closes before the
//! next opens; object-to-pack relationships are checked by authenticated point
//! lookups in the same retained arena rather than a process-wide map.

use super::index_format::{self as wire, Key, PackRecord, Value};
use super::index_io::Operation;
use super::placement_index::IndexSnapshot;
use super::*;
use crate::owned_decode::DecodeScratch;

pub(super) struct Manifest {
    pub(super) entries: Vec<PackManifestEntry>,
    pub(super) physical_bytes: u64,
    _credit: Option<DecodeScratch>,
}

pub(super) fn load_manifest(
    backend: &PackedBlobBackend,
    pack: PackId,
    operation: &mut Operation<'_>,
) -> Result<Manifest, StoreError> {
    let encoded = super::index_io::pack_name(pack);
    let name = std::str::from_utf8(&encoded).map_err(|_| StoreError::Incompatible)?;
    operation.with_path(&backend.packs, name, |operation, path| {
        let file = operation.open(path, false).map_err(|error| match error {
            StoreError::StreamIo { source, .. } if source.kind() == io::ErrorKind::NotFound => {
                StoreError::Incompatible
            }
            error => error,
        })?;
        let physical_bytes = operation.length(&file)?;
        let mut fixed = [0; PACK_MAGIC.len() + 32 + 4 + 4];
        operation.read_exact(file.file(), &mut fixed, 0)?;
        let mut cursor = format::PackedCursor::new(&fixed);
        if cursor.fixed(PACK_MAGIC.len())? != PACK_MAGIC
            || cursor.array_32()? != backend.configuration
        {
            return Err(StoreError::Incompatible);
        }
        let count = usize::try_from(cursor.u32()?).map_err(|_| StoreError::Quota)?;
        let length = usize::try_from(cursor.u32()?).map_err(|_| StoreError::Quota)?;
        if count == 0
            || count > MAX_PACK_ENTRIES
            || length > count.checked_mul(111).ok_or(StoreError::Quota)?
        {
            return Err(StoreError::Incompatible);
        }
        let mut bytes = operation.manifest_bytes(length)?;
        bytes.value.resize(length, 0);
        operation.read_exact(file.file(), &mut bytes.value, fixed.len() as u64)?;
        let mut checksum = [0; 32];
        operation.read_exact(file.file(), &mut checksum, (fixed.len() + length) as u64)?;
        let mut digest = blake3::Hasher::new();
        digest.update(PACK_MANIFEST_DOMAIN);
        digest.update(&fixed);
        for chunk in bytes.value.chunks(checked_io::READ_BYTES) {
            operation.check()?;
            digest.update(chunk);
        }
        operation.check()?;
        if digest.finalize().as_bytes() != &checksum
            || pack_id(backend.configuration, &bytes.value) != pack
        {
            return Err(StoreError::Incompatible);
        }
        let credit = operation.reserve_array::<PackManifestEntry>(count)?;
        let mut entries = Vec::new();
        entries.try_reserve_exact(count).map_err(|error| {
            operation.original.map_or(StoreError::Quota, |original| {
                crate::content_store::batch::allocation_under(original, error)
            })
        })?;
        format::scan_pack_manifest(
            &bytes.value,
            count,
            &mut || operation.check(),
            &mut |entry| {
                entries.push(entry);
                Ok(())
            },
        )?;
        let header_bytes = (fixed.len() + length + 32) as u64;
        if entries
            .first()
            .is_none_or(|entry| entry.offset != header_bytes)
            || entries
                .last()
                .and_then(|entry| entry.offset.checked_add(entry.length))
                != Some(physical_bytes)
            || physical_bytes > MAX_PACK_BYTES
        {
            return Err(StoreError::Incompatible);
        }
        operation.require_eof(file.file(), physical_bytes)?;
        Ok(Manifest {
            entries,
            physical_bytes,
            _credit: credit,
        })
    })
}

pub(super) fn accounting(index: &IndexSnapshot) -> PackedStorageAccounting {
    PackedStorageAccounting {
        generation: index.header.generation,
        logical_objects: index.header.count,
        logical_bytes: index.header.logical_bytes,
        packs: index.header.packs,
        physical_bytes: index.header.physical_bytes,
    }
}

pub(super) fn validate(
    backend: &PackedBlobBackend,
    index: &IndexSnapshot,
    operation: &mut Operation<'_>,
) -> Result<(), StoreError> {
    let reader = index.reader(backend, operation)?;
    let mut cursor = reader.cursor(operation)?;
    let mut objects = 0_u64;
    let mut logical_bytes = 0_u64;
    let mut packs = 0_u64;
    let mut physical_bytes = 0_u64;
    let mut pack_objects = 0_u64;
    let mut pack_logical_bytes = 0_u64;
    let mut reference_mismatch = false;
    while let Some((key, value)) = cursor.next(operation)? {
        value.validate_for(key)?;
        if key.0[0] == 0 {
            let entry = value.entry()?;
            let stored = reader.find(Key::pack(entry.pack), operation)?;
            reference_mismatch |= stored.is_none();
            if let Some(stored) = stored {
                stored.pack_record()?;
            }
            objects = objects.checked_add(1).ok_or(StoreError::Quota)?;
            logical_bytes = logical_bytes
                .checked_add(entry.length)
                .ok_or(StoreError::Quota)?;
        } else {
            let pack = key.pack_id()?;
            let recorded = value.pack_record()?;
            let manifest = load_manifest(backend, pack, operation)?;
            let mut live_objects = 0_u64;
            let mut live_bytes = 0_u64;
            for row in &manifest.entries {
                let indexed = reader.find(Key::object(row.id), operation)?;
                if let Some(indexed) = indexed {
                    let entry = indexed.entry()?;
                    if entry.pack == pack {
                        reference_mismatch |=
                            entry.offset != row.offset || entry.length != row.length;
                        live_objects = live_objects.checked_add(1).ok_or(StoreError::Quota)?;
                        live_bytes = live_bytes
                            .checked_add(entry.length)
                            .ok_or(StoreError::Quota)?;
                    }
                }
            }
            if recorded
                != (PackRecord {
                    physical_bytes: manifest.physical_bytes,
                    objects: live_objects,
                    logical_bytes: live_bytes,
                })
            {
                reference_mismatch = true;
            }
            packs = packs.checked_add(1).ok_or(StoreError::Quota)?;
            physical_bytes = physical_bytes
                .checked_add(recorded.physical_bytes)
                .ok_or(StoreError::Quota)?;
            pack_objects = pack_objects
                .checked_add(live_objects)
                .ok_or(StoreError::Quota)?;
            pack_logical_bytes = pack_logical_bytes
                .checked_add(live_bytes)
                .ok_or(StoreError::Quota)?;
        }
    }
    // Retain only a scalar relationship refusal while every distinct pack
    // still authenticates. A later native/header failure keeps its established
    // priority; no malformed relationship is exposed as an accepted result.
    if reference_mismatch
        || objects != index.header.count
        || logical_bytes != index.header.logical_bytes
        || packs != index.header.packs
        || physical_bytes != index.header.physical_bytes
        || objects != pack_objects
        || logical_bytes != pack_logical_bytes
        || index.header.records != objects.checked_add(packs).ok_or(StoreError::Quota)?
    {
        return Err(StoreError::Incompatible);
    }
    operation.check()
}

/// Checks current additional native storage before opening a pack candidate.
pub(super) fn publication_headroom(
    backend: &PackedBlobBackend,
    index: &IndexSnapshot,
    objects: u64,
    pack_bytes: u64,
    operation: &mut Operation<'_>,
) -> Result<(), StoreError> {
    let changes = objects.checked_add(1).ok_or(StoreError::Quota)?;
    let page_bytes = u64::from(index.header.height)
        .checked_add(1)
        .and_then(|levels| levels.checked_mul(4))
        .and_then(|pages| pages.checked_add(2))
        .and_then(|pages| pages.checked_mul(changes))
        .and_then(|pages| pages.checked_mul(wire::PAGE_BYTES as u64))
        .ok_or(StoreError::Quota)?;
    operation.require_headroom(
        backend,
        pack_bytes
            .checked_add(page_bytes)
            .and_then(|bytes| bytes.checked_add(wire::PAGE_BYTES as u64))
            .ok_or(StoreError::Quota)?,
        4,
    )
}

/// Bounds both live tree pages and failed append tails before a mutation.
fn prepared_update(
    backend: &PackedBlobBackend,
    index: &IndexSnapshot,
    changes: u64,
    operation: &mut Operation<'_>,
    progress: &mut checked_publication::Progress,
) -> Result<index_update::Update, StoreError> {
    let projected_records = index
        .header
        .records
        .checked_add(changes)
        .ok_or(StoreError::Quota)?;
    let reachable_pages = projected_records
        .checked_add(15)
        .and_then(|rows| rows.checked_div(16))
        .and_then(|pages| pages.checked_mul(2))
        .and_then(|pages| pages.checked_add(1))
        .ok_or(StoreError::Quota)?;
    let reachable_bytes = reachable_pages
        .checked_mul(wire::PAGE_BYTES as u64)
        .ok_or(StoreError::Quota)?;
    // A changed level can emit two split pages or replace a sibling pair.
    // The two extra pages cover the root split/collapse endpoints.
    let append_pages = u64::from(index.header.height)
        .checked_add(1)
        .and_then(|levels| levels.checked_mul(4))
        .and_then(|pages| pages.checked_add(2))
        .and_then(|pages| pages.checked_mul(changes))
        .ok_or(StoreError::Quota)?;
    let append_bytes = append_pages
        .checked_mul(wire::PAGE_BYTES as u64)
        .ok_or(StoreError::Quota)?;
    let Some(identity) = index.header.arena else {
        return index_update::Update::new(index, backend, operation);
    };
    let name = index_io::arena_name(identity);
    let name = std::str::from_utf8(&name).map_err(|_| StoreError::Incompatible)?;
    let physical_bytes = operation.with_path(&backend.admin, name, |operation, path| {
        let file = operation.open(path, false)?;
        operation.length(&file)
    })?;
    if physical_bytes < index.header.committed_bytes {
        return Err(StoreError::Incompatible);
    }
    if physical_bytes
        .checked_add(append_bytes)
        .ok_or(StoreError::Quota)?
        <= reachable_bytes.checked_mul(2).ok_or(StoreError::Quota)?
    {
        return index_update::Update::new(index, backend, operation);
    }

    // The committed old arena remains present throughout the streamed rebuild.
    // Filesystem headroom is evidence, while the namespace quota and actual
    // native ENOSPC remain authoritative at every write.
    operation.require_headroom(
        backend,
        reachable_bytes
            .checked_add(append_bytes)
            .and_then(|bytes| bytes.checked_add((16 * wire::PAGE_BYTES) as u64))
            .ok_or(StoreError::Quota)?,
        3,
    )?;
    let mut builder = index_build::Builder::new(index.header, operation)?;
    let work = (|| {
        let reader = index.reader(backend, operation)?;
        let mut cursor = reader.cursor(operation)?;
        while let Some((key, value)) = cursor.next(operation)? {
            builder.push(backend, key, value, operation)?;
        }
        Ok(())
    })();
    let terminal = builder.terminate(backend, operation, work);
    progress.outcome.index_reclamation_pending |= terminal.uncommitted_arena_created;
    let compacted = match terminal.result {
        Ok(index) => {
            checked_publication::record_cleanup(Ok(()), terminal.cleanup, progress)?;
            index.snapshot()
        }
        Err(error) => {
            checked_publication::record_cleanup(Err(error), terminal.cleanup, progress)?;
            return Err(StoreError::Unavailable);
        }
    };
    progress.obsolete_arenas[0] = Some(identity);
    index_update::Update::new(&compacted, backend, operation)
}

fn finish_update(
    backend: &PackedBlobBackend,
    update: &mut index_update::Update,
    operation: &mut Operation<'_>,
    progress: &mut checked_publication::Progress,
) -> Result<placement_index::EncodedIndex, StoreError> {
    let result = update.finish(backend, operation);
    progress.outcome.index_reclamation_pending |= update.uncommitted_backing();
    if result
        .as_ref()
        .is_ok_and(|index| index.header.arena.is_none())
        && let Some(identity) = update.arena_identity()
    {
        if !progress.obsolete_arenas.contains(&Some(identity)) {
            let slot = if progress.obsolete_arenas[0].is_none() {
                0
            } else {
                1
            };
            progress.obsolete_arenas[slot] = Some(identity);
        }
        progress.outcome.index_reclamation_pending = true;
    }
    result
}

pub(super) fn replacement(
    backend: &PackedBlobBackend,
    index: &IndexSnapshot,
    entries: &[(ContentId, IndexEntry)],
    pack_bytes: u64,
    operation: &mut Operation<'_>,
    progress: &mut checked_publication::Progress,
) -> Result<placement_index::EncodedIndex, StoreError> {
    if entries.is_empty() {
        return Err(StoreError::Incompatible);
    }
    let pack = entries[0].1.pack;
    if entries.iter().any(|(_, entry)| entry.pack != pack) {
        return Err(StoreError::Incompatible);
    }
    let mut update = prepared_update(
        backend,
        index,
        (entries.len() as u64)
            .checked_add(1)
            .ok_or(StoreError::Quota)?,
        operation,
        progress,
    )?;
    for (id, entry) in entries {
        if update.find(Key::object(*id), operation)?.is_some() {
            return Err(StoreError::InvalidComposition {
                reason: "Packed insertion requires confirmed absence",
            });
        }
        let work = update.set(
            backend,
            Key::object(*id),
            Some(Value::object(*entry)),
            operation,
        );
        progress.outcome.index_reclamation_pending |= update.uncommitted_backing();
        work?;
    }
    let key = Key::pack(pack);
    let prior = update
        .find(key, operation)?
        .map(Value::pack_record)
        .transpose()?;
    let mut record = prior.unwrap_or(PackRecord {
        physical_bytes: pack_bytes,
        objects: 0,
        logical_bytes: 0,
    });
    if record.physical_bytes != pack_bytes {
        return Err(StoreError::Incompatible);
    }
    record.objects = record
        .objects
        .checked_add(entries.len() as u64)
        .ok_or(StoreError::Quota)?;
    for (_, entry) in entries {
        record.logical_bytes = record
            .logical_bytes
            .checked_add(entry.length)
            .ok_or(StoreError::Quota)?;
    }
    let work = update.set(backend, key, Some(Value::pack(record)), operation);
    progress.outcome.index_reclamation_pending |= update.uncommitted_backing();
    work?;
    update.clear_repack_plan();
    finish_update(backend, &mut update, operation, progress)
}

pub(super) fn removed(
    backend: &PackedBlobBackend,
    index: &IndexSnapshot,
    id: ContentId,
    operation: &mut Operation<'_>,
    progress: &mut checked_publication::Progress,
) -> Result<Option<(placement_index::EncodedIndex, PackId, bool)>, StoreError> {
    let Some(entry) = index
        .reader(backend, operation)?
        .find(Key::object(id), operation)?
        .map(Value::entry)
        .transpose()?
    else {
        return Ok(None);
    };
    let mut update = prepared_update(backend, index, 2, operation, progress)?;
    let mut record = update
        .find(Key::pack(entry.pack), operation)?
        .ok_or(StoreError::Incompatible)?
        .pack_record()?;
    record.objects = record
        .objects
        .checked_sub(1)
        .ok_or(StoreError::Incompatible)?;
    record.logical_bytes = record
        .logical_bytes
        .checked_sub(entry.length)
        .ok_or(StoreError::Incompatible)?;
    let work = update.set(backend, Key::object(id), None, operation);
    progress.outcome.index_reclamation_pending |= update.uncommitted_backing();
    work?;
    let empty = record.objects == 0;
    let work = update.set(
        backend,
        Key::pack(entry.pack),
        if empty {
            None
        } else {
            Some(Value::pack(record))
        },
        operation,
    );
    progress.outcome.index_reclamation_pending |= update.uncommitted_backing();
    work?;
    update.clear_repack_plan();
    Ok(Some((
        finish_update(backend, &mut update, operation, progress)?,
        entry.pack,
        empty,
    )))
}

pub(super) fn cleanup(
    backend: &PackedBlobBackend,
    index: &IndexSnapshot,
    operation: &mut Operation<'_>,
) -> Result<(u64, u64), StoreError> {
    let reader = index.reader(backend, operation)?;
    let mut packs = 0_u64;
    let mut stages = 0_u64;
    operation.visit_names(&backend.packs, &mut |operation, name, kind| {
        let name = name.to_str().map_err(|_| StoreError::Incompatible)?;
        if is_pack_temporary_name(name) {
            if !kind.is_file() {
                return Err(StoreError::InvalidComposition {
                    reason: "packed staging path is not a regular file",
                });
            }
            if operation.remove_name(&backend.packs, name)? {
                stages = stages.checked_add(1).ok_or(StoreError::Quota)?;
            }
        } else if !name.starts_with('.') {
            let pack = name
                .strip_suffix(PACK_SUFFIX)
                .and_then(decode_hex)
                .map(PackId)
                .ok_or(StoreError::Incompatible)?;
            if !kind.is_file() {
                return Err(StoreError::Incompatible);
            }
            if reader.find(Key::pack(pack), operation)?.is_none()
                && operation.remove_name(&backend.packs, name)?
            {
                packs = packs.checked_add(1).ok_or(StoreError::Quota)?;
            }
        }
        Ok(())
    })?;
    if packs != 0 || stages != 0 {
        operation.sync_directory(&backend.packs)?;
    }
    let retained = index.header.arena.map(super::index_io::arena_name);
    let mut changed = false;
    operation.visit_names(&backend.admin, &mut |operation, name, kind| {
        let bytes = name.to_bytes();
        if !bytes.starts_with(b"arena-") {
            return Ok(());
        }
        let name = name.to_str().map_err(|_| StoreError::Incompatible)?;
        if bytes.len() != 70 || decode_hex(&name[6..]).is_none() || !kind.is_file() {
            return Err(StoreError::Incompatible);
        }
        if retained.as_ref().is_none_or(|retained| bytes != retained) {
            changed |= operation.remove_name(&backend.admin, name)?;
        }
        Ok(())
    })?;
    if changed {
        operation.sync_admin(backend)?;
    }
    Ok((packs, stages))
}

/// Reclaims an obsolete generation only after the new root is durable.
pub(super) fn ordinary_completion<T>(
    backend: &PackedBlobBackend,
    result: Result<T, StoreError>,
    progress: &mut checked_publication::Progress,
) -> Result<T, StoreError> {
    let result = result.and_then(|value| {
        for identity in std::mem::take(&mut progress.obsolete_arenas)
            .into_iter()
            .flatten()
        {
            let name = index_io::arena_name(identity);
            let name = std::str::from_utf8(&name).map_err(|_| StoreError::Incompatible)?;
            let mut operation = Operation {
                original: None,
                boundary: &mut || Ok(()),
            };
            operation.remove_name(&backend.admin, name)?;
            operation.sync_directory(&backend.admin)?;
        }
        progress.outcome.index_reclamation_pending = false;
        Ok(value)
    });
    match result {
        Ok(value) => Ok(value),
        Err(error)
            if progress.cleanup.iter().all(Option::is_none)
                && progress.outcome == checked_publication::PackedPublicationOutcome::default() =>
        {
            Err(error)
        }
        Err(error) => Err(checked_publication::ordinary_scope_error(
            (!progress.cleanup_only).then_some(error),
            std::mem::take(&mut progress.cleanup),
            progress.outcome,
        )),
    }
}
