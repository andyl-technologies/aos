//! Fenced, bounded maintenance of Packed placement and physical generations.
//!
//! Repacking retains one metadata group and opens its sources one at a time.
//! A complete replacement arena stays private until all candidate packs and
//! arena pages synchronize. Only the atomic root switch commits the new set.

use super::index_format::{Key, PackRecord, Value};
use super::index_io::{Operation, Temporary};
use super::*;
use crate::owned_decode::DecodeBudget;

pub(super) fn accounting(
    backend: &PackedBlobBackend,
) -> Result<PackedStorageAccounting, StoreError> {
    accounting_under(
        backend,
        &mut Operation {
            original: None,
            boundary: &mut || Ok(()),
        },
    )
}

pub(super) fn accounting_under(
    backend: &PackedBlobBackend,
    operation: &mut Operation<'_>,
) -> Result<PackedStorageAccounting, StoreError> {
    let _lifecycle = operation.lock(backend, LIFECYCLE_LOCK_FILE, true)?;
    let _state = operation.lock(backend, STATE_LOCK_FILE, false)?;
    let index = index_snapshot::IndexSnapshot::load_under(backend, operation)?;
    maintenance::validate(backend, &index, operation)?;
    Ok(maintenance::accounting(&index))
}

pub(super) fn plan(backend: &PackedBlobBackend) -> Result<PackedRepackPlan, StoreError> {
    plan_under(
        backend,
        &mut Operation {
            original: None,
            boundary: &mut || Ok(()),
        },
    )
}

pub(super) fn plan_under(
    backend: &PackedBlobBackend,
    operation: &mut Operation<'_>,
) -> Result<PackedRepackPlan, StoreError> {
    let _lifecycle = operation.lock(backend, LIFECYCLE_LOCK_FILE, true)?;
    let _state = operation.lock(backend, STATE_LOCK_FILE, false)?;
    let index = index_snapshot::IndexSnapshot::load_under(backend, operation)?;
    maintenance::validate(backend, &index, operation)?;
    Ok(new_repack_plan(
        backend.configuration,
        index.header.instance,
        index.header.generation,
        index.digest(),
        maintenance::accounting(&index),
    ))
}

pub(super) fn apply(
    backend: &PackedBlobBackend,
    plan: &PackedRepackPlan,
) -> Result<PackedRepackReport, StoreError> {
    apply_under(
        backend,
        plan,
        &mut Operation {
            original: None,
            boundary: &mut || Ok(()),
        },
    )
}

pub(super) fn apply_under(
    backend: &PackedBlobBackend,
    plan: &PackedRepackPlan,
    operation: &mut Operation<'_>,
) -> Result<PackedRepackReport, StoreError> {
    operation.check()?;
    let diagnostic = operation.reserve_array::<checked_publication::Failure>(1)?;
    let mut progress = checked_publication::Progress::default();
    let mut first_boundary = None;
    let result = {
        let mut boundary = || {
            if first_boundary.is_some() {
                return Err(crate::content_store::composite_publication::refusal_marker());
            }
            match (operation.boundary)() {
                Ok(()) => Ok(()),
                Err(error) => {
                    first_boundary = Some(error);
                    Err(crate::content_store::composite_publication::refusal_marker())
                }
            }
        };
        perform(
            backend,
            plan,
            &mut Operation {
                original: operation.original,
                boundary: &mut boundary,
            },
            &mut progress,
        )
    };
    match (first_boundary, result) {
        (None, Ok(report)) => Ok(report),
        (first, result) => {
            let work = match result {
                Ok(_) => None,
                Err(StoreError::CompositeBoundary { .. }) if first.is_some() => None,
                Err(_) if progress.cleanup_only => None,
                Err(error) => Some(error),
            };
            match diagnostic {
                Some(credit) => Err(checked_publication::scope_error(
                    first,
                    work,
                    progress.cleanup,
                    progress.outcome,
                    credit,
                )),
                None if progress.cleanup.iter().all(Option::is_none)
                    && progress.outcome
                        == checked_publication::PackedPublicationOutcome::default() =>
                {
                    Err(first.or(work).unwrap_or(StoreError::Unavailable))
                }
                None => {
                    // Ordinary callbacks are internal no-op boundaries. The
                    // ordinary API retains its actual work and cleanup too.
                    Err(checked_publication::ordinary_scope_error(
                        first.or(work),
                        progress.cleanup,
                        progress.outcome,
                    ))
                }
            }
        }
    }
}

fn perform(
    backend: &PackedBlobBackend,
    plan: &PackedRepackPlan,
    operation: &mut Operation<'_>,
    progress: &mut checked_publication::Progress,
) -> Result<PackedRepackReport, StoreError> {
    let _lifecycle = operation.lock(backend, LIFECYCLE_LOCK_FILE, false)?;
    let _state = operation.lock(backend, STATE_LOCK_FILE, false)?;
    let index = index_snapshot::IndexSnapshot::load_under(backend, operation)?;
    maintenance::validate(backend, &index, operation)?;
    if plan.configuration != backend.configuration || plan.instance != index.header.instance {
        return Err(StoreError::Incompatible);
    }
    if index.header.last_repack_plan == Some(plan.id) {
        if index.header.generation != plan.generation.checked_add(1).ok_or(StoreError::Quota)? {
            return Err(StoreError::Incompatible);
        }
        let (removed_packs, _) = maintenance::cleanup(backend, &index, operation)?;
        return Ok(PackedRepackReport {
            plan: plan.id,
            before: plan.before,
            after: maintenance::accounting(&index),
            removed_packs,
            replayed: true,
        });
    }
    if index.header.generation != plan.generation
        || maintenance::accounting(&index) != plan.before
        || index.digest() != plan.index_digest
    {
        return Err(StoreError::Incompatible);
    }
    let (removed_before, _) = maintenance::cleanup(backend, &index, operation)?;
    // Old pack bytes stay live. This checks additional replacement and index
    // material before writing; the namespace quota still governs each effect.
    let reachable_pages = index
        .header
        .records
        .checked_add(15)
        .and_then(|rows| rows.checked_div(16))
        .and_then(|pages| pages.checked_mul(2))
        .and_then(|pages| pages.checked_add(1))
        .ok_or(StoreError::Quota)?;
    let page_bound = reachable_pages.checked_mul(8192).ok_or(StoreError::Quota)?;
    operation.require_headroom(
        backend,
        index
            .header
            .physical_bytes
            .checked_add(page_bound)
            .and_then(|bytes| bytes.checked_add(16 * 8192))
            .ok_or(StoreError::Quota)?,
        index.header.count.checked_add(4).ok_or(StoreError::Quota)?,
    )?;
    let initial =
        index_snapshot::EncodedIndex::empty_under(backend, index.header.instance, operation)?
            .snapshot();
    let mut packs = index_update::Update::new(&initial, backend, operation)?;
    let mut header = index.header;
    header.generation = plan.generation.checked_add(1).ok_or(StoreError::Quota)?;
    header.last_repack_plan = Some(plan.id);
    let mut builder = index_build::Builder::new(header, operation)?;
    let work = (|| {
        let reader = index.reader(backend, operation)?;
        let mut cursor = reader.cursor(operation)?;
        let group_credit = operation.reserve_array::<(ContentId, IndexEntry)>(MAX_PACK_ENTRIES)?;
        let mut group = Vec::new();
        group
            .try_reserve_exact(MAX_PACK_ENTRIES)
            .map_err(|error| allocation(operation.original, error))?;
        let mut group_bytes = pack_fixed_header_length();
        let mut replacements = 0_u64;
        while let Some((key, value)) = cursor.next(operation)? {
            if key.0[0] != 0 {
                break;
            }
            let id = key.id()?;
            let entry = value.entry()?;
            let bytes = id.with_encoded_text(|text| {
                (text.len() as u64)
                    .checked_add(18)
                    .and_then(|bytes| bytes.checked_add(entry.length))
                    .ok_or(StoreError::Quota)
            })?;
            if !group.is_empty()
                && (group.len() == MAX_PACK_ENTRIES
                    || group_bytes
                        .checked_add(bytes)
                        .is_none_or(|sum| sum > backend.target_pack_bytes))
            {
                publish_group(
                    backend,
                    &group,
                    &mut builder,
                    &mut packs,
                    operation,
                    progress,
                )?;
                replacements = replacements.checked_add(1).ok_or(StoreError::Quota)?;
                group.clear();
                group_bytes = pack_fixed_header_length();
            }
            group_bytes = group_bytes
                .checked_add(bytes)
                .filter(|bytes| *bytes <= MAX_PACK_BYTES)
                .ok_or(StoreError::Quota)?;
            group.push((id, entry));
        }
        if !group.is_empty() {
            publish_group(
                backend,
                &group,
                &mut builder,
                &mut packs,
                operation,
                progress,
            )?;
            replacements = replacements.checked_add(1).ok_or(StoreError::Quota)?;
        }
        drop(group);
        drop(group_credit);
        drop(cursor);
        drop(reader);
        let pack_index = packs.finish(backend, operation)?.snapshot();
        let pack_reader = pack_index.reader(backend, operation)?;
        let mut pack_cursor = pack_reader.cursor(operation)?;
        while let Some((key, value)) = pack_cursor.next(operation)? {
            if key.0[0] != 1 {
                return Err(StoreError::Incompatible);
            }
            builder.push(backend, key, value, operation)?;
        }
        Ok(replacements)
    })();
    let terminal = builder.terminate(backend, operation, work.map(|_| ()));
    progress.outcome.index_reclamation_pending |= terminal.uncommitted_arena_created;
    if let Err(error) = terminal.cleanup {
        let slot = if progress.cleanup[0].is_some() { 1 } else { 0 };
        progress.cleanup[slot] = Some(error);
        progress.outcome.staging_cleanup_pending = true;
        if terminal.result.is_ok() {
            progress.cleanup_only = true;
        }
        return terminal.result.and(Err(StoreError::Unavailable));
    }
    let replacement = terminal.result?;
    #[cfg(feature = "destructive-recovery-faults")]
    if progress.outcome.published_packs != 0 {
        inject_pack_index_interruption();
    }
    publish_root(backend, &replacement, operation, progress)?;
    progress.outcome.durable_objects = index.header.count;
    let next = replacement.snapshot();
    progress.outcome.index_reclamation_pending = true;
    let (removed, _) = maintenance::cleanup(backend, &next, operation)?;
    progress.outcome.index_reclamation_pending = false;
    Ok(PackedRepackReport {
        plan: plan.id,
        before: plan.before,
        after: maintenance::accounting(&next),
        removed_packs: removed_before
            .checked_add(removed)
            .ok_or(StoreError::Quota)?,
        replayed: false,
    })
}

fn publish_root(
    backend: &PackedBlobBackend,
    replacement: &index_snapshot::EncodedIndex,
    operation: &mut Operation<'_>,
    progress: &mut checked_publication::Progress,
) -> Result<(), StoreError> {
    match operation.original {
        Some(original) => checked_publication::publish_index(
            backend,
            original,
            replacement,
            progress,
            operation.boundary,
            replacement.header.count,
        ),
        None => backend.publish_index_reconciled(replacement),
    }
}

fn publish_group(
    backend: &PackedBlobBackend,
    rows: &[(ContentId, IndexEntry)],
    builder: &mut index_build::Builder,
    packs: &mut index_update::Update,
    operation: &mut Operation<'_>,
    progress: &mut checked_publication::Progress,
) -> Result<(), StoreError> {
    let ordered_credit = operation.reserve_array::<(ContentId, IndexEntry)>(rows.len())?;
    let mut ordered = Vec::new();
    ordered
        .try_reserve_exact(rows.len())
        .map_err(|error| allocation(operation.original, error))?;
    ordered.extend_from_slice(rows);
    ordered.sort_unstable_by_key(|(id, _)| *id);
    let manifest_length = ordered.iter().try_fold(0_usize, |sum, (id, _)| {
        id.with_encoded_text(|text| sum.checked_add(text.len() + 18).ok_or(StoreError::Quota))
    })?;
    let header_length = pack_fixed_header_length()
        .checked_add(manifest_length as u64)
        .ok_or(StoreError::Quota)?;
    let entries_credit = operation.reserve_array::<PackManifestEntry>(rows.len())?;
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(rows.len())
        .map_err(|error| allocation(operation.original, error))?;
    let mut offset = header_length;
    let mut logical_bytes = 0_u64;
    for (id, entry) in &ordered {
        entries.push(PackManifestEntry {
            id: *id,
            offset,
            length: entry.length,
        });
        offset = offset
            .checked_add(entry.length)
            .filter(|bytes| *bytes <= MAX_PACK_BYTES)
            .ok_or(StoreError::Quota)?;
        logical_bytes = logical_bytes
            .checked_add(entry.length)
            .ok_or(StoreError::Quota)?;
    }
    let mut bytes = operation.manifest_bytes(header_length as usize)?;
    bytes.value.extend_from_slice(PACK_MAGIC);
    bytes.value.extend_from_slice(&backend.configuration);
    bytes
        .value
        .extend_from_slice(&(rows.len() as u32).to_be_bytes());
    bytes
        .value
        .extend_from_slice(&(manifest_length as u32).to_be_bytes());
    let manifest_offset = bytes.value.len();
    for entry in &entries {
        entry.id.with_encoded_text(|text| {
            bytes
                .value
                .extend_from_slice(&(text.len() as u16).to_be_bytes());
            bytes.value.extend_from_slice(text);
            bytes.value.extend_from_slice(&entry.offset.to_be_bytes());
            bytes.value.extend_from_slice(&entry.length.to_be_bytes());
        });
    }
    let pack = pack_id(backend.configuration, &bytes.value[manifest_offset..]);
    let mut checksum = blake3::Hasher::new();
    checksum.update(PACK_MANIFEST_DOMAIN);
    checksum.update(&bytes.value);
    bytes
        .value
        .extend_from_slice(checksum.finalize().as_bytes());
    let mut staging = Temporary::new(backend, &backend.packs, "pack", operation)?;
    let work = (|| {
        operation.write(staging.file()?, 0, &bytes.value)?;
        for ((id, entry), output) in ordered.iter().zip(&entries) {
            let source = match operation.original {
                Some(original) => {
                    checked::open_entry(backend, original, *id, *entry, None, operation.boundary)?
                }
                None => backend.open_entry(*id, entry)?,
            };
            match operation.original {
                Some(original) => checked_publication::io::copy(
                    original,
                    *id,
                    &source,
                    Some((staging.file(), output.offset)),
                    operation.boundary,
                )?,
                None => {
                    let mut target = staging.file()?;
                    target
                        .seek(io::SeekFrom::Start(output.offset))
                        .map_err(|source| StoreError::StreamIo {
                            operation: "seek-packed-repack-output",
                            source,
                        })?;
                    copy_source(*id, &source, &mut target)?;
                }
            }
        }
        operation.sync(staging.file()?)?;
        let encoded = super::index_io::pack_name(pack);
        let name = std::str::from_utf8(&encoded).map_err(|_| StoreError::Incompatible)?;
        operation.with_path(&backend.packs, name, |operation, target| {
            match staging.link(target, operation) {
                Ok(()) => {
                    progress.outcome.published_packs = progress
                        .outcome
                        .published_packs
                        .checked_add(1)
                        .ok_or(StoreError::Quota)?;
                    progress.outcome.pack_visibility_uncertain = true;
                }
                Err(StoreError::StreamIo { source, .. })
                    if source.kind() == io::ErrorKind::AlreadyExists =>
                {
                    staging.compare(target, operation)?
                }
                Err(error) => {
                    progress.outcome.pack_visibility_uncertain = true;
                    return Err(error);
                }
            }
            operation.check()?;
            operation.sync_directory(&backend.packs)?;
            progress.outcome.pack_visibility_uncertain = false;
            Ok(())
        })?;
        for entry in &entries {
            builder.push(
                backend,
                Key::object(entry.id),
                Value::object(entry.to_index_entry(pack)),
                operation,
            )?;
        }
        packs.set(
            backend,
            Key::pack(pack),
            Some(Value::pack(PackRecord {
                physical_bytes: offset,
                objects: rows.len() as u64,
                logical_bytes,
            })),
            operation,
        )?;
        Ok(())
    })();
    let cleanup = staging.cleanup();
    let result = match cleanup {
        Ok(()) => work,
        Err(error) => {
            progress.cleanup[0] = Some(error);
            progress.outcome.staging_cleanup_pending = true;
            if work.is_ok() {
                progress.cleanup_only = true;
            }
            work.and(Err(StoreError::Unavailable))
        }
    };
    drop(entries);
    drop(entries_credit);
    drop(ordered);
    drop(ordered_credit);
    result
}

fn allocation(
    original: Option<&DecodeBudget>,
    error: std::collections::TryReserveError,
) -> StoreError {
    match original {
        Some(original) => crate::content_store::batch::allocation_under(original, error),
        None => StoreError::Quota,
    }
}
