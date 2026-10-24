//! Builds deterministic structural indices from resolved metadata only.

use std::collections::BTreeSet;

use terrane_format::identity::Digest;
use terrane_format::tree_format::{ContentRef, MAX_SYMLINK, validate_key};

use super::metadata::Input;
use super::{ENTRY, Error, HEADER, Index, Kind, NO_HASH, NONE, Record, VERSION};

/// Compiles resolved, sorted tree metadata within explicit entry and byte bounds.
///
/// The root directory is synthesized. Callers must retain authenticated graft
/// boundaries when resolving metadata; this function cannot reconstruct them
/// from a flattened view or establish that the supplied root names that view.
/// Limits include the synthesized root and the complete serialized file.
/// These minimal records supply no recorded attributes or hard-link identity.
/// Canonical tree callers use [`super::compile_tree`] or [`super::compile_nodes`]
/// to retain that metadata instead of reconstructing it from flattened paths.
///
/// # Errors
/// Returns an error for invalid paths, absent or nondirectory parents, unsorted
/// or duplicate inputs, invalid symlink targets, or exceeded format, allocation,
/// and caller-supplied bounds. It never fetches content or mutates a store.
pub fn compile(
    root: Digest,
    records: &[Record<'_>],
    max_entries: u32,
    max_bytes: usize,
) -> Result<Vec<u8>, Error> {
    if records.len() >= max_entries as usize || records.len() >= NONE as usize - 1 {
        return Err(Error::Limit);
    }
    let minimum = records
        .len()
        .checked_add(1)
        .and_then(|count| count.checked_mul(ENTRY + super::metadata::MINIMUM))
        .and_then(|size| size.checked_add(HEADER + 32))
        .ok_or(Error::Limit)?;
    if minimum > max_bytes {
        return Err(Error::Limit);
    }
    let defaults: Vec<_> = records.iter().map(|_| Input::default()).collect();
    let inputs: Vec<_> = defaults.iter().collect();
    compile_metadata(
        root,
        records,
        &Input::default(),
        &inputs,
        max_entries,
        max_bytes,
    )
}

pub(super) fn compile_metadata(
    root: Digest,
    records: &[Record<'_>],
    root_metadata: &Input<'_>,
    metadata: &[&Input<'_>],
    max_entries: u32,
    max_bytes: usize,
) -> Result<Vec<u8>, Error> {
    if records.len() != metadata.len() {
        return Err(Error::Tree);
    }
    let count = records.len().checked_add(1).ok_or(Error::Limit)?;
    if count > max_entries as usize || count >= NONE as usize {
        return Err(Error::Limit);
    }

    let mut hashes = BTreeSet::new();
    let mut path_bytes = 0usize;
    let mut target_bytes = 0usize;
    for (position, record) in records.iter().enumerate() {
        validate_key(record.path).map_err(|_| Error::Tree)?;
        if position > 0 && records[position - 1].path >= record.path {
            return Err(Error::Tree);
        }
        path_bytes = path_bytes
            .checked_add(record.path.len())
            .ok_or(Error::Limit)?;
        match record.kind {
            Kind::Directory {
                governing_root: Some(hash),
            }
            | Kind::File {
                content: ContentRef::Inline(hash) | ContentRef::Manifest(hash),
                ..
            } => {
                hashes.insert(hash);
            }
            Kind::Symlink(target) => {
                if target.is_empty() || target.len() > MAX_SYMLINK || target.contains(&0) {
                    return Err(Error::Tree);
                }
                target_bytes = target_bytes.checked_add(target.len()).ok_or(Error::Limit)?;
            }
            Kind::Directory {
                governing_root: None,
            } => {}
        }
    }
    // Symlink offsets are u32 even on hosts with a larger address space.
    if target_bytes > u32::MAX as usize {
        return Err(Error::Limit);
    }
    let paths = HEADER + 32;
    let targets = paths.checked_add(path_bytes).ok_or(Error::Limit)?;
    let hash_start = targets.checked_add(target_bytes).ok_or(Error::Limit)?;
    let metadata_start = hashes
        .len()
        .checked_mul(32)
        .and_then(|size| hash_start.checked_add(size))
        .ok_or(Error::Limit)?;
    let metadata_bytes =
        metadata
            .iter()
            .try_fold(root_metadata.encoded_length()?, |size, input| {
                size.checked_add(input.encoded_length()?)
                    .ok_or(Error::Limit)
            })?;
    let entries = metadata_start
        .checked_add(metadata_bytes)
        .ok_or(Error::Limit)?;
    let children = count
        .checked_mul(ENTRY)
        .and_then(|size| entries.checked_add(size))
        .ok_or(Error::Limit)?;
    let links = records
        .len()
        .checked_mul(4)
        .and_then(|size| children.checked_add(size))
        .ok_or(Error::Limit)?;
    let mut canonical = vec![NONE; count];
    let mut link_counts = vec![0u32; count];
    let mut file_count = 0usize;
    for (position, (record, input)) in records.iter().zip(metadata).enumerate() {
        if !matches!(record.kind, Kind::File { .. }) {
            if input.canonical_path.is_some() {
                return Err(Error::Tree);
            }
            continue;
        }
        let owner = match &input.canonical_path {
            Some(path) => records
                .binary_search_by_key(&path.as_slice(), |record| record.path)
                .map_err(|_| Error::Tree)?,
            None => position,
        };
        if owner > position || !matches!(records[owner].kind, Kind::File { .. }) {
            return Err(Error::Tree);
        }
        canonical[position + 1] = (owner + 1) as u32;
        link_counts[owner + 1] = link_counts[owner + 1].checked_add(1).ok_or(Error::Limit)?;
        file_count += 1;
    }
    let length = file_count
        .checked_mul(4)
        .and_then(|size| links.checked_add(size))
        .ok_or(Error::Limit)?;
    if length > max_bytes {
        return Err(Error::Limit);
    }

    let hashes: Vec<_> = hashes.into_iter().collect();
    let mut parents = Vec::new();
    parents.try_reserve_exact(count).map_err(|_| Error::Limit)?;
    parents.push(NONE);
    let mut child_counts = vec![0u32; count];
    for record in records {
        let parent = match record.path.iter().rposition(|byte| *byte == b'/') {
            None => 0,
            Some(slash) => {
                let position = records
                    .binary_search_by_key(&&record.path[..slash], |entry| entry.path)
                    .map_err(|_| Error::Tree)?;
                if !matches!(records[position].kind, Kind::Directory { .. }) {
                    return Err(Error::Tree);
                }
                u32::try_from(position + 1).map_err(|_| Error::Limit)?
            }
        };
        parents.push(parent);
        child_counts[parent as usize] = child_counts[parent as usize]
            .checked_add(1)
            .ok_or(Error::Limit)?;
    }

    let mut output = Vec::new();
    output.try_reserve_exact(length).map_err(|_| Error::Limit)?;
    output.resize(length, 0);
    output[..4].copy_from_slice(b"TRIX");
    output[4..6].copy_from_slice(&VERSION.to_le_bytes());
    put32(&mut output, 8, count as u32);
    for (slot, value) in [
        (12, HEADER),
        (20, paths),
        (28, targets),
        (36, hash_start),
        (44, entries),
        (52, children),
        (60, length),
        (68, metadata_start),
        (76, links),
    ] {
        put64(&mut output, slot, value as u64);
    }
    output[HEADER..paths].copy_from_slice(&root);
    for (position, hash) in hashes.iter().enumerate() {
        let start = hash_start + position * 32;
        output[start..start + 32].copy_from_slice(hash);
    }

    let mut metadata_cursor = 0;
    let mut link_cursor = 0u32;
    let mut next_links = Vec::new();
    let mut path_cursor = 0;
    let mut target_cursor = 0;
    let mut child_cursor = 0;
    let mut next_children = Vec::new();
    next_children
        .try_reserve_exact(count)
        .map_err(|_| Error::Limit)?;
    for position in 0..count {
        let (path, kind) = if position == 0 {
            (
                &b""[..],
                Kind::Directory {
                    governing_root: None,
                },
            )
        } else {
            (records[position - 1].path, records[position - 1].kind)
        };
        let start = entries + position * ENTRY;
        let input = if position == 0 {
            root_metadata
        } else {
            metadata[position - 1]
        };
        let metadata_length = input.encoded_length()?;
        let metadata_end = metadata_cursor + metadata_length;
        input
            .encode(&mut output[metadata_start + metadata_cursor..metadata_start + metadata_end])?;
        put64(&mut output, start + 52, metadata_cursor as u64);
        put32(
            &mut output,
            start + 60,
            u32::try_from(metadata_length).map_err(|_| Error::Limit)?,
        );
        metadata_cursor = metadata_end;
        put32(&mut output, start + 64, canonical[position]);
        put32(&mut output, start + 68, link_cursor);
        put32(&mut output, start + 72, link_counts[position]);
        next_links.push(link_cursor);
        link_cursor = link_cursor
            .checked_add(link_counts[position])
            .ok_or(Error::Limit)?;
        put64(&mut output, start, path_cursor as u64);
        put32(&mut output, start + 8, path.len() as u32);
        output[paths + path_cursor..paths + path_cursor + path.len()].copy_from_slice(path);
        path_cursor += path.len();
        let (tag, flags, size, hash) = match kind {
            Kind::Directory { governing_root } => {
                (1, u8::from(governing_root.is_some()), 0, governing_root)
            }
            Kind::File { content, size } => match content {
                ContentRef::Inline(hash) => (2, 0, size, Some(hash)),
                ContentRef::Manifest(hash) => (2, 1, size, Some(hash)),
            },
            Kind::Symlink(target) => {
                put32(&mut output, start + 32, target_cursor as u32);
                put32(&mut output, start + 36, target.len() as u32);
                output[targets + target_cursor..targets + target_cursor + target.len()]
                    .copy_from_slice(target);
                target_cursor += target.len();
                (3, 0, target.len() as u64, None)
            }
        };
        let hash_position = match hash {
            Some(hash) => hashes.binary_search(&hash).map_err(|_| Error::Encoding)? as u64,
            None => NO_HASH,
        };
        output[start + 12] = tag;
        output[start + 13] = flags;
        put64(&mut output, start + 16, size);
        put64(&mut output, start + 24, hash_position);
        put32(&mut output, start + 40, parents[position]);
        put32(&mut output, start + 44, child_cursor);
        put32(&mut output, start + 48, child_counts[position]);
        next_children.push(child_cursor);
        child_cursor += child_counts[position];
    }
    // Entry order is full-path order, so appending each entry to its parent's
    // run also gives deterministic, strictly increasing child indices.
    for (position, &parent) in parents.iter().enumerate().skip(1) {
        let slot = &mut next_children[parent as usize];
        put32(&mut output, children + *slot as usize * 4, position as u32);
        *slot += 1;
    }

    for (position, &owner) in canonical.iter().enumerate() {
        if owner == NONE {
            continue;
        }
        let slot = &mut next_links[owner as usize];
        put32(&mut output, links + *slot as usize * 4, position as u32);
        *slot += 1;
    }

    Index::open(&output)?;
    Ok(output)
}

fn put32(output: &mut [u8], start: usize, value: u32) {
    output[start..start + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(output: &mut [u8], start: usize, value: u64) {
    output[start..start + 8].copy_from_slice(&value.to_le_bytes());
}
