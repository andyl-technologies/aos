//! Flattens canonical ordinary tree metadata while preserving graft identities.

use std::collections::BTreeMap;

use terrane_format::identity::Digest;
use terrane_format::tree_builder::Tree;
use terrane_format::tree_format::{self, EntryKind, TreeUse, validate_graft_chain, validate_key};

use super::{ENTRY, Error, HEADER, Kind, Record};
use super::{
    compile::compile_metadata,
    metadata::{self, Input},
};

/// Compiles a canonical tree and its complete reachable graft metadata.
///
/// Each [`Tree`] binds its metadata to its actual domain-separated root hash.
/// Graft map keys are checked against those identities, and every expansion
/// retains its governing root. Repeated grafts expand at each distinct path.
/// The output root comes from the canonical input, never a caller-written tag.
/// No file content, manifest, chunk reader or network interface is accepted.
///
/// This validates structural identity, not current Read permission or provenance
/// trust. A caller must authenticate its selected root and authorize metadata
/// disclosure before using or sharing the result. Overlay layers, index trees
/// and unresolved conflicts must be resolved before this ordinary projection.
///
/// # Errors
/// Refuses nonordinary trees, absent or misbound grafts, inconsistent chunk
/// geometry, cycles, excessive graft depth, invalid expanded paths and exceeded
/// entry or serialized-byte bounds. All limits include the synthesized root.
pub fn compile_tree(
    root: &Tree<'_>,
    grafts: &BTreeMap<Digest, Tree<'_>>,
    max_entries: u32,
    max_bytes: usize,
) -> Result<Vec<u8>, Error> {
    if root.usage() != TreeUse::Ordinary {
        return Err(Error::Tree);
    }
    if max_entries == 0 || max_bytes < HEADER + 32 + ENTRY + metadata::MINIMUM {
        return Err(Error::Limit);
    }

    let root_metadata = Input {
        root_properties: root.root().node().props.clone().unwrap_or_default(),
        ..Input::default()
    };
    let mut pending = vec![(root, Vec::new(), Vec::new())];
    let mut flattened = Vec::new();
    // This lower bound excludes deduplicated hashes, whose exact contribution
    // the final encoder checks. It stops expansion before oversized arenas are
    // accumulated without refusing a valid exact-bound output with shared hashes.
    let mut minimum_bytes = HEADER + 32 + ENTRY + root_metadata.encoded_length()?;
    while let Some((tree, prefix, mut ancestors)) = pending.pop() {
        ancestors.push(tree.root_identity());
        validate_graft_chain(&ancestors).map_err(|error| {
            if error == tree_format::Error::Limit {
                Error::Limit
            } else {
                Error::Tree
            }
        })?;
        if tree.usage() != TreeUse::Ordinary || tree.min_chunk_size() != root.min_chunk_size() {
            return Err(Error::Tree);
        }
        for item in tree.iter() {
            if flattened.len() >= max_entries as usize - 1 {
                return Err(Error::Limit);
            }
            let mut path = prefix.clone();
            if !path.is_empty() {
                path.push(b'/');
            }
            path.extend_from_slice(&item.key);
            validate_key(&path).map_err(|_| Error::Tree)?;
            let mut metadata = Input {
                attributes: item.entry.attrs.clone(),
                xattrs: item.entry.xattrs.clone(),
                attributes_present: item.entry.attrs_present,
                xattrs_present: item.entry.xattrs_present,
                ..Input::default()
            };
            let kind = match &item.entry.kind {
                EntryKind::Directory { mode } => {
                    metadata.mode = Some(*mode);
                    Kind::Directory {
                        governing_root: None,
                    }
                }
                EntryKind::File {
                    mode,
                    content,
                    size,
                    link_id,
                } => {
                    metadata.mode = Some(*mode);
                    if let Some(link_id) = link_id {
                        let mut canonical = prefix.clone();
                        if !canonical.is_empty() {
                            canonical.push(b'/');
                        }
                        canonical.extend_from_slice(link_id);
                        metadata.canonical_path = Some(canonical);
                    }
                    Kind::File {
                        content: *content,
                        size: *size,
                    }
                }
                EntryKind::Symlink { target } => Kind::Symlink(target),
                EntryKind::Tree { root, props } => {
                    let graft = grafts.get(root).ok_or(Error::Tree)?;
                    if graft.root_identity() != *root {
                        return Err(Error::Tree);
                    }
                    metadata.root_properties =
                        graft.root().node().props.clone().unwrap_or_default();
                    metadata.graft_overrides = props.clone().unwrap_or_default();
                    pending.push((graft, path.clone(), ancestors.clone()));
                    Kind::Directory {
                        governing_root: Some(*root),
                    }
                }
                _ => return Err(Error::Tree),
            };
            let target_bytes = if let Kind::Symlink(target) = kind {
                target.len()
            } else {
                0
            };
            minimum_bytes = minimum_bytes
                .checked_add(ENTRY + 4 + usize::from(matches!(kind, Kind::File { .. })) * 4)
                .and_then(|size| size.checked_add(metadata.encoded_length().ok()?))
                .and_then(|size| size.checked_add(path.len()))
                .and_then(|size| size.checked_add(target_bytes))
                .ok_or(Error::Limit)?;
            if minimum_bytes > max_bytes {
                return Err(Error::Limit);
            }
            flattened.push((path, kind, metadata));
        }
    }

    flattened.sort_by(|left, right| left.0.cmp(&right.0));
    let records: Vec<_> = flattened
        .iter()
        .map(|(path, kind, _)| Record { path, kind: *kind })
        .collect();
    let metadata: Vec<_> = flattened.iter().map(|(_, _, input)| input).collect();
    // Both views borrow the flattened projection until encoding finishes.
    compile_metadata(
        root.root_identity(),
        &records,
        &root_metadata,
        &metadata,
        max_entries,
        max_bytes,
    )
}
