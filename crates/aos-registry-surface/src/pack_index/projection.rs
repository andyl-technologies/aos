//! Bounded storage-local projections from a complete SHA-256 Git pack/index.
//!
//! Pack feeds are consumed incrementally; encoded pack bytes are never retained.
//! Index bytes are bounded semantic metadata. Complete checksum, object graph,
//! index CRC and offset validation precede every selection. Returned ranges are
//! facts derived from a verified whole object, not independently hashable Git
//! objects. Callers authenticate source identity and this projection's transport.
//!
//! ```text
//! index path + pack chunks + index chunks + selected OIDs/ranges
//!   -> exact encoded commitments + bounded decoded selected content
//! ```

use anyhow::{ensure, Context as _, Result};
use sha2::{Digest as _, Sha256};

use super::{
    companion_pack_path, expected_pack_checksum, parse_index, resolve_pack_entries_measured,
    stream::PackStream, MAX_PUBLISHED_PACK_INDEX_BYTES,
};
use crate::object::{ObjectKind, Oid};

mod catalogue;

pub use catalogue::{VerifiedCatalogue, VerifiedObjectSummary, MAX_CATALOGUE_OBJECTS};

/// Maximum decoded content returned across all selections.
pub const MAX_SELECTED_CONTENT_BYTES: usize = 128 * 1024;

/// Maximum distinct ordered objects selected in one inspection.
pub const MAX_SELECTED_OBJECTS: usize = 8;

/// Maximum input chunk copied from a storage stream.
pub const MAX_FEED_BYTES: usize = super::stream::CHUNK_BYTES;

/// A half-open byte range in decoded Git object content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContentRange {
    /// Inclusive decoded content offset.
    pub start: u64,
    /// Exclusive decoded content offset.
    pub end: u64,
}

/// A requested object and optional decoded content range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    /// Full SHA-256 Git object identity.
    pub oid: Oid,
    /// `None` requests the whole decoded object within the projection bound.
    pub range: Option<ContentRange>,
}

/// Exact independently computed identity of an encoded source body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedCommitment {
    /// SHA-256 over all encoded source bytes, including trailers.
    pub sha256: [u8; 32],
    /// Exact encoded source byte count.
    pub size: u64,
}

/// Selected content derived only after the entire pair passes validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedObject {
    /// Requested whole-object SHA-256 Git identity.
    pub oid: Oid,
    /// Whole-object Git kind inherited through any delta chain.
    pub kind: ObjectKind,
    /// Full decoded object content size before range selection.
    pub object_size: u64,
    /// Exact returned half-open range, including for a whole-object selection.
    pub range: ContentRange,
    /// Bounded decoded content for the selected range.
    pub content: Vec<u8>,
}

/// Verified encoded commitments and selected decoded objects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPair {
    /// Canonical selected index path.
    pub index_path: String,
    /// Canonical companion pack path derived from the index path.
    pub pack_path: String,
    /// SHA-256 of the pack payload, excluding its trailer; also its path identity.
    pub pack_trailer_sha256: [u8; 32],
    /// Independently computed complete encoded pack commitment.
    pub pack: EncodedCommitment,
    /// Independently computed complete encoded index commitment.
    pub index: EncodedCommitment,
    /// Requested objects in the same strict OID order as the selection.
    pub objects: Vec<SelectedObject>,
    /// Total inflated packed entry bytes retained before delta resolution.
    pub inflated_entry_bytes: u64,
    /// Peak simultaneously live decoded bytes, including delta input and result.
    /// This excludes fixed decoder state, 64 KiB scratch and table overhead.
    pub peak_decoded_graph_bytes: u64,
}

/// Verified positive selections and explicit absences from one complete pair.
///
/// Together, `pair.objects` and `missing_oids` partition the original requested
/// OIDs. Each list preserves their strict request order. Absence is reported
/// only after complete pack/index validation; it never represents a failed read
/// or a missing source pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvailablePair {
    /// Exact source commitments and bounded content for the present selections.
    pub pair: VerifiedPair,
    /// Requested OIDs absent from this fully verified companion pair.
    pub missing_oids: Vec<Oid>,
}

/// A storage-local projection derived from a fully verified decoded tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectedTree<T> {
    /// Requested whole-tree SHA-256 Git identity.
    pub oid: Oid,
    /// Complete decoded tree size before the callback's projection.
    pub object_size: u64,
    /// Local callback output; the caller enforces its transport format and bound.
    pub projection: T,
}

/// Complete pair commitments and an optional storage-local tree projection.
///
/// An absent tree is reported only after the whole pair passes validation.
/// `pair.objects` is empty; decoded tree bytes are borrowed by the callback and
/// are never included in this result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTreeProjection<T> {
    /// Exact encoded pair identities and decoded memory measurements.
    pub pair: VerifiedPair,
    /// The selected projection, or `None` when the OID is absent from the pair.
    pub tree: Option<ProjectedTree<T>>,
}

struct VerifiedGraph {
    pair: VerifiedPair,
    objects: Vec<(super::IndexEntry, super::ResolvedEntry)>,
}

/// Incrementally verifies a pack and its bounded companion index.
///
/// A failed feed invalidates the whole reader, even if previously fed bytes
/// describe a valid prefix. No result contains the encoded pack or index.
pub struct PairReader {
    index_path: String,
    pack_path: String,
    pack_checksum: [u8; 32],
    pack: PackStream,
    index: Vec<u8>,
    failed: bool,
}

impl PairReader {
    /// Creates a reader for one canonical SHA-256 pack-index path.
    ///
    /// # Errors
    /// Returns an error for a non-canonical index path or malformed checksum.
    pub fn new(index_path: &str) -> Result<Self> {
        let pack_path =
            companion_pack_path(index_path).context("projection index path is not canonical")?;
        let pack_checksum = expected_pack_checksum(index_path)?;
        Ok(Self {
            index_path: index_path.to_owned(),
            pack_path,
            pack_checksum,
            pack: PackStream::new(pack_checksum),
            index: Vec::new(),
            failed: false,
        })
    }

    /// Consumes a pack chunk without retaining its encoded bytes.
    ///
    /// # Errors
    /// Returns an error for a chunk above 64 KiB, a malformed pack, exceeded
    /// encoded/decoded bounds or any previous feed failure.
    pub fn feed_pack(&mut self, bytes: &[u8]) -> Result<()> {
        ensure!(!self.failed, "pack pair reader previously failed");
        let result = self.pack.feed(bytes);
        self.failed |= result.is_err();
        result
    }

    /// Retains a bounded chunk of the companion index's semantic tables.
    ///
    /// # Errors
    /// Returns an error for chunks above 64 KiB, an index above 4 MiB or any
    /// previous feed failure. Bounds are checked before allocation or copying.
    pub fn feed_index(&mut self, bytes: &[u8]) -> Result<()> {
        let result = self.feed_index_inner(bytes);
        self.failed |= result.is_err();
        result
    }

    fn feed_index_inner(&mut self, bytes: &[u8]) -> Result<()> {
        ensure!(!self.failed, "pack pair reader previously failed");
        ensure!(
            bytes.len() <= MAX_FEED_BYTES,
            "index feed exceeds its chunk limit"
        );
        ensure!(
            self.index
                .len()
                .checked_add(bytes.len())
                .is_some_and(|size| size as u64 <= MAX_PUBLISHED_PACK_INDEX_BYTES),
            "index feed exceeds its encoded-size limit"
        );
        self.index.try_reserve_exact(bytes.len())?;
        self.index.extend_from_slice(bytes);
        Ok(())
    }

    /// Validates the complete pair and returns a bounded ordered selection.
    ///
    /// Empty selection inspects only encoded commitments. Every selected OID
    /// must occur in the exact companion pack. Ranges must lie entirely within
    /// decoded content; no clipping or full-body fallback occurs.
    ///
    /// # Errors
    /// Returns an error for incomplete or corrupt input, any index/pack
    /// disagreement, delta violations, unordered/duplicate selections, absent
    /// objects, invalid ranges or output above the aggregate 128 KiB bound.
    pub fn finish(self, selections: &[Selection]) -> Result<VerifiedPair> {
        let available = self.finish_available(selections)?;
        ensure!(
            available.missing_oids.is_empty(),
            "selected object is absent from pack"
        );
        Ok(available.pair)
    }

    /// Validates the complete pair and partitions requested OIDs by presence.
    ///
    /// Present selections obey the same object, range and aggregate output
    /// bounds as [`Self::finish`]. All original selections, including absent
    /// ones, count toward the ordered batch and requested range limits. An
    /// absent selection does not clip, replace or excuse a present object's
    /// invalid range, and a corrupt pair never supplies an absence result.
    ///
    /// # Errors
    /// Returns an error for incomplete or corrupt input, any index/pack
    /// disagreement, delta violations, unordered/duplicate selections, invalid
    /// ranges or present output above the aggregate 128 KiB bound.
    pub fn finish_available(self, selections: &[Selection]) -> Result<AvailablePair> {
        validate_selections(selections)?;
        let VerifiedGraph {
            mut pair,
            objects: mut resolved,
        } = self.verify()?;

        let mut objects = Vec::with_capacity(selections.len());
        let mut missing_oids = Vec::new();
        let mut total = 0_usize;
        for selection in selections {
            let Ok(position) =
                resolved.binary_search_by(|(entry, _)| entry.oid.cmp(selection.oid.as_bytes()))
            else {
                missing_oids.push(selection.oid);
                continue;
            };
            let object = &mut resolved[position].1;
            let object_size = object.data.len() as u64;
            let range = selection.range.unwrap_or(ContentRange {
                start: 0,
                end: object_size,
            });
            ensure!(
                range.start <= range.end && range.end <= object_size,
                "selected range exceeds decoded object content"
            );
            let start = usize::try_from(range.start)?;
            let end = usize::try_from(range.end)?;
            let length = end - start;
            total = total
                .checked_add(length)
                .context("selected content size overflows")?;
            ensure!(
                total <= MAX_SELECTED_CONTENT_BYTES,
                "selected content exceeds projection limit"
            );
            // Move the already verified object; remove unselected bytes in place.
            let mut content = std::mem::take(&mut object.data);
            content.truncate(end);
            content.drain(..start);
            content.shrink_to_fit();
            objects.push(SelectedObject {
                oid: selection.oid,
                kind: object.kind,
                object_size,
                range,
                content,
            });
        }
        pair.objects = objects;
        Ok(AvailablePair { pair, missing_oids })
    }

    /// Projects one decoded tree beside storage after complete pair validation.
    ///
    /// The callback borrows the verified whole tree within the existing 4 MiB
    /// object and 12 MiB graph limits. This permits bounded names or cursor
    /// projections from trees larger than the normal 128 KiB content result.
    /// The caller must enforce its projection's transport bound; this method
    /// does not enlarge [`Self::finish`] or [`Self::finish_available`] results.
    /// Missing OIDs return `tree: None` without invoking the callback.
    ///
    /// # Errors
    /// Returns an error for incomplete or corrupt input, index/pack disagreement,
    /// delta violations, a present non-tree object or the callback's failure.
    /// Pair validation always completes before the callback runs.
    pub fn finish_tree_projection<T>(
        self,
        oid: Oid,
        project: impl FnOnce(&[u8]) -> Result<T>,
    ) -> Result<VerifiedTreeProjection<T>> {
        let VerifiedGraph { pair, objects } = self.verify()?;
        let Ok(position) = objects.binary_search_by(|(entry, _)| entry.oid.cmp(oid.as_bytes()))
        else {
            return Ok(VerifiedTreeProjection { pair, tree: None });
        };
        let object = &objects[position].1;
        ensure!(
            object.kind == ObjectKind::Tree,
            "selected object is not a Git tree"
        );
        let tree = ProjectedTree {
            oid,
            object_size: object.data.len() as u64,
            projection: project(&object.data)?,
        };
        Ok(VerifiedTreeProjection {
            pair,
            tree: Some(tree),
        })
    }

    fn verify(self) -> Result<VerifiedGraph> {
        ensure!(!self.failed, "pack pair reader previously failed");
        let expected = parse_index(&self.index_path, &self.index)?;
        let parsed = self.pack.finish()?;
        ensure!(
            parsed.entries.len() == expected.len(),
            "pack index object count does not match its companion pack"
        );
        let (mut resolved, peak_decoded_graph_bytes) =
            resolve_pack_entries_measured(parsed.entries, &expected)?;
        resolved.sort_by_key(|(entry, _)| entry.oid);
        ensure!(
            resolved.iter().map(|(entry, _)| entry).eq(expected.iter()),
            "pack index does not describe its companion pack"
        );

        let pair = VerifiedPair {
            index_path: self.index_path,
            pack_path: self.pack_path,
            pack_trailer_sha256: self.pack_checksum,
            pack: EncodedCommitment {
                sha256: parsed.encoded_hash,
                size: parsed.encoded_bytes,
            },
            index: EncodedCommitment {
                sha256: Sha256::digest(&self.index).into(),
                size: self.index.len() as u64,
            },
            objects: Vec::new(),
            inflated_entry_bytes: parsed.decoded_bytes as u64,
            peak_decoded_graph_bytes: peak_decoded_graph_bytes as u64,
        };
        Ok(VerifiedGraph {
            pair,
            objects: resolved,
        })
    }
}

fn validate_selections(selections: &[Selection]) -> Result<()> {
    ensure!(
        selections.len() <= MAX_SELECTED_OBJECTS,
        "too many pack object selections"
    );
    ensure!(
        selections.windows(2).all(|pair| pair[0].oid < pair[1].oid),
        "pack selections must be distinct and strictly ordered"
    );
    let mut total = 0_u64;
    for selection in selections {
        if let Some(range) = selection.range {
            ensure!(
                range.end <= super::MAX_PACK_OBJECT_BYTES as u64,
                "selected range exceeds the decoded object limit"
            );
            let size = range
                .end
                .checked_sub(range.start)
                .context("selected range is reversed")?;
            total = total
                .checked_add(size)
                .context("selected content size overflows")?;
            ensure!(
                total <= MAX_SELECTED_CONTENT_BYTES as u64,
                "selected content exceeds projection limit"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "tree_projection_tests.rs"]
mod tree_projection_tests;
