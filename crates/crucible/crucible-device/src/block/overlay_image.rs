//! Immutable, chunked, content-addressed images of a block overlay.
//!
//! A [`BlockOverlayImage`] is the overlay half of a block snapshot. It names
//! the overlay as a sparse sequence of 4 MiB chunks over the device's logical
//! byte range. Each chunk with at least one copied-up page carries:
//!
//! - `present`: the pages copied up in that chunk (a 1,024-bit bitmap),
//! - `dirty`: the pages written since the last checkpoint boundary, a subset
//!   of `present` ([IO-7]),
//! - `identity`: the BLAKE3 hash of the chunk's logical bytes, or `None` when
//!   every byte is zero.
//!
//! A chunk's logical bytes are its present pages' bytes with zeroes in place
//! of absent pages, truncated to the device length for the final chunk. The
//! identity is the plain BLAKE3 content key, the same key a content-addressed
//! object store files the chunk under, so unchanged chunks deduplicate across
//! checkpoints and forks ([TEMP-16]). The base image never appears in an image
//! ([TEMP-9]); absent pages resolve to the base on restore.
//!
//! ```text
//! image  = { length, chunks: [chunk] ascending by index }
//! chunk  = { index, present: [u64; 16], dirty: [u64; 16], identity: hash? }
//! bytes(chunk) = concat(page(p) if present(p) else zeroes(4096))[..chunk_len]
//! ```
//!
//! An image captured from a live overlay shares the overlay's page store and
//! can always be read. An image decoded from a snapshot holds only the chunk
//! records; [`BlockOverlayImage::bind_source`] attaches a
//! [`BlockOverlayChunkSource`] that serves chunk bytes by identity. Every
//! chunk read from a source is authenticated against its identity and the
//! canonical chunk rules before use.

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::sync::Arc;

use super::overlay::{
    CowOverlay, OVERLAY_CHUNK_BYTES, OVERLAY_CHUNK_PAGES, OverlayChunk, PAGE_SIZE, page_base_at,
    store_error,
};
use super::page_store::{BlockPageStore, PageRef};
use crate::error::DeviceError;

const BITMAP_WORDS: usize = OVERLAY_CHUNK_PAGES / 64;

/// A bitmap over the 1,024 pages of one overlay chunk.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct ChunkPageBits([u64; BITMAP_WORDS]);

impl ChunkPageBits {
    /// Builds a bitmap from its little-endian word representation.
    ///
    /// Bit `b` of word `w` names page `64 * w + b` of the chunk.
    #[must_use]
    pub const fn from_words(words: [u64; BITMAP_WORDS]) -> Self {
        Self(words)
    }

    /// Returns the word representation described in [`Self::from_words`].
    #[must_use]
    pub const fn words(&self) -> [u64; BITMAP_WORDS] {
        self.0
    }

    /// Returns `true` when page `slot` is set.
    #[must_use]
    pub fn contains(&self, slot: usize) -> bool {
        slot < OVERLAY_CHUNK_PAGES && self.0[slot / 64] & (1 << (slot % 64)) != 0
    }

    /// Sets page `slot`; slots outside the chunk are ignored.
    pub fn insert(&mut self, slot: usize) {
        if slot < OVERLAY_CHUNK_PAGES {
            self.0[slot / 64] |= 1 << (slot % 64);
        }
    }

    /// Returns `true` when no page is set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.iter().all(|word| *word == 0)
    }

    /// Returns the number of pages set.
    #[must_use]
    pub fn count(&self) -> usize {
        self.0.iter().map(|word| word.count_ones() as usize).sum()
    }

    /// Returns `true` when every page set here is also set in `other`.
    #[must_use]
    pub fn is_subset(&self, other: &Self) -> bool {
        self.0
            .iter()
            .zip(other.0.iter())
            .all(|(mine, theirs)| mine & !theirs == 0)
    }

    /// Returns `true` when no page at or beyond `pages` is set.
    #[must_use]
    pub fn fits(&self, pages: usize) -> bool {
        (pages..OVERLAY_CHUNK_PAGES).all(|slot| !self.contains(slot))
    }

    /// Iterates the set page slots in ascending order.
    pub fn iter(self) -> impl Iterator<Item = usize> {
        (0..OVERLAY_CHUNK_PAGES).filter(move |slot| self.contains(*slot))
    }
}

impl fmt::Debug for ChunkPageBits {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ChunkPageBits({} pages)", self.count())
    }
}

/// One chunk record of a block overlay image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockOverlayChunk {
    /// The chunk index; the chunk covers bytes `[index * 4 MiB, (index + 1) * 4 MiB)`.
    pub index: u64,
    /// The BLAKE3 identity of the chunk's logical bytes, or `None` if all zero.
    pub identity: Option<[u8; 32]>,
    /// The copied-up pages in this chunk; never empty.
    pub present: ChunkPageBits,
    /// The pages dirtied since the last checkpoint boundary; a subset of `present`.
    pub dirty: ChunkPageBits,
}

/// A content-addressed reader of overlay chunk objects.
///
/// Implementations return the exact bytes of the object named `identity`.
/// The image authenticates every returned chunk, so a source need not.
pub trait BlockOverlayChunkSource: Send + Sync {
    /// Replaces `output` with the bytes of the object named `identity`.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the object is absent or cannot be read.
    fn read_chunk(&self, identity: [u8; 32], output: &mut Vec<u8>) -> io::Result<()>;
}

impl BlockOverlayChunkSource for BTreeMap<[u8; 32], Vec<u8>> {
    fn read_chunk(&self, identity: [u8; 32], output: &mut Vec<u8>) -> io::Result<()> {
        let bytes = self.get(&identity).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "block overlay chunk is absent")
        })?;
        output.clear();
        output.extend_from_slice(bytes);
        Ok(())
    }
}

#[derive(Clone)]
struct ImageChunk {
    present: ChunkPageBits,
    dirty: ChunkPageBits,
    content: ImageContent,
}

#[derive(Clone)]
enum ImageContent {
    /// Pages shared with the live overlay the image was frozen from.
    Live(Arc<OverlayChunk>),
    /// A decoded chunk known only by identity.
    Stored(Option<[u8; 32]>),
}

/// An immutable, chunked image of a block overlay.
///
/// See the [module documentation](self) for the representation. Equality
/// compares the device length and every chunk record, including chunk
/// identities; an image whose live pages cannot be read compares unequal.
#[derive(Clone)]
pub struct BlockOverlayImage {
    length: u64,
    chunks: BTreeMap<u64, ImageChunk>,
    source: Option<Arc<dyn BlockOverlayChunkSource>>,
}

impl BlockOverlayImage {
    /// Returns an empty image for a device of `length` bytes.
    #[must_use]
    pub fn empty(length: u64) -> Self {
        Self {
            length,
            chunks: BTreeMap::new(),
            source: None,
        }
    }

    pub(crate) fn from_live(
        length: u64,
        chunks: &BTreeMap<u64, Arc<OverlayChunk>>,
        dirty: &BTreeMap<u64, ChunkPageBits>,
    ) -> Self {
        let chunks = chunks
            .iter()
            .map(|(index, chunk)| {
                (
                    *index,
                    ImageChunk {
                        present: chunk.present(),
                        dirty: dirty.get(index).copied().unwrap_or_default(),
                        content: ImageContent::Live(Arc::clone(chunk)),
                    },
                )
            })
            .collect();
        Self {
            length,
            chunks,
            source: None,
        }
    }

    /// Builds an image from decoded chunk records.
    ///
    /// The records must be valid for a device of `length` bytes; the image
    /// has no chunk source until [`Self::bind_source`] attaches one.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::BlockOverlayImage`] when the records are not
    /// strictly ascending, name a chunk outside the device, have an empty
    /// present set, set pages beyond the device end, or mark a page dirty
    /// that is not present.
    pub fn from_chunks(
        length: u64,
        records: impl IntoIterator<Item = BlockOverlayChunk>,
    ) -> Result<Self, DeviceError> {
        let mut chunks = BTreeMap::new();
        let mut prior = None;
        for record in records {
            if prior.is_some_and(|prior| record.index <= prior) {
                return Err(invalid("chunk records are not strictly ascending"));
            }
            prior = Some(record.index);
            let chunk_length = chunk_length(length, record.index)
                .ok_or_else(|| invalid("chunk lies beyond the device"))?;
            let pages = chunk_length.div_ceil(PAGE_SIZE);
            if record.present.is_empty()
                || !record.present.fits(pages)
                || !record.dirty.is_subset(&record.present)
            {
                return Err(invalid("chunk page sets violate the chunk geometry"));
            }
            chunks.insert(
                record.index,
                ImageChunk {
                    present: record.present,
                    dirty: record.dirty,
                    content: ImageContent::Stored(record.identity),
                },
            );
        }
        Ok(Self {
            length,
            chunks,
            source: None,
        })
    }

    /// Returns a copy that keeps only the chunks overlapping `[offset, offset + length)`.
    ///
    /// Reads inside that range resolve exactly as they do through the full
    /// image; restoring the window touches at most the overlapping chunks.
    /// Use it for bounded read-only inspection, never as a continuation.
    #[must_use]
    pub fn window(&self, offset: u64, length: u64) -> Self {
        let first = offset / OVERLAY_CHUNK_BYTES;
        let end = offset.saturating_add(length).div_ceil(OVERLAY_CHUNK_BYTES);
        Self {
            length: self.length,
            chunks: self
                .chunks
                .range(first..end.max(first))
                .map(|(index, chunk)| (*index, chunk.clone()))
                .collect(),
            source: self.source.clone(),
        }
    }

    /// Attaches the content-addressed source that serves stored chunks.
    ///
    /// Chunks frozen from a live overlay keep reading their shared pages.
    pub fn bind_source(&mut self, source: Arc<dyn BlockOverlayChunkSource>) {
        self.source = Some(source);
    }

    /// Returns the device length in bytes the image covers.
    #[must_use]
    pub const fn length(&self) -> u64 {
        self.length
    }

    /// Returns the number of chunks holding at least one copied-up page.
    #[must_use]
    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
    }

    /// Returns the number of copied-up pages.
    #[must_use]
    pub fn page_count(&self) -> usize {
        self.chunks
            .values()
            .map(|chunk| chunk.present.count())
            .sum()
    }

    /// Returns the number of pages dirtied since the last checkpoint boundary.
    #[must_use]
    pub fn dirty_page_count(&self) -> usize {
        self.chunks.values().map(|chunk| chunk.dirty.count()).sum()
    }

    /// Returns the dirtied page bases in ascending order ([IO-7]).
    pub fn dirty_pages(&self) -> impl Iterator<Item = u64> + '_ {
        self.chunks.iter().flat_map(|(index, chunk)| {
            chunk
                .dirty
                .iter()
                .map(move |slot| page_base_at(*index, slot))
        })
    }

    /// Returns the copied-up page bases in ascending order.
    pub fn present_pages(&self) -> impl Iterator<Item = u64> + '_ {
        self.chunks.iter().flat_map(|(index, chunk)| {
            chunk
                .present
                .iter()
                .map(move |slot| page_base_at(*index, slot))
        })
    }

    /// Returns `true` when every stored chunk with content can be read.
    ///
    /// Live chunks are always readable; stored chunks need a bound source.
    #[must_use]
    pub fn is_readable(&self) -> bool {
        self.source.is_some()
            || self
                .chunks
                .values()
                .all(|chunk| !matches!(chunk.content, ImageContent::Stored(Some(_))))
    }

    /// Returns every chunk record, computing live chunk identities once.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::BlockPageStore`] when a live page cannot be read
    /// while its chunk identity is computed.
    pub fn chunks(&self) -> Result<Vec<BlockOverlayChunk>, DeviceError> {
        self.chunks
            .iter()
            .map(|(index, chunk)| {
                Ok(BlockOverlayChunk {
                    index: *index,
                    identity: self.identity(*index, chunk)?,
                    present: chunk.present,
                    dirty: chunk.dirty,
                })
            })
            .collect()
    }

    fn identity(&self, index: u64, chunk: &ImageChunk) -> Result<Option<[u8; 32]>, DeviceError> {
        match &chunk.content {
            ImageContent::Stored(identity) => Ok(*identity),
            ImageContent::Live(live) => live.identity(self.required_length(index)?),
        }
    }

    fn required_length(&self, index: u64) -> Result<usize, DeviceError> {
        chunk_length(self.length, index).ok_or_else(|| invalid("chunk lies beyond the device"))
    }

    /// Reads the logical bytes of chunk `index` into `output`.
    ///
    /// Returns the chunk identity, or `None` (with `output` left empty) for an
    /// all-zero chunk. Bytes read from a source are authenticated first.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::BlockOverlayImage`] when the image has no such
    /// chunk, no bound source, or the source returns non-canonical bytes, and
    /// [`DeviceError::BlockPageStore`] when a live page cannot be read.
    pub fn read_chunk(
        &self,
        index: u64,
        output: &mut Vec<u8>,
    ) -> Result<Option<[u8; 32]>, DeviceError> {
        output.clear();
        let chunk = self
            .chunks
            .get(&index)
            .ok_or_else(|| invalid("chunk is not present in the image"))?;
        let length = self.required_length(index)?;
        let Some(identity) = self.identity(index, chunk)? else {
            return Ok(None);
        };
        match &chunk.content {
            ImageContent::Live(live) => {
                output
                    .try_reserve_exact(length)
                    .map_err(|_| invalid("chunk buffer cannot be reserved"))?;
                live.visit_bytes(length, &mut |bytes| {
                    output.extend_from_slice(bytes);
                    Ok(())
                })?;
            }
            ImageContent::Stored(_) => {
                let source = self
                    .source
                    .as_ref()
                    .ok_or_else(|| invalid("stored chunk has no bound source"))?;
                source
                    .read_chunk(identity, output)
                    .map_err(|_| invalid("stored chunk cannot be read from its source"))?;
                authenticate_chunk(output, length, identity, chunk.present)?;
            }
        }
        Ok(Some(identity))
    }

    /// Authenticates every stored chunk through the bound source.
    ///
    /// At most one chunk is resident at a time. Live chunks need no check.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::read_chunk`] for the first failing chunk.
    pub fn verify(&self) -> Result<(), DeviceError> {
        let mut buffer = Vec::new();
        for (index, chunk) in &self.chunks {
            if matches!(chunk.content, ImageContent::Stored(Some(_))) {
                self.read_chunk(*index, &mut buffer)?;
            }
        }
        Ok(())
    }

    /// Rebuilds a live overlay whose new pages go to `store`.
    ///
    /// Live chunks are shared without copying. Stored chunks are read one at a
    /// time, authenticated, and their present pages written to `store`.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::read_chunk`], and
    /// [`DeviceError::BlockPageStore`] when `store` rejects a page.
    pub fn materialize_into(&self, store: &BlockPageStore) -> Result<CowOverlay, DeviceError> {
        let mut chunks = BTreeMap::new();
        let mut dirty = BTreeMap::new();
        let mut buffer = Vec::new();
        for (index, chunk) in &self.chunks {
            let rebuilt = match &chunk.content {
                ImageContent::Live(live) => Arc::clone(live),
                ImageContent::Stored(_) => {
                    let identity = self.read_chunk(*index, &mut buffer)?;
                    Arc::new(rebuild_chunk(store, &buffer, chunk.present, identity)?)
                }
            };
            chunks.insert(*index, rebuilt);
            if !chunk.dirty.is_empty() {
                dirty.insert(*index, chunk.dirty);
            }
        }
        Ok(CowOverlay::from_parts(store.clone(), chunks, dirty))
    }
}

/// Returns the logical byte length of chunk `index`, or `None` beyond the device.
pub(crate) fn chunk_length(length: u64, index: u64) -> Option<usize> {
    let start = index.checked_mul(OVERLAY_CHUNK_BYTES)?;
    if start >= length {
        return None;
    }
    // Bounded by the 4 MiB chunk size, so the narrowing is lossless.
    Some((length - start).min(OVERLAY_CHUNK_BYTES) as usize)
}

fn invalid(reason: &'static str) -> DeviceError {
    DeviceError::BlockOverlayImage { reason }
}

/// Checks a source chunk against its identity and the canonical chunk rules.
///
/// A canonical chunk has the exact logical length, hashes to its identity,
/// is not all zero (an all-zero chunk is recorded without identity), and is
/// zero wherever no page is present.
fn authenticate_chunk(
    bytes: &[u8],
    length: usize,
    identity: [u8; 32],
    present: ChunkPageBits,
) -> Result<(), DeviceError> {
    if bytes.len() != length {
        return Err(invalid("stored chunk has the wrong length"));
    }
    if *blake3::hash(bytes).as_bytes() != identity {
        return Err(invalid("stored chunk fails content authentication"));
    }
    let mut nonzero = false;
    for (slot, page) in bytes.chunks(PAGE_SIZE).enumerate() {
        let page_nonzero = page.iter().any(|byte| *byte != 0);
        if page_nonzero && !present.contains(slot) {
            return Err(invalid("stored chunk has bytes outside its present pages"));
        }
        nonzero |= page_nonzero;
    }
    if !nonzero {
        return Err(invalid("stored all-zero chunk carries an identity"));
    }
    Ok(())
}

fn rebuild_chunk(
    store: &BlockPageStore,
    bytes: &[u8],
    present: ChunkPageBits,
    identity: Option<[u8; 32]>,
) -> Result<OverlayChunk, DeviceError> {
    let mut pages: Vec<Option<PageRef>> = vec![None; OVERLAY_CHUNK_PAGES];
    let mut page = [0_u8; PAGE_SIZE];
    for slot in present.iter() {
        page.fill(0);
        // An all-zero chunk has no bytes; its present pages are zero pages.
        let start = slot * PAGE_SIZE;
        if start < bytes.len() {
            let end = (start + PAGE_SIZE).min(bytes.len());
            page[..end - start].copy_from_slice(&bytes[start..end]);
        }
        pages[slot] = Some(store.allocate(&page).map_err(store_error("write"))?);
    }
    Ok(OverlayChunk::from_pages(pages, present, identity))
}

impl PartialEq for BlockOverlayImage {
    fn eq(&self, other: &Self) -> bool {
        self.length == other.length
            && match (self.chunks(), other.chunks()) {
                (Ok(mine), Ok(theirs)) => mine == theirs,
                _ => false,
            }
    }
}

impl Eq for BlockOverlayImage {}

impl fmt::Debug for BlockOverlayImage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BlockOverlayImage")
            .field("length", &self.length)
            .field("chunks", &self.chunks.len())
            .field("pages", &self.page_count())
            .field("dirty_pages", &self.dirty_page_count())
            .field("readable", &self.is_readable())
            .finish()
    }
}
