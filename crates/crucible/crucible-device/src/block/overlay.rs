//! The read-only base image and its 4 KiB copy-on-write overlay.
//!
//! This module owns [`BaseImage`] (a content-addressed, never-mutated byte
//! array, [IO-5]) and [`CowOverlay`] (the page overlay layered over it). Reads
//! resolve each 4 KiB page from the overlay if present, else from the base;
//! writes copy the affected base page up into the overlay and patch it there;
//! the set of dirtied pages is tracked so a checkpoint can tell which pages
//! changed since its parent ([IO-7], [TEMP-15]).
//!
//! Overlay page bytes live in a [`BlockPageStore`], normally a private file in
//! the run's quota-accounted directory, not on the heap. The overlay itself
//! keeps only a page table grouped into 4 MiB chunks of 1,024 pages. Chunks
//! are reference counted: cloning an overlay (as every staged transaction
//! does) or freezing it into a snapshot copies the chunk table, not the pages,
//! and a later write copies only the touched chunk's table. Each chunk caches
//! its content identity, so unchanged chunks are never rehashed across
//! checkpoints.
//!
//! Page geometry is fixed at [`PAGE_SIZE`] = 4096 bytes and chunk geometry at
//! [`OVERLAY_CHUNK_BYTES`]. Every table is a [`BTreeMap`] keyed by chunk index,
//! so every capture and materialize pass visits pages in one deterministic
//! order ([IO-24]).
//!
//! ```text
//! page_index(off)  = off / 4096
//! chunk_index(off) = off / (4 MiB)
//! read(off, len):  for each page in [off, off+len):
//!                    overlay[page] if present else base[page]
//! write(off, data):for each page in [off, off+len):
//!                    shared or absent page -> store a patched copy
//!                    sole holder           -> patch the stored page in place
//!                    mark the page dirty
//! materialize(out):stream base bytes with every overlay page applied
//! ```

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::{Arc, OnceLock};

use super::overlay_image::{BlockOverlayImage, ChunkPageBits};
use super::page_store::{BlockPageStore, PageRef};
use crate::error::DeviceError;

/// The fixed copy-on-write page size in bytes (4 KiB).
pub const PAGE_SIZE: usize = 4096;

/// The fixed overlay chunk size in bytes (4 MiB).
///
/// It equals the exact-checkpoint artifact chunk size, so a block overlay
/// image uses the same sparse chunk geometry as a VM disk overlay.
pub const OVERLAY_CHUNK_BYTES: u64 = 4 * 1024 * 1024;

/// The number of 4 KiB pages in one overlay chunk.
pub const OVERLAY_CHUNK_PAGES: usize = (OVERLAY_CHUNK_BYTES / PAGE_SIZE as u64) as usize;

pub(crate) const PAGE_SIZE_U64: u64 = PAGE_SIZE as u64;

/// A read-only, content-addressed base disk image held in memory.
///
/// The base is **never mutated** by any device operation ([IO-5], [INV-5]); all
/// writes land in the [`CowOverlay`]. Its content hash is computed once at
/// construction and used to key the device's identity and to verify that a
/// restore stacks an overlay over the same parent. Clones share the bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BaseImage {
    bytes: Arc<[u8]>,
    hash: [u8; 32],
}

impl BaseImage {
    /// Wraps `bytes` as a read-only base image, hashing its content.
    ///
    /// The BLAKE3 content hash is the base's stable identity ([IO-5]); it is
    /// recomputed nowhere else, so the base bytes can never silently change
    /// identity.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        let hash = *blake3::hash(&bytes).as_bytes();
        Self {
            bytes: Arc::from(bytes),
            hash,
        }
    }

    /// Returns the base image length in bytes.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.bytes.len() as u64
    }

    /// Returns `true` when the base image is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Returns the BLAKE3 content hash of the base image.
    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }

    /// Returns the raw base bytes (read-only).
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Reads a single page-aligned 4 KiB page from the base, zero-padded.
    ///
    /// Bytes past the end of the base read back as zero, so a page that straddles
    /// the image tail is well-defined. `page_base` must be page-aligned.
    fn read_page(&self, page_base: u64) -> [u8; PAGE_SIZE] {
        let mut page = [0u8; PAGE_SIZE];
        let start = usize::try_from(page_base).unwrap_or(usize::MAX);
        if start < self.bytes.len() {
            let end = start.saturating_add(PAGE_SIZE).min(self.bytes.len());
            page[..end - start].copy_from_slice(&self.bytes[start..end]);
        }
        page
    }
}

/// The page base (page-aligned byte offset) containing byte `offset`.
#[must_use]
fn page_base_of(offset: u64) -> u64 {
    offset - (offset % PAGE_SIZE_U64)
}

/// Splits a page base into its chunk index and page slot within the chunk.
pub(crate) fn chunk_position(page_base: u64) -> (u64, usize) {
    let page_index = page_base / PAGE_SIZE_U64;
    let chunk_pages = OVERLAY_CHUNK_PAGES as u64;
    (
        page_index / chunk_pages,
        (page_index % chunk_pages) as usize,
    )
}

/// Returns the page base of `slot` in chunk `chunk`.
pub(crate) fn page_base_at(chunk: u64, slot: usize) -> u64 {
    chunk * OVERLAY_CHUNK_BYTES + slot as u64 * PAGE_SIZE_U64
}

/// Maps a page-store I/O error into the device taxonomy.
pub(crate) fn store_error(operation: &'static str) -> impl Fn(std::io::Error) -> DeviceError {
    move |error| DeviceError::BlockPageStore {
        operation,
        kind: error.kind(),
    }
}

/// One 4 MiB chunk of the overlay page table.
///
/// The identity cache holds the BLAKE3 identity of the chunk's logical bytes
/// (present pages, zeroes elsewhere, truncated to the device length), or
/// `None` when every byte is zero. Any mutation goes through
/// [`Arc::make_mut`] and clears the cache.
#[derive(Clone)]
pub(crate) struct OverlayChunk {
    pages: Vec<Option<PageRef>>,
    present: ChunkPageBits,
    identity: OnceLock<Option<[u8; 32]>>,
}

impl OverlayChunk {
    fn empty() -> Self {
        Self {
            pages: vec![None; OVERLAY_CHUNK_PAGES],
            present: ChunkPageBits::default(),
            identity: OnceLock::new(),
        }
    }

    /// Builds a chunk from stored pages whose identity is already known.
    pub(crate) fn from_pages(
        pages: Vec<Option<PageRef>>,
        present: ChunkPageBits,
        identity: Option<[u8; 32]>,
    ) -> Self {
        let cache = OnceLock::new();
        let _ = cache.set(identity);
        Self {
            pages,
            present,
            identity: cache,
        }
    }

    pub(crate) fn present(&self) -> ChunkPageBits {
        self.present
    }

    pub(crate) fn page(&self, slot: usize) -> Option<&PageRef> {
        self.pages.get(slot).and_then(Option::as_ref)
    }

    /// Returns the chunk's cached content identity, computing it once.
    ///
    /// `length` is the logical byte length of this chunk (shorter only for the
    /// final chunk of a device whose length is not a chunk multiple).
    pub(crate) fn identity(&self, length: usize) -> Result<Option<[u8; 32]>, DeviceError> {
        if let Some(identity) = self.identity.get() {
            return Ok(*identity);
        }
        let mut hasher = blake3::Hasher::new();
        let mut nonzero = false;
        self.visit_bytes(length, &mut |bytes| {
            nonzero |= bytes.iter().any(|byte| *byte != 0);
            hasher.update(bytes);
            Ok(())
        })?;
        let identity = nonzero.then(|| *hasher.finalize().as_bytes());
        let _ = self.identity.set(identity);
        Ok(identity)
    }

    /// Streams the chunk's logical bytes, one page at a time.
    pub(crate) fn visit_bytes(
        &self,
        length: usize,
        visit: &mut dyn FnMut(&[u8]) -> Result<(), DeviceError>,
    ) -> Result<(), DeviceError> {
        let zeroes = [0_u8; PAGE_SIZE];
        let mut page = [0_u8; PAGE_SIZE];
        let mut offset = 0;
        for slot in &self.pages {
            if offset >= length {
                break;
            }
            let span = (length - offset).min(PAGE_SIZE);
            match slot {
                Some(stored) => {
                    stored
                        .read_at(0, &mut page[..span])
                        .map_err(store_error("read"))?;
                    visit(&page[..span])?;
                }
                None => visit(&zeroes[..span])?,
            }
            offset += span;
        }
        Ok(())
    }

    fn set_page(&mut self, slot: usize, page: PageRef) {
        self.pages[slot] = Some(page);
        self.present.insert(slot);
        self.invalidate_identity();
    }

    fn invalidate_identity(&mut self) {
        self.identity = OnceLock::new();
    }
}

/// The copy-on-write overlay of 4 KiB pages over a base image.
///
/// A page is present only after a copy-up (a write touching it); reads of an
/// absent page fall through to the base. The dirty bitmap records pages
/// written since the last checkpoint boundary ([IO-7]).
///
/// Equality compares guest-visible content and bookkeeping: the present and
/// dirty page sets and every present page's bytes. Two overlays over
/// different page stores compare equal when their content matches. A page
/// that cannot be read from its store compares unequal.
#[derive(Clone)]
pub struct CowOverlay {
    store: BlockPageStore,
    chunks: BTreeMap<u64, Arc<OverlayChunk>>,
    dirty: BTreeMap<u64, ChunkPageBits>,
    page_count: usize,
}

impl Default for CowOverlay {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for CowOverlay {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CowOverlay")
            .field("store", &self.store)
            .field("chunks", &self.chunks.len())
            .field("page_count", &self.page_count)
            .field("dirty_pages", &self.dirty_page_count())
            .finish()
    }
}

impl CowOverlay {
    /// Creates an empty heap-backed overlay (every read falls through to the base).
    #[must_use]
    pub fn new() -> Self {
        Self::with_store(BlockPageStore::memory())
    }

    /// Creates an empty overlay whose copied-up pages go to `store`.
    #[must_use]
    pub fn with_store(store: BlockPageStore) -> Self {
        Self {
            store,
            chunks: BTreeMap::new(),
            dirty: BTreeMap::new(),
            page_count: 0,
        }
    }

    pub(crate) fn from_parts(
        store: BlockPageStore,
        chunks: BTreeMap<u64, Arc<OverlayChunk>>,
        dirty: BTreeMap<u64, ChunkPageBits>,
    ) -> Self {
        let page_count = chunks.values().map(|chunk| chunk.present().count()).sum();
        Self {
            store,
            chunks,
            dirty,
            page_count,
        }
    }

    /// Returns the store that receives this overlay's new pages.
    #[must_use]
    pub fn store(&self) -> &BlockPageStore {
        &self.store
    }

    /// Returns the number of copied-up pages held in the overlay.
    #[must_use]
    pub fn page_count(&self) -> usize {
        self.page_count
    }

    /// Returns the number of pages dirtied since the last checkpoint boundary.
    #[must_use]
    pub fn dirty_page_count(&self) -> usize {
        self.dirty.values().map(|bits| bits.count()).sum()
    }

    /// Returns the page bases dirtied since the last checkpoint boundary.
    ///
    /// The iteration order is ascending by page base ([IO-24]).
    pub fn dirty_pages(&self) -> impl Iterator<Item = u64> + '_ {
        self.dirty
            .iter()
            .flat_map(|(chunk, bits)| bits.iter().map(move |slot| page_base_at(*chunk, slot)))
    }

    /// Returns the page bases currently present in the overlay, ascending.
    pub fn present_pages(&self) -> impl Iterator<Item = u64> + '_ {
        self.chunks.iter().flat_map(|(chunk, pages)| {
            pages
                .present()
                .iter()
                .map(move |slot| page_base_at(*chunk, slot))
        })
    }

    /// Reads `len` bytes at `offset`, overlay page over base page.
    ///
    /// Each spanned 4 KiB page resolves from the overlay if copied up, else from
    /// the read-only base ([IO-5]). The base is never consulted for mutation.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::OutOfRange`] when `[offset, offset+len)` extends
    /// past the device length ([IO-6]); the read never truncates or extends.
    /// Returns [`DeviceError::BlockPageStore`] when a stored page cannot be read.
    pub fn read(&self, base: &BaseImage, offset: u64, len: u64) -> Result<Vec<u8>, DeviceError> {
        let end = checked_range_end(offset, len, base.len())?;
        let length = usize::try_from(len).map_err(|_| DeviceError::OutOfRange {
            offset,
            len,
            device_len: base.len(),
        })?;
        let mut out = vec![0_u8; length];
        let mut cursor = offset;
        let mut written = 0usize;
        while cursor < end {
            let pb = page_base_of(cursor);
            let page_off = (cursor - pb) as usize;
            let take = (PAGE_SIZE - page_off).min((end - cursor) as usize);
            let target = &mut out[written..written + take];
            match self.stored_page(pb) {
                Some(page) => page
                    .read_at(page_off, target)
                    .map_err(store_error("read"))?,
                None => target.copy_from_slice(&base.read_page(pb)[page_off..page_off + take]),
            }
            cursor += take as u64;
            written += take;
        }
        Ok(out)
    }

    /// Writes `data` at `offset`, copying affected base pages up first.
    ///
    /// Each spanned page is copied up from the base into the overlay (if not
    /// already present) and patched; every touched page base is marked dirty
    /// ([IO-5], [IO-7]). The base image is never written. A page still shared
    /// with a clone or snapshot is copied rather than patched in place, so the
    /// other holders keep their exact prior bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::OutOfRange`] when `[offset, offset+data.len())`
    /// extends past the device length ([IO-6]), and
    /// [`DeviceError::BlockPageStore`] when the page store fails. A store
    /// failure may leave earlier pages of a multi-page write applied; callers
    /// stage writes on a clone and discard it on error.
    pub fn write(&mut self, base: &BaseImage, offset: u64, data: &[u8]) -> Result<(), DeviceError> {
        let len = data.len() as u64;
        let end = checked_range_end(offset, len, base.len())?;
        let mut cursor = offset;
        let mut src = 0usize;
        while cursor < end {
            let pb = page_base_of(cursor);
            let page_off = (cursor - pb) as usize;
            let take = (PAGE_SIZE - page_off).min((end - cursor) as usize);
            self.write_page(base, pb, page_off, &data[src..src + take])?;
            cursor += take as u64;
            src += take;
        }
        Ok(())
    }

    fn write_page(
        &mut self,
        base: &BaseImage,
        page_base: u64,
        page_off: usize,
        bytes: &[u8],
    ) -> Result<(), DeviceError> {
        let (chunk_index, slot) = chunk_position(page_base);
        let chunk = Arc::make_mut(
            self.chunks
                .entry(chunk_index)
                .or_insert_with(|| Arc::new(OverlayChunk::empty())),
        );
        match &mut chunk.pages[slot] {
            Some(stored) => {
                if !stored
                    .patch_if_unique(page_off, bytes)
                    .map_err(store_error("write"))?
                {
                    let mut copy = stored.read_page().map_err(store_error("read"))?;
                    copy[page_off..page_off + bytes.len()].copy_from_slice(bytes);
                    *stored = self.store.allocate(&copy).map_err(store_error("write"))?;
                }
                chunk.invalidate_identity();
            }
            None => {
                let mut copy = base.read_page(page_base);
                copy[page_off..page_off + bytes.len()].copy_from_slice(bytes);
                let page = self.store.allocate(&copy).map_err(store_error("write"))?;
                chunk.set_page(slot, page);
                self.page_count += 1;
            }
        }
        self.dirty.entry(chunk_index).or_default().insert(slot);
        Ok(())
    }

    fn stored_page(&self, page_base: u64) -> Option<&PageRef> {
        let (chunk, slot) = chunk_position(page_base);
        self.chunks.get(&chunk).and_then(|chunk| chunk.page(slot))
    }

    /// Clears the dirty set at a checkpoint boundary, after the snapshot is taken.
    ///
    /// Successive checkpoints then see disjoint dirty sets ([IO-7]). The
    /// copied-up pages themselves remain in the overlay; only the dirty
    /// bookkeeping is reset.
    pub fn clear_dirty(&mut self) {
        self.dirty.clear();
    }

    /// Freezes the overlay into an immutable snapshot image.
    ///
    /// The image shares this overlay's chunk tables and pages; it copies no
    /// page bytes. `length` is the device length in bytes.
    #[must_use]
    pub fn freeze(&self, length: u64) -> BlockOverlayImage {
        BlockOverlayImage::from_live(length, &self.chunks, &self.dirty)
    }

    /// Streams the full current disk image to `output`: base bytes with every
    /// overlay page applied on top.
    ///
    /// This is the materialize-to-image hand-off ([IO-12]): the output is a
    /// standalone raw image a real-time QEMU can mount. The base image is
    /// **not** mutated, and no full-device buffer is allocated ([INV-5]).
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::BlockPageStore`] when a stored page cannot be
    /// read or `output` rejects a write.
    pub fn materialize_to(
        &self,
        base: &BaseImage,
        output: &mut dyn Write,
    ) -> Result<(), DeviceError> {
        let length = base.len();
        let mut page = [0_u8; PAGE_SIZE];
        let mut page_base = 0_u64;
        while page_base < length {
            // Bounded by PAGE_SIZE, so the narrowing is lossless.
            let span = (length - page_base).min(PAGE_SIZE_U64) as usize;
            match self.stored_page(page_base) {
                Some(stored) => stored
                    .read_at(0, &mut page[..span])
                    .map_err(store_error("read"))?,
                None => page[..span].copy_from_slice(&base.read_page(page_base)[..span]),
            }
            output
                .write_all(&page[..span])
                .map_err(store_error("materialize"))?;
            page_base += PAGE_SIZE_U64;
        }
        Ok(())
    }

    fn content_eq(&self, other: &Self) -> bool {
        if self.page_count != other.page_count
            || self.dirty != other.dirty
            || self.chunks.len() != other.chunks.len()
        {
            return false;
        }
        self.chunks
            .iter()
            .zip(&other.chunks)
            .all(|((left_index, left), (right_index, right))| {
                left_index == right_index
                    && (Arc::ptr_eq(left, right) || chunk_content_eq(left, right))
            })
    }
}

fn chunk_content_eq(left: &OverlayChunk, right: &OverlayChunk) -> bool {
    if left.present() != right.present() {
        return false;
    }
    left.present()
        .iter()
        .all(|slot| match (left.page(slot), right.page(slot)) {
            (Some(a), Some(b)) if a.ptr_eq(b) => true,
            (Some(a), Some(b)) => matches!(
                (a.read_page(), b.read_page()),
                (Ok(a), Ok(b)) if a == b
            ),
            _ => false,
        })
}

impl PartialEq for CowOverlay {
    fn eq(&self, other: &Self) -> bool {
        self.content_eq(other)
    }
}

impl Eq for CowOverlay {}

/// Returns the exclusive end of `[offset, offset+len)`, range-checked.
///
/// # Errors
///
/// Returns [`DeviceError::OutOfRange`] when the range overflows `u64` or extends
/// past `device_len` ([IO-6]). A zero-length range at exactly `device_len` is
/// in range.
fn checked_range_end(offset: u64, len: u64, device_len: u64) -> Result<u64, DeviceError> {
    let end = offset.checked_add(len).ok_or(DeviceError::OutOfRange {
        offset,
        len,
        device_len,
    })?;
    if end > device_len {
        return Err(DeviceError::OutOfRange {
            offset,
            len,
            device_len,
        });
    }
    Ok(end)
}
