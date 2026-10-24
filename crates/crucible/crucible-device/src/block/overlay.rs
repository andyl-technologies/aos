//! The read-only base image and its in-memory 4 KiB copy-on-write overlay.
//!
//! This module owns [`BaseImage`] (a content-addressed, never-mutated byte
//! array, [IO-5]) and [`CowOverlay`] (the in-memory page overlay layered over
//! it). Reads resolve each 4 KiB page from the overlay if present, else from the
//! base; writes copy the affected base page up into the overlay and patch it
//! there; the set of dirtied pages is tracked so a checkpoint captures only the
//! delta dirtied since its parent ([IO-7], [TEMP-15]).
//!
//! Page geometry is fixed at [`PAGE_SIZE`] = 4096 bytes. The overlay keys pages
//! by their **page base** (the page-aligned byte offset) in a [`BTreeMap`] so
//! every captured delta and every materialize pass iterates pages in a single
//! deterministic order ([IO-24]) — never a default-hasher order.
//!
//! ```text
//! page_index(off) = off / 4096
//! page_base(off)  = page_index * 4096
//! read(off, len):  for each page in [off, off+len):
//!                    overlay[page] if present else base[page]
//! write(off, data):for each page in [off, off+len):
//!                    overlay.entry(base).or_insert(base_page_or_zero(base));
//!                    patch the page; dirty.insert(base)
//! materialize():   base bytes, then overwrite each overlay page on top
//! ```

use std::collections::{BTreeMap, BTreeSet};

use crate::error::DeviceError;

/// The fixed copy-on-write page size in bytes (4 KiB).
pub const PAGE_SIZE: usize = 4096;

/// A read-only, content-addressed base disk image held in memory.
///
/// The base is **never mutated** by any device operation ([IO-5], [INV-5]); all
/// writes land in the [`CowOverlay`]. Its content hash is computed once at
/// construction and used to key the device's identity and to verify that a
/// restore stacks an overlay over the same parent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BaseImage {
    bytes: Vec<u8>,
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
        Self { bytes, hash }
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
        let start = page_base as usize;
        if start < self.bytes.len() {
            let end = start.saturating_add(PAGE_SIZE).min(self.bytes.len());
            let span = end - start;
            page[..span].copy_from_slice(&self.bytes[start..end]);
        }
        page
    }
}

/// The page base (page-aligned byte offset) containing byte `offset`.
#[must_use]
fn page_base_of(offset: u64) -> u64 {
    offset - (offset % PAGE_SIZE as u64)
}

/// The in-memory copy-on-write overlay of 4 KiB pages over a base image.
///
/// Each entry maps a page base to its full 4 KiB page bytes. A page is present
/// only after a copy-up (a write touching it); reads of an absent page fall
/// through to the base. The `dirty` set records pages written since the last
/// checkpoint boundary so the next snapshot captures a disjoint delta ([IO-7]).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct CowOverlay {
    /// Copied-up pages keyed by page base, in deterministic ascending order.
    pages: BTreeMap<u64, [u8; PAGE_SIZE]>,
    /// Page bases dirtied since the last checkpoint boundary ([IO-7]).
    dirty: BTreeSet<u64>,
}

impl CowOverlay {
    /// Creates an empty overlay (every read falls through to the base).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of copied-up pages held in the overlay.
    #[must_use]
    pub fn page_count(&self) -> usize {
        self.pages.len()
    }

    /// Returns the page bases dirtied since the last checkpoint boundary.
    ///
    /// The iteration order is ascending by page base ([IO-24]).
    #[must_use]
    pub fn dirty_pages(&self) -> &BTreeSet<u64> {
        &self.dirty
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
    pub fn read(&self, base: &BaseImage, offset: u64, len: u64) -> Result<Vec<u8>, DeviceError> {
        let end = checked_range_end(offset, len, base.len())?;
        let mut out = Vec::with_capacity(len as usize);
        let mut cursor = offset;
        while cursor < end {
            let pb = page_base_of(cursor);
            let page_off = (cursor - pb) as usize;
            let take = (PAGE_SIZE - page_off).min((end - cursor) as usize);
            match self.pages.get(&pb) {
                Some(page) => out.extend_from_slice(&page[page_off..page_off + take]),
                None => {
                    let page = base.read_page(pb);
                    out.extend_from_slice(&page[page_off..page_off + take]);
                }
            }
            cursor += take as u64;
        }
        Ok(out)
    }

    /// Writes `data` at `offset`, copying affected base pages up first.
    ///
    /// Each spanned page is copied up from the base into the overlay (if not
    /// already present) and patched in place; every touched page base is marked
    /// dirty ([IO-5], [IO-7]). The base image is never written.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::OutOfRange`] when `[offset, offset+data.len())`
    /// extends past the device length ([IO-6]).
    pub fn write(&mut self, base: &BaseImage, offset: u64, data: &[u8]) -> Result<(), DeviceError> {
        let len = data.len() as u64;
        let end = checked_range_end(offset, len, base.len())?;
        let mut cursor = offset;
        let mut src = 0usize;
        while cursor < end {
            let pb = page_base_of(cursor);
            let page_off = (cursor - pb) as usize;
            let take = (PAGE_SIZE - page_off).min((end - cursor) as usize);
            // Copy-up: materialize the page from the base on first touch.
            let page = self.pages.entry(pb).or_insert_with(|| base.read_page(pb));
            page[page_off..page_off + take].copy_from_slice(&data[src..src + take]);
            self.dirty.insert(pb);
            cursor += take as u64;
            src += take;
        }
        Ok(())
    }

    /// Returns the delta of pages dirtied since the last checkpoint boundary.
    ///
    /// The returned map holds *only* the dirty pages (a disjoint successor-
    /// checkpoint delta, [IO-7]/[TEMP-15]), keyed by page base in ascending
    /// order, alongside each page's BLAKE3 content hash for dedup ([TEMP-16]).
    #[must_use]
    pub fn dirty_delta(&self) -> OverlayDelta {
        let mut pages = BTreeMap::new();
        for &pb in &self.dirty {
            if let Some(page) = self.pages.get(&pb) {
                pages.insert(pb, *page);
            }
        }
        OverlayDelta { pages }
    }

    /// Returns every live overlay page, regardless of dirty state.
    ///
    /// Used by [`CowOverlay::materialize`] and by a full (non-delta) snapshot.
    /// Ordered ascending by page base ([IO-24]).
    #[must_use]
    pub fn all_pages(&self) -> &BTreeMap<u64, [u8; PAGE_SIZE]> {
        &self.pages
    }

    /// Clears the dirty set at a checkpoint boundary, after the delta is taken.
    ///
    /// Successive checkpoints then capture disjoint deltas ([IO-7]). The copied-
    /// up pages themselves remain in the overlay; only the dirty bookkeeping is
    /// reset.
    pub fn clear_dirty(&mut self) {
        self.dirty.clear();
    }

    /// Replaces the dirty page set verbatim (the restore step, [IO-7]).
    ///
    /// Restore uses this to reinstate the exact dirty bookkeeping a snapshot
    /// captured, so the next checkpoint emits the same delta an uninterrupted run
    /// would. It does not touch the copied-up pages.
    pub fn set_dirty(&mut self, dirty: BTreeSet<u64>) {
        self.dirty = dirty;
    }

    /// Stacks a delta's pages on top of this overlay (the restore step).
    ///
    /// Each page in `delta` overwrites or inserts the corresponding overlay
    /// page; the applied pages are *not* marked dirty (they already belong to
    /// the parent-plus-delta materialized state, [IO-11]).
    pub fn apply_delta(&mut self, delta: &OverlayDelta) {
        for (&pb, page) in &delta.pages {
            self.pages.insert(pb, *page);
        }
    }

    /// Produces the full current disk image: base bytes with every overlay page
    /// applied on top.
    ///
    /// This is the materialize-to-image hand-off ([IO-12]): the returned `Vec`
    /// is a standalone raw image a real-time QEMU can mount. The base image is
    /// **not** mutated — the bytes are copied first, then overlay pages overwrite
    /// their ranges ([INV-5]).
    ///
    /// # Panics
    ///
    /// In debug builds, panics via `debug_assert!` if an overlay page base lies
    /// beyond the image length — an invariant violation, since [`CowOverlay::write`]
    /// range-checks every copy-up against the base length so no out-of-bounds
    /// page can be created. In release builds the stray page is skipped rather
    /// than producing an out-of-bounds image, keeping the QEMU hand-off safe.
    #[must_use]
    pub fn materialize(&self, base: &BaseImage) -> Vec<u8> {
        let mut image = base.bytes().to_vec();
        for (&pb, page) in &self.pages {
            let start = pb as usize;
            debug_assert!(
                start < image.len(),
                "overlay page base {start} lies beyond image length {}; \
                 a copy-up must be range-checked against the base ([IO-12])",
                image.len()
            );
            if start >= image.len() {
                continue;
            }
            let span = (image.len() - start).min(PAGE_SIZE);
            image[start..start + span].copy_from_slice(&page[..span]);
        }
        image
    }

    /// Reconstructs an overlay from its full page set and dirty set.
    ///
    /// Used by snapshot restore: the captured pages and dirty bookkeeping are
    /// stacked verbatim ([IO-11]).
    #[must_use]
    pub fn from_parts(pages: BTreeMap<u64, [u8; PAGE_SIZE]>, dirty: BTreeSet<u64>) -> Self {
        Self { pages, dirty }
    }
}

/// A copy-on-write delta: the pages dirtied since a parent checkpoint.
///
/// Keyed by page base in deterministic ascending order ([IO-24]). This is the
/// device half of a `MaterializedState` overlay contribution ([IO-11]); it never
/// carries the base image ([TEMP-9]).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct OverlayDelta {
    /// The dirtied pages keyed by page base, ascending.
    pub pages: BTreeMap<u64, [u8; PAGE_SIZE]>,
}

impl OverlayDelta {
    /// Returns the BLAKE3 hash of each delta page, keyed by page base.
    ///
    /// The per-page content hash is what the temporal graph uses to deduplicate
    /// identical pages across checkpoints ([IO-11], [TEMP-16]).
    #[must_use]
    pub fn page_hashes(&self) -> BTreeMap<u64, [u8; 32]> {
        self.pages
            .iter()
            .map(|(&pb, page)| (pb, *blake3::hash(page).as_bytes()))
            .collect()
    }
}

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
