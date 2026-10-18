//! SPDX-License-Identifier: MIT OR Apache-2.0
//! Retains independent, bounded dirty obligations and coherent page-version receipts.
//!
//! Writers mark candidate pages without hashing. Captures own immutable versions;
//! acknowledging one consumer never clears another, nor a write after capture.
//! The caller holds its admitted writer barrier while marking/capturing and
//! acknowledges only after that consumer's publication/durability contract.
//! Fork and restore use distinct tracking incarnations and private mutable state.

use crate::budget::Reservation;
use crate::{MetadataBudget, RamError, RegionClass, Topology};
use std::collections::BTreeMap;
use std::sync::Arc;

// Sparse chunks amortize version and consumer bits without reserving a dense
// guest-sized array. The map charge covers a whole sparse B-tree node rather
// than just its key/value pair; each chunk owns its fixed page-state array.
const CHUNK_PAGES: usize = 128;
const CHUNK_CHARGE: u64 = 512 + (CHUNK_PAGES * std::mem::size_of::<PageState>()) as u64;

#[derive(Clone, Copy, Debug)]
struct PageState {
    version: PageVersion,
    pending: u8,
}

#[derive(Clone, Debug)]
struct PageChunk {
    pages: Box<[PageState; CHUNK_PAGES]>,
    pending: [u16; 4],
}

impl PageState {
    const CLEAN: Self = Self {
        version: PageVersion(0),
        pending: 0,
    };
}

fn chunk_key(coordinate: PageCoordinate) -> PageCoordinate {
    PageCoordinate {
        region_index: coordinate.region_index,
        page_index: coordinate.page_index / CHUNK_PAGES as u64,
    }
}

/// A page coordinate bound to the canonical inventory of its tracker.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PageCoordinate {
    /// Region position in the complete sorted inventory, including omitted scopes.
    pub region_index: u32,
    /// Logical page position in that region.
    pub page_index: u64,
}

/// An operational content generation, excluded from all logical hash preimages.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PageVersion(u64);

impl PageVersion {
    /// Returns the operational generation counter; zero denotes initialized content.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A caller-owned unique tracking incarnation, independent of logical identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrackingIncarnation([u8; 16]);

impl TrackingIncarnation {
    /// Establishes an operational identity supplied by the VM lifecycle owner.
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the public fixed-width incarnation bytes.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// An independently acknowledged dirty consumer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Consumer {
    /// Coherent fingerprint publication.
    Fingerprint = 0,
    /// Durable exact-checkpoint publication and matching commit.
    Checkpoint = 1,
    /// Authoritative preservation/writeback of a page version.
    Paging = 2,
    /// Destination possession acknowledged by the transfer protocol.
    Transfer = 3,
}

/// Explicit sparse ledger and capture bounds, independent of guest RAM capacity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrackingLimits {
    /// Maximum distinct pages retaining nonzero operational versions.
    pub max_versioned_pages: usize,
    /// Maximum aggregate dirty entries across the four consumers.
    pub max_dirty_entries: usize,
    /// Maximum pages in one immutable capture.
    pub max_capture_pages: usize,
}

impl Default for TrackingLimits {
    fn default() -> Self {
        Self {
            max_versioned_pages: 1_048_576,
            max_dirty_entries: 4_194_304,
            max_capture_pages: 1_048_576,
        }
    }
}

#[derive(Debug)]
struct Identity;

#[derive(Debug)]
struct CaptureInner {
    identity: Arc<Identity>,
    incarnation: TrackingIncarnation,
    consumer: Consumer,
    sequence: u64,
    entries: Vec<(PageCoordinate, PageVersion)>,
    _charge: Reservation,
}

/// An immutable consumer-specific set of page versions captured under a coherent barrier.
///
/// Clones share one bounded allocation. Receipts are local ownership objects;
/// public process protocols must encode their own checked portable records.
#[derive(Clone, Debug)]
pub struct DirtyCapture {
    inner: Arc<CaptureInner>,
}

impl DirtyCapture {
    /// Returns the tracking incarnation associated with this capture.
    pub fn incarnation(&self) -> TrackingIncarnation {
        self.inner.incarnation
    }

    /// Returns the independent consumer that may acknowledge this receipt.
    pub fn consumer(&self) -> Consumer {
        self.inner.consumer
    }

    /// Returns the monotonic capture sequence within this consumer incarnation.
    pub fn sequence(&self) -> u64 {
        self.inner.sequence
    }

    /// Returns canonical coordinates and frozen candidate versions.
    pub fn entries(&self) -> &[(PageCoordinate, PageVersion)] {
        &self.inner.entries
    }
}

/// A private multi-consumer dirty ledger with checked monotonic page versions.
#[derive(Debug)]
pub struct DirtyTracker {
    topology: Topology,
    incarnation: TrackingIncarnation,
    identity: Arc<Identity>,
    limits: TrackingLimits,
    budget: MetadataBudget,
    chunks: BTreeMap<PageCoordinate, PageChunk>,
    versioned_pages: usize,
    pending: [usize; 4],
    sequences: [u64; 4],
    acknowledged: [u64; 4],
    charge: Reservation,
}

impl DirtyTracker {
    /// Establishes clean initialized content under a new lifecycle incarnation.
    ///
    /// Restore must first authenticate the installed content or rebuild its
    /// identity. Construction alone does not establish that content or execution
    /// authority. Existing receipts cannot acknowledge a new tracker.
    ///
    /// # Errors
    ///
    /// Returns [`RamError::ResourceLimit`] if fixed ledger metadata cannot be admitted.
    pub fn new(
        topology: Topology,
        incarnation: TrackingIncarnation,
        limits: TrackingLimits,
        budget: &MetadataBudget,
    ) -> Result<Self, RamError> {
        let charge = budget.reserve((std::mem::size_of::<Self>() + 64) as u64)?;
        Ok(Self {
            topology,
            incarnation,
            identity: Arc::new(Identity),
            limits,
            budget: budget.clone(),
            chunks: BTreeMap::new(),
            versioned_pages: 0,
            pending: [0; 4],
            sequences: [0; 4],
            acknowledged: [0; 4],
            charge,
        })
    }

    /// Returns the complete inventory to which coordinates are bound.
    pub fn topology(&self) -> &Topology {
        &self.topology
    }

    /// Returns the current operational tracking incarnation.
    pub const fn incarnation(&self) -> TrackingIncarnation {
        self.incarnation
    }

    /// Returns a page's latest operational version, including clean initialization.
    ///
    /// # Errors
    ///
    /// Returns [`RamError::OutOfRange`] for coordinates outside the inventory.
    pub fn page_version(&self, coordinate: PageCoordinate) -> Result<PageVersion, RamError> {
        self.validate_coordinate(coordinate, false)?;
        Ok(self.state(coordinate).version)
    }

    /// Marks one potentially changed page for all independent consumers.
    ///
    /// # Errors
    ///
    /// Returns errors from [`Self::mark_pages`]. No page bytes are hashed.
    pub fn mark_page(&mut self, coordinate: PageCoordinate) -> Result<(), RamError> {
        self.mark_pages(&[coordinate])
    }

    /// Atomically marks a unique batch of page coordinates without hashing stores.
    ///
    /// Every admitted write advances its operational version, including writes
    /// that retain or restore the same bytes. Version equality cannot therefore
    /// authorize stale preservation completion. Callers may coalesce stores only
    /// while excluding outstanding coherent-version readers themselves.
    ///
    /// # Errors
    ///
    /// Returns [`RamError`] for invalid/immutable coordinates, duplicates, counter
    /// overflow, allocation failure, or ledger/budget exhaustion. On rejection,
    /// all versions and consumer obligations remain unchanged.
    pub fn mark_pages(&mut self, coordinates: &[PageCoordinate]) -> Result<(), RamError> {
        if coordinates.is_empty() {
            return Ok(());
        }
        if coordinates.len() > self.limits.max_versioned_pages {
            return Err(RamError::ResourceLimit);
        }
        let work_bytes = coordinates
            .len()
            .checked_mul(std::mem::size_of::<(PageCoordinate, PageVersion)>())
            .ok_or(RamError::Overflow)?;
        let _work = self.budget.reserve(work_bytes as u64)?;
        let mut next = Vec::new();
        next.try_reserve_exact(coordinates.len())
            .map_err(|_| RamError::Allocation)?;
        for coordinate in coordinates {
            self.validate_coordinate(*coordinate, true)?;
            let state = self.state(*coordinate);
            next.push((
                *coordinate,
                PageVersion(state.version.0.checked_add(1).ok_or(RamError::Overflow)?),
            ));
        }
        next.sort_unstable_by_key(|(coordinate, _)| *coordinate);
        if next.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(RamError::InvalidOrder);
        }

        let mut versioned_pages = self.versioned_pages;
        let mut pending = self.pending;
        let mut additional_chunks = 0_u64;
        let mut previous_chunk = None;
        for (coordinate, _) in &next {
            let state = self.state(*coordinate);
            if state.version.0 == 0 {
                versioned_pages = versioned_pages.checked_add(1).ok_or(RamError::Overflow)?;
            }
            for (index, count) in pending.iter_mut().enumerate() {
                if state.pending & (1 << index) == 0 {
                    *count = count.checked_add(1).ok_or(RamError::Overflow)?;
                }
            }
            let chunk = chunk_key(*coordinate);
            if previous_chunk != Some(chunk) && !self.chunks.contains_key(&chunk) {
                additional_chunks += 1;
            }
            previous_chunk = Some(chunk);
        }
        let dirty_count = pending.iter().try_fold(0_usize, |total, count| {
            total.checked_add(*count).ok_or(RamError::Overflow)
        })?;
        if versioned_pages > self.limits.max_versioned_pages
            || dirty_count > self.limits.max_dirty_entries
        {
            return Err(RamError::ResourceLimit);
        }
        self.charge.grow(
            additional_chunks
                .checked_mul(CHUNK_CHARGE)
                .ok_or(RamError::Overflow)?,
        )?;
        for (coordinate, version) in next {
            let chunk = self
                .chunks
                .entry(chunk_key(coordinate))
                .or_insert_with(|| PageChunk {
                    pages: Box::new([PageState::CLEAN; CHUNK_PAGES]),
                    pending: [0; 4],
                });
            let state = &mut chunk.pages[coordinate.page_index as usize % CHUNK_PAGES];
            for (index, count) in chunk.pending.iter_mut().enumerate() {
                if state.pending & (1 << index) == 0 {
                    *count += 1;
                }
            }
            *state = PageState {
                version,
                pending: 15,
            };
        }
        self.versioned_pages = versioned_pages;
        self.pending = pending;
        Ok(())
    }

    /// Marks every logical page intersecting an admitted region-relative byte write.
    ///
    /// # Errors
    ///
    /// Returns [`RamError`] for unknown regions, out-of-range/overflowing byte
    /// ranges, immutable regions, or bounds/allocation failures. Empty ranges
    /// within an existing region perform no mutation.
    pub fn mark_range(
        &mut self,
        region_id: &str,
        offset: u64,
        length: u64,
    ) -> Result<(), RamError> {
        let region_index = self
            .topology
            .regions()
            .binary_search_by(|region| region.id().as_bytes().cmp(region_id.as_bytes()))
            .map_err(|_| RamError::OutOfRange)?;
        let region = &self.topology.regions()[region_index];
        let end = offset.checked_add(length).ok_or(RamError::Overflow)?;
        if end > region.logical_length() {
            return Err(RamError::OutOfRange);
        }
        if length == 0 {
            return Ok(());
        }
        let first = offset / 4096;
        let last = (end - 1) / 4096;
        let count = usize::try_from(last - first + 1).map_err(|_| RamError::ResourceLimit)?;
        if count > self.limits.max_versioned_pages {
            return Err(RamError::ResourceLimit);
        }
        let _work = self.budget.reserve(
            count
                .checked_mul(std::mem::size_of::<PageCoordinate>())
                .ok_or(RamError::Overflow)? as u64,
        )?;
        let mut coordinates = Vec::new();
        coordinates
            .try_reserve_exact(count)
            .map_err(|_| RamError::Allocation)?;
        for page_index in first..=last {
            coordinates.push(PageCoordinate {
                region_index: region_index as u32,
                page_index,
            });
        }
        self.mark_pages(&coordinates)
    }

    /// Captures candidate versions for one consumer without clearing obligations.
    ///
    /// # Errors
    ///
    /// Returns [`RamError`] for capture/budget exhaustion, allocation failure, or
    /// sequence overflow. Failed captures do not rotate or acknowledge a baseline.
    pub fn capture(&mut self, consumer: Consumer) -> Result<DirtyCapture, RamError> {
        let index = consumer as usize;
        let count = self.pending[index];
        if count > self.limits.max_capture_pages {
            return Err(RamError::ResourceLimit);
        }
        let sequence = self.sequences[index]
            .checked_add(1)
            .ok_or(RamError::Overflow)?;
        let bytes = count
            .checked_mul(std::mem::size_of::<(PageCoordinate, PageVersion)>())
            .and_then(|value| value.checked_add(std::mem::size_of::<CaptureInner>() + 64))
            .ok_or(RamError::Overflow)?;
        let charge = self.budget.reserve(bytes as u64)?;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(count)
            .map_err(|_| RamError::Allocation)?;
        for (key, chunk) in &self.chunks {
            if chunk.pending[index] == 0 {
                continue;
            }
            for (offset, state) in chunk.pages.iter().enumerate() {
                if state.pending & (1 << index) != 0 {
                    entries.push((
                        PageCoordinate {
                            region_index: key.region_index,
                            page_index: key.page_index * CHUNK_PAGES as u64 + offset as u64,
                        },
                        state.version,
                    ));
                }
            }
        }
        if entries.len() != count {
            return Err(RamError::InvalidEncoding);
        }
        let capture = DirtyCapture {
            inner: Arc::new(CaptureInner {
                identity: self.identity.clone(),
                incarnation: self.incarnation,
                consumer,
                sequence,
                entries,
                _charge: charge,
            }),
        };
        self.sequences[index] = sequence;
        Ok(capture)
    }

    /// Acknowledges successfully published versions for exactly one consumer.
    ///
    /// Writers after capture retain their newer obligations. The caller must
    /// first satisfy fingerprint publication, checkpoint durability, preservation,
    /// or destination possession; this ledger does not supply that authority.
    ///
    /// # Errors
    ///
    /// Returns [`RamError::StaleReceipt`] for another tracker/incarnation, duplicate
    /// acknowledgement, or receipt older than the already accepted baseline.
    pub fn acknowledge(&mut self, capture: &DirtyCapture) -> Result<(), RamError> {
        let index = capture.inner.consumer as usize;
        if !Arc::ptr_eq(&capture.inner.identity, &self.identity)
            || capture.inner.incarnation != self.incarnation
            || capture.inner.sequence <= self.acknowledged[index]
            || capture.inner.sequence > self.sequences[index]
        {
            return Err(RamError::StaleReceipt);
        }
        for (coordinate, version) in &capture.inner.entries {
            if let Some(chunk) = self.chunks.get_mut(&chunk_key(*coordinate)) {
                let state = &mut chunk.pages[coordinate.page_index as usize % CHUNK_PAGES];
                if state.version == *version && state.pending & (1 << index) != 0 {
                    state.pending &= !(1 << index);
                    self.pending[index] -= 1;
                    chunk.pending[index] -= 1;
                }
            }
        }
        self.acknowledged[index] = capture.inner.sequence;
        Ok(())
    }

    /// Returns the number of outstanding pages for an independent consumer.
    pub fn pending_pages(&self, consumer: Consumer) -> usize {
        self.pending[consumer as usize]
    }

    /// Deep-copies mutable version/consumer state for a new child incarnation.
    ///
    /// Shared content snapshots and storage leases remain the lifecycle owner's
    /// responsibility. Parent receipts can never acknowledge this child.
    ///
    /// # Errors
    ///
    /// Returns [`RamError::StaleReceipt`] if the incarnation is reused, or resource
    /// errors if the private child's metadata cannot be admitted.
    pub fn fork(&self, incarnation: TrackingIncarnation) -> Result<Self, RamError> {
        if incarnation == self.incarnation {
            return Err(RamError::StaleReceipt);
        }
        let mut child = Self::new(
            self.topology.clone(),
            incarnation,
            self.limits,
            &self.budget,
        )?;
        child.charge.grow(
            (self.chunks.len() as u64)
                .checked_mul(CHUNK_CHARGE)
                .ok_or(RamError::Overflow)?,
        )?;
        child.chunks = self.chunks.clone();
        child.versioned_pages = self.versioned_pages;
        child.pending = self.pending;
        Ok(child)
    }

    fn state(&self, coordinate: PageCoordinate) -> PageState {
        self.chunks
            .get(&chunk_key(coordinate))
            .map(|chunk| chunk.pages[coordinate.page_index as usize % CHUNK_PAGES])
            .unwrap_or(PageState::CLEAN)
    }

    fn validate_coordinate(
        &self,
        coordinate: PageCoordinate,
        writing: bool,
    ) -> Result<(), RamError> {
        let region = self
            .topology
            .regions()
            .get(coordinate.region_index as usize)
            .ok_or(RamError::OutOfRange)?;
        region.geometry().valid_length(coordinate.page_index)?;
        if writing && region.class() == RegionClass::ImmutableImage {
            return Err(RamError::InvalidEncoding);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Limits, RegionDescriptor};

    #[test]
    // crucible-lint: allow panic-shortcut -- this exhaustion test panics if construction violates its fixed fixture.
    #[allow(clippy::unwrap_used)]
    fn monotonic_counter_exhaustion_preserves_ledger() {
        let topology = Topology::new(
            vec![RegionDescriptor::new("ram", RegionClass::MutableMain, 8192).unwrap()],
            Limits::default(),
        )
        .unwrap();
        let budget = MetadataBudget::new(100_000);
        let mut tracker = DirtyTracker::new(
            topology,
            TrackingIncarnation::new([1; 16]),
            TrackingLimits::default(),
            &budget,
        )
        .unwrap();
        let first = PageCoordinate {
            region_index: 0,
            page_index: 0,
        };
        let second = PageCoordinate {
            region_index: 0,
            page_index: 1,
        };
        tracker.mark_page(first).unwrap();
        tracker.chunks.get_mut(&chunk_key(first)).unwrap().pages[0].version = PageVersion(u64::MAX);
        let charged = budget.used_bytes();

        assert_eq!(
            tracker.mark_pages(&[first, second]),
            Err(RamError::Overflow)
        );
        assert_eq!(tracker.page_version(first).unwrap().get(), u64::MAX);
        assert_eq!(tracker.page_version(second).unwrap().get(), 0);
        assert_eq!(budget.used_bytes(), charged);
        tracker.sequences[Consumer::Fingerprint as usize] = u64::MAX;
        assert!(matches!(
            tracker.capture(Consumer::Fingerprint),
            Err(RamError::Overflow)
        ));
        assert_eq!(tracker.pending_pages(Consumer::Fingerprint), 1);
        assert_eq!(budget.used_bytes(), charged);
    }
}
