//! Retains the exact six prepared directed rings through one stopped HOLD.
//!
//! This library primitive records actual mapping exclusion and ring atomics.
//! The caller independently authenticates native preparation/HOLD before entry
//! and ends every Rust guard before native return, getter, setter or adoption.
//! It issues no native epoch, worker census, grant, readiness or release proof.

use super::*;
use crate::mapped_setup_region::offsets::{
    directed_ring_descriptor, mapped_node_slot_offset, mapped_ring_entries_offset,
    mapped_ring_header_offset,
};
use crate::{
    DirectedRing, HotForkMappingDispositionError, MappedSetupRegionAccessError, RegionLayout,
    RingHeader,
};

const RING_COUNT: usize = 6;

/// Retains six exact original directed headers and successful mapping exclusion.
///
/// Only the restricted construction view creates this noncloneable roster.
/// Its inert identity cannot authorize native participation or selection. The
/// owning source retains this token and the same setup owner through HOLD.
pub struct PreparedDirectedRingRoster {
    process: u32,
    owner: MappingOwnerKey,
    mapping_object: usize,
    layout: RegionLayout,
    offsets: [usize; RING_COUNT],
    attempted: bool,
    held: bool,
}

/// Reports only the exact prepared directed-ring barriers and mapping exclusion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreparedDirectedRingHoldSnapshot {
    offsets: [u64; RING_COUNT],
    held: u64,
    producers: u64,
    consumers: u64,
}

impl PreparedDirectedRingHoldSnapshot {
    /// Borrows the six original checked offsets in constructor pair order.
    pub fn header_offsets(&self) -> &[u64; RING_COUNT] {
        &self.offsets
    }

    /// Returns the exact number of observed prepared headers.
    pub const fn ring_count(&self) -> u64 {
        RING_COUNT as u64
    }

    /// Returns the number whose producer and consumer barriers are both held.
    pub const fn held_rings(&self) -> u64 {
        self.held
    }

    /// Returns the checked total of already admitted producers on these headers.
    pub const fn producers_in_flight(&self) -> u64 {
        self.producers
    }

    /// Returns the checked total of already admitted consumers on these headers.
    pub const fn consumers_in_flight(&self) -> u64 {
        self.consumers
    }

    /// Confirms actual DONTFORK under the current original owner's alias fence.
    pub const fn mapping_excluded(&self) -> bool {
        true
    }

    /// Confirms all six barriers are held with no admitted operation remaining.
    pub const fn quiescent(&self) -> bool {
        self.held == RING_COUNT as u64 && self.producers == 0 && self.consumers == 0
    }
}

/// Refuses changed source geometry, lifetime custody or incomplete ring stopping.
#[derive(Debug, thiserror::Error)]
pub enum PreparedDirectedRingHoldError {
    /// Retains the original process-private ownership refusal.
    #[error("prepared directed-ring custody refused: {source}")]
    Custody {
        #[source]
        /// Retains the exact current ownership refusal.
        source: WholeMappingCustodyError,
    },
    /// Retains a malformed or changed original ring/header geometry.
    #[error("prepared directed-ring geometry refused: {source}")]
    Geometry {
        #[source]
        /// Retains the exact ring or header access failure.
        source: MappedSetupRegionAccessError,
    },
    /// Retains the actual kernel mapping-exclusion failure.
    #[error("prepared directed-ring mapping exclusion refused: {source}")]
    Exclusion {
        #[source]
        /// Retains the actual mapping-exclusion error.
        source: HotForkMappingDispositionError,
    },
    /// Retains actual held barriers whose previously admitted I/O remains active.
    #[error("the six original directed rings have not drained")]
    NotQuiescent {
        /// Records only the observed original six-ring barriers.
        snapshot: PreparedDirectedRingHoldSnapshot,
    },
}

impl From<WholeMappingCustodyError> for PreparedDirectedRingHoldError {
    fn from(source: WholeMappingCustodyError) -> Self {
        Self::Custody { source }
    }
}

impl From<MappedSetupRegionAccessError> for PreparedDirectedRingHoldError {
    fn from(source: MappedSetupRegionAccessError) -> Self {
        Self::Geometry { source }
    }
}

impl OrdinaryPreparationView<'_> {
    /// Prepares the exact six directed headers and excludes their original VMA.
    ///
    /// Owning retention and native preparation must precede this construction
    /// loan. Every pair touches the selected node and resolves through actual
    /// checked geometry. No raw pointer or whole mapping borrow escapes.
    ///
    /// # Errors
    /// Refuses a foreign owner, invalid node/ring, duplicate header, changed
    /// geometry or actual kernel exclusion failure. The enclosing construction
    /// helper retains sticky failure custody for the same original mapping.
    pub fn prepare_directed_ring_hold_roster(
        &mut self,
        node_slot: u32,
        pairs: [(u32, u32); RING_COUNT],
    ) -> Result<PreparedDirectedRingRoster, PreparedDirectedRingHoldError> {
        let owner = self.mapping.mapping_owner_key();
        if owner.process != std::process::id() {
            return Err(WholeMappingCustodyError::Unregistered.into());
        }
        let layout = self
            .mapping
            .layout()
            .map_err(|source| MappedSetupRegionAccessError::Header { source })?;
        mapped_node_slot_offset(layout, owner.length, node_slot)?;
        let mut offsets = [0_usize; RING_COUNT];
        for (index, (source, destination)) in pairs.into_iter().enumerate() {
            if source == destination || (source != node_slot && destination != node_slot) {
                return Err(WholeMappingCustodyError::Unregistered.into());
            }
            let ring: DirectedRing =
                directed_ring_descriptor(layout.vm_node_count, source, destination)?;
            offsets[index] = mapped_ring_header_offset(layout, owner.length, ring)?;
            mapped_ring_entries_offset(layout, owner.length, ring)?;
            if offsets[..index].contains(&offsets[index]) {
                return Err(MappedSetupRegionAccessError::DuplicateDirectedRing {
                    ring_index: ring.index,
                }
                .into());
            }
        }
        self.mapping
            .exclude_from_hot_fork_child()
            .map_err(|source| PreparedDirectedRingHoldError::Exclusion { source })?;
        Ok(PreparedDirectedRingRoster {
            process: owner.process,
            owner,
            mapping_object: std::ptr::from_ref(self.mapping) as usize,
            layout,
            offsets,
            attempted: false,
            held: false,
        })
    }
}

struct HoldFence<'a> {
    owner: &'a SharedOwnedSetupMapping,
    process: u32,
    succeeded: bool,
}

impl Drop for HoldFence<'_> {
    fn drop(&mut self) {
        if self.process == std::process::id() && !self.succeeded {
            self.owner.refuse_whole_control();
        }
    }
}

impl SharedOwnedSetupMapping {
    /// Holds only the same six prepared directed headers exactly once.
    ///
    /// Native source authentication precedes this call. A short current-owner
    /// and ordinary-domain loan closes backing aliases before reestablishing
    /// actual DONTFORK and holding the six atomics. Every Rust guard ends here;
    /// no native call occurs inside the loan. Whole intent and native adoption
    /// follow the actual source HOLD separately. There is no release or retry.
    ///
    /// # Errors
    /// Refuses foreign PID before locks, an unprepared ticket, changed roster,
    /// repeated attempt, intent/selection/failure, busy or poisoned custody,
    /// failed kernel exclusion or admitted I/O that has not drained. A current
    /// failure keeps the original mapping fenced and owned under its ticket.
    pub fn hold_prepared_directed_rings(
        &self,
        roster: &mut PreparedDirectedRingRoster,
    ) -> Result<PreparedDirectedRingHoldSnapshot, PreparedDirectedRingHoldError> {
        let generation = self.generation()?;
        let mut fence = HoldFence {
            owner: self,
            process: generation.process,
            succeeded: false,
        };
        if !generation.retention_slot.armed() {
            return Err(WholeMappingCustodyError::ResourceLimit.into());
        }
        if roster.process != generation.process
            || roster.attempted
            || generation.intent.load(Ordering::Acquire)
            || generation.selected.load(Ordering::Acquire)
            || generation.failed.load(Ordering::Acquire)
            || generation.prepared_hold.swap(true, Ordering::AcqRel)
        {
            return Err(WholeMappingCustodyError::Selected.into());
        }
        roster.attempted = true;
        let owner = try_lock(&generation.owner)?;
        let mapping = owner.mapping();
        validate_mapping(mapping, roster, generation)?;
        let domain = generation.domain.as_ref().map_err(|error| *error)?;
        let _ordinary = super::super::ordinary(domain)?;
        if generation.failed.load(Ordering::Acquire)
            || generation.intent.load(Ordering::Acquire)
            || generation.selected.load(Ordering::Acquire)
        {
            return Err(WholeMappingCustodyError::Selected.into());
        }
        // An alias cannot release these barriers or restore inheritance after
        // this fence. The separately retained pre-intent flag owns the same Arc.
        domain.selected.store(true, Ordering::Release);
        exclude_under_loan(mapping)?;
        for offset in roster.offsets {
            let ring = ring_header(mapping, offset);
            ring.hold_hot_fork_producers_with_mapping_loan();
            ring.hold_hot_fork_consumers_with_mapping_loan();
        }
        let snapshot = observe(mapping, roster)?;
        if !snapshot.quiescent() {
            return Err(PreparedDirectedRingHoldError::NotQuiescent { snapshot });
        }
        if generation.failed.load(Ordering::Acquire) {
            return Err(WholeMappingCustodyError::Selected.into());
        }
        roster.held = true;
        fence.succeeded = true;
        Ok(snapshot)
    }

    /// Observes the same successfully held roster without releasing any ring.
    ///
    /// Only this exact current owner and successful original HOLD admit the
    /// query. It reads no worker state and issues no native epoch or authority.
    ///
    /// # Errors
    /// Refuses foreign PID before locks, changed ownership/geometry, an absent
    /// successful HOLD, failed custody or unavailable original owner loan.
    pub fn prepared_directed_ring_snapshot(
        &self,
        roster: &PreparedDirectedRingRoster,
    ) -> Result<PreparedDirectedRingHoldSnapshot, PreparedDirectedRingHoldError> {
        let generation = self.generation()?;
        let mut fence = HoldFence {
            owner: self,
            process: generation.process,
            succeeded: false,
        };
        if generation.process != roster.process
            || !roster.held
            || !generation.prepared_hold.load(Ordering::Acquire)
            || generation.failed.load(Ordering::Acquire)
        {
            return Err(WholeMappingCustodyError::Selected.into());
        }
        let owner = try_lock(&generation.owner)?;
        let mapping = owner.mapping();
        validate_mapping(mapping, roster, generation)?;
        let domain = generation.domain.as_ref().map_err(|error| *error)?;
        if !domain.selected.load(Ordering::Acquire) {
            return Err(WholeMappingCustodyError::Selected.into());
        }
        let snapshot = observe(mapping, roster)?;
        if generation.failed.load(Ordering::Acquire) {
            return Err(WholeMappingCustodyError::Selected.into());
        }
        fence.succeeded = true;
        Ok(snapshot)
    }
}

fn validate_mapping(
    mapping: &MappedSetupRegion,
    roster: &PreparedDirectedRingRoster,
    generation: &OwnerGeneration,
) -> Result<(), PreparedDirectedRingHoldError> {
    let current = mapping.mapping_owner_key();
    let original = roster.owner;
    if std::ptr::from_ref(mapping) as usize != roster.mapping_object
        || current.process != std::process::id()
        || current.process != original.process
        || current.address != original.address
        || current.length != original.length
        || current.identity != original.identity
    {
        return Err(WholeMappingCustodyError::Unregistered.into());
    }
    let registration = generation.registration.owner;
    if current.process != registration.process
        || current.address != registration.address
        || current.length != registration.length
        || current.identity != registration.identity
    {
        return Err(WholeMappingCustodyError::Unregistered.into());
    }
    let domain = registered_domain(current)?;
    let cell = registered_cell(current)?;
    if !generation
        .domain
        .as_ref()
        .is_ok_and(|original| Arc::ptr_eq(original, &domain))
        || !generation
            .cell
            .as_ref()
            .is_ok_and(|original| Arc::ptr_eq(original, &cell))
    {
        return Err(WholeMappingCustodyError::Unregistered.into());
    }
    let layout = mapping
        .layout()
        .map_err(|source| MappedSetupRegionAccessError::Header { source })?;
    if layout != roster.layout {
        return Err(WholeMappingCustodyError::Unregistered.into());
    }
    Ok(())
}

fn ring_header(mapping: &MappedSetupRegion, offset: usize) -> &RingHeader {
    // SAFETY: the opaque roster validated all six exact directed header offsets
    // and alignment before effects; the same retained owner/layout was rechecked.
    unsafe { &*mapping.base_ptr().add(offset).cast::<RingHeader>() }
}

fn observe(
    mapping: &MappedSetupRegion,
    roster: &PreparedDirectedRingRoster,
) -> Result<PreparedDirectedRingHoldSnapshot, PreparedDirectedRingHoldError> {
    let mut snapshot = PreparedDirectedRingHoldSnapshot {
        offsets: roster.offsets.map(|offset| offset as u64),
        held: 0,
        producers: 0,
        consumers: 0,
    };
    for offset in roster.offsets {
        let ring = ring_header(mapping, offset);
        let producer = ring.producer_barrier_snapshot();
        let consumer = ring.consumer_barrier_snapshot();
        snapshot.held += u64::from(producer.held() && consumer.held());
        snapshot.producers = snapshot
            .producers
            .checked_add(producer.in_flight())
            .ok_or(WholeMappingCustodyError::ResourceLimit)?;
        snapshot.consumers = snapshot
            .consumers
            .checked_add(consumer.in_flight())
            .ok_or(WholeMappingCustodyError::ResourceLimit)?;
    }
    Ok(snapshot)
}

#[cfg(target_os = "linux")]
fn exclude_under_loan(mapping: &MappedSetupRegion) -> Result<(), PreparedDirectedRingHoldError> {
    let status = unsafe {
        // SAFETY: the current owner lock retains this exact live, page-aligned
        // VMA and its length. The ordinary-domain loan and selected alias fence
        // prevent replacement or inheritance changes during MADV_DONTFORK.
        libc::madvise(mapping.base_ptr().cast(), mapping.len, libc::MADV_DONTFORK)
    };
    if status != 0 {
        return Err(PreparedDirectedRingHoldError::Exclusion {
            source: HotForkMappingDispositionError::Madvise {
                operation: "MADV_DONTFORK",
                source: std::io::Error::last_os_error(),
            },
        });
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn exclude_under_loan(_: &MappedSetupRegion) -> Result<(), PreparedDirectedRingHoldError> {
    Err(PreparedDirectedRingHoldError::Exclusion {
        source: HotForkMappingDispositionError::Unsupported,
    })
}

#[cfg(all(test, target_os = "linux"))]
#[path = "prepared_directed/tests.rs"]
mod tests;
