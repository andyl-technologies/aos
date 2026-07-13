//! Candidate-C reservation heap-image round-trip primitive (RFC-0007 doc 31 §1).
//!
//! A heap-image snapshot dumps the used bytes of a [`ReservedArena`] and reloads
//! them into a *fresh* mapping in a later (or the same) process. Because a
//! Candidate-C runtime word addresses the heap as a `(domain, index)` pair —
//! where `index` is a base-relative byte offset and `domain` is a registry key
//! resolved to the reservation's live base (see
//! [`reservation_registry`](crate::heap::reservation_registry)) — the reload is
//! **address-free**: the used bytes are copied to the same offsets in a new
//! mapping and the *original domain* is re-registered against the new base, so
//! every dumped word resolves unchanged with no per-pointer rewrite pass (doc 31
//! §3.3 end state).
//!
//! This module owns only the raw arena mechanics — reading the used lanes and
//! reconstructing a reservation from them. The image file format (header,
//! manifest, integrity digest) and the [`SharedFlatStoreArena`] wrapping live one
//! layer up in [`crate::heap::snapshot`].
//!
//! # Domain-preservation invariant
//!
//! [`ReservedArena::from_reloaded_image`] registers the *stored* domain rather
//! than allocating a fresh one, deliberately bypassing the monotonic
//! never-reissue allocator. This is sound only while that domain is not
//! concurrently live: the caller (the snapshot restore path, or an in-process
//! round-trip test) must ensure the reservation that produced the image has been
//! dropped — freeing its registry entry — before the image is reloaded. The
//! snapshot restore path enforces this with an explicit liveness check; the
//! monotonic allocator never reissues the domain to a fresh reservation, so no
//! collision with unrelated live heaps can occur.

use std::ptr;
use std::sync::atomic::AtomicUsize;

use super::{
    ArenaDomainId, ReservedArena, ReservedArenaError, map_anonymous_reservation, validate_capacity,
};
use crate::heap::reservation_registry::register_reservation_base;

impl ReservedArena {
    /// Copies the two used allocation lanes' bytes for a heap-image dump.
    ///
    /// Returns `(low, high)`: the upward-growing permanent lane `[0, low_used)`
    /// and the downward-growing rewindable lane `[high_cursor, capacity)`, each
    /// as an owned byte vector. The virtual reservation is demand-paged, so only
    /// these used prefixes are read; untouched pages are never faulted in.
    pub(crate) fn copy_used_lanes(&self) -> (Vec<u8>, Vec<u8>) {
        let stats = self.stats();
        let high_cursor = self.capacity - stats.high_used_bytes;
        let base = self.base.as_ptr();
        // SAFETY: `[base, base + low_used)` and `[base + high_cursor, base +
        // capacity)` are within this arena's live mapping and were initialized
        // by the allocations that advanced the two cursors. A zero-length lane
        // yields a valid empty slice from the (non-null) base pointer.
        unsafe {
            (
                std::slice::from_raw_parts(base, stats.low_used_bytes).to_vec(),
                std::slice::from_raw_parts(base.add(high_cursor), stats.high_used_bytes).to_vec(),
            )
        }
    }

    /// Reconstructs a reservation from a dumped heap image, preserving its
    /// domain so compressed `(domain, index)` words resolve unchanged.
    ///
    /// Maps a fresh `capacity`-byte demand-paged reservation, copies `low` to
    /// offset zero and `high` to `[capacity - high.len(), capacity)`, publishes
    /// `domain -> new_base` in the process-global registry, and positions the
    /// two cursors at the reloaded used prefixes. See the
    /// [module documentation](self) for the domain-preservation invariant the
    /// caller must uphold.
    ///
    /// # Errors
    ///
    /// Returns [`ReservedArenaError::UnsupportedPointerWidth`] on a non-64-bit
    /// target, [`ReservedArenaError::SizeOverflow`] when the lanes do not fit the
    /// capacity, a mapping error from [`map_anonymous_reservation`], or
    /// [`ReservedArenaError::DomainRegistry`] when the registry has no free slot.
    pub(crate) fn from_reloaded_image(
        domain: ArenaDomainId,
        capacity: usize,
        low: &[u8],
        high: &[u8],
    ) -> Result<Self, ReservedArenaError> {
        if usize::BITS < 64 {
            return Err(ReservedArenaError::UnsupportedPointerWidth);
        }
        validate_capacity(capacity)?;
        let high_cursor = capacity
            .checked_sub(high.len())
            .ok_or(ReservedArenaError::SizeOverflow)?;
        if low.len() > high_cursor || low.len() > u32::MAX as usize {
            return Err(ReservedArenaError::SizeOverflow);
        }
        let base = map_anonymous_reservation(capacity)?;
        // SAFETY: `base` owns a fresh `capacity`-byte mapping; the two lanes are
        // disjoint (`low.len() <= high_cursor`) and each fits inside the mapping
        // by the bounds checked above, so both copies stay in-bounds.
        unsafe {
            ptr::copy_nonoverlapping(low.as_ptr(), base.as_ptr(), low.len());
            ptr::copy_nonoverlapping(high.as_ptr(), base.as_ptr().add(high_cursor), high.len());
        }
        if let Err(error) = register_reservation_base(domain, base.as_ptr() as usize, capacity) {
            // SAFETY: `base`/`capacity` denote the mapping created above and no
            // reference into it exists yet, so releasing it here is sound.
            let _ = unsafe { libc::munmap(base.as_ptr().cast(), capacity) };
            return Err(ReservedArenaError::from(error));
        }
        Ok(Self {
            base,
            domain_id: domain,
            capacity,
            low_cursor: AtomicUsize::new(low.len()),
            high_cursor,
        })
    }
}
