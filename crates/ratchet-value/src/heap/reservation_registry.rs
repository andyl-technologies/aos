//! Process-global map from a Candidate-C reservation domain to its base address.
//!
//! RFC-0007 Candidate-C addresses a heap value by a `(domain, index)` pair: the
//! 23-bit [`ArenaDomainId`](super::ArenaDomainId) names one
//! [`ReservedArena`](super::ReservedArena) and the 32-bit
//! [`ArenaIndex`](super::ArenaIndex) is a byte offset into it. A compressed word
//! therefore cannot be turned back into a native pointer on its own — it needs
//! the reservation's base address, which is a *dynamic* per-evaluation `mmap`
//! (no fixed virtual address) and several reservations can be live at once.
//!
//! This module is the **correctness** half of the two-layer resolution the
//! cutover ruling mandates (see `design-notes/candidate-c-cutover-plan.md` §7):
//! a reservation publishes `domain → base` here when it is mapped and withdraws
//! it before the mapping is unmapped, so any holder of a compressed word — the
//! self-contained `Value::as_heap_ptr` accessor, `Debug`, FFI decode, future JIT
//! helpers, and heap-image snapshot rebase — can resolve `base + index` without
//! threading a heap handle. Arena-internal *hot* paths deliberately bypass this
//! table and resolve through their own cached base field; the global lookup is
//! for the cold, context-free callers.
//!
//! # Layout
//!
//! A fixed-capacity, lock-free open table of slots — live domains per process
//! are few (one per serial [`super::super::EvalHeap`]; one shared reservation
//! across parallel workers), so a small flat table resolves in a bounded scan
//! with no allocation and no lock:
//!
//! ```text
//! REGISTRATION_SLOTS x { domain: AtomicU32, base: AtomicUsize }
//!   domain == 0            -> empty slot
//!   domain == RESERVING    -> claimed, base not yet published (transient)
//!   domain == <1..=2^23-1> -> live: base is the reservation's mapped address
//! ```
//!
//! The table stores addresses only; it never dereferences them. All pointer
//! reconstruction (and its `unsafe`) lives at the resolution site, and the
//! lifecycle invariant — a domain is unregistered before its mapping is
//! released, so a published `(domain, base)` always names live memory — is
//! enforced by [`ReservedArena`](super::ReservedArena)'s constructor and `Drop`.

use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use thiserror::Error;

use super::ArenaDomainId;

/// Number of reservation base slots the process-global table holds.
///
/// Live Candidate-C reservations are ordinarily one (serial) or a small handful
/// (parallel shards share a single reservation; nested or concurrent evaluations
/// add a few more), so this bound is far above any realistic live set while
/// keeping the static table small (`2048 * 16 B = 32 KiB`).
const REGISTRATION_SLOTS: usize = 2048;

/// Sentinel domain marking a slot that is claimed but whose base is not yet
/// published. It is outside the valid `1..=2^23-1` domain range, so a concurrent
/// lookup can never mistake it for a real domain.
const RESERVING: u32 = u32::MAX;

/// One reservation base entry in the process-global table.
struct Slot {
    /// The occupying reservation domain, `0` when empty, or [`RESERVING`] during
    /// a claim that has not yet published its base.
    domain: AtomicU32,
    /// The reservation's mapped base address, valid only while `domain` names a
    /// live reservation.
    base: AtomicUsize,
    /// The reservation's mapped byte length, so an address can be matched to the
    /// reservation whose `[base, base + capacity)` range contains it.
    capacity: AtomicUsize,
}

impl Slot {
    /// A const-constructible empty slot for the static table initializer.
    const EMPTY: Self = Self {
        domain: AtomicU32::new(0),
        base: AtomicUsize::new(0),
        capacity: AtomicUsize::new(0),
    };
}

/// A fixed-capacity, lock-free `domain → base` table.
struct ReservationBaseRegistry {
    slots: [Slot; REGISTRATION_SLOTS],
    /// One past the highest slot index ever claimed, so lookups scan only the
    /// prefix that has been used rather than the whole table. Never decreases,
    /// which keeps the bound monotonic and lock-free.
    high_water: AtomicUsize,
}

impl ReservationBaseRegistry {
    /// Creates an empty table. Used for the process-global static and, in tests,
    /// for isolated local instances that do not share state with live
    /// reservations.
    const fn new() -> Self {
        Self {
            slots: [const { Slot::EMPTY }; REGISTRATION_SLOTS],
            high_water: AtomicUsize::new(0),
        }
    }

    /// Publishes `base` for `domain`, returning the claimed slot index.
    ///
    /// # Errors
    ///
    /// Returns [`ReservationRegistryError::TableFull`] when every slot is
    /// occupied, which only happens with more concurrently-live reservations
    /// than [`REGISTRATION_SLOTS`].
    fn register(
        &self,
        domain: ArenaDomainId,
        base: usize,
        capacity: usize,
    ) -> Result<usize, ReservationRegistryError> {
        let domain = domain.raw();
        for (index, slot) in self.slots.iter().enumerate() {
            // Claim an empty slot with the transient RESERVING sentinel so a
            // concurrent lookup for `domain` (which cannot legitimately occur
            // until this call returns and values are allocated) never observes a
            // matching domain with an unpublished base.
            if slot
                .domain
                .compare_exchange(0, RESERVING, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                slot.base.store(base, Ordering::Relaxed);
                slot.capacity.store(capacity, Ordering::Relaxed);
                // Publishing the real domain releases the base/capacity stores above.
                slot.domain.store(domain, Ordering::Release);
                self.high_water.fetch_max(index + 1, Ordering::AcqRel);
                return Ok(index);
            }
        }
        Err(ReservationRegistryError::TableFull)
    }

    /// Withdraws `domain`'s entry so its slot can be reused.
    ///
    /// Idempotent: withdrawing an absent domain is a no-op. The base word is left
    /// as-is; it is ignored while the slot's domain is `0`.
    fn unregister(&self, domain: ArenaDomainId) {
        let domain = domain.raw();
        let scanned = self.high_water.load(Ordering::Acquire);
        for slot in self.slots.iter().take(scanned) {
            if slot.domain.load(Ordering::Acquire) == domain
                && slot
                    .domain
                    .compare_exchange(domain, 0, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                return;
            }
        }
    }

    /// Returns the base address published for `domain`, if any is live.
    fn base_for(&self, domain: ArenaDomainId) -> Option<usize> {
        let domain = domain.raw();
        let scanned = self.high_water.load(Ordering::Acquire);
        for slot in self.slots.iter().take(scanned) {
            if slot.domain.load(Ordering::Acquire) == domain {
                return Some(slot.base.load(Ordering::Acquire));
            }
        }
        None
    }

    /// Returns the domain and base of the live reservation whose mapped range
    /// contains `address`, if any.
    fn reservation_containing(&self, address: usize) -> Option<(ArenaDomainId, usize)> {
        let scanned = self.high_water.load(Ordering::Acquire);
        for slot in self.slots.iter().take(scanned) {
            let raw = slot.domain.load(Ordering::Acquire);
            let Some(domain) = ArenaDomainId::from_raw(raw) else {
                // Empty (`0`) or in-flight (`RESERVING`) slots never match.
                continue;
            };
            let base = slot.base.load(Ordering::Acquire);
            let capacity = slot.capacity.load(Ordering::Acquire);
            if address >= base && address - base < capacity {
                return Some((domain, base));
            }
        }
        None
    }
}

/// The process-global reservation base table.
static RESERVATION_BASE_REGISTRY: ReservationBaseRegistry = ReservationBaseRegistry::new();

/// Publishes `base` as the mapped address of `domain`'s reservation.
///
/// Called by [`ReservedArena`](super::ReservedArena) immediately after a
/// successful mapping, before any value can reference the reservation.
///
/// # Errors
///
/// Returns [`ReservationRegistryError::TableFull`] when more reservations are
/// concurrently live than the process table holds ([`REGISTRATION_SLOTS`]).
pub fn register_reservation_base(
    domain: ArenaDomainId,
    base: usize,
    capacity: usize,
) -> Result<(), ReservationRegistryError> {
    RESERVATION_BASE_REGISTRY
        .register(domain, base, capacity)
        .map(|_| ())
}

/// Withdraws `domain`'s reservation base entry.
///
/// Called by [`ReservedArena`](super::ReservedArena)'s `Drop` **before** the
/// mapping is unmapped, so a published `(domain, base)` always names live
/// memory. Idempotent.
pub fn unregister_reservation_base(domain: ArenaDomainId) {
    RESERVATION_BASE_REGISTRY.unregister(domain);
}

/// Returns the mapped base address of `domain`'s reservation, if it is live.
///
/// This is the context-free resolution path: a compressed heap word carries a
/// `(domain, index)` pair and a holder without a heap handle recovers the native
/// address as `reservation_base(domain)? + index`. Arena-internal hot paths use
/// their own cached base instead and never call this.
#[must_use]
pub fn reservation_base(domain: ArenaDomainId) -> Option<usize> {
    RESERVATION_BASE_REGISTRY.base_for(domain)
}

/// Returns the domain and base of the live reservation containing `address`.
///
/// This is the context-free construction path: a caller holding a raw heap
/// pointer but no heap handle recovers the reservation identity to build a
/// compressed `(domain, index)` word as `(domain, address - base)`. Arena hot
/// paths that already hold their own base skip this scan. Returns `None` when no
/// live reservation's mapped range contains `address`.
#[must_use]
pub fn reservation_containing_address(address: usize) -> Option<(ArenaDomainId, usize)> {
    RESERVATION_BASE_REGISTRY.reservation_containing(address)
}

/// A failed reservation base registration.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ReservationRegistryError {
    /// Every process-global reservation base slot is occupied.
    #[error("reservation base registry is full ({REGISTRATION_SLOTS} live reservations)")]
    TableFull,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain(raw: u32) -> ArenaDomainId {
        ArenaDomainId::from_raw(raw).expect("valid test domain")
    }

    // These tests exercise the table logic on isolated local instances rather
    // than the process-global static: `ReservedArena` lifecycles in sibling
    // tests register real monotonic domain ids concurrently, so fixed test
    // domains would collide with them on the shared static.

    const CAP: usize = 0x1_0000;

    #[test]
    fn registered_base_resolves_and_unregister_clears_it() {
        let registry = ReservationBaseRegistry::new();
        let d = domain(0x0011_00);
        assert_eq!(registry.base_for(d), None);

        registry.register(d, 0xdead_0000, CAP).expect("registers");
        assert_eq!(registry.base_for(d), Some(0xdead_0000));

        registry.unregister(d);
        assert_eq!(registry.base_for(d), None);
    }

    #[test]
    fn coexisting_domains_resolve_to_distinct_bases() {
        let registry = ReservationBaseRegistry::new();
        let a = domain(0x0022_01);
        let b = domain(0x0022_02);
        registry.register(a, 0x1000, CAP).expect("registers a");
        registry.register(b, 0x2000, CAP).expect("registers b");

        assert_eq!(registry.base_for(a), Some(0x1000));
        assert_eq!(registry.base_for(b), Some(0x2000));

        registry.unregister(a);
        assert_eq!(registry.base_for(a), None);
        // Withdrawing one domain leaves the other resolvable.
        assert_eq!(registry.base_for(b), Some(0x2000));
        registry.unregister(b);
        assert_eq!(registry.base_for(b), None);
    }

    #[test]
    fn unregister_is_idempotent_and_absent_domains_are_none() {
        let registry = ReservationBaseRegistry::new();
        let d = domain(0x0033_07);
        // Withdrawing a never-registered domain is a no-op.
        registry.unregister(d);
        assert_eq!(registry.base_for(d), None);

        registry.register(d, 0x4000, CAP).expect("registers");
        registry.unregister(d);
        registry.unregister(d);
        assert_eq!(registry.base_for(d), None);
    }

    #[test]
    fn freed_slots_are_reused_across_many_lifecycles() {
        let registry = ReservationBaseRegistry::new();
        // Far more lifecycles than the table has slots, but only one live at a
        // time, proving slot reclamation works and never exhausts the table.
        for raw in 1..(REGISTRATION_SLOTS as u32 * 4) {
            let d = domain(raw);
            registry
                .register(d, raw as usize * 0x100, CAP)
                .expect("registration reuses freed slots");
            assert_eq!(registry.base_for(d), Some(raw as usize * 0x100));
            registry.unregister(d);
        }
    }

    #[test]
    fn a_full_table_reports_table_full() {
        let registry = ReservationBaseRegistry::new();
        for raw in 1..=(REGISTRATION_SLOTS as u32) {
            registry
                .register(domain(raw), raw as usize, CAP)
                .expect("fills the table");
        }
        assert_eq!(
            registry.register(domain(REGISTRATION_SLOTS as u32 + 1), 0, CAP),
            Err(ReservationRegistryError::TableFull),
        );
    }

    #[test]
    fn reverse_lookup_matches_the_containing_reservation() {
        let registry = ReservationBaseRegistry::new();
        let a = domain(0x0044_01);
        let b = domain(0x0044_02);
        registry.register(a, 0x1_0000, 0x1000).expect("registers a");
        registry.register(b, 0x2_0000, 0x1000).expect("registers b");

        // Base, interior, and last-byte addresses resolve to their reservation.
        assert_eq!(
            registry.reservation_containing(0x1_0000),
            Some((a, 0x1_0000))
        );
        assert_eq!(
            registry.reservation_containing(0x1_0800),
            Some((a, 0x1_0000))
        );
        assert_eq!(
            registry.reservation_containing(0x1_0fff),
            Some((a, 0x1_0000))
        );
        assert_eq!(
            registry.reservation_containing(0x2_0001),
            Some((b, 0x2_0000))
        );

        // One past the end of a's range and an address in no reservation miss.
        assert_eq!(registry.reservation_containing(0x1_1000), None);
        assert_eq!(registry.reservation_containing(0x9_0000), None);

        registry.unregister(a);
        assert_eq!(registry.reservation_containing(0x1_0800), None);
        assert_eq!(
            registry.reservation_containing(0x2_0001),
            Some((b, 0x2_0000))
        );
    }

    #[test]
    fn process_global_helpers_round_trip() {
        // A single high-range domain the monotonic allocator will not reach
        // during the test run, so it does not collide on the shared static.
        let d = domain(super::super::CANDIDATE_C_ARENA_DOMAIN_MAX);
        register_reservation_base(d, 0x5000, 0x1000).expect("registers on the global table");
        assert_eq!(reservation_base(d), Some(0x5000));
        assert_eq!(reservation_containing_address(0x5500), Some((d, 0x5000)));
        unregister_reservation_base(d);
        assert_eq!(reservation_base(d), None);
        assert_eq!(reservation_containing_address(0x5500), None);
    }
}
