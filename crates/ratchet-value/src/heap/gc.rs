//! Generational-GC policy surfaces for runtime heap objects.
//!
//! The active runtime does not yet include the daemon collector. This module
//! defines the precise write-barrier decision table for the one mutating Nix
//! heap transition: resolving a blackholed thunk to its forced value. The table
//! is deliberately narrow so later collector code records old-to-young edges in
//! one place instead of spreading field-store barriers across immutable value
//! constructors.

use crate::value::tag::POINTER_TAG_MASK;

/// The runtime tier in which the generational write barrier is evaluated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GenerationalGcTier {
    /// One-shot CLI or harness evaluation; the bump arena never collects.
    OneShotArena,
    /// Long-lived daemon evaluation with a young generation and remembered set.
    DaemonGenerational,
}

/// The generation that owns a heap object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HeapGeneration {
    /// The object is in the young generation.
    Young,
    /// The object is in the old generation.
    Old,
    /// The object is in permanent space and bypasses promotion churn.
    Permanent,
}

impl HeapGeneration {
    const fn needs_young_target_barrier(self) -> bool {
        matches!(self, Self::Old | Self::Permanent)
    }
}

/// An aligned heap object address used by the generational barrier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GcHeapAddress {
    address_bits: usize,
}

impl GcHeapAddress {
    /// Creates a heap address from untagged address bits.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError::NullAddress`] when `address_bits` is zero,
    /// or [`GenerationalGcError::LowTagBitsPresent`] when low pointer-tag bits
    /// are still present.
    pub fn new(address_bits: usize) -> Result<Self, GenerationalGcError> {
        if address_bits & POINTER_TAG_MASK != 0 {
            return Err(GenerationalGcError::LowTagBitsPresent { address_bits });
        }
        if address_bits == 0 {
            return Err(GenerationalGcError::NullAddress);
        }
        Ok(Self { address_bits })
    }

    /// Returns the untagged aligned address bits.
    pub const fn address_bits(self) -> usize {
        self.address_bits
    }
}

/// The forced value written into a resolved thunk, classified for GC.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ResolvedValueGeneration {
    /// The forced value is inline and contains no heap pointer.
    Inline,
    /// The forced value is heap-backed.
    Heap {
        /// The forced value's heap object address.
        address: GcHeapAddress,
        /// The forced value's generation.
        generation: HeapGeneration,
    },
}

impl ResolvedValueGeneration {
    /// Creates a young heap-backed resolved value.
    pub const fn young(address: GcHeapAddress) -> Self {
        Self::Heap {
            address,
            generation: HeapGeneration::Young,
        }
    }

    /// Creates an old heap-backed resolved value.
    pub const fn old(address: GcHeapAddress) -> Self {
        Self::Heap {
            address,
            generation: HeapGeneration::Old,
        }
    }

    /// Creates a permanent heap-backed resolved value.
    pub const fn permanent(address: GcHeapAddress) -> Self {
        Self::Heap {
            address,
            generation: HeapGeneration::Permanent,
        }
    }
}

/// A thunk-resolution write into an already allocated thunk object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ThunkResolveWrite {
    thunk: GcHeapAddress,
    thunk_generation: HeapGeneration,
    value: ResolvedValueGeneration,
}

impl ThunkResolveWrite {
    /// Creates a thunk-resolution write descriptor.
    pub const fn new(
        thunk: GcHeapAddress,
        thunk_generation: HeapGeneration,
        value: ResolvedValueGeneration,
    ) -> Self {
        Self {
            thunk,
            thunk_generation,
            value,
        }
    }

    /// Returns the thunk object being resolved.
    pub const fn thunk(self) -> GcHeapAddress {
        self.thunk
    }

    /// Returns the thunk object's generation.
    pub const fn thunk_generation(self) -> HeapGeneration {
        self.thunk_generation
    }

    /// Returns the forced value being published.
    pub const fn value(self) -> ResolvedValueGeneration {
        self.value
    }
}

/// One old-or-permanent to young edge recorded for minor collection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RememberedEdge {
    source: GcHeapAddress,
    target: GcHeapAddress,
}

impl RememberedEdge {
    /// Creates a remembered old-to-young edge.
    pub const fn new(source: GcHeapAddress, target: GcHeapAddress) -> Self {
        Self { source, target }
    }

    /// Returns the old or permanent source object.
    pub const fn source(self) -> GcHeapAddress {
        self.source
    }

    /// Returns the young target object.
    pub const fn target(self) -> GcHeapAddress {
        self.target
    }
}

/// The write-barrier action for resolving a thunk.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ThunkResolveWriteBarrier {
    /// No generational collector is active for this tier.
    Disabled,
    /// The write does not create an old-to-young edge.
    NotRequired,
    /// The write must be recorded in the remembered set.
    Remember {
        /// The precise edge created by resolving the thunk.
        edge: RememberedEdge,
    },
}

impl ThunkResolveWriteBarrier {
    /// Returns whether the write can publish without recording a remembered edge.
    pub const fn permits_unrecorded_publish(self) -> bool {
        matches!(self, Self::Disabled | Self::NotRequired)
    }
}

/// Classifies the generational write barrier for a thunk-resolution write.
pub const fn classify_thunk_resolve_write_barrier(
    tier: GenerationalGcTier,
    write: ThunkResolveWrite,
) -> ThunkResolveWriteBarrier {
    match tier {
        GenerationalGcTier::OneShotArena => ThunkResolveWriteBarrier::Disabled,
        GenerationalGcTier::DaemonGenerational => match write.value {
            ResolvedValueGeneration::Inline => ThunkResolveWriteBarrier::NotRequired,
            ResolvedValueGeneration::Heap {
                address: target,
                generation: HeapGeneration::Young,
            } if write.thunk_generation.needs_young_target_barrier() => {
                ThunkResolveWriteBarrier::Remember {
                    edge: RememberedEdge::new(write.thunk, target),
                }
            }
            ResolvedValueGeneration::Heap { .. } => ThunkResolveWriteBarrier::NotRequired,
        },
    }
}

/// A remembered-set insertion result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RememberedSetUpdate {
    /// The edge was newly inserted.
    Inserted,
    /// The same edge was already present.
    AlreadyPresent,
}

/// A simple remembered set for old-to-young edges.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RememberedSet {
    edges: Vec<RememberedEdge>,
}

impl RememberedSet {
    /// Creates an empty remembered set.
    pub const fn new() -> Self {
        Self { edges: Vec::new() }
    }

    /// Returns remembered edges in insertion order.
    pub fn edges(&self) -> &[RememberedEdge] {
        &self.edges
    }

    /// Returns the number of remembered edges.
    pub fn len(&self) -> usize {
        self.edges.len()
    }

    /// Returns whether no edges have been remembered.
    pub fn is_empty(&self) -> bool {
        self.edges.is_empty()
    }

    /// Records an old-to-young edge.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError::RememberedSetLengthOverflow`] if the edge
    /// count overflows, or [`GenerationalGcError::RememberedSetAllocationFailed`]
    /// if storage for the edge cannot be reserved.
    pub fn record(
        &mut self,
        edge: RememberedEdge,
    ) -> Result<RememberedSetUpdate, GenerationalGcError> {
        if self.edges.contains(&edge) {
            return Ok(RememberedSetUpdate::AlreadyPresent);
        }
        let edges = self
            .edges
            .len()
            .checked_add(1)
            .ok_or(GenerationalGcError::RememberedSetLengthOverflow)?;
        self.edges
            .try_reserve_exact(1)
            .map_err(|_| GenerationalGcError::RememberedSetAllocationFailed { edges })?;
        self.edges.push(edge);
        Ok(RememberedSetUpdate::Inserted)
    }
}

/// Classifies and records the write barrier for a thunk-resolution write.
///
/// # Errors
///
/// Returns [`GenerationalGcError`] if the write requires a remembered edge and
/// the remembered set cannot reserve storage for it.
pub fn record_thunk_resolve_write_barrier(
    tier: GenerationalGcTier,
    write: ThunkResolveWrite,
    remembered_set: &mut RememberedSet,
) -> Result<ThunkResolveWriteBarrier, GenerationalGcError> {
    let action = classify_thunk_resolve_write_barrier(tier, write);
    if let ThunkResolveWriteBarrier::Remember { edge } = action {
        remembered_set.record(edge)?;
    }
    Ok(action)
}

/// A failed generational-GC policy or remembered-set operation.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum GenerationalGcError {
    /// A heap address decoded to zero.
    #[error("GC heap address is null")]
    NullAddress,
    /// A heap address still carried low pointer-tag bits.
    #[error("GC heap address still has low pointer-tag bits set: 0x{address_bits:x}")]
    LowTagBitsPresent {
        /// The rejected address bits.
        address_bits: usize,
    },
    /// The remembered-set edge count overflowed.
    #[error("remembered-set edge count overflow")]
    RememberedSetLengthOverflow,
    /// The remembered set could not reserve storage.
    #[error("failed to reserve {edges} remembered-set edges")]
    RememberedSetAllocationFailed {
        /// The requested remembered-set capacity.
        edges: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(bits: usize) -> GcHeapAddress {
        GcHeapAddress::new(bits).expect("aligned address")
    }

    #[test]
    fn heap_addresses_reject_null_and_low_pointer_tags() {
        assert_eq!(GcHeapAddress::new(0), Err(GenerationalGcError::NullAddress));
        assert_eq!(
            GcHeapAddress::new(0b1010),
            Err(GenerationalGcError::LowTagBitsPresent {
                address_bits: 0b1010,
            })
        );
        assert_eq!(address(0x1000).address_bits(), 0x1000);
    }

    #[test]
    fn one_shot_tier_disables_thunk_resolve_write_barrier() {
        let write = ThunkResolveWrite::new(
            address(0x1000),
            HeapGeneration::Old,
            ResolvedValueGeneration::young(address(0x2000)),
        );

        let action = classify_thunk_resolve_write_barrier(GenerationalGcTier::OneShotArena, write);

        assert_eq!(action, ThunkResolveWriteBarrier::Disabled);
        assert!(action.permits_unrecorded_publish());
    }

    #[test]
    fn daemon_tier_remembers_old_to_young_thunk_resolutions() {
        let thunk = address(0x1000);
        let value = address(0x2000);
        let write = ThunkResolveWrite::new(
            thunk,
            HeapGeneration::Old,
            ResolvedValueGeneration::young(value),
        );

        let action =
            classify_thunk_resolve_write_barrier(GenerationalGcTier::DaemonGenerational, write);

        assert_eq!(
            action,
            ThunkResolveWriteBarrier::Remember {
                edge: RememberedEdge::new(thunk, value),
            }
        );
        assert!(!action.permits_unrecorded_publish());
    }

    #[test]
    fn daemon_tier_remembers_permanent_to_young_thunk_resolutions() {
        let thunk = address(0x3000);
        let value = address(0x4000);
        let write = ThunkResolveWrite::new(
            thunk,
            HeapGeneration::Permanent,
            ResolvedValueGeneration::young(value),
        );

        assert_eq!(
            classify_thunk_resolve_write_barrier(GenerationalGcTier::DaemonGenerational, write),
            ThunkResolveWriteBarrier::Remember {
                edge: RememberedEdge::new(thunk, value),
            }
        );
    }

    #[test]
    fn daemon_tier_skips_young_sources_and_non_young_targets() {
        let old_value = ResolvedValueGeneration::old(address(0x3000));
        let permanent_value = ResolvedValueGeneration::permanent(address(0x4000));
        for write in [
            ThunkResolveWrite::new(
                address(0x1000),
                HeapGeneration::Young,
                ResolvedValueGeneration::young(address(0x2000)),
            ),
            ThunkResolveWrite::new(address(0x1000), HeapGeneration::Old, old_value),
            ThunkResolveWrite::new(address(0x1000), HeapGeneration::Old, permanent_value),
            ThunkResolveWrite::new(
                address(0x1000),
                HeapGeneration::Permanent,
                ResolvedValueGeneration::Inline,
            ),
        ] {
            let action =
                classify_thunk_resolve_write_barrier(GenerationalGcTier::DaemonGenerational, write);
            assert_eq!(action, ThunkResolveWriteBarrier::NotRequired);
            assert!(action.permits_unrecorded_publish());
        }
    }

    #[test]
    fn remembered_set_deduplicates_recorded_edges() {
        let edge = RememberedEdge::new(address(0x1000), address(0x2000));
        let mut set = RememberedSet::new();

        assert_eq!(
            set.record(edge).expect("edge records"),
            RememberedSetUpdate::Inserted
        );
        assert_eq!(
            set.record(edge).expect("duplicate edge is accepted"),
            RememberedSetUpdate::AlreadyPresent
        );

        assert_eq!(set.edges(), &[edge]);
        assert_eq!(set.len(), 1);
        assert!(!set.is_empty());
    }

    #[test]
    fn record_thunk_resolve_write_barrier_records_only_required_edges() {
        let edge = RememberedEdge::new(address(0x1000), address(0x2000));
        let write = ThunkResolveWrite::new(
            edge.source(),
            HeapGeneration::Old,
            ResolvedValueGeneration::young(edge.target()),
        );
        let mut set = RememberedSet::new();

        let action = record_thunk_resolve_write_barrier(
            GenerationalGcTier::DaemonGenerational,
            write,
            &mut set,
        )
        .expect("barrier records");

        assert_eq!(action, ThunkResolveWriteBarrier::Remember { edge });
        assert_eq!(set.edges(), &[edge]);

        let no_barrier = ThunkResolveWrite::new(
            address(0x3000),
            HeapGeneration::Young,
            ResolvedValueGeneration::young(address(0x4000)),
        );
        let action = record_thunk_resolve_write_barrier(
            GenerationalGcTier::DaemonGenerational,
            no_barrier,
            &mut set,
        )
        .expect("non-barrier write succeeds");

        assert_eq!(action, ThunkResolveWriteBarrier::NotRequired);
        assert_eq!(set.edges(), &[edge]);
    }
}
