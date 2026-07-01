//! Generational-GC policy surfaces for runtime heap objects.
//!
//! The active runtime does not yet include the daemon collector. This module
//! defines two precise policy surfaces for the future Tier-B daemon heap: the
//! write-barrier decision table for the one mutating Nix heap transition
//! (`Blackhole -> Forced(value)`) and the initial minor-GC frontier planner that
//! combines young roots with the remembered old/permanent-to-young edge set. The
//! barrier table is deliberately narrow so later collector code records
//! old-to-young edges in one place instead of spreading field-store barriers
//! across immutable value constructors.

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

/// Minor-collection age metadata for one young-generation object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NurseryObjectAge {
    address: GcHeapAddress,
    survived_minor_collections: u32,
}

impl NurseryObjectAge {
    /// Creates age metadata for a nursery object.
    pub const fn new(address: GcHeapAddress, survived_minor_collections: u32) -> Self {
        Self {
            address,
            survived_minor_collections,
        }
    }

    /// Returns the young-generation object address.
    pub const fn address(self) -> GcHeapAddress {
        self.address
    }

    /// Returns the number of minor collections already survived.
    pub const fn survived_minor_collections(self) -> u32 {
        self.survived_minor_collections
    }
}

/// Age threshold that promotes nursery survivors into the old generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MinorGcPromotionPolicy {
    promote_after_survivals: u32,
}

impl MinorGcPromotionPolicy {
    /// Creates a promotion policy from a survivor-count threshold.
    ///
    /// A threshold of zero promotes every survivor immediately. A threshold of
    /// `N` promotes an object once the current minor collection would make its
    /// survived-minor count at least `N`.
    pub const fn new(promote_after_survivals: u32) -> Self {
        Self {
            promote_after_survivals,
        }
    }

    /// Returns the survivor-count threshold that triggers promotion.
    pub const fn promote_after_survivals(self) -> u32 {
        self.promote_after_survivals
    }

    const fn action_for_survivor(self, next_survivals: u32) -> MinorGcSurvivorAction {
        if next_survivals >= self.promote_after_survivals {
            MinorGcSurvivorAction::PromoteToOld
        } else {
            MinorGcSurvivorAction::CopyToNursery
        }
    }
}

/// The copying action selected for a live nursery object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MinorGcSurvivorAction {
    /// Copy the object to the next nursery semispace.
    CopyToNursery,
    /// Promote the object to the old generation.
    PromoteToOld,
}

/// One young object that a minor collection must preserve.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MinorGcSurvivor {
    address: GcHeapAddress,
    previous_survivals: u32,
    next_survivals: u32,
    action: MinorGcSurvivorAction,
}

impl MinorGcSurvivor {
    /// Returns the live young object address.
    pub const fn address(self) -> GcHeapAddress {
        self.address
    }

    /// Returns the survived-minor count before the current collection.
    pub const fn previous_survivals(self) -> u32 {
        self.previous_survivals
    }

    /// Returns the survived-minor count after the current collection.
    pub const fn next_survivals(self) -> u32 {
        self.next_survivals
    }

    /// Returns whether this survivor is copied or promoted.
    pub const fn action(self) -> MinorGcSurvivorAction {
        self.action
    }
}

/// A minor-collection frontier plan for the young generation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MinorGcPlan {
    survivors: Vec<MinorGcSurvivor>,
}

impl MinorGcPlan {
    /// Builds the initial young-object frontier for a minor collection.
    ///
    /// Inline, old-generation, and permanent roots do not enter the minor-GC
    /// frontier. Young roots and remembered-set targets are deduplicated in
    /// discovery order, then classified according to the promotion policy.
    /// The caller must pass the remembered set for the same collection epoch:
    /// it must contain every current old/permanent-to-young edge and its targets
    /// must refer to objects still present in `nursery_objects`.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError`] if frontier storage cannot be reserved,
    /// if the frontier length overflows, if a young frontier object has no
    /// nursery age metadata, or if duplicate nursery age metadata is supplied.
    pub fn from_roots_and_remembered(
        roots: impl IntoIterator<Item = ResolvedValueGeneration>,
        remembered_set: &RememberedSet,
        nursery_objects: &[NurseryObjectAge],
        promotion_policy: MinorGcPromotionPolicy,
    ) -> Result<Self, GenerationalGcError> {
        validate_unique_nursery_objects(nursery_objects)?;
        let mut frontier = MinorGcFrontier::new();
        for root in roots {
            if let ResolvedValueGeneration::Heap {
                address,
                generation: HeapGeneration::Young,
            } = root
            {
                frontier.insert(address)?;
            }
        }
        for edge in remembered_set.edges() {
            frontier.insert(edge.target())?;
        }

        let mut survivors = Vec::new();
        for address in frontier.addresses {
            let age = nursery_age_for(nursery_objects, address)?;
            let next_survivals = age.survived_minor_collections.saturating_add(1);
            let action = promotion_policy.action_for_survivor(next_survivals);
            let survivors_len = survivors
                .len()
                .checked_add(1)
                .ok_or(GenerationalGcError::MinorGcSurvivorLengthOverflow)?;
            survivors.try_reserve_exact(1).map_err(|_| {
                GenerationalGcError::MinorGcSurvivorAllocationFailed {
                    survivors: survivors_len,
                }
            })?;
            survivors.push(MinorGcSurvivor {
                address,
                previous_survivals: age.survived_minor_collections,
                next_survivals,
                action,
            });
        }

        Ok(Self { survivors })
    }

    /// Returns planned young-generation survivors in frontier order.
    pub fn survivors(&self) -> &[MinorGcSurvivor] {
        &self.survivors
    }

    /// Returns the number of live young objects in the initial frontier.
    pub fn len(&self) -> usize {
        self.survivors.len()
    }

    /// Returns whether the initial young-object frontier is empty.
    pub fn is_empty(&self) -> bool {
        self.survivors.is_empty()
    }
}

#[derive(Debug, Default)]
struct MinorGcFrontier {
    addresses: Vec<GcHeapAddress>,
}

impl MinorGcFrontier {
    const fn new() -> Self {
        Self {
            addresses: Vec::new(),
        }
    }

    fn insert(&mut self, address: GcHeapAddress) -> Result<(), GenerationalGcError> {
        if self.addresses.contains(&address) {
            return Ok(());
        }
        let objects = self
            .addresses
            .len()
            .checked_add(1)
            .ok_or(GenerationalGcError::MinorGcFrontierLengthOverflow)?;
        self.addresses
            .try_reserve_exact(1)
            .map_err(|_| GenerationalGcError::MinorGcFrontierAllocationFailed { objects })?;
        self.addresses.push(address);
        Ok(())
    }
}

fn validate_unique_nursery_objects(
    nursery_objects: &[NurseryObjectAge],
) -> Result<(), GenerationalGcError> {
    for (index, object) in nursery_objects.iter().enumerate() {
        if nursery_objects[index + 1..]
            .iter()
            .any(|other| other.address == object.address)
        {
            return Err(GenerationalGcError::DuplicateNurseryObjectAge {
                address: object.address,
            });
        }
    }
    Ok(())
}

fn nursery_age_for(
    nursery_objects: &[NurseryObjectAge],
    address: GcHeapAddress,
) -> Result<NurseryObjectAge, GenerationalGcError> {
    nursery_objects
        .iter()
        .copied()
        .find(|object| object.address == address)
        .ok_or(GenerationalGcError::MissingNurseryObjectAge { address })
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
    /// The minor-GC frontier length overflowed.
    #[error("minor-GC frontier length overflow")]
    MinorGcFrontierLengthOverflow,
    /// The minor-GC frontier could not reserve storage.
    #[error("failed to reserve {objects} minor-GC frontier objects")]
    MinorGcFrontierAllocationFailed {
        /// The requested frontier capacity.
        objects: usize,
    },
    /// The minor-GC survivor plan length overflowed.
    #[error("minor-GC survivor length overflow")]
    MinorGcSurvivorLengthOverflow,
    /// The minor-GC survivor plan could not reserve storage.
    #[error("failed to reserve {survivors} minor-GC survivors")]
    MinorGcSurvivorAllocationFailed {
        /// The requested survivor-plan capacity.
        survivors: usize,
    },
    /// A young frontier object had no age metadata.
    #[error("missing nursery age metadata for 0x{address:x}", address = address.address_bits())]
    MissingNurseryObjectAge {
        /// The young object missing nursery metadata.
        address: GcHeapAddress,
    },
    /// A young object appeared more than once in the nursery age table.
    #[error("duplicate nursery age metadata for 0x{address:x}", address = address.address_bits())]
    DuplicateNurseryObjectAge {
        /// The duplicated young object.
        address: GcHeapAddress,
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

    #[test]
    fn minor_gc_plan_uses_young_roots_and_remembered_targets_only() {
        let root = address(0x1000);
        let remembered = address(0x2000);
        let ignored_old = address(0x3000);
        let ignored_permanent = address(0x4000);
        let mut remembered_set = RememberedSet::new();
        remembered_set
            .record(RememberedEdge::new(address(0x5000), remembered))
            .expect("remembered edge records");
        let plan = MinorGcPlan::from_roots_and_remembered(
            [
                ResolvedValueGeneration::Inline,
                ResolvedValueGeneration::young(root),
                ResolvedValueGeneration::old(ignored_old),
                ResolvedValueGeneration::permanent(ignored_permanent),
            ],
            &remembered_set,
            &[
                NurseryObjectAge::new(root, 0),
                NurseryObjectAge::new(remembered, 0),
            ],
            MinorGcPromotionPolicy::new(2),
        )
        .expect("minor GC plan builds");

        assert_eq!(plan.len(), 2);
        assert!(!plan.is_empty());
        assert_eq!(plan.survivors()[0].address(), root);
        assert_eq!(plan.survivors()[1].address(), remembered);
        assert!(
            plan.survivors()
                .iter()
                .all(|survivor| survivor.action() == MinorGcSurvivorAction::CopyToNursery)
        );
    }

    #[test]
    fn minor_gc_plan_deduplicates_roots_and_distinct_remembered_sources() {
        let young = address(0x1000);
        let mut remembered_set = RememberedSet::new();
        remembered_set
            .record(RememberedEdge::new(address(0x3000), young))
            .expect("remembered edge records");
        remembered_set
            .record(RememberedEdge::new(address(0x4000), young))
            .expect("same young target from a distinct source records");

        let plan = MinorGcPlan::from_roots_and_remembered(
            [
                ResolvedValueGeneration::young(young),
                ResolvedValueGeneration::young(young),
            ],
            &remembered_set,
            &[NurseryObjectAge::new(young, 0)],
            MinorGcPromotionPolicy::new(2),
        )
        .expect("minor GC plan builds");

        assert_eq!(plan.survivors().len(), 1);
        assert_eq!(plan.survivors()[0].address(), young);
    }

    #[test]
    fn minor_gc_plan_applies_age_based_promotion_policy() {
        let copy = address(0x1000);
        let promote = address(0x2000);
        let plan = MinorGcPlan::from_roots_and_remembered(
            [
                ResolvedValueGeneration::young(copy),
                ResolvedValueGeneration::young(promote),
            ],
            &RememberedSet::new(),
            &[
                NurseryObjectAge::new(copy, 0),
                NurseryObjectAge::new(promote, 1),
            ],
            MinorGcPromotionPolicy::new(2),
        )
        .expect("minor GC plan builds");

        assert_eq!(plan.survivors()[0].previous_survivals(), 0);
        assert_eq!(plan.survivors()[0].next_survivals(), 1);
        assert_eq!(
            plan.survivors()[0].action(),
            MinorGcSurvivorAction::CopyToNursery
        );
        assert_eq!(plan.survivors()[1].previous_survivals(), 1);
        assert_eq!(plan.survivors()[1].next_survivals(), 2);
        assert_eq!(
            plan.survivors()[1].action(),
            MinorGcSurvivorAction::PromoteToOld
        );
    }

    #[test]
    fn zero_survival_threshold_promotes_every_minor_gc_survivor() {
        let young = address(0x1000);
        let plan = MinorGcPlan::from_roots_and_remembered(
            [ResolvedValueGeneration::young(young)],
            &RememberedSet::new(),
            &[NurseryObjectAge::new(young, 0)],
            MinorGcPromotionPolicy::new(0),
        )
        .expect("minor GC plan builds");

        assert_eq!(plan.survivors()[0].next_survivals(), 1);
        assert_eq!(
            plan.survivors()[0].action(),
            MinorGcSurvivorAction::PromoteToOld
        );
    }

    #[test]
    fn minor_gc_plan_rejects_missing_or_duplicate_nursery_metadata() {
        let young = address(0x1000);
        assert_eq!(
            MinorGcPlan::from_roots_and_remembered(
                [ResolvedValueGeneration::young(young)],
                &RememberedSet::new(),
                &[],
                MinorGcPromotionPolicy::new(2),
            ),
            Err(GenerationalGcError::MissingNurseryObjectAge { address: young })
        );
        assert_eq!(
            MinorGcPlan::from_roots_and_remembered(
                [ResolvedValueGeneration::young(young)],
                &RememberedSet::new(),
                &[
                    NurseryObjectAge::new(young, 0),
                    NurseryObjectAge::new(young, 1)
                ],
                MinorGcPromotionPolicy::new(2),
            ),
            Err(GenerationalGcError::DuplicateNurseryObjectAge { address: young })
        );
    }
}
