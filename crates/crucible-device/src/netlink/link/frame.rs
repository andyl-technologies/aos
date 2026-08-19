//! Frame identities, resolved effects, deliveries, policies, and deterministic draws.

use super::*;

/// The shmem slot the link carries frames over (`SLOT_NET_ROUTER`).
///
/// Re-exported from `crucible-shmem` so the slot binding is referenced, never
/// hardcoded ([IO-20]). The QEMU backend performs the concrete ring copy while
/// this crate owns the deterministic link model.
pub const LINK_SLOT: usize = SLOT_NET_ROUTER;

/// A frame emitted by the link's source node at a virtual-time icount.
///
/// The payload is opaque bytes the link delivers (and may corrupt); `emit_icount`
/// is the source's icount when the frame was emitted (the base for the delivery
/// computation, [IO-20]); `frame_id` correlates the frame across the link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    /// The source node's icount when the frame was emitted.
    pub emit_icount: u64,
    /// The correlation id carried with the frame.
    pub frame_id: u32,
    /// The opaque frame payload.
    pub payload: Vec<u8>,
    /// Exact signal-adapter outcomes already resolved for this frame.
    pub(super) resolved_effects: ResolvedNetworkFrameEffects,
}

impl Frame {
    /// Creates a frame emitted at `emit_icount` with an opaque payload.
    #[must_use]
    pub fn new(emit_icount: u64, frame_id: u32, payload: Vec<u8>) -> Self {
        Self {
            emit_icount,
            frame_id,
            payload,
            resolved_effects: ResolvedNetworkFrameEffects::default(),
        }
    }

    /// Replaces the exact signal-adapter outcomes carried by this frame.
    #[must_use]
    pub fn with_resolved_effects(mut self, effects: ResolvedNetworkFrameEffects) -> Self {
        self.resolved_effects = effects;
        self
    }

    /// Returns the exact signal-adapter outcomes carried by this frame.
    #[must_use]
    pub const fn resolved_effects(&self) -> &ResolvedNetworkFrameEffects {
        &self.resolved_effects
    }
}

/// Exact per-frame outcomes resolved by the signal adapter before link scheduling.
///
/// This is an outcome contract rather than another fault program: the link
/// never evaluates signals, probabilities, technology lookups, or composition
/// rules. It only applies these already-resolved integer results.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResolvedNetworkFrameEffects {
    /// Signed adjustment to immutable link latency before floor clamping.
    latency_delta_nanos: i64,
    /// Nonnegative propagation, access, jitter, and reorder delay.
    additional_delay_nanos: u64,
    /// Minimum effective bit-rate cap after adapter-side composition.
    serialization_rate_cap_bps: Option<u64>,
    /// Whether adapter-owned queue service already consumed serialization time.
    serialization_accounted: bool,
    /// Canonical identities of intermittent-contact services already reserved.
    contact_services_accounted: Vec<[u8; 32]>,
    /// Whether the adapter resolved this frame to no delivery.
    drop: bool,
    /// Added-copy gaps from the primary delivery, in canonical copy order.
    duplicate_gaps_nanos: Vec<u64>,
}

/// Failure to compose a bounded exact per-frame network outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ResolvedNetworkFrameEffectsError {
    /// Signed latency composition exceeded its exact integer representation.
    #[error("resolved network latency adjustment overflowed")]
    LatencyOverflow,
    /// Nonnegative delay composition exceeded its exact integer representation.
    #[error("resolved network delay overflowed")]
    DelayOverflow,
    /// A bit-rate cap must be positive.
    #[error("resolved network bit-rate cap must be positive")]
    ZeroRate,
    /// The bounded per-frame copy count was exceeded.
    #[error("resolved network duplicate count exceeds 256")]
    DuplicateLimit,
    /// The bounded per-frame contact-service identity count was exceeded.
    #[error("resolved network contact-service count exceeds 256")]
    ContactServiceLimit,
}

impl ResolvedNetworkFrameEffects {
    /// Adds one signed latency contribution exactly.
    ///
    /// # Errors
    ///
    /// Returns [`ResolvedNetworkFrameEffectsError::LatencyOverflow`] when the
    /// composed signed adjustment cannot be represented by `i64`.
    pub fn add_latency_delta(
        &mut self,
        delta_nanos: i64,
    ) -> Result<(), ResolvedNetworkFrameEffectsError> {
        self.latency_delta_nanos = self
            .latency_delta_nanos
            .checked_add(delta_nanos)
            .ok_or(ResolvedNetworkFrameEffectsError::LatencyOverflow)?;
        Ok(())
    }

    /// Adds one nonnegative delay contribution exactly.
    ///
    /// # Errors
    ///
    /// Returns [`ResolvedNetworkFrameEffectsError::DelayOverflow`] when the
    /// composed delay cannot be represented by `u64`.
    pub fn add_delay(&mut self, delay_nanos: u64) -> Result<(), ResolvedNetworkFrameEffectsError> {
        self.additional_delay_nanos = self
            .additional_delay_nanos
            .checked_add(delay_nanos)
            .ok_or(ResolvedNetworkFrameEffectsError::DelayOverflow)?;
        Ok(())
    }

    /// Applies a positive simultaneous rate constraint using minimum composition.
    ///
    /// # Errors
    ///
    /// Returns [`ResolvedNetworkFrameEffectsError::ZeroRate`] for a zero cap.
    pub fn constrain_rate(
        &mut self,
        bits_per_second: u64,
    ) -> Result<(), ResolvedNetworkFrameEffectsError> {
        if bits_per_second == 0 {
            return Err(ResolvedNetworkFrameEffectsError::ZeroRate);
        }
        self.serialization_rate_cap_bps = Some(
            self.serialization_rate_cap_bps
                .map_or(bits_per_second, |current| current.min(bits_per_second)),
        );
        Ok(())
    }

    /// Resolves this frame to no delivery.
    pub const fn mark_drop(&mut self) {
        self.drop = true;
    }

    /// Marks serialization as fully consumed by the adapter-owned service queue.
    pub const fn mark_serialization_accounted(&mut self) {
        self.serialization_accounted = true;
    }

    /// Marks one exact contact service and downstream serialization as consumed.
    ///
    /// # Errors
    ///
    /// Returns [`ResolvedNetworkFrameEffectsError::ContactServiceLimit`] when
    /// the frame has already traversed 256 distinct contact services.
    pub fn mark_contact_service_accounted(
        &mut self,
        identity: [u8; 32],
    ) -> Result<(), ResolvedNetworkFrameEffectsError> {
        match self.contact_services_accounted.binary_search(&identity) {
            Ok(_index) => {}
            Err(index) => {
                if self.contact_services_accounted.len() == 256 {
                    return Err(ResolvedNetworkFrameEffectsError::ContactServiceLimit);
                }
                self.contact_services_accounted.insert(index, identity);
            }
        }
        self.serialization_accounted = true;
        Ok(())
    }

    /// Requires a later queue or link to serialize this frame again.
    ///
    /// Protocol expansion uses this after an upstream service point because
    /// every child is a new downstream frame with its own copied headers.
    pub fn require_serialization(&mut self) {
        self.serialization_accounted = false;
        self.contact_services_accounted.clear();
    }

    /// Adds one bounded copy gap and preserves canonical gap ordering.
    ///
    /// # Errors
    ///
    /// Returns [`ResolvedNetworkFrameEffectsError::DuplicateLimit`] after 256
    /// added copies have already been composed.
    pub fn add_duplicate_gap(
        &mut self,
        gap_nanos: u64,
    ) -> Result<(), ResolvedNetworkFrameEffectsError> {
        if self.duplicate_gaps_nanos.len() == 256 {
            return Err(ResolvedNetworkFrameEffectsError::DuplicateLimit);
        }
        let index = self
            .duplicate_gaps_nanos
            .partition_point(|gap| *gap <= gap_nanos);
        self.duplicate_gaps_nanos.insert(index, gap_nanos);
        Ok(())
    }

    /// Returns the composed signed latency adjustment.
    #[must_use]
    pub const fn latency_delta_nanos(&self) -> i64 {
        self.latency_delta_nanos
    }

    /// Returns the composed nonnegative delay.
    #[must_use]
    pub const fn additional_delay_nanos(&self) -> u64 {
        self.additional_delay_nanos
    }

    /// Returns the composed minimum rate constraint.
    #[must_use]
    pub const fn serialization_rate_cap_bps(&self) -> Option<u64> {
        self.serialization_rate_cap_bps
    }

    /// Returns whether the adapter already consumed serialization service.
    #[must_use]
    pub const fn serialization_is_accounted(&self) -> bool {
        self.serialization_accounted
    }

    /// Returns whether custody already reserved this exact contact service.
    #[must_use]
    pub fn contact_service_is_accounted(&self, identity: &[u8; 32]) -> bool {
        self.contact_services_accounted
            .binary_search(identity)
            .is_ok()
    }

    /// Returns exact contact services already consumed in canonical order.
    #[must_use]
    pub fn accounted_contact_services(&self) -> &[[u8; 32]] {
        &self.contact_services_accounted
    }

    /// Returns whether the frame resolves to no delivery.
    #[must_use]
    pub const fn is_dropped(&self) -> bool {
        self.drop
    }

    /// Returns added-copy gaps in canonical delivery order.
    #[must_use]
    pub fn duplicate_gaps_nanos(&self) -> &[u64] {
        &self.duplicate_gaps_nanos
    }
}

/// A frame delivered to the destination at an exact icount, in delivery order.
///
/// The link drains these from its in-flight queue when the consumer's frontier
/// reaches `delivery_icount`. A duplicate fault produces two `Delivery` values
/// for one emitted [`Frame`], distinguished by their `key.seq`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delivery {
    /// The deterministic delivery-order key (icount + source + sequence).
    pub key: FrameDeliveryKey,
    /// The correlation id echoed from the originating frame.
    pub frame_id: u32,
    /// The delivered payload (post-corruption if a corrupt fault fired).
    pub payload: Vec<u8>,
}

impl Delivery {
    /// Returns the exact icount at which this frame becomes visible.
    #[must_use]
    pub fn delivery_icount(&self) -> u64 {
        self.key.delivery_icount
    }
}

/// The policy for a reorder/jitter shift that lands in the consumer's past.
///
/// RFC section 15.4.2 / [IO-34] forbids ever silently delivering late. A modeled shift
/// that would land at or before the consumer's frontier is therefore either
/// **clamped** up to the next deliverable future icount or it **fails loudly**
/// via the divergence path; the link never delivers late.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PastDeliveryPolicy {
    /// Fail loudly with [`DeviceError::DeliveryReorderedIntoPast`] ([INV-10]).
    FailLoud,
    /// Clamp the delivery up to `consumer_frontier + 1` (a deliverable future).
    ///
    /// When a duplicate fault also fires and both copies land in the past, the
    /// duplicate is clamped to preserve its `duplicate_gap_ns` relative to the
    /// clamped primary, so the two copies stay at distinct, ordered icounts rather
    /// than collapsing onto one.
    ClampToFuture,
}

/// The outcome of resolving one emitted frame through the link.
///
/// A frame resolves to zero deliveries (loss), one delivery (the fault-free or
/// shifted/corrupted path), or two deliveries (duplicate). A lookahead recompute
/// raised during the link's lifetime is surfaced separately via
/// [`NetLink::take_lookahead_recompute`], not on this per-emit outcome.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResolveOutcome {
    /// The deliveries produced (0 = loss, 1 = normal, 2 = duplicate).
    pub deliveries: Vec<Delivery>,
}

/// The injected RNG draws one frame's fault resolution consumes, in fixed order.
///
/// Each probabilistic effect draws from this struct in the order the model
/// applies them: jitter, reorder, loss rates, duplicate, corrupt (with
/// `corruption_selectors` supplying draws for payload corruption strategies).
/// Supplying the same draws and the same frame yields byte-identical deliveries
/// ([IO-4], [IO-22]).
///
/// The seeded per-device RNG ([`DeviceRng`]) produces these draws in this exact
/// consumption order via [`FrameDraws::from_rng_for_faults`] ([IO-21]); callers
/// may still inject draws directly for unit tests.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FrameDraws {
    /// The jitter-window draw.
    pub jitter: u64,
    /// The reorder-window draw.
    pub reorder: u64,
    /// The loss-Bernoulli draw.
    pub loss: u64,
    /// Additional loss-Bernoulli draws for overlapping loss rates.
    pub additional_loss: Vec<u64>,
    /// The duplicate-Bernoulli draw.
    pub duplicate: u64,
    /// The corrupt-Bernoulli draw.
    pub corrupt: u64,
    /// Corruption selector draws.
    ///
    /// Strategies consume these in declaration order: bit flips use
    /// bit-position selectors, field mutation uses one byte selector, and
    /// truncation uses one truncation-length selector.
    pub corruption_selectors: Vec<u64>,
}

impl FrameDraws {
    /// Draws one frame's fault draws from the seeded per-device RNG ([IO-21]).
    ///
    /// Consumes draws from `rng` in the fixed model order -- jitter, reorder,
    /// loss, duplicate, corrupt, then `bit_flips` corruption-bit selectors -- so
    /// two runs with the same seed and the same frames produce byte-identical
    /// deliveries ([IO-22]). `selector_draws` is the number of selectors needed
    /// by the link's concrete corruption strategies; supplying it here keeps
    /// the RNG cursor aligned whether or not corruption ultimately fires.
    #[must_use]
    pub fn from_rng(rng: &mut DeviceRng, selector_draws: u32) -> Self {
        Self::from_rng_parts(rng, selector_draws, 0)
    }

    /// Draws one frame's fault draws for an effective link fault table.
    ///
    /// This is the RFC-level path used by [`NetLink::emit_with_rng_draws`]. It
    /// consumes one draw for each overlapping loss probability before duplicate
    /// and corruption draws, preserving the highest-first any-fires evaluation
    /// order while keeping the primary loss draw first.
    #[must_use]
    pub fn from_rng_for_faults(rng: &mut DeviceRng, faults: &LinkFaults) -> Self {
        Self::from_rng_parts(
            rng,
            faults.corruption_selector_draws(),
            faults.additional_loss.len(),
        )
    }

    fn from_rng_parts(
        rng: &mut DeviceRng,
        selector_draws: u32,
        additional_loss_count: usize,
    ) -> Self {
        let jitter = rng.next_u64();
        let reorder = rng.next_u64();
        let loss = rng.next_u64();
        let mut additional_loss = Vec::with_capacity(additional_loss_count);
        for _ in 0..additional_loss_count {
            additional_loss.push(rng.next_u64());
        }
        let duplicate = rng.next_u64();
        let corrupt = rng.next_u64();
        let mut corruption_selectors = Vec::with_capacity(selector_draws as usize);
        for _ in 0..selector_draws {
            corruption_selectors.push(rng.next_u64());
        }
        Self {
            jitter,
            reorder,
            loss,
            additional_loss,
            duplicate,
            corrupt,
            corruption_selectors,
        }
    }
}
