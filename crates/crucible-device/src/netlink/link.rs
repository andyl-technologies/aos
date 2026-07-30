//! The network-link sub-node: a directed `A -> B` edge that schedules frames.
//!
//! This module owns [`NetLink`], the link sub-node of RFC-0010 §15.4. A link
//! carries [`Frame`]s from a source VM node to a destination over the
//! [`SLOT_NET_ROUTER`] shmem slot: given a frame emitted by the source at icount
//! `t`, the link computes the destination
//! `delivery_icount = ic(vt(t) + effective_latency)` and applies the effective
//! fault table at RESOLVE ([IO-20]).
//!
//! Unlike the block and 9p sub-nodes (whose completion is an *exact* local
//! event), the link is **the one source of conservative uncertainty**
//! (§15.4.2): its base latency supplies the scheduler's lookahead bound, so the
//! link enforces a strictly positive latency floor ([IO-33]), clamps sub-floor
//! latency faults up to that floor, raises a recompute signal when the
//! conservative minimum latency bound changes, and fails loudly when a
//! reorder/jitter shift would deliver into the consumer's past ([IO-34]).
//!
//! ```text
//! emit(frame, t):                                  (SOURCE emits)
//!   base_ns    = vt(t)
//!   eff_lat    = max(base_latency + faults.added_latency, floor)   // clamp (IO-33)
//!   delivery_ns = base_ns + eff_lat
//!              += serialization_delay(len, bandwidth)
//!              += jitter_shift(draw) + reorder_shift(draw)
//!   delivery_icount = ceil_ns_to_icount(delivery_ns)
//!   if delivery_icount <= consumer_frontier: FAIL-LOUD or clamp (IO-34)
//!   loss?      DROP (no delivery)
//!   duplicate? emit a 2nd delivery at delivery_ns + gap
//!   corrupt?   mutate payload bytes
//! advance_to(limit): drain frames with delivery_icount <= limit  (DESTINATION sees)
//! ```
//!
//! The concrete QEMU transport drains and fills the `SLOT_NET_ROUTER` rings in
//! `crucible-qemu`'s network I/O servicer. This device-level type deliberately
//! owns only deterministic scheduling and fault transforms. It references the
//! slot constant and stamps each delivery's `src_node`/`seq` into a
//! [`FrameDeliveryKey`] so the modeled order matches the transport.
//!
//! The probabilistic transforms consume RNG draws; [`NetLink::emit_from_rng`]
//! draws them from the seeded per-device RNG ([`crate::fault::DeviceRng`]) forked
//! by name-hash in their fixed order ([IO-21]), and [`NetLink::emit`] accepts
//! injected draws for unit testing.

use crucible_shmem::{FrameDeliveryKey, SLOT_NET_ROUTER};

use crate::clock::VirtualClock;
use crate::error::DeviceError;
use crate::inflight::{InflightQueue, PendingResponse};
use crate::request::{Response, ResponseStatus};

use crate::fault::DeviceRng;

use super::fault::{
    LinkCorruptionStrategy, LinkFaults, corrupt_payload, jitter_shift_ns, reorder_shift_ns,
};

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
}

impl Frame {
    /// Creates a frame emitted at `emit_icount` with an opaque payload.
    #[must_use]
    pub fn new(emit_icount: u64, frame_id: u32, payload: Vec<u8>) -> Self {
        Self {
            emit_icount,
            frame_id,
            payload,
        }
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
/// RFC §15.4.2 / [IO-34] forbids ever silently delivering late. A modeled shift
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
/// Each probabilistic fault draws from this struct in the order the model
/// applies them: jitter, reorder, loss rates, duplicate, corrupt (with
/// `corrupt_bits` supplying selectors for payload corruption strategies).
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
    /// Legacy bit-flip-only faults interpret each draw as a bit position.
    /// Strategy-based corruption consumes these in strategy order: bit flips use
    /// bit-position selectors, field mutation uses one byte selector, and
    /// truncation uses one truncation-length selector.
    pub corrupt_bits: Vec<u64>,
}

impl FrameDraws {
    /// Draws one frame's fault draws from the seeded per-device RNG ([IO-21]).
    ///
    /// Consumes draws from `rng` in the fixed model order — jitter, reorder,
    /// loss, duplicate, corrupt, then `bit_flips` corruption-bit selectors — so
    /// two runs with the same seed and the same frames produce byte-identical
    /// deliveries ([IO-22]). `bit_flips` is the link's `corrupt_bit_flips`
    /// parameter; supplying it here keeps the RNG cursor aligned whether or not
    /// the corrupt fault ultimately fires, so the next frame's draws are stable.
    #[must_use]
    pub fn from_rng(rng: &mut DeviceRng, bit_flips: u32) -> Self {
        Self::from_rng_parts(rng, bit_flips, 0)
    }

    /// Draws one frame's fault draws for an effective link fault table.
    ///
    /// This is the RFC-level path used by [`NetLink::emit_with_rng_draws`]. It
    /// consumes one draw for each overlapping loss probability before duplicate
    /// and corruption draws, preserving the highest-first any-fires evaluation
    /// order while keeping the legacy single-loss path byte-identical.
    #[must_use]
    pub fn from_rng_for_faults(rng: &mut DeviceRng, faults: &LinkFaults) -> Self {
        Self::from_rng_parts(
            rng,
            faults.corrupt_bit_draws(),
            faults.additional_loss.len(),
        )
    }

    fn from_rng_parts(rng: &mut DeviceRng, bit_flips: u32, additional_loss_count: usize) -> Self {
        let jitter = rng.next_u64();
        let reorder = rng.next_u64();
        let loss = rng.next_u64();
        let mut additional_loss = Vec::with_capacity(additional_loss_count);
        for _ in 0..additional_loss_count {
            additional_loss.push(rng.next_u64());
        }
        let duplicate = rng.next_u64();
        let corrupt = rng.next_u64();
        let mut corrupt_bits = Vec::with_capacity(bit_flips as usize);
        for _ in 0..bit_flips {
            corrupt_bits.push(rng.next_u64());
        }
        Self {
            jitter,
            reorder,
            loss,
            additional_loss,
            duplicate,
            corrupt,
            corrupt_bits,
        }
    }
}

/// A directed network link sub-node: `A -> B` frame delivery with faults.
///
/// Composes a [`VirtualClock`] and a delivery-ordered [`InflightQueue`] (reusing
/// the foundation's in-flight machinery) with the link's base latency, latency
/// floor, and effective fault table. Frames are emitted with [`NetLink::emit`],
/// advanced to a limit with [`NetLink::advance_to`], and drained with
/// [`NetLink::next_delivery`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetLink {
    clock: VirtualClock,
    inflight: InflightQueue,
    /// The source node id stamped into delivery keys.
    src_node: u32,
    /// The link's base latency in virtual nanoseconds (strictly positive, [IO-33]).
    base_latency_ns: u64,
    /// The strictly-positive minimum link-latency floor in virtual nanoseconds.
    floor_ns: u64,
    /// The effective fault table applied at RESOLVE.
    faults: LinkFaults,
    /// The next per-frame sequence number, for deterministic tie-breaking.
    next_seq: u32,
    /// Set when a conservative latency-bound change requires scheduler recompute.
    lookahead_recompute_pending: bool,
    /// The per-device RNG stream cursor (draws consumed so far, [IO-23]).
    ///
    /// Advanced by [`NetLink::emit_from_rng`] as the seeded per-device RNG
    /// produces each frame's draws; captured in the snapshot and re-derived on
    /// restore via [`NetLink::rng`] so a fork resumes the same draw sequence.
    rng_position: u64,
}

impl NetLink {
    /// Builds a link with a clock shift, source id, base latency, floor, and faults.
    ///
    /// The base latency MUST be strictly positive and at or above `floor_ns`, and
    /// `floor_ns` MUST itself be strictly positive ([IO-33]): the base latency is
    /// what supplies the scheduler's conservative lookahead bound, so a
    /// zero-latency link is rejected rather than silently collapsing parallelism.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::Clock`] when `shift_bits >= 64`, and
    /// [`DeviceError::LinkLatencyBelowFloor`] when `floor_ns` is zero or
    /// `base_latency_ns < floor_ns`.
    pub fn new(
        shift_bits: u8,
        src_node: u32,
        base_latency_ns: u64,
        floor_ns: u64,
        faults: LinkFaults,
    ) -> Result<Self, DeviceError> {
        if floor_ns == 0 || base_latency_ns < floor_ns {
            return Err(DeviceError::LinkLatencyBelowFloor {
                base_latency_ns,
                floor_ns,
            });
        }
        Ok(Self {
            clock: VirtualClock::new(shift_bits)?,
            inflight: InflightQueue::new(),
            src_node,
            base_latency_ns,
            floor_ns,
            faults,
            next_seq: 0,
            lookahead_recompute_pending: false,
            rng_position: 0,
        })
    }

    /// Returns the link's current (consumer-frontier) icount.
    #[must_use]
    pub fn current_icount(&self) -> u64 {
        self.clock.current_icount()
    }

    /// Returns the link's base latency in virtual nanoseconds.
    #[must_use]
    pub fn base_latency_ns(&self) -> u64 {
        self.base_latency_ns
    }

    /// Returns the strictly-positive minimum link-latency floor.
    #[must_use]
    pub fn floor_ns(&self) -> u64 {
        self.floor_ns
    }

    /// Returns a read-only view of the effective fault table.
    #[must_use]
    pub fn faults(&self) -> &LinkFaults {
        &self.faults
    }

    /// Returns the per-device RNG stream cursor (draws consumed so far, [IO-23]).
    #[must_use]
    pub fn rng_position(&self) -> u64 {
        self.rng_position
    }

    /// Repositions the deterministic cursor after an explorer-injected draw set.
    ///
    /// This setter is intentionally narrow: the engine supplies a cursor derived
    /// from the exact draw vector consumed by [`NetLink::emit`]. General callers
    /// should use [`NetLink::emit_with_rng_draws`].
    pub fn set_rng_position_for_branch(&mut self, position: u64) {
        self.rng_position = position;
    }

    /// Returns the number of frames in flight (resolved but not yet delivered).
    #[must_use]
    pub fn inflight_len(&self) -> usize {
        self.inflight.len()
    }

    /// Returns the in-flight head's delivery icount: the next exact local event.
    ///
    /// The scheduler reads this to bound the destination's horizon; `None` when no
    /// frame is in flight.
    #[must_use]
    pub fn next_exact_local_event(&self) -> Option<u64> {
        self.inflight.next_exact_local_event()
    }

    /// Returns the link's **effective latency** in ns: base + added, clamped to the floor.
    ///
    /// A latency fault that *raises* the effective latency is honored as-is (it
    /// only widens lookahead); a fault that would push it below the floor is
    /// clamped up to the floor ([IO-33]). This is the value the scheduler's
    /// lookahead uses; it is always at or above the strictly-positive floor.
    #[must_use]
    pub fn effective_latency_ns(&self) -> u64 {
        let raised = self
            .base_latency_ns
            .saturating_add(self.faults.added_latency_ns);
        raised.max(self.floor_ns)
    }

    /// Replaces the effective fault table, flagging a lookahead recompute if needed.
    ///
    /// If the new table changes the link's conservative minimum effective latency
    /// ([IO-33]) — currently the `added_latency_ns` component — the link sets the
    /// lookahead-recompute flag so the scheduler recomputes its lookahead/horizon
    /// at the **next quantum boundary**, never mid-RUN. The signal is exposed via
    /// [`NetLink::take_lookahead_recompute`]; this method cannot call the
    /// scheduler (it lives in another crate), so it records the flag for the
    /// integration layer (CS-INT) to consume.
    ///
    /// Jitter, reorder, bandwidth, loss, duplicate, and corrupt changes do not
    /// raise the flag ([`LinkFaults::affects_latency`]). They may shift or alter
    /// individual frames, but they do not raise the scalar lower bound consumed by
    /// the scheduler's lookahead graph.
    ///
    /// The recompute predicate compares the fields that can change the scalar
    /// bound, not the full per-frame latency profile.
    pub fn set_faults(&mut self, faults: LinkFaults) {
        if Self::latency_profile_changed(&self.faults, &faults) {
            self.lookahead_recompute_pending = true;
        }
        self.faults = faults;
    }

    /// Returns whether two fault tables differ in the conservative latency bound.
    ///
    /// The bound-relevant fields are exactly those
    /// [`LinkFaults::affects_latency`] reports. Other fields can perturb a
    /// specific delivery after EMIT, but their minimum additional delay is zero and
    /// therefore they do not change the lookahead edge the scheduler reads
    /// ([IO-33]).
    fn latency_profile_changed(before: &LinkFaults, after: &LinkFaults) -> bool {
        before.added_latency_ns != after.added_latency_ns
    }

    /// Takes and clears the pending lookahead-recompute signal ([IO-33]).
    ///
    /// Returns `true` exactly once after any conservative latency-bound change,
    /// then resets to `false`. The integration layer (CS-INT) consumes this at
    /// the quantum boundary to trigger the scheduler's lookahead/horizon
    /// recompute ([SCHED-37]).
    pub fn take_lookahead_recompute(&mut self) -> bool {
        core::mem::replace(&mut self.lookahead_recompute_pending, false)
    }

    /// Returns whether a lookahead recompute is pending without clearing it.
    #[must_use]
    pub fn lookahead_recompute_pending(&self) -> bool {
        self.lookahead_recompute_pending
    }

    /// Resolves and enqueues one emitted frame, applying the effective fault table.
    ///
    /// Computes the delivery icount from the base latency (clamped to the floor,
    /// [IO-33]) plus bandwidth serialization and seeded jitter/reorder shifts,
    /// then applies the probabilistic faults from `draws` ([IO-20]): loss drops
    /// the frame (zero deliveries), duplicate emits a second delivery at a
    /// deterministically-derived later icount, and corrupt mutates payload bytes.
    /// Each produced delivery is inserted into the delivery-ordered
    /// in-flight queue and is also returned in the [`ResolveOutcome`].
    ///
    /// The `draws` are injected here for unit testing;
    /// [`NetLink::emit_from_rng`] draws them from the seeded per-device RNG. The
    /// same `frame` and `draws` always yield byte-identical deliveries ([IO-4],
    /// [IO-22]).
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::CompletionOverflow`] / [`DeviceError::Clock`] /
    /// [`DeviceError::IcountOverflow`] when the virtual-time arithmetic overflows,
    /// and — when `policy` is [`PastDeliveryPolicy::FailLoud`] —
    /// [`DeviceError::DeliveryReorderedIntoPast`] if a jitter/reorder shift would
    /// move the delivery to at or before the consumer's current frontier ([IO-34]).
    /// On any error no delivery is enqueued (the frame is fully rejected).
    pub fn emit(
        &mut self,
        frame: &Frame,
        draws: &FrameDraws,
        policy: PastDeliveryPolicy,
    ) -> Result<ResolveOutcome, DeviceError> {
        let mut outcome = ResolveOutcome::default();

        // --- partition (IO-20): drop the frame, no delivery ---
        if self.faults.partitioned {
            return Ok(outcome);
        }

        // --- delivery-time computation (deterministic shifts) ---
        let base_ns = self.clock.virtual_ns(frame.emit_icount)?;
        let eff_latency = self.effective_latency_ns();
        let len = frame.payload.len() as u64;
        let serialization = self.faults.serialization_delay_ns(len);
        let jitter = jitter_shift_ns(draws.jitter, self.faults.jitter_window_ns);
        let reorder = reorder_shift_ns(draws.reorder, self.faults.reorder_window_ns);

        let delivery_ns = base_ns
            .checked_add(eff_latency)
            .and_then(|v| v.checked_add(serialization))
            .and_then(|v| v.checked_add(jitter))
            .and_then(|v| v.checked_add(reorder))
            .ok_or(DeviceError::CompletionOverflow {
                request_icount: frame.emit_icount,
                latency_ns: eff_latency,
            })?;
        // The unguarded primary icount; kept so the duplicate gap can be re-derived
        // from raw values even when the primary is clamped into the future.
        let delivery_icount_raw = self.clock.ceil_ns_to_icount(delivery_ns)?;

        // --- into-the-past guard (IO-34): never silently deliver late ---
        let delivery_icount = self.guard_future(delivery_icount_raw, policy)?;

        // --- loss (IO-20): drop the frame, no delivery ---
        if self.faults.loss_fires(draws.loss, &draws.additional_loss) {
            return Ok(outcome);
        }

        // --- corrupt (IO-20): mutate payload bytes deterministically ---
        let mut payload = frame.payload.clone();
        if self.faults.corrupt.fires(draws.corrupt) {
            corrupt_link_payload(&self.faults, &mut payload, &draws.corrupt_bits);
        }

        // --- the primary delivery ---
        // `delivery_icount` is the guarded (possibly clamped) primary icount.
        let primary = self.enqueue_delivery(delivery_icount, frame.frame_id, payload.clone());
        outcome.deliveries.push(primary);

        // --- duplicate (IO-20): emit a second delivery at a later icount ---
        if self.faults.duplicate.fires(draws.duplicate) {
            let dup_ns = delivery_ns
                .checked_add(self.faults.duplicate_gap_ns)
                .ok_or(DeviceError::CompletionOverflow {
                    request_icount: frame.emit_icount,
                    latency_ns: self.faults.duplicate_gap_ns,
                })?;
            let dup_icount_raw = self.clock.ceil_ns_to_icount(dup_ns)?;
            // The duplicate must also stay in the consumer's future ([IO-34]).
            let dup_icount_guarded = self.guard_future(dup_icount_raw, policy)?;
            // Preserve the duplicate gap under ClampToFuture: if both the primary
            // and the duplicate were clamped into the consumer's past, naively
            // clamping both to frontier+1 would collapse them onto one icount and
            // lose `duplicate_gap_ns`. Re-derive the gap in icounts from the
            // *unguarded* raw values and keep the duplicate at least that far past
            // the guarded primary (and always strictly after it). This is a no-op
            // on the normal path where neither was clamped.
            let gap_icount = dup_icount_raw.saturating_sub(delivery_icount_raw);
            let dup_floor = delivery_icount
                .saturating_add(gap_icount)
                .max(delivery_icount.saturating_add(1));
            let dup_icount = dup_icount_guarded.max(dup_floor);
            let dup = self.enqueue_delivery(dup_icount, frame.frame_id, payload);
            outcome.deliveries.push(dup);
        }

        Ok(outcome)
    }

    /// Resolves one emitted frame, drawing its faults from the seeded RNG ([IO-21]).
    ///
    /// Identical to [`NetLink::emit`] except the [`FrameDraws`] are produced by
    /// the seeded per-device RNG in the fixed model order
    /// ([`FrameDraws::from_rng_for_faults`]) rather than injected, and the link's RNG cursor
    /// ([`NetLink::rng_position`]) advances to match. The cursor is captured in the
    /// snapshot so a fork resumes the same draw sequence ([IO-23]). The draws are
    /// taken before any early-out so the cursor stays aligned whether or not the
    /// frame is lost.
    ///
    /// # Errors
    ///
    /// Same as [`NetLink::emit`].
    pub fn emit_from_rng(
        &mut self,
        frame: &Frame,
        rng: &mut DeviceRng,
        policy: PastDeliveryPolicy,
    ) -> Result<ResolveOutcome, DeviceError> {
        let (outcome, _draws) = self.emit_with_rng_draws(frame, rng, policy)?;
        Ok(outcome)
    }

    /// Resolves one emitted frame from the seeded RNG and returns the consumed draws.
    ///
    /// This is the recording-friendly twin of [`NetLink::emit_from_rng`]: it
    /// draws the frame's [`FrameDraws`] from `rng`, resolves the frame through
    /// [`NetLink::emit`], advances [`NetLink::rng_position`], and returns both the
    /// [`ResolveOutcome`] and the raw draws. The engine uses this to record the
    /// same draw stream as engine `RngDraw` decisions without re-deriving link
    /// fault choices from the final payload.
    ///
    /// # Errors
    ///
    /// Same as [`NetLink::emit`].
    pub fn emit_with_rng_draws(
        &mut self,
        frame: &Frame,
        rng: &mut DeviceRng,
        policy: PastDeliveryPolicy,
    ) -> Result<(ResolveOutcome, FrameDraws), DeviceError> {
        let draws = FrameDraws::from_rng_for_faults(rng, &self.faults);
        let outcome = self.emit(frame, &draws, policy)?;
        self.rng_position = rng.position();
        Ok((outcome, draws))
    }

    /// Builds a seeded RNG positioned at this link's captured cursor ([IO-23]).
    ///
    /// Forks the link stream by name-hash from the engine's decision-RNG
    /// `root_seed` in `domain` for `name` ([DET-25]) and resumes it at the
    /// captured cursor, so the returned RNG's next draw is byte-identical to the
    /// uninterrupted run's. The caller supplies the engine root seed and the
    /// link's stable stream domain and name (the engine owns the name-hash).
    #[must_use]
    pub fn rng(&self, root_seed: u64, domain: &str, name: &str) -> DeviceRng {
        DeviceRng::restore(root_seed, domain, name, self.rng_position)
    }

    /// Enforces that a delivery icount is in the consumer's strict future ([IO-34]).
    ///
    /// A delivery at or before the current frontier can never be made visible at
    /// its exact icount; per `policy` the link either fails loudly or clamps up to
    /// `frontier + 1`. Never silently delivers late.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::DeliveryReorderedIntoPast`] when `policy` is
    /// [`PastDeliveryPolicy::FailLoud`] and the delivery is not strictly in the
    /// future.
    fn guard_future(
        &self,
        delivery_icount: u64,
        policy: PastDeliveryPolicy,
    ) -> Result<u64, DeviceError> {
        let frontier = self.clock.current_icount();
        if delivery_icount > frontier {
            return Ok(delivery_icount);
        }
        match policy {
            PastDeliveryPolicy::FailLoud => Err(DeviceError::DeliveryReorderedIntoPast {
                delivery_icount,
                consumer_frontier: frontier,
            }),
            // Clamp to the next deliverable future icount. `frontier` is below
            // u64::MAX in any real run; saturating keeps it total.
            PastDeliveryPolicy::ClampToFuture => Ok(frontier.saturating_add(1)),
        }
    }

    /// Inserts one delivery into the in-flight queue and returns it.
    ///
    /// Assigns the next per-frame sequence number so coincident deliveries break
    /// ties deterministically by `(delivery_icount, src_node, seq)`. The delivery
    /// is carried as a [`PendingResponse`] over the reused in-flight machinery;
    /// the [`Response`] payload is the (possibly corrupted) frame bytes.
    fn enqueue_delivery(
        &mut self,
        delivery_icount: u64,
        frame_id: u32,
        payload: Vec<u8>,
    ) -> Delivery {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        let key = FrameDeliveryKey {
            delivery_icount,
            src_node: self.src_node,
            seq,
        };
        let response = Response::new(frame_id, ResponseStatus::Ok, payload.clone());
        self.inflight.insert(PendingResponse::new(key, response));
        Delivery {
            key,
            frame_id,
            payload,
        }
    }

    /// Advances the clock to `limit` and returns every delivery due by then.
    ///
    /// Drains exactly the in-flight frames whose `delivery_icount <= limit`, in
    /// deterministic `(delivery_icount, src_node, seq)` order. The clock advances
    /// to `limit` (never backward).
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::ClockRegression`] when `limit` is below the current
    /// icount.
    pub fn advance_to(&mut self, limit: u64) -> Result<Vec<Delivery>, DeviceError> {
        self.clock.advance_to(limit)?;
        let due = self.inflight.drain_due(limit);
        Ok(due.into_iter().map(Self::pending_to_delivery).collect())
    }

    /// Pops the earliest in-flight frame whose delivery is at or before `limit`.
    ///
    /// A streaming alternative to [`NetLink::advance_to`] that returns one
    /// delivery at a time without advancing the clock. Returns `None` when the
    /// head is past `limit` or the queue is empty.
    pub fn next_delivery(&mut self, limit: u64) -> Option<Delivery> {
        match self.inflight.next_exact_local_event() {
            Some(head) if head <= limit => {
                let mut due = self.inflight.drain_due(head);
                // `drain_due(head)` may return several coincident frames; re-queue
                // all but the first so callers see exactly one per call.
                if due.is_empty() {
                    return None;
                }
                let first = due.remove(0);
                for pending in due {
                    self.inflight.insert(pending);
                }
                Some(Self::pending_to_delivery(first))
            }
            _ => None,
        }
    }

    /// Converts a reused [`PendingResponse`] back into a [`Delivery`].
    fn pending_to_delivery(pending: PendingResponse) -> Delivery {
        Delivery {
            key: pending.key,
            frame_id: pending.response.request_id,
            payload: pending.response.payload,
        }
    }

    /// Captures the link's deterministic state for snapshot/restore ([IO-23]).
    ///
    /// Holds the clock cursor, the base latency, floor, fault table, sequence
    /// counter, the pending-recompute flag, the RNG cursor, and the
    /// in-flight deliveries with their exact icounts. Restoring via
    /// [`NetLink::restore`] reproduces a byte-identical state.
    #[must_use]
    pub fn snapshot(&self) -> LinkSnapshot {
        LinkSnapshot {
            current_icount: self.clock.current_icount(),
            shift_bits: self.clock.shift_bits(),
            src_node: self.src_node,
            base_latency_ns: self.base_latency_ns,
            floor_ns: self.floor_ns,
            faults: self.faults.clone(),
            next_seq: self.next_seq,
            lookahead_recompute_pending: self.lookahead_recompute_pending,
            rng_position: self.rng_position,
            inflight: self.inflight.entries().to_vec(),
        }
    }

    /// Reconstructs a link from a captured snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::Clock`] when the snapshot's shift is invalid, and
    /// [`DeviceError::LinkLatencyBelowFloor`] when the captured base latency is
    /// below the captured floor (a corrupt snapshot).
    pub fn restore(snapshot: &LinkSnapshot) -> Result<Self, DeviceError> {
        if snapshot.floor_ns == 0 || snapshot.base_latency_ns < snapshot.floor_ns {
            return Err(DeviceError::LinkLatencyBelowFloor {
                base_latency_ns: snapshot.base_latency_ns,
                floor_ns: snapshot.floor_ns,
            });
        }
        let mut clock = VirtualClock::new(snapshot.shift_bits)?;
        clock.advance_to(snapshot.current_icount)?;
        let mut inflight = InflightQueue::new();
        for pending in &snapshot.inflight {
            inflight.insert(pending.clone());
        }
        Ok(Self {
            clock,
            inflight,
            src_node: snapshot.src_node,
            base_latency_ns: snapshot.base_latency_ns,
            floor_ns: snapshot.floor_ns,
            faults: snapshot.faults.clone(),
            next_seq: snapshot.next_seq,
            lookahead_recompute_pending: snapshot.lookahead_recompute_pending,
            rng_position: snapshot.rng_position,
        })
    }
}

/// The device half of a network link's `MaterializedState` ([IO-23], [IO-26]).
///
/// Captures the link's clock cursor, base latency, floor, effective fault table,
/// sequence counter, pending-recompute flag, RNG cursor, and the
/// in-flight deliveries. The active fault set is part of the captured state so a
/// fork resumes with identical link behavior (deferred wiring in CS-IO-5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkSnapshot {
    /// The link's current (consumer-frontier) icount at snapshot time.
    pub current_icount: u64,
    /// The fixed virtual-time shift in bits.
    pub shift_bits: u8,
    /// The source node id stamped into delivery keys.
    pub src_node: u32,
    /// The link's base latency in virtual nanoseconds.
    pub base_latency_ns: u64,
    /// The strictly-positive minimum link-latency floor.
    pub floor_ns: u64,
    /// The effective fault table active at snapshot time.
    pub faults: LinkFaults,
    /// The next per-frame sequence number.
    pub next_seq: u32,
    /// Whether a lookahead recompute was pending at snapshot time.
    pub lookahead_recompute_pending: bool,
    /// The per-device RNG stream cursor (draws consumed so far, [IO-23]).
    pub rng_position: u64,
    /// The in-flight deliveries, in delivery order.
    pub inflight: Vec<PendingResponse>,
}

impl LinkSnapshot {
    /// Returns the in-flight deliveries captured in the snapshot.
    #[must_use]
    pub fn inflight(&self) -> &[PendingResponse] {
        &self.inflight
    }
}
mod corruption;

use corruption::*;
