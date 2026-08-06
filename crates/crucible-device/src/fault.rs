//! The shared I/O fault taxonomy and the seeded per-device RNG.
//!
//! RFC-0010 §15.6 unifies disk, filesystem, and network fault injection under a
//! single taxonomy: a fault perturbs a sub-node's *modeled* completion/response,
//! never the host I/O. This module owns that shared vocabulary so the block, 9p,
//! and network-link sub-nodes apply **the same** faults with the same activation
//! mechanism ([IO-25], [IO-26]):
//!
//! ```text
//!   fault       network link                block/9p request
//!   ───────     ────────────                ────────────────
//!   latency     shift delivery_vt later     shift response delivery_vt later
//!   jitter      shift delivery_vt (seeded)  shift response delivery_vt (seeded)
//!   loss        drop the frame              return an error-status response
//!   reorder     shift past a peer (seeded)  shift one response past another
//!   duplicate   emit a second frame         emit a second (duplicate) response
//!   corrupt     flip seeded payload bits    flip seeded bits in read data
//!   bandwidth   add serialization delay     add transfer delay ∝ count
//! ```
//!
//! # The two halves
//!
//! - The pure, integer-only **transforms** ([`Probability`],
//!   [`serialization_delay_ns`], [`jitter_shift_ns`], [`reorder_shift_ns`],
//!   [`corrupt_payload`]) are functions of an injected draw value — no RNG,
//!   no floating point ([IO-24]). The network link
//!   ([`super::netlink::fault`]) re-exports these so disk, filesystem, and
//!   network share one implementation.
//! - The seeded **per-device RNG** ([`DeviceRng`]) supplies those draws in a
//!   fixed consumption order ([IO-21]). It is forked by name-hash from the
//!   scenario seed (the fork itself is computed in the `crucible` engine via the
//!   determinism-contract name-hash; this crate only carries the resulting
//!   stream seed and the SplitMix64 draw sequence), so adding or renaming an
//!   unrelated device never perturbs another device's draws.
//!
//! # The block/9p completion fault model
//!
//! [`IoFaults`] is the uniform fault table for an exact-completion sub-node
//! (block or 9p). [`IoFaults::resolve`] applies the taxonomy to a modeled
//! `(delivery_icount, status, payload)` triple, drawing every probabilistic
//! choice from a [`DeviceRng`] in this fixed order: latency/bandwidth (no draw),
//! jitter (1 draw), reorder (1 draw), loss (1 draw), duplicate (1 draw), corrupt
//! (1 draw + one draw per flipped bit). The same seed and the same inputs yield a
//! byte-identical [`IoFaultOutcome`] ([IO-22]).

/// A Bernoulli probability expressed as an exact integer fraction.
///
/// The fault model uses no floating point ([IO-24]); a probability is the
/// rational `numerator / denominator`, and a draw `d` fires the decision when
/// `(d % denominator) < numerator`. A `numerator` of zero never fires; a
/// `numerator >= denominator` always fires.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Probability {
    /// The fraction numerator (favorable outcomes).
    pub numerator: u64,
    /// The fraction denominator (total outcomes); a zero denominator never fires.
    pub denominator: u64,
}

impl Probability {
    /// A probability that never fires (the absence of a probabilistic effect).
    pub const NEVER: Self = Self {
        numerator: 0,
        denominator: 1,
    };

    /// A probability that always fires.
    pub const ALWAYS: Self = Self {
        numerator: 1,
        denominator: 1,
    };

    /// Creates a probability from an exact integer fraction.
    ///
    /// A `denominator` of zero is treated as "never fires" so a malformed table
    /// cannot panic on the modulo.
    #[must_use]
    pub fn new(numerator: u64, denominator: u64) -> Self {
        Self {
            numerator,
            denominator,
        }
    }

    /// Returns whether the injected `draw` fires this probability.
    ///
    /// Pure function of `(self, draw)`: `(draw % denominator) < numerator`. A zero
    /// denominator never fires. No floating point is used ([IO-24]).
    #[must_use]
    pub fn fires(&self, draw: u64) -> bool {
        if self.denominator == 0 {
            return false;
        }
        (draw % self.denominator) < self.numerator
    }
}

impl Default for Probability {
    fn default() -> Self {
        Self::NEVER
    }
}

/// The deterministic serialization delay for a payload under a bandwidth limit.
///
/// Models `delay_ns = len_bytes * 1_000_000_000 / bandwidth_bytes_per_sec`,
/// computed entirely in integer arithmetic — **no floating point** ([IO-24]).
/// The multiplication is widened to `u128` so a large payload cannot overflow,
/// and the result saturates at `u64::MAX`. A `bandwidth_bytes_per_sec` of zero
/// means "unlimited" and yields no delay.
///
/// # Examples
///
/// ```no_run
/// use crucible_device::fault::serialization_delay_ns;
/// // 1500 bytes at 1 Gbps (125_000_000 B/s) = 12_000 ns.
/// assert_eq!(serialization_delay_ns(1500, 125_000_000), 12_000);
/// ```
#[must_use]
pub fn serialization_delay_ns(len_bytes: u64, bandwidth_bytes_per_sec: u64) -> u64 {
    if bandwidth_bytes_per_sec == 0 {
        return 0;
    }
    let nanos = u128::from(len_bytes) * 1_000_000_000_u128 / u128::from(bandwidth_bytes_per_sec);
    u64::try_from(nanos).unwrap_or(u64::MAX)
}

/// Computes serialization delay for a bit-per-second bandwidth cap.
///
/// This is the exact RFC-level form used by fault plans: `len_bytes * 8 * 1e9 /
/// bits_per_second`, widened and saturating so the result is host-independent.
#[must_use]
pub fn serialization_delay_bits_per_sec(len_bytes: u64, bits_per_second: u64) -> u64 {
    if bits_per_second == 0 {
        return 0;
    }
    let nanos = u128::from(len_bytes)
        .saturating_mul(8)
        .saturating_mul(1_000_000_000_u128)
        / u128::from(bits_per_second);
    u64::try_from(nanos).unwrap_or(u64::MAX)
}

/// The deterministic jitter shift drawn from an injected value.
///
/// Returns `draw % (window_ns + 1)`, a value in `0..=window_ns` ([IO-20]). A zero
/// window yields zero. Pure function of `(draw, window_ns)`.
///
/// The maximal `window_ns == u64::MAX` is the full-range identity: `window_ns + 1`
/// would overflow, so the function returns `draw` verbatim — which is already in
/// `0..=u64::MAX`, satisfying the `0..=window_ns` contract.
#[must_use]
pub fn jitter_shift_ns(draw: u64, window_ns: u64) -> u64 {
    match window_ns.checked_add(1) {
        Some(modulus) => draw % modulus,
        // window_ns == u64::MAX: the full range; the draw is already in 0..=window.
        None => draw,
    }
}

/// The deterministic reorder shift drawn from an injected value.
///
/// Returns `draw % (window_ns + 1)`, a value in `0..=window_ns` ([IO-20]). A zero
/// window yields zero. Pure function of `(draw, window_ns)`. Identical math to
/// [`jitter_shift_ns`] but kept distinct so the two faults consume independent
/// draws in a fixed order; the same `window_ns == u64::MAX` full-range identity
/// applies (the draw is returned verbatim, already in `0..=window_ns`).
#[must_use]
pub fn reorder_shift_ns(draw: u64, window_ns: u64) -> u64 {
    match window_ns.checked_add(1) {
        Some(modulus) => draw % modulus,
        // window_ns == u64::MAX: the full range; the draw is already in 0..=window.
        None => draw,
    }
}

/// Flips `bit_flips` bits in `payload` at positions derived from `draws`.
///
/// Each draw selects a bit position `draw % (payload_bits)`, and that bit is
/// toggled in place ([IO-20]). The same draws flip exactly the same bits, so the
/// corruption is reproducible. An empty payload or zero `bit_flips` leaves the
/// payload unchanged. Pure function of `(payload, draws, bit_flips)`.
///
/// `draws` MUST supply at least `bit_flips` values; only the first `bit_flips`
/// are consumed. If fewer are supplied, only that many bits are flipped (the
/// caller is responsible for supplying enough draws).
pub fn corrupt_payload(payload: &mut [u8], draws: &[u64], bit_flips: u32) {
    if payload.is_empty() {
        return;
    }
    let total_bits = (payload.len() as u64) * 8;
    let count = (bit_flips as usize).min(draws.len());
    for &draw in draws.iter().take(count) {
        let bit_index = draw % total_bits;
        let byte = (bit_index / 8) as usize;
        let bit = (bit_index % 8) as u8;
        payload[byte] ^= 1 << bit;
    }
}

/// A seeded per-device RNG: the source of every probabilistic device draw ([IO-21]).
///
/// `DeviceRng` is a thin newtype over the `crucible` engine's
/// [`crucible_sim::DecisionStream`], so the PRNG has a **single source of truth**
/// in L0: the SplitMix64 algorithm, the seed-fork formula, and the draw-cursor
/// convention are defined once and cannot drift between a device's recorded draws
/// and an engine replay. A device stream forked by name-hash from the scenario
/// seed ([DET-25]) therefore reproduces the same sequence an engine
/// [`crucible_sim::DecisionRng::fork_in_domain`] would. The RNG tracks a
/// monotonically increasing **draw cursor** ([`DeviceRng::position`]); that cursor
/// is the device's RNG state captured in a snapshot and restored on resume so the
/// next draw resolves identically after a pause as it would have without one
/// ([IO-23], [EXEC-13]).
///
/// Forking by name-hash (rather than by sequential draw from a root) is what
/// makes the stream order- and topology-stable: adding or renaming an unrelated
/// device never perturbs this device's sequence ([IO-21]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceRng {
    stream: crucible_sim::DecisionStream,
}

impl DeviceRng {
    /// Forks a device RNG by name-hash from the engine's decision-RNG root seed.
    ///
    /// Delegates to [`crucible_sim::DecisionRng::fork_in_domain`], the single L0
    /// source of the SplitMix64 stream and the `seed XOR stable_hash(domain,
    /// name)` fork formula ([DET-25]). `root_seed` is the scenario's
    /// decision-RNG root (`Seed::decision_rng().root_seed()`); `domain` and
    /// `name` are the device stream's stable domain and the device name. Because
    /// the fork is by name-hash, an unrelated device never perturbs this device's
    /// sequence.
    #[must_use]
    pub fn fork(root_seed: u64, domain: &str, name: &str) -> Self {
        Self {
            stream: crucible_sim::DecisionRng::new(root_seed).fork_in_domain(domain, name),
        }
    }

    /// Restores a forked device RNG to a captured draw cursor ([IO-23]).
    ///
    /// Re-forks the stream from `(root_seed, domain, name)` and replays
    /// `position` draws, so a restored stream's next draw is byte-identical to
    /// the uninterrupted run's. Restoring to position zero is identical to
    /// [`DeviceRng::fork`].
    #[must_use]
    pub fn restore(root_seed: u64, domain: &str, name: &str, position: u64) -> Self {
        let mut rng = Self::fork(root_seed, domain, name);
        let mut remaining = position;
        while remaining > 0 {
            let _ = rng.next_u64();
            remaining -= 1;
        }
        rng
    }

    /// Returns the forked stream seed this RNG draws from.
    #[must_use]
    pub fn seed(&self) -> u64 {
        self.stream.seed()
    }

    /// Returns the number of values drawn so far (the snapshot cursor, [IO-23]).
    #[must_use]
    pub fn position(&self) -> u64 {
        self.stream.draws()
    }

    /// Draws the next deterministic `u64`, advancing the cursor by one.
    pub fn next_u64(&mut self) -> u64 {
        self.stream.next_u64()
    }
}

/// The uniform completion-fault table for an exact-completion sub-node ([IO-25]).
///
/// Holds every fault parameter a block or 9p sub-node applies at RESOLVE, in the
/// same taxonomy as the network link's `LinkFaults`. All fields are integer
/// nanoseconds or exact-fraction probabilities; no floating point appears
/// anywhere ([IO-24]). A default table is fault-free: zero shifts, zero bandwidth
/// limit (unlimited), and never-firing probabilities, so the response delivers at
/// exactly its modeled completion icount with its modeled status and payload.
///
/// The fields are a flat data contract: the sub-node reads them and a snapshot
/// stores the *active set* verbatim, so the active I/O fault set is part of the
/// scheduler state captured in `MaterializedState` ([IO-26]).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct IoFaults {
    /// Extra fixed latency added to the response delivery, in virtual nanoseconds.
    pub added_latency_ns: u64,
    /// The upper bound (inclusive) of the seeded jitter window, in ns.
    pub jitter_window_ns: u64,
    /// The upper bound (inclusive) of the seeded reorder window, in ns.
    pub reorder_window_ns: u64,
    /// The serialization rate in bytes per second; zero means unlimited.
    ///
    /// Adds a transfer delay proportional to `payload_len` ([IO-25]).
    pub bandwidth_bytes_per_sec: u64,
    /// Additional RFC-level bandwidth caps in bits per virtual second.
    ///
    /// Each nonzero cap contributes its own exact integer serialization delay.
    pub bandwidth_bits_per_sec: Vec<u64>,
    /// The probability a response is failed (turned into an error-status response).
    pub loss: Probability,
    /// Additional failure probabilities evaluated after [`Self::loss`].
    ///
    /// Overlapping block/9p failures use the same any-fires rule as network loss.
    /// The bridge stores rates highest-first so the draw order is deterministic.
    pub additional_loss: Vec<Probability>,
    /// Whether a fired failure drops the response instead of returning an error.
    pub drop_on_loss: bool,
    /// The 9p errno encoded when a fired failure returns an `Rlerror`.
    ///
    /// Block devices ignore this and synthesize their normal block error status.
    pub failure_errno: Option<u32>,
    /// Errnos paired with [`Self::additional_loss`] for overlapping 9p failures.
    pub additional_failure_errno: Vec<u32>,
    /// The probability a response is duplicated (a second copy is emitted).
    pub duplicate: Probability,
    /// The fixed gap, in ns, between an original and its duplicate's delivery.
    pub duplicate_gap_ns: u64,
    /// The probability a response's read payload is corrupted (bits flipped).
    pub corrupt: Probability,
    /// The number of payload bit positions a corruption flips.
    pub corrupt_bit_flips: u32,
}

impl IoFaults {
    /// Returns a fault-free table (the default): no shifts, no probabilistic effects.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Returns the latency shift this table adds to a `payload_len`-byte response.
    ///
    /// The deterministic part of the fault model — added latency plus bandwidth
    /// serialization — that needs no RNG draw. Saturating throughout so a hostile
    /// length cannot overflow ([IO-24]).
    #[must_use]
    pub fn deterministic_latency_shift_ns(&self, payload_len: u64) -> u64 {
        let byte_rate_delay = serialization_delay_ns(payload_len, self.bandwidth_bytes_per_sec);
        let bit_rate_delay =
            self.bandwidth_bits_per_sec
                .iter()
                .copied()
                .fold(0_u64, |total, bits_per_second| {
                    total.saturating_add(serialization_delay_bits_per_sec(
                        payload_len,
                        bits_per_second,
                    ))
                });
        self.added_latency_ns
            .saturating_add(byte_rate_delay)
            .saturating_add(bit_rate_delay)
    }

    /// Resolves a modeled response through the active fault table ([IO-25]).
    ///
    /// Applies the uniform taxonomy as perturbations of the modeled completion,
    /// drawing every probabilistic choice from `rng` in a **fixed order** so the
    /// outcome is a pure function of `(self, inputs, rng position)` ([IO-22]):
    ///
    /// 1. latency + bandwidth shift `delivery_icount` later (no draw),
    /// 2. jitter shifts it later by a seeded amount (1 draw),
    /// 3. reorder shifts it later by a seeded amount (1 draw),
    /// 4. loss/failure turns the response into an error status or drop
    ///    (1 draw plus one per additional rate),
    /// 5. duplicate emits a second response `duplicate_gap_ns` later (1 draw),
    /// 6. corrupt flips seeded bits in the payload (1 draw + one per flipped bit).
    ///
    /// Latency/jitter/reorder/bandwidth shifts are converted from nanoseconds to
    /// icounts via `ns_to_icount` (the sub-node's `ceil_ns_to_icount`), so the
    /// device need not expose its clock here. Every shift and gap is saturating;
    /// no floating point is used ([IO-24]).
    ///
    /// Returns the perturbed primary response plus an optional duplicate. A
    /// failure either returns an error-status response or, for block drop mode,
    /// records the fired decision and suppresses completion emission.
    pub fn resolve(
        &self,
        primary_icount: u64,
        status: crate::request::ResponseStatus,
        payload: Vec<u8>,
        rng: &mut DeviceRng,
        ns_to_icount: impl Fn(u64) -> u64,
    ) -> IoFaultOutcome {
        let payload_len = payload.len() as u64;

        // --- (1) deterministic latency + bandwidth shift (no draw) ---
        let deterministic_ns = self.deterministic_latency_shift_ns(payload_len);

        // --- (2) jitter, (3) reorder: seeded shifts, fixed draw order ---
        let jitter_ns = jitter_shift_ns(rng.next_u64(), self.jitter_window_ns);
        let reorder_ns = reorder_shift_ns(rng.next_u64(), self.reorder_window_ns);

        let shift_ns = deterministic_ns
            .saturating_add(jitter_ns)
            .saturating_add(reorder_ns);
        let shift_icount = ns_to_icount(shift_ns);
        let delivery_icount = primary_icount.saturating_add(shift_icount);

        // --- (4) loss/failure: error-status response, or block drop mode ---
        let loss_draw = rng.next_u64();
        let mut additional_loss_draws = Vec::with_capacity(self.additional_loss.len());
        for _ in 0..self.additional_loss.len() {
            additional_loss_draws.push(rng.next_u64());
        }
        let failure_errno = self.failure_errno_for(loss_draw, &additional_loss_draws);
        let loss_fired = failure_errno.is_some();
        let dropped = loss_fired && self.drop_on_loss;
        let resolved_status = if loss_fired {
            crate::request::ResponseStatus::Error
        } else {
            status
        };

        // --- (5) duplicate: a second response a fixed gap later ---
        let duplicate_draw = rng.next_u64();
        let duplicate_fired = !dropped && self.duplicate.fires(duplicate_draw);

        // --- (6) corrupt: flip seeded payload bits ---
        let mut resolved_payload = payload;
        let corrupt_draw = rng.next_u64();
        let corrupt_fired = !dropped && !loss_fired && self.corrupt.fires(corrupt_draw);
        if corrupt_fired {
            let mut bit_draws = Vec::with_capacity(self.corrupt_bit_flips as usize);
            for _ in 0..self.corrupt_bit_flips {
                bit_draws.push(rng.next_u64());
            }
            corrupt_payload(&mut resolved_payload, &bit_draws, self.corrupt_bit_flips);
        }

        let primary = ResolvedResponse {
            delivery_icount,
            status: resolved_status,
            payload: resolved_payload.clone(),
        };

        let duplicate = if duplicate_fired {
            let dup_shift = ns_to_icount(shift_ns.saturating_add(self.duplicate_gap_ns));
            // Keep the duplicate strictly after the primary so the two never
            // collapse onto one icount and their order stays deterministic.
            let dup_icount = primary_icount
                .saturating_add(dup_shift)
                .max(delivery_icount.saturating_add(1));
            Some(ResolvedResponse {
                delivery_icount: dup_icount,
                status: resolved_status,
                payload: resolved_payload,
            })
        } else {
            None
        };

        IoFaultOutcome {
            primary,
            duplicate,
            loss_fired,
            dropped,
            failure_errno,
            duplicate_fired,
            corrupt_fired,
        }
    }

    fn failure_errno_for(&self, loss_draw: u64, additional_loss_draws: &[u64]) -> Option<u32> {
        if self.loss.fires(loss_draw) {
            return Some(self.failure_errno.unwrap_or(5));
        }
        self.additional_loss
            .iter()
            .zip(additional_loss_draws.iter().copied())
            .enumerate()
            .find_map(|(index, (probability, draw))| {
                if probability.fires(draw) {
                    Some(
                        self.additional_failure_errno
                            .get(index)
                            .copied()
                            .unwrap_or(5),
                    )
                } else {
                    None
                }
            })
    }
}

/// One resolved (post-fault) response: its delivery icount, status, and payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedResponse {
    /// The exact icount at which the response becomes visible (post-shift).
    pub delivery_icount: u64,
    /// The terminal status after the loss fault is applied.
    pub status: crate::request::ResponseStatus,
    /// The response payload after the corrupt fault is applied.
    pub payload: Vec<u8>,
}

/// The outcome of resolving one modeled response through [`IoFaults::resolve`].
///
/// Carries the perturbed primary response, an optional duplicate, and which
/// probabilistic effects fired (the per-effect outcomes the engine records as
/// `Decision`s). One modeled response resolves to one primary plus zero or one
/// duplicate. A block failure in `Drop` mode records a fired loss decision but
/// suppresses response emission; error-status block failures and 9p failures
/// return a device-specific error payload ([IO-25]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IoFaultOutcome {
    /// The perturbed primary response.
    pub primary: ResolvedResponse,
    /// The duplicate response, present exactly when the duplicate fault fired.
    pub duplicate: Option<ResolvedResponse>,
    /// Whether the loss fault fired (the response was turned into an error).
    pub loss_fired: bool,
    /// Whether the fired failure dropped the response entirely.
    pub dropped: bool,
    /// Selected errno for a fired 9p failure, when applicable.
    pub failure_errno: Option<u32>,
    /// Whether the duplicate fault fired.
    pub duplicate_fired: bool,
    /// Whether the corrupt fault fired (payload bits were flipped).
    pub corrupt_fired: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::ResponseStatus;

    /// A fixed engine decision-RNG root for the fault tests.
    const TEST_ROOT: u64 = 0x1234_5678_9abc_def0;
    /// A stand-in device stream domain for the fault tests.
    const TEST_DOMAIN: &str = "crucible.test.device-stream";

    /// Forks a device RNG for `name` from the fixed test root.
    fn test_rng(name: &str) -> DeviceRng {
        DeviceRng::fork(TEST_ROOT, TEST_DOMAIN, name)
    }

    #[test]
    fn probability_fires_on_exact_fraction_without_float() {
        let p = Probability::new(3, 10); // 30%
        assert!(p.fires(0));
        assert!(p.fires(2));
        assert!(!p.fires(3));
        assert!(!p.fires(9));
        assert!(p.fires(10)); // 10 % 10 = 0 < 3
        assert!(!Probability::NEVER.fires(0));
        assert!(Probability::ALWAYS.fires(123));
    }

    #[test]
    fn device_rng_is_deterministic_and_tracks_position() {
        let mut a = test_rng("disk");
        let mut b = test_rng("disk");
        assert_eq!(a.position(), 0);
        let first = a.next_u64();
        let second = a.next_u64();
        assert_eq!(a.position(), 2);
        assert_eq!(first, b.next_u64());
        assert_eq!(second, b.next_u64());
        assert_ne!(first, second);
    }

    #[test]
    fn device_rng_name_hash_fork_is_topology_stable() {
        // The engine forks `seed XOR stable_hash(domain, name)`; an unrelated
        // device must never perturb this device's draw sequence.
        let mut a1 = test_rng("disk");
        let mut a2 = test_rng("disk");
        let mut unrelated = test_rng("cache");
        let a1_first = a1.next_u64();
        let _ = unrelated.next_u64();
        let a2_first = a2.next_u64();
        assert_eq!(
            a1_first, a2_first,
            "device A draws unaffected by device B existence"
        );
    }

    #[test]
    fn device_rng_restore_resumes_identical_stream() {
        let mut live = test_rng("disk");
        let _ = live.next_u64();
        let _ = live.next_u64();
        let _ = live.next_u64();
        let position = live.position();
        let live_next = live.next_u64();

        let mut restored = DeviceRng::restore(TEST_ROOT, TEST_DOMAIN, "disk", position);
        assert_eq!(restored.position(), position);
        assert_eq!(
            restored.next_u64(),
            live_next,
            "restored stream resumes byte-identically ([IO-23])"
        );
    }

    #[test]
    fn fault_free_table_is_an_identity() {
        let mut rng = test_rng("disk");
        let outcome = IoFaults::none().resolve(
            100,
            ResponseStatus::Ok,
            vec![1, 2, 3],
            &mut rng,
            identity_icount,
        );
        assert_eq!(outcome.primary.delivery_icount, 100);
        assert_eq!(outcome.primary.status, ResponseStatus::Ok);
        assert_eq!(outcome.primary.payload, vec![1, 2, 3]);
        assert!(outcome.duplicate.is_none());
        assert!(!outcome.loss_fired);
    }

    #[test]
    fn each_fault_kind_perturbs_the_modeled_response() {
        // latency
        let latency = IoFaults {
            added_latency_ns: 50,
            ..IoFaults::none()
        };
        assert_eq!(
            resolve_primary(&latency, 10, ResponseStatus::Ok, vec![0; 2]).delivery_icount,
            60
        );

        // bandwidth (transfer delay proportional to count)
        let bandwidth = IoFaults {
            bandwidth_bytes_per_sec: 1_000_000_000, // 1 ns/byte
            ..IoFaults::none()
        };
        assert_eq!(
            resolve_primary(&bandwidth, 0, ResponseStatus::Ok, vec![0; 8]).delivery_icount,
            8
        );

        // jitter (always shifts within window)
        let jitter = IoFaults {
            jitter_window_ns: 16,
            ..IoFaults::none()
        };
        assert!(resolve_primary(&jitter, 0, ResponseStatus::Ok, vec![0]).delivery_icount <= 16);

        // reorder
        let reorder = IoFaults {
            reorder_window_ns: 32,
            ..IoFaults::none()
        };
        assert!(resolve_primary(&reorder, 0, ResponseStatus::Ok, vec![0]).delivery_icount <= 32);

        // loss -> error status
        let loss = IoFaults {
            loss: Probability::ALWAYS,
            ..IoFaults::none()
        };
        assert_eq!(
            resolve_primary(&loss, 0, ResponseStatus::Ok, vec![0]).status,
            ResponseStatus::Error
        );

        // duplicate -> a second response strictly later
        let dup = IoFaults {
            duplicate: Probability::ALWAYS,
            duplicate_gap_ns: 5,
            ..IoFaults::none()
        };
        let mut rng = test_rng("dup");
        let outcome = dup.resolve(0, ResponseStatus::Ok, vec![0], &mut rng, identity_icount);
        let duplicate = match outcome.duplicate {
            Some(duplicate) => duplicate,
            None => panic!("duplicate fault must emit a second response"),
        };
        assert!(duplicate.delivery_icount > outcome.primary.delivery_icount);

        // corrupt -> flipped read payload bits
        let corrupt = IoFaults {
            corrupt: Probability::ALWAYS,
            corrupt_bit_flips: 3,
            ..IoFaults::none()
        };
        let mut rng = test_rng("corrupt");
        let outcome = corrupt.resolve(
            0,
            ResponseStatus::Ok,
            vec![0u8; 8],
            &mut rng,
            identity_icount,
        );
        assert!(outcome.corrupt_fired);
        assert_ne!(outcome.primary.payload, vec![0u8; 8]);
    }

    #[test]
    fn resolve_is_byte_identical_for_equal_seeds() {
        let faults = IoFaults {
            jitter_window_ns: 100,
            reorder_window_ns: 200,
            loss: Probability::new(1, 4),
            duplicate: Probability::new(1, 3),
            duplicate_gap_ns: 7,
            corrupt: Probability::new(1, 2),
            corrupt_bit_flips: 2,
            ..IoFaults::none()
        };
        let mut rng_a = test_rng("disk");
        let mut rng_b = test_rng("disk");
        let a = faults.resolve(
            5,
            ResponseStatus::Ok,
            vec![9; 4],
            &mut rng_a,
            identity_icount,
        );
        let b = faults.resolve(
            5,
            ResponseStatus::Ok,
            vec![9; 4],
            &mut rng_b,
            identity_icount,
        );
        assert_eq!(a, b);
        assert_eq!(rng_a.position(), rng_b.position());
    }

    fn identity_icount(ns: u64) -> u64 {
        ns
    }

    fn resolve_primary(
        faults: &IoFaults,
        primary_icount: u64,
        status: ResponseStatus,
        payload: Vec<u8>,
    ) -> ResolvedResponse {
        let mut rng = test_rng("disk");
        faults
            .resolve(primary_icount, status, payload, &mut rng, identity_icount)
            .primary
    }
}
