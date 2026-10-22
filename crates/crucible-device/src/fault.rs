//! Deterministic network-effect transforms and the seeded per-device RNG.
//!
//! Signal-driven network adapters use these integer-only primitives to resolve
//! frame effects without host time or floating-point behavior.
//!
//! - The pure, integer-only **transforms** ([`Probability`],
//!   [`jitter_shift_ticks`], [`reorder_shift_ticks`],
//!   [`corrupt_payload`]) are functions of an injected draw value — no RNG,
//!   no floating point ([IO-24]). The network link
//!   ([`super::netlink::fault`]) re-exports these so disk, filesystem, and
//!   network share one implementation.
//! - The seeded **per-device RNG** ([`DeviceRng`]) supplies those draws in a
//!   fixed consumption order ([IO-21]). Its stream is keyed by domain and
//!   device name from the scenario root through the L0 `keyed-blake3-v2`
//!   derivation, so adding or renaming an unrelated device never perturbs
//!   another device's draws. A stream shared by several producers addresses
//!   each draw by an event identity ([`LinkFrameDrawKey`]) instead.
//!

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

/// The deterministic jitter shift drawn from an injected value.
///
/// Returns `draw % (window_ticks + 1)`, a value in `0..=window_ticks` ([IO-20]). A zero
/// window yields zero. Pure function of `(draw, window_ticks)`.
///
/// The maximal `window_ticks == u64::MAX` is the full-range identity: `window_ticks + 1`
/// would overflow, so the function returns `draw` verbatim — which is already in
/// `0..=u64::MAX`, satisfying the `0..=window_ticks` contract.
#[must_use]
pub fn jitter_shift_ticks(draw: u64, window_ticks: u64) -> u64 {
    match window_ticks.checked_add(1) {
        Some(modulus) => draw % modulus,
        // window_ticks == u64::MAX: the full range; the draw is already in 0..=window.
        None => draw,
    }
}

/// The deterministic reorder shift drawn from an injected value.
///
/// Returns `draw % (window_ticks + 1)`, a value in `0..=window_ticks` ([IO-20]). A zero
/// window yields zero. Pure function of `(draw, window_ticks)`. Identical math to
/// [`jitter_shift_ticks`] but kept distinct so the two faults consume independent
/// draws in a fixed order; the same `window_ticks == u64::MAX` full-range identity
/// applies (the draw is returned verbatim, already in `0..=window_ticks`).
#[must_use]
pub fn reorder_shift_ticks(draw: u64, window_ticks: u64) -> u64 {
    match window_ticks.checked_add(1) {
        Some(modulus) => draw % modulus,
        // window_ticks == u64::MAX: the full range; the draw is already in 0..=window.
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
/// [`crucible_sim::DecisionStream`], so the keyed `keyed-blake3-v2` derivation
/// has a **single source of truth** in L0 and cannot drift between a device's
/// recorded draws and an engine replay ([DET-25]).
///
/// A device owned by one node addresses its draws by a **draw cursor**
/// ([`DeviceRng::position`]): the ordinal its own deterministic request order
/// assigns. That cursor is the device's RNG state captured in a snapshot and
/// restored on resume, so the next draw resolves identically after a pause as
/// it would have without one ([IO-23], [EXEC-13]). A stream shared by several
/// producers instead opens one event at a time ([`DeviceRng::for_event`]), so a
/// draw never depends on how producers interleaved ([SCHED-50]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceRng {
    stream: crucible_sim::DecisionStream,
}

impl DeviceRng {
    /// Forks an ordinal-addressed device RNG from the engine's decision-RNG root.
    ///
    /// `root_seed` is the scenario's decision-RNG root
    /// (`Seed::decision_rng().root_seed()`); `domain` and `name` are the device
    /// stream's stable domain and the device name. An unrelated device never
    /// perturbs this device's draws.
    #[must_use]
    pub fn fork(root_seed: u64, domain: &str, name: &str) -> Self {
        Self {
            stream: crucible_sim::DecisionRng::new(root_seed).fork_in_domain(domain, name),
        }
    }

    /// Opens the role-indexed draws of one event on a shared stream.
    ///
    /// `event` is the canonical encoding of an order-independent identity, such
    /// as [`LinkFrameDrawKey::encode`]. The returned RNG's position counts the
    /// draws taken for this event only.
    #[must_use]
    pub fn for_event(root_seed: u64, domain: &str, name: &str, event: &[u8]) -> Self {
        Self {
            stream: crucible_sim::DecisionRng::new(root_seed).event_in_domain(domain, name, event),
        }
    }

    /// Restores a forked device RNG to a captured draw cursor ([IO-23]).
    ///
    /// Draws are addressed by position, so a restored stream's next draw is
    /// byte-identical to the uninterrupted run's. Restoring to position zero is
    /// identical to [`DeviceRng::fork`].
    #[must_use]
    pub fn restore(root_seed: u64, domain: &str, name: &str, position: u64) -> Self {
        let mut rng = Self::fork(root_seed, domain, name);
        rng.stream.advance_by(position);
        rng
    }

    /// Returns the identifier of the stream this RNG draws from.
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

/// The order-independent identity of one frame's draws on a shared link stream.
///
/// A logical link carries both directions on one stream. Each direction has
/// exactly one producer, whose own frame sequence numbers its emissions, so
/// `(direction, producer sequence)` names a frame without reference to how the
/// two directions' frames were admitted relative to each other ([SCHED-50]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LinkFrameDrawKey {
    /// `0` for endpoint A to endpoint B, `1` for endpoint B to endpoint A.
    pub direction: u8,
    /// The producer's own sequence number for the frame.
    pub producer_sequence: u64,
}

impl LinkFrameDrawKey {
    /// The fixed width of [`LinkFrameDrawKey::encode`].
    pub const ENCODED_LEN: usize = 9;

    /// Returns the canonical event encoding: `direction || u64le(sequence)`.
    #[must_use]
    pub fn encode(self) -> [u8; Self::ENCODED_LEN] {
        let mut bytes = [0; Self::ENCODED_LEN];
        bytes[0] = self.direction;
        bytes[1..].copy_from_slice(&self.producer_sequence.to_le_bytes());
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // Streams are keyed by domain and name; an unrelated device must never
        // perturb this device's draw sequence.
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
    fn link_frame_draws_depend_only_on_the_frame_identity() {
        let a_to_b = LinkFrameDrawKey {
            direction: 0,
            producer_sequence: 7,
        };
        let b_to_a = LinkFrameDrawKey {
            direction: 1,
            producer_sequence: 7,
        };

        let mut first = DeviceRng::for_event(TEST_ROOT, TEST_DOMAIN, "link", &a_to_b.encode());
        let _other = DeviceRng::for_event(TEST_ROOT, TEST_DOMAIN, "link", &b_to_a.encode());
        let mut again = DeviceRng::for_event(TEST_ROOT, TEST_DOMAIN, "link", &a_to_b.encode());
        let mut reverse = DeviceRng::for_event(TEST_ROOT, TEST_DOMAIN, "link", &b_to_a.encode());

        let first_draw = first.next_u64();
        assert_eq!(first_draw, again.next_u64());
        assert_ne!(first_draw, reverse.next_u64());
        assert_eq!(first.position(), 1);
        assert_eq!(a_to_b.encode(), [0, 7, 0, 0, 0, 0, 0, 0, 0]);
    }
}
