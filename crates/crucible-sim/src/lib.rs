//! `crucible-sim` owns Crucible's deterministic core primitives.
//!
//! Spec index: RFC-0010 files 04, 08, 09.
//!
//! This L0 crate owns keyed decision streams, ordered collections,
//! deterministic selection, virtual-time arithmetic, and the content-addressing
//! primitives described by the indexed RFC-0010 files.
//! It intentionally has no QEMU, transport, scheduler-policy, or wall-clock
//! surface.
//!
//! Module map: [`contract_a`] owns the isolated single-VM Contract A driver; the
//! crate root owns [`StableHasher`], [`StableDigest`], [`DecisionRng`],
//! [`DecisionStream`], and the content-addressing primitives;
//! future modules will split ordered selection and virtual-time arithmetic.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod contract_a;

/// The keyed PRNG derivation used by [`DecisionStream`].
///
/// Every draw is a pure function of the scenario root, the stream identity and
/// the draw's own key, so the value never depends on how many other draws ran
/// before it or in which order hosts completed work ([DET-25], [SCHED-50]).
pub const DECISION_RNG_ALGORITHM: &str = "keyed-blake3-v2";

/// The superseded sequential derivation, recognized only to refuse it.
///
/// Draw values recorded under this algorithm are not reproducible by
/// [`DecisionStream`]; artifacts carrying them are refused rather than
/// re-valued.
pub const DECISION_RNG_LEGACY_ALGORITHM: &str = "splitmix64-v1";

/// The BLAKE3 key-derivation context that turns a scenario root into a world key.
pub const DECISION_RNG_WORLD_KEY_CONTEXT: &str = "crucible decision-rng keyed-blake3-v2 world-key";

/// The stable domain used for streams named without an explicit domain.
pub const DECISION_RNG_NAME_HASH_DOMAIN: &str = "crucible.decision-rng.name-hash.v1";

/// The stable domain used for node-scoped decision streams.
pub const DECISION_RNG_NODE_STREAM_DOMAIN: &str = "crucible.decision-rng.node-stream.v1";

/// The stable domain used for link-scoped decision streams.
pub const DECISION_RNG_LINK_STREAM_DOMAIN: &str = "crucible.decision-rng.link-stream.v1";

/// Label separating a stream-key derivation from every other keyed hash.
const STREAM_KEY_LABEL: &[u8] = b"stream";

/// Label for draws addressed by a per-stream ordinal.
const COUNTER_DRAW_LABEL: &[u8] = b"counter";

/// Label for draws addressed by an event identity and role index.
const EVENT_DRAW_LABEL: &[u8] = b"event";

/// A deterministic 256-bit digest produced by [`StableHasher`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct StableDigest {
    /// The digest bytes in canonical little-endian lane order.
    pub bytes: [u8; 32],
}

/// A small deterministic hasher for simulation-state fingerprints.
///
/// This hasher is deliberately not cryptographic. It exists to give test
/// doubles and deterministic model tests a stable, host-independent byte
/// accumulator before the production content-addressing implementation lands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StableHasher {
    lanes: [u64; 4],
    bytes_written: u64,
}

/// The single seeded source for intended nondeterministic choices.
///
/// The derivation is `keyed-blake3-v2`:
///
/// ```text
/// world_key        = BLAKE3.derive_key(DECISION_RNG_WORLD_KEY_CONTEXT, u64le(root))
/// stream_key       = BLAKE3.keyed_hash(world_key,  lp("stream")  || lp(domain) || lp(name))
/// counter draw n   = BLAKE3.keyed_hash(stream_key, lp("counter") || u64le(n))[0..8]
/// event draw (e,i) = BLAKE3.keyed_hash(stream_key, lp("event")   || lp(e) || u64le(i))[0..8]
/// lp(x)            = u64le(len(x)) || x;  draws are read little-endian
/// ```
///
/// A stream owned by one entity, whose draws that entity orders by its own
/// deterministic execution, addresses draws by ordinal. A stream shared by
/// several producers addresses each draw by an event identity that names its
/// producer, so no cross-producer commit order enters a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecisionRng {
    seed: u64,
    world_key: [u8; 32],
}

impl DecisionRng {
    /// Builds a decision RNG from the scenario root seed.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            seed,
            world_key: blake3::derive_key(DECISION_RNG_WORLD_KEY_CONTEXT, &seed.to_le_bytes()),
        }
    }

    /// Returns the scenario root seed.
    #[must_use]
    pub fn root_seed(&self) -> u64 {
        self.seed
    }

    /// Returns the 64-bit stream identifier for `entity_name` in the default domain.
    ///
    /// The identifier is the low eight bytes of the stream key, so it changes
    /// with the root and the name but is never consumed as a draw.
    #[must_use]
    pub fn stream_seed(&self, entity_name: &str) -> u64 {
        self.stream_seed_in_domain(DECISION_RNG_NAME_HASH_DOMAIN, entity_name)
    }

    /// Returns the 64-bit stream identifier for `entity_name` inside `stream_domain`.
    #[must_use]
    pub fn stream_seed_in_domain(&self, stream_domain: &str, entity_name: &str) -> u64 {
        low_u64(&self.stream_key(stream_domain, entity_name))
    }

    /// Forks an ordinal-addressed stream for `entity_name` in the default domain.
    #[must_use]
    pub fn fork(&self, entity_name: &str) -> DecisionStream {
        self.fork_in_domain(DECISION_RNG_NAME_HASH_DOMAIN, entity_name)
    }

    /// Forks an ordinal-addressed node-scoped stream for `node_name`.
    #[must_use]
    pub fn fork_for_node(&self, node_name: &str) -> DecisionStream {
        self.fork_in_domain(DECISION_RNG_NODE_STREAM_DOMAIN, node_name)
    }

    /// Forks an ordinal-addressed link-scoped stream for `link_name`.
    #[must_use]
    pub fn fork_for_link(&self, link_name: &str) -> DecisionStream {
        self.fork_in_domain(DECISION_RNG_LINK_STREAM_DOMAIN, link_name)
    }

    /// Forks an ordinal-addressed stream inside a fixed stream domain.
    #[must_use]
    pub fn fork_in_domain(&self, stream_domain: &str, entity_name: &str) -> DecisionStream {
        DecisionStream::counter(self.stream_key(stream_domain, entity_name))
    }

    /// Opens the draws of one event on a shared stream.
    ///
    /// `event` is the canonical encoding of an identity that is independent of
    /// execution order, such as a link direction and producer sequence. The
    /// returned stream yields the event's role-indexed draws `0, 1, 2, ...`.
    #[must_use]
    pub fn event_in_domain(
        &self,
        stream_domain: &str,
        entity_name: &str,
        event: &[u8],
    ) -> DecisionStream {
        DecisionStream::event(self.stream_key(stream_domain, entity_name), event)
    }

    fn stream_key(&self, stream_domain: &str, entity_name: &str) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(&self.world_key);
        write_length_prefixed(&mut hasher, STREAM_KEY_LABEL);
        write_length_prefixed(&mut hasher, stream_domain.as_bytes());
        write_length_prefixed(&mut hasher, entity_name.as_bytes());
        *hasher.finalize().as_bytes()
    }
}

/// A named deterministic stream forked from [`DecisionRng`].
///
/// [`DecisionStream::draws`] is the position of the next draw: the stream
/// ordinal for an ordinal-addressed stream, or the role index within one event.
/// Because each draw is addressed rather than chained, advancing is free and a
/// value never depends on draws taken by any other stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecisionStream {
    stream_key: [u8; 32],
    event: Option<Vec<u8>>,
    draws: u64,
}

impl DecisionStream {
    fn counter(stream_key: [u8; 32]) -> Self {
        Self {
            stream_key,
            event: None,
            draws: 0,
        }
    }

    fn event(stream_key: [u8; 32], event: &[u8]) -> Self {
        Self {
            stream_key,
            event: Some(event.to_vec()),
            draws: 0,
        }
    }

    /// Returns the 64-bit identifier of the stream this cursor draws from.
    #[must_use]
    pub fn seed(&self) -> u64 {
        low_u64(&self.stream_key)
    }

    /// Returns the number of values drawn from this stream.
    #[must_use]
    pub fn draws(&self) -> u64 {
        self.draws
    }

    /// Advances the stream by `draws` values without materializing them.
    ///
    /// Draws are addressed by position, so this is exactly equivalent to
    /// calling [`Self::next_u64`] `draws` times.
    pub fn advance_by(&mut self, draws: u64) {
        self.draws = self.draws.wrapping_add(draws);
    }

    /// Returns the draw at `position` without moving the cursor.
    #[must_use]
    pub fn draw_at(&self, position: u64) -> u64 {
        let mut hasher = blake3::Hasher::new_keyed(&self.stream_key);
        match &self.event {
            None => write_length_prefixed(&mut hasher, COUNTER_DRAW_LABEL),
            Some(event) => {
                write_length_prefixed(&mut hasher, EVENT_DRAW_LABEL);
                write_length_prefixed(&mut hasher, event);
            }
        }
        hasher.update(&position.to_le_bytes());
        low_u64(hasher.finalize().as_bytes())
    }

    /// Draws the next deterministic `u64`.
    pub fn next_u64(&mut self) -> u64 {
        let value = self.draw_at(self.draws);
        self.draws = self.draws.wrapping_add(1);
        value
    }
}

fn write_length_prefixed(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn low_u64(bytes: &[u8; 32]) -> u64 {
    let mut low = [0; 8];
    low.copy_from_slice(&bytes[..8]);
    u64::from_le_bytes(low)
}

impl Default for StableHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl StableHasher {
    /// Builds an empty stable hasher.
    #[must_use]
    pub fn new() -> Self {
        Self {
            lanes: [
                0x243f_6a88_85a3_08d3,
                0x1319_8a2e_0370_7344,
                0xa409_3822_299f_31d0,
                0x082e_fa98_ec4e_6c89,
            ],
            bytes_written: 0,
        }
    }

    /// Adds a domain-separation tag to the stream.
    pub fn write_tag(&mut self, tag: &str) {
        self.write_bytes(tag.as_bytes());
    }

    /// Adds one unsigned integer to the stream in little-endian order.
    pub fn write_u64(&mut self, value: u64) {
        self.mix_word(value);
        self.bytes_written = self.bytes_written.wrapping_add(8);
    }

    /// Adds one boolean value to the stream.
    pub fn write_bool(&mut self, value: bool) {
        self.write_u64(u64::from(value));
    }

    /// Adds a byte slice to the stream with its length.
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.write_u64(bytes.len() as u64);

        let (chunks, remainder) = bytes.as_chunks::<8>();
        for chunk in chunks {
            self.mix_word(u64::from_le_bytes(*chunk));
        }

        if !remainder.is_empty() {
            let mut word = [0; 8];
            for (index, byte) in remainder.iter().enumerate() {
                word[index] = *byte;
            }
            self.mix_word(u64::from_le_bytes(word));
        }

        self.bytes_written = self.bytes_written.wrapping_add(bytes.len() as u64);
    }

    /// Finishes the stream and returns its deterministic digest.
    #[must_use]
    pub fn finish(&self) -> StableDigest {
        let mut lanes = self.lanes;
        for (index, lane) in lanes.iter_mut().enumerate() {
            let salt = (index as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
            *lane = finalize_word(lane.wrapping_add(self.bytes_written).wrapping_add(salt));
        }

        let mut bytes = [0; 32];
        for (index, lane) in lanes.iter().enumerate() {
            bytes[index * 8..index * 8 + 8].copy_from_slice(&lane.to_le_bytes());
        }
        StableDigest { bytes }
    }

    fn mix_word(&mut self, word: u64) {
        for (index, lane) in self.lanes.iter_mut().enumerate() {
            let rotation = 13 + (index as u32 * 7);
            let salt = (index as u64).wrapping_mul(0xd6e8_feb8_6659_fd93);
            *lane ^= word.wrapping_add(salt);
            *lane = lane
                .rotate_left(rotation)
                .wrapping_mul(0x9e37_79b1_85eb_ca87);
            *lane ^= *lane >> 33;
        }
    }
}

fn finalize_word(mut word: u64) -> u64 {
    word ^= word >> 30;
    word = word.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    word ^= word >> 27;
    word = word.wrapping_mul(0x94d0_49bb_1331_11eb);
    word ^ (word >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_hasher_is_repeatable() {
        let mut first = StableHasher::new();
        first.write_tag("node");
        first.write_u64(42);

        let mut second = StableHasher::new();
        second.write_tag("node");
        second.write_u64(42);

        assert_eq!(first.finish(), second.finish());
    }

    #[test]
    fn stable_hasher_is_order_sensitive() {
        let mut first = StableHasher::new();
        first.write_u64(1);
        first.write_u64(2);

        let mut second = StableHasher::new();
        second.write_u64(2);
        second.write_u64(1);

        assert_ne!(first.finish(), second.finish());
    }

    #[test]
    fn stable_hasher_covers_chunk_remainder_and_bool_inputs() {
        let mut with_full_chunk = StableHasher::new();
        with_full_chunk.write_bytes(b"abcdefgh");
        with_full_chunk.write_bool(true);

        let mut with_remainder = StableHasher::new();
        with_remainder.write_bytes(b"abcdefghi");
        with_remainder.write_bool(true);

        let mut with_false = StableHasher::new();
        with_false.write_bytes(b"abcdefgh");
        with_false.write_bool(false);

        assert_ne!(with_full_chunk.finish(), with_remainder.finish());
        assert_ne!(with_full_chunk.finish(), with_false.finish());
    }

    #[test]
    fn decision_rng_stream_ids_change_with_root_name_and_domain() {
        let rng = DecisionRng::new(0x0010_c001);

        assert_eq!(rng.root_seed(), 0x0010_c001);
        assert_ne!(rng.stream_seed("node-a"), rng.stream_seed("node-b"));
        assert_ne!(
            rng.stream_seed("node-a"),
            DecisionRng::new(0x0010_c002).stream_seed("node-a")
        );
        assert_ne!(
            rng.stream_seed_in_domain(DECISION_RNG_NODE_STREAM_DOMAIN, "node-a"),
            rng.stream_seed_in_domain(DECISION_RNG_LINK_STREAM_DOMAIN, "node-a")
        );
        assert_eq!(rng.fork("node-a").seed(), rng.stream_seed("node-a"));
    }

    #[test]
    fn decision_stream_is_repeatable_and_counts_draws() {
        let mut first = DecisionRng::new(0x0010_c001).fork("fault/node-a");
        let mut second = DecisionRng::new(0x0010_c001).fork("fault/node-a");

        assert_eq!(first.next_u64(), second.next_u64());
        assert_eq!(first.next_u64(), second.next_u64());
        assert_eq!(first.draws(), 2);
        assert_eq!(second.draws(), 2);
    }

    #[test]
    fn decision_stream_draws_are_addressed_by_position() {
        let stream = DecisionRng::new(0x0010_c001).fork("fault/node-a");
        let mut sequential = stream.clone();

        let in_order = [
            sequential.next_u64(),
            sequential.next_u64(),
            sequential.next_u64(),
        ];
        let out_of_order = [stream.draw_at(2), stream.draw_at(0), stream.draw_at(1)];

        assert_eq!(
            in_order,
            [out_of_order[1], out_of_order[2], out_of_order[0]]
        );
    }

    #[test]
    fn event_draws_are_separate_from_counter_draws() {
        let rng = DecisionRng::new(0x0010_c001);
        let counter = rng.fork_for_link("a-b");
        let event = rng.event_in_domain(DECISION_RNG_LINK_STREAM_DOMAIN, "a-b", b"");

        assert_eq!(counter.seed(), event.seed());
        assert_ne!(counter.draw_at(0), event.draw_at(0));
    }

    #[test]
    fn decision_stream_constant_time_advance_matches_materialized_draws() {
        let mut advanced = DecisionRng::new(0x0010_c001).fork("fault/node-a");
        let mut materialized = advanced.clone();

        advanced.advance_by(10_000);
        for _ in 0..10_000 {
            let _ = materialized.next_u64();
        }

        assert_eq!(advanced, materialized);
        assert_eq!(advanced.next_u64(), materialized.next_u64());
    }
}
