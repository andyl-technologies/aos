//! `crucible-sim` owns Crucible's deterministic core primitives.
//!
//! Spec index: RFC-0010 files 04, 08, 09.
//!
//! This L0 crate owns seeded decision streams, ordered collections,
//! deterministic selection, virtual-time arithmetic, and the content-addressing
//! seam described by the indexed RFC-0010 files.
//! The current content-addressing primitives are intentionally local to this
//! crate; [`FUTURE_RATCHET_INTEGRATION_SEAM`] marks the only candidate boundary
//! for any later RFC-0007 integration.
//! It intentionally has no QEMU, transport, scheduler-policy, or wall-clock
//! surface.
//!
//! Module map: [`contract_a`] owns the isolated single-VM Contract A driver; the
//! crate root owns [`StableHasher`], [`StableDigest`], [`DecisionRng`],
//! [`DecisionStream`], and the named content-addressing integration boundary;
//! future modules will split ordered selection and virtual-time arithmetic.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod contract_a;

const SPLITMIX64_GAMMA: u64 = 0x9e37_79b9_7f4a_7c15;

/// The fixed PRNG algorithm used by [`DecisionStream`].
pub const DECISION_RNG_ALGORITHM: &str = "splitmix64-v1";

/// The stable hash domain used for decision-stream name forking.
pub const DECISION_RNG_NAME_HASH_DOMAIN: &str = "crucible.decision-rng.name-hash.v1";

/// The stable domain used for node-scoped decision streams.
pub const DECISION_RNG_NODE_STREAM_DOMAIN: &str = "crucible.decision-rng.node-stream.v1";

/// The stable domain used for link-scoped decision streams.
pub const DECISION_RNG_LINK_STREAM_DOMAIN: &str = "crucible.decision-rng.link-stream.v1";

/// Marks the future RFC-0007 integration boundary for content-addressing code.
///
/// Crucible ships standalone today: the stable hashing primitives below are
/// owned here, and no Crucible crate may depend on `ratchet-*` or `aos-nix-*`.
/// A later ratchet merge must adapt behind this named seam instead of adding a
/// direct dependency to the current crate graph.
pub const FUTURE_RATCHET_INTEGRATION_SEAM: &str = "crucible-sim::content-addressing";

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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecisionRng {
    seed: u64,
}

impl DecisionRng {
    /// Builds a decision RNG from the scenario root seed.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self { seed }
    }

    /// Returns the scenario root seed.
    #[must_use]
    pub fn root_seed(&self) -> u64 {
        self.seed
    }

    /// Returns the fork seed for `entity_name`.
    ///
    /// The seed is computed as `root_seed XOR stable_name_hash(entity_name)`,
    /// so constructing unrelated streams never consumes from the root and never
    /// perturbs any existing stream.
    #[must_use]
    pub fn stream_seed(&self, entity_name: &str) -> u64 {
        self.seed ^ stable_name_hash(entity_name)
    }

    /// Returns the fork seed for `entity_name` inside `stream_domain`.
    ///
    /// The seed is computed as `root_seed XOR stable_domain_name_hash`, keeping
    /// node and link streams with the same entity name independent when callers
    /// use the fixed node/link domains.
    #[must_use]
    pub fn stream_seed_in_domain(&self, stream_domain: &str, entity_name: &str) -> u64 {
        self.seed ^ stable_domain_name_hash(stream_domain, entity_name)
    }

    /// Forks a deterministic decision stream for `entity_name`.
    #[must_use]
    pub fn fork(&self, entity_name: &str) -> DecisionStream {
        DecisionStream::from_seed(self.stream_seed(entity_name))
    }

    /// Forks a deterministic node-scoped decision stream for `node_name`.
    #[must_use]
    pub fn fork_for_node(&self, node_name: &str) -> DecisionStream {
        self.fork_in_domain(DECISION_RNG_NODE_STREAM_DOMAIN, node_name)
    }

    /// Forks a deterministic link-scoped decision stream for `link_name`.
    #[must_use]
    pub fn fork_for_link(&self, link_name: &str) -> DecisionStream {
        self.fork_in_domain(DECISION_RNG_LINK_STREAM_DOMAIN, link_name)
    }

    /// Forks a deterministic decision stream inside a fixed stream domain.
    #[must_use]
    pub fn fork_in_domain(&self, stream_domain: &str, entity_name: &str) -> DecisionStream {
        DecisionStream::from_seed(self.stream_seed_in_domain(stream_domain, entity_name))
    }
}

/// A named deterministic stream forked from [`DecisionRng`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecisionStream {
    seed: u64,
    state: u64,
    draws: u64,
}

impl DecisionStream {
    /// Builds a stream from a fixed stream seed.
    #[must_use]
    fn from_seed(seed: u64) -> Self {
        Self {
            seed,
            state: seed,
            draws: 0,
        }
    }

    /// Returns the seed used to initialize this stream.
    #[must_use]
    pub fn seed(&self) -> u64 {
        self.seed
    }

    /// Returns the number of values drawn from this stream.
    #[must_use]
    pub fn draws(&self) -> u64 {
        self.draws
    }

    /// Advances the stream by `draws` values without materializing them.
    ///
    /// This is equivalent to calling [`Self::next_u64`] `draws` times and is
    /// constant-time, including for checkpoint-supplied cursor positions.
    pub fn advance_by(&mut self, draws: u64) {
        self.state = self
            .state
            .wrapping_add(SPLITMIX64_GAMMA.wrapping_mul(draws));
        self.draws = self.draws.wrapping_add(draws);
    }

    /// Draws the next deterministic `u64`.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(SPLITMIX64_GAMMA);
        self.draws = self.draws.wrapping_add(1);
        splitmix64(self.state)
    }
}

/// Returns a stable cross-platform hash for a decision-stream name.
#[must_use]
pub fn stable_name_hash(entity_name: &str) -> u64 {
    let mut hasher = StableHasher::new();
    hasher.write_tag(DECISION_RNG_NAME_HASH_DOMAIN);
    hasher.write_bytes(entity_name.as_bytes());
    let digest = hasher.finish();
    let mut seed_bytes = [0; 8];
    seed_bytes.copy_from_slice(&digest.bytes[..8]);
    u64::from_le_bytes(seed_bytes)
}

/// Returns a stable cross-platform hash for a decision-stream domain and name.
#[must_use]
pub fn stable_domain_name_hash(stream_domain: &str, entity_name: &str) -> u64 {
    let mut hasher = StableHasher::new();
    hasher.write_tag(DECISION_RNG_NAME_HASH_DOMAIN);
    hasher.write_tag(stream_domain);
    hasher.write_bytes(entity_name.as_bytes());
    let digest = hasher.finish();
    let mut seed_bytes = [0; 8];
    seed_bytes.copy_from_slice(&digest.bytes[..8]);
    u64::from_le_bytes(seed_bytes)
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

        let mut chunks = bytes.chunks_exact(8);
        for chunk in &mut chunks {
            let mut word = [0; 8];
            word.copy_from_slice(chunk);
            self.mix_word(u64::from_le_bytes(word));
        }

        let remainder = chunks.remainder();
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

fn splitmix64(mut word: u64) -> u64 {
    word = (word ^ (word >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    word = (word ^ (word >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
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
    fn decision_rng_forks_stream_seed_by_name_hash() {
        let rng = DecisionRng::new(0x0010_c001);

        assert_eq!(rng.root_seed(), 0x0010_c001);
        assert_eq!(
            rng.stream_seed("node-a"),
            0x0010_c001 ^ stable_name_hash("node-a")
        );
        assert_ne!(rng.stream_seed("node-a"), rng.stream_seed("node-b"));
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
