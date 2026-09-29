//! Cuts file bytes at deterministic FastCDC boundaries.
//!
//! The gear table is derived from a chunk-profile seed. Each chunk starts a
//! fresh fingerprint; neither path names nor earlier files affect boundaries.

use alloc::vec::Vec;
use core::{fmt, ops::Range};

/// The minimum size of a chunk in the `cdc-1m` profile.
pub const CDC_1M_MIN: usize = 262_144;
/// The target size of a chunk in the `cdc-1m` profile.
pub const CDC_1M_TARGET: usize = 1_048_576;
/// The maximum size of a chunk in the `cdc-1m` profile.
pub const CDC_1M_MAX: usize = 4_194_304;
/// The number of data bytes influencing the masked Gear fingerprint.
pub const CDC_1M_WINDOW: u8 = 48;
/// The number of mask bits shifted across the target boundary.
pub const CDC_1M_NORMALIZATION: u8 = 2;

/// Invalid parameters in a chunk profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileError {
    /// Minimum, target, and maximum sizes are not positive and ordered.
    InvalidSizes,
    /// The effective Gear span cannot fit a 64-bit fingerprint.
    InvalidWindow,
    /// The derived strict or eager mask cannot fit the Gear span.
    InvalidNormalization,
}

impl fmt::Display for ProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSizes => f.write_str("chunk sizes must be positive and ordered"),
            Self::InvalidWindow => f.write_str("Gear span must be between 32 and 64 bytes"),
            Self::InvalidNormalization => {
                f.write_str("normalized masks must fit the Gear span")
            }
        }
    }
}

impl core::error::Error for ProfileError {}

/// A fixed chunking profile and its seeded Gear table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkProfile {
    minimum: usize,
    target: usize,
    maximum: usize,
    window: u8,
    normalization: u8,
    seed: [u8; 32],
    gear: [u64; 256],
    strict_mask: u64,
    eager_mask: u64,
}

impl ChunkProfile {
    /// Creates the `cdc-1m` profile with its registered seed.
    #[must_use]
    pub fn cdc_1m(seed: [u8; 32]) -> Self {
        // All fixed parameters are statically known to satisfy `new`.
        Self::from_validated(
            CDC_1M_MIN,
            CDC_1M_TARGET,
            CDC_1M_MAX,
            CDC_1M_WINDOW,
            CDC_1M_NORMALIZATION,
            seed,
        )
    }

    /// Builds a profile with a deterministic seeded Gear table.
    ///
    /// # Errors
    ///
    /// Returns an error when chunk sizes are unordered or zero, the effective
    /// Gear span is outside 32–64 bytes, or the masks cannot fit that span.
    pub fn new(
        minimum: usize,
        target: usize,
        maximum: usize,
        window: u8,
        normalization: u8,
        seed: [u8; 32],
    ) -> Result<Self, ProfileError> {
        if minimum == 0 || minimum > target || target > maximum {
            return Err(ProfileError::InvalidSizes);
        }
        if !(32..=64).contains(&window) {
            return Err(ProfileError::InvalidWindow);
        }

        let bits = target.ilog2();
        let strict = bits + u32::from(normalization);
        let eager = bits.checked_sub(u32::from(normalization));
        if strict < 2 || strict > 32 || eager.is_none_or(|bits| bits < 2) {
            return Err(ProfileError::InvalidNormalization);
        }

        Ok(Self::from_validated(
            minimum,
            target,
            maximum,
            window,
            normalization,
            seed,
        ))
    }

    fn from_validated(
        minimum: usize,
        target: usize,
        maximum: usize,
        window: u8,
        normalization: u8,
        seed: [u8; 32],
    ) -> Self {
        let bits = target.ilog2();
        let strict_bits = bits + u32::from(normalization);
        let eager_bits = bits - u32::from(normalization);

        Self {
            minimum,
            target,
            maximum,
            window,
            normalization,
            seed,
            gear: gear_table(seed),
            strict_mask: sparse_mask(window, strict_bits),
            eager_mask: sparse_mask(window, eager_bits),
        }
    }

    /// Returns the profile's minimum chunk size.
    #[must_use]
    pub const fn minimum(&self) -> usize {
        self.minimum
    }

    /// Returns the profile's target chunk size.
    #[must_use]
    pub const fn target(&self) -> usize {
        self.target
    }

    /// Returns the profile's maximum chunk size.
    #[must_use]
    pub const fn maximum(&self) -> usize {
        self.maximum
    }

    /// Returns the profile's effective Gear span.
    #[must_use]
    pub const fn window(&self) -> u8 {
        self.window
    }

    /// Returns the profile's mask normalization level.
    #[must_use]
    pub const fn normalization(&self) -> u8 {
        self.normalization
    }

    /// Returns the seed from which the Gear table was derived.
    #[must_use]
    pub const fn seed(&self) -> [u8; 32] {
        self.seed
    }

    /// Returns a reference to the seeded Gear table.
    #[must_use]
    pub const fn gear_table(&self) -> &[u64; 256] {
        &self.gear
    }

    /// Returns the length of the first chunk, ending at a cut or at EOF.
    ///
    /// An empty input has one zero-length chunk. For larger inputs this
    /// method inspects at most `maximum` bytes.
    #[must_use]
    pub fn first_boundary(&self, bytes: &[u8]) -> usize {
        self.first_cut(bytes).0
    }

    /// Returns whether the bytes form an honestly cut non-final chunk.
    ///
    /// A natural mask match at the final byte or the maximum-size forced cut
    /// is required. Reaching EOF alone cannot prove a non-final boundary.
    #[must_use]
    pub fn valid_nonfinal_chunk(&self, bytes: &[u8]) -> bool {
        let (boundary, was_cut) = self.first_cut(bytes);
        bytes.len() >= self.minimum && boundary == bytes.len() && was_cut
    }

    /// Iterates over the ordered chunk ranges of a file.
    ///
    /// The empty file yields exactly one `0..0` range. Files no larger than
    /// the minimum yield one range, suitable for an inline chunk reference.
    #[must_use]
    pub fn ranges<'a>(&'a self, bytes: &'a [u8]) -> ChunkRanges<'a> {
        ChunkRanges {
            profile: self,
            bytes,
            offset: 0,
            emitted_empty: false,
        }
    }

    /// Collects all ordered chunk ranges into a vector.
    #[must_use]
    pub fn boundaries(&self, bytes: &[u8]) -> Vec<Range<usize>> {
        self.ranges(bytes).collect()
    }

    fn first_cut(&self, bytes: &[u8]) -> (usize, bool) {
        let limit = bytes.len().min(self.maximum);
        if limit <= self.minimum {
            return (limit, limit == self.maximum);
        }

        let mut fingerprint = 0_u64;
        for (index, &byte) in bytes[self.minimum..limit].iter().enumerate() {
            fingerprint = fingerprint
                .wrapping_shl(1)
                .wrapping_add(self.gear[usize::from(byte)]);
            let position = self.minimum + index + 1;
            let mask = if position <= self.target {
                self.strict_mask
            } else {
                self.eager_mask
            };
            if fingerprint & mask == 0 {
                return (position, true);
            }
        }

        (limit, limit == self.maximum)
    }
}

/// An iterator over content-defined chunk ranges in file order.
pub struct ChunkRanges<'a> {
    profile: &'a ChunkProfile,
    bytes: &'a [u8],
    offset: usize,
    emitted_empty: bool,
}

impl Iterator for ChunkRanges<'_> {
    type Item = Range<usize>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.bytes.is_empty() {
            return (!core::mem::replace(&mut self.emitted_empty, true)).then_some(0..0);
        }
        if self.offset == self.bytes.len() {
            return None;
        }

        let start = self.offset;
        self.offset += self.profile.first_boundary(&self.bytes[start..]);
        Some(start..self.offset)
    }
}

/// Derives all 256 Gear words from the profile seed.
#[must_use]
pub fn gear_table(seed: [u8; 32]) -> [u64; 256] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"terrane-gear-v1\0");
    hasher.update(&seed);
    let mut reader = hasher.finalize_xof();

    let mut table = [0_u64; 256];
    for word in &mut table {
        let mut bytes = [0_u8; 8];
        reader.fill(&mut bytes);
        *word = u64::from_le_bytes(bytes);
    }
    table
}

fn sparse_mask(window: u8, bits: u32) -> u64 {
    let first = u32::from(window) - 32;
    let mut mask = 0_u64;
    for index in 0..bits {
        let position = first + (31 * index) / (bits - 1);
        mask |= 1_u64 << position;
    }
    mask
}

#[cfg(test)]
mod tests {
    use super::{
        CDC_1M_MAX, CDC_1M_MIN, ChunkProfile, ProfileError, gear_table, sparse_mask,
    };

    #[test]
    fn zero_seed_gear_table_matches_registered_values_and_digest() {
        let table = gear_table([0; 32]);
        assert_eq!(table[0], 0x15f2_3553_a70d_a356);
        assert_eq!(table[1], 0x9700_318b_430e_40f3);
        assert_eq!(table[7], 0xb0cd_9e1c_e544_864c);

        let bytes = table.into_iter().flat_map(u64::to_le_bytes).collect::<alloc::vec::Vec<_>>();
        assert_eq!(
            blake3::hash(&bytes).to_hex().as_str(),
            "22e8d10aa13d65d681fa4ff159d1151c11c90f652bc059d4418c3f463f49b14c",
        );
    }

    #[test]
    fn sparse_masks_use_exact_48_byte_span_and_level_two() {
        let strict = sparse_mask(48, 22);
        let eager = sparse_mask(48, 18);
        assert_eq!(strict.count_ones(), 22);
        assert_eq!(eager.count_ones(), 18);
        assert_eq!(strict.trailing_zeros(), 16);
        assert_eq!(eager.trailing_zeros(), 16);
        assert_eq!(63 - strict.leading_zeros(), 47);
        assert_eq!(63 - eager.leading_zeros(), 47);
    }

    #[test]
    fn empty_and_small_files_have_one_chunk() {
        let profile = ChunkProfile::cdc_1m([0; 32]);
        assert_eq!(profile.boundaries(&[]), alloc::vec![0..0]);
        assert_eq!(profile.boundaries(&[1; 10]), alloc::vec![0..10]);
        assert_eq!(profile.boundaries(&alloc::vec![1; CDC_1M_MIN]), alloc::vec![0..CDC_1M_MIN]);
        assert!(!profile.valid_nonfinal_chunk(&[1; 10]));
        assert!(!profile.valid_nonfinal_chunk(&alloc::vec![1; CDC_1M_MIN]));
    }

    #[test]
    fn max_is_forced_and_invalid_profiles_fail_closed() {
        let profile = ChunkProfile::cdc_1m([0; 32]);
        let bytes = alloc::vec![0; CDC_1M_MAX];
        assert!(profile.first_boundary(&bytes) <= CDC_1M_MAX);
        assert_eq!(
            ChunkProfile::new(0, 1, 2, 48, 2, [0; 32]),
            Err(ProfileError::InvalidSizes),
        );
        assert_eq!(
            ChunkProfile::new(1, 2, 3, 31, 0, [0; 32]),
            Err(ProfileError::InvalidWindow),
        );
    }

    #[test]
    fn boundary_is_independent_of_chunking_call_history() {
        let profile = ChunkProfile::cdc_1m([0; 32]);
        let bytes: alloc::vec::Vec<u8> = (0..(CDC_1M_MAX * 2))
            .map(|index| (index % 251) as u8)
            .collect();
        let first = profile.boundaries(&bytes);
        let second = profile.boundaries(&bytes);
        assert_eq!(first, second);
        assert_eq!(first.first().map(|range| range.start), Some(0));
        assert_eq!(first.last().map(|range| range.end), Some(bytes.len()));
        assert!(first.iter().all(|range| range.end - range.start <= CDC_1M_MAX));
    }
}
