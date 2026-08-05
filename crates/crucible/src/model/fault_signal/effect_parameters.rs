//! Validated scalar and aggregate values shared by typed effect schemas.
//!
//! Constructors enforce the wire-level constraints once so effect variants do
//! not repeatedly reinterpret raw integers or strings. None of these values is
//! an extension map: every consuming effect still names each field explicitly.

use std::num::{NonZeroU32, NonZeroU64};

use super::{FaultAdapter, FaultContractError, FaultObjectId, FaultOperation};

/// The maximum accepted encoded payload size for one effect.
pub const HARD_EFFECT_PAYLOAD_BYTES: usize = 16_777_216;

/// A probability represented as integer millionths in the inclusive range
/// `0..=1_000_000`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProbabilityMillionths(u32);

impl ProbabilityMillionths {
    /// Builds a bounded probability.
    ///
    /// # Errors
    ///
    /// Returns [`FaultContractError::ProbabilityOutOfRange`] when `value`
    /// exceeds one million.
    pub const fn new(value: u32) -> Result<Self, FaultContractError> {
        if value > 1_000_000 {
            return Err(FaultContractError::ProbabilityOutOfRange { value });
        }
        Ok(Self(value))
    }

    /// Returns the probability in integer millionths.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// A positive count whose semantic hard ceiling is checked at construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BoundedCount {
    value: NonZeroU32,
    limit: CountLimit,
}

/// An implementation-owned semantic ceiling for a positive count field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CountLimit {
    /// Network lanes or node vCPUs: 4,096.
    LanesOrVcpus,
    /// Per-operation duplicates or instruction replay: 256.
    DuplicatesOrInstructionReplay,
    /// Network or storage queue entries: 1,048,576.
    QueueEntries,
    /// Connection, custody, or interrupt-storm entries: 4,194,304.
    LargeStateEntries,
    /// Architecture register bits: 65,536.
    RegisterBits,
}

impl CountLimit {
    /// Returns the fixed compiled hard ceiling.
    #[must_use]
    pub const fn hard(self) -> u32 {
        match self {
            Self::LanesOrVcpus => 4_096,
            Self::DuplicatesOrInstructionReplay => 256,
            Self::QueueEntries => 1_048_576,
            Self::LargeStateEntries => 4_194_304,
            Self::RegisterBits => 65_536,
        }
    }

    const fn field(self) -> &'static str {
        match self {
            Self::LanesOrVcpus => "lanes_or_vcpus",
            Self::DuplicatesOrInstructionReplay => "duplicates_or_instruction_replay",
            Self::QueueEntries => "queue_entries",
            Self::LargeStateEntries => "large_state_entries",
            Self::RegisterBits => "register_bits",
        }
    }
}

impl BoundedCount {
    /// Builds a positive bounded count.
    ///
    /// # Errors
    ///
    /// Returns [`FaultContractError::ZeroValue`] for zero or
    /// [`FaultContractError::ResourceLimitExceeded`] above the selected fixed
    /// [`CountLimit`] ceiling.
    pub fn new(limit: CountLimit, value: u32) -> Result<Self, FaultContractError> {
        let field = limit.field();
        let value = NonZeroU32::new(value).ok_or(FaultContractError::ZeroValue { field })?;
        let hard = limit.hard();
        if value.get() > hard {
            return Err(FaultContractError::ResourceLimitExceeded {
                field,
                requested: u64::from(value.get()),
                hard: u64::from(hard),
            });
        }
        Ok(Self { value, limit })
    }

    /// Returns the validated count.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.value.get()
    }

    /// Returns the compiled semantic ceiling used by this value.
    #[must_use]
    pub const fn hard(self) -> u32 {
        self.limit.hard()
    }
}

/// A positive quantity represented by `u64`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PositiveU64(NonZeroU64);

impl PositiveU64 {
    /// Builds a positive quantity.
    ///
    /// # Errors
    ///
    /// Returns [`FaultContractError::ZeroValue`] when `value` is zero.
    pub fn new(field: &'static str, value: u64) -> Result<Self, FaultContractError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or(FaultContractError::ZeroValue { field })
    }

    /// Returns the positive quantity.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// A validated half-open byte range `[start, start + length)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ByteRange {
    start: u64,
    length: NonZeroU64,
}

impl ByteRange {
    /// Builds a non-empty byte range whose exclusive end fits in `u64`.
    ///
    /// # Errors
    ///
    /// Returns [`FaultContractError::InvalidByteRange`] for a zero length or an
    /// overflowing exclusive end.
    pub fn new(start: u64, length: u64) -> Result<Self, FaultContractError> {
        let length = NonZeroU64::new(length)
            .ok_or(FaultContractError::InvalidByteRange { start, length })?;
        if start.checked_add(length.get()).is_none() {
            return Err(FaultContractError::InvalidByteRange {
                start,
                length: length.get(),
            });
        }
        Ok(Self { start, length })
    }

    /// Returns the first selected byte.
    #[must_use]
    pub const fn start(self) -> u64 {
        self.start
    }

    /// Returns the positive selected byte count.
    #[must_use]
    pub const fn length(self) -> u64 {
        self.length.get()
    }

    /// Returns the exclusive range end.
    #[must_use]
    pub fn end(self) -> u64 {
        self.start + self.length.get()
    }
}

/// Lowercase even-length hexadecimal bytes with an explicit size ceiling.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HexBytes(String);

impl HexBytes {
    /// Validates canonical hexadecimal text and its decoded byte limit.
    ///
    /// # Errors
    ///
    /// Returns [`FaultContractError::InvalidHexBytes`] for upper-case,
    /// non-hexadecimal, odd-length, or over-limit input.
    pub fn parse(value: impl Into<String>, limit_bytes: usize) -> Result<Self, FaultContractError> {
        let value = value.into();
        let decoded_bytes = value.len() / 2;
        if value.len() % 2 != 0
            || decoded_bytes > limit_bytes
            || decoded_bytes > HARD_EFFECT_PAYLOAD_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(FaultContractError::InvalidHexBytes {
                encoded_bytes: value.len(),
                limit_bytes: limit_bytes.min(HARD_EFFECT_PAYLOAD_BYTES),
            });
        }
        Ok(Self(value))
    }

    /// Returns the canonical hexadecimal text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the decoded byte count without allocating decoded bytes.
    #[must_use]
    pub const fn decoded_len(&self) -> usize {
        self.0.len() / 2
    }
}

/// A non-empty canonical set of operations used by an effect filter.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OperationSet(Vec<FaultOperation>);

impl OperationSet {
    /// Sorts, deduplicates, and validates an operation set.
    ///
    /// # Errors
    ///
    /// Returns [`FaultContractError::EmptyCollection`] when `operations` is
    /// empty or [`FaultContractError::MixedAdapters`] when it spans adapters.
    pub fn new(mut operations: Vec<FaultOperation>) -> Result<Self, FaultContractError> {
        operations.sort();
        operations.dedup();
        let Some(first) = operations.first() else {
            return Err(FaultContractError::EmptyCollection {
                field: "operations",
            });
        };
        let adapter = first.adapter();
        if operations
            .iter()
            .any(|operation| operation.adapter() != adapter)
        {
            return Err(FaultContractError::MixedAdapters {
                field: "operations",
            });
        }
        Ok(Self(operations))
    }

    /// Returns operations in canonical enum order.
    #[must_use]
    pub fn as_slice(&self) -> &[FaultOperation] {
        &self.0
    }

    /// Returns the single adapter shared by every operation.
    #[must_use]
    pub fn adapter(&self) -> FaultAdapter {
        self.0[0].adapter()
    }

    /// Returns whether the canonical set contains `operation`.
    #[must_use]
    pub fn contains(&self, operation: FaultOperation) -> bool {
        self.0.binary_search(&operation).is_ok()
    }
}

/// A non-empty canonical set of object identities.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ObjectIdSet(Vec<FaultObjectId>);

impl ObjectIdSet {
    /// Sorts, deduplicates, and validates an identity set.
    ///
    /// # Errors
    ///
    /// Returns [`FaultContractError::EmptyCollection`] when `ids` is empty.
    pub fn new(mut ids: Vec<FaultObjectId>) -> Result<Self, FaultContractError> {
        ids.sort();
        ids.dedup();
        if ids.is_empty() {
            return Err(FaultContractError::EmptyCollection { field: "ids" });
        }
        Ok(Self(ids))
    }

    /// Returns identities in canonical order.
    #[must_use]
    pub fn as_slice(&self) -> &[FaultObjectId] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probabilities_and_ranges_fail_closed() {
        assert_eq!(
            ProbabilityMillionths::new(1_000_001),
            Err(FaultContractError::ProbabilityOutOfRange { value: 1_000_001 })
        );
        assert_eq!(
            ByteRange::new(u64::MAX, 1),
            Err(FaultContractError::InvalidByteRange {
                start: u64::MAX,
                length: 1,
            })
        );
    }

    #[test]
    fn hex_bytes_require_canonical_bounded_text() {
        assert!(HexBytes::parse("00ff", 2).is_ok());
        assert!(HexBytes::parse("00FF", 2).is_err());
        assert!(HexBytes::parse("0", 2).is_err());
        assert!(HexBytes::parse("000000", 2).is_err());
    }

    #[test]
    fn operation_sets_reject_mixed_adapters() {
        assert_eq!(
            OperationSet::new(vec![
                FaultOperation::NetworkTransmit,
                FaultOperation::StorageRead,
            ]),
            Err(FaultContractError::MixedAdapters {
                field: "operations",
            })
        );
    }

    #[test]
    fn count_ceiling_is_implementation_owned() {
        assert!(BoundedCount::new(CountLimit::DuplicatesOrInstructionReplay, 256).is_ok());
        assert_eq!(
            BoundedCount::new(CountLimit::DuplicatesOrInstructionReplay, 257),
            Err(FaultContractError::ResourceLimitExceeded {
                field: "duplicates_or_instruction_replay",
                requested: 257,
                hard: 256,
            })
        );
    }
}
