//! Allocation-free element types for fixed-size signal vectors.

use super::SignalValueType;

/// Closed allocation-free scalar types admitted as vector elements.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum SignalVectorElementType {
    /// Signed 64-bit integer.
    I64,
    /// Unsigned 64-bit integer.
    U64,
    /// Unsigned duration in virtual nanoseconds.
    DurationNanos,
    /// Unsigned rate per second.
    RatePerSecond,
    /// Probability in millionths from zero through one million.
    ProbabilityMillionths,
}

impl SignalVectorElementType {
    /// Returns the corresponding scalar signal value type.
    #[must_use]
    pub const fn value_type(self) -> SignalValueType {
        match self {
            Self::I64 => SignalValueType::I64,
            Self::U64 => SignalValueType::U64,
            Self::DurationNanos => SignalValueType::DurationNanos,
            Self::RatePerSecond => SignalValueType::RatePerSecond,
            Self::ProbabilityMillionths => SignalValueType::ProbabilityMillionths,
        }
    }

    pub(super) const fn material(self) -> &'static str {
        match self {
            Self::I64 => "i64",
            Self::U64 => "u64",
            Self::DurationNanos => "duration_nanos",
            Self::RatePerSecond => "rate_per_second",
            Self::ProbabilityMillionths => "probability_millionths",
        }
    }
}

impl TryFrom<SignalValueType> for SignalVectorElementType {
    type Error = SignalValueType;

    fn try_from(value: SignalValueType) -> Result<Self, Self::Error> {
        match value {
            SignalValueType::I64 => Ok(Self::I64),
            SignalValueType::U64 => Ok(Self::U64),
            SignalValueType::DurationNanos => Ok(Self::DurationNanos),
            SignalValueType::RatePerSecond => Ok(Self::RatePerSecond),
            SignalValueType::ProbabilityMillionths => Ok(Self::ProbabilityMillionths),
            other => Err(other),
        }
    }
}
