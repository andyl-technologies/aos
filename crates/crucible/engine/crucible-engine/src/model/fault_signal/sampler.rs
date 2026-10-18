//! Canonical integer inverse-CDF tables for stochastic wait sources.
//!
//! Tables bind a distribution's exact parameters to a complete partition of
//! the keyed `u64` quantile domain. Runtime sampling is one binary search and
//! never calls a platform floating-point or transcendental implementation.

use std::error::Error;
use std::fmt;

use super::*;

/// Inverse-CDF table codec version.
pub const INVERSE_CDF_CODEC_VERSION: u16 = 1;
/// Hard maximum points in one inverse-CDF table.
pub const HARD_INVERSE_CDF_POINTS: usize = 1_048_576;
const MAGIC: &[u8; 8] = b"CRCDFTB1";

/// Exact distribution contract bound into a normalized table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InverseCdfDistribution {
    /// Exponential wait with an exact positive event rate.
    Exponential {
        /// Events per virtual nanosecond under the authored scale convention.
        rate: ExactRatio,
    },
    /// Weibull wait with exact shape and integer nanosecond scale.
    Weibull {
        /// Positive exact shape.
        shape: ExactRatio,
        /// Positive duration scale.
        scale_nanos: u64,
    },
}

/// One inclusive quantile boundary and its rounded duration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InverseCdfPoint {
    /// Inclusive last keyed quantile selecting this point.
    pub quantile_upper: u64,
    /// Monotone rounded duration in virtual nanoseconds.
    pub duration_nanos: u64,
}

/// Validated content-addressed inverse-CDF table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InverseCdfTable {
    distribution: InverseCdfDistribution,
    points: Vec<InverseCdfPoint>,
    content: ContentHash,
}

impl InverseCdfTable {
    /// Validates and content-addresses a complete monotone table.
    ///
    /// # Errors
    ///
    /// Returns [`InverseCdfTableError`] for invalid parameters, an empty or
    /// oversized table, non-increasing quantile bounds, decreasing durations,
    /// or a final bound that does not cover `u64::MAX`.
    pub fn new(
        distribution: InverseCdfDistribution,
        points: Vec<InverseCdfPoint>,
    ) -> Result<Self, InverseCdfTableError> {
        validate_distribution(distribution)?;
        if points.is_empty() || points.len() > HARD_INVERSE_CDF_POINTS {
            return Err(InverseCdfTableError::PointLimit);
        }
        if points.windows(2).any(|pair| {
            pair[0].quantile_upper >= pair[1].quantile_upper
                || pair[0].duration_nanos > pair[1].duration_nanos
        }) || points.last().map(|point| point.quantile_upper) != Some(u64::MAX)
        {
            return Err(InverseCdfTableError::InvalidPoints);
        }
        let mut table = Self {
            distribution,
            points,
            content: ContentHash::default(),
        };
        table.content = ContentHash::from_bytes(&table.encode());
        Ok(table)
    }

    /// Returns the exact distribution and parameter contract.
    #[must_use]
    pub const fn distribution(&self) -> InverseCdfDistribution {
        self.distribution
    }

    /// Returns points in increasing quantile order.
    #[must_use]
    pub fn points(&self) -> &[InverseCdfPoint] {
        &self.points
    }

    /// Returns the canonical table content address.
    #[must_use]
    pub const fn content(&self) -> ContentHash {
        self.content
    }

    /// Samples a keyed quantile with logarithmic lookup time.
    #[must_use]
    pub fn sample(&self, quantile: u64) -> u64 {
        let index = self
            .points
            .partition_point(|point| point.quantile_upper < quantile);
        self.points[index].duration_nanos
    }

    /// Encodes the canonical portable big-endian representation.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(32 + self.points.len() * 16);
        output.extend_from_slice(MAGIC);
        output.extend_from_slice(&INVERSE_CDF_CODEC_VERSION.to_be_bytes());
        match self.distribution {
            InverseCdfDistribution::Exponential { rate } => {
                output.push(0);
                put_ratio(&mut output, rate);
            }
            InverseCdfDistribution::Weibull { shape, scale_nanos } => {
                output.push(1);
                put_ratio(&mut output, shape);
                output.extend_from_slice(&scale_nanos.to_be_bytes());
            }
        }
        output.extend_from_slice(
            &u32::try_from(self.points.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        for point in &self.points {
            output.extend_from_slice(&point.quantile_upper.to_be_bytes());
            output.extend_from_slice(&point.duration_nanos.to_be_bytes());
        }
        output
    }

    /// Decodes, revalidates, and proves canonical byte identity.
    ///
    /// # Errors
    ///
    /// Returns [`InverseCdfTableError`] for malformed, unsupported,
    /// noncanonical, oversized, or trailing input.
    pub fn decode(bytes: &[u8]) -> Result<Self, InverseCdfTableError> {
        let mut reader = TableReader::new(bytes);
        if reader.take(MAGIC.len())? != MAGIC {
            return Err(InverseCdfTableError::MalformedCodec);
        }
        let version = reader.u16()?;
        if version != INVERSE_CDF_CODEC_VERSION {
            return Err(InverseCdfTableError::VersionMismatch {
                expected: INVERSE_CDF_CODEC_VERSION,
                actual: version,
            });
        }
        let distribution = match reader.byte()? {
            0 => InverseCdfDistribution::Exponential {
                rate: reader.ratio()?,
            },
            1 => InverseCdfDistribution::Weibull {
                shape: reader.ratio()?,
                scale_nanos: reader.u64()?,
            },
            _ => return Err(InverseCdfTableError::MalformedCodec),
        };
        let count = usize::try_from(reader.u32()?).map_err(|_| InverseCdfTableError::PointLimit)?;
        if count == 0 || count > HARD_INVERSE_CDF_POINTS {
            return Err(InverseCdfTableError::PointLimit);
        }
        let mut points = Vec::with_capacity(count);
        for _ in 0..count {
            points.push(InverseCdfPoint {
                quantile_upper: reader.u64()?,
                duration_nanos: reader.u64()?,
            });
        }
        if !reader.remaining().is_empty() {
            return Err(InverseCdfTableError::TrailingBytes);
        }
        let table = Self::new(distribution, points)?;
        if table.encode() != bytes {
            return Err(InverseCdfTableError::NonCanonicalCodec);
        }
        Ok(table)
    }
}

fn validate_distribution(distribution: InverseCdfDistribution) -> Result<(), InverseCdfTableError> {
    let valid = match distribution {
        InverseCdfDistribution::Exponential { rate } => rate.numerator() > 0,
        InverseCdfDistribution::Weibull { shape, scale_nanos } => {
            shape.numerator() > 0 && scale_nanos > 0
        }
    };
    if valid {
        Ok(())
    } else {
        Err(InverseCdfTableError::InvalidDistribution)
    }
}

fn put_ratio(output: &mut Vec<u8>, ratio: ExactRatio) {
    output.extend_from_slice(&ratio.numerator().to_be_bytes());
    output.extend_from_slice(&ratio.denominator().to_be_bytes());
}

struct TableReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> TableReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.cursor..]
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], InverseCdfTableError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(InverseCdfTableError::MalformedCodec)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(InverseCdfTableError::MalformedCodec)?;
        self.cursor = end;
        Ok(value)
    }

    fn byte(&mut self) -> Result<u8, InverseCdfTableError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, InverseCdfTableError> {
        let bytes = self
            .take(2)?
            .try_into()
            .map_err(|_| InverseCdfTableError::MalformedCodec)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32, InverseCdfTableError> {
        let bytes = self
            .take(4)?
            .try_into()
            .map_err(|_| InverseCdfTableError::MalformedCodec)?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, InverseCdfTableError> {
        let bytes = self
            .take(8)?
            .try_into()
            .map_err(|_| InverseCdfTableError::MalformedCodec)?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn i64(&mut self) -> Result<i64, InverseCdfTableError> {
        let bytes = self
            .take(8)?
            .try_into()
            .map_err(|_| InverseCdfTableError::MalformedCodec)?;
        Ok(i64::from_be_bytes(bytes))
    }

    fn ratio(&mut self) -> Result<ExactRatio, InverseCdfTableError> {
        ExactRatio::new(self.i64()?, self.u64()?).map_err(InverseCdfTableError::Program)
    }
}

/// Canonical inverse-CDF table construction or codec failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InverseCdfTableError {
    /// Codec version differs from the implemented version.
    VersionMismatch {
        /// Implemented version.
        expected: u16,
        /// Encoded version.
        actual: u16,
    },
    /// Distribution parameters are not positive and finite in integer form.
    InvalidDistribution,
    /// Point count is empty or exceeds the hard ceiling.
    PointLimit,
    /// Quantiles or durations are not monotone or do not cover the full domain.
    InvalidPoints,
    /// Binary framing is truncated or has an unknown tag.
    MalformedCodec,
    /// Binary input contains trailing bytes.
    TrailingBytes,
    /// Decoded content does not reproduce the original bytes.
    NonCanonicalCodec,
    /// Nested exact-ratio validation failed.
    Program(SignalProgramError),
}

impl fmt::Display for InverseCdfTableError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid inverse-CDF table: {self:?}")
    }
}

impl Error for InverseCdfTableError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_codec_and_full_domain_lookup_are_exact() {
        let rate = match ExactRatio::new(1, 10) {
            Ok(value) => value,
            Err(error) => panic!("test rate must be valid: {error}"),
        };
        let table = match InverseCdfTable::new(
            InverseCdfDistribution::Exponential { rate },
            vec![
                InverseCdfPoint {
                    quantile_upper: 9,
                    duration_nanos: 1,
                },
                InverseCdfPoint {
                    quantile_upper: u64::MAX,
                    duration_nanos: 2,
                },
            ],
        ) {
            Ok(value) => value,
            Err(error) => panic!("test table must be valid: {error}"),
        };
        assert_eq!(table.sample(9), 1);
        assert_eq!(table.sample(10), 2);
        assert_eq!(InverseCdfTable::decode(&table.encode()), Ok(table));
    }
}
