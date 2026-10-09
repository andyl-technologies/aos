//! Exact numeric contracts and canonical decimal-string interchange.
//!
//! Resource inputs use unsigned 64-bit quantities. Aggregates use arbitrary-
//! precision integers and objective values use reduced rationals:
//!
//! ```json
//! {"numerator":"-7","denominator":"8"}
//! ```

use std::cmp::Ordering;
use std::fmt;
use std::ops::{Add, Mul, Neg, Sub};

use num_bigint::BigInt;
use num_integer::Integer as _;
use num_traits::{One, Signed, Zero};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::ModelError;

/// A nonnegative resource input represented as a canonical decimal string.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct Quantity(u64);

impl Quantity {
    /// Constructs a resource quantity without changing its unit.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the unsigned 64-bit quantity.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl From<u64> for Quantity {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl fmt::Display for Quantity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Serialize for Quantity {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for Quantity {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        if !canonical_unsigned(&text) {
            return Err(serde::de::Error::custom(
                "quantity must be canonical unsigned decimal",
            ));
        }

        text.parse::<u64>()
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

/// An arbitrary-precision integer aggregate with decimal-string interchange.
#[derive(Clone, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct Integer(BigInt);

impl Integer {
    /// Returns the exact integer value.
    pub fn value(&self) -> &BigInt {
        &self.0
    }

    /// Reports whether this aggregate is zero.
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

impl From<BigInt> for Integer {
    fn from(value: BigInt) -> Self {
        Self(value)
    }
}

impl From<u64> for Integer {
    fn from(value: u64) -> Self {
        Self(BigInt::from(value))
    }
}

impl fmt::Display for Integer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Serialize for Integer {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for Integer {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        parse_integer(&text)
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

/// A reduced exact rational with a strictly positive denominator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Rational {
    numerator: BigInt,
    denominator: BigInt,
}

impl Rational {
    /// Constructs a reduced rational from portable input-sized coefficients.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use dispatch_model::Rational;
    ///
    /// let preference = Rational::from_parts(3, 2)?;
    /// assert!(preference > Rational::one());
    /// # Ok::<(), dispatch_model::ModelError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error when the denominator is zero.
    pub fn from_parts(numerator: i64, denominator: u64) -> Result<Self, ModelError> {
        Self::new(BigInt::from(numerator), BigInt::from(denominator))
    }

    /// Constructs and reduces an exact rational.
    ///
    /// # Errors
    ///
    /// Returns an error when the denominator is zero or negative.
    pub fn new(numerator: BigInt, denominator: BigInt) -> Result<Self, ModelError> {
        if denominator <= BigInt::zero() {
            return Err(ModelError::new(
                "rational.denominator",
                "must be strictly positive",
            ));
        }

        Ok(Self::reduce(numerator, denominator))
    }

    /// Returns the additive identity.
    pub fn zero() -> Self {
        Self::from(0_u64)
    }

    /// Returns the multiplicative identity.
    pub fn one() -> Self {
        Self::from(1_u64)
    }

    /// Returns the reduced numerator.
    pub fn numerator(&self) -> &BigInt {
        &self.numerator
    }

    /// Returns the strictly positive reduced denominator.
    pub fn denominator(&self) -> &BigInt {
        &self.denominator
    }

    /// Reports whether the value is zero.
    pub fn is_zero(&self) -> bool {
        self.numerator.is_zero()
    }

    /// Reports whether the value is negative.
    pub fn is_negative(&self) -> bool {
        self.numerator.is_negative()
    }

    /// Returns the absolute value.
    pub fn abs(&self) -> Self {
        Self {
            numerator: self.numerator.abs(),
            denominator: self.denominator.clone(),
        }
    }

    /// Divides by a nonzero rational without approximation.
    ///
    /// # Errors
    ///
    /// Returns an error when the divisor is zero.
    pub fn checked_div(&self, divisor: &Self) -> Result<Self, ModelError> {
        if divisor.is_zero() {
            return Err(ModelError::new("rational.divisor", "must be nonzero"));
        }

        let numerator = &self.numerator * &divisor.denominator;
        let denominator = &self.denominator * &divisor.numerator;
        let sign = denominator.signum();
        Ok(Self::reduce(numerator * &sign, denominator * sign))
    }

    fn reduce(numerator: BigInt, denominator: BigInt) -> Self {
        let divisor = numerator.gcd(&denominator);
        Self {
            numerator: numerator / &divisor,
            denominator: denominator / divisor,
        }
    }
}

impl Default for Rational {
    fn default() -> Self {
        Self::zero()
    }
}

impl From<u64> for Rational {
    fn from(value: u64) -> Self {
        Self::from(BigInt::from(value))
    }
}

impl From<i64> for Rational {
    fn from(value: i64) -> Self {
        Self::from(BigInt::from(value))
    }
}

impl From<BigInt> for Rational {
    fn from(numerator: BigInt) -> Self {
        Self {
            numerator,
            denominator: BigInt::one(),
        }
    }
}

impl Ord for Rational {
    fn cmp(&self, other: &Self) -> Ordering {
        (&self.numerator * &other.denominator).cmp(&(&other.numerator * &self.denominator))
    }
}

impl PartialOrd for Rational {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Add<&Rational> for &Rational {
    type Output = Rational;

    fn add(self, other: &Rational) -> Rational {
        Rational::reduce(
            &self.numerator * &other.denominator + &other.numerator * &self.denominator,
            &self.denominator * &other.denominator,
        )
    }
}

impl Sub<&Rational> for &Rational {
    type Output = Rational;

    fn sub(self, other: &Rational) -> Rational {
        self + &(-other)
    }
}

impl Mul<&Rational> for &Rational {
    type Output = Rational;

    fn mul(self, other: &Rational) -> Rational {
        Rational::reduce(
            &self.numerator * &other.numerator,
            &self.denominator * &other.denominator,
        )
    }
}

impl Neg for &Rational {
    type Output = Rational;

    fn neg(self) -> Rational {
        Rational {
            numerator: -&self.numerator,
            denominator: self.denominator.clone(),
        }
    }
}

impl fmt::Display for Rational {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.numerator, self.denominator)
    }
}

impl Serialize for Rational {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        RationalWire {
            numerator: self.numerator.to_string(),
            denominator: self.denominator.to_string(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Rational {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = RationalWire::deserialize(deserializer)?;
        let numerator = parse_integer(&wire.numerator).map_err(serde::de::Error::custom)?;
        let denominator = parse_integer(&wire.denominator).map_err(serde::de::Error::custom)?;
        let value =
            Self::new(numerator.clone(), denominator.clone()).map_err(serde::de::Error::custom)?;
        if value.numerator != numerator || value.denominator != denominator {
            return Err(serde::de::Error::custom("rational must be reduced"));
        }

        Ok(value)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RationalWire {
    numerator: String,
    denominator: String,
}

fn canonical_unsigned(text: &str) -> bool {
    text == "0"
        || (!text.starts_with('0')
            && !text.is_empty()
            && text.bytes().all(|byte| byte.is_ascii_digit()))
}

fn parse_integer(text: &str) -> Result<BigInt, &'static str> {
    let unsigned = text.strip_prefix('-').unwrap_or(text);
    // Reject oversized interchange before allocating an arbitrary-precision value.
    if unsigned.len() > 19_729 {
        return Err("integer decimal representation exceeds the exact evaluation bound");
    }
    if !canonical_unsigned(unsigned) || text == "-0" {
        return Err("integer must be canonical decimal");
    }

    let value: BigInt = text.parse().map_err(|_| "invalid integer")?;
    if value.bits() > crate::MAX_EVALUATION_BITS {
        return Err("integer exceeds the exact evaluation bound");
    }

    Ok(value)
}
