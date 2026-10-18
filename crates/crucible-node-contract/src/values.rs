//! Bounded CNP/1 identifiers and canonical decimal-string integers.
//!
//! ```json
//! { "id": "machine/0", "time_ps": "50", "offset_ps": "-10" }
//! ```

use std::{fmt, str::FromStr};

use base64::Engine;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{ContractError, Validate, invalid};

/// Limits each portable array independently of frame and admission ceilings.
pub const MAX_ARRAY_ELEMENTS: usize = 65_536;

/// Identifies a semantic node, owner, operation, or other named contract object.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
#[serde(transparent)]
pub struct Id(String);

impl Id {
    /// Constructs a bounded ASCII identifier.
    ///
    /// # Errors
    /// Rejects empty identifiers, lengths over 128 bytes, and characters outside
    /// `[A-Za-z0-9][A-Za-z0-9._:/-]*`.
    pub fn new(value: impl Into<String>) -> Result<Self, ContractError> {
        Self::try_from_owned(value.into()).map_err(|(_, error)| error)
    }

    /// Constructs an identifier while preserving invalid owned input on refusal.
    ///
    /// The original String and its spare capacity are returned unchanged. This
    /// lets an enclosing decoder retain its current child when validation fails.
    ///
    /// # Errors
    /// Returns the original backing and validation error for the same invalid
    /// identifiers rejected by [`Self::new`].
    pub fn try_from_owned(value: String) -> Result<Self, (String, ContractError)> {
        let mut bytes = value.bytes();
        if value.len() > 128
            || !bytes
                .next()
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
            || !bytes.all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
        {
            return Err((
                value,
                invalid("id", "expected 1–128 bounded ASCII identifier bytes"),
            ));
        }
        Ok(Self(value))
    }

    /// Returns the allocated byte capacity of the owned identifier string.
    ///
    /// The capacity includes unused storage. It does not change the identifier's
    /// content, validation or wire representation.
    pub fn allocated_capacity(&self) -> usize {
        self.0.capacity()
    }

    /// Returns the validated ASCII identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for Id {
    type Err = ContractError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl<'de> Deserialize<'de> for Id {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

impl Validate for Id {
    fn validate(&self) -> Result<(), ContractError> {
        Ok(())
    }
}

impl Validate for Vec<Id> {
    fn validate(&self) -> Result<(), ContractError> {
        validate_ids(self, "id_set")
    }
}

/// Identifies a logical simulation node.
pub type NodeId = Id;
/// Identifies an indivisible execution or capture owner.
pub type OwnerId = Id;
/// Identifies one live realization of an owner.
pub type IncarnationId = Id;
/// Identifies one accepted operation.
pub type OperationId = Id;
/// Represents a strictly sorted, duplicate-free set of identifiers.
pub type IdSet = Vec<Id>;
/// Represents a bounded numeric protocol or schema version.
pub type Version = u16;

/// Deserializes a bounded JSON integer regardless of its numeric token notation.
///
/// Portable version fields use this function through `serde(deserialize_with)`.
/// Integral JSON forms such as `1`, `1.0`, and `1e0` all denote version one.
/// The selected schema separately determines whether zero is permitted.
///
/// # Errors
/// Rejects nonnumeric values, fractions, nonfinite numbers, negative integers,
/// and integers exceeding `u16::MAX`. Floating-point conversion uses the same
/// IEEE-754 and ECMAScript number semantics as CNP/1 canonicalization.
pub fn deserialize_version<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Version, D::Error> {
    let number = serde_json::Number::deserialize(deserializer)?;
    let invalid = || serde::de::Error::custom("expected a JSON integer from 0 through 65535");
    if let Some(value) = number.as_u64() {
        return Version::try_from(value).map_err(|_| invalid());
    }

    // JCS normalizes integral floating-point tokens to their decimal integer
    // representation. Parsing that representation checks both integrality and
    // range without truncating, saturating, or casting floating-point values.
    let value = number
        .as_f64()
        .filter(|value| value.is_finite())
        .ok_or_else(invalid)?;
    let mut buffer = ryu_js::Buffer::new();
    buffer
        .format(value)
        .parse::<Version>()
        .map_err(|_| invalid())
}

/// Carries identity-bearing or negotiated extension values.
pub type Extensions = std::collections::BTreeMap<String, serde_json::Value>;

macro_rules! decimal_integer {
    ($name:ident, $native:ty, $description:literal, $signed:expr) => {
        #[doc = $description]
        #[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
        pub struct $name($native);

        impl $name {
            /// Constructs the value from a native integer without conversion.
            pub const fn new(value: $native) -> Self {
                Self(value)
            }

            /// Returns the checked native integer.
            pub const fn get(self) -> $native {
                self.0
            }
        }

        impl From<$native> for $name {
            fn from(value: $native) -> Self {
                Self(value)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        impl FromStr for $name {
            type Err = ContractError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                let digits = if $signed {
                    value.strip_prefix('-').unwrap_or(value)
                } else {
                    value
                };
                if digits.is_empty()
                    || !digits.bytes().all(|byte| byte.is_ascii_digit())
                    || (digits.starts_with('0') && (digits.len() != 1 || value.starts_with('-')))
                {
                    return Err(invalid(
                        stringify!($name),
                        "expected canonical decimal string",
                    ));
                }
                value
                    .parse::<$native>()
                    .map(Self)
                    .map_err(|_| invalid(stringify!($name), "integer outside declared range"))
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                String::deserialize(deserializer)?
                    .parse()
                    .map_err(serde::de::Error::custom)
            }
        }
    };
}

decimal_integer!(
    U64,
    u64,
    "Encodes an unsigned 64-bit value as a canonical decimal JSON string.",
    false
);
decimal_integer!(
    I64,
    i64,
    "Encodes a signed 64-bit offset as a canonical decimal JSON string.",
    true
);

impl Serialize for U64 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // The lookup table is static data; only the twenty-digit output bank
        // is per call. Two digits per division reduce wide-value loop iterations.
        const DIGIT_PAIRS: &[u8; 200] = b"00010203040506070809\
            10111213141516171819\
            20212223242526272829\
            30313233343536373839\
            40414243444546474849\
            50515253545556575859\
            60616263646566676869\
            70717273747576777879\
            80818283848586878889\
            90919293949596979899";
        let mut buffer = [b'0'; 20];
        let mut remaining = self.0;
        let mut start = buffer.len();
        while remaining >= 100 {
            let pair = (remaining % 100) as usize * 2;
            remaining /= 100;
            start -= 2;
            buffer[start] = DIGIT_PAIRS[pair];
            buffer[start + 1] = DIGIT_PAIRS[pair + 1];
        }
        if remaining < 10 {
            start -= 1;
            buffer[start] = b'0' + remaining as u8;
        } else {
            let pair = remaining as usize * 2;
            start -= 2;
            buffer[start] = DIGIT_PAIRS[pair];
            buffer[start + 1] = DIGIT_PAIRS[pair + 1];
        }
        // Each written byte is an ASCII digit; checked UTF-8 keeps this safe
        // without changing the canonical serialize_str representation.
        let digits = std::str::from_utf8(&buffer[start..]).map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(digits)
    }
}

impl Serialize for I64 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl Validate for U64 {
    fn validate(&self) -> Result<(), ContractError> {
        Ok(())
    }
}

impl Validate for I64 {
    fn validate(&self) -> Result<(), ContractError> {
        Ok(())
    }
}

/// Encodes opaque octets using canonical unpadded URL-safe base64.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Bytes(Vec<u8>);

impl Bytes {
    /// Constructs an opaque byte value; frame and resource limits apply at admission.
    pub fn new(value: Vec<u8>) -> Self {
        Self(value)
    }

    /// Returns the exact decoded octets.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Reports the actual decoded byte allocation capacity without copying.
    ///
    /// This is local storage metadata rather than a wire limit or source right.
    /// Serialization and equality continue to depend on the exact byte length.
    pub fn allocation_capacity(&self) -> usize {
        self.0.capacity()
    }

    /// Consumes the value and returns its decoded octets.
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

impl Serialize for Bytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

impl Validate for Bytes {
    fn validate(&self) -> Result<(), ContractError> {
        Ok(())
    }
}

#[path = "values/borrowed_bytes.rs"]
mod borrowed_bytes;

/// Measures picoseconds on the admitted coordinator timeline.
pub type Tick = U64;

impl U64 {
    /// Subtracts two values without unsigned underflow.
    ///
    /// # Errors
    /// Returns [`ContractError::Overflow`] when the result would be negative.
    pub fn checked_sub(self, other: Self) -> Result<Self, ContractError> {
        self.0
            .checked_sub(other.0)
            .map(Self)
            .ok_or(ContractError::Overflow)
    }

    /// Applies a signed clock offset without changing integer units.
    ///
    /// # Errors
    /// Rejects a result below zero or above `u64::MAX`.
    pub fn checked_offset(self, offset: I64) -> Result<Self, ContractError> {
        self.0
            .checked_add_signed(offset.get())
            .map(Self)
            .ok_or(ContractError::Overflow)
    }

    /// Adds two values with overflow detection.
    ///
    /// # Errors
    /// Returns [`ContractError::Overflow`] when the result exceeds `u64::MAX`.
    pub fn checked_add(self, other: Self) -> Result<Self, ContractError> {
        self.0
            .checked_add(other.0)
            .map(Self)
            .ok_or(ContractError::Overflow)
    }

    /// Multiplies two values with overflow detection.
    ///
    /// # Errors
    /// Returns [`ContractError::Overflow`] when the result exceeds `u64::MAX`.
    pub fn checked_mul(self, other: Self) -> Result<Self, ContractError> {
        self.0
            .checked_mul(other.0)
            .map(Self)
            .ok_or(ContractError::Overflow)
    }
}

/// Commits to bytes in a domain-separated CNP/1 hash namespace.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HashRef {
    /// Names the sole baseline digest algorithm, `blake3-256`.
    pub algorithm: String,
    /// Separates this identity from unrelated content constructions.
    pub domain: String,
    /// Contains exactly 64 lowercase hexadecimal characters.
    pub digest: String,
}

impl Validate for HashRef {
    fn validate(&self) -> Result<(), ContractError> {
        if self.algorithm != "blake3-256" {
            return Err(invalid("algorithm", "unsupported hash algorithm"));
        }
        validate_domain(&self.domain)?;
        if self.digest.len() != 64
            || !self
                .digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(invalid(
                "digest",
                "expected 64 lowercase hexadecimal characters",
            ));
        }
        Ok(())
    }
}

/// Identifies immutable portable content without granting access to it.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentRef {
    /// Hashes the exact stored bytes in `cnp.blob.v1`.
    pub hash: HashRef,
    /// Declares the exact stored byte length.
    pub length: U64,
    /// Describes the content using bounded printable ASCII.
    pub media_type: String,
}

impl ContentRef {
    /// Verifies exact byte length and opaque content identity.
    ///
    /// # Errors
    /// Rejects invalid reference syntax, a length mismatch, or a digest mismatch.
    /// Successful verification does not validate the referenced object's schema.
    pub fn verify(&self, payload: &[u8]) -> Result<(), ContractError> {
        self.validate()?;
        if u64::try_from(payload.len()).map_err(|_| ContractError::Overflow)? != self.length.get() {
            return Err(invalid(
                "content.length",
                "stored byte length disagrees with reference",
            ));
        }
        if crate::canonical::hash("cnp.blob.v1", payload)? != self.hash {
            return Err(invalid("content.hash", "stored bytes disagree with digest"));
        }
        Ok(())
    }
}

impl Validate for ContentRef {
    fn validate(&self) -> Result<(), ContractError> {
        self.hash.validate()?;
        if self.hash.domain != "cnp.blob.v1" {
            return Err(invalid("hash.domain", "content must use cnp.blob.v1"));
        }
        if self.media_type.is_empty()
            || self.media_type.len() > 128
            || !self
                .media_type
                .bytes()
                .all(|byte| (0x20..=0x7e).contains(&byte))
        {
            return Err(invalid(
                "media_type",
                "expected 1–128 printable ASCII bytes",
            ));
        }
        Ok(())
    }
}

pub(crate) fn validate_domain(domain: &str) -> Result<(), ContractError> {
    if domain.is_empty() || domain.len() > 128 || !domain.is_ascii() {
        return Err(invalid("domain", "expected 1–128 ASCII bytes"));
    }
    Ok(())
}

pub(crate) fn validate_sorted<T, K: Ord>(
    values: &[T],
    key: impl Fn(&T) -> K,
    field: &'static str,
) -> Result<(), ContractError> {
    if values.len() > MAX_ARRAY_ELEMENTS {
        return Err(invalid(field, "array exceeds 65536 elements"));
    }
    if values.windows(2).any(|pair| key(&pair[0]) >= key(&pair[1])) {
        return Err(invalid(
            field,
            "set must be strictly sorted with no duplicates",
        ));
    }
    Ok(())
}

pub(crate) fn validate_ids(ids: &[Id], field: &'static str) -> Result<(), ContractError> {
    validate_sorted(ids, |id| id.as_str().to_owned(), field)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod original_bytes_capacity_tests {
    use super::*;

    #[test]
    fn decoded_capacity_observation_preserves_existing_wire_and_same_empty_bank() {
        let mut original = Vec::with_capacity(128);
        original.extend_from_slice(b"abcd");
        let bytes = Bytes::new(original);
        assert_eq!(bytes.allocation_capacity(), 128);
        assert_eq!(serde_json::to_string(&bytes).unwrap(), "\"YWJjZA\"");
        let mut original = bytes.into_vec();
        let pointer = original.as_ptr();
        original.clear();
        let bytes = Bytes::new(original);
        assert_eq!(bytes.allocation_capacity(), 128);
        assert_eq!(bytes.as_slice().as_ptr(), pointer);
        assert_eq!(serde_json::to_string(&bytes).unwrap(), "\"\"");
    }
}

#[cfg(test)]
// These bounded fixture constructors deliberately panic on invalid test setup.
#[allow(clippy::unwrap_used)]
mod allocated_capacity_tests {
    use super::Id;

    #[test]
    fn allocated_identifier_capacity_retains_spare_storage_without_changing_wire_bytes() {
        let mut original = String::with_capacity(4096);
        original.push_str("capture/owner");
        let capacity = original.capacity();
        let id = Id::new(original).unwrap();

        assert_eq!(id.allocated_capacity(), capacity);
        assert!(id.allocated_capacity() > id.as_str().len());
        assert_eq!(serde_json::to_string(&id).unwrap(), "\"capture/owner\"");
        let decoded: Id = serde_json::from_str("\"capture/owner\"").unwrap();
        assert_eq!(decoded, id);
    }
}

#[cfg(test)]
mod retained_identifier_refusal_tests {
    use super::Id;

    #[test]
    fn invalid_owned_identifier_returns_the_same_spare_backing() {
        let mut text = String::with_capacity(97);
        text.push_str("contains space");
        let pointer = text.as_ptr();
        let capacity = text.capacity();

        let Err((returned, _)) = Id::try_from_owned(text) else {
            panic!("invalid identifier was accepted");
        };

        assert_eq!(returned, "contains space");
        assert_eq!(returned.as_ptr(), pointer);
        assert_eq!(returned.capacity(), capacity);
    }
}

#[cfg(test)]
#[path = "values/u64_serialize_tests.rs"]
mod u64_serialize_tests;
