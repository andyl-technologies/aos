//! Portable typed choice values for the guest selectable boundary.
//!
//! These types own the L1 canonical representation shared by the optional
//! guest agent and host campaign adapter. The encoding is fixed-width
//! big-endian with one-byte union tags and `u64` collection/string lengths.

use std::collections::BTreeMap;
use std::fmt;
use std::str;

use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

const CHOICE_DOMAIN_SCHEMA_VERSION: u32 = 1;
const MAX_CHOICE_DOMAIN_BYTES: usize = 32 * 1024 * 1024;
const MAX_DISCRETE_ALTERNATIVES: usize = 4096;
const MAX_INTEGER_LANDMARKS: usize = 4096;
const MAX_PRESENTATION_BYTES: usize = 2048;

/// Error decoding or validating a portable typed choice.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ChoiceCodecError {
    /// The input ended before the declared value was complete.
    #[error("typed choice is truncated")]
    Truncated,
    /// Bytes remained after the one expected value.
    #[error("typed choice contains trailing bytes")]
    TrailingBytes,
    /// A boolean was not encoded as zero or one.
    #[error("typed choice contains a non-canonical boolean")]
    InvalidBoolean,
    /// A closed union tag was unknown.
    #[error("typed choice contains an unknown {kind} tag {tag}")]
    UnknownTag {
        /// Stable union name.
        kind: &'static str,
        /// Rejected tag.
        tag: u8,
    },
    /// Text was not valid UTF-8.
    #[error("typed choice contains invalid UTF-8")]
    InvalidUtf8,
    /// A declared allocation or byte limit was exceeded.
    #[error("typed choice exceeds the {limit} limit")]
    LimitExceeded {
        /// Stable limit category.
        limit: &'static str,
    },
    /// The input had a valid shape but noncanonical bytes.
    #[error("typed choice is not canonically encoded")]
    NonCanonical,
    /// A hexadecimal alternative identifier was malformed.
    #[error("typed choice identity is not canonical lowercase hexadecimal")]
    InvalidHex,
    /// A semantic domain invariant was violated.
    #[error("typed choice is invalid: {reason}")]
    InvalidValue {
        /// Stable validation reason.
        reason: &'static str,
    },
}

/// Stable 256-bit identity for one discrete alternative.
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AlternativeId([u8; 32]);

impl AlternativeId {
    /// Builds an identifier from its exact digest bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Parses exactly 64 lowercase hexadecimal characters.
    ///
    /// # Errors
    ///
    /// Returns [`ChoiceCodecError::InvalidHex`] for any other representation.
    pub fn parse(value: &str) -> Result<Self, ChoiceCodecError> {
        if value.len() != 64
            || value
                .bytes()
                .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
        {
            return Err(ChoiceCodecError::InvalidHex);
        }
        let mut bytes = [0_u8; 32];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            bytes[index] = (hex_digit(pair[0])? << 4) | hex_digit(pair[1])?;
        }
        Ok(Self(bytes))
    }

    /// Renders the canonical lowercase hexadecimal identity.
    #[must_use]
    pub fn to_hex(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut result = String::with_capacity(64);
        for byte in self.0 {
            result.push(char::from(HEX[usize::from(byte >> 4)]));
            result.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        result
    }
}

impl fmt::Debug for AlternativeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("AlternativeId")
            .field(&self.to_hex())
            .finish()
    }
}

impl fmt::Display for AlternativeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

/// Reduced nonnegative exact rational used by integer domain scales.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ExactRational {
    numerator: u64,
    denominator: u64,
}

impl ExactRational {
    /// Builds and reduces one nonnegative rational.
    ///
    /// # Errors
    ///
    /// Returns [`ChoiceCodecError::InvalidValue`] for denominator zero.
    pub fn new(numerator: u64, denominator: u64) -> Result<Self, ChoiceCodecError> {
        if denominator == 0 {
            return Err(ChoiceCodecError::InvalidValue {
                reason: "rational denominator is zero",
            });
        }
        let divisor = greatest_common_divisor(numerator, denominator);
        Ok(Self {
            numerator: numerator / divisor,
            denominator: denominator / divisor,
        })
    }

    /// Returns the reduced numerator.
    #[must_use]
    pub const fn numerator(self) -> u64 {
        self.numerator
    }

    /// Returns the positive reduced denominator.
    #[must_use]
    pub const fn denominator(self) -> u64 {
        self.denominator
    }
}

/// Boolean domain with an explicit semantic version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BooleanDomain {
    semantic_version: u32,
}

impl BooleanDomain {
    /// Builds a versioned Boolean domain.
    ///
    /// # Errors
    ///
    /// Returns [`ChoiceCodecError::InvalidValue`] for version zero.
    pub fn new(semantic_version: u32) -> Result<Self, ChoiceCodecError> {
        if semantic_version == 0 {
            return Err(ChoiceCodecError::InvalidValue {
                reason: "choice-domain semantic version is zero",
            });
        }
        Ok(Self { semantic_version })
    }

    /// Returns the semantic domain version.
    #[must_use]
    pub const fn semantic_version(self) -> u32 {
        self.semantic_version
    }
}

/// Stable discrete alternative with non-semantic presentation text.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DiscreteAlternative {
    id: AlternativeId,
    label: String,
    description: Option<String>,
}

impl DiscreteAlternative {
    /// Builds one stable alternative.
    ///
    /// # Errors
    ///
    /// Returns [`ChoiceCodecError`] for invalid or oversized presentation text.
    pub fn new(
        id: AlternativeId,
        label: impl Into<String>,
        description: Option<String>,
    ) -> Result<Self, ChoiceCodecError> {
        let label = label.into();
        validate_text(&label, false)?;
        if let Some(value) = &description {
            validate_text(value, true)?;
        }
        Ok(Self {
            id,
            label,
            description,
        })
    }

    /// Returns the stable semantic identity.
    #[must_use]
    pub const fn id(&self) -> AlternativeId {
        self.id
    }

    /// Returns the display label.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Returns the optional display description.
    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

/// Nonempty finite discrete choice domain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscreteDomain {
    semantic_version: u32,
    alternatives: BTreeMap<AlternativeId, DiscreteAlternative>,
}

impl DiscreteDomain {
    /// Builds a canonical alternative map keyed by stable identity.
    ///
    /// # Errors
    ///
    /// Returns [`ChoiceCodecError`] for version zero, invalid count, or a
    /// key/value identity mismatch.
    pub fn new(
        semantic_version: u32,
        alternatives: BTreeMap<AlternativeId, DiscreteAlternative>,
    ) -> Result<Self, ChoiceCodecError> {
        if semantic_version == 0 {
            return Err(ChoiceCodecError::InvalidValue {
                reason: "choice-domain semantic version is zero",
            });
        }
        if alternatives.is_empty() || alternatives.len() > MAX_DISCRETE_ALTERNATIVES {
            return Err(ChoiceCodecError::InvalidValue {
                reason: "discrete domain is empty or oversized",
            });
        }
        if alternatives
            .iter()
            .any(|(id, alternative)| *id != alternative.id)
        {
            return Err(ChoiceCodecError::InvalidValue {
                reason: "discrete-domain key disagrees with alternative ID",
            });
        }
        Ok(Self {
            semantic_version,
            alternatives,
        })
    }

    /// Returns alternatives in canonical ID order.
    #[must_use]
    pub fn alternatives(&self) -> &BTreeMap<AlternativeId, DiscreteAlternative> {
        &self.alternatives
    }
}

/// Signedness and fixed width of an integer domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IntegerRepresentation {
    /// Canonical signed 64-bit integer.
    Signed64,
    /// Canonical unsigned 64-bit integer.
    Unsigned64,
}

/// Fixed-width integer value without platform-native narrowing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IntegerValue {
    /// Signed 64-bit value.
    Signed(i64),
    /// Unsigned 64-bit value.
    Unsigned(u64),
}

/// Inclusive stepped integer domain with exact scale and landmarks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntegerDomain {
    semantic_version: u32,
    representation: IntegerRepresentation,
    minimum: IntegerValue,
    maximum: IntegerValue,
    step: u64,
    unit: Option<String>,
    scale: ExactRational,
    landmarks: Vec<IntegerValue>,
}

impl IntegerDomain {
    /// Builds and validates one fixed-width integer domain.
    ///
    /// # Errors
    ///
    /// Returns [`ChoiceCodecError`] for an invalid version, representation,
    /// range, step, unit, scale, or landmark set.
    // crucible-lint: allow rust-allow -- the constructor mirrors the closed integer-domain wire record.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        semantic_version: u32,
        representation: IntegerRepresentation,
        minimum: IntegerValue,
        maximum: IntegerValue,
        step: u64,
        unit: Option<String>,
        scale: ExactRational,
        mut landmarks: Vec<IntegerValue>,
    ) -> Result<Self, ChoiceCodecError> {
        if semantic_version == 0 || step == 0 || scale.numerator == 0 {
            return Err(ChoiceCodecError::InvalidValue {
                reason: "integer domain has zero version, step, or scale",
            });
        }
        if let Some(value) = &unit {
            validate_text(value, false)?;
        }
        if landmarks.len() > MAX_INTEGER_LANDMARKS {
            return Err(ChoiceCodecError::LimitExceeded {
                limit: "integer-domain-landmark-count",
            });
        }
        validate_representation(representation, minimum)?;
        validate_representation(representation, maximum)?;
        let span = integer_offset(minimum, maximum).ok_or(ChoiceCodecError::InvalidValue {
            reason: "integer domain range is inverted",
        })?;
        if span % u128::from(step) != 0 {
            return Err(ChoiceCodecError::InvalidValue {
                reason: "integer domain maximum is unreachable by its step",
            });
        }
        landmarks.sort_unstable();
        if landmarks.windows(2).any(|window| window[0] == window[1]) {
            return Err(ChoiceCodecError::InvalidValue {
                reason: "integer domain contains duplicate landmarks",
            });
        }
        let domain = Self {
            semantic_version,
            representation,
            minimum,
            maximum,
            step,
            unit,
            scale,
            landmarks,
        };
        if domain
            .landmarks
            .iter()
            .any(|value| !domain.contains_integer(*value))
        {
            return Err(ChoiceCodecError::InvalidValue {
                reason: "integer domain contains an illegal landmark",
            });
        }
        Ok(domain)
    }

    /// Returns whether one integer is legal in the domain.
    #[must_use]
    pub fn contains_integer(&self, value: IntegerValue) -> bool {
        validate_representation(self.representation, value).is_ok()
            && integer_offset(self.minimum, value)
                .zip(integer_offset(value, self.maximum))
                .is_some_and(|(offset, _)| offset % u128::from(self.step) == 0)
    }
}

/// Closed typed legal-value domain shared across the selectable protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChoiceDomain {
    /// Boolean false/true domain.
    Boolean(BooleanDomain),
    /// Nonempty finite stable alternatives.
    Discrete(DiscreteDomain),
    /// Signed or unsigned stepped integer range.
    Integer(IntegerDomain),
}

impl ChoiceDomain {
    /// Returns whether `value` is legal in this domain.
    #[must_use]
    pub fn contains(&self, value: &ChoiceValue) -> bool {
        match (self, value) {
            (Self::Boolean(_), ChoiceValue::Boolean(_)) => true,
            (Self::Discrete(domain), ChoiceValue::Discrete(id)) => {
                domain.alternatives.contains_key(id)
            }
            (Self::Integer(domain), ChoiceValue::Integer(value)) => domain.contains_integer(*value),
            _ => false,
        }
    }

    /// Returns strict schema-versioned canonical bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut encoder = Encoder::default();
        encoder.u32(CHOICE_DOMAIN_SCHEMA_VERSION);
        encode_domain(&mut encoder, self);
        encoder.bytes
    }

    /// Decodes and validates strict schema-versioned canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ChoiceCodecError`] for malformed, noncanonical, oversized,
    /// or semantically invalid bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ChoiceCodecError> {
        if bytes.len() > MAX_CHOICE_DOMAIN_BYTES {
            return Err(ChoiceCodecError::LimitExceeded {
                limit: "choice-domain-encoded-bytes",
            });
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.u32()? != CHOICE_DOMAIN_SCHEMA_VERSION {
            return Err(ChoiceCodecError::InvalidValue {
                reason: "unsupported choice-domain schema version",
            });
        }
        let value = decode_domain(&mut decoder)?;
        decoder.finish()?;
        if value.canonical_bytes() != bytes {
            return Err(ChoiceCodecError::NonCanonical);
        }
        Ok(value)
    }
}

/// Concrete legal value selected from a [`ChoiceDomain`].
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChoiceValue {
    /// Boolean value.
    Boolean(bool),
    /// Stable discrete alternative.
    Discrete(AlternativeId),
    /// Signed or unsigned fixed-width integer.
    Integer(IntegerValue),
}

impl ChoiceValue {
    /// Returns strict canonical value bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut encoder = Encoder::default();
        encode_value(&mut encoder, self);
        encoder.bytes
    }

    /// Decodes and validates strict canonical value bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ChoiceCodecError`] for malformed or noncanonical bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ChoiceCodecError> {
        let mut decoder = Decoder::new(bytes);
        let value = decode_value(&mut decoder)?;
        decoder.finish()?;
        if value.canonical_bytes() != bytes {
            return Err(ChoiceCodecError::NonCanonical);
        }
        Ok(value)
    }
}

#[derive(Default)]
struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }
    fn bool(&mut self, value: bool) {
        self.u8(u8::from(value));
    }
    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }
    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }
    fn i64(&mut self, value: i64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }
    fn string(&mut self, value: &str) {
        self.u64(value.len() as u64);
        self.bytes.extend_from_slice(value.as_bytes());
    }
    fn option_string(&mut self, value: Option<&str>) {
        self.bool(value.is_some());
        if let Some(value) = value {
            self.string(value);
        }
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }
    fn finish(self) -> Result<(), ChoiceCodecError> {
        (self.cursor == self.bytes.len())
            .then_some(())
            .ok_or(ChoiceCodecError::TrailingBytes)
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], ChoiceCodecError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(ChoiceCodecError::Truncated)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(ChoiceCodecError::Truncated)?;
        self.cursor = end;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], ChoiceCodecError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ChoiceCodecError::Truncated)
    }
    fn u8(&mut self) -> Result<u8, ChoiceCodecError> {
        Ok(self.array::<1>()?[0])
    }
    fn bool(&mut self) -> Result<bool, ChoiceCodecError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(ChoiceCodecError::InvalidBoolean),
        }
    }
    fn u32(&mut self) -> Result<u32, ChoiceCodecError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, ChoiceCodecError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn i64(&mut self) -> Result<i64, ChoiceCodecError> {
        Ok(i64::from_be_bytes(self.array()?))
    }
    fn count(&mut self, maximum: usize, limit: &'static str) -> Result<usize, ChoiceCodecError> {
        let value = self.u64()?;
        if value > maximum as u64 {
            return Err(ChoiceCodecError::LimitExceeded { limit });
        }
        usize::try_from(value).map_err(|_| ChoiceCodecError::LimitExceeded { limit })
    }
    fn string(&mut self, maximum: usize, limit: &'static str) -> Result<String, ChoiceCodecError> {
        let length = self.count(maximum, limit)?;
        let value =
            str::from_utf8(self.take(length)?).map_err(|_| ChoiceCodecError::InvalidUtf8)?;
        if value.nfc().ne(value.chars()) {
            return Err(ChoiceCodecError::NonCanonical);
        }
        Ok(value.to_owned())
    }
    fn option_string(&mut self) -> Result<Option<String>, ChoiceCodecError> {
        if self.bool()? {
            self.string(MAX_PRESENTATION_BYTES, "discrete-description-bytes")
                .map(Some)
        } else {
            Ok(None)
        }
    }
}

fn encode_alternative(encoder: &mut Encoder, value: &DiscreteAlternative) {
    encoder.bytes.extend_from_slice(&value.id.0);
    encoder.string(&value.label);
    encoder.option_string(value.description.as_deref());
}

fn decode_alternative(decoder: &mut Decoder<'_>) -> Result<DiscreteAlternative, ChoiceCodecError> {
    DiscreteAlternative::new(
        AlternativeId(decoder.array()?),
        decoder.string(MAX_PRESENTATION_BYTES, "discrete-label-bytes")?,
        decoder.option_string()?,
    )
}

fn encode_integer_value(encoder: &mut Encoder, value: IntegerValue) {
    match value {
        IntegerValue::Signed(value) => {
            encoder.u8(0);
            encoder.i64(value);
        }
        IntegerValue::Unsigned(value) => {
            encoder.u8(1);
            encoder.u64(value);
        }
    }
}

fn decode_integer_value(decoder: &mut Decoder<'_>) -> Result<IntegerValue, ChoiceCodecError> {
    match decoder.u8()? {
        0 => decoder.i64().map(IntegerValue::Signed),
        1 => decoder.u64().map(IntegerValue::Unsigned),
        tag => Err(ChoiceCodecError::UnknownTag {
            kind: "integer-value",
            tag,
        }),
    }
}

fn encode_domain(encoder: &mut Encoder, value: &ChoiceDomain) {
    match value {
        ChoiceDomain::Boolean(domain) => {
            encoder.u8(0);
            encoder.u32(domain.semantic_version);
        }
        ChoiceDomain::Discrete(domain) => {
            encoder.u8(1);
            encoder.u32(domain.semantic_version);
            encoder.u64(domain.alternatives.len() as u64);
            for (id, alternative) in &domain.alternatives {
                encoder.bytes.extend_from_slice(&id.0);
                encode_alternative(encoder, alternative);
            }
        }
        ChoiceDomain::Integer(domain) => {
            encoder.u8(2);
            encoder.u32(domain.semantic_version);
            encoder.u8(match domain.representation {
                IntegerRepresentation::Signed64 => 0,
                IntegerRepresentation::Unsigned64 => 1,
            });
            encode_integer_value(encoder, domain.minimum);
            encode_integer_value(encoder, domain.maximum);
            encoder.u64(domain.step);
            encoder.option_string(domain.unit.as_deref());
            encoder.u64(domain.scale.numerator);
            encoder.u64(domain.scale.denominator);
            encoder.u64(domain.landmarks.len() as u64);
            for landmark in &domain.landmarks {
                encode_integer_value(encoder, *landmark);
            }
        }
    }
}

fn decode_domain(decoder: &mut Decoder<'_>) -> Result<ChoiceDomain, ChoiceCodecError> {
    match decoder.u8()? {
        0 => BooleanDomain::new(decoder.u32()?).map(ChoiceDomain::Boolean),
        1 => {
            let version = decoder.u32()?;
            let count = decoder.count(
                MAX_DISCRETE_ALTERNATIVES,
                "discrete-domain-alternative-count",
            )?;
            let mut alternatives = BTreeMap::new();
            for _ in 0..count {
                let id = AlternativeId(decoder.array()?);
                let alternative = decode_alternative(decoder)?;
                if alternatives.insert(id, alternative).is_some() {
                    return Err(ChoiceCodecError::InvalidValue {
                        reason: "canonical map contains a duplicate key",
                    });
                }
            }
            DiscreteDomain::new(version, alternatives).map(ChoiceDomain::Discrete)
        }
        2 => {
            let version = decoder.u32()?;
            let representation = match decoder.u8()? {
                0 => IntegerRepresentation::Signed64,
                1 => IntegerRepresentation::Unsigned64,
                tag => {
                    return Err(ChoiceCodecError::UnknownTag {
                        kind: "integer-representation",
                        tag,
                    });
                }
            };
            let minimum = decode_integer_value(decoder)?;
            let maximum = decode_integer_value(decoder)?;
            let step = decoder.u64()?;
            let unit = if decoder.bool()? {
                Some(decoder.string(MAX_PRESENTATION_BYTES, "integer-unit-bytes")?)
            } else {
                None
            };
            let scale = ExactRational::new(decoder.u64()?, decoder.u64()?)?;
            let count = decoder.count(MAX_INTEGER_LANDMARKS, "integer-domain-landmark-count")?;
            let mut landmarks = Vec::with_capacity(count);
            for _ in 0..count {
                landmarks.push(decode_integer_value(decoder)?);
            }
            IntegerDomain::new(
                version,
                representation,
                minimum,
                maximum,
                step,
                unit,
                scale,
                landmarks,
            )
            .map(ChoiceDomain::Integer)
        }
        tag => Err(ChoiceCodecError::UnknownTag {
            kind: "choice-domain",
            tag,
        }),
    }
}

fn encode_value(encoder: &mut Encoder, value: &ChoiceValue) {
    match value {
        ChoiceValue::Boolean(value) => {
            encoder.u8(0);
            encoder.bool(*value);
        }
        ChoiceValue::Discrete(id) => {
            encoder.u8(1);
            encoder.bytes.extend_from_slice(&id.0);
        }
        ChoiceValue::Integer(value) => {
            encoder.u8(2);
            encode_integer_value(encoder, *value);
        }
    }
}

fn decode_value(decoder: &mut Decoder<'_>) -> Result<ChoiceValue, ChoiceCodecError> {
    match decoder.u8()? {
        0 => decoder.bool().map(ChoiceValue::Boolean),
        1 => decoder
            .array()
            .map(|bytes| ChoiceValue::Discrete(AlternativeId(bytes))),
        2 => decode_integer_value(decoder).map(ChoiceValue::Integer),
        tag => Err(ChoiceCodecError::UnknownTag {
            kind: "choice-value",
            tag,
        }),
    }
}

fn validate_text(value: &str, allow_empty: bool) -> Result<(), ChoiceCodecError> {
    if (!allow_empty && value.is_empty()) || value.len() > MAX_PRESENTATION_BYTES {
        return Err(ChoiceCodecError::InvalidValue {
            reason: "choice presentation text is invalid",
        });
    }
    if value.nfc().ne(value.chars()) {
        return Err(ChoiceCodecError::NonCanonical);
    }
    Ok(())
}

fn validate_representation(
    representation: IntegerRepresentation,
    value: IntegerValue,
) -> Result<(), ChoiceCodecError> {
    if matches!(
        (representation, value),
        (IntegerRepresentation::Signed64, IntegerValue::Signed(_))
            | (IntegerRepresentation::Unsigned64, IntegerValue::Unsigned(_))
    ) {
        Ok(())
    } else {
        Err(ChoiceCodecError::InvalidValue {
            reason: "integer value disagrees with domain representation",
        })
    }
}

fn integer_offset(minimum: IntegerValue, value: IntegerValue) -> Option<u128> {
    match (minimum, value) {
        (IntegerValue::Signed(minimum), IntegerValue::Signed(value)) => {
            u128::try_from(i128::from(value) - i128::from(minimum)).ok()
        }
        (IntegerValue::Unsigned(minimum), IntegerValue::Unsigned(value)) => {
            value.checked_sub(minimum).map(u128::from)
        }
        _ => None,
    }
}

fn greatest_common_divisor(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left.max(1)
}

fn hex_digit(value: u8) -> Result<u8, ChoiceCodecError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(ChoiceCodecError::InvalidHex),
    }
}
