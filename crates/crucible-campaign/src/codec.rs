//! Strict canonical binary primitives for campaign objects.
//!
//! The format uses fixed-width big-endian integers, one-byte variants and
//! booleans, and `u64` length prefixes. Decoding is bounded before allocation.
//! A decoded value is accepted only when re-encoding it produces the exact
//! input bytes, which rejects alternate or trailing representations.

use std::collections::{BTreeMap, BTreeSet};
use std::str;

use crucible_cas::content_envelope::ContentEnvelopeError;
use crucible_cas::content_store::ContentId;
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

pub(crate) const MAX_CANONICAL_BYTES: usize = 64 * 1024 * 1024;
const MAX_COLLECTION_ITEMS: u64 = 1_000_000;
const MAX_STRING_BYTES: u64 = 1024 * 1024;

/// Error returned while encoding, decoding, or validating campaign bytes.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CampaignCodecError {
    /// Generic child-bearing envelope framing failed validation.
    #[error(transparent)]
    Envelope(#[from] ContentEnvelopeError),
    /// The input ended before the declared value was complete.
    #[error("campaign object is truncated")]
    Truncated,
    /// Bytes remained after the one expected value.
    #[error("campaign object contains trailing bytes")]
    TrailingBytes,
    /// A boolean was not encoded as zero or one.
    #[error("campaign object contains a non-canonical boolean")]
    InvalidBoolean,
    /// An enum or union tag is unknown.
    #[error("campaign object contains an unknown {kind} tag {tag}")]
    UnknownTag {
        /// Stable name of the tagged type.
        kind: &'static str,
        /// Rejected tag value.
        tag: u8,
    },
    /// A string was not valid UTF-8.
    #[error("campaign object contains invalid UTF-8")]
    InvalidUtf8,
    /// A declared length exceeded a canonical decoding limit.
    #[error("campaign object exceeds the {limit} limit")]
    LimitExceeded {
        /// Stable limit category.
        limit: &'static str,
    },
    /// A value had a valid shape but a non-canonical byte representation.
    #[error("campaign object is not canonically encoded")]
    NonCanonical,
    /// A hexadecimal identity was malformed or not lowercase canonical text.
    #[error("campaign identity is not canonical lowercase hexadecimal")]
    InvalidHex,
    /// A semantic invariant was violated.
    #[error("campaign object is invalid: {reason}")]
    InvalidValue {
        /// Stable validation reason.
        reason: &'static str,
    },
}

pub(crate) trait Canonical: Sized {
    fn encode(&self, encoder: &mut Encoder);

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError>;
}

impl Canonical for bool {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.bool(*self);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        decoder.bool()
    }
}

impl Canonical for u8 {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u8(*self);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        decoder.u8()
    }
}

impl Canonical for u32 {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u32(*self);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        decoder.u32()
    }
}

impl Canonical for u64 {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u64(*self);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        decoder.u64()
    }
}

impl Canonical for i64 {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.i64(*self);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        decoder.i64()
    }
}

impl Canonical for u128 {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u128(*self);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        decoder.u128()
    }
}

impl Canonical for String {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.string(self);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        decoder.string()
    }
}

impl Canonical for ContentId {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.string(&ContentId::encode(*self));
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        ContentId::parse(&decoder.string_bounded(256, "content-id-text-bytes")?).map_err(|_| {
            CampaignCodecError::InvalidValue {
                reason: "content reference is invalid or noncanonical",
            }
        })
    }
}

impl<T: Canonical> Canonical for Option<T> {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.option(self.as_ref(), |encoder, value| value.encode(encoder));
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        decoder.option(T::decode)
    }
}

impl<T: Canonical> Canonical for Vec<T> {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.sequence(self, |encoder, value| value.encode(encoder));
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        decoder.sequence(T::decode)
    }
}

impl<T: Canonical + Ord> Canonical for BTreeSet<T> {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u64(self.len() as u64);
        for value in self {
            value.encode(encoder);
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let count = decoder.bounded_count()?;
        let mut values = BTreeSet::new();
        for _ in 0..count {
            if !values.insert(T::decode(decoder)?) {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "canonical set contains a duplicate value",
                });
            }
        }
        Ok(values)
    }
}

impl<K: Canonical + Ord, V: Canonical> Canonical for BTreeMap<K, V> {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u64(self.len() as u64);
        for (key, value) in self {
            key.encode(encoder);
            value.encode(encoder);
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let count = decoder.bounded_count()?;
        let mut values = BTreeMap::new();
        for _ in 0..count {
            let key = K::decode(decoder)?;
            let value = V::decode(decoder)?;
            if values.insert(key, value).is_some() {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "canonical map contains a duplicate key",
                });
            }
        }
        Ok(values)
    }
}

pub(crate) fn encode<T: Canonical>(value: &T) -> Vec<u8> {
    let mut encoder = Encoder::new();
    value.encode(&mut encoder);
    encoder.finish()
}

pub(crate) fn decode<T: Canonical>(bytes: &[u8]) -> Result<T, CampaignCodecError> {
    if bytes.len() > MAX_CANONICAL_BYTES {
        return Err(CampaignCodecError::LimitExceeded {
            limit: "canonical-byte-count",
        });
    }
    let mut decoder = Decoder::new(bytes);
    let value = T::decode(&mut decoder)?;
    decoder.finish()?;
    if encode(&value) != bytes {
        return Err(CampaignCodecError::NonCanonical);
    }
    Ok(value)
}

pub(crate) fn validate_nfc(value: &str) -> Result<(), CampaignCodecError> {
    if value.nfc().eq(value.chars()) {
        Ok(())
    } else {
        Err(CampaignCodecError::NonCanonical)
    }
}

pub(crate) fn ensure_encoded_size<T: Canonical>(
    value: &T,
    maximum: usize,
    limit: &'static str,
) -> Result<(), CampaignCodecError> {
    if encode(value).len() <= maximum {
        Ok(())
    } else {
        Err(CampaignCodecError::LimitExceeded { limit })
    }
}

pub(crate) struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    pub(crate) fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    pub(crate) fn finish(self) -> Vec<u8> {
        self.bytes
    }

    pub(crate) fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    pub(crate) fn bool(&mut self, value: bool) {
        self.u8(u8::from(value));
    }

    pub(crate) fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub(crate) fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub(crate) fn i64(&mut self, value: i64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub(crate) fn u128(&mut self, value: u128) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub(crate) fn fixed(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    pub(crate) fn bytes(&mut self, value: &[u8]) {
        self.u64(value.len() as u64);
        self.fixed(value);
    }

    pub(crate) fn string(&mut self, value: &str) {
        self.bytes(value.as_bytes());
    }

    pub(crate) fn option<T>(
        &mut self,
        value: Option<&T>,
        encode_value: impl FnOnce(&mut Self, &T),
    ) {
        match value {
            Some(value) => {
                self.bool(true);
                encode_value(self, value);
            }
            None => self.bool(false),
        }
    }

    pub(crate) fn sequence<T>(
        &mut self,
        values: &[T],
        mut encode_value: impl FnMut(&mut Self, &T),
    ) {
        self.u64(values.len() as u64);
        for value in values {
            encode_value(self, value);
        }
    }
}

pub(crate) struct Decoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn finish(self) -> Result<(), CampaignCodecError> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err(CampaignCodecError::TrailingBytes)
        }
    }

    pub(crate) fn u8(&mut self) -> Result<u8, CampaignCodecError> {
        let value = *self
            .bytes
            .get(self.cursor)
            .ok_or(CampaignCodecError::Truncated)?;
        self.cursor += 1;
        Ok(value)
    }

    pub(crate) fn bool(&mut self) -> Result<bool, CampaignCodecError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(CampaignCodecError::InvalidBoolean),
        }
    }

    pub(crate) fn u32(&mut self) -> Result<u32, CampaignCodecError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, CampaignCodecError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    pub(crate) fn i64(&mut self) -> Result<i64, CampaignCodecError> {
        Ok(i64::from_be_bytes(self.array()?))
    }

    pub(crate) fn u128(&mut self) -> Result<u128, CampaignCodecError> {
        Ok(u128::from_be_bytes(self.array()?))
    }

    pub(crate) fn fixed<const N: usize>(&mut self) -> Result<[u8; N], CampaignCodecError> {
        self.array()
    }

    pub(crate) fn string(&mut self) -> Result<String, CampaignCodecError> {
        self.string_bounded(MAX_STRING_BYTES as usize, "string-length")
    }

    pub(crate) fn string_bounded(
        &mut self,
        maximum: usize,
        limit: &'static str,
    ) -> Result<String, CampaignCodecError> {
        let length = self.bounded_length(maximum as u64, limit)?;
        let bytes = self.take(length)?;
        let value = str::from_utf8(bytes).map_err(|_| CampaignCodecError::InvalidUtf8)?;
        if value.nfc().ne(value.chars()) {
            return Err(CampaignCodecError::NonCanonical);
        }
        Ok(value.to_owned())
    }

    pub(crate) fn option_string_bounded(
        &mut self,
        maximum: usize,
        limit: &'static str,
    ) -> Result<Option<String>, CampaignCodecError> {
        self.option(|decoder| decoder.string_bounded(maximum, limit))
    }

    pub(crate) fn option<T>(
        &mut self,
        decode_value: impl FnOnce(&mut Self) -> Result<T, CampaignCodecError>,
    ) -> Result<Option<T>, CampaignCodecError> {
        if self.bool()? {
            decode_value(self).map(Some)
        } else {
            Ok(None)
        }
    }

    pub(crate) fn sequence<T>(
        &mut self,
        mut decode_value: impl FnMut(&mut Self) -> Result<T, CampaignCodecError>,
    ) -> Result<Vec<T>, CampaignCodecError> {
        let length = self.bounded_length(MAX_COLLECTION_ITEMS, "collection-item-count")?;
        let mut values = Vec::new();
        values
            .try_reserve_exact(length)
            .map_err(|_| CampaignCodecError::LimitExceeded {
                limit: "collection-allocation",
            })?;
        for _ in 0..length {
            values.push(decode_value(self)?);
        }
        Ok(values)
    }

    pub(crate) fn sequence_bounded<T>(
        &mut self,
        maximum: usize,
        limit: &'static str,
        mut decode_value: impl FnMut(&mut Self) -> Result<T, CampaignCodecError>,
    ) -> Result<Vec<T>, CampaignCodecError> {
        let length = self.bounded_length(maximum as u64, limit)?;
        let mut values = Vec::new();
        values
            .try_reserve_exact(length)
            .map_err(|_| CampaignCodecError::LimitExceeded { limit })?;
        for _ in 0..length {
            values.push(decode_value(self)?);
        }
        Ok(values)
    }

    pub(crate) fn set_bounded<T: Canonical + Ord>(
        &mut self,
        maximum: usize,
        limit: &'static str,
    ) -> Result<BTreeSet<T>, CampaignCodecError> {
        self.set_bounded_by(maximum, limit, T::decode)
    }

    pub(crate) fn set_bounded_by<T: Ord>(
        &mut self,
        maximum: usize,
        limit: &'static str,
        mut decode_value: impl FnMut(&mut Self) -> Result<T, CampaignCodecError>,
    ) -> Result<BTreeSet<T>, CampaignCodecError> {
        let count = self.bounded_length(maximum as u64, limit)?;
        let mut values = BTreeSet::new();
        for _ in 0..count {
            if !values.insert(decode_value(self)?) {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "canonical set contains a duplicate value",
                });
            }
        }
        Ok(values)
    }

    pub(crate) fn map_bounded<K: Canonical + Ord, V: Canonical>(
        &mut self,
        maximum: usize,
        limit: &'static str,
    ) -> Result<BTreeMap<K, V>, CampaignCodecError> {
        self.map_bounded_by(maximum, limit, K::decode, V::decode)
    }

    pub(crate) fn map_bounded_by<K: Ord, V>(
        &mut self,
        maximum: usize,
        limit: &'static str,
        mut decode_key: impl FnMut(&mut Self) -> Result<K, CampaignCodecError>,
        mut decode_value: impl FnMut(&mut Self) -> Result<V, CampaignCodecError>,
    ) -> Result<BTreeMap<K, V>, CampaignCodecError> {
        let count = self.bounded_length(maximum as u64, limit)?;
        let mut values = BTreeMap::new();
        for _ in 0..count {
            let key = decode_key(self)?;
            let value = decode_value(self)?;
            if values.insert(key, value).is_some() {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "canonical map contains a duplicate key",
                });
            }
        }
        Ok(values)
    }

    pub(crate) fn bounded_count(&mut self) -> Result<usize, CampaignCodecError> {
        self.bounded_length(MAX_COLLECTION_ITEMS, "collection-item-count")
    }

    fn bounded_length(
        &mut self,
        maximum: u64,
        limit: &'static str,
    ) -> Result<usize, CampaignCodecError> {
        let length = self.u64()?;
        if length > maximum {
            return Err(CampaignCodecError::LimitExceeded { limit });
        }
        usize::try_from(length).map_err(|_| CampaignCodecError::LimitExceeded { limit })
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], CampaignCodecError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(CampaignCodecError::Truncated)?;
        let bytes = self
            .bytes
            .get(self.cursor..end)
            .ok_or(CampaignCodecError::Truncated)?;
        self.cursor = end;
        Ok(bytes)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], CampaignCodecError> {
        self.take(N)?
            .try_into()
            .map_err(|_| CampaignCodecError::Truncated)
    }
}
