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
    /// Original resource ownership refused an artifact allocation.
    #[error(transparent)]
    DecodeAdmission(#[from] crucible_cas::owned_decode::DecodeAdmissionError),
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
        decoder.set_bounded_by(
            MAX_COLLECTION_ITEMS as usize,
            "collection-item-count",
            T::decode,
        )
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
        decoder.map_bounded_by(
            MAX_COLLECTION_ITEMS as usize,
            "collection-item-count",
            K::decode,
            V::decode,
        )
    }
}

pub(crate) fn encode<T: Canonical>(value: &T) -> Vec<u8> {
    let mut counter = Encoder::counting(usize::MAX);
    value.encode(&mut counter);
    let length = counter.counted.unwrap_or(0);
    let mut encoder = match Encoder::bounded(length) {
        Ok(encoder) => encoder,
        Err(CampaignCodecError::DecodeAdmission(error)) => {
            if let Some(budget) = crucible_cas::owned_decode::current_budget() {
                budget.record_failure(error);
            }
            return Vec::new();
        }
        Err(_) => return Vec::new(),
    };
    value.encode(&mut encoder);
    encoder.finish()
}

pub(crate) fn encoded_length<T: Canonical>(value: &T) -> Result<usize, CampaignCodecError> {
    encoded_length_with(|encoder| value.encode(encoder))
}

pub(crate) fn encoded_length_with(
    encode: impl FnOnce(&mut Encoder),
) -> Result<usize, CampaignCodecError> {
    let mut counter = Encoder::counting(MAX_CANONICAL_BYTES);
    encode(&mut counter);
    if counter.exceeded {
        return Err(CampaignCodecError::LimitExceeded {
            limit: "canonical-byte-count",
        });
    }
    counter.counted.ok_or(CampaignCodecError::InvalidValue {
        reason: "canonical length counter lost its counting state",
    })
}

/// Reconstructs an owned canonical value under the original allocation account.
pub(crate) fn admitted_clone<T: Canonical>(value: &T) -> Result<T, CampaignCodecError> {
    let bytes = encode(value);
    if let Some(budget) = crucible_cas::owned_decode::current_budget() {
        budget.check()?;
    }
    decode(&bytes)
}

pub(crate) fn decode<T: Canonical>(bytes: &[u8]) -> Result<T, CampaignCodecError> {
    decode_bounded(bytes, MAX_CANONICAL_BYTES, "canonical-byte-count")
}

pub(crate) fn decode_bounded<T: Canonical>(
    bytes: &[u8],
    maximum: usize,
    limit: &'static str,
) -> Result<T, CampaignCodecError> {
    if bytes.len() > maximum {
        return Err(CampaignCodecError::LimitExceeded { limit });
    }
    let mut decoder = Decoder::new(bytes);
    let value = T::decode(&mut decoder)?;
    decoder.finish()?;
    // Authentication bytes close here; the decoded value keeps its original
    // outer account while the temporary image borrows a child of that account.
    let canonical_budget = crucible_cas::owned_decode::current_child_budget()?;
    {
        let _scope = canonical_budget.as_ref().map(|budget| budget.enter());
        let mut canonical = Encoder::bounded(bytes.len())?;
        value.encode(&mut canonical);
        if let Some(budget) = &canonical_budget {
            budget.check()?;
        }
        if canonical.exceeded || canonical.finish() != bytes {
            return Err(CampaignCodecError::NonCanonical);
        }
    }
    if let Some(budget) = crucible_cas::owned_decode::current_budget() {
        budget.check()?;
    }
    Ok(value)
}

pub(crate) fn validate_nfc(value: &str) -> Result<(), CampaignCodecError> {
    // Every ASCII string is already NFC; avoid the Unicode iterator on this path.
    if value.is_ascii() {
        return Ok(());
    }
    // Count canonical decomposition without allocating. The iterator owns
    // decomposition pairs, recomposition characters and stable-sort scratch;
    // four complete slots per scalar cover minimum/growth overlap.
    let mut decomposed = 4_usize;
    for character in value.chars() {
        let mut count = 0_usize;
        unicode_normalization::char::decompose_canonical(character, |_| count += 1);
        decomposed = decomposed
            .checked_add(count)
            .ok_or(CampaignCodecError::LimitExceeded {
                limit: "unicode-normalization-allocation",
            })?;
    }
    let scratch = decomposed
        .checked_mul(4 * (std::mem::size_of::<(u8, char)>() + std::mem::size_of::<char>()))
        .ok_or(CampaignCodecError::LimitExceeded {
            limit: "unicode-normalization-allocation",
        })?;
    crucible_cas::owned_decode::charge_array::<u8>(scratch)?;
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
    let mut encoder = Encoder::counting(maximum);
    value.encode(&mut encoder);
    if !encoder.exceeded {
        Ok(())
    } else {
        Err(CampaignCodecError::LimitExceeded { limit })
    }
}

pub(crate) struct Encoder {
    bytes: Vec<u8>,
    maximum: Option<usize>,
    exceeded: bool,
    counted: Option<usize>,
}

impl Encoder {
    pub(crate) fn new() -> Self {
        Self {
            bytes: Vec::new(),
            maximum: None,
            exceeded: false,
            counted: None,
        }
    }

    fn bounded(maximum: usize) -> Result<Self, CampaignCodecError> {
        crucible_cas::owned_decode::charge_array::<u8>(maximum)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(maximum).map_err(|source| {
            CampaignCodecError::DecodeAdmission(
                crucible_cas::owned_decode::DecodeAdmissionError::new(source),
            )
        })?;
        Ok(Self {
            bytes,
            maximum: Some(maximum),
            exceeded: false,
            counted: None,
        })
    }

    fn counting(maximum: usize) -> Self {
        Self {
            bytes: Vec::new(),
            maximum: Some(maximum),
            exceeded: false,
            counted: Some(0),
        }
    }

    pub(crate) fn finish(self) -> Vec<u8> {
        if self.exceeded {
            Vec::new()
        } else {
            self.bytes
        }
    }

    pub(crate) fn u8(&mut self, value: u8) {
        self.fixed(&[value]);
    }

    pub(crate) fn bool(&mut self, value: bool) {
        self.u8(u8::from(value));
    }

    pub(crate) fn u32(&mut self, value: u32) {
        self.fixed(&value.to_be_bytes());
    }

    pub(crate) fn u64(&mut self, value: u64) {
        self.fixed(&value.to_be_bytes());
    }

    pub(crate) fn i64(&mut self, value: i64) {
        self.fixed(&value.to_be_bytes());
    }

    pub(crate) fn u128(&mut self, value: u128) {
        self.fixed(&value.to_be_bytes());
    }

    pub(crate) fn fixed(&mut self, value: &[u8]) {
        if let Some(counted) = &mut self.counted {
            if let Some(total) = counted
                .checked_add(value.len())
                .filter(|total| self.maximum.is_none_or(|maximum| *total <= maximum))
            {
                *counted = total;
            } else {
                self.exceeded = true;
            }
            return;
        }
        if self.exceeded
            || self
                .maximum
                .is_some_and(|maximum| value.len() > maximum.saturating_sub(self.bytes.len()))
        {
            self.exceeded = true;
            return;
        }
        if self.maximum.is_none()
            && value.len() > self.bytes.capacity().saturating_sub(self.bytes.len())
        {
            // Infallible public canonical encoders cannot return an operational
            // error. The original account records refusal; the owning fallible
            // decode checks it before publication or guest release.
            let requested = self.bytes.len().checked_add(value.len());
            let admitted = requested
                .and_then(|required| required.checked_mul(2).map(|bytes| (required, bytes)))
                .is_some_and(|(required, bytes)| {
                    if crucible_cas::owned_decode::charge_array::<u8>(bytes.max(8)).is_err() {
                        return false;
                    }
                    match self
                        .bytes
                        .try_reserve_exact(required.saturating_sub(self.bytes.len()))
                    {
                        Ok(()) => true,
                        Err(source) => {
                            if let Some(budget) = crucible_cas::owned_decode::current_budget() {
                                budget.record_failure(
                                    crucible_cas::owned_decode::DecodeAdmissionError::new(source),
                                );
                            }
                            false
                        }
                    }
                });
            if !admitted {
                self.exceeded = true;
                return;
            }
        }
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
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    pub(crate) fn finish(self) -> Result<(), CampaignCodecError> {
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
        validate_nfc(value)?;
        crucible_cas::owned_decode::charge_array::<u8>(length)?;
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
        crucible_cas::owned_decode::charge_array::<T>(length)?;
        let mut values = Vec::new();
        values.try_reserve_exact(length).map_err(|source| {
            CampaignCodecError::DecodeAdmission(
                crucible_cas::owned_decode::DecodeAdmissionError::new(source),
            )
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
        crucible_cas::owned_decode::charge_array::<T>(length)?;
        let mut values = Vec::new();
        values.try_reserve_exact(length).map_err(|source| {
            CampaignCodecError::DecodeAdmission(
                crucible_cas::owned_decode::DecodeAdmissionError::new(source),
            )
        })?;
        for _ in 0..length {
            values.push(decode_value(self)?);
        }
        Ok(values)
    }

    pub(crate) fn byte_sequence_bounded_charged(
        &mut self,
        maximum: usize,
        item_limit: &'static str,
        aggregate_bytes: &mut usize,
        maximum_aggregate_bytes: usize,
        aggregate_limit: &'static str,
    ) -> Result<Vec<u8>, CampaignCodecError> {
        let length = self.bounded_length(maximum as u64, item_limit)?;
        let next_aggregate =
            aggregate_bytes
                .checked_add(length)
                .ok_or(CampaignCodecError::LimitExceeded {
                    limit: aggregate_limit,
                })?;
        if next_aggregate > maximum_aggregate_bytes {
            return Err(CampaignCodecError::LimitExceeded {
                limit: aggregate_limit,
            });
        }

        *aggregate_bytes = next_aggregate;
        crucible_cas::owned_decode::charge_array::<u8>(length)?;
        Ok(self.take(length)?.to_vec())
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
            crucible_cas::owned_decode::charge_btree_set_entry::<T>()?;
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
            crucible_cas::owned_decode::charge_btree_entry::<K, V>()?;
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

#[cfg(test)]
mod tests {
    use crucible_cas::owned_decode::{DecodeAdmissionError, DecodeBudget, DecodeResourceAuthority};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Authority(Arc<AtomicU64>);
    struct Receipt {
        used: Arc<AtomicU64>,
        bytes: u64,
    }

    impl Drop for Receipt {
        fn drop(&mut self) {
            self.used.fetch_sub(self.bytes, Ordering::SeqCst);
        }
    }

    impl DecodeResourceAuthority for Authority {
        fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
            if self.0.load(Ordering::SeqCst) > 4096 {
                return Err(DecodeAdmissionError::new(std::io::Error::other(
                    "original component accounting is invalid",
                )));
            }
            Ok(())
        }

        fn reserve(
            &self,
            bytes: u64,
        ) -> Result<crucible_cas::owned_decode::ResourceLoan, DecodeAdmissionError> {
            self.0
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                    used.checked_add(bytes).filter(|used| *used <= 4096)
                })
                .map_err(|_| {
                    DecodeAdmissionError::new(std::io::Error::other(
                        "finite fixture metadata exhausted",
                    ))
                })?;
            Ok(crucible_cas::owned_decode::ResourceLoan::new(Receipt {
                used: self.0.clone(),
                bytes,
            }))
        }
    }

    #[test]
    fn typed_sequence_admission_precedes_every_item_decoder() -> Result<(), CampaignCodecError> {
        let authority = Arc::new(Authority(Arc::new(AtomicU64::new(0))));
        let budget = DecodeBudget::new(authority.clone(), 4096)?;
        let _scope = budget.enter();
        let bytes = 1024_u64.to_be_bytes();
        let mut visited = 0;
        let result =
            Decoder::new(&bytes).sequence_bounded::<u64>(1024, "test-sequence", |decoder| {
                visited += 1;
                decoder.u64()
            });
        assert!(matches!(
            result,
            Err(CampaignCodecError::DecodeAdmission(_))
        ));
        assert_eq!(visited, 0);
        assert!(budget.check().is_err());
        drop(_scope);
        drop(budget);
        assert_eq!(authority.0.load(Ordering::SeqCst), 0);
        Ok(())
    }

    #[test]
    fn infallible_canonical_refusal_cannot_become_a_successful_owned_decode()
    -> Result<(), CampaignCodecError> {
        let source = vec![0_u64; 1024];
        let ordinary = encode(&source);
        let authority = Arc::new(Authority(Arc::new(AtomicU64::new(0))));
        let budget = DecodeBudget::new(authority, 4096)?;
        let _scope = budget.enter();
        assert!(encode(&source).is_empty());
        assert!(budget.check().is_err());
        assert!(matches!(
            decode::<Vec<u64>>(&ordinary),
            Err(CampaignCodecError::DecodeAdmission(_))
        ));
        Ok(())
    }

    use super::*;

    #[test]
    fn repeated_scalar_authentication_releases_its_canonical_image()
    -> Result<(), CampaignCodecError> {
        let authority = Arc::new(Authority(Arc::new(AtomicU64::new(0))));
        let budget = DecodeBudget::new(authority.clone(), 4096)?;
        let _scope = budget.enter();
        let encoded = 42_u64.to_be_bytes();
        let retained = authority.0.load(Ordering::SeqCst);

        for _ in 0..2048 {
            assert_eq!(decode::<u64>(&encoded)?, 42);
            assert_eq!(authority.0.load(Ordering::SeqCst), retained);
        }

        // A returned owning value is different from authentication scratch:
        // its slots stay charged to the enclosing original account.
        let vector_bytes = [2_u64.to_be_bytes(), encoded, encoded].concat();
        let decoded = decode::<Vec<u64>>(&vector_bytes)?;
        assert_eq!(decoded, vec![42, 42]);
        let owning_charge = authority.0.load(Ordering::SeqCst);
        assert!(owning_charge > retained);
        assert_eq!(decode::<u64>(&encoded)?, 42);
        assert_eq!(authority.0.load(Ordering::SeqCst), owning_charge);

        drop(decoded);
        drop(_scope);
        drop(budget);
        assert_eq!(authority.0.load(Ordering::SeqCst), 0);
        Ok(())
    }

    #[test]
    fn ascii_strings_preserve_canonical_bytes() {
        let all_ascii: String = (0..=127).map(char::from).collect();
        for value in ["", "scenario-a", all_ascii.as_str()] {
            assert_eq!(validate_nfc(value), Ok(()));

            let bytes = encode(&value.to_owned());
            assert_eq!(&bytes[..8], &(value.len() as u64).to_be_bytes());
            assert_eq!(&bytes[8..], value.as_bytes());
            assert_eq!(decode::<String>(&bytes), Ok(value.to_owned()));
        }
    }

    #[test]
    fn unicode_strings_retain_normalization_validation() {
        for value in ["é", "가", "\u{0301}", "👩\u{200d}💻"] {
            assert_eq!(validate_nfc(value), Ok(()));
            let bytes = encode(&value.to_owned());
            assert_eq!(decode::<String>(&bytes), Ok(value.to_owned()));
        }

        for value in ["e\u{0301}", "\u{1100}\u{1161}", "\u{212b}"] {
            assert_eq!(validate_nfc(value), Err(CampaignCodecError::NonCanonical));
            let bytes = encode(&value.to_owned());
            assert_eq!(
                decode::<String>(&bytes),
                Err(CampaignCodecError::NonCanonical)
            );
        }
    }

    #[test]
    fn string_byte_limits_and_utf8_errors_keep_their_order() {
        let bytes = encode(&"é".to_owned());
        assert_eq!(
            Decoder::new(&bytes).string_bounded(2, "test-string"),
            Ok("é".to_owned())
        );
        assert_eq!(
            Decoder::new(&bytes).string_bounded(1, "test-string"),
            Err(CampaignCodecError::LimitExceeded {
                limit: "test-string"
            })
        );

        let mut invalid = Encoder::new();
        invalid.bytes(&[0xc0]);
        let invalid = invalid.finish();
        assert_eq!(
            Decoder::new(&invalid).string_bounded(1, "test-string"),
            Err(CampaignCodecError::InvalidUtf8)
        );
        assert_eq!(
            Decoder::new(&invalid).string_bounded(0, "test-string"),
            Err(CampaignCodecError::LimitExceeded {
                limit: "test-string"
            })
        );
        assert_eq!(
            decode::<String>(&invalid[..8]),
            Err(CampaignCodecError::Truncated)
        );
    }

    #[test]
    fn truncated_bounded_sequence_preserves_component_format_error() {
        let bytes = MAX_COLLECTION_ITEMS.to_be_bytes();
        let mut decoder = Decoder::new(&bytes);

        assert_eq!(
            decoder.sequence_bounded(MAX_COLLECTION_ITEMS as usize, "test-sequence", Decoder::u8),
            Err(CampaignCodecError::Truncated)
        );
    }
}
