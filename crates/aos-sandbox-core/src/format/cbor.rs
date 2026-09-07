//! Allocation-bounded deterministic CBOR primitives.

use std::cmp::Ordering;

/// Absolute and caller-selectable limits applied before decoding allocations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodeLimits {
    /// Maximum total encoded object bytes.
    pub maximum_bytes: usize,
    /// Maximum elements claimed by any one array or map.
    pub maximum_collection_items: usize,
    /// Maximum aggregate values visited across the object.
    pub maximum_total_items: usize,
    /// Maximum byte-string length.
    pub maximum_byte_string_bytes: usize,
    /// Maximum UTF-8 text-string byte length.
    pub maximum_text_bytes: usize,
    /// Maximum recursively nested array/map depth.
    pub maximum_depth: usize,
}

impl Default for DecodeLimits {
    fn default() -> Self {
        Self {
            maximum_bytes: 64 * 1024 * 1024,
            maximum_collection_items: 1_048_576,
            maximum_total_items: 4_194_304,
            maximum_byte_string_bytes: 16 * 1024 * 1024,
            maximum_text_bytes: 1_048_576,
            maximum_depth: 4_096,
        }
    }
}

/// Reports a deterministic-CBOR profile or decoder-limit violation.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CanonicalCborError {
    /// The encoded object exceeds the caller's total-byte ceiling.
    #[error("CBOR object exceeds the maximum encoded byte length")]
    ObjectTooLarge,
    /// The input ends before the declared item is complete.
    #[error("truncated CBOR item at byte offset {offset}")]
    Truncated {
        /// Offset at which another byte was required.
        offset: usize,
    },
    /// An integer or length uses more bytes than its value requires.
    #[error("non-shortest CBOR argument at byte offset {offset}")]
    NonShortestArgument {
        /// Offset of the item's initial byte.
        offset: usize,
    },
    /// The profile forbids indefinite arrays, maps, text, and byte strings.
    #[error("indefinite CBOR item at byte offset {offset}")]
    IndefiniteItem {
        /// Offset of the item's initial byte.
        offset: usize,
    },
    /// The profile forbids CBOR tags.
    #[error("CBOR tag at byte offset {offset}")]
    TagNotAllowed {
        /// Offset of the item's initial byte.
        offset: usize,
    },
    /// The profile forbids floating point and unsupported simple values.
    #[error("unsupported CBOR simple or floating-point value at byte offset {offset}")]
    UnsupportedSimple {
        /// Offset of the item's initial byte.
        offset: usize,
    },
    /// A text item is not valid UTF-8.
    #[error("invalid UTF-8 CBOR text at byte offset {offset}")]
    InvalidUtf8 {
        /// Offset of the text item's initial byte.
        offset: usize,
    },
    /// One byte or text string exceeds its caller-selected bound.
    #[error("CBOR string length exceeds its decoder limit at byte offset {offset}")]
    StringTooLarge {
        /// Offset of the string item's initial byte.
        offset: usize,
    },
    /// One collection claims too many members before allocation.
    #[error("CBOR collection length exceeds its decoder limit at byte offset {offset}")]
    CollectionTooLarge {
        /// Offset of the collection item's initial byte.
        offset: usize,
    },
    /// Aggregate object work exceeds its item budget.
    #[error("CBOR object exceeds its aggregate item budget")]
    ItemBudgetExceeded,
    /// Recursive nesting exceeds the caller's depth ceiling.
    #[error("CBOR nesting exceeds its decoder depth limit")]
    NestingTooDeep,
    /// Map keys are not in RFC 8949 length-first deterministic order.
    #[error("CBOR map keys are not in deterministic order at byte offset {offset}")]
    MapKeyOrder {
        /// Offset of the non-increasing key.
        offset: usize,
    },
    /// A map repeats an exactly encoded key.
    #[error("duplicate CBOR map key at byte offset {offset}")]
    DuplicateMapKey {
        /// Offset of the duplicate key.
        offset: usize,
    },
    /// More than one top-level item or trailing bytes follow the object.
    #[error("trailing bytes begin at byte offset {offset}")]
    TrailingBytes {
        /// Offset after the complete top-level item.
        offset: usize,
    },
    /// A schema decoder encountered another CBOR major type.
    #[error("expected {expected} at byte offset {offset}")]
    UnexpectedType {
        /// Human-readable expected schema type.
        expected: &'static str,
        /// Offset of the mismatched item.
        offset: usize,
    },
    /// A fixed schema array has another element count.
    #[error("expected CBOR array length {expected}, found {actual} at byte offset {offset}")]
    ArrayLength {
        /// Required fixed array length.
        expected: usize,
        /// Encoded array length.
        actual: usize,
        /// Offset of the array.
        offset: usize,
    },
    /// A set-valued array is not strictly ordered by complete encoded item.
    #[error("CBOR set items are not in canonical order at byte offset {offset}")]
    SetOrder {
        /// Offset of the duplicate or non-increasing item.
        offset: usize,
    },
    /// A decoded integer cannot fit the schema's signed range.
    #[error("CBOR integer is outside the schema range at byte offset {offset}")]
    IntegerOutOfRange {
        /// Offset of the integer.
        offset: usize,
    },
    /// A schema version or closed discriminant is not registered.
    #[error("unknown {registry} value {value} at byte offset {offset}")]
    UnknownRegistryValue {
        /// Closed registry name.
        registry: &'static str,
        /// Unknown numeric value.
        value: u64,
        /// Offset of the value.
        offset: usize,
    },
    /// A decoded value violates a cross-field semantic invariant.
    #[error("invalid {object} semantics: {message}")]
    InvalidSemantics {
        /// Portable object or nested value name.
        object: &'static str,
        /// Stable diagnostic message.
        message: String,
    },
}

/// Validates one complete value under the deterministic CBOR profile.
///
/// This pass performs no allocation proportional to claimed string or
/// collection lengths. Schema decoding should run only after it succeeds.
///
/// # Errors
///
/// Returns [`CanonicalCborError`] for any forbidden encoding, noncanonical map,
/// trailing bytes, truncation, or selected resource-limit violation.
pub fn validate_canonical_cbor(
    bytes: &[u8],
    limits: DecodeLimits,
) -> Result<(), CanonicalCborError> {
    if bytes.len() > limits.maximum_bytes {
        return Err(CanonicalCborError::ObjectTooLarge);
    }
    let mut decoder = Decoder::new_prevalidated_size(bytes, limits);
    decoder.validate_item(0)?;
    decoder.finish()
}

#[derive(Clone, Copy)]
struct Head {
    major: u8,
    argument: u64,
    offset: usize,
}

/// Builds exact deterministic CBOR values for schema encoders.
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

    pub(crate) fn array(&mut self, length: usize) {
        self.head(4, length as u64);
    }

    pub(crate) fn bytes(&mut self, value: &[u8]) {
        self.head(2, value.len() as u64);
        self.bytes.extend_from_slice(value);
    }

    pub(crate) fn text(&mut self, value: &str) {
        self.head(3, value.len() as u64);
        self.bytes.extend_from_slice(value.as_bytes());
    }

    pub(crate) fn unsigned(&mut self, value: u64) {
        self.head(0, value);
    }

    pub(crate) fn signed(&mut self, value: i64) {
        if value >= 0 {
            self.unsigned(value as u64);
        } else {
            self.head(1, (-1_i128 - i128::from(value)) as u64);
        }
    }

    pub(crate) fn boolean(&mut self, value: bool) {
        self.bytes.push(if value { 0xf5 } else { 0xf4 });
    }

    pub(crate) fn null(&mut self) {
        self.bytes.push(0xf6);
    }

    pub(crate) fn raw(&mut self, canonical_item: &[u8]) {
        self.bytes.extend_from_slice(canonical_item);
    }

    fn head(&mut self, major: u8, argument: u64) {
        let prefix = major << 5;
        match argument {
            0..=23 => self.bytes.push(prefix | argument as u8),
            24..=0xff => self.bytes.extend_from_slice(&[prefix | 24, argument as u8]),
            0x100..=0xffff => {
                self.bytes.push(prefix | 25);
                self.bytes
                    .extend_from_slice(&(argument as u16).to_be_bytes());
            }
            0x1_0000..=0xffff_ffff => {
                self.bytes.push(prefix | 26);
                self.bytes
                    .extend_from_slice(&(argument as u32).to_be_bytes());
            }
            _ => {
                self.bytes.push(prefix | 27);
                self.bytes.extend_from_slice(&argument.to_be_bytes());
            }
        }
    }
}

/// Reads already profile-validated bytes through schema-specific expectations.
pub(crate) struct Decoder<'a> {
    bytes: &'a [u8],
    position: usize,
    limits: DecodeLimits,
    remaining_items: usize,
}

impl<'a> Decoder<'a> {
    pub(crate) fn new(bytes: &'a [u8], limits: DecodeLimits) -> Result<Self, CanonicalCborError> {
        validate_canonical_cbor(bytes, limits)?;
        Ok(Self::new_prevalidated_size(bytes, limits))
    }

    fn new_prevalidated_size(bytes: &'a [u8], limits: DecodeLimits) -> Self {
        Self {
            bytes,
            position: 0,
            limits,
            remaining_items: limits.maximum_total_items,
        }
    }

    pub(crate) const fn position(&self) -> usize {
        self.position
    }

    pub(crate) fn encoded_range(&self, start: usize, end: usize) -> &'a [u8] {
        &self.bytes[start..end]
    }

    pub(crate) fn finish(&self) -> Result<(), CanonicalCborError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(CanonicalCborError::TrailingBytes {
                offset: self.position,
            })
        }
    }

    pub(crate) fn array(&mut self, expected: usize) -> Result<(), CanonicalCborError> {
        let head = self.read_head()?;
        if head.major != 4 {
            return Err(unexpected("array", head.offset));
        }
        let actual = self.collection_length(head)?;
        if actual == expected {
            Ok(())
        } else {
            Err(CanonicalCborError::ArrayLength {
                expected,
                actual,
                offset: head.offset,
            })
        }
    }

    pub(crate) fn array_len(&mut self) -> Result<usize, CanonicalCborError> {
        let head = self.read_head()?;
        if head.major != 4 {
            return Err(unexpected("array", head.offset));
        }
        self.collection_length(head)
    }

    pub(crate) fn bytes(&mut self, maximum: usize) -> Result<&'a [u8], CanonicalCborError> {
        let head = self.read_head()?;
        if head.major != 2 {
            return Err(unexpected("byte string", head.offset));
        }
        let length =
            self.string_length(head, maximum.min(self.limits.maximum_byte_string_bytes))?;
        self.take(length)
    }

    pub(crate) fn text(&mut self, maximum: usize) -> Result<&'a str, CanonicalCborError> {
        let head = self.read_head()?;
        if head.major != 3 {
            return Err(unexpected("text string", head.offset));
        }
        let length = self.string_length(head, maximum.min(self.limits.maximum_text_bytes))?;
        let bytes = self.take(length)?;
        std::str::from_utf8(bytes).map_err(|_| CanonicalCborError::InvalidUtf8 {
            offset: head.offset,
        })
    }

    pub(crate) fn unsigned(&mut self) -> Result<u64, CanonicalCborError> {
        let head = self.read_head()?;
        if head.major == 0 {
            Ok(head.argument)
        } else {
            Err(unexpected("unsigned integer", head.offset))
        }
    }

    pub(crate) fn signed(&mut self) -> Result<i64, CanonicalCborError> {
        let head = self.read_head()?;
        match head.major {
            0 => i64::try_from(head.argument).map_err(|_| CanonicalCborError::IntegerOutOfRange {
                offset: head.offset,
            }),
            1 if head.argument <= i64::MAX as u64 => Ok(-1 - head.argument as i64),
            1 => Err(CanonicalCborError::IntegerOutOfRange {
                offset: head.offset,
            }),
            _ => Err(unexpected("signed integer", head.offset)),
        }
    }

    pub(crate) fn boolean(&mut self) -> Result<bool, CanonicalCborError> {
        let offset = self.position;
        let byte = self.take(1)?[0];
        match byte {
            0xf4 => Ok(false),
            0xf5 => Ok(true),
            _ => Err(unexpected("boolean", offset)),
        }
    }

    pub(crate) fn nullable<T>(
        &mut self,
        decode: impl FnOnce(&mut Self) -> Result<T, CanonicalCborError>,
    ) -> Result<Option<T>, CanonicalCborError> {
        if self.bytes.get(self.position) == Some(&0xf6) {
            self.position += 1;
            self.charge_item()?;
            Ok(None)
        } else {
            decode(self).map(Some)
        }
    }

    pub(crate) fn closed(
        &mut self,
        registry: &'static str,
        maximum: u64,
    ) -> Result<u64, CanonicalCborError> {
        let offset = self.position;
        let value = self.unsigned()?;
        if value <= maximum {
            Ok(value)
        } else {
            Err(CanonicalCborError::UnknownRegistryValue {
                registry,
                value,
                offset,
            })
        }
    }

    pub(crate) fn exact(
        &mut self,
        registry: &'static str,
        expected: u64,
    ) -> Result<(), CanonicalCborError> {
        let offset = self.position;
        let value = self.unsigned()?;
        if value == expected {
            Ok(())
        } else {
            Err(CanonicalCborError::UnknownRegistryValue {
                registry,
                value,
                offset,
            })
        }
    }

    fn validate_item(&mut self, depth: usize) -> Result<(), CanonicalCborError> {
        if depth > self.limits.maximum_depth {
            return Err(CanonicalCborError::NestingTooDeep);
        }
        let head = self.read_head()?;
        match head.major {
            0 | 1 => Ok(()),
            2 => {
                let length = self.string_length(head, self.limits.maximum_byte_string_bytes)?;
                self.take(length).map(|_| ())
            }
            3 => {
                let length = self.string_length(head, self.limits.maximum_text_bytes)?;
                let bytes = self.take(length)?;
                std::str::from_utf8(bytes).map(|_| ()).map_err(|_| {
                    CanonicalCborError::InvalidUtf8 {
                        offset: head.offset,
                    }
                })
            }
            4 => {
                let length = self.collection_length(head)?;
                for _ in 0..length {
                    self.validate_item(depth + 1)?;
                }
                Ok(())
            }
            5 => self.validate_map(head, depth),
            6 => Err(CanonicalCborError::TagNotAllowed {
                offset: head.offset,
            }),
            7 if head.argument <= 22 && matches!(self.bytes[head.offset], 0xf4..=0xf6) => Ok(()),
            7 => Err(CanonicalCborError::UnsupportedSimple {
                offset: head.offset,
            }),
            _ => unreachable!("CBOR major type is three bits"),
        }
    }

    fn validate_map(&mut self, head: Head, depth: usize) -> Result<(), CanonicalCborError> {
        let length = self.collection_length(head)?;
        let mut prior_key: Option<(usize, usize)> = None;
        for _ in 0..length {
            let key_start = self.position;
            self.validate_item(depth + 1)?;
            let key_end = self.position;
            if let Some((prior_start, prior_end)) = prior_key {
                match canonical_key_cmp(
                    &self.bytes[prior_start..prior_end],
                    &self.bytes[key_start..key_end],
                ) {
                    Ordering::Equal => {
                        return Err(CanonicalCborError::DuplicateMapKey { offset: key_start });
                    }
                    Ordering::Greater => {
                        return Err(CanonicalCborError::MapKeyOrder { offset: key_start });
                    }
                    Ordering::Less => {}
                }
            }
            prior_key = Some((key_start, key_end));
            self.validate_item(depth + 1)?;
        }
        Ok(())
    }

    fn read_head(&mut self) -> Result<Head, CanonicalCborError> {
        self.charge_item()?;
        let offset = self.position;
        let initial = self.take(1)?[0];
        let major = initial >> 5;
        let additional = initial & 0x1f;
        if major == 7 {
            return match additional {
                value @ 20..=22 => Ok(Head {
                    major,
                    argument: u64::from(value),
                    offset,
                }),
                24 => {
                    self.take(1)?;
                    Err(CanonicalCborError::UnsupportedSimple { offset })
                }
                25 => {
                    self.take(2)?;
                    Err(CanonicalCborError::UnsupportedSimple { offset })
                }
                26 => {
                    self.take(4)?;
                    Err(CanonicalCborError::UnsupportedSimple { offset })
                }
                27 => {
                    self.take(8)?;
                    Err(CanonicalCborError::UnsupportedSimple { offset })
                }
                31 => Err(CanonicalCborError::IndefiniteItem { offset }),
                _ => Err(CanonicalCborError::UnsupportedSimple { offset }),
            };
        }
        let argument = match additional {
            value @ 0..=23 => u64::from(value),
            24 => {
                let value = u64::from(self.take(1)?[0]);
                if value < 24 {
                    return Err(CanonicalCborError::NonShortestArgument { offset });
                }
                value
            }
            25 => {
                let value = u64::from(u16::from_be_bytes(self.take_array()?));
                if value <= u8::MAX.into() {
                    return Err(CanonicalCborError::NonShortestArgument { offset });
                }
                value
            }
            26 => {
                let value = u64::from(u32::from_be_bytes(self.take_array()?));
                if value <= u16::MAX.into() {
                    return Err(CanonicalCborError::NonShortestArgument { offset });
                }
                value
            }
            27 => {
                let value = u64::from_be_bytes(self.take_array()?);
                if value <= u32::MAX.into() {
                    return Err(CanonicalCborError::NonShortestArgument { offset });
                }
                value
            }
            31 => return Err(CanonicalCborError::IndefiniteItem { offset }),
            _ => return Err(CanonicalCborError::UnsupportedSimple { offset }),
        };
        Ok(Head {
            major,
            argument,
            offset,
        })
    }

    fn collection_length(&self, head: Head) -> Result<usize, CanonicalCborError> {
        let length =
            usize::try_from(head.argument).map_err(|_| CanonicalCborError::CollectionTooLarge {
                offset: head.offset,
            })?;
        if length <= self.limits.maximum_collection_items {
            Ok(length)
        } else {
            Err(CanonicalCborError::CollectionTooLarge {
                offset: head.offset,
            })
        }
    }

    fn string_length(&self, head: Head, maximum: usize) -> Result<usize, CanonicalCborError> {
        let length =
            usize::try_from(head.argument).map_err(|_| CanonicalCborError::StringTooLarge {
                offset: head.offset,
            })?;
        if length <= maximum {
            Ok(length)
        } else {
            Err(CanonicalCborError::StringTooLarge {
                offset: head.offset,
            })
        }
    }

    fn charge_item(&mut self) -> Result<(), CanonicalCborError> {
        self.remaining_items = self
            .remaining_items
            .checked_sub(1)
            .ok_or(CanonicalCborError::ItemBudgetExceeded)?;
        Ok(())
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], CanonicalCborError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(CanonicalCborError::Truncated {
                offset: self.position,
            })?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(CanonicalCborError::Truncated {
                offset: self.position,
            })?;
        self.position = end;
        Ok(value)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], CanonicalCborError> {
        self.take(N)?
            .try_into()
            .map_err(|_| CanonicalCborError::Truncated {
                offset: self.position,
            })
    }
}

fn canonical_key_cmp(left: &[u8], right: &[u8]) -> Ordering {
    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
}

fn unexpected(expected: &'static str, offset: usize) -> CanonicalCborError {
    CanonicalCborError::UnexpectedType { expected, offset }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoder_uses_shortest_integer_widths() {
        let mut encoder = Encoder::new();
        encoder.array(5);
        encoder.unsigned(23);
        encoder.unsigned(24);
        encoder.unsigned(255);
        encoder.unsigned(256);
        encoder.signed(-25);

        assert_eq!(hex::encode(encoder.finish()), "8517181818ff1901003818");
    }

    #[test]
    fn non_shortest_integers_fail() {
        assert!(matches!(
            validate_canonical_cbor(&[0x18, 0x17], DecodeLimits::default()),
            Err(CanonicalCborError::NonShortestArgument { .. })
        ));
    }

    #[test]
    fn indefinite_values_and_tags_fail() {
        assert!(matches!(
            validate_canonical_cbor(&[0x9f, 0xff], DecodeLimits::default()),
            Err(CanonicalCborError::IndefiniteItem { .. })
        ));
        assert!(matches!(
            validate_canonical_cbor(&[0xc0, 0x00], DecodeLimits::default()),
            Err(CanonicalCborError::TagNotAllowed { .. })
        ));
    }

    #[test]
    fn floating_point_and_undefined_fail() {
        assert!(matches!(
            validate_canonical_cbor(&[0xf9, 0x00, 0x00], DecodeLimits::default()),
            Err(CanonicalCborError::UnsupportedSimple { .. })
        ));
        assert!(matches!(
            validate_canonical_cbor(&[0xf7], DecodeLimits::default()),
            Err(CanonicalCborError::UnsupportedSimple { .. })
        ));
    }

    #[test]
    fn duplicate_and_unsorted_map_keys_fail() {
        let duplicate = [0xa2, 0x00, 0x01, 0x00, 0x02];
        assert!(matches!(
            validate_canonical_cbor(&duplicate, DecodeLimits::default()),
            Err(CanonicalCborError::DuplicateMapKey { .. })
        ));

        let descending = [0xa2, 0x01, 0x01, 0x00, 0x02];
        assert!(matches!(
            validate_canonical_cbor(&descending, DecodeLimits::default()),
            Err(CanonicalCborError::MapKeyOrder { .. })
        ));
    }

    #[test]
    fn allocation_claims_fail_before_payload_read() {
        let limits = DecodeLimits {
            maximum_collection_items: 2,
            ..DecodeLimits::default()
        };
        assert!(matches!(
            validate_canonical_cbor(&[0x83], limits),
            Err(CanonicalCborError::CollectionTooLarge { .. })
        ));
    }

    #[test]
    fn resource_and_text_negative_vectors_fail_closed() {
        let too_large = DecodeLimits {
            maximum_bytes: 0,
            ..DecodeLimits::default()
        };
        assert_eq!(
            validate_canonical_cbor(&[0], too_large),
            Err(CanonicalCborError::ObjectTooLarge)
        );

        let short_string = DecodeLimits {
            maximum_byte_string_bytes: 1,
            ..DecodeLimits::default()
        };
        assert!(matches!(
            validate_canonical_cbor(&[0x42, 0, 0], short_string),
            Err(CanonicalCborError::StringTooLarge { .. })
        ));
        assert!(matches!(
            validate_canonical_cbor(&[0x61, 0xff], DecodeLimits::default()),
            Err(CanonicalCborError::InvalidUtf8 { .. })
        ));

        let shallow = DecodeLimits {
            maximum_depth: 1,
            ..DecodeLimits::default()
        };
        assert_eq!(
            validate_canonical_cbor(&[0x81, 0x81, 0], shallow),
            Err(CanonicalCborError::NestingTooDeep)
        );

        let few_items = DecodeLimits {
            maximum_total_items: 2,
            ..DecodeLimits::default()
        };
        assert_eq!(
            validate_canonical_cbor(&[0x82, 0, 0], few_items),
            Err(CanonicalCborError::ItemBudgetExceeded)
        );
        assert!(matches!(
            validate_canonical_cbor(&[0x1a, 0], DecodeLimits::default()),
            Err(CanonicalCborError::Truncated { .. })
        ));
    }

    #[test]
    fn schema_primitives_round_trip_without_serde() {
        let mut encoder = Encoder::new();
        encoder.array(7);
        encoder.bytes(&[0xff, 0]);
        encoder.text("text");
        encoder.boolean(true);
        encoder.null();
        encoder.signed(i64::MIN);
        encoder.signed(i64::MAX);
        encoder.unsigned(u64::MAX);
        let encoded = encoder.finish();

        let mut decoder = Decoder::new(&encoded, DecodeLimits::default())
            .unwrap_or_else(|error| panic!("test decoder failed: {error}"));
        assert_eq!(
            decoder
                .array_len()
                .unwrap_or_else(|error| panic!("test array failed: {error}")),
            7
        );
        assert_eq!(
            decoder
                .bytes(2)
                .unwrap_or_else(|error| panic!("test bytes failed: {error}")),
            &[0xff, 0]
        );
        assert_eq!(
            decoder
                .text(4)
                .unwrap_or_else(|error| panic!("test text failed: {error}")),
            "text"
        );
        assert!(
            decoder
                .boolean()
                .unwrap_or_else(|error| panic!("test bool failed: {error}"))
        );
        assert_eq!(
            decoder
                .nullable(|value| value.unsigned())
                .unwrap_or_else(|error| panic!("test null failed: {error}")),
            None
        );
        assert_eq!(
            decoder
                .signed()
                .unwrap_or_else(|error| panic!("test integer failed: {error}")),
            i64::MIN
        );
        assert_eq!(
            decoder
                .signed()
                .unwrap_or_else(|error| panic!("test integer failed: {error}")),
            i64::MAX
        );
        assert_eq!(
            decoder
                .unsigned()
                .unwrap_or_else(|error| panic!("test integer failed: {error}")),
            u64::MAX
        );
        decoder
            .finish()
            .unwrap_or_else(|error| panic!("test trailing check failed: {error}"));

        let mut fixed = Decoder::new(&[0x81, 0x00], DecodeLimits::default())
            .unwrap_or_else(|error| panic!("test decoder failed: {error}"));
        fixed
            .array(1)
            .unwrap_or_else(|error| panic!("test fixed array failed: {error}"));
        assert_eq!(
            fixed
                .closed("test", 0)
                .unwrap_or_else(|error| panic!("test registry failed: {error}")),
            0
        );
    }

    #[test]
    fn trailing_items_fail() {
        assert!(matches!(
            validate_canonical_cbor(&[0x00, 0x01], DecodeLimits::default()),
            Err(CanonicalCborError::TrailingBytes { offset: 1 })
        ));
    }
}
