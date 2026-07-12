//! Inline cached expression payload representation and codec helpers.

use super::*;
use crate::cache::hashing::CachedExpressionPayloadValueHash;

mod payload_cursor;

pub(in crate::cache::runtime) use self::payload_cursor::PayloadCursor;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum InlineValuePayload {
    Int(i64),
    Float(u64),
    Bool(bool),
    Null,
    ContextFreeString(Vec<u8>),
    ContextString {
        bytes: Vec<u8>,
        context: StringContext,
    },
    Path(Vec<u8>),
    ContextPath {
        bytes: Vec<u8>,
        context: StringContext,
    },
    EmptyList,
    List(Vec<InlineValuePayload>),
    EmptyAttrs,
    Attrs(Vec<AttrPayloadEntry>),
    SourceOrderedAttrs(Vec<AttrPayloadEntry>),
    PositionedAttrs(Vec<PositionedAttrPayloadEntry>),
    SourceOrderedPositionedAttrs(Vec<PositionedAttrPayloadEntry>),
    AttrRepr {
        repr: AttrSetReprKind,
        payload: Box<InlineValuePayload>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AttrPayloadEntry {
    pub(super) name: Vec<u8>,
    pub(super) value: InlineValuePayload,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PositionedAttrPayloadEntry {
    pub(super) name: Vec<u8>,
    pub(super) position: Option<AttrPosition>,
    pub(super) value: InlineValuePayload,
}

impl InlineValuePayload {
    pub(super) fn from_value(value: Value) -> Result<Self, ValueHashError> {
        value
            .validate_payload()
            .map_err(|source| ValueHashError::InvalidValue { source })?;
        match value.tag() {
            crate::value::ValueTag::Int => value
                .as_int()
                .map(Self::Int)
                .map_err(|source| ValueHashError::InvalidValue { source }),
            #[cfg(not(feature = "candidate_c_value"))]
            crate::value::ValueTag::Float => value
                .as_float()
                .map(f64::to_bits)
                .map(Self::Float)
                .map_err(|source| ValueHashError::InvalidValue { source }),
            // On the Candidate-C carrier a float is a boxed reservation cell, so
            // it has no context-free immediate form: it is not an inline payload
            // and the cache falls through to a full re-evaluation for it.
            #[cfg(feature = "candidate_c_value")]
            crate::value::ValueTag::Float => Err(ValueHashError::UnsupportedTag {
                tag: crate::value::ValueTag::Float,
            }),
            crate::value::ValueTag::Bool => value
                .as_bool()
                .map(Self::Bool)
                .map_err(|source| ValueHashError::InvalidValue { source }),
            crate::value::ValueTag::Null => {
                value
                    .as_null()
                    .map_err(|source| ValueHashError::InvalidValue { source })?;
                Ok(Self::Null)
            }
            tag => Err(ValueHashError::UnsupportedTag { tag }),
        }
    }

    pub(super) fn immediate_value(&self) -> Option<Value> {
        match self {
            #[cfg(not(feature = "candidate_c_value"))]
            Self::Int(value) => Some(Value::int(*value)),
            #[cfg(not(feature = "candidate_c_value"))]
            Self::Float(bits) => Some(Value::float(f64::from_bits(*bits))),
            // The Candidate-C carrier can reconstruct only the inline `i32` half
            // context-free; a wide integer or any float is a boxed reservation
            // cell that needs the evaluator heap, so it is not an immediate here
            // (the caller re-evaluates instead of rehydrating from the cache).
            #[cfg(feature = "candidate_c_value")]
            Self::Int(value) => i32::try_from(*value).ok().map(|_| Value::int(*value)),
            #[cfg(feature = "candidate_c_value")]
            Self::Float(_) => None,
            Self::Bool(value) => Some(Value::bool(*value)),
            Self::Null => Some(Value::null()),
            Self::ContextFreeString(_)
            | Self::ContextString { .. }
            | Self::Path(_)
            | Self::ContextPath { .. }
            | Self::EmptyList
            | Self::List(_)
            | Self::EmptyAttrs
            | Self::Attrs(_)
            | Self::SourceOrderedAttrs(_)
            | Self::PositionedAttrs(_)
            | Self::SourceOrderedPositionedAttrs(_)
            | Self::AttrRepr { .. } => None,
        }
    }

    pub(super) fn retains_attr_positions(&self) -> bool {
        match self {
            Self::AttrRepr { payload, .. } => payload.retains_attr_positions(),
            Self::PositionedAttrs(_) | Self::SourceOrderedPositionedAttrs(_) => true,
            Self::List(elements) => elements.iter().any(Self::retains_attr_positions),
            Self::Attrs(entries) | Self::SourceOrderedAttrs(entries) => entries
                .iter()
                .any(|entry| entry.value.retains_attr_positions()),
            Self::Int(_)
            | Self::Float(_)
            | Self::Bool(_)
            | Self::Null
            | Self::ContextFreeString(_)
            | Self::ContextString { .. }
            | Self::Path(_)
            | Self::ContextPath { .. }
            | Self::EmptyList
            | Self::EmptyAttrs => false,
        }
    }

    pub(super) fn attr_positions_all_in_module(&self, module: u32) -> bool {
        match self {
            Self::AttrRepr { payload, .. } => payload.attr_positions_all_in_module(module),
            Self::PositionedAttrs(entries) | Self::SourceOrderedPositionedAttrs(entries) => {
                entries.iter().all(|entry| {
                    entry
                        .position
                        .map(|position| position.module == module)
                        .unwrap_or(true)
                        && entry.value.attr_positions_all_in_module(module)
                })
            }
            Self::List(elements) => elements
                .iter()
                .all(|element| element.attr_positions_all_in_module(module)),
            Self::Attrs(entries) | Self::SourceOrderedAttrs(entries) => entries
                .iter()
                .all(|entry| entry.value.attr_positions_all_in_module(module)),
            Self::Int(_)
            | Self::Float(_)
            | Self::Bool(_)
            | Self::Null
            | Self::ContextFreeString(_)
            | Self::ContextString { .. }
            | Self::Path(_)
            | Self::ContextPath { .. }
            | Self::EmptyList
            | Self::EmptyAttrs => true,
        }
    }

    pub(super) fn collect_attr_position_modules(&self, modules: &mut BTreeSet<u32>) {
        match self {
            Self::AttrRepr { payload, .. } => payload.collect_attr_position_modules(modules),
            Self::PositionedAttrs(entries) | Self::SourceOrderedPositionedAttrs(entries) => {
                for entry in entries {
                    if let Some(position) = entry.position {
                        modules.insert(position.module);
                    }
                    entry.value.collect_attr_position_modules(modules);
                }
            }
            Self::List(elements) => {
                for element in elements {
                    element.collect_attr_position_modules(modules);
                }
            }
            Self::Attrs(entries) | Self::SourceOrderedAttrs(entries) => {
                for entry in entries {
                    entry.value.collect_attr_position_modules(modules);
                }
            }
            Self::Int(_)
            | Self::Float(_)
            | Self::Bool(_)
            | Self::Null
            | Self::ContextFreeString(_)
            | Self::ContextString { .. }
            | Self::Path(_)
            | Self::ContextPath { .. }
            | Self::EmptyList
            | Self::EmptyAttrs => {}
        }
    }

    pub(super) fn value_hash_from_persistent_payload(&self) -> ValueHash {
        let mut hasher = blake3::Hasher::new();
        self.update_persistent_payload_preimage(&mut hasher);
        ValueHash::from_cached_expression_payload_hash(
            CachedExpressionPayloadValueHash::from_hasher(hasher),
        )
    }

    pub(super) fn update_persistent_payload_preimage(&self, hasher: &mut blake3::Hasher) {
        match self {
            Self::Int(value) => {
                hasher.update(INLINE_VALUE_HASH_DOMAIN_VERSION);
                hasher.update(b"int");
                hasher.update(&value.to_le_bytes());
            }
            Self::Float(bits) => {
                hasher.update(INLINE_VALUE_HASH_DOMAIN_VERSION);
                hasher.update(b"float");
                hasher.update(&bits.to_le_bytes());
            }
            Self::Bool(value) => {
                hasher.update(INLINE_VALUE_HASH_DOMAIN_VERSION);
                hasher.update(b"bool");
                hasher.update(&[u8::from(*value)]);
            }
            Self::Null => {
                hasher.update(INLINE_VALUE_HASH_DOMAIN_VERSION);
                hasher.update(b"null");
            }
            Self::ContextFreeString(bytes) => {
                hasher.update(CONTEXT_FREE_STRING_VALUE_HASH_DOMAIN_VERSION);
                hasher.update(b"string");
                hasher.update(&(bytes.len() as u128).to_le_bytes());
                hasher.update(bytes);
            }
            Self::ContextString { bytes, context } => {
                hasher.update(CONTEXT_STRING_VALUE_HASH_DOMAIN_VERSION);
                hasher.update(b"string");
                hasher.update(&(bytes.len() as u128).to_le_bytes());
                hasher.update(bytes);
                update_string_context_payload_preimage(hasher, context);
            }
            Self::Path(bytes) => {
                hasher.update(PATH_VALUE_HASH_DOMAIN_VERSION);
                hasher.update(b"path");
                hasher.update(&(bytes.len() as u128).to_le_bytes());
                hasher.update(bytes);
            }
            Self::ContextPath { bytes, context } => {
                hasher.update(CONTEXT_PATH_VALUE_HASH_DOMAIN_VERSION);
                hasher.update(b"path");
                hasher.update(&(bytes.len() as u128).to_le_bytes());
                hasher.update(bytes);
                update_string_context_payload_preimage(hasher, context);
            }
            Self::EmptyList => {
                hasher.update(LIST_VALUE_HASH_DOMAIN_VERSION);
                hasher.update(b"list");
                hasher.update(&0u128.to_le_bytes());
            }
            Self::List(elements) => {
                hasher.update(LIST_VALUE_HASH_DOMAIN_VERSION);
                hasher.update(b"list");
                hasher.update(&(elements.len() as u128).to_le_bytes());
                for element in elements {
                    hasher.update(&element.persistent_payload_len().to_le_bytes());
                    element.update_persistent_payload_preimage(hasher);
                }
            }
            Self::EmptyAttrs => {
                hasher.update(ATTRS_VALUE_HASH_DOMAIN_VERSION);
                hasher.update(b"attrs");
                hasher.update(&0u128.to_le_bytes());
            }
            Self::Attrs(entries) => {
                hasher.update(ATTRS_VALUE_HASH_DOMAIN_VERSION);
                hasher.update(b"attrs");
                hasher.update(&(entries.len() as u128).to_le_bytes());
                for entry in entries {
                    hasher.update(&(entry.name.len() as u128).to_le_bytes());
                    hasher.update(&entry.name);
                    hasher.update(&entry.value.persistent_payload_len().to_le_bytes());
                    entry.value.update_persistent_payload_preimage(hasher);
                }
            }
            Self::SourceOrderedAttrs(entries) => {
                hasher.update(ATTRS_VALUE_HASH_DOMAIN_VERSION);
                hasher.update(SOURCE_ORDERED_ATTRS_PAYLOAD_TAG);
                hasher.update(&(entries.len() as u128).to_le_bytes());
                for entry in entries {
                    hasher.update(&(entry.name.len() as u128).to_le_bytes());
                    hasher.update(&entry.name);
                    hasher.update(&entry.value.persistent_payload_len().to_le_bytes());
                    entry.value.update_persistent_payload_preimage(hasher);
                }
            }
            Self::PositionedAttrs(entries) => {
                hasher.update(ATTRS_VALUE_HASH_DOMAIN_VERSION);
                hasher.update(POSITIONED_ATTRS_PAYLOAD_TAG);
                update_positioned_attr_entries_preimage(hasher, entries);
            }
            Self::SourceOrderedPositionedAttrs(entries) => {
                hasher.update(ATTRS_VALUE_HASH_DOMAIN_VERSION);
                hasher.update(SOURCE_ORDERED_POSITIONED_ATTRS_PAYLOAD_TAG);
                update_positioned_attr_entries_preimage(hasher, entries);
            }
            Self::AttrRepr { repr, payload } => {
                hasher.update(ATTR_REPR_PAYLOAD_ENVELOPE_TAG);
                hasher.update(&[attr_repr_payload_byte(*repr)]);
                hasher.update(&payload.persistent_payload_len().to_le_bytes());
                payload.update_persistent_payload_preimage(hasher);
            }
        }
    }

    pub(super) fn persistent_payload_len(&self) -> u128 {
        match self {
            Self::Int(_) => INLINE_VALUE_HASH_DOMAIN_VERSION.len() as u128 + 3 + 8,
            Self::Float(_) => INLINE_VALUE_HASH_DOMAIN_VERSION.len() as u128 + 5 + 8,
            Self::Bool(_) => INLINE_VALUE_HASH_DOMAIN_VERSION.len() as u128 + 4 + 1,
            Self::Null => INLINE_VALUE_HASH_DOMAIN_VERSION.len() as u128 + 4,
            Self::ContextFreeString(bytes) => {
                CONTEXT_FREE_STRING_VALUE_HASH_DOMAIN_VERSION.len() as u128
                    + 6
                    + 16
                    + bytes.len() as u128
            }
            Self::ContextString { bytes, context } => {
                CONTEXT_STRING_VALUE_HASH_DOMAIN_VERSION.len() as u128
                    + 6
                    + 16
                    + bytes.len() as u128
                    + string_context_payload_len(context)
            }
            Self::Path(bytes) => {
                PATH_VALUE_HASH_DOMAIN_VERSION.len() as u128 + 4 + 16 + bytes.len() as u128
            }
            Self::ContextPath { bytes, context } => {
                CONTEXT_PATH_VALUE_HASH_DOMAIN_VERSION.len() as u128
                    + 4
                    + 16
                    + bytes.len() as u128
                    + string_context_payload_len(context)
            }
            Self::EmptyList => LIST_VALUE_HASH_DOMAIN_VERSION.len() as u128 + 4 + 16,
            Self::List(elements) => {
                LIST_VALUE_HASH_DOMAIN_VERSION.len() as u128
                    + 4
                    + 16
                    + elements
                        .iter()
                        .map(|element| 16 + element.persistent_payload_len())
                        .sum::<u128>()
            }
            Self::EmptyAttrs => ATTRS_VALUE_HASH_DOMAIN_VERSION.len() as u128 + 5 + 16,
            Self::Attrs(entries) => {
                ATTRS_VALUE_HASH_DOMAIN_VERSION.len() as u128
                    + 5
                    + 16
                    + entries
                        .iter()
                        .map(|entry| {
                            16 + entry.name.len() as u128
                                + 16
                                + entry.value.persistent_payload_len()
                        })
                        .sum::<u128>()
            }
            Self::SourceOrderedAttrs(entries) => {
                ATTRS_VALUE_HASH_DOMAIN_VERSION.len() as u128
                    + SOURCE_ORDERED_ATTRS_PAYLOAD_TAG.len() as u128
                    + 16
                    + entries
                        .iter()
                        .map(|entry| {
                            16 + entry.name.len() as u128
                                + 16
                                + entry.value.persistent_payload_len()
                        })
                        .sum::<u128>()
            }
            Self::PositionedAttrs(entries) => {
                ATTRS_VALUE_HASH_DOMAIN_VERSION.len() as u128
                    + POSITIONED_ATTRS_PAYLOAD_TAG.len() as u128
                    + 16
                    + entries
                        .iter()
                        .map(positioned_attr_entry_payload_len)
                        .sum::<u128>()
            }
            Self::SourceOrderedPositionedAttrs(entries) => {
                ATTRS_VALUE_HASH_DOMAIN_VERSION.len() as u128
                    + SOURCE_ORDERED_POSITIONED_ATTRS_PAYLOAD_TAG.len() as u128
                    + 16
                    + entries
                        .iter()
                        .map(positioned_attr_entry_payload_len)
                        .sum::<u128>()
            }
            Self::AttrRepr { payload, .. } => {
                ATTR_REPR_PAYLOAD_ENVELOPE_TAG.len() as u128
                    + 1
                    + 16
                    + payload.persistent_payload_len()
            }
        }
    }

    pub(super) fn encode_persistent_payload(
        &self,
    ) -> Result<Vec<u8>, CachedExpressionValuePayloadError> {
        let mut out = Vec::new();
        match self {
            Self::Int(value) => {
                append_payload_bytes(&mut out, INLINE_VALUE_HASH_DOMAIN_VERSION)?;
                append_payload_bytes(&mut out, b"int")?;
                append_payload_bytes(&mut out, &value.to_le_bytes())?;
            }
            Self::Float(bits) => {
                append_payload_bytes(&mut out, INLINE_VALUE_HASH_DOMAIN_VERSION)?;
                append_payload_bytes(&mut out, b"float")?;
                append_payload_bytes(&mut out, &bits.to_le_bytes())?;
            }
            Self::Bool(value) => {
                append_payload_bytes(&mut out, INLINE_VALUE_HASH_DOMAIN_VERSION)?;
                append_payload_bytes(&mut out, b"bool")?;
                append_payload_byte(&mut out, u8::from(*value))?;
            }
            Self::Null => {
                append_payload_bytes(&mut out, INLINE_VALUE_HASH_DOMAIN_VERSION)?;
                append_payload_bytes(&mut out, b"null")?;
            }
            Self::ContextFreeString(bytes) => {
                append_payload_bytes(&mut out, CONTEXT_FREE_STRING_VALUE_HASH_DOMAIN_VERSION)?;
                append_payload_bytes(&mut out, b"string")?;
                append_payload_u128(&mut out, bytes.len() as u128)?;
                append_payload_bytes(&mut out, bytes)?;
            }
            Self::ContextString { bytes, context } => {
                append_payload_bytes(&mut out, CONTEXT_STRING_VALUE_HASH_DOMAIN_VERSION)?;
                append_payload_bytes(&mut out, b"string")?;
                append_payload_u128(&mut out, bytes.len() as u128)?;
                append_payload_bytes(&mut out, bytes)?;
                append_string_context_payload(&mut out, context)?;
            }
            Self::Path(bytes) => {
                append_payload_bytes(&mut out, PATH_VALUE_HASH_DOMAIN_VERSION)?;
                append_payload_bytes(&mut out, b"path")?;
                append_payload_u128(&mut out, bytes.len() as u128)?;
                append_payload_bytes(&mut out, bytes)?;
            }
            Self::ContextPath { bytes, context } => {
                append_payload_bytes(&mut out, CONTEXT_PATH_VALUE_HASH_DOMAIN_VERSION)?;
                append_payload_bytes(&mut out, b"path")?;
                append_payload_u128(&mut out, bytes.len() as u128)?;
                append_payload_bytes(&mut out, bytes)?;
                append_string_context_payload(&mut out, context)?;
            }
            Self::EmptyList => {
                append_payload_bytes(&mut out, LIST_VALUE_HASH_DOMAIN_VERSION)?;
                append_payload_bytes(&mut out, b"list")?;
                append_payload_u128(&mut out, 0)?;
            }
            Self::List(elements) => {
                append_payload_bytes(&mut out, LIST_VALUE_HASH_DOMAIN_VERSION)?;
                append_payload_bytes(&mut out, b"list")?;
                append_payload_u128(&mut out, elements.len() as u128)?;
                for element in elements {
                    append_payload_u128(&mut out, element.persistent_payload_len())?;
                    append_payload_bytes(&mut out, &element.encode_persistent_payload()?)?;
                }
            }
            Self::EmptyAttrs => {
                append_payload_bytes(&mut out, ATTRS_VALUE_HASH_DOMAIN_VERSION)?;
                append_payload_bytes(&mut out, b"attrs")?;
                append_payload_u128(&mut out, 0)?;
            }
            Self::Attrs(entries) => {
                append_payload_bytes(&mut out, ATTRS_VALUE_HASH_DOMAIN_VERSION)?;
                append_payload_bytes(&mut out, b"attrs")?;
                append_payload_u128(&mut out, entries.len() as u128)?;
                for entry in entries {
                    append_payload_u128(&mut out, entry.name.len() as u128)?;
                    append_payload_bytes(&mut out, &entry.name)?;
                    append_payload_u128(&mut out, entry.value.persistent_payload_len())?;
                    append_payload_bytes(&mut out, &entry.value.encode_persistent_payload()?)?;
                }
            }
            Self::SourceOrderedAttrs(entries) => {
                append_payload_bytes(&mut out, ATTRS_VALUE_HASH_DOMAIN_VERSION)?;
                append_payload_bytes(&mut out, SOURCE_ORDERED_ATTRS_PAYLOAD_TAG)?;
                append_payload_u128(&mut out, entries.len() as u128)?;
                for entry in entries {
                    append_payload_u128(&mut out, entry.name.len() as u128)?;
                    append_payload_bytes(&mut out, &entry.name)?;
                    append_payload_u128(&mut out, entry.value.persistent_payload_len())?;
                    append_payload_bytes(&mut out, &entry.value.encode_persistent_payload()?)?;
                }
            }
            Self::PositionedAttrs(entries) => {
                append_payload_bytes(&mut out, ATTRS_VALUE_HASH_DOMAIN_VERSION)?;
                append_payload_bytes(&mut out, POSITIONED_ATTRS_PAYLOAD_TAG)?;
                append_payload_u128(&mut out, entries.len() as u128)?;
                for entry in entries {
                    append_payload_u128(&mut out, entry.name.len() as u128)?;
                    append_payload_bytes(&mut out, &entry.name)?;
                    append_attr_position_payload(&mut out, entry.position)?;
                    append_payload_u128(&mut out, entry.value.persistent_payload_len())?;
                    append_payload_bytes(&mut out, &entry.value.encode_persistent_payload()?)?;
                }
            }
            Self::SourceOrderedPositionedAttrs(entries) => {
                append_payload_bytes(&mut out, ATTRS_VALUE_HASH_DOMAIN_VERSION)?;
                append_payload_bytes(&mut out, SOURCE_ORDERED_POSITIONED_ATTRS_PAYLOAD_TAG)?;
                append_payload_u128(&mut out, entries.len() as u128)?;
                for entry in entries {
                    append_payload_u128(&mut out, entry.name.len() as u128)?;
                    append_payload_bytes(&mut out, &entry.name)?;
                    append_attr_position_payload(&mut out, entry.position)?;
                    append_payload_u128(&mut out, entry.value.persistent_payload_len())?;
                    append_payload_bytes(&mut out, &entry.value.encode_persistent_payload()?)?;
                }
            }
            Self::AttrRepr { repr, payload } => {
                append_payload_bytes(&mut out, ATTR_REPR_PAYLOAD_ENVELOPE_TAG)?;
                append_payload_byte(&mut out, attr_repr_payload_byte(*repr))?;
                append_payload_u128(&mut out, payload.persistent_payload_len())?;
                append_payload_bytes(&mut out, &payload.encode_persistent_payload()?)?;
            }
        }
        Ok(out)
    }

    pub(super) fn decode_persistent_payload(
        bytes: &[u8],
    ) -> Result<Self, CachedExpressionValuePayloadError> {
        Self::decode_persistent_payload_with_depth(bytes, 0)
    }

    fn decode_persistent_payload_with_depth(
        bytes: &[u8],
        depth: usize,
    ) -> Result<Self, CachedExpressionValuePayloadError> {
        if depth > MAX_CACHED_EXPRESSION_PAYLOAD_NESTING {
            return Err(
                CachedExpressionValuePayloadError::PayloadNestingLimitExceeded {
                    limit: MAX_CACHED_EXPRESSION_PAYLOAD_NESTING,
                },
            );
        }
        if bytes.starts_with(ATTR_REPR_PAYLOAD_ENVELOPE_TAG) {
            let mut cursor = PayloadCursor::new(bytes);
            cursor.take_marker(
                ATTR_REPR_PAYLOAD_ENVELOPE_TAG,
                "attr representation envelope",
            )?;
            let repr = attr_repr_from_payload_byte(cursor.take_byte()?)?;
            if matches!(repr, AttrSetReprKind::Flat) {
                return Err(CachedExpressionValuePayloadError::NonCanonicalAttrReprEnvelope);
            }
            let len = cursor.take_len()?;
            let payload_bytes = cursor.take_bytes(len)?;
            let payload =
                Self::decode_persistent_payload_with_depth(payload_bytes, depth.saturating_add(1))?;
            if matches!(payload, Self::AttrRepr { .. }) {
                return Err(CachedExpressionValuePayloadError::NonCanonicalAttrReprEnvelope);
            }
            if !payload.is_attrs_payload() {
                return Err(CachedExpressionValuePayloadError::AttrReprWithoutAttrs);
            }
            cursor.finish()?;
            return Ok(Self::AttrRepr {
                repr,
                payload: Box::new(payload),
            });
        }
        if bytes.starts_with(INLINE_VALUE_HASH_DOMAIN_VERSION) {
            let mut cursor = PayloadCursor::new(bytes);
            cursor.take_marker(INLINE_VALUE_HASH_DOMAIN_VERSION, "inline value domain")?;
            let payload = decode_inline_value_payload(&mut cursor)?;
            cursor.finish()?;
            return Ok(payload);
        }
        if bytes.starts_with(CONTEXT_FREE_STRING_VALUE_HASH_DOMAIN_VERSION) {
            let mut cursor = PayloadCursor::new(bytes);
            cursor.take_marker(
                CONTEXT_FREE_STRING_VALUE_HASH_DOMAIN_VERSION,
                "context-free string value domain",
            )?;
            cursor.take_marker(b"string", "string payload tag")?;
            let payload = Self::ContextFreeString(cursor.take_length_prefixed_bytes()?);
            cursor.finish()?;
            return Ok(payload);
        }
        if bytes.starts_with(CONTEXT_STRING_VALUE_HASH_DOMAIN_VERSION) {
            let mut cursor = PayloadCursor::new(bytes);
            cursor.take_marker(
                CONTEXT_STRING_VALUE_HASH_DOMAIN_VERSION,
                "context string value domain",
            )?;
            cursor.take_marker(b"string", "string payload tag")?;
            let string_bytes = cursor.take_length_prefixed_bytes()?;
            let context = cursor.take_string_context()?;
            if context.is_empty() {
                return Err(CachedExpressionValuePayloadError::EmptyStringContext {
                    payload: "context string",
                });
            }
            cursor.finish()?;
            return Ok(Self::ContextString {
                bytes: string_bytes,
                context,
            });
        }
        if bytes.starts_with(PATH_VALUE_HASH_DOMAIN_VERSION) {
            let mut cursor = PayloadCursor::new(bytes);
            cursor.take_marker(PATH_VALUE_HASH_DOMAIN_VERSION, "path value domain")?;
            cursor.take_marker(b"path", "path payload tag")?;
            let payload = Self::Path(cursor.take_length_prefixed_bytes()?);
            cursor.finish()?;
            return Ok(payload);
        }
        if bytes.starts_with(CONTEXT_PATH_VALUE_HASH_DOMAIN_VERSION) {
            let mut cursor = PayloadCursor::new(bytes);
            cursor.take_marker(
                CONTEXT_PATH_VALUE_HASH_DOMAIN_VERSION,
                "context path value domain",
            )?;
            cursor.take_marker(b"path", "path payload tag")?;
            let path_bytes = cursor.take_length_prefixed_bytes()?;
            let context = cursor.take_string_context()?;
            if context.is_empty() {
                return Err(CachedExpressionValuePayloadError::EmptyStringContext {
                    payload: "context path",
                });
            }
            cursor.finish()?;
            return Ok(Self::ContextPath {
                bytes: path_bytes,
                context,
            });
        }
        if bytes.starts_with(LIST_VALUE_HASH_DOMAIN_VERSION) {
            let mut cursor = PayloadCursor::new(bytes);
            cursor.take_marker(LIST_VALUE_HASH_DOMAIN_VERSION, "list value domain")?;
            cursor.take_marker(b"list", "list payload tag")?;
            let len = cursor.take_len()?;
            if len == 0 {
                cursor.finish()?;
                return Ok(Self::EmptyList);
            }
            let mut elements = Vec::new();
            elements
                .try_reserve_exact(len)
                .map_err(|_| CachedExpressionValuePayloadError::ListAllocationFailed { len })?;
            for _ in 0..len {
                let element = cursor.take_length_prefixed_bytes()?;
                elements.push(Self::decode_persistent_payload_with_depth(
                    &element,
                    depth.saturating_add(1),
                )?);
            }
            cursor.finish()?;
            return Ok(Self::List(elements));
        }
        if bytes.starts_with(ATTRS_VALUE_HASH_DOMAIN_VERSION) {
            let mut cursor = PayloadCursor::new(bytes);
            cursor.take_marker(ATTRS_VALUE_HASH_DOMAIN_VERSION, "attrs value domain")?;
            let (source_ordered, positioned) = if cursor
                .remaining()
                .starts_with(SOURCE_ORDERED_POSITIONED_ATTRS_PAYLOAD_TAG)
            {
                cursor.take_marker(
                    SOURCE_ORDERED_POSITIONED_ATTRS_PAYLOAD_TAG,
                    "source-order positioned attrs payload tag",
                )?;
                (true, true)
            } else if cursor.remaining().starts_with(POSITIONED_ATTRS_PAYLOAD_TAG) {
                cursor.take_marker(POSITIONED_ATTRS_PAYLOAD_TAG, "positioned attrs payload tag")?;
                (false, true)
            } else if cursor
                .remaining()
                .starts_with(SOURCE_ORDERED_ATTRS_PAYLOAD_TAG)
            {
                cursor.take_marker(
                    SOURCE_ORDERED_ATTRS_PAYLOAD_TAG,
                    "source-order attrs payload tag",
                )?;
                (true, false)
            } else {
                cursor.take_marker(b"attrs", "attrs payload tag")?;
                (false, false)
            };
            let len = cursor.take_len()?;
            if len == 0 {
                cursor.finish()?;
                if positioned {
                    return Err(
                        CachedExpressionValuePayloadError::PositionlessPositionedAttrsPayload,
                    );
                }
                return Ok(Self::EmptyAttrs);
            }
            if positioned {
                let mut entries: Vec<PositionedAttrPayloadEntry> = Vec::new();
                entries.try_reserve_exact(len).map_err(|_| {
                    CachedExpressionValuePayloadError::AttrsAllocationFailed { len }
                })?;
                let mut has_position = false;
                for index in 0..len {
                    let name = cursor.take_length_prefixed_bytes()?;
                    if !source_ordered
                        && let Some(previous) = entries.last()
                        && previous.name.as_slice() >= name.as_slice()
                    {
                        return Err(
                            CachedExpressionValuePayloadError::NonCanonicalAttrsPayloadName {
                                index,
                            },
                        );
                    }
                    let position = cursor.take_attr_position()?;
                    has_position |= position.is_some();
                    let value = cursor.take_length_prefixed_bytes()?;
                    entries.push(PositionedAttrPayloadEntry {
                        name,
                        position,
                        value: Self::decode_persistent_payload_with_depth(
                            &value,
                            depth.saturating_add(1),
                        )?,
                    });
                }
                cursor.finish()?;
                if !has_position {
                    return Err(
                        CachedExpressionValuePayloadError::PositionlessPositionedAttrsPayload,
                    );
                }
                if source_ordered {
                    ensure_unique_attr_payload_names(
                        entries.iter().map(|entry| entry.name.as_slice()),
                    )?;
                    return Ok(Self::SourceOrderedPositionedAttrs(entries));
                }
                return Ok(Self::PositionedAttrs(entries));
            }
            let mut entries: Vec<AttrPayloadEntry> = Vec::new();
            entries
                .try_reserve_exact(len)
                .map_err(|_| CachedExpressionValuePayloadError::AttrsAllocationFailed { len })?;
            for index in 0..len {
                let name = cursor.take_length_prefixed_bytes()?;
                if !source_ordered
                    && let Some(previous) = entries.last()
                    && previous.name.as_slice() >= name.as_slice()
                {
                    return Err(
                        CachedExpressionValuePayloadError::NonCanonicalAttrsPayloadName { index },
                    );
                }
                let value = cursor.take_length_prefixed_bytes()?;
                entries.push(AttrPayloadEntry {
                    name,
                    value: Self::decode_persistent_payload_with_depth(
                        &value,
                        depth.saturating_add(1),
                    )?,
                });
            }
            cursor.finish()?;
            if source_ordered {
                ensure_unique_attr_payload_names(
                    entries.iter().map(|entry| entry.name.as_slice()),
                )?;
                return Ok(Self::SourceOrderedAttrs(entries));
            }
            return Ok(Self::Attrs(entries));
        }
        Err(CachedExpressionValuePayloadError::UnknownDomain)
    }

    pub(super) fn attr_repr_kind(&self) -> Option<AttrSetReprKind> {
        match self {
            Self::AttrRepr { repr, .. } => Some(*repr),
            Self::EmptyAttrs
            | Self::Attrs(_)
            | Self::SourceOrderedAttrs(_)
            | Self::PositionedAttrs(_)
            | Self::SourceOrderedPositionedAttrs(_) => Some(AttrSetReprKind::Flat),
            Self::Int(_)
            | Self::Float(_)
            | Self::Bool(_)
            | Self::Null
            | Self::ContextFreeString(_)
            | Self::ContextString { .. }
            | Self::Path(_)
            | Self::ContextPath { .. }
            | Self::EmptyList
            | Self::List(_) => None,
        }
    }

    pub(super) fn with_attr_repr(
        self,
        repr: AttrSetReprKind,
    ) -> Result<Self, CachedExpressionValuePayloadError> {
        if !self.is_attrs_payload() {
            return Err(CachedExpressionValuePayloadError::AttrReprWithoutAttrs);
        }
        let payload = match self {
            Self::AttrRepr { payload, .. } => payload,
            payload if matches!(repr, AttrSetReprKind::Flat) => return Ok(payload),
            payload => Box::new(payload),
        };
        match repr {
            AttrSetReprKind::Flat => Ok(*payload),
            AttrSetReprKind::Hamt => Ok(Self::AttrRepr { repr, payload }),
        }
    }

    fn is_attrs_payload(&self) -> bool {
        match self {
            Self::EmptyAttrs
            | Self::Attrs(_)
            | Self::SourceOrderedAttrs(_)
            | Self::PositionedAttrs(_)
            | Self::SourceOrderedPositionedAttrs(_) => true,
            Self::AttrRepr { payload, .. } => payload.is_attrs_payload(),
            Self::Int(_)
            | Self::Float(_)
            | Self::Bool(_)
            | Self::Null
            | Self::ContextFreeString(_)
            | Self::ContextString { .. }
            | Self::Path(_)
            | Self::ContextPath { .. }
            | Self::EmptyList
            | Self::List(_) => false,
        }
    }
}

const fn attr_repr_payload_byte(repr: AttrSetReprKind) -> u8 {
    match repr {
        AttrSetReprKind::Flat => 0,
        AttrSetReprKind::Hamt => 1,
    }
}

fn attr_repr_from_payload_byte(
    tag: u8,
) -> Result<AttrSetReprKind, CachedExpressionValuePayloadError> {
    match tag {
        0 => Ok(AttrSetReprKind::Flat),
        1 => Ok(AttrSetReprKind::Hamt),
        tag => Err(CachedExpressionValuePayloadError::InvalidTag {
            section: "attr representation",
            tag,
        }),
    }
}

pub(super) fn ensure_unique_attr_payload_names<'a, I>(
    names: I,
) -> Result<(), CachedExpressionValuePayloadError>
where
    I: IntoIterator<Item = &'a [u8]>,
{
    let mut seen = BTreeMap::<Vec<u8>, usize>::new();
    for (index, name) in names.into_iter().enumerate() {
        if seen.contains_key(name) {
            return Err(CachedExpressionValuePayloadError::NonCanonicalAttrsPayloadName { index });
        }
        seen.insert(name.to_vec(), index);
    }
    Ok(())
}

fn update_positioned_attr_entries_preimage(
    hasher: &mut blake3::Hasher,
    entries: &[PositionedAttrPayloadEntry],
) {
    hasher.update(&(entries.len() as u128).to_le_bytes());
    for entry in entries {
        hasher.update(&(entry.name.len() as u128).to_le_bytes());
        hasher.update(&entry.name);
        update_attr_position_preimage(hasher, entry.position);
        hasher.update(&entry.value.persistent_payload_len().to_le_bytes());
        entry.value.update_persistent_payload_preimage(hasher);
    }
}

fn update_attr_position_preimage(hasher: &mut blake3::Hasher, position: Option<AttrPosition>) {
    match position {
        Some(position) => {
            hasher.update(&[1]);
            hasher.update(&position.module.to_le_bytes());
            hasher.update(&position.span.start.to_le_bytes());
            hasher.update(&position.span.end.to_le_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
}

fn positioned_attr_entry_payload_len(entry: &PositionedAttrPayloadEntry) -> u128 {
    16 + entry.name.len() as u128
        + attr_position_payload_len(entry.position)
        + 16
        + entry.value.persistent_payload_len()
}

const fn attr_position_payload_len(position: Option<AttrPosition>) -> u128 {
    if position.is_some() { 13 } else { 1 }
}

fn append_attr_position_payload(
    out: &mut Vec<u8>,
    position: Option<AttrPosition>,
) -> Result<(), CachedExpressionValuePayloadError> {
    match position {
        Some(position) => {
            append_payload_byte(out, 1)?;
            append_payload_bytes(out, &position.module.to_le_bytes())?;
            append_payload_bytes(out, &position.span.start.to_le_bytes())?;
            append_payload_bytes(out, &position.span.end.to_le_bytes())
        }
        None => append_payload_byte(out, 0),
    }
}

pub(super) fn append_payload_byte(
    out: &mut Vec<u8>,
    byte: u8,
) -> Result<(), CachedExpressionValuePayloadError> {
    append_payload_bytes(out, &[byte])
}

pub(super) fn append_payload_u128(
    out: &mut Vec<u8>,
    value: u128,
) -> Result<(), CachedExpressionValuePayloadError> {
    append_payload_bytes(out, &value.to_le_bytes())
}

pub(super) fn append_payload_bytes(
    out: &mut Vec<u8>,
    bytes: &[u8],
) -> Result<(), CachedExpressionValuePayloadError> {
    let len = out.len().checked_add(bytes.len()).ok_or(
        CachedExpressionValuePayloadError::PayloadLengthOverflow {
            current: out.len(),
            additional: bytes.len(),
        },
    )?;
    out.try_reserve_exact(bytes.len())
        .map_err(|_| CachedExpressionValuePayloadError::PayloadAllocationFailed { len })?;
    out.extend_from_slice(bytes);
    Ok(())
}

pub(super) fn append_length_prefixed_payload_bytes(
    out: &mut Vec<u8>,
    bytes: &[u8],
) -> Result<(), CachedExpressionValuePayloadError> {
    append_payload_u128(out, bytes.len() as u128)?;
    append_payload_bytes(out, bytes)
}

fn append_string_context_payload(
    out: &mut Vec<u8>,
    context: &StringContext,
) -> Result<(), CachedExpressionValuePayloadError> {
    append_payload_bytes(out, b"context")?;
    append_payload_u128(out, context.len() as u128)?;
    for element in context.elements() {
        match element.kind() {
            ContextKind::OpaquePath => {
                append_payload_byte(out, 0)?;
                append_length_prefixed_payload_bytes(out, element.path())?;
            }
            ContextKind::SingleOutput => {
                append_payload_byte(out, 1)?;
                append_length_prefixed_payload_bytes(out, element.path())?;
                let output = match element.output() {
                    Some(output) => output,
                    None => &[],
                };
                append_length_prefixed_payload_bytes(out, output)?;
            }
            ContextKind::DeepDerivation => {
                append_payload_byte(out, 2)?;
                append_length_prefixed_payload_bytes(out, element.path())?;
            }
        }
    }
    Ok(())
}

fn string_context_payload_len(context: &StringContext) -> u128 {
    7 + 16
        + context
            .elements()
            .iter()
            .map(|element| {
                let path_len = element.path().len() as u128;
                match element.kind() {
                    ContextKind::OpaquePath | ContextKind::DeepDerivation => 1 + 16 + path_len,
                    ContextKind::SingleOutput => {
                        let output_len = element.output().unwrap_or_default().len() as u128;
                        1 + 16 + path_len + 16 + output_len
                    }
                }
            })
            .sum::<u128>()
}

fn update_string_context_payload_preimage(hasher: &mut blake3::Hasher, context: &StringContext) {
    hasher.update(b"context");
    hasher.update(&(context.len() as u128).to_le_bytes());
    for element in context.elements() {
        match element.kind() {
            ContextKind::OpaquePath => {
                hasher.update(&[0]);
                hasher.update(&(element.path().len() as u128).to_le_bytes());
                hasher.update(element.path());
            }
            ContextKind::SingleOutput => {
                hasher.update(&[1]);
                hasher.update(&(element.path().len() as u128).to_le_bytes());
                hasher.update(element.path());
                let output = element.output().unwrap_or_default();
                hasher.update(&(output.len() as u128).to_le_bytes());
                hasher.update(output);
            }
            ContextKind::DeepDerivation => {
                hasher.update(&[2]);
                hasher.update(&(element.path().len() as u128).to_le_bytes());
                hasher.update(element.path());
            }
        }
    }
}

fn decode_inline_value_payload(
    cursor: &mut PayloadCursor<'_>,
) -> Result<InlineValuePayload, CachedExpressionValuePayloadError> {
    if cursor.remaining().starts_with(b"int") {
        cursor.take_marker(b"int", "int payload tag")?;
        return Ok(InlineValuePayload::Int(cursor.take_i64()?));
    }
    if cursor.remaining().starts_with(b"float") {
        cursor.take_marker(b"float", "float payload tag")?;
        return Ok(InlineValuePayload::Float(cursor.take_u64()?));
    }
    if cursor.remaining().starts_with(b"bool") {
        cursor.take_marker(b"bool", "bool payload tag")?;
        let byte = cursor.take_byte()?;
        return match byte {
            0 => Ok(InlineValuePayload::Bool(false)),
            1 => Ok(InlineValuePayload::Bool(true)),
            byte => Err(CachedExpressionValuePayloadError::InvalidBool { byte }),
        };
    }
    if cursor.remaining().starts_with(b"null") {
        cursor.take_marker(b"null", "null payload tag")?;
        return Ok(InlineValuePayload::Null);
    }
    let tag = cursor.remaining().first().copied().unwrap_or_default();
    Err(CachedExpressionValuePayloadError::InvalidTag {
        section: "inline value",
        tag,
    })
}
