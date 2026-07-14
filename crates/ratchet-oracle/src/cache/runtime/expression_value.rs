//! Cached expression payload wrapper and replay accessors.

use crate::cache::hashing::CacheDigestHasher;
use super::*;
use crate::cache::hashing::CachedExpressionPayloadValueHash;

// Precomputed BLAKE3 hashes of the canonical empty payload preimages keep the
// public empty constructors const while every cached value carries a hash field.
const EMPTY_LIST_VALUE_HASH: ValueHash = ValueHash::from_cached_expression_payload_hash(
    CachedExpressionPayloadValueHash::from_precomputed_hash(DurableBlake3Hash::from_bytes([
        54, 154, 29, 29, 98, 143, 209, 209, 178, 225, 27, 65, 134, 247, 216, 4, 24, 162, 28, 201,
        95, 112, 180, 91, 27, 211, 47, 234, 71, 240, 246, 20,
    ])),
);

const EMPTY_ATTRS_VALUE_HASH: ValueHash = ValueHash::from_cached_expression_payload_hash(
    CachedExpressionPayloadValueHash::from_precomputed_hash(DurableBlake3Hash::from_bytes([
        208, 38, 121, 20, 160, 193, 6, 66, 13, 195, 48, 174, 248, 48, 164, 106, 51, 179, 197, 106,
        209, 182, 57, 99, 242, 188, 73, 48, 52, 151, 114, 248,
    ])),
);

/// A memoized force-cache payload that can be replayed by an evaluator.
///
/// Scalars and heap-backed values both store canonical, runtime-independent
/// data. Evaluator replay rehydrates that data through the receiving heap so a
/// cached payload never persists an arena-qualified Candidate-B or Candidate-C
/// word.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachedExpressionValue {
    pub(super) payload: InlineValuePayload,
    pub(super) attr_position_source_hash: Option<AttrPositionSourceHash>,
    value_hash: ValueHash,
}

/// One canonical scalar carried by a cached expression payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CachedScalarValue {
    Int(i64),
    FloatBits(u64),
    Bool(bool),
    Null,
}

/// One cached attrset entry with an optional source position.
pub type CachedAttrEntryWithPosition = (Vec<u8>, Option<AttrPosition>, CachedExpressionValue);

impl CachedExpressionValue {
    /// Creates a cached signed integer without constructing an active value.
    ///
    /// Keeping the canonical `i64` in the cache payload lets a future
    /// Candidate-C replay allocate a boxed scalar in the receiving evaluator's
    /// reservation instead of persisting an arena-qualified runtime word.
    pub fn int(value: i64) -> Self {
        Self::from_payload(InlineValuePayload::Int(value))
    }

    /// Creates a cached exact floating-point payload without constructing an
    /// active value.
    ///
    /// The bit pattern is retained verbatim, including signed zero and NaN
    /// payloads, until the receiving evaluator rehydrates its active value.
    pub fn float(value: f64) -> Self {
        Self::from_payload(InlineValuePayload::Float(value.to_bits()))
    }

    /// Creates a cached boolean without constructing an active value.
    pub fn bool(value: bool) -> Self {
        Self::from_payload(InlineValuePayload::Bool(value))
    }

    /// Creates a cached null without constructing an active value.
    pub fn null() -> Self {
        Self::from_payload(InlineValuePayload::Null)
    }

    /// Creates a cached immediate scalar value.
    ///
    /// # Errors
    ///
    /// Returns [`ValueHashError`] if `value` is invalid or is not an inline
    /// scalar supported by the current force-cache payload precursor.
    pub fn immediate(value: Value) -> Result<Self, ValueHashError> {
        Ok(Self::from_payload(InlineValuePayload::from_value(value)?))
    }

    /// Creates a cached context-free Nix string payload from canonical bytes.
    pub fn context_free_string(bytes: Vec<u8>) -> Self {
        Self::from_payload(InlineValuePayload::ContextFreeString(bytes))
    }

    /// Creates a cached Nix string payload from canonical bytes and context.
    ///
    /// Empty contexts are canonicalized to [`Self::context_free_string`].
    pub fn context_string(bytes: Vec<u8>, context: StringContext) -> Self {
        if context.is_empty() {
            return Self::context_free_string(bytes);
        }
        Self::from_payload(InlineValuePayload::ContextString { bytes, context })
    }

    /// Creates a cached Nix path payload from canonical path bytes.
    pub fn path(bytes: Vec<u8>) -> Self {
        Self::from_payload(InlineValuePayload::Path(bytes))
    }

    /// Creates a cached Nix path payload from canonical path bytes and context.
    ///
    /// Empty contexts are canonicalized to [`Self::path`].
    pub fn context_path(bytes: Vec<u8>, context: StringContext) -> Self {
        if context.is_empty() {
            return Self::path(bytes);
        }
        Self::from_payload(InlineValuePayload::ContextPath { bytes, context })
    }

    /// Creates a cached empty Nix list payload.
    pub const fn empty_list() -> Self {
        Self {
            payload: InlineValuePayload::EmptyList,
            attr_position_source_hash: None,
            value_hash: EMPTY_LIST_VALUE_HASH,
        }
    }

    /// Creates a cached strict Nix list payload from replayable element payloads.
    ///
    /// This represents a list spine whose elements are already replayable
    /// values. It does not represent lazy element thunks; callers must not force
    /// elements just to build this payload.
    pub fn strict_list(elements: Vec<Self>) -> Self {
        if elements.is_empty() {
            return Self::empty_list();
        }
        Self::from_payload(InlineValuePayload::List(
            elements.into_iter().map(|value| value.payload).collect(),
        ))
    }

    /// Creates a cached strict Nix attrset payload from replayable bindings.
    ///
    /// This represents an attrset whose binding values are already replayable
    /// values. It does not represent lazy binding thunks; callers must not
    /// force bindings just to build this payload.
    ///
    /// # Errors
    ///
    /// Returns [`CachedExpressionValuePayloadError::NonCanonicalAttrsPayloadName`]
    /// if two bindings have the same attribute name.
    pub fn strict_attrs(
        mut entries: Vec<(Vec<u8>, Self)>,
    ) -> Result<Self, CachedExpressionValuePayloadError> {
        if entries.is_empty() {
            return Ok(Self::empty_attrs());
        }
        entries.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        for (index, pair) in entries.windows(2).enumerate() {
            if pair[0].0 == pair[1].0 {
                return Err(
                    CachedExpressionValuePayloadError::NonCanonicalAttrsPayloadName {
                        index: index + 1,
                    },
                );
            }
        }
        Ok(Self::from_payload(InlineValuePayload::Attrs(
            entries
                .into_iter()
                .map(|(name, value)| AttrPayloadEntry {
                    name,
                    value: value.payload,
                })
                .collect(),
        )))
    }

    /// Creates a cached strict Nix attrset payload with binding source positions.
    ///
    /// This represents an attrset whose binding values are already replayable
    /// values and whose optional binding positions are observable through
    /// `builtins.unsafeGetAttrPos`. It does not represent lazy binding thunks.
    /// Inputs with no positions canonicalize to [`Self::strict_attrs`].
    ///
    /// # Errors
    ///
    /// Returns [`CachedExpressionValuePayloadError::NonCanonicalAttrsPayloadName`]
    /// if two bindings have the same attribute name.
    pub fn positioned_attrs(
        mut entries: Vec<(Vec<u8>, Option<AttrPosition>, Self)>,
    ) -> Result<Self, CachedExpressionValuePayloadError> {
        if entries.is_empty() {
            return Ok(Self::empty_attrs());
        }
        if entries.iter().all(|(_, position, _)| position.is_none()) {
            return Self::strict_attrs(
                entries
                    .into_iter()
                    .map(|(name, _, value)| (name, value))
                    .collect(),
            );
        }
        entries.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        for (index, pair) in entries.windows(2).enumerate() {
            if pair[0].0 == pair[1].0 {
                return Err(
                    CachedExpressionValuePayloadError::NonCanonicalAttrsPayloadName {
                        index: index + 1,
                    },
                );
            }
        }
        Ok(Self::from_payload(InlineValuePayload::PositionedAttrs(
            entries
                .into_iter()
                .map(|(name, position, value)| PositionedAttrPayloadEntry {
                    name,
                    position,
                    value: value.payload,
                })
                .collect(),
        )))
    }

    /// Creates a cached strict Nix attrset payload that preserves source order.
    ///
    /// This represents an attrset whose binding values are already replayable
    /// values and whose source-order permutation is observable. It does not
    /// represent binding positions or lazy binding thunks.
    ///
    /// # Errors
    ///
    /// Returns [`CachedExpressionValuePayloadError::NonCanonicalAttrsPayloadName`]
    /// if two bindings have the same attribute name.
    pub fn source_ordered_attrs(
        entries: Vec<(Vec<u8>, Self)>,
    ) -> Result<Self, CachedExpressionValuePayloadError> {
        if entries.is_empty() {
            return Ok(Self::empty_attrs());
        }
        ensure_unique_attr_payload_names(entries.iter().map(|(name, _)| name.as_slice()))?;
        Ok(Self::from_payload(InlineValuePayload::SourceOrderedAttrs(
            entries
                .into_iter()
                .map(|(name, value)| AttrPayloadEntry {
                    name,
                    value: value.payload,
                })
                .collect(),
        )))
    }

    /// Creates a cached strict Nix attrset payload with source order and positions.
    ///
    /// This represents an attrset whose binding values are already replayable
    /// values, whose source-order permutation is observable, and whose optional
    /// binding positions are observable through `builtins.unsafeGetAttrPos`.
    /// It does not represent lazy binding thunks. Inputs with no positions
    /// canonicalize to [`Self::source_ordered_attrs`].
    ///
    /// # Errors
    ///
    /// Returns [`CachedExpressionValuePayloadError::NonCanonicalAttrsPayloadName`]
    /// if two bindings have the same attribute name.
    pub fn source_ordered_positioned_attrs(
        entries: Vec<(Vec<u8>, Option<AttrPosition>, Self)>,
    ) -> Result<Self, CachedExpressionValuePayloadError> {
        if entries.is_empty() {
            return Ok(Self::empty_attrs());
        }
        if entries.iter().all(|(_, position, _)| position.is_none()) {
            return Self::source_ordered_attrs(
                entries
                    .into_iter()
                    .map(|(name, _, value)| (name, value))
                    .collect(),
            );
        }
        ensure_unique_attr_payload_names(entries.iter().map(|(name, _, _)| name.as_slice()))?;
        Ok(Self::from_payload(
            InlineValuePayload::SourceOrderedPositionedAttrs(
                entries
                    .into_iter()
                    .map(|(name, position, value)| PositionedAttrPayloadEntry {
                        name,
                        position,
                        value: value.payload,
                    })
                    .collect(),
            ),
        ))
    }

    /// Creates a cached empty Nix attrset payload.
    pub const fn empty_attrs() -> Self {
        Self {
            payload: InlineValuePayload::EmptyAttrs,
            attr_position_source_hash: None,
            value_hash: EMPTY_ATTRS_VALUE_HASH,
        }
    }

    pub(crate) fn with_attr_position_source_hash(
        mut self,
        source_hash: AttrPositionSourceHash,
    ) -> Self {
        if self.retains_attr_positions() {
            self.attr_position_source_hash = Some(source_hash);
            self.value_hash = Self::value_hash_for_attr_position_source(&self.payload, source_hash);
        }
        self
    }

    pub(crate) const fn attr_position_source_hash(&self) -> Option<AttrPositionSourceHash> {
        self.attr_position_source_hash
    }

    pub(crate) fn with_attr_repr_metadata(
        self,
        repr: AttrSetReprKind,
    ) -> Result<Self, CachedExpressionValuePayloadError> {
        let attr_position_source_hash = self.attr_position_source_hash;
        let mut value = Self::from_payload(self.payload.with_attr_repr(repr)?);
        if let Some(source_hash) = attr_position_source_hash {
            value = value.with_attr_position_source_hash(source_hash);
        }
        Ok(value)
    }

    pub(crate) fn attr_repr_kind(&self) -> Option<AttrSetReprKind> {
        self.payload.attr_repr_kind()
    }

    /// Returns the durable value hash for this cached payload.
    ///
    /// # Errors
    ///
    /// This is currently infallible because the hash is computed when the
    /// payload is constructed. The `Result` return type is retained for the
    /// existing cache-runtime API boundary.
    pub fn value_hash(&self) -> Result<ValueHash, ValueHashError> {
        Ok(self.value_hash)
    }

    /// Returns the canonical persistent payload byte length.
    ///
    /// This is the exact length of [`Self::encode_persistent_payload`] without
    /// allocating the encoded byte vector.
    pub fn persistent_payload_len(&self) -> u128 {
        let payload_len = self.payload.persistent_payload_len();
        if self.attr_position_source_hash.is_some() {
            ATTR_POSITION_SOURCE_PAYLOAD_ENVELOPE_TAG.len() as u128 + 32 + 16 + payload_len
        } else {
            payload_len
        }
    }

    /// Encodes this payload for the persistent `values/` pack.
    ///
    /// For persistent payloads, the encoded bytes are the canonical BLAKE3
    /// preimage used by [`Self::value_hash`]. Consequently
    /// `DurableBlake3Hash::for_bytes(encoded) == self.value_hash().as_durable_hash()`,
    /// allowing the persistent pack to address payload bytes by the same value
    /// hash the demand graph records.
    ///
    /// # Errors
    ///
    /// Returns [`CachedExpressionValuePayloadError`] if the encoded payload
    /// cannot reserve enough byte storage.
    pub fn encode_persistent_payload(&self) -> Result<Vec<u8>, CachedExpressionValuePayloadError> {
        let mut encoded = self.payload.encode_persistent_payload()?;
        let Some(source_hash) = self.attr_position_source_hash else {
            return Ok(encoded);
        };
        let mut out = Vec::new();
        append_payload_bytes(&mut out, ATTR_POSITION_SOURCE_PAYLOAD_ENVELOPE_TAG)?;
        append_payload_bytes(&mut out, &source_hash.as_durable_hash().as_bytes())?;
        append_payload_u128(&mut out, encoded.len() as u128)?;
        out.try_reserve_exact(encoded.len()).map_err(|_| {
            CachedExpressionValuePayloadError::PayloadAllocationFailed { len: encoded.len() }
        })?;
        out.append(&mut encoded);
        Ok(out)
    }

    /// Decodes a payload produced by [`Self::encode_persistent_payload`].
    ///
    /// # Errors
    ///
    /// Returns [`CachedExpressionValuePayloadError`] if `bytes` are not a
    /// complete, canonical cached-expression payload.
    pub fn decode_persistent_payload(
        bytes: &[u8],
    ) -> Result<Self, CachedExpressionValuePayloadError> {
        if bytes.starts_with(ATTR_POSITION_SOURCE_PAYLOAD_ENVELOPE_TAG) {
            let mut cursor = PayloadCursor::new(bytes);
            cursor.take_marker(
                ATTR_POSITION_SOURCE_PAYLOAD_ENVELOPE_TAG,
                "attr-position source envelope",
            )?;
            let source_hash = AttrPositionSourceHash::from_persisted_hash(
                DurableBlake3Hash::from_bytes(cursor.take_digest()?),
            );
            let len = cursor.take_len()?;
            let payload_bytes = cursor.take_bytes(len)?;
            let payload = InlineValuePayload::decode_persistent_payload(payload_bytes)?;
            if !payload.retains_attr_positions() {
                return Err(CachedExpressionValuePayloadError::PositionSourceWithoutPositions);
            }
            cursor.finish()?;
            return Ok(Self::from_payload_with_attr_position_source_hash(
                payload,
                source_hash,
            ));
        }
        Ok(Self::from_payload(
            InlineValuePayload::decode_persistent_payload(bytes)?,
        ))
    }

    /// Returns the active context-free scalar value, if this payload is scalar.
    ///
    /// Evaluator replay must use `scalar_value` and rehydrate through
    /// its heap. This compatibility accessor remains for cache-only callers
    /// that still consume the active two-word representation.
    pub fn immediate_value(&self) -> Option<Value> {
        self.payload.immediate_value()
    }

    /// Returns the canonical cached scalar without constructing a runtime value.
    pub(crate) fn scalar_value(&self) -> Option<CachedScalarValue> {
        match &self.payload {
            InlineValuePayload::Int(value) => Some(CachedScalarValue::Int(*value)),
            InlineValuePayload::Float(bits) => Some(CachedScalarValue::FloatBits(*bits)),
            InlineValuePayload::Bool(value) => Some(CachedScalarValue::Bool(*value)),
            InlineValuePayload::Null => Some(CachedScalarValue::Null),
            InlineValuePayload::ContextFreeString(_)
            | InlineValuePayload::ContextString { .. }
            | InlineValuePayload::Path(_)
            | InlineValuePayload::ContextPath { .. }
            | InlineValuePayload::EmptyList
            | InlineValuePayload::List(_)
            | InlineValuePayload::EmptyAttrs
            | InlineValuePayload::Attrs(_)
            | InlineValuePayload::SourceOrderedAttrs(_)
            | InlineValuePayload::PositionedAttrs(_)
            | InlineValuePayload::SourceOrderedPositionedAttrs(_)
            | InlineValuePayload::AttrRepr { .. } => None,
        }
    }

    /// Returns the cached context-free string bytes, if this payload is a string.
    pub fn context_free_string_bytes(&self) -> Option<&[u8]> {
        match &self.payload {
            InlineValuePayload::ContextFreeString(bytes) => Some(bytes),
            InlineValuePayload::ContextString { .. }
            | InlineValuePayload::Path(_)
            | InlineValuePayload::ContextPath { .. }
            | InlineValuePayload::EmptyList
            | InlineValuePayload::List(_)
            | InlineValuePayload::EmptyAttrs
            | InlineValuePayload::SourceOrderedAttrs(_)
            | InlineValuePayload::PositionedAttrs(_)
            | InlineValuePayload::SourceOrderedPositionedAttrs(_)
            | InlineValuePayload::Attrs(_)
            | InlineValuePayload::AttrRepr { .. }
            | InlineValuePayload::Int(_)
            | InlineValuePayload::Float(_)
            | InlineValuePayload::Bool(_)
            | InlineValuePayload::Null => None,
        }
    }

    /// Returns cached string bytes and context, if this payload is a contextual string.
    pub fn context_string_parts(&self) -> Option<(&[u8], &StringContext)> {
        match &self.payload {
            InlineValuePayload::ContextString { bytes, context } => Some((bytes, context)),
            InlineValuePayload::Int(_)
            | InlineValuePayload::Float(_)
            | InlineValuePayload::Bool(_)
            | InlineValuePayload::ContextFreeString(_)
            | InlineValuePayload::Path(_)
            | InlineValuePayload::ContextPath { .. }
            | InlineValuePayload::EmptyList
            | InlineValuePayload::List(_)
            | InlineValuePayload::EmptyAttrs
            | InlineValuePayload::SourceOrderedAttrs(_)
            | InlineValuePayload::PositionedAttrs(_)
            | InlineValuePayload::SourceOrderedPositionedAttrs(_)
            | InlineValuePayload::Attrs(_)
            | InlineValuePayload::AttrRepr { .. }
            | InlineValuePayload::Null => None,
        }
    }

    /// Returns the cached path bytes, if this payload is a context-free path.
    pub fn path_bytes(&self) -> Option<&[u8]> {
        match &self.payload {
            InlineValuePayload::Path(bytes) => Some(bytes),
            InlineValuePayload::Int(_)
            | InlineValuePayload::Float(_)
            | InlineValuePayload::Bool(_)
            | InlineValuePayload::ContextFreeString(_)
            | InlineValuePayload::ContextString { .. }
            | InlineValuePayload::ContextPath { .. }
            | InlineValuePayload::EmptyList
            | InlineValuePayload::List(_)
            | InlineValuePayload::EmptyAttrs
            | InlineValuePayload::SourceOrderedAttrs(_)
            | InlineValuePayload::PositionedAttrs(_)
            | InlineValuePayload::SourceOrderedPositionedAttrs(_)
            | InlineValuePayload::Attrs(_)
            | InlineValuePayload::AttrRepr { .. }
            | InlineValuePayload::Null => None,
        }
    }

    /// Returns cached path bytes and context, if this payload is a contextual path.
    pub fn context_path_parts(&self) -> Option<(&[u8], &StringContext)> {
        match &self.payload {
            InlineValuePayload::ContextPath { bytes, context } => Some((bytes, context)),
            InlineValuePayload::Int(_)
            | InlineValuePayload::Float(_)
            | InlineValuePayload::Bool(_)
            | InlineValuePayload::ContextFreeString(_)
            | InlineValuePayload::ContextString { .. }
            | InlineValuePayload::Path(_)
            | InlineValuePayload::EmptyList
            | InlineValuePayload::List(_)
            | InlineValuePayload::EmptyAttrs
            | InlineValuePayload::SourceOrderedAttrs(_)
            | InlineValuePayload::PositionedAttrs(_)
            | InlineValuePayload::SourceOrderedPositionedAttrs(_)
            | InlineValuePayload::Attrs(_)
            | InlineValuePayload::AttrRepr { .. }
            | InlineValuePayload::Null => None,
        }
    }

    /// Returns whether this payload is the empty Nix list.
    pub const fn is_empty_list(&self) -> bool {
        matches!(&self.payload, InlineValuePayload::EmptyList)
    }

    /// Returns the cached list spine length, if this payload is a list.
    pub fn list_len(&self) -> Option<usize> {
        match &self.payload {
            InlineValuePayload::EmptyList => Some(0),
            InlineValuePayload::List(elements) => Some(elements.len()),
            InlineValuePayload::Int(_)
            | InlineValuePayload::Float(_)
            | InlineValuePayload::Bool(_)
            | InlineValuePayload::Null
            | InlineValuePayload::ContextFreeString(_)
            | InlineValuePayload::ContextString { .. }
            | InlineValuePayload::Path(_)
            | InlineValuePayload::ContextPath { .. }
            | InlineValuePayload::EmptyAttrs
            | InlineValuePayload::SourceOrderedAttrs(_)
            | InlineValuePayload::PositionedAttrs(_)
            | InlineValuePayload::SourceOrderedPositionedAttrs(_)
            | InlineValuePayload::Attrs(_)
            | InlineValuePayload::AttrRepr { .. } => None,
        }
    }

    pub(crate) fn list_element_payloads(&self) -> Option<Vec<Self>> {
        match &self.payload {
            InlineValuePayload::EmptyList => Some(Vec::new()),
            InlineValuePayload::List(elements) => {
                let mut out = Vec::new();
                out.try_reserve_exact(elements.len()).ok()?;
                out.extend(
                    elements
                        .iter()
                        .cloned()
                        .map(CachedExpressionValue::from_payload),
                );
                Some(out)
            }
            InlineValuePayload::Int(_)
            | InlineValuePayload::Float(_)
            | InlineValuePayload::Bool(_)
            | InlineValuePayload::Null
            | InlineValuePayload::ContextFreeString(_)
            | InlineValuePayload::ContextString { .. }
            | InlineValuePayload::Path(_)
            | InlineValuePayload::ContextPath { .. }
            | InlineValuePayload::EmptyAttrs
            | InlineValuePayload::SourceOrderedAttrs(_)
            | InlineValuePayload::PositionedAttrs(_)
            | InlineValuePayload::SourceOrderedPositionedAttrs(_)
            | InlineValuePayload::Attrs(_)
            | InlineValuePayload::AttrRepr { .. } => None,
        }
    }

    /// Returns whether this payload is the empty Nix attrset.
    pub fn is_empty_attrs(&self) -> bool {
        match &self.payload {
            InlineValuePayload::EmptyAttrs => true,
            InlineValuePayload::AttrRepr { payload, .. } => {
                CachedExpressionValue::from_payload((**payload).clone()).is_empty_attrs()
            }
            _ => false,
        }
    }

    /// Returns the cached attrset binding count, if this payload is an attrset.
    pub fn attrs_len(&self) -> Option<usize> {
        match &self.payload {
            InlineValuePayload::AttrRepr { payload, .. } => {
                CachedExpressionValue::from_payload((**payload).clone()).attrs_len()
            }
            InlineValuePayload::EmptyAttrs => Some(0),
            InlineValuePayload::Attrs(entries)
            | InlineValuePayload::SourceOrderedAttrs(entries) => Some(entries.len()),
            InlineValuePayload::PositionedAttrs(entries)
            | InlineValuePayload::SourceOrderedPositionedAttrs(entries) => Some(entries.len()),
            InlineValuePayload::Int(_)
            | InlineValuePayload::Float(_)
            | InlineValuePayload::Bool(_)
            | InlineValuePayload::Null
            | InlineValuePayload::ContextFreeString(_)
            | InlineValuePayload::ContextString { .. }
            | InlineValuePayload::Path(_)
            | InlineValuePayload::ContextPath { .. }
            | InlineValuePayload::EmptyList
            | InlineValuePayload::List(_) => None,
        }
    }

    /// Returns cached attrset entries without binding positions, if this payload is an attrset.
    ///
    /// Position-bearing attrset payloads return `None` so callers do not
    /// accidentally drop provenance needed by `builtins.unsafeGetAttrPos`.
    pub fn attrs_entries(&self) -> Option<Vec<(Vec<u8>, Self)>> {
        match &self.payload {
            InlineValuePayload::AttrRepr { payload, .. } => {
                CachedExpressionValue::from_payload((**payload).clone()).attrs_entries()
            }
            InlineValuePayload::EmptyAttrs => Some(Vec::new()),
            InlineValuePayload::Attrs(entries)
            | InlineValuePayload::SourceOrderedAttrs(entries) => {
                let mut out = Vec::new();
                out.try_reserve_exact(entries.len()).ok()?;
                out.extend(entries.iter().map(|entry| {
                    (
                        entry.name.clone(),
                        CachedExpressionValue::from_payload(entry.value.clone()),
                    )
                }));
                Some(out)
            }
            InlineValuePayload::PositionedAttrs(_)
            | InlineValuePayload::SourceOrderedPositionedAttrs(_) => None,
            InlineValuePayload::Int(_)
            | InlineValuePayload::Float(_)
            | InlineValuePayload::Bool(_)
            | InlineValuePayload::Null
            | InlineValuePayload::ContextFreeString(_)
            | InlineValuePayload::ContextString { .. }
            | InlineValuePayload::Path(_)
            | InlineValuePayload::ContextPath { .. }
            | InlineValuePayload::EmptyList
            | InlineValuePayload::List(_) => None,
        }
    }

    /// Returns cached attrset entries and optional binding positions, if this payload is an attrset.
    pub fn attrs_entries_with_positions(&self) -> Option<Vec<CachedAttrEntryWithPosition>> {
        match &self.payload {
            InlineValuePayload::AttrRepr { payload, .. } => {
                CachedExpressionValue::from_payload((**payload).clone())
                    .attrs_entries_with_positions()
            }
            InlineValuePayload::EmptyAttrs => Some(Vec::new()),
            InlineValuePayload::Attrs(entries)
            | InlineValuePayload::SourceOrderedAttrs(entries) => {
                let mut out = Vec::new();
                out.try_reserve_exact(entries.len()).ok()?;
                out.extend(entries.iter().map(|entry| {
                    (
                        entry.name.clone(),
                        None,
                        CachedExpressionValue::from_payload(entry.value.clone()),
                    )
                }));
                Some(out)
            }
            InlineValuePayload::PositionedAttrs(entries)
            | InlineValuePayload::SourceOrderedPositionedAttrs(entries) => {
                let mut out = Vec::new();
                out.try_reserve_exact(entries.len()).ok()?;
                out.extend(entries.iter().map(|entry| {
                    (
                        entry.name.clone(),
                        entry.position,
                        CachedExpressionValue::from_payload(entry.value.clone()),
                    )
                }));
                Some(out)
            }
            InlineValuePayload::Int(_)
            | InlineValuePayload::Float(_)
            | InlineValuePayload::Bool(_)
            | InlineValuePayload::Null
            | InlineValuePayload::ContextFreeString(_)
            | InlineValuePayload::ContextString { .. }
            | InlineValuePayload::Path(_)
            | InlineValuePayload::ContextPath { .. }
            | InlineValuePayload::EmptyList
            | InlineValuePayload::List(_) => None,
        }
    }

    pub(crate) fn retains_attr_positions(&self) -> bool {
        self.payload.retains_attr_positions()
    }

    pub(crate) fn attr_positions_all_in_module(&self, module: u32) -> bool {
        self.payload.attr_positions_all_in_module(module)
    }

    pub(crate) fn collect_attr_position_modules(&self, modules: &mut BTreeSet<u32>) {
        self.payload.collect_attr_position_modules(modules);
    }

    pub(super) fn from_payload(payload: InlineValuePayload) -> Self {
        let value_hash = payload.value_hash_from_persistent_payload();
        Self {
            payload,
            attr_position_source_hash: None,
            value_hash,
        }
    }

    pub(super) fn from_payload_with_attr_position_source_hash(
        payload: InlineValuePayload,
        source_hash: AttrPositionSourceHash,
    ) -> Self {
        let value_hash = Self::value_hash_for_attr_position_source(&payload, source_hash);
        Self {
            payload,
            attr_position_source_hash: Some(source_hash),
            value_hash,
        }
    }

    fn value_hash_for_attr_position_source(
        payload: &InlineValuePayload,
        source_hash: AttrPositionSourceHash,
    ) -> ValueHash {
        let mut hasher = CacheDigestHasher::new();
        hasher.update(ATTR_POSITION_SOURCE_PAYLOAD_ENVELOPE_TAG);
        hasher.update(&source_hash.as_durable_hash().as_bytes());
        hasher.update(&payload.persistent_payload_len().to_le_bytes());
        payload.update_persistent_payload_preimage(&mut hasher);
        ValueHash::from_cached_expression_payload_hash(
            CachedExpressionPayloadValueHash::from_hasher(hasher),
        )
    }
}

#[cfg(test)]
mod scalar_constructor_tests {
    use super::{CachedExpressionValue, CachedScalarValue};

    #[test]
    fn canonical_scalar_constructors_preserve_full_width_payloads() {
        let integer = CachedExpressionValue::int(i64::MIN);
        assert_eq!(
            integer.scalar_value(),
            Some(CachedScalarValue::Int(i64::MIN))
        );

        let float_bits = 0xfff8_0000_0000_0042;
        let float = CachedExpressionValue::float(f64::from_bits(float_bits));
        assert_eq!(
            float.scalar_value(),
            Some(CachedScalarValue::FloatBits(float_bits))
        );
        assert_eq!(
            CachedExpressionValue::bool(true).scalar_value(),
            Some(CachedScalarValue::Bool(true))
        );
        assert_eq!(
            CachedExpressionValue::null().scalar_value(),
            Some(CachedScalarValue::Null)
        );
    }
}
