//! Inline cached expression payload representation and codec helpers.

use crate::cache::hashing::CacheDigestHasher;
use super::*;
use crate::cache::hashing::CachedExpressionPayloadValueHash;

mod payload_cursor;
mod decode;
mod encode;

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
        let mut hasher = CacheDigestHasher::new();
        self.update_persistent_payload_preimage(&mut hasher);
        ValueHash::from_cached_expression_payload_hash(
            CachedExpressionPayloadValueHash::from_hasher(hasher),
        )
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
    hasher: &mut CacheDigestHasher,
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

fn update_attr_position_preimage(hasher: &mut CacheDigestHasher, position: Option<AttrPosition>) {
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

fn update_string_context_payload_preimage(hasher: &mut CacheDigestHasher, context: &StringContext) {
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
