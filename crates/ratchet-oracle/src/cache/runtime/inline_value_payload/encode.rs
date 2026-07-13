//! `InlineValuePayload` persistent-payload length + encode, split from the parent for the §2 line cap.

use super::*;

impl InlineValuePayload {
    pub(in crate::cache::runtime) fn update_persistent_payload_preimage(&self, hasher: &mut blake3::Hasher) {
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

    pub(in crate::cache::runtime) fn persistent_payload_len(&self) -> u128 {
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

    pub(in crate::cache::runtime) fn encode_persistent_payload(
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
}
