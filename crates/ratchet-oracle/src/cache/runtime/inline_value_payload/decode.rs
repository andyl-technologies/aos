//! `InlineValuePayload` persistent-payload decode, split from the parent for the §2 line cap.

use super::*;

impl InlineValuePayload {
    pub(in crate::cache::runtime) fn decode_persistent_payload(
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
}
