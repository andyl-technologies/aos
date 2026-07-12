//! Persistent cached-expression payload encoding tests.

use super::*;

// Baseline float/scalar ABI test; variant float path via scalars.rs + parity
// battery (cutover plan section 7).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn cached_expression_payloads_round_trip_through_persistent_encoding() {
    let payloads = vec![
        CachedExpressionValue::immediate(Value::int(-7)).expect("int payload builds"),
        CachedExpressionValue::immediate(Value::float(1.25)).expect("float payload builds"),
        CachedExpressionValue::immediate(Value::bool(false)).expect("bool payload builds"),
        CachedExpressionValue::immediate(Value::null()).expect("null payload builds"),
        CachedExpressionValue::context_free_string(b"plain bytes".to_vec()),
        CachedExpressionValue::context_string(b"context bytes".to_vec(), all_context_kinds()),
        CachedExpressionValue::path(b"/nix/store/path".to_vec()),
        CachedExpressionValue::context_path(
            b"/nix/store/context-path".to_vec(),
            all_context_kinds(),
        ),
        CachedExpressionValue::empty_list(),
        CachedExpressionValue::strict_list(vec![
            CachedExpressionValue::immediate(Value::int(1)).expect("int payload builds"),
            CachedExpressionValue::context_string(b"context element".to_vec(), all_context_kinds()),
            CachedExpressionValue::context_path(
                b"/nix/store/context-list-path".to_vec(),
                all_context_kinds(),
            ),
            CachedExpressionValue::strict_list(vec![
                CachedExpressionValue::empty_list(),
                CachedExpressionValue::empty_attrs(),
            ]),
        ]),
        CachedExpressionValue::empty_attrs(),
        CachedExpressionValue::strict_attrs(vec![
            (
                b"b".to_vec(),
                CachedExpressionValue::context_free_string(b"value".to_vec()),
            ),
            (
                b"a".to_vec(),
                CachedExpressionValue::strict_list(vec![
                    CachedExpressionValue::immediate(Value::bool(true))
                        .expect("bool payload builds"),
                    CachedExpressionValue::empty_attrs(),
                ]),
            ),
        ])
        .expect("strict attrs payload builds"),
        CachedExpressionValue::strict_attrs(vec![(
            b"a".to_vec(),
            CachedExpressionValue::immediate(Value::int(1)).expect("int payload builds"),
        )])
        .expect("HAMT attrs payload builds")
        .with_attr_repr_metadata(AttrSetReprKind::Hamt)
        .expect("HAMT attrs representation metadata attaches"),
        CachedExpressionValue::source_ordered_attrs(vec![
            (
                b"c".to_vec(),
                CachedExpressionValue::immediate(Value::int(2)).expect("int payload builds"),
            ),
            (
                b"b".to_vec(),
                CachedExpressionValue::strict_list(vec![
                    CachedExpressionValue::immediate(Value::bool(false))
                        .expect("bool payload builds"),
                ]),
            ),
        ])
        .expect("source-order attrs payload builds"),
        CachedExpressionValue::positioned_attrs(vec![
            (
                b"b".to_vec(),
                Some(AttrPosition::new(0, Span::new(8, 9))),
                CachedExpressionValue::context_free_string(b"value".to_vec()),
            ),
            (
                b"a".to_vec(),
                None,
                CachedExpressionValue::strict_list(vec![
                    CachedExpressionValue::immediate(Value::bool(true))
                        .expect("bool payload builds"),
                ]),
            ),
        ])
        .expect("positioned attrs payload builds"),
        CachedExpressionValue::source_ordered_positioned_attrs(vec![
            (
                b"c".to_vec(),
                Some(AttrPosition::new(0, Span::new(12, 13))),
                CachedExpressionValue::immediate(Value::int(2)).expect("int payload builds"),
            ),
            (
                b"b".to_vec(),
                Some(AttrPosition::new(0, Span::new(16, 17))),
                CachedExpressionValue::positioned_attrs(vec![(
                    b"a".to_vec(),
                    Some(AttrPosition::new(0, Span::new(20, 21))),
                    CachedExpressionValue::immediate(Value::int(1)).expect("int payload builds"),
                )])
                .expect("nested positioned attrs payload builds"),
            ),
        ])
        .expect("source-order positioned attrs payload builds"),
    ];

    for payload in payloads {
        let encoded = payload
            .encode_persistent_payload()
            .expect("payload encodes");
        assert_eq!(
            payload.persistent_payload_len(),
            encoded.len() as u128,
            "reported payload length matches canonical encoding"
        );
        assert_eq!(
            DurableBlake3Hash::for_bytes(&encoded),
            payload
                .value_hash()
                .expect("payload hashes")
                .as_durable_hash()
        );
        assert_eq!(
            CachedExpressionValue::decode_persistent_payload(&encoded).expect("payload decodes"),
            payload
        );
    }
}

#[test]
fn cached_expression_payload_constructors_canonicalize_empty_contexts() {
    let string =
        CachedExpressionValue::context_string(b"plain bytes".to_vec(), StringContext::empty());
    let path =
        CachedExpressionValue::context_path(b"/nix/store/path".to_vec(), StringContext::empty());

    assert_eq!(
        string.context_free_string_bytes(),
        Some(b"plain bytes".as_slice())
    );
    assert!(string.context_string_parts().is_none());
    assert_eq!(path.path_bytes(), Some(b"/nix/store/path".as_slice()));
    assert!(path.context_path_parts().is_none());
}

#[test]
fn cached_expression_payload_decode_rejects_unknown_domain() {
    let error = CachedExpressionValue::decode_persistent_payload(b"not-a-cache-payload")
        .expect_err("unknown domains error");

    assert_eq!(error, CachedExpressionValuePayloadError::UnknownDomain);
}

#[test]
fn cached_expression_payload_decode_rejects_trailing_bytes() {
    let mut encoded = CachedExpressionValue::immediate(Value::int(7))
        .expect("payload builds")
        .encode_persistent_payload()
        .expect("payload encodes");
    encoded.extend_from_slice(b"trailing");

    let error = CachedExpressionValue::decode_persistent_payload(&encoded)
        .expect_err("trailing bytes error");

    assert_eq!(
        error,
        CachedExpressionValuePayloadError::TrailingBytes {
            remaining: b"trailing".len()
        }
    );
}

#[test]
fn cached_expression_payload_decode_rejects_truncated_payload() {
    let mut encoded = CachedExpressionValue::context_free_string(b"abc".to_vec())
        .encode_persistent_payload()
        .expect("payload encodes");
    encoded.pop();

    let error = CachedExpressionValue::decode_persistent_payload(&encoded)
        .expect_err("truncated bytes error");

    assert!(matches!(
        error,
        CachedExpressionValuePayloadError::ShortPayload { .. }
    ));
}

#[test]
fn cached_expression_payload_decode_rejects_empty_contextual_domains() {
    for (encoded, payload) in [
        (
            context_string_payload_with_opaque_paths(&[]),
            "context string",
        ),
        (context_path_payload_with_opaque_paths(&[]), "context path"),
    ] {
        let error = CachedExpressionValue::decode_persistent_payload(&encoded)
            .expect_err("empty context errors");

        assert_eq!(
            error,
            CachedExpressionValuePayloadError::EmptyStringContext { payload }
        );
    }
}

#[test]
fn cached_expression_payload_decode_validates_context_elements() {
    let mut encoded = Vec::new();
    append_payload_bytes(&mut encoded, CONTEXT_STRING_VALUE_HASH_DOMAIN_VERSION)
        .expect("domain appends");
    append_payload_bytes(&mut encoded, b"string").expect("tag appends");
    append_payload_u128(&mut encoded, 0).expect("string length appends");
    append_payload_bytes(&mut encoded, b"context").expect("context tag appends");
    append_payload_u128(&mut encoded, 1).expect("context count appends");
    append_payload_byte(&mut encoded, 0).expect("context kind appends");
    append_payload_u128(&mut encoded, 0).expect("empty path length appends");

    let error = CachedExpressionValue::decode_persistent_payload(&encoded)
        .expect_err("empty context path errors");

    assert!(matches!(
        error,
        CachedExpressionValuePayloadError::Context {
            source: NixStringError::EmptyContextPath
        }
    ));
}

#[test]
fn cached_expression_payload_decode_rejects_unsorted_context_elements() {
    let encoded = context_string_payload_with_opaque_paths(&[
        b"/nix/store/z".as_slice(),
        b"/nix/store/a".as_slice(),
    ]);

    let error = CachedExpressionValue::decode_persistent_payload(&encoded)
        .expect_err("non-canonical context order errors");

    assert_eq!(
        error,
        CachedExpressionValuePayloadError::NonCanonicalStringContext { index: 1 }
    );
}

#[test]
fn cached_expression_payload_decode_rejects_duplicate_context_elements() {
    let encoded = context_string_payload_with_opaque_paths(&[
        b"/nix/store/a".as_slice(),
        b"/nix/store/a".as_slice(),
    ]);

    let error = CachedExpressionValue::decode_persistent_payload(&encoded)
        .expect_err("duplicate context element errors");

    assert_eq!(
        error,
        CachedExpressionValuePayloadError::NonCanonicalStringContext { index: 1 }
    );
}

#[test]
fn cached_expression_payload_decode_rejects_truncated_list_elements() {
    let encoded = list_payload_with_len(1);

    let error = CachedExpressionValue::decode_persistent_payload(&encoded)
        .expect_err("truncated list element payload errors");

    assert!(matches!(
        error,
        CachedExpressionValuePayloadError::ShortPayload { .. }
    ));
}

#[test]
fn cached_expression_payload_decode_rejects_excessive_list_nesting() {
    let mut payload = CachedExpressionValue::immediate(Value::int(1)).expect("int payload builds");
    for _ in 0..=MAX_CACHED_EXPRESSION_PAYLOAD_NESTING {
        payload = CachedExpressionValue::strict_list(vec![payload]);
    }
    let encoded = payload
        .encode_persistent_payload()
        .expect("deep list payload encodes");

    let error = CachedExpressionValue::decode_persistent_payload(&encoded)
        .expect_err("excessive nesting errors");

    assert_eq!(
        error,
        CachedExpressionValuePayloadError::PayloadNestingLimitExceeded {
            limit: MAX_CACHED_EXPRESSION_PAYLOAD_NESTING
        }
    );
}

#[test]
fn cached_expression_payload_decode_rejects_truncated_attrset_bindings() {
    let encoded = attrs_payload_with_len(1);

    let error = CachedExpressionValue::decode_persistent_payload(&encoded)
        .expect_err("truncated attrset binding payload errors");

    assert!(matches!(
        error,
        CachedExpressionValuePayloadError::ShortPayload { .. }
    ));
}

#[test]
fn cached_expression_payload_decode_rejects_noncanonical_attrset_names() {
    let mut encoded = Vec::new();
    append_payload_bytes(&mut encoded, ATTRS_VALUE_HASH_DOMAIN_VERSION).expect("domain appends");
    append_payload_bytes(&mut encoded, b"attrs").expect("tag appends");
    append_payload_u128(&mut encoded, 2).expect("attrs length appends");
    let value = CachedExpressionValue::immediate(Value::int(1))
        .expect("int payload builds")
        .encode_persistent_payload()
        .expect("value encodes");
    for name in [b"b".as_slice(), b"a".as_slice()] {
        append_payload_u128(&mut encoded, name.len() as u128).expect("name length appends");
        append_payload_bytes(&mut encoded, name).expect("name appends");
        append_payload_u128(&mut encoded, value.len() as u128).expect("value length appends");
        append_payload_bytes(&mut encoded, &value).expect("value appends");
    }

    let error = CachedExpressionValue::decode_persistent_payload(&encoded)
        .expect_err("out-of-order attrset names error");

    assert_eq!(
        error,
        CachedExpressionValuePayloadError::NonCanonicalAttrsPayloadName { index: 1 }
    );
}

#[test]
fn cached_expression_payload_decode_rejects_duplicate_source_ordered_attrset_names() {
    let mut encoded = Vec::new();
    append_payload_bytes(&mut encoded, ATTRS_VALUE_HASH_DOMAIN_VERSION).expect("domain appends");
    append_payload_bytes(&mut encoded, SOURCE_ORDERED_ATTRS_PAYLOAD_TAG).expect("tag appends");
    append_payload_u128(&mut encoded, 2).expect("attrs length appends");
    let value = CachedExpressionValue::immediate(Value::int(1))
        .expect("int payload builds")
        .encode_persistent_payload()
        .expect("value encodes");
    for name in [b"a".as_slice(), b"a".as_slice()] {
        append_payload_u128(&mut encoded, name.len() as u128).expect("name length appends");
        append_payload_bytes(&mut encoded, name).expect("name appends");
        append_payload_u128(&mut encoded, value.len() as u128).expect("value length appends");
        append_payload_bytes(&mut encoded, &value).expect("value appends");
    }

    let error = CachedExpressionValue::decode_persistent_payload(&encoded)
        .expect_err("duplicate source-order attrset names error");

    assert_eq!(
        error,
        CachedExpressionValuePayloadError::NonCanonicalAttrsPayloadName { index: 1 }
    );
}

#[test]
fn cached_expression_payload_decode_rejects_flat_attr_repr_envelope() {
    let payload = CachedExpressionValue::empty_attrs()
        .encode_persistent_payload()
        .expect("empty attrs payload encodes");
    let encoded = attr_repr_envelope_payload(0, &payload);

    let error = CachedExpressionValue::decode_persistent_payload(&encoded)
        .expect_err("flat attr representation envelope errors");

    assert_eq!(
        error,
        CachedExpressionValuePayloadError::NonCanonicalAttrReprEnvelope
    );
}

#[test]
fn cached_expression_payload_decode_rejects_nested_attr_repr_envelope() {
    let payload = CachedExpressionValue::strict_attrs(vec![(
        b"a".to_vec(),
        CachedExpressionValue::immediate(Value::int(1)).expect("int payload builds"),
    )])
    .expect("attrs payload builds")
    .with_attr_repr_metadata(AttrSetReprKind::Hamt)
    .expect("HAMT attrs representation metadata attaches")
    .encode_persistent_payload()
    .expect("HAMT attr repr payload encodes");
    let encoded = attr_repr_envelope_payload(1, &payload);

    let error = CachedExpressionValue::decode_persistent_payload(&encoded)
        .expect_err("nested attr representation envelope errors");

    assert_eq!(
        error,
        CachedExpressionValuePayloadError::NonCanonicalAttrReprEnvelope
    );
}

#[test]
fn cached_expression_payload_decode_rejects_invalid_attr_position_tag() {
    let mut encoded = Vec::new();
    append_payload_bytes(&mut encoded, ATTRS_VALUE_HASH_DOMAIN_VERSION).expect("domain appends");
    append_payload_bytes(&mut encoded, POSITIONED_ATTRS_PAYLOAD_TAG).expect("tag appends");
    append_payload_u128(&mut encoded, 1).expect("attrs length appends");
    append_length_prefixed_payload_bytes(&mut encoded, b"a").expect("name appends");
    append_payload_byte(&mut encoded, 9).expect("invalid position tag appends");

    let error = CachedExpressionValue::decode_persistent_payload(&encoded)
        .expect_err("invalid attr position tag errors");

    assert_eq!(
        error,
        CachedExpressionValuePayloadError::InvalidTag {
            section: "attr position",
            tag: 9,
        }
    );
}

#[test]
fn cached_expression_payload_decode_rejects_positioned_attrset_without_positions() {
    let value = CachedExpressionValue::immediate(Value::int(1))
        .expect("int payload builds")
        .encode_persistent_payload()
        .expect("value encodes");
    let mut empty_positioned = Vec::new();
    append_payload_bytes(&mut empty_positioned, ATTRS_VALUE_HASH_DOMAIN_VERSION)
        .expect("domain appends");
    append_payload_bytes(&mut empty_positioned, POSITIONED_ATTRS_PAYLOAD_TAG).expect("tag appends");
    append_payload_u128(&mut empty_positioned, 0).expect("attrs length appends");
    let mut all_none = Vec::new();
    append_payload_bytes(&mut all_none, ATTRS_VALUE_HASH_DOMAIN_VERSION).expect("domain appends");
    append_payload_bytes(&mut all_none, SOURCE_ORDERED_POSITIONED_ATTRS_PAYLOAD_TAG)
        .expect("tag appends");
    append_payload_u128(&mut all_none, 1).expect("attrs length appends");
    append_length_prefixed_payload_bytes(&mut all_none, b"a").expect("name appends");
    append_payload_byte(&mut all_none, 0).expect("absent position tag appends");
    append_length_prefixed_payload_bytes(&mut all_none, &value).expect("value appends");

    for encoded in [empty_positioned, all_none] {
        let error = CachedExpressionValue::decode_persistent_payload(&encoded)
            .expect_err("positionless positioned attrset errors");

        assert_eq!(
            error,
            CachedExpressionValuePayloadError::PositionlessPositionedAttrsPayload
        );
    }
}

fn attr_repr_envelope_payload(repr: u8, payload: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::new();
    append_payload_bytes(&mut encoded, ATTR_REPR_PAYLOAD_ENVELOPE_TAG).expect("tag appends");
    append_payload_byte(&mut encoded, repr).expect("repr appends");
    append_payload_u128(&mut encoded, payload.len() as u128).expect("payload length appends");
    append_payload_bytes(&mut encoded, payload).expect("payload appends");
    encoded
}
