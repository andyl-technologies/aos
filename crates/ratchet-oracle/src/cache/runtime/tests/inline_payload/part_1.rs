//! Split-out tests (part_1). See parent module.

use super::*;

#[test]
fn eval_cache_observes_inline_expression_results() {
    let mut cache = EvalCache::new();
    let identity = identity(b"source", 7);

    let first = cache
        .observe_inline_expression_result(identity, std::iter::empty::<ValueHash>(), Value::int(3))
        .expect("first result observes");
    let second = cache
        .observe_inline_expression_result(identity, std::iter::empty::<ValueHash>(), Value::int(3))
        .expect("second result observes");

    assert_eq!(first.decision(), crate::cache::CutoffDecision::Propagate);
    assert_eq!(second.node(), first.node());
    assert_eq!(second.decision(), crate::cache::CutoffDecision::CutOff);
    assert_eq!(cache.len(), 1);
}

#[test]
fn eval_cache_looks_up_clean_inline_expression_results() {
    let mut cache = EvalCache::new();
    let identity = identity(b"source", 7);

    cache
        .observe_inline_expression_result(identity, std::iter::empty::<ValueHash>(), Value::int(3))
        .expect("result observes");
    let value = cache
        .lookup_inline_expression_result(identity, std::iter::empty::<ValueHash>())
        .expect("lookup succeeds")
        .expect("memoized inline result is present");

    assert_eq!(value.as_int(), Ok(3));
}

#[test]
fn eval_cache_payload_hits_return_supplier_node_for_memo_read_edges() {
    let mut cache = EvalCache::new();
    let parent_identity = identity(b"parent", 1);
    let child_identity = identity(b"child", 2);
    let child_observation = cache
        .observe_inline_expression_payload(
            child_identity,
            std::iter::empty::<ValueHash>(),
            CachedExpressionValue::immediate(Value::int(3)).expect("int payload builds"),
        )
        .expect("child payload observes");
    let child_node = child_observation.node();
    let parent_node = cache
        .get_or_insert_expression_node(parent_identity, std::iter::empty::<ValueHash>(), None)
        .expect("parent node inserts");

    let hit = cache
        .lookup_inline_expression_payload_hit(child_identity, std::iter::empty::<ValueHash>())
        .expect("payload hit lookup succeeds")
        .expect("child payload hit is present");
    cache
        .record_memo_read_dependency(parent_node, hit.node())
        .expect("memo-read edge records");

    assert_eq!(hit.node(), child_node);
    assert_eq!(
        hit.into_value()
            .immediate_value()
            .expect("hit payload is immediate")
            .as_int(),
        Ok(3)
    );
    let parent = cache
        .graph()
        .node(parent_node)
        .expect("parent node is present");
    assert!(parent.dependencies().contains(&child_node));
    assert!(
        parent
            .dependencies_in_group(DemandDependencyGroup::MemoRead)
            .expect("memo-read group exists")
            .contains(&child_node)
    );
}

#[test]
fn clean_inline_payload_with_dirty_memo_supplier_misses_and_purges_record() {
    let mut cache = EvalCache::new();
    let supplier = cache
        .graph
        .get_or_insert_node(
            DemandCacheKey::for_free_vars(identity(b"supplier", 1), [value_hash(b"supplier")])
                .expect("supplier key builds"),
            Some(value_hash(b"supplier")),
        )
        .expect("supplier inserts");
    let expression_identity = identity(b"dependent", 2);
    let observation = cache
        .observe_inline_expression_result(
            expression_identity,
            std::iter::empty::<ValueHash>(),
            Value::int(3),
        )
        .expect("dependent payload observes");
    cache
        .record_memo_read_dependency(observation.node(), supplier)
        .expect("memo-read edge records");
    cache
        .test_mark_dirty_node(supplier)
        .expect("supplier marks dirty");
    assert_eq!(
        cache
            .graph()
            .node(observation.node())
            .expect("dependent node exists")
            .freshness(),
        NodeFreshness::Clean
    );

    let value = cache
        .lookup_inline_expression_result(expression_identity, std::iter::empty::<ValueHash>())
        .expect("lookup succeeds");

    assert!(value.is_none());
    assert_eq!(cache.inline_payload_record_count(), 0);
    assert_eq!(
        cache
            .graph()
            .node(observation.node())
            .expect("dependent node exists")
            .freshness(),
        NodeFreshness::Dirty
    );
}

#[test]
fn clean_inline_payload_with_transitively_dirty_memo_supplier_misses_and_purges_record() {
    let mut cache = EvalCache::new();
    let root = cache
        .get_or_insert_expression_node(
            identity(b"dirty-root", 1),
            std::iter::empty::<ValueHash>(),
            Some(value_hash(b"dirty-root")),
        )
        .expect("root inserts");
    let supplier = cache
        .get_or_insert_expression_node(
            identity(b"clean-supplier", 2),
            std::iter::empty::<ValueHash>(),
            Some(value_hash(b"clean-supplier")),
        )
        .expect("supplier inserts");
    cache
        .record_memo_read_dependency(supplier, root)
        .expect("supplier memo-read edge records");
    let expression_identity = identity(b"transitive-dependent", 3);
    let observation = cache
        .observe_inline_expression_result(
            expression_identity,
            std::iter::empty::<ValueHash>(),
            Value::int(3),
        )
        .expect("dependent payload observes");
    cache
        .record_memo_read_dependency(observation.node(), supplier)
        .expect("dependent memo-read edge records");
    cache.test_mark_dirty_node(root).expect("root marks dirty");
    assert_eq!(
        cache
            .graph()
            .node(supplier)
            .expect("supplier node exists")
            .freshness(),
        NodeFreshness::Clean
    );
    assert_eq!(
        cache
            .graph()
            .node(observation.node())
            .expect("dependent node exists")
            .freshness(),
        NodeFreshness::Clean
    );

    let value = cache
        .lookup_inline_expression_result(expression_identity, std::iter::empty::<ValueHash>())
        .expect("lookup succeeds");

    assert!(value.is_none());
    assert_eq!(cache.inline_payload_record_count(), 0);
    assert_eq!(
        cache
            .graph()
            .node(observation.node())
            .expect("dependent node exists")
            .freshness(),
        NodeFreshness::Dirty
    );
}

#[test]
fn eval_cache_looks_up_context_free_string_payloads() {
    let mut cache = EvalCache::new();
    let identity = identity(b"source", 7);

    cache
        .observe_inline_expression_payload(
            identity,
            std::iter::empty::<ValueHash>(),
            CachedExpressionValue::context_free_string(b"cached string".to_vec()),
        )
        .expect("string payload observes");
    let payload = cache
        .lookup_inline_expression_payload(identity, std::iter::empty::<ValueHash>())
        .expect("payload lookup succeeds")
        .expect("memoized string payload is present");
    let immediate = cache
        .lookup_inline_expression_result(identity, std::iter::empty::<ValueHash>())
        .expect("immediate lookup succeeds");

    assert_eq!(
        payload.context_free_string_bytes(),
        Some(b"cached string".as_slice())
    );
    assert!(payload.immediate_value().is_none());
    assert!(
        immediate.is_none(),
        "generic Value lookup must not return heap-backed payload pointers"
    );
}

#[test]
fn eval_cache_looks_up_context_string_payloads() {
    let mut cache = EvalCache::new();
    let identity = identity(b"source", 7);
    let context = opaque_context(b"/nix/store/source");

    cache
        .observe_inline_expression_payload(
            identity,
            std::iter::empty::<ValueHash>(),
            CachedExpressionValue::context_string(b"cached string".to_vec(), context.clone()),
        )
        .expect("context string payload observes");
    let payload = cache
        .lookup_inline_expression_payload(identity, std::iter::empty::<ValueHash>())
        .expect("payload lookup succeeds")
        .expect("memoized context string payload is present");
    let immediate = cache
        .lookup_inline_expression_result(identity, std::iter::empty::<ValueHash>())
        .expect("immediate lookup succeeds");
    let (bytes, cached_context) = payload
        .context_string_parts()
        .expect("context string payload is present");

    assert_eq!(bytes, b"cached string");
    assert_eq!(cached_context, &context);
    assert!(payload.context_free_string_bytes().is_none());
    assert!(payload.path_bytes().is_none());
    assert!(payload.immediate_value().is_none());
    assert!(
        immediate.is_none(),
        "generic Value lookup must not return heap-backed payload pointers"
    );
}

#[test]
fn eval_cache_looks_up_path_payloads() {
    let mut cache = EvalCache::new();
    let identity = identity(b"source", 7);

    cache
        .observe_inline_expression_payload(
            identity,
            std::iter::empty::<ValueHash>(),
            CachedExpressionValue::path(b"/tmp/cached-path".to_vec()),
        )
        .expect("path payload observes");
    let payload = cache
        .lookup_inline_expression_payload(identity, std::iter::empty::<ValueHash>())
        .expect("payload lookup succeeds")
        .expect("memoized path payload is present");
    let immediate = cache
        .lookup_inline_expression_result(identity, std::iter::empty::<ValueHash>())
        .expect("immediate lookup succeeds");

    assert_eq!(payload.path_bytes(), Some(b"/tmp/cached-path".as_slice()));
    assert!(payload.context_free_string_bytes().is_none());
    assert!(payload.immediate_value().is_none());
    assert!(
        immediate.is_none(),
        "generic Value lookup must not return heap-backed payload pointers"
    );
}

#[test]
fn eval_cache_looks_up_context_path_payloads() {
    let mut cache = EvalCache::new();
    let identity = identity(b"source", 7);
    let context = opaque_context(b"/nix/store/source");

    cache
        .observe_inline_expression_payload(
            identity,
            std::iter::empty::<ValueHash>(),
            CachedExpressionValue::context_path(
                b"/nix/store/context-path".to_vec(),
                context.clone(),
            ),
        )
        .expect("context path payload observes");
    let payload = cache
        .lookup_inline_expression_payload(identity, std::iter::empty::<ValueHash>())
        .expect("payload lookup succeeds")
        .expect("memoized context path payload is present");
    let immediate = cache
        .lookup_inline_expression_result(identity, std::iter::empty::<ValueHash>())
        .expect("immediate lookup succeeds");
    let (bytes, cached_context) = payload
        .context_path_parts()
        .expect("context path payload is present");

    assert_eq!(bytes, b"/nix/store/context-path");
    assert_eq!(cached_context, &context);
    assert!(payload.context_string_parts().is_none());
    assert!(payload.path_bytes().is_none());
    assert!(payload.immediate_value().is_none());
    assert!(
        immediate.is_none(),
        "generic Value lookup must not return heap-backed payload pointers"
    );
}

#[test]
fn eval_cache_looks_up_empty_list_payloads() {
    let mut cache = EvalCache::new();
    let identity = identity(b"source", 7);

    cache
        .observe_inline_expression_payload(
            identity,
            std::iter::empty::<ValueHash>(),
            CachedExpressionValue::empty_list(),
        )
        .expect("empty list payload observes");
    let payload = cache
        .lookup_inline_expression_payload(identity, std::iter::empty::<ValueHash>())
        .expect("payload lookup succeeds")
        .expect("memoized empty list payload is present");
    let immediate = cache
        .lookup_inline_expression_result(identity, std::iter::empty::<ValueHash>())
        .expect("immediate lookup succeeds");

    assert!(payload.is_empty_list());
    assert!(payload.context_free_string_bytes().is_none());
    assert!(payload.context_string_parts().is_none());
    assert!(payload.path_bytes().is_none());
    assert!(payload.context_path_parts().is_none());
    assert!(payload.immediate_value().is_none());
    assert!(
        immediate.is_none(),
        "generic Value lookup must not return heap-backed payload pointers"
    );
}

#[test]
fn eval_cache_looks_up_strict_list_payloads() {
    let mut cache = EvalCache::new();
    let identity = identity(b"source", 7);

    cache
        .observe_inline_expression_payload(
            identity,
            std::iter::empty::<ValueHash>(),
            CachedExpressionValue::strict_list(vec![
                CachedExpressionValue::immediate(Value::int(1)).expect("int payload builds"),
                CachedExpressionValue::context_free_string(b"element".to_vec()),
            ]),
        )
        .expect("strict list payload observes");
    let payload = cache
        .lookup_inline_expression_payload(identity, std::iter::empty::<ValueHash>())
        .expect("payload lookup succeeds")
        .expect("memoized strict list payload is present");
    let immediate = cache
        .lookup_inline_expression_result(identity, std::iter::empty::<ValueHash>())
        .expect("immediate lookup succeeds");

    assert_eq!(payload.list_len(), Some(2));
    assert!(!payload.is_empty_list());
    assert!(payload.context_free_string_bytes().is_none());
    assert!(payload.context_string_parts().is_none());
    assert!(payload.path_bytes().is_none());
    assert!(payload.context_path_parts().is_none());
    assert!(payload.immediate_value().is_none());
    assert!(
        immediate.is_none(),
        "generic Value lookup must not return heap-backed payload pointers"
    );
}

#[test]
fn eval_cache_looks_up_empty_attrs_payloads() {
    let mut cache = EvalCache::new();
    let identity = identity(b"source", 7);

    cache
        .observe_inline_expression_payload(
            identity,
            std::iter::empty::<ValueHash>(),
            CachedExpressionValue::empty_attrs(),
        )
        .expect("empty attrset payload observes");
    let payload = cache
        .lookup_inline_expression_payload(identity, std::iter::empty::<ValueHash>())
        .expect("payload lookup succeeds")
        .expect("memoized empty attrset payload is present");
    let immediate = cache
        .lookup_inline_expression_result(identity, std::iter::empty::<ValueHash>())
        .expect("immediate lookup succeeds");

    assert!(payload.is_empty_attrs());
    assert!(!payload.is_empty_list());
    assert!(payload.context_free_string_bytes().is_none());
    assert!(payload.context_string_parts().is_none());
    assert!(payload.path_bytes().is_none());
    assert!(payload.context_path_parts().is_none());
    assert!(payload.immediate_value().is_none());
    assert!(
        immediate.is_none(),
        "generic Value lookup must not return heap-backed payload pointers"
    );
}

#[test]
fn eval_cache_looks_up_strict_attrs_payloads() {
    let mut cache = EvalCache::new();
    let identity = identity(b"source", 7);

    cache
        .observe_inline_expression_payload(
            identity,
            std::iter::empty::<ValueHash>(),
            CachedExpressionValue::strict_attrs(vec![
                (
                    b"b".to_vec(),
                    CachedExpressionValue::context_free_string(b"value".to_vec()),
                ),
                (
                    b"a".to_vec(),
                    CachedExpressionValue::immediate(Value::int(1)).expect("int payload builds"),
                ),
            ])
            .expect("strict attrs payload builds"),
        )
        .expect("strict attrset payload observes");
    let payload = cache
        .lookup_inline_expression_payload(identity, std::iter::empty::<ValueHash>())
        .expect("payload lookup succeeds")
        .expect("memoized strict attrset payload is present");
    let immediate = cache
        .lookup_inline_expression_result(identity, std::iter::empty::<ValueHash>())
        .expect("immediate lookup succeeds");

    assert_eq!(payload.attrs_len(), Some(2));
    assert!(!payload.is_empty_attrs());
    assert!(!payload.is_empty_list());
    assert!(payload.context_free_string_bytes().is_none());
    assert!(payload.context_string_parts().is_none());
    assert!(payload.path_bytes().is_none());
    assert!(payload.context_path_parts().is_none());
    assert!(payload.immediate_value().is_none());
    assert!(
        immediate.is_none(),
        "generic Value lookup must not return heap-backed payload pointers"
    );
}

#[test]
fn eval_cache_looks_up_source_ordered_attrs_payloads() {
    let mut cache = EvalCache::new();
    let identity = identity(b"source", 8);

    cache
        .observe_inline_expression_payload(
            identity,
            std::iter::empty::<ValueHash>(),
            CachedExpressionValue::source_ordered_attrs(vec![
                (
                    b"c".to_vec(),
                    CachedExpressionValue::immediate(Value::int(2)).expect("int payload builds"),
                ),
                (
                    b"b".to_vec(),
                    CachedExpressionValue::immediate(Value::int(1)).expect("int payload builds"),
                ),
            ])
            .expect("source-order attrs payload builds"),
        )
        .expect("source-order attrset payload observes");
    let payload = cache
        .lookup_inline_expression_payload(identity, std::iter::empty::<ValueHash>())
        .expect("payload lookup succeeds")
        .expect("memoized source-order attrset payload is present");
    let entries = payload
        .attrs_entries()
        .expect("payload carries attrset entries");
    let entry_names: Vec<_> = entries.iter().map(|(name, _)| name.as_slice()).collect();

    assert_eq!(payload.attrs_len(), Some(2));
    assert_eq!(entry_names, vec![b"c".as_slice(), b"b".as_slice()]);
    assert!(payload.context_free_string_bytes().is_none());
    assert!(payload.context_string_parts().is_none());
    assert!(payload.path_bytes().is_none());
    assert!(payload.context_path_parts().is_none());
    assert!(payload.immediate_value().is_none());
}

#[test]
fn eval_cache_looks_up_positioned_attrs_payloads() {
    let mut cache = EvalCache::new();
    let identity = identity(b"source", 9);
    let position = AttrPosition::new(0, Span::new(4, 5));

    cache
        .observe_inline_expression_payload(
            identity,
            std::iter::empty::<ValueHash>(),
            CachedExpressionValue::positioned_attrs(vec![(
                b"a".to_vec(),
                Some(position),
                CachedExpressionValue::immediate(Value::int(1)).expect("int payload builds"),
            )])
            .expect("positioned attrs payload builds"),
        )
        .expect("positioned attrset payload observes");
    let payload = cache
        .lookup_inline_expression_payload(identity, std::iter::empty::<ValueHash>())
        .expect("payload lookup succeeds")
        .expect("memoized positioned attrset payload is present");
    let entries = payload
        .attrs_entries_with_positions()
        .expect("payload carries positioned attrset entries");

    assert_eq!(payload.attrs_len(), Some(1));
    assert_eq!(entries[0].0, b"a");
    assert_eq!(entries[0].1, Some(position));
    assert_eq!(
        entries[0]
            .2
            .immediate_value()
            .expect("entry value is immediate")
            .as_int(),
        Ok(1)
    );
    assert!(
        payload.attrs_entries().is_none(),
        "positioned payloads must not silently drop binding positions"
    );
}

#[test]
fn source_ordered_positioned_attrs_preserve_order_and_hash_positions() {
    let first_position = AttrPosition::new(0, Span::new(4, 5));
    let second_position = AttrPosition::new(0, Span::new(8, 9));
    let changed_position = AttrPosition::new(0, Span::new(10, 11));
    let first = CachedExpressionValue::source_ordered_positioned_attrs(vec![
        (
            b"c".to_vec(),
            Some(first_position),
            CachedExpressionValue::immediate(Value::int(2)).expect("int payload builds"),
        ),
        (
            b"b".to_vec(),
            Some(second_position),
            CachedExpressionValue::immediate(Value::int(1)).expect("int payload builds"),
        ),
    ])
    .expect("source-ordered positioned attrs payload builds");
    let same = CachedExpressionValue::source_ordered_positioned_attrs(vec![
        (
            b"c".to_vec(),
            Some(first_position),
            CachedExpressionValue::immediate(Value::int(2)).expect("int payload builds"),
        ),
        (
            b"b".to_vec(),
            Some(second_position),
            CachedExpressionValue::immediate(Value::int(1)).expect("int payload builds"),
        ),
    ])
    .expect("matching source-ordered positioned attrs payload builds");
    let changed = CachedExpressionValue::source_ordered_positioned_attrs(vec![
        (
            b"c".to_vec(),
            Some(first_position),
            CachedExpressionValue::immediate(Value::int(2)).expect("int payload builds"),
        ),
        (
            b"b".to_vec(),
            Some(changed_position),
            CachedExpressionValue::immediate(Value::int(1)).expect("int payload builds"),
        ),
    ])
    .expect("changed source-ordered positioned attrs payload builds");

    let entries = first
        .attrs_entries_with_positions()
        .expect("payload carries positioned attrset entries");
    let entry_names: Vec<_> = entries.iter().map(|(name, _, _)| name.as_slice()).collect();

    assert_eq!(entry_names, vec![b"c".as_slice(), b"b".as_slice()]);
    assert_eq!(
        first.value_hash().expect("positioned attrset hashes"),
        same.value_hash()
            .expect("matching positioned attrset hashes")
    );
    assert_ne!(
        first.value_hash().expect("positioned attrset hashes"),
        changed
            .value_hash()
            .expect("changed positioned attrset hashes"),
        "binding positions must participate in positioned attrset hashes"
    );
}

#[test]
fn positioned_attrs_payloads_round_trip_through_persistent_encoding() {
    let first_position = AttrPosition::new(0, Span::new(4, 5));
    let second_position = AttrPosition::new(0, Span::new(8, 9));
    let payload = CachedExpressionValue::source_ordered_positioned_attrs(vec![
        (
            b"c".to_vec(),
            Some(first_position),
            CachedExpressionValue::immediate(Value::int(2)).expect("int payload builds"),
        ),
        (
            b"b".to_vec(),
            Some(second_position),
            CachedExpressionValue::immediate(Value::int(1)).expect("int payload builds"),
        ),
    ])
    .expect("source-ordered positioned attrs payload builds");

    let encoded = payload
        .encode_persistent_payload()
        .expect("positioned attrset payload encodes");
    let decoded = CachedExpressionValue::decode_persistent_payload(&encoded)
        .expect("positioned attrset payload decodes");
    let entries = decoded
        .attrs_entries_with_positions()
        .expect("decoded payload carries positioned attrset entries");
    let entry_names: Vec<_> = entries.iter().map(|(name, _, _)| name.as_slice()).collect();

    assert_eq!(
        DurableBlake3Hash::for_bytes(&encoded),
        payload
            .value_hash()
            .expect("positioned attrset payload hashes")
            .as_durable_hash()
    );
    assert_eq!(decoded, payload);
    assert_eq!(entry_names, vec![b"c".as_slice(), b"b".as_slice()]);
    assert_eq!(entries[0].1, Some(first_position));
    assert_eq!(entries[1].1, Some(second_position));
}

#[test]
fn attr_position_source_envelope_reports_persistent_payload_length() {
    let payload = CachedExpressionValue::positioned_attrs(vec![(
        b"a".to_vec(),
        Some(AttrPosition::new(0, Span::new(4, 5))),
        CachedExpressionValue::immediate(Value::int(1)).expect("int payload builds"),
    )])
    .expect("positioned attrs payload builds")
    .with_attr_position_source_hash(AttrPositionSourceHash::from_persisted_hash(
        DurableBlake3Hash::for_bytes(b"source"),
    ));
    let encoded = payload
        .encode_persistent_payload()
        .expect("position-source payload encodes");

    assert_eq!(payload.persistent_payload_len(), encoded.len() as u128);
    assert_eq!(
        DurableBlake3Hash::for_bytes(&encoded),
        payload
            .value_hash()
            .expect("position-source payload hashes")
            .as_durable_hash()
    );
    assert_eq!(
        CachedExpressionValue::decode_persistent_payload(&encoded)
            .expect("position-source payload decodes"),
        payload
    );
}

#[test]
fn attr_position_source_envelope_decode_preserves_cached_value_hash() {
    let source_hash =
        AttrPositionSourceHash::from_persisted_hash(DurableBlake3Hash::for_bytes(b"source"));
    let payload = CachedExpressionValue::positioned_attrs(vec![(
        b"a".to_vec(),
        Some(AttrPosition::new(0, Span::new(4, 5))),
        CachedExpressionValue::immediate(Value::int(1)).expect("int payload builds"),
    )])
    .expect("positioned attrs payload builds")
    .with_attr_position_source_hash(source_hash);
    let encoded = payload
        .encode_persistent_payload()
        .expect("position-source payload encodes");

    let decoded = CachedExpressionValue::decode_persistent_payload(&encoded)
        .expect("position-source payload decodes");

    assert_eq!(decoded.attr_position_source_hash(), Some(source_hash));
    assert_eq!(
        decoded.value_hash().expect("decoded payload hashes"),
        payload.value_hash().expect("source payload hashes")
    );
    assert_eq!(
        decoded
            .value_hash()
            .expect("decoded payload hashes")
            .as_durable_hash(),
        DurableBlake3Hash::for_bytes(&encoded)
    );
}

#[test]
fn empty_payload_const_constructors_cache_expected_value_hashes() {
    const EMPTY_LIST: CachedExpressionValue = CachedExpressionValue::empty_list();
    const EMPTY_ATTRS: CachedExpressionValue = CachedExpressionValue::empty_attrs();

    assert_eq!(
        EMPTY_LIST.value_hash().expect("empty list hashes"),
        ValueHash::from_empty_list()
    );
    assert_eq!(
        EMPTY_ATTRS.value_hash().expect("empty attrs hashes"),
        ValueHash::from_empty_attrs()
    );
}

#[test]
fn inline_payload_records_replay_cached_value_hashes() {
    let mut cache = EvalCache::new();
    let identity = identity(b"source", 7);
    let payload = CachedExpressionValue::strict_list(vec![
        CachedExpressionValue::context_free_string(b"cached".to_vec()),
        CachedExpressionValue::immediate(Value::int(3)).expect("int payload builds"),
    ]);
    let value_hash = payload.value_hash().expect("payload hashes");

    cache
        .observe_inline_expression_payload(identity, std::iter::empty::<ValueHash>(), payload)
        .expect("payload observes");
    let replayed = cache
        .lookup_inline_expression_payload(identity, std::iter::empty::<ValueHash>())
        .expect("payload lookup succeeds")
        .expect("memoized payload is present");

    assert_eq!(
        replayed.value_hash().expect("replayed payload hashes"),
        value_hash
    );
}

#[test]
fn inline_payload_records_replay_attr_position_source_value_hashes() {
    let mut cache = EvalCache::new();
    let identity = identity(b"source", 8);
    let source_hash =
        AttrPositionSourceHash::from_persisted_hash(DurableBlake3Hash::for_bytes(b"source"));
    let payload = CachedExpressionValue::positioned_attrs(vec![(
        b"a".to_vec(),
        Some(AttrPosition::new(0, Span::new(4, 5))),
        CachedExpressionValue::immediate(Value::int(1)).expect("int payload builds"),
    )])
    .expect("positioned attrs payload builds")
    .with_attr_position_source_hash(source_hash);
    let value_hash = payload.value_hash().expect("payload hashes");

    cache
        .observe_inline_expression_payload(identity, std::iter::empty::<ValueHash>(), payload)
        .expect("payload observes");
    let replayed = cache
        .lookup_inline_expression_payload(identity, std::iter::empty::<ValueHash>())
        .expect("payload lookup succeeds")
        .expect("memoized payload is present");

    assert_eq!(replayed.attr_position_source_hash(), Some(source_hash));
    assert_eq!(
        replayed.value_hash().expect("replayed payload hashes"),
        value_hash
    );
}

#[test]
fn position_free_positioned_attrs_canonicalize_to_plain_attrs() {
    let plain = CachedExpressionValue::strict_attrs(vec![(
        b"a".to_vec(),
        CachedExpressionValue::immediate(Value::int(1)).expect("int payload builds"),
    )])
    .expect("plain attrs payload builds");
    let positioned = CachedExpressionValue::positioned_attrs(vec![(
        b"a".to_vec(),
        None,
        CachedExpressionValue::immediate(Value::int(1)).expect("int payload builds"),
    )])
    .expect("position-free positioned attrs payload builds");

    assert_eq!(
        positioned
            .attrs_entries()
            .expect("canonicalized payload has plain entries")
            .len(),
        1
    );
    assert_eq!(
        positioned.value_hash().expect("position-free attrs hash"),
        plain.value_hash().expect("plain attrs hash")
    );
    assert!(
        positioned.encode_persistent_payload().is_ok(),
        "position-free positioned constructor should produce persistent plain attrs"
    );
}

#[test]
fn eval_cache_lookup_requires_side_payload_record() {
    let mut cache = EvalCache::new();
    let identity = identity(b"source", 7);
    cache
        .get_or_insert_expression_node(
            identity,
            std::iter::empty::<ValueHash>(),
            Some(ValueHash::from_inline_value(Value::int(3)).expect("inline value hashes")),
        )
        .expect("node inserts");

    let value = cache
        .lookup_inline_expression_result(identity, std::iter::empty::<ValueHash>())
        .expect("lookup succeeds");

    assert!(value.is_none());
}

#[test]
fn dirty_pure_inline_payload_lookup_reconsiders_same_hash_and_cuts_off() {
    let mut cache = EvalCache::new();
    let identity = identity(b"source", 7);
    let observation = cache
        .observe_inline_expression_result(identity, std::iter::empty::<ValueHash>(), Value::int(3))
        .expect("result observes");
    cache
        .graph
        .mark_dirty(observation.node())
        .expect("node can be marked dirty");

    let hit = cache
        .lookup_inline_expression_payload_hit(identity, std::iter::empty::<ValueHash>())
        .expect("lookup succeeds")
        .expect("dirty pure payload cuts off");

    assert_eq!(hit.node(), observation.node());
    assert_eq!(
        hit.reconsideration()
            .expect("dirty pure hit reports reconsideration")
            .decision(),
        CutoffDecision::CutOff
    );
    assert_eq!(
        hit.into_value()
            .immediate_value()
            .expect("payload is immediate")
            .as_int(),
        Ok(3)
    );
    assert_eq!(
        cache
            .graph()
            .node(observation.node())
            .expect("node exists")
            .freshness(),
        NodeFreshness::Clean
    );
    assert_eq!(cache.inline_payload_record_count(), 1);
}
