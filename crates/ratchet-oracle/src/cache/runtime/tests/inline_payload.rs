//! Reusable inline expression payload cache tests.

use super::*;

#[test]
fn eval_cache_observes_inline_expression_results() {
    let mut cache = EvalCache::new();
    let identity = identity(b"source", 7);

    let first = cache
        .observe_inline_expression_result(
            identity,
            std::iter::empty::<DurableBlake3Hash>(),
            Value::int(3),
        )
        .expect("first result observes");
    let second = cache
        .observe_inline_expression_result(
            identity,
            std::iter::empty::<DurableBlake3Hash>(),
            Value::int(3),
        )
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
        .observe_inline_expression_result(
            identity,
            std::iter::empty::<DurableBlake3Hash>(),
            Value::int(3),
        )
        .expect("result observes");
    let value = cache
        .lookup_inline_expression_result(identity, std::iter::empty::<DurableBlake3Hash>())
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
            std::iter::empty::<DurableBlake3Hash>(),
            CachedExpressionValue::immediate(Value::int(3)).expect("int payload builds"),
        )
        .expect("child payload observes");
    let child_node = child_observation.node();
    let parent_node = cache
        .get_or_insert_expression_node(
            parent_identity,
            std::iter::empty::<DurableBlake3Hash>(),
            None,
        )
        .expect("parent node inserts");

    let hit = cache
        .lookup_inline_expression_payload_hit(
            child_identity,
            std::iter::empty::<DurableBlake3Hash>(),
        )
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
fn eval_cache_looks_up_context_free_string_payloads() {
    let mut cache = EvalCache::new();
    let identity = identity(b"source", 7);

    cache
        .observe_inline_expression_payload(
            identity,
            std::iter::empty::<DurableBlake3Hash>(),
            CachedExpressionValue::context_free_string(b"cached string".to_vec()),
        )
        .expect("string payload observes");
    let payload = cache
        .lookup_inline_expression_payload(identity, std::iter::empty::<DurableBlake3Hash>())
        .expect("payload lookup succeeds")
        .expect("memoized string payload is present");
    let immediate = cache
        .lookup_inline_expression_result(identity, std::iter::empty::<DurableBlake3Hash>())
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
            std::iter::empty::<DurableBlake3Hash>(),
            CachedExpressionValue::context_string(b"cached string".to_vec(), context.clone()),
        )
        .expect("context string payload observes");
    let payload = cache
        .lookup_inline_expression_payload(identity, std::iter::empty::<DurableBlake3Hash>())
        .expect("payload lookup succeeds")
        .expect("memoized context string payload is present");
    let immediate = cache
        .lookup_inline_expression_result(identity, std::iter::empty::<DurableBlake3Hash>())
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
            std::iter::empty::<DurableBlake3Hash>(),
            CachedExpressionValue::path(b"/tmp/cached-path".to_vec()),
        )
        .expect("path payload observes");
    let payload = cache
        .lookup_inline_expression_payload(identity, std::iter::empty::<DurableBlake3Hash>())
        .expect("payload lookup succeeds")
        .expect("memoized path payload is present");
    let immediate = cache
        .lookup_inline_expression_result(identity, std::iter::empty::<DurableBlake3Hash>())
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
            std::iter::empty::<DurableBlake3Hash>(),
            CachedExpressionValue::context_path(
                b"/nix/store/context-path".to_vec(),
                context.clone(),
            ),
        )
        .expect("context path payload observes");
    let payload = cache
        .lookup_inline_expression_payload(identity, std::iter::empty::<DurableBlake3Hash>())
        .expect("payload lookup succeeds")
        .expect("memoized context path payload is present");
    let immediate = cache
        .lookup_inline_expression_result(identity, std::iter::empty::<DurableBlake3Hash>())
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
            std::iter::empty::<DurableBlake3Hash>(),
            CachedExpressionValue::empty_list(),
        )
        .expect("empty list payload observes");
    let payload = cache
        .lookup_inline_expression_payload(identity, std::iter::empty::<DurableBlake3Hash>())
        .expect("payload lookup succeeds")
        .expect("memoized empty list payload is present");
    let immediate = cache
        .lookup_inline_expression_result(identity, std::iter::empty::<DurableBlake3Hash>())
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
            std::iter::empty::<DurableBlake3Hash>(),
            CachedExpressionValue::strict_list(vec![
                CachedExpressionValue::immediate(Value::int(1)).expect("int payload builds"),
                CachedExpressionValue::context_free_string(b"element".to_vec()),
            ]),
        )
        .expect("strict list payload observes");
    let payload = cache
        .lookup_inline_expression_payload(identity, std::iter::empty::<DurableBlake3Hash>())
        .expect("payload lookup succeeds")
        .expect("memoized strict list payload is present");
    let immediate = cache
        .lookup_inline_expression_result(identity, std::iter::empty::<DurableBlake3Hash>())
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
            std::iter::empty::<DurableBlake3Hash>(),
            CachedExpressionValue::empty_attrs(),
        )
        .expect("empty attrset payload observes");
    let payload = cache
        .lookup_inline_expression_payload(identity, std::iter::empty::<DurableBlake3Hash>())
        .expect("payload lookup succeeds")
        .expect("memoized empty attrset payload is present");
    let immediate = cache
        .lookup_inline_expression_result(identity, std::iter::empty::<DurableBlake3Hash>())
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
            std::iter::empty::<DurableBlake3Hash>(),
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
        .lookup_inline_expression_payload(identity, std::iter::empty::<DurableBlake3Hash>())
        .expect("payload lookup succeeds")
        .expect("memoized strict attrset payload is present");
    let immediate = cache
        .lookup_inline_expression_result(identity, std::iter::empty::<DurableBlake3Hash>())
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
            std::iter::empty::<DurableBlake3Hash>(),
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
        .lookup_inline_expression_payload(identity, std::iter::empty::<DurableBlake3Hash>())
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
            std::iter::empty::<DurableBlake3Hash>(),
            CachedExpressionValue::positioned_attrs(vec![(
                b"a".to_vec(),
                Some(position),
                CachedExpressionValue::immediate(Value::int(1)).expect("int payload builds"),
            )])
            .expect("positioned attrs payload builds"),
        )
        .expect("positioned attrset payload observes");
    let payload = cache
        .lookup_inline_expression_payload(identity, std::iter::empty::<DurableBlake3Hash>())
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
    .with_attr_position_source_hash(DurableBlake3Hash::for_bytes(b"source"));
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
            std::iter::empty::<DurableBlake3Hash>(),
            Some(ValueHash::from_inline_value(Value::int(3)).expect("inline value hashes")),
        )
        .expect("node inserts");

    let value = cache
        .lookup_inline_expression_result(identity, std::iter::empty::<DurableBlake3Hash>())
        .expect("lookup succeeds");

    assert!(value.is_none());
}

#[test]
fn eval_cache_lookup_rejects_dirty_inline_expression_nodes() {
    let mut cache = EvalCache::new();
    let identity = identity(b"source", 7);
    let observation = cache
        .observe_inline_expression_result(
            identity,
            std::iter::empty::<DurableBlake3Hash>(),
            Value::int(3),
        )
        .expect("result observes");
    cache
        .graph
        .mark_dirty(observation.node())
        .expect("node can be marked dirty");

    let value = cache
        .lookup_inline_expression_result(identity, std::iter::empty::<DurableBlake3Hash>())
        .expect("lookup succeeds");

    assert!(value.is_none());
}

#[test]
fn eval_cache_lookup_rejects_stale_inline_payload_records() {
    let mut cache = EvalCache::new();
    let identity = identity(b"source", 7);
    let observation = cache
        .observe_inline_expression_result(
            identity,
            std::iter::empty::<DurableBlake3Hash>(),
            Value::int(3),
        )
        .expect("result observes");
    cache
        .graph
        .reconsider_node(
            observation.node(),
            ValueHash::from_inline_value(Value::int(4)).expect("inline value hashes"),
        )
        .expect("node can be reconsidered independently");

    let value = cache
        .lookup_inline_expression_result(identity, std::iter::empty::<DurableBlake3Hash>())
        .expect("lookup succeeds");

    assert!(value.is_none());
}

#[test]
fn enabled_eval_cache_runtime_observes_inline_expression_results() {
    let mut runtime = EvalCacheRuntime::enabled();
    let identity = identity(b"source", 7);

    let first = runtime
        .observe_inline_expression_result(
            identity,
            std::iter::empty::<DurableBlake3Hash>(),
            Value::int(3),
        )
        .expect("first result observes")
        .expect("enabled runtime observes expression results");
    let second = runtime
        .observe_inline_expression_result(
            identity,
            std::iter::empty::<DurableBlake3Hash>(),
            Value::int(3),
        )
        .expect("second result observes")
        .expect("enabled runtime observes expression results");

    assert_eq!(first.decision(), crate::cache::CutoffDecision::Propagate);
    assert_eq!(second.node(), first.node());
    assert_eq!(second.decision(), crate::cache::CutoffDecision::CutOff);
    assert_eq!(runtime.cache().expect("cache is enabled").len(), 1);
}

#[test]
fn enabled_eval_cache_runtime_looks_up_inline_expression_results() {
    let mut runtime = EvalCacheRuntime::enabled();
    let identity = identity(b"source", 7);

    runtime
        .observe_inline_expression_result(
            identity,
            std::iter::empty::<DurableBlake3Hash>(),
            Value::bool(true),
        )
        .expect("result observes")
        .expect("enabled runtime observes expression results");
    let value = runtime
        .lookup_inline_expression_result(identity, std::iter::empty::<DurableBlake3Hash>())
        .expect("lookup succeeds")
        .expect("memoized inline result is present");

    assert_eq!(value.as_bool(), Ok(true));
}

#[test]
fn disabled_eval_cache_runtime_expression_result_observation_is_noop() {
    let mut runtime = EvalCacheRuntime::disabled();

    let observation = runtime
        .observe_inline_expression_result(
            identity(b"source", 7),
            std::iter::empty::<DurableBlake3Hash>(),
            Value::int(3),
        )
        .expect("disabled expression result observation succeeds");

    assert_eq!(observation, None);
    assert!(runtime.cache().is_none());
}

#[test]
fn disabled_eval_cache_runtime_expression_result_lookup_is_noop() {
    let runtime = EvalCacheRuntime::disabled();

    let value = runtime
        .lookup_inline_expression_result(
            identity(b"source", 7),
            std::iter::empty::<DurableBlake3Hash>(),
        )
        .expect("disabled lookup succeeds");

    assert!(value.is_none());
    assert!(runtime.cache().is_none());
}

#[test]
fn eval_cache_reconsiders_expression_node_from_inline_value() {
    let mut cache = EvalCache::new();
    let node = cache
        .get_or_insert_expression_node(
            identity(b"source", 7),
            [durable_hash(b"free-var")],
            Some(ValueHash::from_inline_value(Value::int(1)).expect("inline value hashes")),
        )
        .expect("expression node inserts");

    let reconsideration = cache
        .reconsider_inline_value_node(node, Value::int(2))
        .expect("node reconsiders");

    assert_eq!(
        reconsideration.decision(),
        crate::cache::CutoffDecision::Propagate
    );
    assert_eq!(
        cache.graph().node(node).expect("node exists").value_hash(),
        Some(ValueHash::from_inline_value(Value::int(2)).expect("inline value hashes"))
    );
}
