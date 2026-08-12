//! Split-out tests (part_2). See parent module.

use super::*;

#[test]
fn attr_filter_builtins_record_dynamic_repr_decisions() {
    let ir = lower(
        "builtins.deepSeq [
            (builtins.removeAttrs { a = 1; b = 2; } [ \"b\" ])
            (builtins.intersectAttrs { a = 0; } { a = 1; b = 2; })
            (let remove = builtins.removeAttrs { a = 1; b = 2; }; in remove [ \"b\" ])
            (let intersect = builtins.intersectAttrs { a = 0; }; in intersect { a = 1; b = 2; })
        ] 0",
    );

    let outcome = eval_whnf_owned(&ir).expect("attr filter builtins evaluate");

    assert_eq!(outcome.value().as_int(), Ok(0));
    let snapshot = outcome
        .attr_telemetry()
        .update_merge_snapshot()
        .expect("repr telemetry snapshot allocates");
    assert_eq!(snapshot.decisions, 10);
    assert_eq!(snapshot.flat_decisions, 10);
    assert_eq!(snapshot.update_merges, 0);
    assert_eq!(snapshot.reasons.static_literal, 6);
    assert_eq!(snapshot.reasons.small_shape_stable, 4);
    let stats = outcome.attr_telemetry().order_parity_stats();
    assert_eq!(stats.matched, 4);
    assert_eq!(stats.mismatched, 0);
}

#[test]
fn map_attrs_records_dynamic_repr_decisions_for_empty_and_non_empty_results() {
    let ir = lower(
        "builtins.deepSeq [
            (builtins.mapAttrs (_name: value: value + 1) { a = 1; })
            (builtins.mapAttrs (_name: value: value) {})
        ] 0",
    );

    let outcome = eval_whnf_owned(&ir).expect("mapAttrs evaluates");

    assert_eq!(outcome.value().as_int(), Ok(0));
    let snapshot = outcome
        .attr_telemetry()
        .update_merge_snapshot()
        .expect("repr telemetry snapshot allocates");
    assert_eq!(snapshot.decisions, 4);
    assert_eq!(snapshot.flat_decisions, 4);
    assert_eq!(snapshot.update_merges, 0);
    assert_eq!(snapshot.reasons.static_literal, 2);
    assert_eq!(snapshot.reasons.small_shape_stable, 2);
    let stats = outcome.attr_telemetry().order_parity_stats();
    assert_eq!(stats.matched, 2);
    assert_eq!(stats.mismatched, 0);
}

#[test]
fn zip_attrs_with_records_dynamic_repr_decisions() {
    let ir = lower(
        "builtins.deepSeq [
            (builtins.zipAttrsWith (_name: values: values) [ { a = 1; } { b = 2; } ])
            (let zip = builtins.zipAttrsWith (_name: values: values); in zip [ { c = 3; } ])
            (builtins.zipAttrsWith (_name: values: values) [])
        ] 0",
    );

    let outcome = eval_whnf_owned(&ir).expect("zipAttrsWith evaluates");

    assert_eq!(outcome.value().as_int(), Ok(0));
    let snapshot = outcome
        .attr_telemetry()
        .update_merge_snapshot()
        .expect("repr telemetry snapshot allocates");
    assert_eq!(snapshot.decisions, 6);
    assert_eq!(snapshot.flat_decisions, 6);
    assert_eq!(snapshot.update_merges, 0);
    assert_eq!(snapshot.reasons.static_literal, 3);
    assert_eq!(snapshot.reasons.small_shape_stable, 3);
    let stats = outcome.attr_telemetry().order_parity_stats();
    assert_eq!(stats.matched, 3);
    assert_eq!(stats.mismatched, 0);
}

#[test]
fn attr_position_builtins_record_dynamic_repr_decisions() {
    let source = "builtins.deepSeq [
            (builtins.unsafeGetAttrPos \"a\" { a = 1; })
            __curPos
        ] 0";

    let outcome = eval_owned_with_source(b"/source.nix", source);

    assert_eq!(outcome.value().as_int(), Ok(0));
    let snapshot = outcome
        .attr_telemetry()
        .update_merge_snapshot()
        .expect("repr telemetry snapshot allocates");
    assert_eq!(snapshot.decisions, 3);
    assert_eq!(snapshot.flat_decisions, 3);
    assert_eq!(snapshot.update_merges, 0);
    assert_eq!(snapshot.reasons.static_literal, 1);
    assert_eq!(snapshot.reasons.small_shape_stable, 2);
    let stats = outcome.attr_telemetry().order_parity_stats();
    assert_eq!(stats.matched, 2);
    assert_eq!(stats.mismatched, 0);
}

#[test]
fn partition_records_dynamic_repr_decisions() {
    let ir = lower(
        "builtins.deepSeq [
            (builtins.partition (value: value < 2) [ 1 2 ])
            (let partition = builtins.partition (value: value < 2); in partition [ 1 2 ])
        ] 0",
    );

    let outcome = eval_whnf_owned(&ir).expect("partition evaluates");

    assert_eq!(outcome.value().as_int(), Ok(0));
    let snapshot = outcome
        .attr_telemetry()
        .update_merge_snapshot()
        .expect("repr telemetry snapshot allocates");
    assert_eq!(snapshot.decisions, 2);
    assert_eq!(snapshot.flat_decisions, 2);
    assert_eq!(snapshot.update_merges, 0);
    assert_eq!(snapshot.reasons.static_literal, 0);
    assert_eq!(snapshot.reasons.small_shape_stable, 2);
    let stats = outcome.attr_telemetry().order_parity_stats();
    assert_eq!(stats.matched, 2);
    assert_eq!(stats.mismatched, 0);
}

#[test]
fn group_by_records_dynamic_repr_decisions() {
    let ir = lower(
        "builtins.deepSeq [
            (builtins.groupBy (value: if value < 2 then \"small\" else \"large\") [ 1 2 ])
            (let group = builtins.groupBy (value: \"all\"); in group [ 3 ])
        ] 0",
    );

    let outcome = eval_whnf_owned(&ir).expect("groupBy evaluates");

    assert_eq!(outcome.value().as_int(), Ok(0));
    let snapshot = outcome
        .attr_telemetry()
        .update_merge_snapshot()
        .expect("repr telemetry snapshot allocates");
    assert_eq!(snapshot.decisions, 2);
    assert_eq!(snapshot.flat_decisions, 2);
    assert_eq!(snapshot.update_merges, 0);
    assert_eq!(snapshot.reasons.static_literal, 0);
    assert_eq!(snapshot.reasons.small_shape_stable, 2);
    let stats = outcome.attr_telemetry().order_parity_stats();
    assert_eq!(stats.matched, 2);
    assert_eq!(stats.mismatched, 0);
}

#[test]
fn function_args_records_dynamic_repr_decisions() {
    let ir = lower(
        "builtins.deepSeq [
            (builtins.functionArgs ({ a, b ? 1 }: a))
            (let functionArgs = builtins.functionArgs; in functionArgs builtins.length)
        ] 0",
    );

    let outcome = eval_whnf_owned(&ir).expect("functionArgs evaluates");

    assert_eq!(outcome.value().as_int(), Ok(0));
    let snapshot = outcome
        .attr_telemetry()
        .update_merge_snapshot()
        .expect("repr telemetry snapshot allocates");
    assert_eq!(snapshot.decisions, 2);
    assert_eq!(snapshot.flat_decisions, 2);
    assert_eq!(snapshot.update_merges, 0);
    assert_eq!(snapshot.reasons.static_literal, 0);
    assert_eq!(snapshot.reasons.small_shape_stable, 2);
    let stats = outcome.attr_telemetry().order_parity_stats();
    assert_eq!(stats.matched, 2);
    assert_eq!(stats.mismatched, 0);
}

#[test]
fn codec_attrsets_record_dynamic_repr_decisions() {
    let ir = lower(
        "builtins.deepSeq [
            (builtins.fromJSON ''{\"a\":{\"b\":1}}'')
            (builtins.fromTOML \"a = 1\\n[nested]\\nb = 2\")
            (builtins.fromTOML \"a = 1979-05-27T07:32:00Z\")
        ] 0",
    );
    let options = TreeWalkOptions::with_parse_toml_timestamps(true);

    let outcome = eval_whnf_owned_with_options(&ir, options).expect("codec attrsets evaluate");

    assert_eq!(outcome.value().as_int(), Ok(0));
    let snapshot = outcome
        .attr_telemetry()
        .update_merge_snapshot()
        .expect("repr telemetry snapshot allocates");
    assert_eq!(snapshot.decisions, 6);
    assert_eq!(snapshot.flat_decisions, 6);
    assert_eq!(snapshot.update_merges, 0);
    assert_eq!(snapshot.reasons.static_literal, 0);
    assert_eq!(snapshot.reasons.small_shape_stable, 6);
    let stats = outcome.attr_telemetry().order_parity_stats();
    assert_eq!(stats.matched, 6);
    assert_eq!(stats.mismatched, 0);
}

#[test]
fn path_surface_attrsets_record_dynamic_repr_decisions() {
    let root = unique_temp_dir("attr-telemetry-read-dir");
    fs::write(root.join("alpha"), b"alpha").expect("readDir fixture writes");
    let source = format!(
        "builtins.deepSeq [
            (builtins.parseDrvName \"pkg-1.0\")
            (builtins.readDir {})
            builtins.nixPath
        ] 0",
        nix_string_literal(&path_source(&root))
    );
    let options = search_path_options(b"nixpkgs", &root);
    let ir = lower(&source);

    let outcome =
        eval_whnf_owned_with_options(&ir, options).expect("path surface attrsets evaluate");

    assert_eq!(outcome.value().as_int(), Ok(0));
    let snapshot = outcome
        .attr_telemetry()
        .update_merge_snapshot()
        .expect("repr telemetry snapshot allocates");
    assert_eq!(snapshot.decisions, 3);
    assert_eq!(snapshot.flat_decisions, 3);
    assert_eq!(snapshot.update_merges, 0);
    assert_eq!(snapshot.reasons.static_literal, 0);
    assert_eq!(snapshot.reasons.small_shape_stable, 3);
    let stats = outcome.attr_telemetry().order_parity_stats();
    assert_eq!(stats.matched, 3);
    assert_eq!(stats.mismatched, 0);

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn try_eval_records_dynamic_repr_decisions() {
    let ir = lower(
        "builtins.deepSeq [
            (builtins.tryEval 1)
            (let tryEval = builtins.tryEval; in tryEval (builtins.throw \"boom\"))
        ] 0",
    );

    let outcome = eval_whnf_owned(&ir).expect("tryEval results evaluate");

    assert_eq!(outcome.value().as_int(), Ok(0));
    let snapshot = outcome
        .attr_telemetry()
        .update_merge_snapshot()
        .expect("repr telemetry snapshot allocates");
    assert_eq!(snapshot.decisions, 2);
    assert_eq!(snapshot.flat_decisions, 2);
    assert_eq!(snapshot.update_merges, 0);
    assert_eq!(snapshot.reasons.static_literal, 0);
    assert_eq!(snapshot.reasons.small_shape_stable, 2);
    let stats = outcome.attr_telemetry().order_parity_stats();
    assert_eq!(stats.matched, 2);
    assert_eq!(stats.mismatched, 0);
}

#[test]
fn get_context_records_dynamic_repr_decisions() {
    let ir = lower("builtins.getContext \"x\"");
    let root = *ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let argument = ir
        .arena
        .child_slice(args)
        .expect("primop args exist")
        .first()
        .copied()
        .expect("getContext argument exists");
    let argument_span = ir.arena.node(argument).expect("argument exists").span;
    let mut evaluator = TreeWalk::new(&ir);
    let context = StringContext::new(vec![
        ContextElement::opaque_path(b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src".to_vec())
            .expect("source context is valid"),
        ContextElement::single_output(
            b"/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-drv.drv".to_vec(),
            b"out".to_vec(),
        )
        .expect("output context is valid"),
        ContextElement::deep_derivation(
            b"/nix/store/cccccccccccccccccccccccccccccccc-deep.drv".to_vec(),
        )
        .expect("deep context is valid"),
    ]);
    let value = evaluator
        .heap
        .alloc_string(NixString::new(b"x".to_vec(), context))
        .expect("context-bearing string allocates");

    let result = evaluator
        .eval_get_context_primop(ir.root, root.span, argument, argument_span, value)
        .expect("getContext evaluates");

    let attrs = evaluator
        .heap
        .get_attrs(result)
        .expect("getContext result is attrs");
    assert_eq!(attrs.len(), 3);
    let metadata = evaluator
        .heap
        .get_attrs_metadata(result)
        .expect("getContext result metadata exists");
    assert!(metadata.projected_shape().is_some());
    assert_eq!(metadata.repr(), AttrSetReprKind::Flat);
    let keys = attrs
        .iter_lexicographic()
        .map(|entry| {
            evaluator
                .symbols
                .resolve(entry.key)
                .expect("getContext key resolves")
                .to_vec()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        keys,
        vec![
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src".to_vec(),
            b"/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-drv.drv".to_vec(),
            b"/nix/store/cccccccccccccccccccccccccccccccc-deep.drv".to_vec(),
        ],
    );
    let snapshot = evaluator
        .attr_telemetry
        .update_merge_snapshot()
        .expect("repr telemetry snapshot allocates");
    assert_eq!(snapshot.decisions, 4);
    assert_eq!(snapshot.flat_decisions, 4);
    assert_eq!(snapshot.update_merges, 0);
    assert_eq!(snapshot.reasons.static_literal, 0);
    assert_eq!(snapshot.reasons.small_shape_stable, 4);
    let stats = evaluator.attr_telemetry.order_parity_stats();
    assert_eq!(stats.matched, 4);
    assert_eq!(stats.mismatched, 0);
}

#[test]
fn active_flat_selects_record_slow_select_telemetry() {
    let ir = lower(
        "builtins.deepSeq [
            ({ a = 1; }).a
            (({}).missing or 2)
            ({ a = 1; } ? a)
            ({} ? missing)
            (with { a = 1; }; a)
        ] 0",
    );

    let outcome = eval_whnf_owned(&ir).expect("active flat selects evaluate");

    assert_eq!(outcome.value().as_int(), Ok(0));
    let counts = outcome.attr_telemetry().slow_select_snapshot();
    assert_eq!(counts.flat_hits, 0);
    assert_eq!(counts.flat_misses, 0);
    assert_eq!(counts.hamt_hits, 0);
    assert_eq!(counts.hamt_misses, 0);
    assert_eq!(counts.shaped_hits, 3);
    assert_eq!(counts.shaped_misses, 2);
}

#[test]
fn repeated_static_select_site_uses_shaped_inline_cache_for_projected_flat_receivers() {
    let ir = lower("let f = x: x.a; in (f { a = 1; }) + (f { a = 2; })");

    let outcome = eval_whnf_owned(&ir).expect("repeated static select evaluates");

    assert_eq!(outcome.value().as_int(), Ok(3));
    assert_eq!(outcome.stats().inline_cache_hits(), 1);
    assert_eq!(outcome.stats().inline_cache_misses(), 1);
    let ic_snapshot = outcome.attr_telemetry().inline_cache_snapshot();
    assert_eq!(ic_snapshot.flat_select_sites.monomorphic, 0);
    assert_eq!(ic_snapshot.shaped_select_sites.monomorphic, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.hits, 2);
    assert_eq!(ic_snapshot.shaped_select_lookups.resolved_hits, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.cached_hits, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.monomorphic_fast_hits, 1);
    let counts = outcome.attr_telemetry().slow_select_snapshot();
    assert_eq!(counts.flat_hits, 0);
    assert_eq!(counts.flat_misses, 0);
    assert_eq!(counts.shaped_hits, 1);
    assert_eq!(counts.shaped_misses, 0);
}

#[test]
fn repeated_static_select_site_uses_hamt_inline_cache_for_projected_hamt_receivers() {
    let ir = lower(
        "let base = ((((({ a = 1; } // { b = 2; }) // { c = 3; }) // { d = 4; }) // { e = 5; }) // { f = 6; });
             select = x: x.f;
         in (select base) + (select base)",
    );

    let outcome = eval_whnf_owned(&ir).expect("repeated projected-HAMT static select evaluates");

    assert_eq!(outcome.value().as_int(), Ok(12));
    assert_eq!(outcome.stats().inline_cache_hits(), 1);
    assert_eq!(outcome.stats().inline_cache_misses(), 1);
    let ic_snapshot = outcome.attr_telemetry().inline_cache_snapshot();
    assert_eq!(ic_snapshot.flat_select_sites.monomorphic, 0);
    assert_eq!(ic_snapshot.hamt_select_sites.distinguished_hamt, 1);
    assert_eq!(ic_snapshot.hamt_select_lookups.hits, 2);
    assert_eq!(ic_snapshot.hamt_select_lookups.resolved_hits, 1);
    assert_eq!(ic_snapshot.hamt_select_lookups.cached_hits, 1);
    let counts = outcome.attr_telemetry().slow_select_snapshot();
    assert_eq!(counts.flat_hits, 0);
    assert_eq!(counts.hamt_hits, 2);
    assert_eq!(counts.hamt_misses, 0);
}

#[test]
fn repeated_static_select_site_separates_projected_shapes_with_different_slots() {
    let ir = lower("let seed = { a = 0; }; f = x: x.b; in (f { b = 1; }) + (f { a = 0; b = 2; })");

    let outcome = eval_whnf_owned(&ir).expect("shifted static select evaluates");

    assert_eq!(outcome.value().as_int(), Ok(3));
    assert_eq!(outcome.stats().inline_cache_hits(), 0);
    assert_eq!(outcome.stats().inline_cache_misses(), 2);
    let ic_snapshot = outcome.attr_telemetry().inline_cache_snapshot();
    assert_eq!(ic_snapshot.flat_select_sites.polymorphic, 0);
    assert_eq!(ic_snapshot.shaped_select_sites.polymorphic, 1);
    let counts = outcome.attr_telemetry().slow_select_snapshot();
    assert_eq!(counts.flat_hits, 0);
    assert_eq!(counts.flat_misses, 0);
    assert_eq!(counts.shaped_hits, 2);
    assert_eq!(counts.shaped_misses, 0);
}

#[test]
fn polymorphic_static_select_defaults_keep_shaped_cache_after_missing_receiver() {
    let ir = lower(
        "let f = x: x.b or 10;
         in (f { b = 1; })
          + (f { a = 0; b = 2; })
          + (f { c = 0; })
          + (f { b = 3; })
          + (f { a = 0; b = 4; })
          + (f { c = 5; })",
    );

    let outcome = eval_whnf_owned(&ir).expect("polymorphic hit-miss-hit-miss select evaluates");

    assert_eq!(outcome.value().as_int(), Ok(30));
    assert_eq!(outcome.stats().inline_cache_hits(), 2);
    assert_eq!(outcome.stats().inline_cache_misses(), 4);
    let ic_snapshot = outcome.attr_telemetry().inline_cache_snapshot();
    assert_eq!(ic_snapshot.flat_select_sites.polymorphic, 0);
    assert_eq!(ic_snapshot.shaped_select_sites.polymorphic, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.hits, 4);
    assert_eq!(ic_snapshot.shaped_select_lookups.misses, 2);
    assert_eq!(ic_snapshot.shaped_select_lookups.resolved_hits, 2);
    assert_eq!(ic_snapshot.shaped_select_lookups.cached_hits, 2);
    assert_eq!(ic_snapshot.shaped_select_lookups.resolved_misses, 2);
    assert_eq!(ic_snapshot.shaped_select_lookups.cached_misses, 0);
    assert_eq!(ic_snapshot.shaped_select_lookups.monomorphic_fast_hits, 0);
    let counts = outcome.attr_telemetry().slow_select_snapshot();
    assert_eq!(counts.flat_hits, 0);
    assert_eq!(counts.flat_misses, 0);
    assert_eq!(counts.shaped_hits, 2);
    assert_eq!(counts.shaped_misses, 2);
}

#[test]
fn projected_shaped_select_site_becomes_megamorphic_after_cap_overflow() {
    // The default shaped PIC cap is four entries; the fifth distinct projected
    // shape drives the active bridge into the megamorphic terminal state.
    let ir = lower(
        "let f = x: x.a;
         in (f { a = 1; })
          + (f { b = 0; a = 2; })
          + (f { c = 0; a = 3; })
          + (f { d = 0; a = 4; })
          + (f { e = 0; a = 5; })",
    );

    let outcome = eval_whnf_owned(&ir).expect("megamorphic projected-shaped select evaluates");

    assert_eq!(outcome.value().as_int(), Ok(15));
    assert_eq!(outcome.stats().inline_cache_hits(), 0);
    assert_eq!(outcome.stats().inline_cache_misses(), 5);
    let ic_snapshot = outcome.attr_telemetry().inline_cache_snapshot();
    assert_eq!(ic_snapshot.flat_select_sites.megamorphic, 0);
    assert_eq!(ic_snapshot.shaped_select_sites.megamorphic, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.hits, 5);
    assert_eq!(ic_snapshot.shaped_select_lookups.resolved_hits, 5);
    assert_eq!(ic_snapshot.shaped_select_lookups.cached_hits, 0);
    let counts = outcome.attr_telemetry().slow_select_snapshot();
    assert_eq!(counts.flat_hits, 0);
    assert_eq!(counts.shaped_hits, 5);
    assert_eq!(counts.shaped_misses, 0);
}

#[test]
fn megamorphic_static_select_defaults_stay_slow_after_missing_receivers() {
    let ir = lower(
        "let f = x: x.a or 10;
         in (f { a = 1; })
          + (f { b = 0; a = 2; })
          + (f { c = 0; a = 3; })
          + (f { d = 0; a = 4; })
          + (f { e = 0; a = 5; })
          + (f { missing = 0; })
          + (f { missing = 1; })
          + (f { a = 6; })",
    );

    let outcome = eval_whnf_owned(&ir).expect("megamorphic hit-miss-hit select evaluates");

    assert_eq!(outcome.value().as_int(), Ok(41));
    assert_eq!(outcome.stats().inline_cache_hits(), 0);
    assert_eq!(outcome.stats().inline_cache_misses(), 8);
    let ic_snapshot = outcome.attr_telemetry().inline_cache_snapshot();
    assert_eq!(ic_snapshot.flat_select_sites.megamorphic, 0);
    assert_eq!(ic_snapshot.shaped_select_sites.megamorphic, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.hits, 6);
    assert_eq!(ic_snapshot.shaped_select_lookups.misses, 2);
    assert_eq!(ic_snapshot.shaped_select_lookups.resolved_hits, 6);
    assert_eq!(ic_snapshot.shaped_select_lookups.cached_hits, 0);
    assert_eq!(ic_snapshot.shaped_select_lookups.resolved_misses, 2);
    assert_eq!(ic_snapshot.shaped_select_lookups.cached_misses, 0);
    assert_eq!(ic_snapshot.shaped_select_lookups.monomorphic_fast_hits, 0);
    let counts = outcome.attr_telemetry().slow_select_snapshot();
    assert_eq!(counts.flat_hits, 0);
    assert_eq!(counts.flat_misses, 0);
    assert_eq!(counts.shaped_hits, 6);
    assert_eq!(counts.shaped_misses, 2);
}

#[test]
fn repeated_static_select_defaults_preserve_hit_then_miss_semantics() {
    let ir = lower("let f = x: x.a or 10; in (f { a = 1; }) + (f {})");

    let outcome = eval_whnf_owned(&ir).expect("hit-then-miss default select evaluates");

    assert_eq!(outcome.value().as_int(), Ok(11));
    assert_eq!(outcome.stats().inline_cache_hits(), 0);
    assert_eq!(outcome.stats().inline_cache_misses(), 2);
    let ic_snapshot = outcome.attr_telemetry().inline_cache_snapshot();
    assert_eq!(ic_snapshot.flat_select_sites.monomorphic, 0);
    assert_eq!(ic_snapshot.shaped_select_sites.monomorphic, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.hits, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.misses, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.resolved_hits, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.resolved_misses, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.cached_misses, 0);
    let counts = outcome.attr_telemetry().slow_select_snapshot();
    assert_eq!(counts.flat_hits, 0);
    assert_eq!(counts.flat_misses, 0);
    assert_eq!(counts.shaped_hits, 1);
    assert_eq!(counts.shaped_misses, 1);
}

#[test]
fn repeated_static_select_defaults_keep_shaped_cache_after_missing_receiver() {
    let ir = lower("let f = x: x.a or 10; in (f { a = 1; }) + (f { b = 2; }) + (f { a = 3; })");

    let outcome = eval_whnf_owned(&ir).expect("hit-miss-hit default select evaluates");

    assert_eq!(outcome.value().as_int(), Ok(14));
    assert_eq!(outcome.stats().inline_cache_hits(), 1);
    assert_eq!(outcome.stats().inline_cache_misses(), 2);
    let ic_snapshot = outcome.attr_telemetry().inline_cache_snapshot();
    assert_eq!(ic_snapshot.flat_select_sites.monomorphic, 0);
    assert_eq!(ic_snapshot.shaped_select_sites.monomorphic, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.hits, 2);
    assert_eq!(ic_snapshot.shaped_select_lookups.misses, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.resolved_hits, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.cached_hits, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.resolved_misses, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.cached_misses, 0);
    assert_eq!(ic_snapshot.shaped_select_lookups.monomorphic_fast_hits, 1);
    let counts = outcome.attr_telemetry().slow_select_snapshot();
    assert_eq!(counts.flat_hits, 0);
    assert_eq!(counts.flat_misses, 0);
    assert_eq!(counts.shaped_hits, 1);
    assert_eq!(counts.shaped_misses, 1);
}

#[test]
fn repeated_static_select_defaults_preserve_miss_then_hit_semantics() {
    let ir = lower("let f = x: x.a or 10; in (f {}) + (f { a = 2; })");

    let outcome = eval_whnf_owned(&ir).expect("miss-then-hit default select evaluates");

    assert_eq!(outcome.value().as_int(), Ok(12));
    assert_eq!(outcome.stats().inline_cache_hits(), 0);
    assert_eq!(outcome.stats().inline_cache_misses(), 2);
    let ic_snapshot = outcome.attr_telemetry().inline_cache_snapshot();
    assert_eq!(ic_snapshot.flat_select_sites.monomorphic, 0);
    assert_eq!(ic_snapshot.shaped_select_sites.monomorphic, 1);
    let counts = outcome.attr_telemetry().slow_select_snapshot();
    assert_eq!(counts.flat_hits, 0);
    assert_eq!(counts.flat_misses, 0);
    assert_eq!(counts.shaped_hits, 1);
    assert_eq!(counts.shaped_misses, 1);
}

#[test]
fn repeated_static_select_defaults_use_hamt_inline_cache_for_projected_hamt_misses() {
    let ir = lower(
        "let base = ((((({ a = 1; } // { b = 2; }) // { c = 3; }) // { d = 4; }) // { e = 5; }) // { f = 6; });
             select = x: x.missing or 10;
         in (select base) + (select base)",
    );

    let outcome = eval_whnf_owned(&ir).expect("repeated projected-HAMT static select misses");

    assert_eq!(outcome.value().as_int(), Ok(20));
    assert_eq!(outcome.stats().inline_cache_hits(), 1);
    assert_eq!(outcome.stats().inline_cache_misses(), 1);
    let ic_snapshot = outcome.attr_telemetry().inline_cache_snapshot();
    assert_eq!(ic_snapshot.flat_select_sites.monomorphic, 0);
    assert_eq!(ic_snapshot.hamt_select_sites.distinguished_hamt, 1);
    assert_eq!(ic_snapshot.hamt_select_lookups.misses, 2);
    assert_eq!(ic_snapshot.hamt_select_lookups.resolved_misses, 1);
    assert_eq!(ic_snapshot.hamt_select_lookups.cached_misses, 1);
    let counts = outcome.attr_telemetry().slow_select_snapshot();
    assert_eq!(counts.flat_misses, 0);
    assert_eq!(counts.hamt_hits, 0);
    assert_eq!(counts.hamt_misses, 2);
}

#[test]
fn dynamic_select_site_stays_on_slow_select_path() {
    let ir = lower(r#"let f = name: set: set.${name}; in (f "a" { a = 1; }) + (f "b" { b = 2; })"#);

    let outcome = eval_whnf_owned(&ir).expect("repeated dynamic select evaluates");

    assert_eq!(outcome.value().as_int(), Ok(3));
    assert_eq!(outcome.stats().inline_cache_hits(), 0);
    assert_eq!(outcome.stats().inline_cache_misses(), 0);
    let ic_snapshot = outcome.attr_telemetry().inline_cache_snapshot();
    assert_eq!(ic_snapshot.flat_select_sites.monomorphic, 0);
    assert_eq!(ic_snapshot.flat_select_sites.polymorphic, 0);
    let counts = outcome.attr_telemetry().slow_select_snapshot();
    assert_eq!(counts.flat_hits, 2);
    assert_eq!(counts.flat_misses, 0);
}

#[test]
fn multi_segment_static_select_caches_each_path_index_separately() {
    let ir = lower("let f = x: x.a.b; in (f { a = { b = 1; }; }) + (f { a = { b = 2; }; })");

    let outcome = eval_whnf_owned(&ir).expect("multi-segment static select evaluates");

    assert_eq!(outcome.value().as_int(), Ok(3));
    assert_eq!(outcome.stats().inline_cache_hits(), 2);
    assert_eq!(outcome.stats().inline_cache_misses(), 2);
    let ic_snapshot = outcome.attr_telemetry().inline_cache_snapshot();
    assert_eq!(ic_snapshot.flat_select_sites.monomorphic, 0);
    assert_eq!(ic_snapshot.shaped_select_sites.monomorphic, 2);
    let counts = outcome.attr_telemetry().slow_select_snapshot();
    assert_eq!(counts.flat_hits, 0);
    assert_eq!(counts.flat_misses, 0);
    assert_eq!(counts.shaped_hits, 2);
    assert_eq!(counts.shaped_misses, 0);
}

#[test]
fn repeated_static_has_attr_site_uses_shaped_inline_cache_for_projected_flat_receivers() {
    let ir = lower("let f = x: x ? a; in if (f { a = 1; }) && (f { a = 2; }) then 1 else 0");

    let outcome = eval_whnf_owned(&ir).expect("repeated static hasAttr evaluates");

    assert_eq!(outcome.value().as_int(), Ok(1));
    assert_eq!(outcome.stats().inline_cache_hits(), 1);
    assert_eq!(outcome.stats().inline_cache_misses(), 1);
    let ic_snapshot = outcome.attr_telemetry().inline_cache_snapshot();
    assert_eq!(ic_snapshot.flat_select_sites.monomorphic, 0);
    assert_eq!(ic_snapshot.shaped_select_sites.monomorphic, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.hits, 2);
    assert_eq!(ic_snapshot.shaped_select_lookups.resolved_hits, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.cached_hits, 1);
    let counts = outcome.attr_telemetry().slow_select_snapshot();
    assert_eq!(counts.flat_hits, 0);
    assert_eq!(counts.flat_misses, 0);
    assert_eq!(counts.shaped_hits, 1);
    assert_eq!(counts.shaped_misses, 0);
}

#[test]
fn repeated_static_has_attr_site_keeps_shaped_cache_after_missing_receiver() {
    let ir = lower(
        "let f = x: x ? a;
         in if (f { a = 1; })
            then if (f { b = 2; })
                 then 0
                 else if (f { a = 3; }) then 1 else 0
            else 0",
    );

    let outcome = eval_whnf_owned(&ir).expect("hit-miss-hit static hasAttr evaluates");

    assert_eq!(outcome.value().as_int(), Ok(1));
    assert_eq!(outcome.stats().inline_cache_hits(), 1);
    assert_eq!(outcome.stats().inline_cache_misses(), 2);
    let ic_snapshot = outcome.attr_telemetry().inline_cache_snapshot();
    assert_eq!(ic_snapshot.flat_select_sites.monomorphic, 0);
    assert_eq!(ic_snapshot.shaped_select_sites.monomorphic, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.hits, 2);
    assert_eq!(ic_snapshot.shaped_select_lookups.misses, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.resolved_hits, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.cached_hits, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.resolved_misses, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.cached_misses, 0);
    assert_eq!(ic_snapshot.shaped_select_lookups.monomorphic_fast_hits, 1);
    let counts = outcome.attr_telemetry().slow_select_snapshot();
    assert_eq!(counts.flat_hits, 0);
    assert_eq!(counts.flat_misses, 0);
    assert_eq!(counts.shaped_hits, 1);
    assert_eq!(counts.shaped_misses, 1);
}

#[test]
fn repeated_static_has_attr_site_keeps_projected_shaped_misses_uncached() {
    let ir = lower("let f = x: x ? missing; in if (f {}) || (f {}) then 1 else 0");

    let outcome = eval_whnf_owned(&ir).expect("repeated projected-shaped hasAttr misses");

    assert_eq!(outcome.value().as_int(), Ok(0));
    assert_eq!(outcome.stats().inline_cache_hits(), 0);
    assert_eq!(outcome.stats().inline_cache_misses(), 2);
    let ic_snapshot = outcome.attr_telemetry().inline_cache_snapshot();
    assert_eq!(ic_snapshot.flat_select_sites.monomorphic, 0);
    assert_eq!(ic_snapshot.shaped_select_sites.uninitialized, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.misses, 2);
    assert_eq!(ic_snapshot.shaped_select_lookups.resolved_misses, 2);
    assert_eq!(ic_snapshot.shaped_select_lookups.cached_misses, 0);
    let counts = outcome.attr_telemetry().slow_select_snapshot();
    assert_eq!(counts.flat_misses, 0);
    assert_eq!(counts.shaped_hits, 0);
    assert_eq!(counts.shaped_misses, 2);
}

#[test]
fn polymorphic_static_has_attr_keeps_shaped_cache_after_missing_receivers() {
    let ir = lower(
        "let f = x: x ? b;
         in (if (f { b = 1; }) then 1 else 0)
          + (if (f { a = 0; b = 2; }) then 2 else 0)
          + (if (f { c = 0; }) then 0 else 4)
          + (if (f { c = 1; }) then 0 else 8)
          + (if (f { b = 3; }) then 16 else 0)
          + (if (f { a = 0; b = 4; }) then 32 else 0)",
    );

    let outcome = eval_whnf_owned(&ir).expect("polymorphic hit-miss-hit-miss hasAttr evaluates");

    assert_eq!(outcome.value().as_int(), Ok(63));
    assert_eq!(outcome.stats().inline_cache_hits(), 2);
    assert_eq!(outcome.stats().inline_cache_misses(), 4);
    let ic_snapshot = outcome.attr_telemetry().inline_cache_snapshot();
    assert_eq!(ic_snapshot.flat_select_sites.polymorphic, 0);
    assert_eq!(ic_snapshot.shaped_select_sites.polymorphic, 1);
    assert_eq!(ic_snapshot.shaped_select_lookups.hits, 4);
    assert_eq!(ic_snapshot.shaped_select_lookups.misses, 2);
    assert_eq!(ic_snapshot.shaped_select_lookups.resolved_hits, 2);
    assert_eq!(ic_snapshot.shaped_select_lookups.cached_hits, 2);
    assert_eq!(ic_snapshot.shaped_select_lookups.resolved_misses, 2);
    assert_eq!(ic_snapshot.shaped_select_lookups.cached_misses, 0);
    assert_eq!(ic_snapshot.shaped_select_lookups.monomorphic_fast_hits, 0);
    let counts = outcome.attr_telemetry().slow_select_snapshot();
    assert_eq!(counts.flat_hits, 0);
    assert_eq!(counts.flat_misses, 0);
    assert_eq!(counts.shaped_hits, 2);
    assert_eq!(counts.shaped_misses, 2);
}
