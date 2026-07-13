//! Split-out tests (part_3). See parent module.

use super::*;

#[test]
fn megamorphic_static_has_attr_stays_slow_after_missing_receivers() {
    let ir = lower(
        "let f = x: x ? a;
         in (if (f { a = 1; }) then 1 else 0)
          + (if (f { b = 0; a = 2; }) then 2 else 0)
          + (if (f { c = 0; a = 3; }) then 3 else 0)
          + (if (f { d = 0; a = 4; }) then 4 else 0)
          + (if (f { e = 0; a = 5; }) then 5 else 0)
          + (if (f { missing = 0; }) then 0 else 10)
          + (if (f { missing = 1; }) then 0 else 20)
          + (if (f { a = 6; }) then 6 else 0)",
    );

    let outcome = eval_whnf_owned(&ir).expect("megamorphic hit-miss-hit hasAttr evaluates");

    assert_eq!(outcome.value().as_int(), Ok(51));
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
fn repeated_static_has_attr_site_uses_hamt_inline_cache_for_projected_hamt_receivers() {
    let ir = lower(
        "let base = ((((({ a = 1; } // { b = 2; }) // { c = 3; }) // { d = 4; }) // { e = 5; }) // { f = 6; });
             has = x: x ? f;
         in if (has base) && (has base) then 1 else 0",
    );

    let outcome = eval_whnf_owned(&ir).expect("repeated projected-HAMT hasAttr evaluates");

    assert_eq!(outcome.value().as_int(), Ok(1));
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
fn repeated_static_has_attr_site_uses_hamt_inline_cache_for_projected_hamt_misses() {
    let ir = lower(
        "let base = ((((({ a = 1; } // { b = 2; }) // { c = 3; }) // { d = 4; }) // { e = 5; }) // { f = 6; });
             has = x: x ? missing;
         in if (has base) || (has base) then 1 else 0",
    );

    let outcome = eval_whnf_owned(&ir).expect("repeated projected-HAMT hasAttr misses");

    assert_eq!(outcome.value().as_int(), Ok(0));
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
fn attr_update_telemetry_tracks_projected_hamt_left_state() {
    let ir = lower(
        "((((({ a = 1; } // { b = 2; }) // { c = 3; }) // { d = 4; }) // { e = 5; }) // { f = 6; }).f",
    );

    let outcome = eval_whnf_owned(&ir).expect("deep attr update chain evaluates");

    assert_eq!(outcome.value().as_int(), Ok(6));
    let snapshot = outcome
        .attr_telemetry()
        .update_merge_snapshot()
        .expect("merge telemetry snapshot allocates");
    assert_eq!(snapshot.decisions, 11);
    assert_eq!(snapshot.flat_decisions, 9);
    assert_eq!(snapshot.hamt_decisions, 2);
    assert_eq!(snapshot.update_merges, 5);
    assert_eq!(snapshot.flat_update_merges, 3);
    assert_eq!(snapshot.hamt_update_merges, 2);
    assert_eq!(snapshot.hamt_inserted, 2);
    assert_eq!(snapshot.hamt_replaced, 0);
    assert_eq!(snapshot.reasons.static_literal, 6);
    assert_eq!(snapshot.reasons.small_shape_stable, 3);
    assert_eq!(snapshot.reasons.deep_override_chain, 1);
    assert_eq!(snapshot.reasons.left_already_hamt, 1);
}

#[test]
fn attr_update_heap_metadata_records_projected_hamt_repr() {
    let ir = lower(
        "((((({ a = 1; } // { b = 2; }) // { c = 3; }) // { d = 4; }) // { e = 5; }) // { f = 6; })",
    );
    let f = symbol_for(&ir, b"f");

    let outcome = eval_whnf_owned(&ir).expect("deep attr update chain evaluates");
    let metadata = outcome
        .heap()
        .get_attrs_metadata(outcome.value())
        .expect("result metadata exists");
    let attrs = outcome
        .heap()
        .get_attrs(outcome.value())
        .expect("result attrs remain flat-readable");

    assert_eq!(metadata.shape(), 0);
    assert!(metadata.projected_shape().is_some());
    assert_eq!(metadata.repr(), AttrSetReprKind::Hamt);
    assert_eq!(attrs.get(f).expect("f exists").as_int(), Ok(6));
}

#[test]
fn static_attrset_heap_metadata_records_projected_shape() {
    let ir = lower("{ b = 2; a = 1; }");

    let outcome = eval_whnf_owned(&ir).expect("static attrset evaluates");
    let metadata = outcome
        .heap()
        .get_attrs_metadata(outcome.value())
        .expect("result metadata exists");

    assert_eq!(metadata.shape(), 0);
    assert!(metadata.projected_shape().is_some());
    assert_eq!(metadata.repr(), AttrSetReprKind::Flat);
    let census = outcome
        .attr_telemetry()
        .shape_census()
        .expect("shape census snapshot allocates");
    assert_eq!(census.total_instances, 1);
    assert_eq!(census.shapes.len(), 1);
    assert_eq!(census.shapes[0].key_count, 2);
}

#[test]
fn projected_shape_static_attr_names_and_values_preserve_raw_byte_order() {
    let attrs_source = "{ z = 1; A = 2; aa = 3; _ = 4; a = 5; }";
    let names_source = format!("builtins.attrNames {attrs_source}");
    let values_source = format!("builtins.attrValues {attrs_source}");

    assert_eq!(
        eval_list_string_bytes(&names_source),
        vec![
            b"A".to_vec(),
            b"_".to_vec(),
            b"a".to_vec(),
            b"aa".to_vec(),
            b"z".to_vec(),
        ],
    );
    assert_eq!(eval_list_ints(&values_source), vec![2, 4, 5, 3, 1]);

    let ir = lower(attrs_source);
    let outcome = eval_whnf_owned(&ir).expect("projected-shape static attrset evaluates");
    let metadata = outcome
        .heap()
        .get_attrs_metadata(outcome.value())
        .expect("result metadata exists");

    assert!(metadata.projected_shape().is_some());
    assert_eq!(metadata.repr(), AttrSetReprKind::Flat);
}

#[test]
fn attr_names_and_values_record_projected_shape_order_parity_telemetry() {
    let ir = lower(
        "
        let attrs = { z = 1; A = 2; aa = 3; _ = 4; a = 5; };
        in builtins.length (builtins.attrNames attrs)
           + builtins.length (builtins.attrValues attrs)
        ",
    );
    let outcome = eval_whnf_owned(&ir).expect("attr order-parity sample evaluates");

    assert_eq!(outcome.value().as_int(), Ok(10));
    let stats = outcome.attr_telemetry().order_parity_stats();
    assert_eq!(stats.matched, 2);
    assert_eq!(stats.mismatched, 0);
}

#[test]
fn map_attrs_projected_shape_preserves_order_and_records_order_parity_telemetry() {
    let attrs_source = "{ z = 1; A = 2; aa = 3; _ = 4; a = 5; }";
    let names_source =
        format!("builtins.attrNames (builtins.mapAttrs (_name: value: value + 1) {attrs_source})");
    let values_source = format!(
        "builtins.concatStringsSep \",\" \
         (builtins.attrValues (builtins.mapAttrs (name: _value: name) {attrs_source}))"
    );

    let expected_order = vec![
        b"A".to_vec(),
        b"_".to_vec(),
        b"a".to_vec(),
        b"aa".to_vec(),
        b"z".to_vec(),
    ];
    assert_eq!(eval_list_string_bytes(&names_source), expected_order);
    assert_eq!(eval_string_bytes(&values_source), b"A,_,a,aa,z");

    let ir = lower(&format!(
        "builtins.mapAttrs (_name: value: value + 1) {attrs_source}"
    ));
    let outcome = eval_whnf_owned(&ir).expect("mapAttrs projected-shape result evaluates");
    let metadata = outcome
        .heap()
        .get_attrs_metadata(outcome.value())
        .expect("mapAttrs result metadata exists");

    assert!(metadata.projected_shape().is_some());
    assert_eq!(metadata.repr(), AttrSetReprKind::Flat);
    let stats = outcome.attr_telemetry().order_parity_stats();
    assert_eq!(stats.matched, 1);
    assert_eq!(stats.mismatched, 0);
}

#[test]
fn zip_attrs_with_projected_shape_preserves_order_and_records_order_parity_telemetry() {
    let zip_source = r#"
        builtins.zipAttrsWith
          (name: values: name + ":" + builtins.toString (builtins.length values))
          [ { z = 1; A = 2; } { aa = 3; _ = 4; a = 5; A = 6; } ]
    "#;
    let names_source = format!("builtins.attrNames ({zip_source})");
    let values_source =
        format!("builtins.concatStringsSep \",\" (builtins.attrValues ({zip_source}))");

    assert_eq!(
        eval_list_string_bytes(&names_source),
        vec![
            b"A".to_vec(),
            b"_".to_vec(),
            b"a".to_vec(),
            b"aa".to_vec(),
            b"z".to_vec(),
        ],
    );
    assert_eq!(eval_string_bytes(&values_source), b"A:2,_:1,a:1,aa:1,z:1");

    let ir = lower(zip_source);
    let outcome = eval_whnf_owned(&ir).expect("zipAttrsWith projected-shape result evaluates");
    let metadata = outcome
        .heap()
        .get_attrs_metadata(outcome.value())
        .expect("zipAttrsWith result metadata exists");

    assert!(metadata.projected_shape().is_some());
    assert_eq!(metadata.repr(), AttrSetReprKind::Flat);
    let stats = outcome.attr_telemetry().order_parity_stats();
    assert_eq!(stats.matched, 1);
    assert_eq!(stats.mismatched, 0);
}

#[test]
fn attr_filter_projected_shape_preserves_order_and_records_order_parity_telemetry() {
    let attrs_source = "{ z = 1; A = 2; aa = 3; _ = 4; a = 5; }";
    let remove_source = format!("builtins.removeAttrs {attrs_source} [ \"aa\" ]");
    let intersect_source =
        format!("builtins.intersectAttrs {{ _ = 0; z = 0; A = 0; missing = 0; }} {attrs_source}");

    assert_eq!(
        eval_list_string_bytes(&format!("builtins.attrNames ({remove_source})")),
        vec![b"A".to_vec(), b"_".to_vec(), b"a".to_vec(), b"z".to_vec()],
    );
    assert_eq!(
        eval_list_ints(&format!("builtins.attrValues ({remove_source})")),
        vec![2, 4, 5, 1],
    );
    assert_eq!(
        eval_list_string_bytes(&format!("builtins.attrNames ({intersect_source})")),
        vec![b"A".to_vec(), b"_".to_vec(), b"z".to_vec()],
    );
    assert_eq!(
        eval_list_ints(&format!("builtins.attrValues ({intersect_source})")),
        vec![2, 4, 1],
    );

    for source in [remove_source, intersect_source] {
        let ir = lower(&source);
        let outcome = eval_whnf_owned(&ir).expect("attr filter result evaluates");
        let metadata = outcome
            .heap()
            .get_attrs_metadata(outcome.value())
            .expect("attr filter result metadata exists");

        assert!(metadata.projected_shape().is_some());
        assert_eq!(metadata.repr(), AttrSetReprKind::Flat);
        let stats = outcome.attr_telemetry().order_parity_stats();
        assert_eq!(stats.matched, 1, "{source}");
        assert_eq!(stats.mismatched, 0, "{source}");
    }
}

#[test]
fn partition_projected_shape_preserves_order_and_records_order_parity_telemetry() {
    let source = "builtins.partition (value: value < 3) [ 3 1 2 4 ]";

    assert_eq!(
        eval_list_string_bytes(&format!("builtins.attrNames ({source})")),
        vec![b"right".to_vec(), b"wrong".to_vec()],
    );
    assert_eq!(eval_list_ints(&format!("({source}).right")), vec![1, 2]);
    assert_eq!(eval_list_ints(&format!("({source}).wrong")), vec![3, 4]);

    let ir = lower(source);
    let outcome = eval_whnf_owned(&ir).expect("partition projected-shape result evaluates");
    let metadata = outcome
        .heap()
        .get_attrs_metadata(outcome.value())
        .expect("partition result metadata exists");

    assert!(metadata.projected_shape().is_some());
    assert_eq!(metadata.repr(), AttrSetReprKind::Flat);
    let stats = outcome.attr_telemetry().order_parity_stats();
    assert_eq!(stats.matched, 1);
    assert_eq!(stats.mismatched, 0);
}

#[test]
fn codec_projected_shape_preserves_order_and_records_order_parity_telemetry() {
    let json_source = r#"builtins.fromJSON ''{"z":1,"A":2,"aa":3,"_":4,"a":5}''"#;
    let toml_source = r#"builtins.fromTOML "z = 1
A = 2
aa = 3
_ = 4
a = 5
""#;

    for source in [json_source, toml_source] {
        assert_eq!(
            eval_list_string_bytes(&format!("builtins.attrNames ({source})")),
            vec![
                b"A".to_vec(),
                b"_".to_vec(),
                b"a".to_vec(),
                b"aa".to_vec(),
                b"z".to_vec(),
            ],
            "{source}",
        );
        assert_eq!(
            eval_list_ints(&format!("builtins.attrValues ({source})")),
            vec![2, 4, 5, 3, 1],
            "{source}",
        );

        let ir = lower(source);
        let outcome = eval_whnf_owned(&ir).expect("codec projected-shape result evaluates");
        let metadata = outcome
            .heap()
            .get_attrs_metadata(outcome.value())
            .expect("codec result metadata exists");

        assert!(metadata.projected_shape().is_some(), "{source}");
        assert_eq!(metadata.repr(), AttrSetReprKind::Flat, "{source}");
        let stats = outcome.attr_telemetry().order_parity_stats();
        assert_eq!(stats.matched, 1, "{source}");
        assert_eq!(stats.mismatched, 0, "{source}");
    }
}

#[test]
fn path_surface_projected_shape_preserves_order_and_records_order_parity_telemetry() {
    let root = unique_temp_dir("path-surface-order");
    fs::write(root.join("a"), b"regular").expect("regular file writes");
    fs::create_dir(root.join("_")).expect("underscore directory creates");
    std::os::unix::fs::symlink(root.join("a"), root.join("0")).expect("symlink creates");
    fs::create_dir(root.join("aa")).expect("aa directory creates");
    fs::write(root.join("z"), b"regular").expect("z file writes");

    let parse_source = r#"builtins.parseDrvName "pkg-1.0""#;
    assert_eq!(
        eval_list_string_bytes(&format!("builtins.attrNames ({parse_source})")),
        vec![b"name".to_vec(), b"version".to_vec()],
    );
    assert_eq!(
        eval_list_string_bytes(&format!("builtins.attrValues ({parse_source})")),
        vec![b"pkg".to_vec(), b"1.0".to_vec()],
    );
    let parse_outcome =
        eval_whnf_owned(&lower(parse_source)).expect("parseDrvName result evaluates");
    let parse_metadata = parse_outcome
        .heap()
        .get_attrs_metadata(parse_outcome.value())
        .expect("parseDrvName result metadata exists");
    assert!(parse_metadata.projected_shape().is_some());
    assert_eq!(parse_metadata.repr(), AttrSetReprKind::Flat);
    let parse_stats = parse_outcome.attr_telemetry().order_parity_stats();
    assert_eq!(parse_stats.matched, 1);
    assert_eq!(parse_stats.mismatched, 0);

    let read_source = format!(
        "builtins.readDir {}",
        nix_string_literal(&path_source(&root))
    );
    assert_eq!(
        eval_list_string_bytes(&format!("builtins.attrNames ({read_source})")),
        vec![
            b"0".to_vec(),
            b"_".to_vec(),
            b"a".to_vec(),
            b"aa".to_vec(),
            b"z".to_vec(),
        ],
    );
    assert_eq!(
        eval_list_string_bytes(&format!("builtins.attrValues ({read_source})")),
        vec![
            b"symlink".to_vec(),
            b"directory".to_vec(),
            b"regular".to_vec(),
            b"directory".to_vec(),
            b"regular".to_vec(),
        ],
    );
    let read_outcome = eval_whnf_owned(&lower(&read_source)).expect("readDir result evaluates");
    let read_metadata = read_outcome
        .heap()
        .get_attrs_metadata(read_outcome.value())
        .expect("readDir result metadata exists");
    assert!(read_metadata.projected_shape().is_some());
    assert_eq!(read_metadata.repr(), AttrSetReprKind::Flat);
    let read_stats = read_outcome.attr_telemetry().order_parity_stats();
    assert_eq!(read_stats.matched, 1);
    assert_eq!(read_stats.mismatched, 0);

    let options = search_path_options(b"pkg", &root);
    assert_eq!(
        eval_list_string_bytes_with_options(
            "builtins.attrNames (builtins.head builtins.nixPath)",
            options.clone(),
        ),
        vec![b"path".to_vec(), b"prefix".to_vec()],
    );
    assert_eq!(
        eval_list_string_bytes_with_options(
            "builtins.attrValues (builtins.head builtins.nixPath)",
            options.clone(),
        ),
        vec![path_bytes(&root), b"pkg".to_vec()],
    );
    let nix_path_ir = lower("builtins.nixPath");
    let nix_path_outcome =
        eval_whnf_owned_with_options(&nix_path_ir, options).expect("nixPath result evaluates");
    let nix_path_entry = {
        let list = nix_path_outcome
            .heap()
            .get_list(nix_path_outcome.value())
            .expect("nixPath result is a list");
        list.get(0).expect("nixPath entry exists")
    };
    let nix_path_metadata = nix_path_outcome
        .heap()
        .get_attrs_metadata(nix_path_entry)
        .expect("nixPath entry metadata exists");
    assert!(nix_path_metadata.projected_shape().is_some());
    assert_eq!(nix_path_metadata.repr(), AttrSetReprKind::Flat);
    let nix_path_stats = nix_path_outcome.attr_telemetry().order_parity_stats();
    assert_eq!(nix_path_stats.matched, 1);
    assert_eq!(nix_path_stats.mismatched, 0);

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn function_args_projected_shape_preserves_order_and_records_order_parity_telemetry() {
    let source = r#"builtins.functionArgs ({ z ? (throw "z"), A, aa ? 1, _, a ? 2 }: A)"#;

    assert_eq!(
        eval_list_string_bytes(&format!("builtins.attrNames ({source})")),
        vec![
            b"A".to_vec(),
            b"_".to_vec(),
            b"a".to_vec(),
            b"aa".to_vec(),
            b"z".to_vec(),
        ],
    );
    assert_eq!(
        eval(&format!(
            "builtins.attrValues ({source}) == [ false false true true true ]"
        ))
        .as_bool(),
        Ok(true),
    );

    let ir = lower(source);
    let outcome = eval_whnf_owned(&ir).expect("functionArgs projected-shape result evaluates");
    let metadata = outcome
        .heap()
        .get_attrs_metadata(outcome.value())
        .expect("functionArgs result metadata exists");

    assert!(metadata.projected_shape().is_some());
    assert_eq!(metadata.repr(), AttrSetReprKind::Flat);
    let stats = outcome.attr_telemetry().order_parity_stats();
    assert_eq!(stats.matched, 1);
    assert_eq!(stats.mismatched, 0);
}

#[test]
fn list_to_attrs_projected_shape_preserves_order_and_records_order_parity_telemetry() {
    let list_source = r#"[
        { name = "z"; value = 1; }
        { name = "A"; value = 2; }
        { name = "aa"; value = 3; }
        { name = "_"; value = 4; }
        { name = "a"; value = 5; }
        { name = "a"; value = 99; }
    ]"#;
    let attrs_source = format!("builtins.listToAttrs {list_source}");

    assert_eq!(
        eval_list_string_bytes(&format!("builtins.attrNames ({attrs_source})")),
        vec![
            b"A".to_vec(),
            b"_".to_vec(),
            b"a".to_vec(),
            b"aa".to_vec(),
            b"z".to_vec(),
        ],
    );
    assert_eq!(
        eval_list_ints(&format!("builtins.attrValues ({attrs_source})")),
        vec![2, 4, 5, 3, 1],
    );

    let ir = lower(&attrs_source);
    let outcome = eval_whnf_owned(&ir).expect("listToAttrs projected-shape result evaluates");
    let metadata = outcome
        .heap()
        .get_attrs_metadata(outcome.value())
        .expect("listToAttrs result metadata exists");

    assert!(metadata.projected_shape().is_some());
    assert_eq!(metadata.repr(), AttrSetReprKind::Flat);
    let stats = outcome.attr_telemetry().order_parity_stats();
    assert_eq!(stats.matched, 1);
    assert_eq!(stats.mismatched, 0);
}

#[test]
fn group_by_projected_shape_preserves_order_and_records_order_parity_telemetry() {
    let source = r#"
        builtins.groupBy
          (value:
            if value == "z" then "z"
            else if value == "A" then "A"
            else if value == "aa" then "aa"
            else if value == "_" then "_"
            else "a")
          [ "z" "A" "aa" "_" "a" "A" ]
    "#;

    assert_eq!(
        eval_list_string_bytes(&format!("builtins.attrNames ({source})")),
        vec![
            b"A".to_vec(),
            b"_".to_vec(),
            b"a".to_vec(),
            b"aa".to_vec(),
            b"z".to_vec(),
        ],
    );
    assert_eq!(
        eval(&format!("builtins.length ({source}).A")).as_int(),
        Ok(2),
    );

    let ir = lower(source);
    let outcome = eval_whnf_owned(&ir).expect("groupBy projected-shape result evaluates");
    let metadata = outcome
        .heap()
        .get_attrs_metadata(outcome.value())
        .expect("groupBy result metadata exists");

    assert!(metadata.projected_shape().is_some());
    assert_eq!(metadata.repr(), AttrSetReprKind::Flat);
    let stats = outcome.attr_telemetry().order_parity_stats();
    assert_eq!(stats.matched, 1);
    assert_eq!(stats.mismatched, 0);
}

#[test]
fn force_cache_payload_replay_preserves_attr_repr_metadata() {
    let ir = lower(
        "((((({ a = 1; } // { b = 2; }) // { c = 3; }) // { d = 4; }) // { e = 5; }) // { f = 6; })",
    );
    let f = symbol_for(&ir, b"f");
    let mut evaluator = TreeWalk::new(&ir);
    let value = evaluator
        .eval_root()
        .expect("deep attr update chain evaluates");
    let payload = evaluator
        .force_cache_payload_for_value(value)
        .expect("HAMT-projected attrs capture as a cache payload");

    let mut replay = TreeWalk::new(&ir);
    let value = replay
        .value_for_cached_expression_payload_for_test(payload)
        .expect("cached attr payload replays");
    let metadata = replay
        .heap()
        .get_attrs_metadata(value)
        .expect("replayed metadata exists");
    let attrs = replay
        .heap()
        .get_attrs(value)
        .expect("replayed attrs remain flat-readable");

    assert_eq!(metadata.shape(), 0);
    assert!(metadata.projected_shape().is_some());
    assert_eq!(metadata.repr(), AttrSetReprKind::Hamt);
    assert_eq!(attrs.get(f).expect("f exists").as_int(), Ok(6));
    assert_eq!(replay.stats.shape_transitions(), 6);

    let census = replay
        .attr_telemetry
        .shape_census()
        .expect("shape census snapshot allocates");
    assert_eq!(census.total_instances, 1);
    assert_eq!(census.distinct_shapes, 1);
    assert_eq!(census.shapes[0].key_count, 6);
}

#[test]
fn attr_update_telemetry_records_hamt_replacements_from_dispatch_bridge() {
    let ir = lower(
        "((((({ a = 1; b = 2; } // { c = 3; }) // { d = 4; }) // { e = 5; }) // { a = 50; }) // { c = 60; }).c",
    );

    let outcome = eval_whnf_owned(&ir).expect("deep replacement attr update chain evaluates");

    assert_eq!(outcome.value().as_int(), Ok(60));
    let snapshot = outcome
        .attr_telemetry()
        .update_merge_snapshot()
        .expect("merge telemetry snapshot allocates");
    assert_eq!(snapshot.update_merges, 5);
    assert_eq!(snapshot.hamt_update_merges, 2);
    assert_eq!(snapshot.hamt_inserted, 0);
    assert_eq!(snapshot.hamt_replaced, 2);
    assert_eq!(snapshot.reasons.deep_override_chain, 1);
    assert_eq!(snapshot.reasons.left_already_hamt, 1);
}

#[test]
fn attr_update_telemetry_does_not_attach_reused_result_depth_to_canonical_attrs() {
    let ir = lower(
        "let base = { a = 1; }; noop = base // {}; in builtins.seq noop ((base // { b = 2; }).b)",
    );

    let outcome = eval_whnf_owned(&ir).expect("reused attr update result evaluates");

    assert_eq!(outcome.value().as_int(), Ok(2));
    let snapshot = outcome
        .attr_telemetry()
        .update_merge_snapshot()
        .expect("merge telemetry snapshot allocates");
    assert_eq!(snapshot.update_merges, 2);
    assert_eq!(
        &*snapshot.override_chain_depth_distribution,
        &[HistogramBucket { value: 1, count: 2 }],
    );
}

#[test]
fn attr_update_telemetry_keys_projected_state_by_module() {
    let ir = lower("1");
    let mut evaluator = TreeWalk::new(&ir);
    let span = Span::new(0, 0);
    let module = evaluator
        .push_module(
            IrId::new(0),
            span,
            lower("1"),
            b"/tmp".to_vec(),
            b"/tmp/imported.nix".to_vec(),
            b"1".to_vec(),
        )
        .expect("test module loads");

    evaluator
        .with_current_module(module, |eval| {
            eval.record_attr_update_telemetry(IrId::new(10), span, IrId::new(1), 1, 1);
            eval.record_attr_update_telemetry(IrId::new(11), span, IrId::new(10), 2, 1);
            eval.record_attr_update_telemetry(IrId::new(12), span, IrId::new(11), 3, 1);
            eval.record_attr_update_telemetry(IrId::new(13), span, IrId::new(12), 4, 1);
            Ok(())
        })
        .expect("imported module telemetry records");
    evaluator.record_attr_update_telemetry(IrId::new(20), span, IrId::new(13), 1, 1);

    let snapshot = evaluator
        .attr_telemetry
        .update_merge_snapshot()
        .expect("merge telemetry snapshot allocates");
    assert_eq!(snapshot.decisions, 5);
    assert_eq!(snapshot.flat_decisions, 4);
    assert_eq!(snapshot.hamt_decisions, 1);
    assert_eq!(snapshot.reasons.small_shape_stable, 4);
    assert_eq!(snapshot.reasons.deep_override_chain, 1);
    assert_eq!(snapshot.reasons.left_already_hamt, 0);
    assert_eq!(
        &*snapshot.override_chain_depth_distribution,
        &[
            HistogramBucket { value: 1, count: 2 },
            HistogramBucket { value: 2, count: 1 },
            HistogramBucket { value: 3, count: 1 },
            HistogramBucket { value: 4, count: 1 },
        ],
    );
}

#[test]
fn strictness_analysis_preserves_unreached_dynamic_attr_path_ordering() {
    let mut select_ir = lower("({}).${\"a\"}.${1 / 0} or 2");
    crate::compile::annotate_strictness(&mut select_ir).expect("strictness analysis succeeds");
    let select = eval_whnf_owned(&select_ir).expect("unreached dynamic select key stays lazy");
    assert_eq!(select.value().as_int(), Ok(2));

    let mut has_attr_ir = lower("({} ? missing.${1 / 0})");
    crate::compile::annotate_strictness(&mut has_attr_ir).expect("strictness analysis succeeds");
    let has_attr = eval_whnf_owned(&has_attr_ir).expect("unreached dynamic hasAttr key stays lazy");
    assert_eq!(has_attr.value().as_bool(), Ok(false));
}

#[test]
fn strict_attr_binding_facts_do_not_preempt_dynamic_attr_name_errors() {
    let mut ir = lower(r#"({ a = builtins.throw "value"; ${builtins.throw "key"} = 1; }).a"#);
    mark_all_thunk_allocs_strict(&mut ir);

    let error = eval_whnf_owned(&ir).expect_err("dynamic key error wins");

    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected thrown dynamic key error");
    };
    assert_eq!(message, b"key");
}

#[test]
fn strict_thunk_alloc_facts_do_not_elide_during_let_frame_initialization() {
    let mut ir = lower("let x = y; y = 7; in x");
    mark_all_thunk_allocs_strict(&mut ir);

    let outcome = eval_whnf_owned(&ir).expect("forward let reference evaluates");

    assert_eq!(outcome.value().as_int(), Ok(7));
    assert_eq!(outcome.stats().thunks_elided(), 0);
}

#[test]
fn strict_thunk_alloc_facts_do_not_elide_during_recursive_attr_frame_initialization() {
    let mut ir = lower("(rec { a = b; b = 7; }).a");
    mark_all_thunk_allocs_strict(&mut ir);

    let outcome = eval_whnf_owned(&ir).expect("forward rec attr reference evaluates");

    assert_eq!(outcome.value().as_int(), Ok(7));
}

#[test]
fn strict_thunk_alloc_facts_do_not_elide_during_formal_default_initialization() {
    let mut ir = lower("({ a ? b, b }: a) { b = 2; }");
    mark_all_thunk_allocs_strict(&mut ir);

    let outcome = eval_whnf_owned(&ir).expect("forward formal default evaluates");

    assert_eq!(outcome.value().as_int(), Ok(2));
}

#[test]
fn strict_inherited_select_binding_facts_stay_lazy_during_attrset_assembly() {
    let mut ir = lower("{ inherit ({ a = 1 + 6; }) a; }");
    let a = symbol_for(&ir, b"a");
    let inherited_select = first_inherit_select_thunk_alloc_id(&ir);
    *ir.facts
        .get_mut(inherited_select)
        .expect("inherited select fact exists") = crate::compile::ExprFacts {
        strictness: crate::compile::Strictness::DemandedBeforeEffect,
        cardinality: crate::compile::Cardinality::Many,
        escape: crate::compile::Escape::Escapes,
    };

    let outcome = eval_whnf_owned(&ir).expect("strict inherited select evaluates");
    let attr_value = {
        let attrs = outcome
            .heap()
            .get_attrs(outcome.value())
            .expect("root is a heap-owned attrset");
        attrs.get(a).expect("a exists")
    };

    assert_eq!(attr_value.tag(), ValueTag::Thunk);
    assert_eq!(outcome.stats().thunks_elided(), 0);
}

