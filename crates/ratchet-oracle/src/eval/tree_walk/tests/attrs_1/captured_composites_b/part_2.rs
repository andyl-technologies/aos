//! Split-out tests (part_2). See parent module.

use super::*;

#[test]
fn captured_static_select_defaults_hit_when_present_branch_ignores_default_and_siblings() {
    let (ir, used, unused) = captured_static_select_default_projection_ir();
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for (offset, expected_hit) in [(0, false), (10, true)] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "captured-static-select-default-present.nix",
            "x.used or default",
            cache.clone(),
        );
        let default_value = unhashable_apply_thunk(&mut evaluator, IrId::new(3 + offset));
        let unused_value = unhashable_apply_thunk(&mut evaluator, IrId::new(4 + offset));
        let thunk_value = captured_static_select_default_thunk_for_attrs(
            &mut evaluator,
            &ir,
            used,
            unused,
            Some(Value::int(7)),
            unused_value,
            default_value,
        );
        let subject = {
            let thunk = evaluator
                .heap()
                .get_thunk(thunk_value)
                .expect("captured defaulted static select thunk is heap-owned");
            evaluator
                .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
                .expect("present defaulted static select subject builds")
        };
        assert_eq!(
            subject.free_var_value_hashes.len(),
            1,
            "present defaulted selects should hash only the selected branch"
        );

        let hits_before = evaluator.stats().force_cache_hits();
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 17), thunk_value)
            .expect("captured defaulted static select force succeeds");

        assert_eq!(forced.as_int(), Ok(7));
        assert_eq!(
            evaluator.stats().force_cache_hits() > hits_before,
            expected_hit,
            "unused defaults and siblings should not dirty a present selected path"
        );
        for lazy in [default_value, unused_value] {
            assert_eq!(
                evaluator
                    .heap()
                    .get_thunk(lazy)
                    .expect("lazy fixture thunk remains heap-owned")
                    .cell()
                    .state(),
                Ok(ThunkState::Suspended),
                "present select-default branch must not force unused inputs"
            );
        }
    }
}

#[test]
fn captured_static_select_defaults_present_nested_let_ignores_bound_default_capture() {
    let (ir, used, unused) = captured_static_select_default_nested_let_projection_ir();
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for (default_value, expected_hit) in [(11, false), (12, true)] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "captured-static-select-default-present-nested-let.nix",
            "let default = captured; in x.used or default",
            cache.clone(),
        );
        let thunk_value = captured_static_select_default_thunk_for_attrs(
            &mut evaluator,
            &ir,
            used,
            unused,
            Some(Value::int(7)),
            Value::int(1),
            Value::int(default_value),
        );
        let subject = {
            let thunk = evaluator
                .heap()
                .get_thunk(thunk_value)
                .expect("captured nested-let defaulted static select thunk is heap-owned");
            evaluator
                .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
                .expect("present nested-let defaulted static select subject builds")
        };
        assert_eq!(
            subject.free_var_value_hashes.len(),
            1,
            "present nested-let defaults should hash only the selected branch"
        );

        let hits_before = evaluator.stats().force_cache_hits();
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 34), thunk_value)
            .expect("captured nested-let defaulted static select force succeeds");

        assert_eq!(forced.as_int(), Ok(7));
        assert_eq!(
            evaluator.stats().force_cache_hits() > hits_before,
            expected_hit,
            "bound default captures should not dirty a present selected path"
        );
    }
}

#[test]
fn captured_static_select_defaults_miss_when_present_selected_values_change() {
    let (ir, used, unused) = captured_static_select_default_projection_ir();
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for selected_value in [7, 8] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "captured-static-select-default-present-change.nix",
            "x.used or default",
            cache.clone(),
        );
        let thunk_value = captured_static_select_default_thunk_for_attrs(
            &mut evaluator,
            &ir,
            used,
            unused,
            Some(Value::int(selected_value)),
            Value::int(1),
            Value::int(99),
        );
        let subject = {
            let thunk = evaluator
                .heap()
                .get_thunk(thunk_value)
                .expect("captured defaulted static select thunk is heap-owned");
            evaluator
                .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
                .expect("present defaulted static select subject builds")
        };
        assert_eq!(
            subject.free_var_value_hashes.len(),
            1,
            "present defaulted selects should hash the selected value"
        );

        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 17), thunk_value)
            .expect("captured defaulted static select force succeeds");

        assert_eq!(forced.as_int(), Ok(selected_value));
        assert_eq!(
            evaluator.stats().force_cache_hits(),
            0,
            "changed selected values must not false-hit defaulted select payloads"
        );
    }
}

#[test]
fn captured_static_select_defaults_separate_present_and_missing_equal_values() {
    let (ir, used, unused) = captured_static_select_default_projection_ir();
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut present = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "captured-static-select-default-branch-separation.nix",
        "x.used or default",
        cache.clone(),
    );
    let present_thunk = captured_static_select_default_thunk_for_attrs(
        &mut present,
        &ir,
        used,
        unused,
        Some(Value::int(7)),
        Value::int(1),
        Value::int(99),
    );
    let present_forced = present
        .force_admitted_value(ir.root, Span::new(0, 17), present_thunk)
        .expect("present defaulted select force succeeds");
    assert_eq!(present_forced.as_int(), Ok(7));

    let mut missing = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "captured-static-select-default-branch-separation.nix",
        "x.used or default",
        cache.clone(),
    );
    let missing_thunk = captured_static_select_default_thunk_for_attrs(
        &mut missing,
        &ir,
        used,
        unused,
        None,
        Value::int(1),
        Value::int(7),
    );
    let subject = {
        let thunk = missing
            .heap()
            .get_thunk(missing_thunk)
            .expect("missing defaulted static select thunk is heap-owned");
        missing
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
            .expect("missing defaulted static select subject builds")
    };
    assert_eq!(
        subject.free_var_value_hashes.len(),
        2,
        "missing branch should hash the branch marker and default capture"
    );
    let missing_forced = missing
        .force_admitted_value(ir.root, Span::new(0, 17), missing_thunk)
        .expect("missing defaulted select force succeeds");
    assert_eq!(missing_forced.as_int(), Ok(7));
    assert_eq!(
        missing.stats().force_cache_hits(),
        0,
        "present and missing branches must not share a payload even with equal results"
    );
}

#[test]
fn captured_static_select_present_defaults_do_not_scan_unused_unsupported_defaults() {
    let mut symbols = SymbolTable::new();
    let used = symbols.intern(b"used").expect("used interns");
    let path = IrAttrPathId::new(0);
    let ir = manual_ir_with_attr_paths(
        IrId::new(2),
        vec![
            pure_node(IrKind::LocalVar, Span::new(0, 1), IrData::Local { slot: 0 }),
            pure_node(
                IrKind::AttrSet,
                Span::new(10, 15),
                IrData::AttrSet {
                    shape: IrShapeId::new(0),
                    bindings: IrBindingSlice::new(0, 0),
                    recursive: true,
                    has_dynamic: false,
                    frame: None,
                },
            ),
            pure_node(
                IrKind::Select,
                Span::new(0, 15),
                IrData::Select {
                    site: IrInlineCacheSiteId::new(0),
                    receiver: IrId::new(0),
                    path,
                    default: Some(IrId::new(1)),
                },
            ),
        ],
        symbols,
        vec![Box::new([IrAttrPathSegment::Static(used)])],
    );
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "captured-static-select-default-unsupported-present.nix",
        "x.used or rec {}",
        cache.clone(),
    );
    let attrs = FlatAttrs::new(
        vec![AttrEntry::new(used, Value::int(7))],
        &evaluator.symbols,
    )
    .expect("captured receiver attrs build");
    let captured = evaluator
        .heap
        .alloc_attrs(0, attrs)
        .expect("captured receiver attrs allocate");
    let frame = EvalFrame::new(1).expect("capture frame allocates");
    frame
        .set(0, captured)
        .expect("receiver capture frame slot sets");
    let env = EvalEnv::capture(&[frame]).expect("capture env allocates");
    let thunk_value = evaluator
        .heap
        .alloc_thunk(EvalThunk::with_env(EvalModuleId::ROOT, ir.root, env))
        .expect("captured defaulted static select thunk allocates");
    let subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("present defaulted static select thunk is heap-owned");
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
            .expect("present branch should not scan the unused unsupported default")
    };
    assert_eq!(
        subject.free_var_value_hashes.len(),
        1,
        "present branch should key only on selected value plus branch marker"
    );

    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 15), thunk_value)
        .expect("present defaulted static select force succeeds");
    assert_eq!(forced.as_int(), Ok(7));
}

#[test]
fn captured_static_select_defaults_missing_branch_hashes_default_capture() {
    let (ir, used, unused) = captured_static_select_default_projection_ir();
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for (offset, default_value, expected_hit) in [(0, 11, false), (10, 11, true), (20, 12, false)] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "captured-static-select-default-missing.nix",
            "x.used or default",
            cache.clone(),
        );
        let unused_value = unhashable_apply_thunk(&mut evaluator, IrId::new(3 + offset));
        let thunk_value = captured_static_select_default_thunk_for_attrs(
            &mut evaluator,
            &ir,
            used,
            unused,
            None,
            unused_value,
            Value::int(default_value),
        );
        let subject = {
            let thunk = evaluator
                .heap()
                .get_thunk(thunk_value)
                .expect("captured defaulted static select thunk is heap-owned");
            evaluator
                .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
                .expect("missing defaulted static select subject builds")
        };
        assert_eq!(
            subject.free_var_value_hashes.len(),
            2,
            "missing defaulted selects should hash the missing branch and default capture"
        );

        let hits_before = evaluator.stats().force_cache_hits();
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 17), thunk_value)
            .expect("captured defaulted static select force succeeds");

        assert_eq!(forced.as_int(), Ok(default_value));
        assert_eq!(
            evaluator.stats().force_cache_hits() > hits_before,
            expected_hit,
            "missing defaulted selects should hit only when the default capture matches"
        );
        assert_eq!(
            evaluator
                .heap()
                .get_thunk(unused_value)
                .expect("unselected sibling remains heap-owned")
                .cell()
                .state(),
            Ok(ThunkState::Suspended),
            "missing defaulted selects should not force unselected receiver siblings"
        );
    }
}

#[test]
fn captured_static_select_defaults_missing_nested_let_hashes_bound_default_capture() {
    let (ir, used, unused) = captured_static_select_default_nested_let_projection_ir();
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for (default_value, expected_hit) in [(11, false), (11, true), (12, false)] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "captured-static-select-default-missing-nested-let.nix",
            "let default = captured; in x.used or default",
            cache.clone(),
        );
        let thunk_value = captured_static_select_default_thunk_for_attrs(
            &mut evaluator,
            &ir,
            used,
            unused,
            None,
            Value::int(1),
            Value::int(default_value),
        );
        let subject = {
            let thunk = evaluator
                .heap()
                .get_thunk(thunk_value)
                .expect("captured nested-let defaulted static select thunk is heap-owned");
            evaluator
                .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
                .expect("missing nested-let defaulted static select subject builds")
        };
        assert_eq!(
            subject.free_var_value_hashes.len(),
            2,
            "missing nested-let defaults should hash the missing branch and bound default capture"
        );

        let hits_before = evaluator.stats().force_cache_hits();
        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 34), thunk_value)
            .expect("captured nested-let defaulted static select force succeeds");

        assert_eq!(forced.as_int(), Ok(default_value));
        assert_eq!(
            evaluator.stats().force_cache_hits() > hits_before,
            expected_hit,
            "missing nested-let defaults should hit only when the bound default capture matches"
        );
    }
}

#[test]
fn captured_static_selects_miss_when_selected_values_change() {
    let (ir, used, unused) = captured_static_select_projection_ir();
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for selected_value in [7, 8] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "captured-static-select-selected-change.nix",
            "x.used",
            cache.clone(),
        );
        let thunk_value = captured_static_select_thunk_for_attrs(
            &mut evaluator,
            &ir,
            used,
            unused,
            Value::int(selected_value),
            Value::int(1),
        );
        let subject = {
            let thunk = evaluator
                .heap()
                .get_thunk(thunk_value)
                .expect("captured static select thunk is heap-owned");
            evaluator
                .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
                .expect("captured static select subject builds")
        };
        assert_eq!(
            subject.free_var_value_hashes.len(),
            1,
            "captured static select subject should hash the selected value"
        );

        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 6), thunk_value)
            .expect("captured static select force succeeds");

        assert_eq!(forced.as_int(), Ok(selected_value));
        assert_eq!(
            evaluator.stats().force_cache_hits(),
            0,
            "changed selected values must not false-hit through the projected key"
        );
    }
}

#[test]
fn captured_static_selects_fallback_to_whole_receiver_without_forcing_suspended_receivers() {
    let source = "let x = { used = 7; unused = 1; }; in { a = x.used; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "captured-static-select-suspended-receiver.nix",
        source,
        cache.clone(),
    );
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let captured_x = {
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("a is a node thunk");
        let env = thunk.env().expect("a captures x");
        env.frames()[0].get(0).expect("x capture exists")
    };
    let x_thunk = evaluator
        .heap()
        .get_thunk(captured_x)
        .expect("x capture is a thunk");
    assert_eq!(x_thunk.cell().state(), Ok(ThunkState::Suspended));

    let subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("a remains a node thunk");
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
            .expect("captured static select fallback subject builds")
    };
    assert_eq!(
        subject.free_var_value_hashes.len(),
        1,
        "fallback subject should retain one whole-receiver hash"
    );
    let x_thunk = evaluator
        .heap()
        .get_thunk(captured_x)
        .expect("x capture remains a thunk");
    assert_eq!(
        x_thunk.cell().state(),
        Ok(ThunkState::Suspended),
        "projection fallback must not force a suspended receiver"
    );

    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("captured static select force succeeds");

    assert_eq!(forced.as_int(), Ok(7));
}

#[test]
fn captured_suspended_computed_thunks_do_not_build_force_cache_subjects() {
    let source = "let x = 1 + 2; in { a = x == 3; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "captured-suspended-computed.nix",
        source,
        cache.clone(),
    );
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let captured_x = {
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("a is a node thunk");
        let env = thunk.env().expect("a captures x");
        env.frames()[0].get(0).expect("x capture exists")
    };
    let x_thunk = evaluator
        .heap()
        .get_thunk(captured_x)
        .expect("x capture is a thunk");
    assert_eq!(x_thunk.cell().state(), Ok(ThunkState::Suspended));

    let subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("a remains a node thunk");
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
    };
    assert!(
        subject.is_none(),
        "captured suspended computed thunks must not be hashed into demand keys"
    );
    let x_thunk = evaluator
        .heap()
        .get_thunk(captured_x)
        .expect("x capture remains a thunk");
    assert_eq!(
        x_thunk.cell().state(),
        Ok(ThunkState::Suspended),
        "probing the captured force-cache subject must not force captured thunks"
    );

    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("captured suspended computed force succeeds");

    assert_eq!(forced.as_bool(), Ok(true));
    let runtime = cache.lock().expect("cache lock is valid");
    assert!(
        runtime.cache().expect("cache is enabled").is_empty(),
        "subjects with captured suspended computed thunks wait for canonical value hashes"
    );
}

#[test]
fn captured_nested_let_body_thunks_use_outer_free_variable_hashes() {
    let source = "let x = 1; in { a = let y = x + 2; in y + 3; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    for expected_hit in [false, true] {
        let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
            &ir,
            TreeWalkOptions::new(),
            "captured-nested-let-body.nix",
            source,
            cache.clone(),
        );
        let root = evaluator.eval_root().expect("attrset evaluates");
        let thunk_value = {
            let attrs = evaluator
                .heap()
                .get_attrs(root)
                .expect("attrset is heap-owned");
            attrs.get(a).expect("a exists")
        };
        let subject = {
            let thunk = evaluator
                .heap()
                .get_thunk(thunk_value)
                .expect("a is a node thunk");
            let body = thunk.body().expect("a has a lowered nested let body");
            let node = ir.arena.node(body).expect("nested let body exists");
            assert!(
                matches!(node.data, IrData::Let { .. }),
                "fixture must exercise a nested let body"
            );
            let env = thunk.env().expect("a captures the outer let frame");
            let slots = TreeWalk::captured_free_variable_slots(&ir, body, env.frames().len())
                .expect("nested let free-variable slots collect");
            assert_eq!(
                slots.len(),
                1,
                "nested let slot scan should retain exactly the outer x capture"
            );
            evaluator
                .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
                .expect("nested let body subject builds")
        };
        assert_eq!(
            subject.free_var_value_hashes.len(),
            1,
            "nested let subject should include exactly the outer x capture"
        );

        let forced = evaluator
            .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("nested let body force succeeds");

        assert_eq!(forced.as_int(), Ok(6));
        assert_eq!(evaluator.stats().cache_hits() > 0, expected_hit);
    }
}

#[test]
fn captured_nested_let_body_thunks_miss_when_outer_free_variables_change() {
    let source = "let f = x: { a = let y = x + 2; in y + 3; }; in { first = f 1; second = f 5; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let first = symbol_for(&ir, b"first");
    let second = symbol_for(&ir, b"second");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "captured-nested-let-body-changed-capture.nix",
        source,
        cache.clone(),
    );
    let root = evaluator.eval_root().expect("attrset evaluates");
    let (first_thunk, second_thunk) = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        (
            attrs.get(first).expect("first exists"),
            attrs.get(second).expect("second exists"),
        )
    };

    let first_attrs_value = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), first_thunk)
        .expect("first function result force succeeds");
    let second_attrs_value = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), second_thunk)
        .expect("second function result force succeeds");
    let (first_a, second_a) = {
        let first_attrs = evaluator
            .heap()
            .get_attrs(first_attrs_value)
            .expect("first function result is an attrset");
        let first_a = first_attrs.get(a).expect("first a exists");
        let second_attrs = evaluator
            .heap()
            .get_attrs(second_attrs_value)
            .expect("second function result is an attrset");
        let second_a = second_attrs.get(a).expect("second a exists");
        (first_a, second_a)
    };
    let first_subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(first_a)
            .expect("first a is a node thunk");
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
            .expect("first nested let body subject builds")
    };
    let second_subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(second_a)
            .expect("second a is a node thunk");
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
            .expect("second nested let body subject builds")
    };
    assert_eq!(
        first_subject.free_var_value_hashes.len(),
        1,
        "first nested let subject should include exactly the outer x capture"
    );
    assert_eq!(
        second_subject.free_var_value_hashes.len(),
        1,
        "second nested let subject should include exactly the outer x capture"
    );
    assert_ne!(
        first_subject.free_var_value_hashes, second_subject.free_var_value_hashes,
        "changed outer captures must produce distinct nested-let demand keys"
    );

    let first_forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), first_a)
        .expect("first nested let body force succeeds");
    let second_forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), second_a)
        .expect("second nested let body force succeeds");

    assert_eq!(first_forced.as_int(), Ok(6));
    assert_eq!(
        second_forced.as_int(),
        Ok(10),
        "changed lambda captures must not replay the first nested-let payload"
    );
    assert_eq!(
        evaluator.stats().cache_hits(),
        0,
        "distinct nested-let capture hashes must miss in one shared runtime"
    );
}

#[test]
fn captured_nested_let_body_thunks_skip_dead_binding_free_variables() {
    let source =
        "let used = 1; unused = 2; in { a = let y = used + 2; dead = unused + 10; in y + 3; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "captured-nested-let-dead-binding.nix",
        source,
        cache.clone(),
    );
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let subject = {
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("a is a node thunk");
        let body = thunk.body().expect("a has a lowered nested let body");
        let node = ir.arena.node(body).expect("nested let body exists");
        assert!(
            matches!(node.data, IrData::Let { .. }),
            "fixture must exercise a nested let body"
        );
        let env = thunk.env().expect("a captures the outer let frame");
        let slots = TreeWalk::captured_free_variable_slots(&ir, body, env.frames().len())
            .expect("nested let free-variable slots collect");
        assert_eq!(
            slots.len(),
            1,
            "dead nested let bindings must not pull unrelated outer captures into the demand key"
        );
        evaluator
            .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
            .expect("nested let body subject builds")
    };
    assert_eq!(
        subject.free_var_value_hashes.len(),
        1,
        "nested let subject should include only the used outer capture"
    );

    let forced = evaluator
        .force_admitted_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("nested let body force succeeds");

    assert_eq!(forced.as_int(), Ok(6));
}

