//! Tree-walk evaluator tests: trace.

use super::*;

#[test]
fn static_builtin_selects_are_first_class_functions() {
    let length = lower("builtins.length");
    assert_eq!(
        length.arena.node(length.root).expect("root exists").kind,
        IrKind::BuiltinAttr
    );
    assert_eq!(eval("builtins.length [ 1 2 ]").as_int(), Ok(2));
    assert_eq!(eval("builtins.true").as_bool(), Ok(true));
    assert_eq!(eval("builtins.false").as_bool(), Ok(false));
    assert_eq!(eval("builtins.null").as_null(), Ok(()));
    assert_eq!(eval("builtins.break 7").as_int(), Ok(7));
    assert_eq!(eval("let f = builtins.break; in f 9").as_int(), Ok(9));
    assert_eq!(eval_string_bytes("builtins.storeDir"), b"/nix/store");
    assert_eq!(
        eval_string_bytes_with_options(
            "builtins.storeDir",
            TreeWalkOptions::with_store_dir(b"/tmp/aos-store".to_vec())
                .expect("store dir is valid")
        ),
        b"/tmp/aos-store"
    );
    assert_eq!(
        eval_string_bytes("builtins.typeOf builtins.storeDir"),
        b"string"
    );
    assert_eq!(eval_string_bytes("builtins.nixVersion"), PINNED_NIX_VERSION);
    assert_eq!(
        eval_string_bytes("builtins.typeOf builtins.nixVersion"),
        b"string"
    );
    assert_eq!(
        eval("builtins.langVersion").as_int(),
        Ok(PINNED_NIX_LANG_VERSION)
    );
    assert_eq!(
        eval_string_bytes("builtins.typeOf builtins.langVersion"),
        b"int"
    );
    assert!(matches!(
        eval_whnf(&lower("builtins.nixVersion null"))
            .expect_err("nixVersion is a value, not a function")
            .kind(),
        TreeWalkErrorKind::Type {
            expected: "lambda",
            actual: ValueTag::String,
            ..
        }
    ));
    assert!(matches!(
        eval_whnf(&lower("builtins.langVersion null"))
            .expect_err("langVersion is a value, not a function")
            .kind(),
        TreeWalkErrorKind::Type {
            expected: "lambda",
            actual: ValueTag::Int,
            ..
        }
    ));
    assert_eq!(
        eval_string_bytes_with_options(
            "builtins.currentSystem",
            TreeWalkOptions::with_current_system(b"aarch64-linux".to_vec())
                .expect("currentSystem is valid")
        ),
        b"aarch64-linux"
    );
    assert_eq!(
        eval_string_bytes_with_options(
            "builtins.typeOf builtins.currentSystem",
            TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())
                .expect("currentSystem is valid")
        ),
        b"string"
    );
    assert_eq!(
        eval_with_options(
            "builtins.currentTime",
            TreeWalkOptions::with_current_time(1_700_000_000).expect("currentTime is valid")
        )
        .as_int(),
        Ok(1_700_000_000)
    );
    assert_eq!(
        eval_string_bytes_with_options(
            "builtins.typeOf builtins.currentTime",
            TreeWalkOptions::with_current_time(1_700_000_000).expect("currentTime is valid")
        ),
        b"int"
    );
    assert_eq!(
        eval_with_options(
            "builtins.currentTime == builtins.currentTime",
            TreeWalkOptions::with_current_time(1_700_000_000).expect("currentTime is valid")
        )
        .as_bool(),
        Ok(true)
    );
    assert_eq!(eval("builtins ? length").as_bool(), Ok(true));
    assert_eq!(eval("builtins ? break").as_bool(), Ok(true));
    assert_eq!(eval("builtins ? getEnv").as_bool(), Ok(true));
    assert_eq!(eval("builtins ? throw").as_bool(), Ok(true));
    assert_eq!(eval("builtins ? abort").as_bool(), Ok(true));
    assert_eq!(eval("builtins ? tryEval").as_bool(), Ok(true));
    assert_eq!(eval("builtins ? placeholder").as_bool(), Ok(true));
    assert_eq!(eval("builtins ? nixVersion").as_bool(), Ok(true));
    assert_eq!(eval("builtins ? langVersion").as_bool(), Ok(true));
    assert_eq!(eval("builtins ? currentSystem").as_bool(), Ok(false));
    assert_eq!(
        eval_with_options(
            "builtins ? currentSystem",
            TreeWalkOptions::with_current_system(b"aarch64-linux".to_vec())
                .expect("currentSystem is valid")
        )
        .as_bool(),
        Ok(true)
    );
    assert_eq!(eval("builtins ? currentTime").as_bool(), Ok(false));
    assert_eq!(
        eval_with_options(
            "builtins ? currentTime",
            TreeWalkOptions::with_current_time(1_700_000_000).expect("currentTime is valid")
        )
        .as_bool(),
        Ok(true)
    );
    assert_eq!(eval("builtins ? storeDir").as_bool(), Ok(true));
    assert_eq!(eval("builtins ? __missing").as_bool(), Ok(false));
    assert_eq!(eval("builtins ? length.foo").as_bool(), Ok(false));
    assert_eq!(
        eval("builtins.isFunction builtins.length").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.isFunction builtins.head").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.isFunction builtins.tail").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.isFunction builtins.concatLists").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval_string_bytes("builtins.typeOf builtins.length"),
        b"lambda"
    );
    assert_eq!(
        eval("builtins.functionArgs builtins.length == {}").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let f = builtins.length; in f [ 1 2 3 ]").as_int(),
        Ok(3)
    );
    assert_eq!(
        eval("builtins.isFunction builtins.elemAt").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.isFunction builtins.elem").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let f = builtins.isFunction; in f builtins.convertHash").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.isFunction builtins.throw").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.isFunction builtins.abort").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.isFunction builtins.tryEval").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.isFunction builtins.placeholder").as_bool(),
        Ok(true)
    );
    assert_eq!(eval("builtins.isFunction builtins.all").as_bool(), Ok(true));
    assert_eq!(eval("builtins.isFunction builtins.any").as_bool(), Ok(true));
    assert_eq!(
        eval("builtins.isFunction builtins.concatMap").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.isFunction builtins.filter").as_bool(),
        Ok(true)
    );
    assert_eq!(eval("builtins.isFunction builtins.map").as_bool(), Ok(true));
    assert_eq!(
        eval("builtins.isFunction builtins.genList").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.isFunction builtins.groupBy").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.isFunction builtins.partition").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.isFunction builtins.foldl'").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.isFunction builtins.substring").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.isFunction builtins.replaceStrings").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.isFunction builtins.sort").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let x = builtins.break (1 / 0); in 42").as_int(),
        Ok(42)
    );
    assert!(matches!(
        eval_whnf(&lower("builtins.length (builtins.break [ 1 2 ])"))
            .expect_err("length sees the break result as an unforced thunk")
            .kind(),
        TreeWalkErrorKind::Type {
            expected: "list",
            actual: ValueTag::Thunk,
            ..
        }
    ));
    assert!(matches!(
        eval_whnf(&lower(
            "builtins.length (let f = builtins.break; in f [ 1 2 ])"
        ))
        .expect_err("first-class break preserves the returned thunk")
        .kind(),
        TreeWalkErrorKind::Type {
            expected: "list",
            actual: ValueTag::Thunk,
            ..
        }
    ));
    assert!(matches!(
        eval_whnf(&lower("builtins.hasAttr \"x\" (builtins.break { x = 1; })"))
            .expect_err("hasAttr sees the break result as an unforced thunk")
            .kind(),
        TreeWalkErrorKind::Type {
            expected: "attrs",
            actual: ValueTag::Thunk,
            ..
        }
    ));
    assert_eq!(eval("builtins.__missing or 42").as_int(), Ok(42));
    assert_eq!(eval("builtins.__missing.foo or 42").as_int(), Ok(42));
    assert_eq!(eval("builtins.length.foo or 42").as_int(), Ok(42));
    assert_eq!(
        eval_string_bytes("builtins.storeDir or \"fallback\""),
        b"/nix/store"
    );
    assert_eq!(
        eval_string_bytes("builtins.nixVersion or \"fallback\""),
        PINNED_NIX_VERSION
    );
    assert_eq!(
        eval("builtins.langVersion or 42").as_int(),
        Ok(PINNED_NIX_LANG_VERSION)
    );
    assert_eq!(
        eval_string_bytes("builtins.currentSystem or \"fallback\""),
        b"fallback"
    );
    assert_eq!(
        eval_string_bytes_with_options(
            "builtins.currentSystem or \"fallback\"",
            TreeWalkOptions::with_current_system(b"aarch64-linux".to_vec())
                .expect("currentSystem is valid")
        ),
        b"aarch64-linux"
    );
    assert_eq!(eval("builtins.currentTime or 42").as_int(), Ok(42));
    assert_eq!(
        eval_with_options(
            "builtins.currentTime or 42",
            TreeWalkOptions::with_current_time(1_700_000_000).expect("currentTime is valid")
        )
        .as_int(),
        Ok(1_700_000_000)
    );
}

#[test]
fn builtins_global_evaluates_to_registry_backed_attrset() {
    fn expected_builtin_names(include_system: bool, include_time: bool) -> Vec<Vec<u8>> {
        let mut names = BUILTINS
            .iter()
            .filter(|builtin| {
                include_system || builtin.availability() != BuiltinAvailability::ImpureCurrentSystem
            })
            .filter(|builtin| {
                include_time || builtin.availability() != BuiltinAvailability::ImpureCurrentTime
            })
            .map(|builtin| builtin.name().to_vec())
            .collect::<Vec<_>>();
        names.sort();
        names
    }

    assert_eq!(eval("builtins ? builtins").as_bool(), Ok(true));
    assert_eq!(
        eval_string_bytes("builtins.typeOf builtins.builtins"),
        b"set"
    );
    assert_eq!(
        eval_string_bytes("let b = builtins; in builtins.typeOf b.builtins"),
        b"set"
    );
    assert_eq!(
        eval("let b = builtins; in builtins.isFunction b.genericClosure").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval_list_string_bytes("builtins.attrNames builtins"),
        expected_builtin_names(false, false)
    );
    assert_eq!(
        eval_list_string_bytes("builtins.attrNames builtins.builtins"),
        expected_builtin_names(false, false)
    );

    let mut options =
        TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec()).expect("system valid");
    options.set_current_time(1_700_000_000).expect("time valid");
    assert_eq!(
        eval_list_string_bytes_with_options("builtins.attrNames builtins", options),
        expected_builtin_names(true, true)
    );
}

#[test]
fn builtins_global_records_large_dynamic_repr_decision() {
    let ir = lower("builtins");
    let span = ir.arena.node(ir.root).expect("root node exists").span;
    let mut evaluator = TreeWalk::new(&ir);

    let value = evaluator
        .eval_builtins_attrset(ir.root, span)
        .expect("builtins attrset evaluates");

    let attrs = evaluator
        .heap
        .get_attrs(value)
        .expect("builtins value is attrs");
    assert!(attrs.len() > 64);
    let snapshot = evaluator
        .attr_telemetry
        .update_merge_snapshot()
        .expect("repr telemetry snapshot allocates");
    assert_eq!(snapshot.decisions, 1);
    assert_eq!(snapshot.flat_decisions, 0);
    assert_eq!(snapshot.hamt_decisions, 1);
    assert_eq!(snapshot.update_merges, 0);
    assert_eq!(snapshot.reasons.static_literal, 0);
    assert_eq!(snapshot.reasons.small_shape_stable, 0);
    assert_eq!(snapshot.reasons.large_dynamic_construction, 1);
}

#[test]
fn trace_primop_records_output_and_returns_second_argument() {
    let outcome = eval_owned(r#"builtins.trace "hello" 7"#);

    assert_eq!(outcome.value().as_int(), Ok(7));
    assert_eq!(outcome.trace_output().len(), 1);
    assert_trace_output(
        outcome.trace_output().first().expect("trace output exists"),
        EvalTraceKind::Trace,
        b"hello",
    );

    let outcome = eval_owned(r#"let t = builtins.trace "first-class"; in t 9"#);

    assert_eq!(outcome.value().as_int(), Ok(9));
    assert_eq!(outcome.trace_output().len(), 1);
    assert_trace_output(
        outcome.trace_output().first().expect("trace output exists"),
        EvalTraceKind::Trace,
        b"first-class",
    );
}

#[test]
fn trace_primop_forces_message_to_whnf_but_not_nested_values() {
    let outcome = eval_owned(r#"builtins.trace [ (builtins.throw "nested") ] { a = 1 / 0; }"#);

    assert_eq!(outcome.value().tag(), ValueTag::Attrs);
    assert_eq!(outcome.trace_output().len(), 1);
    assert_trace_output(
        outcome.trace_output().first().expect("trace output exists"),
        EvalTraceKind::Trace,
        "[ «thunk» ]".as_bytes(),
    );
}

#[test]
fn trace_primop_renders_unforced_literals_but_not_computed_thunks() {
    let outcome = eval_owned(r#"builtins.trace [ 1 "x" true null /tmp/foo (1 + 2) ] 1"#);

    assert_eq!(outcome.value().as_int(), Ok(1));
    assert_eq!(outcome.trace_output().len(), 1);
    assert_trace_output(
        outcome.trace_output().first().expect("trace output exists"),
        EvalTraceKind::Trace,
        r#"[ 1 "x" true null /tmp/foo «thunk» ]"#.as_bytes(),
    );

    let outcome = eval_owned(r#"builtins.trace { a = /tmp/foo; b = 1; c = 1 + 2; } 1"#);

    assert_eq!(outcome.value().as_int(), Ok(1));
    assert_eq!(outcome.trace_output().len(), 1);
    assert_trace_output(
        outcome.trace_output().first().expect("trace output exists"),
        EvalTraceKind::Trace,
        "{ a = /tmp/foo; b = 1; c = «thunk»; }".as_bytes(),
    );
}

#[test]
fn trace_primop_renders_recursive_cached_thunks_shallowly() {
    let outcome = eval_owned("let s = rec { a = s; }; in builtins.seq s.a (builtins.trace s 1)");

    assert_eq!(outcome.value().as_int(), Ok(1));
    assert_eq!(outcome.trace_output().len(), 1);
    assert_trace_output(
        outcome.trace_output().first().expect("trace output exists"),
        EvalTraceKind::Trace,
        "{ a = «repeated»; }".as_bytes(),
    );
}

#[test]
fn raw_renderer_tracks_logical_sharing_without_hash_cons_aliases() {
    let shared = lower("let empty = []; in [ empty empty ]");
    assert_eq!(
        eval_raw_bytes(&shared).expect("shared values render"),
        b"[ [ ] [ ] ]"
    );

    let shared_attrs = lower("let empty = {}; in [ empty empty ]");
    assert_eq!(
        eval_raw_bytes(&shared_attrs).expect("shared attrsets render"),
        b"[ { } { } ]"
    );

    let shared_attrs = lower("let value = { a = 1; }; in [ value value ]");
    assert_eq!(
        eval_raw_bytes(&shared_attrs).expect("shared non-empty attrsets render"),
        "[ { a = 1; } «repeated» ]".as_bytes()
    );

    let independent_attrs =
        lower(r#"[ (builtins.tryEval (throw "a")) (builtins.tryEval (throw "b")) ]"#);
    assert_eq!(
        eval_raw_bytes_with_options(
            &independent_attrs,
            TreeWalkOptions::with_parallel_workers(std::num::NonZeroUsize::new(4)),
        )
        .expect("parallel raw values preserve logical identity"),
        b"[ { success = false; value = false; } { success = false; value = false; } ]"
    );

    let recursive = lower("let xs = [ xs ]; in xs");
    assert_eq!(
        eval_raw_bytes(&recursive).expect("recursive value renders"),
        "[ [ «repeated» ] ]".as_bytes()
    );

    let nested_recursive = lower("let xs = [ [ xs ] ]; in xs");
    assert_eq!(
        eval_raw_bytes(&nested_recursive).expect("nested recursive value renders"),
        "[ [ [ «repeated» ] ] ]".as_bytes()
    );

    let sibling_recursive = lower("let xs = [ xs ]; ys = [ ys ]; in [ xs ys ]");
    assert_eq!(
        eval_raw_bytes(&sibling_recursive).expect("sibling recursive values render"),
        "[ [ [ «repeated» ] ] [ [ «repeated» ] ] ]".as_bytes()
    );

    let same_sibling_recursive = lower("let xs = [ xs xs ]; in xs");
    assert_eq!(
        eval_raw_bytes(&same_sibling_recursive).expect("same recursive sibling values render"),
        "[ [ «repeated» «repeated» ] «repeated» ]".as_bytes()
    );
}

#[test]
fn moving_gc_rewrites_raw_render_traversal_identities() {
    let options = TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint());
    for (source, expected) in [
        ("let xs = [ xs ]; in xs", "[ [ «repeated» ] ]"),
        (
            "let xs = [ xs xs ]; in xs",
            "[ [ «repeated» «repeated» ] «repeated» ]",
        ),
        (
            "let value = { a = 1; }; in [ value value ]",
            "[ { a = 1; } «repeated» ]",
        ),
    ] {
        let rendered = eval_raw_bytes_with_options(&lower(source), options.clone())
            .expect("moving-GC raw traversal renders");
        assert_eq!(rendered, expected.as_bytes());
    }
}

#[test]
fn moving_gc_unmarks_the_relocated_active_force_identity() {
    let ir = lower("builtins.break (builtins.head [ (x: x) ])");
    let options = TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint());
    let evaluator = TreeWalk::with_options(&ir, options);

    let (rendered, evaluator) = eval_raw_bytes_with_evaluator_owned(&ir, evaluator)
        .expect("moving-GC break identity renders");

    assert_eq!(rendered, b"<LAMBDA>");
    assert!(
        evaluator.lazy_identity_thunks.is_empty(),
        "the relocated active force key is removed after forcing"
    );
    assert!(evaluator.active_force_roots.is_empty());
}

#[test]
fn trace_primop_renders_whnf_values() {
    for (source, expected) in [
        (r#"builtins.trace "a\n\"b" 1"#, b"a\n\"b".as_slice()),
        ("builtins.trace 1000000.0 1", b"1e+06".as_slice()),
        (
            "builtins.trace builtins.length 1",
            "«primop length»".as_bytes(),
        ),
        ("builtins.trace (x: x) 1", "«lambda»".as_bytes()),
        ("builtins.trace { } 1", b"{ }".as_slice()),
    ] {
        let outcome = eval_owned(source);

        assert_eq!(outcome.value().as_int(), Ok(1), "{source}");
        assert_eq!(outcome.trace_output().len(), 1, "{source}");
        assert_trace_output(
            outcome.trace_output().first().expect("trace output exists"),
            EvalTraceKind::Trace,
            expected,
        );
    }
}

#[test]
fn trace_verbose_primop_respects_verbose_option() {
    let hidden = eval_owned(r#"builtins.traceVerbose (builtins.throw "hidden") 1"#);

    assert_eq!(hidden.value().as_int(), Ok(1));
    assert!(hidden.trace_output().is_empty());

    let hidden = eval_owned(r#"let t = builtins.traceVerbose (builtins.throw "hidden"); in t 1"#);

    assert_eq!(hidden.value().as_int(), Ok(1));
    assert!(hidden.trace_output().is_empty());

    let shown = eval_owned_with_options(
        r#"builtins.traceVerbose "shown" 2"#,
        TreeWalkOptions::with_trace_verbose(true),
    );

    assert_eq!(shown.value().as_int(), Ok(2));
    assert_eq!(shown.trace_output().len(), 1);
    assert_trace_output(
        shown.trace_output().first().expect("trace output exists"),
        EvalTraceKind::TraceVerbose,
        b"shown",
    );

    let error = eval_whnf_owned_with_options(
        &lower(r#"builtins.traceVerbose (builtins.throw "boom") 1"#),
        TreeWalkOptions::with_trace_verbose(true),
    )
    .expect_err("verbose trace forces its message");

    assert!(matches!(error.kind(), TreeWalkErrorKind::Thrown { .. }));
}

#[test]
fn tree_walk_preserves_trace_records_after_later_errors() {
    let ir = lower(r#"builtins.trace "before-error" (builtins.throw "boom")"#);
    let mut evaluator = TreeWalk::new(&ir);
    let error = evaluator.eval_root().expect_err("second argument throws");

    assert!(matches!(error.kind(), TreeWalkErrorKind::Thrown { .. }));
    assert_eq!(evaluator.trace_output().len(), 1);
    assert_trace_output(
        evaluator
            .trace_output()
            .first()
            .expect("trace output exists"),
        EvalTraceKind::Trace,
        b"before-error",
    );
}

#[test]
fn warn_primop_records_warning_and_returns_second_argument() {
    let outcome = eval_owned(r#"builtins.warn "hello" 7"#);

    assert_eq!(outcome.value().as_int(), Ok(7));
    assert!(outcome.trace_output().is_empty());
    assert_eq!(outcome.warning_output().len(), 1);
    assert_warning_output(
        outcome
            .warning_output()
            .first()
            .expect("warning output exists"),
        b"hello",
    );

    let outcome = eval_owned(r#"let w = builtins.warn "first-class"; in w 9"#);

    assert_eq!(outcome.value().as_int(), Ok(9));
    assert_eq!(outcome.warning_output().len(), 1);
    assert_warning_output(
        outcome
            .warning_output()
            .first()
            .expect("warning output exists"),
        b"first-class",
    );

    let outcome = eval_owned(r#"builtins.warn ("a" + "b") { a = 1 / 0; }"#);

    assert_eq!(outcome.value().tag(), ValueTag::Attrs);
    assert_eq!(outcome.warning_output().len(), 1);
    assert_warning_output(
        outcome
            .warning_output()
            .first()
            .expect("warning output exists"),
        b"ab",
    );
}

#[test]
fn warn_primop_requires_string_message() {
    for source in [
        "builtins.warn 1 7",
        "builtins.warn /tmp/foo 7",
        r#"builtins.warn { __toString = self: "hook"; } 7"#,
    ] {
        let error = eval_whnf_owned(&lower(source)).expect_err("warn requires a string");
        assert!(
            matches!(
                error.kind(),
                TreeWalkErrorKind::Type {
                    expected: "string",
                    ..
                }
            ),
            "{source}: {error:?}"
        );
    }
}

#[test]
fn warn_primop_formats_multiline_stderr_like_cpp_nix() {
    fn formatted(message: &[u8]) -> Vec<u8> {
        TreeWalk::warning_stderr_bytes(IrId::new(0), Span::new(0, 0), message)
            .expect("warning output formats")
    }

    assert_eq!(formatted(b"hello"), b"evaluation warning: hello\n");
    assert_eq!(
        formatted(b"a\nb"),
        b"evaluation warning: a\n                    b\n"
    );
    assert_eq!(
        formatted(b"a\n\nb"),
        b"evaluation warning: a\n\n                    b\n"
    );
    assert_eq!(formatted(b"a\n"), b"evaluation warning: a\n");
    assert_eq!(formatted(b""), b"\n");
    assert_eq!(formatted(b"\n"), b"\n");
    assert_eq!(
        formatted(b"\nb"),
        b"evaluation warning:\n                    b\n"
    );
}

#[test]
fn warn_primop_abort_on_warn_emits_warning_then_errors() {
    let ir = lower(r#"builtins.warn "strict" 7"#);
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::with_abort_on_warn(true));
    let error = evaluator
        .eval_root()
        .expect_err("abort-on-warn fails after emitting warning");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::WarningAborted { .. }
    ));
    assert_eq!(evaluator.warning_output().len(), 1);
    assert_warning_output(
        evaluator
            .warning_output()
            .first()
            .expect("warning output exists"),
        b"strict",
    );

    let ir = lower(r#"builtins.tryEval (builtins.warn "strict" 7)"#);
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::with_abort_on_warn(true));
    let error = evaluator
        .eval_root()
        .expect_err("tryEval does not catch abort-on-warn");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::WarningAborted { .. }
    ));
    assert_eq!(evaluator.warning_output().len(), 1);
    assert_warning_output(
        evaluator
            .warning_output()
            .first()
            .expect("warning output exists"),
        b"strict",
    );
}

#[test]
#[ignore = "requires the pinned C++ Nix 2.24.12 nix-instantiate oracle"]
fn cpp_nix_trace_and_warn_stderr_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_trace_and_warn_stderr_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_trace_and_warn_stderr_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix trace/warn check");
        return;
    };
    assert_cpp_nix_trace_and_warn_stderr_match_tree_walk(&oracle);
}
