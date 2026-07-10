//! Tree-walk evaluator tests: analysis annotation soundness.

use proptest::prelude::*;

use super::*;

#[derive(Debug, PartialEq, Eq)]
struct JsonObservation {
    bytes: Vec<u8>,
    trace_output: Vec<EvalTraceOutput>,
    warning_output: Vec<EvalWarningOutput>,
}

fn nix_int(value: i64) -> String {
    if value < 0 {
        format!("({value})")
    } else {
        value.to_string()
    }
}

fn nix_int_list(values: &[i64]) -> String {
    let elements = values
        .iter()
        .map(|value| nix_int(*value))
        .collect::<Vec<_>>()
        .join(" ");
    format!("[ {elements} ]")
}

fn fact_delta_count(left: &crate::compile::Ir, right: &crate::compile::Ir) -> usize {
    left.facts
        .as_slice()
        .iter()
        .zip(right.facts.as_slice())
        .filter(|(left, right)| left != right)
        .count()
}

fn eval_json_observation(ir: &crate::compile::Ir) -> JsonObservation {
    let outcome = eval_whnf_owned(ir).expect("JSON expression evaluates");
    let string = outcome
        .heap()
        .get_string(outcome.value())
        .expect("builtins.toJSON returns a string");
    JsonObservation {
        bytes: string.bytes().to_vec(),
        trace_output: outcome.trace_output().to_vec(),
        warning_output: outcome.warning_output().to_vec(),
    }
}

fn assert_annotated_json_matches_conservative(source: &str) {
    let json_source = format!("builtins.toJSON ({source})");
    let conservative_ir = lower(&json_source);
    let mut annotated_ir = lower(&json_source);
    crate::compile::annotate_ir(&mut annotated_ir).expect("analysis succeeds");
    assert_ne!(
        fact_delta_count(&conservative_ir, &annotated_ir),
        0,
        "{source}"
    );

    let conservative = eval_json_observation(&conservative_ir);
    let annotated = eval_json_observation(&annotated_ir);

    assert_eq!(annotated.bytes, conservative.bytes, "{source}");
    assert_eq!(
        annotated.trace_output, conservative.trace_output,
        "{source}"
    );
    assert_eq!(
        annotated.warning_output, conservative.warning_output,
        "{source}"
    );
}

fn json_parity_source_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        (-100_i64..=100).prop_map(|value| nix_int(value)),
        (-100_i64..=100).prop_map(|value| format!("let x = {}; in x", nix_int(value))),
        (-100_i64..=100, -100_i64..=100).prop_map(|(left, right)| {
            format!("builtins.sub {} {}", nix_int(left), nix_int(right))
        }),
        (-20_i64..=20, -20_i64..=20).prop_map(|(left, right)| {
            format!("builtins.mul {} {}", nix_int(left), nix_int(right))
        }),
        (-100_i64..=100, 1_i64..=20).prop_map(|(left, right)| {
            format!("builtins.div {} {}", nix_int(left), nix_int(right))
        }),
        prop::collection::vec(-20_i64..=20, 0..6)
            .prop_map(|values| { format!("builtins.length {}", nix_int_list(&values)) }),
        prop::collection::vec(-20_i64..=20, 0..6)
            .prop_map(|values| { format!("builtins.any (x: x == 3) {}", nix_int_list(&values)) }),
        prop::collection::vec(-20_i64..=20, 0..6)
            .prop_map(|values| { format!("builtins.all (x: x < 0) {}", nix_int_list(&values)) }),
        // Apply through a let-bound lambda (slot chase + parameter summary).
        (-100_i64..=100).prop_map(|value| {
            format!("let f = x: x + 1; in f {}", nix_int(value))
        }),
        // Apply through a select-resolved lambda on a static attrset literal.
        (-100_i64..=100).prop_map(|value| {
            format!("let lib = {{ inc = x: x + 1; }}; in lib.inc {}", nix_int(value))
        }),
        // Identity result spine: the argument is forced by the caller.
        (-100_i64..=100).prop_map(|value| format!("(x: x) {}", nix_int(value))),
        // Recursive let forward references (intra-frame demand fixpoint).
        (-100_i64..=100).prop_map(|value| {
            format!("let a = b + 1; b = {}; in a", nix_int(value))
        }),
        // Branch meet: demanded in both branches of a total condition.
        ((-100_i64..=100), proptest::bool::ANY).prop_map(|(value, flag)| {
            format!(
                "(x: if {flag} then x + 1 else x - 1) {}",
                nix_int(value)
            )
        }),
        // tryEval barrier (S4): no demand through the catch.
        (-100_i64..=100).prop_map(|value| {
            format!(
                "(x: (builtins.tryEval x).success) (if {} < -200 then throw \"t\" else 1)",
                nix_int(value)
            )
        }),
        // Effect-rank cap: a trace between body start and the forced use.
        (-100_i64..=100).prop_map(|value| {
            format!("(x: builtins.trace \"m\" (x + 1)) {}", nix_int(value))
        }),
        // Derivation-boundary seeding: total binding values assemble
        // eagerly, `name` is first-forced, everything else stays lazy.
        (prop::collection::vec(-20_i64..=20, 0..5), -100_i64..=100).prop_map(
            |(deps, value)| {
                format!(
                    "(builtins.derivationStrict {{ name = \"d\" + \"x\"; \
                     builder = \"b\"; system = \"s\"; \
                     deps = {}; value = {}; }}).drvPath",
                    nix_int_list(&deps),
                    nix_int(value),
                )
            }
        ),
    ]
}

#[test]
fn analysis_annotations_preserve_lazy_json_observables() {
    for source in [
        "builtins.length [ (1 / 0) ]",
        r#"builtins.hasAttr "a" { a = 1 / 0; }"#,
        "builtins.any (x: true) [ (1 / 0) ]",
        "builtins.all (x: false) [ (1 / 0) ]",
        "({ x ? 1 / 0 }: 7) {}",
        "(x: 7) (1 / 0)",
        "let x = 1 / 0; in 7",
    ] {
        assert_annotated_json_matches_conservative(source);
    }
}

#[test]
fn analysis_annotations_preserve_trace_and_warning_outputs() {
    for source in [
        r#"builtins.trace "visible" 7"#,
        r#"builtins.warn "visible" 7"#,
    ] {
        assert_annotated_json_matches_conservative(source);
    }
}

#[test]
fn analysis_annotations_drive_tree_walk_thunk_elision() {
    let source = "(x: x + 1) (1 + 2)";
    let conservative_ir = lower(source);
    let mut annotated_ir = lower(source);
    crate::compile::annotate_ir(&mut annotated_ir).expect("analysis succeeds");
    assert_ne!(
        fact_delta_count(&conservative_ir, &annotated_ir),
        0,
        "{source}"
    );

    let conservative = eval_whnf_owned(&conservative_ir).expect("conservative evaluates");
    let annotated = eval_whnf_owned(&annotated_ir).expect("annotated evaluates");

    assert_eq!(conservative.value().as_int(), Ok(4), "{source}");
    assert_eq!(annotated.value().as_int(), Ok(4), "{source}");
    assert_eq!(
        annotated.trace_output(),
        conservative.trace_output(),
        "{source}"
    );
    assert_eq!(
        annotated.warning_output(),
        conservative.warning_output(),
        "{source}"
    );
    assert_eq!(conservative.stats().thunks_elided(), 0, "{source}");
    assert_eq!(annotated.stats().thunks_elided(), 1, "{source}");
    assert_eq!(conservative.stats().thunks_allocated(), 1, "{source}");
    assert_eq!(annotated.stats().thunks_allocated(), 0, "{source}");
}

#[test]
fn analysis_annotations_drive_tree_walk_dead_binding_elision() {
    let source = r#"let used = 7; dead = builtins.trace "hidden" (1 + 2); in used"#;
    let conservative_ir = lower(source);
    let mut annotated_ir = lower(source);
    crate::compile::annotate_ir(&mut annotated_ir).expect("analysis succeeds");
    assert_ne!(
        fact_delta_count(&conservative_ir, &annotated_ir),
        0,
        "{source}"
    );

    let conservative = eval_whnf_owned(&conservative_ir).expect("conservative evaluates");
    let annotated = eval_whnf_owned(&annotated_ir).expect("annotated evaluates");

    assert_eq!(conservative.value().as_int(), Ok(7), "{source}");
    assert_eq!(annotated.value().as_int(), Ok(7), "{source}");
    assert_eq!(
        annotated.trace_output(),
        conservative.trace_output(),
        "{source}"
    );
    assert_eq!(
        annotated.warning_output(),
        conservative.warning_output(),
        "{source}"
    );
    assert_eq!(conservative.stats().thunks_elided(), 0, "{source}");
    assert_eq!(annotated.stats().thunks_elided(), 1, "{source}");
    assert_eq!(conservative.stats().thunks_allocated(), 1, "{source}");
    assert_eq!(annotated.stats().thunks_allocated(), 0, "{source}");
}

#[test]
fn analysis_annotations_elide_dead_transitive_binding_values() {
    let source = r#"let used = 7; dead = builtins.trace "hidden" (1 + 2); alias = dead; in used"#;
    let conservative_ir = lower(source);
    let mut annotated_ir = lower(source);
    crate::compile::annotate_ir(&mut annotated_ir).expect("analysis succeeds");
    assert_ne!(
        fact_delta_count(&conservative_ir, &annotated_ir),
        0,
        "{source}"
    );

    let conservative = eval_whnf_owned(&conservative_ir).expect("conservative evaluates");
    let annotated = eval_whnf_owned(&annotated_ir).expect("annotated evaluates");

    assert_eq!(conservative.value().as_int(), Ok(7), "{source}");
    assert_eq!(annotated.value().as_int(), Ok(7), "{source}");
    assert_eq!(
        annotated.trace_output(),
        conservative.trace_output(),
        "{source}"
    );
    assert_eq!(
        annotated.warning_output(),
        conservative.warning_output(),
        "{source}"
    );
    assert_eq!(conservative.stats().thunks_elided(), 0, "{source}");
    assert_eq!(annotated.stats().thunks_elided(), 2, "{source}");
    assert_eq!(conservative.stats().thunks_allocated(), 2, "{source}");
    assert_eq!(annotated.stats().thunks_allocated(), 0, "{source}");
}

#[test]
fn analysis_annotations_preserve_live_alias_while_eliding_dead_sibling_alias() {
    let source = r#"let x = builtins.trace "visible" (1 + 2); live = x; dead = x; in live + 1"#;
    let conservative_ir = lower(source);
    let mut annotated_ir = lower(source);
    crate::compile::annotate_ir(&mut annotated_ir).expect("analysis succeeds");
    assert_ne!(
        fact_delta_count(&conservative_ir, &annotated_ir),
        0,
        "{source}"
    );

    let conservative = eval_whnf_owned(&conservative_ir).expect("conservative evaluates");
    let annotated = eval_whnf_owned(&annotated_ir).expect("annotated evaluates");

    assert_eq!(conservative.value().as_int(), Ok(4), "{source}");
    assert_eq!(annotated.value().as_int(), Ok(4), "{source}");
    assert_eq!(
        annotated.trace_output(),
        conservative.trace_output(),
        "{source}"
    );
    assert_eq!(
        annotated.warning_output(),
        conservative.warning_output(),
        "{source}"
    );
    assert_eq!(conservative.stats().thunks_elided(), 0, "{source}");
    assert_eq!(annotated.stats().thunks_elided(), 1, "{source}");
    assert_eq!(
        annotated.stats().thunks_allocated() + 1,
        conservative.stats().thunks_allocated(),
        "{source}"
    );
}

/// One observation of a possibly-failing evaluation: the rendered value or the
/// error display, plus emitted trace and warning output.
#[derive(Debug, PartialEq, Eq)]
struct FallibleObservation {
    result: Result<Vec<u8>, String>,
    trace_output: Vec<EvalTraceOutput>,
    warning_output: Vec<EvalWarningOutput>,
}

fn eval_fallible_observation(ir: &crate::compile::Ir) -> FallibleObservation {
    let mut evaluator = TreeWalk::with_options(ir, TreeWalkOptions::default());
    let result = match evaluator.eval_root() {
        Ok(value) => {
            let string = evaluator
                .heap
                .get_string(value)
                .expect("builtins.toJSON returns a string");
            Ok(string.bytes().to_vec())
        }
        Err(error) => Err(error.to_string()),
    };
    FallibleObservation {
        result,
        trace_output: evaluator.trace_output.clone(),
        warning_output: evaluator.warning_output.clone(),
    }
}

fn assert_annotated_fallible_observation_matches_conservative(source: &str) {
    let json_source = format!("builtins.toJSON ({source})");
    let conservative_ir = lower(&json_source);
    let mut annotated_ir = lower(&json_source);
    crate::compile::annotate_ir(&mut annotated_ir).expect("analysis succeeds");

    let conservative = eval_fallible_observation(&conservative_ir);
    let annotated = eval_fallible_observation(&annotated_ir);

    assert_eq!(annotated.result, conservative.result, "{source}");
    assert_eq!(
        annotated.trace_output, conservative.trace_output,
        "{source}"
    );
    assert_eq!(
        annotated.warning_output, conservative.warning_output,
        "{source}"
    );
}

#[test]
fn analysis_annotations_preserve_try_eval_catch_for_thrown_arguments() {
    for source in [
        r#"(x: builtins.tryEval x) (builtins.throw "boom")"#,
        r#"(x: (builtins.tryEval x).success) (builtins.throw "boom")"#,
        r#"(x: builtins.tryEval (x + 1)) (builtins.throw "boom")"#,
        r#"builtins.tryEval ((x: x + 1) (builtins.throw "boom"))"#,
    ] {
        assert_annotated_fallible_observation_matches_conservative(source);
    }
}

#[test]
fn analysis_annotations_preserve_trace_before_forced_argument_trap() {
    for source in [
        r#"(x: builtins.trace "m" x) (builtins.throw "e")"#,
        r#"(x: builtins.trace "m" (x + 1)) (builtins.throw "e")"#,
        r#"(x: builtins.seq (builtins.trace "m" 1) x) (builtins.throw "e")"#,
    ] {
        assert_annotated_fallible_observation_matches_conservative(source);
    }
}

#[test]
fn analysis_annotations_preserve_two_throwing_strict_binding_order() {
    for source in [
        r#"(a: b: a + b) (builtins.throw "first") (builtins.throw "second")"#,
        r#"(a: b: b + a) (builtins.throw "first") (builtins.throw "second")"#,
        r#"(a: (b: a + b) (builtins.throw "second")) (builtins.throw "first")"#,
    ] {
        assert_annotated_fallible_observation_matches_conservative(source);
    }
}

#[test]
fn analysis_annotations_preserve_rec_let_forward_references() {
    for source in [
        "let a = b + 1; b = 2; in a",
        "let a = b + 1; b = a; in 7",
        "rec { a = b + 1; b = 2; }.a",
        r#"let a = b + 1; b = builtins.throw "cycle"; in builtins.tryEval a"#,
    ] {
        assert_annotated_fallible_observation_matches_conservative(source);
    }
}

/// Randomized per-builtin value-parity sources for the enabled per-argument
/// escape signatures (R-9): each shape routes a once-used `let` binding into
/// a consumed argument position of one enabled builtin, so the annotated run
/// exercises the frame-local single-entry proof that signature licenses.
fn consumed_signature_source_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        (-100_i64..=100).prop_map(|n| format!("let x = {} + 1; in builtins.isInt x", nix_int(n))),
        prop::collection::vec(-20_i64..=20, 0..6)
            .prop_map(|v| format!("let x = {}; in builtins.length x", nix_int_list(&v))),
        ("[a-z]{0,12}").prop_map(|s| {
            format!(r#"let x = "v" + "{s}"; in builtins.stringLength x"#)
        }),
        (-100_i64..=100, -100_i64..=100).prop_map(|(a, b)| {
            format!("let x = {} + 0; in builtins.sub x {}", nix_int(a), nix_int(b))
        }),
        (-20_i64..=20, -20_i64..=20).prop_map(|(a, b)| {
            format!("let x = {} + 0; in builtins.mul {} x", nix_int(a), nix_int(b))
        }),
        (-100_i64..=100, 1_i64..=20).prop_map(|(a, b)| {
            format!("let x = {} + 0; in builtins.div x {}", nix_int(a), nix_int(b))
        }),
        (0_i64..=255, 0_i64..=255).prop_map(|(a, b)| {
            format!("let x = {} + 0; in builtins.bitAnd x {}", nix_int(a), nix_int(b))
        }),
        (0_i64..=255, 0_i64..=255).prop_map(|(a, b)| {
            format!("let x = {} + 0; in builtins.bitXor {} x", nix_int(a), nix_int(b))
        }),
        (-100_i64..=100, -100_i64..=100).prop_map(|(a, b)| {
            format!("let x = {} + 0; in builtins.lessThan x {}", nix_int(a), nix_int(b))
        }),
        ("[0-9]{1,3}", "[0-9]{1,3}").prop_map(|(a, b)| {
            format!(r#"let x = "1." + "{a}"; in builtins.compareVersions x "1.{b}""#)
        }),
        prop::collection::vec(-20_i64..=20, 0..6).prop_map(|v| {
            format!("let x = {}; in builtins.any (e: e == 3) x", nix_int_list(&v))
        }),
        prop::collection::vec(-20_i64..=20, 0..6).prop_map(|v| {
            format!("let x = {}; in builtins.all (e: e < 0) x", nix_int_list(&v))
        }),
        (-20_i64..=20, prop::collection::vec(-20_i64..=20, 0..6)).prop_map(|(n, v)| {
            format!(
                "let x = {} + 0; in builtins.elem x {}",
                nix_int(n),
                nix_int_list(&v)
            )
        }),
        (-20_i64..=20).prop_map(|n| {
            format!(
                "let x = {{ a = {}; }}; in builtins.hasAttr \"a\" x",
                nix_int(n)
            )
        }),
        // Consumed-position ceil/floor over a float-typed binding.
        (-100_i64..=100).prop_map(|n| {
            format!("let x = 0.5 + {}; in builtins.ceil x", nix_int(n))
        }),
        (-100_i64..=100).prop_map(|n| {
            format!("let x = 0.5 + {}; in builtins.floor x", nix_int(n))
        }),
    ]
}

proptest! {
    #[test]
    fn analysis_annotations_preserve_generated_json_observables(
        source in json_parity_source_strategy(),
    ) {
        assert_annotated_json_matches_conservative(&source);
    }

    #[test]
    fn consumed_escape_signatures_preserve_json_observables(
        source in consumed_signature_source_strategy(),
    ) {
        assert_annotated_json_matches_conservative(&source);
    }
}

#[test]
fn analysis_annotations_preserve_single_entry_recomputation_traps() {
    // Single-entry thunks re-evaluate their body on every force. Each shape
    // below manufactures a once-per-frame binding whose handle could leak to
    // a position that forces it more than once; a wrong frame-local proof
    // would double the trace output (or double-throw).
    for source in [
        // The frame result is cached by an enclosing update thunk whose
        // cached value is the inner thunk handle; two container reads force
        // that handle twice.
        r#"let outer = [ (let x = builtins.trace "t" 1; in x) ];
           in (builtins.elemAt outer 0) + (builtins.elemAt outer 0)"#,
        // Same trap through an attrset member instead of a list element.
        r#"let outer = { m = (let x = builtins.trace "t" 1; in x); };
           in outer.m + outer.m"#,
        // The inner thunk escapes through a directly applied lambda result.
        r#"let outer = [ ((x: x) (let y = builtins.trace "t" 2; in y)) ];
           in (builtins.elemAt outer 0) + (builtins.elemAt outer 0)"#,
        // A consumed-position use inside a shared closure entered twice.
        r#"let x = builtins.trace "t" [ 1 2 ];
           f = z: builtins.length x + z;
           in f 1 + f 2"#,
    ] {
        assert_annotated_fallible_observation_matches_conservative(source);
    }
}

#[test]
fn single_entry_storage_preserves_observables_and_is_exercised() {
    // A consumed-position once-used binding takes single-entry storage in
    // the annotated run; per-call frames re-allocate it, so the trace count
    // must match the conservative update-thunk schedule exactly.
    let source = r#"let f = z: (let x = builtins.trace "t" [ 1 2 ];
                                 in builtins.length x + z);
                    in f 1 + f 2"#;
    let json_source = format!("builtins.toJSON ({source})");
    let conservative_ir = lower(&json_source);
    let mut annotated_ir = lower(&json_source);
    crate::compile::annotate_ir(&mut annotated_ir).expect("analysis succeeds");

    let mut conservative_eval = TreeWalk::with_options(&conservative_ir, TreeWalkOptions::default());
    let conservative_value = conservative_eval.eval_root().expect("conservative evaluates");
    let mut annotated_eval = TreeWalk::with_options(&annotated_ir, TreeWalkOptions::default());
    let annotated_value = annotated_eval.eval_root().expect("annotated evaluates");

    let conservative_json = conservative_eval
        .heap
        .get_string(conservative_value)
        .expect("toJSON returns a string")
        .bytes()
        .to_vec();
    let annotated_json = annotated_eval
        .heap
        .get_string(annotated_value)
        .expect("toJSON returns a string")
        .bytes()
        .to_vec();
    assert_eq!(annotated_json, conservative_json);
    assert_eq!(
        annotated_eval.trace_output, conservative_eval.trace_output,
        "single-entry storage must not change trace multiplicity"
    );

    assert_eq!(conservative_eval.stats().single_entry_thunks_allocated(), 0);
    assert_eq!(
        annotated_eval.stats().single_entry_thunks_allocated(),
        2,
        "one single-entry allocation per call frame"
    );
    assert_eq!(
        annotated_eval.stats().single_entry_thunks_forced(),
        2,
        "each single-entry thunk forced exactly once"
    );
}

#[test]
fn analysis_annotations_preserve_unforced_identity_call_results() {
    // An identity-shaped callee returns its argument unforced; the argument
    // may only be treated as demanded when the call's own value is forced.
    for source in [
        r#"builtins.length (builtins.map (y: (x: x) (builtins.throw "a")) [1])"#,
        r#"builtins.length [ ((x: x) (builtins.throw "a")) ]"#,
    ] {
        assert_annotated_fallible_observation_matches_conservative(source);
    }
}

#[test]
fn capture_plans_match_runtime_slot_reads() {
    // FV-5 validation: every captured-prefix slot read performed while a
    // planned thunk body runs must be inside the site's flat capture plan.
    let mut total_reads_checked = 0;
    for source in [
        "let a = 1 + 1; b = a + 2; in b + a",
        "(x: y: x + y) 3 4",
        "let f = x: x + 1; in f (f 2)",
        "let a = 1 + 1; in (x: a + x) 5",
        "rec { m = n + 1; n = 2; }.m",
        "let a = 1 + 1; in let b = a + 1; in (x: a + b + x) 1",
        "({ x ? 1, y ? x }: x + y) {}",
        "builtins.length (builtins.map (e: e + 1) [ 1 2 3 ])",
        "let xs = [ 1 2 3 ]; in builtins.foldl' (acc: e: acc + e) 0 xs",
        r#"let s = "a" + "b"; t = s + "c"; in builtins.stringLength t"#,
    ] {
        let mut ir = lower(source);
        crate::compile::annotate_ir(&mut ir).expect("analysis succeeds");
        let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::default());
        evaluator.enable_capture_plan_validation();
        evaluator.eval_root().expect("source evaluates");
        assert!(
            evaluator.capture_plan_violations().is_empty(),
            "{source}: {:?}",
            evaluator.capture_plan_violations()
        );
        total_reads_checked += evaluator.capture_plan_reads_checked();
    }
    assert!(
        total_reads_checked > 0,
        "the validation harness must observe captured-prefix reads"
    );
}

#[test]
fn flat_capture_plans_replace_outer_frames_after_publication() {
    let mut ir = lower("let a = 1 + 1; in x: a + x");
    crate::compile::annotate_ir(&mut ir).expect("analysis succeeds");
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::default());
    let value = evaluator.eval_root().expect("lambda evaluates");
    let lambda = evaluator
        .heap()
        .get_lambda(value)
        .expect("root is a heap-owned lambda");
    let env = lambda.env();

    assert!(env.frames().is_empty(), "flat sites retain no outer frames");
    let flat = env.flat_base().expect("lambda consumes its flat plan");
    assert!(
        flat.inline_owner().raw_eq(value),
        "the closure value must own its inlined capture tail"
    );
    let values = evaluator
        .flat_capture_values(flat)
        .expect("flat capture values resolve");
    assert_eq!(flat.frame_count(), 1);
    assert_eq!(values.len(), 1);
    assert_eq!(values[0].tag(), ValueTag::Thunk);
    let campaign = evaluator.stats_snapshot().campaign();
    assert!(campaign.flat_env_captures > 0);
    assert!(campaign.flat_env_capture_values > 0);
}

#[test]
fn recursive_assembly_flattens_only_after_publication() {
    let mut ir = lower("rec { a = 1; b = a; }");
    crate::compile::annotate_ir(&mut ir).expect("analysis succeeds");
    let b = symbol_for(&ir, b"b");
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::default());
    let value = evaluator.eval_root().expect("recursive attrset evaluates");
    let attrs = evaluator
        .heap()
        .get_attrs(value)
        .expect("root is a heap-owned attrset");
    let b_value = attrs.get(b).expect("b exists");
    let thunk = evaluator
        .heap()
        .get_thunk(b_value)
        .expect("b remains a suspended thunk");
    let env = thunk.env().expect("node thunk has a lexical environment");

    assert!(
        env.frames().is_empty(),
        "published recursive closures must release their assembly frame"
    );
    let flat = env
        .flat_base()
        .expect("published recursive closure consumes its flat plan");
    assert!(
        flat.inline_owner().raw_eq(b_value),
        "publication must point the environment at its owning closure"
    );
    let values = evaluator
        .flat_capture_values(flat)
        .expect("flat capture values resolve");
    assert_eq!(flat.frame_count(), 1);
    assert_eq!(values.len(), 1);
}

#[test]
fn capture_plan_validation_detects_understated_plans() {
    // Harness self-check: corrupt one thunk site's plan to claim an empty
    // free-variable set; the body's real captured-prefix read must surface
    // as a violation.
    let source = "let a = 1 + 1; b = a + 2; in b";
    let mut ir = lower(source);
    crate::compile::annotate_ir(&mut ir).expect("analysis succeeds");
    let mut corrupted = 0;
    for index in 0..ir.arena.nodes().len() as u32 {
        let id = crate::compile::IrId::new(index);
        let node = ir.arena.node(id).expect("node exists");
        if node.kind != crate::compile::IrKind::ThunkAlloc {
            continue;
        }
        if let Some(crate::compile::CapturePlan::Flat(slots)) = ir.facts.capture_plan(id)
            && !slots.is_empty()
        {
            ir.facts.set_capture_plan(
                id,
                Some(crate::compile::CapturePlan::Flat(Box::new([]))),
            );
            corrupted += 1;
        }
    }
    assert!(corrupted > 0, "corpus must contain a capturing thunk site");
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::default());
    evaluator.enable_capture_plan_validation();
    evaluator.eval_root().expect("source evaluates");
    assert!(
        !evaluator.capture_plan_violations().is_empty(),
        "an understated plan must be detected"
    );
}

/// Measurement probe: aggregates the FV-5 free-variable histogram over every
/// `.nix` file below `AOS_NIX_CAPTURE_HISTOGRAM_DIR` (recursively) and prints
/// the distribution. Ignored by default; run explicitly:
///
/// ```text
/// AOS_NIX_CAPTURE_HISTOGRAM_DIR=/path/to/repo cargo test -p ratchet-oracle \
///   capture_plan_free_var_histogram -- --ignored --nocapture
/// ```
#[test]
#[ignore = "measurement probe; needs AOS_NIX_CAPTURE_HISTOGRAM_DIR"]
fn capture_plan_free_var_histogram_over_corpus() {
    use crate::compile::analysis::{
        FREE_VAR_HISTOGRAM_BUCKETS, annotate_capture_plans, annotate_cardinality,
        annotate_escape, annotate_strictness,
    };
    let Ok(root) = std::env::var("AOS_NIX_CAPTURE_HISTOGRAM_DIR") else {
        panic!("set AOS_NIX_CAPTURE_HISTOGRAM_DIR to the corpus root");
    };
    let mut histogram = [0usize; FREE_VAR_HISTOGRAM_BUCKETS];
    let mut lambda_sites = 0usize;
    let mut thunk_sites = 0usize;
    let mut flat = 0usize;
    let mut shared = 0usize;
    let mut silent = 0usize;
    let mut max_free = 0usize;
    let mut files = 0usize;
    let mut skipped = 0usize;
    let mut phase_times = [std::time::Duration::ZERO; 4];
    let mut stack = vec![std::path::PathBuf::from(root)];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|name| name == ".git") {
                    continue;
                }
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|extension| extension != "nix") {
                continue;
            }
            let Ok(source) = std::fs::read(&path) else {
                skipped += 1;
                continue;
            };
            let Ok(parsed) = parse_bytes(&source) else {
                skipped += 1;
                continue;
            };
            let Ok(resolved) = resolve_ast(parsed) else {
                skipped += 1;
                continue;
            };
            let Ok(mut ir) = aos_nix_dialect::nix_lower(resolved) else {
                skipped += 1;
                continue;
            };
            let started = std::time::Instant::now();
            if annotate_strictness(&mut ir).is_err() {
                skipped += 1;
                continue;
            }
            phase_times[0] += started.elapsed();
            let started = std::time::Instant::now();
            if annotate_cardinality(&mut ir).is_err() {
                skipped += 1;
                continue;
            }
            phase_times[1] += started.elapsed();
            let started = std::time::Instant::now();
            if annotate_escape(&mut ir).is_err() {
                skipped += 1;
                continue;
            }
            phase_times[2] += started.elapsed();
            let started = std::time::Instant::now();
            let Ok(report) = annotate_capture_plans(&mut ir) else {
                skipped += 1;
                continue;
            };
            phase_times[3] += started.elapsed();
            files += 1;
            for (bucket, count) in report.free_var_histogram.iter().enumerate() {
                histogram[bucket] += count;
            }
            lambda_sites += report.lambda_sites;
            thunk_sites += report.thunk_sites;
            flat += report.flat_plans;
            shared += report.shared_chain_plans;
            silent += report.pure_silent_thunk_bodies;
            max_free = max_free.max(report.max_free_vars);
        }
    }
    println!("files analyzed: {files} (skipped {skipped})");
    println!("lambda sites: {lambda_sites}, thunk sites: {thunk_sites}");
    println!("flat plans: {flat}, shared-chain plans: {shared}");
    println!("pure-silent thunk bodies (call-by-name candidates): {silent}");
    println!("max free vars: {max_free}");
    println!("analysis times [strict, cardinality, escape, capture]: {phase_times:?}");
    let total: usize = histogram.iter().sum();
    let mut cumulative = 0usize;
    for (size, count) in histogram.iter().enumerate() {
        cumulative += count;
        let label = if size == FREE_VAR_HISTOGRAM_BUCKETS - 1 {
            format!("{size}+")
        } else {
            size.to_string()
        };
        println!(
            "free={label:>3}: {count:>7} ({:5.1}% cum {:5.1}%)",
            100.0 * *count as f64 / total.max(1) as f64,
            100.0 * cumulative as f64 / total.max(1) as f64,
        );
    }
    assert!(files > 0, "corpus contained no analyzable .nix files");
}

/// Pins the `derivationStrict` dialect-op key the core strictness analysis
/// mirrors (`ratchet-core` cannot depend on the dialect crate). The key is
/// serialized raw into persisted `ir.bin` artifacts, so it is format-stable
/// and the mirror constant may rely on it.
#[test]
fn derivation_strict_dialect_op_is_format_stable() {
    assert_eq!(
        aos_nix_dialect::NIX_OP_DERIVATION_STRICT,
        crate::compile::IrDialectOp::new(1),
    );
}

#[test]
fn analysis_annotations_preserve_derivation_strict_error_identity_and_order() {
    for source in [
        // `name` is forced first: its error wins over every other attribute.
        r#"builtins.derivationStrict {
             name = builtins.throw "name-error";
             builder = builtins.throw "builder-error";
             system = "s";
           }"#,
        // Sorted force order between two throwing attributes: `builder`
        // precedes `system` lexicographically in both schedules.
        r#"builtins.derivationStrict {
             name = "ok";
             builder = builtins.throw "first-sorted";
             system = builtins.throw "second-sorted";
           }"#,
        // A missing `name` throws before any attribute value is forced.
        r#"builtins.derivationStrict {
             builder = builtins.throw "builder-error";
             system = "s";
           }"#,
        // Non-string name: the type error fires after the first force.
        r#"builtins.derivationStrict {
             name = 1 + 2;
             builder = builtins.throw "builder-error";
             system = "s";
           }"#,
    ] {
        assert_annotated_fallible_observation_matches_conservative(source);
    }
}

#[test]
fn analysis_annotations_preserve_derivation_strict_ignore_nulls_interplay() {
    for source in [
        // Null attributes are forced before the `__ignoreNulls` drop.
        r#"(builtins.derivationStrict {
             name = "d";
             builder = "b";
             system = "s";
             __ignoreNulls = true;
             dropped = null;
             extra = [ 1 2 ];
           }).drvPath"#,
        // A throwing `__ignoreNulls` fires in its pre-loop force position.
        r#"builtins.derivationStrict {
             name = "d";
             builder = "b";
             system = "s";
             __ignoreNulls = builtins.throw "ignore-nulls";
           }"#,
    ] {
        assert_annotated_fallible_observation_matches_conservative(source);
    }
}

#[test]
fn analysis_annotations_preserve_derivation_strict_structured_attrs() {
    for source in [
        r#"(builtins.derivationStrict {
             name = "d";
             builder = "b";
             system = "s";
             __structuredAttrs = true;
             nested = { a = [ 1 ]; b = "x"; };
             outputs = [ "out" "dev" ];
           }).drvPath"#,
        r#"builtins.derivationStrict {
             name = "d";
             builder = "b";
             system = "s";
             __structuredAttrs = builtins.throw "structured";
           }"#,
    ] {
        assert_annotated_fallible_observation_matches_conservative(source);
    }
}

#[test]
fn analysis_annotations_preserve_derivation_strict_binding_sources() {
    for source in [
        // `inherit (src) attr` values route through the shared-receiver
        // select-thunk path and must stay as lazy as before.
        r#"let src = { dep = builtins.throw "inherited"; };
           in builtins.derivationStrict {
             name = "d";
             builder = "b";
             system = "s";
             inherit (src) dep;
           }"#,
        // Dynamic keys mixed with static ones decline the eager plan.
        r#"builtins.derivationStrict {
             name = "d";
             builder = "b";
             system = "s";
             ${"dy" + "namic"} = builtins.throw "dynamic-value";
           }"#,
        // Formal defaults are populated by the same order-sensitive
        // assembler and must stay lazy.
        r#"({ x ? builtins.throw "default" }: builtins.derivationStrict {
             name = "d";
             builder = "b";
             system = "s";
           }) {}"#,
        // Recursive-let forward references feeding a derivation literal.
        r#"let n = "a" + b; b = "bc";
           in (builtins.derivationStrict {
             name = n;
             builder = "b";
             system = "s";
             deps = [ 1 2 3 ];
           }).drvPath"#,
        // A rec literal argument declines seeding but must stay equivalent.
        r#"(builtins.derivationStrict (rec {
             name = "d" + "x";
             builder = "b";
             system = "s";
             alias = name;
           })).drvPath"#,
    ] {
        assert_annotated_fallible_observation_matches_conservative(source);
    }
}

#[test]
fn analysis_annotations_drive_binding_assembly_elision() {
    let source = r#"(builtins.derivationStrict {
        name = "d-" + "1";
        builder = "/bin/sh";
        system = "x86_64-linux";
        args = [ "-c" "true" ];
    }).drvPath"#;
    let conservative_ir = lower(source);
    let mut annotated_ir = lower(source);
    crate::compile::annotate_ir(&mut annotated_ir).expect("analysis succeeds");

    let conservative = eval_whnf_owned(&conservative_ir).expect("conservative evaluates");
    let annotated = eval_whnf_owned(&annotated_ir).expect("annotated evaluates");

    let conservative_path = conservative
        .heap()
        .get_string(conservative.value())
        .expect("drvPath is a string")
        .bytes()
        .to_vec();
    let annotated_path = annotated
        .heap()
        .get_string(annotated.value())
        .expect("drvPath is a string")
        .bytes()
        .to_vec();
    assert_eq!(annotated_path, conservative_path);

    // The non-total first-forced `name` and the total `args` list evaluate
    // directly into their slots; the conservative plan allocates instead.
    assert_eq!(conservative.stats().binding_assembly_elisions(), 0);
    assert!(
        annotated.stats().binding_assembly_elisions() >= 2,
        "expected at least two assembly elisions, got {}",
        annotated.stats().binding_assembly_elisions(),
    );
    assert!(
        annotated.stats().thunks_allocated() < conservative.stats().thunks_allocated(),
        "eager assembly must allocate fewer thunks ({} vs {})",
        annotated.stats().thunks_allocated(),
        conservative.stats().thunks_allocated(),
    );
}
