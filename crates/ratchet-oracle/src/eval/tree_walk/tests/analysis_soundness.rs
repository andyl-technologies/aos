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
        (-100_i64..=100).prop_map(|value| { format!("let f = x: x + 1; in f {}", nix_int(value)) }),
        // Apply through a select-resolved lambda on a static attrset literal.
        (-100_i64..=100).prop_map(|value| {
            format!(
                "let lib = {{ inc = x: x + 1; }}; in lib.inc {}",
                nix_int(value)
            )
        }),
        // Identity result spine: the argument is forced by the caller.
        (-100_i64..=100).prop_map(|value| format!("(x: x) {}", nix_int(value))),
        // Recursive let forward references (intra-frame demand fixpoint).
        (-100_i64..=100)
            .prop_map(|value| { format!("let a = b + 1; b = {}; in a", nix_int(value)) }),
        // Branch meet: demanded in both branches of a total condition.
        ((-100_i64..=100), proptest::bool::ANY).prop_map(|(value, flag)| {
            format!("(x: if {flag} then x + 1 else x - 1) {}", nix_int(value))
        }),
        // tryEval barrier (S4): no demand through the catch.
        (-100_i64..=100).prop_map(|value| {
            format!(
                "(x: (builtins.tryEval x).success) (if {} < -200 then throw \"t\" else 1)",
                nix_int(value)
            )
        }),
        // Effect-rank cap: a trace between body start and the forced use.
        (-100_i64..=100)
            .prop_map(|value| { format!("(x: builtins.trace \"m\" (x + 1)) {}", nix_int(value)) }),
        // Derivation-boundary seeding: total binding values assemble
        // eagerly, `name` is first-forced, everything else stays lazy.
        (prop::collection::vec(-20_i64..=20, 0..5), -100_i64..=100).prop_map(|(deps, value)| {
            format!(
                "(builtins.derivationStrict {{ name = \"d\" + \"x\"; \
                     builder = \"b\"; system = \"s\"; \
                     deps = {}; value = {}; }}).drvPath",
                nix_int_list(&deps),
                nix_int(value),
            )
        }),
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
        ("[a-z]{0,12}")
            .prop_map(|s| { format!(r#"let x = "v" + "{s}"; in builtins.stringLength x"#) }),
        (-100_i64..=100, -100_i64..=100).prop_map(|(a, b)| {
            format!(
                "let x = {} + 0; in builtins.sub x {}",
                nix_int(a),
                nix_int(b)
            )
        }),
        (-20_i64..=20, -20_i64..=20).prop_map(|(a, b)| {
            format!(
                "let x = {} + 0; in builtins.mul {} x",
                nix_int(a),
                nix_int(b)
            )
        }),
        (-100_i64..=100, 1_i64..=20).prop_map(|(a, b)| {
            format!(
                "let x = {} + 0; in builtins.div x {}",
                nix_int(a),
                nix_int(b)
            )
        }),
        (0_i64..=255, 0_i64..=255).prop_map(|(a, b)| {
            format!(
                "let x = {} + 0; in builtins.bitAnd x {}",
                nix_int(a),
                nix_int(b)
            )
        }),
        (0_i64..=255, 0_i64..=255).prop_map(|(a, b)| {
            format!(
                "let x = {} + 0; in builtins.bitXor {} x",
                nix_int(a),
                nix_int(b)
            )
        }),
        (-100_i64..=100, -100_i64..=100).prop_map(|(a, b)| {
            format!(
                "let x = {} + 0; in builtins.lessThan x {}",
                nix_int(a),
                nix_int(b)
            )
        }),
        ("[0-9]{1,3}", "[0-9]{1,3}").prop_map(|(a, b)| {
            format!(r#"let x = "1." + "{a}"; in builtins.compareVersions x "1.{b}""#)
        }),
        prop::collection::vec(-20_i64..=20, 0..6).prop_map(|v| {
            format!(
                "let x = {}; in builtins.any (e: e == 3) x",
                nix_int_list(&v)
            )
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
        (-100_i64..=100)
            .prop_map(|n| { format!("let x = 0.5 + {}; in builtins.ceil x", nix_int(n)) }),
        (-100_i64..=100)
            .prop_map(|n| { format!("let x = 0.5 + {}; in builtins.floor x", nix_int(n)) }),
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

mod part_1;
