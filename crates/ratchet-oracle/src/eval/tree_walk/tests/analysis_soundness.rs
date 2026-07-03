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

proptest! {
    #[test]
    fn analysis_annotations_preserve_generated_json_observables(
        source in json_parity_source_strategy(),
    ) {
        assert_annotated_json_matches_conservative(&source);
    }
}
