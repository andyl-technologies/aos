//! Value- and trap-mode differential tests for the compiled helper shapes.

use ratchet_value::value::Value;

use super::*;

#[test]
fn static_select_present_attr_matches_tree_walk() {
    let outcome =
        nix_jit_static_select_native_differential("{ target = 40 + 2; other = 7; }", b"target")
            .expect("static select differential runs");

    let ShapeDifferentialOutcome::Value { native, .. } = outcome else {
        panic!("expected a value-agreement outcome, got {outcome:?}");
    };
    assert_eq!(native.as_int(), Ok(42));
}

#[test]
fn static_select_missing_attr_transfers_trap() {
    let outcome = nix_jit_static_select_native_differential("{ other = 7; }", b"target")
        .expect("static select trap differential runs");

    let ShapeDifferentialOutcome::Trap {
        oracle_error,
        native_trap,
    } = outcome
    else {
        panic!("expected a trap-agreement outcome, got {outcome:?}");
    };
    assert!(matches!(
        native_trap,
        RuntimeTrap::Attr(trap_error) if trap_error == oracle_error
    ));
}

#[test]
fn static_has_attr_present_matches_tree_walk() {
    let outcome = nix_jit_static_has_attr_native_differential("{ target = 42; }", b"target")
        .expect("has-attr present differential runs");

    let ShapeDifferentialOutcome::Value { native, .. } = outcome else {
        panic!("expected a value-agreement outcome, got {outcome:?}");
    };
    assert_eq!(native.as_bool(), Ok(true));
}

#[test]
fn static_has_attr_absent_matches_tree_walk() {
    let outcome = nix_jit_static_has_attr_native_differential("{ other = 7; }", b"target")
        .expect("has-attr absent differential runs");

    let ShapeDifferentialOutcome::Value { native, .. } = outcome else {
        panic!("expected a value-agreement outcome, got {outcome:?}");
    };
    assert_eq!(native.as_bool(), Ok(false));
}

#[test]
fn apply_lambda_matches_tree_walk() {
    let outcome = nix_jit_apply_native_differential("x: x + 1", Value::int(41))
        .expect("apply differential runs");

    let ShapeDifferentialOutcome::Value { native, .. } = outcome else {
        panic!("expected a value-agreement outcome, got {outcome:?}");
    };
    assert_eq!(native.as_int(), Ok(42));
}

#[test]
fn apply_non_function_transfers_trap() {
    // Applying an integer is a call-control error; native code transfers a trap
    // carrying the same tree-walk error the oracle raised.
    let outcome = nix_jit_apply_native_differential("5", Value::int(1))
        .expect("apply non-function trap differential runs");

    let ShapeDifferentialOutcome::Trap {
        oracle_error,
        native_trap,
    } = outcome
    else {
        panic!("expected a trap-agreement outcome, got {outcome:?}");
    };
    assert!(matches!(
        native_trap,
        RuntimeTrap::Apply(trap_error) if trap_error == oracle_error
    ));
}

#[test]
fn update_merges_attrsets_matching_tree_walk() {
    let outcome = nix_jit_update_native_differential(
        "{ left = { keep = 1; replace = 2; }; right = { replace = 42; add = 7; }; }",
        &[b"keep", b"replace", b"add"],
    )
    .expect("update differential runs");

    assert!(
        outcome.is_value(),
        "expected value agreement, got {outcome:?}"
    );
}

#[test]
fn update_non_attrset_transfers_trap() {
    // Updating a non-attribute-set left operand fails; native code transfers a
    // trap carrying the same tree-walk error the oracle raised.
    let outcome = nix_jit_update_native_differential("{ left = 5; right = { a = 1; }; }", &[])
        .expect("update non-attrset trap differential runs");

    let ShapeDifferentialOutcome::Trap {
        oracle_error,
        native_trap,
    } = outcome
    else {
        panic!("expected a trap-agreement outcome, got {outcome:?}");
    };
    assert!(matches!(
        native_trap,
        RuntimeTrap::Attr(trap_error) if trap_error == oracle_error
    ));
}
