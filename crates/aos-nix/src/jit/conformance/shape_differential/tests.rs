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
fn integer_arithmetic_matches_tree_walk() {
    use ratchet_core::syntax::BinOpKind;

    // (operands, op, expected int result)
    let cases: &[(&str, &str, BinOpKind, i64)] = &[
        ("3", "4", BinOpKind::Add, 7),
        ("10", "3", BinOpKind::Sub, 7),
        ("6", "7", BinOpKind::Mul, 42),
        ("20", "4", BinOpKind::Div, 5),
        ("-7", "2", BinOpKind::Div, -3),
        ("2 * 3", "4", BinOpKind::Add, 10),
    ];
    for (left, right, op, expected) in cases {
        let outcome = nix_jit_arith_native_differential(left, right, *op)
            .unwrap_or_else(|error| panic!("{left} {op:?} {right} differential runs: {error}"));
        let ShapeDifferentialOutcome::Value { native, .. } = outcome else {
            panic!("expected a value-agreement outcome for {left} {op:?} {right}, got {outcome:?}");
        };
        assert_eq!(native.as_int(), Ok(*expected), "{left} {op:?} {right}");
    }
}

#[test]
fn integer_comparison_matches_tree_walk() {
    use ratchet_core::syntax::BinOpKind;

    // (operands, op, expected bool result)
    let cases: &[(&str, &str, BinOpKind, bool)] = &[
        ("3", "5", BinOpKind::Lt, true),
        ("5", "3", BinOpKind::Lt, false),
        ("5", "5", BinOpKind::Le, true),
        ("6", "5", BinOpKind::Gt, true),
        ("5", "5", BinOpKind::Ge, true),
        ("5", "5", BinOpKind::Eq, true),
        ("5", "6", BinOpKind::Eq, false),
        ("5", "6", BinOpKind::Ne, true),
    ];
    for (left, right, op, expected) in cases {
        let outcome = nix_jit_arith_native_differential(left, right, *op)
            .unwrap_or_else(|error| panic!("{left} {op:?} {right} differential runs: {error}"));
        let ShapeDifferentialOutcome::Value { native, .. } = outcome else {
            panic!("expected a value-agreement outcome for {left} {op:?} {right}, got {outcome:?}");
        };
        assert_eq!(native.as_bool(), Ok(*expected), "{left} {op:?} {right}");
    }
}

#[test]
fn integer_division_by_zero_transfers_trap() {
    use ratchet_core::syntax::BinOpKind;

    // The tree walk errors on a zero divisor; the inline divide guard branches to
    // the deopt trampoline, which records a trap. Both sides fail.
    let outcome = nix_jit_arith_native_differential("3", "0", BinOpKind::Div)
        .expect("division-by-zero differential runs");
    assert!(
        outcome.is_trap(),
        "expected a trap-agreement outcome, got {outcome:?}"
    );
}

#[test]
fn integer_division_overflow_transfers_trap() {
    use ratchet_core::syntax::BinOpKind;

    // `i64::MIN / -1` overflows; the tree walk errors and the inline guard deopts.
    let outcome =
        nix_jit_arith_native_differential("(-9223372036854775807 - 1)", "-1", BinOpKind::Div)
            .expect("division-overflow differential runs");
    assert!(
        outcome.is_trap(),
        "expected a trap-agreement outcome, got {outcome:?}"
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
