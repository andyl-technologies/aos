//! Checks `gate:layer0-determinism` for assertion data contracts.

#![forbid(unsafe_code)]

use crucible_assert::{
    ASSERTION_VOCABULARY_VERSION, AssertionKind, AssertionSpec, AssertionSpecError,
};

#[test]
fn gate_layer0_determinism_assertion_ids_are_canonical() {
    let spec = AssertionSpec::new(
        AssertionKind::DigestEquality,
        "crucible.layer0.reduce-twice",
    );
    let spec = match spec {
        Ok(spec) => spec,
        Err(error) => panic!("assertion spec should be valid: {error}"),
    };

    let canonical_id = assert_twice_reduce_canonical_digest(|| spec.canonical_id());

    assert_eq!(
        canonical_id,
        format!("{ASSERTION_VOCABULARY_VERSION}:digest-equality:crucible.layer0.reduce-twice")
    );
}

#[test]
fn gate_layer0_determinism_assertion_order_is_stable() {
    let ordered_ids = assert_twice_reduce_canonical_digest(|| {
        let mut specs = [
            assertion(AssertionKind::TotalOrderStability, "scheduler.event-key"),
            assertion(AssertionKind::DecisionStreamStability, "rng.node-a"),
            assertion(AssertionKind::DigestEquality, "reduce.fixed-schedule"),
        ];

        specs.sort();

        specs
            .iter()
            .map(AssertionSpec::canonical_id)
            .collect::<Vec<_>>()
    });

    assert_eq!(
        ordered_ids,
        vec![
            "crucible-assert.v1:digest-equality:reduce.fixed-schedule",
            "crucible-assert.v1:total-order-stability:scheduler.event-key",
            "crucible-assert.v1:decision-stream-stability:rng.node-a",
        ]
    );
}

#[test]
fn gate_layer0_determinism_assertions_reject_ambiguous_subjects() {
    assert_eq!(
        AssertionSpec::new(AssertionKind::DigestEquality, ""),
        Err(AssertionSpecError::EmptySubject)
    );
    assert_eq!(
        AssertionSpec::new(AssertionKind::DigestEquality, "reduce:fixed-schedule"),
        Err(AssertionSpecError::AmbiguousSubject)
    );
}

fn assert_twice_reduce_canonical_digest<D, F>(mut reduce: F) -> D
where
    D: Clone + std::fmt::Debug + PartialEq,
    F: FnMut() -> D,
{
    let first = reduce();
    let second = reduce();

    assert_eq!(first, second);

    first
}

fn assertion(kind: AssertionKind, subject: &str) -> AssertionSpec {
    match AssertionSpec::new(kind, subject) {
        Ok(spec) => spec,
        Err(error) => panic!("assertion spec should be valid: {error}"),
    }
}
