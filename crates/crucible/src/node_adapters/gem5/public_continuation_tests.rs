//! Exercises post-capture wrapping failures with data-only original byte custody.
//!
//! These records do not create a native seal or qualify an implementation. The
//! installed native witness separately checks identical-cut image reuse.

// Panics intentionally make a violated custody or certainty invariant fail its test.
#![allow(clippy::unwrap_used)]

use super::*;

fn original() -> InputPayload {
    let bytes = b"original captured native record".to_vec();
    InputPayload {
        reference: canonical::content_ref(&bytes, "application/octet-stream").unwrap(),
        bytes,
    }
}

fn envelope(reference: &ContentRef) -> PublicWire {
    PublicWire {
        format: "crucible.gem5.public-native-continuation".to_owned(),
        schema_version: 1,
        node: Id::new("cpu").unwrap(),
        native_state: reference.clone(),
        world_preparation: reference.clone(),
        ready: reference.clone(),
        native_ready: reference.clone(),
        native_session: reference.clone(),
        previous: None,
    }
}

#[test]
fn bounded_serialization_failure_preserves_original_bytes_and_reports_unknown() {
    let retained = original();
    let before = retained.clone();
    let wire = envelope(&retained.reference);
    let mut reservations = 0;

    let failure = prepare_public_envelope(&wire, 1, || {
        reservations += 1;
        Ok(())
    })
    .err()
    .unwrap();

    assert_eq!(failure.effects, EffectKnowledge::Unknown);
    assert_eq!(retained, before);
    assert_eq!(reservations, 0);
    let retried = prepare_public_envelope(&wire, 4096, || Ok(())).unwrap();
    retried.reference.verify(&retried.bytes).unwrap();
    assert_eq!(retained, before);
}

#[test]
fn evidence_allocation_failure_preserves_original_inventory_and_reports_unknown() {
    let retained = original();
    let wire = envelope(&retained.reference);
    let mut evidence = vec![retained.clone()];
    let before = evidence.clone();

    let failure = prepare_public_envelope(&wire, 4096, || {
        evidence
            .try_reserve(usize::MAX)
            .map_err(|_| refusal("public evidence allocation exceeds reserved object credit"))
    })
    .err()
    .unwrap();

    assert_eq!(failure.effects, EffectKnowledge::Unknown);
    assert_eq!(evidence, before);
    let retried = prepare_public_envelope(&wire, 4096, || {
        evidence
            .try_reserve(1)
            .map_err(|_| refusal("retry credit unavailable"))
    })
    .unwrap();
    assert_eq!(
        retried,
        prepare_public_envelope(&wire, 4096, || Ok(())).unwrap()
    );
    assert_eq!(evidence, before);
}
