//! Canonical continuation, parser refusal, and returned-byte custody regressions.

use super::*;
use crate::test_support::fixture_decode_scope;

#[test]
fn cbor_roundtrip_preserves_large_scalar_and_encoded_credit_outlives_checkpoint()
-> Result<(), Box<dyn Error>> {
    let scope = fixture_decode_scope(8 << 20)?;
    let marker = GuestAssertionMarker::new(
        AssertionId::from_name("large-cbor"),
        "m".repeat(9000),
        GuestAssertionKind::Always,
        true,
        true,
        Vec::new(),
        "guest",
    );
    let evaluator = HostAssertionEvaluator::new(&Properties::empty())?
        .with_guest_assertion_catalog(&[marker])?;
    let baseline = scope.retained_bytes();
    let checkpoint = evaluator.checkpoint()?;
    let bytes = checkpoint.canonical_bytes()?;
    let decoded = HostAssertionEvaluatorCheckpoint::from_canonical_bytes(&bytes)?;
    assert_eq!(decoded.wire.guest_marker_states[0].message.len(), 9000);
    assert_eq!(decoded.canonical_bytes()?.as_slice(), bytes.as_slice());
    drop(decoded);
    drop(checkpoint);
    assert!(scope.retained_bytes() > baseline);
    assert!(bytes.starts_with(MAGIC));
    drop(bytes);
    assert_eq!(scope.retained_bytes(), baseline);
    Ok(())
}

#[test]
fn parser_admission_refuses_before_decode_and_retains_typed_error_credit()
-> Result<(), Box<dyn Error>> {
    let mut payload = Vec::from(MAGIC);
    payload.push(0xa0); // A valid CBOR map, but no required continuation fields.
    let scope = fixture_decode_scope(4096)?;
    let baseline = scope.retained_bytes();
    let error = HostAssertionEvaluatorCheckpoint::from_canonical_bytes(&payload)
        .err()
        .ok_or_else(|| io::Error::other("fixture must refuse parser admission"))?;
    assert!(matches!(
        error,
        HostAssertionCheckpointError::Admission { .. }
    ));
    assert!(error.source().is_some());
    assert!(scope.retained_bytes() > baseline);
    drop(error);
    assert_eq!(scope.retained_bytes(), baseline);
    Ok(())
}

#[test]
fn truncated_huge_declared_scalar_does_not_allocate_declared_extent() -> Result<(), Box<dyn Error>>
{
    let scope = fixture_decode_scope(1 << 20)?;
    let baseline = scope.retained_bytes();
    let mut payload = Vec::from(MAGIC);
    // A definite text string declaring u64::MAX bytes, with no body.
    payload.push(0x7b);
    payload.extend_from_slice(&u64::MAX.to_be_bytes());
    assert!(matches!(
        HostAssertionEvaluatorCheckpoint::from_canonical_bytes(&payload),
        Err(HostAssertionCheckpointError::Malformed)
    ));
    assert_eq!(scope.retained_bytes(), baseline);
    scope.check()?;
    Ok(())
}

#[test]
fn canonical_empty_wire_remains_the_same_cbor_envelope() -> Result<(), Box<dyn Error>> {
    let _scope = fixture_decode_scope(1 << 20)?;
    let evaluator = HostAssertionEvaluator::new(&Properties::empty())?;
    let checkpoint = evaluator.checkpoint()?;
    let actual = checkpoint.canonical_bytes()?;
    let mut oracle = Vec::from(MAGIC);
    ciborium::ser::into_writer(&checkpoint.wire, &mut oracle)?;
    assert_eq!(actual.as_slice(), oracle.as_slice());
    let mut trailing = oracle;
    trailing.push(0);
    assert!(matches!(
        HostAssertionEvaluatorCheckpoint::from_canonical_bytes(&trailing),
        Err(HostAssertionCheckpointError::Noncanonical)
    ));
    Ok(())
}

#[test]
fn long_unknown_identifier_and_extreme_numeric_errors_release_parser_bank()
-> Result<(), Box<dyn Error>> {
    let scope = fixture_decode_scope(2 << 20)?;
    let baseline = scope.retained_bytes();
    for payload in [
        ciborium::value::Value::Map(vec![(
            ciborium::value::Value::Text("unknown\nfield\0".repeat(512)),
            ciborium::value::Value::Null,
        )]),
        ciborium::value::Value::Float(f64::MAX),
        ciborium::value::Value::Float(f64::from_bits(1)),
    ] {
        let mut bytes = Vec::from(MAGIC);
        ciborium::ser::into_writer(&payload, &mut bytes)?;
        assert!(matches!(
            HostAssertionEvaluatorCheckpoint::from_canonical_bytes(&bytes),
            Err(HostAssertionCheckpointError::Malformed)
        ));
        assert_eq!(scope.retained_bytes(), baseline);
    }
    scope.check()?;
    Ok(())
}
