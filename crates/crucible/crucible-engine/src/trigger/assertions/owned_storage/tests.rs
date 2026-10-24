//! Constructor refusal and independent diagnostic-copy lifetime regressions.

use super::*;
use crate::test_support::fixture_decode_scope;

#[test]
fn constructor_requires_original_finite_authority() {
    assert!(matches!(
        HostAssertionEvaluator::new(&Properties::empty()),
        Err(EngineError::ArtifactDecodeAdmission { .. })
    ));
}

#[test]
fn definition_copy_refusal_returns_all_provisional_credits() -> Result<(), Box<dyn Error>> {
    let scope = fixture_decode_scope(4096)?;
    let baseline = scope.retained_bytes();
    let marker = GuestAssertionMarker::new(
        AssertionId::from_name("large-marker"),
        "m".repeat(16384),
        GuestAssertionKind::Always,
        true,
        true,
        Vec::new(),
        "guest",
    );
    let result =
        HostAssertionEvaluator::new(&Properties::empty())?.with_guest_assertion_catalog(&[marker]);
    assert!(matches!(
        result,
        Err(EngineError::ArtifactDecodeAdmission { .. })
    ));
    drop(result);
    assert_eq!(scope.retained_bytes(), baseline);
    Ok(())
}

#[test]
fn diagnostic_copies_release_independently_and_two_live_copies_charge_twice()
-> Result<(), Box<dyn Error>> {
    let scope = fixture_decode_scope(8 << 20)?;
    let violation = HostAssertionViolation::from_owned_fields(HostAssertionViolationFields {
        assertion: copy_assertion_id(&AssertionId::from_name("copy-lifetime"))?,
        message: copy_string(&"m".repeat(8192))?,
        quantifier: AssertionQuantifierKind::Always,
        event_kind: copy_string("assertion_state_changed")?,
        at_icount: None,
        at_virtual_time: VirtualTime { ticks: 17 },
        node: None,
        detail: copy_string("original admitted observation")?,
        reproduction_artifact: ContentHash::from_bytes(b"same-record"),
    })?;
    let baseline = scope.retained_bytes();
    for _ in 0..512 {
        let copy = violation.try_clone_admitted()?;
        assert_eq!(copy, violation);
        assert!(scope.retained_bytes() > baseline);
        drop(copy);
        assert_eq!(scope.retained_bytes(), baseline);
    }
    let first = violation.try_clone_admitted()?;
    let one_copy = scope.retained_bytes() - baseline;
    let second = violation.try_clone_admitted()?;
    assert_eq!(scope.retained_bytes(), baseline + 2 * one_copy);
    drop(first);
    assert_eq!(scope.retained_bytes(), baseline + one_copy);
    assert_eq!(second.message, violation.message);
    drop(second);
    assert_eq!(scope.retained_bytes(), baseline);
    Ok(())
}
