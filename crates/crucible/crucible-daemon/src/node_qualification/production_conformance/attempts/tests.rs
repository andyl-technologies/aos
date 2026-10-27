//! Checks refusal retention without constructing provider or class authority.

use super::*;

#[test]
fn refused_actual_attempt_cannot_become_unexecuted() -> Result<(), QualificationError> {
    let mut original = OriginalCollectionAttempts::default();
    assert!(original.complete());

    original.begin("original-window".into());
    assert!(!original.complete());
    assert!(original.attempted("original-window"));
    assert!(original.authenticated_cases().is_empty());

    original.authenticate("original-window")?;
    assert!(original.complete());
    assert_eq!(original.attempted_cases(), original.authenticated_cases());
    Ok(())
}

#[test]
fn foreign_and_replacement_authentication_retains_original_attempts()
-> Result<(), QualificationError> {
    let mut original = OriginalCollectionAttempts::default();
    original.begin("original-window".into());

    assert!(original.authenticate("foreign-window").is_err());
    assert!(!original.complete());
    assert!(original.authenticated_cases().is_empty());

    original.authenticate("original-window")?;
    assert!(original.authenticate("original-window").is_err());
    assert!(original.complete());
    assert_eq!(original.attempted_cases().len(), 1);
    Ok(())
}

#[test]
fn missing_original_evidence_refuses_before_issuance_and_keeps_attempts() {
    let mut original = OriginalCollectionAttempts::default();
    original.begin("refused-window".into());
    let mut issuance_called = false;

    let (retained, issued) = original.finish(|| {
        issuance_called = true;
        Ok(())
    });
    assert!(!issuance_called);
    assert!(matches!(
        issued,
        Err(QualificationError::Refused(
            "original conformance attempt lacks authenticated evidence"
        ))
    ));
    assert!(retained.attempted("refused-window"));
    assert!(retained.authenticated_cases().is_empty());
}

#[test]
fn authenticated_originals_preserve_the_actual_issuance_result() -> Result<(), QualificationError> {
    let mut original = OriginalCollectionAttempts::default();
    original.begin("original-window".into());
    original.authenticate("original-window")?;
    let mut issuance_called = false;

    let (retained, issued) = original.finish(|| {
        issuance_called = true;
        Err::<(), _>(QualificationError::Refused("original encoding refusal"))
    });
    assert!(issuance_called);
    assert!(matches!(
        issued,
        Err(QualificationError::Refused("original encoding refusal"))
    ));
    assert_eq!(retained.attempted_cases(), retained.authenticated_cases());
    Ok(())
}
