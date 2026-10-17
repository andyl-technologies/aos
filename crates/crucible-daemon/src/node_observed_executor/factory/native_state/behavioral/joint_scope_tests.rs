//! Tests fresh joint-boundary ordering and actual mutable-file refusal only.
//!
//! These controls use no native owner, activation, graph or accepted report.

use std::cell::Cell;

use super::{authenticate_joint_scope, evidence};
use crate::node_observed_executor::factory::measure_executable;
use crate::node_qualification::QualificationError;

#[test]
fn joint_scope_checks_identity_before_one_fresh_authority_read() {
    let calls = Cell::new(0);
    let current = || {
        calls.set(calls.get() + 1);
        Ok(())
    };

    assert!(authenticate_joint_scope(|| Ok(()), current).is_ok());
    assert_eq!(calls.get(), 1);
    assert!(
        authenticate_joint_scope(
            || Err(QualificationError::Refused("foreign original tuple")),
            current,
        )
        .is_err()
    );
    assert_eq!(calls.get(), 1);
}

#[test]
fn changed_source_during_callback_refuses_the_fresh_final_read() -> Result<(), QualificationError> {
    let directory = tempfile::tempdir().map_err(evidence)?;
    let path = directory.path().join("source");
    std::fs::write(&path, b"original source").map_err(evidence)?;
    let expected = measure_executable(&path).map_err(evidence)?;
    let calls = Cell::new(0);
    let current = || {
        calls.set(calls.get() + 1);
        let actual = measure_executable(&path).map_err(evidence)?;
        if actual != expected {
            return Err(QualificationError::Refused("changed original source"));
        }
        Ok(())
    };

    authenticate_joint_scope(|| Ok(()), current)?;
    // This is the callback batch between the production collector's boundaries.
    std::fs::write(&path, b"changed source!").map_err(evidence)?;
    let final_read = authenticate_joint_scope(|| Ok(()), current);

    assert!(final_read.is_err());
    assert_eq!(calls.get(), 2);
    Ok(())
}

#[test]
fn missing_source_during_callback_refuses_the_fresh_final_read() -> Result<(), QualificationError> {
    let directory = tempfile::tempdir().map_err(evidence)?;
    let path = directory.path().join("source");
    std::fs::write(&path, b"original source").map_err(evidence)?;
    let expected = measure_executable(&path).map_err(evidence)?;
    let calls = Cell::new(0);
    let current = || {
        calls.set(calls.get() + 1);
        if measure_executable(&path).map_err(evidence)? != expected {
            return Err(QualificationError::Refused("changed original source"));
        }
        Ok(())
    };

    authenticate_joint_scope(|| Ok(()), current)?;
    std::fs::remove_file(&path).map_err(evidence)?;
    let final_read = authenticate_joint_scope(|| Ok(()), current);

    assert!(final_read.is_err());
    assert_eq!(calls.get(), 2);
    Ok(())
}
