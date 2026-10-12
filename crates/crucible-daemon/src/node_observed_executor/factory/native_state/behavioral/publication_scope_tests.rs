//! Checks the actual pre-publication helper against changed and missing source.
//!
//! These controls establish ordering only; they own no native process or class.

use std::cell::Cell;

use super::{evidence, publish_current_original};
use crate::{
    node_observed_executor::factory::measure_executable, node_qualification::QualificationError,
};

#[test]
fn source_revoked_after_poll_cannot_publish_original_result() -> Result<(), QualificationError> {
    let directory = tempfile::tempdir().map_err(evidence)?;
    let path = directory.path().join("source");
    std::fs::write(&path, b"original bytes").map_err(evidence)?;
    let expected = measure_executable(&path).map_err(evidence)?;
    let published = Cell::new(false);
    let authenticate = || {
        if measure_executable(&path).map_err(evidence)? != expected {
            return Err(QualificationError::Refused("changed original source"));
        }
        Ok(())
    };

    // The native poll callback may finish successfully while its source changes.
    std::fs::write(&path, b"changed bytes!").map_err(evidence)?;
    let result = publish_current_original(authenticate, || {
        published.set(true);
        Ok(())
    });

    assert!(result.is_err());
    assert!(!published.get());
    Ok(())
}

#[test]
fn missing_source_cannot_acknowledge_original_result() -> Result<(), QualificationError> {
    let directory = tempfile::tempdir().map_err(evidence)?;
    let path = directory.path().join("source");
    std::fs::write(&path, b"original bytes").map_err(evidence)?;
    let expected = measure_executable(&path).map_err(evidence)?;
    let acknowledged = Cell::new(false);
    std::fs::remove_file(&path).map_err(evidence)?;

    let result = publish_current_original(
        || {
            if measure_executable(&path).map_err(evidence)? != expected {
                return Err(QualificationError::Refused("changed original source"));
            }
            Ok(())
        },
        || {
            acknowledged.set(true);
            Ok(())
        },
    );

    assert!(result.is_err());
    assert!(!acknowledged.get());
    Ok(())
}

#[test]
fn unchanged_source_reaches_one_original_publication() -> Result<(), QualificationError> {
    let current_reads = Cell::new(0);
    let publications = Cell::new(0);

    publish_current_original(
        || {
            current_reads.set(current_reads.get() + 1);
            Ok(())
        },
        || {
            publications.set(publications.get() + 1);
            Ok(())
        },
    )?;

    assert_eq!(current_reads.get(), 1);
    assert_eq!(publications.get(), 1);
    Ok(())
}
