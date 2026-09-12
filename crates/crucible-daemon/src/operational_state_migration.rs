//! Ordered stopped-daemon migration of executor operational state.
//!
//! The operation acquires the assignment writer lock first, converts every
//! bounded assignment attempt record to v15, and retains that lock while it
//! converts v1 prepared-result journals under their per-key namespace locks.
//! Runtime readers accept only the current formats after this cutover.

use std::path::PathBuf;

use thiserror::Error;

use crate::prepared_result_journal::migrate_prepared_result_journals;
use crate::{AssignmentLedgerError, DirectoryAssignmentLedger, PreparedResultJournalError};

/// Bounded input to the stopped-daemon operational-state migration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationalStateMigrationConfig {
    /// Existing assignment-ledger root containing `writer.lock`.
    pub assignment_ledger: PathBuf,
    /// Existing prepared-result journal namespace.
    pub prepared_results: PathBuf,
    /// Maximum assignment attempt records admitted in one migration.
    pub maximum_assignment_records: usize,
    /// Maximum prepared-result journals admitted in one migration.
    pub maximum_prepared_journals: usize,
    /// Maximum bytes admitted for any prepared-result payload.
    pub maximum_prepared_result_bytes: usize,
}

/// Durable outcome of one stopped-daemon operational-state migration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperationalStateMigrationSummary {
    /// Number of authenticated assignment attempt records examined.
    pub assignment_records: usize,
    /// Number of legacy assignment records converted to v15.
    pub assignments_migrated: usize,
    /// Number of authenticated prepared-result journals examined.
    pub prepared_journals: usize,
    /// Number of legacy journals converted or durably finalized.
    pub prepared_journals_migrated: usize,
}

/// Migrates legacy executor state while retaining the canonical writer lock.
///
/// Assignment records are converted before prepared journals. This ordering
/// lets journal validation use the current assignment decoder and prevents a
/// daemon restart from observing current journals with a legacy assignment
/// ledger.
///
/// # Errors
///
/// Returns [`OperationalStateMigrationError`] when the assignment root cannot
/// be exclusively opened, either bound is zero, any record is corrupt, any
/// journal lacks its assignment binding, or a durable filesystem operation
/// fails.
pub fn migrate_operational_state(
    config: &OperationalStateMigrationConfig,
) -> Result<OperationalStateMigrationSummary, OperationalStateMigrationError> {
    validate_config(config)?;
    let mut ledger = DirectoryAssignmentLedger::open_existing(&config.assignment_ledger)?;
    let assignments = ledger.migrate_attempt_records(config.maximum_assignment_records)?;
    let prepared_results = migrate_prepared_result_journals(
        &config.prepared_results,
        &mut ledger,
        config.maximum_prepared_journals,
        config.maximum_prepared_result_bytes,
    )?;
    Ok(OperationalStateMigrationSummary {
        assignment_records: assignments.records,
        assignments_migrated: assignments.migrated,
        prepared_journals: prepared_results.journals,
        prepared_journals_migrated: prepared_results.migrated,
    })
}

/// Failure from an ordered stopped-daemon operational-state migration.
#[derive(Debug, Error)]
pub enum OperationalStateMigrationError {
    /// A configured inventory or payload bound is zero.
    #[error("operational-state migration bounds must be nonzero")]
    InvalidBound,
    /// The assignment ledger migration failed.
    #[error(transparent)]
    Assignment(#[from] AssignmentLedgerError),
    /// The prepared-result journal migration failed.
    #[error(transparent)]
    PreparedResult(#[from] PreparedResultJournalError),
}

fn validate_config(
    config: &OperationalStateMigrationConfig,
) -> Result<(), OperationalStateMigrationError> {
    if config.maximum_assignment_records == 0
        || config.maximum_prepared_journals == 0
        || config.maximum_prepared_result_bytes == 0
    {
        Err(OperationalStateMigrationError::InvalidBound)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- failures identify the exact lock-order fixture step.
    #![allow(clippy::expect_used)]

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn ordered_migration_acquires_assignment_writer_before_journal_namespace() {
        let ledger_root = TempDir::new().expect("ledger root");
        let prepared_results = TempDir::new().expect("prepared-result namespace");
        let held_writer = DirectoryAssignmentLedger::open(ledger_root.path()).expect("hold writer");
        let config = OperationalStateMigrationConfig {
            assignment_ledger: ledger_root.path().to_path_buf(),
            prepared_results: prepared_results.path().to_path_buf(),
            maximum_assignment_records: 1,
            maximum_prepared_journals: 1,
            maximum_prepared_result_bytes: 1,
        };

        assert!(matches!(
            migrate_operational_state(&config),
            Err(OperationalStateMigrationError::Assignment(
                AssignmentLedgerError::Io {
                    operation: "lock-writer",
                    ..
                }
            ))
        ));
        drop(held_writer);
    }
}
