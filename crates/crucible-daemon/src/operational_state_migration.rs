//! Ordered stopped-daemon migration of executor operational state.
//!
//! The operation acquires the assignment writer lock first, converts every
//! bounded assignment attempt record to v15, and retains that lock while it
//! converts v1 prepared-result journals under their per-key namespace locks.
//! Runtime readers accept only the current formats after this cutover.

use std::fs;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::anchored_fs::AnchoredDirectory;
use crate::prepared_result_journal::migrate_prepared_result_journals;
use crate::{AssignmentLedgerError, DirectoryAssignmentLedger, PreparedResultJournalError};

pub(crate) mod receipt;

use receipt::{activate_marker, combined_receipt_id, finish_marker, prepare_receipt_directory};

pub(crate) const MAX_OPERATIONAL_STATE_MIGRATION_ENTRIES: usize = 1_000_000;

/// Bounded input to the stopped-daemon operational-state migration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationalStateMigrationConfig {
    /// Existing assignment-ledger root containing `writer.lock`.
    pub assignment_ledger: PathBuf,
    /// Existing prepared-result journal namespace.
    pub prepared_results: PathBuf,
    /// Durable directory for authenticated rewrite provenance.
    pub receipt: PathBuf,
    /// Maximum assignment-ledger entries admitted in one migration.
    pub maximum_assignment_entries: usize,
    /// Maximum aggregate bytes admitted from assignment-ledger entries.
    pub maximum_assignment_bytes: u64,
    /// Maximum prepared-result namespace entries admitted in one migration.
    pub maximum_prepared_result_entries: usize,
    /// Maximum aggregate bytes admitted from prepared-result entries.
    pub maximum_prepared_result_bytes: usize,
}

/// Durable outcome of one stopped-daemon operational-state migration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationalStateMigrationSummary {
    /// Number of authenticated assignment attempt records examined.
    pub assignment_records: usize,
    /// Number of legacy assignment records converted to v15.
    pub assignments_migrated: usize,
    /// Number of authenticated prepared-result journals examined.
    pub prepared_journals: usize,
    /// Number of legacy journals converted or durably finalized.
    pub prepared_journals_migrated: usize,
    /// Authenticated identity of the two durable phase receipts.
    pub receipt_id: String,
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
    let assignment_ledger = canonical_existing(&config.assignment_ledger, "canonicalize-ledger")?;
    let prepared_results = canonical_existing(&config.prepared_results, "canonicalize-prepared")?;
    let receipt = canonical_output(&config.receipt)?;
    let prepared_guard = AnchoredDirectory::new(prepared_results.clone())?;
    let receipt_guard = prepare_receipt_directory(&receipt)?;
    let mut ledger = DirectoryAssignmentLedger::open_existing_for_migration(&assignment_ledger)?;
    let assignment_marker = activate_marker(
        ledger.authority(),
        &receipt_guard,
        &assignment_ledger,
        &prepared_results,
    )?;
    let prepared_marker = activate_marker(
        &prepared_guard,
        &receipt_guard,
        &assignment_ledger,
        &prepared_results,
    )?;
    let assignments = ledger.migrate_attempt_records(
        &receipt_guard,
        config.maximum_assignment_entries,
        config.maximum_assignment_bytes,
    )?;
    let prepared_summary = migrate_prepared_result_journals(
        &prepared_guard,
        &receipt_guard,
        &mut ledger,
        config.maximum_prepared_result_entries,
        config.maximum_prepared_result_bytes,
    )?;
    let summary = OperationalStateMigrationSummary {
        assignment_records: assignments.records,
        assignments_migrated: assignments.migrated,
        prepared_journals: prepared_summary.journals,
        prepared_journals_migrated: prepared_summary.migrated,
        receipt_id: combined_receipt_id(&assignments.receipt.id, &prepared_summary.receipt.id),
    };
    assignments.receipt.verify_path_binding()?;
    prepared_summary.receipt.verify_path_binding()?;
    finish_marker(&prepared_marker, &receipt_guard)?;
    finish_marker(&assignment_marker, &receipt_guard)?;
    Ok(summary)
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
    /// A durable provenance receipt is malformed or inconsistent.
    #[error("operational-state migration receipt is invalid")]
    InvalidReceipt,
    /// A durable receipt filesystem operation failed.
    #[error("operational-state migration receipt {operation} failed for {path}: {source}")]
    ReceiptIo {
        /// Filesystem operation that failed.
        operation: &'static str,
        /// Receipt path involved.
        path: PathBuf,
        /// Underlying I/O failure.
        #[source]
        source: std::io::Error,
    },
    /// A migration root no longer names the locked physical directory.
    #[error("operational-state migration directory was replaced: {path}")]
    DirectoryReplaced {
        /// Canonical path whose physical identity changed.
        path: PathBuf,
    },
}

impl From<crate::anchored_fs::AnchoredFsError> for OperationalStateMigrationError {
    fn from(error: crate::anchored_fs::AnchoredFsError) -> Self {
        use crate::anchored_fs::AnchoredFsError;

        match error {
            AnchoredFsError::InvalidPath { .. } => Self::InvalidReceipt,
            AnchoredFsError::DirectoryReplaced { path } => Self::DirectoryReplaced { path },
            AnchoredFsError::Io {
                operation,
                path,
                source,
            } => Self::ReceiptIo {
                operation,
                path,
                source,
            },
        }
    }
}

fn validate_config(
    config: &OperationalStateMigrationConfig,
) -> Result<(), OperationalStateMigrationError> {
    if config.maximum_assignment_entries == 0
        || config.maximum_assignment_bytes == 0
        || config.maximum_prepared_result_entries == 0
        || config.maximum_prepared_result_bytes == 0
        || config.maximum_assignment_entries > MAX_OPERATIONAL_STATE_MIGRATION_ENTRIES
        || config.maximum_prepared_result_entries > MAX_OPERATIONAL_STATE_MIGRATION_ENTRIES
    {
        Err(OperationalStateMigrationError::InvalidBound)
    } else {
        Ok(())
    }
}

fn canonical_existing(
    path: &Path,
    operation: &'static str,
) -> Result<PathBuf, OperationalStateMigrationError> {
    if !path.is_absolute() {
        return Err(OperationalStateMigrationError::InvalidReceipt);
    }
    fs::canonicalize(path).map_err(|source| OperationalStateMigrationError::ReceiptIo {
        operation,
        path: path.to_path_buf(),
        source,
    })
}

fn canonical_output(path: &Path) -> Result<PathBuf, OperationalStateMigrationError> {
    if !path.is_absolute() {
        return Err(OperationalStateMigrationError::InvalidReceipt);
    }
    match fs::canonicalize(path) {
        Ok(path) => Ok(path),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .ok_or(OperationalStateMigrationError::InvalidReceipt)?;
            let name = path
                .file_name()
                .ok_or(OperationalStateMigrationError::InvalidReceipt)?;
            canonical_existing(parent, "canonicalize-receipt-parent")
                .map(|parent| parent.join(name))
        }
        Err(source) => Err(OperationalStateMigrationError::ReceiptIo {
            operation: "canonicalize-receipt",
            path: path.to_path_buf(),
            source,
        }),
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
        let receipt_parent = TempDir::new().expect("receipt parent");
        let held_writer = DirectoryAssignmentLedger::open(ledger_root.path()).expect("hold writer");
        let config = OperationalStateMigrationConfig {
            assignment_ledger: ledger_root.path().to_path_buf(),
            prepared_results: prepared_results.path().to_path_buf(),
            receipt: receipt_parent.path().join("receipt"),
            maximum_assignment_entries: 1,
            maximum_assignment_bytes: 1,
            maximum_prepared_result_entries: 1,
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

    fn empty_config(
        ledger: &TempDir,
        prepared: &TempDir,
        receipt_parent: &TempDir,
    ) -> OperationalStateMigrationConfig {
        drop(DirectoryAssignmentLedger::open(ledger.path()).expect("initialize ledger"));
        OperationalStateMigrationConfig {
            assignment_ledger: ledger.path().canonicalize().expect("canonical ledger"),
            prepared_results: prepared
                .path()
                .canonicalize()
                .expect("canonical prepared namespace"),
            receipt: receipt_parent.path().join("receipt"),
            maximum_assignment_entries: 64,
            maximum_assignment_bytes: 64 * 1024,
            maximum_prepared_result_entries: 64,
            maximum_prepared_result_bytes: 64 * 1024,
        }
    }

    #[test]
    fn migration_receipts_are_durable_and_stable_on_retry() {
        let ledger = TempDir::new().expect("ledger");
        let prepared = TempDir::new().expect("prepared");
        let receipt_parent = TempDir::new().expect("receipt parent");
        let config = empty_config(&ledger, &prepared, &receipt_parent);

        let first = migrate_operational_state(&config).expect("first migration");
        assert_eq!(first.receipt_id.len(), 64);
        assert!(ledger.path().join(receipt::ACTIVE_MARKER).exists());
        assert!(prepared.path().join(receipt::ACTIVE_MARKER).exists());
        let second = migrate_operational_state(&config).expect("idempotent retry");
        assert_eq!(second.receipt_id, first.receipt_id);
    }

    #[test]
    fn migration_bounds_every_ledger_entry_and_byte_before_replacement() {
        for byte_bound in [false, true] {
            let ledger = TempDir::new().expect("ledger");
            let prepared = TempDir::new().expect("prepared");
            let receipt_parent = TempDir::new().expect("receipt parent");
            let mut config = empty_config(&ledger, &prepared, &receipt_parent);
            if byte_bound {
                config.maximum_assignment_bytes = 1;
            } else {
                config.maximum_assignment_entries = 1;
            }

            assert!(matches!(
                migrate_operational_state(&config),
                Err(OperationalStateMigrationError::Assignment(
                    AssignmentLedgerError::Corrupt { .. }
                ))
            ));
        }
    }

    #[test]
    fn migration_bounds_prepared_lock_and_junk_entries() {
        let ledger = TempDir::new().expect("ledger");
        let prepared = TempDir::new().expect("prepared");
        let receipt_parent = TempDir::new().expect("receipt parent");
        let mut config = empty_config(&ledger, &prepared, &receipt_parent);
        config.maximum_prepared_result_entries = 1;
        for marker in [0x31_u8, 0x32] {
            fs::write(
                prepared
                    .path()
                    .join(format!(".lock-{}", hex(&[marker; 32]))),
                [],
            )
            .expect("prepared lock file");
        }

        assert!(matches!(
            migrate_operational_state(&config),
            Err(OperationalStateMigrationError::PreparedResult(
                PreparedResultJournalError::MigrationLimitExceeded
            ))
        ));
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
