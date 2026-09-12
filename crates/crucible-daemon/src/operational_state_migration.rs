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

/// Maximum pre-cutover inventory accepted by either migration phase.
pub(crate) const MAX_OPERATIONAL_STATE_MIGRATION_ENTRIES: usize = 1_000_000;
/// Runtime inventory limit including one terminal staging entry per source.
pub(crate) const MAX_OPERATIONAL_STATE_RUNTIME_ENTRIES: usize =
    MAX_OPERATIONAL_STATE_MIGRATION_ENTRIES * 2;

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
    _owner: &crate::PreparedCampaignStoppedOwner,
    config: &OperationalStateMigrationConfig,
) -> Result<OperationalStateMigrationSummary, OperationalStateMigrationError> {
    migrate_operational_state_inner(config)
}

fn migrate_operational_state_inner(
    config: &OperationalStateMigrationConfig,
) -> Result<OperationalStateMigrationSummary, OperationalStateMigrationError> {
    validate_config(config)?;
    let assignment_ledger = canonical_existing(&config.assignment_ledger, "canonicalize-ledger")?;
    let prepared_results = canonical_existing(&config.prepared_results, "canonicalize-prepared")?;
    let (receipt, receipt_parent) = canonical_output(&config.receipt)?;
    let prepared_guard = AnchoredDirectory::new(prepared_results.clone())?;
    let mut ledger = DirectoryAssignmentLedger::open_existing_for_migration(&assignment_ledger)?;
    validate_root_separation(
        &assignment_ledger,
        ledger.authority(),
        &prepared_results,
        &prepared_guard,
        &receipt,
    )?;
    let prepared_owner =
        crate::prepared_result_journal::acquire_runtime_owner_lock(&prepared_guard)?;
    #[cfg(test)]
    run_root_race_hook();
    receipt_parent.verify_path_binding()?;
    let receipt_guard = prepare_receipt_directory(&receipt_parent, &receipt)?;
    receipt_parent.verify_path_binding()?;
    if receipt_guard.identity() == ledger.authority().identity()
        || receipt_guard.identity() == prepared_guard.identity()
    {
        return Err(OperationalStateMigrationError::InvalidReceipt);
    }
    ledger.verify_writer_authority()?;
    prepared_owner.verify_path_binding()?;
    let assignment_marker = activate_marker(
        ledger.authority(),
        &receipt_guard,
        &assignment_ledger,
        &prepared_results,
    )?;
    ledger.verify_writer_authority()?;
    prepared_owner.verify_path_binding()?;
    let prepared_marker = activate_marker(
        &prepared_guard,
        &receipt_guard,
        &assignment_ledger,
        &prepared_results,
    )?;
    ledger.verify_writer_authority()?;
    prepared_owner.verify_path_binding()?;
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
    prepared_owner.verify_path_binding()?;
    #[cfg(test)]
    run_root_race_hook();
    ledger.verify_writer_authority()?;
    prepared_guard.verify_path_binding()?;
    finish_marker(&prepared_marker, &receipt_guard)?;
    finish_marker(&assignment_marker, &receipt_guard)?;
    #[cfg(test)]
    run_root_race_hook();
    ledger.verify_writer_authority()?;
    prepared_owner.verify_path_binding()?;
    prepared_guard.verify_path_binding()?;
    receipt_guard.verify_path_binding()?;
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
    let metadata =
        fs::symlink_metadata(path).map_err(|source| OperationalStateMigrationError::ReceiptIo {
            operation,
            path: path.to_path_buf(),
            source,
        })?;
    if !metadata.file_type().is_dir() {
        return Err(OperationalStateMigrationError::InvalidReceipt);
    }
    fs::canonicalize(path).map_err(|source| OperationalStateMigrationError::ReceiptIo {
        operation,
        path: path.to_path_buf(),
        source,
    })
}

fn canonical_output(
    path: &Path,
) -> Result<(PathBuf, AnchoredDirectory), OperationalStateMigrationError> {
    if !path.is_absolute() {
        return Err(OperationalStateMigrationError::InvalidReceipt);
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.file_type().is_dir() => {
            return Err(OperationalStateMigrationError::InvalidReceipt);
        }
        Ok(_) => {}
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(OperationalStateMigrationError::ReceiptIo {
                operation: "inspect-receipt",
                path: path.to_path_buf(),
                source,
            });
        }
    }
    match fs::canonicalize(path) {
        Ok(path) => {
            let parent = path
                .parent()
                .ok_or(OperationalStateMigrationError::InvalidReceipt)?;
            Ok((path.clone(), AnchoredDirectory::new(parent.to_owned())?))
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .ok_or(OperationalStateMigrationError::InvalidReceipt)?;
            let name = path
                .file_name()
                .ok_or(OperationalStateMigrationError::InvalidReceipt)?;
            let parent = canonical_existing(parent, "canonicalize-receipt-parent")?;
            let guard = AnchoredDirectory::new(parent.clone())?;
            Ok((parent.join(name), guard))
        }
        Err(source) => Err(OperationalStateMigrationError::ReceiptIo {
            operation: "canonicalize-receipt",
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn validate_root_separation(
    assignment_path: &Path,
    assignment: &AnchoredDirectory,
    prepared_path: &Path,
    prepared: &AnchoredDirectory,
    receipt_path: &Path,
) -> Result<(), OperationalStateMigrationError> {
    let paths = [assignment_path, prepared_path, receipt_path];
    for (index, path) in paths.iter().enumerate() {
        if paths[index + 1..]
            .iter()
            .any(|other| path.starts_with(other) || other.starts_with(path))
        {
            return Err(OperationalStateMigrationError::InvalidReceipt);
        }
    }
    if assignment.identity() == prepared.identity() {
        return Err(OperationalStateMigrationError::InvalidReceipt);
    }
    if receipt_path.exists() {
        let receipt = AnchoredDirectory::new(receipt_path.to_owned())?;
        if receipt.identity() == assignment.identity() || receipt.identity() == prepared.identity()
        {
            return Err(OperationalStateMigrationError::InvalidReceipt);
        }
    }
    Ok(())
}

#[cfg(test)]
thread_local! {
    static ROOT_RACE_HOOK: std::cell::RefCell<Option<(usize, Box<dyn FnOnce()>)>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
fn install_root_race_hook(point: usize, hook: impl FnOnce() + 'static) {
    ROOT_RACE_HOOK.with(|slot| *slot.borrow_mut() = Some((point, Box::new(hook))));
}

#[cfg(test)]
fn run_root_race_hook() {
    ROOT_RACE_HOOK.with(|slot| {
        let mut pending = slot.borrow_mut();
        if pending.as_ref().is_some_and(|(point, _)| *point == 0) {
            if let Some((_, hook)) = pending.take() {
                hook();
            }
        } else if let Some((point, _)) = pending.as_mut() {
            *point -= 1;
        }
    });
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
            migrate_operational_state_inner(&config),
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

        let first = migrate_operational_state_inner(&config).expect("first migration");
        assert_eq!(first.receipt_id.len(), 64);
        assert!(ledger.path().join(receipt::ACTIVE_MARKER).exists());
        assert!(prepared.path().join(receipt::ACTIVE_MARKER).exists());
        let second = migrate_operational_state_inner(&config).expect("idempotent retry");
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
                migrate_operational_state_inner(&config),
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
            migrate_operational_state_inner(&config),
            Err(OperationalStateMigrationError::PreparedResult(
                PreparedResultJournalError::MigrationLimitExceeded
            ))
        ));
    }

    #[test]
    fn migration_rejects_equal_nested_and_alias_roots_before_mutation() {
        for kind in ["equal", "receipt-in-ledger", "receipt-in-prepared", "alias"] {
            let ledger = TempDir::new().expect("ledger");
            let prepared = TempDir::new().expect("prepared");
            let receipt_parent = TempDir::new().expect("receipt parent");
            let mut config = empty_config(&ledger, &prepared, &receipt_parent);
            match kind {
                "equal" => config.prepared_results = config.assignment_ledger.clone(),
                "receipt-in-ledger" => config.receipt = ledger.path().join("receipt"),
                "receipt-in-prepared" => config.receipt = prepared.path().join("receipt"),
                "alias" => {
                    let alias = receipt_parent.path().join("ledger-alias");
                    std::os::unix::fs::symlink(ledger.path(), &alias).expect("ledger alias");
                    config.receipt = alias;
                }
                _ => unreachable!(),
            }

            assert!(matches!(
                migrate_operational_state_inner(&config),
                Err(OperationalStateMigrationError::InvalidReceipt)
            ));
            assert!(!ledger.path().join(receipt::ACTIVE_MARKER).exists());
            assert!(!prepared.path().join(receipt::ACTIVE_MARKER).exists());

            config.receipt = receipt_parent.path().join("valid-receipt");
            config.prepared_results = prepared.path().canonicalize().expect("prepared path");
            migrate_operational_state_inner(&config).expect("retry with disjoint roots");
        }
    }

    #[test]
    fn migration_rejects_symlinked_operational_and_receipt_roots() {
        for kind in ["assignment", "prepared", "receipt", "dangling-receipt"] {
            let ledger = TempDir::new().expect("ledger");
            let prepared = TempDir::new().expect("prepared");
            let receipt_parent = TempDir::new().expect("receipt parent");
            let receipt_target = TempDir::new().expect("receipt target");
            let mut config = empty_config(&ledger, &prepared, &receipt_parent);
            let alias = receipt_parent.path().join(format!("{kind}-alias"));
            match kind {
                "assignment" => {
                    std::os::unix::fs::symlink(ledger.path(), &alias).expect("ledger symlink");
                    config.assignment_ledger = alias;
                }
                "prepared" => {
                    std::os::unix::fs::symlink(prepared.path(), &alias).expect("prepared symlink");
                    config.prepared_results = alias;
                }
                "receipt" => {
                    std::os::unix::fs::symlink(receipt_target.path(), &alias)
                        .expect("receipt symlink");
                    config.receipt = alias;
                }
                "dangling-receipt" => {
                    std::os::unix::fs::symlink("missing-receipt", &alias)
                        .expect("dangling receipt symlink");
                    config.receipt = alias;
                }
                _ => unreachable!(),
            }

            assert!(matches!(
                migrate_operational_state_inner(&config),
                Err(OperationalStateMigrationError::InvalidReceipt)
            ));
            assert!(!ledger.path().join(receipt::ACTIVE_MARKER).exists());
            assert!(!prepared.path().join(receipt::ACTIVE_MARKER).exists());
            assert!(
                fs::read_dir(receipt_target.path())
                    .expect("receipt target remains untouched")
                    .next()
                    .is_none()
            );
        }
    }

    #[test]
    fn absent_receipt_cannot_be_replaced_with_an_operational_root() {
        let ledger = TempDir::new().expect("ledger");
        let prepared = TempDir::new().expect("prepared");
        let receipt_parent = TempDir::new().expect("receipt parent");
        let config = empty_config(&ledger, &prepared, &receipt_parent);
        let original_ledger = ledger.path().to_owned();
        let raced_ledger = original_ledger.clone();
        let raced_receipt = config.receipt.clone();
        install_root_race_hook(0, move || {
            fs::rename(&raced_ledger, &raced_receipt).expect("move ledger to receipt path");
            fs::create_dir(&raced_ledger).expect("replace ledger path");
        });

        assert!(matches!(
            migrate_operational_state_inner(&config),
            Err(OperationalStateMigrationError::InvalidReceipt)
        ));
        assert!(!config.receipt.join(receipt::ACTIVE_MARKER).exists());
        assert!(!prepared.path().join(receipt::ACTIVE_MARKER).exists());

        fs::remove_dir(&original_ledger).expect("remove empty replacement");
        fs::rename(&config.receipt, &original_ledger).expect("restore ledger path");
        migrate_operational_state_inner(&config).expect("retry after restoring disjoint roots");
    }

    #[test]
    fn absent_receipt_parent_replacement_cannot_redirect_creation() {
        let ledger = TempDir::new().expect("ledger");
        let prepared = TempDir::new().expect("prepared");
        let receipt_parent = TempDir::new().expect("receipt parent");
        let nested_parent = receipt_parent.path().join("nested");
        fs::create_dir(&nested_parent).expect("nested receipt parent");
        let mut config = empty_config(&ledger, &prepared, &receipt_parent);
        config.receipt = nested_parent.join("receipt");
        let moved_parent = receipt_parent.path().join("moved-nested");
        let raced_parent = nested_parent.clone();
        let raced_moved = moved_parent.clone();
        let prepared_path = prepared.path().to_owned();
        install_root_race_hook(0, move || {
            fs::rename(&raced_parent, &raced_moved).expect("move receipt parent");
            std::os::unix::fs::symlink(&prepared_path, &raced_parent)
                .expect("redirect receipt parent");
        });

        assert!(matches!(
            migrate_operational_state_inner(&config),
            Err(OperationalStateMigrationError::DirectoryReplaced { .. })
        ));
        assert!(!prepared.path().join("receipt").exists());
        assert!(!ledger.path().join(receipt::ACTIVE_MARKER).exists());
        assert!(!prepared.path().join(receipt::ACTIVE_MARKER).exists());

        fs::remove_file(&nested_parent).expect("remove redirected parent");
        fs::rename(&moved_parent, &nested_parent).expect("restore receipt parent");
        migrate_operational_state_inner(&config).expect("retry with restored parent");
    }

    #[test]
    fn stopped_migration_admits_a_prior_runtime_owner_lock() {
        let ledger = TempDir::new().expect("ledger");
        let prepared = TempDir::new().expect("prepared");
        let receipt_parent = TempDir::new().expect("receipt parent");
        let config = empty_config(&ledger, &prepared, &receipt_parent);
        drop(
            crate::PreparedResultJournalNamespace::open(prepared.path())
                .expect("start and stop runtime namespace"),
        );

        migrate_operational_state_inner(&config).expect("migrate current state");
        assert!(prepared.path().join(".lock-runtime-owner").is_file());
    }

    #[test]
    fn active_runtime_owner_blocks_migration_before_markers() {
        let ledger = TempDir::new().expect("ledger");
        let prepared = TempDir::new().expect("prepared");
        let receipt_parent = TempDir::new().expect("receipt parent");
        let config = empty_config(&ledger, &prepared, &receipt_parent);
        let _runtime = crate::PreparedResultJournalNamespace::open(prepared.path())
            .expect("active runtime namespace");

        assert!(matches!(
            migrate_operational_state_inner(&config),
            Err(OperationalStateMigrationError::PreparedResult(
                PreparedResultJournalError::Io {
                    operation: "lock-journal-namespace",
                    ..
                }
            ))
        ));
        assert!(!ledger.path().join(receipt::ACTIVE_MARKER).exists());
        assert!(!prepared.path().join(receipt::ACTIVE_MARKER).exists());
    }

    #[test]
    fn migration_rejects_lock_replacement_before_marker_activation() {
        for kind in ["assignment", "prepared"] {
            let ledger = TempDir::new().expect("ledger");
            let prepared = TempDir::new().expect("prepared");
            let receipt_parent = TempDir::new().expect("receipt parent");
            let moved_parent = TempDir::new().expect("moved lock parent");
            let config = empty_config(&ledger, &prepared, &receipt_parent);
            let lock = if kind == "assignment" {
                ledger.path().join("writer.lock")
            } else {
                prepared.path().join(".lock-runtime-owner")
            };
            let moved = moved_parent.path().join("lock");
            install_root_race_hook(0, {
                let lock = lock.clone();
                let moved = moved.clone();
                move || {
                    fs::rename(&lock, &moved).expect("move migration lock");
                    fs::write(&lock, b"replacement").expect("replace migration lock");
                }
            });

            assert!(matches!(
                migrate_operational_state_inner(&config),
                Err(OperationalStateMigrationError::Assignment(_))
                    | Err(OperationalStateMigrationError::DirectoryReplaced { .. })
            ));
            assert!(!ledger.path().join(receipt::ACTIVE_MARKER).exists());
            assert!(!prepared.path().join(receipt::ACTIVE_MARKER).exists());

            fs::remove_file(&lock).expect("remove replacement lock");
            fs::rename(&moved, &lock).expect("restore migration lock");
            migrate_operational_state_inner(&config).expect("retry with restored lock");
        }
    }

    #[test]
    fn migration_rejects_operational_root_replacement_before_and_after_marker_completion() {
        for point in [1, 2] {
            let ledger = TempDir::new().expect("ledger");
            let prepared = TempDir::new().expect("prepared");
            let moved_parent = TempDir::new().expect("moved parent");
            let receipt_parent = TempDir::new().expect("receipt parent");
            let config = empty_config(&ledger, &prepared, &receipt_parent);
            let prepared_path = prepared.path().to_owned();
            let moved = moved_parent.path().join("prepared");
            let raced_prepared = prepared_path.clone();
            let raced_moved = moved.clone();
            install_root_race_hook(point, move || {
                fs::rename(&raced_prepared, &raced_moved).expect("move prepared root");
                fs::create_dir(&raced_prepared).expect("replace prepared root");
            });

            assert!(matches!(
                migrate_operational_state_inner(&config),
                Err(OperationalStateMigrationError::DirectoryReplaced { .. })
            ));
            fs::remove_dir(&prepared_path).expect("remove replacement root");
            fs::rename(&moved, &prepared_path).expect("restore prepared root");
            migrate_operational_state_inner(&config).expect("retry on restored root");
        }
    }

    #[test]
    fn migration_rejects_receipt_root_replacement_after_marker_completion() {
        let ledger = TempDir::new().expect("ledger");
        let prepared = TempDir::new().expect("prepared");
        let receipt_parent = TempDir::new().expect("receipt parent");
        let moved_parent = TempDir::new().expect("moved parent");
        let config = empty_config(&ledger, &prepared, &receipt_parent);
        let receipt = config.receipt.clone();
        let moved = moved_parent.path().join("receipt");
        let raced_receipt = receipt.clone();
        let raced_moved = moved.clone();
        install_root_race_hook(2, move || {
            fs::rename(&raced_receipt, &raced_moved).expect("move receipt root");
            fs::create_dir(&raced_receipt).expect("replace receipt root");
        });

        assert!(matches!(
            migrate_operational_state_inner(&config),
            Err(OperationalStateMigrationError::DirectoryReplaced { .. })
        ));
        fs::remove_dir(&receipt).expect("remove replacement receipt root");
        fs::rename(&moved, &receipt).expect("restore receipt root");
        migrate_operational_state_inner(&config).expect("retry on restored receipt root");
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
