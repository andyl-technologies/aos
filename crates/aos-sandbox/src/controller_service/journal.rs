//! Protected controller identity binding and journal resource limits.
//!
//! The journal binds a node before accepting current runtime assignments.
//! Existing nonempty unbound state cannot be migrated implicitly.
//!
//! ```text
//! ControllerIdentity["node"] = "AOSCNI01" || node_id[16]
//! ```

use crate::{
    Journal, JournalError, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace,
};
use aos_sandbox_core::{NodeId, OperationId};

const CONTROLLER_IDENTITY_KEY: &[u8] = b"node";
const CONTROLLER_IDENTITY_MAGIC: &[u8; 8] = b"AOSCNI01";
const MEBIBYTE: usize = 1024 * 1024;
const PRODUCTION_MAXIMUM_JOURNAL_BYTES: u64 = 256 * 1024 * 1024;
const PRODUCTION_MAXIMUM_MATERIALIZED_BYTES: usize = 128 * MEBIBYTE;
const PRODUCTION_MAXIMUM_TRANSACTIONS: usize = 65_536;
const PRODUCTION_MAXIMUM_MATERIALIZED_RECORDS: usize = 131_072;
#[cfg(test)]
const JOURNAL_NAME: &str = "controller.journal";

/// Reports invalid controller identity or protected journal state.
#[derive(Debug, thiserror::Error)]
pub enum ControllerJournalError {
    /// Existing state has no durable node binding.
    #[error("nonempty controller state has no durable node identity")]
    UnboundControllerIdentity,
    /// The durable binding is malformed or duplicated.
    #[error("durable controller node identity is invalid")]
    InvalidControllerIdentity,
    /// The configured node differs from the durable binding.
    #[error("configured node identity does not match durable controller state")]
    ControllerIdentityMismatch,
    /// Protected journal validation or persistence failed.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// A current assignment is invalid or belongs to another node.
    #[error(transparent)]
    RuntimeAuthority(#[from] crate::runtime_authority::RuntimeAuthorityError),
}

/// Binds the journal identity and validates all current node assignments.
///
/// # Errors
///
/// Rejects unbound nonempty state, malformed or mismatched identity, invalid
/// current assignments, or failed journal persistence.
pub fn validate_controller_journal(
    journal: &mut Journal,
    node_id: [u8; 16],
) -> Result<(), ControllerJournalError> {
    journal.ensure_protected_authority()?;
    if node_id == [0; 16] {
        return Err(ControllerJournalError::InvalidControllerIdentity);
    }

    bind_controller_identity(journal, node_id)?;
    crate::runtime_authority::RuntimeAuthorityStore::load(
        journal,
        crate::runtime_authority::RuntimeAuthorityLimits::default(),
    )?
    .validate_current_node(NodeId::from_bytes(node_id))
    .map_err(ControllerJournalError::from)
}

fn bind_controller_identity(
    journal: &mut Journal,
    node_id: [u8; 16],
) -> Result<(), ControllerJournalError> {
    let records = journal
        .records(RecordNamespace::ControllerIdentity)
        .map(|(key, value)| (key.to_vec(), value.to_vec()))
        .collect::<Vec<_>>();
    match records.as_slice() {
        [] => {
            if journal.all_records().next().is_some() {
                return Err(ControllerJournalError::UnboundControllerIdentity);
            }
            let mut value = Vec::with_capacity(CONTROLLER_IDENTITY_MAGIC.len() + node_id.len());
            value.extend_from_slice(CONTROLLER_IDENTITY_MAGIC);
            value.extend_from_slice(&node_id);
            let record = JournalRecord::put(
                RecordNamespace::ControllerIdentity,
                CONTROLLER_IDENTITY_KEY.to_vec(),
                value,
            );
            let transaction =
                JournalTransaction::new(OperationId::new().into_bytes(), vec![record])?;
            journal.commit(&transaction)?;
            Ok(())
        }
        [(key, value)]
            if key.as_slice() == CONTROLLER_IDENTITY_KEY
                && value.len() == CONTROLLER_IDENTITY_MAGIC.len() + node_id.len()
                && value.starts_with(CONTROLLER_IDENTITY_MAGIC) =>
        {
            if value[CONTROLLER_IDENTITY_MAGIC.len()..] != node_id {
                return Err(ControllerJournalError::ControllerIdentityMismatch);
            }
            Ok(())
        }
        _ => Err(ControllerJournalError::InvalidControllerIdentity),
    }
}

/// Returns the bounded production controller journal configuration.
#[must_use]
pub fn production_journal_limits() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: PRODUCTION_MAXIMUM_JOURNAL_BYTES,
        maximum_record_bytes: 16 * MEBIBYTE,
        maximum_key_bytes: 1024,
        maximum_records_per_transaction: 4096,
        maximum_transaction_bytes: 64 * MEBIBYTE,
        maximum_transactions: PRODUCTION_MAXIMUM_TRANSACTIONS,
        maximum_materialized_bytes: PRODUCTION_MAXIMUM_MATERIALIZED_BYTES,
        maximum_materialized_records: PRODUCTION_MAXIMUM_MATERIALIZED_RECORDS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn validate_test_journal(
        mut journal: Journal,
        node_id: [u8; 16],
    ) -> Result<Journal, ControllerJournalError> {
        validate_controller_journal(&mut journal, node_id)?;
        Ok(journal)
    }

    fn protected_test_journal(directory: &tempfile::TempDir, limits: JournalLimits) -> Journal {
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        Journal::open_protected_at_uid(
            directory.path(),
            JOURNAL_NAME,
            limits,
            rustix::process::getuid().as_raw(),
        )
        .unwrap()
        .0
    }

    #[test]
    fn invalid_node_identity_does_not_bind_empty_state() {
        let directory = tempfile::tempdir().unwrap();
        let mut journal = protected_test_journal(&directory, production_journal_limits());

        assert!(matches!(
            validate_controller_journal(&mut journal, [0; 16]),
            Err(ControllerJournalError::InvalidControllerIdentity)
        ));
        assert_eq!(journal.all_records().count(), 0);
    }

    #[test]
    fn protected_controller_recovery_retains_its_node_binding() {
        let directory = tempfile::tempdir().unwrap();
        let journal = protected_test_journal(&directory, production_journal_limits());
        let controller = validate_test_journal(journal, [7; 16]).unwrap();
        drop(controller);
        let before = std::fs::read(directory.path().join(JOURNAL_NAME)).unwrap();

        let journal = protected_test_journal(&directory, production_journal_limits());
        let controller = validate_test_journal(journal, [7; 16]).unwrap();
        drop(controller);

        assert_eq!(
            std::fs::read(directory.path().join(JOURNAL_NAME)).unwrap(),
            before
        );
    }

    #[test]
    fn durable_first_bind_is_idempotent_after_an_ambiguous_process_exit() {
        let directory = tempfile::tempdir().unwrap();
        let mut journal = protected_test_journal(&directory, production_journal_limits());
        bind_controller_identity(&mut journal, [7; 16]).unwrap();
        let before = std::fs::read(directory.path().join(JOURNAL_NAME)).unwrap();
        drop(journal);

        let mut journal = protected_test_journal(&directory, production_journal_limits());
        bind_controller_identity(&mut journal, [7; 16]).unwrap();

        assert_eq!(
            journal.records(RecordNamespace::ControllerIdentity).count(),
            1
        );
        assert_eq!(
            std::fs::read(directory.path().join(JOURNAL_NAME)).unwrap(),
            before
        );
    }

    #[test]
    fn unbound_preexisting_state_has_no_automatic_identity_migration() {
        let directory = tempfile::tempdir().unwrap();
        let mut journal = protected_test_journal(&directory, production_journal_limits());
        let transaction = JournalTransaction::new(
            OperationId::from_bytes([9; 16]).into_bytes(),
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                vec![1],
                vec![2],
            )],
        )
        .unwrap();
        journal.commit(&transaction).unwrap();
        let before = std::fs::read(directory.path().join(JOURNAL_NAME)).unwrap();
        drop(journal);

        let journal = protected_test_journal(&directory, production_journal_limits());
        assert!(matches!(
            validate_test_journal(journal, [7; 16]),
            Err(ControllerJournalError::UnboundControllerIdentity)
        ));

        assert_eq!(
            std::fs::read(directory.path().join(JOURNAL_NAME)).unwrap(),
            before
        );
    }

    #[test]
    fn protected_controller_rejects_a_different_node_without_changing_state() {
        let directory = tempfile::tempdir().unwrap();
        let journal = protected_test_journal(&directory, production_journal_limits());
        let controller = validate_test_journal(journal, [7; 16]).unwrap();
        drop(controller);
        let before = std::fs::read(directory.path().join(JOURNAL_NAME)).unwrap();

        let journal = protected_test_journal(&directory, production_journal_limits());
        assert!(matches!(
            validate_test_journal(journal, [8; 16]),
            Err(ControllerJournalError::ControllerIdentityMismatch)
        ));

        assert_eq!(
            std::fs::read(directory.path().join(JOURNAL_NAME)).unwrap(),
            before
        );
    }

    #[test]
    fn production_journal_limits_fit_the_service_memory_budget() {
        let limits = production_journal_limits();

        assert_eq!(limits.maximum_journal_bytes, 256 * 1024 * 1024);
        assert_eq!(limits.maximum_materialized_bytes, 128 * MEBIBYTE);
        assert!(
            limits.maximum_journal_bytes
                + u64::try_from(limits.maximum_materialized_bytes).unwrap()
                < 512 * 1024 * 1024
        );
        assert_eq!(limits.maximum_transactions, 65_536);
        assert_eq!(limits.maximum_materialized_records, 131_072);
    }

    #[test]
    fn production_journal_rejects_a_sparse_file_above_its_limit() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join(JOURNAL_NAME);
        let file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.set_len(PRODUCTION_MAXIMUM_JOURNAL_BYTES + 1).unwrap();
        drop(file);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        assert!(matches!(
            Journal::open_protected_at_uid(
                directory.path(),
                JOURNAL_NAME,
                production_journal_limits(),
                rustix::process::getuid().as_raw(),
            ),
            Err(JournalError::JournalTooLarge)
        ));
    }
}
