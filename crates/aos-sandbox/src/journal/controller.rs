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

/// Retains the paid Controller opening, identity commit and independent posts.
///
/// A pre-opening bootstrap loan is mandatory. This owner creates no operation
/// or read permit and cannot recover unreturned nested executor/RPC originals.
pub struct ControllerJournalConstructionV1 {
    opening: crate::journal::ControllerJournalOpenOriginalsV1,
    before: Option<crate::controller_resource_reservation::ControllerResourcePreopenPostV1>,
    post: Option<crate::controller_resource_reservation::ControllerResourcePreopenPostV1>,
    node: Option<Result<(), crate::controller_resource_reservation::ResourceReservationErrorV1>>,
    protected: Option<Result<(), JournalError>>,
    identity: ControllerIdentityOriginalsV1,
    identity_result: Option<Result<(), ControllerJournalError>>,
    authority: Option<Result<(), crate::runtime_authority::RuntimeAuthorityError>>,
    assignments: Option<Result<(), crate::runtime_authority::RuntimeAuthorityError>>,
    names_post: Option<Result<(), JournalError>>,
    attempted: bool,
    finished: bool,
}

impl ControllerJournalConstructionV1 {
    /// Prearms a vacant destination without opening files or observing authority.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            opening: crate::journal::ControllerJournalOpenOriginalsV1::new(),
            before: None,
            post: None,
            node: None,
            protected: None,
            identity: ControllerIdentityOriginalsV1 { transaction: None, native: None },
            identity_result: None,
            authority: None,
            assignments: None,
            names_post: None,
            attempted: false,
            finished: false,
        }
    }

    /// Opens and binds the same protected Controller writer once under its payer.
    ///
    /// The report is resident before any of its fields are observed. A failed
    /// native result stays in the exact stage and no failed phase is retried.
    ///
    /// # Errors
    /// Returns a negative disposition on failed original currentness, node,
    /// protected opening, identity persistence or current assignment validation.
    /// The original cause remains available through `failure`.
    pub fn open_once(
        &mut self,
        loan: &crate::controller_resource_reservation::ControllerResourcePreopenLoanV1<'_>,
        directory: &std::path::Path,
        uid: u32,
        node: [u8; 16],
    ) -> Result<(), ()> {
        if self.attempted {
            return Err(());
        }
        self.attempted = true;
        self.before = Some(crate::controller_resource_reservation::ControllerResourcePreopenPostV1::new());
        loan.observe_into(self.before.as_mut().ok_or(())?);
        self.before.as_ref().ok_or(())?.require_success().map_err(|_| ())?;
        self.node = Some(loan.require_node(node));
        if !matches!(self.node, Some(Ok(()))) {
            return Err(());
        }
        self.opening.open_once(directory, "controller.journal", production_journal_limits(), uid);
        let journal = self.opening.journal_mut().ok_or(())?;
        self.protected = Some(journal.ensure_protected_authority());
        if !matches!(self.protected, Some(Ok(()))) {
            return Err(());
        }
        self.identity_result = Some(if node == [0; 16] {
            Err(ControllerJournalError::InvalidControllerIdentity)
        } else {
            bind_controller_identity_with_originals(journal, node, Some(&mut self.identity))
        });
        if !matches!(self.identity_result, Some(Ok(()))) {
            return Err(());
        }
        let authority = crate::runtime_authority::RuntimeAuthorityStore::load(
            journal, crate::runtime_authority::RuntimeAuthorityLimits::default(),
        );
        // The whole returned borrow stays local through validation. Ending an
        // Ok short borrow retains its actual writer and only Copy counters;
        // an Err is moved into its owning field before any independent post.
        match authority {
            Ok(authority) => {
                self.assignments = Some(authority.validate_current_node(NodeId::from_bytes(node)));
                self.authority = Some(Ok(()));
            }
            Err(cause) => self.authority = Some(Err(cause)),
        }
        if !matches!(self.assignments, Some(Ok(()))) {
            return Err(());
        }
        Ok(())
    }

    /// Retains independent native-name and original-profile posts even after Err.
    ///
    /// # Errors
    /// Rejects repeated completion, earlier failure or any post debt. Native
    /// name validation is attempted whenever a completed writer exists.
    pub fn finish_posts(
        &mut self,
        loan: &crate::controller_resource_reservation::ControllerResourcePreopenLoanV1<'_>,
    ) -> Result<(), ()> {
        if self.finished {
            return Err(());
        }
        self.finished = true;
        if let Some(journal) = self.opening.journal_mut() {
            self.names_post = Some(journal.validate_held_protected_names());
        }
        self.post = Some(crate::controller_resource_reservation::ControllerResourcePreopenPostV1::new());
        loan.observe_into(self.post.as_mut().ok_or(())?);
        if self.failure().is_some() || !matches!(self.assignments, Some(Ok(()))) {
            return Err(());
        }
        self.post.as_ref().ok_or(())?.require_success().map_err(|_| ())
    }

    /// Borrows the actual staged writer for the fixed installed constructor.
    ///
    /// This does not bypass any namespace or effect authority guard.
    #[must_use]
    pub fn journal_mut(&mut self) -> Option<&mut Journal> {
        if self.failure().is_some() || !matches!(self.assignments, Some(Ok(()))) {
            return None;
        }
        self.opening.journal_mut()
    }

    /// Moves the actual writer only after successful construction and posts.
    #[must_use]
    pub fn take_journal(&mut self) -> Option<Journal> {
        if !self.finished || self.failure().is_some()
            || !matches!(self.assignments, Some(Ok(())))
        {
            return None;
        }
        self.opening.take_journal()
    }

    /// Borrows the first original construction failure without taking custody.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.primary_failure().or_else(|| self.postcheck_debt())
    }

    /// Borrows a construction cause independently of later negative posts.
    #[must_use]
    pub fn primary_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.before.as_ref().and_then(|post| post.failure())
            .or_else(|| self.node.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.opening.failure())
            .or_else(|| self.protected.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.identity.native.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.identity_result.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.authority.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.assignments.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
    }

    /// Borrows separately retained later native-name/profile debt.
    #[must_use]
    pub fn postcheck_debt(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.names_post.as_ref().and_then(|result| result.as_ref().err())
            .map(|error| error as &(dyn std::error::Error + 'static))
            .or_else(|| self.post.as_ref().and_then(|post| post.failure()))
    }
}

struct ControllerIdentityOriginalsV1 {
    transaction: Option<JournalTransaction>,
    native: Option<Result<crate::journal::CommitResult, JournalError>>,
}

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
    bind_controller_identity_with_originals(journal, node_id, None)
}

fn bind_controller_identity_with_originals(
    journal: &mut Journal,
    node_id: [u8; 16],
    originals: Option<&mut ControllerIdentityOriginalsV1>,
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
                JournalTransaction::new(OperationId::new().into_bytes(), vec![record])
                    .map_err(JournalError::from)?;
            match originals {
                None => { journal.commit(&transaction)?; }
                Some(originals) => {
                    originals.transaction = Some(transaction);
                    let transaction = originals.transaction.as_ref()
                        .ok_or(ControllerJournalError::InvalidControllerIdentity)?;
                    originals.native = Some(journal.commit(transaction));
                    if !matches!(originals.native, Some(Ok(_))) {
                        return Err(ControllerJournalError::Journal(JournalError::ProtectedBoundary));
                    }
                }
            }
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
