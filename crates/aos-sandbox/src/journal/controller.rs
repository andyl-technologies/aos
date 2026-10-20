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
use aos_sandbox_broker::controller_receiving::bank_launch::{
    ControllerBankLaunchErrorV1, ControllerCoordinatorWriterV1,
};
use aos_sandbox_journal::protected_storage::FileIdentity;
use aos_sandbox_ledger_replay::cold::ColdReplayOriginalV1;

use super::semantic_remainder::ColdSemanticRemainderOriginalV1;

const CONTROLLER_IDENTITY_KEY: &[u8] = b"node";
const CONTROLLER_IDENTITY_MAGIC: &[u8; 8] = b"AOSCNI01";
const MEBIBYTE: usize = 1024 * 1024;
const PRODUCTION_MAXIMUM_JOURNAL_BYTES: u64 = 256 * 1024 * 1024;
const PRODUCTION_MAXIMUM_MATERIALIZED_BYTES: usize = 128 * MEBIBYTE;
const PRODUCTION_MAXIMUM_TRANSACTIONS: usize = 65_536;
const PRODUCTION_MAXIMUM_MATERIALIZED_RECORDS: usize = 131_072;
#[cfg(test)]
const JOURNAL_NAME: &str = "controller.journal";

/// Retains the genuine fixed C opening, semantic replay and independent posts.
///
/// The actual paired Bank preopen loan is required. Native acquisition and the
/// sole upper semantic replay run on the same held file. Identity binding and
/// current-assignment checks keep their existing semantic order afterward.
pub struct ControllerJournalConstructionV1 {
    opening: Option<aos_sandbox_broker::controller_receiving::bank_launch::ControllerWriterOpeningOriginalV1>,
    opening_result: Option<Result<(), aos_sandbox_broker::controller_receiving::bank_launch::ControllerBankLaunchErrorV1>>,
    semantic: ColdReplayOriginalV1<ControllerBankLaunchErrorV1>,
    semantic_entry: Option<Result<(), ControllerBankLaunchErrorV1>>,
    semantic_identity: Option<Result<FileIdentity, ControllerBankLaunchErrorV1>>,
    conversion: ColdSemanticRemainderOriginalV1,
    coordinator: Option<ControllerCoordinatorWriterV1<super::native_backing::Selection>>,
    semantic_result: Option<Result<(), ()>>,
    native_installation: Option<Result<(), aos_sandbox_broker::controller_receiving::bank_launch::ControllerBankLaunchErrorV1>>,
    journal: Option<Journal>,
    before: Option<crate::controller_resource_reservation::ControllerResourcePreopenPostV1>,
    post: Option<crate::controller_resource_reservation::ControllerResourcePreopenPostV1>,
    node: Option<Result<(), crate::controller_resource_reservation::ResourceReservationErrorV1>>,
    representation: Option<Result<aos_sandbox_core::ResourceVector, JournalError>>,
    protected: Option<Result<(), JournalError>>,
    identity: ControllerIdentityOriginalsV1,
    identity_result: Option<Result<(), ControllerJournalError>>,
    authority: Option<Result<(), crate::runtime_authority::RuntimeAuthorityError>>,
    assignments: Option<Result<(), crate::runtime_authority::RuntimeAuthorityError>>,
    native_post: Option<aos_sandbox_broker::controller_receiving::bank_launch::ControllerNativePostOriginalV1>,
    native_post_entry: Option<Result<(), JournalError>>,
    names_post: Option<Result<(), JournalError>>,
    disposition: Option<Result<(), JournalError>>,
    traversal_disposition: Option<Result<(), JournalError>>,
    existing_only: bool,
    existing_node: Option<[u8; 16]>,
    existing_validation: Option<Result<(), ControllerJournalError>>,
    attempted: bool,
    finished: bool,
}

impl ControllerJournalConstructionV1 {
    /// Prearms only empty destinations; no file or receiving account is opened.
    #[must_use]
    pub fn new() -> Self {
        Self {
            opening: None, opening_result: None,
            semantic: ColdReplayOriginalV1::new(), semantic_entry: None, semantic_identity: None,
            conversion: ColdSemanticRemainderOriginalV1::new(), coordinator: None,
            semantic_result: None, native_installation: None, journal: None,
            before: None, post: None, node: None, representation: None,
            protected: None,
            identity: ControllerIdentityOriginalsV1 { transaction: None, native: None },
            identity_result: None, authority: None, assignments: None,
            native_post: None, native_post_entry: None, names_post: None, disposition: None, traversal_disposition: None,
            existing_only: false, existing_node: None, existing_validation: None,
            attempted: false, finished: false,
        }
    }

    fn representation_demand_v1() -> Result<aos_sandbox_core::ResourceVector, JournalError> {
        use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
        use aos_sandbox_broker::controller_receiving::bank_launch::ControllerNativePostOriginalV1;

        let invalid = || JournalError::LimitExceeded("Controller constructor representation");
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(4 * std::mem::size_of::<usize>()))
            .ok_or_else(invalid)?;
        let post = ControllerNativePostOriginalV1::receiving_demand_v1()
            .map_err(|_| JournalError::ProtectedBoundary)?;
        ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| invalid())?)
            .checked_add(post)?
            .checked_add(ColdReplayOriginalV1::<ControllerBankLaunchErrorV1>::fixed_demand_v1()?)?
            .checked_add(ColdSemanticRemainderOriginalV1::receiving_demand_v1()?)
            .map_err(JournalError::ReceivingAccounting)
    }

    /// Opens only the original fixed Controller writer under the actual loan.
    ///
    /// # Errors
    /// Retains the real native acquisition/replay or semantic failure. All
    /// reached writers and typed prefixes remain owned through later posts.
    pub fn open_once(
        &mut self,
        loan: &crate::controller_resource_reservation::ControllerResourcePreopenLoanV1<'_>,
        directory: &std::path::Path,
        uid: u32,
        node: [u8; 16],
    ) -> Result<(), ()> {
        self.open_with_recipe_once(loan, directory, uid, node, false)
    }

    /// Opens fixed Controller state without creating or initializing it.
    ///
    /// The same paired C is required. No missing file, partial tail or empty
    /// history can be initialized as an administrative side effect.
    ///
    /// # Errors
    /// Retains the actual acquisition, replay, identity or independent post debt.
    pub fn open_existing_once(
        &mut self,
        loan: &crate::controller_resource_reservation::ControllerResourcePreopenLoanV1<'_>,
        directory: &std::path::Path,
        uid: u32,
        node: [u8; 16],
    ) -> Result<(), ()> {
        self.open_with_recipe_once(loan, directory, uid, node, true)
    }

    fn open_with_recipe_once(
        &mut self,
        loan: &crate::controller_resource_reservation::ControllerResourcePreopenLoanV1<'_>,
        directory: &std::path::Path,
        uid: u32,
        node: [u8; 16],
        existing_only: bool,
    ) -> Result<(), ()> {
        if self.attempted { return Err(()); }
        self.attempted = true;
        self.existing_only = existing_only;
        self.before = Some(crate::controller_resource_reservation::ControllerResourcePreopenPostV1::new());
        loan.observe_into(self.before.as_mut().ok_or(())?);
        self.before.as_ref().ok_or(())?.require_success().map_err(|_| ())?;
        self.node = Some(loan.require_fixed_controller_recipe_v1(directory, uid, node));
        if !matches!(self.node, Some(Ok(()))) { return Err(()); }
        self.existing_node = Some(node);

        self.opening = Some(loan.take_fixed_controller_opening_once_v1().map_err(|_| ())?);
        let opening = self.opening.as_mut().ok_or(())?;
        self.opening_result = Some(if existing_only {
            opening.prepare_existing_once(loan.lower_profile_v1(), node)
        } else { opening.prepare_once(loan.lower_profile_v1(), node) });
        if !matches!(self.opening_result, Some(Ok(()))) { return Err(()); }
        self.representation = Some(Self::representation_demand_v1());
        let demand = self.representation.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or(())?;
        self.semantic_entry = Some(opening.debit_semantic_representation_v1(demand));
        if !matches!(self.semantic_entry, Some(Ok(()))) {
            return Err(());
        }
        self.semantic_identity = Some(opening.prepare_semantic_identity_once());
        let identity = self.semantic_identity.as_ref()
            .and_then(|result| result.as_ref().ok()).copied().ok_or(())?;
        let limits = opening.fixed_limits();

        {
            let mut cursor = match opening.begin_replay_once() {
                Ok(cursor) => cursor,
                Err(cause) => {
                    self.semantic_entry = Some(Err(cause));
                    return Err(());
                }
            };
            self.semantic_result = Some(self.semantic
                .observe_controller_once(&mut cursor, identity, limits).map_err(|_| ()));
        }
        if !matches!(self.semantic_result, Some(Ok(()))) { return Err(()); }

        self.conversion.observe_once(&mut self.semantic.take_remainder_once());
        if !self.conversion.ready() {
            return Err(());
        }

        let selection = super::runtime_deployment_history::OriginalCompactionSelectionV1::capture(
            directory, "controller.journal",
        );
        self.coordinator = Some(match opening.take_coordinator_after_semantic_replay_once(selection) {
            Ok(coordinator) => coordinator,
            Err(cause) => {
                self.native_installation = Some(Err(cause));
                return Err(());
            }
        });
        self.native_installation = Some(Ok(()));
        let inputs = (self.coordinator.take(), self.conversion.take_once());
        let (coordinator, semantic) = match inputs {
            (Some(coordinator), Some(semantic)) => (coordinator, semantic),
            (coordinator, semantic) => {
                self.coordinator = coordinator;
                self.conversion.restore_unmoved(semantic);
                return Err(());
            }
        };
        // This actual authority marker is allocated only after the same C's
        // complete constructor debit, at the original post-replay frontier.
        let authority = std::sync::Arc::new(super::JournalAuthorityInstance);
        self.journal = Some(Journal::from_controller_coordinator_v1(coordinator, semantic, authority));
        let journal = self.journal.as_mut().ok_or(())?;
        self.native_post_entry = Some(match journal.controller_coordinator_for_bank_v1() {
            Ok(writer) => match writer.begin_independent_native_post_once() {
                Ok(post) => { self.native_post = Some(post); Ok(()) }
                Err(_) => Err(JournalError::ProtectedBoundary),
            },
            Err(cause) => Err(cause),
        });
        if !matches!(self.native_post_entry, Some(Ok(()))) { return Err(()); }
        self.protected = Some(journal.ensure_protected_authority());
        if !matches!(self.protected, Some(Ok(()))) { return Err(()); }

        // Issue-only preserves its original Controller-open, Source-open,
        // then Controller-identity validation frontier. No validator is
        // duplicated and no supplied success value completes that stage.
        if existing_only { return Ok(()); }

        self.identity_result = Some(if node == [0; 16] {
            Err(ControllerJournalError::InvalidControllerIdentity)
        } else {
            bind_controller_identity_with_originals(journal, node, Some(&mut self.identity))
        });
        if !matches!(self.identity_result, Some(Ok(()))) { return Err(()); }
        let authority = crate::runtime_authority::RuntimeAuthorityStore::load(
            journal, crate::runtime_authority::RuntimeAuthorityLimits::default(),
        );
        match authority {
            Ok(authority) => {
                self.assignments = Some(authority.validate_current_node(NodeId::from_bytes(node)));
                self.authority = Some(Ok(()));
            }
            Err(cause) => self.authority = Some(Err(cause)),
        }
        if !matches!(self.assignments, Some(Ok(()))) { return Err(()); }
        Ok(())
    }

    /// Validates the same existing Controller after actual Source acquisition.
    ///
    /// The node is retained from the original recipe join. This executes the
    /// existing Controller validator itself and grants no Source completion.
    ///
    /// # Errors
    /// Retains empty/mismatched history or the original current-assignment cause.
    #[doc(hidden)]
    pub fn validate_existing_after_source_once(&mut self) -> Result<(), ()> {
        if !self.existing_only || self.existing_validation.is_some() || self.finished
            || self.primary_failure().is_some()
        { return Err(()); }
        let node = self.existing_node.ok_or(())?;
        let journal = self.journal.as_mut().ok_or(())?;
        self.existing_validation = Some(if journal.all_records().next().is_none() {
            // The normal identity binder intentionally initializes empty state.
            // Issue-only refuses before reaching that mutating branch.
            Err(ControllerJournalError::InvalidControllerIdentity)
        } else { validate_controller_journal(journal, node) });
        if matches!(self.existing_validation, Some(Ok(()))) { Ok(()) } else { Err(()) }
    }

    fn completed_identity_admission(&self) -> bool {
        if self.existing_only {
            matches!(self.existing_validation, Some(Ok(())))
        } else { matches!(self.assignments, Some(Ok(()))) }
    }

    /// Attempts actual already-owed names and independent C/profile posts.
    ///
    /// # Errors
    /// Refuses repeat, any primary error or independent post debt. The same
    /// native post bypasses fresh health reentry after an ambiguous append.
    pub fn finish_posts(
        &mut self,
        loan: &crate::controller_resource_reservation::ControllerResourcePreopenLoanV1<'_>,
    ) -> Result<(), ()> {
        if self.finished { return Err(()); }
        self.finished = true;
        if let (Some(journal), Some(post)) = (self.journal.as_mut(), self.native_post.as_mut()) {
            self.names_post = Some(journal.controller_coordinator_for_bank_v1()
                .and_then(|writer| writer.finish_independent_native_post_once(post)
                    .map_err(|_| JournalError::ProtectedBoundary)));
        }
        // Independent profile work remains owed even if native names failed.
        self.post = Some(crate::controller_resource_reservation::ControllerResourcePreopenPostV1::new());
        loan.observe_controller_post_into(self.post.as_mut().ok_or(())?);
        if self.failure().is_some() || !self.completed_identity_admission() { return Err(()); }
        self.post.as_ref().ok_or(())?.require_success().map_err(|_| ())?;
        if let (Some(journal), Some(post)) = (self.journal.as_mut(), self.native_post.as_mut()) {
            self.disposition = Some(journal.controller_coordinator_for_bank_v1()
                .and_then(|writer| writer.dispose_native_post_after_upper_posts_once(post)
                    .map_err(|_| JournalError::ProtectedBoundary)));
        }
        if !matches!(self.disposition, Some(Ok(()))) { return Err(()); }
        self.traversal_disposition = Some((|| {
            let opening = self.opening.as_mut().ok_or(JournalError::ProtectedBoundary)?;
            let journal = self.journal.as_mut().ok_or(JournalError::ProtectedBoundary)?;
            let post = self.native_post.as_ref().ok_or(JournalError::ProtectedBoundary)?;
            let writer = journal.controller_coordinator_for_bank_v1()?;
            opening.retire_completed_traversal_after_upper_posts_once_v1(writer, post)
                .map_err(|_| JournalError::ProtectedBoundary)
        })());
        if matches!(self.traversal_disposition, Some(Ok(()))) { Ok(()) } else { Err(()) }
    }

    /// Borrows the same staged writer after its actual constructor checks.
    #[must_use]
    pub fn journal_mut(&mut self) -> Option<&mut Journal> {
        if self.failure().is_some() || !self.completed_identity_admission() { return None; }
        self.journal.as_mut()
    }

    /// Moves the same writer after all real native/profile posts and disposal.
    #[must_use]
    pub fn take_journal(&mut self) -> Option<Journal> {
        if !self.finished || self.failure().is_some()
            || !self.completed_identity_admission()
            || !matches!(self.disposition, Some(Ok(())))
            || !matches!(self.traversal_disposition, Some(Ok(())))
        { return None; }
        self.journal.take()
    }

    /// Borrows the earliest retained actual constructor or independent debt.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.primary_failure().or_else(|| self.postcheck_debt())
    }

    /// Borrows the actual primary failure independently of later owed posts.
    #[must_use]
    pub fn primary_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.before.as_ref().and_then(|post| post.failure())
            .or_else(|| retained_constructor_error(&self.node))
            .or_else(|| self.opening.as_ref().and_then(|opening| opening.failure()))
            .or_else(|| retained_constructor_error(&self.opening_result))
            .or_else(|| retained_constructor_error(&self.representation))
            .or_else(|| retained_constructor_error(&self.semantic_identity))
            .or_else(|| retained_constructor_error(&self.semantic_entry))
            .or_else(|| self.semantic.failure())
            .or_else(|| self.conversion.failure())
            .or_else(|| retained_constructor_error(&self.native_installation))
            .or_else(|| retained_constructor_error(&self.native_post_entry))
            .or_else(|| retained_constructor_error(&self.protected))
            .or_else(|| retained_constructor_error(&self.identity.native))
            .or_else(|| retained_constructor_error(&self.identity_result))
            .or_else(|| retained_constructor_error(&self.authority))
            .or_else(|| retained_constructor_error(&self.assignments))
            .or_else(|| retained_constructor_error(&self.existing_validation))
    }

    /// Borrows separately retained native-name and original-profile debt.
    #[must_use]
    pub fn postcheck_debt(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.native_post.as_ref().and_then(|post| post.failure())
            .or_else(|| retained_constructor_error(&self.names_post))
            .or_else(|| self.post.as_ref().and_then(|post| post.failure()))
            .or_else(|| retained_constructor_error(&self.disposition))
            .or_else(|| retained_constructor_error(&self.traversal_disposition))
    }
}

fn retained_constructor_error<T, E: std::error::Error + 'static>(
    returned: &Option<Result<T, E>>,
) -> Option<&(dyn std::error::Error + 'static)> {
    returned.as_ref()?.as_ref().err().map(|cause| cause as _)
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
