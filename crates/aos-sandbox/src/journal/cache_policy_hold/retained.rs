//! Original Cache mutation interlock retained across one owner cut.
//!
//! This deny-only value owns an existing gate writer, never releases a policy
//! hold, and grants no Read or Root authority. Dropping it is not disposition.

use std::{path::PathBuf, sync::Arc};

use super::super::{
    Journal, JournalAuthorityInstance, JournalError, JournalLimits, JournalTransaction,
    ProtectedWriterNameWitness,
};
use super::{CachePolicyHoldStateV1, NAME, current_state, hold_limits, mutation_guard};

struct RetainedCacheTargetV1 {
    name: &'static str,
    instance: Arc<JournalAuthorityInstance>,
    limits: JournalLimits,
    sequence: u64,
    witness: ProtectedWriterNameWitness,
    own_append: Option<(u64, u64, [u8; 32], u64)>,
}

/// Owns the original existing interlock, not a policy or effect capability.
pub(crate) struct HeldCacheMutationGateV1 {
    gate: Journal,
    checks: RetainedCacheGateChecksV1,
}

/// Borrows the already resident interlock without opening another writer.
pub(crate) struct BorrowedCacheMutationGateV1<'hold> {
    gate: &'hold mut Journal,
    checks: RetainedCacheGateChecksV1,
}

// Both dispositions use exactly the same original-name and own-append checks.
pub(crate) struct RetainedCacheGateChecksV1 {
    directory: PathBuf,
    uid: u32,
    gate_witness: ProtectedWriterNameWitness,
    gate_sequence: u64,
    state: CachePolicyHoldStateV1,
    targets: [RetainedCacheTargetV1; 2],
}

/// Selects ordinary acquisition or a borrowed original interlock.
pub(crate) enum CacheMutationGateV1<'held> {
    Ordinary,
    Retained(&'held mut HeldCacheMutationGateV1),
    Resident(&'held mut Journal, &'held mut RetainedCacheGateChecksV1),
}

impl CacheMutationGateV1<'_> {
    /// Simulates ordinary bounds using the selected original interlock.
    ///
    /// # Errors
    /// Returns the unchanged Journal validation or retained-name refusal.
    pub(crate) fn preflight(
        &mut self,
        journal: &Journal,
        transactions: &[JournalTransaction],
    ) -> Result<(), JournalError> {
        match self {
            Self::Ordinary => journal.preflight_transactions(transactions),
            Self::Retained(gate) => {
                journal.preflight_with_retained_cache_gate_v1(transactions, gate)
            }
            Self::Resident(_, _) => {
                journal.preflight_with_original_cache_gate_v1(transactions, self.reborrow())
            }
        }
    }

    /// Appends through the existing Journal engine, retaining the selected gate.
    ///
    /// # Errors
    /// Returns validation or ambiguous append errors; no error grants release.
    pub(crate) fn commit(
        &mut self,
        journal: &mut Journal,
        transaction: &JournalTransaction,
    ) -> Result<super::super::CommitResult, JournalError> {
        match self {
            Self::Ordinary => journal.commit(transaction),
            Self::Retained(gate) => journal.commit_with_retained_cache_gate_v1(transaction, gate),
            Self::Resident(_, _) => {
                journal.commit_with_original_cache_gate_v1(transaction, self.reborrow())
            }
        }
    }

    pub(in crate::journal) fn check(&mut self, target: &Journal) -> Result<(), JournalError> {
        match self {
            Self::Ordinary => super::check_unheld(target),
            Self::Retained(gate) => gate.require_for_target(target),
            Self::Resident(gate, checks) => checks.require_for_target(gate, target),
        }
    }

    pub(in crate::journal) fn before_append(
        &mut self,
        target: &Journal,
    ) -> Result<Option<Journal>, JournalError> {
        match self {
            Self::Ordinary => mutation_guard(target),
            Self::Retained(gate) => {
                gate.require_for_target(target)?;
                Ok(None)
            }
            Self::Resident(gate, checks) => {
                checks.require_for_target(gate, target)?;
                Ok(None)
            }
        }
    }

    pub(in crate::journal) fn own_successor(
        &mut self,
        target: &Journal,
        transaction: &JournalTransaction,
        sequence: u64,
        length: u64,
    ) -> Result<(), JournalError> {
        match self {
            Self::Ordinary => Ok(()),
            Self::Retained(gate) => gate.own_successor(target, transaction, sequence, length),
            Self::Resident(gate, checks) => {
                checks.own_successor(gate, target, transaction, sequence, length)
            }
        }
    }

    /// Borrows the same disposition again; it never captures a newer cut.
    pub(crate) fn reborrow(&mut self) -> CacheMutationGateV1<'_> {
        match self {
            Self::Ordinary => CacheMutationGateV1::Ordinary,
            Self::Retained(gate) => CacheMutationGateV1::Retained(gate),
            Self::Resident(gate, checks) => CacheMutationGateV1::Resident(gate, checks),
        }
    }

    pub(in crate::journal) fn require_own_append(
        &mut self,
        target: &Journal,
        before: u64,
        transaction: &JournalTransaction,
        result: &super::super::CommitResult,
    ) -> Result<(), JournalError> {
        match self {
            Self::Ordinary => Err(JournalError::ProtectedBoundary),
            Self::Retained(gate) => gate.require_own_append(target, before, transaction, result),
            Self::Resident(gate, checks) => {
                checks.require_own_append(gate, target, before, transaction, result)
            }
        }
    }
}

fn require_named(
    target: &Journal,
    directory: &std::path::Path,
    name: &str,
    uid: u32,
    limits: JournalLimits,
) -> Result<(), JournalError> {
    #[cfg(test)]
    return target.require_protected_named_location_at_uid_for_test(directory, name, uid, limits);
    #[cfg(not(test))]
    target.require_protected_named_location(directory, name, uid, limits)
}

fn retain_target(
    journal: &Journal,
    directory: &std::path::Path,
    uid: u32,
    name: &'static str,
) -> Result<RetainedCacheTargetV1, JournalError> {
    require_named(journal, directory, name, uid, journal.limits)?;
    Ok(RetainedCacheTargetV1 {
        name,
        instance: Arc::clone(&journal.authority_instance),
        limits: journal.limits,
        sequence: journal.snapshot_sequence(),
        witness: journal.protected_writer_name_witness()?,
        own_append: None,
    })
}

impl Journal {
    /// Retains only provisioned, canonical, unheld Cache writer names.
    ///
    /// # Errors
    /// Refuses missing, unsafe, substituted, held or V8-pending protected files.
    pub(crate) fn retain_cache_read_mutation_gate_v1(
        state: &Journal,
        authority: &Journal,
    ) -> Result<HeldCacheMutationGateV1, JournalError> {
        let (directory, uid) = state
            .cache_policy_gate
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        #[cfg(not(test))]
        if directory.as_path() != std::path::Path::new(crate::cache_residency::PROTECTED_CACHE_ROOT)
        {
            return Err(JournalError::ProtectedBoundary);
        }
        if authority.cache_policy_gate.as_ref() != Some(&(directory.clone(), *uid)) {
            return Err(JournalError::ProtectedBoundary);
        }
        let targets = [
            retain_target(state, directory, *uid, "state.journal")?,
            retain_target(authority, directory, *uid, "authority.journal")?,
        ];
        #[cfg(not(test))]
        let (mut gate, _) =
            Journal::open_existing_protected_at_for_uid(directory, NAME, hold_limits(), *uid)?;
        #[cfg(test)]
        let (mut gate, _) = Journal::open_protected_directory(
            directory,
            state
                .protected
                .as_ref()
                .ok_or(JournalError::ProtectedBoundary)?
                .directory
                .try_clone()?,
            NAME,
            hold_limits(),
            super::super::ProtectedOwnerPolicy::Exact(*uid),
            false,
        )?;
        require_named(&gate, directory, NAME, *uid, hold_limits())?;
        let current = current_state(&mut gate)?;
        if current.hold.is_some_and(|hold| hold.is_held()) || current.v8_pending.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(HeldCacheMutationGateV1 {
            checks: RetainedCacheGateChecksV1 {
                directory: directory.clone(),
                uid: *uid,
                gate_sequence: gate.snapshot_sequence(),
                gate_witness: gate.protected_writer_name_witness()?,
                state: current,
                targets,
            },
            gate,
        })
    }

    /// Borrows the actual initialization's hold writer and both original targets.
    ///
    /// # Errors
    /// Refuses unsafe names, foreign target allocations, held or pending policy
    /// state. This method neither opens a writer nor changes a policy hold.
    pub(crate) fn borrow_cache_mutation_gate_v1<'hold>(
        state: &Journal,
        authority: &Journal,
        gate: &'hold mut Journal,
    ) -> Result<BorrowedCacheMutationGateV1<'hold>, JournalError> {
        let (directory, uid) = state
            .cache_policy_gate
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        #[cfg(not(test))]
        if directory.as_path() != std::path::Path::new(crate::cache_residency::PROTECTED_CACHE_ROOT)
        {
            return Err(JournalError::ProtectedBoundary);
        }
        if authority.cache_policy_gate.as_ref() != Some(&(directory.clone(), *uid)) {
            return Err(JournalError::ProtectedBoundary);
        }

        let targets = [
            retain_target(state, directory, *uid, "state.journal")?,
            retain_target(authority, directory, *uid, "authority.journal")?,
        ];
        require_named(gate, directory, NAME, *uid, hold_limits())?;
        let current = current_state(gate)?;
        if current.hold.is_some_and(|hold| hold.is_held()) || current.v8_pending.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }

        Ok(BorrowedCacheMutationGateV1 {
            checks: RetainedCacheGateChecksV1 {
                directory: directory.clone(),
                uid: *uid,
                gate_sequence: gate.snapshot_sequence(),
                gate_witness: gate.protected_writer_name_witness()?,
                state: current,
                targets,
            },
            gate,
        })
    }
}

impl HeldCacheMutationGateV1 {
    pub(in crate::journal) fn require_own_append(
        &mut self,
        target: &Journal,
        before: u64,
        transaction: &JournalTransaction,
        result: &super::super::CommitResult,
    ) -> Result<(), JournalError> {
        self.checks.require_own_append(&mut self.gate, target, before, transaction, result)
    }

    /// Checks the original gate and one exact retained writer target.
    ///
    /// # Errors
    /// Refuses any changed identity, protected name, witness or sequence.
    pub(crate) fn require_for_target(&mut self, target: &Journal) -> Result<(), JournalError> {
        self.checks.require_for_target(&mut self.gate, target)
    }

    fn own_successor(
        &mut self,
        target: &Journal,
        transaction: &JournalTransaction,
        sequence: u64,
        length: u64,
    ) -> Result<(), JournalError> {
        self.checks.own_successor(&mut self.gate, target, transaction, sequence, length)
    }
}

impl BorrowedCacheMutationGateV1<'_> {
    /// Loans the original gate checks for one exact operation.
    pub(crate) fn as_gate(&mut self) -> CacheMutationGateV1<'_> {
        CacheMutationGateV1::Resident(self.gate, &mut self.checks)
    }
}

impl RetainedCacheGateChecksV1 {
    // The seal is installed only by the actual shared append engine. A copied
    // transaction/result cannot advance a token at an arbitrary later head.
    fn require_own_append(
        &mut self,
        gate: &mut Journal,
        target: &Journal,
        before: u64,
        transaction: &JournalTransaction,
        result: &super::super::CommitResult,
    ) -> Result<(), JournalError> {
        self.require_for_target(gate, target)?;
        let original = &self.targets[self.target_index(target)?];
        if original.own_append
            != Some((
                before,
                target.snapshot_sequence(),
                super::super::authority_preflight_digest(std::slice::from_ref(transaction)),
                result.durable_bytes,
            ))
            || result.commit_sequence.checked_add(1) != Some(target.snapshot_sequence())
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }

    fn target_index(&self, target: &Journal) -> Result<usize, JournalError> {
        self.targets
            .iter()
            .position(|original| Arc::ptr_eq(&original.instance, &target.authority_instance))
            .ok_or(JournalError::StaleAuthoritySnapshot)
    }

    fn require_gate(&self, gate: &mut Journal) -> Result<(), JournalError> {
        require_named(gate, &self.directory, NAME, self.uid, hold_limits())?;
        gate.validate_protected_writer_name_witness(&self.gate_witness)?;
        if gate.snapshot_sequence() != self.gate_sequence
            || current_state(gate)? != self.state
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }

    /// Checks the original gate and one exact retained writer target.
    ///
    /// # Errors
    /// Refuses any changed identity, protected name, witness or sequence.
    fn require_for_target(&self, gate: &mut Journal, target: &Journal) -> Result<(), JournalError> {
        self.require_gate(gate)?;
        let original = &self.targets[self.target_index(target)?];
        if target.cache_policy_gate.as_ref() != Some(&(self.directory.clone(), self.uid))
            || target.snapshot_sequence() != original.sequence
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        require_named(
            target,
            &self.directory,
            original.name,
            self.uid,
            original.limits,
        )?;
        target.validate_protected_writer_name_witness(&original.witness)
    }

    // Only the shared append engine calls this after its own successful sync and
    // RAM application. Stable origin plus exact successor excludes latest-head refresh.
    fn own_successor(
        &mut self,
        gate: &mut Journal,
        target: &Journal,
        transaction: &JournalTransaction,
        sequence: u64,
        length: u64,
    ) -> Result<(), JournalError> {
        self.require_gate(gate)?;
        let index = self.target_index(target)?;
        let original = &self.targets[index];
        require_named(
            target,
            &self.directory,
            original.name,
            self.uid,
            original.limits,
        )?;
        let successor = target.protected_writer_name_witness()?;
        if successor.directory != original.witness.directory
            || successor.lock != original.witness.lock
            || (successor.file.device, successor.file.inode)
                != (original.witness.file.device, original.witness.file.inode)
            || successor.file.size != length
            || target.snapshot_sequence() != sequence
            || sequence <= original.sequence
            || transaction
                .records()
                .iter()
                .any(|record| target.get(record.namespace(), record.key()) != record.value())
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        self.targets[index].own_append = Some((
            original.sequence,
            sequence,
            super::super::authority_preflight_digest(std::slice::from_ref(transaction)),
            length,
        ));
        self.targets[index].sequence = sequence;
        self.targets[index].witness = successor;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::{JournalRecord, RecordNamespace};
    use std::{
        fs,
        os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    };

    fn fixture(initialize: bool) -> (tempfile::TempDir, u32, Journal, Journal) {
        fixture_with_limits(initialize, JournalLimits::default())
    }

    fn fixture_with_limits(
        initialize: bool,
        limits: JournalLimits,
    ) -> (tempfile::TempDir, u32, Journal, Journal) {
        let directory = tempfile::tempdir().expect("private fixture");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(directory.path()).unwrap().uid();
        if initialize {
            super::super::initialize_fresh(directory.path(), uid).unwrap();
        }
        let opened = |name| {
            let (mut journal, _) = Journal::open_protected_at_uid(
                directory.path(),
                name,
                limits,
                uid,
            )
            .unwrap();
            journal
                .enable_cache_policy_hold_gate(directory.path(), uid)
                .unwrap();
            journal
        };
        let state = opened("state.journal");
        let authority = opened("authority.journal");
        (directory, uid, state, authority)
    }

    fn put(id: u8) -> JournalTransaction {
        JournalTransaction::new(
            [id; 16],
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                vec![id],
                vec![id],
            )],
        )
        .unwrap()
    }

    #[test]
    fn borrowed_gate_uses_the_actual_existing_writer_and_own_seal() {
        let (_directory, _uid, mut state, authority) = fixture(true);
        let mut original = Journal::retain_cache_read_mutation_gate_v1(&state, &authority).unwrap();
        let mut borrowed =
            Journal::borrow_cache_mutation_gate_v1(&state, &authority, &mut original.gate).unwrap();
        let transaction = put(71);
        let before = state.snapshot_sequence();

        borrowed
            .as_gate()
            .preflight(&state, std::slice::from_ref(&transaction))
            .unwrap();
        let committed = borrowed
            .as_gate()
            .commit(&mut state, &transaction)
            .unwrap();

        borrowed
            .as_gate()
            .require_own_append(&state, before, &transaction, &committed)
            .unwrap();
        let mut substituted = committed;
        substituted.durable_bytes += 1;
        assert!(
            borrowed
                .as_gate()
                .require_own_append(&state, before, &transaction, &substituted)
                .is_err()
        );
        assert!(matches!(
            state.preflight_transactions(&[put(72)]),
            Err(JournalError::AlreadyLocked)
        ));
        assert_eq!(
            state.get(RecordNamespace::DesiredState, &[71]),
            Some([71].as_slice())
        );
    }

    #[test]
    fn borrowed_gate_refuses_foreign_targets_and_keeps_the_original_lock() {
        let (_directory, _uid, state, authority) = fixture(true);
        let (_foreign_directory, _foreign_uid, foreign_state, _) = fixture(true);
        let mut original = Journal::retain_cache_read_mutation_gate_v1(&state, &authority).unwrap();

        assert!(
            Journal::borrow_cache_mutation_gate_v1(&foreign_state, &authority, &mut original.gate)
                .is_err()
        );

        assert!(matches!(
            state.preflight_transactions(&[put(73)]),
            Err(JournalError::AlreadyLocked)
        ));
        assert!(
            Journal::borrow_cache_mutation_gate_v1(&state, &authority, &mut original.gate).is_ok()
        );
    }

    #[test]
    fn borrowed_preflight_preserves_all_eight_native_limit_families() {
        let default = JournalLimits::default();
        let limits = [
            JournalLimits { maximum_journal_bytes: 72, ..default },
            JournalLimits { maximum_record_bytes: 7, ..default },
            JournalLimits { maximum_key_bytes: 1, ..default },
            JournalLimits { maximum_records_per_transaction: 1, ..default },
            JournalLimits { maximum_transaction_bytes: 7, ..default },
            JournalLimits { maximum_transactions: 1, ..default },
            JournalLimits { maximum_materialized_bytes: 1, ..default },
            JournalLimits { maximum_materialized_records: 1, ..default },
        ];
        for (index, limit) in limits.into_iter().enumerate() {
            let (_directory, _uid, state, authority) = fixture_with_limits(true, limit);
            let mut original = Journal::retain_cache_read_mutation_gate_v1(&state, &authority).unwrap();
            let mut borrowed =
                Journal::borrow_cache_mutation_gate_v1(&state, &authority, &mut original.gate)
                    .unwrap();
            let transaction = |id| {
                JournalTransaction::new(
                    [id; 16],
                    vec![
                        JournalRecord::put(RecordNamespace::DesiredState, vec![1, id], vec![9; 16]),
                        JournalRecord::put(RecordNamespace::DesiredState, vec![2, id], vec![8; 16]),
                    ],
                )
                .unwrap()
            };

            let returned = borrowed.as_gate().preflight(&state, &[transaction(81), transaction(82)]);

            assert!(
                returned.is_err(),
                "limit family {index} must refuse before append"
            );
            assert_eq!(state.snapshot_sequence(), 0);
        }
    }

    #[test]
    fn borrowed_preflight_preserves_next_frame_sequence_overflow() {
        let (_directory, _uid, mut state, authority) = fixture(true);
        state.next_sequence = u64::MAX;
        let mut original = Journal::retain_cache_read_mutation_gate_v1(&state, &authority).unwrap();
        let mut borrowed =
            Journal::borrow_cache_mutation_gate_v1(&state, &authority, &mut original.gate).unwrap();

        let returned = borrowed.as_gate().preflight(&state, &[put(83)]);

        assert!(matches!(returned, Err(JournalError::SequenceExhausted)));
        assert!(state.get(RecordNamespace::DesiredState, &[83]).is_none());
    }

    #[test]
    fn retained_gate_holds_one_lock_and_advances_only_own_successor() {
        let (_directory, _uid, mut state, authority) = fixture(true);
        let mut gate = Journal::retain_cache_read_mutation_gate_v1(&state, &authority).unwrap();
        let original = state.protected_writer_name_witness().unwrap();
        assert!(matches!(
            state.preflight_transactions(&[put(1)]),
            Err(JournalError::AlreadyLocked)
        ));
        state
            .preflight_with_retained_cache_gate_v1(&[put(1)], &mut gate)
            .unwrap();
        state
            .commit_with_retained_cache_gate_v1(&put(1), &mut gate)
            .unwrap();
        assert!(
            state
                .validate_protected_writer_name_witness(&original)
                .is_err()
        );
        gate.require_for_target(&state).unwrap();
        gate.require_for_target(&authority).unwrap();
        state
            .commit_with_retained_cache_gate_v1(&put(2), &mut gate)
            .unwrap();
        drop(gate);
        state.commit(&put(3)).unwrap();
    }

    #[test]
    fn retained_factory_neither_creates_missing_gate_nor_repairs_torn_tail() {
        let (directory, _uid, state, authority) = fixture(false);
        assert!(Journal::retain_cache_read_mutation_gate_v1(&state, &authority).is_err());
        assert!(!directory.path().join(NAME).exists());
        drop((state, authority));

        let (directory, _uid, state, authority) = fixture(true);
        let path = directory.path().join(NAME);
        use std::io::Write as _;
        let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"partial").unwrap();
        file.sync_all().unwrap();
        let length = file.metadata().unwrap().len();
        assert!(Journal::retain_cache_read_mutation_gate_v1(&state, &authority).is_err());
        assert_eq!(fs::metadata(path).unwrap().len(), length);
    }

    #[test]
    fn same_inode_reopened_owner_is_not_original_retained_target() {
        let (directory, uid, state, authority) = fixture(true);
        let mut gate = Journal::retain_cache_read_mutation_gate_v1(&state, &authority).unwrap();
        drop(state);
        let (mut reopened, _) = Journal::open_protected_at_uid(
            directory.path(),
            "state.journal",
            JournalLimits::default(),
            uid,
        )
        .unwrap();
        reopened
            .enable_cache_policy_hold_gate(directory.path(), uid)
            .unwrap();
        assert!(matches!(
            gate.require_for_target(&reopened),
            Err(JournalError::StaleAuthoritySnapshot)
        ));
    }

    #[test]
    fn retained_target_mode_or_named_lock_substitution_refuses() {
        let (directory, _uid, state, authority) = fixture(true);
        let mut gate = Journal::retain_cache_read_mutation_gate_v1(&state, &authority).unwrap();
        fs::set_permissions(
            directory.path().join("state.journal"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(gate.require_for_target(&state).is_err());
        fs::set_permissions(
            directory.path().join("state.journal"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        fs::rename(
            directory.path().join("authority.journal.lock"),
            directory.path().join("old-lock"),
        )
        .unwrap();
        assert!(gate.require_for_target(&authority).is_err());
    }
}
