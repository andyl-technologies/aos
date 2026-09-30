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
    directory: PathBuf,
    uid: u32,
    gate: Journal,
    gate_witness: ProtectedWriterNameWitness,
    gate_sequence: u64,
    state: CachePolicyHoldStateV1,
    targets: [RetainedCacheTargetV1; 2],
}

/// Selects ordinary acquisition or a borrowed original interlock.
pub(crate) enum CacheMutationGateV1<'held> {
    Ordinary,
    Retained(&'held mut HeldCacheMutationGateV1),
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
        }
    }

    pub(in crate::journal) fn check(&mut self, target: &Journal) -> Result<(), JournalError> {
        match self {
            Self::Ordinary => super::check_unheld(target),
            Self::Retained(gate) => gate.require_for_target(target),
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
        let target = |journal: &Journal, name| -> Result<RetainedCacheTargetV1, JournalError> {
            require_named(journal, directory, name, *uid, journal.limits)?;
            Ok(RetainedCacheTargetV1 {
                name,
                instance: Arc::clone(&journal.authority_instance),
                limits: journal.limits,
                sequence: journal.snapshot_sequence(),
                witness: journal.protected_writer_name_witness()?,
                own_append: None,
            })
        };
        let targets = [
            target(state, "state.journal")?,
            target(authority, "authority.journal")?,
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
            directory: directory.clone(),
            uid: *uid,
            gate_sequence: gate.snapshot_sequence(),
            gate_witness: gate.protected_writer_name_witness()?,
            gate,
            state: current,
            targets,
        })
    }
}

impl HeldCacheMutationGateV1 {
    // The seal is installed only by the actual shared append engine. A copied
    // transaction/result cannot advance a token at an arbitrary later head.
    pub(in crate::journal) fn require_own_append(
        &mut self,
        target: &Journal,
        before: u64,
        transaction: &JournalTransaction,
        result: &super::super::CommitResult,
    ) -> Result<(), JournalError> {
        self.require_for_target(target)?;
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

    fn require_gate(&mut self) -> Result<(), JournalError> {
        require_named(&self.gate, &self.directory, NAME, self.uid, hold_limits())?;
        self.gate
            .validate_protected_writer_name_witness(&self.gate_witness)?;
        if self.gate.snapshot_sequence() != self.gate_sequence
            || current_state(&mut self.gate)? != self.state
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }

    /// Checks the original gate and one exact retained writer target.
    ///
    /// # Errors
    /// Refuses any changed identity, protected name, witness or sequence.
    pub(crate) fn require_for_target(&mut self, target: &Journal) -> Result<(), JournalError> {
        self.require_gate()?;
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
        target: &Journal,
        transaction: &JournalTransaction,
        sequence: u64,
        length: u64,
    ) -> Result<(), JournalError> {
        self.require_gate()?;
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
                JournalLimits::default(),
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
