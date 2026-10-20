//! Actual committed challenge checkpoints from the held fixed challenge file.
//!
//! The shared Journal parser records physical rows without implementing the
//! challenge codec. Source validates its complete typed set; Ledger checks the
//! exact borrowed row required by each held edge. Historical values are never
//! synthesized from a current Spent value.

use std::sync::Arc;

use super::super::{
    Journal, JournalAuthorityInstance, JournalError, JournalTransaction, RecordNamespace,
};

pub use aos_sandbox_ledger_replay::replay::challenge::SourceOriginalChallengeCheckpointV5;
use aos_sandbox_ledger_replay::replay::challenge::{
    SourceChallengeReplayWitnessDataV5, challenge_prefix_digest,
};

/// Borrows historical bytes while the fixed challenge writer remains held.
///
/// There is no constructor, mutation, issuance, clock or signing conversion.
/// Source owns canonical challenge-set validation and Ledger owns exact joins.
pub struct SourceOriginalChallengeHistoryViewV5<'journal> {
    journal: &'journal Journal,
    instance: Arc<JournalAuthorityInstance>,
    sequence: u64,
}

impl SourceOriginalChallengeHistoryViewV5<'_> {
    /// Returns the exact current complete physical challenge-prefix commitment.
    ///
    /// # Errors
    ///
    /// Refuses changed held custody or an incomplete requested prefix.
    pub fn current_prefix(
        &self,
    ) -> Result<((u64, u64), u64, aos_sandbox_core::ObjectDigest), JournalError> {
        self.validate_current()?;
        let identity = self.journal.native_view().file_identity::<crate::provider_journal::JournalError>()?;
        let sequence = self
            .sequence
            .checked_sub(1)
            .ok_or(JournalError::SequenceExhausted)?;
        Ok((
            identity.physical_pair(),
            sequence,
            challenge_prefix_digest(
                identity.physical_pair(),
                sequence,
                &self.journal.source_challenge_history,
            ),
        ))
    }

    /// Requires an archived cut to name a real complete prefix of this actual file.
    ///
    /// # Errors
    ///
    /// Refuses a foreign inode, future/non-commit sequence, substituted digest or stale current custody.
    pub fn require_archived_prefix(
        &self,
        identity: (u64, u64),
        sequence: u64,
        digest: aos_sandbox_core::ObjectDigest,
    ) -> Result<(), JournalError> {
        let (current_identity, current_sequence, _) = self.current_prefix()?;
        let history = &self.journal.source_challenge_history;
        if identity != current_identity || sequence > current_sequence
            || (sequence != 0 && !history.iter().any(|row| row.commit_sequence == sequence))
            || challenge_prefix_digest(identity, sequence, history) != digest
        {
            return Err(JournalError::ProtectedBoundary);
        }
        self.validate_current()
    }

    /// Rechecks the same physical file, current instance and complete history.
    ///
    /// # Errors
    ///
    /// Rejects changed paths/inodes, poisoned custody or an intervening append.
    pub fn validate_current(&self) -> Result<(), JournalError> {
        require_fixed(self.journal)?;
        if !Arc::ptr_eq(&self.instance, &self.journal.authority_instance)
            || self.sequence != self.journal.native_view().next_sequence()
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }

    /// Borrows every actual committed challenge checkpoint.
    ///
    /// # Errors
    ///
    /// Rejects stale physical or same-instance sequence custody.
    pub fn checkpoints(
        &self,
    ) -> Result<impl Iterator<Item = &SourceOriginalChallengeCheckpointV5>, JournalError> {
        self.validate_current()?;
        Ok(self.journal.source_challenge_history.iter())
    }

    pub(super) fn retained_witness(
        &self,
    ) -> Result<SourceChallengeReplayWitnessDataV5<JournalAuthorityInstance>, JournalError> {
        self.validate_current()?;
        let data = SourceChallengeReplayWitnessDataV5::retain_rows(
            &self.journal.source_challenge_history,
            self.journal.native_view().limits().maximum_journal_bytes,
            &self.instance,
            self.sequence,
        )?;
        Ok(data)
    }

    pub(super) fn validate_retained_witness(
        &self,
        witness: &SourceChallengeReplayWitnessDataV5<JournalAuthorityInstance>,
    ) -> Result<(), JournalError> {
        self.validate_current()?;
        witness.require_same_identity(&self.instance, self.sequence)
            .map_err(JournalError::from)
    }

    pub(super) fn retained_rows(
        &self,
    ) -> Result<&[SourceOriginalChallengeCheckpointV5], JournalError> {
        self.validate_current()?;
        Ok(&self.journal.source_challenge_history)
    }
}


impl Journal {
    /// Replays and lends the actual fixed challenge file's committed history.
    ///
    /// This is nonauthorizing physical membership only. Source still validates
    /// all subjects, duplicate attempts and lifetimes with its existing codec.
    ///
    /// # Errors
    ///
    /// Rejects foreign/changed protected names, incomplete history, any replay
    /// error or disagreement with the actual held writer's materialization.
    #[doc(hidden)]
    pub fn source_original_challenge_history_v5(
        &mut self,
    ) -> Result<SourceOriginalChallengeHistoryViewV5<'_>, JournalError> {
        require_fixed(self)?;
        let limits = self.native_view().limits();
        let replay = super::super::reread::ordinary(&mut self.held, limits, None)?;
        if replay.require_same_data(self, self.native_view().metadata()?.len()).is_err() {
            self.poison();
            return Err(JournalError::StaleAuthoritySnapshot);
        }

        self.source_challenge_history = replay.semantic.source_challenge_history;
        require_fixed(self)?;
        Ok(SourceOriginalChallengeHistoryViewV5 {
            instance: Arc::clone(&self.authority_instance),
            sequence: self.native_view().next_sequence(),
            journal: self,
        })
    }
}

fn require_fixed(journal: &Journal) -> Result<(), JournalError> {
    journal.ensure_protected_authority()?;
    journal.validate_held_root_owned_at(
        "/var/lib/aos/source-provider",
        "native-hold-challenges.journal",
    )?;
    if journal.source_history_compacted {
        return Err(JournalError::ProtectedBoundary);
    }
    if journal.native_view().committed_namespaces().iter().any(|namespace| {
        *namespace != RecordNamespace::SourceProviderAuthority
    }) || journal.native_view().state().keys().any(|(namespace, key)| {
        *namespace != RecordNamespace::SourceProviderAuthority || !is_challenge_key(key)
    }) {
        return Err(JournalError::ForeignAuthorityNamespace);
    }
    Ok(())
}

pub(in crate::provider_journal) fn is_challenge_key(key: &[u8]) -> bool {
    aos_sandbox_ledger_replay::replay::challenge::is_challenge_key(key)
}

pub(in crate::provider_journal) fn capture_checkpoint(
    history: &mut Vec<SourceOriginalChallengeCheckpointV5>,
    retained_bytes: &mut u64,
    transaction: &JournalTransaction,
    begin_sequence: u64,
    commit_sequence: u64,
    begin_offset: u64,
    durable_end: u64,
    limits: super::super::JournalLimits,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::challenge::capture_checkpoint(
        history,
        retained_bytes,
        transaction,
        begin_sequence,
        commit_sequence,
        begin_offset,
        durable_end,
        limits,
    ).map_err(JournalError::from)
}

#[cfg(test)]
mod tests;
