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

/// Borrows one actual committed record checkpoint without granting nonce custody.
#[derive(Clone)]
pub struct SourceOriginalChallengeCheckpointV5 {
    key: Vec<u8>,
    value: Vec<u8>,
    transaction: [u8; 16],
    begin_sequence: u64,
    commit_sequence: u64,
    begin_offset: u64,
    durable_end: u64,
}

impl SourceOriginalChallengeCheckpointV5 {
    /// Borrows the actual committed key.
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Borrows the actual committed value, not a reconstructed earlier state.
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Returns the actual physical transaction identity.
    pub const fn transaction_id(&self) -> &[u8; 16] {
        &self.transaction
    }

    /// Returns the actual begin and commit frame sequences.
    pub const fn frame_sequences(&self) -> (u64, u64) {
        (self.begin_sequence, self.commit_sequence)
    }

    /// Returns the actual begin offset and committed-prefix end.
    pub const fn file_offsets(&self) -> (u64, u64) {
        (self.begin_offset, self.durable_end)
    }
}

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
    pub fn current_prefix(&self) -> Result<((u64, u64), u64, aos_sandbox_core::ObjectDigest), JournalError> {
        self.validate_current()?;
        let identity = super::super::FileIdentity::of(&self.journal.file)?;
        let sequence = self.sequence.checked_sub(1).ok_or(JournalError::SequenceExhausted)?;
        Ok(((identity.device, identity.inode), sequence, challenge_prefix_digest(
            (identity.device, identity.inode), sequence, &self.journal.source_challenge_history,
        )))
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
            || self.sequence != self.journal.next_sequence
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
    ) -> Result<SourceChallengeReplayWitnessV5, JournalError> {
        self.validate_current()?;
        let bytes = self.journal.source_challenge_history.iter().try_fold(
            0_u64,
            |total, row| {
                let width = row.key.len().checked_add(row.value.len())
                    .ok_or(JournalError::JournalTooLarge)?;
                total.checked_add(u64::try_from(width)
                    .map_err(|_| JournalError::JournalTooLarge)?)
                    .ok_or(JournalError::JournalTooLarge)
            },
        )?;
        if bytes > self.journal.limits.maximum_journal_bytes {
            return Err(JournalError::LimitExceeded("retained challenge history"));
        }

        Ok(SourceChallengeReplayWitnessV5 {
            rows: Arc::from(self.journal.source_challenge_history.clone()),
            instance: Arc::clone(&self.instance),
            sequence: self.sequence,
        })
    }

    pub(super) fn retained_rows(
        &self,
    ) -> Result<&[SourceOriginalChallengeCheckpointV5], JournalError> {
        self.validate_current()?;
        Ok(&self.journal.source_challenge_history)
    }
}

fn challenge_prefix_digest(
    identity: (u64, u64),
    sequence: u64,
    history: &[SourceOriginalChallengeCheckpointV5],
) -> aos_sandbox_core::ObjectDigest {
    use sha2::{Digest as _, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"aos.source.original.challenge-physical-prefix.v5\0");
    hash.update(identity.0.to_be_bytes());
    hash.update(identity.1.to_be_bytes());
    hash.update(sequence.to_be_bytes());
    for row in history.iter().filter(|row| row.commit_sequence <= sequence) {
        hash.update(row.transaction);
        for value in [row.begin_sequence, row.commit_sequence, row.begin_offset, row.durable_end] {
            hash.update(value.to_be_bytes());
        }
        for bytes in [&row.key[..], &row.value[..]] {
            hash.update((bytes.len() as u64).to_be_bytes());
            hash.update(bytes);
        }
    }
    aos_sandbox_core::ObjectDigest::from_bytes(hash.finalize().into())
}

#[derive(Clone)]
pub(super) struct SourceChallengeReplayWitnessV5 {
    rows: Arc<[SourceOriginalChallengeCheckpointV5]>,
    instance: Arc<JournalAuthorityInstance>,
    sequence: u64,
}

impl SourceChallengeReplayWitnessV5 {
    pub(super) fn validate_current(
        &self,
        view: &SourceOriginalChallengeHistoryViewV5<'_>,
    ) -> Result<(), JournalError> {
        view.validate_current()?;
        if !Arc::ptr_eq(&self.instance, &view.instance) || self.sequence != view.sequence {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }

    pub(super) fn rows(&self) -> &[SourceOriginalChallengeCheckpointV5] {
        &self.rows
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
        let replay = super::super::replay(&mut self.file, self.limits)?;
        if replay.state != self.state
            || replay.next_sequence != self.next_sequence
            || replay.transaction_ids != self.transaction_ids
            || replay.durable_end != self.file.metadata()?.len()
        {
            self.poisoned = true;
            return Err(JournalError::StaleAuthoritySnapshot);
        }

        self.source_challenge_history = replay.source_challenge_history;
        require_fixed(self)?;
        Ok(SourceOriginalChallengeHistoryViewV5 {
            instance: Arc::clone(&self.authority_instance),
            sequence: self.next_sequence,
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
    if journal.committed_namespaces.iter().any(|namespace| {
        *namespace != RecordNamespace::SourceProviderAuthority
    }) || journal.state.keys().any(|(namespace, key)| {
        *namespace != RecordNamespace::SourceProviderAuthority || !is_challenge_key(key)
    }) {
        return Err(JournalError::ForeignAuthorityNamespace);
    }
    Ok(())
}

pub(super) fn is_challenge_key(key: &[u8]) -> bool {
    key.starts_with(b"AOSZHK01")
}

pub(in crate::journal) fn capture_checkpoint(
    history: &mut Vec<SourceOriginalChallengeCheckpointV5>,
    retained_bytes: &mut u64,
    transaction: &JournalTransaction,
    begin_sequence: u64,
    commit_sequence: u64,
    begin_offset: u64,
    durable_end: u64,
    limits: super::super::JournalLimits,
) -> Result<(), JournalError> {
    for record in transaction.records() {
        if record.namespace() != RecordNamespace::SourceProviderAuthority
            || !is_challenge_key(record.key())
        {
            continue;
        }
        let value = record.value().ok_or(JournalError::ProtectedBoundary)?;
        let width = record.key().len().checked_add(value.len())
            .ok_or(JournalError::JournalTooLarge)?;
        let total = retained_bytes.checked_add(
            u64::try_from(width).map_err(|_| JournalError::JournalTooLarge)?,
        ).ok_or(JournalError::JournalTooLarge)?;
        if total > limits.maximum_journal_bytes {
            return Err(JournalError::LimitExceeded("retained challenge history"));
        }

        // The full payload is bounded before either copy. The descriptor comes
        // only from a checksum-verified committed frame in the shared parser.
        history.push(SourceOriginalChallengeCheckpointV5 {
            key: record.key().to_vec(),
            value: value.to_vec(),
            transaction: *transaction.id(),
            begin_sequence,
            commit_sequence,
            begin_offset,
            durable_end,
        });
        *retained_bytes = total;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
