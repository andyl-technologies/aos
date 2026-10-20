//! Owns historical challenge checkpoint and replay-witness comparison DATA.
//!
//! The native challenge opener and all protected-name/currentness observations
//! stay with their original physical owner. These supplied saved rows, identity
//! comparisons and commitments prove no native membership or nonce authority.

use std::sync::Arc;
use super::{JournalError, JournalTransaction, RecordNamespace};

/// Borrows one actual committed record checkpoint without granting nonce custody.
#[derive(Clone)]
pub struct SourceOriginalChallengeCheckpointV5 {
    /// Retains the historical key DATA.
    pub key: Vec<u8>,
    /// Retains the historical value DATA.
    pub value: Vec<u8>,
    /// Retains the historical transaction DATA.
    pub transaction: [u8; 16],
    /// Retains the historical begin sequence DATA.
    pub begin_sequence: u64,
    /// Retains the historical commit sequence DATA.
    pub commit_sequence: u64,
    /// Retains the historical begin offset DATA.
    pub begin_offset: u64,
    /// Retains the historical durable end DATA.
    pub durable_end: u64,
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

/// Commits the exact ordered checkpoints up to the given complete sequence.
///
/// These supplied rows and identity fields are comparison DATA, not custody.
pub fn challenge_prefix_digest(
    identity: (u64, u64),
    sequence: u64,
    history: &[SourceOriginalChallengeCheckpointV5],
) -> aos_sandbox_model::ObjectDigest {
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
    aos_sandbox_model::ObjectDigest::from_bytes(hash.finalize().into())
}

/// Retains immutable rows and the same opaque identity for DATA comparison.
///
/// The identity type supplies no methods or native IO. Constructing this DATA
/// value proves neither the identity's origin nor live Journal currentness.
#[doc(hidden)]
pub struct SourceChallengeReplayWitnessDataV5<I> {
    rows: Arc<[SourceOriginalChallengeCheckpointV5]>,
    instance: Arc<I>,
    sequence: u64,
}

impl<I> Clone for SourceChallengeReplayWitnessDataV5<I> {
    fn clone(&self) -> Self {
        Self {
            rows: Arc::clone(&self.rows),
            instance: Arc::clone(&self.instance),
            sequence: self.sequence,
        }
    }
}

impl<I> SourceChallengeReplayWitnessDataV5<I> {
    /// Copies the same bounded saved rows after the caller's native check.
    ///
    /// This method performs no native observation or admission and yields only
    /// comparison DATA. Its name does not assert that a native check occurred.
    ///
    /// # Errors
    /// Returns the original arithmetic or complete retained-history bound error.
    pub fn retain_rows(
        history: &Vec<SourceOriginalChallengeCheckpointV5>,
        maximum_journal_bytes: u64,
        instance: &Arc<I>,
        sequence: u64,
    ) -> Result<Self, JournalError> {
        let bytes = history.iter().try_fold(
            0_u64,
            |total, row| {
                let width = row.key.len().checked_add(row.value.len())
                    .ok_or(JournalError::JournalTooLarge)?;
                total.checked_add(u64::try_from(width)
                    .map_err(|_| JournalError::JournalTooLarge)?)
                    .ok_or(JournalError::JournalTooLarge)
            },
        )?;
        if bytes > maximum_journal_bytes {
            return Err(JournalError::LimitExceeded("retained challenge history"));
        }

        Ok(Self {
            rows: Arc::from(history.clone()),
            instance: Arc::clone(instance),
            sequence,
        })
    }

    /// Compares only the same retained identity and exact saved sequence.
    ///
    /// # Errors
    /// Returns the original stale comparison class when either DATA differs.
    pub fn require_same_identity(
        &self,
        instance: &Arc<I>,
        sequence: u64,
    ) -> Result<(), JournalError> {
        if !Arc::ptr_eq(&self.instance, instance) || self.sequence != sequence {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }

    /// Borrows the actual immutable retained checkpoint DATA.
    pub fn rows(&self) -> &[SourceOriginalChallengeCheckpointV5] {
        &self.rows
    }
}

/// Recognizes the fixed challenge namespace key prefix without decoding it.
pub fn is_challenge_key(key: &[u8]) -> bool {
    key.starts_with(b"AOSZHK01")
}

/// Retains the same bounded checkpoint DATA from a supplied committed transaction.
///
/// The caller must establish its physical membership separately. This helper
/// cannot create a native history view or populate another owner's Journal.
///
/// # Errors
/// Returns the original missing-value or retained-byte bound classification.
pub fn capture_checkpoint(
    history: &mut Vec<SourceOriginalChallengeCheckpointV5>,
    retained_bytes: &mut u64,
    transaction: &JournalTransaction,
    begin_sequence: u64,
    commit_sequence: u64,
    begin_offset: u64,
    durable_end: u64,
    limits: aos_sandbox_protocol::domain_ledger::transaction::JournalLimits,
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
mod tests {
    use super::*;

    // The real opaque native identity is deliberately not Clone. Cloning a
    // witness clones only its retained Arcs, and never manufactures identity.
    struct Identity;

    #[test]
    fn witness_requires_same_opaque_identity_and_exact_sequence() {
        let identity = Arc::new(Identity);
        let other = Arc::new(Identity);
        let rows = Vec::new();
        let original = SourceChallengeReplayWitnessDataV5::retain_rows(
            &rows, 0, &identity, 7,
        ).unwrap();
        let retained = original.clone();

        assert!(retained.require_same_identity(&identity, 7).is_ok());
        assert!(matches!(retained.require_same_identity(&other, 7),
            Err(JournalError::StaleAuthoritySnapshot)));
        assert!(matches!(retained.require_same_identity(&identity, 8),
            Err(JournalError::StaleAuthoritySnapshot)));
    }
}
