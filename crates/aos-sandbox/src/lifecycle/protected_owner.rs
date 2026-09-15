//! Dormant lifecycle protected-journal ownership and cold replay.

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use crate::journal::Journal;
use crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1;

use super::LifecycleJournalVerifierV1;
use super::protected_journal::{
    LifecycleProtectedJournalErrorV1, LifecycleProtectedJournalProjectionV1,
    LifecycleProtectedJournalSchemaV1, LifecycleProtectedJournalV1, LifecycleProtectedRecordKindV1,
    claim_lifecycle_protected_journal_v1,
};
use super::protected_journal_adapter::{
    ProtectedCurrentRecordCandidateV1, protected_current_record_candidates_v1,
};

/// Owns a cold-replayed, dormant lifecycle adapter and its custody verifier.
pub struct LifecycleProtectedJournalOwnerV1<'journal> {
    journal: LifecycleProtectedJournalV1<'journal>,
}

impl<'journal> LifecycleProtectedJournalOwnerV1<'journal> {
    /// Cold-replays actual current records and claims the lifecycle adapter.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed protected records, failed typed replay,
    /// or absent protected provenance.
    pub fn claim(
        journal_owner: &'journal mut ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<Self, LifecycleProtectedJournalErrorV1> {
        let journal = journal_owner.journal();
        let verifier = recover_lifecycle_journal_verifier_v1(journal)?;
        let claimed = claim_lifecycle_protected_journal_v1(journal, verifier)?;
        claimed.replay()?;
        Ok(Self { journal: claimed })
    }

    /// Replays the complete current lifecycle projection.
    ///
    /// # Errors
    ///
    /// Returns an error when the retained fixed journal is unhealthy or any
    /// current record fails full typed validation.
    pub fn replay(
        &self,
    ) -> Result<LifecycleProtectedJournalProjectionV1, LifecycleProtectedJournalErrorV1> {
        self.journal.replay()
    }
}

pub(crate) fn recover_lifecycle_journal_verifier_v1(
    journal: &Journal,
) -> Result<LifecycleJournalVerifierV1, LifecycleProtectedJournalErrorV1> {
    let candidates =
        protected_current_record_candidates_v1::<LifecycleProtectedJournalSchemaV1>(journal)?;
    let mut accepted_records = candidates
        .iter()
        .filter(|candidate| candidate.key().kind() != LifecycleProtectedRecordKindV1::Checkpoint)
        .map(ProtectedCurrentRecordCandidateV1::envelope_digest)
        .collect::<Vec<_>>();
    let mut accepted_checkpoints = candidates
        .iter()
        .filter(|candidate| candidate.key().kind() == LifecycleProtectedRecordKindV1::Checkpoint)
        .map(ProtectedCurrentRecordCandidateV1::envelope_digest)
        .collect::<Vec<_>>();
    accepted_records.sort_unstable();
    accepted_checkpoints.sort_unstable();
    let authority = protected_lifecycle_authority(&candidates);
    LifecycleJournalVerifierV1::from_verified_authority(
        authority,
        accepted_records,
        accepted_checkpoints,
    )
    .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)
}

fn protected_lifecycle_authority(
    candidates: &[ProtectedCurrentRecordCandidateV1<LifecycleProtectedJournalSchemaV1>],
) -> ObjectDigest {
    let mut hasher = Sha256::new()
        .chain_update(b"aos.sandbox.lifecycle.protected-owner.v1\0")
        .chain_update((candidates.len() as u64).to_be_bytes());
    for candidate in candidates {
        hasher = hasher
            .chain_update((candidate.key().as_bytes().len() as u32).to_be_bytes())
            .chain_update(candidate.key().as_bytes())
            .chain_update(candidate.envelope_digest().as_bytes());
    }
    ObjectDigest::from_bytes(hasher.finalize().into())
}
