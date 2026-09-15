//! Dormant Git protected-journal ownership and cold replay.

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use crate::journal::Journal;
use crate::lifecycle::protected_journal_adapter::{
    ProtectedDomainJournalErrorV1, protected_current_record_candidates_v1,
};

use super::protected_evidence::GitProtectedClaimEvidenceV1;
use super::protected_journal::{
    GitProtectedJournalProjectionV1, GitProtectedJournalSchemaV1, GitProtectedJournalV1,
    GitProtectedRecordKindV1, claim_git_protected_journal_v1,
};
use super::{GitJournalVerifierV1, GitProtectedEvidenceOwnerV1};

/// Owns a cold-replayed, dormant Git adapter and its custody verifier.
pub struct GitProtectedJournalOwnerV1<'journal, 'evidence> {
    journal: GitProtectedJournalV1<'journal>,
    evidence_owner: &'evidence mut GitProtectedEvidenceOwnerV1,
}

impl<'journal, 'evidence> GitProtectedJournalOwnerV1<'journal, 'evidence> {
    /// Cold-replays actual current records and claims the Git adapter.
    ///
    /// Validator and boot-clock evidence must be a singular token issued by the
    /// fixed protected evidence owner. Record and checkpoint custody are
    /// derived exclusively from the protected domain journal.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed protected records, invalid validator or
    /// boot evidence, failed typed replay, or absent protected provenance.
    pub(crate) fn claim(
        journal: &'journal mut Journal,
        evidence: GitProtectedClaimEvidenceV1,
        evidence_owner: &'evidence mut GitProtectedEvidenceOwnerV1,
    ) -> Result<Self, ProtectedDomainJournalErrorV1> {
        let verifier = recover_git_journal_verifier_v1(journal, evidence)?;
        let claimed = claim_git_protected_journal_v1(journal, verifier.validator().clone())?;
        claimed.replay()?;
        evidence_owner
            .revalidate_pinned()
            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;

        Ok(Self {
            journal: claimed,
            evidence_owner,
        })
    }

    /// Replays the current Git projection under fresh protected evidence.
    ///
    /// # Errors
    ///
    /// Returns an error when the retained fixed evidence is no longer current.
    #[must_use]
    pub fn replay(
        &mut self,
    ) -> Result<GitProtectedJournalProjectionV1, ProtectedDomainJournalErrorV1> {
        self.revalidate_evidence()?;
        self.journal.replay()
    }

    fn revalidate_evidence(&mut self) -> Result<(), ProtectedDomainJournalErrorV1> {
        self.evidence_owner
            .revalidate_pinned()
            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)
    }
}

pub(crate) fn recover_git_journal_verifier_v1(
    journal: &Journal,
    evidence: GitProtectedClaimEvidenceV1,
) -> Result<GitJournalVerifierV1, ProtectedDomainJournalErrorV1> {
    let (
        validator_attestation,
        current_boot,
        current_boottime,
        boot_attestation,
        mut authenticated_predecessor_boots,
        mut accepted_graphs,
        mut accepted_ancestry,
        mut accepted_validation_reports,
    ) = evidence.into_parts();
    let candidates =
        protected_current_record_candidates_v1::<GitProtectedJournalSchemaV1>(journal)?;
    authenticated_predecessor_boots.sort_unstable();
    accepted_graphs.sort_unstable();
    accepted_ancestry.sort_unstable();
    accepted_validation_reports.sort_unstable();
    if authenticated_predecessor_boots
        .windows(2)
        .chain(accepted_graphs.windows(2))
        .chain(accepted_ancestry.windows(2))
        .chain(accepted_validation_reports.windows(2))
        .any(|pair| pair[0] == pair[1])
    {
        return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
    }

    let mut accepted_records = candidates
        .iter()
        .filter(|candidate| candidate.key().kind() != GitProtectedRecordKindV1::Checkpoint)
        .map(|candidate| candidate.envelope_digest())
        .collect::<Vec<_>>();
    let mut accepted_checkpoints = candidates
        .iter()
        .filter(|candidate| candidate.key().kind() == GitProtectedRecordKindV1::Checkpoint)
        .map(|candidate| candidate.envelope_digest())
        .collect::<Vec<_>>();
    accepted_records.sort_unstable();
    accepted_checkpoints.sort_unstable();
    let authority = protected_git_authority(&candidates);
    GitJournalVerifierV1::from_verified_state(
        authority,
        validator_attestation,
        current_boot,
        current_boottime,
        boot_attestation,
        authenticated_predecessor_boots,
        accepted_graphs,
        accepted_ancestry,
        accepted_validation_reports,
        accepted_records,
        accepted_checkpoints,
    )
    .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)
}

fn protected_git_authority(
    candidates: &[crate::lifecycle::protected_journal_adapter::ProtectedCurrentRecordCandidateV1<
        GitProtectedJournalSchemaV1,
    >],
) -> ObjectDigest {
    let mut hasher = Sha256::new()
        .chain_update(b"aos.sandbox.git.protected-owner.v1\0")
        .chain_update((candidates.len() as u64).to_be_bytes());
    for candidate in candidates {
        hasher = hasher
            .chain_update((candidate.key().as_bytes().len() as u32).to_be_bytes())
            .chain_update(candidate.key().as_bytes())
            .chain_update(candidate.envelope_digest().as_bytes());
    }
    ObjectDigest::from_bytes(hasher.finalize().into())
}
