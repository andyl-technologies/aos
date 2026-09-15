//! Dormant environment protected-journal ownership and cold replay.

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use crate::journal::Journal;
use crate::lifecycle::protected_journal_adapter::{
    ProtectedDomainJournalErrorV1, decode_reducer_payload_with_validator,
    protected_current_record_candidates_v1,
};

use super::EnvironmentProtectedEvidenceOwnerV1;
use super::protected_evidence::EnvironmentProtectedClaimEvidenceV1;
use super::protected_journal::{
    EnvironmentProtectedJournalProjectionV1, EnvironmentProtectedJournalSchemaV1,
    EnvironmentProtectedJournalV1, EnvironmentProtectedRecordKindV1,
    claim_environment_protected_journal_v1,
};
use super::{
    EnvironmentGenerationHistoryV1, EnvironmentJournalVerifierV1, EnvironmentModelError,
    decode_environment_generation_v1,
};

/// Owns a cold-replayed, dormant environment adapter and its custody verifier.
pub struct EnvironmentProtectedJournalOwnerV1<'journal, 'evidence> {
    journal: EnvironmentProtectedJournalV1<'journal>,
    evidence_owner: &'evidence mut EnvironmentProtectedEvidenceOwnerV1,
}

impl<'journal, 'evidence> EnvironmentProtectedJournalOwnerV1<'journal, 'evidence> {
    /// Cold-replays actual current records and claims the environment adapter.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed protected records, invalid generation
    /// lineage, invalid trusted clock input, or absent protected provenance.
    pub(crate) fn claim(
        journal: &'journal mut Journal,
        evidence: EnvironmentProtectedClaimEvidenceV1,
        evidence_owner: &'evidence mut EnvironmentProtectedEvidenceOwnerV1,
    ) -> Result<Self, ProtectedDomainJournalErrorV1> {
        let history = recover_environment_generation_history_v1(journal)?;
        recover_environment_journal_verifier_v1(journal, evidence)?;

        let claimed = claim_environment_protected_journal_v1(journal, history.clone())?;
        let projection = claimed.replay()?;
        let authenticated_manifests = projection
            .records()
            .iter()
            .filter(|record| record.key().kind() == EnvironmentProtectedRecordKindV1::Generation)
            .map(|record| {
                let payload = decode_reducer_payload_with_validator::<
                    EnvironmentProtectedJournalSchemaV1,
                >(record.key(), record.payload(), &history)?;
                decode_environment_generation_v1(payload.body())
                    .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let authenticated_history =
            EnvironmentGenerationHistoryV1::from_protected_manifests(authenticated_manifests)
                .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
        if authenticated_history != history {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        evidence_owner
            .revalidate_pinned()
            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;

        Ok(Self {
            journal: claimed,
            evidence_owner,
        })
    }

    /// Replays the current environment projection under fresh evidence.
    ///
    /// # Errors
    ///
    /// Returns an error when the retained fixed evidence is no longer current.
    #[must_use]
    pub fn replay(
        &mut self,
    ) -> Result<EnvironmentProtectedJournalProjectionV1, ProtectedDomainJournalErrorV1> {
        self.revalidate_evidence()?;
        self.journal.replay()
    }

    fn revalidate_evidence(&mut self) -> Result<(), ProtectedDomainJournalErrorV1> {
        self.evidence_owner
            .revalidate_pinned()
            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)
    }
}

pub(crate) fn recover_environment_generation_history_v1(
    journal: &Journal,
) -> Result<EnvironmentGenerationHistoryV1, ProtectedDomainJournalErrorV1> {
    let manifests =
        protected_current_record_candidates_v1::<EnvironmentProtectedJournalSchemaV1>(journal)?
            .into_iter()
            .filter(|candidate| {
                candidate.key().kind() == EnvironmentProtectedRecordKindV1::Generation
            })
            .map(|candidate| {
                decode_environment_generation_v1(candidate.body())
                    .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)
            })
            .collect::<Result<Vec<_>, _>>()?;
    EnvironmentGenerationHistoryV1::from_protected_manifests(manifests)
        .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)
}

pub(crate) fn recover_environment_journal_verifier_v1(
    journal: &Journal,
    evidence: EnvironmentProtectedClaimEvidenceV1,
) -> Result<EnvironmentJournalVerifierV1, ProtectedDomainJournalErrorV1> {
    let (current_boot, current_time, boot_attestation, mut authenticated_predecessor_boots) =
        evidence.into_parts();
    let candidates =
        protected_current_record_candidates_v1::<EnvironmentProtectedJournalSchemaV1>(journal)?;
    authenticated_predecessor_boots.sort_unstable();
    if authenticated_predecessor_boots
        .windows(2)
        .any(|pair| pair[0] == pair[1])
    {
        return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
    }
    let mut accepted_records = candidates
        .iter()
        .filter(|candidate| candidate.key().kind() != EnvironmentProtectedRecordKindV1::Checkpoint)
        .map(|candidate| candidate.envelope_digest())
        .collect::<Vec<_>>();
    let mut accepted_checkpoints = candidates
        .iter()
        .filter(|candidate| candidate.key().kind() == EnvironmentProtectedRecordKindV1::Checkpoint)
        .map(|candidate| candidate.envelope_digest())
        .collect::<Vec<_>>();
    accepted_records.sort_unstable();
    accepted_checkpoints.sort_unstable();
    let mut hasher = Sha256::new()
        .chain_update(b"aos.sandbox.environment.protected-owner.v1\0")
        .chain_update((candidates.len() as u64).to_be_bytes());
    for candidate in &candidates {
        hasher = hasher
            .chain_update((candidate.key().as_bytes().len() as u32).to_be_bytes())
            .chain_update(candidate.key().as_bytes())
            .chain_update(candidate.envelope_digest().as_bytes());
    }
    let authority = ObjectDigest::from_bytes(hasher.finalize().into());
    EnvironmentJournalVerifierV1::from_verified_state(
        authority,
        current_boot,
        current_time,
        boot_attestation,
        authenticated_predecessor_boots,
        accepted_records,
        accepted_checkpoints,
    )
    .map_err(map_environment_error)
}

fn map_environment_error(_error: EnvironmentModelError) -> ProtectedDomainJournalErrorV1 {
    ProtectedDomainJournalErrorV1::NonCanonicalRecord
}
