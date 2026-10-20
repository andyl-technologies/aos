//! Retains the exact candidate, auxiliary and verifier recovery prefix.
//!
//! This owner recovers only historical schema DATA. It has no Source writer,
//! physical reader, native currentness, account or completion constructor.

use super::*;
use std::error::Error;
use aos_sandbox_protocol::domain_ledger::records::{
    CurrentRecordCandidatesCaptureV1, current_record_candidates_with_capture_v1,
};
use crate::lifecycle::{LifecycleAuxiliaryDecodeOriginalV1, LifecycleReplayVerificationV1};

/// Prices the shared full schema graph plus both actual selected carriers.
///
/// This is inert DATA over reached row widths. The physical reader/raw prefix
/// is separate. Callers must debit the same genuine receiving original before
/// either candidate recovery, complete schema replay or latest selection.
pub(crate) fn retained_lifecycle_replay_receiving_demand_v1<'row>(
    records: impl Iterator<Item = (crate::RecordNamespace, &'row [u8], &'row [u8])>,
) -> Option<aos_sandbox_core::ResourceVector> {
    use aos_sandbox_core::{ResourceDimension, ResourceVector};
    let shared = crate::lifecycle::protected_journal::LifecycleReplayReceivingV1::
        from_records_v1(records)?;
    let memory = shared.memory_bytes_v1()
        .checked_add(LifecycleVerifierRecoveryOriginalV1::carrier_receiving_bytes_v1()?)?
        .checked_add(LifecycleCurrentOperationSelectionOriginalV1::carrier_receiving_bytes_v1()?)?;
    Some(ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, u64::try_from(memory).ok()?)
        .with(ResourceDimension::MetadataEntries, u64::try_from(shared.metadata_entries_v1()).ok()?))
}

/// Owns every reached historical verifier-recovery input and refusal.
///
/// The actual caller admits the complete Lifecycle replay demand plus this
/// carrier before scanning the held rows. Failed captures and catalogs remain
/// resident; only a successful pure auxiliary leaf is disposed after its
/// complete digest has entered the retained accepted prefix.
#[derive(Default)]
pub(crate) struct LifecycleVerifierRecoveryOriginalV1 {
    scan: CurrentRecordCandidatesCaptureV1<LifecycleProtectedJournalSchemaV1>,
    candidates: Vec<ProtectedCurrentRecordCandidateV1<LifecycleProtectedJournalSchemaV1>>,
    provisional: Option<Result<LifecycleReplayVerificationV1,
        aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleModelError>>,
    accepted_records: Vec<ObjectDigest>,
    accepted_checkpoints: Vec<ObjectDigest>,
    auxiliary: LifecycleAuxiliaryDecodeOriginalV1,
    verifier: Option<Result<LifecycleJournalVerifierV1,
        aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleModelError>>,
    returned: Option<Result<(), LifecycleProtectedJournalErrorV1>>,
    reentry: Option<LifecycleProtectedJournalErrorV1>,
    entered: bool,
    taken: bool,
}

impl LifecycleVerifierRecoveryOriginalV1 {
    pub(crate) fn new() -> Self { Self::default() }

    pub(crate) fn carrier_receiving_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>().checked_mul(2)
    }

    pub(crate) fn recover_from_records_once_v1<'row>(
        &mut self,
        records: impl Iterator<Item = (crate::RecordNamespace, &'row [u8], &'row [u8])>,
    ) -> Result<(), LifecycleProtectedJournalErrorV1> {
        if self.entered {
            self.reentry.get_or_insert(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        self.entered = true;
        if current_record_candidates_with_capture_v1(records, &mut self.scan).is_err() {
            self.returned = Some(Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord));
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        let Some(candidates) = self.scan.take_completed_once() else {
            self.returned = Some(Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord));
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        };
        self.candidates = candidates;
        self.returned = Some(self.recover_engine(true));
        if matches!(self.returned, Some(Ok(()))) { Ok(()) }
        else { Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord) }
    }

    pub(crate) fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.scan.failure().map(|cause| cause as &(dyn Error + 'static))
            .or_else(|| self.provisional.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static)))
            .or_else(|| self.auxiliary.failure_view_v1())
            .or_else(|| self.verifier.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static)))
            .or_else(|| self.returned.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static)))
            .or_else(|| self.reentry.as_ref().map(|cause| cause as &(dyn Error + 'static)))
    }

    pub(crate) fn completed_v1(&self) -> Option<&LifecycleJournalVerifierV1> {
        if !matches!(self.returned, Some(Ok(()))) || self.reentry.is_some() { return None; }
        self.verifier.as_ref()?.as_ref().ok()
    }

    fn take_completed_once(&mut self) -> Option<LifecycleJournalVerifierV1> {
        if self.taken || self.completed_v1().is_none() { return None; }
        self.taken = true;
        self.verifier.take()?.ok()
    }

    fn recover_engine(&mut self, retaining: bool) -> Result<(), LifecycleProtectedJournalErrorV1> {
        let invalid = || LifecycleProtectedJournalErrorV1::NonCanonicalRecord;
        let authority = protected_lifecycle_authority(&self.candidates);
        self.provisional = Some(LifecycleReplayVerificationV1::from_verified_authority(
            authority, Vec::new(), Vec::new(),
        ));
        let provisional = self.provisional.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or_else(invalid)?;
        for candidate in &self.candidates {
            if candidate.key().kind() != LifecycleProtectedRecordKindV1::Auxiliary { continue; }
            let digest = if retaining {
                self.auxiliary.decode_from_protected_envelope_once(candidate.body(), provisional)
                    .map_err(|_| invalid())?;
                self.auxiliary.completed().ok_or_else(invalid)?.complete_digest()
            } else {
                super::super::decode_lifecycle_auxiliary_record_from_protected_envelope_v1(
                    candidate.body(), provisional,
                ).map_err(|_| invalid())?.complete_digest()
            };
            self.accepted_records.push(digest);
            if retaining {
                // This pure leaf has passed the complete old envelope check;
                // its digest is now in the same retained accepted prefix.
                self.auxiliary = LifecycleAuxiliaryDecodeOriginalV1::new();
            }
        }
        self.accepted_checkpoints = self.candidates.iter()
            .filter(|candidate| candidate.key().kind() == LifecycleProtectedRecordKindV1::Checkpoint)
            .map(ProtectedCurrentRecordCandidateV1::envelope_digest).collect::<Vec<_>>();
        self.accepted_records.sort_unstable();
        self.accepted_checkpoints.sort_unstable();
        // The sole constructor validates by borrowing first. A refusal keeps
        // both actual arrays here; a positive move makes the verifier their owner.
        self.verifier = Some(LifecycleJournalVerifierV1::from_verified_authority_decode_parts(
            authority, &mut self.accepted_records, &mut self.accepted_checkpoints,
        ));
        self.verifier.as_ref().and_then(|result| result.as_ref().ok()).ok_or_else(invalid)?;
        Ok(())
    }
}

pub(super) fn recover_from_candidates_v1(
    candidates: Vec<ProtectedCurrentRecordCandidateV1<LifecycleProtectedJournalSchemaV1>>,
) -> Result<LifecycleJournalVerifierV1, LifecycleProtectedJournalErrorV1> {
    let mut original = LifecycleVerifierRecoveryOriginalV1::new();
    original.entered = true;
    original.candidates = candidates;
    original.returned = Some(original.recover_engine(false));
    match original.returned.take() {
        Some(Ok(())) => {
            original.returned = Some(Ok(()));
            original.take_completed_once().ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)
        }
        Some(Err(cause)) => Err(cause),
        None => Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_protocol::domain_ledger::records::ProtectedDomainSchemaV1;

    #[test]
    fn a_refused_candidate_scan_keeps_its_original_cause_on_reentry() {
        let mut original = LifecycleVerifierRecoveryOriginalV1::new();
        let malformed_key = LifecycleProtectedJournalSchemaV1::KEY_PREFIX;
        let rows = [(crate::RecordNamespace::DesiredState, malformed_key, b"".as_slice())];
        assert!(original.recover_from_records_once_v1(rows.into_iter()).is_err());
        let cause = original.failure_v1().unwrap() as *const dyn Error;

        assert!(original.recover_from_records_once_v1(std::iter::empty()).is_err());
        assert!(std::ptr::eq(cause, original.failure_v1().unwrap()));
        assert!(original.completed_v1().is_none());
    }

    #[test]
    fn reentry_closes_a_positive_verifier_without_replacing_it() {
        let mut original = LifecycleVerifierRecoveryOriginalV1::new();
        original.recover_from_records_once_v1(std::iter::empty()).unwrap();
        let verifier = original.completed_v1().unwrap() as *const LifecycleJournalVerifierV1;

        assert!(original.recover_from_records_once_v1(std::iter::empty()).is_err());
        assert!(original.completed_v1().is_none());
        let retained = original.verifier.as_ref().unwrap().as_ref().unwrap();
        assert!(std::ptr::eq(verifier, retained));
    }
}
