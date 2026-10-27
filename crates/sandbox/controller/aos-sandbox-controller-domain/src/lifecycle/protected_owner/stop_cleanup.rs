//! Plans independent Stop settlement through the sole auxiliary/reducer engine.

use super::*;
use crate::controller_lifecycle_stop::StopCleanupSourceAppendAuthorizationV1;
use crate::journal::CacheMutationGateV1;
use crate::protected_domain_journal::ResidentDomainCommitFailureV1;

impl<'journal> LifecycleProtectedJournalOwnerV1<'journal> {
    pub(crate) fn claim_original_stop_cleanup_source_v1(
        source: &'journal mut ProtectedSourceDomainJournalOwnerV1,
        original: &StopCleanupSourceAppendAuthorizationV1<'_>,
    ) -> Result<Self, LifecycleProtectedJournalErrorV1> {
        original.require_source_prefix_v1(source.journal_ref_v1())?;
        let verifier = original.projection_v1()?.1.clone();
        let journal = claim_lifecycle_protected_journal_v1(source.journal(), verifier.clone())?;
        Ok(Self { journal, verifier })
    }

    pub(crate) fn prepare_original_stop_cleanup_source_v1(
        &self,
        original: &StopCleanupSourceAppendAuthorizationV1<'_>,
    ) -> Result<PreparedSourceLifecycleAdmissionV1, LifecycleProtectedJournalErrorV1> {
        original.require_current_v1()?;
        let (key, current, record) = original
            .read_v1()
            .optional_selection_v4()?
            .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let data = *original.completion_data_v1();
        if data.binding_v1().operation_record != record.digest()
            || data.binding_v1().source_root != original.projection_v1()?.0.root()
        {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        super::super::durable::require_stop_completion_current_v1(&data, current)
            .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let transaction = original.transaction_id_v1();
        let prepared = self.prepare_auxiliary_append_with_gate_v1(
            transaction,
            ResourceId::from_bytes(transaction),
            original.lineage_v1(true),
            original.lineage_v1(false),
            current.clone(),
            LifecycleAuxiliaryPayloadV1::StopCompletion(data),
            Some(CacheMutationGateV1::StopCleanupSource(original)),
        )?;
        Ok(PreparedSourceLifecycleAdmissionV1::Prepared {
            key: key.clone(),
            record: None,
            prepared: prepared.prepared,
        })
    }

    pub(crate) fn commit_original_stop_cleanup_source_v1(
        &mut self,
        prepared: &PreparedSourceLifecycleAdmissionV1,
        native: &mut aos_sandbox_broker::source_receiving::SourceProvisioningCurrentnessOriginalV1,
        original: &StopCleanupSourceAppendAuthorizationV1<'_>,
    ) -> Result<SourceLifecycleAdmissionCommitV1, ResidentDomainCommitFailureV1> {
        let PreparedSourceLifecycleAdmissionV1::Prepared { prepared, .. } = prepared else {
            return Err(ResidentDomainCommitFailureV1::Before(
                crate::JournalError::ProtectedBoundary.into(),
            ));
        };
        self.journal
            .commit_resident_stop_cleanup_prepared_v1(prepared, native, original)
            .map(SourceLifecycleAdmissionCommitV1::Applied)
    }

    pub(crate) fn require_original_stop_cleanup_published_v1(
        &self,
        prepared: &PreparedSourceLifecycleAdmissionV1,
        native: &mut aos_sandbox_broker::source_receiving::SourceProvisioningCurrentnessOriginalV1,
        original: &StopCleanupSourceAppendAuthorizationV1<'_>,
    ) -> Result<(), crate::JournalError> {
        let PreparedSourceLifecycleAdmissionV1::Prepared { prepared, .. } = prepared else {
            return Err(crate::JournalError::ProtectedBoundary);
        };
        self.journal
            .require_stop_cleanup_published_v1(prepared, native, original)
    }
}
