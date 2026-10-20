//! Compares exact Delete acceptance at the actual native COMMIT prior state.
//!
//! The retained inputs are Root's independently checked original witness and
//! batch. The same canonical plan/ordered-record recipe builds comparison DATA;
//! neither these inputs nor the result creates admission or native authority.

use super::*;
use aos_sandbox_broker::canonical_journal::CanonicalCommitReadViewV1;
use aos_sandbox_protocol::domain_ledger::delete_batch::DeleteBatchViewV1;
use aos_sandbox_protocol::domain_ledger::delete_root::{
    authorization::DeleteRootAuthorizationFieldsV2, transport::DeleteRootOpenDataV2,
};
use aos_sandbox_protocol::public_api::mutation::ResolvedPublicMutationRequestV1;

type Cause = Box<dyn Error + Send + Sync>;

pub(crate) struct DeleteAdmissionAuditInputsDataV3 {
    pub(crate) native: [u8; 64],
    pub(crate) batch: Vec<u8>,
    pub(crate) input: Vec<u8>,
    pub(crate) fields: DeleteRootAuthorizationFieldsV2,
    pub(crate) opening: DeleteRootOpenDataV2,
    pub(crate) authorization: [u8; 32],
}

impl DeleteAdmissionAuditInputsDataV3 {
    pub(crate) fn receiving_demand_v3(
        extent: &ProtectedJournalPreopenReplayExtentV1,
        batch: &[u8],
        input: &[u8],
    ) -> Result<ResourceVector, JournalError> {
        let invalid = || JournalError::JournalTooLarge;
        // The Fixed stage already paid the sole batch decoder before this
        // reached quote. Native framing bounds every actual prior-map row.
        let view = DeleteBatchViewV1::decode(batch).map_err(|_| invalid())?;
        let rows = view
            .count(0)
            .checked_add(view.count(2))
            .and_then(|n| n.checked_add(6))
            .ok_or_else(invalid)?;
        let prefix = usize::try_from(extent.native_bytes).map_err(|_| invalid())?;
        let prior_rows = prefix / aos_sandbox_journal::framing::HEADER_BYTES;
        let encoded = prefix
            .checked_add(batch.len())
            .and_then(|n| n.checked_add(input.len()))
            .ok_or_else(invalid)?;
        let semantic = super::super::semantic_receiving::semantic_representation_demand_v1(
            encoded,
            prior_rows.checked_add(rows).ok_or_else(invalid)?,
        )?;
        let request =
            crate::public_mutation_compiler::delete_admission::geometry::delete_decode_bytes_v1(
                input.len(),
            )
            .ok_or_else(invalid)?;
        let carriers = size_of::<Self>()
            .checked_mul(3)
            .and_then(|n| n.checked_add(size_of::<crate::OperationPlan>().checked_mul(3)?))
            .and_then(|n| n.checked_add(size_of::<JournalTransaction>().checked_mul(3)?))
            .and_then(|n| {
                n.checked_add(
                    size_of::<super::super::JournalRecord>()
                        .checked_mul(rows)?
                        .checked_mul(6)?,
                )
            })
            .and_then(|n| n.checked_add(request))
            .and_then(|n| u64::try_from(n).ok())
            .ok_or_else(invalid)?;
        semantic
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, carriers))
            .map_err(Into::into)
    }
}

pub(super) struct DeleteAdmissionAuditOriginalV3 {
    inputs: DeleteAdmissionAuditInputsDataV3,
    request: Option<
        Result<
            ResolvedPublicMutationRequestV1,
            aos_sandbox_protocol::public_api::mutation::PublicMutationResolutionErrorV1,
        >,
    >,
    authorization: Option<
        Result<[u8; 32], crate::cli_model::authorization_adapter::CliAuthorizationAdapterError>,
    >,
    candidate: Option<Result<(crate::OperationPlan, JournalTransaction), Cause>>,
    comparison: Option<Result<(), JournalError>>,
    native: aos_sandbox_ledger_replay::delete_pending::DeleteSelectedCommitReplayDataV3,
}

impl DeleteAdmissionAuditOriginalV3 {
    pub(super) fn new(inputs: DeleteAdmissionAuditInputsDataV3) -> Self {
        let native =
            aos_sandbox_ledger_replay::delete_pending::DeleteSelectedCommitReplayDataV3::new(
                inputs.native,
            );
        Self {
            inputs,
            request: None,
            authorization: None,
            candidate: None,
            comparison: None,
            native,
        }
    }

    pub(super) fn observe_commit_v3(
        &mut self,
        actual: &CanonicalCommitReadViewV1<'_>,
    ) -> Result<(), JournalError> {
        if actual.transaction().id().as_slice() != &self.inputs.native[..16] {
            return Ok(());
        }
        if self.comparison.is_some() {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        self.authorization = Some(crate::cli_model::authorization_adapter::recompute_delete_authorization_cut_from_records_v2(
            crate::publisher_admin::PublisherReadDataV2::from_state_v2(actual.prior_state()),
            &self.inputs.input, self.inputs.fields, self.inputs.opening));
        self.request = Some(ResolvedPublicMutationRequestV1::decode_delete(
            &self.inputs.input,
        ));
        self.candidate = Some((|| {
            if self
                .authorization
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                != Some(&self.inputs.authorization)
            {
                return Err(JournalError::StaleAuthoritySnapshot.into());
            }
            let request = self
                .request
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            let batch = DeleteBatchViewV1::decode(&self.inputs.batch)?;
            crate::reconciler::prepare_delete_admission_comparison_data_v3(
                batch,
                request,
                aos_sandbox_model::PrincipalId::from_bytes(self.inputs.fields.caller),
                batch.project(),
                self.inputs.fields.authorized_wall,
                &self.inputs.input,
                &self.inputs.opening.source_pending,
            )
        })());
        self.comparison = Some((|| {
            let (plan, expected) = self
                .candidate
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            // The comparison occurs before this real native group applies. A
            // later map with rows removed cannot substitute this predecessor.
            if expected != actual.transaction()
                || actual.prior_state().contains_key(&(
                    RecordNamespace::Operation,
                    plan.operation_id().into_bytes().to_vec(),
                ))
            {
                return Err(JournalError::StaleAuthoritySnapshot);
            }
            self.native.observe_commit_v3(actual).map_err(JournalError::from)
        })());
        match self
            .comparison
            .as_ref()
            .and_then(|result| result.as_ref().ok())
        {
            Some(()) => Ok(()),
            None => Err(JournalError::ProtectedBoundary),
        }
    }

    pub(super) fn finish_prefix_v3(
        &mut self,
        prefix: aos_sandbox_broker::canonical_journal::CanonicalReplayPrefixReadViewV1<'_>,
        bytes: u64,
    ) -> Result<(), JournalError> {
        if !matches!(self.comparison, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.native.finish_prefix_v3(prefix, bytes).map_err(JournalError::from)
    }

    pub(super) fn require_completed_v3(&self) -> Result<(), JournalError> {
        self.native
            .data_v3()
            .map(|_| ())
            .map_err(|_| JournalError::ProtectedBoundary)
    }

    pub(super) fn require_current_rows_v3(&self, actual: &State) -> Result<(), JournalError> {
        self.require_completed_v3()?;
        let (_, expected) = self
            .candidate
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        for record in expected.records() {
            let value = actual
                .iter()
                .find(|((namespace, key), _)| {
                    *namespace == record.namespace() && key.as_slice() == record.key()
                })
                .map(|(_, value)| value.as_slice());
            if value != record.value() {
                return Err(JournalError::StaleAuthoritySnapshot);
            }
        }
        Ok(())
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.authorization
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| {
                self.request
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.candidate
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause.as_ref() as _)
            })
            .or_else(|| self.native.failure_v3())
            .or_else(|| {
                self.comparison
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
    }
}
