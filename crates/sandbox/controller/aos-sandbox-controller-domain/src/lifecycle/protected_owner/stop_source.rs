//! Plans Stop metadata on the ordinary Source append gate.
//!
//! This adapter borrows the already paid, same-interval captured projection.
//! Its constructor requires the actual accepted Stop and native Source owner;
//! no historical model, supplied receipt or Start append cut creates it.

use super::*;
use crate::controller_lifecycle_stop::source::{StopSourceAuthorizationV4, StopSourcePurposeV4};
use crate::journal::CacheMutationGateV1;
use crate::protected_domain_journal::ResidentDomainCommitFailureV1;

pub(crate) fn stop_inventory_challenge_receiving_bytes_v5() -> Option<usize> {
    let encoded = LifecycleProtectedJournalKeyV1::encoded_bytes_for_identity_v1(
        super::super::protected_journal::LIFECYCLE_PROTECTED_IDENTITY_BYTES).ok()?;
    std::mem::size_of::<LifecycleProtectedJournalKeyV1>().checked_mul(2)?
        .checked_add(super::super::protected_journal::LIFECYCLE_PROTECTED_IDENTITY_BYTES)?
        .checked_add(encoded)?
        .checked_add(std::mem::size_of::<sha2::Sha256>().checked_mul(2)?)?
        .checked_add(std::mem::size_of::<[u8; 32]>())?
        .checked_add(std::mem::size_of::<[u8; 16]>())
}

impl<'journal> LifecycleProtectedJournalOwnerV1<'journal> {
    pub(crate) fn stop_inventory_challenge_data_v5(
        current: &CurrentLifecycleOperationV1<'_>,
        projection: &super::super::protected_journal::LifecycleProtectedJournalProjectionV1,
        nonce: [u8; 32], boot: [u8; 16],
    ) -> Result<super::super::LifecycleBootInventoryBootstrapChallengeV1, LifecycleProtectedJournalErrorV1> {
        let operation = current.operation();
        let resource = super::super::lifecycle_plan_resource_id_v5(operation.operation_id(), b"boot-inventory-lineage");
        let key = super::super::lifecycle_protected_key_v1(
            super::super::LifecycleProtectedRecordKindV1::Auxiliary,
            operation.project(), resource, operation.operation_id())?;
        if current.projection_root() != projection.root()
            || projection.records().iter().any(|row| row.key() == &key)
        { return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord); }
        super::super::LifecycleBootInventoryBootstrapChallengeV1::from_protected_absence(
            nonce, operation.operation_id(), current.record(), projection.root(), boot)
            .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)
    }

    pub(crate) fn claim_original_stop_source_v4(
        source: &'journal mut ProtectedSourceDomainJournalOwnerV1,
        original: StopSourceAuthorizationV4<'journal>,
    ) -> Result<Self, LifecycleProtectedJournalErrorV1> {
        original.require_current_v4()?;
        original.require_source_prefix_v4(source.journal_ref_v1())?;
        let (_, verified) = original.projection_v4()?;
        let verifier = verified.clone();
        let journal = claim_lifecycle_protected_journal_v1(source.journal(), verifier.clone())?;
        Ok(Self { journal, verifier })
    }

    pub(super) fn current_operation_with_stop_selection_v4(
        &self,
        key: &LifecycleProtectedJournalKeyV1,
        stop: Option<&StopSourceAuthorizationV4<'_>>,
    ) -> Result<Option<CurrentLifecycleOperationV1<'_>>, LifecycleProtectedJournalErrorV1> {
        let Some(original) = stop else { return self.current_operation(key); };
        let Some((actual_key, operation, record, root)) = original.current_data_v4()? else {
            return Ok(None);
        };
        if key != &actual_key { return Ok(None); }
        Ok(Some(CurrentLifecycleOperationV1::from_protected_current(operation, record, root)))
    }

    pub(super) fn current_operation_by_id_with_stop_selection_v4(
        &self,
        operation: OperationId,
        stop: Option<&StopSourceAuthorizationV4<'_>>,
    ) -> Result<Option<(LifecycleProtectedJournalKeyV1, CurrentLifecycleOperationV1<'_>)>, LifecycleProtectedJournalErrorV1> {
        let Some(original) = stop else { return self.current_operation_by_id(operation); };
        let Some((key, model, record, root)) = original.current_data_v4()? else { return Ok(None); };
        if operation != model.operation_id() { return Ok(None); }
        Ok(Some((key, CurrentLifecycleOperationV1::from_protected_current(model, record, root))))
    }

    pub(crate) fn stop_dispatch_receiving_demand_v1(source: &Journal, packet_bytes: usize)
        -> Result<aos_sandbox_model::ResourceVector, crate::ResourceReservationErrorV1> {
        super::provisioning_geometry::stop_dispatch_source_receiving_demand_v1(source, packet_bytes)
    }

    pub(crate) fn prepare_original_stop_dispatch_v1(
        &self, original: &StopSourceAuthorizationV4<'_>,
        binding: aos_sandbox_protocol::domain_ledger::stop_dispatch::LifecycleStopDispatchDataV1,
    ) -> Result<PreparedSourceLifecycleAdmissionV1, LifecycleProtectedJournalErrorV1> {
        use super::super::{LifecycleAuxiliaryPayloadV1, lifecycle_plan_resource_id_v5,
            lifecycle_progress_transaction_id_v1};
        original.require_current_v4()?;
        if original.purpose_v4() != StopSourcePurposeV4::HostDispatch {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        let (key, current) = self.current_operation_by_id_with_stop_selection_v4(
            original.operation_v4(), Some(original))?
            .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        if binding.operation_record() != current.record().digest()
            || binding.source_root() != current.projection_root()
        {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        super::super::durable::require_stop_dispatch_current_v1(&binding, current.operation())
            .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let operation = current.operation().operation_id();
        let transaction = lifecycle_progress_transaction_id_v1(operation, current.record().digest(), b"stop-dispatch-binding");
        let prepared = self.prepare_auxiliary_append_for_current(
            transaction, aos_sandbox_model::ResourceId::from_bytes(transaction),
            lifecycle_plan_resource_id_v5(operation, b"stop-dispatch-operation"),
            lifecycle_plan_resource_id_v5(operation, b"stop-dispatch-request"),
            current.operation().clone(), LifecycleAuxiliaryPayloadV1::StopDispatch(binding))?;
        Ok(PreparedSourceLifecycleAdmissionV1::Prepared {
            key, record: None, prepared: prepared.prepared,
        })
    }

    pub(crate) fn prepare_original_stop_source_v4(
        &self,
        original: &StopSourceAuthorizationV4<'_>,
    ) -> Result<PreparedSourceLifecycleAdmissionV1, LifecycleProtectedJournalErrorV1> {
        original.require_current_v4()?;
        if original.purpose_v4() == StopSourcePurposeV4::Admission {
            return self.prepare_admission_with_stop_selection_v4(
                original.expected_operation_v4()?.clone(), None, Some(original),
            );
        }

        let (key, current) = self.current_operation_by_id_with_stop_selection_v4(original.operation_v4(), Some(original))?
            .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        require_same_lifecycle_admission_v1(original.expected_operation_v4()?, current.operation())?;
        let transaction = original.transaction_v4()?;
        let prepared = match original.purpose_v4() {
            StopSourcePurposeV4::Admission | StopSourcePurposeV4::HostDispatch | StopSourcePurposeV4::Terminal => {
                return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
            }
            StopSourcePurposeV4::BindPlan => {
                let steps = crate::lifecycle::LifecycleSuspensionPlanV1::planned_stop_steps(&current)
                    .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
                self.prepare_plan_binding_with_stop_selection_v4(&key, transaction, steps, None, Some(original))?
            }
            StopSourcePurposeV4::InitialProgress => {
                self.prepare_initial_lifecycle_progress_with_stop_selection_v4(
                    &key, transaction, original.started_at_v4()?, None, Some(original))?
            }
            StopSourcePurposeV4::SemanticReadiness => {
                self.prepare_semantic_commit_readiness_with_stop_selection_v4(
                    &key, transaction, None, Some(original))?
            }
            StopSourcePurposeV4::SemanticCommit => {
                self.prepare_semantic_commit_with_stop_selection_v4(
                    &key, transaction, original.semantic_v4()?.clone(), None, Some(original))?
            }
            StopSourcePurposeV4::Success => {
                self.prepare_successful_effect_progress_with_stop_selection_v5(
                    &key, transaction, original.residual_observation_v4()?,
                    original.started_at_v4()?, None, Some(original))?
            }
            StopSourcePurposeV4::Residual => {
                self.prepare_runtime_stop_residual_progress_with_stop_selection_v4(
                    &key, transaction, original.residual_observation_v4()?,
                    original.started_at_v4()?, None, Some(original))?
            }
            StopSourcePurposeV4::Completing => {
                self.prepare_postcommit_progress_with_stop_selection_v4(
                    &key, transaction, original.started_at_v4()?, None, Some(original))?
            }
        };
        Ok(PreparedSourceLifecycleAdmissionV1::Prepared {
            key,
            record: prepared.record,
            prepared: prepared.prepared,
        })
    }

    pub(crate) fn commit_original_stop_source_v4(
        &mut self,
        prepared: &PreparedSourceLifecycleAdmissionV1,
        original: &StopSourceAuthorizationV4<'_>,
    ) -> Result<SourceLifecycleAdmissionCommitV1, ResidentDomainCommitFailureV1> {
        original.require_current_v4().map_err(|cause|
            ResidentDomainCommitFailureV1::Before(cause.into()))?;
        match prepared {
            PreparedSourceLifecycleAdmissionV1::Replay(_) => Ok(SourceLifecycleAdmissionCommitV1::Replay),
            PreparedSourceLifecycleAdmissionV1::Prepared { prepared, .. } => self.journal
                .commit_resident_prepared(prepared, CacheMutationGateV1::Ordinary)
                .map(SourceLifecycleAdmissionCommitV1::Applied),
        }
    }
}
