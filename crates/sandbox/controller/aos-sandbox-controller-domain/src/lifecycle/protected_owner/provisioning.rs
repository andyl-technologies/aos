//! Shares the canonical first lifecycle admission with the closed Source turn.

use super::*;
use crate::controller_resource_reservation::SourceAdmissionAuthorizationV1;
use crate::protected_domain_journal::ResidentDomainCommitFailureV1;

pub(crate) enum PreparedSourceLifecycleAdmissionV1 {
    Replay(LifecycleProtectedJournalKeyV1),
    Prepared { key: LifecycleProtectedJournalKeyV1, prepared: PreparedLifecycleJournalTransactionV1,
        record: Option<LifecycleRecordDigestV1> },
}

pub(crate) enum SourceLifecycleAdmissionCommitV1 {
    Replay,
    Applied(AppliedLifecycleJournalTransactionV1),
}

impl SourceLifecycleAdmissionCommitV1 {
    pub(crate) fn retire_completed_payloads_v1(&mut self) {
        if let Self::Applied(applied) = self {
            // The first Accepted Intent issues no effect to a later phase.
            // Consume its unused composite only after all external posts; the
            // whole actual transaction/snapshot result remains retained.
            drop(applied.take_postcommit());
        }
    }
}

impl PreparedSourceLifecycleAdmissionV1 {
    pub(crate) fn transaction_v1(&self) -> Option<&crate::JournalTransaction> {
        match self { Self::Prepared { prepared, .. } => Some(prepared.journal_transaction_v1()),
            Self::Replay(_) => None }
    }
}

impl LifecycleProtectedJournalOwnerV1<'_> {
    pub(crate) fn prepare_original_create_source_turn_v1(&self,
        original: &SourceAdmissionAuthorizationV1<'_>,
    ) -> Result<PreparedSourceLifecycleAdmissionV1, LifecycleProtectedJournalErrorV1> {
        use crate::controller_resource_reservation::SourcePurposeV1;

        original.require_current_v1().map_err(LifecycleProtectedJournalErrorV1::from)?;
        let purpose = original.purpose_v1();
        if purpose == SourcePurposeV1::Admission {
            return self.prepare_original_create_source_admission_v1(original);
        }
        let (key, current) = self.current_operation_by_id(original.parent_operation_v1())?
            .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        if current.operation() != original.expected_operation_v1() {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        let transaction = original.transaction_id_v1()?;
        let prepared = match purpose {
            SourcePurposeV1::Admission => return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord),
            SourcePurposeV1::BindPlan => self.prepare_plan_binding_with_source_selection_v1(
                &key, transaction, vec![original.bound_step_v1()?], Some(crate::controller_resource_reservation::SourceAppendBoundaryV1::Create(original)),
            )?,
            SourcePurposeV1::InitialProgress => self.prepare_initial_lifecycle_progress_with_source_selection_v1(
                &key, transaction, original.actual_started_at_v1()?, Some(crate::controller_resource_reservation::SourceAppendBoundaryV1::Create(original)),
            )?,
            SourcePurposeV1::SemanticReadiness => self.prepare_semantic_commit_readiness_with_source_selection_v1(
                &key, transaction, Some(crate::controller_resource_reservation::SourceAppendBoundaryV1::Create(original)),
            )?,
            SourcePurposeV1::SemanticCommit => self.prepare_semantic_commit_with_source_selection_v1(
                &key, transaction, original.semantic_commit_v1()?, Some(crate::controller_resource_reservation::SourceAppendBoundaryV1::Create(original)),
            )?,
            SourcePurposeV1::Completing => self.prepare_postcommit_progress_with_source_selection_v1(
                &key, transaction, original.actual_started_at_v1()?, Some(crate::controller_resource_reservation::SourceAppendBoundaryV1::Create(original)),
            )?,
        };
        Ok(PreparedSourceLifecycleAdmissionV1::Prepared {
            key: original.expected_key_v1()?, record: prepared.record, prepared: prepared.prepared,
        })
    }

    pub(crate) fn prepare_original_create_source_admission_v1(&self,
        original: &SourceAdmissionAuthorizationV1<'_>,
    ) -> Result<PreparedSourceLifecycleAdmissionV1, LifecycleProtectedJournalErrorV1> {
        original.require_current_v1().map_err(LifecycleProtectedJournalErrorV1::from)?;
        self.prepare_admission_with_source_selection_v1(original.expected_operation_v1().clone(), Some(original))
    }

    pub(crate) fn commit_original_create_source_admission_v1(&mut self,
        prepared: &PreparedSourceLifecycleAdmissionV1, original: &SourceAdmissionAuthorizationV1<'_>,
    ) -> Result<SourceLifecycleAdmissionCommitV1, ResidentDomainCommitFailureV1> {
        match prepared {
            PreparedSourceLifecycleAdmissionV1::Replay(_) => Ok(SourceLifecycleAdmissionCommitV1::Replay),
            PreparedSourceLifecycleAdmissionV1::Prepared { prepared, .. } => {
                self.journal.commit_resident_source_prepared_v1(prepared, original)
                    .map(SourceLifecycleAdmissionCommitV1::Applied)
            }
        }
    }

    pub(super) fn prepare_admission_with_source_selection_v1(&self, operation: LifecycleOperationV1,
        source: Option<&SourceAdmissionAuthorizationV1<'_>>,
    ) -> Result<PreparedSourceLifecycleAdmissionV1, LifecycleProtectedJournalErrorV1> {
        self.prepare_admission_with_boundary_v1(operation,
            source.map(crate::controller_resource_reservation::SourceAppendBoundaryV1::Create))
    }

    pub(crate) fn prepare_original_start_source_admission_v1(&self,
        original:&crate::controller_resource_reservation::StartSourceAdmissionAuthorizationV1<'_>,
    )->Result<PreparedSourceLifecycleAdmissionV1,LifecycleProtectedJournalErrorV1> {
        original.require_current_v1()?;
        self.prepare_admission_with_boundary_v1(original.expected_operation_v1().clone(),
            Some(crate::controller_resource_reservation::SourceAppendBoundaryV1::Start(original)))
    }

    pub(crate) fn commit_original_start_source_admission_v1(&mut self,
        prepared:&PreparedSourceLifecycleAdmissionV1,
        original:&crate::controller_resource_reservation::StartSourceAdmissionAuthorizationV1<'_>,
    )->Result<SourceLifecycleAdmissionCommitV1,ResidentDomainCommitFailureV1> {
        match prepared {
            PreparedSourceLifecycleAdmissionV1::Replay(_)=>Ok(SourceLifecycleAdmissionCommitV1::Replay),
            PreparedSourceLifecycleAdmissionV1::Prepared{prepared,..}=>self.journal
                .commit_resident_start_source_prepared_v1(prepared,original)
                .map(SourceLifecycleAdmissionCommitV1::Applied),
        }
    }

    fn prepare_admission_with_boundary_v1(&self,operation:LifecycleOperationV1,
        source:Option<crate::controller_resource_reservation::SourceAppendBoundaryV1<'_>>,
    )->Result<PreparedSourceLifecycleAdmissionV1,LifecycleProtectedJournalErrorV1> {
        self.prepare_admission_with_stop_selection_v4(operation, source, None)
    }

    pub(super) fn prepare_admission_with_stop_selection_v4(&self,operation:LifecycleOperationV1,
        source:Option<crate::controller_resource_reservation::SourceAppendBoundaryV1<'_>>,
        stop: Option<&crate::controller_lifecycle_stop::source::StopSourceAuthorizationV4<'_>>,
    )->Result<PreparedSourceLifecycleAdmissionV1,LifecycleProtectedJournalErrorV1> {
        if operation.phase() != super::LifecyclePhaseV1::Accepted
            || operation.record_revision().get() != 1
            || operation.predecessor_digest().is_some()
        {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }

        let ordinary_projection;
        let projection=match (source, stop) {
            (None, Some(original)) => { original.require_current_v4()?; original.projection_v4()?.0 },
            (Some(crate::controller_resource_reservation::SourceAppendBoundaryV1::Start(original)), _)=>
                original.projection_v1()?.0,
            _=>{ordinary_projection=self.journal.replay()?;&ordinary_projection},
        };
        for envelope in projection.records().iter().filter(|envelope| {
            matches!(
                envelope.key().kind(),
                LifecycleProtectedRecordKindV1::Intent
                    | LifecycleProtectedRecordKindV1::Operation
                    | LifecycleProtectedRecordKindV1::Effect
            )
        }) {
            let reducer = decode_reducer_payload_with_validator::<LifecycleProtectedJournalSchemaV1>(
                envelope.key(),
                envelope.payload(),
                &self.verifier,
            )?;
            let ordinary_current;
            let retained_current;
            let current=match (source, stop) {
                (None, Some(original)) => {
                    retained_current=original.decode_admission_operation_v4(reducer.body())?;
                    retained_current.completed().ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?
                },
                (Some(crate::controller_resource_reservation::SourceAppendBoundaryV1::Start(original)), _)=>{
                    retained_current=original.decode_admission_operation_v1(reducer.body())?;
                    retained_current.completed().ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?
                }
                _=>{ordinary_current=decode_operation_record_v1(reducer.body())
                    .map_err(|_|LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;&ordinary_current},
            };
            if current.caller() != operation.caller()
                || current.project() != operation.project()
                || current.intent().method() != operation.intent().method()
                || current.idempotency() != operation.idempotency()
            {
                continue;
            }
            if current.normalized_request() == operation.normalized_request()
                && current.operation_id() == operation.operation_id()
            {
                if source.is_some() || operation.start_native_origin_v1().is_some()
                    || current.start_native_origin_v1().is_some() {
                    super::require_same_lifecycle_admission_v1(&operation, current)?;
                }
                return Ok(PreparedSourceLifecycleAdmissionV1::Replay(
                    envelope.key().clone(),
                ));
            }
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }

        let subject = aos_sandbox_model::ResourceId::from_bytes(
            crate::lifecycle::protected_journal::lifecycle_journal_subject(operation.intent()),
        );
        let key = crate::lifecycle::lifecycle_protected_key_v1(
            LifecycleProtectedRecordKindV1::Intent,
            operation.project(),
            subject,
            operation.operation_id(),
        )?;
        let envelope = lifecycle_reducer_envelope_v1(
            key.clone(),
            1,
            None,
            LifecycleReducerRecordV1::Operation(&operation),
            &self.verifier,
        )?;
        let prepared = match source {
            Some(crate::controller_resource_reservation::SourceAppendBoundaryV1::Create(original)) =>
                self.journal.plan_with_source_provisioning_v1(operation.operation_id().into_bytes(),vec![envelope],original)?,
            Some(crate::controller_resource_reservation::SourceAppendBoundaryV1::Start(original)) =>
                self.journal.plan_with_start_source_v1(operation.operation_id().into_bytes(),vec![envelope],original)?,
            None => self.journal.plan(operation.operation_id().into_bytes(), vec![envelope])?,
        };
        Ok(PreparedSourceLifecycleAdmissionV1::Prepared { key, prepared, record: None })
    }
}


impl LifecycleProtectedJournalOwnerV1<'_> {
    pub(crate) fn prepare_original_create_terminal_source_v1(&self,
        original: &SourceAdmissionAuthorizationV1<'_>,
    ) -> Result<PreparedSourceLifecycleAdmissionV1, LifecycleProtectedJournalErrorV1> {
        original.require_current_v1().map_err(LifecycleProtectedJournalErrorV1::from)?;
        let (key, current) = self.current_operation_by_id(original.parent_operation_v1())?
            .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let expected = original.expected_operation_v1();
        if current.operation()!=expected || expected.phase()!=super::super::LifecyclePhaseV1::Completing
            || expected.terminal_result().is_some() || expected.method_semantic_commit().is_none() {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        let fields = original.resource_fields_v1();
        let handoff = current.recover_reserved_effect(super::super::LifecycleEffectDomainV1::Controller,
            1, fields.sandbox.into_bytes(), fields.public_request, fields.root_plan)
            .map_err(|_|LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let (acknowledgement, inventory)=original.completion_readback_v1()?;
        let observation=handoff.observe_controller_readback(acknowledgement, inventory)
            .map_err(|_|LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let prepared=self.prepare_successful_effect_progress_with_source_selection_v1(&key,
            original.transaction_id_v1()?, observation, original.actual_started_at_v1()?, Some(crate::controller_resource_reservation::SourceAppendBoundaryV1::Create(original)))?;
        Ok(PreparedSourceLifecycleAdmissionV1::Prepared {key:original.expected_key_v1()?, record:prepared.record, prepared:prepared.prepared})
    }
}


impl SourceLifecycleAdmissionCommitV1 {
    pub(crate) fn completed_resident_backing_bytes_v1(&self) -> Option<usize> {
        match self {
            Self::Replay => Some(0),
            Self::Applied(applied) => applied.completed_resident_backing_bytes_v1(),
        }
    }
}

impl LifecycleProtectedJournalOwnerV1<'_> {
    pub(crate) fn prepare_original_start_source_turn_v2(
        &self, original: &crate::controller_resource_reservation::StartSourceAdmissionAuthorizationV1<'_>,
    ) -> Result<PreparedSourceLifecycleAdmissionV1, LifecycleProtectedJournalErrorV1> {
        use crate::controller_resource_reservation::{StartSourcePurposeV2 as Purpose, SourceAppendBoundaryV1};
        original.require_current_v1()?;
        if original.purpose_v2() == Purpose::Admission {
            return self.prepare_original_start_source_admission_v1(original);
        }
        let (key, current) = self.current_operation_by_id(original.parent_operation_v2())?
            .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        if current.operation() != original.expected_operation_v1() {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        let transaction = original.transaction_id_v1()?;
        let source = Some(SourceAppendBoundaryV1::Start(original));
        let prepared = match original.purpose_v2() {
            Purpose::Admission => return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord),
            Purpose::BindPlan => self.prepare_plan_binding_with_source_selection_v1(
                &key, transaction, vec![original.bound_step_v2()?], source)?,
            Purpose::InitialProgress => self.prepare_initial_lifecycle_progress_with_source_selection_v1(
                &key, transaction, original.actual_started_at_v2()?, source)?,
            Purpose::SemanticReadiness => self.prepare_semantic_commit_readiness_with_source_selection_v1(
                &key, transaction, source)?,
            Purpose::SemanticCommit => self.prepare_semantic_commit_with_source_selection_v1(
                &key, transaction, original.semantic_commit_v2()?, source)?,
            Purpose::Completing => self.prepare_postcommit_progress_with_source_selection_v1(
                &key, transaction, original.actual_started_at_v2()?, source)?,
            Purpose::Terminal => {
                let (request, plan) = original.anchor_commitments_v2()?;
                let handoff = current.recover_reserved_effect(super::super::LifecycleEffectDomainV1::Controller,
                    1, original.q04_v1().sandbox().into_bytes(), request, plan)
                    .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
                let (acknowledgement, inventory) = original.completed_readback_v2()?;
                let observation = handoff.observe_controller_readback(acknowledgement, inventory)
                    .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
                self.prepare_successful_effect_progress_with_source_selection_v1(
                    &key, transaction, observation, original.actual_started_at_v2()?, source)?
            }
        };
        Ok(PreparedSourceLifecycleAdmissionV1::Prepared {
            key: original.expected_key_v1()?, record: prepared.record, prepared: prepared.prepared,
        })
    }
}

impl PreparedSourceLifecycleAdmissionV1 {
    pub(crate) fn original_record_digest_data_v2(&self)
        -> Result<LifecycleRecordDigestV1, crate::JournalError> {
        match self {
            Self::Prepared { record: Some(record), .. } => Ok(*record),
            _ => Err(crate::JournalError::ProtectedBoundary),
        }
    }
}
