//! Builds accepted-batch Source facts from original typed access sets.
//!
//! State2 is immutable acceptance and residual cleanup debt. It records no
//! physical deletion. Native callers separately authenticate original state1,
//! the same actual C COMMIT and current Root/Source/C17 before appending it.

use super::*;
use crate::lifecycle::{
    DesiredStateCasV1, DesiredStateDocumentDigestV1, LifecycleCommittedResourceV1,
    LifecycleIntentV1, LifecycleJournalCommitDigestV1, LifecycleMethodSemanticCommitV1,
    LifecycleReadCommitFactV1, LifecycleResourceStateDigestV1, LifecycleSemanticCommitFactV1,
    LifecycleSemanticCommitV1, LifecycleSemanticEvidenceV1, LifecycleTimeV1,
    ResourceExpectedStateV1,
};
use aos_sandbox_core::{DesiredGeneration, RawPairedClockSample};

pub(super) fn successor_v3(
    previous: &LifecycleOperationV1,
    previous_digest: crate::lifecycle::LifecycleRecordDigestV1,
    batch: LifecycleDeleteBatchRecordV1,
    now: RawPairedClockSample,
) -> Result<LifecycleOperationV1, LifecycleModelError> {
    if previous.phase() != LifecyclePhaseV1::ReadyToCommit
        || previous.method_semantic_commit().is_some()
    {
        return Err(LifecycleModelError::InvalidTransition);
    }
    let facts = semantic_commit_v3(previous, batch, now)?;
    previous
        .successor(
            previous_digest,
            LifecyclePhaseV1::Committed,
            previous.forward_progress(),
            previous.compensation_progress(),
            previous.steps().to_vec(),
            Some(facts),
            None,
            None,
            None,
            None,
        )?
        .select_delete_batch_layout()
}

fn semantic_commit_v3(
    operation: &LifecycleOperationV1,
    batch: LifecycleDeleteBatchRecordV1,
    now: RawPairedClockSample,
) -> Result<LifecycleMethodSemanticCommitV1, LifecycleModelError> {
    let invalid = || LifecycleModelError::InvalidModel;
    let view = batch.batch().view()?;
    let LifecycleIntentV1::DeleteSandbox { sandbox, fence } = operation.intent() else {
        return Err(invalid());
    };
    if batch.state() != 2
        || view.project() != operation.project()
        || view.operation() != operation.operation_id()
        || view.root()?
            != aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleResourceV1::Sandbox(
                *sandbox,
            )
    {
        return Err(invalid());
    }
    let encoded = batch.encode()?;
    let cas = DesiredStateCasV1::new(
        fence.resource(),
        fence.expected_generation(),
        Some(DesiredStateDocumentDigestV1::commit(
            fence.resource_state().digest().as_bytes(),
        )),
        DesiredGeneration::new(
            fence
                .expected_generation()
                .get()
                .checked_add(1)
                .ok_or_else(invalid)?,
        ),
        DesiredStateDocumentDigestV1::commit(&encoded),
    )?;
    let mut reads = Vec::new();
    let mut resources = Vec::new();
    reads
        .try_reserve_exact(operation.expectations().len())
        .map_err(|_| LifecycleModelError::Allocation)?;
    resources
        .try_reserve_exact(view.count(0))
        .map_err(|_| LifecycleModelError::Allocation)?;
    for expectation in operation.expectations() {
        let written = view
            .postorder_resources_data_v2()
            .try_fold(false, |written, resource| {
                let resource = resource?;
                Ok::<_, LifecycleModelError>(written || resource == expectation.resource())
            })?;
        if written {
            let ResourceExpectedStateV1::Present { revision, .. } = expectation.expected() else {
                return Err(invalid());
            };
            resources.push(LifecycleCommittedResourceV1::new(
                expectation.resource(),
                expectation.expected(),
                revision.checked_next().map_err(|_| invalid())?,
                LifecycleResourceStateDigestV1::commit(&encoded),
                (expectation.resource() == cas.resource()).then_some(cas.digest()),
            )?);
        } else {
            reads.push(LifecycleReadCommitFactV1::new(
                expectation.resource(),
                expectation.expected(),
            ));
        }
    }
    if resources.len() != view.count(0) {
        return Err(invalid());
    }
    // This is the actual Controller semantic transaction's native position,
    // not a Source revision or replacement for the Source append's own proof.
    let sequence = u64::from_be_bytes(
        batch.native_proof()[48..56]
            .try_into()
            .map_err(|_| invalid())?,
    )
    .checked_add(1)
    .ok_or_else(invalid)?;
    let nanos = u64::try_from(now.wall_seconds())
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .ok_or_else(invalid)?;
    if nanos < operation.accepted_at().get() {
        return Err(invalid());
    }
    let witness = LifecycleSemanticCommitV1::new(
        sequence,
        cas,
        LifecycleJournalCommitDigestV1::commit(batch.native_proof()),
        LifecycleTimeV1::new(nanos)?,
    )?;
    LifecycleMethodSemanticCommitV1::new(
        witness,
        LifecycleSemanticCommitFactV1::DeleteBatch {
            cas,
            reads,
            resources,
            assignments: Vec::new(),
            reservations: Vec::new(),
            batch,
        },
        LifecycleSemanticEvidenceV1::default(),
        operation.intent(),
        operation.expectations(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::*;
    use aos_sandbox_core::{RawClockProvenance, ResourceId};

    fn digest(operation: &LifecycleOperationV1) -> LifecycleRecordDigestV1 {
        let bytes = crate::lifecycle::format::encode_retained_operation_record(operation).unwrap();
        crate::lifecycle::format::record_digest(&bytes).unwrap()
    }

    fn planned() -> LifecycleDeleteBatchRecordV1 {
        let bytes = aos_sandbox_protocol::domain_ledger::delete_batch::fixture_batch_v1(
            b"projection",
            b"retained before",
            1,
        );
        let mut payload = vec![1, 0, 0, 0];
        payload.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        payload.extend_from_slice(&bytes);
        payload.extend_from_slice(&[0; 64]);
        LifecycleDeleteBatchRecordV1::from_bytes(&payload).unwrap()
    }

    fn join(
        previous: Option<&[LifecycleAuxiliaryRecordV1]>,
        operation: &LifecycleOperationV1,
        batch: LifecycleDeleteBatchRecordV1,
        verifier: &LifecycleReplayVerificationV1,
    ) -> Vec<LifecycleAuxiliaryRecordV1> {
        let revision = operation.record_revision();
        let join = ResourceId::from_bytes([60 + revision.get() as u8; 16]);
        let payloads = [
            LifecycleAuxiliaryPayloadV1::Operation(operation.clone()),
            LifecycleAuxiliaryPayloadV1::DeleteBatch(batch),
        ];
        let members = payloads
            .into_iter()
            .enumerate()
            .map(|(index, payload)| {
                let old = previous.map(|records| &records[index]);
                LifecycleAuxiliaryRecordV1::proposal(
                    operation.project(),
                    operation.operation_id(),
                    revision,
                    digest(operation),
                    old.map_or(ResourceId::from_bytes([50 + index as u8; 16]), |old| {
                        old.lineage()
                    }),
                    old.map_or(Revision::new(1), |old| {
                        old.revision().checked_next().unwrap()
                    }),
                    old.map(LifecycleAuxiliaryRecordV1::complete_digest),
                    payload,
                    join,
                    None,
                    verifier,
                )
                .unwrap()
            })
            .collect();
        bind_lifecycle_atomic_join_v1(members).unwrap()
    }

    #[test]
    fn state2_joins_real_planned_chain_and_preserves_physical_cleanup_debt() {
        let verification = LifecycleReplayVerificationV1::from_verified_authority(
            ObjectDigest::from_bytes([40; 32]),
            vec![],
            vec![],
        )
        .unwrap();
        let mut operation = super::super::tests::accepted();
        let planned = planned();
        let mut members = join(None, &operation, planned.clone(), &verification);
        let mut history = LifecycleAuxiliaryHistoryV1::under_verification(&verification);
        history.apply_atomic_join(&members).unwrap();
        let effect = LifecyclePhase6EffectPlanV1::new(
            LifecycleEffectDomainV1::Controller,
            1,
            [7; 16],
            ObjectDigest::from_bytes([20; 32]),
            ObjectDigest::from_bytes([21; 32]),
        )
        .unwrap();
        for phase in [
            DeleteSourceReadinessPhaseV3::Binding,
            DeleteSourceReadinessPhaseV3::Prepared,
            DeleteSourceReadinessPhaseV3::Ready,
        ] {
            operation =
                super::super::successor_for_effect(&operation, digest(&operation), phase, effect)
                    .unwrap();
            members = join(Some(&members), &operation, planned.clone(), &verification);
            history.apply_atomic_join(&members).unwrap();
        }
        let mut native = [0; 64];
        native[..16].copy_from_slice(&planned.batch().view().unwrap().transaction());
        native[16..48].fill(9);
        native[48..56].copy_from_slice(&7_u64.to_be_bytes());
        native[56..].copy_from_slice(&900_u64.to_be_bytes());
        let accepted = planned.controller_committed_data_v3(&native).unwrap();
        let now = RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted([1; 16]).unwrap(),
            [2; 16],
            3,
            10,
        )
        .unwrap();
        let committed =
            successor_v3(&operation, digest(&operation), accepted.clone(), now).unwrap();
        let next = join(Some(&members), &committed, accepted, &verification);

        assert!(
            LifecycleAuxiliaryHistoryV1::under_verification(&verification)
                .apply_atomic_join(&next)
                .is_err()
        );
        let mut changed = native;
        changed[16] ^= 1;
        let mismatched = join(
            Some(&members),
            &committed,
            planned.controller_committed_data_v3(&changed).unwrap(),
            &verification,
        );
        assert!(history.apply_atomic_join(&mismatched).is_err());
        assert_eq!(
            history.operations().operation(operation.operation_id()),
            Some(&operation)
        );
        changed[..16].fill(8);
        assert!(planned.controller_committed_data_v3(&changed).is_err());

        history.apply_atomic_join(&next).unwrap();
        assert_eq!(
            history.operations().operation(committed.operation_id()),
            Some(&committed)
        );
        assert_eq!(committed.phase(), LifecyclePhaseV1::Committed);
        assert_eq!(committed.steps()[0].state(), LifecycleStepStateV1::Planned);
        assert!(committed.steps()[0].forward_attempts().is_empty());
        assert!(committed.terminal_result().is_none());
        assert!(
            matches!(committed.method_semantic_commit().unwrap().facts(),
            LifecycleSemanticCommitFactV1::DeleteBatch { batch, reads, resources, .. }
                if batch.state() == 2 && reads.len() == 1 && resources.len() == 1
                    && reads[0].resource() == operation.expectations()[1].resource()
                    && reads[0].expected() == operation.expectations()[1].expected()
                    && resources[0].successor_revision() == Revision::new(2))
        );

        // Continue the actual accepted history with Operation-only joins.
        // Batch2 is neither rewritten nor replaced with a completion state.
        use super::super::super::completion::{DeleteSourceCompletionPhaseV4 as Phase,
            successor_v4, require_terminal_operation_data_v4};
        let physical = [94; 32];
        let immutable_batch = next[1].clone();
        let mut old = next[0].clone();
        let mut latest = committed.clone();
        for phase in [Phase::Reserve, Phase::Terminal] {
            let successor = successor_v4(&latest, digest(&latest), phase, physical, now).unwrap();
            let member = LifecycleAuxiliaryRecordV1::proposal(successor.project(),
                successor.operation_id(), successor.record_revision(), digest(&successor),
                old.lineage(), old.revision().checked_next().unwrap(), Some(old.complete_digest()),
                LifecycleAuxiliaryPayloadV1::Operation(successor.clone()),
                ResourceId::from_bytes([96 + phase.index_v4() as u8; 16]), None, &verification).unwrap();
            let members = bind_lifecycle_atomic_join_v1(vec![member]).unwrap();
            history.apply_atomic_join(&members).unwrap();
            old = members[0].clone();
            latest = successor;
        }
        require_terminal_operation_data_v4(&committed, &latest, physical).unwrap();
        assert!(require_terminal_operation_data_v4(&committed, &latest, [95; 32]).is_err());
        assert_eq!(latest.method_semantic_commit(), committed.method_semantic_commit());
        assert_eq!(next[1], immutable_batch);
        assert_eq!(history.operations().operation(latest.operation_id()), Some(&latest));
        use aos_sandbox_protocol::domain_ledger::delete_root::source_current::
            require_source_delete_terminal_operation_frame_v4 as select_terminal;
        let encoded = super::super::super::super::format::encode_retained_operation_record(&latest).unwrap();
        let decoded = super::super::super::super::format::decode_operation_record_v1(&encoded).unwrap();
        assert_eq!(decoded, latest);
        require_terminal_operation_data_v4(&committed, &decoded, physical).unwrap();
        // The ordinary model can describe another domain's applied step.
        // That DATA must not select this Controller-only retained layout.
        let step = &latest.steps()[0];
        let foreign_step = LifecycleStepV1::new(
            step.index(), step.class(), LifecycleStepDomainV1::Network,
            step.request(), step.request_body(), step.plan(), None, None, None,
            step.state(), step.forward_attempts().to_vec(), Vec::new(),
            step.result(), None, step.inventory(), None, None,
        ).unwrap();
        let foreign = LifecycleOperationV1::new(
            latest.operation_id(), latest.caller(), latest.project(), latest.idempotency(),
            latest.intent().clone(), latest.accepted_at(), latest.record_revision(),
            latest.expectations().to_vec(), vec![foreign_step], latest.phase(),
            latest.forward_progress(), latest.compensation_progress(),
            latest.method_semantic_commit().cloned(), latest.failure(), latest.retry(),
            latest.terminal_result(), latest.finished_at(), latest.predecessor_digest(),
        ).unwrap();
        assert!(foreign.select_delete_batch_layout().is_err());

        assert_eq!(&select_terminal(&encoded, latest.project().as_bytes(), latest.operation_id().as_bytes()).unwrap(),
            digest(&latest).digest().as_bytes());
        let reserve = successor_v4(&committed, digest(&committed), Phase::Reserve, physical, now).unwrap();
        let reserve_bytes = super::super::super::super::format::encode_retained_operation_record(&reserve).unwrap();
        assert!(select_terminal(&reserve_bytes, latest.project().as_bytes(), latest.operation_id().as_bytes()).is_err());
        assert!(select_terminal(&encoded, &[99; 16], latest.operation_id().as_bytes()).is_err());
        let mut tampered = encoded;
        tampered[750] ^= 1;
        assert!(select_terminal(&tampered, latest.project().as_bytes(), latest.operation_id().as_bytes()).is_err());
    }
}
