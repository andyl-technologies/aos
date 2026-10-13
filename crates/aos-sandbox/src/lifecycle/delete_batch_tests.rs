//! Exercises selected Delete Lifecycle replay using canonical lower DATA.

use aos_sandbox_core::{OperationId, ProjectId};
use aos_sandbox_protocol::domain_ledger::delete_batch::{
    LifecycleDeleteBatchRecordV1, fixture_batch_v1,
};
use aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleResourceV1;

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_core::{DesiredGeneration, ObjectDigest, PrincipalId, ResourceId, Revision, SandboxId};
    use super::super::*;

    // These fixtures exercise codecs and replay only. The test-only private
    // verifier inputs are synthetic DATA, not genuine protected owner custody.
    fn selected_operation() -> LifecycleOperationV1 {
        let sandbox = SandboxId::from_bytes([7; 16]);
        let resource = LifecycleResourceV1::Sandbox(sandbox);
        let state = LifecycleResourceStateDigestV1::commit(b"before");
        let fence = DesiredStateFenceV1::new(
            resource, DesiredGeneration::new(1), Revision::new(1), state,
        ).unwrap();
        let step = LifecycleStepV1::unbound(
            0, LifecycleStepClassV1::PostCommitForward, LifecycleStepDomainV1::Controller,
            LifecycleStepRequestDigestV1::commit(b"pending Delete"), None,
        ).unwrap();

        LifecycleOperationV1::new(
            OperationId::from_bytes([5; 16]), PrincipalId::from_bytes([3; 16]),
            ProjectId::from_bytes([4; 16]), LifecycleIdempotencyDigestV1::commit(b"key"),
            LifecycleIntentV1::DeleteSandbox { sandbox, fence }, LifecycleTimeV1::new(1).unwrap(),
            Revision::new(1), vec![ResourceExpectationV1::present(resource, Revision::new(1), state).unwrap()],
            vec![step], LifecyclePhaseV1::Accepted, 0, 0, None, None, None, None, None, None,
        ).unwrap().select_delete_batch_layout().unwrap()
    }

    fn planned_record() -> LifecycleDeleteBatchRecordV1 {
        let bytes = fixture_batch_v1(b"projection", b"retained before", 1);
        let mut payload = vec![1, 0, 0, 0];
        payload.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        payload.extend_from_slice(&bytes);
        payload.extend_from_slice(&[0; 64]);
        LifecycleDeleteBatchRecordV1::from_bytes(&payload).unwrap()
    }

    fn planned_join(
        verification: &LifecycleReplayVerificationV1,
    ) -> Vec<LifecycleAuxiliaryRecordV1> {
        let operation = selected_operation();
        let encoded = super::super::format::encode_retained_operation_record(&operation).unwrap();
        let digest = super::super::format::record_digest(&encoded).unwrap();
        let project = operation.project();
        let id = operation.operation_id();
        let join = ResourceId::from_bytes([52; 16]);
        let revision = Revision::new(1);
        let operation_member = LifecycleAuxiliaryRecordV1::proposal(
            project, id, revision, digest, ResourceId::from_bytes([50; 16]), revision, None,
            LifecycleAuxiliaryPayloadV1::Operation(operation), join, None, verification,
        ).unwrap();
        let batch_member = LifecycleAuxiliaryRecordV1::proposal(
            project, id, revision, digest, ResourceId::from_bytes([51; 16]), revision, None,
            LifecycleAuxiliaryPayloadV1::DeleteBatch(planned_record()), join, None, verification,
        ).unwrap();

        bind_lifecycle_atomic_join_v1(vec![operation_member, batch_member]).unwrap()
    }

    // Rebuild proposal DATA without reusing the immutable bound member set.
    fn unbound_fixture_member(
        record: &LifecycleAuxiliaryRecordV1,
        verification: &LifecycleReplayVerificationV1,
    ) -> LifecycleAuxiliaryRecordV1 {
        LifecycleAuxiliaryRecordV1::proposal(
            record.project(),
            record.operation(),
            record.operation_revision(),
            record.operation_record(),
            record.lineage(),
            record.revision(),
            record.predecessor(),
            record.payload().clone(),
            record.atomic_join(),
            record.replay_floor(),
            verification,
        )
        .unwrap()
    }

    fn operation_digest(operation: &LifecycleOperationV1) -> LifecycleRecordDigestV1 {
        let encoded = super::super::format::encode_retained_operation_record(operation).unwrap();
        super::super::format::record_digest(&encoded).unwrap()
    }

    fn bound_successor(operation: &LifecycleOperationV1) -> LifecycleOperationV1 {
        let step = operation.steps()[0]
            .bind(
                LifecycleStepBodyDigestV1::commit(b"bound Delete body"),
                LifecycleStepPlanDigestV1::commit(b"bound Delete plan"),
                None,
                None,
            )
            .unwrap();

        operation
            .successor(
                operation_digest(operation), LifecyclePhaseV1::Accepted, 0, 0,
                vec![step], None, None, None, None, None,
            )
            .unwrap()
            .select_delete_batch_layout()
            .unwrap()
    }

    fn checkpoint_operation(
        operation: &LifecycleOperationV1,
        caller: PrincipalId,
        idempotency: LifecycleIdempotencyDigestV1,
        accepted_at: LifecycleTimeV1,
        revision: Revision,
        predecessor: Option<LifecycleRecordDigestV1>,
        selected: bool,
    ) -> LifecycleOperationV1 {
        let copied = LifecycleOperationV1::new(
            operation.operation_id(),
            caller,
            operation.project(),
            idempotency,
            operation.intent().clone(),
            accepted_at,
            revision,
            operation.expectations().to_vec(),
            operation.steps().to_vec(),
            operation.phase(),
            operation.forward_progress(),
            operation.compensation_progress(),
            operation.method_semantic_commit().cloned(),
            operation.failure(),
            operation.retry(),
            operation.terminal_result(),
            operation.finished_at(),
            predecessor,
        )
        .unwrap();

        if selected {
            copied.select_delete_batch_layout().unwrap()
        } else {
            copied
        }
    }

    fn checkpoint_successor_join(
        before: &[LifecycleAuxiliaryRecordV1],
        operation: LifecycleOperationV1,
        join: u8,
        include_batch: bool,
        verification: &LifecycleReplayVerificationV1,
    ) -> Vec<LifecycleAuxiliaryRecordV1> {
        let previous = &before[0];
        let digest = operation_digest(&operation);
        let operation_member = LifecycleAuxiliaryRecordV1::proposal(
            operation.project(),
            operation.operation_id(),
            operation.record_revision(),
            digest,
            previous.lineage(),
            previous.revision().checked_next().unwrap(),
            Some(previous.complete_digest()),
            LifecycleAuxiliaryPayloadV1::Operation(operation),
            ResourceId::from_bytes([join; 16]),
            None,
            verification,
        )
        .unwrap();
        let mut records = vec![operation_member];

        if include_batch {
            let previous = &before[1];
            records.push(LifecycleAuxiliaryRecordV1::proposal(
                previous.project(),
                previous.operation(),
                records[0].operation_revision(),
                digest,
                previous.lineage(),
                previous.revision().checked_next().unwrap(),
                Some(previous.complete_digest()),
                previous.payload().clone(),
                ResourceId::from_bytes([join; 16]),
                None,
                verification,
            ).unwrap());
        }

        bind_lifecycle_atomic_join_v1(records).unwrap()
    }

    #[test]
    fn selected_operation_is_version_separated_before_semantic_commit() {
        let operation = selected_operation();
        let encoded = super::super::format::encode_retained_operation_record(&operation).unwrap();

        assert_eq!(&encoded[..10], b"AOSLIF04\0\x04");
        assert_eq!(decode_operation_record_v1(&encoded).unwrap(), operation);
        assert!(encode_operation_record_v1(&operation).is_err());
    }

    #[test]
    fn planned_auxiliary_join_replays_exactly_and_keeps_original_dependencies() {
        let authority = ObjectDigest::from_bytes([40; 32]);
        let initial = LifecycleReplayVerificationV1::from_verified_authority(authority, vec![], vec![]).unwrap();
        let records = planned_join(&initial);
        let encoded: Vec<_> = records.iter().map(|record| encode_lifecycle_auxiliary_record_v1(record).unwrap()).collect();
        let mut accepted: Vec<_> = records.iter().map(LifecycleAuxiliaryRecordV1::complete_digest).collect();
        accepted.sort();
        let verification = LifecycleReplayVerificationV1::from_verified_authority(authority, accepted, vec![]).unwrap();

        let history = LifecycleAuxiliaryHistoryV1::replay(encoded.iter().map(Vec::as_slice), &verification).unwrap();
        assert_eq!(history.operations().operation(OperationId::from_bytes([5; 16])), Some(&selected_operation()));
        assert!(encoded.iter().all(|bytes| &bytes[..10] == b"AOSLIFA5\0\x03"));
        assert!(history.operations().checkpoint().is_err());
        assert!(LifecycleAuxiliaryHistoryV1::replay(encoded[1..].iter().map(Vec::as_slice), &verification).is_err());
    }

    #[test]
    fn selected_generic_cancellation_and_orphan_operation_refuse() {
        let verification = LifecycleReplayVerificationV1::from_verified_authority(
            ObjectDigest::from_bytes([40; 32]), vec![], vec![],
        ).unwrap();
        let records = planned_join(&verification);
        let mut history = LifecycleAuxiliaryHistoryV1::under_verification(&verification);
        history.apply_atomic_join(&records).unwrap();
        let operation = selected_operation();
        let encoded = super::super::format::encode_retained_operation_record(&operation).unwrap();
        let digest = super::super::format::record_digest(&encoded).unwrap();
        let request = LifecycleCancelRequestV1::new(
            operation.caller(), operation.project(), operation.operation_id(), Revision::new(1),
            digest, LifecycleCancelIdempotencyDigestV1::commit(b"cancel"), LifecycleTimeV1::new(2).unwrap(),
        ).unwrap();

        assert!(history.admit_cancellation(
            request, ResourceId::from_bytes([50; 16]), ResourceId::from_bytes([53; 16]),
            ResourceId::from_bytes([54; 16]), &verification,
        ).is_err());
        let orphan = bind_lifecycle_atomic_join_v1(vec![
            unbound_fixture_member(&records[0], &verification),
        ]).unwrap();
        assert!(LifecycleAuxiliaryHistoryV1::under_verification(&verification).apply_atomic_join(&orphan).is_err());
        assert_eq!(history.operations().operation(operation.operation_id()), Some(&operation));
    }

    #[test]
    fn old_auxiliary_payload_api_cannot_encode_selected_batch_or_operation() {
        assert!(encode_lifecycle_auxiliary_payload_v1(&LifecycleAuxiliaryPayloadV1::DeleteBatch(planned_record())).is_err());
        assert!(encode_lifecycle_auxiliary_payload_v1(&LifecycleAuxiliaryPayloadV1::Operation(selected_operation())).is_err());
    }

    #[test]
    fn committed_native_data_cannot_replace_missing_source_planned_history() {
        let verification = LifecycleReplayVerificationV1::from_verified_authority(
            ObjectDigest::from_bytes([40; 32]), vec![], vec![],
        ).unwrap();
        let mut payload = planned_record().encode().unwrap();
        payload[0] = 2;
        let start = payload.len() - 64;
        payload[start..start + 16].fill(6);
        payload[start + 16..start + 48].fill(9);
        payload[start + 48..start + 56].copy_from_slice(&9_u64.to_be_bytes());
        payload[start + 56..].copy_from_slice(&1000_u64.to_be_bytes());
        let committed = LifecycleDeleteBatchRecordV1::from_bytes(&payload).unwrap();
        let mut records = planned_join(&verification);
        let before = records.pop().unwrap();
        records[0] = unbound_fixture_member(&records[0], &verification);
        let member = LifecycleAuxiliaryRecordV1::proposal(
            before.project(), before.operation(), before.operation_revision(), before.operation_record(),
            before.lineage(), before.revision(), before.predecessor(),
            LifecycleAuxiliaryPayloadV1::DeleteBatch(committed), before.atomic_join(),
            before.replay_floor(), &verification,
        ).unwrap();
        records.push(member);
        let records = bind_lifecycle_atomic_join_v1(records).unwrap();

        assert!(LifecycleAuxiliaryHistoryV1::under_verification(&verification).apply_atomic_join(&records).is_err());
    }

    #[test]
    fn selected_checkpoint_replays_bound_successor_and_exact_repeated_member() {
        let verification = LifecycleReplayVerificationV1::from_verified_authority(
            ObjectDigest::from_bytes([40; 32]), vec![], vec![],
        ).unwrap();
        let mut records = planned_join(&verification);
        let operation = bound_successor(&selected_operation());
        let successor = checkpoint_successor_join(&records, operation.clone(), 53, true, &verification);
        let repeated = checkpoint_successor_join(&successor, operation.clone(), 54, true, &verification);
        records.extend(successor);
        records.extend(repeated);

        let history = LifecycleAuxiliaryHistoryV1::from_checkpoint_records(records, &verification)
            .unwrap();

        assert_eq!(
            history.operations().operation_record(operation.operation_id()),
            Some((&operation, operation_digest(&operation))),
        );
    }

    #[test]
    fn selected_checkpoint_rejects_changed_admission_fields() {
        let verification = LifecycleReplayVerificationV1::from_verified_authority(
            ObjectDigest::from_bytes([40; 32]), vec![], vec![],
        ).unwrap();
        let operation = bound_successor(&selected_operation());
        let mutations = [
            (
                PrincipalId::from_bytes([9; 16]),
                operation.idempotency(),
                operation.accepted_at(),
            ),
            (
                operation.caller(),
                LifecycleIdempotencyDigestV1::commit(b"another key"),
                operation.accepted_at(),
            ),
            (
                operation.caller(),
                operation.idempotency(),
                LifecycleTimeV1::new(2).unwrap(),
            ),
        ];

        for (caller, idempotency, accepted_at) in mutations {
            let changed = checkpoint_operation(
                &operation, caller, idempotency, accepted_at,
                operation.record_revision(), operation.predecessor_digest(), true,
            );
            let mut records = planned_join(&verification);
            let successor = checkpoint_successor_join(&records, changed, 53, true, &verification);
            records.extend(successor);

            assert!(LifecycleAuxiliaryHistoryV1::from_checkpoint_records(records, &verification)
                .is_err());
        }
    }

    #[test]
    fn selected_checkpoint_rejects_disconnected_or_skipped_operation_predecessor() {
        let verification = LifecycleReplayVerificationV1::from_verified_authority(
            ObjectDigest::from_bytes([40; 32]), vec![], vec![],
        ).unwrap();
        let operation = bound_successor(&selected_operation());
        for (revision, predecessor) in [
            (Revision::new(3), operation.predecessor_digest()),
            (operation.record_revision(), Some(operation_digest(&operation))),
        ] {
            let changed = checkpoint_operation(
                &operation, operation.caller(), operation.idempotency(),
                operation.accepted_at(), revision, predecessor, true,
            );
            let mut records = planned_join(&verification);
            let successor = checkpoint_successor_join(&records, changed, 53, true, &verification);
            records.extend(successor);

            assert!(LifecycleAuxiliaryHistoryV1::from_checkpoint_records(records, &verification)
                .is_err());
        }
    }

    #[test]
    fn selected_checkpoint_does_not_ignore_later_operation_only_member() {
        let verification = LifecycleReplayVerificationV1::from_verified_authority(
            ObjectDigest::from_bytes([40; 32]), vec![], vec![],
        ).unwrap();
        let operation = bound_successor(&selected_operation());
        let changed = checkpoint_operation(
            &operation, PrincipalId::from_bytes([9; 16]),
            operation.idempotency(), operation.accepted_at(), operation.record_revision(),
            operation.predecessor_digest(), true,
        );
        let mut records = planned_join(&verification);
        let successor = checkpoint_successor_join(&records, changed, 53, false, &verification);
        assert_eq!(
            (successor[0].declared_members(), successor[0].declared_count()),
            (0x01, 1),
        );
        records.extend(successor);

        assert!(LifecycleAuxiliaryHistoryV1::from_checkpoint_records(records, &verification)
            .is_err());
    }

    #[test]
    fn ordinary_checkpoint_keeps_latest_only_baseline_without_selected_records() {
        let verification = LifecycleReplayVerificationV1::from_verified_authority(
            ObjectDigest::from_bytes([40; 32]), vec![], vec![],
        ).unwrap();
        let selected = bound_successor(&selected_operation());
        let operation = checkpoint_operation(
            &selected, selected.caller(), selected.idempotency(), selected.accepted_at(),
            selected.record_revision(), selected.predecessor_digest(), false,
        );
        let digest = operation_digest(&operation);
        let record = LifecycleAuxiliaryRecordV1::proposal(
            operation.project(),
            operation.operation_id(),
            operation.record_revision(),
            digest,
            ResourceId::from_bytes([50; 16]),
            Revision::new(1),
            None,
            LifecycleAuxiliaryPayloadV1::Operation(operation.clone()),
            ResourceId::from_bytes([52; 16]),
            None,
            &verification,
        )
        .unwrap();
        let records = bind_lifecycle_atomic_join_v1(vec![record]).unwrap();

        let history = LifecycleAuxiliaryHistoryV1::from_checkpoint_records(records, &verification)
            .unwrap();

        assert_eq!(
            history.operations().operation_record(operation.operation_id()),
            Some((&operation, digest)),
        );
    }
}
