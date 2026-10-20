//! Exercises selected Delete Lifecycle replay using canonical lower DATA.

use aos_sandbox_core::{OperationId, ProjectId};
use aos_sandbox_protocol::domain_ledger::delete_batch::{
    LifecycleDeleteBatchRecordV1, fixture_batch_v1,
};
use aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleResourceV1;

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::*;
    use aos_sandbox_core::{
        DesiredGeneration, ObjectDigest, PrincipalId, ResourceId, Revision, SandboxId,
    };

    // These fixtures exercise codecs and replay only. The test-only private
    // verifier inputs are synthetic DATA, not genuine protected owner custody.
    fn selected_operation() -> LifecycleOperationV1 {
        let sandbox = SandboxId::from_bytes([7; 16]);
        let resource = LifecycleResourceV1::Sandbox(sandbox);
        let state = LifecycleResourceStateDigestV1::commit(b"before");
        let fence =
            DesiredStateFenceV1::new(resource, DesiredGeneration::new(1), Revision::new(1), state)
                .unwrap();
        let step = LifecycleStepV1::unbound(
            0,
            LifecycleStepClassV1::PostCommitForward,
            LifecycleStepDomainV1::Controller,
            LifecycleStepRequestDigestV1::commit(b"pending Delete"),
            None,
        )
        .unwrap();

        LifecycleOperationV1::new(
            OperationId::from_bytes([5; 16]),
            PrincipalId::from_bytes([3; 16]),
            ProjectId::from_bytes([4; 16]),
            LifecycleIdempotencyDigestV1::commit(b"key"),
            LifecycleIntentV1::DeleteSandbox { sandbox, fence },
            LifecycleTimeV1::new(1).unwrap(),
            Revision::new(1),
            vec![ResourceExpectationV1::present(resource, Revision::new(1), state).unwrap()],
            vec![step],
            LifecyclePhaseV1::Accepted,
            0,
            0,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap()
        .select_delete_batch_layout()
        .unwrap()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn selected_pending_operation_rejects_a_substituted_public_idempotency_key() {
        let operation = selected_operation();

        assert!(super::super::delete_pending::require_operation_request_v1(&operation, b"key").is_ok());
        assert!(super::super::delete_pending::require_operation_request_v1(&operation, b"different key").is_err());
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
            project,
            id,
            revision,
            digest,
            ResourceId::from_bytes([50; 16]),
            revision,
            None,
            LifecycleAuxiliaryPayloadV1::Operation(operation),
            join,
            None,
            verification,
        )
        .unwrap();
        let batch_member = LifecycleAuxiliaryRecordV1::proposal(
            project,
            id,
            revision,
            digest,
            ResourceId::from_bytes([51; 16]),
            revision,
            None,
            LifecycleAuxiliaryPayloadV1::DeleteBatch(planned_record()),
            join,
            None,
            verification,
        )
        .unwrap();

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
                operation_digest(operation),
                LifecyclePhaseV1::Accepted,
                0,
                0,
                vec![step],
                None,
                None,
                None,
                None,
                None,
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
            records.push(
                LifecycleAuxiliaryRecordV1::proposal(
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
                )
                .unwrap(),
            );
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
        let initial =
            LifecycleReplayVerificationV1::from_verified_authority(authority, vec![], vec![])
                .unwrap();
        let records = planned_join(&initial);
        let encoded: Vec<_> = records
            .iter()
            .map(|record| encode_lifecycle_auxiliary_record_v1(record).unwrap())
            .collect();
        let mut accepted: Vec<_> = records
            .iter()
            .map(LifecycleAuxiliaryRecordV1::complete_digest)
            .collect();
        accepted.sort();
        let verification =
            LifecycleReplayVerificationV1::from_verified_authority(authority, accepted, vec![])
                .unwrap();

        let history =
            LifecycleAuxiliaryHistoryV1::replay(encoded.iter().map(Vec::as_slice), &verification)
                .unwrap();
        assert_eq!(
            history
                .operations()
                .operation(OperationId::from_bytes([5; 16])),
            Some(&selected_operation())
        );
        assert!(
            encoded
                .iter()
                .all(|bytes| &bytes[..10] == b"AOSLIFA5\0\x03")
        );
        assert!(history.operations().checkpoint().is_err());
        assert!(
            LifecycleAuxiliaryHistoryV1::replay(
                encoded[1..].iter().map(Vec::as_slice),
                &verification
            )
            .is_err()
        );
    }

    #[test]
    fn selected_generic_cancellation_and_orphan_operation_refuse() {
        let verification = LifecycleReplayVerificationV1::from_verified_authority(
            ObjectDigest::from_bytes([40; 32]),
            vec![],
            vec![],
        )
        .unwrap();
        let records = planned_join(&verification);
        let mut history = LifecycleAuxiliaryHistoryV1::under_verification(&verification);
        history.apply_atomic_join(&records).unwrap();
        let operation = selected_operation();
        let encoded = super::super::format::encode_retained_operation_record(&operation).unwrap();
        let digest = super::super::format::record_digest(&encoded).unwrap();
        let request = LifecycleCancelRequestV1::new(
            operation.caller(),
            operation.project(),
            operation.operation_id(),
            Revision::new(1),
            digest,
            LifecycleCancelIdempotencyDigestV1::commit(b"cancel"),
            LifecycleTimeV1::new(2).unwrap(),
        )
        .unwrap();

        assert!(
            history
                .admit_cancellation(
                    request,
                    ResourceId::from_bytes([50; 16]),
                    ResourceId::from_bytes([53; 16]),
                    ResourceId::from_bytes([54; 16]),
                    &verification,
                )
                .is_err()
        );
        let orphan =
            bind_lifecycle_atomic_join_v1(vec![unbound_fixture_member(&records[0], &verification)])
                .unwrap();
        assert!(
            LifecycleAuxiliaryHistoryV1::under_verification(&verification)
                .apply_atomic_join(&orphan)
                .is_err()
        );
        assert_eq!(
            history.operations().operation(operation.operation_id()),
            Some(&operation)
        );
    }

    #[test]
    fn old_auxiliary_payload_api_cannot_encode_selected_batch_or_operation() {
        assert!(
            encode_lifecycle_auxiliary_payload_v1(&LifecycleAuxiliaryPayloadV1::DeleteBatch(
                planned_record()
            ))
            .is_err()
        );
        assert!(
            encode_lifecycle_auxiliary_payload_v1(&LifecycleAuxiliaryPayloadV1::Operation(
                selected_operation()
            ))
            .is_err()
        );
    }

    #[test]
    fn committed_native_data_cannot_replace_missing_source_planned_history() {
        let verification = LifecycleReplayVerificationV1::from_verified_authority(
            ObjectDigest::from_bytes([40; 32]),
            vec![],
            vec![],
        )
        .unwrap();
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
            before.project(),
            before.operation(),
            before.operation_revision(),
            before.operation_record(),
            before.lineage(),
            before.revision(),
            before.predecessor(),
            LifecycleAuxiliaryPayloadV1::DeleteBatch(committed),
            before.atomic_join(),
            before.replay_floor(),
            &verification,
        )
        .unwrap();
        records.push(member);
        let records = bind_lifecycle_atomic_join_v1(records).unwrap();

        assert!(
            LifecycleAuxiliaryHistoryV1::under_verification(&verification)
                .apply_atomic_join(&records)
                .is_err()
        );
    }

    #[test]
    fn selected_checkpoint_replays_bound_successor_and_exact_repeated_member() {
        let verification = LifecycleReplayVerificationV1::from_verified_authority(
            ObjectDigest::from_bytes([40; 32]),
            vec![],
            vec![],
        )
        .unwrap();
        let mut records = planned_join(&verification);
        let operation = bound_successor(&selected_operation());
        let successor =
            checkpoint_successor_join(&records, operation.clone(), 53, true, &verification);
        let repeated =
            checkpoint_successor_join(&successor, operation.clone(), 54, true, &verification);
        records.extend(successor);
        records.extend(repeated);

        let history =
            LifecycleAuxiliaryHistoryV1::from_checkpoint_records(records, &verification).unwrap();

        assert_eq!(
            history
                .operations()
                .operation_record(operation.operation_id()),
            Some((&operation, operation_digest(&operation))),
        );
    }

    #[test]
    fn selected_checkpoint_rejects_changed_admission_fields() {
        let verification = LifecycleReplayVerificationV1::from_verified_authority(
            ObjectDigest::from_bytes([40; 32]),
            vec![],
            vec![],
        )
        .unwrap();
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
                &operation,
                caller,
                idempotency,
                accepted_at,
                operation.record_revision(),
                operation.predecessor_digest(),
                true,
            );
            let mut records = planned_join(&verification);
            let successor = checkpoint_successor_join(&records, changed, 53, true, &verification);
            records.extend(successor);

            assert!(
                LifecycleAuxiliaryHistoryV1::from_checkpoint_records(records, &verification)
                    .is_err()
            );
        }
    }

    #[test]
    fn selected_checkpoint_rejects_disconnected_or_skipped_operation_predecessor() {
        let verification = LifecycleReplayVerificationV1::from_verified_authority(
            ObjectDigest::from_bytes([40; 32]),
            vec![],
            vec![],
        )
        .unwrap();
        let operation = bound_successor(&selected_operation());
        for (revision, predecessor) in [
            (Revision::new(3), operation.predecessor_digest()),
            (
                operation.record_revision(),
                Some(operation_digest(&operation)),
            ),
        ] {
            let changed = checkpoint_operation(
                &operation,
                operation.caller(),
                operation.idempotency(),
                operation.accepted_at(),
                revision,
                predecessor,
                true,
            );
            let mut records = planned_join(&verification);
            let successor = checkpoint_successor_join(&records, changed, 53, true, &verification);
            records.extend(successor);

            assert!(
                LifecycleAuxiliaryHistoryV1::from_checkpoint_records(records, &verification)
                    .is_err()
            );
        }
    }

    #[test]
    fn selected_checkpoint_does_not_ignore_later_operation_only_member() {
        let verification = LifecycleReplayVerificationV1::from_verified_authority(
            ObjectDigest::from_bytes([40; 32]),
            vec![],
            vec![],
        )
        .unwrap();
        let operation = bound_successor(&selected_operation());
        let changed = checkpoint_operation(
            &operation,
            PrincipalId::from_bytes([9; 16]),
            operation.idempotency(),
            operation.accepted_at(),
            operation.record_revision(),
            operation.predecessor_digest(),
            true,
        );
        let mut records = planned_join(&verification);
        let successor = checkpoint_successor_join(&records, changed, 53, false, &verification);
        assert_eq!(
            (
                successor[0].declared_members(),
                successor[0].declared_count()
            ),
            (0x01, 1),
        );
        records.extend(successor);

        assert!(
            LifecycleAuxiliaryHistoryV1::from_checkpoint_records(records, &verification).is_err()
        );
    }

    #[test]
    fn ordinary_checkpoint_keeps_latest_only_baseline_without_selected_records() {
        let verification = LifecycleReplayVerificationV1::from_verified_authority(
            ObjectDigest::from_bytes([40; 32]),
            vec![],
            vec![],
        )
        .unwrap();
        let selected = bound_successor(&selected_operation());
        let operation = checkpoint_operation(
            &selected,
            selected.caller(),
            selected.idempotency(),
            selected.accepted_at(),
            selected.record_revision(),
            selected.predecessor_digest(),
            false,
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

        let history =
            LifecycleAuxiliaryHistoryV1::from_checkpoint_records(records, &verification).unwrap();

        assert_eq!(
            history
                .operations()
                .operation_record(operation.operation_id()),
            Some((&operation, digest)),
        );
    }
    #[test]
    fn source_batch2_observer_binds_real_commit_eof_without_claiming_operation_validation() {
        use aos_sandbox_protocol::domain_ledger::{
            delete_batch::encode_native_commit_data_v1,
            delete_root::source_current::{SourceDeleteCurrentPurposeDataV3 as Purpose,
                SourceDeleteCurrentQueryDataV1, source_delete_controller_committed_batch_digest_v3},
            lifecycle_auxiliary::{LifecycleAuxiliaryFrameDataV1, borrow_lifecycle_auxiliary_member_data_v1},
            records::{encode_durable_member, domain_transaction_set_digest},
            transaction::{JournalRecord, JournalTransaction, JournalLimits, encode_transaction},
        };
        use crate::lifecycle::protected_journal::{LifecycleProtectedJournalSchemaV1 as Schema,
            LifecycleProtectedRecordKindV1 as Kind, LifecycleReducerRecordV1,
            lifecycle_protected_key_v1, lifecycle_reducer_envelope_v1};
        use aos_sandbox_broker::canonical_journal::{CanonicalReplayOriginalV1,
            coordinator::indexed_replay::{CanonicalIndexedReplayV1, CanonicalReplayIndexOriginalsV1}};
        use aos_sandbox_ledger_replay::delete_pending::SourceDeletePendingReplayDataV1;
        use std::io::Write as _;

        let authority = ObjectDigest::from_bytes([40;32]);
        let verifier = LifecycleJournalVerifierV1::from_verified_authority(authority, vec![], vec![]).unwrap();
        let planned = planned_record();
        let native = encode_native_commit_data_v1(planned.batch().view().unwrap().transaction(), 7, 512, &[8;32]).unwrap();
        let committed = planned.controller_committed_data_v3(&native).unwrap();
        let encoded = committed.encode().unwrap();
        let operation = selected_operation();
        // Deliberately omit the Operation companion. The Source observation is
        // only canonical Batch2/native EOF; Domain must still refuse this orphan.
        let auxiliary = LifecycleAuxiliaryRecordV1::proposal(operation.project(), operation.operation_id(),
            operation.record_revision(), operation_digest(&operation), ResourceId::from_bytes([51;16]),
            Revision::new(1), None, LifecycleAuxiliaryPayloadV1::DeleteBatch(committed),
            ResourceId::from_bytes([52;16]), None, verifier.replay()).unwrap();
        let auxiliary_bytes = encode_lifecycle_auxiliary_record_v1(
            &bind_lifecycle_atomic_join_v1(vec![unbound_fixture_member(&planned_join(verifier.replay())[0], verifier.replay()),
                auxiliary]).unwrap()[1]).unwrap();
        let frame = LifecycleAuxiliaryFrameDataV1::decode(&auxiliary_bytes).unwrap();
        assert_eq!(frame.payload, encoded);
        let auxiliary = decode_lifecycle_auxiliary_record_from_protected_envelope_v1(&auxiliary_bytes, verifier.replay()).unwrap();
        assert!(LifecycleAuxiliaryHistoryV1::from_checkpoint_records(vec![auxiliary.clone()], verifier.replay()).is_err());
        let key = lifecycle_protected_key_v1(Kind::Auxiliary, operation.project(), auxiliary.lineage(), operation.operation_id()).unwrap();
        let envelope = lifecycle_reducer_envelope_v1(key.clone(), 1, None,
            LifecycleReducerRecordV1::Auxiliary(&auxiliary), &verifier).unwrap();
        let transaction_id = [54;16];
        let set = domain_transaction_set_digest::<Schema>(transaction_id, std::slice::from_ref(&envelope));
        let member = encode_durable_member::<Schema>(transaction_id, 0, 1, set, envelope).unwrap();
        assert_eq!(borrow_lifecycle_auxiliary_member_data_v1(key.as_bytes(), member.encoded(), &transaction_id).unwrap().payload, encoded);
        assert!(borrow_lifecycle_auxiliary_member_data_v1(key.as_bytes(), member.encoded(), &[55;16]).is_err());
        let planned_transaction = JournalTransaction::new([52;16], vec![JournalRecord::put(
            crate::RecordNamespace::SourceDomainPolicyHold,
            aos_sandbox_ledger_replay::source_policy_hold::DELETE_PENDING_KEY.to_vec(),
            planned.batch().as_bytes().to_vec())]).unwrap();
        let batch_transaction = JournalTransaction::new(transaction_id, vec![JournalRecord::put(
            crate::RecordNamespace::DesiredState, key.as_bytes().to_vec(), member.encoded().to_vec())]).unwrap();
        let query = SourceDeleteCurrentQueryDataV1 { nonce: [1;16], project: *operation.project().as_bytes(),
            operation: *operation.operation_id().as_bytes(), batch: source_delete_controller_committed_batch_digest_v3(&encoded).unwrap(),
            boot: [2;16], started: 100, cutoff: 1000 };
        let limits = JournalLimits { maximum_records_per_transaction: 8, maximum_record_bytes: 1024*1024,
            maximum_key_bytes: 1024, maximum_transaction_bytes: 4*1024*1024, maximum_transactions: 8,
            maximum_materialized_records: 16, maximum_materialized_bytes: 4*1024*1024, maximum_journal_bytes: 4*1024*1024 };
        for append_later in [false, true] {
            let mut file = tempfile::tempfile().unwrap();
            let mut sequence = 1;
            let mut transactions = vec![planned_transaction.clone(), batch_transaction.clone()];
            if append_later { transactions.push(JournalTransaction::new([60;16], vec![JournalRecord::put(
                crate::RecordNamespace::DesiredState, b"unrelated".to_vec(), b"later".to_vec())]).unwrap()); }
            for transaction in transactions {
                let frames = encode_transaction(&transaction, sequence).unwrap();
                sequence += frames.len() as u64;
                for frame in frames { file.write_all(&frame).unwrap(); }
            }
            let end = file.metadata().unwrap().len();
            let mut replay = CanonicalReplayOriginalV1::new();
            let mut index_original = CanonicalReplayIndexOriginalsV1::new();
            let mut index = std::collections::BTreeMap::new();
            let cursor = replay.begin_semantic_cursor_once(&mut file, limits, end).unwrap();
            let mut cursor = CanonicalIndexedReplayV1::from_supplied_data_v1(cursor, &mut index, &mut index_original);
            let mut observer = SourceDeletePendingReplayDataV1::new_for_purpose_v3(query, Purpose::ControllerCommitted);
            while cursor.advance_once().unwrap() {
                cursor.validate_compaction_once().unwrap();
                cursor.register_and_compare_index_once().unwrap();
                cursor.prepare_change_once().unwrap();
                while cursor.apply_next_record_once().unwrap() {}
                cursor.finish_commit_accounting_once().unwrap();

                observer.observe_commit(cursor.current_commit().unwrap()).unwrap();
                cursor.finish_commit_once().unwrap();
            }
            let result = observer.finish_prefix(cursor.completed_prefix().unwrap(), end);
            assert_eq!(result.is_ok(), !append_later);
            assert!(observer.proof(query).is_err());
            if !append_later {
                let proof = observer.proof_for_purpose_v3(query, Purpose::ControllerCommitted).unwrap();
                assert_eq!(proof[..16], transaction_id);
                assert_eq!(u64::from_be_bytes(proof[56..].try_into().unwrap()), end);
                let mut changed = query; changed.batch[0] ^= 1;
                assert!(observer.proof_for_purpose_v3(changed, Purpose::ControllerCommitted).is_err());
            } else { assert!(observer.proof_for_purpose_v3(query, Purpose::ControllerCommitted).is_err()); }
        }
    }

}
