//! Exercises the complete Delete metadata recipe with passive canonical DATA.

use aos_sandbox_api::aos::sandbox::v1::{DeleteSandboxRequest, Duration, MutationContext};
use aos_sandbox_model::{PrincipalId, ResourceId, ResourceKind, Selector};
use buffa::Message as _;

use super::*;
use crate::domain_ledger::operation::{OperationRecord, encode_operation_record};
use crate::domain_ledger::public_operation::PublicOperationAdmissionV1;
use crate::public_api::PublicOperationMethodV1;
use crate::public_api::method::PublicApiAuditMethodV1;
use crate::public_api::mutation::PublicMutationRequestV1;
use crate::public_api::public_mutation_context::PublicMutationContextV1;

fn admission_records(batch: DeleteBatchViewV1<'_>) -> Vec<JournalRecord> {
    let root = batch.bytes()[65..81].to_vec();
    let authorization = PublicOperationAuthorizationV1::new(
        batch.project(),
        ResourceKind::Sandbox,
        Selector::Resource {
            resource: ResourceId::from_bytes(root.as_slice().try_into().unwrap()),
        },
    )
    .unwrap();
    let public = PublicOperationAdmissionV1::new(
        PublicOperationMethodV1::DeleteSandbox,
        2,
        [20; 16],
        100,
        authorization.clone(),
    )
    .unwrap();
    let request = DeleteSandboxRequest {
        sandbox_id: root,
        expected_plan_digest: batch.graph_plan().to_vec(),
        cascade: batch.flags() & 1 != 0,
        force: batch.flags() & 2 != 0,
        mutation: MutationContext {
            idempotency_key: b"delete".to_vec(),
            expected_resource_version: vec![21; 32],
            operation_timeout: Duration {
                nanoseconds: 1,
                ..Default::default()
            }
            .into(),
            ..Default::default()
        }
        .into(),
        ..Default::default()
    };
    let envelope = PublicMutationRequestV1::new(
        PublicApiAuditMethodV1::DeleteSandbox,
        &request.encode_to_vec(),
    )
    .unwrap()
    .encode();
    let context = PublicMutationContextV1::new(
        PrincipalId::from_bytes([22; 16]),
        batch.project(),
        100,
        envelope,
    )
    .unwrap();
    let plan = super::super::effect_history::EffectPlan::from_public_mutation_bytes(
        PublicOperationMethodV1::DeleteSandbox,
        context.encode().unwrap(),
    )
    .unwrap();
    let effect = EffectLedgerRecord::from_parts((plan, EffectState::Planned, None, None));
    let mut idempotency = batch.request_digest().to_vec();
    idempotency.extend_from_slice(batch.operation().as_bytes());

    // Only the metadata relation is under test. Native checks own these local
    // DesiredState rows, their CAS preimages, and the handoff marker separately.
    vec![
        JournalRecord::put(
            RecordNamespace::DesiredState,
            b"batch".to_vec(),
            batch.bytes().to_vec(),
        ),
        JournalRecord::put(
            RecordNamespace::Operation,
            batch.operation().as_bytes().to_vec(),
            encode_operation_record(OperationRecord::new(
                OperationState::Accepted,
                1,
                false,
                None,
                Some(public.durable()),
            )),
        ),
        JournalRecord::put(
            RecordNamespace::Idempotency,
            b"delete".to_vec(),
            idempotency,
        ),
        JournalRecord::put(
            RecordNamespace::PublicOperationAuthorization,
            batch.operation().as_bytes().to_vec(),
            authorization.encode().unwrap(),
        ),
        JournalRecord::put(RecordNamespace::DesiredState, b"local".to_vec(), vec![1]),
        JournalRecord::put(RecordNamespace::DesiredState, b"handoff".to_vec(), vec![1]),
        JournalRecord::put(
            RecordNamespace::Effect,
            effect_key(batch.operation(), 0).to_vec(),
            encode_effect(&effect).unwrap(),
        ),
    ]
}

#[test]
fn complete_delete_metadata_rejects_join_substitution_and_offset_before_decoding() {
    let bytes = codec::fixture_batch_v1(b"projection", b"retained before", 1);
    let batch = DeleteBatchViewV1::decode(&bytes).unwrap();
    let records = admission_records(batch);
    let transaction = JournalTransaction::new(batch.transaction(), records.clone()).unwrap();

    assert!(validate_delete_batch_admission_records_v1(batch, &transaction, 4, 6).is_ok());

    for index in [2, 3, 6] {
        let mut changed = records.clone();
        let mut value = changed[index].value().unwrap().to_vec();
        value[0] ^= 1;
        changed[index] = JournalRecord::put(
            changed[index].namespace(),
            changed[index].key().to_vec(),
            value,
        );
        let transaction = JournalTransaction::new(batch.transaction(), changed).unwrap();
        assert!(validate_delete_batch_admission_records_v1(batch, &transaction, 4, 6).is_err());
    }

    let mut malformed = records;
    malformed[1] = JournalRecord::put(
        RecordNamespace::Operation,
        batch.operation().as_bytes().to_vec(),
        vec![0; OPERATION_RECORD_V2_BYTES],
    );
    let transaction = JournalTransaction::new(batch.transaction(), malformed).unwrap();
    assert!(matches!(
        validate_delete_batch_admission_records_v1(batch, &transaction, 4, 6),
        Err(DeleteAdmissionHistoryErrorV1::Operation(
            PublicOperationDataError::CorruptLedger(_)
        ))
    ));
    assert!(matches!(
        validate_delete_batch_admission_records_v1(batch, &transaction, 4, 5),
        Err(DeleteAdmissionHistoryErrorV1::Effect(
            EffectHistoryDataError::CorruptLedger("invalid Delete batch admission metadata")
        ))
    ));
}
