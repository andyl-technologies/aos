//! Exercises the real shared pending CAS/barrier on complete companion DATA.

use super::*;
use aos_sandbox_model::{AssignmentEpoch, ObjectDigest, OperationId, ProjectId,
    ResourceId, Revision, SandboxId};
use aos_sandbox_protocol::domain_ledger::delete_batch::{
    DeleteBatchCommitmentsDataV2, DeleteBatchDependencyDataV1,
    DeleteBatchEncodingDataV1, DeleteBatchOwnerCutDataV1,
    DeleteBatchWriteDataV1, native_value_digest,
};
use aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleResourceV1;
use aos_sandbox_protocol::domain_ledger::provisioning_resources::{
    ProvisioningCompanionRetirementDataV2, ProvisioningModeDataV1,
    ProvisioningResourceFieldsV1, ProvisioningResourceRecordsV1, ProvisioningResourceRowKindV1,
};

    fn original() -> ProvisioningResourceRecordsV1 {
        ProvisioningResourceRecordsV1::from_data_v1(ProvisioningResourceFieldsV1 {
            mode: ProvisioningModeDataV1::CreateStopped,
            parent: OperationId::from_bytes([10; 16]),
            publication_operation: OperationId::from_bytes([11; 16]),
            sandbox: SandboxId::from_bytes([12; 16]),
            project: ProjectId::from_bytes([13; 16]),
            assignment: ResourceId::from_bytes([14; 16]),
            reservation: ResourceId::from_bytes([15; 16]),
            epoch: AssignmentEpoch::new(42), reservation_revision: Revision::new(1),
            public_request: ObjectDigest::from_bytes([1; 32]),
            manifest: ObjectDigest::from_bytes([2; 32]),
            source_draft: ObjectDigest::from_bytes([3; 32]),
            root_plan: ObjectDigest::from_bytes([4; 32]),
            child_head: ObjectDigest::from_bytes([5; 32]),
            inclusive_grant: ObjectDigest::from_bytes([6; 32]),
        }).unwrap()
    }

    fn encode(original: ProvisioningResourceRecordsV1, missing_edge: bool,
        generation: u64, include_descriptor: bool) -> Result<codec::LifecycleDeleteBatchV1, aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleModelError>
    {
        let fields = original.fields_v1();
        let assignment = LifecycleResourceV1::Other(fields.assignment);
        let reservation = LifecycleResourceV1::Other(fields.reservation);
        let sandbox = LifecycleResourceV1::Sandbox(fields.sandbox);
        let assignment_key = original.key_v1(ProvisioningResourceRowKindV1::Assignment);
        let reservation_key = original.key_v1(ProvisioningResourceRowKindV1::Reservation);
        let writes = [
            DeleteBatchWriteDataV1 { resource: sandbox, key: b"a-sandbox",
                before_generation: 2, before_digest: [1; 32] },
            DeleteBatchWriteDataV1 { resource: assignment, key: &assignment_key,
                before_generation: generation, before_digest: native_value_digest(
                    &original.encode_v1(ProvisioningResourceRowKindV1::Assignment)) },
            DeleteBatchWriteDataV1 { resource: reservation, key: &reservation_key,
                before_generation: 1, before_digest: native_value_digest(
                    &original.encode_v1(ProvisioningResourceRowKindV1::Reservation)) },
        ];
        let edges = [
            DeleteBatchDependencyDataV1 { dependent: assignment, dependency: sandbox, class: 7 },
            DeleteBatchDependencyDataV1 { dependent: assignment, dependency: reservation, class: 7 },
            DeleteBatchDependencyDataV1 { dependent: reservation, dependency: sandbox, class: 7 },
        ];
        let postorder = [assignment, reservation, sandbox];
        let input = DeleteBatchEncodingDataV1 {
            project: fields.project, operation: OperationId::from_bytes([20; 16]),
            transaction: [21; 16], root: sandbox, flags: 1, before_sequence: 3,
            authority_epoch: 1, commitments: [[1; 32]; 5],
            owners: std::array::from_fn(|_| DeleteBatchOwnerCutDataV1 {
                sequence: 1, count: 1, digest: [2; 32] }),
            writes: &writes, reads: &[], collections: &[],
            dependencies: &edges[..if missing_edge { 2 } else { 3 }], postorder: &postorder,
        };
        let descriptors = [ProvisioningCompanionRetirementDataV2::from_data_v2(
            original, input.operation, input.transaction).unwrap()];
        codec::LifecycleDeleteBatchV1::from_encoding_with_companions_v2(&input,
            DeleteBatchCommitmentsDataV2 { authorization: [3; 32], source: [4; 32],
                controller: [5; 32], initial_six: [6; 32] }, 41,
            &descriptors[..usize::from(include_descriptor)])
    }


#[test]
fn pending_companion_set_preserves_all_three_originals_and_native_cas_requires_parent() {
    let original = original();
    let encoded = encode(original, false, 1, true).unwrap();
    let batch = encoded.view().unwrap();
    let mut state = original.records_v1().into_iter().map(|row|
        ((row.namespace(), row.key().to_vec()), row.value().unwrap().to_vec()))
        .collect::<BTreeMap<_, _>>();
    state.insert((RecordNamespace::DesiredState,
        codec::batch_key(batch.project(), batch.operation())), encoded.as_bytes().to_vec());

    for row in batch.rows(0).filter(|row| row[0] == 9) {
        require_projection(&state, batch, row).unwrap();
    }
    for kind in [ProvisioningResourceRowKindV1::Parent,
        ProvisioningResourceRowKindV1::Assignment, ProvisioningResourceRowKindV1::Reservation]
    {
        let transaction = JournalTransaction::new([31; 16], vec![JournalRecord::delete(
            RecordNamespace::DesiredState, original.key_v1(kind).to_vec())]).unwrap();
        assert!(matches!(validate(&state, &transaction, 10, JournalLimits::default()),
            Err(JournalError::ProtectedBoundary)));
    }

    state.remove(&(RecordNamespace::DesiredState,
        original.key_v1(ProvisioningResourceRowKindV1::Parent).to_vec()));
    for row in batch.rows(0).filter(|row| row[0] == 9) {
        assert!(require_projection(&state, batch, row).is_err());
    }
}
