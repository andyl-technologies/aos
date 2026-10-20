//! Exercises typed provisioning insertion against the existing signed fixture.

use aos_sandbox_core::{PrincipalId, ResourceId, Revision};
use sha2::{Digest as _, Sha256};
use aos_sandbox_protocol::domain_ledger::provisioning_resources::{
    ProvisioningModeDataV1, ProvisioningResourceFieldsV1, ProvisioningResourceRecordsV1,
};

use super::*;

pub(super) fn plan_and_records() -> (OperationPlan, ProvisioningResourceRecordsV1) {
    let (draft, _) = crate::publication::tests::descriptor_free_launch_activation_fixture(1);
    let manifest = draft.manifest();
    let operation = OperationId::from_bytes([61; 16]);
    let records = ProvisioningResourceRecordsV1::from_data_v1(ProvisioningResourceFieldsV1 {
        mode: ProvisioningModeDataV1::StartRunning,
        parent: OperationId::from_bytes([62; 16]),
        publication_operation: operation,
        sandbox: manifest.manifest().sandbox(),
        project: manifest.manifest().project(),
        assignment: ResourceId::from_bytes([63; 16]),
        reservation: ResourceId::from_bytes([64; 16]),
        epoch: manifest.manifest().epoch(),
        reservation_revision: Revision::new(1),
        public_request: ObjectDigest::from_bytes([65; 32]),
        manifest: manifest.digest(),
        source_draft: draft.digest(),
        root_plan: ObjectDigest::from_bytes(Sha256::digest(
            draft.templates()[0].canonical_plan(),
        ).into()),
        child_head: ObjectDigest::from_bytes([66; 32]),
        inclusive_grant: ObjectDigest::from_bytes([67; 32]),
    }).unwrap();
    let effect = aos_sandbox_protocol::publication::bind_authority_publication_effect(
        &draft, draft.templates()[0].digest(),
    ).unwrap();
    let claim = crate::publication::tests::activation_claim(&draft, 1);
    let plan = OperationPlan::ownership_gated(
        operation, IdempotencyKey::new(b"provisioning-plan".to_vec()).unwrap(),
        [68; 32], b"provisioning-plan".to_vec(), b"pending".to_vec(),
        vec![effect], claim, draft,
    ).unwrap().with_runtime_authority(
        RuntimeAuthorityIntentV1::bind_holder(PrincipalId::from_bytes([69; 16]), None).unwrap(),
    ).unwrap();
    (plan, records)
}

#[test]
fn typed_companions_keep_the_complete_existing_plan_and_exact_three_rows() {
    let (plan, records) = plan_and_records();
    let expected = plan.clone();

    let actual = plan.with_provisioning_resource_records_v1(records).unwrap();

    assert_eq!(actual.local_records, records.records_v1());
    assert_eq!(actual.operation_id, expected.operation_id);
    assert_eq!(actual.effects, expected.effects);
    assert_eq!(actual.ownership_gate, expected.ownership_gate);
    assert_eq!(actual.runtime_authority, expected.runtime_authority);
    assert!(actual.clone().with_provisioning_resource_records_v1(records).is_err());
}

#[test]
fn another_root_plan_or_internal_operation_cannot_supply_the_companions() {
    let (plan, records) = plan_and_records();
    let mut fields = records.fields_v1();
    fields.root_plan = ObjectDigest::from_bytes([70; 32]);
    let substituted = ProvisioningResourceRecordsV1::from_data_v1(fields).unwrap();
    assert!(plan.clone().with_provisioning_resource_records_v1(substituted).is_err());

    fields = records.fields_v1();
    fields.publication_operation = OperationId::from_bytes([71; 16]);
    let substituted = ProvisioningResourceRecordsV1::from_data_v1(fields).unwrap();
    assert!(plan.with_provisioning_resource_records_v1(substituted).is_err());
}
