//! Hostile public-record validation tests for Mount source acquisition.

use super::correlation::proof_class_matches_consistency;
use super::*;

fn complete_record(phase: MountSourceAcquisitionPhase) -> MountSourceAcquisitionRecord {
    let binding_digest = [1; 32];
    let physical_proof = physical_proof(binding_digest, 8, 9, 10);
    let source_root = SourceRootObservationV1::new([7; 16], 8, 9, 10, true, true, true)
        .expect("canonical source-root observation");
    MountSourceAcquisitionRecord {
        phase: phase.into(),
        acquire: Some(
            aos_proto::aos::sandbox::local::v1::MountOperationCorrelation {
                operation_id: vec![25; 16],
                request_digest: vec![26; 32],
                ..Default::default()
            },
        )
        .into(),
        source_binding_digest: binding_digest.to_vec(),
        provider_route_id: vec![11; 16],
        provider_route_generation: 1,
        provider_route_digest: vec![12; 32],
        provider_authority_id: vec![2; 16],
        provider_authority_generation: 1,
        provider_authority_digest: vec![3; 32],
        provider_key_id: vec![13; 16],
        provider_key_generation: 1,
        provider_public_key_digest: vec![14; 32],
        resource_namespace_digest: vec![15; 32],
        provider_resource_id: vec![4; 32],
        provider_resource_generation: 1,
        provider_resource_digest: vec![5; 32],
        provider_catalog_generation: 1,
        provider_catalog_digest: vec![6; 32],
        provider_selection_generation: 1,
        provider_selection_digest: vec![16; 32],
        proof_class: MountSourceProofClass::MOUNT_SOURCE_PROOF_CLASS_IMMUTABLE_TREE.into(),
        provider_proof_digest: vec![17; 32],
        lease_id: vec![18; 16],
        signed_lease_digest: vec![19; 32],
        lease_issued_seconds: 20,
        lease_expires_seconds: 21,
        source_realization_handle: crate::mount_source_realization_handle_v1(
            binding_digest,
            physical_proof,
        )
        .to_vec(),
        source_physical_proof_digest: physical_proof.to_vec(),
        source_kernel_boot_id: vec![7; 16],
        source_device: Some(8),
        source_inode: Some(9),
        source_unique_mount_id: Some(10),
        descriptor_commitment: source_root_descriptor_commitment_v1(&source_root)
            .as_bytes()
            .to_vec(),
        ..Default::default()
    }
}

fn physical_proof(binding_digest: [u8; 32], device: u64, inode: u64, mount: u64) -> [u8; 32] {
    crate::mount_source_physical_proof_digest_v1(crate::MountSourcePhysicalProofV1 {
        binding_digest,
        proof_class: crate::MountSourceProofClassV1::ImmutableTree,
        provider_authority_id: [2; 16],
        provider_authority_generation: 1,
        provider_authority_digest: [3; 32],
        provider_resource_id: [4; 32],
        provider_resource_generation: 1,
        provider_resource_digest: [5; 32],
        provider_catalog_generation: 1,
        provider_catalog_digest: [6; 32],
        kernel_boot_id: [7; 16],
        device,
        inode,
        unique_mount_id: mount,
    })
}

#[test]
fn complete_resource_rejects_proof_and_handle_substitution() {
    let baseline =
        complete_record(MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_ACTIVE);
    assert!(validate_complete_resource_group(&baseline).is_ok());

    let mut changed_proof = baseline.clone();
    changed_proof.source_physical_proof_digest[0] ^= 1;
    assert!(validate_complete_resource_group(&changed_proof).is_err());

    let mut changed_class = baseline;
    changed_class.proof_class =
        MountSourceProofClass::MOUNT_SOURCE_PROOF_CLASS_BEST_EFFORT_REPLICA.into();
    assert!(validate_complete_resource_group(&changed_class).is_err());

    let mut changed_descriptor =
        complete_record(MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_ACTIVE);
    changed_descriptor.descriptor_commitment[0] ^= 1;
    assert!(validate_complete_resource_group(&changed_descriptor).is_err());
}

#[test]
fn inventory_boot_and_unique_mount_rules_apply_only_to_live_rows() {
    let mut historical =
        complete_record(MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_RELEASED);
    historical.source_kernel_boot_id = vec![23; 16];
    assert!(validate_inventory_relations(&[historical], [7; 16]).is_ok());

    let first = complete_record(MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_ACTIVE);
    let mut alias = first.clone();
    alias.acquire.get_or_insert_default().operation_id = vec![27; 16];
    alias.source_device = Some(24);
    alias.source_inode = Some(25);
    let proof = physical_proof([1; 32], 24, 25, 10);
    alias.source_physical_proof_digest = proof.to_vec();
    alias.source_realization_handle =
        crate::mount_source_realization_handle_v1([1; 32], proof).to_vec();

    assert!(validate_inventory_relations(&[first, alias], [7; 16]).is_err());
}

#[test]
fn public_record_acquisition_id_reproduces_from_operation_and_request() {
    let operation_id = [26; 16];
    let request_digest = [27; 32];
    let expected =
        mount_source_acquisition_id_v1(operation_id, ObjectDigest::from_bytes(request_digest));
    assert!(record_acquisition_id_is_exact(
        expected.as_bytes(),
        operation_id,
        request_digest,
    ));

    let mut substituted = *expected.as_bytes();
    substituted[0] ^= 1;
    assert!(!record_acquisition_id_is_exact(
        &substituted,
        operation_id,
        request_digest,
    ));
}

#[test]
fn public_inventory_operation_ids_are_globally_unique() {
    let first = complete_record(MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_ACTIVE);
    let duplicate_acquire = first.clone();
    assert!(validate_inventory_relations(&[first.clone(), duplicate_acquire], [7; 16]).is_err());

    let mut acquire_release = first.clone();
    acquire_release.acquire.get_or_insert_default().operation_id = vec![27; 16];
    acquire_release.release = Some(
        aos_proto::aos::sandbox::local::v1::MountOperationCorrelation {
            operation_id: vec![25; 16],
            request_digest: vec![28; 32],
            ..Default::default()
        },
    )
    .into();
    assert!(validate_inventory_relations(&[first.clone(), acquire_release], [7; 16]).is_err());

    let release = aos_proto::aos::sandbox::local::v1::MountOperationCorrelation {
        operation_id: vec![29; 16],
        request_digest: vec![30; 32],
        ..Default::default()
    };
    let mut first_release = first;
    first_release.release = Some(release.clone()).into();
    let mut second_release = first_release.clone();
    second_release.acquire.get_or_insert_default().operation_id = vec![31; 16];
    second_release.release = Some(release).into();
    assert!(validate_inventory_relations(&[first_release, second_release], [7; 16]).is_err());
}

#[test]
fn every_nonreleased_resource_row_is_boot_scoped() {
    for phase in [
        MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_PENDING_QUERY,
        MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_DESCRIPTOR_CUSTODIED,
        MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_ACTIVE,
        MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_CONSUMED,
        MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_RELEASING,
        MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_FAULTED,
    ] {
        let mut record = complete_record(phase);
        record.source_kernel_boot_id = vec![32; 16];
        assert!(validate_inventory_relations(&[record], [7; 16]).is_err());
    }
}

#[test]
fn release_fence_uses_closed_same_lineage_dominance() {
    let record = ValidatedMountSourceAcquisitionRecord {
        record: MountSourceAcquisitionRecord::default(),
        acquisition_id: [1; 32],
        revision: 1,
        phase: MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_RELEASING,
        acquire_operation_id: [2; 16],
        acquire_request_digest: [3; 32],
        release_operation_id: Some([4; 16]),
        release_request_digest: Some([5; 32]),
        sandbox_id: [6; 16],
        incarnation_id: [7; 16],
        assignment_epoch: 8,
        desired_generation: 9,
        assignment_digest: [10; 32],
        namespace_generation: 1,
        record_digest: [11; 32],
    };
    let mut fence = ValidatedAssignmentFence {
        sandbox_id: record.sandbox_id,
        incarnation_id: record.incarnation_id,
        assignment_epoch: record.assignment_epoch,
        desired_generation: record.desired_generation,
        assignment_digest: record.assignment_digest,
    };
    assert!(release_fence_dominates_record(&record, &fence));

    fence.desired_generation += 1;
    fence.assignment_digest = [12; 32];
    assert!(release_fence_dominates_record(&record, &fence));

    fence.assignment_epoch += 1;
    fence.desired_generation = 1;
    assert!(release_fence_dominates_record(&record, &fence));

    fence.assignment_epoch = record.assignment_epoch - 1;
    fence.desired_generation = u64::MAX;
    assert!(!release_fence_dominates_record(&record, &fence));

    fence.assignment_epoch = record.assignment_epoch;
    fence.desired_generation = record.desired_generation;
    fence.assignment_digest = [13; 32];
    assert!(!release_fence_dominates_record(&record, &fence));

    fence.assignment_digest = record.assignment_digest;
    fence.incarnation_id[0] ^= 1;
    assert!(!release_fence_dominates_record(&record, &fence));
}

#[test]
fn public_inventory_rejects_route_key_and_selection_equivocation() {
    let first = complete_record(MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_ACTIVE);

    let mut changed_key = first.clone();
    changed_key.acquire.get_or_insert_default().operation_id = vec![31; 16];
    changed_key.provider_key_id = vec![32; 16];
    assert!(validate_inventory_relations(&[first.clone(), changed_key], [7; 16]).is_err());

    let mut changed_namespace = first.clone();
    changed_namespace
        .acquire
        .get_or_insert_default()
        .operation_id = vec![33; 16];
    changed_namespace.resource_namespace_digest = vec![34; 32];
    assert!(validate_inventory_relations(&[first.clone(), changed_namespace], [7; 16]).is_err());

    let mut changed_selection_target = first.clone();
    changed_selection_target
        .acquire
        .get_or_insert_default()
        .operation_id = vec![35; 16];
    changed_selection_target.provider_resource_id = vec![36; 32];
    changed_selection_target.provider_resource_digest = vec![37; 32];
    assert!(validate_inventory_relations(&[first, changed_selection_target], [7; 16]).is_err());
}

#[test]
fn provider_proof_class_must_equal_requested_consistency() {
    use aos_proto::aos::sandbox::local::v1::MountSourceConsistency;

    let pairs = [
        (
            MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_IMMUTABLE_REVISION,
            MountSourceProofClass::MOUNT_SOURCE_PROOF_CLASS_IMMUTABLE_TREE,
        ),
        (
            MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_LOCAL_LIVE,
            MountSourceProofClass::MOUNT_SOURCE_PROOF_CLASS_LOCAL_LIVE,
        ),
        (
            MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_BEST_EFFORT_REPLICA,
            MountSourceProofClass::MOUNT_SOURCE_PROOF_CLASS_BEST_EFFORT_REPLICA,
        ),
    ];
    for (consistency, expected) in pairs {
        for candidate in [
            MountSourceProofClass::MOUNT_SOURCE_PROOF_CLASS_IMMUTABLE_TREE,
            MountSourceProofClass::MOUNT_SOURCE_PROOF_CLASS_LOCAL_LIVE,
            MountSourceProofClass::MOUNT_SOURCE_PROOF_CLASS_BEST_EFFORT_REPLICA,
        ] {
            assert_eq!(
                proof_class_matches_consistency(consistency, Some(candidate)),
                candidate == expected,
            );
        }
    }
}
