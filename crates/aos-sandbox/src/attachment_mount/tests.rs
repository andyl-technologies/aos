//! Exact action-to-wire derivation tests without live broker descriptors.

#![allow(
    clippy::unwrap_used,
    reason = "Fixture construction and regression assertions intentionally panic."
)]

use aos_proto::aos::sandbox::local::v1::{
    AssignmentFence, Audience, InventoryMountResourcesResponse, MountAssignmentBinding,
    MountInventoryRecord, MountInventorySourceAuthority, MountKernelObservation,
    MountOperationCorrelation, MountPublicationCorrelation, MountRecipe, MountSourceProofClass,
    RequestHeader,
};
use aos_sandbox_core::model::{
    AttachmentConsistency, AttachmentLease, CacheDomain, CacheDomainKind, MountAttributes, View,
    ViewConsistency, ViewMutation, ViewSource,
};
use aos_sandbox_core::{
    AttachmentId, AttachmentSlotId, CacheDomainId, DesiredGeneration, FeatureRef, IncarnationId,
    LeaseId, MediaType, NamespaceGeneration, ObjectDigest, OperationId, PortableMediaType,
    Revision, SandboxId, ViewId, descriptor_for_bytes, encode_view, encode_view_source,
};
use aos_sandbox_protocol::{
    MountSourcePhysicalProofV1, MountSourceProofClassV1, PeerCredentials, PeerPolicy,
    SourceRealizationBindingV1, decode_mount_inventory_response, decode_mount_request,
    mount_source_physical_proof_digest_v1, mount_source_realization_handle_v1,
};
use buffa::Message as _;

use super::*;

const ATTACHMENT: [u8; 16] = [1; 16];
const SLOT: [u8; 16] = [2; 16];
const CURRENT_HANDLE: [u8; 32] = [11; 32];
const HISTORICAL_HANDLE: [u8; 32] = [12; 32];

fn immutable_view() -> View {
    View::new(
        ViewSource::ImmutableTree {
            tree: ObjectDescriptor::new(
                MediaType::new(PortableMediaType::Tree.as_str()).unwrap(),
                ObjectDigest::from_bytes([24; 32]),
                25,
            ),
        },
        Vec::new(),
        ViewConsistency::Immutable,
        ViewMutation::ReadOnly,
        FeatureRef::new("aos.sandbox.identity.posix32", 1, 0).unwrap(),
        CacheDomain::new(
            CacheDomainKind::Private,
            CacheDomainId::from_bytes([26; 16]),
        ),
        Vec::new(),
    )
    .unwrap()
}

fn intent_descriptor() -> ObjectDescriptor {
    descriptor_for_bytes(
        MediaType::new(PortableMediaType::View.as_str()).unwrap(),
        &encode_view(&immutable_view()),
    )
}

fn journal_with_view() -> (tempfile::TempDir, Journal) {
    let directory = tempfile::tempdir().unwrap();
    let (mut journal, _) = Journal::open(
        directory.path().join("controller.journal"),
        Default::default(),
    )
    .unwrap();
    let mutation = crate::filesystem_view_state::FilesystemViewRevisionMutationV1::new(
        FilesystemViewRevisionPresenceV1::Available,
        ViewId::from_bytes([6; 16]),
        Revision::new(1),
        immutable_view(),
        OperationId::from_bytes([27; 16]),
        ObjectDigest::from_bytes([28; 32]),
        None,
    )
    .unwrap();
    crate::filesystem_view_state::commit(&mut journal, mutation).unwrap();
    (directory, journal)
}

fn intent() -> AttachmentIntent {
    AttachmentIntent::new(
        AttachmentId::from_bytes(ATTACHMENT),
        DesiredGeneration::new(2),
        SandboxId::from_bytes([3; 16]),
        IncarnationId::from_bytes([4; 16]),
        NamespaceGeneration::new(5),
        ViewId::from_bytes([6; 16]),
        Revision::new(1),
        None,
        intent_descriptor(),
        AttachmentSlotId::from_bytes(SLOT),
        AttachmentConsistency::ImmutableRevision,
        ViewMutation::ReadOnly,
        MountAttributes::new(true, false, true, true, true, true),
        AttachmentLease::new(LeaseId::from_bytes([10; 16]), 11, 21).unwrap(),
    )
    .unwrap()
}

fn wire_resource(
    handle: [u8; 32],
    resource_generation: u64,
    source_generation: u64,
    descriptor_digest: [u8; 32],
    source_view: [u8; 16],
    source_incarnation: Option<[u8; 16]>,
    source_consistency: MountSourceConsistency,
) -> MountInventoryRecord {
    let source = match source_consistency {
        MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_IMMUTABLE_REVISION => {
            immutable_view().source().clone()
        }
        MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_LOCAL_LIVE
        | MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_BEST_EFFORT_REPLICA => {
            ViewSource::LiveExport {
                owner_sandbox: SandboxId::from_bytes([29; 16]),
                export: aos_sandbox_core::ExportId::from_bytes([30; 16]),
                source_generation: Revision::new(source_generation),
            }
        }
        _ => immutable_view().source().clone(),
    };
    let source_handle = encode_view_source(&source);
    let (source_proof_class, wire_source_proof_class) = match source_consistency {
        MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_IMMUTABLE_REVISION => (
            MountSourceProofClassV1::ImmutableTree,
            MountSourceProofClass::MOUNT_SOURCE_PROOF_CLASS_IMMUTABLE_TREE,
        ),
        MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_LOCAL_LIVE => (
            MountSourceProofClassV1::LocalLive,
            MountSourceProofClass::MOUNT_SOURCE_PROOF_CLASS_LOCAL_LIVE,
        ),
        MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_BEST_EFFORT_REPLICA => (
            MountSourceProofClassV1::BestEffortReplica,
            MountSourceProofClass::MOUNT_SOURCE_PROOF_CLASS_BEST_EFFORT_REPLICA,
        ),
        _ => unreachable!(),
    };
    let source_binding_digest = SourceRealizationBindingV1::new(
        source_view,
        source_generation,
        ObjectDescriptor::new(
            MediaType::new(PortableMediaType::View.as_str()).unwrap(),
            ObjectDigest::from_bytes(descriptor_digest),
            9,
        ),
        source,
        source_consistency,
        source_incarnation,
    )
    .map(|binding| *binding.digest().as_bytes())
    .unwrap_or([31; 32]);
    let source_physical_proof_digest =
        mount_source_physical_proof_digest_v1(MountSourcePhysicalProofV1 {
            binding_digest: source_binding_digest,
            proof_class: source_proof_class,
            provider_authority_id: [41; 16],
            provider_authority_generation: 42,
            provider_authority_digest: [35; 32],
            provider_resource_id: [36; 32],
            provider_resource_generation: 37,
            provider_resource_digest: [38; 32],
            provider_catalog_generation: 39,
            provider_catalog_digest: [40; 32],
            kernel_boot_id: [14; 16],
            device: 43,
            inode: 44,
            unique_mount_id: 34,
        });
    MountInventoryRecord {
        mount_handle: handle.to_vec(),
        resource_revision: 1,
        binding: Some(MountAssignmentBinding {
            fence: Some(AssignmentFence {
                sandbox_id: vec![3; 16],
                incarnation_id: vec![4; 16],
                assignment_epoch: 2,
                desired_generation: 3,
                assignment_digest: vec![13; 32],
                ..Default::default()
            })
            .into(),
            namespace_generation: 5,
            ..Default::default()
        })
        .into(),
        recipe: Some(MountRecipe {
            attachment_id: ATTACHMENT.to_vec(),
            destination_slot_id: SLOT.to_vec(),
            view_revision: Some(Descriptor {
                media_type: "application/vnd.aos.sandbox.view.v1+cbor".to_owned(),
                sha256: descriptor_digest.to_vec(),
                encoded_size: 9,
                ..Default::default()
            })
            .into(),
            source_generation,
            attributes: Some(WireMountAttributes {
                read_only: true,
                no_exec: false,
                no_suid: true,
                no_device: true,
                no_atime: true,
                mutation_mode: 0,
                recursive: true,
                ..Default::default()
            })
            .into(),
            resource_attachment_generation: resource_generation,
            source_view_id: source_view.to_vec(),
            source_incarnation_id: source_incarnation.map_or_else(Vec::new, |value| value.to_vec()),
            source_consistency: source_consistency.into(),
            source_handle,
            source_authority: MountInventorySourceAuthority::MOUNT_INVENTORY_SOURCE_AUTHORITY_EXACT
                .into(),
            source_binding_digest: source_binding_digest.to_vec(),
            source_realization_handle: mount_source_realization_handle_v1(
                source_binding_digest,
                source_physical_proof_digest,
            )
            .to_vec(),
            source_physical_proof_digest: source_physical_proof_digest.to_vec(),
            source_unique_mount_id: 34,
            source_provider_authority_id: vec![41; 16],
            source_provider_authority_generation: 42,
            source_provider_authority_digest: vec![35; 32],
            source_provider_resource_id: vec![36; 32],
            source_provider_resource_generation: 37,
            source_provider_resource_digest: vec![38; 32],
            source_provider_catalog_generation: 39,
            source_provider_catalog_digest: vec![40; 32],
            source_kernel_boot_id: vec![14; 16],
            source_device: 43,
            source_inode: 44,
            source_proof_class: wire_source_proof_class.into(),
            ..Default::default()
        })
        .into(),
        lifecycle: aos_proto::aos::sandbox::local::v1::MountLifecycle::MOUNT_LIFECYCLE_INSTALLED
            .into(),
        resource_kernel_boot_id: vec![14; 16],
        detached_unique_mount_id: Some(15),
        installed_observation: Some(MountKernelObservation {
            unique_mount_id: 15,
            parent_mount_id: 16,
            mount_namespace_id: 17,
            device_major: 8,
            device_minor: 1,
            superblock_magic: 0xef53,
            superblock_flags: 1,
            mount_attributes: 2,
            propagation: 4,
            root: b"/root".to_vec(),
            mount_point: b"/mnt/view".to_vec(),
            identity_map_digest: vec![18; 32],
            ..Default::default()
        })
        .into(),
        publication: Some(MountPublicationCorrelation {
            operation: Some(MountOperationCorrelation {
                operation_id: vec![19; 16],
                request_digest: vec![20; 32],
                ..Default::default()
            })
            .into(),
            target_mount_namespace_id: 17,
            target_namespace_generation: 5,
            ..Default::default()
        })
        .into(),
        ..Default::default()
    }
}

fn validated_resource(record: MountInventoryRecord) -> ValidatedMountInventoryRecord {
    decode_mount_inventory_response(
        &InventoryMountResourcesResponse {
            kernel_boot_id: vec![14; 16],
            broker_instance_id: vec![21; 16],
            journal_sequence: 1,
            mounts: vec![record],
            ..Default::default()
        }
        .encode_to_vec(),
        16 * 1024 * 1024,
    )
    .unwrap()
    .mounts()[0]
        .clone()
}

fn validate_shape(mut request: ApplyMountRequest) {
    request.header = Some(RequestHeader {
        protocol_major: 2,
        protocol_minor: 0,
        request_id: vec![22; 16],
        audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
        deadline_boottime_nanoseconds: 2,
        maximum_response_bytes: 16 * 1024,
        ..Default::default()
    })
    .into();
    request.fence = Some(AssignmentFence {
        sandbox_id: vec![3; 16],
        incarnation_id: vec![4; 16],
        assignment_epoch: 2,
        desired_generation: 3,
        assignment_digest: vec![13; 32],
        ..Default::default()
    })
    .into();
    request.namespace_generation = 5;

    decode_mount_request(
        &request.encode_to_vec(),
        PeerCredentials {
            uid: 1,
            gid: 1,
            pid: Some(1),
        },
        PeerPolicy {
            uid: 1,
            gid: Some(1),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        },
        1,
    )
    .unwrap();
}

#[test]
fn every_effect_request_is_derived_with_a_valid_closed_shape() {
    let (_directory, journal) = journal_with_view();
    let intent = intent();
    let current = validated_resource(wire_resource(
        CURRENT_HANDLE,
        2,
        1,
        *intent_descriptor().digest().as_bytes(),
        [6; 16],
        None,
        MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_IMMUTABLE_REVISION,
    ));
    let resources = [current];

    let cases = [
        AttachmentReconciliationActionV1::Prepare {
            replacement_mount_handle: Some(HISTORICAL_HANDLE),
        },
        AttachmentReconciliationActionV1::Install {
            mount_handle: CURRENT_HANDLE,
        },
        AttachmentReconciliationActionV1::Replace {
            mount_handle: CURRENT_HANDLE,
            replacement_mount_handle: HISTORICAL_HANDLE,
        },
        AttachmentReconciliationActionV1::Detach {
            mount_handle: CURRENT_HANDLE,
        },
        AttachmentReconciliationActionV1::Release {
            mount_handle: CURRENT_HANDLE,
        },
    ];

    for action in cases {
        let request = request_for_action(&journal, &intent, action, &resources, None).unwrap();
        assert!(request.header.as_option().is_none());
        assert!(request.fence.as_option().is_none());
        assert_eq!(request.namespace_generation, 0);
        assert_eq!(request.desired_attachment_generation, 2);
        assert_eq!(request.attachment_lease_id, vec![10; 16]);
        validate_shape(request);
    }
}

#[test]
fn teardown_reproduces_the_historical_recipe_under_current_desired_authority() {
    let (_directory, journal) = journal_with_view();
    let intent = intent();
    let historical = validated_resource(wire_resource(
        HISTORICAL_HANDLE,
        1,
        30,
        [31; 32],
        [32; 16],
        Some([33; 16]),
        MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_LOCAL_LIVE,
    ));

    for action in [
        AttachmentReconciliationActionV1::Detach {
            mount_handle: HISTORICAL_HANDLE,
        },
        AttachmentReconciliationActionV1::Release {
            mount_handle: HISTORICAL_HANDLE,
        },
    ] {
        let request = request_for_action(
            &journal,
            &intent,
            action,
            std::slice::from_ref(&historical),
            None,
        )
        .unwrap();

        assert_eq!(request.attachment_id, ATTACHMENT);
        assert_eq!(request.destination_slot_id, SLOT);
        assert_eq!(request.desired_attachment_generation, 2);
        assert_eq!(request.resource_attachment_generation, 1);
        assert_eq!(request.source_generation, 30);
        assert_eq!(request.source_view_id, vec![32; 16]);
        assert_eq!(request.source_incarnation_id, vec![33; 16]);
        assert_eq!(
            request.source_consistency.as_known(),
            Some(MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_LOCAL_LIVE)
        );
        assert!(request.view_revision.as_option().is_none());
        assert!(request.attributes.as_option().is_none());
        assert_eq!(request.attachment_lease_id, vec![10; 16]);
        assert_eq!(request.attachment_lease_issued_seconds, 11);
        assert_eq!(request.attachment_lease_expires_seconds, 21);
        validate_shape(request);
    }
}

#[test]
fn missing_resource_and_non_effect_actions_fail_closed() {
    let (_directory, journal) = journal_with_view();
    let intent = intent();
    assert!(matches!(
        request_for_action(
            &journal,
            &intent,
            AttachmentReconciliationActionV1::Install {
                mount_handle: CURRENT_HANDLE,
            },
            &[],
            None,
        ),
        Err(AttachmentMountError::Reconciliation(
            AttachmentReconciliationError::ActionChanged
        ))
    ));
    assert!(matches!(
        request_for_action(
            &journal,
            &intent,
            AttachmentReconciliationActionV1::Verify {
                mount_handle: CURRENT_HANDLE,
                unique_mount_id: 1,
            },
            &[],
            None,
        ),
        Err(AttachmentMountError::NotPreparable)
    ));
}
