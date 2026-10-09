//! Retains the original five historical FUSE DATA regression cases.
use super::*;
use aos_proto::aos::sandbox::v1::{AttachmentPhase, Duration, MutationContext, ReplaceAttachmentRequest};
use aos_sandbox_core::{CapabilityRecord, ChannelBinding, Grant, GrantId, ObjectDescriptor, ObjectDigest, PrincipalId, ProjectId, ResourceId, ResourceKind, Operation, OperationSet, Selector};
use crate::public_api::{method::PublicApiAuditMethodV1, mutation::PublicMutationRequestV1, projection::PublicProjectionPlanV1};
use buffa::Message as _;

use crate as protocol;
mod fixture;

fn fixture() -> ControllerFuseAdmissionCarrierV1 {
    fixture::historical_fixture()
}

fn frame_json(json: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&[0; 6]);
    bytes.extend_from_slice(&(json.len() as u32).to_be_bytes());
    bytes.extend_from_slice(json);
    let digest = Sha256::new()
        .chain_update(DOMAIN)
        .chain_update(&bytes)
        .finalize();
    bytes.extend_from_slice(&digest);
    bytes
}

#[test]
fn controller_fuse_carrier_roundtrip_keeps_ordinary_effect_bytes() {
    let carrier = fixture();
    assert_eq!(
        ControllerFuseAdmissionCarrierV1::decode(carrier.canonical_bytes()).unwrap(),
        Some(carrier.clone())
    );
    assert!(carrier.ordinary_effect().starts_with(b"AOSPME01"));
    assert!(
        ControllerFuseAdmissionCarrierV1::decode(carrier.ordinary_effect())
            .unwrap()
            .is_none()
    );
    let context = PublicMutationContextV1::decode(carrier.ordinary_effect())
        .unwrap()
        .unwrap();
    assert!(super::super::decode_history(carrier.ordinary_effect()).unwrap().unwrap().1.is_none());
    super::super::require_fuse_context(&context, None, &carrier).unwrap();
    assert_eq!(super::super::decode_history(carrier.canonical_bytes()).unwrap().unwrap().1, Some(carrier.clone()));
}

#[test]
fn controller_fuse_carrier_rejects_mixed_versions_noncanonical_json_and_bounds() {
    let carrier = fixture();
    for offset in [8, 10, 16, carrier.canonical.len() - 1] {
        let mut bytes = carrier.canonical.clone();
        bytes[offset] ^= 1;
        assert!(ControllerFuseAdmissionCarrierV1::decode(&bytes).is_err());
    }
    let mut json = serde_json::to_value(&carrier.stored).unwrap();
    json["unknown"] = serde_json::json!(true);
    assert!(
        ControllerFuseAdmissionCarrierV1::decode(&frame_json(&serde_json::to_vec(&json).unwrap()))
            .is_err()
    );
    let spaced = serde_json::to_vec_pretty(&carrier.stored).unwrap();
    assert!(ControllerFuseAdmissionCarrierV1::decode(&frame_json(&spaced)).is_err());
    assert!(
        ControllerFuseAdmissionCarrierV1::decode(&frame_json(&vec![b' '; MAXIMUM_BYTES])).is_err()
    );
}

#[test]
fn controller_fuse_carrier_rejects_foreign_holder_key_policy_and_capability_scope() {
    let carrier = fixture();
    for index in 0..8 {
        let mut stored = carrier.stored.clone();
        match index {
            0 => stored.authority.holder = PrincipalId::from_bytes([30; 16]),
            1 => stored.authority.key_binding = ChannelBinding::new([31; 32]),
            2 => stored.authority.project = ProjectId::from_bytes([32; 16]),
            3 => {
                stored.authority.policy_descriptor = ObjectDescriptor::new(
                    stored.authority.policy_descriptor.media_type().clone(),
                    ObjectDigest::from_bytes([33; 32]),
                    128,
                )
            }
            4 => stored.authority.accepted_wall_seconds = 200,
            5 => {
                let mut draft = stored.authority.capability.claims().clone();
                draft.grants = vec![
                    Grant::new(
                        GrantId::from_bytes([21; 16]),
                        ResourceKind::Tree,
                        OperationSet::one(Operation::ContentRead),
                        Selector::Resource {
                            resource: ResourceId::from_bytes([10; 16]),
                        },
                        false,
                    )
                    .unwrap(),
                ];
                stored.authority.capability = CapabilityRecord::issue(draft).unwrap();
            }
            6 => stored.incarnation = None,
            _ => stored.incarnation = Some(IncarnationId::from_bytes([40; 16])),
        }
        assert!(ControllerFuseAdmissionCarrierV1::from_stored(stored).is_err());
    }
}

#[test]
fn controller_fuse_replace_retains_absent_observation_but_runtime_bound_capability_refuses() {
    let carrier = fixture();
    let mut stored = carrier.stored.clone();
    let request = ReplaceAttachmentRequest {
        attachment_id: carrier.attachment().attachment_id.clone(),
        new_view_id: carrier.original_view().view_id.clone(),
        new_view_revision: carrier.original_view().revision.clone(),
        mutation: Some(MutationContext {
            idempotency_key: vec![13; 16],
            expected_resource_version: vec![11; 32],
            operation_timeout: Some(Duration {
                nanoseconds: 1,
                ..Default::default()
            })
            .into(),
            ..Default::default()
        })
        .into(),
        ..Default::default()
    };
    let encoded = PublicMutationRequestV1::new(
        PublicApiAuditMethodV1::ReplaceAttachment,
        &request.encode_to_vec(),
    )
    .unwrap()
    .encode();
    stored.public_effect =
        PublicMutationContextV1::new(carrier.holder(), carrier.project(), 150, encoded)
            .unwrap()
            .encode()
            .unwrap();
    let mut attachment = carrier.attachment().clone();
    attachment.phase = AttachmentPhase::ATTACHMENT_PHASE_REPLACING.into();
    attachment.desired_generation = 2;
    let desired = PublicProjectionPlanV1::new(
        carrier.project(),
        carrier.operation(),
        PublicProjectionResourceV1::Attachment(attachment),
    )
    .unwrap();
    stored.attachment_value = desired.desired_value().to_vec();
    stored.incarnation = None;
    let mut draft = stored.authority.capability.claims().clone();
    draft.grants = vec![
        Grant::new(
            GrantId::from_bytes([21; 16]),
            ResourceKind::AttachmentSlot,
            OperationSet::one(Operation::Attach),
            Selector::Resource {
                resource: ResourceId::from_bytes([8; 16]),
            },
            false,
        )
        .unwrap(),
    ];
    stored.authority.capability = CapabilityRecord::issue(draft.clone()).unwrap();
    let replacement = ControllerFuseAdmissionCarrierV1::from_stored(stored.clone()).unwrap();
    assert_eq!(replacement.incarnation(), None);

    draft.sandbox = Some(aos_sandbox_core::SandboxId::from_bytes([9; 16]));
    draft.incarnation = Some(IncarnationId::from_bytes([15; 16]));
    draft.assignment_epoch = Some(aos_sandbox_core::AssignmentEpoch::new(12));
    stored.authority.capability = CapabilityRecord::issue(draft).unwrap();
    assert!(ControllerFuseAdmissionCarrierV1::from_stored(stored).is_err());
}

#[test]
fn controller_fuse_carrier_rejects_operation_and_original_view_substitution() {
    let carrier = fixture();
    let mut wrong_operation = carrier.stored.clone();
    wrong_operation.operation = OperationId::from_bytes([41; 16]);
    assert!(ControllerFuseAdmissionCarrierV1::from_stored(wrong_operation).is_err());

    let mut wrong_view = carrier.original_view().clone();
    wrong_view.desired_generation += 1;
    let view_plan = PublicProjectionPlanV1::new(
        carrier.project(),
        OperationId::from_bytes([24; 16]),
        PublicProjectionResourceV1::FilesystemView(wrong_view),
    )
    .unwrap();
    let mut substituted = carrier.stored.clone();
    substituted.original_view_value = view_plan.desired_value().to_vec();
    assert!(ControllerFuseAdmissionCarrierV1::from_stored(substituted).is_err());
}
