//! Fence-free intent validation without manufacturing live runtime authority.

#![allow(
    clippy::unwrap_used,
    reason = "Fixture construction and regression assertions intentionally panic."
)]

use aos_proto::aos::sandbox::local::v1::{
    ApplyMountRequest, AssignmentFence, Audience, Descriptor, MountAction, MountAttributes,
    MountSourceConsistency,
};

use super::*;

fn create_intent() -> ApplyMountRequest {
    ApplyMountRequest {
        action: MountAction::MOUNT_ACTION_CREATE_DETACHED.into(),
        attachment_id: vec![3; 16],
        destination_slot_id: vec![4; 16],
        view_revision: Some(Descriptor {
            media_type: "application/vnd.aos.sandbox.view.v1+cbor".to_owned(),
            sha256: vec![5; 32],
            encoded_size: 64,
            ..Default::default()
        })
        .into(),
        attributes: Some(MountAttributes {
            read_only: true,
            no_exec: true,
            no_suid: true,
            no_device: true,
            no_atime: true,
            mutation_mode: 0,
            ..Default::default()
        })
        .into(),
        source_generation: 7,
        desired_attachment_generation: 8,
        resource_attachment_generation: 8,
        source_view_id: vec![9; 16],
        source_consistency: MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_IMMUTABLE_REVISION
            .into(),
        attachment_lease_id: vec![10; 16],
        attachment_lease_issued_seconds: 11,
        attachment_lease_expires_seconds: 12,
        ..Default::default()
    }
}

#[test]
fn intent_accepts_only_action_fields_and_keeps_context_unset() {
    let intent = MountCatalogIntentV1::new(create_intent()).unwrap();
    assert!(intent.request.header.as_option().is_none());
    assert!(intent.request.fence.as_option().is_none());
    assert_eq!(intent.request.namespace_generation, 0);
}

#[test]
fn intent_rejects_every_caller_owned_context_field() {
    let mut with_header = create_intent();
    with_header.header = Some(request_header(
        MOUNT_VERSION,
        Audience::AUDIENCE_NODE_CONTROLLER,
        [8; 16],
        9,
    ))
    .into();
    assert!(matches!(
        MountCatalogIntentV1::new(with_header),
        Err(MountCatalogPreparationError::InvalidIntent)
    ));

    let mut with_fence = create_intent();
    with_fence.fence = Some(AssignmentFence {
        sandbox_id: vec![1; 16],
        incarnation_id: vec![2; 16],
        assignment_epoch: 1,
        desired_generation: 1,
        assignment_digest: vec![3; 32],
        ..Default::default()
    })
    .into();
    assert!(matches!(
        MountCatalogIntentV1::new(with_fence),
        Err(MountCatalogPreparationError::InvalidIntent)
    ));

    let mut with_generation = create_intent();
    with_generation.namespace_generation = 1;
    assert!(matches!(
        MountCatalogIntentV1::new(with_generation),
        Err(MountCatalogPreparationError::InvalidIntent)
    ));
}

#[test]
fn intent_rejects_release_and_invalid_mount_shapes() {
    let release = ApplyMountRequest {
        action: MountAction::MOUNT_ACTION_RELEASE.into(),
        attachment_id: vec![3; 16],
        destination_slot_id: vec![4; 16],
        detached_mount_handle: vec![6; 32],
        source_generation: 7,
        desired_attachment_generation: 8,
        resource_attachment_generation: 8,
        source_view_id: vec![9; 16],
        source_consistency: MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_IMMUTABLE_REVISION
            .into(),
        attachment_lease_id: vec![10; 16],
        attachment_lease_issued_seconds: 11,
        attachment_lease_expires_seconds: 12,
        ..Default::default()
    };
    assert!(matches!(
        MountCatalogIntentV1::new(release),
        Err(MountCatalogPreparationError::InvalidIntent)
    ));

    let mut missing_attachment = create_intent();
    missing_attachment.attachment_id.clear();
    assert!(matches!(
        MountCatalogIntentV1::new(missing_attachment),
        Err(MountCatalogPreparationError::Protocol(_))
    ));

    let mut unsupported_mutation = create_intent();
    unsupported_mutation
        .attributes
        .get_or_insert_default()
        .mutation_mode = 5;
    assert!(matches!(
        MountCatalogIntentV1::new(unsupported_mutation),
        Err(MountCatalogPreparationError::Protocol(_))
    ));
}

#[test]
fn pending_replay_preserves_the_exact_body_and_original_deadline() {
    let fence = AssignmentFence {
        sandbox_id: vec![1; 16],
        incarnation_id: vec![2; 16],
        assignment_epoch: 3,
        desired_generation: 4,
        assignment_digest: vec![5; 32],
        ..Default::default()
    };
    let deadline = transport::boottime()
        .unwrap()
        .checked_add(60_000_000_000)
        .unwrap();
    let maximum_deadline = deadline.checked_add(1).unwrap();
    let mut request = create_intent();
    request.header = Some(request_header(
        MOUNT_VERSION,
        Audience::AUDIENCE_NODE_CONTROLLER,
        [6; 16],
        0,
    ))
    .into();
    request.fence = Some(fence.clone()).into();
    request.namespace_generation = 7;
    let body = request.encode_to_vec();

    let (mut replay, action) =
        decode_replay_mount_request(&body, deadline, maximum_deadline, &fence, 7).unwrap();
    assert_eq!(action, MountAction::MOUNT_ACTION_CREATE_DETACHED);
    assert_eq!(
        replay
            .header
            .as_option()
            .unwrap()
            .deadline_boottime_nanoseconds,
        deadline
    );
    replay
        .header
        .get_or_insert_default()
        .deadline_boottime_nanoseconds = 0;
    assert_eq!(replay.encode_to_vec(), body);

    let mut with_deadline = request.clone();
    with_deadline
        .header
        .get_or_insert_default()
        .deadline_boottime_nanoseconds = deadline;
    let mut wrong_fence = request.clone();
    wrong_fence.fence.get_or_insert_default().assignment_epoch += 1;
    let mut wrong_generation = request;
    wrong_generation.namespace_generation += 1;
    let mut trailing = body.clone();
    trailing.push(0);

    for changed in [
        with_deadline.encode_to_vec(),
        wrong_fence.encode_to_vec(),
        wrong_generation.encode_to_vec(),
        trailing,
    ] {
        assert!(matches!(
            decode_replay_mount_request(&changed, deadline, maximum_deadline, &fence, 7),
            Err(MountCatalogPreparationError::ReplayMismatch)
        ));
    }
    for invalid_deadline in [0, maximum_deadline + 1] {
        assert!(matches!(
            decode_replay_mount_request(&body, invalid_deadline, maximum_deadline, &fence, 7),
            Err(MountCatalogPreparationError::Deadline)
        ));
    }
}
