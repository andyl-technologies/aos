//! Shared historical DATA fixture compiled only in the two codec/native test modules.
use aos_proto::aos::sandbox::v1::{Attachment, FilesystemView, AttachViewRequest, AttachmentPhase, Duration, MutationContext, ObjectDescriptor as WireDescriptor, Timestamp, ViewMutation, ViewPhase};
use aos_sandbox_core::{AuditId, CapabilityDraft, CapabilityId, CapabilityRecord, ChannelBinding, DelegationLimits, Grant, GrantId, MediaType, ObjectDescriptor, ObjectDigest, Operation, OperationId, OperationSet, PrincipalId, ProjectId, ResourceId, ResourceKind, ResourceVector, Revision, RevocationScopeId, Selector, IncarnationId};
use buffa::Message as _;
use super::protocol::public_api::{method::PublicApiAuditMethodV1, mutation::PublicMutationRequestV1, projection::{PublicProjectionPlanV1, PublicProjectionResourceV1}, public_mutation_context::PublicMutationContextV1, mutation_history::{AdmissionAuthorityV1, ControllerFuseAdmissionCarrierV1}};

pub(super) fn historical_fixture() -> ControllerFuseAdmissionCarrierV1 {
    let project = ProjectId::from_bytes([1; 16]);
    let holder = PrincipalId::from_bytes([2; 16]);
    let operation = OperationId::from_bytes([3; 16]);
    let timestamp = Timestamp {
        seconds: 150,
        ..Default::default()
    };
    let revision = WireDescriptor {
        media_type: "application/vnd.aos.sandbox.view.v1+cbor".to_owned(),
        sha256: vec![4; 32],
        encoded_size: 128,
        ..Default::default()
    };
    let view = FilesystemView {
        view_id: vec![5; 16],
        project_id: project.as_bytes().to_vec(),
        resource_version: vec![6; 32],
        revision: Some(revision.clone()).into(),
        phase: ViewPhase::VIEW_PHASE_READY.into(),
        desired_generation: 7,
        observation_sequence: 1,
        last_successful_reconciliation_time: Some(timestamp.clone()).into(),
        ..Default::default()
    };
    let attachment = Attachment {
        attachment_id: vec![8; 16],
        sandbox_id: vec![9; 16],
        source_view_id: view.view_id.clone(),
        destination_slot_id: vec![10; 16],
        resource_version: vec![11; 32],
        view_revision: Some(revision.clone()).into(),
        mutation: ViewMutation::VIEW_MUTATION_READ_ONLY.into(),
        phase: AttachmentPhase::ATTACHMENT_PHASE_REQUESTED.into(),
        desired_generation: 1,
        source_generation: view.desired_generation,
        observation_sequence: 1,
        assignment_epoch: 12,
        last_successful_reconciliation_time: Some(timestamp).into(),
        ..Default::default()
    };
    let request = AttachViewRequest {
        sandbox_id: attachment.sandbox_id.clone(),
        view_id: view.view_id.clone(),
        view_revision: Some(revision).into(),
        destination_slot_id: attachment.destination_slot_id.clone(),
        mutation_mode: attachment.mutation,
        mutation: Some(MutationContext {
            idempotency_key: vec![13; 16],
            expected_resource_version: vec![14; 32],
            expected_incarnation_id: vec![15; 16],
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
    let encoded =
        PublicMutationRequestV1::new(PublicApiAuditMethodV1::AttachView, &request.encode_to_vec())
            .unwrap()
            .encode();
    let effect = PublicMutationContextV1::new(holder, project, 150, encoded).unwrap();
    let policy_descriptor = ObjectDescriptor::new(
        MediaType::new("application/vnd.aos.sandbox.policy.v1+cbor").unwrap(),
        ObjectDigest::from_bytes([16; 32]),
        128,
    );
    let capability = CapabilityRecord::issue(CapabilityDraft {
        id: CapabilityId::from_bytes([17; 16]),
        issuer: PrincipalId::from_bytes([18; 16]),
        audience: PrincipalId::from_bytes([19; 16]),
        holder,
        channel_binding: ChannelBinding::new([20; 32]),
        root_subject: holder,
        project,
        sandbox: None,
        incarnation: None,
        grants: vec![
            Grant::new(
                GrantId::from_bytes([21; 16]),
                ResourceKind::AttachmentSlot,
                OperationSet::one(Operation::Attach),
                Selector::Resource {
                    resource: ResourceId::from_bytes([10; 16]),
                },
                false,
            )
            .unwrap(),
        ],
        policy_digest: policy_descriptor.digest(),
        assignment_epoch: None,
        not_before: 100,
        expires_at: 200,
        revocation_scope: RevocationScopeId::from_bytes([22; 16]),
        revocation_generation: Revision::new(1),
        delegation: DelegationLimits::new(0, 0, ResourceVector::ZERO),
        parent_decision: AuditId::from_bytes([23; 16]),
    })
    .unwrap();
    let attachment_plan = PublicProjectionPlanV1::new(
        project,
        operation,
        PublicProjectionResourceV1::Attachment(attachment),
    )
    .unwrap();
    let view_plan = PublicProjectionPlanV1::new(
        project,
        OperationId::from_bytes([24; 16]),
        PublicProjectionResourceV1::FilesystemView(view),
    )
    .unwrap();
    ControllerFuseAdmissionCarrierV1::from_stored_parts((
        operation,
        ObjectDigest::from_bytes([25; 32]),
        AdmissionAuthorityV1::from_historical_parts((
            capability,
            holder,
            ChannelBinding::new([20; 32]),
            project,
            150,
            1,
            policy_descriptor,
            1,
            ObjectDigest::from_bytes([26; 32]),
            ObjectDigest::from_bytes([27; 32]),
        )),
        effect.encode().unwrap(),
        attachment_plan.desired_key().to_vec(),
        attachment_plan.desired_value().to_vec(),
        view_plan.desired_key().to_vec(),
        view_plan.desired_value().to_vec(),
        Some(IncarnationId::from_bytes([15; 16])),
    ))
    .unwrap()
}
