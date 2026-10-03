//! Exercises historical claims and the real protected admission/readback join.
//!
//! Capability and TLS facts are synthetic test inputs, not production peer
//! qualification. The journal, projection codec and reconciler are genuine.

use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::Path;

use aos_proto::aos::sandbox::v1::{
    AttachViewRequest, AttachmentPhase, Duration, MutationContext,
    ObjectDescriptor as WireDescriptor, ReplaceAttachmentRequest, Timestamp, ViewMutation,
    ViewPhase,
};
use aos_sandbox_core::{
    AuditId, CapabilityDraft, CapabilityId, CapabilityRecord, ChannelBinding, DelegationLimits,
    Grant, GrantId, MediaType, ObjectDescriptor, Operation, OperationSet, ResourceId, ResourceKind,
    ResourceVector, Revision, RevocationScopeId, Selector,
};
use buffa::Message as _;

use super::*;
use crate::cli_model::{PublicApiAuditMethodV1, PublicMutationRequestV1};
use crate::controller_fuse_admission::AcceptedControllerFuseAdmissionV1;
use crate::controller_query::PublicOperationMethodV1;
use crate::{
    EffectFailure, EffectObservation, EffectPlan, EffectReceipt, IdempotencyKey, JournalLimits,
    JournalRecord, JournalTransaction, OperationPlan, PublicOperationAdmissionV1,
    PublicOperationAuthorizationV1, Reconciler, RecordNamespace, SingleNodeEffectExecutor,
};

fn fixture() -> ControllerFuseAdmissionCarrierV1 {
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
    let effect = PublicMutationEffectV1::new(holder, project, 150, encoded).unwrap();
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
    ControllerFuseAdmissionCarrierV1::from_stored(StoredCarrier {
        operation,
        request_digest: ObjectDigest::from_bytes([25; 32]),
        authority: AdmissionAuthorityV1 {
            capability,
            holder,
            key_binding: ChannelBinding::new([20; 32]),
            project,
            accepted_wall_seconds: 150,
            policy_generation: 1,
            policy_descriptor,
            controller_generation: 1,
            authorization_revision: ObjectDigest::from_bytes([26; 32]),
            authenticated_request: ObjectDigest::from_bytes([27; 32]),
        },
        public_effect: effect.encode_plain().unwrap(),
        attachment_key: attachment_plan.desired_key().to_vec(),
        attachment_value: attachment_plan.desired_value().to_vec(),
        original_view_key: view_plan.desired_key().to_vec(),
        original_view_value: view_plan.desired_value().to_vec(),
        incarnation: Some(IncarnationId::from_bytes([15; 16])),
    })
    .unwrap()
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

struct NoDispatch;

impl SingleNodeEffectExecutor for NoDispatch {
    fn observe(
        &mut self,
        _: OperationId,
        _: u32,
        _: &EffectPlan,
    ) -> Result<EffectObservation, EffectFailure> {
        panic!("admission must not dispatch")
    }

    fn apply(
        &mut self,
        _: OperationId,
        _: u32,
        _: &EffectPlan,
    ) -> Result<EffectReceipt, EffectFailure> {
        panic!("admission must not dispatch")
    }
}

fn admit(
    journal: Journal,
    carrier: &ControllerFuseAdmissionCarrierV1,
    legacy: bool,
) -> Reconciler<NoDispatch> {
    let mut reconciler = Reconciler::new(journal, NoDispatch);
    let context = PublicMutationEffectV1::decode_plain(carrier.ordinary_effect())
        .unwrap()
        .unwrap();
    let context = if legacy {
        context
    } else {
        context.with_fuse_admission(carrier.clone()).unwrap()
    };
    let effect =
        EffectPlan::authorized_public_mutation(PublicOperationMethodV1::AttachView, context)
            .unwrap();
    let plan = OperationPlan::new(
        carrier.operation(),
        IdempotencyKey::new(vec![13; 16]).unwrap(),
        *carrier.request_digest().as_bytes(),
        carrier.stored.attachment_key.clone(),
        carrier.stored.attachment_value.clone(),
        vec![effect],
    )
    .unwrap()
    .with_public_operation(
        PublicOperationAdmissionV1::new(
            PublicOperationMethodV1::AttachView,
            1,
            [28; 16],
            150,
            PublicOperationAuthorizationV1::new(
                carrier.project(),
                ResourceKind::AttachmentSlot,
                Selector::Resource {
                    resource: ResourceId::from_bytes([10; 16]),
                },
            )
            .unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    reconciler
        .journal_mut()
        .commit(
            &JournalTransaction::new(
                [29; 16],
                vec![JournalRecord::put(
                    RecordNamespace::DesiredState,
                    carrier.stored.original_view_key.clone(),
                    carrier.stored.original_view_value.clone(),
                )],
            )
            .unwrap(),
        )
        .unwrap();
    reconciler.accept(&plan).unwrap();
    reconciler
}

fn open(directory: &Path) -> Journal {
    Journal::open_protected_at_uid(
        directory,
        "controller.journal",
        JournalLimits::default(),
        fs::metadata(directory).unwrap().uid(),
    )
    .unwrap()
    .0
}

fn read<'journal>(
    journal: &'journal Journal,
    root: &Path,
    operation: OperationId,
) -> Result<Option<AcceptedControllerFuseAdmissionV1<'journal>>, ControllerFuseAdmissionErrorV1> {
    AcceptedControllerFuseAdmissionV1::read_at_location(
        journal,
        operation,
        crate::controller_fuse_admission::ControllerAdmissionLocationV1 {
            fixture_root: Some(root.to_path_buf()),
        },
    )
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
    let mut context = PublicMutationEffectV1::decode_plain(carrier.ordinary_effect())
        .unwrap()
        .unwrap();
    assert!(context.fuse_admission().is_none());
    context = context.with_fuse_admission(carrier.clone()).unwrap();
    assert_eq!(context.fuse_admission(), Some(&carrier));
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
        PublicMutationEffectV1::new(carrier.holder(), carrier.project(), 150, encoded)
            .unwrap()
            .encode_plain()
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

#[test]
fn controller_fuse_admission_real_atomic_ledger_reopens_and_legacy_refuses() {
    for legacy in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let carrier = fixture();
        let mut reconciler = admit(open(directory.path()), &carrier, legacy);
        let accepted = read(
            reconciler.journal_mut(),
            directory.path(),
            carrier.operation(),
        )
        .unwrap();
        assert_eq!(accepted.is_none(), legacy);
        if let Some(accepted) = accepted {
            assert_eq!(accepted.carrier(), &carrier);
            accepted.recheck().unwrap();
        }
        drop(reconciler);

        let journal = open(directory.path());
        let accepted = read(&journal, directory.path(), carrier.operation()).unwrap();
        assert_eq!(accepted.is_none(), legacy);
        if let Some(accepted) = accepted {
            assert_eq!(accepted.digest(), carrier.digest());
        }
    }
}

#[test]
fn controller_fuse_admission_refuses_foreign_production_path_and_changed_owner_names() {
    for name in ["controller.journal", "controller.journal.lock"] {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let carrier = fixture();
        let mut reconciler = admit(open(directory.path()), &carrier, false);
        let journal = reconciler.journal_mut();
        let sequence = journal.snapshot_sequence();
        assert!(AcceptedControllerFuseAdmissionV1::read(journal, carrier.operation()).is_err());
        let accepted = read(journal, directory.path(), carrier.operation())
            .unwrap()
            .unwrap();
        fs::rename(
            directory.path().join(name),
            directory.path().join("moved-name"),
        )
        .unwrap();
        assert!(accepted.recheck().is_err());
        assert_eq!(journal.snapshot_sequence(), sequence);
    }
}

#[test]
fn controller_fuse_admission_keeps_historical_view_but_refuses_changed_attachment_or_release() {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let carrier = fixture();
    let mut reconciler = admit(open(directory.path()), &carrier, false);
    let mut view = carrier.original_view().clone();
    view.revision.as_option_mut().unwrap().sha256 = vec![34; 32];
    view.desired_generation += 1;
    let latest = PublicProjectionPlanV1::new(
        carrier.project(),
        OperationId::from_bytes([35; 16]),
        PublicProjectionResourceV1::FilesystemView(view.clone()),
    )
    .unwrap();
    reconciler
        .journal_mut()
        .commit(
            &JournalTransaction::new(
                [36; 16],
                vec![JournalRecord::put(
                    RecordNamespace::DesiredState,
                    latest.desired_key().to_vec(),
                    latest.desired_value().to_vec(),
                )],
            )
            .unwrap(),
        )
        .unwrap();
    let accepted = read(
        reconciler.journal_mut(),
        directory.path(),
        carrier.operation(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(accepted.carrier().original_view(), carrier.original_view());
    drop(accepted);

    view.phase = ViewPhase::VIEW_PHASE_RELEASED.into();
    let released = PublicProjectionPlanV1::new(
        carrier.project(),
        OperationId::from_bytes([35; 16]),
        PublicProjectionResourceV1::FilesystemView(view),
    )
    .unwrap();
    reconciler
        .journal_mut()
        .commit(
            &JournalTransaction::new(
                [37; 16],
                vec![JournalRecord::put(
                    RecordNamespace::DesiredState,
                    released.desired_key().to_vec(),
                    released.desired_value().to_vec(),
                )],
            )
            .unwrap(),
        )
        .unwrap();
    assert!(
        read(
            reconciler.journal_mut(),
            directory.path(),
            carrier.operation()
        )
        .is_err()
    );

    // Restore the View so the next rejection independently tests Attachment.
    reconciler
        .journal_mut()
        .commit(
            &JournalTransaction::new(
                [38; 16],
                vec![JournalRecord::put(
                    RecordNamespace::DesiredState,
                    carrier.stored.original_view_key.clone(),
                    carrier.stored.original_view_value.clone(),
                )],
            )
            .unwrap(),
        )
        .unwrap();
    assert!(
        read(
            reconciler.journal_mut(),
            directory.path(),
            carrier.operation()
        )
        .unwrap()
        .is_some()
    );

    let mut attachment = carrier.attachment().clone();
    attachment.assignment_epoch += 1;
    let changed = PublicProjectionPlanV1::new(
        carrier.project(),
        carrier.operation(),
        PublicProjectionResourceV1::Attachment(attachment),
    )
    .unwrap();
    reconciler
        .journal_mut()
        .commit(
            &JournalTransaction::new(
                [39; 16],
                vec![JournalRecord::put(
                    RecordNamespace::DesiredState,
                    changed.desired_key().to_vec(),
                    changed.desired_value().to_vec(),
                )],
            )
            .unwrap(),
        )
        .unwrap();
    assert!(
        read(
            reconciler.journal_mut(),
            directory.path(),
            carrier.operation()
        )
        .is_err()
    );
}
