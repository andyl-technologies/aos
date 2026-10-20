//! Exercises exact typed targets and hostile canonical tombstone comparisons.

use super::*;
use aos_sandbox_api::aos::sandbox::v1 as wire;
use aos_sandbox_model::{ResourceId, SandboxId, ViewId};
use DormantSandboxRequestKindV1 as Request;

fn marker(project: ProjectId, resource: LifecycleResourceV1) -> (Vec<u8>, [u8; 160]) {
    let mut value = [0; 160];
    value[..8].copy_from_slice(b"AOSDTS01");
    value[9] = 1;
    value[10] = 1;
    value[12..28].copy_from_slice(project.as_bytes());
    value[28..44].fill(2);
    value[44..60].fill(3);
    value[60] = resource.code();
    value[61..77].copy_from_slice(resource.as_bytes());
    value[80..88].copy_from_slice(&1_u64.to_be_bytes());
    value[88..96].copy_from_slice(&2_u64.to_be_bytes());
    value[96..128].fill(4);
    super::super::seal(&mut value, super::super::TOMBSTONE_DOMAIN);
    let key = super::super::tombstone_key(project, &value[60..77]);
    (key, value)
}

#[test]
fn execution_and_snapshot_requests_use_their_actual_sandbox_target() {
    let project = ProjectId::from_bytes([1; 16]);
    let sandbox = LifecycleResourceV1::Sandbox(SandboxId::from_bytes([5; 16]));
    let requests = [
        Request::Exec(wire::CreateExecutionRequest { sandbox_id: vec![5; 16], ..Default::default() }),
        Request::Snapshot(wire::CreateSnapshotRequest { sandbox_id: vec![5; 16], ..Default::default() }),
    ];
    let (key, value) = marker(project, sandbox);
    for request in requests {
        assert_eq!(require_public_mutation_targets_live_data_v2(project, &request,
            [(key.as_slice(), value.as_slice())]), Err(PublicMutationNewUseErrorV2::Tombstoned(sandbox)));
    }

    let (other_key, other_value) = marker(project,
        LifecycleResourceV1::Execution(aos_sandbox_model::ExecutionId::from_bytes([5; 16])));
    assert!(require_public_mutation_targets_live_data_v2(project,
        &Request::Exec(wire::CreateExecutionRequest { sandbox_id: vec![5; 16], ..Default::default() }),
        [(other_key.as_slice(), other_value.as_slice())]).is_ok());
}

#[test]
fn attachment_uses_sandbox_and_view_without_treating_slot_as_a_resource() {
    let request = Request::ViewAttach(wire::AttachViewRequest {
        sandbox_id: vec![5; 16], view_id: vec![6; 16], destination_slot_id: vec![7; 16],
        ..Default::default()
    });
    let project = ProjectId::from_bytes([1; 16]);
    for resource in [
        LifecycleResourceV1::Sandbox(SandboxId::from_bytes([5; 16])),
        LifecycleResourceV1::View(ViewId::from_bytes([6; 16])),
    ] {
        let (key, value) = marker(project, resource);
        assert_eq!(require_public_mutation_targets_live_data_v2(project, &request,
            [(key.as_slice(), value.as_slice())]), Err(PublicMutationNewUseErrorV2::Tombstoned(resource)));
    }
    let (key, value) = marker(project, LifecycleResourceV1::Attachment(ResourceId::from_bytes([7; 16])));
    assert!(require_public_mutation_targets_live_data_v2(project, &request,
        [(key.as_slice(), value.as_slice())]).is_ok());
}

#[test]
fn every_targeted_mutation_selects_concrete_typed_ids() {
    let sandbox = Some(LifecycleResourceV1::Sandbox(SandboxId::from_bytes([5; 16])));
    let view = Some(LifecycleResourceV1::View(ViewId::from_bytes([6; 16])));
    let attachment = Some(LifecycleResourceV1::Attachment(ResourceId::from_bytes([7; 16])));
    let snapshot = Some(LifecycleResourceV1::Snapshot(aos_sandbox_model::SnapshotId::from_bytes([8; 16])));
    let execution = Some(LifecycleResourceV1::Execution(aos_sandbox_model::ExecutionId::from_bytes([9; 16])));
    let cases = [
        (Request::Create(wire::CreateSandboxRequest { parent_sandbox_id: vec![5; 16], ..Default::default() }), [sandbox, None]),
        (Request::UpdatePolicy(wire::UpdateSandboxPolicyRequest { sandbox_id: vec![5; 16], ..Default::default() }), [sandbox, None]),
        (Request::Start(wire::SandboxLifecycleRequest { sandbox_id: vec![5; 16], ..Default::default() }), [sandbox, None]),
        (Request::Suspend(wire::SandboxLifecycleRequest { sandbox_id: vec![5; 16], ..Default::default() }), [sandbox, None]),
        (Request::Resume(wire::SandboxLifecycleRequest { sandbox_id: vec![5; 16], ..Default::default() }), [sandbox, None]),
        (Request::ExecutionControl(wire::ExecutionControlRequest { execution_id: vec![9; 16], ..Default::default() }), [execution, None]),
        (Request::Restore(wire::RestoreSnapshotRequest { snapshot_id: vec![8; 16], target_sandbox_id: vec![5; 16], ..Default::default() }), [snapshot, sandbox]),
        (Request::Fork(wire::ForkSnapshotRequest { snapshot_id: vec![8; 16], parent_sandbox_id: vec![5; 16], ..Default::default() }), [snapshot, sandbox]),
        (Request::ViewReplace(wire::ReplaceAttachmentRequest { attachment_id: vec![7; 16], new_view_id: vec![6; 16], ..Default::default() }), [attachment, view]),
        (Request::CachePin(wire::PinCacheObjectRequest { view_id: vec![6; 16], attachment_id: vec![7; 16], ..Default::default() }), [view, attachment]),
    ];
    for (request, expected) in cases {
        assert_eq!(targets_v2(&request), Ok(expected));
    }
}

#[test]
fn malformed_recognized_markers_refuse_instead_of_becoming_absence() {
    let project = ProjectId::from_bytes([1; 16]);
    let request = Request::Start(wire::SandboxLifecycleRequest { sandbox_id: vec![5; 16], ..Default::default() });
    let (key, value) = marker(ProjectId::from_bytes([2; 16]),
        LifecycleResourceV1::Sandbox(SandboxId::from_bytes([5; 16])));
    assert!(require_public_mutation_targets_live_data_v2(project, &request,
        [(key.as_slice(), value.as_slice())]).is_ok());
    let mut wrong_key = key.clone();
    *wrong_key.last_mut().unwrap() ^= 1;
    for (key, value) in [(wrong_key.as_slice(), value.as_slice()), (key.as_slice(), &value[..159])] {
        assert!(matches!(require_public_mutation_targets_live_data_v2(project, &request, [(key, value)]),
            Err(PublicMutationNewUseErrorV2::CorruptTombstone(_))));
    }
    let mut wrong = value;
    wrong[60] = 255;
    super::super::seal(&mut wrong, super::super::TOMBSTONE_DOMAIN);
    assert!(matches!(require_public_mutation_targets_live_data_v2(project, &request,
        [(key.as_slice(), wrong.as_slice())]), Err(PublicMutationNewUseErrorV2::CorruptTombstone(_))));
}

#[test]
fn cleanup_is_not_a_new_use_and_unknown_entrypoints_are_not_adopted() {
    let project = ProjectId::from_bytes([1; 16]);
    let (key, value) = marker(project, LifecycleResourceV1::Sandbox(SandboxId::from_bytes([5; 16])));
    let cleanup = Request::Stop(wire::SandboxLifecycleRequest { sandbox_id: vec![5; 16], ..Default::default() });
    assert!(require_public_mutation_targets_live_data_v2(project, &cleanup,
        [(key.as_slice(), value.as_slice())]).is_ok());
    assert_eq!(targets_v2(&Request::GetSandbox(Default::default())),
        Err(PublicMutationNewUseErrorV2::UnsupportedRequest));
    for id in [Vec::new(), vec![0; 16], vec![5; 15], vec![5; 17]] {
        assert_eq!(targets_v2(&Request::Start(wire::SandboxLifecycleRequest { sandbox_id: id, ..Default::default() })),
            Err(PublicMutationNewUseErrorV2::InvalidTarget));
    }
}

#[test]
fn live_export_uses_only_the_actual_typed_source_owner() {
    use aos_sandbox_model::{ExportId, ObjectDescriptor, ObjectDigest, Revision};
    let project = ProjectId::from_bytes([1; 16]);
    let resource = LifecycleResourceV1::Sandbox(SandboxId::from_bytes([5; 16]));
    let (key, value) = marker(project, resource);
    let live = ViewSource::LiveExport {
        owner_sandbox: SandboxId::from_bytes([5; 16]),
        export: ExportId::from_bytes([6; 16]),
        source_generation: Revision::new(1),
    };
    assert_eq!(require_view_source_live_data_v2(project, &live,
        [(key.as_slice(), value.as_slice())]), Err(PublicMutationNewUseErrorV2::Tombstoned(resource)));

    // Coincidentally equal descriptor/export bytes are not a sandbox identity.
    let immutable = ViewSource::ImmutableTree { tree: ObjectDescriptor::new(
        aos_sandbox_model::MediaType::new("application/octet-stream").unwrap(),
        ObjectDigest::from_bytes([5; 32]), 1,
    ) };
    assert!(require_view_source_live_data_v2(project, &immutable,
        [(key.as_slice(), value.as_slice())]).is_ok());
    let other_owner = ViewSource::LiveExport {
        owner_sandbox: SandboxId::from_bytes([7; 16]),
        export: ExportId::from_bytes([5; 16]),
        source_generation: Revision::new(1),
    };
    assert!(require_view_source_live_data_v2(project, &other_owner,
        [(key.as_slice(), value.as_slice())]).is_ok());
}
