//! Exercises the canonical no-slot request, row and physical inventory relation.

use super::*;
use aos_proto::aos::sandbox::local::v1::{
    AttachmentAnchorInventoryRecord, Audience, InventoryDestinationSlotsResponse,
};
use aos_sandbox_core::{
    AttachmentSlotId, FeatureRef, MediaType, ObjectDigest, PortableMediaType,
    descriptor_for_bytes, encode_sandbox_spec,
};
use aos_sandbox_core::model::{
    IdentityProfile, Limit, LimitDimension, LimitValue, NetworkKind, NetworkProfile,
    ResourceProfile, SandboxSpec, UnmappableIdentityPolicy,
};
use std::num::NonZeroU32;

fn descriptor(kind: PortableMediaType, byte: u8) -> ObjectDescriptor {
    ObjectDescriptor::new(MediaType::new(kind.as_str().to_owned()).unwrap(),
        ObjectDigest::from_bytes([byte; 32]), 1)
}

fn request(slots: Vec<AttachmentSlotId>) -> ApplyAttachmentAnchorRequestV1 {
    let spec = SandboxSpec::new(
        FeatureRef::new("aos.sandbox.runtime.linux-systemd", 1, 0).unwrap(),
        IdentityProfile::PrivateUserns {
            id_range_size: NonZeroU32::new(65_536).unwrap(),
            unmappable_policy: UnmappableIdentityPolicy::Reject,
            required_features: Vec::new(),
        },
        ResourceProfile::new(vec![Limit::new(LimitDimension::Memory,
            LimitValue::Bounded(1 << 20),
            FeatureRef::new("aos.sandbox.enforcement.cgroup-v2", 1, 0).unwrap())]).unwrap(),
        descriptor(PortableMediaType::Environment, 1),
        descriptor(PortableMediaType::View, 2),
        slots,
        NetworkProfile::new(NetworkKind::Isolated, Vec::new(), Vec::new()).unwrap(),
        Vec::new(),
    ).unwrap();
    let bytes = encode_sandbox_spec(&spec);
    let spec = descriptor_for_bytes(
        MediaType::new(PortableMediaType::SandboxSpec.as_str().to_owned()).unwrap(), &bytes,
    );
    ApplyAttachmentAnchorRequestV1 {
        header: Some(RequestHeader {
            protocol_major: 2, protocol_minor: 0,
            request_id: vec![7; 16], audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
            deadline_boottime_nanoseconds: 100, maximum_response_bytes: 4096,
            ..Default::default()
        }).into(),
        fence: Some(AssignmentFence {
            sandbox_id: vec![1; 16], incarnation_id: vec![2; 16],
            assignment_epoch: 3, desired_generation: 4, assignment_digest: vec![5; 32],
            ..Default::default()
        }).into(),
        action: AttachmentAnchorActionV1::ATTACHMENT_ANCHOR_ACTION_V1_MATERIALIZE.into(),
        namespace_generation: 6,
        sandbox_spec: Some(wire_descriptor(&spec)).into(), sandbox_spec_bytes: bytes,
        ..Default::default()
    }
}

fn decode(wire: &ApplyAttachmentAnchorRequestV1) -> Result<ValidatedAttachmentAnchorRequestV1, ProtocolValidationError> {
    decode_attachment_anchor_request_v1(&wire.encode_to_vec(),
        PeerCredentials { uid: 811, gid: 812, pid: Some(813) },
        PeerPolicy { uid: 811, gid: Some(812), audience: Audience::AUDIENCE_NODE_CONTROLLER }, 1)
}

fn ready() -> (ApplyAttachmentAnchorRequestV1, ValidatedAttachmentAnchorResourceV1) {
    let wire = request(Vec::new());
    let request = decode(&wire).unwrap();
    let intent = ValidatedAttachmentAnchorResourceV1::materializing_v1(
        &request, &wire.encode_to_vec(), [8; 16],
    ).unwrap();
    let ready = intent.ready_v1((9, 10, 11)).unwrap();
    intent.require_successor_v1(&ready).unwrap();
    (wire, ready)
}

#[test]
fn delete_reap_keeps_current_cleanup_fence_separate_from_host_and_ready_creation_scope() {
    use aos_sandbox_core::{AssignmentEpoch, CanonicalAssignmentManifestV1, DesiredGeneration,
        IncarnationId, NamespaceGeneration, NodeId, OperationId, ProjectId, ResourceVector,
        SandboxId};
    use aos_sandbox_core::model::{AssignmentManifestV1, SandboxAncestry};
    use crate::host_stopped_namespace::HostStoppedNamespaceDataV4;

    // These are canonical model fixtures, never signed plans or native owners.
    let mut wire = request(Vec::new());
    let specification = decode(&wire).unwrap().sandbox_spec().clone();
    let assignment = |generation| CanonicalAssignmentManifestV1::new(AssignmentManifestV1::new(
        SandboxId::from_bytes([1; 16]), ProjectId::from_bytes([20; 16]),
        SandboxAncestry::new(SandboxId::from_bytes([1; 16]), Vec::new()).unwrap(),
        IncarnationId::from_bytes([2; 16]), NodeId::from_bytes([21; 16]),
        AssignmentEpoch::new(3), DesiredGeneration::new(generation), NamespaceGeneration::new(6),
        specification.clone(), descriptor(PortableMediaType::Policy, 22),
        descriptor(PortableMediaType::Environment, 1), descriptor(PortableMediaType::View, 2),
        Vec::new(), ObjectDigest::from_bytes([23; 32]), ResourceVector::ZERO, Vec::new(),
    ).unwrap());
    let old = assignment(4);
    wire.fence.as_option_mut().unwrap().assignment_digest = old.digest().as_bytes().to_vec();
    let materialize = decode(&wire).unwrap();
    let ready = ValidatedAttachmentAnchorResourceV1::materializing_v1(
        &materialize, &wire.encode_to_vec(), [8; 16]).unwrap().ready_v1((9, 10, 11)).unwrap();
    let anchor = crate::attachment_anchor_handle_v1(&[1; 16], &[2; 16], 6, &[8; 16], 9, 10, 11);
    let scope = |boot, anchor| HostStoppedNamespaceDataV4::from_data_v4(
        boot, *ready.fence(), anchor,
        ([24; 16], [25; 32], [26; 32]), ([27; 16], [28; 32], [29; 32]),
    ).unwrap();
    let stopped = scope([8; 16], anchor);
    let current = assignment(5);
    let build = |assignment: &CanonicalAssignmentManifestV1, stopped: &HostStoppedNamespaceDataV4, bytes: &[u8]| {
        prepare_delete_mount_reap_request_data_v4(assignment, &ready, stopped, bytes,
            OperationId::from_bytes([30; 16]), [31; 16], [32; 32], 100)
    };

    let reap = build(&current, &stopped, &wire.sandbox_spec_bytes).unwrap();

    assert_eq!(reap.fence().desired_generation(), 5);
    assert_eq!(reap.resource_fence(), Some(ready.fence()));
    assert_eq!(reap.expected_resource_digest(), Some(ready.resource_digest()));
    assert_eq!(reap.action(), AttachmentAnchorActionV1::ATTACHMENT_ANCHOR_ACTION_V1_REAP);
    assert!(build(&assignment(3), &stopped, &wire.sandbox_spec_bytes).is_err());
    assert!(build(&current, &scope([33; 16], anchor), &wire.sandbox_spec_bytes).is_err());
    assert!(build(&current, &scope([8; 16], [34; 32]), &wire.sandbox_spec_bytes).is_err());
    let mut changed = wire.sandbox_spec_bytes;
    changed.push(0);
    assert!(build(&current, &stopped, &changed).is_err());
}

#[test]
fn empty_namespace_is_distinct_from_any_declared_slot() {
    let wire = request(Vec::new());
    let decoded = decode(&wire).unwrap();
    assert!(decoded.specification().attachment_slots().is_empty());
    let canonical = canonical_attachment_anchor_semantics_v1(&decoded).unwrap();
    assert_eq!(canonical.verb(), BrokerVerb::MountMaterializeAttachmentAnchor);
    assert!(matches!(canonical.target(), BrokerGrantTarget::Assignment));
    assert!(decode(&request(vec![AttachmentSlotId::from_bytes([4; 16])])).is_err());

    let mut substituted = wire;
    substituted.namespace_generation += 1;
    assert_ne!(canonical.commitment(),
        canonical_attachment_anchor_semantics_v1(&decode(&substituted).unwrap()).unwrap().commitment());
}

#[test]
fn durable_codec_preserves_full_finite_chain_and_rejects_phase_skips() {
    let (wire, ready) = ready();
    let encoded = encode_attachment_anchor_resource_v1(&ready);
    assert_eq!(decode_attachment_anchor_resource_v1(&encoded).unwrap(), ready);
    ready.require_request_v1(&decode(&wire).unwrap(), &wire.encode_to_vec()).unwrap();
    assert!(ready.require_request_v1(&decode(&wire).unwrap(), b"substituted request").is_err());

    let mut reap = wire.clone();
    reap.action = AttachmentAnchorActionV1::ATTACHMENT_ANCHOR_ACTION_V1_REAP.into();
    reap.header.as_option_mut().unwrap().request_id = vec![12; 16];
    reap.resource_fence = reap.fence.clone();
    reap.expected_resource_digest = ready.resource_digest().to_vec();
    let reaping = ready.reaping_v1(&decode(&reap).unwrap(), &reap.encode_to_vec()).unwrap();
    let released = reaping.released_v1().unwrap();
    ready.require_successor_v1(&reaping).unwrap();
    reaping.require_successor_v1(&released).unwrap();
    assert!(ready.require_successor_v1(&released).is_err());
    assert!(released.ready_v1((9, 10, 11)).is_err());
    released.require_request_v1(&decode(&reap).unwrap(), &reap.encode_to_vec()).unwrap();

    reap.expected_resource_digest[0] ^= 1;
    assert!(ready.reaping_v1(&decode(&reap).unwrap(), &reap.encode_to_vec()).is_err());
    let mut changed = encoded;
    *changed.last_mut().unwrap() ^= 1;
    assert!(decode_attachment_anchor_resource_v1(&changed).is_err());
}

fn inventory(row: &ValidatedAttachmentAnchorResourceV1) -> InventoryDestinationSlotsResponse {
    let fence = row.fence();
    let (device, inode, mount) = row.physical_identity_v1().unwrap();
    InventoryDestinationSlotsResponse {
        kernel_boot_id: vec![8; 16], broker_instance_id: vec![13; 16], journal_sequence: 1,
        namespace_anchors: vec![row.wire_v1()],
        attachment_anchors: vec![AttachmentAnchorInventoryRecord {
            attachment_anchor_handle: crate::attachment_anchor_handle_v1(
                fence.sandbox_id(), fence.incarnation_id(), row.namespace_generation(),
                row.resource_kernel_boot_id(), device, inode, mount).to_vec(),
            sandbox_id: fence.sandbox_id().to_vec(), incarnation_id: fence.incarnation_id().to_vec(),
            namespace_generation: row.namespace_generation(),
            resource_kernel_boot_id: row.resource_kernel_boot_id().to_vec(),
            directory_device: device, directory_inode: inode, unique_mount_id: mount,
            ..Default::default()
        }],
        ..Default::default()
    }
}

#[test]
fn complete_inventory_requires_actual_namespace_row_and_exact_physical_identity() {
    let (_, ready) = ready();
    let mut wire = inventory(&ready);
    let decoded = crate::decode_destination_slot_inventory_response(&wire.encode_to_vec(), 1 << 20).unwrap();
    assert_eq!(decoded.namespace_anchors_v1(), &[ready]);
    assert_eq!(decoded.attachment_anchors().len(), 1);

    wire.attachment_anchors.clear();
    assert!(crate::decode_destination_slot_inventory_response(&wire.encode_to_vec(), 1 << 20).is_err());
    wire = inventory(&decoded.namespace_anchors_v1()[0]);
    wire.namespace_anchors.clear();
    assert!(crate::decode_destination_slot_inventory_response(&wire.encode_to_vec(), 1 << 20).is_err());
    wire = inventory(&decoded.namespace_anchors_v1()[0]);
    wire.attachment_anchors[0].directory_inode += 1;
    let anchor = &mut wire.attachment_anchors[0];
    anchor.attachment_anchor_handle = crate::attachment_anchor_handle_v1(
        &[1; 16], &[2; 16], 6, &[8; 16], anchor.directory_device,
        anchor.directory_inode, anchor.unique_mount_id).to_vec();
    assert!(crate::decode_destination_slot_inventory_response(&wire.encode_to_vec(), 1 << 20).is_err());
}

#[test]
fn predecode_bound_covers_retained_unknown_groups_and_rejects_excessive_input() {
    use aos_sandbox_core::ResourceDimension;
    let mut body = request(Vec::new()).encode_to_vec();
    // Unknown field 90 contains a group with five scalar members. This reaches
    // an actual separate unknown-field Vec and its minimum/growing capacity.
    body.extend_from_slice(&[0xd3, 0x05]);
    for _ in 0..5 { body.extend_from_slice(&[0x08, 0x01]); }
    body.extend_from_slice(&[0xd4, 0x05]);
    let cost = attachment_anchor_request_decoding_demand_v4(body.len()).unwrap();
    let decoded = ApplyAttachmentAnchorRequestV1::decode_from_slice(body.as_slice()).unwrap();
    // Wire decoding reaches the prepaid unknown-group graph, then the sole
    // canonical semantic decoder rejects those unknown fields.
    assert!(decode(&decoded).is_err());
    assert!(cost.get(ResourceDimension::MemoryBytes) > body.len() as u64);
    assert_eq!(cost.get(ResourceDimension::MetadataEntries), 0);
    assert!(attachment_anchor_request_decoding_demand_v4(MAXIMUM_REQUEST_BYTES + 1).is_err());
    assert!(attachment_anchor_request_decoding_demand_v4(usize::MAX).is_err());
}
