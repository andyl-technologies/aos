//! Exercises whole-batch omissions and independently changed current versions.

use super::*;
use aos_proto::aos::sandbox::v1::{
    DesiredLifecycle, ObjectDescriptor, Sandbox, SandboxDesiredState, SandboxObservedState,
    SandboxPhase, Timestamp,
};
use aos_sandbox_core::{
    DesiredGeneration, ObjectDigest, OperationId, ProjectId, Revision, SandboxId,
};
use aos_sandbox_core::source_tree_model::{SandboxTreeRecordV1, TreeLimitsV1};
use aos_sandbox_ledger_replay::{
    delete_graph::{DeleteGraphEdgeDataV2, DeleteGraphProjectionDataV2},
    hierarchy::graph::SandboxTreeV1,
    replay::tree_lineage::ClosedTreeLineageHeadV1,
};
use aos_sandbox_protocol::{
    domain_ledger::{
        delete_batch::{
            DeleteBatchCommitmentsDataV2, DeleteBatchDependencyDataV1, DeleteBatchEncodingDataV1,
            DeleteBatchNativeBoundaryDataV2, DeleteBatchOwnerCutDataV1, DeleteBatchOwnerCutDataV2,
            DeleteBatchWriteDataV1, DeleteDependencyClassDataV2, LifecycleDeleteBatchV1,
        },
        lifecycle_model::LifecycleDependencyEdgeV1,
    },
    public_api::projection::{
        PublicProjectionPlanV1, PublicProjectionResourceV1, decode_checked_public_projection_v1,
    },
};

fn projection(id: u8, parent: Option<u8>) -> DeleteGraphProjectionDataV2 {
    let descriptor = |media: aos_sandbox_core::PortableMediaType| ObjectDescriptor {
        media_type: media.as_str().to_owned(), sha256: vec![7; 32], encoded_size: 1,
        ..Default::default()
    };
    let policy = descriptor(aos_sandbox_core::PortableMediaType::Policy);
    let plan = PublicProjectionPlanV1::new(ProjectId::from_bytes([4; 16]),
        OperationId::from_bytes([8; 16]), PublicProjectionResourceV1::Sandbox(Sandbox {
            sandbox_id: vec![id; 16], project_id: vec![4; 16], resource_version: vec![id; 32],
            parent_sandbox_id: parent.map_or_else(Vec::new, |parent| vec![parent; 16]),
            desired: Some(SandboxDesiredState {
                specification: Some(descriptor(aos_sandbox_core::PortableMediaType::SandboxSpec)).into(),
                requested_policy: Some(policy.clone()).into(), generation: 1,
                lifecycle: DesiredLifecycle::DESIRED_LIFECYCLE_STOPPED.into(), ..Default::default()
            }).into(),
            observed: Some(SandboxObservedState {
                phase: SandboxPhase::SANDBOX_PHASE_REQUESTED.into(), desired_generation: 1,
                observation_sequence: 1, ..Default::default()
            }).into(),
            effective_policy: Some(policy).into(),
            created_at: Some(Timestamp { seconds: 1, ..Default::default() }).into(),
            updated_at: Some(Timestamp { seconds: 1, ..Default::default() }).into(),
            ..Default::default()
        })).unwrap();
    DeleteGraphProjectionDataV2 {
        resource: Resource::Sandbox(SandboxId::from_bytes([id; 16])),
        record: decode_checked_public_projection_v1(plan.desired_key(), plan.desired_value()).unwrap(),
        key: plan.desired_key().to_vec(), original: plan.desired_value().to_vec(),
    }
}

fn graph() -> DeleteDependencyGraphDataV2 {
    let project = ProjectId::from_bytes([4; 16]);
    let root = SandboxId::from_bytes([1; 16]);
    let child = SandboxId::from_bytes([2; 16]);
    let tree = SandboxTreeV1::from_records(project, Revision::new(1),
        TreeLimitsV1::new(1, 2, 2, 1, 1, 1, 1).unwrap(), vec![
            SandboxTreeRecordV1::new(project, root, None, DesiredGeneration::new(1), None).unwrap(),
            SandboxTreeRecordV1::new(project, child, Some(root), DesiredGeneration::new(1), None).unwrap(),
        ]).unwrap();
    DeleteDependencyGraphDataV2 {
        project, tree: ClosedTreeLineageHeadV1 {
            tree, tree_head: ObjectDigest::from_bytes([9; 32]),
            lineage_head: ObjectDigest::from_bytes([10; 32]), initial_seed_packet: [0; aos_sandbox_protocol::controller_source_seed::CONTROLLER_SOURCE_TREE_SEED_BYTES_V1],
        },
        projections: vec![projection(1, None), projection(2, Some(1))], views: Vec::new(),
        snapshots: Vec::new(), companions: Vec::new(), capabilities: Vec::new(),
        edges: vec![DeleteGraphEdgeDataV2 {
            edge: LifecycleDependencyEdgeV1::new(Resource::Sandbox(child), Resource::Sandbox(root)).unwrap(),
            class: DeleteDependencyClassDataV2::SandboxParent,
        }],
    }
}

fn batch(graph: &DeleteDependencyGraphDataV2, omit_child: bool, generation: u64) -> LifecycleDeleteBatchV1 {
    let selection = graph.select_dependent_closure_data_v2(SandboxId::from_bytes([1; 16]), true).unwrap();
    let writes: Vec<_> = graph.projections.iter().take(if omit_child { 1 } else { 2 }).map(|row| {
        DeleteBatchWriteDataV1 { resource: row.resource, key: &row.key,
            before_generation: generation, before_digest: native_value_digest(&row.original) }
    }).collect();
    let dependencies: Vec<_> = selection.dependencies.iter().take(usize::from(!omit_child)).map(|edge| {
        DeleteBatchDependencyDataV1 { dependent: edge.edge.dependent(),
            dependency: edge.edge.dependency(), class: edge.class.code_v2() }
    }).collect();
    let postorder = if omit_child { vec![Resource::Sandbox(selection.root)] } else { selection.postorder };
    let input = DeleteBatchEncodingDataV1 {
        project: graph.project, operation: OperationId::from_bytes([5; 16]), transaction: [6; 16],
        root: Resource::Sandbox(selection.root), flags: 1, before_sequence: 20, authority_epoch: 0,
        commitments: [[8; 32]; 5], owners: [DeleteBatchOwnerCutDataV1 { sequence: 0, count: 0, digest: [11; 32] }; 6],
        writes: &writes, reads: &[], collections: &[], dependencies: &dependencies, postorder: &postorder,
    };
    LifecycleDeleteBatchV1::from_encoding_with_native_cuts_v2(&input,
        DeleteBatchCommitmentsDataV2 { authorization: [12; 32], source: [13; 32],
            controller: [14; 32], initial_six: [15; 32] }, 21,
        [DeleteBatchOwnerCutDataV2 { boundary: DeleteBatchNativeBoundaryDataV2::JournalPrefix {
            next_sequence: 22 }, count: 0, digest: [16; 32] }; 6], &[]).unwrap()
}

#[test]
fn independently_reconstructed_child_cannot_disappear_from_a_resealed_batch() {
    let graph = graph();
    let selected = graph.select_dependent_closure_data_v2(SandboxId::from_bytes([1; 16]), true).unwrap();
    let complete = batch(&graph, false, 1);
    assert!(require_delete_graph_batch_data_v2(&graph, &selected, complete.view().unwrap()).is_ok());

    // Both candidates have valid canonical checksums and complete local codec
    // postorders. Only the independently reconstructed graph reveals omission.
    let omitted = batch(&graph, true, 1);
    assert!(require_delete_graph_batch_data_v2(&graph, &selected, omitted.view().unwrap()).is_err());
    let changed_version = batch(&graph, false, 2);
    assert!(require_delete_graph_batch_data_v2(&graph, &selected, changed_version.view().unwrap()).is_err());
    assert!(graph.select_dependent_closure_data_v2(SandboxId::from_bytes([1; 16]), false).is_err());
}
