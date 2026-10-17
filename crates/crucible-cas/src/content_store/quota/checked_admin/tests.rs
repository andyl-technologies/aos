//! Real checked quota deletion, dirty-state restart and original refusal.

use super::*;
use crate::content_store::admin::outcome::test_original::{account, assert_closed};
use crate::content_store::{StoreGraph, StoreGraphConfig, StoreNodeId, StoreNodeSpec};
use std::collections::{BTreeMap, BTreeSet};

fn config(root: &Path) -> StoreGraphConfig {
    let quota = StoreNodeId::new("quota").unwrap();
    let directory = StoreNodeId::new("directory").unwrap();
    StoreGraphConfig {
        gc_mark_root: None,
        root: quota.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
        nodes: BTreeMap::from([
            (
                quota,
                StoreNodeSpec::LogicalQuota {
                    child: directory.clone(),
                    state_root: root.join("quota"),
                    maximum_objects: 2,
                    maximum_logical_bytes: 10,
                },
            ),
            (
                directory,
                StoreNodeSpec::Directory {
                    root: root.join("objects"),
                },
            ),
        ]),
    }
}

#[test]
fn checked_delete_recovers_dirty_state_and_restores_original_capacity_on_restart() {
    let root = tempfile::tempdir().unwrap();
    let (graph, admin) = StoreGraph::build_with_admin(config(root.path())).unwrap();
    let bytes = b"1234567890";
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, bytes);
    graph
        .put_if_absent(id, &BlobHandle::from_bytes(bytes.to_vec()))
        .unwrap();
    mark_quota_state_dirty(&root.path().join("quota")).unwrap();
    let (quota, original) = account();
    let baseline = quota.resources.usage().unwrap();
    let _entered = original.enter();
    let physical = admin.physical();
    let mut fence = physical[0]
        .admin()
        .acquire_inventory_fence_with_boundary(&mut || Ok(()))
        .unwrap();
    let summary = fence
        .visit_inventory_with_boundary(&mut |_| Ok(()), &mut || Ok(()))
        .unwrap();
    assert_eq!(summary.backend(), "quota");
    assert_eq!(summary.objects(), 1);
    assert_eq!(summary.logical_bytes(), 10);
    let deleted = fence
        .delete_candidates_with_boundary(&[id, id], &mut || Ok(()))
        .unwrap();
    assert_eq!(
        &*deleted,
        &[
            PlannedDeleteDisposition::Deleted,
            PlannedDeleteDisposition::AlreadyAbsent
        ]
    );
    drop(fence);
    drop(summary);
    drop(deleted);
    assert_eq!(quota.resources.usage().unwrap(), baseline);
    drop(physical);
    drop(admin);
    drop(graph);

    let (graph, _) = StoreGraph::build_with_admin(config(root.path())).unwrap();
    assert!(!graph.contains(id).unwrap());
    graph
        .put_if_absent(id, &BlobHandle::from_bytes(bytes.to_vec()))
        .unwrap();
}

#[test]
fn quota_post_delete_refusal_preserves_child_outcome_and_dirty_restart_recovery() {
    let root = tempfile::tempdir().unwrap();
    let (graph, admin) = StoreGraph::build_with_admin(config(root.path())).unwrap();
    let bytes = b"1234567890";
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, bytes);
    graph
        .put_if_absent(id, &BlobHandle::from_bytes(bytes.to_vec()))
        .unwrap();
    let (_, original) = account();
    let _entered = original.enter();
    let physical = admin.physical();
    let mut fence = physical[0]
        .admin()
        .acquire_inventory_fence_with_boundary(&mut || Ok(()))
        .unwrap();
    let path = super::super::super::directory::DirectoryBlobBackend::new(
        "directory",
        root.path().join("objects"),
    );
    let object_path = path.object_path(id);
    let error = fence
        .delete_candidates_with_boundary(&[id], &mut || {
            if object_path.exists() {
                Ok(())
            } else {
                Err(StoreError::Unauthorized)
            }
        })
        .unwrap_err();
    assert!(matches!(error.original_failure(), StoreError::Unauthorized));
    let StoreError::AdministrativeScope { source } = &error else {
        panic!("quota state custody");
    };
    assert!(source.mutation_uncertain());
    assert_closed(&mut fence, id);
    drop(fence);
    drop(physical);
    drop(admin);
    drop(graph);
    let (graph, _) = StoreGraph::build_with_admin(config(root.path())).unwrap();
    assert!(!graph.contains(id).unwrap());
    graph
        .put_if_absent(id, &BlobHandle::from_bytes(bytes.to_vec()))
        .unwrap();
}

#[test]
fn quota_callback_tls_switch_keeps_child_admission_and_dispatch_on_saved_original() {
    let root = tempfile::tempdir().unwrap();
    let (graph, admin) = StoreGraph::build_with_admin(config(root.path())).unwrap();
    let bytes = b"1234567890";
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, bytes);
    graph
        .put_if_absent(id, &BlobHandle::from_bytes(bytes.to_vec()))
        .unwrap();
    let (owner, original) = account();
    let (foreign_owner, foreign) = account();
    let baseline = owner.resources.usage().unwrap();
    let foreign_baseline = foreign_owner.resources.usage().unwrap();
    let _entered = original.enter();
    let physical = admin.physical();
    let mut switched = None;
    let mut fence = physical[0]
        .admin()
        .acquire_inventory_fence_with_boundary(&mut || {
            if switched.is_none() {
                switched = Some(foreign.enter());
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(owner.resources.usage().unwrap().0, 7);
    assert_eq!(foreign_owner.resources.usage().unwrap(), foreign_baseline);
    drop(switched);

    let mut switched = None;
    let summary = fence
        .visit_inventory_with_boundary(&mut |_| Ok(()), &mut || {
            if switched.is_none() {
                switched = Some(foreign.enter());
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(summary.objects(), 1);
    assert_eq!(foreign_owner.resources.usage().unwrap(), foreign_baseline);
    drop(switched);
    drop(summary);

    let mut switched = None;
    let deleted = fence
        .delete_candidates_with_boundary(&[id], &mut || {
            if switched.is_none() {
                switched = Some(foreign.enter());
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(&*deleted, &[PlannedDeleteDisposition::Deleted]);
    assert_eq!(foreign_owner.resources.usage().unwrap(), foreign_baseline);
    drop(switched);
    drop(deleted);
    drop(fence);
    assert_eq!(owner.resources.usage().unwrap(), baseline);
    assert!(!graph.contains(id).unwrap());
}
