//! Closed selector, full-response partition and unchanged byte-budget regressions.

use super::*;
use crate::storage_work::{StorageWorkOperation, StorageWorkOutcome};

fn targets(count: usize) -> Vec<HybridLiveDeliveryTarget> {
    (0..count)
        .map(|index| HybridLiveDeliveryTarget {
            registry_id: 1,
            registry_resource_version: 2,
            mirror_resource_version: 3,
            placement_id: 4,
            placement_resource_version: 5,
            write_spec_version: 6,
            placement_prefix: "registry".into(),
            binding_id: 7,
            binding_resource_version: 8,
            protected_profile_digest: "a".repeat(64),
            upstream_base: "https://example.org/registry/".into(),
            path: format!("channels/stable/{index:02x}"),
            class: HybridLiveDeliveryClass::Metadata,
            maximum_bytes: 128 * 1024,
        })
        .collect()
}

fn plan(targets: Vec<HybridLiveDeliveryTarget>) -> StorageWorkPlan {
    StorageWorkPlan {
        version: 1,
        plan_id: "a".repeat(32),
        deployment_id: "deployment".into(),
        issued_at: 100,
        expires_at: 130,
        placement_id: 4,
        placement_resource_version: 5,
        binding_id: 7,
        binding_resource_version: 8,
        binding_kind: "deployment_r2".into(),
        binding_snapshot_revision: None,
        credential_references: vec![],
        placement_prefix: "registry".into(),
        operation: StorageWorkOperation::InspectMirrorLiveMetadataBatch { targets },
    }
}

fn positive(target: &HybridLiveDeliveryTarget, bytes: &[u8]) -> LiveMetadataObservation {
    LiveMetadataObservation {
        target_digest: target_digest(target).unwrap(),
        source_bytes: Some(bytes.len() as u64),
        outcome: LiveMetadataOutcome::Found {
            sha256: crate::hybrid_ingress::body_sha256(bytes),
            size: bytes.len() as u64,
            content_base64: base64::engine::general_purpose::STANDARD.encode(bytes),
        },
    }
}

#[test]
fn original_targets_are_bounded_sorted_and_share_every_authority_pin() {
    let original = targets(32);
    assert!(plan(original.clone()).validate("deployment", 100).is_ok());
    assert!(plan(targets(33)).validate("deployment", 100).is_err());
    assert!(plan(vec![]).validate("deployment", 100).is_err());
    let mut changed = original.clone();
    changed[2].path = changed[1].path.clone();
    assert!(plan(changed).validate("deployment", 100).is_err());
    let mutations: [fn(&mut HybridLiveDeliveryTarget); 5] = [
        |target: &mut HybridLiveDeliveryTarget| target.mirror_resource_version += 1,
        |target: &mut HybridLiveDeliveryTarget| target.protected_profile_digest = "b".repeat(64),
        |target: &mut HybridLiveDeliveryTarget| {
            target.upstream_base = "https://other.example.org/".into()
        },
        |target: &mut HybridLiveDeliveryTarget| target.placement_resource_version += 1,
        |target: &mut HybridLiveDeliveryTarget| target.binding_resource_version += 1,
    ];
    for mutate in mutations {
        let mut changed = original.clone();
        mutate(&mut changed[1]);
        assert!(plan(changed).validate("deployment", 100).is_err());
    }
}

#[test]
fn mixed_results_preserve_order_absence_refusal_and_unknown_source_cost() {
    let targets = targets(3);
    let mut items = vec![
        positive(&targets[0], b"signed-document"),
        LiveMetadataObservation {
            target_digest: target_digest(&targets[1]).unwrap(),
            source_bytes: Some(0),
            outcome: LiveMetadataOutcome::NotFound,
        },
        LiveMetadataObservation {
            target_digest: target_digest(&targets[2]).unwrap(),
            source_bytes: None,
            outcome: LiveMetadataOutcome::Refused {
                reason: LiveMetadataRefusal::SourceReadFailed,
            },
        },
    ];
    assert!(validate_observations(&targets, &items, 15).is_ok());
    items[2].source_bytes = Some(0);
    assert!(validate_observations(&targets, &items, 15).is_err());
    items[2].source_bytes = None;
    items.swap(0, 1);
    assert!(validate_observations(&targets, &items, 15).is_err());
}

#[test]
fn changed_paths_bodies_and_omitted_positions_refuse() {
    let targets = targets(2);
    let mut items = vec![positive(&targets[0], b"one"), positive(&targets[1], b"two")];
    assert!(validate_observations(&targets, &items, 6).is_ok());
    let mut rewritten = targets.clone();
    rewritten[1].path = "channels/stable/ff".into();
    assert!(validate_observations(&rewritten, &items, 6).is_err());
    assert!(validate_observations(&targets, &items[..1], 3).is_err());
    if let LiveMetadataOutcome::Found { sha256, .. } = &mut items[1].outcome {
        *sha256 = "0".repeat(64);
    }
    assert!(validate_observations(&targets, &items, 6).is_err());
}

#[test]
fn aggregate_budget_retains_every_original_and_actual_completed_read_cost() {
    let targets = targets(3);
    let plan = plan(targets.clone());
    let items = targets
        .iter()
        .map(|target| positive(target, &vec![0; 128 * 1024]))
        .collect();
    let mut result = StorageWorkResult {
        plan_id: plan.plan_id.clone(),
        placement_id: 4,
        placement_resource_version: 5,
        binding_id: 7,
        binding_resource_version: 8,
        source_bytes: 3 * 128 * 1024,
        outcome: StorageWorkOutcome::MirrorLiveMetadataBatch { items },
    };
    bound_result(&targets, &mut result).unwrap();
    assert!(serde_json::to_vec(&result).unwrap().len() <= MAX_RESULT_BYTES);
    let StorageWorkOutcome::MirrorLiveMetadataBatch { items } = &result.outcome else {
        unreachable!()
    };
    assert_eq!(items.len(), 3);
    assert_eq!(
        items
            .iter()
            .filter(|item| matches!(
                item.outcome,
                LiveMetadataOutcome::Refused {
                    reason: LiveMetadataRefusal::ResultBudget
                }
            ))
            .count(),
        2
    );
    validate_observations(&targets, items, result.source_bytes).unwrap();
}
