//! Pure retained correlation and finite live semantic-read acceptance tests.

use super::*;
use aos_hub_core::mirror_tree_inventory::{MirrorTreeInventoryQuery, MirrorTreeInventorySource};

fn inventory() -> (StorageWorkPlan, StorageWorkResult) {
    let plan = StorageWorkPlan {
        version: 1,
        plan_id: "a".repeat(32),
        deployment_id: "deployment-1".into(),
        issued_at: 100,
        expires_at: 130,
        placement_id: 4,
        placement_resource_version: 2,
        binding_id: 3,
        binding_resource_version: 1,
        binding_kind: "deployment_r2".into(),
        binding_snapshot_revision: None,
        credential_references: Vec::new(),
        placement_prefix: "registry".into(),
        operation: StorageWorkOperation::InspectMirrorTreeInventory {
            query: MirrorTreeInventoryQuery {
                source: MirrorTreeInventorySource::Loose {
                    registry_id: 1,
                    registry_resource_version: 2,
                    mirror_resource_version: 3,
                    upstream_base: "https://mirror.example.org/registry".into(),
                    protected_profile_digest: "b".repeat(64),
                },
                tree_oid: "c".repeat(64),
                cursor: None,
            },
        },
    };
    let result = StorageWorkResult {
        plan_id: plan.plan_id.clone(),
        placement_id: plan.placement_id,
        placement_resource_version: plan.placement_resource_version,
        binding_id: plan.binding_id,
        binding_resource_version: plan.binding_resource_version,
        source_bytes: 0,
        outcome: StorageWorkOutcome::NotFound,
    };
    (plan, result)
}

#[test]
fn retained_inventory_correlation_does_not_renew_live_acceptance() {
    let (plan, mut result) = inventory();

    // Old captures remain structurally inspectable. Their zero-byte absence
    // has only the original short execution horizon at the production boundary.
    assert!(validate_result(&plan, &result).is_ok());
    assert!(validate_result_acceptance_at(&plan, &result, 129).is_ok());
    assert!(validate_result_acceptance_at(&plan, &result, 130).is_ok());
    assert!(validate_result_acceptance_at(&plan, &result, 131).is_err());
    assert!(validate_result_acceptance_at(&plan, &result, 94).is_err());

    result.binding_resource_version += 1;
    assert!(validate_result(&plan, &result).is_err());
}

#[test]
fn cold_semantic_reads_keep_the_original_finite_horizon() {
    let (mut plan, mut result) = inventory();
    result.source_bytes = 1;

    assert!(validate_result_acceptance_at(&plan, &result, 699).is_ok());
    assert!(validate_result_acceptance_at(&plan, &result, 700).is_err());
    assert!(validate_result_acceptance_at(&plan, &result, 99).is_err());
    // A nonzero accounting field alone cannot fabricate a valid cold result.
    assert!(validate_result(&plan, &result).is_err());

    plan.operation = StorageWorkOperation::InspectMirrorMembership {
        query: aos_hub_core::mirror_membership::MirrorMembershipQuery {
            inspection: aos_hub_core::mirror_inspection::MirrorPackInspection {
                registry_id: 1,
                registry_resource_version: 2,
                mirror_resource_version: 3,
                upstream_base: "https://mirror.example.org/registry".into(),
                index_path: format!("objects/pack/pack-{}.idx", "d".repeat(64)),
                protected_profile_digest: "b".repeat(64),
                selections: Vec::new(),
            },
            oids: vec!["c".repeat(64)],
            expected_source: None,
        },
    };
    assert!(validate_result_acceptance_at(&plan, &result, 699).is_ok());
    assert!(validate_result_acceptance_at(&plan, &result, 700).is_err());
    result.source_bytes = 0;
    assert!(validate_result_acceptance_at(&plan, &result, 129).is_ok());
    assert!(validate_result_acceptance_at(&plan, &result, 131).is_err());
}
