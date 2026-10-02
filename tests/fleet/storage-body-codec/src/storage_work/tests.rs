//! Exact retained GC metadata correlation through the production validator.

use aos_hub_core::storage_work::StorageObjectIdentity;

use super::*;

fn fixture() -> (StorageWorkPlan, StorageWorkResult) {
    let plan = StorageWorkPlan {
        version: 1,
        plan_id: "a".repeat(32),
        deployment_id: "fixture".into(),
        issued_at: 100,
        expires_at: 130,
        placement_id: 4,
        placement_resource_version: 2,
        binding_id: 3,
        binding_resource_version: 1,
        binding_kind: "deployment_r2".into(),
        binding_snapshot_revision: None,
        credential_references: Vec::new(),
        placement_prefix: "registry/".into(),
        operation: StorageWorkOperation::Head {
            path: "HEAD".into(),
        },
    };
    let result = StorageWorkResult {
        plan_id: plan.plan_id.clone(),
        placement_id: plan.placement_id,
        placement_resource_version: plan.placement_resource_version,
        binding_id: plan.binding_id,
        binding_resource_version: plan.binding_resource_version,
        source_bytes: 0,
        outcome: StorageWorkOutcome::Head {
            object: StorageObjectIdentity {
                key: "registry/HEAD".into(),
                size: 5,
                etag: "\"etag\"".into(),
                provider_version: Some("version-1".into()),
            },
        },
    };
    (plan, result)
}

#[test]
fn retained_exact_metadata_and_not_found_do_not_require_fabricated_current_time() {
    let (plan, mut result) = fixture();
    let request = serde_json::to_vec(&plan).unwrap();
    let positive = decode(&request, &serde_json::to_vec(&result).unwrap(), "fixture").unwrap();
    assert_eq!(positive.1, "storage_work_gc_metadata");

    result.outcome = StorageWorkOutcome::NotFound;
    let absent = decode(&request, &serde_json::to_vec(&result).unwrap(), "fixture").unwrap();
    assert_eq!(absent.1, "storage_work_not_found_metadata");
    assert!(plan.validate("fixture", 131).is_err());
}

#[test]
fn substituted_fences_source_cost_and_raw_content_operations_refuse() {
    let (mut plan, result) = fixture();
    let request = serde_json::to_vec(&plan).unwrap();
    let mut altered = result.clone();
    altered.placement_resource_version += 1;
    assert!(decode(&request, &serde_json::to_vec(&altered).unwrap(), "fixture").is_err());

    altered = result.clone();
    altered.source_bytes = 1;
    assert!(decode(&request, &serde_json::to_vec(&altered).unwrap(), "fixture").is_err());
    assert!(decode(&request, &serde_json::to_vec(&result).unwrap(), "another").is_err());

    plan.operation = StorageWorkOperation::InspectOciRange {
        path: "HEAD".into(),
        start: 0,
        end: 0,
    };
    assert!(decode(
        &serde_json::to_vec(&plan).unwrap(),
        &serde_json::to_vec(&result).unwrap(),
        "fixture"
    )
    .is_err());
    assert!(decode(&vec![b' '; MAX_PLAN_BYTES + 1], b"{}", "fixture").is_err());
}
