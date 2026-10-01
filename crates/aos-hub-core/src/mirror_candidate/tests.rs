//! Purpose, destination and deadline checks for actual encoded candidate plans.

use super::*;
use crate::mirror_work::{MirrorOriginal, MirrorStep, MirrorVerification};

fn plan() -> StorageWorkPlan {
    let mut original = MirrorOriginal {
        version: 1,
        job_id: String::new(),
        copy_operation_id: Some("4".repeat(32)),
        registry_id: 1,
        registry_resource_version: 1,
        mirror_resource_version: 1,
        upstream_base: "https://upstream.example.invalid/registry/".into(),
        path: "nar/source.nar".into(),
        placement_id: 1,
        placement_resource_version: 1,
        write_spec_version: 1,
        binding_id: 1,
        binding_resource_version: 1,
        placement_prefix: format!(".aos-mirror-qualification/{}/final", "a".repeat(32)),
        protected_profile_digest: "3".repeat(64),
        verification: MirrorVerification::Sha256 {
            sha256: "1".repeat(64),
            size: 11,
        },
    };
    original.job_id = original.identity().unwrap();
    StorageWorkPlan {
        version: 1,
        plan_id: "b".repeat(32),
        deployment_id: "candidate-deployment".into(),
        issued_at: 100,
        expires_at: 130,
        placement_id: 1,
        placement_resource_version: 1,
        binding_id: 1,
        binding_resource_version: 1,
        binding_kind: "deployment_r2".into(),
        binding_snapshot_revision: None,
        credential_references: vec![],
        placement_prefix: original.placement_prefix.clone(),
        operation: StorageWorkOperation::MirrorTransfer {
            original,
            step: MirrorStep::Begin,
        },
    }
}

#[test]
fn candidate_and_production_signatures_cannot_cross_authenticate() {
    let key = StorageWorkKey::new("controlled-role-key-with-at-least-thirty-two-bytes").unwrap();
    let plan = plan();
    let body = serde_json::to_vec(&plan).unwrap();
    let signature = sign_mirror_candidate_plan(&key, &plan).unwrap();

    assert_eq!(
        verify_mirror_candidate_plan(&key, &signature, &body, "candidate-deployment", 101).unwrap(),
        plan
    );
    assert!(key
        .verify_plan(&signature, &body, "candidate-deployment", 101)
        .is_err());
    assert!(verify_mirror_candidate_plan(
        &key,
        &key.sign_body(&body).unwrap(),
        &body,
        "candidate-deployment",
        101
    )
    .is_err());
    assert!(
        verify_mirror_candidate_plan(&key, &signature, &body, "candidate-deployment", 131).is_err()
    );
    assert!(
        verify_mirror_candidate_plan(&key, &signature, &body, "foreign-deployment", 101).is_err()
    );
}

#[test]
fn candidate_cannot_address_public_destinations_or_another_operation() {
    let key = StorageWorkKey::new("controlled-role-key-with-at-least-thirty-two-bytes").unwrap();
    for prefix in [
        "registry/root",
        ".aos-mirror-qualification/not-a-run/final",
        ".aos-mirror-qualification/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/final/extra",
    ] {
        let mut plan = plan();
        let StorageWorkOperation::MirrorTransfer { original, .. } = &mut plan.operation else {
            panic!()
        };
        original.placement_prefix = prefix.into();
        original.job_id = original.identity().unwrap();
        plan.placement_prefix = prefix.into();
        assert!(sign_mirror_candidate_plan(&key, &plan).is_err());
    }

    let mut plan = plan();
    plan.operation = StorageWorkOperation::Head {
        path: "nar/source.nar".into(),
    };
    assert!(sign_mirror_candidate_plan(&key, &plan).is_err());
}
