//! Adversarial validation of the shared source-controlled qualification policy.

use aos_release::{
    canonical,
    plan::ReleaseClass,
    qualification::{QualificationContractV1, QualificationPhase, QualificationScope},
};

fn contract() -> QualificationContractV1 {
    canonical::from_slice(
        include_bytes!("fixtures/qualification-contract.json"),
        "qualification fixture",
    )
    .unwrap()
}

#[test]
fn one_contract_selects_class_obligations_without_renaming_requirements() {
    let contract = contract();
    contract.validate().unwrap();
    let edge = contract.gates(ReleaseClass::Edge).unwrap();
    let stable = contract.gates(ReleaseClass::Stable).unwrap();
    assert!(
        edge.iter()
            .all(|gate| stable.iter().any(|other| other.policy_id == gate.policy_id))
    );
    assert!(
        stable
            .iter()
            .any(|gate| gate.policy_id == "production-recovery")
    );
    assert!(
        !edge
            .iter()
            .any(|gate| gate.policy_id == "production-recovery")
    );
    assert_ne!(edge[0].policy_digest, stable[0].policy_digest);
}

#[test]
fn omitted_or_reclassified_mandatory_requirement_is_rejected() {
    for id in [
        "image-update-recovery",
        "build-integrity",
        "package-function",
        "operator-recovery",
        "rollout-health",
        "rollout-observation",
    ] {
        let mut policy = contract();
        policy.requirements.retain(|gate| gate.id != id);
        assert!(policy.validate().is_err(), "omitted {id}");
    }
    let mut policy = contract();
    policy
        .requirements
        .iter_mut()
        .find(|gate| gate.id == "image-update-recovery")
        .unwrap()
        .scope = QualificationScope::Release;
    assert!(policy.validate().is_err());
    let mut policy = contract();
    policy
        .requirements
        .iter_mut()
        .find(|gate| gate.id == "rollout-health")
        .unwrap()
        .phase = QualificationPhase::Build;
    assert!(policy.validate().is_err());
}

#[test]
fn contract_rejects_weakened_platform_and_production_obligations() {
    let mut policy = contract();
    policy.targets.pop();
    assert!(policy.validate().is_err());
    let mut policy = contract();
    policy.thresholds.get_mut("stable").unwrap().soak_seconds = 0;
    assert!(policy.validate().is_err());
    let mut policy = contract();
    policy
        .thresholds
        .get_mut("emergency")
        .unwrap()
        .require_independent_review = false;
    assert!(policy.validate().is_err());
    let mut policy = contract();
    policy.package_rules[0].inherit_dependency_obligations = false;
    assert!(policy.validate().is_err());
}

#[test]
fn unknown_and_duplicate_contract_fields_fail_closed() {
    let mut value = serde_json::to_value(contract()).unwrap();
    value["allow_failed_gates"] = true.into();
    assert!(serde_json::from_value::<QualificationContractV1>(value).is_err());
    assert!(
        canonical::from_slice::<QualificationContractV1>(
            br#"{"id":"a","id":"b"}"#,
            "duplicate contract"
        )
        .is_err()
    );
}
