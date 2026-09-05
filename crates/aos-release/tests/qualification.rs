//! Adversarial validation of the shared source-controlled qualification policy.

use aos_release::{
    canonical,
    plan::ReleaseClass,
    qualification::{QualificationContract, QualificationPhase, QualificationScope},
};

fn contract() -> QualificationContract {
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
    assert!(serde_json::from_value::<QualificationContract>(value).is_err());
    assert!(
        canonical::from_slice::<QualificationContract>(
            br#"{"id":"a","id":"b"}"#,
            "duplicate contract"
        )
        .is_err()
    );
}

#[test]
fn archival_contracts_preserve_their_original_bytes_and_gate_domains() {
    let bytes = include_bytes!("fixtures/qualification-contract-v1.json");
    let value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    let archived: QualificationContract =
        canonical::from_slice(bytes, "archived qualification").unwrap();
    archived.validate().unwrap();
    assert_eq!(
        canonical::to_vec(&archived).unwrap(),
        canonical::canonical_json(&value).unwrap()
    );
    assert_eq!(
        archived.digest().unwrap(),
        aos_release::Sha256Digest::of_canonical(aos_release::qualification::CONTRACT_V1, &value)
            .unwrap()
    );
    let gates = archived.gates(ReleaseClass::Stable).unwrap();
    for (gate, requirement) in gates.iter().zip(value["requirements"].as_array().unwrap()) {
        assert_eq!(
            gate.policy_digest,
            aos_release::Sha256Digest::of_canonical(
                aos_release::qualification::CONTRACT_V1,
                &(requirement, &value["thresholds"]["stable"])
            )
            .unwrap()
        );
    }
    let mut smuggled = value;
    smuggled["claims"] = serde_json::to_value(contract().claims).unwrap();
    let parsed: QualificationContract = serde_json::from_value(smuggled).unwrap();
    assert!(parsed.validate().is_err());
}
