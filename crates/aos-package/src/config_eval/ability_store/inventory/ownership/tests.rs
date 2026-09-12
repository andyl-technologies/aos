//! Focused tests for durable ownership provenance helpers.

use aos_ability_validate::test_support::checked_systemd_manager_effect_plan;

use super::*;

fn distinct_artifact(label: &str, store_hash: char) -> ArtifactReference {
    ArtifactReference {
        content: aos_contract::Sha256Digest::of_bytes(format!("{label} content")),
        store_path: format!("/nix/store/{}-{label}", store_hash.to_string().repeat(32)),
        nar_hash: aos_contract::Sha256Digest::of_bytes(format!("{label} nar")),
        closure: aos_contract::Sha256Digest::of_bytes(format!("{label} closure")),
    }
}

#[test]
fn retained_provenance_requires_the_exact_checked_plan_artifacts() {
    let plan = checked_systemd_manager_effect_plan();
    let exact = plan.required_runtime_artifacts().to_vec();
    assert!(!exact.is_empty(), "fixture plan must retain an artifact");

    let mut removed = exact.clone();
    removed.remove(0);

    let mut added = exact.clone();
    added.push(distinct_artifact("added", '1'));
    let added = canonical_artifacts(&added).expect("canonical added artifacts");

    let mut substituted = exact.clone();
    substituted[0] = distinct_artifact("substituted", '2');
    let substituted = canonical_artifacts(&substituted).expect("canonical substituted artifacts");

    for provenance in ["provider owner claim", "provider owner establishment"] {
        authenticate_retained_provenance_artifacts(&plan, &exact, provenance)
            .expect("exact retained artifacts");
        for mutated in [&removed, &added, &substituted] {
            assert!(
                authenticate_retained_provenance_artifacts(&plan, mutated, provenance).is_err(),
                "{provenance} accepted jointly mutated owner artifacts"
            );
        }
    }
}

#[test]
fn receipt_artifact_union_must_retain_the_exact_establishment_vector() {
    let plan = checked_systemd_manager_effect_plan();
    let establishment = plan.required_runtime_artifacts().to_vec();
    assert!(
        !establishment.is_empty(),
        "fixture plan must retain an artifact"
    );

    let mut union = establishment.clone();
    union.push(distinct_artifact("retained-source", '3'));
    let union = canonical_artifacts(&union).expect("canonical retained union");
    validate_receipt_artifact_union(&union, &establishment)
        .expect("a canonical recovery union may retain additional artifacts");

    let mut removed = union.clone();
    removed.retain(|artifact| artifact != &establishment[0]);
    assert!(validate_receipt_artifact_union(&removed, &establishment).is_err());

    let mut substituted = union;
    substituted.retain(|artifact| artifact != &establishment[0]);
    substituted.push(distinct_artifact("substituted-source", '4'));
    let substituted = canonical_artifacts(&substituted).expect("canonical substitution");
    assert!(validate_receipt_artifact_union(&substituted, &establishment).is_err());
}
