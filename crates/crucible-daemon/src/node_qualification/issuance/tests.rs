//! Population assembly models; these checks issue no native qualification.

// crucible-lint: allow panic-shortcut -- These issuance tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;

struct ModelAuthority {
    plan: ContentRef,
    reject_result: bool,
}

impl InstalledWitnessAuthority for ModelAuthority {
    fn authenticate_plan(
        &self,
        reference: &ContentRef,
        _: &[u8],
        _: &WitnessPlan,
    ) -> Result<(), QualificationError> {
        if reference != &self.plan {
            return Err(QualificationError::Refused("model untrusted plan"));
        }
        Ok(())
    }

    fn authenticate_result(
        &self,
        _: &WitnessPlan,
        _: &PlannedWitnessCase,
        _: CaseVerdict,
        _: &ContentRef,
        _: &[u8],
    ) -> Result<(), QualificationError> {
        if self.reject_result {
            return Err(QualificationError::Refused(
                "model rejected original result",
            ));
        }
        Ok(())
    }
}

fn reference(bytes: &[u8]) -> ContentRef {
    canonical::content_ref(bytes, "application/json").unwrap()
}

fn model_plan() -> WitnessPlan {
    let axis = reference(b"{}");
    let unit = QualificationUnit {
        implementation: axis.clone(),
        realization: axis.clone(),
        descriptors: axis.clone(),
        contracts: axis.clone(),
        port_profiles: axis.clone(),
        environment: axis.clone(),
        harness: axis.clone(),
        fixtures: axis.clone(),
        specification: normative_specification().unwrap().0,
    };
    // Reusing one modeled criterion across rows exercises only population data
    // plumbing; a native installed authority must reject this fabricated policy.
    WitnessPlan {
        schema: "crucible.node-witness-plan.v1".into(),
        unit,
        classes: BTreeSet::from([QualificationClass::BaseProvider]),
        requirements: requirement_catalog()
            .unwrap()
            .1
            .into_iter()
            .map(|id| {
                (
                    id.to_owned(),
                    WitnessCriterion::Applicable {
                        cases: vec!["model-a".into(), "model-b".into()],
                        criterion: axis.clone(),
                    },
                )
            })
            .collect(),
        cases: ["model-a", "model-b"]
            .into_iter()
            .map(|id| PlannedWitnessCase {
                id: id.into(),
                kind: CaseKind::Model,
                classes: BTreeSet::from([QualificationClass::BaseProvider]),
                oracle: axis.clone(),
            })
            .collect(),
        limitations: axis,
    }
}

fn encode(plan: &WitnessPlan) -> (Vec<u8>, ContentRef) {
    let bytes = canonical::canonical_json(&serde_json::to_value(plan).unwrap()).unwrap();
    let reference = reference(&bytes);
    (bytes, reference)
}

fn population() -> (WitnessPopulation, ModelAuthority) {
    let (bytes, plan) = encode(&model_plan());
    let authority = ModelAuthority {
        plan: plan.clone(),
        reject_result: false,
    };
    (
        WitnessPopulation::install(&bytes, &plan, &authority, QualificationLimits::default())
            .unwrap(),
        authority,
    )
}

#[test]
fn failed_original_cannot_be_replaced_by_passing_retry() {
    let (mut population, authority) = population();
    let failed = b"{\"failed\":true}";
    population
        .record(
            "model-a",
            CaseVerdict::Failed,
            &reference(failed),
            failed,
            &authority,
        )
        .unwrap();
    let passing = b"{\"passed\":true}";
    assert!(
        population
            .record(
                "model-a",
                CaseVerdict::Passed,
                &reference(passing),
                passing,
                &authority
            )
            .is_err()
    );
    population
        .record(
            "model-b",
            CaseVerdict::Passed,
            &reference(passing),
            passing,
            &authority,
        )
        .unwrap();

    let issued = population.finish().unwrap();
    issued.reference().verify(issued.bytes()).unwrap();
    let claim: QualificationClaim = serde_json::from_slice(issued.bytes()).unwrap();
    assert_eq!(
        claim.requirements.len(),
        requirement_catalog().unwrap().1.len()
    );
    assert!(
        claim
            .requirements
            .iter()
            .all(|row| row.disposition == RequirementDisposition::Failed)
    );
    assert!(
        claim
            .requirements
            .iter()
            .all(|row| row.cases[0].verdict == CaseVerdict::Failed)
    );
    assert!(
        issued
            .objects()
            .iter()
            .any(|(ref_, bytes)| *ref_ == reference(failed) && bytes.as_slice() == failed)
    );
}

#[test]
fn missing_originals_remain_not_executed_and_authentication_refusal_is_atomic() {
    let (mut population, mut authority) = population();
    let bytes = b"{}";
    authority.reject_result = true;
    assert!(
        population
            .record(
                "model-a",
                CaseVerdict::Passed,
                &reference(bytes),
                bytes,
                &authority
            )
            .is_err()
    );
    authority.reject_result = false;
    population
        .record(
            "model-b",
            CaseVerdict::Passed,
            &reference(bytes),
            bytes,
            &authority,
        )
        .unwrap();

    let issued = population.finish().unwrap();
    let claim: QualificationClaim = serde_json::from_slice(issued.bytes()).unwrap();
    assert!(
        claim
            .requirements
            .iter()
            .all(|row| row.disposition == RequirementDisposition::NotExecuted)
    );
    let missing = &claim.requirements[0].cases[0];
    assert_eq!(missing.kind, CaseKind::Model);
    assert_eq!(missing.verdict, CaseVerdict::NotExecuted);
    let (_, bytes) = issued
        .objects()
        .iter()
        .find(|(ref_, _)| ref_ == &missing.result)
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(bytes.as_slice()).unwrap();
    assert_eq!(value["case"], "model-a");
    assert_eq!(value["verdict"], "not_executed");
}

#[test]
fn incomplete_or_untrusted_installed_criteria_refuse_before_collection() {
    let mut plan = model_plan();
    let authority = ModelAuthority {
        plan: reference(b"{}"),
        reject_result: false,
    };
    let (bytes, ref_) = encode(&plan);
    assert!(
        WitnessPopulation::install(&bytes, &ref_, &authority, QualificationLimits::default())
            .is_err()
    );
    plan.requirements.remove("CN-NODE-1");
    let (bytes, ref_) = encode(&plan);
    let authority = ModelAuthority {
        plan: ref_.clone(),
        reject_result: false,
    };
    assert!(
        WitnessPopulation::install(&bytes, &ref_, &authority, QualificationLimits::default())
            .is_err()
    );

    let mut plan = model_plan();
    plan.cases.push(PlannedWitnessCase {
        id: "unused".into(),
        ..plan.cases[0].clone()
    });
    let (bytes, ref_) = encode(&plan);
    let authority = ModelAuthority {
        plan: ref_.clone(),
        reject_result: false,
    };
    assert!(
        WitnessPopulation::install(&bytes, &ref_, &authority, QualificationLimits::default())
            .is_err()
    );
}

#[test]
fn changed_and_over_budget_result_bytes_do_not_consume_original_case() {
    let (mut population, authority) = population();
    assert!(
        population
            .record(
                "model-a",
                CaseVerdict::Passed,
                &reference(b"{}"),
                b"[]",
                &authority
            )
            .is_err()
    );
    population.limits.maximum_total_evidence_bytes = 1;
    assert!(
        population
            .record(
                "model-a",
                CaseVerdict::Passed,
                &reference(b"{}"),
                b"{}",
                &authority
            )
            .is_err()
    );
    assert!(population.recorded.is_empty());
    assert_eq!(population.recorded_bytes, 0);
}
