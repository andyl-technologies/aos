//! Checks source-plan integrity without claiming executed native qualification.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::node_qualification::{
    CaseVerdict, InstalledWitnessAuthority, QualificationClaim, QualificationLimits,
    RequirementDisposition, WitnessPopulation,
};

fn unit() -> QualificationUnit {
    let placeholder = canonical::content_ref(b"policy-model-only", "text/plain").unwrap();
    QualificationUnit {
        implementation: placeholder.clone(),
        realization: placeholder.clone(),
        descriptors: placeholder.clone(),
        contracts: placeholder.clone(),
        port_profiles: placeholder.clone(),
        environment: placeholder.clone(),
        harness: placeholder.clone(),
        fixtures: placeholder,
        specification: normative_specification().unwrap().0,
    }
}

/// Authenticates only this test's fixed data plan, never behavioral acceptance.
struct PlanDataFixture {
    reference: ContentRef,
    bytes: Vec<u8>,
    plan: WitnessPlan,
}

impl InstalledWitnessAuthority for PlanDataFixture {
    fn authenticate_plan(
        &self,
        reference: &ContentRef,
        bytes: &[u8],
        plan: &WitnessPlan,
    ) -> Result<(), QualificationError> {
        if reference != &self.reference || bytes != self.bytes || plan != &self.plan {
            return Err(refused("changed model policy plan"));
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
        Err(refused(
            "policy data fixture authenticates no observed result",
        ))
    }
}

#[test]
fn compiled_plan_has_every_exact_clause_and_no_bullet_cross_contamination() {
    let criteria = ReferenceQualificationCriteria::build(unit()).unwrap();
    let (_, catalog) = requirement_catalog().unwrap();

    assert_eq!(catalog.len(), 382);
    assert!(criteria.clauses.keys().map(String::as_str).eq(catalog));
    assert_eq!(criteria.plan.requirements.len(), 382);
    for (id, clause) in &criteria.clauses {
        let chapter = criteria.objects.get(&clause.chapter_reference).unwrap();
        clause.chapter_reference.verify(chapter).unwrap();
        let chapter = std::str::from_utf8(chapter).unwrap();
        let first = chapter.lines().nth(clause.line - 1).unwrap();
        let marker = format!("**[{id}]**");
        let offset = first.find(&marker).unwrap();
        assert!(clause.text.starts_with(&first[offset..]));
        assert_eq!(clause.text.matches("**[CN-").count(), 1);
        assert_eq!(clause.specification, criteria.plan.unit.specification);
    }
    assert!(!criteria.clauses["CN-IPC-1"].text.contains("CN-IPC-2"));
    assert!(!criteria.clauses["CN-SEC-1"].text.contains("CN-SEC-2"));
    for (reference, bytes) in &criteria.objects {
        reference.verify(bytes).unwrap();
    }
}

#[test]
fn exclusions_are_exact_conditional_classes_and_never_requirement_families() {
    let criteria = ReferenceQualificationCriteria::build(unit()).unwrap();
    let excluded = criteria
        .plan
        .requirements
        .iter()
        .filter_map(|(id, criterion)| {
            matches!(criterion, WitnessCriterion::NotApplicable { .. }).then_some(id.as_str())
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        excluded,
        BTreeSet::from([
            "CN-TEST-011",
            "CN-TEST-012",
            "CN-TEST-013",
            "CN-TEST-017",
            "CN-TEST-018",
            "CN-TEST-020",
            "CN-TEST-021",
            "CN-TEST-023",
            "CN-TEST-024",
            "CN-TEST-035",
        ])
    );
    for id in [
        "CN-STATE-3",
        "CN-STATE-19",
        "CN-NODE-6",
        "CN-TEST-015",
        "CN-SEC-4",
        "CN-REPLAY-23",
    ] {
        assert!(matches!(
            criteria.plan.requirements[id],
            WitnessCriterion::Applicable { .. }
        ));
    }
    assert!(
        !criteria
            .plan
            .classes
            .contains(&QualificationClass::ExactTiming)
    );
    assert!(
        !criteria
            .plan
            .classes
            .contains(&QualificationClass::Repeatable)
    );
    assert!(
        !criteria
            .plan
            .classes
            .contains(&QualificationClass::ConditionalReplay)
    );
}

#[test]
fn every_native_subset_keeps_the_missing_complete_review_mandatory() {
    let criteria = ReferenceQualificationCriteria::build(unit()).unwrap();
    let mut used = BTreeSet::new();
    for (id, criterion) in &criteria.plan.requirements {
        let WitnessCriterion::Applicable { cases, .. } = criterion else {
            continue;
        };
        let missing = format!("reference/review/{id}");
        assert!(cases.contains(&missing));
        assert!(cases.windows(2).all(|pair| pair[0] < pair[1]));
        for case in cases {
            used.insert(case.as_str());
        }
    }
    assert!(used.contains(WORLD_CASE));
    assert!(used.contains(RETIREMENT_CASE));
    assert!(
        criteria
            .plan
            .cases
            .iter()
            .all(|case| used.contains(case.id.as_str()))
    );
    assert_eq!(criteria.plan.cases.len(), 374);
    let cases = match &criteria.plan.requirements["CN-QUANT-3"] {
        WitnessCriterion::Applicable { cases, .. } => cases,
        _ => panic!("staging is an applicable obligation"),
    };
    assert_eq!(
        cases,
        &[WORLD_CASE.to_owned(), "reference/review/CN-QUANT-3".into()]
    );
}

#[test]
fn an_unexecuted_population_never_infers_passing_behavior_from_the_plan() {
    let criteria = ReferenceQualificationCriteria::build(unit()).unwrap();
    let authority = PlanDataFixture {
        reference: criteria.reference.clone(),
        bytes: criteria.bytes.clone(),
        plan: criteria.plan.clone(),
    };
    let population = WitnessPopulation::install(
        &criteria.bytes,
        &criteria.reference,
        &authority,
        QualificationLimits::default(),
    )
    .unwrap();
    let issued = population.finish().unwrap();
    let claim: QualificationClaim = serde_json::from_slice(issued.bytes()).unwrap();

    assert_eq!(claim.requirements.len(), 382);
    for row in claim.requirements {
        assert!(matches!(
            row.disposition,
            RequirementDisposition::NotExecuted | RequirementDisposition::NotApplicable
        ));
        assert!(
            row.cases
                .iter()
                .all(|case| case.verdict == CaseVerdict::NotExecuted)
        );
    }
}

#[test]
fn a_mutated_plan_is_refused_before_original_result_recording() {
    let criteria = ReferenceQualificationCriteria::build(unit()).unwrap();
    let authority = PlanDataFixture {
        reference: criteria.reference.clone(),
        bytes: criteria.bytes.clone(),
        plan: criteria.plan.clone(),
    };
    let mut changed = criteria.plan.clone();
    changed.requirements.remove("CN-SEC-4");
    let bytes = canonical::canonical_json(&serde_json::to_value(changed).unwrap()).unwrap();
    let reference = canonical::content_ref(&bytes, "application/json").unwrap();
    assert!(
        WitnessPopulation::install(
            &bytes,
            &reference,
            &authority,
            QualificationLimits::default()
        )
        .is_err()
    );

    let mut changed = criteria.plan;
    let WitnessCriterion::Applicable { cases, .. } =
        changed.requirements.get_mut("CN-QUANT-3").unwrap()
    else {
        panic!("staging must remain applicable")
    };
    cases.retain(|case| case == WORLD_CASE);
    let bytes = canonical::canonical_json(&serde_json::to_value(changed).unwrap()).unwrap();
    let reference = canonical::content_ref(&bytes, "application/json").unwrap();
    assert!(
        WitnessPopulation::install(
            &bytes,
            &reference,
            &authority,
            QualificationLimits::default()
        )
        .is_err()
    );
}

#[test]
fn another_specification_cannot_reuse_this_source_owned_population() {
    let mut changed = unit();
    changed.specification =
        canonical::content_ref(b"different specification", "text/plain").unwrap();
    assert!(ReferenceQualificationCriteria::build(changed).is_err());
}
