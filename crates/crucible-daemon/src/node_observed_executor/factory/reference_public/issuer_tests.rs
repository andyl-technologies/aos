//! Native-backed negative checks for the private installed qualification issuer.
//!
//! One genuine candidate supplies immutable original observations. These tests
//! exercise rejection, not full behavioral qualification or ordinary readiness.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crucible_node_contract::Bytes;
use serde_json::Value;

#[test]
#[ignore = "requires the compile-pinned source-built reference implementation"]
fn genuine_original_population_cannot_authorize_synthetic_or_incomplete_acceptance() {
    let nonce = super::super::candidate::entropy().unwrap();
    let suffix = canonical::content_ref(nonce.as_slice(), "application/octet-stream").unwrap();
    let directory = std::env::temp_dir().join(format!(
        "refiss-{}-{}",
        std::process::id(),
        &suffix.hash.digest[..16]
    ));
    let receiver = super::super::harness::start(directory.clone()).unwrap();
    let original = receiver
        .recv_timeout(std::time::Duration::from_secs(60))
        .expect("original owning actor did not finish")
        .expect("original candidate setup failed");

    assert!(
        original.succeeded(),
        "original failed result: {:?}",
        original.original_result()
    );
    assert!(original.population_result().is_some());
    let authority = SourceAuthority::new(&original).unwrap();
    let criteria = authority.criteria;
    let world_case = criteria
        .plan
        .cases
        .iter()
        .find(|case| case.id == WORLD_CASE)
        .unwrap();
    let retirement_case = criteria
        .plan
        .cases
        .iter()
        .find(|case| case.id == RETIREMENT_CASE)
        .unwrap();

    // Each positive premise is an actual actor-issued original, so a missing
    // lifecycle object cannot accidentally make the negative probe vacuous.
    authenticate_original(&authority, world_case, original.original_bytes());
    authenticate_original(&authority, retirement_case, original.retirement_bytes());
    assert_eq!(authority.retirement_verdict().unwrap(), CaseVerdict::Passed);

    reject_rewritten_lifecycle(&authority, world_case, &original);
    reject_rewritten_retirement(&authority, retirement_case, &original);
    reject_missing_reviews(&authority);
    reject_changed_scope(&authority);

    let issued = SourceIssuedQualification::issue(original).unwrap();
    let claim: QualificationClaim = serde_json::from_value(
        canonical::parse_json(issued.report().bytes(), 1024 * 1024).unwrap(),
    )
    .unwrap();
    assert_eq!(claim.requirements.len(), 382);
    assert!(claim.requirements.iter().any(|row| {
        row.cases
            .iter()
            .any(|case| case.verdict == CaseVerdict::NotExecuted)
    }));

    // This constructor deliberately takes no caller-created accepted token or
    // authority. Both original native subsets still cannot waive full review.
    assert!(issued.admit_current().is_err());
    assert!(issued.admit_ordinary(&claim.unit, &claim.classes).is_err());
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
#[ignore = "requires the compile-pinned source-built reference implementation"]
fn original_failed_setup_cannot_be_replaced_by_passing_evidence() {
    let nonce = super::super::candidate::entropy().unwrap();
    let suffix = canonical::content_ref(nonce.as_slice(), "application/octet-stream").unwrap();
    // This deliberately exceeds the endpoint's checked Unix socket length.
    // It is an original setup-refusal witness, never an executed native-window
    // witness or permission to alter the supported transport limit.
    let directory = std::env::temp_dir().join(format!(
        "reference-issuer-overlong-path-{}-{}",
        "x".repeat(80),
        &suffix.hash.digest[..16]
    ));
    let original = super::super::harness::start(directory.clone())
        .unwrap()
        .recv_timeout(std::time::Duration::from_secs(60))
        .expect("original owning actor did not finish")
        .expect("original actor did not retain setup failure");

    assert!(!original.succeeded());
    assert!(original.population_result().is_some());
    let failed = canonical::parse_json(original.original_bytes(), 16 * 1024 * 1024).unwrap();
    assert_eq!(failed["phase"], "native-preparation");
    assert!(
        failed["error"]
            .as_str()
            .unwrap()
            .contains("socket path geometry")
    );

    let authority = SourceAuthority::new(&original).unwrap();
    assert_eq!(authority.world_verdict(), CaseVerdict::Failed);
    let criteria = authority.criteria;
    let mut population = WitnessPopulation::install(
        &criteria.bytes,
        &criteria.reference,
        &authority,
        QualificationLimits::default(),
    )
    .unwrap();
    let reference = canonical::content_ref(original.original_bytes(), "application/json").unwrap();
    population
        .record(
            WORLD_CASE,
            CaseVerdict::Failed,
            &reference,
            original.original_bytes(),
            &authority,
        )
        .unwrap();
    assert!(
        population
            .record(
                WORLD_CASE,
                CaseVerdict::Passed,
                &reference,
                original.original_bytes(),
                &authority
            )
            .is_err()
    );
    let case = criteria
        .plan
        .cases
        .iter()
        .find(|case| case.id == WORLD_CASE)
        .unwrap();
    assert!(
        authority
            .authenticate_result(
                &criteria.plan,
                case,
                CaseVerdict::Passed,
                &reference,
                original.original_bytes()
            )
            .is_err()
    );

    let report = population.finish().unwrap();
    let claim: QualificationClaim =
        serde_json::from_value(canonical::parse_json(report.bytes(), 1024 * 1024).unwrap())
            .unwrap();
    assert!(
        claim
            .requirements
            .iter()
            .flat_map(|row| &row.cases)
            .any(|case| { case.case == WORLD_CASE && case.verdict == CaseVerdict::Failed })
    );
    let issued = SourceIssuedQualification::issue(original).unwrap();
    assert!(issued.admit_current().is_err());
    std::fs::remove_dir_all(directory).unwrap();
}

fn authenticate_original(authority: &SourceAuthority<'_>, case: &PlannedWitnessCase, bytes: &[u8]) {
    let reference = canonical::content_ref(bytes, "application/json").unwrap();
    authority
        .authenticate_result(
            &authority.criteria.plan,
            case,
            CaseVerdict::Passed,
            &reference,
            bytes,
        )
        .unwrap();
}

fn reject_rewritten_lifecycle(
    authority: &SourceAuthority<'_>,
    case: &PlannedWitnessCase,
    original: &CandidateHarnessResult,
) {
    let value = canonical::parse_json(original.original_bytes(), 16 * 1024 * 1024).unwrap();
    for field in [
        "activation",
        "coordinator",
        "prepared_nodes",
        "prepared_owners",
    ] {
        let mut changed = value.clone();
        assert!(changed.as_object_mut().unwrap().remove(field).is_some());
        reject_changed_result(authority, case, &changed);
    }

    for field in ["complete_world_activation", "original_consumptions"] {
        let mut changed = value.clone();
        let window = changed["windows"]
            .as_array_mut()
            .unwrap()
            .first_mut()
            .unwrap();
        let encoded: Bytes = serde_json::from_value(window["bytes"].clone()).unwrap();
        let mut evidence = canonical::parse_json(encoded.as_slice(), 16 * 1024 * 1024).unwrap();
        let lifecycle = evidence["lifecycle"].as_object_mut().unwrap();
        assert!(lifecycle.remove(field).is_some());
        let bytes = canonical::canonical_json(&evidence).unwrap();
        window["reference"] =
            serde_json::to_value(canonical::content_ref(&bytes, "application/json").unwrap())
                .unwrap();
        window["bytes"] = serde_json::to_value(Bytes::new(bytes)).unwrap();
        reject_changed_result(authority, case, &changed);
    }
}

fn reject_rewritten_retirement(
    authority: &SourceAuthority<'_>,
    case: &PlannedWitnessCase,
    original: &CandidateHarnessResult,
) {
    let value = canonical::parse_json(original.retirement_bytes(), 1024 * 1024).unwrap();
    for field in [
        "original_result",
        "original_scopes",
        "reclaimed_original_peers",
    ] {
        let mut changed = value.clone();
        assert!(changed.as_object_mut().unwrap().remove(field).is_some());
        reject_changed_result(authority, case, &changed);
    }
}

fn reject_changed_result(
    authority: &SourceAuthority<'_>,
    case: &PlannedWitnessCase,
    changed: &Value,
) {
    let bytes = canonical::canonical_json(changed).unwrap();
    let reference = canonical::content_ref(&bytes, "application/json").unwrap();
    assert!(
        authority
            .authenticate_result(
                &authority.criteria.plan,
                case,
                CaseVerdict::Passed,
                &reference,
                &bytes,
            )
            .is_err()
    );
}

fn reject_missing_reviews(authority: &SourceAuthority<'_>) {
    let criteria = authority.criteria;
    let mut population = WitnessPopulation::install(
        &criteria.bytes,
        &criteria.reference,
        authority,
        QualificationLimits::default(),
    )
    .unwrap();
    let world_bytes = authority.original.original_bytes();
    let world_reference = canonical::content_ref(world_bytes, "application/json").unwrap();
    population
        .record(
            WORLD_CASE,
            CaseVerdict::Passed,
            &world_reference,
            world_bytes,
            authority,
        )
        .unwrap();
    assert!(
        population
            .record(
                WORLD_CASE,
                CaseVerdict::Failed,
                &world_reference,
                world_bytes,
                authority
            )
            .is_err()
    );

    let residual = criteria
        .plan
        .cases
        .iter()
        .find(|case| case.id.starts_with("reference/review/"))
        .unwrap();
    let invented = br#"{"caller_asserted_pass":true}"#;
    let reference = canonical::content_ref(invented, "application/json").unwrap();
    assert!(
        population
            .record(
                &residual.id,
                CaseVerdict::Passed,
                &reference,
                invented,
                authority
            )
            .is_err()
    );

    let issued = population.finish().unwrap();
    let mut claim: QualificationClaim =
        serde_json::from_value(canonical::parse_json(issued.bytes(), 1024 * 1024).unwrap())
            .unwrap();
    for row in &mut claim.requirements {
        if row.disposition != crate::node_qualification::RequirementDisposition::NotApplicable {
            row.disposition = crate::node_qualification::RequirementDisposition::Passed;
        }
        for case in &mut row.cases {
            case.verdict = CaseVerdict::Passed;
        }
    }
    let bytes = canonical::canonical_json(&serde_json::to_value(&claim).unwrap()).unwrap();
    let reference = canonical::content_ref(&bytes, "application/json").unwrap();
    assert!(
        authority
            .authenticate_claim(&reference, &bytes, &claim)
            .is_err()
    );
}

fn reject_changed_scope(authority: &SourceAuthority<'_>) {
    let criteria = authority.criteria;
    let changed =
        canonical::content_ref(b"changed immutable implementation", "text/plain").unwrap();
    let mut unit = criteria.plan.unit.clone();
    unit.implementation = changed;
    assert!(
        authority
            .applicability(&unit, &criteria.plan.classes, &criteria.reference)
            .is_err()
    );
    let mut classes = criteria.plan.classes.clone();
    classes.insert(QualificationClass::ExactTiming);
    assert!(
        authority
            .applicability(&criteria.plan.unit, &classes, &criteria.reference)
            .is_err()
    );
    let mut plan = criteria.plan.clone();
    plan.unit = unit;
    let bytes = canonical::canonical_json(&serde_json::to_value(&plan).unwrap()).unwrap();
    let reference = canonical::content_ref(&bytes, "application/json").unwrap();
    assert!(
        authority
            .authenticate_plan(&reference, &bytes, &plan)
            .is_err()
    );
}
