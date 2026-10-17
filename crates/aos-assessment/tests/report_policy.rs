//! Canonical report policy, frozen predicates and independent automation failure.

mod common;

use anyhow::Result;
use aos_assessment::{
    evaluator::evaluate, input::Profile, report_policy::*, result::Applicability,
    security::CoverageState,
};
use aos_contract::Sha256Digest;

#[test]
fn caller_conditions_normalize_but_wire_policies_refuse_ambiguity() -> Result<()> {
    let policy = AssessmentReportPolicyV1::new(vec![
        ReportFailureCondition::Vulnerabilities,
        ReportFailureCondition::Coverage,
        ReportFailureCondition::Coverage,
    ])?;
    assert_eq!(
        policy.conditions,
        [
            ReportFailureCondition::Coverage,
            ReportFailureCondition::Vulnerabilities
        ]
    );
    assert_eq!(
        AssessmentReportPolicyV1::from_slice(&serde_json::to_vec(&policy)?)?,
        policy
    );
    assert!(AssessmentReportPolicyV1::new(vec![]).is_err());
    for value in [
        serde_json::json!({"schema":"aos.assessment-report-policy/v1", "conditions":[]}),
        serde_json::json!({"schema":"aos.assessment-report-policy/v1", "conditions":["coverage","coverage"]}),
        serde_json::json!({"schema":"aos.assessment-report-policy/v1", "conditions":["updates","coverage"]}),
        serde_json::json!({"schema":"aos.assessment-report-policy/v1", "conditions":["coverage"], "permission":"release"}),
        serde_json::json!({"schema":"aos.assessment-report-policy/v1", "conditions":null}),
    ] {
        assert!(AssessmentReportPolicyV1::from_slice(&serde_json::to_vec(&value)?).is_err());
    }
    assert!(AssessmentReportPolicyV1::from_slice(b"{\"schema\":\"a\",\"schema\":\"b\"}").is_err());
    Ok(())
}

#[test]
fn raw_vulnerability_claims_fail_independently_from_dispositions_or_match_class() -> Result<()> {
    let data = common::fixture("1.2.0")?;
    let input = data.freeze(vec![Profile::Vulnerabilities], common::evaluated_at()?)?;
    let assessment = evaluate(&input, &data)?;
    let policy = AssessmentReportPolicyV1::new(vec![ReportFailureCondition::Vulnerabilities])?;
    for applicability in [
        Applicability::Affected,
        Applicability::PotentiallyAffected,
        Applicability::Unknown,
    ] {
        let mut result = assessment.clone();
        result.subject_results[0].findings[0].applicability = applicability;
        result.subject_results[0].findings[0].disposition_refs =
            vec![Sha256Digest::of_bytes("reviewed statement")];
        let outcome = policy.evaluate(&result)?;
        assert!(outcome.failed);
        assert_eq!(outcome.matched_conditions, policy.conditions);
        outcome.to_bytes(&result)?;
    }
    assert!(
        AssessmentReportPolicyV1::new(vec![ReportFailureCondition::Updates])?
            .evaluate(&assessment)
            .is_err()
    );
    assert!(policy.validate_profiles(&[Profile::Updates]).is_err());
    Ok(())
}

#[test]
fn only_actionable_updates_match_and_outcomes_bind_exact_assessments() -> Result<()> {
    let now = common::evaluated_at()?;
    let mut data = common::updates::data(now.clone())?;
    let input = data.freeze(vec![Profile::Updates], now.clone())?;
    let assessment = evaluate(&input, &data)?;
    let policy = AssessmentReportPolicyV1::new(vec![ReportFailureCondition::Updates])?;
    let outcome = policy.evaluate(&assessment)?;
    assert!(outcome.failed);
    outcome.to_bytes(&assessment)?;
    let mut forged = outcome.clone();
    forged.failed = false;
    assert!(forged.to_bytes(&assessment).is_err());
    let mut forged = outcome;
    forged.assessment_digest = Sha256Digest::of_bytes("other result");
    assert!(forged.to_bytes(&assessment).is_err());

    data.history[0].first_observed_at = now.clone();
    data.upstream[0].observation.candidates[0].first_observed_at_unix = now.unix_seconds();
    let input = data.freeze(vec![Profile::Updates], now)?;
    let stabilizing = evaluate(&input, &data)?;
    assert!(!policy.evaluate(&stabilizing)?.failed);
    Ok(())
}

#[test]
fn incomplete_coverage_is_separate_from_empty_findings_and_transport_failure() -> Result<()> {
    let data = common::fixture("9.0.0")?;
    let input = data.freeze(vec![Profile::Vulnerabilities], common::evaluated_at()?)?;
    let mut assessment = evaluate(&input, &data)?;
    assert!(assessment.subject_results[0].findings.is_empty());
    let policy = AssessmentReportPolicyV1::new(vec![ReportFailureCondition::Coverage])?;
    assert!(!policy.evaluate(&assessment)?.failed);
    assessment.coverage = CoverageState::Unknown;
    let outcome = policy.evaluate(&assessment)?;
    assert!(outcome.failed);
    assert_eq!(
        outcome.matched_conditions,
        [ReportFailureCondition::Coverage]
    );
    assert!(policy.validate_profiles(&[]).is_err());
    assessment.schema = "unsupported-result".into();
    assert!(policy.evaluate(&assessment).is_err());
    Ok(())
}
