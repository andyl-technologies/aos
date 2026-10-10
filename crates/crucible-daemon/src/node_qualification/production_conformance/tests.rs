//! Exercises report substitution, omission and pre-effect credit refusals.
//!
//! These are host verifier controls, not executed provider/class evidence.

use std::collections::{BTreeMap, BTreeSet};

use crucible_node_contract::{Id, U64, canonical};
use crucible_node_provider::conformance::{
    CheckDisposition, CheckKind, CheckResult, ConformanceReport, EndpointMeasurement, Expectation,
    ProbePlan, ProbeStep,
};

use super::{ProtocolCase, QualificationError, QualificationLimits, protocol};

fn original() -> Result<(ProtocolCase, ConformanceReport), QualificationError> {
    let plan = ProbePlan {
        schema_version: 1,
        fixture: Id::new("original-fixture")?,
        required_checks: BTreeSet::from([CheckKind::ActivationGate]),
        steps: vec![ProbeStep::Exchange {
            id: Id::new("before-world-commit")?,
            check: CheckKind::ActivationGate,
            request: serde_json::json!({"method": "begin"}),
            expected: Expectation::Error {
                code: Id::new("not_active")?,
                effect: crucible_node_provider::bodies::EffectCertainty::NotStarted,
            },
            assertions: Vec::new(),
            captures: BTreeMap::new(),
        }],
    };
    let plan_value =
        serde_json::to_value(&plan).map_err(crucible_node_contract::ContractError::from)?;
    let plan_bytes = canonical::canonical_json(&plan_value)?;
    let peer = canonical::content_ref(
        b"original verifier peer fixture",
        "application/octet-stream",
    )?;
    let report = ConformanceReport {
        schema_version: 1,
        harness: "crucible-node-conformance.protocol-v1".into(),
        harness_executable: None,
        plan_identity: canonical::json_hash("cnp.conformance-plan.v1", &plan_value)?,
        fixture: plan.fixture.clone(),
        endpoints: vec![EndpointMeasurement {
            peer_pid: U64::new(42),
            peer_uid: U64::new(1000),
            executable: peer.clone(),
        }],
        results: vec![CheckResult {
            case: plan.steps[0].id().clone(),
            check: Some(CheckKind::ActivationGate),
            disposition: CheckDisposition::Passed,
            request_identity: Some(canonical::json_hash(
                "cnp.conformance-request.v1",
                &serde_json::json!({}),
            )?),
            response_identity: Some(canonical::json_hash(
                "cnp.conformance-reply.v1",
                &serde_json::json!({}),
            )?),
            diagnostic: "protocol oracle satisfied".into(),
        }],
        missing_checks: BTreeSet::new(),
        protocol_only: true,
    };
    Ok((
        ProtocolCase {
            case: "original-case".into(),
            plan,
            oracle: canonical::content_ref(&plan_bytes, "application/json")?,
            peer_executable: peer,
            peer_uid: 1000,
        },
        report,
    ))
}

#[test]
fn original_protocol_report_keeps_its_narrow_scope() -> Result<(), QualificationError> {
    let (case, report) = original()?;
    protocol::check_plan(&case, QualificationLimits::default())?;
    protocol::check_report(&case.plan, &report, &case.peer_executable, case.peer_uid)?;
    assert!(report.passed());
    Ok(())
}

#[test]
fn substituted_plan_and_case_population_are_refused() -> Result<(), QualificationError> {
    let (case, mut report) = original()?;
    report.fixture = Id::new("foreign-fixture")?;
    assert!(
        protocol::check_report(&case.plan, &report, &case.peer_executable, case.peer_uid).is_err()
    );
    report.fixture = case.plan.fixture.clone();
    report.results.clear();
    assert!(
        protocol::check_report(&case.plan, &report, &case.peer_executable, case.peer_uid).is_err()
    );
    Ok(())
}

#[test]
fn missing_required_check_cannot_be_hidden() -> Result<(), QualificationError> {
    let (case, mut report) = original()?;
    report.results[0].disposition = CheckDisposition::Failed;
    assert!(
        protocol::check_report(&case.plan, &report, &case.peer_executable, case.peer_uid).is_err()
    );
    report.missing_checks.insert(CheckKind::ActivationGate);
    protocol::check_report(&case.plan, &report, &case.peer_executable, case.peer_uid)?;
    assert!(!report.passed());
    Ok(())
}

#[test]
fn changed_peer_and_absent_measurement_are_refused() -> Result<(), QualificationError> {
    let (case, mut report) = original()?;
    report.endpoints[0].peer_uid = U64::new(1001);
    assert!(
        protocol::check_report(&case.plan, &report, &case.peer_executable, case.peer_uid).is_err()
    );
    report.endpoints.clear();
    assert!(
        protocol::check_report(&case.plan, &report, &case.peer_executable, case.peer_uid).is_err()
    );
    Ok(())
}

#[test]
fn model_promotion_and_unexplained_nonexecution_are_refused() -> Result<(), QualificationError> {
    let (case, mut report) = original()?;
    report.protocol_only = false;
    assert!(
        protocol::check_report(&case.plan, &report, &case.peer_executable, case.peer_uid).is_err()
    );
    report.protocol_only = true;
    report.results[0].disposition = CheckDisposition::NotExecuted;
    report.missing_checks.insert(CheckKind::ActivationGate);
    assert!(
        protocol::check_report(&case.plan, &report, &case.peer_executable, case.peer_uid).is_err()
    );
    Ok(())
}

#[test]
fn report_credit_is_required_before_connector_effects() -> Result<(), QualificationError> {
    let (case, _) = original()?;
    let limits = QualificationLimits {
        maximum_claim_bytes: 16_383,
        ..QualificationLimits::default()
    };
    assert!(protocol::check_plan(&case, limits).is_err());
    let limits = QualificationLimits {
        maximum_claim_bytes: 16_384,
        ..limits
    };
    protocol::check_plan(&case, limits)?;
    Ok(())
}

#[test]
fn complete_observation_encoding_credit_precedes_copying() -> Result<(), QualificationError> {
    let (_, report) = original()?;
    let bytes = serde_json::to_vec(&report).map_err(crucible_node_contract::ContractError::from)?;

    assert_eq!(protocol::encoded_size(&report, bytes.len())?, bytes.len());
    assert!(protocol::encoded_size(&report, bytes.len() - 1).is_err());
    assert!(protocol::encoded_size(&report, 0).is_err());
    Ok(())
}
