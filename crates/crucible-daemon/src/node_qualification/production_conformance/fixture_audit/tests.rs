//! Checks complete planning data without source installation or native execution.

use super::*;
use crate::node_qualification::{
    CaseKind, QualificationUnit, RequirementDisposition, WitnessCriterion, normative_specification,
    requirement_catalog,
};

fn plan() -> Result<(WitnessPlan, ContentRef), QualificationError> {
    let object = canonical::content_ref(b"inert audit metadata", "application/json")?;
    let classes = BTreeSet::from([QualificationClass::BaseProvider]);
    let mut requirements = BTreeMap::new();
    let mut cases = Vec::new();
    for requirement in requirement_catalog()?.1 {
        let id = format!("unexecuted/{requirement}");
        requirements.insert(
            requirement.to_owned(),
            WitnessCriterion::Applicable {
                cases: vec![id.clone()],
                criterion: object.clone(),
            },
        );
        cases.push(PlannedWitnessCase {
            id,
            kind: CaseKind::RealizedProvider,
            classes: classes.clone(),
            oracle: object.clone(),
        });
    }
    // Additional finite windows cannot remove the original unexecuted case.
    let criterion = requirements.get_mut("CN-QUANT-10").ok_or_else(refused)?;
    let WitnessCriterion::Applicable {
        cases: required, ..
    } = criterion
    else {
        return Err(refused());
    };
    for index in 0..9 {
        let id = format!("finite-window/{index}");
        required.push(id.clone());
        cases.push(PlannedWitnessCase {
            id,
            kind: CaseKind::RealizedProvider,
            classes: classes.clone(),
            oracle: object.clone(),
        });
    }
    required.sort();
    cases.sort_by(|left, right| left.id.cmp(&right.id));
    let unit = QualificationUnit {
        implementation: object.clone(),
        realization: object.clone(),
        descriptors: object.clone(),
        contracts: object.clone(),
        port_profiles: object.clone(),
        environment: object.clone(),
        harness: object.clone(),
        fixtures: object.clone(),
        specification: normative_specification()?.0,
    };
    let plan = WitnessPlan {
        schema: "crucible.node-witness-plan.v1".to_owned(),
        unit,
        classes,
        requirements,
        cases,
        limitations: object,
    };
    let bytes = canonical::canonical_json(
        &serde_json::to_value(&plan).map_err(crucible_node_contract::ContractError::from)?,
    )?;
    let reference = canonical::content_ref(&bytes, "application/json")?;
    Ok((plan, reference))
}

#[test]
fn all_original_planning_cases_remain_unexecuted_and_evaluation_refuses()
-> Result<(), QualificationError> {
    let (plan, reference) = plan()?;
    let audit = PlannedFixtureAudit::prepare(
        &plan,
        &reference,
        QualificationLimits::default(),
        8 * 1024 * 1024,
    )?;

    assert_eq!(audit.record().original.requirements.len(), 382);
    assert_eq!(
        audit
            .record()
            .original
            .requirements
            .iter()
            .map(|row| row.cases.len())
            .sum::<usize>(),
        391
    );
    assert!(audit.record().original.requirements.iter().all(|row| {
        row.disposition == RequirementDisposition::NotExecuted
            && row.not_applicable_reason.is_none()
            && row
                .cases
                .iter()
                .all(|case| case.verdict == CaseVerdict::NotExecuted)
    }));
    assert!(matches!(
        audit.record().decision,
        AcceptanceDecision::Refused { .. }
    ));
    audit.claim().verify(audit.original_bytes())?;
    assert!(
        NoAcceptedClaim
            .authenticate_claim(
                audit.claim(),
                audit.original_bytes(),
                &audit.record().original
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn changed_original_plan_and_tiny_body_credit_refuse_before_audit() -> Result<(), QualificationError>
{
    let (plan, reference) = plan()?;
    let mut changed = plan.clone();
    changed.limitations = canonical::content_ref(b"foreign", "application/json")?;
    assert!(
        PlannedFixtureAudit::prepare(
            &changed,
            &reference,
            QualificationLimits::default(),
            8 * 1024 * 1024
        )
        .is_err()
    );

    let limits = QualificationLimits {
        maximum_claim_bytes: 1,
        ..QualificationLimits::default()
    };
    assert!(PlannedFixtureAudit::prepare(&plan, &reference, limits, 8 * 1024 * 1024).is_err());
    assert!(
        PlannedFixtureAudit::prepare(&plan, &reference, QualificationLimits::default(), 1).is_err()
    );
    Ok(())
}
