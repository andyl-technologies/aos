//! Checks original-report lookup and pre-effect credit using explicit data models.
//!
//! These controls do not construct a runner-origin witness or native authority.

use std::{cell::Cell, collections::BTreeMap};

use super::*;
use crate::node_qualification::QualificationUnit;

fn model() -> Result<(WitnessPlan, PlannedWitnessCase, ContentRef), QualificationError> {
    let reference = canonical::content_ref(b"original data fixture", "application/octet-stream")?;
    let case = PlannedWitnessCase {
        id: "original-window".into(),
        kind: CaseKind::RealizedProvider,
        classes: Default::default(),
        oracle: reference.clone(),
    };
    let unit = QualificationUnit {
        implementation: reference.clone(),
        realization: reference.clone(),
        descriptors: reference.clone(),
        contracts: reference.clone(),
        port_profiles: reference.clone(),
        environment: reference.clone(),
        harness: reference.clone(),
        fixtures: reference.clone(),
        specification: reference.clone(),
    };
    let plan = WitnessPlan {
        schema: "crucible.node-witness-plan.v1".into(),
        unit,
        classes: Default::default(),
        requirements: BTreeMap::new(),
        cases: vec![case.clone()],
        limitations: reference.clone(),
    };
    Ok((plan, case, reference))
}

fn store(
    plan: &WitnessPlan,
    case: &PlannedWitnessCase,
    original: Option<RetainedReport>,
) -> OriginalRuntimeReportStore {
    OriginalRuntimeReportStore {
        plan: plan.clone(),
        slots: vec![ReportSlot {
            case: case.clone(),
            attempted: original.is_some(),
            original,
        }],
        maximum_bytes: 1024 * 1024,
        retained_bytes: 0,
    }
}

#[test]
fn matching_serialized_report_cannot_enroll_original() -> Result<(), QualificationError> {
    let (plan, case, _) = model()?;
    let body = b"matching report metadata";
    let reference = canonical::content_ref(body, "application/json")?;
    let store = store(&plan, &case, None);
    assert!(
        store
            .authenticate_result(&plan, &case, CaseVerdict::Passed, &reference, body)
            .is_err()
    );
    assert!(store.original_report(&case.id).is_none());
    Ok(())
}

#[test]
fn unauthenticated_original_body_survives_and_cannot_issue() -> Result<(), QualificationError> {
    let (plan, case, _) = model()?;
    let body = b"original refused report";
    let reference = canonical::content_ref(body, "application/json")?;
    let store = store(
        &plan,
        &case,
        Some(RetainedReport {
            reference: reference.clone(),
            bytes: body.to_vec(),
            verdict: None,
        }),
    );
    assert!(
        store
            .authenticate_result(&plan, &case, CaseVerdict::Passed, &reference, body)
            .is_err()
    );
    assert!(
        store
            .authenticate_result(&plan, &case, CaseVerdict::Failed, &reference, body)
            .is_err()
    );
    assert_eq!(
        store
            .original_report(&case.id)
            .map(|(_, bytes, verdict)| (bytes, verdict)),
        Some((body.as_slice(), None))
    );
    Ok(())
}

#[test]
fn authenticated_failed_original_rejects_changed_verdict_case_plan_or_body()
-> Result<(), QualificationError> {
    let (plan, case, _) = model()?;
    let body = b"original adverse report";
    let reference = canonical::content_ref(body, "application/json")?;
    let store = store(
        &plan,
        &case,
        Some(RetainedReport {
            reference: reference.clone(),
            bytes: body.to_vec(),
            verdict: Some(CaseVerdict::Failed),
        }),
    );
    store.authenticate_result(&plan, &case, CaseVerdict::Failed, &reference, body)?;
    assert!(
        store
            .authenticate_result(&plan, &case, CaseVerdict::Passed, &reference, body)
            .is_err()
    );
    assert!(
        store
            .authenticate_result(
                &plan,
                &case,
                CaseVerdict::Failed,
                &reference,
                b"rewritten report"
            )
            .is_err()
    );
    let mut changed = case.clone();
    changed.kind = CaseKind::Model;
    assert!(
        store
            .authenticate_result(&plan, &changed, CaseVerdict::Failed, &reference, body)
            .is_err()
    );
    let mut changed = plan.clone();
    changed.unit.realization = canonical::content_ref(b"foreign", "application/json")?;
    assert!(
        store
            .authenticate_result(&changed, &case, CaseVerdict::Failed, &reference, body)
            .is_err()
    );
    Ok(())
}

#[test]
fn tiny_complete_plan_credit_refuses_before_installed_callback() -> Result<(), QualificationError> {
    struct Refusing(Cell<usize>);
    impl InstalledWitnessAuthority for Refusing {
        fn authenticate_plan(
            &self,
            _: &ContentRef,
            _: &[u8],
            _: &WitnessPlan,
        ) -> Result<(), QualificationError> {
            self.0.set(self.0.get() + 1);
            Err(QualificationError::Refused("model installer refuses"))
        }
        fn authenticate_result(
            &self,
            _: &WitnessPlan,
            _: &PlannedWitnessCase,
            _: CaseVerdict,
            _: &ContentRef,
            _: &[u8],
        ) -> Result<(), QualificationError> {
            Err(QualificationError::Refused("model installer refuses"))
        }
    }
    let (plan, _, reference) = model()?;
    let authority = Refusing(Cell::new(0));
    assert!(
        OriginalRuntimeReportStore::new(
            &authority,
            &plan,
            &reference,
            QualificationLimits::default(),
            1
        )
        .is_err()
    );
    assert_eq!(authority.0.get(), 0);
    Ok(())
}
