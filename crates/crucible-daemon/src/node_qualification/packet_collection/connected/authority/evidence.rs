//! Authenticates the original Refused population without accepted-class claims.

use super::*;
use crate::node_qualification::{
    AcceptanceScope, Applicability, CaseEvidence, CaseVerdict, ExactCompletionCase,
    InstalledAcceptancePolicy, InstalledConformanceAuthority, InstalledQualificationAuthority,
    InstalledWitnessAuthority, OriginalCompletionWitness, PlannedWitnessCase, QualificationClaim,
    QualificationClass, QualificationUnit,
};
use std::collections::{BTreeMap, BTreeSet};

impl InstalledQualificationAuthority for InstalledPacketConnectedCollectionAuthority {
    fn authenticate_claim(
        &self,
        _: &ContentRef,
        _: &[u8],
        _: &QualificationClaim,
    ) -> Result<(), QualificationError> {
        Err(refused())
    }

    fn applicability(
        &self,
        unit: &QualificationUnit,
        classes: &BTreeSet<QualificationClass>,
        policy: &ContentRef,
    ) -> Result<BTreeMap<String, Applicability>, QualificationError> {
        self.current()?;
        if unit != &self.population.plan.unit
            || classes != &self.population.plan.classes
            || policy != &self.audit.record().original.applicability_policy
        {
            return Err(refused());
        }
        let answer = self
            .population
            .plan
            .requirements
            .keys()
            .map(|id| {
                (
                    id.clone(),
                    Applicability::Applicable {
                        classes: classes.clone(),
                    },
                )
            })
            .collect();
        self.current()?;
        Ok(answer)
    }

    fn verify_evidence(
        &self,
        _: &ContentRef,
        _: u64,
        _: usize,
    ) -> Result<Vec<ContentRef>, QualificationError> {
        Err(refused())
    }

    fn authenticate_case(
        &self,
        _: &QualificationUnit,
        _: &str,
        _: &CaseEvidence,
    ) -> Result<(), QualificationError> {
        Err(refused())
    }
}

impl InstalledAcceptancePolicy for InstalledPacketConnectedCollectionAuthority {
    fn scope_for_node(&self, node: &Id) -> Result<AcceptanceScope<'_>, QualificationError> {
        self.current()?;
        let binding = &self.binding(node)?.compatibility;
        self.current()?;
        Ok(AcceptanceScope {
            binding,
            current_unit: self.population.plan.unit.clone(),
            required_classes: self.population.plan.classes.clone(),
            original_bytes: self.audit.original_bytes(),
            original_claim: self.audit.claim(),
            record: self.audit.record(),
        })
    }
}

impl InstalledWitnessAuthority for InstalledPacketConnectedCollectionAuthority {
    fn authenticate_plan(
        &self,
        reference: &ContentRef,
        bytes: &[u8],
        plan: &WitnessPlan,
    ) -> Result<(), QualificationError> {
        self.current()?;
        if reference != &self.population.reference
            || bytes != self.population.bytes
            || plan != &self.population.plan
        {
            return Err(refused());
        }
        self.current()
    }

    fn authenticate_result(
        &self,
        plan: &WitnessPlan,
        case: &PlannedWitnessCase,
        verdict: CaseVerdict,
        reference: &ContentRef,
        bytes: &[u8],
    ) -> Result<(), QualificationError> {
        self.current()?;
        let answer = (|| {
            let reports = self.reports.try_borrow().map_err(|_| refused())?;
            reports
                .as_ref()
                .ok_or_else(refused)?
                .authenticate_result(plan, case, verdict, reference, bytes)
        })();
        self.current()?;
        answer
    }
}

impl InstalledConformanceAuthority for InstalledPacketConnectedCollectionAuthority {
    fn authenticate_realized_reservation(
        &self,
        plan: &WitnessPlan,
        case: &str,
        oracle: &ContentRef,
        maximum_bytes: u64,
    ) -> Result<(), QualificationError> {
        self.current()?;
        let answer = self
            .oracle
            .authenticate_case_reservation(plan, case, oracle, maximum_bytes);
        self.current()?;
        answer
    }

    fn authenticate_exact_fixture(
        &self,
        plan: &WitnessPlan,
        actual: &ExactCompletionCase,
    ) -> Result<(), QualificationError> {
        self.current()?;
        if plan != &self.population.plan {
            return Err(refused());
        }
        let expected = self.oracle.expected_completion(&actual.case)?;
        if actual.case != expected.case
            || actual.oracle != expected.oracle
            || actual.request != expected.request
            || actual.outcome != expected.outcome
            || actual.input != expected.input
            || actual.acknowledged != expected.acknowledged
            || actual.maximum_bytes != expected.maximum_bytes
        {
            return Err(refused());
        }
        self.current()
    }

    fn retain_original_runtime_witness(
        &self,
        plan: &WitnessPlan,
        case: &str,
        oracle: &ContentRef,
        original: &OriginalCompletionWitness<'_, '_>,
    ) -> Result<(), QualificationError> {
        self.current()?;
        // Bind the actual opaque completed token and original report BEFORE
        // report storage. Parsed report contents never enroll native custody.
        let answer = (|| {
            self.oracle
                .authenticate_original_runtime(plan, case, oracle, original)?;
            let mut reports = self.reports.try_borrow_mut().map_err(|_| refused())?;
            reports.as_mut().ok_or_else(refused)?.observe(
                plan,
                case,
                oracle,
                original,
                self.oracle.as_ref(),
            )
        })();
        self.current()?;
        answer
    }
}
