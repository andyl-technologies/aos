//! Authenticates only same-source original collection observations for the full world.
//!
//! The complete Refused population is fixed before Child. Runtime report bodies
//! enter the store only through its opaque original-origin witness, joined to the
//! independently owned native receipts and UnixDatagram observations for that
//! exact participant. Serialized Passed data cannot enroll an original here.

use super::*;
use crate::node_qualification::{
    AcceptanceScope, Applicability, CaseEvidence, CaseVerdict, ExactCompletionCase,
    InstalledAcceptancePolicy, InstalledConformanceAuthority, InstalledQualificationAuthority,
    InstalledWitnessAuthority, OriginalCompletionWitness, PlannedWitnessCase, QualificationClaim,
    QualificationClass, QualificationUnit,
};

impl InstalledPacketWorldCollectionAuthority {
    fn plan(&self, plan: &WitnessPlan) -> Result<(), QualificationError> {
        self.current()?;
        if plan != &self.plan {
            return Err(refused());
        }
        Ok(())
    }

    fn case_member(&self, case: &str) -> Result<usize, QualificationError> {
        let mut selected = None;
        for member in 0..3 {
            if self.oracles[member].template_oracle(case).is_ok() {
                if selected.is_some() {
                    return Err(refused());
                }
                selected = Some(member);
            }
        }
        selected.ok_or_else(refused)
    }
}

impl InstalledQualificationAuthority for InstalledPacketWorldCollectionAuthority {
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
        if unit != &self.plan.unit
            || classes != &self.plan.classes
            || policy != &self.audit.record().original.applicability_policy
        {
            return Err(refused());
        }
        Ok(self
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
            .collect())
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

impl InstalledAcceptancePolicy for InstalledPacketWorldCollectionAuthority {
    fn scope_for_node(&self, node: &Id) -> Result<AcceptanceScope<'_>, QualificationError> {
        self.current()?;
        let member = self.node(node)?;
        Ok(AcceptanceScope {
            binding: &self.sources[member].installation().binding.compatibility,
            current_unit: self.plan.unit.clone(),
            required_classes: self.plan.classes.clone(),
            original_bytes: self.audit.original_bytes(),
            original_claim: self.audit.claim(),
            record: self.audit.record(),
        })
    }
}

impl InstalledWitnessAuthority for InstalledPacketWorldCollectionAuthority {
    fn authenticate_plan(
        &self,
        reference: &ContentRef,
        bytes: &[u8],
        plan: &WitnessPlan,
    ) -> Result<(), QualificationError> {
        self.plan(plan)?;
        if reference != &self.reference || bytes != self.bytes {
            return Err(refused());
        }
        Ok(())
    }

    fn authenticate_result(
        &self,
        plan: &WitnessPlan,
        case: &PlannedWitnessCase,
        verdict: CaseVerdict,
        reference: &ContentRef,
        bytes: &[u8],
    ) -> Result<(), QualificationError> {
        self.plan(plan)?;
        let reports = self.reports.try_borrow().map_err(|_| refused())?;
        reports
            .as_ref()
            .ok_or_else(refused)?
            .authenticate_result(plan, case, verdict, reference, bytes)?;
        self.current()
    }
}

impl InstalledConformanceAuthority for InstalledPacketWorldCollectionAuthority {
    fn authenticate_realized_reservation(
        &self,
        plan: &WitnessPlan,
        case: &str,
        oracle: &ContentRef,
        maximum_bytes: u64,
    ) -> Result<(), QualificationError> {
        self.plan(plan)?;
        let member = self.case_member(case)?;
        self.oracles[member].authenticate_case_reservation(plan, case, oracle, maximum_bytes)?;
        self.current()
    }

    fn authenticate_exact_fixture(
        &self,
        plan: &WitnessPlan,
        actual: &ExactCompletionCase,
    ) -> Result<(), QualificationError> {
        self.plan(plan)?;
        let member = self.case_member(&actual.case)?;
        let expected = self.oracles[member].expected_completion(&actual.case)?;
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
        self.plan(plan)?;
        let member = self.case_member(case)?;
        // Select the fixed template first, then conjunct the actual opaque
        // completed token's participant. A case string cannot substitute owners.
        if self.node(&original.original().admission().token().route().node)? != member {
            return Err(refused());
        }
        let mut reports = self.reports.try_borrow_mut().map_err(|_| refused())?;
        reports.as_mut().ok_or_else(refused)?.observe(
            plan,
            case,
            oracle,
            original,
            self.oracles[member].as_ref(),
        )?;
        self.current()
    }
}
