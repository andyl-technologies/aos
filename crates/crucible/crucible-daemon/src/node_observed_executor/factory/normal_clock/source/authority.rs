//! Reauthenticates actual source-owned Clock originals at normal ledger gates.

use std::collections::{BTreeMap, BTreeSet};

use crate::node_qualification::{
    AcceptanceScope, Applicability, CaseEvidence, CaseKind, CaseVerdict, ExactCompletionCase,
    InstalledAcceptancePolicy, InstalledConformanceAuthority, InstalledQualificationAuthority,
    InstalledWitnessAuthority, OriginalSourceInspectionSlot, PlannedWitnessCase,
    QualificationClaim, QualificationClass, QualificationUnit, WitnessPlan,
};
use crucible_engine::node_contract::{ProviderPlanningRequest, ProviderPreparationPlan};

use super::*;

impl OriginalNormalClockSource {
    fn plan_is_current(&self, plan: &WitnessPlan) -> Result<(), QualificationError> {
        self.authenticate_current()?;
        if plan != &self.population.plan {
            return Err(reject("Clock complete original population changed"));
        }
        Ok(())
    }

    fn result_is_original(
        &self,
        case: &PlannedWitnessCase,
        verdict: CaseVerdict,
        reference: &ContentRef,
        bytes: &[u8],
    ) -> Result<(), QualificationError> {
        let originals = self
            .results
            .try_borrow()
            .map_err(|_| reject("Clock original result bank busy"))?;
        let original = originals
            .get(&case.id)
            .ok_or(reject("Clock actual original result absent"))?;
        if !original.authenticated
            || verdict != CaseVerdict::Passed
            || reference != &original.reference
            || bytes != original.bytes
        {
            return Err(reject("Clock original result or verdict changed"));
        }
        reference.verify(bytes)?;
        Ok(())
    }
}

impl InstalledWitnessAuthority for OriginalNormalClockSource {
    fn authenticate_plan(
        &self,
        reference: &ContentRef,
        bytes: &[u8],
        plan: &WitnessPlan,
    ) -> Result<(), QualificationError> {
        self.plan_is_current(plan)?;
        if reference != &self.population.reference || bytes != self.population.bytes {
            return Err(reject("Clock original plan bytes changed"));
        }
        reference.verify(bytes)?;
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
        self.plan_is_current(plan)?;
        if self
            .population
            .plan
            .cases
            .iter()
            .find(|original| original.id == case.id)
            != Some(case)
        {
            return Err(reject("Clock original case kind/classes/oracle changed"));
        }
        self.result_is_original(case, verdict, reference, bytes)?;
        self.authenticate_current()
    }
}

impl InstalledQualificationAuthority for OriginalNormalClockSource {
    fn authenticate_claim(
        &self,
        reference: &ContentRef,
        bytes: &[u8],
        claim: &QualificationClaim,
    ) -> Result<(), QualificationError> {
        self.authenticate_current()?;
        let original = self
            .issued
            .get()
            .ok_or(reject("Clock original population is not sealed"))?;
        if reference != original.reference()
            || bytes != original.bytes()
            || claim.unit != self.unit.value
            || claim.classes != self.population.plan.classes
            || claim.applicability_policy != self.population.reference
        {
            return Err(reject(
                "Clock claim differs from actual original population",
            ));
        }
        reference.verify(bytes)?;
        Ok(())
    }

    fn applicability(
        &self,
        unit: &QualificationUnit,
        classes: &BTreeSet<QualificationClass>,
        policy: &ContentRef,
    ) -> Result<BTreeMap<String, Applicability>, QualificationError> {
        self.authenticate_current()?;
        if unit != &self.unit.value
            || classes != &self.population.plan.classes
            || policy != &self.population.reference
        {
            return Err(reject("Clock original applicability scope changed"));
        }
        Ok(self
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
            .collect())
    }

    fn verify_evidence(
        &self,
        reference: &ContentRef,
        maximum_bytes: u64,
        maximum_dependencies: usize,
    ) -> Result<Vec<ContentRef>, QualificationError> {
        self.authenticate_current()?;
        if reference.length.get() > maximum_bytes {
            return Err(reject("Clock evidence byte ceiling"));
        }
        if reference == &self.origin.source {
            if measure_executable(&self.origin.source_path).map_err(failure)? != *reference {
                return Err(reject("Clock measured executable changed"));
            }
            return self.authenticate_current().map(|_| Vec::new());
        }
        let dependencies = self
            .evidence
            .try_borrow()
            .map_err(|_| reject("Clock evidence bank busy"))?
            .verify(reference, maximum_bytes, maximum_dependencies)?
            .ok_or(reject("Clock original evidence object unavailable"))?;
        self.authenticate_current()?;
        Ok(dependencies)
    }

    fn authenticate_case(
        &self,
        unit: &QualificationUnit,
        requirement: &str,
        case: &CaseEvidence,
    ) -> Result<(), QualificationError> {
        self.authenticate_current()?;
        if unit != &self.unit.value {
            return Err(reject("Clock original case unit changed"));
        }
        let Some(crate::node_qualification::WitnessCriterion::Applicable { cases, .. }) =
            self.population.plan.requirements.get(requirement)
        else {
            return Err(reject(
                "Clock requirement is not in original complete population",
            ));
        };
        let planned = self
            .population
            .plan
            .cases
            .iter()
            .find(|planned| planned.id == case.case)
            .ok_or(reject("Clock original case undeclared"))?;
        if !cases.contains(&case.case)
            || case.kind != planned.kind
            || case.classes != planned.classes
            || case.oracle != planned.oracle
        {
            return Err(reject("Clock requirement/case coverage changed"));
        }
        let originals = self
            .results
            .try_borrow()
            .map_err(|_| reject("Clock original bank busy"))?;
        let original = originals
            .get(&case.case)
            .ok_or(reject("Clock required original absent"))?;
        self.result_is_original(planned, case.verdict, &case.result, &original.bytes)?;
        drop(originals);
        self.authenticate_current()
    }
}

impl InstalledAcceptancePolicy for OriginalNormalClockSource {
    fn scope_for_node(&self, node: &Id) -> Result<AcceptanceScope<'_>, QualificationError> {
        self.authenticate_current()?;
        if node != &self.profile.selection.node {
            return Err(reject("Clock source does not own selected node"));
        }
        let (original_bytes, original_claim, record) = match (self.issued.get(), self.record.get())
        {
            (None, None) => (
                self.population.audit.original_bytes(),
                self.population.audit.claim(),
                self.population.audit.record(),
            ),
            (Some(issued), Some(record)) => (issued.bytes(), issued.reference(), record),
            _ => return Err(reject("Clock original population sealing is incomplete")),
        };
        Ok(AcceptanceScope {
            binding: &self.profile.scenario.compatibility[0],
            current_unit: self.unit.value.clone(),
            required_classes: population::classes(),
            original_bytes,
            original_claim,
            record,
        })
    }
}

impl InstalledConformanceAuthority for OriginalNormalClockSource {
    fn authenticate_original_provider_plan(
        &self,
        selection: ProviderPlanningRequest<'_>,
        plan: &ProviderPreparationPlan,
    ) -> Result<(), QualificationError> {
        self.authenticate_current()?;
        if selection.limits.nodes == 0
            || selection.limits.profiles == 0
            || selection.limits.providers == 0
            || selection.limits.metadata_bytes == 0
            || selection.limits.metadata_bytes > 4 * 1024 * 1024
        {
            return Err(reject("Clock ordinary metadata planning credit differs"));
        }
        unit::bounded(
            &(plan, selection.nodes, selection.resources),
            selection.limits.metadata_bytes,
        )?;
        let (profile, expected) = self.future_plan()?;
        if selection.profile != &profile
            || selection.configuration != &expected.bindings[0].configuration_ref
            || selection.nodes != std::slice::from_ref(&self.profile.selection.node)
            || selection.resources != self.aggregate.limits_data()
            || plan != &expected
            || selection.limits.nodes < 1
            || selection.limits.profiles < 1
        {
            return Err(reject(
                "Clock ordinary profile/resources/original plan changed",
            ));
        }
        self.authenticate_current()
    }

    fn authenticate_realized_reservation(
        &self,
        plan: &WitnessPlan,
        case: &str,
        oracle: &ContentRef,
        maximum_bytes: u64,
    ) -> Result<(), QualificationError> {
        self.plan_is_current(plan)?;
        let planned = self
            .population
            .plan
            .cases
            .iter()
            .find(|planned| planned.id == case)
            .ok_or(reject("Clock original reservation undeclared"))?;
        if planned.kind != CaseKind::RealizedProvider
            || &planned.oracle != oracle
            || maximum_bytes == 0
            || maximum_bytes
                > if case == population::ADVERSE {
                    512 * 1024
                } else {
                    state_witness::MAXIMUM_STATE_BYTES as u64
                }
        {
            return Err(reject("Clock original reservation scope changed"));
        }
        Ok(())
    }

    fn authenticate_exact_fixture(
        &self,
        plan: &WitnessPlan,
        case: &ExactCompletionCase,
    ) -> Result<(), QualificationError> {
        self.plan_is_current(plan)?;
        let expected = self
            .expected
            .get(&case.case)
            .ok_or(reject("Clock original exact case absent"))?;
        if case.oracle != expected.oracle.reference
            || case.request != expected.expected.request
            || case.outcome != expected.expected.outcome
            || case.input.is_some()
            || !case.acknowledged
            || case.maximum_bytes != MAXIMUM_CASE_BYTES as u64
        {
            return Err(reject("Clock independent exact oracle changed"));
        }
        Ok(())
    }

    fn retain_original_runtime_witness(
        &self,
        plan: &WitnessPlan,
        case: &str,
        oracle: &ContentRef,
        witness: &OriginalCompletionWitness<'_, '_>,
    ) -> Result<(), QualificationError> {
        self.plan_is_current(plan)?;
        self.retain_exact_original(case, oracle, witness)
    }

    fn retain_original_clock_state_witness(
        &self,
        plan: &WitnessPlan,
        case: &str,
        oracle: &ContentRef,
        witness: &OriginalClockStateWitness<'_>,
        reference: &ContentRef,
        bytes: &[u8],
    ) -> Result<CaseVerdict, QualificationError> {
        self.plan_is_current(plan)?;
        self.retain_state_original(
            case,
            &self.population.reference,
            oracle,
            witness,
            reference,
            bytes,
        )
    }

    fn retain_original_clock_adverse_witness(
        &self,
        plan: &WitnessPlan,
        case: &str,
        oracle: &ContentRef,
        witness: &OriginalClockAdverseWitness<'_>,
        reference: &ContentRef,
        bytes: &[u8],
    ) -> Result<CaseVerdict, QualificationError> {
        self.plan_is_current(plan)?;
        self.retain_adverse_original(case, oracle, witness, reference, bytes)
    }

    fn retain_original_clock_failure_witness(
        &self,
        plan: &WitnessPlan,
        case: &str,
        oracle: &ContentRef,
        witness: &OriginalClockFailureWitness<'_>,
        reference: &ContentRef,
        bytes: &[u8],
    ) -> Result<CaseVerdict, QualificationError> {
        self.plan_is_current(plan)?;
        self.retain_failure_original(case, oracle, witness, reference, bytes)
    }

    fn execute_original_source_inspection(
        &self,
        plan: &WitnessPlan,
        case: &PlannedWitnessCase,
        output: &mut OriginalSourceInspectionSlot,
    ) -> Result<CaseVerdict, QualificationError> {
        self.plan_is_current(plan)?;
        if case.id != population::IDENTITY
            || case.kind != CaseKind::SourceInspection
            || self
                .population
                .plan
                .cases
                .iter()
                .find(|original| original.id == case.id)
                != Some(case)
        {
            return Err(reject("Clock original source inspection undeclared"));
        }
        self.failed.set(true);
        let bytes = canonical::canonical_json(
            &serde_json::to_value((
                "crucible.original-clock-source-inspection/1",
                &self.unit.value,
                &self.profile.scenario,
                self.aggregate.limits_data(),
                self.unit.ceilings,
            ))
            .map_err(crucible_node_format::ContractError::from)?,
        )?;
        let reference = canonical::content_ref(&bytes, "application/json")?;
        self.retain_first_result(&case.id, &reference, &bytes)?;
        output.write_original(&bytes)?;
        self.evidence
            .try_borrow_mut()
            .map_err(|_| reject("Clock evidence busy"))?
            .retain_result(&reference, &bytes)?;
        self.mark_authenticated(&case.id)?;
        self.failed.set(false);
        self.authenticate_current()?;
        Ok(CaseVerdict::Passed)
    }
}
