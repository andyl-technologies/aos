//! Issues the complete original population from a source-owned native actor.
//!
//! Native success covers only the declared two case subsets. Every remaining
//! required review stays NotExecuted. The private acceptance authority refuses
//! unresolved criteria before ordinary installation can use this report.

use std::collections::BTreeMap;

use crucible_node_contract::{ContentRef, canonical};

use super::{criteria::ReferenceQualificationCriteria, harness::CandidateHarnessResult};
use crate::node_qualification::{
    AcceptedQualification, Applicability, CaseEvidence, CaseVerdict,
    InstalledQualificationAuthority, InstalledWitnessAuthority, IssuedQualification,
    PlannedWitnessCase, QualificationClaim, QualificationClass, QualificationError,
    QualificationLimits, QualificationUnit, WitnessCriterion, WitnessPlan, WitnessPopulation,
    accept_claim,
};

const WORLD_CASE: &str = "reference/native-complete-world-and-windows";
const RETIREMENT_CASE: &str = "reference/native-original-custody-retirement";

/// Retains source-origin data without allowing callers to construct its authority.
pub(super) struct SourceIssuedQualification {
    original: CandidateHarnessResult,
    issued: IssuedQualification,
}

impl SourceIssuedQualification {
    /// Issues both original native cases and every still-unexecuted requirement.
    pub(super) fn issue(original: CandidateHarnessResult) -> Result<Self, QualificationError> {
        let issued = issue_report(&original)?;
        Ok(Self { original, issued })
    }

    pub(super) fn report(&self) -> &IssuedQualification {
        &self.issued
    }

    /// Measures a fresh installed scope before the concrete ordinary gate.
    pub(super) fn admit_current(&self) -> Result<AcceptedQualification, QualificationError> {
        let package = super::package::InstalledPublicReferencePackage::built_in()
            .map_err(|_| refused("current source implementation unavailable"))?;
        let candidate = super::candidate::PrivateCandidate::new(
            package,
            crucible_node_contract::U64::new(1000),
            crucible_node_contract::U64::new(1_000_000_000),
        )
        .map_err(|_| refused("fresh source candidate scope unavailable"))?;
        let oracles = candidate
            .installations
            .iter()
            .map(|installed| {
                let cases = (0..3)
                    .map(|quantum| super::harness::window_case(installed, quantum))
                    .collect::<Result<Vec<_>, _>>()?;
                super::harness::oracle_contract(installed, &cases)
            })
            .collect::<Result<Vec<_>, crucible_node_provider::ProviderError>>()
            .map_err(|_| refused("fresh source fixture population unavailable"))?;
        let unit = super::context::measure(&candidate, &oracles)
            .map_err(|_| refused("fresh installed qualification context unavailable"))?;
        let criteria = ReferenceQualificationCriteria::build(unit.identity.clone())?;
        self.admit_ordinary(&unit.identity, &criteria.plan.classes)
    }

    /// Re-runs the concrete source-owned gate for ordinary installed admission.
    ///
    /// A caller-created AcceptedQualification is deliberately not an input.
    /// The current partial case population remains refused even when both native
    /// subsets passed; no provider or caller can waive the remaining review.
    pub(super) fn admit_ordinary(
        &self,
        current: &QualificationUnit,
        classes: &std::collections::BTreeSet<QualificationClass>,
    ) -> Result<AcceptedQualification, QualificationError> {
        let authority = SourceAuthority::new(&self.original)?;
        accept_claim(
            self.issued.bytes(),
            self.issued.reference(),
            current,
            classes,
            &authority,
            QualificationLimits::default(),
        )
    }
}

/// Assembles a complete original population without consuming its native seal.
pub(super) fn issue_report(
    original: &CandidateHarnessResult,
) -> Result<IssuedQualification, QualificationError> {
    let authority = SourceAuthority::new(original)?;
    let criteria = authority.criteria;
    let mut population = WitnessPopulation::install(
        &criteria.bytes,
        &criteria.reference,
        &authority,
        QualificationLimits::default(),
    )?;
    for (id, bytes, verdict) in [
        (
            WORLD_CASE,
            original.original_bytes(),
            authority.world_verdict(),
        ),
        (
            RETIREMENT_CASE,
            original.retirement_bytes(),
            authority.retirement_verdict()?,
        ),
    ] {
        let reference = canonical::content_ref(bytes, "application/json")?;
        population.record(id, verdict, &reference, bytes, &authority)?;
    }
    population.finish()
}

struct SourceAuthority<'a> {
    original: &'a CandidateHarnessResult,
    criteria: &'a ReferenceQualificationCriteria,
}

impl<'a> SourceAuthority<'a> {
    fn new(original: &'a CandidateHarnessResult) -> Result<Self, QualificationError> {
        let (unit, criteria) = original.qualification_context().ok_or(refused(
            "source candidate did not reach complete predeclared context",
        ))?;
        let expected = ReferenceQualificationCriteria::build(unit.identity.clone())?;
        if expected.plan != criteria.plan
            || expected.bytes != criteria.bytes
            || expected.reference != criteria.reference
            || expected.objects != criteria.objects
            || expected.clauses != criteria.clauses
        {
            return Err(refused("original source criteria changed"));
        }
        for (reference, bytes) in &unit.objects {
            reference.verify(bytes)?;
        }
        Ok(Self { original, criteria })
    }

    fn world_verdict(&self) -> CaseVerdict {
        if self.original.succeeded() {
            CaseVerdict::Passed
        } else {
            CaseVerdict::Failed
        }
    }

    fn retirement_verdict(&self) -> Result<CaseVerdict, QualificationError> {
        let retirement = canonical::parse_json(self.original.retirement_bytes(), 1024 * 1024)?;
        if retirement.get("schema").and_then(serde_json::Value::as_str)
            != Some("crucible.reference.candidate-retirement.v1")
            || retirement
                .get("original_result")
                .and_then(serde_json::Value::as_str)
                != Some(self.original.original_result().encode().as_str())
            || retirement
                .get("world_reservations")
                .and_then(serde_json::Value::as_u64)
                != Some(0)
        {
            return Err(refused("original retirement scope differs"));
        }
        let scopes = retirement
            .get("original_scopes")
            .and_then(serde_json::Value::as_array)
            .ok_or(refused("original retirement owner roster unavailable"))?;
        Ok(
            if retirement
                .get("reclaimed_original_peers")
                .and_then(serde_json::Value::as_u64)
                == Some(2)
                && scopes.len() == 2
            {
                CaseVerdict::Passed
            } else {
                CaseVerdict::Failed
            },
        )
    }
}

impl InstalledWitnessAuthority for SourceAuthority<'_> {
    fn authenticate_plan(
        &self,
        reference: &ContentRef,
        bytes: &[u8],
        plan: &WitnessPlan,
    ) -> Result<(), QualificationError> {
        if reference != &self.criteria.reference
            || bytes != self.criteria.bytes
            || plan != &self.criteria.plan
        {
            return Err(refused(
                "plan differs from source-owned predeclared population",
            ));
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
        if plan != &self.criteria.plan || !plan.cases.contains(case) {
            return Err(refused("original native case is not source planned"));
        }
        let (original, expected) = match case.id.as_str() {
            WORLD_CASE => (self.original.original_bytes(), self.world_verdict()),
            RETIREMENT_CASE => (self.original.retirement_bytes(), self.retirement_verdict()?),
            _ => return Err(refused("source authority has no original review witness")),
        };
        if original != bytes
            || verdict != expected
            || canonical::content_ref(bytes, "application/json")? != *reference
        {
            return Err(refused("original native bytes or verdict rewritten"));
        }
        Ok(())
    }
}

impl InstalledQualificationAuthority for SourceAuthority<'_> {
    fn authenticate_claim(
        &self,
        _: &ContentRef,
        _: &[u8],
        claim: &QualificationClaim,
    ) -> Result<(), QualificationError> {
        if claim.unit != self.criteria.plan.unit || claim.classes != self.criteria.plan.classes {
            return Err(refused("ordinary source qualification unit differs"));
        }
        // This installed issuer has no authenticated residual review witnesses.
        // Accepting a syntactically complete passing report would manufacture
        // their execution. Retained original native facts are not a substitute.
        Err(refused(
            "source qualification still lacks mandatory original review evidence",
        ))
    }

    fn applicability(
        &self,
        unit: &QualificationUnit,
        classes: &std::collections::BTreeSet<QualificationClass>,
        policy: &ContentRef,
    ) -> Result<BTreeMap<String, Applicability>, QualificationError> {
        if unit != &self.criteria.plan.unit
            || classes != &self.criteria.plan.classes
            || policy != &self.criteria.reference
        {
            return Err(refused("source applicability scope changed"));
        }
        Ok(self
            .criteria
            .plan
            .requirements
            .iter()
            .map(|(id, criterion)| {
                let application = match criterion {
                    WitnessCriterion::Applicable { .. } => Applicability::Applicable {
                        classes: classes.clone(),
                    },
                    WitnessCriterion::NotApplicable { reason, .. } => {
                        Applicability::NotApplicable {
                            reason: reason.clone(),
                        }
                    }
                };
                (id.clone(), application)
            })
            .collect())
    }

    fn verify_evidence(
        &self,
        _: &ContentRef,
        _: u64,
        _: usize,
    ) -> Result<Vec<ContentRef>, QualificationError> {
        Err(refused(
            "complete ordinary source evidence closure remains unqualified",
        ))
    }

    fn authenticate_case(
        &self,
        _: &QualificationUnit,
        _: &str,
        _: &CaseEvidence,
    ) -> Result<(), QualificationError> {
        Err(refused(
            "complete ordinary source review remains unqualified",
        ))
    }
}

fn refused(reason: &'static str) -> QualificationError {
    QualificationError::Refused(reason)
}

#[cfg(test)]
#[path = "issuer_tests.rs"]
mod issuer_tests;
