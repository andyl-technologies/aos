//! Retains runner-origin reports beneath independent installed native oracles.
//!
//! This store supplies custody and exact later-result lookup. It grants no
//! source installation, collection graph, class, admission or Ready authority.
//! The complete plan and every original source oracle remain independently
//! authenticated; a report decoder cannot add an original observation here.

use crucible_node_contract::{ContentRef, canonical};

use super::{
    CaseKind, CaseVerdict, OriginalCompletionObservation, OriginalCompletionWitness,
    QualificationError, QualificationLimits, WitnessPlan, WitnessPopulation, protocol,
};
use crate::node_qualification::{InstalledWitnessAuthority, PlannedWitnessCase};

/// Verifies original runtime custody against independently retained native seals.
///
/// Source installation must bind this implementation to the immutable fixture
/// programme before Child allocation. It must check semantic output against
/// predeclared expectations and compare physical/native fields with original
/// seals enrolled before common completion or report inspection.
pub trait InstalledRuntimeWitnessOracle {
    /// Authenticates one original report without replacing an adverse verdict.
    ///
    /// # Errors
    /// Defaults to refusal. Unknown source seals, changed original windows,
    /// missing producer/input/ACK bodies or unavailable independent oracles
    /// must remain refused. Only Passed or Failed can describe an actual case.
    fn authenticate_original(
        &self,
        _plan: &WitnessPlan,
        _case: &PlannedWitnessCase,
        _original: &OriginalCompletionWitness<'_, '_>,
    ) -> Result<CaseVerdict, QualificationError> {
        Err(QualificationError::Refused(
            "independent original runtime oracle unavailable",
        ))
    }
}

struct ReportSlot {
    case: PlannedWitnessCase,
    attempted: bool,
    original: Option<RetainedReport>,
}

struct RetainedReport {
    reference: ContentRef,
    bytes: Vec<u8>,
    verdict: Option<CaseVerdict>,
}

/// Owns bounded original reports for a single complete installed witness plan.
///
/// A shared fixture authority can delegate its runtime-origin callback and
/// later result lookup here. The native oracle remains a separate installed
/// conjunction. This store has no report decoder or public insertion method.
pub struct OriginalRuntimeReportStore {
    plan: WitnessPlan,
    slots: Vec<ReportSlot>,
    maximum_bytes: usize,
    retained_bytes: usize,
}

impl OriginalRuntimeReportStore {
    /// Authenticates complete coverage and reserves original slots before launch.
    ///
    /// # Errors
    /// Refuses an unauthenticated or substituted complete plan, exhausted
    /// case/body credits, unavailable allocation or no realized-provider cases.
    pub fn new(
        authority: &dyn InstalledWitnessAuthority,
        plan: &WitnessPlan,
        reference: &ContentRef,
        limits: QualificationLimits,
        maximum_bytes: usize,
    ) -> Result<Self, QualificationError> {
        // Count both the retained full plan and independently indexed case rows
        // before canonical Value/Vec construction or any descriptor cloning.
        let retained_bytes = protocol::encoded_size(&(plan, &plan.cases), maximum_bytes)?;
        protocol::precharge(plan, limits.maximum_claim_bytes)?;
        let bytes = canonical::canonical_json(
            &serde_json::to_value(plan).map_err(crucible_node_contract::ContractError::from)?,
        )?;
        reference.verify(&bytes)?;
        WitnessPopulation::install(&bytes, reference, authority, limits)?;

        let count = plan
            .cases
            .iter()
            .filter(|case| case.kind == CaseKind::RealizedProvider)
            .count();
        if count == 0 || count > limits.maximum_cases {
            return Err(QualificationError::Refused("original runtime case credit"));
        }
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(count)
            .map_err(|_| QualificationError::Refused("original runtime slot allocation"))?;
        slots.extend(
            plan.cases
                .iter()
                .filter(|case| case.kind == CaseKind::RealizedProvider)
                .map(|case| ReportSlot {
                    case: case.clone(),
                    attempted: false,
                    original: None,
                }),
        );
        Ok(Self {
            plan: plan.clone(),
            slots,
            maximum_bytes,
            retained_bytes,
        })
    }

    /// Retains a runner-created original before invoking the independent oracle.
    ///
    /// Refusal or callback unwind leaves the attempt and complete report in
    /// this store; another observation cannot replace it. The runner separately
    /// retains its actual native owner and original full evidence bodies.
    ///
    /// # Errors
    /// Refuses changed plan/case/oracle, duplicate attempt, insufficient whole
    /// storage credit, unavailable allocation or independently refused custody.
    pub fn observe(
        &mut self,
        plan: &WitnessPlan,
        case: &str,
        oracle: &ContentRef,
        original: &OriginalCompletionWitness<'_, '_>,
        verifier: &dyn InstalledRuntimeWitnessOracle,
    ) -> Result<(), QualificationError> {
        if plan != &self.plan {
            return Err(QualificationError::Refused(
                "original runtime population changed",
            ));
        }
        let observed_case = match original.observation() {
            OriginalCompletionObservation::Exact(observation) => &observation.case,
            OriginalCompletionObservation::Quantized(observation) => &observation.case,
        };
        if observed_case != case {
            return Err(QualificationError::Refused(
                "original runtime report case differs",
            ));
        }
        let slot = self
            .slots
            .iter_mut()
            .find(|slot| slot.case.id == case)
            .ok_or(QualificationError::Refused("unknown original runtime case"))?;
        if slot.case.oracle != *oracle || slot.attempted {
            return Err(QualificationError::Refused(
                "original runtime case replaced",
            ));
        }
        slot.attempted = true;
        original.reference().verify(original.bytes())?;
        let remaining = self.maximum_bytes.checked_sub(self.retained_bytes).ok_or(
            QualificationError::Refused("original report budget accounting"),
        )?;
        let complete_bytes =
            protocol::encoded_size(&(original.reference(), original.bytes()), remaining)?;
        let retained_bytes = self
            .retained_bytes
            .checked_add(complete_bytes)
            .filter(|bytes| *bytes <= self.maximum_bytes)
            .ok_or(QualificationError::Refused(
                "whole original runtime report credit",
            ))?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(original.bytes().len())
            .map_err(|_| QualificationError::Refused("original runtime report allocation"))?;
        bytes.extend_from_slice(original.bytes());
        self.retained_bytes = retained_bytes;
        slot.original = Some(RetainedReport {
            reference: original.reference().clone(),
            bytes,
            verdict: None,
        });

        // Install custody before any source callback. A panic or oracle refusal
        // cannot discard the original body or silently admit a passing retry.
        let verdict = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            verifier.authenticate_original(plan, &slot.case, original)
        }))
        .map_err(|_| QualificationError::Refused("installed original runtime oracle panicked"))??;
        if !matches!(verdict, CaseVerdict::Passed | CaseVerdict::Failed) {
            return Err(QualificationError::Refused(
                "executed runtime oracle disposition",
            ));
        }
        let retained = slot.original.as_mut().ok_or(QualificationError::Refused(
            "original runtime report custody unavailable",
        ))?;
        retained.verdict = Some(verdict);
        Ok(())
    }

    /// Authenticates exactly one retained original result without parsing it.
    ///
    /// # Errors
    /// Refuses missing/unauthenticated originals, a changed whole plan or case,
    /// rewritten verdict/class/oracle, substituted report bytes or foreign CF.
    pub fn authenticate_result(
        &self,
        plan: &WitnessPlan,
        case: &PlannedWitnessCase,
        verdict: CaseVerdict,
        reference: &ContentRef,
        bytes: &[u8],
    ) -> Result<(), QualificationError> {
        if plan != &self.plan {
            return Err(QualificationError::Refused(
                "original runtime population changed",
            ));
        }
        let slot = self
            .slots
            .iter()
            .find(|slot| slot.case == *case)
            .ok_or(QualificationError::Refused("original runtime case changed"))?;
        let original = slot.original.as_ref().ok_or(QualificationError::Refused(
            "original runtime report missing",
        ))?;
        if original.verdict != Some(verdict)
            || original.reference != *reference
            || original.bytes != bytes
        {
            return Err(QualificationError::Refused(
                "original runtime result substituted",
            ));
        }
        reference.verify(bytes)?;
        Ok(())
    }

    /// Borrows a retained original body, including an unauthenticated failure.
    pub fn original_report(&self, case: &str) -> Option<(&ContentRef, &[u8], Option<CaseVerdict>)> {
        let original = self
            .slots
            .iter()
            .find(|slot| slot.case.id == case)?
            .original
            .as_ref()?;
        Some((&original.reference, &original.bytes, original.verdict))
    }
}

#[cfg(test)]
#[path = "runtime_reports/tests.rs"]
mod tests;
