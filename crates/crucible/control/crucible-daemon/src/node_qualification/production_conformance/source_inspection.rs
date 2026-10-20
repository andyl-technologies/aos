//! Executes installed source inspections while retaining their first output.
//!
//! Only the genuine runner constructs an output slot. The installed source runs
//! the exact planned inspection; this path accepts no caller-supplied report and
//! cannot relabel a model or source inspection as realized-provider evidence.

use std::collections::BTreeMap;

use crucible_node_format::{ContentRef, canonical};

use super::{CaseKind, CaseVerdict, ProductionConformanceRunner, QualificationError, protocol};

/// Retains whether the actual installed inspection returned, refused or unwound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceInspectionOutcome {
    /// The original slot precedes execution of the installed callback.
    Reserved,
    /// The installed callback returned its original case verdict.
    Returned,
    /// The installed callback refused after any retained original output.
    Refused,
    /// The installed callback unwound after any retained original output.
    Unwound,
}

/// Owns the once-written finite output of one installed source inspection.
///
/// This slot has no public constructor. Its byte ceiling covers serialized
/// evidence, not the source callback's total heap, working storage or native
/// resource peak. Those remain independent installed-source obligations.
pub struct OriginalSourceInspectionSlot {
    maximum: usize,
    attempted: bool,
    bytes: Vec<u8>,
}

impl OriginalSourceInspectionSlot {
    /// Retains the first exact public canonical evidence body in reserved storage.
    ///
    /// This method performs no source checks and grants no passing verdict. The
    /// runner subsequently verifies complete canonical syntax, exact case kind,
    /// current scope and independently installed result authentication.
    ///
    /// # Errors
    /// Refuses another write, an empty body or a body above the declared ceiling.
    /// A refused write cannot be replaced by another body under this slot.
    pub fn write_original(&mut self, bytes: &[u8]) -> Result<(), QualificationError> {
        if self.attempted {
            return Err(refused(
                "source inspection original output already attempted",
            ));
        }
        self.attempted = true;
        if bytes.is_empty() || bytes.len() > self.maximum {
            return Err(refused("source inspection original output byte ceiling"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
}

/// Retains the first source callback output before later result authentication.
///
/// Errors and unwinds preserve this same record. An original returned verdict
/// remains distinct from successful population authentication and acceptance.
pub struct OriginalSourceInspection {
    output: OriginalSourceInspectionSlot,
    outcome: SourceInspectionOutcome,
    verdict: Option<CaseVerdict>,
    reference: Option<ContentRef>,
}

impl OriginalSourceInspection {
    /// Borrows exact original output, including output preceding a refusal.
    pub fn bytes(&self) -> &[u8] {
        &self.output.bytes
    }

    /// Reports the observed original callback disposition without class authority.
    pub fn outcome(&self) -> SourceInspectionOutcome {
        self.outcome
    }

    /// Borrows the original callback verdict, even if later authentication refused.
    pub fn returned_verdict(&self) -> Option<CaseVerdict> {
        self.verdict
    }

    /// Borrows the exact body reference after complete canonical validation.
    pub fn reference(&self) -> Option<&ContentRef> {
        self.reference.as_ref()
    }
}

impl ProductionConformanceRunner<'_> {
    /// Executes the exact independently installed source inspection once.
    ///
    /// Attempt and output custody precede the callback. All output survives a
    /// refusal or unwind. The case must be declared `SourceInspection`; this
    /// operation cannot supply a protocol, model or realized-provider witness.
    /// Existing full class acceptance remains a separate required gate.
    ///
    /// # Errors
    /// Refuses foreign creator, unknown/wrong-kind/repeated case, exhausted
    /// serialized credit, missing source executor, callback refusal/unwind,
    /// malformed output, changed source scope or unauthenticated original result.
    ///
    /// # Panics
    /// Independent scope/result authenticators may unwind. The caller still owns
    /// this runner and its retained original; inspection-executor unwinds are
    /// recorded and returned as refusal without retrying the actual inspection.
    pub fn run_source_inspection(
        &mut self,
        case: &str,
        maximum_bytes: usize,
    ) -> Result<&OriginalSourceInspection, QualificationError> {
        if self.process != std::process::id() || self.owner_thread != std::thread::current().id() {
            return Err(refused("foreign source inspection creator"));
        }
        let planned = self
            .plan
            .cases
            .iter()
            .find(|planned| planned.id == case)
            .ok_or(refused("unplanned original source inspection"))?;
        if planned.kind != CaseKind::SourceInspection || self.attempts.attempted(case) {
            return Err(refused("changed or repeated original source inspection"));
        }
        let credit = maximum_bytes
            .checked_mul(6)
            .and_then(|bytes| bytes.checked_add(16_384))
            .ok_or(refused("source inspection encoding credit overflow"))?;
        let reserved = self
            .reserved_bytes
            .checked_add(credit as u64)
            .ok_or(refused("source inspection aggregate credit overflow"))?;
        if maximum_bytes == 0
            || credit > self.limits.maximum_claim_bytes
            || credit as u64 > self.limits.maximum_evidence_bytes
            || reserved > self.limits.maximum_total_evidence_bytes
        {
            return Err(refused("source inspection pre-execution byte credit"));
        }
        protocol::precharge(planned, self.limits.maximum_claim_bytes)?;
        protocol::current_scope(
            self.authority,
            &self.node,
            &self.binding,
            &self.plan.unit,
            &self.plan.classes,
        )?;
        protocol::check_applicability(self.authority, &self.plan, &self.population_reference)?;
        let planned = planned.clone();
        let mut output = Vec::new();
        output
            .try_reserve_exact(maximum_bytes)
            .map_err(|_| refused("source inspection output reservation"))?;
        self.reserved_bytes = reserved;
        self.attempts.begin(case.to_owned());
        self.source_inspections.insert(
            case.to_owned(),
            OriginalSourceInspection {
                output: OriginalSourceInspectionSlot {
                    maximum: maximum_bytes,
                    attempted: false,
                    bytes: output,
                },
                outcome: SourceInspectionOutcome::Reserved,
                verdict: None,
                reference: None,
            },
        );
        let original = self
            .source_inspections
            .get_mut(case)
            .ok_or(refused("source inspection original slot absent"))?;
        let executed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.authority.execute_original_source_inspection(
                &self.plan,
                &planned,
                &mut original.output,
            )
        }));
        let verdict = match executed {
            Ok(Ok(verdict)) => {
                original.outcome = SourceInspectionOutcome::Returned;
                original.verdict = Some(verdict);
                verdict
            }
            Ok(Err(error)) => {
                original.outcome = SourceInspectionOutcome::Refused;
                return Err(error);
            }
            Err(_) => {
                original.outcome = SourceInspectionOutcome::Unwound;
                return Err(refused("original source inspection callback unwound"));
            }
        };
        if !matches!(verdict, CaseVerdict::Passed | CaseVerdict::Failed)
            || !original.output.attempted
            || original.bytes().is_empty()
        {
            return Err(refused(
                "source inspection lacks an actual completed result",
            ));
        }
        let value = canonical::parse_json(original.bytes(), maximum_bytes)?;
        if canonical::canonical_json(&value)? != original.bytes() {
            return Err(refused("source inspection original is not canonical"));
        }
        original.reference = Some(canonical::content_ref(
            original.bytes(),
            "application/json",
        )?);
        protocol::current_scope(
            self.authority,
            &self.node,
            &self.binding,
            &self.plan.unit,
            &self.plan.classes,
        )?;
        let original = self
            .source_inspections
            .get(case)
            .ok_or(refused("source inspection original output absent"))?;
        let reference = original
            .reference()
            .ok_or(refused("source inspection canonical reference absent"))?;
        self.population
            .record(case, verdict, reference, original.bytes(), self.authority)?;
        self.attempts.authenticate(case)?;
        Ok(original)
    }

    /// Borrows every first source output, including failed and unissued originals.
    pub fn source_inspections(&self) -> &BTreeMap<String, OriginalSourceInspection> {
        &self.source_inspections
    }
}

fn refused(message: &'static str) -> QualificationError {
    QualificationError::Refused(message)
}

impl crate::node_qualification::RetainedMetadataOwned for OriginalSourceInspectionSlot {
    fn charge(
        &self,
        counter: &mut crate::node_qualification::RetainedMetadataCounter,
    ) -> Result<(), QualificationError> {
        let Self {
            maximum: _,
            attempted: _,
            bytes,
        } = self;
        counter.charge(bytes)
    }
}

impl crate::node_qualification::RetainedMetadataOwned for OriginalSourceInspection {
    fn charge(
        &self,
        counter: &mut crate::node_qualification::RetainedMetadataCounter,
    ) -> Result<(), QualificationError> {
        let Self {
            output,
            outcome: _,
            verdict: _,
            reference,
        } = self;
        counter.charge(output)?;
        counter.charge(reference)
    }
}
