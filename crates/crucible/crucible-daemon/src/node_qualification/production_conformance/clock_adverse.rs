//! Collects concrete original Clock loss, publication and archive refusal owners.
//!
//! This population entry covers the actual withheld-readiness and lost-completion
//! programme. It does not replace full publication-failure, recovery or damaged
//! restoration cases. The installed Source independently authenticates same-owner
//! native observations; data bytes alone never install classes.

use super::{
    CaseKind, CaseVerdict, OriginalRealizedCaseReservation, ProductionConformanceRunner,
    QualificationClass, QualificationError, protocol,
};
use crate::node_observed_executor::OriginalClockAdverseWitness;
use crucible_node_format::{Bytes, ContentRef};
use serde::Serialize;

/// Retains the first original two-owner Clock adverse report and oracle verdict.
#[derive(Serialize)]
pub struct OriginalClockAdverseObservation {
    case: String,
    reference: ContentRef,
    bytes: Bytes,
    verdict: Option<CaseVerdict>,
}

impl OriginalClockAdverseObservation {
    /// Borrows the first full report, including an unaccepted oracle attempt.
    pub fn bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Borrows its complete normative content identity.
    pub fn reference(&self) -> &ContentRef {
        &self.reference
    }

    /// Returns the actual source verdict, if the callback returned one.
    pub fn verdict(&self) -> Option<CaseVerdict> {
        self.verdict
    }
}

impl ProductionConformanceRunner<'_> {
    /// Reserves the declared original two-owner Clock loss case before its Arm.
    ///
    /// # Errors
    /// Refuses foreign creator, changed plan/class/oracle, duplicates or missing
    /// original source and finite report credit. This issues no native permission.
    pub fn reserve_clock_adverse(
        &mut self,
        case: &str,
        oracle: &ContentRef,
        maximum_bytes: u64,
    ) -> Result<OriginalRealizedCaseReservation, QualificationError> {
        self.require_clock_adverse(case, oracle)?;
        self.reserve_exact_case(case, oracle, maximum_bytes)
    }

    /// Retains a real adverse report before the installed Source callback.
    ///
    /// The witness loans the same retained worlds and concrete stored publisher.
    /// Refusal/unwind preserves the first report and original attempt; this
    /// method cannot run, publish, resume, acknowledge or restore a provider.
    ///
    /// # Errors
    /// Refuses foreign/repeated reservation, changed plan/source or real native
    /// observations, over-budget output or a refused/unwound Source oracle.
    pub fn collect_clock_adverse_reserved(
        &mut self,
        reservation: OriginalRealizedCaseReservation,
        case: &str,
        oracle: &ContentRef,
        maximum_bytes: u64,
        witness: &OriginalClockAdverseWitness<'_>,
    ) -> Result<&OriginalClockAdverseObservation, QualificationError> {
        self.require_clock_adverse(case, oracle)?;
        if !reservation.matches(&self.reservation_owner, case, oracle, maximum_bytes)
            || !self.attempts.attempted(case)
            || self.attempts.authenticated_cases().contains(case)
            || self.clock_adverse_observations.contains_key(case)
        {
            return Err(refused("foreign or repeated Clock adverse reservation"));
        }
        protocol::current_scope(
            self.authority,
            &self.node,
            &self.binding,
            &self.plan.unit,
            &self.plan.classes,
        )?;
        protocol::check_applicability(self.authority, &self.plan, &self.population_reference)?;
        let ceiling = usize::try_from(maximum_bytes)
            .map_err(|_| refused("Clock adverse address-space ceiling"))?;
        if witness.bytes().len() > ceiling {
            return Err(refused("Clock adverse complete report ceiling"));
        }
        witness.reference().verify(witness.bytes())?;
        // Preserve the original complete output before any fallible source or
        // native reauthentication callback. The actor still owns every world.
        self.clock_adverse_observations.insert(
            case.to_owned(),
            OriginalClockAdverseObservation {
                case: case.to_owned(),
                reference: witness.reference().clone(),
                bytes: Bytes::new(witness.bytes().to_vec()),
                verdict: None,
            },
        );
        let original = self
            .clock_adverse_observations
            .get(case)
            .ok_or(refused("Clock adverse first output absent"))?;
        let verdict = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.authority.retain_original_clock_adverse_witness(
                &self.plan,
                case,
                oracle,
                witness,
                original.reference(),
                original.bytes(),
            )
        }))
        .map_err(|_| refused("installed Clock adverse oracle unwound"))??;
        if !matches!(verdict, CaseVerdict::Passed | CaseVerdict::Failed) {
            return Err(refused("Clock adverse oracle did not execute"));
        }
        self.clock_adverse_observations
            .get_mut(case)
            .ok_or(refused("Clock adverse first output absent"))?
            .verdict = Some(verdict);
        witness
            .authenticate_current()
            .map_err(|error| QualificationError::Evidence(error.to_string()))?;
        protocol::current_scope(
            self.authority,
            &self.node,
            &self.binding,
            &self.plan.unit,
            &self.plan.classes,
        )?;
        let original = self
            .clock_adverse_observations
            .get(case)
            .ok_or(refused("Clock adverse first output absent"))?;
        self.population.record(
            case,
            verdict,
            original.reference(),
            original.bytes(),
            self.authority,
        )?;
        self.attempts.authenticate(case)?;
        Ok(original)
    }

    fn require_clock_adverse(
        &self,
        case: &str,
        oracle: &ContentRef,
    ) -> Result<(), QualificationError> {
        if self.process != std::process::id() || self.owner_thread != std::thread::current().id() {
            return Err(refused("foreign original Clock adverse collector"));
        }
        let planned = self
            .plan
            .cases
            .iter()
            .find(|planned| planned.id == case)
            .ok_or(refused("unplanned original Clock adverse case"))?;
        if planned.kind != CaseKind::RealizedProvider
            || &planned.oracle != oracle
            || planned.classes
                != std::collections::BTreeSet::from([QualificationClass::BaseProvider])
        {
            return Err(refused("Clock adverse kind/classes/oracle changed"));
        }
        Ok(())
    }
}

fn refused(reason: &'static str) -> QualificationError {
    QualificationError::Refused(reason)
}

impl crate::node_qualification::RetainedMetadataOwned for OriginalClockAdverseObservation {
    fn charge(
        &self,
        counter: &mut crate::node_qualification::RetainedMetadataCounter,
    ) -> Result<(), QualificationError> {
        let Self {
            case,
            reference,
            bytes,
            verdict: _,
        } = self;
        counter.charge(case)?;
        counter.charge(reference)?;
        counter.charge(bytes)
    }
}

use crate::node_observed_executor::OriginalClockFailureWitness;

impl ProductionConformanceRunner<'_> {
    /// Reserves one fixed original publication or damaged-restoration experiment.
    ///
    /// # Errors
    /// Refuses foreign creator, changed plan/class/oracle, duplicates or missing
    /// original source and finite report credit. This issues no native permission.
    pub fn reserve_clock_failure(
        &mut self,
        case: &str,
        oracle: &ContentRef,
        maximum_bytes: u64,
    ) -> Result<OriginalRealizedCaseReservation, QualificationError> {
        self.require_clock_failure(case, oracle)?;
        self.reserve_exact_case(case, oracle, maximum_bytes)
    }

    /// Retains an actual failure report before the installed Source callback.
    ///
    /// The witness loans the same retained worlds and concrete stored publisher.
    /// Refusal/unwind preserves the first report and original attempt; this
    /// method cannot run, publish, resume, acknowledge or restore a provider.
    ///
    /// # Errors
    /// Refuses foreign/repeated reservation, changed plan/source or real native
    /// observations, over-budget output or a refused/unwound Source oracle.
    pub fn collect_clock_failure_reserved(
        &mut self,
        reservation: OriginalRealizedCaseReservation,
        case: &str,
        oracle: &ContentRef,
        maximum_bytes: u64,
        witness: &OriginalClockFailureWitness<'_>,
    ) -> Result<&OriginalClockAdverseObservation, QualificationError> {
        self.require_clock_failure(case, oracle)?;
        if !reservation.matches(&self.reservation_owner, case, oracle, maximum_bytes)
            || !self.attempts.attempted(case)
            || self.attempts.authenticated_cases().contains(case)
            || self.clock_adverse_observations.contains_key(case)
        {
            return Err(refused("foreign or repeated Clock failure reservation"));
        }
        protocol::current_scope(
            self.authority,
            &self.node,
            &self.binding,
            &self.plan.unit,
            &self.plan.classes,
        )?;
        protocol::check_applicability(self.authority, &self.plan, &self.population_reference)?;
        let ceiling = usize::try_from(maximum_bytes)
            .map_err(|_| refused("Clock failure address-space ceiling"))?;
        let report = witness
            .original_data()
            .map_err(|error| QualificationError::Evidence(error.to_string()))?;
        if report.bytes.len() > ceiling {
            return Err(refused("Clock failure complete report ceiling"));
        }
        report.reference.verify(&report.bytes)?;
        // Preserve the original complete output before any fallible source or
        // native reauthentication callback. The actor still owns every world.
        self.clock_adverse_observations.insert(
            case.to_owned(),
            OriginalClockAdverseObservation {
                case: case.to_owned(),
                reference: report.reference,
                bytes: Bytes::new(report.bytes),
                verdict: None,
            },
        );
        let original = self
            .clock_adverse_observations
            .get(case)
            .ok_or(refused("Clock failure first output absent"))?;
        let verdict = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.authority.retain_original_clock_failure_witness(
                &self.plan,
                case,
                oracle,
                witness,
                original.reference(),
                original.bytes(),
            )
        }))
        .map_err(|_| refused("installed Clock failure oracle unwound"))??;
        if !matches!(verdict, CaseVerdict::Passed | CaseVerdict::Failed) {
            return Err(refused("Clock failure oracle did not execute"));
        }
        self.clock_adverse_observations
            .get_mut(case)
            .ok_or(refused("Clock failure first output absent"))?
            .verdict = Some(verdict);
        witness
            .authenticate_current()
            .map_err(|error| QualificationError::Evidence(error.to_string()))?;
        protocol::current_scope(
            self.authority,
            &self.node,
            &self.binding,
            &self.plan.unit,
            &self.plan.classes,
        )?;
        let original = self
            .clock_adverse_observations
            .get(case)
            .ok_or(refused("Clock failure first output absent"))?;
        self.population.record(
            case,
            verdict,
            original.reference(),
            original.bytes(),
            self.authority,
        )?;
        self.attempts.authenticate(case)?;
        Ok(original)
    }

    fn require_clock_failure(
        &self,
        case: &str,
        oracle: &ContentRef,
    ) -> Result<(), QualificationError> {
        if self.process != std::process::id() || self.owner_thread != std::thread::current().id() {
            return Err(refused("foreign original Clock failure collector"));
        }
        witness_classes(case)?;
        let planned = self
            .plan
            .cases
            .iter()
            .find(|planned| planned.id == case)
            .ok_or(refused("unplanned original Clock failure case"))?;
        if planned.kind != CaseKind::RealizedProvider
            || &planned.oracle != oracle
            || planned.classes != witness_classes(case)?
        {
            return Err(refused("Clock failure kind/classes/oracle changed"));
        }
        Ok(())
    }
}

fn witness_classes(
    case: &str,
) -> Result<std::collections::BTreeSet<QualificationClass>, QualificationError> {
    use QualificationClass::*;
    match case {
        "clock/failed-publication-before-commit" | "clock/failed-publication-after-commit" => {
            Ok(std::collections::BTreeSet::from([BaseProvider]))
        }
        "clock/damaged-restoration-refusals" => Ok(std::collections::BTreeSet::from([
            CaptureModeledLive,
            CaptureModeledDurable,
        ])),
        _ => Err(refused("undeclared Clock failure experiment")),
    }
}
