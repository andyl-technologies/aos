//! Retains actual Clock state owners through independent normal qualification.
//!
//! A private borrowed witness comes only from the real Clock programme. The
//! complete population, expected state oracle, source currentness, observation
//! kind and final acceptance remain separate installed-source conjunctions.

use crucible_node_format::{Bytes, ContentRef, canonical};
use serde::Serialize;

use super::{
    CaseKind, CaseVerdict, OriginalRealizedCaseReservation, ProductionConformanceRunner,
    QualificationClass, QualificationError, protocol,
};
use crate::node_observed_executor::OriginalClockStateWitness;

/// Retains the runner's first actual original Clock state report.
///
/// Serialized bytes alone grant no normal class, provider source or activation.
/// The real original and both fresh native owners remain retained on the actor.
#[derive(Serialize)]
pub struct OriginalClockStateObservation {
    case: String,
    reference: ContentRef,
    bytes: Bytes,
    verdict: Option<CaseVerdict>,
}

impl OriginalClockStateObservation {
    /// Borrows the original canonical full-state body, including failed attempts.
    pub fn bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Borrows the exact original body identity.
    pub fn reference(&self) -> &ContentRef {
        &self.reference
    }

    /// Reports the independently authenticated original verdict, if returned.
    pub fn verdict(&self) -> Option<CaseVerdict> {
        self.verdict
    }
}

impl ProductionConformanceRunner<'_> {
    /// Reserves a source-declared complete original Clock state attempt.
    ///
    /// This reuses the actual noncloneable runner reservation and serialized
    /// credit before capture/restoration. No native effect occurs here; the
    /// source still authenticates its exact fixed programme and all classes.
    ///
    /// # Errors
    /// Refuses wrong classes, case/oracle/source, a duplicate or exhausted credit.
    pub fn reserve_clock_state(
        &mut self,
        case: &str,
        oracle: &ContentRef,
        maximum_bytes: u64,
    ) -> Result<OriginalRealizedCaseReservation, QualificationError> {
        if self.process != std::process::id() || self.owner_thread != std::thread::current().id() {
            return Err(refused("foreign original Clock state reservation"));
        }
        self.require_clock_state_case(case, oracle)?;
        self.reserve_exact_case(case, oracle, maximum_bytes)
    }

    /// Collects genuine retired and independently continued Clock owners once.
    ///
    /// Original output custody precedes every independent oracle callback.
    /// Refusal/unwind cannot replace this report or renew its original attempt.
    /// This method never captures, restores, runs, publishes or ACKs a provider.
    ///
    /// # Errors
    /// Refuses foreign creator/reservation, changed kind/classes/oracle/source,
    /// incomplete real owners, over-budget evidence or refused original oracle.
    pub fn collect_clock_state_reserved(
        &mut self,
        reservation: OriginalRealizedCaseReservation,
        case: &str,
        oracle: &ContentRef,
        maximum_bytes: u64,
        witness: &OriginalClockStateWitness<'_>,
    ) -> Result<&OriginalClockStateObservation, QualificationError> {
        if self.process != std::process::id() || self.owner_thread != std::thread::current().id() {
            return Err(refused("foreign original Clock state collector"));
        }
        self.require_clock_state_case(case, oracle)?;
        if !reservation.matches(&self.reservation_owner, case, oracle, maximum_bytes)
            || !self.attempts.attempted(case)
            || self.attempts.authenticated_cases().contains(case)
            || self.clock_state_observations.contains_key(case)
        {
            return Err(refused(
                "foreign or repeated original Clock state reservation",
            ));
        }
        protocol::current_scope(
            self.authority,
            &self.node,
            &self.binding,
            &self.plan.unit,
            &self.plan.classes,
        )?;
        protocol::check_applicability(self.authority, &self.plan, &self.population_reference)?;
        let data = witness
            .observation_data()
            .map_err(|error| QualificationError::Evidence(error.to_string()))?;
        let ceiling = usize::try_from(maximum_bytes)
            .map_err(|_| refused("Clock state address-space ceiling"))?;
        let report = (
            "crucible.original-clock-state-observation/1",
            &self.population_reference,
            case,
            oracle,
            &data,
        );
        protocol::precharge(&report, ceiling)?;
        let bytes = canonical::canonical_json(
            &serde_json::to_value(&report).map_err(crucible_node_format::ContractError::from)?,
        )?;
        if bytes.len() > ceiling {
            return Err(refused("Clock state complete evidence ceiling"));
        }
        let reference = canonical::content_ref(&bytes, "application/json")?;
        self.clock_state_observations.insert(
            case.to_owned(),
            OriginalClockStateObservation {
                case: case.to_owned(),
                reference,
                bytes: Bytes::new(bytes),
                verdict: None,
            },
        );
        let original = self
            .clock_state_observations
            .get(case)
            .ok_or(refused("original Clock state output absent"))?;
        let verdict = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.authority.retain_original_clock_state_witness(
                &self.plan,
                case,
                oracle,
                witness,
                original.reference(),
                original.bytes(),
            )
        }))
        .map_err(|_| refused("installed original Clock state oracle unwound"))??;
        if !matches!(verdict, CaseVerdict::Passed | CaseVerdict::Failed) {
            return Err(refused("Clock state oracle did not execute"));
        }
        let original = self
            .clock_state_observations
            .get_mut(case)
            .ok_or(refused("original Clock state output absent"))?;
        original.verdict = Some(verdict);
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
            .clock_state_observations
            .get(case)
            .ok_or(refused("original Clock state output absent"))?;
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

    fn require_clock_state_case(
        &self,
        case: &str,
        oracle: &ContentRef,
    ) -> Result<(), QualificationError> {
        let planned = self
            .plan
            .cases
            .iter()
            .find(|planned| planned.id == case)
            .ok_or(refused("unplanned original Clock state case"))?;
        let classes = std::collections::BTreeSet::from([
            QualificationClass::Repeatable,
            QualificationClass::CaptureModeledLive,
            QualificationClass::CaptureModeledDurable,
        ]);
        let complete_classes = std::collections::BTreeSet::from([
            QualificationClass::BaseProvider,
            QualificationClass::ExactTiming,
            QualificationClass::RoleProfile,
            QualificationClass::Repeatable,
            QualificationClass::CaptureModeledLive,
            QualificationClass::CaptureModeledDurable,
        ]);
        // The real witness authenticates complete same-owner admission guards
        // and original timing/role history as well as fresh state continuations.
        // The installed source must independently authenticate whichever exact
        // fixed class roster it declared; no arbitrary class subset is accepted.
        if planned.kind != CaseKind::RealizedProvider
            || &planned.oracle != oracle
            || (planned.classes != classes && planned.classes != complete_classes)
        {
            return Err(refused("original Clock state kind/classes/oracle differs"));
        }
        Ok(())
    }
}

fn refused(reason: &'static str) -> QualificationError {
    QualificationError::Refused(reason)
}

impl crate::node_qualification::RetainedMetadataOwned for OriginalClockStateObservation {
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
