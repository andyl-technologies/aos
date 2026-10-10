//! Prepares backend-neutral immutable unexecuted audit data before installation.
//!
//! These records supply original bytes for private launch/binding construction.
//! They install no source, witness, collection graph, class or Ready authority.
//! The shared host authority separately requires current concrete source trust.

use std::collections::{BTreeMap, BTreeSet};

use crucible_node_contract::{ContentRef, canonical};

use crate::node_qualification::{
    AcceptanceDecision, AcceptanceLimits, AcceptanceRecord, Applicability, CaseEvidence,
    CaseVerdict, InstalledQualificationAuthority, InstalledWitnessAuthority, IssuedQualification,
    PlannedWitnessCase, QualificationClaim, QualificationClass, QualificationError,
    QualificationLimits, QualificationUnit, WitnessPlan, WitnessPopulation, evaluate_acceptance,
};

/// Retains complete original NotExecuted coverage and its evaluated Refused audit.
///
/// This type exposes immutable data only. Its constructor authenticates no
/// installation or observed source. The complete plan and independently
/// installed source must be reauthenticated before any launch or collection.
/// Declared exclusions remain data until independently installed applicability
/// policy authenticates them; this helper supplies no exclusion authority.
pub struct PlannedFixtureAudit {
    issued: IssuedQualification,
    record: AcceptanceRecord,
}

impl PlannedFixtureAudit {
    /// Prepares complete unexecuted original bytes for pre-Child binding assembly.
    ///
    /// The complete catalog and canonical plan geometry are checked by the same
    /// population implementation as later collection. No result is recorded.
    /// Evaluation explicitly has no accepted-claim authority and must refuse.
    ///
    /// # Errors
    /// Refuses malformed, substituted, incomplete or over-budget plan data,
    /// unavailable report capacity or a non-Refused audit evaluation.
    pub fn prepare(
        plan: &WitnessPlan,
        reference: &ContentRef,
        limits: QualificationLimits,
        maximum_audit_bytes: usize,
    ) -> Result<Self, QualificationError> {
        super::protocol::precharge(plan, limits.maximum_claim_bytes)?;
        let value =
            serde_json::to_value(plan).map_err(crucible_node_contract::ContractError::from)?;
        let bytes = canonical::canonical_json(&value)?;
        reference.verify(&bytes)?;
        let geometry = PlanGeometry {
            plan,
            reference,
            bytes: &bytes,
        };
        let issued = WitnessPopulation::install(&bytes, reference, &geometry, limits)?.finish()?;
        let evaluated = evaluate_acceptance(
            issued.bytes(),
            issued.reference(),
            &plan.unit,
            &plan.classes,
            &NoAcceptedClaim,
            AcceptanceLimits {
                qualification: limits,
                maximum_record_bytes: maximum_audit_bytes,
            },
        )?;
        if !matches!(
            evaluated.record().decision,
            AcceptanceDecision::Refused { .. }
        ) {
            return Err(refused());
        }
        super::protocol::precharge(evaluated.record(), maximum_audit_bytes)?;
        let value = serde_json::to_value(evaluated.record())
            .map_err(crucible_node_contract::ContractError::from)?;
        let record: AcceptanceRecord =
            serde_json::from_value(value).map_err(crucible_node_contract::ContractError::from)?;
        Ok(Self { issued, record })
    }

    /// Borrows the original report identity for exact private binding construction.
    pub fn claim(&self) -> &ContentRef {
        self.issued.reference()
    }

    /// Borrows complete canonical original coverage, including every omission.
    pub fn original_bytes(&self) -> &[u8] {
        self.issued.bytes()
    }

    /// Borrows the evaluated Refused record without providing acceptance authority.
    pub fn record(&self) -> &AcceptanceRecord {
        &self.record
    }
}

// This adapter checks data geometry only. It is private, has no collection or
// acceptance interface, and cannot record any actual result or create an owner.
struct PlanGeometry<'a> {
    plan: &'a WitnessPlan,
    reference: &'a ContentRef,
    bytes: &'a [u8],
}

impl InstalledWitnessAuthority for PlanGeometry<'_> {
    fn authenticate_plan(
        &self,
        reference: &ContentRef,
        bytes: &[u8],
        plan: &WitnessPlan,
    ) -> Result<(), QualificationError> {
        if reference != self.reference || bytes != self.bytes || plan != self.plan {
            return Err(refused());
        }
        Ok(())
    }

    fn authenticate_result(
        &self,
        _: &WitnessPlan,
        _: &PlannedWitnessCase,
        _: CaseVerdict,
        _: &ContentRef,
        _: &[u8],
    ) -> Result<(), QualificationError> {
        Err(refused())
    }
}

struct NoAcceptedClaim;

impl InstalledQualificationAuthority for NoAcceptedClaim {
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
        _: &QualificationUnit,
        _: &BTreeSet<QualificationClass>,
        _: &ContentRef,
    ) -> Result<BTreeMap<String, Applicability>, QualificationError> {
        Err(refused())
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

fn refused() -> QualificationError {
    QualificationError::Refused("planned fixture has no executed acceptance authority")
}

#[cfg(test)]
#[path = "fixture_audit/tests.rs"]
mod tests;
