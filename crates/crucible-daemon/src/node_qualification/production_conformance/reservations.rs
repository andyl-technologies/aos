//! Reserves one original realized-case attempt before native execution.
//!
//! Reservations retain audit identity and evidence credit only. They grant no
//! native permission and cannot authenticate an outcome or replace custody.

use std::rc::Rc;

use crucible_node_contract::ContentRef;

use super::{
    CaseKind, ExactCompletionCase, ExactCompletionObservation, ProductionConformanceRunner,
    QualificationError, QualificationLimits, protocol,
};

/// Retains one pre-effect attempt belonging to its original owning runner.
///
/// The private, non-cloneable identity binds the fixed case, independent oracle
/// and snapshot ceiling. Dropping this handle never removes the audit attempt;
/// finishing without authenticated original evidence therefore refuses issuance.
/// This type supplies no admission, native permission or acceptance authority.
pub struct OriginalRealizedCaseReservation {
    owner: Rc<()>,
    case: String,
    oracle: ContentRef,
    maximum_bytes: u64,
}

impl OriginalRealizedCaseReservation {
    /// Borrows the original predeclared case identity.
    pub fn case(&self) -> &str {
        &self.case
    }

    fn matches(&self, owner: &Rc<()>, case: &str, oracle: &ContentRef, maximum_bytes: u64) -> bool {
        Rc::ptr_eq(&self.owner, owner)
            && self.case == case
            && &self.oracle == oracle
            && self.maximum_bytes == maximum_bytes
    }
}

impl<'a> ProductionConformanceRunner<'a> {
    /// Reserves an installed exact-case template before its original Begin.
    ///
    /// The complete plan and current installed source are checked before the
    /// attempt is recorded. The fixed semantic template can precede post-Arm
    /// proof identities; full outcome authentication remains a later independent
    /// source obligation. Callers retain this handle through uncertain execution.
    ///
    /// # Errors
    /// Refuses unknown or non-realized cases, substituted oracles, duplicate
    /// attempts, missing installed templates, withdrawn scope or exhausted
    /// evidence credit. No native execution occurs here.
    pub fn reserve_exact_case(
        &mut self,
        case: &str,
        oracle: &ContentRef,
        maximum_bytes: u64,
    ) -> Result<OriginalRealizedCaseReservation, QualificationError> {
        let planned = self
            .plan
            .cases
            .iter()
            .find(|planned| planned.id == case)
            .ok_or(QualificationError::Refused(
                "unplanned realized reservation",
            ))?;
        if planned.kind != CaseKind::RealizedProvider
            || &planned.oracle != oracle
            || self.attempts.attempted(case)
        {
            return Err(QualificationError::Refused("changed realized reservation"));
        }

        protocol::current_scope(
            self.authority,
            &self.node,
            &self.binding,
            &self.plan.unit,
            &self.plan.classes,
        )?;
        protocol::check_applicability(self.authority, &self.plan, &self.population_reference)?;
        protocol::precharge(&(case, oracle, case), 16_384)?;
        let reserved = reserve_credit(self.reserved_bytes, maximum_bytes, self.limits)?;

        self.authority.authenticate_realized_reservation(
            &self.plan,
            case,
            oracle,
            maximum_bytes,
        )?;
        protocol::current_scope(
            self.authority,
            &self.node,
            &self.binding,
            &self.plan.unit,
            &self.plan.classes,
        )?;

        // Both retained case copies and all proof readback credit are bounded
        // before any allocation or native work. The audit survives handle Drop.
        let original = OriginalRealizedCaseReservation {
            owner: Rc::clone(&self.reservation_owner),
            case: case.to_owned(),
            oracle: oracle.clone(),
            maximum_bytes,
        };
        self.reserved_bytes = reserved;
        self.attempts.begin(case.to_owned());
        Ok(original)
    }

    /// Consumes the original pre-Begin reservation to inspect its exact witness.
    ///
    /// Dynamic outcome/proof associations must already be authenticated from
    /// the actual original source. This method uses the original attempt and
    /// evidence reservation once; it never creates a second attempt or runs,
    /// publishes or acknowledges native execution.
    ///
    /// # Errors
    /// Refuses foreign or substituted reservations, changed case/oracle/credit,
    /// unavailable original completion, withdrawn source scope or unauthenticated
    /// body closure. The audit attempt remains retained on every refusal.
    pub fn collect_exact_witness_reserved(
        &mut self,
        original: OriginalRealizedCaseReservation,
        case: ExactCompletionCase,
        runtime: &mut crucible::node_contract::OriginalRuntimeWitness<'_>,
        token: &crucible::node_contract::OperationToken,
    ) -> Result<&ExactCompletionObservation, QualificationError> {
        self.collect_exact_original(case, runtime, None, token, Some(original))
    }

    pub(super) fn require_reserved_exact(
        &self,
        case: &ExactCompletionCase,
        original: &OriginalRealizedCaseReservation,
    ) -> Result<(), QualificationError> {
        if !original.matches(
            &self.reservation_owner,
            &case.case,
            &case.oracle,
            case.maximum_bytes,
        ) || !self.attempts.attempted(&case.case)
            || self.attempts.authenticated_cases().contains(&case.case)
        {
            return Err(QualificationError::Refused(
                "foreign original realized reservation",
            ));
        }
        Ok(())
    }
}

fn reserve_credit(
    retained: u64,
    maximum_bytes: u64,
    limits: QualificationLimits,
) -> Result<u64, QualificationError> {
    let encoded = maximum_bytes
        .checked_mul(6)
        .and_then(|bytes| bytes.checked_add(16_384))
        .ok_or(QualificationError::Refused(
            "exact encoding credit overflow",
        ))?;
    let reserved = retained
        .checked_add(encoded)
        .ok_or(QualificationError::Refused(
            "exact collection credit overflow",
        ))?;
    if maximum_bytes == 0
        || encoded > limits.maximum_evidence_bytes
        || encoded > limits.maximum_claim_bytes as u64
        || reserved > limits.maximum_total_evidence_bytes
    {
        return Err(QualificationError::Refused(
            "exact collection pre-read credit",
        ));
    }
    Ok(reserved)
}

#[cfg(test)]
mod tests;
