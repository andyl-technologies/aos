//! Retains one original nine-window host collection and every attempted case.
//!
//! A ticket is allocated from the frozen programme before native Stage. It is
//! collection data, never an execution grant. Refused source-oracle construction
//! remains an attempted, unauthenticated case even before the common collector
//! can retain a completion body. Actual source/runtime custody stays with the
//! independently owning cohort throughout collection and unwinding.

use std::rc::Rc;

use crucible::node_contract::{OperationToken, OriginalRuntimeWitness};
use crucible_node_contract::{ContentRef, Id};

use super::{TypedReaderProgrammeWindow, TypedReaderWitnessAuthority};
use crate::node_qualification::{
    CollectedConformance, InstalledAcceptancePolicy, ProductionConformanceRunner,
    QualificationError, QualificationLimits, QuantizedCompletionObservation,
};

const WINDOWS: usize = 9;

/// Distinguishes an original native attempt from authenticated report custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TypedReaderWindowDisposition {
    /// The owning driver has not attempted this original window.
    NotAttempted,
    /// A native attempt was declared, but its evidence is not authenticated.
    Attempted,
    /// The original body was authenticated, with its verdict retained separately.
    Authenticated,
}

/// Identifies one original attempt within the same private host collection.
///
/// No public constructor, clone or decoder can manufacture a replacement. This
/// record grants no Stage, Begin, Close, acknowledgement or native authority.
pub struct TypedReaderWindowTicket {
    origin: Rc<()>,
    index: usize,
}

/// Owns the original report population beside its shared installed authority.
///
/// Construction precedes Child. The caller retains this object across driver
/// failures and unwinding, then calls [`Self::finish`] after native containment.
/// The driver must declare each attempt before its first actual Stage or Begin.
pub struct TypedReaderHostCollection<'a> {
    authority: &'a TypedReaderWitnessAuthority,
    plan: ContentRef,
    origin: Rc<()>,
    states: [TypedReaderWindowDisposition; WINDOWS],
    runner: ProductionConformanceRunner<'a>,
    maximum_snapshot_bytes: u64,
}

/// Retains all actual report bodies and source-oracle attempt dispositions.
pub struct TypedReaderHostReport {
    /// Orders dispositions by the original programme's nine immutable windows.
    pub windows: [TypedReaderWindowDisposition; WINDOWS],
    /// Retains complete coverage, authenticated bodies and any issuance refusal.
    pub collection: CollectedConformance,
}

impl<'a> TypedReaderHostCollection<'a> {
    /// Installs the complete original population before any participant launches.
    ///
    /// The node selects one scope from the same independently installed host
    /// authority; the complete programme and unit still include all three peers.
    /// All 382 normative placeholders remain required and unexecuted.
    ///
    /// # Errors
    /// Refuses foreign scope or plan, missing independent source installation,
    /// changed nine-window geometry, zero snapshot credit or population limits.
    pub fn prepare(
        authority: &'a TypedReaderWitnessAuthority,
        node: Id,
        plan_bytes: &[u8],
        plan: &ContentRef,
        limits: QualificationLimits,
        maximum_snapshot_bytes: u64,
    ) -> Result<Self, QualificationError> {
        if authority.programme().windows().len() != WINDOWS || maximum_snapshot_bytes == 0 {
            return Err(refused());
        }
        // The entire finite programme is credited before any native attempt,
        // including the common collector's full snapshot encoding expansion.
        let encoded = maximum_snapshot_bytes
            .checked_mul(6)
            .and_then(|bytes| bytes.checked_add(16_384))
            .ok_or_else(refused)?;
        let total = encoded
            .checked_mul(WINDOWS as u64)
            .and_then(|bytes| bytes.checked_add(plan.length.get()))
            .ok_or_else(refused)?;
        if encoded > limits.maximum_evidence_bytes
            || encoded > limits.maximum_claim_bytes as u64
            || total > limits.maximum_total_evidence_bytes
        {
            return Err(refused());
        }
        authority.current_plan(plan).map_err(|_| refused())?;
        let binding = authority.scope_for_node(&node)?.binding.identity()?;
        let runner =
            ProductionConformanceRunner::new(authority, node, binding, plan_bytes, plan, limits)?;
        authority.current_plan(plan).map_err(|_| refused())?;

        Ok(Self {
            authority,
            plan: plan.clone(),
            origin: Rc::new(()),
            states: [TypedReaderWindowDisposition::NotAttempted; WINDOWS],
            runner,
            maximum_snapshot_bytes,
        })
    }

    // The driver must borrow this same installed object before recording an
    // attempt; equivalent plan data on another host holder cannot substitute it.
    pub(super) fn authenticate_authority(
        &self,
        authority: &TypedReaderWitnessAuthority,
    ) -> Result<(), QualificationError> {
        if !std::ptr::eq(self.authority, authority) {
            return Err(refused());
        }
        self.authority
            .current_plan(&self.plan)
            .map_err(|_| refused())?;
        Ok(())
    }

    /// Borrows the fixed original window order without granting execution.
    pub fn windows(&self) -> &[TypedReaderProgrammeWindow] {
        self.authority.programme().windows()
    }

    /// Declares one original attempt before native Stage or Begin.
    ///
    /// Source custody remains with the driver. An abandoned ticket leaves an
    /// explicit attempted case and prevents population issuance at finish.
    ///
    /// # Errors
    /// Refuses unplanned, duplicate or replaced cases and changed current scope.
    pub fn begin_window(
        &mut self,
        case: &str,
    ) -> Result<TypedReaderWindowTicket, QualificationError> {
        self.authority
            .current_plan(&self.plan)
            .map_err(|_| refused())?;
        let index = self
            .windows()
            .iter()
            .position(|window| window.case == case)
            .ok_or_else(refused)?;
        begin(&mut self.states, &self.origin, index)
    }

    /// Collects the same acknowledged original token against native source seals.
    ///
    /// The source-selected case is derived before report inspection. Its failure
    /// cannot turn the already declared native attempt into NotExecuted. This
    /// method only borrows the restricted runtime witness; it performs no native
    /// dispatch, polling, publication, acknowledgement or reclamation.
    ///
    /// # Errors
    /// Refuses foreign or consumed tickets, unavailable independent source seals,
    /// changed original completion, missing full Stage bodies or report limits.
    pub fn collect_window(
        &mut self,
        ticket: TypedReaderWindowTicket,
        witness: &mut OriginalRuntimeWitness<'_>,
        token: &OperationToken,
    ) -> Result<&QuantizedCompletionObservation, QualificationError> {
        if !belongs(&ticket, &self.origin, &self.states) {
            return Err(refused());
        }
        let window = self.windows().get(ticket.index).ok_or_else(refused)?;
        let case = self
            .authority
            .quantized_case(&window.case, self.maximum_snapshot_bytes)
            .map_err(|_| {
                QualificationError::Refused("original typed native window oracle unavailable")
            })?;
        let observation = self
            .runner
            .collect_quantized_witness(case, witness, token)?;
        self.states[ticket.index] = TypedReaderWindowDisposition::Authenticated;
        Ok(observation)
    }

    /// Retains complete reports and refuses issuance for any unauthenticated attempt.
    ///
    /// Authenticated windows retain their actual Passed or Failed verdict. Nine
    /// observations never replace the separate unexecuted normative obligations.
    /// Native disposal must still be serviced by the same owning cohort.
    pub fn finish(self) -> TypedReaderHostReport {
        let mut collection = self.runner.finish();
        if self
            .states
            .contains(&TypedReaderWindowDisposition::Attempted)
        {
            collection.issued = Err(QualificationError::Refused(
                "original typed native attempt lacks authenticated collection",
            ));
        }
        TypedReaderHostReport {
            windows: self.states,
            collection,
        }
    }
}

fn refused() -> QualificationError {
    QualificationError::Refused("original typed host collection scope differs")
}

fn begin(
    states: &mut [TypedReaderWindowDisposition; WINDOWS],
    origin: &Rc<()>,
    index: usize,
) -> Result<TypedReaderWindowTicket, QualificationError> {
    let state = states.get_mut(index).ok_or_else(refused)?;
    if *state != TypedReaderWindowDisposition::NotAttempted {
        return Err(refused());
    }
    *state = TypedReaderWindowDisposition::Attempted;
    Ok(TypedReaderWindowTicket {
        origin: Rc::clone(origin),
        index,
    })
}

fn belongs(
    ticket: &TypedReaderWindowTicket,
    origin: &Rc<()>,
    states: &[TypedReaderWindowDisposition; WINDOWS],
) -> bool {
    Rc::ptr_eq(&ticket.origin, origin)
        && states.get(ticket.index) == Some(&TypedReaderWindowDisposition::Attempted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_attempt_is_sticky_even_when_ticket_is_abandoned() {
        let origin = Rc::new(());
        let mut states = [TypedReaderWindowDisposition::NotAttempted; WINDOWS];
        let ticket = begin(&mut states, &origin, 0);
        assert!(ticket.is_ok());
        drop(ticket);
        assert_eq!(states[0], TypedReaderWindowDisposition::Attempted);
        assert!(begin(&mut states, &origin, 0).is_err());
        assert!(states.contains(&TypedReaderWindowDisposition::Attempted));
    }

    #[test]
    fn equal_programme_index_cannot_substitute_another_host_origin() {
        let original = Rc::new(());
        let foreign = Rc::new(());
        let mut states = [TypedReaderWindowDisposition::NotAttempted; WINDOWS];
        let ticket = begin(&mut states, &foreign, 0);
        assert!(ticket.is_ok());
        if let Ok(ticket) = ticket {
            assert!(!belongs(&ticket, &original, &states));
            assert!(belongs(&ticket, &foreign, &states));
        }
        assert_eq!(states[0], TypedReaderWindowDisposition::Attempted);
    }

    #[test]
    fn unknown_or_authenticated_case_cannot_issue_a_second_ticket() {
        let origin = Rc::new(());
        let mut states = [TypedReaderWindowDisposition::NotAttempted; WINDOWS];
        assert!(begin(&mut states, &origin, WINDOWS).is_err());
        assert!(
            states
                .iter()
                .all(|state| *state == TypedReaderWindowDisposition::NotAttempted)
        );
        states[0] = TypedReaderWindowDisposition::Authenticated;
        assert!(begin(&mut states, &origin, 0).is_err());
        assert_eq!(states[0], TypedReaderWindowDisposition::Authenticated);
    }
}
