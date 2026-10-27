//! Lends only the actor's actual failure owners to the same installed Source.

use super::*;
use std::{cell::RefCell, rc::Weak};

struct Loan<'a> {
    programme: &'a mut OriginalClockFailureProgramme,
    original: &'a OriginalClockQualificationRun,
    state: &'a OriginalClockStateProgramme,
}

/// Borrows original Clock failures without granting native operation authority.
///
/// The private constructor requires retained actual owners and a completed
/// report. Source authentication checks the same original programme and fixed
/// execution roster; a decoded report cannot manufacture this loan.
pub struct OriginalClockFailureWitness<'a> {
    process: u32,
    thread: std::thread::ThreadId,
    case: &'static str,
    loan: RefCell<Loan<'a>>,
}

impl<'a> OriginalClockFailureWitness<'a> {
    pub(super) fn new(
        programme: &'a mut OriginalClockFailureProgramme,
        case: &'static str,
        original: &'a OriginalClockQualificationRun,
        state: &'a OriginalClockStateProgramme,
    ) -> Result<Self, NodeObservedError> {
        if programme.origin.process != std::process::id()
            || programme.origin.thread != std::thread::current().id()
        {
            return Err(refused("foreign original Clock failure witness creator"));
        }
        let witness = Self {
            process: programme.origin.process,
            thread: programme.origin.thread,
            case,
            loan: RefCell::new(Loan {
                programme,
                original,
                state,
            }),
        };
        witness.authenticate_current()?;
        Ok(witness)
    }

    fn creator(&self) -> Result<(), NodeObservedError> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(refused("foreign original Clock failure witness"));
        }
        Ok(())
    }

    /// Reauthenticates the actual first failure, native gates and durable bytes.
    ///
    /// # Errors
    /// Refuses a foreign creator, busy loan, incomplete original or changed
    /// native/source/store observations. This method never retries publication.
    pub fn authenticate_current(&self) -> Result<(), NodeObservedError> {
        self.creator()?;
        let mut loan = self
            .loan
            .try_borrow_mut()
            .map_err(|_| refused("Clock failure witness busy"))?;
        let Loan {
            programme,
            original,
            state,
        } = &mut *loan;
        programme.origin.current()?;
        match self.case {
            BEFORE | AFTER => {
                let fixture = &mut programme.publications[usize::from(self.case == AFTER)];
                if !fixture.complete {
                    return Err(refused("Clock publication failure report incomplete"));
                }
                fixture.authenticate(original)?;
            }
            DAMAGED => {
                if !programme.damage.complete {
                    return Err(refused("Clock damaged archive report incomplete"));
                }
                programme.damage.authenticate(state, original)?;
            }
            _ => return Err(refused("unknown Clock failure witness case")),
        }
        Ok(())
    }

    pub(in super::super) fn authenticate_source_data(
        &self,
        case: &str,
        lifetime: &Weak<()>,
        proposal: &crucible_engine::node_contract::ActivationRecord,
        scenario: &crate::node_scenario::NodeScenario,
        executions: [ExecutionId; 2],
    ) -> Result<(), NodeObservedError> {
        self.authenticate_current()?;
        let loan = self
            .loan
            .try_borrow()
            .map_err(|_| refused("Clock failure source loan busy"))?;
        if case != self.case
            || !Weak::ptr_eq(lifetime, &Rc::downgrade(&loan.original.source_lifetime))
            || proposal != &loan.original.proposal
            || executions != loan.programme.executions
            || scenario.canonical_bytes()? != loan.original.scenario.canonical_bytes()?
            || loan.original.origin.source != loan.programme.origin.source
        {
            return Err(refused("Clock failure belongs to another original source"));
        }
        Ok(())
    }

    /// Copies the bounded first report while retaining the actual owner loan.
    ///
    /// # Errors
    /// Refuses foreign origin, a busy loan or a missing completed original.
    pub fn original_data(&self) -> Result<InputPayload, NodeObservedError> {
        self.creator()?;
        let loan = self
            .loan
            .try_borrow()
            .map_err(|_| refused("Clock failure report loan busy"))?;
        let report = match self.case {
            BEFORE => loan.programme.publications[0].report.as_ref(),
            AFTER => loan.programme.publications[1].report.as_ref(),
            DAMAGED => loan.programme.damage.report.as_ref(),
            _ => None,
        }
        .ok_or_else(|| refused("Clock original failure report absent"))?;
        report.reference.verify(&report.bytes)?;
        Ok(report.clone())
    }
}
