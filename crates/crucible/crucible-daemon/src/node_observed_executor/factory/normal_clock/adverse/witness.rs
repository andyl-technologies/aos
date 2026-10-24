//! Loans the actual two-world adverse owners to their installed source.
//!
//! The private constructor requires the same actor's real programme, stored
//! publisher and original qualification owner. A bounded mutable loan prevents
//! concurrent mutation while the source rechecks native status and durability.

use std::cell::RefCell;
use std::rc::{Rc, Weak};

use super::*;

struct Loan<'a> {
    programme: &'a mut OriginalClockAdverseProgramme,
    original: &'a OriginalClockQualificationRun,
    publisher: &'a mut crate::node_observed_executor::StoredWorldActivationPublisher,
}

/// Borrows original adverse owners without transferring execution authority.
///
/// Each authentication checks real current statuses, the same stored complete
/// publication and the original native proof bodies. The immutable report is
/// retained by the actor before this loan. No decoder constructs a witness.
pub struct OriginalClockAdverseWitness<'a> {
    process: u32,
    thread: std::thread::ThreadId,
    loan: RefCell<Loan<'a>>,
    report: &'a InputPayload,
}

impl<'a> OriginalClockAdverseWitness<'a> {
    pub(in super::super) fn new(
        programme: &'a mut OriginalClockAdverseProgramme,
        original: &'a OriginalClockQualificationRun,
        publisher: &'a mut crate::node_observed_executor::StoredWorldActivationPublisher,
        report: &'a InputPayload,
    ) -> Result<Self, NodeObservedError> {
        let process = programme.origin.process;
        let thread = programme.origin.thread;
        if process != std::process::id() || thread != std::thread::current().id() {
            return Err(refused("foreign original Clock adverse witness creator"));
        }
        let witness = Self {
            process,
            thread,
            loan: RefCell::new(Loan {
                programme,
                original,
                publisher,
            }),
            report,
        };
        witness.authenticate_current()?;
        Ok(witness)
    }

    /// Reauthenticates actual native owners and the full original report.
    ///
    /// # Errors
    /// Refuses foreign origin, a busy loan, changed real boundaries, gates,
    /// published bodies, committed store record or lost-completion knowledge.
    /// Native status is an observation; no physical suspension grant is issued.
    pub fn authenticate_current(&self) -> Result<(), NodeObservedError> {
        // Check raw origin before acquiring the actual owner loan or observing
        // executable/native/store state through its retained references.
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(refused("foreign original Clock adverse witness creator"));
        }
        let mut loan = self
            .loan
            .try_borrow_mut()
            .map_err(|_| refused("Clock adverse owner loan busy"))?;
        let Loan {
            programme,
            original,
            publisher,
        } = &mut *loan;
        programme.authenticate_observed_data(original, publisher)?;
        self.report.reference.verify(&self.report.bytes)?;
        let actual = programme.original_data()?;
        if actual.reference != self.report.reference || actual.bytes != self.report.bytes {
            return Err(refused("Clock first original adverse report changed"));
        }
        Ok(())
    }

    pub(in super::super) fn authenticate_source_data(
        &self,
        lifetime: &Weak<()>,
        proposal: &crucible_engine::node_contract::ActivationRecord,
        scenario: &crate::node_scenario::NodeScenario,
        executions: [ExecutionId; 2],
    ) -> Result<(), NodeObservedError> {
        self.authenticate_current()?;
        let loan = self
            .loan
            .try_borrow()
            .map_err(|_| refused("Clock adverse source loan busy"))?;
        if !Weak::ptr_eq(lifetime, &Rc::downgrade(&loan.original.source_lifetime))
            || loan.programme.original_executions_data() != executions
            || &loan.original.proposal != proposal
            || loan.original.scenario.canonical_bytes()? != scenario.canonical_bytes()?
            || loan.programme.origin.source != loan.original.origin.source
            || loan.programme.origin.process != loan.original.origin.process
            || loan.programme.origin.thread != loan.original.origin.thread
        {
            return Err(refused(
                "Clock adverse owners belong to another original source",
            ));
        }
        Ok(())
    }

    /// Borrows the first complete original report retained before source callbacks.
    pub fn reference(&self) -> &ContentRef {
        &self.report.reference
    }

    /// Borrows the complete original canonical report bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.report.bytes
    }
}
