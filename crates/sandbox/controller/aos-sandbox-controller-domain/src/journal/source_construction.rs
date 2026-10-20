//! Adapts actual protected Source custody to the existing upper Journal.
//!
//! Source itself owns fixed opening, complete paid cold replay and native
//! custody. This private adapter moves the same historical remainder into the
//! existing Native live-history wrapper and retains actual upper Journal
//! recovery/posts without a public native adopter or semantic-success input.

use aos_sandbox_broker::controller_receiving::ControllerSourcePreBankConstructionLoanV1;
use aos_sandbox_ledger_replay::cold::ColdReplayRemainderDataV1;
use aos_sandbox_source::native::{SourceJournalConstructionOriginalsV1 as SourceOriginal, SourceNativeJournalOwnerV1};
use super::semantic_remainder::ColdSemanticRemainderOriginalV1;
use super::*;

type Selection = runtime_deployment_history::OriginalCompactionSelectionV1;

pub(crate) struct SourceJournalConstructionOriginalsV1 {
    original: SourceOriginal<Selection>,
    owner: Option<SourceNativeJournalOwnerV1<Selection>>,
    remainder: Option<ColdReplayRemainderDataV1>,
    conversion: ColdSemanticRemainderOriginalV1,
    journal: Option<Journal>,
    taken: bool,
}

impl SourceJournalConstructionOriginalsV1 {
    pub(crate) const fn new() -> Self {
        Self {
            original: SourceOriginal::new(), owner: None, remainder: None,
            conversion: ColdSemanticRemainderOriginalV1::new(), journal: None, taken: false,
        }
    }

    pub(crate) fn open_once(
        &mut self,
        loan: &mut ControllerSourcePreBankConstructionLoanV1<'_>,
    ) -> Result<(), ()> {
        self.open_with_recipe_once(loan, false)
    }

    pub(crate) fn open_existing_once(
        &mut self,
        loan: &mut ControllerSourcePreBankConstructionLoanV1<'_>,
    ) -> Result<(), ()> {
        self.open_with_recipe_once(loan, true)
    }

    fn open_with_recipe_once(
        &mut self,
        loan: &mut ControllerSourcePreBankConstructionLoanV1<'_>,
        existing_only: bool,
    ) -> Result<(), ()> {
        if existing_only { self.original.open_existing_once::<Self>(loan)?; }
        else { self.original.open_once::<Self>(loan)?; }
        let (owner, remainder) = self.original.take_completed_once(
            Selection::capture(
                std::path::Path::new(aos_sandbox_broker::source_receiving::SOURCE_DOMAIN_DIRECTORY_V1),
                aos_sandbox_broker::source_receiving::SOURCE_DOMAIN_JOURNAL_V1,
            ),
        ).ok_or(())?;
        self.owner = Some(owner);
        self.remainder = Some(remainder);
        // The genuine lower constructor already prices two actual Outer
        // representations before native entry. That includes this converter's
        // resident and complete nonallocating working planes.
        self.conversion.observe_once(&mut self.remainder);
        if !self.conversion.ready() { return Err(()); }
        let inputs = (self.owner.take(), self.conversion.take_once());
        let (owner, remainder) = match inputs {
            (Some(owner), Some(remainder)) => (owner, remainder),
            (owner, remainder) => {
                self.owner = owner;
                self.conversion.restore_unmoved(remainder);
                return Err(());
            }
        };
        self.journal = Some(Journal::from_source_owner_v1(
            owner, remainder, Arc::new(JournalAuthorityInstance),
        ));
        Ok(())
    }

    pub(crate) fn take_for_recovery_once(&mut self) -> Option<Journal> {
        if self.taken || self.primary_failure().is_some() {
            return None;
        }
        self.taken = true;
        self.journal.take()
    }

    pub(crate) fn finish_posts(
        &mut self,
        journal: Option<&Journal>,
        loan: &mut ControllerSourcePreBankConstructionLoanV1<'_>,
    ) -> Result<(), ()> {
        let owner = journal.and_then(|journal| journal.source_owner_for_read_v1().ok())
            .or(self.owner.as_ref());
        self.original.finish_posts(owner, loan)
    }

    pub(crate) fn primary_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.primary_failure().or_else(|| self.conversion.failure())
    }

    pub(crate) fn primary_failure_with_loan<'cause>(
        &'cause self,
        loan: &'cause ControllerSourcePreBankConstructionLoanV1<'_>,
    ) -> Option<&'cause (dyn std::error::Error + 'static)> {
        self.original.primary_failure_with_loan(loan).or_else(|| self.conversion.failure())
    }

    pub(crate) fn postcheck_debt(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.postcheck_debt()
    }

    pub(crate) fn postcheck_debt_with_loan<'cause>(
        &'cause self,
        loan: &'cause ControllerSourcePreBankConstructionLoanV1<'_>,
    ) -> Option<&'cause (dyn std::error::Error + 'static)> {
        self.original.postcheck_debt_with_loan(loan)
    }
}
