//! Retains the actual startup writer across the closed credential recipe.
//!
//! Four-role startup additionally keeps its same genuine RootR locked and paid.
//! Ordinary startup borrows its existing writer without claiming receiving.
//! Independent returned credential policy results remain the daemon's decision.

use crate::policy_compiler::RootPolicyStartupJournalV1;

use super::{NormalRootStartupErrorV1, ProductionNormalRootStartupV1, RootReceivingGuardV1};

/// Borrows the same startup writer and, when installed, its genuine RootR owner.
///
/// Only the actual selected startup constructs this loan. No scalar, pathname,
/// decoded credential or caller-selected budget constructs receiving authority.
#[must_use = "finish the original native bookends before releasing credential custody"]
pub struct RootStartupCredentialReceivingLoanV1<'original> {
    original: Option<RootReceivingGuardV1<'original>>,
    startup: &'original ProductionNormalRootStartupV1,
    journal: &'original mut RootPolicyStartupJournalV1,
    finished: bool,
}

impl<'original> RootStartupCredentialReceivingLoanV1<'original> {
    pub(super) fn borrow_once(
        startup: &'original ProductionNormalRootStartupV1,
        journal: &'original mut RootPolicyStartupJournalV1,
    ) -> Result<Self, NormalRootStartupErrorV1> {
        let original = if startup.receiving.is_some() {
            let mut original = startup.lock_receiving_v1()?;
            let returned = original.begin_startup_credentials_native_once_v1(startup, journal);
            original.finish_returned_v1(returned)?;
            Some(original)
        } else {
            None
        };
        Ok(Self { original, startup, journal, finished: false })
    }

    /// Reports whether this actual writer borrow also retains genuine RootR.
    #[must_use]
    pub fn is_resource_receiving(&self) -> bool {
        self.original.is_some()
    }

    /// Checks that the closed fixed credential recipe remains borrowed and open.
    ///
    /// # Errors
    /// Rejects ended receiving, earlier debt or an incomplete original permit.
    pub fn require_reading(&self) -> Result<(), NormalRootStartupErrorV1> {
        if self.finished {
            return Err(NormalRootStartupErrorV1::Service);
        }
        match &self.original {
            Some(original) => {
                let returned = original.original_v1().require_startup_credentials_receiving();
                original.finish_returned_v1(returned)
            }
            None => Ok(()),
        }
    }

    /// Reborrows the same actual writer for existing fixed pin/head admissions.
    ///
    /// # Errors
    /// Refuses an ended or unhealthy actual entered credential interval.
    pub fn journal_mut(&mut self) -> Result<crate::policy_compiler::RootStartupCredentialWriterV1<'_>, NormalRootStartupErrorV1> {
        self.require_reading()?;
        let original = match self.original.as_mut() {
            Some(original) => Some(original.borrow_startup_credential_financial_v1()?),
            None => None,
        };
        match original {
            Some(original) => self.journal.native_mut_v1()?
                .selected_credential_writer_v1(original),
            None => self.journal.native_mut_v1()?.ordinary_credential_writer_v1(),
        }.map_err(NormalRootStartupErrorV1::StartupJournal)
    }

    /// Denies new shared entry after the caller retains its actual body error.
    pub fn refuse_primary_v1(&self) {
        if let Some(original) = &self.original { original.refuse_v1(); }
    }

    /// Retains final actual names and independent same-original startup posts.
    ///
    /// The caller has already parked its whole credential Result. This native
    /// bookend cannot heal that Result or admit a signer. Ordinary startup keeps
    /// its existing named-writer post without adding a receiving claim.
    ///
    /// # Errors
    /// Rejects changed native names or original selected/current containment.
    pub fn finish_once(mut self) -> Result<(), NormalRootStartupErrorV1> {
        let result = match self.original.as_mut() {
            Some(original) => {
                let returned = original.finish_startup_credentials_native_once_v1(self.startup, self.journal);
                original.finish_returned_v1(returned)
            }
            None => self.journal.finish_names_once().map_err(|_| NormalRootStartupErrorV1::Image),
        };
        self.finished = true;
        result
    }
}

impl Drop for RootStartupCredentialReceivingLoanV1<'_> {
    fn drop(&mut self) {
        if self.original.is_some() && !self.finished {
            self.refuse_primary_v1();
            // Unwinding cannot release unresolved original receiving custody.
            std::process::abort();
        }
    }
}
