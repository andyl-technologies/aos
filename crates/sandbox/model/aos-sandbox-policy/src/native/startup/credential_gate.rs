//! Keeps the actual continuously held startup financial borrow at append.
//!
//! Only the native startup owner constructs this private loan from its own
//! completed fixed writer. The common append engine uses its borrowed debit at
//! the two original pre-entry fees and never reacquires the held L mutex.

use super::super::PolicyNativeJournalErrorV1 as ErrorV1;
use super::super::journal::{PolicyJournalInstanceV1, PolicyJournalStorageV1, RootPolicyJournalV1};
use aos_sandbox_broker::receiving::{RootJournalFinancialBorrowV1, RootJournalFinancialOriginalV1};
use aos_sandbox_model::ResourceVector;
use std::sync::Arc;

pub(in crate::native) struct StartupCredentialAppendGateV1<'borrow, 'initial> {
    original: &'borrow RootJournalFinancialBorrowV1<'initial>,
    instance: Arc<PolicyJournalInstanceV1>,
    financial: RootJournalFinancialOriginalV1,
}

impl StartupCredentialAppendGateV1<'_, '_> {
    pub(in crate::native) fn borrowed_financial_v1(&self) -> &RootJournalFinancialBorrowV1<'_> {
        self.original
    }

    pub(in crate::native) fn require_initial_current_v1(
        &self,
        journal: &RootPolicyJournalV1,
    ) -> Result<(), ErrorV1> {
        self.require_same_journal_v1(journal)?;
        self.original
            .require_current_v1()
            .map_err(|_| ErrorV1::Financial(self.financial.clone()))
    }

    pub(in crate::native) fn require_same_journal_v1(
        &self,
        journal: &RootPolicyJournalV1,
    ) -> Result<(), ErrorV1> {
        let PolicyJournalStorageV1::Selected { financial, .. } = &journal.storage else {
            return Err(ErrorV1::boundary());
        };
        if !Arc::ptr_eq(&self.instance, &journal.instance)
            || !financial.same_original_data_v1(&self.financial)
        {
            return Err(ErrorV1::boundary());
        }
        Ok(())
    }

    pub(in crate::native) fn debit_v1(
        &self,
        journal: &RootPolicyJournalV1,
        demand: ResourceVector,
    ) -> Result<(), ErrorV1> {
        self.require_same_journal_v1(journal)?;
        let PolicyJournalStorageV1::Selected { writer, .. } = &journal.storage else {
            return Err(ErrorV1::boundary());
        };
        self.original
            .debit_v1(writer, demand)
            .map_err(|_| ErrorV1::Financial(self.financial.clone()))
    }
}

impl super::RootSelectedStartupJournalOriginalV1 {
    // Actual fixed credential methods create this gate after journal_mut_v1;
    // this is deliberately private to native startup, not a journal adopter.
    pub(super) fn credential_append_gate_v1<'borrow, 'initial>(
        &self,
        original: &'borrow RootJournalFinancialBorrowV1<'initial>,
    ) -> Result<StartupCredentialAppendGateV1<'borrow, 'initial>, ErrorV1> {
        let journal = self.journal.as_ref().ok_or_else(ErrorV1::boundary)?;
        let actual = original
            .diagnostic_original_v1()
            .ok_or_else(ErrorV1::boundary)?;
        if !actual.same_original_data_v1(&self.financial) {
            return Err(ErrorV1::boundary());
        }
        Ok(StartupCredentialAppendGateV1 {
            original,
            instance: Arc::clone(&journal.instance),
            financial: actual,
        })
    }
}

// This quote is consumed by the genuine startup fixed pre-entry supplier, not
// manufactured from demand or debited through an unrelated Controller path.
pub(super) fn control_bytes_v1() -> Option<usize> {
    use std::mem::size_of;
    size_of::<StartupCredentialAppendGateV1<'_, '_>>()
        .checked_mul(3)?
        .checked_add(
            size_of::<Result<StartupCredentialAppendGateV1<'_, '_>, ErrorV1>>().checked_mul(3)?,
        )?
        .checked_add(
            size_of::<(
                &super::RootSelectedStartupJournalOriginalV1,
                &RootJournalFinancialBorrowV1<'_>,
            )>()
            .checked_mul(3)?,
        )?
        .checked_add(
            size_of::<(
                &StartupCredentialAppendGateV1<'_, '_>,
                &RootPolicyJournalV1,
                ResourceVector,
            )>()
            .checked_mul(3)?,
        )?
        .checked_add(size_of::<Result<(), ErrorV1>>().checked_mul(9)?)?
        .checked_add(size_of::<Option<RootJournalFinancialOriginalV1>>().checked_mul(3)?)?
        .checked_add(size_of::<RootJournalFinancialOriginalV1>().checked_mul(3)?)?
        .checked_add(size_of::<Arc<PolicyJournalInstanceV1>>().checked_mul(3)?)?
        .checked_add(size_of::<bool>().checked_mul(3)?)?
        .checked_add(size_of::<Option<usize>>().checked_mul(3)?)
}
