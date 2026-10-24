//! Lends the real financial original only during native credential receiving.

use super::RootReceivingOriginalV1;
use crate::normal_root::NormalRootStartupErrorV1;

impl RootReceivingOriginalV1 {
    pub(crate) fn borrow_startup_credential_financial_v1<'original>(
        &'original mut self,
        mutation: &'original aos_sandbox_broker::receiving::RootUpperMutationGuardV1<'_>,
    ) -> Result<
        aos_sandbox_broker::receiving::RootJournalFinancialBorrowV1<'original>,
        NormalRootStartupErrorV1,
    > {
        if self.require_startup_credentials_receiving().is_err() {
            self.activation.latch_root_refusal_v1();
            return Err(NormalRootStartupErrorV1::Service);
        }
        // The return lifetime borrows this WHOLE upper original. None of its
        // entered credential fields can change during the fixed admission.
        self.activation
            .borrow_journal_financial_v1(mutation)
            .map_err(|_| NormalRootStartupErrorV1::Service)
    }

    pub(crate) fn require_startup_credentials_receiving(
        &self,
    ) -> Result<(), NormalRootStartupErrorV1> {
        self.native_startup_prior
            .as_ref()
            .ok_or(NormalRootStartupErrorV1::Service)?
            .require_selected_credentials_receiving_v1(&self.activation)
            .map_err(Into::into)
    }
}
