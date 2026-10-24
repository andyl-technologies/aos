//! Lends finite serving comparisons from the same completed Authority owner.
//!
//! The listener retains this actual owner beside the actual Policy target.
//! These comparisons neither adopt a journal nor reconstruct an Authority from
//! names, a financial handle or an opaque captured identity.

use aos_sandbox_broker::receiving::RootJournalFinancialOriginalV1;

use super::RootAuthorityOriginalV1;
use crate::native::{PolicyNativeJournalErrorV1, RootPolicyJournalServingIdentityV1};

impl RootAuthorityOriginalV1 {
    /// Samples the same held file and copies its original fixed limits.
    ///
    /// The caller owns the original receiving invoice and retains the complete
    /// returned IO result. This performs no fresh health or role observation.
    pub fn held_native_receiving_metadata_v1(
        &self,
    ) -> (
        std::io::Result<std::fs::Metadata>,
        aos_sandbox_protocol::domain_ledger::transaction::JournalLimits,
    ) {
        let view = self.journal.read_view();
        (view.metadata(), view.limits())
    }


    /// Captures the same native Authority allocation and next sequence.
    ///
    /// # Errors
    /// Refuses unhealthy native custody or an ended original invocation.
    pub fn serving_identity_v1(
        &self,
    ) -> Result<RootPolicyJournalServingIdentityV1, PolicyNativeJournalErrorV1> {
        self.journal.serving_identity_v1()
    }

    /// Compares the retained identity with this same unchanged native owner.
    ///
    /// # Errors
    /// Refuses a different allocation, sequence or unhealthy native custody.
    pub fn require_serving_identity_v1(
        &self,
        identity: &RootPolicyJournalServingIdentityV1,
    ) -> Result<(), PolicyNativeJournalErrorV1> {
        self.journal.require_serving_identity_v1(identity)
    }

    /// Requires this actual owner to retain the original financial allocation.
    ///
    /// # Errors
    /// Preserves the original native or financial refusal without a new debit.
    pub fn require_serving_financial_v1(
        &self,
        financial: &RootJournalFinancialOriginalV1,
    ) -> Result<(), PolicyNativeJournalErrorV1> {
        self.journal.require_serving_financial_v1(financial)
    }

    /// Reports the same actual native owner's recorded NEXT as comparison DATA.
    ///
    /// This adds no IO, health gate, admission or currentness assertion, including
    /// on an independently owed after path following an earlier refusal.
    #[must_use]
    pub fn snapshot_sequence_v1(&self) -> u64 {
        self.journal.next_sequence()
    }
}

impl RootAuthorityOriginalV1 {
    /// Borrows complete historical row/index DATA from this same held owner.
    ///
    /// The view performs no IO and supplies no currentness, writer, financial
    /// grant or publication permission. Actual serving intervals retain their
    /// independent current-name posts around each use.
    #[must_use]
    pub fn historical_read_view_v1(
        &self,
    ) -> aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerReadViewV1<'_> {
        self.journal.read_view().historical_view()
    }

    /// Measures this same genuine Root writer's independent native names post.
    ///
    /// # Errors
    /// Refuses ordinary storage or preserves the actual Root native refusal.
    pub fn root_names_post_demand_v1(
        &self,
    ) -> Result<aos_sandbox_model::ResourceVector, PolicyNativeJournalErrorV1> {
        self.journal.root_names_post_demand_v1()
    }

    /// Arms the same actual Root writer's independently owed native names post.
    ///
    /// The existing serving receiver pays the complete post demand before this
    /// call and retains its returned original before entering native observation.
    ///
    /// # Errors
    /// Refuses ordinary storage or preserves the original Root invocation cause.
    pub fn arm_root_names_post_once_v1(
        &self,
    ) -> Result<aos_sandbox_broker::receiving::RootWriterPostOriginalV1, PolicyNativeJournalErrorV1>
    {
        self.journal.arm_root_names_post_once_v1()
    }

    /// Completes the original armed names post on this same genuine Root writer.
    ///
    /// # Errors
    /// Refuses a foreign post, ordinary storage, failed original observation or
    /// ended actual invocation; the caller keeps the post original resident.
    pub fn finish_root_names_post_once_v1(
        &self,
        post: &mut aos_sandbox_broker::receiving::RootWriterPostOriginalV1,
    ) -> Result<(), PolicyNativeJournalErrorV1> {
        self.journal.finish_root_names_post_once_v1(post)
    }
}
