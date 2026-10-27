//! Lends actual Target serving comparisons and independently owed posts.
//!
//! The upper pair retains this real target beside Authority. Opened-only after
//! access borrows the owner without requiring healthy serving entry; completing
//! a prearmed post uses its genuine writer even after a primary refusal.

use super::RootPolicyTargetOriginalV1;
use crate::native::journal::RootPolicyJournalServingIdentityV1;
use crate::native::PolicyNativeJournalErrorV1 as ErrorV1;
use aos_sandbox_broker::receiving::{RootJournalFinancialOriginalV1, RootWriterPostOriginalV1};
use aos_sandbox_model::ResourceVector;

impl RootPolicyTargetOriginalV1 {
    // This passive NEXT query borrows the same actual Target. It supplies no
    // health, financial, currentness or append permission.
    pub(in crate::native) fn current_snapshot_sequence_data_v1(&self) -> u64 {
        self.journal.snapshot_sequence()
    }

    /// Borrows complete historical DATA without asserting native currentness.
    #[must_use]
    pub fn historical_read_view_v1(&self)
        -> aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerReadViewV1<'_>
    {
        self.journal.read_view().historical_view()
    }

    /// Captures the actual selected target allocation and current sequence.
    ///
    /// # Errors
    /// Refuses unhealthy custody or an ended original invocation.
    pub fn serving_identity_v1(&self) -> Result<RootPolicyJournalServingIdentityV1, ErrorV1> {
        self.journal.serving_identity_v1()
    }

    /// Compares the same target allocation and unchanged captured sequence.
    ///
    /// # Errors
    /// Refuses changed allocation, sequence or unhealthy native custody.
    pub fn require_serving_identity_v1(&self, identity: &RootPolicyJournalServingIdentityV1)
        -> Result<(), ErrorV1>
    {
        self.journal.require_serving_identity_v1(identity)
    }

    /// Requires the genuine selected writer's same financial allocation.
    ///
    /// # Errors
    /// Retains original financial/native refusal and rejects ordinary custody.
    pub fn require_serving_financial_v1(&self, financial: &RootJournalFinancialOriginalV1)
        -> Result<(), ErrorV1>
    {
        self.journal.require_serving_financial_v1(financial)
    }

    /// Measures the actual writer's independent names post before arming it.
    ///
    /// # Errors
    /// Refuses ordinary custody or preserves the actual native geometry error.
    pub fn root_names_post_demand_v1(&self) -> Result<ResourceVector, ErrorV1> {
        self.journal.root_names_post_demand_v1()
    }

    /// Arms the already-paid actual writer's independent names post.
    ///
    /// # Errors
    /// Refuses ordinary custody or preserves the actual native invocation error.
    pub fn arm_root_names_post_once_v1(&self) -> Result<RootWriterPostOriginalV1, ErrorV1> {
        self.journal.arm_root_names_post_once_v1()
    }

    /// Finishes an actual prearmed names post without a new healthy entry gate.
    ///
    /// # Errors
    /// Retains original post/native refusal and rejects foreign or ordinary custody.
    pub fn finish_root_names_post_once_v1(&self, post: &mut RootWriterPostOriginalV1)
        -> Result<(), ErrorV1>
    {
        self.journal.finish_root_names_post_once_v1(post)
    }
}
