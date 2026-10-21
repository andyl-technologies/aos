//! Owns the actual compiler-state target and its retained native observations.
//!
//! The fixed Root construction transfers this owner only after the same full
//! semantic replay, tail and owed name posts. Publication borrows this writer;
//! no caller can supply a journal, native parts or an authenticated DATA stamp.

mod currentness;
mod owed_names;
mod opening;
mod serving;
mod names;
mod work;

use super::journal::RootPolicyJournalV1;
use currentness::PolicyTargetCurrentCustodyV1;
pub use currentness::PolicyTargetCurrentFailureV1;
pub use opening::RootPolicyTargetConstructionOriginalV1;
pub use work::{
    RootOriginalInputLoanV1, RootPolicyHistoryAdmissionFailureV1, RootPolicyPublicationErrorV1, RootPolicyPublicationWorkV1,
};

/// Retains the same compiler-state writer and every failed target observation.
pub struct RootPolicyTargetOriginalV1 {
    journal: RootPolicyJournalV1,
    current: PolicyTargetCurrentCustodyV1,
    owed_names: owed_names::PolicyTargetOwedNamesCustodyV1,
}

impl RootPolicyTargetOriginalV1 {
    pub(in crate::native) fn require_original_input_names_v1(
        &self,
    ) -> Result<(), super::PolicyNativeJournalErrorV1> {
        currentness::require_current_names_v1(&self.journal, &self.current)
    }

    pub(in crate::native) fn require_original_input_names_post_once_v1(
        &self,
    ) -> Result<(), super::PolicyNativeJournalErrorV1> {
        self.owed_names.finish_once_v1(&self.journal)
    }

    /// Borrows only the independently owed Target-name post's actual refusal.
    ///
    /// Body-currentness refusal remains in its separate destination. This
    /// passive accessor neither enters native work nor substitutes that cause.
    #[must_use]
    pub fn retained_owed_names_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.owed_names.failure()
    }

    pub(in crate::native) fn retained_selected_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.journal.retained_selected_failure_v1()
    }

    /// Borrows an actual retained target cause without resampling native state.
    #[must_use]
    pub fn retained_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.current.failure().or_else(|| self.journal.failure())
    }
}

pub(in crate::native) use work::RootCurrentInputVerifierV1;
