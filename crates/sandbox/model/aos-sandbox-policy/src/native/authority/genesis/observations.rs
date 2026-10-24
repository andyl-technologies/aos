//! Retires successful probes at the original temporary-observation boundary.
//!
//! Genesis used nonretaining owner/name helpers before its native-owner move.
//! Its resident destination now keeps every entered failure, while the same
//! existing positive retirement releases successful probes at that old local
//! boundary. This composition adds no observation, retry or clearance.

use super::super::names::{RootAuthorityNameRecipeV1, RootAuthorityNamesOriginalV1};
use crate::native::journal::RootPolicyJournalV1;

impl RootAuthorityNamesOriginalV1 {
    pub(in crate::native::authority::genesis) fn observe_transient_once_v1(
        &mut self,
        journal: &RootPolicyJournalV1,
        recipe: RootAuthorityNameRecipeV1,
    ) -> Result<(), ()> {
        let returned = self.observe_once(journal, recipe);
        if returned.is_ok() {
            self.settle_positive_once_v1();
        }
        returned
    }
}
