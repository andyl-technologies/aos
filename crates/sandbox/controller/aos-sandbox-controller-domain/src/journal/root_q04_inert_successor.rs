//! Lends only this held native Root map to its nonissuing Q04 predecessor check.

use crate::policy_compiler::create_q04::{CreateQ04ErrorV1, RootInertHistoryScanV1,
    require_inert_root_open_history_v1};

use super::Journal;

impl Journal {
    pub(crate) fn observe_inert_root_q04_predecessor_v1(&self,
        originals: &mut RootInertHistoryScanV1) -> Result<(), CreateQ04ErrorV1>
    {
        require_inert_root_open_history_v1(self.native.state(), originals)
    }
}

impl Journal {
    pub(crate) fn observe_original_root_q04_parent_v1(
        &self, originals: &mut RootInertHistoryScanV1,
        identity: &crate::policy_compiler::create_q04::Q04CutIdentityV1,
        root_final: [u8; 32],
    ) -> Result<(), CreateQ04ErrorV1> {
        originals.observe_original_parent_once(self.native.state(), identity, root_final)
    }
}
