//! Records weak Plan backing as a historical shared edge without upgrading it.

use super::*;
use crate::node_contract::RuntimeError;
use crate::node_contract::restored_owner_history::{
    OriginalRestoredOwnerCapacityAliases, OriginalRestoredOwnerCapacityRow,
};

impl WeakInstalledConformancePlan {
    pub(crate) fn borrowed_settled_role_data(
        &self,
        aliases: &mut OriginalRestoredOwnerCapacityAliases,
    ) -> Result<OriginalRestoredOwnerCapacityRow, RuntimeError> {
        aliases.weak_owner_data(&self.0)
    }

    pub(crate) fn settled_history_counter_scratch_data() -> usize {
        std::mem::size_of::<&Self>()
            + std::mem::size_of::<&Weak<Plan>>()
            + std::mem::size_of::<&mut OriginalRestoredOwnerCapacityAliases>()
            + std::mem::size_of::<OriginalRestoredOwnerCapacityRow>()
            + std::mem::size_of::<Result<OriginalRestoredOwnerCapacityRow, RuntimeError>>()
    }
}

impl WeakInstalledConformancePlan {
    /// Records only the real weak allocation shell without upgrading authority.
    ///
    /// # Errors
    /// Refuses selected-row exhaustion, invalid layout or unready physical backing.
    pub(crate) fn record_retained_capacity_data(
        &self,
        census: &mut crate::node_contract::restored_owner_history::OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        census.observe_weak_allocation_data(&self.0)
    }
}
