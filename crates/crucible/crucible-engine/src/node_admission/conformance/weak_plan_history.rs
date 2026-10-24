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
