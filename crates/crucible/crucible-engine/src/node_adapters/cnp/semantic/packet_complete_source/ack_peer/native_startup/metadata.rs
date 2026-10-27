//! Includes every retained native startup finalization prefix in the birth census.

use super::*;
use crate::node_contract::restored_owner_history::OriginalOwnerCapacityMetadataData;

impl OriginalNativeStartupFinalization {
    /// Records original member views, replacement capacity and both JSON owners.
    ///
    /// # Errors
    /// Refuses unsupported nested backing/depth, exhausted rows or unready banks.
    pub(in super::super) fn record_retained_capacity_data(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        let Self {
            member,
            replacement,
            body,
            additions,
            complete,
        } = self;
        census.observe_inline_data(complete)?;
        member.record_retained_capacity_data(census)?;
        census.observe(replacement)?;
        for value in [body, additions].into_iter().flatten() {
            retained_values::record_value_capacity_data_with_error::<RuntimeError>(
                value, 0, census,
            )?;
        }
        Ok(())
    }
}
