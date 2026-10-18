//! Networks reads in the topology capability.

use super::*;

impl Database {
    /// Counts still-live pin identities sealed into a coordination operation.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn count_live_network_policy_pins(&self, pin_ids: &[String]) -> Result<i64> {
        let mut live = 0_i64;
        for pin_id in pin_ids {
            if self
                .backend
                .query_opt(
                    "SELECT 1 FROM network_policy_serving_pins WHERE pin_id = ?1",
                    &vals![pin_id],
                )
                .await?
                .is_some()
            {
                live += 1;
            }
        }
        Ok(live)
    }
}
