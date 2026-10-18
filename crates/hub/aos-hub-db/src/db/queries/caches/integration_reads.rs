//! Integration reads in the caches capability.

use super::*;

impl Database {
    /// Lists population targets that write to one cache.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_cache_population_targets(
        &self,
        cache_id: i64,
    ) -> Result<Vec<CachePopulationTargetRecord>> {
        self.backend.query(&format!("SELECT {POPULATION_COLUMNS} FROM cache_population_targets WHERE cache_id = ?1 ORDER BY registry_id, trigger_kind"), &vals![cache_id]).await?.iter().map(row_to_cache_population_target).collect()
    }
}
