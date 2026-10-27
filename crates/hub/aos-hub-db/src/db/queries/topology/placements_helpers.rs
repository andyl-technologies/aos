//! Placements helpers in the topology capability.

use super::*;

impl Database {
    pub(in crate::db) async fn surface_placement_operation_target_id(
        &self,
        id: i64,
    ) -> Result<String> {
        let row = self
            .backend
            .query_opt(
                "SELECT p.name, r.stable_id, c.stable_id FROM surface_placements p
                 LEFT JOIN registries r ON r.id = p.registry_id
                 LEFT JOIN binary_caches c ON c.id = p.cache_id WHERE p.id = ?1",
                &vals![id],
            )
            .await?
            .context("surface placement does not exist")?;
        let name: String = row.get(0)?;
        let registry: Option<String> = row.get(1)?;
        let cache: Option<String> = row.get(2)?;
        match (registry, cache) {
            (Some(surface), None) => Ok(format!("registry:{surface}/placement:{name}")),
            (None, Some(surface)) => Ok(format!("cache:{surface}/placement:{name}")),
            _ => bail!("surface placement has an invalid surface identity"),
        }
    }
}
