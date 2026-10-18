//! Jobs helpers in the administration capability.

use super::*;

impl Database {
    pub(in crate::db) async fn resolve_operation_target(
        &self,
        target: &NewTopologyOperationTarget,
    ) -> Result<(NewTopologyOperationTargetRef, String, String, String)> {
        validate_key_bytes(&target.role, "operation target role", 32)?;
        if target.generation_key < 0 {
            bail!("operation target generation cannot be negative");
        }
        if !target.configuration_digest.is_empty()
            && (target.configuration_digest.len() != 64
                || !target
                    .configuration_digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')))
        {
            bail!("operation target configuration digest must be lowercase SHA-256 hex");
        }
        let (kind, stable_id, scope): (&str, String, String) = match &target.target {
            NewTopologyOperationTargetRef::Registry(id) => {
                if target.generation_key != 0 || !target.configuration_digest.is_empty() {
                    bail!("registry operation targets do not accept a generation or digest");
                }
                let row = self
                    .backend
                    .query_opt(
                        "SELECT r.stable_id, r.scope_key FROM registries r WHERE r.id = ?1",
                        &vals![id],
                    )
                    .await?
                    .context("operation registry target does not exist")?;
                ("registry", row.get(0)?, row.get(1)?)
            }
            NewTopologyOperationTargetRef::BinaryCache(id) => {
                if target.generation_key != 0 || !target.configuration_digest.is_empty() {
                    bail!("binary-cache operation targets do not accept a generation or digest");
                }
                let row = self
                    .backend
                    .query_opt(
                        "SELECT c.stable_id, c.scope_key FROM binary_caches c WHERE c.id = ?1",
                        &vals![id],
                    )
                    .await?
                    .context("operation binary-cache target does not exist")?;
                ("binary_cache", row.get(0)?, row.get(1)?)
            }
            NewTopologyOperationTargetRef::Placement(id) => {
                let row = self
                    .backend
                    .query_opt(
                        "SELECT p.name, r.stable_id, c.stable_id,
                            COALESCE(r.scope_key, c.scope_key)
                     FROM surface_placements p
                     LEFT JOIN registries r ON r.id = p.registry_id
                     LEFT JOIN binary_caches c ON c.id = p.cache_id
                     WHERE p.id = ?1",
                        &vals![id],
                    )
                    .await?
                    .context("operation placement target does not exist")?;
                let name: String = row.get(0)?;
                let registry: Option<String> = row.get(1)?;
                let cache: Option<String> = row.get(2)?;
                let stable_id = match (registry, cache) {
                    (Some(surface), None) | (None, Some(surface)) => {
                        format!("{surface}/placement:{name}")
                    }
                    _ => bail!("operation placement target has an invalid surface"),
                };
                let resource_version: i64 = self
                    .backend
                    .query_opt(
                        "SELECT resource_version FROM surface_placements WHERE id = ?1",
                        &vals![id],
                    )
                    .await?
                    .context("operation placement target does not exist")?
                    .get(0)?;
                if target.generation_key != resource_version
                    || !target.configuration_digest.is_empty()
                {
                    bail!("operation placement target version is stale");
                }
                ("placement", stable_id, row.get(3)?)
            }
            NewTopologyOperationTargetRef::Domain(id) => {
                let row = self
                    .backend
                    .query_opt(
                        "SELECT owner_scope_key, resource_version FROM domains WHERE stable_id = ?1",
                        &vals![id],
                    )
                    .await?
                    .context("operation domain target does not exist")?;
                let resource_version: i64 = row.get(1)?;
                if target.generation_key != resource_version
                    || !target.configuration_digest.is_empty()
                {
                    bail!("operation domain target version is stale");
                }
                ("domain", id.clone(), row.get(0)?)
            }
            NewTopologyOperationTargetRef::NetworkPolicy(id) => {
                let row = self
                    .backend
                    .query_opt(
                        "SELECT owner_scope_key FROM network_policies WHERE id = ?1",
                        &vals![id],
                    )
                    .await?
                    .context("operation boundary target does not exist")?;
                let revision = self
                    .backend
                    .query_opt(
                        "SELECT content_digest FROM network_policy_revisions
                         WHERE boundary_id = ?1 AND revision = ?2",
                        &vals![id, target.generation_key],
                    )
                    .await?
                    .context("operation boundary revision target does not exist")?;
                let digest: String = revision.get(0)?;
                if target.configuration_digest != digest {
                    bail!("operation boundary revision digest is stale");
                }
                ("network_policy", id.clone(), row.get(0)?)
            }
            NewTopologyOperationTargetRef::Endpoint(id) => {
                let row = self
                    .backend
                    .query_opt(
                        "SELECT owner_scope_key FROM endpoints WHERE id = ?1",
                        &vals![id],
                    )
                    .await?
                    .context("operation endpoint target does not exist")?;
                let revision = self
                    .backend
                    .query_opt(
                        "SELECT content_digest FROM endpoint_revisions
                         WHERE endpoint_id = ?1 AND generation = ?2",
                        &vals![id, target.generation_key],
                    )
                    .await?
                    .context("operation endpoint generation target does not exist")?;
                let digest: String = revision.get(0)?;
                if target.configuration_digest != digest {
                    bail!("operation endpoint generation digest is stale");
                }
                ("endpoint", id.clone(), row.get(0)?)
            }
            NewTopologyOperationTargetRef::Gateway(id) => {
                let row = self
                    .backend
                    .query_opt(
                        "SELECT owner_scope_key FROM gateways WHERE id = ?1",
                        &vals![id],
                    )
                    .await?
                    .context("operation gateway target does not exist")?;
                let revision = self
                    .backend
                    .query_opt(
                        "SELECT content_digest FROM gateway_revisions
                         WHERE gateway_id = ?1 AND generation = ?2",
                        &vals![id, target.generation_key],
                    )
                    .await?
                    .context("operation gateway generation target does not exist")?;
                let digest: String = revision.get(0)?;
                if target.configuration_digest != digest {
                    bail!("operation gateway generation digest is stale");
                }
                ("gateway", id.clone(), row.get(0)?)
            }
            NewTopologyOperationTargetRef::Route(id) => {
                let row = self
                    .backend
                    .query_opt(
                        "SELECT e.owner_scope_key, h.configuration_generation,
                           h.configuration_digest FROM routes r
                     JOIN endpoints e ON e.id = r.endpoint_id
                     JOIN route_heads h ON h.route_id = r.id
                     WHERE r.id = ?1",
                        &vals![id],
                    )
                    .await?
                    .context("operation route target does not exist")?;
                let generation: i64 = row.get(1)?;
                let digest: String = row.get(2)?;
                if target.generation_key != generation || target.configuration_digest != digest {
                    bail!("operation delivery-route configuration target is stale");
                }
                ("route", id.clone(), row.get(0)?)
            }
            NewTopologyOperationTargetRef::Binding(id) => {
                let row = self
                    .backend
                    .query_opt(
                        "SELECT stable_id, owner_scope_key, resource_version
                         FROM bindings WHERE id = ?1",
                        &vals![id],
                    )
                    .await?
                    .context("operation storage-binding target does not exist")?;
                let resource_version: i64 = row.get(2)?;
                if target.generation_key != resource_version
                    || !target.configuration_digest.is_empty()
                {
                    bail!("operation storage-binding target version is stale");
                }
                ("binding", row.get(0)?, row.get(1)?)
            }
        };
        Ok((target.target.clone(), kind.to_owned(), stable_id, scope))
    }

    pub(in crate::db) async fn numeric_operation_target_scope(
        &self,
        table: &str,
        stable_id: &str,
    ) -> Result<Option<String>> {
        let id = stable_id
            .parse::<i64>()
            .context("numeric operation target has a malformed identity")?;
        self.backend
            .query_opt(
                &format!(
                    "SELECT cache.scope_key FROM {table} target
                     JOIN binary_caches cache ON cache.id = target.cache_id
                     WHERE target.id = ?1"
                ),
                &vals![id],
            )
            .await?
            .map(|row| row.get(0))
            .transpose()
    }
}
