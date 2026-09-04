//! Scoped delivery inventories used by settings and workflow selectors.
//!
//! These queries preserve resource ownership while exposing explicitly granted
//! resources to their consumer scope. Pagination precedes resource expansion.

use anyhow::{bail, Result};

use super::{Database, DeliveryIdentityPage, GatewayRecord, RouteRecord, SurfaceTarget};

impl Database {
    /// Lists a bounded route page for one surface in stable identity order.
    ///
    /// Callers authorize the surface before querying. The exclusive continuation
    /// cursor is a route id; full topology snapshots use `list_routes` instead.
    ///
    /// # Errors
    /// Returns an error on database failure or malformed persisted route data.
    pub async fn list_routes_page(
        &self,
        surface: SurfaceTarget,
        page_size: u32,
        after_id: &str,
    ) -> Result<DeliveryIdentityPage<RouteRecord>> {
        let (registry, cache) = surface.ids();
        let limit = i64::from(if page_size == 0 {
            50
        } else {
            page_size.min(200)
        });
        let rows = self
            .backend
            .query(
                "SELECT r.id, h.configuration_generation, h.configuration_digest,
            r.endpoint_id, r.endpoint_generation, r.base_path, r.registry_id, r.cache_id,
            r.mode, r.enabled, r.resource_version, r.created_at, r.updated_at
            FROM routes r JOIN route_heads h ON h.route_id = r.id
            WHERE (r.registry_id = ?1 OR r.cache_id = ?2) AND r.id > ?3
            ORDER BY r.id LIMIT ?4",
                &vals![registry, cache, after_id, limit + 1],
            )
            .await?;
        let mut records = rows
            .iter()
            .map(|row| super::topology::route_list_record(row, surface))
            .collect::<Result<Vec<_>>>()?;
        let next_cursor = if records.len() > limit as usize {
            records.pop();
            records.last().map(|route| route.id.clone())
        } else {
            None
        };
        Ok(DeliveryIdentityPage {
            records,
            next_cursor,
        })
    }

    /// Lists a stable page of owned gateways and optionally granted generations.
    ///
    /// A grant only exposes a gateway when it covers its current desired
    /// generation. Historical grants cannot authorize a successor generation.
    /// Callers must authorize read access to `owner_scope_key` before querying.
    ///
    /// # Errors
    ///
    /// Returns an error for a noncanonical scope, database failure, or malformed
    /// persisted gateway data.
    pub async fn list_gateways_page(
        &self,
        owner_scope_key: &str,
        page_size: u32,
        after_id: Option<&str>,
        include_granted: bool,
    ) -> Result<DeliveryIdentityPage<GatewayRecord>> {
        if !crate::domain::Scope::is_canonical(owner_scope_key) {
            bail!("scope must be an immutable instance, organization, or project scope");
        }
        let limit = i64::from(if page_size == 0 {
            50
        } else {
            page_size.min(200)
        });
        let rows = self
            .backend
            .query(
                "SELECT g.id, g.owner_scope_key, g.enabled, g.desired_generation,
                        g.observed_generation, g.reconciliation_state, g.reconciliation_error,
                        g.resource_version, g.created_at, g.updated_at
                   FROM gateways g
                  WHERE (g.owner_scope_key = ?1 OR (?4 AND EXISTS (
                      SELECT 1 FROM gateway_revision_route_scopes grant_record
                       WHERE grant_record.gateway_id = g.id
                         AND grant_record.generation = g.desired_generation
                         AND grant_record.consumer_scope_key = ?1
                         AND grant_record.state = 'active'
                  ))) AND g.id > ?2
                  ORDER BY g.id LIMIT ?3",
                &vals![
                    owner_scope_key,
                    after_id.unwrap_or(""),
                    limit + 1,
                    include_granted
                ],
            )
            .await?;
        let mut records = rows
            .iter()
            .map(|row| {
                Ok(GatewayRecord {
                    id: row.get(0)?,
                    owner_scope_key: row.get(1)?,
                    enabled: row.get(2)?,
                    desired_generation: row.get(3)?,
                    observed_generation: row.get(4)?,
                    reconciliation_state: row.get(5)?,
                    reconciliation_error: row.get(6)?,
                    resource_version: row.get(7)?,
                    created_at: row.get(8)?,
                    updated_at: row.get(9)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let next_cursor = if records.len() > limit as usize {
            records.pop();
            records.last().map(|record| record.id.clone())
        } else {
            None
        };
        Ok(DeliveryIdentityPage {
            records,
            next_cursor,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn route_pages_are_bounded_and_resume_in_stable_identity_order() {
        let (db, registry_id, mut spec, _, _) = crate::db::topology::tests::route_fixture().await;
        let surface = SurfaceTarget::Registry(registry_id);
        for (name, byte) in [("z", 3), ("a", 1), ("m", 2)] {
            spec.base_path = format!("/cache-{name}");
            let reservation = [byte; 32];
            db.create_route(
                &format!("route:{name}"),
                surface,
                &spec,
                &format!("https://route-probes.example.test/cache-{name}"),
                1,
                &reservation,
                &[(1, reservation.to_vec())],
                None,
                "test",
            )
            .await
            .unwrap();
        }
        let first = db.list_routes_page(surface, 2, "").await.unwrap();
        assert_eq!(
            first
                .records
                .iter()
                .map(|route| route.id.as_str())
                .collect::<Vec<_>>(),
            ["route:a", "route:m"]
        );
        let second = db
            .list_routes_page(surface, 2, first.next_cursor.as_deref().unwrap())
            .await
            .unwrap();
        assert_eq!(
            second
                .records
                .iter()
                .map(|route| route.id.as_str())
                .collect::<Vec<_>>(),
            ["route:z"]
        );
        assert!(second.next_cursor.is_none());
        assert!(db
            .list_routes_page(surface, 2, "route:z")
            .await
            .unwrap()
            .records
            .is_empty());
        assert!(db
            .list_routes_page(SurfaceTarget::Registry(registry_id + 1000), 2, "")
            .await
            .unwrap()
            .records
            .is_empty());
        assert_eq!(db.list_routes(surface).await.unwrap().len(), 3);
    }
}
