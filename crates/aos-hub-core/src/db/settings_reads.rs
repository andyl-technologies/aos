//! Scoped delivery inventories used by settings and workflow selectors.
//!
//! These queries preserve resource ownership while exposing explicitly granted
//! resources to their consumer scope. Pagination precedes resource expansion.

use anyhow::{bail, Context as _, Result};

use super::{Database, DeliveryIdentityPage, GatewayRecord, RouteRecord, SurfaceTarget};

impl Database {
    /// Lists pending/running operations whose immutable targets touch a surface.
    ///
    /// Primary and secondary targets are matched in SQL so unrelated tenants'
    /// operations never cross the Worker database bridge. Placement identities
    /// use the same surface stable-id prefix as typed operation admission.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing surface, database failure, or malformed rows.
    pub async fn list_active_surface_operations(
        &self,
        surface: SurfaceTarget,
    ) -> Result<Vec<super::TopologyOperationRecord>> {
        let (kind, stable_id) = match surface {
            SurfaceTarget::Registry(id) => (
                "registry",
                self.registry_by_id(id)
                    .await?
                    .context("registry surface does not exist")?
                    .stable_id,
            ),
            SurfaceTarget::BinaryCache(id) => (
                "binary_cache",
                self.binary_cache_by_id(id)
                    .await?
                    .context("binary-cache surface does not exist")?
                    .stable_id,
            ),
        };
        let (registry_id, cache_id) = surface.ids();
        self.backend
            .query(
                &format!(
                    "WITH surface_targets AS (
                       SELECT ?1 AS target_kind, ?2 AS stable_id
                       UNION ALL
                       SELECT 'placement', ?2 || '/placement:' || name
                         FROM surface_placements
                        WHERE registry_id = ?3 OR cache_id = ?4
                     )
                     SELECT {} FROM topology_operations o
                      WHERE o.state IN ('pending', 'running')
                        AND o.operation_id IN (
                          SELECT candidate.operation_id FROM topology_operations candidate
                          JOIN surface_targets target
                            ON target.target_kind = candidate.primary_target_kind
                           AND target.stable_id = candidate.primary_target_stable_id
                          UNION
                          SELECT secondary_target.operation_id
                            FROM operation_secondary_targets secondary_target
                          JOIN surface_targets target
                            ON target.target_kind = secondary_target.target_kind
                           AND target.stable_id = secondary_target.stable_id
                        )
                      ORDER BY o.created_at DESC, o.operation_id",
                    super::OPERATION_COLUMNS,
                ),
                &vals![kind, stable_id, registry_id, cache_id],
            )
            .await?
            .iter()
            .map(super::row_to_topology_operation)
            .collect()
    }

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
        let scope_predicate = match surface {
            SurfaceTarget::Registry(_) => "r.registry_id = ?1",
            SurfaceTarget::BinaryCache(_) => "r.cache_id = ?2",
        };
        let limit = i64::from(if page_size == 0 {
            50
        } else {
            page_size.min(200)
        });
        let rows = self
            .backend
            .query(
                &format!(
                    "SELECT r.id, h.configuration_generation, h.configuration_digest,
            r.endpoint_id, r.endpoint_generation, r.base_path, r.registry_id, r.cache_id,
            r.mode, r.enabled, r.resource_version, r.created_at, r.updated_at
            FROM routes r JOIN route_heads h ON h.route_id = r.id
            WHERE {scope_predicate} AND r.id > ?3
            ORDER BY r.id LIMIT ?4"
                ),
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
    use crate::db::{
        GrantResource, NewSurfacePlacementSpec, NewTopologyOperation, NewTopologyOperationTarget,
        NewTopologyOperationTargetRef,
    };
    use crate::domain::Permission;

    async fn operation_target(
        db: &Database,
        target: NewTopologyOperationTargetRef,
        role: &str,
    ) -> NewTopologyOperationTarget {
        let generation_key = match &target {
            NewTopologyOperationTargetRef::Placement(id) => {
                db.surface_placement(*id)
                    .await
                    .unwrap()
                    .unwrap()
                    .resource_version
            }
            _ => 0,
        };
        NewTopologyOperationTarget {
            role: role.into(),
            target,
            generation_key,
            configuration_digest: String::new(),
        }
    }

    #[tokio::test]
    async fn active_surface_operations_match_scoped_primary_and_secondary_targets() {
        let db = Database::open_in_memory().await.unwrap();
        let owner = db
            .create_org("surface-ops", "Surface operations")
            .await
            .unwrap();
        let other = db
            .create_org("other-ops", "Other operations")
            .await
            .unwrap();
        let registry = db
            .create_managed_registry(owner, "", "main", "private", &[], false)
            .await
            .unwrap();
        let cache = db
            .create_binary_cache(
                Some(owner),
                "surface-ops/cache",
                "Cache",
                "private",
                0,
                "zstd",
                false,
            )
            .await
            .unwrap();
        let unrelated = db
            .create_managed_registry(other, "", "main", "private", &[], false)
            .await
            .unwrap();
        let binding = db
            .ensure_instance_default_binding("local_fs", Some("/tmp/surface-ops-fixture"), None)
            .await
            .unwrap();
        let owner_scope = db.org_by_id(owner).await.unwrap().unwrap().stable_id;
        db.grant_consumer_scope(
            GrantResource::Binding {
                id: binding.id,
                stable_id: &binding.stable_id,
            },
            &owner_scope,
            "explicit",
            "test",
            "surface-ops-grant",
        )
        .await
        .unwrap();

        for (label, surface, target) in [
            (
                "registry",
                SurfaceTarget::Registry(registry),
                NewTopologyOperationTargetRef::Registry(registry),
            ),
            (
                "cache",
                SurfaceTarget::BinaryCache(cache),
                NewTopologyOperationTargetRef::BinaryCache(cache),
            ),
        ] {
            let placement = db
                .create_surface_placement(&NewSurfacePlacementSpec {
                    surface,
                    name: "primary".into(),
                    binding_id: binding.id,
                    prefix: format!("surface-ops/{label}"),
                    kind: "complete".into(),
                    desired_state: "active".into(),
                    hash_range: None,
                    desired_read_enabled: true,
                    read_order: 0,
                    requires_conditional_writes: false,
                })
                .await
                .unwrap();
            let placement_target = NewTopologyOperationTargetRef::Placement(placement.id);
            let foreign_target = NewTopologyOperationTargetRef::Registry(unrelated);
            for (name, primary, secondary) in [
                ("a-primary", target.clone(), None),
                ("b-placement", placement_target.clone(), None),
                (
                    "c-secondary-surface",
                    foreign_target.clone(),
                    Some(target.clone()),
                ),
                (
                    "d-secondary-placement",
                    foreign_target.clone(),
                    Some(placement_target.clone()),
                ),
                ("e-both", target.clone(), Some(placement_target)),
                ("f-newest", target.clone(), None),
                ("g-completed", target.clone(), None),
                ("h-unrelated", foreign_target, None),
            ] {
                let mut targets = vec![operation_target(&db, primary, "primary").await];
                if let Some(secondary) = secondary {
                    targets.push(operation_target(&db, secondary, "source").await);
                }
                db.create_topology_operation(&NewTopologyOperation {
                    operation_id: format!("{label}-{name}"),
                    operation_kind: "test_surface_operation".into(),
                    control_permission: Permission::Read,
                    targets,
                    detail_json: "{}".into(),
                    progress_total: None,
                })
                .await
                .unwrap();
            }
            // Stable timestamps make both ordering keys observable, while a
            // completed match verifies the inventory's active-state filter.
            db.backend
                .execute("UPDATE topology_operations SET created_at = 1", &[])
                .await
                .unwrap();
            db.backend
                .execute(
                    "UPDATE topology_operations SET created_at = 2 WHERE operation_id = ?1",
                    &vals![format!("{label}-f-newest")],
                )
                .await
                .unwrap();
            db.backend.execute("UPDATE topology_operations SET state = 'succeeded', started_at = 2, finished_at = 2 WHERE operation_id = ?1", &vals![format!("{label}-g-completed")]).await.unwrap();
            db.backend.execute("UPDATE topology_operations SET state = 'running', started_at = 2 WHERE operation_id = ?1", &vals![format!("{label}-b-placement")]).await.unwrap();
            let actual = db
                .list_active_surface_operations(surface)
                .await
                .unwrap()
                .into_iter()
                .map(|operation| operation.operation_id)
                .collect::<Vec<_>>();
            let expected = [
                "f-newest",
                "a-primary",
                "b-placement",
                "c-secondary-surface",
                "d-secondary-placement",
                "e-both",
            ]
            .map(|name| format!("{label}-{name}"));
            assert_eq!(actual, expected);
        }
        assert!(db
            .list_active_surface_operations(SurfaceTarget::Registry(i64::MAX))
            .await
            .is_err());
    }

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
