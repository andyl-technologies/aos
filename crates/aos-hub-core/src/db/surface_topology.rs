//! Surface-scoped projections for the complete delivery settings snapshot.
//!
//! Joins resolve current route heads, target names, and placement binding names
//! within SQL. No query fans out per placement, route, policy, or grant. Callers
//! retain their existing surface authorization before using these read models.

use anyhow::{Context as _, Result};

use super::*;

/// Current route configuration with the display identity of its pinned target.
pub(crate) struct SurfaceRouteProjection {
    pub route: RouteRecord,
    pub snapshot: RouteSnapshotRecord,
    pub placement_name: Option<String>,
    pub policy_name: Option<String>,
    pub policy_revision: Option<i64>,
}

/// Policy identity and the minimal public header of its current revision.
pub(crate) struct SurfacePolicyProjection {
    pub identity: PlacementPolicyIdentityRecord,
    pub kind: String,
    pub revision: i64,
    pub content_digest: String,
}

impl Database {
    /// Reads all live pins for one exact endpoint generation, grouped by consumer.
    ///
    /// # Errors
    /// Returns an error for database failure or malformed pin target versions.
    pub(crate) async fn endpoint_grant_pins_by_consumer(
        &self,
        endpoint_id: &str,
        generation: i64,
    ) -> Result<std::collections::BTreeMap<String, Vec<ConsumerScopeGrantPinRecord>>> {
        let rows = self.backend.query(
            "SELECT pin.consumer_scope_key, pin.pin_id, pin.target_kind, pin.target_stable_id,
                pin.target_generation_key, pin.target_configuration_digest,
                CASE pin.target_kind
                  WHEN 'listener' THEN (SELECT resource_version FROM endpoints WHERE id = pin.endpoint_id)
                  WHEN 'route' THEN (SELECT resource_version FROM routes WHERE id = pin.target_stable_id)
                END
             FROM endpoint_scope_grant_pins pin
             WHERE pin.endpoint_id = ?1 AND pin.endpoint_generation = ?2
             ORDER BY pin.consumer_scope_key, pin.pin_id",
            &vals![endpoint_id, generation],
        ).await?;
        let mut pins =
            std::collections::BTreeMap::<String, Vec<ConsumerScopeGrantPinRecord>>::new();
        for row in rows {
            pins.entry(row.get(0)?)
                .or_default()
                .push(ConsumerScopeGrantPinRecord {
                    pin_id: row.get(1)?,
                    target_kind: row.get(2)?,
                    target_stable_id: row.get(3)?,
                    target_generation_key: row.get(4)?,
                    target_configuration_digest: row.get(5)?,
                    target_resource_version: row.get(6)?,
                });
        }
        Ok(pins)
    }

    /// Reads placements and their binding names in one surface-scoped query.
    ///
    /// # Errors
    /// Returns an error for database failure, invalid rows, or a missing binding.
    pub(crate) async fn surface_topology_placements(
        &self,
        surface: SurfaceTarget,
    ) -> Result<Vec<(SurfacePlacementRecord, String)>> {
        let (registry, cache) = surface.ids();
        self.backend
            .query(
                &format!(
                    "SELECT {PLACEMENT_COLUMNS},
                (SELECT b.name FROM bindings b WHERE b.id = p.binding_id)
                FROM surface_placement_effective p
                WHERE p.registry_id = ?1 OR p.cache_id = ?2 ORDER BY p.read_order, p.name"
                ),
                &vals![registry, cache],
            )
            .await?
            .iter()
            .map(|row| {
                Ok((
                    row_to_surface_placement(row)?,
                    row.get::<Option<String>>(PLACEMENT_COLUMN_COUNT)?
                        .context("placement binding is missing")?,
                ))
            })
            .collect()
    }

    /// Reads route heads, exact snapshots, and pinned target names in one query.
    ///
    /// # Errors
    /// Returns an error for database failure or malformed/missing snapshots.
    pub(crate) async fn surface_topology_routes(
        &self,
        surface: SurfaceTarget,
    ) -> Result<Vec<SurfaceRouteProjection>> {
        let (registry, cache) = surface.ids();
        self.backend.query(
            "SELECT r.id, h.configuration_generation, h.configuration_digest, r.endpoint_id,
                r.endpoint_generation, r.base_path, r.registry_id, r.cache_id, r.mode, r.enabled,
                r.resource_version, r.created_at, r.updated_at,
                c.canonical_configuration_json, c.canonical_rendered_url,
                o.state, o.observed_at, o.error, p.name, policy.name, revision.revision,
                r.placement_id, r.placement_policy_revision_id
             FROM routes r JOIN route_heads h ON h.route_id = r.id
             LEFT JOIN route_configurations c ON c.route_id = h.route_id
               AND c.configuration_generation = h.configuration_generation
               AND c.configuration_digest = h.configuration_digest
             LEFT JOIN route_observations o ON o.route_id = h.route_id
               AND o.configuration_generation = h.configuration_generation
               AND o.configuration_digest = h.configuration_digest
             LEFT JOIN surface_placements p ON p.id = r.placement_id
               AND (p.registry_id = r.registry_id OR p.cache_id = r.cache_id)
             LEFT JOIN placement_policy_revisions revision ON revision.id = r.placement_policy_revision_id
               AND (revision.registry_id = r.registry_id OR revision.cache_id = r.cache_id)
             LEFT JOIN placement_policies policy ON policy.id = revision.policy_id
             WHERE r.registry_id = ?1 OR r.cache_id = ?2
             ORDER BY r.endpoint_id, r.base_path, r.id",
            &vals![registry, cache],
        ).await?.iter().map(|row| {
            let spec: RouteSpec = serde_json::from_str(&row.get::<String>(13)?)
                .context("decoding current route configuration")?;
            anyhow::ensure!(spec.placement_id == row.get::<Option<i64>>(21)?
                && spec.placement_policy_revision_id == row.get::<Option<String>>(22)?,
                "route target differs from current immutable configuration");
            Ok(SurfaceRouteProjection {
                route: topology::route_list_record(row, surface)?,
                snapshot: RouteSnapshotRecord {
                    spec, canonical_url: row.get(14)?, observation_state: row.get(15)?,
                    observed_at: row.get(16)?, observation_error: row.get(17)?,
                },
                placement_name: row.get(18)?, policy_name: row.get(19)?, policy_revision: row.get(20)?,
            })
        }).collect()
    }

    /// Reads the three supported canonical audiences in their wire order.
    ///
    /// # Errors
    /// Returns an error for database failure or invalid stored rows.
    pub(crate) async fn surface_topology_advertisements(
        &self,
        surface: SurfaceTarget,
    ) -> Result<Vec<RouteAdvertisementRecord>> {
        let (registry, cache) = surface.ids();
        self.backend
            .query(
                "SELECT audience, route_id, resource_version, created_at, updated_at
             FROM route_advertisements WHERE (registry_id = ?1 OR cache_id = ?2)
               AND audience IN ('git', 'nix_cache', 'web')
             ORDER BY CASE audience WHEN 'git' THEN 0 WHEN 'nix_cache' THEN 1 ELSE 2 END",
                &vals![registry, cache],
            )
            .await?
            .iter()
            .map(|row| {
                Ok(RouteAdvertisementRecord {
                    surface,
                    audience: row.get(0)?,
                    route_id: row.get(1)?,
                    resource_version: row.get(2)?,
                    created_at: row.get(3)?,
                    updated_at: row.get(4)?,
                })
            })
            .collect()
    }

    /// Reads policy identities and selected revision headers without fan-out.
    ///
    /// # Errors
    /// Returns an error for database failure or invalid stored rows.
    pub(crate) async fn surface_topology_policies(
        &self,
        surface: SurfaceTarget,
    ) -> Result<Vec<SurfacePolicyProjection>> {
        let (registry, cache) = surface.ids();
        self.backend
            .query(
                "SELECT p.id, p.name, p.creation_token, h.current_revision_id,
                h.resource_version, p.created_at, h.updated_at, r.kind, r.revision, r.content_digest
             FROM placement_policies p JOIN placement_policy_heads h ON h.policy_id = p.id
             LEFT JOIN placement_policy_revisions r ON r.id = h.current_revision_id
             WHERE p.registry_id = ?1 OR p.cache_id = ?2 ORDER BY p.name, p.id",
                &vals![registry, cache],
            )
            .await?
            .iter()
            .map(|row| {
                Ok(SurfacePolicyProjection {
                    identity: PlacementPolicyIdentityRecord {
                        id: row.get(0)?,
                        surface,
                        name: row.get(1)?,
                        creation_token: row.get(2)?,
                        current_revision_id: row.get(3)?,
                        resource_version: row.get(4)?,
                        created_at: row.get(5)?,
                        updated_at: row.get(6)?,
                    },
                    kind: row.get::<Option<String>>(7)?.unwrap_or_default(),
                    revision: row.get::<Option<i64>>(8)?.unwrap_or_default(),
                    content_digest: row.get::<Option<String>>(9)?.unwrap_or_default(),
                })
            })
            .collect()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    struct CountingBackend {
        inner: Box<dyn Backend>,
        queries: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl Backend for CountingBackend {
        fn dialect(&self) -> Dialect {
            self.inner.dialect()
        }
        async fn execute(&self, sql: &str, params: &[Value]) -> Result<u64> {
            self.inner.execute(sql, params).await
        }
        async fn execute_insert(&self, sql: &str, params: &[Value]) -> Result<i64> {
            self.inner.execute_insert(sql, params).await
        }
        async fn query(&self, sql: &str, params: &[Value]) -> Result<Vec<Row>> {
            self.queries.fetch_add(1, Ordering::Relaxed);
            self.inner.query(sql, params).await
        }
        async fn execute_batch(&self, sql: &str) -> Result<()> {
            self.inner.execute_batch(sql).await
        }
        async fn batch(&self, statements: &[Statement]) -> Result<()> {
            self.inner.batch(statements).await
        }
        async fn checked_batch(&self, statements: &[CheckedStatement]) -> Result<()> {
            self.inner.checked_batch(statements).await
        }
    }

    pub(crate) fn count_queries(mut db: Database) -> (Database, Arc<AtomicUsize>) {
        let queries = Arc::new(AtomicUsize::new(0));
        db.backend = Box::new(CountingBackend {
            inner: db.backend,
            queries: queries.clone(),
        });
        (db, queries)
    }

    pub(crate) async fn topology_fixture() -> (Database, SurfaceTarget) {
        let (db, registry, spec, url, key) = crate::db::topology::tests::route_fixture().await;
        let surface = SurfaceTarget::Registry(registry);
        for index in 0..8 {
            let mut desired = spec.clone();
            desired.serves_web = true;
            desired.base_path = format!("{}/route-{index}", spec.base_path);
            let route_url = format!("{url}/route-{index}");
            let endpoint = db.endpoint(&spec.endpoint_id).await.unwrap().unwrap();
            let identity = hex::decode(endpoint.endpoint_identity_digest).unwrap();
            let digest =
                Database::route_reservation_digest(&key, &identity, &desired.base_path, &route_url)
                    .unwrap();
            db.create_route(
                &format!("route:projection-{index}"),
                surface,
                &desired,
                &route_url,
                1,
                &digest,
                &[(1, digest.to_vec())],
                None,
                "test",
            )
            .await
            .unwrap();
        }
        for audience in ["git", "nix_cache", "web"] {
            db.backend
                .execute(
                    "INSERT INTO route_advertisements
                (registry_id, audience, route_id, resource_version, created_at, updated_at)
                VALUES (?1, ?2, 'route:projection-0', 1, 1, 1)",
                    &vals![registry, audience],
                )
                .await
                .unwrap();
        }
        db.create_placement_policy_identity(surface, "policy:projection", "replicas", "projection")
            .await
            .unwrap();
        let other = db
            .create_org("unrelated-topology", "Unrelated")
            .await
            .unwrap();
        db.create_managed_registry(other, "", "main", "private", &[], false)
            .await
            .unwrap();
        (db, surface)
    }

    #[tokio::test]
    async fn endpoint_grant_pin_batch_preserves_consumer_and_generation_boundaries() {
        let (db, _) = topology_fixture().await;
        let resource = GrantResource::Endpoint {
            id: "endpoint:route-probes",
            generation: 1,
        };
        let foreign = db.org_by_slug("unrelated-topology").await.unwrap().unwrap();
        db.grant_consumer_scope(
            resource,
            &foreign.stable_id,
            "explicit",
            "test",
            "projection-grant",
        )
        .await
        .unwrap();
        let expected = db.list_consumer_scope_grants(resource).await.unwrap();
        let (db, queries) = count_queries(db);
        let mut actual = db
            .endpoint_grant_pins_by_consumer("endpoint:route-probes", 1)
            .await
            .unwrap();
        assert_eq!(queries.load(Ordering::Relaxed), 1);
        assert!(actual.values().any(|pins| pins.len() >= 8));
        for grant in expected {
            assert_eq!(
                actual.remove(&grant.consumer_scope_key).unwrap_or_default(),
                db.consumer_scope_grant_pin_records(resource, &grant.consumer_scope_key)
                    .await
                    .unwrap()
            );
        }
        assert!(actual.is_empty());
        assert!(db
            .endpoint_grant_pins_by_consumer("endpoint:route-probes", 2)
            .await
            .unwrap()
            .is_empty());
        assert!(db
            .endpoint_grant_pins_by_consumer("endpoint:unrelated", 1)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn topology_batches_preserve_records_order_and_tenant_scope() {
        let (db, surface) = topology_fixture().await;
        let (db, queries) = count_queries(db);
        let routes = db.surface_topology_routes(surface).await.unwrap();
        let placements = db.surface_topology_placements(surface).await.unwrap();
        let policies = db.surface_topology_policies(surface).await.unwrap();
        let ads = db.surface_topology_advertisements(surface).await.unwrap();
        assert_eq!(queries.load(Ordering::Relaxed), 4);
        assert_eq!(routes.len(), 8);
        assert_eq!(
            routes.iter().map(|r| r.route.clone()).collect::<Vec<_>>(),
            db.list_routes(surface).await.unwrap()
        );
        for route in routes {
            assert_eq!(
                route.snapshot,
                db.route_snapshot(&route.route.id).await.unwrap().unwrap()
            );
            assert_eq!(route.placement_name.as_deref(), Some("primary"));
        }
        assert_eq!(placements.len(), 1);
        assert_eq!(
            placements[0].1,
            db.binding(placements[0].0.binding_id)
                .await
                .unwrap()
                .unwrap()
                .name
        );
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].identity.name, "replicas");
        assert_eq!(policies[0].revision, 0);
        assert_eq!(
            ads.iter()
                .map(|ad| ad.audience.as_str())
                .collect::<Vec<_>>(),
            ["git", "nix_cache", "web"]
        );
        for ad in ads {
            assert_eq!(
                ad,
                db.route_advertisement(surface, &ad.audience)
                    .await
                    .unwrap()
                    .unwrap()
            );
        }
        let other = db
            .registry_by_slug("unrelated-topology/main")
            .await
            .unwrap()
            .unwrap();
        queries.store(0, Ordering::Relaxed);
        let foreign = SurfaceTarget::Registry(other.id);
        assert!(db
            .surface_topology_routes(foreign)
            .await
            .unwrap()
            .is_empty());
        assert!(db
            .surface_topology_placements(foreign)
            .await
            .unwrap()
            .is_empty());
        assert!(db
            .surface_topology_policies(foreign)
            .await
            .unwrap()
            .is_empty());
        assert!(db
            .surface_topology_advertisements(foreign)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(queries.load(Ordering::Relaxed), 4);
    }
}
