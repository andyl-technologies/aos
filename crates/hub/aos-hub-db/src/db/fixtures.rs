//! Explicit topology and query-counting fixtures for native contract tests.

use super::*;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

/// Builds a ready route with a retained endpoint, placement, and signing key.
///
/// # Panics
///
/// Panics if fixture database creation or any fixture mutation fails.
pub async fn route_fixture() -> (Database, i64, RouteSpec, String, [u8; 32]) {
    let db = Database::open_in_memory().await.unwrap();
    let org_id = db.create_org("route-probes", "Route probes").await.unwrap();
    let org = db.org_by_slug("route-probes").await.unwrap().unwrap();
    db.grant_consumer_scope(
        GrantResource::NetworkPolicy {
            id: "instance:public",
        },
        &org.stable_id,
        "explicit",
        "test",
        "request:route-fixture-public-boundary",
    )
    .await
    .unwrap();
    let binding_id = db
        .create_topology_binding(
            Some(org_id),
            "binding:route-probes",
            &org.stable_id,
            "route-probes",
            "r2",
            None,
            Some("route-probes"),
            Some("routes"),
            Some("https"),
            Some("dns"),
            Some(b"storage.example.invalid"),
            Some(443),
            Some("auto"),
            Some("private"),
        )
        .await
        .unwrap();
    let registry_id = db
        .create_managed_registry(org_id, "", "route-probes", "public", &[], false)
        .await
        .unwrap();
    let placement = db
        .create_surface_placement(&crate::db::NewSurfacePlacementSpec {
            surface: SurfaceTarget::Registry(registry_id),
            name: "primary".to_string(),
            binding_id: binding_id,
            prefix: "registry-route-probes".to_string(),
            kind: "complete".to_string(),
            desired_state: "active".to_string(),
            hash_range: None,
            desired_read_enabled: true,
            read_order: 0,
            requires_conditional_writes: false,
        })
        .await
        .unwrap();
    let endpoint_spec = crate::db::EndpointRevisionSpec {
            boundary_revision: 1,
            ingress_kind: "hub".to_string(),
            listener_configuration: "listener:route-probes".to_string(),
            tls_configuration: "{\"provider\":\"external\",\"certificate_ref\":\"secret:test\",\"require_client_certificate\":false}".to_string(),
            probe_configuration: "{\"provider\":\"native_file\",\"signerSecretRef\":\"test-probe-key\",\"publicKey\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}".to_string(),
        };
    let domain = db
        .create_delivery_domain(
            &org.stable_id,
            Some(org_id),
            "route-probes.example.test",
            "plan:route-probe-domain",
        )
        .await
        .unwrap();
    db.create_endpoint(
        "endpoint:route-probes",
        &org.stable_id,
        Some(org_id),
        "https",
        &crate::db::EndpointHostInput::Domain(domain.stable_id),
        443,
        "instance:public",
        &endpoint_spec,
        None,
        "test",
        "request:endpoint-route-probes",
    )
    .await
    .unwrap();
    let access_policy_json = "{}".to_string();
    let spec = RouteSpec {
        consumer_scope_key: org.stable_id,
        endpoint_id: "endpoint:route-probes".to_string(),
        endpoint_generation: 1,
        endpoint_ingress_kind: "hub".to_string(),
        base_path: "/cache".to_string(),
        mode: "hub_proxy".to_string(),
        access_policy_kind: "public".to_string(),
        access_policy_digest: sha256_hex(&access_policy_json),
        access_policy_json,
        access_boundary_id: None,
        access_boundary_revision: None,
        external_provider_kind: None,
        external_provider_resource_id: None,
        external_provider_revision: None,
        gateway_id: None,
        gateway_generation: None,
        target_binding_id: None,
        gateway_client_base_path: None,
        target_placement_prefix: None,
        placement_id: Some(placement.id),
        placement_policy_revision_id: None,
        serves_git: true,
        serves_cache: true,
        serves_web: false,
        serves_oci: false,
        enabled: true,
    };
    (
        db,
        registry_id,
        spec,
        "https://route-probes.example.test/cache".to_string(),
        [7_u8; 32],
    )
}

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

/// Wraps a database backend with an atomic read-query counter.
pub fn count_queries(mut db: Database) -> (Database, Arc<AtomicUsize>) {
    let queries = Arc::new(AtomicUsize::new(0));
    db.backend = Box::new(CountingBackend {
        inner: db.backend,
        queries: queries.clone(),
    });
    (db, queries)
}

/// Builds a multi-route topology for projection and tenant-boundary checks.
///
/// # Panics
///
/// Panics if fixture database creation or any fixture mutation fails.
pub async fn topology_fixture() -> (Database, SurfaceTarget) {
    let (db, registry, spec, url, key) = route_fixture().await;
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
