//! Instance-owned OCI root routes and per-registry OCI namespaces.
//!
//! Standard Distribution clients always request `https://<host>/v2/<name>/...`
//! at the host root, so a registry-bound OCI route binds one hostname's whole
//! OCI surface to one registry and burns the host's permanent URL reservation
//! when that registry is deleted. An *instance OCI route* is owned by the
//! deployment instead. It sits at a host root, serves only OCI, and dispatches
//! `<name>` by the longest leading path segments that equal the slug of a
//! registry whose *OCI namespace* is enabled, so image references take the
//! `<host>/<registry-slug>/<repository>:<tag>` form. Repository names with no
//! enabled namespace prefix fall back to the route's optional default registry.
//!
//! Durable state:
//!
//! - `instance_oci_routes` holds one route per endpoint, bound to a permanent
//!   `route_url_reservations` row and to an optional default registry;
//! - `registry_oci_namespaces` holds the reviewed per-registry exposure flag.
//!
//! An enabled namespace, or a default-registry binding on an enabled instance
//! route, counts as a live OCI exposure: [`OCI_NAMESPACE_EXPOSURE_PREDICATE`]
//! makes catalog retirement and registry deletion fail closed exactly like an
//! enabled registry-bound OCI route does.

use anyhow::{bail, Context as _, Result};

use super::topology::{sha256_hex, validate_stable_id};
use super::{
    sanitize_log_text, unix_now, Database, InboundEndpointHost, NewTopologyEvent, SurfaceTarget,
};
use crate::backend::Statement;

/// SQL predicate selecting a registry `?1` that instance routes still expose.
///
/// Callers bind the registry id as parameter one. The predicate is true while
/// the registry's namespace is enabled or while an enabled instance route
/// serves the registry's repositories as its default.
pub(crate) const OCI_NAMESPACE_EXPOSURE_PREDICATE: &str = "(EXISTS (
                         SELECT 1 FROM registry_oci_namespaces namespace
                         WHERE namespace.registry_id = ?1 AND namespace.enabled = 1)
                       OR EXISTS (
                         SELECT 1 FROM instance_oci_routes instance_route
                         WHERE instance_route.default_registry_id = ?1
                           AND instance_route.enabled = 1))";

/// Readiness of an instance OCI route, derived from its endpoint alone.
///
/// The Hub serves instance routes itself, so there is no separate route or
/// access probe: the route is ready exactly when its endpoint's desired
/// generation is observed healthy with a verified boundary posture.
const INSTANCE_OCI_ROUTE_READY_SQL: &str = "CASE WHEN e.desired_generation = r.endpoint_generation
                          AND eo.observed_generation = r.endpoint_generation
                          AND eo.state = 'healthy'
                          AND eo.listener_observed = 1
                          AND (e.scheme = 'http' OR eo.tls_observed = 1)
                          AND ebrl.state = 'active'
                          AND ebo.state = 'verified'
                          AND ebo.protected_transport_observed = ebr.protected_transport_required
                          AND ebo.trusted_ingress_observed = ebr.trusted_ingress_kind
                         THEN 1 ELSE 0 END";

/// Joins shared by every instance-route projection.
const INSTANCE_OCI_ROUTE_JOINS: &str = "FROM instance_oci_routes r
             JOIN endpoints e ON e.id = r.endpoint_id
             JOIN endpoint_revisions er
               ON er.endpoint_id = r.endpoint_id
              AND er.generation = r.endpoint_generation
             LEFT JOIN network_policy_revisions ebr
               ON ebr.boundary_id = er.network_policy_id
              AND ebr.revision = er.boundary_revision
             LEFT JOIN network_policy_revision_lifecycle ebrl
               ON ebrl.boundary_id = ebr.boundary_id
              AND ebrl.revision = ebr.revision
             LEFT JOIN network_policy_observations ebo
               ON ebo.boundary_id = ebr.boundary_id
              AND ebo.revision = ebr.revision
             LEFT JOIN endpoint_observations eo ON eo.endpoint_id = e.id
             LEFT JOIN domains d ON d.id = e.domain_id
             LEFT JOIN registries reg ON reg.id = r.default_registry_id";

/// One instance-owned OCI root route with its current readiness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceOciRouteRecord {
    /// Stable public id.
    pub id: String,
    /// Exact endpoint identity.
    pub endpoint_id: String,
    /// Exact endpoint generation.
    pub endpoint_generation: i64,
    /// `hub` or `layer7`.
    pub endpoint_ingress_kind: String,
    /// Immutable canonical rendered root URL.
    pub canonical_url: String,
    /// `public` or `hub_auth`.
    pub access_policy_kind: String,
    /// Canonical access policy JSON.
    pub access_policy_json: String,
    /// Stable access policy digest.
    pub access_policy_digest: String,
    /// Registry served for repository names without an enabled namespace prefix.
    pub default_registry_id: Option<i64>,
    /// Slug of the default registry, when one is bound.
    pub default_registry_slug: Option<String>,
    /// Whether request matching may select this route.
    pub enabled: bool,
    /// Whether the endpoint chain admits Hub serving.
    pub ready: bool,
    /// Optimistic concurrency version.
    pub resource_version: i64,
    /// Creation time in Unix seconds.
    pub created_at: i64,
    /// Last desired change in Unix seconds.
    pub updated_at: i64,
}

/// Desired instance-route configuration supplied by the control plane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceOciRouteSpec {
    /// Exact endpoint identity.
    pub endpoint_id: String,
    /// Exact endpoint generation.
    pub endpoint_generation: i64,
    /// Ingress kind of that endpoint generation.
    pub endpoint_ingress_kind: String,
    /// `public` or `hub_auth`.
    pub access_policy_kind: String,
    /// Canonical access policy JSON.
    pub access_policy_json: String,
    /// Stable access policy digest.
    pub access_policy_digest: String,
    /// Registry served for unnamespaced repository names.
    pub default_registry_id: Option<i64>,
    /// Desired enabled posture.
    pub enabled: bool,
}

/// Privacy-minimized URL reservation inputs for one instance-route creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceOciRouteReservation<'a> {
    /// Active reservation key version.
    pub key_version: i64,
    /// Candidate digest under the active key.
    pub digest: &'a [u8],
    /// The same candidate under every retained key version.
    pub candidates: &'a [(i64, Vec<u8>)],
    /// Whether an equal existing reservation may be bound instead of refused.
    ///
    /// Reservations prevent one tenant from taking over another tenant's former
    /// URL. The instance is not a tenant, so an instance administrator may
    /// deliberately re-bind a host root whose reservation an earlier
    /// registry-bound route left behind.
    pub bind_existing: bool,
}

/// The instance route selected for one inbound delivery request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundInstanceOciRoute {
    /// Stable route identity.
    pub id: String,
    /// `public` or `hub_auth`.
    pub access_policy_kind: String,
    /// Registry served for unnamespaced repository names.
    pub default_registry_id: Option<i64>,
    /// Whether the endpoint chain admits Hub serving.
    pub ready: bool,
}

/// Reviewed OCI exposure state of one registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciNamespaceRecord {
    /// Registry database id.
    pub registry_id: i64,
    /// Whether instance routes serve this registry under its slug.
    pub enabled: bool,
    /// Optimistic concurrency version; zero until the row exists.
    pub resource_version: i64,
    /// Last change in Unix seconds; zero until the row exists.
    pub updated_at: i64,
}

/// One registry reachable through instance routes under its slug.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciNamespaceEntry {
    /// Registry database id.
    pub registry_id: i64,
    /// Canonical registry slug, which is also the repository-name prefix.
    pub slug: String,
}

fn instance_route_columns() -> String {
    format!(
        "r.id, r.endpoint_id, r.endpoint_generation, r.endpoint_ingress_kind,
                r.canonical_rendered_url, r.access_policy_kind, r.access_policy_json,
                r.access_policy_digest, r.default_registry_id, reg.slug, r.enabled,
                r.resource_version, r.created_at, r.updated_at,
                {INSTANCE_OCI_ROUTE_READY_SQL}"
    )
}

fn row_to_instance_route(row: &crate::value::Row) -> Result<InstanceOciRouteRecord> {
    Ok(InstanceOciRouteRecord {
        id: row.get(0)?,
        endpoint_id: row.get(1)?,
        endpoint_generation: row.get(2)?,
        endpoint_ingress_kind: row.get(3)?,
        canonical_url: row.get(4)?,
        access_policy_kind: row.get(5)?,
        access_policy_json: row.get(6)?,
        access_policy_digest: row.get(7)?,
        default_registry_id: row.get(8)?,
        default_registry_slug: row.get(9)?,
        enabled: row.get(10)?,
        resource_version: row.get(11)?,
        created_at: row.get(12)?,
        updated_at: row.get(13)?,
        ready: row.get(14)?,
    })
}

fn validate_instance_route_spec(spec: &InstanceOciRouteSpec) -> Result<()> {
    if !matches!(spec.endpoint_ingress_kind.as_str(), "hub" | "layer7") {
        bail!("an instance OCI route requires a hub or layer7 endpoint");
    }
    if !matches!(spec.access_policy_kind.as_str(), "public" | "hub_auth") {
        bail!("an instance OCI route access policy must be public or hub_auth");
    }
    let policy: serde_json::Value = serde_json::from_str(&spec.access_policy_json)
        .context("instance OCI route access policy is not valid JSON")?;
    if !policy.is_object() {
        bail!("instance OCI route access policy must be a JSON object");
    }
    if spec.access_policy_digest != sha256_hex(&spec.access_policy_json) {
        bail!("instance OCI route access-policy digest does not match its canonical JSON");
    }
    Ok(())
}

fn validate_reservation(reservation: &InstanceOciRouteReservation<'_>) -> Result<()> {
    if reservation.key_version <= 0
        || reservation.digest.len() != 32
        || reservation.candidates.is_empty()
        || reservation
            .candidates
            .iter()
            .any(|(version, digest)| *version <= 0 || digest.len() != 32)
        || !reservation.candidates.iter().any(|(version, digest)| {
            *version == reservation.key_version && digest == reservation.digest
        })
    {
        bail!("instance OCI route reservation key versions and digests are invalid");
    }
    let mut versions = std::collections::BTreeSet::new();
    if reservation
        .candidates
        .iter()
        .any(|(version, _)| !versions.insert(*version))
    {
        bail!("instance OCI route reservation candidate versions must be unique");
    }
    Ok(())
}

/// Renders `(reservation_key_version = ?n AND reservation_digest = ?n+1)` terms
/// for every candidate, appending their parameters to `params`.
fn reservation_collision_terms(
    candidates: &[(i64, Vec<u8>)],
    params: &mut Vec<crate::value::Value>,
) -> String {
    let mut terms = Vec::with_capacity(candidates.len());
    for (version, digest) in candidates {
        let version_parameter = params.len() + 1;
        params.extend(vals![version, digest]);
        terms.push(format!(
            "(reservation_key_version = ?{version_parameter} AND reservation_digest = ?{})",
            version_parameter + 1
        ));
    }
    terms.join(" OR ")
}

impl Database {
    /// Returns whether any retained-key candidate digest is already reserved.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed candidates or database failure.
    pub async fn route_url_reservation_exists(&self, candidates: &[(i64, Vec<u8>)]) -> Result<bool> {
        if candidates.is_empty()
            || candidates
                .iter()
                .any(|(version, digest)| *version <= 0 || digest.len() != 32)
        {
            bail!("route reservation candidates are invalid");
        }
        let mut params = Vec::new();
        let terms = reservation_collision_terms(candidates, &mut params);
        Ok(self
            .backend
            .query_opt(
                &format!("SELECT 1 FROM route_url_reservations WHERE {terms}"),
                &params,
            )
            .await?
            .is_some())
    }

    /// Creates an instance OCI route bound to a new or existing URL reservation.
    ///
    /// The reservation collision check and the route insert are one
    /// transaction. Without `bind_existing`, an equal reservation under any
    /// retained key refuses the creation exactly like a tenant route; with it,
    /// the route binds the oldest equal reservation instead.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid spec, a refused reservation collision, a
    /// second route on the same endpoint, a missing default registry, or
    /// database failure.
    pub async fn create_instance_oci_route(
        &self,
        id: &str,
        spec: &InstanceOciRouteSpec,
        canonical_url: &str,
        reservation: &InstanceOciRouteReservation<'_>,
    ) -> Result<InstanceOciRouteRecord> {
        validate_stable_id(id, "instance OCI route id")?;
        validate_instance_route_spec(spec)?;
        validate_reservation(reservation)?;
        let now = unix_now();
        let reservation_id = format!("reservation:{}", uuid::Uuid::new_v4().simple());

        let mut reservation_params = vals![
            reservation_id,
            reservation.key_version,
            reservation.digest.to_vec(),
            now
        ];
        let collision = reservation_collision_terms(reservation.candidates, &mut reservation_params);
        let reservation_statement = Statement::new(
            format!(
                "INSERT INTO route_url_reservations
                 (id, digest_scheme, reservation_key_version, reservation_digest, created_at)
                 SELECT ?1, 'hmac_sha256_v1', ?2, ?3, ?4
                 WHERE NOT EXISTS (SELECT 1 FROM route_url_reservations WHERE {collision})"
            ),
            reservation_params,
        );

        // Without binding, the route must reference the reservation inserted
        // above; a skipped insert then selects nothing and the checked batch
        // rolls back. With binding, the oldest equal reservation is selected.
        let mut route_params = vals![
            id,
            spec.endpoint_id,
            spec.endpoint_generation,
            spec.endpoint_ingress_kind,
            canonical_url,
            spec.access_policy_kind,
            spec.access_policy_json,
            spec.access_policy_digest,
            spec.default_registry_id,
            spec.enabled,
            now,
            reservation.bind_existing,
            reservation_id
        ];
        let collision = reservation_collision_terms(reservation.candidates, &mut route_params);
        let route_statement = Statement::new(
            format!(
                "INSERT INTO instance_oci_routes
                 (id, url_reservation_id, resource_version, endpoint_id, endpoint_generation,
                  endpoint_ingress_kind, canonical_rendered_url, access_policy_kind,
                  access_policy_json, access_policy_digest, default_registry_id, enabled,
                  created_at, updated_at)
                 SELECT ?1, reservation.id, 1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?11
                 FROM route_url_reservations reservation
                 WHERE (?12 = 1 AND ({collision}))
                    OR (?12 = 0 AND reservation.id = ?13)
                 ORDER BY reservation.created_at, reservation.id
                 LIMIT 1"
            ),
            route_params,
        );
        self.backend
            .checked_batch(&[
                reservation_statement.unchecked(),
                route_statement.expecting(1),
            ])
            .await
            .context("creating instance OCI route")?;
        self.instance_oci_route(id)
            .await?
            .context("instance OCI route vanished after creation")
    }

    /// Returns one instance OCI route by stable identity.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn instance_oci_route(&self, id: &str) -> Result<Option<InstanceOciRouteRecord>> {
        self.backend
            .query_opt(
                &format!(
                    "SELECT {} {INSTANCE_OCI_ROUTE_JOINS} WHERE r.id = ?1",
                    instance_route_columns()
                ),
                &vals![id],
            )
            .await?
            .map(|row| row_to_instance_route(&row))
            .transpose()
    }

    /// Lists every instance OCI route in stable id order.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_instance_oci_routes(&self) -> Result<Vec<InstanceOciRouteRecord>> {
        self.backend
            .query(
                &format!(
                    "SELECT {} {INSTANCE_OCI_ROUTE_JOINS} ORDER BY r.id",
                    instance_route_columns()
                ),
                &[],
            )
            .await?
            .iter()
            .map(row_to_instance_route)
            .collect()
    }

    /// Replaces the mutable configuration of one instance OCI route.
    ///
    /// The endpoint identity and canonical URL are immutable; the generation,
    /// access policy, default registry, and enabled posture may change.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid spec, a changed endpoint identity, or
    /// database failure. Returns `Ok(false)` when `expected_version` is stale.
    pub async fn update_instance_oci_route(
        &self,
        id: &str,
        spec: &InstanceOciRouteSpec,
        expected_version: i64,
    ) -> Result<bool> {
        validate_instance_route_spec(spec)?;
        let Some(current) = self.instance_oci_route(id).await? else {
            return Ok(false);
        };
        if current.endpoint_id != spec.endpoint_id {
            bail!("an instance OCI route endpoint identity is immutable");
        }
        let affected = self
            .backend
            .execute(
                "UPDATE instance_oci_routes
                 SET endpoint_generation = ?3, endpoint_ingress_kind = ?4,
                     access_policy_kind = ?5, access_policy_json = ?6,
                     access_policy_digest = ?7, default_registry_id = ?8, enabled = ?9,
                     resource_version = resource_version + 1, updated_at = ?10
                 WHERE id = ?1 AND resource_version = ?2",
                &vals![
                    id,
                    expected_version,
                    spec.endpoint_generation,
                    spec.endpoint_ingress_kind,
                    spec.access_policy_kind,
                    spec.access_policy_json,
                    spec.access_policy_digest,
                    spec.default_registry_id,
                    spec.enabled,
                    unix_now()
                ],
            )
            .await?;
        Ok(affected == 1)
    }

    /// Deletes a disabled instance OCI route, leaving its reservation in place.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure. Returns `Ok(false)` when the route
    /// is missing, enabled, or at another resource version.
    pub async fn delete_instance_oci_route(&self, id: &str, expected_version: i64) -> Result<bool> {
        let affected = self
            .backend
            .execute(
                "DELETE FROM instance_oci_routes
                 WHERE id = ?1 AND resource_version = ?2 AND enabled = 0",
                &vals![id, expected_version],
            )
            .await?;
        Ok(affected == 1)
    }

    /// Selects the enabled instance OCI route on one exact inbound endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported scheme or ingress, a malformed host,
    /// or database failure.
    pub async fn inbound_instance_oci_route(
        &self,
        host: &InboundEndpointHost,
        effective_port: u16,
        scheme: &str,
        ingress_kind: &str,
    ) -> Result<Option<InboundInstanceOciRoute>> {
        if !matches!(scheme, "http" | "https") {
            bail!("delivery request scheme must be http or https");
        }
        if !matches!(ingress_kind, "hub" | "layer7") {
            bail!("delivery request ingress must be hub or layer7");
        }
        let (host_predicate, host_value) = match host {
            InboundEndpointHost::Domain(hostname) if !hostname.is_empty() => (
                "d.hostname = ?1",
                crate::value::Value::Text(hostname.clone()),
            ),
            InboundEndpointHost::Ipv4(bytes) if bytes.len() == 4 => (
                "e.ipv4_bytes = ?1",
                crate::value::Value::Bytes(bytes.clone()),
            ),
            InboundEndpointHost::Ipv6(bytes) if bytes.len() == 16 => (
                "e.ipv6_bytes = ?1",
                crate::value::Value::Bytes(bytes.clone()),
            ),
            InboundEndpointHost::Domain(_) => bail!("delivery hostname cannot be empty"),
            InboundEndpointHost::Ipv4(_) => bail!("IPv4 endpoint identity must contain four bytes"),
            InboundEndpointHost::Ipv6(_) => {
                bail!("IPv6 endpoint identity must contain sixteen bytes")
            }
        };
        self.backend
            .query_opt(
                &format!(
                    "SELECT r.id, r.access_policy_kind, r.default_registry_id,
                            {INSTANCE_OCI_ROUTE_READY_SQL}
                     {INSTANCE_OCI_ROUTE_JOINS}
                     WHERE {host_predicate} AND e.effective_port = ?2
                       AND e.scheme = ?3 AND er.ingress_kind = ?4
                       AND r.enabled = 1
                     ORDER BY r.id"
                ),
                &vec![
                    host_value,
                    crate::value::Value::Int(i64::from(effective_port)),
                    crate::value::Value::Text(scheme.to_owned()),
                    crate::value::Value::Text(ingress_kind.to_owned()),
                ],
            )
            .await?
            .map(|row| {
                Ok(InboundInstanceOciRoute {
                    id: row.get(0)?,
                    access_policy_kind: row.get(1)?,
                    default_registry_id: row.get(2)?,
                    ready: row.get(3)?,
                })
            })
            .transpose()
    }

    /// Lists every registry whose OCI namespace is enabled, longest slug first.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn enabled_oci_namespaces(&self) -> Result<Vec<OciNamespaceEntry>> {
        self.backend
            .query(
                "SELECT reg.id, reg.slug
                 FROM registry_oci_namespaces namespace
                 JOIN registries reg ON reg.id = namespace.registry_id
                 WHERE namespace.enabled = 1
                 ORDER BY length(reg.slug) DESC, reg.slug",
                &[],
            )
            .await?
            .iter()
            .map(|row| {
                Ok(OciNamespaceEntry {
                    registry_id: row.get(0)?,
                    slug: row.get(1)?,
                })
            })
            .collect()
    }

    /// Returns one registry's OCI namespace state, disabled when unset.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn registry_oci_namespace(&self, registry_id: i64) -> Result<OciNamespaceRecord> {
        let row = self
            .backend
            .query_opt(
                "SELECT enabled, resource_version, updated_at
                 FROM registry_oci_namespaces WHERE registry_id = ?1",
                &vals![registry_id],
            )
            .await?;
        match row {
            Some(row) => Ok(OciNamespaceRecord {
                registry_id,
                enabled: row.get(0)?,
                resource_version: row.get(1)?,
                updated_at: row.get(2)?,
            }),
            None => Ok(OciNamespaceRecord {
                registry_id,
                enabled: false,
                resource_version: 0,
                updated_at: 0,
            }),
        }
    }

    /// Sets one registry's OCI namespace exposure at an exact version.
    ///
    /// Version zero creates the row. The registry row is write-locked in the
    /// same transaction so retirement, deletion, and exposure changes serialize.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing registry or database failure. Returns
    /// `Ok(false)` when `expected_version` is stale.
    pub async fn set_registry_oci_namespace(
        &self,
        registry_id: i64,
        enabled: bool,
        expected_version: i64,
    ) -> Result<bool> {
        let now = unix_now();
        let lock = Statement::new(
            "UPDATE registries SET updated_at = updated_at WHERE id = ?1",
            vals![registry_id],
        )
        .expecting(1);
        let write = if expected_version == 0 {
            Statement::new(
                "INSERT INTO registry_oci_namespaces
                 (registry_id, enabled, resource_version, created_at, updated_at)
                 SELECT ?1, ?2, 1, ?3, ?3
                 WHERE NOT EXISTS (
                   SELECT 1 FROM registry_oci_namespaces WHERE registry_id = ?1)",
                vals![registry_id, enabled, now],
            )
        } else {
            Statement::new(
                "UPDATE registry_oci_namespaces
                 SET enabled = ?2, resource_version = resource_version + 1, updated_at = ?3
                 WHERE registry_id = ?1 AND resource_version = ?4",
                vals![registry_id, enabled, now, expected_version],
            )
        };
        match self
            .backend
            .checked_batch(&[lock, write.expecting(1)])
            .await
        {
            Ok(()) => Ok(true),
            Err(error) => {
                if self.registry_by_id(registry_id).await?.is_none() {
                    bail!("registry does not exist");
                }
                let current = self.registry_oci_namespace(registry_id).await?;
                if current.resource_version != expected_version {
                    return Ok(false);
                }
                Err(error)
            }
        }
    }

    /// Converts a registry-bound root OCI route into an instance OCI route.
    ///
    /// The canonical rendered URL stays byte-identical, so the conversion is an
    /// update in RFC-0012 terms: the new instance route binds the old route's
    /// existing URL reservation. The converted registry's namespace is enabled
    /// and becomes the route's default registry, so both namespaced and legacy
    /// unnamespaced references keep resolving. The old route rows are retired
    /// in the same transaction.
    ///
    /// # Errors
    ///
    /// Returns an error when the route is not an OCI-only hub-proxy root route
    /// on a registry with a public or hub-auth policy, when its version is
    /// stale, or on database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn convert_route_to_instance_oci_route(
        &self,
        route_id: &str,
        expected_route_version: i64,
        instance_route_id: &str,
        actor_kind: &str,
        actor_id: Option<i64>,
        actor_label: &str,
    ) -> Result<InstanceOciRouteRecord> {
        validate_stable_id(instance_route_id, "instance OCI route id")?;
        let route = self
            .route(route_id)
            .await?
            .context("route does not exist")?;
        if route.resource_version != expected_route_version {
            bail!("route resource version is stale");
        }
        let SurfaceTarget::Registry(registry_id) = route.surface else {
            bail!("only a registry route can become an instance OCI route");
        };
        let snapshot = self
            .route_snapshot(route_id)
            .await?
            .context("route has no current configuration")?;
        if route.mode != "hub_proxy" || !route.base_path.is_empty() {
            bail!("only a hub-proxy route at the host root can become an instance OCI route");
        }
        if !snapshot.spec.serves_oci {
            bail!("the route does not serve OCI");
        }
        if snapshot.spec.serves_git || snapshot.spec.serves_cache || snapshot.spec.serves_web {
            bail!(
                "the route also serves git, cache, or web; create the instance OCI route \
                 binding the existing reservation and then drop oci from this route"
            );
        }
        if !matches!(snapshot.spec.access_policy_kind.as_str(), "public" | "hub_auth") {
            bail!("an instance OCI route access policy must be public or hub_auth");
        }
        let owner_scope_key: String = self
            .backend
            .query_opt(
                "SELECT owner_scope_key FROM endpoints WHERE id = ?1",
                &vals![route.endpoint_id],
            )
            .await?
            .context("route endpoint does not exist")?
            .get(0)?;

        let now = unix_now();
        let event_id = format!("topology-event:{}", uuid::Uuid::new_v4().simple());
        let payload = serde_json::to_string(&serde_json::json!({
            "type": "topology.route.converted",
            "resource_kind": "route",
            "resource_stable_id": route_id,
            "resource_version": expected_route_version,
            "instance_oci_route_id": instance_route_id,
        }))?;
        let route_scoped = |sql: &str| Statement::new(sql, vals![route_id]).unchecked();
        self.backend
            .checked_batch(&[
                // Serialize against registry deletion and retirement, which
                // take the same registry write lock.
                Statement::new(
                    "UPDATE registries SET updated_at = updated_at WHERE id = ?1",
                    vals![registry_id],
                )
                .expecting(1),
                Statement::new(
                    "UPDATE topology_operations
                     SET state = 'cancelled', started_at = COALESCE(started_at, ?3),
                         finished_at = ?3, error = 'route converted',
                         resource_version = resource_version + 1
                     WHERE operation_kind = 'route_probe'
                       AND primary_target_kind = 'route'
                       AND primary_target_stable_id = ?1
                       AND state IN ('pending', 'running')
                       AND EXISTS (SELECT 1 FROM routes r
                         WHERE r.id = ?1 AND r.resource_version = ?2)",
                    vals![route_id, expected_route_version, now],
                )
                .unchecked(),
                // Live pins and evidence must disappear before the
                // configuration identities they reference.
                route_scoped(
                    "DELETE FROM network_policy_serving_pins
                     WHERE target_kind = 'route' AND target_stable_id = ?1",
                ),
                route_scoped(
                    "DELETE FROM endpoint_scope_grant_pins
                     WHERE target_kind = 'route' AND target_stable_id = ?1",
                ),
                route_scoped(
                    "DELETE FROM gateway_scope_grant_pins
                     WHERE target_kind = 'route' AND target_stable_id = ?1",
                ),
                route_scoped("DELETE FROM direct_route_evidence WHERE route_id = ?1"),
                route_scoped("DELETE FROM route_access_observations WHERE route_id = ?1"),
                route_scoped("DELETE FROM route_observations WHERE route_id = ?1"),
                route_scoped("DELETE FROM route_heads WHERE route_id = ?1"),
                route_scoped("DELETE FROM route_configurations WHERE route_id = ?1"),
                route_scoped("DELETE FROM route_oci_capabilities WHERE route_id = ?1"),
                // The instance route inherits the exact reservation, endpoint
                // generation, access policy, and enabled posture of the route.
                Statement::new(
                    "INSERT INTO instance_oci_routes
                     (id, url_reservation_id, resource_version, endpoint_id,
                      endpoint_generation, endpoint_ingress_kind, canonical_rendered_url,
                      access_policy_kind, access_policy_json, access_policy_digest,
                      default_registry_id, enabled, created_at, updated_at)
                     SELECT ?1, r.url_reservation_id, 1, r.endpoint_id, r.endpoint_generation,
                            r.endpoint_ingress_kind, ?4, r.access_policy_kind,
                            r.access_policy_json, r.access_policy_digest, r.registry_id,
                            r.enabled, ?5, ?5
                     FROM routes r WHERE r.id = ?2 AND r.resource_version = ?3",
                    vals![
                        instance_route_id,
                        route_id,
                        expected_route_version,
                        snapshot.canonical_url,
                        now
                    ],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO registry_oci_namespaces
                     (registry_id, enabled, resource_version, created_at, updated_at)
                     SELECT ?1, 1, 1, ?2, ?2
                     WHERE NOT EXISTS (
                       SELECT 1 FROM registry_oci_namespaces WHERE registry_id = ?1)",
                    vals![registry_id, now],
                )
                .unchecked(),
                Statement::new(
                    "UPDATE registry_oci_namespaces
                     SET enabled = 1, resource_version = resource_version + 1, updated_at = ?2
                     WHERE registry_id = ?1 AND enabled = 0",
                    vals![registry_id, now],
                )
                .unchecked(),
                Statement::new(
                    "DELETE FROM routes WHERE id = ?1 AND resource_version = ?2",
                    vals![route_id, expected_route_version],
                )
                .expecting(1),
                Database::topology_event_statement(&NewTopologyEvent {
                    event_id: &event_id,
                    event_name: "topology.route.deleted",
                    owner_scope_key: &owner_scope_key,
                    resource_kind: "route",
                    resource_stable_id: route_id,
                    resource_generation_key: 0,
                    actor_kind,
                    actor_id,
                    actor_label: &sanitize_log_text(actor_label),
                    payload_json: &payload,
                    occurred_at: now,
                }),
            ])
            .await
            .context("converting route into instance OCI route")?;
        self.instance_oci_route(instance_route_id)
            .await?
            .context("instance OCI route vanished after conversion")
    }
}

#[cfg(test)]
mod tests {
    use super::super::topology::tests::route_fixture;
    use super::super::RouteSpec;
    use super::*;

    fn instance_spec(default_registry_id: Option<i64>, enabled: bool) -> InstanceOciRouteSpec {
        let access_policy_json = "{}".to_string();
        InstanceOciRouteSpec {
            endpoint_id: "endpoint:route-probes".to_string(),
            endpoint_generation: 1,
            endpoint_ingress_kind: "hub".to_string(),
            access_policy_kind: "public".to_string(),
            access_policy_digest: sha256_hex(&access_policy_json),
            access_policy_json,
            default_registry_id,
            enabled,
        }
    }

    fn reservation<'a>(
        candidates: &'a [(i64, Vec<u8>)],
        bind_existing: bool,
    ) -> InstanceOciRouteReservation<'a> {
        InstanceOciRouteReservation {
            key_version: 1,
            digest: &candidates[0].1,
            candidates,
            bind_existing,
        }
    }

    fn root_oci_spec(template: &RouteSpec) -> RouteSpec {
        RouteSpec {
            base_path: String::new(),
            serves_git: false,
            serves_cache: false,
            serves_web: false,
            serves_oci: true,
            ..template.clone()
        }
    }

    #[tokio::test]
    async fn instance_route_refuses_then_binds_an_existing_reservation() {
        let (db, registry_id, spec, _, _) = route_fixture().await;
        let root_url = "https://route-probes.example.test";
        let candidates = vec![(1_i64, vec![9_u8; 32])];
        db.create_route(
            "route:root-oci",
            SurfaceTarget::Registry(registry_id),
            &root_oci_spec(&spec),
            root_url,
            1,
            &candidates[0].1,
            &candidates,
            None,
            "test",
        )
        .await
        .unwrap();
        assert!(db.route_url_reservation_exists(&candidates).await.unwrap());

        // The ordinary tenant rule still refuses an equal reservation.
        let refused = db
            .create_instance_oci_route(
                "instance-oci:root",
                &instance_spec(None, true),
                root_url,
                &reservation(&candidates, false),
            )
            .await;
        assert!(refused.is_err());
        assert!(db.instance_oci_route("instance-oci:root").await.unwrap().is_none());

        // A reviewed binding reuses the reservation without inserting another.
        let bound = db
            .create_instance_oci_route(
                "instance-oci:root",
                &instance_spec(Some(registry_id), true),
                root_url,
                &reservation(&candidates, true),
            )
            .await
            .unwrap();
        assert_eq!(bound.canonical_url, root_url);
        assert_eq!(
            bound.default_registry_slug.as_deref(),
            Some("route-probes/route-probes")
        );
        assert!(bound.enabled);
        let reservations: i64 = db
            .backend
            .query_opt("SELECT COUNT(*) FROM route_url_reservations", &[])
            .await
            .unwrap()
            .unwrap()
            .get(0)
            .unwrap();
        assert_eq!(reservations, 1);
    }

    #[tokio::test]
    async fn fresh_instance_route_reserves_its_url_once() {
        let (db, _, _, _, _) = route_fixture().await;
        let candidates = vec![(1_i64, vec![11_u8; 32])];
        let created = db
            .create_instance_oci_route(
                "instance-oci:fresh",
                &instance_spec(None, false),
                "https://route-probes.example.test",
                &reservation(&candidates, false),
            )
            .await
            .unwrap();
        assert!(!created.enabled);
        assert_eq!(created.resource_version, 1);
        assert!(db.route_url_reservation_exists(&candidates).await.unwrap());

        // One endpoint carries at most one instance route.
        assert!(db
            .create_instance_oci_route(
                "instance-oci:second",
                &instance_spec(None, false),
                "https://route-probes.example.test",
                &reservation(&candidates, true),
            )
            .await
            .is_err());

        assert!(db
            .update_instance_oci_route("instance-oci:fresh", &instance_spec(None, true), 1)
            .await
            .unwrap());
        assert!(!db
            .update_instance_oci_route("instance-oci:fresh", &instance_spec(None, true), 1)
            .await
            .unwrap());
        let updated = db.instance_oci_route("instance-oci:fresh").await.unwrap().unwrap();
        assert!(updated.enabled);
        assert_eq!(updated.resource_version, 2);

        // Deletion requires a disabled route and keeps the reservation.
        assert!(!db.delete_instance_oci_route("instance-oci:fresh", 2).await.unwrap());
        assert!(db
            .update_instance_oci_route("instance-oci:fresh", &instance_spec(None, false), 2)
            .await
            .unwrap());
        assert!(db.delete_instance_oci_route("instance-oci:fresh", 3).await.unwrap());
        assert!(db.route_url_reservation_exists(&candidates).await.unwrap());
        assert!(db.list_instance_oci_routes().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn namespace_state_is_versioned_and_listed_longest_slug_first() {
        let (db, registry_id, _, _, _) = route_fixture().await;
        let initial = db.registry_oci_namespace(registry_id).await.unwrap();
        assert!(!initial.enabled);
        assert_eq!(initial.resource_version, 0);
        assert!(db.enabled_oci_namespaces().await.unwrap().is_empty());

        assert!(db
            .set_registry_oci_namespace(registry_id, true, 0)
            .await
            .unwrap());
        assert!(!db
            .set_registry_oci_namespace(registry_id, true, 0)
            .await
            .unwrap());
        let enabled = db.registry_oci_namespace(registry_id).await.unwrap();
        assert!(enabled.enabled);
        assert_eq!(enabled.resource_version, 1);
        assert_eq!(
            db.enabled_oci_namespaces().await.unwrap(),
            vec![OciNamespaceEntry {
                registry_id,
                slug: "route-probes/route-probes".to_string(),
            }]
        );
        assert!(db.set_registry_oci_namespace(999_999, true, 0).await.is_err());

        assert!(db
            .set_registry_oci_namespace(registry_id, false, 1)
            .await
            .unwrap());
        assert!(db.enabled_oci_namespaces().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn conversion_keeps_the_reservation_and_enables_the_namespace() {
        let (db, registry_id, spec, _, _) = route_fixture().await;
        let root_url = "https://route-probes.example.test";
        let candidates = vec![(1_i64, vec![5_u8; 32])];
        let route = db
            .create_route(
                "route:root-oci",
                SurfaceTarget::Registry(registry_id),
                &root_oci_spec(&spec),
                root_url,
                1,
                &candidates[0].1,
                &candidates,
                None,
                "test",
            )
            .await
            .unwrap();
        let reservation_id: String = db
            .backend
            .query_opt(
                "SELECT url_reservation_id FROM routes WHERE id = ?1",
                &vals![route.id],
            )
            .await
            .unwrap()
            .unwrap()
            .get(0)
            .unwrap();

        assert!(db
            .convert_route_to_instance_oci_route(
                &route.id,
                route.resource_version + 1,
                "instance-oci:converted",
                "user",
                None,
                "test",
            )
            .await
            .is_err());
        let converted = db
            .convert_route_to_instance_oci_route(
                &route.id,
                route.resource_version,
                "instance-oci:converted",
                "user",
                None,
                "test",
            )
            .await
            .unwrap();
        assert_eq!(converted.canonical_url, root_url);
        assert_eq!(converted.default_registry_id, Some(registry_id));
        assert!(converted.enabled);
        assert!(db.route(&route.id).await.unwrap().is_none());
        let bound_reservation: String = db
            .backend
            .query_opt(
                "SELECT url_reservation_id FROM instance_oci_routes WHERE id = ?1",
                &vals!["instance-oci:converted"],
            )
            .await
            .unwrap()
            .unwrap()
            .get(0)
            .unwrap();
        assert_eq!(bound_reservation, reservation_id);
        assert!(db.registry_oci_namespace(registry_id).await.unwrap().enabled);
    }

    #[tokio::test]
    async fn conversion_refuses_routes_that_serve_other_audiences() {
        let (db, registry_id, spec, _, _) = route_fixture().await;
        let mut mixed = root_oci_spec(&spec);
        mixed.serves_web = true;
        let route = db
            .create_route(
                "route:mixed",
                SurfaceTarget::Registry(registry_id),
                &mixed,
                "https://route-probes.example.test",
                1,
                &[6_u8; 32],
                &[(1, vec![6_u8; 32])],
                None,
                "test",
            )
            .await
            .unwrap();
        let error = db
            .convert_route_to_instance_oci_route(
                &route.id,
                route.resource_version,
                "instance-oci:mixed",
                "user",
                None,
                "test",
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("also serves"), "{error:#}");
        assert!(db.route(&route.id).await.unwrap().is_some());
    }
}
