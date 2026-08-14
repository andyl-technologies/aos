//! Normalized storage and delivery topology persistence.
//!
//! This module owns the RFC-0012 resources whose identities and immutable
//! configuration generations must be shared by the native Hub and the Worker.
//! Desired configuration, controller observations, authorization grants, and
//! live grant pins are deliberately separate records.
//!
//! Route creation and update use [`Backend::batch`](crate::backend::Backend::batch)
//! so a route's current configuration pointer can never commit without its
//! immutable configuration snapshot.

use anyhow::{bail, Context, Result};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::backend::Statement;

use super::{unix_now, Database, SurfaceTarget};

type HmacSha256 = Hmac<Sha256>;

fn automatic_route_probe_operation_id(
    trigger: &str,
    route_id: &str,
    generation: i64,
    digest: &str,
) -> String {
    hex::encode(Sha256::digest(
        format!("delivery-route-auto-probe-v1\0{trigger}\0{route_id}\0{generation}\0{digest}")
            .as_bytes(),
    ))
}

/// One immutable purpose-scoped storage credential revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageCredentialRevisionRecord {
    /// Owning storage binding database id.
    pub storage_binding_id: i64,
    /// Credential purpose: read, write, delete, list, or presign.
    pub purpose: String,
    /// Monotonic purpose-local generation.
    pub generation: i64,
    /// Opaque immutable secret-store version reference.
    pub secret_version_ref: String,
    /// Validation lifecycle.
    pub validation_state: String,
    /// Terminal validation time.
    pub validated_at: Option<i64>,
    /// Redacted validation failure.
    pub validation_error: Option<String>,
    /// Non-secret fingerprint of the referenced credential.
    pub credential_fingerprint: String,
    /// Creation time in Unix seconds.
    pub created_at: i64,
}

/// A durable consumer-scope grant and its current generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumerScopeGrantRecord {
    /// Resource family owning the grant.
    pub resource_kind: String,
    /// Stable resource id.
    pub resource_stable_id: String,
    /// Exact immutable resource generation, or zero for stable resources.
    pub resource_generation: i64,
    /// Exact consuming scope.
    pub consumer_scope_key: String,
    /// Monotonic grant lifecycle generation.
    pub grant_generation: i64,
    /// Owner, instance_default, or explicit.
    pub grant_kind: String,
    /// Active or revoked.
    pub state: String,
    /// Principal that most recently granted access.
    pub granted_by: String,
    /// Grant time in Unix seconds.
    pub granted_at: i64,
    /// Principal that revoked access.
    pub revoked_by: Option<String>,
    /// Revocation time in Unix seconds.
    pub revoked_at: Option<i64>,
    /// Optimistic concurrency version.
    pub resource_version: i64,
}

/// One exact live target preventing a consumer-scope grant revocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsumerScopeGrantPinRecord {
    /// Stable or deterministically derived pin identity.
    pub pin_id: String,
    /// Closed target kind.
    pub target_kind: String,
    /// Stable target identity.
    pub target_stable_id: String,
    /// Exact immutable target generation.
    pub target_generation_key: i64,
    /// Exact immutable target configuration digest.
    pub target_configuration_digest: String,
    /// Exact target optimistic-concurrency version.
    pub target_resource_version: i64,
}

/// A grant-bearing topology resource and its authorization granularity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantResource<'a> {
    /// Stable storage binding grant.
    StorageBinding {
        /// Numeric binding id.
        id: i64,
        /// Stable public binding id used in events.
        stable_id: &'a str,
    },
    /// Stable NetworkBoundary grant.
    NetworkBoundary {
        /// Stable boundary id.
        id: &'a str,
    },
    /// Exact endpoint generation grant.
    DeliveryEndpoint {
        /// Stable endpoint id.
        id: &'a str,
        /// Exact endpoint generation.
        generation: i64,
    },
    /// Exact storage gateway generation grant.
    StorageGateway {
        /// Stable gateway id.
        id: &'a str,
        /// Exact gateway generation.
        generation: i64,
    },
}

impl GrantResource<'_> {
    fn kind(self) -> &'static str {
        match self {
            Self::StorageBinding { .. } => "storage_binding",
            Self::NetworkBoundary { .. } => "network_boundary",
            Self::DeliveryEndpoint { .. } => "delivery_endpoint",
            Self::StorageGateway { .. } => "storage_gateway",
        }
    }

    fn stable_id(self) -> String {
        match self {
            Self::StorageBinding { stable_id, .. } => stable_id.to_owned(),
            Self::NetworkBoundary { id }
            | Self::DeliveryEndpoint { id, .. }
            | Self::StorageGateway { id, .. } => id.to_owned(),
        }
    }

    fn generation(self) -> i64 {
        match self {
            Self::StorageBinding { .. } | Self::NetworkBoundary { .. } => 0,
            Self::DeliveryEndpoint { generation, .. } | Self::StorageGateway { generation, .. } => {
                generation
            }
        }
    }
}

/// One storage gateway identity and desired/observed generation pointers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageGatewayRecord {
    /// Stable public id.
    pub id: String,
    /// Exact owner scope.
    pub owner_scope_key: String,
    /// Whether new serving pins may use the gateway.
    pub enabled: bool,
    /// Desired immutable generation.
    pub desired_generation: Option<i64>,
    /// Reconciled immutable generation.
    pub observed_generation: Option<i64>,
    /// Reconciliation state.
    pub reconciliation_state: String,
    /// Reconciliation failure.
    pub reconciliation_error: Option<String>,
    /// Optimistic concurrency version.
    pub resource_version: i64,
    /// Creation time.
    pub created_at: i64,
    /// Last desired or observed change.
    pub updated_at: i64,
}

/// Closed immutable storage gateway generation input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageGatewayRevisionSpec {
    /// Storage binding database id.
    pub storage_binding_id: i64,
    /// Exact endpoint identity.
    pub endpoint_id: String,
    /// Exact endpoint generation.
    pub endpoint_generation: i64,
    /// Normalized client-visible base path.
    pub client_base_path: String,
    /// Normalized storage-origin prefix.
    pub origin_prefix: String,
    /// public, external_provider, or private_network.
    pub access_policy_kind: String,
    /// Exact private-network boundary.
    pub access_boundary_id: Option<String>,
    /// Exact private-network boundary revision.
    pub access_boundary_revision: Option<i64>,
    /// External access-provider kind.
    pub external_provider_kind: Option<String>,
    /// Stable external access-provider resource.
    pub external_provider_resource_id: Option<String>,
    /// Exact external access-provider revision.
    pub external_provider_revision: Option<String>,
    /// Canonical closed access policy JSON.
    pub access_policy_json: String,
}

/// Exact source grant sealed by a gateway-generation update plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageGatewayGrantCarryForward {
    /// Consumer scope copied into the new generation.
    pub consumer_scope_key: String,
    /// Source grant lifecycle generation.
    pub grant_generation: i64,
    /// Source grant optimistic-concurrency version.
    pub resource_version: i64,
}

/// One immutable storage-gateway generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageGatewayRevisionRecord {
    /// Stable gateway identity.
    pub gateway_id: String,
    /// Monotonic gateway-local generation.
    pub generation: i64,
    /// Exact owner scope.
    pub owner_scope_key: String,
    /// Immutable revision body.
    pub spec: StorageGatewayRevisionSpec,
    /// Endpoint ingress kind pinned by the endpoint generation.
    pub endpoint_ingress_kind: String,
    /// Stable access-policy digest.
    pub access_policy_digest: String,
    /// Digest of the complete immutable revision.
    pub content_digest: String,
    /// Creation actor.
    pub created_by: String,
    /// Creation time.
    pub created_at: i64,
}

/// One current direct route rendered through a gateway generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageGatewayRoutePreviewRecord {
    /// Current immutable canonical URL.
    pub canonical_url: String,
    /// Placement name targeted by the route.
    pub placement_name: String,
    /// Route's normalized client-visible base path.
    pub base_path: String,
}

/// One route identity and current immutable configuration pointer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryRouteRecord {
    /// Stable public id.
    pub id: String,
    /// Current configuration generation.
    pub configuration_generation: Option<i64>,
    /// Current configuration digest.
    pub configuration_digest: Option<String>,
    /// Exact endpoint identity.
    pub endpoint_id: String,
    /// Exact endpoint generation.
    pub endpoint_generation: i64,
    /// Normalized client path.
    pub base_path: String,
    /// Registry or binary-cache surface.
    pub surface: SurfaceTarget,
    /// hub_proxy, hub_redirect, or direct.
    pub mode: String,
    /// Whether request matching may select this route.
    pub enabled: bool,
    /// Optimistic concurrency version.
    pub resource_version: i64,
    /// Creation time.
    pub created_at: i64,
    /// Last desired change.
    pub updated_at: i64,
}

/// Complete current immutable route configuration and controller observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryRouteSnapshotRecord {
    /// Normalized configuration selected by the route head.
    pub spec: DeliveryRouteSpec,
    /// Immutable canonical rendered URL.
    pub canonical_url: String,
    /// Controller observation state.
    pub observation_state: String,
    /// Controller observation time.
    pub observed_at: i64,
    /// Redacted controller failure.
    pub observation_error: Option<String>,
}

/// Exact desired route snapshot consumed by an observation provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryRouteReconciliationTarget {
    /// Stable route identity.
    pub id: String,
    /// Immutable desired generation.
    pub configuration_generation: i64,
    /// Immutable desired digest.
    pub configuration_digest: String,
    /// Exact endpoint identity.
    pub endpoint_id: String,
    /// Exact endpoint generation.
    pub endpoint_generation: i64,
    /// Canonical URL to probe.
    pub canonical_url: String,
    /// `hub_proxy`, `hub_redirect`, or `direct`.
    pub mode: String,
    /// Exact access-policy digest.
    pub access_policy_digest: String,
    /// Closed access-policy kind.
    pub access_policy_kind: String,
    /// External provider kind, when configured.
    pub external_provider_kind: Option<String>,
    /// External provider resource identity, when configured.
    pub external_provider_resource_id: Option<String>,
    /// External provider revision, when configured.
    pub external_provider_revision: Option<String>,
    /// Exact current publication manifest for a direct placement.
    pub publication_manifest_id: Option<String>,
}

/// Immutable ready canonical route identity safe to carry through a plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadyCanonicalRouteIdentity {
    /// Stable route identity.
    pub route_id: String,
    /// Exact immutable configuration generation.
    pub configuration_generation: i64,
    /// Exact immutable configuration digest.
    pub configuration_digest: String,
    /// Canonical client URL rendered by that immutable configuration.
    pub canonical_url: String,
}

/// A typed request host used to resolve inbound delivery routes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundEndpointHost {
    /// Canonical DNS hostname.
    Domain(String),
    /// Canonical four-byte IPv4 address.
    Ipv4(Vec<u8>),
    /// Canonical sixteen-byte IPv6 address.
    Ipv6(Vec<u8>),
}

/// One enabled delivery route whose endpoint identity matches an HTTP request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundDeliveryRouteRecord {
    /// Stable route identity.
    pub id: String,
    /// Exact immutable configuration generation selected by the route head.
    pub configuration_generation: i64,
    /// Exact immutable configuration digest selected by the route head.
    pub configuration_digest: String,
    /// Normalized route base path.
    pub base_path: String,
    /// Registry or binary-cache target.
    pub surface: SurfaceTarget,
    /// Internal surface slug used by the common serving handlers.
    pub target_slug: String,
    /// `hub_proxy`, `hub_redirect`, or `direct`.
    pub mode: String,
    /// Access policy variant enforced at the Hub boundary.
    pub access_policy_kind: String,
    /// Exact private-network boundary, when applicable.
    pub access_boundary_id: Option<String>,
    /// Exact private-network boundary revision, when applicable.
    pub access_boundary_revision: Option<i64>,
    /// Stable external-provider kind, when applicable.
    pub external_provider_kind: Option<String>,
    /// Stable external-provider resource, when applicable.
    pub external_provider_resource_id: Option<String>,
    /// Exact external-provider revision, when applicable.
    pub external_provider_revision: Option<String>,
    /// Exact selected placement, when the route pins one.
    pub placement_id: Option<i64>,
    /// Immutable published policy revision, when the route selects a policy.
    pub placement_policy_revision_id: Option<String>,
    /// Git capability.
    pub serves_git: bool,
    /// Nix-cache capability.
    pub serves_cache: bool,
    /// Web capability.
    pub serves_web: bool,
    /// Whether endpoint, route, and access observations admit Hub serving.
    pub ready: bool,
}

/// One canonical route selection for a surface audience.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalRouteRecord {
    /// Registry or binary-cache surface.
    pub surface: SurfaceTarget,
    /// `git`, `nix_cache`, or `web`.
    pub audience: String,
    /// Stable selected delivery-route id.
    pub delivery_route_id: String,
    /// Optimistic concurrency version.
    pub resource_version: i64,
    /// Creation time.
    pub created_at: i64,
    /// Last selection change.
    pub updated_at: i64,
}

/// Complete normalized route configuration used for create/update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryRouteSpec {
    /// Exact consumer scope.
    pub consumer_scope_key: String,
    /// Exact endpoint identity.
    pub endpoint_id: String,
    /// Exact endpoint generation.
    pub endpoint_generation: i64,
    /// Endpoint ingress kind pinned by the generation.
    pub endpoint_ingress_kind: String,
    /// Normalized path.
    pub base_path: String,
    /// hub_proxy, hub_redirect, or direct.
    pub mode: String,
    /// Closed access policy kind.
    pub access_policy_kind: String,
    /// Canonical access policy JSON.
    pub access_policy_json: String,
    /// Stable access policy digest.
    pub access_policy_digest: String,
    /// Exact private-network access boundary.
    pub access_boundary_id: Option<String>,
    /// Exact private-network access boundary revision.
    pub access_boundary_revision: Option<i64>,
    /// External access provider kind.
    pub external_provider_kind: Option<String>,
    /// Stable external provider resource.
    pub external_provider_resource_id: Option<String>,
    /// Exact external provider revision.
    pub external_provider_revision: Option<String>,
    /// Direct route gateway.
    pub storage_gateway_id: Option<String>,
    /// Exact gateway generation.
    pub gateway_generation: Option<i64>,
    /// Direct target binding.
    pub target_storage_binding_id: Option<i64>,
    /// Direct gateway client base path.
    pub gateway_client_base_path: Option<String>,
    /// Direct placement prefix.
    pub target_placement_prefix: Option<String>,
    /// Pinned placement.
    pub placement_id: Option<i64>,
    /// Published placement policy revision.
    pub placement_policy_revision_id: Option<String>,
    /// Git capability.
    pub serves_git: bool,
    /// Nix-cache capability.
    pub serves_cache: bool,
    /// Web capability.
    pub serves_web: bool,
    /// Desired enabled posture.
    pub enabled: bool,
}

/// One entry in a registry's indexed, signed consumer-cache stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryCacheStackEntryRecord {
    /// Registry owning the committed stack.
    pub registry_id: i64,
    /// Stable location of the entry in the signed stack expression.
    pub stack_path: String,
    /// Exact URL committed by the registry.
    pub committed_url: String,
    /// Effective consumer priority after flattening the expression.
    pub resolved_priority: i64,
    /// Stable digest identity of the containing mirror group, when any.
    pub mirror_group_id: Option<String>,
    /// Hub-managed binary cache, or `None` for an external cache.
    pub cache_id: Option<i64>,
    /// Exact delivery route that materialized a managed-cache URL.
    pub delivery_route_id: Option<String>,
    /// Exact immutable route generation.
    pub route_configuration_generation: Option<i64>,
    /// Exact immutable route configuration digest.
    pub route_configuration_digest: Option<String>,
    /// Signed registry commit from which this projection was indexed.
    pub indexed_commit: String,
}

fn canonical_json<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).context("serializing canonical topology configuration")
}

fn sha256_hex(bytes: impl AsRef<[u8]>) -> String {
    hex::encode(Sha256::digest(bytes.as_ref()))
}

fn validate_stable_id(value: &str, field: &str) -> Result<()> {
    if value.is_empty() || value.len() > 64 {
        bail!("{field} must contain 1..=64 bytes");
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'.'))
    {
        bail!("{field} contains an unsupported character");
    }
    Ok(())
}

fn validate_scope(scope: &str) -> Result<()> {
    if crate::domain::Scope::is_canonical(scope) {
        Ok(())
    } else {
        bail!("scope must be an immutable instance, organization, or project scope")
    }
}

fn normalize_base_path(path: &str) -> Result<String> {
    if path.is_empty() || path == "/" {
        return Ok(String::new());
    }
    if !path.starts_with('/')
        || path.ends_with('/')
        || path.contains(['?', '#'])
        || path.contains("//")
    {
        bail!("base path must be empty or a normalized rooted path without a trailing slash");
    }
    if path.split('/').any(|segment| matches!(segment, "." | "..")) {
        bail!("base path must not contain dot segments");
    }
    Ok(path.to_owned())
}

fn join_route_segments(base: &str, prefix: &str) -> Result<String> {
    let base = normalize_base_path(base)?;
    let prefix = prefix.trim_matches('/');
    if prefix.is_empty() {
        return Ok(base);
    }
    normalize_base_path(&format!("{base}/{prefix}"))
}

fn validate_storage_gateway_revision_spec(spec: &StorageGatewayRevisionSpec) -> Result<()> {
    let private_shape = spec.access_boundary_id.is_some()
        && spec.access_boundary_revision.is_some()
        && spec.external_provider_kind.is_none()
        && spec.external_provider_resource_id.is_none()
        && spec.external_provider_revision.is_none();
    let external_shape = spec.access_boundary_id.is_none()
        && spec.access_boundary_revision.is_none()
        && spec.external_provider_kind.is_some()
        && spec.external_provider_resource_id.is_some()
        && spec.external_provider_revision.is_some();
    let public_shape = spec.access_boundary_id.is_none()
        && spec.access_boundary_revision.is_none()
        && spec.external_provider_kind.is_none()
        && spec.external_provider_resource_id.is_none()
        && spec.external_provider_revision.is_none();
    if !matches!(
        (
            spec.access_policy_kind.as_str(),
            private_shape,
            external_shape,
            public_shape
        ),
        ("private_network", true, false, false)
            | ("external_provider", false, true, false)
            | ("public", false, false, true)
    ) {
        bail!("storage gateway access policy has an invalid closed variant shape");
    }
    let policy: serde_json::Value = serde_json::from_str(&spec.access_policy_json)
        .context("gateway access policy is not valid JSON")?;
    if !policy.is_object() {
        bail!("gateway access policy must be a JSON object");
    }
    Ok(())
}

fn validate_delivery_route_spec(spec: &DeliveryRouteSpec) -> Result<String> {
    let base_path = normalize_base_path(&spec.base_path)?;
    if !(spec.serves_git || spec.serves_cache || spec.serves_web) {
        bail!("route must serve at least one audience");
    }
    if !matches!(spec.mode.as_str(), "hub_proxy" | "hub_redirect" | "direct") {
        bail!("invalid route mode");
    }
    let policy: serde_json::Value = serde_json::from_str(&spec.access_policy_json)
        .context("route access policy is not valid JSON")?;
    if !policy.is_object() {
        bail!("route access policy must be a JSON object");
    }
    if spec.access_policy_digest != sha256_hex(&spec.access_policy_json) {
        bail!("route access-policy digest does not match its canonical JSON");
    }
    let direct = spec.mode == "direct";
    let direct_shape = spec.storage_gateway_id.is_some()
        && spec.gateway_generation.is_some()
        && spec.target_storage_binding_id.is_some()
        && spec.gateway_client_base_path.is_some()
        && spec.target_placement_prefix.is_some()
        && spec.placement_id.is_some()
        && spec.placement_policy_revision_id.is_none();
    let hub_shape = spec.storage_gateway_id.is_none()
        && spec.gateway_generation.is_none()
        && spec.target_storage_binding_id.is_none()
        && spec.gateway_client_base_path.is_none()
        && spec.target_placement_prefix.is_none()
        && (spec.placement_id.is_some() ^ spec.placement_policy_revision_id.is_some());
    if (direct && !direct_shape) || (!direct && !hub_shape) {
        bail!("route target does not match delivery mode");
    }
    if (direct && !matches!(spec.endpoint_ingress_kind.as_str(), "external" | "layer7"))
        || (!direct && !matches!(spec.endpoint_ingress_kind.as_str(), "hub" | "layer7"))
    {
        bail!("route mode is incompatible with the endpoint ingress kind");
    }
    let private_shape = spec.access_boundary_id.is_some()
        && spec.access_boundary_revision.is_some()
        && spec.external_provider_kind.is_none()
        && spec.external_provider_resource_id.is_none()
        && spec.external_provider_revision.is_none();
    let external_shape = spec.access_boundary_id.is_none()
        && spec.access_boundary_revision.is_none()
        && spec.external_provider_kind.is_some()
        && spec.external_provider_resource_id.is_some()
        && spec.external_provider_revision.is_some();
    let simple_shape = spec.access_boundary_id.is_none()
        && spec.access_boundary_revision.is_none()
        && spec.external_provider_kind.is_none()
        && spec.external_provider_resource_id.is_none()
        && spec.external_provider_revision.is_none();
    if !matches!(
        (
            spec.access_policy_kind.as_str(),
            private_shape,
            external_shape,
            simple_shape
        ),
        ("private_network", true, false, false)
            | ("external_provider", false, true, false)
            | ("public" | "hub_auth", false, false, true)
    ) {
        bail!("route access policy has an invalid closed variant shape");
    }
    Ok(base_path)
}

impl Database {
    /// Lists every reservation-key version still referenced by a permanent URL reservation.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn route_reservation_key_versions(&self) -> Result<Vec<i64>> {
        self.backend
            .query(
                "SELECT DISTINCT reservation_key_version
                   FROM delivery_route_url_reservations
                  ORDER BY reservation_key_version",
                &[],
            )
            .await?
            .iter()
            .map(|row| row.get(0))
            .collect()
    }

    /// Lists every grant for one exact grant-bearing resource.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed stored data.
    pub async fn list_consumer_scope_grants(
        &self,
        resource: GrantResource<'_>,
    ) -> Result<Vec<ConsumerScopeGrantRecord>> {
        let (sql, params) = match resource {
            GrantResource::StorageBinding { id, .. } => (
                "SELECT consumer_scope_key FROM storage_binding_consumer_scopes
                 WHERE storage_binding_id = ?1 ORDER BY consumer_scope_key",
                vals![id],
            ),
            GrantResource::NetworkBoundary { id } => (
                "SELECT consumer_scope_key FROM network_boundary_consumer_scopes
                 WHERE boundary_id = ?1 ORDER BY consumer_scope_key",
                vals![id],
            ),
            GrantResource::DeliveryEndpoint { id, generation } => (
                "SELECT consumer_scope_key FROM delivery_endpoint_route_scopes
                 WHERE endpoint_id = ?1 AND endpoint_generation = ?2
                 ORDER BY consumer_scope_key",
                vals![id, generation],
            ),
            GrantResource::StorageGateway { id, generation } => (
                "SELECT consumer_scope_key FROM storage_gateway_revision_route_scopes
                 WHERE gateway_id = ?1 AND generation = ?2 ORDER BY consumer_scope_key",
                vals![id, generation],
            ),
        };
        let rows = self.backend.query(sql, &params).await?;
        let mut records = Vec::with_capacity(rows.len());
        for row in rows {
            let scope: String = row.get(0)?;
            records.push(
                self.load_consumer_scope_grant(resource, &scope)
                    .await?
                    .context("grant disappeared while listing")?,
            );
        }
        Ok(records)
    }

    /// Lists live pin descriptions blocking revocation of an exact grant.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn consumer_scope_grant_pin_impacts(
        &self,
        resource: GrantResource<'_>,
        consumer_scope_key: &str,
    ) -> Result<Vec<String>> {
        Ok(self
            .consumer_scope_grant_pin_records(resource, consumer_scope_key)
            .await?
            .into_iter()
            .map(|pin| {
                format!(
                    "{}:{}@{}",
                    pin.target_kind, pin.target_stable_id, pin.target_generation_key
                )
            })
            .collect())
    }

    /// Lists full exact pin identities and target CAS seals for revocation.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn consumer_scope_grant_pin_records(
        &self,
        resource: GrantResource<'_>,
        consumer_scope_key: &str,
    ) -> Result<Vec<ConsumerScopeGrantPinRecord>> {
        if let GrantResource::StorageBinding { id, .. } = resource {
            let mut records = Vec::new();
            for row in self
                .backend
                .query(
                    "SELECT id, name, write_spec_version, storage_binding_id, prefix,
                            kind, desired_state, desired_read_enabled, read_order,
                            resource_version
                       FROM surface_placements
                      WHERE storage_binding_id = ?1 AND consumer_scope_key = ?2
                        AND binding_grant_state = 'active'
                      ORDER BY id",
                    &vals![id, consumer_scope_key],
                )
                .await?
            {
                let placement_id: i64 = row.get(0)?;
                let name: String = row.get(1)?;
                let generation: i64 = row.get(2)?;
                let canonical = serde_json::to_vec(&serde_json::json!({
                    "storage_binding_id": row.get::<i64>(3)?,
                    "prefix": row.get::<String>(4)?,
                    "kind": row.get::<String>(5)?,
                    "desired_state": row.get::<String>(6)?,
                    "desired_read_enabled": row.get::<bool>(7)?,
                    "read_order": row.get::<i64>(8)?,
                }))?;
                records.push(ConsumerScopeGrantPinRecord {
                    pin_id: format!("placement-pin:{placement_id}"),
                    target_kind: "placement".to_string(),
                    target_stable_id: format!("placement:{placement_id}:{name}"),
                    target_generation_key: generation,
                    target_configuration_digest: sha256_hex(canonical),
                    target_resource_version: row.get(9)?,
                });
            }
            for row in self
                .backend
                .query(
                    "SELECT pin_id, target_kind, target_stable_id,
                            target_generation_key, target_configuration_digest,
                            resource_version
                       FROM storage_binding_scope_grant_pins
                      WHERE storage_binding_id = ?1 AND consumer_scope_key = ?2
                      ORDER BY target_kind, target_stable_id, target_generation_key",
                    &vals![id, consumer_scope_key],
                )
                .await?
            {
                records.push(ConsumerScopeGrantPinRecord {
                    pin_id: row.get(0)?,
                    target_kind: row.get(1)?,
                    target_stable_id: row.get(2)?,
                    target_generation_key: row.get(3)?,
                    target_configuration_digest: row.get(4)?,
                    target_resource_version: row.get(5)?,
                });
            }
            records.sort_by(|left, right| left.pin_id.cmp(&right.pin_id));
            return Ok(records);
        }
        let (sql, params) = match resource {
            GrantResource::StorageBinding { .. } => unreachable!("handled above"),
            GrantResource::NetworkBoundary { id } => (
                "SELECT pin.pin_id, pin.target_kind, pin.target_stable_id,
                        pin.target_generation_key, pin.target_configuration_digest,
                        CASE pin.target_kind
                          WHEN 'endpoint' THEN (SELECT resource_version
                            FROM delivery_endpoints WHERE id = pin.target_stable_id)
                          WHEN 'route' THEN (SELECT resource_version
                            FROM delivery_routes WHERE id = pin.target_stable_id)
                        END
                   FROM network_boundary_serving_pins pin
                  WHERE boundary_id = ?1 AND consumer_scope_key = ?2
                  ORDER BY pin.pin_id",
                vals![id, consumer_scope_key],
            ),
            GrantResource::DeliveryEndpoint { id, generation } => (
                "SELECT pin.pin_id, pin.target_kind, pin.target_stable_id,
                        pin.target_generation_key, pin.target_configuration_digest,
                        CASE pin.target_kind
                          WHEN 'listener' THEN (SELECT resource_version
                            FROM delivery_endpoints WHERE id = pin.endpoint_id)
                          WHEN 'route' THEN (SELECT resource_version
                            FROM delivery_routes WHERE id = pin.target_stable_id)
                        END
                   FROM delivery_endpoint_scope_grant_pins pin
                  WHERE endpoint_id = ?1 AND endpoint_generation = ?2
                    AND consumer_scope_key = ?3
                  ORDER BY pin.pin_id",
                vals![id, generation, consumer_scope_key],
            ),
            GrantResource::StorageGateway { id, generation } => (
                "SELECT pin.pin_id, pin.target_kind, pin.target_stable_id,
                        pin.target_generation_key, pin.target_configuration_digest,
                        CASE pin.target_kind
                          WHEN 'route' THEN (SELECT resource_version
                            FROM delivery_routes WHERE id = pin.target_stable_id)
                        END
                   FROM storage_gateway_scope_grant_pins pin
                  WHERE gateway_id = ?1 AND generation = ?2 AND consumer_scope_key = ?3
                  ORDER BY pin.pin_id",
                vals![id, generation, consumer_scope_key],
            ),
        };
        self.backend
            .query(sql, &params)
            .await?
            .iter()
            .map(|row| {
                Ok(ConsumerScopeGrantPinRecord {
                    pin_id: row.get(0)?,
                    target_kind: row.get(1)?,
                    target_stable_id: row.get(2)?,
                    target_generation_key: row.get(3)?,
                    target_configuration_digest: row.get(4)?,
                    target_resource_version: row.get(5)?,
                })
            })
            .collect()
    }

    /// Updates binary-cache identity fields with optimistic concurrency.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid closed vocabulary or database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_binary_cache_identity(
        &self,
        id: i64,
        expected_version: i64,
        name: &str,
        visibility: &str,
        nix_priority: i64,
        compression: &str,
        want_mass_query: bool,
    ) -> Result<bool> {
        if !matches!(visibility, "public" | "internal" | "private") {
            bail!("invalid binary-cache visibility");
        }
        if !matches!(compression, "zstd" | "xz" | "none") {
            bail!("invalid binary-cache compression");
        }
        let now = unix_now();
        Ok(self
            .backend
            .execute(
                "UPDATE binary_caches SET name = ?3, visibility = ?4, priority = ?5,
             compression = ?6, want_mass_query = ?7,
             resource_version = resource_version + 1, updated_at = ?8
             WHERE id = ?1 AND resource_version = ?2 AND deleted_at IS NULL",
                &vals![
                    id,
                    expected_version,
                    name,
                    visibility,
                    nix_priority,
                    compression,
                    want_mass_query,
                    now
                ],
            )
            .await?
            == 1)
    }

    /// Tombstones an unreferenced binary cache with optimistic concurrency.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn delete_binary_cache_identity(
        &self,
        id: i64,
        expected_version: i64,
    ) -> Result<bool> {
        let now = unix_now();
        Ok(self
            .backend
            .execute(
                "UPDATE binary_caches SET deleted_at = ?3, purge_after = ?3,
             resource_version = resource_version + 1, updated_at = ?3
             WHERE id = ?1 AND resource_version = ?2 AND deleted_at IS NULL
               AND NOT EXISTS (SELECT 1 FROM surface_placements p WHERE p.cache_id = ?1)
               AND NOT EXISTS (SELECT 1 FROM delivery_routes r WHERE r.cache_id = ?1)
               AND NOT EXISTS (SELECT 1 FROM cache_retention_subscriptions s
                 WHERE s.cache_id = ?1 AND s.retired_at IS NULL)
               AND NOT EXISTS (SELECT 1 FROM cache_population_targets t
                 WHERE t.cache_id = ?1)
               AND NOT EXISTS (SELECT 1 FROM cache_write_tickets ticket
                 WHERE ticket.cache_id = ?1 AND (ticket.active_cache_slot = 1 OR
                   (ticket.state = 'completed'
                     AND ticket.covered_inventory_generation IS NULL)))",
                &vals![id, expected_version, now],
            )
            .await?
            == 1)
    }

    /// Appends and selects a new purpose-scoped storage credential revision.
    ///
    /// The secret itself is never accepted; `secret_version_ref` names an
    /// immutable version in the deployment's sealed secret store.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid purpose, empty reference/fingerprint,
    /// unknown binding, or database failure.
    pub async fn set_storage_binding_credential(
        &self,
        storage_binding_id: i64,
        purpose: &str,
        secret_version_ref: &str,
        credential_fingerprint: &str,
        actor: &str,
    ) -> Result<StorageCredentialRevisionRecord> {
        if !matches!(purpose, "read" | "write" | "delete" | "list" | "presign") {
            bail!("invalid storage credential purpose");
        }
        if secret_version_ref.is_empty() || credential_fingerprint.is_empty() {
            bail!("credential reference and fingerprint must not be empty");
        }
        let generation: i64 = self
            .backend
            .query_opt(
                "SELECT COALESCE(MAX(generation), 0) + 1
                 FROM storage_binding_credential_revisions
                 WHERE storage_binding_id = ?1 AND purpose = ?2",
                &vals![storage_binding_id, purpose],
            )
            .await?
            .context("credential generation query returned no row")?
            .get(0)?;
        let now = unix_now();
        self.backend
            .checked_batch(&[
                Statement::new(
                    "INSERT INTO storage_binding_credential_revisions
                     (storage_binding_id, purpose, generation, secret_version_ref,
                      validation_state, credential_fingerprint, created_by, created_at)
                     SELECT ?1, ?2, ?3, ?4, 'unknown', ?5, ?6, ?7
                     WHERE EXISTS (SELECT 1 FROM storage_bindings WHERE id = ?1)",
                    vals![
                        storage_binding_id,
                        purpose,
                        generation,
                        secret_version_ref,
                        credential_fingerprint,
                        actor,
                        now
                    ],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO storage_binding_credential_heads
                     (storage_binding_id, purpose, current_generation, resource_version, updated_at)
                     VALUES (?1, ?2, ?3, 1, ?4)
                     ON CONFLICT(storage_binding_id, purpose) DO UPDATE SET
                       current_generation = excluded.current_generation,
                       resource_version = storage_binding_credential_heads.resource_version + 1,
                       updated_at = excluded.updated_at
                     WHERE NOT EXISTS (SELECT 1 FROM cache_write_tickets ticket
                       WHERE ticket.storage_binding_id = excluded.storage_binding_id
                         AND (ticket.write_credential_purpose = excluded.purpose
                           OR (excluded.purpose = 'presign'
                             AND ticket.presign_credential_generation IS NOT NULL))
                         AND (ticket.active_cache_slot = 1 OR
                           (ticket.state = 'completed'
                             AND ticket.covered_inventory_generation IS NULL)))
                       AND NOT EXISTS (SELECT 1 FROM object_deletion_jobs job
                         JOIN surface_placements placement
                           ON placement.id = job.placement_id
                         WHERE placement.storage_binding_id = excluded.storage_binding_id
                           AND excluded.purpose = 'delete' AND job.active_slot = 1)",
                    vals![storage_binding_id, purpose, generation, now],
                )
                .expecting(1),
            ])
            .await?;
        self.storage_binding_credential(storage_binding_id, purpose, generation)
            .await?
            .context("created storage credential revision disappeared")
    }

    /// Returns one immutable storage credential revision.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn storage_binding_credential(
        &self,
        storage_binding_id: i64,
        purpose: &str,
        generation: i64,
    ) -> Result<Option<StorageCredentialRevisionRecord>> {
        self.backend
            .query_opt(
                "SELECT storage_binding_id, purpose, generation, secret_version_ref,
                 validation_state, validated_at, validation_error, credential_fingerprint,
                 created_at FROM storage_binding_credential_revisions
                 WHERE storage_binding_id = ?1 AND purpose = ?2 AND generation = ?3",
                &vals![storage_binding_id, purpose, generation],
            )
            .await?
            .as_ref()
            .map(|row| {
                Ok(StorageCredentialRevisionRecord {
                    storage_binding_id: row.get(0)?,
                    purpose: row.get(1)?,
                    generation: row.get(2)?,
                    secret_version_ref: row.get(3)?,
                    validation_state: row.get(4)?,
                    validated_at: row.get(5)?,
                    validation_error: row.get(6)?,
                    credential_fingerprint: row.get(7)?,
                    created_at: row.get(8)?,
                })
            })
            .transpose()
    }

    /// Grants or regrants one exact consumer scope.
    ///
    /// Initial grant uses generation one; a regrant increments the durable
    /// generation so pins to a revoked cycle can never become usable again.
    /// Every transition appends an immutable event in the same atomic batch.
    ///
    /// # Errors
    ///
    /// Returns an error when the resource generation does not exist, the
    /// current grant is already active, or the database batch fails.
    pub async fn grant_consumer_scope(
        &self,
        resource: GrantResource<'_>,
        consumer_scope_key: &str,
        grant_kind: &str,
        actor: &str,
        request_id: &str,
    ) -> Result<ConsumerScopeGrantRecord> {
        validate_scope(consumer_scope_key)?;
        if self
            .backend
            .query_opt(
                "SELECT 1 FROM authorization_scopes a
                 LEFT JOIN orgs o ON o.id = a.org_id
                 WHERE a.scope_key = ?1
                   AND a.kind IN ('instance', 'organization', 'project')
                   AND (a.kind = 'instance' OR o.deleted_at IS NULL)",
                &vals![consumer_scope_key],
            )
            .await?
            .is_none()
        {
            bail!("consumer authorization scope does not exist or is inactive");
        }
        if !matches!(grant_kind, "owner" | "instance_default" | "explicit") {
            bail!("invalid grant kind");
        }
        let current = self
            .load_consumer_scope_grant(resource, consumer_scope_key)
            .await?;
        if current
            .as_ref()
            .is_some_and(|grant| grant.state == "active")
        {
            bail!("consumer scope is already granted");
        }
        let grant_generation = current
            .as_ref()
            .map_or(1, |grant| grant.grant_generation + 1);
        let transition = if current.is_some() {
            "regranted"
        } else {
            "granted"
        };
        let previous_state = current.as_ref().map(|grant| grant.state.clone());
        let now = unix_now();
        let event_id = format!("grant-event:{}", Uuid::new_v4().simple());
        let resource_id = resource.stable_id();
        let (mutation_sql, mutation_params) = match (resource, current.as_ref()) {
            (GrantResource::StorageBinding { id, .. }, None) => (
                "INSERT INTO storage_binding_consumer_scopes
                 (storage_binding_id, consumer_scope_key, grant_generation, grant_kind, state,
                  granted_by, granted_at, resource_version)
                 SELECT ?1, a.scope_key, 1, ?3, 'active', ?4, ?5, 1
                 FROM authorization_scopes a LEFT JOIN orgs o ON o.id = a.org_id
                 WHERE a.scope_key = ?2
                   AND a.kind IN ('instance', 'organization', 'project')
                   AND (a.kind = 'instance' OR o.deleted_at IS NULL)",
                vals![id, consumer_scope_key, grant_kind, actor, now],
            ),
            (GrantResource::StorageBinding { id, .. }, Some(grant)) => (
                "UPDATE storage_binding_consumer_scopes SET
                   grant_generation = ?3, grant_kind = ?4, state = 'active',
                   granted_by = ?5, granted_at = ?6, revoked_by = NULL, revoked_at = NULL,
                   resource_version = resource_version + 1
                 WHERE storage_binding_id = ?1 AND consumer_scope_key = ?2
                   AND grant_generation = ?7 AND resource_version = ?8 AND state = 'revoked'
                   AND EXISTS (SELECT 1 FROM authorization_scopes a LEFT JOIN orgs o ON o.id = a.org_id
                     WHERE a.scope_key = ?2
                       AND a.kind IN ('instance', 'organization', 'project')
                       AND (a.kind = 'instance' OR o.deleted_at IS NULL))",
                vals![
                    id,
                    consumer_scope_key,
                    grant_generation,
                    grant_kind,
                    actor,
                    now,
                    grant.grant_generation,
                    grant.resource_version
                ],
            ),
            (GrantResource::NetworkBoundary { id }, None) => (
                "INSERT INTO network_boundary_consumer_scopes
                 (boundary_id, consumer_scope_key, grant_generation, grant_kind, state,
                  granted_by, granted_at, resource_version)
                 SELECT ?1, a.scope_key, 1, ?3, 'active', ?4, ?5, 1
                 FROM authorization_scopes a LEFT JOIN orgs o ON o.id = a.org_id
                 WHERE a.scope_key = ?2
                   AND a.kind IN ('instance', 'organization', 'project')
                   AND (a.kind = 'instance' OR o.deleted_at IS NULL)",
                vals![id, consumer_scope_key, grant_kind, actor, now],
            ),
            (GrantResource::NetworkBoundary { id }, Some(grant)) => (
                "UPDATE network_boundary_consumer_scopes SET
                   grant_generation = ?3, grant_kind = ?4, state = 'active',
                   granted_by = ?5, granted_at = ?6, revoked_by = NULL, revoked_at = NULL,
                   resource_version = resource_version + 1
                 WHERE boundary_id = ?1 AND consumer_scope_key = ?2
                   AND grant_generation = ?7 AND resource_version = ?8 AND state = 'revoked'
                   AND EXISTS (SELECT 1 FROM authorization_scopes a LEFT JOIN orgs o ON o.id = a.org_id
                     WHERE a.scope_key = ?2
                       AND a.kind IN ('instance', 'organization', 'project')
                       AND (a.kind = 'instance' OR o.deleted_at IS NULL))",
                vals![
                    id,
                    consumer_scope_key,
                    grant_generation,
                    grant_kind,
                    actor,
                    now,
                    grant.grant_generation,
                    grant.resource_version
                ],
            ),
            (GrantResource::DeliveryEndpoint { id, generation }, None) => (
                "INSERT INTO delivery_endpoint_route_scopes
                 (endpoint_id, endpoint_generation, consumer_scope_key, grant_generation,
                  grant_kind, state, granted_by, granted_at, resource_version)
                 SELECT ?1, ?2, a.scope_key, 1, ?4, 'active', ?5, ?6, 1
                 FROM authorization_scopes a LEFT JOIN orgs o ON o.id = a.org_id
                 WHERE a.scope_key = ?3
                   AND a.kind IN ('instance', 'organization', 'project')
                   AND (a.kind = 'instance' OR o.deleted_at IS NULL)",
                vals![id, generation, consumer_scope_key, grant_kind, actor, now],
            ),
            (GrantResource::DeliveryEndpoint { id, generation }, Some(grant)) => (
                "UPDATE delivery_endpoint_route_scopes SET
                   grant_generation = ?4, grant_kind = ?5, state = 'active',
                   granted_by = ?6, granted_at = ?7, revoked_by = NULL, revoked_at = NULL,
                   resource_version = resource_version + 1
                 WHERE endpoint_id = ?1 AND endpoint_generation = ?2 AND consumer_scope_key = ?3
                   AND grant_generation = ?8 AND resource_version = ?9 AND state = 'revoked'
                   AND EXISTS (SELECT 1 FROM authorization_scopes a LEFT JOIN orgs o ON o.id = a.org_id
                     WHERE a.scope_key = ?3
                       AND a.kind IN ('instance', 'organization', 'project')
                       AND (a.kind = 'instance' OR o.deleted_at IS NULL))",
                vals![
                    id,
                    generation,
                    consumer_scope_key,
                    grant_generation,
                    grant_kind,
                    actor,
                    now,
                    grant.grant_generation,
                    grant.resource_version
                ],
            ),
            (GrantResource::StorageGateway { id, generation }, None) => (
                "INSERT INTO storage_gateway_revision_route_scopes
                 (gateway_id, generation, consumer_scope_key, grant_generation, grant_kind,
                  state, granted_by, granted_at, resource_version)
                 SELECT ?1, ?2, a.scope_key, 1, ?4, 'active', ?5, ?6, 1
                 FROM authorization_scopes a LEFT JOIN orgs o ON o.id = a.org_id
                 WHERE a.scope_key = ?3
                   AND a.kind IN ('instance', 'organization', 'project')
                   AND (a.kind = 'instance' OR o.deleted_at IS NULL)",
                vals![id, generation, consumer_scope_key, grant_kind, actor, now],
            ),
            (GrantResource::StorageGateway { id, generation }, Some(grant)) => (
                "UPDATE storage_gateway_revision_route_scopes SET
                   grant_generation = ?4, grant_kind = ?5, state = 'active',
                   granted_by = ?6, granted_at = ?7, revoked_by = NULL, revoked_at = NULL,
                   resource_version = resource_version + 1
                 WHERE gateway_id = ?1 AND generation = ?2 AND consumer_scope_key = ?3
                   AND grant_generation = ?8 AND resource_version = ?9 AND state = 'revoked'
                   AND EXISTS (SELECT 1 FROM authorization_scopes a LEFT JOIN orgs o ON o.id = a.org_id
                     WHERE a.scope_key = ?3
                       AND a.kind IN ('instance', 'organization', 'project')
                       AND (a.kind = 'instance' OR o.deleted_at IS NULL))",
                vals![
                    id,
                    generation,
                    consumer_scope_key,
                    grant_generation,
                    grant_kind,
                    actor,
                    now,
                    grant.grant_generation,
                    grant.resource_version
                ],
            ),
        };
        self.backend
            .checked_batch(&[
                Statement::new(mutation_sql, mutation_params).expecting(1),
                Statement::new(
                    "INSERT INTO consumer_scope_grant_events
                     (event_id, resource_kind, resource_stable_id, resource_generation_key,
                      consumer_scope_key, grant_generation, transition, previous_state,
                      resulting_state, actor_id, occurred_at, request_id)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'active', ?9, ?10, ?11)",
                    vals![
                        event_id,
                        resource.kind(),
                        resource_id,
                        resource.generation(),
                        consumer_scope_key,
                        grant_generation,
                        transition,
                        previous_state,
                        actor,
                        now,
                        request_id
                    ],
                )
                .expecting(1),
            ])
            .await?;
        Ok(ConsumerScopeGrantRecord {
            resource_kind: resource.kind().to_owned(),
            resource_stable_id: resource.stable_id(),
            resource_generation: resource.generation(),
            consumer_scope_key: consumer_scope_key.to_owned(),
            grant_generation,
            grant_kind: grant_kind.to_owned(),
            state: "active".to_owned(),
            granted_by: actor.to_owned(),
            granted_at: now,
            revoked_by: None,
            revoked_at: None,
            resource_version: current
                .as_ref()
                .map_or(1, |grant| grant.resource_version + 1),
        })
    }

    /// Revokes one exact grant generation only when it has no live pins.
    ///
    /// The durable row remains as a tombstone, and the transition event is
    /// appended atomically. A concurrent pin acquisition and revoke therefore
    /// have one winner through the active-generation foreign key/CAS.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing/stale grant, any live pin, or database failure.
    pub async fn revoke_consumer_scope(
        &self,
        resource: GrantResource<'_>,
        consumer_scope_key: &str,
        expected_version: i64,
        actor: &str,
        request_id: &str,
    ) -> Result<ConsumerScopeGrantRecord> {
        let current = self
            .load_consumer_scope_grant(resource, consumer_scope_key)
            .await?
            .context("consumer-scope grant does not exist")?;
        if current.state != "active" || current.resource_version != expected_version {
            bail!("consumer-scope grant is revoked or stale");
        }
        let event_id = format!("grant-event:{}", Uuid::new_v4().simple());
        let now = unix_now();
        let (update_sql, params) = match resource {
            GrantResource::StorageBinding { id, .. } => (
                "UPDATE storage_binding_consumer_scopes SET state = 'revoked', revoked_by = ?4,
                 revoked_at = ?5, resource_version = resource_version + 1
                 WHERE storage_binding_id = ?1 AND consumer_scope_key = ?2
                   AND resource_version = ?3 AND state = 'active'
                   AND NOT EXISTS (SELECT 1 FROM storage_binding_scope_grant_pins
                     WHERE storage_binding_id = ?1 AND consumer_scope_key = ?2
                       AND grant_generation = ?6)
                   AND NOT EXISTS (SELECT 1 FROM surface_placements
                     WHERE storage_binding_id = ?1 AND consumer_scope_key = ?2
                       AND binding_grant_generation = ?6
                       AND binding_grant_state = 'active')",
                vals![id, consumer_scope_key, expected_version, actor, now, current.grant_generation],
            ),
            GrantResource::NetworkBoundary { id } => (
                "UPDATE network_boundary_consumer_scopes SET state = 'revoked', revoked_by = ?4,
                 revoked_at = ?5, resource_version = resource_version + 1
                 WHERE boundary_id = ?1 AND consumer_scope_key = ?2
                   AND resource_version = ?3 AND state = 'active'
                   AND NOT EXISTS (SELECT 1 FROM network_boundary_serving_pins
                     WHERE boundary_id = ?1 AND consumer_scope_key = ?2
                       AND grant_generation = ?6)",
                vals![id, consumer_scope_key, expected_version, actor, now, current.grant_generation],
            ),
            GrantResource::DeliveryEndpoint { id, generation } => (
                "UPDATE delivery_endpoint_route_scopes SET state = 'revoked', revoked_by = ?5,
                 revoked_at = ?6, resource_version = resource_version + 1
                 WHERE endpoint_id = ?1 AND endpoint_generation = ?2 AND consumer_scope_key = ?3
                   AND resource_version = ?4 AND state = 'active'
                   AND NOT EXISTS (SELECT 1 FROM delivery_endpoint_scope_grant_pins
                     WHERE endpoint_id = ?1 AND endpoint_generation = ?2
                       AND consumer_scope_key = ?3 AND grant_generation = ?7)",
                vals![id, generation, consumer_scope_key, expected_version, actor, now, current.grant_generation],
            ),
            GrantResource::StorageGateway { id, generation } => (
                "UPDATE storage_gateway_revision_route_scopes SET state = 'revoked', revoked_by = ?5,
                 revoked_at = ?6, resource_version = resource_version + 1
                 WHERE gateway_id = ?1 AND generation = ?2 AND consumer_scope_key = ?3
                   AND resource_version = ?4 AND state = 'active'
                   AND NOT EXISTS (SELECT 1 FROM storage_gateway_scope_grant_pins
                     WHERE gateway_id = ?1 AND generation = ?2
                       AND consumer_scope_key = ?3 AND grant_generation = ?7)",
                vals![id, generation, consumer_scope_key, expected_version, actor, now, current.grant_generation],
            ),
        };
        self.backend
            .checked_batch(&[
                Statement::new(update_sql, params).expecting(1),
                Statement::new(
                    "INSERT INTO consumer_scope_grant_events
                     (event_id, resource_kind, resource_stable_id, resource_generation_key,
                      consumer_scope_key, grant_generation, transition, previous_state,
                      resulting_state, actor_id, occurred_at, request_id)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'revoked', 'active', 'revoked', ?7, ?8, ?9)",
                    vals![
                        event_id,
                        resource.kind(),
                        resource.stable_id(),
                        resource.generation(),
                        consumer_scope_key,
                        current.grant_generation,
                        actor,
                        now,
                        request_id
                    ],
                )
                .expecting(1),
            ])
            .await?;
        Ok(ConsumerScopeGrantRecord {
            state: "revoked".to_owned(),
            revoked_by: Some(actor.to_owned()),
            revoked_at: Some(now),
            resource_version: expected_version + 1,
            ..current
        })
    }

    pub(crate) async fn load_consumer_scope_grant(
        &self,
        resource: GrantResource<'_>,
        consumer_scope_key: &str,
    ) -> Result<Option<ConsumerScopeGrantRecord>> {
        let (sql, params) = match resource {
            GrantResource::StorageBinding { id, .. } => (
                "SELECT grant_generation, grant_kind, state, granted_by, granted_at,
                 revoked_by, revoked_at, resource_version FROM storage_binding_consumer_scopes
                 WHERE storage_binding_id = ?1 AND consumer_scope_key = ?2",
                vals![id, consumer_scope_key],
            ),
            GrantResource::NetworkBoundary { id } => (
                "SELECT grant_generation, grant_kind, state, granted_by, granted_at,
                 revoked_by, revoked_at, resource_version FROM network_boundary_consumer_scopes
                 WHERE boundary_id = ?1 AND consumer_scope_key = ?2",
                vals![id, consumer_scope_key],
            ),
            GrantResource::DeliveryEndpoint { id, generation } => (
                "SELECT grant_generation, grant_kind, state, granted_by, granted_at,
                 revoked_by, revoked_at, resource_version FROM delivery_endpoint_route_scopes
                 WHERE endpoint_id = ?1 AND endpoint_generation = ?2 AND consumer_scope_key = ?3",
                vals![id, generation, consumer_scope_key],
            ),
            GrantResource::StorageGateway { id, generation } => (
                "SELECT grant_generation, grant_kind, state, granted_by, granted_at,
                 revoked_by, revoked_at, resource_version FROM storage_gateway_revision_route_scopes
                 WHERE gateway_id = ?1 AND generation = ?2 AND consumer_scope_key = ?3",
                vals![id, generation, consumer_scope_key],
            ),
        };
        self.backend
            .query_opt(sql, &params)
            .await?
            .as_ref()
            .map(|row| {
                Ok(ConsumerScopeGrantRecord {
                    resource_kind: resource.kind().to_owned(),
                    resource_stable_id: resource.stable_id(),
                    resource_generation: resource.generation(),
                    consumer_scope_key: consumer_scope_key.to_owned(),
                    grant_generation: row.get(0)?,
                    grant_kind: row.get(1)?,
                    state: row.get(2)?,
                    granted_by: row.get(3)?,
                    granted_at: row.get(4)?,
                    revoked_by: row.get(5)?,
                    revoked_at: row.get(6)?,
                    resource_version: row.get(7)?,
                })
            })
            .transpose()
    }

    /// Creates a storage gateway and immutable generation one.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid closed policy/path fields, missing exact
    /// grants, a path reservation collision, or database failure.
    pub async fn create_storage_gateway(
        &self,
        id: &str,
        owner_scope_key: &str,
        org_id: Option<i64>,
        spec: &StorageGatewayRevisionSpec,
        actor: &str,
    ) -> Result<StorageGatewayRecord> {
        validate_stable_id(id, "gateway id")?;
        validate_scope(owner_scope_key)?;
        let client_base_path = normalize_base_path(&spec.client_base_path)?;
        let origin_prefix = normalize_base_path(&spec.origin_prefix)?;
        validate_storage_gateway_revision_spec(spec)?;
        let access_policy_digest = sha256_hex(&spec.access_policy_json);
        let canonical = canonical_json(spec)?;
        let content_digest = sha256_hex(&canonical);
        let reservation_id = format!("gateway-path:{}", Uuid::new_v4().simple());
        let now = unix_now();
        let topology_event_id = format!("topology-event:{}", Uuid::new_v4().simple());
        let topology_event_payload = serde_json::to_string(&serde_json::json!({
            "type": "topology.storage_gateway.created",
            "resource_kind": "storage_gateway",
            "resource_stable_id": id,
            "resource_generation": 1,
            "resource_version": 1,
        }))?;
        self.backend
            .batch(&[
                Statement::new(
                    "INSERT INTO storage_gateways (id, org_id, owner_scope_key, enabled,
                 reconciliation_state, created_at, updated_at)
                 VALUES (?1, ?2, ?3, 0, 'pending', ?4, ?4)",
                    vals![id, org_id, owner_scope_key, now],
                ),
                Statement::new(
                    "INSERT INTO storage_gateway_path_reservations
                 (reservation_id, gateway_id, endpoint_id, client_base_path, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                    vals![reservation_id, id, spec.endpoint_id, client_base_path, now],
                ),
                Statement::new(
                    "INSERT INTO storage_gateway_revisions (gateway_id, generation, org_id,
                 owner_scope_key, path_reservation_id, storage_binding_id, endpoint_id,
                 endpoint_generation, endpoint_ingress_kind, client_base_path, origin_prefix,
                 access_policy_kind, access_boundary_id, access_boundary_revision,
                 external_provider_kind, external_provider_resource_id,
                 external_provider_revision,
                 access_policy_json, access_policy_digest, content_digest, created_by, created_at)
                 SELECT ?1, 1, ?2, ?3, ?4, ?5, ?6, ?7, er.ingress_kind, ?8, ?9,
                   ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20
                 FROM delivery_endpoint_revisions er
                 WHERE er.endpoint_id = ?6 AND er.generation = ?7
                   AND er.ingress_kind IN ('external', 'layer7')
                   AND EXISTS (SELECT 1 FROM storage_binding_consumer_scopes
                     WHERE storage_binding_id = ?5 AND consumer_scope_key = ?3 AND state = 'active')
                   AND EXISTS (SELECT 1 FROM delivery_endpoint_route_scopes
                     WHERE endpoint_id = ?6 AND endpoint_generation = ?7
                       AND consumer_scope_key = ?3 AND state = 'active')",
                    vals![
                        id,
                        org_id,
                        owner_scope_key,
                        reservation_id,
                        spec.storage_binding_id,
                        spec.endpoint_id,
                        spec.endpoint_generation,
                        client_base_path,
                        origin_prefix,
                        spec.access_policy_kind,
                        spec.access_boundary_id,
                        spec.access_boundary_revision,
                        spec.external_provider_kind,
                        spec.external_provider_resource_id,
                        spec.external_provider_revision,
                        spec.access_policy_json,
                        access_policy_digest,
                        content_digest,
                        actor,
                        now
                    ],
                ),
                Statement::new(
                    "UPDATE storage_gateways SET desired_generation = 1 WHERE id = ?1",
                    vals![id],
                ),
                Statement::new(
                    "INSERT INTO storage_gateway_revision_route_scopes
                 (gateway_id, generation, consumer_scope_key, grant_generation, grant_kind,
                  state, granted_by, granted_at, resource_version)
                 SELECT ?1, 1, ?2, 1, 'owner', 'active', ?3, ?4, 1
                 WHERE EXISTS (SELECT 1 FROM storage_gateway_revisions
                   WHERE gateway_id = ?1 AND generation = 1)",
                    vals![id, owner_scope_key, actor, now],
                ),
                Statement::new(
                    "INSERT INTO storage_gateway_revision_events
                     (event_id, gateway_id, generation, gateway_resource_version,
                      transition, actor_id, occurred_at)
                     VALUES (?1, ?2, 1, 1, 'desired', ?3, ?4)",
                    vals![
                        format!("gateway-revision:{}", Uuid::new_v4().simple()),
                        id,
                        actor,
                        now
                    ],
                ),
                Database::topology_event_insert_statement(&crate::db::NewTopologyEvent {
                    event_id: &topology_event_id,
                    event_name: "topology.storage_gateway.created",
                    owner_scope_key,
                    resource_kind: "storage_gateway",
                    resource_stable_id: id,
                    resource_generation_key: 1,
                    actor_kind: "key",
                    actor_id: None,
                    actor_label: actor,
                    payload_json: &topology_event_payload,
                    occurred_at: now,
                }),
            ])
            .await?;
        self.storage_gateway(id)
            .await?
            .context("created gateway disappeared")
    }

    /// Returns a storage gateway identity and its desired/observed pointers.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn storage_gateway(&self, id: &str) -> Result<Option<StorageGatewayRecord>> {
        self.backend
            .query_opt(
                "SELECT id, owner_scope_key, enabled, desired_generation, observed_generation,
             reconciliation_state, reconciliation_error, resource_version, created_at, updated_at
             FROM storage_gateways WHERE id = ?1",
                &vals![id],
            )
            .await?
            .as_ref()
            .map(|row| {
                Ok(StorageGatewayRecord {
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
            .transpose()
    }

    /// Lists storage gateways, optionally restricted to one storage binding.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn list_storage_gateways(
        &self,
        storage_binding_id: Option<i64>,
    ) -> Result<Vec<StorageGatewayRecord>> {
        let rows = if let Some(storage_binding_id) = storage_binding_id {
            self.backend
                .query(
                    "SELECT g.id, g.owner_scope_key, g.enabled, g.desired_generation,
                     g.observed_generation, g.reconciliation_state, g.reconciliation_error,
                     g.resource_version, g.created_at, g.updated_at
                     FROM storage_gateways g JOIN storage_gateway_revisions r
                       ON r.gateway_id = g.id AND r.generation = g.desired_generation
                     WHERE r.storage_binding_id = ?1 ORDER BY g.id",
                    &vals![storage_binding_id],
                )
                .await?
        } else {
            self.backend
                .query(
                    "SELECT id, owner_scope_key, enabled, desired_generation,
                     observed_generation, reconciliation_state, reconciliation_error,
                     resource_version, created_at, updated_at
                     FROM storage_gateways ORDER BY id",
                    &[],
                )
                .await?
        };
        rows.iter()
            .map(|row| {
                Ok(StorageGatewayRecord {
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
            .collect()
    }

    /// Enables or disables a storage gateway under optimistic concurrency.
    ///
    /// Enabling requires the desired generation to be reconciled and ready.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale version, unreconciled enable, missing
    /// gateway, or database failure.
    pub async fn set_storage_gateway_enabled(
        &self,
        id: &str,
        enabled: bool,
        expected_resource_version: i64,
        actor_kind: &str,
        actor_id: Option<i64>,
        actor_label: &str,
    ) -> Result<StorageGatewayRecord> {
        let gateway = self
            .storage_gateway(id)
            .await?
            .context("storage gateway does not exist")?;
        let now = unix_now();
        let event_id = format!("topology-event:{}", Uuid::new_v4().simple());
        let event_name = if enabled {
            "topology.storage_gateway.enabled"
        } else {
            "topology.storage_gateway.disabled"
        };
        let payload = serde_json::to_string(&serde_json::json!({
            "type": event_name,
            "resource_kind": "storage_gateway",
            "resource_stable_id": id,
            "resource_generation": gateway.desired_generation.unwrap_or_default(),
            "resource_version": expected_resource_version + 1,
        }))?;
        self.backend
            .checked_batch(&[
                Statement::new(
                    "UPDATE storage_gateways SET enabled = ?2,
                 resource_version = resource_version + 1, updated_at = ?3
                 WHERE id = ?1 AND resource_version = ?4
                   AND (?2 = 0 OR (desired_generation = observed_generation
                     AND reconciliation_state = 'ready'))",
                    vals![id, enabled, now, expected_resource_version],
                )
                .expecting(1),
                Database::topology_event_statement(&crate::db::NewTopologyEvent {
                    event_id: &event_id,
                    event_name,
                    owner_scope_key: &gateway.owner_scope_key,
                    resource_kind: "storage_gateway",
                    resource_stable_id: id,
                    resource_generation_key: gateway.desired_generation.unwrap_or_default(),
                    actor_kind,
                    actor_id,
                    actor_label,
                    payload_json: &payload,
                    occurred_at: now,
                }),
            ])
            .await?;
        self.storage_gateway(id)
            .await?
            .context("updated storage gateway disappeared")
    }

    /// Deletes a disabled, unreferenced storage gateway under CAS.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn delete_storage_gateway(
        &self,
        id: &str,
        expected_resource_version: i64,
        actor_kind: &str,
        actor_id: Option<i64>,
        actor_label: &str,
    ) -> Result<bool> {
        let gateway = self
            .storage_gateway(id)
            .await?
            .context("storage gateway does not exist")?;
        let now = unix_now();
        let event_id = format!("topology-event:{}", Uuid::new_v4().simple());
        let payload = serde_json::to_string(&serde_json::json!({
            "type": "topology.storage_gateway.deleted",
            "resource_kind": "storage_gateway",
            "resource_stable_id": id,
            "resource_generation": gateway.desired_generation.unwrap_or_default(),
            "resource_version": expected_resource_version,
        }))?;
        self.backend
            .checked_batch(&[
                Statement::new(
                    "DELETE FROM storage_gateways WHERE id = ?1 AND resource_version = ?2
                 AND enabled = 0
                 AND NOT EXISTS (SELECT 1 FROM delivery_routes
                   WHERE storage_gateway_id = ?1)
                 AND NOT EXISTS (SELECT 1 FROM topology_defaults
                   WHERE storage_gateway_id = ?1)
                 AND NOT EXISTS (SELECT 1 FROM topology_operations o
                   WHERE o.state IN ('pending', 'running') AND (
                     (o.primary_target_kind = 'storage_gateway'
                       AND o.primary_target_stable_id = ?1)
                     OR EXISTS (SELECT 1 FROM operation_secondary_targets t
                       WHERE t.operation_id = o.operation_id
                         AND t.target_kind = 'storage_gateway' AND t.stable_id = ?1)))",
                    vals![id, expected_resource_version],
                )
                .expecting(1),
                Database::topology_event_statement(&crate::db::NewTopologyEvent {
                    event_id: &event_id,
                    event_name: "topology.storage_gateway.deleted",
                    owner_scope_key: &gateway.owner_scope_key,
                    resource_kind: "storage_gateway",
                    resource_stable_id: id,
                    resource_generation_key: gateway.desired_generation.unwrap_or_default(),
                    actor_kind,
                    actor_id,
                    actor_label,
                    payload_json: &payload,
                    occurred_at: now,
                }),
            ])
            .await?;
        Ok(self.storage_gateway(id).await?.is_none())
    }

    /// Returns one immutable storage-gateway generation.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn storage_gateway_revision(
        &self,
        gateway_id: &str,
        generation: i64,
    ) -> Result<Option<StorageGatewayRevisionRecord>> {
        self.backend
            .query_opt(
                "SELECT gateway_id, generation, owner_scope_key, storage_binding_id,
                 endpoint_id, endpoint_generation, endpoint_ingress_kind,
                 client_base_path, origin_prefix, access_policy_kind,
                 access_boundary_id, access_boundary_revision, external_provider_kind,
                 external_provider_resource_id, external_provider_revision,
                 access_policy_json, access_policy_digest, content_digest,
                 created_by, created_at
                 FROM storage_gateway_revisions
                 WHERE gateway_id = ?1 AND generation = ?2",
                &vals![gateway_id, generation],
            )
            .await?
            .map(|row| {
                Ok(StorageGatewayRevisionRecord {
                    gateway_id: row.get(0)?,
                    generation: row.get(1)?,
                    owner_scope_key: row.get(2)?,
                    spec: StorageGatewayRevisionSpec {
                        storage_binding_id: row.get(3)?,
                        endpoint_id: row.get(4)?,
                        endpoint_generation: row.get(5)?,
                        client_base_path: row.get(7)?,
                        origin_prefix: row.get(8)?,
                        access_policy_kind: row.get(9)?,
                        access_boundary_id: row.get(10)?,
                        access_boundary_revision: row.get(11)?,
                        external_provider_kind: row.get(12)?,
                        external_provider_resource_id: row.get(13)?,
                        external_provider_revision: row.get(14)?,
                        access_policy_json: row.get(15)?,
                    },
                    endpoint_ingress_kind: row.get(6)?,
                    access_policy_digest: row.get(16)?,
                    content_digest: row.get(17)?,
                    created_by: row.get(18)?,
                    created_at: row.get(19)?,
                })
            })
            .transpose()
    }

    /// Creates and selects the next immutable gateway generation under CAS.
    ///
    /// Existing routes remain pinned to their reviewed older generation. The
    /// controller reconciles the new desired generation independently.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid closed revision, stale gateway version,
    /// missing exact grants, path collision, or database failure.
    pub async fn revise_storage_gateway(
        &self,
        gateway_id: &str,
        spec: &StorageGatewayRevisionSpec,
        owner_grant: &StorageGatewayGrantCarryForward,
        carry_forward_grants: &[StorageGatewayGrantCarryForward],
        expected_resource_version: i64,
        actor: &str,
        request_id: &str,
    ) -> Result<StorageGatewayRecord> {
        validate_storage_gateway_revision_spec(spec)?;
        let gateway = self
            .storage_gateway(gateway_id)
            .await?
            .context("storage gateway does not exist")?;
        if gateway.resource_version != expected_resource_version {
            bail!("storage gateway resource version is stale");
        }
        let previous = gateway
            .desired_generation
            .context("storage gateway has no desired generation")?;
        let generation = previous + 1;
        if owner_grant.consumer_scope_key != gateway.owner_scope_key
            || owner_grant.grant_generation <= 0
            || owner_grant.resource_version <= 0
        {
            bail!("plan-sealed storage gateway owner grant is invalid");
        }
        let mut carried_scopes = std::collections::BTreeSet::new();
        for grant in carry_forward_grants {
            validate_scope(&grant.consumer_scope_key)?;
            if grant.consumer_scope_key == gateway.owner_scope_key {
                bail!("the owner grant is carried automatically");
            }
            if grant.grant_generation <= 0 || grant.resource_version <= 0 {
                bail!("carried gateway grant versions must be positive");
            }
            if !carried_scopes.insert(grant.consumer_scope_key.clone()) {
                bail!("duplicate carried gateway consumer scope");
            }
        }
        let client_base_path = normalize_base_path(&spec.client_base_path)?;
        let origin_prefix = normalize_base_path(&spec.origin_prefix)?;
        let access_policy_digest = sha256_hex(&spec.access_policy_json);
        let content_digest = sha256_hex(&canonical_json(spec)?);
        let reservation_id = format!("gateway-path:{}", Uuid::new_v4().simple());
        let event_id = format!("gateway-revision:{}", Uuid::new_v4().simple());
        let next_resource_version = expected_resource_version + 1;
        let now = unix_now();
        let mut statements = vec![
            Statement::new(
                "INSERT INTO storage_gateway_path_reservations
                     (reservation_id, gateway_id, endpoint_id, client_base_path, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                vals![
                    reservation_id,
                    gateway_id,
                    spec.endpoint_id,
                    client_base_path,
                    now
                ],
            )
            .unchecked(),
            Statement::new(
                "INSERT INTO storage_gateway_revisions (gateway_id, generation, org_id,
                     owner_scope_key, path_reservation_id, storage_binding_id, endpoint_id,
                     endpoint_generation, endpoint_ingress_kind, client_base_path, origin_prefix,
                     access_policy_kind, access_boundary_id, access_boundary_revision,
                     external_provider_kind, external_provider_resource_id,
                     external_provider_revision, access_policy_json, access_policy_digest,
                     content_digest, created_by, created_at)
                     SELECT g.id, ?2, g.org_id, g.owner_scope_key, ?3, ?4, ?5, ?6,
                            er.ingress_kind, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                            ?15, ?16, ?17, ?18, ?19
                     FROM storage_gateways g JOIN delivery_endpoint_revisions er
                       ON er.endpoint_id = ?5 AND er.generation = ?6
                     WHERE g.id = ?1 AND g.resource_version = ?20
                       AND er.ingress_kind IN ('external', 'layer7')
                       AND EXISTS (SELECT 1 FROM storage_binding_consumer_scopes s
                         WHERE s.storage_binding_id = ?4
                           AND s.consumer_scope_key = g.owner_scope_key AND s.state = 'active')
                       AND EXISTS (SELECT 1 FROM delivery_endpoint_route_scopes s
                         WHERE s.endpoint_id = ?5 AND s.endpoint_generation = ?6
                           AND s.consumer_scope_key = g.owner_scope_key AND s.state = 'active')",
                vals![
                    gateway_id,
                    generation,
                    reservation_id,
                    spec.storage_binding_id,
                    spec.endpoint_id,
                    spec.endpoint_generation,
                    client_base_path,
                    origin_prefix,
                    spec.access_policy_kind,
                    spec.access_boundary_id,
                    spec.access_boundary_revision,
                    spec.external_provider_kind,
                    spec.external_provider_resource_id,
                    spec.external_provider_revision,
                    spec.access_policy_json,
                    access_policy_digest,
                    content_digest,
                    actor,
                    now,
                    expected_resource_version
                ],
            )
            .unchecked(),
            Statement::new(
                "UPDATE storage_gateways SET desired_generation = ?2,
                     reconciliation_state = 'pending', reconciliation_error = NULL,
                     resource_version = resource_version + 1, updated_at = ?3
                     WHERE id = ?1 AND resource_version = ?4 AND EXISTS (
                       SELECT 1 FROM storage_gateway_revisions
                       WHERE gateway_id = ?1 AND generation = ?2)",
                vals![gateway_id, generation, now, expected_resource_version],
            )
            .unchecked(),
            Statement::new(
                "INSERT INTO storage_gateway_revision_route_scopes
                     (gateway_id, generation, consumer_scope_key, grant_generation,
                      grant_kind, state, granted_by, granted_at, resource_version)
                     SELECT ?1, ?2, consumer_scope_key, 1, 'owner', 'active', ?4, ?5, 1
                     FROM storage_gateway_revision_route_scopes
                     WHERE gateway_id = ?1 AND generation = ?3
                       AND consumer_scope_key = ?6 AND grant_kind = 'owner' AND state = 'active'
                       AND grant_generation = ?7 AND resource_version = ?8
                       AND EXISTS (SELECT 1 FROM storage_gateways
                         WHERE id = ?1 AND desired_generation = ?2
                           AND resource_version = ?9)",
                vals![
                    gateway_id,
                    generation,
                    previous,
                    actor,
                    now,
                    gateway.owner_scope_key,
                    owner_grant.grant_generation,
                    owner_grant.resource_version,
                    next_resource_version
                ],
            )
            .expecting(1),
            Statement::new(
                "INSERT INTO consumer_scope_grant_events
                     (event_id, resource_kind, resource_stable_id, resource_generation_key,
                      consumer_scope_key, grant_generation, transition, previous_state,
                      resulting_state, actor_id, occurred_at, request_id)
                     VALUES (?1, 'storage_gateway', ?2, ?3, ?4, 1, 'granted', NULL,
                       'active', ?5, ?6, ?7)",
                vals![
                    format!("grant-event:{}", Uuid::new_v4().simple()),
                    gateway_id,
                    generation,
                    gateway.owner_scope_key,
                    actor,
                    now,
                    request_id
                ],
            )
            .expecting(1),
            Statement::new(
                "INSERT INTO storage_gateway_revision_events
                     (event_id, gateway_id, generation, gateway_resource_version,
                      transition, actor_id, occurred_at)
                     VALUES (?1, ?2, ?3, ?4, 'desired', ?5, ?6)",
                vals![
                    event_id,
                    gateway_id,
                    generation,
                    next_resource_version,
                    actor,
                    now
                ],
            )
            .unchecked(),
        ];
        for grant in carry_forward_grants {
            statements.push(
                Statement::new(
                    "INSERT INTO storage_gateway_revision_route_scopes
                     (gateway_id, generation, consumer_scope_key, grant_generation,
                      grant_kind, state, granted_by, granted_at, resource_version)
                     SELECT ?1, ?2, consumer_scope_key, 1, grant_kind, 'active', ?4, ?5, 1
                     FROM storage_gateway_revision_route_scopes
                     WHERE gateway_id = ?1 AND generation = ?3
                       AND consumer_scope_key = ?6 AND grant_kind = 'explicit'
                       AND state = 'active' AND grant_generation = ?7
                       AND resource_version = ?8
                       AND EXISTS (SELECT 1 FROM storage_gateways
                         WHERE id = ?1 AND desired_generation = ?2
                           AND resource_version = ?9)",
                    vals![
                        gateway_id,
                        generation,
                        previous,
                        actor,
                        now,
                        grant.consumer_scope_key,
                        grant.grant_generation,
                        grant.resource_version,
                        next_resource_version
                    ],
                )
                .expecting(1),
            );
            statements.push(
                Statement::new(
                    "INSERT INTO consumer_scope_grant_events
                     (event_id, resource_kind, resource_stable_id, resource_generation_key,
                      consumer_scope_key, grant_generation, transition, previous_state,
                      resulting_state, actor_id, occurred_at, request_id)
                     VALUES (?1, 'storage_gateway', ?2, ?3, ?4, 1, 'granted', NULL,
                       'active', ?5, ?6, ?7)",
                    vals![
                        format!("grant-event:{}", Uuid::new_v4().simple()),
                        gateway_id,
                        generation,
                        grant.consumer_scope_key,
                        actor,
                        now,
                        request_id
                    ],
                )
                .expecting(1),
            );
        }
        let topology_event_id = format!("topology-event:{}", Uuid::new_v4().simple());
        let topology_event_payload = serde_json::to_string(&serde_json::json!({
            "type": "topology.storage_gateway.revised",
            "resource_kind": "storage_gateway",
            "resource_stable_id": gateway_id,
            "resource_generation": generation,
            "resource_version": next_resource_version,
        }))?;
        statements.push(Database::topology_event_statement(
            &crate::db::NewTopologyEvent {
                event_id: &topology_event_id,
                event_name: "topology.storage_gateway.revised",
                owner_scope_key: &gateway.owner_scope_key,
                resource_kind: "storage_gateway",
                resource_stable_id: gateway_id,
                resource_generation_key: generation,
                actor_kind: "key",
                actor_id: None,
                actor_label: actor,
                payload_json: &topology_event_payload,
                occurred_at: now,
            },
        ));
        self.backend.checked_batch(&statements).await?;
        self.storage_gateway(gateway_id)
            .await?
            .context("revised storage gateway disappeared")
    }

    /// Records controller reconciliation for the exact desired generation.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid state, stale gateway version/generation,
    /// missing generation, or database failure.
    pub async fn observe_storage_gateway(
        &self,
        gateway_id: &str,
        generation: i64,
        state: &str,
        error: Option<&str>,
        expected_resource_version: i64,
    ) -> Result<StorageGatewayRecord> {
        if !matches!(state, "ready" | "failed") || (state == "ready" && error.is_some()) {
            bail!("gateway observation must be ready without error or failed");
        }
        let affected = self
            .storage_gateway(gateway_id)
            .await?
            .context("storage gateway does not exist")?;
        let now = unix_now();
        let event_id = format!("topology-event:{}", Uuid::new_v4().simple());
        let payload = serde_json::to_string(&serde_json::json!({
            "type": "topology.storage_gateway.reconciled",
            "resource_kind": "storage_gateway",
            "resource_stable_id": gateway_id,
            "resource_generation": generation,
            "resource_version": expected_resource_version + 1,
            "state": state,
        }))?;
        self.backend
            .checked_batch(&[
                Statement::new(
                    "UPDATE storage_gateways SET observed_generation = ?2,
                 reconciliation_state = ?3, reconciliation_error = ?4,
                 resource_version = resource_version + 1, updated_at = ?5
                 WHERE id = ?1 AND desired_generation = ?2 AND resource_version = ?6
                   AND EXISTS (SELECT 1 FROM storage_gateway_revisions
                     WHERE gateway_id = ?1 AND generation = ?2)",
                    vals![
                        gateway_id,
                        generation,
                        state,
                        error,
                        now,
                        expected_resource_version
                    ],
                )
                .expecting(1),
                Database::topology_event_statement(&crate::db::NewTopologyEvent {
                    event_id: &event_id,
                    event_name: "topology.storage_gateway.reconciled",
                    owner_scope_key: &affected.owner_scope_key,
                    resource_kind: "storage_gateway",
                    resource_stable_id: gateway_id,
                    resource_generation_key: generation,
                    actor_kind: "system",
                    actor_id: None,
                    actor_label: "storage-gateway-controller",
                    payload_json: &payload,
                    occurred_at: now,
                }),
            ])
            .await?;
        self.storage_gateway(gateway_id)
            .await?
            .context("observed storage gateway disappeared")
    }

    /// Lists current direct routes pinned to one exact gateway generation.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn storage_gateway_route_preview(
        &self,
        gateway_id: &str,
        generation: i64,
    ) -> Result<Vec<StorageGatewayRoutePreviewRecord>> {
        self.backend
            .query(
                "SELECT c.canonical_rendered_url, p.name, r.base_path
                   FROM delivery_routes r
                   JOIN delivery_route_heads h ON h.delivery_route_id = r.id
                   JOIN delivery_route_configurations c
                     ON c.delivery_route_id = h.delivery_route_id
                    AND c.configuration_generation = h.configuration_generation
                    AND c.configuration_digest = h.configuration_digest
                   JOIN surface_placements p ON p.id = r.placement_id
                  WHERE r.storage_gateway_id = ?1 AND r.gateway_generation = ?2
                  ORDER BY c.canonical_rendered_url, r.id",
                &vals![gateway_id, generation],
            )
            .await?
            .iter()
            .map(|row| {
                Ok(StorageGatewayRoutePreviewRecord {
                    canonical_url: row.get(0)?,
                    placement_name: row.get(1)?,
                    base_path: row.get(2)?,
                })
            })
            .collect()
    }

    /// Resolves every enabled route bound to one exact typed endpoint host.
    ///
    /// Results are ordered by descending base-path length so callers can apply
    /// segment-boundary matching and select the most specific route. Direct
    /// routes are returned even though Hub must answer them with `421`; this is
    /// what distinguishes a misdirected direct-route request from an unknown
    /// hostname. Hub routes carry a separate readiness bit derived from exact
    /// endpoint, route, and access observations.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid typed host/port or database failure.
    pub async fn inbound_delivery_routes(
        &self,
        host: &InboundEndpointHost,
        effective_port: u16,
        scheme: &str,
        ingress_kind: &str,
    ) -> Result<Vec<InboundDeliveryRouteRecord>> {
        if !matches!(scheme, "http" | "https") {
            bail!("delivery request scheme must be http or https");
        }
        if !matches!(ingress_kind, "hub" | "layer7") {
            bail!("delivery request ingress must be hub or layer7");
        }
        let (host_predicate, host_value) = match host {
            InboundEndpointHost::Domain(hostname) => {
                if hostname.is_empty() {
                    bail!("delivery hostname cannot be empty");
                }
                (
                    "d.hostname = ?1",
                    crate::value::Value::Text(hostname.clone()),
                )
            }
            InboundEndpointHost::Ipv4(bytes) => {
                if bytes.len() != 4 {
                    bail!("IPv4 endpoint identity must contain four bytes");
                }
                (
                    "e.ipv4_bytes = ?1",
                    crate::value::Value::Bytes(bytes.clone()),
                )
            }
            InboundEndpointHost::Ipv6(bytes) => {
                if bytes.len() != 16 {
                    bail!("IPv6 endpoint identity must contain sixteen bytes");
                }
                (
                    "e.ipv6_bytes = ?1",
                    crate::value::Value::Bytes(bytes.clone()),
                )
            }
        };
        let sql = format!(
            "SELECT r.id, r.base_path, r.registry_id, r.cache_id,
                    COALESCE(reg.slug, cache.slug), r.mode,
                    r.access_policy_kind, r.access_boundary_id,
                    r.access_boundary_revision, r.external_provider_kind,
                    r.external_provider_resource_id, r.external_provider_revision,
                    r.placement_id, r.placement_policy_revision_id,
                    r.serves_git, r.serves_cache, r.serves_web,
                    h.configuration_generation, h.configuration_digest,
                    CASE WHEN e.desired_generation = r.endpoint_generation
                          AND eo.observed_generation = r.endpoint_generation
                          AND eo.state = 'healthy'
                          AND eo.listener_observed = 1
                          AND (e.scheme = 'http' OR eo.tls_observed = 1)
                          AND ebrl.state = 'active'
                          AND ebo.state = 'verified'
                          AND ebo.protected_transport_observed = ebr.protected_transport_required
                          AND ebo.trusted_ingress_observed = ebr.trusted_ingress_kind
                          AND ro.configuration_generation = h.configuration_generation
                          AND ro.configuration_digest = h.configuration_digest
                          AND ro.state = 'healthy'
                          AND ao.configuration_generation = h.configuration_generation
                          AND ao.configuration_digest = h.configuration_digest
                          AND ao.access_policy_digest = r.access_policy_digest
                          AND ao.state = 'verified'
                          AND (r.mode <> 'direct' OR EXISTS (
                            SELECT 1 FROM direct_delivery_route_evidence de
                            JOIN placement_delivery_manifest_heads mh
                              ON mh.placement_id = de.placement_id
                             AND mh.manifest_id = de.publication_manifest_id
                            JOIN storage_gateways g ON g.id = de.storage_gateway_id
                            WHERE de.delivery_route_id = r.id
                              AND de.configuration_generation = h.configuration_generation
                              AND de.configuration_digest = h.configuration_digest
                              AND de.endpoint_id = r.endpoint_id
                              AND de.endpoint_generation = r.endpoint_generation
                              AND de.placement_id = r.placement_id
                              AND de.storage_gateway_id = r.storage_gateway_id
                              AND de.gateway_generation = r.gateway_generation
                              AND g.enabled = 1
                              AND g.desired_generation = de.gateway_generation
                              AND g.observed_generation = de.gateway_generation
                              AND g.reconciliation_state = 'ready'))
                          AND (r.access_policy_kind <> 'private_network' OR (
                            abrl.state = 'active'
                            AND abo.state = 'verified'
                            AND abo.protected_transport_observed = abr.protected_transport_required
                            AND abo.trusted_ingress_observed = abr.trusted_ingress_kind))
                         THEN 1 ELSE 0 END
             FROM delivery_routes r
             JOIN delivery_route_heads h ON h.delivery_route_id = r.id
             JOIN delivery_endpoints e ON e.id = r.endpoint_id
             JOIN delivery_endpoint_revisions er
               ON er.endpoint_id = r.endpoint_id
              AND er.generation = r.endpoint_generation
             JOIN network_boundary_revisions ebr
               ON ebr.boundary_id = er.network_boundary_id
              AND ebr.revision = er.boundary_revision
             JOIN network_boundary_revision_lifecycle ebrl
               ON ebrl.boundary_id = ebr.boundary_id
              AND ebrl.revision = ebr.revision
             JOIN network_boundary_observations ebo
               ON ebo.boundary_id = ebr.boundary_id
              AND ebo.revision = ebr.revision
             LEFT JOIN network_boundary_revisions abr
               ON abr.boundary_id = r.access_boundary_id
              AND abr.revision = r.access_boundary_revision
             LEFT JOIN network_boundary_revision_lifecycle abrl
               ON abrl.boundary_id = abr.boundary_id
              AND abrl.revision = abr.revision
             LEFT JOIN network_boundary_observations abo
               ON abo.boundary_id = abr.boundary_id
              AND abo.revision = abr.revision
             LEFT JOIN domains d ON d.id = e.domain_id
             LEFT JOIN registries reg ON reg.id = r.registry_id
             LEFT JOIN binary_caches cache ON cache.id = r.cache_id
             LEFT JOIN delivery_endpoint_observations eo ON eo.endpoint_id = e.id
             LEFT JOIN delivery_route_observations ro ON ro.delivery_route_id = r.id
             LEFT JOIN delivery_route_access_observations ao
               ON ao.delivery_route_id = r.id
             WHERE {host_predicate} AND e.effective_port = ?2
               AND e.scheme = ?3 AND er.ingress_kind = ?4
               AND r.enabled = 1
               AND (reg.id IS NOT NULL OR cache.id IS NOT NULL)
             ORDER BY length(r.base_path) DESC, r.id"
        );
        self.backend
            .query(
                &sql,
                &vec![
                    host_value,
                    crate::value::Value::Int(i64::from(effective_port)),
                    crate::value::Value::Text(scheme.to_owned()),
                    crate::value::Value::Text(ingress_kind.to_owned()),
                ],
            )
            .await?
            .iter()
            .map(|row| {
                let registry_id: Option<i64> = row.get(2)?;
                let cache_id: Option<i64> = row.get(3)?;
                let surface = match (registry_id, cache_id) {
                    (Some(id), None) => SurfaceTarget::Registry(id),
                    (None, Some(id)) => SurfaceTarget::BinaryCache(id),
                    _ => bail!("inbound route has an invalid surface identity"),
                };
                Ok(InboundDeliveryRouteRecord {
                    id: row.get(0)?,
                    configuration_generation: row.get(17)?,
                    configuration_digest: row.get(18)?,
                    base_path: row.get(1)?,
                    surface,
                    target_slug: row.get(4)?,
                    mode: row.get(5)?,
                    access_policy_kind: row.get(6)?,
                    access_boundary_id: row.get(7)?,
                    access_boundary_revision: row.get(8)?,
                    external_provider_kind: row.get(9)?,
                    external_provider_resource_id: row.get(10)?,
                    external_provider_revision: row.get(11)?,
                    placement_id: row.get(12)?,
                    placement_policy_revision_id: row.get(13)?,
                    serves_git: row.get(14)?,
                    serves_cache: row.get(15)?,
                    serves_web: row.get(16)?,
                    ready: row.get(19)?,
                })
            })
            .collect()
    }

    /// Atomically admits one route-bound delivery assertion nonce exactly once.
    ///
    /// Expired nonce rows are reaped before admission. The insert additionally
    /// verifies that `route_configuration_digest` is still the route's current
    /// immutable head, so a signed assertion cannot be rebound across a route
    /// update. The primary key serializes concurrent attempts across native
    /// replicas or the Worker's colocated database authority.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed digests or a database failure.
    pub async fn claim_delivery_attestation_nonce(
        &self,
        route_id: &str,
        route_configuration_digest: &str,
        nonce_digest: &str,
        expires_at: i64,
        now: i64,
    ) -> Result<bool> {
        for (value, label) in [
            (route_configuration_digest, "route configuration digest"),
            (nonce_digest, "delivery attestation nonce digest"),
        ] {
            if value.len() != 64
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            {
                bail!("{label} must be lowercase SHA-256 hex");
            }
        }
        if route_id.is_empty() || expires_at < now {
            return Ok(false);
        }
        self.backend
            .execute(
                "DELETE FROM delivery_attestation_nonces WHERE expires_at < ?1",
                &vals![now],
            )
            .await?;
        let affected = self
            .backend
            .execute(
                "INSERT INTO delivery_attestation_nonces (delivery_route_id,
                    route_configuration_digest, nonce_digest, expires_at, accepted_at)
                 SELECT ?1, ?2, ?3, ?4, ?5
                 WHERE EXISTS (SELECT 1 FROM delivery_route_heads
                   WHERE delivery_route_id = ?1 AND configuration_digest = ?2)
                 ON CONFLICT(delivery_route_id, route_configuration_digest, nonce_digest)
                 DO NOTHING",
                &vals![
                    route_id,
                    route_configuration_digest,
                    nonce_digest,
                    expires_at,
                    now
                ],
            )
            .await?;
        Ok(affected == 1)
    }

    /// Returns whether a typed host belongs to any delivery endpoint identity.
    ///
    /// Scheme and port are intentionally ignored. Once a host is dedicated to
    /// delivery, a request on the wrong listener must fail closed instead of
    /// falling through to Hub control-plane or slug routing.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid typed address or database failure.
    pub async fn delivery_endpoint_host_exists(&self, host: &InboundEndpointHost) -> Result<bool> {
        let (predicate, value) = match host {
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
            InboundEndpointHost::Ipv4(_) => {
                bail!("IPv4 endpoint identity must contain four bytes")
            }
            InboundEndpointHost::Ipv6(_) => {
                bail!("IPv6 endpoint identity must contain sixteen bytes")
            }
        };
        Ok(self
            .backend
            .query_opt(
                &format!(
                    "SELECT 1 FROM delivery_endpoints e
                     LEFT JOIN domains d ON d.id = e.domain_id
                     WHERE {predicate}"
                ),
                &vec![value],
            )
            .await?
            .is_some())
    }

    /// Creates a route and generation-one immutable configuration atomically.
    ///
    /// The caller supplies the active privacy-preserving reservation digest and
    /// the same candidate recomputed under every retained key. The collision
    /// check and active-version insert are one transaction, and the database
    /// never stores the route's plaintext URL in the permanent reservation row.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid closed route shape, URL reservation
    /// collision, missing exact grants/targets, or database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_delivery_route(
        &self,
        id: &str,
        surface: SurfaceTarget,
        spec: &DeliveryRouteSpec,
        canonical_rendered_url: &str,
        reservation_key_version: i64,
        reservation_digest: &[u8],
        reservation_candidates: &[(i64, Vec<u8>)],
        predecessor: Option<(&str, i64)>,
        actor: &str,
    ) -> Result<DeliveryRouteRecord> {
        validate_stable_id(id, "route id")?;
        if reservation_key_version <= 0
            || reservation_digest.len() != 32
            || reservation_candidates.is_empty()
            || reservation_candidates
                .iter()
                .any(|(version, digest)| *version <= 0 || digest.len() != 32)
            || !reservation_candidates.iter().any(|(version, digest)| {
                *version == reservation_key_version && digest == reservation_digest
            })
        {
            bail!("route reservation key versions and digests are invalid");
        }
        let mut versions = std::collections::BTreeSet::new();
        if reservation_candidates
            .iter()
            .any(|(version, _)| !versions.insert(*version))
        {
            bail!("route reservation candidate versions must be unique");
        }
        let base_path = validate_delivery_route_spec(spec)?;
        if matches!(surface, SurfaceTarget::BinaryCache(_)) && spec.serves_git {
            bail!("a binary-cache route cannot serve Git");
        }
        if !(spec.serves_git || spec.serves_cache || spec.serves_web) {
            bail!("route must serve at least one audience");
        }
        if !matches!(spec.mode.as_str(), "hub_proxy" | "hub_redirect" | "direct") {
            bail!("invalid route mode");
        }
        let direct = spec.mode == "direct";
        let direct_shape = spec.storage_gateway_id.is_some()
            && spec.gateway_generation.is_some()
            && spec.target_storage_binding_id.is_some()
            && spec.gateway_client_base_path.is_some()
            && spec.target_placement_prefix.is_some()
            && spec.placement_id.is_some()
            && spec.placement_policy_revision_id.is_none();
        let hub_shape = spec.storage_gateway_id.is_none()
            && spec.gateway_generation.is_none()
            && spec.target_storage_binding_id.is_none()
            && spec.gateway_client_base_path.is_none()
            && spec.target_placement_prefix.is_none()
            && (spec.placement_id.is_some() ^ spec.placement_policy_revision_id.is_some());
        if (direct && !direct_shape) || (!direct && !hub_shape) {
            bail!("route target does not match delivery mode");
        }
        if (direct && !matches!(spec.endpoint_ingress_kind.as_str(), "external" | "layer7"))
            || (!direct && !matches!(spec.endpoint_ingress_kind.as_str(), "hub" | "layer7"))
        {
            bail!("route mode is incompatible with the endpoint ingress kind");
        }
        let private_shape = spec.access_boundary_id.is_some()
            && spec.access_boundary_revision.is_some()
            && spec.external_provider_kind.is_none()
            && spec.external_provider_resource_id.is_none()
            && spec.external_provider_revision.is_none();
        let external_shape = spec.access_boundary_id.is_none()
            && spec.access_boundary_revision.is_none()
            && spec.external_provider_kind.is_some()
            && spec.external_provider_resource_id.is_some()
            && spec.external_provider_revision.is_some();
        let simple_shape = spec.access_boundary_id.is_none()
            && spec.access_boundary_revision.is_none()
            && spec.external_provider_kind.is_none()
            && spec.external_provider_resource_id.is_none()
            && spec.external_provider_revision.is_none();
        if !matches!(
            (
                spec.access_policy_kind.as_str(),
                private_shape,
                external_shape,
                simple_shape
            ),
            ("private_network", true, false, false)
                | ("external_provider", false, true, false)
                | ("public" | "hub_auth", false, false, true)
        ) {
            bail!("route access policy has an invalid closed variant shape");
        }
        if let Some(placement_id) = spec.placement_id {
            let placement = self
                .surface_placement(placement_id)
                .await?
                .context("route placement does not exist")?;
            if placement.kind != "complete" {
                bail!("a pinned route target must be a complete placement");
            }
            if direct {
                if Some(placement.storage_binding_id) != spec.target_storage_binding_id
                    || Some(placement.prefix.as_str()) != spec.target_placement_prefix.as_deref()
                    || join_route_segments(
                        spec.gateway_client_base_path.as_deref().unwrap_or_default(),
                        &placement.prefix,
                    )? != base_path
                {
                    bail!(
                        "direct route path and binding must derive from its gateway and placement"
                    );
                }
            }
        }
        if let Some(policy_revision_id) = spec.placement_policy_revision_id.as_deref() {
            let policy_revision = self
                .placement_policy_revision(policy_revision_id)
                .await?
                .context("route placement-policy revision does not exist")?;
            if policy_revision.state != "published" || policy_revision.surface != surface {
                bail!("route placement-policy revision must be published for the same surface");
            }
        }
        let target_placement_kind = spec.placement_id.map(|_| "complete");
        let policy_revision_state = spec
            .placement_policy_revision_id
            .as_ref()
            .map(|_| "published");
        let canonical_configuration_json = canonical_json(spec)?;
        let configuration_digest = sha256_hex(&canonical_configuration_json);
        let probe_operation_id =
            automatic_route_probe_operation_id("create", id, 1, &configuration_digest);
        let probe_detail = serde_json::json!({
            "trigger": "create",
            "deliveryRouteId": id,
            "generation": 1,
            "configurationDigest": configuration_digest,
            "accessPolicyDigest": spec.access_policy_digest,
            "endpointId": spec.endpoint_id,
            "endpointGeneration": spec.endpoint_generation,
            "gatewayId": spec.storage_gateway_id,
            "gatewayGeneration": spec.gateway_generation,
            "externalProviderKind": spec.external_provider_kind,
            "externalProviderResourceId": spec.external_provider_resource_id,
            "externalProviderRevision": spec.external_provider_revision,
        })
        .to_string();
        let reservation_id = format!("route-url:{}", Uuid::new_v4().simple());
        let (registry_id, cache_id) = surface.ids();
        let now = unix_now();
        let endpoint = self
            .delivery_endpoint(&spec.endpoint_id)
            .await?
            .context("route endpoint does not exist")?;
        let topology_event_id = format!("topology-event:{}", Uuid::new_v4().simple());
        let topology_event_payload = serde_json::to_string(&serde_json::json!({
            "type": "topology.delivery_route.created",
            "resource_kind": "delivery_route",
            "resource_stable_id": id,
            "resource_generation": 1,
            "resource_version": 1,
        }))?;
        let mut reservation_params = vals![
            reservation_id,
            reservation_key_version,
            reservation_digest.to_vec(),
            now
        ];
        let mut collision_terms = Vec::with_capacity(reservation_candidates.len());
        for (version, digest) in reservation_candidates {
            let version_parameter = reservation_params.len() + 1;
            reservation_params.extend(vals![version, digest]);
            collision_terms.push(format!(
                "(reservation_key_version = ?{version_parameter} AND reservation_digest = ?{})",
                version_parameter + 1
            ));
        }
        let reservation_statement = Statement::new(
            format!(
                "INSERT INTO delivery_route_url_reservations
                 (id, digest_scheme, reservation_key_version, reservation_digest, created_at)
                 SELECT ?1, 'hmac_sha256_v1', ?2, ?3, ?4
                 WHERE NOT EXISTS (SELECT 1 FROM delivery_route_url_reservations WHERE {})",
                collision_terms.join(" OR ")
            ),
            reservation_params,
        );
        self.backend
            .batch(&[
                reservation_statement,
                Statement::new(
                    "INSERT INTO delivery_routes (id, url_reservation_id, resource_version,
                 endpoint_id, endpoint_generation, endpoint_ingress_kind, consumer_scope_key,
                 storage_gateway_id, gateway_generation, target_storage_binding_id,
                 gateway_client_base_path, target_placement_prefix, base_path, registry_id,
                 cache_id, mode, access_policy_kind, access_boundary_id,
                 access_boundary_revision, external_provider_kind,
                 external_provider_resource_id, external_provider_revision,
                 access_policy_json, access_policy_digest,
                 placement_id, target_placement_kind, placement_policy_revision_id,
                 placement_policy_revision_state, serves_git, serves_cache, serves_web,
                 enabled, created_at, updated_at)
                 SELECT ?1, ?2, 1, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                   ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24,
                   ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32, ?32
                 WHERE ?33 IS NULL OR EXISTS (
                   SELECT 1 FROM delivery_routes predecessor
                   WHERE predecessor.id = ?33 AND predecessor.resource_version = ?34
                     AND predecessor.enabled = 1
                     AND (predecessor.registry_id = ?13 OR predecessor.cache_id = ?14)
                     AND NOT EXISTS (SELECT 1 FROM delivery_route_replacements replacement
                       WHERE replacement.predecessor_route_id = predecessor.id))",
                    vals![
                        id,
                        reservation_id,
                        spec.endpoint_id,
                        spec.endpoint_generation,
                        spec.endpoint_ingress_kind,
                        spec.consumer_scope_key,
                        spec.storage_gateway_id,
                        spec.gateway_generation,
                        spec.target_storage_binding_id,
                        spec.gateway_client_base_path,
                        spec.target_placement_prefix,
                        base_path,
                        registry_id,
                        cache_id,
                        spec.mode,
                        spec.access_policy_kind,
                        spec.access_boundary_id,
                        spec.access_boundary_revision,
                        spec.external_provider_kind,
                        spec.external_provider_resource_id,
                        spec.external_provider_revision,
                        spec.access_policy_json,
                        spec.access_policy_digest,
                        spec.placement_id,
                        target_placement_kind,
                        spec.placement_policy_revision_id,
                        policy_revision_state,
                        spec.serves_git,
                        spec.serves_cache,
                        spec.serves_web,
                        spec.enabled,
                        now,
                        predecessor.map(|value| value.0),
                        predecessor.map(|value| value.1)
                    ],
                ),
                Statement::new(
                    "INSERT INTO delivery_route_replacements
                     (successor_route_id, predecessor_route_id,
                      predecessor_resource_version, created_at)
                     SELECT ?1, ?2, ?3, ?4 WHERE ?2 IS NOT NULL
                       AND EXISTS (SELECT 1 FROM delivery_routes WHERE id = ?1)",
                    vals![
                        id,
                        predecessor.map(|value| value.0),
                        predecessor.map(|value| value.1),
                        now
                    ],
                ),
                Statement::new(
                    "INSERT INTO delivery_route_configurations (delivery_route_id, registry_id,
                 cache_id, configuration_generation, configuration_digest,
                 canonical_rendered_url, canonical_configuration_json, created_by, created_at)
                 SELECT ?1, ?2, ?3, 1, ?4, ?5, ?6, ?7, ?8
                 WHERE EXISTS (SELECT 1 FROM delivery_routes WHERE id = ?1)",
                    vals![
                        id,
                        registry_id,
                        cache_id,
                        configuration_digest,
                        canonical_rendered_url,
                        canonical_configuration_json,
                        actor,
                        now
                    ],
                ),
                Statement::new(
                    "INSERT INTO delivery_route_heads
                 (delivery_route_id, registry_id, cache_id, configuration_generation,
                  configuration_digest, access_policy_digest)
                 SELECT id, registry_id, cache_id, 1, ?2, access_policy_digest
                 FROM delivery_routes WHERE id = ?1
                   AND EXISTS (SELECT 1 FROM delivery_route_configurations
                   WHERE delivery_route_id = ?1 AND configuration_generation = 1
                     AND configuration_digest = ?2)",
                    vals![id, configuration_digest],
                ),
                Statement::new(
                    "UPDATE delivery_routes SET enabled = ?2, updated_at = ?3
                     WHERE id = ?1 AND EXISTS (SELECT 1 FROM delivery_route_heads
                       WHERE delivery_route_id = ?1 AND configuration_generation = 1
                         AND configuration_digest = ?4)",
                    vals![id, spec.enabled, now, configuration_digest],
                ),
                Statement::new(
                    "INSERT INTO delivery_route_observations (delivery_route_id, registry_id,
                 cache_id, configuration_generation, configuration_digest, state, observed_at)
                 VALUES (?1, ?2, ?3, 1, ?4, 'unknown', ?5)",
                    vals![id, registry_id, cache_id, configuration_digest, now],
                ),
                Statement::new(
                    "INSERT INTO delivery_endpoint_scope_grant_pins
                     (pin_id, endpoint_id, endpoint_generation, consumer_scope_key,
                      grant_generation, grant_state, target_kind, target_stable_id,
                      target_generation_key, target_configuration_digest,
                      resource_version)
                     SELECT ?1, ?2, ?3, ?4, grant_generation, 'active', 'route',
                       ?5, 1, ?6, 1 FROM delivery_endpoint_route_scopes
                     WHERE endpoint_id = ?2 AND endpoint_generation = ?3
                       AND consumer_scope_key = ?4 AND state = 'active' AND ?7 = 1",
                    vals![
                        format!("endpoint-pin:{}", Uuid::new_v4().simple()),
                        spec.endpoint_id,
                        spec.endpoint_generation,
                        spec.consumer_scope_key,
                        id,
                        configuration_digest,
                        spec.enabled
                    ],
                ),
                Statement::new(
                    "INSERT INTO storage_gateway_scope_grant_pins
                     (pin_id, gateway_id, generation, consumer_scope_key,
                      grant_generation, grant_state, target_kind, target_stable_id,
                      target_generation_key, target_configuration_digest,
                      resource_version)
                     SELECT ?1, ?2, ?3, ?4, grant_generation, 'active', 'route',
                       ?5, 1, ?6, 1 FROM storage_gateway_revision_route_scopes
                     WHERE ?2 IS NOT NULL AND gateway_id = ?2 AND generation = ?3
                       AND consumer_scope_key = ?4 AND state = 'active' AND ?7 = 1",
                    vals![
                        format!("gateway-pin:{}", Uuid::new_v4().simple()),
                        spec.storage_gateway_id,
                        spec.gateway_generation,
                        spec.consumer_scope_key,
                        id,
                        configuration_digest,
                        spec.enabled
                    ],
                ),
                Statement::new(
                    "INSERT INTO network_boundary_serving_pins
                     (pin_id, boundary_id, revision, consumer_scope_key,
                      grant_generation, grant_state, usage_kind, target_kind,
                      target_stable_id, target_generation_key,
                      target_configuration_digest, acquired_by, acquired_at,
                      resource_version)
                     SELECT ?1, er.network_boundary_id, er.boundary_revision, ?2,
                       s.grant_generation, 'active', 'route_endpoint', 'route',
                       ?3, 1, ?4, ?5, ?6, 1
                     FROM delivery_endpoint_revisions er
                     JOIN network_boundary_consumer_scopes s
                       ON s.boundary_id = er.network_boundary_id
                      AND s.consumer_scope_key = ?2 AND s.state = 'active'
                     JOIN network_boundary_revision_lifecycle l
                       ON l.boundary_id = er.network_boundary_id
                      AND l.revision = er.boundary_revision AND l.state = 'active'
                     WHERE er.endpoint_id = ?7 AND er.generation = ?8 AND ?9 = 1",
                    vals![
                        format!("boundary-pin:{}", Uuid::new_v4().simple()),
                        spec.consumer_scope_key,
                        id,
                        configuration_digest,
                        actor,
                        now,
                        spec.endpoint_id,
                        spec.endpoint_generation,
                        spec.enabled
                    ],
                ),
                Statement::new(
                    "INSERT INTO network_boundary_serving_pins
                     (pin_id, boundary_id, revision, consumer_scope_key,
                      grant_generation, grant_state, usage_kind, target_kind,
                      target_stable_id, target_generation_key,
                      target_configuration_digest, acquired_by, acquired_at,
                      resource_version)
                     SELECT ?1, ?2, ?3, ?4, s.grant_generation, 'active',
                       'route_access', 'route', ?5, 1, ?6, ?7, ?8, 1
                     FROM network_boundary_consumer_scopes s
                     JOIN network_boundary_revision_lifecycle l
                       ON l.boundary_id = s.boundary_id AND l.revision = ?3
                      AND l.state = 'active'
                     WHERE ?2 IS NOT NULL AND s.boundary_id = ?2
                       AND s.consumer_scope_key = ?4 AND s.state = 'active' AND ?9 = 1",
                    vals![
                        format!("boundary-pin:{}", Uuid::new_v4().simple()),
                        spec.access_boundary_id,
                        spec.access_boundary_revision,
                        spec.consumer_scope_key,
                        id,
                        configuration_digest,
                        actor,
                        now,
                        spec.enabled
                    ],
                ),
                Statement::new(
                    "INSERT INTO topology_operations
                     (operation_id, operation_kind, authorization_scope_key,
                      control_permission, primary_target_kind,
                      primary_target_stable_id, primary_target_generation_key,
                      primary_target_configuration_digest, state, progress_total,
                      detail_json, created_at)
                     SELECT ?1, 'delivery_route_probe', e.owner_scope_key,
                       'route.manage', 'delivery_route', r.id,
                       h.configuration_generation, h.configuration_digest,
                       'pending', 1, ?2, ?3
                     FROM delivery_routes r
                     JOIN delivery_route_heads h ON h.delivery_route_id = r.id
                     JOIN delivery_endpoints e ON e.id = r.endpoint_id
                     WHERE r.id = ?4 AND r.enabled = 1
                       AND h.configuration_generation = 1
                       AND h.configuration_digest = ?5",
                    vals![
                        probe_operation_id,
                        probe_detail,
                        now,
                        id,
                        configuration_digest
                    ],
                ),
                Database::topology_event_insert_statement(&crate::db::NewTopologyEvent {
                    event_id: &topology_event_id,
                    event_name: "topology.delivery_route.created",
                    owner_scope_key: &endpoint.owner_scope_key,
                    resource_kind: "delivery_route",
                    resource_stable_id: id,
                    resource_generation_key: 1,
                    actor_kind: "key",
                    actor_id: None,
                    actor_label: actor,
                    payload_json: &topology_event_payload,
                    occurred_at: now,
                }),
            ])
            .await?;
        self.delivery_route(id)
            .await?
            .context("created route disappeared")
    }

    /// Returns a normalized route identity and current configuration pointer.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn delivery_route(&self, id: &str) -> Result<Option<DeliveryRouteRecord>> {
        self.backend
            .query_opt(
                "SELECT r.id, h.configuration_generation, h.configuration_digest, r.endpoint_id,
             r.endpoint_generation, r.base_path, r.registry_id, r.cache_id, r.mode, r.enabled,
             r.resource_version, r.created_at, r.updated_at FROM delivery_routes r
             JOIN delivery_route_heads h ON h.delivery_route_id = r.id WHERE r.id = ?1",
                &vals![id],
            )
            .await?
            .as_ref()
            .map(|row| {
                let registry_id: Option<i64> = row.get(6)?;
                let cache_id: Option<i64> = row.get(7)?;
                let surface = match (registry_id, cache_id) {
                    (Some(id), None) => SurfaceTarget::Registry(id),
                    (None, Some(id)) => SurfaceTarget::BinaryCache(id),
                    _ => bail!("route has invalid surface discriminator"),
                };
                Ok(DeliveryRouteRecord {
                    id: row.get(0)?,
                    configuration_generation: row.get(1)?,
                    configuration_digest: row.get(2)?,
                    endpoint_id: row.get(3)?,
                    endpoint_generation: row.get(4)?,
                    base_path: row.get(5)?,
                    surface,
                    mode: row.get(8)?,
                    enabled: row.get(9)?,
                    resource_version: row.get(10)?,
                    created_at: row.get(11)?,
                    updated_at: row.get(12)?,
                })
            })
            .transpose()
    }

    /// Returns the complete current immutable route snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted JSON.
    pub async fn delivery_route_snapshot(
        &self,
        id: &str,
    ) -> Result<Option<DeliveryRouteSnapshotRecord>> {
        self.backend
            .query_opt(
                "SELECT c.canonical_configuration_json, c.canonical_rendered_url,
                        o.state, o.observed_at, o.error
                   FROM delivery_route_heads h
                   JOIN delivery_route_configurations c
                     ON c.delivery_route_id = h.delivery_route_id
                    AND c.configuration_generation = h.configuration_generation
                    AND c.configuration_digest = h.configuration_digest
                   JOIN delivery_route_observations o
                     ON o.delivery_route_id = h.delivery_route_id
                    AND o.configuration_generation = h.configuration_generation
                    AND o.configuration_digest = h.configuration_digest
                  WHERE h.delivery_route_id = ?1",
                &vals![id],
            )
            .await?
            .map(|row| {
                let canonical: String = row.get(0)?;
                Ok(DeliveryRouteSnapshotRecord {
                    spec: serde_json::from_str(&canonical)
                        .context("decoding current route configuration")?,
                    canonical_url: row.get(1)?,
                    observation_state: row.get(2)?,
                    observed_at: row.get(3)?,
                    observation_error: row.get(4)?,
                })
            })
            .transpose()
    }

    /// Lists delivery routes for one exact surface.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn list_delivery_routes(
        &self,
        surface: SurfaceTarget,
    ) -> Result<Vec<DeliveryRouteRecord>> {
        let (registry_id, cache_id) = surface.ids();
        self.backend
            .query(
                "SELECT r.id, h.configuration_generation, h.configuration_digest, r.endpoint_id,
                 r.endpoint_generation, r.base_path, r.registry_id, r.cache_id, r.mode, r.enabled,
                 r.resource_version, r.created_at, r.updated_at FROM delivery_routes r
                 JOIN delivery_route_heads h ON h.delivery_route_id = r.id
                 WHERE r.registry_id = ?1 OR r.cache_id = ?2
                 ORDER BY r.endpoint_id, r.base_path, r.id",
                &vals![registry_id, cache_id],
            )
            .await?
            .iter()
            .map(|row| {
                Ok(DeliveryRouteRecord {
                    id: row.get(0)?,
                    configuration_generation: row.get(1)?,
                    configuration_digest: row.get(2)?,
                    endpoint_id: row.get(3)?,
                    endpoint_generation: row.get(4)?,
                    base_path: row.get(5)?,
                    surface,
                    mode: row.get(8)?,
                    enabled: row.get(9)?,
                    resource_version: row.get(10)?,
                    created_at: row.get(11)?,
                    updated_at: row.get(12)?,
                })
            })
            .collect()
    }

    /// Updates a route only when its rendered URL remains byte-identical.
    ///
    /// The old observation/access evidence is removed before the immutable
    /// configuration pointer advances, so stale evidence can never satisfy the
    /// new generation.
    ///
    /// # Errors
    ///
    /// Returns an error for URL identity change, stale resource version,
    /// current signed-stack references whose URL would change, or database failure.
    pub async fn update_delivery_route(
        &self,
        id: &str,
        spec: &DeliveryRouteSpec,
        canonical_rendered_url: &str,
        expected_version: i64,
        actor: &str,
    ) -> Result<DeliveryRouteRecord> {
        let base_path = validate_delivery_route_spec(spec)?;
        let existing = self
            .delivery_route(id)
            .await?
            .context("route does not exist")?;
        if existing.resource_version != expected_version {
            bail!("route resource version is stale");
        }
        if existing.base_path != base_path {
            bail!("route base-path identity change requires ReplaceRoute");
        }
        if matches!(existing.surface, SurfaceTarget::BinaryCache(_)) && spec.serves_git {
            bail!("a binary-cache route cannot serve Git");
        }
        let canonical_audiences = self
            .backend
            .query(
                "SELECT audience FROM canonical_routes WHERE delivery_route_id = ?1",
                &vals![id],
            )
            .await?
            .iter()
            .map(|row| row.get::<String>(0))
            .collect::<Result<Vec<_>>>()?;
        if canonical_audiences.iter().any(|audience| {
            !spec.enabled
                || audience == "git" && !spec.serves_git
                || audience == "nix_cache" && !spec.serves_cache
                || audience == "web" && !spec.serves_web
        }) {
            bail!("move canonical audiences before disabling their route capability");
        }
        let current = self
            .backend
            .query_opt(
                "SELECT h.configuration_generation, c.canonical_rendered_url
             FROM delivery_routes r JOIN delivery_route_heads h ON h.delivery_route_id = r.id
             JOIN delivery_route_configurations c
               ON c.delivery_route_id = r.id
              AND c.configuration_generation = h.configuration_generation
             WHERE r.id = ?1 AND r.resource_version = ?2",
                &vals![id, expected_version],
            )
            .await?
            .context("route is missing or stale")?;
        let generation: i64 = current.get(0)?;
        let current_url: String = current.get(1)?;
        if current_url != canonical_rendered_url {
            bail!("route URL identity change requires ReplaceRoute");
        }
        if let Some(placement_id) = spec.placement_id {
            let placement = self
                .surface_placement(placement_id)
                .await?
                .context("route placement does not exist")?;
            if placement.kind != "complete" {
                bail!("a pinned route target must be a complete placement");
            }
            if spec.mode == "direct"
                && (Some(placement.storage_binding_id) != spec.target_storage_binding_id
                    || Some(placement.prefix.as_str()) != spec.target_placement_prefix.as_deref()
                    || join_route_segments(
                        spec.gateway_client_base_path.as_deref().unwrap_or_default(),
                        &placement.prefix,
                    )? != base_path)
            {
                bail!("direct route path and binding must derive from its gateway and placement");
            }
        }
        if let Some(policy_revision_id) = spec.placement_policy_revision_id.as_deref() {
            let policy_revision = self
                .placement_policy_revision(policy_revision_id)
                .await?
                .context("route placement-policy revision does not exist")?;
            if policy_revision.state != "published" || policy_revision.surface != existing.surface {
                bail!("route placement-policy revision must be published for the same surface");
            }
        }
        let target_placement_kind = spec.placement_id.map(|_| "complete");
        let policy_revision_state = spec
            .placement_policy_revision_id
            .as_ref()
            .map(|_| "published");
        let next = generation + 1;
        let canonical_configuration_json = canonical_json(spec)?;
        let digest = sha256_hex(&canonical_configuration_json);
        let trigger = if !existing.enabled && spec.enabled {
            "enable"
        } else if existing.enabled && !spec.enabled {
            "disable"
        } else {
            "update"
        };
        let probe_operation_id = automatic_route_probe_operation_id(trigger, id, next, &digest);
        let probe_detail = serde_json::json!({
            "trigger": trigger,
            "deliveryRouteId": id,
            "generation": next,
            "configurationDigest": digest,
            "accessPolicyDigest": spec.access_policy_digest,
            "endpointId": spec.endpoint_id,
            "endpointGeneration": spec.endpoint_generation,
            "gatewayId": spec.storage_gateway_id,
            "gatewayGeneration": spec.gateway_generation,
            "externalProviderKind": spec.external_provider_kind,
            "externalProviderResourceId": spec.external_provider_resource_id,
            "externalProviderRevision": spec.external_provider_revision,
        })
        .to_string();
        let now = unix_now();
        let endpoint = self
            .delivery_endpoint(&spec.endpoint_id)
            .await?
            .context("route endpoint does not exist")?;
        let topology_event_id = format!("topology-event:{}", Uuid::new_v4().simple());
        let topology_event_payload = serde_json::to_string(&serde_json::json!({
            "type": "topology.delivery_route.revised",
            "resource_kind": "delivery_route",
            "resource_stable_id": id,
            "resource_generation": next,
            "resource_version": expected_version + 1,
            "enabled": spec.enabled,
        }))?;
        self.backend
            .batch(&[
                Statement::new(
                    "DELETE FROM network_boundary_serving_pins
                     WHERE target_kind = 'route' AND target_stable_id = ?1",
                    vals![id],
                ),
                Statement::new(
                    "DELETE FROM delivery_endpoint_scope_grant_pins
                     WHERE target_kind = 'route' AND target_stable_id = ?1",
                    vals![id],
                ),
                Statement::new(
                    "DELETE FROM storage_gateway_scope_grant_pins
                     WHERE target_kind = 'route' AND target_stable_id = ?1",
                    vals![id],
                ),
                Statement::new(
                    "DELETE FROM direct_delivery_route_evidence WHERE delivery_route_id = ?1",
                    vals![id],
                ),
                Statement::new(
                    "DELETE FROM delivery_route_access_observations WHERE delivery_route_id = ?1",
                    vals![id],
                ),
                Statement::new(
                    "DELETE FROM delivery_route_observations WHERE delivery_route_id = ?1",
                    vals![id],
                ),
                Statement::new(
                    "INSERT INTO delivery_route_configurations (delivery_route_id, registry_id,
                 cache_id, configuration_generation, configuration_digest, canonical_rendered_url,
                 canonical_configuration_json, created_by, created_at)
                 SELECT id, registry_id, cache_id, ?2, ?3, ?4, ?5, ?6, ?7
                 FROM delivery_routes WHERE id = ?1 AND resource_version = ?8",
                    vals![
                        id,
                        next,
                        digest,
                        canonical_rendered_url,
                        canonical_configuration_json,
                        actor,
                        now,
                        expected_version
                    ],
                ),
                Statement::new(
                    "UPDATE delivery_routes SET endpoint_id = ?4, endpoint_generation = ?5,
                 endpoint_ingress_kind = ?6, consumer_scope_key = ?7,
                 storage_gateway_id = ?8, gateway_generation = ?9,
                 target_storage_binding_id = ?10, gateway_client_base_path = ?11,
                 target_placement_prefix = ?12, mode = ?13, access_policy_kind = ?14,
                 access_boundary_id = ?15, access_boundary_revision = ?16,
                 external_provider_kind = ?17, external_provider_resource_id = ?18,
                 external_provider_revision = ?19, access_policy_json = ?20,
                 access_policy_digest = ?21, placement_id = ?22,
                 target_placement_kind = ?23, placement_policy_revision_id = ?24,
                 placement_policy_revision_state = ?25, serves_git = ?26,
                 serves_cache = ?27, serves_web = ?28, enabled = ?29,
                 resource_version = resource_version + 1, updated_at = ?30
                 WHERE id = ?1 AND resource_version = ?31 AND EXISTS (
                   SELECT 1 FROM delivery_route_configurations WHERE delivery_route_id = ?1
                     AND configuration_generation = ?2 AND configuration_digest = ?3)",
                    vals![
                        id,
                        next,
                        digest,
                        spec.endpoint_id,
                        spec.endpoint_generation,
                        spec.endpoint_ingress_kind,
                        spec.consumer_scope_key,
                        spec.storage_gateway_id,
                        spec.gateway_generation,
                        spec.target_storage_binding_id,
                        spec.gateway_client_base_path,
                        spec.target_placement_prefix,
                        spec.mode,
                        spec.access_policy_kind,
                        spec.access_boundary_id,
                        spec.access_boundary_revision,
                        spec.external_provider_kind,
                        spec.external_provider_resource_id,
                        spec.external_provider_revision,
                        spec.access_policy_json,
                        spec.access_policy_digest,
                        spec.placement_id,
                        target_placement_kind,
                        spec.placement_policy_revision_id,
                        policy_revision_state,
                        spec.serves_git,
                        spec.serves_cache,
                        spec.serves_web,
                        spec.enabled,
                        now,
                        expected_version
                    ],
                ),
                Statement::new(
                    "UPDATE delivery_route_heads SET configuration_generation = ?2,
                     configuration_digest = ?3, access_policy_digest = ?4
                     WHERE delivery_route_id = ?1 AND EXISTS (
                       SELECT 1 FROM delivery_route_configurations
                       WHERE delivery_route_id = ?1 AND configuration_generation = ?2
                         AND configuration_digest = ?3)",
                    vals![id, next, digest, spec.access_policy_digest],
                ),
                Statement::new(
                    "INSERT INTO delivery_route_observations (delivery_route_id, registry_id,
                 cache_id, configuration_generation, configuration_digest, state, observed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'unknown', ?6)",
                    {
                        let (registry_id, cache_id) = existing.surface.ids();
                        vals![id, registry_id, cache_id, next, digest, now]
                    },
                ),
                Statement::new(
                    "INSERT INTO delivery_endpoint_scope_grant_pins
                     (pin_id, endpoint_id, endpoint_generation, consumer_scope_key,
                      grant_generation, grant_state, target_kind, target_stable_id,
                      target_generation_key, target_configuration_digest,
                      resource_version)
                     SELECT ?1, r.endpoint_id, r.endpoint_generation,
                       r.consumer_scope_key, g.grant_generation, 'active', 'route',
                       r.id, h.configuration_generation, h.configuration_digest, 1
                     FROM delivery_routes r JOIN delivery_route_heads h
                       ON h.delivery_route_id = r.id
                     JOIN delivery_endpoint_route_scopes g
                       ON g.endpoint_id = r.endpoint_id
                      AND g.endpoint_generation = r.endpoint_generation
                      AND g.consumer_scope_key = r.consumer_scope_key
                      AND g.state = 'active' WHERE r.id = ?2 AND r.enabled = 1",
                    vals![format!("endpoint-pin:{}", Uuid::new_v4().simple()), id],
                ),
                Statement::new(
                    "INSERT INTO storage_gateway_scope_grant_pins
                     (pin_id, gateway_id, generation, consumer_scope_key,
                      grant_generation, grant_state, target_kind, target_stable_id,
                      target_generation_key, target_configuration_digest,
                      resource_version)
                     SELECT ?1, r.storage_gateway_id, r.gateway_generation,
                       r.consumer_scope_key, g.grant_generation, 'active', 'route',
                       r.id, h.configuration_generation, h.configuration_digest, 1
                     FROM delivery_routes r JOIN delivery_route_heads h
                       ON h.delivery_route_id = r.id
                     JOIN storage_gateway_revision_route_scopes g
                       ON g.gateway_id = r.storage_gateway_id
                      AND g.generation = r.gateway_generation
                      AND g.consumer_scope_key = r.consumer_scope_key
                      AND g.state = 'active' WHERE r.id = ?2 AND r.enabled = 1
                       AND r.storage_gateway_id IS NOT NULL",
                    vals![format!("gateway-pin:{}", Uuid::new_v4().simple()), id],
                ),
                Statement::new(
                    "INSERT INTO network_boundary_serving_pins
                     (pin_id, boundary_id, revision, consumer_scope_key,
                      grant_generation, grant_state, usage_kind, target_kind,
                      target_stable_id, target_generation_key,
                      target_configuration_digest, acquired_by, acquired_at,
                      resource_version)
                     SELECT ?1, er.network_boundary_id, er.boundary_revision,
                       r.consumer_scope_key, g.grant_generation, 'active',
                       'route_endpoint', 'route', r.id, h.configuration_generation,
                       h.configuration_digest, ?3, ?4, 1
                     FROM delivery_routes r JOIN delivery_route_heads h
                       ON h.delivery_route_id = r.id
                     JOIN delivery_endpoint_revisions er
                       ON er.endpoint_id = r.endpoint_id
                      AND er.generation = r.endpoint_generation
                     JOIN network_boundary_consumer_scopes g
                       ON g.boundary_id = er.network_boundary_id
                      AND g.consumer_scope_key = r.consumer_scope_key
                      AND g.state = 'active'
                     JOIN network_boundary_revision_lifecycle l
                       ON l.boundary_id = er.network_boundary_id
                      AND l.revision = er.boundary_revision AND l.state = 'active'
                     WHERE r.id = ?2 AND r.enabled = 1",
                    vals![
                        format!("boundary-pin:{}", Uuid::new_v4().simple()),
                        id,
                        actor,
                        now
                    ],
                ),
                Statement::new(
                    "INSERT INTO network_boundary_serving_pins
                     (pin_id, boundary_id, revision, consumer_scope_key,
                      grant_generation, grant_state, usage_kind, target_kind,
                      target_stable_id, target_generation_key,
                      target_configuration_digest, acquired_by, acquired_at,
                      resource_version)
                     SELECT ?1, r.access_boundary_id, r.access_boundary_revision,
                       r.consumer_scope_key, g.grant_generation, 'active',
                       'route_access', 'route', r.id, h.configuration_generation,
                       h.configuration_digest, ?3, ?4, 1
                     FROM delivery_routes r JOIN delivery_route_heads h
                       ON h.delivery_route_id = r.id
                     JOIN network_boundary_consumer_scopes g
                       ON g.boundary_id = r.access_boundary_id
                      AND g.consumer_scope_key = r.consumer_scope_key
                      AND g.state = 'active'
                     JOIN network_boundary_revision_lifecycle l
                       ON l.boundary_id = r.access_boundary_id
                      AND l.revision = r.access_boundary_revision AND l.state = 'active'
                     WHERE r.id = ?2 AND r.enabled = 1
                       AND r.access_boundary_id IS NOT NULL",
                    vals![
                        format!("boundary-pin:{}", Uuid::new_v4().simple()),
                        id,
                        actor,
                        now
                    ],
                ),
                Statement::new(
                    "UPDATE topology_operations
                     SET state = 'cancelled',
                         started_at = COALESCE(started_at, ?2), finished_at = ?2,
                         error = 'superseded by a route desired-state mutation',
                         resource_version = resource_version + 1
                     WHERE operation_kind = 'delivery_route_probe'
                       AND primary_target_kind = 'delivery_route'
                       AND primary_target_stable_id = ?1
                       AND state IN ('pending', 'running')
                       AND EXISTS (SELECT 1 FROM delivery_route_heads h
                         WHERE h.delivery_route_id = ?1
                           AND h.configuration_generation = ?3
                           AND h.configuration_digest = ?4)",
                    vals![id, now, next, digest],
                ),
                Statement::new(
                    "INSERT INTO topology_operations
                     (operation_id, operation_kind, authorization_scope_key,
                      control_permission, primary_target_kind,
                      primary_target_stable_id, primary_target_generation_key,
                      primary_target_configuration_digest, state, progress_total,
                      detail_json, created_at)
                     SELECT ?1, 'delivery_route_probe', e.owner_scope_key,
                       'route.manage', 'delivery_route', r.id,
                       h.configuration_generation, h.configuration_digest,
                       'pending', 1, ?2, ?3
                     FROM delivery_routes r
                     JOIN delivery_route_heads h ON h.delivery_route_id = r.id
                     JOIN delivery_endpoints e ON e.id = r.endpoint_id
                     WHERE r.id = ?4 AND r.enabled = 1
                       AND h.configuration_generation = ?5
                       AND h.configuration_digest = ?6",
                    vals![probe_operation_id, probe_detail, now, id, next, digest],
                ),
                Database::topology_event_insert_statement(&crate::db::NewTopologyEvent {
                    event_id: &topology_event_id,
                    event_name: "topology.delivery_route.revised",
                    owner_scope_key: &endpoint.owner_scope_key,
                    resource_kind: "delivery_route",
                    resource_stable_id: id,
                    resource_generation_key: next,
                    actor_kind: "key",
                    actor_id: None,
                    actor_label: actor,
                    payload_json: &topology_event_payload,
                    occurred_at: now,
                }),
            ])
            .await?;
        self.delivery_route(id)
            .await?
            .context("updated route disappeared")
    }

    /// Deletes an unreferenced disabled route in dependency order.
    ///
    /// The permanent URL reservation is intentionally retained.
    ///
    /// # Errors
    ///
    /// Returns an error when the route is stale, enabled, canonical, present in
    /// the signed stack, pinned, or on database failure.
    pub async fn delete_delivery_route(
        &self,
        id: &str,
        expected_version: i64,
        actor_kind: &str,
        actor_id: Option<i64>,
        actor_label: &str,
    ) -> Result<bool> {
        let eligible = self
            .backend
            .query_opt(
                "SELECT e.owner_scope_key FROM delivery_routes r
             JOIN delivery_endpoints e ON e.id = r.endpoint_id
             WHERE r.id = ?1 AND r.resource_version = ?2
             AND r.enabled = 0
             AND NOT EXISTS (SELECT 1 FROM canonical_routes c WHERE c.delivery_route_id = r.id)
             AND NOT EXISTS (SELECT 1 FROM registry_cache_stack_entries s
               WHERE s.delivery_route_id = r.id)
             AND NOT EXISTS (SELECT 1 FROM delivery_endpoint_scope_grant_pins p
               WHERE p.target_kind = 'route' AND p.target_stable_id = r.id)
             AND NOT EXISTS (SELECT 1 FROM storage_gateway_scope_grant_pins p
               WHERE p.target_kind = 'route' AND p.target_stable_id = r.id)
             AND NOT EXISTS (SELECT 1 FROM network_boundary_serving_pins p
               WHERE p.target_kind = 'route' AND p.target_stable_id = r.id)
             AND NOT EXISTS (SELECT 1 FROM topology_operations o
               WHERE o.state IN ('pending', 'running') AND (
                 (o.primary_target_kind = 'delivery_route'
                   AND o.primary_target_stable_id = r.id
                   AND o.operation_kind <> 'delivery_route_probe')
                 OR EXISTS (SELECT 1 FROM operation_secondary_targets t
                   WHERE t.operation_id = o.operation_id
                     AND t.target_kind = 'delivery_route' AND t.stable_id = r.id)))",
                &vals![id, expected_version],
            )
            .await?;
        let Some(eligible) = eligible else {
            return Ok(false);
        };
        let owner_scope_key: String = eligible.get(0)?;
        let now = unix_now();
        let event_id = format!("topology-event:{}", Uuid::new_v4().simple());
        let payload = serde_json::to_string(&serde_json::json!({
            "type": "topology.delivery_route.deleted",
            "resource_kind": "delivery_route",
            "resource_stable_id": id,
            "resource_version": expected_version,
        }))?;
        self.backend
            .checked_batch(&[
                Statement::new(
                    "UPDATE topology_operations
                     SET state = 'cancelled', started_at = COALESCE(started_at, ?3),
                         finished_at = ?3, error = 'route deleted',
                         resource_version = resource_version + 1
                     WHERE operation_kind = 'delivery_route_probe'
                       AND primary_target_kind = 'delivery_route'
                       AND primary_target_stable_id = ?1
                       AND state IN ('pending', 'running')
                       AND EXISTS (SELECT 1 FROM delivery_routes r
                         WHERE r.id = ?1 AND r.resource_version = ?2 AND r.enabled = 0)",
                    vals![id, expected_version, now],
                )
                .unchecked(),
                Statement::new(
                    "DELETE FROM direct_delivery_route_evidence WHERE delivery_route_id = ?1",
                    vals![id],
                )
                .unchecked(),
                Statement::new(
                    "DELETE FROM delivery_route_access_observations WHERE delivery_route_id = ?1",
                    vals![id],
                )
                .unchecked(),
                Statement::new(
                    "DELETE FROM delivery_route_observations WHERE delivery_route_id = ?1",
                    vals![id],
                )
                .unchecked(),
                Statement::new(
                    "DELETE FROM delivery_route_heads WHERE delivery_route_id = ?1",
                    vals![id],
                )
                .unchecked(),
                Statement::new(
                    "DELETE FROM delivery_route_configurations WHERE delivery_route_id = ?1",
                    vals![id],
                )
                .unchecked(),
                Statement::new(
                    "DELETE FROM delivery_routes WHERE id = ?1 AND resource_version = ?2
                     AND enabled = 0
                     AND NOT EXISTS (SELECT 1 FROM topology_operations o
                       WHERE o.state IN ('pending', 'running') AND (
                         (o.primary_target_kind = 'delivery_route'
                           AND o.primary_target_stable_id = ?1
                           AND o.operation_kind <> 'delivery_route_probe')
                         OR EXISTS (SELECT 1 FROM operation_secondary_targets t
                           WHERE t.operation_id = o.operation_id
                             AND t.target_kind = 'delivery_route' AND t.stable_id = ?1)))",
                    vals![id, expected_version],
                )
                .expecting(1),
                Database::topology_event_statement(&crate::db::NewTopologyEvent {
                    event_id: &event_id,
                    event_name: "topology.delivery_route.deleted",
                    owner_scope_key: &owner_scope_key,
                    resource_kind: "delivery_route",
                    resource_stable_id: id,
                    resource_generation_key: 0,
                    actor_kind,
                    actor_id,
                    actor_label,
                    payload_json: &payload,
                    occurred_at: now,
                }),
            ])
            .await?;
        Ok(self.delivery_route(id).await?.is_none())
    }

    /// Creates or advances one surface/audience canonical route selection.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid audience, wrong-surface or disabled
    /// route, missing capability, stale selection, or database failure.
    pub async fn set_canonical_route(
        &self,
        surface: SurfaceTarget,
        audience: &str,
        delivery_route_id: &str,
        expected_resource_version: Option<i64>,
    ) -> Result<CanonicalRouteRecord> {
        if !matches!(audience, "git" | "nix_cache" | "web") {
            bail!("canonical route audience must be git, nix_cache, or web");
        }
        let capability = match audience {
            "git" => "serves_git",
            "nix_cache" => "serves_cache",
            _ => "serves_web",
        };
        let (registry_id, cache_id) = surface.ids();
        let surface_predicate = match surface {
            SurfaceTarget::Registry(_) => "registry_id = ?1 AND cache_id IS NULL",
            SurfaceTarget::BinaryCache(_) => "registry_id IS NULL AND cache_id = ?2",
        };
        let route_surface_predicate = match surface {
            SurfaceTarget::Registry(_) => "r.registry_id = ?1 AND r.cache_id IS NULL",
            SurfaceTarget::BinaryCache(_) => "r.registry_id IS NULL AND r.cache_id = ?2",
        };
        let now = unix_now();
        let affected = if let Some(expected) = expected_resource_version {
            self.backend
                .execute(
                    &format!(
                        "UPDATE canonical_routes SET delivery_route_id = ?4,
                         resource_version = resource_version + 1, updated_at = ?5
                         WHERE {surface_predicate} AND audience = ?3
                           AND resource_version = ?6 AND EXISTS (
                             SELECT 1 FROM delivery_routes r WHERE r.id = ?4
                               AND {route_surface_predicate}
                               AND r.enabled = 1 AND r.{capability} = 1)"
                    ),
                    &vals![
                        registry_id,
                        cache_id,
                        audience,
                        delivery_route_id,
                        now,
                        expected
                    ],
                )
                .await?
        } else {
            self.backend
                .execute(
                    &format!(
                        "INSERT INTO canonical_routes (registry_id, cache_id, audience,
                         delivery_route_id, resource_version, created_at, updated_at)
                         SELECT ?1, ?2, ?3, r.id, 1, ?5, ?5 FROM delivery_routes r
                         WHERE r.id = ?4 AND {route_surface_predicate}
                           AND r.enabled = 1 AND r.{capability} = 1"
                    ),
                    &vals![registry_id, cache_id, audience, delivery_route_id, now],
                )
                .await?
        };
        if affected != 1 {
            bail!("canonical route is missing, stale, disabled, or incompatible");
        }
        self.canonical_route(surface, audience)
            .await?
            .context("canonical route selection disappeared")
    }

    /// Returns one configured canonical route selection.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn canonical_route(
        &self,
        surface: SurfaceTarget,
        audience: &str,
    ) -> Result<Option<CanonicalRouteRecord>> {
        let (registry_id, cache_id) = surface.ids();
        let surface_predicate = match surface {
            SurfaceTarget::Registry(_) => "registry_id = ?1 AND cache_id IS NULL",
            SurfaceTarget::BinaryCache(_) => "registry_id IS NULL AND cache_id = ?2",
        };
        self.backend
            .query_opt(
                &format!(
                    "SELECT registry_id, cache_id, audience, delivery_route_id,
                 resource_version, created_at, updated_at FROM canonical_routes
                 WHERE {surface_predicate} AND audience = ?3"
                ),
                &vals![registry_id, cache_id, audience],
            )
            .await?
            .map(|row| {
                Ok(CanonicalRouteRecord {
                    surface,
                    audience: row.get(2)?,
                    delivery_route_id: row.get(3)?,
                    resource_version: row.get(4)?,
                    created_at: row.get(5)?,
                    updated_at: row.get(6)?,
                })
            })
            .transpose()
    }

    /// Lists the exact consumer-cache stack projected from a signed registry commit.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn registry_cache_stack_entries(
        &self,
        registry_id: i64,
    ) -> Result<Vec<RegistryCacheStackEntryRecord>> {
        self.backend
            .query(
                "SELECT registry_id, stack_path, committed_url, resolved_priority,
                 mirror_group_id, cache_id, delivery_route_id, route_configuration_generation,
                 route_configuration_digest, indexed_commit
                 FROM registry_cache_stack_entries WHERE registry_id = ?1
                 ORDER BY resolved_priority, stack_path",
                &vals![registry_id],
            )
            .await?
            .iter()
            .map(|row| {
                Ok(RegistryCacheStackEntryRecord {
                    registry_id: row.get(0)?,
                    stack_path: row.get(1)?,
                    committed_url: row.get(2)?,
                    resolved_priority: row.get(3)?,
                    mirror_group_id: row.get(4)?,
                    cache_id: row.get(5)?,
                    delivery_route_id: row.get(6)?,
                    route_configuration_generation: row.get(7)?,
                    route_configuration_digest: row.get(8)?,
                    indexed_commit: row.get(9)?,
                })
            })
            .collect()
    }

    /// Lists every signed-registry publication of one managed binary cache.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn cache_registry_stack_entries(
        &self,
        cache_id: i64,
    ) -> Result<Vec<RegistryCacheStackEntryRecord>> {
        self.backend
            .query(
                "SELECT registry_id, stack_path, committed_url, resolved_priority,
                 mirror_group_id, cache_id, delivery_route_id, route_configuration_generation,
                 route_configuration_digest, indexed_commit
                 FROM registry_cache_stack_entries WHERE cache_id = ?1
                 ORDER BY registry_id, resolved_priority, stack_path",
                &vals![cache_id],
            )
            .await?
            .iter()
            .map(|row| {
                Ok(RegistryCacheStackEntryRecord {
                    registry_id: row.get(0)?,
                    stack_path: row.get(1)?,
                    committed_url: row.get(2)?,
                    resolved_priority: row.get(3)?,
                    mirror_group_id: row.get(4)?,
                    cache_id: row.get(5)?,
                    delivery_route_id: row.get(6)?,
                    route_configuration_generation: row.get(7)?,
                    route_configuration_digest: row.get(8)?,
                    indexed_commit: row.get(9)?,
                })
            })
            .collect()
    }

    /// Returns a canonical Nix-cache URL only while its exact route evidence is ready.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn ready_cache_canonical_url(&self, cache_id: i64) -> Result<Option<String>> {
        Ok(self
            .ready_cache_canonical_route_identity(cache_id)
            .await?
            .map(|identity| identity.canonical_url))
    }

    /// Resolves an exact ready delivery URL to its logical binary cache.
    ///
    /// # Errors
    ///
    /// Returns an error when the URL is ambiguous or on database failure.
    pub async fn binary_cache_by_ready_delivery_url(
        &self,
        delivery_url: &str,
    ) -> Result<Option<crate::db::BinaryCache>> {
        let rows = self
            .backend
            .query(
                "SELECT cache.stable_id
                 FROM delivery_routes route
                 JOIN delivery_route_heads head ON head.delivery_route_id = route.id
                 JOIN delivery_route_configurations config
                   ON config.delivery_route_id = head.delivery_route_id
                  AND config.configuration_generation = head.configuration_generation
                  AND config.configuration_digest = head.configuration_digest
                 JOIN delivery_route_observations route_observation
                   ON route_observation.delivery_route_id = route.id
                  AND route_observation.configuration_generation = head.configuration_generation
                  AND route_observation.configuration_digest = head.configuration_digest
                 JOIN delivery_route_access_observations access_observation
                   ON access_observation.delivery_route_id = route.id
                  AND access_observation.configuration_generation = head.configuration_generation
                  AND access_observation.configuration_digest = head.configuration_digest
                  AND access_observation.access_policy_digest = head.access_policy_digest
                 JOIN binary_caches cache ON cache.id = route.cache_id
                 LEFT JOIN orgs org ON org.id = cache.org_id
                 WHERE config.canonical_rendered_url = ?1
                   AND route.cache_id IS NOT NULL AND route.serves_cache = 1
                   AND route.enabled = 1
                   AND route_observation.state IN ('healthy', 'declared')
                   AND access_observation.state = 'verified'
                   AND cache.deleted_at IS NULL
                   AND (cache.org_id IS NULL OR org.deleted_at IS NULL)",
                &vals![delivery_url.trim_end_matches('/')],
            )
            .await?;
        if rows.len() > 1 {
            bail!("delivery URL resolves to more than one binary cache");
        }
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let stable_id: String = row.get(0)?;
        self.binary_cache_by_stable_id(&stable_id).await
    }

    /// Returns the exact ready Nix-cache route identity and immutable URL.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn ready_cache_canonical_route_identity(
        &self,
        cache_id: i64,
    ) -> Result<Option<ReadyCanonicalRouteIdentity>> {
        self.ready_canonical_route_identity(SurfaceTarget::BinaryCache(cache_id), "nix_cache")
            .await
    }

    /// Returns a canonical Git URL only while its exact route evidence is ready.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn ready_registry_canonical_url(&self, registry_id: i64) -> Result<Option<String>> {
        Ok(self
            .ready_canonical_route_identity(SurfaceTarget::Registry(registry_id), "git")
            .await?
            .map(|identity| identity.canonical_url))
    }

    async fn ready_canonical_route_identity(
        &self,
        surface: SurfaceTarget,
        audience: &str,
    ) -> Result<Option<ReadyCanonicalRouteIdentity>> {
        let (registry_id, cache_id) = surface.ids();
        let surface_predicate = match surface {
            SurfaceTarget::Registry(_) => "cr.registry_id = ?1 AND cr.cache_id IS NULL",
            SurfaceTarget::BinaryCache(_) => "cr.registry_id IS NULL AND cr.cache_id = ?2",
        };
        self.backend
            .query_opt(
                &format!(
                    "SELECT r.id, h.configuration_generation,
                   h.configuration_digest, c.canonical_rendered_url FROM canonical_routes cr
                 JOIN delivery_routes r ON r.id = cr.delivery_route_id
                 JOIN delivery_route_heads h ON h.delivery_route_id = r.id
                 JOIN delivery_route_configurations c
                   ON c.delivery_route_id = r.id
                  AND c.configuration_generation = h.configuration_generation
                  AND c.configuration_digest = h.configuration_digest
                 JOIN delivery_route_observations ro
                   ON ro.delivery_route_id = r.id
                  AND ro.configuration_generation = h.configuration_generation
                  AND ro.configuration_digest = h.configuration_digest
                  AND ro.state = 'healthy'
                 JOIN delivery_route_access_observations ao
                   ON ao.delivery_route_id = r.id
                  AND ao.configuration_generation = h.configuration_generation
                  AND ao.configuration_digest = h.configuration_digest
                  AND ao.access_policy_digest = h.access_policy_digest
                  AND ao.state = 'verified'
                 WHERE {surface_predicate} AND cr.audience = ?3
                   AND r.enabled = 1
                   AND (r.mode <> 'direct' OR EXISTS (
                     SELECT 1 FROM direct_delivery_route_evidence de
                     JOIN placement_delivery_manifest_heads mh
                       ON mh.placement_id = de.placement_id
                      AND mh.manifest_id = de.publication_manifest_id
                     JOIN storage_gateways g ON g.id = de.storage_gateway_id
                     JOIN delivery_endpoints e ON e.id = de.endpoint_id
                     JOIN delivery_endpoint_observations eo ON eo.endpoint_id = de.endpoint_id
                     WHERE de.delivery_route_id = r.id
                       AND de.configuration_generation = h.configuration_generation
                       AND de.configuration_digest = h.configuration_digest
                       AND de.endpoint_id = r.endpoint_id
                       AND de.endpoint_generation = r.endpoint_generation
                       AND de.placement_id = r.placement_id
                       AND de.storage_gateway_id = r.storage_gateway_id
                       AND de.gateway_generation = r.gateway_generation
                       AND g.enabled = 1 AND g.desired_generation = de.gateway_generation
                       AND g.observed_generation = de.gateway_generation
                       AND g.reconciliation_state = 'ready'
                       AND eo.observed_generation = de.endpoint_generation
                       AND eo.state = 'healthy' AND eo.listener_observed = 1
                       AND (e.scheme = 'http' OR eo.tls_observed = 1)))"
                ),
                &vals![registry_id, cache_id, audience],
            )
            .await?
            .map(|row| {
                Ok(ReadyCanonicalRouteIdentity {
                    route_id: row.get(0)?,
                    configuration_generation: row.get(1)?,
                    configuration_digest: row.get(2)?,
                    canonical_url: row.get(3)?,
                })
            })
            .transpose()
    }

    /// Loads one exact current route snapshot for reconciliation.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn delivery_route_reconciliation_target(
        &self,
        delivery_route_id: &str,
    ) -> Result<Option<DeliveryRouteReconciliationTarget>> {
        self.backend
            .query_opt(
                "SELECT r.id, h.configuration_generation, h.configuration_digest,
                   r.endpoint_id, r.endpoint_generation,
                   c.canonical_rendered_url, r.mode, h.access_policy_digest,
                   r.access_policy_kind, r.external_provider_kind,
                   r.external_provider_resource_id, r.external_provider_revision,
                   mh.manifest_id
                 FROM delivery_routes r
                 JOIN delivery_route_heads h ON h.delivery_route_id = r.id
                 JOIN delivery_route_configurations c
                   ON c.delivery_route_id = r.id
                  AND c.configuration_generation = h.configuration_generation
                  AND c.configuration_digest = h.configuration_digest
                 LEFT JOIN placement_delivery_manifest_heads mh
                   ON mh.placement_id = r.placement_id
                 WHERE r.id = ?1 AND r.enabled = 1",
                &vals![delivery_route_id],
            )
            .await?
            .map(|row| {
                Ok(DeliveryRouteReconciliationTarget {
                    id: row.get(0)?,
                    configuration_generation: row.get(1)?,
                    configuration_digest: row.get(2)?,
                    endpoint_id: row.get(3)?,
                    endpoint_generation: row.get(4)?,
                    canonical_url: row.get(5)?,
                    mode: row.get(6)?,
                    access_policy_digest: row.get(7)?,
                    access_policy_kind: row.get(8)?,
                    external_provider_kind: row.get(9)?,
                    external_provider_resource_id: row.get(10)?,
                    external_provider_revision: row.get(11)?,
                    publication_manifest_id: row.get(12)?,
                })
            })
            .transpose()
    }

    /// Returns whether a Hub-served route's exact deployed/access state is ready.
    ///
    /// External-provider access is never inferred from configuration and must
    /// be supplied by an observation provider.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn hub_delivery_route_state_ready(
        &self,
        delivery_route_id: &str,
        generation: i64,
        digest: &str,
    ) -> Result<bool> {
        Ok(self
            .backend
            .query_opt(
                "SELECT 1 FROM delivery_routes r
                 JOIN delivery_route_heads h ON h.delivery_route_id = r.id
                 JOIN delivery_endpoints e ON e.id = r.endpoint_id
                 JOIN delivery_endpoint_observations eo ON eo.endpoint_id = e.id
                 JOIN delivery_endpoint_revisions er
                   ON er.endpoint_id = e.id AND er.generation = r.endpoint_generation
                 JOIN network_boundary_revisions ebr
                   ON ebr.boundary_id = er.network_boundary_id
                  AND ebr.revision = er.boundary_revision
                 JOIN network_boundary_revision_lifecycle ebl
                   ON ebl.boundary_id = er.network_boundary_id
                  AND ebl.revision = er.boundary_revision AND ebl.state = 'active'
                 JOIN network_boundary_observations ebo
                   ON ebo.boundary_id = er.network_boundary_id
                  AND ebo.revision = er.boundary_revision AND ebo.state = 'verified'
                 LEFT JOIN network_boundary_revision_lifecycle abl
                   ON abl.boundary_id = r.access_boundary_id
                  AND abl.revision = r.access_boundary_revision
                 LEFT JOIN network_boundary_observations abo
                   ON abo.boundary_id = r.access_boundary_id
                  AND abo.revision = r.access_boundary_revision
                 WHERE r.id = ?1 AND r.mode IN ('hub_proxy', 'hub_redirect')
                   AND r.access_policy_kind <> 'external_provider'
                   AND h.configuration_generation = ?2 AND h.configuration_digest = ?3
                   AND e.desired_generation = r.endpoint_generation
                   AND eo.observed_generation = r.endpoint_generation
                   AND eo.state = 'healthy' AND eo.listener_observed = 1
                   AND (e.scheme = 'http' OR eo.tls_observed = 1)
                   AND ebo.protected_transport_observed = ebr.protected_transport_required
                   AND ebo.trusted_ingress_observed = ebr.trusted_ingress_kind
                   AND (r.access_policy_kind <> 'private_network'
                     OR (abl.state = 'active' AND abo.state = 'verified'
                       AND EXISTS (SELECT 1 FROM network_boundary_revisions abr
                         WHERE abr.boundary_id = r.access_boundary_id
                           AND abr.revision = r.access_boundary_revision
                           AND abo.protected_transport_observed = abr.protected_transport_required
                           AND abo.trusted_ingress_observed = abr.trusted_ingress_kind)))",
                &vals![delivery_route_id, generation, digest],
            )
            .await?
            .is_some())
    }

    /// Atomically replaces route, access, and direct-publication observations.
    ///
    /// Every row is foreign-keyed to the exact current desired generation and
    /// digest. A successful direct observation additionally proves the exact
    /// endpoint, gateway generation, placement, and current publication
    /// manifest; a stale manifest or topology head rolls the whole batch back.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid state combinations, stale evidence, or a
    /// database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn reconcile_delivery_route(
        &self,
        delivery_route_id: &str,
        configuration_generation: i64,
        configuration_digest: &str,
        access_policy_digest: &str,
        route_state: &str,
        access_state: &str,
        error: Option<&str>,
        direct_publication_manifest_id: Option<&str>,
        observed_at: i64,
    ) -> Result<()> {
        if !matches!(route_state, "healthy" | "degraded" | "unreachable")
            || !matches!(access_state, "verified" | "degraded" | "failed")
            || (route_state == "healthy" && access_state == "verified" && error.is_some())
            || ((route_state != "healthy" || access_state != "verified") && error.is_none())
        {
            bail!("route reconciliation has an invalid state/error combination");
        }
        let route = self
            .backend
            .query_opt(
                "SELECT r.mode, r.registry_id, r.cache_id, e.owner_scope_key
                 FROM delivery_routes r
                 JOIN delivery_route_heads h ON h.delivery_route_id = r.id
                 JOIN delivery_endpoints e ON e.id = r.endpoint_id
                 WHERE r.id = ?1 AND h.configuration_generation = ?2
                   AND h.configuration_digest = ?3 AND h.access_policy_digest = ?4",
                &vals![
                    delivery_route_id,
                    configuration_generation,
                    configuration_digest,
                    access_policy_digest
                ],
            )
            .await?
            .context("route reconciliation target is stale")?;
        let mode: String = route.get(0)?;
        let registry_id: Option<i64> = route.get(1)?;
        let cache_id: Option<i64> = route.get(2)?;
        let owner_scope_key: String = route.get(3)?;
        let ready = route_state == "healthy" && access_state == "verified";
        if mode == "direct" && ready && direct_publication_manifest_id.is_none() {
            bail!("ready direct route evidence requires a publication manifest");
        }
        if mode != "direct" && direct_publication_manifest_id.is_some() {
            bail!("only direct routes accept publication-manifest evidence");
        }
        let mut statements = vec![
            Statement::new(
                "DELETE FROM direct_delivery_route_evidence WHERE delivery_route_id = ?1",
                vals![delivery_route_id],
            )
            .unchecked(),
            Statement::new(
                "DELETE FROM delivery_route_access_observations WHERE delivery_route_id = ?1",
                vals![delivery_route_id],
            )
            .unchecked(),
            Statement::new(
                "DELETE FROM delivery_route_observations WHERE delivery_route_id = ?1",
                vals![delivery_route_id],
            )
            .unchecked(),
            Statement::new(
                "INSERT INTO delivery_route_observations
                 (delivery_route_id, registry_id, cache_id, configuration_generation,
                  configuration_digest, state, observed_at, error)
                 SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8
                 WHERE EXISTS (SELECT 1 FROM delivery_route_heads
                   WHERE delivery_route_id = ?1 AND configuration_generation = ?4
                     AND configuration_digest = ?5)",
                vals![
                    delivery_route_id,
                    registry_id,
                    cache_id,
                    configuration_generation,
                    configuration_digest,
                    route_state,
                    observed_at,
                    error
                ],
            )
            .expecting(1),
            Statement::new(
                "INSERT INTO delivery_route_access_observations
                 (delivery_route_id, configuration_generation, configuration_digest,
                  access_policy_digest, state, observed_at, error)
                 SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7
                 WHERE EXISTS (SELECT 1 FROM delivery_route_heads
                   WHERE delivery_route_id = ?1 AND configuration_generation = ?2
                     AND configuration_digest = ?3 AND access_policy_digest = ?4)",
                vals![
                    delivery_route_id,
                    configuration_generation,
                    configuration_digest,
                    access_policy_digest,
                    access_state,
                    observed_at,
                    error
                ],
            )
            .expecting(1),
        ];
        if let Some(manifest_id) = direct_publication_manifest_id {
            statements.push(
                Statement::new(
                    "INSERT INTO direct_delivery_route_evidence
                     (delivery_route_id, registry_id, cache_id, configuration_generation,
                      configuration_digest, endpoint_id, endpoint_generation, placement_id,
                      storage_gateway_id, gateway_generation, publication_manifest_id, observed_at)
                     SELECT r.id, r.registry_id, r.cache_id, h.configuration_generation,
                       h.configuration_digest, r.endpoint_id, r.endpoint_generation,
                       r.placement_id, r.storage_gateway_id, r.gateway_generation, mh.manifest_id, ?6
                     FROM delivery_routes r JOIN delivery_route_heads h
                       ON h.delivery_route_id = r.id
                     JOIN delivery_endpoints e ON e.id = r.endpoint_id
                     JOIN delivery_endpoint_observations eo ON eo.endpoint_id = r.endpoint_id
                     JOIN storage_gateways g ON g.id = r.storage_gateway_id
                     JOIN placement_delivery_manifest_heads mh ON mh.placement_id = r.placement_id
                     WHERE r.id = ?1 AND r.mode = 'direct'
                       AND h.configuration_generation = ?2 AND h.configuration_digest = ?3
                       AND h.access_policy_digest = ?4 AND mh.manifest_id = ?5
                       AND eo.observed_generation = r.endpoint_generation
                       AND eo.state = 'healthy' AND eo.listener_observed = 1
                       AND (e.scheme = 'http' OR eo.tls_observed = 1) AND g.enabled = 1
                       AND g.desired_generation = r.gateway_generation
                       AND g.observed_generation = r.gateway_generation
                       AND g.reconciliation_state = 'ready'",
                    vals![
                        delivery_route_id,
                        configuration_generation,
                        configuration_digest,
                        access_policy_digest,
                        manifest_id,
                        observed_at
                    ],
                )
                .expecting(1),
            );
        }
        let event_id = format!("topology-event:{}", Uuid::new_v4().simple());
        let payload = serde_json::to_string(&serde_json::json!({
            "type": "topology.delivery_route.reconciled",
            "resource_kind": "delivery_route",
            "resource_stable_id": delivery_route_id,
            "resource_generation": configuration_generation,
            "route_state": route_state,
            "access_state": access_state,
        }))?;
        statements.push(Database::topology_event_statement(
            &crate::db::NewTopologyEvent {
                event_id: &event_id,
                event_name: "topology.delivery_route.reconciled",
                owner_scope_key: &owner_scope_key,
                resource_kind: "delivery_route",
                resource_stable_id: delivery_route_id,
                resource_generation_key: configuration_generation,
                actor_kind: "system",
                actor_id: None,
                actor_label: "delivery-route-controller",
                payload_json: &payload,
                occurred_at: observed_at,
            },
        ));
        self.backend.checked_batch(&statements).await
    }

    /// Records the exact managed-cache route reviewed by a signed changeset.
    ///
    /// The indexer activates this identity only after the changeset is applied;
    /// URL equality by itself never establishes managed ownership.
    ///
    /// # Errors
    ///
    /// Returns an error when the changeset, registry, cache, or exact current
    /// canonical route is missing, or on database failure.
    pub async fn record_consumer_cache_publication_intent(
        &self,
        change_id: &str,
        registry_id: i64,
        cache_id: i64,
        route: &ReadyCanonicalRouteIdentity,
    ) -> Result<()> {
        let affected = self
            .backend
            .execute(
                "INSERT INTO consumer_cache_publication_intents
                 (change_id, registry_id, committed_url, cache_id,
                  delivery_route_id, route_configuration_generation,
                 route_configuration_digest, created_at)
                 SELECT ?1, ?2, ?4, ?3, r.id, h.configuration_generation,
                        h.configuration_digest, ?8
                 FROM canonical_routes cr JOIN delivery_routes r
                   ON r.id = cr.delivery_route_id
                 JOIN delivery_route_heads h ON h.delivery_route_id = r.id
                 JOIN delivery_route_configurations c
                   ON c.delivery_route_id = r.id
                  AND c.configuration_generation = ?6
                  AND c.configuration_digest = ?7
                 JOIN delivery_route_observations ro
                   ON ro.delivery_route_id = r.id
                  AND ro.configuration_generation = ?6
                  AND ro.configuration_digest = ?7 AND ro.state = 'healthy'
                 JOIN delivery_route_access_observations ao
                   ON ao.delivery_route_id = r.id
                  AND ao.configuration_generation = ?6
                  AND ao.configuration_digest = ?7 AND ao.state = 'verified'
                 WHERE cr.cache_id = ?3 AND cr.audience = 'nix_cache'
                   AND r.id = ?5 AND h.configuration_generation = ?6
                   AND h.configuration_digest = ?7
                   AND c.canonical_rendered_url = ?4
                   AND r.enabled = 1 AND r.serves_cache = 1
                   AND (r.mode <> 'direct' OR EXISTS (
                     SELECT 1 FROM direct_delivery_route_evidence de
                     JOIN placement_delivery_manifest_heads mh
                       ON mh.placement_id = de.placement_id
                      AND mh.manifest_id = de.publication_manifest_id
                     JOIN storage_gateways g ON g.id = de.storage_gateway_id
                     JOIN delivery_endpoints e ON e.id = de.endpoint_id
                     JOIN delivery_endpoint_observations eo
                       ON eo.endpoint_id = de.endpoint_id
                     WHERE de.delivery_route_id = r.id
                       AND de.configuration_generation = ?6
                       AND de.configuration_digest = ?7
                       AND de.endpoint_id = r.endpoint_id
                       AND de.endpoint_generation = r.endpoint_generation
                       AND de.placement_id = r.placement_id
                       AND de.storage_gateway_id = r.storage_gateway_id
                       AND de.gateway_generation = r.gateway_generation
                       AND g.enabled = 1
                       AND g.desired_generation = de.gateway_generation
                       AND g.observed_generation = de.gateway_generation
                       AND g.reconciliation_state = 'ready'
                       AND eo.observed_generation = de.endpoint_generation
                       AND eo.state = 'healthy'
                       AND eo.listener_observed = 1
                       AND (e.scheme = 'http' OR eo.tls_observed = 1)))
                 ON CONFLICT(change_id, committed_url) DO NOTHING",
                &vals![
                    change_id,
                    registry_id,
                    cache_id,
                    route.canonical_url,
                    route.route_id,
                    route.configuration_generation,
                    route.configuration_digest,
                    unix_now()
                ],
            )
            .await?;
        if affected == 1 {
            return Ok(());
        }
        let existing = self
            .backend
            .query_opt(
                "SELECT cache_id, delivery_route_id, route_configuration_generation,
                        route_configuration_digest
                   FROM consumer_cache_publication_intents
                 WHERE change_id = ?1 AND registry_id = ?2 AND committed_url = ?3",
                &vals![change_id, registry_id, route.canonical_url],
            )
            .await?;
        if let Some(row) = existing {
            if row.get::<i64>(0)? == cache_id
                && row.get::<String>(1)? == route.route_id
                && row.get::<i64>(2)? == route.configuration_generation
                && row.get::<String>(3)? == route.configuration_digest
            {
                return Ok(());
            }
        }
        bail!("managed consumer-cache intent has no exact canonical route or conflicts")
    }

    /// Records that a signed changeset deliberately treats a URL as external.
    ///
    /// This negative identity claim prevents an older managed claim for the
    /// same portable URL from being reused after an explicit replacement.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing changeset/registry, conflicting intent,
    /// or database failure.
    pub async fn record_external_consumer_cache_publication_intent(
        &self,
        change_id: &str,
        registry_id: i64,
        committed_url: &str,
    ) -> Result<()> {
        let affected = self
            .backend
            .execute(
                "INSERT INTO consumer_cache_publication_intents
                 (change_id, registry_id, committed_url, cache_id,
                  delivery_route_id, route_configuration_generation,
                  route_configuration_digest, created_at)
                 VALUES (?1, ?2, ?3, NULL, NULL, NULL, NULL, ?4)
                 ON CONFLICT(change_id, committed_url) DO NOTHING",
                &vals![change_id, registry_id, committed_url, unix_now()],
            )
            .await?;
        if affected == 1 {
            return Ok(());
        }
        let existing = self
            .backend
            .query_opt(
                "SELECT cache_id FROM consumer_cache_publication_intents
                 WHERE change_id = ?1 AND registry_id = ?2 AND committed_url = ?3",
                &vals![change_id, registry_id, committed_url],
            )
            .await?;
        if existing.map(|row| row.get::<Option<i64>>(0)).transpose()? == Some(None) {
            return Ok(());
        }
        bail!("external consumer-cache intent conflicts with an existing claim")
    }

    /// Computes a versioned privacy-minimized route reservation digest.
    ///
    /// # Errors
    ///
    /// Returns an error only when the HMAC implementation rejects the key.
    pub fn route_reservation_digest(
        key: &[u8],
        endpoint_identity_digest: &[u8],
        normalized_base_path: &str,
        canonical_rendered_url: &str,
    ) -> Result<[u8; 32]> {
        let mut mac =
            HmacSha256::new_from_slice(key).context("constructing route reservation HMAC")?;
        mac.update(b"aos-hub-route-reservation-v1\0");
        mac.update(endpoint_identity_digest);
        mac.update(&(normalized_base_path.len() as u32).to_be_bytes());
        mac.update(normalized_base_path.as_bytes());
        mac.update(&(canonical_rendered_url.len() as u32).to_be_bytes());
        mac.update(canonical_rendered_url.as_bytes());
        Ok(mac.finalize().into_bytes().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn route_fixture() -> (Database, i64, DeliveryRouteSpec, String, [u8; 32]) {
        let db = Database::open_in_memory().await.unwrap();
        let org_id = db.create_org("route-probes", "Route probes").await.unwrap();
        let org = db.org_by_slug("route-probes").await.unwrap().unwrap();
        let binding_id = db
            .create_topology_storage_binding(
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
                storage_binding_id: binding_id,
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
        let endpoint_spec = crate::db::DeliveryEndpointRevisionSpec {
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
        db.create_delivery_endpoint(
            "endpoint:route-probes",
            &org.stable_id,
            Some(org_id),
            "https",
            &crate::db::DeliveryEndpointHostInput::Domain(domain.stable_id),
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
        let spec = DeliveryRouteSpec {
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
            storage_gateway_id: None,
            gateway_generation: None,
            target_storage_binding_id: None,
            gateway_client_base_path: None,
            target_placement_prefix: None,
            placement_id: Some(placement.id),
            placement_policy_revision_id: None,
            serves_git: true,
            serves_cache: true,
            serves_web: false,
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

    #[test]
    fn normalizes_route_paths() {
        assert_eq!(normalize_base_path("").unwrap(), "");
        assert_eq!(normalize_base_path("/").unwrap(), "");
        assert_eq!(normalize_base_path("/cache").unwrap(), "/cache");
        assert!(normalize_base_path("cache").is_err());
        assert!(normalize_base_path("/cache/").is_err());
        assert!(normalize_base_path("/../cache").is_err());
    }

    #[test]
    fn reservation_digest_commits_to_path_and_url() {
        let key = [7_u8; 32];
        let endpoint = [9_u8; 32];
        let first = Database::route_reservation_digest(
            &key,
            &endpoint,
            "/cache",
            "https://cache.example/cache",
        );
        let second = Database::route_reservation_digest(
            &key,
            &endpoint,
            "/other",
            "https://cache.example/other",
        );
        assert!(first.is_ok());
        assert!(second.is_ok());
        assert_ne!(first.ok(), second.ok());
    }

    #[tokio::test]
    async fn retained_key_digest_blocks_cross_version_url_reuse() {
        let (db, registry_id, mut spec, url, version_one_digest) = route_fixture().await;
        spec.enabled = false;
        let first = db
            .create_delivery_route(
                "route:reservation-v1",
                SurfaceTarget::Registry(registry_id),
                &spec,
                &url,
                1,
                &version_one_digest,
                &[(1, version_one_digest.to_vec())],
                None,
                "test",
            )
            .await
            .unwrap();
        assert!(db
            .delete_delivery_route(&first.id, first.resource_version, "user", Some(1), "test")
            .await
            .unwrap());
        let endpoint = db
            .delivery_endpoint(&spec.endpoint_id)
            .await
            .unwrap()
            .unwrap();
        let endpoint_digest = hex::decode(endpoint.endpoint_identity_digest).unwrap();
        let version_two_digest = Database::route_reservation_digest(
            &[8_u8; 32],
            &endpoint_digest,
            &spec.base_path,
            &url,
        )
        .unwrap();
        assert!(db
            .create_delivery_route(
                "route:reservation-v2",
                SurfaceTarget::Registry(registry_id),
                &spec,
                &url,
                2,
                &version_two_digest,
                &[
                    (1, version_one_digest.to_vec()),
                    (2, version_two_digest.to_vec()),
                ],
                None,
                "test",
            )
            .await
            .is_err());
        assert!(db
            .delivery_route("route:reservation-v2")
            .await
            .unwrap()
            .is_none());
    }

    #[test]
    fn rejects_open_route_variants_and_forged_access_digests() {
        let access_policy_json = "{}".to_string();
        let mut spec = DeliveryRouteSpec {
            consumer_scope_key: "org:example".to_string(),
            endpoint_id: "endpoint:edge".to_string(),
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
            storage_gateway_id: None,
            gateway_generation: None,
            target_storage_binding_id: None,
            gateway_client_base_path: None,
            target_placement_prefix: None,
            placement_id: Some(1),
            placement_policy_revision_id: None,
            serves_git: false,
            serves_cache: true,
            serves_web: false,
            enabled: true,
        };
        assert_eq!(validate_delivery_route_spec(&spec).unwrap(), "/cache");

        spec.access_policy_digest = "forged".to_string();
        assert!(validate_delivery_route_spec(&spec).is_err());
        spec.access_policy_digest = sha256_hex(&spec.access_policy_json);
        spec.mode = "direct".to_string();
        spec.endpoint_ingress_kind = "external".to_string();
        assert!(validate_delivery_route_spec(&spec).is_err());
    }

    #[tokio::test]
    async fn route_mutation_and_probe_outbox_commit_atomically_and_deduplicate() {
        let (db, registry_id, spec, url, reservation_digest) = route_fixture().await;
        let route = db
            .create_delivery_route(
                "route:atomic",
                SurfaceTarget::Registry(registry_id),
                &spec,
                &url,
                1,
                &reservation_digest,
                &[(1, reservation_digest.to_vec())],
                None,
                "test",
            )
            .await
            .unwrap();
        let digest = route.configuration_digest.clone().unwrap();
        let operation_id = automatic_route_probe_operation_id("create", &route.id, 1, &digest);
        let operation = db.topology_operation(&operation_id).await.unwrap().unwrap();
        assert_eq!(operation.primary_target_generation_key, 1);
        assert_eq!(operation.primary_target_configuration_digest, digest);
        assert_eq!(operation.state, "pending");

        assert!(db
            .create_delivery_route(
                "route:atomic",
                SurfaceTarget::Registry(registry_id),
                &spec,
                &url,
                1,
                &reservation_digest,
                &[(1, reservation_digest.to_vec())],
                None,
                "test",
            )
            .await
            .is_err());
        let count = db
            .backend
            .query_opt(
                "SELECT COUNT(*) FROM topology_operations WHERE operation_id = ?1",
                &vals![operation_id],
            )
            .await
            .unwrap()
            .unwrap()
            .get::<i64>(0)
            .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn domain_probe_completion_promotes_endpoint_and_requeues_routes_atomically() {
        let (db, registry_id, spec, url, reservation_digest) = route_fixture().await;
        let route = db
            .create_delivery_route(
                "route:endpoint-ready",
                SurfaceTarget::Registry(registry_id),
                &spec,
                &url,
                1,
                &reservation_digest,
                &[(1, reservation_digest.to_vec())],
                None,
                "test",
            )
            .await
            .unwrap();
        let route_digest = route.configuration_digest.clone().unwrap();
        let initial_route_operation =
            automatic_route_probe_operation_id("create", &route.id, 1, &route_digest);
        let now = unix_now();
        assert_eq!(
            db.backend
                .execute(
                    "UPDATE topology_operations
                     SET state = 'failed', started_at = ?2, finished_at = ?2,
                         error = 'endpoint was not ready'
                     WHERE operation_id = ?1 AND state = 'pending'",
                    &vals![initial_route_operation, now],
                )
                .await
                .unwrap(),
            1
        );

        let domain = db
            .delivery_domain_by_hostname("route-probes.example.test")
            .await
            .unwrap()
            .unwrap();
        let domain_operation_id = "domain-probe:endpoint-ready";
        let operation = db
            .create_topology_operation(&crate::db::NewTopologyOperation {
                operation_id: domain_operation_id.to_string(),
                operation_kind: "domain_probe".to_string(),
                control_permission: crate::domain::Permission::DomainManage,
                targets: vec![crate::db::NewTopologyOperationTarget {
                    role: "primary".to_string(),
                    target: crate::db::NewTopologyOperationTargetRef::Domain(
                        domain.stable_id.clone(),
                    ),
                    generation_key: domain.resource_version,
                    configuration_digest: String::new(),
                }],
                detail_json: "{}".to_string(),
                progress_total: Some(1),
            })
            .await
            .unwrap();
        let claimed = db
            .claim_domain_probe_operation(&operation.operation_id, operation.resource_version, 120)
            .await
            .unwrap()
            .unwrap();

        let retry_operation_id = sha256_hex(format!(
            "delivery-route-endpoint-ready-v1\0{}\0{}\0{}\0{}",
            domain_operation_id, route.id, 1, route_digest
        ));
        db.create_topology_operation(&crate::db::NewTopologyOperation {
            operation_id: retry_operation_id.clone(),
            operation_kind: "test_collision".to_string(),
            control_permission: crate::domain::Permission::DomainManage,
            targets: vec![crate::db::NewTopologyOperationTarget {
                role: "primary".to_string(),
                target: crate::db::NewTopologyOperationTargetRef::Domain(domain.stable_id.clone()),
                generation_key: domain.resource_version,
                configuration_digest: String::new(),
            }],
            detail_json: "{}".to_string(),
            progress_total: Some(1),
        })
        .await
        .unwrap();
        db.complete_delivery_domain_probe(
            &claimed.operation_id,
            claimed.resource_version,
            &domain.stable_id,
            "unconfigured",
            "unconfigured",
            None,
            domain.resource_version,
            "{}",
            &"a".repeat(64),
            "test-controller",
            now,
            &spec.endpoint_id,
            spec.endpoint_generation,
        )
        .await
        .unwrap_err();
        assert_eq!(
            db.delivery_domain(&domain.stable_id)
                .await
                .unwrap()
                .unwrap()
                .resource_version,
            domain.resource_version
        );
        assert_eq!(
            db.delivery_endpoint(&spec.endpoint_id)
                .await
                .unwrap()
                .unwrap()
                .resource_version,
            1
        );
        db.backend
            .execute(
                "DELETE FROM topology_operations WHERE operation_id = ?1",
                &vals![retry_operation_id],
            )
            .await
            .unwrap();

        let completed = db
            .complete_delivery_domain_probe(
                &claimed.operation_id,
                claimed.resource_version,
                &domain.stable_id,
                "unconfigured",
                "unconfigured",
                None,
                domain.resource_version,
                "{}",
                &"a".repeat(64),
                "test-controller",
                now,
                &spec.endpoint_id,
                spec.endpoint_generation,
            )
            .await
            .unwrap();
        assert_eq!(completed.resource_version, domain.resource_version + 1);
        let endpoint = db
            .delivery_endpoint(&spec.endpoint_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(endpoint.resource_version, 2);
        let observation = db
            .delivery_endpoint_observation(&spec.endpoint_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(observation.state, "healthy");
        assert_eq!(
            observation.observed_generation,
            Some(spec.endpoint_generation)
        );

        let pending = db
            .backend
            .query_opt(
                "SELECT COUNT(*) FROM topology_operations
                 WHERE operation_kind = 'delivery_route_probe'
                   AND primary_target_stable_id = ?1
                   AND primary_target_generation_key = ?2
                   AND primary_target_configuration_digest = ?3
                   AND state = 'pending'",
                &vals![route.id, 1, route_digest],
            )
            .await
            .unwrap()
            .unwrap()
            .get::<i64>(0)
            .unwrap();
        assert_eq!(pending, 1);
    }

    #[tokio::test]
    async fn route_probe_outbox_failure_rolls_back_the_route_mutation() {
        let (db, registry_id, spec, url, reservation_digest) = route_fixture().await;
        let digest = sha256_hex(canonical_json(&spec).unwrap());
        let operation_id =
            automatic_route_probe_operation_id("create", "route:rollback", 1, &digest);
        db.backend
            .execute(
                "INSERT INTO topology_operations
                 (operation_id, operation_kind, authorization_scope_key,
                  control_permission, primary_target_kind, primary_target_stable_id,
                  primary_target_generation_key, primary_target_configuration_digest,
                  state, detail_json, created_at)
                 VALUES (?1, 'delivery_route_probe', 'instance', 'route.manage',
                  'delivery_route', 'collision', 1, ?2, 'pending', '{}', ?3)",
                &vals![operation_id, digest, unix_now()],
            )
            .await
            .unwrap();
        assert!(db
            .create_delivery_route(
                "route:rollback",
                SurfaceTarget::Registry(registry_id),
                &spec,
                &url,
                1,
                &reservation_digest,
                &[(1, reservation_digest.to_vec())],
                None,
                "test",
            )
            .await
            .is_err());
        assert!(db.delivery_route("route:rollback").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn route_update_cancels_stale_probe_and_stale_evidence_is_rejected() {
        let (db, registry_id, mut spec, url, reservation_digest) = route_fixture().await;
        let first = db
            .create_delivery_route(
                "route:supersede",
                SurfaceTarget::Registry(registry_id),
                &spec,
                &url,
                1,
                &reservation_digest,
                &[(1, reservation_digest.to_vec())],
                None,
                "test",
            )
            .await
            .unwrap();
        let first_digest = first.configuration_digest.clone().unwrap();
        let first_operation =
            automatic_route_probe_operation_id("create", &first.id, 1, &first_digest);
        spec.serves_web = true;
        let second = db
            .update_delivery_route(&first.id, &spec, &url, first.resource_version, "test")
            .await
            .unwrap();
        assert_eq!(
            db.topology_operation(&first_operation)
                .await
                .unwrap()
                .unwrap()
                .state,
            "cancelled"
        );
        assert!(db
            .reconcile_delivery_route(
                &first.id,
                1,
                &first_digest,
                &spec.access_policy_digest,
                "healthy",
                "verified",
                None,
                None,
                unix_now(),
            )
            .await
            .is_err());
        let second_digest = second.configuration_digest.clone().unwrap();
        let second_operation =
            automatic_route_probe_operation_id("update", &second.id, 2, &second_digest);
        assert_eq!(
            db.topology_operation(&second_operation)
                .await
                .unwrap()
                .unwrap()
                .state,
            "pending"
        );

        spec.enabled = false;
        let disabled = db
            .update_delivery_route(&second.id, &spec, &url, second.resource_version, "test")
            .await
            .unwrap();
        assert_eq!(
            db.topology_operation(&second_operation)
                .await
                .unwrap()
                .unwrap()
                .state,
            "cancelled"
        );
        assert!(db
            .delete_delivery_route(
                &disabled.id,
                disabled.resource_version,
                "user",
                Some(1),
                "test"
            )
            .await
            .unwrap());
        assert!(db.delivery_route(&disabled.id).await.unwrap().is_none());
    }
}
