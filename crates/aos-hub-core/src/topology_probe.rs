//! Durable scheduling for topology probes that perform external I/O.
//!
//! User-facing verification methods enqueue one of the closed [`TopologyProbe`]
//! variants as a pending generic topology operation. Controllers consume those
//! operations and report measured state through the corresponding reconcile
//! RPC; scheduling never mutates an observation inline.

use std::sync::Arc;

use anyhow::{Context as _, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer as _, Verifier as _};
use serde::Deserialize;
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::backend::BackendBounds;
use crate::db::{
    Database, NetworkPolicyCoordinationRevisionSeal, NetworkPolicyDefaultCas, NewTopologyOperation,
    NewTopologyOperationTarget, NewTopologyOperationTargetRef, TopologyOperationRecord,
};
use crate::domain::Permission;
use crate::web::console::ports::HttpClient;
use crate::{
    clock,
    jobs::{Job, Queue},
};

#[derive(Debug, Deserialize)]
struct BoundaryCoordinationDetail {
    boundary_id: String,
    target_revision: i64,
    target_content_digest: String,
    old_revisions: Vec<NetworkPolicyCoordinationRevisionSeal>,
    default_cas: Option<BoundaryCoordinationDefaultSeal>,
    actor_kind: String,
    actor_id: Option<i64>,
    actor_label: String,
}

#[derive(Debug, Deserialize)]
struct BoundaryCoordinationDefaultSeal {
    boundary_resource_version: i64,
    previous_revision: Option<i64>,
    previous_resource_version: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct GrantRevocationDetail {
    resource_kind: String,
    resource_stable_id: String,
    resource_generation: i64,
    consumer_scope_key: String,
    expected_grant_resource_version: i64,
    resolutions: Vec<GrantRevocationResolution>,
    actor: String,
    request_id: String,
}

#[derive(Debug, Deserialize)]
struct GrantRevocationResolution {
    source: GrantRevocationPin,
    action_kind: String,
    replacement: Option<GrantRevocationTarget>,
    replacement_resource_version: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct GrantRevocationPin {
    pin_id: String,
    target_kind: String,
    target_stable_id: String,
    target_generation_key: i64,
    target_configuration_digest: String,
    target_resource_version: i64,
}

#[derive(Debug, Deserialize)]
struct GrantRevocationTarget {
    #[serde(alias = "resourceKind")]
    resource_kind: String,
    #[serde(alias = "resourceStableId")]
    resource_stable_id: String,
    #[serde(alias = "resourceGeneration")]
    resource_generation: i64,
    #[serde(alias = "configurationDigest")]
    configuration_digest: String,
    #[serde(alias = "expectedResourceVersion")]
    expected_resource_version: String,
}

/// Typed measurements produced by the shared domain controller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainProbeEvidence {
    /// Typed, canonical DNS answers observed across A, AAAA, and CNAME queries.
    pub dns_records: Vec<DnsProbeRecord>,
    /// Whether the runtime completed a verified TLS handshake for the hostname.
    pub tls_handshake_valid: bool,
    /// Exact endpoint identity proven by the pinned responder key.
    pub responder_endpoint_id: String,
    /// Exact immutable endpoint generation proven by the responder.
    pub responder_endpoint_generation: i64,
    /// SHA-256 identity of the pinned responder public key.
    pub responder_key_identity_sha256: String,
    /// Unix timestamp at which the measurements were completed.
    pub observed_at: i64,
    /// Stable runtime/vantage identifier.
    pub probe_location: String,
}

/// Exact active observation returned by a controller-owned route adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteProbeEvidence {
    /// Stable route identity.
    pub route_id: String,
    /// Exact desired route generation.
    pub configuration_generation: i64,
    /// Exact desired route digest.
    pub configuration_digest: String,
    /// Exact endpoint identity observed at the edge.
    pub endpoint_id: String,
    /// Exact endpoint generation observed at the edge.
    pub endpoint_generation: i64,
    /// Exact access-policy digest.
    pub access_policy_digest: String,
    /// Exact current publication manifest for direct delivery.
    pub publication_manifest_id: Option<String>,
    /// External provider implementation kind, when applicable.
    pub external_provider_kind: Option<String>,
    /// External provider resource identity, when applicable.
    pub external_provider_resource_id: Option<String>,
    /// Exact deployed external provider revision, when applicable.
    pub external_provider_revision: Option<String>,
    /// Whether provider configuration was observed live.
    pub provider_configuration_observed: bool,
    /// Whether the exact deployment revision was observed live.
    pub deployment_observed: bool,
    /// Whether the exact access policy was observed live.
    pub access_observed: bool,
    /// Whether traffic reached the active serving edge.
    pub edge_observed: bool,
}

/// Typed fail-closed port for direct and external/CDN route observations.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait RouteObservationProvider: crate::backend::BackendBounds {
    /// Observes one exact immutable desired route at its live edge.
    ///
    /// # Errors
    ///
    /// Returns an error when the provider cannot attest exact configuration,
    /// deployment, access, edge, and publication-manifest evidence.
    async fn observe(
        &self,
        target: &crate::db::RouteReconciliationTarget,
    ) -> Result<RouteProbeEvidence>;
}

/// Purpose-specific evidence from a controller-owned storage credential probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageCredentialProbeEvidence {
    /// Whether the exact credential generation exercised its declared purpose.
    pub valid: bool,
    /// Whether a write probe proved create-if-absent semantics.
    pub conditional_writes_supported: bool,
    /// Sanitized failure classification when `valid` is false.
    pub error: Option<String>,
    /// Provider-neutral evidence safe to retain in operation detail.
    pub evidence: serde_json::Value,
}

/// Controller-owned adapter for real, purpose-specific storage probes.
///
/// Implementations own secret resolution and provider transport. Public RPC
/// callers never supply validation results or credential material.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait StorageCredentialProbeProvider: crate::backend::BackendBounds {
    /// Exercises one exact credential revision against its configured origin.
    ///
    /// # Errors
    ///
    /// Returns an error when the controller cannot perform a trustworthy probe.
    async fn probe(
        &self,
        binding: &crate::db::BindingRecord,
        credential: &crate::db::BindingCredentialRevisionRecord,
        probe_token: &str,
    ) -> Result<StorageCredentialProbeEvidence>;
}

struct UnavailableStorageCredentialProbeProvider;

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl StorageCredentialProbeProvider for UnavailableStorageCredentialProbeProvider {
    async fn probe(
        &self,
        _binding: &crate::db::BindingRecord,
        _credential: &crate::db::BindingCredentialRevisionRecord,
        _probe_token: &str,
    ) -> Result<StorageCredentialProbeEvidence> {
        anyhow::bail!("no controller-owned storage credential probe adapter is configured")
    }
}

/// Controller-owned authenticated provider-control-plane adapter.
///
/// Implementations query the CDN/provider API with controller credentials and
/// return typed evidence for the exact resource revision. Origin responses are
/// not evidence and must never be used to implement this port.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait ExternalRouteControlPlane: crate::backend::BackendBounds {
    /// Observes one exact external-provider resource and deployed revision.
    ///
    /// # Errors
    ///
    /// Returns an error when authenticated control-plane evidence is absent,
    /// stale, or disagrees with the exact desired route generation.
    async fn observe_external(
        &self,
        target: &crate::db::RouteReconciliationTarget,
    ) -> Result<RouteProbeEvidence>;
}

/// Authenticated transport for the fixed Cloudflare v4 control-plane API.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait CloudflareControlPlaneClient: crate::backend::BackendBounds {
    /// GETs one absolute-path Cloudflare API resource with controller credentials.
    async fn get(&self, path: &str) -> Result<Vec<u8>>;
}

/// Cloudflare CDN adapter using authenticated hostname and Access API state.
pub struct CloudflareRouteControlPlane {
    api: Arc<dyn CloudflareControlPlaneClient>,
    edge: Arc<dyn HttpClient>,
}

impl CloudflareRouteControlPlane {
    /// Creates an adapter over authenticated control-plane and hardened edge ports.
    #[must_use]
    pub fn new(api: Arc<dyn CloudflareControlPlaneClient>, edge: Arc<dyn HttpClient>) -> Self {
        Self { api, edge }
    }
}

#[derive(Deserialize)]
struct CloudflareEnvelope {
    success: bool,
    result: serde_json::Value,
}

fn cloudflare_snapshot_revision(snapshot: &serde_json::Value) -> Result<String> {
    Ok(format!(
        "sha256:{}",
        hex::encode(Sha256::digest(serde_json::to_vec(snapshot)?))
    ))
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl ExternalRouteControlPlane for CloudflareRouteControlPlane {
    async fn observe_external(
        &self,
        target: &crate::db::RouteReconciliationTarget,
    ) -> Result<RouteProbeEvidence> {
        anyhow::ensure!(
            target.external_provider_kind.as_deref() == Some("cloudflare"),
            "Cloudflare adapter cannot observe another provider"
        );
        let resource = target
            .external_provider_resource_id
            .as_deref()
            .context("Cloudflare resource identity is absent")?;
        let parts = resource.split('/').collect::<Vec<_>>();
        anyhow::ensure!(
            parts.len() == 8
                && parts[0] == "accounts"
                && parts[2] == "zones"
                && parts[4] == "custom_hostnames"
                && parts[6] == "access_apps"
                && parts.iter().all(|part| {
                    !part.is_empty()
                        && part
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
                }),
            "Cloudflare resource identity must be accounts/<id>/zones/<id>/custom_hostnames/<id>/access_apps/<id>"
        );
        let hostname_path = format!(
            "/client/v4/zones/{}/custom_hostnames/{}",
            parts[3], parts[5]
        );
        let access_path = format!(
            "/client/v4/accounts/{}/access/apps/{}/policies",
            parts[1], parts[7]
        );
        let (hostname, access) =
            futures_util::try_join!(self.api.get(&hostname_path), self.api.get(&access_path),)?;
        anyhow::ensure!(
            hostname.len() <= 1024 * 1024 && access.len() <= 1024 * 1024,
            "Cloudflare API response exceeds 1 MiB"
        );
        let hostname: CloudflareEnvelope = serde_json::from_slice(&hostname)?;
        let access: CloudflareEnvelope = serde_json::from_slice(&access)?;
        anyhow::ensure!(
            hostname.success && access.success,
            "Cloudflare control-plane request failed"
        );
        let snapshot =
            serde_json::json!({ "hostname": hostname.result, "accessPolicies": access.result });
        let revision = cloudflare_snapshot_revision(&snapshot)?;
        anyhow::ensure!(
            target.external_provider_revision.as_deref() == Some(revision.as_str()),
            "Cloudflare control-plane revision does not match desired revision"
        );
        let metadata = snapshot["hostname"]["custom_metadata"]
            .as_object()
            .context("Cloudflare custom hostname lacks AOS controller metadata")?;
        let field = |name: &str| {
            metadata
                .get(name)
                .and_then(serde_json::Value::as_str)
                .context("Cloudflare AOS metadata field is absent")
        };
        anyhow::ensure!(
            field("aos_route_id")? == target.id
                && field("aos_configuration_generation")?.parse::<i64>()?
                    == target.configuration_generation
                && field("aos_configuration_digest")? == target.configuration_digest
                && field("aos_endpoint_id")? == target.endpoint_id
                && field("aos_endpoint_generation")?.parse::<i64>()? == target.endpoint_generation
                && field("aos_access_policy_digest")? == target.access_policy_digest,
            "Cloudflare controller metadata does not match exact desired topology"
        );
        let liveness =
            validated_route_liveness_url(&target.canonical_url, field("aos_liveness_url")?)?;
        let body = self.edge.get(liveness.as_str()).await?;
        anyhow::ensure!(
            hex::encode(Sha256::digest(&body)) == field("aos_liveness_sha256")?,
            "Cloudflare edge bytes do not match authenticated control-plane metadata"
        );
        Ok(RouteProbeEvidence {
            route_id: target.id.clone(),
            configuration_generation: target.configuration_generation,
            configuration_digest: target.configuration_digest.clone(),
            endpoint_id: target.endpoint_id.clone(),
            endpoint_generation: target.endpoint_generation,
            access_policy_digest: target.access_policy_digest.clone(),
            publication_manifest_id: target.publication_manifest_id.clone(),
            external_provider_kind: target.external_provider_kind.clone(),
            external_provider_resource_id: target.external_provider_resource_id.clone(),
            external_provider_revision: target.external_provider_revision.clone(),
            provider_configuration_observed: true,
            deployment_observed: true,
            access_observed: true,
            edge_observed: true,
        })
    }
}

/// Dispatches direct and external routes to distinct typed trust adapters.
pub struct ControllerOwnedRouteObservationProvider {
    direct: Option<Arc<dyn RouteObservationProvider>>,
    external: Option<Arc<dyn ExternalRouteControlPlane>>,
}

impl ControllerOwnedRouteObservationProvider {
    /// Creates a fail-closed adapter set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            direct: None,
            external: None,
        }
    }

    /// Installs signed-publication evidence for direct delivery.
    #[must_use]
    pub fn with_direct(mut self, direct: Arc<dyn RouteObservationProvider>) -> Self {
        self.direct = Some(direct);
        self
    }

    /// Installs authenticated provider-control-plane evidence for CDN delivery.
    #[must_use]
    pub fn with_external(mut self, external: Arc<dyn ExternalRouteControlPlane>) -> Self {
        self.external = Some(external);
        self
    }
}

impl Default for ControllerOwnedRouteObservationProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl RouteObservationProvider for ControllerOwnedRouteObservationProvider {
    async fn observe(
        &self,
        target: &crate::db::RouteReconciliationTarget,
    ) -> Result<RouteProbeEvidence> {
        if target.mode == "direct" {
            return self
                .direct
                .as_deref()
                .context("direct-route signed-publication adapter is not configured")?
                .observe(target)
                .await;
        }
        if target.access_policy_kind == "external_provider" {
            return self
                .external
                .as_deref()
                .context("external provider control-plane adapter is not configured")?
                .observe_external(target)
                .await;
        }
        anyhow::bail!("route does not require an external observation adapter")
    }
}

/// Fail-closed route adapter used until a runtime installs controller-owned evidence.
pub struct UnavailableRouteObservationProvider;

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl RouteObservationProvider for UnavailableRouteObservationProvider {
    async fn observe(
        &self,
        _target: &crate::db::RouteReconciliationTarget,
    ) -> Result<RouteProbeEvidence> {
        anyhow::bail!("no controller-owned delivery-route observation adapter is configured")
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SignedPublicationManifestEnvelope {
    payload: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicationManifestSet {
    version: u8,
    issued_at: i64,
    expires_at: i64,
    routes: Vec<PublicationManifestRoute>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicationManifestRoute {
    route_id: String,
    configuration_generation: i64,
    configuration_digest: String,
    endpoint_id: String,
    endpoint_generation: i64,
    access_policy_digest: String,
    publication_manifest_id: String,
    liveness_url: String,
    liveness_sha256: String,
}

/// Direct-route adapter backed by a controller-pinned signed publication manifest.
///
/// The manifest is controller configuration, not content read from the probed
/// origin. A route becomes observable only when its exact immutable identity is
/// signed and bytes fetched from that route match the signed liveness digest.
pub struct SignedManifestRouteObservationProvider {
    http: Arc<dyn HttpClient>,
    manifest: PublicationManifestSet,
}

impl SignedManifestRouteObservationProvider {
    /// Verifies and loads a signed direct-publication manifest.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed or non-canonical base64url, an invalid
    /// Ed25519 signature, duplicate route generations, or invalid bounds.
    pub fn from_signed_json(
        json: &str,
        verifying_key: &str,
        now: i64,
        http: Arc<dyn HttpClient>,
    ) -> Result<Self> {
        anyhow::ensure!(
            json.len() <= 1024 * 1024,
            "publication manifest exceeds 1 MiB"
        );
        let envelope: SignedPublicationManifestEnvelope =
            serde_json::from_str(json).context("decoding signed publication manifest envelope")?;
        let payload = URL_SAFE_NO_PAD
            .decode(&envelope.payload)
            .context("publication manifest payload is not base64url")?;
        anyhow::ensure!(
            URL_SAFE_NO_PAD.encode(&payload) == envelope.payload,
            "publication manifest payload is not canonical base64url"
        );
        let signature_bytes = URL_SAFE_NO_PAD
            .decode(&envelope.signature)
            .context("publication manifest signature is not base64url")?;
        anyhow::ensure!(
            URL_SAFE_NO_PAD.encode(&signature_bytes) == envelope.signature,
            "publication manifest signature is not canonical base64url"
        );
        let public_key: [u8; 32] = URL_SAFE_NO_PAD
            .decode(verifying_key)
            .context("publication manifest public key is not base64url")?
            .try_into()
            .map_err(|_| {
                anyhow::anyhow!("publication manifest public key must contain 32 bytes")
            })?;
        let signature = ed25519_dalek::Signature::from_slice(&signature_bytes)
            .context("publication manifest signature must contain 64 bytes")?;
        ed25519_dalek::VerifyingKey::from_bytes(&public_key)
            .context("publication manifest public key is invalid")?
            .verify(&payload, &signature)
            .context("publication manifest signature is invalid")?;
        let manifest: PublicationManifestSet =
            serde_json::from_slice(&payload).context("decoding publication manifest payload")?;
        anyhow::ensure!(
            manifest.version == 1
                && manifest.issued_at <= now
                && manifest.expires_at >= now
                && manifest.expires_at - manifest.issued_at <= 24 * 60 * 60,
            "publication manifest version or validity window is invalid"
        );
        anyhow::ensure!(
            manifest.routes.len() <= 4096,
            "publication manifest has too many routes"
        );
        let mut identities = std::collections::BTreeSet::new();
        for route in &manifest.routes {
            anyhow::ensure!(
                route.configuration_generation > 0
                    && route.endpoint_generation > 0
                    && route.configuration_digest.len() == 64
                    && route.access_policy_digest.len() == 64
                    && route.liveness_sha256.len() == 64
                    && !route.publication_manifest_id.is_empty(),
                "publication manifest route has invalid identity bounds"
            );
            anyhow::ensure!(
                identities.insert((route.route_id.clone(), route.configuration_generation)),
                "publication manifest contains a duplicate route generation"
            );
        }
        Ok(Self { http, manifest })
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl RouteObservationProvider for SignedManifestRouteObservationProvider {
    async fn observe(
        &self,
        target: &crate::db::RouteReconciliationTarget,
    ) -> Result<RouteProbeEvidence> {
        anyhow::ensure!(
            target.mode == "direct",
            "signed publication adapter only observes direct routes"
        );
        let now = clock::now_unix_secs();
        anyhow::ensure!(
            self.manifest.issued_at <= now && self.manifest.expires_at >= now,
            "signed publication manifest is not currently valid"
        );
        let route = self
            .manifest
            .routes
            .iter()
            .find(|route| {
                route.route_id == target.id
                    && route.configuration_generation == target.configuration_generation
            })
            .context("signed publication manifest has no exact route generation")?;
        anyhow::ensure!(
            route.configuration_digest == target.configuration_digest
                && route.endpoint_id == target.endpoint_id
                && route.endpoint_generation == target.endpoint_generation
                && route.access_policy_digest == target.access_policy_digest
                && Some(route.publication_manifest_id.as_str())
                    == target.publication_manifest_id.as_deref(),
            "signed publication manifest does not match exact desired route state"
        );
        let liveness = validated_route_liveness_url(&target.canonical_url, &route.liveness_url)?;
        let body = self.http.get(liveness.as_str()).await?;
        anyhow::ensure!(
            hex::encode(Sha256::digest(&body)) == route.liveness_sha256,
            "live edge bytes do not match the signed publication manifest"
        );
        Ok(RouteProbeEvidence {
            route_id: route.route_id.clone(),
            configuration_generation: route.configuration_generation,
            configuration_digest: route.configuration_digest.clone(),
            endpoint_id: route.endpoint_id.clone(),
            endpoint_generation: route.endpoint_generation,
            access_policy_digest: route.access_policy_digest.clone(),
            publication_manifest_id: Some(route.publication_manifest_id.clone()),
            external_provider_kind: None,
            external_provider_resource_id: None,
            external_provider_revision: None,
            provider_configuration_observed: true,
            deployment_observed: true,
            access_observed: true,
            edge_observed: true,
        })
    }
}

fn validated_route_liveness_url(canonical_url: &str, liveness_url: &str) -> Result<url::Url> {
    let canonical = url::Url::parse(canonical_url).context("route canonical URL is malformed")?;
    let liveness = url::Url::parse(liveness_url).context("manifest liveness URL is malformed")?;
    let canonical_base = canonical.path().trim_end_matches('/');
    let path_contained = liveness.path() == canonical_base
        || liveness
            .path()
            .strip_prefix(canonical_base)
            .is_some_and(|suffix| suffix.starts_with('/'));
    anyhow::ensure!(
        canonical.scheme() == liveness.scheme()
            && canonical.host_str() == liveness.host_str()
            && canonical.port_or_known_default() == liveness.port_or_known_default()
            && canonical.username().is_empty()
            && canonical.password().is_none()
            && canonical.query().is_none()
            && canonical.fragment().is_none()
            && liveness.username().is_empty()
            && liveness.password().is_none()
            && liveness.query().is_none()
            && liveness.fragment().is_none()
            && path_contained,
        "manifest liveness URL is outside the exact route origin and base path"
    );
    Ok(liveness)
}

fn validate_route_evidence(
    target: &crate::db::RouteReconciliationTarget,
    evidence: &RouteProbeEvidence,
) -> Result<()> {
    anyhow::ensure!(
        evidence.route_id == target.id
            && evidence.configuration_generation == target.configuration_generation
            && evidence.configuration_digest == target.configuration_digest
            && evidence.endpoint_id == target.endpoint_id
            && evidence.endpoint_generation == target.endpoint_generation
            && evidence.access_policy_digest == target.access_policy_digest
            && evidence.publication_manifest_id == target.publication_manifest_id
            && evidence.external_provider_kind == target.external_provider_kind
            && evidence.external_provider_resource_id == target.external_provider_resource_id
            && evidence.external_provider_revision == target.external_provider_revision
            && evidence.provider_configuration_observed
            && evidence.deployment_observed
            && evidence.access_observed
            && evidence.edge_observed,
        "delivery-route probe did not attest the exact desired topology"
    );
    Ok(())
}

/// One canonical DNS answer used as domain-verification evidence.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsProbeRecord {
    /// Canonical owner hostname without a trailing dot.
    pub owner: String,
    /// Closed DNS record type (`A`, `AAAA`, or `CNAME`).
    pub record_type: String,
    /// Canonical IP address or target hostname.
    pub target: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct DnsJsonResponse {
    #[serde(rename = "Status")]
    status: i64,
    #[serde(rename = "Answer", default)]
    answer: Vec<DnsJsonAnswer>,
}

#[derive(Debug, Deserialize, Serialize)]
struct DnsJsonAnswer {
    #[serde(rename = "name")]
    name: String,
    #[serde(rename = "type")]
    record_type: u16,
    data: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TlsProbeStatement {
    version: u8,
    issued_at: i64,
    expires_at: i64,
    nonce: String,
    hostname: String,
    endpoint_id: String,
    endpoint_generation: i64,
    responder_key_identity_sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SignedTlsProbeResponse {
    payload: String,
    signature: String,
}

/// Runtime facts signed by a configured endpoint-generation terminator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainProbeResponseInput {
    /// Challenge supplied by the controller.
    pub nonce: String,
    /// Canonical request hostname.
    pub hostname: String,
    /// Stable endpoint identity.
    pub endpoint_id: String,
    /// Exact endpoint generation holding the public-key pin.
    pub endpoint_generation: i64,
    /// Response issue time.
    pub issued_at: i64,
}

/// Builds the canonical Ed25519-signed well-known probe response.
///
/// # Errors
///
/// Returns an error for an invalid hostname or generation.
pub fn sign_domain_probe_response(
    signing_key: &ed25519_dalek::SigningKey,
    mut input: DomainProbeResponseInput,
) -> Result<Vec<u8>> {
    input.hostname = crate::db::canonical_delivery_hostname(&input.hostname)?;
    anyhow::ensure!(
        input.endpoint_generation > 0,
        "endpoint generation must be positive"
    );
    let statement = TlsProbeStatement {
        version: 2,
        issued_at: input.issued_at,
        expires_at: input.issued_at + TLS_PROOF_MAX_LIFETIME_SECONDS,
        nonce: input.nonce,
        hostname: input.hostname,
        endpoint_id: input.endpoint_id.clone(),
        endpoint_generation: input.endpoint_generation,
        responder_key_identity_sha256: hex::encode(Sha256::digest(
            signing_key.verifying_key().as_bytes(),
        )),
    };
    let payload_bytes = serde_json::to_vec(&statement)?;
    let signature = signing_key.sign(&payload_bytes);
    serde_json::to_vec(&SignedTlsProbeResponse {
        payload: URL_SAFE_NO_PAD.encode(payload_bytes),
        signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    })
    .map_err(Into::into)
}

/// Private-key material supplied by a terminator.
pub struct DomainProbeTerminatorMaterial {
    /// Per-endpoint-generation signing key resolved from the configured secret reference.
    pub signing_key: ed25519_dalek::SigningKey,
}

/// Resolves private signing material inside the TLS terminator's trust boundary.
pub trait DomainProbeTerminatorProvider: crate::backend::BackendBounds {
    /// Resolves one exact provider-owned secret reference.
    ///
    /// # Errors
    ///
    /// Returns an error when the provider cannot prove it installed the exact
    /// endpoint-generation identity.
    fn resolve(
        &self,
        endpoint_id: &str,
        endpoint_generation: i64,
        identity: &crate::db::EndpointProbeSigningIdentity,
    ) -> Result<DomainProbeTerminatorMaterial>;
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DomainProbeTerminatorManifestEntry {
    endpoint_id: String,
    endpoint_generation: i64,
    signer_secret_ref: String,
    signing_seed: String,
}

/// In-memory provider loaded from an operator-managed secret manifest.
pub struct ManifestDomainProbeTerminatorProvider {
    provider_kind: String,
    entries: std::collections::BTreeMap<(String, i64, String), DomainProbeTerminatorManifestEntry>,
}

impl ManifestDomainProbeTerminatorProvider {
    /// Loads a secret manifest supplied by a native file or Worker secret.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed JSON, duplicate identities, or malformed
    /// Ed25519 seed material.
    pub fn from_json(json: &str, provider_kind: &str) -> Result<Self> {
        anyhow::ensure!(
            matches!(provider_kind, "native_file" | "worker_secret"),
            "manifest responder provider must be native_file or worker_secret"
        );
        let entries: Vec<DomainProbeTerminatorManifestEntry> =
            serde_json::from_str(json).context("decoding domain probe terminator manifest")?;
        let mut indexed = std::collections::BTreeMap::new();
        for entry in entries {
            anyhow::ensure!(entry.endpoint_generation > 0, "invalid endpoint generation");
            let seed: [u8; 32] = URL_SAFE_NO_PAD
                .decode(&entry.signing_seed)
                .context("domain probe signing seed is not base64url")?
                .try_into()
                .map_err(|_| anyhow::anyhow!("domain probe signing seed must contain 32 bytes"))?;
            let _ = ed25519_dalek::SigningKey::from_bytes(&seed);
            let key = (
                entry.endpoint_id.clone(),
                entry.endpoint_generation,
                entry.signer_secret_ref.clone(),
            );
            anyhow::ensure!(
                indexed.insert(key, entry).is_none(),
                "duplicate terminator identity"
            );
        }
        Ok(Self {
            provider_kind: provider_kind.to_string(),
            entries: indexed,
        })
    }
}

impl DomainProbeTerminatorProvider for ManifestDomainProbeTerminatorProvider {
    fn resolve(
        &self,
        endpoint_id: &str,
        endpoint_generation: i64,
        identity: &crate::db::EndpointProbeSigningIdentity,
    ) -> Result<DomainProbeTerminatorMaterial> {
        anyhow::ensure!(
            identity.provider == self.provider_kind,
            "endpoint-generation probe provider is not owned by this runtime"
        );
        let entry = self
            .entries
            .get(&(
                endpoint_id.to_string(),
                endpoint_generation,
                identity.signer_secret_ref.clone(),
            ))
            .context("terminator manifest has no exact endpoint-generation secret reference")?;
        let seed: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&entry.signing_seed)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("domain probe signing seed must contain 32 bytes"))?;
        Ok(DomainProbeTerminatorMaterial {
            signing_key: ed25519_dalek::SigningKey::from_bytes(&seed),
        })
    }
}

/// Serves one replay-protected well-known probe response.
///
/// # Errors
///
/// Returns an error for an invalid authority/nonce, absent endpoint-generation
/// pin, provider failure, replay, or database failure.
pub async fn respond_to_domain_probe(
    db: &Database,
    provider: &dyn DomainProbeTerminatorProvider,
    authority: &str,
    nonce: &str,
    now: i64,
) -> Result<Vec<u8>> {
    let nonce_bytes = URL_SAFE_NO_PAD
        .decode(nonce)
        .context("domain probe nonce is not base64url")?;
    anyhow::ensure!(
        nonce_bytes.len() == 32 && URL_SAFE_NO_PAD.encode(&nonce_bytes) == nonce,
        "domain probe nonce is not a canonical 256-bit challenge"
    );
    let authority_url = url::Url::parse(&format!("https://{authority}/"))
        .context("domain probe authority is malformed")?;
    anyhow::ensure!(
        authority_url.port_or_known_default() == Some(443),
        "domain probe responder requires HTTPS port 443"
    );
    let hostname = crate::db::canonical_delivery_hostname(
        authority_url
            .host_str()
            .context("domain probe authority has no hostname")?,
    )?;
    let domain = db
        .delivery_domain_by_hostname(&hostname)
        .await?
        .context("domain probe hostname is not configured")?;
    let (endpoint_id, endpoint_generation, identity) =
        db.domain_probe_signing_identity(domain.id).await?;
    let material = provider.resolve(&endpoint_id, endpoint_generation, &identity)?;
    anyhow::ensure!(
        URL_SAFE_NO_PAD.encode(material.signing_key.verifying_key().as_bytes())
            == identity.public_key,
        "terminator private key does not match the endpoint-generation public-key pin"
    );
    let response = sign_domain_probe_response(
        &material.signing_key,
        DomainProbeResponseInput {
            nonce: nonce.to_string(),
            hostname,
            endpoint_id: endpoint_id.clone(),
            endpoint_generation,
            issued_at: now,
        },
    )?;
    anyhow::ensure!(
        db.consume_domain_probe_nonce(nonce, &endpoint_id, endpoint_generation, now)
            .await?,
        "domain probe nonce was already consumed"
    );
    Ok(response)
}

const TLS_PROOF_MAX_LIFETIME_SECONDS: i64 = 30;
const TLS_PROOF_FUTURE_SKEW_SECONDS: i64 = 5;

/// Verifies signed, nonce-bound TLS-terminator identity statements.
#[derive(Clone, Default)]
pub struct DomainTlsProbeVerifier;

impl DomainTlsProbeVerifier {
    /// Creates a verifier for database-issued random challenges.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    fn verify(
        &self,
        response: &[u8],
        nonce: &str,
        hostname: &str,
        endpoint_id: &str,
        endpoint_generation: i64,
        identity: &crate::db::EndpointProbeSigningIdentity,
        now: i64,
    ) -> Result<TlsProbeStatement> {
        let envelope: SignedTlsProbeResponse = serde_json::from_slice(response)
            .context("decoding signed domain TLS proof envelope")?;
        let payload = URL_SAFE_NO_PAD
            .decode(&envelope.payload)
            .context("decoding domain TLS proof payload")?;
        let signature = URL_SAFE_NO_PAD
            .decode(&envelope.signature)
            .context("decoding domain TLS proof signature")?;
        anyhow::ensure!(
            URL_SAFE_NO_PAD.encode(&payload) == envelope.payload
                && URL_SAFE_NO_PAD.encode(&signature) == envelope.signature,
            "domain TLS proof is not canonically encoded"
        );
        let statement: TlsProbeStatement =
            serde_json::from_slice(&payload).context("decoding signed domain TLS proof")?;
        anyhow::ensure!(
            serde_json::to_vec(&statement)? == payload,
            "domain TLS proof payload is not canonical"
        );
        let public_key: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&identity.public_key)
            .context("decoding endpoint probe public key")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("endpoint probe public key must contain 32 bytes"))?;
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key)
            .context("endpoint probe public key is invalid")?;
        let signature = ed25519_dalek::Signature::from_slice(&signature)
            .context("domain TLS proof signature is malformed")?;
        verifying_key
            .verify(&payload, &signature)
            .map_err(|_| anyhow::anyhow!("domain TLS proof signature is invalid"))?;
        anyhow::ensure!(
            statement.version == 2,
            "unsupported domain TLS proof version"
        );
        anyhow::ensure!(statement.nonce == nonce, "domain TLS proof nonce mismatch");
        anyhow::ensure!(
            statement.responder_key_identity_sha256
                == hex::encode(Sha256::digest(verifying_key.as_bytes())),
            "domain TLS proof signer identity mismatch"
        );
        anyhow::ensure!(
            statement.endpoint_id == endpoint_id
                && statement.endpoint_generation == endpoint_generation,
            "domain TLS proof names another endpoint generation"
        );
        anyhow::ensure!(
            statement.issued_at <= now + TLS_PROOF_FUTURE_SKEW_SECONDS
                && statement.expires_at >= now
                && statement.expires_at >= statement.issued_at
                && statement.expires_at - statement.issued_at <= TLS_PROOF_MAX_LIFETIME_SECONDS,
            "domain TLS proof is outside its freshness window"
        );
        anyhow::ensure!(
            crate::db::canonical_delivery_hostname(&statement.hostname)?
                == crate::db::canonical_delivery_hostname(hostname)?,
            "domain TLS proof names another hostname"
        );
        Ok(statement)
    }
}

/// One closed, immutable probe request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TopologyProbe {
    /// Verifies DNS ownership and certificate posture for a domain.
    Domain {
        /// Stable domain identity.
        stable_id: String,
        /// Resource version whose desired configuration is being verified.
        resource_version: i64,
    },
    /// Measures enforcement of one immutable network-boundary revision.
    NetworkPolicy {
        /// Stable boundary identity.
        stable_id: String,
        /// Exact immutable revision.
        revision: i64,
        /// Exact revision content digest.
        configuration_digest: String,
    },
    /// Measures one immutable delivery-endpoint generation.
    Endpoint {
        /// Stable endpoint identity.
        stable_id: String,
        /// Exact immutable generation.
        generation: i64,
        /// Exact generation content digest.
        configuration_digest: String,
    },
    /// Measures one immutable delivery-route configuration.
    Route {
        /// Stable route identity.
        stable_id: String,
        /// Exact immutable configuration generation.
        generation: i64,
        /// Exact configuration digest.
        configuration_digest: String,
    },
    /// Validates one immutable purpose-scoped storage credential generation.
    StorageCredential {
        /// Stable storage-binding identity.
        stable_id: String,
        /// Database identity resolved by the authorized service.
        binding_id: i64,
        /// Exact binding resource version at scheduling time.
        binding_resource_version: i64,
        /// Closed capability purpose being exercised.
        purpose: String,
        /// Exact immutable credential generation.
        generation: i64,
        /// Credential-head resource version guarding the observation write.
        credential_head_resource_version: i64,
    },
}

/// Schedules typed probes as durable pending operations.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait TopologyProbeScheduler: BackendBounds {
    /// Creates and queues one probe operation.
    ///
    /// # Errors
    ///
    /// Returns an error when the target snapshot is stale or persistence fails.
    async fn schedule(
        &self,
        operation_id: &str,
        probe: TopologyProbe,
    ) -> Result<TopologyOperationRecord>;

    /// Wakes the controller for durable operations created outside this scheduler.
    ///
    /// # Errors
    ///
    /// Returns an error when the runtime queue cannot accept the wakeup.
    async fn wake_controller(&self) -> Result<()>;
}

/// Database-backed durable probe queue used by both Hub runtimes.
pub struct DatabaseTopologyProbeScheduler {
    db: Arc<Database>,
    wakeup: Option<Arc<dyn Queue>>,
}

impl DatabaseTopologyProbeScheduler {
    /// Creates a scheduler over the shared Hub database.
    #[must_use]
    pub fn new(db: Arc<Database>) -> Self {
        Self { db, wakeup: None }
    }

    /// Attaches the runtime queue used to wake an asynchronous controller.
    #[must_use]
    pub fn with_wakeup(mut self, wakeup: Arc<dyn Queue>) -> Self {
        self.wakeup = Some(wakeup);
        self
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl TopologyProbeScheduler for DatabaseTopologyProbeScheduler {
    async fn schedule(
        &self,
        operation_id: &str,
        probe: TopologyProbe,
    ) -> Result<TopologyOperationRecord> {
        let (
            kind,
            target_kind,
            target_stable_id,
            target,
            generation_key,
            configuration_digest,
            control_permission,
            detail,
        ) = match probe {
            TopologyProbe::Domain {
                stable_id,
                resource_version,
            } => (
                "domain_probe",
                "domain",
                stable_id.clone(),
                NewTopologyOperationTargetRef::Domain(stable_id.clone()),
                resource_version,
                String::new(),
                Permission::DomainManage,
                serde_json::json!({
                    "domainId": stable_id,
                    "resourceVersion": resource_version,
                }),
            ),
            TopologyProbe::NetworkPolicy {
                stable_id,
                revision,
                configuration_digest,
            } => (
                "network_policy_probe",
                "network_policy",
                stable_id.clone(),
                NewTopologyOperationTargetRef::NetworkPolicy(stable_id.clone()),
                revision,
                configuration_digest.clone(),
                Permission::NetworkPolicyManage,
                serde_json::json!({ "networkBoundaryId": stable_id, "revision": revision }),
            ),
            TopologyProbe::Endpoint {
                stable_id,
                generation,
                configuration_digest,
            } => (
                "endpoint_probe",
                "endpoint",
                stable_id.clone(),
                NewTopologyOperationTargetRef::Endpoint(stable_id.clone()),
                generation,
                configuration_digest.clone(),
                Permission::EndpointManage,
                serde_json::json!({ "deliveryEndpointId": stable_id, "generation": generation }),
            ),
            TopologyProbe::Route {
                stable_id,
                generation,
                configuration_digest,
            } => (
                "route_probe",
                "route",
                stable_id.clone(),
                NewTopologyOperationTargetRef::Route(stable_id.clone()),
                generation,
                configuration_digest.clone(),
                Permission::RouteManage,
                serde_json::json!({ "deliveryRouteId": stable_id, "generation": generation }),
            ),
            TopologyProbe::StorageCredential {
                stable_id,
                binding_id,
                binding_resource_version,
                purpose,
                generation,
                credential_head_resource_version,
            } => {
                let probe_token = hex::encode(Sha256::digest(
                    format!("storage-probe-token-v1\0{operation_id}\0{stable_id}").as_bytes(),
                ));
                (
                    "storage_credential_probe",
                    "binding",
                    stable_id.clone(),
                    NewTopologyOperationTargetRef::Binding(binding_id),
                    binding_resource_version,
                    String::new(),
                    Permission::BindingManage,
                    serde_json::json!({
                        "bindingId": stable_id,
                        "purpose": purpose,
                        "credentialGeneration": generation,
                        "credentialHeadResourceVersion": credential_head_resource_version,
                        "probeToken": probe_token,
                    }),
                )
            }
        };
        if let Some(existing) = self.db.topology_operation(operation_id).await? {
            let targets = self.db.topology_operation_targets(operation_id).await?;
            if existing.operation_kind == kind
                && targets.len() == 1
                && targets[0].role == "primary"
                && targets[0].target_kind == target_kind
                && targets[0].stable_id == target_stable_id
                && targets[0].generation_key == generation_key
                && targets[0].configuration_digest == configuration_digest
            {
                if matches!(existing.state.as_str(), "pending" | "running") {
                    if let Some(wakeup) = &self.wakeup {
                        wakeup.enqueue(&Job::RunTopologyProbes).await?;
                    }
                }
                return Ok(existing);
            }
            anyhow::bail!("probe idempotency key is already used by another operation");
        }
        let created = self
            .db
            .create_topology_operation(&NewTopologyOperation {
                operation_id: operation_id.to_string(),
                operation_kind: kind.to_string(),
                control_permission,
                targets: vec![NewTopologyOperationTarget {
                    role: "primary".to_string(),
                    target,
                    generation_key,
                    configuration_digest: configuration_digest.clone(),
                }],
                detail_json: detail.to_string(),
                progress_total: None,
            })
            .await;
        let operation = match created {
            Ok(operation) => Ok(operation),
            Err(error) => {
                let Some(existing) = self.db.topology_operation(operation_id).await? else {
                    return Err(error);
                };
                let targets = self.db.topology_operation_targets(operation_id).await?;
                if existing.operation_kind == kind
                    && targets.len() == 1
                    && targets[0].role == "primary"
                    && targets[0].target_kind == target_kind
                    && targets[0].stable_id == target_stable_id
                    && targets[0].generation_key == generation_key
                    && targets[0].configuration_digest == configuration_digest
                {
                    Ok(existing)
                } else {
                    Err(error)
                }
            }
        }?;
        if matches!(operation.state.as_str(), "pending" | "running") {
            if let Some(wakeup) = &self.wakeup {
                wakeup.enqueue(&Job::RunTopologyProbes).await?;
            }
        }
        Ok(operation)
    }

    async fn wake_controller(&self) -> Result<()> {
        if let Some(wakeup) = &self.wakeup {
            wakeup.enqueue(&Job::RunTopologyProbes).await?;
        }
        Ok(())
    }
}

/// Shared asynchronous executor for durable domain probes.
pub struct DomainProbeController {
    db: Arc<Database>,
    http: Arc<dyn HttpClient>,
    tls_verifier: DomainTlsProbeVerifier,
    dns_json_endpoint: String,
    probe_location: String,
    route_observer: Arc<dyn RouteObservationProvider>,
    storage_credential_probe: Arc<dyn StorageCredentialProbeProvider>,
}

impl DomainProbeController {
    /// Creates a controller with explicit DNS and TLS-attestation trust roots.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe resolver URL or empty probe location.
    pub fn new(
        db: Arc<Database>,
        http: Arc<dyn HttpClient>,
        tls_verifier: DomainTlsProbeVerifier,
        dns_json_endpoint: impl Into<String>,
        probe_location: impl Into<String>,
    ) -> Result<Self> {
        let dns_json_endpoint = dns_json_endpoint.into();
        crate::url_guard::is_safe_remote_url(&dns_json_endpoint)
            .context("unsafe domain-probe DNS JSON endpoint")?;
        let endpoint = url::Url::parse(&dns_json_endpoint)
            .context("invalid domain-probe DNS JSON endpoint")?;
        anyhow::ensure!(
            endpoint.scheme() == "https",
            "DNS JSON endpoint must use HTTPS"
        );
        anyhow::ensure!(
            endpoint.username().is_empty()
                && endpoint.password().is_none()
                && endpoint.query().is_none()
                && endpoint.fragment().is_none(),
            "DNS JSON endpoint cannot contain credentials, query, or fragment"
        );
        let probe_location = probe_location.into();
        anyhow::ensure!(!probe_location.is_empty(), "domain probe location is empty");
        let route_observer = Arc::new(UnavailableRouteObservationProvider);
        let storage_credential_probe = Arc::new(UnavailableStorageCredentialProbeProvider);
        Ok(Self {
            db,
            http,
            tls_verifier,
            dns_json_endpoint,
            probe_location,
            route_observer,
            storage_credential_probe,
        })
    }

    /// Installs the controller-owned direct/CDN observation adapter.
    ///
    /// Without this explicit port, non-Hub route probes fail closed. Runtime
    /// shells must never substitute an origin-served self-attestation endpoint.
    #[must_use]
    pub fn with_route_observer(
        mut self,
        route_observer: Arc<dyn RouteObservationProvider>,
    ) -> Self {
        self.route_observer = route_observer;
        self
    }

    /// Installs the controller-owned, purpose-specific storage probe adapter.
    #[must_use]
    pub fn with_storage_credential_probe(
        mut self,
        probe: Arc<dyn StorageCredentialProbeProvider>,
    ) -> Self {
        self.storage_credential_probe = probe;
        self
    }

    /// Claims and executes at most `limit` due domain probes.
    pub async fn run_due(&self, limit: usize) -> Result<usize> {
        const LEASE_SECONDS: i64 = 120;
        let due = self
            .db
            .due_domain_probe_operations(clock::now_unix_secs() - LEASE_SECONDS, limit)
            .await?;
        let mut completed = 0;
        for operation in due {
            let Some(claimed) = self
                .db
                .claim_domain_probe_operation(
                    &operation.operation_id,
                    operation.resource_version,
                    LEASE_SECONDS,
                )
                .await?
            else {
                continue;
            };
            if let Err(error) = self.run_claimed(&claimed).await {
                let now = clock::now_unix_secs();
                let detail = serde_json::json!({ "attempts": 3 }).to_string();
                let failure_update = self
                    .db
                    .update_topology_operation(
                        &claimed.operation_id,
                        claimed.resource_version,
                        "failed",
                        0,
                        None,
                        &detail,
                        Some(&format!(
                            "domain measurement failed after retries: {error:#}"
                        )),
                        Some(now),
                        Some(now),
                    )
                    .await;
                if let Err(update_error) = failure_update {
                    let current = self.db.topology_operation(&claimed.operation_id).await?;
                    if current.as_ref().is_some_and(|current| {
                        current.resource_version != claimed.resource_version
                            || current.state != "running"
                    }) {
                        tracing::info!(
                            operation_id = %claimed.operation_id,
                            "domain probe lease was superseded before failure recording"
                        );
                    } else {
                        return Err(update_error);
                    }
                }
            }
            completed += 1;
        }
        let remaining = limit.saturating_sub(completed);
        let due_routes = self
            .db
            .due_route_probe_operations(clock::now_unix_secs() - LEASE_SECONDS, remaining)
            .await?;
        for operation in due_routes {
            let Some(claimed) = self
                .db
                .claim_route_probe_operation(
                    &operation.operation_id,
                    operation.resource_version,
                    LEASE_SECONDS,
                )
                .await?
            else {
                continue;
            };
            self.run_route_claimed(&claimed).await?;
            completed += 1;
        }
        let remaining = limit.saturating_sub(completed);
        let due_credentials = self
            .db
            .due_storage_credential_probe_operations(
                clock::now_unix_secs() - LEASE_SECONDS,
                remaining,
            )
            .await?;
        for operation in due_credentials {
            let Some(claimed) = self
                .db
                .claim_storage_credential_probe_operation(
                    &operation.operation_id,
                    operation.resource_version,
                    LEASE_SECONDS,
                )
                .await?
            else {
                continue;
            };
            if let Err(error) = self.run_storage_credential_claimed(&claimed).await {
                let now = clock::now_unix_secs();
                let current = self
                    .db
                    .topology_operation(&claimed.operation_id)
                    .await?
                    .context("claimed storage credential operation disappeared")?;
                if current.state != "running" {
                    completed += 1;
                    continue;
                }
                self.db
                    .update_topology_operation(
                        &current.operation_id,
                        current.resource_version,
                        "failed",
                        0,
                        Some(1),
                        &current.detail_json,
                        Some(&format!(
                            "storage credential probe could not produce trusted evidence: {error:#}"
                        )),
                        current.started_at.or(Some(now)),
                        Some(now),
                    )
                    .await?;
            }
            completed += 1;
        }
        let remaining = limit.saturating_sub(completed);
        let due_coordinations = self
            .db
            .due_network_policy_coordination_operations(
                clock::now_unix_secs() - LEASE_SECONDS,
                remaining,
            )
            .await?;
        for operation in due_coordinations {
            let Some(claimed) = self
                .db
                .claim_network_policy_coordination_operation(
                    &operation.operation_id,
                    operation.resource_version,
                    LEASE_SECONDS,
                )
                .await?
            else {
                continue;
            };
            self.run_boundary_coordination_claimed(&claimed).await?;
            completed += 1;
        }
        let remaining = limit.saturating_sub(completed);
        let due_revocations = self
            .db
            .due_consumer_scope_grant_revocation_operations(
                clock::now_unix_secs() - LEASE_SECONDS,
                remaining,
            )
            .await?;
        for operation in due_revocations {
            let Some(claimed) = self
                .db
                .claim_consumer_scope_grant_revocation_operation(
                    &operation.operation_id,
                    operation.resource_version,
                    LEASE_SECONDS,
                )
                .await?
            else {
                continue;
            };
            if let Err(error) = self.run_grant_revocation_claimed(&claimed).await {
                let now = clock::now_unix_secs();
                let message = format!("{error:#}")
                    .chars()
                    .take(4 * 1024)
                    .collect::<String>();
                self.db
                    .update_topology_operation(
                        &claimed.operation_id,
                        claimed.resource_version,
                        "failed",
                        claimed.progress_current,
                        claimed.progress_total,
                        &claimed.detail_json,
                        Some(&message),
                        claimed.started_at.or(Some(now)),
                        Some(now),
                    )
                    .await?;
            }
            completed += 1;
        }
        Ok(completed)
    }

    async fn run_storage_credential_claimed(
        &self,
        operation: &TopologyOperationRecord,
    ) -> Result<()> {
        let detail: serde_json::Value = serde_json::from_str(&operation.detail_json)
            .context("storage credential operation has malformed detail")?;
        let purpose = detail
            .get("purpose")
            .and_then(serde_json::Value::as_str)
            .context("storage credential operation has no purpose")?
            .to_owned();
        let generation = detail
            .get("credentialGeneration")
            .and_then(serde_json::Value::as_i64)
            .context("storage credential operation has no generation")?;
        let expected_head_version = detail
            .get("credentialHeadResourceVersion")
            .and_then(serde_json::Value::as_i64)
            .context("storage credential operation has no head version")?;
        let probe_token = detail
            .get("probeToken")
            .and_then(serde_json::Value::as_str)
            .context("storage credential operation has no durable probe token")?;
        anyhow::ensure!(
            probe_token.len() == 64
                && probe_token
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
            "storage credential operation has an invalid probe token"
        );
        let target = self
            .db
            .topology_operation_targets(&operation.operation_id)
            .await?
            .into_iter()
            .find(|target| target.role == "primary" && target.target_kind == "binding")
            .context("storage credential operation has no binding target")?;
        let binding = self
            .db
            .binding_by_stable_id(&target.stable_id)
            .await?
            .context("storage credential binding no longer exists")?;
        anyhow::ensure!(
            binding.resource_version == target.generation_key,
            "binding changed before credential probe"
        );
        let credential = self
            .db
            .binding_credential_revision(binding.id, &purpose, generation)
            .await?
            .context("storage credential generation no longer exists")?;
        let now = clock::now_unix_secs();
        let (evidence, checkpoint) = if credential.head_resource_version == expected_head_version {
            let evidence = self
                .storage_credential_probe
                .probe(&binding, &credential, probe_token)
                .await?;
            anyhow::ensure!(
                evidence.valid == evidence.error.is_none(),
                "storage credential adapter returned inconsistent evidence"
            );
            let checkpoint_detail = serde_json::json!({
                "bindingId": target.stable_id,
                "purpose": purpose,
                "credentialGeneration": generation,
                "credentialHeadResourceVersion": expected_head_version,
                "probeToken": probe_token,
                "probeResult": if evidence.valid { "valid" } else { "invalid" },
                "probeError": evidence.error,
                "conditionalWritesSupported": evidence.conditional_writes_supported,
                "evidence": evidence.evidence,
            })
            .to_string();
            let checkpoint = self
                .db
                .update_topology_operation(
                    &operation.operation_id,
                    operation.resource_version,
                    "running",
                    0,
                    Some(1),
                    &checkpoint_detail,
                    None,
                    operation.started_at.or(Some(now)),
                    None,
                )
                .await?;
            let state = if evidence.valid { "valid" } else { "invalid" };
            self.db
                .validate_binding_credential_revision(
                    binding.id,
                    &purpose,
                    generation,
                    state,
                    evidence.error.as_deref(),
                    expected_head_version,
                )
                .await?;
            (evidence, checkpoint)
        } else if credential.head_resource_version == expected_head_version + 1 {
            let state = detail
                .get("probeResult")
                .and_then(serde_json::Value::as_str)
                .context("credential probe advanced without durable evidence")?;
            let valid = match state {
                "valid" => true,
                "invalid" => false,
                _ => anyhow::bail!("credential probe checkpoint has an invalid result"),
            };
            anyhow::ensure!(
                credential.validation_state == state,
                "credential validation does not match its durable evidence"
            );
            let error = detail
                .get("probeError")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned);
            anyhow::ensure!(
                valid == error.is_none(),
                "credential probe checkpoint is inconsistent"
            );
            let conditional_writes_supported = detail
                .get("conditionalWritesSupported")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            let evidence_value = detail
                .get("evidence")
                .cloned()
                .context("credential probe checkpoint has no evidence")?;
            (
                StorageCredentialProbeEvidence {
                    valid,
                    conditional_writes_supported,
                    error,
                    evidence: evidence_value,
                },
                operation.clone(),
            )
        } else {
            anyhow::bail!("storage credential head changed before its probe completed")
        };
        let state = if evidence.valid { "valid" } else { "invalid" };
        if purpose == "write" && evidence.valid {
            self.record_storage_write_evidence(
                &binding,
                &credential,
                evidence.conditional_writes_supported,
            )
            .await?;
        }
        let completed_detail = serde_json::json!({
            "bindingId": target.stable_id,
            "purpose": purpose,
            "credentialGeneration": generation,
            "credentialHeadResourceVersion": expected_head_version,
            "probeToken": probe_token,
            "result": state,
            "conditionalWritesSupported": evidence.conditional_writes_supported,
            "evidence": evidence.evidence,
        })
        .to_string();
        self.db
            .update_topology_operation(
                &operation.operation_id,
                checkpoint.resource_version,
                "succeeded",
                1,
                Some(1),
                &completed_detail,
                None,
                checkpoint.started_at.or(Some(now)),
                Some(now),
            )
            .await?;
        Ok(())
    }

    async fn record_storage_write_evidence(
        &self,
        binding: &crate::db::BindingRecord,
        credential: &crate::db::BindingCredentialRevisionRecord,
        conditional_writes_supported: bool,
    ) -> Result<()> {
        let capability_fingerprint = hex::encode(Sha256::digest(serde_json::to_vec(&(
            binding.kind.as_str(),
            true,
            conditional_writes_supported,
        ))?));
        let revision_fingerprint = hex::encode(Sha256::digest(serde_json::to_vec(&(
            credential.secret_version_ref.as_str(),
            credential.generation,
            capability_fingerprint.as_str(),
        ))?));
        let revision = self
            .db
            .create_binding_write_revision(&crate::db::NewBindingWriteRevision {
                binding_id: binding.id,
                write_credential_generation: credential.generation,
                writes_supported: true,
                conditional_writes_supported,
                revision_fingerprint,
                capability_fingerprint,
            })
            .await?;
        let observation = self
            .db
            .binding_write_observation(binding.id, revision.revision)
            .await?;
        if !observation
            .as_ref()
            .is_some_and(|observation| observation.state == "valid")
        {
            self.db
                .observe_binding_write_revision(
                    binding.id,
                    revision.revision,
                    "valid",
                    None,
                    observation.map(|observation| observation.observation_version),
                )
                .await?;
        }
        let write_state = self
            .db
            .binding_write_state(binding.id)
            .await?
            .context("binding write state is missing")?;
        if write_state.current_write_revision != Some(revision.revision) {
            self.db
                .set_current_binding_write_revision(
                    binding.id,
                    revision.revision,
                    write_state.resource_version,
                )
                .await?;
        }
        Ok(())
    }

    async fn run_boundary_coordination_claimed(
        &self,
        operation: &TopologyOperationRecord,
    ) -> Result<()> {
        let detail: BoundaryCoordinationDetail = serde_json::from_str(&operation.detail_json)
            .context("boundary coordination operation has malformed detail")?;
        let jobs = self
            .db
            .topology_pin_resolution_jobs(&operation.operation_id)
            .await?;
        anyhow::ensure!(
            operation.progress_total == Some(i64::try_from(jobs.len())?),
            "boundary coordination child-job count changed"
        );
        for pending in jobs.iter().filter(|job| job.state != "succeeded") {
            let Some(job) = self
                .db
                .claim_topology_pin_resolution_job(
                    &pending.operation_id,
                    &pending.pin_id,
                    pending.resource_version,
                )
                .await?
            else {
                continue;
            };
            let result = async {
                match (job.source_target_kind.as_str(), job.action_kind.as_str()) {
                    ("endpoint", "move_endpoint") => {
                        self.db
                            .execute_endpoint_pin_move(
                                &job,
                                "system",
                                None,
                                "system:boundary-coordination",
                            )
                            .await?;
                    }
                    ("endpoint", "release") => {
                        if let Some(endpoint) =
                            self.db.endpoint(&job.source_target_stable_id).await?
                        {
                            anyhow::ensure!(
                                endpoint.resource_version == job.source_target_resource_version,
                                "source endpoint changed before release"
                            );
                            self.db
                                .delete_endpoint(
                                    &job.source_target_stable_id,
                                    job.source_target_resource_version,
                                    "system",
                                    None,
                                    "system:boundary-coordination",
                                )
                                .await?;
                        }
                    }
                    ("route", "replace_route" | "release") => {
                        let route = self
                            .db
                            .route(&job.source_target_stable_id)
                            .await?
                            .context("source route disappeared before disable")?;
                        if route.enabled {
                            anyhow::ensure!(
                                route.resource_version == job.source_target_resource_version
                                    && route.configuration_generation
                                        == Some(job.source_target_generation_key)
                                    && route.configuration_digest.as_deref()
                                        == Some(job.source_target_configuration_digest.as_str()),
                                "source route changed before disable"
                            );
                            let mut snapshot = self
                                .db
                                .route_snapshot(&job.source_target_stable_id)
                                .await?
                                .context("source route snapshot disappeared before disable")?;
                            snapshot.spec.enabled = false;
                            self.db
                                .update_route(
                                    &job.source_target_stable_id,
                                    &snapshot.spec,
                                    &snapshot.canonical_url,
                                    job.source_target_resource_version,
                                    "system:boundary-coordination",
                                )
                                .await?;
                        } else {
                            anyhow::ensure!(
                                route.resource_version == job.source_target_resource_version + 1,
                                "disabled source route does not match the sealed resolution"
                            );
                        }
                    }
                    _ => anyhow::bail!("unsupported boundary pin-resolution job"),
                }
                self.db.acknowledge_topology_pin_resolution_job(&job).await
            }
            .await;
            if let Err(error) = result {
                let message = format!("{error:#}")
                    .chars()
                    .take(4 * 1024)
                    .collect::<String>();
                self.db
                    .fail_topology_pin_resolution_job(&job, &message)
                    .await?;
                let now = clock::now_unix_secs();
                self.db
                    .update_topology_operation(
                        &operation.operation_id,
                        operation.resource_version,
                        "failed",
                        i64::try_from(
                            self.db
                                .topology_pin_resolution_jobs(&operation.operation_id)
                                .await?
                                .iter()
                                .filter(|job| job.state == "succeeded")
                                .count(),
                        )?,
                        operation.progress_total,
                        &operation.detail_json,
                        Some(&message),
                        operation.started_at.or(Some(now)),
                        Some(now),
                    )
                    .await?;
                return Ok(());
            }
        }
        let final_jobs = self
            .db
            .topology_pin_resolution_jobs(&operation.operation_id)
            .await?;
        anyhow::ensure!(
            final_jobs.iter().all(|job| job.state == "succeeded"),
            "boundary coordination left unacknowledged child jobs"
        );
        let default_cas = detail.default_cas.map(|seal| NetworkPolicyDefaultCas {
            boundary_resource_version: seal.boundary_resource_version,
            previous_revision: seal.previous_revision,
            previous_resource_version: seal.previous_resource_version,
        });
        self.db
            .finalize_network_policy_coordination(
                &operation.operation_id,
                operation.resource_version,
                &detail.boundary_id,
                detail.target_revision,
                &detail.target_content_digest,
                &detail.old_revisions,
                default_cas.as_ref(),
                &detail.actor_kind,
                detail.actor_id,
                &detail.actor_label,
            )
            .await
    }

    async fn run_grant_revocation_claimed(
        &self,
        operation: &TopologyOperationRecord,
    ) -> Result<()> {
        let detail: GrantRevocationDetail = serde_json::from_str(&operation.detail_json)
            .context("grant revocation operation has malformed detail")?;
        anyhow::ensure!(
            operation.progress_total == Some(i64::try_from(detail.resolutions.len())? + 1),
            "grant revocation work count changed"
        );
        for resolution in &detail.resolutions {
            match (
                resolution.source.target_kind.as_str(),
                resolution.action_kind.as_str(),
            ) {
                ("route", "replace_route" | "release") => {
                    if let Some(target) = resolution.replacement.as_ref() {
                        let replacement = self
                            .db
                            .route(&target.resource_stable_id)
                            .await?
                            .context("replacement route disappeared")?;
                        anyhow::ensure!(
                            target.resource_kind == "route"
                                && replacement.enabled
                                && replacement.resource_version
                                    == resolution
                                        .replacement_resource_version
                                        .context("replacement route version is absent")?
                                && replacement.configuration_generation
                                    == Some(target.resource_generation)
                                && replacement.configuration_digest.as_deref()
                                    == Some(target.configuration_digest.as_str())
                                && target.expected_resource_version
                                    == replacement.resource_version.to_string(),
                            "replacement route changed before grant revocation"
                        );
                    }
                    let route = self
                        .db
                        .route(&resolution.source.target_stable_id)
                        .await?
                        .context("source route disappeared")?;
                    if route.enabled {
                        anyhow::ensure!(
                            route.resource_version == resolution.source.target_resource_version
                                && route.configuration_generation
                                    == Some(resolution.source.target_generation_key)
                                && route.configuration_digest.as_deref()
                                    == Some(resolution.source.target_configuration_digest.as_str()),
                            "source route changed before grant revocation"
                        );
                        let mut snapshot = self
                            .db
                            .route_snapshot(&resolution.source.target_stable_id)
                            .await?
                            .context("source route snapshot disappeared")?;
                        snapshot.spec.enabled = false;
                        self.db
                            .update_route(
                                &resolution.source.target_stable_id,
                                &snapshot.spec,
                                &snapshot.canonical_url,
                                resolution.source.target_resource_version,
                                "system:grant-revocation",
                            )
                            .await?;
                    } else {
                        anyhow::ensure!(
                            route.resource_version == resolution.source.target_resource_version + 1,
                            "disabled source route is not the sealed transition"
                        );
                    }
                }
                ("endpoint" | "listener", "move_endpoint") => {
                    let target = resolution
                        .replacement
                        .as_ref()
                        .context("endpoint move has no replacement")?;
                    let endpoint = self
                        .db
                        .endpoint(&resolution.source.target_stable_id)
                        .await?
                        .context("source endpoint disappeared")?;
                    if endpoint.desired_generation != Some(target.resource_generation) {
                        let revision = self
                            .db
                            .endpoint_revision(
                                &target.resource_stable_id,
                                target.resource_generation,
                            )
                            .await?
                            .context("replacement endpoint generation disappeared")?;
                        anyhow::ensure!(
                            target.resource_kind == "endpoint"
                                && target.resource_stable_id == resolution.source.target_stable_id
                                && revision.content_digest == target.configuration_digest
                                && resolution.replacement_resource_version
                                    == Some(endpoint.resource_version)
                                && target.expected_resource_version
                                    == endpoint.resource_version.to_string(),
                            "replacement endpoint changed or changes stable identity"
                        );
                        self.db
                            .activate_staged_endpoint_generation(
                                &target.resource_stable_id,
                                target.resource_generation,
                                resolution.source.target_resource_version,
                                false,
                                "system",
                                None,
                                "system:grant-revocation",
                            )
                            .await?;
                    } else {
                        anyhow::ensure!(
                            endpoint.resource_version
                                == resolution.source.target_resource_version + 1,
                            "selected endpoint is not the sealed transition"
                        );
                    }
                }
                ("endpoint" | "listener", "release") => {
                    if let Some(endpoint) = self
                        .db
                        .endpoint(&resolution.source.target_stable_id)
                        .await?
                    {
                        anyhow::ensure!(
                            endpoint.resource_version == resolution.source.target_resource_version
                                && endpoint.desired_generation
                                    == Some(resolution.source.target_generation_key),
                            "source endpoint changed before release"
                        );
                        self.db
                            .delete_endpoint(
                                &resolution.source.target_stable_id,
                                resolution.source.target_resource_version,
                                "system",
                                None,
                                "system:grant-revocation",
                            )
                            .await?;
                    }
                }
                ("placement", "release") => {
                    let placement_id = resolution
                        .source
                        .target_stable_id
                        .split(':')
                        .nth(1)
                        .and_then(|value| value.parse::<i64>().ok())
                        .context("placement pin has malformed stable identity")?;
                    if let Some(placement) = self.db.surface_placement(placement_id).await? {
                        let digest =
                            hex::encode(Sha256::digest(serde_json::to_vec(&serde_json::json!({
                                "binding_id": placement.binding_id,
                                "prefix": placement.prefix,
                                "kind": placement.kind,
                                "desired_state": placement.desired_state,
                                "desired_read_enabled": placement.desired_read_enabled,
                                "read_order": placement.read_order,
                            }))?));
                        anyhow::ensure!(
                            placement.resource_version == resolution.source.target_resource_version
                                && placement.write_spec_version
                                    == resolution.source.target_generation_key
                                && digest == resolution.source.target_configuration_digest
                                && placement.desired_state == "offline"
                                && !placement.effective_read_enabled
                                && !placement.effective_write_enabled,
                            "placement must be exact, offline, and drain-complete before release"
                        );
                        anyhow::ensure!(
                            self.db
                                .delete_surface_placement(
                                    placement.id,
                                    resolution.source.target_resource_version,
                                )
                                .await?,
                            "placement is not delete-eligible"
                        );
                    }
                }
                _ => anyhow::bail!(
                    "unsupported grant pin action '{}' for '{}' ({})",
                    resolution.action_kind,
                    resolution.source.target_kind,
                    resolution.source.pin_id
                ),
            }
        }
        let binding_id = if detail.resource_kind == "binding" {
            Some(
                self.db
                    .binding_by_stable_id(&detail.resource_stable_id)
                    .await?
                    .context("grant binding disappeared")?
                    .id,
            )
        } else {
            None
        };
        let resource = match detail.resource_kind.as_str() {
            "binding" => crate::db::GrantResource::Binding {
                id: binding_id.context("grant binding id is absent")?,
                stable_id: &detail.resource_stable_id,
            },
            "network_policy" => crate::db::GrantResource::NetworkPolicy {
                id: &detail.resource_stable_id,
            },
            "endpoint" => crate::db::GrantResource::Endpoint {
                id: &detail.resource_stable_id,
                generation: detail.resource_generation,
            },
            "gateway" => crate::db::GrantResource::Gateway {
                id: &detail.resource_stable_id,
                generation: detail.resource_generation,
            },
            _ => anyhow::bail!("unknown grant resource kind"),
        };
        match self
            .db
            .load_consumer_scope_grant(resource, &detail.consumer_scope_key)
            .await?
        {
            Some(grant) if grant.state == "active" => {
                self.db
                    .revoke_consumer_scope(
                        resource,
                        &detail.consumer_scope_key,
                        detail.expected_grant_resource_version,
                        &detail.actor,
                        &detail.request_id,
                    )
                    .await?;
            }
            Some(grant)
                if grant.state == "revoked"
                    && grant.resource_version == detail.expected_grant_resource_version + 1 => {}
            Some(_) => anyhow::bail!("grant changed before coordinated revocation"),
            None => anyhow::ensure!(
                detail.resource_kind == "endpoint"
                    && self
                        .db
                        .endpoint(&detail.resource_stable_id)
                        .await?
                        .is_none(),
                "grant disappeared without its terminal endpoint deletion"
            ),
        }
        let now = clock::now_unix_secs();
        self.db
            .update_topology_operation(
                &operation.operation_id,
                operation.resource_version,
                "succeeded",
                operation
                    .progress_total
                    .context("grant revocation total is absent")?,
                operation.progress_total,
                &operation.detail_json,
                None,
                operation.started_at.or(Some(now)),
                Some(now),
            )
            .await?;
        Ok(())
    }

    async fn run_route_claimed(&self, operation: &TopologyOperationRecord) -> Result<()> {
        let target_ref = self
            .db
            .topology_operation_targets(&operation.operation_id)
            .await?
            .into_iter()
            .find(|target| target.role == "primary" && target.target_kind == "route")
            .context("delivery-route probe has no primary route target")?;
        let target = self
            .db
            .route_reconciliation_target(&target_ref.stable_id)
            .await?
            .context("delivery-route probe target no longer exists")?;
        anyhow::ensure!(
            target.configuration_generation == target_ref.generation_key
                && target.configuration_digest == target_ref.configuration_digest,
            "delivery-route desired state changed before its probe ran"
        );
        let now = clock::now_unix_secs();
        let internal = matches!(target.mode.as_str(), "hub_proxy" | "hub_redirect")
            && target.access_policy_kind != "external_provider";
        let observation = if internal {
            self.db
                .hub_route_state_ready(
                    &target.id,
                    target.configuration_generation,
                    &target.configuration_digest,
                )
                .await?
                .then(|| target.publication_manifest_id.clone())
                .ok_or_else(|| anyhow::anyhow!("Hub endpoint or access state is not ready"))
        } else {
            self.route_observer
                .observe(&target)
                .await
                .and_then(|evidence| {
                    validate_route_evidence(&target, &evidence)?;
                    Ok(evidence.publication_manifest_id)
                })
        };
        let (route_state, access_state, error, manifest) = match observation {
            Ok(manifest) => ("healthy", "verified", None, manifest),
            Err(error) => (
                "degraded",
                "failed",
                Some(format!("delivery observation failed: {error:#}")),
                None,
            ),
        };
        self.db
            .reconcile_route(
                &target.id,
                target.configuration_generation,
                &target.configuration_digest,
                &target.access_policy_digest,
                route_state,
                access_state,
                error.as_deref(),
                if target.mode == "direct" {
                    manifest.as_deref()
                } else {
                    None
                },
                now,
            )
            .await?;
        let detail = serde_json::json!({
            "routeId": target.id,
            "configurationGeneration": target.configuration_generation,
            "configurationDigest": target.configuration_digest,
            "accessPolicyDigest": target.access_policy_digest,
            "ready": error.is_none(),
            "publicationManifestId": manifest,
        })
        .to_string();
        self.db
            .update_topology_operation(
                &operation.operation_id,
                operation.resource_version,
                if error.is_none() {
                    "succeeded"
                } else {
                    "failed"
                },
                1,
                Some(1),
                &detail,
                error.as_deref(),
                operation.started_at,
                Some(now),
            )
            .await?;
        Ok(())
    }

    async fn run_claimed(&self, operation: &TopologyOperationRecord) -> Result<()> {
        let target = self
            .db
            .topology_operation_targets(&operation.operation_id)
            .await?
            .into_iter()
            .find(|target| target.role == "primary" && target.target_kind == "domain")
            .context("domain probe has no primary domain target")?;
        let domain = self
            .db
            .delivery_domain(&target.stable_id)
            .await?
            .context("domain probe target no longer exists")?;
        anyhow::ensure!(
            target.generation_key == domain.resource_version,
            "domain desired state changed before its probe ran"
        );
        let evidence = self
            .measure_domain(
                &operation.operation_id,
                target.generation_key,
                domain.id,
                &domain.hostname,
            )
            .await?;
        let dns_state = match domain.dns_configuration_json.as_deref() {
            None => "unconfigured",
            Some(json) => {
                let desired: crate::db::DeliveryDnsConfigurationSpec = serde_json::from_str(json)?;
                let expected = match desired {
                    crate::db::DeliveryDnsConfigurationSpec::HubManaged { target, .. } => target,
                    crate::db::DeliveryDnsConfigurationSpec::External { expected_target } => {
                        expected_target
                    }
                };
                if evidence
                    .dns_records
                    .iter()
                    .any(|record| dns_target_eq(&record.target, &expected))
                {
                    "verified"
                } else {
                    "failed"
                }
            }
        };
        let certificate_state = match domain.certificate_configuration_json.as_deref() {
            None => "unconfigured",
            // The HTTPS client independently validates hostname coverage,
            // trust, and validity on this exact connection. Neither reqwest nor
            // Worker Fetch exposes portable leaf-certificate metadata, so the
            // responder deliberately makes no self-attested fingerprint,
            // issuer-mode, SAN, or configuration-digest claims.
            Some(_) if evidence.tls_handshake_valid => "active",
            Some(_) => "failed",
        };
        let error = match (dns_state == "failed", certificate_state == "failed") {
            (true, true) => Some("DNS target and TLS verification did not match desired state"),
            (true, false) => Some("DNS target did not match desired state"),
            (false, true) => Some("TLS verification failed"),
            (false, false) => None,
        };
        let evidence_json = serde_json::to_string(&serde_json::json!({
            "dnsRecords": evidence.dns_records,
            "tlsHandshakeValid": evidence.tls_handshake_valid,
            "responderEndpointId": evidence.responder_endpoint_id,
            "responderEndpointGeneration": evidence.responder_endpoint_generation,
            "responderKeyIdentitySha256": evidence.responder_key_identity_sha256,
            "observedAt": evidence.observed_at,
            "probeLocation": evidence.probe_location,
        }))?;
        let digest = hex::encode(Sha256::digest(evidence_json.as_bytes()));
        self.db
            .complete_delivery_domain_probe(
                &operation.operation_id,
                operation.resource_version,
                &domain.stable_id,
                dns_state,
                certificate_state,
                error,
                domain.resource_version,
                &evidence_json,
                &digest,
                &evidence.probe_location,
                evidence.observed_at,
                &evidence.responder_endpoint_id,
                evidence.responder_endpoint_generation,
            )
            .await?;
        Ok(())
    }

    async fn measure_domain(
        &self,
        operation_id: &str,
        generation: i64,
        domain_id: i64,
        hostname: &str,
    ) -> Result<DomainProbeEvidence> {
        let (endpoint_id, endpoint_generation, signing_identity) =
            self.db.domain_probe_signing_identity(domain_id).await?;
        let mut last_error = None;
        for attempt in 0..3 {
            let nonce = self
                .db
                .issue_domain_probe_challenge(
                    operation_id,
                    generation,
                    attempt,
                    &endpoint_id,
                    endpoint_generation,
                    clock::now_unix_secs(),
                )
                .await?;
            match measure_domain_once(
                self.http.as_ref(),
                &self.tls_verifier,
                hostname,
                &nonce,
                &endpoint_id,
                endpoint_generation,
                &signing_identity,
                &self.dns_json_endpoint,
                &self.probe_location,
            )
            .await
            {
                Ok(evidence) => return Ok(evidence),
                Err(error) => {
                    last_error = Some(error);
                    if attempt < 2 {
                        clock::sleep(std::time::Duration::from_millis(100 * (attempt + 1) as u64))
                            .await;
                    }
                }
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("domain probe did not run")))
    }
}

async fn measure_domain_once(
    http: &dyn HttpClient,
    tls_verifier: &DomainTlsProbeVerifier,
    hostname: &str,
    nonce: &str,
    endpoint_id: &str,
    endpoint_generation: i64,
    signing_identity: &crate::db::EndpointProbeSigningIdentity,
    dns_json_endpoint: &str,
    probe_location: &str,
) -> Result<DomainProbeEvidence> {
    let mut tls_url = url::Url::parse(&format!("https://{hostname}/.well-known/aos-domain-probe"))?;
    tls_url.query_pairs_mut().append_pair("nonce", nonce);
    let (a, aaaa, cname, tls) = futures_util::join!(
        dns_answers(http, dns_json_endpoint, hostname, "A"),
        dns_answers(http, dns_json_endpoint, hostname, "AAAA"),
        dns_answers(http, dns_json_endpoint, hostname, "CNAME"),
        http.probe_https(tls_url.as_str()),
    );
    let mut dns_records = Vec::new();
    let mut successful_dns_queries = 0usize;
    for (record_type, result) in [("A", a), ("AAAA", aaaa), ("CNAME", cname)] {
        match result {
            Ok(answers) => {
                successful_dns_queries += 1;
                dns_records.extend(answers);
            }
            Err(error) => tracing::warn!(
                %hostname,
                %record_type,
                error = %format!("{error:#}"),
                "domain DNS probe attempt failed"
            ),
        }
    }
    if successful_dns_queries == 0 {
        anyhow::bail!("all DNS measurements failed for {hostname}");
    }
    dns_records.sort();
    dns_records.dedup();
    let tls_body = tls.context("TLS identity proof failed")?;
    let now = crate::clock::now_unix_secs();
    let tls = tls_verifier.verify(
        &tls_body,
        nonce,
        hostname,
        endpoint_id,
        endpoint_generation,
        signing_identity,
        now,
    )?;
    Ok(DomainProbeEvidence {
        dns_records,
        tls_handshake_valid: true,
        responder_endpoint_id: tls.endpoint_id,
        responder_endpoint_generation: tls.endpoint_generation,
        responder_key_identity_sha256: tls.responder_key_identity_sha256,
        observed_at: now,
        probe_location: probe_location.to_string(),
    })
}

async fn dns_answers(
    http: &dyn HttpClient,
    endpoint: &str,
    hostname: &str,
    record_type: &str,
) -> Result<Vec<DnsProbeRecord>> {
    let mut url = url::Url::parse(endpoint)?;
    url.query_pairs_mut()
        .append_pair("name", hostname)
        .append_pair("type", record_type);
    let body = http.get(url.as_str()).await?;
    let response: DnsJsonResponse = serde_json::from_slice(&body)
        .with_context(|| format!("decoding {record_type} DNS response"))?;
    if response.status != 0 && response.status != 3 {
        anyhow::bail!(
            "DNS {record_type} query returned status {}",
            response.status
        );
    }
    let expected_type = match record_type {
        "A" => 1,
        "CNAME" => 5,
        "AAAA" => 28,
        _ => anyhow::bail!("unsupported DNS record type"),
    };
    let canonical_hostname = crate::db::canonical_delivery_hostname(hostname)?;
    response
        .answer
        .into_iter()
        .filter(|answer| answer.record_type == expected_type)
        .map(|answer| {
            let owner = crate::db::canonical_delivery_hostname(answer.name.trim_end_matches('.'))?;
            anyhow::ensure!(
                owner == canonical_hostname,
                "DNS answer owner does not match query"
            );
            let target = match expected_type {
                1 => answer
                    .data
                    .parse::<std::net::Ipv4Addr>()
                    .context("invalid A answer")?
                    .to_string(),
                28 => answer
                    .data
                    .parse::<std::net::Ipv6Addr>()
                    .context("invalid AAAA answer")?
                    .to_string(),
                5 => crate::db::canonical_delivery_hostname(answer.data.trim_end_matches('.'))?,
                _ => unreachable!(),
            };
            Ok(DnsProbeRecord {
                owner,
                record_type: record_type.to_owned(),
                target,
            })
        })
        .collect()
}

/// Resolves organization-domain ownership challenges through a DNS JSON endpoint.
pub struct DnsJsonIdentityDomainVerifier {
    http: Arc<dyn HttpClient>,
    endpoint: String,
}

impl DnsJsonIdentityDomainVerifier {
    /// Constructs a verifier over the runtime's hardened outbound HTTP client.
    #[must_use]
    pub fn new(http: Arc<dyn HttpClient>, endpoint: String) -> Self {
        Self { http, endpoint }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl IdentityDomainVerifier for DnsJsonIdentityDomainVerifier {
    async fn challenge_is_published(&self, domain: &str, challenge: &str) -> Result<bool> {
        let mut url = url::Url::parse(&self.endpoint)?;
        url.query_pairs_mut()
            .append_pair("name", domain)
            .append_pair("type", "TXT");
        let body = self.http.get(url.as_str()).await?;
        let response: DnsJsonResponse =
            serde_json::from_slice(&body).context("decoding TXT DNS response")?;
        if response.status != 0 && response.status != 3 {
            anyhow::bail!("DNS TXT query returned status {}", response.status);
        }
        let canonical_domain = crate::db::canonical_delivery_hostname(domain)?;
        for answer in response.answer {
            if answer.record_type != 16 {
                continue;
            }
            let owner = crate::db::canonical_delivery_hostname(answer.name.trim_end_matches('.'))?;
            if owner == canonical_domain && dns_txt_value(&answer.data)? == challenge {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// Verifies a reviewed organization-domain ownership challenge.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait IdentityDomainVerifier: crate::backend::BackendBounds {
    /// Returns whether the exact TXT challenge is published at the exact domain.
    ///
    /// # Errors
    ///
    /// Returns an error when DNS cannot be queried or its response is malformed.
    async fn challenge_is_published(&self, domain: &str, challenge: &str) -> Result<bool>;
}

fn dns_txt_value(encoded: &str) -> Result<String> {
    let encoded = encoded.trim();
    if !encoded.starts_with('"') {
        return Ok(encoded.to_string());
    }
    let mut value = String::new();
    for segment in serde_json::Deserializer::from_str(encoded).into_iter::<String>() {
        value.push_str(&segment.context("decoding DNS TXT segment")?);
    }
    Ok(value)
}

fn dns_target_eq(observed: &str, desired: &str) -> bool {
    match (
        observed.trim().parse::<std::net::IpAddr>(),
        desired.trim().parse::<std::net::IpAddr>(),
    ) {
        (Ok(observed), Ok(desired)) => observed == desired,
        (Err(_), Err(_)) => {
            crate::db::canonical_delivery_hostname(observed.trim_end_matches('.')).ok()
                == crate::db::canonical_delivery_hostname(desired.trim_end_matches('.')).ok()
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn explicit_controller_wakeup_enqueues_topology_pass() {
        let database = Arc::new(Database::open_in_memory().await.unwrap());
        let queue = Arc::new(crate::jobs::InMemoryQueue::new());
        let scheduler = DatabaseTopologyProbeScheduler::new(database).with_wakeup(queue.clone());

        scheduler.wake_controller().await.unwrap();

        assert_eq!(queue.drain(), vec![Job::RunTopologyProbes]);
    }

    #[test]
    fn grant_revocation_detail_accepts_generated_target_field_names() {
        for replacement in [
            serde_json::json!({
                "resource_kind": "endpoint",
                "resource_stable_id": "endpoint:test",
                "resource_generation": 2,
                "configuration_digest": "a".repeat(64),
                "expected_resource_version": "3"
            }),
            serde_json::json!({
                "resourceKind": "endpoint",
                "resourceStableId": "endpoint:test",
                "resourceGeneration": 2,
                "configurationDigest": "a".repeat(64),
                "expectedResourceVersion": "3"
            }),
        ] {
            let target: GrantRevocationTarget = serde_json::from_value(replacement).unwrap();
            assert_eq!(target.resource_generation, 2);
            assert_eq!(target.expected_resource_version, "3");
        }
    }

    struct MockCloudflareApi {
        responses: std::collections::BTreeMap<String, Vec<u8>>,
    }

    #[async_trait::async_trait]
    impl CloudflareControlPlaneClient for MockCloudflareApi {
        async fn get(&self, path: &str) -> Result<Vec<u8>> {
            self.responses
                .get(path)
                .cloned()
                .with_context(|| format!("unexpected Cloudflare API path {path}"))
        }
    }

    struct MockRouteHttp {
        url: String,
        body: Vec<u8>,
    }

    #[async_trait::async_trait]
    impl HttpClient for MockRouteHttp {
        async fn post_form(&self, _url: &str, _form: &[(String, String)]) -> Result<Vec<u8>> {
            anyhow::bail!("unexpected POST")
        }

        async fn get(&self, url: &str) -> Result<Vec<u8>> {
            anyhow::ensure!(url == self.url, "unexpected edge URL");
            Ok(self.body.clone())
        }
    }

    fn cloudflare_target(revision: String) -> crate::db::RouteReconciliationTarget {
        crate::db::RouteReconciliationTarget {
            id: "route:cdn".to_string(),
            configuration_generation: 8,
            configuration_digest: "a".repeat(64),
            endpoint_id: "endpoint:cdn".to_string(),
            endpoint_generation: 3,
            canonical_url: "https://cdn.example/cache".to_string(),
            mode: "hub_redirect".to_string(),
            access_policy_digest: "b".repeat(64),
            access_policy_kind: "external_provider".to_string(),
            external_provider_kind: Some("cloudflare".to_string()),
            external_provider_resource_id: Some(
                "accounts/account1/zones/zone1/custom_hostnames/host1/access_apps/app1".to_string(),
            ),
            external_provider_revision: Some(revision),
            publication_manifest_id: None,
        }
    }

    fn cloudflare_fixture(
        metadata_change: Option<(&str, &str)>,
        edge_body: Vec<u8>,
        access: serde_json::Value,
    ) -> (
        CloudflareRouteControlPlane,
        crate::db::RouteReconciliationTarget,
    ) {
        let expected_body = vec![9_u8; 4];
        let mut metadata = serde_json::json!({
            "aos_route_id": "route:cdn",
            "aos_configuration_generation": "8",
            "aos_configuration_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aos_endpoint_id": "endpoint:cdn",
            "aos_endpoint_generation": "3",
            "aos_access_policy_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "aos_liveness_url": "https://cdn.example/cache/live-object",
            "aos_liveness_sha256": hex::encode(Sha256::digest(&expected_body)),
        });
        if let Some((key, value)) = metadata_change {
            metadata[key] = serde_json::Value::String(value.to_string());
        }
        let hostname = serde_json::json!({
            "id": "host1",
            "status": "active",
            "custom_metadata": metadata,
        });
        let snapshot = serde_json::json!({
            "hostname": hostname,
            "accessPolicies": access,
        });
        let revision = cloudflare_snapshot_revision(&snapshot).unwrap();
        let responses = std::collections::BTreeMap::from([
            (
                "/client/v4/zones/zone1/custom_hostnames/host1".to_string(),
                serde_json::to_vec(&serde_json::json!({
                    "success": true,
                    "result": snapshot["hostname"].clone(),
                }))
                .unwrap(),
            ),
            (
                "/client/v4/accounts/account1/access/apps/app1/policies".to_string(),
                serde_json::to_vec(&serde_json::json!({
                    "success": true,
                    "result": snapshot["accessPolicies"].clone(),
                }))
                .unwrap(),
            ),
        ]);
        (
            CloudflareRouteControlPlane::new(
                Arc::new(MockCloudflareApi { responses }),
                Arc::new(MockRouteHttp {
                    url: "https://cdn.example/cache/live-object".to_string(),
                    body: edge_body,
                }),
            ),
            cloudflare_target(revision),
        )
    }

    fn route_target() -> crate::db::RouteReconciliationTarget {
        crate::db::RouteReconciliationTarget {
            id: "route:test".to_string(),
            configuration_generation: 4,
            configuration_digest: "a".repeat(64),
            endpoint_id: "endpoint:test".to_string(),
            endpoint_generation: 7,
            canonical_url: "https://cache.example/cache".to_string(),
            mode: "direct".to_string(),
            access_policy_digest: "b".repeat(64),
            access_policy_kind: "external_provider".to_string(),
            external_provider_kind: Some("cloudflare".to_string()),
            external_provider_resource_id: Some("distribution:test".to_string()),
            external_provider_revision: Some("etag:4".to_string()),
            publication_manifest_id: Some("manifest:4".to_string()),
        }
    }

    fn route_evidence() -> RouteProbeEvidence {
        RouteProbeEvidence {
            route_id: "route:test".to_string(),
            configuration_generation: 4,
            configuration_digest: "a".repeat(64),
            endpoint_id: "endpoint:test".to_string(),
            endpoint_generation: 7,
            access_policy_digest: "b".repeat(64),
            publication_manifest_id: Some("manifest:4".to_string()),
            external_provider_kind: Some("cloudflare".to_string()),
            external_provider_resource_id: Some("distribution:test".to_string()),
            external_provider_revision: Some("etag:4".to_string()),
            provider_configuration_observed: true,
            deployment_observed: true,
            access_observed: true,
            edge_observed: true,
        }
    }

    #[test]
    fn route_evidence_rejects_stale_generation_manifest_access_and_edge() {
        let target = route_target();
        let evidence = route_evidence();
        assert!(validate_route_evidence(&target, &evidence).is_ok());

        let mut stale = evidence.clone();
        stale.configuration_generation = 3;
        assert!(validate_route_evidence(&target, &stale).is_err());
        let mut stale = evidence.clone();
        stale.publication_manifest_id = Some("manifest:3".to_string());
        assert!(validate_route_evidence(&target, &stale).is_err());
        let mut stale = evidence.clone();
        stale.access_policy_digest = "c".repeat(64);
        assert!(validate_route_evidence(&target, &stale).is_err());
        let mut stale = evidence;
        stale.edge_observed = false;
        assert!(validate_route_evidence(&target, &stale).is_err());
    }

    #[test]
    fn direct_liveness_url_is_same_origin_and_segment_contained() {
        let canonical = "https://cache.example/cache";
        assert!(
            validated_route_liveness_url(canonical, "https://cache.example/cache/live-object")
                .is_ok()
        );
        for rejected in [
            "https://cache.example/cache-evil/live-object",
            "https://other.example/cache/live-object",
            "http://cache.example/cache/live-object",
            "https://user@cache.example/cache/live-object",
            "https://cache.example/cache/live-object?token=secret",
            "https://cache.example/cache/live-object#fragment",
        ] {
            assert!(
                validated_route_liveness_url(canonical, rejected).is_err(),
                "accepted {rejected}"
            );
        }
    }

    #[tokio::test]
    async fn cloudflare_control_plane_requires_exact_metadata_revision_access_and_edge() {
        let access = serde_json::json!([{"id": "policy1", "decision": "allow"}]);
        let (adapter, target) = cloudflare_fixture(None, vec![9_u8; 4], access.clone());
        assert!(adapter.observe_external(&target).await.is_ok());

        let mut stale_revision = target.clone();
        stale_revision.external_provider_revision = Some(format!("sha256:{}", "0".repeat(64)));
        assert!(adapter.observe_external(&stale_revision).await.is_err());

        for (field, wrong) in [
            ("aos_route_id", "route:other"),
            ("aos_configuration_generation", "7"),
            (
                "aos_configuration_digest",
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            ),
            ("aos_endpoint_id", "endpoint:other"),
            ("aos_endpoint_generation", "2"),
            (
                "aos_access_policy_digest",
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            ),
        ] {
            let (adapter, target) =
                cloudflare_fixture(Some((field, wrong)), vec![9_u8; 4], access.clone());
            assert!(
                adapter.observe_external(&target).await.is_err(),
                "accepted mismatched {field}"
            );
        }

        let (adapter, target) = cloudflare_fixture(None, vec![8_u8; 4], access.clone());
        assert!(adapter.observe_external(&target).await.is_err());

        let (adapter, mut target) = cloudflare_fixture(
            None,
            vec![9_u8; 4],
            serde_json::json!([{"id": "different-policy", "decision": "deny"}]),
        );
        target.external_provider_revision = Some(
            cloudflare_target(
                cloudflare_snapshot_revision(&serde_json::json!({
                    "hostname": {},
                    "accessPolicies": access,
                }))
                .unwrap(),
            )
            .external_provider_revision
            .unwrap(),
        );
        assert!(adapter.observe_external(&target).await.is_err());
    }

    fn signed_proof(
        signing_key: &ed25519_dalek::SigningKey,
        nonce: &str,
        issued_at: i64,
    ) -> Vec<u8> {
        sign_domain_probe_response(
            signing_key,
            DomainProbeResponseInput {
                nonce: nonce.to_string(),
                hostname: "cache.example".to_string(),
                endpoint_id: "endpoint-1".to_string(),
                endpoint_generation: 4,
                issued_at,
            },
        )
        .unwrap()
    }

    #[test]
    fn tls_proof_is_signature_nonce_identity_and_freshness_bound() {
        let verifier = DomainTlsProbeVerifier::new();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[11_u8; 32]);
        let identity = crate::db::EndpointProbeSigningIdentity {
            provider: "native_file".to_string(),
            signer_secret_ref: "test".to_string(),
            public_key: URL_SAFE_NO_PAD.encode(signing_key.verifying_key().as_bytes()),
        };
        let nonce = URL_SAFE_NO_PAD.encode([7_u8; 32]);
        let proof = signed_proof(&signing_key, &nonce, 90);
        assert!(verifier
            .verify(
                &proof,
                &nonce,
                "cache.example",
                "endpoint-1",
                4,
                &identity,
                100
            )
            .is_ok());
        assert!(verifier
            .verify(
                &proof,
                "another-nonce",
                "cache.example",
                "endpoint-1",
                4,
                &identity,
                100
            )
            .is_err());
        assert!(verifier
            .verify(
                &proof,
                &nonce,
                "other.example",
                "endpoint-1",
                4,
                &identity,
                100
            )
            .is_err());
        assert!(verifier
            .verify(
                &proof,
                &nonce,
                "cache.example",
                "endpoint-1",
                4,
                &identity,
                121
            )
            .is_err());

        let other_key = ed25519_dalek::SigningKey::from_bytes(&[12_u8; 32]);
        let other_identity = crate::db::EndpointProbeSigningIdentity {
            public_key: URL_SAFE_NO_PAD.encode(other_key.verifying_key().as_bytes()),
            ..identity.clone()
        };
        assert!(verifier
            .verify(
                &proof,
                &nonce,
                "cache.example",
                "endpoint-1",
                4,
                &other_identity,
                100
            )
            .is_err());
    }

    #[test]
    fn dns_txt_values_preserve_exact_content_and_join_segments() {
        assert_eq!(
            super::dns_txt_value(r#""aos-domain-verify=abc""#).unwrap(),
            "aos-domain-verify=abc"
        );
        assert_eq!(
            super::dns_txt_value(r#""aos-domain-" "verify=abc""#).unwrap(),
            "aos-domain-verify=abc"
        );
        assert_eq!(
            super::dns_txt_value("aos-domain-verify=abc").unwrap(),
            "aos-domain-verify=abc"
        );
    }
}
