//! Deterministic request-execution shard routing.
//!
//! The relational source of truth remains the single transactional `HubDb`.
//! This module assigns the comparatively expensive HTTP/service execution to a
//! control singleton or a tenant, registry, or cache resource shard. Shards use
//! the seal-gated remote SQL protocol for short transactions, so routing never
//! changes database ownership or weakens cross-resource constraints.

use sha2::{Digest as _, Sha256};

/// Logical request-execution partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RequestShardKind {
    /// Instance-wide authentication, settings, audit, and fallback operations.
    Control,
    /// Organization, project, identity, binding, and topology operations.
    Tenant,
    /// Registry publication, index, package, channel, image, and Git operations.
    Registry,
    /// Binary-cache inventory, upload, retention, and garbage-collection operations.
    Cache,
}

impl RequestShardKind {
    /// Returns the stable lowercase partition label used in object names and logs.
    #[must_use]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::Tenant => "tenant",
            Self::Registry => "registry",
            Self::Cache => "cache",
        }
    }
}

/// One deterministic execution-shard decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RequestShardRoute {
    /// Logical partition owning request execution.
    pub(crate) kind: RequestShardKind,
    /// Opaque, fixed-width resource affinity key.
    pub(crate) key: String,
    /// Whether the operation is safe during a read-only staged cutover.
    pub(crate) read_only: bool,
    /// Whether routing found a resource identity rather than using the partition fallback.
    pub(crate) resource_specific: bool,
}

impl RequestShardRoute {
    /// Returns the deployment-scoped Durable Object instance name.
    #[must_use]
    #[cfg(target_arch = "wasm32")]
    pub(crate) fn instance_name(&self, database_instance: &str) -> String {
        format!("{database_instance}:{}:{}", self.kind.as_str(), self.key)
    }
}

/// Classifies an HTTP request from its path, authority, and optional JSON body.
///
/// The body is used only as an affinity hint. It is never trusted for
/// authorization or resource identity; the shared service re-resolves every
/// resource against authoritative SQL state. Unknown shapes remain safe on a
/// stable per-partition fallback shard.
#[must_use]
pub(crate) fn classify_request(
    method: &str,
    path: &str,
    authority: &str,
    json_body: Option<&[u8]>,
) -> RequestShardRoute {
    let kind = request_kind(path, json_body);
    let path_key = resource_key_from_path(kind, path);
    let body_key = json_body
        .and_then(|body| serde_json::from_slice::<serde_json::Value>(body).ok())
        .and_then(|value| resource_key_from_json(kind, &value));
    let authority_key =
        (!authority.is_empty() && !is_connect_path(path)).then(|| format!("authority:{authority}"));
    let resource_key = path_key.or(body_key).or(authority_key);
    let resource_specific = resource_key.is_some();
    let affinity = resource_key.unwrap_or_else(|| "shared".to_string());
    let key = hex::encode(Sha256::digest(
        format!("{}\0{affinity}", kind.as_str()).as_bytes(),
    ));

    RequestShardRoute {
        kind,
        key: key[..32].to_string(),
        read_only: request_is_read_only(method, path),
        resource_specific,
    }
}

fn is_connect_path(path: &str) -> bool {
    path.starts_with("/aos.hub.v1.")
}

fn request_kind(path: &str, body: Option<&[u8]>) -> RequestShardKind {
    if path.contains(".BinaryCacheService/")
        || path.contains(".CacheIntegrationService/")
        || path.contains(".BinaryCacheUploadControllerService/")
        || path.contains("/BinaryCacheService/")
        || path.starts_with("/_cache/")
    {
        return RequestShardKind::Cache;
    }
    if path.contains(".PublishService/")
        || path.contains(".RegistryService/")
        || path.contains(".RegistryMirrorService/")
        || path.contains(".RegistryConfigurationService/")
        || path.contains(".GitService/")
        || path.contains(".PackageService/")
        || path.contains(".ChannelService/")
        || path.contains(".ImageService/")
    {
        return RequestShardKind::Registry;
    }
    if path.contains(".OrganizationService/")
        || path.contains(".SigningKeyService/")
        || path.contains(".ProjectService/")
        || path.contains(".BindingService/")
        || path.contains(".DomainService/")
        || path.contains(".NetworkPolicyService/")
        || path.contains(".EndpointService/")
        || path.contains(".GatewayService/")
        || path.contains(".RouteService/")
        || path.contains(".DeliveryService/")
        || path.contains(".PlacementService/")
        || path.contains(".BindingControllerService/")
        || path.contains(".NetworkPolicyControllerService/")
        || path.contains(".DeliveryControllerService/")
        || path.contains(".RouteControllerService/")
        || path.contains(".TopologyControllerService/")
        || path.contains(".WebhookService/")
    {
        return RequestShardKind::Tenant;
    }
    if path.contains(".TopologyService/") {
        if let Some(body) = body {
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) {
                if json_has_any_key(&value, &["cache", "cacheId", "cacheSlug"]) {
                    return RequestShardKind::Cache;
                }
                if json_has_any_key(
                    &value,
                    &["registry", "registryId", "registrySlug", "publicationId"],
                ) {
                    return RequestShardKind::Registry;
                }
            }
        }
        return RequestShardKind::Tenant;
    }
    if !is_connect_path(path) && path != "/" && !path.starts_with("/_") {
        return RequestShardKind::Registry;
    }
    RequestShardKind::Control
}

fn resource_key_from_path(kind: RequestShardKind, path: &str) -> Option<String> {
    for marker in [
        "PublishService/UploadObject/",
        "PublishService/UploadPart/",
        "BinaryCacheService/UploadObject/",
        "BinaryCacheService/UploadPart/",
    ] {
        if let Some(rest) = path.split_once(marker).map(|(_, rest)| rest) {
            if let Some(identity) = rest.split('/').find(|part| !part.is_empty()) {
                return Some(format!("path-id:{identity}"));
            }
        }
    }
    if kind == RequestShardKind::Registry {
        if let Some((slug, _)) = path.trim_start_matches('/').split_once("/-/") {
            if !slug.is_empty() {
                return Some(format!("registry:{slug}"));
            }
        }
    }
    None
}

fn resource_key_from_json(kind: RequestShardKind, value: &serde_json::Value) -> Option<String> {
    let candidates: &[&str] = match kind {
        RequestShardKind::Control => &[],
        RequestShardKind::Tenant => &[
            "orgSlug",
            "org",
            "organizationId",
            "projectId",
            "bindingId",
            "domainId",
            "scope",
            "slug",
        ],
        RequestShardKind::Registry => &[
            "registry",
            "registrySlug",
            "publicationId",
            "uploadId",
            "slug",
        ],
        RequestShardKind::Cache => &[
            "cache",
            "cacheSlug",
            "cacheId",
            "ticketId",
            "uploadId",
            "slug",
        ],
    };
    find_json_string(value, candidates, 0)
}

fn find_json_string(
    value: &serde_json::Value,
    candidates: &[&str],
    depth: usize,
) -> Option<String> {
    if depth > 4 {
        return None;
    }
    match value {
        serde_json::Value::Object(fields) => {
            for candidate in candidates {
                if let Some(value) = fields.get(*candidate).and_then(serde_json::Value::as_str) {
                    if !value.is_empty() {
                        return Some(format!("{candidate}:{value}"));
                    }
                }
            }
            fields
                .values()
                .find_map(|value| find_json_string(value, candidates, depth + 1))
        }
        serde_json::Value::Array(values) => values
            .iter()
            .find_map(|value| find_json_string(value, candidates, depth + 1)),
        _ => None,
    }
}

fn json_has_any_key(value: &serde_json::Value, candidates: &[&str]) -> bool {
    find_json_string(value, candidates, 0).is_some()
}

fn request_is_read_only(method: &str, path: &str) -> bool {
    if matches!(method, "GET" | "HEAD" | "OPTIONS") {
        return true;
    }
    let operation = path.rsplit('/').next().unwrap_or_default();
    [
        "Get",
        "List",
        "Search",
        "Resolve",
        "Preview",
        "WhoAmI",
        "GitLog",
        "GitDiff",
        "CacheClosure",
    ]
    .iter()
    .any(|prefix| operation.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_resource_families_and_stable_affinity() {
        let registry = classify_request(
            "POST",
            "/aos.hub.v1.PublishService/AppendRegistryPublicationManifest",
            "hub.example",
            Some(br#"{"publicationId":"publication-1","chunkIndex":3}"#),
        );
        assert_eq!(registry.kind, RequestShardKind::Registry);
        assert!(registry.resource_specific);
        assert!(!registry.read_only);
        assert_eq!(registry.key.len(), 32);
        assert_eq!(
            registry,
            classify_request(
                "POST",
                "/aos.hub.v1.PublishService/AppendRegistryPublicationManifest",
                "hub.example",
                Some(br#"{"publicationId":"publication-1","chunkIndex":4}"#),
            )
        );

        let cache = classify_request(
            "POST",
            "/aos.hub.v1.BinaryCacheService/CreateCacheObjectUploads",
            "hub.example",
            Some(br#"{"cache":"team/cache","objects":[]}"#),
        );
        assert_eq!(cache.kind, RequestShardKind::Cache);
        assert_ne!(cache.key, registry.key);

        let tenant = classify_request(
            "POST",
            "/aos.hub.v1.OrganizationService/GetOrganization",
            "hub.example",
            Some(br#"{"orgSlug":"team"}"#),
        );
        assert_eq!(tenant.kind, RequestShardKind::Tenant);
        assert!(tenant.read_only);
    }

    #[test]
    fn routes_upload_paths_without_reading_the_payload() {
        let publication = classify_request(
            "PUT",
            "/aos.hub.v1.PublishService/UploadObject/publication-1/42",
            "hub.example",
            None,
        );
        assert_eq!(publication.kind, RequestShardKind::Registry);
        assert!(publication.resource_specific);

        let cache = classify_request(
            "PUT",
            "/aos.hub.v1.BinaryCacheService/UploadObject/ticket-1",
            "hub.example",
            None,
        );
        assert_eq!(cache.kind, RequestShardKind::Cache);
        assert!(cache.resource_specific);
    }

    #[test]
    fn unknown_shapes_use_a_stable_partition_fallback() {
        let one = classify_request(
            "POST",
            "/aos.hub.v1.IdentityService/Login",
            "hub.example",
            Some(br#"{"email":"one@example.com"}"#),
        );
        let two = classify_request(
            "POST",
            "/aos.hub.v1.IdentityService/Login",
            "hub.example",
            Some(br#"{"email":"two@example.com"}"#),
        );
        assert_eq!(one.kind, RequestShardKind::Control);
        assert!(!one.resource_specific);
        assert_eq!(one.key, two.key);
    }

    #[test]
    fn every_hub_service_has_an_explicit_partition() {
        for (service, expected) in [
            ("RegistryService", RequestShardKind::Registry),
            ("RegistryMirrorService", RequestShardKind::Registry),
            ("RegistryConfigurationService", RequestShardKind::Registry),
            ("PackageService", RequestShardKind::Registry),
            ("ChannelService", RequestShardKind::Registry),
            ("ImageService", RequestShardKind::Registry),
            ("PublishService", RequestShardKind::Registry),
            ("GitService", RequestShardKind::Registry),
            ("BinaryCacheService", RequestShardKind::Cache),
            ("CacheIntegrationService", RequestShardKind::Cache),
            (
                "BinaryCacheUploadControllerService",
                RequestShardKind::Cache,
            ),
            ("OrganizationService", RequestShardKind::Tenant),
            ("SigningKeyService", RequestShardKind::Tenant),
            ("ProjectService", RequestShardKind::Tenant),
            ("BindingService", RequestShardKind::Tenant),
            ("DomainService", RequestShardKind::Tenant),
            ("NetworkPolicyService", RequestShardKind::Tenant),
            ("DeliveryService", RequestShardKind::Tenant),
            ("RouteService", RequestShardKind::Tenant),
            ("TopologyService", RequestShardKind::Tenant),
            ("BindingControllerService", RequestShardKind::Tenant),
            ("NetworkPolicyControllerService", RequestShardKind::Tenant),
            ("DeliveryControllerService", RequestShardKind::Tenant),
            ("RouteControllerService", RequestShardKind::Tenant),
            ("TopologyControllerService", RequestShardKind::Tenant),
            ("WebhookService", RequestShardKind::Tenant),
            ("AuditService", RequestShardKind::Control),
            ("InstanceService", RequestShardKind::Control),
            ("OperationService", RequestShardKind::Control),
            ("IdentityService", RequestShardKind::Control),
        ] {
            let path = format!("/aos.hub.v1.{service}/Unknown");
            assert_eq!(
                classify_request("POST", &path, "hub.example", None).kind,
                expected,
                "{service}"
            );
        }
    }
}
