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

/// Anonymous server-rendered browse surface eligible for the colocated path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AnonymousBrowseRoute<'a> {
    /// Instance registry directory.
    Instance,
    /// One registry's human browse surface.
    Registry(&'a str),
}

/// Classifies a request that can never contain personalized browse content.
#[must_use]
pub(crate) fn anonymous_browse_route<'a>(
    method: &str,
    path: &'a str,
    accept: Option<&str>,
    authorization_present: bool,
    session_cookie_present: bool,
) -> Option<AnonymousBrowseRoute<'a>> {
    if !matches!(method, "GET" | "HEAD")
        || authorization_present
        || session_cookie_present
        || !accepts_html(accept)
    {
        return None;
    }
    if path == "/" {
        return Some(AnonymousBrowseRoute::Instance);
    }
    browse_registry_slug(path).map(AnonymousBrowseRoute::Registry)
}

fn accepts_html(accept: Option<&str>) -> bool {
    let Some(accept) = accept else {
        return true;
    };
    accept.split(',').any(|part| {
        matches!(
            part.split(';').next().map(str::trim),
            Some("text/html" | "text/*" | "*/*")
        )
    })
}

/// Returns whether a successful request can change anonymous browse output.
#[must_use]
pub(crate) fn invalidates_browse_directory(method: &str, path: &str) -> bool {
    if matches!(method, "GET" | "HEAD" | "OPTIONS") || !is_connect_path(path) {
        return false;
    }
    if path.contains("/UploadObject/") || path.contains("/UploadPart/") {
        return false;
    }
    let operation = path.rsplit('/').next().unwrap_or_default();
    ![
        "Get",
        "List",
        "Search",
        "Resolve",
        "Preview",
        "WhoAmI",
        "GitLog",
        "GitDiff",
        "CacheClosure",
        "Plan",
        "UploadObject",
        "UploadPart",
        "AppendRegistryPublicationManifest",
    ]
    .iter()
    .any(|prefix| operation.starts_with(prefix))
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

/// Extracts a canonical repository from one supported OCI Distribution path.
///
/// Ping and token requests intentionally return `None`: they remain on HubDb
/// unless the caller has another authoritative registry identity. Malformed or
/// encoded aliases also return `None` and are rejected later by the shared
/// router rather than influencing execution affinity.
#[must_use]
pub(crate) fn oci_repository_from_path(path: &str) -> Option<aos_oci_types::RepositoryName> {
    aos_hub_core::oci::parse_oci_path(path)
        .ok()
        .and_then(|request| request.repository().cloned())
}

/// Routes one already-resolved registry/repository pair to a stable shard.
///
/// The outer Worker obtains the stable registry incarnation from an
/// eventually-consistent authority projection. This value is affinity only;
/// the shared router re-resolves authority and authorization from SQL.
#[must_use]
pub(crate) fn classify_oci_repository(
    method: &str,
    registry_stable_id: &str,
    repository: &aos_oci_types::RepositoryName,
) -> RequestShardRoute {
    RequestShardRoute {
        kind: RequestShardKind::Registry,
        key: aos_hub_core::oci::oci_repository_affinity(registry_stable_id, repository),
        read_only: matches!(method, "GET" | "HEAD"),
        resource_specific: true,
    }
}

/// Renders the canonical OCI token audience for one parsed request URL.
///
/// User information and non-HTTP schemes are rejected. Default ports are
/// omitted and IPv6 literals retain the brackets required in authorities.
#[must_use]
pub(crate) fn canonical_oci_authority(url: &url::Url) -> Option<String> {
    if !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    let host = match url.host()? {
        url::Host::Domain(domain) => domain.to_ascii_lowercase(),
        url::Host::Ipv4(address) => address.to_string(),
        url::Host::Ipv6(address) => format!("[{address}]"),
    };
    let port = url.port_or_known_default()?;
    let default_port = match url.scheme() {
        "http" => 80,
        "https" => 443,
        _ => return None,
    };
    Some(if port == default_port {
        host
    } else {
        format!("{host}:{port}")
    })
}

/// Validates one persisted stable registry incarnation identifier.
#[must_use]
pub(crate) fn canonical_registry_stable_id(value: &str) -> bool {
    value.len() == "registry:".len() + 32
        && value.strip_prefix("registry:").is_some_and(|opaque| {
            opaque
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        })
}

fn is_connect_path(path: &str) -> bool {
    path.starts_with("/aos.hub.v1.")
}

fn request_kind(path: &str, body: Option<&[u8]>) -> RequestShardKind {
    // ContainerService remains on the control shard through Phase 7. Moving its
    // reviewed administration surface requires an explicit migration because
    // publication transactions already use this authority.
    if path.contains(".ContainerService/") {
        return RequestShardKind::Control;
    }
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
        if let Some(slug) = browse_registry_slug(path) {
            return Some(format!("registry:{slug}"));
        }
    }
    None
}

/// Extracts the canonical registry slug from a human browse path.
///
/// Registry homes do not contain the reserved `/-/` marker, so treating only
/// marked browse paths as resource-specific sent every home page on a host to
/// one authority shard. This parser deliberately owns both shapes and rejects
/// reserved instance namespaces.
#[must_use]
pub(crate) fn browse_registry_slug(path: &str) -> Option<&str> {
    let nested = path.trim_start_matches('/');
    if let Some((slug, _)) = nested.split_once("/-/") {
        return valid_browse_slug(slug).then_some(slug);
    }

    let slug = nested.strip_suffix('/')?;
    valid_browse_slug(slug).then_some(slug)
}

fn valid_browse_slug(slug: &str) -> bool {
    !slug.is_empty()
        && !slug.starts_with('_')
        && !slug.starts_with('.')
        && slug
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
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
    fn oci_affinity_is_registry_and_repository_specific() {
        let repository = oci_repository_from_path(
            "/v2/team/runtime/manifests/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap();
        assert_eq!(repository.as_str(), "team/runtime");
        let first = classify_oci_repository(
            "GET",
            "registry:00000000000000000000000000000001",
            &repository,
        );
        assert_eq!(first.kind, RequestShardKind::Registry);
        assert!(first.read_only);
        assert!(first.resource_specific);
        assert_eq!(first.key.len(), 32);
        assert_ne!(
            first,
            classify_oci_repository(
                "GET",
                "registry:00000000000000000000000000000002",
                &repository,
            )
        );
        assert_ne!(
            first,
            classify_oci_repository(
                "GET",
                "registry:00000000000000000000000000000001",
                &aos_oci_types::RepositoryName::parse("team/other").unwrap(),
            )
        );
        assert!(
            !classify_oci_repository(
                "PATCH",
                "registry:00000000000000000000000000000001",
                &repository,
            )
            .read_only
        );
        for path in [
            "/v2/",
            "/v2/token",
            "/v2/team%2fruntime/blobs/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "/v2/team//runtime/tags/list",
        ] {
            assert!(oci_repository_from_path(path).is_none(), "accepted {path}");
        }
    }

    #[test]
    fn oci_authorities_and_registry_incarnations_are_canonical() {
        assert_eq!(
            canonical_oci_authority(&url::Url::parse("https://EXAMPLE.test:443/v2/").unwrap()),
            Some("example.test".to_string())
        );
        assert_eq!(
            canonical_oci_authority(&url::Url::parse("http://[::1]:8080/v2/").unwrap()),
            Some("[::1]:8080".to_string())
        );
        assert!(
            canonical_oci_authority(&url::Url::parse("ftp://example.test/v2/").unwrap()).is_none()
        );
        assert!(canonical_registry_stable_id(
            "registry:0123456789abcdef0123456789abcdef"
        ));
        assert!(!canonical_registry_stable_id(
            "registry:0123456789ABCDEF0123456789ABCDEF"
        ));
    }

    #[test]
    fn registry_home_and_browse_pages_share_affinity() {
        let home = classify_request("GET", "/andyl/main/", "hub.example", None);
        let packages = classify_request("GET", "/andyl/main/-/packages", "hub.example", None);
        let images = classify_request("GET", "/andyl/main/-/images", "hub.example", None);

        assert!(home.resource_specific);
        assert_eq!(home.key, packages.key);
        assert_eq!(home.key, images.key);
        assert_eq!(browse_registry_slug("/andyl/main/"), Some("andyl/main"));
        assert_eq!(
            browse_registry_slug("/andyl/main/-/packages"),
            Some("andyl/main")
        );
        assert_eq!(browse_registry_slug("/"), None);
        assert_eq!(browse_registry_slug("/_assets/"), None);
    }

    #[test]
    fn only_anonymous_html_uses_the_colocated_browse_fast_path() {
        assert_eq!(
            anonymous_browse_route("GET", "/", Some("text/html"), false, false),
            Some(AnonymousBrowseRoute::Instance)
        );
        assert_eq!(
            anonymous_browse_route(
                "GET",
                "/andyl/main/-/packages",
                Some("text/html,application/xhtml+xml"),
                false,
                false,
            ),
            Some(AnonymousBrowseRoute::Registry("andyl/main"))
        );
        assert_eq!(
            anonymous_browse_route("GET", "/andyl/main/", None, true, false),
            None
        );
        assert_eq!(
            anonymous_browse_route("GET", "/andyl/main/", None, false, true),
            None
        );
        assert_eq!(
            anonymous_browse_route(
                "GET",
                "/andyl/main/",
                Some("application/octet-stream"),
                false,
                false,
            ),
            None
        );
    }

    #[test]
    fn browse_invalidation_excludes_reads_plans_and_object_chunks() {
        assert!(invalidates_browse_directory(
            "POST",
            "/aos.hub.v1.PublishService/CommitRegistryPublication"
        ));
        assert!(invalidates_browse_directory(
            "POST",
            "/aos.hub.v1.RegistryService/UpdateRegistry"
        ));
        assert!(!invalidates_browse_directory(
            "POST",
            "/aos.hub.v1.RegistryService/GetRegistry"
        ));
        assert!(!invalidates_browse_directory(
            "POST",
            "/aos.hub.v1.RegistryService/PlanUpdateRegistry"
        ));
        assert!(!invalidates_browse_directory(
            "PUT",
            "/aos.hub.v1.PublishService/UploadObject/publication/42"
        ));
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
            ("ContainerService", RequestShardKind::Control),
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

    #[test]
    fn phase_seven_container_service_remains_on_the_control_shard() {
        for method in [
            "ListContainerRepositories",
            "PlanSetContainerTag",
            "BeginContainerPublication",
            "PlanRunContainerGc",
            "ListContainerGcCandidates",
            "ListContainerGcBlockers",
            "ListContainerGcPlacementActions",
            "RequeueContainerGcPlacementAction",
            "ListContainerUntrackedInventory",
            "PlanRepairContainerUntrackedObject",
            "RepairContainerUntrackedObject",
            "GetContainerUntrackedRepair",
            "PlanContainerRegistryPurgeFence",
            "ApplyContainerRegistryPurgeFence",
            "GetContainerRegistryPurgeFence",
        ] {
            let path = format!("/aos.hub.v1.ContainerService/{method}");
            let classified = classify_request(
                "POST",
                &path,
                "hub.example",
                Some(br#"{"registry":"andyl/main","repository":"aos"}"#),
            );
            assert_eq!(classified.kind, RequestShardKind::Control, "{method}");
            assert!(!classified.resource_specific, "{method}");
        }
    }
}
