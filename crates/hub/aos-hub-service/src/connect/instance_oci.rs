//! Typed dispatch for instance-owned OCI root routes.
//!
//! An enabled instance OCI route owns a host's `/v2` namespace. Every
//! repository name on it is resolved through the enabled registry namespaces
//! and the route's default registry (see [`crate::oci::namespace`]) before the
//! request reaches the shared Distribution handler with a registry-local
//! repository. Ambiguity between the default registry's catalog and another
//! registry's namespace fails closed here; it is never resolved by preference.

use aos_oci_types::{DistributionErrorCode, RepositoryName};
use axum::extract::Request;
use axum::http::{Method, StatusCode, Uri};
use axum::response::Response;

use crate::db::{InboundEndpointHost, InboundInstanceOciRoute};
use crate::oci::namespace::{OciNamespaceCatalog, OciNamespaceError, OciNamespaceMatch};
use crate::oci::{self, OciRequest, ResolvedOciRoute};
use crate::service::RpcService;

/// Rewrites one `/v2` request on an instance OCI route for the internal handler.
///
/// # Errors
///
/// Returns a rendered Distribution error for an unready route, a malformed or
/// unsupported path, an unknown or ambiguous repository name, token scopes
/// that span registries, or an unavailable catalog.
pub(super) async fn rewrite_for_instance_oci_route(
    svc: &RpcService,
    mut request: Request,
    route: InboundInstanceOciRoute,
    host: &InboundEndpointHost,
    port: u16,
    scheme: &str,
    surface_path: &str,
) -> Result<Request, Response> {
    let head = *request.method() == Method::HEAD;
    let fail = |status: StatusCode, code: DistributionErrorCode, message: &str| {
        oci::distribution_error_response(status, code, message, None, head)
    };
    if !route.ready {
        return Err(fail(
            StatusCode::SERVICE_UNAVAILABLE,
            DistributionErrorCode::Unsupported,
            "OCI route is temporarily unavailable",
        ));
    }
    let parsed = match oci::parse_oci_path(surface_path) {
        Ok(parsed) => parsed,
        Err(oci::OciPathError::InvalidReference) => {
            return Err(fail(
                StatusCode::BAD_REQUEST,
                DistributionErrorCode::NameInvalid,
                "invalid OCI repository, tag, or digest",
            ));
        }
        Err(oci::OciPathError::Unknown) => {
            return Err(fail(
                StatusCode::NOT_FOUND,
                DistributionErrorCode::Unsupported,
                "unsupported Distribution endpoint",
            ));
        }
    };
    let Ok(authority) = oci::canonical_service_authority(scheme, host, port) else {
        return Err(fail(
            StatusCode::SERVICE_UNAVAILABLE,
            DistributionErrorCode::Unsupported,
            "OCI service authority is unavailable",
        ));
    };
    let Ok(namespaces) = svc.db.enabled_oci_namespaces().await else {
        return Err(fail(
            StatusCode::SERVICE_UNAVAILABLE,
            DistributionErrorCode::Unsupported,
            "OCI namespace catalog is unavailable",
        ));
    };
    let catalog = OciNamespaceCatalog::new(namespaces, route.default_registry_id);

    let (registry_id, repository_prefix, local_request) = match parsed {
        OciRequest::Ping => (route.default_registry_id, None, OciRequest::Ping),
        OciRequest::Token => {
            let resolved = resolve_token_scopes(svc, &catalog, request.uri().query(), head).await?;
            (
                Some(resolved.registry_id),
                resolved.prefix,
                OciRequest::Token,
            )
        }
        repository_request => {
            let Some(name) = repository_request.repository() else {
                return Err(fail(
                    StatusCode::NOT_FOUND,
                    DistributionErrorCode::Unsupported,
                    "unsupported Distribution request",
                ));
            };
            let resolved = resolve_repository(svc, &catalog, name, head).await?;
            (
                Some(resolved.registry_id),
                resolved.prefix,
                repository_request.with_repository(resolved.repository),
            )
        }
    };

    // The Worker's single-registry affinity hint cannot describe a shared
    // authority; a stale hint must not steer requests toward one registry.
    if let Some(kv) = &svc.kv {
        if let Err(error) = oci::clear_oci_route_projection(kv.as_ref(), &authority).await {
            tracing::warn!(
                authority,
                route_id = route.id,
                error = %format!("{error:#}"),
                "clearing OCI route projection for instance route failed"
            );
        }
    }

    request.extensions_mut().insert(ResolvedOciRoute {
        registry_id,
        authority,
        scheme: scheme.to_owned(),
        access_policy_kind: route.access_policy_kind,
        repository_prefix,
        request: local_request,
    });
    let mut rewritten = "/_aos-internal/delivery".to_owned();
    if let Some(query) = request.uri().query() {
        rewritten.push('?');
        rewritten.push_str(query);
    }
    match Uri::try_from(rewritten) {
        Ok(uri) => {
            *request.uri_mut() = uri;
            Ok(request)
        }
        Err(_) => Err(fail(
            StatusCode::BAD_REQUEST,
            DistributionErrorCode::Unsupported,
            "OCI request routing failed",
        )),
    }
}

/// Resolves one wire repository name, failing closed on ambiguity.
async fn resolve_repository(
    svc: &RpcService,
    catalog: &OciNamespaceCatalog,
    name: &RepositoryName,
    head: bool,
) -> Result<OciNamespaceMatch, Response> {
    let fail = |status: StatusCode, code: DistributionErrorCode, message: &str| {
        oci::distribution_error_response(status, code, message, None, head)
    };
    let resolved = match catalog.resolve(name) {
        Ok(resolved) => resolved,
        Err(OciNamespaceError::Unknown) => {
            return Err(fail(
                StatusCode::NOT_FOUND,
                DistributionErrorCode::NameUnknown,
                "repository unknown",
            ));
        }
        Err(OciNamespaceError::MissingRepository) => {
            return Err(fail(
                StatusCode::BAD_REQUEST,
                DistributionErrorCode::NameInvalid,
                "a registry namespace must be followed by a repository name",
            ));
        }
    };
    if !resolved.shadows_default {
        return Ok(resolved);
    }
    let Some(default_registry_id) = catalog.default_registry_id() else {
        return Ok(resolved);
    };
    match svc.db.oci_repository(default_registry_id, name).await {
        Ok(None) => Ok(resolved),
        Ok(Some(_)) => Err(fail(
            StatusCode::CONFLICT,
            DistributionErrorCode::NameInvalid,
            "repository name is ambiguous between the default registry and a registry namespace",
        )),
        Err(_) => Err(fail(
            StatusCode::SERVICE_UNAVAILABLE,
            DistributionErrorCode::Unsupported,
            "repository catalog is unavailable",
        )),
    }
}

/// Resolves every requested token scope to one registry and namespace prefix.
///
/// Tokens are minted per registry, so a scope list that spans registries is
/// rejected rather than partially honored.
async fn resolve_token_scopes(
    svc: &RpcService,
    catalog: &OciNamespaceCatalog,
    query: Option<&str>,
    head: bool,
) -> Result<OciNamespaceMatch, Response> {
    let invalid = || {
        oci::distribution_error_response(
            StatusCode::BAD_REQUEST,
            DistributionErrorCode::Unauthorized,
            "invalid OCI token service or scope",
            None,
            head,
        )
    };
    let token_request = oci::parse_token_query(query.unwrap_or_default()).map_err(|_| invalid())?;
    let mut selected: Option<OciNamespaceMatch> = None;
    for grant in &token_request.grants {
        let resolved = resolve_repository(svc, catalog, &grant.repository, head).await?;
        match &selected {
            None => selected = Some(resolved),
            Some(first)
                if first.registry_id == resolved.registry_id && first.prefix == resolved.prefix => {
            }
            Some(_) => return Err(invalid()),
        }
    }
    selected.ok_or_else(invalid)
}
