//! OCI Distribution request, authority, challenge, and token contracts.
//!
//! Delivery authorities are resolved to an AOS registry before this module is
//! invoked. Repository names are then parsed from the canonical raw path and
//! remain local to that registry. Private requests authorize the exact
//! repository before any tag, manifest, or blob lookup, preventing digest
//! probing across repositories that share registry-wide CAS bytes.

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use aos_oci_types::{
    to_canonical_json, Annotations, DistributionError, DistributionErrorCode,
    DistributionErrorEnvelope, ImageIndex, ManifestReference, MediaType, RepositoryName,
    Sha256Digest, Tag,
};
use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::auth::jwt::OciTokenGrant;
use crate::db::{InboundEndpointHost, RegistryRecord, SurfaceTarget};
use crate::delivery_http::{DeliveryMethod, HttpTimestamp};
use crate::oci_http::{OciAccess, OciHttpMetadata, OciHttpRequest};
use crate::placement_read::PlacementReadOutcome;
use crate::service::{ReadAuthorization, RpcError, RpcService};

/// Distribution API version advertised on every OCI response.
pub const DISTRIBUTION_API_VERSION: &str = "registry/2.0";

/// Header advertising the Distribution protocol version.
pub const DISTRIBUTION_API_VERSION_HEADER: HeaderName =
    HeaderName::from_static("docker-distribution-api-version");

/// Header carrying the canonical content digest.
pub const CONTENT_DIGEST_HEADER: HeaderName = HeaderName::from_static("docker-content-digest");

/// Short-lived pull-token lifetime.
pub const OCI_PULL_TOKEN_TTL_SECONDS: i64 = 300;

/// Returns the opaque KV key projecting one canonical OCI authority to its
/// owning registry incarnation.
#[must_use]
pub fn oci_route_projection_key(authority: &str) -> String {
    format!(
        "oci-route:{}",
        hex::encode(Sha256::digest(authority.as_bytes()))
    )
}

/// Returns the fixed-width execution affinity for one registry-owned OCI
/// repository.
#[must_use]
pub fn oci_repository_affinity(registry_stable_id: &str, repository: &RepositoryName) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"aos-hub-oci-repository-affinity-v1\0");
    hasher.update(registry_stable_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(repository.as_str().as_bytes());
    hex::encode(hasher.finalize())[..32].to_string()
}

/// One exact request on a registry's root `/v2` surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OciRequest {
    /// Distribution version discovery.
    Ping,
    /// Same-authority repository-token exchange.
    Token,
    /// Immutable blob bytes.
    Blob {
        /// Exact repository local to the route's registry.
        repository: RepositoryName,
        /// Exact SHA-256 digest.
        digest: Sha256Digest,
    },
    /// Manifest or index bytes addressed by tag or digest.
    Manifest {
        /// Exact repository local to the route's registry.
        repository: RepositoryName,
        /// Exact tag or SHA-256 digest.
        reference: ManifestReference,
    },
    /// Deterministic repository tag listing.
    Tags {
        /// Exact repository local to the route's registry.
        repository: RepositoryName,
    },
    /// OCI 1.1 referrer listing.
    Referrers {
        /// Exact repository local to the route's registry.
        repository: RepositoryName,
        /// Exact referred subject digest.
        digest: Sha256Digest,
    },
}

impl OciRequest {
    /// Returns the repository named by a repository-scoped operation.
    #[must_use]
    pub const fn repository(&self) -> Option<&RepositoryName> {
        match self {
            Self::Blob { repository, .. }
            | Self::Manifest { repository, .. }
            | Self::Tags { repository }
            | Self::Referrers { repository, .. } => Some(repository),
            Self::Ping | Self::Token => None,
        }
    }
}

/// Failure to interpret an exact Distribution path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OciPathError {
    /// The path does not name a supported v1 endpoint.
    Unknown,
    /// A repository, tag, or digest is non-canonical.
    InvalidReference,
}

/// Parses one route-relative canonical path without normalization fallback.
///
/// # Errors
///
/// Returns [`OciPathError::InvalidReference`] for malformed repository,
/// digest, or tag bytes, and [`OciPathError::Unknown`] for unsupported paths.
pub fn parse_oci_path(path: &str) -> std::result::Result<OciRequest, OciPathError> {
    let path = path.trim_start_matches('/');
    if path == "v2" || path == "v2/" {
        return Ok(OciRequest::Ping);
    }
    if path == "v2/token" {
        return Ok(OciRequest::Token);
    }
    let rest = path.strip_prefix("v2/").ok_or(OciPathError::Unknown)?;
    if rest.contains('%') || rest.contains('\\') || rest.contains("//") {
        return Err(OciPathError::InvalidReference);
    }
    if let Some(repository) = rest.strip_suffix("/tags/list") {
        return RepositoryName::parse(repository)
            .map(|repository| OciRequest::Tags { repository })
            .map_err(|_| OciPathError::InvalidReference);
    }
    if let Some((repository, digest)) = rest.rsplit_once("/referrers/") {
        return Ok(OciRequest::Referrers {
            repository: RepositoryName::parse(repository)
                .map_err(|_| OciPathError::InvalidReference)?,
            digest: Sha256Digest::parse(digest).map_err(|_| OciPathError::InvalidReference)?,
        });
    }
    if let Some((repository, digest)) = rest.rsplit_once("/blobs/") {
        return Ok(OciRequest::Blob {
            repository: RepositoryName::parse(repository)
                .map_err(|_| OciPathError::InvalidReference)?,
            digest: Sha256Digest::parse(digest).map_err(|_| OciPathError::InvalidReference)?,
        });
    }
    if let Some((repository, reference)) = rest.rsplit_once("/manifests/") {
        return Ok(OciRequest::Manifest {
            repository: RepositoryName::parse(repository)
                .map_err(|_| OciPathError::InvalidReference)?,
            reference: ManifestReference::parse(reference)
                .map_err(|_| OciPathError::InvalidReference)?,
        });
    }
    Err(OciPathError::Unknown)
}

/// Parsed standard token-exchange query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciTokenRequest {
    /// Exact canonical service authority.
    pub service: String,
    /// Exact repository requested in the pull scope.
    pub repository: RepositoryName,
}

/// Parses a single `service` and `repository:<name>:pull` query.
///
/// # Errors
///
/// Returns an error for missing, duplicate, extra, malformed, or broader
/// query fields and scopes.
pub fn parse_token_query(query: &str) -> Result<OciTokenRequest> {
    let pairs = url::form_urlencoded::parse(query.as_bytes()).collect::<Vec<_>>();
    if pairs.len() != 2 {
        bail!("OCI token query requires exactly service and scope");
    }
    let mut service = None;
    let mut scope = None;
    for (key, value) in pairs {
        match key.as_ref() {
            "service" if service.is_none() => service = Some(value.into_owned()),
            "scope" if scope.is_none() => scope = Some(value.into_owned()),
            _ => bail!("OCI token query contains duplicate or unsupported fields"),
        }
    }
    let service = service.context("OCI token service is missing")?;
    if service.is_empty()
        || service.len() > 255
        || !service.is_ascii()
        || service.chars().any(char::is_control)
    {
        bail!("OCI token service is malformed");
    }
    let scope = scope.context("OCI token scope is missing")?;
    let repository = scope
        .strip_prefix("repository:")
        .and_then(|value| value.strip_suffix(":pull"))
        .context("OCI token scope must be repository:<name>:pull")?;
    Ok(OciTokenRequest {
        service,
        repository: RepositoryName::parse(repository)?,
    })
}

/// Renders the exact service authority bound into challenges and tokens.
///
/// # Errors
///
/// Returns an error for unsupported schemes or malformed persisted host bytes.
pub fn canonical_service_authority(
    scheme: &str,
    host: &InboundEndpointHost,
    port: u16,
) -> Result<String> {
    let default_port = match scheme {
        "http" => 80,
        "https" => 443,
        _ => bail!("OCI authority scheme must be http or https"),
    };
    let rendered = match host {
        InboundEndpointHost::Domain(domain) => domain.clone(),
        InboundEndpointHost::Ipv4(bytes) => {
            let octets: [u8; 4] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("OCI IPv4 authority has invalid bytes"))?;
            std::net::Ipv4Addr::from(octets).to_string()
        }
        InboundEndpointHost::Ipv6(bytes) => {
            let octets: [u8; 16] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("OCI IPv6 authority has invalid bytes"))?;
            format!("[{}]", std::net::Ipv6Addr::from(octets))
        }
    };
    if port == default_port {
        Ok(rendered)
    } else {
        Ok(format!("{rendered}:{port}"))
    }
}

/// Builds the standard same-authority Bearer challenge for one repository.
#[must_use]
pub fn pull_challenge(scheme: &str, authority: &str, repository: &RepositoryName) -> String {
    format!(
        "Bearer realm=\"{scheme}://{authority}/v2/token\",service=\"{authority}\",scope=\"repository:{repository}:pull\""
    )
}

/// Standard token-service JSON response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OciTokenResponse {
    /// Compact repository-scoped bearer.
    pub token: String,
    /// Alias required by some Distribution clients.
    pub access_token: String,
    /// Lifetime in seconds.
    pub expires_in: i64,
    /// RFC 3339 UTC issue time.
    pub issued_at: String,
}

/// Typed route state carried from authority resolution to the internal handler.
#[derive(Debug, Clone)]
pub struct ResolvedOciRoute {
    /// Exact registry database id selected by the delivery route.
    pub registry_id: i64,
    /// Exact canonical service authority.
    pub authority: String,
    /// Trusted listener scheme used by the same-authority token realm.
    pub scheme: String,
    /// Exact route-level access policy selected by topology resolution.
    pub access_policy_kind: String,
    /// Exact parsed Distribution operation.
    pub request: OciRequest,
}

impl RpcService {
    /// Exchanges an existing Hub bearer or provisioning-token Basic password
    /// for one repository-scoped OCI pull token.
    ///
    /// The repository need not exist; authorization is evaluated only against
    /// the already-resolved owning registry so the token endpoint is not a
    /// private repository existence oracle. A `hub_auth` delivery route
    /// requires Hub credentials even when the registry itself is public.
    ///
    /// # Errors
    ///
    /// Returns an authentication, registry authorization, malformed credential,
    /// or token-signing error.
    pub async fn mint_oci_pull_token(
        &self,
        registry: &RegistryRecord,
        authority: &str,
        repository: &RepositoryName,
        authorization: Option<&str>,
        route_requires_hub_auth: bool,
    ) -> Result<OciTokenResponse, RpcError> {
        let (subject, hub_bearer) = match authorization {
            Some(value) if value.starts_with("Bearer ") => {
                let claims = self.require_claims(Some(value))?;
                (format!("hub:{}", claims.sub), value.to_string())
            }
            Some(value) if value.starts_with("Basic ") => {
                let encoded = value.strip_prefix("Basic ").unwrap_or_default();
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .map_err(|_| RpcError::Unauthenticated("invalid Basic credentials".into()))?;
                let decoded = String::from_utf8(decoded)
                    .map_err(|_| RpcError::Unauthenticated("invalid Basic credentials".into()))?;
                let (_, secret) = decoded
                    .split_once(':')
                    .ok_or_else(|| RpcError::Unauthenticated("invalid Basic credentials".into()))?;
                let auth = self
                    .validate_token_cached(secret)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| RpcError::Unauthenticated("invalid credentials".into()))?;
                let bearer = self.jwt_keys.mint(&auth, 60).map_err(RpcError::internal)?;
                (
                    format!("token:{}", auth.token_id),
                    format!("Bearer {bearer}"),
                )
            }
            Some(_) => {
                return Err(RpcError::Unauthenticated(
                    "OCI token exchange requires Bearer or Basic credentials".into(),
                ));
            }
            None if !route_requires_hub_auth
                && (registry.visibility == "public" || registry.org_id.is_none()) =>
            {
                ("anonymous".to_string(), String::new())
            }
            None => {
                return Err(RpcError::Unauthenticated(
                    "credentials are required for this registry".into(),
                ));
            }
        };
        if route_requires_hub_auth {
            self.require_authenticated_registry_read(Some(&hub_bearer), registry)
                .await?;
        } else if !(registry.visibility == "public" || registry.org_id.is_none()) {
            self.authorize_delivery_surface_read(
                ReadAuthorization::AuthorizationHeader(Some(&hub_bearer)),
                SurfaceTarget::Registry(registry.id),
            )
            .await?;
        }
        let token = self
            .jwt_keys
            .mint_oci(
                &OciTokenGrant {
                    subject,
                    authority: authority.to_string(),
                    registry_stable_id: registry.stable_id.clone(),
                    repository: repository.clone(),
                    actions: vec!["pull".to_string()],
                },
                OCI_PULL_TOKEN_TTL_SECONDS,
            )
            .map_err(RpcError::internal)?;
        Ok(OciTokenResponse {
            access_token: token.clone(),
            token,
            expires_in: OCI_PULL_TOKEN_TTL_SECONDS,
            issued_at: format_rfc3339_utc(crate::clock::now_unix_secs()),
        })
    }

    /// Authorizes one exact repository pull without performing object lookup.
    ///
    /// # Errors
    ///
    /// Returns an authentication or repository-scope mismatch for a private
    /// registry or a `hub_auth` delivery route. Public registry pulls remain
    /// anonymous only on an explicitly public route.
    pub fn authorize_oci_pull(
        &self,
        registry: &RegistryRecord,
        authority: &str,
        repository: &RepositoryName,
        authorization: Option<&str>,
        route_requires_oci_token: bool,
    ) -> Result<(), RpcError> {
        if !route_requires_oci_token
            && (registry.visibility == "public" || registry.org_id.is_none())
        {
            return Ok(());
        }
        let header = authorization
            .ok_or_else(|| RpcError::Unauthenticated("OCI pull token is required".into()))?;
        let token = header.strip_prefix("Bearer ").ok_or_else(|| {
            RpcError::Unauthenticated("Authorization header must start with Bearer".into())
        })?;
        let claims = self
            .jwt_keys
            .verify_oci_claims(token)
            .map_err(|error| RpcError::Unauthenticated(error.to_string()))?;
        if claims.aud != authority
            || claims.registry != registry.stable_id
            || claims.repository != *repository
            || claims.actions.as_slice() != ["pull"]
        {
            return Err(RpcError::PermissionDenied(
                "OCI token is not authorized for this repository request".into(),
            ));
        }
        Ok(())
    }

    /// Serves one already-routed read-only Distribution request.
    ///
    /// # Errors
    ///
    /// This method renders protocol errors into the returned response. It does
    /// not return transport errors to the outer Connect router.
    pub async fn serve_oci(
        self: Arc<Self>,
        resolved: ResolvedOciRoute,
        method: Method,
        headers: HeaderMap,
        query: Option<&str>,
    ) -> Response {
        let head = method == Method::HEAD;
        if !matches!(method, Method::GET | Method::HEAD) {
            return distribution_error_response(
                StatusCode::METHOD_NOT_ALLOWED,
                DistributionErrorCode::Unsupported,
                "read-only OCI delivery accepts only GET and HEAD",
                None,
                head,
            );
        }
        let registry = match self.db.registry_by_id(resolved.registry_id).await {
            Ok(Some(registry)) => registry,
            Ok(None) => {
                return distribution_error_response(
                    StatusCode::NOT_FOUND,
                    DistributionErrorCode::NameUnknown,
                    "repository unknown",
                    None,
                    head,
                );
            }
            Err(_) => return unavailable_response("registry catalog is unavailable", head),
        };
        if let Some(org_id) = registry.org_id {
            match self.db.org_is_active(org_id).await {
                Ok(true) => {}
                Ok(false) => {
                    return distribution_error_response(
                        StatusCode::NOT_FOUND,
                        DistributionErrorCode::NameUnknown,
                        "repository unknown",
                        None,
                        head,
                    );
                }
                Err(_) => return unavailable_response("registry catalog is unavailable", head),
            }
        }
        if resolved.request == OciRequest::Ping {
            let mut response = if head {
                (StatusCode::OK, Body::empty()).into_response()
            } else {
                (StatusCode::OK, [(header::CONTENT_LENGTH, "2")], "{}").into_response()
            };
            add_distribution_version(&mut response);
            return response;
        }
        let route_requires_hub_auth = resolved.access_policy_kind == "hub_auth";
        if resolved.request == OciRequest::Token {
            if head {
                return distribution_error_response(
                    StatusCode::METHOD_NOT_ALLOWED,
                    DistributionErrorCode::Unsupported,
                    "token exchange requires GET",
                    None,
                    true,
                );
            }
            let token_request = match parse_token_query(query.unwrap_or_default()) {
                Ok(request) if request.service == resolved.authority => request,
                Ok(_) | Err(_) => {
                    return distribution_error_response(
                        StatusCode::BAD_REQUEST,
                        DistributionErrorCode::Unauthorized,
                        "invalid OCI token service or scope",
                        None,
                        false,
                    );
                }
            };
            let authorization = headers
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok());
            return match self
                .mint_oci_pull_token(
                    &registry,
                    &resolved.authority,
                    &token_request.repository,
                    authorization,
                    route_requires_hub_auth,
                )
                .await
            {
                Ok(token) => {
                    let mut response = axum::Json(token).into_response();
                    response.headers_mut().insert(
                        header::CACHE_CONTROL,
                        HeaderValue::from_static("private, no-store"),
                    );
                    add_distribution_version(&mut response);
                    response
                }
                Err(RpcError::PermissionDenied(_)) => distribution_error_response(
                    StatusCode::FORBIDDEN,
                    DistributionErrorCode::Denied,
                    "permission denied",
                    None,
                    false,
                ),
                Err(RpcError::Internal | RpcError::Unavailable(_)) => distribution_error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    DistributionErrorCode::Unsupported,
                    "token service is temporarily unavailable",
                    None,
                    false,
                ),
                Err(_) => {
                    let challenge = pull_challenge(
                        &resolved.scheme,
                        &resolved.authority,
                        &token_request.repository,
                    );
                    distribution_error_response(
                        StatusCode::UNAUTHORIZED,
                        DistributionErrorCode::Unauthorized,
                        "authentication required",
                        Some(&challenge),
                        false,
                    )
                }
            };
        }

        let Some(repository_name) = resolved.request.repository() else {
            return distribution_error_response(
                StatusCode::NOT_FOUND,
                DistributionErrorCode::Unsupported,
                "unsupported Distribution request",
                None,
                head,
            );
        };
        let authorization = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok());
        if let Err(error) = self.authorize_oci_pull(
            &registry,
            &resolved.authority,
            repository_name,
            authorization,
            route_requires_hub_auth,
        ) {
            if matches!(error, RpcError::PermissionDenied(_)) {
                return distribution_error_response(
                    StatusCode::FORBIDDEN,
                    DistributionErrorCode::Denied,
                    "permission denied",
                    None,
                    head,
                );
            }
            let challenge = pull_challenge(&resolved.scheme, &resolved.authority, repository_name);
            return distribution_error_response(
                StatusCode::UNAUTHORIZED,
                DistributionErrorCode::Unauthorized,
                "authentication required",
                Some(&challenge),
                head,
            );
        }
        let repository = match self.db.oci_repository(registry.id, repository_name).await {
            Ok(Some(repository)) => repository,
            Ok(None) => {
                return distribution_error_response(
                    StatusCode::NOT_FOUND,
                    DistributionErrorCode::NameUnknown,
                    "repository unknown",
                    None,
                    head,
                );
            }
            Err(_) => return unavailable_response("repository catalog is unavailable", head),
        };
        let private = resolved.access_policy_kind != "public"
            || !(registry.visibility == "public" || registry.org_id.is_none());
        match resolved.request {
            OciRequest::Blob { digest, .. } => {
                let blob = match self.db.oci_blob_for_repository(repository.id, digest).await {
                    Ok(Some(blob)) => blob,
                    Ok(None) => {
                        return distribution_error_response(
                            StatusCode::NOT_FOUND,
                            DistributionErrorCode::BlobUnknown,
                            "blob unknown",
                            None,
                            head,
                        );
                    }
                    Err(_) => return unavailable_response("blob catalog is unavailable", head),
                };
                self.serve_oci_object(
                    &headers,
                    &method,
                    registry.id,
                    blob.object_key,
                    blob.digest,
                    blob.byte_size,
                    blob.media_type,
                    private,
                )
                .await
            }
            OciRequest::Manifest { reference, .. } => {
                let manifest = match self
                    .db
                    .oci_manifest_for_repository(repository.id, &reference)
                    .await
                {
                    Ok(Some(manifest)) => manifest,
                    Ok(None) => {
                        return distribution_error_response(
                            StatusCode::NOT_FOUND,
                            DistributionErrorCode::ManifestUnknown,
                            "manifest unknown",
                            None,
                            head,
                        );
                    }
                    Err(_) => {
                        return unavailable_response("manifest catalog is unavailable", head);
                    }
                };
                if !accepts_media_type(&headers, manifest.media_type) {
                    return distribution_error_response(
                        StatusCode::NOT_ACCEPTABLE,
                        DistributionErrorCode::Unsupported,
                        "manifest media type is not acceptable",
                        None,
                        head,
                    );
                }
                self.serve_oci_object(
                    &headers,
                    &method,
                    registry.id,
                    manifest.object_key,
                    manifest.digest,
                    manifest.byte_size,
                    manifest.media_type,
                    private,
                )
                .await
            }
            OciRequest::Tags { .. } => {
                serve_tags(&self, &method, &repository, query, private).await
            }
            OciRequest::Referrers { digest, .. } => {
                serve_referrers(&self, &method, &repository, digest, query, private).await
            }
            OciRequest::Ping | OciRequest::Token => distribution_error_response(
                StatusCode::NOT_FOUND,
                DistributionErrorCode::Unsupported,
                "unsupported Distribution request",
                None,
                head,
            ),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn serve_oci_object(
        &self,
        headers: &HeaderMap,
        method: &Method,
        registry_id: i64,
        object_key: String,
        digest: Sha256Digest,
        byte_size: u64,
        media_type: MediaType,
        private: bool,
    ) -> Response {
        let now = match HttpTimestamp::from_unix_seconds(crate::clock::now_unix_secs()) {
            Ok(now) => now,
            Err(_) => {
                return unavailable_response(
                    "server clock is unavailable",
                    *method == Method::HEAD,
                );
            }
        };
        let request = OciHttpRequest {
            method: if *method == Method::HEAD {
                DeliveryMethod::Head
            } else {
                DeliveryMethod::Get
            },
            range: headers.get(header::RANGE).map(HeaderValue::as_bytes),
            if_match: headers.get(header::IF_MATCH).map(HeaderValue::as_bytes),
            if_unmodified_since: headers
                .get(header::IF_UNMODIFIED_SINCE)
                .map(HeaderValue::as_bytes),
            if_none_match: headers
                .get(header::IF_NONE_MATCH)
                .map(HeaderValue::as_bytes),
            if_modified_since: headers
                .get(header::IF_MODIFIED_SINCE)
                .map(HeaderValue::as_bytes),
            if_range: headers.get(header::IF_RANGE).map(HeaderValue::as_bytes),
            now,
        };
        let plan = match crate::oci_http::plan_oci_response(
            &OciHttpMetadata {
                media_type: media_type.as_str().to_string(),
                byte_size,
                digest: digest.to_string(),
            },
            if private {
                OciAccess::Private
            } else {
                OciAccess::Public
            },
            request,
        ) {
            Ok(plan) => plan,
            Err(_) => {
                return distribution_error_response(
                    StatusCode::BAD_REQUEST,
                    DistributionErrorCode::Unsupported,
                    "invalid OCI request headers",
                    None,
                    *method == Method::HEAD,
                );
            }
        };
        let mut response = Response::new(Body::empty());
        let Ok(status) = StatusCode::from_u16(plan.status) else {
            return unavailable_response(
                "invalid internal response status",
                *method == Method::HEAD,
            );
        };
        *response.status_mut() = status;
        for (name, value) in &plan.headers {
            let Ok(name) = HeaderName::try_from(name.as_str()) else {
                return unavailable_response(
                    "invalid internal response header",
                    *method == Method::HEAD,
                );
            };
            let Ok(value) = HeaderValue::from_str(value) else {
                return unavailable_response(
                    "invalid internal response header",
                    *method == Method::HEAD,
                );
            };
            response.headers_mut().insert(name, value);
        }
        if *method == Method::HEAD && plan.status < 300 {
            let probe_range = (byte_size > 0).then_some((0, 0));
            let probe = crate::placement_read::stream_verified_image_from_placements(
                &self.db,
                self.surface.as_ref(),
                registry_id,
                &object_key,
                &digest.encoded(),
                byte_size,
                probe_range,
            )
            .await;
            return match probe {
                Ok(PlacementReadOutcome::Found(read)) if read.value.range == probe_range => {
                    response
                }
                Ok(PlacementReadOutcome::Found(_))
                | Ok(PlacementReadOutcome::NotFound)
                | Err(_) => unavailable_response("OCI object is temporarily unavailable", true),
            };
        }
        let Some(range) = plan.body_range else {
            return response;
        };
        let storage_range = (plan.status == StatusCode::PARTIAL_CONTENT.as_u16())
            .then_some((range.start, range.end));
        let read = crate::placement_read::stream_verified_image_from_placements(
            &self.db,
            self.surface.as_ref(),
            registry_id,
            &object_key,
            &digest.encoded(),
            byte_size,
            storage_range,
        )
        .await;
        match read {
            Ok(PlacementReadOutcome::Found(read)) if read.value.range == storage_range => {
                *response.body_mut() =
                    crate::service::exact_image_body(read.value.body, range.len());
                response
            }
            Ok(PlacementReadOutcome::Found(_)) | Ok(PlacementReadOutcome::NotFound) | Err(_) => {
                distribution_error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    DistributionErrorCode::Unsupported,
                    "OCI object is temporarily unavailable",
                    None,
                    *method == Method::HEAD,
                )
            }
        }
    }
}

async fn serve_tags(
    service: &RpcService,
    method: &Method,
    repository: &crate::db::OciRepositoryRecord,
    query: Option<&str>,
    private: bool,
) -> Response {
    let (limit, last) = match parse_tag_query(query) {
        Ok(query) => query,
        Err(_) => {
            return distribution_error_response(
                StatusCode::BAD_REQUEST,
                DistributionErrorCode::TagInvalid,
                "invalid tag pagination",
                None,
                *method == Method::HEAD,
            );
        }
    };
    let tags = match service
        .db
        .oci_tags(repository.id, limit, last.as_ref())
        .await
    {
        Ok(tags) => tags,
        Err(_) => {
            return unavailable_response("tag catalog is unavailable", *method == Method::HEAD);
        }
    };
    let next = match tags.last() {
        Some(last_tag) => match service
            .db
            .oci_tag_follows(repository.id, &last_tag.name)
            .await
        {
            Ok(true) => Some(last_tag.name.clone()),
            Ok(false) => None,
            Err(_) => {
                return unavailable_response("tag catalog is unavailable", *method == Method::HEAD);
            }
        },
        None => None,
    };
    #[derive(Serialize)]
    struct TagsResponse<'a> {
        name: &'a RepositoryName,
        tags: Vec<&'a Tag>,
    }
    let body = match serde_json::to_vec(&TagsResponse {
        name: &repository.name,
        tags: tags.iter().map(|tag| &tag.name).collect(),
    }) {
        Ok(body) => body,
        Err(_) => {
            return unavailable_response("tag response encoding failed", *method == Method::HEAD);
        }
    };
    let mut response = json_response(method.clone(), body, "application/json", private);
    if let Some(next) = next {
        let link = format!(
            "</v2/{}/tags/list?n={limit}&last={next}>; rel=\"next\"",
            repository.name
        );
        let Ok(link) = HeaderValue::from_str(&link) else {
            return unavailable_response("tag pagination encoding failed", *method == Method::HEAD);
        };
        response.headers_mut().insert(header::LINK, link);
    }
    response
}

async fn serve_referrers(
    service: &RpcService,
    method: &Method,
    repository: &crate::db::OciRepositoryRecord,
    digest: Sha256Digest,
    query: Option<&str>,
    private: bool,
) -> Response {
    let artifact_type = match parse_referrer_query(query) {
        Ok(artifact_type) => artifact_type,
        Err(_) => {
            return distribution_error_response(
                StatusCode::BAD_REQUEST,
                DistributionErrorCode::Unsupported,
                "invalid referrer filter",
                None,
                *method == Method::HEAD,
            );
        }
    };
    let manifests = match service
        .db
        .oci_referrers(repository.id, digest, artifact_type)
        .await
    {
        Ok(manifests) => manifests,
        Err(_) => {
            return unavailable_response(
                "referrer catalog is unavailable",
                *method == Method::HEAD,
            );
        }
    };
    let index = ImageIndex {
        schema_version: 2,
        media_type: Some(MediaType::OciImageIndex),
        artifact_type: None,
        manifests,
        subject: None,
        annotations: Annotations::new(),
    };
    let body = match to_canonical_json(&index) {
        Ok(body) => body,
        Err(_) => {
            return unavailable_response(
                "referrer response encoding failed",
                *method == Method::HEAD,
            );
        }
    };
    json_response(
        method.clone(),
        body,
        MediaType::OciImageIndex.as_str(),
        private,
    )
}

fn parse_tag_query(query: Option<&str>) -> Result<(u32, Option<Tag>)> {
    let Some(query) = query else {
        return Ok((100, None));
    };
    let mut limit = 100_u32;
    let mut saw_limit = false;
    let mut last = None;
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        match key.as_ref() {
            "n" if !saw_limit => {
                limit = value.parse().context("invalid OCI tag page size")?;
                saw_limit = true;
            }
            "last" if last.is_none() => last = Some(Tag::parse(&value)?),
            _ => bail!("unsupported or duplicate OCI tag pagination field"),
        }
    }
    if limit == 0 || limit > crate::db::OCI_MAX_TAG_PAGE {
        bail!(
            "OCI tag page size must be between 1 and {}",
            crate::db::OCI_MAX_TAG_PAGE
        );
    }
    Ok((limit, last))
}

fn parse_referrer_query(query: Option<&str>) -> Result<Option<MediaType>> {
    let Some(query) = query else {
        return Ok(None);
    };
    let pairs = url::form_urlencoded::parse(query.as_bytes()).collect::<Vec<_>>();
    if pairs.len() != 1 || pairs[0].0 != "artifactType" {
        bail!("referrer query accepts only one artifactType field");
    }
    MediaType::parse(&pairs[0].1).map(Some).map_err(Into::into)
}

fn json_response(
    method: Method,
    body: Vec<u8>,
    content_type: &'static str,
    private: bool,
) -> Response {
    let length = body.len().to_string();
    let mut response = if method == Method::HEAD {
        Response::new(Body::empty())
    } else {
        Response::new(Body::from(body))
    };
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    if let Ok(length) = HeaderValue::from_str(&length) {
        response
            .headers_mut()
            .insert(header::CONTENT_LENGTH, length);
    }
    add_distribution_version(&mut response);
    if private {
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("private, no-store"),
        );
        response
            .headers_mut()
            .insert(header::VARY, HeaderValue::from_static("Authorization"));
    } else {
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("public, no-cache"),
        );
    }
    response
}

fn accepts_media_type(headers: &HeaderMap, media_type: MediaType) -> bool {
    let values = headers.get_all(header::ACCEPT);
    if values.iter().next().is_none() {
        return true;
    }
    values
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| {
            value.split(',').any(|member| {
                let mut pieces = member.split(';');
                let candidate = pieces.next().unwrap_or_default().trim();
                let enabled = pieces.all(|parameter| {
                    let Some((name, value)) = parameter.trim().split_once('=') else {
                        return false;
                    };
                    !name.trim().eq_ignore_ascii_case("q")
                        || value.trim().parse::<f32>().is_ok_and(|quality| {
                            quality.is_finite() && quality > 0.0 && quality <= 1.0
                        })
                });
                let media_range_matches = || {
                    if candidate == "*/*" || candidate.eq_ignore_ascii_case(media_type.as_str()) {
                        return true;
                    }
                    let Some((range_type, range_subtype)) = candidate.split_once('/') else {
                        return false;
                    };
                    let Some((media_type_name, _)) = media_type.as_str().split_once('/') else {
                        return false;
                    };
                    range_subtype == "*" && range_type.eq_ignore_ascii_case(media_type_name)
                };
                enabled && media_range_matches()
            })
        })
}

fn unavailable_response(message: &'static str, head: bool) -> Response {
    distribution_error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        DistributionErrorCode::Unsupported,
        message,
        None,
        head,
    )
}

fn add_distribution_version(response: &mut Response) {
    response.headers_mut().insert(
        DISTRIBUTION_API_VERSION_HEADER,
        HeaderValue::from_static(DISTRIBUTION_API_VERSION),
    );
}

/// Builds one standard Distribution error response.
#[must_use]
pub fn distribution_error_response(
    status: StatusCode,
    code: DistributionErrorCode,
    message: impl Into<String>,
    challenge: Option<&str>,
    head: bool,
) -> Response {
    let envelope = DistributionErrorEnvelope {
        errors: vec![DistributionError {
            code,
            message: message.into(),
            detail: None,
        }],
    };
    let body = serde_json::to_vec(&envelope).unwrap_or_else(|_| {
        br#"{"errors":[{"code":"UNSUPPORTED","message":"response encoding failed"}]}"#.to_vec()
    });
    let length = body.len().to_string();
    let mut response = if head {
        let mut response = (status, Body::empty()).into_response();
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        if let Ok(length) = HeaderValue::from_str(&length) {
            response
                .headers_mut()
                .insert(header::CONTENT_LENGTH, length);
        }
        response
    } else {
        (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
    };
    response.headers_mut().insert(
        DISTRIBUTION_API_VERSION_HEADER,
        HeaderValue::from_static(DISTRIBUTION_API_VERSION),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    if let Some(challenge) = challenge.and_then(|value| HeaderValue::from_str(value).ok()) {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, challenge);
    }
    response
}

fn format_rfc3339_utc(unix_seconds: i64) -> String {
    let seconds = unix_seconds.max(0);
    let days = seconds / 86_400;
    let day_seconds = seconds % 86_400;
    let hour = day_seconds / 3_600;
    let minute = (day_seconds % 3_600) / 60;
    let second = day_seconds % 60;

    // Howard Hinnant's civil-from-days transform, with 1970-01-01 as day 0.
    let z = days + 719_468;
    let era = z / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested_repository_distribution_paths_exactly() {
        assert_eq!(parse_oci_path("v2/"), Ok(OciRequest::Ping));
        assert!(matches!(
            parse_oci_path(&format!("v2/team/base/blobs/{}", Sha256Digest::digest(b"x"))),
            Ok(OciRequest::Blob { repository, .. }) if repository.as_str() == "team/base"
        ));
        assert!(matches!(
            parse_oci_path("v2/team/base/manifests/latest"),
            Ok(OciRequest::Manifest { repository, reference: ManifestReference::Tag(_) })
                if repository.as_str() == "team/base"
        ));
    }

    #[test]
    fn rejects_encoded_or_ambiguous_paths() {
        for path in [
            "v2/a%2fb/manifests/latest",
            "v2/a//b/manifests/latest",
            "v2/a/blobs/sha256:ABC",
            "v2/A/manifests/latest",
            "v2/a/manifests/bad@tag",
        ] {
            assert!(parse_oci_path(path).is_err(), "accepted {path}");
        }
    }

    #[test]
    fn token_query_is_exact_and_repository_scoped() {
        let request =
            parse_token_query("service=containers.example&scope=repository%3Aaos%3Apull").unwrap();
        assert_eq!(request.service, "containers.example");
        assert_eq!(request.repository.as_str(), "aos");
        assert!(
            parse_token_query("service=containers.example&scope=repository%3Aaos%3Apush").is_err()
        );
        assert!(parse_token_query("service=x&service=y&scope=repository%3Aaos%3Apull").is_err());
    }

    #[test]
    fn authority_preserves_ports_and_ipv6_brackets() {
        assert_eq!(
            canonical_service_authority(
                "https",
                &InboundEndpointHost::Domain("containers.example".into()),
                443
            )
            .unwrap(),
            "containers.example"
        );
        assert_eq!(
            canonical_service_authority(
                "http",
                &InboundEndpointHost::Ipv6(vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
                8080
            )
            .unwrap(),
            "[::1]:8080"
        );
    }

    #[test]
    fn token_issue_time_is_rfc3339_utc() {
        assert_eq!(format_rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_rfc3339_utc(1_700_000_000), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn route_projection_and_repository_affinity_are_domain_separated() {
        let repository = RepositoryName::parse("team/runtime").unwrap();
        let first =
            oci_repository_affinity("registry:00000000000000000000000000000001", &repository);
        assert_eq!(first.len(), 32);
        assert_eq!(
            first,
            oci_repository_affinity("registry:00000000000000000000000000000001", &repository,)
        );
        assert_ne!(
            first,
            oci_repository_affinity("registry:00000000000000000000000000000002", &repository,)
        );
        assert_ne!(
            oci_route_projection_key("registry.example"),
            oci_route_projection_key("registry.example:8443")
        );
    }

    #[test]
    fn accept_negotiation_rejects_zero_quality_members() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            HeaderValue::from_static(
                "application/vnd.oci.image.manifest.v1+json;q=0, application/vnd.oci.image.index.v1+json",
            ),
        );
        assert!(!accepts_media_type(&headers, MediaType::OciImageManifest));
        assert!(accepts_media_type(&headers, MediaType::OciImageIndex));
    }

    #[test]
    fn accept_negotiation_supports_case_insensitive_and_type_wildcard_ranges() {
        for value in [
            "Application/Vnd.Oci.Image.Index.V1+Json",
            "APPLICATION/*",
            "text/plain;q=0.2, application/*;q=0.5",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(header::ACCEPT, HeaderValue::from_str(value).unwrap());
            assert!(accepts_media_type(&headers, MediaType::OciImageIndex));
        }
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            HeaderValue::from_static("application/*;q=0"),
        );
        assert!(!accepts_media_type(&headers, MediaType::OciImageIndex));
    }

    #[test]
    fn private_json_responses_vary_on_authorization() {
        let response = json_response(Method::HEAD, b"{}".to_vec(), "application/json", true);
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_LENGTH], "2");
        assert_eq!(response.headers()[header::VARY], "Authorization");
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "private, no-store"
        );
        assert_eq!(
            response.headers()[DISTRIBUTION_API_VERSION_HEADER],
            DISTRIBUTION_API_VERSION
        );
    }

    #[test]
    fn public_mutable_json_requires_cache_revalidation() {
        let response = json_response(Method::GET, b"{}".to_vec(), "application/json", false);
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "public, no-cache"
        );
        assert!(response.headers().get(header::VARY).is_none());
    }
}
