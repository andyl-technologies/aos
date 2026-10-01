//! Bounded signed Native logical control for direct provider uploads.
//!
//! The paired ingress attests the public transport, while a separate logical
//! body domain binds the private phase. Current JWT provenance and configured
//! target authority are checked before the retained service mutates SQL.

pub mod authority;

use std::sync::Arc;

use anyhow::{ensure, Result};
use aos_hub_core::auth::jwt::JwtKeys;
use aos_hub_core::direct_upload::*;
use aos_hub_core::hybrid_ingress::{HybridIngressAssertion, HybridOriginRequest};
use aos_hub_core::storage_work::StorageWorkKey;
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse as _, Response};

/// Configured runtime factory using the router's actual current RPC authority.
pub trait DirectUploadTransportFactory: Send + Sync {
    /// Builds dispatch using the same IAM, leases and storage dependencies as RPC.
    ///
    /// # Errors
    /// Returns an error when independently configured dependencies are incomplete.
    fn build(
        &self,
        db: Arc<crate::db::Database>,
        rpc: Arc<aos_hub_core::service::RpcService>,
        jwt_keys: JwtKeys,
        deployment: &str,
    ) -> Result<Arc<DirectUploadTransport>>;
}

/// Authenticated metadata transport with exact deployment and executor pins.
pub struct DirectUploadTransport {
    service: DirectUploadService,
    jwt_keys: JwtKeys,
    logical_key: StorageWorkKey,
    deployment_id: String,
    executor_origin: String,
    clock_uncertainty_seconds: u64,
}

impl DirectUploadTransport {
    /// Configures logical dispatch beside an explicitly paired Worker origin.
    ///
    /// The uncertainty must come from the independently reviewed deployment
    /// clock qualification. The authority separately requires qualified provider
    /// and current guard dependencies before accepting an original admission.
    ///
    /// # Errors
    /// Returns an error for invalid deployment, origin or uncertainty bounds.
    pub fn new(
        service: DirectUploadService,
        jwt_keys: JwtKeys,
        logical_key: StorageWorkKey,
        deployment_id: String,
        executor_origin: String,
        clock_uncertainty_seconds: u64,
    ) -> Result<Self> {
        let origin = url::Url::parse(&executor_origin)?;
        ensure!(
            valid_direct_identity(&deployment_id)
                && origin.scheme() == "https"
                && origin.host_str().is_some()
                && origin.username().is_empty()
                && origin.password().is_none()
                && origin.path() == "/"
                && origin.query().is_none()
                && origin.fragment().is_none()
                && origin.origin().ascii_serialization() == executor_origin
                && (1..30).contains(&clock_uncertainty_seconds),
            "invalid direct logical transport configuration"
        );
        Ok(Self {
            service,
            jwt_keys,
            logical_key,
            deployment_id,
            executor_origin,
            clock_uncertainty_seconds,
        })
    }

    /// Handles the exact signed logical service body after verified hybrid ingress.
    ///
    /// No public object bytes are accepted by this handler. Bodies are bounded
    /// again at this boundary before signature verification or JSON decoding.
    pub async fn handle(&self, request: axum::extract::Request) -> Response {
        match self.handle_checked(request).await {
            Ok(response) => response,
            Err(status) => status.into_response(),
        }
    }

    async fn handle_checked(
        &self,
        request: axum::extract::Request,
    ) -> Result<Response, StatusCode> {
        if request.method() != Method::POST
            || request.uri().query().is_some()
            || request.extensions().get::<HybridOriginRequest>().is_none()
        {
            return Err(StatusCode::UNAUTHORIZED);
        }
        let ingress = request
            .extensions()
            .get::<HybridIngressAssertion>()
            .cloned()
            .ok_or(StatusCode::UNAUTHORIZED)?;
        let authorization = single_header(request.headers(), header::AUTHORIZATION.as_str())?;
        let bearer = authorization
            .strip_prefix("Bearer ")
            .ok_or(StatusCode::UNAUTHORIZED)?;
        let claims = self
            .jwt_keys
            .verify(bearer)
            .map_err(|_| StatusCode::UNAUTHORIZED)?;
        let path = request.uri().path().to_owned();
        let now = aos_hub_core::clock::now_unix_secs();
        let latest = u64::try_from(now)
            .ok()
            .and_then(|now| now.checked_add(self.clock_uncertainty_seconds))
            .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
        if path == "/aos.hub.v1.DirectUploadService/GetCapabilities" {
            if ingress.upload_phase.is_some() {
                return Err(StatusCode::BAD_REQUEST);
            }
            let body = axum::body::to_bytes(request.into_body(), 4096)
                .await
                .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;
            let query: DirectGetCapabilities =
                decode_direct_control(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
            let capabilities = self
                .service
                .get_capabilities(
                    &claims,
                    &query.target,
                    &self.deployment_id,
                    i64::try_from(latest).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
                )
                .await
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            let mut response = (
                StatusCode::OK,
                encode_direct_control(&capabilities)
                    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
            )
                .into_response();
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            return Ok(response);
        }
        let phase = ingress
            .upload_phase
            .as_deref()
            .ok_or(StatusCode::BAD_REQUEST)?;
        let signature = single_header(request.headers(), DIRECT_LOGICAL_SIGNATURE_HEADER)?;
        let body = axum::body::to_bytes(request.into_body(), MAX_DIRECT_CONTROL_BYTES)
            .await
            .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;
        let envelope = verify_direct_logical_request(
            &self.logical_key,
            &signature,
            &body,
            &self.deployment_id,
            &self.executor_origin,
            latest,
        )
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
        envelope
            .validate_transport("POST", &path, &ingress.authority, phase)
            .map_err(|_| StatusCode::UNAUTHORIZED)?;
        let reply = self
            .service
            .dispatch(
                &claims,
                &envelope,
                i64::try_from(latest).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
            )
            .await
            .map_err(|_| StatusCode::UNAUTHORIZED)?;
        let signed = sign_direct_logical_reply(
            &self.logical_key,
            &DirectLogicalReplyEnvelope {
                context: envelope.context,
                reply,
            },
        )
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let mut response = (StatusCode::OK, signed.body).into_response();
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response.headers_mut().insert(
            DIRECT_LOGICAL_SIGNATURE_HEADER,
            HeaderValue::from_str(&signed.signature)
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
        );
        Ok(response)
    }
}

fn single_header(headers: &HeaderMap, name: &str) -> Result<String, StatusCode> {
    let mut values = headers.get_all(name).iter();
    let value = values.next().ok_or(StatusCode::UNAUTHORIZED)?;
    if values.next().is_some() {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(value
        .to_str()
        .map_err(|_| StatusCode::UNAUTHORIZED)?
        .to_owned())
}
