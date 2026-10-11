//! Paired current-effect confirmation over exact retained notification claims.
//!
//! A physical executor receives a short dispatch grant only after the coordinator
//! has rechecked current reviewer, destination, resource and every pinned member.
//! The request carries commitments and a challenge; event bodies and actor claims
//! remain in the coordinator database.

use std::sync::Arc;

use anyhow::{ensure, Result};
use aos_assessment_http::PhysicalClock;
use aos_assessment_runtime::notifications::{
    NotificationInstallationV1, NotificationWorkAuth, NotificationWorkPlanV1,
    NOTIFICATION_EFFECT_PATH,
};
use aos_assessment_runtime::ports::Clock;
use aos_hub_core::assessment_execution::confirm_assessment_notification_effect;
use aos_hub_core::db::{AssessmentObjectKind, Database};
use axum::body::{to_bytes, Body};
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::Response;

use crate::server::AppState;

/// Confirms one independently installed executor's exact current notification claims.
pub struct NotificationAuthorityService {
    db: Arc<Database>,
    installation: NotificationInstallationV1,
    auth: Arc<NotificationWorkAuth>,
}

impl NotificationAuthorityService {
    pub(super) fn new(
        db: Arc<Database>,
        installation: NotificationInstallationV1,
        auth: Arc<NotificationWorkAuth>,
    ) -> Self {
        Self {
            db,
            installation,
            auth,
        }
    }

    /// Authenticates a compact challenge and signs only freshly checked dispatch facts.
    ///
    /// # Errors
    /// Returns an error for wrong MAC/scope, stale challenges, missing retained work,
    /// revoked current authority or insufficient remaining physical time.
    pub async fn confirm(&self, bytes: &[u8], signature: &str) -> Result<(Vec<u8>, String)> {
        ensure!(
            bytes.len() <= 4096,
            "notification effect query exceeds its compact bound"
        );
        let query = self
            .auth
            .verify_effect_query(bytes, signature, &PhysicalClock.now()?)?;
        let grant =
            confirm_assessment_notification_effect(&self.db, &self.installation, &query).await?;
        let bytes = self
            .db
            .assessment_object(
                &query.resource_scope,
                AssessmentObjectKind::NotificationWork,
                query.plan_digest,
            )
            .await?
            .ok_or_else(|| anyhow::anyhow!("notification effect retained work is absent"))?;
        let plan = NotificationWorkPlanV1::from_slice(&bytes, &grant.checked_at)?;
        self.auth
            .sign_effect_grant(&grant, &query, &plan, &PhysicalClock.now()?)
    }
}

/// Admits only bounded paired current-effect challenges to the installed authority.
pub(crate) async fn notification_effect(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Response {
    let Some(authority) = state.assessment_notification_authority.get() else {
        return refused(StatusCode::SERVICE_UNAVAILABLE);
    };
    if request.uri().path() != NOTIFICATION_EFFECT_PATH || request.uri().query().is_some() {
        return refused(StatusCode::NOT_FOUND);
    }
    let Some(signature) = request
        .headers()
        .get("X-AOS-Assessment-Notification-Signature")
        .and_then(|value| value.to_str().ok())
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .map(str::to_owned)
    else {
        return refused(StatusCode::UNAUTHORIZED);
    };
    if request
        .headers()
        .get("content-type")
        .is_none_or(|value| value != "application/json")
        || request.headers().contains_key("content-encoding")
    {
        return refused(StatusCode::BAD_REQUEST);
    }
    let Ok(body) = to_bytes(request.into_body(), 4096).await else {
        return refused(StatusCode::PAYLOAD_TOO_LARGE);
    };
    match authority.confirm(&body, &signature).await {
        Ok((bytes, signature)) => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .header("cache-control", "private, no-store")
            .header("X-AOS-Assessment-Notification-Signature", signature)
            .body(Body::from(bytes))
            .unwrap_or_else(|_| refused(StatusCode::INTERNAL_SERVER_ERROR)),
        Err(_) => refused(StatusCode::CONFLICT),
    }
}

fn refused(status: StatusCode) -> Response {
    let mut response = Response::new(Body::from("notification effect confirmation refused"));
    *response.status_mut() = status;
    response.headers_mut().insert(
        "cache-control",
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}
