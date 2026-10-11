//! Independently authenticated compact notification work to one paired HTTPS Worker.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result, ensure};
use aos_assessment_runtime::notifications::{
    NOTIFICATION_WORK_PATH, NotificationWorkAuth, NotificationWorkPlanV1, NotificationWorkReceiptV1,
};
use aos_assessment_runtime::ports::Clock;

use crate::PhysicalClock;

/// Sends notification attempts to one explicit executor without topology fallback.
pub struct RemoteNotificationExecutor {
    origin: reqwest::Url,
    auth: Arc<NotificationWorkAuth>,
    client: reqwest::Client,
}

impl RemoteNotificationExecutor {
    /// Creates a separately authenticated client without proxies or redirects.
    ///
    /// # Errors
    /// Returns an error for a malformed HTTPS origin or unavailable TLS initialization.
    pub fn new(origin: &str, auth: Arc<NotificationWorkAuth>) -> Result<Self> {
        let origin = reqwest::Url::parse(origin)?;
        ensure!(
            origin.scheme() == "https"
                && origin.host_str().is_some()
                && origin.username().is_empty()
                && origin.password().is_none()
                && origin.path() == "/"
                && origin.query().is_none()
                && origin.fragment().is_none(),
            "notification executor requires an exact installed HTTPS origin"
        );
        let client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|_| anyhow::anyhow!("notification executor TLS initialization failed"))?;
        Ok(Self {
            origin,
            auth,
            client,
        })
    }

    /// Exchanges one exact attempt for authenticated compact receipt facts.
    ///
    /// # Errors
    /// Returns an error for expired work, unavailable executor, redirects, unbounded
    /// or compressed responses, missing authentication or an unrelated receipt.
    pub async fn execute(
        &self,
        plan: &NotificationWorkPlanV1,
    ) -> Result<NotificationWorkReceiptV1> {
        let now = PhysicalClock.now()?;
        let (body, signature) = self.auth.sign_plan(plan, &now)?;
        let remaining = plan.deadline.elapsed_since(&now)?;
        let mut response = self
            .client
            .post(self.origin.join(NOTIFICATION_WORK_PATH)?)
            .timeout(Duration::from_secs(remaining.min(60)))
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .header("accept-encoding", "identity")
            .header("X-AOS-Assessment-Notification-Signature", signature)
            .body(body)
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("paired notification executor is unavailable"))?;
        ensure!(
            response.status() == reqwest::StatusCode::OK,
            "paired notification executor rejected work"
        );
        ensure!(
            response
                .content_length()
                .is_none_or(|length| length <= 262_144)
                && response
                    .headers()
                    .get("content-encoding")
                    .is_none_or(|value| value == "identity"),
            "notification receipt exceeds the compact identity envelope"
        );
        let signature = response
            .headers()
            .get("X-AOS-Assessment-Notification-Signature")
            .and_then(|value| value.to_str().ok())
            .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .context("notification receipt authentication is absent")?
            .to_owned();
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| anyhow::anyhow!("notification receipt transport failed"))?
        {
            ensure!(
                body.len().saturating_add(chunk.len()) <= 262_144,
                "notification receipt exceeds the compact envelope"
            );
            body.extend_from_slice(&chunk);
        }
        self.auth
            .verify_receipt(&body, &signature, plan, &PhysicalClock.now()?)
    }
}
