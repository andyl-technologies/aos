//! Native bounded callback effects with versioned keys and pinned public DNS.
//!
//! The host rechecks its current journal/review through [`NotificationCredentials`]
//! immediately before signing and posting. This adapter never resolves a source
//! provider key, follows a redirect, or exposes response bodies to the coordinator.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, ensure};
use aos_assessment_runtime::notifications::{
    CallbackSignature, NotificationDestinationV1, NotificationTransport, NotificationWorkPlanV1,
};
use aos_assessment_runtime::ports::Clock;
use zeroize::Zeroizing;

use crate::PhysicalClock;

mod remote;
pub use remote::RemoteNotificationExecutor;

#[cfg(test)]
mod tests;

/// Resolves independently installed callback keys and current journal authority.
#[async_trait::async_trait]
pub trait NotificationCredentials: Send + Sync {
    /// Rechecks the exact current outbox claim, review and installed destination.
    ///
    /// # Errors
    /// Returns an error for revoked review/credential, stale lease or changed destination scope.
    async fn authorize(
        &self,
        destination: &NotificationDestinationV1,
        plan: &NotificationWorkPlanV1,
    ) -> Result<()>;

    /// Resolves the exact immutable destination key into a drop-zeroed allocation.
    ///
    /// # Errors
    /// Returns an error for unknown, revoked or unavailable key versions.
    async fn resolve(&self, destination: &NotificationDestinationV1) -> Result<Zeroizing<Vec<u8>>>;
}

/// Posts only reviewed callbacks with public DNS pinning and bounded physical time.
pub struct NativeNotificationTransport {
    credentials: Arc<dyn NotificationCredentials>,
    http: reqwest::Client,
}

impl NativeNotificationTransport {
    /// Creates a hardened independent callback adapter without ambient proxy credentials.
    ///
    /// # Errors
    /// Returns an error if the installed TLS client cannot be initialized.
    pub fn new(credentials: Arc<dyn NotificationCredentials>) -> Result<Self> {
        let http = crate::source_client_builder(5)
            .dns_resolver(Arc::new(crate::dns::PublicNotificationResolver))
            .timeout(Duration::from_secs(15))
            .user_agent("aos-assessment-notifications/v1")
            .build()
            .map_err(|_| anyhow::anyhow!("notification TLS client could not be initialized"))?;
        Ok(Self { credentials, http })
    }
}

#[async_trait::async_trait]
impl NotificationTransport for NativeNotificationTransport {
    async fn sign_callback(
        &self,
        destination: &NotificationDestinationV1,
        plan: &NotificationWorkPlanV1,
        body: &[u8],
    ) -> Result<CallbackSignature> {
        plan.validate_at(&PhysicalClock.now()?)?;
        plan.require_destination(destination)?;
        self.credentials.authorize(destination, plan).await?;
        let key = self.credentials.resolve(destination).await?;
        self.credentials.authorize(destination, plan).await?;
        plan.validate_at(&PhysicalClock.now()?)?;
        CallbackSignature::sign(destination, plan, body, &key)
    }

    async fn post(
        &self,
        destination: &NotificationDestinationV1,
        plan: &NotificationWorkPlanV1,
        body: &[u8],
        signature: &CallbackSignature,
    ) -> Result<(Option<u16>, Option<u32>)> {
        plan.validate_at(&PhysicalClock.now()?)?;
        plan.require_destination(destination)?;
        ensure!(
            body == plan.body.to_bytes()?
                && signature.timestamp == plan.issued_at
                && signature.key_version == destination.secret_version_reference
                && signature.version == "aos.notification-signature/hmac-sha256-v1",
            "notification callback bytes or signed metadata changed"
        );
        self.credentials.authorize(destination, plan).await?;
        let now = PhysicalClock.now()?;
        plan.validate_at(&now)?;
        ensure!(
            now.unix_seconds().saturating_add(15) <= plan.deadline.unix_seconds(),
            "notification authority does not cover the full physical timeout"
        );
        let response = self
            .http
            .post(&destination.url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header("X-AOS-Event", "assessment.notification")
            .header("X-AOS-Delivery-ID", &plan.body.delivery_id)
            .header("X-AOS-Signature-Version", &signature.version)
            .header("X-AOS-Signing-Key-Version", &signature.key_version)
            .header("X-AOS-Timestamp", signature.timestamp.as_str())
            .header("X-AOS-Signature", format!("sha256={}", signature.signature))
            .body(body.to_vec())
            .send()
            .await;
        match response {
            Ok(response) => {
                let status = response.status().as_u16();
                let delay = response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<u32>().ok())
                    .map(|seconds| seconds.min(3600));
                // Dropping the response avoids reading or retaining arbitrary
                // destination bytes. Acceptance is solely the actual HTTP status.
                Ok((Some(status), delay))
            }
            Err(_) => Ok((None, None)),
        }
    }
}
