//! Authenticated Native-to-Worker provider work with bounded compact responses.
//!
//! The installed HTTPS origin and independent provider-work key belong to
//! deployment policy. This client sends plans and normalized receipts only;
//! raw provider evidence stays in executor custody and never traverses Native.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use aos_assessment_runtime::ports::{Clock, ProviderTransport};
use aos_assessment_runtime::provider::{
    CapabilityChallenge, PROVIDER_CAPABILITIES_PATH, PROVIDER_SIGNATURE_HEADER, PROVIDER_WORK_PATH,
    ProviderCapabilitiesV1, ProviderWorkAuth, ProviderWorkPlanV1, ProviderWorkResultV1,
};

use crate::PhysicalClock;

#[cfg(test)]
mod tests;

/// Sends separately authenticated provider work to one installed HTTPS executor.
pub struct RemoteProviderTransport {
    origin: reqwest::Url,
    auth: Arc<ProviderWorkAuth>,
    client: reqwest::Client,
}

impl RemoteProviderTransport {
    /// Creates an explicit paired executor client without ambient proxy or redirects.
    ///
    /// The origin contains no path, credentials, query or fragment. Provider
    /// requests cannot select it or cause fallback to direct Native acquisition.
    ///
    /// # Errors
    /// Returns an error for an invalid HTTPS origin or unavailable TLS initialization.
    pub fn new(origin: &str, auth: Arc<ProviderWorkAuth>) -> Result<Self> {
        let origin = reqwest::Url::parse(origin)?;
        if origin.scheme() != "https"
            || origin.host_str().is_none()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.path() != "/"
            || origin.query().is_some()
            || origin.fragment().is_some()
        {
            bail!("provider executor requires an exact installed HTTPS origin");
        }
        let client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|_| anyhow::anyhow!("provider executor TLS initialization failed"))?;
        Ok(Self {
            origin,
            auth,
            client,
        })
    }

    async fn exchange(
        &self,
        route: &str,
        body: Vec<u8>,
        signature: &str,
        remaining_seconds: u64,
    ) -> Result<(Vec<u8>, String)> {
        if ![PROVIDER_CAPABILITIES_PATH, PROVIDER_WORK_PATH].contains(&route)
            || body.len() > 256 * 1024
            || remaining_seconds == 0
        {
            bail!("provider exchange exceeds its installed route or deadline");
        }
        let mut response = self
            .client
            .post(self.origin.join(route)?)
            .timeout(Duration::from_secs(remaining_seconds.min(60)))
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .header("accept-encoding", "identity")
            .header(PROVIDER_SIGNATURE_HEADER, signature)
            .body(body)
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("paired provider executor is unavailable"))?;
        if response.status() != reqwest::StatusCode::OK {
            bail!("paired provider executor rejected work");
        }
        if response
            .content_length()
            .is_some_and(|length| length > 256 * 1024)
            || response
                .headers()
                .get("content-encoding")
                .is_some_and(|value| value != "identity")
        {
            bail!("provider executor response exceeds the compact identity envelope");
        }
        let signature = response
            .headers()
            .get(PROVIDER_SIGNATURE_HEADER)
            .and_then(|value| value.to_str().ok())
            .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .context("provider executor response authentication is missing")?
            .to_owned();
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| anyhow::anyhow!("provider executor response stream failed"))?
        {
            let size = body
                .len()
                .checked_add(chunk.len())
                .filter(|size| *size <= 256 * 1024)
                .context("provider executor response exceeds the compact limit")?;
            body.try_reserve(size - body.len())
                .map_err(|_| anyhow::anyhow!("provider executor response allocation failed"))?;
            body.extend_from_slice(&chunk);
        }
        Ok((body, signature))
    }
}

#[async_trait::async_trait]
impl ProviderTransport for RemoteProviderTransport {
    async fn capabilities(
        &self,
        challenge: &CapabilityChallenge,
    ) -> Result<ProviderCapabilitiesV1> {
        let now = PhysicalClock.now()?;
        let (body, signature) = self.auth.sign_challenge(challenge, &now)?;
        let remaining = challenge
            .expires_at
            .unix_seconds()
            .checked_sub(now.unix_seconds())
            .context("provider capability challenge expired")?;
        let (body, signature) = self
            .exchange(PROVIDER_CAPABILITIES_PATH, body, &signature, remaining)
            .await?;
        self.auth
            .verify_capabilities(&body, &signature, challenge, &PhysicalClock.now()?)
    }

    async fn execute(&self, plan: &ProviderWorkPlanV1) -> Result<ProviderWorkResultV1> {
        let now = PhysicalClock.now()?;
        let (body, signature) = self.auth.sign_plan(plan, &now)?;
        let remaining = plan
            .expires_at
            .unix_seconds()
            .checked_sub(now.unix_seconds())
            .context("provider work expired before executor dispatch")?;
        let (body, signature) = self
            .exchange(PROVIDER_WORK_PATH, body, &signature, remaining)
            .await?;
        self.auth
            .verify_result(&body, &signature, plan, &PhysicalClock.now()?)
    }
}
