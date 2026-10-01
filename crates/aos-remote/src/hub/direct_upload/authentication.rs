//! Original-origin provisioning exchange with genuine bounded grant custody.
//!
//! Each provider caches only its own successful OAuth grant, using the positive
//! returned lifetime measured conservatively from request start. This cache
//! supplies credentials; the consuming upload protocol must still prove actor,
//! deployment, owner, provider policy and transfer-mode continuity.

use std::fmt;
use std::time::Duration;

use aos_net::direct_upload::DirectClientError;
use tokio_stream::StreamExt as _;

use super::{super::HubClient, DirectHubAuthentication};

const MAX_GRANT_BYTES: usize = 64 * 1024;

/// Caches genuine short-lived credentials from one original provisioning secret.
///
/// No shared active-account store, locally decoded JWT or guessed lifetime is
/// consulted. The secret and grant have redacted Debug and no serialization.
/// Unexpected early rejection fails closed; this type does not switch actors.
pub struct DirectProvisioningAuthentication {
    origin: String,
    secret: String,
    http: reqwest::Client,
    cached: tokio::sync::Mutex<Option<CachedGrant>>,
}

struct CachedGrant {
    hub: HubClient,
    expires: tokio::time::Instant,
}

impl fmt::Debug for DirectProvisioningAuthentication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DirectProvisioningAuthentication([private])")
    }
}

impl DirectProvisioningAuthentication {
    /// Pins a bare HTTP(S) Hub origin and its caller-owned provisioning secret.
    ///
    /// HTTP is retained for explicit local/on-prem Hub deployments. Redirects
    /// and ambient proxy routing are disabled for this credential exchange.
    ///
    /// # Errors
    /// Refuses malformed/nonbare origins, missing/excessive secret material or
    /// failure to construct the bounded credential client.
    pub fn new(origin: &str, secret: String) -> Result<Self, DirectClientError> {
        let origin = canonical_origin(origin)?;
        if secret.is_empty() || secret.len() > 8192 {
            return Err(DirectClientError::Invalid);
        }
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|_| DirectClientError::Invalid)?;
        Ok(Self {
            origin,
            secret,
            http,
            cached: tokio::sync::Mutex::new(None),
        })
    }
}

#[async_trait::async_trait]
impl DirectHubAuthentication for DirectProvisioningAuthentication {
    async fn authenticate(&self, canonical_hub: &str) -> Result<HubClient, DirectClientError> {
        if canonical_origin(canonical_hub)? != self.origin {
            return Err(DirectClientError::Invalid);
        }
        let mut cached = self.cached.lock().await;
        if let Some(grant) = cached.as_ref() {
            if tokio::time::Instant::now() < grant.expires {
                return Ok(grant.hub.clone());
            }
        }
        // Request duration consumes the returned lifetime. Measuring from
        // response receipt could extend a grant after a slow exchange.
        let started = tokio::time::Instant::now();
        let response = self
            .http
            .post(format!("{}/oauth2/token", self.origin))
            .bearer_auth(&self.secret)
            .form(&[(
                "grant_type",
                "urn:aos:params:oauth:grant-type:provisioning-token",
            )])
            .send()
            .await
            .map_err(|_| DirectClientError::ControlUnavailable)?;
        if !response.status().is_success() {
            return Err(if response.status().is_server_error() {
                DirectClientError::ControlUnavailable
            } else {
                DirectClientError::Denied
            });
        }
        if response
            .content_length()
            .is_some_and(|size| size > MAX_GRANT_BYTES as u64)
        {
            return Err(DirectClientError::Invalid);
        }
        let mut bytes = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| DirectClientError::ControlUnavailable)?;
            if bytes
                .len()
                .checked_add(chunk.len())
                .is_none_or(|size| size > MAX_GRANT_BYTES)
            {
                return Err(DirectClientError::Invalid);
            }
            bytes.extend_from_slice(&chunk);
        }
        let grant: crate::TokenGrant =
            serde_json::from_slice(&bytes).map_err(|_| DirectClientError::Invalid)?;
        let seconds = u64::try_from(grant.expires_in).map_err(|_| DirectClientError::Invalid)?;
        if seconds == 0
            || !grant.token_type.eq_ignore_ascii_case("Bearer")
            || grant.access_token.is_empty()
        {
            return Err(DirectClientError::Invalid);
        }
        let lifetime = Duration::from_secs(seconds);
        let skew = (lifetime / 10).min(Duration::from_secs(5));
        let expires = started
            .checked_add(lifetime - skew)
            .ok_or(DirectClientError::Invalid)?;
        if tokio::time::Instant::now() >= expires {
            return Err(DirectClientError::Denied);
        }
        let hub = HubClient::connect_with_token(&self.origin, &grant.access_token)
            .map_err(|_| DirectClientError::Invalid)?;
        *cached = Some(CachedGrant {
            hub: hub.clone(),
            expires,
        });
        Ok(hub)
    }
}

fn canonical_origin(value: &str) -> Result<String, DirectClientError> {
    let url = url::Url::parse(value).map_err(|_| DirectClientError::Invalid)?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(DirectClientError::Invalid);
    }
    Ok(url.origin().ascii_serialization())
}

#[cfg(test)]
mod tests;
