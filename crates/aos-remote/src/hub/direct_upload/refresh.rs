//! Renews ephemeral authentication without changing admitted operation authority.
//!
//! Only the original application authentication provider may supply a new Hub
//! client. Discovery may change its exclusive lifetime; every other actor,
//! owner, placement, profile and protocol limit remains exactly pinned.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aos_net::direct_upload::{DirectClientError, DirectUploadControl};
use aos_proto_types::direct_upload::*;
use async_trait::async_trait;

use super::{super::HubClient, DirectHubControl};

/// Original credential authority for renewal on the already pinned Hub origin.
#[async_trait]
pub trait DirectHubAuthentication: Send + Sync + fmt::Debug {
    /// Resolves current credentials for the exact original canonical Hub.
    ///
    /// # Errors
    /// Returns a value-free failure if the original credential provider cannot
    /// renew access. Implementations must not consult a different active origin.
    async fn authenticate(&self, canonical_hub: &str) -> Result<HubClient, DirectClientError>;
}

struct State {
    control: DirectHubControl,
    capabilities: DirectUploadCapabilities,
    checked: tokio::time::Instant,
    epoch: u64,
}

pub(super) struct RefreshingControl {
    base: String,
    pinned: DirectUploadCapabilities,
    initial_hub: HubClient,
    authentication: Option<Arc<dyn DirectHubAuthentication>>,
    state: tokio::sync::Mutex<State>,
    metrics: Arc<aos_net::direct_upload::DirectTransferMetrics>,
}

impl RefreshingControl {
    pub(super) fn new(
        hub: &HubClient,
        caps: DirectUploadCapabilities,
        authentication: Option<Arc<dyn DirectHubAuthentication>>,
        metrics: Arc<aos_net::direct_upload::DirectTransferMetrics>,
    ) -> Result<Self, DirectClientError> {
        Ok(Self {
            base: hub.base.clone(),
            pinned: caps.clone(),
            initial_hub: hub.clone(),
            authentication,
            metrics: metrics.clone(),
            state: tokio::sync::Mutex::new(State {
                control: DirectHubControl::new(hub)?
                    .with_metrics(metrics)
                    .with_control_limit(caps.maximum_control_bytes as usize)?,
                capabilities: caps,
                checked: tokio::time::Instant::now(),
                epoch: 0,
            }),
        })
    }

    pub(super) async fn snapshot(&self) -> Result<DirectUploadCapabilities, DirectClientError> {
        Ok(self.current(None).await?.1)
    }

    async fn current(
        &self,
        denied_epoch: Option<u64>,
    ) -> Result<(DirectHubControl, DirectUploadCapabilities, u64), DirectClientError> {
        let mut state = self.state.lock().await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| DirectClientError::Invalid)?
            .as_secs();
        if denied_epoch == Some(state.epoch)
            || state.checked.elapsed() >= Duration::from_secs(60)
            || state.capabilities.valid_until.get().saturating_sub(now) <= 30
        {
            let hub = match &self.authentication {
                Some(provider) => provider.authenticate(&self.base).await?,
                None => self.initial_hub.clone(),
            };
            if hub.base != self.base {
                return Err(DirectClientError::Invalid);
            }
            let control = DirectHubControl::new(&hub)?
                .with_metrics(self.metrics.clone())
                .with_control_limit(self.pinned.maximum_control_bytes as usize)?;
            let request = super::coordinator::discovery_target(&self.pinned);
            let renewed = control.capabilities(&request).await?;
            let latest_now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| DirectClientError::Invalid)?
                .as_secs();
            renewed
                .validate_at_for(&request, latest_now)
                .map_err(|_| DirectClientError::Invalid)?;
            validate_renewal(&self.pinned, &renewed)?;
            let epoch = state
                .epoch
                .checked_add(1)
                .ok_or(DirectClientError::Invalid)?;
            state.control = control;
            state.epoch = epoch;
            state.capabilities = renewed;
            state.checked = tokio::time::Instant::now();
        }
        Ok((
            state.control.clone(),
            state.capabilities.clone(),
            state.epoch,
        ))
    }
}

#[async_trait]
impl DirectUploadControl for RefreshingControl {
    async fn execute(
        &self,
        request: &DirectUploadRequest,
    ) -> Result<DirectUploadResponse, DirectClientError> {
        let (control, _, epoch) = self.current(None).await?;
        match control.execute(request).await {
            Err(DirectClientError::Denied) => {
                // Authentication retries preserve every byte of the original
                // control request, including operation identity and original RV.
                let (renewed, _, _) = self.current(Some(epoch)).await?;
                renewed.execute(request).await
            }
            result => result,
        }
    }
}

fn validate_renewal(
    original: &DirectUploadCapabilities,
    renewed: &DirectUploadCapabilities,
) -> Result<(), DirectClientError> {
    let mut expected = original.clone();
    expected.valid_until = renewed.valid_until;
    if &expected != renewed {
        return Err(DirectClientError::Invalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
