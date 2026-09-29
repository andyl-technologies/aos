//! Native paired semantic HEAD transport, without a lease-renewal role.
//!
//! The caller selects the original SQL stamp and independently reviewed profile
//! pins. The Worker acquires the read lease. Signed historical evidence stays
//! historical; the business caller still repeats live authorization after await.

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::storage_authority::external_object::observation::{
    semantic::{
        SemanticExternalObservationReply, SemanticExternalObservationRequest,
        SEMANTIC_OBSERVATION_PATH,
    },
    MAX_OBSERVATION_REPLY_BYTES,
};
use aos_hub_core::storage_work::{StorageWorkKey, STORAGE_WORK_SIGNATURE_HEADER};

use super::{read_bounded_response, RemoteStorageWorkClient};

/// Builds the pooled client for a single semantic invocation per HTTP request.
///
/// # Errors
/// Returns an error if the HTTP client cannot be configured.
pub(super) fn http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("building single-attempt semantic observation client")
}

impl RemoteStorageWorkClient {
    /// Sends one signed semantic HEAD plan without internal transport retry.
    ///
    /// The request names a required SQL-derived stamp and independently selected
    /// profile pins. Each new transport invocation uses a fresh operation/plan
    /// identity and original bounded deadline; an ambiguous prior attempt may
    /// retain its physical fence. This method receives no renewal credential,
    /// supplies no default lease, and never converts history into a current read.
    ///
    /// The original request remains borrowed for the caller's after-await actor,
    /// ACL, binding, placement, publication, receipt and lease checks. A returned
    /// interval grants neither mutable object-body access nor delivery signing.
    ///
    /// # Errors
    /// Returns an error for expired or invalid request, concurrency shutdown,
    /// Worker refusal, response bounds, MAC/context/stamp mismatch, or expiry
    /// after reply authentication.
    pub async fn observe_external_head(
        &self,
        request: &SemanticExternalObservationRequest,
    ) -> Result<SemanticExternalObservationReply> {
        self.observe_external_head_at_time(request, aos_hub_core::clock::now_unix_secs)
            .await
    }

    async fn observe_external_head_at_time(
        &self,
        request: &SemanticExternalObservationRequest,
        clock: impl Fn() -> i64,
    ) -> Result<SemanticExternalObservationReply> {
        let _permit = self
            .in_flight
            .acquire()
            .await
            .context("storage Worker concurrency gate closed")?;
        let (body, mac) = request.sign(&self.key, &self.deployment_id, clock())?;
        let mut endpoint = url::Url::parse(&self.endpoint)?;
        endpoint.set_path(SEMANTIC_OBSERVATION_PATH);
        let response = self
            .semantic_observation_http
            .post(endpoint)
            .header(STORAGE_WORK_SIGNATURE_HEADER, mac)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.clone())
            .send()
            .await
            .context("requesting paired external HEAD observation")?;
        ensure!(
            response.status() == reqwest::StatusCode::OK,
            "storage Worker refused semantic observation"
        );
        let reply_mac = response
            .headers()
            .get(STORAGE_WORK_SIGNATURE_HEADER)
            .context("semantic observation signature absent")?
            .to_str()
            .context("semantic observation signature malformed")?
            .to_owned();
        let reply_bytes = read_bounded_response(response, MAX_OBSERVATION_REPLY_BYTES).await?;
        let reply = authenticate_reply(&self.key, &reply_mac, &reply_bytes, &body)?;
        request.validate(&self.deployment_id, clock())?;
        // Observe again after validation CPU. This is only the original local
        // application cutoff, not the caller's live ACL/publication decision.
        check_application_time(request, clock())?;
        Ok(reply)
    }
}

fn authenticate_reply(
    key: &StorageWorkKey,
    mac: &str,
    reply: &[u8],
    request: &[u8],
) -> Result<SemanticExternalObservationReply> {
    SemanticExternalObservationReply::authenticate(key, mac, reply, request)
        .map_err(|_| anyhow::anyhow!("semantic observation reply authentication failed"))
}

fn check_application_time(request: &SemanticExternalObservationRequest, now: i64) -> Result<()> {
    ensure!(
        request.plan.issued_at <= now.saturating_add(5) && now <= request.plan.expires_at,
        "semantic observation application permission expired"
    );
    Ok(())
}

#[cfg(test)]
mod tests;
