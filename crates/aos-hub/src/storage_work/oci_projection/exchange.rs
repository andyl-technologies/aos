//! Original-deadline HTTP accounting for independent OCI metadata exchanges.

use anyhow::{Context as _, Result};
use aos_hub_core::{
    oci_projection::{guard::*, MAX_OCI_PROJECTION_BYTES},
    storage_work::StorageWorkKey,
};
use std::time::Duration;

use crate::storage_work::{
    read_observed_response, telemetry::ExchangeTelemetry, RemoteStorageWorkClient,
};

impl RemoteStorageWorkClient {
    pub(in crate::storage_work) async fn exchange_oci_projection(
        &self,
        origin: &str,
        key: &StorageWorkKey,
        lookup: &OciProjectionLookup,
    ) -> Result<VerifiedOciProjection> {
        let mut exchange = ExchangeTelemetry::control(&lookup.nonce, "OciDocumentProjection");
        let result = self
            .oci_projection_http(origin, key, lookup, &mut exchange)
            .await;
        if result.is_ok() {
            exchange.finish("success");
        }
        result
    }

    async fn oci_projection_http(
        &self,
        origin: &str,
        key: &StorageWorkKey,
        lookup: &OciProjectionLookup,
        exchange: &mut ExchangeTelemetry<'_>,
    ) -> Result<VerifiedOciProjection> {
        let latest_now = u64::try_from(aos_hub_core::clock::now_unix_secs())?
            .checked_add(lookup.clock_uncertainty_seconds)
            .context("OCI guard clock overflow")?;
        lookup
            .validate(&self.deployment_id, latest_now)
            .inspect_err(|_| exchange.finish("invalid_plan"))?;
        let remaining = lookup
            .expires_at
            .checked_sub(latest_now)
            .filter(|seconds| *seconds > 0)
            .context("OCI projection deadline expired")?;
        // One monotonic deadline covers headers and every streamed response
        // chunk. Neither partial progress nor transport retries renew it.
        let timeout = Duration::from_secs(remaining);
        let signed = sign_oci_projection_lookup(key, lookup)?;
        let request = self
            .http
            .post(format!("{origin}{OCI_PROJECTION_PATH}"))
            .header("content-type", "application/json")
            .header(OCI_PROJECTION_SIGNATURE_HEADER, signed.signature)
            .body(signed.body.clone())
            .timeout(timeout);
        exchange.offer_plan(signed.body.len());
        let operation = async {
            let response = request
                .send()
                .await
                .context("reading exact OCI document projection")
                .inspect_err(|_| exchange.finish("transport_failed"))?;
            if !response.status().is_success() {
                exchange.discard_status_response();
                exchange.finish("http_rejected");
                anyhow::bail!("OCI physical readback is unavailable or unsettled");
            }
            let signature = response
                .headers()
                .get(OCI_PROJECTION_SIGNATURE_HEADER)
                .context("OCI projection signature absent")
                .inspect_err(|_| exchange.finish("invalid_result"))?
                .to_str()
                .context("OCI projection signature invalid")
                .inspect_err(|_| exchange.finish("invalid_result"))?
                .to_owned();
            let bytes = read_observed_response(response, MAX_OCI_PROJECTION_BYTES, |length| {
                exchange.observe_body(length);
                tracing::trace!(
                    chunk_bytes = length,
                    "OCI projection response chunk observed"
                );
            })
            .await
            .inspect_err(|_| exchange.finish("response_read_failed"))?;
            let latest_now = u64::try_from(aos_hub_core::clock::now_unix_secs())?
                .checked_add(lookup.clock_uncertainty_seconds)
                .context("OCI guard clock overflow")?;
            verify_oci_projection_reply(key, &signature, &bytes, lookup, latest_now)
                .inspect_err(|_| exchange.finish("invalid_result"))
        };
        match tokio::time::timeout(timeout, operation).await {
            Ok(result) => result,
            Err(_) => {
                exchange.finish("deadline");
                anyhow::bail!("OCI projection response exceeded its original deadline")
            }
        }
    }
}

#[cfg(test)]
mod tests;
