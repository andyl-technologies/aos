//! Outbound webhook delivery: the native HTTP worker that drains the queue.
//!
//! The event taxonomy ([`WebhookEvent`]), the HMAC-SHA256 body [`sign_body`],
//! the db-enqueue [`dispatch`], and the [`backoff_secs`] retry schedule moved to
//! [`aos_hub_core::webhook`] (RFC-0004 Phase 5) so the Cloudflare Worker
//! shares them; they are re-exported here so the hub's `webhook::…` paths are
//! stable. What stays native is the delivery side: [`deliver_one`] `POST`s a
//! queued delivery with a hardened reqwest client (re-validating the URL through
//! the SSRF guard first), and [`run_delivery_worker`] sweeps the due queue on a
//! tokio interval.
//!
//! # Delivery wire format
//!
//! Every delivery is a single `POST` of the event's JSON payload as the raw
//! request body, with three hub-specific headers:
//!
//! ```text
//! POST <webhook.url>
//! Content-Type:    application/json
//! X-AOS-Event:     <event_type>
//! X-AOS-Signature: sha256=<hex>
//! X-AOS-Delivery-ID: <stable_delivery_id>
//!
//! <payload JSON bytes>
//! ```
//!
//! A `2xx` response marks the delivery `delivered`; any other status (or a
//! transport error) increments the attempt count and schedules a retry, up to
//! [`MAX_ATTEMPTS`], after which the delivery is `failed`.
//!
//! The Cloudflare Worker drains the same durable rows from both Queue delivery
//! jobs and its Cron backstop, forwarding the closed signed-header set through
//! the authenticated hardened-egress gateway.

use std::sync::Arc;
use std::time::Duration;

use crate::db::{Database, DueDelivery};
use aos_hub_core::secret_version::{verify_secret_fingerprint, SecretVersionResolver};

pub use aos_hub_core::webhook::{
    backoff_secs, dispatch, sign_body, sign_body_bytes, WebhookEvent, MAX_ATTEMPTS,
};

/// Per-request timeout for a delivery `POST`.
const DELIVERY_TIMEOUT_SECS: u64 = 15;

/// Interval, in seconds, between delivery-worker sweeps of the due queue.
const WORKER_INTERVAL_SECS: u64 = 5;

/// Attempt to deliver one queued delivery, recording the outcome.
///
/// `POST`s the delivery's payload to its webhook URL with the `X-AOS-Event`
/// and `X-AOS-Signature` headers, then updates the row:
///
/// - a `2xx` response marks it `delivered`;
/// - any other status, or a transport error, increments `attempts` and either
///   schedules the next retry (`pending`, `next_attempt_at = now +
///   backoff_secs`) or, once [`MAX_ATTEMPTS`] is reached, marks it `failed`.
///
/// Before the `POST`, the delivery URL is re-validated against the SSRF guard
/// ([`crate::fetch::is_safe_remote_url`]) as defense in depth: a row written
/// before this guard existed, or one whose host now resolves internally, is
/// marked `failed` immediately (not retried — the target is structurally
/// rejected, so retries would never succeed) and never `POST`ed.
///
/// Returns `true` when the delivery succeeded.
///
/// # Errors
///
/// Returns an error only when recording the outcome to the database fails; a
/// failed `POST` or an SSRF-guard rejection is a normal (recorded) outcome, not
/// an error.
pub async fn deliver_one(
    http: &reqwest::Client,
    db: &Database,
    secrets: &dyn SecretVersionResolver,
    delivery: &DueDelivery,
) -> anyhow::Result<bool> {
    // Defense in depth against TOCTOU / pre-guard rows: never POST to a target
    // the SSRF guard rejects. Mark it failed rather than retried — the rejection
    // is structural, so no future attempt would pass.
    if crate::fetch::is_safe_remote_url(&delivery.url).is_err() {
        tracing::warn!(
            webhook_id = delivery.webhook_id,
            "rejecting webhook delivery: url fails SSRF guard"
        );
        db.mark_delivery(
            delivery.id,
            &delivery.claim_token,
            "failed",
            None,
            delivery.attempts + 1,
            None,
        )
        .await?;
        return Ok(false);
    }
    let secret = match secrets.resolve(&delivery.secret_version_ref).await {
        Ok(secret) => secret,
        Err(_) => {
            tracing::error!(
                webhook_id = delivery.webhook_id,
                "webhook signing credential could not be resolved"
            );
            schedule_retry(db, delivery, None, delivery.attempts + 1).await?;
            return Ok(false);
        }
    };
    if verify_secret_fingerprint(&secret, &delivery.credential_fingerprint).is_err() {
        tracing::error!(
            webhook_id = delivery.webhook_id,
            "webhook signing credential fingerprint mismatch"
        );
        drop(secret);
        db.mark_delivery(
            delivery.id,
            &delivery.claim_token,
            "failed",
            None,
            delivery.attempts + 1,
            None,
        )
        .await?;
        return Ok(false);
    }
    let signature = sign_body_bytes(secret.expose_bytes(), delivery.payload.as_bytes());
    drop(secret);
    let response = http
        .post(&delivery.url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("X-AOS-Event", &delivery.event)
        .header("X-AOS-Signature", signature)
        .header("X-AOS-Delivery-ID", &delivery.delivery_id)
        .timeout(Duration::from_secs(DELIVERY_TIMEOUT_SECS))
        .body(delivery.payload.clone())
        .send()
        .await;

    let attempts = delivery.attempts + 1;
    match response {
        Ok(resp) if resp.status().is_success() => {
            let code = resp.status().as_u16() as i64;
            db.mark_delivery(
                delivery.id,
                &delivery.claim_token,
                "delivered",
                Some(code),
                attempts,
                None,
            )
            .await?;
            Ok(true)
        }
        Ok(resp) => {
            let code = resp.status().as_u16() as i64;
            schedule_retry(db, delivery, Some(code), attempts).await?;
            Ok(false)
        }
        Err(err) => {
            tracing::warn!(
                webhook_id = delivery.webhook_id,
                error = %err,
                "webhook delivery POST failed"
            );
            schedule_retry(db, delivery, None, attempts).await?;
            Ok(false)
        }
    }
}

/// Record a failed attempt: schedule a backed-off retry, or mark `failed` once
/// the attempt cap is reached.
async fn schedule_retry(
    db: &Database,
    delivery: &DueDelivery,
    response_code: Option<i64>,
    attempts: i64,
) -> anyhow::Result<()> {
    if attempts >= MAX_ATTEMPTS {
        db.mark_delivery(
            delivery.id,
            &delivery.claim_token,
            "failed",
            response_code,
            attempts,
            None,
        )
        .await?;
    } else {
        let next = now() + backoff_secs(attempts);
        db.mark_delivery(
            delivery.id,
            &delivery.claim_token,
            "pending",
            response_code,
            attempts,
            Some(next),
        )
        .await?;
    }
    Ok(())
}

/// Run the webhook delivery worker until the process exits.
///
/// Every [`WORKER_INTERVAL_SECS`] seconds it sweeps the queue for due
/// deliveries ([`Database::claim_due_deliveries`]) and attempts each in order. A
/// single failing endpoint cannot stall the others: each delivery's outcome is
/// recorded independently, and a recording error is logged rather than
/// aborting the loop. Spawn this once from the server's `serve` entry point.
///
pub async fn run_delivery_worker(
    db: Arc<Database>,
    http: reqwest::Client,
    secrets: Arc<dyn SecretVersionResolver>,
) {
    let mut tick = tokio::time::interval(Duration::from_secs(WORKER_INTERVAL_SECS));
    loop {
        tick.tick().await;
        let due = match db.claim_due_deliveries(now(), 100, 30).await {
            Ok(due) => due,
            Err(err) => {
                tracing::warn!(error = %format!("{err:#}"), "listing due webhook deliveries");
                continue;
            }
        };
        for delivery in &due {
            if let Err(err) = deliver_one(&http, &db, secrets.as_ref(), delivery).await {
                tracing::warn!(
                    delivery_id = delivery.id,
                    error = %format!("{err:#}"),
                    "recording webhook delivery outcome"
                );
            }
        }
    }
}

/// Current Unix time in seconds.
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
