//! Outbound webhooks: registry events fanned out to subscriber endpoints.
//!
//! RFC-0004's phase-4 "webhooks/notifications". When a registry's state
//! changes through a hub-mediated path — an index completes, a channel
//! advances, a registry's visibility flips, a release is published — the hub
//! raises a [`WebhookEvent`]. [`dispatch`] finds the owning org's *active*
//! webhooks subscribed to that event type and enqueues one durable delivery
//! per hook ([`crate::db::Database::enqueue_delivery`]). A background
//! [`run_delivery_worker`] drains the queue, `POST`ing each payload with an
//! HMAC-SHA256 signature and retrying with exponential backoff.
//!
//! Raising an event is **additive and non-fatal**: a webhook failure (no
//! subscribers, a database hiccup, a dead endpoint) never breaks the operation
//! that raised it. The event sources call [`dispatch`] and log, never `?`, on
//! error.
//!
//! # Event taxonomy
//!
//! Each event carries an `event_type()` string (the value subscribers match on
//! and the hub sends in the `X-AOS-Event` header) and a `payload()` JSON
//! object describing what changed:
//!
//! | `event_type()` | Raised when | Payload keys |
//! | --- | --- | --- |
//! | `index.completed` | a registry finishes (re)indexing | `registry`, `commit`, `packages`, `releases`, `channels`, `incremental`, `at` |
//! | `channel.advanced` | a channel's partitions move to a release | `registry`, `channel`, `release`, `moved`, `at_target`, `rollout_percent`, `at` |
//! | `registry.visibility_changed` | a registry's visibility flips | `registry`, `old`, `new`, `at` |
//! | `release.published` | a new release tag is indexed | `registry`, `semver`, `commit`, `at` |
//!
//! # Delivery wire format and signature scheme
//!
//! Every delivery is a single `POST` of the event's JSON payload as the raw
//! request body, with two hub-specific headers:
//!
//! ```text
//! POST <webhook.url>
//! Content-Type:    application/json
//! X-AOS-Event:     <event_type>
//! X-AOS-Signature: sha256=<hex>
//!
//! <payload JSON bytes>
//! ```
//!
//! `<hex>` is the lowercase-hex HMAC-SHA256 of the **exact raw body bytes**
//! computed under the webhook's shared `secret`. A subscriber verifies a
//! delivery by recomputing the same MAC over the bytes it received and
//! comparing in constant time — the GitHub-style scheme. A `2xx` response
//! marks the delivery `delivered`; any other status (or a transport error)
//! increments the attempt count and schedules a retry, up to [`MAX_ATTEMPTS`],
//! after which the delivery is `failed`.

use std::sync::Arc;
use std::time::Duration;

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::db::{Database, DueDelivery};

/// Maximum number of delivery attempts before a delivery is marked `failed`.
///
/// Backoff is exponential (see [`backoff_secs`]); six attempts spans roughly
/// 10s + 20s + 40s + 80s + 160s ≈ 5 minutes of retries before giving up.
pub const MAX_ATTEMPTS: i64 = 6;

/// Base delay, in seconds, for the first retry; doubled each subsequent
/// attempt by [`backoff_secs`].
const BASE_BACKOFF_SECS: i64 = 10;

/// Cap, in seconds, on a single backoff interval (1 hour), so a long-failing
/// delivery does not schedule retries arbitrarily far out.
const MAX_BACKOFF_SECS: i64 = 3600;

/// Per-request timeout for a delivery `POST`.
const DELIVERY_TIMEOUT_SECS: u64 = 15;

/// Interval, in seconds, between delivery-worker sweeps of the due queue.
const WORKER_INTERVAL_SECS: u64 = 5;

/// HMAC-SHA256 keyed by a webhook's shared secret.
type HmacSha256 = Hmac<Sha256>;

/// A registry event that may fan out to an org's subscribed webhooks.
///
/// Each variant maps to a stable [`Self::event_type`] string subscribers match
/// on and a [`Self::payload`] JSON object describing the change. New variants
/// are additive: an unknown type is simply not matched by older subscriptions.
#[derive(Debug, Clone)]
pub enum WebhookEvent {
    /// A registry finished (re)indexing its verified surface.
    IndexCompleted {
        /// The registry's canonical slug.
        registry: String,
        /// The commit the index was built from.
        commit: String,
        /// Number of packages in the new index.
        packages: usize,
        /// Number of verified releases.
        releases: usize,
        /// Number of channels resolved.
        channels: usize,
        /// Whether the run took the incremental fast path.
        incremental: bool,
        /// Unix time the index completed.
        at: i64,
    },
    /// A channel's partitions advanced to a release.
    ChannelAdvanced {
        /// The registry's canonical slug.
        registry: String,
        /// The advanced channel.
        channel: String,
        /// The release the partitions now point at.
        release: String,
        /// How many partitions this advance newly moved.
        moved: usize,
        /// How many of the 256 partitions point at the release after the advance.
        at_target: usize,
        /// The rollout percentage (`at_target` / 256), whole number.
        rollout_percent: u32,
        /// Unix time the advance completed.
        at: i64,
    },
    /// A registry's visibility changed.
    VisibilityChanged {
        /// The registry's canonical slug.
        registry: String,
        /// The previous visibility (`public`, `internal`, or `private`).
        old: String,
        /// The new visibility.
        new: String,
        /// Unix time the change applied.
        at: i64,
    },
    /// A new release tag was published (observed in the index).
    ReleasePublished {
        /// The registry's canonical slug.
        registry: String,
        /// The released semver.
        semver: String,
        /// The release commit.
        commit: String,
        /// Unix time the release was observed.
        at: i64,
    },
}

impl WebhookEvent {
    /// The stable event-type string subscribers match on.
    ///
    /// Mirrored into the `X-AOS-Event` delivery header and stored on each
    /// queued delivery row.
    #[must_use]
    pub fn event_type(&self) -> &'static str {
        match self {
            WebhookEvent::IndexCompleted { .. } => "index.completed",
            WebhookEvent::ChannelAdvanced { .. } => "channel.advanced",
            WebhookEvent::VisibilityChanged { .. } => "registry.visibility_changed",
            WebhookEvent::ReleasePublished { .. } => "release.published",
        }
    }

    /// The JSON payload describing this event.
    ///
    /// Always a JSON object carrying the affected `registry` slug, a `type`
    /// echo of [`Self::event_type`], and event-specific fields (see the
    /// [taxonomy](self#event-taxonomy)). This is the exact value delivered as
    /// the request body and signed.
    #[must_use]
    pub fn payload(&self) -> serde_json::Value {
        let mut value = match self {
            WebhookEvent::IndexCompleted {
                registry,
                commit,
                packages,
                releases,
                channels,
                incremental,
                at,
            } => serde_json::json!({
                "registry": registry,
                "commit": commit,
                "packages": packages,
                "releases": releases,
                "channels": channels,
                "incremental": incremental,
                "at": at,
            }),
            WebhookEvent::ChannelAdvanced {
                registry,
                channel,
                release,
                moved,
                at_target,
                rollout_percent,
                at,
            } => serde_json::json!({
                "registry": registry,
                "channel": channel,
                "release": release,
                "moved": moved,
                "at_target": at_target,
                "rollout_percent": rollout_percent,
                "at": at,
            }),
            WebhookEvent::VisibilityChanged {
                registry,
                old,
                new,
                at,
            } => serde_json::json!({
                "registry": registry,
                "old": old,
                "new": new,
                "at": at,
            }),
            WebhookEvent::ReleasePublished {
                registry,
                semver,
                commit,
                at,
            } => serde_json::json!({
                "registry": registry,
                "semver": semver,
                "commit": commit,
                "at": at,
            }),
        };
        if let serde_json::Value::Object(map) = &mut value {
            map.insert("type".into(), self.event_type().into());
        }
        value
    }
}

/// Compute the `X-AOS-Signature` header value for `body` under `secret`.
///
/// Returns `"sha256=<hex>"`, the lowercase-hex HMAC-SHA256 of the raw body
/// bytes keyed by the webhook's shared secret. HMAC-SHA256 accepts a key of
/// any length (`new_from_slice` never returns `InvalidLength` for this MAC),
/// so the construction is infallible.
#[must_use]
pub fn sign_body(secret: &str, body: &[u8]) -> String {
    let Ok(mut mac) = <HmacSha256 as Mac>::new_from_slice(secret.as_bytes()) else {
        // Unreachable: HMAC accepts any key length. Returning a stable,
        // never-matching marker keeps this total without an `expect`.
        return "sha256=".to_string();
    };
    mac.update(body);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

/// Fan one event out to an org's subscribed, active webhooks.
///
/// Looks up the org's webhooks, and for each one that is active and subscribed
/// to `event.event_type()` enqueues one pending delivery of the event's
/// payload. Returns the number of deliveries enqueued (`0` when the org has no
/// matching subscriptions).
///
/// This is intentionally cheap and synchronous (a few small inserts): callers
/// invoke it inline on the operation that raised the event and ignore — or
/// merely log — its result, so a webhook failure never breaks that operation.
///
/// # Errors
///
/// Returns an error only on database failure while listing webhooks or
/// enqueuing a delivery; the payload serialization is infallible.
pub fn dispatch(db: &Database, org_id: i64, event: &WebhookEvent) -> anyhow::Result<usize> {
    let event_type = event.event_type();
    let payload = serde_json::to_string(&event.payload())?;
    let mut enqueued = 0;
    for hook in db.list_webhooks(org_id)? {
        if hook.active && hook.subscribes_to(event_type) {
            db.enqueue_delivery(hook.id, event_type, &payload)?;
            enqueued += 1;
        }
    }
    Ok(enqueued)
}

/// The retry delay, in seconds, after `attempts` have already been made.
///
/// Exponential from [`BASE_BACKOFF_SECS`] (10s, 20s, 40s, …), capped at
/// [`MAX_BACKOFF_SECS`]. `attempts` is the count *including* the one that just
/// failed, so the first retry (after attempt 1) waits 20s.
#[must_use]
pub fn backoff_secs(attempts: i64) -> i64 {
    let shift = attempts.clamp(0, 16) as u32;
    BASE_BACKOFF_SECS
        .saturating_mul(1_i64.checked_shl(shift).unwrap_or(i64::MAX))
        .min(MAX_BACKOFF_SECS)
}

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
    delivery: &DueDelivery,
) -> anyhow::Result<bool> {
    // Defense in depth against TOCTOU / pre-guard rows: never POST to a target
    // the SSRF guard rejects. Mark it failed rather than retried — the rejection
    // is structural, so no future attempt would pass.
    if let Err(err) = crate::fetch::is_safe_remote_url(&delivery.url) {
        tracing::warn!(
            webhook_id = delivery.webhook_id,
            url = %delivery.url,
            error = %format!("{err:#}"),
            "rejecting webhook delivery: url fails SSRF guard"
        );
        db.mark_delivery(delivery.id, "failed", None, delivery.attempts + 1, None)?;
        return Ok(false);
    }
    let signature = sign_body(&delivery.secret, delivery.payload.as_bytes());
    let response = http
        .post(&delivery.url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("X-AOS-Event", &delivery.event)
        .header("X-AOS-Signature", signature)
        .timeout(Duration::from_secs(DELIVERY_TIMEOUT_SECS))
        .body(delivery.payload.clone())
        .send()
        .await;

    let attempts = delivery.attempts + 1;
    match response {
        Ok(resp) if resp.status().is_success() => {
            let code = resp.status().as_u16() as i64;
            db.mark_delivery(delivery.id, "delivered", Some(code), attempts, None)?;
            Ok(true)
        }
        Ok(resp) => {
            let code = resp.status().as_u16() as i64;
            schedule_retry(db, delivery.id, Some(code), attempts)?;
            Ok(false)
        }
        Err(err) => {
            tracing::warn!(
                webhook_id = delivery.webhook_id,
                error = %err,
                "webhook delivery POST failed"
            );
            schedule_retry(db, delivery.id, None, attempts)?;
            Ok(false)
        }
    }
}

/// Record a failed attempt: schedule a backed-off retry, or mark `failed` once
/// the attempt cap is reached.
fn schedule_retry(
    db: &Database,
    id: i64,
    response_code: Option<i64>,
    attempts: i64,
) -> anyhow::Result<()> {
    if attempts >= MAX_ATTEMPTS {
        db.mark_delivery(id, "failed", response_code, attempts, None)?;
    } else {
        let next = now() + backoff_secs(attempts);
        db.mark_delivery(id, "pending", response_code, attempts, Some(next))?;
    }
    Ok(())
}

/// Run the webhook delivery worker until the process exits.
///
/// Every [`WORKER_INTERVAL_SECS`] seconds it sweeps the queue for due
/// deliveries ([`Database::due_deliveries`]) and attempts each in order. A
/// single failing endpoint cannot stall the others: each delivery's outcome is
/// recorded independently, and a recording error is logged rather than
/// aborting the loop. Spawn this once from the server's `serve` entry point.
///
/// [`Database::due_deliveries`]: crate::db::Database::due_deliveries
pub async fn run_delivery_worker(db: Arc<Database>, http: reqwest::Client) {
    let mut tick = tokio::time::interval(Duration::from_secs(WORKER_INTERVAL_SECS));
    loop {
        tick.tick().await;
        let due = match db.due_deliveries(now()) {
            Ok(due) => due,
            Err(err) => {
                tracing::warn!(error = %format!("{err:#}"), "listing due webhook deliveries");
                continue;
            }
        };
        for delivery in &due {
            if let Err(err) = deliver_one(&http, &db, delivery).await {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_type_and_payload_shape() {
        let event = WebhookEvent::ChannelAdvanced {
            registry: "acme/cdn".into(),
            channel: "stable".into(),
            release: "1.2.3".into(),
            moved: 64,
            at_target: 128,
            rollout_percent: 50,
            at: 1_770_000_000,
        };
        assert_eq!(event.event_type(), "channel.advanced");
        let payload = event.payload();
        assert_eq!(payload["type"], "channel.advanced");
        assert_eq!(payload["registry"], "acme/cdn");
        assert_eq!(payload["channel"], "stable");
        assert_eq!(payload["release"], "1.2.3");
        assert_eq!(payload["moved"], 64);
        assert_eq!(payload["rollout_percent"], 50);
    }

    #[test]
    fn index_completed_payload_has_all_fields() {
        let event = WebhookEvent::IndexCompleted {
            registry: "acme/cdn".into(),
            commit: "ab".repeat(32),
            packages: 3,
            releases: 2,
            channels: 1,
            incremental: true,
            at: 1_770_000_000,
        };
        let payload = event.payload();
        assert_eq!(payload["type"], "index.completed");
        assert_eq!(payload["packages"], 3);
        assert_eq!(payload["incremental"], true);
        assert_eq!(payload["commit"], "ab".repeat(32));
    }

    #[test]
    fn signature_is_hmac_sha256_of_the_body() {
        // A known HMAC-SHA256 vector: key "key", message "The quick brown fox
        // jumps over the lazy dog".
        let sig = sign_body("key", b"The quick brown fox jumps over the lazy dog");
        assert_eq!(
            sig,
            "sha256=f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }

    #[test]
    fn signature_verifies_with_the_secret_and_rejects_tampering() {
        let body = br#"{"type":"index.completed","registry":"acme/cdn"}"#;
        let sig = sign_body("s3cret", body);
        // A receiver recomputing under the same secret matches.
        assert_eq!(sign_body("s3cret", body), sig);
        // A different secret, or a tampered body, does not.
        assert_ne!(sign_body("other", body), sig);
        assert_ne!(sign_body("s3cret", b"{}"), sig);
    }

    #[test]
    fn backoff_is_exponential_and_capped() {
        assert_eq!(backoff_secs(0), 10);
        assert_eq!(backoff_secs(1), 20);
        assert_eq!(backoff_secs(2), 40);
        assert_eq!(backoff_secs(3), 80);
        // Eventually saturates at the cap rather than overflowing.
        assert_eq!(backoff_secs(20), MAX_BACKOFF_SECS);
    }
}
