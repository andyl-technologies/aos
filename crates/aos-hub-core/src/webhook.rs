//! Outbound-webhook event taxonomy, signing, and dispatch (the runtime-agnostic
//! half).
//!
//! When a registry's state changes through a hub-mediated path — an index
//! completes, a channel advances, a registry's visibility flips, a release is
//! published — the hub raises a [`WebhookEvent`]. [`dispatch`] finds the owning
//! org's *active* webhooks subscribed to that event type and enqueues one
//! durable delivery per hook (a pure database write). The actual HTTP delivery
//! worker — the part that `POST`s payloads with a hardened client and retries —
//! lives in the native hub (RFC-0004 Phase 5), since it needs an HTTP stack; on
//! the Cloudflare Worker the same queue is drained by a Cron-triggered fetch.
//!
//! This module owns the deployment-independent pieces shared by both: the event
//! [taxonomy](WebhookEvent), the HMAC-SHA256 [body signature](sign_body), the
//! db-enqueue [`dispatch`], and the [`backoff_secs`] retry schedule.
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
//! # Signature scheme
//!
//! Every delivery is signed `sha256=<hex>`, the lowercase-hex HMAC-SHA256 of the
//! **exact raw body bytes** keyed by the webhook's shared `secret`. A subscriber
//! verifies by recomputing the same MAC over the bytes it received and comparing
//! in constant time — the GitHub-style scheme.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::db::Database;

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
pub async fn dispatch(db: &Database, org_id: i64, event: &WebhookEvent) -> anyhow::Result<usize> {
    let event_type = event.event_type();
    let payload = serde_json::to_string(&event.payload())?;
    let mut enqueued = 0;
    for hook in db.list_webhooks(org_id).await? {
        if hook.active && hook.subscribes_to(event_type) {
            db.enqueue_delivery(hook.id, event_type, &payload).await?;
            enqueued += 1;
        }
    }
    Ok(enqueued)
}

/// The retry delay, in seconds, after `attempts` have already been made.
///
/// Exponential from a 10s base (10s, 20s, 40s, …), capped at one hour.
/// `attempts` is the count *including* the one that just failed, so the first
/// retry (after attempt 1) waits 20s.
#[must_use]
pub fn backoff_secs(attempts: i64) -> i64 {
    let shift = attempts.clamp(0, 16) as u32;
    BASE_BACKOFF_SECS
        .saturating_mul(1_i64.checked_shl(shift).unwrap_or(i64::MAX))
        .min(MAX_BACKOFF_SECS)
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
