//! Outbound-webhook event taxonomy, signing, and dispatch (the runtime-agnostic
//! half).
//!
//! When a registry's state changes through a hub-mediated path — an index
//! completes, a channel advances, or a release is published — the hub commits
//! a [`WebhookEvent`] to the canonical topology outbox. The materializer fans
//! that event out to active subscriptions, and native and Worker delivery
//! loops send the resulting durable deliveries.
//!
//! This module owns the deployment-independent pieces shared by both: the event
//! [taxonomy](WebhookEvent), the HMAC-SHA256 [body signature](sign_body), the
//! outbox-enqueue [`dispatch`], and the [`backoff_secs`] retry schedule.
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
/// Backoff is exponential (see [`backoff_secs`]); six attempts span five waits
/// of 20s + 40s + 80s + 160s + 320s (about ten minutes) before giving up.
pub const MAX_ATTEMPTS: i64 = 6;

/// Base delay, in seconds, for the first retry; doubled each subsequent
/// attempt by [`backoff_secs`].
const BASE_BACKOFF_SECS: i64 = 10;

/// Cap, in seconds, on a single backoff interval (1 hour), so a long-failing
/// delivery does not schedule retries arbitrarily far out.
const MAX_BACKOFF_SECS: i64 = 3600;

/// Returns whether an event name is safe for the closed webhook header wire.
///
/// Every closed-taxonomy value must also remain a bounded ASCII token before it
/// can be persisted and mirrored into `X-AOS-Event`.
#[must_use]
pub fn is_safe_event_header_value(event_type: &str) -> bool {
    !event_type.is_empty()
        && event_type.len() <= 128
        && event_type
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// Event names accepted by webhook subscription filters.
///
/// This is the single API/CLI/UI taxonomy: it contains operational registry
/// events plus every topology outbox event emitted by the hard-cutover schema.
pub const SUPPORTED_EVENT_TYPES: &[&str] = &[
    "index.completed",
    "channel.advanced",
    "release.published",
    "project.created",
    "project.deleted",
    "registry.configuration.updated",
    "registry.deleted",
    "webhook.created",
    "webhook.deleted",
    "topology.storage_credential.validated",
    "topology.storage_credential.rejected",
    "topology.storage_gateway.created",
    "topology.storage_gateway.revised",
    "topology.storage_gateway.enabled",
    "topology.storage_gateway.disabled",
    "topology.storage_gateway.reconciled",
    "topology.storage_gateway.deleted",
    "topology.delivery_route.created",
    "topology.delivery_route.revised",
    "topology.delivery_route.reconciled",
    "topology.delivery_route.deleted",
    "topology.network_boundary.activation_started",
    "topology.network_boundary.activated",
    "topology.network_boundary.retirement_started",
    "topology.network_boundary.retired",
    "topology.delivery_endpoint.created",
    "topology.delivery_endpoint.generation_staged",
    "topology.delivery_endpoint.generation_activated",
    "topology.delivery_endpoint.reconciled",
    "topology.delivery_endpoint.deleted",
];

/// Returns whether `event_type` is a member of the closed webhook taxonomy.
#[must_use]
pub fn is_supported_event_type(event_type: &str) -> bool {
    SUPPORTED_EVENT_TYPES.contains(&event_type)
}

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
            WebhookEvent::ReleasePublished { .. } => "release.published",
        }
    }

    /// Returns the canonical registry identity carried by the event.
    #[must_use]
    pub fn registry(&self) -> &str {
        match self {
            WebhookEvent::IndexCompleted { registry, .. }
            | WebhookEvent::ChannelAdvanced { registry, .. }
            | WebhookEvent::ReleasePublished { registry, .. } => registry,
        }
    }

    /// Returns a stable semantic key used to deduplicate producer retries.
    pub(crate) fn dedupe_key(&self) -> serde_json::Value {
        match self {
            WebhookEvent::IndexCompleted {
                registry, commit, ..
            } => serde_json::json!([registry, commit]),
            WebhookEvent::ChannelAdvanced {
                registry,
                channel,
                release,
                at_target,
                rollout_percent,
                ..
            } => serde_json::json!([registry, channel, release, at_target, rollout_percent]),
            WebhookEvent::ReleasePublished {
                registry,
                semver,
                commit,
                ..
            } => serde_json::json!([registry, semver, commit]),
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
    sign_body_bytes(secret.as_bytes(), body)
}

/// Computes an HMAC signature with arbitrary provider-managed key bytes.
#[must_use]
pub fn sign_body_bytes(secret: &[u8], body: &[u8]) -> String {
    let Ok(mut mac) = <HmacSha256 as Mac>::new_from_slice(secret) else {
        // Unreachable: HMAC accepts any key length. Returning a stable,
        // never-matching marker keeps this total without an `expect`.
        return "sha256=".to_string();
    };
    mac.update(body);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

/// Commits one operational event to the canonical topology outbox.
///
/// Producer retries use the event's semantic key to converge on one immutable
/// outbox identity. The ordinary materializer performs subscription fanout and
/// creates stable delivery IDs; operational events therefore have exactly the
/// same audit, Queue, lease, and deduplication path as topology mutations.
/// Returns `1` when it inserts the event and `0` when a producer retry finds
/// the same semantic identity already durable.
///
/// # Errors
///
/// Returns an error for serialization, inconsistent registry ownership, or
/// outbox persistence failure.
pub async fn dispatch(db: &Database, org_id: i64, event: &WebhookEvent) -> anyhow::Result<usize> {
    let event_type = event.event_type();
    let payload = serde_json::to_string(&event.payload())?;
    let dedupe_key = serde_json::to_string(&event.dedupe_key())?;
    Ok(
        if db
            .enqueue_operational_webhook_event(
                org_id,
                event.registry(),
                event_type,
                &dedupe_key,
                &payload,
            )
            .await?
        {
            1
        } else {
            0
        },
    )
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
    fn channel_dedupe_uses_exact_partition_count() {
        let event = |at_target| WebhookEvent::ChannelAdvanced {
            registry: "acme/cdn".into(),
            channel: "stable".into(),
            release: "1.2.3".into(),
            moved: 1,
            at_target,
            rollout_percent: 50,
            at: 1_770_000_000,
        };
        assert_ne!(event(128).dedupe_key(), event(129).dedupe_key());
    }

    #[test]
    fn event_header_tokens_are_bounded_and_injection_safe() {
        assert!(is_safe_event_header_value("topology.webhook.created"));
        assert!(!is_safe_event_header_value(""));
        assert!(!is_safe_event_header_value(
            "index.completed\r\nx-injected: yes"
        ));
        assert!(!is_safe_event_header_value(&"x".repeat(129)));
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
