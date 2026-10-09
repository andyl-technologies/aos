//! Webhooks records returned by typed Hub persistence operations.

/// One webhook subscription (system-of-record row).
///
/// An org's HTTP notification endpoint plus the event types it wants and the
/// immutable secret-provider version used to sign deliveries (see
/// the service webhook dispatcher). Plaintext signing material is not persisted.
#[derive(Debug, Clone)]
pub struct WebhookRecord {
    /// Database id.
    pub id: i64,
    /// Owning org id.
    pub org_id: i64,
    /// Destination URL each subscribed event is `POST`ed to.
    pub url: String,
    /// Immutable reference resolved by the delivery runtime.
    pub secret_version_ref: String,
    /// Required SHA-256 hex digest of the resolved signing secret.
    pub credential_fingerprint: String,
    /// Subscribed event-type strings; empty means *all* events.
    pub events: Vec<String>,
    /// Whether the subscription currently receives deliveries.
    pub active: bool,
    /// Unix time the subscription was created.
    pub created_at: i64,
    /// Optimistic-concurrency version for webhook lifecycle changes.
    pub resource_version: i64,
    /// Last lifecycle update time in Unix seconds.
    pub updated_at: i64,
}

/// A due delivery joined with its webhook's URL and signing-secret reference.
///
/// Produced by [`Database::claim_due_deliveries`]; a delivery runtime resolves
/// the exact secret version only while signing the payload to `POST`.
#[derive(Clone)]
pub struct DueDelivery {
    /// The `webhook_deliveries` row id.
    pub id: i64,
    /// Stable public delivery identity sent to the receiver.
    pub delivery_id: String,
    /// Fencing token proving ownership of the active delivery lease.
    pub claim_token: String,
    /// The webhook this delivery targets.
    pub webhook_id: i64,
    /// The event-type string, mirrored into the `X-AOS-Event` header.
    pub event: String,
    /// The exact JSON body to sign and `POST`.
    pub payload: String,
    /// How many attempts have already been made (for backoff scheduling).
    pub attempts: i64,
    /// The destination URL.
    pub url: String,
    /// Immutable reference resolved by the delivery runtime.
    pub secret_version_ref: String,
    /// Required SHA-256 hex digest expected for the resolved secret.
    pub credential_fingerprint: String,
}

impl WebhookRecord {
    /// Whether this webhook is subscribed to `event_type`.
    ///
    /// An empty subscription list matches every event.
    #[must_use]
    pub fn subscribes_to(&self, event_type: &str) -> bool {
        self.events.is_empty() || self.events.iter().any(|e| e == event_type)
    }
}
