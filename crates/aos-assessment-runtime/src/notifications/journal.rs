//! Bounded delivery status projections without execution capabilities or callback bodies.
//!
//! A delivery identity names one event intent. Digest batches additionally expose
//! their shared physical delivery identity and pinned body commitment. Status reads
//! never claim, retry, acknowledge or otherwise change an intent.
//!
//! A continuation preserves its authorized registry incarnation and filter:
//!
//! ```json
//! {"schema":"aos.assessment-notification-delivery-query/v1","resourceScope":"registry-incarnation","subscriptionId":"review","limit":10}
//! ```

use anyhow::{Result, ensure};
use aos_assessment::time::Timestamp;
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::validation::{decode, encoded, text};

/// Names the coordinator's retained state for one notification intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NotificationIntentState {
    /// Awaits its next eligible attempt.
    Pending,
    /// Holds a finite physical-attempt lease, possibly with an uncertain outcome.
    Leased,
    /// Retains an authenticated successful destination response.
    Delivered,
    /// Exhausted its age/attempt allowance or received a permanent refusal.
    DeadLetter,
    /// Lost its reviewed subscription authority.
    Revoked,
}

/// Carries a closed operational reason without upstream response text.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NotificationFailureCode {
    /// The subscription review was replaced or disabled.
    SubscriptionReviewReplaced,
    /// The retained review authority expired.
    NotificationReviewExpired,
    /// The attempt or age bound was exhausted.
    NotificationAttemptOrAgeExhausted,
    /// The physical outcome permits a bounded later retry.
    DestinationRetryable,
    /// The destination returned a permanent failure.
    DestinationPermanentFailure,
}

/// Exposes one event intent's status and immutable batch linkage.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NotificationDeliveryV1 {
    /// Stable public event-intent identity.
    pub delivery_id: String,
    /// Public subscription identity; private database keys are omitted.
    pub subscription_id: String,
    /// Exact subscription review revision in decimal form.
    pub subscription_revision: String,
    /// Original event sequence in decimal form.
    pub event_sequence: String,
    /// Current retained intent state.
    pub state: NotificationIntentState,
    /// Number of admitted attempts, from zero through twenty.
    pub attempt: u8,
    /// Earliest eligibility time, interpreted with the page's database clock.
    pub not_before: Timestamp,
    /// Exclusive expiry of a currently leased attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_expires_at: Option<Timestamp>,
    /// Monotonic row revision in decimal form.
    pub resource_version: String,
    /// Original intent admission time.
    pub created_at: Timestamp,
    /// Most recent retained state change time.
    pub updated_at: Timestamp,
    /// Closed most recent failure category, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error_code: Option<NotificationFailureCode>,
    /// Shared physical callback identity after the first claim pins its batch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch_delivery_id: Option<String>,
    /// Exact callback body commitment, present with its physical batch identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_digest: Option<Sha256Digest>,
    /// Most recent retained compact receipt commitment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_digest: Option<Sha256Digest>,
}

impl NotificationDeliveryV1 {
    /// Checks status invariants and canonical decimal counters.
    ///
    /// # Errors
    /// Returns an error for malformed identities, counters or inconsistent batch/lease facts.
    pub fn validate(&self) -> Result<()> {
        text(&self.delivery_id, 128, "notification delivery identity")?;
        text(
            &self.subscription_id,
            128,
            "notification subscription identity",
        )?;
        for value in [
            &self.subscription_revision,
            &self.event_sequence,
            &self.resource_version,
        ] {
            let number = value.parse::<u64>()?;
            ensure!(
                number > 0 && number.to_string() == *value,
                "invalid notification decimal counter"
            );
        }
        ensure!(
            self.attempt <= 20,
            "notification attempt count exceeds its bound"
        );
        ensure!(
            (self.state == NotificationIntentState::Leased) == self.lease_expires_at.is_some(),
            "notification lease facts differ from its state"
        );
        ensure!(
            self.batch_delivery_id.is_some() == self.body_digest.is_some()
                && (self.attempt > 0) == self.body_digest.is_some(),
            "notification batch commitment differs from its attempt history"
        );
        if let Some(identity) = &self.batch_delivery_id {
            text(identity, 128, "notification batch delivery identity")?;
        }
        ensure!(
            self.receipt_digest.is_none() || self.attempt > 0,
            "unattempted notification has a receipt"
        );
        ensure!(
            self.state != NotificationIntentState::Leased || self.attempt > 0,
            "unattempted notification has a physical lease"
        );
        ensure!(
            self.state != NotificationIntentState::Delivered
                || (self.receipt_digest.is_some() && self.last_error_code.is_none()),
            "delivered notification lacks its accepted receipt facts"
        );
        Ok(())
    }
}

/// Selects one delivery or a finite resource-bound page without changing delivery state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NotificationDeliveryQueryV1 {
    /// Exact query discriminator.
    pub schema: String,
    /// Registry incarnation; required when continuing a prior page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_scope: Option<String>,
    /// Exact event-intent identity for a detail read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_id: Option<String>,
    /// Optional public subscription filter, retained across page continuations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subscription_id: Option<String>,
    /// Opaque retained page handle from the preceding response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_delivery: Option<String>,
    /// Maximum projected rows, from one through ten.
    pub limit: u32,
}

impl NotificationDeliveryQueryV1 {
    /// Decodes a closed bounded status query.
    ///
    /// # Errors
    /// Returns an error for unknown fields, ambiguous selectors or invalid bounds.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let value: Self = decode(bytes, "notification delivery query")?;
        value.validate()?;
        Ok(value)
    }

    /// Checks detail/page selectors and incarnation-bound continuation.
    ///
    /// # Errors
    /// Returns an error for invalid schema, identities, bounds or missing continuation scope.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == "aos.assessment-notification-delivery-query/v1"
                && (1..=10).contains(&self.limit),
            "invalid notification delivery query"
        );
        for value in [
            &self.resource_scope,
            &self.delivery_id,
            &self.subscription_id,
            &self.after_delivery,
        ]
        .into_iter()
        .flatten()
        {
            text(value, 128, "notification delivery query selector")?;
        }
        ensure!(
            self.delivery_id.is_none() || self.after_delivery.is_none(),
            "delivery detail and continuation cannot be combined"
        );
        ensure!(
            self.after_delivery.is_none() || self.resource_scope.is_some(),
            "delivery continuation requires its original resource incarnation"
        );
        if let Some(cursor) = &self.after_delivery {
            crate::read_snapshot::deliveries::parse_delivery_cursor(cursor)?;
        }
        Ok(())
    }
}

/// Returns a bounded operational view with no callback URL, key, body or claim token.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NotificationDeliveryPageV1 {
    /// Exact response discriminator.
    pub schema: String,
    /// Exact authorized registry incarnation.
    pub resource_scope: String,
    /// Original database observation time for interpreting eligibility and leases.
    pub as_of: Timestamp,
    /// Applied public subscription filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subscription_id: Option<String>,
    /// At most ten projections in stable event-intent identity order.
    pub deliveries: Vec<NotificationDeliveryV1>,
    /// Opaque next-page handle bound to the original scope, filter and page size.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_delivery: Option<String>,
}

impl NotificationDeliveryPageV1 {
    /// Encodes a validated finite status page shared by all clients.
    ///
    /// # Errors
    /// Returns an error for invalid schema, scope, ordering, filter or continuation.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        ensure!(
            self.schema == "aos.assessment-notification-delivery-page/v1"
                && self.deliveries.len() <= 10,
            "invalid notification delivery page"
        );
        text(
            &self.resource_scope,
            128,
            "notification delivery page resource",
        )?;
        if let Some(identity) = &self.subscription_id {
            text(identity, 128, "notification delivery page subscription")?;
        }
        for delivery in &self.deliveries {
            delivery.validate()?;
            ensure!(
                self.subscription_id
                    .as_ref()
                    .is_none_or(|identity| identity == &delivery.subscription_id),
                "notification delivery differs from its subscription filter"
            );
        }
        ensure!(
            self.deliveries
                .windows(2)
                .all(|pair| pair[0].delivery_id < pair[1].delivery_id),
            "notification delivery identities are unordered or duplicated"
        );
        if let Some(next) = &self.next_delivery {
            crate::read_snapshot::deliveries::parse_delivery_cursor(next)?;
            ensure!(
                !self.deliveries.is_empty(),
                "empty notification delivery page has a continuation"
            );
        }
        encoded(self)
    }

    /// Decodes the same status projection used by CLI and web clients.
    ///
    /// # Errors
    /// Returns an error for unknown fields or inconsistent status page facts.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let value: Self = decode(bytes, "notification delivery page")?;
        value.to_bytes()?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn delivery() -> NotificationDeliveryV1 {
        NotificationDeliveryV1 {
            delivery_id: "intent-a".into(),
            subscription_id: "review".into(),
            subscription_revision: "1".into(),
            event_sequence: u64::MAX.to_string(),
            state: NotificationIntentState::Pending,
            attempt: 0,
            not_before: Timestamp::parse("2026-10-10T00:00:00Z").unwrap(),
            lease_expires_at: None,
            resource_version: "1".into(),
            created_at: Timestamp::parse("2026-10-10T00:00:00Z").unwrap(),
            updated_at: Timestamp::parse("2026-10-10T00:00:00Z").unwrap(),
            last_error_code: None,
            batch_delivery_id: None,
            body_digest: None,
            receipt_digest: None,
        }
    }

    #[test]
    fn rejects_inconsistent_attempt_lease_and_disclosure_facts() {
        let mut item = delivery();
        item.validate().unwrap();
        item.state = NotificationIntentState::Leased;
        assert!(item.validate().is_err());
        item.lease_expires_at = Some(item.not_before.clone());
        assert!(item.validate().is_err());
        item.attempt = 1;
        item.batch_delivery_id = Some("batch-a".into());
        item.body_digest = Some(Sha256Digest::of_bytes("pinned body"));
        item.validate().unwrap();
        item.state = NotificationIntentState::Delivered;
        item.lease_expires_at = None;
        assert!(item.validate().is_err());
        item.receipt_digest = Some(Sha256Digest::of_bytes("accepted receipt"));
        item.validate().unwrap();
        item.event_sequence = "01".into();
        assert!(item.validate().is_err());
    }

    #[test]
    fn page_rejects_cross_filter_unordered_and_unclosed_projections() {
        let mut page = NotificationDeliveryPageV1 {
            schema: "aos.assessment-notification-delivery-page/v1".into(),
            resource_scope: "registry-incarnation".into(),
            as_of: delivery().created_at,
            subscription_id: Some("review".into()),
            deliveries: vec![delivery()],
            next_delivery: Some(format!(
                "d1:{}:0123456789abcdef0123456789abcdef",
                Sha256Digest::of_bytes("capture").hex()
            )),
        };
        let bytes = page.to_bytes().unwrap();
        assert_eq!(
            NotificationDeliveryPageV1::from_slice(&bytes).unwrap(),
            page
        );
        let mut disclosure: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        disclosure["deliveries"][0]["claimToken"] = serde_json::json!("forbidden");
        assert!(
            NotificationDeliveryPageV1::from_slice(&serde_json::to_vec(&disclosure).unwrap())
                .is_err()
        );
        page.subscription_id = Some("other-review".into());
        assert!(page.to_bytes().is_err());
        page.subscription_id = None;
        page.deliveries.push(delivery());
        assert!(page.to_bytes().is_err());
    }

    #[test]
    fn continuation_requires_original_scope_and_unambiguous_selectors() {
        let mut query = NotificationDeliveryQueryV1 {
            schema: "aos.assessment-notification-delivery-query/v1".into(),
            resource_scope: None,
            delivery_id: None,
            subscription_id: None,
            after_delivery: Some(format!(
                "d1:{}:0123456789abcdef0123456789abcdef",
                Sha256Digest::of_bytes("capture").hex()
            )),
            limit: 10,
        };
        assert!(query.validate().is_err());
        query.resource_scope = Some("registry-incarnation".into());
        query.validate().unwrap();
        let cursor = query.after_delivery.clone();
        for invalid in ["intent-a", "d1:invalid", "n1:invalid"] {
            query.after_delivery = Some(invalid.into());
            assert!(query.validate().is_err());
        }
        query.after_delivery = cursor;
        query.delivery_id = Some("intent-a".into());
        assert!(query.validate().is_err());
        query.delivery_id = None;
        query.limit = 11;
        assert!(query.validate().is_err());
    }
}
