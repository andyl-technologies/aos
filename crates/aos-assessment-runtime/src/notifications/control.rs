//! Closed reviewed-destination and subscription page controls shared by all clients.

use anyhow::{Result, ensure};
use aos_assessment::time::Timestamp;
use serde::{Deserialize, Serialize};

use super::SubscriptionV1;
use crate::validation::{decode, encoded, text};

/// Selects one registered destination commitment before writing a subscription.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DestinationReviewQueryV1 {
    /// Exact query discriminator.
    pub schema: String,
    /// Exact registry incarnation whose organization owns the destination.
    pub resource_scope: String,
    /// Registered destination identity; arbitrary URLs are not accepted.
    pub destination_reference: String,
    /// Explicit exclusive destination-review deadline.
    pub review_expires_at: Timestamp,
}

impl DestinationReviewQueryV1 {
    /// Decodes a closed destination-review query without accepting URLs or key material.
    ///
    /// # Errors
    /// Returns an error for unknown fields, malformed scope or unsupported schema.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let value: Self = decode(bytes, "notification destination review query")?;
        ensure!(
            value.schema == "aos.assessment-notification-destination-query/v1",
            "invalid notification destination query schema"
        );
        text(
            &value.resource_scope,
            128,
            "notification destination query resource",
        )?;
        text(
            &value.destination_reference,
            128,
            "registered notification destination",
        )?;
        Ok(value)
    }
}

/// Selects a subscription detail or a finite page scoped to a resource incarnation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SubscriptionQueryV1 {
    /// Exact query discriminator.
    pub schema: String,
    /// Optional resource incarnation; required when continuing a prior page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_scope: Option<String>,
    /// Exact public subscription identity for a detail read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subscription_id: Option<String>,
    /// Exclusive public identity from a prior page in the same resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_subscription: Option<String>,
    /// Maximum rows, from one through ten.
    pub limit: u32,
}

impl SubscriptionQueryV1 {
    /// Decodes a bounded detail/page request with an incarnation-bound continuation.
    ///
    /// # Errors
    /// Returns an error for ambiguous selectors, missing scope or exceeded page bounds.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let value: Self = decode(bytes, "assessment subscription query")?;
        value.validate()?;
        Ok(value)
    }

    /// Checks page bounds and mutually exclusive detail/cursor selectors.
    ///
    /// # Errors
    /// Returns an error for invalid schema, identity, selector combination or bounds.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == "aos.assessment-subscription-query/v1" && (1..=10).contains(&self.limit),
            "invalid assessment subscription query"
        );
        for value in [
            &self.resource_scope,
            &self.subscription_id,
            &self.after_subscription,
        ]
        .into_iter()
        .flatten()
        {
            text(value, 128, "subscription query scope")?;
        }
        ensure!(
            self.subscription_id.is_none() || self.after_subscription.is_none(),
            "subscription detail and page continuation cannot be combined"
        );
        ensure!(
            self.after_subscription.is_none() || self.resource_scope.is_some(),
            "subscription continuation requires its original resource incarnation"
        );
        Ok(())
    }
}

/// Returns finite public reviews without destination credentials or private actor claims.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SubscriptionPageV1 {
    /// Exact response discriminator.
    pub schema: String,
    /// Exact registry incarnation independently authorized by the service.
    pub resource_scope: String,
    /// Database time for interpreting review expiry.
    pub as_of: Timestamp,
    /// At most ten public subscription reviews in public identity order.
    pub subscriptions: Vec<SubscriptionV1>,
    /// Exclusive public identity for another page in this exact resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_subscription: Option<String>,
}

impl SubscriptionPageV1 {
    /// Encodes a bounded page and rejects inconsistent scopes or continuation identities.
    ///
    /// # Errors
    /// Returns an error for invalid schema, ordering, scope, reviews or envelope limits.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        ensure!(
            self.schema == "aos.assessment-subscription-page/v1" && self.subscriptions.len() <= 10,
            "invalid assessment subscription page"
        );
        text(&self.resource_scope, 128, "subscription page resource")?;
        for subscription in &self.subscriptions {
            ensure!(
                subscription.resource_scope == self.resource_scope,
                "subscription page contains another resource"
            );
            subscription.to_bytes()?;
        }
        ensure!(
            self.subscriptions
                .windows(2)
                .all(|pair| pair[0].subscription_id < pair[1].subscription_id),
            "subscription page identities are unordered or duplicated"
        );
        if let Some(next) = &self.next_subscription {
            ensure!(
                self.subscriptions
                    .last()
                    .is_some_and(|last| last.subscription_id == *next),
                "subscription page cursor does not match its last public identity"
            );
        }
        encoded(self)
    }

    /// Decodes the same bounded projection consumed by CLI and web clients.
    ///
    /// # Errors
    /// Returns an error for unknown fields or inconsistent page content.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let value: Self = decode(bytes, "assessment subscription page")?;
        value.to_bytes()?;
        Ok(value)
    }
}
