//! Closed operational delivery failure facts without callback authority or secrets.
//!
//! The enclosing event supplies the registry-local sequence and occurrence time:
//!
//! ```json
//! {
//!   "kind": "delivery-failed",
//!   "failure": {
//!     "deliveryId": "delivery-1",
//!     "subscriptionId": "security-updates",
//!     "subscriptionRevision": 3,
//!     "attempt": 2,
//!     "receiptDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
//!     "code": "destination-retryable",
//!     "status": 503,
//!     "terminal": false,
//!     "retryAt": "2026-10-10T00:02:00Z"
//!   }
//! }
//! ```

use anyhow::{Result, ensure};
use aos_assessment::time::Timestamp;
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::validation::text;

/// Names the sanitized reason that one callback attempt failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeliveryFailureCode {
    /// The destination or transport permits a later bounded attempt.
    DestinationRetryable,
    /// The destination permanently refused this physical attempt.
    DestinationPermanentFailure,
}

/// Exposes one immutable failed attempt independently of notification dispatch.
///
/// This document contains no destination, body, key reference, claim token or
/// private review. Its event can be inspected by current registry readers, but
/// cannot be selected for callback fanout.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DeliveryFailureV1 {
    /// Public root intent identity of the frozen physical batch.
    pub delivery_id: String,
    /// Public subscription identity within the independently authorized registry.
    pub subscription_id: String,
    /// Exact review revision that authorized the failed attempt.
    pub subscription_revision: u64,
    /// Physical attempt number, never a count of frozen digest members.
    pub attempt: u8,
    /// Exact admitted immutable receipt commitment.
    pub receipt_digest: Sha256Digest,
    /// Sanitized destination or transport outcome.
    pub code: DeliveryFailureCode,
    /// Actual final status, absent for uncertain transport failures.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Whether the intent entered its terminal dead-letter state.
    pub terminal: bool,
    /// Original next eligible time, present only when a retry remains pending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_at: Option<Timestamp>,
}

impl DeliveryFailureV1 {
    /// Validates bounded immutable attempt facts without granting a retry.
    ///
    /// # Errors
    /// Returns an error for invalid identities, attempt/review limits,
    /// contradictory terminal state or a successful HTTP status.
    pub fn validate(&self) -> Result<()> {
        text(&self.delivery_id, 128, "failed delivery identity")?;
        text(&self.subscription_id, 128, "failed delivery subscription")?;
        ensure!(
            (1..=9_007_199_254_740_991).contains(&self.subscription_revision)
                && (1..=20).contains(&self.attempt)
                && self.terminal != self.retry_at.is_some(),
            "delivery failure has inconsistent review, attempt or retry state"
        );
        ensure!(
            self.code != DeliveryFailureCode::DestinationPermanentFailure || self.terminal,
            "permanent delivery failure cannot remain pending"
        );
        ensure!(
            self.status.is_none_or(
                |status| (100..=599).contains(&status) && !(200..=299).contains(&status)
            ),
            "delivery failure contains an invalid or successful status"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{AssessmentEventPayload, AssessmentEventV1};
    use crate::notifications::NotificationSummaryV1;

    fn event() -> Result<AssessmentEventV1> {
        let now = Timestamp::parse("2026-10-10T00:00:00Z")?;
        Ok(AssessmentEventV1 {
            schema: "aos.assessment-event/v1".into(),
            event_id: "failure-event".into(),
            sequence: 7,
            occurred_at: now.clone(),
            payload: AssessmentEventPayload::DeliveryFailed {
                failure: Box::new(DeliveryFailureV1 {
                    delivery_id: "delivery".into(),
                    subscription_id: "security-updates".into(),
                    subscription_revision: 3,
                    attempt: 2,
                    receipt_digest: Sha256Digest::of_bytes("receipt"),
                    code: DeliveryFailureCode::DestinationRetryable,
                    status: Some(503),
                    terminal: false,
                    retry_at: Some(Timestamp::from_unix_seconds(now.unix_seconds() + 120)?),
                }),
            },
        })
    }

    #[test]
    fn failure_events_are_closed_inspectable_and_cannot_be_callback_summaries() -> Result<()> {
        let event = event()?;
        assert_eq!(AssessmentEventV1::from_slice(&event.to_bytes()?)?, event);
        assert!(NotificationSummaryV1::from_event(&event).is_err());
        let mut document = serde_json::to_value(&event)?;
        document["payload"]["failure"]["destinationUrl"] =
            serde_json::json!("https://example.org/private");
        assert!(AssessmentEventV1::from_slice(&serde_json::to_vec(&document)?).is_err());
        let encoded = String::from_utf8(event.to_bytes()?)?;
        assert!(!encoded.contains("claimToken") && !encoded.contains("destinationReference"));
        Ok(())
    }

    #[test]
    fn failed_attempts_cannot_claim_success_unbounded_retries_or_contradict_terminal_state()
    -> Result<()> {
        let mut event = event()?;
        let AssessmentEventPayload::DeliveryFailed { failure } = &mut event.payload else {
            anyhow::bail!("fixture payload differs");
        };
        failure.status = Some(204);
        assert!(failure.validate().is_err());
        failure.status = Some(503);
        failure.attempt = 21;
        assert!(failure.validate().is_err());
        failure.attempt = 2;
        failure.terminal = true;
        assert!(failure.validate().is_err());
        failure.terminal = false;
        failure.code = DeliveryFailureCode::DestinationPermanentFailure;
        assert!(failure.validate().is_err());
        failure.code = DeliveryFailureCode::DestinationRetryable;
        failure.retry_at = Some(Timestamp::from_unix_seconds(
            event.occurred_at.unix_seconds() + 3601,
        )?);
        assert!(event.validate().is_err());
        let AssessmentEventPayload::DeliveryFailed { failure } = &mut event.payload else {
            anyhow::bail!("fixture payload differs");
        };
        failure.retry_at = Some(Timestamp::from_unix_seconds(
            event.occurred_at.unix_seconds() - 1,
        )?);
        assert!(event.validate().is_err());
        Ok(())
    }
}
