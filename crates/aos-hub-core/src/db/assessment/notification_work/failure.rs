//! Operational failure events share physical receipt settlement and never fan out.

use anyhow::Result;
use aos_assessment::time::Timestamp;
use aos_assessment_runtime::events::{
    AssessmentEventPayload, DeliveryFailureCode, DeliveryFailureV1,
};
use aos_assessment_runtime::notifications::{DeliveryOutcome, NotificationWorkReceiptV1};

use super::AssessmentNotificationWork;
use crate::backend::CheckedStatement;
use crate::db::Database;

impl Database {
    /// Builds one sanitized event for a failed batch's exact admitted receipt.
    ///
    /// Callers append these statements to the live attempt settlement transaction.
    /// Exact replay returns before allocation, so neither digest membership nor
    /// a restarted receipt can create another failure event.
    ///
    /// # Errors
    /// Returns an error for malformed failure facts or unavailable event allocation.
    pub(super) async fn notification_failure_event_statements(
        &self,
        work: &AssessmentNotificationWork,
        receipt: &NotificationWorkReceiptV1,
        terminal: bool,
        not_before: u64,
        now: &Timestamp,
    ) -> Result<Vec<CheckedStatement>> {
        let code = match receipt.outcome {
            DeliveryOutcome::Accepted => return Ok(Vec::new()),
            DeliveryOutcome::Retryable => DeliveryFailureCode::DestinationRetryable,
            DeliveryOutcome::PermanentFailure => DeliveryFailureCode::DestinationPermanentFailure,
        };
        let failure = DeliveryFailureV1 {
            delivery_id: work.plan.body.delivery_id.clone(),
            subscription_id: work.plan.body.subscription_id.clone(),
            subscription_revision: work.plan.body.subscription_revision,
            attempt: work.plan.attempt,
            receipt_digest: receipt.digest()?,
            code,
            status: receipt.status,
            terminal,
            retry_at: if terminal {
                None
            } else {
                Some(Timestamp::from_unix_seconds(not_before)?)
            },
        };
        failure.validate()?;
        self.assessment_event_statements(
            work.registry_id,
            vec![AssessmentEventPayload::DeliveryFailed {
                failure: Box::new(failure),
            }],
            now,
        )
        .await
    }
}
