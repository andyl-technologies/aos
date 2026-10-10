//! Replayable assessment events with bounded, closed payloads.
//!
//! Events describe committed admission or attention changes. They never grant
//! evidence import, acknowledgement or release authority to their recipients.

use anyhow::{Result, bail};
use aos_assessment::time::Timestamp;
use aos_contract::Sha256Digest;
use aos_contract::limits::{BoundedWriter, JsonLimits};
use serde::{Deserialize, Serialize};

use crate::alerts::{AlertTransitionKind, AssessmentAlertV1};
use crate::validation::text;

mod delivery;

pub use delivery::{DeliveryFailureCode, DeliveryFailureV1};

const LIMITS: JsonLimits = JsonLimits {
    max_bytes: 262_144,
    max_depth: 16,
    max_items: 16_384,
    max_string_bytes: 4096,
};

/// Names one committed event's closed payload.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum AssessmentEventPayload {
    /// Reports a committed attention transition and its complete resulting revision.
    Alert {
        /// Lifecycle transition independent of acknowledgement.
        transition: AlertTransitionKind,
        /// Exact committed attention revision.
        alert: Box<AssessmentAlertV1>,
    },
    /// Reports an authorized acknowledgement of an exact open episode.
    Acknowledged {
        /// Exact resulting revision including the acknowledgement audit.
        alert: Box<AssessmentAlertV1>,
    },
    /// Reports a revision-bound recurring review without private credentials.
    #[serde(rename_all = "camelCase")]
    ScheduleChanged {
        /// Public identity within the authorized registry.
        schedule_id: String,
        /// New review revision.
        revision: u64,
        /// Current due-execution setting.
        enabled: bool,
    },
    /// Reports a complete notification review without destination or actor credentials.
    #[serde(rename_all = "camelCase")]
    SubscriptionChanged {
        /// Public identity within the independently authorized registry.
        subscription_id: String,
        /// New review revision.
        revision: u64,
        /// Whether newly committed events may create delivery intents.
        enabled: bool,
    },
    /// Reports admitted results, including results with unknown coverage.
    #[serde(rename_all = "camelCase")]
    ScanCompleted {
        /// Original immutable operation identity.
        scan_id: String,
        /// Exact result commitment; coverage remains inside the result.
        assessment_digest: Sha256Digest,
    },
    /// Reports one settled failed callback attempt without callback fanout.
    DeliveryFailed {
        /// Sanitized immutable operational facts for the exact physical batch.
        failure: Box<DeliveryFailureV1>,
    },
}

/// Carries one ordered resource event for watch replay and notifications.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AssessmentEventV1 {
    /// Exact event discriminator.
    pub schema: String,
    /// Unpredictable globally unique identity retained through retries.
    pub event_id: String,
    /// Positive resource-local sequence encoded losslessly for all clients.
    #[serde(with = "crate::validation::decimal_u64")]
    pub sequence: u64,
    /// Journal time at which admission or attention changed.
    pub occurred_at: Timestamp,
    /// Closed committed change, independent of any delivery destination.
    pub payload: AssessmentEventPayload,
}

impl AssessmentEventV1 {
    /// Validates event scope and the embedded complete attention revision.
    ///
    /// # Errors
    /// Returns an error for unsupported schema, exhausted sequence, invalid IDs,
    /// malformed attention state or a future embedded revision.
    pub fn validate(&self) -> Result<()> {
        if self.schema != "aos.assessment-event/v1"
            || self.sequence == 0
            || self.sequence > 9_007_199_254_740_991
        {
            bail!("invalid assessment event schema or sequence");
        }
        text(&self.event_id, 128, "assessment event ID")?;
        match &self.payload {
            AssessmentEventPayload::Alert { alert, .. }
            | AssessmentEventPayload::Acknowledged { alert } => {
                alert.validate()?;
                if alert.updated_at > self.occurred_at {
                    bail!("assessment event embeds a future attention revision");
                }
            }
            AssessmentEventPayload::ScheduleChanged {
                schedule_id,
                revision,
                ..
            } => {
                text(schedule_id, 128, "assessment schedule identity")?;
                if *revision == 0 || *revision > 9_007_199_254_740_991 {
                    bail!("assessment schedule event revision is invalid");
                }
            }
            AssessmentEventPayload::SubscriptionChanged {
                subscription_id,
                revision,
                ..
            } => {
                text(subscription_id, 128, "assessment subscription identity")?;
                if *revision == 0 || *revision > 9_007_199_254_740_991 {
                    bail!("assessment subscription event revision is invalid");
                }
            }
            AssessmentEventPayload::ScanCompleted { scan_id, .. } => {
                text(scan_id, 128, "assessment event operation")?;
            }
            AssessmentEventPayload::DeliveryFailed { failure } => {
                failure.validate()?;
                if let Some(retry_at) = &failure.retry_at {
                    let delay = retry_at.elapsed_since(&self.occurred_at)?;
                    if delay > 3600 {
                        bail!("delivery failure retry exceeds the installed one-hour ceiling");
                    }
                }
            }
        }
        Ok(())
    }

    /// Encodes canonical bounded bytes without unbounded intermediate allocation.
    ///
    /// # Errors
    /// Returns an error for invalid event content, structural or byte limits.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut count =
            BoundedWriter::new(LIMITS.max_bytes as u64, "assessment event exceeds limit");
        serde_json::to_writer(&mut count, self)?;
        let value = serde_json::to_value(self)?;
        LIMITS.check_value(&value, "assessment event")?;
        crate::validation::reject_null(&value)?;
        let bytes = aos_contract::canonical::to_vec(&value)?;
        if bytes.len() > LIMITS.max_bytes {
            bail!("canonical assessment event exceeds limit");
        }
        Ok(bytes)
    }

    /// Decodes one bounded closed document and checks its retained state.
    ///
    /// # Errors
    /// Returns an error for ambiguous JSON, unknown fields, invalid state or limits.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let value: serde_json::Value = LIMITS.decode(bytes, "assessment event")?;
        crate::validation::reject_null(&value)?;
        let event: Self = serde_json::from_value(value)?;
        event.validate()?;
        Ok(event)
    }
}
