//! Closed alert, acknowledgement and event-replay controls for every client.
//!
//! Continuations bind a non-reusable resource scope. Acknowledgements identify
//! an exact episode and revision and cannot confer remediation authority.

use anyhow::{Result, bail};
use aos_assessment::time::Timestamp;
use aos_contract::Sha256Digest;
use aos_contract::limits::{BoundedWriter, JsonLimits};
use serde::{Deserialize, Serialize};

use crate::alerts::AssessmentAlertV1;
use crate::events::AssessmentEventV1;
use crate::validation::{decode, text};

const PAGE_LIMITS: JsonLimits = JsonLimits {
    max_bytes: 4 * 1024 * 1024,
    max_depth: 32,
    max_items: 250_000,
    max_string_bytes: 8 * 1024,
};

/// Selects a finite issue page in stable issue-key order.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AlertQueryV1 {
    /// Exact query discriminator.
    pub schema: String,
    /// Maximum complete records, between one and ten.
    pub limit: u32,
    /// Exclusive issue position; possession grants no access.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_issue: Option<Sha256Digest>,
    /// Non-reusable scope required for a continuation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_scope: Option<String>,
}

impl AlertQueryV1 {
    /// Decodes a bounded scope-bound issue selector.
    ///
    /// # Errors
    /// Returns an error for ambiguous schemas, excessive pages or unbound cursors.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let query: Self = decode(bytes, "assessment alert query")?;
        if query.schema != "aos.assessment-alert-query/v1" {
            bail!("unsupported assessment alert query schema");
        }
        validate_query(
            query.limit,
            query.after_issue.is_some(),
            &query.resource_scope,
        )?;
        Ok(query)
    }
}

/// Selects resource-local events after an exclusive committed sequence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EventQueryV1 {
    /// Exact query discriminator.
    pub schema: String,
    /// Maximum complete events, between one and ten.
    pub limit: u32,
    /// Exclusive portable sequence; zero requests retained history.
    pub after_sequence: u64,
    /// Non-reusable scope required for replay after a nonzero sequence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_scope: Option<String>,
}

impl EventQueryV1 {
    /// Decodes bounded event replay without acquiring provider evidence.
    ///
    /// # Errors
    /// Returns an error for ambiguous schemas, exhausted sequences or unbound replay.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let query: Self = decode(bytes, "assessment event query")?;
        if query.schema != "aos.assessment-event-query/v1"
            || query.after_sequence > 9_007_199_254_740_991
        {
            bail!("invalid assessment event query schema or sequence");
        }
        validate_query(
            query.limit,
            query.after_sequence != 0,
            &query.resource_scope,
        )?;
        Ok(query)
    }
}

/// Requests attention acknowledgement of one exact open episode.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AlertAcknowledgementV1 {
    /// Exact request discriminator.
    pub schema: String,
    /// Non-reusable authorized resource scope.
    pub resource_scope: String,
    /// Original stable issue identity.
    pub issue_key: Sha256Digest,
    /// Exact open episode, independent of later reopenings.
    pub episode: u64,
    /// Required current transition revision.
    pub expected_sequence: u64,
    /// Actor-scoped retry identity; conflicting reuse is refused.
    pub idempotency_key: String,
    /// Optional bounded attention note.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl AlertAcknowledgementV1 {
    /// Decodes an acknowledgement without accepting caller-supplied actor or time.
    ///
    /// # Errors
    /// Returns an error for ambiguous schemas, invalid scope or episode/revision.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let request: Self = decode(bytes, "assessment acknowledgement")?;
        if request.schema != "aos.assessment-alert-acknowledgement/v1"
            || request.episode == 0
            || request.expected_sequence == 0
            || request.episode > 9_007_199_254_740_991
            || request.expected_sequence > 9_007_199_254_740_991
        {
            bail!("invalid assessment acknowledgement schema or revision");
        }
        text(
            &request.resource_scope,
            128,
            "acknowledgement resource scope",
        )?;
        text(&request.idempotency_key, 128, "acknowledgement retry key")?;
        if let Some(reason) = &request.reason {
            text(reason, 4096, "acknowledgement reason")?;
        }
        Ok(request)
    }
}

/// Returns complete alert records including resolved and retired history.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AlertPageV1 {
    /// Exact page discriminator.
    pub schema: String,
    /// Independently authorized non-reusable resource scope.
    pub resource_scope: String,
    /// Database time of this side-effect-free read.
    pub as_of: Timestamp,
    /// Complete records in ascending issue-key order.
    pub alerts: Vec<AssessmentAlertV1>,
    /// Exclusive continuation when more records exist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_issue: Option<Sha256Digest>,
}

impl AlertPageV1 {
    /// Encodes a bounded canonical alert page.
    ///
    /// # Errors
    /// Returns an error for invalid records, ordering, continuation or page bounds.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        encode_page(self)
    }

    /// Decodes the exact same canonical page consumed by all clients.
    ///
    /// # Errors
    /// Returns an error for ambiguous content, invalid records or page bounds.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let page: Self = decode_page(bytes)?;
        page.validate()?;
        Ok(page)
    }

    fn validate(&self) -> Result<()> {
        if self.schema != "aos.assessment-alert-page/v1"
            || self.alerts.len() > 10
            || self
                .alerts
                .windows(2)
                .any(|pair| pair[0].issue_key >= pair[1].issue_key)
            || self.next_issue.is_some_and(|key| {
                self.alerts
                    .last()
                    .is_none_or(|alert| alert.issue_key != key)
            })
        {
            bail!("invalid assessment alert page or continuation");
        }
        text(&self.resource_scope, 128, "alert page resource scope")?;
        for alert in &self.alerts {
            alert.validate()?;
            if alert.updated_at > self.as_of {
                bail!("alert page contains a future revision");
            }
        }
        Ok(())
    }
}

/// Returns committed event replay or an empty heartbeat with database time.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EventPageV1 {
    /// Exact replay discriminator.
    pub schema: String,
    /// Independently authorized non-reusable resource scope.
    pub resource_scope: String,
    /// Database time, including when no new events exist.
    pub as_of: Timestamp,
    /// Complete committed events in ascending sequence order.
    pub events: Vec<AssessmentEventV1>,
    /// Exclusive position for the next poll; unchanged for an empty heartbeat.
    pub next_sequence: u64,
}

impl EventPageV1 {
    /// Encodes a bounded canonical event replay page.
    ///
    /// # Errors
    /// Returns an error for invalid events, ordering, cursor or byte bounds.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        encode_page(self)
    }

    /// Decodes bounded event replay for reconnecting clients.
    ///
    /// # Errors
    /// Returns an error for ambiguous content, invalid events or page bounds.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let page: Self = decode_page(bytes)?;
        page.validate()?;
        Ok(page)
    }

    fn validate(&self) -> Result<()> {
        if self.schema != "aos.assessment-event-page/v1"
            || self.events.len() > 10
            || self.next_sequence > 9_007_199_254_740_991
            || self
                .events
                .windows(2)
                .any(|pair| pair[0].sequence >= pair[1].sequence)
            || self
                .events
                .last()
                .is_some_and(|event| event.sequence != self.next_sequence)
        {
            bail!("invalid assessment event replay or continuation");
        }
        text(&self.resource_scope, 128, "event page resource scope")?;
        for event in &self.events {
            event.validate()?;
            if event.occurred_at > self.as_of {
                bail!("event page contains a future event");
            }
        }
        Ok(())
    }
}

fn validate_query(limit: u32, continued: bool, scope: &Option<String>) -> Result<()> {
    if !(1..=10).contains(&limit) || (continued && scope.is_none()) {
        bail!("attention page exceeds its limit or lacks its resource scope");
    }
    if let Some(scope) = scope {
        text(scope, 128, "attention continuation scope")?;
    }
    Ok(())
}

fn encode_page<T: Serialize>(page: &T) -> Result<Vec<u8>> {
    let mut bound =
        BoundedWriter::new(PAGE_LIMITS.max_bytes as u64, "attention page exceeds limit");
    serde_json::to_writer(&mut bound, page)?;
    let value = serde_json::to_value(page)?;
    PAGE_LIMITS.check_value(&value, "attention page")?;
    crate::validation::reject_null(&value)?;
    aos_contract::canonical::to_vec(&value)
}

fn decode_page<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let value = PAGE_LIMITS.decode(bytes, "attention page")?;
    crate::validation::reject_null(&value)?;
    Ok(serde_json::from_value(value)?)
}
