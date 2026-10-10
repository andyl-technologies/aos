//! Compact event disclosure with finite, immutable digest membership.

use anyhow::{Result, bail, ensure};
use aos_assessment::time::Timestamp;
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::alerts::{AlertTransitionKind, AttentionState, IssueFamily};
use crate::events::{AssessmentEventPayload, AssessmentEventV1};
use crate::validation::{decode, encoded, text};

/// Names explicitly selectable committed changes without disclosing their raw payloads.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NotificationEventKind {
    /// A first or reopened attention episode.
    AlertOpened,
    /// Material evidence, uncertainty or lineage changed.
    AlertChanged,
    /// Fresh relevant evidence justified resolution.
    AlertResolved,
    /// Monitoring or a merged branch ended without proving remediation.
    AlertRetired,
    /// An authorized actor acknowledged an exact episode.
    AlertAcknowledged,
    /// A scan committed its frozen assessment.
    ScanCompleted,
    /// A recurring review was created, replaced or disabled.
    ScheduleChanged,
    /// A notification review was created, replaced or disabled.
    SubscriptionChanged,
}

/// Exposes compact committed facts without notes, raw advisory text or source locations.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NotificationSummaryV1 {
    /// Original unique event identity for receiver deduplication.
    pub event_id: String,
    /// Exact registry-local journal sequence.
    #[serde(with = "crate::validation::decimal_u64")]
    pub sequence: u64,
    /// Original journal time, independent of the callback attempt timestamp.
    pub occurred_at: Timestamp,
    /// Selected committed change.
    pub kind: NotificationEventKind,
    /// Issue category, absent for operational events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<IssueFamily>,
    /// Exact stable issue key, usable in an independently authorized detail request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issue_key: Option<Sha256Digest>,
    /// Exact immutable subject/component context rather than a guessed package name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_digest: Option<Sha256Digest>,
    /// Exact attention episode; absent for operational events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub episode: Option<u64>,
    /// Resulting attention lifecycle, independent of acknowledgement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<AttentionState>,
    /// Whether retained attention has incomplete supporting evidence.
    pub uncertain: bool,
    /// Canonical assessment reference; absence never asserts clean coverage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assessment_digest: Option<Sha256Digest>,
}

impl NotificationSummaryV1 {
    /// Projects only the explicit compact disclosure contract from a committed event.
    ///
    /// # Errors
    /// Returns an error if the event or its embedded attention revision is invalid.
    pub fn from_event(event: &AssessmentEventV1) -> Result<Self> {
        event.validate()?;
        let mut value = Self {
            event_id: event.event_id.clone(),
            sequence: event.sequence,
            occurred_at: event.occurred_at.clone(),
            kind: NotificationEventKind::ScanCompleted,
            family: None,
            issue_key: None,
            context_digest: None,
            episode: None,
            state: None,
            uncertain: false,
            assessment_digest: None,
        };
        match &event.payload {
            AssessmentEventPayload::Alert { transition, alert } => {
                value.kind = match transition {
                    AlertTransitionKind::Opened | AlertTransitionKind::Reopened => {
                        NotificationEventKind::AlertOpened
                    }
                    AlertTransitionKind::Changed
                    | AlertTransitionKind::Unconfirmed
                    | AlertTransitionKind::Merged => NotificationEventKind::AlertChanged,
                    AlertTransitionKind::Resolved => NotificationEventKind::AlertResolved,
                    AlertTransitionKind::Retired => NotificationEventKind::AlertRetired,
                };
                value.attention(alert);
            }
            AssessmentEventPayload::Acknowledged { alert } => {
                value.kind = NotificationEventKind::AlertAcknowledged;
                value.attention(alert);
            }
            AssessmentEventPayload::ScanCompleted {
                assessment_digest, ..
            } => value.assessment_digest = Some(*assessment_digest),
            AssessmentEventPayload::ScheduleChanged { .. } => {
                value.kind = NotificationEventKind::ScheduleChanged
            }
            AssessmentEventPayload::SubscriptionChanged { .. } => {
                value.kind = NotificationEventKind::SubscriptionChanged
            }
            AssessmentEventPayload::DeliveryFailed { .. } => {
                bail!("operational delivery failures cannot be selected for callback fanout");
            }
        }
        value.validate()?;
        Ok(value)
    }

    fn attention(&mut self, alert: &crate::alerts::AssessmentAlertV1) {
        self.family = Some(alert.issue.family);
        self.issue_key = Some(alert.issue_key);
        self.context_digest = Some(alert.issue.context_digest);
        self.episode = Some(alert.episode);
        self.state = Some(alert.state);
        self.uncertain = alert.issue.uncertain;
        self.assessment_digest = Some(alert.assessment_digest);
    }

    /// Checks that attention facts are complete and operational facts cannot impersonate them.
    ///
    /// # Errors
    /// Returns an error for malformed identity, sequence or inconsistent optional facts.
    pub fn validate(&self) -> Result<()> {
        text(&self.event_id, 128, "notification event identity")?;
        ensure!(
            self.sequence > 0 && self.sequence <= 9_007_199_254_740_991,
            "invalid notification event sequence"
        );
        let attention = matches!(
            self.kind,
            NotificationEventKind::AlertOpened
                | NotificationEventKind::AlertChanged
                | NotificationEventKind::AlertResolved
                | NotificationEventKind::AlertRetired
                | NotificationEventKind::AlertAcknowledged
        );
        ensure!(
            self.family.is_some() == attention
                && self.issue_key.is_some() == attention
                && self.context_digest.is_some() == attention
                && self.episode.is_some() == attention
                && self.state.is_some() == attention,
            "notification attention facts are incomplete or misplaced"
        );
        if let Some(episode) = self.episode {
            ensure!(
                episode > 0 && episode <= 9_007_199_254_740_991 && self.assessment_digest.is_some(),
                "invalid notification episode or assessment"
            );
        } else {
            ensure!(
                !self.uncertain,
                "operational notification cannot assert issue uncertainty"
            );
        }
        ensure!(
            self.kind != NotificationEventKind::ScanCompleted || self.assessment_digest.is_some(),
            "completed scan notification lacks an assessment"
        );
        Ok(())
    }
}

/// Pins a finite, ordered callback body whose bytes remain identical through retries.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NotificationBodyV1 {
    /// Exact disclosure discriminator.
    pub schema: String,
    /// Stable logical callback identity, independent of physical attempt identity.
    pub delivery_id: String,
    /// Independently authorized non-reusable registry incarnation.
    pub resource_scope: String,
    /// Reviewed public subscription identity.
    pub subscription_id: String,
    /// Exact review that selected these events.
    pub subscription_revision: u64,
    /// At most fifty original events, strictly ordered by journal sequence.
    pub events: Vec<NotificationSummaryV1>,
}

impl NotificationBodyV1 {
    /// Encodes a compact body after checking pinned membership and resource scope.
    ///
    /// # Errors
    /// Returns an error for unsupported schema, malformed scope or duplicate/unordered events.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        ensure!(
            self.schema == "aos.assessment-notification-body/v1",
            "invalid notification body schema"
        );
        for value in [
            &self.delivery_id,
            &self.resource_scope,
            &self.subscription_id,
        ] {
            text(value, 128, "notification body scope")?;
        }
        ensure!(
            self.subscription_revision > 0 && self.subscription_revision <= 9_007_199_254_740_991,
            "invalid notification subscription revision"
        );
        ensure!(
            !self.events.is_empty() && self.events.len() <= 50,
            "notification membership is empty or exceeds fifty events"
        );
        let mut identities = std::collections::BTreeSet::new();
        for event in &self.events {
            event.validate()?;
            ensure!(
                identities.insert(&event.event_id),
                "duplicate notification event identity"
            );
        }
        ensure!(
            self.events
                .windows(2)
                .all(|pair| pair[0].sequence < pair[1].sequence),
            "notification membership is not in journal order"
        );
        encoded(self)
    }

    /// Decodes an exact bounded callback body and verifies immutable membership.
    ///
    /// # Errors
    /// Returns an error for unknown fields, invalid membership or envelope limits.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let value: Self = decode(bytes, "notification body")?;
        value.to_bytes()?;
        Ok(value)
    }

    /// Returns the semantic commitment used by the durable outbox and work plan.
    ///
    /// # Errors
    /// Returns an error for invalid body content or exceeded envelope limits.
    pub fn digest(&self) -> Result<Sha256Digest> {
        self.to_bytes()?;
        Sha256Digest::of_canonical("aos.assessment-notification-body/v1", self)
    }
}
