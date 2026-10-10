//! Explicit destination reviews, selection thresholds and revision preconditions.

use anyhow::{Result, ensure};
use aos_assessment::time::Timestamp;
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use super::{NotificationEventKind, NotificationSummaryV1};
use crate::alerts::IssueFamily;
use crate::attention_selection::{AttentionSelectionContext, SeverityBand};
use crate::validation::{decode, encoded, sorted, text};

/// Separates uncertain attention from confirmed attention without changing findings.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NotificationThreshold {
    /// Includes retained uncertain issues and incomplete-coverage attention.
    AllAttention,
    /// Selects currently confirmed issues; operational events still remain visible.
    ConfirmedAttention,
}

/// Pins when an intent becomes due without permitting an unbounded digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum NotificationFrequency {
    /// Admits an independent delivery for each selected committed event.
    Immediate {},
    /// Groups at most fifty ordered events from a fixed time window.
    #[serde(rename_all = "camelCase")]
    Digest {
        /// Window duration from one minute through one day.
        window_seconds: u32,
    },
}

/// Records the complete independently reviewed notification selection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NotificationConfigurationV1 {
    /// Exact closed configuration discriminator.
    pub schema: String,
    /// Sorted selected committed event kinds, never a wildcard subscription.
    pub events: Vec<NotificationEventKind>,
    /// Sorted selected issue families for attention events.
    pub families: Vec<IssueFamily>,
    /// Explicit uncertainty threshold, independent of the canonical assessment.
    pub threshold: NotificationThreshold,
    /// Sorted exact subject coordinates; an empty list preserves resource-wide selection.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub package_coordinates: Vec<String>,
    /// Optional vulnerability-only base-score threshold with explicit unknown handling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<NotificationSeverityFilter>,
    /// Sorted issue-specific notification silences for this subscription only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suppressions: Vec<NotificationSuppression>,
    /// Immediate or bounded digest selection.
    pub frequency: NotificationFrequency,
    /// Registered destination identity; neither provider data nor packages supply a URL.
    pub destination_reference: String,
    /// Exact registered destination revision reviewed by the subscriber.
    pub destination_revision: u64,
    /// Digest of the registered destination and immutable signing-key reference.
    pub destination_digest: Sha256Digest,
    /// Exclusive review deadline, independently limited by authenticated authority.
    pub review_expires_at: Timestamp,
}

impl NotificationConfigurationV1 {
    /// Checks finite selectors, destination revision and frequency bounds.
    ///
    /// # Errors
    /// Returns an error for unsupported schema, duplicate selectors or invalid bounds.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == "aos.assessment-notification-configuration/v1",
            "invalid notification configuration schema"
        );
        ensure!(
            !self.events.is_empty() && self.events.len() <= 8,
            "notification requires bounded explicit events"
        );
        ensure!(
            !self.families.is_empty() && self.families.len() <= 4,
            "notification requires bounded explicit families"
        );
        sorted(&self.events, "notification event selection")?;
        sorted(&self.families, "notification family selection")?;
        ensure!(
            self.package_coordinates.len() <= 256,
            "excessive package selectors"
        );
        sorted(&self.package_coordinates, "notification package selectors")?;
        for coordinate in &self.package_coordinates {
            text(coordinate, 1024, "notification package selector")?;
        }
        ensure!(
            self.suppressions.len() <= 128,
            "excessive notification suppressions"
        );
        sorted(&self.suppressions, "notification suppressions")?;
        ensure!(
            !self
                .suppressions
                .windows(2)
                .any(|pair| pair[0].issue_key == pair[1].issue_key),
            "duplicate notification suppression issue"
        );
        for suppression in &self.suppressions {
            ensure!(
                suppression.until <= self.review_expires_at,
                "suppression exceeds its reviewed authority"
            );
        }
        text(
            &self.destination_reference,
            128,
            "registered notification destination",
        )?;
        ensure!(
            self.destination_revision > 0 && self.destination_revision <= 9_007_199_254_740_991,
            "invalid notification destination revision"
        );
        if let NotificationFrequency::Digest { window_seconds } = self.frequency {
            ensure!(
                (60..=86_400).contains(&window_seconds),
                "invalid notification digest window"
            );
        }
        encoded(self)?;
        Ok(())
    }

    /// Selects a compact event using the exact reviewed threshold and families.
    #[must_use]
    pub fn selects(
        &self,
        event: &NotificationSummaryV1,
        context: Option<&AttentionSelectionContext>,
    ) -> bool {
        self.events.binary_search(&event.kind).is_ok()
            && event
                .family
                .is_none_or(|family| self.families.binary_search(&family).is_ok())
            && (self.threshold == NotificationThreshold::AllAttention || !event.uncertain)
            && (self.package_coordinates.is_empty()
                || context.is_some_and(|context| {
                    self.package_coordinates
                        .binary_search(&context.package_coordinate)
                        .is_ok()
                }))
            && self.severity.as_ref().is_none_or(|filter| {
                event.family == Some(IssueFamily::Vulnerability)
                    && match context {
                        Some(context) => {
                            context
                                .severity_bands
                                .iter()
                                .any(|band| *band >= filter.minimum)
                                || (filter.include_unknown && context.unknown_severity)
                        }
                        None => filter.include_unknown,
                    }
            })
            && !self.suppressions.iter().any(|silence| {
                event.issue_key == Some(silence.issue_key) && event.occurred_at < silence.until
            })
    }
}

/// Selects any supported source score meeting the threshold, preserving disagreement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NotificationSeverityFilter {
    /// Minimum FIRST CVSS v3/v4 base-score band.
    pub minimum: SeverityBand,
    /// Whether missing, unsupported or malformed severity also selects the event.
    pub include_unknown: bool,
}

/// Silences one stable issue for one reviewed recipient without altering findings.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NotificationSuppression {
    /// Exact stable issue key, including its immutable artifact/component scope.
    pub issue_key: Sha256Digest,
    /// Exclusive expiry evaluated against the committed event time.
    pub until: Timestamp,
}

/// Creates or replaces a complete subscription using an exact revision precondition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SubscriptionWriteV1 {
    /// Exact request discriminator.
    pub schema: String,
    /// Exact non-reusable registry incarnation authorized independently by the service.
    pub resource_scope: String,
    /// Caller-chosen subscription identity scoped to the resource.
    pub subscription_id: String,
    /// Zero creates; a positive current revision replaces the complete review.
    pub expected_revision: u64,
    /// Whether new committed events may create delivery intents.
    pub enabled: bool,
    /// Complete reviewed selectors and destination commitment.
    pub configuration: NotificationConfigurationV1,
}

impl SubscriptionWriteV1 {
    /// Decodes a closed bounded request without accepting principal provenance.
    ///
    /// # Errors
    /// Returns an error for unknown fields, invalid scope or invalid configuration.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let value: Self = decode(bytes, "assessment subscription write")?;
        value.validate()?;
        Ok(value)
    }

    /// Checks scope, identity and portable revision bounds.
    ///
    /// # Errors
    /// Returns an error for unsupported schema, exhausted revision or invalid selectors.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == "aos.assessment-subscription-write/v1"
                && self.expected_revision < 9_007_199_254_740_991,
            "invalid assessment subscription write"
        );
        text(&self.resource_scope, 128, "subscription resource")?;
        text(&self.subscription_id, 128, "subscription identity")?;
        self.configuration.validate()
    }
}

/// Exposes a reviewed subscription without private authentication provenance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SubscriptionV1 {
    /// Exact response discriminator.
    pub schema: String,
    /// Authorized non-reusable registry incarnation.
    pub resource_scope: String,
    /// Public identity scoped to that registry.
    pub subscription_id: String,
    /// Current complete review revision.
    pub revision: u64,
    /// Whether the subscription creates new delivery intents.
    pub enabled: bool,
    /// Exclusive effective authority deadline.
    pub authority_expires_at: Timestamp,
    /// Exact independently reviewed configuration.
    pub configuration: NotificationConfigurationV1,
}

impl SubscriptionV1 {
    /// Encodes a bounded public projection with no actor claims or signing material.
    ///
    /// # Errors
    /// Returns an error for malformed scope, revision or inconsistent authority expiry.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        ensure!(
            self.schema == "aos.assessment-subscription/v1"
                && self.revision > 0
                && self.revision <= 9_007_199_254_740_991,
            "invalid assessment subscription projection"
        );
        text(&self.resource_scope, 128, "subscription resource")?;
        text(&self.subscription_id, 128, "subscription identity")?;
        self.configuration.validate()?;
        ensure!(
            self.authority_expires_at <= self.configuration.review_expires_at,
            "subscription authority exceeds reviewed deadline"
        );
        encoded(self)
    }

    /// Decodes the same closed projection consumed by API, CLI and web clients.
    ///
    /// # Errors
    /// Returns an error for unknown fields or inconsistent projection content.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let value: Self = decode(bytes, "assessment subscription")?;
        value.to_bytes()?;
        Ok(value)
    }
}
