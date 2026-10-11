//! Reviewed selector compatibility, immutable facts and timed recipient silences.

use super::*;
use crate::alerts::{AttentionState, IssueFamily};
use crate::attention_selection::{AttentionSelectionContext, SeverityBand};
use aos_assessment::time::Timestamp;
use aos_contract::Sha256Digest;

fn at(seconds: u64) -> Timestamp {
    Timestamp::from_unix_seconds(seconds).unwrap()
}

fn fixture() -> (
    NotificationConfigurationV1,
    NotificationSummaryV1,
    AttentionSelectionContext,
) {
    (
        NotificationConfigurationV1 {
            schema: "aos.assessment-notification-configuration/v1".into(),
            events: vec![NotificationEventKind::AlertOpened],
            families: vec![IssueFamily::Vulnerability],
            threshold: NotificationThreshold::AllAttention,
            package_coordinates: vec!["publisher/package".into()],
            severity: Some(NotificationSeverityFilter {
                minimum: SeverityBand::High,
                include_unknown: false,
            }),
            suppressions: Vec::new(),
            frequency: NotificationFrequency::Immediate {},
            destination_reference: "webhook:42".into(),
            destination_revision: 1,
            destination_digest: Sha256Digest::of_bytes(b"destination"),
            review_expires_at: at(2000),
        },
        NotificationSummaryV1 {
            event_id: "event".into(),
            sequence: 1,
            occurred_at: at(1000),
            kind: NotificationEventKind::AlertOpened,
            family: Some(IssueFamily::Vulnerability),
            issue_key: Some(Sha256Digest::of_bytes(b"issue")),
            context_digest: Some(Sha256Digest::of_bytes(b"context")),
            episode: Some(1),
            state: Some(AttentionState::Open),
            uncertain: false,
            assessment_digest: Some(Sha256Digest::of_bytes(b"assessment")),
        },
        AttentionSelectionContext {
            package_coordinate: "publisher/package".into(),
            severity_bands: vec![SeverityBand::Low, SeverityBand::Critical],
            unknown_severity: false,
        },
    )
}

#[test]
fn selectors_require_exact_coordinate_and_any_matching_source_band() {
    let (configuration, event, mut context) = fixture();
    configuration.validate().unwrap();
    event.validate().unwrap();
    assert!(configuration.selects(&event, Some(&context)));
    context.package_coordinate = "another-publisher/package".into();
    assert!(!configuration.selects(&event, Some(&context)));
    context.package_coordinate = "publisher/package".into();
    context.severity_bands = vec![SeverityBand::Low];
    assert!(!configuration.selects(&event, Some(&context)));
    assert!(!configuration.selects(&event, None));
}

#[test]
fn unknown_selection_is_explicit_including_legacy_alerts() {
    let (mut configuration, mut event, mut context) = fixture();
    configuration.package_coordinates.clear();
    context.severity_bands.clear();
    context.unknown_severity = true;
    assert!(!configuration.selects(&event, Some(&context)));
    configuration.severity.as_mut().unwrap().include_unknown = true;
    assert!(configuration.selects(&event, Some(&context)));
    assert!(configuration.selects(&event, None));
    event.family = Some(IssueFamily::Coverage);
    configuration.families = vec![IssueFamily::Coverage];
    assert!(!configuration.selects(&event, Some(&context)));
}

#[test]
fn suppression_is_exact_recipient_policy_with_exclusive_expiry() {
    let (mut configuration, mut event, context) = fixture();
    configuration.suppressions.push(NotificationSuppression {
        issue_key: event.issue_key.unwrap(),
        until: at(1100),
    });
    configuration.validate().unwrap();
    let original = serde_json::to_vec(&event).unwrap();
    assert!(!configuration.selects(&event, Some(&context)));
    assert_eq!(serde_json::to_vec(&event).unwrap(), original);
    event.issue_key = Some(Sha256Digest::of_bytes(b"another-artifact"));
    assert!(configuration.selects(&event, Some(&context)));
    event.issue_key = Some(configuration.suppressions[0].issue_key);
    event.occurred_at = at(1100);
    assert!(configuration.selects(&event, Some(&context)));
    configuration.suppressions[0].until = at(2001);
    assert!(configuration.validate().is_err());
}

#[test]
fn old_documents_preserve_canonical_bytes_and_new_filters_bind_review_digest() {
    let (mut configuration, _, _) = fixture();
    configuration.package_coordinates.clear();
    configuration.severity = None;
    let legacy = serde_json::to_value(&configuration).unwrap();
    for absent in ["packageCoordinates", "severity", "suppressions"] {
        assert!(legacy.get(absent).is_none());
    }
    let decoded: NotificationConfigurationV1 = serde_json::from_value(legacy.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), legacy);
    let digest = Sha256Digest::of_canonical("review", &configuration).unwrap();
    configuration
        .package_coordinates
        .push("publisher/package".into());
    assert_ne!(
        Sha256Digest::of_canonical("review", &configuration).unwrap(),
        digest
    );
    configuration
        .package_coordinates
        .push("publisher/package".into());
    assert!(configuration.validate().is_err());
}

#[test]
fn complete_review_rejects_unknown_nested_selector_and_frequency_fields() {
    let (configuration, _, _) = fixture();
    for field in ["severity", "frequency"] {
        let mut value = serde_json::to_value(&configuration).unwrap();
        value[field]["unreviewedSelector"] = serde_json::json!("ignore");
        assert!(serde_json::from_value::<NotificationConfigurationV1>(value).is_err());
    }
}
