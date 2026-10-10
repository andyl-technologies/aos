//! Adversarial authentication, disclosure and retry qualification.

use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::Result;
use aos_assessment::time::Timestamp;
use aos_contract::Sha256Digest;

use super::*;
use crate::alerts::{
    Acknowledgement, AlertTransitionKind, AssessmentAlertV1, AttentionState, IssueFamily,
    IssueObservation,
};
use crate::events::{AssessmentEventPayload, AssessmentEventV1};
use crate::ports::Clock;

fn time(seconds: u64) -> Timestamp {
    Timestamp::from_unix_seconds(seconds).unwrap()
}

fn fixture() -> (NotificationDestinationV1, NotificationWorkPlanV1) {
    let destination = NotificationDestinationV1 {
        schema: "aos.assessment-notification-destination/v1".into(),
        destination_reference: "webhook-42".into(),
        revision: 3,
        resource_scope: "registry-incarnation".into(),
        url: "https://receiver.example/callback".into(),
        secret_version_reference: "webhook-secret-version-3".into(),
        credential_fingerprint: Sha256Digest::of_bytes(&[7; 32]),
        expires_at: time(2000),
    };
    let event = AssessmentEventV1 {
        schema: "aos.assessment-event/v1".into(),
        event_id: "event-1".into(),
        sequence: 1,
        occurred_at: time(900),
        payload: AssessmentEventPayload::ScanCompleted {
            scan_id: "scan-1".into(),
            assessment_digest: Sha256Digest::of_bytes(b"assessment"),
        },
    };
    let body = NotificationBodyV1 {
        schema: "aos.assessment-notification-body/v1".into(),
        delivery_id: "delivery-1".into(),
        resource_scope: destination.resource_scope.clone(),
        subscription_id: "subscription-1".into(),
        subscription_revision: 2,
        events: vec![NotificationSummaryV1::from_event(&event).unwrap()],
    };
    let plan = NotificationWorkPlanV1 {
        schema: "aos.assessment-notification-work/v1".into(),
        deployment_id: "deployment".into(),
        issuer: "coordinator".into(),
        audience: "executor".into(),
        claim_token: "claim-1".into(),
        attempt: 1,
        reservation_digest: Sha256Digest::of_bytes(b"reservation"),
        destination_reference: destination.destination_reference.clone(),
        destination_digest: destination.digest().unwrap(),
        body_digest: body.digest().unwrap(),
        body,
        issued_at: time(1000),
        deadline: time(1060),
    };
    (destination, plan)
}

#[test]
fn registered_destinations_refuse_private_literals_userinfo_and_unbounded_scope() {
    let (destination, _) = fixture();
    for url in [
        "https://127.0.0.1/callback",
        "https://[::1]/callback",
        "https://169.254.169.254/callback",
        "https://[::ffff:127.0.0.1]/callback",
        "https://localhost/callback",
        "https://host.internal/callback",
        "https://token@receiver.example/callback",
        "http://receiver.example/callback",
        "https://receiver.example/callback#fragment",
    ] {
        let mut invalid = destination.clone();
        invalid.url = url.into();
        assert!(invalid.validate().is_err(), "accepted {url}");
    }
    let mut public = destination;
    public.url = "https://8.8.8.8/callback".into();
    assert!(public.validate().is_ok());
}

#[test]
fn notification_queries_require_original_scope_and_reject_unknown_filters() {
    let query = SubscriptionQueryV1 {
        schema: "aos.assessment-subscription-query/v1".into(),
        resource_scope: None,
        subscription_id: None,
        after_subscription: Some("cursor".into()),
        limit: 10,
    };
    assert!(query.validate().is_err());
    let mut query = query;
    query.resource_scope = Some("registry".into());
    query.validate().unwrap();
    query.subscription_id = Some("identity".into());
    assert!(query.validate().is_err());
    let (_, plan) = fixture();
    let value = serde_json::json!({"schema":"aos.assessment-notification-configuration/v1", "events":["scan-completed"], "families":["vulnerability"], "threshold":"all-attention", "frequency":{"kind":"immediate"}, "destinationReference":"webhook:42", "destinationRevision":3, "destinationDigest":plan.destination_digest, "reviewExpiresAt":time(1500), "minimumSeverity":"critical"});
    assert!(serde_json::from_value::<NotificationConfigurationV1>(value).is_err());
}

#[test]
fn callbacks_bind_exact_body_key_version_and_fresh_attempt_timestamp() {
    let (destination, plan) = fixture();
    let body = plan.body.to_bytes().unwrap();
    let signature = CallbackSignature::sign(&destination, &plan, &body, &[7; 32]).unwrap();
    assert_eq!(
        signature
            .verify(
                &body,
                &destination.secret_version_reference,
                &[7; 32],
                &time(1001)
            )
            .unwrap(),
        plan.body
    );

    let mut altered = plan.body.clone();
    altered.resource_scope = "other-registry".into();
    assert!(
        signature
            .verify(
                &altered.to_bytes().unwrap(),
                &destination.secret_version_reference,
                &[7; 32],
                &time(1001)
            )
            .is_err()
    );
    assert!(
        signature
            .verify(&body, "rotated-key", &[7; 32], &time(1001))
            .is_err()
    );
    assert!(
        signature
            .verify(
                &body,
                &destination.secret_version_reference,
                &[8; 32],
                &time(1001)
            )
            .is_err()
    );
    assert!(
        signature
            .verify(
                &body,
                &destination.secret_version_reference,
                &[7; 32],
                &time(1301)
            )
            .is_err()
    );
    assert!(
        signature
            .verify(
                &body,
                &destination.secret_version_reference,
                &[7; 32],
                &time(969)
            )
            .is_err()
    );

    let mut retry = plan.clone();
    retry.attempt = 2;
    retry.claim_token = "claim-2".into();
    retry.issued_at = time(1100);
    retry.deadline = time(1160);
    assert_eq!(retry.body.to_bytes().unwrap(), body);
    let second = CallbackSignature::sign(&destination, &retry, &body, &[7; 32]).unwrap();
    assert_ne!(second.signature, signature.signature);
}

#[test]
fn work_authentication_rejects_receipt_reuse_cross_pairing_and_altered_bytes() {
    let (_, plan) = fixture();
    let auth = NotificationWorkAuth::new(
        vec![9; 32],
        "deployment".into(),
        "coordinator".into(),
        "executor".into(),
    )
    .unwrap();
    let (bytes, signature) = auth.sign_plan(&plan, &time(1000)).unwrap();
    assert_eq!(
        auth.verify_plan(&bytes, &signature, &time(1000)).unwrap(),
        plan
    );
    assert!(auth.verify_plan(&bytes, &signature, &time(1060)).is_err());
    let other = NotificationWorkAuth::new(
        vec![9; 32],
        "other-deployment".into(),
        "coordinator".into(),
        "executor".into(),
    )
    .unwrap();
    assert!(other.verify_plan(&bytes, &signature, &time(1000)).is_err());
    let mut altered = bytes.clone();
    altered.push(b' ');
    assert!(auth.verify_plan(&altered, &signature, &time(1000)).is_err());

    let receipt = NotificationWorkReceiptV1 {
        schema: "aos.assessment-notification-receipt/v1".into(),
        plan_digest: plan.digest().unwrap(),
        body_digest: plan.body_digest,
        claim_token: plan.claim_token.clone(),
        outcome: DeliveryOutcome::Accepted,
        status: Some(204),
        retry_after_seconds: None,
        completed_at: time(1001),
    };
    let (receipt_bytes, receipt_signature) =
        auth.sign_receipt(&receipt, &plan, &time(1001)).unwrap();
    assert!(
        auth.verify_receipt(&receipt_bytes, &receipt_signature, &plan, &time(1001))
            .is_ok()
    );
    assert!(
        auth.verify_plan(&receipt_bytes, &receipt_signature, &time(1001))
            .is_err()
    );
    assert!(
        auth.verify_receipt(&bytes, &signature, &plan, &time(1001))
            .is_err()
    );
}

#[test]
fn attention_disclosure_omits_acknowledgement_notes_provider_ids_and_source_locations() {
    let (_, mut plan) = fixture();
    let issue_key = Sha256Digest::of_bytes(b"issue");
    let event = AssessmentEventV1 {
        schema: "aos.assessment-event/v1".into(),
        event_id: "attention-event".into(),
        sequence: 2,
        occurred_at: time(901),
        payload: AssessmentEventPayload::Alert {
            transition: AlertTransitionKind::Opened,
            alert: Box::new(AssessmentAlertV1 {
                schema: "aos.assessment-alert/v1".into(),
                issue_key,
                issue: IssueObservation {
                    issue_key,
                    context_digest: Sha256Digest::of_bytes(b"private-component"),
                    family: IssueFamily::Vulnerability,
                    profile: aos_assessment::input::Profile::Vulnerabilities,
                    lineage_ids: vec!["private-upstream-identity".into()],
                    source_keys: vec![Sha256Digest::of_bytes(b"https://private-source.example")],
                    material_digest: Sha256Digest::of_bytes(b"material"),
                    uncertain: true,
                },
                state: AttentionState::Open,
                episode: 1,
                sequence: 1,
                assessment_digest: Sha256Digest::of_bytes(b"assessment"),
                updated_at: time(901),
                acknowledgements: vec![Acknowledgement {
                    idempotency_key: None,
                    issue_key,
                    episode: 1,
                    actor_ref: "private-principal".into(),
                    acknowledged_at: time(901),
                    reason: Some("private-customer-note".into()),
                }],
                lineage_keys: Vec::new(),
            }),
        },
    };
    let summary = NotificationSummaryV1::from_event(&event).unwrap();
    assert!(summary.uncertain);
    plan.body.events.push(summary.clone());
    let disclosed = String::from_utf8(plan.body.to_bytes().unwrap()).unwrap();
    for private in [
        "private-upstream-identity",
        "private-principal",
        "private-customer-note",
        "https://private-source.example",
    ] {
        assert!(!disclosed.contains(private));
    }
    let configuration = NotificationConfigurationV1 {
        schema: "aos.assessment-notification-configuration/v1".into(),
        events: vec![NotificationEventKind::AlertOpened],
        families: vec![IssueFamily::Vulnerability],
        threshold: NotificationThreshold::ConfirmedAttention,
        frequency: NotificationFrequency::Immediate,
        destination_reference: "webhook-42".into(),
        destination_revision: 3,
        destination_digest: plan.destination_digest,
        review_expires_at: time(1500),
    };
    configuration.validate().unwrap();
    assert!(!configuration.selects(&summary));
    let mut includes_uncertainty = configuration;
    includes_uncertainty.threshold = NotificationThreshold::AllAttention;
    assert!(includes_uncertainty.selects(&summary));
}

#[test]
fn digest_membership_is_finite_ordered_unique_and_committed() {
    let (_, plan) = fixture();
    let original = plan.body.digest().unwrap();
    let mut body = plan.body.clone();
    body.events.push(body.events[0].clone());
    assert!(body.to_bytes().is_err());
    body.events[1].event_id = "new-event".into();
    assert!(body.to_bytes().is_err());
    body.events[1].sequence = 2;
    assert_ne!(body.digest().unwrap(), original);
    body.events[1].occurred_at = time(899);
    // Database clock corrections cannot reorder the journal or prevent delivery.
    assert!(body.to_bytes().is_ok());
    let mut unknown = serde_json::to_value(&plan.body).unwrap();
    unknown["sourceUrl"] = serde_json::json!("https://private.example");
    assert!(NotificationBodyV1::from_slice(&serde_json::to_vec(&unknown).unwrap()).is_err());
}

struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> Result<Timestamp> {
        Ok(time(1000))
    }
}

struct RecordingTransport {
    calls: AtomicUsize,
    status: Option<u16>,
}

#[async_trait::async_trait]
impl NotificationTransport for RecordingTransport {
    async fn sign_callback(
        &self,
        destination: &NotificationDestinationV1,
        plan: &NotificationWorkPlanV1,
        body: &[u8],
    ) -> Result<CallbackSignature> {
        CallbackSignature::sign(destination, plan, body, &[7; 32])
    }

    async fn post(
        &self,
        _: &NotificationDestinationV1,
        _: &NotificationWorkPlanV1,
        _: &[u8],
        _: &CallbackSignature,
    ) -> Result<(Option<u16>, Option<u32>)> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok((self.status, Some(86_400)))
    }
}

#[tokio::test]
async fn expired_or_changed_grants_cannot_disclose_and_retry_classes_are_conservative() {
    let (mut destination, plan) = fixture();
    let transport = RecordingTransport {
        calls: AtomicUsize::new(0),
        status: Some(204),
    };
    destination.resource_scope = "unrelated-registry".into();
    assert!(
        execute_notification(&transport, &FixedClock, &destination, &plan)
            .await
            .is_err()
    );
    assert_eq!(transport.calls.load(Ordering::SeqCst), 0);

    let (destination, plan) = fixture();
    for (status, outcome) in [
        (Some(204), DeliveryOutcome::Accepted),
        (Some(302), DeliveryOutcome::PermanentFailure),
        (Some(401), DeliveryOutcome::PermanentFailure),
        (Some(429), DeliveryOutcome::Retryable),
        (Some(503), DeliveryOutcome::Retryable),
        (None, DeliveryOutcome::Retryable),
    ] {
        let transport = RecordingTransport {
            calls: AtomicUsize::new(0),
            status,
        };
        let receipt = execute_notification(&transport, &FixedClock, &destination, &plan)
            .await
            .unwrap();
        assert_eq!(receipt.outcome, outcome);
        assert_eq!(
            receipt.retry_after_seconds,
            (outcome == DeliveryOutcome::Retryable).then_some(3600)
        );
        assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn retries_preserve_server_minimum_bounded_jitter_and_attempt_limits() {
    for attempt in 1..=20 {
        let delay = retry_delay("delivery", attempt, None).unwrap();
        assert!((20..=3600).contains(&delay));
        assert_eq!(delay, retry_delay("delivery", attempt, None).unwrap());
        assert!(retry_delay("delivery", attempt, Some(3000)).unwrap() >= 3000);
    }
    assert!(retry_delay("delivery", 0, None).is_err());
    assert!(retry_delay("delivery", 21, None).is_err());
    assert!(retry_delay("delivery", 1, Some(3601)).is_err());
}

#[test]
fn installed_notifications_require_exact_independent_quotas_and_sorted_destinations() {
    let (destination, _) = fixture();
    let installation = NotificationInstallationV1 {
        schema: "aos.assessment-notification-installation/v1".into(),
        deployment_id: "deployment".into(),
        coordinator_id: "coordinator".into(),
        executor_id: "executor".into(),
        destinations: vec![InstalledNotificationDestination {
            destination,
            budget_key: "notification:account".into(),
        }],
        budgets: vec![crate::routes::InstalledSourceBudget {
            key: "notification:account".into(),
            window_seconds: 60,
            allowance: 10,
            min_interval_seconds: 1,
        }],
    };
    installation.validate().unwrap();
    let bytes = aos_contract::canonical::to_vec(&installation).unwrap();
    assert_eq!(
        NotificationInstallationV1::from_slice(&bytes).unwrap(),
        installation
    );

    let mut source_quota = installation.clone();
    source_quota.destinations[0].budget_key = "osv:account".into();
    source_quota.budgets[0].key = "osv:account".into();
    assert!(source_quota.validate().is_err());
    let mut unused = installation.clone();
    unused.budgets[0].key = "notification:other".into();
    assert!(unused.validate().is_err());
    let mut duplicate = installation.clone();
    duplicate
        .destinations
        .push(duplicate.destinations[0].clone());
    assert!(duplicate.validate().is_err());
    let mut oversized = installation;
    oversized.budgets[0].allowance = 1_000_001;
    assert!(oversized.validate().is_err());
}

#[test]
fn worker_notification_keys_require_exact_versions_and_separate_unique_bindings() {
    let (destination, _) = fixture();
    let version = destination.secret_version_reference.clone();
    let mut installation = WorkerNotificationInstallationV1 {
        schema: "aos.assessment-worker-notification-installation/v1".into(),
        egress_gateway_url: "https://egress.fixture.invalid/v1/fetch".into(),
        installation: NotificationInstallationV1 {
            schema: "aos.assessment-notification-installation/v1".into(),
            deployment_id: "deployment".into(),
            coordinator_id: "coordinator".into(),
            executor_id: "executor".into(),
            destinations: vec![InstalledNotificationDestination {
                destination,
                budget_key: "notification:account".into(),
            }],
            budgets: vec![crate::routes::InstalledSourceBudget {
                key: "notification:account".into(),
                window_seconds: 60,
                allowance: 10,
                min_interval_seconds: 0,
            }],
        },
        secret_bindings: vec![NotificationSecretBinding {
            version_reference: version,
            binding: "ASSESSMENT_NOTIFICATION_CALLBACK_V3".into(),
        }],
    };
    installation.validate().unwrap();
    let bytes = aos_contract::canonical::to_vec(&installation).unwrap();
    assert_eq!(
        WorkerNotificationInstallationV1::from_slice(&bytes).unwrap(),
        installation
    );

    installation.secret_bindings[0].binding = "ASSESSMENT_GITHUB_TOKEN".into();
    assert!(installation.validate().is_err());
    installation.secret_bindings[0].binding = "ASSESSMENT_NOTIFICATION_CALLBACK_V3".into();
    installation.secret_bindings[0].version_reference = "other-version".into();
    assert!(installation.validate().is_err());
}

#[test]
fn fresh_effect_grants_bind_the_exact_challenge_and_cannot_extend_dispatch_authority() {
    let (_, plan) = fixture();
    let query = NotificationEffectQueryV1 {
        schema: "aos.assessment-notification-effect-query/v1".into(),
        deployment_id: plan.deployment_id.clone(),
        issuer: plan.issuer.clone(),
        audience: plan.audience.clone(),
        resource_scope: plan.body.resource_scope.clone(),
        plan_digest: plan.digest().unwrap(),
        claim_token: plan.claim_token.clone(),
        nonce: "0123456789abcdef0123456789abcdef".into(),
        issued_at: time(1001),
    };
    let auth = NotificationWorkAuth::new(
        vec![11; 32],
        plan.deployment_id.clone(),
        plan.issuer.clone(),
        plan.audience.clone(),
    )
    .unwrap();
    let (query_bytes, query_signature) = auth.sign_effect_query(&query, &time(1001)).unwrap();
    assert_eq!(
        auth.verify_effect_query(&query_bytes, &query_signature, &time(1002))
            .unwrap(),
        query
    );
    assert!(
        auth.verify_plan(&query_bytes, &query_signature, &time(1002))
            .is_err()
    );
    assert!(
        auth.verify_effect_query(&query_bytes, &query_signature, &time(1006))
            .is_err()
    );

    let grant = NotificationEffectGrantV1::from_current_check(&query, &plan, time(1002)).unwrap();
    let (bytes, signature) = auth
        .sign_effect_grant(&grant, &query, &plan, &time(1002))
        .unwrap();
    assert_eq!(
        auth.verify_effect_grant(&bytes, &signature, &query, &plan, &time(1006))
            .unwrap(),
        grant
    );
    assert!(
        auth.verify_effect_grant(&bytes, &signature, &query, &plan, &time(1007))
            .is_err()
    );
    let mut different = query.clone();
    different.nonce = "abcdef0123456789abcdef0123456789".into();
    assert!(
        auth.verify_effect_grant(&bytes, &signature, &different, &plan, &time(1003))
            .is_err()
    );
    let mut extended = grant;
    extended.dispatch_by = time(1008);
    assert!(
        auth.sign_effect_grant(&extended, &query, &plan, &time(1003))
            .is_err()
    );
    let mut late_query = query;
    late_query.issued_at = time(1040);
    assert!(NotificationEffectGrantV1::from_current_check(&late_query, &plan, time(1040)).is_err());
}
