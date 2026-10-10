//! Reviewed subscriptions and atomic compact outbox intent admission.
//!
//! The event allocator serializes subscription replacements with assessment
//! commits. A review stores authenticated provenance privately and binds an exact
//! registered webhook revision. Its outbox contains only immutable compact body
//! references; dispatch authority is checked independently for every attempt.

use anyhow::{ensure, Context as _, Result};
use aos_assessment::time::Timestamp;
use aos_assessment_runtime::events::{AssessmentEventPayload, AssessmentEventV1};
use aos_assessment_runtime::notifications::{
    NotificationBodyV1, NotificationConfigurationV1, NotificationDestinationV1,
    NotificationFrequency, NotificationSummaryV1, SubscriptionV1, SubscriptionWriteV1,
};
use aos_contract::{canonical, limits::JsonLimits, Sha256Digest};
use serde::{Deserialize, Serialize};

use super::AssessmentObjectKind;
use crate::auth::jwt::{Claims, AUTHORIZATION_CLAIMS_VERSION};
use crate::backend::{CheckedStatement, Statement};
use crate::db::Database;

const LIMITS: JsonLimits = JsonLimits {
    max_bytes: 262_144,
    max_depth: 16,
    max_items: 16_384,
    max_string_bytes: 4096,
};
const MAX_SUBSCRIPTIONS: usize = 64;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct PrivateReview {
    pub(super) subscription_id: String,
    pub(super) configuration: NotificationConfigurationV1,
    pub(super) claims: Claims,
    pub(super) authority_expires_at: Timestamp,
}

pub(super) struct SubscriptionRecord {
    pub(super) key: String,
    pub(super) revision: u64,
    pub(super) enabled: bool,
    pub(super) review: PrivateReview,
}

impl Database {
    /// Creates or replaces an exact registered-destination review under current IAM fences.
    ///
    /// Replacement revokes all old pending/leased deliveries in the same transaction.
    /// Original authenticated expiry cannot be extended by replaying a write.
    ///
    /// # Errors
    /// Returns an error for stale revision, wrong registry/destination ownership,
    /// expired authority, exhausted subscription capacity or failed current IAM guards.
    pub async fn write_assessment_subscription_fenced(
        &self,
        registry_id: i64,
        request: &SubscriptionWriteV1,
        claims: &Claims,
        fences: &[CheckedStatement],
    ) -> Result<SubscriptionV1> {
        self.write_assessment_subscription_with_plan_fenced(
            registry_id,
            request,
            claims,
            fences,
            None,
        )
        .await
    }

    /// Commits configuration and an optional immutable plan receipt atomically.
    ///
    /// # Errors
    /// Returns an error for stale configuration, authority or plan fences.
    pub(crate) async fn write_assessment_subscription_with_plan_fenced(
        &self,
        registry_id: i64,
        request: &SubscriptionWriteV1,
        claims: &Claims,
        fences: &[CheckedStatement],
        completion: Option<&super::reviews::AssessmentReviewCompletion>,
    ) -> Result<SubscriptionV1> {
        request.validate()?;
        if let Some(completion) = completion {
            completion.require_kind("assessment_subscription_review")?;
        }
        ensure!(
            !fences.is_empty()
                && fences.len() <= 32
                && claims.authz_version == AUTHORIZATION_CLAIMS_VERSION,
            "notification review requires current authenticated authority"
        );
        let registry = self
            .registry_by_id(registry_id)
            .await?
            .context("subscription registry is absent")?;
        ensure!(
            registry.scope_key == request.resource_scope,
            "subscription resource incarnation changed"
        );
        let key = subscription_key(&request.resource_scope, &request.subscription_id)?;
        let now = self.assessment_database_time().await?;
        let expires = Timestamp::from_unix_seconds(u64::try_from(claims.exp)?)?
            .min(request.configuration.review_expires_at.clone());
        ensure!(
            !request.enabled || expires > now,
            "enabled notification review is expired"
        );
        let existing = self.subscription_record(registry_id, &key).await?;
        // Revoking an unchanged review must remain possible after the destination
        // has been disabled, rotated or deleted. It grants no new delivery scope.
        let revoke_only = !request.enabled
            && existing
                .as_ref()
                .is_some_and(|record| record.review.configuration == request.configuration);
        let destination = if revoke_only {
            None
        } else {
            let destination = self
                .assessment_notification_destination(
                    registry_id,
                    &request.configuration.destination_reference,
                    &request.configuration.review_expires_at,
                )
                .await?;
            ensure!(
                destination.revision == request.configuration.destination_revision
                    && destination.digest()? == request.configuration.destination_digest,
                "registered notification destination changed since review"
            );
            Some(destination)
        };
        if let Some(existing) = &existing {
            if (request.expected_revision == 0
                || existing.revision == request.expected_revision + 1)
                && existing.enabled == request.enabled
                && existing.review.configuration == request.configuration
                && super::assessment_actor_ref(&existing.review.claims)?
                    == super::assessment_actor_ref(claims)?
            {
                let mut checked = fences.to_vec();
                checked.push(self.subscription_revision_guard(registry_id, existing, false));
                if let Some(destination) = &destination {
                    checked.push(self.notification_destination_guard(registry_id, destination)?);
                }
                let receipt = project(&registry.scope_key, existing)?;
                if let Some(completion) = completion {
                    checked.push(completion.statement(
                        receipt.to_bytes()?,
                        self.backend.dialect().unix_time_expression(),
                    )?);
                }
                self.backend.checked_batch(&checked).await?;
                return Ok(receipt);
            }
            ensure!(
                existing.revision == request.expected_revision,
                "subscription revision conflict"
            );
        } else {
            ensure!(
                request.expected_revision == 0,
                "subscription revision is absent"
            );
        }
        let review = PrivateReview {
            subscription_id: request.subscription_id.clone(),
            configuration: request.configuration.clone(),
            claims: claims.clone(),
            authority_expires_at: expires,
        };
        let bytes = canonical::to_vec(&review)?;
        LIMITS.decode::<PrivateReview>(&bytes, "private notification review")?;
        let clock = self.backend.dialect().unix_time_expression();
        let mut checked = fences.to_vec();
        checked.push(
            Statement::new(
                "UPDATE registries SET scope_key = scope_key WHERE id = ?1 AND scope_key = ?2",
                vals![registry_id, registry.scope_key],
            )
            .expecting(1),
        );
        if let Some(destination) = &destination {
            checked.push(self.notification_destination_guard(registry_id, destination)?);
        }
        // Every subscription write also allocates an event. Its CAS serializes
        // fanout snapshots, capacity checks and replacement revocation with scans.
        checked.extend(
            self.assessment_event_statements(
                registry_id,
                vec![AssessmentEventPayload::SubscriptionChanged {
                    subscription_id: request.subscription_id.clone(),
                    revision: request.expected_revision + 1,
                    enabled: request.enabled,
                }],
                &now,
            )
            .await?,
        );
        if existing.is_none() {
            let destination = destination
                .as_ref()
                .context("new subscription requires a reviewed destination")?;
            ensure!(
                self.subscription_records(registry_id).await?.len() < MAX_SUBSCRIPTIONS,
                "assessment subscription capacity is exhausted"
            );
            checked.push(Statement::new(format!("INSERT INTO assessment_subscriptions(subscription_id, registry_id, configuration_json, destination_reference, secret_version_reference, enabled, resource_version, created_at, updated_at)
                VALUES(?1, ?2, ?3, ?4, ?5, ?6, 1, {clock}, {clock})"), vals![key, registry_id, bytes, destination.destination_reference, destination.secret_version_reference, i64::from(request.enabled)]).expecting(1));
        } else {
            checked.push(Statement::new(format!("UPDATE assessment_subscriptions SET configuration_json = ?3, destination_reference = ?4, secret_version_reference = COALESCE(?5, secret_version_reference), enabled = ?6, resource_version = resource_version + 1, updated_at = {clock}
                WHERE subscription_id = ?1 AND registry_id = ?2 AND resource_version = ?7"), vals![key, registry_id, bytes, request.configuration.destination_reference, destination.as_ref().map(|destination| destination.secret_version_reference.clone()), i64::from(request.enabled), request.expected_revision]).expecting(1));
            checked.push(Statement::new(format!("UPDATE assessment_notification_outbox SET state = 'revoked', claim_token = NULL, lease_expires_at = NULL, last_error_code = 'subscription-review-replaced', resource_version = resource_version + 1, updated_at = {clock}
                WHERE registry_id = ?1 AND subscription_id = ?2 AND subscription_revision = ?3 AND state IN('pending', 'leased')"), vals![registry_id, key, request.expected_revision]).unchecked());
        }
        let receipt = SubscriptionV1 {
            schema: "aos.assessment-subscription/v1".into(),
            resource_scope: registry.scope_key,
            subscription_id: request.subscription_id.clone(),
            revision: request
                .expected_revision
                .checked_add(1)
                .context("subscription revision exhausted")?,
            enabled: request.enabled,
            authority_expires_at: review.authority_expires_at.clone(),
            configuration: request.configuration.clone(),
        };
        receipt.to_bytes()?;
        if let Some(completion) = completion {
            checked.push(completion.statement(receipt.to_bytes()?, clock)?);
        }
        self.backend.checked_batch(&checked).await?;
        Ok(receipt)
    }

    /// Reads an exact public subscription without private authenticated provenance.
    ///
    /// # Errors
    /// Returns an error for malformed identity, missing registry or corrupt retained review.
    pub async fn assessment_subscription(
        &self,
        registry_id: i64,
        subscription_id: &str,
    ) -> Result<Option<SubscriptionV1>> {
        let registry = self
            .registry_by_id(registry_id)
            .await?
            .context("subscription registry is absent")?;
        let key = subscription_key(&registry.scope_key, subscription_id)?;
        self.subscription_record(registry_id, &key)
            .await?
            .map(|record| project(&registry.scope_key, &record))
            .transpose()
    }

    /// Reads a bounded sorted public page using public subscription identities as cursors.
    ///
    /// # Errors
    /// Returns an error for invalid page bounds, resource state or retained reviews.
    pub async fn assessment_subscription_page(
        &self,
        registry_id: i64,
        after: &str,
        limit: u32,
    ) -> Result<Vec<SubscriptionV1>> {
        ensure!(
            (1..=10).contains(&limit) && after.len() <= 128 && !after.chars().any(char::is_control),
            "invalid assessment subscription page"
        );
        let registry = self
            .registry_by_id(registry_id)
            .await?
            .context("subscription registry is absent")?;
        let mut records = self.subscription_records(registry_id).await?;
        records.sort_by(|left, right| {
            left.review
                .subscription_id
                .cmp(&right.review.subscription_id)
        });
        records
            .into_iter()
            .filter(|record| record.review.subscription_id.as_str() > after)
            .take(limit as usize)
            .map(|record| project(&registry.scope_key, &record))
            .collect()
    }

    /// Projects the exact registered webhook commitment for an independent subscription review.
    ///
    /// Callers must separately authorize destination review; this method grants no
    /// webhook-management or subscription-management permission.
    ///
    /// # Errors
    /// Returns an error for inactive/cross-organization destinations or malformed immutable keys.
    pub async fn assessment_notification_destination(
        &self,
        registry_id: i64,
        reference: &str,
        expires_at: &Timestamp,
    ) -> Result<NotificationDestinationV1> {
        let id = webhook_id(reference)?;
        let registry = self
            .registry_by_id(registry_id)
            .await?
            .context("notification registry is absent")?;
        let webhook = self
            .webhook(id)
            .await?
            .context("registered notification destination is absent")?;
        ensure!(
            webhook.active && registry.org_id == Some(webhook.org_id),
            "notification destination is inactive or belongs to another organization"
        );
        let destination = NotificationDestinationV1 {
            schema: "aos.assessment-notification-destination/v1".into(),
            destination_reference: reference.into(),
            revision: u64::try_from(webhook.resource_version)?,
            resource_scope: registry.scope_key,
            url: webhook.url,
            secret_version_reference: webhook.secret_version_ref,
            credential_fingerprint: Sha256Digest::parse(&format!(
                "sha256:{}",
                webhook.credential_fingerprint
            ))?,
            expires_at: expires_at.clone(),
        };
        destination.validate()?;
        Ok(destination)
    }

    pub(super) async fn assessment_notification_intent_statements(
        &self,
        registry_id: i64,
        event: &AssessmentEventV1,
    ) -> Result<Vec<CheckedStatement>> {
        // Delivery failures cannot recurse. Physical source attempts acquire
        // callback visibility through grouped source-health attention instead.
        if matches!(
            event.payload,
            AssessmentEventPayload::DeliveryFailed { .. }
                | AssessmentEventPayload::SourceFailed { .. }
        ) {
            return Ok(Vec::new());
        }
        let subscriptions = self.subscription_records(registry_id).await?;
        if subscriptions.is_empty() {
            return Ok(Vec::new());
        }
        let registry = self
            .registry_by_id(registry_id)
            .await?
            .context("notification resource is absent")?;
        let resource = self
            .assessment_resource(registry_id)
            .await?
            .context("notification inventory is absent")?;
        let summary = NotificationSummaryV1::from_event(event)?;
        let selection_context = match &event.payload {
            AssessmentEventPayload::Alert { alert, .. }
            | AssessmentEventPayload::Acknowledged { alert } => {
                alert.issue.selection_context.as_ref()
            }
            _ => None,
        };
        let mut statements = Vec::new();
        for record in subscriptions {
            if !record.enabled
                || record.review.authority_expires_at <= event.occurred_at
                || !record
                    .review
                    .configuration
                    .selects(&summary, selection_context)
            {
                continue;
            }
            let delivery_id = Sha256Digest::of_canonical(
                "aos.assessment-notification-intent/v1",
                &(
                    &registry.scope_key,
                    event.sequence,
                    &record.key,
                    record.revision,
                ),
            )?
            .hex();
            let body = NotificationBodyV1 {
                schema: "aos.assessment-notification-body/v1".into(),
                delivery_id: delivery_id.clone(),
                resource_scope: registry.scope_key.clone(),
                subscription_id: record.review.subscription_id.clone(),
                subscription_revision: record.revision,
                events: vec![summary.clone()],
            };
            let payload_digest = body.digest()?;
            self.put_assessment_object(
                &resource.partition,
                AssessmentObjectKind::NotificationBody,
                payload_digest,
                &body.to_bytes()?,
                i64::try_from(event.occurred_at.unix_seconds())?,
            )
            .await?;
            let not_before = match record.review.configuration.frequency {
                NotificationFrequency::Immediate {} => event.occurred_at.unix_seconds(),
                NotificationFrequency::Digest { window_seconds } => {
                    let width = u64::from(window_seconds);
                    event.occurred_at.unix_seconds() / width * width + width
                }
            };
            statements.push(Statement::new("INSERT INTO assessment_notification_outbox(delivery_id, registry_id, event_sequence, subscription_id, subscription_revision, payload_digest, state, attempt, not_before, resource_version, created_at, updated_at)
                VALUES(?1, ?2, ?3, ?4, ?5, ?6, 'pending', 0, ?7, 1, ?8, ?8)", vals![delivery_id, registry_id, event.sequence, record.key, record.revision, payload_digest.to_string(), not_before, event.occurred_at.unix_seconds()]).expecting(1));
        }
        Ok(statements)
    }

    pub(super) async fn subscription_record(
        &self,
        registry_id: i64,
        key: &str,
    ) -> Result<Option<SubscriptionRecord>> {
        self.backend.query_opt("SELECT subscription_id, configuration_json, enabled, resource_version FROM assessment_subscriptions WHERE registry_id = ?1 AND subscription_id = ?2", &vals![@slice registry_id, key]).await?.map(decode_record).transpose()
    }

    pub(super) async fn subscription_records(
        &self,
        registry_id: i64,
    ) -> Result<Vec<SubscriptionRecord>> {
        let rows = self.backend.query("SELECT subscription_id, configuration_json, enabled, resource_version FROM assessment_subscriptions WHERE registry_id = ?1 ORDER BY subscription_id LIMIT 65", &vals![@slice registry_id]).await?;
        ensure!(
            rows.len() <= MAX_SUBSCRIPTIONS,
            "retained assessment subscriptions exceed the installed bound"
        );
        rows.into_iter().map(decode_record).collect()
    }

    pub(super) fn subscription_revision_guard(
        &self,
        registry_id: i64,
        record: &SubscriptionRecord,
        live: bool,
    ) -> CheckedStatement {
        let clock = self.backend.dialect().unix_time_expression();
        Statement::new(format!("UPDATE assessment_subscriptions SET resource_version = resource_version WHERE registry_id = ?1 AND subscription_id = ?2 AND resource_version = ?3 AND (?4 = 0 OR (enabled = 1 AND {clock} < ?5))"), vals![registry_id, record.key, record.revision, i64::from(live), record.review.authority_expires_at.unix_seconds()]).expecting(1)
    }

    pub(super) fn notification_destination_guard(
        &self,
        registry_id: i64,
        destination: &NotificationDestinationV1,
    ) -> Result<CheckedStatement> {
        Ok(Statement::new("UPDATE webhooks SET resource_version = resource_version WHERE id = ?1 AND resource_version = ?2 AND active = 1 AND url = ?3 AND secret_version_ref = ?4 AND credential_fingerprint = ?5 AND org_id = (SELECT org_id FROM registries WHERE id = ?6 AND scope_key = ?7)", vals![webhook_id(&destination.destination_reference)?, destination.revision, destination.url, destination.secret_version_reference, destination.credential_fingerprint.hex(), registry_id, destination.resource_scope]).expecting(1))
    }
}

pub(super) fn subscription_key(resource: &str, identity: &str) -> Result<String> {
    ensure!(
        !identity.is_empty() && identity.len() <= 128 && !identity.chars().any(char::is_control),
        "invalid subscription identity"
    );
    Ok(
        Sha256Digest::of_canonical("aos.assessment-subscription-key/v1", &(resource, identity))?
            .hex(),
    )
}

fn webhook_id(reference: &str) -> Result<i64> {
    let encoded = reference
        .strip_prefix("webhook:")
        .context("notification destination must reference a registered webhook")?;
    let id: i64 = encoded.parse()?;
    ensure!(
        id > 0 && encoded == id.to_string(),
        "invalid registered notification destination identity"
    );
    Ok(id)
}

fn decode_record(row: crate::value::Row) -> Result<SubscriptionRecord> {
    let review: PrivateReview =
        LIMITS.decode(&row.get::<Vec<u8>>(1)?, "private notification review")?;
    review.configuration.validate()?;
    ensure!(
        review.claims.authz_version == AUTHORIZATION_CLAIMS_VERSION
            && review.authority_expires_at <= review.configuration.review_expires_at
            && review.authority_expires_at.unix_seconds() <= u64::try_from(review.claims.exp)?,
        "retained notification review exceeds its original authority"
    );
    let record = SubscriptionRecord {
        key: row.get(0)?,
        review,
        enabled: row.get::<i64>(2)? == 1,
        revision: row.get(3)?,
    };
    ensure!(
        record.revision > 0 && record.revision <= 9_007_199_254_740_991,
        "invalid retained notification review revision"
    );
    Ok(record)
}

pub(super) fn project(resource: &str, record: &SubscriptionRecord) -> Result<SubscriptionV1> {
    ensure!(
        subscription_key(resource, &record.review.subscription_id)? == record.key,
        "retained notification subscription belongs to another incarnation"
    );
    let value = SubscriptionV1 {
        schema: "aos.assessment-subscription/v1".into(),
        resource_scope: resource.into(),
        subscription_id: record.review.subscription_id.clone(),
        revision: record.revision,
        enabled: record.enabled,
        authority_expires_at: record.review.authority_expires_at.clone(),
        configuration: record.review.configuration.clone(),
    };
    value.to_bytes()?;
    Ok(value)
}
