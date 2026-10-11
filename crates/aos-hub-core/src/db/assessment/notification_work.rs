//! Shared outbox claims, pinned digest membership, quotas and exact receipt fencing.
//!
//! The first claim freezes a finite body. Later attempts retain those bytes even
//! when newer events arrive. One quota debit and every member lease commit
//! together; physical delivery never occurs within the transaction.

use anyhow::{ensure, Context as _, Result};
use aos_assessment::time::Timestamp;
use aos_assessment_runtime::notifications::{
    retry_delay, DeliveryOutcome, NotificationBodyV1, NotificationDestinationV1,
    NotificationFrequency, NotificationWorkPlanV1, NotificationWorkReceiptV1,
};
use aos_contract::Sha256Digest;

use super::{notifications::SubscriptionRecord, AssessmentObjectKind};
use crate::backend::{CheckedStatement, Statement};
use crate::db::Database;
use crate::domain::Permission;

mod failure;

/// Selects independently installed service pairing and a notification-only shared quota.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssessmentNotificationPlacement {
    /// Installed deployment identity.
    pub deployment_id: String,
    /// Installed logical coordinator identity.
    pub issuer: String,
    /// Installed physical notification executor identity.
    pub audience: String,
    /// Independently installed quota key prefixed with `notification:`.
    pub budget_key: String,
}

/// Carries one admitted exact callback attempt and its independently installed destination.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssessmentNotificationWork {
    /// Authorized owning registry.
    pub registry_id: i64,
    /// Complete immutable plan pinned before dispatch.
    pub plan: NotificationWorkPlanV1,
    /// Exact independently installed destination, including its immutable key reference.
    pub destination: NotificationDestinationV1,
}

struct Row {
    delivery_id: String,
    sequence: u64,
    subscription_key: String,
    subscription_revision: u64,
    payload_digest: Sha256Digest,
    state: String,
    attempt: u8,
    not_before: u64,
    version: u64,
    created_at: u64,
    receipt_digest: Option<Sha256Digest>,
}

impl Database {
    /// Reads an intent's exact review commitment without exposing callback URLs or credentials.
    ///
    /// The commitment selects an independently installed destination; it never
    /// authorizes disclosure or a physical effect by itself.
    ///
    /// # Errors
    /// Returns an error for absent/replaced reviews or unavailable persistence.
    pub async fn assessment_notification_intent_destination(
        &self,
        registry_id: i64,
        delivery_id: &str,
    ) -> Result<(String, Sha256Digest)> {
        let row = self
            .notification_row(registry_id, delivery_id)
            .await?
            .context("notification intent is absent")?;
        let record = self
            .subscription_record(registry_id, &row.subscription_key)
            .await?
            .context("notification review is absent")?;
        ensure!(
            record.enabled && record.revision == row.subscription_revision,
            "notification review was replaced or disabled"
        );
        Ok((
            record.review.configuration.destination_reference,
            record.review.configuration.destination_digest,
        ))
    }

    /// Rechecks current reviewer authority and the exact live attempt before an external effect.
    ///
    /// # Errors
    /// Returns an error for revoked credentials/review/destination, expired work or a stale lease.
    pub async fn check_assessment_notification_work(
        &self,
        work: &AssessmentNotificationWork,
    ) -> Result<()> {
        let root = self
            .notification_row(work.registry_id, &work.plan.body.delivery_id)
            .await?
            .context("notification root is absent")?;
        let record = self
            .subscription_record(work.registry_id, &root.subscription_key)
            .await?
            .context("notification review is absent")?;
        let fences = self
            .notification_authority_fences(work.registry_id, &record)
            .await?;
        self.check_assessment_notification_work_fenced(work, &fences)
            .await
    }

    /// Holds current principal locks and all exact member leases through effect admission.
    ///
    /// # Errors
    /// Returns an error for missing authority, changed scope, review replacement or expired claims.
    pub async fn check_assessment_notification_work_fenced(
        &self,
        work: &AssessmentNotificationWork,
        fences: &[CheckedStatement],
    ) -> Result<()> {
        ensure!(
            !fences.is_empty() && fences.len() <= 32,
            "notification effect requires current authority"
        );
        let now = self.assessment_database_time().await?;
        work.plan.validate_at(&now)?;
        work.plan.require_destination(&work.destination)?;
        let root = self
            .notification_row(work.registry_id, &work.plan.body.delivery_id)
            .await?
            .context("notification root is absent")?;
        let record = self
            .subscription_record(work.registry_id, &root.subscription_key)
            .await?
            .context("notification review is absent")?;
        ensure!(
            record.revision == work.plan.body.subscription_revision
                && record.enabled
                && record.review.configuration.destination_digest == work.plan.destination_digest,
            "notification review changed before the effect"
        );
        let resource = self
            .assessment_resource(work.registry_id)
            .await?
            .context("notification resource is absent")?;
        let retained = self
            .assessment_object(
                &resource.partition,
                AssessmentObjectKind::NotificationWork,
                work.plan.digest()?,
            )
            .await?
            .context("notification effect lacks its exact retained work proof")?;
        ensure!(
            retained == aos_contract::canonical::to_vec(&work.plan)?,
            "notification effect work proof differs from admission"
        );
        let clock = self.backend.dialect().unix_time_expression();
        let mut checked = fences.to_vec();
        checked.push(self.subscription_revision_guard(work.registry_id, &record, true));
        checked.push(self.notification_destination_guard(work.registry_id, &work.destination)?);
        checked.push(Statement::new(format!("UPDATE assessment_notification_outbox SET resource_version = resource_version WHERE registry_id = ?1 AND subscription_id = ?2 AND subscription_revision = ?3 AND payload_digest = ?4 AND state = 'leased' AND claim_token = ?5 AND attempt = ?6 AND lease_expires_at = ?7 AND {clock} < ?7"), vals![work.registry_id, record.key, record.revision, work.plan.body_digest.to_string(), work.plan.claim_token, u32::from(work.plan.attempt), work.plan.deadline.unix_seconds()]).expecting(work.plan.body.events.len() as u64));
        self.backend.checked_batch(&checked).await
    }

    /// Settles expired reviews and exhausted/aged attempts without granting callback authority.
    ///
    /// A finite page prevents permanently unclaimable rows from remaining pending
    /// forever. Uncertain attempts retain consumed quota and immutable receipts.
    ///
    /// # Errors
    /// Returns an error for invalid page bounds, concurrent review changes or unavailable persistence.
    pub async fn reconcile_assessment_notifications(
        &self,
        registry_id: i64,
        limit: u32,
    ) -> Result<()> {
        ensure!(
            (1..=100).contains(&limit),
            "notification recovery page exceeds its bound"
        );
        let now = self.assessment_database_time().await?;
        let clock = self.backend.dialect().unix_time_expression();
        let mut remaining = limit;
        for record in self.subscription_records(registry_id).await? {
            if remaining == 0 {
                return Ok(());
            }
            if record.review.authority_expires_at > now {
                continue;
            }
            let rows = self.backend.query(
                "SELECT delivery_id, resource_version FROM assessment_notification_outbox WHERE registry_id = ?1 AND subscription_id = ?2 AND subscription_revision = ?3 AND state IN('pending', 'leased') ORDER BY event_sequence, delivery_id LIMIT ?4",
                &vals![@slice registry_id, record.key, record.revision, remaining],
            ).await?;
            for row in rows {
                self.backend.checked_batch(&[
                    self.subscription_revision_guard(registry_id, &record, false),
                    Statement::new(format!("UPDATE assessment_notification_outbox SET state = 'revoked', claim_token = NULL, lease_expires_at = NULL, last_error_code = 'notification-review-expired', resource_version = resource_version + 1, updated_at = {clock} WHERE registry_id = ?1 AND delivery_id = ?2 AND resource_version = ?3 AND subscription_id = ?4 AND subscription_revision = ?5 AND state IN('pending', 'leased') AND {clock} >= ?6"), vals![registry_id, row.get::<String>(0)?, row.get::<u64>(1)?, record.key, record.revision, record.review.authority_expires_at.unix_seconds()]).expecting(1),
                ]).await?;
                remaining -= 1;
            }
        }
        if remaining == 0 {
            return Ok(());
        }
        let rows = self.backend.query(&format!("SELECT delivery_id, resource_version FROM assessment_notification_outbox WHERE registry_id = ?1 AND (state = 'pending' OR (state = 'leased' AND lease_expires_at <= {clock})) AND (attempt >= 20 OR created_at <= {clock} - 604800) ORDER BY event_sequence, delivery_id LIMIT ?2"), &vals![@slice registry_id, remaining]).await?;
        for row in rows {
            self.backend.checked_batch(&[Statement::new(format!("UPDATE assessment_notification_outbox SET state = 'dead-letter', claim_token = NULL, lease_expires_at = NULL, last_error_code = 'notification-attempt-or-age-exhausted', resource_version = resource_version + 1, updated_at = {clock} WHERE registry_id = ?1 AND delivery_id = ?2 AND resource_version = ?3 AND (state = 'pending' OR (state = 'leased' AND lease_expires_at <= {clock})) AND (attempt >= 20 OR created_at <= {clock} - 604800)"), vals![registry_id, row.get::<String>(0)?, row.get::<u64>(1)?]).expecting(1)]).await?;
        }
        Ok(())
    }

    /// Enumerates a finite due page without granting delivery authority.
    ///
    /// # Errors
    /// Returns an error for invalid bounds or unavailable persistence.
    pub async fn assessment_notification_due_page(
        &self,
        registry_id: i64,
        limit: u32,
    ) -> Result<Vec<String>> {
        ensure!(
            (1..=10).contains(&limit),
            "notification due page exceeds its bound"
        );
        let clock = self.backend.dialect().unix_time_expression();
        self.backend.query(&format!("SELECT delivery_id FROM assessment_notification_outbox WHERE registry_id = ?1 AND not_before <= {clock}
            AND (state = 'pending' OR (state = 'leased' AND lease_expires_at <= {clock})) AND attempt < 20 AND created_at >= {clock} - 604800
            AND (attempt = 0 OR NOT EXISTS(SELECT 1 FROM assessment_notification_outbox member
                WHERE member.registry_id = assessment_notification_outbox.registry_id
                  AND member.subscription_id = assessment_notification_outbox.subscription_id
                  AND member.subscription_revision = assessment_notification_outbox.subscription_revision
                  AND member.payload_digest = assessment_notification_outbox.payload_digest
                  AND member.event_sequence < assessment_notification_outbox.event_sequence))
            ORDER BY event_sequence, delivery_id LIMIT ?2"), &vals![@slice registry_id, limit]).await?.into_iter().map(|row| row.get(0)).collect()
    }

    /// Claims bounded work under the original reviewer's current read and subscription authority.
    ///
    /// # Errors
    /// Returns an error for unavailable permission policy, revoked review/destination,
    /// expired credentials, unavailable quota or concurrent claim/review changes.
    pub async fn claim_assessment_notification_work(
        &self,
        registry_id: i64,
        delivery_id: &str,
        placement: &AssessmentNotificationPlacement,
        destination: &NotificationDestinationV1,
    ) -> Result<AssessmentNotificationWork> {
        let row = self
            .notification_row(registry_id, delivery_id)
            .await?
            .context("notification intent is absent")?;
        let record = self
            .subscription_record(registry_id, &row.subscription_key)
            .await?
            .context("notification review is absent")?;
        let fences = self
            .notification_authority_fences(registry_id, &record)
            .await?;
        self.claim_assessment_notification_work_fenced(
            registry_id,
            delivery_id,
            placement,
            destination,
            &fences,
        )
        .await
    }

    /// Claims all pinned members and consumes one shared quota unit atomically.
    ///
    /// Callers supply separately established current principal locks. This method
    /// additionally holds the exact original review, destination and member CAS.
    ///
    /// # Errors
    /// Returns an error for stale members, wrong installed scope, exhausted quota,
    /// missing authority fences, expiry or invalid retained bodies.
    pub async fn claim_assessment_notification_work_fenced(
        &self,
        registry_id: i64,
        delivery_id: &str,
        placement: &AssessmentNotificationPlacement,
        destination: &NotificationDestinationV1,
        fences: &[CheckedStatement],
    ) -> Result<AssessmentNotificationWork> {
        ensure!(
            !fences.is_empty()
                && fences.len() <= 32
                && placement.budget_key.starts_with("notification:")
                && placement.budget_key.len() <= 128
                && !placement.budget_key.chars().any(char::is_control),
            "notification work requires independent authority and installed quota"
        );
        let root = self
            .notification_row(registry_id, delivery_id)
            .await?
            .context("notification root is absent")?;
        let record = self
            .subscription_record(registry_id, &root.subscription_key)
            .await?
            .context("notification review is absent")?;
        ensure!(
            record.enabled && record.revision == root.subscription_revision,
            "notification subscription revision is no longer enabled"
        );
        let registry = self
            .registry_by_id(registry_id)
            .await?
            .context("notification resource is absent")?;
        let resource = self
            .assessment_resource(registry_id)
            .await?
            .context("notification inventory is absent")?;
        ensure!(
            resource.partition == registry.scope_key
                && destination.resource_scope == registry.scope_key
                && destination.revision == record.review.configuration.destination_revision
                && destination.digest()? == record.review.configuration.destination_digest,
            "notification installed destination differs from the reviewed resource"
        );
        let now = self.assessment_database_time().await?;
        let deadline = Timestamp::from_unix_seconds(now.unix_seconds() + 60)?;
        ensure!(
            record.review.authority_expires_at >= deadline
                && destination.expires_at >= deadline
                && (root.state == "pending" || root.state == "leased")
                && root.attempt < 20
                && root.not_before <= now.unix_seconds()
                && root.created_at.saturating_add(604800) > now.unix_seconds(),
            "notification claim is not due or exceeds authority/age bounds"
        );
        let mut body = self
            .notification_body(&resource.partition, root.payload_digest)
            .await?;
        ensure!(
            body.delivery_id == root.delivery_id
                && body.subscription_id == record.review.subscription_id
                && body.subscription_revision == record.revision
                && body.resource_scope == registry.scope_key,
            "notification claim is not the exact pinned group root"
        );
        let members = if root.attempt == 0
            && matches!(
                record.review.configuration.frequency,
                NotificationFrequency::Digest { .. }
            ) {
            ensure!(
                root.state == "pending" && body.events.len() == 1,
                "unclaimed notification digest has inconsistent membership"
            );
            let rows = self.backend.query("SELECT delivery_id FROM assessment_notification_outbox WHERE registry_id = ?1 AND subscription_id = ?2 AND subscription_revision = ?3 AND state = 'pending' AND attempt = 0 AND not_before = ?4 AND event_sequence >= ?5 ORDER BY event_sequence, delivery_id LIMIT 50", &vals![@slice registry_id, record.key, record.revision, root.not_before, root.sequence]).await?;
            let mut members = Vec::with_capacity(rows.len());
            body.events.clear();
            for selected in rows {
                let member = self
                    .notification_row(registry_id, &selected.get::<String>(0)?)
                    .await?
                    .context("notification digest member changed")?;
                let single = self
                    .notification_body(&resource.partition, member.payload_digest)
                    .await?;
                ensure!(
                    single.events.len() == 1
                        && single.events[0].sequence == member.sequence
                        && single.delivery_id == member.delivery_id
                        && single.resource_scope == body.resource_scope
                        && single.subscription_id == body.subscription_id
                        && single.subscription_revision == body.subscription_revision,
                    "notification digest member differs from its exact admitted intent"
                );
                body.events.push(single.events[0].clone());
                members.push(member);
            }
            members
        } else {
            let rows = self.backend.query("SELECT delivery_id FROM assessment_notification_outbox WHERE registry_id = ?1 AND subscription_id = ?2 AND subscription_revision = ?3 AND payload_digest = ?4 ORDER BY event_sequence, delivery_id LIMIT 51", &vals![@slice registry_id, record.key, record.revision, root.payload_digest.to_string()]).await?;
            ensure!(
                rows.len() <= 50,
                "pinned notification membership exceeds fifty events"
            );
            let mut members = Vec::with_capacity(rows.len());
            for row in rows {
                members.push(
                    self.notification_row(registry_id, &row.get::<String>(0)?)
                        .await?
                        .context("pinned notification member is absent")?,
                );
            }
            members
        };
        ensure!(
            !members.is_empty()
                && members.len() <= 50
                && members.len() == body.events.len()
                && members
                    .iter()
                    .zip(&body.events)
                    .all(|(member, event)| member.sequence == event.sequence
                        && member.subscription_key == root.subscription_key
                        && member.subscription_revision == root.subscription_revision
                        && member.attempt == root.attempt
                        && member.not_before <= now.unix_seconds()
                        && matches!(member.state.as_str(), "pending" | "leased")),
            "notification membership changed or exceeded its bound"
        );
        let body_digest = body.digest()?;
        self.put_assessment_object(
            &resource.partition,
            AssessmentObjectKind::NotificationBody,
            body_digest,
            &body.to_bytes()?,
            i64::try_from(now.unix_seconds())?,
        )
        .await?;
        let token = uuid::Uuid::new_v4().simple().to_string();
        let attempt = root.attempt + 1;
        let plan = NotificationWorkPlanV1 {
            schema: "aos.assessment-notification-work/v1".into(),
            deployment_id: placement.deployment_id.clone(),
            issuer: placement.issuer.clone(),
            audience: placement.audience.clone(),
            claim_token: token.clone(),
            attempt,
            reservation_digest: Sha256Digest::of_canonical(
                "aos.assessment-notification-reservation/v1",
                &(&placement.budget_key, &token, body_digest, attempt),
            )?,
            destination_reference: destination.destination_reference.clone(),
            destination_digest: destination.digest()?,
            body,
            body_digest,
            issued_at: now.clone(),
            deadline: deadline.clone(),
        };
        plan.validate_at(&now)?;
        self.put_assessment_object(
            &resource.partition,
            AssessmentObjectKind::NotificationWork,
            plan.digest()?,
            &aos_contract::canonical::to_vec(&plan)?,
            i64::try_from(now.unix_seconds())?,
        )
        .await?;
        let budget = self
            .backend
            .query_opt(
                "SELECT window_seconds FROM assessment_source_budgets WHERE budget_key = ?1",
                &vals![@slice placement.budget_key],
            )
            .await?
            .context("notification quota is not independently installed")?;
        let width: u64 = budget.get(0)?;
        ensure!(
            width > 0 && width <= 86400,
            "notification quota window is invalid"
        );
        let window = now.unix_seconds() / width * width;
        let clock = self.backend.dialect().unix_time_expression();
        let mut checked = fences.to_vec();
        checked.push(self.subscription_revision_guard(registry_id, &record, true));
        checked.push(self.notification_destination_guard(registry_id, destination)?);
        checked.push(Statement::new(format!("UPDATE assessment_source_budgets SET consumed = CASE WHEN window_start + window_seconds <= {clock} THEN 1 ELSE consumed + 1 END, next_eligible_at = {clock} + min_interval_seconds, resource_version = resource_version + 1, window_start = ?2
            WHERE budget_key = ?1 AND circuit_until <= {clock} AND next_eligible_at <= {clock} AND window_seconds = ?3 AND {clock} >= ?2 AND {clock} < ?2 + window_seconds AND (window_start + window_seconds <= {clock} OR consumed < allowance)"), vals![placement.budget_key, window, width]).expecting(1));
        for member in members {
            checked.push(Statement::new(format!("UPDATE assessment_notification_outbox SET state = 'leased', payload_digest = ?4, claim_token = ?5, lease_expires_at = ?6, attempt = ?7, receipt_digest = NULL, last_error_code = NULL, resource_version = resource_version + 1, updated_at = ?8
                WHERE delivery_id = ?1 AND registry_id = ?2 AND resource_version = ?3 AND subscription_id = ?9 AND subscription_revision = ?10 AND attempt = ?11 AND not_before <= {clock}
                  AND {clock} < ?6 AND {clock} < ?12 AND created_at > {clock} - 604800 AND (state = 'pending' OR (state = 'leased' AND lease_expires_at <= {clock}))"), vals![member.delivery_id, registry_id, member.version, body_digest.to_string(), token, deadline.unix_seconds(), u32::from(attempt), now.unix_seconds(), record.key, record.revision, u32::from(root.attempt), record.review.authority_expires_at.unix_seconds()]).expecting(1));
        }
        self.backend.checked_batch(&checked).await?;
        Ok(AssessmentNotificationWork {
            registry_id,
            plan,
            destination: destination.clone(),
        })
    }

    /// Commits a compact receipt under the original reviewer's current authority.
    ///
    /// # Errors
    /// Returns an error for revoked review/credential, stale claim or malformed receipt.
    pub async fn admit_assessment_notification_receipt(
        &self,
        work: &AssessmentNotificationWork,
        receipt: &NotificationWorkReceiptV1,
    ) -> Result<()> {
        let root = self
            .notification_row(work.registry_id, &work.plan.body.delivery_id)
            .await?
            .context("notification root is absent")?;
        let record = self
            .subscription_record(work.registry_id, &root.subscription_key)
            .await?
            .context("notification review is absent")?;
        let fences = self
            .notification_authority_fences(work.registry_id, &record)
            .await?;
        self.admit_assessment_notification_receipt_fenced(work, receipt, &fences)
            .await
    }

    /// Settles every frozen member together against its exact live attempt fence.
    ///
    /// Accepted HTTP indicates destination acceptance only. Retryable results retain
    /// the same pinned body, and consumed quota is never refunded.
    ///
    /// # Errors
    /// Returns an error for missing current authority, altered work, expired claim or persistence failure.
    pub async fn admit_assessment_notification_receipt_fenced(
        &self,
        work: &AssessmentNotificationWork,
        receipt: &NotificationWorkReceiptV1,
        fences: &[CheckedStatement],
    ) -> Result<()> {
        ensure!(
            !fences.is_empty() && fences.len() <= 32,
            "notification receipt requires current authority"
        );
        let now = self.assessment_database_time().await?;
        receipt.validate_for(&work.plan, &now)?;
        work.plan.require_destination(&work.destination)?;
        let root = self
            .notification_row(work.registry_id, &work.plan.body.delivery_id)
            .await?
            .context("notification root is absent")?;
        let record = self
            .subscription_record(work.registry_id, &root.subscription_key)
            .await?
            .context("notification review is absent")?;
        ensure!(
            record.revision == work.plan.body.subscription_revision
                && record.enabled
                && record.review.configuration.destination_digest == work.plan.destination_digest,
            "notification review changed before receipt admission"
        );
        let resource = self
            .assessment_resource(work.registry_id)
            .await?
            .context("notification resource is absent")?;
        let bytes = self
            .assessment_object(
                &resource.partition,
                AssessmentObjectKind::NotificationWork,
                work.plan.digest()?,
            )
            .await?
            .context("notification work has no retained exact admission proof")?;
        ensure!(
            bytes == aos_contract::canonical::to_vec(&work.plan)?,
            "notification work proof differs"
        );
        let receipt_digest = receipt.digest()?;
        self.put_assessment_object(
            &resource.partition,
            AssessmentObjectKind::NotificationReceipt,
            receipt_digest,
            &receipt.to_bytes()?,
            i64::try_from(now.unix_seconds())?,
        )
        .await?;
        let clock = self.backend.dialect().unix_time_expression();
        let mut checked = fences.to_vec();
        checked.push(self.subscription_revision_guard(work.registry_id, &record, true));
        checked.push(self.notification_destination_guard(work.registry_id, &work.destination)?);
        if root.receipt_digest == Some(receipt_digest) {
            checked.push(Statement::new("UPDATE assessment_notification_outbox SET resource_version = resource_version WHERE registry_id = ?1 AND delivery_id = ?2 AND receipt_digest = ?3 AND payload_digest = ?4", vals![work.registry_id, root.delivery_id, receipt_digest.to_string(), work.plan.body_digest.to_string()]).expecting(1));
            return self.backend.checked_batch(&checked).await;
        }
        let delay = retry_delay(
            &work.plan.body.delivery_id,
            work.plan.attempt,
            receipt.retry_after_seconds,
        )?;
        let mut not_before = now.unix_seconds().saturating_add(u64::from(delay));
        if receipt.status.is_none() {
            // A timed-out remote invocation may still be finishing its admitted
            // effect. No new attempt may overlap the old authority window.
            not_before = not_before.max(work.plan.deadline.unix_seconds());
        }
        let retry = receipt.outcome == DeliveryOutcome::Retryable
            && work.plan.attempt < 20
            && not_before < root.created_at.saturating_add(604800)
            && not_before < record.review.authority_expires_at.unix_seconds();
        let state = match receipt.outcome {
            DeliveryOutcome::Accepted => "delivered",
            DeliveryOutcome::Retryable if retry => "pending",
            _ => "dead-letter",
        };
        let failure = match receipt.outcome {
            DeliveryOutcome::Accepted => None,
            DeliveryOutcome::Retryable => Some("destination-retryable"),
            DeliveryOutcome::PermanentFailure => Some("destination-permanent-failure"),
        };
        checked.push(Statement::new(format!("UPDATE assessment_notification_outbox SET state = ?7, claim_token = NULL, lease_expires_at = NULL, not_before = ?8, last_error_code = ?9, receipt_digest = ?10, resource_version = resource_version + 1, updated_at = {clock}
            WHERE registry_id = ?1 AND subscription_id = ?2 AND subscription_revision = ?3 AND payload_digest = ?4 AND state = 'leased' AND claim_token = ?5 AND attempt = ?6 AND lease_expires_at = ?11 AND {clock} < ?11"), vals![work.registry_id, record.key, record.revision, work.plan.body_digest.to_string(), work.plan.claim_token, u32::from(work.plan.attempt), state, not_before, failure, receipt_digest.to_string(), work.plan.deadline.unix_seconds()]).expecting(work.plan.body.events.len() as u64));
        checked.extend(
            self.notification_failure_event_statements(
                work,
                receipt,
                state == "dead-letter",
                not_before,
                &now,
            )
            .await?,
        );
        self.backend.checked_batch(&checked).await
    }

    async fn notification_authority_fences(
        &self,
        registry_id: i64,
        record: &SubscriptionRecord,
    ) -> Result<Vec<CheckedStatement>> {
        let registry = self
            .registry_by_id(registry_id)
            .await?
            .context("notification resource is absent")?;
        if let Some(organization) = registry.org_id {
            ensure!(
                self.org_is_active(organization).await?,
                "notification organization is inactive"
            );
        }
        let mut fences = Vec::new();
        let permissions: &[&str] = if record.review.service_authority.is_some() {
            &["assessment.read"]
        } else {
            &["assessment.read", "assessment.subscription.manage"]
        };
        for name in permissions {
            let permission = Permission::parse(name)
                .context("assessment notification permission policy is unavailable")?;
            fences.extend(
                self.assessment_iam_statements(
                    record.review.execution_principal(),
                    &registry.scope_key,
                    permission,
                )
                .await?,
            );
        }
        if let Some(authority) = &record.review.service_authority {
            fences.push(self.assessment_service_owner_guard(registry_id, authority));
        }
        super::service_authority::distinct_authority_fences(fences)
    }

    async fn notification_body(
        &self,
        partition: &str,
        digest: Sha256Digest,
    ) -> Result<NotificationBodyV1> {
        let bytes = self
            .assessment_object(partition, AssessmentObjectKind::NotificationBody, digest)
            .await?
            .context("notification body is absent")?;
        let body = NotificationBodyV1::from_slice(&bytes)?;
        ensure!(
            body.digest()? == digest,
            "notification body commitment changed"
        );
        Ok(body)
    }

    async fn notification_row(&self, registry_id: i64, delivery_id: &str) -> Result<Option<Row>> {
        self.backend.query_opt("SELECT delivery_id, event_sequence, subscription_id, subscription_revision, payload_digest, state, attempt, not_before, resource_version, created_at, receipt_digest FROM assessment_notification_outbox WHERE registry_id = ?1 AND delivery_id = ?2", &vals![@slice registry_id, delivery_id]).await?.map(|row| Ok(Row {
            delivery_id: row.get(0)?, sequence: row.get(1)?, subscription_key: row.get(2)?, subscription_revision: row.get(3)?, payload_digest: Sha256Digest::parse(&row.get::<String>(4)?)?, state: row.get(5)?, attempt: u8::try_from(row.get::<u32>(6)?)?, not_before: row.get(7)?, version: row.get(8)?, created_at: row.get(9)?, receipt_digest: row.get::<Option<String>>(10)?.map(|value| Sha256Digest::parse(&value)).transpose()?,
        })).transpose()
    }
}
