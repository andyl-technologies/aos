//! Read-only notification intent projections with bounded immutable batch lookups.

use std::collections::BTreeMap;

use anyhow::{ensure, Context as _, Result};
use aos_assessment::time::Timestamp;
use aos_assessment_runtime::notifications::{
    NotificationBodyV1, NotificationDeliveryV1, NotificationIntentState,
};
use aos_contract::Sha256Digest;

use super::{notifications::subscription_key, AssessmentObjectKind};
use crate::db::Database;

const COLUMNS: &str = "delivery_id, subscription_id, subscription_revision, event_sequence,
    state, attempt, not_before, lease_expires_at, resource_version, created_at, updated_at,
    last_error_code, payload_digest, receipt_digest";

impl Database {
    /// Reads a finite delivery page without claiming, reconciling or dispatching any intent.
    ///
    /// Eleven rows permit ten public projections and one continuation lookahead.
    /// The service independently checks current read authority before and after
    /// this operation. Stable delivery identities survive retry and digest batching.
    ///
    /// # Errors
    /// Returns an error for invalid selectors, unavailable resource, inconsistent
    /// retained batch facts or failed persistence.
    pub async fn assessment_notification_delivery_page(
        &self,
        registry_id: i64,
        after_delivery: &str,
        subscription_id: Option<&str>,
        delivery_id: Option<&str>,
        limit: u32,
    ) -> Result<Vec<NotificationDeliveryV1>> {
        ensure!(
            (1..=11).contains(&limit),
            "notification delivery page exceeds its bound"
        );
        ensure!(
            delivery_id.is_none() || after_delivery.is_empty(),
            "notification detail cannot continue a page"
        );
        for identity in [Some(after_delivery), subscription_id, delivery_id]
            .into_iter()
            .flatten()
        {
            ensure!(
                identity.len() <= 128 && !identity.chars().any(char::is_control),
                "invalid notification delivery selector"
            );
        }
        ensure!(
            subscription_id.is_none_or(|identity| !identity.is_empty())
                && delivery_id.is_none_or(|identity| !identity.is_empty()),
            "notification detail/filter identity is empty"
        );
        let Some(resource) = self.assessment_resource(registry_id).await? else {
            return Ok(Vec::new());
        };
        let filter_key = subscription_id
            .map(|identity| subscription_key(&resource.partition, identity))
            .transpose()?
            .unwrap_or_default();
        let rows = self.backend.query(
            &format!("SELECT {COLUMNS} FROM assessment_notification_outbox
                WHERE registry_id = ?1 AND delivery_id > ?2
                  AND (?3 = '' OR subscription_id = ?3)
                  AND (?4 = '' OR delivery_id = ?4)
                ORDER BY delivery_id LIMIT ?5"),
            &vals![@slice registry_id, after_delivery, filter_key, delivery_id.unwrap_or(""), limit],
        ).await?;

        let mut subscriptions = BTreeMap::<String, String>::new();
        let mut bodies = BTreeMap::<Sha256Digest, NotificationBodyV1>::new();
        let mut deliveries = Vec::with_capacity(rows.len());
        for row in rows {
            let key = row.get::<String>(1)?;
            let identity = if let Some(identity) = subscriptions.get(&key) {
                identity.clone()
            } else {
                let record = self
                    .subscription_record(registry_id, &key)
                    .await?
                    .context("notification subscription is absent")?;
                let identity = record.review.subscription_id;
                ensure!(
                    subscription_key(&resource.partition, &identity)? == key,
                    "notification subscription identity differs from its scope"
                );
                subscriptions.insert(key, identity.clone());
                identity
            };
            let state: NotificationIntentState =
                serde_json::from_value(serde_json::Value::String(row.get(4)?))?;
            let attempt = u8::try_from(row.get::<u32>(5)?)?;
            let sequence = row.get::<u64>(3)?;
            let revision = row.get::<u64>(2)?;
            let payload_digest = Sha256Digest::parse(&row.get::<String>(12)?)?;
            let batch_delivery_id = if attempt > 0 {
                if let std::collections::btree_map::Entry::Vacant(entry) =
                    bodies.entry(payload_digest)
                {
                    let bytes = self
                        .assessment_object(
                            &resource.partition,
                            AssessmentObjectKind::NotificationBody,
                            payload_digest,
                        )
                        .await?
                        .context("notification batch body is absent")?;
                    let body = NotificationBodyV1::from_slice(&bytes)?;
                    ensure!(
                        body.digest()? == payload_digest,
                        "notification batch commitment differs"
                    );
                    entry.insert(body);
                }
                let body = bodies
                    .get(&payload_digest)
                    .context("notification batch body is absent")?;
                ensure!(
                    body.resource_scope == resource.partition
                        && body.subscription_id == identity
                        && body.subscription_revision == revision
                        && body.events.iter().any(|event| event.sequence == sequence),
                    "notification batch membership differs from its intent"
                );
                Some(body.delivery_id.clone())
            } else {
                None
            };
            let delivery = NotificationDeliveryV1 {
                delivery_id: row.get(0)?,
                subscription_id: identity,
                subscription_revision: revision.to_string(),
                event_sequence: sequence.to_string(),
                state,
                attempt,
                not_before: Timestamp::from_unix_seconds(row.get(6)?)?,
                lease_expires_at: row
                    .get::<Option<u64>>(7)?
                    .map(Timestamp::from_unix_seconds)
                    .transpose()?,
                resource_version: row.get::<u64>(8)?.to_string(),
                created_at: Timestamp::from_unix_seconds(row.get(9)?)?,
                updated_at: Timestamp::from_unix_seconds(row.get(10)?)?,
                last_error_code: row
                    .get::<Option<String>>(11)?
                    .map(|value| serde_json::from_value(serde_json::Value::String(value)))
                    .transpose()?,
                batch_delivery_id,
                body_digest: (attempt > 0).then_some(payload_digest),
                receipt_digest: row
                    .get::<Option<String>>(13)?
                    .map(|value| Sha256Digest::parse(&value))
                    .transpose()?,
            };
            delivery.validate()?;
            deliveries.push(delivery);
        }
        Ok(deliveries)
    }
}
