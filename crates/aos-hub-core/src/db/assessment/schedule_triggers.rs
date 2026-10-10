//! Bounded inventory and policy wakeups under an explicitly reviewed selection.
//!
//! A retained input watermark acknowledges admission, never grants execution.
//! Future reviews rotate through bounded observations; due-slot retry keys remain
//! unchanged once due. All execution still requires the current review and IAM.

use anyhow::{ensure, Context as _, Result};
use aos_contract::{canonical, Sha256Digest};

use super::{decode_record, LIMITS};
use crate::backend::Statement;
use crate::db::assessment::AssessmentResource;
use crate::db::Database;

pub(super) fn input_basis(resource: &AssessmentResource) -> Result<Sha256Digest> {
    ensure!(
        resource.next_generation > 0,
        "invalid assessment generation allocator"
    );
    // Scan allocation increments these counters together. Their difference
    // therefore counts input mutations without a self-trigger on every scan,
    // including policy A -> B -> A and inventory reactivation.
    let input_revision = resource
        .resource_version
        .checked_sub(resource.next_generation)
        .context("assessment generation exceeds its resource revision")?;
    Sha256Digest::of_canonical(
        "aos.assessment-recurring-input/v1",
        &(
            &resource.partition,
            resource.inventory_digest,
            resource.inventory_revision,
            resource.policy_digest,
            input_revision,
            resource.authorization_revision,
        ),
    )
}

impl Database {
    /// Wakes a finite set of explicitly continuous reviews for changed admitted input.
    ///
    /// Observations rotate through future reviews. They preserve due slots once
    /// due, configuration revisions, credential deadlines and current execution
    /// guards. Legacy reviews retain their requested cadence. No network request,
    /// quota reservation or scan admission occurs here.
    ///
    /// # Errors
    /// Returns an error for invalid bounds, corrupt private reviews, invalid
    /// resource counters, unavailable persistence or a concurrent input/review change.
    pub async fn wake_changed_assessment_schedules(
        &self,
        registry_id: i64,
        limit: u32,
    ) -> Result<u32> {
        ensure!(
            (1..=10).contains(&limit),
            "continuous schedule page exceeds its bound"
        );
        let Some(resource) = self.assessment_resource(registry_id).await? else {
            return Ok(0);
        };
        let now = self.assessment_database_time().await?;
        let clock = self.backend.dialect().unix_time_expression();
        // Enumerate small metadata first. Corrupt oversized private cells never
        // cross the backend boundary or prevent other reviews from progressing.
        let candidates = self
            .backend
            .query(
                &format!(
                    "SELECT schedule_id, resource_version, next_due_at, updated_at
             FROM assessment_schedules WHERE registry_id = ?1 AND enabled = 1
                 AND next_due_at > {clock} AND LENGTH(configuration_json) <= ?3
             ORDER BY updated_at, next_due_at, schedule_id LIMIT ?2"
                ),
                &vals![@slice registry_id, limit, LIMITS.max_bytes as u64],
            )
            .await?;
        let mut woken = 0;
        for candidate in candidates {
            let key: String = candidate.get(0)?;
            let revision: u64 = candidate.get(1)?;
            let next_due: u64 = candidate.get(2)?;
            let updated: u64 = candidate.get(3)?;
            let Some(row) = self.backend.query_opt(
                "SELECT schedule_id, actor_ref, resource_version, enabled, next_due_at, configuration_json
                 FROM assessment_schedules WHERE registry_id = ?1 AND schedule_id = ?2
                     AND resource_version = ?3 AND next_due_at = ?4 AND updated_at = ?5
                     AND enabled = 1 AND LENGTH(configuration_json) <= ?6",
                &vals![@slice registry_id, key, revision, next_due, updated, LIMITS.max_bytes as u64],
            ).await? else {
                continue;
            };
            let original: Vec<u8> = row.get(5)?;
            let mut record = decode_record(&row)?;
            ensure!(
                super::schedule_key(&resource.partition, &record.review.schedule_id)? == record.key,
                "continuous review differs from the resource incarnation"
            );
            let basis = if record.review.configuration.continuous
                && record.review.authority_expires_at > now
            {
                Some(input_basis(&resource)?)
            } else {
                None
            };
            let wake = basis.is_some() && record.review.observed_input != basis;
            let due = if wake {
                now.unix_seconds().min(next_due)
            } else {
                next_due
            };
            let reviewed = if wake {
                record.review.pending_input = basis;
                canonical::to_vec(&record.review)?
            } else {
                original.clone()
            };
            LIMITS.decode::<super::PrivateReview>(&reviewed, "continuous schedule watermark")?;
            let mut changes = vec![
                Statement::new(format!(
                    "UPDATE assessment_schedules SET next_due_at = ?6, configuration_json = ?8,
                         updated_at = CASE WHEN updated_at >= {clock} THEN updated_at + 1 ELSE {clock} END
                     WHERE registry_id = ?1 AND schedule_id = ?2 AND resource_version = ?3
                         AND next_due_at = ?4 AND updated_at = ?5 AND enabled = 1
                         AND configuration_json = ?7"
                ), vals![registry_id, key, revision, next_due, updated, due, original, reviewed]).expecting(1),
            ];
            if wake {
                // Schedule first, then resource: the same lock order as due-slot
                // advancement. Activation never needs to acquire a schedule lock.
                changes.push(Statement::new(
                    "UPDATE assessment_resources SET updated_at = updated_at WHERE registry_id = ?1
                     AND partition_key = ?2 AND inventory_digest = ?3 AND inventory_revision = ?4
                     AND policy_digest = ?5 AND resource_version - next_generation = ?6
                     AND authorization_revision = ?7",
                    vals![registry_id, resource.partition, resource.inventory_digest.to_string(), resource.inventory_revision,
                        resource.policy_digest.to_string(), resource.resource_version - resource.next_generation, resource.authorization_revision],
                ).expecting(1));
            }
            self.backend.checked_batch(&changes).await?;
            woken += u32::from(wake);
        }
        Ok(woken)
    }
}
