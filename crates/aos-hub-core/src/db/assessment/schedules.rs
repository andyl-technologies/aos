//! Credential-bounded recurring reviews, due-slot idempotency and schedule fences.
//!
//! Private configuration cells retain authenticated claim metadata without tokens.
//! Public projections remove this provenance. Due scans retain the exact schedule
//! revision; disabling or replacing that review fences every later scan effect.

use anyhow::{ensure, Context as _, Result};
use aos_assessment::time::Timestamp;
use aos_assessment_runtime::scan::{ScanRequestV1, SCAN_REQUEST_V1};
use aos_assessment_runtime::schedules::{ScheduleConfigurationV1, ScheduleV1, ScheduleWriteV1};
use aos_contract::{canonical, limits::JsonLimits, Sha256Digest};
use serde::{Deserialize, Serialize};

use super::job_authority::ScheduleGrant;
use super::service_authority::{distinct_authority_fences, ReviewedServiceAuthority};
use super::{assessment_actor_ref, AssessmentScanRecord};
use crate::auth::jwt::{Claims, AUTHORIZATION_CLAIMS_VERSION};
use crate::backend::{CheckedStatement, Statement};
use crate::db::Database;
use crate::domain::Permission;

const LIMITS: JsonLimits = JsonLimits {
    max_bytes: 262_144,
    max_depth: 16,
    max_items: 16_384,
    max_string_bytes: 4096,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PrivateReview {
    schedule_id: String,
    configuration: ScheduleConfigurationV1,
    claims: Claims,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    service_authority: Option<ReviewedServiceAuthority>,
    authority_expires_at: Timestamp,
}

struct Record {
    key: String,
    actor: String,
    revision: u64,
    enabled: bool,
    next_due: Timestamp,
    review: PrivateReview,
}

impl Database {
    /// Creates or replaces an explicit review while holding current IAM guards.
    ///
    /// An explicit service review uses an existing service credential. Other
    /// reviews expire by the original authenticated credential. A replacement
    /// is another review; retries cannot silently extend either authority.
    ///
    /// # Errors
    /// Returns an error for stale revisions, invalid review, missing guards,
    /// conflicting retries, changed resource scope or persistence failure.
    pub async fn write_assessment_schedule_fenced(
        &self,
        registry_id: i64,
        request: &ScheduleWriteV1,
        claims: &Claims,
        fences: &[CheckedStatement],
    ) -> Result<ScheduleV1> {
        self.write_assessment_schedule_with_plan_fenced(registry_id, request, claims, fences, None)
            .await
    }

    /// Commits configuration and an optional immutable plan receipt atomically.
    ///
    /// # Errors
    /// Returns an error for stale configuration, authority or plan fences.
    pub(crate) async fn write_assessment_schedule_with_plan_fenced(
        &self,
        registry_id: i64,
        request: &ScheduleWriteV1,
        claims: &Claims,
        fences: &[CheckedStatement],
        completion: Option<&super::reviews::AssessmentReviewCompletion>,
    ) -> Result<ScheduleV1> {
        request.validate()?;
        let (service_authority, fences) = if let Some(credential) = &request.service_credential_id {
            let permissions = [
                Permission::parse("assessment.scan")
                    .context("assessment scan permission policy is unavailable")?,
                Permission::parse("assessment.read")
                    .context("assessment read permission policy is unavailable")?,
            ];
            let (authority, mut execution_fences) = self
                .prepare_assessment_service_authority(
                    registry_id,
                    credential,
                    &request.configuration.review_expires_at,
                    claims,
                    &permissions,
                )
                .await?;
            execution_fences.extend_from_slice(fences);
            (
                Some(authority),
                distinct_authority_fences(execution_fences)?,
            )
        } else {
            (None, fences.to_vec())
        };
        self.write_prepared_assessment_schedule(
            registry_id,
            request,
            claims,
            &fences,
            completion,
            service_authority,
        )
        .await
    }

    async fn write_prepared_assessment_schedule(
        &self,
        registry_id: i64,
        request: &ScheduleWriteV1,
        claims: &Claims,
        fences: &[CheckedStatement],
        completion: Option<&super::reviews::AssessmentReviewCompletion>,
        service_authority: Option<ReviewedServiceAuthority>,
    ) -> Result<ScheduleV1> {
        request.validate()?;
        ensure!(
            request.service_credential_id.as_deref()
                == service_authority
                    .as_ref()
                    .map(|authority| authority.principal.sub.as_str()),
            "service review differs from the exact requested credential"
        );
        if let Some(authority) = &service_authority {
            authority.validate(claims)?;
        }
        if let Some(completion) = completion {
            completion.require_kind("assessment_schedule_review")?;
        }
        ensure!(
            !fences.is_empty() && fences.len() <= 32,
            "schedule review requires current authority"
        );
        ensure!(
            claims.authz_version == AUTHORIZATION_CLAIMS_VERSION,
            "schedule authorization epoch is obsolete"
        );
        let registry = self
            .registry_by_id(registry_id)
            .await?
            .context("schedule registry is absent")?;
        ensure!(
            registry.scope_key == request.resource_scope,
            "schedule review resource incarnation changed"
        );
        let key = schedule_key(&registry.scope_key, &request.schedule_id)?;
        let execution_principal = service_authority
            .as_ref()
            .map_or(claims, |authority| &authority.principal);
        let actor = assessment_actor_ref(execution_principal)?;
        let now = self.assessment_database_time().await?;
        let authority_expires_at =
            Timestamp::from_unix_seconds(u64::try_from(execution_principal.exp)?)?
                .min(request.configuration.review_expires_at.clone());
        ensure!(
            !request.enabled || authority_expires_at > now,
            "enabled schedule review is expired"
        );
        if let Some(existing) = self.schedule_record(registry_id, &key).await? {
            if request.expected_revision == 0
                && existing.actor == actor
                && assessment_actor_ref(&existing.review.claims)? == assessment_actor_ref(claims)?
                && existing.enabled == request.enabled
                && existing.review.configuration == request.configuration
                && existing
                    .review
                    .service_authority
                    .as_ref()
                    .map(|authority| authority.principal.sub.as_str())
                    == request.service_credential_id.as_deref()
            {
                let mut checked = fences.to_vec();
                checked.push(self.schedule_revision_guard(registry_id, &existing, false));
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
                "schedule revision conflict"
            );
        } else {
            ensure!(
                request.expected_revision == 0,
                "schedule revision is absent"
            );
        }
        let next_due = now.clone();
        let bytes = canonical::to_vec(&PrivateReview {
            schedule_id: request.schedule_id.clone(),
            configuration: request.configuration.clone(),
            claims: claims.clone(),
            service_authority: service_authority.clone(),
            authority_expires_at: authority_expires_at.clone(),
        })?;
        LIMITS.decode::<PrivateReview>(&bytes, "private schedule review")?;
        let clock = self.backend.dialect().unix_time_expression();
        let mut checked = fences.to_vec();
        checked.push(
            Statement::new(
                "UPDATE registries SET scope_key = scope_key WHERE id = ?1 AND scope_key = ?2",
                vals![registry_id, registry.scope_key],
            )
            .expecting(1),
        );
        if request.expected_revision == 0 {
            checked.push(Statement::new(format!(
                "INSERT INTO assessment_schedules(schedule_id, registry_id, actor_ref, configuration_json,
                 enabled, cadence_seconds, next_due_at, resource_version, created_at, updated_at)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, {clock}, {clock})"
            ), vals![key, registry_id, actor, bytes, i64::from(request.enabled), request.configuration.cadence_seconds, next_due.unix_seconds()]).expecting(1));
        } else {
            checked.push(Statement::new(format!(
                "UPDATE assessment_schedules SET actor_ref = ?3, configuration_json = ?4,
                 enabled = ?5, cadence_seconds = ?6, next_due_at = ?7, resource_version = resource_version + 1,
                 updated_at = {clock} WHERE schedule_id = ?1 AND registry_id = ?2 AND resource_version = ?8"
            ), vals![key, registry_id, actor, bytes, i64::from(request.enabled), request.configuration.cadence_seconds, next_due.unix_seconds(), request.expected_revision]).expecting(1));
        }
        checked.extend(
            self.assessment_event_statements(
                registry_id,
                vec![
                    aos_assessment_runtime::events::AssessmentEventPayload::ScheduleChanged {
                        schedule_id: request.schedule_id.clone(),
                        revision: request.expected_revision + 1,
                        enabled: request.enabled,
                    },
                ],
                &now,
            )
            .await?,
        );
        let receipt = ScheduleV1 {
            schema: "aos.assessment-schedule/v1".into(),
            resource_scope: registry.scope_key,
            schedule_id: request.schedule_id.clone(),
            revision: request
                .expected_revision
                .checked_add(1)
                .context("schedule revision exhausted")?,
            enabled: request.enabled,
            authority_expires_at,
            next_due_at: next_due,
            configuration: request.configuration.clone(),
            service_authority: service_authority.map(|authority| authority.receipt),
        };
        receipt.to_bytes()?;
        if let Some(completion) = completion {
            checked.push(completion.statement(receipt.to_bytes()?, clock)?);
        }
        self.backend.checked_batch(&checked).await?;
        Ok(receipt)
    }

    /// Reads a public projection scoped to the current registry incarnation.
    ///
    /// # Errors
    /// Returns an error for invalid identity, corrupt review or persistence failure.
    pub async fn assessment_schedule(
        &self,
        registry_id: i64,
        schedule_id: &str,
    ) -> Result<Option<ScheduleV1>> {
        let registry = self
            .registry_by_id(registry_id)
            .await?
            .context("schedule registry is absent")?;
        self.schedule_record(
            registry_id,
            &schedule_key(&registry.scope_key, schedule_id)?,
        )
        .await?
        .map(|record| project(&registry.scope_key, record))
        .transpose()
    }

    /// Reads a bounded page ordered by immutable scoped schedule identity.
    ///
    /// # Errors
    /// Returns an error for invalid bounds, cursor, corrupt reviews or persistence.
    pub async fn assessment_schedule_page(
        &self,
        registry_id: i64,
        after_schedule: &str,
        limit: u32,
    ) -> Result<Vec<ScheduleV1>> {
        ensure!((1..=10).contains(&limit), "schedule page exceeds its bound");
        let registry = self
            .registry_by_id(registry_id)
            .await?
            .context("schedule registry is absent")?;
        let after = if after_schedule.is_empty() {
            String::new()
        } else {
            schedule_key(&registry.scope_key, after_schedule)?
        };
        let rows = self.backend.query("SELECT schedule_id FROM assessment_schedules WHERE registry_id = ?1 AND schedule_id > ?2 ORDER BY schedule_id LIMIT ?3", &vals![@slice registry_id, after, limit]).await?;
        let mut page = Vec::with_capacity(rows.len());
        for row in rows {
            let record = self
                .schedule_record(registry_id, &row.get::<String>(0)?)
                .await?
                .context("schedule page changed")?;
            page.push(project(&registry.scope_key, record)?);
        }
        Ok(page)
    }

    /// Admits a finite page of due scans under each review's current IAM.
    ///
    /// A due slot pins the current inventory and policy. Durable scan retry keys
    /// make interruption before cursor advancement safe. Missed slots coalesce
    /// into one execution, followed by deterministic bounded jitter.
    ///
    /// # Errors
    /// Returns an error for invalid bounds or unavailable enumeration. Individual
    /// expired, revoked or conflicting reviews remain unexecuted.
    pub async fn admit_due_assessment_schedules(
        &self,
        registry_id: i64,
        limit: u32,
    ) -> Result<u32> {
        ensure!(
            (1..=10).contains(&limit),
            "due schedule page exceeds its bound"
        );
        let clock = self.backend.dialect().unix_time_expression();
        let rows = self.backend.query(&format!("SELECT schedule_id FROM assessment_schedules WHERE registry_id = ?1 AND enabled = 1 AND next_due_at <= {clock} ORDER BY next_due_at, schedule_id LIMIT ?2"), &vals![@slice registry_id, limit]).await?;
        let mut admitted = 0;
        for row in rows {
            let key: String = row.get(0)?;
            if self.admit_due_schedule(registry_id, &key).await.is_ok() {
                admitted += 1;
            }
        }
        Ok(admitted)
    }

    async fn admit_due_schedule(
        &self,
        registry_id: i64,
        key: &str,
    ) -> Result<AssessmentScanRecord> {
        let record = self
            .schedule_record(registry_id, key)
            .await?
            .context("due schedule is absent")?;
        let registry = self
            .registry_by_id(registry_id)
            .await?
            .context("schedule registry is absent")?;
        let scan_permission = Permission::parse("assessment.scan")
            .context("assessment permission policy is unavailable")?;
        let execution_principal = record.review.execution_principal();
        let mut fences = self
            .assessment_iam_statements(execution_principal, &registry.scope_key, scan_permission)
            .await?;
        if let Some(authority) = &record.review.service_authority {
            fences.push(self.assessment_service_owner_guard(registry_id, authority));
        } else {
            let schedule_permission = Permission::parse("assessment.schedule.manage")
                .context("assessment permission policy is unavailable")?;
            fences.extend(
                self.assessment_iam_statements(
                    execution_principal,
                    &registry.scope_key,
                    schedule_permission,
                )
                .await?,
            );
        }
        let resource = self
            .assessment_resource(registry_id)
            .await?
            .context("scheduled assessment publication is unavailable")?;
        fences.extend(
            self.assessment_publication_fences(
                registry_id,
                &registry.scope_key,
                resource.inventory_digest,
                resource.policy_digest,
            )
            .await?,
        );
        fences.push(self.schedule_revision_guard(registry_id, &record, true));
        ensure!(
            fences.len() <= 32,
            "schedule current authority exceeds its bounds"
        );
        self.admit_due_schedule_fenced(registry_id, &registry.scope_key, record, &fences)
            .await
    }

    async fn admit_due_schedule_fenced(
        &self,
        registry_id: i64,
        scope: &str,
        record: Record,
        fences: &[CheckedStatement],
    ) -> Result<AssessmentScanRecord> {
        let now = self.assessment_database_time().await?;
        ensure!(
            record.enabled && record.next_due <= now && record.review.authority_expires_at > now,
            "schedule is not currently due and authorized"
        );
        let resource = self
            .assessment_resource(registry_id)
            .await?
            .context("schedule inventory is absent")?;
        ensure!(
            resource.partition == scope,
            "schedule resource incarnation changed"
        );
        // The finite registry inventory bounds the selector. No package regex or
        // arbitrary query supplied by metadata is evaluated by the coordinator.
        let rows = self.backend.query("SELECT subject_ref, package_coordinate FROM assessment_subjects WHERE registry_id = ?1 AND inventory_digest = ?2 ORDER BY subject_ref LIMIT 10001", &vals![@slice registry_id, resource.inventory_digest.to_string()]).await?;
        ensure!(
            rows.len() <= 10_000,
            "schedule inventory exceeds its selection ceiling"
        );
        let mut subjects = Vec::new();
        for row in rows {
            let coordinate: String = row.get(1)?;
            if record
                .review
                .configuration
                .packages
                .binary_search(&coordinate)
                .is_ok()
            {
                subjects.push(row.get(0)?);
            }
        }
        let idempotency = Sha256Digest::of_canonical(
            "aos.assessment-schedule-slot/v1",
            &(&record.key, record.revision, &record.next_due),
        )?;
        let previous = self.backend.query_opt("SELECT scan_id FROM assessment_scans WHERE registry_id = ?1 AND actor_ref = ?2 AND idempotency_key = ?3", &vals![@slice registry_id, record.actor, idempotency.to_string()]).await?;
        let request = if let Some(previous) = previous {
            let previous = self
                .assessment_scan(registry_id, &previous.get::<String>(0)?)
                .await?
                .context("schedule slot scan is absent")?;
            ensure!(
                previous.request.trigger == "schedule",
                "schedule slot conflicts with another request class"
            );
            previous.request
        } else {
            ScanRequestV1 {
                schema: SCAN_REQUEST_V1.into(),
                resource_scope: scope.into(),
                authorization_partition: scope.into(),
                inventory_revision: resource.inventory_revision,
                inventory_digest: resource.inventory_digest,
                policy_digest: resource.policy_digest,
                subjects,
                profiles: record.review.configuration.profiles.clone(),
                freshness: record.review.configuration.freshness,
                trigger: "schedule".into(),
                actor_ref: record.actor.clone(),
                idempotency_key: idempotency.to_string(),
                limits: record.review.configuration.limits.clone(),
            }
        };
        let scan = self
            .request_assessment_scan_fenced(registry_id, &request, fences)
            .await?;
        let mut claims = record.review.execution_principal().clone();
        claims.exp = claims.exp.min(i64::try_from(
            record.review.authority_expires_at.unix_seconds(),
        )?);
        if self.assessment_scan_authority(&scan).await.is_err() {
            if scan.request.inventory_revision == resource.inventory_revision
                && scan.request.inventory_digest == resource.inventory_digest
                && scan.request.policy_digest == resource.policy_digest
            {
                self.admit_assessment_job_authority(
                    &scan,
                    &claims,
                    Some(ScheduleGrant {
                        schedule_id: record.key.clone(),
                        revision: record.revision,
                    }),
                    fences,
                )
                .await?;
            } else {
                // A slot interrupted before provenance cannot authorize old
                // inventory. Settle it before advancing; the next slot pins new data.
                self.reconcile_assessment_scans(registry_id, "", 100)
                    .await?;
                ensure!(
                    self.assessment_scan(registry_id, &scan.scan_id)
                        .await?
                        .is_some_and(|scan| scan.state.is_terminal()),
                    "interrupted schedule slot remains unsettled"
                );
            }
        }
        let jitter = u64::from(idempotency.as_bytes()[0])
            % (u64::from(record.review.configuration.cadence_seconds) / 10 + 1);
        let next = now
            .unix_seconds()
            .checked_add(u64::from(record.review.configuration.cadence_seconds) + jitter)
            .context("schedule deadline overflowed")?;
        let mut checked = fences.to_vec();
        checked.push(Statement::new(format!("UPDATE assessment_schedules SET next_due_at = ?4, updated_at = {clock} WHERE registry_id = ?1 AND schedule_id = ?2 AND resource_version = ?3 AND next_due_at = ?5 AND enabled = 1", clock=self.backend.dialect().unix_time_expression()), vals![registry_id, record.key, record.revision, next, record.next_due.unix_seconds()]).expecting(1));
        self.backend.checked_batch(&checked).await?;
        Ok(scan)
    }

    pub(super) async fn assessment_schedule_live_guard(
        &self,
        registry_id: i64,
        grant: &ScheduleGrant,
    ) -> Result<CheckedStatement> {
        let record = self
            .schedule_record(registry_id, &grant.schedule_id)
            .await?
            .context("scan schedule review is absent")?;
        ensure!(
            record.revision == grant.revision
                && record.enabled
                && record.review.authority_expires_at > self.assessment_database_time().await?,
            "scan schedule review is no longer current"
        );
        Ok(self.schedule_revision_guard(registry_id, &record, true))
    }

    pub(super) async fn assessment_schedule_service_authority(
        &self,
        registry_id: i64,
        grant: &ScheduleGrant,
    ) -> Result<Option<ReviewedServiceAuthority>> {
        self.assessment_schedule_live_guard(registry_id, grant)
            .await?;
        Ok(self
            .schedule_record(registry_id, &grant.schedule_id)
            .await?
            .context("scan schedule review is absent")?
            .review
            .service_authority)
    }

    fn schedule_revision_guard(
        &self,
        registry_id: i64,
        record: &Record,
        live: bool,
    ) -> CheckedStatement {
        let clock = self.backend.dialect().unix_time_expression();
        Statement::new(format!("UPDATE assessment_schedules SET updated_at = updated_at WHERE registry_id = ?1 AND schedule_id = ?2 AND resource_version = ?3{}", if live { format!(" AND enabled = 1 AND ?4 > {clock}") } else { String::new() }), if live { vals![registry_id, record.key, record.revision, record.review.authority_expires_at.unix_seconds()] } else { vals![registry_id, record.key, record.revision] }).expecting(1)
    }

    /// Captures finite public reviews from one bounded SQL observation.
    ///
    /// # Errors
    /// Returns an error for excessive records/bytes, corrupt original reviews,
    /// conflicting resource custody or unavailable persistence.
    pub(super) async fn assessment_schedule_capture(
        &self,
        registry_id: i64,
        scope: &str,
    ) -> Result<Vec<ScheduleV1>> {
        use aos_assessment_runtime::read_snapshot::ScanPageError;

        // Metadata and original reviews share one observation. Oversized private
        // review sets never cross the backend boundary for projection.
        const MAX_RAW_BYTES: u64 = 8 * 1024 * 1024 - 16_384;
        let rows = self.backend.query(
            "WITH schedule_capture AS (
                SELECT schedule_id, actor_ref, resource_version, enabled, next_due_at,
                    configuration_json FROM assessment_schedules WHERE registry_id = ?1
             ), capture_bounds AS (
                SELECT COUNT(*) AS record_count, COALESCE(SUM(LENGTH(configuration_json)), 0)
                    AS byte_count FROM schedule_capture
             )
             SELECT '' AS schedule_id, '' AS actor_ref, 0 AS resource_version, 0 AS enabled,
                0 AS next_due_at, NULL AS configuration_json, record_count, byte_count, 0 AS row_kind
             FROM capture_bounds
             UNION ALL
             SELECT s.schedule_id, s.actor_ref, s.resource_version, s.enabled, s.next_due_at,
                s.configuration_json, b.record_count, b.byte_count, 1 AS row_kind
             FROM schedule_capture s CROSS JOIN capture_bounds b
             WHERE b.record_count <= 64 AND b.byte_count <= ?2
             ORDER BY row_kind, schedule_id",
            &vals![@slice registry_id, MAX_RAW_BYTES],
        ).await?;
        let bounds = rows.first().context("schedule capture bounds are absent")?;
        let record_count = bounds.get::<u64>(6)?;
        if record_count > 64 || bounds.get::<u64>(7)? > MAX_RAW_BYTES {
            return Err(ScanPageError::CapacityExceeded.into());
        }
        ensure!(
            bounds.get::<u64>(8)? == 0 && rows.len() as u64 == record_count + 1,
            "schedule capture differs from its atomic bounds"
        );
        rows.iter()
            .skip(1)
            .map(|row| project(scope, decode_record(row)?))
            .collect()
    }

    async fn schedule_record(&self, registry_id: i64, key: &str) -> Result<Option<Record>> {
        self.backend.query_opt(
            "SELECT schedule_id, actor_ref, resource_version, enabled, next_due_at, configuration_json
             FROM assessment_schedules WHERE registry_id = ?1 AND schedule_id = ?2",
            &vals![@slice registry_id, key],
        ).await?.map(|row| decode_record(&row)).transpose()
    }
}

fn decode_record(row: &crate::value::Row) -> Result<Record> {
    let bytes: Vec<u8> = row.get(5)?;
    canonical::require_canonical(&bytes, "private schedule review")?;
    let review: PrivateReview = LIMITS.decode(&bytes, "private schedule review")?;
    review.configuration.validate()?;
    if let Some(authority) = &review.service_authority {
        authority.validate(&review.claims)?;
    }
    let actor: String = row.get(1)?;
    ensure!(
        assessment_actor_ref(review.execution_principal())? == actor
            && review.authority_expires_at.unix_seconds()
                <= u64::try_from(review.execution_principal().exp)?
            && review.authority_expires_at <= review.configuration.review_expires_at,
        "private schedule authority differs from its review"
    );
    Ok(Record {
        key: row.get(0)?,
        actor,
        revision: row.get(2)?,
        enabled: row.get::<i64>(3)? == 1,
        next_due: Timestamp::from_unix_seconds(row.get(4)?)?,
        review,
    })
}

impl PrivateReview {
    fn execution_principal(&self) -> &Claims {
        self.service_authority
            .as_ref()
            .map_or(&self.claims, |authority| &authority.principal)
    }
}

fn schedule_key(scope: &str, identity: &str) -> Result<String> {
    ensure!(
        !identity.is_empty() && identity.len() <= 128 && !identity.chars().any(char::is_control),
        "invalid schedule identity"
    );
    Ok(
        Sha256Digest::of_canonical("aos.assessment-schedule-key/v1", &(scope, identity))?
            .to_string(),
    )
}

fn project(scope: &str, record: Record) -> Result<ScheduleV1> {
    ensure!(
        schedule_key(scope, &record.review.schedule_id)? == record.key,
        "schedule identity differs from its current resource"
    );
    let value = ScheduleV1 {
        schema: "aos.assessment-schedule/v1".into(),
        resource_scope: scope.into(),
        schedule_id: record.review.schedule_id,
        revision: record.revision,
        enabled: record.enabled,
        authority_expires_at: record.review.authority_expires_at,
        next_due_at: record.next_due,
        configuration: record.review.configuration,
        service_authority: record
            .review
            .service_authority
            .map(|authority| authority.receipt),
    };
    value.to_bytes()?;
    Ok(value)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "service_schedule_tests.rs"]
pub(super) mod service_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::db::assessment::{authority_tests, scans_tests};
    use aos_assessment::input::{FreshnessMode, Profile};
    use aos_assessment_runtime::scan::ScanLimits;

    async fn setup() -> Result<(
        Database,
        i64,
        Claims,
        Vec<CheckedStatement>,
        ScheduleWriteV1,
    )> {
        let (db, registry, request) = scans_tests::setup().await?;
        let claims = authority_tests::claims(&db).await?;
        let fences = db
            .assessment_iam_statements(&claims, &request.resource_scope, Permission::Read)
            .await?;
        let write = ScheduleWriteV1 {
            service_credential_id: None,
            schema: "aos.assessment-schedule-write/v1".into(),
            resource_scope: request.resource_scope,
            schedule_id: "daily-fixture".into(),
            expected_revision: 0,
            enabled: true,
            configuration: ScheduleConfigurationV1 {
                schema: "aos.assessment-schedule-configuration/v1".into(),
                packages: vec!["fixture/example".into()],
                profiles: vec![Profile::Updates],
                freshness: FreshnessMode::Offline,
                cadence_seconds: 60,
                review_expires_at: Timestamp::from_unix_seconds(u64::try_from(claims.exp)? + 3600)?,
                limits: ScanLimits::default(),
            },
        };
        Ok((db, registry, claims, fences, write))
    }

    #[tokio::test]
    async fn reviewed_due_slot_is_idempotent_private_and_fenced_by_disable() -> Result<()> {
        let (db, registry, claims, fences, mut write) = setup().await?;
        let created = db
            .write_assessment_schedule_fenced(registry, &write, &claims, &fences)
            .await?;
        assert_eq!(
            created.authority_expires_at.unix_seconds(),
            u64::try_from(claims.exp)?
        );
        let projection = String::from_utf8(created.to_bytes()?)?;
        assert!(!projection.contains(&claims.sub));
        assert!(!projection.contains("ownerIncarnation"));
        let retry = db
            .write_assessment_schedule_fenced(registry, &write, &claims, &fences)
            .await?;
        assert_eq!(created, retry);

        let key = schedule_key(&created.resource_scope, &write.schedule_id)?;
        let record = db
            .schedule_record(registry, &key)
            .await?
            .context("review")?;
        let mut due_fences = fences.clone();
        due_fences.push(db.schedule_revision_guard(registry, &record, true));
        let first_due = record.next_due.clone();
        let first = db
            .admit_due_schedule_fenced(registry, &created.resource_scope, record, &due_fences)
            .await?;
        assert_eq!(first.request.trigger, "schedule");
        assert_eq!(first.request.subjects, vec!["subject"]);
        db.assessment_scan_authority(&first).await?;
        let held = db.assessment_job_authority_guard(&first).await?;
        db.backend.execute("UPDATE assessment_schedules SET next_due_at = ?3 WHERE registry_id = ?1 AND schedule_id = ?2", &vals![@slice registry, key, first_due.unix_seconds()]).await?;
        let replay = db
            .schedule_record(registry, &key)
            .await?
            .context("interrupted slot")?;
        let second = db
            .admit_due_schedule_fenced(registry, &created.resource_scope, replay, &due_fences)
            .await?;
        assert_eq!(first.scan_id, second.scan_id);
        let current = db
            .assessment_schedule(registry, &write.schedule_id)
            .await?
            .context("advanced schedule")?;
        let now = db.assessment_database_time().await?;
        assert!((60..=66).contains(&current.next_due_at.elapsed_since(&now)?));

        write.expected_revision = current.revision;
        write.enabled = false;
        let disabled = db
            .write_assessment_schedule_fenced(registry, &write, &claims, &fences)
            .await?;
        assert_eq!(disabled.revision, 2);
        assert!(!disabled.enabled);
        assert!(db.backend.checked_batch(&[held]).await.is_err());
        assert!(db.assessment_scan_authority(&first).await.is_err());
        assert!(db
            .assessment_schedule(registry + 1, &write.schedule_id)
            .await
            .is_err());
        Ok(())
    }

    #[tokio::test]
    async fn revoked_review_cannot_write_and_stale_revision_cannot_replace() -> Result<()> {
        let (db, registry, claims, fences, mut write) = setup().await?;
        db.write_assessment_schedule_fenced(registry, &write, &claims, &fences)
            .await?;
        write.expected_revision = 7;
        write.enabled = false;
        assert!(db
            .write_assessment_schedule_fenced(registry, &write, &claims, &fences)
            .await
            .is_err());
        write.expected_revision = 1;
        authority_tests::revoke(&db, &claims, "credential").await?;
        assert!(db
            .write_assessment_schedule_fenced(registry, &write, &claims, &fences)
            .await
            .is_err());
        assert!(
            db.assessment_schedule(registry, &write.schedule_id)
                .await?
                .context("retained review")?
                .enabled
        );
        Ok(())
    }
}
