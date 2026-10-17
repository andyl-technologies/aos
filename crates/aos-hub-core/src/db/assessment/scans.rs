//! Idempotent paged scan admission, database leases and immutable cancellation.

use anyhow::{bail, Context as _, Result};
use aos_assessment::input::Profile;
use aos_assessment::time::Timestamp;
use aos_assessment_runtime::scan::{ScanRequestV1, ScanState, ScanUsage, TaskClaim};
use aos_contract::Sha256Digest;

use crate::backend::{CheckedStatement, Statement};
use crate::db::Database;
use crate::value::ToValue as _;

/// Describes one immutable request and its durable execution state.
#[derive(Clone, Debug)]
pub struct AssessmentScanRecord {
    /// Unpredictable public operation reference.
    pub scan_id: String,
    /// Exact registry key under independent service authorization.
    pub registry_id: i64,
    /// Closed immutable caller request.
    pub request: ScanRequestV1,
    /// Exact request digest checked on every read.
    pub request_digest: Sha256Digest,
    /// Monotonic desired generation.
    pub generation: u64,
    /// Independent authorization generation at admission.
    pub authorization_revision: u64,
    /// Current runtime state, independent of package risk.
    pub state: ScanState,
    /// Whether all pinned targets are durably indexed.
    pub admission_complete: bool,
    /// Monotonic attempt number.
    pub attempt: u32,
    /// Conservative operation-wide usage.
    pub usage: ScanUsage,
    /// Canonical result, when the operation committed one.
    pub assessment_digest: Option<Sha256Digest>,
    /// Bounded stable terminal diagnostic, never an exception or source response.
    pub failure_code: Option<String>,
    // Internal continuation marker never appears as a terminal API diagnostic.
    cooperative_pause: bool,
    /// Optimistic state version.
    pub resource_version: u64,
    /// Database admission time.
    pub created_at: Timestamp,
}

pub(super) fn profile_name(profile: Profile) -> &'static str {
    match profile {
        Profile::Updates => "updates",
        Profile::Vulnerabilities => "vulnerabilities",
        Profile::LicenseSignals => "license-signals",
    }
}

impl Database {
    /// Checks a coordinator claim against database time and current resource/head fences.
    ///
    /// # Errors
    /// Returns an error for stale attempts, expired/cancelled/superseded work,
    /// changed authority or unavailable persistence. A valid checksum is insufficient.
    pub async fn check_assessment_scan_claim(
        &self,
        registry_id: i64,
        claim: &TaskClaim,
    ) -> Result<()> {
        claim.validate_at(&self.assessment_database_time().await?)?;
        if claim.task_id != "coordinator" {
            bail!("coordinator fence requires its exact claim kind");
        }
        let guard = self.assessment_claim_guard();
        let row = self
            .backend
            .query_opt(
                &format!("SELECT 1 FROM assessment_scans WHERE {guard}"),
                &claim_values(registry_id, claim),
            )
            .await?;
        if row.is_none() {
            bail!("assessment claim lost its current database authority fence");
        }
        Ok(())
    }

    pub(super) fn assessment_claim_guard(&self) -> String {
        let clock = self.backend.dialect().unix_time_expression();
        format!(
            "registry_id = ?1 AND scan_id = ?2 AND claim_token = ?3 AND generation = ?4
             AND inventory_revision = ?5 AND request_digest = ?6 AND attempt = ?7
             AND lease_expires_at = ?8 AND lease_expires_at > {clock} AND state = 'running' AND admission_complete = 1
             AND EXISTS(SELECT 1 FROM assessment_resources AS resource WHERE resource.registry_id = ?1
                 AND resource.partition_key = assessment_scans.partition_key
                 AND resource.inventory_digest = assessment_scans.inventory_digest
                 AND resource.inventory_revision = assessment_scans.inventory_revision
                 AND resource.policy_digest = assessment_scans.policy_digest
                 AND resource.authorization_revision = assessment_scans.authorization_revision)
             AND NOT EXISTS(SELECT 1 FROM assessment_scan_targets AS target
                 LEFT JOIN assessment_heads AS head ON head.registry_id = ?1 AND head.inventory_digest = assessment_scans.inventory_digest
                     AND head.subject_ref = target.subject_ref AND head.profile = target.profile AND head.policy_digest = assessment_scans.policy_digest
                 WHERE target.scan_id = ?2 AND (head.desired_generation IS NULL OR head.desired_generation <> assessment_scans.generation))"
        )
    }

    /// Reads one operation without provider work or freshness mutation.
    ///
    /// # Errors
    /// Returns an error for broken request identity, malformed state or SQL failure.
    pub async fn assessment_scan(
        &self,
        registry_id: i64,
        scan_id: &str,
    ) -> Result<Option<AssessmentScanRecord>> {
        let Some(row) = self
            .backend
            .query_opt(
                "SELECT request_json, request_digest, generation, authorization_revision,
                    state, admission_complete, attempt, usage_json, assessment_digest,
                    resource_version, created_at, last_error_code
             FROM assessment_scans WHERE registry_id = ?1 AND scan_id = ?2
               AND length(request_json) <= 262144 AND length(usage_json) <= 8192",
                &vals![@slice registry_id, scan_id],
            )
            .await?
        else {
            return Ok(None);
        };
        let request = ScanRequestV1::from_slice(&row.get::<Vec<u8>>(0)?)?;
        let request_digest: Sha256Digest = Sha256Digest::parse(&row.get::<String>(1)?)?;
        if request.digest()? != request_digest {
            bail!("stored scan request identity changed");
        }
        let state: ScanState = serde_json::from_value(serde_json::Value::String(row.get(4)?))?;
        let diagnostic: Option<String> = row.get(11)?;
        Ok(Some(AssessmentScanRecord {
            scan_id: scan_id.into(),
            registry_id,
            request,
            request_digest,
            generation: row.get(2)?,
            authorization_revision: row.get(3)?,
            state,
            admission_complete: row.get(5)?,
            attempt: row.get(6)?,
            usage: serde_json::from_slice(&row.get::<Vec<u8>>(7)?)?,
            assessment_digest: row
                .get::<Option<String>>(8)?
                .map(|value| Sha256Digest::parse(&value))
                .transpose()?,
            resource_version: row.get(9)?,
            created_at: Timestamp::from_unix_seconds(row.get(10)?)?,
            cooperative_pause: diagnostic.as_deref() == Some("acquisition-paused"),
            failure_code: if matches!(
                state,
                ScanState::Failed | ScanState::Superseded | ScanState::Cancelled
            ) {
                diagnostic
            } else {
                None
            },
        }))
    }

    /// Allocates an idempotent request generation and indexes its targets in pages.
    ///
    /// The service authenticates actor/resource scope before calling. Identical
    /// retries resume hidden admission; changed content with the same actor/key
    /// is a conflict. Every head update refuses generation regression.
    ///
    /// # Errors
    /// Returns an error for mismatched authority/inventory/policy, selector gaps,
    /// idempotency conflict, exhausted generations or unavailable persistence.
    pub async fn request_assessment_scan(
        &self,
        registry_id: i64,
        request: &ScanRequestV1,
    ) -> Result<AssessmentScanRecord> {
        self.request_assessment_scan_fenced(registry_id, request, &[])
            .await
    }

    /// Admits a scan while holding current granting authority in every write page.
    ///
    /// The caller constructs exact current IAM locks and eligibility checks.
    /// Those checks run atomically with generation allocation, each target/head
    /// page and final admission. Revocation can leave a hidden resumable partial
    /// admission, but cannot authorize its remaining writes or provider dispatch.
    ///
    /// # Errors
    /// Returns an error for exceeded fence bounds, revoked granting authority,
    /// changed resource, selector or idempotency conflicts, or persistence failure.
    pub async fn request_assessment_scan_fenced(
        &self,
        registry_id: i64,
        request: &ScanRequestV1,
        authority_fences: &[CheckedStatement],
    ) -> Result<AssessmentScanRecord> {
        if authority_fences.len() > 32 {
            bail!("assessment admission authority exceeds its transaction fence bound");
        }
        if !authority_fences.is_empty() {
            self.backend.checked_batch(authority_fences).await?;
        }
        request.validate()?;
        let digest = request.digest()?;
        let registry = self
            .registry_by_id(registry_id)
            .await?
            .context("assessment registry is absent")?;
        if registry.scope_key != request.resource_scope {
            bail!("scan request differs from the current registry scope");
        }
        let previous = self
            .backend
            .query_opt(
                "SELECT scan_id, request_digest FROM assessment_scans
             WHERE registry_id = ?1 AND actor_ref = ?2 AND idempotency_key = ?3",
                &vals![@slice registry_id, request.actor_ref, request.idempotency_key],
            )
            .await?;
        if let Some(previous) = &previous {
            if previous.get::<String>(1)? != digest.to_string() {
                bail!("scan idempotency key has different request content");
            }
            let record = self
                .assessment_scan(registry_id, &previous.get::<String>(0)?)
                .await?
                .context("idempotent scan receipt disappeared")?;
            // Completed admission is an immutable receipt. Rechecking mutable
            // inventory/policy here would turn an identical retry into new work.
            // The service must still reauthorize the actor before returning it.
            if record.admission_complete || record.state.is_terminal() {
                return Ok(record);
            }
        }
        let resource = self
            .assessment_resource(registry_id)
            .await?
            .context("registry has no admitted assessment inventory")?;
        if registry.scope_key != request.resource_scope
            || resource.partition != request.authorization_partition
            || resource.inventory_revision != request.inventory_revision
            || resource.inventory_digest != request.inventory_digest
            || resource.policy_digest != request.policy_digest
        {
            bail!("scan request differs from the current admitted resource authority");
        }
        let inventory_bytes = self
            .assessment_object(
                &resource.partition,
                super::AssessmentObjectKind::Inventory,
                request.inventory_digest,
            )
            .await?
            .context("admitted inventory custody is absent")?;
        let inventory =
            aos_assessment::scan_inventory::ScanInventoryV1::from_slice(&inventory_bytes)?;
        let subjects: std::collections::BTreeSet<_> = inventory
            .subjects
            .iter()
            .map(|subject| subject.subject_ref.as_str())
            .collect();
        if request
            .subjects
            .iter()
            .any(|subject| !subjects.contains(subject.as_str()))
        {
            bail!("scan selector includes a subject absent from the exact admitted inventory");
        }
        let scan_id = if let Some(previous) = previous {
            if previous.get::<String>(1)? != digest.to_string() {
                bail!("scan idempotency key has different request content");
            }
            previous.get::<String>(0)?
        } else {
            if resource.next_generation >= 9_007_199_254_740_991 {
                bail!("scan generation exhausted");
            }
            let scan_id = uuid::Uuid::new_v4().simple().to_string();
            let now = self.assessment_database_time().await?.unix_seconds();
            let mut statements = authority_fences.to_vec();
            statements.extend([
                Statement::new(
                    "UPDATE assessment_resources SET next_generation = next_generation + 1,
                         resource_version = resource_version + 1, updated_at = ?7
                     WHERE registry_id = ?1 AND partition_key = ?2 AND inventory_digest = ?3
                       AND policy_digest = ?4 AND resource_version = ?5 AND next_generation = ?6",
                    vals![registry_id, resource.partition, resource.inventory_digest.to_string(), resource.policy_digest.to_string(),
                        resource.resource_version, resource.next_generation, now],
                ).expecting(1),
                Statement::new(
                    "INSERT INTO assessment_scans
                        (scan_id, registry_id, partition_key, request_digest, request_json, generation,
                         inventory_revision, inventory_digest, policy_digest, authorization_revision,
                         actor_ref, idempotency_key, state, attempt, usage_json, resource_version, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 'queued', 0, ?13, 1, ?14, ?14)",
                    vals![scan_id, registry_id, resource.partition, digest.to_string(), aos_contract::canonical::to_vec(request)?,
                        resource.next_generation, resource.inventory_revision, resource.inventory_digest.to_string(), resource.policy_digest.to_string(),
                        resource.authorization_revision, request.actor_ref, request.idempotency_key, serde_json::to_vec(&ScanUsage::default())?, now],
                ).expecting(1),
            ]);
            let admission = self.backend.checked_batch(&statements).await;
            if let Err(error) = admission {
                if !authority_fences.is_empty() {
                    self.backend.checked_batch(authority_fences).await?;
                }
                let winner = self
                    .backend
                    .query_opt(
                        "SELECT scan_id, request_digest FROM assessment_scans
                     WHERE registry_id = ?1 AND actor_ref = ?2 AND idempotency_key = ?3",
                        &vals![@slice registry_id, request.actor_ref, request.idempotency_key],
                    )
                    .await?;
                match winner {
                    Some(winner) if winner.get::<String>(1)? == digest.to_string() => {
                        winner.get::<String>(0)?
                    }
                    Some(_) => bail!("scan idempotency key has different request content"),
                    None => return Err(error),
                }
            } else {
                scan_id
            }
        };
        let record = self
            .assessment_scan(registry_id, &scan_id)
            .await?
            .context("admitted scan disappeared")?;
        if record.admission_complete || record.state.is_terminal() {
            return Ok(record);
        }
        let resource_guard = Statement::new(
            "UPDATE assessment_resources SET updated_at = updated_at
             WHERE registry_id = ?1 AND partition_key = ?2 AND inventory_digest = ?3
               AND policy_digest = ?4 AND inventory_revision = ?5 AND authorization_revision = ?6",
            vals![
                registry_id,
                resource.partition,
                request.inventory_digest.to_string(),
                request.policy_digest.to_string(),
                request.inventory_revision,
                record.authorization_revision
            ],
        )
        .expecting(1);
        let mut page = Vec::with_capacity(90);
        for subject in &request.subjects {
            for profile in &request.profiles {
                // A subject must be present in the exact ready inventory. The
                // target insert and head initialization share the same page.
                page.push(Statement::new(
                    "INSERT INTO assessment_scan_targets(scan_id, subject_ref, profile)
                     SELECT ?1, ?2, ?3 FROM assessment_subjects AS subject
                     JOIN assessment_inventory_sets AS inventory ON inventory.registry_id = subject.registry_id
                       AND inventory.inventory_digest = subject.inventory_digest
                     WHERE subject.registry_id = ?4 AND subject.inventory_digest = ?5 AND subject.subject_ref = ?2
                       AND inventory.state = 'ready'
                     ON CONFLICT(scan_id, subject_ref, profile) DO NOTHING",
                    vals![scan_id, subject, profile_name(*profile), registry_id, request.inventory_digest.to_string()],
                ));
                page.push(Statement::new(
                    "INSERT INTO assessment_heads
                        (registry_id, inventory_digest, subject_ref, profile, policy_digest,
                         desired_generation, committed_generation, resource_version, updated_at)
                     SELECT ?1, ?2, ?3, ?4, ?5, ?6, 0, 1, ?7 FROM assessment_scan_targets
                     WHERE scan_id = ?8 AND subject_ref = ?3 AND profile = ?4
                     ON CONFLICT(registry_id, inventory_digest, subject_ref, profile, policy_digest) DO NOTHING",
                    vals![registry_id, request.inventory_digest.to_string(), subject, profile_name(*profile), request.policy_digest.to_string(),
                        record.generation, record.created_at.unix_seconds(), scan_id],
                ));
                page.push(Statement::new(
                    "UPDATE assessment_heads SET desired_generation = ?6, resource_version = resource_version + 1, updated_at = ?7
                     WHERE registry_id = ?1 AND inventory_digest = ?2 AND subject_ref = ?3 AND profile = ?4
                       AND policy_digest = ?5 AND desired_generation < ?6",
                    vals![registry_id, request.inventory_digest.to_string(), subject, profile_name(*profile), request.policy_digest.to_string(),
                        record.generation, record.created_at.unix_seconds()],
                ));
                if page.len() == 90 {
                    let mut statements = authority_fences.to_vec();
                    statements.push(resource_guard.clone());
                    statements.extend(page.iter().cloned().map(Statement::unchecked));
                    self.backend.checked_batch(&statements).await?;
                    page.clear();
                }
            }
        }
        if !page.is_empty() {
            let mut statements = authority_fences.to_vec();
            statements.push(resource_guard.clone());
            statements.extend(page.into_iter().map(Statement::unchecked));
            self.backend.checked_batch(&statements).await?;
        }
        let mut statements = authority_fences.to_vec();
        statements.push(resource_guard);
        statements.push(Statement::new(
            "UPDATE assessment_scans SET admission_complete = 1, resource_version = resource_version + 1
             WHERE scan_id = ?1 AND state = 'queued' AND admission_complete = 0
               AND (SELECT count(*) FROM assessment_scan_targets WHERE scan_id = ?1) = ?2",
            vals![scan_id, (request.subjects.len() * request.profiles.len()) as u64],
        ).expecting(1));
        let completed = self.backend.checked_batch(&statements).await;
        if let Err(error) = completed {
            if !authority_fences.is_empty() {
                self.backend.checked_batch(authority_fences).await?;
            }
            let current = self.assessment_scan(registry_id, &scan_id).await?;
            if !current
                .is_some_and(|record| record.admission_complete && record.request_digest == digest)
            {
                return Err(error);
            }
        }
        self.assessment_scan(registry_id, &scan_id)
            .await?
            .context("indexed scan is absent")
    }

    /// Claims an admitted operation with an exclusive database-clock lease.
    ///
    /// # Errors
    /// Returns an error for invalid lease duration, lost generation/authority,
    /// exhausted attempts, terminal work or unavailable persistence.
    pub async fn claim_assessment_scan(
        &self,
        registry_id: i64,
        scan_id: &str,
        lease_seconds: u32,
    ) -> Result<TaskClaim> {
        if !(1..=900).contains(&lease_seconds) {
            bail!("scan lease duration is invalid");
        }
        let record = self
            .assessment_scan(registry_id, scan_id)
            .await?
            .context("scan is absent")?;
        let now = self.assessment_database_time().await?;
        let expires_at =
            Timestamp::from_unix_seconds(now.unix_seconds() + u64::from(lease_seconds))?;
        let token = uuid::Uuid::new_v4().simple().to_string();
        let clock = self.backend.dialect().unix_time_expression();
        let sql = format!(
            "UPDATE assessment_scans SET state = 'running', claim_token = ?3, lease_expires_at = ?4,
                 attempt = attempt + CASE WHEN last_error_code = 'acquisition-paused' THEN 0 ELSE 1 END,
                 last_error_code = NULL, updated_at = {clock}, resource_version = resource_version + 1
             WHERE registry_id = ?1 AND scan_id = ?2 AND admission_complete = 1 AND attempt < 100
               AND resource_version = ?5 AND ?4 > {clock}
               AND (state = 'queued' OR (state = 'running' AND lease_expires_at <= {clock}))
               AND EXISTS(SELECT 1 FROM assessment_resources AS resource WHERE resource.registry_id = ?1
                   AND resource.inventory_digest = assessment_scans.inventory_digest AND resource.inventory_revision = assessment_scans.inventory_revision
                   AND resource.policy_digest = assessment_scans.policy_digest AND resource.authorization_revision = assessment_scans.authorization_revision)
               AND NOT EXISTS(SELECT 1 FROM assessment_scan_targets AS target
                   JOIN assessment_heads AS head ON head.registry_id = ?1 AND head.inventory_digest = assessment_scans.inventory_digest
                       AND head.subject_ref = target.subject_ref AND head.profile = target.profile AND head.policy_digest = assessment_scans.policy_digest
                   WHERE target.scan_id = ?2 AND head.desired_generation <> assessment_scans.generation)"
        );
        self.backend
            .checked_batch(&[Statement::new(
                sql,
                vals![
                    registry_id,
                    scan_id,
                    token,
                    expires_at.unix_seconds(),
                    record.resource_version
                ],
            )
            .expecting(1)])
            .await?;
        Ok(TaskClaim {
            scan_id: scan_id.into(),
            task_id: "coordinator".into(),
            request_digest: record.request_digest,
            generation: record.generation,
            inventory_revision: record.request.inventory_revision,
            claim_token: token,
            expires_at,
            attempt: record.attempt + u32::from(!record.cooperative_pause),
        })
    }

    /// Renews one live coordinator attempt while holding current authority.
    ///
    /// Renewal preserves its token, generation and attempt. It cannot revive an
    /// expired lease, extend the original job deadline, or outlive cancellation.
    /// The returned claim replaces the old exact expiry fence.
    ///
    /// # Errors
    /// Returns an error for invalid bounds, lost claims, revoked authority,
    /// exhausted wall time, or unavailable persistence.
    pub async fn renew_assessment_scan_fenced(
        &self,
        registry_id: i64,
        claim: &TaskClaim,
        lease_seconds: u32,
        authority_deadline: &Timestamp,
        authority_fences: &[crate::backend::CheckedStatement],
    ) -> Result<TaskClaim> {
        if !(1..=900).contains(&lease_seconds) || authority_fences.len() > 32 {
            bail!("assessment lease renewal exceeds its bounds");
        }
        self.check_assessment_scan_claim(registry_id, claim).await?;
        let scan = self
            .assessment_scan(registry_id, &claim.scan_id)
            .await?
            .context("assessment renewal scan is absent")?;
        let now = self.assessment_database_time().await?;
        let wall = scan
            .created_at
            .unix_seconds()
            .checked_add(u64::from(scan.request.limits.wall_seconds))
            .context("assessment renewal deadline overflowed")?;
        let deadline = now
            .unix_seconds()
            .checked_add(u64::from(lease_seconds))
            .context("assessment renewal expiry overflowed")?
            .min(authority_deadline.unix_seconds())
            .min(wall);
        if deadline <= claim.expires_at.unix_seconds() {
            bail!("assessment renewal cannot advance within original authority");
        }
        let mut values = claim_values(registry_id, claim);
        values.push(deadline.to_value());
        let clock = self.backend.dialect().unix_time_expression();
        let mut statements = authority_fences.to_vec();
        statements.push(
            Statement::new(
                format!(
                    "UPDATE assessment_scans SET lease_expires_at = ?9, updated_at = {clock},
                 resource_version = resource_version + 1
             WHERE {} AND ?9 > {clock} AND ?9 <= created_at + ?10",
                    self.assessment_claim_guard()
                ),
                {
                    values.push(scan.request.limits.wall_seconds.to_value());
                    values
                },
            )
            .expecting(1),
        );
        self.backend.checked_batch(&statements).await?;
        let mut renewed = claim.clone();
        renewed.expires_at = Timestamp::from_unix_seconds(deadline)?;
        Ok(renewed)
    }

    /// Releases a live coordinator quantum without completing its assessment.
    ///
    /// The exact old claim becomes unusable immediately. Independently admitted
    /// child results and consumed quota remain immutable; unfinished physical
    /// attempts must settle before a host can yield.
    ///
    /// # Errors
    /// Returns an error for stale or revoked authority, active child effects,
    /// excessive guards or unavailable persistence.
    pub async fn pause_assessment_scan_fenced(
        &self,
        registry_id: i64,
        claim: &TaskClaim,
        authority_fences: &[CheckedStatement],
    ) -> Result<()> {
        if authority_fences.len() > 32 {
            bail!("assessment pause exceeds its authority bound");
        }
        self.check_assessment_scan_claim(registry_id, claim).await?;
        let clock = self.backend.dialect().unix_time_expression();
        let mut statements = authority_fences.to_vec();
        statements.push(
            Statement::new(
                format!(
                    "UPDATE assessment_scans SET lease_expires_at = {clock}, updated_at = {clock},
                 last_error_code = CASE WHEN checkpoint_digest IS NOT NULL THEN 'acquisition-paused' ELSE last_error_code END,
                 resource_version = resource_version + 1
             WHERE {} AND NOT EXISTS(SELECT 1 FROM assessment_tasks AS task
                 WHERE task.scan_id = ?2 AND task.state = 'leased'
                   AND task.lease_expires_at > {clock})",
                    self.assessment_claim_guard()
                ),
                claim_values(registry_id, claim),
            )
            .expecting(1),
        );
        self.backend.checked_batch(&statements).await
    }

    /// Fences cancellation immediately without mutating prior assessment heads.
    ///
    /// # Errors
    /// Returns an error for missing/terminal work, stale resource version or SQL failure.
    pub async fn cancel_assessment_scan(
        &self,
        registry_id: i64,
        scan_id: &str,
        expected_version: u64,
    ) -> Result<()> {
        self.cancel_assessment_scan_fenced(registry_id, scan_id, expected_version, &[])
            .await
    }

    /// Cancels an operation while holding its current granting authority atomically.
    ///
    /// # Errors
    /// Returns an error for exceeded fence bounds, revoked authority, missing or
    /// terminal operations, changed resource version, or persistence failure.
    pub async fn cancel_assessment_scan_fenced(
        &self,
        registry_id: i64,
        scan_id: &str,
        expected_version: u64,
        authority_fences: &[CheckedStatement],
    ) -> Result<()> {
        if authority_fences.len() > 32 {
            bail!("assessment cancellation authority exceeds its transaction fence bound");
        }
        let clock = self.backend.dialect().unix_time_expression();
        let mut statements = authority_fences.to_vec();
        statements.push(Statement::new(format!(
            "UPDATE assessment_scans SET state = 'cancelling', claim_token = NULL, lease_expires_at = NULL,
                 updated_at = {clock}, resource_version = resource_version + 1
             WHERE registry_id = ?1 AND scan_id = ?2 AND resource_version = ?3 AND state IN('queued', 'running', 'cancelling')"
        ), vals![registry_id, scan_id, expected_version]).expecting(1));
        statements.extend(self.assessment_cancellation_statements(registry_id, scan_id));
        self.backend.checked_batch(&statements).await
    }
    /// Settles cancellation after physical attempts report completion or expire.
    ///
    /// # Errors
    /// Returns an error for persistence failure. Live reserved attempts keep the
    /// operation cancelling; historical evidence and consumed quota are retained.
    pub async fn settle_assessment_scan_cancellation(
        &self,
        registry_id: i64,
        scan_id: &str,
    ) -> Result<()> {
        self.backend
            .checked_batch(&self.assessment_cancellation_statements(registry_id, scan_id))
            .await
    }

    fn assessment_cancellation_statements(
        &self,
        registry_id: i64,
        scan_id: &str,
    ) -> Vec<crate::backend::CheckedStatement> {
        let clock = self.backend.dialect().unix_time_expression();
        vec![
            Statement::new(format!(
                "UPDATE assessment_tasks SET state = 'cancelled', claim_token = NULL,
                     lease_expires_at = NULL, resource_version = resource_version + 1
                 WHERE scan_id = ?2 AND EXISTS(SELECT 1 FROM assessment_scans
                     WHERE registry_id = ?1 AND scan_id = ?2 AND state = 'cancelling')
                   AND (state IN('pending', 'waiting') OR (state = 'leased' AND
                       (lease_expires_at <= {clock} OR EXISTS(SELECT 1 FROM assessment_budget_reservations
                           WHERE reservation_id = assessment_tasks.reservation_id AND deadline <= {clock}))))"
            ), vals![registry_id, scan_id]).unchecked(),
            Statement::new(format!(
                "UPDATE assessment_scans SET state = 'cancelled', completed_at = {clock}, updated_at = {clock},
                     resource_version = resource_version + 1
                 WHERE registry_id = ?1 AND scan_id = ?2 AND state = 'cancelling'
                   AND NOT EXISTS(SELECT 1 FROM assessment_tasks WHERE scan_id = ?2 AND state IN('pending', 'leased', 'waiting'))"
            ), vals![registry_id, scan_id]).unchecked(),
        ]
    }
}

pub(super) fn claim_values(registry_id: i64, claim: &TaskClaim) -> Vec<crate::value::Value> {
    vals![
        registry_id,
        claim.scan_id,
        claim.claim_token,
        claim.generation,
        claim.inventory_revision,
        claim.request_digest.to_string(),
        claim.attempt,
        claim.expires_at.unix_seconds()
    ]
}
