//! Private authenticated scan provenance with immutable, bounded credential expiry.
//!
//! Durable records contain claim metadata, never signed access tokens or secret
//! bytes. They authorize only their exact admitted request and require current
//! IAM again before execution and final result admission.

use anyhow::{ensure, Context as _, Result};
use aos_contract::{canonical, limits::JsonLimits, Sha256Digest};

use crate::auth::jwt::{Claims, AUTHORIZATION_CLAIMS_VERSION};
use crate::backend::{CheckedStatement, Statement};
use crate::db::{AssessmentScanRecord, Database};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct ScheduleGrant {
    pub schedule_id: String,
    pub revision: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PrivateJobAuthority {
    claims: Claims,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    schedule: Option<ScheduleGrant>,
}

const LIMITS: JsonLimits = JsonLimits {
    max_bytes: 16_384,
    max_depth: 8,
    max_items: 256,
    max_string_bytes: 512,
};

/// Computes an authenticated principal's stable, portable assessment actor.
///
/// # Errors
/// Returns an error for absent or invalid immutable principal identity or kind.
pub fn assessment_actor_ref(claims: &Claims) -> Result<String> {
    ensure!(
        matches!(claims.owner_kind.as_str(), "user" | "service_account"),
        "assessment principal kind is invalid"
    );
    let identity = uuid::Uuid::parse_str(
        claims
            .owner_incarnation
            .as_deref()
            .context("assessment principal incarnation is absent")?,
    )?;
    Ok(Sha256Digest::of_canonical(
        "aos.assessment-actor/v1",
        &(claims.owner_kind.as_str(), identity.to_string()),
    )?
    .to_string())
}

impl Database {
    /// Resolves an installed partition to its current logical registry incarnation.
    ///
    /// This internal controller lookup grants no principal permission. Jobs still
    /// require their immutable admission and current IAM before every effect.
    ///
    /// # Errors
    /// Returns an error for malformed scope, ambiguous resources or persistence.
    pub async fn assessment_registry_for_partition(&self, partition: &str) -> Result<Option<i64>> {
        ensure!(
            !partition.is_empty()
                && partition.len() <= 128
                && !partition.chars().any(char::is_control),
            "installed assessment partition is invalid"
        );
        let rows = self
            .backend
            .query(
                "SELECT registry.id FROM registries registry
             JOIN authorization_scopes scope ON scope.scope_key = registry.scope_key
             WHERE registry.scope_key = ?1
               AND scope.retired_at IS NULL LIMIT 2",
                &vals![@slice partition],
            )
            .await?;
        ensure!(
            rows.len() <= 1,
            "assessment partition has ambiguous current resources"
        );
        rows.first().map(|row| row.get(0)).transpose()
    }

    /// Enumerates a bounded page of privately admitted, currently claimable jobs.
    ///
    /// The installed coordinator independently owns this registry partition.
    /// This selection grants no permission and does not claim or refresh work.
    ///
    /// # Errors
    /// Returns an error for invalid bounds, cursor shape or unavailable persistence.
    pub async fn assessment_controller_scan_page(
        &self,
        registry_id: i64,
        after_scan: &str,
        limit: u32,
    ) -> Result<Vec<String>> {
        ensure!(
            (1..=32).contains(&limit)
                && after_scan.len() <= 128
                && !after_scan.chars().any(char::is_control),
            "assessment controller scan page exceeds its bounds"
        );
        let clock = self.backend.dialect().unix_time_expression();
        self.backend.query(&format!(
            "SELECT scan.scan_id FROM assessment_scans scan JOIN assessment_scan_authorities authority ON authority.scan_id = scan.scan_id
             WHERE scan.registry_id = ?1 AND scan.scan_id > ?2 AND scan.admission_complete = 1
               AND authority.registry_id = ?1 AND authority.request_digest = scan.request_digest
               AND authority.actor_ref = scan.actor_ref AND authority.authorization_revision = scan.authorization_revision
               AND authority.resource_scope = scan.partition_key AND authority.expires_at > {clock}
               AND (scan.state = 'queued' OR (scan.state = 'running' AND scan.lease_expires_at <= {clock}))
             ORDER BY scan.scan_id LIMIT ?3"
        ), &vals![@slice registry_id, after_scan, limit]).await?.iter().map(|row| row.get(0)).collect()
    }

    /// Retains exact authenticated job provenance while holding current IAM.
    ///
    /// The service authenticates claims and prepares exact scan permission
    /// fences. This transaction binds the immutable request and actor, current
    /// resource authorization generation, and original credential expiry. A
    /// retried submission cannot replace or extend the first job authority.
    ///
    /// # Errors
    /// Returns an error for invalid scope, expired credentials, missing current
    /// fences, changed request/resource, conflicting provenance or persistence.
    pub async fn admit_assessment_scan_authority(
        &self,
        scan: &AssessmentScanRecord,
        claims: &Claims,
        authority_fences: &[CheckedStatement],
    ) -> Result<()> {
        self.admit_assessment_job_authority(scan, claims, None, authority_fences)
            .await
    }

    pub(super) async fn admit_assessment_job_authority(
        &self,
        scan: &AssessmentScanRecord,
        claims: &Claims,
        schedule: Option<ScheduleGrant>,
        authority_fences: &[CheckedStatement],
    ) -> Result<()> {
        ensure!(
            !authority_fences.is_empty() && authority_fences.len() <= 32,
            "assessment job admission requires bounded current IAM fences"
        );
        ensure!(
            scan.admission_complete && scan.request.actor_ref == assessment_actor_ref(claims)?,
            "assessment job actor differs from authenticated admission"
        );
        ensure!(
            claims.authz_version == AUTHORIZATION_CLAIMS_VERSION,
            "assessment job authorization epoch is obsolete"
        );
        let bytes = canonical::to_vec(&PrivateJobAuthority {
            claims: claims.clone(),
            schedule,
        })?;
        LIMITS.decode::<PrivateJobAuthority>(&bytes, "assessment job provenance")?;
        let wall_deadline = scan
            .created_at
            .unix_seconds()
            .checked_add(u64::from(scan.request.limits.wall_seconds))
            .context("assessment job deadline overflowed")?;
        let expires = claims.exp.min(i64::try_from(wall_deadline)?);
        let clock = self.backend.dialect().unix_time_expression();
        let mut statements = authority_fences.to_vec();
        statements.push(Statement::new(format!(
            "UPDATE assessment_scans SET resource_version = resource_version
             WHERE scan_id = ?1 AND registry_id = ?2 AND request_digest = ?3 AND actor_ref = ?4
               AND admission_complete = 1 AND authorization_revision = ?5
               AND EXISTS(SELECT 1 FROM assessment_resources resource WHERE resource.registry_id = ?2
                 AND resource.partition_key = assessment_scans.partition_key
                 AND resource.authorization_revision = ?5 AND resource.inventory_digest = assessment_scans.inventory_digest
                 AND resource.policy_digest = assessment_scans.policy_digest) AND ?6 > {clock}"
        ), vals![scan.scan_id, scan.registry_id, scan.request_digest.to_string(), scan.request.actor_ref, scan.authorization_revision, expires]).expecting(1));
        statements.push(Statement::new(format!(
            "INSERT INTO assessment_scan_authorities(scan_id, registry_id, resource_scope, request_digest,
                actor_ref, authorization_revision, authority_json, expires_at, admitted_at)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, {clock}) ON CONFLICT(scan_id) DO UPDATE SET
                 admitted_at = assessment_scan_authorities.admitted_at
             WHERE assessment_scan_authorities.registry_id = ?2 AND assessment_scan_authorities.resource_scope = ?3
               AND assessment_scan_authorities.request_digest = ?4 AND assessment_scan_authorities.actor_ref = ?5
               AND assessment_scan_authorities.authorization_revision = ?6 AND assessment_scan_authorities.expires_at > {clock}"
        ), vals![scan.scan_id, scan.registry_id, scan.request.resource_scope, scan.request_digest.to_string(), scan.request.actor_ref, scan.authorization_revision, bytes, expires]).expecting(1));
        self.backend.checked_batch(&statements).await?;
        self.assessment_scan_authority(scan).await?;
        Ok(())
    }

    /// Reads one private authority bound to the exact admitted scan and live clock.
    ///
    /// This read grants no current IAM authority. The execution host must still
    /// check current principal, membership and credential before every effect.
    ///
    /// # Errors
    /// Returns an error for absent, expired, conflicting or malformed provenance.
    pub async fn assessment_scan_authority(&self, scan: &AssessmentScanRecord) -> Result<Claims> {
        let clock = self.backend.dialect().unix_time_expression();
        let row = self.backend.query_opt(&format!(
            "SELECT authority_json FROM assessment_scan_authorities WHERE scan_id = ?1 AND registry_id = ?2
             AND resource_scope = ?3 AND request_digest = ?4 AND actor_ref = ?5 AND authorization_revision = ?6
             AND expires_at > {clock} AND length(authority_json) <= 16384"
        ), &vals![@slice scan.scan_id, scan.registry_id, scan.request.resource_scope, scan.request_digest.to_string(), scan.request.actor_ref, scan.authorization_revision]).await?.context("assessment job provenance is absent or expired")?;
        let bytes = row.get::<Vec<u8>>(0)?;
        canonical::require_canonical(&bytes, "assessment job provenance")?;
        let provenance: PrivateJobAuthority = LIMITS.decode(&bytes, "assessment job provenance")?;
        if let Some(grant) = &provenance.schedule {
            self.assessment_schedule_live_guard(scan.registry_id, grant)
                .await?;
            if let Some(service) = self
                .assessment_schedule_service_authority(scan.registry_id, grant)
                .await?
            {
                let retained = &provenance.claims;
                let reviewed = &service.principal;
                ensure!(
                    retained.sub == reviewed.sub
                        && retained.owner_kind == reviewed.owner_kind
                        && retained.owner_id == reviewed.owner_id
                        && retained.owner_incarnation == reviewed.owner_incarnation
                        && retained.scope == reviewed.scope
                        && retained.perms == reviewed.perms
                        && retained.browser_session_id_hash.is_none()
                        && retained.exp <= reviewed.exp,
                    "job principal differs from the reviewed service delegation"
                );
                let current = self
                    .current_token_authority(&retained.sub)
                    .await?
                    .context("reviewed service credential is no longer current")?;
                ensure!(
                    current.owner.id == retained.owner_id
                        && current.owner.kind == crate::domain::PrincipalKind::ServiceAccount
                        && current.owner_incarnation == retained.owner_incarnation
                        && current.scope.as_str() == retained.scope,
                    "reviewed service credential incarnation changed"
                );
            }
        }
        let claims = provenance.claims;
        ensure!(
            claims.authz_version == AUTHORIZATION_CLAIMS_VERSION
                && assessment_actor_ref(&claims)? == scan.request.actor_ref,
            "assessment job principal differs from admitted provenance"
        );
        Ok(claims)
    }

    /// Returns current organization guards for an explicitly service-backed schedule.
    ///
    /// Absence preserves the original credential-bounded authority path. The
    /// returned guards supplement current scan IAM; they never grant permissions.
    ///
    /// # Errors
    /// Returns an error for expired provenance or a replaced/disabled review.
    pub async fn assessment_scan_service_guards(
        &self,
        scan: &AssessmentScanRecord,
    ) -> Result<Option<Vec<CheckedStatement>>> {
        self.assessment_scan_authority(scan).await?;
        let row = self.backend.query_opt(
            "SELECT authority_json FROM assessment_scan_authorities WHERE scan_id = ?1 AND registry_id = ?2",
            &vals![@slice scan.scan_id, scan.registry_id],
        ).await?.context("assessment job provenance is absent")?;
        let provenance: PrivateJobAuthority =
            LIMITS.decode(&row.get::<Vec<u8>>(0)?, "assessment job provenance")?;
        let Some(grant) = provenance.schedule else {
            return Ok(None);
        };
        let Some(service) = self
            .assessment_schedule_service_authority(scan.registry_id, &grant)
            .await?
        else {
            return Ok(None);
        };
        Ok(Some(vec![self.assessment_service_owner_guard(
            scan.registry_id,
            &service,
        )]))
    }

    /// Reads the immutable private job deadline before issuing physical work.
    ///
    /// # Errors
    /// Returns an error for absent, expired or conflicting exact job authority.
    pub async fn assessment_scan_authority_deadline(
        &self,
        scan: &AssessmentScanRecord,
    ) -> Result<aos_assessment::time::Timestamp> {
        self.assessment_scan_authority(scan).await?;
        let row = self.backend.query_opt("SELECT expires_at FROM assessment_scan_authorities WHERE scan_id = ?1 AND registry_id = ?2 AND request_digest = ?3", &vals![@slice scan.scan_id, scan.registry_id, scan.request_digest.to_string()]).await?.context("assessment job deadline is absent")?;
        aos_assessment::time::Timestamp::from_unix_seconds(row.get(0)?)
    }

    /// Builds a live authority-row guard for a final atomic scan effect.
    ///
    /// # Errors
    /// Returns an error for absent or expired exact private job provenance.
    pub async fn assessment_job_authority_guard(
        &self,
        scan: &AssessmentScanRecord,
    ) -> Result<CheckedStatement> {
        self.assessment_scan_authority(scan).await?;
        let row = self.backend.query_opt("SELECT authority_json FROM assessment_scan_authorities WHERE scan_id = ?1 AND registry_id = ?2", &vals![@slice scan.scan_id, scan.registry_id]).await?.context("assessment job provenance is absent")?;
        let provenance: PrivateJobAuthority =
            LIMITS.decode(&row.get::<Vec<u8>>(0)?, "assessment job provenance")?;
        let mut parameters = vals![
            scan.scan_id,
            scan.registry_id,
            scan.request_digest.to_string(),
            scan.request.actor_ref,
            scan.authorization_revision,
            scan.request.resource_scope
        ];
        let schedule_fence = if let Some(grant) = provenance.schedule {
            parameters.extend(vals![grant.schedule_id, grant.revision]);
            " AND EXISTS(SELECT 1 FROM assessment_schedules schedule WHERE schedule.registry_id = ?2 AND schedule.schedule_id = ?7 AND schedule.resource_version = ?8 AND schedule.enabled = 1)"
        } else {
            ""
        };
        let clock = self.backend.dialect().unix_time_expression();
        Ok(Statement::new(format!(
            "UPDATE assessment_scan_authorities SET admitted_at = admitted_at WHERE scan_id = ?1
             AND registry_id = ?2 AND request_digest = ?3 AND actor_ref = ?4 AND authorization_revision = ?5
             AND resource_scope = ?6 AND expires_at > {clock}
             AND EXISTS(SELECT 1 FROM assessment_scans scan JOIN assessment_resources resource ON resource.registry_id = scan.registry_id
               WHERE scan.scan_id = ?1 AND scan.registry_id = ?2 AND scan.admission_complete = 1
                 AND scan.state IN('queued', 'running') AND resource.partition_key = ?6
                 AND resource.authorization_revision = ?5 AND resource.inventory_digest = scan.inventory_digest
                 AND resource.inventory_revision = scan.inventory_revision AND resource.policy_digest = scan.policy_digest){schedule_fence}"
        ), parameters).expecting(1))
    }
}
