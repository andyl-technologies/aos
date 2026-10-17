//! Single-statement status capture with immutable scoped continuations.
//!
//! Heads and pending state are captured together; continuation never revisits
//! current heads, source allowances or freshness time. Indexed metadata admission
//! bounds row/text volume before capture, and immutable custody enforces its own
//! finite encoding, retention and concurrent insertion limits.

use std::collections::BTreeMap;

use anyhow::{ensure, Context as _, Result};
use aos_assessment::time::Timestamp;
use aos_assessment_runtime::application::retained::{
    parse_status_cursor, StatusPageV2, StatusQueryV2, StatusReadSnapshotV1, STATUS_READ_SNAPSHOT_V1,
};
use aos_assessment_runtime::application::{AssessmentStatusV1, ProfileStatus, SubjectStatus};
use aos_assessment_runtime::read_snapshot::ScanPageError;
use aos_contract::Sha256Digest;

use super::{scans::profile_name, AssessmentObjectKind};
use crate::db::Database;

impl Database {
    /// Reads retained status pages under one original finite observation.
    ///
    /// The service independently checks current registry and read authority.
    /// First-page capture also requires current publication fences; continuations
    /// describe historical status within the same authorized resource incarnation.
    ///
    /// # Errors
    /// Returns an error for changed selectors, expired or forged handles, missing
    /// custody, excessive metadata/storage bounds, concurrent input or persistence.
    pub async fn assessment_retained_status_page(
        &self,
        registry_id: i64,
        query: &StatusQueryV2,
    ) -> Result<Option<StatusPageV2>> {
        query.validate()?;
        let Some(registry) = self.registry_by_id(registry_id).await? else {
            return Ok(None);
        };
        if query
            .resource_scope
            .as_ref()
            .is_some_and(|scope| scope != &registry.scope_key)
        {
            return Err(ScanPageError::SelectorChanged.into());
        }
        if let Some(cursor) = &query.cursor {
            let (digest, _) = parse_status_cursor(cursor)?;
            let bytes = self
                .assessment_object(
                    &registry.scope_key,
                    AssessmentObjectKind::StatusReadSnapshot,
                    digest,
                )
                .await?
                .ok_or(ScanPageError::CursorExpired)?;
            return StatusReadSnapshotV1::from_slice(&bytes)?
                .page(query, &self.assessment_database_time().await?)
                .map(Some);
        }

        let Some(resource) = self.assessment_resource(registry_id).await? else {
            return Ok(None);
        };
        if resource.partition != registry.scope_key
            || query
                .inventory_digest
                .is_some_and(|digest| digest != resource.inventory_digest)
            || query
                .policy_digest
                .is_some_and(|digest| digest != resource.policy_digest)
        {
            return Err(ScanPageError::SelectorChanged.into());
        }
        // SQLite LENGTH(text) counts characters. Admission counts bytes even
        // for multibyte metadata, using each backend's native byte expression.
        let metadata_bytes = [
            "subject_ref",
            "package_coordinate",
            "package_version",
            "platform",
            "output_name",
        ]
        .iter()
        .map(|column| match self.backend.dialect() {
            crate::dialect::Dialect::Sqlite => format!("LENGTH(CAST({column} AS BLOB))"),
            crate::dialect::Dialect::Postgres | crate::dialect::Dialect::Mysql => {
                format!("OCTET_LENGTH({column})")
            }
        })
        .collect::<Vec<_>>()
        .join(" + ");
        let metadata = self
            .backend
            .query_opt(
                &format!(
                    "SELECT COUNT(*), COALESCE(SUM({metadata_bytes}), 0)
             FROM (SELECT subject_ref, package_coordinate, package_version, platform, output_name
                 FROM assessment_subjects WHERE registry_id = ?1 AND inventory_digest = ?2
                 ORDER BY subject_ref LIMIT 10001) AS selected"
                ),
                &vals![@slice registry_id, resource.inventory_digest.to_string()],
            )
            .await?
            .context("status capture metadata is absent")?;
        if metadata.get::<u64>(0)? > 10_000 || metadata.get::<u64>(1)? > 4 * 1024 * 1024 {
            return Err(ScanPageError::CapacityExceeded.into());
        }
        let first = *query
            .profiles
            .first()
            .context("status profiles are absent")?;
        let profiles = [
            first,
            *query.profiles.get(1).unwrap_or(&first),
            *query.profiles.get(2).unwrap_or(&first),
        ];
        let clock = self.backend.dialect().unix_time_expression();
        // One statement observes all selected heads and their pending scans. The
        // closed digest projections also bound corrupt cells before row transfer.
        let rows = self.backend.query(
            &format!("WITH selected AS (
                SELECT subject_ref, package_coordinate, package_version, platform, output_name
                FROM assessment_subjects WHERE registry_id = ?1 AND inventory_digest = ?2
                ORDER BY subject_ref LIMIT 10001)
             SELECT subject.subject_ref, subject.package_coordinate, subject.package_version,
                subject.platform, subject.output_name, head.profile, head.desired_generation,
                head.committed_generation,
                CASE WHEN head.assessment_digest IS NULL OR LENGTH(head.assessment_digest) <= 71 THEN head.assessment_digest ELSE 'invalid' END,
                CASE WHEN head.input_digest IS NULL OR LENGTH(head.input_digest) <= 71 THEN head.input_digest ELSE 'invalid' END,
                head.validated_until,
                EXISTS(SELECT 1 FROM assessment_scans AS scan
                    JOIN assessment_scan_targets AS target ON target.scan_id = scan.scan_id
                    WHERE scan.registry_id = ?1 AND scan.inventory_digest = ?2
                        AND scan.policy_digest = ?3 AND scan.generation = head.desired_generation
                        AND target.subject_ref = subject.subject_ref AND target.profile = head.profile
                        AND scan.admission_complete = 1 AND scan.state IN ('queued', 'running', 'cancelling')),
                {clock}
             FROM selected AS subject LEFT JOIN assessment_heads AS head
                ON head.registry_id = ?1 AND head.inventory_digest = ?2 AND head.policy_digest = ?3
                    AND head.subject_ref = subject.subject_ref AND head.profile IN (?4, ?5, ?6)
             ORDER BY subject.subject_ref, head.profile LIMIT 30001"),
            &vals![@slice registry_id, resource.inventory_digest.to_string(), resource.policy_digest.to_string(),
                profile_name(profiles[0]), profile_name(profiles[1]), profile_name(profiles[2])],
        ).await?;
        let as_of = if let Some(row) = rows.first() {
            Timestamp::from_unix_seconds(row.get(12)?)?
        } else {
            self.assessment_database_time().await?
        };
        let mut subjects = BTreeMap::<String, SubjectStatus>::new();
        for row in rows {
            ensure!(
                row.get::<u64>(12)? == as_of.unix_seconds(),
                "status capture observation time changed"
            );
            let subject_ref: String = row.get(0)?;
            let subject = subjects
                .entry(subject_ref.clone())
                .or_insert(SubjectStatus {
                    subject_ref,
                    package_coordinate: row.get(1)?,
                    version: row.get(2)?,
                    platform: row.get(3)?,
                    output: row.get(4)?,
                    profiles: query
                        .profiles
                        .iter()
                        .map(|profile| ProfileStatus {
                            profile: *profile,
                            desired_generation: 0,
                            committed_generation: 0,
                            assessment_digest: None,
                            input_digest: None,
                            validated_until: None,
                            fresh: false,
                            pending: false,
                        })
                        .collect(),
                });
            if let Some(name) = row.get::<Option<String>>(5)? {
                let state = subject
                    .profiles
                    .iter_mut()
                    .find(|state| profile_name(state.profile) == name)
                    .context("status capture returned an unselected profile")?;
                state.desired_generation = row.get(6)?;
                state.committed_generation = row.get(7)?;
                state.assessment_digest = row
                    .get::<Option<String>>(8)?
                    .map(|digest| Sha256Digest::parse(&digest))
                    .transpose()?;
                state.input_digest = row
                    .get::<Option<String>>(9)?
                    .map(|digest| Sha256Digest::parse(&digest))
                    .transpose()?;
                state.validated_until = row
                    .get::<Option<u64>>(10)?
                    .map(Timestamp::from_unix_seconds)
                    .transpose()?;
                state.fresh = state
                    .validated_until
                    .as_ref()
                    .is_some_and(|deadline| as_of < *deadline);
                state.pending =
                    state.desired_generation > state.committed_generation && row.get::<bool>(11)?;
            }
        }
        if subjects.len() > 10_000 {
            return Err(ScanPageError::CapacityExceeded.into());
        }
        let source_status = self
            .assessment_source_status(&registry.scope_key, &as_of)
            .await?;
        if self.assessment_resource(registry_id).await?.as_ref() != Some(&resource) {
            return Err(ScanPageError::SelectorChanged.into());
        }
        let mut base = AssessmentStatusV1 {
            schema: "aos.assessment-status/v1".into(),
            resource_scope: registry.scope_key.clone(),
            inventory_digest: resource.inventory_digest,
            inventory_revision: resource.inventory_revision,
            policy_digest: resource.policy_digest,
            as_of: as_of.clone(),
            source_status,
            subjects: vec![],
            next_subject: None,
        };
        let subjects = subjects.into_values().collect::<Vec<_>>();
        let pages = if subjects.is_empty() {
            vec![base]
        } else {
            subjects
                .chunks(query.limit as usize)
                .map(|subjects| {
                    base.subjects = subjects.to_vec();
                    base.clone()
                })
                .collect::<Vec<_>>()
        };
        let mut selection = query.clone();
        selection.resource_scope = Some(registry.scope_key.clone());
        let snapshot = StatusReadSnapshotV1 {
            schema: STATUS_READ_SNAPSHOT_V1.into(),
            selection,
            expires_at: Timestamp::from_unix_seconds(
                as_of
                    .unix_seconds()
                    .checked_add(900)
                    .context("status capture deadline overflow")?,
            )?,
            page_handles: (1..pages.len())
                .map(|_| uuid::Uuid::new_v4().simple().to_string())
                .collect(),
            pages,
        };
        let page = snapshot.page(query, &as_of)?;
        if !snapshot.page_handles.is_empty() {
            if let Err(error) = self
                .put_assessment_object(
                    &registry.scope_key,
                    AssessmentObjectKind::StatusReadSnapshot,
                    snapshot.digest()?,
                    &snapshot.to_bytes()?,
                    i64::try_from(as_of.unix_seconds())?,
                )
                .await
            {
                let count: u64 = self.backend.query_opt("SELECT COUNT(*) FROM assessment_objects WHERE partition_key = ?1 AND object_kind = ?2",
                    &vals![@slice registry.scope_key, STATUS_READ_SNAPSHOT_V1]).await?.context("status capture count")?.get(0)?;
                if count >= 16 {
                    return Err(ScanPageError::CapacityExceeded.into());
                }
                return Err(error);
            }
        }
        Ok(Some(page))
    }
}
