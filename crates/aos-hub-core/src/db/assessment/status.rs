//! Bounded database status projections without implicit provider acquisition.

use anyhow::{bail, Context as _, Result};
use aos_assessment::input::Profile;
use aos_assessment::time::Timestamp;
use aos_assessment_runtime::scan::ScanState;
use aos_contract::Sha256Digest;

use super::scans::profile_name;
use crate::db::Database;

/// Describes one independently selected profile's current and desired generations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssessmentProfileStatus {
    /// Independently requested assessment profile.
    pub profile: Profile,
    /// Latest desired generation, or zero when never requested.
    pub desired_generation: u64,
    /// Latest successfully committed generation, or zero when unassessed.
    pub committed_generation: u64,
    /// Exact retained result, absent when unassessed.
    pub assessment_digest: Option<Sha256Digest>,
    /// Exact frozen input, absent when unassessed.
    pub input_digest: Option<Sha256Digest>,
    /// Exclusive policy/source freshness deadline for complete coverage only.
    pub validated_until: Option<Timestamp>,
    /// Whether complete evidence remains fresh at this page's database time.
    pub fresh: bool,
    /// Whether a newer desired generation still has an active scan.
    pub pending: bool,
}

/// Groups selected profile status for one exact admitted subject.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssessmentSubjectStatus {
    /// Portable subject identity within the active immutable inventory.
    pub subject_ref: String,
    /// Exact publisher-scoped package coordinate from the admitted inventory.
    pub package_coordinate: String,
    /// Exact AOS version admitted for this subject.
    pub version: String,
    /// Exact target platform of this subject.
    pub platform: String,
    /// Exact package output or aggregate name.
    pub output: String,
    /// Selected independently evaluated profiles in canonical order.
    pub profiles: Vec<AssessmentProfileStatus>,
}

/// Returns a finite status page with an exact inventory and observation time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssessmentStatusPage {
    /// Database time used for every effective freshness projection in this page.
    pub as_of: Timestamp,
    /// Exact resource revision used for this status query.
    pub resource: super::AssessmentResource,
    /// Status for admitted subjects, including unassessed inventory.
    pub subjects: Vec<AssessmentSubjectStatus>,
    /// Exclusive next subject cursor; absent only on the final page.
    pub next_subject: Option<String>,
}

/// Describes a scan list row without copying its full selector or evidence graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssessmentScanSummary {
    /// Public unpredictable operation identity.
    pub scan_id: String,
    /// Exact immutable request identity available from the operation detail read.
    pub request_digest: Sha256Digest,
    /// Current runtime state, independent of package coverage or risk.
    pub state: ScanState,
    /// Monotonic desired generation.
    pub generation: u64,
    /// Current state revision used for cancellation.
    pub resource_version: u64,
    /// Database admission time.
    pub created_at: Timestamp,
    /// Exact committed result, when available.
    pub assessment_digest: Option<Sha256Digest>,
}

impl Database {
    /// Checks whether an exact assessment has a successful scoped admission.
    ///
    /// A retained or imported object alone never establishes Hub authority.
    /// The service separately checks current read access to this registry.
    ///
    /// # Errors
    /// Returns an error for unavailable or malformed persistence.
    pub async fn has_admitted_assessment(
        &self,
        registry_id: i64,
        digest: Sha256Digest,
    ) -> Result<bool> {
        Ok(self.backend.query_opt(
            "SELECT 1 FROM assessment_scans WHERE registry_id = ?1 AND state IN ('succeeded', 'partial') AND assessment_digest = ?2 LIMIT 1",
            &vals![@slice registry_id, digest.to_string()],
        ).await?.is_some())
    }

    /// Reads a bounded inventory-complete status page for selected profiles.
    ///
    /// The caller independently authorizes the registry. A missing head is an
    /// unassessed subject, rather than an absent inventory member or clean result.
    /// Resource replacement during the read rejects the page for an explicit retry.
    ///
    /// # Errors
    /// Returns an error for invalid cursors/profiles/limits, missing inventory,
    /// changed resource versions or unavailable persistence.
    pub async fn assessment_status_page(
        &self,
        registry_id: i64,
        profiles: &[Profile],
        after_subject: &str,
        limit: u32,
    ) -> Result<AssessmentStatusPage> {
        validate_page(after_subject, limit)?;
        if profiles.is_empty()
            || profiles.len() > 3
            || profiles.windows(2).any(|pair| pair[0] >= pair[1])
        {
            bail!("assessment status profiles must be sorted and unique");
        }
        let resource = self
            .assessment_resource(registry_id)
            .await?
            .context("assessment inventory is absent")?;
        let rows = self.backend.query(
            "SELECT subject_ref, package_coordinate, package_version, platform, output_name FROM assessment_subjects WHERE registry_id = ?1 AND inventory_digest = ?2
             AND subject_ref > ?3 ORDER BY subject_ref LIMIT ?4",
            &vals![@slice registry_id, resource.inventory_digest.to_string(), after_subject, u64::from(limit) + 1],
        ).await?;
        let mut subjects = Vec::with_capacity(limit as usize);
        let has_more = rows.len() > limit as usize;
        let last = rows
            .iter()
            .take(limit as usize)
            .next_back()
            .map(|row| row.get::<String>(0))
            .transpose()?;
        let heads = if let Some(last) = &last {
            self.backend.query(
                "SELECT head.subject_ref, head.profile, head.desired_generation, head.committed_generation, head.assessment_digest,
                    head.input_digest, head.validated_until,
                    EXISTS(SELECT 1 FROM assessment_scans AS scan
                        JOIN assessment_scan_targets AS target ON target.scan_id = scan.scan_id
                        WHERE scan.registry_id = head.registry_id AND scan.inventory_digest = head.inventory_digest
                          AND scan.policy_digest = head.policy_digest AND scan.generation = head.desired_generation
                          AND target.subject_ref = head.subject_ref AND target.profile = head.profile
                          AND scan.admission_complete = 1 AND scan.state IN('queued', 'running', 'cancelling'))
                 FROM assessment_heads AS head
                 WHERE head.registry_id = ?1 AND head.inventory_digest = ?2 AND head.policy_digest = ?3
                   AND head.subject_ref > ?4 AND head.subject_ref <= ?5 ORDER BY head.subject_ref, head.profile LIMIT ?6",
                &vals![@slice registry_id, resource.inventory_digest.to_string(), resource.policy_digest.to_string(), after_subject, last, u64::from(limit) * 3],
            ).await?
        } else {
            Vec::new()
        };
        // Read time after the rows so a just-committed result cannot appear
        // to have been evaluated after the page's declared observation time.
        let now = self.assessment_database_time().await?;
        let mut indexed = std::collections::BTreeMap::new();
        for row in heads {
            indexed.insert((row.get::<String>(0)?, row.get::<String>(1)?), row);
        }
        for row in rows.into_iter().take(limit as usize) {
            let subject_ref = row.get::<String>(0)?;
            let mut states = Vec::with_capacity(profiles.len());
            for profile in profiles {
                let head = indexed.get(&(subject_ref.clone(), profile_name(*profile).into()));
                let state = if let Some(head) = head {
                    let desired = head.get::<u64>(2)?;
                    let committed = head.get::<u64>(3)?;
                    let validated_until = head
                        .get::<Option<u64>>(6)?
                        .map(Timestamp::from_unix_seconds)
                        .transpose()?;
                    AssessmentProfileStatus {
                        profile: *profile,
                        desired_generation: desired,
                        committed_generation: committed,
                        assessment_digest: head
                            .get::<Option<String>>(4)?
                            .map(|value| Sha256Digest::parse(&value))
                            .transpose()?,
                        input_digest: head
                            .get::<Option<String>>(5)?
                            .map(|value| Sha256Digest::parse(&value))
                            .transpose()?,
                        fresh: validated_until
                            .as_ref()
                            .is_some_and(|deadline| &now < deadline),
                        pending: desired > committed && head.get::<bool>(7)?,
                        validated_until,
                    }
                } else {
                    AssessmentProfileStatus {
                        profile: *profile,
                        desired_generation: 0,
                        committed_generation: 0,
                        assessment_digest: None,
                        input_digest: None,
                        validated_until: None,
                        fresh: false,
                        pending: false,
                    }
                };
                states.push(state);
            }
            subjects.push(AssessmentSubjectStatus {
                subject_ref,
                package_coordinate: row.get(1)?,
                version: row.get(2)?,
                platform: row.get(3)?,
                output: row.get(4)?,
                profiles: states,
            });
        }
        if self.assessment_resource(registry_id).await?.as_ref() != Some(&resource) {
            bail!("assessment resource changed during status read; restart pagination");
        }
        Ok(AssessmentStatusPage {
            as_of: now,
            resource,
            subjects,
            next_subject: if has_more { last } else { None },
        })
    }

    /// Lists finite compact operation summaries using an exclusive operation cursor.
    ///
    /// The opaque operation IDs determine stable pagination order. The detail
    /// endpoint returns each exact immutable request; hidden partial admissions
    /// remain excluded from the listing.
    ///
    /// # Errors
    /// Returns an error for invalid cursor/limit, malformed stored contracts or SQL failure.
    pub async fn assessment_scan_summaries(
        &self,
        registry_id: i64,
        after_scan: &str,
        limit: u32,
    ) -> Result<Vec<AssessmentScanSummary>> {
        validate_page(after_scan, limit)?;
        self.assessment_scan_summary_rows(registry_id, after_scan, limit)
            .await
    }

    pub(super) async fn assessment_scan_summary_rows(
        &self,
        registry_id: i64,
        after_scan: &str,
        limit: u32,
    ) -> Result<Vec<AssessmentScanSummary>> {
        let rows = self.backend.query(
            "SELECT scan_id, request_digest, state, generation, resource_version, created_at, assessment_digest
             FROM assessment_scans WHERE registry_id = ?1 AND scan_id > ?2 AND admission_complete = 1
             ORDER BY scan_id LIMIT ?3", &vals![@slice registry_id, after_scan, limit],
        ).await?;
        rows.into_iter()
            .map(|row| {
                Ok(AssessmentScanSummary {
                    scan_id: row.get(0)?,
                    request_digest: Sha256Digest::parse(&row.get::<String>(1)?)?,
                    state: serde_json::from_value(serde_json::Value::String(row.get(2)?))?,
                    generation: row.get(3)?,
                    resource_version: row.get(4)?,
                    created_at: Timestamp::from_unix_seconds(row.get(5)?)?,
                    assessment_digest: row
                        .get::<Option<String>>(6)?
                        .map(|value| Sha256Digest::parse(&value))
                        .transpose()?,
                })
            })
            .collect()
    }
}

fn validate_page(cursor: &str, limit: u32) -> Result<()> {
    if cursor.len() > 128 || cursor.chars().any(char::is_control) || !(1..=100).contains(&limit) {
        bail!("assessment page has an invalid cursor or limit");
    }
    Ok(())
}
