//! Compact provider heads, immutable advisory indexes and first-observation history.
//!
//! Index writes share provider-result admission. These rows locate admitted
//! objects; matching still reads complete normalized records and exact query
//! snapshots. An index hit alone cannot establish affected or clean status.

use anyhow::{Context as _, Result, bail};
use aos_assessment::input::CandidateHistory;
use aos_assessment::observation::{ProviderCoverage, ProviderObservationV1};
use aos_assessment_runtime::provider::{
    NormalizedObject, ProviderWorkPlanV1, ProviderWorkResultV1,
};
use aos_contract::Sha256Digest;

use crate::backend::Statement;
use crate::db::Database;

use super::AssessmentObjectKind;
use super::objects::encode;

impl Database {
    /// Reads retained revisions for an exact advisory ID or equivalent alias.
    ///
    /// Related and upstream IDs do not create lookup equivalence. The page
    /// retains withdrawals and prior revisions for audit; its order does not
    /// select the newest revision or establish a current query snapshot.
    ///
    /// # Errors
    /// Returns an error for invalid bounds, absent/corrupt custody or persistence.
    pub async fn assessment_advisory_revision_page(
        &self,
        partition: &str,
        advisory_id: &str,
        after_record: &str,
        limit: u32,
    ) -> Result<Vec<aos_assessment::advisory::AdvisoryRecordV1>> {
        if advisory_id.is_empty()
            || advisory_id.len() > 128
            || advisory_id.chars().any(char::is_control)
            || !(1..=100).contains(&limit)
        {
            bail!("advisory revision query exceeds identity/page bounds");
        }
        if !after_record.is_empty() {
            Sha256Digest::parse(after_record)?;
        }
        let identity = Sha256Digest::of_canonical("aos.advisory-identity/v1", &advisory_id)?;
        let rows = self
            .backend
            .query(
                "SELECT record_digest FROM assessment_advisory_identity_index
             WHERE partition_key = ?1 AND identity_digest = ?2 AND record_digest > ?3
             ORDER BY record_digest LIMIT ?4",
                &vals![@slice partition, identity.to_string(), after_record, limit],
            )
            .await?;
        let mut records = Vec::with_capacity(rows.len());
        for row in rows {
            let digest = Sha256Digest::parse(&row.get::<String>(0)?)?;
            let bytes = self
                .assessment_object(partition, AssessmentObjectKind::AdvisoryRecord, digest)
                .await?
                .context("indexed advisory revision custody is absent")?;
            let record = aos_assessment::advisory::AdvisoryRecordV1::from_slice(&bytes)?;
            if record.id != advisory_id && !record.aliases.iter().any(|alias| alias == advisory_id)
            {
                bail!("advisory identity index differs from its exact equivalence scope");
            }
            records.push(record);
        }
        Ok(records)
    }

    pub(super) fn assessment_provider_index_statements(
        &self,
        plan: &ProviderWorkPlanV1,
        result: &ProviderWorkResultV1,
        admitted_at: u64,
    ) -> Result<Vec<Statement>> {
        let mut statements = Vec::new();
        for projection in &result.normalized_objects {
            match &projection.object {
                NormalizedObject::Observation(observation) => {
                    let coverage = match observation.coverage {
                        ProviderCoverage::Complete { .. } => "complete",
                        ProviderCoverage::ThroughBoundary { .. } => "through-boundary",
                        ProviderCoverage::Partial { .. } => "partial",
                        ProviderCoverage::Unknown { .. } => "unknown",
                    };
                    statements.push(Statement::new(
                        "INSERT INTO assessment_observation_heads(partition_key, provider, project_digest,
                             operation_digest, observation_digest, validated_at, expires_at, coverage_state, resource_version)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1)
                         ON CONFLICT(partition_key, provider, project_digest, operation_digest) DO NOTHING",
                        vals![plan.authorization_partition, observation.provider, project_digest(&observation.project)?.to_string(),
                            plan.operation.digest()?.to_string(), projection.digest.to_string(), observation.validated_at.unix_seconds(),
                            observation.expires_at.unix_seconds(), coverage],
                    ));
                    statements.push(Statement::new(
                        "UPDATE assessment_observation_heads SET observation_digest = ?5, validated_at = ?6,
                             expires_at = ?7, coverage_state = ?8, resource_version = resource_version + 1
                         WHERE partition_key = ?1 AND provider = ?2 AND project_digest = ?3 AND operation_digest = ?4
                           AND (validated_at < ?6 OR (validated_at = ?6 AND observation_digest < ?5))",
                        vals![plan.authorization_partition, observation.provider, project_digest(&observation.project)?.to_string(),
                            plan.operation.digest()?.to_string(), projection.digest.to_string(), observation.validated_at.unix_seconds(),
                            observation.expires_at.unix_seconds(), coverage],
                    ));
                }
                NormalizedObject::Advisory(record) => {
                    statements.push(Statement::new(
                        "INSERT INTO assessment_advisory_revisions(partition_key, provider, advisory_id, record_digest,
                             modification_identity, withdrawn, admitted_at)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                         ON CONFLICT(partition_key, provider, advisory_id, record_digest) DO NOTHING",
                        vals![plan.authorization_partition, record.provider, record.id, projection.digest.to_string(),
                            record.modified, record.withdrawn.is_some(), admitted_at],
                    ));
                    let mut identities = record
                        .affected
                        .iter()
                        .map(|product| {
                            Sha256Digest::of_canonical(
                                "aos.security-identity/v1",
                                &product.identity,
                            )
                        })
                        .collect::<Result<std::collections::BTreeSet<_>>>()?;
                    for id in std::iter::once(&record.id).chain(&record.aliases) {
                        identities
                            .insert(Sha256Digest::of_canonical("aos.advisory-identity/v1", id)?);
                    }
                    for identity in identities {
                        statements.push(Statement::new(
                            "INSERT INTO assessment_advisory_identity_index(partition_key, identity_digest, record_digest)
                             VALUES (?1, ?2, ?3)
                             ON CONFLICT(partition_key, identity_digest, record_digest) DO NOTHING",
                            vals![plan.authorization_partition, identity.to_string(), projection.digest.to_string()],
                        ));
                    }
                }
                NormalizedObject::Upstream(observation) => {
                    for candidate in &observation.candidates {
                        let bytes = encode(candidate)?;
                        if bytes.len() > 8192 {
                            bail!("candidate exceeds durable history bounds");
                        }
                        let candidate_digest = Sha256Digest::of_canonical(
                            "aos.assessment-candidate-key/v1",
                            &candidate.raw_id,
                        )?;
                        statements.push(Statement::new(
                            "INSERT INTO assessment_candidate_history(partition_key, project_digest, candidate_digest,
                                 first_observed_at, candidate_json) VALUES (?1, ?2, ?3, ?4, ?5)
                             ON CONFLICT(partition_key, project_digest, candidate_digest) DO NOTHING",
                            vals![plan.authorization_partition,
                                source_project_digest(&observation.provider, &observation.project)?.to_string(),
                                candidate_digest.to_string(), admitted_at.min(observation.retrieved_at_unix), bytes],
                        ));
                        statements.push(Statement::new(
                            "UPDATE assessment_candidate_history SET first_observed_at = ?4
                             WHERE partition_key = ?1 AND project_digest = ?2 AND candidate_digest = ?3
                               AND first_observed_at > ?4",
                            vals![plan.authorization_partition,
                                source_project_digest(&observation.provider, &observation.project)?.to_string(),
                                candidate_digest.to_string(), admitted_at.min(observation.retrieved_at_unix)],
                        ));
                    }
                }
                NormalizedObject::KnownExploit(_) => {}
                NormalizedObject::Page(_) => {}
            }
        }
        if statements.len() > 32_768 {
            bail!("provider index admission exceeds its finite statement budget");
        }
        Ok(statements)
    }

    /// Reads a finite exact provider-query observation page from admitted custody.
    ///
    /// Freshness is evaluated by the caller's pinned policy and explicit time.
    /// Missing pages never prove complete query or checkpoint coverage.
    ///
    /// # Errors
    /// Returns an error for invalid bounds, absent/corrupt custody or persistence.
    pub async fn assessment_observation_page(
        &self,
        partition: &str,
        provider: &str,
        project: &str,
        after_operation: &str,
        limit: u32,
    ) -> Result<Vec<(Sha256Digest, ProviderObservationV1)>> {
        if !(1..=100).contains(&limit) {
            bail!("provider observation page requires a bounded limit");
        }
        if !after_operation.is_empty() {
            Sha256Digest::parse(after_operation)?;
        }
        let rows = self.backend.query(
            "SELECT operation_digest, observation_digest FROM assessment_observation_heads
             WHERE partition_key = ?1 AND provider = ?2 AND project_digest = ?3 AND operation_digest > ?4
             ORDER BY operation_digest LIMIT ?5",
            &vals![@slice partition, provider, project_digest(project)?.to_string(), after_operation, limit],
        ).await?;
        let mut objects = Vec::with_capacity(rows.len());
        for row in rows {
            let operation = Sha256Digest::parse(&row.get::<String>(0)?)?;
            let digest = Sha256Digest::parse(&row.get::<String>(1)?)?;
            let bytes = self
                .assessment_object(partition, AssessmentObjectKind::Observation, digest)
                .await?
                .context("indexed observation custody is absent")?;
            let observation = ProviderObservationV1::from_slice(&bytes)?;
            if observation.provider != provider
                || observation.project != project
                || observation.request_identity_digest != operation
            {
                bail!("indexed observation differs from its exact query scope");
            }
            objects.push((operation, observation));
        }
        Ok(objects)
    }

    /// Reads original admitted times for a finite set of source candidate IDs.
    ///
    /// The first admitted retrieval is bounded by the issued invocation, rather
    /// than a parser's claimed publication date for an undated release. Refresh
    /// never resets an existing time.
    ///
    /// # Errors
    /// Returns an error for excessive candidate IDs, invalid times or persistence.
    pub async fn assessment_candidate_history(
        &self,
        partition: &str,
        provider: &str,
        project: &str,
        raw_ids: &[String],
    ) -> Result<Vec<CandidateHistory>> {
        if raw_ids.len() > 2000
            || raw_ids.windows(2).any(|pair| pair[0] >= pair[1])
            || raw_ids
                .iter()
                .any(|id| id.is_empty() || id.len() > 512 || id.chars().any(char::is_control))
        {
            bail!("candidate history query requires bounded sorted unique identities");
        }
        let mut result = Vec::new();
        let project_digest = source_project_digest(provider, project)?.to_string();
        for page in raw_ids.chunks(100) {
            let candidates = page
                .iter()
                .map(|id| {
                    Ok((
                        Sha256Digest::of_canonical("aos.assessment-candidate-key/v1", id)?
                            .to_string(),
                        id,
                    ))
                })
                .collect::<Result<std::collections::BTreeMap<_, _>>>()?;
            let mut values = vals![partition, project_digest];
            let mut selectors = Vec::with_capacity(candidates.len());
            for (index, digest) in candidates.keys().enumerate() {
                selectors.push(format!("?{}", index + 3));
                values.push(crate::value::Value::Text(digest.clone()));
            }
            for row in self
                .backend
                .query(
                    &format!(
                "SELECT candidate_digest, first_observed_at FROM assessment_candidate_history
                 WHERE partition_key = ?1 AND project_digest = ?2 AND candidate_digest IN({})",
                selectors.join(", "),
            ),
                    &values,
                )
                .await?
            {
                let digest = row.get::<String>(0)?;
                let raw_id = candidates
                    .get(&digest)
                    .context("history row exceeds the selected candidates")?;
                result.push(CandidateHistory {
                    provider: provider.into(),
                    project: project.into(),
                    raw_id: (*raw_id).clone(),
                    first_observed_at: aos_assessment::time::Timestamp::from_unix_seconds(
                        row.get(1)?,
                    )?,
                });
            }
        }
        result.sort();
        Ok(result)
    }
}

fn project_digest(project: &str) -> Result<Sha256Digest> {
    Sha256Digest::of_canonical("aos.assessment-project/v1", &project)
}

fn source_project_digest(provider: &str, project: &str) -> Result<Sha256Digest> {
    Sha256Digest::of_canonical("aos.assessment-source-project/v1", &(provider, project))
}
