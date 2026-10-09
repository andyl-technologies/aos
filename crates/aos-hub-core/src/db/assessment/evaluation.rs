//! Immutable evaluation pinning and all-or-nothing profile-head admission.
//!
//! Evidence retention precedes authority admission: orphaned immutable objects
//! confer no authority. The final checked batch fences every selected profile
//! with the same database lease, inventory, policy and authorization revision.

use anyhow::{bail, Context as _, Result};
use aos_assessment::input::{AssessmentPolicyV1, EvaluationData, ScanInputV1};
use aos_assessment::result::PackageAssessmentV1;
use aos_assessment_runtime::scan::{ScanState, ScanUsage, TaskClaim};
use aos_contract::Sha256Digest;

use crate::backend::Statement;
use crate::db::Database;

use super::objects::encode;
use super::scans::{claim_values, profile_name};
use super::AssessmentObjectKind;

impl Database {
    /// Restores an existing frozen closure under the current coordinator claim.
    ///
    /// A reclaimed operation reuses its original input and evaluation time;
    /// it cannot spend provider quota or replace evidence after freezing.
    ///
    /// # Errors
    /// Returns an error for a stale claim, incomplete checkpoint or unavailable
    /// or inconsistent retained evidence.
    pub async fn assessment_evaluation_checkpoint(
        &self,
        registry_id: i64,
        claim: &TaskClaim,
    ) -> Result<Option<(ScanInputV1, EvaluationData)>> {
        self.check_assessment_scan_claim(registry_id, claim).await?;
        let row = self
            .backend
            .query_opt(
                "SELECT evaluation_input_digest, evaluation_data_digest FROM assessment_scans
             WHERE registry_id = ?1 AND scan_id = ?2",
                &vals![@slice registry_id, claim.scan_id],
            )
            .await?
            .context("assessment operation is absent")?;
        match (row.get::<Option<String>>(0)?, row.get::<Option<String>>(1)?) {
            (None, None) => Ok(None),
            (Some(_), Some(_)) => {
                let checkpoint = self
                    .assessment_frozen_evaluation(registry_id, &claim.scan_id)
                    .await?;
                self.check_assessment_scan_claim(registry_id, claim).await?;
                Ok(Some(checkpoint))
            }
            _ => bail!("assessment evaluation checkpoint is incomplete"),
        }
    }

    /// Loads the admitted inventory closure with the operation's pinned policy.
    ///
    /// Provider acquisition may augment this closure before freezing. This read
    /// never starts HTTP work or treats missing observations as complete coverage.
    ///
    /// # Errors
    /// Returns an error for lost claims, unavailable retained evidence or a
    /// changed inventory/policy commitment.
    pub async fn assessment_evaluation_base(
        &self,
        registry_id: i64,
        claim: &TaskClaim,
    ) -> Result<EvaluationData> {
        self.check_assessment_scan_claim(registry_id, claim).await?;
        let scan = self
            .assessment_scan(registry_id, &claim.scan_id)
            .await?
            .context("assessment operation is absent")?;
        let row = self
            .backend
            .query_opt(
                "SELECT evaluation_base_digest FROM assessment_inventory_sets
             WHERE registry_id = ?1 AND inventory_digest = ?2 AND state = 'ready'",
                &vals![@slice registry_id, scan.request.inventory_digest.to_string()],
            )
            .await?
            .context("ready assessment inventory is absent")?;
        let digest = Sha256Digest::parse(&row.get::<String>(0)?)?;
        let bytes = self
            .assessment_object(
                &scan.request.authorization_partition,
                AssessmentObjectKind::EvaluationData,
                digest,
            )
            .await?
            .context("assessment inventory closure custody is absent")?;
        let mut data = EvaluationData::from_slice(&bytes)?;
        let policy = self
            .assessment_object(
                &scan.request.authorization_partition,
                AssessmentObjectKind::Policy,
                scan.request.policy_digest,
            )
            .await?
            .context("assessment policy custody is absent")?;
        data.policy = serde_json::from_slice::<AssessmentPolicyV1>(&policy)?;
        self.restore_assessment_committed_evidence(&scan, &mut data)
            .await?;
        if scan
            .request
            .profiles
            .contains(&aos_assessment::input::Profile::Vulnerabilities)
            && data.advisory_snapshot.is_none()
        {
            // An explicit empty snapshot pins the absence of admitted source
            // queries. The matcher exposes missing coverage; it never treats
            // an offline acquisition gap as an empty complete source answer.
            data.advisory_snapshot = Some(aos_assessment::advisory::AdvisorySnapshotV1 {
                schema: aos_assessment::advisory::ADVISORY_SNAPSHOT_V1.into(),
                sources: vec![],
                exploit_catalog: None,
            });
        }
        if data.inventory.digest()? != scan.request.inventory_digest
            || data.policy.digest()? != scan.request.policy_digest
        {
            bail!("assessment base differs from operation commitments");
        }
        self.check_assessment_scan_claim(registry_id, claim).await?;
        Ok(data)
    }

    /// Freezes independently admitted evidence exactly once for an operation.
    ///
    /// The service verifies source custody, query bindings and disposition
    /// authority before supplying this closure. This method binds immutable
    /// content to a current operation; checksums do not establish source trust.
    /// Identical retries preserve the original evaluation time.
    ///
    /// # Errors
    /// Returns an error for conflicting retries, changed scope, expired authority,
    /// outstanding physical tasks, resource limits or missing object custody.
    pub async fn freeze_assessment_evaluation(
        &self,
        registry_id: i64,
        claim: &TaskClaim,
        data: &EvaluationData,
    ) -> Result<ScanInputV1> {
        self.check_assessment_scan_claim(registry_id, claim).await?;
        let scan = self
            .assessment_scan(registry_id, &claim.scan_id)
            .await?
            .context("assessment operation is absent")?;
        if data.inventory.digest()? != scan.request.inventory_digest
            || data.policy.digest()? != scan.request.policy_digest
        {
            bail!("evaluation closure differs from the exact admitted operation scope");
        }
        let bytes = encode(data)?;
        let data_digest =
            Sha256Digest::separated(AssessmentObjectKind::EvaluationData.domain(), &bytes);
        let previous = self
            .backend
            .query_opt(
                "SELECT evaluation_input_digest, evaluation_data_digest FROM assessment_scans
             WHERE registry_id = ?1 AND scan_id = ?2",
                &vals![@slice registry_id, claim.scan_id],
            )
            .await?
            .context("assessment operation is absent")?;
        if let Some(existing) = previous.get::<Option<String>>(0)? {
            if previous.get::<Option<String>>(1)?.as_deref()
                != Some(data_digest.to_string().as_str())
            {
                bail!("operation evaluation is already pinned to different evidence");
            }
            let input = self
                .assessment_object(
                    &scan.request.authorization_partition,
                    AssessmentObjectKind::Input,
                    Sha256Digest::parse(&existing)?,
                )
                .await?
                .context("pinned assessment input custody is absent")?;
            let input: ScanInputV1 = serde_json::from_slice(&input)?;
            if data.freeze_selected(
                input.profiles.clone(),
                input.subject_refs.clone(),
                input.evaluated_at.clone(),
            )? != input
            {
                bail!("retained evaluation input differs from its evidence closure");
            }
            self.check_assessment_scan_claim(registry_id, claim).await?;
            return Ok(input);
        }
        let now = self.assessment_database_time().await?;
        let input = data.freeze_selected(
            scan.request.profiles.clone(),
            scan.request.subjects.clone(),
            now.clone(),
        )?;
        let input_bytes = encode(&input)?;
        let input_digest = input.digest()?;
        let usage = scan.usage.consume(
            &ScanUsage {
                normalized_bytes: (bytes.len() + input_bytes.len()) as u64,
                ..Default::default()
            },
            &scan.request.limits,
        )?;
        for (kind, digest, body) in [
            (AssessmentObjectKind::EvaluationData, data_digest, bytes),
            (AssessmentObjectKind::Input, input_digest, input_bytes),
        ] {
            self.put_assessment_object(
                &scan.request.authorization_partition,
                kind,
                digest,
                &body,
                now.unix_seconds() as i64,
            )
            .await?;
        }
        let mut values = claim_values(registry_id, claim);
        values.extend(vals![
            input_digest.to_string(),
            data_digest.to_string(),
            encode(&usage)?,
            scan.resource_version
        ]);
        self.backend.checked_batch(&[Statement::new(format!(
            "UPDATE assessment_scans SET evaluation_input_digest = ?9, evaluation_data_digest = ?10,
                 usage_json = ?11, resource_version = resource_version + 1
             WHERE {} AND resource_version = ?12 AND evaluation_input_digest IS NULL
               AND NOT EXISTS(SELECT 1 FROM assessment_tasks WHERE scan_id = ?2 AND state IN('pending', 'leased', 'waiting'))",
            self.assessment_claim_guard()), values).expecting(1)]).await?;
        Ok(input)
    }

    /// Reads the exact frozen input and its retained evidence for reevaluation.
    ///
    /// # Errors
    /// Returns an error for unavailable custody, malformed references or an
    /// operation that has not frozen an evaluation input.
    pub async fn assessment_frozen_evaluation(
        &self,
        registry_id: i64,
        scan_id: &str,
    ) -> Result<(ScanInputV1, EvaluationData)> {
        let scan = self
            .assessment_scan(registry_id, scan_id)
            .await?
            .context("assessment operation is absent")?;
        let row = self
            .backend
            .query_opt(
                "SELECT evaluation_input_digest, evaluation_data_digest FROM assessment_scans
             WHERE registry_id = ?1 AND scan_id = ?2",
                &vals![@slice registry_id, scan_id],
            )
            .await?
            .context("assessment operation is absent")?;
        let input_digest = Sha256Digest::parse(
            &row.get::<Option<String>>(0)?
                .context("evaluation is not frozen")?,
        )?;
        let data_digest = Sha256Digest::parse(
            &row.get::<Option<String>>(1)?
                .context("evaluation data is not frozen")?,
        )?;
        let input = self
            .assessment_object(
                &scan.request.authorization_partition,
                AssessmentObjectKind::Input,
                input_digest,
            )
            .await?
            .context("frozen input custody is absent")?;
        let data = self
            .assessment_object(
                &scan.request.authorization_partition,
                AssessmentObjectKind::EvaluationData,
                data_digest,
            )
            .await?
            .context("frozen evidence custody is absent")?;
        let input: ScanInputV1 = serde_json::from_slice(&input)?;
        let data = EvaluationData::from_slice(&data)?;
        if data.freeze_selected(
            input.profiles.clone(),
            input.subject_refs.clone(),
            input.evaluated_at.clone(),
        )? != input
        {
            bail!("frozen assessment closure changed");
        }
        Ok((input, data))
    }

    /// Commits a reproduced assessment and all selected profile heads together.
    ///
    /// A stored successful operation is immutable. Every head update is checked;
    /// cancellation, replacement or stale authorization rolls back the entire
    /// admission. Incomplete coverage remains visible in a successful operation.
    ///
    /// # Errors
    /// Returns an error for forged results, stale claims, changed targets,
    /// exhausted normalized-byte allowance or persistence failures.
    pub async fn commit_assessment_evaluation(
        &self,
        registry_id: i64,
        claim: &TaskClaim,
        assessment: &PackageAssessmentV1,
    ) -> Result<()> {
        self.commit_assessment_evaluation_fenced(registry_id, claim, assessment, vec![])
            .await
    }

    /// Commits reproduced results while holding the host's current authority fences.
    ///
    /// The host supplies checked principal, credential and granting-membership
    /// locks. They precede operation, profile-head, alert and event mutations in
    /// one transaction. A lost authority check rolls back every admission effect;
    /// independently retained immutable objects confer no result authority.
    ///
    /// # Errors
    /// Returns an error for lost authority, invalid results, stale operation
    /// claims, changed targets, exhausted limits or persistence failure.
    pub async fn commit_assessment_evaluation_fenced(
        &self,
        registry_id: i64,
        claim: &TaskClaim,
        assessment: &PackageAssessmentV1,
        authority_fences: Vec<crate::backend::CheckedStatement>,
    ) -> Result<()> {
        let scan = self
            .assessment_scan(registry_id, &claim.scan_id)
            .await?
            .context("assessment operation is absent")?;
        let digest = assessment.digest()?;
        if matches!(scan.state, ScanState::Succeeded | ScanState::Partial)
            && scan.assessment_digest == Some(digest)
        {
            let retained = self
                .assessment_object(
                    &scan.request.authorization_partition,
                    AssessmentObjectKind::Assessment,
                    digest,
                )
                .await?
                .context("committed assessment custody is absent")?;
            if retained == encode(assessment)? {
                return Ok(());
            }
            bail!("committed assessment content conflicts");
        }
        self.check_assessment_scan_claim(registry_id, claim).await?;
        let (input, data) = self
            .assessment_frozen_evaluation(registry_id, &claim.scan_id)
            .await?;
        if aos_assessment::evaluator::evaluate(&input, &data)? != *assessment {
            bail!("assessment does not reproduce from the pinned evaluation closure");
        }
        let bytes = encode(assessment)?;
        let usage = scan.usage.consume(
            &ScanUsage {
                normalized_bytes: bytes.len() as u64,
                ..Default::default()
            },
            &scan.request.limits,
        )?;
        let now = self.assessment_database_time().await?;
        if input.evaluated_at > now {
            bail!("assessment evaluation time exceeds current journal time");
        }
        self.put_assessment_object(
            &scan.request.authorization_partition,
            AssessmentObjectKind::Assessment,
            digest,
            &bytes,
            now.unix_seconds() as i64,
        )
        .await?;
        let mut values = claim_values(registry_id, claim);
        let state = if assessment.coverage == aos_assessment::security::CoverageState::Complete {
            "succeeded"
        } else {
            "partial"
        };
        values.extend(vals![
            digest.to_string(),
            input.digest()?.to_string(),
            encode(&usage)?,
            scan.resource_version,
            state
        ]);
        let clock = self.backend.dialect().unix_time_expression();
        let mut statements = authority_fences;
        statements.push(Statement::new(format!(
            "UPDATE assessment_scans SET state = ?13, assessment_digest = ?9,
                 usage_json = ?11, claim_token = NULL, lease_expires_at = NULL,
                 completed_at = {clock}, updated_at = {clock}, resource_version = resource_version + 1
             WHERE {} AND evaluation_input_digest = ?10 AND resource_version = ?12
               AND NOT EXISTS(SELECT 1 FROM assessment_tasks WHERE scan_id = ?2 AND state IN('pending', 'leased', 'waiting'))",
            self.assessment_claim_guard()), values).expecting(1));
        let mut deadlines = std::collections::BTreeMap::new();
        for subject in &assessment.subject_results {
            for coverage in &subject.coverage {
                if coverage.state == aos_assessment::security::CoverageState::Complete
                    && !deadlines.contains_key(&coverage.profile)
                {
                    let deadline = aos_assessment_runtime::status::profile_freshness_deadline(
                        &input, &data, coverage,
                    )?;
                    deadlines.insert(coverage.profile, deadline.map(|time| time.unix_seconds()));
                }
            }
        }
        let mut groups = std::collections::BTreeMap::<_, Vec<&str>>::new();
        for subject in &assessment.subject_results {
            for coverage in &subject.coverage {
                let deadline =
                    if coverage.state == aos_assessment::security::CoverageState::Complete {
                        deadlines.get(&coverage.profile).copied().flatten()
                    } else {
                        None
                    };
                groups
                    .entry((coverage.profile, deadline))
                    .or_default()
                    .push(&subject.subject_ref);
            }
        }
        let input_digest = input.digest()?.to_string();
        for ((profile, deadline), subjects) in groups {
            // Group identical head mutations into finite SQL pages. All pages
            // remain in one checked transaction; one lost target rolls it back.
            for page in subjects.chunks(100) {
                let mut values = vals![
                    registry_id,
                    input.inventory_digest.to_string(),
                    profile_name(profile),
                    input.policy_digest.to_string(),
                    claim.generation,
                    digest.to_string(),
                    input_digest,
                    claim.scan_id,
                    deadline
                ];
                let selectors = page
                    .iter()
                    .enumerate()
                    .map(|(index, _)| format!("?{}", index + 10))
                    .collect::<Vec<_>>()
                    .join(", ");
                for subject in page {
                    values.push(crate::value::Value::Text((*subject).into()));
                }
                statements.push(Statement::new(format!(
                    "UPDATE assessment_heads SET committed_generation = ?5, assessment_digest = ?6,
                         input_digest = ?7, validated_until = ?9, last_scan_id = ?8,
                         updated_at = {clock}, resource_version = resource_version + 1
                     WHERE registry_id = ?1 AND inventory_digest = ?2 AND profile = ?3
                       AND policy_digest = ?4 AND desired_generation = ?5 AND committed_generation < ?5
                       AND subject_ref IN({selectors})"), values).expecting(page.len() as u64));
            }
        }
        statements.extend(
            self.assessment_attention_statements(
                registry_id,
                &claim.scan_id,
                &input,
                &data,
                assessment,
                &now,
            )
            .await?,
        );
        self.backend.checked_batch(&statements).await?;
        Ok(())
    }
}
