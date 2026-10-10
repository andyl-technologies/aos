//! Paged immutable inventory admission and compare-and-swap resource activation.
//!
//! Building inventories remain invisible. Every index row derives from the
//! retained normalized object; activation verifies expected row counts and
//! changes the resource revision in the same checked transaction.

use anyhow::{bail, Context as _, Result};
use aos_assessment::input::EvaluationData;
use aos_assessment::scan_inventory::SubjectKind;
use aos_contract::Sha256Digest;

use crate::backend::{CheckedStatement, Statement};
use crate::db::Database;

use super::AssessmentObjectKind;

/// Pins the independently verified publication/source authority for an inventory.
///
/// The service constructs this record after verifying exact source/artifact
/// custody and publisher authorization. Content digests alone are insufficient.
#[derive(Clone, Debug)]
pub struct AssessmentInventoryAdmission {
    /// Exact registry resource with independently checked write permission.
    pub registry_id: i64,
    /// Non-reusable authorization partition of that resource.
    pub partition: String,
    /// Exact signed publication or explicitly admitted source provenance.
    pub provenance_digest: Sha256Digest,
    /// Retained admission decision including source/artifact custody checks.
    pub admission_digest: Sha256Digest,
    /// Expected resource version, or zero for an absent resource.
    pub expected_resource_version: u64,
}

/// Identifies the active inventory and independent decision/authorization fences.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssessmentResource {
    /// Exact registry database key; never used as an authorization identity.
    pub registry_id: i64,
    /// Stable authorization partition.
    pub partition: String,
    /// Active immutable inventory.
    pub inventory_digest: Sha256Digest,
    /// Required immutable policy.
    pub policy_digest: Sha256Digest,
    /// Monotonic active inventory revision.
    pub inventory_revision: u64,
    /// Next coordinator generation to allocate atomically.
    pub next_generation: u64,
    /// Independent authorization fence.
    pub authorization_revision: u64,
    /// Resource compare-and-swap revision.
    pub resource_version: u64,
}

impl Database {
    /// Replaces decision policy under an exact current resource revision.
    ///
    /// Existing immutable inventories and assessments remain retained. Unfinished
    /// operations pinned to the prior policy immediately lose their commit fence.
    ///
    /// # Errors
    /// Returns an error for invalid policy, wrong authorization partition,
    /// missing resource, stale revision or unavailable persistence.
    pub async fn set_assessment_policy(
        &self,
        registry_id: i64,
        partition: &str,
        expected_version: u64,
        policy: &aos_assessment::input::AssessmentPolicyV1,
    ) -> Result<AssessmentResource> {
        self.set_assessment_policy_fenced(registry_id, partition, expected_version, policy, &[])
            .await
    }

    /// Updates policy while holding independent publication or current IAM guards.
    ///
    /// # Errors
    /// Returns an error for invalid policy, lost resource/version authority,
    /// excessive guards or unavailable persistence.
    pub async fn set_assessment_policy_fenced(
        &self,
        registry_id: i64,
        partition: &str,
        expected_version: u64,
        policy: &aos_assessment::input::AssessmentPolicyV1,
        fences: &[crate::backend::CheckedStatement],
    ) -> Result<AssessmentResource> {
        if fences.len() > 32 {
            bail!("assessment policy guard bound exceeded");
        }
        policy.validate()?;
        let resource = self
            .assessment_resource(registry_id)
            .await?
            .context("assessment resource is absent")?;
        if resource.partition != partition || resource.resource_version != expected_version {
            bail!("assessment policy mutation lost its authority/version fence");
        }
        let digest = policy.digest()?;
        let now = self.assessment_database_time().await?.unix_seconds();
        self.put_assessment_object(
            partition,
            AssessmentObjectKind::Policy,
            digest,
            &super::objects::encode(policy)?,
            now as i64,
        )
        .await?;
        let mut checked = fences.to_vec();
        checked.push(
            Statement::new(
                "UPDATE assessment_resources SET policy_digest = ?4,
                 resource_version = resource_version + 1, updated_at = ?5
             WHERE registry_id = ?1 AND partition_key = ?2 AND resource_version = ?3",
                vals![
                    registry_id,
                    partition,
                    expected_version,
                    digest.to_string(),
                    now
                ],
            )
            .expecting(1),
        );
        self.backend.checked_batch(&checked).await?;
        self.assessment_resource(registry_id)
            .await?
            .context("updated assessment resource is absent")
    }

    /// Reads active inventory state without refreshing providers.
    ///
    /// # Errors
    /// Returns an error for SQL failure or a malformed stored digest/revision.
    pub async fn assessment_resource(
        &self,
        registry_id: i64,
    ) -> Result<Option<AssessmentResource>> {
        let Some(row) = self
            .backend
            .query_opt(
                "SELECT partition_key, inventory_digest, policy_digest, inventory_revision,
                    next_generation, authorization_revision, resource_version
             FROM assessment_resources WHERE registry_id = ?1",
                &vals![@slice registry_id],
            )
            .await?
        else {
            return Ok(None);
        };
        Ok(Some(AssessmentResource {
            registry_id,
            partition: row.get(0)?,
            inventory_digest: Sha256Digest::parse(&row.get::<String>(1)?)?,
            policy_digest: Sha256Digest::parse(&row.get::<String>(2)?)?,
            inventory_revision: row.get(3)?,
            next_generation: row.get(4)?,
            authorization_revision: row.get(5)?,
            resource_version: row.get(6)?,
        }))
    }

    /// Retains and indexes one verified inventory before atomic activation.
    ///
    /// Index writes use bounded pages. A crash leaves a hidden building set,
    /// which an identical admitted retry can resume without exposing partial
    /// inventory. Authoritative callers must verify the admission record first.
    ///
    /// # Errors
    /// Returns an error for invalid closure, mismatched authority, changed CAS
    /// revision, conflicting prior admission, incomplete indexes or SQL failure.
    pub async fn admit_assessment_inventory(
        &self,
        admission: &AssessmentInventoryAdmission,
        data: &EvaluationData,
    ) -> Result<AssessmentResource> {
        self.admit_assessment_inventory_fenced(admission, data, &[])
            .await
    }

    /// Activates an inventory while atomically holding independent publication guards.
    ///
    /// Preparing immutable objects and paged indexes grants no current authority.
    /// Callers supply their exact signed publication or authenticated source
    /// guards; those guards are rechecked in the activation transaction and on replay.
    ///
    /// # Errors
    /// Returns an error for invalid closure, lost publication authority, excessive
    /// guard scope, conflicting immutable admission or failed resource activation.
    pub async fn admit_assessment_inventory_fenced(
        &self,
        admission: &AssessmentInventoryAdmission,
        data: &EvaluationData,
        authority_fences: &[CheckedStatement],
    ) -> Result<AssessmentResource> {
        if authority_fences.len() > 32 {
            bail!("inventory publication authority exceeds its bounded guard scope");
        }
        if admission.registry_id <= 0
            || admission.partition.is_empty()
            || admission.partition.len() > 128
            || admission.partition.chars().any(char::is_control)
            || admission.expected_resource_version >= 9_007_199_254_740_991
        {
            bail!("inventory admission authority or revision is invalid");
        }
        let registry = self
            .registry_by_id(admission.registry_id)
            .await?
            .context("inventory registry is absent")?;
        if registry.scope_key != admission.partition {
            bail!("inventory authorization partition differs from the stable registry incarnation");
        }
        let now = self.assessment_database_time().await?;
        data.freeze(vec![aos_assessment::input::Profile::Updates], now.clone())?;
        let previous = self.assessment_resource(admission.registry_id).await?;
        if previous
            .as_ref()
            .map_or(0, |resource| resource.resource_version)
            != admission.expected_resource_version
            || previous
                .as_ref()
                .is_some_and(|resource| resource.partition != admission.partition)
        {
            bail!("inventory admission lost the resource authority/version fence");
        }
        let inventory_digest = data.inventory.digest()?;
        let policy_digest = data.policy.digest()?;
        let data_bytes = super::objects::encode(data)?;
        let data_digest =
            Sha256Digest::separated(AssessmentObjectKind::EvaluationData.domain(), &data_bytes);
        let timestamp = now.unix_seconds() as i64;
        for (kind, digest, bytes) in [
            (
                AssessmentObjectKind::Inventory,
                inventory_digest,
                super::objects::encode(&data.inventory)?,
            ),
            (
                AssessmentObjectKind::Policy,
                policy_digest,
                super::objects::encode(&data.policy)?,
            ),
            (
                AssessmentObjectKind::EvaluationData,
                data_digest,
                data_bytes,
            ),
        ] {
            self.put_assessment_object(&admission.partition, kind, digest, &bytes, timestamp)
                .await?;
        }
        for definition in &data.definitions {
            self.put_assessment_object(
                &admission.partition,
                AssessmentObjectKind::Definition,
                definition.digest()?,
                &super::objects::encode(definition)?,
                timestamp,
            )
            .await?;
        }

        if let Some(resource) = self
            .reactivate_ready_assessment_inventory(
                admission,
                data,
                data_digest,
                previous.as_ref(),
                authority_fences,
                timestamp,
            )
            .await?
        {
            return Ok(resource);
        }
        let revision = previous
            .as_ref()
            .map_or(1, |resource| resource.inventory_revision + 1);
        if revision > 9_007_199_254_740_991 {
            bail!("inventory revision exhausted");
        }
        let identity_count: usize = data
            .inventory
            .components
            .iter()
            .map(|component| component.security.identities.len())
            .sum();
        self.backend.execute(
            "INSERT INTO assessment_inventory_sets
                (registry_id, inventory_digest, provenance_digest, admission_digest, evaluation_base_digest,
                 inventory_revision, state, expected_subject_count, expected_identity_count, admitted_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'building', ?7, ?8, ?9)
             ON CONFLICT(registry_id, inventory_digest) DO NOTHING",
            &vals![@slice admission.registry_id, inventory_digest.to_string(), admission.provenance_digest.to_string(),
                admission.admission_digest.to_string(), data_digest.to_string(), revision,
                data.inventory.subjects.len() as u64, identity_count as u64, timestamp],
        ).await?;
        let existing = self
            .backend
            .query_opt(
                "SELECT provenance_digest, admission_digest, evaluation_base_digest, state
             FROM assessment_inventory_sets WHERE registry_id = ?1 AND inventory_digest = ?2",
                &vals![@slice admission.registry_id, inventory_digest.to_string()],
            )
            .await?
            .context("inventory admission disappeared")?;
        if existing.get::<String>(0)? != admission.provenance_digest.to_string()
            || existing.get::<String>(1)? != admission.admission_digest.to_string()
            || existing.get::<String>(2)? != data_digest.to_string()
            || existing.get::<String>(3)? == "rejected"
        {
            bail!("immutable inventory admission conflicts with retained authority");
        }

        let mut page = Vec::with_capacity(128);
        for subject in &data.inventory.subjects {
            let kind = match subject.kind {
                SubjectKind::Source => "source",
                SubjectKind::PackageArtifact => "package-artifact",
                SubjectKind::Release => "release",
                SubjectKind::SystemImage => "system-image",
                SubjectKind::OciImage => "oci-image",
            };
            page.push(Statement::new(
                "INSERT INTO assessment_subjects
                    (registry_id, inventory_digest, subject_ref, definition_digest, component_inventory_digest,
                     package_coordinate, package_version, platform, output_name, subject_kind, artifact_digest, source_content_digest)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
                 ON CONFLICT(registry_id, inventory_digest, subject_ref) DO NOTHING",
                vals![admission.registry_id, inventory_digest.to_string(), subject.subject_ref,
                    subject.scan_definition_digest.to_string(), subject.component_inventory_digest.to_string(),
                    subject.package_coordinate, subject.version, subject.platform, subject.output, kind,
                    subject.artifact_digest.map(|value| value.to_string()), subject.source_content_digest.map(|value| value.to_string())],
            ));
            if page.len() == 128 {
                self.backend.batch(&page).await?;
                page.clear();
            }
        }
        if !page.is_empty() {
            self.backend.batch(&page).await?;
            page.clear();
        }
        for component in &data.inventory.components {
            let component_digest = component.digest()?;
            for identity in &component.security.identities {
                let identity_digest =
                    Sha256Digest::of_canonical("aos.security-identity/v1", identity)?;
                page.push(Statement::new(
                    "INSERT INTO assessment_component_index
                        (registry_id, inventory_digest, subject_ref, component_ref, component_digest, identity_digest)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT(registry_id, inventory_digest, component_ref, identity_digest) DO NOTHING",
                    vals![admission.registry_id, inventory_digest.to_string(), component.subject_ref,
                        component.component_ref, component_digest.to_string(), identity_digest.to_string()],
                ));
                if page.len() == 128 {
                    self.backend.batch(&page).await?;
                    page.clear();
                }
            }
        }
        if !page.is_empty() {
            self.backend.batch(&page).await?;
        }

        let mut commit = authority_fences.to_vec();
        commit.push(Statement::new(
            "UPDATE assessment_inventory_sets SET state = 'ready'
             WHERE registry_id = ?1 AND inventory_digest = ?2 AND state IN('building', 'ready')
               AND expected_subject_count = (SELECT count(*) FROM assessment_subjects WHERE registry_id = ?1 AND inventory_digest = ?2)
               AND expected_identity_count = (SELECT count(*) FROM assessment_component_index WHERE registry_id = ?1 AND inventory_digest = ?2)",
            vals![admission.registry_id, inventory_digest.to_string()],
        ).expecting(1));
        let values = vals![
            admission.registry_id,
            admission.partition,
            inventory_digest.to_string(),
            policy_digest.to_string(),
            revision,
            timestamp
        ];
        if let Some(previous) = previous {
            let mut values = values;
            values.extend(vals![previous.resource_version]);
            commit.push(Statement::new(
                "UPDATE assessment_resources SET inventory_digest = ?3, policy_digest = ?4,
                     inventory_revision = ?5, resource_version = resource_version + 1, updated_at = ?6
                 WHERE registry_id = ?1 AND partition_key = ?2 AND resource_version = ?7", values,
            ).expecting(1));
        } else {
            commit.push(Statement::new(
                "INSERT INTO assessment_resources
                    (registry_id, partition_key, inventory_digest, policy_digest, inventory_revision,
                     next_generation, authorization_revision, resource_version, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, 1, 1, 1, ?6)", values,
            ).expecting(1));
        }
        self.backend.checked_batch(&commit).await?;
        self.assessment_resource(admission.registry_id)
            .await?
            .context("activated inventory is absent")
    }

    // Ready inventory sets keep their first admission forever. Reactivation
    // changes only the active resource and its monotonic activation revision.
    async fn reactivate_ready_assessment_inventory(
        &self,
        admission: &AssessmentInventoryAdmission,
        data: &EvaluationData,
        data_digest: Sha256Digest,
        previous: Option<&AssessmentResource>,
        authority_fences: &[CheckedStatement],
        timestamp: i64,
    ) -> Result<Option<AssessmentResource>> {
        let inventory_digest = data.inventory.digest()?;
        let Some(retained) = self
            .backend
            .query_opt(
                "SELECT provenance_digest, admission_digest, evaluation_base_digest, state
             FROM assessment_inventory_sets WHERE registry_id = ?1 AND inventory_digest = ?2",
                &vals![@slice admission.registry_id, inventory_digest.to_string()],
            )
            .await?
        else {
            return Ok(None);
        };
        if retained.get::<String>(3)? != "ready" {
            return Ok(None);
        }
        let previous =
            previous.context("ready inventory has no retained active resource revision")?;
        let provenance: String = retained.get(0)?;
        let original_admission: String = retained.get(1)?;
        let original_base: String = retained.get(2)?;
        if provenance != admission.provenance_digest.to_string() {
            bail!("ready inventory reactivation changed immutable provenance");
        }
        if original_admission != admission.admission_digest.to_string()
            || original_base != data_digest.to_string()
        {
            // A new policy is an independently authorized decision. Compare
            // the complete normalized closure after replacing only that policy;
            // definitions, source identities and publication custody cannot drift.
            if authority_fences.is_empty() {
                bail!("ready inventory policy reactivation requires current authority guards");
            }
            let bytes = self
                .assessment_object(
                    &admission.partition,
                    AssessmentObjectKind::EvaluationData,
                    Sha256Digest::parse(&original_base)?,
                )
                .await?
                .context("ready inventory first-admission custody is absent")?;
            let mut original = EvaluationData::from_slice(&bytes)?;
            if original.policy.digest()? == data.policy.digest()? {
                bail!("ready inventory replay changed its immutable admission content");
            }
            original.policy = data.policy.clone();
            if Sha256Digest::separated(
                AssessmentObjectKind::EvaluationData.domain(),
                &super::objects::encode(&original)?,
            ) != data_digest
            {
                bail!("ready inventory reactivation changed its immutable evaluation closure");
            }
        }
        let policy_digest = data.policy.digest()?;
        let changed = previous.inventory_digest != inventory_digest
            || previous.policy_digest != policy_digest;
        let revision =
            previous.inventory_revision + u64::from(previous.inventory_digest != inventory_digest);
        if revision > 9_007_199_254_740_991 {
            bail!("ready inventory activation revision exhausted");
        }
        let mut checked = authority_fences.to_vec();
        checked.push(
            Statement::new(
                "UPDATE assessment_inventory_sets SET state = state
             WHERE registry_id = ?1 AND inventory_digest = ?2 AND state = 'ready'
               AND provenance_digest = ?3 AND admission_digest = ?4 AND evaluation_base_digest = ?5
               AND expected_subject_count = (SELECT count(*) FROM assessment_subjects
                 WHERE registry_id = ?1 AND inventory_digest = ?2)
               AND expected_identity_count = (SELECT count(*) FROM assessment_component_index
                 WHERE registry_id = ?1 AND inventory_digest = ?2)",
                vals![
                    admission.registry_id,
                    inventory_digest.to_string(),
                    provenance,
                    original_admission,
                    original_base
                ],
            )
            .expecting(1),
        );
        let update = if changed {
            "UPDATE assessment_resources SET inventory_digest = ?4, policy_digest = ?5,
               inventory_revision = ?6, resource_version = resource_version + 1, updated_at = ?7
             WHERE registry_id = ?1 AND partition_key = ?2 AND resource_version = ?3"
        } else {
            "UPDATE assessment_resources SET updated_at = updated_at
             WHERE registry_id = ?1 AND partition_key = ?2 AND resource_version = ?3
               AND inventory_digest = ?4 AND policy_digest = ?5 AND inventory_revision = ?6
               AND updated_at <= ?7"
        };
        checked.push(
            Statement::new(
                update,
                vals![
                    admission.registry_id,
                    admission.partition,
                    previous.resource_version,
                    inventory_digest.to_string(),
                    policy_digest.to_string(),
                    revision,
                    timestamp
                ],
            )
            .expecting(1),
        );
        self.backend.checked_batch(&checked).await?;
        Ok(Some(
            self.assessment_resource(admission.registry_id)
                .await?
                .context("reactivated inventory resource is absent")?,
        ))
    }
}
