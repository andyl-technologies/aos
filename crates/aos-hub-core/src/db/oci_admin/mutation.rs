//! Durable review plans and tenant-bound OCI administration mutations.

use anyhow::{bail, Context, Result};
use aos_oci_types::{ManifestReference, RepositoryName, Sha256Digest, Tag};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    OciAdminRepositoryRecord, OciAdminTagRecord, OciRetentionPolicyRecord,
    OCI_REPOSITORY_DESCRIPTION_MAX_BYTES,
};
use crate::backend::{CheckedStatement, Statement};
use crate::db::{portable_relational_id, Database};
use crate::value::Row;

const OCI_RETENTION_GRACE_MAX_SECONDS: u64 = 10 * 366 * 24 * 60 * 60;
const OCI_RETENTION_HISTORY_MAX: u32 = 1_000_000;
const OCI_ADMIN_PLAN_TTL_SECONDS: i64 = 15 * 60;
const OCI_ADMIN_MUTATION_COLUMNS: &str = "id, registry_id, repository_id,
    repository_name, mutation_kind, selector_json, desired_json,
    confirmation_hash, actor_id, idempotency_key, apply_idempotency_key,
    expected_resource_version, state, created_at, expires_at, applied_at,
    resource_version";

/// Supported repository plan operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OciRepositoryMutationOperation {
    /// Creates an empty repository.
    Create,
    /// Changes presentation metadata only.
    Update,
    /// Deletes a repository only while it has no catalog roots or active work.
    Delete,
}

impl OciRepositoryMutationOperation {
    fn mutation_kind(self) -> &'static str {
        match self {
            Self::Create => "repository.create",
            Self::Update => "repository.update",
            Self::Delete => "repository.delete",
        }
    }
}

/// Parameters for planning a repository administration mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanOciRepositoryMutation {
    /// Owning registry id authorized by the caller.
    pub registry_id: i64,
    /// Registry-local repository name.
    pub repository: RepositoryName,
    /// Requested operation.
    pub operation: OciRepositoryMutationOperation,
    /// Desired description for create/update; `None` for delete.
    pub description: Option<String>,
    /// Required live repository version for update/delete; absent for create.
    pub expected_resource_version: Option<i64>,
    /// Stable actor identity.
    pub actor_id: String,
    /// Retry identity unique to this actor and registry.
    pub idempotency_key: String,
    /// Positive current Unix time.
    pub now: i64,
}

/// Parameters for planning a registry retention-policy mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanOciRetentionPolicy {
    /// Owning registry id authorized by the caller.
    pub registry_id: i64,
    /// Minimum age of untagged content before it may become collectible.
    pub untagged_grace_seconds: u64,
    /// Age after which deleted tag-history records may be trimmed.
    pub deleted_tag_history_seconds: u64,
    /// Recent manual tag revisions retained regardless of age.
    pub recent_manual_tag_revisions: u32,
    /// Whether referrers of retained subjects remain roots.
    pub retain_referrers: bool,
    /// Required policy version, or `None` when no policy may exist.
    pub expected_resource_version: Option<i64>,
    /// Stable actor identity.
    pub actor_id: String,
    /// Retry identity unique to this actor and registry.
    pub idempotency_key: String,
    /// Positive current Unix time.
    pub now: i64,
}

/// Supported reviewed manual-tag operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OciManualTagMutationOperation {
    /// Creates or moves a manual tag.
    Set,
    /// Removes an existing manual tag.
    Unset,
}

impl OciManualTagMutationOperation {
    fn mutation_kind(self) -> &'static str {
        match self {
            Self::Set => "tag.set",
            Self::Unset => "tag.unset",
        }
    }
}

/// Parameters for planning a reviewed manual-tag mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanOciManualTagMutation {
    /// Owning registry id authorized by the caller.
    pub registry_id: i64,
    /// Registry-local repository name.
    pub repository: RepositoryName,
    /// Case-sensitive manual tag.
    pub tag: Tag,
    /// Requested operation.
    pub operation: OciManualTagMutationOperation,
    /// Desired repository-linked manifest digest for `Set`.
    pub target_digest: Option<Sha256Digest>,
    /// Expected old digest, paired with the version for an existing tag.
    pub expected_digest: Option<Sha256Digest>,
    /// Expected current version; absence requires tag absence for `Set`.
    pub expected_resource_version: Option<i64>,
    /// Stable actor identity.
    pub actor_id: String,
    /// Retry identity unique to this actor and registry.
    pub idempotency_key: String,
    /// Positive current Unix time.
    pub now: i64,
}

/// Parameters for applying an exact reviewed OCI administration plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyOciAdminMutation {
    /// Stable plan id.
    pub mutation_id: String,
    /// Actor that created the plan.
    pub actor_id: String,
    /// Independent apply retry identity.
    pub idempotency_key: String,
    /// Exact review confirmation hash returned by planning.
    pub confirmation_hash: Sha256Digest,
    /// Positive current Unix time.
    pub now: i64,
}

/// Durable OCI administration mutation plan and lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciAdminMutationRecord {
    /// Stable plan id.
    pub id: String,
    /// Owning registry id.
    pub registry_id: i64,
    /// Existing repository id, when the plan targets one.
    pub repository_id: Option<i64>,
    /// Registry-local repository name, when applicable.
    pub repository_name: Option<RepositoryName>,
    /// Stable dotted mutation kind.
    pub mutation_kind: String,
    /// Canonical selector JSON included in the confirmation hash.
    pub selector_json: String,
    /// Canonical desired-state JSON included in the confirmation hash.
    pub desired_json: String,
    /// Review confirmation hash.
    pub confirmation_hash: Sha256Digest,
    /// Stable planning actor.
    pub actor_id: String,
    /// Planning retry identity.
    pub idempotency_key: String,
    /// Winning apply retry identity, when applied.
    pub apply_idempotency_key: Option<String>,
    /// Frozen optimistic-concurrency precondition.
    pub expected_resource_version: Option<i64>,
    /// `planned`, `applied`, or `aborted`.
    pub state: String,
    /// Plan creation time in Unix seconds.
    pub created_at: i64,
    /// Last Unix second at which the planned mutation may be applied.
    pub expires_at: i64,
    /// Apply time in Unix seconds, when applied.
    pub applied_at: Option<i64>,
    /// Plan optimistic-concurrency version.
    pub resource_version: i64,
}

/// Result of applying an OCI administration plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedOciAdminMutation {
    /// Applied durable plan.
    pub mutation: OciAdminMutationRecord,
    /// Created or updated repository, when applicable and still present.
    pub repository: Option<OciAdminRepositoryRecord>,
    /// Winning manual tag after `tag.set`, including its exact version.
    pub tag: Option<OciAdminTagRecord>,
    /// Updated retention policy, when applicable.
    pub retention_policy: Option<OciRetentionPolicyRecord>,
    /// Deleted resource identity for repository deletes and tag unsets.
    pub deletion: Option<OciAdminDeletionIdentity>,
}

/// Exact identity of an administration resource removed by an applied plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciAdminDeletionIdentity {
    /// Registry-local repository that was removed or contained the removed tag.
    pub repository: RepositoryName,
    /// Removed tag, or `None` when the repository itself was removed.
    pub tag: Option<Tag>,
    /// Exact terminal mutation resource version.
    pub resource_version: i64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RepositorySelector {
    repository: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RepositoryDesiredState {
    repository_id: i64,
    description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RetentionDesiredState {
    untagged_grace_seconds: u64,
    deleted_tag_history_seconds: u64,
    recent_manual_tag_revisions: u32,
    retain_referrers: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ManualTagSelector {
    repository: String,
    tag: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ManualTagDesiredState {
    target_digest: Option<String>,
    expected_digest: Option<String>,
    history_id: String,
}

impl Database {
    /// Creates or idempotently returns a repository mutation plan.
    ///
    /// Planning freezes the exact live repository version. It never changes
    /// repository state and never creates an empty repository as a side effect.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed metadata, an absent/conflicting target,
    /// an idempotency conflict, or database failure.
    pub async fn plan_oci_repository_mutation(
        &self,
        input: &PlanOciRepositoryMutation,
    ) -> Result<OciAdminMutationRecord> {
        validate_plan_identity(
            input.registry_id,
            &input.actor_id,
            &input.idempotency_key,
            input.now,
        )?;
        validate_repository_description(input.description.as_deref())?;
        let selector_json = canonical_json(&RepositorySelector {
            repository: input.repository.as_str().to_string(),
        })?;
        if let Some(record) = self
            .oci_admin_mutation_by_idempotency(
                input.registry_id,
                &input.actor_id,
                &input.idempotency_key,
            )
            .await?
        {
            ensure_same_repository_plan(&record, input, &selector_json)?;
            return Ok(record);
        }

        let current = self
            .oci_admin_repository(input.registry_id, &input.repository)
            .await?;
        match input.operation {
            OciRepositoryMutationOperation::Create => {
                if current.is_some()
                    || input.expected_resource_version.is_some()
                    || input.description.is_none()
                {
                    bail!("OCI repository create plan conflicts with live state");
                }
            }
            OciRepositoryMutationOperation::Update => {
                let current = current
                    .as_ref()
                    .context("OCI repository update target does not exist")?;
                if input.description.is_none()
                    || input.expected_resource_version != Some(current.resource_version)
                {
                    bail!("OCI repository update plan has a stale precondition");
                }
            }
            OciRepositoryMutationOperation::Delete => {
                let current = current
                    .as_ref()
                    .context("OCI repository delete target does not exist")?;
                if input.description.is_some()
                    || input.expected_resource_version != Some(current.resource_version)
                {
                    bail!("OCI repository delete plan has a stale precondition");
                }
            }
        }

        let mutation_id = Uuid::new_v4().simple().to_string();
        let desired_repository_id = current
            .as_ref()
            .map(|repository| repository.id)
            .unwrap_or_else(|| stable_relational_id(input));
        let desired_json = canonical_json(&RepositoryDesiredState {
            repository_id: desired_repository_id,
            description: input.description.clone(),
        })?;
        let expires_at = plan_expiry(input.now)?;
        let confirmation_hash = mutation_confirmation_hash(
            &mutation_id,
            input.registry_id,
            input.operation.mutation_kind(),
            &selector_json,
            &desired_json,
            input.expected_resource_version,
            expires_at,
        );
        let repository_id = current.as_ref().map(|repository| repository.id);

        self.backend
            .execute_discarding_count(
                "INSERT INTO oci_admin_mutations
                   (id, registry_id, repository_id, repository_name,
                    mutation_kind, selector_json, desired_json, confirmation_hash,
                    actor_id, idempotency_key, apply_idempotency_key,
                    expected_resource_version, state, created_at, expires_at,
                    applied_at, resource_version)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                         NULL, ?11, 'planned', ?12, ?13, NULL, 1)
                 ON CONFLICT(registry_id, actor_id, idempotency_key) DO NOTHING",
                &vals![
                    mutation_id,
                    input.registry_id,
                    repository_id,
                    input.repository.as_str(),
                    input.operation.mutation_kind(),
                    selector_json,
                    desired_json,
                    confirmation_hash.to_string(),
                    input.actor_id,
                    input.idempotency_key,
                    input.expected_resource_version,
                    input.now,
                    expires_at
                ],
            )
            .await?;
        let record = self
            .oci_admin_mutation_by_idempotency(
                input.registry_id,
                &input.actor_id,
                &input.idempotency_key,
            )
            .await?
            .context("new OCI repository mutation plan disappeared")?;
        ensure_same_plan(
            &record,
            input.operation.mutation_kind(),
            &selector_json,
            &desired_json,
            input.expected_resource_version,
        )?;
        Ok(record)
    }

    /// Creates or idempotently returns a retention-policy mutation plan.
    ///
    /// This only stores policy intent. It does not mark, plan, or physically
    /// delete an OCI object; those operations belong to the GC engine.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid bounds, a stale precondition, idempotency
    /// conflict, absent registry, or database failure.
    pub async fn plan_oci_retention_policy(
        &self,
        input: &PlanOciRetentionPolicy,
    ) -> Result<OciAdminMutationRecord> {
        validate_plan_identity(
            input.registry_id,
            &input.actor_id,
            &input.idempotency_key,
            input.now,
        )?;
        validate_retention(
            input.untagged_grace_seconds,
            input.deleted_tag_history_seconds,
            input.recent_manual_tag_revisions,
        )?;
        let selector_json = "{\"policy\":\"registry\"}".to_string();
        let desired_json = canonical_json(&RetentionDesiredState {
            untagged_grace_seconds: input.untagged_grace_seconds,
            deleted_tag_history_seconds: input.deleted_tag_history_seconds,
            recent_manual_tag_revisions: input.recent_manual_tag_revisions,
            retain_referrers: input.retain_referrers,
        })?;
        if let Some(record) = self
            .oci_admin_mutation_by_idempotency(
                input.registry_id,
                &input.actor_id,
                &input.idempotency_key,
            )
            .await?
        {
            ensure_same_plan(
                &record,
                "retention.set",
                &selector_json,
                &desired_json,
                input.expected_resource_version,
            )?;
            return Ok(record);
        }
        if self.registry_by_id(input.registry_id).await?.is_none() {
            bail!("OCI retention policy registry does not exist");
        }
        let current = self.oci_admin_retention_policy(input.registry_id).await?;
        if current.as_ref().map(|policy| policy.resource_version) != input.expected_resource_version
        {
            bail!("OCI retention policy plan has a stale precondition");
        }

        let mutation_id = Uuid::new_v4().simple().to_string();
        let mutation_kind = "retention.set";
        let expires_at = plan_expiry(input.now)?;
        let confirmation_hash = mutation_confirmation_hash(
            &mutation_id,
            input.registry_id,
            mutation_kind,
            &selector_json,
            &desired_json,
            input.expected_resource_version,
            expires_at,
        );
        self.backend
            .execute_discarding_count(
                "INSERT INTO oci_admin_mutations
                   (id, registry_id, repository_id, repository_name,
                    mutation_kind, selector_json, desired_json, confirmation_hash,
                    actor_id, idempotency_key, apply_idempotency_key,
                    expected_resource_version, state, created_at, expires_at,
                    applied_at, resource_version)
                 VALUES (?1, ?2, NULL, NULL, ?3, ?4, ?5, ?6, ?7, ?8,
                         NULL, ?9, 'planned', ?10, ?11, NULL, 1)
                 ON CONFLICT(registry_id, actor_id, idempotency_key) DO NOTHING",
                &vals![
                    mutation_id,
                    input.registry_id,
                    mutation_kind,
                    selector_json,
                    desired_json,
                    confirmation_hash.to_string(),
                    input.actor_id,
                    input.idempotency_key,
                    input.expected_resource_version,
                    input.now,
                    expires_at
                ],
            )
            .await?;
        let record = self
            .oci_admin_mutation_by_idempotency(
                input.registry_id,
                &input.actor_id,
                &input.idempotency_key,
            )
            .await?
            .context("new OCI retention mutation plan disappeared")?;
        ensure_same_plan(
            &record,
            mutation_kind,
            &selector_json,
            &desired_json,
            input.expected_resource_version,
        )?;
        Ok(record)
    }

    /// Creates or idempotently returns a reviewed manual-tag mutation plan.
    ///
    /// Planning freezes both the current tag version and digest. Signed
    /// release and channel tags cannot be targeted by this workflow.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing repository or target manifest, a stale
    /// precondition, signed ownership, idempotency conflict, or database
    /// failure.
    pub async fn plan_oci_manual_tag_mutation(
        &self,
        input: &PlanOciManualTagMutation,
    ) -> Result<OciAdminMutationRecord> {
        validate_plan_identity(
            input.registry_id,
            &input.actor_id,
            &input.idempotency_key,
            input.now,
        )?;
        if input
            .expected_resource_version
            .is_some_and(|version| version < 1)
        {
            bail!("OCI manual-tag plan version is invalid");
        }

        let selector_json = canonical_json(&ManualTagSelector {
            repository: input.repository.as_str().to_string(),
            tag: input.tag.as_str().to_string(),
        })?;
        let desired_json = canonical_json(&ManualTagDesiredState {
            target_digest: input.target_digest.map(|digest| digest.to_string()),
            expected_digest: input.expected_digest.map(|digest| digest.to_string()),
            history_id: stable_history_id(input),
        })?;
        if let Some(record) = self
            .oci_admin_mutation_by_idempotency(
                input.registry_id,
                &input.actor_id,
                &input.idempotency_key,
            )
            .await?
        {
            ensure_same_plan(
                &record,
                input.operation.mutation_kind(),
                &selector_json,
                &desired_json,
                input.expected_resource_version,
            )?;
            return Ok(record);
        }

        let repository = self
            .oci_admin_repository(input.registry_id, &input.repository)
            .await?
            .context("OCI manual-tag repository does not exist")?;
        let current = self
            .resolve_oci_admin_tag(input.registry_id, &input.repository, &input.tag)
            .await?;
        validate_manual_tag_plan(input, current.as_ref())?;
        if let Some(target) = input.target_digest {
            self.oci_admin_manifest(
                input.registry_id,
                &input.repository,
                &ManifestReference::Digest(target),
            )
            .await?
            .context("OCI manual-tag target manifest does not exist")?;
        }

        let mutation_id = Uuid::new_v4().simple().to_string();
        let mutation_kind = input.operation.mutation_kind();
        let expires_at = plan_expiry(input.now)?;
        let confirmation_hash = mutation_confirmation_hash(
            &mutation_id,
            input.registry_id,
            mutation_kind,
            &selector_json,
            &desired_json,
            input.expected_resource_version,
            expires_at,
        );
        self.backend
            .execute_discarding_count(
                "INSERT INTO oci_admin_mutations
                   (id, registry_id, repository_id, repository_name,
                    mutation_kind, selector_json, desired_json, confirmation_hash,
                    actor_id, idempotency_key, apply_idempotency_key,
                    expected_resource_version, state, created_at, expires_at,
                    applied_at, resource_version)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                         NULL, ?11, 'planned', ?12, ?13, NULL, 1)
                 ON CONFLICT(registry_id, actor_id, idempotency_key) DO NOTHING",
                &vals![
                    mutation_id,
                    input.registry_id,
                    repository.id,
                    input.repository.as_str(),
                    mutation_kind,
                    selector_json,
                    desired_json,
                    confirmation_hash.to_string(),
                    input.actor_id,
                    input.idempotency_key,
                    input.expected_resource_version,
                    input.now,
                    expires_at
                ],
            )
            .await?;
        let record = self
            .oci_admin_mutation_by_idempotency(
                input.registry_id,
                &input.actor_id,
                &input.idempotency_key,
            )
            .await?
            .context("new OCI manual-tag mutation plan disappeared")?;
        ensure_same_plan(
            &record,
            mutation_kind,
            &selector_json,
            &desired_json,
            input.expected_resource_version,
        )?;
        Ok(record)
    }

    /// Returns one durable plan only to its exact planning actor and registry.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn oci_admin_mutation(
        &self,
        registry_id: i64,
        mutation_id: &str,
        actor_id: &str,
    ) -> Result<Option<OciAdminMutationRecord>> {
        self.backend
            .query_opt(
                &format!(
                    "SELECT {OCI_ADMIN_MUTATION_COLUMNS} FROM oci_admin_mutations
                     WHERE id = ?1 AND registry_id = ?2 AND actor_id = ?3"
                ),
                &vals![mutation_id, registry_id, actor_id],
            )
            .await?
            .as_ref()
            .map(row_to_admin_mutation)
            .transpose()
    }

    /// Returns one durable plan bound to its authenticated planning actor.
    ///
    /// The returned durable registry id is the only selector a service should
    /// authorize before apply; the request cannot supply a replacement id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn oci_admin_mutation_for_actor(
        &self,
        mutation_id: &str,
        actor_id: &str,
    ) -> Result<Option<OciAdminMutationRecord>> {
        self.backend
            .query_opt(
                &format!(
                    "SELECT {OCI_ADMIN_MUTATION_COLUMNS}
                     FROM oci_admin_mutations mutation
                     WHERE mutation.id = ?1 AND mutation.actor_id = ?2"
                ),
                &vals![mutation_id, actor_id],
            )
            .await?
            .as_ref()
            .map(row_to_admin_mutation)
            .transpose()
    }

    /// Applies a reviewed repository, manual-tag, or retention plan once.
    ///
    /// A successful replay must supply the same apply idempotency key. The
    /// confirmation hash binds the plan id, registry, kind, selector, desired
    /// state, and frozen optimistic precondition.
    ///
    /// # Errors
    ///
    /// Returns an error for wrong ownership or confirmation, stale live state,
    /// a non-empty repository delete, retry conflict, or database failure.
    pub async fn apply_oci_admin_mutation(
        &self,
        input: &ApplyOciAdminMutation,
    ) -> Result<AppliedOciAdminMutation> {
        validate_apply_identity(input)?;
        validate_identity(&input.mutation_id, "OCI mutation id", 64)?;
        let plan = self
            .oci_admin_mutation_for_actor(&input.mutation_id, &input.actor_id)
            .await?
            .context("OCI administration mutation plan does not exist")?;
        if plan.confirmation_hash != input.confirmation_hash {
            bail!("OCI administration mutation confirmation does not match");
        }
        if plan.state == "applied" {
            if plan.apply_idempotency_key.as_deref() != Some(&input.idempotency_key) {
                bail!("OCI administration mutation apply idempotency conflict");
            }
            return self.applied_mutation_result(plan).await;
        }
        if plan.state != "planned" {
            bail!("OCI administration mutation is not applicable");
        }
        if plan.expires_at < input.now {
            bail!("OCI administration mutation plan has expired");
        }

        let mut statements = vec![ensure_registry_state_statement(plan.registry_id, input.now)];
        match plan.mutation_kind.as_str() {
            "repository.create" => {
                append_repository_create(&mut statements, &plan, input)?;
            }
            "repository.update" => {
                append_repository_update(&mut statements, &plan, input)?;
            }
            "repository.delete" => {
                append_repository_delete(&mut statements, &plan, input)?;
            }
            "tag.set" => append_manual_tag_set(&mut statements, &plan, input)?,
            "tag.unset" => append_manual_tag_unset(&mut statements, &plan, input)?,
            "retention.set" => append_retention_update(&mut statements, &plan, input)?,
            other => bail!("unsupported OCI administration mutation kind '{other}'"),
        }
        statements.push(apply_plan_statement(&plan, input));
        self.backend
            .checked_batch(&statements)
            .await
            .context("applying OCI administration mutation")?;

        let applied = self
            .oci_admin_mutation_for_actor(&input.mutation_id, &input.actor_id)
            .await?
            .context("applied OCI administration mutation disappeared")?;
        self.applied_mutation_result(applied).await
    }

    async fn oci_admin_mutation_by_idempotency(
        &self,
        registry_id: i64,
        actor_id: &str,
        idempotency_key: &str,
    ) -> Result<Option<OciAdminMutationRecord>> {
        self.backend
            .query_opt(
                &format!(
                    "SELECT {OCI_ADMIN_MUTATION_COLUMNS} FROM oci_admin_mutations
                     WHERE registry_id = ?1 AND actor_id = ?2 AND idempotency_key = ?3"
                ),
                &vals![registry_id, actor_id, idempotency_key],
            )
            .await?
            .as_ref()
            .map(row_to_admin_mutation)
            .transpose()
    }

    async fn applied_mutation_result(
        &self,
        mutation: OciAdminMutationRecord,
    ) -> Result<AppliedOciAdminMutation> {
        let repository = if mutation.mutation_kind == "repository.delete" {
            None
        } else if mutation.mutation_kind.starts_with("repository.") {
            let name = mutation
                .repository_name
                .as_ref()
                .context("applied repository mutation has no repository name")?;
            self.oci_admin_repository(mutation.registry_id, name)
                .await?
        } else {
            None
        };
        let tag = if mutation.mutation_kind == "tag.set" {
            let repository = mutation
                .repository_name
                .as_ref()
                .context("applied manual-tag mutation has no repository name")?;
            let selector = decode_manual_tag_selector(&mutation)?;
            let tag = Tag::parse(&selector.tag)?;
            Some(
                self.resolve_oci_admin_tag(mutation.registry_id, repository, &tag)
                    .await?
                    .context("applied manual tag disappeared")?,
            )
        } else {
            None
        };
        let retention_policy = if mutation.mutation_kind == "retention.set" {
            self.oci_admin_retention_policy(mutation.registry_id)
                .await?
        } else {
            None
        };
        let deletion = if matches!(
            mutation.mutation_kind.as_str(),
            "repository.delete" | "tag.unset"
        ) {
            let repository = mutation
                .repository_name
                .clone()
                .context("applied deletion mutation has no repository name")?;
            let (tag, resource_version) = if mutation.mutation_kind == "tag.unset" {
                let desired = decode_manual_tag_desired(&mutation)?;
                let version = self
                    .backend
                    .query_opt(
                        "SELECT tag_resource_version FROM oci_tag_history
                         WHERE id = ?1 AND registry_id = ?2",
                        &vals![desired.history_id, mutation.registry_id],
                    )
                    .await?
                    .context("applied manual-tag deletion history disappeared")?
                    .get(0)?;
                (
                    Some(Tag::parse(&decode_manual_tag_selector(&mutation)?.tag)?),
                    version,
                )
            } else {
                (
                    None,
                    mutation
                        .expected_resource_version
                        .and_then(|version| version.checked_add(1))
                        .context("repository deletion version exceeds int64")?,
                )
            };
            Some(OciAdminDeletionIdentity {
                repository,
                tag,
                resource_version,
            })
        } else {
            None
        };
        Ok(AppliedOciAdminMutation {
            mutation,
            repository,
            tag,
            retention_policy,
            deletion,
        })
    }
}

fn append_repository_create(
    statements: &mut Vec<CheckedStatement>,
    plan: &OciAdminMutationRecord,
    input: &ApplyOciAdminMutation,
) -> Result<()> {
    let repository = plan
        .repository_name
        .as_ref()
        .context("OCI repository create plan has no repository name")?;
    let desired = decode_repository_desired(plan)?;
    let description = desired
        .description
        .as_deref()
        .context("OCI repository create plan has no description")?;
    statements.push(
        Statement::new(
            "INSERT INTO oci_repositories
               (id, registry_id, name, visibility, lifecycle_state,
                resource_version, created_at, updated_at)
             SELECT ?1, registry.id, ?3, 'inherit', 'active', 1, ?4, ?4
             FROM registries registry WHERE registry.id = ?2
               AND NOT EXISTS (SELECT 1 FROM oci_repositories existing
                 WHERE existing.registry_id = registry.id AND existing.name = ?3)",
            vals![
                desired.repository_id,
                plan.registry_id,
                repository.as_str(),
                input.now
            ],
        )
        .expecting(1),
    );
    statements.push(
        Statement::new(
            "INSERT INTO oci_repository_metadata
               (repository_id, registry_id, description, resource_version, updated_at)
             VALUES (?1, ?2, ?3, 1, ?4)",
            vals![
                desired.repository_id,
                plan.registry_id,
                description,
                input.now
            ],
        )
        .expecting(1),
    );
    statements.push(mutation_epoch_statement(plan.registry_id, input.now));
    Ok(())
}

fn append_repository_update(
    statements: &mut Vec<CheckedStatement>,
    plan: &OciAdminMutationRecord,
    input: &ApplyOciAdminMutation,
) -> Result<()> {
    let repository_id = plan
        .repository_id
        .context("OCI repository update plan has no repository id")?;
    let expected = plan
        .expected_resource_version
        .context("OCI repository update plan has no precondition")?;
    let desired = decode_repository_desired(plan)?;
    let description = desired
        .description
        .as_deref()
        .context("OCI repository update plan has no description")?;
    statements.push(
        Statement::new(
            "UPDATE oci_repository_metadata
             SET description = ?4, resource_version = resource_version + 1,
                 updated_at = ?5
             WHERE repository_id = ?1 AND registry_id = ?2
               AND EXISTS (SELECT 1 FROM oci_repositories repository
                 WHERE repository.id = ?1 AND repository.registry_id = ?2
                   AND repository.lifecycle_state = 'active'
                   AND repository.resource_version = ?3)",
            vals![
                repository_id,
                plan.registry_id,
                expected,
                description,
                input.now
            ],
        )
        .expecting(1),
    );
    statements.push(
        Statement::new(
            "UPDATE oci_repositories
             SET resource_version = resource_version + 1, updated_at = ?4
             WHERE id = ?1 AND registry_id = ?2 AND resource_version = ?3
               AND lifecycle_state = 'active'",
            vals![repository_id, plan.registry_id, expected, input.now],
        )
        .expecting(1),
    );
    statements.push(mutation_epoch_statement(plan.registry_id, input.now));
    Ok(())
}

fn append_repository_delete(
    statements: &mut Vec<CheckedStatement>,
    plan: &OciAdminMutationRecord,
    input: &ApplyOciAdminMutation,
) -> Result<()> {
    let repository_id = plan
        .repository_id
        .context("OCI repository delete plan has no repository id")?;
    let expected = plan
        .expected_resource_version
        .context("OCI repository delete plan has no precondition")?;
    let empty_guard = "NOT EXISTS (SELECT 1 FROM oci_repository_objects object_link
             WHERE object_link.repository_id = ?1)
           AND NOT EXISTS (SELECT 1 FROM oci_tags tag WHERE tag.repository_id = ?1)
           AND NOT EXISTS (SELECT 1 FROM oci_release_roots root
             WHERE root.repository_id = ?1)
           AND NOT EXISTS (SELECT 1 FROM oci_upload_sessions upload
             WHERE upload.repository_id = ?1 AND upload.state IN('active', 'completing'))
           AND NOT EXISTS (SELECT 1 FROM oci_publication_sessions publication
             WHERE publication.repository_id = ?1
               AND publication.state IN('preparing', 'committing'))";
    statements.push(
        Statement::new(
            format!(
                "UPDATE oci_registry_state SET mutation_epoch = mutation_epoch + 1,
                    updated_at = ?4
                 WHERE registry_id = ?2
                   AND NOT EXISTS (SELECT 1 FROM oci_gc_registry_locks registry_lock
                     WHERE registry_lock.registry_id = ?2)
                   AND NOT EXISTS (SELECT 1 FROM oci_registry_purge_fences purge
                     WHERE purge.registry_id = ?2 AND purge.state = 'collecting')
                   AND EXISTS (SELECT 1 FROM oci_repositories repository
                   WHERE repository.id = ?1 AND repository.registry_id = ?2
                     AND repository.resource_version = ?3
                     AND repository.lifecycle_state = 'active' AND {empty_guard})"
            ),
            vals![repository_id, plan.registry_id, expected, input.now],
        )
        .expecting(1),
    );
    statements.push(
        Statement::new(
            format!(
                "DELETE FROM oci_repositories
                 WHERE id = ?1 AND registry_id = ?2 AND resource_version = ?3
                   AND lifecycle_state = 'active' AND {empty_guard}"
            ),
            vals![repository_id, plan.registry_id, expected],
        )
        .expecting(1),
    );
    Ok(())
}

fn append_manual_tag_set(
    statements: &mut Vec<CheckedStatement>,
    plan: &OciAdminMutationRecord,
    input: &ApplyOciAdminMutation,
) -> Result<()> {
    let repository_id = plan
        .repository_id
        .context("OCI manual-tag set plan has no repository id")?;
    let selector = decode_manual_tag_selector(plan)?;
    let desired = decode_manual_tag_desired(plan)?;
    let target = desired
        .target_digest
        .as_deref()
        .context("OCI manual-tag set plan has no target digest")?;
    let tag = Tag::parse(&selector.tag)?;

    statements.push(
        Statement::new(
            "INSERT INTO oci_tag_history
               (id, repository_id, registry_id, name, prior_digest,
                next_digest, source_kind, actor_id, changed_at,
                tag_resource_version)
             SELECT ?1, repository.id, repository.registry_id, ?3,
                    current.digest, ?4, 'manual', ?5, ?6,
                    (SELECT COUNT(*) + 1 FROM oci_tag_history prior
                     WHERE prior.repository_id = repository.id
                       AND prior.name = ?3)
             FROM oci_repositories repository LEFT JOIN oci_tags current
               ON current.repository_id = repository.id AND current.name = ?3
             WHERE repository.id = ?2 AND repository.registry_id = ?7
               AND repository.lifecycle_state = 'active'
               AND EXISTS (SELECT 1 FROM oci_repository_objects link
                 WHERE link.repository_id = repository.id AND link.digest = ?4
                   AND link.object_kind = 'manifest')
               AND ((?8 IS NULL AND ?9 IS NULL AND current.name IS NULL)
                 OR (?8 IS NOT NULL AND ?9 IS NOT NULL
                   AND current.resource_version = ?8 AND current.digest = ?9
                   AND current.source_kind = 'manual'))",
            vals![
                desired.history_id,
                repository_id,
                tag.as_str(),
                target,
                plan.actor_id,
                input.now,
                plan.registry_id,
                plan.expected_resource_version,
                desired.expected_digest
            ],
        )
        .expecting(1),
    );
    if let Some(expected) = plan.expected_resource_version {
        statements.push(
            Statement::new(
                "UPDATE oci_tags SET digest = ?3, source_kind = 'manual',
                    resource_version = resource_version + 1, updated_at = ?4
                 WHERE repository_id = ?1 AND registry_id = ?5 AND name = ?2
                   AND resource_version = ?6 AND digest = ?7
                   AND source_kind = 'manual'",
                vals![
                    repository_id,
                    tag.as_str(),
                    target,
                    input.now,
                    plan.registry_id,
                    expected,
                    desired.expected_digest
                ],
            )
            .expecting(1),
        );
    } else {
        statements.push(
            Statement::new(
                "INSERT INTO oci_tags
                   (repository_id, registry_id, name, digest, source_kind,
                    resource_version, updated_at, created_at)
                 SELECT repository.id, repository.registry_id, ?3, ?4,
                        'manual', 1, ?5, ?5
                 FROM oci_repositories repository
                 WHERE repository.id = ?1 AND repository.registry_id = ?2
                   AND repository.lifecycle_state = 'active'
                   AND NOT EXISTS (SELECT 1 FROM oci_tags
                     WHERE repository_id = ?1 AND name = ?3)",
                vals![
                    repository_id,
                    plan.registry_id,
                    tag.as_str(),
                    target,
                    input.now
                ],
            )
            .expecting(1),
        );
    }
    statements.push(
        Statement::new(
            "UPDATE oci_blobs SET unreferenced_since = NULL, updated_at = ?3
             WHERE registry_id = ?1 AND digest = ?2 AND lifecycle_state = 'active'",
            vals![plan.registry_id, target, input.now],
        )
        .expecting(1),
    );
    if desired.expected_digest.as_deref() != Some(target) {
        statements.push(
            Statement::new(
                "UPDATE oci_blobs SET unreferenced_since = COALESCE(unreferenced_since, ?3),
                    updated_at = ?3
                 WHERE registry_id = ?1 AND digest = ?2 AND lifecycle_state = 'active'
                   AND NOT EXISTS (SELECT 1 FROM oci_tags tag
                     WHERE tag.registry_id = ?1 AND tag.digest = ?2)
                   AND NOT EXISTS (SELECT 1 FROM oci_release_roots root
                     WHERE root.registry_id = ?1 AND root.index_digest = ?2)
                   AND NOT EXISTS (SELECT 1 FROM oci_release_evidence evidence
                     WHERE evidence.registry_id = ?1 AND evidence.referrer_digest = ?2
                       AND evidence.verification = 'verified')",
                vals![plan.registry_id, desired.expected_digest, input.now],
            )
            .unchecked(),
        );
    }
    statements.push(mutation_epoch_statement(plan.registry_id, input.now));
    Ok(())
}

fn append_manual_tag_unset(
    statements: &mut Vec<CheckedStatement>,
    plan: &OciAdminMutationRecord,
    input: &ApplyOciAdminMutation,
) -> Result<()> {
    let repository_id = plan
        .repository_id
        .context("OCI manual-tag unset plan has no repository id")?;
    let expected = plan
        .expected_resource_version
        .context("OCI manual-tag unset plan has no version")?;
    let selector = decode_manual_tag_selector(plan)?;
    let desired = decode_manual_tag_desired(plan)?;
    let expected_digest = desired
        .expected_digest
        .as_deref()
        .context("OCI manual-tag unset plan has no expected digest")?;
    let tag = Tag::parse(&selector.tag)?;
    statements.push(
        Statement::new(
            "INSERT INTO oci_tag_history
               (id, repository_id, registry_id, name, prior_digest,
                next_digest, source_kind, actor_id, changed_at,
                tag_resource_version)
             SELECT ?1, tag.repository_id, tag.registry_id, tag.name,
                    tag.digest, NULL, 'manual', ?6, ?7,
                    (SELECT COUNT(*) + 1 FROM oci_tag_history prior
                     WHERE prior.repository_id = tag.repository_id
                       AND prior.name = tag.name)
             FROM oci_tags tag WHERE tag.repository_id = ?2
               AND tag.registry_id = ?3 AND tag.name = ?4
               AND tag.resource_version = ?5 AND tag.digest = ?8
               AND tag.source_kind = 'manual'",
            vals![
                desired.history_id,
                repository_id,
                plan.registry_id,
                tag.as_str(),
                expected,
                plan.actor_id,
                input.now,
                expected_digest
            ],
        )
        .expecting(1),
    );
    statements.push(
        Statement::new(
            "DELETE FROM oci_tags WHERE repository_id = ?1 AND registry_id = ?2
               AND name = ?3 AND resource_version = ?4 AND digest = ?5
               AND source_kind = 'manual'",
            vals![
                repository_id,
                plan.registry_id,
                tag.as_str(),
                expected,
                expected_digest
            ],
        )
        .expecting(1),
    );
    statements.push(
        Statement::new(
            "UPDATE oci_blobs SET unreferenced_since = COALESCE(unreferenced_since, ?3),
                updated_at = ?3
             WHERE registry_id = ?1 AND digest = ?2 AND lifecycle_state = 'active'
               AND NOT EXISTS (SELECT 1 FROM oci_tags tag
                 WHERE tag.registry_id = ?1 AND tag.digest = ?2)
               AND NOT EXISTS (SELECT 1 FROM oci_release_roots root
                 WHERE root.registry_id = ?1 AND root.index_digest = ?2)
               AND NOT EXISTS (SELECT 1 FROM oci_release_evidence evidence
                 WHERE evidence.registry_id = ?1 AND evidence.referrer_digest = ?2
                   AND evidence.verification = 'verified')",
            vals![plan.registry_id, expected_digest, input.now],
        )
        .unchecked(),
    );
    statements.push(mutation_epoch_statement(plan.registry_id, input.now));
    Ok(())
}

fn append_retention_update(
    statements: &mut Vec<CheckedStatement>,
    plan: &OciAdminMutationRecord,
    input: &ApplyOciAdminMutation,
) -> Result<()> {
    let desired = serde_json::from_str::<RetentionDesiredState>(&plan.desired_json)
        .context("decoding OCI retention desired state")?;
    validate_retention(
        desired.untagged_grace_seconds,
        desired.deleted_tag_history_seconds,
        desired.recent_manual_tag_revisions,
    )?;
    let grace = i64::try_from(desired.untagged_grace_seconds)
        .context("OCI retention grace exceeds int64")?;
    let deleted_history = i64::try_from(desired.deleted_tag_history_seconds)
        .context("OCI deleted tag-history age exceeds int64")?;
    if let Some(expected) = plan.expected_resource_version {
        statements.push(
            Statement::new(
                "UPDATE oci_retention_policies
                 SET untagged_grace_seconds = ?3,
                     deleted_tag_history_seconds = ?4,
                     recent_manual_tag_revisions = ?5, tag_history_limit = ?5,
                     retain_referrers = ?6, resource_version = resource_version + 1,
                     updated_at = ?7
                 WHERE registry_id = ?1 AND resource_version = ?2",
                vals![
                    plan.registry_id,
                    expected,
                    grace,
                    deleted_history,
                    i64::from(desired.recent_manual_tag_revisions),
                    desired.retain_referrers,
                    input.now
                ],
            )
            .expecting(1),
        );
    } else {
        statements.push(
            Statement::new(
                "INSERT INTO oci_retention_policies
                   (registry_id, untagged_grace_seconds, tag_history_limit,
                    deleted_tag_history_seconds, recent_manual_tag_revisions,
                    retain_referrers, resource_version, updated_at)
                 SELECT registry.id, ?2, ?4, ?3, ?4, ?5, 1, ?6
                 FROM registries registry
                 WHERE registry.id = ?1 AND NOT EXISTS (
                   SELECT 1 FROM oci_retention_policies policy
                   WHERE policy.registry_id = registry.id)",
                vals![
                    plan.registry_id,
                    grace,
                    deleted_history,
                    i64::from(desired.recent_manual_tag_revisions),
                    desired.retain_referrers,
                    input.now
                ],
            )
            .expecting(1),
        );
    }
    statements.push(mutation_epoch_statement(plan.registry_id, input.now));
    Ok(())
}

fn ensure_registry_state_statement(registry_id: i64, now: i64) -> CheckedStatement {
    Statement::new(
        "INSERT INTO oci_registry_state
           (registry_id, mutation_epoch, charged_bytes, charged_objects, updated_at)
         SELECT registry.id, 0, 0, 0, ?2 FROM registries registry
         WHERE registry.id = ?1
         ON CONFLICT(registry_id) DO NOTHING",
        vals![registry_id, now],
    )
    .unchecked()
}

fn mutation_epoch_statement(registry_id: i64, now: i64) -> CheckedStatement {
    Statement::new(
        "UPDATE oci_registry_state SET mutation_epoch = mutation_epoch + 1,
            updated_at = ?2 WHERE registry_id = ?1
            AND NOT EXISTS (SELECT 1 FROM oci_gc_registry_locks registry_lock
              WHERE registry_lock.registry_id = ?1)
            AND NOT EXISTS (SELECT 1 FROM oci_registry_purge_fences purge
              WHERE purge.registry_id = ?1 AND purge.state = 'collecting')",
        vals![registry_id, now],
    )
    .expecting(1)
}

fn apply_plan_statement(
    plan: &OciAdminMutationRecord,
    input: &ApplyOciAdminMutation,
) -> CheckedStatement {
    Statement::new(
        "UPDATE oci_admin_mutations
         SET state = 'applied', apply_idempotency_key = ?4, applied_at = ?5,
             resource_version = resource_version + 1
         WHERE id = ?1 AND registry_id = ?2 AND actor_id = ?3
           AND state = 'planned' AND apply_idempotency_key IS NULL
           AND confirmation_hash = ?6 AND resource_version = ?7
           AND expires_at >= ?5",
        vals![
            plan.id,
            plan.registry_id,
            plan.actor_id,
            input.idempotency_key,
            input.now,
            plan.confirmation_hash.to_string(),
            plan.resource_version
        ],
    )
    .expecting(1)
}

fn decode_repository_desired(plan: &OciAdminMutationRecord) -> Result<RepositoryDesiredState> {
    let desired = serde_json::from_str::<RepositoryDesiredState>(&plan.desired_json)
        .context("decoding OCI repository desired state")?;
    if desired.repository_id <= 0 {
        bail!("OCI repository desired id is invalid");
    }
    validate_repository_description(desired.description.as_deref())?;
    Ok(desired)
}

fn decode_manual_tag_selector(plan: &OciAdminMutationRecord) -> Result<ManualTagSelector> {
    let selector = serde_json::from_str::<ManualTagSelector>(&plan.selector_json)
        .context("decoding OCI manual-tag selector")?;
    RepositoryName::parse(&selector.repository)?;
    Tag::parse(&selector.tag)?;
    Ok(selector)
}

fn decode_manual_tag_desired(plan: &OciAdminMutationRecord) -> Result<ManualTagDesiredState> {
    let desired = serde_json::from_str::<ManualTagDesiredState>(&plan.desired_json)
        .context("decoding OCI manual-tag desired state")?;
    desired
        .target_digest
        .as_deref()
        .map(Sha256Digest::parse)
        .transpose()?;
    desired
        .expected_digest
        .as_deref()
        .map(Sha256Digest::parse)
        .transpose()?;
    validate_identity(&desired.history_id, "OCI tag history id", 64)?;
    Ok(desired)
}

fn ensure_same_repository_plan(
    record: &OciAdminMutationRecord,
    input: &PlanOciRepositoryMutation,
    selector_json: &str,
) -> Result<()> {
    let desired = decode_repository_desired(record)?;
    if desired.description != input.description {
        bail!("OCI administration mutation idempotency conflict");
    }
    ensure_same_plan(
        record,
        input.operation.mutation_kind(),
        selector_json,
        &record.desired_json,
        input.expected_resource_version,
    )
}

fn validate_manual_tag_plan(
    input: &PlanOciManualTagMutation,
    current: Option<&OciAdminTagRecord>,
) -> Result<()> {
    match input.operation {
        OciManualTagMutationOperation::Set if input.target_digest.is_none() => {
            bail!("OCI manual-tag set plan has no target digest");
        }
        OciManualTagMutationOperation::Unset if input.target_digest.is_some() => {
            bail!("OCI manual-tag unset plan cannot have a target digest");
        }
        _ => {}
    }
    if input.expected_resource_version.is_some() != input.expected_digest.is_some() {
        bail!("OCI manual-tag digest and version preconditions must be paired");
    }
    match current {
        Some(current)
            if current.ownership_kind == "manual"
                && input.expected_resource_version == Some(current.resource_version)
                && input.expected_digest == Some(current.digest) => {}
        None if input.operation == OciManualTagMutationOperation::Set
            && input.expected_resource_version.is_none() => {}
        Some(current) if current.ownership_kind != "manual" => {
            bail!("signed OCI release and channel tags are immutable");
        }
        _ => bail!("OCI manual-tag plan has a stale precondition"),
    }
    Ok(())
}

fn stable_relational_id(input: &PlanOciRepositoryMutation) -> i64 {
    let digest = stable_plan_identity(
        input.registry_id,
        &input.actor_id,
        &input.idempotency_key,
        "repository",
    );
    let mut bytes = [0_u8; 16];
    let encoded_digest = digest.encoded();
    let encoded = encoded_digest.as_bytes();
    for (index, byte) in bytes.iter_mut().enumerate() {
        let high = hex_value(encoded[index * 2]);
        let low = hex_value(encoded[index * 2 + 1]);
        *byte = (high << 4) | low;
    }
    portable_relational_id(Uuid::from_bytes(bytes))
}

fn stable_history_id(input: &PlanOciManualTagMutation) -> String {
    stable_plan_identity(
        input.registry_id,
        &input.actor_id,
        &input.idempotency_key,
        "tag-history",
    )
    .encoded()
    .to_string()
}

fn stable_plan_identity(
    registry_id: i64,
    actor_id: &str,
    idempotency_key: &str,
    domain: &str,
) -> Sha256Digest {
    let input = format!(
        "aos-hub/oci-admin-plan-id/v1\0{domain}\0{registry_id}\0{actor_id}\0{idempotency_key}"
    );
    Sha256Digest::digest(input.as_bytes())
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => 0,
    }
}

fn plan_expiry(now: i64) -> Result<i64> {
    now.checked_add(OCI_ADMIN_PLAN_TTL_SECONDS)
        .context("OCI administration plan expiry exceeds int64")
}

fn mutation_confirmation_hash(
    mutation_id: &str,
    registry_id: i64,
    mutation_kind: &str,
    selector_json: &str,
    desired_json: &str,
    expected_resource_version: Option<i64>,
    expires_at: i64,
) -> Sha256Digest {
    let mut bytes = b"aos-hub/oci-admin-mutation/v1\0".to_vec();
    for field in [
        mutation_id,
        &registry_id.to_string(),
        mutation_kind,
        selector_json,
        desired_json,
        &expected_resource_version.unwrap_or(0).to_string(),
        &expires_at.to_string(),
    ] {
        bytes.extend_from_slice(field.as_bytes());
        bytes.push(0);
    }
    Sha256Digest::digest(&bytes)
}

fn ensure_same_plan(
    record: &OciAdminMutationRecord,
    mutation_kind: &str,
    selector_json: &str,
    desired_json: &str,
    expected_resource_version: Option<i64>,
) -> Result<()> {
    if record.mutation_kind != mutation_kind
        || record.selector_json != selector_json
        || record.desired_json != desired_json
        || record.expected_resource_version != expected_resource_version
        || record.confirmation_hash
            != mutation_confirmation_hash(
                &record.id,
                record.registry_id,
                mutation_kind,
                selector_json,
                desired_json,
                expected_resource_version,
                record.expires_at,
            )
    {
        bail!("OCI administration mutation idempotency conflict");
    }
    Ok(())
}

fn row_to_admin_mutation(row: &Row) -> Result<OciAdminMutationRecord> {
    Ok(OciAdminMutationRecord {
        id: row.get(0)?,
        registry_id: row.get(1)?,
        repository_id: row.get(2)?,
        repository_name: row
            .get::<Option<String>>(3)?
            .map(|name| RepositoryName::parse(&name))
            .transpose()?,
        mutation_kind: row.get(4)?,
        selector_json: row.get(5)?,
        desired_json: row.get(6)?,
        confirmation_hash: Sha256Digest::parse(&row.get::<String>(7)?)?,
        actor_id: row.get(8)?,
        idempotency_key: row.get(9)?,
        apply_idempotency_key: row.get(10)?,
        expected_resource_version: row.get(11)?,
        state: row.get(12)?,
        created_at: row.get(13)?,
        expires_at: row.get(14)?,
        applied_at: row.get(15)?,
        resource_version: row.get(16)?,
    })
}

fn validate_plan_identity(
    registry_id: i64,
    actor_id: &str,
    idempotency_key: &str,
    now: i64,
) -> Result<()> {
    if registry_id <= 0 || now <= 0 {
        bail!("OCI administration plan metadata is invalid");
    }
    validate_identity(actor_id, "OCI administration actor", 128)?;
    validate_identity(idempotency_key, "OCI administration idempotency key", 128)
}

fn validate_apply_identity(input: &ApplyOciAdminMutation) -> Result<()> {
    if input.now <= 0 {
        bail!("OCI administration apply metadata is invalid");
    }
    validate_identity(&input.actor_id, "OCI administration actor", 128)?;
    validate_identity(
        &input.idempotency_key,
        "OCI administration idempotency key",
        128,
    )
}

fn validate_identity(value: &str, label: &str, maximum: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > maximum
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b'\0')
    {
        bail!("{label} is malformed");
    }
    Ok(())
}

fn validate_repository_description(description: Option<&str>) -> Result<()> {
    if description.is_some_and(|value| {
        value.len() > OCI_REPOSITORY_DESCRIPTION_MAX_BYTES || value.contains('\0')
    }) {
        bail!("OCI repository description is malformed");
    }
    Ok(())
}

fn validate_retention(
    untagged_grace_seconds: u64,
    deleted_tag_history_seconds: u64,
    recent_manual_tag_revisions: u32,
) -> Result<()> {
    if untagged_grace_seconds > OCI_RETENTION_GRACE_MAX_SECONDS
        || deleted_tag_history_seconds > OCI_RETENTION_GRACE_MAX_SECONDS
        || recent_manual_tag_revisions > OCI_RETENTION_HISTORY_MAX
    {
        bail!("OCI retention policy is outside supported bounds");
    }
    Ok(())
}

fn canonical_json<T: Serialize>(value: &T) -> Result<String> {
    String::from_utf8(aos_oci_types::to_canonical_json(value)?)
        .context("canonical OCI administration JSON is not UTF-8")
}
