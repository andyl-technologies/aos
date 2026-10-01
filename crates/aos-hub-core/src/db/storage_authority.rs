//! Reviewed physical storage identity and desired admission persistence.
//!
//! SQL stores immutable operator decisions and a delivery outbox. It does not
//! establish provider exclusivity or settle pending provider effects. Every
//! readiness check requires a fresh authenticated remote watermark; an old SQL
//! acknowledgement is insufficient after a database restore.
//!
//! Public mutation callers must authorize `StorageManage` on the instance root
//! both before planning and before applying. This module binds that decision to
//! the reserved root topology plan, exact actor, input, confirmation, and key.

use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};

use crate::backend::{CheckedStatement, Statement};
use crate::storage_authority::{
    canonical_digest, ApproveStorageAuthorityAlias, AssociateStorageAuthorityBinding,
    AttestStorageAuthorityExclusivity, CreatePhysicalStorageAuthority, PhysicalStorageAuthorityId,
    SetStorageAuthorityAdmission, StorageAuthorityAdmissionState, StorageAuthorityDecisionInput,
    StorageAuthorityHost, StorageAuthorityRemoteWatermark, StorageAuthorityReviewedPlanInput,
};

use super::{unix_now, Database, TopologyPlanRecord, PORTABLE_RELATIONAL_ID_MAX};

mod publication;

/// Actor and confirmation selecting an already reserved, root-reviewed plan.
///
/// This is a trusted service-to-database contract, not an authorization token.
#[derive(Debug, Clone)]
pub struct ReviewedStorageAuthorityDecision {
    /// Exact plan created after root permission checking.
    pub plan_id: String,
    /// Exact reserved apply key, unchanged across response-loss retries.
    pub apply_idempotency_key: String,
    /// Confirmation digest presented after operator review.
    pub confirmation_hash: String,
    /// Authenticated principal kind, supplied by the service.
    pub actor_kind: String,
    /// Authenticated principal database identity, supplied by the service.
    pub actor_id: i64,
    /// Original immutable owner pin; None retains only legacy DB fixture semantics.
    pub actor_incarnation: Option<String>,
}

/// Durable result replayed only for the exact reviewed operation and actor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageAuthorityDecisionResult {
    /// Permanent physical identity retained by the decision.
    pub authority_id: PhysicalStorageAuthorityId,
    /// Immutable authority, alias, association, or attestation identity.
    pub record_id: String,
    /// Desired generation for admission decisions; absent for immutable facts.
    pub admission_generation: Option<i64>,
}

/// Immutable desired admission and its canonical control digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageAuthorityAdmissionRecord {
    /// Exact reviewed desired specification.
    pub specification: SetStorageAuthorityAdmission,
    /// Positive monotonically increasing authority generation.
    pub generation: i64,
    /// Digest of the exact specification delivered through the future adapter.
    pub digest: String,
}

impl Database {
    /// Atomically applies one already authorized and reserved root decision.
    ///
    /// The topology result and domain mutation share a checked transaction.
    /// This first milestone never activates an executor or deletion capability.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-root-scoped or mismatched plan, conflicting replay,
    /// invalid coordinates, stale revisions, failed attestation, or SQL failure.
    pub async fn apply_storage_authority_decision(
        &self,
        decision: &ReviewedStorageAuthorityDecision,
        input: &StorageAuthorityDecisionInput,
    ) -> Result<StorageAuthorityDecisionResult> {
        let plan = self.reviewed_authority_plan(decision, input).await?;
        if let Some(result) = applied_authority_result(&plan)? {
            return Ok(result);
        }

        let now = unix_now();
        let prepared: Result<_> = async {
            let creation_fence = self.reviewed_authority_creation_fence(input, &plan).await?;
            let (result, mut mutations) = match input {
                StorageAuthorityDecisionInput::Create(spec) => {
                    self.prepare_authority(spec, &plan, now)
                }
                StorageAuthorityDecisionInput::ApproveAlias(spec) => {
                    self.prepare_alias(spec, &plan, now).await
                }
                StorageAuthorityDecisionInput::AssociateBinding(spec) => {
                    self.prepare_association(spec, &plan, now).await
                }
                StorageAuthorityDecisionInput::Attest(spec) => {
                    self.prepare_attestation(spec, &plan, now).await
                }
                StorageAuthorityDecisionInput::SetAdmission(spec) => {
                    self.prepare_admission(spec, &plan, now).await
                }
            }?;
            if let Some(fence) = creation_fence {
                mutations.insert(0, fence);
            }
            Ok((result, mutations))
        }
        .await;
        let (result, mutations) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                // Preparation awaits mutable heads. An exact concurrent retry
                // may commit while those reads are pending; recover only this
                // same reserved decision, never another plan's CAS result.
                let completed = self.reviewed_authority_plan(decision, input).await?;
                if let Some(result) = applied_authority_result(&completed)? {
                    return Ok(result);
                }
                return Err(error);
            }
        };
        let result_json = serde_json::to_string(&result)?;
        let mut statements = vec![Statement::new(
            "UPDATE topology_plans SET applied_at = ?2, apply_result_json = ?3
             WHERE plan_id = ?1 AND scope = 'instance' AND applied_at IS NULL
               AND apply_idempotency_key = ?4 AND actor_kind = ?5 AND actor_id = ?6
               AND input_versions_json = ?7 AND confirmation_hash = ?8
               AND (actor_incarnation = ?9 OR (actor_incarnation IS NULL AND ?9 IS NULL))
               AND (?9 IS NULL
                 OR (?5 = 'user' AND EXISTS (SELECT 1 FROM users u WHERE u.id = ?6
                     AND u.deleted_at IS NULL AND u.principal_incarnation = ?9))
                 OR (?5 = 'service_account' AND EXISTS (SELECT 1 FROM service_accounts s
                     JOIN orgs o ON o.id = s.org_id WHERE s.id = ?6
                       AND o.deleted_at IS NULL AND s.principal_incarnation = ?9)))",
            vals![
                plan.plan_id,
                now,
                result_json,
                decision.apply_idempotency_key,
                decision.actor_kind,
                decision.actor_id,
                plan.input_versions_json,
                decision.confirmation_hash,
                decision.actor_incarnation
            ],
        )
        .expecting(1)];
        statements.extend(mutations);
        if let Err(error) = self.backend.checked_batch(&statements).await {
            // A concurrent exact retry may have completed the same atomic
            // decision. Recover only its identical durable result.
            let completed = self.reviewed_authority_plan(decision, input).await?;
            if completed.applied_at.is_none()
                || completed.apply_result_json.as_deref() != Some(result_json.as_str())
            {
                return Err(error);
            }
        }
        Ok(result)
    }

    /// Reads the permanent domain without consulting logical binding heads.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed stored JSON or SQL failure.
    pub async fn physical_storage_authority(
        &self,
        id: &PhysicalStorageAuthorityId,
    ) -> Result<Option<CreatePhysicalStorageAuthority>> {
        self.backend
            .query_opt(
                "SELECT specification_json, specification_digest
                 FROM physical_storage_authorities WHERE authority_id = ?1",
                &vals![id.as_str()],
            )
            .await?
            .map(|row| {
                let authority: CreatePhysicalStorageAuthority =
                    serde_json::from_str(&row.get::<String>(0)?)?;
                authority.validate()?;
                ensure!(
                    canonical_digest(&authority)? == row.get::<String>(1)?,
                    "stored authority creation digest is invalid"
                );
                Ok(authority)
            })
            .transpose()
    }

    /// Reads an immutable root-approved endpoint/bucket equivalence decision.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed stored JSON or SQL failure.
    pub async fn physical_storage_alias(
        &self,
        id: &str,
    ) -> Result<Option<ApproveStorageAuthorityAlias>> {
        self.authority_json("physical_storage_aliases", "alias_id", id)
            .await
    }

    /// Reads the exact historical binding revision and prefix association.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed stored JSON or SQL failure.
    pub async fn binding_storage_authority_association(
        &self,
        id: &str,
    ) -> Result<Option<AssociateStorageAuthorityBinding>> {
        self.authority_json("binding_storage_authority_revisions", "association_id", id)
            .await
    }

    /// Reads an immutable operator exclusivity assertion without secret material.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed stored JSON or SQL failure.
    pub async fn storage_authority_attestation(
        &self,
        id: &str,
    ) -> Result<Option<AttestStorageAuthorityExclusivity>> {
        self.authority_json("storage_authority_attestations", "attestation_id", id)
            .await
    }

    /// Reads the current desired admission independently of remote enforcement.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed stored JSON, corrupt digest, or SQL failure.
    pub async fn desired_storage_authority_admission(
        &self,
        authority_id: &PhysicalStorageAuthorityId,
    ) -> Result<Option<StorageAuthorityAdmissionRecord>> {
        self.backend.query_opt(
            "SELECT revision.specification_json, revision.generation, revision.specification_digest
             FROM storage_authority_admission_heads head
             JOIN storage_authority_admission_revisions revision
               ON revision.authority_id = head.authority_id
              AND revision.generation = head.desired_generation
             WHERE head.authority_id = ?1",
            &vals![authority_id.as_str()],
        ).await?.map(|row| {
            let specification = serde_json::from_str(&row.get::<String>(0)?)?;
            let digest: String = row.get(2)?;
            ensure!(canonical_digest(&specification)? == digest, "stored admission digest is invalid");
            Ok(StorageAuthorityAdmissionRecord { specification, generation: row.get(1)?, digest })
        }).transpose()
    }

    /// Records an exact authenticated executor acknowledgement for delivery retry.
    ///
    /// This does not authorize I/O; admission still requires a fresh watermark.
    /// It never clears pending mutations or treats credential expiry as drainage.
    ///
    /// # Errors
    ///
    /// Returns an error when the remote identity differs from desired SQL state
    /// or when atomic acknowledgement persistence fails.
    pub async fn reconcile_storage_authority_watermark(
        &self,
        remote: &StorageAuthorityRemoteWatermark,
    ) -> Result<()> {
        let desired = self.require_matching_authority_watermark(remote).await?;
        self.backend.checked_batch(&[
            Statement::new(
                "UPDATE storage_authority_admission_heads SET acknowledged_generation = ?2,
                   acknowledged_digest = ?3, resource_version = resource_version + 1
                 WHERE authority_id = ?1 AND desired_generation = ?2
                   AND EXISTS (SELECT 1 FROM storage_authority_admission_revisions revision
                     WHERE revision.authority_id = ?1 AND revision.generation = ?2
                       AND revision.specification_digest = ?3)",
                vals![remote.authority_id.as_str(), desired.generation, desired.digest],
            ).expecting(1),
            Statement::new(
                "UPDATE storage_authority_control_requests SET acknowledged_at = COALESCE(acknowledged_at, ?3)
                 WHERE authority_id = ?1 AND generation = ?2 AND specification_digest = ?4",
                vals![remote.authority_id.as_str(), desired.generation, unix_now(), desired.digest],
            ).expecting(1),
        ]).await
    }

    /// Returns reviewed admission only after persisted and fresh remote agreement.
    ///
    /// Callers must obtain `remote` through an authenticated executor adapter.
    /// No adapter or provider capability is enabled by these SQL primitives.
    /// A restored SQL acknowledgement cannot replace this fresh observation.
    ///
    /// # Errors
    ///
    /// Returns an error for missing reconciliation, a changed namespace, remote
    /// rollback/advance, blocked state, expired evidence, or SQL failure.
    pub async fn storage_authority_admission_for_remote(
        &self,
        remote: &StorageAuthorityRemoteWatermark,
    ) -> Result<StorageAuthorityAdmissionRecord> {
        let desired = self.require_matching_authority_watermark(remote).await?;
        ensure!(
            desired.specification.state == StorageAuthorityAdmissionState::Admitted,
            "authority stops new admission"
        );
        let head = self
            .backend
            .query_opt(
                "SELECT acknowledged_generation, acknowledged_digest
             FROM storage_authority_admission_heads WHERE authority_id = ?1",
                &vals![remote.authority_id.as_str()],
            )
            .await?
            .context("authority admission head disappeared")?;
        ensure!(
            head.get::<Option<i64>>(0)? == Some(desired.generation)
                && head.get::<Option<String>>(1)?.as_deref() == Some(desired.digest.as_str()),
            "authority requires remote watermark reconciliation"
        );
        self.validate_admitted_specification(&desired.specification, unix_now())
            .await?;
        Ok(desired)
    }

    async fn authority_json<T: serde::de::DeserializeOwned>(
        &self,
        table: &str,
        column: &str,
        id: &str,
    ) -> Result<Option<T>> {
        // SQL identifiers are private static call-site constants, never user input.
        self.backend
            .query_opt(
                &format!("SELECT specification_json FROM {table} WHERE {column} = ?1"),
                &vals![id],
            )
            .await?
            .map(|row| Ok(serde_json::from_str(&row.get::<String>(0)?)?))
            .transpose()
    }

    async fn reviewed_authority_plan(
        &self,
        decision: &ReviewedStorageAuthorityDecision,
        input: &StorageAuthorityDecisionInput,
    ) -> Result<TopologyPlanRecord> {
        if let Some(incarnation) = &decision.actor_incarnation {
            let kind = crate::domain::PrincipalKind::parse(&decision.actor_kind)
                .context("authority decision actor kind is invalid")?;
            let principal = crate::domain::Principal {
                kind,
                id: decision.actor_id,
            };
            super::direct_identity::validate_actor_incarnation(principal, incarnation)?;
            ensure!(
                self.principal_incarnation(principal).await?.as_ref() == Some(incarnation),
                "authority decision actor incarnation is unavailable"
            );
        }
        let plan = self
            .topology_plan(&decision.plan_id)
            .await?
            .context("authority plan does not exist")?;
        let (input_json, confirmation) = if let Ok(reviewed) =
            serde_json::from_str::<StorageAuthorityReviewedPlanInput>(&plan.input_versions_json)
        {
            reviewed.validate()?;
            ensure!(
                &reviewed.decision == input,
                "authority review intent differs"
            );
            (
                serde_json::to_string(&reviewed)?,
                canonical_digest(&reviewed)?,
            )
        } else {
            // Historical DB callers persisted a bare typed decision. Closed
            // deserialization prevents a malformed/future envelope falling back.
            let legacy: StorageAuthorityDecisionInput =
                serde_json::from_str(&plan.input_versions_json)?;
            ensure!(&legacy == input, "legacy authority review intent differs");
            (serde_json::to_string(&legacy)?, canonical_digest(&legacy)?)
        };
        ensure!(
            plan.scope == "instance"
                && plan.plan_kind == input.plan_kind()
                && plan.actor_kind == decision.actor_kind
                && plan.actor_id == Some(decision.actor_id)
                && plan.actor_incarnation == decision.actor_incarnation
                && plan.input_versions_json == input_json
                && plan.confirmation_hash.as_deref() == Some(decision.confirmation_hash.as_str())
                && decision.confirmation_hash == confirmation
                && plan.apply_idempotency_key.as_deref()
                    == Some(decision.apply_idempotency_key.as_str()),
            "authority decision requires its exact reserved root plan, actor, and confirmation"
        );
        Ok(plan)
    }

    async fn reviewed_authority_creation_fence(
        &self,
        input: &StorageAuthorityDecisionInput,
        plan: &TopologyPlanRecord,
    ) -> Result<Option<CheckedStatement>> {
        let Ok(reviewed) =
            serde_json::from_str::<StorageAuthorityReviewedPlanInput>(&plan.input_versions_json)
        else {
            // Legacy DB plans retain their original pre-envelope semantics.
            return Ok(None);
        };
        let authority_id = match input {
            StorageAuthorityDecisionInput::ApproveAlias(spec) => &spec.authority_id,
            StorageAuthorityDecisionInput::Attest(spec) => &spec.authority_id,
            _ => return Ok(None),
        };
        let authority = self
            .physical_storage_authority(authority_id)
            .await?
            .context("reviewed authority no longer exists")?;
        let digest = canonical_digest(&authority)?;
        ensure!(
            digest == reviewed.expected_resource_version,
            "reviewed immutable authority facts changed"
        );

        // This no-op write fences exact creation facts in the same transaction
        // as the decision/result. It does not advance the permanent identity.
        Ok(Some(Statement::new(
            "UPDATE physical_storage_authorities SET specification_digest = specification_digest
             WHERE authority_id = ?1 AND specification_digest = ?2 AND specification_json = ?3",
            vals![authority_id.as_str(), digest, serde_json::to_string(&authority)?],
        ).expecting(1)))
    }

    fn prepare_authority(
        &self,
        spec: &CreatePhysicalStorageAuthority,
        plan: &TopologyPlanRecord,
        now: i64,
    ) -> Result<(StorageAuthorityDecisionResult, Vec<CheckedStatement>)> {
        spec.validate()?;
        let result = immutable_result(&spec.authority_id, spec.authority_id.as_str());
        Ok((
            result,
            vec![
                Statement::new(
                    "INSERT INTO physical_storage_authorities
                 (authority_id, guard_namespace_id, specification_json, specification_digest,
                  creation_plan_id, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    vals![
                        spec.authority_id.as_str(),
                        spec.guard_namespace_id,
                        serde_json::to_string(spec)?,
                        canonical_digest(spec)?,
                        plan.plan_id,
                        now
                    ],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO storage_authority_admission_heads(authority_id) VALUES (?1)",
                    vals![spec.authority_id.as_str()],
                )
                .expecting(1),
            ],
        ))
    }

    async fn prepare_alias(
        &self,
        spec: &ApproveStorageAuthorityAlias,
        plan: &TopologyPlanRecord,
        now: i64,
    ) -> Result<(StorageAuthorityDecisionResult, Vec<CheckedStatement>)> {
        validate_key(&spec.alias_id, 64)?;
        validate_digest(&spec.equivalence_evidence_digest)?;
        let digest = spec.spec.digest()?;
        Ok((immutable_result(&spec.authority_id, &spec.alias_id), vec![Statement::new(
            "INSERT INTO physical_storage_aliases
             (alias_id, authority_id, canonical_alias_digest, specification_json, approval_plan_id, approved_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            vals![spec.alias_id, spec.authority_id.as_str(), digest,
                serde_json::to_string(spec)?, plan.plan_id, now],
        ).expecting(1)]))
    }

    async fn prepare_association(
        &self,
        spec: &AssociateStorageAuthorityBinding,
        plan: &TopologyPlanRecord,
        now: i64,
    ) -> Result<(StorageAuthorityDecisionResult, Vec<CheckedStatement>)> {
        validate_key(&spec.association_id, 64)?;
        validate_prefix(&spec.binding_prefix)?;
        let binding = self
            .binding(spec.binding_id)
            .await?
            .context("association binding does not exist")?;
        let alias = self
            .physical_storage_alias(&spec.alias_id)
            .await?
            .context("association alias does not exist")?;
        let (host_kind, host_bytes) = match &alias.spec.host {
            StorageAuthorityHost::Dns(host) => ("dns", host.as_bytes().to_vec()),
            StorageAuthorityHost::Ipv4(bytes) => ("ipv4", bytes.to_vec()),
            StorageAuthorityHost::Ipv6(bytes) => ("ipv6", bytes.to_vec()),
        };
        ensure!(
            binding.kind == "s3"
                && !binding.is_instance_default
                && binding.stable_id == spec.binding_stable_id
                && binding.resource_version == spec.binding_resource_version
                && binding.object_prefix.as_deref() == Some(spec.binding_prefix.as_str())
                && binding.object_bucket.as_deref() == Some(alias.spec.bucket.as_str())
                && binding.endpoint_scheme.as_deref() == Some("https")
                && binding.endpoint_host_kind.as_deref() == Some(host_kind)
                && binding.endpoint_host_bytes.as_deref() == Some(host_bytes.as_slice())
                && binding.endpoint_port == Some(i64::from(alias.spec.port))
                && alias.authority_id == spec.authority_id,
            "association does not match exact approved S3 binding coordinates"
        );
        // Retain every reviewed coordinate in the atomic predicate; a precheck
        // alone cannot bind a later transaction to this physical identity.
        let statement = Statement::new(
            "INSERT INTO binding_storage_authority_revisions
             (association_id, authority_id, alias_id, binding_id, binding_resource_version,
              binding_write_revision, binding_prefix, specification_json, approval_plan_id, approved_at)
             SELECT ?1, ?2, ?3, binding.id, binding.resource_version, writer.revision,
                    binding.object_prefix, ?8, ?9, ?10
             FROM bindings binding
             JOIN binding_write_revisions writer
               ON writer.binding_id = binding.id AND writer.revision = ?6
             WHERE binding.id = ?4 AND binding.resource_version = ?5
               AND binding.object_prefix = ?7 AND binding.stable_id = ?11
               AND binding.kind = 's3' AND binding.is_instance_default = 0
               AND binding.object_bucket = ?12 AND binding.endpoint_scheme = 'https'
               AND binding.endpoint_host_kind = ?13 AND binding.endpoint_host_bytes = ?14
               AND binding.endpoint_port = ?15",
            vals![
                spec.association_id,
                spec.authority_id.as_str(),
                spec.alias_id,
                spec.binding_id,
                spec.binding_resource_version,
                spec.binding_write_revision,
                spec.binding_prefix,
                serde_json::to_string(spec)?,
                plan.plan_id,
                now,
                spec.binding_stable_id,
                alias.spec.bucket,
                host_kind,
                host_bytes,
                i64::from(alias.spec.port)
            ],
        )
        .expecting(1);
        Ok((
            immutable_result(&spec.authority_id, &spec.association_id),
            vec![statement],
        ))
    }

    async fn prepare_attestation(
        &self,
        spec: &AttestStorageAuthorityExclusivity,
        plan: &TopologyPlanRecord,
        now: i64,
    ) -> Result<(StorageAuthorityDecisionResult, Vec<CheckedStatement>)> {
        validate_key(&spec.attestation_id, 64)?;
        validate_key(&spec.executor_identity, 255)?;
        validate_prefix(&spec.managed_prefix)?;
        validate_digest(&spec.provider_policy_evidence_digest)?;
        let authority = self
            .physical_storage_authority(&spec.authority_id)
            .await?
            .context("attestation authority does not exist")?;
        ensure!(
            authority.qualification_digest == spec.qualification_digest,
            "attestation changes the authority's initial qualification"
        );
        authority.validate()?;
        ensure!(
            within_prefix(&spec.managed_prefix, &authority.qualified_managed_prefix),
            "attestation expands beyond the authority's qualified prefix"
        );
        ensure!(
            spec.valid_until > now && !spec.credentials.is_empty() && spec.credentials.len() <= 256,
            "attestation is expired or has an invalid credential set"
        );
        let mut statements = vec![Statement::new(
            "INSERT INTO storage_authority_attestations
             (attestation_id, authority_id, managed_prefix, specification_json, specification_digest,
              approval_plan_id, valid_until, approved_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            vals![spec.attestation_id, spec.authority_id.as_str(), spec.managed_prefix,
                serde_json::to_string(spec)?, canonical_digest(spec)?, plan.plan_id, spec.valid_until, now],
        ).expecting(1)];
        let mut previous = None;
        for member in &spec.credentials {
            let identity = (member.association_id.as_str(), member.purpose.as_str());
            ensure!(
                previous.is_none_or(|prior| prior < identity),
                "credential members must be sorted and unique"
            );
            previous = Some(identity);
            let association = self
                .binding_storage_authority_association(&member.association_id)
                .await?
                .context("credential association does not exist")?;
            validate_prefix(&association.binding_prefix)?;
            ensure!(
                association.authority_id == spec.authority_id
                    && within_prefix(&association.binding_prefix, &spec.managed_prefix),
                "attestation credential falls outside its physical domain or prefix"
            );
            if member.purpose == "write" {
                let writer = self
                    .binding_write_revision(
                        association.binding_id,
                        association.binding_write_revision,
                    )
                    .await?
                    .context("attested binding writer revision disappeared")?;
                ensure!(
                    writer.write_credential_generation == member.generation,
                    "attestation write credential differs from the immutable writer revision"
                );
            }
            statements.push(
                Statement::new(
                    "INSERT INTO storage_authority_credential_members
                 (attestation_id, authority_id, association_id, binding_id, purpose, generation)
                 SELECT ?1, ?2, ?3, binding_id, purpose, generation
                 FROM binding_credential_revisions
                 WHERE binding_id = ?4 AND purpose = ?5 AND generation = ?6
                   AND secret_version_ref = ?7 AND credential_fingerprint = ?8
                   AND validation_state = 'valid'",
                    vals![
                        spec.attestation_id,
                        spec.authority_id.as_str(),
                        member.association_id,
                        association.binding_id,
                        member.purpose,
                        member.generation,
                        member.secret_version_ref,
                        member.credential_fingerprint
                    ],
                )
                .expecting(1),
            );
        }
        Ok((
            immutable_result(&spec.authority_id, &spec.attestation_id),
            statements,
        ))
    }

    async fn prepare_admission(
        &self,
        spec: &SetStorageAuthorityAdmission,
        plan: &TopologyPlanRecord,
        now: i64,
    ) -> Result<(StorageAuthorityDecisionResult, Vec<CheckedStatement>)> {
        let authority = self
            .physical_storage_authority(&spec.authority_id)
            .await?
            .context("admission authority does not exist")?;
        ensure!(
            authority.guard_namespace_id == spec.guard_namespace_id,
            "authority guard namespace is immutable"
        );
        ensure!(
            spec.expected_generation >= 0 && spec.expected_generation < PORTABLE_RELATIONAL_ID_MAX,
            "admission generation is invalid or exhausted"
        );
        let current = self
            .desired_storage_authority_admission(&spec.authority_id)
            .await?;
        ensure!(
            current.as_ref().map_or(0, |r| r.generation) == spec.expected_generation
                && current.as_ref().map(|r| &r.digest) == spec.expected_digest.as_ref(),
            "admission generation or digest is stale"
        );
        ensure!(
            current
                .as_ref()
                .is_none_or(|r| r.specification.state != StorageAuthorityAdmissionState::Retired),
            "authority retirement is terminal"
        );
        if spec.state == StorageAuthorityAdmissionState::Admitted {
            self.validate_admitted_specification(spec, now).await?;
        } else {
            ensure!(
                spec.attestation_id.is_none() && spec.association_ids.is_empty(),
                "blocked or retired admission cannot retain admitted members"
            );
        }
        let generation = spec.expected_generation + 1;
        let digest = canonical_digest(spec)?;
        let state = match spec.state {
            StorageAuthorityAdmissionState::Admitted => "admitted",
            StorageAuthorityAdmissionState::Blocked => "blocked",
            StorageAuthorityAdmissionState::Retired => "retired",
        };
        let result = StorageAuthorityDecisionResult {
            authority_id: spec.authority_id.clone(),
            record_id: spec.authority_id.as_str().into(),
            admission_generation: Some(generation),
        };
        Ok((result, vec![
            Statement::new(
                "INSERT INTO storage_authority_admission_revisions
                 (authority_id, generation, state, attestation_id, specification_json,
                  specification_digest, approval_plan_id, approved_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                vals![spec.authority_id.as_str(), generation, state, spec.attestation_id,
                    serde_json::to_string(spec)?, digest, plan.plan_id, now],
            ).expecting(1),
            Statement::new(
                "UPDATE storage_authority_admission_heads SET desired_generation = ?2,
                   acknowledged_generation = NULL, acknowledged_digest = NULL,
                   resource_version = resource_version + 1
                 WHERE authority_id = ?1 AND COALESCE(desired_generation, 0) = ?3",
                vals![spec.authority_id.as_str(), generation, spec.expected_generation],
            ).expecting(1),
            Statement::new(
                "INSERT INTO storage_authority_control_requests
                 (authority_id, generation, request_id, specification_digest) VALUES (?1, ?2, ?3, ?4)",
                vals![spec.authority_id.as_str(), generation, plan.plan_id, digest],
            ).expecting(1),
        ]))
    }

    async fn validate_admitted_specification(
        &self,
        spec: &SetStorageAuthorityAdmission,
        now: i64,
    ) -> Result<()> {
        let attestation_id = spec
            .attestation_id
            .as_deref()
            .context("admission requires an exclusivity attestation")?;
        let attestation = self
            .storage_authority_attestation(attestation_id)
            .await?
            .context("admission attestation does not exist")?;
        validate_prefix(&attestation.managed_prefix)?;
        let authority = self
            .physical_storage_authority(&spec.authority_id)
            .await?
            .context("admission authority does not exist")?;
        ensure!(
            attestation.qualification_digest == authority.qualification_digest
                && within_prefix(
                    &attestation.managed_prefix,
                    &authority.qualified_managed_prefix
                ),
            "admission attestation exceeds the immutable qualification ceiling"
        );
        ensure!(
            attestation.authority_id == spec.authority_id
                && attestation.valid_until > now
                && !spec.association_ids.is_empty()
                && spec.association_ids.len() <= 256,
            "admission lacks current exclusivity evidence or valid members"
        );
        let mut previous = None;
        for association_id in &spec.association_ids {
            ensure!(
                previous.is_none_or(|prior: &String| prior < association_id),
                "admission associations must be sorted and unique"
            );
            previous = Some(association_id);
            let association = self
                .binding_storage_authority_association(association_id)
                .await?
                .context("admission association does not exist")?;
            validate_prefix(&association.binding_prefix)?;
            ensure!(
                association.authority_id == spec.authority_id
                    && within_prefix(&association.binding_prefix, &attestation.managed_prefix),
                "admission association is outside its physical authority or attested prefix"
            );
            let members = self.backend.query(
                "SELECT member.purpose, credential.validation_state
                 FROM storage_authority_credential_members member
                 JOIN binding_credential_revisions credential
                   ON credential.binding_id = member.binding_id AND credential.purpose = member.purpose
                  AND credential.generation = member.generation
                 WHERE member.attestation_id = ?1 AND member.association_id = ?2",
                &vals![attestation_id, association_id],
            ).await?;
            let mut has_writer = false;
            for member in &members {
                ensure!(
                    member.get::<String>(1)? == "valid",
                    "attested credential has been invalidated or retired"
                );
                has_writer |= member.get::<String>(0)? == "write";
            }
            ensure!(
                has_writer,
                "admission association lacks an attested immutable writer"
            );
        }
        Ok(())
    }

    async fn require_matching_authority_watermark(
        &self,
        remote: &StorageAuthorityRemoteWatermark,
    ) -> Result<StorageAuthorityAdmissionRecord> {
        let desired = self
            .desired_storage_authority_admission(&remote.authority_id)
            .await?
            .context("authority has no desired admission")?;
        ensure!(
            desired.generation == remote.generation
                && desired.digest == remote.digest
                && desired.specification.guard_namespace_id == remote.guard_namespace_id,
            "remote authority watermark requires reviewed reconciliation; SQL restore cannot reopen admission"
        );
        Ok(desired)
    }
}

// The caller has already checked the exact reserved plan, actor, input and key.
fn applied_authority_result(
    plan: &TopologyPlanRecord,
) -> Result<Option<StorageAuthorityDecisionResult>> {
    if plan.applied_at.is_none() {
        return Ok(None);
    }
    let encoded = plan
        .apply_result_json
        .as_deref()
        .context("applied decision has no result")?;
    serde_json::from_str(encoded)
        .context("decoding authority decision replay")
        .map(Some)
}

fn immutable_result(
    id: &PhysicalStorageAuthorityId,
    record_id: &str,
) -> StorageAuthorityDecisionResult {
    StorageAuthorityDecisionResult {
        authority_id: id.clone(),
        record_id: record_id.into(),
        admission_generation: None,
    }
}

fn validate_key(value: &str, maximum: usize) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= maximum
            && value.trim() == value
            && !value.chars().any(char::is_control),
        "authority key is invalid"
    );
    Ok(())
}

fn validate_digest(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
        "authority evidence digest must be canonical SHA-256 hex"
    );
    Ok(())
}

fn validate_prefix(prefix: &str) -> Result<()> {
    ensure!(
        prefix.len() <= 512
            && prefix.trim_matches('/') == prefix
            && prefix.trim() == prefix
            && !prefix.contains("//")
            && !prefix.chars().any(|c| c.is_control() || c == '\\')
            && !prefix.split('/').any(|part| matches!(part, "." | "..")),
        "authority prefix is not canonical"
    );
    Ok(())
}

fn within_prefix(prefix: &str, root: &str) -> bool {
    root.is_empty()
        || prefix == root
        || prefix
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

#[cfg(test)]
mod tests;
