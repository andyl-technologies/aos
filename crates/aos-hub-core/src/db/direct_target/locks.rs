//! Per-original row locks for direct authorization under read-committed SQL.
//!
//! Eligibility predicates run after these checked no-op updates. Referenced
//! authority rows remain locked until the target and its terminal receipt commit.
//! Sorted distinct keys bound the work to the original, rather than its parts.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{ensure, Context as _, Result};

use super::super::{Database, DirectUploadSessionRecord};
use crate::{
    backend::{CheckedStatement, Statement},
    direct_upload::{DirectActorKind, DirectActorSlot, DirectPhysicalContext, DirectPlacement},
    value::Value,
};

fn lock(table: &str, column: &str, predicate: &str, values: Vec<Value>) -> CheckedStatement {
    Statement::new(
        format!("UPDATE {table} SET {column} = {column} WHERE {predicate}"),
        values,
    )
    .expecting(1)
}

impl Database {
    /// Locks the current credential and one exact granting membership before IAM eligibility.
    ///
    /// Shared owner locks are deduplicated by the direct transaction runner.
    /// No provider material or cross-request permission cache participates.
    ///
    /// # Errors
    /// Rejects missing actor, current granting membership, malformed claims or SQL failure.
    pub async fn direct_iam_statements(
        &self,
        claims: &crate::auth::jwt::Claims,
        scope: &str,
        permission: crate::domain::Permission,
        now: i64,
    ) -> Result<Vec<CheckedStatement>> {
        use crate::domain::{iam::role_grants, Role};
        let eligibility = self
            .direct_iam_fence(claims, scope, permission, now)
            .await?;
        let kind = match claims.owner_kind.as_str() {
            "user" => DirectActorKind::User,
            "service_account" => DirectActorKind::ServiceAccount,
            _ => anyhow::bail!("direct actor kind differs"),
        };
        let actor = DirectActorSlot {
            kind,
            numeric_id: crate::direct_upload::WireInteger::new(u64::try_from(claims.owner_id)?),
            incarnation: claims
                .owner_incarnation
                .clone()
                .context("direct actor incarnation absent")?,
        };
        let mut result = self.direct_owner_locks(scope, &actor).await?;
        if let Some(session) = &claims.browser_session_id_hash {
            result.push(lock(
                "sessions",
                "last_seen_at",
                "id_hash = ?1 AND user_id = ?2 AND owner_incarnation = ?3",
                vals![session, claims.owner_id, &actor.incarnation],
            ));
        } else {
            result.push(lock(
                "tokens",
                "last_used_at",
                "id = ?1 AND owner_kind = ?2 AND owner_id = ?3 AND owner_incarnation = ?4",
                vals![
                    &claims.sub,
                    &claims.owner_kind,
                    claims.owner_id,
                    &actor.incarnation
                ],
            ));
        }
        let roles = [
            Role::Owner,
            Role::Admin,
            Role::Maintainer,
            Role::Developer,
            Role::Viewer,
        ]
        .into_iter()
        .filter(|role| role_grants(*role).contains(&permission))
        .map(|role| format!("'{}'", role.as_str()))
        .collect::<Vec<_>>()
        .join(", ");
        let grant = self.backend.query_opt(&format!(
            "SELECT membership.id, membership.scope_key, membership.role FROM memberships membership
             JOIN authorization_scope_ancestors ancestry ON ancestry.ancestor_scope_key = membership.scope_key
             JOIN authorization_scopes granted ON granted.scope_key = membership.scope_key
             LEFT JOIN orgs org ON org.id = granted.org_id
             WHERE ancestry.descendant_scope_key = ?1 AND membership.principal_kind = ?2 AND membership.principal_id = ?3
               AND membership.role IN ({roles}) AND granted.retired_at IS NULL AND (granted.org_id IS NULL OR org.deleted_at IS NULL)
             ORDER BY membership.id LIMIT 1"), &vals![scope, &claims.owner_kind, claims.owner_id],
        ).await?.context("direct current granting membership absent")?;
        result.push(lock("memberships", "role", "id = ?1 AND principal_kind = ?2 AND principal_id = ?3 AND scope_key = ?4 AND role = ?5",
            vals![grant.get::<i64>(0)?, &claims.owner_kind, claims.owner_id, grant.get::<String>(1)?, grant.get::<String>(2)?]));
        result.push(eligibility);
        Ok(result)
    }

    pub(crate) async fn direct_owner_locks(
        &self,
        scope: &str,
        actor: &DirectActorSlot,
    ) -> Result<Vec<CheckedStatement>> {
        let rows = self.backend.query(
            "SELECT scope.scope_key, scope.org_id FROM authorization_scopes scope
             JOIN authorization_scope_ancestors ancestry ON ancestry.ancestor_scope_key = scope.scope_key
             WHERE ancestry.descendant_scope_key = ?1 ORDER BY scope.scope_key LIMIT 9", &vals![scope],
        ).await?;
        ensure!(
            !rows.is_empty() && rows.len() <= 8,
            "direct scope ancestry is absent or unbounded"
        );
        let mut orgs = BTreeSet::new();
        let mut scopes = BTreeSet::new();
        for row in rows {
            scopes.insert(row.get::<String>(0)?);
            if let Some(org) = row.get::<Option<i64>>(1)? {
                orgs.insert(org);
            }
        }
        let actor_id = i64::try_from(actor.numeric_id.get())?;
        let table = match actor.kind {
            DirectActorKind::User => "users",
            DirectActorKind::ServiceAccount => {
                let row = self
                    .backend
                    .query_opt(
                        "SELECT org_id FROM service_accounts WHERE id = ?1",
                        &vals![actor_id],
                    )
                    .await?
                    .context("direct actor is absent")?;
                orgs.insert(row.get::<i64>(0)?);
                "service_accounts"
            }
        };
        let mut result = Vec::new();
        for id in orgs {
            result.push(lock("orgs", "updated_at", "id = ?1", vals![id]));
            // Absence means unlimited, but must not permit a concurrent cap
            // insertion to race a successful reservation.
            result.push(CheckedStatement::unchecked(
                "INSERT INTO org_quotas(org_id) VALUES (?1) ON CONFLICT(org_id) DO NOTHING",
                vals![id],
            ));
            result.push(lock("org_quotas", "max_bytes", "org_id = ?1", vals![id]));
            result.push(CheckedStatement::unchecked(
                "UPDATE org_usage SET used_bytes = used_bytes WHERE org_id = ?1",
                vals![id],
            ));
        }
        for scope in scopes {
            result.push(lock(
                "authorization_scopes",
                "retired_at",
                "scope_key = ?1",
                vals![scope],
            ));
        }
        result.push(lock(
            table,
            "principal_incarnation",
            "id = ?1 AND principal_incarnation = ?2",
            vals![actor_id, &actor.incarnation],
        ));
        Ok(result)
    }

    pub(crate) async fn direct_topology_locks(
        &self,
        placements: &[DirectPlacement],
    ) -> Result<Vec<CheckedStatement>> {
        ensure!(
            !placements.is_empty() && placements.len() <= 64,
            "direct original placement set is unbounded"
        );
        let mut bindings = BTreeMap::new();
        let mut writes = BTreeSet::new();
        let mut heads = BTreeMap::new();
        let mut credentials = BTreeSet::new();
        let mut selected = BTreeMap::new();
        for placement in placements {
            let binding = i64::try_from(placement.binding_id.get())?;
            let version = i64::try_from(placement.binding_resource_version.get())?;
            ensure!(
                bindings
                    .insert(binding, version)
                    .is_none_or(|old| old == version),
                "direct original binding versions disagree"
            );
            writes.insert((
                binding,
                i64::try_from(placement.binding_write_revision.get())?,
            ));
            ensure!(
                selected
                    .insert(i64::try_from(placement.placement_id.get())?, placement)
                    .is_none(),
                "direct original placement is duplicated"
            );
            if matches!(placement.physical, DirectPhysicalContext::External { .. }) {
                for credential in [
                    &placement.write_credential,
                    &placement.read_credential,
                    &placement.presign_credential,
                ] {
                    let key = (binding, credential.purpose.clone());
                    let generation = i64::try_from(credential.generation.get())?;
                    ensure!(
                        heads
                            .insert(key, Some(generation))
                            .is_none_or(|old| old == Some(generation)),
                        "direct original credential heads disagree"
                    );
                    credentials.insert((binding, credential.purpose.clone(), generation));
                }
            }
        }
        // The managed public credential refs are runtime identities. Lock the
        // real immutable SQL writer credential as well, without replacing those
        // refs with synthetic provider material or requiring an external head.
        let mut writer_rows = Vec::new();
        for &(binding, revision) in &writes {
            let row = self.backend.query_opt(
                "SELECT write_credential_purpose, write_credential_generation FROM binding_write_revisions WHERE binding_id = ?1 AND revision = ?2",
                &vals![binding, revision],
            ).await?.context("direct original writer revision disappeared")?;
            let purpose: String = row.get(0)?;
            let generation: i64 = row.get(1)?;
            credentials.insert((binding, purpose.clone(), generation));
            writer_rows.push((binding, revision, purpose, generation));
        }
        let mut result = Vec::new();
        for (id, version) in bindings {
            result.push(lock(
                "bindings",
                "updated_at",
                "id = ?1 AND resource_version = ?2",
                vals![id, version],
            ));
        }
        for ((binding, purpose), generation) in heads {
            result.push(lock(
                "binding_credential_heads",
                "updated_at",
                "binding_id = ?1 AND purpose = ?2 AND current_generation = ?3",
                vals![binding, purpose, generation],
            ));
        }
        for (binding, purpose, generation) in credentials {
            result.push(lock(
                "binding_credential_revisions",
                "validated_at",
                "binding_id = ?1 AND purpose = ?2 AND generation = ?3",
                vals![binding, purpose, generation],
            ));
        }
        for binding in writes
            .iter()
            .map(|(binding, _)| *binding)
            .collect::<BTreeSet<_>>()
        {
            result.push(CheckedStatement::unchecked(
                "UPDATE binding_write_state SET updated_at = updated_at WHERE binding_id = ?1",
                vals![binding],
            ));
        }
        for (binding, revision, purpose, generation) in writer_rows {
            result.push(lock("binding_write_revisions", "created_at", "binding_id = ?1 AND revision = ?2 AND write_credential_purpose = ?3 AND write_credential_generation = ?4", vals![binding, revision, purpose, generation]));
            result.push(lock(
                "binding_write_observations",
                "validated_at",
                "binding_id = ?1 AND revision = ?2",
                vals![binding, revision],
            ));
        }
        for (&id, placement) in &selected {
            result.push(lock(
                "surface_write_authorities",
                "updated_at",
                "desired_placement_id = ?1 AND desired_binding_write_revision = ?2",
                vals![id, i64::try_from(placement.binding_write_revision.get())?],
            ));
        }
        for (id, placement) in selected {
            result.push(lock(
                "surface_placements",
                "updated_at",
                "id = ?1 AND resource_version = ?2",
                vals![
                    id,
                    i64::try_from(placement.placement_resource_version.get())?
                ],
            ));
            result.push(lock(
                "surface_placement_observations",
                "observed_at",
                "placement_id = ?1",
                vals![id],
            ));
            result.push(lock("surface_placement_write_capabilities", "created_at", "placement_id = ?1 AND placement_write_spec_version = ?2 AND binding_write_revision = ?3", vals![id, i64::try_from(placement.write_spec_version.get())?, i64::try_from(placement.binding_write_revision.get())?]));
        }
        Ok(result)
    }

    pub(crate) fn direct_batch<'a>(
        &'a self,
        record: &'a DirectUploadSessionRecord,
    ) -> DirectAuthorityBatch<'a> {
        DirectAuthorityBatch { db: self, record }
    }
}

pub(crate) struct DirectAuthorityBatch<'a> {
    db: &'a Database,
    record: &'a DirectUploadSessionRecord,
}

impl DirectAuthorityBatch<'_> {
    pub(crate) async fn checked_batch(&self, statements: &[CheckedStatement]) -> Result<()> {
        let mut locks = self
            .db
            .direct_owner_locks(
                &self.record.owner_scope_key,
                &self.record.admission.actor_slot,
            )
            .await?;
        locks.extend(self.db.direct_target_parent_locks(self.record).await?);
        locks.extend(
            self.db
                .direct_topology_locks(&self.record.admission.placements)
                .await?,
        );
        locks.extend(self.db.direct_target_dependency_locks(self.record).await?);
        let mut plan = locks.clone();
        // Native authority plans use these same lock builders. Keep each exact
        // row lock once, but never deduplicate eligibility or target mutations.
        for statement in statements {
            if !locks.iter().any(|held| {
                held.statement.sql == statement.statement.sql
                    && held.statement.params == statement.statement.params
                    && held.expected_rows == statement.expected_rows
            }) {
                plan.push(statement.clone());
            }
        }
        self.db.backend.checked_batch(&plan).await
    }
}
