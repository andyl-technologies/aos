//! Projects mutations in the tenancy capability.

use super::*;

impl Database {
    /// Create a project under an org at a materialized path; returns its id.
    ///
    /// Pass `""` as `path` for a project that sits directly under the org
    /// root.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, including a unique-constraint
    /// violation when `(org_id, path)` already exists or `org_id` does not
    /// reference an org.
    pub async fn create_project(&self, org_id: i64, path: &str, name: &str) -> Result<i64> {
        self.create_project_with_plan(org_id, path, name, None, None, None, None)
            .await
    }

    /// Creates a project attributed to one immutable control plan.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::create_project`], plus a duplicate
    /// plan conflict.
    pub async fn create_project_from_plan(
        &self,
        org_id: i64,
        path: &str,
        name: &str,
        plan_id: &str,
        actor_kind: &str,
        actor_id: Option<i64>,
        actor_label: &str,
    ) -> Result<i64> {
        self.create_project_with_plan(
            org_id,
            path,
            name,
            Some(plan_id),
            Some(actor_kind),
            actor_id,
            Some(actor_label),
        )
        .await
    }

    /// Loads one project by its exact materialized path.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn project_by_path(&self, org_id: i64, path: &str) -> Result<Option<ProjectRecord>> {
        self.backend
            .query_opt(
                "SELECT id, stable_id, scope_key, owner_scope_key, org_id, path, name,
                        created_at, resource_version, updated_at
                   FROM projects WHERE org_id = ?1 AND path = ?2",
                &vals![org_id, path],
            )
            .await?
            .map(|row| {
                Ok(ProjectRecord {
                    id: row.get(0)?,
                    stable_id: row.get(1)?,
                    scope_key: row.get(2)?,
                    owner_scope_key: row.get(3)?,
                    org_id: row.get(4)?,
                    path: row.get(5)?,
                    name: row.get(6)?,
                    created_at: row.get(7)?,
                    resource_version: row.get(8)?,
                    updated_at: row.get(9)?,
                })
            })
            .transpose()
    }

    /// Returns whether a project was created by one exact control plan.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn project_matches_creation_plan(
        &self,
        project_id: i64,
        plan_id: &str,
    ) -> Result<bool> {
        Ok(self
            .backend
            .query_opt(
                "SELECT 1 FROM projects WHERE id = ?1 AND creation_plan_id = ?2",
                &vals![project_id, plan_id],
            )
            .await?
            .is_some())
    }

    /// Resolves an exact materialized project path to its stable scope key.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn project_scope_by_path(&self, org_id: i64, path: &str) -> Result<Option<String>> {
        self.backend
            .query_opt(
                "SELECT p.scope_key FROM projects p
                  JOIN orgs o ON o.id = p.org_id
                 WHERE p.org_id = ?1 AND p.path = ?2 AND o.deleted_at IS NULL",
                &vals![org_id, path],
            )
            .await?
            .map(|row| row.get(0))
            .transpose()
    }

    /// Deletes an empty project under one exact resource-version CAS.
    ///
    /// # Errors
    ///
    /// Returns an error when the project owns registry identities or the
    /// checked history/audit/outbox transaction cannot commit.
    #[allow(clippy::too_many_arguments)]
    pub async fn delete_project_at_version(
        &self,
        org_id: i64,
        project_id: i64,
        expected_version: i64,
        change_id: &str,
        actor_kind: &str,
        actor_id: Option<i64>,
        actor_label: &str,
    ) -> Result<bool> {
        let Some(project) = self
            .list_projects(org_id)
            .await?
            .into_iter()
            .find(|project| project.id == project_id)
        else {
            return Ok(false);
        };
        if project.resource_version != expected_version {
            return Ok(false);
        }
        let now = unix_now();
        let event_id = uuid::Uuid::new_v4().simple().to_string();
        let old_json = serde_json::to_string(&serde_json::json!({
            "stableId": &project.stable_id,
            "path": &project.path,
            "name": &project.name,
            "resourceVersion": expected_version,
        }))?;
        let payload_json = serde_json::to_string(&serde_json::json!({
            "changeId": change_id,
            "projectId": &project.stable_id,
            "path": &project.path,
            "resourceVersion": expected_version,
        }))?;
        let event = NewTopologyEvent {
            event_id: &event_id,
            event_name: "project.deleted",
            owner_scope_key: &project.scope_key,
            resource_kind: "project",
            resource_stable_id: &project.stable_id,
            resource_generation_key: expected_version,
            actor_kind,
            actor_id,
            actor_label,
            payload_json: &payload_json,
            occurred_at: now,
        };
        let summary = format!("delete empty project path '{}'", project.path);
        self.backend
            .checked_batch(&[
                Statement::new(
                    "INSERT INTO change_requests
                     (change_id, actor_kind, actor_id, actor_label, scope, status,
                      summary, created_at, applied_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, 'applied', ?6, ?7, ?7)",
                    vals![
                        change_id,
                        actor_kind,
                        actor_id,
                        sanitize_log_text(actor_label),
                        project.scope_key,
                        summary,
                        now
                    ],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO change_request_revisions
                     (change_id, object_type, object_id, op, old_json, new_json, seq)
                     VALUES (?1, 'project', ?2, 'delete', ?3, NULL, 0)",
                    vals![change_id, project.stable_id, old_json],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO audit_log
                     (outbox_event_id, change_id, actor_kind, actor_id, actor_label,
                      action, scope, detail, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, 'project.deleted', ?6, ?7, ?8)",
                    vals![
                        event_id,
                        change_id,
                        actor_kind,
                        actor_id,
                        sanitize_log_text(actor_label),
                        project.scope_key,
                        payload_json,
                        now
                    ],
                )
                .expecting(1),
                Self::topology_event_statement(&event),
                Statement::new(
                    "DELETE FROM projects
                      WHERE id = ?1 AND org_id = ?2 AND scope_key = ?3
                        AND resource_version = ?4
                        AND NOT EXISTS (SELECT 1 FROM registries
                          WHERE org_id = ?2 AND project_path = ?5)",
                    vals![
                        project_id,
                        org_id,
                        project.scope_key,
                        expected_version,
                        project.path
                    ],
                )
                .expecting(1),
                Statement::new(
                    "UPDATE authorization_scopes SET retired_at = ?2
                      WHERE scope_key = ?1 AND kind = 'project' AND retired_at IS NULL",
                    vals![project.scope_key, now],
                )
                .expecting(1),
            ])
            .await?;
        Ok(true)
    }

    /// Deletes a project fixture without exercising the control plane.
    ///
    /// This helper is absent from optimized production builds.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    #[cfg(any(test, debug_assertions))]
    pub async fn seed_delete_project_for_test(&self, org_id: i64, project_id: i64) -> Result<bool> {
        let Some(scope_key) = self
            .backend
            .query_opt(
                "SELECT scope_key FROM projects WHERE id = ?1 AND org_id = ?2",
                &vals![project_id, org_id],
            )
            .await?
            .map(|row| row.get::<String>(0))
            .transpose()?
        else {
            return Ok(false);
        };
        self.backend
            .checked_batch(&[
                Statement::new(
                    "DELETE FROM projects WHERE id = ?1 AND org_id = ?2 AND scope_key = ?3",
                    vals![project_id, org_id, scope_key],
                )
                .expecting(1),
                Statement::new(
                    "DELETE FROM authorization_scopes WHERE scope_key = ?1 AND kind = 'project'",
                    vals![scope_key],
                )
                .expecting(1),
            ])
            .await?;
        Ok(true)
    }

    /// Create a service account under an org; returns the new id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, including a unique-constraint
    /// violation when `(org_id, name)` already exists.
    pub async fn create_service_account(&self, org_id: i64, name: &str) -> Result<i64> {
        self.backend
            .execute_insert(
                "INSERT INTO service_accounts (org_id, name, created_at) VALUES (?1, ?2, ?3)",
                &vals![org_id, name, unix_now()],
            )
            .await
    }

    /// Look up a service account's id by `(org_id, name)`.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn service_account_by_name(&self, org_id: i64, name: &str) -> Result<Option<i64>> {
        self.backend
            .query_opt(
                "SELECT id FROM service_accounts WHERE org_id = ?1 AND name = ?2",
                &vals![org_id, name],
            )
            .await
            .context("loading service account by name")?
            .map(|row| row.get(0))
            .transpose()
    }

    /// Loads one service account by organization and name.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn service_account_record(
        &self,
        org_id: i64,
        name: &str,
    ) -> Result<Option<ServiceAccountRecord>> {
        self.backend
            .query_opt(
                "SELECT id, org_id, name, created_at FROM service_accounts
                 WHERE org_id = ?1 AND name = ?2",
                &vals![org_id, name],
            )
            .await?
            .map(|row| {
                Ok(ServiceAccountRecord {
                    id: row.get(0)?,
                    org_id: row.get(1)?,
                    name: row.get(2)?,
                    created_at: row.get(3)?,
                })
            })
            .transpose()
    }

    /// Renames one service account when its current name still matches.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, including name collisions.
    pub async fn rename_service_account(
        &self,
        id: i64,
        expected_name: &str,
        new_name: &str,
    ) -> Result<bool> {
        Ok(self
            .backend
            .execute(
                "UPDATE service_accounts SET name = ?3 WHERE id = ?1 AND name = ?2",
                &vals![id, expected_name, new_name],
            )
            .await?
            == 1)
    }

    /// Deletes one service account when its current name still matches.
    ///
    /// Direct memberships are removed in the same transaction. Owned tokens
    /// remain as audit metadata but immediately become unusable because token
    /// validation requires a live principal.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn delete_service_account(&self, id: i64, expected_name: &str) -> Result<()> {
        self.backend
            .checked_batch(&[
                Statement::new(
                    "UPDATE service_accounts SET name = name WHERE id = ?1 AND name = ?2",
                    vals![id, expected_name],
                )
                .expecting(1),
                Statement::new(
                    "DELETE FROM memberships
                     WHERE principal_kind = 'service_account' AND principal_id = ?1",
                    vals![id],
                )
                .unchecked(),
                Statement::new(
                    "DELETE FROM service_accounts WHERE id = ?1 AND name = ?2",
                    vals![id, expected_name],
                )
                .expecting(1),
            ])
            .await?;
        Ok(())
    }

    /// Returns the canonical `org/service-account` reference for a live account.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn service_account_reference(
        &self,
        service_account_id: i64,
    ) -> Result<Option<String>> {
        self.backend
            .query_opt(
                "SELECT o.slug, sa.name
                 FROM service_accounts sa
                 JOIN orgs o ON o.id = sa.org_id
                 WHERE sa.id = ?1 AND o.deleted_at IS NULL",
                &vals![service_account_id],
            )
            .await
            .context("loading service account reference")?
            .map(|row| {
                Ok(format!(
                    "{}/{}",
                    row.get::<String>(0)?,
                    row.get::<String>(1)?
                ))
            })
            .transpose()
    }
}
