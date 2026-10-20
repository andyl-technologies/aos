//! Projects helpers in the tenancy capability.

use super::*;

impl Database {
    pub(in crate::db) async fn create_project_with_plan(
        &self,
        org_id: i64,
        path: &str,
        name: &str,
        creation_plan_id: Option<&str>,
        actor_kind: Option<&str>,
        actor_id: Option<i64>,
        actor_label: Option<&str>,
    ) -> Result<i64> {
        let incarnation = uuid::Uuid::new_v4();
        // Client-generated ids avoid the `MAX(id) + 1` race across native,
        // PostgreSQL, MySQL, SQLite, and HubDb writers. The stable incarnation remains the
        // idempotency identity; the positive portable integer is only the
        // local relational key.
        let project_id = portable_relational_id(incarnation);
        let stable_id = format!("project:{}", incarnation.simple());
        let org_scope: String = self
            .backend
            .query_opt(
                "SELECT stable_id FROM orgs WHERE id = ?1 AND deleted_at IS NULL",
                &vals![org_id],
            )
            .await?
            .context("project owner organization does not exist")?
            .get(0)?;
        let scope_key = stable_id.clone();
        let now = unix_now();
        let mut statements = vec![
            Statement::new(
                "INSERT INTO authorization_scopes
                     (scope_key, kind, org_id, parent_scope_key, resource_stable_id, created_at)
                     VALUES (?1, 'project', ?2, ?3, ?1, ?4)",
                vals![scope_key, org_id, org_scope, now],
            )
            .expecting(1),
            Statement::new(
                "INSERT INTO authorization_scope_ancestors
                     (descendant_scope_key, ancestor_scope_key, depth)
                     VALUES (?1, ?1, 0)",
                vals![scope_key],
            )
            .expecting(1),
            Statement::new(
                "INSERT INTO authorization_scope_ancestors
                     (descendant_scope_key, ancestor_scope_key, depth)
                     SELECT ?1, ancestor_scope_key, depth + 1
                       FROM authorization_scope_ancestors
                      WHERE descendant_scope_key = ?2",
                vals![scope_key, org_scope],
            )
            .unchecked(),
            Statement::new(
                "INSERT INTO projects
                     (id, stable_id, scope_key, owner_scope_key, org_id, path, name,
                      created_at, updated_at, creation_plan_id)
                     SELECT ?1, ?2, ?2, ?3, ?4, ?5, ?6, ?7, ?7, ?8
                     WHERE EXISTS (SELECT 1 FROM orgs
                       WHERE id = ?4 AND stable_id = ?3 AND deleted_at IS NULL)",
                vals![
                    project_id,
                    stable_id,
                    org_scope,
                    org_id,
                    path,
                    name,
                    now,
                    creation_plan_id
                ],
            )
            .expecting(1),
        ];
        if let (Some(change_id), Some(actor_kind), Some(actor_label)) =
            (creation_plan_id, actor_kind, actor_label)
        {
            let new_json = serde_json::to_string(&serde_json::json!({
                "stableId": &stable_id,
                "path": path,
                "name": name,
                "resourceVersion": 1,
            }))?;
            let event_id = uuid::Uuid::new_v4().simple().to_string();
            let payload_json = serde_json::to_string(&serde_json::json!({
                "changeId": change_id,
                "projectId": &stable_id,
                "path": path,
                "resourceVersion": 1,
            }))?;
            let summary = format!("create project path '{path}'");
            statements.extend([
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
                        stable_id,
                        summary,
                        now
                    ],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO change_request_revisions
                     (change_id, object_type, object_id, op, old_json, new_json, seq)
                     VALUES (?1, 'project', ?2, 'create', NULL, ?3, 0)",
                    vals![change_id, stable_id, new_json],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO audit_log
                     (outbox_event_id, change_id, actor_kind, actor_id, actor_label,
                      action, scope, detail, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, 'project.created', ?6, ?7, ?8)",
                    vals![
                        event_id,
                        change_id,
                        actor_kind,
                        actor_id,
                        sanitize_log_text(actor_label),
                        stable_id,
                        payload_json,
                        now
                    ],
                )
                .expecting(1),
                Self::topology_event_statement(&NewTopologyEvent {
                    event_id: &event_id,
                    event_name: "project.created",
                    owner_scope_key: &stable_id,
                    resource_kind: "project",
                    resource_stable_id: &stable_id,
                    resource_generation_key: 1,
                    actor_kind,
                    actor_id,
                    actor_label,
                    payload_json: &payload_json,
                    occurred_at: now,
                }),
            ]);
        }
        self.backend.checked_batch(&statements).await?;
        Ok(project_id)
    }
}
