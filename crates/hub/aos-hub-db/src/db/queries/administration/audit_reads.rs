//! Audit reads in the administration capability.

use super::*;

impl Database {
    /// List audit entries at or below `scope`, newest first.
    ///
    /// Returns entries whose recorded `scope` is `scope` or any descendant
    /// of it (so an org-scoped query surfaces actions on its registries),
    /// using the persisted stable-scope ancestor graph. The `instance` scope
    /// lists every entry whose subject scope is still live.
    ///
    /// The `audit_log` is append-only and grows without bound, so the DB read
    /// is capped at `MAX_AUDIT_SCAN` **most-recent** rows before the
    /// scope filter is applied in Rust: a single request can never materialize
    /// the whole table. Scope-filtered results are therefore drawn from the
    /// most recent `MAX_AUDIT_SCAN` entries — ample for the console's paged
    /// audit view and the `ListAudit` RPC, which surface recent activity.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_audit(&self, scope: &str) -> Result<Vec<AuditRow>> {
        self.materialize_topology_events().await?;
        let rows = self
            .backend
            .query(
                "SELECT id, change_id, actor_kind, actor_label, action, scope,
                    result_commit, result_tag, detail, created_at
             FROM audit_log ORDER BY id DESC LIMIT ?1",
                &vals![MAX_AUDIT_SCAN],
            )
            .await?;
        let mut out = Vec::new();
        for row in &rows {
            let entry = AuditRow {
                id: row.get(0)?,
                change_id: row.get(1)?,
                actor_kind: row.get(2)?,
                actor_label: row.get(3)?,
                action: row.get(4)?,
                scope: row.get(5)?,
                result_commit: row.get(6)?,
                result_tag: row.get(7)?,
                detail: row.get(8)?,
                created_at: row.get(9)?,
            };
            let covered = self
                .backend
                .query_opt(
                    "SELECT 1 FROM authorization_scope_ancestors
                      WHERE descendant_scope_key = ?1 AND ancestor_scope_key = ?2",
                    &vals![entry.scope, scope],
                )
                .await?
                .is_some();
            if covered {
                out.push(entry);
            }
        }
        Ok(out)
    }
}
