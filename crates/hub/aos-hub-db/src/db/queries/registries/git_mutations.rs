//! Git mutations in the registries capability.

use super::*;

impl Database {
    /// Create a git-backed change-request change-set in `draft` status.
    ///
    /// Identical to [`Self::create_changeset`] but additionally records the
    /// draft ref (`refs/hub/changes/<change_id>`) the hub wrote and the signed
    /// draft-commit oid it points at (RFC-0004 "Configuration management",
    /// git-backed path). These columns are `NULL` for SQL-only change-sets;
    /// their presence is what marks a change-set as a git-backed change request
    /// the console and `apr change` surface and promote.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, including a primary-key collision
    /// on `change_id`.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_git_changeset(
        &self,
        change_id: &str,
        actor_kind: &str,
        actor_id: Option<i64>,
        actor_label: &str,
        scope: &str,
        summary: Option<&str>,
        git_ref: &str,
        git_commit: &str,
        title: Option<&str>,
        body: Option<&str>,
    ) -> Result<()> {
        if !aos_hub_model::domain::Scope::is_canonical(scope) {
            bail!("git change-set scope is not canonical");
        }
        let affected = self
            .backend
            .execute(
                "INSERT INTO change_requests
             (change_id, actor_kind, actor_id, actor_label, scope, status,
              summary, created_at, applied_at, reverted_by_change_id, git_ref, git_commit,
              title, body)
             SELECT ?1, ?2, ?3, ?4, a.scope_key, 'draft', ?6, ?7, NULL, NULL,
                    ?8, ?9, ?10, ?11
               FROM authorization_scopes a LEFT JOIN orgs o ON o.id = a.org_id
              WHERE a.scope_key = ?5 AND (a.org_id IS NULL OR o.deleted_at IS NULL)",
                &vals![
                    change_id,
                    actor_kind,
                    actor_id,
                    actor_label,
                    scope,
                    summary,
                    unix_now(),
                    git_ref,
                    git_commit,
                    title,
                    body,
                ],
            )
            .await?;
        if affected != 1 {
            bail!("git change-set scope does not identify a live scope");
        }
        Ok(())
    }
}
