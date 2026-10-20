//! Audit mutations in the administration capability.

use super::*;

impl Database {
    // -- audit log ----------------------------------------------------------

    /// Append one audit-log row; returns its new id.
    ///
    /// Append-only: every mutating action that goes through the hub's
    /// SQL-backed write paths records exactly one row here. `change_id`
    /// ties the row to a configuration change-set when applicable;
    /// `result_commit`/`result_tag` cross-reference the cryptographic
    /// history for surface-touching operations (RFC-0004 "Tenancy and IAM").
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_audit(
        &self,
        actor_kind: &str,
        actor_id: Option<i64>,
        actor_label: &str,
        action: &str,
        scope: &str,
        change_id: Option<&str>,
        result_commit: Option<&str>,
        result_tag: Option<&str>,
        detail: Option<&str>,
    ) -> Result<i64> {
        // Sanitize the caller-controlled text fields against log/stored
        // injection: `actor_label` (token/session labels), `scope` (registry and
        // org slugs), and `detail` (free-form context, often a URL or name) can
        // carry attacker-influenced strings. Stripping embedded C0 controls here
        // — the single audit choke point — protects every caller without
        // touching the dozens of call sites. `actor_kind`/`action` are
        // hub-internal enum literals and are recorded verbatim.
        let actor_label = sanitize_log_text(actor_label);
        let scope = sanitize_log_text(scope);
        let detail = detail.map(sanitize_log_text);
        self.backend
            .execute_insert(
                "INSERT INTO audit_log
             (change_id, actor_kind, actor_id, actor_label, action, scope,
              result_commit, result_tag, detail, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                &vals![
                    change_id,
                    actor_kind,
                    actor_id,
                    actor_label,
                    action,
                    scope,
                    result_commit,
                    result_tag,
                    detail,
                    unix_now(),
                ],
            )
            .await
    }

    /// Whether an audit row already records `result_commit`.
    ///
    /// The indexer synthesizes one `external` audit entry per out-of-band
    /// (direct-publish) commit it observes; this check keeps that synthesis
    /// idempotent across re-indexes, so the same commit is never audited twice
    /// (RFC-0004 "Configuration management", cross-referencing).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn audit_exists_for_commit(&self, action: &str, result_commit: &str) -> Result<bool> {
        Ok(self
            .backend
            .query_opt(
                "SELECT 1 FROM audit_log WHERE action = ?1 AND result_commit = ?2 LIMIT 1",
                &vals![action, result_commit],
            )
            .await?
            .is_some())
    }
}
