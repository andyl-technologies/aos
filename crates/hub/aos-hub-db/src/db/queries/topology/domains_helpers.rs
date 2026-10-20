//! Domains helpers in the topology capability.

use super::*;

impl Database {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::db) async fn apply_org_domain_mutation_plan(
        &self,
        mutation: CheckedStatement,
        action: &str,
        domain: &str,
        scope: &str,
        plan_id: &str,
        apply_idempotency_key: &str,
        result_json: &str,
        actor_kind: &str,
        actor_id: Option<i64>,
        actor_label: &str,
        audit_event_id: &str,
    ) -> Result<()> {
        validate_key_bytes(apply_idempotency_key, "apply idempotency key", 128)?;
        validate_key_bytes(audit_event_id, "audit event id", 64)?;
        validate_json_value(result_json, "apply result")?;
        let now = unix_now();
        self.backend
            .checked_batch(&[
                mutation,
                Statement::new(
                    "INSERT INTO audit_log
                 (outbox_event_id, change_id, actor_kind, actor_id, actor_label,
                  action, scope, detail, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    vals![
                        audit_event_id,
                        plan_id,
                        actor_kind,
                        actor_id,
                        sanitize_log_text(actor_label),
                        sanitize_log_text(action),
                        sanitize_log_text(scope),
                        sanitize_log_text(domain),
                        now
                    ],
                )
                .expecting(1),
                Statement::new(
                    "UPDATE topology_plans SET applied_at = ?4, apply_result_json = ?3
                   WHERE plan_id = ?1 AND apply_idempotency_key = ?2 AND applied_at IS NULL",
                    vals![plan_id, apply_idempotency_key, result_json, now],
                )
                .expecting(1),
            ])
            .await
    }
}
