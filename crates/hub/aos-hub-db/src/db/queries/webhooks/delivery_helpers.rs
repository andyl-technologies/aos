//! Delivery helpers in the webhooks capability.

use super::*;

impl Database {
    /// Builds a deduplicated registry event insert for an atomic mutation batch.
    pub(in crate::db) fn operational_webhook_event_insert_statement(
        registry: &RegistryRecord,
        event: &aos_hub_model::webhook::WebhookEvent,
        dedupe_key: Option<&str>,
        occurred_at: i64,
    ) -> Result<Statement> {
        let event_name = event.event_type();
        anyhow::ensure!(
            aos_hub_model::webhook::is_supported_event_type(event_name)
                && aos_hub_model::webhook::is_safe_event_header_value(event_name),
            "unsupported webhook event"
        );
        anyhow::ensure!(
            event.registry() == registry.slug,
            "webhook event registry identity is inconsistent"
        );
        let payload_json = serde_json::to_string(&event.payload())?;
        anyhow::ensure!(
            payload_json.len() <= 1024 * 1024,
            "webhook event payload exceeds limit"
        );
        let canonical_dedupe_key;
        let dedupe_key = match dedupe_key {
            Some(value) => value,
            None => {
                canonical_dedupe_key = serde_json::to_string(&event.dedupe_key())?;
                &canonical_dedupe_key
            }
        };
        let event_id = hex::encode(sha2::Sha256::digest(
            format!(
                "aos-operational-webhook-v1\0{}\0{}\0{}",
                registry.stable_id, event_name, dedupe_key
            )
            .as_bytes(),
        ));
        Ok(Statement::new(
            "INSERT INTO topology_event_outbox
             (event_id, event_name, owner_scope_key, resource_kind,
              resource_stable_id, resource_generation_key, actor_kind, actor_id,
              actor_label, payload_json, occurred_at)
             SELECT ?1, ?2, scope_key, 'registry', ?4, ?5, 'system', NULL,
                    'registry-event-producer', ?6, ?7
               FROM authorization_scopes
              WHERE scope_key = ?3 AND retired_at IS NULL
                AND NOT EXISTS (SELECT 1 FROM topology_event_outbox WHERE event_id = ?1)",
            vals![
                event_id,
                event_name,
                registry.scope_key,
                registry.stable_id,
                registry.resource_version,
                payload_json,
                occurred_at
            ],
        ))
    }
}
