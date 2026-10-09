//! Operations helpers in the topology capability.

use super::*;

impl Database {
    /// Builds the insert appended to an atomic topology mutation batch.
    pub(in crate::db) fn topology_event_insert_statement(event: &NewTopologyEvent<'_>) -> Statement {
        Statement::new(
            "INSERT INTO topology_event_outbox
             (event_id, event_name, owner_scope_key, resource_kind,
              resource_stable_id, resource_generation_key, actor_kind, actor_id,
              actor_label, payload_json, occurred_at)
             SELECT ?1, ?2, scope_key, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11
               FROM authorization_scopes WHERE scope_key = ?3 AND retired_at IS NULL",
            vals![
                event.event_id,
                event.event_name,
                event.owner_scope_key,
                event.resource_kind,
                event.resource_stable_id,
                event.resource_generation_key,
                event.actor_kind,
                event.actor_id,
                sanitize_log_text(event.actor_label),
                event.payload_json,
                event.occurred_at
            ],
        )
    }

    /// Builds the checked insert appended to an atomic topology mutation batch.
    pub(in crate::db) fn topology_event_statement(event: &NewTopologyEvent<'_>) -> CheckedStatement {
        Self::topology_event_insert_statement(event).expecting(1)
    }
}
