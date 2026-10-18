//! Commits portable webhook events to the durable delivery outbox.

use aos_hub_db::db::Database;
pub use aos_hub_model::webhook::*;

/// Commits one operational event to the canonical topology outbox.
///
/// Producer retries use the event's semantic key to converge on one immutable
/// outbox identity. The ordinary materializer performs subscription fanout and
/// creates stable delivery IDs; operational events therefore have exactly the
/// same audit, Queue, lease, and deduplication path as topology mutations.
/// Returns `1` when it inserts the event and `0` when a producer retry finds
/// the same semantic identity already durable.
///
/// # Errors
///
/// Returns an error for serialization, inconsistent registry ownership, or
/// outbox persistence failure.
pub async fn dispatch(db: &Database, org_id: i64, event: &WebhookEvent) -> anyhow::Result<usize> {
    let event_type = event.event_type();
    let payload = serde_json::to_string(&event.payload())?;
    let dedupe_key = serde_json::to_string(&event.dedupe_key())?;
    Ok(
        if db
            .enqueue_operational_webhook_event(
                org_id,
                event.registry(),
                event_type,
                &dedupe_key,
                &payload,
            )
            .await?
        {
            1
        } else {
            0
        },
    )
}
