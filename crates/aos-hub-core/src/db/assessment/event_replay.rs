//! Clock-consistent committed replay with explicit gaps and finite body admission.
//!
//! One database statement captures the resource incarnation, allocator, ordered
//! immutable events and heartbeat time. Reads neither prune history nor create
//! provider work, notifications or authority. Hosts reauthorize every poll.

use anyhow::Result;
use aos_assessment::time::Timestamp;
use aos_assessment_runtime::attention_control::EventPageV1;
use aos_assessment_runtime::events::AssessmentEventV1;
use aos_assessment_runtime::read_snapshot::ScanPageError;

use crate::db::Database;
use crate::dialect::Dialect;

impl Database {
    /// Reads one committed replay window under a single database observation.
    ///
    /// Sequence zero starts at the first retained event. A nonzero position must
    /// have uninterrupted successor custody, or be the current committed end.
    /// Missing interior/tail history fails explicitly instead of advancing a
    /// watch cursor over unobserved events. This read performs no retention.
    ///
    /// # Errors
    /// Returns a typed error for replaced scope, future cursors, missing/corrupt
    /// replay custody or excessive bodies, and an error for unavailable storage.
    pub async fn assessment_event_replay_page(
        &self,
        registry_id: i64,
        resource_scope: &str,
        after_sequence: u64,
        limit: u32,
    ) -> Result<EventPageV1> {
        if after_sequence > 9_007_199_254_740_991 || !(1..=10).contains(&limit) {
            return Err(ScanPageError::InvalidCursor.into());
        }
        let clock = self.backend.dialect().unix_time_expression();
        let bytes = match self.backend.dialect() {
            Dialect::Sqlite => "LENGTH(event.payload_json)",
            Dialect::Postgres | Dialect::Mysql => "OCTET_LENGTH(event.payload_json)",
        };
        let rows = self.backend.query(
            &format!(
                "WITH replay_position AS (
                    SELECT registry.scope_key, COALESCE(allocator.current_sequence, 0) AS high_water,
                        {clock} AS as_of,
                        COALESCE((SELECT event_sequence FROM assessment_events
                            WHERE registry_id = ?1 ORDER BY event_sequence DESC LIMIT 1), 0) AS physical_tail
                    FROM registries registry
                    LEFT JOIN assessment_event_sequences allocator ON allocator.registry_id = registry.id
                    WHERE registry.id = ?1 AND registry.scope_key = ?2
                ), selected AS (
                    SELECT event.event_sequence, event.occurred_at, {bytes} AS body_bytes,
                        CASE WHEN {bytes} <= 262144 THEN event.payload_json ELSE NULL END AS body
                    FROM assessment_events event
                    WHERE event.registry_id = ?1 AND event.event_sequence > ?3
                        AND event.event_sequence <= (SELECT high_water FROM replay_position)
                    ORDER BY event.event_sequence LIMIT ?4
                )
                SELECT replay_position.high_water, replay_position.as_of, replay_position.physical_tail,
                    selected.event_sequence, selected.occurred_at, selected.body_bytes, selected.body
                FROM replay_position LEFT JOIN selected ON 1 = 1 ORDER BY selected.event_sequence"
            ),
            &vals![@slice registry_id, resource_scope, after_sequence, limit],
        ).await?;
        let first = rows.first().ok_or(ScanPageError::SelectorChanged)?;
        let high_water: u64 = first.get(0)?;
        let as_of = Timestamp::from_unix_seconds(first.get(1)?)?;
        let physical_tail: u64 = first.get(2)?;
        if high_water > 9_007_199_254_740_991 || physical_tail > high_water {
            return Err(ScanPageError::CursorExpired.into());
        }
        if after_sequence > high_water {
            return Err(ScanPageError::InvalidCursor.into());
        }

        let mut events = Vec::with_capacity(rows.len());
        let mut previous = after_sequence;
        for row in &rows {
            let Some(sequence) = row.get::<Option<u64>>(3)? else {
                continue;
            };
            if sequence == 0 || (previous != 0 && sequence != previous + 1) || sequence > high_water
            {
                return Err(ScanPageError::CursorExpired.into());
            }
            let body_bytes: u64 = row.get(5)?;
            if body_bytes == 0 || body_bytes > 262_144 {
                return Err(ScanPageError::CapacityExceeded.into());
            }
            let body: Vec<u8> = row.get(6)?;
            let event =
                AssessmentEventV1::from_slice(&body).map_err(|_| ScanPageError::CursorExpired)?;
            let recorded_time = Timestamp::from_unix_seconds(row.get(4)?)?;
            if event.sequence != sequence
                || event.occurred_at != recorded_time
                || event.occurred_at > as_of
            {
                return Err(ScanPageError::CursorExpired.into());
            }
            previous = sequence;
            events.push(event);
        }
        if events.len() < limit as usize && previous != high_water {
            return Err(ScanPageError::CursorExpired.into());
        }
        let page = EventPageV1 {
            schema: "aos.assessment-event-page/v1".into(),
            resource_scope: resource_scope.into(),
            as_of,
            events,
            next_sequence: previous,
        };
        // Apply the shared response limit before any host can publish the page.
        page.to_bytes()?;
        Ok(page)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "event_replay_tests.rs"]
pub(super) mod tests;
