//! Sessions helpers in the identity capability.

use super::*;

impl Database {
    /// Validates live session state at one clock sample, preserving second-level idle expiry.
    pub(in crate::db) async fn validate_session_at(
        &self,
        secret: &str,
        now: i64,
    ) -> Result<Option<SessionAuth>> {
        use aos_hub_model::auth::session::{ABSOLUTE_LIFETIME_SECS, IDLE_TIMEOUT_SECS};
        let hash = aos_hub_model::auth::token::sha256_hex(secret);
        let row = self
            .backend
            .query_opt(
                "SELECT s.user_id, s.auth_level, s.last_authenticated_at, s.expires_at,
                        s.created_at, s.last_seen_at
                 FROM sessions s JOIN users u ON u.id = s.user_id
                 WHERE s.id_hash = ?1 AND u.deleted_at IS NULL",
                &vals![hash],
            )
            .await
            .context("loading session by hash")?
            .map(|row| -> Result<(SessionAuth, i64, i64)> {
                let auth = SessionAuth {
                    user_id: row.get(0)?,
                    auth_level: row.get(1)?,
                    last_authenticated_at: row.get(2)?,
                    expires_at: row.get(3)?,
                };
                let created_at: i64 = row.get(4)?;
                let last_seen_at: i64 = row.get(5)?;
                Ok((auth, created_at, last_seen_at))
            })
            .transpose()?;
        let Some((session, created_at, last_seen_at)) = row else {
            return Ok(None);
        };
        // Absolute deadline (the stamped cap), idle timeout (no activity for
        // too long), and the absolute lifetime from creation. A session that
        // crosses any bound is dead; expire it so the row does not linger.
        let dead = now >= session.expires_at
            || now.saturating_sub(last_seen_at) > IDLE_TIMEOUT_SECS
            || now.saturating_sub(created_at) > ABSOLUTE_LIFETIME_SECS;
        if dead {
            self.backend
                .execute("DELETE FROM sessions WHERE id_hash = ?1", &vals![hash])
                .await?;
            return Ok(None);
        }
        // Repeated reads within one clock second must not rewrite identical
        // bookkeeping. The SQL predicate also covers concurrent validations;
        // liveness and expiry above remain authoritative on every request.
        self.backend
            .execute(
                "UPDATE sessions SET last_seen_at = ?2
                 WHERE id_hash = ?1 AND last_seen_at != ?2",
                &vals![hash, now],
            )
            .await?;
        Ok(Some(session))
    }
}
