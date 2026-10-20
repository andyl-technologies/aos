//! Sessions helpers in the identity capability.

use super::*;

impl Database {
    /// Validates the cookie's original UUID without adopting a recycled owner.
    pub(in crate::db) async fn validate_session_at(
        &self,
        secret: &str,
        now: i64,
    ) -> Result<Option<SessionAuth>> {
        use aos_hub_model::auth::session::ABSOLUTE_LIFETIME_SECS;
        use aos_hub_model::auth::session::IDLE_TIMEOUT_SECS;

        let hash = aos_hub_model::auth::token::sha256_hex(secret);
        let Some(row) = self
            .backend
            .query_opt(
                "SELECT s.user_id, s.auth_level, s.last_authenticated_at, s.expires_at,
                    s.created_at, s.last_seen_at, s.owner_incarnation
             FROM sessions s JOIN users u ON u.id = s.user_id
             WHERE s.id_hash = ?1 AND u.deleted_at IS NULL
               AND s.owner_incarnation IS NOT NULL
               AND s.owner_incarnation = u.principal_incarnation",
                &vals![hash],
            )
            .await
            .context("loading session by hash")?
        else {
            return Ok(None);
        };
        let user_id: i64 = row.get(0)?;
        let owner_incarnation: String = row.get(6)?;
        if direct_identity::validate_actor_incarnation(
            aos_hub_model::domain::Principal::user(user_id),
            &owner_incarnation,
        )
        .is_err()
        {
            return Ok(None);
        }
        let created_at: i64 = row.get(4)?;
        let last_seen_at: i64 = row.get(5)?;
        let expires_at: i64 = row.get(3)?;
        let dead = now >= expires_at
            || now.saturating_sub(last_seen_at) > IDLE_TIMEOUT_SECS
            || now.saturating_sub(created_at) > ABSOLUTE_LIFETIME_SECS;
        if dead {
            self.backend
                .execute(
                    "DELETE FROM sessions WHERE id_hash = ?1 AND user_id = ?2
                       AND owner_incarnation = ?3 AND created_at = ?4 AND expires_at = ?5",
                    &vals![hash, user_id, owner_incarnation, created_at, expires_at],
                )
                .await?;
            return Ok(None);
        }

        // Same-second reads avoid a bookkeeping write. Every actual update
        // remains tied to the original session UUID and live account UUID.
        self.backend
            .execute(
                "UPDATE sessions SET last_seen_at = ?2
             WHERE id_hash = ?1 AND user_id = ?3 AND created_at = ?4
               AND expires_at = ?5 AND owner_incarnation = ?6 AND last_seen_at != ?2
               AND EXISTS (SELECT 1 FROM users u WHERE u.id = sessions.user_id
                 AND u.deleted_at IS NULL AND u.principal_incarnation = ?6)",
                &vals![
                    hash,
                    now,
                    user_id,
                    created_at,
                    expires_at,
                    owner_incarnation
                ],
            )
            .await?;
        let auth = SessionAuth {
            owner_incarnation,
            session_id_hash: hash,
            user_id,
            auth_level: row.get(1)?,
            last_authenticated_at: row.get(2)?,
            expires_at,
        };
        if !self.session_auth_is_current_at(&auth, now).await? {
            return Ok(None);
        }
        Ok(Some(auth))
    }
}
