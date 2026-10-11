//! Original browser-session owner pins for cold and cached authentication.
//!
//! A cookie identifies a retained session row. Its numeric user ID is only an
//! address: the UUID stored at genuine mint must still match the current user.
//! Legacy rows without that original pin require reauthentication, and this
//! read-only check never fills an absent pin from a replacement account.

use anyhow::Result;

use super::{Database, SessionAuth, direct_identity, unix_now};
use crate::auth::session::{ABSOLUTE_LIFETIME_SECS, IDLE_TIMEOUT_SECS};
use crate::domain::Principal;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;

impl Database {
    /// Checks that a resolved cookie still owns its original live session.
    ///
    /// Cold and cached callers retain the authenticated secret hash and UUID.
    /// This query compares both with the original session row and live account,
    /// and applies the current idle and absolute lifetime bounds. It performs
    /// no bookkeeping write, principal creation or legacy-pin repair.
    ///
    /// # Errors
    /// Returns an error on database failure or malformed retained scalar data.
    pub async fn session_auth_is_current(&self, auth: &SessionAuth) -> Result<bool> {
        self.session_auth_is_current_at(auth, unix_now()).await
    }

    pub(super) async fn session_auth_is_current_at(
        &self,
        auth: &SessionAuth,
        now: i64,
    ) -> Result<bool> {
        if auth.session_id_hash.len() != 64
            || !auth
                .session_id_hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || direct_identity::validate_actor_incarnation(
                Principal::user(auth.user_id),
                &auth.owner_incarnation,
            )
            .is_err()
        {
            return Ok(false);
        }

        let Some(row) = self
            .backend
            .query_opt(
                "SELECT s.created_at, s.last_seen_at, s.expires_at
             FROM sessions s JOIN users u ON u.id = s.user_id
             WHERE s.id_hash = ?1 AND s.user_id = ?2 AND s.owner_incarnation = ?3
               AND s.expires_at = ?4 AND u.deleted_at IS NULL
               AND u.principal_incarnation = s.owner_incarnation",
                &vals![
                    auth.session_id_hash,
                    auth.user_id,
                    auth.owner_incarnation,
                    auth.expires_at
                ],
            )
            .await?
        else {
            return Ok(false);
        };
        let created_at: i64 = row.get(0)?;
        let last_seen_at: i64 = row.get(1)?;
        let expires_at: i64 = row.get(2)?;
        let latest = unix_now().max(now);
        Ok(latest < expires_at
            && latest.saturating_sub(last_seen_at) <= IDLE_TIMEOUT_SECS
            && latest.saturating_sub(created_at) <= ABSOLUTE_LIFETIME_SECS)
    }
}
