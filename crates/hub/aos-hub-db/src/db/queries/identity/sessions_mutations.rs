//! Sessions mutations in the identity capability.

use super::*;

impl Database {
    // -- auth: human sessions -----------------------------------------------

    /// Create a session for `user_id`, returning the opaque cookie secret.
    ///
    /// Only the SHA-256 hash of the secret is stored. `ttl_secs` is the
    /// session's **absolute** lifetime: `expires_at` is stamped to
    /// `now + ttl_secs` (callers pass
    /// [`ABSOLUTE_LIFETIME_SECS`](aos_hub_model::auth::session::ABSOLUTE_LIFETIME_SECS)).
    /// An independent idle timeout is enforced in
    /// [`validate_session`](Self::validate_session) via `last_seen_at`.
    /// `auth_level` is `1` for a sudo-capable session (the user
    /// re-authenticated) and `0` otherwise; `last_authenticated_at` is stamped
    /// to now so the sudo window is meaningful.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn create_session(
        &self,
        user_id: i64,
        ttl_secs: i64,
        auth_level: i64,
    ) -> Result<String> {
        let secret = aos_hub_model::auth::session::new_session_secret();
        let hash = aos_hub_model::auth::token::sha256_hex(&secret);
        let now = unix_now();
        let affected = self
            .backend
            .execute(
                "INSERT INTO sessions
             (id_hash, user_id, created_at, last_seen_at, expires_at, auth_level,
              last_authenticated_at)
             SELECT ?1, u.id, ?3, ?3, ?4, ?5, ?3 FROM users u
              WHERE u.id = ?2 AND u.deleted_at IS NULL",
                &vals![hash, user_id, now, now + ttl_secs, auth_level],
            )
            .await?;
        if affected != 1 {
            bail!("session owner does not identify a live user");
        }
        Ok(secret)
    }

    /// Validate a session cookie secret, returning its [`SessionAuth`].
    ///
    /// Accepts the secret when its hash is known and the session is live under
    /// all three lifetime bounds, then bumps `last_seen_at` to now (sliding
    /// the idle window). Returns `Ok(None)` for an unknown session or one that
    /// has crossed any bound:
    ///
    /// - **absolute deadline**: `now >= expires_at` (the
    ///   [`ABSOLUTE_LIFETIME_SECS`](aos_hub_model::auth::session::ABSOLUTE_LIFETIME_SECS)
    ///   cap stamped at creation, also covered by `created_at`);
    /// - **idle timeout**: `now - last_seen_at` exceeds
    ///   [`IDLE_TIMEOUT_SECS`](aos_hub_model::auth::session::IDLE_TIMEOUT_SECS);
    /// - **absolute lifetime**: `now - created_at` exceeds
    ///   [`ABSOLUTE_LIFETIME_SECS`](aos_hub_model::auth::session::ABSOLUTE_LIFETIME_SECS).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn validate_session(&self, secret: &str) -> Result<Option<SessionAuth>> {
        self.validate_session_at(secret, unix_now()).await
    }

    /// The signed-in user's email for a session secret, without bumping
    /// `last_seen_at` (the masthead reads this on every page render).
    ///
    /// Returns `None` when the secret is unknown, the session is expired, or
    /// the user was deleted.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn session_email(&self, secret: &str) -> Result<Option<String>> {
        let hash = aos_hub_model::auth::token::sha256_hex(secret);
        let now = unix_now();
        self.backend
            .query_opt(
                "SELECT u.email FROM sessions s JOIN users u ON u.id = s.user_id
                 WHERE s.id_hash = ?1 AND s.expires_at > ?2 AND u.deleted_at IS NULL",
                &vals![hash, now],
            )
            .await
            .context("loading session email")?
            .map(|row| row.get(0))
            .transpose()
    }

    /// Revoke a single session by its cookie secret.
    ///
    /// A no-op when the secret is unknown.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn revoke_session(&self, secret: &str) -> Result<()> {
        let hash = aos_hub_model::auth::token::sha256_hex(secret);
        self.backend
            .execute("DELETE FROM sessions WHERE id_hash = ?1", &vals![hash])
            .await?;
        Ok(())
    }

    /// Revoke every session belonging to a user ("sign out everywhere").
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn revoke_all_user_sessions(&self, user_id: i64) -> Result<()> {
        self.backend
            .execute("DELETE FROM sessions WHERE user_id = ?1", &vals![user_id])
            .await?;
        Ok(())
    }

    /// Elevate a session to sudo: set `auth_level = 1` and stamp
    /// `last_authenticated_at = now`.
    ///
    /// A no-op when the secret is unknown.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn elevate_session(&self, secret: &str) -> Result<()> {
        let hash = aos_hub_model::auth::token::sha256_hex(secret);
        self.backend
            .execute(
                "UPDATE sessions SET auth_level = 1, last_authenticated_at = ?2 WHERE id_hash = ?1",
                &vals![hash, unix_now()],
            )
            .await?;
        Ok(())
    }
}
