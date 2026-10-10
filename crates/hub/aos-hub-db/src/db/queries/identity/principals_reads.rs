//! Principals reads in the identity capability.

use super::*;

impl Database {
    /// Whether a user holds any role grant at any scope.
    ///
    /// Used by the `invite_only` signup gate: an existing member of some org
    /// may create another org without an invitation (RFC-0004).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    /// The number of orgs a user currently *owns* (holds an `Owner`
    /// membership on at an organization authorization scope).
    ///
    /// Used by the org-creation cap (the hub's `ratelimit::MAX_ORGS_PER_OWNER`) to bound namespace
    /// pollution. Scope identities are opaque, so the query joins their typed
    /// authorization records instead of inferring resource kind from key text.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn count_user_owned_orgs(&self, user_id: i64) -> Result<i64> {
        self.backend
            .query_opt(
                "SELECT COUNT(*) FROM memberships m
                 JOIN authorization_scopes s ON s.scope_key = m.scope_key
                 WHERE m.principal_kind = 'user' AND m.principal_id = ?1
                   AND m.role = 'owner' AND s.kind = 'organization'",
                &vals![user_id],
            )
            .await?
            .context("owned-org count query returned no row")?
            .get(0)
    }

    /// List a user's registered WebAuthn credentials, newest first.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_user_credentials(
        &self,
        user_id: i64,
    ) -> Result<Vec<WebauthnCredentialRecord>> {
        self.backend
            .query(
                "SELECT id, user_id, credential_id, public_key, sign_count, transports,
                        label, created_at, last_used_at
                 FROM webauthn_credentials WHERE user_id = ?1
                 ORDER BY created_at DESC, id DESC",
                &vals![user_id],
            )
            .await
            .context("listing user webauthn credentials")?
            .iter()
            .map(row_to_webauthn_credential)
            .collect()
    }

    /// Find a user by email, creating one if absent; returns the user id.
    ///
    /// The human-login path: a magic link or an invitation accepts an email
    /// and needs the user row whether or not it already exists. The lookup
    /// and insert run under one connection lock, so two concurrent first
    /// sign-ins for the same address resolve to one row (the second insert
    /// hits the `UNIQUE(email)` constraint and falls back to the lookup).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn find_or_create_user(&self, email: &str) -> Result<i64> {
        if let Some(id) = self.user_by_email(email).await? {
            return Ok(id);
        }
        self.backend
            .execute(
                "INSERT INTO users (email, display_name, created_at) VALUES (?1, NULL, ?2)
             ON CONFLICT(email) DO NOTHING",
                &vals![email, unix_now()],
            )
            .await?;
        self.backend
            .query_opt("SELECT id FROM users WHERE email = ?1", &vals![email])
            .await?
            .context("resolving user id after insert")?
            .get(0)
    }
}
