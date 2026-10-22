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

    /// Finds the verified owner of a mailbox, creating one if absent.
    ///
    /// The human-login path calls this only after proving control of `email`.
    /// A legacy provider-created user that still carries the address as profile
    /// metadata is moved to an internal address before the mailbox owner is
    /// created. Concurrent claims resolve to the first committed owner.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn find_or_create_user(&self, email: &str) -> Result<i64> {
        if let Some(id) = self.user_by_email(email).await? {
            return Ok(id);
        }

        let user_id = portable_relational_id(uuid::Uuid::new_v4());
        let now = unix_now();
        let mut statements = Vec::new();
        if let Some(provisional_user_id) = self.user_by_profile_email(email).await? {
            let replacement =
                format!("oidc-legacy-{provisional_user_id}-{user_id}@identity.invalid");
            statements.push(
                Statement::new(
                    "UPDATE users SET email = ?2
                     WHERE id = ?1 AND email = ?3 AND deleted_at IS NULL
                       AND NOT EXISTS (
                             SELECT 1 FROM user_mailboxes mailbox
                              WHERE mailbox.user_id = ?1
                           )",
                    vals![provisional_user_id, replacement, email],
                )
                .expecting(1),
            );
        }
        statements.extend([
            Statement::new(
                "INSERT INTO users (id, email, display_name, created_at)
                 VALUES (?1, ?2, NULL, ?3)",
                vals![user_id, email, now],
            )
            .expecting(1),
            Statement::new(
                "INSERT INTO user_mailboxes (email, user_id, verified_at)
                 VALUES (?1, ?2, ?3)",
                vals![email, user_id, now],
            )
            .expecting(1),
        ]);

        if let Err(error) = self.backend.checked_batch(&statements).await {
            if let Some(existing) = self.user_by_email(email).await? {
                return Ok(existing);
            }
            return Err(error).context("claiming verified mailbox");
        }

        Ok(user_id)
    }
}
