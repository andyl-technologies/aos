//! Membership reads in the identity capability.

use super::*;

impl Database {
    /// Whether a live (unexpired, unaccepted) invitation exists for `email`.
    ///
    /// Used by the `invite_only` signup gate. A user invited to any org may
    /// create their own org (RFC-0004 "open membership-by-invitation").
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn has_pending_invitation(&self, email: &str) -> Result<bool> {
        let now = unix_now();
        let count: i64 = self
            .backend
            .query_opt(
                "SELECT COUNT(*) FROM invitations
                 WHERE email = ?1 AND accepted_at IS NULL
                   AND cancelled_at IS NULL AND expires_at > ?2",
                &vals![email, now],
            )
            .await?
            .context("invitation count query returned no row")?
            .get(0)?;
        Ok(count > 0)
    }

    // -- tenancy: invitations ------------------------------------------------

    /// Lists every invitation owned by an organization, newest first.
    ///
    /// Terminal invitations remain visible for audit. Expiry is derived from
    /// the stored deadline rather than materialized by a background job.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn list_invitations(&self, org_id: i64) -> Result<Vec<InvitationRecord>> {
        self.backend
            .query(
                "SELECT id, org_id, email, scope_key, role, created_at,
                        accepted_at, cancelled_at, expires_at
                   FROM invitations WHERE org_id = ?1
                  ORDER BY created_at DESC, id DESC",
                &vals![org_id],
            )
            .await?
            .into_iter()
            .map(invitation_record_from_row)
            .collect()
    }

    /// Finds a live invitation for the same email and membership scope.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn pending_invitation_for(
        &self,
        org_id: i64,
        email: &str,
        scope: &str,
    ) -> Result<Option<i64>> {
        let now = unix_now();
        self.backend
            .query_opt(
                "SELECT id FROM invitations
                  WHERE org_id = ?1 AND email = ?2 AND scope_key = ?3
                    AND accepted_at IS NULL AND cancelled_at IS NULL
                    AND expires_at > ?4
                  ORDER BY created_at DESC, id DESC LIMIT 1",
                &vals![org_id, email, scope, now],
            )
            .await?
            .map(|row| row.get(0))
            .transpose()
    }
}
