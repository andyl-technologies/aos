//! Membership helpers in the identity capability.

use super::*;

impl Database {
    /// Writes one already-validated membership role at a live scope.
    pub(in crate::db) async fn upsert_live_membership_role(
        &self,
        principal_kind: &str,
        principal_id: i64,
        scope: &str,
        role: &str,
    ) -> Result<()> {
        let affected = self
            .backend
            .execute(
                "INSERT INTO memberships
                 (principal_kind, principal_id, scope_key, role, created_at)
                 SELECT ?1, ?2, a.scope_key, ?4, ?5 FROM authorization_scopes a
                 LEFT JOIN orgs o ON o.id = a.org_id
                 WHERE a.scope_key = ?3 AND a.retired_at IS NULL
                   AND (a.org_id IS NULL OR o.deleted_at IS NULL)
                   AND ((?1 = 'user' AND EXISTS (
                          SELECT 1 FROM users u WHERE u.id = ?2 AND u.deleted_at IS NULL))
                     OR (?1 = 'service_account' AND EXISTS (
                          SELECT 1 FROM service_accounts s
                          JOIN orgs owner_org ON owner_org.id = s.org_id
                           WHERE s.id = ?2 AND owner_org.deleted_at IS NULL)))
                 ON CONFLICT(principal_kind, principal_id, scope_key)
                 DO UPDATE SET role = excluded.role",
                &vals![principal_kind, principal_id, scope, role, unix_now()],
            )
            .await?;
        if affected != 1 {
            bail!("authorization scope does not identify a live scope");
        }
        Ok(())
    }

    /// Owner-safety state for a principal at `scope`: `(live_human_owner_count,
    /// target_is_live_human_owner)`.
    ///
    /// Only non-deleted users satisfy the human-owner invariant. Service
    /// accounts may carry an owner role for automation, but can never keep an
    /// organization alive after its final human owner is removed.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub(in crate::db) async fn owner_membership_state(
        &self,
        principal_kind: &str,
        principal_id: i64,
        scope: &str,
    ) -> Result<(i64, bool)> {
        let row = self
            .backend
            .query_opt(
                "SELECT
                   (SELECT COUNT(*) FROM memberships membership
                      WHERE membership.scope_key = ?1
                        AND membership.principal_kind = 'user'
                        AND membership.role = 'owner'
                        AND EXISTS (SELECT 1 FROM users u
                                     WHERE u.id = membership.principal_id
                                       AND u.deleted_at IS NULL)),
                   EXISTS(SELECT 1 FROM memberships membership
                      WHERE membership.scope_key = ?1
                        AND membership.principal_kind = ?2
                        AND membership.principal_id = ?3
                        AND membership.role = 'owner'
                        AND membership.principal_kind = 'user'
                        AND EXISTS (SELECT 1 FROM users u
                                     WHERE u.id = membership.principal_id
                                       AND u.deleted_at IS NULL))",
                &vals![scope, principal_kind, principal_id],
            )
            .await?
            .context("owner-state query returned no row")?;
        let owners: i64 = row.get(0)?;
        let target_owner: i64 = row.get(1)?;
        Ok((owners, principal_kind == "user" && target_owner == 1))
    }

    pub(in crate::db) async fn accept_invitation_inner(
        &self,
        token_hash: &str,
        org_id: i64,
        user_id: i64,
        email: &str,
        audit: Option<(&str, Option<i64>, &str, &str)>,
    ) -> Result<Option<InvitationRecord>> {
        let now = unix_now();
        let record = self
            .backend
            .query_opt(
                "SELECT i.id, i.org_id, i.email, i.scope_key, i.role,
                        i.created_at, i.accepted_at, i.cancelled_at, i.expires_at
                   FROM invitations i JOIN orgs o ON o.id = i.org_id
                  WHERE i.token_hash = ?1 AND i.email = ?2 AND i.org_id = ?5
                    AND i.accepted_at IS NULL AND i.cancelled_at IS NULL
                    AND i.expires_at > ?3 AND o.deleted_at IS NULL
                    AND EXISTS (SELECT 1 FROM users u
                                 WHERE u.id = ?4 AND u.email = ?2
                                   AND u.deleted_at IS NULL)",
                &vals![token_hash, email, now, user_id, org_id],
            )
            .await
            .context("loading invitation by hash")?
            .map(invitation_record_from_row)
            .transpose()?;
        if let Some(record) = &record {
            let mut statements = vec![
                Statement::new(
                    "UPDATE invitations SET accepted_at = ?5, secret_enc = NULL
                          WHERE id = ?1 AND token_hash = ?2 AND email = ?3
                            AND accepted_at IS NULL AND cancelled_at IS NULL
                            AND expires_at > ?5 AND org_id = ?6
                            AND EXISTS (SELECT 1 FROM users u
                                         WHERE u.id = ?4 AND u.email = ?3
                                           AND u.deleted_at IS NULL)",
                    vals![record.id, token_hash, email, user_id, now, org_id],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO memberships
                           (principal_kind, principal_id, scope_key, role, created_at)
                         SELECT 'user', ?1, i.scope_key, i.role, ?3
                           FROM invitations i
                          WHERE i.id = ?2 AND i.accepted_at = ?3
                            AND NOT EXISTS (
                              SELECT 1 FROM memberships m
                               WHERE m.principal_kind = 'user'
                                 AND m.principal_id = ?1
                                 AND m.scope_key = i.scope_key)",
                    vals![user_id, record.id, now],
                )
                .expecting(1),
                Statement::new(
                    "DELETE FROM live_invitations WHERE invitation_id = ?1",
                    vals![record.id],
                )
                .expecting(1),
            ];
            if let Some((actor_kind, actor_id, actor_label, event_id)) = audit {
                statements.push(
                    Statement::new(
                        "INSERT INTO audit_log
                         (outbox_event_id, actor_kind, actor_id, actor_label,
                          action, scope, detail, created_at)
                         VALUES (?1, ?2, ?3, ?4, 'invitation.accept', ?5, ?6, ?7)",
                        vals![
                            event_id,
                            actor_kind,
                            actor_id,
                            sanitize_log_text(actor_label),
                            sanitize_log_text(&record.scope),
                            format!("invitation_id={}", record.id),
                            now
                        ],
                    )
                    .expecting(1),
                );
            }
            self.backend.checked_batch(&statements).await?;
            let mut accepted = record.clone();
            accepted.accepted_at = Some(now);
            return Ok(Some(accepted));
        }
        Ok(None)
    }
}
