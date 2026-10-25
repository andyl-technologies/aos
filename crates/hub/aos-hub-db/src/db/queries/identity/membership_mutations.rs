//! Membership mutations in the identity capability.

use super::*;

impl Database {
    /// Revoke a principal's grant at a scope.
    ///
    /// A no-op when no such grant exists.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn revoke_membership(
        &self,
        principal_kind: &str,
        principal_id: i64,
        scope: &str,
    ) -> Result<()> {
        self.revoke_membership_owner_safe(principal_kind, principal_id, scope)
            .await
    }

    /// Revoke a principal's grant at a scope, refusing to orphan the org.
    ///
    /// Every owner-sensitive write first increments the same scope guard inside
    /// its transaction. Two concurrent revokes therefore cannot both act on an
    /// earlier count of two: the second guard write observes the remaining sole
    /// owner and is refused with [`LastOwnerError`].
    ///
    /// The guard fires only when at least one owner existed before the write
    /// (a scope that legitimately has no owners — e.g. a non-org scope — is
    /// never forced to acquire one). Otherwise this behaves like
    /// [`Database::revoke_membership`].
    ///
    /// # Errors
    ///
    /// Returns a [`LastOwnerError`] (classifiable via
    /// [`is_last_owner_error`]) when the revoke would leave the scope without
    /// an owner, or an error on database failure.
    pub async fn revoke_membership_owner_safe(
        &self,
        principal_kind: &str,
        principal_id: i64,
        scope: &str,
    ) -> Result<()> {
        // Every owner-sensitive mutation first writes the same scope row. That
        // shared write is the serialization point on SQLite/HubDb, PostgreSQL and
        // MySQL; transactions changing different membership rows therefore
        // cannot observe the same stale owner count (write skew).
        let result = self
            .backend
            .checked_batch(&[
                Statement::new(
                    "UPDATE authorization_scopes
                        SET owner_guard_version = owner_guard_version + 1
                      WHERE scope_key = ?3
                        AND (NOT EXISTS (
                              SELECT 1 FROM memberships target
                               WHERE target.principal_kind = ?1
                                 AND target.principal_id = ?2
                                 AND target.scope_key = ?3
                                 AND target.role = 'owner'
                                 AND target.principal_kind = 'user'
                                 AND EXISTS (SELECT 1 FROM users u
                                              WHERE u.id = target.principal_id
                                                AND u.deleted_at IS NULL))
                          OR (SELECT COUNT(*) FROM memberships owners
                               WHERE owners.scope_key = ?3
                                 AND owners.principal_kind = 'user'
                                 AND owners.role = 'owner'
                                 AND EXISTS (SELECT 1 FROM users u
                                              WHERE u.id = owners.principal_id
                                                AND u.deleted_at IS NULL)) > 1)",
                    vals![principal_kind, principal_id, scope],
                )
                .expecting(1),
                Statement::new(
                    "DELETE FROM memberships
                      WHERE principal_kind = ?1 AND principal_id = ?2 AND scope_key = ?3",
                    vals![principal_kind, principal_id, scope],
                )
                .unchecked(),
            ])
            .await;
        if result.is_err() {
            let (owners, target_is_owner) = self
                .owner_membership_state(principal_kind, principal_id, scope)
                .await?;
            if target_is_owner && owners <= 1 {
                return Err(anyhow::Error::new(LastOwnerError(scope.to_string())));
            }
            result?;
        }
        Ok(())
    }

    /// Set a principal's role at a scope, refusing to orphan the org.
    ///
    /// The owner-safe counterpart of [`Database::grant_membership`] for
    /// **role changes**. Demotion serializes through the scope's guard row before
    /// applying an upsert, closing both cross-row write skew and the absent-row
    /// check-then-act race.
    ///
    /// The scope must be canonical (same precondition as
    /// [`Database::grant_membership`]).
    ///
    /// # Errors
    ///
    /// Returns a [`LastOwnerError`] (classifiable via
    /// [`is_last_owner_error`]) when the change would leave the scope without
    /// an owner, or an error on database failure or a non-canonical scope.
    pub async fn set_membership_role_owner_safe(
        &self,
        principal_kind: &str,
        principal_id: i64,
        scope: &str,
        role: &str,
    ) -> Result<()> {
        if !aos_hub_model::domain::Scope::is_canonical(scope) {
            bail!("refusing to grant membership at non-canonical scope '{scope}'");
        }
        if aos_hub_model::domain::PrincipalKind::parse(principal_kind).is_none() {
            bail!("unknown membership principal kind '{principal_kind}'");
        }
        if aos_hub_model::domain::Role::parse(role).is_none() {
            bail!("unknown membership role '{role}'");
        }
        if !self.principal_is_live(principal_kind, principal_id).await? {
            bail!("membership principal does not identify a live principal");
        }
        if role == "owner" {
            return self
                .upsert_live_membership_role(principal_kind, principal_id, scope, role)
                .await;
        }
        let incarnation_id = uuid::Uuid::new_v4().simple().to_string();
        let result = self
            .backend
            .checked_batch(&[
                Statement::new(
                    "UPDATE authorization_scopes
                        SET owner_guard_version = owner_guard_version + 1
                      WHERE scope_key = ?3
                        AND (NOT EXISTS (
                              SELECT 1 FROM memberships target
                               WHERE target.principal_kind = ?1
                                 AND target.principal_id = ?2
                                 AND target.scope_key = ?3
                                 AND target.role = 'owner'
                                 AND target.principal_kind = 'user'
                                 AND EXISTS (SELECT 1 FROM users u
                                              WHERE u.id = target.principal_id
                                                AND u.deleted_at IS NULL))
                          OR (SELECT COUNT(*) FROM memberships owners
                               WHERE owners.scope_key = ?3
                                 AND owners.principal_kind = 'user'
                                 AND owners.role = 'owner'
                                 AND EXISTS (SELECT 1 FROM users u
                                              WHERE u.id = owners.principal_id
                                                AND u.deleted_at IS NULL)) > 1)",
                    vals![principal_kind, principal_id, scope],
                )
                .expecting(1),
                Statement::new(
                    "DELETE FROM memberships
                      WHERE principal_kind = ?1 AND principal_id = ?2 AND scope_key = ?3",
                    vals![principal_kind, principal_id, scope],
                )
                .unchecked(),
                Statement::new(
                    "INSERT INTO memberships
                     (principal_kind, principal_id, scope_key, role, created_at, incarnation_id)
                     SELECT ?1, ?2, a.scope_key, ?4, ?5, ?6 FROM authorization_scopes a
                     LEFT JOIN orgs o ON o.id = a.org_id
                     WHERE a.scope_key = ?3 AND a.retired_at IS NULL
                       AND (a.org_id IS NULL OR o.deleted_at IS NULL)
                       AND ((?1 = 'user' AND EXISTS (
                              SELECT 1 FROM users u
                               WHERE u.id = ?2 AND u.deleted_at IS NULL))
                         OR (?1 = 'service_account' AND EXISTS (
                              SELECT 1 FROM service_accounts s
                              JOIN orgs owner_org ON owner_org.id = s.org_id
                               WHERE s.id = ?2 AND owner_org.deleted_at IS NULL)))",
                    vals![
                        principal_kind,
                        principal_id,
                        scope,
                        role,
                        unix_now(),
                        incarnation_id
                    ],
                )
                .expecting(1),
            ])
            .await;
        if result.is_err() {
            let (owners, target_is_owner) = self
                .owner_membership_state(principal_kind, principal_id, scope)
                .await?;
            if target_is_owner && owners <= 1 {
                return Err(anyhow::Error::new(LastOwnerError(scope.to_string())));
            }
            result?;
        }
        Ok(())
    }

    /// Replaces a direct membership if its reviewed state and actor authority remain current.
    ///
    /// The target membership identity, the actor's effective role, and the
    /// surviving human-owner invariant are checked in the same transaction as
    /// the write. Existing memberships retain their row identity across role
    /// changes; a revoked and recreated membership therefore cannot satisfy an
    /// older review.
    ///
    /// # Errors
    ///
    /// Returns a [`MembershipMutationConflictError`] when the membership or
    /// actor authority changed, a [`LastOwnerError`] when the replacement would
    /// remove the final live human owner, or an error on invalid input or
    /// database failure.
    pub async fn replace_membership_if_current(
        &self,
        target: aos_hub_model::domain::Principal,
        scope: &str,
        expected: Option<&MembershipSnapshot>,
        desired_role: Option<&str>,
        actor: aos_hub_model::domain::Principal,
    ) -> Result<()> {
        use aos_hub_model::domain::Role;

        if !aos_hub_model::domain::Scope::is_canonical(scope) {
            bail!("refusing to replace membership at non-canonical scope '{scope}'");
        }
        let expected_role = expected
            .map(|snapshot| {
                Role::parse(&snapshot.role).with_context(|| {
                    format!("unknown expected membership role '{}'", snapshot.role)
                })
            })
            .transpose()?;
        let desired_role = desired_role
            .map(|role| {
                Role::parse(role).with_context(|| format!("unknown membership role '{role}'"))
            })
            .transpose()?;
        let required_rank = expected_role
            .into_iter()
            .chain(desired_role)
            .map(Role::rank)
            .chain(std::iter::once(Role::Admin.rank()))
            .max()
            .unwrap_or(Role::Admin.rank()) as i64;
        let expected_id = expected.map(|snapshot| snapshot.id);
        let expected_role_name = expected.map(|snapshot| snapshot.role.as_str());
        let target_kind = target.kind.as_str();
        let actor_kind = actor.kind.as_str();

        // PostgreSQL needs nullable baseline parameters typed at their first
        // use, even when a later comparison would establish the same type.
        let guard = Statement::new(
            "UPDATE authorization_scopes
                SET owner_guard_version = owner_guard_version + 1
              WHERE scope_key = ?3 AND retired_at IS NULL
                AND ((?1 = 'user' AND EXISTS (
                       SELECT 1 FROM users target_user
                        WHERE target_user.id = ?2 AND target_user.deleted_at IS NULL))
                  OR (?1 = 'service_account' AND EXISTS (
                       SELECT 1 FROM service_accounts target_account
                       JOIN orgs target_org ON target_org.id = target_account.org_id
                        WHERE target_account.id = ?2 AND target_org.deleted_at IS NULL)))
                AND ((CAST(?4 AS BIGINT) IS NULL AND NOT EXISTS (
                       SELECT 1 FROM memberships target
                        WHERE target.principal_kind = ?1
                          AND target.principal_id = ?2
                          AND target.scope_key = ?3))
                  OR EXISTS (
                       SELECT 1 FROM memberships target
                        WHERE target.id = ?4
                          AND target.principal_kind = ?1
                          AND target.principal_id = ?2
                          AND target.scope_key = ?3
                          AND target.role = ?5
                          AND ((CAST(?10 AS TEXT) IS NULL AND target.incarnation_id IS NULL)
                            OR target.incarnation_id = ?10)))
                AND EXISTS (
                     SELECT 1 FROM memberships actor_membership
                     JOIN authorization_scope_ancestors ancestry
                       ON ancestry.ancestor_scope_key = actor_membership.scope_key
                    WHERE ancestry.descendant_scope_key = ?3
                      AND actor_membership.principal_kind = ?6
                      AND actor_membership.principal_id = ?7
                      AND CASE actor_membership.role
                            WHEN 'owner' THEN 4 WHEN 'admin' THEN 3
                            WHEN 'maintainer' THEN 2 WHEN 'developer' THEN 1
                            ELSE 0 END >= ?8
                      AND ((?6 = 'user' AND EXISTS (
                             SELECT 1 FROM users actor_user
                              WHERE actor_user.id = ?7 AND actor_user.deleted_at IS NULL))
                        OR (?6 = 'service_account' AND EXISTS (
                             SELECT 1 FROM service_accounts actor_account
                             JOIN orgs actor_org ON actor_org.id = actor_account.org_id
                              WHERE actor_account.id = ?7 AND actor_org.deleted_at IS NULL))))
                AND (NOT EXISTS (
                       SELECT 1 FROM memberships target_owner
                        WHERE target_owner.principal_kind = ?1
                          AND target_owner.principal_id = ?2
                          AND target_owner.scope_key = ?3
                          AND target_owner.role = 'owner'
                          AND target_owner.principal_kind = 'user'
                          AND EXISTS (SELECT 1 FROM users target_owner_user
                                       WHERE target_owner_user.id = target_owner.principal_id
                                         AND target_owner_user.deleted_at IS NULL))
                  OR ?9 = 'owner'
                  OR (SELECT COUNT(*) FROM memberships owners
                       WHERE owners.scope_key = ?3
                         AND owners.principal_kind = 'user'
                         AND owners.role = 'owner'
                         AND EXISTS (SELECT 1 FROM users owner_user
                                      WHERE owner_user.id = owners.principal_id
                                        AND owner_user.deleted_at IS NULL)) > 1)",
            vals![
                target_kind,
                target.id,
                scope,
                expected_id,
                expected_role_name,
                actor_kind,
                actor.id,
                required_rank,
                desired_role.map(Role::as_str),
                expected.and_then(|snapshot| snapshot.incarnation_id.as_deref()),
            ],
        )
        .expecting(1);
        let mut statements = vec![guard];

        match (expected, desired_role) {
            (Some(snapshot), Some(role)) => statements.push(
                Statement::new(
                    "UPDATE memberships SET role = ?6
                      WHERE id = ?4 AND principal_kind = ?1 AND principal_id = ?2
                        AND scope_key = ?3 AND role = ?5
                        AND ((CAST(?7 AS TEXT) IS NULL AND incarnation_id IS NULL)
                          OR incarnation_id = ?7)",
                    vals![
                        target_kind,
                        target.id,
                        scope,
                        snapshot.id,
                        snapshot.role,
                        role.as_str(),
                        snapshot.incarnation_id.as_deref(),
                    ],
                )
                .expecting(1),
            ),
            (Some(snapshot), None) => statements.push(
                Statement::new(
                    "DELETE FROM memberships
                      WHERE id = ?4 AND principal_kind = ?1 AND principal_id = ?2
                        AND scope_key = ?3 AND role = ?5
                        AND ((CAST(?6 AS TEXT) IS NULL AND incarnation_id IS NULL)
                          OR incarnation_id = ?6)",
                    vals![
                        target_kind,
                        target.id,
                        scope,
                        snapshot.id,
                        snapshot.role,
                        snapshot.incarnation_id.as_deref(),
                    ],
                )
                .expecting(1),
            ),
            (None, Some(role)) => statements.push(
                Statement::new(
                    "INSERT INTO memberships
                     (principal_kind, principal_id, scope_key, role, created_at, incarnation_id)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    vals![
                        target_kind,
                        target.id,
                        scope,
                        role.as_str(),
                        unix_now(),
                        uuid::Uuid::new_v4().simple().to_string(),
                    ],
                )
                .expecting(1),
            ),
            (None, None) => {}
        }

        let result = self.backend.checked_batch(&statements).await;
        if let Err(error) = result {
            let current = self
                .membership_snapshot(target_kind, target.id, scope)
                .await?;
            if current.as_ref() != expected {
                return Err(anyhow::Error::new(MembershipMutationConflictError));
            }

            let (owners, target_is_owner) = self
                .owner_membership_state(target_kind, target.id, scope)
                .await?;
            if target_is_owner && desired_role != Some(Role::Owner) && owners <= 1 {
                return Err(anyhow::Error::new(LastOwnerError(scope.to_string())));
            }
            if !self
                .principal_has_membership_rank(actor, scope, required_rank)
                .await?
            {
                return Err(anyhow::Error::new(MembershipMutationConflictError));
            }

            return Err(error);
        }
        Ok(())
    }

    pub async fn user_has_any_membership(&self, user_id: i64) -> Result<bool> {
        let count: i64 = self
            .backend
            .query_opt(
                "SELECT COUNT(*) FROM memberships
                 WHERE principal_kind = 'user' AND principal_id = ?1",
                &vals![user_id],
            )
            .await?
            .context("membership count query returned no row")?
            .get(0)?;
        Ok(count > 0)
    }

    /// Reads one invitation by its organization-local numeric identity.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn invitation_record(
        &self,
        org_id: i64,
        invitation_id: i64,
    ) -> Result<Option<InvitationRecord>> {
        self.backend
            .query_opt(
                "SELECT id, org_id, email, scope_key, role, created_at,
                        accepted_at, cancelled_at, expires_at
                   FROM invitations WHERE org_id = ?1 AND id = ?2",
                &vals![org_id, invitation_id],
            )
            .await?
            .map(invitation_record_from_row)
            .transpose()
    }

    /// Loads the sealed recovery copy for one live pending invitation.
    ///
    /// Terminal transitions erase this value. Callers must unseal it through
    /// the runtime's retained [`aos_hub_model::auth::seal::SecretSealer`].
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn recoverable_invitation_sealed_secret(
        &self,
        invitation_id: i64,
    ) -> Result<Option<String>> {
        let now = unix_now();
        let row = self
            .backend
            .query_opt(
                "SELECT secret_enc FROM invitations
                  WHERE id = ?1 AND accepted_at IS NULL AND cancelled_at IS NULL
                    AND expires_at > ?2 AND secret_enc IS NOT NULL",
                &vals![invitation_id, now],
            )
            .await?;
        if let Some(row) = row {
            return row.get(0).map(Some);
        }
        self.backend
            .execute(
                "UPDATE invitations SET secret_enc = NULL
                  WHERE id = ?1 AND secret_enc IS NOT NULL
                    AND (accepted_at IS NOT NULL OR cancelled_at IS NOT NULL
                         OR expires_at <= ?2)",
                &vals![invitation_id, now],
            )
            .await?;
        Ok(None)
    }

    /// Erases recovery ciphertext and releases live keys for expired invitations.
    ///
    /// The bounded batch is safe to repeat and commits both effects atomically.
    /// `limit` is clamped to keep one maintenance pass from monopolizing the
    /// database.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn prune_expired_invitation_secrets(&self, now: i64, limit: i64) -> Result<()> {
        let limit = limit.clamp(1, 10_000);
        let expired_ids = "SELECT expired_id FROM (
                            SELECT id AS expired_id FROM invitations
                             WHERE accepted_at IS NULL AND cancelled_at IS NULL
                               AND expires_at <= ?1
                             ORDER BY expires_at, id LIMIT ?2
                          ) expired_invitations";
        self.backend
            .checked_batch(&[
                Statement::new(
                    format!("UPDATE invitations SET secret_enc = NULL WHERE id IN ({expired_ids})"),
                    vals![now, limit],
                )
                .unchecked(),
                Statement::new(
                    format!("DELETE FROM live_invitations WHERE invitation_id IN ({expired_ids})"),
                    vals![now, limit],
                )
                .unchecked(),
            ])
            .await
    }

    /// Create an invitation; returns its new id.
    ///
    /// The caller passes the SHA-256 hash of the invite secret as
    /// `token_hash` (the secret itself is never stored). `expires_at` is a
    /// Unix timestamp after which [`Database::accept_invitation`] refuses
    /// the invite.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, including a unique-constraint
    /// violation when `token_hash` collides.
    pub async fn create_invitation(
        &self,
        org_id: i64,
        email: &str,
        scope: &str,
        role: &str,
        token_hash: &str,
        expires_at: i64,
    ) -> Result<i64> {
        if !aos_hub_model::domain::Scope::is_canonical(scope) {
            bail!("invalid stable authorization scope");
        }
        if aos_hub_model::domain::Role::parse(role).is_none() {
            bail!("unknown invitation role '{role}'");
        }
        let invitation_id = portable_relational_id(uuid::Uuid::new_v4());
        let now = unix_now();
        self.backend
            .checked_batch(&[
                Statement::new(
                    "UPDATE invitations SET secret_enc = NULL
                       WHERE id IN (
                         SELECT invitation_id FROM live_invitations
                          WHERE org_id = ?1 AND email = ?2 AND scope_key = ?3)
                         AND expires_at <= ?4",
                    vals![org_id, email, scope, now],
                )
                .unchecked(),
                Statement::new(
                    "DELETE FROM live_invitations
                       WHERE org_id = ?1 AND email = ?2 AND scope_key = ?3
                         AND invitation_id IN (
                           SELECT id FROM invitations WHERE expires_at <= ?4)",
                    vals![org_id, email, scope, now],
                )
                .unchecked(),
                Statement::new(
                    "INSERT INTO invitations
                     (id, org_id, email, scope_key, role, token_hash, created_at, expires_at)
                     SELECT ?1, ?2, ?3, a.scope_key, ?5, ?6, ?7, ?8
                       FROM authorization_scopes a JOIN orgs o ON o.id = a.org_id
                      WHERE a.scope_key = ?4 AND a.org_id = ?2 AND o.deleted_at IS NULL",
                    vals![
                        invitation_id,
                        org_id,
                        email,
                        scope,
                        role,
                        token_hash,
                        now,
                        expires_at
                    ],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO live_invitations(org_id, email, scope_key, invitation_id)
                     VALUES (?1, ?2, ?3, ?4)",
                    vals![org_id, email, scope, invitation_id],
                )
                .expecting(1),
            ])
            .await?;
        Ok(invitation_id)
    }

    /// Creates an invitation, audits it, and completes its reviewed plan atomically.
    ///
    /// # Errors
    ///
    /// Returns an error when validation, serialization, authorization-scope
    /// lookup, live-key uniqueness, plan fencing, or persistence fails.
    #[allow(clippy::too_many_arguments)]
    pub async fn apply_invitation_creation_plan(
        &self,
        record: &InvitationRecord,
        token_hash: &str,
        sealed_secret: &str,
        plan_id: &str,
        apply_idempotency_key: &str,
        result_json: &str,
        actor_kind: &str,
        actor_id: Option<i64>,
        actor_label: &str,
        audit_event_id: &str,
    ) -> Result<()> {
        validate_key_bytes(apply_idempotency_key, "apply idempotency key", 128)?;
        validate_key_bytes(audit_event_id, "audit event id", 64)?;
        validate_json_value(result_json, "apply result")?;
        let now = unix_now();
        let detail = format!("invitation_id={}", record.id);
        self.backend
            .checked_batch(&[
                Statement::new(
                    "UPDATE invitations SET secret_enc = NULL
                       WHERE id IN (
                         SELECT invitation_id FROM live_invitations
                          WHERE org_id = ?1 AND email = ?2 AND scope_key = ?3)
                         AND expires_at <= ?4",
                    vals![record.org_id, record.email, record.scope, now],
                )
                .unchecked(),
                Statement::new(
                    "DELETE FROM live_invitations
                       WHERE org_id = ?1 AND email = ?2 AND scope_key = ?3
                         AND invitation_id IN (
                           SELECT id FROM invitations WHERE expires_at <= ?4)",
                    vals![record.org_id, record.email, record.scope, now],
                )
                .unchecked(),
                Statement::new(
                    "INSERT INTO invitations
                     (id, org_id, email, scope_key, role, token_hash, created_at,
                      expires_at, secret_enc)
                     SELECT ?1, ?2, ?3, a.scope_key, ?5, ?6, ?7, ?8, ?9
                       FROM authorization_scopes a JOIN orgs o ON o.id = a.org_id
                      WHERE a.scope_key = ?4 AND a.org_id = ?2 AND o.deleted_at IS NULL",
                    vals![
                        record.id,
                        record.org_id,
                        record.email,
                        record.scope,
                        record.role,
                        token_hash,
                        record.created_at,
                        record.expires_at,
                        sealed_secret
                    ],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO live_invitations(org_id, email, scope_key, invitation_id)
                     VALUES (?1, ?2, ?3, ?4)",
                    vals![record.org_id, record.email, record.scope, record.id],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO audit_log
                     (outbox_event_id, change_id, actor_kind, actor_id, actor_label,
                      action, scope, detail, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, 'invitation.create', ?6, ?7, ?8)",
                    vals![
                        audit_event_id,
                        plan_id,
                        actor_kind,
                        actor_id,
                        sanitize_log_text(actor_label),
                        sanitize_log_text(&record.scope),
                        detail,
                        now
                    ],
                )
                .expecting(1),
                Statement::new(
                    "UPDATE topology_plans SET applied_at = ?4, apply_result_json = ?3
                       WHERE plan_id = ?1 AND apply_idempotency_key = ?2
                         AND applied_at IS NULL",
                    vals![plan_id, apply_idempotency_key, result_json, now],
                )
                .expecting(1),
            ])
            .await
    }

    /// Cancels a live invitation using an optimistic-concurrency baseline.
    ///
    /// Returns `false` when the invitation is absent, terminal, expired, or
    /// changed since it was reviewed.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn cancel_invitation(
        &self,
        invitation_id: i64,
        expected_created_at: i64,
    ) -> Result<bool> {
        let now = unix_now();
        let result = self
            .backend
            .checked_batch(&[
                Statement::new(
                    "UPDATE invitations SET cancelled_at = ?3, secret_enc = NULL
                      WHERE id = ?1 AND created_at = ?2
                        AND accepted_at IS NULL AND cancelled_at IS NULL
                        AND expires_at > ?3",
                    vals![invitation_id, expected_created_at, now],
                )
                .expecting(1),
                Statement::new(
                    "DELETE FROM live_invitations WHERE invitation_id = ?1",
                    vals![invitation_id],
                )
                .expecting(1),
            ])
            .await;
        match result {
            Ok(()) => Ok(true),
            Err(error) => {
                let still_matches = self
                    .backend
                    .query_opt(
                        "SELECT id FROM invitations
                           WHERE id = ?1 AND created_at = ?2
                             AND accepted_at IS NULL AND cancelled_at IS NULL
                             AND expires_at > ?3",
                        &vals![invitation_id, expected_created_at, now],
                    )
                    .await?
                    .is_some();
                if still_matches {
                    Err(error)
                } else {
                    Ok(false)
                }
            }
        }
    }

    /// Cancels an invitation, audits it, and completes its reviewed plan atomically.
    ///
    /// # Errors
    ///
    /// Returns an error when the invitation CAS, live-key release, audit
    /// append, plan fence, validation, or persistence fails.
    #[allow(clippy::too_many_arguments)]
    pub async fn apply_invitation_cancellation_plan(
        &self,
        invitation_id: i64,
        expected_created_at: i64,
        cancelled_at: i64,
        scope: &str,
        plan_id: &str,
        apply_idempotency_key: &str,
        result_json: &str,
        actor_kind: &str,
        actor_id: Option<i64>,
        actor_label: &str,
        audit_event_id: &str,
    ) -> Result<()> {
        validate_key_bytes(apply_idempotency_key, "apply idempotency key", 128)?;
        validate_key_bytes(audit_event_id, "audit event id", 64)?;
        validate_json_value(result_json, "apply result")?;
        let detail = format!("invitation_id={invitation_id}");
        self.backend
            .checked_batch(&[
                Statement::new(
                    "UPDATE invitations SET cancelled_at = ?3, secret_enc = NULL
                      WHERE id = ?1 AND created_at = ?2
                        AND accepted_at IS NULL AND cancelled_at IS NULL
                        AND expires_at > ?3",
                    vals![invitation_id, expected_created_at, cancelled_at],
                )
                .expecting(1),
                Statement::new(
                    "DELETE FROM live_invitations WHERE invitation_id = ?1",
                    vals![invitation_id],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO audit_log
                     (outbox_event_id, change_id, actor_kind, actor_id, actor_label,
                      action, scope, detail, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, 'invitation.cancel', ?6, ?7, ?8)",
                    vals![
                        audit_event_id,
                        plan_id,
                        actor_kind,
                        actor_id,
                        sanitize_log_text(actor_label),
                        sanitize_log_text(scope),
                        detail,
                        cancelled_at
                    ],
                )
                .expecting(1),
                Statement::new(
                    "UPDATE topology_plans SET applied_at = ?4, apply_result_json = ?3
                       WHERE plan_id = ?1 AND apply_idempotency_key = ?2
                         AND applied_at IS NULL",
                    vals![plan_id, apply_idempotency_key, result_json, cancelled_at],
                )
                .expecting(1),
            ])
            .await
    }

    /// Accepts an invitation and creates its membership in one transaction.
    ///
    /// Succeeds only for an invitation that is unexpired (`expires_at` is
    /// in the future relative to the current clock) and not already
    /// accepted; on success it stamps `accepted_at` and returns the
    /// invitation and inserts the corresponding membership atomically.
    /// Returns `Ok(None)` when no matching, live, unaccepted invitation
    /// exists — covering unknown hashes, expired invites, and replays
    /// alike, without distinguishing them to the caller.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn accept_invitation(
        &self,
        token_hash: &str,
        org_id: i64,
        user_id: i64,
        email: &str,
    ) -> Result<Option<InvitationRecord>> {
        self.accept_invitation_inner(token_hash, org_id, user_id, email, None)
            .await
    }

    /// Accepts an invitation and appends its IAM audit event atomically.
    ///
    /// # Errors
    ///
    /// Returns an error on invalid audit identity or database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn accept_invitation_audited(
        &self,
        token_hash: &str,
        org_id: i64,
        user_id: i64,
        email: &str,
        actor_kind: &str,
        actor_id: Option<i64>,
        actor_label: &str,
        audit_event_id: &str,
    ) -> Result<Option<InvitationRecord>> {
        validate_key_bytes(audit_event_id, "audit event id", 64)?;
        self.accept_invitation_inner(
            token_hash,
            org_id,
            user_id,
            email,
            Some((actor_kind, actor_id, actor_label, audit_event_id)),
        )
        .await
    }
}
