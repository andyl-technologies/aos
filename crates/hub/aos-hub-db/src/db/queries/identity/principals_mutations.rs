//! Principals mutations in the identity capability.

use super::*;

impl Database {
    /// Looks up the live user who has verified control of an email address.
    ///
    /// Soft-deleted users (those with `deleted_at` set) are not returned.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn user_by_email(&self, email: &str) -> Result<Option<i64>> {
        self.backend
            .query_opt(
                "SELECT u.id FROM user_mailboxes mailbox
                 JOIN users u ON u.id = mailbox.user_id
                 WHERE mailbox.email = ?1 AND u.deleted_at IS NULL",
                &vals![email],
            )
            .await
            .context("loading user by email")?
            .map(|row| row.get(0))
            .transpose()
    }

    /// Look up a non-deleted user's email by id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn user_email(&self, user_id: i64) -> Result<Option<String>> {
        self.backend
            .query_opt(
                "SELECT email FROM users WHERE id = ?1 AND deleted_at IS NULL",
                &vals![user_id],
            )
            .await
            .context("loading user email by id")?
            .map(|row| row.get(0))
            .transpose()
    }

    /// Reports whether a supported principal still exists in a live owner scope.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn principal_is_live(&self, principal_kind: &str, principal_id: i64) -> Result<bool> {
        let sql = match principal_kind {
            "user" => "SELECT 1 FROM users WHERE id = ?1 AND deleted_at IS NULL",
            "service_account" => {
                "SELECT 1 FROM service_accounts s JOIN orgs o ON o.id = s.org_id
                  WHERE s.id = ?1 AND o.deleted_at IS NULL"
            }
            _ => return Ok(false),
        };
        Ok(self
            .backend
            .query_opt(sql, &vals![principal_id])
            .await?
            .is_some())
    }

    /// Applies an exact-version IdP replacement, audit append, and plan completion atomically.
    ///
    /// # Errors
    ///
    /// Returns an error when validation, optimistic concurrency, plan fencing,
    /// audit persistence, or database execution fails.
    #[allow(clippy::too_many_arguments)]
    pub async fn apply_identity_provider_set_plan(
        &self,
        config: &IdpConfigRecord,
        baseline_resource_version: Option<i64>,
        baseline_incarnation_id: Option<&str>,
        scope: &str,
        plan_id: &str,
        apply_idempotency_key: &str,
        result_json: &str,
        actor_kind: &str,
        actor_id: Option<i64>,
        actor_label: &str,
        audit_event_id: &str,
    ) -> Result<()> {
        aos_hub_model::identity::validate_idp_config_record(config)?;
        let incarnation_id = config
            .incarnation_id
            .as_deref()
            .context("reviewed identity-provider mutation has no incarnation")?;
        validate_key_bytes(apply_idempotency_key, "apply idempotency key", 128)?;
        validate_key_bytes(audit_event_id, "audit event id", 64)?;
        validate_json_value(result_json, "apply result")?;
        let now = unix_now();
        let mutation = match baseline_resource_version {
            Some(version) => Statement::new(
                "UPDATE org_idp_configs SET
                    issuer = ?2, authorization_endpoint = ?3, token_endpoint = ?4,
                    jwks_uri = ?5, client_id = ?6, client_secret_enc = ?7,
                    scopes = ?8, groups_claim = ?9, role_map_json = ?10,
                    allow_jit = ?11, enforce_sso = ?12, default_role = ?13,
                    resource_version = resource_version + 1,
                    incarnation_id = ?14, mutation_plan_id = ?15, updated_at = ?16
                  WHERE org_id = ?1 AND resource_version = ?17
                    AND (incarnation_id = ?18
                         OR (incarnation_id IS NULL AND ?18 IS NULL))",
                vals![
                    config.org_id,
                    config.issuer,
                    config.authorization_endpoint,
                    config.token_endpoint,
                    config.jwks_uri,
                    config.client_id,
                    config.client_secret_enc,
                    config.scopes,
                    config.groups_claim,
                    config.role_map_json,
                    config.allow_jit,
                    config.enforce_sso,
                    config.default_role,
                    incarnation_id,
                    plan_id,
                    now,
                    version,
                    baseline_incarnation_id
                ],
            )
            .expecting(1),
            None => Statement::new(
                "INSERT INTO org_idp_configs
                 (org_id, issuer, authorization_endpoint, token_endpoint, jwks_uri,
                  client_id, client_secret_enc, scopes, groups_claim, role_map_json,
                  allow_jit, enforce_sso, default_role, created_at, updated_at,
                  resource_version, incarnation_id, mutation_plan_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                         ?13, ?14, ?14, 1, ?15, ?16)",
                vals![
                    config.org_id,
                    config.issuer,
                    config.authorization_endpoint,
                    config.token_endpoint,
                    config.jwks_uri,
                    config.client_id,
                    config.client_secret_enc,
                    config.scopes,
                    config.groups_claim,
                    config.role_map_json,
                    config.allow_jit,
                    config.enforce_sso,
                    config.default_role,
                    now,
                    incarnation_id,
                    plan_id
                ],
            )
            .expecting(1),
        };
        self.backend
            .checked_batch(&[
                mutation,
                Statement::new(
                    "INSERT INTO audit_log
                     (outbox_event_id, change_id, actor_kind, actor_id, actor_label,
                      action, scope, detail, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, 'idp.set', ?6, NULL, ?7)",
                    vals![
                        audit_event_id,
                        plan_id,
                        actor_kind,
                        actor_id,
                        sanitize_log_text(actor_label),
                        sanitize_log_text(scope),
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

    /// Removes an exact IdP revision and completes its reviewed plan atomically.
    ///
    /// # Errors
    ///
    /// Returns an error when the revision changed or persistence fails.
    #[allow(clippy::too_many_arguments)]
    pub async fn apply_identity_provider_remove_plan(
        &self,
        org_id: i64,
        expected_resource_version: i64,
        expected_incarnation_id: Option<&str>,
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
        let now = unix_now();
        self.backend
            .checked_batch(&[
                Statement::new(
                    "DELETE FROM org_idp_configs
                      WHERE org_id = ?1 AND resource_version = ?2
                        AND (incarnation_id = ?3
                             OR (incarnation_id IS NULL AND ?3 IS NULL))",
                    vals![org_id, expected_resource_version, expected_incarnation_id],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO audit_log
                 (outbox_event_id, change_id, actor_kind, actor_id, actor_label,
                  action, scope, detail, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'idp.remove', ?6, NULL, ?7)",
                    vals![
                        audit_event_id,
                        plan_id,
                        actor_kind,
                        actor_id,
                        sanitize_log_text(actor_label),
                        sanitize_log_text(scope),
                        now
                    ],
                )
                .expecting(1),
                Statement::new(
                    "UPDATE topology_plans SET applied_at = ?4, apply_result_json = ?3
                   WHERE plan_id = ?1 AND apply_idempotency_key = ?2 AND applied_at IS NULL",
                    vals![plan_id, apply_idempotency_key, result_json, now],
                )
                .expecting(1),
            ])
            .await
    }

    /// Reconciles a verifier-bound OIDC identity to a hub user.
    ///
    /// Identities are keyed on `(verifier_id, subject)` — never bare email — so an
    /// IdP that recycles an email address can never silently take over another
    /// user's account. Resolution, in order:
    ///
    /// 1. An existing `(verifier_id, subject)` identity resolves to its user
    ///    ([`IdentityLink::Existing`]); its `email`/`last_login` are refreshed.
    /// 2. Otherwise, when `email` is IdP-*verified* and its domain is captured
    ///    by `org_id`, the identity links to the existing user with that email
    ///    ([`IdentityLink::Linked`]).
    /// 3. Otherwise, when `allow_jit`, a fresh user and identity are created
    ///    ([`IdentityLink::Created`]). A verified address under a captured
    ///    domain becomes that user's mailbox. Every other address remains
    ///    provider profile metadata and the user receives an internal address.
    ///
    /// Returns `Ok(None)` when no identity exists, no auto-link applies, and
    /// `allow_jit` is false — the caller rejects the login.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn link_or_create_identity(
        &self,
        verifier_id: &str,
        issuer: &str,
        subject: &str,
        email: Option<&str>,
        email_verified: bool,
        org_id: i64,
        allow_jit: bool,
    ) -> Result<Option<IdentityLink>> {
        let now = unix_now();
        // 1. Existing verifier-bound identity.
        if let Some(user_id) = self.identity_user(verifier_id, subject).await? {
            self.backend
                .execute(
                    "UPDATE oidc_identities SET email = ?3, last_login = ?4
                     WHERE verifier_id = ?1 AND subject = ?2",
                    &vals![verifier_id, subject, email, now],
                )
                .await?;
            return Ok(Some(IdentityLink::Existing(user_id)));
        }

        // Earlier releases keyed identities only by issuer. Adopt one of those
        // rows only when every current configuration for that issuer resolves
        // to this verifier, so an ambiguous legacy row never crosses verifier
        // namespaces.
        if self.issuer_has_single_verifier(issuer, verifier_id).await? {
            if let Some(user_id) = self.legacy_identity_user(issuer, subject).await? {
                self.insert_oidc_identity(verifier_id, issuer, subject, user_id, email, now)
                    .await?;
                return Ok(Some(IdentityLink::Existing(user_id)));
            }
        }
        // 2. Auto-link a verified email on a captured domain to an existing user.
        let captured_email = if email_verified {
            match email {
                Some(address) => {
                    let domain = address
                        .rsplit_once('@')
                        .map(|(_, value)| value.to_lowercase());
                    match domain {
                        Some(domain) if self.org_for_domain(&domain).await? == Some(org_id) => {
                            Some(address)
                        }
                        _ => None,
                    }
                }
                None => None,
            }
        } else {
            None
        };
        if let Some(address) = captured_email {
            if let Some(user_id) = self.user_by_email(address).await? {
                self.insert_oidc_identity(verifier_id, issuer, subject, user_id, email, now)
                    .await?;
                return Ok(Some(IdentityLink::Linked(user_id)));
            }
        }
        // 3. JIT-provision a brand-new user + identity.
        if !allow_jit {
            return Ok(None);
        }
        // A captured provider may establish a new mailbox owner. Other claims
        // remain profile metadata and receive an internal, non-routable user
        // address so later mailbox proof creates an independent account.
        let user_id = if let Some(address) = captured_email {
            self.create_user(address, None).await?
        } else {
            self.create_provisional_oidc_user(verifier_id, subject)
                .await?
        };
        self.insert_oidc_identity(verifier_id, issuer, subject, user_id, email, now)
            .await?;
        Ok(Some(IdentityLink::Created(user_id)))
    }

    /// Returns the user linked to a verifier and OIDC subject, if any.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn identity_user(&self, verifier_id: &str, subject: &str) -> Result<Option<i64>> {
        self.backend
            .query_opt(
                "SELECT user_id FROM oidc_identities
                 WHERE verifier_id = ?1 AND subject = ?2",
                &vals![verifier_id, subject],
            )
            .await
            .context("loading identity user")?
            .map(|row| row.get(0))
            .transpose()
    }

    async fn legacy_identity_user(&self, issuer: &str, subject: &str) -> Result<Option<i64>> {
        self.backend
            .query_opt(
                "SELECT user_id FROM user_identities WHERE issuer = ?1 AND subject = ?2",
                &vals![issuer, subject],
            )
            .await
            .context("loading legacy identity user")?
            .map(|row| row.get(0))
            .transpose()
    }

    // -- tenancy: principals -------------------------------------------------

    /// Create a user; returns the new user id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, including a unique-constraint
    /// violation when `email` is already registered.
    pub async fn create_user(&self, email: &str, display_name: Option<&str>) -> Result<i64> {
        let user_id = portable_relational_id(uuid::Uuid::new_v4());
        let now = unix_now();
        self.backend
            .checked_batch(&[
                Statement::new(
                    "INSERT INTO users (id, email, display_name, created_at)
                     VALUES (?1, ?2, ?3, ?4)",
                    vals![user_id, email, display_name, now],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO user_mailboxes (email, user_id, verified_at)
                     VALUES (?1, ?2, ?3)",
                    vals![email, user_id, now],
                )
                .expecting(1),
            ])
            .await?;
        Ok(user_id)
    }

    /// Soft-delete a user, failing if they are the sole owner of any org.
    ///
    /// Offboarding rule: a user may not be deleted while they are the only
    /// `Owner` of an org — the ownership must be transferred first
    /// ([`Database::transfer_org_ownership`]). On the blocking path this
    /// returns an `Err` whose message lists the offending org slugs and makes
    /// no change. On success it stamps `users.deleted_at`, revokes every
    /// session the user holds, and hard-revokes every token they own (their
    /// credentials deaden immediately), all in one transaction. Returns
    /// `Ok(false)` when the user is unknown or already deleted.
    ///
    /// # Errors
    ///
    /// Returns an error (listing the orgs) when the user is the sole owner of
    /// any org, or on database failure.
    pub async fn delete_user(&self, user_id: i64) -> Result<bool> {
        let now = unix_now();
        if !self.principal_is_live("user", user_id).await? {
            return Ok(false);
        }
        let owned_scopes = self
            .backend
            .query(
                "SELECT o.stable_id FROM orgs o JOIN memberships membership
                   ON membership.scope_key = o.stable_id
                  AND membership.principal_kind = 'user'
                  AND membership.principal_id = ?1 AND membership.role = 'owner'
                 WHERE o.deleted_at IS NULL",
                &vals![user_id],
            )
            .await?
            .iter()
            .map(|row| row.get::<String>(0))
            .collect::<Result<Vec<_>>>()?;
        // Derive the orgs the user solely owns in one query (an owner grant at a
        // non-deleted org with no *other* live owner) and refuse the delete when
        // any remain. The race a concurrent demote could open — dropping an
        // org's other owner between this read and the delete — is closed not by
        // an interactive transaction but by repeating the same NOT EXISTS guard
        // in the soft-delete's WHERE, so the user can never be deleted while
        // sole owner of any org.
        let blocking: Vec<String> = self
            .backend
            .query(
                "SELECT o.slug FROM orgs o
                 JOIN memberships m
                   ON m.scope_key = o.stable_id AND m.principal_kind = 'user'
                  AND m.principal_id = ?1 AND m.role = 'owner'
                 WHERE o.deleted_at IS NULL
                   AND NOT EXISTS (
                     SELECT 1 FROM memberships m2
                     WHERE m2.scope_key = o.stable_id
                       AND m2.principal_kind = 'user' AND m2.role = 'owner'
                       AND m2.principal_id <> ?1
                       AND EXISTS (SELECT 1 FROM users u
                                    WHERE u.id = m2.principal_id
                                      AND u.deleted_at IS NULL))",
                &vals![user_id],
            )
            .await?
            .iter()
            .map(|row| row.get(0))
            .collect::<Result<_>>()?;
        if !blocking.is_empty() {
            bail!(
                "user {user_id} is the sole owner of: {} — transfer ownership before deleting",
                blocking.join(", ")
            );
        }
        // Guarded soft-delete: applies only if the user still owns no org solely
        // (re-evaluated atomically here), and only if not already deleted.
        let mut statements = Vec::with_capacity(owned_scopes.len() + 4);
        for scope in owned_scopes {
            statements.push(
                Statement::new(
                    "UPDATE authorization_scopes
                        SET owner_guard_version = owner_guard_version + 1
                      WHERE scope_key = ?2
                        AND EXISTS (SELECT 1 FROM memberships target
                          WHERE target.scope_key = ?2 AND target.principal_kind = 'user'
                            AND target.principal_id = ?1 AND target.role = 'owner')
                        AND EXISTS (SELECT 1 FROM memberships other
                          JOIN users owner_user ON owner_user.id = other.principal_id
                          WHERE other.scope_key = ?2 AND other.principal_kind = 'user'
                            AND other.principal_id <> ?1 AND other.role = 'owner'
                            AND owner_user.deleted_at IS NULL)",
                    vals![user_id, scope],
                )
                .expecting(1),
            );
        }
        statements.extend([
            Statement::new(
                "UPDATE users SET deleted_at = ?2
             WHERE id = ?1 AND deleted_at IS NULL
               AND NOT EXISTS (
                 SELECT 1 FROM orgs o
                 JOIN memberships m
                   ON m.scope_key = o.stable_id AND m.principal_kind = 'user'
                  AND m.principal_id = ?1 AND m.role = 'owner'
                 WHERE o.deleted_at IS NULL
                   AND NOT EXISTS (
                     SELECT 1 FROM memberships m2
                     WHERE m2.scope_key = o.stable_id
                       AND m2.principal_kind = 'user' AND m2.role = 'owner'
                       AND m2.principal_id <> ?1
                       AND EXISTS (SELECT 1 FROM users u
                                    WHERE u.id = m2.principal_id
                                      AND u.deleted_at IS NULL)))",
                vals![user_id, now],
            )
            .expecting(1),
            Statement::new(
                "DELETE FROM sessions WHERE user_id = ?1",
                vals![user_id].to_vec(),
            )
            .unchecked(),
            Statement::new(
                "UPDATE tokens SET revoked_at = ?2
                 WHERE owner_kind = 'user' AND owner_id = ?1 AND revoked_at IS NULL",
                vals![user_id, now].to_vec(),
            )
            .unchecked(),
            Statement::new(
                "DELETE FROM memberships
                      WHERE principal_kind = 'user' AND principal_id = ?1",
                vals![user_id],
            )
            .unchecked(),
        ]);
        if let Err(error) = self.backend.checked_batch(&statements).await {
            let blocking = self.sole_owned_orgs(user_id).await?;
            if !blocking.is_empty() {
                bail!(
                    "user {user_id} is the sole owner of: {} — transfer ownership before deleting",
                    blocking.join(", ")
                );
            }
            return Err(error);
        }
        Ok(true)
    }
}
