//! Credentials mutations in the identity capability.

use super::*;

/// Largest number of expired OIDC flows removed by one maintenance pass.
const MAX_OIDC_FLOW_PRUNE_BATCH: i64 = 1_000;

impl Database {
    // -- auth: passwords (migration v18) -------------------------------------

    /// Set (or replace) a user's password hash.
    ///
    /// `password_hash` is an Argon2id PHC string from
    /// [`aos_hub_model::auth::password::hash_password`] — never a plaintext password.
    /// Overwriting an existing hash is how a password change is recorded; a
    /// later `NULL` (not exposed here) would clear it. Targets only a
    /// non-deleted user.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn set_user_password(&self, user_id: i64, password_hash: &str) -> Result<()> {
        self.backend
            .execute(
                "UPDATE users SET password_hash = ?2 WHERE id = ?1 AND deleted_at IS NULL",
                &vals![user_id, password_hash],
            )
            .await?;
        Ok(())
    }

    /// Looks up a verified mailbox owner's id and stored password hash for login.
    ///
    /// Returns `Ok(Some((user_id, phc)))` only when a non-deleted user exists
    /// for `email` **and** has a password set; returns `Ok(None)` when no such
    /// mailbox owner exists or the user has no password (`password_hash IS NULL`).
    /// The caller verifies `phc` with
    /// [`aos_hub_model::auth::password::verify_password`] and must surface the same
    /// generic "invalid email or password" outcome for both the `None` and the
    /// wrong-password cases, so the password login path never reveals whether
    /// an email is registered.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn user_for_password(&self, email: &str) -> Result<Option<(i64, String)>> {
        let row = self
            .backend
            .query_opt(
                "SELECT u.id, u.password_hash FROM user_mailboxes mailbox
                 JOIN users u ON u.id = mailbox.user_id
                 WHERE mailbox.email = ?1 AND u.deleted_at IS NULL
                   AND u.password_hash IS NOT NULL",
                &vals![email],
            )
            .await
            .context("loading user for password login")?;
        let Some(row) = row else {
            return Ok(None);
        };
        let user_id: i64 = row.get(0)?;
        let hash: String = row.get(1)?;
        Ok(Some((user_id, hash)))
    }

    /// Report whether a non-deleted user has a password set.
    ///
    /// Used by the account page to show whether a password is currently
    /// configured. Returns `Ok(false)` for an unknown or soft-deleted user, or
    /// a user whose `password_hash IS NULL`.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn user_has_password(&self, user_id: i64) -> Result<bool> {
        let row = self
            .backend
            .query_opt(
                "SELECT 1 FROM users
                 WHERE id = ?1 AND deleted_at IS NULL AND password_hash IS NOT NULL",
                &vals![user_id],
            )
            .await
            .context("checking whether user has a password")?;
        Ok(row.is_some())
    }

    // -- auth: magic links --------------------------------------------------

    /// Create a single-use email magic link, returning the link secret.
    ///
    /// Only the SHA-256 hash is stored; the link expires in
    /// [`aos_hub_model::auth::magic::MAGIC_LINK_TTL_SECS`].
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn create_magic_link(&self, email: &str) -> Result<String> {
        let secret = aos_hub_model::auth::magic::new_magic_secret();
        let hash = aos_hub_model::auth::token::sha256_hex(&secret);
        let now = unix_now();
        self.backend
            .execute(
                "INSERT INTO magic_links (token_hash, email, created_at, expires_at, consumed_at)
             VALUES (?1, ?2, ?3, ?4, NULL)",
                &vals![
                    hash,
                    email,
                    now,
                    now + aos_hub_model::auth::magic::MAGIC_LINK_TTL_SECS
                ],
            )
            .await?;
        Ok(secret)
    }

    /// Consume a magic link by its secret, returning the bound email once.
    ///
    /// Succeeds only for a link that is unexpired and not already consumed;
    /// on success it stamps `consumed_at` so the same secret cannot be used
    /// twice. Returns `Ok(None)` for unknown, expired, or replayed links.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn consume_magic_link(&self, secret: &str) -> Result<Option<String>> {
        let hash = aos_hub_model::auth::token::sha256_hex(secret);
        let now = unix_now();
        // Claim-then-read: the conditional UPDATE is the single-use gate, so
        // two concurrent consumptions of the same link cannot both succeed
        // (the second stamps zero rows). On sqlite/postgres a single
        // `UPDATE … RETURNING email` ties the claim to the email atomically;
        // MySQL has no `UPDATE … RETURNING`, so a transactional
        // select-claim-then-read preserves the same single-use guarantee.
        if self.dialect() == Dialect::Mysql {
            // MySQL lacks `UPDATE … RETURNING`; the conditional UPDATE is still
            // the single-use claim gate (a replay stamps zero rows), so the
            // follow-up read only fires — and only returns an email — when this
            // call won the claim.
            let claimed = self
                .backend
                .execute(
                    "UPDATE magic_links SET consumed_at = ?2
                     WHERE token_hash = ?1 AND consumed_at IS NULL AND expires_at > ?2",
                    &vals![hash, now],
                )
                .await
                .context("consuming magic link by hash")?;
            if claimed == 0 {
                return Ok(None);
            }
            let email = self
                .backend
                .query_opt(
                    "SELECT email FROM magic_links WHERE token_hash = ?1",
                    &vals![hash],
                )
                .await?
                .map(|r| r.get(0))
                .transpose()?;
            return Ok(email);
        }
        let email: Option<String> = self
            .backend
            .query_opt(
                "UPDATE magic_links SET consumed_at = ?2
                 WHERE token_hash = ?1 AND consumed_at IS NULL AND expires_at > ?2
                 RETURNING email",
                &vals![hash, now],
            )
            .await
            .context("consuming magic link by hash")?
            .map(|row| row.get(0))
            .transpose()?;
        Ok(email)
    }

    // -- auth: per-org OIDC SSO ---------------------------------------------

    /// Seeds an org's OIDC identity-provider configuration for a test fixture.
    ///
    /// One IdP per org (the `org_id` primary key); re-calling overwrites the
    /// existing configuration and bumps `updated_at`. `client_secret_enc`
    /// must already be **sealed** by a [`aos_hub_model::auth::seal::SecretSealer`] —
    /// this method stores the value verbatim and never sees the plaintext.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, including a foreign-key
    /// violation when `org_id` does not reference an org.
    #[cfg(any(test, feature = "test-fixtures"))]
    pub async fn upsert_idp_config(&self, config: &IdpConfigRecord) -> Result<()> {
        aos_hub_model::identity::validate_idp_config_record(config)?;
        let now = unix_now();
        self.backend
            .execute(
                "INSERT INTO org_idp_configs
             (org_id, issuer, authorization_endpoint, token_endpoint, jwks_uri,
              client_id, client_secret_enc, scopes, groups_claim, role_map_json,
              allow_jit, enforce_sso, default_role, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?14)
             ON CONFLICT(org_id) DO UPDATE SET
                 issuer = excluded.issuer,
                 authorization_endpoint = excluded.authorization_endpoint,
                 token_endpoint = excluded.token_endpoint,
                 jwks_uri = excluded.jwks_uri,
                 client_id = excluded.client_id,
                 client_secret_enc = excluded.client_secret_enc,
                 scopes = excluded.scopes,
                 groups_claim = excluded.groups_claim,
                 role_map_json = excluded.role_map_json,
                 allow_jit = excluded.allow_jit,
                 enforce_sso = excluded.enforce_sso,
                 default_role = excluded.default_role,
                 resource_version = org_idp_configs.resource_version + 1,
                 mutation_plan_id = NULL,
                 updated_at = excluded.updated_at",
                &vals![
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
                ],
            )
            .await?;
        Ok(())
    }

    /// Removes an identity-provider row while constructing a test fixture.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    #[cfg(any(test, feature = "test-fixtures"))]
    pub async fn delete_idp_config(&self, org_id: i64) -> Result<bool> {
        let n = self
            .backend
            .execute(
                "DELETE FROM org_idp_configs WHERE org_id = ?1",
                &vals![org_id],
            )
            .await?;
        Ok(n > 0)
    }

    /// Load an org's OIDC identity-provider configuration, if configured.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn idp_config(&self, org_id: i64) -> Result<Option<IdpConfigRecord>> {
        self.backend
            .query_opt(
                "SELECT org_id, issuer, authorization_endpoint, token_endpoint, jwks_uri,
                        client_id, client_secret_enc, scopes, groups_claim, role_map_json,
                        allow_jit, enforce_sso, default_role,
                        resource_version, incarnation_id, mutation_plan_id
                 FROM org_idp_configs WHERE org_id = ?1",
                &vals![org_id],
            )
            .await
            .context("loading idp config by org id")?
            .map(|row| row_to_idp_config(&row))
            .transpose()
    }

    /// Record an in-flight OIDC authorization-code request.
    ///
    /// Stores the opaque `state`, the verifier configuration, the `nonce` the
    /// id_token will be checked against, the PKCE `code_verifier`, and the
    /// browser-binding digest, with an `expires_at` `ttl_secs` from now. The
    /// row is consumed exactly once at
    /// the callback by [`Database::take_oidc_flow`].
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, a `state` collision, or when the
    /// pending-flow limit for the organization or hub has been reached.
    pub async fn create_oidc_flow(
        &self,
        state: &str,
        org_id: i64,
        verifier_id: &str,
        nonce: &str,
        code_verifier: &str,
        browser_binding_hash: &str,
        redirect_after: Option<&str>,
        ttl_secs: i64,
    ) -> Result<()> {
        let now = unix_now();
        self.backend
            .checked_batch(&[
                CheckedStatement::unchecked(
                    "UPDATE hub_schema_identity SET identity = identity WHERE identity = ?1",
                    vals![SCHEMA_IDENTITY],
                ),
                CheckedStatement::exact(
                    "INSERT INTO oidc_flows
             (state, org_id, verifier_id, nonce, code_verifier,
              browser_binding_hash, redirect_after, created_at, expires_at)
             SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9
             WHERE (SELECT COUNT(*) FROM oidc_flows
                    WHERE org_id = ?2 AND expires_at > ?8) < ?10
               AND (SELECT COUNT(*) FROM oidc_flows
                    WHERE expires_at > ?8) < ?11",
                    vals![
                        state,
                        org_id,
                        verifier_id,
                        nonce,
                        code_verifier,
                        browser_binding_hash,
                        redirect_after,
                        now,
                        now + ttl_secs,
                        MAX_PENDING_OIDC_FLOWS_PER_ORG,
                        MAX_PENDING_OIDC_FLOWS_TOTAL
                    ],
                    1,
                ),
            ])
            .await
            .context("staging OIDC flow within pending-flow limits")?;
        Ok(())
    }

    /// Removes a bounded batch of expired OIDC login flows.
    ///
    /// Rows are selected through the expiry index in oldest-first order. The
    /// nested selection remains portable to MySQL, which rejects deleting
    /// directly from a table referenced by the same statement's subquery.
    ///
    /// # Errors
    ///
    /// Returns an error when `limit` is outside `1..=1000` or on database
    /// failure.
    pub async fn prune_expired_oidc_flows(&self, now: i64, limit: i64) -> Result<u64> {
        anyhow::ensure!(
            (1..=MAX_OIDC_FLOW_PRUNE_BATCH).contains(&limit),
            "OIDC flow prune limit must be between 1 and {MAX_OIDC_FLOW_PRUNE_BATCH}"
        );

        let deleted = self
            .backend
            .execute(
                "DELETE FROM oidc_flows
                 WHERE state IN (
                   SELECT state FROM (
                     SELECT state FROM oidc_flows
                     WHERE expires_at <= ?1
                     ORDER BY expires_at, state
                     LIMIT ?2
                   ) AS expired_oidc_flows
                 )",
                &vals![now, limit],
            )
            .await?;
        Ok(deleted)
    }

    /// Consumes an OIDC flow by its `state` and browser-binding digest.
    ///
    /// Deletes the row and returns it in one statement (`DELETE … RETURNING`),
    /// so a replayed or forged `state` finds nothing — the single-use,
    /// CSRF-defeating gate. Returns `Ok(None)` for an unknown, mismatched,
    /// already-consumed, or expired flow. A mismatched digest leaves the row
    /// available for its initiating browser.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn take_oidc_flow(
        &self,
        state: &str,
        browser_binding_hash: &str,
    ) -> Result<Option<OidcFlowRecord>> {
        let now = unix_now();
        // sqlite/postgres do the delete-and-read in one `DELETE … RETURNING`;
        // MySQL lacks it, so select-then-delete inside a transaction keeps the
        // single-use, CSRF-defeating gate (the delete claims the state).
        let row: Option<OidcFlowRecord> = if self.dialect() == Dialect::Mysql {
            // MySQL lacks `DELETE … RETURNING`; read the row, then DELETE — the
            // DELETE is the single-use claim gate. Only return the row if the
            // DELETE affected a row, so a concurrent consumer that already
            // claimed the state gets `None` here.
            let selected = self
                .backend
                .query_opt(
                    "SELECT state, org_id, verifier_id, nonce, code_verifier, redirect_after, expires_at
                     FROM oidc_flows
                     WHERE state = ?1 AND browser_binding_hash = ?2",
                    &vals![state, browser_binding_hash],
                )
                .await?;
            if let Some(r) = selected {
                let claimed = self
                    .backend
                    .execute(
                        "DELETE FROM oidc_flows
                         WHERE state = ?1 AND browser_binding_hash = ?2",
                        &vals![state, browser_binding_hash],
                    )
                    .await?;
                if claimed > 0 {
                    Some(row_to_oidc_flow(&r)?)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            self.backend
                .query_opt(
                    "DELETE FROM oidc_flows
                     WHERE state = ?1 AND browser_binding_hash = ?2
                     RETURNING state, org_id, verifier_id, nonce, code_verifier, redirect_after, expires_at",
                    &vals![state, browser_binding_hash],
                )
                .await
                .context("consuming oidc flow by state")?
                .map(|row| row_to_oidc_flow(&row))
                .transpose()?
        };
        // Even though the row is deleted, an expired flow must not authenticate.
        match row {
            Some(flow) if now < flow.expires_at => Ok(Some(flow)),
            _ => Ok(None),
        }
    }

    // -- WebAuthn / passkeys (migration v17) --------------------------------

    /// Stage a WebAuthn ceremony challenge with a short TTL.
    ///
    /// `kind` is `"registration"` or `"assertion"`; `user_id` is the
    /// registering user for a registration ceremony, or `None` for a
    /// usernameless assertion ceremony (the user is resolved from the presented
    /// credential at verify). Registration ceremonies carry the browser-session
    /// binding that authorized them; assertion ceremonies pass `None`. The
    /// challenge is consumed exactly once by
    /// [`Database::take_webauthn_challenge`].
    ///
    /// # Errors
    ///
    /// Returns an error on database failure (including a `challenge` collision,
    /// which cannot happen for a 256-bit random value in practice).
    pub async fn create_webauthn_challenge(
        &self,
        challenge: &str,
        user_id: Option<i64>,
        kind: &str,
        ttl_secs: i64,
        registration_binding: Option<&WebauthnChallengeBinding>,
    ) -> Result<()> {
        let now = unix_now();
        let (session_id_hash, reauthentication_generation) =
            registration_binding.map_or((None, None), |binding| {
                (
                    Some(binding.session_id_hash.as_str()),
                    Some(binding.reauthentication_generation),
                )
            });
        self.backend
            .execute(
                "INSERT INTO webauthn_challenges
                 (challenge, user_id, kind, created_at, expires_at,
                  session_id_hash, reauthentication_generation)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                &vals![
                    challenge,
                    user_id,
                    kind,
                    now,
                    now + ttl_secs,
                    session_id_hash,
                    reauthentication_generation
                ],
            )
            .await?;
        Ok(())
    }

    /// Consume a WebAuthn challenge by value *and kind*, returning it once.
    ///
    /// Deletes the row and returns it (`DELETE … RETURNING` on sqlite/postgres,
    /// a select-then-delete transaction on MySQL), so a replayed challenge finds
    /// nothing — the single-use, anti-replay gate. Returns `Ok(None)` for an
    /// unknown, already-consumed, expired, or wrong-`kind` challenge.
    ///
    /// The delete is scoped to **both** `challenge` and `kind`: a submission of
    /// a known challenge value through the *other* ceremony's endpoint (the
    /// wrong `kind`) matches no row and therefore deletes nothing, so it cannot
    /// consume a victim's in-flight challenge of the other kind. (A challenge is
    /// a 256-bit random value, so a cross-kind collision is implausible, but the
    /// kind-scoped delete makes the property explicit and robust.)
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn take_webauthn_challenge(
        &self,
        challenge: &str,
        kind: &str,
    ) -> Result<Option<WebauthnChallengeRecord>> {
        let now = unix_now();
        let row: Option<WebauthnChallengeRecord> = if self.dialect() == Dialect::Mysql {
            // mysql lacks DELETE ... RETURNING: read the row, then claim it via
            // the delete's rows-affected (sequential statements — mysql is never
            // Worker HubDb, which uses the single-statement RETURNING path).
            let selected = self
                .backend
                .query_opt(
                    "SELECT challenge, user_id, kind, expires_at,
                            session_id_hash, reauthentication_generation
                     FROM webauthn_challenges WHERE challenge = ?1 AND kind = ?2",
                    &vals![challenge, kind],
                )
                .await?;
            if let Some(r) = selected {
                let n = self
                    .backend
                    .execute(
                        "DELETE FROM webauthn_challenges WHERE challenge = ?1 AND kind = ?2",
                        &vals![challenge, kind],
                    )
                    .await?;
                if n > 0 {
                    Some(row_to_webauthn_challenge(&r)?)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            self.backend
                .query_opt(
                    "DELETE FROM webauthn_challenges WHERE challenge = ?1 AND kind = ?2
                     RETURNING challenge, user_id, kind, expires_at,
                               session_id_hash, reauthentication_generation",
                    &vals![challenge, kind],
                )
                .await
                .context("consuming webauthn challenge")?
                .map(|row| row_to_webauthn_challenge(&row))
                .transpose()?
        };
        // The row is deleted (already kind-scoped), but an expired challenge
        // must still not authenticate.
        match row {
            Some(rec) if now < rec.expires_at => Ok(Some(rec)),
            _ => Ok(None),
        }
    }
}
