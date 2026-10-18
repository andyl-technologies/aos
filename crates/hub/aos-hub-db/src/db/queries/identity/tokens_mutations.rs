//! Tokens mutations in the identity capability.

use super::*;

impl Database {
    /// The number of active (non-revoked) tokens owned by any principal in an
    /// org.
    ///
    /// Counts tokens whose owner is the org's service accounts; user-owned
    /// tokens are not scoped to a single org, so the per-org token quota
    /// governs the org's service-account publishers (the CI surface). Used by
    /// the token-mint quota gate.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn org_active_token_count(&self, org_id: i64) -> Result<i64> {
        self.backend
            .query_opt(
                "SELECT COUNT(*) FROM tokens
                 WHERE owner_kind = 'service_account'
                   AND revoked_at IS NULL
                   AND owner_id IN (SELECT id FROM service_accounts WHERE org_id = ?1)",
                &vals![org_id],
            )
            .await?
            .context("token count query returned no row")?
            .get(0)
    }

    /// List token *metadata* (never the hash/secret) for an org's service
    /// accounts, for export.
    ///
    /// Returns `(token_id, owner_kind, owner_id, scope, permissions_json,
    /// created_at, expires_at, last_used_at)` for every token owned by a
    /// service account in `org_id`. The `hash` column is deliberately excluded
    /// — an export carries no usable credential (RFC-0004 offboarding).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    #[allow(clippy::type_complexity)]
    pub async fn export_org_token_metadata(
        &self,
        org_id: i64,
    ) -> Result<
        Vec<(
            String,
            String,
            i64,
            String,
            String,
            i64,
            Option<i64>,
            Option<i64>,
        )>,
    > {
        let rows = self
            .backend
            .query(
                "SELECT id, owner_kind, owner_id, scope_key, permissions, created_at, expires_at,
                    last_used_at
             FROM tokens
             WHERE owner_kind = 'service_account'
               AND owner_id IN (SELECT id FROM service_accounts WHERE org_id = ?1)
             ORDER BY created_at, id",
                &vals![org_id],
            )
            .await?;
        rows.iter()
            .map(|row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            })
            .collect()
    }

    // -- auth: provisioning tokens ------------------------------------------

    /// Mint a provisioning token owned by `owner`, returning `(id, secret)`.
    ///
    /// The caller is handed the plaintext `secret` exactly once; only its
    /// SHA-256 hash is stored. `scope` is the immutable resource identity the token is
    /// bound to and `permissions` the verbs it carries; `expires_at`, when
    /// set, is the Unix time after which [`Database::validate_token`] stops
    /// accepting the secret.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, including a hash collision.
    pub async fn create_token(
        &self,
        owner: aos_hub_model::domain::Principal,
        scope: &str,
        permissions: &[aos_hub_model::domain::Permission],
        comment: Option<&str>,
        expires_at: Option<i64>,
    ) -> Result<(String, String)> {
        if !aos_hub_model::domain::Scope::is_canonical(scope) {
            bail!("invalid stable authorization scope");
        }
        if !self
            .principal_is_live(owner.kind.as_str(), owner.id)
            .await?
        {
            bail!("token owner does not identify a live principal");
        }
        let context = self
            .authorization_context(scope)
            .await?
            .context("token scope does not identify a live authorization scope")?;
        let grants = self.effective_scopes(owner).await?;
        if permissions.is_empty()
            || permissions.iter().any(|permission| {
                !aos_hub_model::domain::iam::allow(&grants, *permission, &context)
            })
        {
            bail!("token permissions exceed the owner's current grants");
        }
        let (secret, hash) = aos_hub_model::auth::token::generate_token();
        let id = uuid::Uuid::new_v4().to_string();
        let perms_json = serde_json::to_string(&permission_names(permissions))?;
        let affected = self
            .backend
            .execute(
                "INSERT INTO tokens
             (id, hash, owner_kind, owner_id, scope_key, permissions, comment, created_at,
              expires_at, revoked_at, last_used_at)
             SELECT ?1, ?2, ?3, ?4, a.scope_key, ?6, ?7, ?8, ?9, NULL, NULL
             FROM authorization_scopes a LEFT JOIN orgs o ON o.id = a.org_id
             WHERE a.scope_key = ?5 AND (a.org_id IS NULL OR o.deleted_at IS NULL)
               AND ((?3 = 'user' AND EXISTS (
                      SELECT 1 FROM users u WHERE u.id = ?4 AND u.deleted_at IS NULL))
                 OR (?3 = 'service_account' AND EXISTS (
                      SELECT 1 FROM service_accounts s
                      JOIN orgs owner_org ON owner_org.id = s.org_id
                       WHERE s.id = ?4 AND owner_org.deleted_at IS NULL)))",
                &vals![
                    id,
                    hash,
                    owner.kind.as_str(),
                    owner.id,
                    aos_hub_model::domain::Scope::parse(scope).as_str(),
                    perms_json,
                    comment,
                    unix_now(),
                    expires_at,
                ],
            )
            .await?;
        if affected != 1 {
            bail!("token scope does not identify a live authorization scope");
        }
        Ok((id, secret))
    }

    /// Validate a token secret, returning its [`TokenAuth`] when live.
    ///
    /// A secret is accepted when its hash is known, it is not expired, and
    /// it is either not revoked or still inside the
    /// `ROTATION_GRACE_SECS` window after its `revoked_at` stamp (so a
    /// rotated token's old secret keeps working briefly). On success
    /// `last_used_at` is bumped to now. Returns `Ok(None)` for any
    /// unknown, expired, or fully-revoked secret without distinguishing
    /// the reason.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or a malformed stored row.
    pub async fn validate_token(&self, secret: &str) -> Result<Option<TokenAuth>> {
        let hash = aos_hub_model::auth::token::sha256_hex(secret);
        let row = self
            .backend
            .query_opt("SELECT id FROM tokens WHERE hash = ?1", &vals![hash])
            .await
            .context("loading token by hash")?;
        let Some(row) = row else {
            return Ok(None);
        };
        let id: String = row.get(0)?;
        self.live_token_auth_by_id(&id, true).await
    }

    /// Revoke a token by id, stamping `revoked_at = now`.
    ///
    /// A no-op when the id is unknown or already revoked.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn revoke_token(&self, token_id: &str) -> Result<()> {
        self.backend
            .execute(
                "UPDATE tokens SET revoked_at = ?2 WHERE id = ?1 AND revoked_at IS NULL",
                &vals![token_id, unix_now()],
            )
            .await?;
        Ok(())
    }

    /// Returns the immutable lifecycle revision of an access-token generation.
    ///
    /// The revision is `active`, `rotated`, or `retired`; `None` means the
    /// stable token id does not exist. Callers use this value as an exact
    /// plan/apply compare-and-swap precondition without exposing credential
    /// material.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed stored values.
    pub async fn token_lifecycle_version(&self, token_id: &str) -> Result<Option<String>> {
        Ok(self
            .token_scope_and_lifecycle(token_id)
            .await?
            .map(|(_, lifecycle)| lifecycle))
    }

    /// Returns the exact authorization scope and lifecycle revision for one token.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed stored values.
    pub async fn token_scope_and_lifecycle(
        &self,
        token_id: &str,
    ) -> Result<Option<(String, String)>> {
        let row = self
            .backend
            .query_opt(
                "SELECT scope_key, revoked_at, rotated_at FROM tokens WHERE id = ?1",
                &vals![token_id],
            )
            .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let scope: String = row.get(0)?;
        let revoked_at: Option<i64> = row.get(1)?;
        let rotated_at: Option<i64> = row.get(2)?;
        let lifecycle = if revoked_at.is_some() {
            "retired"
        } else if rotated_at.is_some() {
            "rotated"
        } else {
            "active"
        };
        Ok(Some((scope, lifecycle.to_string())))
    }

    /// Rotate a token: revoke the old one and mint a replacement with the
    /// same owner, scope, permissions, comment, and expiry.
    ///
    /// The old secret keeps validating for `ROTATION_GRACE_SECS` after
    /// rotation (its `revoked_at` is stamped now, and
    /// [`Database::validate_token`] honors the grace window) so in-flight
    /// clients are not cut off mid-request. Returns `(new_id, new_secret)`,
    /// or `Ok(None)` when the id is unknown or already revoked.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or a malformed stored row.
    pub async fn rotate_token(&self, token_id: &str) -> Result<Option<(String, String)>> {
        let now = unix_now();
        // Read the live token first; the checked batch below then proves that
        // this exact incarnation is still rotatable and that its stable
        // authorization scope is still live before it mints the replacement.
        // A concurrent rotation, revocation, or organization deletion makes
        // one of those checks affect zero rows and rolls the whole batch back.
        let Some(old) = self
            .backend
            .query_opt(
                "SELECT owner_kind, owner_id, scope_key, permissions, comment, expires_at
             FROM tokens WHERE id = ?1 AND revoked_at IS NULL",
                &vals![token_id],
            )
            .await?
        else {
            return Ok(None);
        };
        let owner_kind: String = old.get(0)?;
        let owner_id: i64 = old.get(1)?;
        let scope: String = old.get(2)?;
        let perms_json: String = old.get(3)?;
        let comment: Option<String> = old.get(4)?;
        let expires_at: Option<i64> = old.get(5)?;
        let Some(kind) = aos_hub_model::domain::PrincipalKind::parse(&owner_kind) else {
            return Ok(None);
        };
        let owner = aos_hub_model::domain::Principal { kind, id: owner_id };
        if !self.principal_is_live(&owner_kind, owner_id).await? {
            return Ok(None);
        }
        let Some(context) = self.authorization_context(&scope).await? else {
            return Ok(None);
        };
        let grants = self.effective_scopes(owner).await?;
        let permissions = parse_permission_names(&perms_json);
        if permissions.is_empty()
            || permissions.iter().any(|permission| {
                !aos_hub_model::domain::iam::allow(&grants, *permission, &context)
            })
        {
            return Ok(None);
        }
        let (secret, hash) = aos_hub_model::auth::token::generate_token();
        let new_id = uuid::Uuid::new_v4().to_string();
        self.backend
            .checked_batch(&[
                Statement::new(
                    "UPDATE tokens SET rotated_at = ?2
                     WHERE id = ?1 AND revoked_at IS NULL AND rotated_at IS NULL",
                    vals![token_id, now].to_vec(),
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO tokens
                 (id, hash, owner_kind, owner_id, scope_key, permissions, comment, created_at,
                  expires_at, revoked_at, last_used_at)
                 SELECT ?1, ?2, ?3, ?4, a.scope_key, ?6, ?7, ?8, ?9, NULL, NULL
                 FROM authorization_scopes a LEFT JOIN orgs o ON o.id = a.org_id
                 WHERE (a.org_id IS NULL OR o.deleted_at IS NULL)
                   AND ((?3 = 'user' AND EXISTS (
                          SELECT 1 FROM users u WHERE u.id = ?4 AND u.deleted_at IS NULL))
                     OR (?3 = 'service_account' AND EXISTS (
                          SELECT 1 FROM service_accounts s
                          JOIN orgs owner_org ON owner_org.id = s.org_id
                           WHERE s.id = ?4 AND owner_org.deleted_at IS NULL)))",
                    vals![
                        new_id, hash, owner_kind, owner_id, scope, perms_json, comment, now,
                        expires_at
                    ]
                    .to_vec(),
                )
                .expecting(1),
            ])
            .await?;
        Ok(Some((new_id, secret)))
    }

    /// Rotates one OAuth refresh credential and returns a fresh credential pair.
    ///
    /// Refresh credentials are single-use. Presenting a consumed credential
    /// revokes its complete family, preventing an attacker and the legitimate
    /// client from racing indefinitely after credential theft.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed stored credential
    /// metadata.
    pub async fn rotate_refresh_token(&self, secret: &str) -> Result<RefreshTokenResult> {
        let hash = aos_hub_model::auth::token::sha256_hex(secret);
        let now = unix_now();
        let row = self
            .backend
            .query_opt(
                "SELECT refresh.family_id, refresh.expires_at, refresh.consumed_at,
                        family.token_id, family.absolute_expires_at, family.revoked_at
                 FROM refresh_tokens refresh
                 JOIN refresh_token_families family ON family.id = refresh.family_id
                 WHERE refresh.hash = ?1",
                &vals![hash],
            )
            .await
            .context("loading OAuth refresh credential")?;
        let Some(row) = row else {
            return Ok(RefreshTokenResult::Invalid);
        };
        let family_id: String = row.get(0)?;
        let expires_at: i64 = row.get(1)?;
        let consumed_at: Option<i64> = row.get(2)?;
        let token_id: String = row.get(3)?;
        let absolute_expires_at: i64 = row.get(4)?;
        let revoked_at: Option<i64> = row.get(5)?;
        if consumed_at.is_some() {
            self.revoke_refresh_family(&family_id, now).await?;
            return Ok(RefreshTokenResult::Reused);
        }
        if revoked_at.is_some() || expires_at <= now || absolute_expires_at <= now {
            return Ok(RefreshTokenResult::Invalid);
        }
        let Some(auth) = self.live_token_auth_by_id(&token_id, false).await? else {
            self.revoke_refresh_family(&family_id, now).await?;
            return Ok(RefreshTokenResult::Invalid);
        };

        let (refresh_token, refresh_hash) = aos_hub_model::auth::token::generate_refresh_token();
        let next_expires_at = (now + aos_hub_model::auth::token::REFRESH_TOKEN_IDLE_TTL_SECS)
            .min(absolute_expires_at);
        let rotated = self
            .backend
            .checked_batch(&[
                Statement::new(
                    "UPDATE refresh_tokens SET consumed_at = ?2
                     WHERE hash = ?1 AND consumed_at IS NULL AND expires_at > ?2",
                    vals![hash, now],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO refresh_tokens
                     (hash, family_id, created_at, expires_at, consumed_at)
                     VALUES (?1, ?2, ?3, ?4, NULL)",
                    vals![refresh_hash, family_id, now, next_expires_at],
                )
                .expecting(1),
                Statement::new(
                    "UPDATE refresh_token_families SET last_used_at = ?2
                     WHERE id = ?1 AND revoked_at IS NULL AND absolute_expires_at > ?2",
                    vals![family_id, now],
                )
                .expecting(1),
            ])
            .await;
        match rotated {
            Ok(()) => Ok(RefreshTokenResult::Rotated(DeviceTokenGrant {
                auth,
                refresh_token,
                refresh_expires_in: next_expires_at - now,
            })),
            Err(error) => {
                let consumed = self
                    .backend
                    .query_opt(
                        "SELECT consumed_at FROM refresh_tokens WHERE hash = ?1",
                        &vals![aos_hub_model::auth::token::sha256_hex(secret)],
                    )
                    .await?
                    .and_then(|row| row.get::<Option<i64>>(0).ok())
                    .flatten()
                    .is_some();
                if consumed {
                    self.revoke_refresh_family(&family_id, now).await?;
                    Ok(RefreshTokenResult::Reused)
                } else {
                    Err(error)
                }
            }
        }
    }

    /// Revokes the refresh-token family containing `secret`.
    ///
    /// Returns `false` for an unknown credential and `true` when the family is
    /// known, including an already-revoked family.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn revoke_refresh_token(&self, secret: &str) -> Result<bool> {
        let hash = aos_hub_model::auth::token::sha256_hex(secret);
        let row = self
            .backend
            .query_opt(
                "SELECT family_id FROM refresh_tokens WHERE hash = ?1",
                &vals![hash],
            )
            .await?;
        let Some(row) = row else {
            return Ok(false);
        };
        let family_id: String = row.get(0)?;
        self.revoke_refresh_family(&family_id, unix_now()).await?;
        Ok(true)
    }

    // -- auth: device authorization (RFC 8628) ------------------------------

    /// Start a device-authorization grant, storing only secret hashes.
    ///
    /// Returns `(device_code_secret, user_code, expires_in_secs)`: the
    /// device code is the long secret the CLI polls with, the `user_code`
    /// is the short string the human types into `/activate`. `scope` and
    /// `permissions` record what the CLI *requested*; approval clamps them
    /// to the approver's grants.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, including a `user_code`
    /// collision.
    pub async fn start_device_authorization(
        &self,
        scope: &str,
        permissions: &[aos_hub_model::domain::Permission],
    ) -> Result<(String, String, i64)> {
        if !aos_hub_model::domain::Scope::is_canonical(scope) {
            bail!("invalid stable authorization scope");
        }
        let secret = aos_hub_model::auth::device::new_device_code();
        let hash = aos_hub_model::auth::token::sha256_hex(&secret);
        let user_code = aos_hub_model::auth::device::new_user_code();
        let now = unix_now();
        let ttl = aos_hub_model::auth::device::DEVICE_CODE_TTL_SECS;
        let perms_json = serde_json::to_string(&permission_names(permissions))?;
        let affected = self
            .backend
            .execute(
                "INSERT INTO device_codes
             (device_code_hash, user_code, scope_key, permissions, created_at, expires_at,
              approved_by_user, denied, issued_token_id)
             SELECT ?1, ?2, a.scope_key, ?4, ?5, ?6, NULL, 0, NULL
             FROM authorization_scopes a LEFT JOIN orgs o ON o.id = a.org_id
             WHERE a.scope_key = ?3 AND a.retired_at IS NULL
               AND (a.org_id IS NULL OR o.deleted_at IS NULL)",
                &vals![
                    hash,
                    user_code,
                    aos_hub_model::domain::Scope::parse(scope).as_str(),
                    perms_json,
                    now,
                    now + ttl,
                ],
            )
            .await?;
        if affected != 1 {
            bail!("device scope does not identify a live authorization scope");
        }
        Ok((secret, user_code, ttl))
    }

    /// Approve a device grant by its `user_code`, minting a token owned by
    /// `approver` and clamped to the approver's current live grants.
    ///
    /// The requested scope is clamped to the smallest scope the approver
    /// may grant (if the approver holds no grant covering it, the request
    /// is denied), and the requested permissions are intersected with what
    /// the approver actually holds at that scope. The minted token reuses the
    /// device-code secret as its bearer secret, so no recoverable token secret
    /// is persisted for [`Database::poll_device`].
    /// Returns `Ok(false)` when the `user_code` is unknown, already
    /// resolved (approved or denied), or expired.
    ///
    /// # Atomicity
    ///
    /// The claim, token mint, and token-id link happen inside one transaction.
    /// The grant is claimed by a conditional
    /// `UPDATE … WHERE approved_by_user IS NULL AND denied = 0 AND
    /// expires_at > ?` stamping `approved_by_user`; the mint proceeds only
    /// when that update touches exactly one row. Two concurrent approvals of
    /// the same `user_code` therefore cannot both mint — the loser's
    /// conditional claim stamps zero rows and it returns `Ok(false)` without
    /// minting, so no orphaned-but-live provisioning token is ever issued
    /// (the failure mode this method was hardened against). This mirrors the
    /// claim-then-act idiom of [`Database::consume_magic_link`] and
    /// [`Database::deny_device`].
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn approve_device(
        &self,
        user_code: &str,
        approver: aos_hub_model::domain::Principal,
        _approver_grants: &[(aos_hub_model::domain::Scope, aos_hub_model::domain::Role)],
    ) -> Result<bool> {
        let now = unix_now();
        if !self
            .principal_is_live(approver.kind.as_str(), approver.id)
            .await?
        {
            return Ok(false);
        }
        let Some(row) = self
            .backend
            .query_opt(
                "SELECT scope_key, permissions FROM device_codes
                  WHERE user_code = ?1 AND approved_by_user IS NULL
                    AND denied = 0 AND expires_at > ?2",
                &vals![user_code, now],
            )
            .await?
        else {
            return Ok(false);
        };
        let scope: String = row.get(0)?;
        let perms_json: String = row.get(1)?;
        let requested_scope = aos_hub_model::domain::Scope::parse(&scope);
        let requested_context = self
            .authorization_context(requested_scope.as_str())
            .await?
            .context("device code references a missing authorization scope")?;
        let requested = parse_permission_names(&perms_json);
        let current_grants = self.effective_scopes(approver).await?;
        // Clamp: keep only requested permissions the approver may actually
        // grant at the requested scope (downward inheritance via `allow`).
        let granted: Vec<aos_hub_model::domain::Permission> = requested
            .into_iter()
            .filter(|perm| {
                aos_hub_model::domain::iam::allow(&current_grants, *perm, &requested_context)
            })
            .collect();
        if granted.is_empty() {
            return Ok(false);
        }
        let token_id = uuid::Uuid::new_v4().to_string();
        let perms_out = serde_json::to_string(&permission_names(&granted))?;
        // This token is the durable authority behind short-lived access JWTs
        // and refresh-token families. Discard its generated plaintext so the
        // one-time device code can never be replayed as an ordinary bearer.
        let (_discarded_secret, authority_hash) = aos_hub_model::auth::token::generate_token();
        self.backend
            .checked_batch(&[
                Statement::new(
                    "UPDATE device_codes SET approved_by_user = ?2
                      WHERE user_code = ?1 AND approved_by_user IS NULL AND denied = 0
                        AND expires_at > ?3",
                    vals![user_code, approver.id, now],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO tokens
                 (id, hash, owner_kind, owner_id, scope_key, permissions, comment, created_at,
                  expires_at, revoked_at, last_used_at)
                 SELECT ?1, ?8, ?2, ?3, a.scope_key, ?5,
                        'OAuth device authorization', ?6, ?9, NULL, NULL
                 FROM device_codes device
                 JOIN authorization_scopes a ON a.scope_key = ?4
                 LEFT JOIN orgs o ON o.id = a.org_id
                 WHERE a.retired_at IS NULL
                   AND (a.org_id IS NULL OR o.deleted_at IS NULL)
                   AND device.user_code = ?7 AND device.approved_by_user = ?3
                   AND device.expires_at > ?6
                   AND ((?2 = 'user' AND EXISTS (
                          SELECT 1 FROM users u WHERE u.id = ?3 AND u.deleted_at IS NULL))
                     OR (?2 = 'service_account' AND EXISTS (
                          SELECT 1 FROM service_accounts s
                          JOIN orgs owner_org ON owner_org.id = s.org_id
                           WHERE s.id = ?3 AND owner_org.deleted_at IS NULL)))",
                    vals![
                        token_id,
                        approver.kind.as_str(),
                        approver.id,
                        requested_scope.as_str(),
                        perms_out,
                        now,
                        user_code,
                        authority_hash,
                        now + aos_hub_model::auth::token::REFRESH_TOKEN_ABSOLUTE_TTL_SECS,
                    ]
                    .to_vec(),
                )
                .expecting(1),
                Statement::new(
                    "UPDATE device_codes SET issued_token_id = ?2
                 WHERE user_code = ?1 AND approved_by_user = ?3
                   AND issued_token_id IS NULL",
                    vals![user_code, token_id, approver.id].to_vec(),
                )
                .expecting(1),
            ])
            .await?;
        Ok(true)
    }

    /// Deny a device grant by its `user_code`.
    ///
    /// Returns `Ok(false)` when the code is unknown or already resolved.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn deny_device(&self, user_code: &str) -> Result<bool> {
        let n = self
            .backend
            .execute(
                "UPDATE device_codes SET denied = 1
             WHERE user_code = ?1 AND approved_by_user IS NULL AND denied = 0",
                &vals![user_code],
            )
            .await?;
        Ok(n > 0)
    }

    /// Poll a device grant by its device-code secret.
    ///
    /// Returns [`DevicePollResult::Pending`] while the user has neither
    /// approved nor denied, [`DevicePollResult::SlowDown`] when the caller
    /// polls faster than the advertised interval, [`DevicePollResult::Denied`]
    /// or [`DevicePollResult::Expired`] for terminal failures, and
    /// [`DevicePollResult::Approved`] with a live token identity and new
    /// rotating refresh credential after approval.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn poll_device(&self, device_code_secret: &str) -> Result<DevicePollResult> {
        let hash = aos_hub_model::auth::token::sha256_hex(device_code_secret);
        let row = self
            .backend
            .query_opt(
                "SELECT denied, approved_by_user, expires_at, delivered_at, issued_token_id,
                        last_polled_at
                 FROM device_codes WHERE device_code_hash = ?1",
                &vals![hash],
            )
            .await
            .context("loading device code for poll")?;
        let Some(row) = row else {
            return Ok(DevicePollResult::Expired);
        };
        let denied: i64 = row.get(0)?;
        let approved_by: Option<i64> = row.get(1)?;
        let expires_at: i64 = row.get(2)?;
        let delivered_at: Option<i64> = row.get(3)?;
        let issued_token_id: Option<String> = row.get(4)?;
        let last_polled_at: Option<i64> = row.get(5)?;
        let now = unix_now();
        if expires_at <= now || delivered_at.is_some() {
            return Ok(DevicePollResult::Expired);
        }
        if last_polled_at.is_some_and(|last| now.saturating_sub(last) < 5) {
            return Ok(DevicePollResult::SlowDown);
        }
        if denied != 0 {
            return Ok(DevicePollResult::Denied);
        }
        if approved_by.is_none() || issued_token_id.is_none() {
            self.backend
                .execute(
                    "UPDATE device_codes SET last_polled_at = ?2
                     WHERE device_code_hash = ?1 AND delivered_at IS NULL",
                    &vals![hash, now],
                )
                .await?;
            return Ok(DevicePollResult::Pending);
        }
        let token_id = issued_token_id.context("approved device has no token id")?;
        let Some(auth) = self.live_token_auth_by_id(&token_id, false).await? else {
            return Ok(DevicePollResult::Expired);
        };
        let family_id = uuid::Uuid::new_v4().to_string();
        let (refresh_token, refresh_hash) = aos_hub_model::auth::token::generate_refresh_token();
        let absolute_expires_at = now + aos_hub_model::auth::token::REFRESH_TOKEN_ABSOLUTE_TTL_SECS;
        let refresh_expires_at = now + aos_hub_model::auth::token::REFRESH_TOKEN_IDLE_TTL_SECS;
        let delivered = self
            .backend
            .checked_batch(&[
                Statement::new(
                    "UPDATE device_codes SET delivered_at = ?2, last_polled_at = ?2
                     WHERE device_code_hash = ?1 AND delivered_at IS NULL
                       AND expires_at > ?2",
                    vals![hash, now],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO refresh_token_families
                     (id, token_id, created_at, last_used_at, absolute_expires_at, revoked_at)
                     VALUES (?1, ?2, ?3, ?3, ?4, NULL)",
                    vals![family_id, token_id, now, absolute_expires_at],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO refresh_tokens
                     (hash, family_id, created_at, expires_at, consumed_at)
                     VALUES (?1, ?2, ?3, ?4, NULL)",
                    vals![refresh_hash, family_id, now, refresh_expires_at],
                )
                .expecting(1),
            ])
            .await;
        match delivered {
            Ok(()) => Ok(DevicePollResult::Approved(DeviceTokenGrant {
                auth,
                refresh_token,
                refresh_expires_in: refresh_expires_at - now,
            })),
            Err(error) => {
                let already_delivered = self
                    .backend
                    .query_opt(
                        "SELECT delivered_at FROM device_codes WHERE device_code_hash = ?1",
                        &vals![aos_hub_model::auth::token::sha256_hex(device_code_secret)],
                    )
                    .await?
                    .and_then(|row| row.get::<Option<i64>>(0).ok())
                    .flatten()
                    .is_some();
                if already_delivered {
                    Ok(DevicePollResult::Expired)
                } else {
                    Err(error)
                }
            }
        }
    }
}
