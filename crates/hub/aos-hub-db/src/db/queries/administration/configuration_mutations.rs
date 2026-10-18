//! Configuration mutations in the administration capability.

use super::*;

impl Database {
    /// Records the write capability supplied by the deployment itself.
    ///
    /// Local filesystem and Worker R2 bindings do not use operator-managed
    /// object-store credentials. Their deployment attachment is nevertheless
    /// an immutable authorization input, so it receives the same validated
    /// credential and write-revision history used by external providers.
    pub async fn ensure_deployment_owned_write_revision(
        &self,
        binding: &BindingRecord,
    ) -> Result<()> {
        let version_ref = match binding.kind.as_str() {
            "local_fs" => "native://aos-hub/default-storage/v1",
            "deployment_r2" => "worker://aos-hub/default-storage/v1",
            kind => bail!("instance-default binding cannot use provider kind '{kind}'"),
        };
        let provider_identity = serde_json::to_vec(&(
            binding.kind.as_str(),
            binding.local_root_path.as_deref(),
            binding.object_bucket.as_deref(),
            version_ref,
        ))?;
        let credential_fingerprint = hex::encode(sha2::Sha256::digest(&provider_identity));

        let credential = match self.current_binding_credential(binding.id, "write").await? {
            Some(credential) => credential,
            None => match self
                .set_binding_credential_revision(
                    binding.id,
                    "write",
                    version_ref,
                    0,
                    &credential_fingerprint,
                    "deployment-runtime",
                )
                .await
            {
                Ok(credential) => credential,
                Err(error) => self
                    .current_binding_credential(binding.id, "write")
                    .await?
                    .ok_or(error)?,
            },
        };
        anyhow::ensure!(
            credential.secret_version_ref == version_ref
                && credential.credential_fingerprint == credential_fingerprint,
            "instance-default write credential disagrees with deployment storage"
        );
        let credential = match credential.validation_state.as_str() {
            "valid" => credential,
            "unknown" => match self
                .validate_binding_credential_revision(
                    binding.id,
                    "write",
                    credential.generation,
                    "valid",
                    None,
                    credential.head_resource_version,
                )
                .await
            {
                Ok(credential) => credential,
                Err(error) => {
                    let Some(current) =
                        self.current_binding_credential(binding.id, "write").await?
                    else {
                        return Err(error);
                    };
                    if current.validation_state != "valid" {
                        return Err(error);
                    }
                    current
                }
            },
            state => bail!("instance-default write credential is {state}"),
        };

        let capability_fingerprint = hex::encode(sha2::Sha256::digest(serde_json::to_vec(&(
            binding.kind.as_str(),
            true,
            false,
        ))?));
        let revision_fingerprint = hex::encode(sha2::Sha256::digest(serde_json::to_vec(&(
            credential.secret_version_ref.as_str(),
            credential.generation,
            capability_fingerprint.as_str(),
        ))?));
        let revision = self
            .create_binding_write_revision(&NewBindingWriteRevision {
                binding_id: binding.id,
                write_credential_generation: credential.generation,
                writes_supported: true,
                conditional_writes_supported: false,
                revision_fingerprint,
                capability_fingerprint,
            })
            .await?;
        let observation = self
            .binding_write_observation(binding.id, revision.revision)
            .await?;
        match observation {
            None => {
                if let Err(error) = self
                    .observe_binding_write_revision(
                        binding.id,
                        revision.revision,
                        "valid",
                        None,
                        None,
                    )
                    .await
                {
                    let current = self
                        .binding_write_observation(binding.id, revision.revision)
                        .await?;
                    if !current
                        .as_ref()
                        .is_some_and(|current| current.state == "valid")
                    {
                        return Err(error);
                    }
                }
            }
            Some(observation) if observation.state == "valid" => {}
            Some(observation) => bail!(
                "instance-default write revision has unexpected state '{}'",
                observation.state
            ),
        }
        let state = self
            .binding_write_state(binding.id)
            .await?
            .context("instance-default write state is missing")?;
        match state.current_write_revision {
            Some(current) if current == revision.revision => {}
            None => {
                if let Err(error) = self
                    .set_current_binding_write_revision(
                        binding.id,
                        revision.revision,
                        state.resource_version,
                    )
                    .await
                {
                    let current = self
                        .binding_write_state(binding.id)
                        .await?
                        .context("instance-default write state disappeared")?;
                    if current.current_write_revision != Some(revision.revision) {
                        return Err(error);
                    }
                }
            }
            Some(_) => bail!("instance-default binding selected an unexpected write revision"),
        }
        Ok(())
    }

    /// Read an instance-config value by key.
    ///
    /// Returns `None` when the key is unset.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn instance_config_get(&self, key: &str) -> Result<Option<String>> {
        self.backend
            .query_opt(
                "SELECT value FROM instance_config WHERE config_key = ?1",
                &vals![key],
            )
            .await?
            .map(|row| row.get(0))
            .transpose()
    }

    /// Set an instance-config value, upserting the key.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn instance_config_set(&self, key: &str, value: &str) -> Result<()> {
        self.backend
            .execute(
                "INSERT INTO instance_config (config_key, value) VALUES (?1, ?2)
             ON CONFLICT(config_key) DO UPDATE SET value = excluded.value",
                &vals![key, value],
            )
            .await?;
        Ok(())
    }

    /// Delete an instance-config value by key (a no-op when the key is unset).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn instance_config_delete(&self, key: &str) -> Result<()> {
        self.backend
            .execute(
                "DELETE FROM instance_config WHERE config_key = ?1",
                &vals![key],
            )
            .await?;
        Ok(())
    }

    /// Deletes an `instance_config` key (clearing an optional setting back to
    /// its default), a no-op when the key is absent.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn instance_config_clear(&self, key: &str) -> Result<()> {
        self.backend
            .execute(
                "DELETE FROM instance_config WHERE config_key = ?1",
                &vals![key],
            )
            .await?;
        Ok(())
    }

    /// Loads the full editable instance-settings bundle from `instance_config`.
    ///
    /// Every field falls back to a documented default when its key is unset, so
    /// a fresh deployment reads as sensible defaults until an admin (or the
    /// deploy-time seed) overrides them. Read by the instance-settings console
    /// and the API/CLI; the branding/footer subset is also seeded into the page
    /// chrome at startup.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn instance_settings(&self) -> Result<InstanceSettings> {
        // One snapshot avoids mixed settings and one remote SQL call per field.
        let rows = self
            .backend
            .query(
                "SELECT config_key, value FROM instance_config
                 WHERE config_key IN (
                     'site_title', 'tagline', 'announcement', 'tos_url', 'privacy_url', 'support_url',
                     'signup_policy', 'signup_domains', 'password_login', 'caches_public',
                     'session_lifetime_secs', 'default_crawl_policy', 'max_upload_bytes'
                 )",
                &[],
            )
            .await?;
        let mut values = std::collections::HashMap::<String, String>::new();
        for row in rows {
            values.insert(row.get(0)?, row.get(1)?);
        }
        let get = |key: &str| values.get(key).cloned();

        Ok(InstanceSettings {
            site_title: get("site_title"),
            tagline: get("tagline"),
            announcement: get("announcement"),
            tos_url: get("tos_url"),
            privacy_url: get("privacy_url"),
            support_url: get("support_url"),
            signup_policy: SignupPolicy::parse(
                get("signup_policy").as_deref().unwrap_or("invite_only"),
            ),
            signup_domains: get("signup_domains")
                .map(|v| {
                    v.split(|c: char| c == ',' || c.is_whitespace())
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_lowercase())
                        .collect()
                })
                .unwrap_or_default(),
            password_login: get("password_login")
                .map(|v| v != "off" && v != "false" && v != "0")
                .unwrap_or(true),
            caches_public: get("caches_public")
                .map(|v| v == "on" || v == "true" || v == "1")
                .unwrap_or(false),
            session_lifetime_secs: get("session_lifetime_secs").and_then(|v| v.parse().ok()),
            default_crawl_policy: get("default_crawl_policy")
                .unwrap_or_else(|| "allow_all".to_string()),
            max_upload_bytes: get("max_upload_bytes").and_then(|v| v.parse().ok()),
        })
    }

    /// Upserts a single instance-config key, or clears it when `value` is
    /// `None`/blank (resetting to the default).
    ///
    /// The typed front door the console/API/CLI setters share, so an empty form
    /// field consistently means "reset" rather than "store an empty string".
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn replace_instance_setting_value(
        &self,
        key: &str,
        value: Option<&str>,
    ) -> Result<()> {
        match value.map(str::trim).filter(|v| !v.is_empty()) {
            Some(v) => self.instance_config_set(key, v).await,
            None => self.instance_config_clear(key).await,
        }
    }

    // -- configuration change-sets ------------------------------------------

    /// Create a change-set in `draft` status; returns nothing (the caller
    /// supplies the `change_id`).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, including a primary-key
    /// collision on `change_id`.
    pub async fn create_changeset(
        &self,
        change_id: &str,
        actor_kind: &str,
        actor_id: Option<i64>,
        actor_label: &str,
        scope: &str,
        summary: Option<&str>,
    ) -> Result<()> {
        if !aos_hub_model::domain::Scope::is_canonical(scope) {
            bail!("configuration change-set scope is not canonical");
        }
        let affected = self
            .backend
            .execute(
                "INSERT INTO change_requests
             (change_id, actor_kind, actor_id, actor_label, scope, status,
              summary, created_at, applied_at, reverted_by_change_id)
             SELECT ?1, ?2, ?3, ?4, a.scope_key, 'draft', ?6, ?7, NULL, NULL
               FROM authorization_scopes a LEFT JOIN orgs o ON o.id = a.org_id
              WHERE a.scope_key = ?5 AND (a.org_id IS NULL OR o.deleted_at IS NULL)",
                &vals![
                    change_id,
                    actor_kind,
                    actor_id,
                    actor_label,
                    scope,
                    summary,
                    unix_now(),
                ],
            )
            .await?;
        if affected != 1 {
            bail!("configuration change-set scope does not identify a live scope");
        }
        Ok(())
    }

    /// Append a revision to a change-set; returns the assigned `seq`.
    ///
    /// The `seq` is the next ordinal for the change-set (its current
    /// revision count), so revisions apply in insertion order.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, including a foreign-key
    /// violation when `change_id` is unknown.
    pub async fn add_revision(
        &self,
        change_id: &str,
        object_type: &str,
        object_id: &str,
        op: &str,
        old_json: Option<&str>,
        new_json: Option<&str>,
    ) -> Result<i64> {
        let seq: i64 = self
            .backend
            .query_opt(
                "SELECT COUNT(*) FROM change_request_revisions WHERE change_id = ?1",
                &vals![change_id],
            )
            .await?
            .context("count query returned no row")?
            .get(0)?;
        self.backend
            .execute(
                "INSERT INTO change_request_revisions
             (change_id, object_type, object_id, op, old_json, new_json, seq)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                &vals![
                    change_id,
                    object_type,
                    object_id,
                    op,
                    old_json,
                    new_json,
                    seq
                ],
            )
            .await?;
        Ok(seq)
    }

    /// Load one change-set summary by id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn changeset(&self, change_id: &str) -> Result<Option<ChangesetRow>> {
        self.backend
            .query_opt(
                &format!("SELECT {CHANGESET_COLUMNS} FROM change_requests WHERE change_id = ?1"),
                &vals![change_id],
            )
            .await
            .context("loading changeset by id")?
            .map(|row| row_to_changeset(&row))
            .transpose()
    }

    /// Withdraw an open draft change request (close without merging).
    ///
    /// Stamps `closed_at = now` on a change-set that is still `draft` and not
    /// already closed. This is hub-side advisory metadata only — it never
    /// touches `status` or the git ref, so a closed change can still be promoted
    /// by `apr change merge` (the indexer would then flip it to `applied`).
    /// Idempotent: closing an already-closed or non-draft row affects no rows.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn close_changeset(&self, change_id: &str) -> Result<()> {
        self.backend
            .execute(
                "UPDATE change_requests SET closed_at = ?2
             WHERE change_id = ?1 AND status = 'draft' AND closed_at IS NULL",
                &vals![change_id, unix_now()],
            )
            .await?;
        Ok(())
    }

    /// Reopen a closed change request, clearing its `closed_at` stamp.
    ///
    /// Only affects a `draft` row (a merged or reverted change-set is terminal
    /// and cannot be reopened). Clearing `closed_at` re-arms the indexer's
    /// auto-merge detection. Idempotent.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn reopen_changeset(&self, change_id: &str) -> Result<()> {
        self.backend
            .execute(
                "UPDATE change_requests SET closed_at = NULL
             WHERE change_id = ?1 AND status = 'draft'",
                &vals![change_id],
            )
            .await?;
        Ok(())
    }

    /// Set a change-set's lifecycle status, optionally stamping
    /// `applied_at` and/or `reverted_by_change_id`.
    ///
    /// Pass `applied_at = Some(t)` when transitioning to `applied`, and
    /// `reverted_by = Some(id)` when marking a change-set reverted by
    /// another. `None` arguments leave the corresponding columns untouched.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn set_changeset_status(
        &self,
        change_id: &str,
        status: &str,
        applied_at: Option<i64>,
        reverted_by: Option<&str>,
    ) -> Result<()> {
        self.backend
            .execute(
                "UPDATE change_requests
             SET status = ?2,
                 applied_at = COALESCE(?3, applied_at),
                 reverted_by_change_id = COALESCE(?4, reverted_by_change_id)
             WHERE change_id = ?1",
                &vals![change_id, status, applied_at, reverted_by],
            )
            .await?;
        Ok(())
    }

    /// Mark a git-backed change request applied, linking the promoting commit.
    ///
    /// Called by the indexer when it re-walks a registry surface and finds the
    /// verified HEAD commit carries an `AOS-Change-Id: <change_id>` trailer
    /// matching a `draft` change request (RFC-0004 "Configuration management",
    /// cross-referencing): the maintainer's `apr change merge` re-signed and
    /// pushed the draft, so the change request is now live. Stamps
    /// `status = 'applied'`, `applied_at = now`, and rewrites `git_commit` to
    /// the *promoting* (roster-signed) commit oid — the draft commit is
    /// superseded. Idempotent: re-marking an already-applied row is a harmless
    /// no-op on a status-guarded `UPDATE`.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn mark_changeset_applied_commit(
        &self,
        change_id: &str,
        commit_oid: &str,
    ) -> Result<()> {
        self.backend
            .execute(
                "UPDATE change_requests
             SET status = 'applied', applied_at = ?2, git_commit = ?3
             WHERE change_id = ?1 AND status = 'draft'",
                &vals![change_id, unix_now(), commit_oid],
            )
            .await?;
        Ok(())
    }

    /// Apply a change-set atomically: run `apply_fn` for each revision in
    /// `seq` order inside one transaction, then stamp `status = 'applied'`
    /// and `applied_at = now`.
    ///
    /// The caller supplies `apply_fn`, the live-object mutation for one
    /// revision (e.g. setting a registry's visibility). If any invocation
    /// fails the whole transaction rolls back and neither the live objects
    /// nor the changeset status change. The closure is `FnMut` so callers
    /// may thread mutable state through it.
    ///
    /// Note that `apply_fn` mutates live objects through a *separate*
    /// connection (it receives only the [`RevisionRow`], not the
    /// transaction), so its writes are not rolled back by a later revision's
    /// failure; the engine stages revisions only for changes whose live
    /// writes are individually idempotent and re-appliable (visibility,
    /// membership grants/revokes), so a partial apply is recoverable by
    /// re-applying.
    ///
    /// # Errors
    ///
    /// Returns an error if loading the revisions fails, if any `apply_fn`
    /// call returns an error, or on database failure committing the
    /// transaction.
    pub async fn apply_changeset<F>(&self, change_id: &str, mut apply_fn: F) -> Result<()>
    where
        F: for<'r> FnMut(
            &'r RevisionRow,
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + 'r>>,
    {
        let revisions = self.list_revisions(change_id).await?;
        for revision in &revisions {
            apply_fn(revision).await?;
        }
        self.mark_changeset_applied(change_id).await?;
        Ok(())
    }

    /// Stamps a change-set `applied`, recording the current time.
    ///
    /// This is the single status write that follows a change-set's
    /// per-revision live mutations; it is atomic on its own, so no transaction
    /// is needed.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn mark_changeset_applied(&self, change_id: &str) -> Result<()> {
        self.backend
            .execute(
                "UPDATE change_requests SET status = 'applied', applied_at = ?2
             WHERE change_id = ?1",
                &vals![change_id, unix_now()],
            )
            .await?;
        Ok(())
    }

    /// Append a discussion comment to a change request.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, including a foreign-key violation
    /// when `change_id` is unknown.
    pub async fn add_change_comment(
        &self,
        change_id: &str,
        actor_kind: &str,
        actor_id: Option<i64>,
        actor_label: &str,
        body: &str,
    ) -> Result<()> {
        self.backend
            .execute(
                "INSERT INTO change_comments
             (change_id, actor_kind, actor_id, actor_label, body, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                &vals![
                    change_id,
                    actor_kind,
                    actor_id,
                    actor_label,
                    body,
                    unix_now()
                ],
            )
            .await?;
        Ok(())
    }

    /// Record an advisory review (`approve` or `request_changes`) on a change.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, including a foreign-key violation
    /// when `change_id` is unknown.
    pub async fn add_change_review(
        &self,
        change_id: &str,
        actor_kind: &str,
        actor_id: Option<i64>,
        actor_label: &str,
        verdict: &str,
        body: Option<&str>,
    ) -> Result<()> {
        self.backend
            .execute(
                "INSERT INTO change_reviews
             (change_id, actor_kind, actor_id, actor_label, verdict, body, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                &vals![
                    change_id,
                    actor_kind,
                    actor_id,
                    actor_label,
                    verdict,
                    body,
                    unix_now()
                ],
            )
            .await?;
        Ok(())
    }
}
