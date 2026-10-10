//! Credentials mutations in the topology capability.

use super::*;

impl Database {
    /// Persist a newly-registered WebAuthn credential, returning its id.
    ///
    /// `credential_id` is the base64url of the authenticator's raw credential
    /// id; `public_key` is the base64 of its COSE public key. `sign_count` is
    /// the authenticator's initial signature counter.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, including a `UNIQUE(credential_id)`
    /// violation when the same credential is registered twice.
    pub async fn add_webauthn_credential(
        &self,
        user_id: i64,
        credential_id: &str,
        public_key: &str,
        sign_count: i64,
        transports: Option<&str>,
        label: Option<&str>,
    ) -> Result<i64> {
        self.backend
            .execute_insert(
                "INSERT INTO webauthn_credentials
             (user_id, credential_id, public_key, sign_count, transports, label, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                &vals![
                    user_id,
                    credential_id,
                    public_key,
                    sign_count,
                    transports,
                    label,
                    unix_now()
                ],
            )
            .await
    }

    /// Delete one of a user's passkeys by its row id.
    ///
    /// Scoped to `user_id` so a caller can only remove their own credential.
    /// Returns `false` when no matching credential exists (already gone, or not
    /// owned by the user).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn delete_webauthn_credential(&self, user_id: i64, id: i64) -> Result<bool> {
        let n = self
            .backend
            .execute(
                "DELETE FROM webauthn_credentials WHERE id = ?1 AND user_id = ?2",
                &vals![id, user_id],
            )
            .await?;
        Ok(n > 0)
    }

    /// Update a credential's stored signature counter.
    ///
    /// Called after a successful assertion to advance the monotonic counter the
    /// next assertion is checked against.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn update_credential_sign_count(&self, id: i64, sign_count: i64) -> Result<()> {
        self.backend
            .execute(
                "UPDATE webauthn_credentials SET sign_count = ?2 WHERE id = ?1",
                &vals![id, sign_count],
            )
            .await?;
        Ok(())
    }

    /// Stamp a credential's `last_used_at` to now.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn touch_credential(&self, id: i64) -> Result<()> {
        self.backend
            .execute(
                "UPDATE webauthn_credentials SET last_used_at = ?2 WHERE id = ?1",
                &vals![id, unix_now()],
            )
            .await?;
        Ok(())
    }

    /// Lists storage-credential probes eligible for a controller claim.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn due_storage_credential_probe_operations(
        &self,
        stale_before: i64,
        limit: usize,
    ) -> Result<Vec<TopologyOperationRecord>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        self.backend
            .query(
                &format!(
                    "SELECT {OPERATION_COLUMNS} FROM topology_operations o
                     WHERE o.operation_kind = 'storage_credential_probe'
                       AND (o.state = 'pending'
                         OR (o.state = 'running' AND o.started_at <= ?1))
                     ORDER BY o.created_at, o.operation_id LIMIT ?2"
                ),
                &vals![stale_before, i64::try_from(limit)?],
            )
            .await?
            .iter()
            .map(row_to_topology_operation)
            .collect()
    }

    /// Claims a pending or stale-running storage-credential probe under CAS.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid lease or database failure.
    pub async fn claim_storage_credential_probe_operation(
        &self,
        operation_id: &str,
        expected_version: i64,
        lease_seconds: i64,
    ) -> Result<Option<TopologyOperationRecord>> {
        if lease_seconds <= 0 {
            bail!("storage-credential probe claim lease must be positive");
        }
        let now = unix_now();
        let changed = self
            .backend
            .execute(
                "UPDATE topology_operations SET state = 'running', started_at = ?3,
                   finished_at = NULL, error = NULL, resource_version = resource_version + 1
                 WHERE operation_id = ?1 AND operation_kind = 'storage_credential_probe'
                   AND resource_version = ?2
                   AND (state = 'pending' OR (state = 'running' AND started_at <= ?4))",
                &vals![operation_id, expected_version, now, now - lease_seconds],
            )
            .await?;
        if changed == 0 {
            return Ok(None);
        }
        self.topology_operation(operation_id).await
    }

    /// Returns one credential revision and its current-head resource version.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn binding_credential_revision(
        &self,
        binding_id: i64,
        purpose: &str,
        generation: i64,
    ) -> Result<Option<BindingCredentialRevisionRecord>> {
        self.backend
            .query_opt(
                "SELECT r.binding_id, r.purpose, r.generation,
                   r.secret_version_ref, r.validation_state, r.validated_at,
                   r.validation_error, r.credential_fingerprint, r.created_by,
                   r.created_at, h.resource_version
                 FROM binding_credential_revisions r
                 JOIN binding_credential_heads h
                   ON h.binding_id = r.binding_id AND h.purpose = r.purpose
                 WHERE r.binding_id = ?1 AND r.purpose = ?2 AND r.generation = ?3",
                &vals![binding_id, purpose, generation],
            )
            .await?
            .map(|row| {
                Ok(BindingCredentialRevisionRecord {
                    binding_id: row.get(0)?,
                    purpose: row.get(1)?,
                    generation: row.get(2)?,
                    secret_version_ref: row.get(3)?,
                    validation_state: row.get(4)?,
                    validated_at: row.get(5)?,
                    validation_error: row.get(6)?,
                    credential_fingerprint: row.get(7)?,
                    created_by: row.get(8)?,
                    created_at: row.get(9)?,
                    head_resource_version: row.get(10)?,
                })
            })
            .transpose()
    }

    /// Creates and selects one immutable credential revision under a head CAS.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid fields, a stale expected generation,
    /// conflicting reuse, or database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn set_binding_credential_revision(
        &self,
        binding_id: i64,
        purpose: &str,
        secret_version_ref: &str,
        expected_current_generation: i64,
        credential_fingerprint: &str,
        actor: &str,
    ) -> Result<BindingCredentialRevisionRecord> {
        if !matches!(purpose, "read" | "write" | "delete" | "list" | "presign") {
            bail!("invalid storage credential purpose '{purpose}'");
        }
        aos_hub_model::secret_version::validate_secret_version_ref(secret_version_ref)?;
        anyhow::ensure!(
            credential_fingerprint.len() == 64
                && credential_fingerprint
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit()),
            "credential fingerprint must be a 64-character SHA-256 hex digest"
        );
        if let Some(row) = self
            .backend
            .query_opt(
                "SELECT generation FROM binding_credential_revisions
                 WHERE binding_id = ?1 AND purpose = ?2 AND secret_version_ref = ?3",
                &vals![binding_id, purpose, secret_version_ref],
            )
            .await?
        {
            let generation = row.get(0)?;
            let existing = self
                .binding_credential_revision(binding_id, purpose, generation)
                .await?
                .context("credential revision disappeared")?;
            let current = self.current_binding_credential(binding_id, purpose).await?;
            if existing.credential_fingerprint == credential_fingerprint
                && current.as_ref().map(|head| head.generation) == Some(existing.generation)
                && existing.generation == expected_current_generation + 1
            {
                return Ok(existing);
            }
            if existing.credential_fingerprint == credential_fingerprint {
                bail!("secret version reference replay does not match the current credential head");
            }
            bail!("secret version reference is already bound to different content");
        }
        let head = self.current_binding_credential(binding_id, purpose).await?;
        let current_generation = head.as_ref().map_or(0, |head| head.generation);
        if current_generation != expected_current_generation {
            bail!("credential head generation is stale");
        }
        let generation = current_generation + 1;
        let now = unix_now();
        let insert_sql = if current_generation == 0 {
            "INSERT INTO binding_credential_revisions
             (binding_id, purpose, generation, secret_version_ref,
              validation_state, credential_fingerprint, created_by, created_at)
             SELECT id, ?2, ?3, ?4, 'unknown', ?5, ?6, ?7
             FROM bindings WHERE id = ?1
               AND NOT EXISTS (SELECT 1 FROM binding_credential_heads
                 WHERE binding_id = ?1 AND purpose = ?2)"
        } else {
            "INSERT INTO binding_credential_revisions
             (binding_id, purpose, generation, secret_version_ref,
              validation_state, credential_fingerprint, created_by, created_at)
             SELECT id, ?2, ?3, ?4, 'unknown', ?5, ?6, ?7
             FROM bindings WHERE id = ?1
               AND EXISTS (SELECT 1 FROM binding_credential_heads
                 WHERE binding_id = ?1 AND purpose = ?2
                   AND current_generation = ?8)"
        };
        let insert_values = if current_generation == 0 {
            vals![
                binding_id,
                purpose,
                generation,
                secret_version_ref,
                credential_fingerprint,
                actor,
                now
            ]
            .to_vec()
        } else {
            vals![
                binding_id,
                purpose,
                generation,
                secret_version_ref,
                credential_fingerprint,
                actor,
                now,
                current_generation
            ]
            .to_vec()
        };
        let mut statements = vec![Statement::new(insert_sql, insert_values).expecting(1)];
        if current_generation == 0 {
            statements.push(
                Statement::new(
                    "INSERT INTO binding_credential_heads
                 (binding_id, purpose, current_generation, updated_at)
                 VALUES (?1, ?2, ?3, ?4)",
                    vals![binding_id, purpose, generation, now].to_vec(),
                )
                .expecting(1),
            );
        } else {
            statements.push(
                Statement::new(
                    "UPDATE binding_credential_heads
                 SET current_generation = ?3, resource_version = resource_version + 1,
                     updated_at = ?4
                 WHERE binding_id = ?1 AND purpose = ?2
                   AND current_generation = ?5
                   AND NOT EXISTS (SELECT 1 FROM cache_write_tickets ticket
                     WHERE ticket.binding_id = ?1
                       AND (ticket.write_credential_purpose = ?2
                         OR (?2 = 'presign'
                           AND ticket.presign_credential_generation IS NOT NULL))
                       AND (ticket.active_cache_slot = 1 OR
                         (ticket.state = 'completed'
                           AND ticket.covered_inventory_generation IS NULL)))
                   AND NOT EXISTS (SELECT 1 FROM object_deletion_jobs job
                     JOIN surface_placements placement
                       ON placement.id = job.placement_id
                     WHERE placement.binding_id = ?1
                       AND ?2 = 'delete' AND job.active_slot = 1)",
                    vals![binding_id, purpose, generation, now, current_generation].to_vec(),
                )
                .expecting(1),
            );
        }
        self.backend.checked_batch(&statements).await?;
        self.binding_credential_revision(binding_id, purpose, generation)
            .await?
            .context("created credential revision disappeared")
    }

    /// Records controller validation under the credential-head version CAS.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid state, stale version, a non-current
    /// generation, or database failure.
    pub async fn validate_binding_credential_revision(
        &self,
        binding_id: i64,
        purpose: &str,
        generation: i64,
        state: &str,
        validation_error: Option<&str>,
        expected_resource_version: i64,
    ) -> Result<BindingCredentialRevisionRecord> {
        if !matches!(state, "valid" | "invalid") || (state == "valid") != validation_error.is_none()
        {
            bail!("credential validation must be valid without an error or invalid with an error");
        }
        let binding = self
            .binding(binding_id)
            .await?
            .context("binding does not exist")?;
        let now = unix_now();
        let event_id = format!("topology-event:{}", uuid::Uuid::new_v4().simple());
        let event_name = if state == "valid" {
            "topology.storage_credential.validated"
        } else {
            "topology.storage_credential.rejected"
        };
        let payload_json = serde_json::to_string(&serde_json::json!({
            "type": event_name,
            "resource_kind": "binding_credential",
            "binding_id": binding.stable_id,
            "purpose": purpose,
            "generation": generation,
            "result": state,
        }))?;
        self.backend
            .checked_batch(&[
                Statement::new(
                    "UPDATE binding_credential_revisions
                     SET validation_state = ?4, validated_at = ?5, validation_error = ?6
                     WHERE binding_id = ?1 AND purpose = ?2 AND generation = ?3
                       AND EXISTS (SELECT 1 FROM binding_credential_heads h
                         WHERE h.binding_id = ?1 AND h.purpose = ?2
                           AND h.current_generation = ?3 AND h.resource_version = ?7)",
                    vals![
                        binding_id,
                        purpose,
                        generation,
                        state,
                        now,
                        validation_error,
                        expected_resource_version
                    ]
                    .to_vec(),
                )
                .expecting(1),
                Statement::new(
                    "UPDATE binding_credential_heads
                     SET resource_version = resource_version + 1, updated_at = ?4
                     WHERE binding_id = ?1 AND purpose = ?2
                       AND current_generation = ?3 AND resource_version = ?5",
                    vals![
                        binding_id,
                        purpose,
                        generation,
                        now,
                        expected_resource_version
                    ]
                    .to_vec(),
                )
                .expecting(1),
                Database::topology_event_statement(&NewTopologyEvent {
                    event_id: &event_id,
                    event_name,
                    owner_scope_key: &binding.owner_scope_key,
                    resource_kind: "binding_credential",
                    resource_stable_id: &binding.stable_id,
                    resource_generation_key: generation,
                    actor_kind: "system",
                    actor_id: None,
                    actor_label: "storage-credential-controller",
                    payload_json: &payload_json,
                    occurred_at: now,
                }),
            ])
            .await?;
        let record = self
            .binding_credential_revision(binding_id, purpose, generation)
            .await?
            .context("validated credential revision disappeared")?;
        if record.validation_state != state
            || record.validation_error.as_deref() != validation_error
            || record.head_resource_version != expected_resource_version + 1
        {
            bail!("credential validation resource version is stale");
        }
        Ok(record)
    }
}
