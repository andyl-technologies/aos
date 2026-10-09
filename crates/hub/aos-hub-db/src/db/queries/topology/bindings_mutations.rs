//! Bindings mutations in the topology capability.

use super::*;

impl Database {
    /// Creates a new immutable write revision without selecting it for use.
    ///
    /// A credential rotation always creates a distinct revision, even when its
    /// capability fingerprint is unchanged. The revision fingerprint provides
    /// retry idempotency without conflating two credential versions.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid fingerprints, an absent binding, a reused
    /// revision fingerprint, or a database failure.
    pub async fn create_binding_write_revision(
        &self,
        input: &NewBindingWriteRevision,
    ) -> Result<BindingWriteRevisionRecord> {
        if input.write_credential_generation <= 0 {
            bail!("write credential generation must be positive");
        }
        let credential = self
            .binding_credential_revision(
                input.binding_id,
                "write",
                input.write_credential_generation,
            )
            .await?
            .context("write credential generation does not exist")?;
        if credential.validation_state != "valid" {
            bail!("write credential generation is not valid");
        }
        validate_key_bytes(&input.revision_fingerprint, "revision fingerprint", 128)?;
        validate_key_bytes(&input.capability_fingerprint, "capability fingerprint", 128)?;
        if input.conditional_writes_supported && !input.writes_supported {
            bail!("conditional writes require ordinary write capability");
        }
        self.ensure_binding_write_state(input.binding_id).await?;
        let now = unix_now();
        let matching_existing = |record: &BindingWriteRevisionRecord| {
            record.write_credential_generation == input.write_credential_generation
                && record.writes_supported == input.writes_supported
                && record.conditional_writes_supported == input.conditional_writes_supported
                && record.capability_fingerprint == input.capability_fingerprint
        };
        let existing_by_fingerprint = async {
            self.backend.query_opt(
                &format!("SELECT {BINDING_WRITE_REVISION_COLUMNS} FROM binding_write_revisions WHERE binding_id = ?1 AND revision_fingerprint = ?2"),
                &vals![input.binding_id, input.revision_fingerprint],
            ).await
        };
        if let Some(row) = existing_by_fingerprint.await? {
            let existing = row_to_binding_write_revision(&row)?;
            if matching_existing(&existing) {
                return Ok(existing);
            }
            bail!("revision fingerprint is already bound to different revision content");
        }
        let revision = loop {
            let revision: i64 = self
                .backend
                .query_opt(
                    "SELECT COALESCE((SELECT MAX(revision)
                        FROM binding_write_revisions r
                        WHERE r.binding_id = b.id), 0) + 1
                     FROM bindings b WHERE b.id = ?1",
                    &vals![input.binding_id],
                )
                .await?
                .context("binding does not exist")?
                .get(0)?;
            let inserted = self
                .backend
                .execute(
                    "INSERT INTO binding_write_revisions
                 (binding_id, revision, write_credential_version_ref,
                  write_credential_purpose, write_credential_generation,
                  writes_supported, conditional_writes_supported,
                  revision_fingerprint, capability_fingerprint, created_at)
                 SELECT id, ?2, ?3, 'write', ?4,
                   ?5, ?6, ?7, ?8, ?9
                 FROM bindings WHERE id = ?1",
                    &vals![
                        input.binding_id,
                        revision,
                        credential.secret_version_ref,
                        input.write_credential_generation,
                        input.writes_supported,
                        input.conditional_writes_supported,
                        input.revision_fingerprint,
                        input.capability_fingerprint,
                        now
                    ],
                )
                .await;
            match inserted {
                Ok(1) => break revision,
                Ok(_) => bail!("binding does not exist"),
                Err(error) => {
                    if let Some(row) = self.backend.query_opt(
                        &format!("SELECT {BINDING_WRITE_REVISION_COLUMNS} FROM binding_write_revisions WHERE binding_id = ?1 AND revision_fingerprint = ?2"),
                        &vals![input.binding_id, input.revision_fingerprint],
                    ).await? {
                        let existing = row_to_binding_write_revision(&row)?;
                        if matching_existing(&existing) {
                            return Ok(existing);
                        }
                        bail!("revision fingerprint is already bound to different revision content");
                    }
                    // Retry only when a concurrent, different revision won
                    // this local ordinal. Other database errors are stable and
                    // must not become an unbounded retry loop.
                    let latest: Option<i64> = self
                        .backend
                        .query_opt(
                            "SELECT MAX(revision) FROM binding_write_revisions
                             WHERE binding_id = ?1",
                            &vals![input.binding_id],
                        )
                        .await?
                        .context("revision allocation query returned no row")?
                        .get(0)?;
                    if !latest.is_some_and(|latest| latest >= revision) {
                        return Err(error);
                    }
                }
            }
        };
        self.binding_write_revision(input.binding_id, revision)
            .await?
            .context("created binding-write revision disappeared")
    }

    /// Returns one immutable binding-write revision.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn binding_write_revision(
        &self,
        binding_id: i64,
        revision: i64,
    ) -> Result<Option<BindingWriteRevisionRecord>> {
        let rows = self
            .backend
            .query(
                &format!(
                    "SELECT {BINDING_WRITE_REVISION_COLUMNS}
                     FROM binding_write_revisions
                     WHERE binding_id = ?1 AND revision = ?2"
                ),
                &vals![binding_id, revision],
            )
            .await?;
        rows.first().map(row_to_binding_write_revision).transpose()
    }

    /// Returns the binding's default write revision for new plans.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn binding_write_state(
        &self,
        binding_id: i64,
    ) -> Result<Option<BindingWriteStateRecord>> {
        let row = self
            .backend
            .query_opt(
                "SELECT binding_id, current_write_revision,
                        resource_version, updated_at
                 FROM binding_write_state WHERE binding_id = ?1",
                &vals![binding_id],
            )
            .await?;
        row.map(|row| {
            Ok(BindingWriteStateRecord {
                binding_id: row.get(0)?,
                current_write_revision: row.get(1)?,
                resource_version: row.get(2)?,
                updated_at: row.get(3)?,
            })
        })
        .transpose()
    }

    /// Selects a validated immutable revision as the default for new plans.
    ///
    /// Existing surface authorities remain pinned to their exact desired and
    /// observed revisions; moving this pointer does not rotate them.
    ///
    /// # Errors
    ///
    /// Returns an error unless the revision has a `valid` observation and the
    /// binding-write state resource version matches.
    pub async fn set_current_binding_write_revision(
        &self,
        binding_id: i64,
        revision: i64,
        expected_version: i64,
    ) -> Result<BindingWriteStateRecord> {
        let affected = self
            .backend
            .execute(
                "UPDATE binding_write_state
                 SET current_write_revision = ?2,
                     resource_version = resource_version + 1, updated_at = ?4
                 WHERE binding_id = ?1 AND resource_version = ?3
                   AND EXISTS (SELECT 1 FROM binding_write_observations o
                     WHERE o.binding_id = ?1 AND o.revision = ?2
                       AND o.state = 'valid')",
                &vals![binding_id, revision, expected_version, unix_now()],
            )
            .await?;
        if affected != 1 {
            bail!("binding-write state is stale or the revision is not valid");
        }
        self.binding_write_state(binding_id)
            .await?
            .context("binding-write state disappeared")
    }

    /// Records controller validation for an immutable binding-write revision.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid state/error combination, an absent
    /// revision, stale observation version, or database failure.
    pub async fn observe_binding_write_revision(
        &self,
        binding_id: i64,
        revision: i64,
        state: &str,
        error: Option<&str>,
        expected_observation_version: Option<i64>,
    ) -> Result<BindingWriteObservationRecord> {
        if !matches!(state, "unknown" | "validating" | "valid" | "invalid") {
            bail!("invalid binding-write observation state '{state}'");
        }
        if state != "invalid" && error.is_some() {
            bail!("only an invalid binding-write observation may carry an error");
        }
        let validated_at = matches!(state, "valid" | "invalid").then(unix_now);
        let affected = if let Some(version) = expected_observation_version {
            self.backend
                .execute(
                    "UPDATE binding_write_observations
                     SET state = ?4, validated_at = ?5, error = ?6,
                         observation_version = observation_version + 1
                     WHERE binding_id = ?1 AND revision = ?2
                       AND observation_version = ?3",
                    &vals![binding_id, revision, version, state, validated_at, error],
                )
                .await?
        } else {
            self.backend
                .execute(
                    "INSERT INTO binding_write_observations
                     (binding_id, revision, state, validated_at, error)
                     SELECT binding_id, revision, ?3, ?4, ?5
                     FROM binding_write_revisions
                     WHERE binding_id = ?1 AND revision = ?2",
                    &vals![binding_id, revision, state, validated_at, error],
                )
                .await?
        };
        if affected != 1 {
            bail!("binding-write revision is missing or its observation version is stale");
        }
        let row = self.backend.query_opt(
            &format!("SELECT {BINDING_WRITE_OBSERVATION_COLUMNS} FROM binding_write_observations WHERE binding_id = ?1 AND revision = ?2"),
            &vals![binding_id, revision],
        ).await?.context("binding-write observation disappeared")?;
        row_to_binding_write_observation(&row)
    }

    /// Returns the controller observation for one binding-write revision.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn binding_write_observation(
        &self,
        binding_id: i64,
        revision: i64,
    ) -> Result<Option<BindingWriteObservationRecord>> {
        let row = self.backend.query_opt(
            &format!("SELECT {BINDING_WRITE_OBSERVATION_COLUMNS} FROM binding_write_observations WHERE binding_id = ?1 AND revision = ?2"),
            &vals![binding_id, revision],
        ).await?;
        row.map(|row| row_to_binding_write_observation(&row))
            .transpose()
    }

    /// Lists authorities pinned to one immutable binding-write revision.
    ///
    /// The result is the fan-out set that credential rotation must move before
    /// the old revision can be retired.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn surface_write_authorities_using_binding_revision(
        &self,
        binding_id: i64,
        binding_write_revision: i64,
    ) -> Result<Vec<SurfaceWriteAuthorityRecord>> {
        let rows = self
            .backend
            .query(
                &format!(
                    "SELECT {WRITE_AUTHORITY_COLUMNS} FROM surface_write_authorities a
                 WHERE (a.desired_binding_write_revision = ?2
                    AND EXISTS (SELECT 1 FROM surface_placements p
                      WHERE p.id = a.desired_placement_id AND p.binding_id = ?1))
                    OR (a.observed_binding_write_revision = ?2
                    AND EXISTS (SELECT 1 FROM surface_placements p
                      WHERE p.id = a.observed_placement_id AND p.binding_id = ?1))
                 ORDER BY a.id"
                ),
                &vals![binding_id, binding_write_revision],
            )
            .await?;
        rows.iter().map(row_to_surface_write_authority).collect()
    }

    /// Retires an immutable binding-write revision after every authority moved away.
    ///
    /// Candidate capability pins are removed as part of retirement. Database
    /// foreign keys reject the operation while any desired or observed
    /// authority still references the revision, and the desired current
    /// binding revision is never removed.
    ///
    /// # Errors
    ///
    /// Returns an error on a remaining authority/current-pointer pin or database failure.
    pub async fn retire_binding_write_revision(
        &self,
        binding_id: i64,
        revision: i64,
    ) -> Result<bool> {
        if !self
            .surface_write_authorities_using_binding_revision(binding_id, revision)
            .await?
            .is_empty()
        {
            bail!("binding-write revision remains pinned by surface authority");
        }
        if self
            .binding_write_state(binding_id)
            .await?
            .is_some_and(|state| state.current_write_revision == Some(revision))
        {
            bail!("binding-write revision is still the binding's current revision");
        }
        if self
            .backend
            .query_opt(
                "SELECT 1 FROM oci_gc_placement_snapshots snapshot
                 JOIN oci_gc_runs run ON run.id = snapshot.run_id
                 WHERE snapshot.binding_id = ?1
                   AND snapshot.binding_write_revision = ?2
                   AND run.state = 'applying' LIMIT 1",
                &vals![binding_id, revision],
            )
            .await?
            .is_some()
        {
            bail!("binding-write revision remains pinned by applying OCI GC");
        }
        self.backend
            .batch(&[
                Statement::new(
                    "DELETE FROM surface_placement_write_capabilities
                     WHERE binding_id = ?1 AND binding_write_revision = ?2
                       AND NOT EXISTS (SELECT 1
                         FROM oci_gc_placement_snapshots snapshot
                         JOIN oci_gc_runs run ON run.id = snapshot.run_id
                         WHERE snapshot.binding_id = ?1
                           AND snapshot.binding_write_revision = ?2
                           AND run.state = 'applying')",
                    vals![binding_id, revision].to_vec(),
                ),
                Statement::new(
                    "DELETE FROM binding_write_revisions
                     WHERE binding_id = ?1 AND revision = ?2
                       AND NOT EXISTS (SELECT 1 FROM binding_write_state s
                         WHERE s.binding_id = ?1 AND s.current_write_revision = ?2)
                       AND NOT EXISTS (SELECT 1
                         FROM oci_gc_placement_snapshots snapshot
                         JOIN oci_gc_runs run ON run.id = snapshot.run_id
                         WHERE snapshot.binding_id = ?1
                           AND snapshot.binding_write_revision = ?2
                           AND run.state = 'applying')",
                    vals![binding_id, revision].to_vec(),
                ),
            ])
            .await?;
        Ok(self
            .binding_write_revision(binding_id, revision)
            .await?
            .is_none())
    }

    /// Creates one final-topology binding with a caller-chosen stable identity.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identity/spec fields, uniqueness conflicts,
    /// or database failure.
    pub async fn create_topology_binding(
        &self,
        org_id: Option<i64>,
        stable_id: &str,
        owner_scope_key: &str,
        name: &str,
        kind: &str,
        local_root_path: Option<&str>,
        object_bucket: Option<&str>,
        object_prefix: Option<&str>,
        endpoint_scheme: Option<&str>,
        endpoint_host_kind: Option<&str>,
        endpoint_host_bytes: Option<&[u8]>,
        endpoint_port: Option<i64>,
        signing_region: Option<&str>,
        access_mode: Option<&str>,
    ) -> Result<i64> {
        validate_key_bytes(stable_id, "binding stable id", 64)?;
        validate_key_bytes(owner_scope_key, "binding owner scope", 64)?;
        validate_key_bytes(name, "binding name", 128)?;
        aos_hub_model::binding::BindingKind::parse(kind)
            .context("binding kind must be local_fs, s3, r2, or deployment_r2")?;
        if org_id.is_some() && matches!(kind, "local_fs" | "deployment_r2") {
            bail!("organization bindings must use an external s3 or r2 provider");
        }
        let is_instance_default = org_id.is_none();
        if is_instance_default != (owner_scope_key == "instance") {
            anyhow::bail!(
                "instance bindings must own the instance scope and organization bindings must not"
            );
        }
        let now = unix_now();
        let id = self.max_id("bindings").await? + 1;
        let default_key = is_instance_default.then_some("singleton");
        let statements = [
            Statement::new(
                "INSERT INTO bindings
                 (id, org_id, name, kind, is_instance_default, instance_default_key, created_at,
                  stable_id, owner_scope_key, local_root_path,
                  object_bucket, object_prefix, endpoint_scheme, endpoint_host_kind,
                  endpoint_host_bytes, endpoint_port, signing_region, access_mode,
                  resource_version, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                         ?13, ?14, ?15, ?16, ?17, ?18, 1, ?7)",
                vals![
                    id,
                    org_id,
                    name,
                    kind,
                    is_instance_default,
                    default_key,
                    now,
                    stable_id,
                    owner_scope_key,
                    local_root_path,
                    object_bucket,
                    object_prefix,
                    endpoint_scheme,
                    endpoint_host_kind,
                    endpoint_host_bytes,
                    endpoint_port,
                    signing_region,
                    access_mode
                ],
            )
            .expecting(1),
            Statement::new(
                "INSERT INTO binding_consumer_scopes
                 (binding_id, consumer_scope_key, grant_generation, grant_kind,
                  state, granted_by, granted_at, resource_version)
                 VALUES (?1, ?2, 1, 'owner', 'active', 'system:binding-create', ?3, 1)",
                vals![id, owner_scope_key, now],
            )
            .expecting(1),
        ];
        self.backend.checked_batch(&statements).await?;
        Ok(id)
    }

    /// Look up a binding by id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn binding(&self, id: i64) -> Result<Option<BindingRecord>> {
        self.backend
            .query_opt(
                "SELECT id, org_id, name, kind, is_instance_default, stable_id, owner_scope_key,
                 local_root_path, object_bucket, object_prefix, endpoint_scheme,
                 endpoint_host_kind, endpoint_host_bytes, endpoint_port,
                 signing_region, access_mode, resource_version, created_at, updated_at
                 FROM bindings WHERE id = ?1",
                &vals![id],
            )
            .await
            .context("loading binding by id")?
            .map(|row| row_to_binding(&row))
            .transpose()
    }

    /// Returns the singleton instance-level default binding.
    ///
    /// The binding is an explicitly addressable topology resource and a default
    /// for creation workflows. Surfaces never inherit it implicitly: every
    /// placement pins a concrete binding and binding revision.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn instance_default_binding(&self) -> Result<Option<BindingRecord>> {
        self.backend
            .query_opt(
                "SELECT id, org_id, name, kind, is_instance_default, stable_id, owner_scope_key,
                 local_root_path, object_bucket, object_prefix, endpoint_scheme,
                 endpoint_host_kind, endpoint_host_bytes, endpoint_port,
                 signing_region, access_mode, resource_version, created_at, updated_at
                 FROM bindings WHERE is_instance_default = 1 LIMIT 1",
                &[],
            )
            .await
            .context("loading instance default binding")?
            .map(|row| row_to_binding(&row))
            .transpose()
    }

    /// Provisions the immutable deployment-owned default binding exactly once.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported deployment shape or database failure.
    pub async fn ensure_instance_default_binding(
        &self,
        kind: &str,
        local_root_path: Option<&str>,
        object_bucket: Option<&str>,
    ) -> Result<BindingRecord> {
        let binding = if let Some(binding) = self.instance_default_binding().await? {
            if binding.kind != kind
                || binding.local_root_path.as_deref() != local_root_path
                || binding.object_bucket.as_deref() != object_bucket
            {
                bail!("instance-default binding disagrees with deployment storage");
            }
            binding
        } else {
            let created = self
                .create_topology_binding(
                    None,
                    "instance-default",
                    "instance",
                    "default",
                    kind,
                    local_root_path,
                    object_bucket,
                    (kind == "deployment_r2").then_some(""),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
                .await;
            match created {
                Ok(_) => {}
                Err(_error) if self.instance_default_binding().await?.is_some() => {}
                Err(error) => return Err(error),
            }
            self.instance_default_binding()
                .await?
                .context("instance-default binding disappeared after provisioning")?
        };
        self.ensure_deployment_owned_write_revision(&binding)
            .await?;
        Ok(binding)
    }

    /// Look up a binding by `(org_id, name)`.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn binding_by_name(&self, org_id: i64, name: &str) -> Result<Option<BindingRecord>> {
        self.backend
            .query_opt(
                "SELECT id, org_id, name, kind, is_instance_default, stable_id, owner_scope_key,
                 local_root_path, object_bucket, object_prefix, endpoint_scheme,
                 endpoint_host_kind, endpoint_host_bytes, endpoint_port,
                 signing_region, access_mode, resource_version, created_at, updated_at
                 FROM bindings WHERE org_id = ?1 AND name = ?2",
                &vals![org_id, name],
            )
            .await
            .context("loading binding by name")?
            .map(|row| row_to_binding(&row))
            .transpose()
    }

    /// Returns live topology references that prevent storage-binding deletion.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn binding_delete_blockers(&self, id: i64) -> Result<Vec<String>> {
        let checks = [
            (
                "placements",
                "SELECT COUNT(*) FROM surface_placements WHERE binding_id = ?1",
            ),
            (
                "gateways",
                "SELECT COUNT(*) FROM gateway_revisions WHERE binding_id = ?1",
            ),
            (
                "topology defaults",
                "SELECT COUNT(*) FROM topology_defaults WHERE binding_id = ?1",
            ),
            (
                "active consumer grants",
                "SELECT COUNT(*) FROM binding_consumer_scopes WHERE binding_id = ?1 AND state = 'active' AND grant_kind <> 'owner'",
            ),
        ];
        let mut blockers = Vec::new();
        for (label, sql) in checks {
            let count: i64 = self
                .backend
                .query_opt(sql, &vals![id])
                .await?
                .context("binding blocker count returned no row")?
                .get(0)?;
            if count > 0 {
                blockers.push(format!("{count} {label}"));
            }
        }
        Ok(blockers)
    }

    /// Deletes an unreferenced non-default binding under a resource-version CAS.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn delete_topology_binding(
        &self,
        id: i64,
        expected_resource_version: i64,
    ) -> Result<bool> {
        let exists = self
            .backend
            .query_opt(
                "SELECT 1 FROM bindings
                 WHERE id = ?1 AND resource_version = ?2 AND is_instance_default = 0",
                &vals![id, expected_resource_version],
            )
            .await?
            .is_some();
        if !exists {
            return Ok(false);
        }

        // Credential heads and write-state rows use restrictive composite foreign keys so
        // deleting the binding cannot rely on cascades alone. Keep the blocker CAS and the
        // dependent-row teardown in one transaction to avoid partially deleting live state.
        self.backend
            .checked_batch(&[
                Statement::new(
                    "UPDATE bindings SET resource_version = resource_version
                     WHERE id = ?1 AND resource_version = ?2 AND is_instance_default = 0
                       AND NOT EXISTS (SELECT 1 FROM surface_placements WHERE binding_id = ?1)
                       AND NOT EXISTS (SELECT 1 FROM gateway_revisions WHERE binding_id = ?1)",
                    vals![id, expected_resource_version],
                )
                .expecting(1),
                Statement::new(
                    "DELETE FROM binding_write_state WHERE binding_id = ?1",
                    vals![id],
                )
                .unchecked(),
                Statement::new(
                    "DELETE FROM binding_write_revisions WHERE binding_id = ?1",
                    vals![id],
                )
                .unchecked(),
                Statement::new(
                    "DELETE FROM binding_credential_heads WHERE binding_id = ?1",
                    vals![id],
                )
                .unchecked(),
                Statement::new(
                    "DELETE FROM binding_credential_revisions WHERE binding_id = ?1",
                    vals![id],
                )
                .unchecked(),
                Statement::new(
                    "DELETE FROM binding_scope_grant_pins WHERE binding_id = ?1",
                    vals![id],
                )
                .unchecked(),
                Statement::new(
                    "DELETE FROM binding_consumer_scopes WHERE binding_id = ?1",
                    vals![id],
                )
                .unchecked(),
                Statement::new(
                    "DELETE FROM bindings WHERE id = ?1 AND resource_version = ?2",
                    vals![id, expected_resource_version],
                )
                .expecting(1),
            ])
            .await?;
        Ok(true)
    }
}
