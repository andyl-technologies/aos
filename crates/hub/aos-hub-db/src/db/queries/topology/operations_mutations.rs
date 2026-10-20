//! Operations mutations in the topology capability.

use super::*;

impl Database {
    /// Stores an immutable, expiring semantic topology plan.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed JSON, non-future expiry, duplicate id,
    /// or database failure.
    pub async fn create_topology_plan(
        &self,
        input: &NewTopologyPlan,
    ) -> Result<TopologyPlanRecord> {
        use sha2::Digest as _;

        validate_key_bytes(&input.plan_id, "topology plan id", 64)?;
        validate_key_bytes(&input.plan_kind, "topology plan kind", 64)?;
        validate_key_bytes(&input.actor_kind, "topology plan actor kind", 32)?;
        if !matches!(
            input.actor_kind.as_str(),
            "user" | "service_account" | "key" | "system"
        ) {
            bail!("invalid topology plan actor kind '{}'", input.actor_kind);
        }
        validate_key_bytes(&input.scope, "topology plan scope", 255)?;
        if let Some(hash) = input.confirmation_hash.as_deref() {
            validate_key_bytes(hash, "confirmation hash", 128)?;
        }
        if let Some(key) = input.request_idempotency_key.as_deref() {
            validate_key_bytes(key, "plan idempotency key", 128)?;
        }
        validate_json_value(&input.input_versions_json, "plan input versions")?;
        validate_json_value(&input.effects_json, "plan effects")?;
        validate_json_value(&input.warnings_json, "plan warnings")?;
        let now = unix_now();
        if input.expires_at <= now {
            bail!("topology plan expiry must be in the future");
        }
        let request_digest =
            hex::encode(sha2::Sha256::digest(input.input_versions_json.as_bytes()));
        if let Some(key) = input.request_idempotency_key.as_deref() {
            let rows = self
                .backend
                .query(
                    &format!(
                        "SELECT {PLAN_COLUMNS} FROM topology_plans
                         WHERE actor_kind = ?1 AND actor_id = ?2 AND plan_kind = ?3
                           AND request_idempotency_key = ?4"
                    ),
                    &vals![input.actor_kind, input.actor_id, input.plan_kind, key],
                )
                .await?;
            if let Some(existing) = rows.first().map(row_to_topology_plan).transpose()? {
                if existing.request_digest.as_deref() != Some(request_digest.as_str()) {
                    bail!("plan idempotency key was already used for different input");
                }
                return Ok(existing);
            }
        }
        let inserted = self
            .backend
            .execute(
                "INSERT INTO topology_plans (plan_id, plan_kind, actor_kind, actor_id,
                actor_label, scope, input_versions_json, effects_json, warnings_json,
                confirmation_hash, request_idempotency_key, request_digest,
                created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                &vals![
                    input.plan_id,
                    input.plan_kind,
                    input.actor_kind,
                    input.actor_id,
                    input.actor_label,
                    input.scope,
                    input.input_versions_json,
                    input.effects_json,
                    input.warnings_json,
                    input.confirmation_hash,
                    input.request_idempotency_key,
                    request_digest,
                    now,
                    input.expires_at
                ],
            )
            .await;
        if let Err(insert_error) = inserted {
            if let Some(key) = input.request_idempotency_key.as_deref() {
                let rows = self
                    .backend
                    .query(
                        &format!(
                            "SELECT {PLAN_COLUMNS} FROM topology_plans
                             WHERE actor_kind = ?1 AND actor_id = ?2 AND plan_kind = ?3
                               AND request_idempotency_key = ?4"
                        ),
                        &vals![input.actor_kind, input.actor_id, input.plan_kind, key],
                    )
                    .await?;
                if let Some(existing) = rows.first().map(row_to_topology_plan).transpose()? {
                    if existing.request_digest.as_deref() == Some(request_digest.as_str()) {
                        return Ok(existing);
                    }
                    bail!("plan idempotency key was concurrently used for different input");
                }
            }
            return Err(insert_error);
        }
        self.topology_plan(&input.plan_id)
            .await?
            .context("created topology plan disappeared")
    }

    /// Returns a topology plan by opaque id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn topology_plan(&self, plan_id: &str) -> Result<Option<TopologyPlanRecord>> {
        let rows = self
            .backend
            .query(
                &format!("SELECT {PLAN_COLUMNS} FROM topology_plans WHERE plan_id = ?1"),
                &vals![plan_id],
            )
            .await?;
        rows.first().map(row_to_topology_plan).transpose()
    }

    /// Returns the plan bound to one actor, operation, and request idempotency key.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid key material or database failure.
    pub async fn topology_plan_for_request(
        &self,
        actor_kind: &str,
        actor_id: Option<i64>,
        plan_kind: &str,
        idempotency_key: &str,
    ) -> Result<Option<TopologyPlanRecord>> {
        validate_key_bytes(actor_kind, "topology plan actor kind", 32)?;
        validate_key_bytes(plan_kind, "topology plan kind", 64)?;
        validate_key_bytes(idempotency_key, "plan idempotency key", 128)?;
        let rows = self
            .backend
            .query(
                &format!(
                    "SELECT {PLAN_COLUMNS} FROM topology_plans
                      WHERE actor_kind = ?1 AND actor_id = ?2 AND plan_kind = ?3
                        AND request_idempotency_key = ?4"
                ),
                &vals![actor_kind, actor_id, plan_kind, idempotency_key],
            )
            .await?;
        rows.first().map(row_to_topology_plan).transpose()
    }

    /// Marks an unapplied topology plan as consumed.
    ///
    /// The guarded domain mutation remains the authoritative replay fence. A
    /// Callers may mark an expired plan only after proving that its exact
    /// intended mutation already happened. Expiration is checked before a new
    /// mutation, while this method closes the recoverable mutation-to-mark gap.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure. A missing plan returns `false`.
    pub async fn mark_topology_plan_applied(&self, plan_id: &str, applied_at: i64) -> Result<bool> {
        let changed = self
            .backend
            .execute(
                "UPDATE topology_plans SET applied_at = ?2
                 WHERE plan_id = ?1 AND applied_at IS NULL",
                &vals![plan_id, applied_at],
            )
            .await?;
        if changed == 1 {
            return Ok(true);
        }
        Ok(self
            .topology_plan(plan_id)
            .await?
            .is_some_and(|plan| plan.applied_at.is_some()))
    }

    /// Atomically consumes a plan and records its replayable response.
    ///
    /// Repeating the same key and response is successful. Reusing the plan
    /// with another key or result is rejected, so an apply retry can never
    /// silently become a different mutation.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty key, malformed response JSON, a conflicting
    /// replay, an unknown plan, or database failure.
    pub async fn complete_topology_plan_apply(
        &self,
        plan_id: &str,
        idempotency_key: &str,
        result_json: &str,
        applied_at: i64,
    ) -> Result<()> {
        validate_key_bytes(idempotency_key, "apply idempotency key", 128)?;
        validate_json_value(result_json, "apply result")?;
        let changed = self
            .backend
            .execute(
                "UPDATE topology_plans SET applied_at = ?4,
                 apply_idempotency_key = ?2, apply_result_json = ?3
                 WHERE plan_id = ?1 AND applied_at IS NULL",
                &vals![plan_id, idempotency_key, result_json, applied_at],
            )
            .await?;
        if changed == 1 {
            return Ok(());
        }
        let current = self
            .topology_plan(plan_id)
            .await?
            .context("topology plan does not exist")?;
        if current.apply_idempotency_key.as_deref() == Some(idempotency_key)
            && current.apply_result_json.as_deref() == Some(result_json)
        {
            return Ok(());
        }
        bail!("topology plan was already applied with another idempotency key or result")
    }

    /// Durably reserves one plan for an idempotent apply attempt.
    ///
    /// The reservation is written before the domain mutation. A process that
    /// crashes after the mutation can therefore recognize the same retry and
    /// run operation-specific outcome recovery; another key is fenced out.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty key, unknown/consumed plan, conflicting
    /// reservation, or database failure.
    pub async fn begin_topology_plan_apply(
        &self,
        plan_id: &str,
        idempotency_key: &str,
    ) -> Result<()> {
        validate_key_bytes(idempotency_key, "apply idempotency key", 128)?;
        let changed = self
            .backend
            .execute(
                "UPDATE topology_plans SET apply_idempotency_key = ?2
                 WHERE plan_id = ?1 AND applied_at IS NULL
                   AND apply_idempotency_key IS NULL",
                &vals![plan_id, idempotency_key],
            )
            .await?;
        if changed == 1 {
            return Ok(());
        }
        let current = self
            .topology_plan(plan_id)
            .await?
            .context("topology plan does not exist")?;
        if current.applied_at.is_none()
            && current.apply_idempotency_key.as_deref() == Some(idempotency_key)
        {
            return Ok(());
        }
        bail!("topology plan is consumed or reserved by another idempotency key")
    }

    /// Creates a durable topology operation after validating its target tuple.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed detail, an incompatible surface and
    /// placement, a missing target, duplicate id, or database failure.
    pub async fn create_topology_operation(
        &self,
        input: &NewTopologyOperation,
    ) -> Result<TopologyOperationRecord> {
        validate_key_bytes(&input.operation_id, "topology operation id", 64)?;
        validate_key_bytes(&input.operation_kind, "topology operation kind", 64)?;
        validate_json_value(&input.detail_json, "operation detail")?;
        if input.progress_total.is_some_and(|total| total < 0) {
            bail!("operation progress total cannot be negative");
        }
        if input.targets.is_empty() {
            bail!("a topology operation requires at least one typed target");
        }
        let mut resolved = Vec::with_capacity(input.targets.len());
        for target in &input.targets {
            resolved.push(self.resolve_operation_target(target).await?);
        }
        let primary_targets = input
            .targets
            .iter()
            .enumerate()
            .filter(|(_, target)| target.role == "primary")
            .collect::<Vec<_>>();
        if primary_targets.len() != 1 {
            bail!("an operation requires exactly one primary target");
        }
        // Only the server-resolved owner of the single primary target controls
        // operation visibility. Source/destination evidence may legitimately
        // cross organization boundaries after the calling service authorizes
        // each resource independently.
        let primary_index = primary_targets[0].0;
        let primary_requested = &input.targets[primary_index];
        let authorization_scope_key = resolved[primary_index].3.clone();
        let primary_target_kind = resolved[primary_index].1.clone();
        let primary_target_stable_id = resolved[primary_index].2.clone();
        let identities = resolved
            .iter()
            .map(|(_, kind, stable_id, _)| (kind.as_str(), stable_id.as_str()))
            .collect::<std::collections::BTreeSet<_>>();
        if identities.len() != resolved.len() {
            bail!("an operation cannot repeat the same target identity");
        }
        let now = unix_now();
        let mut statements = Vec::with_capacity(resolved.len() + 1);
        for ((target, _, _, _), requested) in resolved.iter().zip(&input.targets) {
            let guard = match target {
                NewTopologyOperationTargetRef::Registry(id) => Some(Statement::new(
                    "UPDATE registries SET updated_at = updated_at WHERE id = ?1",
                    vals![id],
                )),
                NewTopologyOperationTargetRef::Placement(id) => Some(Statement::new(
                    "UPDATE surface_placements SET updated_at = updated_at
                     WHERE id = ?1 AND resource_version = ?2",
                    vals![id, requested.generation_key],
                )),
                NewTopologyOperationTargetRef::Route(id) => Some(Statement::new(
                    "UPDATE routes SET updated_at = updated_at
                     WHERE id = ?1 AND EXISTS (
                       SELECT 1 FROM route_heads
                       WHERE route_id = ?1
                         AND configuration_generation = ?2
                         AND configuration_digest = ?3)",
                    vals![id, requested.generation_key, requested.configuration_digest],
                )),
                _ => None,
            };
            if let Some(guard) = guard {
                // Registry deletion locks the same owned rows before it
                // cancels operations. This makes admission and teardown
                // mutually exclusive on every supported SQL backend.
                statements.push(guard.expecting(1));
            }
        }
        statements.push(
            Statement::new(
                "INSERT INTO topology_operations (operation_id, operation_kind,
                authorization_scope_key, control_permission, primary_target_kind,
                primary_target_stable_id, primary_target_generation_key,
                primary_target_configuration_digest, state, progress_total,
                detail_json, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'pending', ?9, ?10, ?11)",
                vals![
                    input.operation_id,
                    input.operation_kind,
                    authorization_scope_key,
                    input.control_permission.as_str(),
                    primary_target_kind,
                    primary_target_stable_id,
                    primary_requested.generation_key,
                    primary_requested.configuration_digest,
                    input.progress_total,
                    input.detail_json,
                    now
                ],
            )
            .expecting(1),
        );
        for ((target, target_kind, stable_id, target_scope), requested) in
            resolved.into_iter().zip(&input.targets)
        {
            let (table, predicate, guard) = match &target {
                NewTopologyOperationTargetRef::Registry(id) => ("registries", "id = ?7", vals![id]),
                NewTopologyOperationTargetRef::BinaryCache(id) => {
                    ("binary_caches", "id = ?7", vals![id])
                }
                NewTopologyOperationTargetRef::Placement(id) => (
                    "surface_placements",
                    "id = ?7 AND resource_version = ?8",
                    vals![id, requested.generation_key],
                ),
                NewTopologyOperationTargetRef::Domain(id) => (
                    "domains",
                    "stable_id = ?7 AND resource_version = ?8",
                    vals![id, requested.generation_key],
                ),
                NewTopologyOperationTargetRef::NetworkPolicy(id) => (
                    "network_policy_revisions",
                    "boundary_id = ?7 AND revision = ?8 AND content_digest = ?9",
                    vals![id, requested.generation_key, requested.configuration_digest],
                ),
                NewTopologyOperationTargetRef::Endpoint(id) => (
                    "endpoint_revisions",
                    "endpoint_id = ?7 AND generation = ?8 AND content_digest = ?9",
                    vals![id, requested.generation_key, requested.configuration_digest],
                ),
                NewTopologyOperationTargetRef::Gateway(id) => (
                    "gateway_revisions",
                    "gateway_id = ?7 AND generation = ?8 AND content_digest = ?9",
                    vals![id, requested.generation_key, requested.configuration_digest],
                ),
                NewTopologyOperationTargetRef::Route(id) => (
                    "route_heads",
                    "route_id = ?7 AND configuration_generation = ?8
                         AND configuration_digest = ?9",
                    vals![id, requested.generation_key, requested.configuration_digest],
                ),
                NewTopologyOperationTargetRef::Binding(id) => (
                    "bindings",
                    "id = ?7 AND resource_version = ?8",
                    vals![id, requested.generation_key],
                ),
            };
            let mut params = vals![
                input.operation_id,
                requested.role,
                target_kind,
                stable_id,
                requested.generation_key,
                requested.configuration_digest
            ];
            params.extend(guard);
            if requested.role == "primary" {
                statements.push(
                    Statement::new(
                        format!(
                            "UPDATE topology_operations
                             SET resource_version = resource_version
                             WHERE operation_id = ?1
                               AND EXISTS (SELECT 1 FROM {table} WHERE {predicate})"
                        ),
                        params,
                    )
                    .expecting(1),
                );
                continue;
            }
            let scope_parameter = params.len() + 1;
            let control_parameter = params.len() + 2;
            params.push(crate::value::ToValue::to_value(&target_scope));
            params.push(crate::value::ToValue::to_value(
                &operation_target_control_permission(&target_kind, input.control_permission)
                    .as_str(),
            ));
            statements.push(
                Statement::new(
                    format!(
                        "INSERT INTO operation_secondary_targets (operation_id, role, target_kind,
                         stable_id, authorization_scope_key, control_permission,
                         generation_key, configuration_digest)
                         SELECT ?1, ?2, ?3, ?4, ?{scope_parameter}, ?{control_parameter}, ?5, ?6
                         WHERE EXISTS (SELECT 1 FROM {table} WHERE {predicate})"
                    ),
                    params,
                )
                .expecting(1),
            );
        }
        self.backend.checked_batch(&statements).await?;
        self.topology_operation(&input.operation_id)
            .await?
            .context("created topology operation disappeared")
    }

    /// Returns a topology operation by opaque id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn topology_operation(
        &self,
        operation_id: &str,
    ) -> Result<Option<TopologyOperationRecord>> {
        let rows = self
            .backend
            .query(
                &format!(
                    "SELECT {OPERATION_COLUMNS} FROM topology_operations WHERE operation_id = ?1"
                ),
                &vals![operation_id],
            )
            .await?;
        rows.first().map(row_to_topology_operation).transpose()
    }

    /// Resolves one live operation-inventory target to its authorization scope.
    ///
    /// Resolution uses the target's system-of-record table, never operation
    /// history, so callers can authorize before querying whether operations
    /// exist for the target.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown target kind, malformed target identity,
    /// or database failure.
    pub async fn topology_operation_target_scope(
        &self,
        target_kind: &str,
        stable_id: &str,
    ) -> Result<Option<String>> {
        validate_key_bytes(stable_id, "operation target stable id", 255)?;
        if target_kind == "placement" {
            let (surface, name) = stable_id
                .rsplit_once("/placement:")
                .context("malformed placement operation target")?;
            let (surface_kind, _) = surface
                .split_once(':')
                .context("malformed placement operation surface")?;
            let (join, predicate) = match surface_kind {
                "registry" => (
                    "JOIN registries s ON s.id = p.registry_id",
                    "s.stable_id = ?1",
                ),
                "cache" => (
                    "JOIN binary_caches s ON s.id = p.cache_id",
                    "s.stable_id = ?1",
                ),
                _ => bail!("unknown placement operation surface kind"),
            };
            return self
                .backend
                .query_opt(
                    &format!(
                        "SELECT s.scope_key
                           FROM surface_placements p {join}
                          WHERE {predicate} AND p.name = ?2"
                    ),
                    &vals![surface, name],
                )
                .await?
                .map(|row| row.get(0))
                .transpose();
        }
        let sql = match target_kind {
            "registry" => "SELECT scope_key FROM registries WHERE stable_id = ?1",
            "binary_cache" => "SELECT scope_key FROM binary_caches WHERE stable_id = ?1",
            "domain" => "SELECT owner_scope_key FROM domains WHERE stable_id = ?1",
            "network_policy" => "SELECT owner_scope_key FROM network_policies WHERE id = ?1",
            "endpoint" => "SELECT owner_scope_key FROM endpoints WHERE id = ?1",
            "gateway" => "SELECT owner_scope_key FROM gateways WHERE id = ?1",
            "binding" => "SELECT owner_scope_key FROM bindings WHERE stable_id = ?1",
            "route" => {
                "SELECT endpoint.owner_scope_key FROM routes route
                   JOIN endpoints endpoint ON endpoint.id = route.endpoint_id
                  WHERE route.id = ?1"
            }
            "placement_policy" => {
                "SELECT COALESCE(registry.scope_key, cache.scope_key)
                   FROM placement_policies policy
                   LEFT JOIN registries registry ON registry.id = policy.registry_id
                   LEFT JOIN binary_caches cache ON cache.id = policy.cache_id
                  WHERE policy.id = ?1"
            }
            "retention_subscription" => {
                return self
                    .numeric_operation_target_scope("cache_retention_subscriptions", stable_id)
                    .await;
            }
            "population_target" => {
                return self
                    .numeric_operation_target_scope("cache_population_targets", stable_id)
                    .await;
            }
            "cache_gc_generation" => {
                "SELECT cache.scope_key
                   FROM cache_gc_generations generation
                   JOIN binary_caches cache ON cache.id = generation.cache_id
                  WHERE generation.generation_id = ?1"
            }
            other => bail!("unknown operation target kind '{other}'"),
        };
        self.backend
            .query_opt(sql, &vals![stable_id])
            .await?
            .map(|row| row.get(0))
            .transpose()
    }

    /// Lists the immutable target snapshot for an operation.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn topology_operation_targets(
        &self,
        operation_id: &str,
    ) -> Result<Vec<TopologyOperationTargetRecord>> {
        let Some(operation) = self.topology_operation(operation_id).await? else {
            return Ok(Vec::new());
        };
        let mut targets = vec![TopologyOperationTargetRecord {
            operation_id: operation.operation_id.clone(),
            role: "primary".to_string(),
            target_kind: operation.primary_target_kind,
            stable_id: operation.primary_target_stable_id,
            authorization_scope_key: operation.authorization_scope_key,
            control_permission: aos_hub_model::auth::permission_from_str(
                &operation.control_permission,
            )
            .context("operation has an invalid primary control permission")?,
            generation_key: operation.primary_target_generation_key,
            configuration_digest: operation.primary_target_configuration_digest,
        }];
        let mut secondary = self
            .backend
            .query(
                "SELECT operation_id, role, target_kind, stable_id, authorization_scope_key,
             control_permission, generation_key, configuration_digest
             FROM operation_secondary_targets WHERE operation_id = ?1
             ORDER BY role, target_kind, stable_id, generation_key",
                &vals![operation_id],
            )
            .await?
            .iter()
            .map(|row| {
                Ok(TopologyOperationTargetRecord {
                    operation_id: row.get(0)?,
                    role: row.get(1)?,
                    target_kind: row.get(2)?,
                    stable_id: row.get(3)?,
                    authorization_scope_key: row.get(4)?,
                    control_permission: aos_hub_model::auth::permission_from_str(
                        &row.get::<String>(5)?,
                    )
                    .context("operation has an invalid secondary control permission")?,
                    generation_key: row.get(6)?,
                    configuration_digest: row.get(7)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        targets.append(&mut secondary);
        Ok(targets)
    }

    /// Advances an operation with optimistic concurrency.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid state, malformed detail, a stale
    /// version, missing operation, or database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_topology_operation(
        &self,
        operation_id: &str,
        expected_version: i64,
        state: &str,
        progress_current: i64,
        progress_total: Option<i64>,
        detail_json: &str,
        error: Option<&str>,
        started_at: Option<i64>,
        finished_at: Option<i64>,
    ) -> Result<TopologyOperationRecord> {
        if !matches!(state, "running" | "succeeded" | "failed" | "cancelled") {
            bail!("invalid topology-operation state '{state}'");
        }
        validate_json_value(detail_json, "operation detail")?;
        if progress_current < 0 || progress_total.is_some_and(|total| total < progress_current) {
            bail!("operation progress must be non-negative and cannot exceed its total");
        }
        match state {
            "running" if started_at.is_none() || finished_at.is_some() || error.is_some() => {
                bail!("a running operation requires started_at and no finish/error")
            }
            "succeeded" if started_at.is_none() || finished_at.is_none() || error.is_some() => {
                bail!("a succeeded operation requires start/finish times and no error")
            }
            "failed" if started_at.is_none() || finished_at.is_none() || error.is_none() => {
                bail!("a failed operation requires start/finish times and an error")
            }
            "cancelled" if started_at.is_none() || finished_at.is_none() => {
                bail!("a cancelled operation requires start/finish times")
            }
            _ => {}
        }
        if finished_at
            .zip(started_at)
            .is_some_and(|(finish, start)| finish < start)
        {
            bail!("operation finish time cannot precede its start time");
        }
        let affected = self
            .backend
            .execute(
                "UPDATE topology_operations SET state = ?3, progress_current = ?4,
                progress_total = COALESCE(?5, progress_total), detail_json = ?6, error = ?7,
                started_at = ?8, finished_at = ?9,
                resource_version = resource_version + 1
             WHERE operation_id = ?1 AND resource_version = ?2
               AND progress_current <= ?4
               AND (progress_total IS NULL OR ?5 IS NULL OR progress_total = ?5)
               AND (?3 <> 'succeeded' OR COALESCE(?5, progress_total) IS NULL
                    OR ?4 = COALESCE(?5, progress_total))
               AND ((state = 'pending' AND ?3 IN ('running', 'cancelled'))
                 OR (state = 'running' AND ?3 IN ('succeeded', 'failed', 'cancelled'))) ",
                &vals![
                    operation_id,
                    expected_version,
                    state,
                    progress_current,
                    progress_total,
                    detail_json,
                    error,
                    started_at,
                    finished_at
                ],
            )
            .await?;
        if affected != 1 {
            bail!("topology operation is missing or its resource version is stale");
        }
        self.topology_operation(operation_id)
            .await?
            .context("updated topology operation disappeared")
    }

    /// Applies an idempotent caller-requested operation transition.
    ///
    /// The mutation key is persisted in the same transaction as the state CAS.
    /// Replaying the same request returns the recorded result; reusing a key for
    /// another mutation or expected version is rejected.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid key, mutation, state transition, stale
    /// resource version, conflicting replay, or database failure.
    pub async fn mutate_topology_operation(
        &self,
        operation_id: &str,
        expected_version: i64,
        mutation_kind: &str,
        idempotency_key: &str,
    ) -> Result<TopologyOperationRecord> {
        validate_key_bytes(idempotency_key, "operation mutation idempotency key", 128)?;
        let (from_states, next_state, finished_at) = match mutation_kind {
            "cancel" => ("'pending', 'running'", "cancelled", Some(unix_now())),
            // A retry is re-queued rather than marked running. Only a controller
            // claim may establish the running lease and its fencing version.
            "retry" => ("'failed', 'cancelled'", "pending", None),
            other => bail!("invalid topology-operation mutation '{other}'"),
        };
        if expected_version <= 0 {
            bail!("operation resource version must be positive");
        }
        if let Some(row) = self
            .backend
            .query_opt(
                "SELECT mutation_kind, expected_resource_version,
                        resulting_resource_version
                   FROM topology_operation_mutations
                  WHERE operation_id = ?1 AND idempotency_key = ?2",
                &vals![operation_id, idempotency_key],
            )
            .await?
        {
            let recorded_kind: String = row.get(0)?;
            let recorded_expected: i64 = row.get(1)?;
            let resulting_version: i64 = row.get(2)?;
            if recorded_kind != mutation_kind || recorded_expected != expected_version {
                bail!("operation idempotency key was used for another mutation");
            }
            let operation = self
                .topology_operation(operation_id)
                .await?
                .context("mutated topology operation disappeared")?;
            if operation.resource_version < resulting_version {
                bail!("operation mutation result is not yet visible");
            }
            return Ok(operation);
        }

        let now = unix_now();
        let transition = format!(
            "UPDATE topology_operations
                SET state = ?3,
                    started_at = CASE WHEN ?3 = 'pending' THEN NULL ELSE COALESCE(started_at, ?4) END,
                    finished_at = ?5,
                    error = CASE WHEN ?3 = 'pending' THEN NULL ELSE error END,
                    progress_current = CASE WHEN ?3 = 'pending' THEN 0 ELSE progress_current END,
                    resource_version = resource_version + 1
              WHERE operation_id = ?1 AND resource_version = ?2
                AND state IN ({from_states})"
        );
        let result = self
            .backend
            .checked_batch(&[
                Statement::new(
                    transition,
                    vals![operation_id, expected_version, next_state, now, finished_at],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO topology_operation_mutations
                     (operation_id, idempotency_key, mutation_kind,
                      expected_resource_version, resulting_resource_version, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    vals![
                        operation_id,
                        idempotency_key,
                        mutation_kind,
                        expected_version,
                        expected_version + 1,
                        now
                    ],
                )
                .expecting(1),
            ])
            .await;
        if result.is_err() {
            if let Some(row) = self
                .backend
                .query_opt(
                    "SELECT mutation_kind, expected_resource_version
                       FROM topology_operation_mutations
                      WHERE operation_id = ?1 AND idempotency_key = ?2",
                    &vals![operation_id, idempotency_key],
                )
                .await?
            {
                let recorded_kind: String = row.get(0)?;
                let recorded_expected: i64 = row.get(1)?;
                if recorded_kind == mutation_kind && recorded_expected == expected_version {
                    return self
                        .topology_operation(operation_id)
                        .await?
                        .context("mutated topology operation disappeared");
                }
                bail!("operation idempotency key was concurrently reused");
            }
            result?;
        }
        self.topology_operation(operation_id)
            .await?
            .context("mutated topology operation disappeared")
    }

    /// Returns creation defaults using only stable public resource identities.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn stable_topology_defaults(
        &self,
        scope_key: &str,
    ) -> Result<Option<StableTopologyDefaultsRecord>> {
        self.backend
            .query_opt(
                "SELECT defaults.scope_key, binding.stable_id, domain.stable_id,
                   defaults.endpoint_id, defaults.endpoint_generation,
                   defaults.gateway_id, defaults.gateway_generation,
                   defaults.resource_version
                 FROM topology_defaults defaults
                 LEFT JOIN bindings binding
                   ON binding.id = defaults.binding_id
                 LEFT JOIN domains domain ON domain.id = defaults.domain_id
                 WHERE defaults.scope_key = ?1",
                &vals![scope_key],
            )
            .await?
            .map(|row| {
                Ok(StableTopologyDefaultsRecord {
                    scope_key: row.get(0)?,
                    binding_id: row.get(1)?,
                    domain_id: row.get(2)?,
                    endpoint_id: row.get(3)?,
                    endpoint_generation: row.get(4)?,
                    gateway_id: row.get(5)?,
                    gateway_generation: row.get(6)?,
                    resource_version: row.get(7)?,
                })
            })
            .transpose()
    }

    /// Creates or replaces topology defaults under an exact resource-version CAS.
    ///
    /// Every optional resource is checked at the write boundary against the
    /// target scope and, for revisioned resources, its exact active consumer
    /// grant. Stable API identities are resolved to internal foreign keys only
    /// inside this persistence boundary.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid scope shape, unpaired revision identity,
    /// missing or inaccessible references, a stale version, or database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn set_stable_topology_defaults(
        &self,
        scope_kind: &str,
        org_id: Option<i64>,
        scope_key: &str,
        binding_stable_id: Option<&str>,
        domain_stable_id: Option<&str>,
        endpoint_id: Option<&str>,
        endpoint_generation: Option<i64>,
        gateway_id: Option<&str>,
        gateway_generation: Option<i64>,
        expected_resource_version: Option<i64>,
    ) -> Result<StableTopologyDefaultsRecord> {
        let valid_scope_shape = match (scope_kind, org_id) {
            ("instance", None) => scope_key == "instance",
            ("organization", Some(_)) => {
                aos_hub_model::domain::Scope::is_canonical(scope_key)
                    && scope_key.starts_with("org:")
            }
            _ => false,
        };
        if !valid_scope_shape {
            bail!("topology defaults have an invalid scope shape");
        }
        if endpoint_id.is_some() != endpoint_generation.is_some()
            || gateway_id.is_some() != gateway_generation.is_some()
            || endpoint_generation.is_some_and(|generation| generation <= 0)
            || gateway_generation.is_some_and(|generation| generation <= 0)
        {
            bail!("topology defaults require paired positive resource generations");
        }

        let binding_id = match binding_stable_id {
            Some(stable_id) => Some(
                self.binding_by_stable_id(stable_id)
                    .await?
                    .context("topology-default binding does not exist")?
                    .id,
            ),
            None => None,
        };
        let domain_id = match domain_stable_id {
            Some(stable_id) => Some(
                self.delivery_domain(stable_id)
                    .await?
                    .context("topology-default domain does not exist")?
                    .id,
            ),
            None => None,
        };
        let now = unix_now();
        let scope_identity_guard = if org_id.is_some() {
            "scope.org_id = ?2"
        } else {
            "scope.org_id IS NULL"
        };
        let defaults_identity_guard = if org_id.is_some() {
            "org_id = ?2"
        } else {
            "org_id IS NULL"
        };
        let guard = format!(
            "EXISTS (SELECT 1 FROM authorization_scopes scope
                       LEFT JOIN orgs org ON org.id = scope.org_id
                       WHERE scope.scope_key = ?3 AND scope.retired_at IS NULL
                         AND {scope_identity_guard}
                         AND (scope.org_id IS NULL OR org.deleted_at IS NULL))
                   AND (?4 IS NULL OR EXISTS (
                     SELECT 1 FROM binding_consumer_scopes grant_row
                      WHERE grant_row.binding_id = ?4
                        AND grant_row.consumer_scope_key = ?3
                        AND grant_row.state = 'active'))
                   AND (?5 IS NULL OR EXISTS (
                     SELECT 1 FROM domains domain
                      WHERE domain.id = ?5 AND domain.owner_scope_key = ?3))
                   AND (?6 IS NULL OR EXISTS (
                     SELECT 1 FROM endpoint_route_scopes grant_row
                      WHERE grant_row.endpoint_id = ?6
                        AND grant_row.endpoint_generation = ?7
                        AND grant_row.consumer_scope_key = ?3
                        AND grant_row.state = 'active'))
                   AND (?8 IS NULL OR EXISTS (
                     SELECT 1 FROM gateway_revision_route_scopes grant_row
                      WHERE grant_row.gateway_id = ?8 AND grant_row.generation = ?9
                        AND grant_row.consumer_scope_key = ?3
                        AND grant_row.state = 'active'))"
        );
        let values = vals![
            scope_kind,
            org_id,
            scope_key,
            binding_id,
            domain_id,
            endpoint_id,
            endpoint_generation,
            gateway_id,
            gateway_generation,
            now,
            expected_resource_version
        ];
        let affected = if expected_resource_version.is_some() {
            self.backend
                .execute(
                    &format!(
                        "UPDATE topology_defaults
                         SET binding_id = ?4, domain_id = ?5,
                             endpoint_id = ?6,
                             endpoint_generation = ?7,
                             gateway_id = ?8,
                             gateway_generation = ?9,
                             resource_version = resource_version + 1, updated_at = ?10
                         WHERE scope_kind = ?1 AND {defaults_identity_guard} AND scope_key = ?3
                           AND resource_version = ?11 AND {guard}"
                    ),
                    &values,
                )
                .await?
        } else {
            self.backend
                .execute(
                    &format!(
                        "INSERT INTO topology_defaults
                         (scope_kind, org_id, scope_key, binding_id, domain_id,
                          endpoint_id, endpoint_generation,
                          gateway_id, gateway_generation,
                          resource_version, created_at, updated_at)
                         SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1, ?10, ?10
                         WHERE {guard}"
                    ),
                    &values,
                )
                .await?
        };
        if affected != 1 {
            bail!(
                "topology defaults are missing, stale, duplicated, or reference inaccessible resources"
            );
        }
        self.stable_topology_defaults(scope_key)
            .await?
            .context("topology defaults disappeared after write")
    }

    /// Seeds one actor-attributed topology event for cross-backend fixtures.
    #[cfg(any(test, debug_assertions, feature = "do-e2e-test-support"))]
    pub async fn seed_topology_event_for_test(
        &self,
        event_name: &str,
        owner_scope_key: &str,
        resource_kind: &str,
        resource_stable_id: &str,
    ) -> Result<String> {
        let event_id = uuid::Uuid::new_v4().simple().to_string();
        let payload = serde_json::to_string(&serde_json::json!({
            "resourceStableId": resource_stable_id,
        }))?;
        self.backend
            .checked_batch(&[Self::topology_event_statement(&NewTopologyEvent {
                event_id: &event_id,
                event_name,
                owner_scope_key,
                resource_kind,
                resource_stable_id,
                resource_generation_key: 1,
                actor_kind: "system",
                actor_id: None,
                actor_label: "dialect fixture",
                payload_json: &payload,
                occurred_at: unix_now(),
            })])
            .await?;
        Ok(event_id)
    }

    /// Materializes pending topology events into deduplicated audit and webhook rows.
    ///
    /// Each event is materialized in one checked transaction. The immutable
    /// outbox row was inserted in the original domain mutation transaction;
    /// unique event links make retries safe after worker or process failure.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed persisted payload/subscription data or a
    /// database failure. A competing materializer may cause a checked-CAS error.
    pub async fn materialize_topology_events(&self) -> Result<usize> {
        Ok(self
            .materialize_topology_events_with_delivery_ids()
            .await?
            .0)
    }

    /// Materializes topology events and returns stable webhook delivery IDs.
    ///
    /// Queue producers may enqueue these IDs after the transaction commits;
    /// duplicate enqueue is safe because consumers claim the durable row.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::materialize_topology_events`].
    pub async fn materialize_topology_events_with_delivery_ids(
        &self,
    ) -> Result<(usize, Vec<String>)> {
        let rows = self
            .backend
            .query(
                "SELECT event.event_id, event.event_name, event.owner_scope_key,
                        scope.org_id, event.resource_kind,
                        event.resource_stable_id, event.resource_generation_key,
                        event.actor_kind, event.actor_id, event.actor_label,
                        event.payload_json, event.occurred_at
                   FROM topology_event_outbox event
                   JOIN authorization_scopes scope
                     ON scope.scope_key = event.owner_scope_key
                  WHERE event.materialized_at IS NULL
                  ORDER BY event.occurred_at, event.event_id LIMIT 10",
                &[],
            )
            .await?;
        let mut materialized = 0;
        let mut delivery_ids = Vec::new();
        for row in rows {
            let event = TopologyEventOutboxRecord {
                event_id: row.get(0)?,
                event_name: row.get(1)?,
                owner_scope_key: row.get(2)?,
                org_id: row.get(3)?,
                resource_kind: row.get(4)?,
                resource_stable_id: row.get(5)?,
                resource_generation_key: row.get(6)?,
                actor_kind: row.get(7)?,
                actor_id: row.get(8)?,
                actor_label: row.get(9)?,
                payload_json: row.get(10)?,
                occurred_at: row.get(11)?,
            };
            anyhow::ensure!(
                aos_hub_model::webhook::is_safe_event_header_value(&event.event_name)
                    && aos_hub_model::webhook::is_supported_event_type(&event.event_name),
                "topology event name is outside the webhook taxonomy"
            );
            validate_json_value(&event.payload_json, "topology event payload")?;
            anyhow::ensure!(
                event.payload_json.len() <= 1024 * 1024,
                "topology event payload exceeds webhook materialization limit"
            );
            let mut statements = vec![Statement::new(
                "INSERT INTO audit_log
                 (outbox_event_id, change_id, actor_kind, actor_id, actor_label,
                  action, scope, result_commit, result_tag, detail, created_at)
                 SELECT ?1, NULL, ?2, ?3, ?4, ?5, ?6, NULL, NULL, ?7, ?8
                  WHERE NOT EXISTS (SELECT 1 FROM audit_log WHERE outbox_event_id = ?1)",
                vals![
                    event.event_id,
                    event.actor_kind,
                    event.actor_id,
                    event.actor_label,
                    event.event_name,
                    event.owner_scope_key,
                    event.payload_json,
                    event.occurred_at
                ],
            )
            .unchecked()];
            if let Some(org_id) = event.org_id {
                for hook in self.list_webhooks(org_id).await? {
                    if hook.active && hook.subscribes_to(&event.event_name) {
                        let delivery_id = uuid::Uuid::new_v4().simple().to_string();
                        statements.push(
                            Statement::new(
                                "INSERT INTO webhook_deliveries
                                 (delivery_id, outbox_event_id, webhook_id, event, payload, status,
                                  attempts, created_at, next_attempt_at)
                                 SELECT ?6, ?1, ?2, ?3, ?4, 'pending', 0, ?5, ?5
                                  WHERE NOT EXISTS (SELECT 1 FROM webhook_deliveries
                                    WHERE webhook_id = ?2 AND outbox_event_id = ?1)",
                                vals![
                                    event.event_id,
                                    hook.id,
                                    event.event_name,
                                    event.payload_json,
                                    event.occurred_at,
                                    delivery_id.clone()
                                ],
                            )
                            .unchecked(),
                        );
                        delivery_ids.push(delivery_id);
                    }
                }
            }
            statements.push(
                Statement::new(
                    "UPDATE topology_event_outbox SET materialized_at = ?2
                     WHERE event_id = ?1 AND materialized_at IS NULL",
                    vals![event.event_id, unix_now()],
                )
                .expecting(1),
            );
            self.backend.checked_batch(&statements).await?;
            materialized += 1;
        }
        Ok((materialized, delivery_ids))
    }
}
