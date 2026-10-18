//! Retention helpers in the caches capability.

use super::*;

impl RpcService {
    pub(in crate::service) async fn require_retention_lease_authority(
        &self,
        auth: Option<&str>,
        cache: &aos_hub_db::db::BinaryCache,
        root: &aos_hub_db::db::ManualRetentionRootRecord,
    ) -> Result<Claims, RpcError> {
        let claims = self.require_claims(auth)?;
        let scope = Scope::parse(&cache.scope_key);
        if claims.owner_kind == "service_account"
            && root.owner_kind == claims.owner_kind
            && root.owner_id == claims.owner_id
            && self
                .require_permission(&claims, Permission::CacheLeaseSelf, &scope)
                .await
                .is_ok()
        {
            return Ok(claims);
        }
        self.require_permission(&claims, Permission::CacheRetentionManage, &scope)
            .await?;
        Ok(claims)
    }

    pub(in crate::service) async fn require_retention_root_creation_authority(
        &self,
        auth: Option<&str>,
        cache: &aos_hub_db::db::BinaryCache,
        leased: bool,
    ) -> Result<Claims, RpcError> {
        let claims = self.require_claims(auth)?;
        let scope = Scope::parse(&cache.scope_key);
        if leased
            && claims.owner_kind == "service_account"
            && self
                .require_permission(&claims, Permission::CacheLeaseSelf, &scope)
                .await
                .is_ok()
        {
            return Ok(claims);
        }
        self.require_permission(&claims, Permission::CacheRetentionManage, &scope)
            .await?;
        Ok(claims)
    }

    /// Materializes a retention refresh from verified registry snapshots.
    ///
    /// # Errors
    ///
    /// Returns an authorization, not-found, or database error.
    pub(in crate::service) async fn execute_refresh_retention_subscription(
        &self,
        auth: Option<&str>,
        req: pb::PlanRefreshRetentionSubscriptionRequest,
    ) -> Result<pb::OperationResponse, RpcError> {
        let (cache, registry) = self
            .authorized_cache_registry_retention_pair(auth, &req.cache_id, &req.registry_id, true)
            .await?;
        let subscription = self
            .db
            .cache_retention_subscription_topology(cache.id, registry.id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("retention subscription"))?;
        if parse_resource_version(
            &req.expected_resource_version,
            subscription.resource_version,
        )? != subscription.resource_version
        {
            return Err(RpcError::FailedPrecondition(
                "retention subscription resource version is stale".to_string(),
            ));
        }
        let started_at = clock::now_unix_secs();
        let operation = self
            .db
            .create_topology_operation(&aos_hub_db::db::NewTopologyOperation {
                operation_id: uuid::Uuid::new_v4().to_string(),
                operation_kind: "retention_refresh".to_string(),
                control_permission: Permission::CacheRetentionManage,
                targets: vec![
                    aos_hub_db::db::NewTopologyOperationTarget {
                        role: "primary".to_string(),
                        target: aos_hub_db::db::NewTopologyOperationTargetRef::BinaryCache(
                            cache.id,
                        ),
                        generation_key: 0,
                        configuration_digest: String::new(),
                    },
                    aos_hub_db::db::NewTopologyOperationTarget {
                        role: "source".to_string(),
                        target: aos_hub_db::db::NewTopologyOperationTargetRef::Registry(
                            registry.id,
                        ),
                        generation_key: 0,
                        configuration_digest: String::new(),
                    },
                ],
                progress_total: None,
                detail_json: serde_json::json!({ "registryId": registry.slug }).to_string(),
            })
            .await
            .map_err(RpcError::internal)?;
        let running = self
            .db
            .update_topology_operation(
                &operation.operation_id,
                operation.resource_version,
                "running",
                0,
                None,
                &operation.detail_json,
                None,
                Some(started_at),
                None,
            )
            .await
            .map_err(RpcError::internal)?;
        let result = self
            .materialize_retention_refresh(&subscription, registry.id)
            .await;
        let finished_at = clock::now_unix_secs();
        let (state, count, detail, error) = match result {
            Ok((refresh_id, count)) => (
                "succeeded",
                count,
                serde_json::json!({
                    "registryId": registry.slug,
                    "refreshId": refresh_id,
                    "reasonCount": count,
                })
                .to_string(),
                None,
            ),
            Err(error) => (
                "failed",
                0,
                serde_json::json!({ "registryId": registry.slug }).to_string(),
                Some(format!("{error:#}")),
            ),
        };
        let terminal = self
            .db
            .update_topology_operation(
                &operation.operation_id,
                running.resource_version,
                state,
                count,
                Some(count),
                &detail,
                error.as_deref(),
                Some(started_at),
                Some(finished_at),
            )
            .await
            .map_err(RpcError::internal)?;
        Ok(pb::OperationResponse {
            operation: Some(pb::OperationRef {
                operation_id: terminal.operation_id,
                kind: terminal.operation_kind,
                state: terminal.state,
                created_at: terminal.created_at,
            }),
        })
    }

    pub(in crate::service) async fn materialize_retention_refresh(
        &self,
        subscription: &aos_hub_db::db::CacheRetentionSubscriptionRecord,
        registry_id: i64,
    ) -> anyhow::Result<(String, i64)> {
        let index = self
            .db
            .index_status(registry_id)
            .await?
            .context("registry index is missing")?;
        if index.state != "fresh" {
            anyhow::bail!("registry index must be fresh before retention refresh");
        }
        let source_revision = index
            .last_indexed_commit
            .context("fresh registry index has no source revision")?;
        let index_digest = index
            .content_digest
            .context("fresh registry index has no immutable content digest")?;
        if index.generation <= 0 {
            anyhow::bail!("fresh registry index has no immutable generation");
        }
        let selector: pb::RetentionSelector = serde_json::from_str(&subscription.selector_json)?;
        let mut spec = pb::RetentionSubscriptionSpec {
            selector: Some(selector),
            removal_grace_seconds: subscription.removal_grace_secs,
        };
        Self::canonicalize_retention_spec(&mut spec)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let selector = spec.selector.context("canonical selector disappeared")?;
        let all_releases = self.db.list_releases(registry_id).await?;
        let complete = self
            .db
            .list_retention_release_snapshots(registry_id)
            .await?;
        let complete_by_tag = complete
            .iter()
            .map(|release| (release.tag.as_str(), release))
            .collect::<BTreeMap<_, _>>();
        let mut reasons = BTreeMap::new();

        if selector.current_catalog {
            for artifact in self
                .db
                .list_current_catalog_retention_artifacts(registry_id)
                .await?
            {
                insert_retention_reason(
                    &mut reasons,
                    "registry_catalog",
                    format!(
                        "catalog@{source_revision}:{}/{}/{}/{}",
                        artifact.package_name,
                        artifact.package_version,
                        artifact.platform,
                        artifact.artifact_kind
                    ),
                    artifact.store_hash,
                    None,
                    None,
                    None,
                    None,
                );
            }
        }

        if selector.all_releases {
            for release in &all_releases {
                let snapshot = complete_by_tag
                    .get(release.semver.as_str())
                    .with_context(|| {
                        format!(
                            "release '{}' has no complete verified artifact snapshot",
                            release.semver
                        )
                    })?;
                add_release_retention_reasons(&mut reasons, "all", snapshot);
            }
        }
        for tag in &selector.release_tags {
            let snapshot = complete_by_tag.get(tag.as_str()).with_context(|| {
                format!("release '{tag}' has no complete verified artifact snapshot")
            })?;
            add_release_retention_reasons(&mut reasons, "exact", snapshot);
        }
        if let Some(semver_selector) = selector.semver.as_ref() {
            let requirement = aos_hub_model::retention::RetentionSemverRequirement::parse(
                &semver_selector.requirement,
            )?;
            for release in &all_releases {
                let Ok(version) = aos_hub_model::retention::CanonicalSemver::parse(&release.semver)
                else {
                    continue;
                };
                if !requirement.matches(&version, semver_selector.include_prereleases) {
                    continue;
                }
                let snapshot = complete_by_tag
                    .get(release.semver.as_str())
                    .with_context(|| {
                        format!(
                        "SemVer-selected release '{}' has no complete verified artifact snapshot",
                        release.semver
                    )
                    })?;
                add_release_retention_reasons(&mut reasons, "semver", snapshot);
            }
        }
        if let Some(recent) = selector.recent_releases.as_ref() {
            let candidates = complete
                .iter()
                .filter_map(|release| {
                    Some(aos_hub_model::retention::VerifiedRelease {
                        release_id: u64::try_from(release.release_id).ok()?,
                        tag: release.tag.clone(),
                        verified_tag_oid: canonical_git_object_id(&release.verified_tag_oid)
                            .ok()?,
                        tagged_at: release.tagged_at?,
                        verified: true,
                        complete_artifact_snapshot: true,
                    })
                })
                .collect::<Vec<_>>();
            for selected in aos_hub_model::retention::select_recent_releases(
                &candidates,
                recent.count,
                recent.include_prereleases,
            )? {
                let snapshot = complete_by_tag
                    .get(selected.tag.as_str())
                    .context("recent release lost its complete snapshot")?;
                add_release_retention_reasons(&mut reasons, "recent", snapshot);
            }
        }

        if let Some(channel_selector) = selector.channel_targets.as_ref() {
            let channels = self.db.list_channels(registry_id).await?;
            let selected_names = if channel_selector.all {
                channels
                    .iter()
                    .map(|channel| channel.name.as_str())
                    .collect::<BTreeSet<_>>()
            } else {
                channel_selector
                    .names
                    .iter()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>()
            };
            for requested in &selected_names {
                if !channels.iter().any(|channel| channel.name == *requested) {
                    anyhow::bail!("channel '{requested}' does not exist");
                }
            }
            let partitions = self
                .db
                .list_retention_channel_partitions(registry_id)
                .await?;
            let complete_partitions = partitions
                .iter()
                .map(|partition| {
                    (
                        (partition.channel_name.as_str(), partition.bucket),
                        partition,
                    )
                })
                .collect::<BTreeMap<_, _>>();
            for channel in channels
                .iter()
                .filter(|channel| selected_names.contains(channel.name.as_str()))
            {
                for (bucket, tag) in channel.partitions.iter().enumerate() {
                    let Some(tag) = tag else { continue };
                    let bucket = i64::try_from(bucket)?;
                    let partition = complete_partitions
                        .get(&(channel.name.as_str(), bucket))
                        .with_context(|| {
                            format!(
                                "channel '{}' partition {bucket} targets release '{}' without a complete verified artifact snapshot",
                                channel.name, tag
                            )
                        })?;
                    for artifact in &partition.artifacts {
                        insert_retention_reason(
                            &mut reasons,
                            "channel",
                            format!(
                                "channel:{}:{bucket}:{}@{}:{}/{}/{}/{}",
                                channel.name,
                                partition.release_tag,
                                partition.snapshot_id,
                                artifact.package_name,
                                artifact.package_version,
                                artifact.platform,
                                artifact.artifact_kind
                            ),
                            artifact.store_hash.clone(),
                            Some(partition.release_id),
                            Some(partition.snapshot_id.clone()),
                            Some(partition.channel_id),
                            Some(bucket),
                        );
                    }
                }
            }
        }

        let reason_count = i64::try_from(reasons.len())?;
        let refresh_id = uuid::Uuid::new_v4().to_string();
        let now = clock::now_unix_secs();
        let state = self
            .db
            .cache_gc_topology_state(subscription.cache_id)
            .await?
            .context("cache GC state is missing")?;
        self.db
            .begin_retention_refresh_topology(&aos_hub_db::db::BeginRetentionRefresh {
                refresh_id: refresh_id.clone(),
                subscription_id: subscription.id,
                expected_subscription_version: subscription.resource_version,
                expected_cache_epoch: state.epoch,
                selector_digest: subscription.selector_digest.clone(),
                registry_source_revision: source_revision,
                registry_index_generation: index.generation,
                registry_index_digest: index_digest,
                expected_reason_count: reason_count,
                started_at: now,
            })
            .await?;
        for reason in reasons.values() {
            let mut reason = reason.clone();
            // Superseded refreshes remain immutable during their removal-grace
            // window, so the same logical reason must have a generation-local
            // row identity while retaining its stable reason key.
            reason.reason_id = retention_refresh_reason_id(&refresh_id, &reason.reason_key);
            reason.refreshed_at = now;
            if let Err(error) = self
                .db
                .stage_retention_refresh_reason_topology(&refresh_id, &reason)
                .await
            {
                let detail = format!("{error:#}");
                let _ = self
                    .db
                    .fail_retention_refresh_topology(&refresh_id, &detail, clock::now_unix_secs())
                    .await;
                return Err(error);
            }
        }
        if let Err(error) = self
            .db
            .complete_retention_refresh_topology(
                &refresh_id,
                &uuid::Uuid::new_v4().to_string(),
                clock::now_unix_secs(),
            )
            .await
        {
            let detail = format!("{error:#}");
            let _ = self
                .db
                .fail_retention_refresh_topology(&refresh_id, &detail, clock::now_unix_secs())
                .await;
            return Err(error);
        }
        Ok((refresh_id, reason_count))
    }

    pub(in crate::service) fn validate_retention_spec(
        spec: &pb::RetentionSubscriptionSpec,
    ) -> Result<(), RpcError> {
        if spec.removal_grace_seconds < 0 {
            return Err(RpcError::invalid("removal grace cannot be negative"));
        }
        let selector = spec
            .selector
            .as_ref()
            .ok_or_else(|| RpcError::invalid("selector is required"))?;
        let has_term = selector.current_catalog
            || selector.channel_targets.is_some()
            || selector.recent_releases.is_some()
            || !selector.release_tags.is_empty()
            || selector.semver.is_some()
            || selector.all_releases;
        if !has_term {
            return Err(RpcError::invalid(
                "retention selector requires at least one union term",
            ));
        }
        if let Some(channels) = selector.channel_targets.as_ref() {
            if channels.all == !channels.names.is_empty() {
                return Err(RpcError::invalid(
                    "channel targets require exactly one of all or names",
                ));
            }
            if channels.names.iter().any(|name| name.trim().is_empty()) {
                return Err(RpcError::invalid("channel target names cannot be empty"));
            }
        }
        if selector
            .release_tags
            .iter()
            .any(|tag| tag.trim().is_empty())
        {
            return Err(RpcError::invalid("release tags cannot be empty"));
        }
        if let Some(recent) = selector.recent_releases.as_ref() {
            if !(1..=100).contains(&recent.count) {
                return Err(RpcError::invalid(
                    "recent release count must be 1 through 100",
                ));
            }
        }
        Ok(())
    }

    pub(in crate::service) fn canonicalize_retention_spec(
        spec: &mut pb::RetentionSubscriptionSpec,
    ) -> Result<(), RpcError> {
        let selector = spec
            .selector
            .as_mut()
            .ok_or_else(|| RpcError::invalid("selector is required"))?;
        selector
            .release_tags
            .sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        selector.release_tags.dedup();
        if let Some(channels) = selector.channel_targets.as_mut() {
            channels
                .names
                .sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
            channels.names.dedup();
        }
        if let Some(semver) = selector.semver.as_mut() {
            semver.requirement =
                aos_hub_model::retention::RetentionSemverRequirement::parse(&semver.requirement)
                    .map_err(|error| RpcError::invalid(error.to_string()))?
                    .canonical()
                    .to_string();
        }
        Self::validate_retention_spec(spec)
    }

    pub(in crate::service) fn retention_subscription_message(
        record: &aos_hub_db::db::CacheRetentionSubscriptionRecord,
        cache_id: &str,
        registry_id: &str,
    ) -> Result<pb::RetentionSubscription, RpcError> {
        let selector = serde_json::from_str(&record.selector_json).map_err(RpcError::internal)?;
        Ok(pb::RetentionSubscription {
            subscription_id: record.id.to_string(),
            cache_id: cache_id.to_string(),
            registry_id: registry_id.to_string(),
            desired: Some(pb::RetentionSubscriptionSpec {
                selector: Some(selector),
                removal_grace_seconds: record.removal_grace_secs,
            }),
            policy_version: record.resource_version,
            current_refresh_id: record.current_refresh_id.clone().unwrap_or_default(),
            refresh_state: record.refresh_state.clone(),
            resource_version: record.resource_version.to_string(),
        })
    }

    pub(in crate::service) async fn authorized_cache_registry_retention_pair(
        &self,
        auth: Option<&str>,
        cache_id: &str,
        registry_id: &str,
        mutate: bool,
    ) -> Result<(aos_hub_db::db::BinaryCache, RegistryRecord), RpcError> {
        let cache = self.binary_cache_or_not_found(cache_id).await?;
        let registry = self.registry_or_not_found(registry_id).await?;
        let claims = if mutate {
            self.require_cache_permission(auth, &cache, Permission::CacheRetentionManage)
                .await?
        } else {
            self.require_cache_operational_read(auth, &cache).await?
        };
        self.require_permission(
            &claims,
            if mutate {
                Permission::RegistryConfigure
            } else {
                Permission::Read
            },
            &self.registry_scope(&registry).await?,
        )
        .await?;
        Ok((cache, registry))
    }

    pub(in crate::service) async fn manual_retention_root_message(
        &self,
        cache_id: &str,
        root: &aos_hub_db::db::ManualRetentionRootRecord,
        include_actor: bool,
    ) -> Result<pb::ManualRetentionRoot, RpcError> {
        let current_lease = if let Some(lease_id) = root.current_lease_id.as_deref() {
            self.db
                .retention_lease(lease_id)
                .await
                .map_err(RpcError::internal)?
                .map(|lease| Self::retention_lease_message(lease, include_actor))
        } else {
            None
        };
        Ok(pb::ManualRetentionRoot {
            root_id: root.id.clone(),
            cache_id: cache_id.to_string(),
            store_hash: root.store_hash.clone(),
            reason: root.reason.clone(),
            created_by: include_actor
                .then(|| root.created_by.clone())
                .unwrap_or_default(),
            created_at: root.created_at,
            deleted_at: root.deleted_at,
            current_lease,
            resource_version: root.resource_version.to_string(),
        })
    }

    pub(in crate::service) fn retention_lease_message(
        lease: aos_hub_db::db::RetentionLeaseRecord,
        include_actor: bool,
    ) -> pb::RetentionLease {
        pb::RetentionLease {
            lease_id: lease.id,
            root_id: lease.manual_retention_root_id,
            expires_at: lease.expires_at,
            state: lease.state,
            renewed_from_lease_id: lease.renewed_from_lease_id.unwrap_or_default(),
            actor: if include_actor {
                lease
                    .revoked_by
                    .clone()
                    .unwrap_or_else(|| lease.renewed_by.clone())
            } else {
                String::new()
            },
            created_at: lease.renewed_at,
            revoked_at: lease.revoked_at,
        }
    }

    /// Refreshes every enabled registry-retention subscription for a cache.
    pub(in crate::service) async fn execute_refresh_all_retention(
        &self,
        auth: Option<&str>,
        req: pb::PlanRefreshAllRetentionRequest,
    ) -> Result<pb::OperationResponse, RpcError> {
        let cache = self.binary_cache_or_not_found(&req.cache_id).await?;
        self.require_cache_permission(auth, &cache, Permission::CacheRetentionManage)
            .await?;
        if req.idempotency_key.is_empty() {
            return Err(RpcError::invalid("idempotency_key is required"));
        }
        let expected_version = parse_resource_version(&req.expected_resource_version, 0)?;
        let request_digest = hex::encode(Sha256::digest(
            serde_json::to_vec(&req).map_err(RpcError::internal)?,
        ));
        let operation_id = hex::encode(Sha256::digest(
            format!("refresh-all:{}:{}", cache.slug, req.idempotency_key).as_bytes(),
        ));
        if let Some(existing) = self
            .db
            .topology_operation(&operation_id)
            .await
            .map_err(RpcError::internal)?
        {
            let detail: serde_json::Value =
                serde_json::from_str(&existing.detail_json).map_err(RpcError::internal)?;
            if detail
                .get("requestDigest")
                .and_then(serde_json::Value::as_str)
                != Some(request_digest.as_str())
                || detail
                    .get("expectedResourceVersion")
                    .and_then(serde_json::Value::as_i64)
                    != Some(expected_version)
            {
                return Err(RpcError::FailedPrecondition(
                    "retention refresh idempotency key was reused with another request".to_string(),
                ));
            }
            return Ok(pb::OperationResponse {
                operation: Some(pb::OperationRef {
                    operation_id: existing.operation_id,
                    kind: existing.operation_kind,
                    state: existing.state,
                    created_at: existing.created_at,
                }),
            });
        }
        let gc_state = self
            .db
            .cache_gc_topology_state(cache.id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("cache GC state"))?;
        if gc_state.resource_version != expected_version {
            return Err(RpcError::FailedPrecondition(
                "cache GC state resource version is stale".to_string(),
            ));
        }
        let subscriptions = self
            .db
            .list_cache_retention_subscriptions_topology(cache.id)
            .await
            .map_err(RpcError::internal)?;
        let operation = self
            .db
            .create_topology_operation(&aos_hub_db::db::NewTopologyOperation {
                operation_id,
                operation_kind: "retention_refresh_all".to_string(),
                control_permission: Permission::CacheRetentionManage,
                targets: vec![aos_hub_db::db::NewTopologyOperationTarget {
                    role: "primary".to_string(),
                    target: aos_hub_db::db::NewTopologyOperationTargetRef::BinaryCache(cache.id),
                    generation_key: 0,
                    configuration_digest: String::new(),
                }],
                detail_json: serde_json::json!({
                    "subscriptionCount": subscriptions.iter().filter(|sub| sub.enabled).count(),
                    "requestDigest": request_digest,
                    "expectedResourceVersion": expected_version
                })
                .to_string(),
                progress_total: Some(
                    i64::try_from(subscriptions.iter().filter(|sub| sub.enabled).count()).map_err(
                        |_| {
                            RpcError::internal(anyhow::anyhow!(
                                "retention subscription count overflow"
                            ))
                        },
                    )?,
                ),
            })
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        let started_at = clock::now_unix_secs();
        let running = self
            .db
            .update_topology_operation(
                &operation.operation_id,
                operation.resource_version,
                "running",
                0,
                operation.progress_total,
                &operation.detail_json,
                None,
                Some(started_at),
                None,
            )
            .await
            .map_err(RpcError::internal)?;
        let mut refreshed = 0_i64;
        let mut failure = None;
        for subscription in subscriptions
            .iter()
            .filter(|subscription| subscription.enabled)
        {
            match self
                .materialize_retention_refresh(subscription, subscription.registry_id)
                .await
            {
                Ok(_) => refreshed += 1,
                Err(error) => {
                    failure = Some(format!("{error:#}"));
                    break;
                }
            }
        }
        let finished_at = clock::now_unix_secs();
        let state = if failure.is_some() {
            "failed"
        } else {
            "succeeded"
        };
        let terminal = self
            .db
            .update_topology_operation(
                &operation.operation_id,
                running.resource_version,
                state,
                refreshed,
                operation.progress_total,
                &serde_json::json!({ "refreshedSubscriptions": refreshed }).to_string(),
                failure.as_deref(),
                Some(started_at),
                Some(finished_at),
            )
            .await
            .map_err(RpcError::internal)?;
        Ok(pb::OperationResponse {
            operation: Some(pb::OperationRef {
                operation_id: terminal.operation_id,
                kind: terminal.operation_kind,
                state: terminal.state,
                created_at: terminal.created_at,
            }),
        })
    }
}
