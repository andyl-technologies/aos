//! Configuration helpers in the registries capability.

use super::*;

impl RpcService {
    pub(in crate::service) async fn registry_scope(
        &self,
        registry: &RegistryRecord,
    ) -> Result<Scope, RpcError> {
        self.db
            .registry_authorization_scope(registry.id)
            .await
            .map_err(RpcError::internal)
            .and_then(|scope| {
                Scope::try_parse(&scope).ok_or_else(|| {
                    RpcError::internal(anyhow::anyhow!(
                        "invalid stored registry authorization scope"
                    ))
                })
            })
    }

    /// Resolves a registry by immutable stable identity or canonical slug.
    pub(in crate::service) async fn registry_or_not_found(
        &self,
        identifier: &str,
    ) -> Result<RegistryRecord, RpcError> {
        if let Some(registry) = self
            .db
            .registry_by_stable_id(identifier)
            .await
            .map_err(RpcError::internal)?
        {
            return Ok(registry);
        }

        self.db
            .registry_by_slug(identifier)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("registry"))
    }

    /// Build the wire [`pb::Registry`] for `record`, folding in its index status,
    /// cache stack, and trust roster.
    pub(in crate::service) async fn registry_message(
        &self,
        record: &RegistryRecord,
        status: Option<IndexStatus>,
    ) -> Result<pb::Registry, RpcError> {
        let stack = self
            .db
            .registry_cache_stack_entries(record.id)
            .await
            .map_err(RpcError::internal)?;
        let mut caches = Vec::with_capacity(stack.len());
        for entry in stack {
            let source = if let Some(cache_id) = entry.cache_id {
                let cache = self
                    .db
                    .binary_cache_by_id(cache_id)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| {
                        RpcError::internal(anyhow::anyhow!(
                            "consumer stack references missing binary cache {cache_id}"
                        ))
                    })?;
                pb::consumer_cache_stack_entry::Source::BinaryCacheId(cache.slug)
            } else {
                pb::consumer_cache_stack_entry::Source::External(pb::ExternalConsumerCache {
                    url: entry.committed_url,
                })
            };
            caches.push(pb::ConsumerCacheStackEntry {
                entry_id: entry.stack_path,
                source: Some(source),
                priority: u32::try_from(entry.resolved_priority).map_err(|_| {
                    RpcError::internal(anyhow::anyhow!("consumer stack priority is invalid"))
                })?,
                mirror_group_id: entry.mirror_group_id.unwrap_or_default(),
            });
        }
        let roster = self
            .db
            .list_roster(record.id)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .map(|(id, key, status)| pb::RosterKey { id, key, status })
            .collect();
        let status = status.unwrap_or(IndexStatus {
            state: "empty".into(),
            error: None,
            last_indexed_commit: None,
            name: None,
            description: None,
            readme: None,
            support: None,
            indexed_at: None,
            generation: 0,
            content_digest: None,
        });
        let exposure = self.container_distribution_exposure(record.id).await?;
        Ok(pb::Registry {
            slug: record.slug.clone(),
            name: status.name.unwrap_or_default(),
            description: status.description.unwrap_or_default(),
            index_state: status.state,
            index_error: status.error.unwrap_or_default(),
            last_indexed_commit: status.last_indexed_commit.unwrap_or_default(),
            indexed_at: status.indexed_at.unwrap_or_default(),
            trust_keys: record.trust_keys.clone(),
            consumer_cache_stack: caches,
            roster,
            crawl_policy: record.crawl_policy.clone(),
            llms_txt_body: record.llms_txt_body.clone().unwrap_or_default(),
            stable_id: record.stable_id.clone(),
            visibility: record.visibility.clone(),
            resource_version: record.resource_version.to_string(),
            updated_at: record.updated_at,
            authorization_scope_key: record.scope_key.clone(),
            owner_scope_key: record.owner_scope_key.clone(),
            oci_distribution_origin: exposure
                .as_ref()
                .map(|exposure| exposure.origin.clone())
                .unwrap_or_default(),
            oci_repository_namespace: exposure
                .and_then(|exposure| exposure.namespace)
                .unwrap_or_default(),
        })
    }

    /// Creates a managed registry attributed to an already-reserved plan.
    ///
    /// The registry is created at the canonical path `{org}/{project_path}/{name}`
    /// with the given visibility and no implicit physical placement. Requires
    /// [`Permission::RegistryConfigure`] on the org scope.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Unauthenticated`] for a missing/invalid bearer JWT,
    /// [`RpcError::PermissionDenied`] when the caller lacks `registry.configure`
    /// on the org scope, [`RpcError::NotFound`] for an unknown org,
    /// [`RpcError::InvalidArgument`] for a missing name or bad
    /// visibility, [`RpcError::AlreadyExists`] when a registry occupies the
    /// canonical path, and [`RpcError::Internal`] on database failure.
    pub(in crate::service) async fn create_registry_from_plan(
        &self,
        auth: Option<&str>,
        req: pb::PlanCreateRegistryRequest,
        plan_id: &str,
    ) -> Result<pb::RegistryResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let org = self.org_or_not_found(&req.org_slug).await?;
        self.require_permission(
            &claims,
            Permission::RegistryConfigure,
            &Scope::parse(&org.stable_id),
        )
        .await?;
        if req.name.is_empty() {
            return Err(RpcError::invalid("registry name is required"));
        }
        let visibility = match req.visibility.as_str() {
            "" => "private",
            v @ ("public" | "internal" | "private") => v,
            other => return Err(RpcError::invalid(format!("invalid visibility '{other}'"))),
        };
        let crawl_policy = self
            .db
            .instance_config_get("default_crawl_policy")
            .await
            .map_err(RpcError::internal)?
            .as_deref()
            .and_then(|value| crate::crawl::CrawlPolicy::parse(value).ok())
            .unwrap_or_default();
        let id = self
            .db
            .create_managed_registry_from_plan(
                org.id,
                &req.project_path,
                &req.name,
                visibility,
                &req.trust_keys,
                true,
                crawl_policy.as_str(),
                plan_id,
            )
            .await
            .map_err(|e| RpcError::AlreadyExists(format!("{e:#}")))?;
        let record = self
            .db
            .registry_by_scope(&org.slug, &req.project_path, &req.name)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| {
                RpcError::internal(anyhow::anyhow!("registry {id} vanished after creation"))
            })?;
        let status = self
            .db
            .index_status(record.id)
            .await
            .map_err(RpcError::internal)?;
        Ok(pb::RegistryResponse {
            registry: Some(self.registry_message(&record, status).await?),
        })
    }

    /// Load a registry by slug only when it is publicly visible.
    ///
    /// The shared anonymous-visibility gate for the `robots.txt`/`llms.txt`
    /// serving paths: returns the [`RegistryRecord`] only for a `public`
    /// registry under an active org, and `None` for an absent, internal, or
    /// private registry — the two are deliberately indistinguishable to a
    /// crawler.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Internal`] on database failure.
    pub(in crate::service) async fn public_registry(
        &self,
        slug: &str,
    ) -> Result<Option<RegistryRecord>, RpcError> {
        let Some(registry) = self
            .db
            .registry_by_slug(slug)
            .await
            .map_err(RpcError::internal)?
        else {
            return Ok(None);
        };
        if registry.visibility != "public" {
            return Ok(None);
        }
        if let Some(org_id) = registry.org_id {
            if !matches!(self.db.org_is_active(org_id).await, Ok(true)) {
                return Ok(None);
            }
        }
        Ok(Some(registry))
    }

    pub(in crate::service) fn registry_mirror_message(
        record: crate::db::RegistryMirrorRecord,
    ) -> pb::RegistryMirror {
        let mode = match record.mode.as_str() {
            "pull_through" => pb::RegistryMirrorMode::PullThrough,
            _ => pb::RegistryMirrorMode::Full,
        };
        pb::RegistryMirror {
            registry_id: record.registry_id.to_string(),
            source_url: record.source_url,
            refspec: record.refspec,
            auth_secret_ref: record.auth_secret_ref,
            interval_seconds: record.interval_seconds,
            state: record.state,
            observed_commit: record.observed_commit.unwrap_or_default(),
            error: record.error.unwrap_or_default(),
            last_sync_at: record.last_sync_at.unwrap_or_default(),
            resource_version: record.resource_version.to_string(),
            signature_policy: record.signature_policy,
            mode: mode as i32,
        }
    }

    pub(in crate::service) fn canonicalize_registry_mirror_spec(
        spec: &mut pb::RegistryMirrorSpec,
    ) -> Result<&'static str, RpcError> {
        spec.source_url = spec.source_url.trim().trim_end_matches('/').to_string();
        spec.refspec = spec.refspec.trim().to_string();
        spec.auth_secret_ref = spec.auth_secret_ref.trim().to_string();
        spec.signature_policy = spec.signature_policy.trim().to_ascii_lowercase();
        if spec.source_url.is_empty() {
            return Err(RpcError::invalid("mirror source_url is required"));
        }
        crate::url_guard::is_safe_remote_url(&spec.source_url)
            .map_err(|error| RpcError::invalid(format!("mirror source_url: {error:#}")))?;
        if spec.refspec.is_empty() {
            spec.refspec = "refs/*".to_string();
        }
        if !spec.refspec.starts_with("refs/")
            || spec.refspec.contains("..")
            || spec.refspec.chars().any(char::is_whitespace)
        {
            return Err(RpcError::invalid(
                "mirror refspec must be a whitespace-free refs/... expression",
            ));
        }
        if spec.signature_policy.is_empty() {
            spec.signature_policy = "required".to_string();
        }
        if !matches!(
            spec.signature_policy.as_str(),
            "required" | "allow_unsigned"
        ) {
            return Err(RpcError::invalid(
                "signature_policy must be required or allow_unsigned",
            ));
        }
        let mode = match pb::RegistryMirrorMode::try_from(spec.mode)
            .map_err(|_| RpcError::invalid("mirror mode is not recognized"))?
        {
            pb::RegistryMirrorMode::Unspecified | pb::RegistryMirrorMode::Full => {
                spec.mode = pb::RegistryMirrorMode::Full as i32;
                if spec.interval_seconds == 0 {
                    spec.interval_seconds = 3600;
                }
                if spec.interval_seconds < 1 {
                    return Err(RpcError::invalid(
                        "full mirror interval_seconds must be positive",
                    ));
                }
                "full"
            }
            pb::RegistryMirrorMode::PullThrough => {
                spec.mode = pb::RegistryMirrorMode::PullThrough as i32;
                if spec.interval_seconds != 0 {
                    return Err(RpcError::invalid(
                        "pull-through mirrors do not accept interval_seconds",
                    ));
                }
                "pull_through"
            }
        };
        Ok(mode)
    }

    pub(in crate::service) async fn authorize_registry_mirror(
        &self,
        auth: Option<&str>,
        registry: &RegistryRecord,
    ) -> Result<Claims, RpcError> {
        let claims = self.require_claims(auth)?;
        self.require_permission(
            &claims,
            Permission::RegistryConfigure,
            &self.registry_scope(&registry).await?,
        )
        .await?;
        Ok(claims)
    }

    /// Enqueues one idempotent full-mirror synchronization operation.
    ///
    /// Pull-through mirrors synchronize on demand and reject this operation.
    ///
    /// # Errors
    ///
    /// Returns an authentication, authorization, validation, stale-version,
    /// precondition, or database error.
    pub(in crate::service) async fn execute_sync_registry_mirror(
        &self,
        auth: Option<&str>,
        req: pb::PlanSyncRegistryMirrorRequest,
    ) -> Result<pb::OperationResponse, RpcError> {
        if req.idempotency_key.is_empty() {
            return Err(RpcError::invalid("idempotency_key is required"));
        }
        let registry = self.registry_or_not_found(&req.registry_id).await?;
        let claims = self.authorize_registry_mirror(auth, &registry).await?;
        let mirror = self
            .db
            .registry_mirror(registry.id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("registry mirror"))?;
        if parse_resource_version(&req.expected_resource_version, 0)? != mirror.resource_version {
            return Err(RpcError::FailedPrecondition(
                "registry mirror resource version is stale".to_string(),
            ));
        }
        if mirror.mode != "full" {
            return Err(RpcError::FailedPrecondition(
                "pull-through mirrors synchronize on demand".to_string(),
            ));
        }
        let identity = format!(
            "{}:{}:{}:{}",
            claims.owner_kind, claims.owner_id, registry.id, req.idempotency_key
        );
        let operation_id = format!(
            "mirror-sync:{}",
            &hex::encode(Sha256::digest(identity.as_bytes()))[..32]
        );
        let operation = if let Some(existing) = self
            .db
            .topology_operation(&operation_id)
            .await
            .map_err(RpcError::internal)?
        {
            let targets = self
                .db
                .topology_operation_targets(&existing.operation_id)
                .await
                .map_err(RpcError::internal)?;
            if existing.operation_kind != "registry_mirror_sync"
                || !targets.iter().any(|target| {
                    target.role == "primary"
                        && target.target_kind == "registry"
                        && target.stable_id == registry.stable_id
                })
            {
                return Err(RpcError::FailedPrecondition(
                    "idempotency key is already used by another operation".to_string(),
                ));
            }
            existing
        } else {
            self.db
                .create_topology_operation(&crate::db::NewTopologyOperation {
                    operation_id,
                    operation_kind: "registry_mirror_sync".to_string(),
                    control_permission: Permission::RegistryConfigure,
                    targets: vec![crate::db::NewTopologyOperationTarget {
                        role: "primary".to_string(),
                        target: crate::db::NewTopologyOperationTargetRef::Registry(registry.id),
                        generation_key: 0,
                        configuration_digest: String::new(),
                    }],
                    progress_total: None,
                    detail_json: serde_json::json!({
                        "registryId": registry.slug,
                        "mirrorResourceVersion": mirror.resource_version,
                    })
                    .to_string(),
                })
                .await
                .map_err(RpcError::internal)?
        };
        Ok(pb::OperationResponse {
            operation: Some(pb::OperationRef {
                operation_id: operation.operation_id,
                kind: operation.operation_kind,
                state: operation.state,
                created_at: operation.created_at,
            }),
        })
    }

    pub(in crate::service) async fn registry_publication_object_context(
        &self,
        auth: Option<&str>,
        publication_id: &str,
        surface_object_id: i64,
    ) -> Result<
        (
            crate::db::RegistryPublicationRecord,
            crate::db::RegistryRecord,
            crate::db::RegistryPublicationUploadObjectRecord,
        ),
        RpcError,
    > {
        let claims = self.require_claims(auth)?;
        let publication = self
            .db
            .registry_publication(publication_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("registry publication"))?;
        let registry = self
            .db
            .registry_by_id(publication.registry_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("registry"))?;
        let scope = self.registry_scope(&registry).await?;
        self.require_permission(&claims, Permission::Publish, &scope)
            .await?;
        let object = self
            .db
            .registry_publication_upload_object(publication_id, surface_object_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("publication object"))?;
        Ok((publication, registry, object))
    }

    pub(in crate::service) async fn registry_publication_response(
        &self,
        publication_id: &str,
        include_objects: bool,
    ) -> Result<pb::RegistryPublication, RpcError> {
        let publication = self
            .db
            .registry_publication(publication_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("registry publication"))?;
        let registry = self
            .db
            .registry_by_id(publication.registry_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("registry"))?;
        let objects = if include_objects {
            let max_complete_upload = self.effective_complete_upload_bytes().await as i64;
            self.db
                .registry_publication_upload_objects(publication_id)
                .await
                .map_err(RpcError::internal)?
                .into_iter()
                .map(|object| pb::RegistryPublicationObject {
                    object_id: object.surface_object_id,
                    path: object.object_key.clone(),
                    sha256: object.expected_hash,
                    byte_size: object.expected_size,
                    kind: object.object_kind,
                    media_type: publication_media_type(&object.object_key).into(),
                    upload_url: (object.expected_size <= max_complete_upload)
                        .then(|| {
                            format!(
                                "{}/aos.hub.v1.PublishService/UploadObject/{}/{}",
                                self.external_url.trim_end_matches('/'),
                                publication_id,
                                object.surface_object_id
                            )
                        })
                        .unwrap_or_default(),
                    verified: object.verified,
                })
                .collect()
        } else {
            Vec::new()
        };
        let mut placements = Vec::new();
        for progress in self
            .db
            .registry_publication_placement_records(publication_id)
            .await
            .map_err(RpcError::internal)?
        {
            let placement = self
                .db
                .surface_placement(progress.placement_id)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::FailedPrecondition("placement disappeared".into()))?;
            placements.push(pb::RegistryPublicationPlacement {
                placement_id: progress.placement_id,
                name: placement.name,
                required: progress.required,
                state: progress.state,
            });
        }
        Ok(pb::RegistryPublication {
            publication_id: publication.publication_id,
            registry: registry.slug,
            ordinal: publication.ordinal,
            generation: publication.generation,
            manifest_digest: publication.manifest_digest,
            refs_digest: publication.refs_digest,
            default_commit: publication.default_commit.unwrap_or_default(),
            parent_publication_id: publication.parent_publication_id.unwrap_or_default(),
            state: publication.state,
            objects,
            placements,
            created_at: publication.created_at,
            completed_at: publication.completed_at.unwrap_or_default(),
        })
    }
}
