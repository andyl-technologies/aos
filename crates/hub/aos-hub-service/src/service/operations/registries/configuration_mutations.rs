//! Configuration mutations in the registries capability.

use super::*;

impl RpcService {
    /// Applies a managed-registry creation plan exactly once.
    ///
    /// # Errors
    ///
    /// Returns an authentication, confirmation, authorization, stale-plan,
    /// conflict, quota, or persistence error.
    pub async fn apply_create_registry(
        &self,
        auth: Option<&str>,
        req: pb::ApplyRegistryMutationRequest,
    ) -> Result<pb::RegistryResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "create_registry",
                Some(&req.confirmation_hash),
                &req.idempotency_key,
            )
            .await?
        {
            return Ok(response);
        }
        self.begin_control_plan_apply(
            auth,
            &req.plan_id,
            "create_registry",
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, RegistryCreatePlanInput) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                "create_registry",
                Some(&req.confirmation_hash),
            )
            .await?;
        let claims = self.require_claims(auth)?;
        let org = self.org_or_not_found(&input.request.org_slug).await?;
        self.require_permission(
            &claims,
            Permission::RegistryConfigure,
            &Scope::parse(&org.stable_id),
        )
        .await?;
        if org.id != input.org_id {
            return Err(RpcError::FailedPrecondition(
                "registry owner identity changed after planning".to_string(),
            ));
        }
        let response = if let Some(record) = self
            .db
            .registry_by_scope(&org.slug, &input.request.project_path, &input.request.name)
            .await
            .map_err(RpcError::internal)?
        {
            if !self
                .db
                .registry_matches_creation_plan(record.id, &plan.plan_id)
                .await
                .map_err(RpcError::internal)?
            {
                return Err(RpcError::FailedPrecondition(
                    "registry identity was claimed after planning".to_string(),
                ));
            }
            let status = self
                .db
                .index_status(record.id)
                .await
                .map_err(RpcError::internal)?;
            pb::RegistryResponse {
                registry: Some(self.registry_message(&record, status).await?),
            }
        } else {
            self.create_registry_from_plan(auth, input.request, &plan.plan_id)
                .await?
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Applies one registry configuration plan exactly once.
    pub async fn apply_update_registry(
        &self,
        auth: Option<&str>,
        req: pb::ApplyRegistryMutationRequest,
    ) -> Result<pb::RegistryResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "update_registry",
                Some(&req.confirmation_hash),
                &req.idempotency_key,
            )
            .await?
        {
            return Ok(response);
        }
        self.begin_control_plan_apply(
            auth,
            &req.plan_id,
            "update_registry",
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, RegistryUpdatePlanInput) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                "update_registry",
                Some(&req.confirmation_hash),
            )
            .await?;
        let claims = self.require_claims(auth)?;
        let registry = self.registry_or_not_found(&input.request.slug).await?;
        self.require_permission(
            &claims,
            Permission::RegistryConfigure,
            &self.registry_scope(&registry).await?,
        )
        .await?;
        if registry.id != input.registry_id || registry.owner_scope_key != input.owner_scope_key {
            return Err(RpcError::FailedPrecondition(
                "registry identity changed after planning".to_string(),
            ));
        }
        let updated = self
            .db
            .apply_registry_configuration_change(
                registry.id,
                input.expected_resource_version,
                &input.request.visibility,
                &input.request.crawl_policy,
                (!input.request.llms_txt_body.is_empty())
                    .then_some(input.request.llms_txt_body.as_str()),
                &input.request.trust_keys,
                &plan.plan_id,
                &claims.owner_kind,
                Some(claims.owner_id),
                &claims.sub,
            )
            .await
            .map_err(RpcError::internal)?;
        if !updated {
            return Err(RpcError::FailedPrecondition(
                "registry changed after planning".to_string(),
            ));
        }
        let record = self.registry_or_not_found(&input.request.slug).await?;
        let trust_keys_updated = input
            .request
            .update_mask
            .iter()
            .any(|field| field == "trust_keys");
        if trust_keys_updated {
            if let Err(error) = self.reindexer.reindex(&record).await {
                // The configuration mutation is already durable. Indexing records
                // its own failed status, and the periodic reconciler can safely
                // retry without making this applied control plan look replayable.
                tracing::warn!(
                    registry = %record.slug,
                    error = %format!("{error:#}"),
                    "registry trust update could not refresh the signed index"
                );
            }
        }
        let status = self
            .db
            .index_status(record.id)
            .await
            .map_err(RpcError::internal)?;
        let response = pb::RegistryResponse {
            registry: Some(self.registry_message(&record, status).await?),
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// The consumer-facing base URL for a registry's git surface.
    ///
    /// The selected canonical Git route is the only source of a consumer URL.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn registry_consumer_url(
        &self,
        registry: &RegistryRecord,
    ) -> Result<String, RpcError> {
        self.db
            .ready_registry_canonical_url(registry.id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| {
                RpcError::FailedPrecondition("registry canonical Git route is not ready".to_owned())
            })
    }

    /// Serve a registry's `robots.txt`, or `None` when the registry is not
    /// public.
    ///
    /// Anonymous serving path: only a **public** registry is exposed (a private
    /// or internal registry, or an absent slug, returns `None` → `404`),
    /// consistent with the anonymous browse gate. A registry with a custom
    /// `robots.txt`... is not modeled per-registry; the per-registry document is
    /// always generated from the registry's [`aos_hub_model::crawl::CrawlPolicy`].
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Internal`] on database failure.
    pub async fn serve_registry_robots(&self, slug: &str) -> Result<Option<String>, RpcError> {
        let Some(registry) = self.public_registry(slug).await? else {
            return Ok(None);
        };
        let policy = aos_hub_model::crawl::CrawlPolicy::parse_or_default(&registry.crawl_policy);
        let base = self.external_url.trim_end_matches('/');
        let llms_url = format!("{base}/{}/llms.txt", registry.slug);
        Ok(Some(crate::robots::render_robots(policy, Some(&llms_url))))
    }

    /// Serve a registry's `llms.txt`, or `None` when the registry is not public.
    ///
    /// Anonymous serving path: only a **public** registry is exposed. A registry
    /// with a custom `llms_txt_body` override is served verbatim; otherwise the
    /// document is generated from the registry's indexed packages and channels
    /// (see [`crate::robots::render_registry_llms`]).
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Internal`] on database failure.
    pub async fn serve_registry_llms(&self, slug: &str) -> Result<Option<String>, RpcError> {
        let Some(registry) = self.public_registry(slug).await? else {
            return Ok(None);
        };
        if let Some(body) = registry.llms_txt_body.clone() {
            return Ok(Some(body));
        }
        let status = self
            .db
            .index_status(registry.id)
            .await
            .map_err(RpcError::internal)?;
        let packages = self
            .db
            .list_packages(registry.id)
            .await
            .map_err(RpcError::internal)?;
        let channels = self
            .db
            .list_channels(registry.id)
            .await
            .map_err(RpcError::internal)?;
        let base = self.external_url.trim_end_matches('/');
        let view = crate::robots::RegistryView {
            base_url: base.to_string(),
            name: status.as_ref().and_then(|s| s.name.clone()),
            description: status.as_ref().and_then(|s| s.description.clone()),
            packages: packages
                .into_iter()
                .map(|p| crate::robots::PackageView {
                    browse_url: format!("{base}/{}/-/packages/{}", registry.slug, p.name),
                    name: p.name,
                    description: p.description,
                })
                .collect(),
            channels: channels
                .into_iter()
                .map(|c| crate::robots::ChannelView {
                    name: c.name,
                    frontier: c.frontier,
                })
                .collect(),
            slug: registry.slug.clone(),
        };
        Ok(Some(crate::robots::render_registry_llms(&view)))
    }

    /// Serves one registry machine object as a streaming, range-aware response.
    ///
    /// Placement selection and every retry complete before the response body is
    /// returned. A body-stream failure is therefore reported on the selected
    /// placement's response and is never spliced with bytes from a replica. A
    /// surface without an active placement fails closed.
    ///
    /// # Errors
    ///
    /// Returns an authentication/authorization error when the registry is not
    /// readable by the caller, or [`RpcError::Internal`] on planning or backend
    /// failure.
    pub async fn registry_serve(
        &self,
        auth: ReadAuthorization<'_>,
        registry: &RegistryRecord,
        path: &str,
        image_request: crate::image_http::ImageHttpRequest<'_>,
    ) -> Result<RegistryServeOutcome, RpcError> {
        let signed_image_path = path.starts_with("images/");
        if !signed_image_path && !keymap::is_machine_path(path) {
            return Ok(RegistryServeOutcome::NotFound);
        }
        // Reload by id to establish the authorization/serve linearization
        // point. Route resolution may have happened before a concurrent delete;
        // only this fresh row may drive authorization and placement planning.
        let registry = self
            .db
            .registry_by_id(registry.id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("registry"))?;
        self.require_registry_stream_read(auth, &registry).await?;
        if signed_image_path {
            return self
                .serve_signed_image_object(&registry, path, image_request)
                .await;
        }
        let range_header = image_request
            .range
            .and_then(|value| std::str::from_utf8(value).ok());
        let requested = parse_byte_range(range_header);
        let mirror = self
            .db
            .registry_mirror(registry.id)
            .await
            .map_err(RpcError::internal)?;
        let read = match placement_read::stream_from_placements_with_requirement(
            self.db.as_ref(),
            self.surface.as_ref(),
            SurfaceTarget::Registry(registry.id),
            path,
            requested,
            if mirror
                .as_ref()
                .is_some_and(|mirror| mirror.mode == "pull_through")
            {
                PlacementReadRequirement::Untracked
            } else {
                placement_read::requirement_for_path(SurfaceTarget::Registry(registry.id), path)
            },
        )
        .await
        .map_err(RpcError::surface_read)?
        {
            PlacementReadOutcome::Found(read) => read.value,
            PlacementReadOutcome::NotFound => return Ok(RegistryServeOutcome::NotFound),
        };
        Ok(RegistryServeOutcome::Response(
            Self::streamed_surface_response(path, read)?,
        ))
    }

    /// Applies a reviewed registry-mirror replacement exactly once.
    ///
    /// # Errors
    ///
    /// Returns an authentication, confirmation, stale-plan, authorization,
    /// validation, or database error.
    pub async fn set_registry_mirror(
        &self,
        auth: Option<&str>,
        req: pb::ApplyTopologyPlanRequest,
    ) -> Result<pb::RegistryMirrorResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "set_registry_mirror",
                Some(&req.confirmation_hash),
                &req.idempotency_key,
            )
            .await?
        {
            return Ok(response);
        }
        self.begin_control_plan_apply(
            auth,
            &req.plan_id,
            "set_registry_mirror",
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, mut input): (_, RegistryMirrorMutationPlanInput) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                "set_registry_mirror",
                Some(&req.confirmation_hash),
            )
            .await?;
        let registry = self
            .registry_or_not_found(&input.request.registry_id)
            .await?;
        if registry.id != input.registry_db_id {
            return Err(RpcError::FailedPrecondition(
                "registry identity changed after planning".to_string(),
            ));
        }
        self.authorize_registry_mirror(auth, &registry).await?;
        let desired = input
            .request
            .desired
            .as_mut()
            .ok_or_else(|| RpcError::invalid("planned desired state is missing"))?;
        let mode = Self::canonicalize_registry_mirror_spec(desired)?;
        let current = self
            .db
            .registry_mirror(registry.id)
            .await
            .map_err(RpcError::internal)?;
        if current.as_ref().map(|record| record.resource_version) != input.baseline_resource_version
        {
            return Err(RpcError::FailedPrecondition(
                "registry mirror changed after planning".to_string(),
            ));
        }
        let record = self
            .db
            .set_registry_mirror(
                registry.id,
                &desired.source_url,
                &desired.refspec,
                &desired.auth_secret_ref,
                mode,
                &desired.signature_policy,
                desired.interval_seconds,
                input.baseline_resource_version,
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        let mut message = Self::registry_mirror_message(record);
        message.registry_id = registry.slug;
        let response = pb::RegistryMirrorResponse {
            mirror: Some(message),
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Applies reviewed deletion of registry-owned mirror configuration.
    ///
    /// # Errors
    ///
    /// Returns an authentication, confirmation, stale-plan, authorization, or
    /// database error.
    pub async fn delete_registry_mirror(
        &self,
        auth: Option<&str>,
        req: pb::ApplyDeleteTopologyResourceRequest,
    ) -> Result<pb::DeleteTopologyResourceResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "delete_registry_mirror",
                Some(&req.confirmation_hash),
                &req.idempotency_key,
            )
            .await?
        {
            return Ok(response);
        }
        self.begin_control_plan_apply(
            auth,
            &req.plan_id,
            "delete_registry_mirror",
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, RegistryMirrorDeletePlanInput) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                "delete_registry_mirror",
                Some(&req.confirmation_hash),
            )
            .await?;
        let registry = self.registry_or_not_found(&input.request.stable_id).await?;
        if registry.id != input.registry_db_id {
            return Err(RpcError::FailedPrecondition(
                "registry identity changed after planning".to_string(),
            ));
        }
        self.authorize_registry_mirror(auth, &registry).await?;
        if !self
            .db
            .delete_registry_mirror_at_version(registry.id, input.baseline_resource_version)
            .await
            .map_err(RpcError::internal)?
        {
            return Err(RpcError::FailedPrecondition(
                "registry mirror changed after planning".to_string(),
            ));
        }
        let response = pb::DeleteTopologyResourceResponse { deleted: true };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Begins one exact, placement-aware registry publication.
    ///
    /// # Errors
    ///
    /// Returns an authorization error when the caller lacks `publish`, an
    /// invalid-argument error for a malformed manifest, a failed-precondition
    /// error when no placement can accept the complete publication, or an
    /// internal error when durable admission fails.
    pub async fn begin_registry_publication(
        &self,
        auth: Option<&str>,
        req: pb::BeginRegistryPublicationRequest,
    ) -> Result<pb::RegistryPublication, RpcError> {
        let claims = self.require_claims(auth)?;
        let registry = self.registry_or_not_found(&req.registry).await?;
        let scope = self.registry_scope(&registry).await?;
        self.require_permission(&claims, Permission::Publish, &scope)
            .await?;

        if req.objects.is_empty() {
            return Err(RpcError::invalid("publication manifest must not be empty"));
        }
        if req.objects.len() > MAX_REGISTRY_PUBLICATION_OBJECTS {
            return Err(RpcError::invalid(format!(
                "publication manifest exceeds the {MAX_REGISTRY_PUBLICATION_OBJECTS} object limit"
            )));
        }
        if req.generation.is_empty() || req.refs_digest.is_empty() {
            return Err(RpcError::invalid(
                "publication generation and refs digest are required",
            ));
        }
        let mut paths = BTreeSet::new();
        let mut canonical = Vec::with_capacity(req.objects.len());
        let complete_upload_limit = self.effective_complete_upload_bytes().await as u64;
        for object in &req.objects {
            if !paths.insert(object.path.as_str()) {
                return Err(RpcError::invalid("publication paths must be unique"));
            }
            if !keymap::is_machine_path(&object.path)
                || aos_hub_model::url_guard::validate_http_surface_path(&object.path).is_err()
                || object.path.len() > MAX_REGISTRY_PUBLICATION_PATH_BYTES
                || object.path.split('/').count() > MAX_REGISTRY_PUBLICATION_PATH_COMPONENTS
            {
                return Err(RpcError::invalid("publication object path is invalid"));
            }
            if !matches!(object.kind.as_str(), "immutable" | "mutable_pointer") {
                return Err(RpcError::invalid(
                    "publication object kind must be immutable or mutable_pointer",
                ));
            }
            if (object.kind == "mutable_pointer") != is_mutable_pointer(&object.path) {
                return Err(RpcError::invalid(
                    "publication object kind does not match path mutability",
                ));
            }
            if object.media_type != publication_media_type(&object.path) {
                return Err(RpcError::invalid(format!(
                    "publication object '{}' must declare media type '{}'",
                    object.path,
                    publication_media_type(&object.path)
                )));
            }
            if object.byte_size < 0
                || object.sha256.len() != 64
                || !object
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(RpcError::invalid(
                    "publication objects require a lowercase SHA-256 and non-negative size",
                ));
            }
            if keymap::is_loose_git_object_path(&object.path)
                && object.byte_size as u64
                    > complete_upload_limit
                        .min(aos_registry_format::object::MAX_PUBLISHED_LOOSE_OBJECT_BYTES)
            {
                return Err(RpcError::invalid(format!(
                    "loose Git object exceeds the {}-byte whole-upload limit",
                    complete_upload_limit
                        .min(aos_registry_format::object::MAX_PUBLISHED_LOOSE_OBJECT_BYTES,)
                )));
            }
            if keymap::is_git_pack_index_path(&object.path)
                && object.byte_size as u64
                    > complete_upload_limit
                        .min(aos_registry_format::pack_index::MAX_PUBLISHED_PACK_INDEX_BYTES)
            {
                return Err(RpcError::invalid(format!(
                    "Git pack index exceeds the {}-byte whole-upload limit",
                    complete_upload_limit
                        .min(aos_registry_format::pack_index::MAX_PUBLISHED_PACK_INDEX_BYTES,)
                )));
            }
            if keymap::is_git_pack_path(&object.path) {
                if object.byte_size as u64
                    > complete_upload_limit
                        .min(aos_registry_format::pack_index::MAX_PUBLISHED_PACK_BYTES)
                {
                    return Err(RpcError::invalid(format!(
                        "Git pack exceeds the {}-byte whole-upload limit",
                        complete_upload_limit
                            .min(aos_registry_format::pack_index::MAX_PUBLISHED_PACK_BYTES)
                    )));
                }
            }
            if !publication_nar_path_matches_sha256(&object.path, &object.sha256) {
                return Err(RpcError::invalid(
                    "publication NAR object path must identify its declared SHA-256",
                ));
            }
            canonical.push((
                object.path.clone(),
                object.sha256.clone(),
                object.byte_size,
                object.kind.clone(),
                object.media_type.clone(),
            ));
        }
        for path in paths
            .iter()
            .filter(|path| keymap::is_git_pack_index_path(path))
        {
            let companion = aos_registry_format::pack_index::companion_pack_path(path)
                .ok_or_else(|| RpcError::invalid("Git pack index path is invalid"))?;
            if !paths.contains(companion.as_str()) {
                return Err(RpcError::invalid(format!(
                    "Git pack index has no companion pack: {path}"
                )));
            }
        }
        for path in paths.iter().filter(|path| keymap::is_git_pack_path(path)) {
            let companion = format!("{}.idx", path.trim_end_matches(".pack"));
            if !paths.contains(companion.as_str()) {
                return Err(RpcError::invalid(format!(
                    "Git pack has no companion index: {path}"
                )));
            }
        }
        canonical.sort();
        // A freshly-created APR registry can consist entirely of replaceable
        // loose Git encodings plus HEAD/info/refs. Requiring a pack, NAR, or
        // other immutable payload here would make that valid initial signed
        // surface impossible to publish. The immutable upload class may be
        // empty; the pointer class is still mandatory because committing it is
        // what makes a publication observable to readers.
        if !canonical.iter().any(|object| object.3 == "mutable_pointer") {
            return Err(RpcError::invalid("publication requires mutable pointers"));
        }
        let placements = self
            .db
            .registry_publication_write_placements(registry.id)
            .await
            .map_err(RpcError::internal)?;
        if placements.is_empty() {
            return Err(RpcError::FailedPrecondition(
                "registry has no validated writable publication placement".into(),
            ));
        }
        let manifest_digest = hex::encode(Sha256::digest(
            serde_json::to_vec(&canonical).map_err(RpcError::internal)?,
        ));
        let parent = if req.parent_publication_id.is_empty() {
            None
        } else {
            Some(req.parent_publication_id.clone())
        };
        let default_commit = (!req.default_commit.is_empty()).then(|| req.default_commit.clone());
        let publication_id = if let Some(existing) = self
            .db
            .registry_publication_by_generation(registry.id, &req.generation)
            .await
            .map_err(RpcError::internal)?
        {
            if existing.manifest_digest != manifest_digest
                || existing.refs_digest != req.refs_digest
                || existing.default_commit != default_commit
                || existing.parent_publication_id != parent
            {
                return Err(RpcError::FailedPrecondition(
                    "publication generation already exists with different content".into(),
                ));
            }
            if existing.state == "retired" {
                return Err(RpcError::FailedPrecondition(format!(
                    "publication generation is {} and cannot be resumed",
                    existing.state
                )));
            }
            if existing.state != "failed" {
                return self
                    .registry_publication_response(&existing.publication_id, true)
                    .await;
            }
            self.db
                .retry_failed_registry_publication(&existing.publication_id, clock::now_unix_secs())
                .await
                .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
            existing.publication_id
        } else {
            let publication_id = uuid::Uuid::new_v4().simple().to_string();
            self.db
                .create_registry_publication(&aos_hub_db::db::NewRegistryPublication {
                    publication_id: publication_id.clone(),
                    registry_id: registry.id,
                    generation: req.generation,
                    manifest_digest,
                    refs_digest: req.refs_digest,
                    default_commit,
                    parent_publication_id: parent,
                })
                .await
                .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
            publication_id
        };

        let admission: Result<(), RpcError> = async {
            let manifest_objects = req
                .objects
                .into_iter()
                .map(|object| aos_hub_db::db::RegistryPublicationManifestObject {
                    object_key: object.path,
                    expected_hash: object.sha256,
                    expected_size: object.byte_size,
                    object_kind: object.kind,
                })
                .collect::<Vec<_>>();
            for objects in
                manifest_objects.chunks(aos_hub_db::db::MAX_REGISTRY_MANIFEST_ADMISSION_BATCH)
            {
                self.db
                    .admit_registry_publication_manifest_objects(
                        registry.id,
                        &publication_id,
                        objects,
                    )
                    .await
                    .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
            }
            for placement in placements {
                self.db
                    .set_registry_publication_placement(
                        &aos_hub_db::db::SetRegistryPublicationPlacement {
                            publication_id: publication_id.clone(),
                            placement_id: placement.id,
                            required: true,
                            state: "preparing".into(),
                            observed_at: clock::now_unix_secs(),
                        },
                    )
                    .await
                    .map_err(RpcError::internal)?;
            }
            self.db
                .inherit_registry_publication_object_evidence(
                    &publication_id,
                    clock::now_unix_secs(),
                )
                .await
                .map_err(RpcError::internal)?;
            Ok(())
        }
        .await;
        if let Err(error) = admission {
            self.db
                .fail_registry_publication(&publication_id, clock::now_unix_secs())
                .await
                .map_err(RpcError::internal)?;
            return Err(error);
        }
        self.registry_publication_response(&publication_id, true)
            .await
    }

    /// Commits an exactly complete publication and makes it discoverable.
    ///
    /// # Errors
    ///
    /// Returns an authorization error, a failed precondition while any object
    /// or placement is incomplete, or an internal error on durable promotion.
    pub async fn commit_registry_publication(
        &self,
        auth: Option<&str>,
        req: pb::CommitRegistryPublicationRequest,
    ) -> Result<pb::RegistryPublication, RpcError> {
        let claims = self.require_claims(auth)?;
        let publication = self
            .db
            .registry_publication(&req.publication_id)
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
        if let Some(state) = self
            .db
            .staged_publication_state(&req.publication_id)
            .await
            .map_err(RpcError::internal)?
        {
            if !matches!(state.as_str(), "releasing" | "released") {
                return Err(RpcError::FailedPrecondition(
                    "staged release publication requires explicit finalization".into(),
                ));
            }
        }
        if publication.state == "ready" {
            // A retry is also the explicit recovery path when publication
            // succeeded but its derived index did not. Returning immediately
            // here would leave operators waiting for a periodic reconciliation
            // even though the commit request is safe and idempotent.
            self.db
                .restore_ready_registry_publication_object_evidence(
                    &req.publication_id,
                    clock::now_unix_secs(),
                )
                .await
                .map_err(RpcError::internal)?;
            self.db
                .refresh_registry_publication_delivery_manifests(&req.publication_id)
                .await
                .map_err(RpcError::internal)?;
            self.refresh_registry_index_after_publication(&registry, &req.publication_id)
                .await;
            return self
                .registry_publication_response(&req.publication_id, true)
                .await;
        }
        let immutable_complete = self
            .db
            .registry_publication_class_is_complete(&req.publication_id, "immutable")
            .await
            .map_err(RpcError::internal)?;
        let pointers_complete = self
            .db
            .registry_publication_class_is_complete(&req.publication_id, "mutable_pointer")
            .await
            .map_err(RpcError::internal)?;
        if !immutable_complete || !pointers_complete {
            return Err(RpcError::FailedPrecondition(
                "publication is not complete on every required placement".into(),
            ));
        }

        if publication.state == "preparing" {
            // A publication whose exact objects already exist needs no upload
            // request. Open its pointer phase here so reuse-only generations
            // follow the same watermark protocol as generations that wrote a
            // pointer body.
            self.lease
                .acquire(
                    registry.id,
                    &publication.publication_id,
                    clock::now_unix_secs(),
                )
                .await
                .map_err(|holder| {
                    RpcError::FailedPrecondition(format!(
                        "registry publication lease is held by {holder}"
                    ))
                })?;
            if !self
                .db
                .advance_registry_publication(
                    &req.publication_id,
                    "preparing",
                    "writing_pointers",
                    clock::now_unix_secs(),
                )
                .await
                .map_err(RpcError::internal)?
            {
                let current = self
                    .db
                    .registry_publication(&req.publication_id)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| RpcError::not_found("registry publication"))?;
                if current.state != "writing_pointers" {
                    return Err(RpcError::FailedPrecondition(
                        "publication pointer phase changed concurrently".into(),
                    ));
                }
            }
        } else if publication.state != "writing_pointers" {
            return Err(RpcError::FailedPrecondition(
                "publication is not ready to commit".into(),
            ));
        }

        for progress in self
            .db
            .registry_publication_placement_records(&req.publication_id)
            .await
            .map_err(RpcError::internal)?
        {
            if !progress.required || progress.state == "ready" {
                continue;
            }
            let mut placement = self
                .db
                .surface_placement(progress.placement_id)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::FailedPrecondition("placement disappeared".into()))?;
            if progress.state == "preparing" {
                let watermark_version = placement.watermark_resource_version.ok_or_else(|| {
                    RpcError::FailedPrecondition("placement has no publication watermark".into())
                })?;
                placement = self
                    .db
                    .begin_registry_pointer_advance(
                        &req.publication_id,
                        placement.id,
                        placement.resource_version,
                        watermark_version,
                        clock::now_unix_secs(),
                    )
                    .await
                    .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
            }
            let watermark_version = placement.watermark_resource_version.ok_or_else(|| {
                RpcError::FailedPrecondition("placement has no publication watermark".into())
            })?;
            self.db
                .finalize_registry_pointer_advance(
                    &req.publication_id,
                    placement.id,
                    placement.resource_version,
                    watermark_version,
                    clock::now_unix_secs(),
                )
                .await
                .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        }
        self.db
            .promote_registry_publication_mutable_objects(&req.publication_id)
            .await
            .map_err(RpcError::internal)?;
        if !self
            .db
            .advance_registry_publication(
                &req.publication_id,
                "writing_pointers",
                "ready",
                clock::now_unix_secs(),
            )
            .await
            .map_err(RpcError::internal)?
        {
            return Err(RpcError::FailedPrecondition(
                "publication could not become ready".into(),
            ));
        }
        let state = self
            .db
            .registry_publication_state(registry.id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::Internal)?;
        self.db
            .set_current_registry_publication(
                registry.id,
                &req.publication_id,
                Some(state.resource_version),
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        self.db
            .refresh_registry_publication_delivery_manifests(&req.publication_id)
            .await
            .map_err(RpcError::internal)?;
        self.lease.release(registry.id, &req.publication_id).await;
        self.refresh_registry_index_after_publication(&registry, &req.publication_id)
            .await;
        self.registry_publication_response(&req.publication_id, true)
            .await
    }

    /// Aborts an incomplete publication without exposing any of its objects.
    ///
    /// Placements that entered the mutable-pointer phase remain failed until
    /// reconciliation restores a complete ready publication; aborting never
    /// guesses that partially written mutable state is safe to serve.
    ///
    /// # Errors
    ///
    /// Returns an authorization or not-found error, a failed precondition for
    /// a ready or retired publication, or an internal database error.
    pub async fn abort_registry_publication(
        &self,
        auth: Option<&str>,
        req: pb::AbortRegistryPublicationRequest,
    ) -> Result<pb::RegistryPublication, RpcError> {
        let claims = self.require_claims(auth)?;
        let publication = self
            .db
            .registry_publication(&req.publication_id)
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
        if let Some(state) = self
            .db
            .staged_publication_state(&req.publication_id)
            .await
            .map_err(RpcError::internal)?
        {
            if state == "releasing" {
                return Err(RpcError::FailedPrecondition(
                    "frozen staged release finalization must be resumed".into(),
                ));
            }
        }
        if publication.state == "failed" {
            self.lease.release(registry.id, &req.publication_id).await;
            return self
                .registry_publication_response(&req.publication_id, true)
                .await;
        }
        if !matches!(publication.state.as_str(), "preparing" | "writing_pointers") {
            return Err(RpcError::FailedPrecondition(
                "only an incomplete publication can be aborted".into(),
            ));
        }
        for upload in self
            .db
            .active_registry_publication_multipart_uploads(&req.publication_id)
            .await
            .map_err(RpcError::internal)?
        {
            self.abort_registry_publication_multipart_record(auth, upload)
                .await?;
        }
        self.db
            .fail_registry_publication(&req.publication_id, clock::now_unix_secs())
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        self.lease.release(registry.id, &req.publication_id).await;
        self.registry_publication_response(&req.publication_id, true)
            .await
    }
}
