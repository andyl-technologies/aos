//! Coordination helpers in the runtime capability.

use super::*;

impl RpcService {
    /// Whether `claims`'s principal may create an org under `invite_only`.
    ///
    /// Permitted for a service-account caller, an existing org member, an
    /// instance admin (an `iam.admin` grant at the instance root), or a user
    /// holding a live invitation for their email.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Internal`] on database failure.
    pub(in crate::service) async fn signup_permitted(
        &self,
        claims: &Claims,
    ) -> Result<bool, RpcError> {
        let Some(principal) = claims_principal(claims) else {
            return Ok(false);
        };
        if !self
            .db
            .principal_is_live(principal.kind.as_str(), principal.id)
            .await
            .map_err(RpcError::internal)?
        {
            return Ok(false);
        }
        if principal.kind != PrincipalKind::User {
            return Ok(true);
        }
        if self
            .db
            .user_has_any_membership(principal.id)
            .await
            .map_err(RpcError::internal)?
        {
            return Ok(true);
        }
        // Instance admin: an iam.admin grant at the instance root.
        let grants = self
            .db
            .effective_scopes(principal)
            .await
            .map_err(RpcError::internal)?;
        if iam::allow(
            &grants,
            Permission::IamAdmin,
            &iam::AuthorizationContext::instance(),
        ) {
            return Ok(true);
        }
        // A live invitation for the caller's email.
        if let Some(email) = self
            .db
            .user_email(principal.id)
            .await
            .map_err(RpcError::internal)?
        {
            if self
                .db
                .has_pending_invitation(&email)
                .await
                .map_err(RpcError::internal)?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(in crate::service) async fn record_consumer_publication_intent(
        &self,
        registry: &RegistryRecord,
        change_id: &str,
        change: &pb::ConsumerCacheChange,
        ready_routes: &std::collections::BTreeMap<
            String,
            crate::db::ReadyRouteAdvertisementIdentity,
        >,
    ) -> Result<(), RpcError> {
        let Some(source) = change
            .desired
            .as_ref()
            .and_then(|entry| entry.source.as_ref())
        else {
            return Ok(());
        };
        match source {
            pb::consumer_cache_stack_entry::Source::BinaryCacheId(cache_id) => {
                let cache = self.binary_cache_or_not_found(cache_id).await?;
                let route = ready_routes
                    .get(
                        &change
                            .desired
                            .as_ref()
                            .map(|entry| entry.entry_id.clone())
                            .unwrap_or_else(|| change.entry_id.clone()),
                    )
                    .ok_or_else(|| {
                        RpcError::FailedPrecondition(
                            "managed cache plan lacks an immutable ready route".to_string(),
                        )
                    })?;
                self.db
                    .record_consumer_cache_publication_intent(
                        change_id,
                        registry.id,
                        cache.id,
                        route,
                    )
                    .await
                    .map_err(RpcError::internal)
            }
            pb::consumer_cache_stack_entry::Source::External(external) => self
                .db
                .record_external_consumer_cache_publication_intent(
                    change_id,
                    registry.id,
                    &external.url,
                )
                .await
                .map_err(RpcError::internal),
        }
    }

    /// Whether `claims` may read `registry`, as a non-erroring list filter.
    ///
    /// A registry under a soft-deleted org is hidden; a `public` (or unowned
    /// phase-1) registry reads anonymously; an `internal`/`private` registry
    /// needs [`Permission::Read`] on the registry scope.
    pub(in crate::service) async fn can_read(
        &self,
        claims: Option<&Claims>,
        registry: &RegistryRecord,
    ) -> bool {
        if let Some(org_id) = registry.org_id {
            if !matches!(self.db.org_is_active(org_id).await, Ok(true)) {
                return false;
            }
        }
        if registry.visibility == "public" || registry.org_id.is_none() {
            return true;
        }
        let Ok(scope) = self.registry_scope(registry).await else {
            return false;
        };
        self.claims_allow(claims, Permission::Read, &scope).await
    }

    /// Resolve a registry's last-indexed HEAD commit oid.
    ///
    /// The `GitService` reads walk from the registry's tracked-branch HEAD, the
    /// last commit the indexer verified.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::FailedPrecondition`] when the registry has not been
    /// indexed yet, [`RpcError::InvalidArgument`] when the recorded commit is
    /// not a valid oid, and [`RpcError::Internal`] on database failure.
    pub(in crate::service) async fn head_commit(
        &self,
        registry: &RegistryRecord,
    ) -> Result<Oid, RpcError> {
        let hex = self
            .db
            .index_status(registry.id)
            .await
            .map_err(RpcError::internal)?
            .and_then(|s| s.last_indexed_commit)
            .ok_or_else(|| {
                RpcError::FailedPrecondition("registry has no indexed commit yet".into())
            })?;
        Oid::from_hex(&hex).map_err(|e| RpcError::invalid(format!("{e:#}")))
    }

    pub(in crate::service) fn image_object_url(
        download_base: &str,
        object_key: &str,
    ) -> Result<String, RpcError> {
        let mut url = url::Url::parse(download_base).map_err(RpcError::internal)?;
        url.path_segments_mut()
            .map_err(|_| {
                RpcError::internal(anyhow::anyhow!(
                    "canonical image delivery URL cannot carry paths"
                ))
            })?
            .pop_if_empty()
            .extend(object_key.split('/'));
        Ok(url.to_string())
    }

    pub(in crate::service) fn control_image_download_base(
        &self,
        registry_id: i64,
    ) -> Result<String, RpcError> {
        let mut url = url::Url::parse(&self.external_url).map_err(RpcError::internal)?;
        url.path_segments_mut()
            .map_err(|_| RpcError::internal(anyhow::anyhow!("Hub URL cannot carry paths")))?
            .pop_if_empty()
            .extend(["-", "images", &registry_id.to_string(), ""]);
        Ok(url.to_string())
    }

    pub(in crate::service) fn system_image_message(
        &self,
        download_base: &str,
        image: crate::db::IndexedSystemImage,
        channel: Option<&str>,
        cache_urls: &[String],
        cache_delivery: bool,
    ) -> Result<pb::SystemImage, RpcError> {
        let delivery = image.delivery;
        let store_backed =
            delivery.is_store_backed() || (cache_delivery && !image.store_path.is_empty());
        Ok(pb::SystemImage {
            package: image.package,
            release: image.release,
            channel: channel.unwrap_or_default().to_string(),
            platform: image.platform,
            architecture: delivery.architecture,
            format: image.format,
            logical_image_id: delivery.logical_image_id,
            filename: delivery.filename,
            download_url: if store_backed {
                String::new()
            } else {
                Self::image_object_url(download_base, &delivery.object_key)?
            },
            media_type: delivery.media_type,
            compression: image_compression_name(delivery.compression).to_string(),
            byte_size: delivery.byte_size,
            sha256: delivery.sha256,
            compatible_targets: delivery
                .compatible_targets
                .into_iter()
                .map(image_target_name)
                .map(str::to_string)
                .collect(),
            boot_verification: format!("provider-contract:{}", delivery.artifact_contract.schema),
            object_key: delivery.object_key,
            image_info: Some(pb::ImageInfo {
                filename: delivery.artifact_contract.document.filename,
                download_url: if store_backed {
                    String::new()
                } else {
                    Self::image_object_url(
                        download_base,
                        &delivery.artifact_contract.document.object_key,
                    )?
                },
                object_key: delivery.artifact_contract.document.object_key,
                media_type: delivery.artifact_contract.document.media_type,
                byte_size: delivery.artifact_contract.document.byte_size,
                sha256: delivery.artifact_contract.document.sha256,
                store_path: delivery.artifact_contract.document.store_path,
                nar_hash: delivery.artifact_contract.document.nar_hash,
                nar_size: delivery.artifact_contract.document.nar_size,
            }),
            logical_disk_sha256: delivery.logical_disk_sha256,
            rootfs_sha256: String::new(),
            uki: None,
            release_verification: "verified".to_string(),
            store_path: store_backed.then_some(image.store_path).unwrap_or_default(),
            nar_hash: store_backed.then_some(image.nar_hash).unwrap_or_default(),
            nar_size: if store_backed { image.nar_size } else { 0 },
            cache_urls: cache_urls.to_vec(),
        })
    }

    pub(in crate::service) fn canonicalize_object_storage_provider(
        bucket: &mut String,
        prefix: &mut String,
        endpoint: &mut Option<pb::StorageEndpoint>,
        signing_region: &mut String,
        access_mode: &mut String,
    ) -> Result<(), RpcError> {
        *bucket = bucket.trim().to_string();
        *prefix = prefix.trim_matches('/').to_string();
        *signing_region = signing_region.trim().to_string();
        *access_mode = access_mode.trim().to_ascii_lowercase();
        if bucket.is_empty() || signing_region.is_empty() {
            return Err(RpcError::invalid(
                "object storage requires bucket and signingRegion",
            ));
        }
        if !matches!(access_mode.as_str(), "public" | "private") {
            return Err(RpcError::invalid(
                "object storage accessMode must be public or private",
            ));
        }
        let endpoint = endpoint
            .as_mut()
            .ok_or_else(|| RpcError::invalid("object storage endpoint is required"))?;
        endpoint.scheme = endpoint.scheme.trim().to_ascii_lowercase();
        if endpoint.scheme != "https" {
            return Err(RpcError::invalid("storage endpoints must use https"));
        }
        if endpoint.port == 0 {
            endpoint.port = 443;
        }
        let authority = match endpoint.host.as_mut() {
            Some(pb::storage_endpoint::Host::DnsName(name)) => {
                *name = crate::db::canonical_delivery_hostname(name)
                    .map_err(|error| RpcError::invalid(format!("endpoint DNS name: {error:#}")))?;
                name.clone()
            }
            Some(pb::storage_endpoint::Host::Ipv4(bytes)) if bytes.len() == 4 => {
                let ip = std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
                if !crate::url_guard::is_global_ip(std::net::IpAddr::V4(ip)) {
                    return Err(RpcError::invalid(
                        "storage endpoint IP must be globally routable",
                    ));
                }
                ip.to_string()
            }
            Some(pb::storage_endpoint::Host::Ipv6(bytes)) if bytes.len() == 16 => {
                let octets: [u8; 16] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| RpcError::invalid("endpoint IPv6 length is invalid"))?;
                let ip = std::net::Ipv6Addr::from(octets);
                if !crate::url_guard::is_global_ip(std::net::IpAddr::V6(ip)) {
                    return Err(RpcError::invalid(
                        "storage endpoint IP must be globally routable",
                    ));
                }
                format!("[{ip}]")
            }
            Some(_) => return Err(RpcError::invalid("endpoint IP length is invalid")),
            None => return Err(RpcError::invalid("endpoint host is required")),
        };
        crate::url_guard::is_safe_remote_url(&format!("https://{authority}:{}/", endpoint.port))
            .map_err(|error| RpcError::invalid(format!("storage endpoint: {error:#}")))?;
        Ok(())
    }

    /// Maps typed authority preconditions while preserving infrastructure failures.
    pub(in crate::service) fn authority_mutation_error(error: anyhow::Error) -> RpcError {
        match crate::db::surface_write_authority_mutation_failure(&error) {
            Some(failure) => RpcError::FailedPrecondition(failure.public_message().to_string()),
            None => RpcError::internal(error),
        }
    }

    pub(in crate::service) fn policy_retry_name(value: i32) -> Result<String, RpcError> {
        let condition = pb::PolicyRetryCondition::try_from(value)
            .map_err(|_| RpcError::invalid("unknown placement-policy retry condition"))?;
        match condition {
            pb::PolicyRetryCondition::Unspecified => Err(RpcError::invalid(
                "retryOn cannot contain the unspecified value",
            )),
            pb::PolicyRetryCondition::ConnectFailure => Ok("connect_failure".to_string()),
            pb::PolicyRetryCondition::TimeoutBeforeHeaders => {
                Ok("timeout_before_headers".to_string())
            }
            pb::PolicyRetryCondition::Origin429 => Ok("origin_429".to_string()),
            pb::PolicyRetryCondition::Origin502 => Ok("origin_502".to_string()),
            pb::PolicyRetryCondition::Origin503 => Ok("origin_503".to_string()),
            pb::PolicyRetryCondition::Origin504 => Ok("origin_504".to_string()),
            pb::PolicyRetryCondition::PresenceMismatch => Ok("presence_mismatch".to_string()),
            pb::PolicyRetryCondition::VerifiedCorruption => Ok("verified_corruption".to_string()),
        }
    }

    pub(in crate::service) fn policy_retry_value(value: &str) -> Result<i32, RpcError> {
        let value = match value {
            "connect_failure" => pb::PolicyRetryCondition::ConnectFailure,
            "timeout_before_headers" => pb::PolicyRetryCondition::TimeoutBeforeHeaders,
            "origin_429" => pb::PolicyRetryCondition::Origin429,
            "origin_502" => pb::PolicyRetryCondition::Origin502,
            "origin_503" => pb::PolicyRetryCondition::Origin503,
            "origin_504" => pb::PolicyRetryCondition::Origin504,
            "presence_mismatch" => pb::PolicyRetryCondition::PresenceMismatch,
            "verified_corruption" => pb::PolicyRetryCondition::VerifiedCorruption,
            _ => {
                return Err(RpcError::internal(anyhow::anyhow!(
                    "persisted placement-policy retry condition is invalid"
                )));
            }
        };
        Ok(value as i32)
    }

    pub(in crate::service) async fn serve_signed_image_object(
        &self,
        registry: &RegistryRecord,
        path: &str,
        request: crate::image_http::ImageHttpRequest<'_>,
    ) -> Result<RegistryServeOutcome, RpcError> {
        use crate::db::IndexedSystemImageObject;
        use crate::image_http::{plan_image_response, ImageAccess, ImageHttpMetadata};
        use axum::body::Body;
        use axum::http::{header, HeaderName, HeaderValue, StatusCode};

        let object = self
            .db
            .system_image_object_by_key(registry.id, path)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("signed image object"))?;
        let metadata = match &object {
            IndexedSystemImageObject::Disk(image) => ImageHttpMetadata {
                filename: image.delivery.filename.clone(),
                media_type: image.delivery.media_type.clone(),
                byte_size: image.delivery.byte_size,
                sha256: image.delivery.sha256.clone(),
            },
            IndexedSystemImageObject::ImageInfo(image) => ImageHttpMetadata {
                filename: image.delivery.artifact_contract.document.filename.clone(),
                media_type: image.delivery.artifact_contract.document.media_type.clone(),
                byte_size: image.delivery.artifact_contract.document.byte_size,
                sha256: image.delivery.artifact_contract.document.sha256.clone(),
            },
        };
        let access = if registry.visibility == "public" {
            ImageAccess::Public
        } else {
            ImageAccess::Private
        };
        let plan = plan_image_response(&metadata, access, request)
            .map_err(|error| RpcError::invalid(format!("invalid image request: {error:#}")))?;
        let status = StatusCode::from_u16(plan.status).map_err(RpcError::internal)?;
        let mut response = axum::response::Response::builder().status(status);
        for (name, value) in &plan.headers {
            response = response.header(
                HeaderName::from_bytes(name.as_bytes()).map_err(RpcError::internal)?,
                HeaderValue::from_str(value).map_err(RpcError::internal)?,
            );
        }
        if access == ImageAccess::Private {
            response = response.header(header::VARY, "Authorization, Cookie");
        }
        let Some(body_range) = plan.body_range else {
            return Ok(RegistryServeOutcome::Response(
                response.body(Body::empty()).map_err(RpcError::internal)?,
            ));
        };
        let requested = (plan.status == 206).then_some((body_range.start, body_range.end));
        let read = match placement_read::stream_verified_image_from_placements(
            self.db.as_ref(),
            self.surface.as_ref(),
            registry.id,
            path,
            &metadata.sha256,
            metadata.byte_size,
            requested,
        )
        .await
        .map_err(RpcError::surface_read)?
        {
            PlacementReadOutcome::Found(read) => read.value,
            PlacementReadOutcome::NotFound => return Ok(RegistryServeOutcome::NotFound),
        };
        if read.total != metadata.byte_size
            || (plan.status == 206 && read.range != Some((body_range.start, body_range.end)))
        {
            return Err(RpcError::FailedPrecondition(
                "stored image bytes do not match signed delivery metadata".to_string(),
            ));
        }
        let body = exact_image_body(read.body, body_range.end - body_range.start + 1);
        Ok(RegistryServeOutcome::Response(
            response.body(body).map_err(RpcError::internal)?,
        ))
    }

    /// Builds the `200`/`206` response for a streamed surface object.
    ///
    /// Shared by the local-surface read and the streamed-origin proxy: a
    /// `StreamedRead` with a `Some` range becomes a `206 Partial Content` with
    /// `Content-Range`/`Content-Length`, and a `None` range a `200 OK` with
    /// `Content-Length`; both advertise `Accept-Ranges: bytes`. The selected
    /// topology placement is recorded only in structured server logs so an
    /// unauthenticated response cannot disclose internal storage topology.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Internal`] if the response builder rejects a header.
    pub(in crate::service) fn streamed_surface_response(
        path: &str,
        read: crate::fetch::StreamedRead,
    ) -> Result<axum::response::Response, RpcError> {
        use axum::http::{header, StatusCode};
        let ct = keymap::content_type(path);
        let cc = keymap::cache_control(path);
        let mut builder = axum::response::Response::builder();
        if keymap::is_producer_document(path) {
            builder = builder
                .header(header::CONTENT_SECURITY_POLICY, "sandbox")
                .header(header::CONTENT_DISPOSITION, "attachment");
        }
        let resp = match read.range {
            Some((start, end)) => builder
                .status(StatusCode::PARTIAL_CONTENT)
                .header(header::CONTENT_TYPE, ct)
                .header(header::CACHE_CONTROL, cc)
                .header(header::ACCEPT_RANGES, "bytes")
                .header(
                    header::CONTENT_RANGE,
                    format!("bytes {start}-{end}/{}", read.total),
                )
                .header(header::CONTENT_LENGTH, end - start + 1)
                .body(read.body),
            None => builder
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, ct)
                .header(header::CACHE_CONTROL, cc)
                .header(header::ACCEPT_RANGES, "bytes")
                .header(header::CONTENT_LENGTH, read.total)
                .body(read.body),
        }
        .map_err(|e| RpcError::internal(anyhow::anyhow!("{e}")))?;
        Ok(resp)
    }

    pub(in crate::service) async fn replayed_control_result<T: serde::de::DeserializeOwned>(
        &self,
        auth: Option<&str>,
        plan_id: &str,
        plan_kind: &str,
        confirmation_hash: Option<&str>,
        idempotency_key: &str,
    ) -> Result<Option<T>, RpcError> {
        if idempotency_key.is_empty() {
            return Err(RpcError::invalid("idempotency_key is required"));
        }
        let claims = self.require_claims(auth)?;
        let plan = self
            .db
            .topology_plan(plan_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("topology plan"))?;
        if plan.plan_kind != plan_kind
            || plan.actor_kind != claims.owner_kind
            || plan.actor_id != Some(claims.owner_id)
        {
            return Err(RpcError::FailedPrecondition(
                "plan belongs to another actor or operation".to_string(),
            ));
        }
        if let Some(expected) = plan.confirmation_hash.as_deref() {
            if confirmation_hash != Some(expected) {
                return Err(RpcError::FailedPrecondition(
                    "confirmation hash does not match the reviewed plan".to_string(),
                ));
            }
        }
        if plan.applied_at.is_none() {
            if plan.apply_idempotency_key.is_some()
                && plan.apply_idempotency_key.as_deref() != Some(idempotency_key)
            {
                return Err(RpcError::FailedPrecondition(
                    "plan apply is reserved by another idempotency key".to_string(),
                ));
            }
            return Ok(None);
        }
        if plan.apply_idempotency_key.as_deref() != Some(idempotency_key) {
            return Err(RpcError::FailedPrecondition(
                "plan was already applied with another idempotency key".to_string(),
            ));
        }
        let result = plan.apply_result_json.ok_or_else(|| {
            RpcError::internal(anyhow::anyhow!("applied plan has no replay result"))
        })?;
        serde_json::from_str(&result)
            .map(Some)
            .map_err(RpcError::internal)
    }

    pub(in crate::service) async fn consumer_entry_url(
        &self,
        auth: Option<&str>,
        registry: &RegistryRecord,
        entry: &pb::ConsumerCacheStackEntry,
    ) -> Result<String, RpcError> {
        match entry.source.as_ref() {
            Some(pb::consumer_cache_stack_entry::Source::BinaryCacheId(cache_id)) => {
                let cache = self.binary_cache_or_not_found(cache_id).await?;
                self.require_cache_read(auth, &cache).await?;
                let claims = self.require_claims(auth)?;
                self.require_permission(
                    &claims,
                    Permission::RegistryConfigure,
                    &self.registry_scope(&registry).await?,
                )
                .await?;
                self.db
                    .ready_cache_canonical_url(cache.id)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| {
                        RpcError::FailedPrecondition(
                            "managed cache canonical Nix-cache route is not ready".to_string(),
                        )
                    })
            }
            Some(pb::consumer_cache_stack_entry::Source::External(external)) => {
                crate::url_guard::is_safe_remote_url(&external.url).map_err(|error| {
                    RpcError::invalid(format!("unsafe external cache URL: {error:#}"))
                })?;
                Ok(external.url.clone())
            }
            None => Err(RpcError::invalid("consumer cache entry source is required")),
        }
    }

    pub(in crate::service) async fn root_reason_message(
        &self,
        cache_id: &str,
        record: &crate::db::CacheRootReasonRecord,
    ) -> Result<pb::RootReason, RpcError> {
        let registry_id = match record.registry_id {
            Some(id) => {
                self.db
                    .registry_by_id(id)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| RpcError::not_found("registry"))?
                    .slug
            }
            None => String::new(),
        };
        Ok(pb::RootReason {
            reason_id: record.id.to_string(),
            cache_id: cache_id.to_string(),
            store_hash: record.store_hash.clone(),
            source_kind: record.source_kind.clone(),
            registry_id,
            retention_subscription_id: record
                .retention_subscription_id
                .map(|id| id.to_string())
                .unwrap_or_default(),
            manual_retention_root_id: record
                .manual_retention_root_id
                .as_ref()
                .map(|id| id.to_string())
                .unwrap_or_default(),
            retention_lease_id: record
                .retention_lease_id
                .as_ref()
                .map(|id| id.to_string())
                .unwrap_or_default(),
            release_id: record
                .release_id
                .map(|id| id.to_string())
                .unwrap_or_default(),
            reason_key: record.reason_key.clone(),
        })
    }

    /// Enqueues population for an exact optional release tag.
    ///
    /// # Errors
    ///
    /// Returns an authorization, not-found, ambiguity, or database error.
    pub(in crate::service) async fn execute_run_population(
        &self,
        auth: Option<&str>,
        req: pb::PlanRunPopulationRequest,
    ) -> Result<pb::OperationResponse, RpcError> {
        let (cache, registry) = self
            .authorized_cache_registry_pair(auth, &req.cache_id, &req.registry_id, true)
            .await?;
        let target = self.single_population_target(cache.id, registry.id).await?;
        if parse_resource_version(&req.expected_resource_version, target.resource_version)?
            != target.resource_version
        {
            return Err(RpcError::FailedPrecondition(
                "population target resource version is stale".to_string(),
            ));
        }
        self.create_cache_operation(
            cache.id,
            "population",
            Permission::StorageManage,
            serde_json::json!({ "registryId": registry.id, "releaseTag": req.release_tag }),
        )
        .await
    }

    /// Enqueues a coverage validation operation.
    ///
    /// # Errors
    ///
    /// Returns an authorization, not-found, or database error.
    pub(in crate::service) async fn execute_run_coverage_validation(
        &self,
        auth: Option<&str>,
        req: pb::PlanCoverageOperationRequest,
    ) -> Result<pb::OperationResponse, RpcError> {
        let (cache, registry) = self
            .authorized_cache_registry_pair(auth, &req.cache_id, &req.registry_id, false)
            .await?;
        let target = self.single_population_target(cache.id, registry.id).await?;
        if parse_resource_version(&req.expected_resource_version, target.resource_version)?
            != target.resource_version
        {
            return Err(RpcError::FailedPrecondition(
                "population target resource version is stale".to_string(),
            ));
        }
        self.create_cache_operation(
            cache.id,
            "coverage_validation",
            Permission::Read,
            serde_json::json!({ "registryId": registry.id }),
        )
        .await
    }

    /// Enqueues a coverage repair operation.
    ///
    /// # Errors
    ///
    /// Returns an authorization, not-found, or database error.
    pub(in crate::service) async fn execute_run_coverage_repair(
        &self,
        auth: Option<&str>,
        req: pb::PlanCoverageOperationRequest,
    ) -> Result<pb::OperationResponse, RpcError> {
        let (cache, registry) = self
            .authorized_cache_registry_pair(auth, &req.cache_id, &req.registry_id, true)
            .await?;
        let target = self.single_population_target(cache.id, registry.id).await?;
        if parse_resource_version(&req.expected_resource_version, target.resource_version)?
            != target.resource_version
        {
            return Err(RpcError::FailedPrecondition(
                "population target resource version is stale".to_string(),
            ));
        }
        self.create_cache_operation(
            cache.id,
            "coverage_repair",
            Permission::StorageManage,
            serde_json::json!({ "registryId": registry.id }),
        )
        .await
    }

    pub(in crate::service) fn validate_population_spec(
        spec: &pb::PopulationTargetSpec,
    ) -> Result<(), RpcError> {
        if !matches!(spec.trigger.as_str(), "release" | "manual" | "continuous") {
            return Err(RpcError::invalid(
                "population trigger must be release, manual, or continuous",
            ));
        }
        if !matches!(
            spec.validation_gate.as_str(),
            "none" | "presence" | "integrity"
        ) {
            return Err(RpcError::invalid(
                "validation gate must be none, presence, or integrity",
            ));
        }
        Ok(())
    }

    pub(in crate::service) async fn population_target_for_pair(
        &self,
        cache_id: i64,
        registry_id: i64,
    ) -> Result<Option<crate::db::CachePopulationTargetRecord>, RpcError> {
        let matches = self
            .db
            .list_cache_population_targets(cache_id)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .filter(|target| target.registry_id == registry_id)
            .collect::<Vec<_>>();
        if matches.len() > 1 {
            return Err(RpcError::FailedPrecondition(
                "multiple population targets exist for one cache/registry pair".to_string(),
            ));
        }
        Ok(matches.into_iter().next())
    }

    pub(in crate::service) async fn single_population_target(
        &self,
        cache_id: i64,
        registry_id: i64,
    ) -> Result<crate::db::CachePopulationTargetRecord, RpcError> {
        self.population_target_for_pair(cache_id, registry_id)
            .await?
            .ok_or_else(|| RpcError::not_found("population target"))
    }

    pub(in crate::service) fn population_target_message(
        record: &crate::db::CachePopulationTargetRecord,
        cache_id: &str,
        registry_id: &str,
    ) -> pb::PopulationTarget {
        pb::PopulationTarget {
            target_id: record.id.to_string(),
            cache_id: cache_id.to_string(),
            registry_id: registry_id.to_string(),
            desired: Some(pb::PopulationTargetSpec {
                trigger: record.trigger_kind.clone(),
                required: record.required,
                placement_policy_revision_id: record
                    .placement_policy_revision_id
                    .clone()
                    .unwrap_or_default(),
                validation_gate: record.validation_gate.clone(),
            }),
            state: if record.enabled {
                "enabled"
            } else {
                "disabled"
            }
            .to_string(),
            resource_version: record.resource_version.to_string(),
        }
    }

    /// Builds the public desired/observed authority view using placement names.
    pub(in crate::service) async fn write_authority_message(
        &self,
        authority: crate::db::SurfaceWriteAuthorityRecord,
    ) -> Result<pb::SurfaceWriteAuthority, RpcError> {
        let desired = self
            .db
            .surface_placement(authority.desired_placement_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::internal(anyhow::anyhow!("desired writer is missing")))?;
        let observed_placement_name = match authority.observed_placement_id {
            Some(id) => {
                self.db
                    .surface_placement(id)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| {
                        RpcError::internal(anyhow::anyhow!("observed writer is missing"))
                    })?
                    .name
            }
            None => String::new(),
        };
        Ok(Self::write_authority_message_with_names(
            authority,
            desired.name,
            observed_placement_name,
        ))
    }

    pub(in crate::service) fn write_authority_message_with_names(
        authority: crate::db::SurfaceWriteAuthorityRecord,
        desired_placement_name: String,
        observed_placement_name: String,
    ) -> pb::SurfaceWriteAuthority {
        pb::SurfaceWriteAuthority {
            mode: authority.mode,
            desired_placement_name,
            observed_placement_name,
            desired_write_spec_version: authority.desired_write_spec_version,
            observed_write_spec_version: authority.observed_write_spec_version.unwrap_or_default(),
            desired_binding_write_revision: authority.desired_binding_write_revision,
            observed_binding_write_revision: authority
                .observed_binding_write_revision
                .unwrap_or_default(),
            desired_generation: authority.desired_generation,
            observed_generation: authority.observed_generation.unwrap_or_default(),
            reconciliation_state: authority.reconciliation_state,
            reconciliation_error: authority.reconciliation_error.unwrap_or_default(),
            resource_version: authority.resource_version.to_string(),
            incarnation_id: authority.incarnation_id,
        }
    }
}
