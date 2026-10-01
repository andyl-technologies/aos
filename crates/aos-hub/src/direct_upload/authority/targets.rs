//! Exact target scopes, required physical placements and accounting statements.

use aos_hub_core::{
    db::{BinaryCache, OciUploadRecord, SurfacePlacementRecord},
    domain::{Permission, Scope},
    hybrid_ingress::HybridObjectProjection,
    keymap,
};

use super::*;

pub(super) enum TargetOwner {
    Cache(BinaryCache),
    Publication,
    Oci(OciUploadRecord),
}

pub(super) struct Target {
    pub scope: String,
    pub path: String,
    pub expires_at: i64,
    pub placements: Vec<SurfacePlacementRecord>,
    pub owner: TargetOwner,
}

impl NativeDirectUploadAuthority {
    pub(super) async fn ensure_new_effect_accounting(
        &self,
        intent: &DirectUploadIntent,
    ) -> Result<()> {
        if let DirectUploadTarget::PublicationObject {
            surface_object_id, ..
        } = &intent.target
        {
            self.db
                .verified_registry_object_accounting_eligibility(i64::try_from(
                    surface_object_id.get(),
                )?)
                .await?;
        }
        Ok(())
    }
}

impl NativeDirectUploadAuthority {
    pub(super) async fn resolve_target(
        &self,
        claims: &Claims,
        actor: &DirectActorSlot,
        intent: &DirectUploadIntent,
        prepare: bool,
        now: i64,
    ) -> Result<Target> {
        ensure!(
            self.current_actor(claims).await? == *actor,
            "direct original actor authority unavailable"
        );
        let mut target = match &intent.target {
            DirectUploadTarget::CacheObject { cache_id, path } => {
                let cache = match self.db.binary_cache_by_stable_id(cache_id).await? {
                    Some(cache) => cache,
                    None => self
                        .db
                        .binary_cache_by_slug(cache_id)
                        .await?
                        .context("direct cache absent")?,
                };
                ensure!(
                    cache.deleted_at.is_none()
                        && keymap::is_machine_path(path)
                        && aos_hub_core::url_guard::validate_http_surface_path(path).is_ok(),
                    "direct cache path unavailable"
                );
                self.check_org(cache.org_id).await?;
                self.require_permission(
                    claims,
                    Permission::RegistryConfigure,
                    &Scope::parse(&cache.scope_key),
                )
                .await?;
                let placements = self
                    .db
                    .list_surface_placements(SurfaceTarget::BinaryCache(cache.id))
                    .await?
                    .into_iter()
                    .filter(|row| row.effective_write_enabled)
                    .collect();
                Target {
                    scope: cache.scope_key.clone(),
                    path: path.clone(),
                    expires_at: now.saturating_add(3600),
                    placements,
                    owner: TargetOwner::Cache(cache),
                }
            }
            DirectUploadTarget::PublicationObject {
                publication_id,
                surface_object_id,
                path,
            } => {
                let publication = self
                    .db
                    .registry_publication(publication_id)
                    .await?
                    .context("direct publication absent")?;
                let registry = self
                    .db
                    .registry_by_id(publication.registry_id)
                    .await?
                    .context("direct registry absent")?;
                self.check_org(registry.org_id).await?;
                let scope = self.db.registry_authorization_scope(registry.id).await?;
                self.require_permission(claims, Permission::Publish, &Scope::parse(&scope))
                    .await?;
                let object = self
                    .db
                    .registry_publication_upload_object(
                        publication_id,
                        i64::try_from(surface_object_id.get())?,
                    )
                    .await?
                    .context("direct publication object absent")?;
                ensure!(
                    object.object_key == *path
                        && object.expected_hash == intent.expected_sha256
                        && object.expected_size == i64::try_from(intent.byte_size.get())?,
                    "direct publication source differs from admitted manifest"
                );
                let placements = if prepare {
                    self.rpc
                        .prepare_direct_publication_upload(&publication, &registry, &object)
                        .await?
                } else {
                    let mut rows = Vec::new();
                    for progress in self
                        .db
                        .registry_publication_placement_records(publication_id)
                        .await?
                    {
                        if progress.required {
                            rows.push(
                                self.db
                                    .surface_placement(progress.placement_id)
                                    .await?
                                    .context("direct required placement absent")?,
                            );
                        }
                    }
                    rows
                };
                Target {
                    scope,
                    path: path.clone(),
                    expires_at: now.saturating_add(3600),
                    placements,
                    owner: TargetOwner::Publication,
                }
            }
            DirectUploadTarget::OciBlob { upload_id } => {
                let upload = if prepare {
                    self.db
                        .direct_oci_upload_for_actor(&self.deployment, actor, upload_id, now)
                        .await?
                } else {
                    self.db
                        .direct_oci_upload_for_actor_recovery(&self.deployment, actor, upload_id)
                        .await?
                };
                ensure!(
                    upload.expected_size == Some(intent.byte_size.get())
                        && upload.expected_digest.map(|item| item.encoded()).as_deref()
                            == Some(intent.expected_sha256.as_str()),
                    "direct OCI source differs from original allocation"
                );
                let registry = self
                    .db
                    .registry_by_id(upload.registry_id)
                    .await?
                    .context("direct OCI registry absent")?;
                self.check_org(registry.org_id).await?;
                let scope = self.db.registry_authorization_scope(registry.id).await?;
                self.require_permission(claims, Permission::Publish, &Scope::parse(&scope))
                    .await?;
                let placements = self
                    .db
                    .list_surface_placements(SurfaceTarget::Registry(registry.id))
                    .await?
                    .into_iter()
                    .filter(|row| row.effective_write_enabled)
                    .collect();
                Target {
                    scope,
                    path: aos_hub_core::db::oci_blob_object_key(
                        upload
                            .expected_digest
                            .context("direct OCI source digest absent")?,
                    ),
                    expires_at: upload.expires_at,
                    placements,
                    owner: TargetOwner::Oci(upload),
                }
            }
        };
        target.placements.sort_by_key(|row| row.id);
        Ok(target)
    }

    async fn require_permission(
        &self,
        claims: &Claims,
        permission: Permission,
        scope: &Scope,
    ) -> Result<()> {
        use aos_hub_core::service::RpcError;

        self.rpc
            .require_permission(claims, permission, scope)
            .await
            .map_err(|error| match error {
                RpcError::PermissionDenied(_) | RpcError::Unauthenticated(_) => {
                    anyhow::Error::new(DirectUploadRefusal {
                        code: DirectItemErrorCode::Denied,
                    })
                }
                other => anyhow::Error::new(other),
            })
    }

    async fn check_org(&self, org: Option<i64>) -> Result<()> {
        if let Some(org) = org {
            ensure!(
                self.db.org_is_active(org).await?,
                "direct target owner unavailable"
            );
        }
        Ok(())
    }

    pub(super) async fn resolve_placement(
        &self,
        row: &SurfacePlacementRecord,
        path: &str,
        intent: &DirectUploadIntent,
        profiles: &[DirectProtectedProfile],
    ) -> Result<DirectPlacement> {
        ensure!(
            row.desired_state == "active",
            "direct placement is not active"
        );
        let binding = self
            .db
            .binding(row.binding_id)
            .await?
            .context("direct binding absent")?;
        let revision = self.db.direct_placement_write_revision(row).await?;
        let selected = profiles
            .iter()
            .find(|profile| match profile {
                DirectProtectedProfile::Managed { .. } => {
                    binding.kind == "deployment_r2" && binding.is_instance_default
                }
                DirectProtectedProfile::External { profile, .. } => {
                    profile.selector.association.binding_stable_id == binding.stable_id
                        && profile.selector.association.binding_id.get() == binding.id
                        && profile.selector.association.binding_resource_version.get()
                            == binding.resource_version
                        && profile.selector.association.binding_write_revision.get() == revision
                        && profile.selector.association.binding_prefix
                            == binding.object_prefix.clone().unwrap_or_default()
                }
            })
            .context("direct binding has no independently accepted protected profile")?;
        let (physical, policy, prefix, checksum, write, read, presign, runtime) = match selected {
            DirectProtectedProfile::Managed {
                profile,
                private_stage_policy,
                runtime_qualification,
            } => {
                let credential = |purpose: &str| DirectCredentialRevision {
                    purpose: purpose.to_owned(),
                    credential_id: profile.credential_id.clone(),
                    generation: profile.credential_generation,
                    secret_version_ref: profile.secret_version_ref.clone(),
                    credential_fingerprint: profile.credential_fingerprint.clone(),
                };
                (
                    DirectPhysicalContext::DeploymentR2 {
                        deployment_id: self.deployment.clone(),
                        bucket_namespace: profile.bucket_namespace.clone(),
                    },
                    private_stage_policy.clone(),
                    ".aos-direct-upload".to_owned(),
                    profile.checksum_algorithm,
                    credential("write"),
                    credential("read"),
                    credential("presign"),
                    runtime_qualification,
                )
            }
            DirectProtectedProfile::External {
                profile,
                runtime_qualification,
            } => (
                DirectPhysicalContext::External {
                    write_cohort: Box::new(profile.write_cohort.clone()),
                    read_cohort: Box::new(profile.read_cohort.clone()),
                },
                profile.private_stage_policy.clone(),
                profile.staging_prefix.clone(),
                profile.checksum_algorithm,
                profile.selector.write_credential.clone(),
                profile.selector.read_credential.clone(),
                profile.selector.presign_credential.clone(),
                runtime_qualification,
            ),
        };
        ensure!(
            intent.byte_size.get() <= runtime.maximum_object_bytes.get(),
            "direct source exceeds accepted runtime limit"
        );
        for credential in [&write, &read, &presign] {
            if binding.kind == "deployment_r2" {
                continue;
            }
            let current = self
                .db
                .current_binding_credential(binding.id, &credential.purpose)
                .await?
                .context("direct current purpose credential absent")?;
            ensure!(
                current.validation_state == "valid"
                    && u64::try_from(current.generation)? == credential.generation.get(),
                "direct purpose credential generation changed"
            );
            if binding.kind != "deployment_r2" {
                ensure!(
                    current.secret_version_ref == credential.secret_version_ref
                        && current.credential_fingerprint == credential.credential_fingerprint,
                    "direct purpose credential publication changed"
                );
            }
        }
        let placement = DirectPlacement {
            placement_id: WireInteger::new(u64::try_from(row.id)?),
            placement_resource_version: WireInteger::new(u64::try_from(row.resource_version)?),
            write_spec_version: WireInteger::new(u64::try_from(row.write_spec_version)?),
            binding_id: WireInteger::new(u64::try_from(binding.id)?),
            binding_resource_version: WireInteger::new(u64::try_from(binding.resource_version)?),
            binding_write_revision: WireInteger::new(u64::try_from(revision)?),
            final_key: keymap::r2_key(&row.prefix, path),
            staging_prefix: prefix,
            private_stage_policy: policy,
            protected_profile_digest: selected.digest()?,
            checksum_algorithm: checksum,
            physical,
            write_credential: write,
            read_credential: read,
            presign_credential: presign,
        };
        placement.validate(&self.deployment)?;
        Ok(placement)
    }

    pub(super) async fn classify_stage(
        &self,
        record: &DirectUploadSessionRecord,
        evidence: &DirectVerifiedStageEvidence,
    ) -> Result<DirectDependencyPhase> {
        match &record.admission.intent.target {
            DirectUploadTarget::CacheObject { path, .. } if path.ends_with(".narinfo") => {
                let Some(HybridObjectProjection::Narinfo(projection)) = &evidence.projection else {
                    anyhow::bail!("direct narinfo verified projection absent");
                };
                projection.validate_cache_path(path)?;
                let DirectSqlOwner::Cache { cache_id, .. } = record.owner else {
                    anyhow::bail!("direct cache owner differs");
                };
                let cache = self
                    .db
                    .binary_cache_by_id(cache_id)
                    .await?
                    .context("direct cache absent")?;
                if let Some(key) = self
                    .db
                    .active_signing_key_for_usage(&cache.stable_id, "narinfo")
                    .await?
                {
                    projection.verify_selected_key(&key.name, &key.public_key)?;
                }
                let file_sha256 =
                    aos_core::nar::cache::canonical_sha256_hex(&projection.file_hash)?;
                let file_size: i64 = projection.file_size.parse()?;
                let direct_ready = self
                    .db
                    .direct_cache_content_ready(
                        cache_id,
                        &projection.nar_url,
                        &file_sha256,
                        file_size,
                    )
                    .await?;
                let existing = self
                    .db
                    .list_object_presence(SurfaceTarget::BinaryCache(cache_id), &projection.nar_url)
                    .await?;
                ensure!(
                    direct_ready
                        || existing.iter().any(|presence| presence.state == "present"
                            && presence.size == Some(file_size)
                            && presence.content_digest.as_deref() == Some(&file_sha256)),
                    "direct narinfo dependency NAR is not verified"
                );
                Ok(DirectDependencyPhase::LeafMetadata)
            }
            DirectUploadTarget::PublicationObject {
                publication_id,
                surface_object_id,
                ..
            } => {
                let object = self
                    .db
                    .registry_publication_upload_object(
                        publication_id,
                        i64::try_from(surface_object_id.get())?,
                    )
                    .await?
                    .context("direct publication object absent")?;
                Ok(if object.object_kind == "mutable_pointer" {
                    DirectDependencyPhase::Visibility
                } else {
                    DirectDependencyPhase::Content
                })
            }
            _ => {
                ensure!(
                    evidence.projection.is_none(),
                    "direct content cannot carry metadata projection"
                );
                Ok(DirectDependencyPhase::Content)
            }
        }
    }

    pub(super) async fn dependency_statements(
        &self,
        record: &DirectUploadSessionRecord,
    ) -> Result<Vec<CheckedStatement>> {
        match &record.admission.intent.target {
            DirectUploadTarget::CacheObject { path, .. } if path.ends_with(".narinfo") => {
                let Some(HybridObjectProjection::Narinfo(projection)) = record
                    .stage_evidence
                    .as_ref()
                    .and_then(|stage| stage.projection.as_ref())
                else {
                    anyhow::bail!("direct original narinfo projection absent");
                };
                let DirectSqlOwner::Cache { cache_id, .. } = record.owner else {
                    anyhow::bail!("direct cache owner differs");
                };
                let cache = self
                    .db
                    .binary_cache_by_id(cache_id)
                    .await?
                    .context("direct cache absent")?;
                let signing = self
                    .db
                    .active_signing_key_for_usage(&cache.stable_id, "narinfo")
                    .await?;
                if let Some(key) = &signing {
                    projection.verify_selected_key(&key.name, &key.public_key)?;
                }
                let hash = aos_core::nar::cache::canonical_sha256_hex(&projection.file_hash)?;
                let mut statements = self
                    .db
                    .direct_cache_dependency_locks(cache_id, &projection.nar_url, signing.as_ref())
                    .await?;
                statements.push(Database::direct_cache_metadata_fence(
                    cache_id,
                    &projection.nar_url,
                    &hash,
                    projection.file_size.parse()?,
                    signing.as_ref(),
                )?);
                Ok(statements)
            }
            DirectUploadTarget::PublicationObject {
                publication_id,
                surface_object_id,
                ..
            } => {
                let object = self
                    .db
                    .registry_publication_upload_object(
                        publication_id,
                        i64::try_from(surface_object_id.get())?,
                    )
                    .await?
                    .context("direct original publication object absent")?;
                Ok(vec![Database::direct_publication_phase_fence(
                    publication_id,
                    object.object_kind == "mutable_pointer",
                )?])
            }
            _ => Ok(Vec::new()),
        }
    }

    pub(super) async fn final_statements(
        &self,
        record: &DirectUploadSessionRecord,
        evidence: &DirectCompletionEvidence,
        now: i64,
    ) -> Result<Vec<CheckedStatement>> {
        let mut statements = record
            .admission
            .placements
            .iter()
            .map(Database::direct_placement_fence)
            .collect::<Result<Vec<_>>>()?;
        statements.extend(self.dependency_statements(record).await?);
        match (&record.owner, &record.admission.intent.target) {
            (DirectSqlOwner::Cache { ticket_id, .. }, DirectUploadTarget::CacheObject { .. }) => {
                let ticket = self
                    .db
                    .cache_write_ticket(ticket_id)
                    .await?
                    .context("direct cache ticket absent")?;
                ensure!(
                    ticket.intended_object_hash.as_deref() == Some(evidence.sha256.as_str())
                        && ticket.declared_size == i64::try_from(evidence.byte_size.get())?,
                    "direct cache final source differs from baseline activation"
                );
                statements.extend(Database::complete_direct_cache_write_ticket_statements(
                    record,
                    evidence,
                    &self.deployment,
                    ticket.resource_version,
                    now,
                )?);
            }
            (DirectSqlOwner::Publication, DirectUploadTarget::PublicationObject { .. }) => {
                statements.extend(
                    self.db
                        .direct_publication_presence_statements(
                            record,
                            evidence,
                            &self.deployment,
                            now,
                        )
                        .await?,
                );
            }
            (DirectSqlOwner::Oci, DirectUploadTarget::OciBlob { upload_id }) => {
                ensure!(
                    evidence.placements.len() == 1,
                    "direct OCI materialization must be singular"
                );
                let upload = self
                    .db
                    .direct_oci_upload_for_actor(
                        &self.deployment,
                        &record.admission.actor_slot,
                        upload_id,
                        now,
                    )
                    .await?;
                let digest =
                    aos_oci_types::Sha256Digest::parse(&format!("sha256:{}", evidence.sha256))?;
                let path = aos_hub_core::db::oci_blob_object_key(digest);
                let object_id = match self
                    .db
                    .surface_object_named(SurfaceTarget::Registry(upload.registry_id), &path)
                    .await?
                {
                    Some(object) => object.id,
                    None => (uuid::Uuid::new_v4().as_u128() % 9_007_199_254_740_991u128) as i64 + 1,
                };
                let placement = &evidence.placements[0];
                statements.extend(
                    self.db
                        .direct_oci_object_presence_statements(
                            upload.registry_id,
                            i64::try_from(placement.placement_id.get())?,
                            digest,
                            evidence.byte_size.get(),
                            &placement.final_etag,
                            now,
                            object_id,
                        )
                        .await?,
                );
                statements.extend(Database::complete_direct_oci_upload_statements(
                    &upload,
                    &record.admission,
                    object_id,
                    i64::try_from(placement.placement_id.get())?,
                    now,
                )?);
            }
            _ => anyhow::bail!("direct original target owner differs"),
        }
        Ok(statements)
    }
}

impl NativeDirectUploadAuthority {
    pub(super) async fn resolve_capabilities(
        &self,
        claims: &Claims,
        requested: &DirectCapabilitiesTarget,
        now: i64,
    ) -> Result<DirectUploadCapabilities> {
        requested.validate()?;
        let actor = self.current_actor(claims).await?;
        let (target, scope, permission, mut rows, config_generation) = match requested {
            DirectCapabilitiesTarget::Cache { cache_id } => {
                let cache = match self.db.binary_cache_by_stable_id(cache_id).await? {
                    Some(cache) => cache,
                    None => self
                        .db
                        .binary_cache_by_slug(cache_id)
                        .await?
                        .context("direct cache absent")?,
                };
                ensure!(cache.deleted_at.is_none(), "direct cache unavailable");
                self.check_org(cache.org_id).await?;
                let rows = self
                    .db
                    .list_surface_placements(SurfaceTarget::BinaryCache(cache.id))
                    .await?
                    .into_iter()
                    .filter(|row| row.effective_write_enabled)
                    .collect();
                (
                    requested.clone(),
                    cache.scope_key,
                    Permission::RegistryConfigure,
                    rows,
                    cache.resource_version,
                )
            }
            DirectCapabilitiesTarget::CacheDelivery { delivery_url } => {
                let cache = self
                    .db
                    .binary_cache_by_ready_delivery_url(delivery_url)
                    .await?
                    .context("direct ready cache delivery absent")?;
                ensure!(cache.deleted_at.is_none(), "direct cache unavailable");
                self.check_org(cache.org_id).await?;
                let rows = self
                    .db
                    .list_surface_placements(SurfaceTarget::BinaryCache(cache.id))
                    .await?
                    .into_iter()
                    .filter(|row| row.effective_write_enabled)
                    .collect();
                (
                    DirectCapabilitiesTarget::Cache {
                        cache_id: cache.stable_id,
                    },
                    cache.scope_key,
                    Permission::RegistryConfigure,
                    rows,
                    cache.resource_version,
                )
            }
            DirectCapabilitiesTarget::Publication { publication_id } => {
                let publication = self
                    .db
                    .registry_publication(publication_id)
                    .await?
                    .context("direct publication absent")?;
                let registry = self
                    .db
                    .registry_by_id(publication.registry_id)
                    .await?
                    .context("direct registry absent")?;
                self.check_org(registry.org_id).await?;
                let scope = self.db.registry_authorization_scope(registry.id).await?;
                let mut rows = Vec::new();
                for progress in self
                    .db
                    .registry_publication_placement_records(publication_id)
                    .await?
                {
                    if progress.required {
                        rows.push(
                            self.db
                                .surface_placement(progress.placement_id)
                                .await?
                                .context("direct required placement absent")?,
                        );
                    }
                }
                (
                    requested.clone(),
                    scope,
                    Permission::Publish,
                    rows,
                    publication.ordinal,
                )
            }
            DirectCapabilitiesTarget::OciRepository {
                registry,
                repository,
            } => {
                aos_oci_types::RepositoryName::parse(repository)?;
                let registry = match self.db.registry_by_stable_id(registry).await? {
                    Some(registry) => registry,
                    None => self
                        .db
                        .registry_by_slug(registry)
                        .await?
                        .context("direct registry absent")?,
                };
                self.check_org(registry.org_id).await?;
                let scope = self.db.registry_authorization_scope(registry.id).await?;
                let rows = self
                    .db
                    .list_surface_placements(SurfaceTarget::Registry(registry.id))
                    .await?
                    .into_iter()
                    .filter(|row| row.effective_write_enabled)
                    .collect();
                (requested.clone(), scope, Permission::Publish, rows, 1)
            }
        };
        self.require_permission(claims, permission, &Scope::parse(&scope))
            .await?;
        rows.sort_by_key(|row| row.id);
        ensure!(
            !rows.is_empty() && rows.len() <= MAX_DIRECT_PLACEMENTS,
            "direct capability target has no bounded qualified placements"
        );
        let issue = WireInteger::new(u64::try_from(now)?);
        let expiry = WireInteger::new(
            issue
                .get()
                .checked_add(25)
                .context("direct capability clock overflow")?
                .min(self.acceptances.valid_until(
                    &self.deployment,
                    &self.origin,
                    self.latest_now()?,
                )?),
        );
        let context = DirectRequestContext {
            deployment_id: self.deployment.clone(),
            executor_public_origin: self.origin.clone(),
            public_authority: url::Url::parse(&self.origin)?
                .host_str()
                .context("direct origin host absent")?
                .to_owned(),
            foreground: DirectForegroundBudget {
                invocation_id: "00".repeat(32),
                issued_at: issue,
                expires_at: expiry,
            },
            request_nonce: "00".repeat(32),
            request_body_sha256: "00".repeat(32),
            public_method: "POST".into(),
            public_path: "/aos.hub.v1.DirectUploadService/GetCapabilities".into(),
            issued_at: issue,
            expires_at: expiry,
        };
        let profiles = self.current_profiles(&context, now).await?;
        let probe = DirectUploadIntent {
            version: 1,
            client_operation_id: "00".repeat(32),
            target: DirectUploadTarget::CacheObject {
                cache_id: "capability".into(),
                path: "nar/probe.nar".into(),
            },
            expected_sha256: "00".repeat(32),
            byte_size: WireInteger::new(0),
            part_size: WireInteger::new(MIN_DIRECT_PART_BYTES),
            dependency_phase: DirectDependencyPhase::Content,
            transfer_mode: DirectTransferMode::DirectRequired,
        };
        let mut public = Vec::new();
        let mut minimum_object_bytes = 0;
        for row in rows {
            let placement = self
                .resolve_placement(&row, "nar/probe.nar", &probe, &profiles)
                .await?;
            let selected = profiles
                .iter()
                .find(|profile| {
                    profile.digest().ok().as_deref() == Some(&placement.protected_profile_digest)
                })
                .context("direct accepted profile absent")?;
            let provider_origin = match selected {
                DirectProtectedProfile::Managed { profile, .. } => {
                    format!("https://{}.r2.cloudflarestorage.com", profile.account_id)
                }
                DirectProtectedProfile::External { profile, .. } => {
                    minimum_object_bytes = 1;
                    use aos_hub_core::storage_authority::StorageAuthorityHost;
                    let alias = &profile.write_cohort.alias.spec;
                    let host = match &alias.host {
                        StorageAuthorityHost::Dns(host) => host.clone(),
                        StorageAuthorityHost::Ipv4(bytes) => {
                            std::net::Ipv4Addr::from(*bytes).to_string()
                        }
                        StorageAuthorityHost::Ipv6(bytes) => {
                            format!("[{}]", std::net::Ipv6Addr::from(*bytes))
                        }
                    };
                    format!(
                        "https://{host}{}",
                        if alias.port == 443 {
                            String::new()
                        } else {
                            format!(":{}", alias.port)
                        }
                    )
                }
            };
            public.push(DirectProviderProfile {
                placement_id: placement.placement_id,
                placement_resource_version: placement.placement_resource_version,
                write_spec_version: placement.write_spec_version,
                binding_id: placement.binding_id,
                binding_resource_version: placement.binding_resource_version,
                binding_write_revision: placement.binding_write_revision,
                checksum_algorithm: placement.checksum_algorithm,
                provider_origin,
                profile_fingerprint: placement.presign_credential.credential_fingerprint,
                private_policy_digest: placement.private_stage_policy.policy_digest,
            });
        }
        self.require_permission(claims, permission, &Scope::parse(&scope))
            .await?;
        let capability = DirectUploadCapabilities {
            target,
            requested_delivery_url: if let DirectCapabilitiesTarget::CacheDelivery {
                delivery_url,
            } = requested
            {
                Some(delivery_url.clone())
            } else {
                None
            },
            deployment_id: self.deployment.clone(),
            principal_id: actor.principal_id(&self.deployment)?,
            version: 1,
            capability: DIRECT_UPLOAD_CAPABILITY.into(),
            transfer_mode: DirectAdvertisedTransferMode::DirectRequired,
            config_generation: WireInteger::new(u64::try_from(config_generation)?),
            valid_until: expiry,
            maximum_control_bytes: MAX_DIRECT_CONTROL_BYTES as u32,
            maximum_batch_items: MAX_DIRECT_BATCH_ITEMS as u32,
            maximum_batch_parts: MAX_DIRECT_BATCH_PARTS as u32,
            minimum_object_bytes: WireInteger::new(minimum_object_bytes),
            maximum_object_bytes: WireInteger::new(
                profiles
                    .iter()
                    .map(|profile| match profile {
                        DirectProtectedProfile::Managed {
                            runtime_qualification,
                            ..
                        }
                        | DirectProtectedProfile::External {
                            runtime_qualification,
                            ..
                        } => runtime_qualification.maximum_object_bytes.get(),
                    })
                    .min()
                    .context("direct runtime profiles absent")?,
            ),
            minimum_part_bytes: WireInteger::new(MIN_DIRECT_PART_BYTES),
            maximum_part_bytes: WireInteger::new(MAX_DIRECT_PART_BYTES),
            profiles: public,
        };
        capability.validate()?;
        Ok(capability)
    }
}
