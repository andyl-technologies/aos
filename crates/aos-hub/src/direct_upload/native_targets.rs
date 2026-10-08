//! Shared SQL target checks for Native and paired-Worker direct uploads.
//!
//! Resolves current users, permissions and physical placements without requiring
//! Worker configuration or previously signed provider test reports. Provider
//! progress and verification remain the caller's responsibility.

mod settlement;

use std::sync::Arc;

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::{
    auth::jwt::Claims,
    db::{BinaryCache, Database, OciUploadRecord, SurfacePlacementRecord, SurfaceTarget},
    direct_upload::*,
    domain::{Permission, Scope},
    keymap,
    service::RpcService,
};

/// Resolves live SQL owners and permissions for either direct-upload runtime.
pub(crate) struct NativeUploadTargets {
    db: Arc<Database>,
    rpc: Arc<RpcService>,
    deployment: String,
}

impl NativeUploadTargets {
    /// Shares the Hub database and ordinary RPC authorization service.
    pub(crate) fn new(db: Arc<Database>, rpc: Arc<RpcService>, deployment: String) -> Self {
        Self {
            db,
            rpc,
            deployment,
        }
    }

    /// Resolves the currently authenticated immutable account identity.
    ///
    /// # Errors
    /// Rejects revoked credentials, deleted owners and persistence failures.
    pub(crate) async fn current_actor(&self, claims: &Claims) -> Result<DirectActorSlot> {
        self.db
            .current_authenticated_actor(claims)
            .await?
            .ok_or_else(|| {
                anyhow::Error::new(DirectUploadRefusal {
                    code: DirectItemErrorCode::Denied,
                })
            })
    }
}

/// Carries the current accounting owner during target preparation.
pub(crate) enum TargetOwner {
    Cache(BinaryCache),
    Publication,
    Oci(OciUploadRecord),
}

/// Describes an authorized target and its required physical placements.
pub(crate) struct Target {
    /// Current authorization scope for the logical target.
    pub scope: String,
    /// Logical surface path, independent of its storage prefix.
    pub path: String,
    /// Original Unix expiration time for new provider operations.
    pub expires_at: i64,
    /// Frozen required physical destinations, in placement-ID order.
    pub placements: Vec<SurfacePlacementRecord>,
    /// Original target accounting owner.
    pub owner: TargetOwner,
}

impl NativeUploadTargets {
    /// Checks whether a publication object has a known logical accounting owner.
    ///
    /// # Errors
    /// Rejects unknown legacy accounting or database failures.
    pub(crate) async fn ensure_new_effect_accounting(
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

impl NativeUploadTargets {
    /// Checks the original actor and current target permission and topology.
    ///
    /// # Errors
    /// Rejects missing targets, changed manifests, revoked permissions or invalid publication phases.
    pub(crate) async fn resolve_target(
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

    /// Applies the ordinary RPC permission check to the exact target scope.
    ///
    /// # Errors
    /// Rejects missing permissions or unavailable authorization state.
    pub(crate) async fn require_permission(
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

    /// Checks that an organization-owned target still has an active owner.
    ///
    /// # Errors
    /// Rejects a deleted organization or database failures.
    pub(crate) async fn check_org(&self, org: Option<i64>) -> Result<()> {
        if let Some(org) = org {
            ensure!(
                self.db.org_is_active(org).await?,
                "direct target owner unavailable"
            );
        }
        Ok(())
    }
}

/// Immutable SQL and credential revisions selected before storage writes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct NativePlacementPin {
    /// Physical surface placement ID.
    pub placement_id: i64,
    /// Original placement configuration revision.
    pub placement_resource_version: i64,
    /// Original placement write configuration revision.
    pub write_spec_version: i64,
    /// Storage binding containing the destination.
    pub binding_id: i64,
    /// Original storage binding configuration revision.
    pub binding_resource_version: i64,
    /// Immutable validated write capability revision.
    pub binding_write_revision: i64,
    /// Validated credential generation for provider control writes.
    pub write_credential_generation: i64,
    /// Validated credential generation for object verification.
    pub read_credential_generation: i64,
    /// Validated credential generation for signed upload URLs.
    pub presign_credential_generation: i64,
}

/// Existing accounting owner retained with the provider upload journal.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) enum NativeTargetOwner {
    Cache { cache_id: i64, ticket_id: String },
    Publication,
    Oci { upload_id: String },
}

/// Original target identity used for every subsequent control call.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct NativeUploadOriginal {
    /// Server-assigned upload identity retained across retries.
    pub session_id: String,
    /// Immutable authenticated account that opened the upload.
    pub actor: DirectActorSlot,
    /// Original object identity and client operation.
    pub intent: DirectUploadIntent,
    /// Current authorization scope for the logical target.
    pub scope: String,
    /// Logical surface path, independent of its storage prefix.
    pub path: String,
    /// Original Unix expiration time for new provider operations.
    pub expires_at: i64,
    /// Original target accounting owner.
    pub owner: NativeTargetOwner,
    /// Frozen required physical destinations, in placement-ID order.
    pub placements: Vec<NativePlacementPin>,
}

/// A provider outcome whose complete bytes were checked by the configured verifier.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct NativeVerifiedPlacement {
    /// Physical surface placement ID.
    pub placement_id: i64,
    /// Strong provider tag obtained after verification.
    pub etag: String,
    /// Provider object version when versioning is supported.
    pub provider_version: Option<String>,
}

impl NativeUploadTargets {
    /// Freezes validated storage and credential revisions for a writable placement.
    ///
    /// # Errors
    /// Rejects unsupported bindings, missing credentials and stale writer capability.
    pub(crate) async fn placement_pin(
        &self,
        row: &SurfacePlacementRecord,
    ) -> Result<NativePlacementPin> {
        ensure!(
            row.desired_state == "active" && row.effective_write_enabled,
            "native direct placement is not writable"
        );
        let binding = self
            .db
            .binding(row.binding_id)
            .await?
            .context("native direct binding absent")?;
        ensure!(
            matches!(binding.kind.as_str(), "s3" | "r2")
                && binding.access_mode.as_deref() == Some("private"),
            DirectUploadRefusal {
                code: DirectItemErrorCode::Unsupported
            }
        );
        let revision = self.db.direct_placement_write_revision(row).await?;
        let write_revision = self
            .db
            .binding_write_revision(row.binding_id, revision)
            .await?
            .context("native direct writer revision absent")?;
        let mut generations = Vec::new();
        for purpose in ["write", "read", "presign"] {
            let credential = self
                .db
                .current_binding_credential(row.binding_id, purpose)
                .await?
                .ok_or_else(|| {
                    anyhow::Error::new(DirectUploadRefusal {
                        code: DirectItemErrorCode::Unsupported,
                    })
                })?;
            ensure!(
                credential.validation_state == "valid",
                DirectUploadRefusal {
                    code: DirectItemErrorCode::Unsupported
                }
            );
            generations.push(credential.generation);
        }
        ensure!(
            write_revision.write_credential_purpose == "write"
                && write_revision.write_credential_generation == generations[0],
            "native direct writer credential changed"
        );
        Ok(NativePlacementPin {
            placement_id: row.id,
            placement_resource_version: row.resource_version,
            write_spec_version: row.write_spec_version,
            binding_id: row.binding_id,
            binding_resource_version: binding.resource_version,
            binding_write_revision: revision,
            write_credential_generation: generations[0],
            read_credential_generation: generations[1],
            presign_credential_generation: generations[2],
        })
    }

    /// Reserves the existing accounting owner before any provider upload is created.
    ///
    /// # Errors
    /// Rejects changed users, storage revisions, conflicting reservations or exhausted quota.
    pub(crate) async fn reserve(
        &self,
        claims: &Claims,
        actor: &DirectActorSlot,
        intent: &DirectUploadIntent,
        session_id: &str,
        placements: Vec<NativePlacementPin>,
        now: i64,
    ) -> Result<NativeUploadOriginal> {
        intent.validate()?;
        ensure!(
            valid_direct_identity(session_id),
            "invalid native direct session identity"
        );
        self.ensure_new_effect_accounting(intent).await?;
        let target = self
            .resolve_target(claims, actor, intent, false, now)
            .await?;
        self.check_placements(&target, &placements).await?;
        let target = self
            .resolve_target(claims, actor, intent, true, now)
            .await?;
        self.check_placements(&target, &placements).await?;
        let mut expires_at = target.expires_at;
        let owner = match target.owner {
            TargetOwner::Cache(cache) => {
                ensure!(
                    placements.len() == 1,
                    "native direct cache writer must be singular"
                );
                let pin = &placements[0];
                let ticket = match self.db.cache_write_ticket(session_id).await? {
                    Some(ticket) => {
                        ensure!(
                            ticket.cache_id == cache.id
                                && ticket.object_key == target.path
                                && ticket.declared_size == i64::try_from(intent.byte_size.get())?
                                && ticket.placement_id == pin.placement_id
                                && ticket.placement_resource_version
                                    == pin.placement_resource_version
                                && ticket.binding_write_revision == pin.binding_write_revision
                                && ticket.write_credential_generation
                                    == pin.write_credential_generation,
                            "native direct cache reservation conflicts"
                        );
                        ticket
                    }
                    None => {
                        self.db
                            .begin_cache_write_ticket(
                                session_id,
                                cache.id,
                                pin.placement_id,
                                pin.placement_resource_version,
                                pin.binding_write_revision,
                                pin.write_credential_generation,
                                &target.path,
                                i64::try_from(intent.byte_size.get())?,
                                "single",
                                cache.org_id,
                                0,
                                0,
                                target.expires_at,
                                now,
                                None,
                                None,
                            )
                            .await?
                    }
                };
                ensure!(
                    ticket.expires_at > now,
                    "native direct cache reservation expired"
                );
                expires_at = ticket.expires_at;
                NativeTargetOwner::Cache {
                    cache_id: cache.id,
                    ticket_id: session_id.to_owned(),
                }
            }
            TargetOwner::Publication => NativeTargetOwner::Publication,
            TargetOwner::Oci(upload) => {
                ensure!(
                    placements.len() == 1,
                    "native direct OCI writer must be singular"
                );
                self.db.reserve_direct_oci_source(&upload, now).await?;
                NativeTargetOwner::Oci {
                    upload_id: upload.id,
                }
            }
        };
        let original = NativeUploadOriginal {
            session_id: session_id.to_owned(),
            actor: actor.clone(),
            intent: intent.clone(),
            scope: target.scope,
            path: target.path,
            expires_at,
            owner,
            placements,
        };
        self.authorize(claims, &original, now).await?;
        Ok(original)
    }

    /// Rechecks the original account, target permission and complete placement set.
    ///
    /// # Errors
    /// Rejects changed ownership, permissions or storage configuration.
    pub(crate) async fn authorize(
        &self,
        claims: &Claims,
        original: &NativeUploadOriginal,
        now: i64,
    ) -> Result<()> {
        let target = self
            .resolve_target(claims, &original.actor, &original.intent, false, now)
            .await?;
        ensure!(
            target.scope == original.scope && target.path == original.path,
            "native direct target changed"
        );
        self.check_placements(&target, &original.placements).await
    }

    async fn check_placements(&self, target: &Target, pins: &[NativePlacementPin]) -> Result<()> {
        ensure!(
            !pins.is_empty()
                && pins.len() <= MAX_DIRECT_PLACEMENTS
                && pins.len() == target.placements.len(),
            "native direct required placement set changed"
        );
        for (row, original) in target.placements.iter().zip(pins) {
            ensure!(
                self.placement_pin(row).await? == *original,
                "native direct placement or credential changed"
            );
        }
        Ok(())
    }
}

/// Describes the authorized public target and available Native upload backends.
pub(crate) struct NativeCapabilityTarget {
    /// Canonical target after delivery-route resolution.
    pub target: DirectCapabilitiesTarget,
    /// Original delivery URL when discovery used a delivery route.
    pub requested_delivery_url: Option<String>,
    /// Current logical target configuration revision.
    pub config_generation: i64,
    /// Frozen required physical destinations, in placement-ID order.
    pub placements: Vec<NativePlacementPin>,
}

impl NativeUploadTargets {
    /// Resolves an authorized target and supported Native signed-upload placements.
    ///
    /// Empty placements advertise the ordinary upload path for unsupported backends.
    ///
    /// # Errors
    /// Rejects revoked permissions, missing targets and unavailable topology.
    pub(crate) async fn capability_target(
        &self,
        claims: &Claims,
        actor: &DirectActorSlot,
        requested: &DirectCapabilitiesTarget,
        _now: i64,
    ) -> Result<NativeCapabilityTarget> {
        requested.validate()?;
        ensure!(
            self.current_actor(claims).await? == *actor,
            "native direct actor changed"
        );
        let (target, scope, permission, mut rows, generation) = match requested {
            DirectCapabilitiesTarget::Cache { cache_id } => {
                let cache = match self.db.binary_cache_by_stable_id(cache_id).await? {
                    Some(cache) => cache,
                    None => self
                        .db
                        .binary_cache_by_slug(cache_id)
                        .await?
                        .context("native direct cache absent")?,
                };
                ensure!(
                    cache.deleted_at.is_none(),
                    "native direct cache unavailable"
                );
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
                    .context("native direct ready cache route absent")?;
                ensure!(
                    cache.deleted_at.is_none(),
                    "native direct cache unavailable"
                );
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
                    .context("native direct publication absent")?;
                let registry = self
                    .db
                    .registry_by_id(publication.registry_id)
                    .await?
                    .context("native direct registry absent")?;
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
                                .context("native direct required placement absent")?,
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
                        .context("native direct registry absent")?,
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
                (
                    requested.clone(),
                    scope,
                    Permission::Publish,
                    rows,
                    registry.resource_version,
                )
            }
        };
        self.require_permission(claims, permission, &Scope::parse(&scope))
            .await?;
        rows.sort_by_key(|row| row.id);
        ensure!(
            !rows.is_empty() && rows.len() <= MAX_DIRECT_PLACEMENTS,
            "native direct target has no bounded writable placements"
        );
        // OCI's original allocation retains one materialization destination.
        // Discovery must offer the ordinary path when this topology cannot be honored.
        if matches!(target, DirectCapabilitiesTarget::OciRepository { .. }) && rows.len() != 1 {
            rows.clear();
        }
        let mut placements = Vec::new();
        for row in rows {
            match self.placement_pin(&row).await {
                Ok(pin) => placements.push(pin),
                Err(error)
                    if error
                        .downcast_ref::<DirectUploadRefusal>()
                        .is_some_and(|refusal| {
                            refusal.code == DirectItemErrorCode::Unsupported
                        }) =>
                {
                    placements.clear();
                    break;
                }
                Err(error) => return Err(error),
            }
        }
        self.require_permission(claims, permission, &Scope::parse(&scope))
            .await?;
        Ok(NativeCapabilityTarget {
            target,
            requested_delivery_url: match requested {
                DirectCapabilitiesTarget::CacheDelivery { delivery_url } => {
                    Some(delivery_url.clone())
                }
                _ => None,
            },
            config_generation: generation,
            placements,
        })
    }

    /// Releases the original accounting owner only after provider abort succeeds.
    ///
    /// # Errors
    /// Rejects changed permissions, storage revisions or accounting ownership.
    pub(crate) async fn abort_statements(
        &self,
        claims: &Claims,
        original: &NativeUploadOriginal,
        now: i64,
    ) -> Result<Vec<aos_hub_core::backend::CheckedStatement>> {
        self.authorize(claims, original, now).await?;
        let mut statements = self.authority_statements(claims, original, now).await?;
        match &original.owner {
            NativeTargetOwner::Cache { ticket_id, .. } => {
                let ticket = self
                    .db
                    .cache_write_ticket(ticket_id)
                    .await?
                    .context("native cache ticket absent")?;
                statements.extend(Database::abort_cache_write_ticket_statements(
                    ticket_id,
                    ticket.resource_version,
                    "aborted",
                    now,
                )?);
            }
            NativeTargetOwner::Oci { upload_id } => {
                let upload = self
                    .db
                    .direct_oci_upload_for_actor_recovery(
                        &self.deployment,
                        &original.actor,
                        upload_id,
                    )
                    .await?;
                statements.extend(Database::abort_direct_oci_upload_statements(&upload, now)?);
            }
            NativeTargetOwner::Publication => {}
        }
        Ok(statements)
    }
}
