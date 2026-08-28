//! Registry-bound OCI container administration reads.

use aos_oci_types::ManifestReference;
use aos_proto_types as pb;

use super::*;
use crate::db::{OciRepositoryListFilter, OciTagListFilter};

impl RpcService {
    /// Lists container repositories visible through one registry.
    ///
    /// # Errors
    ///
    /// Returns an authorization, pagination, validation, or database error.
    pub async fn list_container_repositories(
        &self,
        auth: Option<&str>,
        req: pb::ListContainerRepositoriesRequest,
    ) -> Result<pb::ListContainerRepositoriesResponse, RpcError> {
        let registry = self
            .container_registry_for_read(auth, &req.registry)
            .await?;
        let page = self
            .db
            .list_oci_admin_repositories(
                registry.id,
                &OciRepositoryListFilter {
                    repository_prefix: optional_filter(&req.repository_prefix).map(str::to_string),
                    lifecycle_state: optional_filter(&req.lifecycle_state).map(str::to_string),
                },
                page_size(req.page_size)?,
                optional_filter(&req.page_token),
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        let distribution_authority = self.container_distribution_authority(registry.id).await?;
        Ok(pb::ListContainerRepositoriesResponse {
            repositories: page
                .items
                .iter()
                .map(|item| {
                    repository_message(&registry.slug, item, distribution_authority.as_deref())
                })
                .collect(),
            next_page_token: page.next_cursor.unwrap_or_default(),
            mutation_epoch: page.mutation_epoch.to_string(),
        })
    }

    /// Returns one container repository visible through a registry.
    ///
    /// # Errors
    ///
    /// Returns an authorization, validation, not-found, or database error.
    pub async fn get_container_repository(
        &self,
        auth: Option<&str>,
        req: pb::GetContainerRepositoryRequest,
    ) -> Result<pb::ContainerRepositoryResponse, RpcError> {
        let registry = self
            .container_registry_for_read(auth, &req.registry)
            .await?;
        let repository = repository_name(&req.repository)?;
        let record = self
            .db
            .oci_admin_repository(registry.id, &repository)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("container repository"))?;
        let distribution_authority = self.container_distribution_authority(registry.id).await?;
        Ok(pb::ContainerRepositoryResponse {
            repository: Some(repository_message(
                &registry.slug,
                &record,
                distribution_authority.as_deref(),
            )),
        })
    }

    /// Lists current tags in one repository.
    ///
    /// # Errors
    ///
    /// Returns an authorization, pagination, validation, or database error.
    pub async fn list_container_tags(
        &self,
        auth: Option<&str>,
        req: pb::ListContainerTagsRequest,
    ) -> Result<pb::ListContainerTagsResponse, RpcError> {
        let registry = self
            .container_registry_for_read(auth, &req.registry)
            .await?;
        let repository = repository_name(&req.repository)?;
        let page = self
            .db
            .list_oci_admin_tags(
                registry.id,
                &repository,
                &OciTagListFilter {
                    tag_prefix: optional_filter(&req.tag_prefix).map(str::to_string),
                    ownership_kind: optional_filter(&req.ownership_kind).map(str::to_string),
                },
                page_size(req.page_size)?,
                optional_filter(&req.page_token),
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        Ok(pb::ListContainerTagsResponse {
            tags: page
                .items
                .iter()
                .map(|item| tag_message(&registry.slug, &repository, item))
                .collect(),
            next_page_token: page.next_cursor.unwrap_or_default(),
            mutation_epoch: page.mutation_epoch.to_string(),
        })
    }

    /// Returns one current tag pointer.
    ///
    /// # Errors
    ///
    /// Returns an authorization, validation, not-found, or database error.
    pub async fn get_container_tag(
        &self,
        auth: Option<&str>,
        req: pb::GetContainerTagRequest,
    ) -> Result<pb::ContainerTagResponse, RpcError> {
        let registry = self
            .container_registry_for_read(auth, &req.registry)
            .await?;
        let repository = repository_name(&req.repository)?;
        let tag_name = tag(&req.tag)?;
        let record = self
            .db
            .resolve_oci_admin_tag(registry.id, &repository, &tag_name)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("container tag"))?;
        Ok(pb::ContainerTagResponse {
            tag: Some(tag_message(&registry.slug, &repository, &record)),
        })
    }

    /// Resolves a tag and optionally selects an exact runnable platform.
    ///
    /// # Errors
    ///
    /// Returns an authorization, platform-validation, not-found, or database error.
    pub async fn resolve_container_tag(
        &self,
        auth: Option<&str>,
        req: pb::ResolveContainerTagRequest,
    ) -> Result<pb::ContainerTagResolutionResponse, RpcError> {
        let registry = self
            .container_registry_for_read(auth, &req.registry)
            .await?;
        let repository = repository_name(&req.repository)?;
        let tag_name = tag(&req.tag)?;
        let tag_record = self
            .db
            .resolve_oci_admin_tag(registry.id, &repository, &tag_name)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("container tag"))?;
        let manifest = self
            .db
            .oci_admin_manifest(
                registry.id,
                &repository,
                &ManifestReference::Digest(tag_record.digest),
            )
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("container manifest"))?;

        let selected_platform = if req.operating_system.is_empty()
            && req.architecture.is_empty()
            && req.variant.is_empty()
            && req.os_version.is_empty()
            && req.os_features.is_empty()
        {
            None
        } else {
            if req.operating_system.is_empty() || req.architecture.is_empty() {
                return Err(RpcError::invalid(
                    "operatingSystem and architecture must be supplied together",
                ));
            }
            let platform = platform_selector(
                req.operating_system,
                req.architecture,
                req.variant,
                req.os_version,
                req.os_features,
            )?;
            Some(
                self.db
                    .oci_admin_platform(registry.id, &repository, tag_record.digest, &platform)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| RpcError::not_found("container platform"))?,
            )
        };
        Ok(pb::ContainerTagResolutionResponse {
            tag: Some(tag_message(&registry.slug, &repository, &tag_record)),
            manifest: Some(manifest_message(&registry.slug, &repository, &manifest)?),
            selected_platform: selected_platform
                .as_ref()
                .map(|item| platform_message(&registry.slug, &repository, item)),
        })
    }

    /// Lists immutable tag history in newest-first order.
    ///
    /// # Errors
    ///
    /// Returns an authorization, pagination, validation, or database error.
    pub async fn list_container_tag_history(
        &self,
        auth: Option<&str>,
        req: pb::ListContainerTagHistoryRequest,
    ) -> Result<pb::ListContainerTagHistoryResponse, RpcError> {
        let registry = self
            .container_registry_for_read(auth, &req.registry)
            .await?;
        let repository = repository_name(&req.repository)?;
        let tag_name = optional_filter(&req.tag).map(tag).transpose()?;
        let page = self
            .db
            .list_oci_admin_tag_history(
                registry.id,
                &repository,
                tag_name.as_ref(),
                page_size(req.page_size)?,
                optional_filter(&req.page_token),
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        Ok(pb::ListContainerTagHistoryResponse {
            entries: page
                .items
                .iter()
                .map(|item| history_message(&registry.slug, &repository, item))
                .collect(),
            next_page_token: page.next_cursor.unwrap_or_default(),
            mutation_epoch: page.mutation_epoch.to_string(),
        })
    }

    /// Returns one exact immutable manifest or index projection.
    ///
    /// # Errors
    ///
    /// Returns an authorization, validation, not-found, or database error.
    pub async fn get_container_manifest(
        &self,
        auth: Option<&str>,
        req: pb::GetContainerManifestRequest,
    ) -> Result<pb::ContainerManifestResponse, RpcError> {
        let registry = self
            .container_registry_for_read(auth, &req.registry)
            .await?;
        let repository = repository_name(&req.repository)?;
        let reference = ManifestReference::parse(&req.digest)
            .map_err(|error| RpcError::invalid(error.to_string()))?;
        let record = self
            .db
            .oci_admin_manifest(registry.id, &repository, &reference)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("container manifest"))?;
        Ok(pb::ContainerManifestResponse {
            manifest: Some(manifest_message(&registry.slug, &repository, &record)?),
        })
    }

    /// Lists runnable platforms beneath one root.
    ///
    /// # Errors
    ///
    /// Returns an authorization, pagination, validation, or database error.
    pub async fn list_container_platforms(
        &self,
        auth: Option<&str>,
        req: pb::ListContainerPlatformsRequest,
    ) -> Result<pb::ListContainerPlatformsResponse, RpcError> {
        let registry = self
            .container_registry_for_read(auth, &req.registry)
            .await?;
        let repository = repository_name(&req.repository)?;
        let root = digest(&req.root_digest)?;
        let page = self
            .db
            .list_oci_admin_platforms(
                registry.id,
                &repository,
                root,
                page_size(req.page_size)?,
                optional_filter(&req.page_token),
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        Ok(pb::ListContainerPlatformsResponse {
            platforms: page
                .items
                .iter()
                .map(|item| platform_message(&registry.slug, &repository, item))
                .collect(),
            next_page_token: page.next_cursor.unwrap_or_default(),
        })
    }

    /// Returns one exact runnable platform beneath a root.
    ///
    /// # Errors
    ///
    /// Returns an authorization, validation, not-found, or database error.
    pub async fn get_container_platform(
        &self,
        auth: Option<&str>,
        req: pb::GetContainerPlatformRequest,
    ) -> Result<pb::ContainerPlatformResponse, RpcError> {
        let registry = self
            .container_registry_for_read(auth, &req.registry)
            .await?;
        let repository = repository_name(&req.repository)?;
        let root = digest(&req.root_digest)?;
        let platform = platform_selector(
            req.operating_system,
            req.architecture,
            req.variant,
            req.os_version,
            req.os_features,
        )?;
        let record = self
            .db
            .oci_admin_platform(registry.id, &repository, root, &platform)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("container platform"))?;
        Ok(pb::ContainerPlatformResponse {
            platform: Some(platform_message(&registry.slug, &repository, &record)),
        })
    }

    /// Lists ordered layers for one runnable manifest in a release root.
    ///
    /// # Errors
    ///
    /// Returns an authorization, pagination, validation, or database error.
    pub async fn list_container_layers(
        &self,
        auth: Option<&str>,
        req: pb::ListContainerLayersRequest,
    ) -> Result<pb::ListContainerLayersResponse, RpcError> {
        let registry = self
            .container_registry_for_read(auth, &req.registry)
            .await?;
        let repository = repository_name(&req.repository)?;
        let root = digest(&req.root_digest)?;
        let manifest = digest(&req.manifest_digest)?;
        let page = self
            .db
            .list_oci_admin_layers(
                registry.id,
                &repository,
                root,
                manifest,
                page_size(req.page_size)?,
                optional_filter(&req.page_token),
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        Ok(pb::ListContainerLayersResponse {
            layers: page
                .items
                .iter()
                .map(|item| layer_message(&registry.slug, &repository, item))
                .collect(),
            next_page_token: page.next_cursor.unwrap_or_default(),
        })
    }

    /// Returns one exact layer in a runnable manifest and release root.
    ///
    /// # Errors
    ///
    /// Returns an authorization, validation, not-found, or database error.
    pub async fn get_container_layer(
        &self,
        auth: Option<&str>,
        req: pb::GetContainerLayerRequest,
    ) -> Result<pb::ContainerLayerResponse, RpcError> {
        let registry = self
            .container_registry_for_read(auth, &req.registry)
            .await?;
        let repository = repository_name(&req.repository)?;
        let root = digest(&req.root_digest)?;
        let manifest = digest(&req.manifest_digest)?;
        let layer = digest(&req.digest)?;
        let record = self
            .db
            .oci_admin_layer(registry.id, &repository, root, manifest, layer)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("container layer"))?;
        Ok(pb::ContainerLayerResponse {
            layer: Some(layer_message(&registry.slug, &repository, &record)),
        })
    }

    /// Lists verified and unverified referrers for one exact subject.
    ///
    /// # Errors
    ///
    /// Returns an authorization, pagination, validation, or database error.
    pub async fn list_container_referrers(
        &self,
        auth: Option<&str>,
        req: pb::ListContainerReferrersRequest,
    ) -> Result<pb::ListContainerReferrersResponse, RpcError> {
        let registry = self
            .container_registry_for_read(auth, &req.registry)
            .await?;
        let repository = repository_name(&req.repository)?;
        let subject = digest(&req.subject_digest)?;
        let artifact_type = optional_filter(&req.artifact_type)
            .map(media_type)
            .transpose()?;
        let page = self
            .db
            .list_oci_admin_referrers(
                registry.id,
                &repository,
                subject,
                artifact_type,
                page_size(req.page_size)?,
                optional_filter(&req.page_token),
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        let referrers = page
            .items
            .iter()
            .map(|item| referrer_message(&registry.slug, &repository, item))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(pb::ListContainerReferrersResponse {
            referrers,
            next_page_token: page.next_cursor.unwrap_or_default(),
        })
    }

    /// Lists secret-free verified-publication sessions for a publisher.
    ///
    /// # Errors
    ///
    /// Returns an authorization, pagination, validation, or database error.
    pub async fn list_container_publications(
        &self,
        auth: Option<&str>,
        req: pb::ListContainerPublicationsRequest,
    ) -> Result<pb::ListContainerPublicationsResponse, RpcError> {
        let registry = self
            .container_registry_for_publication_read(auth, &req.registry)
            .await?;
        let repository = optional_filter(&req.repository)
            .map(repository_name)
            .transpose()?;
        let page = self
            .db
            .list_oci_admin_publications(
                registry.id,
                repository.as_ref(),
                optional_filter(&req.state),
                page_size(req.page_size)?,
                optional_filter(&req.page_token),
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        Ok(pb::ListContainerPublicationsResponse {
            publications: page
                .items
                .iter()
                .map(|item| publication_message(&registry.slug, item))
                .collect(),
            next_page_token: page.next_cursor.unwrap_or_default(),
            mutation_epoch: page.mutation_epoch.to_string(),
        })
    }

    /// Returns signed source, closure, and evidence provenance for one root.
    ///
    /// # Errors
    ///
    /// Returns an authorization, validation, not-found, or database error.
    pub async fn get_container_provenance(
        &self,
        auth: Option<&str>,
        req: pb::GetContainerProvenanceRequest,
    ) -> Result<pb::ContainerProvenanceResponse, RpcError> {
        let registry = self
            .container_registry_for_read(auth, &req.registry)
            .await?;
        let repository = repository_name(&req.repository)?;
        let root = digest(&req.root_digest)?;
        let release = optional_filter(&req.release)
            .ok_or_else(|| RpcError::invalid("release is required"))?;
        let record = self
            .db
            .oci_admin_release_provenance(registry.id, &repository, root, release)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("container provenance"))?;
        Ok(pb::ContainerProvenanceResponse {
            provenance: Some(provenance_message(&registry.slug, &record)),
        })
    }

    /// Returns the persisted registry-scoped retention policy or effective defaults.
    ///
    /// # Errors
    ///
    /// Returns an authorization or database error.
    pub async fn get_container_retention_policy(
        &self,
        auth: Option<&str>,
        req: pb::GetContainerRetentionPolicyRequest,
    ) -> Result<pb::ContainerRetentionPolicyResponse, RpcError> {
        let registry = self
            .container_registry_for_read(auth, &req.registry)
            .await?;
        let record = self
            .db
            .oci_admin_retention_policy(registry.id)
            .await
            .map_err(RpcError::internal)?;
        Ok(pb::ContainerRetentionPolicyResponse {
            policy: Some(record.as_ref().map_or_else(
                || default_retention_message(&registry.slug),
                |policy| retention_message(&registry.slug, policy),
            )),
        })
    }

    /// Returns one GC run only after the Phase 7 deletion engine is enabled.
    ///
    /// # Errors
    ///
    /// Returns authorization errors first, then unavailable until Phase 7.
    pub async fn get_container_gc_run(
        &self,
        auth: Option<&str>,
        req: pb::GetContainerGcRunRequest,
    ) -> Result<pb::ContainerGcRunResponse, RpcError> {
        let _ = self
            .container_registry_for_mutation(auth, &req.registry, Permission::RegistryConfigure)
            .await?;
        Err(container_gc_unavailable())
    }

    /// Lists GC runs only after the Phase 7 deletion engine is enabled.
    ///
    /// # Errors
    ///
    /// Returns authorization errors first, then unavailable until Phase 7.
    pub async fn list_container_gc_runs(
        &self,
        auth: Option<&str>,
        req: pb::ListContainerGcRunsRequest,
    ) -> Result<pb::ListContainerGcRunsResponse, RpcError> {
        let _ = self
            .container_registry_for_mutation(auth, &req.registry, Permission::RegistryConfigure)
            .await?;
        Err(container_gc_unavailable())
    }
}
