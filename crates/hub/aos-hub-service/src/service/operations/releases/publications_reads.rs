//! Publications reads in the releases capability.

use super::*;

impl RpcService {
    /// `RegistryService.ListReleases` — verified signed releases, newest first.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::NotFound`] for an unknown slug or a soft-deleted
    /// owning org, [`RpcError::Unauthenticated`]/[`RpcError::PermissionDenied`]
    /// when a non-public registry is read without authority,
    /// [`RpcError::InvalidArgument`] for a malformed `page_token`, and
    /// [`RpcError::Internal`] on database failure.
    pub async fn list_releases(
        &self,
        auth: Option<&str>,
        req: pb::ListReleasesRequest,
    ) -> Result<pb::ListReleasesResponse, RpcError> {
        let record = self.registry_or_not_found(&req.slug).await?;
        self.require_read(auth, &record).await?;
        let releases: Vec<pb::Release> = self
            .db
            .list_releases(record.id)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .map(|r| pb::Release {
                semver: r.semver,
                tag_oid: r.tag_oid,
                commit_oid: r.commit_oid,
                signer: r.signer.unwrap_or_default(),
                tagged_at: r.tagged_at.unwrap_or_default(),
            })
            .collect();
        let (releases, next_page_token) = paginate(releases, req.page_size, &req.page_token)?;
        Ok(pb::ListReleasesResponse {
            releases,
            next_page_token,
        })
    }

    /// Returns exact native operation declarations across one completed release.
    ///
    /// An empty release selects the registry's configured browsing release. An
    /// empty platform selects the first indexed platform in lexical order.
    ///
    /// # Errors
    ///
    /// Returns registry visibility failures, not-found when no release graph is
    /// available, and internal errors for corrupted generated projection bytes.
    pub async fn get_release_ability_graph(
        &self,
        auth: Option<&str>,
        req: pb::GetReleaseAbilityGraphRequest,
    ) -> Result<pb::GetReleaseAbilityGraphResponse, RpcError> {
        let registry = self.registry_or_not_found(&req.registry).await?;
        self.require_read(auth, &registry).await?;
        let release = if req.release.is_empty() {
            self.db
                .default_browse_release(registry.id)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::not_found("default release"))?
        } else {
            req.release
        };
        let graph = self
            .native_release_graph_for_registry(registry.id, &release, &req.platform)
            .await?;
        let registry_commit = graph.registry_commit.clone();
        let platform = graph.platform.clone();
        let canonical_json = graph.canonical_bytes().map_err(RpcError::internal)?;
        let etag = aos_core::Sha256Digest::of_bytes(&canonical_json).to_string();
        Ok(pb::GetReleaseAbilityGraphResponse {
            identity: Some(pb::ReleaseAbilityGraphIdentity {
                registry_commit,
                release,
                platform,
                graph_sha256: etag.clone(),
            }),
            canonical_json,
            etag,
        })
    }

    /// Lists native options from an explicit completed release when selected.
    ///
    /// # Errors
    ///
    /// Returns visibility, exact-selection, integrity, filter, or pagination errors.
    pub(crate) async fn list_package_options_at_release(
        &self,
        auth: Option<&str>,
        req: pb::ListPackageOptionsRequest,
        release: Option<&str>,
    ) -> Result<pb::ListPackageOptionsResponse, RpcError> {
        let registry = self.registry_or_not_found(&req.registry).await?;
        self.require_read(auth, &registry).await?;
        let (locator, document) = self
            .load_native_documentation_for_registry(
                registry.id,
                &req.package,
                &req.version,
                &req.platform,
                release,
            )
            .await?;
        let identity = native_documentation_identity(&locator);
        let mut options = Vec::new();
        for option in document.options() {
            let path = option.path.join(".");
            let signature = aos_module_docs::runtime::type_signature(&option.option_type)
                .map_err(RpcError::internal)?;
            if !req.prefix.is_empty() && !path.starts_with(&req.prefix) {
                continue;
            }
            if !req.owner.is_empty() && option.owner != req.owner {
                continue;
            }
            if !req.r#type.is_empty() && signature != req.r#type {
                continue;
            }
            if req
                .extensible
                .is_some_and(|value| option.extensible != value)
            {
                continue;
            }
            if option.visibility == aos_module_docs::Visibility::Hidden {
                continue;
            }
            options.push(native_option_view(&identity, option).map_err(RpcError::internal)?);
        }
        let (options, next_page_token) = paginate(options, req.page_size, &req.page_token)?;
        Ok(pb::ListPackageOptionsResponse {
            options,
            next_page_token,
        })
    }
}
