//! Catalog reads in the documentation capability.

use super::*;

impl RpcService {
    /// `DocumentationService.GetPackageDocumentation` — one exact canonical document.
    ///
    /// Empty version/platform selectors resolve to the newest indexed version
    /// and first platform. The canonical JSON is fetched from and reverified
    /// against the signed Nix object on every uncached service read.
    ///
    /// # Errors
    ///
    /// Returns the ordinary registry visibility failures, not-found for an
    /// absent selection, and internal/unavailable errors for object-integrity
    /// or placement failures.
    pub async fn get_package_documentation(
        &self,
        auth: Option<&str>,
        req: pb::GetPackageDocumentationRequest,
    ) -> Result<pb::GetPackageDocumentationResponse, RpcError> {
        let registry = self.registry_or_not_found(&req.registry).await?;
        self.require_read(auth, &registry).await?;
        let locator = self
            .db
            .native_documentation_locator(
                registry.id,
                &req.package,
                &req.version,
                &req.platform,
                (!req.release.is_empty()).then_some(req.release.as_str()),
            )
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("native package documentation"))?;
        let fetch =
            self.topology_surface_fetcher(aos_hub_db::db::SurfaceTarget::Registry(registry.id));
        let (canonical_json, _) =
            crate::indexer::native_documentation::fetch_native_documentation_content(
                fetch.as_ref(),
                &locator.package,
                &locator.version,
                &locator.platform,
                &locator.artifact,
            )
            .await
            .map_err(RpcError::internal)?;
        Ok(pb::GetPackageDocumentationResponse {
            identity: Some(native_documentation_identity(&locator)),
            canonical_json,
            etag: locator.artifact.document_sha256,
        })
    }

    /// Returns exact native declarations retained by a completed signed release.
    ///
    /// The response pins the native documentation digest, release, commit, tag,
    /// and completed snapshot. It does not authenticate observed live state.
    /// Empty version/platform selectors use the same deterministic package
    /// selection rules as documentation reads. A release selector additionally
    /// requires the indexed reference commit to equal that release's commit.
    ///
    /// # Errors
    ///
    /// Returns registry visibility failures, not-found for an absent package
    /// reference, and internal errors for corrupted signed reference bytes.
    pub async fn get_package_ability_reference(
        &self,
        auth: Option<&str>,
        req: pb::GetPackageAbilityReferenceRequest,
    ) -> Result<pb::GetPackageAbilityReferenceResponse, RpcError> {
        let registry = self.registry_or_not_found(&req.registry).await?;
        self.require_read(auth, &registry).await?;
        let locator = self
            .db
            .native_documentation_locator(
                registry.id,
                &req.package,
                &req.version,
                &req.platform,
                (!req.release.is_empty()).then_some(req.release.as_str()),
            )
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("native package reference"))?;
        let fetch =
            self.topology_surface_fetcher(aos_hub_db::db::SurfaceTarget::Registry(registry.id));
        let (canonical_json, _) =
            crate::indexer::native_documentation::fetch_native_documentation_content(
                fetch.as_ref(),
                &locator.package,
                &locator.version,
                &locator.platform,
                &locator.artifact,
            )
            .await
            .map_err(RpcError::internal)?;
        Ok(pb::GetPackageAbilityReferenceResponse {
            identity: Some(package_ability_reference_identity(&locator)),
            etag: locator.artifact.document_sha256,
            canonical_json,
        })
    }

    /// Fetches and verifies a previously authorized indexed documentation reference.
    ///
    /// # Errors
    /// Returns an error for missing objects, placement failures, or invalid document integrity.

    /// `DocumentationService.SearchPackageDocumentation` — ranked index search.
    ///
    /// # Errors
    ///
    /// Returns visibility, argument, pagination, or database errors.
    pub async fn search_package_documentation(
        &self,
        auth: Option<&str>,
        req: pb::SearchPackageDocumentationRequest,
    ) -> Result<pb::SearchPackageDocumentationResponse, RpcError> {
        let registry = self.registry_or_not_found(&req.registry).await?;
        self.require_read(auth, &registry).await?;
        let kind = (!req.kind.is_empty()).then_some(req.kind.as_str());
        if kind.is_some_and(|kind| !matches!(kind, "package" | "option" | "operation")) {
            return Err(RpcError::invalid(
                "native documentation kind must be package, option, or operation",
            ));
        }
        let terms = aos_module_docs::tokenize(&req.query);
        let mut results = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for release in self
            .db
            .list_releases(registry.id)
            .await
            .map_err(RpcError::internal)?
        {
            let documents = self
                .db
                .native_documentation_at_release(registry.id, &release.semver)
                .await
                .map_err(RpcError::internal)?;
            for document in documents {
                if !seen.insert((
                    document.package.clone(),
                    document.version.clone(),
                    document.platform.clone(),
                    document.document_sha256.clone(),
                )) {
                    continue;
                }
                for row in document.search {
                    if kind.is_some_and(|kind| row.kind != kind)
                        || !terms.iter().all(|term| row.terms.contains_key(term))
                    {
                        continue;
                    }
                    let score = terms
                        .iter()
                        .map(|term| u64::from(row.terms.get(term).copied().unwrap_or_default()))
                        .sum();
                    results.push(pb::PackageDocumentationSearchResult {
                        package: document.package.clone(),
                        version: document.version.clone(),
                        platform: document.platform.clone(),
                        kind: row.kind,
                        key: row.key,
                        title: row.title,
                        summary: row.summary,
                        score,
                        release: release.semver.clone(),
                        registry_commit: release.commit_oid.clone(),
                        document_sha256: document.document_sha256.clone(),
                    });
                }
            }
        }
        results.sort_by(|left, right| {
            right.score.cmp(&left.score).then_with(|| {
                (
                    &left.package,
                    &left.version,
                    &left.platform,
                    &left.kind,
                    &left.key,
                )
                    .cmp(&(
                        &right.package,
                        &right.version,
                        &right.platform,
                        &right.kind,
                        &right.key,
                    ))
            })
        });
        results.truncate(MAX_DOCUMENTATION_RESULTS);
        let (results, next_page_token) = paginate(results, req.page_size, &req.page_token)?;
        Ok(pb::SearchPackageDocumentationResponse {
            results,
            next_page_token,
        })
    }

    /// Loads one immutable documentation artifact by its signed document digest.
    ///
    /// # Errors
    ///
    /// Returns visibility, digest, not-found, placement, or integrity errors.
    pub async fn get_documentation_artifact(
        &self,
        auth: Option<&str>,
        req: pb::GetDocumentationArtifactRequest,
    ) -> Result<pb::GetPackageDocumentationResponse, RpcError> {
        if !is_sha256_digest(&req.document_sha256) {
            return Err(RpcError::invalid("invalid documentation digest"));
        }
        let registry = self.registry_or_not_found(&req.registry).await?;
        self.require_read(auth, &registry).await?;
        for release in self
            .db
            .list_releases(registry.id)
            .await
            .map_err(RpcError::internal)?
        {
            let documents = self
                .db
                .native_documentation_at_release(registry.id, &release.semver)
                .await
                .map_err(RpcError::internal)?;
            if let Some(document) = documents
                .iter()
                .find(|document| document.document_sha256 == req.document_sha256)
            {
                let (locator, _) = self
                    .load_native_documentation_for_registry(
                        registry.id,
                        &document.package,
                        &document.version,
                        &document.platform,
                        Some(&release.semver),
                    )
                    .await?;
                let fetch = self
                    .topology_surface_fetcher(aos_hub_db::db::SurfaceTarget::Registry(registry.id));
                let (canonical_json, _) =
                    crate::indexer::native_documentation::fetch_native_documentation_content(
                        fetch.as_ref(),
                        &locator.package,
                        &locator.version,
                        &locator.platform,
                        &locator.artifact,
                    )
                    .await
                    .map_err(RpcError::internal)?;
                return Ok(pb::GetPackageDocumentationResponse {
                    identity: Some(native_documentation_identity(&locator)),
                    canonical_json,
                    etag: locator.artifact.document_sha256,
                });
            }
        }
        Err(RpcError::not_found("native documentation artifact"))
    }

    /// Returns the exact checked native package reference used by tooling.
    ///
    /// # Errors
    ///
    /// Returns ordinary registry authorization and selection failures, or an
    /// internal error if the signed package reference fails verification.
    pub async fn get_package_documentation_schema(
        &self,
        auth: Option<&str>,
        req: pb::GetPackageDocumentationSchemaRequest,
    ) -> Result<pb::GetPackageDocumentationSchemaResponse, RpcError> {
        let registry = self.registry_or_not_found(&req.registry).await?;
        self.require_read(auth, &registry).await?;
        let locator = self
            .db
            .native_documentation_locator(
                registry.id,
                &req.package,
                &req.version,
                &req.platform,
                (!req.release.is_empty()).then_some(req.release.as_str()),
            )
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("native package documentation"))?;
        let fetch =
            self.topology_surface_fetcher(aos_hub_db::db::SurfaceTarget::Registry(registry.id));
        let (canonical_json, _) =
            crate::indexer::native_documentation::fetch_native_documentation_content(
                fetch.as_ref(),
                &locator.package,
                &locator.version,
                &locator.platform,
                &locator.artifact,
            )
            .await
            .map_err(RpcError::internal)?;
        Ok(pb::GetPackageDocumentationSchemaResponse {
            documentation_identity: Some(native_documentation_identity(&locator)),
            ability_reference_identity: None,
            canonical_json,
            etag: locator.artifact.document_sha256,
        })
    }

    /// Loads one structured option by its unambiguous path segments.
    ///
    /// # Errors
    ///
    /// Returns visibility, selection, path, not-found, or integrity errors.
    pub async fn get_package_option(
        &self,
        auth: Option<&str>,
        req: pb::GetPackageOptionRequest,
    ) -> Result<pb::GetPackageOptionResponse, RpcError> {
        let registry = self.registry_or_not_found(&req.registry).await?;
        self.require_read(auth, &registry).await?;
        let requested = req
            .path
            .iter()
            .map(|segment| match &segment.segment {
                Some(pb::documentation_path_segment::Segment::Literal(value))
                    if !value.is_empty() =>
                {
                    Ok(value.clone())
                }
                _ => Err(RpcError::invalid(
                    "native option paths require exact nonempty literal segments",
                )),
            })
            .collect::<Result<Vec<_>, _>>()?;
        if requested.is_empty() {
            return Err(RpcError::invalid("option path must not be empty"));
        }
        let (locator, document) = self
            .load_native_documentation_for_registry(
                registry.id,
                &req.package,
                &req.version,
                &req.platform,
                None,
            )
            .await?;
        let option = document
            .options()
            .iter()
            .find(|option| option.path == requested)
            .ok_or_else(|| RpcError::not_found("native package option"))?;
        Ok(pb::GetPackageOptionResponse {
            option: Some(
                native_option_view(&native_documentation_identity(&locator), option)
                    .map_err(RpcError::internal)?,
            ),
        })
    }
}
