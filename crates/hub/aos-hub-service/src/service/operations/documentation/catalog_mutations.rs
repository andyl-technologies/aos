//! Catalog mutations in the documentation capability.

use super::*;

impl RpcService {
    /// Resolves and rechecks one native reference through a completed signed release.
    ///
    /// # Errors
    /// Returns an error for unavailable selections, corrupt catalogs, placement failures,
    /// or signed artifact mismatches. Callers must authorize registry reads first.
    pub(crate) async fn load_native_documentation_for_registry(
        &self,
        registry_id: i64,
        package: &str,
        version: &str,
        platform: &str,
        release: Option<&str>,
    ) -> Result<
        (
            crate::db::NativeDocumentationLocator,
            aos_module_docs::runtime::RuntimeDocument,
        ),
        RpcError,
    > {
        let locator = self
            .db
            .native_documentation_locator(registry_id, package, version, platform, release)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("native package documentation"))?;
        let fetch = self.topology_surface_fetcher(crate::db::SurfaceTarget::Registry(registry_id));
        let document = crate::indexer::native_documentation::fetch_native_documentation(
            fetch.as_ref(),
            &locator.package,
            &locator.version,
            &locator.platform,
            &locator.artifact,
        )
        .await
        .map_err(RpcError::internal)?;
        Ok((locator, document))
    }

    /// Compares two exact package documentation versions on one platform.
    ///
    /// # Errors
    ///
    /// Returns visibility, exact-selection, integrity, or comparison errors.
    pub async fn compare_package_documentation(
        &self,
        auth: Option<&str>,
        req: pb::ComparePackageDocumentationRequest,
    ) -> Result<pb::ComparePackageDocumentationResponse, RpcError> {
        if req.from_version.is_empty() || req.to_version.is_empty() || req.platform.is_empty() {
            return Err(RpcError::invalid(
                "comparison requires exact source and target versions and platform",
            ));
        }
        let registry = self.registry_or_not_found(&req.registry).await?;
        self.require_read(auth, &registry).await?;
        let (from_locator, from_document) = self
            .load_native_documentation_for_registry(
                registry.id,
                &req.package,
                &req.from_version,
                &req.platform,
                None,
            )
            .await?;
        let (to_locator, to_document) = self
            .load_native_documentation_for_registry(
                registry.id,
                &req.package,
                &req.to_version,
                &req.platform,
                None,
            )
            .await?;
        let comparison = from_document
            .compare(&to_document)
            .map_err(|error| RpcError::invalid(error.to_string()))?;
        Ok(pb::ComparePackageDocumentationResponse {
            from: Some(native_documentation_identity(&from_locator)),
            to: Some(native_documentation_identity(&to_locator)),
            canonical_comparison_json: serde_json::to_vec(&comparison)
                .map_err(RpcError::internal)?,
        })
    }
}
