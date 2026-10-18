//! Packages reads in the registries capability.

use super::*;

impl RpcService {
    /// `PackageService.ListPackages` — package summaries with the newest version.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::NotFound`] for an unknown slug or a soft-deleted
    /// owning org, [`RpcError::Unauthenticated`]/[`RpcError::PermissionDenied`]
    /// when a non-public registry is read without authority,
    /// [`RpcError::InvalidArgument`] for a malformed `page_token`, and
    /// [`RpcError::Internal`] on database failure.
    pub async fn list_packages(
        &self,
        auth: Option<&str>,
        req: pb::ListPackagesRequest,
    ) -> Result<pb::ListPackagesResponse, RpcError> {
        let record = self.registry_or_not_found(&req.slug).await?;
        self.require_read(auth, &record).await?;
        let packages: Vec<pb::PackageSummary> = self
            .db
            .list_packages(record.id)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .map(|p| pb::PackageSummary {
                name: p.name,
                description: p.description,
                license: p.license,
                latest_version: p.latest_version.unwrap_or_default(),
            })
            .collect();
        let (packages, next_page_token) = paginate(packages, req.page_size, &req.page_token)?;
        Ok(pb::ListPackagesResponse {
            packages,
            next_page_token,
        })
    }

    /// `PackageService.GetPackage` — full version × platform detail for one package.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::NotFound`] for an unknown slug, package name, or a
    /// soft-deleted owning org,
    /// [`RpcError::Unauthenticated`]/[`RpcError::PermissionDenied`] when a
    /// non-public registry is read without authority, and [`RpcError::Internal`]
    /// on database failure.
    pub async fn get_package(
        &self,
        auth: Option<&str>,
        req: pb::GetPackageRequest,
    ) -> Result<pb::GetPackageResponse, RpcError> {
        let record = self.registry_or_not_found(&req.slug).await?;
        self.require_read(auth, &record).await?;
        let detail = self
            .db
            .package_detail(record.id, &req.name)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("package"))?;
        let versions = detail
            .versions
            .into_iter()
            .map(|v| pb::Version {
                version: v.version,
                previous: v.previous.unwrap_or_default(),
                platforms: v
                    .platforms
                    .into_iter()
                    .map(|p| pb::Platform {
                        platform: p.platform,
                        store_path: p.store_path,
                        nar_hash: p.nar_hash,
                        nar_size: p.nar_size,
                        closure_size: p.closure_size,
                    })
                    .collect(),
            })
            .collect();
        Ok(pb::GetPackageResponse {
            package: Some(pb::Package {
                name: detail.name,
                description: detail.description,
                homepage: detail.homepage.unwrap_or_default(),
                license: detail.license,
                maintainer: detail.maintainer,
                sysroot: detail.sysroot,
                versions,
            }),
        })
    }

    /// Lists structured options for one exact or default package selection.
    ///
    /// # Errors
    ///
    /// Returns visibility, selection, filter, pagination, or object-integrity errors.
    pub async fn list_package_options(
        &self,
        auth: Option<&str>,
        req: pb::ListPackageOptionsRequest,
    ) -> Result<pb::ListPackageOptionsResponse, RpcError> {
        self.list_package_options_at_release(auth, req, None).await
    }
}
