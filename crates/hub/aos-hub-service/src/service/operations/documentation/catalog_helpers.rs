//! Catalog helpers in the documentation capability.

use super::*;

impl RpcService {
    pub(in crate::service) async fn load_exact_package_ability_reference(
        &self,
        registry_id: i64,
        registry_commit: &str,
        package: &str,
        version: &str,
        platform: &str,
    ) -> Result<
        (
            crate::db::NativeDocumentationLocator,
            aos_module_docs::runtime::deployment::ReleasedReference,
        ),
        RpcError,
    > {
        use aos_module_docs::runtime::deployment::{NativePackageIdentity, ReleasedReference};
        let releases = self
            .db
            .list_releases(registry_id)
            .await
            .map_err(RpcError::internal)?;
        for release in releases
            .iter()
            .filter(|release| release.commit_oid == registry_commit)
        {
            let Some(locator) = self
                .db
                .native_documentation_locator(
                    registry_id,
                    package,
                    version,
                    platform,
                    Some(&release.semver),
                )
                .await
                .map_err(RpcError::internal)?
            else {
                continue;
            };
            let fetch =
                self.topology_surface_fetcher(crate::db::SurfaceTarget::Registry(registry_id));
            let (bytes, _) =
                crate::indexer::native_documentation::fetch_native_documentation_content(
                    fetch.as_ref(),
                    package,
                    version,
                    platform,
                    &locator.artifact,
                )
                .await
                .map_err(RpcError::internal)?;
            let reference = ReleasedReference {
                identity: NativePackageIdentity {
                    registry_commit: locator.commit.clone(),
                    package: package.into(),
                    version: version.into(),
                    platform: platform.into(),
                    document_sha256: aos_core::Sha256Digest::parse(
                        &locator.artifact.document_sha256,
                    )
                    .map_err(RpcError::internal)?,
                },
                reference_json: String::from_utf8(bytes).map_err(RpcError::internal)?,
            };
            return Ok((locator, reference));
        }
        Err(RpcError::not_found("exact native package reference"))
    }
}
