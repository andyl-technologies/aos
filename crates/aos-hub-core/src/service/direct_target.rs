//! Existing publication phase and placement barriers shared by direct admission.

use super::*;

impl RpcService {
    /// Prepares an authorized publication object and returns its exact required placements.
    ///
    /// The caller first verifies current publish permission for the registry.
    /// Pointer writes retain the ordinary lease and immutable-object barrier.
    ///
    /// # Errors
    /// Returns an error for a closed phase, incomplete dependencies, lease conflict,
    /// stale publication watermark or missing required placement.
    pub async fn prepare_direct_publication_upload(
        &self,
        publication: &crate::db::RegistryPublicationRecord,
        registry: &crate::db::RegistryRecord,
        object: &crate::db::RegistryPublicationUploadObjectRecord,
    ) -> Result<Vec<crate::db::SurfacePlacementRecord>, RpcError> {
        self.prepare_registry_publication_object_upload(publication, registry, object)
            .await?;
        self.registry_publication_required_placements(
            &publication.publication_id,
            &object.object_kind,
        )
        .await
    }
}
