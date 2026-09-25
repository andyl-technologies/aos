//! Admission and SQL completion for Worker-owned registry publication bytes.
//!
//! The frozen manifest remains authoritative. Native grants exact R2 keys to
//! the Worker, then re-observes every required placement through storage-local
//! hashing before recording publication presence.

use crate::hybrid_ingress::{
    HybridPublicationUploadAdmission, HybridPublicationUploadCompletionRequest,
    HybridPublicationUploadPlacement, MAX_HYBRID_PUBLICATION_PLACEMENTS,
};
use crate::keymap;

use super::{clock, RpcError, RpcService};

impl RpcService {
    /// Authorizes one exact publication object and its required R2 placements.
    ///
    /// # Errors
    ///
    /// Returns an authorization, publication-phase, body-identity, topology,
    /// binding, or database error.
    pub async fn admit_hybrid_registry_publication_object(
        &self,
        auth: Option<&str>,
        publication_id: &str,
        surface_object_id: i64,
    ) -> Result<HybridPublicationUploadAdmission, RpcError> {
        let (publication, registry, object) = self
            .registry_publication_object_context(auth, publication_id, surface_object_id)
            .await?;
        self.prepare_registry_publication_object_upload(&publication, &registry, &object)
            .await?;
        let expected_size = u64::try_from(object.expected_size)
            .map_err(|_| RpcError::invalid("publication object size is out of range"))?;
        if expected_size > self.effective_complete_upload_bytes().await as u64 {
            return Err(RpcError::FailedPrecondition(
                "publication object requires bounded multipart upload".into(),
            ));
        }
        let required = self
            .registry_publication_required_placements(publication_id, &object.object_kind)
            .await?;
        if required.len() > MAX_HYBRID_PUBLICATION_PLACEMENTS {
            return Err(RpcError::ResourceExhausted(
                "publication has too many required placements for one upload".into(),
            ));
        }
        let companion = if keymap::is_git_pack_index_path(&object.object_key) {
            Some(
                aos_registry_surface::pack_index::companion_pack_path(&object.object_key)
                    .ok_or_else(|| RpcError::invalid("Git pack index path is invalid"))?,
            )
        } else {
            None
        };

        let mut placements = Vec::with_capacity(required.len());
        for placement in required {
            if !placement.effective_write_enabled {
                return Err(RpcError::FailedPrecondition(
                    "required publication placement is not writable".into(),
                ));
            }
            let binding = self
                .db
                .binding(placement.binding_id)
                .await
                .map_err(RpcError::internal)?
                .filter(|binding| binding.kind == "deployment_r2" && binding.is_instance_default)
                .ok_or_else(|| {
                    RpcError::FailedPrecondition(
                        "required publication placement is not on deployment R2".into(),
                    )
                })?;
            placements.push(HybridPublicationUploadPlacement {
                placement_id: placement.id,
                placement_resource_version: placement.resource_version,
                binding_id: binding.id,
                binding_resource_version: binding.resource_version,
                object_key: keymap::r2_key(&placement.prefix, &object.object_key),
                companion_pack_key: companion
                    .as_ref()
                    .map(|path| keymap::r2_key(&placement.prefix, path)),
            });
        }
        placements.sort_by_key(|placement| placement.placement_id);

        Ok(HybridPublicationUploadAdmission {
            path: object.object_key,
            size: object.expected_size,
            sha256: object.expected_hash,
            placements,
        })
    }

    /// Verifies Worker-written bytes beside R2 before recording SQL presence.
    ///
    /// # Errors
    ///
    /// Returns an authorization, stale-fence, missing-object, integrity, or
    /// database error. A partial write remains undiscoverable until all required
    /// placements have matching evidence.
    pub async fn complete_hybrid_registry_publication_object(
        &self,
        auth: Option<&str>,
        publication_id: &str,
        surface_object_id: i64,
        request: HybridPublicationUploadCompletionRequest,
    ) -> Result<(), RpcError> {
        let admission = self
            .admit_hybrid_registry_publication_object(auth, publication_id, surface_object_id)
            .await?;
        if request.placements != admission.placements
            || request.size != admission.size as u64
            || request.sha256 != admission.sha256
        {
            return Err(RpcError::FailedPrecondition(
                "publication identity or placement changed during hybrid upload".into(),
            ));
        }

        for admitted in &admission.placements {
            let placement = self
                .db
                .surface_placement(admitted.placement_id)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::FailedPrecondition("placement disappeared".into()))?;
            let fetch = self
                .surface
                .placement_fetcher(&placement)
                .await
                .map_err(|error| RpcError::Unavailable(format!("{error:#}")))?;
            let evidence = fetch
                .inventory_evidence(&admission.path)
                .await
                .map_err(|error| RpcError::Unavailable(format!("{error:#}")))?
                .ok_or_else(|| {
                    RpcError::Unavailable("publication object is absent after R2 PUT".into())
                })?;
            if evidence.size != admission.size || hex::encode(evidence.sha256) != admission.sha256 {
                return Err(RpcError::FailedPrecondition(
                    "publication object failed exact R2 verification".into(),
                ));
            }
            self.db
                .record_registry_publication_object_presence_fenced(
                    publication_id,
                    surface_object_id,
                    placement.id,
                    &admission.sha256,
                    evidence.size,
                    evidence.strong_etag.as_deref(),
                    clock::now_unix_secs(),
                    admitted.placement_resource_version,
                    admitted.binding_resource_version,
                )
                .await
                .map_err(RpcError::internal)?;
        }
        Ok(())
    }
}
