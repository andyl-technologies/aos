//! Admission and SQL completion for Worker-owned registry publication bytes.
//!
//! The frozen manifest remains authoritative. Native grants exact R2 keys to
//! the Worker, then re-observes every required placement through storage-local
//! hashing before recording publication presence.

use crate::hybrid_ingress::{
    HybridPublicationPartAdmission, HybridPublicationPartAdmissionRequest,
    HybridPublicationPartCompletionRequest, HybridPublicationPartDestination,
    HybridPublicationPartPreflight, HybridPublicationUploadAdmission,
    HybridPublicationUploadCompletionRequest, HybridPublicationUploadPlacement,
    MAX_HYBRID_PUBLICATION_PLACEMENTS,
};
use crate::keymap;

use super::{clock, pb, RegistryPublicationMultipartBackend, RpcError, RpcService};

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

impl RpcService {
    /// Checks one contiguous publication part before Worker consumes its body.
    ///
    /// # Errors
    ///
    /// Returns an authorization, upload phase, part shape, or topology error.
    pub async fn preflight_hybrid_registry_publication_part(
        &self,
        auth: Option<&str>,
        upload_id: &str,
        part_number: u32,
    ) -> Result<HybridPublicationPartPreflight, RpcError> {
        let (upload, object, _) = self
            .registry_publication_multipart_context(auth, upload_id)
            .await?;
        if upload.state != "active" || upload.pending_token.is_some() {
            return Err(RpcError::FailedPrecondition(
                "publication multipart upload is not ready for another part".into(),
            ));
        }
        publication_part_shape(&upload, &object, part_number)
    }

    /// Claims one exact publication part and freezes every R2 destination.
    ///
    /// # Errors
    ///
    /// Returns an authorization, digest, concurrent-claim, topology, or SQL error.
    pub async fn admit_hybrid_registry_publication_part(
        &self,
        auth: Option<&str>,
        upload_id: &str,
        part_number: u32,
        request: HybridPublicationPartAdmissionRequest,
    ) -> Result<HybridPublicationPartAdmission, RpcError> {
        let (upload, object, backends) = self
            .registry_publication_multipart_context(auth, upload_id)
            .await?;
        if upload.state != "active" {
            return Err(RpcError::FailedPrecondition(
                "publication multipart upload no longer accepts parts".into(),
            ));
        }
        let shape = publication_part_shape(&upload, &object, part_number)?;
        validate_publication_part_request(
            &shape,
            request.size,
            &request.body_sha256,
            request.prior_hashed_size,
            &request.next_sha256_state,
        )?;
        let destinations = self
            .hybrid_registry_part_destinations(&object.object_key, &backends)
            .await?;
        let claim_token = uuid::Uuid::new_v4().simple().to_string();
        self.db
            .claim_registry_publication_multipart_part(
                upload_id,
                part_number,
                &request.body_sha256,
                upload.hashed_size,
                &claim_token,
                clock::now_unix_secs(),
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        Ok(HybridPublicationPartAdmission {
            claim_token,
            destinations,
        })
    }

    /// Commits Worker-written provider tags for one claimed publication part.
    ///
    /// # Errors
    ///
    /// Returns an authorization, stale claim, changed topology, or SQL error.
    pub async fn complete_hybrid_registry_publication_part(
        &self,
        auth: Option<&str>,
        upload_id: &str,
        part_number: u32,
        request: HybridPublicationPartCompletionRequest,
    ) -> Result<pb::RegistryPublicationMultipartPart, RpcError> {
        let (upload, object, backends) = self
            .registry_publication_multipart_context(auth, upload_id)
            .await?;
        let shape = publication_part_shape(&upload, &object, part_number)?;
        validate_publication_part_request(
            &shape,
            request.size,
            &request.body_sha256,
            request.prior_hashed_size,
            &request.next_sha256_state,
        )?;
        let destinations = self
            .hybrid_registry_part_destinations(&object.object_key, &backends)
            .await?;
        if upload.state != "active"
            || upload.pending_part != Some(i64::from(part_number))
            || upload.pending_hash.as_deref() != Some(request.body_sha256.as_str())
            || upload.pending_token.as_deref() != Some(request.admission.claim_token.as_str())
            || request.admission.destinations != destinations
            || request.placements.len() != destinations.len()
        {
            return Err(RpcError::FailedPrecondition(
                "publication part claim or placement changed".into(),
            ));
        }
        let mut placements = Vec::with_capacity(destinations.len());
        for (destination, tag) in destinations.iter().zip(&request.placements) {
            if destination.placement_id != tag.placement_id
                || tag.etag.is_empty()
                || tag.etag.len() > 1024
                || crate::surface_write::strong_if_match_etag(&tag.etag).is_err()
            {
                return Err(RpcError::invalid("publication part R2 tags are invalid"));
            }
            placements.push((tag.placement_id, tag.etag.clone()));
        }
        let hashed_size = request
            .prior_hashed_size
            .checked_add(request.size)
            .ok_or_else(|| RpcError::invalid("publication multipart size overflowed"))?;
        self.db
            .record_registry_publication_multipart_part(
                upload_id,
                part_number,
                &placements,
                i64::try_from(request.prior_hashed_size).map_err(RpcError::internal)?,
                i64::try_from(hashed_size).map_err(RpcError::internal)?,
                &request.next_sha256_state,
                &request.body_sha256,
                &request.admission.claim_token,
            )
            .await
            .map_err(RpcError::internal)?;
        Ok(pb::RegistryPublicationMultipartPart {
            part_number,
            placements: placements
                .into_iter()
                .map(
                    |(placement_id, etag)| pb::RegistryPublicationPlacementPart {
                        placement_id,
                        etag,
                    },
                )
                .collect(),
        })
    }

    async fn hybrid_registry_part_destinations(
        &self,
        path: &str,
        backends: &[RegistryPublicationMultipartBackend],
    ) -> Result<Vec<HybridPublicationPartDestination>, RpcError> {
        if backends.is_empty() || backends.len() > MAX_HYBRID_PUBLICATION_PLACEMENTS {
            return Err(RpcError::ResourceExhausted(
                "publication has too many multipart R2 placements".into(),
            ));
        }
        let mut destinations = Vec::with_capacity(backends.len());
        for backend in backends {
            if backend.backend_upload_id.is_empty()
                || backend.backend_upload_id.len() > 1024
                || !backend
                    .backend_upload_id
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic() && byte != b'"' && byte != b'\\')
            {
                return Err(RpcError::FailedPrecondition(
                    "publication multipart provider identity is invalid".into(),
                ));
            }
            let placement = self
                .db
                .surface_placement(backend.placement_id)
                .await
                .map_err(RpcError::internal)?
                .filter(|placement| {
                    placement.resource_version == backend.placement_resource_version
                        && placement.effective_write_enabled
                })
                .ok_or_else(|| {
                    RpcError::FailedPrecondition("publication placement changed".into())
                })?;
            self.db
                .binding(placement.binding_id)
                .await
                .map_err(RpcError::internal)?
                .filter(|binding| binding.kind == "deployment_r2" && binding.is_instance_default)
                .ok_or_else(|| {
                    RpcError::FailedPrecondition(
                        "publication multipart requires deployment R2".into(),
                    )
                })?;
            destinations.push(HybridPublicationPartDestination {
                placement_id: placement.id,
                object_key: keymap::r2_key(&placement.prefix, path),
                backend_upload_id: backend.backend_upload_id.clone(),
            });
        }
        Ok(destinations)
    }
}

fn publication_part_shape(
    upload: &crate::db::RegistryPublicationMultipartUploadRecord,
    object: &crate::db::RegistryPublicationUploadObjectRecord,
    part_number: u32,
) -> Result<HybridPublicationPartPreflight, RpcError> {
    let expected_size = u64::try_from(object.expected_size)
        .map_err(|_| RpcError::invalid("publication object size is out of range"))?;
    let part_size = super::REGISTRY_PUBLICATION_PART_BYTES as u64;
    let offset = u64::from(
        part_number
            .checked_sub(1)
            .ok_or_else(|| RpcError::invalid("multipart part numbers are 1-based"))?,
    )
    .checked_mul(part_size)
    .ok_or_else(|| RpcError::invalid("multipart part offset overflowed"))?;
    if offset >= expected_size {
        return Err(RpcError::invalid("multipart part exceeds the object size"));
    }
    let prior_hashed_size = u64::try_from(upload.hashed_size)
        .map_err(|_| RpcError::internal(anyhow::anyhow!("multipart hash progress is negative")))?;
    if prior_hashed_size != offset {
        return Err(RpcError::FailedPrecondition(
            "multipart parts must be uploaded contiguously".into(),
        ));
    }
    let expected_part_size = (expected_size - offset).min(part_size);
    Ok(HybridPublicationPartPreflight {
        expected_part_size,
        prior_hashed_size,
        sha256_state: upload.sha256_state.clone(),
        expected_sha256: object.expected_hash.clone(),
        final_part: offset + expected_part_size == expected_size,
    })
}

fn validate_publication_part_request(
    shape: &HybridPublicationPartPreflight,
    size: u64,
    body_sha256: &str,
    prior_hashed_size: u64,
    next_sha256_state: &str,
) -> Result<(), RpcError> {
    let valid_digest = |value: &str| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    if size != shape.expected_part_size
        || prior_hashed_size != shape.prior_hashed_size
        || !valid_digest(body_sha256)
        || !valid_digest(next_sha256_state)
        || (shape.final_part && next_sha256_state != shape.expected_sha256)
    {
        return Err(RpcError::invalid(
            "publication part differs from its frozen byte identity",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{publication_part_shape, validate_publication_part_request};

    #[test]
    fn final_part_requires_exact_offset_size_and_complete_digest() {
        let part_size = super::super::REGISTRY_PUBLICATION_PART_BYTES as i64;
        let upload = crate::db::RegistryPublicationMultipartUploadRecord {
            upload_id: "upload-1".into(),
            publication_id: "publication-1".into(),
            registry_id: 1,
            surface_object_id: 2,
            state: "active".into(),
            expires_at: 1000,
            hashed_size: part_size,
            sha256_state: "a".repeat(64),
            pending_part: None,
            pending_hash: None,
            pending_token: None,
            pending_since: None,
            completion_token: None,
            completion_since: None,
        };
        let object = crate::db::RegistryPublicationUploadObjectRecord {
            publication_id: "publication-1".into(),
            registry_id: 1,
            surface_object_id: 2,
            object_key: "nar/large.nar".into(),
            object_kind: "immutable".into(),
            expected_hash: "b".repeat(64),
            expected_size: part_size + 13,
            verified: false,
        };
        let shape = publication_part_shape(&upload, &object, 2).unwrap();
        assert_eq!(shape.expected_part_size, 13);
        assert!(shape.final_part);
        assert!(validate_publication_part_request(
            &shape,
            13,
            &"c".repeat(64),
            part_size as u64,
            &object.expected_hash,
        )
        .is_ok());
        assert!(validate_publication_part_request(
            &shape,
            13,
            &"c".repeat(64),
            part_size as u64,
            &"d".repeat(64),
        )
        .is_err());
        assert!(publication_part_shape(&upload, &object, 1).is_err());
    }
}
