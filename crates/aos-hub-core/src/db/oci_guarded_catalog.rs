//! Authenticated storage-local OCI graph admission and current row fences.
//!
//! Independent readbacks carry semantic metadata only. They never replace the
//! exact uploaded byte identity, live actor/IAM rows, canonical presence, or
//! current registry writer. Ordinary catalog admission retains its raw config
//! digest check.

use super::*;

impl Database {
    /// Indexes exact Hybrid OCI metadata under independent stored-read proofs.
    ///
    /// This path preserves ordinary exact-byte validation and permits a
    /// canonical config projection only when an authenticated readback proves
    /// the exact original bytes, descriptor and current placement. It grants
    /// no provider effect or missing graph dependency.
    ///
    /// # Errors
    /// Returns an error for missing/expired proofs, a changed original upload,
    /// graph/config disagreement, current placement changes or database failure.
    pub(crate) async fn index_oci_repository_catalog_guarded(
        &self,
        input: &IndexOciRepositoryCatalog,
        readbacks: &[crate::oci_projection::guard::VerifiedOciProjection],
        authority_statements: Vec<CheckedStatement>,
        authority_expires_at: i64,
    ) -> Result<OciRepositoryRecord> {
        anyhow::ensure!(
            !readbacks.is_empty() && readbacks.len() <= 2,
            "OCI completion requires a bounded root/config readback set"
        );
        anyhow::ensure!(
            !authority_statements.is_empty()
                && authority_expires_at > crate::clock::now_unix_secs(),
            "OCI completion requires live checked authority"
        );
        let root = input
            .objects
            .iter()
            .find(|object| object.descriptor.digest == input.root_digest)
            .context("OCI root is absent")?;
        let root_proof = readbacks
            .iter()
            .find(|proof| {
                proof
                    .check(&root.descriptor, crate::clock::now_unix_secs())
                    .is_ok()
            })
            .context("OCI root has no exact current readback")?;
        let projection = root_proof.check(&root.descriptor, crate::clock::now_unix_secs())?;
        let same_root = match (&root.projection, projection) {
            (
                Some(OciCatalogProjection::Manifest { document, .. }),
                crate::oci_projection::OciDocumentProjection::Manifest(observed),
            ) => document == observed,
            (
                Some(OciCatalogProjection::Index(document)),
                crate::oci_projection::OciDocumentProjection::Index(observed),
            ) => document == observed,
            _ => false,
        };
        anyhow::ensure!(
            same_root,
            "OCI root projection differs from actual stored bytes"
        );
        let admission = root_proof
            .admission()
            .context("OCI root readback has no original upload")?;
        let placement = self
            .surface_placement(input.placement_id)
            .await?
            .context("OCI placement disappeared")?;
        anyhow::ensure!(
            placement.prefix == admission.placement_prefix
                && (root_proof.key()
                    == crate::keymap::r2_key(&placement.prefix, &admission.staging_object_key)
                    || root_proof.key()
                        == crate::keymap::r2_key(
                            &placement.prefix,
                            &oci_blob_object_key(input.root_digest)
                        )),
            "OCI root readback addressed another placement"
        );
        for object in &input.objects {
            if let Some(OciCatalogProjection::Manifest {
                document,
                image_config: Some(_),
                ..
            }) = &object.projection
            {
                for proof in readbacks.iter().filter(|proof| {
                    proof
                        .check(&document.config, crate::clock::now_unix_secs())
                        .is_ok()
                }) {
                    anyhow::ensure!(
                        proof.key()
                            == crate::keymap::r2_key(
                                &placement.prefix,
                                &oci_blob_object_key(document.config.digest)
                            ),
                        "OCI image config readback addressed another placement"
                    );
                }
            }
        }
        let upload = self
            .hybrid_oci_manifest_upload(
                &admission.upload_id,
                &input.actor_id,
                crate::clock::now_unix_secs(),
            )
            .await?
            .context("OCI original upload disappeared")?;
        let binding = self
            .binding(placement.binding_id)
            .await?
            .context("OCI binding disappeared")?;
        let revision_number = upload
            .materialization_binding_write_revision
            .context("OCI writer revision is absent")?;
        let revision = self
            .binding_write_revision(binding.id, revision_number)
            .await?
            .context("OCI writer revision disappeared")?;
        let authority = self
            .surface_write_authority(crate::db::SurfaceTarget::Registry(input.registry_id))
            .await?
            .context("OCI current writer is absent")?;
        let reference = input
            .tag
            .clone()
            .map(ManifestReference::Tag)
            .unwrap_or(ManifestReference::Digest(input.root_digest));
        let original = crate::oci_projection::manifest_original_digest(
            input.registry_id,
            upload.repository_id,
            &input.actor_id,
            &reference,
            root.descriptor.media_type,
            &placement,
            &binding,
            revision_number,
            &authority,
        )?;
        anyhow::ensure!(
            original == admission.original_digest
                && self
                    .hybrid_oci_manifest_original_digest(&upload.id, &input.actor_id)
                    .await?
                    .as_deref()
                    == Some(original.as_str()),
            "OCI original target/authority changed"
        );
        let mut statements = build_oci_catalog_statements_with_readbacks(input, readbacks)?;
        let mut guarded = authority_statements;
        // Match normal upload/GC order: current actor/org, registry, binding,
        // writer, placement, then the exact upload and catalog dependencies.
        guarded.push(statements.remove(0));
        guarded.extend([
            Statement::new("UPDATE bindings SET resource_version = resource_version
                WHERE id = ?1 AND stable_id = ?2 AND resource_version = ?3",
                vals![binding.id, binding.stable_id, binding.resource_version]).expecting(1),
            Statement::new("UPDATE binding_credential_revisions SET validated_at = validated_at
                WHERE binding_id = ?1 AND purpose = ?2 AND generation = ?3
                  AND secret_version_ref = ?4 AND validation_state = 'valid'",
                vals![binding.id, revision.write_credential_purpose, revision.write_credential_generation,
                    revision.write_credential_version_ref]).expecting(1),
            Statement::new("UPDATE binding_write_state SET updated_at = updated_at
                WHERE binding_id = ?1 AND current_write_revision = ?2", vals![binding.id, revision_number]).expecting(1),
            Statement::new("UPDATE binding_write_revisions SET created_at = created_at
                WHERE binding_id = ?1 AND revision = ?2 AND revision_fingerprint = ?3
                  AND writes_supported = 1",
                vals![binding.id, revision_number, revision.revision_fingerprint]).expecting(1),
            Statement::new("UPDATE binding_write_observations SET validated_at = validated_at
                WHERE binding_id = ?1 AND revision = ?2 AND state = 'valid'",
                vals![binding.id, revision_number]).expecting(1),
            Statement::new("UPDATE surface_write_authorities SET updated_at = updated_at
                WHERE id = ?1 AND incarnation_id = ?2 AND registry_id = ?3 AND resource_version = ?4
                  AND desired_placement_id = ?5 AND observed_placement_id = ?5
                  AND desired_write_spec_version = ?6 AND observed_write_spec_version = ?6
                  AND desired_binding_write_revision = ?7 AND observed_binding_write_revision = ?7
                  AND desired_generation = ?8 AND observed_generation = ?8 AND reconciliation_state = 'ready'",
                vals![authority.id, authority.incarnation_id, input.registry_id, authority.resource_version,
                    placement.id, placement.write_spec_version, revision_number, authority.desired_generation]).expecting(1),
            Statement::new("UPDATE surface_placements SET updated_at = updated_at
                WHERE id = ?1 AND registry_id = ?2 AND binding_id = ?3 AND resource_version = ?4
                  AND write_spec_version = ?5 AND prefix = ?6 AND kind = 'complete' AND desired_state = 'active'",
                vals![placement.id, input.registry_id, binding.id, placement.resource_version,
                    placement.write_spec_version, placement.prefix]).expecting(1),
            Statement::new("UPDATE surface_placement_observations SET observed_at = observed_at
                WHERE placement_id = ?1 AND observation_version = ?2 AND state = 'ready' AND completeness = 'complete'",
                vals![placement.id, placement.observation_version]).expecting(1),
            Statement::new("UPDATE surface_placement_write_capabilities SET created_at = created_at
                WHERE placement_id = ?1 AND placement_write_spec_version = ?2
                  AND binding_id = ?3 AND binding_write_revision = ?4",
                vals![placement.id, placement.write_spec_version, binding.id, revision_number]).expecting(1),
            Statement::new("UPDATE oci_upload_sessions SET resource_version = resource_version
                WHERE id = ?1 AND registry_id = ?2 AND writer_id = ?3 AND token_id = ?3
                  AND resource_version = ?4 AND state = 'complete' AND final_digest = ?5 AND expected_digest = ?5
                  AND expected_size = ?6 AND uploaded_size = ?6 AND repository_id = ?7
                  AND staging_placement_id = ?8 AND materialization_placement_id = ?8
                  AND staging_placement_resource_version = ?9 AND materialization_placement_resource_version = ?9
                  AND staging_binding_id = ?10 AND materialization_binding_id = ?10
                  AND staging_binding_write_revision = ?11 AND materialization_binding_write_revision = ?11
                  AND idempotency_key LIKE ?12
                  AND EXISTS (SELECT 1 FROM oci_upload_chunks chunk WHERE chunk.upload_id = oci_upload_sessions.id
                    AND chunk.ordinal = 0 AND chunk.digest = ?5 AND chunk.byte_size = ?6 AND chunk.staging_object_key = ?13)
                  AND EXISTS (SELECT 1 FROM oci_repositories repository
                    WHERE repository.id = ?7 AND repository.registry_id = ?2 AND repository.name = ?14
                      AND repository.lifecycle_state = 'active')",
                vals![upload.id, input.registry_id, input.actor_id, upload.resource_version, input.root_digest.to_string(),
                    checked_u64(root.descriptor.size, "root size")?, upload.repository_id, placement.id,
                    placement.resource_version, binding.id, revision_number, format!("manifest-hybrid-{original}-%"),
                    admission.staging_object_key, input.repository.as_str()]).expecting(1),
        ]);
        for proof in readbacks {
            let object = input
                .objects
                .iter()
                .find(|object| {
                    proof
                        .check(&object.descriptor, crate::clock::now_unix_secs())
                        .is_ok()
                })
                .context("OCI readback is outside the exact closed graph")?;
            let identity = proof.object();
            anyhow::ensure!(
                proof.key()
                    == crate::keymap::r2_key(
                        &placement.prefix,
                        &oci_blob_object_key(object.descriptor.digest)
                    ),
                "OCI final readback does not address its canonical object"
            );
            guarded.push(Statement::new(
                "UPDATE object_placements SET observed_at = observed_at
                 WHERE registry_id = ?1 AND placement_id = ?2 AND state = 'present'
                   AND observed_hash = ?3 AND observed_size = ?4 AND etag = ?5
                   AND (provider_version IS NULL OR provider_version = ?6)
                   AND EXISTS (SELECT 1 FROM surface_objects object
                     WHERE object.id = object_placements.surface_object_id AND object.registry_id = ?1
                       AND object.object_key = ?7 AND object.content_hash = ?3 AND object.size = ?4
                       AND object.lifecycle_state = 'active'
                       AND object_placements.catalog_object_resource_version = object.resource_version)",
                vals![input.registry_id, placement.id, object.descriptor.digest.encoded(),
                    checked_u64(object.descriptor.size, "projection object size")?, identity.etag,
                    identity.provider_version, oci_blob_object_key(object.descriptor.digest)],
            ).expecting(1));
        }
        guarded.append(&mut statements);
        let deadline = readbacks
            .iter()
            .map(|proof| proof.deadline())
            .min()
            .context("OCI completion has no proof deadline")?
            .min(authority_expires_at);
        let remaining = deadline
            .checked_sub(crate::clock::now_unix_secs())
            .filter(|seconds| *seconds > 0)
            .context("OCI completion deadline expired")?;
        let transaction = Box::pin(self.backend.checked_batch(&guarded));
        let timeout = Box::pin(crate::clock::sleep(std::time::Duration::from_secs(
            u64::try_from(remaining)?,
        )));
        match futures_util::future::select(transaction, timeout).await {
            futures_util::future::Either::Left((result, _)) => result?,
            futures_util::future::Either::Right(_) => {
                anyhow::bail!("OCI completion outcome is unresolved after its deadline")
            }
        }
        anyhow::ensure!(
            crate::clock::now_unix_secs() < deadline,
            "OCI completion outcome needs exact original requery"
        );
        let repository = self
            .oci_repository(input.registry_id, &input.repository)
            .await?
            .context("indexed OCI repository disappeared")?;
        anyhow::ensure!(
            crate::clock::now_unix_secs() < deadline,
            "OCI completion readback needs exact original requery"
        );
        Ok(repository)
    }
}
