//! Native direct-upload quota activation, dependency checks and atomic settlement.
//!
//! Provider I/O and full-byte verification finish before these SQL statements.
//! The caller commits them with the terminal provider journal in one transaction.

use super::*;

impl NativeUploadTargets {
    /// Reserves quota against the verified destination baseline before promotion.
    ///
    /// # Errors
    /// Rejects changed authority, baseline identity or exhausted quota.
    pub(crate) async fn activate_cache(
        &self,
        claims: &Claims,
        original: &NativeUploadOriginal,
        prior: Option<&aos_hub_core::db::WriteObjectIdentity>,
        now: i64,
    ) -> Result<()> {
        self.authorize(claims, original, now).await?;
        let NativeTargetOwner::Cache {
            cache_id,
            ticket_id,
        } = &original.owner
        else {
            return Ok(());
        };
        let cache = self
            .db
            .binary_cache_by_id(*cache_id)
            .await?
            .context("native cache absent")?;
        let ticket = self
            .db
            .cache_write_ticket(ticket_id)
            .await?
            .context("native cache ticket absent")?;
        if ticket.state == "active" {
            ensure!(
                ticket.intended_object_hash.as_deref()
                    == Some(original.intent.expected_sha256.as_str())
                    && ticket.prior_object.as_ref() == prior,
                "native cache baseline changed"
            );
            return Ok(());
        }
        let delta_bytes = if cache.org_id.is_some() {
            i64::try_from(original.intent.byte_size.get())? - prior.map_or(0, |object| object.size)
        } else {
            0
        };
        let delta_objects = i64::from(cache.org_id.is_some() && prior.is_none());
        self.db
            .activate_cache_write_ticket(
                ticket_id,
                ticket.resource_version,
                cache.org_id,
                delta_bytes,
                delta_objects,
                prior,
                Some(&original.intent.expected_sha256),
                now,
            )
            .await?;
        Ok(())
    }

    /// Builds current SQL checks and target settlement after complete-byte verification.
    ///
    /// The caller must check every completed provider object against the original
    /// SHA-256 and size before invoking this method. The returned statements must
    /// commit with the journal's verified source and terminal transition.
    ///
    /// # Errors
    /// Rejects changed authority, missing dependencies, invalid provider results or accounting failures.
    pub(crate) async fn final_statements(
        &self,
        claims: &Claims,
        original: &NativeUploadOriginal,
        verified: &[NativeVerifiedPlacement],
        projection: Option<&aos_hub_core::hybrid_ingress::HybridObjectProjection>,
        now: i64,
    ) -> Result<Vec<aos_hub_core::backend::CheckedStatement>> {
        self.authorize(claims, original, now).await?;
        ensure!(
            verified.len() == original.placements.len(),
            "native direct final placement set differs"
        );
        let mut statements = self.authority_statements(claims, original, now).await?;
        for (pin, result) in original.placements.iter().zip(verified) {
            ensure!(
                pin.placement_id == result.placement_id
                    && !result.etag.is_empty()
                    && result.etag.len() <= 512
                    && result
                        .provider_version
                        .as_ref()
                        .is_none_or(|value| !value.is_empty() && value.len() <= 512),
                "native direct final provider identity differs"
            );
        }
        statements.extend(self.dependency_statements(original, projection).await?);
        match (&original.owner, &original.intent.target) {
            (
                NativeTargetOwner::Cache { ticket_id, .. },
                DirectUploadTarget::CacheObject { .. },
            ) => {
                let ticket = self
                    .db
                    .cache_write_ticket(ticket_id)
                    .await?
                    .context("native cache ticket absent")?;
                ensure!(
                    ticket.intended_object_hash.as_deref()
                        == Some(original.intent.expected_sha256.as_str()),
                    "native cache source differs from quota reservation"
                );
                statements.extend(Database::complete_cache_write_ticket_statements(
                    ticket_id,
                    ticket.resource_version,
                    now,
                )?);
            }
            (
                NativeTargetOwner::Publication,
                DirectUploadTarget::PublicationObject {
                    publication_id,
                    surface_object_id,
                    ..
                },
            ) => {
                let object_id = i64::try_from(surface_object_id.get())?;
                for (index, (pin, result)) in original.placements.iter().zip(verified).enumerate() {
                    let presence = if index == 0 {
                        self.db
                            .verified_registry_publication_presence_statements(
                                publication_id,
                                object_id,
                                pin.placement_id,
                                &original.intent.expected_sha256,
                                i64::try_from(original.intent.byte_size.get())?,
                                Some(&result.etag),
                                now,
                                Some((
                                    pin.placement_resource_version,
                                    pin.binding_resource_version,
                                )),
                            )
                            .await?
                    } else {
                        Database::registry_publication_object_presence_statements(
                            publication_id,
                            object_id,
                            pin.placement_id,
                            &original.intent.expected_sha256,
                            i64::try_from(original.intent.byte_size.get())?,
                            Some(&result.etag),
                            now,
                            Some((pin.placement_resource_version, pin.binding_resource_version)),
                        )?
                    };
                    statements.extend(presence);
                }
            }
            (
                NativeTargetOwner::Oci { upload_id },
                DirectUploadTarget::OciBlob {
                    upload_id: target_upload_id,
                },
            ) => {
                ensure!(
                    upload_id == target_upload_id && verified.len() == 1,
                    "native OCI owner changed"
                );
                let upload = self
                    .db
                    .direct_oci_upload_for_actor(&self.deployment, &original.actor, upload_id, now)
                    .await?;
                let pin = &original.placements[0];
                let digest = aos_oci_types::Sha256Digest::parse(&format!(
                    "sha256:{}",
                    original.intent.expected_sha256
                ))?;
                let object_id = match self
                    .db
                    .surface_object_named(
                        SurfaceTarget::Registry(upload.registry_id),
                        &original.path,
                    )
                    .await?
                {
                    Some(object) => object.id,
                    None => (uuid::Uuid::new_v4().as_u128() % 9_007_199_254_740_991u128) as i64 + 1,
                };
                statements.extend(
                    self.db
                        .direct_oci_object_presence_statements(
                            upload.registry_id,
                            pin.placement_id,
                            digest,
                            original.intent.byte_size.get(),
                            &verified[0].etag,
                            now,
                            object_id,
                        )
                        .await?,
                );
                statements.extend(Database::complete_native_direct_oci_upload_statements(
                    &upload,
                    &self.deployment,
                    &original.session_id,
                    object_id,
                    pin.placement_id,
                    pin.placement_resource_version,
                    pin.binding_id,
                    pin.binding_write_revision,
                    now,
                )?);
            }
            _ => anyhow::bail!("native direct target owner differs"),
        }
        Ok(statements)
    }

    /// Builds commit-time current account, IAM and storage revision checks.
    ///
    /// # Errors
    /// Rejects invalid claims or unavailable current authorization state.
    pub(crate) async fn authority_statements(
        &self,
        claims: &Claims,
        original: &NativeUploadOriginal,
        now: i64,
    ) -> Result<Vec<aos_hub_core::backend::CheckedStatement>> {
        let permission = if matches!(original.owner, NativeTargetOwner::Cache { .. }) {
            Permission::RegistryConfigure
        } else {
            Permission::Publish
        };
        let mut statements = self
            .db
            .direct_iam_statements(claims, &original.scope, permission, now)
            .await?;
        statements.extend(original.placements.iter().map(NativePlacementPin::fence));
        Ok(statements)
    }

    async fn dependency_statements(
        &self,
        original: &NativeUploadOriginal,
        projection: Option<&aos_hub_core::hybrid_ingress::HybridObjectProjection>,
    ) -> Result<Vec<aos_hub_core::backend::CheckedStatement>> {
        use aos_hub_core::hybrid_ingress::HybridObjectProjection;
        match &original.intent.target {
            DirectUploadTarget::CacheObject { path, .. } if path.ends_with(".narinfo") => {
                let Some(HybridObjectProjection::Narinfo(projection)) = projection else {
                    anyhow::bail!("native narinfo parsed metadata absent");
                };
                projection.validate_cache_path(path)?;
                let NativeTargetOwner::Cache { cache_id, .. } = original.owner else {
                    anyhow::bail!("native narinfo cache owner differs");
                };
                let cache = self
                    .db
                    .binary_cache_by_id(cache_id)
                    .await?
                    .context("native cache absent")?;
                let signing = self
                    .db
                    .active_signing_key_for_usage(&cache.stable_id, "narinfo")
                    .await?;
                if let Some(key) = &signing {
                    projection.verify_selected_key(&key.name, &key.public_key)?;
                }
                let hash = aos_core::nar::cache::canonical_sha256_hex(&projection.file_hash)?;
                let mut statements = self
                    .db
                    .direct_cache_dependency_locks(cache_id, &projection.nar_url, signing.as_ref())
                    .await?;
                statements.push(Database::direct_cache_metadata_fence(
                    cache_id,
                    &projection.nar_url,
                    &hash,
                    projection.file_size.parse()?,
                    signing.as_ref(),
                )?);
                Ok(statements)
            }
            DirectUploadTarget::PublicationObject {
                publication_id,
                surface_object_id,
                ..
            } => {
                let object = self
                    .db
                    .registry_publication_upload_object(
                        publication_id,
                        i64::try_from(surface_object_id.get())?,
                    )
                    .await?
                    .context("native publication object absent")?;
                Ok(vec![Database::direct_publication_phase_fence(
                    publication_id,
                    object.object_kind == "mutable_pointer",
                )?])
            }
            _ => {
                ensure!(
                    projection.is_none(),
                    "native content cannot carry unrelated parsed metadata"
                );
                Ok(Vec::new())
            }
        }
    }
}

impl NativePlacementPin {
    fn fence(&self) -> aos_hub_core::backend::CheckedStatement {
        use aos_hub_core::{backend::Statement, value::Value};
        Statement::new(
            "UPDATE surface_placements SET resource_version = resource_version
             WHERE id = ?1 AND resource_version = ?2 AND write_spec_version = ?3
               AND binding_id = ?4 AND desired_state = 'active'
               AND EXISTS (SELECT 1 FROM bindings binding WHERE binding.id = ?4
                 AND binding.resource_version = ?5 AND binding.kind IN ('s3', 'r2') AND binding.access_mode = 'private')
               AND EXISTS (SELECT 1 FROM surface_placement_write_capabilities capability
                 WHERE capability.placement_id = ?1 AND capability.binding_id = ?4
                   AND capability.placement_write_spec_version = ?3 AND capability.binding_write_revision = ?6)
               AND EXISTS (SELECT 1 FROM binding_write_revisions revision
                 WHERE revision.binding_id = ?4 AND revision.revision = ?6
                   AND revision.write_credential_purpose = 'write' AND revision.write_credential_generation = ?7)
               AND EXISTS (SELECT 1 FROM binding_credential_heads head
                 JOIN binding_credential_revisions credential ON credential.binding_id = head.binding_id
                   AND credential.purpose = head.purpose AND credential.generation = head.current_generation
                 WHERE head.binding_id = ?4 AND head.purpose = 'write' AND head.current_generation = ?7 AND credential.validation_state = 'valid')
               AND EXISTS (SELECT 1 FROM binding_credential_heads head
                 JOIN binding_credential_revisions credential ON credential.binding_id = head.binding_id
                   AND credential.purpose = head.purpose AND credential.generation = head.current_generation
                 WHERE head.binding_id = ?4 AND head.purpose = 'read' AND head.current_generation = ?8 AND credential.validation_state = 'valid')
               AND EXISTS (SELECT 1 FROM binding_credential_heads head
                 JOIN binding_credential_revisions credential ON credential.binding_id = head.binding_id
                   AND credential.purpose = head.purpose AND credential.generation = head.current_generation
                 WHERE head.binding_id = ?4 AND head.purpose = 'presign' AND head.current_generation = ?9 AND credential.validation_state = 'valid')",
            [self.placement_id, self.placement_resource_version, self.write_spec_version, self.binding_id,
                self.binding_resource_version, self.binding_write_revision, self.write_credential_generation,
                self.read_credential_generation, self.presign_credential_generation].into_iter().map(Value::Int).collect(),
        ).expecting(1)
    }
}
