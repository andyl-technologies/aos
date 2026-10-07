//! Amortizes catalog selection for a native run of validated immutable metadata.
//!
//! This private path is reached only beneath actual native publication controls.
//! Every offered body receives ordinary schema and dependency validation. A
//! fallback is decided before this run performs any effects; it never turns a
//! corrupt or unavailable placement into absence. No generic Store API changes.

use super::*;
use crate::selected_bridge::native_guard::meta_batch::ImmutableEffectContext;

/// Distinguishes a completed native run from a required ordinary admission path.
///
/// This is ordinary control-flow data, not a durable receipt or permission.
pub(crate) enum BatchOutcome {
    /// Contains one verified identity for every offered input, in input order.
    Complete(Vec<Identity>),
    /// Requires ordinary puts because a direct container or repair is involved.
    Sequential,
}

impl<F, C, V> FileBucket<F, C, V>
where
    F: LocalFs + BucketBinding,
    C: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    /// Publishes one preflighted metadata run under the actual native context.
    ///
    /// # Errors
    /// Preserves schema, identity, dependency, quarantine, physical corruption,
    /// current-control, expiry and executor-acknowledgment failures. A failure
    /// after creation can leave an unselected pack; a failed catalog acknowledgment
    /// is indeterminate and is never reported as successful admission.
    pub(in crate::bucket) async fn put_meta_batch_locked(
        &self,
        held: &super::super::held::HeldBucket<'_, F, C, V, true>,
        uploads: &[MetaUpload<'_>],
        context: &ImmutableEffectContext<'_, '_>,
    ) -> Result<BatchOutcome, StoreFailure> {
        if !std::ptr::eq(self, held.bucket()) {
            return Err(files::layout_corrupt());
        }
        held.retained_namespace()?;
        context.recheck()?;
        let observed = held.observe_publication().await?;
        context.check_selection(&observed)?;
        self.write_layout_locked().await?;
        let catalog = self.catalog_observed(&observed).await?;

        // Direct Pack/Index admission has its own retirement/import semantics.
        // Decide fallback before validating dependencies or staging any member.
        if uploads
            .iter()
            .any(|upload| matches!(upload.kind(), IdentityKind::Pack | IdentityKind::Index))
        {
            return Ok(BatchOutcome::Sequential);
        }
        let mut identities = Vec::with_capacity(uploads.len());
        let mut distinct = BTreeMap::new();
        let mut missing = Vec::new();
        let mut existing = Vec::new();
        let mut repair = false;

        for upload in uploads {
            #[cfg(all(test, feature = "tokio", unix))]
            self.inner.content_observation.put(upload.kind());

            context.recheck()?;
            self.inner.validator.validate_meta(upload)?;
            let requirements = self.inner.validator.chunk_requirements(upload)?;
            self.validate_chunk_requirements(&catalog, &requirements)
                .await?;
            let identity = TERRANE_V1
                .calculate(upload.kind(), upload.bytes())
                .map_err(|_| invalid("STORE-33"))?;
            let hash = identity
                .terrane_v1_digest()
                .map_err(|_| invalid("STORE-33"))?;
            if self.is_quarantined(&catalog, &identity)? {
                return Err(corrupt(&identity));
            }
            identities.push(identity.clone());

            if let Some((previous_identity, previous_bytes)) = distinct.get(&hash) {
                if previous_identity != &identity || *previous_bytes != upload.bytes() {
                    return Err(corrupt(&identity));
                }
                // Validation above is still performed for each duplicate offer.
                continue;
            }
            distinct.insert(hash, (identity.clone(), upload.bytes()));
            let placement = self
                .placement_observed(held, &observed, &catalog, &identity)
                .await?;
            if placement
                .as_ref()
                .is_some_and(|placement| placement.is_missing())
            {
                repair = true;
                continue;
            }
            match self.location(&catalog, &identity) {
                Ok(_) => {
                    if self.verified_body(&catalog, &identity).await? != upload.bytes() {
                        return Err(corrupt(&identity));
                    }
                    existing.push((identity, placement));
                }
                Err(error) if matches!(error.kind(), StoreErrorKind::Absent(_)) => {
                    // Ordinary admission handles Tombstone/excluded rows; the same
                    // conservative catalog merge retains their physical binding.
                    missing.push((identity, *upload));
                }
                Err(error) => return Err(error),
            }
        }
        observed.revalidate().await?;
        context.recheck()?;
        for (_, placement) in &existing {
            if let Some(placement) = placement {
                self.recheck_placement(placement).await?;
            }
        }
        observed.revalidate().await?;
        context.recheck()?;
        if repair {
            return Ok(BatchOutcome::Sequential);
        }
        if missing.is_empty() {
            // Empty and all-existing runs never create an empty pack/catalog.
            // Their verified bodies and actual selection were refreshed above.
            return Ok(BatchOutcome::Complete(identities));
        }

        let id = PackId::generate(&self.inner.fs)
            .await
            .map_err(files::io_failure)?;
        if catalog
            .inventory
            .as_ref()
            .is_some_and(|entries| entries.iter().any(|entry| entry.pack_id == *id.as_bytes()))
        {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
        let mut writer = PackWriter::new(id, PackClass::Meta, false);
        for (identity, upload) in &missing {
            let appended = writer
                .append_raw(entry_kind(upload.kind())?, upload.bytes())
                .map_err(|_| invalid("STORE-33"))?;
            if appended
                != identity
                    .terrane_v1_digest()
                    .map_err(|_| invalid("STORE-33"))?
            {
                return Err(corrupt(identity));
            }
        }
        let sealed = writer.seal().map_err(|_| invalid("STORE-33"))?;
        let artifacts = super::super::containers::admitted_artifacts(
            id,
            sealed.bytes(),
            sealed.index_object(),
        )?;
        crate::store::native_publication_effects::stage_container_contextual(
            held.fs(),
            &observed,
            &artifacts,
            context,
        )
        .await?;
        let generation = catalog
            .capabilities
            .generation
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(files::layout_corrupt)?;
        let index = PackIndexSnapshot::decode(sealed.index_object(), generation)
            .map_err(|_| files::layout_corrupt())?;
        self.verified_container(artifacts.inventory()).await?;
        for (_, placement) in &existing {
            if let Some(placement) = placement {
                self.recheck_placement(placement).await?;
            }
        }
        context.recheck()?;
        self.publish_pack_catalog_contextual(
            held,
            &observed,
            super::super::catalog::CatalogAdmission {
                catalog,
                new: index,
                inventory: artifacts.inventory().clone(),
            },
            super::super::catalog::CatalogScope {
                placement: None,
                context: Some(context),
            },
        )
        .await?;

        let selected = held.observe_publication().await?;
        context.check_selection(&selected)?;
        let catalog = self.catalog_observed(&selected).await?;
        for identity in &identities {
            let bytes = distinct
                .get(
                    &identity
                        .terrane_v1_digest()
                        .map_err(|_| invalid("STORE-33"))?,
                )
                .ok_or_else(files::layout_corrupt)?
                .1;
            if self.verified_body(&catalog, identity).await? != bytes {
                return Err(corrupt(identity));
            }
        }
        selected.revalidate().await?;
        context.recheck()?;
        Ok(BatchOutcome::Complete(identities))
    }
}
