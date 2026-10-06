//! Authenticated compact archive inventories and complete RAM availability.
//!
//! Operational readers verify RAM graphs under retained source authority. GC
//! readers authenticate only the bounded inventory and root records under an
//! existing exclusive fence, then require separate transitive RAM marking.

use std::io;

use super::*;
use crate::CampaignArchiveInspection;
use crate::archive::build_inspection;
use crate::object_profile::profile_authenticated_exact_leaf;

impl CampaignRepository {
    /// Loads an archive ref and authenticates its complete direct inventory.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignRepositoryError`] for an invalid or absent ref, corrupt
    /// manifest/page metadata, or any missing, corrupt, or misprofiled selected
    /// object.
    pub fn inspect_campaign_archive_ref(
        &self,
        name: &str,
    ) -> Result<CampaignArchiveInspection, CampaignRepositoryError> {
        self.inspect_campaign_archive_ref_with_boundary(name, &mut || Ok(()))
    }

    /// Authenticates a named archive under its original preparation boundary.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid or missing references, corrupt archive
    /// contents, or a rejected operational boundary.
    pub fn inspect_campaign_archive_ref_with_boundary(
        &self,
        name: &str,
        boundary: &mut dyn FnMut() -> Result<(), crucible_cas::ram::RamStoreError>,
    ) -> Result<CampaignArchiveInspection, CampaignRepositoryError> {
        boundary().map_err(CampaignRepositoryError::Ram)?;
        let target = self
            .refs
            .read_ref(&archive_ref(name)?)?
            .ok_or(CampaignRepositoryError::NotFound)?;
        let id = CampaignArchiveManifestId::from_content_id(target)?;
        self.inspect_campaign_archive_with_boundary(id, boundary)
    }

    /// Authenticates one archive manifest, every inventory page, and every selected object.
    ///
    /// Selected objects are authenticated independently to EOF and compared
    /// with their profiler-derived records. Their ordinary child edges are not
    /// traversed across the declared archive boundary.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignRepositoryError`] for missing or corrupt metadata,
    /// inconsistent page order/digests, or a missing, corrupt, or misprofiled
    /// selected object.
    pub fn inspect_campaign_archive(
        &self,
        id: CampaignArchiveManifestId,
    ) -> Result<CampaignArchiveInspection, CampaignRepositoryError> {
        self.inspect_campaign_archive_with_boundary(id, &mut || Ok(()))
    }

    /// Inspects complete archive availability under its operation boundary.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid metadata, missing or corrupt selected
    /// descendants, or a rejected operational boundary.
    pub fn inspect_campaign_archive_with_boundary(
        &self,
        id: CampaignArchiveManifestId,
        boundary: &mut dyn FnMut() -> Result<(), crucible_cas::ram::RamStoreError>,
    ) -> Result<CampaignArchiveInspection, CampaignRepositoryError> {
        self.inspect_campaign_archive_owned(id, true, boundary)
    }

    /// Authenticates archive metadata under an already held destructive fence.
    ///
    /// Selected RAM roots must subsequently enter the GC transitive root set,
    /// and their full graphs must authenticate under `inventory` before any
    /// deletion. This metadata read creates no shared fence or lazy RAM source.
    ///
    /// # Errors
    ///
    /// Returns an error for corrupt archive metadata, generic selected objects,
    /// RAM root metadata, or inconsistent inventory and policy declarations.
    pub fn inspect_campaign_archive_for_gc(
        &self,
        id: CampaignArchiveManifestId,
        _inventory: &dyn crucible_cas::content_store::RefInventoryFence,
    ) -> Result<CampaignArchiveInspection, CampaignRepositoryError> {
        self.inspect_campaign_archive_owned(id, false, &mut || Ok(()))
    }

    pub(super) fn inspect_campaign_archive_owned(
        &self,
        id: CampaignArchiveManifestId,
        verify_ram: bool,
        boundary: &mut dyn FnMut() -> Result<(), crucible_cas::ram::RamStoreError>,
    ) -> Result<CampaignArchiveInspection, CampaignRepositoryError> {
        boundary().map_err(CampaignRepositoryError::Ram)?;
        let envelope =
            self.require_record_kind(id.content_id(), CampaignRecordKind::ArchiveManifest)?;
        let manifest = CampaignArchiveManifest::from_canonical_bytes(envelope.body())?;
        if manifest.id()? != id {
            return Err(integrity("campaign-archive-manifest-envelope-shape"));
        }

        let (selected, mut page_ids) = self.read_archive_pages(
            manifest.selected_pages(),
            ArchiveInventoryDisposition::Selected,
            boundary,
        )?;
        let (omitted, omitted_page_ids) = self.read_archive_pages(
            manifest.omitted_pages(),
            ArchiveInventoryDisposition::Omitted,
            boundary,
        )?;
        page_ids.extend(omitted_page_ids);
        if selected.len() as u64 != manifest.selected_count()
            || omitted.len() as u64 != manifest.omitted_count()
            || inventory_digest(&selected) != manifest.selected_digest()
            || inventory_digest(&omitted) != manifest.omitted_digest()
        {
            return Err(integrity("campaign-archive-inventory-manifest-mismatch"));
        }

        let declared = selected
            .iter()
            .chain(&omitted)
            .map(|entry| entry.id())
            .collect::<BTreeSet<_>>();
        if !declared.contains(&manifest.source_snapshot().content_id()) {
            return Err(integrity("campaign-archive-source-snapshot-is-undeclared"));
        }

        let executable_closure = if matches!(
            manifest.policy(),
            CampaignArchivePolicy::Executable | CampaignArchivePolicy::Mirror
        ) {
            let roots = [manifest.source_snapshot().content_id()]
                .into_iter()
                .chain(manifest.retained_roots().iter().copied())
                .chain(
                    manifest
                        .checkpoint_selections()
                        .iter()
                        .map(|selection| selection.checkpoint().content_id()),
                );
            Some(self.authenticated_archive_closure(roots, verify_ram, boundary)?)
        } else {
            None
        };
        let mut exact_leaves = executable_closure
            .as_ref()
            .map_or_else(BTreeSet::new, |closure| closure.exact_leaves.clone());
        let selected_ids = selected
            .iter()
            .map(|entry| entry.id())
            .collect::<BTreeSet<_>>();
        let ram_roots = manifest
            .ram_roots()
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if !ram_roots.is_subset(&selected_ids) {
            return Err(integrity("campaign-archive-ram-root-is-not-selected"));
        }
        let mut typed_selected_roots = BTreeSet::new();
        let mut world_ram_roots = BTreeSet::new();
        for entry in &selected {
            boundary().map_err(CampaignRepositoryError::Ram)?;
            if entry.id().kind() != ObjectKind::ExactManifest {
                continue;
            }
            let bytes = self
                .blobs
                .read(entry.id(), None)?
                .read_all(MAX_ENVELOPE_BYTES)?;
            let envelope =
                ContentEnvelope::from_canonical_bytes(&bytes).map_err(CampaignCodecError::from)?;
            if envelope.content_id(ObjectKind::ExactManifest) != entry.id() {
                return Err(integrity("campaign-archive-exact-root-identity"));
            }
            if envelope.schema_name() == "crucible.ram.root" && envelope.schema_version() == 1 {
                typed_selected_roots.insert(entry.id());
            }
            if envelope.schema_name() == "crucible.executor.exact-checkpoint-root"
                && envelope.schema_version() == 6
            {
                let mut ordinal = 0_u32;
                for child in envelope
                    .children()
                    .iter()
                    .filter(|child| child.role().starts_with("ram-root-"))
                {
                    if child.role() != format!("ram-root-{ordinal:08x}")
                        || child.id().kind() != ObjectKind::ExactManifest
                        || child.id().schema_version() != 1
                    {
                        return Err(integrity("campaign-archive-world-ram-role-mismatch"));
                    }
                    world_ram_roots.insert(child.id());
                    ordinal = ordinal
                        .checked_add(1)
                        .ok_or_else(|| integrity("campaign-archive-world-ram-limit"))?;
                }
                for child in envelope.children().iter().filter(|child| {
                    matches!(
                        child.role(),
                        "checkpoint-choice-closure" | "replay-oracle-evidence"
                    )
                }) {
                    exact_leaves.insert(child.id());
                }
            }
        }
        if typed_selected_roots != ram_roots || !ram_roots.is_subset(&world_ram_roots) {
            return Err(integrity("campaign-archive-ram-root-inventory-mismatch"));
        }
        let profiler = CampaignObjectProfiler;
        let mut selected_children = BTreeMap::new();
        for entry in &selected {
            let (profile, children) = self.authenticate_archive_object(
                entry.id(),
                &profiler,
                exact_leaves.contains(&entry.id()),
                ram_roots.contains(&entry.id()),
                verify_ram && executable_closure.is_none(),
                boundary,
            )?;
            if !entry.matches_profile(profile) {
                return Err(integrity(
                    "campaign-archive-selected-object-profile-mismatch",
                ));
            }
            if children.iter().any(|child| !declared.contains(child)) {
                return Err(integrity("campaign-archive-selected-child-is-undeclared"));
            }
            selected_children.insert(entry.id(), children);
        }
        let mut omitted_inventory_verified = true;
        for entry in &omitted {
            match self.authenticate_archive_object(
                entry.id(),
                &profiler,
                exact_leaves.contains(&entry.id()),
                false,
                false,
                boundary,
            ) {
                Ok((profile, _)) if entry.matches_profile(profile) => {}
                Ok(_) => {
                    return Err(integrity(
                        "campaign-archive-omitted-object-profile-mismatch",
                    ));
                }
                Err(CampaignRepositoryError::Store(StoreError::NotFound { .. })) => {
                    omitted_inventory_verified = false;
                }
                Err(source) => return Err(source),
            }
        }
        self.validate_archive_policy(&manifest, &selected, &omitted, &selected_children)?;
        if let Some(complete) = executable_closure {
            self.reject_nested_archive_metadata(&complete.objects, &complete.exact_leaves)?;
            if complete.objects != selected_ids
                || complete.ram_roots != manifest.ram_roots()
                || !omitted.is_empty()
            {
                return Err(integrity(
                    "campaign-archive-executable-closure-is-incomplete",
                ));
            }
        }
        build_inspection(
            id,
            manifest,
            selected,
            omitted,
            page_ids,
            omitted_inventory_verified,
        )
        .map_err(CampaignRepositoryError::from)
    }

    /// Authenticates one finding in a complete imported archive.
    ///
    /// The archive binds the original snapshot, finding evidence, scenario and
    /// configuration artifacts. This read supports model-only findings without
    /// requiring a retained exact checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignRepositoryError`] when the archive is partial or
    /// corrupt, or the finding is absent from its source snapshot.
    pub fn inspect_archived_finding(
        &self,
        archive: CampaignArchiveManifestId,
        finding: crate::FindingId,
    ) -> Result<Finding, CampaignRepositoryError> {
        self.inspect_archived_finding_with_boundary(archive, finding, &mut || Ok(()))
    }

    /// Authenticates an archived finding under its complete read operation boundary.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid archive availability, absent finding
    /// membership, or a rejected operational boundary.
    pub fn inspect_archived_finding_with_boundary(
        &self,
        archive: CampaignArchiveManifestId,
        finding: crate::FindingId,
        boundary: &mut dyn FnMut() -> Result<(), crucible_cas::ram::RamStoreError>,
    ) -> Result<Finding, CampaignRepositoryError> {
        let inspection = self.inspect_campaign_archive_with_boundary(archive, boundary)?;
        if !matches!(
            inspection.manifest().policy(),
            CampaignArchivePolicy::Executable | CampaignArchivePolicy::Mirror
        ) {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "finding handoff requires an executable archive",
            });
        }

        boundary().map_err(CampaignRepositoryError::Ram)?;
        let snapshot = self.read_snapshot(inspection.manifest().source_snapshot().content_id())?;
        let (finding, _) = self.finding_with_proof(snapshot.snapshot.roots().findings, finding)?;
        Ok(finding)
    }

    /// Authenticates one exact-capable finding in a complete imported archive.
    ///
    /// The returned finding retains role-tagged checkpoints for the ordinary
    /// debug-session selection path.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignRepositoryError`] when archive membership fails or
    /// the finding has no retained exact checkpoint.
    pub fn inspect_archived_exact_finding(
        &self,
        archive: CampaignArchiveManifestId,
        finding: crate::FindingId,
    ) -> Result<Finding, CampaignRepositoryError> {
        self.inspect_archived_exact_finding_with_boundary(archive, finding, &mut || Ok(()))
    }

    /// Authenticates an exact-capable finding under its original read boundary.
    ///
    /// # Errors
    /// Refuses invalid archive membership, absent exact pins, or a rejected
    /// operational boundary during complete archive authentication.
    pub fn inspect_archived_exact_finding_with_boundary(
        &self,
        archive: CampaignArchiveManifestId,
        finding: crate::FindingId,
        boundary: &mut dyn FnMut() -> Result<(), crucible_cas::ram::RamStoreError>,
    ) -> Result<Finding, CampaignRepositoryError> {
        let finding = self.inspect_archived_finding_with_boundary(archive, finding, boundary)?;
        if finding.exact_pins().is_empty() {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "archived finding has no retained exact checkpoint",
            });
        }
        Ok(finding)
    }

    fn read_archive_pages(
        &self,
        ids: &[CampaignArchiveInventoryPageId],
        disposition: ArchiveInventoryDisposition,
        boundary: &mut dyn FnMut() -> Result<(), crucible_cas::ram::RamStoreError>,
    ) -> Result<(Vec<ArchiveObjectEntry>, Vec<ContentId>), CampaignRepositoryError> {
        let mut entries = Vec::new();
        let mut page_ids = Vec::with_capacity(ids.len());
        for (ordinal, id) in ids.iter().copied().enumerate() {
            boundary().map_err(CampaignRepositoryError::Ram)?;
            let envelope = self
                .require_record_kind(id.content_id(), CampaignRecordKind::ArchiveInventoryPage)?;
            let page = CampaignArchiveInventoryPage::from_canonical_bytes(envelope.body())?;
            if page.id()? != id
                || page.disposition() != disposition
                || page.ordinal() as usize != ordinal
            {
                return Err(integrity("campaign-archive-inventory-page-mismatch"));
            }
            if entries
                .last()
                .is_some_and(|prior: &ArchiveObjectEntry| prior.id() >= page.entries()[0].id())
            {
                return Err(integrity("campaign-archive-inventory-order-mismatch"));
            }
            entries.extend_from_slice(page.entries());
            page_ids.push(id.content_id());
        }
        Ok((entries, page_ids))
    }

    fn authenticate_archive_object(
        &self,
        id: ContentId,
        profiler: &CampaignObjectProfiler,
        exact_leaf: bool,
        ram_root: bool,
        verify_ram: bool,
        boundary: &mut dyn FnMut() -> Result<(), crucible_cas::ram::RamStoreError>,
    ) -> Result<
        (
            crucible_cas::content_store::ObjectProfile,
            BTreeSet<ContentId>,
        ),
        CampaignRepositoryError,
    > {
        boundary().map_err(CampaignRepositoryError::Ram)?;
        let authenticated = self.blobs.read(id, None)?;
        authenticated.copy_to(&mut io::sink())?;
        boundary().map_err(CampaignRepositoryError::Ram)?;
        let source = self.blobs.read(id, None)?;
        let profile = if exact_leaf {
            profile_authenticated_exact_leaf(id, &source)?
        } else {
            profiler.derive_profile(id, &source)?
        };
        if ram_root {
            self.authenticate_ram_root(id, verify_ram, boundary)?;
        }
        let children = if exact_leaf || ram_root || is_archive_opaque_leaf(id.kind()) {
            BTreeSet::new()
        } else {
            let bytes = self.blobs.read(id, None)?.read_all(MAX_ENVELOPE_BYTES)?;
            if is_campaign_record_kind(id.kind()) {
                let envelope = if id.kind() == ObjectKind::MerkleNode {
                    ObjectEnvelope::from_canonical_bytes_for_owner(&bytes)?
                } else {
                    ObjectEnvelope::from_canonical_bytes(&bytes)?
                };
                if envelope.content_id() != id {
                    return Err(integrity("campaign-archive-object-envelope-id-mismatch"));
                }
                envelope
                    .children()
                    .iter()
                    .map(crate::ChildReference::id)
                    .collect()
            } else {
                let envelope = ContentEnvelope::from_canonical_bytes(&bytes)
                    .map_err(CampaignCodecError::from)?;
                if envelope.content_id(id.kind()) != id {
                    return Err(integrity("campaign-archive-generic-envelope-id-mismatch"));
                }
                envelope
                    .children()
                    .iter()
                    .map(crate::ChildReference::id)
                    .collect()
            }
        };
        boundary().map_err(CampaignRepositoryError::Ram)?;
        Ok((profile, children))
    }

    fn validate_archive_policy(
        &self,
        manifest: &CampaignArchiveManifest,
        selected: &[ArchiveObjectEntry],
        omitted: &[ArchiveObjectEntry],
        selected_children: &BTreeMap<ContentId, BTreeSet<ContentId>>,
    ) -> Result<(), CampaignRepositoryError> {
        let selected_ids = selected
            .iter()
            .map(|entry| entry.id())
            .collect::<BTreeSet<_>>();
        let source = self.read_snapshot(manifest.source_snapshot().content_id())?;
        if !selected_ids.contains(&manifest.source_snapshot().content_id()) {
            return Err(integrity(
                "campaign-archive-source-snapshot-is-not-selected",
            ));
        }

        let finding_reachable = if manifest.policy() == CampaignArchivePolicy::Debug {
            direct_reachable(selected_children, source.snapshot.roots().findings)
        } else {
            BTreeSet::new()
        };
        for entry in selected {
            if !archive_entry_selected(manifest.policy(), *entry, &finding_reachable) {
                return Err(integrity(
                    "campaign-archive-policy-selected-object-mismatch",
                ));
            }
        }
        for entry in omitted {
            if archive_entry_selected(manifest.policy(), *entry, &finding_reachable) {
                return Err(integrity("campaign-archive-policy-omitted-object-mismatch"));
            }
        }
        if matches!(
            manifest.policy(),
            CampaignArchivePolicy::Executable | CampaignArchivePolicy::Mirror
        ) {
            let mut expected = BTreeSet::new();
            self.visit_pin_retention_roots_at(manifest.source_snapshot(), &mut |pin| {
                if pin.retention() == crate::PinRetention::Exact {
                    expected.insert((pin.request().change.configuration(), pin.fact()));
                }
            })?;
            let actual = manifest
                .checkpoint_selections()
                .iter()
                .map(|selection| (selection.configuration(), selection.pin_fact()))
                .collect::<BTreeSet<_>>();
            if actual.len() != manifest.checkpoint_selections().len() || actual != expected {
                return Err(integrity(
                    "campaign-archive-exact-checkpoint-selection-mismatch",
                ));
            }
        }
        Ok(())
    }
}

fn archive_entry_selected(
    policy: CampaignArchivePolicy,
    entry: ArchiveObjectEntry,
    finding_reachable: &BTreeSet<ContentId>,
) -> bool {
    archive_policy_selects(
        policy,
        entry.id(),
        entry.retention_role(),
        finding_reachable,
    )
}

fn direct_reachable(
    children: &BTreeMap<ContentId, BTreeSet<ContentId>>,
    root: ContentId,
) -> BTreeSet<ContentId> {
    let mut pending = vec![root];
    let mut visited = BTreeSet::new();
    while let Some(id) = pending.pop() {
        if !visited.insert(id) {
            continue;
        }
        if let Some(next) = children.get(&id) {
            pending.extend(next.iter().copied());
        }
    }
    visited
}

const fn is_archive_opaque_leaf(kind: ObjectKind) -> bool {
    matches!(
        kind,
        ObjectKind::RamExtent
            | ObjectKind::DiskExtent
            | ObjectKind::DeviceState
            | ObjectKind::Trace
    )
}
