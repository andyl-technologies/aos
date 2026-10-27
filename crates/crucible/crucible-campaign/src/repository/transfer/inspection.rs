//! Streamed authentication of one archive manifest and its direct inventory.
//!
//! Inspection replays the manifest's canonical inventory pages several times
//! instead of holding an inventory, a declared set, or a child graph:
//!
//! 1. one merged pass over both inventories rejects overlap, measures them,
//!    and builds the aggregate reports;
//! 2. one pass per inventory recomputes its manifest digest;
//! 3. every selected object is authenticated to EOF and profiled, in step with
//!    the spilled source closure for executable archives, while its child
//!    identities are spilled;
//! 4. a merged pass proves every spilled child declared;
//! 5. omitted objects are profiled where present;
//! 6. one pass per inventory checks the archive policy, using a spilled
//!    reachable set for the Debug policy.

use super::inventory::{
    ClosureCursor, EdgeSpill, IdMembership, IdSpill, InventoryCursor, MergedInventory,
    digest_inventory, reachable_from,
};
use super::*;
use crate::CampaignArchiveReport;
use crate::archive::InventoryLength;

/// Measurements and reports from the first merged inventory pass.
#[derive(Default)]
struct InventoryShape {
    selected: InventoryLength,
    omitted: InventoryLength,
    selected_report: CampaignArchiveReport,
    omitted_report: CampaignArchiveReport,
    source_selected: bool,
}

/// Spills produced while authenticating the selected inventory.
struct SelectedLinks {
    children: SpillFile,
    /// Selected parent-to-child edges, kept only for the Debug policy.
    edges: Option<SpillFile>,
}

impl CampaignRepository {
    /// Authenticates one archive manifest, every inventory page, and every selected object.
    ///
    /// Selected objects are authenticated independently to EOF and compared
    /// with their profiler-derived records. Their ordinary child edges are not
    /// traversed across the declared archive boundary. Inventory pages are
    /// replayed from the store one at a time, and every archive-sized set the
    /// checks need is external-sorted in the repository's scratch storage.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignRepositoryError`] for missing or corrupt metadata,
    /// inconsistent page order/digests, a missing, corrupt, or misprofiled
    /// selected object, a policy or closure mismatch, or a scratch failure.
    pub fn inspect_campaign_archive(
        &self,
        id: CampaignArchiveManifestId,
    ) -> Result<CampaignArchiveInspection, CampaignRepositoryError> {
        let envelope =
            self.require_record_kind(id.content_id(), CampaignRecordKind::ArchiveManifest)?;
        let manifest = CampaignArchiveManifest::from_canonical_bytes(envelope.body())?;
        if manifest.id()? != id {
            return Err(integrity("campaign-archive-manifest-envelope-shape"));
        }
        let storage = self.spill_storage()?;

        let shape = self.measure_archive_inventory(&manifest)?;
        self.verify_archive_digests(&manifest, &shape)?;

        let executable = matches!(
            manifest.policy(),
            CampaignArchivePolicy::Executable | CampaignArchivePolicy::Mirror
        );
        if executable && manifest.omitted_count() != 0 {
            return Err(integrity(
                "campaign-archive-executable-closure-is-incomplete",
            ));
        }
        let closure = if executable {
            Some(self.spill_archive_closure(&storage, &manifest)?)
        } else {
            None
        };
        let links = self.authenticate_selected_inventory(&manifest, closure.as_ref(), &storage)?;
        drop(closure);

        self.verify_declared_children(&manifest, &links.children)?;
        let omitted_inventory_verified = self.authenticate_omitted_inventory(&manifest)?;
        self.validate_archive_policy(&manifest, &shape, links.edges.as_ref(), &storage)?;
        Ok(CampaignArchiveInspection::new(
            id,
            manifest,
            shape.selected_report,
            shape.omitted_report,
            omitted_inventory_verified,
        ))
    }

    fn merged_store_inventory<'r, 'p>(
        &'r self,
        manifest: &'p CampaignArchiveManifest,
    ) -> Result<MergedInventory<'r, 'p>, CampaignRepositoryError> {
        MergedInventory::new(
            InventoryCursor::store(
                self,
                manifest.selected_pages(),
                ArchiveInventoryDisposition::Selected,
            ),
            InventoryCursor::store(
                self,
                manifest.omitted_pages(),
                ArchiveInventoryDisposition::Omitted,
            ),
        )
    }

    /// Pass 1: rejects overlap and measures both inventories against the manifest.
    fn measure_archive_inventory(
        &self,
        manifest: &CampaignArchiveManifest,
    ) -> Result<InventoryShape, CampaignRepositoryError> {
        let source = manifest.source_snapshot().content_id();
        let mut shape = InventoryShape::default();
        let mut source_declared = false;
        let mut declared = self.merged_store_inventory(manifest)?;
        while let Some((disposition, entry)) = declared.next()? {
            let (length, report) = match disposition {
                ArchiveInventoryDisposition::Selected => {
                    (&mut shape.selected, &mut shape.selected_report)
                }
                ArchiveInventoryDisposition::Omitted => {
                    (&mut shape.omitted, &mut shape.omitted_report)
                }
            };
            length.add(entry)?;
            report.add(entry)?;
            if entry.id() == source {
                source_declared = true;
                shape.source_selected = disposition == ArchiveInventoryDisposition::Selected;
            }
        }

        if shape.selected.entries() != manifest.selected_count()
            || shape.omitted.entries() != manifest.omitted_count()
        {
            return Err(integrity("campaign-archive-inventory-manifest-mismatch"));
        }
        if !source_declared {
            return Err(integrity("campaign-archive-source-snapshot-is-undeclared"));
        }
        Ok(shape)
    }

    /// Pass 2: recomputes both ordered-entry digests from the measured shape.
    fn verify_archive_digests(
        &self,
        manifest: &CampaignArchiveManifest,
        shape: &InventoryShape,
    ) -> Result<(), CampaignRepositoryError> {
        for (pages, disposition, length, expected) in [
            (
                manifest.selected_pages(),
                ArchiveInventoryDisposition::Selected,
                shape.selected,
                manifest.selected_digest(),
            ),
            (
                manifest.omitted_pages(),
                ArchiveInventoryDisposition::Omitted,
                shape.omitted,
                manifest.omitted_digest(),
            ),
        ] {
            let mut cursor = InventoryCursor::store(self, pages, disposition);
            if digest_inventory(&mut cursor, length)?.digest != expected {
                return Err(integrity("campaign-archive-inventory-manifest-mismatch"));
            }
        }
        Ok(())
    }

    /// Pass 3: authenticates and profiles every selected object and spills its children.
    ///
    /// For an executable archive the selected inventory must equal the source
    /// closure exactly; both streams ascend, so equality is checked in step.
    fn authenticate_selected_inventory(
        &self,
        manifest: &CampaignArchiveManifest,
        closure: Option<&SpillFile>,
        storage: &SpillStorage,
    ) -> Result<SelectedLinks, CampaignRepositoryError> {
        let profiler = CampaignObjectProfiler;
        let mut closure = closure.map(ClosureCursor::open).transpose()?;
        let mut children = IdSpill::new(storage, "archive-children");
        let mut edges =
            (manifest.policy() == CampaignArchivePolicy::Debug).then(|| EdgeSpill::new(storage));
        let mut selected = InventoryCursor::store(
            self,
            manifest.selected_pages(),
            ArchiveInventoryDisposition::Selected,
        );
        while let Some(entry) = selected.next_entry()? {
            let exact_leaf = match closure.as_mut() {
                Some(closure) => match closure.next()? {
                    Some((id, exact_leaf)) if id == entry.id() => exact_leaf,
                    _ => {
                        return Err(integrity(
                            "campaign-archive-executable-closure-is-incomplete",
                        ));
                    }
                },
                None => false,
            };
            let (profile, links) =
                self.authenticate_archive_object(entry.id(), &profiler, exact_leaf)?;
            if !entry.matches_profile(profile) {
                return Err(integrity(
                    "campaign-archive-selected-object-profile-mismatch",
                ));
            }
            if closure.is_some() && links.record_kind.is_some_and(is_archive_metadata) {
                return Err(nested_archive_metadata());
            }
            for child in links.children {
                children.push(child)?;
                if let Some(edges) = edges.as_mut() {
                    edges.push(entry.id(), child)?;
                }
            }
        }
        if let Some(closure) = closure.as_mut()
            && closure.next()?.is_some()
        {
            return Err(integrity(
                "campaign-archive-executable-closure-is-incomplete",
            ));
        }
        Ok(SelectedLinks {
            children: children.finish()?,
            edges: edges.map(EdgeSpill::finish).transpose()?,
        })
    }

    /// Pass 4: proves every selected object's child is declared by the archive.
    fn verify_declared_children(
        &self,
        manifest: &CampaignArchiveManifest,
        children: &SpillFile,
    ) -> Result<(), CampaignRepositoryError> {
        let mut children = IdMembership::open(children)?;
        let mut declared = self.merged_store_inventory(manifest)?;
        let mut current = declared.next()?;
        while let Some(child) = children.next()? {
            while current.is_some_and(|(_, entry)| entry.id() < child) {
                current = declared.next()?;
            }
            if !current.is_some_and(|(_, entry)| entry.id() == child) {
                return Err(integrity("campaign-archive-selected-child-is-undeclared"));
            }
        }
        Ok(())
    }

    /// Pass 5: profiles every omitted object that this store still holds.
    ///
    /// Returns whether every omitted object was present.
    fn authenticate_omitted_inventory(
        &self,
        manifest: &CampaignArchiveManifest,
    ) -> Result<bool, CampaignRepositoryError> {
        let profiler = CampaignObjectProfiler;
        let mut verified = true;
        let mut omitted = InventoryCursor::store(
            self,
            manifest.omitted_pages(),
            ArchiveInventoryDisposition::Omitted,
        );
        while let Some(entry) = omitted.next_entry()? {
            match self.authenticate_archive_object(entry.id(), &profiler, false) {
                Ok((profile, _)) if entry.matches_profile(profile) => {}
                Ok(_) => {
                    return Err(integrity(
                        "campaign-archive-omitted-object-profile-mismatch",
                    ));
                }
                Err(CampaignRepositoryError::Store(StoreError::NotFound { .. })) => {
                    verified = false;
                }
                Err(source) => return Err(source),
            }
        }
        Ok(verified)
    }

    /// Pass 6: checks the policy partition and executable checkpoint selections.
    ///
    /// For the Debug policy, exact state is selected exactly when it is
    /// reachable from the source findings root through selected objects.
    fn validate_archive_policy(
        &self,
        manifest: &CampaignArchiveManifest,
        shape: &InventoryShape,
        selected_edges: Option<&SpillFile>,
        storage: &SpillStorage,
    ) -> Result<(), CampaignRepositoryError> {
        let source = self.read_snapshot(manifest.source_snapshot().content_id())?;
        if !shape.source_selected {
            return Err(integrity(
                "campaign-archive-source-snapshot-is-not-selected",
            ));
        }

        let policy = manifest.policy();
        let finding_reachable = match selected_edges {
            Some(edges) if policy == CampaignArchivePolicy::Debug => Some(reachable_from(
                storage,
                source.snapshot.roots().findings,
                edges,
            )?),
            _ => None,
        };
        for (pages, disposition) in [
            (
                manifest.selected_pages(),
                ArchiveInventoryDisposition::Selected,
            ),
            (
                manifest.omitted_pages(),
                ArchiveInventoryDisposition::Omitted,
            ),
        ] {
            let mut reachable = finding_reachable
                .as_ref()
                .map(IdMembership::open)
                .transpose()?;
            let mut cursor = InventoryCursor::store(self, pages, disposition);
            while let Some(entry) = cursor.next_entry()? {
                let in_finding_closure = match reachable.as_mut() {
                    Some(reachable) => reachable.contains(entry.id())?,
                    None => false,
                };
                let selects = archive_policy_selects(
                    policy,
                    entry.id(),
                    entry.retention_role(),
                    in_finding_closure,
                );
                match (disposition, selects) {
                    (ArchiveInventoryDisposition::Selected, false) => {
                        return Err(integrity(
                            "campaign-archive-policy-selected-object-mismatch",
                        ));
                    }
                    (ArchiveInventoryDisposition::Omitted, true) => {
                        return Err(integrity("campaign-archive-policy-omitted-object-mismatch"));
                    }
                    _ => {}
                }
            }
        }

        if matches!(
            policy,
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
