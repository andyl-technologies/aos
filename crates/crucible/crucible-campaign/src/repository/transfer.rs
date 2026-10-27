//! Authenticated archive selection, inspection, publication, and object transfer.
//!
//! Planning streams the source closure through the repository's private
//! scratch storage: identities are external-sorted, each object is profiled as
//! the sorted stream passes, and finished inventory pages are spooled rather
//! than retained. Inspection replays canonical pages from the store. Neither
//! holds an archive-sized set in memory; see the `inventory` module for the
//! scratch records and the `inspection` module for the inspection passes.

use std::collections::BTreeSet;
use std::io;

use crucible_store::content_envelope::ContentEnvelope;
use crucible_store::content_store::{
    ContentId, DurabilityRequirement, ObjectKind, ObjectProfile, RefCasOutcome, RefName,
    RetentionRole, StoreError, StoreObjectProfiler,
};

use super::*;
use crate::archive::CampaignArchiveManifestBasis;
use crate::object_profile::profile_authenticated_exact_leaf;
use crate::spill::{SpillFile, SpillStorage};
use crate::{
    ArchiveInventoryDisposition, ArchiveObjectEntry, CampaignArchiveCheckpointResolver,
    CampaignArchiveCheckpointSelection, CampaignArchiveInspection, CampaignArchiveInventoryPage,
    CampaignArchiveInventoryPageId, CampaignArchiveManifest, CampaignArchiveManifestId,
    CampaignArchivePlan, CampaignArchivePolicy, CampaignArchiveTransferReport,
    CampaignObjectProfiler, CampaignRecordKind, MAX_ARCHIVE_INVENTORY_ENTRIES,
    MAX_ARCHIVE_INVENTORY_PAGE_ENTRIES,
};
use inventory::{
    ClosureCursor, ClosureSpill, EdgeSpill, IdMembership, InventoryCursor, PageSpooler,
    reachable_from,
};

mod inspection;
mod inventory;
mod plan;

impl CampaignRepository {
    /// Validates archive and optional ordinary-head publication intent without mutation.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignRepositoryError`] when either ref spelling is invalid
    /// or a partial archive is asked to advance an ordinary campaign head.
    pub fn validate_campaign_archive_publication_intent(
        &self,
        archive_name: &str,
        campaign_name: Option<&str>,
        policy: CampaignArchivePolicy,
    ) -> Result<(), CampaignRepositoryError> {
        archive_ref(archive_name)?;
        if let Some(campaign_name) = campaign_name {
            if !matches!(
                policy,
                CampaignArchivePolicy::Executable | CampaignArchivePolicy::Mirror
            ) {
                return Err(CampaignRepositoryError::InvalidRequest {
                    reason: "partial campaign archive cannot publish a campaign head",
                });
            }
            campaign_ref(campaign_name)?;
        }
        Ok(())
    }

    /// Builds an archive plan from one fully authenticated source snapshot.
    ///
    /// Partial policies record a complete selected/omitted partition without
    /// turning selected objects into transitive child roots. Executable archives
    /// retain the complete source snapshot closure. Mirror archives additionally
    /// retain the complete closures of every caller-supplied root. Archive
    /// manifests and inventory pages are rejected as retained roots because
    /// their selected inventories are direct GC roots rather than ordinary
    /// Merkle children. This API accepts ordinary complete-closure roots; an
    /// existing partial archive must be transferred through its own archive
    /// plan and boundary.
    ///
    /// The closure is external-sorted and the inventory pages are spooled in
    /// the repository's scratch storage (see
    /// [`Self::with_scratch_directory`]), so memory does not grow with the
    /// archive. Planning writes nothing to the content store.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignRepositoryError`] when the source closure or a retained
    /// root is unavailable or invalid, a profile cannot be derived from complete
    /// authenticated bytes, scratch storage fails, or the canonical manifest
    /// cannot be built within its format limit.
    pub fn plan_campaign_archive(
        &self,
        snapshot: CampaignSnapshotId,
        policy: CampaignArchivePolicy,
        retained_roots: impl IntoIterator<Item = ContentId>,
        checkpoint_resolver: Option<&mut dyn CampaignArchiveCheckpointResolver>,
    ) -> Result<CampaignArchivePlan, CampaignRepositoryError> {
        let retained_roots = retained_roots
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if policy != CampaignArchivePolicy::Mirror && !retained_roots.is_empty() {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "only mirror archives accept additional retained roots",
            });
        }
        let storage = self.spill_storage()?;

        // Streaming the head closure runs complete inductive history
        // validation, so the snapshot is authenticated before its pin index
        // is trusted below.
        let mut closure = ClosureSpill::new(&storage);
        self.spill_head_closure(&mut closure, snapshot)?;
        let checkpoint_selections =
            self.resolve_checkpoint_selections(snapshot, policy, checkpoint_resolver)?;
        let checkpoints = checkpoint_roots(&checkpoint_selections);
        self.spill_retained_closure(&mut closure, &retained_roots)?;
        self.spill_checkpoint_closure(&mut closure, &checkpoints)?;
        let closure = closure.finish()?;

        let finding_closure = if policy == CampaignArchivePolicy::Debug {
            let findings = self
                .read_snapshot(snapshot.content_id())?
                .snapshot
                .roots()
                .findings;
            Some(self.spill_finding_closure(&storage, &closure, findings)?)
        } else {
            None
        };
        let (selected, omitted) =
            self.partition_archive_closure(&storage, policy, &closure, finding_closure.as_ref())?;
        drop(finding_closure);
        drop(closure);

        let selected_summary = selected.summary()?;
        let omitted_summary = omitted.summary()?;
        let manifest = CampaignArchiveManifest::new(CampaignArchiveManifestBasis {
            source_snapshot: snapshot,
            policy,
            checkpoint_selections,
            retained_roots,
            selected_pages: selected.pages,
            omitted_pages: omitted.pages,
            selected: selected_summary,
            omitted: omitted_summary,
        })?;
        let manifest_envelope = ObjectEnvelope::for_archive_manifest(&manifest)?;
        let manifest_id =
            CampaignArchiveManifestId::from_content_id(manifest_envelope.content_id())?;
        Ok(CampaignArchivePlan {
            manifest_id,
            manifest,
            manifest_envelope,
            selected_pages: selected.file,
            omitted_pages: omitted.file,
        })
    }

    /// Publishes canonical archive metadata and advances one archive-only ref.
    ///
    /// This method accepts every archive policy. It never advances a campaign
    /// ref, so a partial archive cannot be mistaken for an executable snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignRepositoryError`] when metadata placement fails, the
    /// plan cannot be inspected from this store, or the expected ref is stale.
    pub fn publish_campaign_archive(
        &self,
        name: &str,
        expected: Option<CampaignArchiveManifestId>,
        plan: &CampaignArchivePlan,
    ) -> Result<CampaignArchiveManifestId, CampaignRepositoryError> {
        let _mutation = self.lock_mutation()?;
        self.put_plan_metadata(plan, "campaign-archive-manifest-publication-mismatch")?;
        self.inspect_campaign_archive(plan.manifest_id)?;
        let archive_ref = archive_ref(name)?;
        let id = plan.manifest_id.content_id();
        let expected = expected.map(CampaignArchiveManifestId::content_id);
        match self.refs.compare_exchange(&archive_ref, expected, id)? {
            RefCasOutcome::Advanced { next } if next == id => Ok(plan.manifest_id),
            RefCasOutcome::Advanced { .. } => {
                Err(integrity("campaign-archive-ref-receipt-mismatch"))
            }
            RefCasOutcome::Conflict {
                current: Some(current),
                ..
            } if current == id => Ok(plan.manifest_id),
            RefCasOutcome::Conflict { current, .. } => {
                Err(CampaignRepositoryError::RefConflict { current })
            }
        }
    }

    /// Durably stages canonical archive metadata in the source repository.
    ///
    /// This method does not publish a ref. A restart-safe transfer owner calls
    /// it after durably recording every selected and metadata object ID in its
    /// source journal and while holding the repository GC exclusion guard.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignRepositoryError`] when the plan no longer matches the
    /// authenticated source closure or an immutable metadata put fails.
    pub fn stage_campaign_archive_metadata(
        &self,
        plan: &CampaignArchivePlan,
    ) -> Result<CampaignArchiveManifestId, CampaignRepositoryError> {
        self.verify_plan_against_source(plan)?;
        self.put_plan_metadata(plan, "campaign-archive-manifest-staging-mismatch")?;
        self.inspect_campaign_archive(plan.manifest_id)?;
        Ok(plan.manifest_id)
    }

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
        let target = self
            .refs
            .read_ref(&archive_ref(name)?)?
            .ok_or(CampaignRepositoryError::NotFound)?;
        let id = CampaignArchiveManifestId::from_content_id(target)?;
        self.inspect_campaign_archive(id)
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
        let inspection = self.inspect_campaign_archive(archive)?;
        if !matches!(
            inspection.manifest().policy(),
            CampaignArchivePolicy::Executable | CampaignArchivePolicy::Mirror
        ) {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "finding handoff requires an executable archive",
            });
        }

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
        let finding = self.inspect_archived_finding(archive, finding)?;
        if finding.exact_pins().is_empty() {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "archived finding has no retained exact checkpoint",
            });
        }
        Ok(finding)
    }

    /// Replays one inspected archive inventory in ascending identity order.
    ///
    /// Each page is read from this repository and checked against the
    /// inspected manifest again, so the replay yields exactly the entries the
    /// manifest digests describe. Memory is bounded by one page.
    ///
    /// # Errors
    ///
    /// Returns the first error from `visit`, or a [`CampaignRepositoryError`]
    /// when a page is missing, corrupt, or inconsistent with the manifest.
    pub fn visit_campaign_archive_entries<E>(
        &self,
        inspection: &CampaignArchiveInspection,
        disposition: ArchiveInventoryDisposition,
        mut visit: impl FnMut(ArchiveObjectEntry) -> Result<(), E>,
    ) -> Result<(), E>
    where
        E: From<CampaignRepositoryError>,
    {
        let manifest = inspection.manifest();
        let pages = match disposition {
            ArchiveInventoryDisposition::Selected => manifest.selected_pages(),
            ArchiveInventoryDisposition::Omitted => manifest.omitted_pages(),
        };
        let mut cursor = InventoryCursor::store(self, pages, disposition);
        while let Some(entry) = cursor.next_entry()? {
            visit(entry)?;
        }
        Ok(())
    }

    /// Visits the manifest, page, and selected-object IDs that archive GC retains.
    ///
    /// The manifest comes first, then every page in manifest order, then the
    /// selected objects in ascending order. Selected entries are replayed as
    /// [`Self::visit_campaign_archive_entries`] does.
    ///
    /// # Errors
    ///
    /// Returns the first error from `visit`, or a [`CampaignRepositoryError`]
    /// when a page is missing, corrupt, or inconsistent with the manifest.
    pub fn visit_campaign_archive_retained_objects<E>(
        &self,
        inspection: &CampaignArchiveInspection,
        mut visit: impl FnMut(ContentId) -> Result<(), E>,
    ) -> Result<(), E>
    where
        E: From<CampaignRepositoryError>,
    {
        let manifest = inspection.manifest();
        visit(inspection.manifest_id().content_id())?;
        for page in manifest
            .selected_pages()
            .iter()
            .chain(manifest.omitted_pages())
        {
            visit(page.content_id())?;
        }
        self.visit_campaign_archive_entries(
            inspection,
            ArchiveInventoryDisposition::Selected,
            |entry| visit(entry.id()),
        )
    }

    /// Copies every missing selected object and canonical archive metadata.
    ///
    /// Destination presence is never trusted. An existing object is read to
    /// authenticated EOF. A copied object is accepted only after a durable,
    /// length-matching receipt and a second authenticated destination read.
    /// This effectful primitive expects the caller to hold durable source and
    /// destination transfer-root journals for `plan`.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignRepositoryError`] for invalid source plan contents,
    /// destination corruption, unsatisfied durability, or copy failure.
    pub fn transfer_campaign_archive_objects(
        &self,
        destination: &CampaignRepository,
        plan: &CampaignArchivePlan,
        destination_durability: DurabilityRequirement,
    ) -> Result<CampaignArchiveTransferReport, CampaignRepositoryError> {
        self.verify_plan_against_source(plan)?;
        let capabilities = destination.blobs.capabilities();
        if !capabilities.durable
            || (capabilities.deferred_write && !destination_durability.allows_deferred_write())
        {
            return Err(StoreError::DurabilityUnsatisfied {
                id: plan.manifest_id.content_id(),
                minimum_durable_placements: destination_durability.minimum_durable_placements(),
                observed_durable_placements: 0,
            }
            .into());
        }
        let mut report = CampaignArchiveTransferReport::new();
        plan.visit_transfer_objects(|id, logical_length| {
            transfer_one(
                self,
                destination,
                id,
                logical_length,
                destination_durability,
                &mut report,
            )
        })?;
        destination.inspect_campaign_archive(plan.manifest_id)?;
        Ok(report)
    }

    /// Advances an ordinary campaign ref for a complete executable or mirror archive.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignRepositoryError`] when the archive is partial, its
    /// direct inventory is invalid, the complete source snapshot closure is not
    /// executable at this destination, or the expected campaign ref is stale.
    pub fn publish_transferred_campaign(
        &self,
        name: &str,
        expected: Option<CampaignSnapshotId>,
        archive: CampaignArchiveManifestId,
    ) -> Result<CampaignSnapshotId, CampaignRepositoryError> {
        let inspection = self.inspect_campaign_archive(archive)?;
        if !matches!(
            inspection.manifest().policy(),
            CampaignArchivePolicy::Executable | CampaignArchivePolicy::Mirror
        ) {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "partial campaign archive cannot publish a campaign head",
            });
        }
        let snapshot = inspection.manifest().source_snapshot();
        self.validate_complete_head(snapshot.content_id())?;

        let _mutation = self.lock_mutation()?;
        let campaign_ref = campaign_ref(name)?;
        match self.refs.compare_exchange(
            &campaign_ref,
            expected.map(CampaignSnapshotId::content_id),
            snapshot.content_id(),
        )? {
            RefCasOutcome::Advanced { next } if next == snapshot.content_id() => Ok(snapshot),
            RefCasOutcome::Advanced { .. } => Err(integrity("campaign-ref-receipt-mismatch")),
            RefCasOutcome::Conflict {
                current: Some(current),
                ..
            } if current == snapshot.content_id() => Ok(snapshot),
            RefCasOutcome::Conflict { current, .. } => {
                Err(CampaignRepositoryError::RefConflict { current })
            }
        }
    }

    /// Resolves the checkpoint selected for every live exact pin of `snapshot`.
    fn resolve_checkpoint_selections(
        &self,
        snapshot: CampaignSnapshotId,
        policy: CampaignArchivePolicy,
        mut checkpoint_resolver: Option<&mut dyn CampaignArchiveCheckpointResolver>,
    ) -> Result<Vec<CampaignArchiveCheckpointSelection>, CampaignRepositoryError> {
        let mut expected_exact_pins = BTreeSet::new();
        self.visit_pin_retention_roots_at(snapshot, &mut |pin| {
            if pin.retention() == crate::PinRetention::Exact {
                expected_exact_pins.insert((pin.request().change.configuration(), pin.fact()));
            }
        })?;
        let mut checkpoint_selections = BTreeSet::new();
        if matches!(
            policy,
            CampaignArchivePolicy::Executable | CampaignArchivePolicy::Mirror
        ) {
            for (configuration, pin_fact) in expected_exact_pins {
                let resolver = checkpoint_resolver.as_deref_mut().ok_or_else(|| {
                    integrity("campaign-archive-exact-pin-materialization-missing")
                })?;
                let checkpoint = resolver.resolve_checkpoint(configuration, pin_fact)?;
                checkpoint_selections.insert(CampaignArchiveCheckpointSelection::new(
                    configuration,
                    pin_fact,
                    checkpoint,
                ));
            }
        }
        Ok(checkpoint_selections.into_iter().collect())
    }

    /// Profiles every closure object and spools it into the inventory its policy picks.
    fn partition_archive_closure(
        &self,
        storage: &SpillStorage,
        policy: CampaignArchivePolicy,
        closure: &SpillFile,
        finding_closure: Option<&SpillFile>,
    ) -> Result<(inventory::SpooledInventory, inventory::SpooledInventory), CampaignRepositoryError>
    {
        let profiler = CampaignObjectProfiler;
        let mut finding_membership = finding_closure.map(IdMembership::open).transpose()?;
        let mut selected = PageSpooler::new(storage, ArchiveInventoryDisposition::Selected)?;
        let mut omitted = PageSpooler::new(storage, ArchiveInventoryDisposition::Omitted)?;
        let mut represented = 0_usize;
        let mut cursor = ClosureCursor::open(closure)?;
        while let Some((id, exact_leaf)) = cursor.next()? {
            represented += 1;
            if represented > MAX_ARCHIVE_INVENTORY_ENTRIES {
                return Err(integrity("campaign-archive-inventory-limit"));
            }
            let source = self.blobs.read(id, None)?;
            let profile = if exact_leaf {
                profile_authenticated_exact_leaf(id, &source)?
            } else {
                profiler.derive_profile(id, &source)?
            };
            // The closure stream ascends, so membership is a forward merge.
            let in_finding_closure = match finding_membership.as_mut() {
                Some(membership) => membership.contains(id)?,
                None => false,
            };
            let entry = ArchiveObjectEntry::from_profile(id, profile);
            if archive_policy_selects(policy, id, profile.retention_role(), in_finding_closure) {
                selected.push(entry)?;
            } else {
                omitted.push(entry)?;
            }
        }
        Ok((selected.finish()?, omitted.finish()?))
    }

    /// Computes the closure of the findings root within an already spilled closure.
    ///
    /// The closure's child edges are spilled once and joined round by round
    /// from the findings root.
    fn spill_finding_closure(
        &self,
        storage: &SpillStorage,
        closure: &SpillFile,
        findings: ContentId,
    ) -> Result<SpillFile, CampaignRepositoryError> {
        let mut edges = EdgeSpill::new(storage);
        let mut cursor = ClosureCursor::open(closure)?;
        while let Some((id, exact_leaf)) = cursor.next()? {
            for child in self.archive_object_links(id, exact_leaf)?.children {
                edges.push(id, child)?;
            }
        }
        reachable_from(storage, findings, &edges.finish()?)
    }

    /// Streams the complete closure of the source head into `closure`.
    fn spill_head_closure(
        &self,
        closure: &mut ClosureSpill,
        snapshot: CampaignSnapshotId,
    ) -> Result<(), CampaignRepositoryError> {
        // Only checkpoint selections opt into raw production leaves; the
        // snapshot's own closure is profiled as ordinary campaign objects.
        self.visit_validated_head_closure(snapshot.content_id(), &mut |id, _exact_leaf| {
            closure.push(id, false)
        })?;
        Ok(())
    }

    /// Streams the closures of mirror retained roots, rejecting archive metadata.
    fn spill_retained_closure(
        &self,
        closure: &mut ClosureSpill,
        roots: &[ContentId],
    ) -> Result<(), CampaignRepositoryError> {
        if roots.is_empty() {
            return Ok(());
        }
        self.walk_campaign_closures(
            roots.iter().copied(),
            &BTreeSet::new(),
            false,
            &mut ChoiceValidationCache::default(),
            Some(&mut |id, _exact_leaf| {
                self.reject_archive_metadata(id)?;
                closure.push(id, false)
            }),
        )?;
        Ok(())
    }

    /// Streams selected exact-checkpoint closures with their raw-leaf flags.
    fn spill_checkpoint_closure(
        &self,
        closure: &mut ClosureSpill,
        roots: &[ContentId],
    ) -> Result<(), CampaignRepositoryError> {
        if roots.is_empty() {
            return Ok(());
        }
        // Only archive checkpoint selections may opt into raw production
        // leaves. The source resolver and destination exact store
        // authenticate their semantics.
        self.walk_campaign_closures(
            roots.iter().copied(),
            &BTreeSet::new(),
            true,
            &mut ChoiceValidationCache::default(),
            Some(&mut |id, exact_leaf| closure.push(id, exact_leaf)),
        )?;
        Ok(())
    }

    /// Spills the complete represented closure that a manifest declares.
    fn spill_archive_closure(
        &self,
        storage: &SpillStorage,
        manifest: &CampaignArchiveManifest,
    ) -> Result<SpillFile, CampaignRepositoryError> {
        let mut closure = ClosureSpill::new(storage);
        self.spill_head_closure(&mut closure, manifest.source_snapshot())?;
        self.spill_retained_closure(&mut closure, manifest.retained_roots())?;
        self.spill_checkpoint_closure(
            &mut closure,
            &checkpoint_roots(manifest.checkpoint_selections()),
        )?;
        closure.finish()
    }

    /// Proves that a plan's declared partition still equals the source closure.
    ///
    /// The source closure is spilled again and merge-compared with the union
    /// of the plan's spooled inventories, whose pages are bound to the
    /// manifest's page IDs and therefore to its digests.
    fn verify_plan_against_source(
        &self,
        plan: &CampaignArchivePlan,
    ) -> Result<(), CampaignRepositoryError> {
        let storage = self.spill_storage()?;
        let closure = self.spill_archive_closure(&storage, &plan.manifest)?;
        let mut closure = ClosureCursor::open(&closure)?;
        let mut declared = inventory::MergedInventory::new(
            InventoryCursor::spool(
                &plan.selected_pages,
                plan.manifest.selected_pages(),
                ArchiveInventoryDisposition::Selected,
            )?,
            InventoryCursor::spool(
                &plan.omitted_pages,
                plan.manifest.omitted_pages(),
                ArchiveInventoryDisposition::Omitted,
            )?,
        )?;
        loop {
            match (closure.next()?, declared.next()?) {
                (None, None) => return Ok(()),
                (Some((id, _)), Some((_, entry))) if id == entry.id() => {}
                _ => return Err(integrity("campaign-archive-plan-no-longer-matches-source")),
            }
        }
    }

    /// Places a plan's spooled pages and its manifest in this store.
    fn put_plan_metadata(
        &self,
        plan: &CampaignArchivePlan,
        mismatch: &'static str,
    ) -> Result<(), CampaignRepositoryError> {
        plan.visit_page_envelopes(|envelope| {
            let expected = envelope.content_id();
            if self.put_envelope(envelope)? != expected {
                return Err(integrity(mismatch));
            }
            Ok(())
        })?;
        if self.put_envelope(plan.manifest_envelope.clone())? != plan.manifest_id.content_id() {
            return Err(integrity(mismatch));
        }
        Ok(())
    }

    fn reject_archive_metadata(&self, id: ContentId) -> Result<(), CampaignRepositoryError> {
        if !is_campaign_record_kind(id.kind()) || id.kind() == ObjectKind::MerkleNode {
            return Ok(());
        }
        if is_archive_metadata(self.read_envelope(id)?.record_kind()) {
            return Err(nested_archive_metadata());
        }
        Ok(())
    }

    /// Authenticates one archive object to EOF and derives its profile and links.
    fn authenticate_archive_object(
        &self,
        id: ContentId,
        profiler: &CampaignObjectProfiler,
        exact_leaf: bool,
    ) -> Result<(ObjectProfile, ArchiveObjectLinks), CampaignRepositoryError> {
        let authenticated = self.blobs.read(id, None)?;
        authenticated.copy_to(&mut io::sink())?;
        let source = self.blobs.read(id, None)?;
        let profile = if exact_leaf {
            profile_authenticated_exact_leaf(id, &source)?
        } else {
            profiler.derive_profile(id, &source)?
        };
        Ok((profile, self.archive_object_links(id, exact_leaf)?))
    }

    /// Reads the child identities of one object without traversing them.
    fn archive_object_links(
        &self,
        id: ContentId,
        exact_leaf: bool,
    ) -> Result<ArchiveObjectLinks, CampaignRepositoryError> {
        if exact_leaf || is_archive_opaque_leaf(id.kind()) {
            return Ok(ArchiveObjectLinks {
                children: Vec::new(),
                record_kind: None,
            });
        }
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
            return Ok(ArchiveObjectLinks {
                children: envelope
                    .children()
                    .iter()
                    .map(crate::ChildReference::id)
                    .collect(),
                record_kind: Some(envelope.record_kind()),
            });
        }
        let envelope =
            ContentEnvelope::from_canonical_bytes(&bytes).map_err(CampaignCodecError::from)?;
        if envelope.content_id(id.kind()) != id {
            return Err(integrity("campaign-archive-generic-envelope-id-mismatch"));
        }
        Ok(ArchiveObjectLinks {
            children: envelope
                .children()
                .iter()
                .map(crate::ChildReference::id)
                .collect(),
            record_kind: None,
        })
    }
}

/// Child identities and campaign record kind of one archive object.
struct ArchiveObjectLinks {
    children: Vec<ContentId>,
    /// Record kind of a campaign envelope; `None` for generic envelopes and raw leaves.
    record_kind: Option<CampaignRecordKind>,
}

fn checkpoint_roots(selections: &[CampaignArchiveCheckpointSelection]) -> Vec<ContentId> {
    selections
        .iter()
        .map(|selection| selection.checkpoint().content_id())
        .collect()
}

fn archive_policy_selects(
    policy: CampaignArchivePolicy,
    id: ContentId,
    role: RetentionRole,
    in_finding_closure: bool,
) -> bool {
    match policy {
        CampaignArchivePolicy::Metadata => role == RetentionRole::CampaignMetadata,
        CampaignArchivePolicy::Findings => {
            matches!(
                role,
                RetentionRole::CampaignMetadata | RetentionRole::Evidence
            ) || id.kind() == ObjectKind::Configuration
        }
        CampaignArchivePolicy::Debug => {
            matches!(
                role,
                RetentionRole::CampaignMetadata | RetentionRole::Evidence
            ) || id.kind() == ObjectKind::Configuration
                || role == RetentionRole::ExactState && in_finding_closure
        }
        CampaignArchivePolicy::Executable | CampaignArchivePolicy::Mirror => true,
    }
}

const fn is_archive_metadata(kind: CampaignRecordKind) -> bool {
    matches!(
        kind,
        CampaignRecordKind::ArchiveManifest | CampaignRecordKind::ArchiveInventoryPage
    )
}

const fn nested_archive_metadata() -> CampaignRepositoryError {
    CampaignRepositoryError::InvalidRequest {
        reason: "mirror retained roots cannot contain archive metadata",
    }
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

fn transfer_one(
    source: &CampaignRepository,
    destination: &CampaignRepository,
    id: ContentId,
    logical_length: u64,
    durability: DurabilityRequirement,
    report: &mut CampaignArchiveTransferReport,
) -> Result<(), CampaignRepositoryError> {
    let existed = match destination.blobs.read(id, None) {
        Ok(existing) => {
            if existing.logical_length() != logical_length {
                return Err(StoreError::Corrupt { id }.into());
            }
            existing.copy_to(&mut io::sink())?;
            true
        }
        Err(StoreError::NotFound { .. }) => false,
        Err(source) => return Err(source.into()),
    };

    let source_handle = source.blobs.read(id, None)?;
    if source_handle.logical_length() != logical_length {
        return Err(StoreError::Corrupt { id }.into());
    }
    let receipt = destination.blobs.put_if_absent(id, &source_handle)?;
    let observed_durable_placements = receipt.durable_placements();
    if receipt.id != id
        || receipt
            .placements
            .iter()
            .any(|placement| placement.logical_length != logical_length)
    {
        return Err(StoreError::Corrupt { id }.into());
    }
    if observed_durable_placements < usize::from(durability.minimum_durable_placements()) {
        let observed_durable_placements = u16::try_from(observed_durable_placements)
            .map_err(|_| integrity("campaign-archive-durable-placement-count-overflow"))?;
        return Err(StoreError::DurabilityUnsatisfied {
            id,
            minimum_durable_placements: durability.minimum_durable_placements(),
            observed_durable_placements,
        }
        .into());
    }
    report.observe_durable_placements(observed_durable_placements)?;
    let persisted = destination.blobs.read(id, None)?;
    if persisted.logical_length() != logical_length {
        return Err(StoreError::Corrupt { id }.into());
    }
    persisted.copy_to(&mut io::sink())?;
    if existed {
        report.existing_objects = report
            .existing_objects
            .checked_add(1)
            .ok_or_else(|| integrity("campaign-archive-transfer-count-overflow"))?;
    } else {
        report.copied_objects = report
            .copied_objects
            .checked_add(1)
            .ok_or_else(|| integrity("campaign-archive-transfer-count-overflow"))?;
        report.copied_bytes = report
            .copied_bytes
            .checked_add(logical_length)
            .ok_or_else(|| integrity("campaign-archive-transfer-byte-overflow"))?;
    }
    Ok(())
}

fn archive_ref(name: &str) -> Result<RefName, CampaignRepositoryError> {
    RefName::new(format!("archives/{name}")).map_err(CampaignRepositoryError::from)
}
