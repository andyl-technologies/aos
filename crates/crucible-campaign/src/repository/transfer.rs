//! Authenticated archive selection, inspection, publication, and object transfer.

use std::collections::{BTreeMap, BTreeSet};
use std::io;

use crucible_cas::content_envelope::ContentEnvelope;
use crucible_cas::content_store::{
    ContentId, DurabilityRequirement, ObjectKind, RefCasOutcome, RefName, RetentionRole,
    StoreError, StoreObjectProfiler,
};

use super::*;
use crate::archive::{build_inspection, inventory_digest};
use crate::{
    ArchiveInventoryDisposition, ArchiveObjectEntry, CampaignArchiveCheckpointResolver,
    CampaignArchiveCheckpointSelection, CampaignArchiveInspection, CampaignArchiveInventoryPage,
    CampaignArchiveInventoryPageId, CampaignArchiveManifest, CampaignArchiveManifestId,
    CampaignArchivePlan, CampaignArchivePolicy, CampaignArchiveTransferReport,
    CampaignObjectProfiler, CampaignRecordKind, MAX_ARCHIVE_INVENTORY_ENTRIES,
    MAX_ARCHIVE_INVENTORY_PAGE_ENTRIES,
};

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

    /// Builds a bounded archive plan from one fully authenticated source snapshot.
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
    /// # Errors
    ///
    /// Returns [`CampaignRepositoryError`] when the source closure or a retained
    /// root is unavailable or invalid, a profile cannot be derived from complete
    /// authenticated bytes, or the bounded canonical manifest cannot be built.
    pub fn plan_campaign_archive(
        &self,
        snapshot: CampaignSnapshotId,
        policy: CampaignArchivePolicy,
        retained_roots: impl IntoIterator<Item = ContentId>,
        mut checkpoint_resolver: Option<&mut dyn CampaignArchiveCheckpointResolver>,
    ) -> Result<CampaignArchivePlan, CampaignRepositoryError> {
        self.validate_complete_head(snapshot.content_id())?;
        let snapshot_record = self.read_snapshot(snapshot.content_id())?;
        let snapshot_closure = self.authenticated_closure_ids([snapshot.content_id()])?;

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

        let retained_roots = retained_roots.into_iter().collect::<BTreeSet<_>>();
        if policy != CampaignArchivePolicy::Mirror && !retained_roots.is_empty() {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "only mirror archives accept additional retained roots",
            });
        }
        let retained_closure = if retained_roots.is_empty() {
            BTreeSet::new()
        } else {
            self.authenticated_closure_ids(retained_roots.iter().copied())?
        };
        self.reject_nested_archive_metadata(&retained_closure)?;
        let mut represented = snapshot_closure.clone();
        represented.extend(retained_closure);
        if !checkpoint_selections.is_empty() {
            represented.extend(
                self.authenticated_closure_ids(
                    checkpoint_selections
                        .iter()
                        .map(|selection| selection.checkpoint().content_id()),
                )?,
            );
        }
        if represented.len() > MAX_ARCHIVE_INVENTORY_ENTRIES {
            return Err(integrity("campaign-archive-inventory-limit"));
        }

        let finding_closure = if policy == CampaignArchivePolicy::Debug {
            self.authenticated_closure_ids([snapshot_record.snapshot.roots().findings])?
        } else {
            BTreeSet::new()
        };
        let profiler = CampaignObjectProfiler;
        let mut selected = Vec::new();
        let mut omitted = Vec::new();
        for id in represented {
            let profile = profiler.derive_profile(id, &self.blobs.read(id, None)?)?;
            let entry = ArchiveObjectEntry::from_profile(id, profile);
            if archive_policy_selects(policy, id, profile.retention_role(), &finding_closure) {
                selected.push(entry);
            } else {
                omitted.push(entry);
            }
        }

        let (selected_pages, mut page_envelopes) =
            archive_pages(ArchiveInventoryDisposition::Selected, &selected)?;
        let (omitted_pages, omitted_envelopes) =
            archive_pages(ArchiveInventoryDisposition::Omitted, &omitted)?;
        page_envelopes.extend(omitted_envelopes);
        let manifest = CampaignArchiveManifest::new(
            snapshot,
            policy,
            checkpoint_selections.into_iter().collect(),
            retained_roots.into_iter().collect(),
            selected_pages,
            omitted_pages,
            &selected,
            &omitted,
        )?;
        let manifest_envelope = ObjectEnvelope::for_archive_manifest(&manifest)?;
        let manifest_id =
            CampaignArchiveManifestId::from_content_id(manifest_envelope.content_id())?;
        Ok(CampaignArchivePlan {
            manifest_id,
            manifest,
            manifest_envelope,
            page_envelopes,
            selected,
            omitted,
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
        for envelope in &plan.page_envelopes {
            self.put_envelope(envelope.clone())?;
        }
        let id = self.put_envelope(plan.manifest_envelope.clone())?;
        if id != plan.manifest_id.content_id() {
            return Err(integrity("campaign-archive-manifest-publication-mismatch"));
        }
        self.inspect_campaign_archive(plan.manifest_id)?;
        let archive_ref = archive_ref(name)?;
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
        for envelope in &plan.page_envelopes {
            self.put_envelope(envelope.clone())?;
        }
        let id = self.put_envelope(plan.manifest_envelope.clone())?;
        if id != plan.manifest_id.content_id() {
            return Err(integrity("campaign-archive-manifest-staging-mismatch"));
        }
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
        let envelope =
            self.require_record_kind(id.content_id(), CampaignRecordKind::ArchiveManifest)?;
        let manifest = CampaignArchiveManifest::from_canonical_bytes(envelope.body())?;
        if manifest.id()? != id {
            return Err(integrity("campaign-archive-manifest-envelope-shape"));
        }

        let (selected, mut page_ids) = self.read_archive_pages(
            manifest.selected_pages(),
            ArchiveInventoryDisposition::Selected,
        )?;
        let (omitted, omitted_page_ids) = self.read_archive_pages(
            manifest.omitted_pages(),
            ArchiveInventoryDisposition::Omitted,
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

        let profiler = CampaignObjectProfiler;
        let mut selected_children = BTreeMap::new();
        for entry in &selected {
            let (profile, children) = self.authenticate_archive_object(entry.id(), &profiler)?;
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
            match self.authenticate_archive_object(entry.id(), &profiler) {
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
        if matches!(
            manifest.policy(),
            CampaignArchivePolicy::Executable | CampaignArchivePolicy::Mirror
        ) {
            let mut roots = vec![manifest.source_snapshot().content_id()];
            roots.extend(
                manifest
                    .checkpoint_selections()
                    .iter()
                    .map(|selection| selection.checkpoint().content_id()),
            );
            roots.extend(manifest.retained_roots().iter().copied());
            let complete = self.authenticated_closure_ids(roots)?;
            self.reject_nested_archive_metadata(&complete)?;
            if complete != selected.iter().map(|entry| entry.id()).collect() || !omitted.is_empty()
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
        let mut report = CampaignArchiveTransferReport::default();
        for entry in &plan.selected {
            transfer_one(
                self,
                destination,
                entry.id(),
                entry.logical_length(),
                destination_durability,
                &mut report,
            )?;
        }
        for envelope in &plan.page_envelopes {
            let bytes = envelope.canonical_bytes();
            transfer_one(
                self,
                destination,
                envelope.content_id(),
                bytes.len() as u64,
                destination_durability,
                &mut report,
            )?;
        }
        let manifest_bytes = plan.manifest_envelope.canonical_bytes();
        transfer_one(
            self,
            destination,
            plan.manifest_id.content_id(),
            manifest_bytes.len() as u64,
            destination_durability,
            &mut report,
        )?;
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

    fn verify_plan_against_source(
        &self,
        plan: &CampaignArchivePlan,
    ) -> Result<(), CampaignRepositoryError> {
        let mut represented =
            self.authenticated_closure_ids([plan.manifest.source_snapshot().content_id()])?;
        represented.extend(
            self.authenticated_closure_ids(
                plan.manifest
                    .checkpoint_selections()
                    .iter()
                    .map(|selection| selection.checkpoint().content_id()),
            )?,
        );
        let retained_closure =
            self.authenticated_closure_ids(plan.manifest.retained_roots().iter().copied())?;
        self.reject_nested_archive_metadata(&retained_closure)?;
        represented.extend(retained_closure);
        let declared = plan
            .selected
            .iter()
            .chain(&plan.omitted)
            .map(|entry| entry.id())
            .collect::<BTreeSet<_>>();
        if represented != declared
            || plan.manifest.selected_digest() != inventory_digest(&plan.selected)
            || plan.manifest.omitted_digest() != inventory_digest(&plan.omitted)
        {
            return Err(integrity("campaign-archive-plan-no-longer-matches-source"));
        }
        Ok(())
    }

    fn reject_nested_archive_metadata(
        &self,
        closure: &BTreeSet<ContentId>,
    ) -> Result<(), CampaignRepositoryError> {
        for id in closure {
            if !is_campaign_record_kind(id.kind()) || id.kind() == ObjectKind::MerkleNode {
                continue;
            }
            let envelope = self.read_envelope(*id)?;
            if matches!(
                envelope.record_kind(),
                CampaignRecordKind::ArchiveManifest | CampaignRecordKind::ArchiveInventoryPage
            ) {
                return Err(CampaignRepositoryError::InvalidRequest {
                    reason: "mirror retained roots cannot contain archive metadata",
                });
            }
        }
        Ok(())
    }

    fn read_archive_pages(
        &self,
        ids: &[CampaignArchiveInventoryPageId],
        disposition: ArchiveInventoryDisposition,
    ) -> Result<(Vec<ArchiveObjectEntry>, Vec<ContentId>), CampaignRepositoryError> {
        let mut entries = Vec::new();
        let mut page_ids = Vec::with_capacity(ids.len());
        for (ordinal, id) in ids.iter().copied().enumerate() {
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
    ) -> Result<
        (
            crucible_cas::content_store::ObjectProfile,
            BTreeSet<ContentId>,
        ),
        CampaignRepositoryError,
    > {
        let authenticated = self.blobs.read(id, None)?;
        authenticated.copy_to(&mut io::sink())?;
        let profile = profiler.derive_profile(id, &self.blobs.read(id, None)?)?;
        let children = if is_archive_opaque_leaf(id.kind()) {
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

fn archive_policy_selects(
    policy: CampaignArchivePolicy,
    id: ContentId,
    role: RetentionRole,
    finding_closure: &BTreeSet<ContentId>,
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
                || role == RetentionRole::ExactState && finding_closure.contains(&id)
        }
        CampaignArchivePolicy::Executable | CampaignArchivePolicy::Mirror => true,
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

fn archive_pages(
    disposition: ArchiveInventoryDisposition,
    entries: &[ArchiveObjectEntry],
) -> Result<(Vec<CampaignArchiveInventoryPageId>, Vec<ObjectEnvelope>), CampaignRepositoryError> {
    let mut ids = Vec::new();
    let mut envelopes = Vec::new();
    for (ordinal, chunk) in entries
        .chunks(MAX_ARCHIVE_INVENTORY_PAGE_ENTRIES)
        .enumerate()
    {
        let ordinal =
            u32::try_from(ordinal).map_err(|_| integrity("campaign-archive-page-limit"))?;
        let page = CampaignArchiveInventoryPage::new(disposition, ordinal, chunk.to_vec())?;
        let envelope = ObjectEnvelope::for_archive_inventory_page(&page)?;
        ids.push(CampaignArchiveInventoryPageId::from_content_id(
            envelope.content_id(),
        )?);
        envelopes.push(envelope);
    }
    Ok((ids, envelopes))
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
