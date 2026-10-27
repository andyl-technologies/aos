//! Authenticated archive selection, publication, and bounded object transfer.
//!
//! The inspection module owns compact inventories and transitive RAM checks.

mod inspection;
mod ordinary_objects;

use std::collections::{BTreeMap, BTreeSet};

use crucible_store::content_envelope::ContentEnvelope;
use crucible_store::content_store::{
    ContentId, DurabilityRequirement, ObjectKind, RefCasOutcome, RefName, RetentionRole,
    StoreError, StoreObjectProfiler,
};

use super::*;
use crate::archive::inventory_digest;
use crate::object_profile::profile_authenticated_exact_leaf;
use crate::{
    ArchiveInventoryDisposition, ArchiveObjectEntry, CampaignArchiveCheckpointResolver,
    CampaignArchiveCheckpointSelection, CampaignArchiveInventoryPage,
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
        checkpoint_resolver: Option<&mut dyn CampaignArchiveCheckpointResolver>,
    ) -> Result<CampaignArchivePlan, CampaignRepositoryError> {
        self.plan_campaign_archive_with_boundary(
            snapshot,
            policy,
            retained_roots,
            checkpoint_resolver,
            &mut || Ok(()),
        )
    }

    /// Builds an archive plan while polling its actual operation supervisor.
    ///
    /// Generic ancestry and closure reads, complete RAM verification, and pin
    /// resolution retain the same boundary. A callback failure prevents plan
    /// publication and remains an operational RAM error.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid source state, exhausted declared bounds,
    /// storage corruption, or an operational boundary rejection.
    pub fn plan_campaign_archive_with_boundary(
        &self,
        snapshot: CampaignSnapshotId,
        policy: CampaignArchivePolicy,
        retained_roots: impl IntoIterator<Item = ContentId>,
        mut checkpoint_resolver: Option<&mut dyn CampaignArchiveCheckpointResolver>,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<CampaignArchivePlan, CampaignRepositoryError> {
        self.verify_ram_admission()?;
        self.validate_complete_head_with_boundary(snapshot.content_id(), boundary)?;
        let snapshot_record = self.read_snapshot(snapshot.content_id())?;
        let snapshot_closure =
            self.authenticated_archive_closure([snapshot.content_id()], true, boundary)?;
        let mut exact_leaves = snapshot_closure.exact_leaves;
        let mut ram_roots = snapshot_closure
            .ram_roots
            .into_iter()
            .collect::<BTreeSet<_>>();
        let mut ram_bindings = snapshot_closure
            .ram_bindings
            .into_iter()
            .collect::<BTreeSet<_>>();

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
                boundary().map_err(CampaignRepositoryError::Ram)?;
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
        let retained_closure =
            self.authenticated_archive_closure(retained_roots.iter().copied(), true, boundary)?;
        self.reject_nested_archive_metadata(
            &retained_closure.objects,
            &retained_closure.exact_leaves,
        )?;
        let mut represented = snapshot_closure.objects;
        represented.extend(retained_closure.objects);
        exact_leaves.extend(retained_closure.exact_leaves);
        ram_roots.extend(retained_closure.ram_roots);
        ram_bindings.extend(retained_closure.ram_bindings);
        if !checkpoint_selections.is_empty() {
            let checkpoint_closure = self.authenticated_archive_closure(
                checkpoint_selections
                    .iter()
                    .map(|selection| selection.checkpoint().content_id()),
                true,
                boundary,
            )?;
            represented.extend(checkpoint_closure.objects);
            exact_leaves.extend(checkpoint_closure.exact_leaves);
            ram_roots.extend(checkpoint_closure.ram_roots);
            ram_bindings.extend(checkpoint_closure.ram_bindings);
        }
        if represented.len() > MAX_ARCHIVE_INVENTORY_ENTRIES {
            return Err(integrity("campaign-archive-inventory-limit"));
        }

        let finding_closure = if policy == CampaignArchivePolicy::Debug {
            self.authenticated_archive_closure(
                [snapshot_record.snapshot.roots().findings],
                true,
                boundary,
            )?
            .objects
        } else {
            BTreeSet::new()
        };
        let profiler = CampaignObjectProfiler;
        let mut selected = Vec::new();
        let mut omitted = Vec::new();
        for id in represented {
            boundary().map_err(CampaignRepositoryError::Ram)?;
            let source = self.blobs.read(id, None)?;
            let profile = if exact_leaves.contains(&id) {
                profile_authenticated_exact_leaf(id, &source)?
            } else {
                profiler.derive_profile(id, &source)?
            };
            let entry = ArchiveObjectEntry::from_profile(id, profile);
            if archive_policy_selects(policy, id, profile.retention_role(), &finding_closure) {
                selected.push(entry);
            } else {
                omitted.push(entry);
            }
        }

        let selected_ids = selected
            .iter()
            .map(|entry| entry.id())
            .collect::<BTreeSet<_>>();
        let ram_roots = ram_roots
            .into_iter()
            .filter(|root| selected_ids.contains(root))
            .collect::<Vec<_>>();
        let ram_bindings = ram_bindings
            .into_iter()
            .filter(|(world, root)| {
                selected_ids.contains(&world.content_id()) && selected_ids.contains(root)
            })
            .collect::<Vec<_>>();
        if ram_roots
            .iter()
            .any(|root| !ram_bindings.iter().any(|(_, bound)| bound == root))
        {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "archive RAM roots require a selected whole-world checkpoint owner",
            });
        }
        let (selected_pages, mut page_envelopes) =
            archive_pages(ArchiveInventoryDisposition::Selected, &selected)?;
        let (omitted_pages, omitted_envelopes) =
            archive_pages(ArchiveInventoryDisposition::Omitted, &omitted)?;
        page_envelopes.extend(omitted_envelopes);
        let manifest =
            CampaignArchiveManifest::new(crate::archive::CampaignArchiveManifestBasis {
                source_snapshot: snapshot,
                policy,
                checkpoint_selections: checkpoint_selections.into_iter().collect(),
                retained_roots: retained_roots.into_iter().collect(),
                ram_roots,
                selected_pages,
                omitted_pages,
                selected: &selected,
                omitted: &omitted,
            })?;
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
            ram_bindings,
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
        self.publish_campaign_archive_with_boundary(name, expected, plan, &mut || Ok(()))
    }

    /// Publishes archive metadata while servicing the original operation owner.
    ///
    /// # Errors
    ///
    /// Returns an error for cancellation, invalid closure, placement, or stale refs.
    pub fn publish_campaign_archive_with_boundary(
        &self,
        name: &str,
        expected: Option<CampaignArchiveManifestId>,
        plan: &CampaignArchivePlan,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<CampaignArchiveManifestId, CampaignRepositoryError> {
        self.verify_ram_admission()?;
        let _mutation = self.lock_mutation()?;
        for envelope in &plan.page_envelopes {
            boundary().map_err(CampaignRepositoryError::Ram)?;
            self.put_envelope(envelope.clone())?;
        }
        boundary().map_err(CampaignRepositoryError::Ram)?;
        let id = self.put_envelope(plan.manifest_envelope.clone())?;
        if id != plan.manifest_id.content_id() {
            return Err(integrity("campaign-archive-manifest-publication-mismatch"));
        }
        self.inspect_campaign_archive_with_boundary(plan.manifest_id, boundary)?;
        let archive_ref = archive_ref(name)?;
        let expected = expected.map(CampaignArchiveManifestId::content_id);
        boundary().map_err(CampaignRepositoryError::Ram)?;
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
        self.verify_ram_admission()?;
        self.verify_plan_against_source_with_boundary(plan, &mut || Ok(()))?;
        for envelope in &plan.page_envelopes {
            self.put_envelope(envelope.clone())?;
        }
        let id = self.put_envelope(plan.manifest_envelope.clone())?;
        if id != plan.manifest_id.content_id() {
            return Err(integrity("campaign-archive-manifest-staging-mismatch"));
        }
        self.inspect_campaign_archive_with_boundary(plan.manifest_id, &mut || Ok(()))?;
        Ok(plan.manifest_id)
    }

    /// Stages source archive metadata under this repository's original boundary.
    ///
    /// Canonical page and manifest images are emitted in bounded pieces and
    /// published through checked private staging. The compatibility method
    /// preserves ordinary publication for callers without checked authority.
    ///
    /// # Errors
    ///
    /// Returns an error for missing original authority, cancellation, invalid
    /// source closure, checked publication, receipt, or readback failure.
    pub fn stage_campaign_archive_metadata_with_boundary(
        &self,
        plan: &CampaignArchivePlan,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<CampaignArchiveManifestId, CampaignRepositoryError> {
        self.verify_ram_admission()?;
        let original = self
            .ram_admission()
            .original()
            .ok_or(StoreError::Unsupported {
                capability: "campaign-archive-source-metadata-admission",
            })?;
        self.verify_plan_against_source_under(plan, Some(Some(original)), boundary)?;
        if plan.manifest_envelope.content_id() != plan.manifest_id.content_id() {
            return Err(integrity("campaign-archive-manifest-staging-mismatch"));
        }
        let id = crucible_store::ram::with_store_operation_boundary(
            original,
            boundary,
            |checked_boundary| {
                for envelope in &plan.page_envelopes {
                    self.put_envelope_with_boundary(envelope, original, checked_boundary)?;
                }
                self.put_envelope_with_boundary(&plan.manifest_envelope, original, checked_boundary)
            },
        )
        .map_err(|source| match source {
            crucible_store::ram::RamStoreError::Store(source) => {
                CampaignRepositoryError::Store(source)
            }
            source => CampaignRepositoryError::Ram(source),
        })?;
        if id != plan.manifest_id.content_id() {
            return Err(integrity("campaign-archive-manifest-staging-mismatch"));
        }
        self.inspect_campaign_archive_with_boundary(plan.manifest_id, boundary)?;
        original.verify_live().map_err(|source| {
            CampaignRepositoryError::Ram(crucible_store::ram::RamStoreError::from_admission(
                original, source,
            ))
        })?;
        Ok(plan.manifest_id)
    }

    /// Copies every missing selected object and canonical archive metadata.
    ///
    /// Destination presence is never trusted. An existing object is read to
    /// authenticated EOF. A copied object is accepted only after a durable,
    /// length-matching receipt and a second authenticated destination read.
    /// This local-copy primitive requires both namespace GC fences to remain
    /// held through final destination ref publication. It does not provide
    /// crash-recoverable transfer journals.
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
        source_original: Option<&crucible_store::owned_decode::DecodeBudget>,
        destination_original: Option<&crucible_store::owned_decode::DecodeBudget>,
    ) -> Result<CampaignArchiveTransferReport, CampaignRepositoryError> {
        let mut operation = blake3::Hasher::new();
        operation.update(b"crucible.campaign.local-archive-copy.v1\0");
        plan.manifest_id()
            .content_id()
            .with_encoded_text(|encoded| operation.update(encoded));
        self.transfer_campaign_archive_objects_for_operation_with_ram_progress_mode(
            destination,
            plan,
            destination_durability,
            *operation.finalize().as_bytes(),
            "selected-campaign-store",
            source_original,
            destination_original,
            &mut |_| Ok(()),
            &mut || Ok(()),
            ordinary_objects::Mode::Compatibility,
        )
    }

    /// Copies a local archive while retaining its original operation boundary.
    ///
    /// The caller holds both real namespace GC fences through final durable
    /// archive/ref publication. Canonical local transfer identity authenticates
    /// the bounded page protocol; it does not establish distributed retry
    /// authority or replace persisted transfer journals.
    ///
    /// # Errors
    /// Refuses invalid source state, corrupt destination objects, insufficient
    /// durability, transfer failure, cancellation, or an expired boundary.
    pub fn transfer_campaign_archive_objects_with_boundary(
        &self,
        destination: &CampaignRepository,
        plan: &CampaignArchivePlan,
        destination_durability: DurabilityRequirement,
        source_original: Option<&crucible_store::owned_decode::DecodeBudget>,
        destination_original: Option<&crucible_store::owned_decode::DecodeBudget>,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<CampaignArchiveTransferReport, CampaignRepositoryError> {
        let mut operation = blake3::Hasher::new();
        operation.update(b"crucible.campaign.local-archive-copy.v1\0");
        plan.manifest_id()
            .content_id()
            .with_encoded_text(|encoded| {
                operation.update(encoded);
            });
        self.transfer_campaign_archive_objects_for_operation(
            destination,
            plan,
            destination_durability,
            *operation.finalize().as_bytes(),
            "selected-campaign-store",
            source_original,
            destination_original,
            boundary,
        )
    }

    /// Copies an archive under its journal-bound operation and destination.
    ///
    /// RAM requests carry authenticated logical coordinates and bounded object
    /// chunks. The caller retains both journals before entering this operation;
    /// the resulting receipt establishes archive possession only.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid bindings, corruption, unavailable contents,
    /// cancellation, transfer limits, or insufficient destination durability.
    // crucible-lint: allow rust-allow -- explicit transfer inputs bind source, destination, durable operation, retention, and original supervision.
    #[allow(clippy::too_many_arguments)]
    pub fn transfer_campaign_archive_objects_for_operation(
        &self,
        destination: &CampaignRepository,
        plan: &CampaignArchivePlan,
        destination_durability: DurabilityRequirement,
        operation: [u8; 32],
        destination_identity: &str,
        source_original: Option<&crucible_store::owned_decode::DecodeBudget>,
        destination_original: Option<&crucible_store::owned_decode::DecodeBudget>,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<CampaignArchiveTransferReport, CampaignRepositoryError> {
        self.transfer_campaign_archive_objects_for_operation_with_ram_progress(
            destination,
            plan,
            destination_durability,
            operation,
            destination_identity,
            source_original,
            destination_original,
            &mut |_| Ok(()),
            boundary,
        )
    }

    /// Copies an archive and durably acknowledges each complete RAM closure.
    ///
    /// The progress callback runs while the destination's complete-closure
    /// lease is live. After the callback succeeds, the operation observes one
    /// more supervision boundary before releasing that lease. Callers can use
    /// this handoff to replace the temporary lease with journaled transitive
    /// retention without exposing the closure to concurrent collection.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid bindings, corruption, unavailable contents,
    /// cancellation, transfer limits, insufficient destination durability, or
    /// a rejected RAM-closure progress transition.
    // crucible-lint: allow rust-allow -- explicit transfer inputs bind source, destination, durable operation, retention, progress, and original supervision.
    #[allow(clippy::too_many_arguments)]
    pub fn transfer_campaign_archive_objects_for_operation_with_ram_progress(
        &self,
        destination: &CampaignRepository,
        plan: &CampaignArchivePlan,
        destination_durability: DurabilityRequirement,
        operation: [u8; 32],
        destination_identity: &str,
        source_original: Option<&crucible_store::owned_decode::DecodeBudget>,
        destination_original: Option<&crucible_store::owned_decode::DecodeBudget>,
        ram_progress: &mut dyn FnMut(ContentId) -> Result<(), CampaignRepositoryError>,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<CampaignArchiveTransferReport, CampaignRepositoryError> {
        self.transfer_campaign_archive_objects_for_operation_with_ram_progress_mode(
            destination,
            plan,
            destination_durability,
            operation,
            destination_identity,
            source_original,
            destination_original,
            ram_progress,
            boundary,
            ordinary_objects::Mode::Checked,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn transfer_campaign_archive_objects_for_operation_with_ram_progress_mode(
        &self,
        destination: &CampaignRepository,
        plan: &CampaignArchivePlan,
        destination_durability: DurabilityRequirement,
        operation: [u8; 32],
        destination_identity: &str,
        source_original: Option<&crucible_store::owned_decode::DecodeBudget>,
        destination_original: Option<&crucible_store::owned_decode::DecodeBudget>,
        ram_progress: &mut dyn FnMut(ContentId) -> Result<(), CampaignRepositoryError>,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
        ordinary_objects: ordinary_objects::Mode,
    ) -> Result<CampaignArchiveTransferReport, CampaignRepositoryError> {
        self.verify_ram_admission()?;
        destination.verify_ram_admission()?;
        let child = |original: &crucible_store::owned_decode::DecodeBudget| {
            original.verify_live().map_err(|source| {
                CampaignRepositoryError::Ram(crucible_store::ram::RamStoreError::from_admission(
                    original, source,
                ))
            })?;
            original.child().map_err(|source| {
                CampaignRepositoryError::Ram(crucible_store::ram::RamStoreError::from_admission(
                    original, source,
                ))
            })
        };
        let source_account = source_original.map(child).transpose()?;
        let destination_account = destination_original.map(child).transpose()?;
        if (!plan.ram_roots().is_empty() || ordinary_objects == ordinary_objects::Mode::Checked)
            && (source_account.is_none() || destination_account.is_none())
        {
            return Err(StoreError::Unsupported {
                capability: "campaign-archive-checked-object-admission",
            }
            .into());
        }
        self.verify_plan_against_source_under(plan, Some(source_account.as_ref()), boundary)?;
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
        // Root inventories authorize transitive RAM retention. The ordinary
        // object loop intentionally has no page catalog and cannot replace this
        // independently authenticated, complete-closure transfer.
        use crucible_store::ram::{RamRetention, RamStore, RamStoreLimits};
        let map_ram_error = CampaignRepositoryError::Ram;
        // Ordinary campaign archives may use an ephemeral source backend.
        // Admit durable RAM capabilities only when a paged RAM graph is selected.
        let ram_accounts = if plan.ram_roots().is_empty() {
            None
        } else {
            Some((
                source_account
                    .as_ref()
                    .ok_or_else(|| integrity("campaign-archive-source-ram-admission"))?,
                destination_account
                    .as_ref()
                    .ok_or_else(|| integrity("campaign-archive-destination-ram-admission"))?,
            ))
        };
        if let Some((source_original, destination_original)) = ram_accounts {
            let source_ram = RamStore::new(
                Arc::clone(&self.blobs),
                destination_durability,
                RamStoreLimits::default(),
            )
            .map_err(map_ram_error)?;
            let destination_ram = RamStore::new(
                Arc::clone(&destination.blobs),
                destination_durability,
                RamStoreLimits::default(),
            )
            .map_err(map_ram_error)?;
            for id in plan.ram_roots() {
                let world = plan
                    .ram_root_bindings()
                    .iter()
                    .find_map(|(world, ram)| (*ram == *id).then_some(*world))
                    .ok_or_else(|| integrity("campaign-archive-ram-owner-missing"))?;
                // Install the source reader claim before acquiring destination
                // publication exclusion. The claim protects the source graph
                // throughout copying without coupling the two GC fences.
                let lease = {
                    let source_retention = self
                        .ram_retention_authority()
                        .acquire()
                        .map_err(map_ram_error)?;
                    source_retention.retain_root(*id).map_err(map_ram_error)?
                };
                let root = source_ram
                    .open_with_metadata_resources(lease, source_original, boundary)
                    .map_err(map_ram_error)?;
                let destination_retention = destination
                    .ram_retention_authority()
                    .acquire()
                    .map_err(map_ram_error)?;
                let stored = source_ram
                    .transfer_archive_to(
                        &root,
                        world.content_id(),
                        &destination_ram,
                        destination_identity,
                        operation,
                        &destination_retention,
                        source_original,
                        destination_original,
                        boundary,
                    )
                    .map_err(map_ram_error)?;
                ram_progress(*id)?;
                boundary().map_err(map_ram_error)?;
                let ram_report = stored.report();
                report.copied_objects = report
                    .copied_objects
                    .checked_add(ram_report.copied_objects)
                    .ok_or_else(|| integrity("campaign-archive-transfer-count-overflow"))?;
                report.existing_objects = report
                    .existing_objects
                    .checked_add(ram_report.authenticated_existing_objects)
                    .ok_or_else(|| integrity("campaign-archive-transfer-count-overflow"))?;
                report.copied_bytes = report
                    .copied_bytes
                    .checked_add(ram_report.copied_bytes)
                    .ok_or_else(|| integrity("campaign-archive-transfer-byte-overflow"))?;
                report.observe_durable_placements(usize::from(
                    destination_durability.minimum_durable_placements(),
                ))?;
            }
        }
        for entry in &plan.selected {
            boundary().map_err(map_ram_error)?;
            ordinary_objects::transfer(
                self,
                destination,
                entry.id(),
                entry.logical_length(),
                destination_durability,
                source_account.as_ref(),
                destination_account.as_ref(),
                boundary,
                ordinary_objects,
                &mut report,
            )?;
        }
        for envelope in &plan.page_envelopes {
            boundary().map_err(map_ram_error)?;
            let bytes = envelope.canonical_bytes();
            ordinary_objects::transfer(
                self,
                destination,
                envelope.content_id(),
                bytes.len() as u64,
                destination_durability,
                source_account.as_ref(),
                destination_account.as_ref(),
                boundary,
                ordinary_objects,
                &mut report,
            )?;
        }
        let manifest_bytes = plan.manifest_envelope.canonical_bytes();
        boundary().map_err(map_ram_error)?;
        ordinary_objects::transfer(
            self,
            destination,
            plan.manifest_id.content_id(),
            manifest_bytes.len() as u64,
            destination_durability,
            source_account.as_ref(),
            destination_account.as_ref(),
            boundary,
            ordinary_objects,
            &mut report,
        )?;
        // Both endpoints remain under actual retention above. The complete RAM
        // graphs have already authenticated; avoid reacquiring their fences.
        destination.inspect_campaign_archive_owned(plan.manifest_id, false, boundary)?;
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
        self.publish_transferred_campaign_with_boundary(name, expected, archive, &mut || Ok(()))
    }

    /// Advances a complete imported campaign under its original supervisor.
    ///
    /// # Errors
    ///
    /// Returns an error for cancellation, incomplete closure, partial policy,
    /// or a conflicting destination campaign ref.
    pub fn publish_transferred_campaign_with_boundary(
        &self,
        name: &str,
        expected: Option<CampaignSnapshotId>,
        archive: CampaignArchiveManifestId,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<CampaignSnapshotId, CampaignRepositoryError> {
        self.verify_ram_admission()?;
        let inspection = self.inspect_campaign_archive_with_boundary(archive, boundary)?;
        if !matches!(
            inspection.manifest().policy(),
            CampaignArchivePolicy::Executable | CampaignArchivePolicy::Mirror
        ) {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "partial campaign archive cannot publish a campaign head",
            });
        }
        let snapshot = inspection.manifest().source_snapshot();
        self.validate_complete_head_with_boundary(snapshot.content_id(), boundary)?;

        let _mutation = self.lock_mutation()?;
        let campaign_ref = campaign_ref(name)?;
        boundary().map_err(CampaignRepositoryError::Ram)?;
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

    fn verify_plan_against_source_with_boundary(
        &self,
        plan: &CampaignArchivePlan,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<(), CampaignRepositoryError> {
        self.verify_plan_against_source_under(plan, None, boundary)
    }

    fn verify_plan_against_source_under(
        &self,
        plan: &CampaignArchivePlan,
        ram_original: Option<Option<&crucible_store::owned_decode::DecodeBudget>>,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<(), CampaignRepositoryError> {
        let roots = [plan.manifest.source_snapshot().content_id()]
            .into_iter()
            .chain(
                plan.manifest
                    .checkpoint_selections()
                    .iter()
                    .map(|selection| selection.checkpoint().content_id()),
            )
            .chain(plan.manifest.retained_roots().iter().copied());
        let closure =
            self.authenticated_archive_closure_under(roots, true, ram_original, boundary)?;
        self.reject_nested_archive_metadata(&closure.objects, &closure.exact_leaves)?;
        let represented = closure.objects;
        let selected = plan
            .selected
            .iter()
            .map(|entry| entry.id())
            .collect::<BTreeSet<_>>();
        let selected_ram = closure
            .ram_roots
            .into_iter()
            .filter(|root| selected.contains(root))
            .collect::<Vec<_>>();
        let selected_bindings = closure
            .ram_bindings
            .into_iter()
            .filter(|(world, root)| {
                selected.contains(&world.content_id()) && selected.contains(root)
            })
            .collect::<Vec<_>>();
        if selected_ram != plan.ram_roots() || selected_bindings != plan.ram_bindings {
            return Err(integrity("campaign-archive-plan-ram-binding-mismatch"));
        }
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
        exact_leaves: &BTreeSet<ContentId>,
    ) -> Result<(), CampaignRepositoryError> {
        for id in closure {
            if exact_leaves.contains(id)
                || !is_campaign_record_kind(id.kind())
                || id.kind() == ObjectKind::MerkleNode
            {
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

fn archive_ref(name: &str) -> Result<RefName, CampaignRepositoryError> {
    RefName::new(format!("archives/{name}")).map_err(CampaignRepositoryError::from)
}
