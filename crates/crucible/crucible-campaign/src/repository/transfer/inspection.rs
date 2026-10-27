//! Authenticated compact archive inventories and complete RAM availability.
//!
//! Operational readers verify RAM graphs under retained source authority. The
//! checked inspection route supervises inventory, selected-object, closure,
//! policy, snapshot, and finding reads under one saved original. Compatibility
//! inspection retains its ordinary backend dispatch. GC readers authenticate
//! bounded inventory and root records under an existing exclusive fence, then
//! require separate transitive RAM marking.

use std::io;

use super::*;
use crate::CampaignArchiveInspection;
use crate::archive::{build_inspection, inventory_digest_admitted};
use crate::object_profile::{
    profile_authenticated_campaign_envelope, profile_authenticated_exact_leaf,
    profile_authenticated_opaque,
};

enum ArchiveInspectionRead<'a> {
    Compatibility,
    Checked {
        saved: &'a crucible_store::owned_decode::DecodeBudget,
        operation: crucible_store::owned_decode::DecodeBudget,
    },
}

impl<'a> ArchiveInspectionRead<'a> {
    fn checked(
        saved: &'a crucible_store::owned_decode::DecodeBudget,
    ) -> Result<Self, CampaignRepositoryError> {
        let operation = saved.child().map_err(|source| {
            CampaignRepositoryError::Ram(crucible_store::ram::RamStoreError::from_admission(
                saved, source,
            ))
        })?;
        Ok(Self::Checked { saved, operation })
    }

    fn accounts(
        &self,
    ) -> Option<(
        &crucible_store::owned_decode::DecodeBudget,
        &crucible_store::owned_decode::DecodeBudget,
    )> {
        match self {
            Self::Compatibility => None,
            Self::Checked { saved, operation } => Some((saved, operation)),
        }
    }

    fn operation(&self) -> Option<&crucible_store::owned_decode::DecodeBudget> {
        self.accounts().map(|(_, operation)| operation)
    }

    fn vec_with_capacity<T>(&self, capacity: usize) -> Result<Vec<T>, CampaignRepositoryError> {
        let Some(operation) = self.operation() else {
            return Ok(Vec::with_capacity(capacity));
        };
        operation
            .charge_array::<T>(capacity)
            .map_err(CampaignCodecError::from)?;
        let mut values = Vec::new();
        values
            .try_reserve_exact(capacity)
            .map_err(|source| StoreError::Allocation {
                source,
                custody: Some(operation.custody()),
            })?;
        if values.capacity() > capacity {
            return Err(StoreError::Quota.into());
        }
        Ok(values)
    }

    fn reserve_growth<T>(
        &self,
        values: &mut Vec<T>,
        additional: usize,
    ) -> Result<(), CampaignRepositoryError> {
        let Some(operation) = self.operation() else {
            values.reserve(additional);
            return Ok(());
        };
        let required = values
            .len()
            .checked_add(additional)
            .ok_or(StoreError::Quota)?;
        if required <= values.capacity() || std::mem::size_of::<T>() == 0 {
            return Ok(());
        }
        let target = values
            .capacity()
            .checked_mul(2)
            .ok_or(StoreError::Quota)?
            .max(8)
            .max(required);
        let geometric = target.checked_sub(values.len()).ok_or(StoreError::Quota)?;
        let _scope = operation.enter();
        crucible_store::owned_decode::reserve_vec(values, geometric)
            .map_err(CampaignCodecError::from)?;
        Ok(())
    }

    fn insert_set<T: Ord>(
        &self,
        values: &mut BTreeSet<T>,
        value: T,
    ) -> Result<bool, CampaignRepositoryError> {
        if !values.contains(&value)
            && let Some(operation) = self.operation()
        {
            operation
                .charge_btree_entry::<T, ()>()
                .map_err(CampaignCodecError::from)?;
        }
        Ok(values.insert(value))
    }

    fn insert_map<K: Ord, V>(
        &self,
        values: &mut BTreeMap<K, V>,
        key: K,
        value: V,
    ) -> Result<Option<V>, CampaignRepositoryError> {
        if !values.contains_key(&key)
            && let Some(operation) = self.operation()
        {
            operation
                .charge_btree_entry::<K, V>()
                .map_err(CampaignCodecError::from)?;
        }
        Ok(values.insert(key, value))
    }

    fn collect_set_with_boundary<T: Ord>(
        &self,
        values: impl IntoIterator<Item = T>,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<BTreeSet<T>, CampaignRepositoryError> {
        let mut output = BTreeSet::new();
        for value in values {
            self.insert_set(&mut output, value)?;
            self.poll_checked(boundary)?;
        }
        Ok(output)
    }

    fn poll_checked(
        &self,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<(), CampaignRepositoryError> {
        if matches!(self, Self::Checked { .. }) {
            self.poll(boundary)?;
        }
        Ok(())
    }

    fn poll(
        &self,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<(), CampaignRepositoryError> {
        let Some((saved, operation)) = self.accounts() else {
            return boundary().map_err(CampaignRepositoryError::Ram);
        };
        let mut supervised = || poll_inspection_saved(saved, boundary);
        crucible_store::ram::with_store_operation_boundary(operation, &mut supervised, |checked| {
            checked()
        })
        .map_err(map_inspection_read_error)
    }

    fn with_store<T>(
        &self,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
        action: impl FnOnce(
            &crucible_store::owned_decode::DecodeBudget,
            &mut dyn FnMut() -> Result<(), StoreError>,
        ) -> Result<T, StoreError>,
    ) -> Result<T, CampaignRepositoryError> {
        let Some((saved, operation)) = self.accounts() else {
            return Err(StoreError::Unsupported {
                capability: "campaign-archive-inspection-checked-read",
            }
            .into());
        };
        let mut supervised = || poll_inspection_saved(saved, boundary);
        crucible_store::ram::with_store_operation_boundary(operation, &mut supervised, |checked| {
            action(operation, checked)
        })
        .map_err(map_inspection_read_error)
    }
}

struct AuthenticatedGenericEnvelope {
    envelope: ContentEnvelope,
    logical_length: u64,
}

struct AuthenticatedCampaignEnvelope {
    envelope: ObjectEnvelope,
    logical_length: u64,
}

fn map_inspection_read_error(
    source: crucible_store::ram::RamStoreError,
) -> CampaignRepositoryError {
    match source {
        source @ crucible_store::ram::RamStoreError::Store(
            StoreError::RamReadBoundary { .. }
            | StoreError::RamReadValidation { .. }
            | StoreError::RamReadContinuation { .. },
        ) => CampaignRepositoryError::Ram(source),
        crucible_store::ram::RamStoreError::Store(source) => CampaignRepositoryError::Store(source),
        source => CampaignRepositoryError::Ram(source),
    }
}

fn poll_inspection_saved(
    saved: &crucible_store::owned_decode::DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
) -> Result<(), crucible_store::ram::RamStoreError> {
    saved
        .verify_live()
        .map_err(|source| crucible_store::ram::RamStoreError::from_admission(saved, source))?;
    boundary()?;
    saved
        .verify_live()
        .map_err(|source| crucible_store::ram::RamStoreError::from_admission(saved, source))
}

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
        self.verify_ram_admission()?;
        let target = self
            .refs
            .read_ref(&archive_ref(name)?)?
            .ok_or(CampaignRepositoryError::NotFound)?;
        let id = CampaignArchiveManifestId::from_content_id(target)?;
        self.inspect_campaign_archive_owned(id, true, &mut || Ok(()))
    }

    /// Authenticates a named archive's bounded object reads under its original boundary.
    ///
    /// The named-ref lookup retains its ordinary backend contract. The target
    /// archive then uses checked reads for its manifest, inventory pages and
    /// selected objects.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid or missing references, corrupt archive
    /// contents, or a rejected operational boundary.
    pub fn inspect_campaign_archive_ref_with_boundary(
        &self,
        name: &str,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<CampaignArchiveInspection, CampaignRepositoryError> {
        let original = self
            .ram_admission()
            .original()
            .ok_or(StoreError::Unsupported {
                capability: "campaign-archive-inspection-admission",
            })?;
        crucible_store::ram::with_store_operation_boundary(
            original,
            boundary,
            |checked_boundary| checked_boundary(),
        )
        .map_err(map_inspection_read_error)?;
        let target = self
            .refs
            .read_ref(&archive_ref(name)?)?
            .ok_or(CampaignRepositoryError::NotFound)?;
        let id = CampaignArchiveManifestId::from_content_id(target)?;
        let reads = ArchiveInspectionRead::checked(original)?;
        self.inspect_campaign_archive_under(id, true, &reads, boundary)
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
        self.inspect_campaign_archive_owned(id, true, &mut || Ok(()))
    }

    /// Inspects bounded archive metadata and selected objects under its operation boundary.
    ///
    /// Closure expansion and policy/source-snapshot reads retain their existing
    /// ordinary contracts. This method does not claim to supervise those reads.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid metadata, missing or corrupt selected
    /// descendants, or a rejected operational boundary.
    pub fn inspect_campaign_archive_with_boundary(
        &self,
        id: CampaignArchiveManifestId,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<CampaignArchiveInspection, CampaignRepositoryError> {
        let original = self
            .ram_admission()
            .original()
            .ok_or(StoreError::Unsupported {
                capability: "campaign-archive-inspection-admission",
            })?;
        let reads = ArchiveInspectionRead::checked(original)?;
        self.inspect_campaign_archive_under(id, true, &reads, boundary)
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
        _inventory: &dyn crucible_store::content_store::RefInventoryFence,
    ) -> Result<CampaignArchiveInspection, CampaignRepositoryError> {
        self.inspect_campaign_archive_for_gc_with_boundary(id, _inventory, &mut || Ok(()))
    }

    /// Authenticates archive GC metadata under the original inventory operation.
    ///
    /// # Errors
    /// Refuses expired supervision, corrupt or missing metadata, invalid
    /// inventories, and inconsistent typed RAM roots before marking.
    pub fn inspect_campaign_archive_for_gc_with_boundary(
        &self,
        id: CampaignArchiveManifestId,
        _inventory: &dyn crucible_store::content_store::RefInventoryFence,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<CampaignArchiveInspection, CampaignRepositoryError> {
        self.inspect_campaign_archive_owned(id, false, boundary)
    }

    pub(super) fn inspect_campaign_archive_owned(
        &self,
        id: CampaignArchiveManifestId,
        verify_ram: bool,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<CampaignArchiveInspection, CampaignRepositoryError> {
        let reads = ArchiveInspectionRead::Compatibility;
        self.inspect_campaign_archive_under(id, verify_ram, &reads, boundary)
    }

    fn inspect_campaign_archive_under(
        &self,
        id: CampaignArchiveManifestId,
        verify_ram: bool,
        reads: &ArchiveInspectionRead<'_>,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<CampaignArchiveInspection, CampaignRepositoryError> {
        self.verify_ram_admission()?;
        let _operation_scope = reads.operation().map(|operation| operation.enter());
        reads.poll(boundary)?;
        let envelope = self.read_archive_record(
            id.content_id(),
            CampaignRecordKind::ArchiveManifest,
            reads,
            boundary,
        )?;
        let manifest = CampaignArchiveManifest::from_canonical_bytes(envelope.body())?;
        let decoded_id = manifest.id()?;
        // Canonical identity reconstruction allocates under the operation
        // account. Surface a sticky refusal before reporting a derived mismatch.
        reads.poll_checked(boundary)?;
        if decoded_id != id {
            return Err(integrity("campaign-archive-manifest-envelope-shape"));
        }

        let (selected, mut page_ids) = self.read_archive_pages(
            manifest.selected_pages(),
            ArchiveInventoryDisposition::Selected,
            reads,
            boundary,
        )?;
        let (omitted, omitted_page_ids) = self.read_archive_pages(
            manifest.omitted_pages(),
            ArchiveInventoryDisposition::Omitted,
            reads,
            boundary,
        )?;
        reads.reserve_growth(&mut page_ids, omitted_page_ids.len())?;
        page_ids.extend(omitted_page_ids);
        if selected.len() as u64 != manifest.selected_count()
            || omitted.len() as u64 != manifest.omitted_count()
        {
            return Err(integrity("campaign-archive-inventory-manifest-mismatch"));
        }
        if inventory_digest_admitted(&selected)? != manifest.selected_digest()
            || inventory_digest_admitted(&omitted)? != manifest.omitted_digest()
        {
            return Err(integrity("campaign-archive-inventory-manifest-mismatch"));
        }

        let declared = reads.collect_set_with_boundary(
            selected.iter().chain(&omitted).map(|entry| entry.id()),
            boundary,
        )?;
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
            Some(if let Some((saved, operation)) = reads.accounts() {
                self.authenticated_archive_closure_with_operation(
                    roots, verify_ram, saved, operation, boundary,
                )?
            } else {
                self.authenticated_archive_closure(roots, verify_ram, boundary)?
            })
        } else {
            None
        };
        let mut exact_leaves = reads.collect_set_with_boundary(
            executable_closure
                .as_ref()
                .into_iter()
                .flat_map(|closure| closure.exact_leaves.iter().copied()),
            boundary,
        )?;
        let selected_ids =
            reads.collect_set_with_boundary(selected.iter().map(|entry| entry.id()), boundary)?;
        let ram_roots =
            reads.collect_set_with_boundary(manifest.ram_roots().iter().copied(), boundary)?;
        if !ram_roots.is_subset(&selected_ids) {
            return Err(integrity("campaign-archive-ram-root-is-not-selected"));
        }
        let mut typed_selected_roots = BTreeSet::new();
        let mut world_ram_roots = BTreeSet::new();
        let mut selected_children = BTreeMap::new();
        for entry in &selected {
            reads.poll(boundary)?;
            if entry.id().kind() != ObjectKind::ExactManifest {
                continue;
            }
            let authenticated = self.read_generic_envelope(entry.id(), reads, boundary)?;
            let envelope = &authenticated.envelope;
            if envelope.content_id(ObjectKind::ExactManifest) != entry.id() {
                return Err(integrity("campaign-archive-exact-root-identity"));
            }
            if envelope.schema_name() == "crucible.ram.root" && envelope.schema_version() == 1 {
                reads.insert_set(&mut typed_selected_roots, entry.id())?;
            }
            if envelope.schema_name() == "crucible.executor.exact-checkpoint-root"
                && envelope.schema_version() == 6
            {
                let mut ordinal = 0_u32;
                for child in envelope.children() {
                    if !child.role().starts_with("ram-root-") {
                        reads.poll_checked(boundary)?;
                        continue;
                    }
                    let role_ordinal = child
                        .role()
                        .strip_prefix("ram-root-")
                        .filter(|suffix| suffix.len() == 8)
                        .and_then(|suffix| u32::from_str_radix(suffix, 16).ok());
                    if role_ordinal != Some(ordinal)
                        || child.id().kind() != ObjectKind::ExactManifest
                        || child.id().schema_version() != 1
                    {
                        return Err(integrity("campaign-archive-world-ram-role-mismatch"));
                    }
                    reads.insert_set(&mut world_ram_roots, child.id())?;
                    ordinal = ordinal
                        .checked_add(1)
                        .ok_or_else(|| integrity("campaign-archive-world-ram-limit"))?;
                    reads.poll_checked(boundary)?;
                }
                for child in envelope.children() {
                    if matches!(
                        child.role(),
                        "checkpoint-choice-closure" | "replay-oracle-evidence"
                    ) {
                        reads.insert_set(&mut exact_leaves, child.id())?;
                    }
                    reads.poll_checked(boundary)?;
                }
            }
            if matches!(reads, ArchiveInspectionRead::Checked { .. }) {
                let profile =
                    profile_authenticated_opaque(entry.id(), authenticated.logical_length)?;
                let children = if ram_roots.contains(&entry.id()) {
                    self.authenticate_inspection_ram_root(
                        entry.id(),
                        verify_ram && executable_closure.is_none(),
                        reads,
                        boundary,
                    )?;
                    BTreeSet::new()
                } else {
                    reads.collect_set_with_boundary(
                        envelope.children().iter().map(crate::ChildReference::id),
                        boundary,
                    )?
                };
                if !entry.matches_profile(profile) {
                    return Err(integrity(
                        "campaign-archive-selected-object-profile-mismatch",
                    ));
                }
                if children.iter().any(|child| !declared.contains(child)) {
                    return Err(integrity("campaign-archive-selected-child-is-undeclared"));
                }
                reads.insert_map(&mut selected_children, entry.id(), children)?;
            }
        }
        if typed_selected_roots != ram_roots || !ram_roots.is_subset(&world_ram_roots) {
            return Err(integrity("campaign-archive-ram-root-inventory-mismatch"));
        }
        if let Some(entry) = selected.iter().find(|entry| {
            entry.id().kind() == ObjectKind::ExactManifest && exact_leaves.contains(&entry.id())
        }) {
            return Err(StoreError::Corrupt { id: entry.id() }.into());
        }
        for entry in &selected {
            if matches!(reads, ArchiveInspectionRead::Checked { .. })
                && entry.id().kind() == ObjectKind::ExactManifest
            {
                continue;
            }
            let (profile, children) = self.authenticate_archive_object(
                entry.id(),
                exact_leaves.contains(&entry.id()),
                ram_roots.contains(&entry.id()),
                verify_ram && executable_closure.is_none(),
                reads,
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
            reads.insert_map(&mut selected_children, entry.id(), children)?;
        }
        let mut omitted_inventory_verified = true;
        for entry in &omitted {
            match self.authenticate_archive_object(
                entry.id(),
                exact_leaves.contains(&entry.id()),
                false,
                false,
                reads,
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
        self.validate_archive_policy(
            &manifest,
            &selected,
            &omitted,
            &selected_children,
            reads,
            boundary,
        )?;
        if let Some(complete) = executable_closure {
            self.reject_nested_archive_metadata_for_inspection(
                &complete.objects,
                &complete.exact_leaves,
                reads,
                boundary,
            )?;
            if complete.objects != selected_ids
                || complete.ram_roots != manifest.ram_roots()
                || !omitted.is_empty()
            {
                return Err(integrity(
                    "campaign-archive-executable-closure-is-incomplete",
                ));
            }
        }
        let inspection = build_inspection(
            id,
            manifest,
            selected,
            omitted,
            page_ids,
            omitted_inventory_verified,
            reads.operation(),
        )
        .map_err(CampaignRepositoryError::from)?;
        reads.poll(boundary)?;
        Ok(inspection)
    }

    fn reject_nested_archive_metadata_for_inspection(
        &self,
        closure: &BTreeSet<ContentId>,
        exact_leaves: &BTreeSet<ContentId>,
        reads: &ArchiveInspectionRead<'_>,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<(), CampaignRepositoryError> {
        if reads.accounts().is_none() {
            return self.reject_nested_archive_metadata(closure, exact_leaves);
        }
        for id in closure {
            if !exact_leaves.contains(id)
                && is_campaign_record_kind(id.kind())
                && id.kind() != ObjectKind::MerkleNode
            {
                let envelope = self.read_campaign_envelope(*id, reads, boundary)?.envelope;
                if matches!(
                    envelope.record_kind(),
                    CampaignRecordKind::ArchiveManifest | CampaignRecordKind::ArchiveInventoryPage
                ) {
                    return Err(CampaignRepositoryError::InvalidRequest {
                        reason: "mirror retained roots cannot contain archive metadata",
                    });
                }
            }
            reads.poll_checked(boundary)?;
        }
        Ok(())
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

    /// Authenticates an archived finding after bounded archive object inspection.
    ///
    /// The later source-snapshot and finding-proof reads retain their ordinary
    /// backend contracts.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid archive availability, absent finding
    /// membership, or a rejected operational boundary.
    pub fn inspect_archived_finding_with_boundary(
        &self,
        archive: CampaignArchiveManifestId,
        finding: crate::FindingId,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<crate::CampaignArchivedFinding, CampaignRepositoryError> {
        let original = self
            .ram_admission()
            .original()
            .ok_or(StoreError::Unsupported {
                capability: "campaign-archive-inspection-admission",
            })?;
        let reads = ArchiveInspectionRead::checked(original)?;
        let inspection = self.inspect_campaign_archive_under(archive, true, &reads, boundary)?;
        if !matches!(
            inspection.manifest().policy(),
            CampaignArchivePolicy::Executable | CampaignArchivePolicy::Mirror
        ) {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "finding handoff requires an executable archive",
            });
        }

        let (saved, operation) = reads.accounts().ok_or(StoreError::Unsupported {
            capability: "campaign-archive-inspection-admission",
        })?;
        let reader =
            crate::repository::closure::read::ClosureRead::from_operation(self, saved, operation);
        let _scope = operation.enter();
        let mut semantic = reader.semantic(boundary);
        let snapshot =
            semantic.read_snapshot(inspection.manifest().source_snapshot().content_id())?;
        let finding = semantic
            .read_finding_cached(finding.content_id(), &mut ChoiceValidationCache::default())?;
        if semantic.merkle_get(
            snapshot.snapshot.roots().findings,
            finding_signature_key(finding.signature().cluster_key()),
        )? != Some(finding.id()?.content_id())
        {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "campaign-finding-is-not-in-snapshot",
            });
        }
        reader.poll(boundary)?;
        let admitted = crate::CampaignArchivedFinding::admitted(finding, operation)
            .map_err(CampaignCodecError::from)
            .map_err(CampaignRepositoryError::from)?;
        reader.poll(boundary)?;
        Ok(admitted)
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

    /// Authenticates an exact-capable finding under its original read boundary.
    ///
    /// # Errors
    /// Refuses invalid archive membership, absent exact pins, or a rejected
    /// operational boundary during complete archive authentication.
    pub fn inspect_archived_exact_finding_with_boundary(
        &self,
        archive: CampaignArchiveManifestId,
        finding: crate::FindingId,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<crate::CampaignArchivedFinding, CampaignRepositoryError> {
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
        reads: &ArchiveInspectionRead<'_>,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<(Vec<ArchiveObjectEntry>, Vec<ContentId>), CampaignRepositoryError> {
        let mut entries = Vec::new();
        let mut page_ids = reads.vec_with_capacity(ids.len())?;
        for (ordinal, id) in ids.iter().copied().enumerate() {
            reads.poll(boundary)?;
            let envelope = self.read_archive_record(
                id.content_id(),
                CampaignRecordKind::ArchiveInventoryPage,
                reads,
                boundary,
            )?;
            let page = CampaignArchiveInventoryPage::from_canonical_bytes(envelope.body())?;
            let decoded_id = page.id()?;
            reads.poll_checked(boundary)?;
            if decoded_id != id
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
            let entries_per_poll = (64 * 1024 / std::mem::size_of::<ArchiveObjectEntry>()).max(1);
            for chunk in page.entries().chunks(entries_per_poll) {
                reads.reserve_growth(&mut entries, chunk.len())?;
                entries.extend_from_slice(chunk);
                reads.poll_checked(boundary)?;
            }
            page_ids.push(id.content_id());
        }
        Ok((entries, page_ids))
    }

    fn authenticate_archive_object(
        &self,
        id: ContentId,
        exact_leaf: bool,
        ram_root: bool,
        verify_ram: bool,
        reads: &ArchiveInspectionRead<'_>,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<
        (
            crucible_store::content_store::ObjectProfile,
            BTreeSet<ContentId>,
        ),
        CampaignRepositoryError,
    > {
        if reads.accounts().is_some() {
            return self.authenticate_archive_object_checked(
                id, exact_leaf, ram_root, verify_ram, reads, boundary,
            );
        }
        boundary().map_err(CampaignRepositoryError::Ram)?;
        let authenticated = self.blobs.read(id, None)?;
        authenticated.copy_to(&mut io::sink())?;
        boundary().map_err(CampaignRepositoryError::Ram)?;
        let source = self.blobs.read(id, None)?;
        let profiler = CampaignObjectProfiler;
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
                reads.collect_set_with_boundary(
                    envelope.children().iter().map(crate::ChildReference::id),
                    boundary,
                )?
            } else {
                let envelope = ContentEnvelope::from_canonical_bytes(&bytes)
                    .map_err(CampaignCodecError::from)?;
                if envelope.content_id(id.kind()) != id {
                    return Err(integrity("campaign-archive-generic-envelope-id-mismatch"));
                }
                reads.collect_set_with_boundary(
                    envelope.children().iter().map(crate::ChildReference::id),
                    boundary,
                )?
            }
        };
        boundary().map_err(CampaignRepositoryError::Ram)?;
        Ok((profile, children))
    }

    fn authenticate_archive_object_checked(
        &self,
        id: ContentId,
        exact_leaf: bool,
        ram_root: bool,
        verify_ram: bool,
        reads: &ArchiveInspectionRead<'_>,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<
        (
            crucible_store::content_store::ObjectProfile,
            BTreeSet<ContentId>,
        ),
        CampaignRepositoryError,
    > {
        let (profile, children) = if exact_leaf || ram_root || is_archive_opaque_leaf(id.kind()) {
            let logical_length = self.authenticate_checked_stream(id, reads, boundary)?;
            if exact_leaf && (id.kind() != ObjectKind::Observation || id.schema_version() != 1) {
                return Err(StoreError::Corrupt { id }.into());
            }
            (
                profile_authenticated_opaque(id, logical_length)?,
                BTreeSet::new(),
            )
        } else if is_campaign_record_kind(id.kind()) {
            let envelope = self.read_campaign_envelope(id, reads, boundary)?;
            let profile = profile_authenticated_campaign_envelope(
                id,
                &envelope.envelope,
                envelope.logical_length,
            )?;
            let children = reads.collect_set_with_boundary(
                envelope
                    .envelope
                    .children()
                    .iter()
                    .map(crate::ChildReference::id),
                boundary,
            )?;
            (profile, children)
        } else {
            let authenticated = self.read_generic_envelope(id, reads, boundary)?;
            let profile = profile_authenticated_opaque(id, authenticated.logical_length)?;
            let children = reads.collect_set_with_boundary(
                authenticated
                    .envelope
                    .children()
                    .iter()
                    .map(crate::ChildReference::id),
                boundary,
            )?;
            (profile, children)
        };
        if ram_root {
            self.authenticate_inspection_ram_root(id, verify_ram, reads, boundary)?;
        }
        reads.poll(boundary)?;
        Ok((profile, children))
    }

    fn read_archive_record(
        &self,
        id: ContentId,
        expected: CampaignRecordKind,
        reads: &ArchiveInspectionRead<'_>,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<ObjectEnvelope, CampaignRepositoryError> {
        if reads.accounts().is_none() {
            return self.require_record_kind(id, expected);
        }
        let authenticated = self.read_campaign_envelope(id, reads, boundary)?;
        if authenticated.envelope.record_kind() != expected {
            return Err(integrity("campaign-child-record-kind-mismatch"));
        }
        Ok(authenticated.envelope)
    }

    fn read_campaign_envelope(
        &self,
        id: ContentId,
        reads: &ArchiveInspectionRead<'_>,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<AuthenticatedCampaignEnvelope, CampaignRepositoryError> {
        let (bytes, logical_length) = self.read_checked_bytes(id, reads, boundary)?;
        let envelope = if id.kind() == ObjectKind::MerkleNode {
            ObjectEnvelope::from_canonical_bytes_for_owner(&bytes)?
        } else {
            ObjectEnvelope::from_canonical_bytes(&bytes)?
        };
        if envelope.content_id() != id {
            return Err(integrity("campaign-archive-object-envelope-id-mismatch"));
        }
        Ok(AuthenticatedCampaignEnvelope {
            envelope,
            logical_length,
        })
    }

    fn read_generic_envelope(
        &self,
        id: ContentId,
        reads: &ArchiveInspectionRead<'_>,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<AuthenticatedGenericEnvelope, CampaignRepositoryError> {
        let (envelope, logical_length) = match reads {
            ArchiveInspectionRead::Compatibility => {
                boundary().map_err(CampaignRepositoryError::Ram)?;
                let source = self.blobs.read(id, None)?;
                let logical_length = source.logical_length();
                let bytes = source.read_all(MAX_ENVELOPE_BYTES)?;
                (
                    ContentEnvelope::from_canonical_bytes(&bytes)
                        .map_err(CampaignCodecError::from)?,
                    logical_length,
                )
            }
            ArchiveInspectionRead::Checked { .. } => {
                let (bytes, logical_length) = self.read_checked_bytes(id, reads, boundary)?;
                (
                    ContentEnvelope::from_canonical_bytes(&bytes)
                        .map_err(CampaignCodecError::from)?,
                    logical_length,
                )
            }
        };
        if envelope.content_id(id.kind()) != id {
            return Err(integrity("campaign-archive-generic-envelope-id-mismatch"));
        }
        Ok(AuthenticatedGenericEnvelope {
            envelope,
            logical_length,
        })
    }

    fn read_checked_bytes(
        &self,
        id: ContentId,
        reads: &ArchiveInspectionRead<'_>,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<(crucible_store::content_store::OwnedBlobBytes, u64), CampaignRepositoryError> {
        reads.with_store(boundary, |operation, checked_boundary| {
            let source = self
                .blobs
                .read_with_boundary(operation, id, None, checked_boundary)?;
            let logical_length = source.logical_length();
            let bytes =
                source.read_all_with_boundary(operation, MAX_ENVELOPE_BYTES, checked_boundary)?;
            checked_boundary()?;
            Ok((bytes, logical_length))
        })
    }

    fn authenticate_checked_stream(
        &self,
        id: ContentId,
        reads: &ArchiveInspectionRead<'_>,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<u64, CampaignRepositoryError> {
        reads.with_store(boundary, |operation, checked_boundary| {
            let source = self
                .blobs
                .read_with_boundary(operation, id, None, checked_boundary)?;
            let logical_length = source.logical_length();
            source.authenticate_with_boundary(operation, id, checked_boundary)?;
            checked_boundary()?;
            Ok(logical_length)
        })
    }

    fn authenticate_inspection_ram_root(
        &self,
        id: ContentId,
        verify_contents: bool,
        reads: &ArchiveInspectionRead<'_>,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<(), CampaignRepositoryError> {
        let Some((saved, operation)) = reads.accounts() else {
            return self.authenticate_ram_root(id, verify_contents, boundary);
        };
        let mut supervised = || poll_inspection_saved(saved, boundary);
        self.authenticate_ram_root_under(id, verify_contents, operation, &mut supervised)?;
        reads.poll(boundary)
    }

    fn read_inspection_snapshot(
        &self,
        id: ContentId,
        reads: &ArchiveInspectionRead<'_>,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<LoadedSnapshot, CampaignRepositoryError> {
        if reads.accounts().is_none() {
            return self.read_snapshot(id);
        }
        if id.kind() != ObjectKind::CampaignSnapshot {
            return Err(integrity("snapshot-content-kind"));
        }
        let envelope =
            self.read_archive_record(id, CampaignRecordKind::Snapshot, reads, boundary)?;
        let snapshot = CampaignSnapshot::from_canonical_bytes(envelope.body())?;
        if reads.accounts().is_none() {
            if ObjectEnvelope::for_snapshot(&snapshot)? != envelope
                || snapshot.id()?.content_id() != id
            {
                return Err(integrity("snapshot-child-table-mismatch"));
            }
        } else {
            let canonical_envelope = ObjectEnvelope::for_snapshot(&snapshot)?;
            reads.poll_checked(boundary)?;
            if canonical_envelope != envelope {
                return Err(integrity("snapshot-child-table-mismatch"));
            }
            let snapshot_id = snapshot.id()?.content_id();
            reads.poll_checked(boundary)?;
            if snapshot_id != id {
                return Err(integrity("snapshot-child-table-mismatch"));
            }
        }
        Ok(LoadedSnapshot { envelope, snapshot })
    }

    fn validate_archive_policy(
        &self,
        manifest: &CampaignArchiveManifest,
        selected: &[ArchiveObjectEntry],
        omitted: &[ArchiveObjectEntry],
        selected_children: &BTreeMap<ContentId, BTreeSet<ContentId>>,
        reads: &ArchiveInspectionRead<'_>,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<(), CampaignRepositoryError> {
        let selected_ids =
            reads.collect_set_with_boundary(selected.iter().map(|entry| entry.id()), boundary)?;
        let source = self.read_inspection_snapshot(
            manifest.source_snapshot().content_id(),
            reads,
            boundary,
        )?;
        if !selected_ids.contains(&manifest.source_snapshot().content_id()) {
            return Err(integrity(
                "campaign-archive-source-snapshot-is-not-selected",
            ));
        }

        let finding_reachable = if manifest.policy() == CampaignArchivePolicy::Debug {
            direct_reachable(
                selected_children,
                source.snapshot.roots().findings,
                reads,
                boundary,
            )?
        } else {
            BTreeSet::new()
        };
        for entry in selected {
            if !archive_entry_selected(manifest.policy(), *entry, &finding_reachable) {
                return Err(integrity(
                    "campaign-archive-policy-selected-object-mismatch",
                ));
            }
            reads.poll(boundary)?;
        }
        for entry in omitted {
            if archive_entry_selected(manifest.policy(), *entry, &finding_reachable) {
                return Err(integrity("campaign-archive-policy-omitted-object-mismatch"));
            }
            reads.poll(boundary)?;
        }
        if matches!(
            manifest.policy(),
            CampaignArchivePolicy::Executable | CampaignArchivePolicy::Mirror
        ) {
            let mut expected = BTreeSet::new();
            let mut allocation_error = None;
            let mut visit = |pin: crate::CampaignPinRetentionRecord| {
                if allocation_error.is_none()
                    && pin.retention() == crate::PinRetention::Exact
                    && let Err(source) = reads.insert_set(
                        &mut expected,
                        (pin.request().change.configuration(), pin.fact()),
                    )
                {
                    allocation_error = Some(source);
                }
            };
            if let Some((saved, operation)) = reads.accounts() {
                let reader = crate::repository::closure::read::ClosureRead::from_operation(
                    self, saved, operation,
                );
                reader
                    .semantic(boundary)
                    .visit_pin_retention_roots_at(manifest.source_snapshot(), &mut visit)?;
            } else {
                self.visit_pin_retention_roots_at(manifest.source_snapshot(), &mut visit)?;
            }
            if let Some(source) = allocation_error {
                return Err(source);
            }
            let actual = reads.collect_set_with_boundary(
                manifest
                    .checkpoint_selections()
                    .iter()
                    .map(|selection| (selection.configuration(), selection.pin_fact())),
                boundary,
            )?;
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
    reads: &ArchiveInspectionRead<'_>,
    boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
) -> Result<BTreeSet<ContentId>, CampaignRepositoryError> {
    let mut pending = reads.vec_with_capacity(1)?;
    pending.push(root);
    let mut visited = BTreeSet::new();
    while let Some(id) = pending.pop() {
        if reads.insert_set(&mut visited, id)?
            && let Some(next) = children.get(&id)
        {
            reads.reserve_growth(&mut pending, next.len())?;
            pending.extend(next.iter().copied());
        }
        reads.poll(boundary)?;
    }
    reads.poll(boundary)?;
    Ok(visited)
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
