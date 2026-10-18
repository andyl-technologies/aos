//! Reads a parent Index3 as immutable evidence under the current signed closure.
//!
//! The stored body has the exact Index3/inventory2 grammar. It is not a locally
//! authenticated archive handle: only the selected top archive has that receipt.
//! Native, Source and imported-role correspondence remain separate conjuncts.

use super::*;
use crucible_node_contract::{CaptureManifest, Id, Validate, canonical};
use crucible_node_provider::protocol_snapshot::borrowed_json::BorrowedJsonFields as Fields;
use serde_json::Value;
use std::mem::size_of;

const INDEX_MEDIA: &str = "application/vnd.crucible.native-signed-index-body.v3+json";

/// Retains each completed or refused parent decode before following its lineage.
pub(super) struct ParentIndex17Attempt {
    reference: Option<ContentRef>,
    value: Option<Value>,
    index: Option<storage::Index>,
    canonical: Option<Vec<u8>>,
    manifest_value: Option<Value>,
    manifest_canonical: Option<Vec<u8>>,
    manifest: Option<CaptureManifest>,
    verified: bool,
}

/// Borrows a strictly read parent under this actual top signed closure.
///
/// This nonconstructible DATA loan grants neither local archive-load admission
/// nor current owner or restoration authority. It restricts all role/body reads
/// to the parent inventory that was checked against the genuine outer closure.
pub(crate) struct ParentArchive17ReadScope<'borrow, 'archive> {
    validation: &'borrow CompleteRestoredSettledArchiveValidation<'archive>,
    parent: &'borrow ParentIndex17Attempt,
}

impl ParentArchive17ReadScope<'_, '_> {
    pub(crate) fn manifest_data(&self) -> Result<&CaptureManifest, StateError> {
        self.validation
            .validation_origin
            .authenticate(self.validation.archive)?;
        Ok(self.parent.parts_data()?.2)
    }

    pub(crate) fn manifest_reference_data(&self) -> Result<&ContentRef, StateError> {
        self.validation
            .validation_origin
            .authenticate(self.validation.archive)?;
        Ok(&self.parent.parts_data()?.1.artifact)
    }

    pub(crate) fn index_reference_data(&self) -> Result<&ContentRef, StateError> {
        self.validation
            .validation_origin
            .authenticate(self.validation.archive)?;
        Ok(self.parent.parts_data()?.0)
    }

    pub(crate) fn selected_owner_data(
        &self,
        node: &Id,
        implementation: &Id,
        profile: &Id,
    ) -> Result<&NativeOwnerState, StateError> {
        self.validation
            .validation_origin
            .authenticate(self.validation.archive)?;
        self.parent.owner_data(node, implementation, profile)
    }

    /// Selects the actual closed initial15 participant without allocating an Id.
    pub(crate) fn selected_initial15_owner_data(
        &self,
        node: &Id,
        implementation: &Id,
    ) -> Result<&NativeOwnerState, StateError> {
        self.validation
            .validation_origin
            .authenticate(self.validation.archive)?;
        let (_, index, _) = self.parent.parts_data()?;
        let mut owners = index
            .owners
            .iter()
            .filter(|owner| owner.participants.as_slice() == std::slice::from_ref(node));
        let owner = owners
            .next()
            .ok_or_else(|| refused("parent initial15 participant absent"))?;
        if owners.next().is_some()
            || &owner.key.implementation != implementation
            || owner.key.profile.as_str() != "source-owned.packet-complete-original-lineage/5"
            || owner.key.schema.id.as_str() != "source-owned.packet-native-continuation/14"
            || owner.key.schema.version != 14
        {
            return Err(refused(
                "parent initial15 participant implementation/profile/family differs",
            ));
        }
        Ok(owner)
    }

    pub(crate) fn dependency_data(
        &self,
        reference: &ContentRef,
    ) -> Result<&[ContentRef], StateError> {
        self.validation
            .validation_origin
            .authenticate(self.validation.archive)?;
        let (_, index, _) = self.parent.parts_data()?;
        index
            .objects
            .iter()
            .find(|row| &row.reference == reference)
            .map(|row| row.dependencies.as_slice())
            .ok_or_else(|| refused("parent role is outside its actual typed inventory"))
    }

    pub(crate) fn body_data(&self, reference: &ContentRef) -> Result<&[u8], StateError> {
        self.dependency_data(reference)?;
        self.validation
            .content
            .get(reference)
            .ok_or_else(|| refused("parent verified body absent"))
    }

    pub(crate) fn original_capture_journal_reference_data(
        &self,
    ) -> Result<&ContentRef, StateError> {
        self.validation
            .validation_origin
            .authenticate(self.validation.archive)?;
        self.parent
            .parts_data()?
            .1
            .original_capture_journal
            .as_ref()
            .ok_or_else(|| refused("parent original administrative journal absent"))
    }

    pub(crate) fn authenticate_initial15_administrative_data(
        &self,
        administrative: &RuntimeOriginalCaptureJournal,
        runtime: &ContentRef,
        scheduler: &ContentRef,
    ) -> Result<(), StateError> {
        self.validation
            .validation_origin
            .authenticate(self.validation.archive)?;
        let (_, index, manifest) = self.parent.parts_data()?;
        let reference = self.original_capture_journal_reference_data()?;
        let dependencies = self.dependency_data(reference)?;
        let limits = self.limits_data()?;
        super::super::complete_original_index::authenticate_initial15_parent_parts_data(
            manifest,
            &index.owners,
            administrative,
            runtime,
            scheduler,
            dependencies,
            limits
                .state
                .maximum_total_content_bytes
                .min(limits.native.maximum_total_record_bytes),
        )?;
        self.validation
            .validation_origin
            .authenticate(self.validation.archive)
    }

    pub(crate) fn limits_data(&self) -> Result<NativeArchiveLimits, StateError> {
        self.validation.archive_limits_data()
    }

    pub(crate) fn retained_content_requested_storage_data(&self) -> Result<usize, StateError> {
        self.validation.retained_verified_content_allocation_bytes()
    }

    pub(crate) fn lineage_limits_data(&self) -> OriginalInputLineageLimits {
        self.validation.lineage_limits
    }
}

impl ParentIndex17Attempt {
    /// Reads the exact parent body, never fabricating an archive-load receipt.
    ///
    /// The owning collector retains `output` and includes its other actual
    /// allocations in `additional`. Depth and inventory extents are rejected
    /// before an owning DOM or typed parent is allocated. Every initialized
    /// parse product remains in the output on refusal.
    pub(super) fn read_into(
        scope: &CompleteRestoredSettledArchiveValidation<'_>,
        reference: &ContentRef,
        depth: usize,
        additional: usize,
        output: &mut Option<Self>,
    ) -> Result<(), StateError> {
        scope.validation_origin.authenticate(scope.archive)?;
        let limits = scope.archive_limits_data()?;
        if output.is_some() || depth >= limits.state.maximum_dependency_depth {
            return Err(refused("parent Index3 attempt is spent or exceeds depth"));
        }
        let row = scope
            .archive
            .index
            .objects
            .iter()
            .find(|row| &row.reference == reference)
            .ok_or_else(|| refused("parent Index3 is outside signed closure"))?;
        if reference.media_type != INDEX_MEDIA {
            return Err(refused("parent Index3 media differs"));
        }
        let bytes = scope
            .content
            .get(reference)
            .ok_or_else(|| refused("parent Index3 body absent"))?;
        let maximum_record = limits
            .state
            .maximum_record_bytes
            .min(limits.native.maximum_record_bytes);
        if bytes.is_empty() || bytes.len() > maximum_record {
            return Err(refused("parent Index3 exceeds record ceiling"));
        }
        admit(
            scope,
            None,
            additional,
            counter_scratch_data()
                .checked_add(core_decode_credit::scanner_storage())
                .ok_or_else(|| refused("parent Index3 scanner credit overflow"))?,
        )?;
        authenticate_borrowed_extents(bytes, limits)?;
        let maximum = maximum(scope)?;
        let credit = core_decode_credit::preflight_archive(bytes, maximum)
            .map_err(super::super::super::schema)?;
        admit(
            scope,
            None,
            additional,
            credit
                .total()
                .map_err(super::super::super::schema)?
                .checked_add(
                    NodeRuntime::capture_reference_storage(reference)
                        .map_err(super::super::super::schema)?,
                )
                .and_then(|n| n.checked_add(counter_scratch_data()))
                .ok_or_else(|| refused("parent Index3 decoder credit overflow"))?,
        )?;
        *output = Some(Self {
            reference: Some(reference.clone()),
            value: None,
            index: None,
            canonical: None,
            manifest_value: None,
            manifest_canonical: None,
            manifest: None,
            verified: false,
        });
        let attempt = output
            .as_mut()
            .ok_or_else(|| refused("parent Index3 owner absent"))?;
        attempt.value = Some(
            canonical::parse_json(bytes, maximum_record).map_err(super::super::super::schema)?,
        );
        attempt.index = Some(typed_index::decode_complete_body_data(
            attempt
                .value
                .as_ref()
                .ok_or_else(|| refused("parent Index3 DOM absent"))?,
        )?);
        attempt.canonical = Some(
            canonical::canonical_json(
                attempt
                    .value
                    .as_ref()
                    .ok_or_else(|| refused("parent Index3 DOM absent"))?,
            )
            .map_err(super::super::super::schema)?,
        );
        if attempt.canonical.as_deref() != Some(bytes) {
            return Err(refused("parent Index3 body is noncanonical"));
        }
        let index = attempt
            .index
            .as_ref()
            .ok_or_else(|| refused("parent Index3 typed owner absent"))?;
        // Inventory validation allocates independent sets and fullref clones.
        // Charge their concrete map-node and string geometry before entry.
        let inventory = inventory_validation_storage(index)?;
        admit(scope, Some(attempt), additional, inventory)?;
        storage::validate_index(index, limits)?;
        if index.owners.len() != 4 || index.artifact == *reference {
            return Err(refused(
                "parent Index3 four-owner roster or manifest differs",
            ));
        }
        for object in &index.objects {
            let outer = scope
                .archive
                .index
                .objects
                .iter()
                .find(|outer| outer.reference == object.reference)
                .ok_or_else(|| refused("parent member is outside signed closure"))?;
            if outer.dependencies != object.dependencies
                || scope.content.get(&object.reference).is_none()
            {
                return Err(refused("parent member dependency/body differs"));
            }
        }
        let journal = index
            .original_capture_journal
            .as_ref()
            .ok_or_else(|| refused("parent administrative journal absent"))?;
        // The defining Index3 dependency writer includes every indexed role and
        // manifest. Its exact role set must remain reachable from this parent.
        if !row.dependencies.contains(&index.artifact)
            || !row.dependencies.contains(journal)
            || index
                .objects
                .iter()
                .any(|object| !row.dependencies.contains(&object.reference))
        {
            return Err(refused(
                "parent Index3 does not own its full typed inventory",
            ));
        }
        let manifest_bytes = scope
            .content
            .get(&index.artifact)
            .ok_or_else(|| refused("parent manifest body absent"))?;
        if manifest_bytes.len() > maximum_record {
            return Err(refused("parent manifest exceeds record ceiling"));
        }
        admit(
            scope,
            Some(attempt),
            additional,
            counter_scratch_data()
                .checked_add(core_decode_credit::scanner_storage())
                .ok_or_else(|| refused("parent manifest scanner credit overflow"))?,
        )?;
        let credit = core_decode_credit::preflight_archive(manifest_bytes, maximum)
            .map_err(super::super::super::schema)?;
        admit(
            scope,
            Some(attempt),
            additional,
            credit
                .total()
                .map_err(super::super::super::schema)?
                .checked_add(credit.typed_containers)
                .ok_or_else(|| refused("parent manifest decoder credit overflow"))?,
        )?;
        attempt.manifest_value = Some(
            canonical::parse_json(manifest_bytes, maximum_record)
                .map_err(super::super::super::schema)?,
        );
        attempt.manifest = Some(
            serde::Deserialize::deserialize(
                attempt
                    .manifest_value
                    .as_ref()
                    .ok_or_else(|| refused("parent manifest DOM absent"))?,
            )
            .map_err(super::super::super::schema)?,
        );
        attempt.manifest_canonical = Some(
            canonical::canonical_json(
                attempt
                    .manifest_value
                    .as_ref()
                    .ok_or_else(|| refused("parent manifest DOM absent"))?,
            )
            .map_err(super::super::super::schema)?,
        );
        if attempt.manifest_canonical.as_deref() != Some(manifest_bytes) {
            return Err(refused("parent manifest body is noncanonical"));
        }
        let manifest = attempt
            .manifest
            .as_ref()
            .ok_or_else(|| refused("parent manifest absent"))?;
        // Portable validation clones sorting keys. The complete typed backing
        // conservatively bounds those independent simultaneous key owners.
        admit(
            scope,
            Some(attempt),
            additional,
            NodeRuntime::capture_manifest_storage(manifest).map_err(super::super::super::schema)?,
        )?;
        manifest.validate().map_err(super::super::super::schema)?;
        if manifest.owners.len() != index.owners.len()
            || manifest
                .owners
                .iter()
                .zip(&index.owners)
                .any(|(captured, native)| {
                    captured.capture_owner_id != native.owner
                        || captured.participant_ids != native.participants
                        || captured.state_ref.as_ref() != Some(&native.state)
                        || captured.state_schema != native.key.schema
                        || native.cut != manifest.cut
                })
        {
            return Err(refused("parent manifest/native owner scopes differ"));
        }
        admit(scope, Some(attempt), additional, counter_scratch_data())?;
        scope.validation_origin.authenticate(scope.archive)?;
        attempt.verified = true;
        Ok(())
    }

    pub(super) fn borrow_data<'borrow, 'archive>(
        &'borrow self,
        scope: &'borrow CompleteRestoredSettledArchiveValidation<'archive>,
    ) -> Result<ParentArchive17ReadScope<'borrow, 'archive>, StateError> {
        scope.validation_origin.authenticate(scope.archive)?;
        let (reference, _, _) = self.parts_data()?;
        if scope.content.get(reference) != self.canonical.as_deref()
            || !scope
                .archive
                .index
                .objects
                .iter()
                .any(|row| &row.reference == reference)
        {
            return Err(refused(
                "parent Index3 is outside this exact verified occurrence",
            ));
        }
        Ok(ParentArchive17ReadScope {
            validation: scope,
            parent: self,
        })
    }

    /// Lends the strictly read parent and exact manifest without a live grant.
    pub(super) fn parts_data(
        &self,
    ) -> Result<(&ContentRef, &storage::Index, &CaptureManifest), StateError> {
        if !self.verified {
            return Err(refused("parent Index3 decoding is incomplete"));
        }
        Ok((
            self.reference
                .as_ref()
                .ok_or_else(|| refused("parent reference absent"))?,
            self.index
                .as_ref()
                .ok_or_else(|| refused("parent Index3 absent"))?,
            self.manifest
                .as_ref()
                .ok_or_else(|| refused("parent manifest absent"))?,
        ))
    }

    /// Selects one exact stable logical node and implementation/profile family.
    pub(super) fn owner_data(
        &self,
        node: &Id,
        implementation: &Id,
        profile: &Id,
    ) -> Result<&NativeOwnerState, StateError> {
        let (_, index, _) = self.parts_data()?;
        let mut matches = index
            .owners
            .iter()
            .filter(|owner| owner.participants.as_slice() == std::slice::from_ref(node));
        let owner = matches
            .next()
            .ok_or_else(|| refused("parent logical Node owner absent"))?;
        if matches.next().is_some()
            || &owner.key.implementation != implementation
            || &owner.key.profile != profile
        {
            return Err(refused("parent logical Node or backend/profile differs"));
        }
        Ok(owner)
    }

    /// Counts actual retained products, independently of their validation stage.
    pub(super) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let mut total = 0usize;
        let mut add = |bytes: usize| {
            total = total
                .checked_add(bytes)
                .filter(|n| *n <= maximum)
                .ok_or(RuntimeError::ResourceLimit)?;
            Ok::<_, RuntimeError>(())
        };
        if let Some(reference) = &self.reference {
            add(NodeRuntime::capture_reference_storage(reference)?)?;
        }
        for value in [&self.value, &self.manifest_value].into_iter().flatten() {
            add(NodeRuntime::original_json_value_requested_storage_data(
                value, maximum,
            )?)?;
        }
        if let Some(index) = &self.index {
            add(storage::index_owned_storage(index)?)?;
        }
        for bytes in [&self.canonical, &self.manifest_canonical]
            .into_iter()
            .flatten()
        {
            add(bytes.capacity())?;
        }
        if let Some(manifest) = &self.manifest {
            add(NodeRuntime::capture_manifest_storage(manifest)?)?;
        }
        Ok(total)
    }
}

fn authenticate_borrowed_extents(
    bytes: &[u8],
    limits: NativeArchiveLimits,
) -> Result<(), StateError> {
    let mut fields = Fields::object(bytes).map_err(super::super::super::schema)?;
    fields
        .named("artifact")
        .map_err(super::super::super::schema)?;
    fields
        .named("original_capture_journal")
        .map_err(super::super::super::schema)?;
    let owners = fields
        .named("owners")
        .map_err(super::super::super::schema)?;
    let mut owners = Fields::array(owners).map_err(super::super::super::schema)?;
    let mut count = 0usize;
    while owners
        .next()
        .map_err(super::super::super::schema)?
        .is_some()
    {
        count = count
            .checked_add(1)
            .ok_or_else(|| refused("parent owner count overflow"))?;
        if count > limits.state.maximum_owners_or_domains || count > 4 {
            return Err(refused("parent owner count exceeds admission"));
        }
    }
    owners.finish().map_err(super::super::super::schema)?;
    if fields
        .named("schema_version")
        .map_err(super::super::super::schema)?
        != b"3"
    {
        return Err(refused("parent Index3 schema differs"));
    }
    let inventory = fields
        .named("typed_inventory")
        .map_err(super::super::super::schema)?;
    fields.finish().map_err(super::super::super::schema)?;
    let mut fields = Fields::object(inventory).map_err(super::super::super::schema)?;
    let objects = fields
        .named("objects")
        .map_err(super::super::super::schema)?;
    if fields
        .named("schema_version")
        .map_err(super::super::super::schema)?
        != b"2"
    {
        return Err(refused("parent inventory schema differs"));
    }
    fields.finish().map_err(super::super::super::schema)?;
    let mut pages = Fields::array(objects).map_err(super::super::super::schema)?;
    let mut count = 0usize;
    while let Some(page) = pages.next().map_err(super::super::super::schema)? {
        let mut entries = Fields::array(page).map_err(super::super::super::schema)?;
        let mut page_count = 0usize;
        while entries
            .next()
            .map_err(super::super::super::schema)?
            .is_some()
        {
            count = count
                .checked_add(1)
                .ok_or_else(|| refused("parent object count overflow"))?;
            page_count += 1;
            if count > limits.state.maximum_content_objects || page_count > 256 {
                return Err(refused("parent object count exceeds admission"));
            }
        }
        entries.finish().map_err(super::super::super::schema)?;
        if page_count == 0 {
            return Err(refused("parent Index3 has an empty inventory page"));
        }
    }
    pages.finish().map_err(super::super::super::schema)?;
    Ok(())
}

fn inventory_validation_storage(index: &storage::Index) -> Result<usize, StateError> {
    let mut bytes = index
        .objects
        .len()
        .checked_mul(
            NodeRuntime::capture_map_node_storage::<ContentRef, ()>()
                + NodeRuntime::capture_map_node_storage::<
                    crucible_node_contract::HashRef,
                    ContentRef,
                >(),
        )
        .ok_or_else(|| refused("parent inventory map layout overflow"))?;
    for object in &index.objects {
        bytes = bytes
            .checked_add(
                NodeRuntime::capture_reference_storage(&object.reference)
                    .map_err(super::super::super::schema)?
                    .checked_mul(2)
                    .ok_or_else(|| refused("parent reference clone overflow"))?,
            )
            .and_then(|n| n.checked_add(object.reference.hash.algorithm.capacity()))
            .and_then(|n| n.checked_add(object.reference.hash.domain.capacity()))
            .and_then(|n| n.checked_add(object.reference.hash.digest.capacity()))
            .ok_or_else(|| refused("parent reference map backing overflow"))?;
    }
    for owner in &index.owners {
        bytes = bytes
            .checked_add(NodeRuntime::capture_map_node_storage::<Id, ()>())
            .and_then(|n| n.checked_add(owner.owner.allocated_capacity()))
            .ok_or_else(|| refused("parent owner set backing overflow"))?;
        // These names are cloned by the defining per-owner artifact validator
        // while its outer object maps and owner set remain alive.
        for artifact in &owner.artifacts {
            bytes = bytes
                .checked_add(NodeRuntime::capture_map_node_storage::<(Id, String), ()>())
                .and_then(|n| n.checked_add(artifact.role.allocated_capacity()))
                .and_then(|n| n.checked_add(artifact.name.capacity()))
                .ok_or_else(|| refused("parent artifact-name set backing overflow"))?;
        }
    }
    Ok(bytes)
}

fn maximum(scope: &CompleteRestoredSettledArchiveValidation<'_>) -> Result<usize, StateError> {
    let limits = scope.archive_limits_data()?;
    Ok(limits
        .state
        .maximum_total_content_bytes
        .min(limits.native.maximum_total_record_bytes)
        .min(
            usize::try_from(limits.state.maximum_native_memory_bytes)
                .map_err(super::super::super::schema)?,
        ))
}

fn admit(
    scope: &CompleteRestoredSettledArchiveValidation<'_>,
    owner: Option<&ParentIndex17Attempt>,
    additional: usize,
    temporary: usize,
) -> Result<(), StateError> {
    let maximum = maximum(scope)?;
    let owned = owner
        .map(|owner| owner.retained_requested_storage_data(maximum))
        .transpose()
        .map_err(super::super::super::schema)?
        .unwrap_or(0);
    let temporary = temporary
        .checked_add(counter_scratch_data())
        .ok_or_else(|| refused("parent defining fixed scratch overflow"))?;
    let terms = [
        scope.retained_core_bytes_excluding_collection_data()?,
        scope.retained_verified_content_allocation_bytes()?,
        additional,
        owned,
        temporary,
        size_of::<Option<ParentIndex17Attempt>>(),
    ];
    terms.into_iter().try_fold(0usize, |total, next| {
        total
            .checked_add(next)
            .filter(|total| *total <= maximum)
            .ok_or_else(|| refused("parent Index3 simultaneous storage exhausted"))
    })?;
    Ok(())
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<ParentIndex17Attempt>()
        + size_of::<Result<ParentIndex17Attempt, StateError>>()
        + size_of::<[usize; 7]>()
        + size_of::<[&ContentRef; 4]>()
        + 5 * size_of::<Fields<'static>>()
        + size_of::<Result<Option<&'static [u8]>, crucible_node_provider::ProviderError>>()
        + NodeRuntime::original_json_value_counter_scratch_data()
        + crucible_node_provider::protocol_snapshot::borrowed_json::counter_scratch_data()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn framing() -> Value {
        json!({
            "artifact": {},
            "original_capture_journal": {},
            "owners": [{}, {}, {}, {}],
            "schema_version": 3,
            "typed_inventory": {"objects": [], "schema_version": 2}
        })
    }

    fn bytes(value: &Value) -> Vec<u8> {
        canonical::canonical_json(value).unwrap()
    }

    #[test]
    fn borrowed_parent_framing_refuses_another_edition_and_extra_fields() {
        let limits = NativeArchiveLimits::default();
        let value = framing();
        // This proves borrowed extent scanning only. Empty placeholder objects
        // cannot pass the actual direct Index3 or manifest/native validators.
        assert!(authenticate_borrowed_extents(&bytes(&value), limits).is_ok());

        for changed in [json!("3"), json!(2), json!(4), json!(null)] {
            let mut value = value.clone();
            value["schema_version"] = changed;
            assert!(authenticate_borrowed_extents(&bytes(&value), limits).is_err());
        }
        let mut extra = value;
        extra["unchecked"] = json!(false);
        assert!(authenticate_borrowed_extents(&bytes(&extra), limits).is_err());
    }

    #[test]
    fn borrowed_owner_and_page_extents_refuse_before_owning_parse() {
        let mut value = framing();
        let mut limits = NativeArchiveLimits::default();
        limits.state.maximum_owners_or_domains = 3;
        assert!(authenticate_borrowed_extents(&bytes(&value), limits).is_err());

        limits.state.maximum_owners_or_domains = 4;
        limits.state.maximum_content_objects = 2;
        value["typed_inventory"]["objects"] = json!([[{}, {}, {}]]);
        assert!(authenticate_borrowed_extents(&bytes(&value), limits).is_err());

        value["typed_inventory"]["objects"] = json!([[]]);
        assert!(authenticate_borrowed_extents(&bytes(&value), limits).is_err());
        value["typed_inventory"]["schema_version"] = json!("2");
        assert!(authenticate_borrowed_extents(&bytes(&value), limits).is_err());
    }
}
