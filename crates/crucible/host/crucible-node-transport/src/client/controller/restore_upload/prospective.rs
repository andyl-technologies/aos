//! Counts the same six-role upload before Prepare constructs or publishes owners.
//!
//! This quote is DATA tied to the actual completed query and fresh controller.
//! It is not an installed allocation action or a receipt verifier. The Source
//! keeps the genuine earlier window while checking the later receipt-gated row.

use super::*;
use crate::protocol_snapshot::PreparedArchivedProtocolMapping;
use crate::reference_packet::service::fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection;
use std::mem::size_of;

/// Retains a prospective upload bound on one actual query/controller frontier.
///
/// No public constructor, clone, decoder or portable permission exists. The
/// mapping reference does not exist yet: its exact borrowed normalization is
/// counted, and the future digest uses the fixed full-reference grammar.
pub struct OriginalCompleteRestoreInputUploadProspectiveStorageData {
    controller: Weak<ProtocolCaptureOwner>,
    frontier: OriginalProtocolStorageFacts,
    query_sequence: U64,
    query_id: blake3::Hash,
    prepare_id: blake3::Hash,
    references: [blake3::Hash; 5],
    mapping: blake3::Hash,
    mapping_owner: Rc<crate::protocol_snapshot::ArchivedProtocolMappingIdentity>,
    mapping_bytes: usize,
    bounded_input_bytes: Option<usize>,
    retained: usize,
    transient: usize,
    scratch: usize,
}

impl OriginalCompleteRestoreInputUploadProspectiveStorageData {
    /// Returns future uploader owners, excluding the independently priced Prepare.
    pub fn retained_growth_bytes(&self) -> usize {
        self.retained
    }

    /// Returns complete future upload protocol work while those owners coexist.
    pub fn maximum_simultaneous_transient_bytes(&self) -> usize {
        self.transient
    }

    /// Returns the actual fixed headers needed before the prospective walk.
    pub fn declared_counter_scratch_bytes(&self) -> usize {
        self.scratch
    }

    /// Reports the actual retained actor and mapping association backing.
    ///
    /// The enclosing root is counted separately. Shared backing is charged
    /// conservatively even when the original mapping has another live alias.
    ///
    /// # Errors
    /// Refuses an expired/foreign actor or incomplete metadata traversal.
    pub fn original_retained_metadata_facts(
        &self,
    ) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        let owner = self.controller.upgrade().ok_or_else(refused)?;
        owner.ensure_current()?;
        let mut observer = MetadataObserver::new();
        observer.shared_value(owner.as_ref())?;
        observer.shared_value(self.mapping_owner.as_ref())?;
        Ok(observer.finish())
    }

    /// Authenticates the exact pre-Prepare source inputs without allocating them.
    ///
    /// # Errors
    /// Refuses a changed query/frontier/controller/mapping, planned ID or full
    /// reference. This check supplies no Source MAC or allocation permission.
    pub fn authenticate_original_inputs_data(
        &self,
        controller: &CnpController,
        emitter: &OriginalCanonicalBlobAckEmitter,
        query: &OriginalFreshRestoreQuery,
        planned_prepare: &Id,
        references: [&ContentRef; 5],
        mapping: &PreparedArchivedProtocolMapping,
    ) -> Result<(), ProviderError> {
        query.authenticate_current(controller, emitter)?;
        controller.authenticate_archived_protocol_transfer_mapping(mapping)?;
        mapping.authenticate_identity(&self.mapping_owner)?;
        let owner = self.controller.upgrade().ok_or_else(refused)?;
        let original = query.original_data().ok_or_else(refused)?;
        if self.bounded_input_bytes.is_some()
            || !Rc::ptr_eq(&owner, &controller.protocol_owner)
            || self.frontier != controller.original_native5_storage_facts()?
            || self.query_sequence != original.sequence
            || self.query_id
                != request_identity(original.request_id.0.as_ref().ok_or_else(refused)?)
            || self.prepare_id != request_identity(planned_prepare)
            || self.references != reference_identities(references)
            || self.mapping != mapping_identity(mapping)
        {
            return Err(refused());
        }
        Ok(())
    }

    /// Checks a real completed-Prepare requote against this earlier funded row.
    ///
    /// The Source independently verifies the native receipt MAC first. No new
    /// allocation budget is issued here, and no uploader owner is constructed.
    ///
    /// # Errors
    /// Refuses another actor, Prepare ID, body role, mapping extent or any
    /// actual added demand beyond the original prospective three-axis bound.
    /// Source separately verifies that the selected signed Prepare was built
    /// from the same original query and native ticket before trusting this row.
    pub fn authenticate_actual_upload_data(
        &self,
        controller: &CnpController,
        emitter: &OriginalCanonicalRestoreInputEmitter,
        actual: &OriginalCompleteRestoreInputUploadStorageData,
        bodies: [&[u8]; 6],
    ) -> Result<(), ProviderError> {
        actual.authenticate(controller, emitter, &bodies)?;
        let owner = self.controller.upgrade().ok_or_else(refused)?;
        let inputs = PrepareInputs::borrow(controller, emitter)?;
        let state = controller
            .original_complete_restore_prepare
            .as_ref()
            .ok_or_else(refused)?;
        if !Rc::ptr_eq(&self.mapping_owner, &state.mapping_identity) {
            return Err(refused());
        }
        // Only the real selected constructor installs this binding. The old
        // phase-only Prepare cannot satisfy a quote tied to a completed Query.
        if !inputs.original.extensions.contains_key(
            crate::reference_packet::service::fresh_restore_allocation::PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING
        ) { return Err(refused()); }
        if !Rc::ptr_eq(&owner, &controller.protocol_owner)
            || actual.prepare_id != self.prepare_id
            || actual.retained > self.retained
            || actual.transient > self.transient
            || actual.scratch > self.scratch
            || bodies[5].len() > self.mapping_bytes
        {
            return Err(credit());
        }
        if let Some(maximum) = self.bounded_input_bytes {
            if inputs.references[..5].iter().any(|r| r.length > maximum) {
                return Err(credit());
            }
        } else {
            for (reference, original) in inputs.references[..5].iter().zip(&self.references) {
                if reference.identity() != *original {
                    return Err(refused());
                }
            }
        }
        Ok(())
    }
}

impl CnpController {
    /// Names fixed counters before observing any prospective publication inputs.
    pub fn original_complete_restore_input_upload_prospective_counter_scratch_data(
        mapping: &PreparedArchivedProtocolMapping,
    ) -> usize {
        mapping.normalization_counter_scratch_data()
            + storage::counter_scratch_data()
            + size_of::<OriginalCompleteRestoreInputUploadProspectiveStorageData>()
            + size_of::<[inputs::Reference<'static>; 6]>()
            + size_of::<[blake3::Hash; 5]>() + size_of::<[&ContentRef; 5]>()
            + size_of::<[&str; 4]>() + size_of::<[u8; 32]>()
            + 2 * size_of::<blake3::Hasher>() + 2 * size_of::<blake3::Hash>()
            // serialized_credit owns only these exact Counter fields. The
            // borrowed mapping normalization has no Bytes/base64 formatter.
            + size_of::<(usize, usize)>() + size_of::<std::fmt::Arguments<'static>>()
    }

    /// Quotes exact future upload inputs before Prepare assigns or sends frames.
    ///
    /// Role order is native protocol, control, anchor, owner state, journal;
    /// the sixth input is this same mapping's future canonical normalization.
    /// The genuine installed restoration action must fund these DATA terms and
    /// the distinct Source/SDK/native Prepare and Commit work before effects.
    ///
    /// # Errors
    /// Refuses an incomplete/foreign query, absent selected mechanism, changed
    /// mapping, an occupied phase/ID, unsupported references or original limits.
    pub fn quote_original_complete_restore_input_upload_prospective_storage_data(
        &self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        query: &OriginalFreshRestoreQuery,
        planned_prepare: &Id,
        references: [&ContentRef; 5],
        mapping: &PreparedArchivedProtocolMapping,
        maximum: usize,
    ) -> Result<OriginalCompleteRestoreInputUploadProspectiveStorageData, ProviderError> {
        query.authenticate_current(self, emitter)?;
        self.authenticate_archived_protocol_transfer_mapping(mapping)?;
        if self.original_native5_complete_restore_selection()?
            != Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
            || self.original_native5_fresh_restore_allocation_selection()?
                != Some(PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13)
            || self.original_complete_restore.is_some()
            || self.original_complete_restore_prepare.is_some()
            || self.original_complete_restore_commit.is_some()
            || self.original(planned_prepare).is_some()
        {
            return Err(refused());
        }
        let mapping_bytes = mapping_extent_data(mapping)?;
        let borrowed = [
            inputs::Reference::typed(references[0])?,
            inputs::Reference::typed(references[1])?,
            inputs::Reference::typed(references[2])?,
            inputs::Reference::typed(references[3])?,
            inputs::Reference::typed(references[4])?,
            inputs::Reference::mapping(mapping_bytes)?,
        ];
        // Account for the real intervening Prepare request/reply cache and
        // literal frontier. Its DTO/assignment owners are separate action rows.
        let parts = storage::quote_references(
            self,
            &borrowed,
            request_identity(planned_prepare),
            1,
            maximum,
        )?;
        let scratch =
            Self::original_complete_restore_input_upload_prospective_counter_scratch_data(mapping);
        if parts
            .retained
            .checked_add(parts.transient)
            .and_then(|n| n.checked_add(scratch))
            .filter(|n| *n <= maximum)
            .is_none()
        {
            return Err(credit());
        }
        let original = query.original_data().ok_or_else(refused)?;
        let result = OriginalCompleteRestoreInputUploadProspectiveStorageData {
            controller: Rc::downgrade(&self.protocol_owner),
            frontier: self.original_native5_storage_facts()?,
            query_sequence: original.sequence,
            query_id: request_identity(original.request_id.0.as_ref().ok_or_else(refused)?),
            prepare_id: request_identity(planned_prepare),
            references: reference_identities(references),
            mapping: mapping_identity(mapping),
            mapping_owner: mapping.retain_identity(),
            mapping_bytes,
            bounded_input_bytes: None,
            retained: parts.retained,
            transient: parts.transient,
            scratch,
        };
        result.authenticate_original_inputs_data(
            self,
            emitter,
            query,
            planned_prepare,
            references,
            mapping,
        )?;
        Ok(result)
    }
    /// Quotes the closed upload before decoding the retained signed journal.
    ///
    /// `maximum_input_bytes` is DATA, not authority: the Core issuer derives it
    /// from the genuine native ticket's entire verified content byte extent.
    /// It conservatively applies that real extent independently to each of five
    /// archive roles, including the maximum closed media-type grammar. Source
    /// must authenticate all actual references against that same ticket later.
    /// The mapping extent comes from the same borrowed normalization, not an
    /// encoded bank or a guessed future allocation allowance.
    ///
    /// # Errors
    /// Refuses foreign/incomplete query or mapping, occupied phases/ID, an empty
    /// content extent or future owners/history above actual finite limits.
    pub fn quote_original_complete_restore_input_upload_before_journal_data(
        &self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        query: &OriginalFreshRestoreQuery,
        planned_prepare: &Id,
        mapping: &PreparedArchivedProtocolMapping,
        maximum_input_bytes: usize,
        maximum: usize,
    ) -> Result<OriginalCompleteRestoreInputUploadProspectiveStorageData, ProviderError> {
        query.authenticate_current(self, emitter)?;
        self.authenticate_archived_protocol_transfer_mapping(mapping)?;
        if self.original_native5_complete_restore_selection()?
            != Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
            || self.original_native5_fresh_restore_allocation_selection()?
                != Some(PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13)
            || self.original_complete_restore.is_some()
            || self.original_complete_restore_prepare.is_some()
            || self.original_complete_restore_commit.is_some()
            || self.original(planned_prepare).is_some()
        {
            return Err(refused());
        }
        let mapping_bytes = mapping_extent_data(mapping)?;
        let archive = inputs::Reference::archive_bound(maximum_input_bytes)?;
        let borrowed = [
            archive,
            archive,
            archive,
            archive,
            archive,
            inputs::Reference::mapping(mapping_bytes)?,
        ];
        let parts = storage::quote_references(
            self,
            &borrowed,
            request_identity(planned_prepare),
            1,
            maximum,
        )?;
        let scratch =
            Self::original_complete_restore_input_upload_prospective_counter_scratch_data(mapping);
        if parts
            .retained
            .checked_add(parts.transient)
            .and_then(|n| n.checked_add(scratch))
            .filter(|n| *n <= maximum)
            .is_none()
        {
            return Err(credit());
        }
        let original = query.original_data().ok_or_else(refused)?;
        Ok(OriginalCompleteRestoreInputUploadProspectiveStorageData {
            controller: Rc::downgrade(&self.protocol_owner),
            frontier: self.original_native5_storage_facts()?,
            query_sequence: original.sequence,
            query_id: request_identity(original.request_id.0.as_ref().ok_or_else(refused)?),
            prepare_id: request_identity(planned_prepare),
            references: [blake3::hash(&[]); 5],
            mapping: mapping_identity(mapping),
            mapping_owner: mapping.retain_identity(),
            mapping_bytes,
            bounded_input_bytes: Some(maximum_input_bytes),
            retained: parts.retained,
            transient: parts.transient,
            scratch,
        })
    }
}

fn request_identity(id: &Id) -> blake3::Hash {
    blake3::hash(id.as_str().as_bytes())
}

fn reference_identities(references: [&ContentRef; 5]) -> [blake3::Hash; 5] {
    references.map(inputs::reference_identity)
}

fn mapping_identity(mapping: &PreparedArchivedProtocolMapping) -> blake3::Hash {
    let mut hash = blake3::Hasher::new();
    for reference in [mapping.archive_protocol(), mapping.native_protocol()] {
        hash.update(inputs::reference_identity(reference).as_bytes());
    }
    hash.update(mapping.nonce());
    hash.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retained_metadata::serialization_storage::OriginalSerializationStorageProjection;

    fn reference(length: u64, media: &str) -> ContentRef {
        ContentRef {
            hash: crucible_node_format::HashRef {
                algorithm: "blake3-256".into(),
                domain: "cnp.blob.v1".into(),
                digest: "a".repeat(64),
            },
            length: U64::new(length),
            media_type: media.into(),
        }
    }

    #[test]
    fn archive_bound_covers_exact_and_smaller_role_geometry() {
        let original = reference(65_536, &"\"".repeat(128));
        let typed = inputs::Reference::typed(&original).unwrap();
        let bound = inputs::Reference::archive_bound(65_536).unwrap();
        let mut actual = OriginalSerializationStorageProjection::new(usize::MAX).unwrap();
        typed.project(&mut actual).unwrap();
        let actual = actual.finish(usize::MAX).unwrap();
        let mut future = OriginalSerializationStorageProjection::new(usize::MAX).unwrap();
        bound.project(&mut future).unwrap();
        let future = future.finish(usize::MAX).unwrap();
        assert!(actual.maximum_encoded_bytes <= future.maximum_encoded_bytes);
        assert!(actual.requested_total().unwrap() <= future.requested_total().unwrap());
        let smaller = reference(1, "x");
        assert!(
            inputs::Reference::typed(&smaller)
                .unwrap()
                .cloned_reference_storage_data()
                .unwrap()
                <= bound.cloned_reference_storage_data().unwrap()
        );
    }

    #[test]
    fn full_reference_identity_preserves_media_and_role_order() {
        let first = reference(7, "application/json");
        let second = reference(7, "text/plain");
        let original = reference_identities([&first, &first, &second, &first, &second]);
        assert_ne!(
            original,
            reference_identities([&second, &first, &first, &first, &second])
        );
        assert_eq!(
            inputs::Reference::typed(&first).unwrap().identity(),
            original[0]
        );
        assert_ne!(original[0], original[2]);
    }

    #[test]
    fn mapping_extent_is_nonempty_bounded_and_never_creates_a_reference() {
        assert!(inputs::Reference::mapping(0).is_err());
        assert!(inputs::Reference::mapping(65_537).is_err());
        let exact = inputs::Reference::mapping(65_536).unwrap();
        assert_eq!(exact.length, 65_536);
        assert!(exact.cloned_reference_storage_data().unwrap() > 0);
        assert!(inputs::Reference::archive_bound(0).is_err());
    }
}

fn mapping_extent_data(mapping: &PreparedArchivedProtocolMapping) -> Result<usize, ProviderError> {
    let mut projection = crate::retained_metadata::serialization_storage::OriginalSerializationStorageProjection::new(usize::MAX)?;
    projection.add_value(&mapping.normalization_view())?;
    let bytes = projection.finish(usize::MAX)?.maximum_encoded_bytes;
    if bytes == 0 || bytes > 64 * 1024 {
        return Err(credit());
    }
    Ok(bytes)
}

#[path = "prospective/before_mapping.rs"]
mod before_mapping;
pub use before_mapping::OriginalCompleteRestoreUploadBeforeMappingData;
