//! Bounds the future upload before its historical mapping is constructed.
//!
//! This numeric DATA closes an allocation-order dependency; it is not a mapping
//! identity or restoration capability. The installed window authenticates the
//! original ticket/body extents and its fixed mapping bank independently. After
//! constructing the actual mapping, it must obtain the identity-bearing quote
//! and compare every axis before creating or publishing a Prepare request.

use super::*;

/// Bounds the same six-role upload before any mapping owner is allocated.
///
/// This copyable row contains no authority, query owner, mapping or receipt.
/// The installed window retains its original same-query/target associations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginalCompleteRestoreUploadBeforeMappingData {
    input_lengths: [usize; 5],
    mapping_bytes: usize,
    retained: usize,
    transient: usize,
    scratch: usize,
}

impl OriginalCompleteRestoreUploadBeforeMappingData {
    /// Returns future uploader ownership, excluding Prepare and mapping owners.
    pub fn retained_growth_bytes(&self) -> usize {
        self.retained
    }

    /// Returns complete simultaneous future upload protocol work.
    pub fn maximum_simultaneous_transient_bytes(&self) -> usize {
        self.transient
    }

    /// Returns explicit quote and prospective association view headers.
    pub fn declared_counter_scratch_bytes(&self) -> usize {
        self.scratch
    }

    /// Checks all later identity-bearing upload axes beneath this earlier row.
    ///
    /// The actual quote independently authenticates the same Query, controller,
    /// emitter, planned Prepare and real mapping. This numeric comparison cannot
    /// replace those checks or grant effects from a matching scalar.
    ///
    /// # Errors
    /// Refuses a journal-bound intermediate quote, changed body role lengths,
    /// excessive mapping extent or any later storage axis above this row.
    pub fn authenticate_actual_quote_data(
        &self,
        actual: &OriginalCompleteRestoreInputUploadProspectiveStorageData,
        references: [&ContentRef; 5],
    ) -> Result<(), ProviderError> {
        if actual.bounded_input_bytes.is_some()
            || references
                .into_iter()
                .zip(self.input_lengths)
                .any(|(reference, length)| usize::try_from(reference.length.get()) != Ok(length))
            || actual.mapping_bytes > self.mapping_bytes
            || actual.retained > self.retained
            || actual.transient > self.transient
            || actual.scratch > self.scratch
        {
            return Err(credit());
        }
        Ok(())
    }
}

impl CnpController {
    /// Names exact fixed views before quoting an upload without a mapping.
    ///
    /// Includes the actual future mapping-normalization tuple and serializer
    /// layouts without constructing a mapping or encoding any archive bytes.
    pub fn original_complete_restore_upload_before_mapping_counter_scratch_data(&self) -> usize {
        PreparedArchivedProtocolMapping::original_normalization_counter_scratch_data(
            self.authority(),
        ) + storage::counter_scratch_data()
            + size_of::<OriginalCompleteRestoreUploadBeforeMappingData>()
            + size_of::<OriginalCompleteRestoreInputUploadProspectiveStorageData>()
            + size_of::<[inputs::Reference<'static>; 6]>()
            + size_of::<[Result<inputs::Reference<'static>, ProviderError>; 5]>()
            + size_of::<[usize; 5]>()
            + size_of::<std::array::IntoIter<usize, 5>>()
            + size_of::<[blake3::Hash; 5]>()
            + size_of::<[&ContentRef; 5]>()
            + size_of::<[&str; 4]>()
            + size_of::<[u8; 32]>()
            + 2 * size_of::<blake3::Hasher>()
            + 2 * size_of::<blake3::Hash>()
            + size_of::<(usize, usize)>()
            + size_of::<std::fmt::Arguments<'static>>()
    }

    /// Quotes six-role publication before constructing a historical mapping.
    ///
    /// The five lengths come from the actual verified ticket's retained role
    /// DATA, and the mapping maximum from the same Source's fixed bank geometry.
    /// Neither caller-provided value supplies authority. Full reference grammar
    /// is conservatively bounded while preserving each exact role length.
    ///
    /// # Errors
    /// Refuses an incomplete/foreign Query, another selected mechanism, occupied
    /// transaction/ID, unsupported role/mapping bounds, overflow or demand above
    /// actual protocol limits or the independent installed byte ceiling.
    pub fn quote_original_complete_restore_upload_before_mapping_data(
        &self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        query: &OriginalFreshRestoreQuery,
        planned_prepare: &Id,
        input_lengths: [usize; 5],
        maximum_mapping_bytes: usize,
        maximum: usize,
    ) -> Result<OriginalCompleteRestoreUploadBeforeMappingData, ProviderError> {
        query.authenticate_current(self, emitter)?;
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
        let roles = input_lengths.map(inputs::Reference::archive_bound);
        let [native, control, anchor, owner, journal] = roles;
        let references = [
            native?,
            control?,
            anchor?,
            owner?,
            journal?,
            inputs::Reference::mapping(maximum_mapping_bytes)?,
        ];
        let parts = storage::quote_references(
            self,
            &references,
            request_identity(planned_prepare),
            1,
            maximum,
        )?;
        let scratch = self.original_complete_restore_upload_before_mapping_counter_scratch_data();
        if parts
            .retained
            .checked_add(parts.transient)
            .and_then(|total| total.checked_add(scratch))
            .filter(|total| *total <= maximum)
            .is_none()
        {
            return Err(credit());
        }
        Ok(OriginalCompleteRestoreUploadBeforeMappingData {
            input_lengths,
            mapping_bytes: maximum_mapping_bytes,
            retained: parts.retained,
            transient: parts.transient,
            scratch,
        })
    }
}
