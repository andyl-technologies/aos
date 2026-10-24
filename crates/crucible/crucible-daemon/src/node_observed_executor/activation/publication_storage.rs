//! Quotes the same concrete directory publisher before any restoration Prepare.
//!
//! Existing publisher/backend owners remain in the enclosing actual census.
//! This fixed DATA row only adds the genuine future namespace owner and the
//! renderer/directory callback peak. It cannot publish or authorize a callback.

use super::*;
use crucible_engine::node_admission::OriginalRestorationCoordinatorConstructionData;
use crucible_engine::node_contract::RuntimeError;
use crucible_store::content_store::{
    DirectoryBlobBackend, DirectoryRefBackend, DirectoryRefNameConstructionData,
};
use std::mem::{size_of, size_of_val};

/// Retains fixed prospective directory publication extents for one real owner.
///
/// The row owns no heap or descriptor. Private process-local addresses bind the
/// same borrowed publisher/backend/coordinator inputs without granting rights.
/// Actual current publisher ownership is always charged independently.
pub(crate) struct OriginalDirectoryPublicationConstructionData {
    publisher: *const StoredWorldActivationPublisher,
    blobs: *const DirectoryBlobBackend,
    refs: *const DirectoryRefBackend,
    coordinator: *const OriginalRestorationCoordinatorConstructionData,
    reference: *const u8,
    reference_length: usize,
    retained: usize,
    transient: usize,
    requested: usize,
    scratch: usize,
    descriptors: usize,
}

impl OriginalDirectoryPublicationConstructionData {
    /// Returns the checked independent future owner-plus-construction sum.
    pub(crate) fn requested_bytes_data(&self) -> usize {
        self.requested
    }

    /// Returns the future retained coordinator namespace String bound.
    pub(crate) fn retained_requested_bytes_data(&self) -> usize {
        self.retained
    }

    /// Returns the complete callback/rendering work that can coexist.
    pub(crate) fn maximum_simultaneous_transient_bytes_data(&self) -> usize {
        self.transient
    }

    /// Returns separately precredited producer, I/O and result headers.
    pub(crate) fn counter_scratch_bytes_data(&self) -> usize {
        self.scratch
    }

    /// Returns additional simultaneously occupied file descriptor slots.
    pub(crate) fn maximum_simultaneous_transient_descriptors_data(&self) -> usize {
        self.descriptors
    }

    /// Returns the fixed row's own heap backing, excluding its enclosing slot.
    ///
    /// All fields are primitives or nonowning pointers; none owns an allocation.
    pub(crate) fn retained_row_requested_storage_data(&self) -> usize {
        0
    }

    /// Checks the same real publisher/backend/coordinator loans without effects.
    ///
    /// # Errors
    /// Refuses another publisher, concrete backend allocation, namespace String
    /// or coordinator row. Source/epoch currency is checked by the real Window.
    pub(crate) fn authenticate_original_data(
        &self,
        publisher: &StoredWorldActivationPublisher,
        blobs: &Arc<DirectoryBlobBackend>,
        refs: &Arc<DirectoryRefBackend>,
        coordinator: &OriginalRestorationCoordinatorConstructionData,
    ) -> Result<(), RuntimeError> {
        if !std::ptr::eq(self.publisher, publisher)
            || !std::ptr::eq(self.blobs, Arc::as_ptr(blobs))
            || !std::ptr::eq(self.refs, Arc::as_ptr(refs))
            || !std::ptr::eq(self.coordinator, coordinator)
            || self.reference != publisher.reference.as_str().as_ptr()
            || self.reference_length != publisher.reference.as_str().len()
            || !std::ptr::addr_eq(Arc::as_ptr(&publisher.blobs), Arc::as_ptr(blobs))
            || !std::ptr::addr_eq(Arc::as_ptr(&publisher.refs), Arc::as_ptr(refs))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }
}

fn checked_sum(rows: &[usize], maximum: usize) -> Result<usize, RuntimeError> {
    rows.iter().try_fold(0usize, |sum, row| {
        sum.checked_add(*row)
            .filter(|n| *n <= maximum)
            .ok_or(RuntimeError::ResourceLimit)
    })
}

fn grown_string_bytes(length: usize) -> Result<usize, RuntimeError> {
    length
        .checked_mul(4)
        .and_then(|n| n.checked_add(256))
        .ok_or(RuntimeError::ResourceLimit)
}

impl StoredWorldActivationPublisher {
    /// Quotes real directory publication work from the same prospective codec.
    ///
    /// All original owners remain independently retained/counted by the holder.
    /// The producer does not call erased backend methods, read paths or create
    /// a publisher/preparation/namespace token. Ordinary old APIs are unchanged.
    ///
    /// # Errors
    /// Refuses foreign backend aliases, unsupported destructive environment
    /// instrumentation, another namespace, overflow or a full conjunction above
    /// `maximum`. The caller obtains this row before native Prepare or Arm.
    pub(crate) fn original_directory_publication_construction_data(
        &self,
        blobs: &Arc<DirectoryBlobBackend>,
        refs: &Arc<DirectoryRefBackend>,
        coordinator: &OriginalRestorationCoordinatorConstructionData,
        maximum: usize,
    ) -> Result<OriginalDirectoryPublicationConstructionData, RuntimeError> {
        if !std::ptr::addr_eq(Arc::as_ptr(&self.blobs), Arc::as_ptr(blobs))
            || !std::ptr::addr_eq(Arc::as_ptr(&self.refs), Arc::as_ptr(refs))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let suffix = self
            .reference
            .as_str()
            .strip_prefix("node-world-activations/")
            .filter(|suffix| !suffix.is_empty())
            .ok_or(RuntimeError::InvalidReceipt)?;
        let future_reference_length = "node-world-coordinators/"
            .len()
            .checked_add(suffix.len())
            .ok_or(RuntimeError::ResourceLimit)?;
        let names = [
            DirectoryRefNameConstructionData::original(&self.reference),
            DirectoryRefNameConstructionData::replace_namespace(
                &self.reference,
                "node-world-activations/",
                "node-world-coordinators/",
            )
            .map_err(|_| RuntimeError::InvalidReceipt)?,
        ];
        let directory = blobs
            .original_two_object_publication_construction_data(
                refs,
                names,
                [
                    coordinator.maximum_encoded_bytes_data(),
                    coordinator.maximum_stored_publication_encoded_bytes_data(),
                ],
                [
                    crucible_engine::node_contract::MAXIMUM_ACTIVATION_COORDINATOR_BYTES,
                    super::complete::MAXIMUM_PREPARATION_RECORD_BYTES,
                ],
                maximum,
            )
            .map_err(|error| match error {
                StoreError::Unsupported { .. } => RuntimeError::UnsupportedFacet,
                _ => RuntimeError::ResourceLimit,
            })?;
        let retained = grown_string_bytes(future_reference_length)?;
        // retain_coordinator's nodes validation drops before storing/publishing.
        // During final reconcile, the caller's first complete_bytes bank remains
        // live beside another real renderer plus its bounded directory readback.
        // Price both banks; only callback-local directory work is phase-maxed.
        let transient = checked_sum(
            &[
                coordinator.stored_publication_requested_bytes_data(),
                grown_string_bytes(coordinator.maximum_stored_publication_encoded_bytes_data())?,
                grown_string_bytes(future_reference_length)?, // independent reconcile name.
                directory.requested_bytes_data(),
            ],
            maximum,
        )?;
        let scratch = checked_sum(
            &[
                Self::original_directory_publication_counter_scratch_data()?,
                coordinator.stored_publication_counter_scratch_data(),
            ],
            maximum,
        )?;
        let requested = checked_sum(&[retained, transient], maximum)?;
        checked_sum(&[requested, scratch], maximum)?;
        Ok(OriginalDirectoryPublicationConstructionData {
            publisher: self,
            blobs: Arc::as_ptr(blobs),
            refs: Arc::as_ptr(refs),
            coordinator,
            reference: self.reference.as_str().as_ptr(),
            reference_length: self.reference.as_str().len(),
            retained,
            transient,
            requested,
            scratch,
            descriptors: directory.maximum_simultaneous_transient_descriptors_data(),
        })
    }

    /// Names concrete producer and defining directory callback scratch.
    ///
    /// # Errors
    /// Refuses checked arithmetic overflow. No path, environment or backend read
    /// occurs; the holder precredits this before even requesting a future row.
    pub(crate) fn original_directory_publication_counter_scratch_data()
    -> Result<usize, RuntimeError> {
        let rows = [
            size_of::<OriginalDirectoryPublicationConstructionData>(),
            size_of::<Result<OriginalDirectoryPublicationConstructionData, RuntimeError>>(),
            size_of::<Result<(), RuntimeError>>(),
            size_of::<Result<usize, RuntimeError>>(),
            size_of::<[DirectoryRefNameConstructionData<'_>; 2]>(),
            size_of::<Result<DirectoryRefNameConstructionData<'_>, StoreError>>(),
            size_of::<crucible_store::content_store::DirectoryPublicationConstructionStorageData>(),
            size_of::<
                Result<
                    crucible_store::content_store::DirectoryPublicationConstructionStorageData,
                    StoreError,
                >,
            >(),
            size_of::<[usize; 4]>(),
            size_of::<std::slice::Iter<'_, usize>>(),
            size_of::<&str>(),
            size_of::<Option<&str>>(),
            DirectoryBlobBackend::original_two_object_publication_counter_scratch_data()
                .map_err(|_| RuntimeError::ResourceLimit)?,
        ];
        let header = size_of_val(&rows)
            .checked_add(size_of::<std::slice::Iter<'_, usize>>())
            .ok_or(RuntimeError::ResourceLimit)?;
        rows.iter().try_fold(header, |sum, row| {
            sum.checked_add(*row).ok_or(RuntimeError::ResourceLimit)
        })
    }
}
