//! Retains the exact directory publisher before the restoration window is issued.
//!
//! Both erased store views must match these concrete directory allocations.
//! Owning metadata and future filesystem work remain distinct observations;
//! neither an incoming publisher nor a numeric row grants publication authority.

use super::*;
use crate::node_observed_executor::{
    OriginalDirectoryPublicationConstructionData, StoredWorldActivationPublisher,
};
use crucible_engine::node_contract::RuntimeError;
use crucible_store::content_store::{DirectoryBlobBackend, DirectoryRefBackend};
use std::{
    cell::OnceCell,
    mem::{align_of, size_of},
    sync::Arc,
};

pub(in crate::node_qualification::packet_collection::complete) struct OriginalRestorationPublicationOwners
{
    publisher: RefCell<StoredWorldActivationPublisher>,
    blobs: Arc<DirectoryBlobBackend>,
    refs: Arc<DirectoryRefBackend>,
    construction: OnceCell<OriginalDirectoryPublicationConstructionData>,
    maximum: usize,
}

impl OriginalRestorationPublicationOwners {
    pub(super) fn retain(
        publisher: &mut Option<StoredWorldActivationPublisher>,
        blobs: Arc<DirectoryBlobBackend>,
        refs: Arc<DirectoryRefBackend>,
        maximum: usize,
    ) -> Result<Self, RuntimeError> {
        let incoming = publisher.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let mut counter = crate::node_qualification::RetainedMetadataCounter::new(maximum);
        incoming
            .charge_original_directory_storage_data(&blobs, &refs, &mut counter)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        Ok(Self {
            publisher: RefCell::new(publisher.take().ok_or(RuntimeError::OwnerUnavailable)?),
            blobs,
            refs,
            construction: OnceCell::new(),
            maximum,
        })
    }

    pub(super) fn retained_storage_data(&self, maximum: usize) -> Result<usize, RuntimeError> {
        let Self {
            publisher,
            blobs,
            refs,
            construction: _,
            maximum: _,
        } = self;
        let mut counter = crate::node_qualification::RetainedMetadataCounter::new(maximum);
        if counter
            .shared_header(
                Arc::as_ptr(blobs).cast(),
                size_of::<DirectoryBlobBackend>(),
                align_of::<DirectoryBlobBackend>(),
            )
            .map_err(|_| RuntimeError::ResourceLimit)?
        {
            counter
                .add(
                    blobs
                        .retained_configuration_requested_storage_data()
                        .ok_or(RuntimeError::ResourceLimit)?,
                )
                .map_err(|_| RuntimeError::ResourceLimit)?;
        }
        if counter
            .shared_header(
                Arc::as_ptr(refs).cast(),
                size_of::<DirectoryRefBackend>(),
                align_of::<DirectoryRefBackend>(),
            )
            .map_err(|_| RuntimeError::ResourceLimit)?
        {
            counter
                .add(refs.retained_configuration_requested_storage_data())
                .map_err(|_| RuntimeError::ResourceLimit)?;
        }
        publisher
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .charge_original_directory_storage_data(blobs, refs, &mut counter)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        Ok(counter.bytes())
    }

    pub(super) fn admit_original_future_data(
        &self,
        coordinator: &crucible_engine::node_admission::OriginalRestorationCoordinatorConstructionData,
        maximum: usize,
    ) -> Result<&OriginalDirectoryPublicationConstructionData, RuntimeError> {
        let publisher = self
            .publisher
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if self.construction.get().is_none() {
            let data = publisher.original_directory_publication_construction_data(
                &self.blobs,
                &self.refs,
                coordinator,
                maximum,
            )?;
            self.construction
                .set(data)
                .map_err(|_| RuntimeError::DuplicateOperation)?;
        }
        let data = self
            .construction
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        data.authenticate_original_data(&publisher, &self.blobs, &self.refs, coordinator)?;
        Ok(data)
    }

    pub(super) fn with_original_publisher_data(
        &self,
        coordinator: &crucible_engine::node_admission::OriginalRestorationCoordinatorConstructionData,
        call: impl FnOnce(&mut StoredWorldActivationPublisher) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        let mut publisher = self
            .publisher
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        self.construction
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .authenticate_original_data(&publisher, &self.blobs, &self.refs, coordinator)?;
        call(&mut publisher)
    }
}

impl OriginalRestorationPublicationOwners {
    pub(super) fn authenticate_retained_directory_views_data(&self) -> Result<(), RuntimeError> {
        self.retained_storage_data(self.maximum).map(|_| ())
    }
}

impl PacketCompleteRestorationPrebirth {
    pub(in crate::node_qualification::packet_collection::complete) fn retain_original_directory_publication_into(
        &mut self,
        publisher: &mut Option<crate::node_observed_executor::StoredWorldActivationPublisher>,
        blobs: Arc<DirectoryBlobBackend>,
        refs: Arc<DirectoryRefBackend>,
        maximum: usize,
    ) -> Result<*const (), RuntimeError> {
        if self.process != std::process::id()
            || self.thread != std::thread::current().id()
            || self.publication.is_some()
            || self.failed_runtime.is_some()
            || self.runtime.is_none()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.publication = Some(OriginalRestorationPublicationOwners::retain(
            publisher, blobs, refs, maximum,
        )?);
        // The capsule is already retained in its original Rc allocation. This
        // inline slot is never moved again or extracted by an effect API.
        Ok(self
            .publication
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .publisher
            .as_ptr()
            .cast())
    }

    pub(in crate::node_qualification::packet_collection::complete) fn original_publication_future_data(
        &self,
        scope: &crucible_engine::node_admission::OriginalRestorationConstructionScope<'_>,
        maximum: usize,
    ) -> Result<(usize, usize), RuntimeError> {
        let owner = self
            .publication
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let Some(coordinator) = scope.coordinator_construction_data() else {
            return Ok((0, 0));
        };
        let row = owner.admit_original_future_data(coordinator, maximum)?;
        Ok((
            row.requested_bytes_data()
                .checked_add(row.counter_scratch_bytes_data())
                .ok_or(RuntimeError::ResourceLimit)?,
            row.maximum_simultaneous_transient_descriptors_data(),
        ))
    }
}
