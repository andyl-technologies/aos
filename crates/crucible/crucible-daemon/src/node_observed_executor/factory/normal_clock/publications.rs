//! Retains the genuine durable publishers beneath the same actual quota.
//!
//! No caller supplies a publisher callback or an alleged publication status to
//! the bounded route. The same real directory blob/ref stores own every initial
//! coordinator and write-once activation record; native archive objects remain
//! in their separately pinned sibling under that same ext4 project.

use super::*;
use crate::node_observed_executor::StoredWorldActivationPublisher;
use crucible_store::content_store::{
    DirectoryBlobBackend, DirectoryRefBackend, RefName, StoreError,
};
use std::sync::Arc;

pub(super) struct ClockPublications {
    blobs: Arc<DirectoryBlobBackend>,
    refs: Arc<DirectoryRefBackend>,
    pub(super) original: StoredWorldActivationPublisher,
    pub(super) left: StoredWorldActivationPublisher,
    pub(super) right: StoredWorldActivationPublisher,
    pub(super) adverse: StoredWorldActivationPublisher,
}

impl ClockPublications {
    pub(super) fn new(
        aggregate: &OriginalClockAggregateResources,
    ) -> Result<Self, NodeObservedError> {
        let root = aggregate
            .publication_path_data()
            .map_err(super::super::native)?;
        // These concrete constructors retain configuration only. Filesystem
        // writes start later, after this whole owner has entered the programme.
        let blobs = Arc::new(DirectoryBlobBackend::new(
            "original-normal-clock",
            root.join("blobs"),
        ));
        let refs = Arc::new(DirectoryRefBackend::new(root.join("refs")));
        let publisher = |name: &str| -> Result<StoredWorldActivationPublisher, StoreError> {
            StoredWorldActivationPublisher::new(blobs.clone(), refs.clone(), RefName::new(name)?)
        };
        Ok(Self {
            original: publisher("node-world-activations/normal-clock-original")?,
            left: publisher("node-world-activations/normal-clock-left")?,
            right: publisher("node-world-activations/normal-clock-right")?,
            adverse: publisher("node-world-activations/normal-clock-adverse")?,
            blobs,
            refs,
        })
    }
}

impl crate::node_qualification::RetainedMetadataOwned for ClockPublications {
    fn charge(
        &self,
        counter: &mut crate::node_qualification::RetainedMetadataCounter,
    ) -> Result<(), QualificationError> {
        use std::mem::{align_of, size_of};
        let Self {
            blobs,
            refs,
            original,
            left,
            right,
            adverse,
        } = self;
        // These are the concrete allocations retained by all four erased views.
        if counter.shared_header(
            Arc::as_ptr(blobs).cast(),
            size_of::<DirectoryBlobBackend>(),
            align_of::<DirectoryBlobBackend>(),
        )? {
            counter.add(
                blobs
                    .retained_configuration_requested_storage_data()
                    .ok_or(QualificationError::Refused(
                        "Clock blob configuration capacity overflow",
                    ))?,
            )?;
        }
        if counter.shared_header(
            Arc::as_ptr(refs).cast(),
            size_of::<DirectoryRefBackend>(),
            align_of::<DirectoryRefBackend>(),
        )? {
            counter.add(refs.retained_configuration_requested_storage_data())?;
        }
        for publisher in [original, left, right, adverse] {
            publisher.charge_original_directory_storage_data(blobs, refs, counter)?;
        }
        Ok(())
    }
}
