//! Retains the three genuine durable publishers beneath the same actual quota.
//!
//! No caller supplies a publisher callback or an alleged publication status to
//! the bounded route. The same real directory blob/ref stores own every initial
//! coordinator and write-once activation record; native archive objects remain
//! in their separately pinned sibling under that same ext4 project.

use super::*;
use crate::node_observed_executor::StoredWorldActivationPublisher;
use crucible_cas::content_store::{
    DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend, MutableRefBackend, RefName,
    StoreError,
};
use std::sync::Arc;

pub(super) struct ClockPublications {
    pub(super) original: StoredWorldActivationPublisher,
    pub(super) left: StoredWorldActivationPublisher,
    pub(super) right: StoredWorldActivationPublisher,
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
        let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
            "original-normal-clock",
            root.join("blobs"),
        ));
        let refs: Arc<dyn MutableRefBackend> =
            Arc::new(DirectoryRefBackend::new(root.join("refs")));
        let publisher = |name: &str| -> Result<StoredWorldActivationPublisher, StoreError> {
            StoredWorldActivationPublisher::new(
                Arc::clone(&blobs),
                Arc::clone(&refs),
                RefName::new(name)?,
            )
        };
        Ok(Self {
            original: publisher("node-world-activations/normal-clock-original")?,
            left: publisher("node-world-activations/normal-clock-left")?,
            right: publisher("node-world-activations/normal-clock-right")?,
        })
    }
}
