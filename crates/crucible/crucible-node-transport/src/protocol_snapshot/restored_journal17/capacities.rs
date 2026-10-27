//! Observes retained Capture ancestry and final journal DTO backing as DATA.
//!
//! Full references keep their actual String capacities even when journal media,
//! aliasing or finalization validation refuses. No journal is constructed here.

use super::*;
use crate::retained_metadata::{MetadataObserver, ObserveMetadata};

impl ObserveMetadata for PacketRestoredSettledAncestry17 {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            parent_archive_index,
            parent_manifest,
            first_semantic,
            first_journal,
            first_observation,
            restoration_commit,
            restoration_hold,
        } = self;

        observer.observe(parent_archive_index)?;
        observer.observe(parent_manifest)?;
        observer.observe(first_semantic)?;
        observer.observe(first_journal)?;
        observer.observe(first_observation)?;
        observer.observe(restoration_commit)?;
        observer.observe(restoration_hold)
    }
}

impl ObserveMetadata for PacketRestoredSettledJournal17Objects {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            snapshot,
            before,
            control,
            anchor,
            after,
            host_protocol,
            semantic,
            runtime_object,
            coordinator_checkpoint,
        } = self;

        observer.observe(snapshot)?;
        observer.observe(before)?;
        observer.observe(control)?;
        observer.observe(anchor)?;
        observer.observe(after)?;
        observer.observe(host_protocol)?;
        observer.observe(semantic)?;
        observer.observe(runtime_object)?;
        observer.observe(coordinator_checkpoint)
    }
}

impl ObserveMetadata for PacketRestoredSettledHistoryCut17 {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            prefix,
            next_sequence,
        } = self;

        observer.observe(prefix)?;
        observer.observe(next_sequence)
    }
}

/// Names actual borrowed journal fields without a constructor or validator.
pub(crate) fn capture_journal_capacity_counter_scratch_data() -> usize {
    fields_layout_data::<PacketRestoredSettledAncestry17, _>(|owner| {
        let PacketRestoredSettledAncestry17 {
            parent_archive_index,
            parent_manifest,
            first_semantic,
            first_journal,
            first_observation,
            restoration_commit,
            restoration_hold,
        } = owner;
        (
            parent_archive_index,
            parent_manifest,
            first_semantic,
            first_journal,
            first_observation,
            restoration_commit,
            restoration_hold,
        )
    }) + fields_layout_data::<PacketRestoredSettledJournal17Objects, _>(|owner| {
        let PacketRestoredSettledJournal17Objects {
            snapshot,
            before,
            control,
            anchor,
            after,
            host_protocol,
            semantic,
            runtime_object,
            coordinator_checkpoint,
        } = owner;
        (
            snapshot,
            before,
            control,
            anchor,
            after,
            host_protocol,
            semantic,
            runtime_object,
            coordinator_checkpoint,
        )
    }) + fields_layout_data::<PacketRestoredSettledHistoryCut17, _>(|owner| {
        let PacketRestoredSettledHistoryCut17 {
            prefix,
            next_sequence,
        } = owner;
        (prefix, next_sequence)
    }) + size_of::<&PacketRestoredSettledAncestry17>()
        + size_of::<&PacketRestoredSettledJournal17Objects>()
        + size_of::<&PacketRestoredSettledHistoryCut17>()
        + size_of::<&mut MetadataObserver<'_>>()
        + size_of::<Result<(), ProviderError>>()
}

fn fields_layout_data<T: 'static, R>(_: impl FnOnce(&'static T) -> R) -> usize {
    size_of::<R>()
}
