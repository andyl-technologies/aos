//! Observes real lazy native decoder slots, including spares and failed children.

use super::*;
use crate::retained_metadata::MetadataObserver;

impl NativeGraph17DecodeCache {
    pub(in crate::protocol_snapshot::restored_settled17) fn observe_capacity_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self { slots, started } = self;
        inline_data(started);

        observer.vector::<Option<NativeCurrentGraph17DecodeAttempt>>(slots.capacity())?;
        for child in slots.iter().flatten() {
            child.observe_capacity_data(observer)?;
        }
        Ok(())
    }

    pub(in crate::protocol_snapshot::restored_settled17) fn capacity_counter_scratch_data() -> usize
    {
        size_of::<&Self>()
            + size_of::<(&Vec<Option<NativeCurrentGraph17DecodeAttempt>>, &bool)>()
            + size_of::<std::slice::Iter<'_, Option<NativeCurrentGraph17DecodeAttempt>>>()
            + size_of::<
                std::iter::Flatten<std::slice::Iter<'_, Option<NativeCurrentGraph17DecodeAttempt>>>,
            >()
            + size_of::<&NativeCurrentGraph17DecodeAttempt>()
            + size_of::<&mut MetadataObserver<'_>>()
            + size_of::<Result<(), ProviderError>>()
            + NativeCurrentGraph17DecodeAttempt::capacity_counter_scratch_data()
    }
}

fn inline_data<T: Copy>(_: &T) {}

#[cfg(test)]
#[path = "capacities/tests.rs"]
mod tests;
