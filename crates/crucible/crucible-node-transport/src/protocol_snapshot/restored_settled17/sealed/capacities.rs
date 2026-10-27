//! Observes every retained native Capture decoder bank without validating it.

use super::*;

impl RestoredSettledNative17DecodeAttempt {
    /// Observes independently retained raw, immutable and native graph backing.
    ///
    /// Historical limits and stages do not grant eligibility. The containing
    /// original Source supplies its creator guard before recording these DTOs.
    ///
    /// # Errors
    /// Refuses bounded observer exhaustion or checked allocation geometry overflow.
    pub(crate) fn observe_capacity_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            references,
            raw,
            before_encoded,
            before_native_graph,
            native_graph,
            immutable,
            aliases,
            limits,
            stage,
        } = self;
        inline_data(limits);
        inline_data(stage);

        for reference in references {
            observer.observe(reference)?;
        }
        for bytes in raw {
            observer.observe(bytes)?;
        }
        observer.observe(before_encoded)?;
        before_native_graph.observe_capacity_data(observer)?;
        native_graph.observe_capacity_data(observer)?;

        observer.vector::<(ContentRef, Vec<u8>)>(immutable.capacity())?;
        for (reference, bytes) in immutable {
            observer.observe(reference)?;
            observer.observe(bytes)?;
        }
        copied_vector_data(aliases, observer)
    }

    /// Names concrete borrowed decoder fields, cache controls and iterators.
    pub(crate) fn capacity_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<(
                &[Option<ContentRef>; 5],
                &[Vec<u8>; 5],
                &Vec<u8>,
                &NativeGraph17DecodeCache,
                &NativeGraph17DecodeCache,
                &Vec<(ContentRef, Vec<u8>)>,
                &Vec<super::super::aliases::RestoredSettledNative17AliasSummary>,
                &Option<RestoredSettledNative17Limits>,
                &DecodeStage,
            )>()
            + size_of::<std::slice::Iter<'_, Option<ContentRef>>>()
            + size_of::<&Option<ContentRef>>()
            + size_of::<std::slice::Iter<'_, Vec<u8>>>()
            + size_of::<&Vec<u8>>()
            + size_of::<std::slice::Iter<'_, (ContentRef, Vec<u8>)>>()
            + size_of::<(&ContentRef, &Vec<u8>)>()
            + size_of::<&mut MetadataObserver<'_>>()
            + size_of::<Result<(), ProviderError>>()
            + NativeGraph17DecodeCache::capacity_counter_scratch_data()
    }
}

fn inline_data<T: Copy>(_: &T) {}

fn copied_vector_data<T: Copy>(
    values: &Vec<T>,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    observer.vector::<T>(values.capacity())
}

#[cfg(test)]
#[path = "capacities/tests.rs"]
mod tests;
