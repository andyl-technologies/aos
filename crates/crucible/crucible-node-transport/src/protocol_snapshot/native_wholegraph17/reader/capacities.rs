//! Observes actual native graph decoder backing without validating the graph.
//!
//! Failed readers and promotion slots keep independent allocations. Historical
//! creator labels and decoder stages remain DATA, including in completed DTOs.

use super::*;
use crate::retained_metadata::aliases::MetadataSharedKind;

impl NativeCurrentGraph17DecodeAttempt {
    /// Observes actual partial, promoted and completed graph allocations as DATA.
    ///
    /// # Errors
    /// Refuses checked allocation geometry overflow or bounded observer exhaustion.
    pub(crate) fn observe_capacity_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            started,
            failed,
            raw,
            summaries,
            control,
            lineage,
            authority,
            normalization,
            hello,
            target_groups,
            selected_groups,
            completed,
            promotion,
            maximum_requested,
            preflight_requested,
            constructed_requested,
        } = self;
        inline_data(started);
        inline_data(failed);
        inline_data(maximum_requested);
        inline_data(preflight_requested);
        inline_data(constructed_requested);

        observer.observe(raw)?;
        copied_vector_data(summaries, observer)?;
        control.observe_attempt_data(observer)?;
        lineage.observe_attempt_data(observer)?;
        HistoricalAuthority17::observe_attempt_data(authority, observer)?;
        NativeMappingNormalization17::observe_attempt_data(normalization, observer)?;
        hello.observe_data(observer)?;
        copied_vector_data(target_groups, observer)?;

        observer.vector::<Option<Arc<[ExtensionSelection]>>>(selected_groups.capacity())?;
        for values in selected_groups.iter().flatten() {
            // A repeated Arc is another real view. The common shared geometry
            // supplies header/alignment policy; no legacy byte sum becomes a row.
            observer.shared_original(MetadataSharedKind::SelectedExtensions, values.as_ref())?;
            for value in values.as_ref() {
                ExtensionSelection::observe_output_data(value, observer)?;
            }
        }

        promotion.observe_capacity_data(observer)?;
        if let Some(completed) = completed {
            completed.observe_capacity_data(observer)?;
        }
        Ok(())
    }

    /// Names the borrowed decoder fields and shared-view controls.
    ///
    /// Defining child-observer and recursive compiler frames remain separate;
    /// the native graph constructor's owning header is no observer workspace.
    pub(crate) fn capacity_counter_scratch_data() -> usize {
        type SelectedGroupViews<'a> =
            std::iter::Flatten<std::slice::Iter<'a, Option<Arc<[ExtensionSelection]>>>>;

        size_of::<&Self>()
            + size_of::<(
                &bool,
                &bool,
                &Vec<u8>,
                &Vec<RestoredSettledNative17AliasSummary>,
                &CurrentControl17ReadAttempt,
                &CurrentNativeLineage17ReadAttempt,
                &<HistoricalAuthority17 as Native17Build>::Attempt,
                &NativeMappingNormalization17ReadAttempt,
                &NativeHello17Data,
                &Vec<bool>,
                &Vec<Option<Arc<[ExtensionSelection]>>>,
                &Option<NativeCurrentGraph17Data>,
                &NativeCurrentGraph17Promotion,
                &usize,
                &Option<usize>,
                &Option<usize>,
            )>()
            + size_of::<std::slice::Iter<'_, Option<Arc<[ExtensionSelection]>>>>()
            + size_of::<SelectedGroupViews<'_>>()
            + size_of::<&Arc<[ExtensionSelection]>>()
            + size_of::<&[ExtensionSelection]>()
            + size_of::<std::slice::Iter<'_, ExtensionSelection>>()
            + size_of::<&ExtensionSelection>()
            + NativeCurrentGraph17Promotion::capacity_counter_scratch_data()
            + NativeCurrentGraph17Data::capacity_counter_scratch_data()
            + size_of::<&mut MetadataObserver<'_>>()
            + size_of::<Result<(), ProviderError>>()
    }
}

impl NativeCurrentGraph17Promotion {
    fn observe_capacity_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            control,
            lineage,
            authority,
            normalization,
        } = self;

        if let Some(control) = control {
            control.observe_owned_metadata_data(observer)?;
        }
        if let Some(lineage) = lineage {
            lineage.observe_metadata_data(observer)?;
        }
        if let Some(authority) = authority {
            HistoricalAuthority17::observe_output_data(authority, observer)?;
        }
        if let Some(normalization) = normalization {
            NativeMappingNormalization17::observe_output_data(normalization, observer)?;
        }
        Ok(())
    }

    fn capacity_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<(
                &Option<CurrentControl17Data>,
                &Option<CurrentNativeLineage17Data>,
                &Option<HistoricalAuthority17>,
                &Option<NativeMappingNormalization17>,
            )>()
            + size_of::<&CurrentControl17Data>()
            + size_of::<&CurrentNativeLineage17Data>()
            + size_of::<&HistoricalAuthority17>()
            + size_of::<&NativeMappingNormalization17>()
    }
}

impl NativeCurrentGraph17Data {
    fn observe_capacity_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            raw,
            summaries,
            control,
            lineage,
            authority,
            normalization,
            hello,
            creator,
            selected_target_requested,
        } = self;
        inline_data(creator);
        inline_data(selected_target_requested);

        observer.observe(raw)?;
        copied_vector_data(summaries, observer)?;
        control.observe_owned_metadata_data(observer)?;
        lineage.observe_metadata_data(observer)?;
        HistoricalAuthority17::observe_output_data(authority, observer)?;
        NativeMappingNormalization17::observe_output_data(normalization, observer)?;
        hello.observe_data(observer)
    }

    fn capacity_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<(
                &Vec<u8>,
                &Vec<RestoredSettledNative17AliasSummary>,
                &CurrentControl17Data,
                &CurrentNativeLineage17Data,
                &HistoricalAuthority17,
                &NativeMappingNormalization17,
                &NativeHello17Data,
                &u32,
                &usize,
            )>()
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
