//! Lends the sealed archive's actual current model to import18 construction quotes.
//!
//! These readonly calls preserve the archive and every cached owner. The model
//! quote covers its own complete field transfer; native phase construction must
//! additionally cover the archive, physical socket, Control, Hold and World.

use super::*;
use crate::protocol_snapshot::native_wholegraph17::{
    NativeCurrentGraph17Data, NativeCurrentGraph17DecodeAttempt,
};
use crate::reference_packet::{
    continuation_models::settled_reader::PacketSettledModel17Data, control::CurrentControl17Data,
};

pub use crate::reference_packet::continuation_models::settled_reader::adoption18::CurrentModel18ConstructionData as RestoredSettledNativeImportModelConstructionData;

impl SealedHistoricalRestoredSettledNative17 {
    /// Quotes formatter work from the same sealed model before serialization.
    ///
    /// The caller first admits the defining fixed counter and metadata walk,
    /// then admits this formatter result before asking for construction DATA.
    /// This method performs no allocating model validation or serialization.
    /// Existing archive provenance and native admission remain independent.
    ///
    /// # Errors
    /// Refuses an incomplete seal or model, metadata/traversal overflow or an
    /// independently restricted formatter window smaller than the demand.
    pub fn current_model18_quote_formatter_temporary_data(
        &self,
        maximum: usize,
    ) -> Result<usize, ProviderError> {
        self.validated_native_graph_data()?
            .current_model17_data()?
            .adoption18_quote_formatter_temporary_data(maximum)
    }

    /// Quotes the actual retained current model's import18 transfer component.
    ///
    /// The caller admits the formatter prewalk's result and defining counter
    /// before this typed serialization traversal. Definitions, Stage/Commit
    /// records, reply evidence and capacities come from this same decoded owner;
    /// no policy ceiling or announced phase number supplies the demand.
    ///
    /// The result preserves the archive and transfers no model or physical
    /// resource. It cannot complete a five-phase Recipe, admit a phase, create a
    /// fresh native owner or release a physical Hold. Those enclosing terms and
    /// original ownership checks remain separate.
    ///
    /// # Errors
    /// Refuses an incomplete seal or model, unsupported typed serialization,
    /// traversal/layout overflow or insufficient whole-component credit.
    pub fn current_model18_construction_data(
        &self,
        maximum: usize,
    ) -> Result<RestoredSettledNativeImportModelConstructionData, ProviderError> {
        self.validated_native_graph_data()?
            .current_model17_data()?
            .adoption18_construction_data(maximum)
    }

    /// Names the model counter and the sealed loan's concrete guard views.
    ///
    /// Both the formatter prewalk and main construction traversal require their
    /// own admitted invocation. Dynamic traversal/formatter windows and native
    /// compiler frames remain independent of this fixed DATA counter.
    pub fn current_model18_construction_counter_scratch_data() -> usize {
        use std::mem::size_of;
        PacketSettledModel17Data::adoption18_construction_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<&NativeCurrentGraph17DecodeAttempt>()
            + size_of::<Option<&NativeCurrentGraph17DecodeAttempt>>()
            + size_of::<&NativeCurrentGraph17Data>()
            + size_of::<Result<&NativeCurrentGraph17Data, ProviderError>>()
            + size_of::<&CurrentControl17Data>()
            + size_of::<&PacketSettledModel17Data>()
            + size_of::<Option<&PacketSettledModel17Data>>()
            + size_of::<Result<&PacketSettledModel17Data, ProviderError>>()
            + size_of::<Result<RestoredSettledNativeImportModelConstructionData, ProviderError>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<[usize; 3]>()
            + size_of::<usize>() * 4
            + size_of::<u32>() * 2
            + size_of::<bool>() * 4
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incomplete_sealed_model18_quotes_refuse_without_touching_retained_prefix()
    -> Result<(), ProviderError> {
        let reference = canonical::content_ref(b"{}", "application/json")?;
        let mut decoded = RestoredSettledNative17DecodeAttempt::new();
        assert!(decoded.retain_reference_data(0, &reference, 64).is_err());
        let retained = decoded.retained_requested_storage_data(64)?;
        let sealed = SealedHistoricalRestoredSettledNative17 { decoded };
        let prefix = sealed.decoded.references[0].clone();

        assert!(
            sealed
                .current_model18_quote_formatter_temporary_data(0)
                .is_err()
        );
        assert!(
            sealed
                .current_model18_quote_formatter_temporary_data(usize::MAX)
                .is_err()
        );
        assert!(sealed.current_model18_construction_data(0).is_err());
        assert!(
            sealed
                .current_model18_construction_data(usize::MAX)
                .is_err()
        );
        assert_eq!(
            sealed.decoded.retained_requested_storage_data(64)?,
            retained
        );
        assert_eq!(sealed.decoded.references[0], prefix);
        assert!(!sealed.decoded.is_validated_data());
        assert!(SealedHistoricalRestoredSettledNative17::current_model18_construction_counter_scratch_data() > 0);
        Ok(())
    }
}
