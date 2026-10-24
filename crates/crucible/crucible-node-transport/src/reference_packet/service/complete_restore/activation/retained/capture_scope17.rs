//! Observes the actual activation scope retained by a frozen Capture checkpoint.

use super::*;

impl PacketRestorationActivationScope {
    /// Counts every actual scope allocation without serializing or authorizing it.
    ///
    /// # Errors
    /// Refuses defining metadata-depth, row or checked-layout overflow.
    pub fn original_capture17_retained_metadata_data(
        &self,
    ) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        let mut observer = MetadataObserver::new();
        observer.observe(self)?;
        Ok(observer.finish())
    }

    /// Names the defining fixed observer and scope/result borrow frames.
    pub fn original_capture17_retained_metadata_counter_scratch_data() -> usize {
        std::mem::size_of::<MetadataObserver<'static>>()
            + std::mem::size_of::<RetainedProtocolMetadataFacts>()
            + std::mem::size_of::<Result<RetainedProtocolMetadataFacts, ProviderError>>()
            + std::mem::size_of::<&Self>()
            + std::mem::size_of::<Result<(), ProviderError>>()
    }
}
