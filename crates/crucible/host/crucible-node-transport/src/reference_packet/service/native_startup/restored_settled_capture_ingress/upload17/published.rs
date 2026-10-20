//! Lends only the actual normal published upload transaction and its quotation.

use super::*;

type PublishedParts<'a> = (
    &'a NativeCapture17UploadStorageData,
    PacketNativeStartupAllocationRow,
    usize,
    &'a NativeCapture17UploadAttempt,
    &'a Map<String, Value>,
);

impl NativeCapture17UploadActionAttempt {
    /// Borrows the actual published transaction after immutable Blob correspondence.
    ///
    /// The private parent publication producer is the sole successful phase
    /// transition. This loan does not authenticate the actual transport record,
    /// current receiver state, Source MAC or continuation ancestry.
    ///
    /// # Errors
    /// Refuses failed/inflight/unpublished transactions, missing normal results,
    /// or quotation/input/result/reply correspondence that no longer agrees.
    pub(crate) fn published_upload17_parts_data(
        &self,
        input: NativeCapture17UploadInput<'_>,
    ) -> Result<PublishedParts<'_>, ProviderError> {
        let record = self.publication_record_data()?;
        let effect = self.effect.as_ref().ok_or_else(refused)?;
        effect.authenticate_completed_quotation17_data(&self.storage, input)?;
        Ok((
            &self.storage,
            self.admitted,
            record,
            effect,
            effect.reply_data()?,
        ))
    }

    /// Names this published transaction's borrowed tuple and completion checks.
    pub(crate) fn published_upload17_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<PublishedParts<'static>>()
            + size_of::<Result<PublishedParts<'static>, ProviderError>>()
            + NativeCapture17UploadAttempt::completed_quotation17_counter_scratch_data()
    }
}
