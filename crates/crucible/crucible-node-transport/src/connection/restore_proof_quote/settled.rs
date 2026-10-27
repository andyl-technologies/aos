//! Borrows complete native Connection child history without reviving rights.
//!
//! Actual shared payloads are encoded once by the enclosing native17 graph.
//! This view preserves all raw/typed/partial fields and records their real alias
//! edges. Deadline labels are historical roles; host clock coordinates are
//! deliberately unencoded and no fresh deadline or issuer is reconstructed.

use super::*;
use crate::retained_metadata::{MetadataObserver, aliases::MetadataSharedKind};
use serde::{Serialize, Serializer, ser::SerializeStruct};

struct ChildHistory<'a>(&'a OriginalRestoreHeldProofAllocationQuote);

impl OriginalRestoreHeldProofAllocationQuote {
    /// Borrows every actual field under its original native owner relation.
    ///
    /// # Errors
    /// Refuses foreign originating roots, borrowed token relations or a changed
    /// installed mapping. This grants no Capture, continuation or installation.
    pub(crate) fn borrowed_settled_history_data(
        &self,
    ) -> Result<impl Serialize + '_, ProviderError> {
        self.actor.ensure_current()?;
        Ok(ChildHistory(self))
    }

    /// Appends complete actual child capacities and shared edges without reset.
    ///
    /// # Errors
    /// Refuses foreign/borrowed roots, exhausted admitted banks or checked overflow.
    pub(crate) fn observe_settled_history_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.actor.ensure_current()?;
        let Self {
            actor,
            codec,
            bank,
            maximum_frames,
            requested_bytes,
            prebuilding,
        } = self;
        observer.shared_original(MetadataSharedKind::ProtocolOwner, actor.as_ref())?;
        observer.shared_original(MetadataSharedKind::Codec, codec.as_ref())?;
        observer.shared_original(MetadataSharedKind::FrameBank, bank.as_ref())?;
        observer.observe(maximum_frames)?;
        observer.observe(requested_bytes)?;
        observer.observe(&prebuilding.get())?;
        Ok(())
    }

    /// Names the defining borrowed field, serializer, option and error headers.
    pub(crate) fn settled_history_counter_scratch_data() -> usize {
        use std::mem::size_of;
        size_of::<ChildHistory<'static>>()
            + size_of::<Result<ChildHistory<'static>, ProviderError>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<MetadataObserver<'static>>()
            + field_view_bytes(|value: &'static OriginalRestoreHeldProofAllocationQuote| {
                let OriginalRestoreHeldProofAllocationQuote {
                    actor,
                    codec,
                    bank,
                    maximum_frames,
                    requested_bytes,
                    prebuilding,
                } = value;
                (
                    actor,
                    codec,
                    bank,
                    maximum_frames,
                    requested_bytes,
                    prebuilding,
                )
            })
    }
}

impl Serialize for ChildHistory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0
            .actor
            .ensure_current()
            .map_err(serde::ser::Error::custom)?;
        let OriginalRestoreHeldProofAllocationQuote {
            actor,
            codec,
            bank,
            maximum_frames,
            requested_bytes,
            prebuilding,
        } = self.0;
        let mut state = serializer.serialize_struct("NativeConnectionChildHistory17", 7)?;
        state.serialize_field("schema", "source-private.restore-proof-quote-history/17")?;
        let _ = actor;
        state.serialize_field("actor_role", "native-connection-actor")?;
        let _ = codec;
        state.serialize_field("codec_role", "native-connection-codec")?;
        let _ = bank;
        state.serialize_field("bank_role", "native-connection-frames")?;
        state.serialize_field("maximum_frames", maximum_frames)?;
        state.serialize_field("requested_bytes", requested_bytes)?;
        state.serialize_field("prebuilding", &prebuilding.get())?;
        state.end()
    }
}

const fn field_view_bytes<T: 'static, U>(_: fn(&'static T) -> U) -> usize {
    std::mem::size_of::<U>()
}
