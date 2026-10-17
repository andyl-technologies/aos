//! Renders the completed SDK Capture quote's actual retained owner graph.
//!
//! ```text
//! ["source-private.native-capture-sdk-completed-owner/12", numeric_data,
//!  "historical-source-owner", FULL_native_codec_view, FULL_compact_frame_bank]
//! ```
//!
//! Repeated codec/bank bodies intentionally follow the existing ordinary alias
//! grammar. Only the separate unique allocation walk deduplicates payloads.

use super::*;
use crate::transport::original_frames::OriginalFrameReservation;
use std::cell::Ref;

pub(super) struct OriginalCompletedOwner<'a> {
    original: &'a NativeCaptureSdkCompletedQuote,
    frames: Ref<'a, OriginalFrameReservation>,
}

pub(super) fn borrow_original(
    original: &NativeCaptureSdkCompletedQuote,
) -> Result<OriginalCompletedOwner<'_>, ProviderError> {
    original.association.actor.ensure_current()?;
    let Native5CodecOwner::NativePacket(_) = original.association.codec.as_ref() else {
        return Err(refused());
    };
    let frames = original
        .association
        .bank
        .try_borrow()
        .map_err(|_| borrowed())?;
    if !frames.complete() {
        return Err(refused());
    }
    Ok(OriginalCompletedOwner { original, frames })
}

impl serde::Serialize for OriginalCompletedOwner<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.original
            .association
            .actor
            .ensure_current()
            .map_err(serde::ser::Error::custom)?;
        let data = self
            .original
            .borrowed_data_view()
            .map_err(serde::ser::Error::custom)?;
        (
            "source-private.native-capture-sdk-completed-owner/12",
            data,
            "historical-source-owner",
            super::super::native_owned11::NativeCodecView(self.original.association.codec.as_ref()),
            self.frames.protocol_view_with_encoding(true),
        )
            .serialize(serializer)
    }
}

pub(super) fn observe_original(
    original: &NativeCaptureSdkCompletedQuote,
    observer: &mut MetadataObserver,
) -> Result<(), ProviderError> {
    let view = borrow_original(original)?;
    // Numeric data owns no child banks. Its complete scalar traversal still
    // contributes bounded work before the owning headers/children below.
    observe_sdk_data(&original.data, observer)?;
    observer.observe(&metadata_values(original.retained))?;
    observer.observe(&[original.strong_edges, original.unique_shared_roots])?;
    observer.shared_original(
        MetadataSharedKind::ProtocolOwner,
        original.association.actor.as_ref(),
    )?;
    observer.shared_original(
        MetadataSharedKind::Codec,
        original.association.codec.as_ref(),
    )?;
    let Native5CodecOwner::NativePacket(policy) = original.association.codec.as_ref() else {
        return Err(refused());
    };
    observer.shared_original(MetadataSharedKind::NativePolicy, policy.as_ref())?;
    policy.observe_owned11_metadata(observer)?;
    observer.shared_original(
        MetadataSharedKind::FrameBank,
        original.association.bank.as_ref(),
    )?;
    view.frames.observe_owned11_metadata(observer)
}
