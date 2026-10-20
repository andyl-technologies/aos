//! Lends complete actual upload frames, including independently typed failures.

use super::*;
use crate::protocol_snapshot::{Sequence, compact_bytes::BorrowedCompactBytes};
use serde::{Serialize, ser::SerializeStruct};

impl AssignedUpload {
    pub(in crate::client::controller) fn borrowed_settled_history_data(
        &self,
    ) -> impl Serialize + '_ {
        let Self {
            request,
            transfer,
            pending_content,
            frames,
            cut: _,
            state,
        } = self;
        (
            "source-private.sdk-activation-upload-current/17",
            request,
            transfer,
            pending_content.as_ref().map(|(reference, bytes)| {
                (
                    reference,
                    BorrowedCompactBytes::new(bytes),
                    bytes.capacity(),
                )
            }),
            Sequence(|| frames.iter().map(FrameData)),
            frames.capacity(),
            match state {
                State::Preparing => "preparing",
                State::Unsigned => "unsigned",
                State::Sealing => "sealing",
                State::Sealed => "sealed",
                State::Publishing => "publishing",
                State::Complete => "complete",
            },
            "historical-nonrenewable-operational-cut",
        )
    }

    pub(in crate::client::controller) fn observe_settled_history_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.request.observe_owned_metadata_data(observer)?;
        observer.observe(&self.transfer)?;
        if let Some((reference, bytes)) = &self.pending_content {
            observer.observe(reference)?;
            observer.vector::<u8>(bytes.capacity())?;
        }
        observer.vector::<Frame>(self.frames.capacity())?;
        for frame in &self.frames {
            observer.observe(&frame.request_id)?;
            observer.observe(&frame.original)?;
            if let Some(received) = &frame.received {
                observer.observe(&received.envelope)?;
                observe_body(&received.body, observer)?;
            }
        }
        Ok(())
    }
}

struct FrameData<'a>(&'a Frame);
struct BodyData<'a>(&'a ReceivedBody);
struct RequestData<'a>(&'a crate::bodies::RequestBody);

impl Serialize for FrameData<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let Frame {
            request_id,
            method,
            offset,
            length,
            original,
            received,
            attempted,
            complete,
        } = self.0;
        let mut fields = serializer.serialize_struct("SdkUploadFrame17", 8)?;
        fields.serialize_field("request_id", request_id)?;
        fields.serialize_field("method", method)?;
        fields.serialize_field("offset", offset)?;
        fields.serialize_field("length", length)?;
        fields.serialize_field("original", original)?;
        fields.serialize_field(
            "received",
            &received
                .as_ref()
                .map(|value| (&value.envelope, BodyData(&value.body))),
        )?;
        fields.serialize_field("attempted", attempted)?;
        fields.serialize_field("complete", complete)?;
        fields.end()
    }
}

impl Serialize for BodyData<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            ReceivedBody::Request(value) => ("request", RequestData(value)).serialize(serializer),
            ReceivedBody::Response(value) => (
                "response",
                crate::retained_metadata::historical_response_body_data(value)
                    .map_err(serde::ser::Error::custom)?,
            )
                .serialize(serializer),
            ReceivedBody::NativeImport18Bootstrap(_) => {
                return Err(serde::ser::Error::custom(
                    "bootstrap18 requires its distinct history grammar",
                ));
            }
            ReceivedBody::Notification(value) => ("notification", value).serialize(serializer),
        }
    }
}

impl Serialize for RequestData<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use crate::bodies::RequestBody;
        match self.0 {
            RequestBody::BlobBegin(value) => ("blob_begin", value).serialize(serializer),
            RequestBody::BlobChunk(value) => ("blob_chunk", value).serialize(serializer),
            RequestBody::BlobFinish(value) => ("blob_finish", value).serialize(serializer),
            RequestBody::Retire(value) => ("retire", value).serialize(serializer),
            // Connection::validate_body forbids all other provider-origin requests.
            _ => Err(serde::ser::Error::custom(
                "invalid retained provider request family",
            )),
        }
    }
}

fn observe_body(
    body: &ReceivedBody,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    use crate::bodies::{
        BlobBeginRequest, BlobChunkRequest, BlobFinishRequest, NotificationBody, RequestBody,
        RetireRequest,
    };
    match body {
        ReceivedBody::Response(value) => {
            observer.boxed_value(value.as_ref())?;
            crate::retained_metadata::historical_response_body_data(value)?
                .observe_retained_metadata_data(observer)
        }
        ReceivedBody::NativeImport18Bootstrap(_) => {
            return Err(crate::ProviderError::Conflict(
                "bootstrap18 requires its distinct current owner",
            ));
        }
        ReceivedBody::Notification(value) => {
            observer.boxed_value(value.as_ref())?;
            let NotificationBody {
                operation_state,
                last_observation_sequence,
                details,
                extensions,
            } = value.as_ref();
            observer.observe(operation_state)?;
            observer.observe(last_observation_sequence)?;
            observer.observe(details)?;
            observer.observe(extensions)
        }
        ReceivedBody::Request(value) => {
            observer.boxed_value(value.as_ref())?;
            match value.as_ref() {
                RequestBody::BlobBegin(BlobBeginRequest {
                    transfer_id,
                    content,
                    extensions,
                }) => {
                    observer.observe(transfer_id)?;
                    observer.observe(content)?;
                    observer.observe(extensions)
                }
                RequestBody::BlobChunk(BlobChunkRequest {
                    transfer_id,
                    offset,
                    bytes,
                    extensions,
                }) => {
                    observer.observe(transfer_id)?;
                    observer.observe(offset)?;
                    observer.observe(bytes)?;
                    observer.observe(extensions)
                }
                RequestBody::BlobFinish(BlobFinishRequest {
                    transfer_id,
                    extensions,
                }) => {
                    observer.observe(transfer_id)?;
                    observer.observe(extensions)
                }
                RequestBody::Retire(RetireRequest {
                    request_ids,
                    operation_ids,
                    disposition: _,
                    custody_receipt,
                    extensions,
                }) => {
                    observer.observe(request_ids)?;
                    observer.observe(operation_ids)?;
                    observer.observe(&custody_receipt.0)?;
                    observer.observe(extensions)
                }
                _ => Err(refused()),
            }
        }
    }
}

fn field_views<T>(_: impl FnOnce(&'static AssignedUpload) -> T) -> usize {
    std::mem::size_of::<T>()
}

fn frame_field_views<T>(_: impl FnOnce(&'static Frame) -> T) -> usize {
    std::mem::size_of::<T>()
}

impl AssignedUpload {
    pub(in crate::client::controller) fn settled_history_counter_scratch_data() -> usize {
        use std::mem::size_of;
        field_views(|value| {
            (
                value.borrowed_settled_history_data(),
                Some(value.borrowed_settled_history_data()),
            )
        }) + field_views(|value| {
            let AssignedUpload {
                request,
                transfer,
                pending_content,
                frames,
                cut,
                state,
            } = value;
            (request, transfer, pending_content, frames, cut, state)
        }) + frame_field_views(|value| {
            let Frame {
                request_id,
                method,
                offset,
                length,
                original,
                received,
                attempted,
                complete,
            } = value;
            (
                request_id, method, offset, length, original, received, attempted, complete,
            )
        }) + size_of::<FrameData<'static>>()
            + size_of::<BodyData<'static>>()
            + size_of::<RequestData<'static>>()
            + size_of::<Option<(&Envelope, BodyData<'static>)>>()
            + size_of::<Option<(&ContentRef, BorrowedCompactBytes<'static>, usize)>>()
            + size_of::<&AssignedUpload>()
            + size_of::<&Frame>()
            + size_of::<&ReceivedBody>()
            + size_of::<&crate::bodies::RequestBody>()
            + size_of::<std::slice::Iter<'static, Frame>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<&mut MetadataObserver<'static>>()
            + crate::retained_metadata::historical_response_body_counter_scratch_data()
            + BorrowedCompactBytes::requested_serialization_scratch_bytes()
    }
}
