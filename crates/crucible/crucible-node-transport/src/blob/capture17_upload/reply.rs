//! Quotes and produces only the real primitive's closed auxiliary result.

use super::*;
use crate::bodies::OperationState;
use crate::retained_metadata::serialization_storage::OriginalSerializationStorageProjection;
use crate::retained_metadata::serialization_storage::actual_serialization_storage_data;
use crucible_node_format::Extensions;
use serde::{Serialize, Serializer};

#[derive(Serialize)]
struct Completed<T> {
    status: &'static str,
    operation_state: OperationState,
    result: T,
    extensions: Extensions,
}

#[derive(Serialize)]
struct Begin<'a> {
    transfer_id: &'a Id,
    next_offset: U64,
    maximum_chunk_bytes: U64,
}

#[derive(Serialize)]
struct Chunk<'a> {
    transfer_id: &'a Id,
    next_offset: U64,
}

#[derive(Serialize)]
struct Finish<'a> {
    transfer_id: &'a Id,
    content: &'a ContentRef,
}

fn completed<T>(result: T) -> Completed<T> {
    Completed {
        status: "completed",
        operation_state: OperationState::Completed,
        result,
        extensions: Extensions::new(),
    }
}

// This enum is private: each branch delegates to exactly the closed serializer
// used for the actual primitive reply, without constructing its owning DOM.
enum ProspectiveReply<'a> {
    Begin(Completed<Begin<'a>>),
    Chunk(Completed<Chunk<'a>>),
    Finish(Completed<Finish<'a>>),
}

impl Serialize for ProspectiveReply<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Begin(value) => value.serialize(serializer),
            Self::Chunk(value) => value.serialize(serializer),
            Self::Finish(value) => value.serialize(serializer),
        }
    }
}

fn prospective_data<'a>(
    input: NativeCapture17UploadInput<'a>,
    record: Option<&'a TransferRecord>,
    maximum_chunk: usize,
) -> Result<ProspectiveReply<'a>, ProviderError> {
    let key = input.key_data();
    match input {
        NativeCapture17UploadInput::Begin { .. } => Ok(ProspectiveReply::Begin(completed(Begin {
            transfer_id: key.transfer,
            next_offset: quantity(record.map_or(0, |record| record.bytes.len()))?,
            maximum_chunk_bytes: quantity(maximum_chunk)?,
        }))),
        NativeCapture17UploadInput::Chunk { offset, bytes, .. } => {
            let record = record.ok_or_else(refused)?;
            let next = usize::try_from(offset.get())
                .map_err(|_| exhausted())?
                .checked_add(bytes.as_slice().len())
                .ok_or_else(exhausted)?
                .max(record.bytes.len());
            Ok(ProspectiveReply::Chunk(completed(Chunk {
                transfer_id: key.transfer,
                next_offset: quantity(next)?,
            })))
        }
        NativeCapture17UploadInput::Finish { .. } => {
            Ok(ProspectiveReply::Finish(completed(Finish {
                transfer_id: key.transfer,
                content: &record.ok_or_else(refused)?.content,
            })))
        }
    }
}

pub(super) fn quote_data(
    input: NativeCapture17UploadInput<'_>,
    record: Option<&TransferRecord>,
    maximum_chunk: usize,
    maximum: usize,
) -> Result<NativeSerializationStorageData, ProviderError> {
    actual_serialization_storage_data(
        &prospective_data(input, record, maximum_chunk)?,
        Default::default(),
        maximum,
    )
}

fn project_data(
    input: NativeCapture17UploadInput<'_>,
    record: Option<&TransferRecord>,
    maximum_chunk: usize,
    out: &mut OriginalSerializationStorageProjection,
) -> Result<(), ProviderError> {
    out.add_value(&prospective_data(input, record, maximum_chunk)?)
}

fn authenticate_geometry(
    actual: &NativeSerializationStorageData,
    quoted: &NativeSerializationStorageData,
) -> Result<(), ProviderError> {
    for (actual, maximum) in [
        (
            actual.dom_and_canonical_scratch_bytes,
            quoted.dom_and_canonical_scratch_bytes,
        ),
        (
            actual.retained_value_backing_bytes,
            quoted.retained_value_backing_bytes,
        ),
        (
            actual.projected_parser_requested_bytes,
            quoted.projected_parser_requested_bytes,
        ),
        (
            actual.canonical_output_requested_bytes,
            quoted.canonical_output_requested_bytes,
        ),
        (
            actual.serializer_temporary_requested_bytes,
            quoted.serializer_temporary_requested_bytes,
        ),
        (
            actual.declared_counter_scratch_bytes,
            quoted.declared_counter_scratch_bytes,
        ),
        (actual.maximum_encoded_bytes, quoted.maximum_encoded_bytes),
        (actual.sequence_elements, quoted.sequence_elements),
        (actual.sequence_containers, quoted.sequence_containers),
        (actual.serialized_value_nodes, quoted.serialized_value_nodes),
        (
            actual.serialized_capacity_records,
            quoted.serialized_capacity_records,
        ),
    ] {
        if actual > maximum {
            return Err(exhausted());
        }
    }
    Ok(())
}

impl BlobReceiver {
    /// Projects the defining successful reply family without a future transfer.
    ///
    /// This closed grammar is shared with the real completed reply serializers
    /// above. The Id grammar permits 128 unescaped ASCII bytes; U64 decimal text
    /// permits 20. Full content media strings permit128 printable ASCII bytes,
    /// including JSON escapes. This DATA neither predicts successful Finish nor
    /// issues any receiver/native permission.
    ///
    /// # Errors
    /// Refuses a non-Blob method, short projection or checked geometry overflow.
    pub(crate) fn project_capture17_upload_future_reply_data(
        method: crate::envelope::Method,
        out: &mut OriginalSerializationStorageProjection,
    ) -> Result<(), ProviderError> {
        use crate::envelope::Method;
        future_object(out, &["status", "operation_state", "result", "extensions"])?;
        out.add_string("completed")?;
        out.add_value(&OperationState::Completed)?;
        match method {
            Method::BlobBegin => {
                future_object(out, &["transfer_id", "next_offset", "maximum_chunk_bytes"])?;
                out.add_unescaped_ascii_extent(128)?;
                out.add_unescaped_ascii_extent(20)?;
                out.add_unescaped_ascii_extent(20)?;
            }
            Method::BlobChunk => {
                future_object(out, &["transfer_id", "next_offset"])?;
                out.add_unescaped_ascii_extent(128)?;
                out.add_unescaped_ascii_extent(20)?;
            }
            Method::BlobFinish => {
                future_object(out, &["transfer_id", "content"])?;
                out.add_unescaped_ascii_extent(128)?;
                future_object(out, &["hash", "length", "media_type"])?;
                future_object(out, &["algorithm", "domain", "digest"])?;
                out.add_string("blake3-256")?;
                out.add_string("cnp.blob.v1")?;
                out.add_unescaped_ascii_extent(64)?;
                out.add_unescaped_ascii_extent(20)?;
                out.add_string_extent(128)?;
            }
            _ => return Err(refused()),
        }
        out.add_object()
    }

    /// Names the closed future reply visitor's fixed borrowed controls.
    pub(crate) fn capture17_upload_future_reply_counter_scratch_data() -> usize {
        size_of::<crate::envelope::Method>()
            + size_of::<OperationState>()
            + size_of::<&mut OriginalSerializationStorageProjection>()
            + size_of::<[&str; 4]>() + size_of::<[&str; 3]>()
            + size_of::<&[&str]>()
            + size_of::<std::slice::Iter<'static, &'static str>>()
            + size_of::<Result<(), ProviderError>>()
            + crate::retained_metadata::serialization_storage::original_serialization_counter_scratch_data()
    }

    /// Projects the closed prospective body from the real unchanged receiver.
    ///
    /// The actual input/prestate guard precedes this borrowed walk. The caller
    /// independently prepays the defining counter and conservative U64 formatter
    /// work before composing its entire future terminal. No DOM, byte bank or
    /// primitive result is constructed, and the view grants no upload effect.
    /// A projected successful Finish remains conditional: the unchanged real
    /// primitive may subsequently quarantine corrupt/truncated content instead.
    ///
    /// # Errors
    /// Refuses a foreign/changed receiver or input, a conflicting ledger borrow,
    /// missing record, checked offset overflow or a short output projection.
    pub(crate) fn project_capture17_upload_reply_data(
        &self,
        storage: &NativeCapture17UploadStorageData,
        input: NativeCapture17UploadInput<'_>,
        out: &mut OriginalSerializationStorageProjection,
    ) -> Result<(), ProviderError> {
        storage.authenticate_data(self, input)?;
        let key = input.key_data();
        let state = self.state.try_borrow().map_err(|_| refused())?;
        let record = state
            .records
            .iter()
            .find_map(|(actual, record)| key.same_data(actual).then_some(record));
        project_data(input, record, self.limits.chunk_bytes, out)
    }

    /// Produces a reply only from the actual successful same-ledger result.
    ///
    /// Before the reply token is touched this checks the genuine retained result
    /// and its complete post-effect ledger. The token separately authenticates
    /// static row/input plus Source/once/occurrence; it must not reassert the old
    /// quoted prestate. Reply partials remain in the original attempt on refusal.
    /// # Errors
    /// Refuses failed/reused/changed attempts, another private action, actual
    /// reply geometry beyond the quote, encoding failure or a nonobject result.
    pub(crate) fn produce_capture17_upload_reply_into_data(
        &self,
        action: &NativeCapture17UploadSpentAction<'_>,
        storage: &NativeCapture17UploadStorageData,
        input: NativeCapture17UploadInput<'_>,
        attempt: &mut NativeCapture17UploadAttempt,
    ) -> Result<(), ProviderError> {
        if attempt.phase != UploadPhase::EffectComplete || attempt.reply.is_some() {
            return Err(refused());
        }
        attempt.authenticate_result_data(self, storage, input)?;
        action.begin_upload_reply_data(self, storage, input)?;
        attempt.phase = UploadPhase::ReplyRunning;
        // Any subsequent error is sticky even when no DOM was produced yet.
        attempt.phase = UploadPhase::ReplyFailed;
        let maximum = storage.reply.requested_total()?;
        let value = match (input, attempt.result.as_ref().ok_or_else(refused)?) {
            (NativeCapture17UploadInput::Begin { .. }, UploadResult::Progress(progress)) => {
                let view = completed(Begin {
                    transfer_id: &progress.transfer_id,
                    next_offset: progress.next_offset,
                    maximum_chunk_bytes: progress.maximum_chunk_bytes,
                });
                authenticate_geometry(
                    &actual_serialization_storage_data(&view, Default::default(), maximum)?,
                    &storage.reply,
                )?;
                serde_json::to_value(view)
            }
            (NativeCapture17UploadInput::Chunk { .. }, UploadResult::Progress(progress)) => {
                let view = completed(Chunk {
                    transfer_id: &progress.transfer_id,
                    next_offset: progress.next_offset,
                });
                authenticate_geometry(
                    &actual_serialization_storage_data(&view, Default::default(), maximum)?,
                    &storage.reply,
                )?;
                serde_json::to_value(view)
            }
            (NativeCapture17UploadInput::Finish { .. }, UploadResult::Verified(verified)) => {
                if !Rc::ptr_eq(&verified.receiver, &self.state)
                    || !input.key_data().same_data(&verified.key)
                {
                    return Err(refused());
                }
                let view = completed(Finish {
                    transfer_id: &verified.key.transfer,
                    content: &verified.content,
                });
                authenticate_geometry(
                    &actual_serialization_storage_data(&view, Default::default(), maximum)?,
                    &storage.reply,
                )?;
                serde_json::to_value(view)
            }
            _ => return Err(refused()),
        }
        .map_err(crucible_node_format::ContractError::from)?;
        attempt.reply = Some(value);
        if attempt
            .reply
            .as_ref()
            .and_then(serde_json::Value::as_object)
            .is_none()
        {
            return Err(refused());
        }
        attempt.phase = UploadPhase::ReplyComplete;
        Ok(())
    }
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<ProspectiveReply<'static>>()
        + size_of::<Result<ProspectiveReply<'static>, ProviderError>>()
        + size_of::<&mut OriginalSerializationStorageProjection>()
        + size_of::<Completed<Begin<'static>>>() + size_of::<Completed<Chunk<'static>>>()
        + size_of::<Completed<Finish<'static>>>() + size_of::<NativeSerializationStorageData>()
        + size_of::<Result<serde_json::Value, serde_json::Error>>()
        + size_of::<Option<serde_json::Value>>() + size_of::<serde_json::Value>()
        + size_of::<[(usize, usize); 11]>()
        + size_of::<Result<(), ProviderError>>()
        + crate::retained_metadata::serialization_storage::original_serialization_counter_scratch_data()
}

#[cfg(test)]
#[path = "reply_projection_tests.rs"]
mod projection_tests;

fn future_object(
    out: &mut OriginalSerializationStorageProjection,
    names: &[&str],
) -> Result<(), ProviderError> {
    out.add_object()?;
    for name in names {
        out.add_field(name)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "reply_future_tests.rs"]
mod future_tests;

// The future grammar must grow with these actual defining reply serializers.
const _: fn(&Completed<Begin<'_>>, &Completed<Chunk<'_>>, &Completed<Finish<'_>>) =
    |begin, chunk, finish| {
        let Completed {
            status: _,
            operation_state: _,
            result: begin,
            extensions: _,
        } = begin;
        let Begin {
            transfer_id: _,
            next_offset: _,
            maximum_chunk_bytes: _,
        } = begin;
        let Chunk {
            transfer_id: _,
            next_offset: _,
        } = &chunk.result;
        let Finish {
            transfer_id: _,
            content: _,
        } = &finish.result;
    };
