//! Borrows actual upload partials beside real shared ledger/supervisor edges.
//!
//! The enclosing native graph defines the actual BlobLedger payload once.
//! These fields link that same allocation through the real alias observer;
//! markers/digests never reconstruct a ledger, native scope or live grant.

use super::*;
use crate::retained_metadata::aliases::MetadataSharedKind;
use serde::{Serialize, Serializer, ser::SerializeStruct};

struct Geometry<'a>(&'a NativeSerializationStorageData);
impl Serialize for Geometry<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let NativeSerializationStorageData {
            dom_and_canonical_scratch_bytes,
            retained_value_backing_bytes,
            projected_parser_requested_bytes,
            canonical_output_requested_bytes,
            serializer_temporary_requested_bytes,
            declared_counter_scratch_bytes,
            maximum_encoded_bytes,
            sequence_elements,
            sequence_containers,
            serialized_value_nodes,
            serialized_capacity_records,
        } = self.0;
        let mut fields = serializer.serialize_struct("UploadReplyGeometry17", 11)?;
        fields.serialize_field(
            "dom_and_canonical_scratch_bytes",
            dom_and_canonical_scratch_bytes,
        )?;
        fields.serialize_field("retained_value_backing_bytes", retained_value_backing_bytes)?;
        fields.serialize_field(
            "projected_parser_requested_bytes",
            projected_parser_requested_bytes,
        )?;
        fields.serialize_field(
            "canonical_output_requested_bytes",
            canonical_output_requested_bytes,
        )?;
        fields.serialize_field(
            "serializer_temporary_requested_bytes",
            serializer_temporary_requested_bytes,
        )?;
        fields.serialize_field(
            "declared_counter_scratch_bytes",
            declared_counter_scratch_bytes,
        )?;
        fields.serialize_field("maximum_encoded_bytes", maximum_encoded_bytes)?;
        fields.serialize_field("sequence_elements", sequence_elements)?;
        fields.serialize_field("sequence_containers", sequence_containers)?;
        fields.serialize_field("serialized_value_nodes", serialized_value_nodes)?;
        fields.serialize_field("serialized_capacity_records", serialized_capacity_records)?;
        fields.end()
    }
}

struct Storage<'a>(&'a NativeCapture17UploadStorageData);
impl Serialize for Storage<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let NativeCapture17UploadStorageData {
            owner: _,
            supervisor: _,
            before,
            input,
            row,
            reply,
        } = self.0;
        let mut fields = serializer.serialize_struct("NativeCapture17UploadStorage", 7)?;
        fields.serialize_field("schema", "source-private.native-capture-upload-storage/17")?;
        fields.serialize_field("ledger", "current-native-blob-ledger")?;
        fields.serialize_field("supervisor", "current-native-supervisor")?;
        fields.serialize_field("before", before)?;
        fields.serialize_field("input", input)?;
        fields.serialize_field("row", row)?;
        fields.serialize_field("reply_geometry", &Geometry(reply))?;
        fields.end()
    }
}

struct ResultView<'a>(&'a UploadResult);
impl Serialize for ResultView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            UploadResult::Progress(progress) => {
                let BlobProgress {
                    transfer_id,
                    next_offset,
                    maximum_chunk_bytes,
                } = progress;
                ("progress", transfer_id, next_offset, maximum_chunk_bytes).serialize(serializer)
            }
            UploadResult::Verified(verified) => {
                let VerifiedTransfer {
                    receiver: _,
                    key,
                    content,
                } = verified;
                let TransferKey {
                    origin,
                    session,
                    incarnation,
                    transfer,
                } = key;
                (
                    "verified",
                    "current-native-blob-ledger",
                    (origin, session, incarnation, transfer),
                    content,
                )
                    .serialize(serializer)
            }
        }
    }
}

struct Attempt<'a>(&'a NativeCapture17UploadAttempt);
impl Serialize for Attempt<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let NativeCapture17UploadAttempt {
            owner: _,
            supervisor: _,
            input,
            before,
            after,
            phase,
            result,
            reply,
        } = self.0;
        let phase = match phase {
            UploadPhase::EffectRunning => "effect-running",
            UploadPhase::EffectFailed => "effect-failed",
            UploadPhase::EffectComplete => "effect-complete",
            UploadPhase::ReplyRunning => "reply-running",
            UploadPhase::ReplyFailed => "reply-failed",
            UploadPhase::ReplyComplete => "reply-complete",
        };
        let mut fields = serializer.serialize_struct("NativeCapture17UploadAttempt", 9)?;
        fields.serialize_field("schema", "source-private.native-capture-upload-attempt/17")?;
        fields.serialize_field("ledger", "current-native-blob-ledger")?;
        fields.serialize_field("supervisor", "current-native-supervisor")?;
        fields.serialize_field("input", input)?;
        fields.serialize_field("before", before)?;
        fields.serialize_field("after", after)?;
        fields.serialize_field("phase", phase)?;
        fields.serialize_field("result", &result.as_ref().map(ResultView))?;
        fields.serialize_field("reply", reply)?;
        fields.end()
    }
}

impl NativeCapture17UploadStorageData {
    /// Borrows every retained row/correspondence field as inert historical DATA.
    ///
    /// The parent reader must independently join real BlobLedger/NativeSupervisor
    /// alias links to its genuine payload roots, never infer them from markers.
    pub(crate) fn borrowed_current17_fields_data(&self) -> impl Serialize + '_ {
        Storage(self)
    }

    /// Records the actual shared owners beside scalar row/correspondence fields.
    /// # Errors
    /// Refuses exhausted alias/capacity banks or checked observer overflow.
    pub(crate) fn observe_current17_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            owner,
            supervisor,
            before,
            input,
            row,
            reply,
        } = self;
        observer.shared_original(MetadataSharedKind::BlobLedger, owner.as_ref())?;
        observer.shared_original(MetadataSharedKind::NativeSupervisor, supervisor.as_ref())?;
        observer.observe(before)?;
        observer.observe(input)?;
        observer.observe(&row.retained_requested_bytes)?;
        observer.observe(&row.maximum_simultaneous_transient_bytes)?;
        observer.observe(&row.declared_counter_scratch_bytes)?;
        let NativeSerializationStorageData {
            dom_and_canonical_scratch_bytes,
            retained_value_backing_bytes,
            projected_parser_requested_bytes,
            canonical_output_requested_bytes,
            serializer_temporary_requested_bytes,
            declared_counter_scratch_bytes,
            maximum_encoded_bytes,
            sequence_elements,
            sequence_containers,
            serialized_value_nodes,
            serialized_capacity_records,
        } = reply;
        for value in [
            dom_and_canonical_scratch_bytes,
            retained_value_backing_bytes,
            projected_parser_requested_bytes,
            canonical_output_requested_bytes,
            serializer_temporary_requested_bytes,
            declared_counter_scratch_bytes,
            maximum_encoded_bytes,
            sequence_elements,
            sequence_containers,
            serialized_value_nodes,
            serialized_capacity_records,
        ] {
            observer.observe(value)?;
        }
        Ok(())
    }
}

impl NativeCapture17UploadAttempt {
    /// Borrows all real phase/result/reply partials without exposing byte access.
    ///
    /// An old successful result may precede later ledger mutations. This writer
    /// preserves history, and does not assert its old after-stamp is current.
    pub(crate) fn borrowed_current17_fields_data(&self) -> impl Serialize + '_ {
        Attempt(self)
    }

    /// Records actual partial/result backing and same-ledger links exhaustively.
    /// # Errors
    /// Refuses exhausted alias/capacity banks or checked observer overflow.
    pub(crate) fn observe_current17_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            owner,
            supervisor,
            input,
            before,
            after,
            phase: _,
            result,
            reply,
        } = self;
        observer.shared_original(MetadataSharedKind::BlobLedger, owner.as_ref())?;
        observer.shared_original(MetadataSharedKind::NativeSupervisor, supervisor.as_ref())?;
        observer.observe(input)?;
        observer.observe(before)?;
        observer.observe(after)?;
        match result {
            None => {}
            Some(UploadResult::Progress(progress)) => {
                let BlobProgress {
                    transfer_id,
                    next_offset,
                    maximum_chunk_bytes,
                } = progress;
                observer.observe(transfer_id)?;
                observer.observe(next_offset)?;
                observer.observe(maximum_chunk_bytes)?;
            }
            Some(UploadResult::Verified(verified)) => {
                let VerifiedTransfer {
                    receiver,
                    key,
                    content,
                } = verified;
                observer.shared_original(MetadataSharedKind::BlobLedger, receiver.as_ref())?;
                let TransferKey {
                    origin: _,
                    session,
                    incarnation,
                    transfer,
                } = key;
                observer.observe(session)?;
                observer.observe(incarnation)?;
                observer.observe(transfer)?;
                observer.observe(content)?;
            }
        }
        observer.observe(reply)
    }
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<Geometry<'static>>()
        + size_of::<Storage<'static>>()
        + size_of::<ResultView<'static>>()
        + size_of::<Attempt<'static>>()
        + size_of::<Option<ResultView<'static>>>()
        + size_of::<[&usize; 11]>()
        + size_of::<std::array::IntoIter<&'static usize, 11>>()
        + size_of::<&str>()
        + size_of::<&mut MetadataObserver<'static>>()
        + size_of::<Result<(), ProviderError>>()
}
