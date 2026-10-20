//! Borrows every actual seven-bank once/progress/original/ACK field as DATA.

use super::*;
use crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes;
use serde::{
    Serialize, Serializer,
    ser::{SerializeSeq, SerializeStruct},
};

struct BankHistory<'a>(&'a InputUploadBank);
struct Owners<'a>(&'a [InputUpload]);
struct OwnerHistory<'a>(&'a InputUpload);
struct Frames<'a>(&'a [UploadFrame]);
struct FrameHistory<'a>(&'a UploadFrame);
struct FrontierHistory<'a>(&'a OriginalProtocolStorageFacts);

type OwnerFieldLoans<'a> = (
    &'a UploadStage,
    &'a [Option<ContentRef>; 7],
    &'a [Option<Id>; 7],
    &'a [usize; 7],
    &'a Vec<UploadFrame>,
    &'a usize,
    &'a usize,
    &'a usize,
    &'a U64,
    &'a U64,
    &'a [u8; 32],
    &'a Option<OriginalProtocolStorageFacts>,
    &'a Option<U64>,
);
type FrameFieldLoans<'a> = (
    &'a PacketNativeImport18InputRole,
    &'a Method,
    &'a usize,
    &'a usize,
    &'a Id,
    &'a Option<Envelope>,
    &'a Option<crate::transport::RetainedFrame>,
    &'a Option<Envelope>,
    &'a Option<ReceivedFrame>,
    &'a bool,
    &'a bool,
);

impl InputUploadBank {
    pub(in super::super) fn authenticate_completed_history_data(
        &self,
        prepare: &AssignedPhase<PacketCompleteRestorePrepareRequest>,
        binding: &PacketNativeImport18Binding,
    ) -> Result<(), ProviderError> {
        let inputs = inputs_data(prepare, binding)?;
        let [held] = self.owners.as_slice() else {
            return Err(invalid());
        };
        if !self.started
            || self.failed
            || held.stage != UploadStage::Complete
            || held.prepare_sequence != inputs.original.sequence
            || held.response_sequence != inputs.response.sequence
            || held.token != *blake3::hash(inputs.receipt.transfer_token.as_slice()).as_bytes()
            || held.frames.is_empty()
            || held.frontier.is_none()
            || held.next_sequence.is_none()
        {
            return Err(invalid());
        }
        for role in PacketNativeImport18InputRole::ALL {
            let index = role.ordinal_data();
            if held.references[index].as_ref() != Some(inputs.references[index])
                || held.offsets[index] as u64 != inputs.references[index].length.get()
            {
                return Err(invalid());
            }
        }
        let mut next = inputs.original.sequence.checked_add(U64::new(1))?;
        for frame in &held.frames {
            let index = frame.role.ordinal_data();
            let original = frame.original.as_ref().ok_or_else(invalid)?;
            let received = frame.received.as_ref().ok_or_else(invalid)?;
            if !frame.attempted || !frame.complete || original.sequence != next {
                return Err(invalid());
            }
            authenticate_ack(
                frame,
                received,
                held.transfers[index].as_ref().ok_or_else(invalid)?,
                held.references[index].as_ref().ok_or_else(invalid)?,
                held.chunk,
                held.maximum_chunk,
            )?;
            next = next.checked_add(U64::new(1))?;
        }
        if held.next_sequence != Some(next) {
            return Err(invalid());
        }
        Ok(())
    }

    pub(in super::super) fn history_data(&self) -> impl Serialize + '_ {
        BankHistory(self)
    }
}

impl Serialize for BankHistory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let InputUploadBank {
            owners,
            started,
            failed,
        } = self.0;
        let mut value = serializer.serialize_struct("NativeImport18UploadBankHistoryData", 3)?;
        value.serialize_field("started", started)?;
        value.serialize_field("failed", failed)?;
        value.serialize_field("owners", &Owners(owners))?;
        value.end()
    }
}

impl Serialize for Owners<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut values = serializer.serialize_seq(Some(self.0.len()))?;
        for owner in self.0 {
            values.serialize_element(&OwnerHistory(owner))?;
        }
        values.end()
    }
}

impl Serialize for OwnerHistory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let InputUpload {
            stage,
            references,
            transfers,
            offsets,
            frames,
            active,
            chunk,
            maximum_chunk,
            cut: _,
            prepare_sequence,
            response_sequence,
            token,
            frontier,
            next_sequence,
        } = self.0;
        let stage = match stage {
            UploadStage::Allocating => "allocating",
            UploadStage::Publishing => "publishing",
            UploadStage::RawReceived => "raw_received",
            UploadStage::Decoding => "decoding",
            UploadStage::Complete => "complete",
            UploadStage::Failed => "failed",
        };
        let mut value = serializer.serialize_struct("NativeImport18InputUploadHistoryData", 13)?;
        value.serialize_field("stage", stage)?;
        value.serialize_field("references", references)?;
        value.serialize_field("transfers", transfers)?;
        value.serialize_field("offsets", offsets)?;
        value.serialize_field("frames", &Frames(frames))?;
        value.serialize_field("active", active)?;
        value.serialize_field("chunk", chunk)?;
        value.serialize_field("maximum_chunk", maximum_chunk)?;
        value.serialize_field("prepare_sequence", prepare_sequence)?;
        value.serialize_field("response_sequence", response_sequence)?;
        value.serialize_field("token", &BorrowedCompactBytes::new(token))?;
        value.serialize_field("frontier", &frontier.as_ref().map(FrontierHistory))?;
        value.serialize_field("next_sequence", next_sequence)?;
        value.end()
    }
}

impl Serialize for Frames<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut values = serializer.serialize_seq(Some(self.0.len()))?;
        for frame in self.0 {
            values.serialize_element(&FrameHistory(frame))?;
        }
        values.end()
    }
}

impl Serialize for FrameHistory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let UploadFrame {
            role,
            method,
            offset,
            length,
            request_id,
            original,
            json_profile: _,
            raw,
            response,
            received,
            attempted,
            complete,
        } = self.0;
        let mut value = serializer.serialize_struct("NativeImport18UploadFrameHistoryData", 11)?;
        value.serialize_field("role", role)?;
        value.serialize_field("method", method)?;
        value.serialize_field("offset", offset)?;
        value.serialize_field("length", length)?;
        value.serialize_field("request_id", request_id)?;
        value.serialize_field("original", original)?;
        value.serialize_field(
            "raw",
            &raw.as_ref()
                .map(|frame| (&frame.value, BorrowedCompactBytes::new(&frame.bytes))),
        )?;
        value.serialize_field("response", response)?;
        value.serialize_field(
            "received",
            &received
                .as_ref()
                .map(ReceivedFrame::borrowed_settled17_data),
        )?;
        value.serialize_field("attempted", attempted)?;
        value.serialize_field("complete", complete)?;
        value.end()
    }
}

impl Serialize for FrontierHistory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let OriginalProtocolStorageFacts {
            maximum_frame_bytes,
            maximum_history_bytes,
            maximum_frames_per_direction,
            byte_capacity: _,
            descriptor_capacity: _,
            descriptor_bytes: _,
            allocated_bytes: _,
            retained_bytes,
            incoming_frames,
            outgoing_frames,
            all_io_complete,
        } = self.0;
        // These are actual nonrenewing original protocol ceilings/progress. Host
        // allocation capacity is excluded. Neither numbers nor equality confer
        // currentness on a historical bank or authorize a new live Session.
        let mut value =
            serializer.serialize_struct("NativeImport18OriginalFrontierHistoryData", 7)?;
        value.serialize_field("maximum_frame_bytes", maximum_frame_bytes)?;
        value.serialize_field("maximum_history_bytes", maximum_history_bytes)?;
        value.serialize_field("maximum_frames_per_direction", maximum_frames_per_direction)?;
        value.serialize_field("retained_bytes", retained_bytes)?;
        value.serialize_field("incoming_frames", incoming_frames)?;
        value.serialize_field("outgoing_frames", outgoing_frames)?;
        value.serialize_field("all_io_complete", all_io_complete)?;
        value.end()
    }
}

pub(in super::super) fn counter_scratch_data() -> usize {
    size_of::<BankHistory<'static>>()
        + size_of::<Owners<'static>>()
        + size_of::<OwnerHistory<'static>>()
        + size_of::<Frames<'static>>()
        + size_of::<FrameHistory<'static>>()
        + size_of::<FrontierHistory<'static>>()
        + size_of::<(&usize, &usize, &usize, &usize, &usize, &usize, &bool)>()
        + size_of::<Option<FrontierHistory<'static>>>()
        + size_of::<OwnerFieldLoans<'static>>()
        + size_of::<FrameFieldLoans<'static>>()
        + size_of::<std::slice::Iter<'static, InputUpload>>()
        + size_of::<std::slice::Iter<'static, UploadFrame>>()
        + size_of::<&ReceivedFrame>()
        + size_of::<Inputs<'static>>()
        + size_of::<Result<Inputs<'static>, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<U64>()
        + ReceivedFrame::borrowed_settled17_counter_scratch_data()
        + BorrowedCompactBytes::requested_serialization_scratch_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_empty_reserved_bank_preserves_once_without_fake_completion() {
        let mut bank = InputUploadBank::empty();
        bank.started = true;
        bank.failed = true;
        bank.owners.try_reserve_exact(1).unwrap();
        let capacity = bank.owners.capacity();
        let mut observer = MetadataObserver::new();

        let data = serde_json::to_value(bank.history_data()).unwrap();
        bank.observe(&mut observer).unwrap();

        assert_eq!(data["started"], true);
        assert_eq!(data["failed"], true);
        assert_eq!(data["owners"], serde_json::json!([]));
        assert!(bank.is_used());
        assert_eq!(
            observer.finish().vector_capacity_bytes,
            capacity * size_of::<InputUpload>()
        );
    }
}

#[path = "history/partials.rs"]
pub(super) mod partials;
