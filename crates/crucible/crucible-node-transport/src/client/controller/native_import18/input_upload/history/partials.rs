//! Lends actual seven-bank upload partials without completed-history filtering.
//!
//! The enclosing capsule callback guards origin before and after these loans.
//! Every owner/frame remains a separate occurrence; no equality, serialization,
//! schema, current-frontier, receipt validation or allocation runs in this view.

use super::super::super::history::partials::{
    OriginalNativeImport18EnvelopePartialData, OriginalNativeImport18RawPartialData,
    OriginalNativeImport18ReceivedPartialData, envelope_partial_data, raw_partial_data,
    received_partial_data,
};
use super::*;

/// Borrows actual once bits and the complete lazy owner spine, including empty.
pub struct OriginalNativeImport18UploadBankPartialData<'a> {
    bank: &'a InputUploadBank,
    /// Borrows the actual spent-before-allocation bit.
    pub started: &'a bool,
    /// Borrows the actual sticky failure bit, independent of owner length.
    pub failed: &'a bool,
}

/// Borrows one real upload owner without checking success or ACK correspondence.
pub struct OriginalNativeImport18UploadOwnerPartialData<'a> {
    owner: &'a InputUpload,
    /// Names the actual retained stage.
    pub stage: &'static str,
    /// Borrows the seven actual role references, including unfilled slots.
    pub references: &'a [Option<ContentRef>; 7],
    /// Borrows the actual unique transfer IDs, including missing slots.
    pub transfers: &'a [Option<Id>; 7],
    /// Borrows the actual per-role byte offsets.
    pub offsets: &'a [usize; 7],
    /// Borrows the actual active role ordinal as modeled progress only.
    pub active: &'a usize,
    /// Borrows the selected actual outgoing chunk size.
    pub chunk: &'a usize,
    /// Borrows the retained negotiated receiver chunk ceiling.
    pub maximum_chunk: &'a usize,
    /// Borrows the literal completed Prepare request sequence, when retained.
    pub prepare_sequence: &'a U64,
    /// Borrows the literal Prepare response sequence.
    pub response_sequence: &'a U64,
    /// Borrows the retained transfer-token digest as modeled bytes only.
    pub token: &'a [u8; 32],
    /// Borrows actual nonrenewing terminal protocol progress, when retained.
    pub frontier: Option<OriginalNativeImport18FrontierPartialData<'a>>,
    /// Borrows the actual next-sequence partial without renewing a Session.
    pub next_sequence: &'a Option<U64>,
}

/// Borrows every literal/typed/raw slot from one actual attempted upload frame.
pub struct OriginalNativeImport18UploadFramePartialData<'a> {
    _frame: &'a UploadFrame,
    /// Borrows the exact role whose body this frame actually transfers.
    pub role: &'a PacketNativeImport18InputRole,
    /// Borrows the exact actual Blob method.
    pub method: &'a Method,
    /// Borrows the actual role-body byte offset.
    pub offset: &'a usize,
    /// Borrows the actual chunk/body extent.
    pub length: &'a usize,
    /// Borrows the assigned ID, including a retained failed original.
    pub request_id: &'a Id,
    /// Borrows the actual optional original and all body/extension operands.
    pub original: Option<OriginalNativeImport18EnvelopePartialData<'a>>,
    /// Borrows exact actual raw Value and bytes without normalization.
    pub raw: Option<OriginalNativeImport18RawPartialData<'a>>,
    /// Borrows the independent response literal, even on interpretation failure.
    pub response: Option<OriginalNativeImport18EnvelopePartialData<'a>>,
    /// Borrows any actual typed received variant without result filtering.
    pub received: Option<OriginalNativeImport18ReceivedPartialData<'a>>,
    /// Borrows the actual original publication attempt bit.
    pub attempted: &'a bool,
    /// Borrows the actual frame completion bit, never a bank-completion claim.
    pub complete: &'a bool,
}

/// Borrows actual nonrenewing ceilings/progress without live or capacity tokens.
pub struct OriginalNativeImport18FrontierPartialData<'a> {
    _frontier: &'a OriginalProtocolStorageFacts,
    /// Borrows the actual original frame byte ceiling.
    pub maximum_frame_bytes: &'a usize,
    /// Borrows the actual lifetime retained-history ceiling.
    pub maximum_history_bytes: &'a usize,
    /// Borrows the actual original per-direction frame ceiling.
    pub maximum_frames_per_direction: &'a usize,
    /// Borrows actual retained literal bytes at this saved frontier.
    pub retained_bytes: &'a usize,
    /// Borrows actual incoming lifetime frame usage.
    pub incoming_frames: &'a usize,
    /// Borrows actual outgoing lifetime frame usage.
    pub outgoing_frames: &'a usize,
    /// Borrows the actual I/O-completeness observation as DATA only.
    pub all_io_complete: &'a bool,
}

impl InputUploadBank {
    pub(in super::super::super) fn partial_history_data(
        &self,
    ) -> OriginalNativeImport18UploadBankPartialData<'_> {
        let Self {
            owners: _,
            started,
            failed,
        } = self;
        OriginalNativeImport18UploadBankPartialData {
            bank: self,
            started,
            failed,
        }
    }
}

impl<'a> OriginalNativeImport18UploadBankPartialData<'a> {
    /// Iterates every actual initialized owner in its retained order.
    pub fn owners_data(
        &self,
    ) -> impl ExactSizeIterator<Item = OriginalNativeImport18UploadOwnerPartialData<'a>> + 'a {
        self.bank
            .owners
            .iter()
            .map(owner_partial_data as OwnerMapper<'a>)
    }
}

impl<'a> OriginalNativeImport18UploadOwnerPartialData<'a> {
    /// Iterates all actual planned/attempted frames, including failed partials.
    pub fn frames_data(
        &self,
    ) -> impl ExactSizeIterator<Item = OriginalNativeImport18UploadFramePartialData<'a>> + 'a {
        self.owner
            .frames
            .iter()
            .map(frame_partial_data as FrameMapper<'a>)
    }
}

fn owner_partial_data(owner: &InputUpload) -> OriginalNativeImport18UploadOwnerPartialData<'_> {
    let InputUpload {
        stage,
        references,
        transfers,
        offsets,
        frames: _,
        active,
        chunk,
        maximum_chunk,
        cut: _,
        prepare_sequence,
        response_sequence,
        token,
        frontier,
        next_sequence,
    } = owner;
    let stage = match stage {
        UploadStage::Allocating => "allocating",
        UploadStage::Publishing => "publishing",
        UploadStage::RawReceived => "raw_received",
        UploadStage::Decoding => "decoding",
        UploadStage::Complete => "complete",
        UploadStage::Failed => "failed",
    };
    OriginalNativeImport18UploadOwnerPartialData {
        owner,
        stage,
        references,
        transfers,
        offsets,
        active,
        chunk,
        maximum_chunk,
        prepare_sequence,
        response_sequence,
        token,
        frontier: frontier.as_ref().map(frontier_partial_data),
        next_sequence,
    }
}

fn frame_partial_data(frame: &UploadFrame) -> OriginalNativeImport18UploadFramePartialData<'_> {
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
    } = frame;
    OriginalNativeImport18UploadFramePartialData {
        _frame: frame,
        role,
        method,
        offset,
        length,
        request_id,
        original: original.as_ref().map(envelope_partial_data),
        raw: raw.as_ref().map(raw_partial_data),
        response: response.as_ref().map(envelope_partial_data),
        received: received.as_ref().map(received_partial_data),
        attempted,
        complete,
    }
}

fn frontier_partial_data(
    frontier: &OriginalProtocolStorageFacts,
) -> OriginalNativeImport18FrontierPartialData<'_> {
    let OriginalProtocolStorageFacts {
        maximum_frame_bytes,
        maximum_history_bytes,
        maximum_frames_per_direction,
        retained_bytes,
        incoming_frames,
        outgoing_frames,
        all_io_complete,
        byte_capacity: _,
        descriptor_capacity: _,
        descriptor_bytes: _,
        allocated_bytes: _,
    } = frontier;
    OriginalNativeImport18FrontierPartialData {
        _frontier: frontier,
        maximum_frame_bytes,
        maximum_history_bytes,
        maximum_frames_per_direction,
        retained_bytes,
        incoming_frames,
        outgoing_frames,
        all_io_complete,
    }
}

type OwnerMapper<'a> = fn(&'a InputUpload) -> OriginalNativeImport18UploadOwnerPartialData<'a>;
type FrameMapper<'a> = fn(&'a UploadFrame) -> OriginalNativeImport18UploadFramePartialData<'a>;

pub(in super::super::super) fn counter_scratch_data() -> usize {
    size_of::<OriginalNativeImport18UploadBankPartialData<'static>>()
        + size_of::<OriginalNativeImport18UploadOwnerPartialData<'static>>()
        + size_of::<OriginalNativeImport18UploadFramePartialData<'static>>()
        + size_of::<OriginalNativeImport18FrontierPartialData<'static>>()
        + size_of::<Option<OriginalNativeImport18FrontierPartialData<'static>>>()
        + size_of::<std::slice::Iter<'static, InputUpload>>()
        + size_of::<std::slice::Iter<'static, UploadFrame>>()
        + size_of::<std::iter::Map<std::slice::Iter<'static, InputUpload>, OwnerMapper<'static>>>()
        + size_of::<std::iter::Map<std::slice::Iter<'static, UploadFrame>, FrameMapper<'static>>>()
        + size_of::<OwnerMapper<'static>>()
        + size_of::<FrameMapper<'static>>()
        + size_of::<Option<OriginalNativeImport18UploadOwnerPartialData<'static>>>()
        + size_of::<Option<OriginalNativeImport18UploadFramePartialData<'static>>>()
        + size_of::<&OriginalNativeImport18UploadBankPartialData<'static>>()
        + size_of::<&OriginalNativeImport18UploadOwnerPartialData<'static>>()
        + size_of::<Option<&InputUpload>>()
        + size_of::<Option<&UploadFrame>>()
        + size_of::<Option<&OriginalProtocolStorageFacts>>()
        + size_of::<&InputUploadBank>()
        + size_of::<&InputUpload>()
        + size_of::<&UploadFrame>()
        + size_of::<&UploadStage>()
        + size_of::<&OriginalProtocolStorageFacts>()
        + size_of::<&Option<OriginalProtocolStorageFacts>>()
        + size_of::<&[Option<ContentRef>; 7]>()
        + size_of::<&[Option<Id>; 7]>()
        + size_of::<&[usize; 7]>()
        + size_of::<&[u8; 32]>()
        + size_of::<&PacketNativeImport18InputRole>()
        + size_of::<&Method>()
        + size_of::<&Id>()
        // Owner sequence pair, frontier's six counters, and frame/bank flag
        // pairs are actual simultaneous destructure loans, not view donors.
        + size_of::<&U64>() * 2
        + size_of::<&Option<U64>>()
        + size_of::<&usize>() * 6
        + size_of::<&bool>() * 2
        + size_of::<&str>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_allocated_empty_spine_remains_distinct_from_unused_bank() {
        let mut bank = InputUploadBank::empty();
        bank.started = true;
        bank.failed = true;
        bank.owners.try_reserve_exact(1).unwrap();
        let before = bank.owners.capacity();

        let view = bank.partial_history_data();

        assert!(*view.started);
        assert!(*view.failed);
        assert_eq!(view.owners_data().len(), 0);
        assert!(bank.is_used());
        assert_eq!(bank.owners.capacity(), before);
    }
}
