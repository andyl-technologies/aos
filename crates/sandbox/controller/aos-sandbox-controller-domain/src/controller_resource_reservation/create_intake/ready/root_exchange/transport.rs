//! Retains the original Controller Root stream and every reached byte flight.
//!
//! This mechanical owner neither chooses a peer nor admits receiving work.
//! Its sole caller is the genuine same-J RootExchange loan after fixed/actual
//! admission. A failed socket/adoption/read/write remains in this same owner.

use std::error::Error;

use aos_linux_descriptors::unix_stream::RetainedUnixStream;
use crate::normal_root::ControllerRootConnectionOriginalV1;
use aos_sandbox_protocol::domain_ledger::create_q04_history::CLAIM_CHUNK_BYTES;
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HistoryErrorV1, root_open::{RootHelloDataV1, RootOpenBodyDataV1, ROOT_HELLO_FRAME_BYTES_V1},
    transport::{OpenQueryV1, TransferIndexV1, FrameCoordinatesV1, FrameKindV1, OPEN_BYTES,
        FRAME_HEADER_BYTES, INDEX_BYTES, CHUNK_HEADER_BYTES},
};
use aos_sandbox_broker::bounded_stream_io::FixedDeadlineStreamIoV1;
use aos_sandbox_broker::bounded_stream_io::DeadlineStreamDirectionV1;

const INDEX_FRAME: usize = FRAME_HEADER_BYTES + INDEX_BYTES;
const CHUNK_FRAME: usize = FRAME_HEADER_BYTES + CHUNK_HEADER_BYTES + CLAIM_CHUNK_BYTES;

pub(super) struct ControllerRootTransportOriginalsV1 {
    connection: ControllerRootConnectionOriginalV1,
    open: [u8; OPEN_BYTES],
    open_encoding: Option<Result<(), HistoryErrorV1>>,
    sent_open: FixedDeadlineStreamIoV1<OPEN_BYTES>,
    hello: [u8; ROOT_HELLO_FRAME_BYTES_V1],
    decoded_hello: Option<Result<RootOpenBodyDataV1, HistoryErrorV1>>,
    index: Option<Result<TransferIndexV1, HistoryErrorV1>>,
    index_frame: [u8; INDEX_FRAME],
    index_encoding: Option<Result<(), HistoryErrorV1>>,
    sent_index: FixedDeadlineStreamIoV1<INDEX_FRAME>,
    chunk: [u8; CHUNK_FRAME],
    chunk_encoding: Option<Result<usize, HistoryErrorV1>>,
    sent_chunk: Option<FixedDeadlineStreamIoV1<CHUNK_FRAME>>,
    next_chunk: u32,
}

impl Default for ControllerRootTransportOriginalsV1 {
    fn default() -> Self {
        Self { connection: Default::default(),
            open: [0; OPEN_BYTES], open_encoding: None, sent_open: Default::default(),
            hello: [0; ROOT_HELLO_FRAME_BYTES_V1], decoded_hello: None,
            index: None, index_frame: [0; INDEX_FRAME], index_encoding: None, sent_index: Default::default(),
            chunk: [0; CHUNK_FRAME], chunk_encoding: None, sent_chunk: None, next_chunk: 0 }
    }
}

impl ControllerRootTransportOriginalsV1 {
    pub(super) fn connect_once(&mut self) -> Result<(), HistoryErrorV1> {
        self.connection.connect_once()
    }

    pub(super) fn stream(&self) -> Result<&RetainedUnixStream, HistoryErrorV1> { self.connection.stream() }

    pub(super) fn send_open_once(&mut self, open: OpenQueryV1, cutoff: u64) -> Result<(), HistoryErrorV1> {
        if self.open_encoding.is_some() { return Err(HistoryErrorV1::Correlation); }
        self.open_encoding = Some(open.encode().map(|bytes| self.open = bytes));
        positive(&self.open_encoding)?;
        let stream = self.connection.stream_mut()?;
        self.sent_open.run_once(stream, &mut self.open, cutoff, DeadlineStreamDirectionV1::Write)
    }

    pub(super) fn accept_hello_once(&mut self, bytes: &[u8], open: OpenQueryV1) -> Result<(), HistoryErrorV1> {
        if self.decoded_hello.is_some() || bytes.len() != self.hello.len() { return Err(HistoryErrorV1::Correlation); }
        self.hello.copy_from_slice(bytes);
        self.decoded_hello = Some(RootHelloDataV1::decode(&self.hello, open).map(|hello| hello.body));
        positive(&self.decoded_hello).map(|_| ())
    }

    pub(super) fn stream_mut(&mut self) -> Result<&mut RetainedUnixStream, HistoryErrorV1> {
        self.connection.stream_mut()
    }

    pub(super) fn hello_frame(&self) -> &[u8; ROOT_HELLO_FRAME_BYTES_V1] { &self.hello }

    pub(super) fn hello_body(&self) -> Result<&RootOpenBodyDataV1, HistoryErrorV1> { positive(&self.decoded_hello) }

    pub(super) fn send_index_once(&mut self, bytes: &[u8], cutoff: u64) -> Result<(), HistoryErrorV1> {
        if self.index.is_some() { return Err(HistoryErrorV1::Correlation); }
        let hello = *self.hello_body()?;
        self.index = Some(u64::try_from(bytes.len()).map_err(|_| HistoryErrorV1::Extent).and_then(|width|
            TransferIndexV1::new(width, hello.open.ready)));
        let index = *positive(&self.index)?;
        self.index_encoding = Some((|| {
            let payload = index.encode();
            let header = coordinates(hello, FrameKindV1::ReadyIndex, 2).encode_header(&payload)?;
            self.index_frame[..FRAME_HEADER_BYTES].copy_from_slice(&header);
            self.index_frame[FRAME_HEADER_BYTES..].copy_from_slice(&payload);
            Ok(())
        })());
        positive(&self.index_encoding)?;
        let stream = self.connection.stream_mut()?;
        self.sent_index.run_once(stream, &mut self.index_frame, cutoff, DeadlineStreamDirectionV1::Write)
    }

    pub(super) fn send_next_chunk_once(&mut self, bytes: &[u8], cutoff: u64) -> Result<(), HistoryErrorV1> {
        if self.sent_chunk.is_some() { return Err(HistoryErrorV1::Correlation); }
        let hello = *self.hello_body()?;
        let index = *positive(&self.index)?;
        self.chunk_encoding = Some((|| {
            let offset = usize::try_from(self.next_chunk).ok().and_then(|value| value.checked_mul(CLAIM_CHUNK_BYTES))
                .ok_or(HistoryErrorV1::Extent)?;
            let remaining = bytes.len().checked_sub(offset).ok_or(HistoryErrorV1::Extent)?;
            let payload = bytes.get(offset..offset + remaining.min(CLAIM_CHUNK_BYTES)).ok_or(HistoryErrorV1::Extent)?;
            let chunk_header = index.encode_chunk_header(self.next_chunk, payload)?;
            let length = CHUNK_HEADER_BYTES.checked_add(payload.len()).ok_or(HistoryErrorV1::Extent)?;
            self.chunk[FRAME_HEADER_BYTES..FRAME_HEADER_BYTES + CHUNK_HEADER_BYTES].copy_from_slice(&chunk_header);
            self.chunk[FRAME_HEADER_BYTES + CHUNK_HEADER_BYTES..FRAME_HEADER_BYTES + length].copy_from_slice(payload);
            let header = coordinates(hello, FrameKindV1::ReadyChunk, u64::from(self.next_chunk) + 3)
                .encode_header(&self.chunk[FRAME_HEADER_BYTES..FRAME_HEADER_BYTES + length])?;
            self.chunk[..FRAME_HEADER_BYTES].copy_from_slice(&header);
            FRAME_HEADER_BYTES.checked_add(length).ok_or(HistoryErrorV1::Extent)
        })());
        let length = *positive(&self.chunk_encoding)?;
        self.sent_chunk = Some(Default::default());
        let stream = self.connection.stream_mut()?;
        self.sent_chunk.as_mut().ok_or(HistoryErrorV1::Correlation)?.run_prefix_once(stream, &mut self.chunk,
            length, cutoff, DeadlineStreamDirectionV1::Write)
    }

    // The genuine outer loan invokes this only after the actual whole peer,
    // Controller/Source/Cache/clock posts. A failed IO capsule is never cleared.
    pub(super) fn dispose_positive_chunk_once(&mut self) -> Result<(), HistoryErrorV1> {
        let io = self.sent_chunk.as_ref().ok_or(HistoryErrorV1::Correlation)?;
        if !io.completed_exact() || io.failure().is_some() { return Err(HistoryErrorV1::Correlation); }
        let next = self.next_chunk.checked_add(1).ok_or(HistoryErrorV1::Extent)?;
        let index = positive(&self.index)?;
        if next > index.count() { return Err(HistoryErrorV1::Correlation); }
        drop(self.sent_chunk.take());
        self.chunk_encoding = None;
        self.next_chunk = next;
        Ok(())
    }

    pub(super) fn completed_index(&self) -> Result<TransferIndexV1, HistoryErrorV1> {
        if !self.ready_sent() { return Err(HistoryErrorV1::Correlation); }
        positive(&self.index).copied()
    }

    pub(super) fn ready_sent(&self) -> bool {
        self.failure().is_none() && self.index.as_ref().and_then(|value| value.as_ref().ok())
            .is_some_and(|index| self.next_chunk == index.count()) && self.sent_chunk.is_none()
    }

    pub(super) fn open_attempted(&self) -> bool { self.open_encoding.is_some() }
    pub(super) fn hello_attempted(&self) -> bool { self.decoded_hello.is_some() }
    pub(super) fn index_attempted(&self) -> bool { self.index.is_some() }
    pub(super) fn chunk_attempted(&self) -> bool { self.chunk_encoding.is_some() }

    pub(super) fn receiving_metadata_cells_v1() -> Option<usize> {
        // Frame, cursor and IO-result storage contributes bytes, not names.
        Some(0)
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.connection.failure()
            .or_else(|| cause(&self.open_encoding)).or_else(|| self.sent_open.failure())
            .or_else(|| cause(&self.decoded_hello))
            .or_else(|| cause(&self.index)).or_else(|| cause(&self.index_encoding))
            .or_else(|| self.sent_index.failure()).or_else(|| cause(&self.chunk_encoding))
            .or_else(|| self.sent_chunk.as_ref().and_then(|io| io.failure()))
    }
}

fn coordinates(hello: RootOpenBodyDataV1, kind: FrameKindV1, sequence: u64) -> FrameCoordinatesV1 {
    FrameCoordinatesV1 { kind, lane: hello.open.lane, sequence,
        root_nonce: hello.root_nonce, controller_nonce: hello.open.controller_nonce }
}

fn positive<T, E>(slot: &Option<Result<T, E>>) -> Result<&T, HistoryErrorV1> {
    slot.as_ref().and_then(|value| value.as_ref().ok()).ok_or(HistoryErrorV1::Correlation)
}

fn cause<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
}
