//! Retains finite original incoming frames from a kernel-measured Unix probe.
//!
//! This process-local journal is not a qualification certificate. Only the
//! actual Unix receive path creates rows; decoding a report cannot recreate it.
//! Outgoing frames, including private Hello credentials, are never retained.
//! Incoming Hello replies can contain nonces or resumption credentials, so this
//! journal stays private. A public evidence exporter must select only the
//! source-authenticated nonsecret proof bodies rather than serialize all rows.

use std::cell::{Ref, RefCell};
use std::rc::Rc;

use crucible_node_contract::{ContentRef, canonical};

use super::EndpointMeasurement;
use crate::ProviderError;

const MAXIMUM_RECORDS: usize = 4096;
const MAXIMUM_BYTES: usize = 32 * 1024 * 1024;

/// Classifies the actual original receive without inventing a completed reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OriginalProbeResponseState {
    /// Reserves the original row before receiving; an unwind leaves it pending.
    Pending,
    /// Retains complete transport-validated original wire bytes.
    Received,
    /// Observes clean EOF before a new frame header.
    EndOfStream,
    /// Observes a read, framing or parsing failure without retrying that receive.
    Failed,
}

/// Borrows one original response and its independently measured kernel peer.
pub struct OriginalProbeResponse {
    peer: EndpointMeasurement,
    state: OriginalProbeResponseState,
    bytes: Vec<u8>,
    reference: Option<ContentRef>,
}

impl OriginalProbeResponse {
    /// Returns the actual peer measured before this connection was used.
    pub fn peer(&self) -> &EndpointMeasurement {
        &self.peer
    }

    /// Returns the original receive status, including unresolved attempts.
    pub fn state(&self) -> OriginalProbeResponseState {
        self.state
    }

    /// Borrows complete original validated frame bytes, when received.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Borrows the identity of the exact wire bytes, without canonical rewriting.
    pub fn reference(&self) -> Option<&ContentRef> {
        self.reference.as_ref()
    }
}

struct State {
    records: Vec<OriginalProbeResponse>,
    maximum_records: usize,
    remaining_bytes: usize,
    pending: bool,
    failed: bool,
}

/// Owns bounded original receive custody independently of serialized reports.
///
/// Construction is available only through a real [`super::UnixProbeConnector`].
/// The handle has no decoder or public row insertion. Its rows establish
/// original transport observations, not native readiness or class acceptance.
/// Incoming credentials remain under this private owner and must not be copied
/// into portable qualification reports or public evidence stores.
pub struct OriginalProbeResponses {
    state: Rc<RefCell<State>>,
}

impl OriginalProbeResponses {
    /// Borrows unchanged original rows without copying their body buffers.
    ///
    /// # Errors
    /// Refuses an overlapping mutable receive borrow. A pending or failed row
    /// remains visible and cannot be replaced with a later successful attempt.
    pub fn records(&self) -> Result<Ref<'_, [OriginalProbeResponse]>, ProviderError> {
        self.state
            .try_borrow()
            .map(|state| Ref::map(state, |state| state.records.as_slice()))
            .map_err(|_| ProviderError::Frame("original probe responses are in use"))
    }
}

#[derive(Clone)]
pub(super) struct Journal {
    state: Rc<RefCell<State>>,
}

impl Journal {
    pub(super) fn new(
        maximum_records: usize,
        maximum_bytes: usize,
    ) -> Result<(Self, OriginalProbeResponses), ProviderError> {
        if maximum_records == 0
            || maximum_records > MAXIMUM_RECORDS
            || maximum_bytes == 0
            || maximum_bytes > MAXIMUM_BYTES
        {
            return Err(ProviderError::ResourceExhausted(
                "original probe response limits",
            ));
        }
        let mut records = Vec::new();
        records.try_reserve_exact(maximum_records).map_err(|_| {
            ProviderError::ResourceExhausted("original probe response row allocation")
        })?;
        let state = Rc::new(RefCell::new(State {
            records,
            maximum_records,
            remaining_bytes: maximum_bytes,
            pending: false,
            failed: false,
        }));
        Ok((
            Self {
                state: Rc::clone(&state),
            },
            OriginalProbeResponses { state },
        ))
    }

    pub(super) fn reserve(
        &self,
        peer: &EndpointMeasurement,
        frame_bytes: usize,
    ) -> Result<usize, ProviderError> {
        let mut state = self
            .state
            .try_borrow_mut()
            .map_err(|_| ProviderError::Frame("original probe responses are in use"))?;
        if state.failed
            || state.pending
            || state.records.len() >= state.maximum_records
            || frame_bytes == 0
            || frame_bytes > state.remaining_bytes
        {
            state.failed = true;
            return Err(ProviderError::ResourceExhausted(
                "original probe response credit",
            ));
        }
        // Charge the entire negotiated incoming frame before its first read.
        // The preallocated row and peer identity remain owned across unwind.
        state.remaining_bytes -= frame_bytes;
        state.pending = true;
        state.records.push(OriginalProbeResponse {
            peer: peer.clone(),
            state: OriginalProbeResponseState::Pending,
            bytes: Vec::new(),
            reference: None,
        });
        Ok(state.records.len() - 1)
    }

    pub(super) fn complete(
        &self,
        index: usize,
        frame_credit: usize,
        bytes: Option<Vec<u8>>,
        failed: bool,
    ) -> Result<(), ProviderError> {
        let mut state = self
            .state
            .try_borrow_mut()
            .map_err(|_| ProviderError::Frame("original probe responses are in use"))?;
        let length = bytes.as_ref().map_or(0, Vec::len);
        if !state.pending || index + 1 != state.records.len() || length > frame_credit {
            return Err(ProviderError::Frame(
                "original probe receive identity differs",
            ));
        }
        let row = &mut state.records[index];
        if let Some(bytes) = bytes {
            // Move the actual retained transport body before deriving its CF;
            // any identity error leaves the original bytes and pending fence.
            row.bytes = bytes;
            row.reference = Some(canonical::content_ref(&row.bytes, "application/json")?);
            row.state = OriginalProbeResponseState::Received;
        } else {
            row.state = if failed {
                OriginalProbeResponseState::Failed
            } else {
                OriginalProbeResponseState::EndOfStream
            };
        }
        state.remaining_bytes += frame_credit - length;
        state.pending = false;
        state.failed = failed || row_end_of_stream(&state.records[index]);
        Ok(())
    }
}

fn row_end_of_stream(row: &OriginalProbeResponse) -> bool {
    row.state == OriginalProbeResponseState::EndOfStream
}

#[cfg(test)]
mod tests;
