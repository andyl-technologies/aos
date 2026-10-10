//! Incremental, original-account parsing of the read-only backing protocol.
//!
//! The stream contains a 64-byte `CRUCALL1` header, followed by each owner's
//! ID length, raw ID, 40-byte metadata and exact used backing bytes. This module
//! validates RAM-only material; it does not certify CPU, devices or aliases.
//! The transport owns the stopped-client binding and calls `finish` only after
//! actual stream EOF and a successful typed command reply.
//!
//! ```text
//! CRUCALL1 | schema/reserved | count/used/section/projection | correlation/stop
//! (id_len:u32 | id:bytes | flags/reserved/used/max/page/payload | payload)*
//! ```

use std::collections::TryReserveError;
use std::error::Error;
use std::fmt;
use std::io;

use crucible_cas::owned_decode::{DecodeAdmissionError, DecodeBudget, DecodeScratch};
use serde::{Deserialize, Serialize};

const MAX_OWNERS: u64 = 4096;
const MAX_FEED_BYTES: usize = 65536;

/// Describes the exact successful native RAM-only export receipt.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct QmpReadOnlyBackingReceipt {
    /// Identifies this receipt's wire edition, currently one.
    pub schema_version: u32,
    /// Correlates the stream with the same client's consumed request.
    pub request_correlation: u64,
    /// Identifies the actual ordinary completed stop used by the request.
    pub stopped_generation: u64,
    /// Counts all registered owners, including zero-used owners.
    pub owner_count: u64,
    /// Counts the direct used backing bytes across all owners.
    pub total_used: u64,
    /// Counts all owner framing, raw IDs and backing bytes.
    pub ram_section_bytes: u64,
    /// Remains zero for this RAM-only edition.
    pub readonly_projection_bytes: u64,
}

/// Consumes bounded transport chunks and the successful reply at factual EOF.
pub trait QmpReadOnlyBackingSink {
    /// Consumes one actual transport buffer slice.
    ///
    /// # Errors
    /// Refuses malformed material, original-account refusal or a visitor error.
    fn feed(&mut self, bytes: &[u8]) -> Result<(), QmpReadOnlyBackingStreamError>;

    /// Accepts a complete stream against its successful typed reply.
    ///
    /// # Errors
    /// Refuses truncation, receipt disagreement or any terminal/repeated call.
    fn finish(
        &mut self,
        receipt: &QmpReadOnlyBackingReceipt,
    ) -> Result<(), QmpReadOnlyBackingStreamError>;
}

/// Binds grammar to a consumed request and actual stop, never to an account.
#[derive(Clone, Copy, Debug)]
pub(crate) struct QmpReadOnlyBackingBinding {
    pub(crate) correlation: u64,
    pub(crate) generation: u64,
}

/// Borrows an owner's native observational metadata and raw identifier.
#[derive(Clone, Copy, Debug)]
pub struct BackingOwner<'a> {
    /// The nonempty raw native identifier, without its NUL terminator.
    pub id: &'a [u8],
    /// The independent public owner classification bits.
    pub classification: u32,
    /// The direct used backing extent in bytes.
    pub used: u64,
    /// The reported reserved maximum extent in bytes.
    pub maximum: u64,
    /// The reported native page-size metadata.
    pub page: u64,
}

/// Borrows owner metadata or an exact direct backing range from this chunk.
#[derive(Clone, Copy, Debug)]
pub enum BackingEvent<'a> {
    /// Reports one complete owner header before its backing payload.
    Owner(BackingOwner<'a>),
    /// Borrows the next contiguous direct range of one owner.
    Payload {
        /// Identifies the owner of this exact direct backing range.
        owner: BackingOwner<'a>,
        /// Gives the checked byte offset within the owner used extent.
        offset: u64,
        /// Borrows this transport-buffer slice only for the callback.
        bytes: &'a [u8],
    },
}

#[derive(Debug)]
enum PrimaryFailure {
    Protocol(&'static str),
    Original(DecodeAdmissionError),
    Visitor(io::Error),
}

struct FailureData {
    primary: Option<PrimaryFailure>,
    secondary: Option<DecodeAdmissionError>,
}

/// Retains the prepared diagnostic storage until its actual allocation closes.
///
/// Visitor diagnostic payloads require their own caller custody. This owner
/// covers its fixed slot and same saved account, not arbitrary IO payloads.
pub struct QmpReadOnlyBackingFailure {
    data: Vec<FailureData>,
    _credit: DecodeScratch,
}

impl QmpReadOnlyBackingFailure {
    /// Borrows an independently observed original refusal after the first error.
    pub fn original_secondary(&self) -> Option<&DecodeAdmissionError> {
        self.data.first().and_then(|data| data.secondary.as_ref())
    }
}

impl Drop for QmpReadOnlyBackingFailure {
    fn drop(&mut self) {
        drop(std::mem::take(&mut self.data));
    }
}

impl fmt::Debug for QmpReadOnlyBackingFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QmpReadOnlyBackingFailure")
            .field(
                "primary",
                &self.data.first().and_then(|data| data.primary.as_ref()),
            )
            .field("secondary", &self.original_secondary())
            .finish()
    }
}

impl fmt::Display for QmpReadOnlyBackingFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.data.first().and_then(|data| data.primary.as_ref()) {
            Some(PrimaryFailure::Protocol(message)) => formatter.write_str(message),
            Some(PrimaryFailure::Original(error)) => error.fmt(formatter),
            Some(PrimaryFailure::Visitor(error)) => error.fmt(formatter),
            None => formatter.write_str("backing stream failure slot is empty"),
        }
    }
}

impl Error for QmpReadOnlyBackingFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self.data.first().and_then(|data| data.primary.as_ref()) {
            Some(PrimaryFailure::Original(error)) => Some(error),
            Some(PrimaryFailure::Visitor(error)) => Some(error),
            _ => None,
        }
    }
}

/// Preserves the first stream error without allocating a replacement on refusal.
#[derive(Debug)]
pub enum QmpReadOnlyBackingStreamError {
    /// Preserves an original refusal before parser construction completes.
    Admission(DecodeAdmissionError),
    /// Preserves a fallible allocation error during prepaid construction.
    Allocation(TryReserveError),
    /// Retains the prepared first-error slot and its same-account credit.
    Failure(QmpReadOnlyBackingFailure),
    /// Refuses reuse after completion or after the first failure was returned.
    Terminal,
}

impl fmt::Display for QmpReadOnlyBackingStreamError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Admission(error) => error.fmt(formatter),
            Self::Allocation(error) => error.fmt(formatter),
            Self::Failure(error) => error.fmt(formatter),
            Self::Terminal => formatter.write_str("backing stream is terminal"),
        }
    }
}

impl Error for QmpReadOnlyBackingStreamError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Admission(error) => Some(error),
            Self::Allocation(error) => Some(error),
            Self::Failure(error) => Some(error),
            Self::Terminal => None,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Stage {
    Header,
    Length,
    Id,
    Metadata,
    Payload,
    Done,
}

struct State {
    stage: Stage,
    filled: usize,
    header: [u8; 64],
    length: [u8; 4],
    id: [u8; 255],
    previous_id: [u8; 255],
    id_length: usize,
    previous_length: usize,
    metadata: [u8; 40],
    receipt: QmpReadOnlyBackingReceipt,
    owners: u64,
    section: u64,
    used: u64,
    payload_offset: u64,
}

impl State {
    fn new() -> Self {
        Self {
            stage: Stage::Header,
            filled: 0,
            header: [0; 64],
            length: [0; 4],
            id: [0; 255],
            previous_id: [0; 255],
            id_length: 0,
            previous_length: 0,
            metadata: [0; 40],
            receipt: QmpReadOnlyBackingReceipt {
                schema_version: 0,
                request_correlation: 0,
                stopped_generation: 0,
                owner_count: 0,
                total_used: 0,
                ram_section_bytes: 0,
                readonly_projection_bytes: 0,
            },
            owners: 0,
            section: 0,
            used: 0,
            payload_offset: 0,
        }
    }

    fn owner(&self) -> BackingOwner<'_> {
        BackingOwner {
            id: &self.id[..self.id_length],
            classification: u32_at(&self.metadata, 0),
            used: u64_at(&self.metadata, 8),
            maximum: u64_at(&self.metadata, 16),
            page: u64_at(&self.metadata, 24),
        }
    }

    fn complete_owner(&mut self) {
        self.previous_id[..self.id_length].copy_from_slice(&self.id[..self.id_length]);
        self.previous_length = self.id_length;
        self.owners += 1;
        self.filled = 0;
        self.stage = if self.owners == self.receipt.owner_count {
            Stage::Done
        } else {
            Stage::Length
        };
    }

    fn add_section(&mut self, count: usize) -> Result<(), PrimaryFailure> {
        self.section = self
            .section
            .checked_add(count as u64)
            .filter(|count| *count <= self.receipt.ram_section_bytes)
            .ok_or(PrimaryFailure::Protocol(
                "backing section length exceeds header",
            ))?;
        Ok(())
    }
}

/// Keeps prepaid fixed parser state and a borrowed same-account visitor.
///
/// Construction is crate-private until the real same-process transport purpose
/// supplies the original. Its inline control and callback belong to that owner;
/// a synthetic binding does not grant observation or process authority.
pub(crate) struct QmpReadOnlyBackingParser<'a, F> {
    original: &'a DecodeBudget,
    binding: QmpReadOnlyBackingBinding,
    state: Vec<State>,
    _state_credit: DecodeScratch,
    failure: Option<QmpReadOnlyBackingFailure>,
    visitor: F,
    terminal: bool,
}

impl<'a, F> QmpReadOnlyBackingParser<'a, F>
where
    F: for<'event> FnMut(BackingEvent<'event>) -> Result<(), io::Error>,
{
    pub(crate) fn prepare(
        original: &'a DecodeBudget,
        binding: &QmpReadOnlyBackingBinding,
        visitor: F,
    ) -> Result<Self, QmpReadOnlyBackingStreamError> {
        live(original).map_err(QmpReadOnlyBackingStreamError::Admission)?;
        let state_credit = original
            .reserve_scratch_array::<State>(1)
            .map_err(QmpReadOnlyBackingStreamError::Admission)?;
        let mut state = Vec::new();
        state
            .try_reserve_exact(1)
            .map_err(QmpReadOnlyBackingStreamError::Allocation)?;
        state.push(State::new());

        let credit = original
            .reserve_scratch_array::<FailureData>(1)
            .map_err(QmpReadOnlyBackingStreamError::Admission)?;
        let mut data = Vec::new();
        data.try_reserve_exact(1)
            .map_err(QmpReadOnlyBackingStreamError::Allocation)?;
        data.push(FailureData {
            primary: None,
            secondary: None,
        });

        Ok(Self {
            original,
            binding: *binding,
            state,
            _state_credit: state_credit,
            failure: Some(QmpReadOnlyBackingFailure {
                data,
                _credit: credit,
            }),
            visitor,
            terminal: false,
        })
    }

    fn fail(&mut self, primary: PrimaryFailure) -> QmpReadOnlyBackingStreamError {
        self.terminal = true;
        let secondary = live(self.original).err();
        match self.failure.take() {
            Some(mut failure) => {
                if let Some(data) = failure.data.first_mut() {
                    data.primary = Some(primary);
                    data.secondary = secondary;
                }
                QmpReadOnlyBackingStreamError::Failure(failure)
            }
            None => QmpReadOnlyBackingStreamError::Terminal,
        }
    }

    fn consume(&mut self, mut input: &[u8]) -> Result<(), PrimaryFailure> {
        while !input.is_empty() {
            live(self.original).map_err(PrimaryFailure::Original)?;
            let state = &mut self.state[0];
            if state.stage == Stage::Done {
                return Err(PrimaryFailure::Protocol("trailing backing bytes"));
            }
            if state.stage == Stage::Payload {
                let owner = state.owner();
                let remaining = owner.used - state.payload_offset;
                let count = usize::try_from(remaining.min(input.len() as u64))
                    .map_err(|_| PrimaryFailure::Protocol("backing payload width overflow"))?;
                (self.visitor)(BackingEvent::Payload {
                    owner,
                    offset: state.payload_offset,
                    bytes: &input[..count],
                })
                .map_err(PrimaryFailure::Visitor)?;
                live(self.original).map_err(PrimaryFailure::Original)?;
                state.payload_offset += count as u64;
                state.add_section(count)?;
                input = &input[count..];
                if state.payload_offset == state.owner().used {
                    state.complete_owner();
                }
                continue;
            }

            let target = match state.stage {
                Stage::Header => &mut state.header[..],
                Stage::Length => &mut state.length[..],
                Stage::Id => &mut state.id[..state.id_length],
                Stage::Metadata => &mut state.metadata[..],
                Stage::Payload | Stage::Done => unreachable!(),
            };
            let count = (target.len() - state.filled).min(input.len());
            target[state.filled..state.filled + count].copy_from_slice(&input[..count]);
            state.filled += count;
            if state.stage != Stage::Header {
                state.add_section(count)?;
            }
            input = &input[count..];
            if state.filled != target_length(state) {
                continue;
            }
            state.filled = 0;

            match state.stage {
                Stage::Header => accept_header(state, self.binding)?,
                Stage::Length => {
                    let length = u32::from_le_bytes(state.length) as usize;
                    if !(1..=255).contains(&length) {
                        return Err(PrimaryFailure::Protocol("invalid backing ID length"));
                    }
                    state.id_length = length;
                    state.stage = Stage::Id;
                }
                Stage::Id => {
                    let id = &state.id[..state.id_length];
                    if id.contains(&0)
                        || (state.owners != 0 && id <= &state.previous_id[..state.previous_length])
                    {
                        return Err(PrimaryFailure::Protocol("invalid backing ID order"));
                    }
                    state.stage = Stage::Metadata;
                }
                Stage::Metadata => {
                    let owner = state.owner();
                    if state
                        .section
                        .checked_add(owner.used)
                        .is_none_or(|end| end > state.receipt.ram_section_bytes)
                        || owner.classification & !0x0f != 0
                        || u32_at(&state.metadata, 4) != 0
                        || owner.used > owner.maximum
                        || u64_at(&state.metadata, 32) != owner.used
                    {
                        return Err(PrimaryFailure::Protocol("invalid backing owner extent"));
                    }
                    state.used = state
                        .used
                        .checked_add(owner.used)
                        .filter(|used| *used <= state.receipt.total_used)
                        .ok_or(PrimaryFailure::Protocol(
                            "backing used total exceeds header",
                        ))?;
                    (self.visitor)(BackingEvent::Owner(state.owner()))
                        .map_err(PrimaryFailure::Visitor)?;
                    live(self.original).map_err(PrimaryFailure::Original)?;
                    state.payload_offset = 0;
                    if state.owner().used == 0 {
                        state.complete_owner();
                    } else {
                        state.stage = Stage::Payload;
                    }
                }
                Stage::Payload | Stage::Done => unreachable!(),
            }
        }
        Ok(())
    }
}

impl<F> Drop for QmpReadOnlyBackingParser<'_, F> {
    fn drop(&mut self) {
        drop(std::mem::take(&mut self.state));
    }
}

impl<F> QmpReadOnlyBackingSink for QmpReadOnlyBackingParser<'_, F>
where
    F: for<'event> FnMut(BackingEvent<'event>) -> Result<(), io::Error>,
{
    fn feed(&mut self, bytes: &[u8]) -> Result<(), QmpReadOnlyBackingStreamError> {
        if self.terminal {
            return Err(QmpReadOnlyBackingStreamError::Terminal);
        }
        let result = live(self.original)
            .map_err(PrimaryFailure::Original)
            .and_then(|()| {
                if bytes.len() > MAX_FEED_BYTES {
                    return Err(PrimaryFailure::Protocol(
                        "backing chunk exceeds transport bound",
                    ));
                }
                self.consume(bytes)
            });
        result.map_err(|error| self.fail(error))
    }

    fn finish(
        &mut self,
        receipt: &QmpReadOnlyBackingReceipt,
    ) -> Result<(), QmpReadOnlyBackingStreamError> {
        if self.terminal {
            return Err(QmpReadOnlyBackingStreamError::Terminal);
        }
        let result = live(self.original)
            .map_err(PrimaryFailure::Original)
            .and_then(|()| {
                let state = &self.state[0];
                if state.stage != Stage::Done
                    || state.receipt != *receipt
                    || state.owners != receipt.owner_count
                    || state.used != receipt.total_used
                    || state.section != receipt.ram_section_bytes
                {
                    return Err(PrimaryFailure::Protocol("backing EOF or receipt mismatch"));
                }
                live(self.original).map_err(PrimaryFailure::Original)
            });
        match result {
            Err(error) => Err(self.fail(error)),
            Ok(()) => {
                self.terminal = true;
                drop(self.failure.take());
                Ok(())
            }
        }
    }
}

fn live(original: &DecodeBudget) -> Result<(), DecodeAdmissionError> {
    match original.verify_live() {
        Ok(()) => Ok(()),
        Err(error) => {
            original.record_failure(error.clone());
            Err(error)
        }
    }
}

fn accept_header(
    state: &mut State,
    binding: QmpReadOnlyBackingBinding,
) -> Result<(), PrimaryFailure> {
    let header = &state.header;
    let receipt = QmpReadOnlyBackingReceipt {
        schema_version: u32_at(header, 8),
        owner_count: u64_at(header, 16),
        total_used: u64_at(header, 24),
        ram_section_bytes: u64_at(header, 32),
        readonly_projection_bytes: u64_at(header, 40),
        request_correlation: u64_at(header, 48),
        stopped_generation: u64_at(header, 56),
    };
    if &header[..8] != b"CRUCALL1"
        || receipt.schema_version != 1
        || u32_at(header, 12) != 0
        || receipt.owner_count > MAX_OWNERS
        || receipt.readonly_projection_bytes != 0
        || receipt.request_correlation == 0
        || receipt.request_correlation != binding.correlation
        || matches!(receipt.stopped_generation, 0 | u64::MAX)
        || receipt.stopped_generation != binding.generation
        || receipt
            .owner_count
            .checked_mul(45)
            .is_none_or(|minimum| minimum > receipt.ram_section_bytes)
        || receipt.ram_section_bytes < receipt.total_used
        || (receipt.owner_count == 0 && (receipt.ram_section_bytes != 0 || receipt.total_used != 0))
    {
        return Err(PrimaryFailure::Protocol("invalid backing header"));
    }
    state.receipt = receipt;
    state.stage = if receipt.owner_count == 0 {
        Stage::Done
    } else {
        Stage::Length
    };
    Ok(())
}

fn target_length(state: &State) -> usize {
    match state.stage {
        Stage::Header => 64,
        Stage::Length => 4,
        Stage::Id => state.id_length,
        Stage::Metadata => 40,
        Stage::Payload | Stage::Done => 0,
    }
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    let mut value = [0; 4];
    value.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(value)
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    let mut value = [0; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(value)
}

#[cfg(test)]
mod tests;
