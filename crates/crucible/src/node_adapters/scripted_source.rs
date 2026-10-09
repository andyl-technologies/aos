//! Finite immutable request scripts and their exact owned execution cursor.
//!
//! The script codec contains a kind byte, bounded event count, and ordered
//! little-endian `(time_ps, payload_length, payload)` records. Continuations
//! retain that complete immutable script, the first unexecuted event, and the
//! administrative native clock. Publication and acknowledgement custody belong
//! to the surrounding `HostModelNode` continuation, rather than this cursor.

use crucible_device::block::BlockRequest;
use crucible_node_contract::{ContentRef, Phase, Position, canonical};

use crate::node_contract::OperationFailure;

use super::host::failure;

#[cfg(test)]
#[path = "scripted_source_tests.rs"]
mod tests;

const SCRIPT_PREFIX: &[u8] = b"crucible.scripted-requests.v1\0";
const STATE_PREFIX: &[u8] = b"crucible.scripted-cursor.v1\0";
// Both installed request lanes use the native device framing ceiling. Obtain
// it through the device codec so this host adapter needs no transport dependency.
const MAXIMUM_REQUEST_BYTES: usize =
    crucible_device::block::device::MAX_READ_BYTES + crucible_device::block::RESPONSE_HEADER_LEN;

type ScriptedOutput = ((u64, u32, u32), Vec<u8>);

/// Bounds the entire immutable script, including requests sharing an instant.
pub const MAXIMUM_SCRIPTED_REQUESTS: usize = 16;

/// Selects the actual native public request decoder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScriptedRequestKind {
    /// Publishes complete original `BlockRequest` frames.
    Block,
    /// Publishes complete original 9P2000.L request frames.
    Ninep,
}

/// Contains an immutable request evaluated at reaction microstep zero.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScriptedRequest {
    /// Gives the exact evaluation instant in virtual picoseconds.
    pub time_ps: u64,
    /// Retains the complete original public request octets.
    pub payload: Vec<u8>,
}

/// Owns the complete finite future request inventory and first unexecuted cursor.
///
/// No input port, background thread, cancellation, fault, or external ingress
/// exists in this profile. Equal-time requests preserve their script order.
pub struct ScriptedSource {
    kind: ScriptedRequestKind,
    requests: Vec<ScriptedRequest>,
    payload_refs: Vec<ContentRef>,
    cursor: usize,
    time_ps: u64,
    evaluated: bool,
}

impl ScriptedSource {
    /// Constructs a validated finite public request source at its initial cut.
    ///
    /// # Errors
    /// Refuses empty or excessive inventories, decreasing times, malformed
    /// request frames, oversized payloads, or unrepresentable response geometry.
    pub fn new(
        kind: ScriptedRequestKind,
        requests: Vec<ScriptedRequest>,
    ) -> Result<Self, OperationFailure> {
        if requests.is_empty() || requests.len() > MAXIMUM_SCRIPTED_REQUESTS {
            return Err(failure(
                "script request inventory is empty or exceeds its finite ceiling",
            ));
        }
        if requests
            .windows(2)
            .any(|pair| pair[0].time_ps > pair[1].time_ps)
        {
            return Err(failure("script request instants are not ordered"));
        }
        let mut payload_refs = Vec::with_capacity(requests.len());
        for request in &requests {
            validate_request(kind, &request.payload)?;
            payload_refs.push(
                canonical::content_ref(&request.payload, "application/octet-stream")
                    .map_err(|error| failure(&error.to_string()))?,
            );
        }
        Ok(Self {
            kind,
            requests,
            payload_refs,
            cursor: 0,
            time_ps: 0,
            evaluated: false,
        })
    }

    /// Decodes the closed immutable script without executing any request.
    ///
    /// # Errors
    /// Refuses unknown editions, unsupported kinds, malformed lengths, trailing
    /// data, or any native request inventory rejected by [`Self::new`].
    pub fn from_script_bytes(bytes: &[u8]) -> Result<Self, OperationFailure> {
        let mut input = bytes
            .strip_prefix(SCRIPT_PREFIX)
            .ok_or_else(|| failure("unsupported scripted request edition"))?;
        let kind = match take::<1>(&mut input)?[0] {
            1 => ScriptedRequestKind::Block,
            2 => ScriptedRequestKind::Ninep,
            _ => return Err(failure("unsupported scripted request decoder")),
        };
        let count = usize::from(take::<1>(&mut input)?[0]);
        if count == 0 || count > MAXIMUM_SCRIPTED_REQUESTS {
            return Err(failure("script event count exceeds its finite ceiling"));
        }
        let mut requests = Vec::with_capacity(count);
        for _ in 0..count {
            let time_ps = u64::from_le_bytes(take::<8>(&mut input)?);
            let length = usize::try_from(u32::from_le_bytes(take::<4>(&mut input)?))
                .map_err(|error| failure(&error.to_string()))?;
            if length > MAXIMUM_REQUEST_BYTES || input.len() < length {
                return Err(failure(
                    "script payload length exceeds actual bounded bytes",
                ));
            }
            let (payload, remaining) = input.split_at(length);
            requests.push(ScriptedRequest {
                time_ps,
                payload: payload.to_vec(),
            });
            input = remaining;
        }
        if !input.is_empty() {
            return Err(failure("script has trailing bytes"));
        }
        Self::new(kind, requests)
    }

    /// Reconstructs native cursor data against an independently installed script.
    ///
    /// This bounded structural constructor authenticates neither saved source
    /// lineage nor activation. Installed archive qualification must separately
    /// verify complete original host, coordinator and connection custody before
    /// the reconstructed model can acquire execution authority.
    ///
    /// # Errors
    /// Refuses unsupported script or continuation editions, changed immutable
    /// futures, impossible cursor/evaluation states, malformed lengths or clocks
    /// that skip remaining requests.
    pub fn from_continuation(
        installed_script: &[u8],
        native: &[u8],
    ) -> Result<Self, OperationFailure> {
        let mut source = Self::from_script_bytes(installed_script)?;
        source.restore(native)?;
        Ok(source)
    }

    /// Encodes the complete original immutable script in its canonical edition.
    ///
    /// # Errors
    /// Refuses event counts or payload lengths outside the bounded codec geometry.
    pub fn script_bytes(&self) -> Result<Vec<u8>, OperationFailure> {
        let mut bytes = SCRIPT_PREFIX.to_vec();
        bytes.push(match self.kind {
            ScriptedRequestKind::Block => 1,
            ScriptedRequestKind::Ninep => 2,
        });
        bytes.push(u8::try_from(self.requests.len()).map_err(|error| failure(&error.to_string()))?);
        for request in &self.requests {
            bytes.extend_from_slice(&request.time_ps.to_le_bytes());
            let length = u32::try_from(request.payload.len())
                .map_err(|error| failure(&error.to_string()))?;
            bytes.extend_from_slice(&length.to_le_bytes());
            bytes.extend_from_slice(&request.payload);
        }
        Ok(bytes)
    }

    /// Returns the installed request decoder.
    pub fn kind(&self) -> ScriptedRequestKind {
        self.kind
    }

    /// Borrows the entire original ordered immutable request inventory.
    pub fn requests(&self) -> &[ScriptedRequest] {
        &self.requests
    }

    /// Borrows the independently verified identity of each original payload.
    pub fn payload_refs(&self) -> &[ContentRef] {
        &self.payload_refs
    }

    /// Returns the first request not yet evaluated by the native source.
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// Returns the administrative native clock at the last completed grant.
    pub fn time_ps(&self) -> u64 {
        self.time_ps
    }

    pub(super) fn next_time(&self) -> Option<u64> {
        self.requests
            .get(self.cursor)
            .map(|request| request.time_ps)
    }

    pub(super) fn next_position(&self) -> Option<Position> {
        self.next_time().map(|time| {
            Position::new(
                time.into(),
                u64::from(self.evaluated).into(),
                if self.evaluated {
                    Phase::Publication
                } else {
                    Phase::Reaction
                },
            )
        })
    }

    pub(super) fn evaluate(&mut self) {
        self.evaluated = true;
    }

    pub(super) fn evaluated(&self) -> bool {
        self.evaluated
    }

    pub(super) fn publish_due(&mut self, time: u64) -> Vec<ScriptedOutput> {
        let mut outputs = Vec::new();
        while let Some(request) = self.requests.get(self.cursor) {
            if request.time_ps != time {
                break;
            }
            // Construction bounds the cursor by sixteen requests. Its native
            // sequence is stable across both retries and cold reconstruction.
            let sequence = u32::from(self.cursor as u8);
            outputs.push(((time, 0, sequence), request.payload.clone()));
            self.cursor += 1;
        }
        self.evaluated = false;
        outputs
    }

    pub(super) fn park(&mut self, time: u64) -> Result<(), OperationFailure> {
        if time < self.time_ps || self.next_time().is_some_and(|next| next < time) {
            return Err(failure(
                "source parking would skip original future requests",
            ));
        }
        self.time_ps = time;
        Ok(())
    }

    pub(super) fn capture(&self) -> Result<Vec<u8>, OperationFailure> {
        let script = self.script_bytes()?;
        let mut bytes = STATE_PREFIX.to_vec();
        bytes.extend_from_slice(&(script.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&script);
        bytes.extend_from_slice(&(self.cursor as u64).to_le_bytes());
        bytes.extend_from_slice(&self.time_ps.to_le_bytes());
        bytes.push(u8::from(self.evaluated));
        Ok(bytes)
    }

    pub(super) fn restore(&mut self, bytes: &[u8]) -> Result<(), OperationFailure> {
        let mut input = bytes
            .strip_prefix(STATE_PREFIX)
            .ok_or_else(|| failure("unsupported scripted continuation edition"))?;
        let length = usize::try_from(u64::from_le_bytes(take::<8>(&mut input)?))
            .map_err(|error| failure(&error.to_string()))?;
        if length > input.len() {
            return Err(failure("scripted continuation is truncated"));
        }
        let (script, remaining) = input.split_at(length);
        if script != self.script_bytes()? {
            return Err(failure(
                "scripted continuation changes the installed immutable future",
            ));
        }
        input = remaining;
        let cursor = usize::try_from(u64::from_le_bytes(take::<8>(&mut input)?))
            .map_err(|error| failure(&error.to_string()))?;
        let time_ps = u64::from_le_bytes(take::<8>(&mut input)?);
        let evaluated = match take::<1>(&mut input)?[0] {
            0 => false,
            1 => true,
            _ => return Err(failure("scripted evaluation state is invalid")),
        };
        if !input.is_empty()
            || cursor > self.requests.len()
            || (evaluated && cursor == self.requests.len())
            || (evaluated
                && self
                    .requests
                    .get(cursor)
                    .is_some_and(|request| request.time_ps != time_ps))
            || self
                .requests
                .get(cursor)
                .is_some_and(|request| request.time_ps < time_ps)
            || cursor
                .checked_sub(1)
                .and_then(|index| self.requests.get(index))
                .zip(self.requests.get(cursor))
                .is_some_and(|(previous, next)| previous.time_ps == next.time_ps)
            || cursor
                .checked_sub(1)
                .and_then(|index| self.requests.get(index))
                .is_some_and(|request| request.time_ps > time_ps)
        {
            return Err(failure(
                "scripted continuation has an inconsistent cursor or clock",
            ));
        }
        self.cursor = cursor;
        self.time_ps = time_ps;
        self.evaluated = evaluated;
        Ok(())
    }
}

fn take<const N: usize>(input: &mut &[u8]) -> Result<[u8; N], OperationFailure> {
    if input.len() < N {
        return Err(failure("scripted codec is truncated"));
    }
    let (bytes, remaining) = input.split_at(N);
    *input = remaining;
    bytes
        .try_into()
        .map_err(|_| failure("scripted codec scalar is truncated"))
}

fn validate_request(kind: ScriptedRequestKind, bytes: &[u8]) -> Result<(), OperationFailure> {
    let maximum = MAXIMUM_REQUEST_BYTES;
    if bytes.len() > maximum {
        return Err(failure("scripted request exceeds the public lane ceiling"));
    }
    match kind {
        ScriptedRequestKind::Block => {
            let request =
                BlockRequest::decode(bytes).map_err(|error| failure(&error.to_string()))?;
            let response = match request.op {
                crucible_device::block::BlockOp::Read => {
                    usize::try_from(request.count).map_err(|error| failure(&error.to_string()))?
                }
                crucible_device::block::BlockOp::GetLength => 8,
                _ => 1,
            };
            if response
                .checked_add(crucible_device::block::RESPONSE_HEADER_LEN)
                .is_none_or(|length| length > maximum)
            {
                return Err(failure("scripted read response exceeds public geometry"));
            }
        }
        ScriptedRequestKind::Ninep => {
            let request = crucible_device::ninep::codec::Message::decode(bytes)
                .map_err(|error| failure(&error.to_string()))?;
            match request.body {
                crucible_device::ninep::codec::TMessage::Read { count, .. }
                | crucible_device::ninep::codec::TMessage::Readdir { count, .. }
                    if u64::from(count) + 11 > maximum as u64 =>
                {
                    return Err(failure(
                        "scripted filesystem response exceeds public geometry",
                    ));
                }
                _ => {}
            }
        }
    }
    Ok(())
}
