//! Prebirth-reserved original private ACK exchanges for graceful retirement.
//!
//! Each fixed holder retains actual request and reply frame bytes before parsing
//! or accepting success. An incomplete exchange fences that original operation;
//! no retry, supervisor or cleanup reader may invent an ACK from a completion.
//! This journal is opt-in and does not alter the legacy native/2 wire grammar.
//! Its separate retirement body uses a magic/version tag, u32be count/capacity,
//! then per attempt u16be identity length + identity, u16be planned/written frame
//! lengths + planned frame, u16be received length + received bytes, and ACK flag.
//!
//! ```text
//! request = uint32_be(length) || {"kind":"acknowledge","operation":id}
//! reply   = uint32_be(length) || {"kind":"acknowledged","operation":id}
//! ```

use std::io::{Read, Write};

use crucible_node_contract::{Id, canonical};
use serde_json::json;

use super::{DeadlineIo, Gem5NativeProcess, ProviderError, deadline};

const MAXIMUM_EXCHANGES: usize = 65_536;
const FRAME_BYTES: usize = 516;

/// Retains the actual bytes of one original private acknowledgement exchange.
pub struct Gem5AcknowledgementExchange {
    operation: Option<Id>,
    request: [u8; FRAME_BYTES],
    request_bytes: usize,
    written_bytes: usize,
    reply: [u8; FRAME_BYTES],
    received_bytes: usize,
    acknowledged: bool,
}

impl Gem5AcknowledgementExchange {
    fn reserved() -> Self {
        Self {
            operation: None,
            request: [0; FRAME_BYTES],
            request_bytes: 0,
            written_bytes: 0,
            reply: [0; FRAME_BYTES],
            received_bytes: 0,
            acknowledged: false,
        }
    }

    /// Borrows the original operation selected before any native write.
    pub fn operation(&self) -> Option<&Id> {
        self.operation.as_ref()
    }

    /// Borrows the exact planned frame; only the written prefix reached the peer.
    pub fn request_frame(&self) -> &[u8] {
        &self.request[..self.request_bytes]
    }

    /// Returns the actual first-write count, including a partial frame.
    pub fn written_bytes(&self) -> usize {
        self.written_bytes
    }

    /// Borrows every actually received byte, including incomplete framing.
    pub fn reply_frame(&self) -> &[u8] {
        &self.reply[..self.received_bytes]
    }

    /// Reports a complete matching reply accepted within its original deadline.
    pub fn acknowledged(&self) -> bool {
        self.acknowledged
    }
}

/// Owns finite private ACK history allocated before native child birth.
///
/// Unused holders and original partial exchanges remain in the same owning
/// capsule. Capacity exhaustion refuses before the first byte of another ACK.
pub struct Gem5AcknowledgementHistory {
    exchanges: Vec<Gem5AcknowledgementExchange>,
    used: usize,
}

impl Gem5AcknowledgementHistory {
    /// Reserves original exchange holders within the unchanged 65,536-prefix interface.
    ///
    /// # Errors
    /// Refuses zero, more than 65,536 exchanges or failed bounded allocation.
    pub fn reserve(maximum_exchanges: usize) -> Result<Self, ProviderError> {
        if maximum_exchanges == 0 || maximum_exchanges > MAXIMUM_EXCHANGES {
            return Err(ProviderError::ResourceExhausted(
                "original private ACK count exceeds selected interface",
            ));
        }
        let mut exchanges = Vec::new();
        exchanges
            .try_reserve_exact(maximum_exchanges)
            .map_err(|_| {
                ProviderError::ResourceExhausted("original private ACK holder allocation")
            })?;
        exchanges.resize_with(maximum_exchanges, Gem5AcknowledgementExchange::reserved);
        Ok(Self { exchanges, used: 0 })
    }

    /// Borrows the actual original exchanges in native submission order.
    pub fn exchanges(&self) -> &[Gem5AcknowledgementExchange] {
        &self.exchanges[..self.used]
    }

    /// Returns the prebirth reserved holder count, including unused credits.
    pub fn capacity(&self) -> usize {
        self.exchanges.len()
    }

    /// Encodes the exact retained first attempts as bounded operational facts.
    ///
    /// The binary record contains planned frame bytes, actual write/read counts
    /// and acceptance state. It does not authorize output settlement or release.
    /// Its full geometry is counted before allocation; no frame is reissued.
    ///
    /// # Errors
    /// Refuses insufficient byte credit, absent original identities or allocation.
    pub fn encode_retirement_history(
        &self,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, ProviderError> {
        const FORMAT: &[u8] = b"crucible.gem5.private-ack-history.v1\0";
        let mut length = FORMAT
            .len()
            .checked_add(8)
            .ok_or(ProviderError::ResourceExhausted(
                "original ACK history header overflow",
            ))?;
        for entry in self.exchanges() {
            let operation = entry.operation().ok_or(ProviderError::Correlation(
                "original ACK history omits attempted operation",
            ))?;
            length = length
                .checked_add(operation.as_str().len())
                .and_then(|value| value.checked_add(entry.request_frame().len()))
                .and_then(|value| value.checked_add(entry.reply_frame().len()))
                .and_then(|value| value.checked_add(9))
                .ok_or(ProviderError::ResourceExhausted(
                    "original ACK history byte overflow",
                ))?;
        }
        if length > maximum_bytes {
            return Err(ProviderError::ResourceExhausted(
                "original ACK history body credit exhausted",
            ));
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length).map_err(|_| {
            ProviderError::ResourceExhausted("original ACK history retention allocation")
        })?;
        self.write_retirement_history(&mut bytes)?;
        Ok(bytes)
    }

    /// Streams exact original first-attempt bytes without an intermediate body copy.
    pub(super) fn write_retirement_history(
        &self,
        output: &mut impl Write,
    ) -> Result<(), ProviderError> {
        const FORMAT: &[u8] = b"crucible.gem5.private-ack-history.v1\0";
        output.write_all(FORMAT)?;
        output.write_all(&(self.used as u32).to_be_bytes())?;
        output.write_all(&(self.capacity() as u32).to_be_bytes())?;
        for entry in self.exchanges() {
            let operation = entry.operation().ok_or(ProviderError::Correlation(
                "original ACK history lost attempted operation",
            ))?;
            output.write_all(&(operation.as_str().len() as u16).to_be_bytes())?;
            output.write_all(operation.as_str().as_bytes())?;
            output.write_all(&(entry.request_frame().len() as u16).to_be_bytes())?;
            output.write_all(&(entry.written_bytes() as u16).to_be_bytes())?;
            output.write_all(entry.request_frame())?;
            output.write_all(&(entry.reply_frame().len() as u16).to_be_bytes())?;
            output.write_all(entry.reply_frame())?;
            output.write_all(&[u8::from(entry.acknowledged())])?;
        }
        Ok(())
    }

    fn begin(&mut self, operation: &Id) -> Result<&mut Gem5AcknowledgementExchange, ProviderError> {
        if self
            .exchanges()
            .iter()
            .any(|entry| entry.operation() == Some(operation))
        {
            return Err(ProviderError::Conflict(
                "original private ACK already attempted; no resend",
            ));
        }
        let entry = self
            .exchanges
            .get_mut(self.used)
            .ok_or(ProviderError::ResourceExhausted(
                "original private ACK holder exhausted",
            ))?;
        // Canonical request construction and the bounded identity copy precede
        // slot consumption and every effect-capable write. Id is at most 128B.
        let body = canonical::canonical_json(&json!({
            "kind":"acknowledge", "operation":operation,
        }))?;
        if body.len() > FRAME_BYTES - 4 {
            return Err(ProviderError::Frame(
                "original private ACK request too large",
            ));
        }
        entry.operation = Some(operation.clone());
        entry.request[..4].copy_from_slice(&(body.len() as u32).to_be_bytes());
        entry.request[4..4 + body.len()].copy_from_slice(&body);
        entry.request_bytes = 4 + body.len();
        self.used += 1;
        Ok(entry)
    }
}

impl Gem5NativeProcess {
    /// Borrows opt-in original private ACK history without creating permission.
    pub fn acknowledgement_history(&self) -> Option<&Gem5AcknowledgementHistory> {
        self.acknowledgement_history.as_ref()
    }

    pub(super) fn acknowledge_retained(&mut self, operation: &Id) -> Result<(), ProviderError> {
        if self.quarantine.is_some() {
            return Err(ProviderError::Conflict("gem5 native owner is quarantined"));
        }
        let stream = self.stream.as_mut().ok_or(ProviderError::Correlation(
            "original private ACK session disconnected",
        ))?;
        let mut io = DeadlineIo {
            stream,
            deadline: deadline(self.launch.timeout)?,
        };
        let history = self
            .acknowledgement_history
            .as_mut()
            .ok_or(ProviderError::Correlation(
                "original private ACK holder omitted",
            ))?;
        let entry = history.begin(operation)?;
        let result = exchange_once(&mut io, entry).and_then(|()| {
            // Late complete bytes remain retained, but never become an ACK.
            io.remaining()?;
            entry.acknowledged = true;
            Ok(())
        });
        if result.is_err() {
            self.stream = None;
        }
        result
    }
}

fn exchange_once(
    io: &mut (impl Read + Write),
    entry: &mut Gem5AcknowledgementExchange,
) -> Result<(), ProviderError> {
    while entry.written_bytes < entry.request_bytes {
        let count = io.write(&entry.request[entry.written_bytes..entry.request_bytes])?;
        if count == 0 {
            return Err(ProviderError::Correlation(
                "original private ACK write stopped",
            ));
        }
        entry.written_bytes += count;
    }
    io.flush()?;
    read_to(io, entry, 4)?;
    let length = u32::from_be_bytes(
        entry.reply[..4]
            .try_into()
            .map_err(|_| ProviderError::Frame("original private ACK header differs"))?,
    ) as usize;
    if length == 0 || length > FRAME_BYTES - 4 {
        return Err(ProviderError::Frame("original private ACK reply too large"));
    }
    read_to(io, entry, 4 + length)?;
    let response = canonical::parse_json(&entry.reply[4..4 + length], FRAME_BYTES - 4)?;
    if response != json!({"kind":"acknowledged", "operation":entry.operation.as_ref()}) {
        return Err(ProviderError::Correlation(
            "original private ACK reply differs",
        ));
    }
    Ok(())
}

fn read_to(
    io: &mut impl Read,
    entry: &mut Gem5AcknowledgementExchange,
    end: usize,
) -> Result<(), ProviderError> {
    while entry.received_bytes < end {
        let count = io.read(&mut entry.reply[entry.received_bytes..end])?;
        if count == 0 {
            return Err(ProviderError::Correlation(
                "original private ACK reply stopped",
            ));
        }
        entry.received_bytes += count;
    }
    Ok(())
}

#[cfg(test)]
#[path = "acknowledgement_history_tests.rs"]
mod tests;
