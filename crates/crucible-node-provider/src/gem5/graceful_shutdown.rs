//! Retains one original controller Shutdown without a signaling fallback.
//!
//! The native/2 controller already accepts the closed request shown below.
//! This owner-only path preserves every receipt and private ACK. A lost reply
//! never permits another Shutdown write, and an acknowledgement is not reaping.
//!
//! ```text
//! request = {"kind":"shutdown"}
//! reply   = {"kind":"shutdown"}
//! ```

use std::io::{Read, Write};

use super::*;

/// Preserves the exact bounded first Shutdown exchange inside original custody.
#[derive(Debug)]
pub struct Gem5ShutdownExchange {
    written_bytes: usize,
    received: [u8; 68],
    received_bytes: usize,
    acknowledged: bool,
}

impl Gem5ShutdownExchange {
    pub(super) fn reserved() -> Self {
        Self {
            written_bytes: 0,
            received: [0; 68],
            received_bytes: 0,
            acknowledged: false,
        }
    }

    /// Borrows every actually received byte, including an incomplete header.
    pub fn received_bytes(&self) -> &[u8] {
        &self.received[..self.received_bytes]
    }

    /// Returns the actual count written from the one original frame.
    pub fn written_bytes(&self) -> usize {
        self.written_bytes
    }

    /// Reports an exact original reply, independently of child/group reaping.
    pub fn acknowledged(&self) -> bool {
        self.acknowledged
    }
}

impl Gem5NativeProcess {
    /// Reports the retained original graceful intent independently of its reply.
    pub fn graceful_retirement_requested(&self) -> bool {
        self.graceful_retirement_requested
    }

    /// Reports mechanical availability of the same original Shutdown session.
    ///
    /// This is not source qualification or permission to discard original state.
    /// The owning installed factory must independently authenticate cleanup scope.
    pub fn graceful_shutdown_available(&self) -> bool {
        self.child.is_some()
            && self.kernel_identity.is_some()
            && self.stream.is_some()
            && self.quarantine.is_none()
            && !self.graceful_retirement_requested
            && self.pending.is_none()
            && self.unresolved.is_none()
            && self.unresolved_capture.is_none()
    }

    /// Requests genuine original controller Shutdown without signaling processes.
    ///
    /// Its fixed retention holder exists in the driver's prebirth quarantine
    /// slot. The latch is installed before writing; repeated calls only inspect
    /// that original exchange. No outcome, prefix or ACK is erased.
    ///
    /// # Errors
    /// Refuses unresolved native output/capture, changed original kernel scope,
    /// absent session, incomplete or late replies and a previously lost reply.
    /// Every refusal retains original resources and offers no forceful fallback.
    pub fn begin_graceful_shutdown(&mut self) -> Result<(), ProviderError> {
        if let Some(state) = &self.quarantine {
            return match state.shutdown.as_ref() {
                Some(exchange) if exchange.acknowledged => Ok(()),
                Some(_) => Err(ProviderError::Conflict(
                    "original Shutdown exchange remains uncertain; no resend",
                )),
                None => Err(ProviderError::Conflict(
                    "original owner already entered a different containment path",
                )),
            };
        }
        // Intent is infallibly retained before missing identity, missing Child or
        // deadline construction can refuse. The same latch travels on Drop.
        self.graceful_retirement_requested = true;
        let child = self.child.as_ref().ok_or(ProviderError::Correlation(
            "original Shutdown omits owning Child",
        ))?;
        let identity = self
            .kernel_identity
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "original Shutdown omits sealed kernel identity",
            ))?;
        let budget = deadline(self.launch.timeout)?;
        // This fixed-size state is retained before the first effect-capable
        // write. In particular, Err/unwind cannot expose a resend or SIGKILL.
        self.quarantine = Some(containment::graceful_state(identity, budget));
        containment::validate_original_identity(child, identity)?;
        let state = self.quarantine.as_mut().ok_or(ProviderError::Correlation(
            "original Shutdown retention holder absent",
        ))?;
        if self.unresolved.is_some() || self.pending.is_some() || self.unresolved_capture.is_some()
        {
            // Preserve a no-write refusal in the same fixed holder. Later Drop
            // cannot silently replace it with the legacy signaling path.
            return Err(ProviderError::Conflict(
                "original Shutdown cannot erase unresolved native obligations",
            ));
        }
        let stream = self.stream.as_mut().ok_or(ProviderError::Correlation(
            "original Shutdown omits same native session; custody remains held",
        ))?;
        let mut io = DeadlineIo {
            stream,
            deadline: deadline(self.launch.timeout)?,
        };
        let exchange = state.shutdown.as_mut().ok_or(ProviderError::Correlation(
            "original Shutdown exchange absent",
        ))?;
        exchange_once(&mut io, exchange)?;
        io.remaining()?;
        exchange.acknowledged = true;
        Ok(())
    }
}

fn exchange_once(
    io: &mut impl ReadWrite,
    exchange: &mut Gem5ShutdownExchange,
) -> Result<(), ProviderError> {
    const BODY: &[u8] = b"{\"kind\":\"shutdown\"}";
    let mut frame = [0; 23];
    frame[..4].copy_from_slice(&(BODY.len() as u32).to_be_bytes());
    frame[4..].copy_from_slice(BODY);
    while exchange.written_bytes < frame.len() {
        let count = io.write(&frame[exchange.written_bytes..])?;
        if count == 0 {
            return Err(ProviderError::Correlation(
                "original Shutdown write made no progress",
            ));
        }
        exchange.written_bytes += count;
    }
    io.flush()?;

    read_retained(io, exchange, 4)?;
    let length = u32::from_be_bytes(
        exchange.received[..4]
            .try_into()
            .map_err(|_| ProviderError::Frame("original Shutdown header differs"))?,
    ) as usize;
    if length > 64 {
        return Err(ProviderError::Frame(
            "original Shutdown reply exceeds fixed credit",
        ));
    }
    read_retained(io, exchange, 4 + length)?;
    if &exchange.received[4..4 + length] != BODY {
        return Err(ProviderError::Correlation(
            "original Shutdown reply differs",
        ));
    }
    Ok(())
}

trait ReadWrite: Read + Write {}

impl<T: Read + Write> ReadWrite for T {}

fn read_retained(
    io: &mut impl Read,
    exchange: &mut Gem5ShutdownExchange,
    until: usize,
) -> Result<(), ProviderError> {
    while exchange.received_bytes < until {
        let count = io.read(&mut exchange.received[exchange.received_bytes..until])?;
        if count == 0 {
            return Err(ProviderError::Correlation(
                "original Shutdown reply ended early",
            ));
        }
        exchange.received_bytes += count;
    }
    Ok(())
}

#[cfg(test)]
#[path = "graceful_shutdown_tests.rs"]
mod tests;
