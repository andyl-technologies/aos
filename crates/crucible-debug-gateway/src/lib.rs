//! SPDX-License-Identifier: GPL-2.0-only
//! GPL-side debugger gateway for stable GDB sessions across QEMU replacement.
//!
//! The gateway is a separate process from the Apache-licensed Crucible host.
//! It consumes only the versioned owned-byte protocol from
//! [`crucible_protocol::debug_gateway`] and connects to QEMU's RSP endpoint;
//! it does not expose QEMU headers, callbacks, or process-private objects.
//!
//! [`DebugGateway`] owns the two-phase active/prepared backend transition.
//! [`classify_rsp_packet`] enforces canonical read-only policy and diverts run
//! control to the scheduler-owning host instead of forwarding it to QEMU.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

use std::collections::BTreeSet;

use thiserror::Error;

/// Maximum unframed RSP bytes retained while waiting for one complete unit.
pub const RSP_MAX_BUFFERED_BYTES: usize = 1024 * 1024;

/// A validated private Unix-socket endpoint for one QEMU gdbstub.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QemuRspEndpoint(String);

impl QemuRspEndpoint {
    /// Builds an absolute Unix-socket path.
    ///
    /// # Errors
    ///
    /// Returns [`DebugGatewayError::InvalidEndpoint`] when `value` is not an
    /// absolute path or contains a NUL or newline byte.
    pub fn new(value: impl Into<String>) -> Result<Self, DebugGatewayError> {
        let value = value.into();
        if !value.starts_with('/') || value.bytes().any(|byte| matches!(byte, 0 | b'\n' | b'\r')) {
            return Err(DebugGatewayError::InvalidEndpoint);
        }
        Ok(Self(value))
    }

    /// Returns the validated Unix-socket path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Monotonic identity for a prepared backend replacement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BackendGeneration(pub u64);

/// Backend information retained by the gateway after validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedBackend {
    /// Monotonic identity used by commit and abort requests.
    pub generation: BackendGeneration,
    /// Private QEMU RSP Unix-socket endpoint.
    pub endpoint: QemuRspEndpoint,
}

/// Process-local gateway state for atomic backend replacement.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DebugGateway {
    active: Option<PreparedBackend>,
    prepared: Option<PreparedBackend>,
    next_generation: u64,
    rsp_state: RspSessionState,
}

impl DebugGateway {
    /// Builds an empty gateway without a QEMU backend.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the active backend, when attachment has completed.
    #[must_use]
    pub const fn active(&self) -> Option<&PreparedBackend> {
        self.active.as_ref()
    }

    /// Returns the candidate backend awaiting commit, when present.
    #[must_use]
    pub const fn prepared(&self) -> Option<&PreparedBackend> {
        self.prepared.as_ref()
    }

    /// Returns GDB session state that survives backend replacement.
    #[must_use]
    pub const fn rsp_state(&self) -> &RspSessionState {
        &self.rsp_state
    }

    /// Registers a connected and validated candidate QEMU endpoint.
    ///
    /// The caller must complete the Unix connection and initial RSP stop query
    /// before invoking this method.
    ///
    /// # Errors
    ///
    /// Returns [`DebugGatewayError::CandidateAlreadyPrepared`] when another
    /// candidate must first be committed or aborted.
    pub fn prepare_backend(
        &mut self,
        endpoint: QemuRspEndpoint,
    ) -> Result<PreparedBackend, DebugGatewayError> {
        if self.prepared.is_some() {
            return Err(DebugGatewayError::CandidateAlreadyPrepared);
        }
        self.next_generation = self.next_generation.saturating_add(1);
        let prepared = PreparedBackend {
            generation: BackendGeneration(self.next_generation),
            endpoint,
        };
        self.prepared = Some(prepared.clone());
        Ok(prepared)
    }

    /// Atomically promotes a prepared backend and returns the replaced backend.
    ///
    /// The downstream GDB transport remains connected; callers replay
    /// [`Self::rsp_state`] into the candidate before sending a synthetic stop.
    ///
    /// # Errors
    ///
    /// Returns [`DebugGatewayError::UnknownPreparedGeneration`] when the token
    /// is stale or foreign.
    pub fn commit_backend(
        &mut self,
        generation: BackendGeneration,
    ) -> Result<Option<PreparedBackend>, DebugGatewayError> {
        let Some(prepared) = self.prepared.take() else {
            return Err(DebugGatewayError::UnknownPreparedGeneration { generation });
        };
        if prepared.generation != generation {
            self.prepared = Some(prepared);
            return Err(DebugGatewayError::UnknownPreparedGeneration { generation });
        }
        Ok(self.active.replace(prepared))
    }

    /// Aborts a candidate without disturbing the active backend or GDB state.
    ///
    /// # Errors
    ///
    /// Returns [`DebugGatewayError::UnknownPreparedGeneration`] when the token
    /// is stale or foreign.
    pub fn abort_backend(
        &mut self,
        generation: BackendGeneration,
    ) -> Result<PreparedBackend, DebugGatewayError> {
        let Some(prepared) = self.prepared.take() else {
            return Err(DebugGatewayError::UnknownPreparedGeneration { generation });
        };
        if prepared.generation != generation {
            self.prepared = Some(prepared);
            return Err(DebugGatewayError::UnknownPreparedGeneration { generation });
        }
        Ok(prepared)
    }

    /// Records persistent RSP state after QEMU acknowledged the packet.
    pub fn observe_acknowledged_rsp(&mut self, packet: &[u8]) {
        self.rsp_state.observe(packet);
    }
}

/// GDB RSP state replayed after an atomic QEMU backend swap.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RspSessionState {
    /// Last general thread selection packet payload.
    pub general_thread: Option<Vec<u8>>,
    /// Last continue thread selection packet payload.
    pub continue_thread: Option<Vec<u8>>,
    /// Canonical hardware breakpoint packets currently installed.
    pub hardware_breakpoints: BTreeSet<Vec<u8>>,
}

impl RspSessionState {
    fn observe(&mut self, packet: &[u8]) {
        let Ok(packet) = rsp_command_payload(packet) else {
            return;
        };
        if packet.starts_with(b"Hg") {
            self.general_thread = Some(packet.to_vec());
        } else if packet.starts_with(b"Hc") {
            self.continue_thread = Some(packet.to_vec());
        } else if packet.starts_with(b"Z1,") {
            self.hardware_breakpoints.insert(packet.to_vec());
        } else if let Some(remove) = packet.strip_prefix(b"z1,") {
            let mut install = b"Z1,".to_vec();
            install.extend_from_slice(remove);
            self.hardware_breakpoints.remove(&install);
        }
    }
}

/// Policy decision for one checksum-validated RSP packet payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RspDisposition {
    /// Forward the packet to the active QEMU gdbstub.
    ForwardToQemu,
    /// Send the operation to Crucible's scheduler owner.
    SchedulerRunControl,
    /// Reject the packet locally with the RSP error `E22`.
    RejectReadOnly,
    /// Reject an unrecognized mutating/control packet with `E01`.
    RejectUnsupported,
}

/// One complete unit decoded from the GDB Remote Serial Protocol byte stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RspUnit {
    /// Positive acknowledgement byte.
    Ack,
    /// Negative acknowledgement byte.
    Nack,
    /// Asynchronous interrupt byte.
    Interrupt,
    /// One checksum-validated `$payload#checksum` packet.
    Packet(Vec<u8>),
}

/// Incremental, bounded decoder for an RSP byte stream.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RspStreamDecoder {
    buffered: Vec<u8>,
}

impl RspStreamDecoder {
    /// Builds an empty stream decoder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends bytes and returns every complete RSP unit now available.
    ///
    /// Incomplete packets remain buffered for the next call. The decoder
    /// accepts acknowledgement bytes, interrupts, and checksum-framed packets;
    /// every other leading byte fails closed.
    ///
    /// # Errors
    ///
    /// Returns [`RspStreamDecodeError`] for an oversized buffer, an invalid
    /// leading byte, malformed checksum digits, or a checksum mismatch.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<RspUnit>, RspStreamDecodeError> {
        if self.buffered.len().saturating_add(bytes.len()) > RSP_MAX_BUFFERED_BYTES {
            return Err(RspStreamDecodeError::BufferLimitExceeded);
        }
        self.buffered.extend_from_slice(bytes);
        let mut units = Vec::new();
        let mut consumed = 0;
        loop {
            let Some(first) = self.buffered.get(consumed).copied() else {
                break;
            };
            match first {
                b'+' => {
                    consumed += 1;
                    units.push(RspUnit::Ack);
                }
                b'-' => {
                    consumed += 1;
                    units.push(RspUnit::Nack);
                }
                0x03 => {
                    consumed += 1;
                    units.push(RspUnit::Interrupt);
                }
                b'$' => {
                    let Some(relative_checksum_offset) = self.buffered[consumed..]
                        .iter()
                        .position(|byte| *byte == b'#')
                    else {
                        break;
                    };
                    let packet_len = relative_checksum_offset.saturating_add(3);
                    if self.buffered.len().saturating_sub(consumed) < packet_len {
                        break;
                    }
                    let packet = self.buffered[consumed..consumed + packet_len].to_vec();
                    rsp_command_payload(&packet)
                        .map_err(|()| RspStreamDecodeError::InvalidPacket)?;
                    consumed += packet_len;
                    units.push(RspUnit::Packet(packet));
                }
                byte => {
                    self.buffered.drain(..consumed);
                    return Err(RspStreamDecodeError::UnexpectedByte { byte });
                }
            }
        }
        self.buffered.drain(..consumed);
        Ok(units)
    }

    /// Returns the number of incomplete bytes retained for the next call.
    #[must_use]
    pub fn buffered_len(&self) -> usize {
        self.buffered.len()
    }
}

/// Errors returned by [`RspStreamDecoder`].
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum RspStreamDecodeError {
    /// Buffered input exceeded the fixed defensive limit.
    #[error("RSP buffered input exceeds the defensive limit")]
    BufferLimitExceeded,
    /// A stream unit began with an unsupported byte.
    #[error("RSP stream contains unexpected leading byte {byte:#04x}")]
    UnexpectedByte {
        /// Rejected leading byte.
        byte: u8,
    },
    /// A complete packet had invalid checksum syntax or content.
    #[error("RSP packet checksum is invalid")]
    InvalidPacket,
}

/// Classifies one decoded RSP packet under canonical read-only policy.
///
/// Continue, step, and `vCont` are always routed to the scheduler. The policy is
/// allow-by-exception: only known read-only queries, thread selection, and
/// hardware breakpoints reach QEMU. Every mutating or unknown packet fails
/// closed.
#[must_use]
pub fn classify_rsp_packet(packet: &[u8]) -> RspDisposition {
    if packet == [0x03] {
        return RspDisposition::SchedulerRunControl;
    }
    let Ok(packet) = rsp_command_payload(packet) else {
        return RspDisposition::RejectUnsupported;
    };
    if matches!(packet.first(), Some(b'c' | b'C' | b's' | b'S'))
        || packet == b"vCont"
        || packet.starts_with(b"vCont;")
    {
        return RspDisposition::SchedulerRunControl;
    }
    if matches!(packet.first(), Some(b'G' | b'P' | b'M' | b'X' | b'A'))
        || packet.starts_with(b"Z0,")
        || packet.starts_with(b"z0,")
        || packet.starts_with(b"qRcmd,")
        || packet.starts_with(b"vFlash")
    {
        return RspDisposition::RejectReadOnly;
    }
    if packet.starts_with(b"Z1,") || packet.starts_with(b"z1,") {
        return RspDisposition::ForwardToQemu;
    }
    if packet == b"?"
        || packet == b"g"
        || matches!(packet.first(), Some(b'p' | b'm' | b'T' | b'H'))
        || packet.starts_with(b"qSupported")
        || packet.starts_with(b"qXfer:features:read:")
        || packet.starts_with(b"qXfer:threads:read:")
        || packet.starts_with(b"qfThreadInfo")
        || packet.starts_with(b"qsThreadInfo")
        || packet.starts_with(b"qC")
        || packet.starts_with(b"qAttached")
        || packet.starts_with(b"qOffsets")
        || packet.starts_with(b"qSymbol")
        || packet.starts_with(b"qThreadExtraInfo,")
        || packet.starts_with(b"qGetTLSAddr:")
        || packet.starts_with(b"qCRC:")
        || packet.starts_with(b"qSearch:memory:")
        || packet == b"vCont?"
        || packet == b"vMustReplyEmpty"
    {
        return RspDisposition::ForwardToQemu;
    }
    RspDisposition::RejectUnsupported
}

fn rsp_command_payload(packet: &[u8]) -> Result<&[u8], ()> {
    if packet.first() != Some(&b'$') {
        return Ok(packet);
    }
    let Some(checksum_offset) = packet.iter().rposition(|byte| *byte == b'#') else {
        return Err(());
    };
    if checksum_offset < 1 || packet.len() != checksum_offset + 3 {
        return Err(());
    }
    let expected = decode_hex_byte(packet[checksum_offset + 1], packet[checksum_offset + 2])?;
    let payload = &packet[1..checksum_offset];
    let actual = payload
        .iter()
        .fold(0_u8, |sum, byte| sum.wrapping_add(*byte));
    if actual != expected {
        return Err(());
    }
    Ok(payload)
}

fn decode_hex_byte(high: u8, low: u8) -> Result<u8, ()> {
    let high = decode_hex_nibble(high)?;
    let low = decode_hex_nibble(low)?;
    Ok((high << 4) | low)
}

fn decode_hex_nibble(value: u8) -> Result<u8, ()> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(()),
    }
}

/// Errors returned by gateway state transitions and endpoint validation.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum DebugGatewayError {
    /// A QEMU endpoint was not a safe absolute Unix-socket path.
    #[error("QEMU RSP endpoint must be an absolute Unix-socket path")]
    InvalidEndpoint,
    /// A second candidate was offered before resolving the first.
    #[error("a debugger backend candidate is already prepared")]
    CandidateAlreadyPrepared,
    /// A commit or abort named a stale or foreign generation.
    #[error("debugger backend generation {generation:?} is not prepared")]
    UnknownPreparedGeneration {
        /// Rejected generation.
        generation: BackendGeneration,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(name: &str) -> QemuRspEndpoint {
        QemuRspEndpoint::new(format!("/run/crucible/{name}.sock"))
            .unwrap_or_else(|error| panic!("fixture endpoint should be valid: {error}"))
    }

    #[test]
    fn failed_candidate_does_not_replace_active_backend_or_rsp_state() {
        let mut gateway = DebugGateway::new();
        let first = gateway
            .prepare_backend(endpoint("first"))
            .unwrap_or_else(|error| panic!("first candidate should prepare: {error}"));
        gateway
            .commit_backend(first.generation)
            .unwrap_or_else(|error| panic!("first candidate should commit: {error}"));
        gateway.observe_acknowledged_rsp(b"Hg1");
        gateway.observe_acknowledged_rsp(b"Z1,4000,1");

        let candidate = gateway
            .prepare_backend(endpoint("candidate"))
            .unwrap_or_else(|error| panic!("replacement should prepare: {error}"));
        assert!(matches!(
            gateway.commit_backend(BackendGeneration(candidate.generation.0 + 1)),
            Err(DebugGatewayError::UnknownPreparedGeneration { .. })
        ));
        assert_eq!(
            gateway.active().map(|item| item.endpoint.as_str()),
            Some("/run/crucible/first.sock")
        );
        assert_eq!(gateway.prepared(), Some(&candidate));
        assert_eq!(
            gateway.rsp_state().general_thread.as_deref(),
            Some(b"Hg1".as_slice())
        );
        assert!(
            gateway
                .rsp_state()
                .hardware_breakpoints
                .contains(b"Z1,4000,1".as_slice())
        );
    }

    #[test]
    fn canonical_policy_intercepts_run_control_and_mutation() {
        for packet in [b"c".as_slice(), b"s", b"vCont;c:1"] {
            assert_eq!(
                classify_rsp_packet(packet),
                RspDisposition::SchedulerRunControl
            );
        }
        for packet in [
            b"M1000,1:00".as_slice(),
            b"P0=00",
            b"Z0,4000,1",
            b"qRcmd,6964",
        ] {
            assert_eq!(classify_rsp_packet(packet), RspDisposition::RejectReadOnly);
        }
        assert_eq!(
            classify_rsp_packet(b"Z1,4000,1"),
            RspDisposition::ForwardToQemu
        );
        assert_eq!(
            classify_rsp_packet(b"m1000,10"),
            RspDisposition::ForwardToQemu
        );
        assert_eq!(
            classify_rsp_packet(b"vCont?"),
            RspDisposition::ForwardToQemu
        );
        for packet in [
            b"k".as_slice(),
            b"D",
            b"vKill;1",
            b"!",
            b"QStartNoAckMode",
            b"vFile:unlink:2f746d702f78",
            b"Z2,4000,1",
            b"Z3,4000,1",
            b"Z4,4000,1",
            b"unknown-packet",
        ] {
            assert_eq!(
                classify_rsp_packet(packet),
                RspDisposition::RejectUnsupported
            );
        }
        assert_eq!(
            classify_rsp_packet(b"$c#63"),
            RspDisposition::SchedulerRunControl
        );
        assert_eq!(
            classify_rsp_packet(b"$M1000,1:00#05"),
            RspDisposition::RejectReadOnly
        );
        assert_eq!(
            classify_rsp_packet(b"$c#00"),
            RspDisposition::RejectUnsupported
        );
    }

    #[test]
    fn rsp_stream_decoder_handles_split_and_coalesced_units() {
        let mut decoder = RspStreamDecoder::new();
        assert!(
            decoder
                .push(b"+$m1000")
                .unwrap_or_else(|error| panic!("prefix should decode: {error}"))
                .eq(&[RspUnit::Ack])
        );
        assert!(decoder.buffered_len() > 0);
        let units = decoder
            .push(b",10#bb-$?#3f\x03")
            .unwrap_or_else(|error| panic!("suffix should decode: {error}"));
        assert_eq!(
            units,
            vec![
                RspUnit::Packet(b"$m1000,10#bb".to_vec()),
                RspUnit::Nack,
                RspUnit::Packet(b"$?#3f".to_vec()),
                RspUnit::Interrupt,
            ]
        );
        assert_eq!(decoder.buffered_len(), 0);
    }

    #[test]
    fn rsp_stream_decoder_rejects_invalid_checksum_and_unknown_bytes() {
        let mut decoder = RspStreamDecoder::new();
        assert!(matches!(
            decoder.push(b"$m1000,10#00"),
            Err(RspStreamDecodeError::InvalidPacket)
        ));
        let mut decoder = RspStreamDecoder::new();
        assert!(matches!(
            decoder.push(b"x"),
            Err(RspStreamDecodeError::UnexpectedByte { byte: b'x' })
        ));
    }

    #[test]
    fn rsp_stream_decoder_consumes_maximum_ack_stream_linearly() {
        let mut decoder = RspStreamDecoder::new();
        let bytes = vec![b'+'; RSP_MAX_BUFFERED_BYTES];
        let units = decoder.push(&bytes).unwrap_or_else(|error| {
            panic!("bounded acknowledgement stream should decode: {error}")
        });
        assert_eq!(units.len(), RSP_MAX_BUFFERED_BYTES);
        assert!(units.iter().all(|unit| *unit == RspUnit::Ack));
        assert_eq!(decoder.buffered_len(), 0);
    }
}
