//! Original whole-operation socket and immutable complete host histories.
//!
//! This host adapter speaks only the public, big-endian whole-control protocol.
//! It owns no QEMU callback table or native pointer. Construction preallocates
//! every historical body; partial writes and reads retain their original bytes.
//! The caller still authenticates preparation, current input ownership and the
//! native stopped cut before using these records for common-node admission.
//!
//! ```text
//! host -> plugin: Request(full body), Acknowledgement(128 bytes)
//! plugin -> host: Result(full body), Acknowledgement(consumed original)
//! each frame: CWHLCTL\0, edition:u32, kind:u32, extent:u32, reserved:u32
//! ```

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;

use crucible_qemu_protocol::whole_control::body::{
    WholeAcknowledgement, WholeOperationQuota, WholeRequest, WholeResult,
};
use crucible_qemu_protocol::whole_control::{
    WHOLE_ACK_BYTES, WHOLE_FRAME_HEADER_BYTES, WholeControlError, WholeControlProfile,
    WholeFrameKind, decode_whole_frame_header, encode_whole_frame_header,
};

/// Reports original transport refusal while retaining complete and partial bytes.
#[derive(Debug, thiserror::Error)]
pub enum NativeWholeControlError {
    /// The independently negotiated public protocol rejected a record.
    #[error(transparent)]
    Protocol(#[from] WholeControlError),
    /// The original socket or monotonic clock failed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// Constructor storage could not retain the complete selected histories.
    #[error("whole-operation history allocation refused")]
    Allocation,
    /// An original request, result or consumed acknowledgement conflicted.
    #[error("whole-operation original custody refused")]
    Custody,
    /// Nonrenewing physical attempts, bytes or the original deadline expired.
    #[error("whole-operation administrative budget exhausted")]
    Exhausted,
}

struct OperationHistory {
    request: Vec<u8>,
    request_extent: usize,
    request_sent: usize,
    result: Vec<u8>,
    result_extent: usize,
    offered_ack: [u8; WHOLE_FRAME_HEADER_BYTES + WHOLE_ACK_BYTES],
    ack_offered: bool,
    ack_sent: usize,
    consumed_ack: [u8; WHOLE_FRAME_HEADER_BYTES + WHOLE_ACK_BYTES],
    ack_consumed: bool,
}

struct ReadPrefix {
    header: [u8; WHOLE_FRAME_HEADER_BYTES],
    received_header: usize,
    extent: usize,
    received_body: usize,
    kind: Option<WholeFrameKind>,
}

/// Owns one original whole-control socket and constructor-selected host history.
///
/// Acknowledgement transmission preserves host custody. Only an exact consumed
/// original returned by the peer settles the local operation, and even that
/// record does not release world mappings, workers or native preparation holds.
pub struct NativeWholeControlTransport {
    socket: Option<UnixStream>,
    profile: WholeControlProfile,
    process: u32,
    history: Vec<OperationHistory>,
    admitted: usize,
    settled: usize,
    charged: WholeOperationQuota,
    read: ReadPrefix,
    read_attempts: u64,
    read_bytes: u64,
    write_attempts: u64,
    write_bytes: u64,
    refused: bool,
}

impl NativeWholeControlTransport {
    /// Retains a negotiated original socket and preallocates its entire history.
    ///
    /// # Errors
    /// Rejects invalid profile, expired deadline, inadequate actual storage,
    /// unavailable allocation or physical socket configuration failure.
    pub fn new(
        socket: UnixStream,
        profile: WholeControlProfile,
    ) -> Result<Self, NativeWholeControlError> {
        profile.validate()?;
        if monotonic_ns()? >= profile.deadline_monotonic_ns {
            return Err(NativeWholeControlError::Exhausted);
        }
        let count = profile.operation_capacity as usize;
        let extent = WHOLE_FRAME_HEADER_BYTES + profile.body_byte_limit as usize;
        let bytes = extent
            .checked_mul(2)
            .and_then(|bodies| bodies.checked_add(std::mem::size_of::<OperationHistory>()))
            .and_then(|per_operation| per_operation.checked_mul(count))
            .ok_or(NativeWholeControlError::Allocation)?;
        if bytes as u64 > profile.provider_history_byte_limit {
            return Err(NativeWholeControlError::Allocation);
        }
        let mut history = Vec::new();
        history
            .try_reserve_exact(count)
            .map_err(|_| NativeWholeControlError::Allocation)?;
        for _ in 0..count {
            history.push(OperationHistory {
                request: allocated_body(extent)?,
                request_extent: 0,
                request_sent: 0,
                result: allocated_body(extent)?,
                result_extent: 0,
                offered_ack: [0; WHOLE_FRAME_HEADER_BYTES + WHOLE_ACK_BYTES],
                ack_offered: false,
                ack_sent: 0,
                consumed_ack: [0; WHOLE_FRAME_HEADER_BYTES + WHOLE_ACK_BYTES],
                ack_consumed: false,
            });
        }
        socket.set_nonblocking(true)?;
        Ok(Self {
            socket: Some(socket),
            profile,
            process: std::process::id(),
            history,
            admitted: 0,
            settled: 0,
            charged: WholeOperationQuota {
                input_bytes: 0,
                input_records: 0,
                output_bytes: 0,
                output_records: 0,
                cpu_retirements: 0,
                event_steps: 0,
            },
            read: ReadPrefix::new(),
            read_attempts: 0,
            read_bytes: 0,
            write_attempts: 0,
            write_bytes: 0,
            refused: false,
        })
    }

    /// Retains the complete next immutable request before offering socket bytes.
    ///
    /// # Errors
    /// Rejects changed originals, foreign scope or epoch, nonmonotonic sequence,
    /// unsettled previous custody or exhausted constructor storage. Exact
    /// historical retries preserve their original transmission cursor.
    pub fn retain_original(&mut self, body: &[u8]) -> Result<(), NativeWholeControlError> {
        self.live()?;
        let request = WholeRequest::decode(body)?;
        let index =
            usize::try_from(request.sequence - 1).map_err(|_| NativeWholeControlError::Custody)?;
        if request.scope != self.profile.scope || index >= self.history.len() {
            return self.refuse(NativeWholeControlError::Custody);
        }
        if index < self.admitted {
            let original = &self.history[index];
            if index + 1 == self.admitted
                && &original.request[WHOLE_FRAME_HEADER_BYTES..original.request_extent] == body
            {
                return Ok(());
            }
            return self.refuse(NativeWholeControlError::Custody);
        }
        if index != self.admitted || self.admitted != self.settled {
            return self.refuse(NativeWholeControlError::Custody);
        }
        if index > 0 {
            let original = &self.history[0];
            let first = WholeRequest::decode(
                &original.request[WHOLE_FRAME_HEADER_BYTES..original.request_extent],
            )?;
            if first.epoch != request.epoch {
                return self.refuse(NativeWholeControlError::Custody);
            }
        }
        let header = encode_whole_frame_header(
            WholeFrameKind::Request,
            body.len(),
            self.profile.body_byte_limit,
        )?;
        let quota = request.quota;
        let charged = WholeOperationQuota {
            input_bytes: self.charge(
                self.charged.input_bytes,
                quota.input_bytes,
                self.profile.input_byte_limit,
            )?,
            input_records: self.charge(
                self.charged.input_records,
                quota.input_records,
                self.profile.input_record_limit,
            )?,
            output_bytes: self.charge(
                self.charged.output_bytes,
                quota.output_bytes,
                self.profile.output_byte_limit,
            )?,
            output_records: self.charge(
                self.charged.output_records,
                quota.output_records,
                self.profile.output_record_limit,
            )?,
            cpu_retirements: self.charge(
                self.charged.cpu_retirements,
                quota.cpu_retirements,
                self.profile.cpu_retirement_limit,
            )?,
            event_steps: self.charge(
                self.charged.event_steps,
                quota.event_steps,
                self.profile.event_step_limit,
            )?,
        };
        let original = &mut self.history[index];
        original.request[..WHOLE_FRAME_HEADER_BYTES].copy_from_slice(&header);
        original.request[WHOLE_FRAME_HEADER_BYTES..WHOLE_FRAME_HEADER_BYTES + body.len()]
            .copy_from_slice(body);
        original.request_extent = WHOLE_FRAME_HEADER_BYTES + body.len();
        self.charged = charged;
        self.admitted += 1;
        Ok(())
    }

    /// Offers at most one nonblocking write of the retained current original.
    ///
    /// # Errors
    /// Retains partial transmission and refuses expired/nonrenewing physical
    /// credit, absent originals or socket errors. True means all request bytes
    /// were offered, and grants no execution or publication authority.
    pub fn transmit_original(&mut self) -> Result<bool, NativeWholeControlError> {
        self.live()?;
        let index = self
            .admitted
            .checked_sub(1)
            .ok_or(NativeWholeControlError::Custody)?;
        if self.history[index].request_sent == self.history[index].request_extent {
            return Ok(true);
        }
        let remaining = self.write_allowance()?;
        let original = &mut self.history[index];
        let end = original
            .request_extent
            .min(original.request_sent.saturating_add(remaining));
        let offered = end - original.request_sent;
        self.write_attempts += 1;
        self.write_bytes += offered as u64;
        match self
            .socket
            .as_mut()
            .ok_or(NativeWholeControlError::Custody)?
            .write(&original.request[original.request_sent..end])
        {
            Ok(0) => self.refuse(
                io::Error::new(
                    io::ErrorKind::WriteZero,
                    "original socket write returned zero",
                )
                .into(),
            ),
            Ok(count) => {
                original.request_sent += count;
                Ok(original.request_sent == original.request_extent)
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(false)
            }
            Err(error) => self.refuse(error.into()),
        }
    }

    /// Offers the exact full ACK after independently authorized host commitment.
    ///
    /// # Errors
    /// Rejects missing, uncertain or conflicting result custody; retains partial
    /// writes and all historical bodies through physical refusal. Sending this
    /// body never manufactures native consumed acknowledgement.
    pub fn transmit_acknowledgement(&mut self) -> Result<bool, NativeWholeControlError> {
        self.live()?;
        let index = self
            .admitted
            .checked_sub(1)
            .ok_or(NativeWholeControlError::Custody)?;
        let original = &self.history[index];
        if original.result_extent == 0 {
            return Err(NativeWholeControlError::Custody);
        }
        if !original.ack_offered {
            let acknowledgement = WholeAcknowledgement::for_complete(
                &original.request[WHOLE_FRAME_HEADER_BYTES..original.request_extent],
                &original.result[WHOLE_FRAME_HEADER_BYTES..original.result_extent],
            )?;
            let header = encode_whole_frame_header(
                WholeFrameKind::Acknowledgement,
                WHOLE_ACK_BYTES,
                self.profile.body_byte_limit,
            )?;
            let original = &mut self.history[index];
            original.offered_ack[..WHOLE_FRAME_HEADER_BYTES].copy_from_slice(&header);
            original.offered_ack[WHOLE_FRAME_HEADER_BYTES..]
                .copy_from_slice(&acknowledgement.encode()?);
            original.ack_offered = true;
        }
        if self.history[index].ack_sent == WHOLE_FRAME_HEADER_BYTES + WHOLE_ACK_BYTES {
            return Ok(true);
        }
        let remaining = self.write_allowance()?;
        let original = &mut self.history[index];
        let end = original
            .offered_ack
            .len()
            .min(original.ack_sent.saturating_add(remaining));
        self.write_attempts += 1;
        self.write_bytes += (end - original.ack_sent) as u64;
        match self
            .socket
            .as_mut()
            .ok_or(NativeWholeControlError::Custody)?
            .write(&original.offered_ack[original.ack_sent..end])
        {
            Ok(0) => self.refuse(
                io::Error::new(io::ErrorKind::WriteZero, "ACK socket write returned zero").into(),
            ),
            Ok(count) => {
                original.ack_sent += count;
                Ok(original.ack_sent == original.offered_ack.len())
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(false)
            }
            Err(error) => self.refuse(error.into()),
        }
    }

    /// Collects at most one physical prefix into its original result or ACK slot.
    ///
    /// # Errors
    /// Rejects unsolicited, changed or malformed peer records and retains all
    /// partial bytes through socket, clock, quota or custody failures. True
    /// reports one complete retained peer frame, independently of native proof.
    pub fn poll_original(&mut self) -> Result<bool, NativeWholeControlError> {
        self.live()?;
        let index = self
            .admitted
            .checked_sub(1)
            .ok_or(NativeWholeControlError::Custody)?;
        if self.settled == self.admitted {
            return Err(NativeWholeControlError::Custody);
        }
        if self.history[index].request_sent != self.history[index].request_extent {
            return self.refuse(NativeWholeControlError::Custody);
        }
        if self.read_attempts >= self.profile.administrative_read_attempt_limit
            || self.read_bytes >= self.profile.administrative_read_byte_limit
        {
            return self.refuse(NativeWholeControlError::Exhausted);
        }
        let remaining =
            usize::try_from(self.profile.administrative_read_byte_limit - self.read_bytes)
                .unwrap_or(usize::MAX);
        self.read_attempts += 1;
        let received = if self.read.received_header < WHOLE_FRAME_HEADER_BYTES {
            let end =
                WHOLE_FRAME_HEADER_BYTES.min(self.read.received_header.saturating_add(remaining));
            self.socket
                .as_mut()
                .ok_or(NativeWholeControlError::Custody)?
                .read(&mut self.read.header[self.read.received_header..end])
        } else {
            let start = WHOLE_FRAME_HEADER_BYTES + self.read.received_body;
            let end =
                (WHOLE_FRAME_HEADER_BYTES + self.read.extent).min(start.saturating_add(remaining));
            let destination = match self.read.kind {
                Some(WholeFrameKind::Result) => &mut self.history[index].result[start..end],
                Some(WholeFrameKind::Acknowledgement) => {
                    &mut self.history[index].consumed_ack[start..end]
                }
                _ => return self.refuse(NativeWholeControlError::Custody),
            };
            self.socket
                .as_mut()
                .ok_or(NativeWholeControlError::Custody)?
                .read(destination)
        };
        let received = match received {
            Ok(0) => {
                return self.refuse(
                    io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "original peer ended during a frame",
                    )
                    .into(),
                );
            }
            Ok(count) => count,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                return Ok(false);
            }
            Err(error) => return self.refuse(error.into()),
        };
        self.read_bytes += received as u64;
        if self.read.received_header < WHOLE_FRAME_HEADER_BYTES {
            self.read.received_header += received;
            if self.read.received_header != WHOLE_FRAME_HEADER_BYTES {
                return Ok(false);
            }
            let (kind, extent) =
                match decode_whole_frame_header(&self.read.header, self.profile.body_byte_limit) {
                    Ok(decoded) => decoded,
                    Err(error) => return self.refuse(error.into()),
                };
            let expected = if self.history[index].result_extent == 0 {
                WholeFrameKind::Result
            } else {
                WholeFrameKind::Acknowledgement
            };
            if kind != expected
                || (kind == WholeFrameKind::Acknowledgement && !self.history[index].ack_offered)
            {
                return self.refuse(NativeWholeControlError::Custody);
            }
            self.read.kind = Some(kind);
            self.read.extent = extent;
            let original = &mut self.history[index];
            match kind {
                WholeFrameKind::Result => {
                    original.result[..WHOLE_FRAME_HEADER_BYTES].copy_from_slice(&self.read.header)
                }
                WholeFrameKind::Acknowledgement => original.consumed_ack
                    [..WHOLE_FRAME_HEADER_BYTES]
                    .copy_from_slice(&self.read.header),
                WholeFrameKind::Request => return self.refuse(NativeWholeControlError::Custody),
            }
            return Ok(false);
        }
        self.read.received_body += received;
        if self.read.received_body != self.read.extent {
            return Ok(false);
        }
        if let Err(error) = self.accept_complete(index) {
            return self.refuse(error);
        }
        self.read = ReadPrefix::new();
        Ok(true)
    }

    /// Borrows the immutable complete original native result for a retained sequence.
    pub fn original_result(&self, sequence: u64) -> Option<&[u8]> {
        let index = usize::try_from(sequence.checked_sub(1)?).ok()?;
        let original = self.history.get(index)?;
        (original.result_extent != 0)
            .then(|| &original.result[WHOLE_FRAME_HEADER_BYTES..original.result_extent])
    }

    /// Reports exact consumed original ACK retention without releasing world custody.
    pub fn acknowledgement_consumed(&self, sequence: u64) -> bool {
        sequence
            .checked_sub(1)
            .and_then(|index| usize::try_from(index).ok())
            .and_then(|index| self.history.get(index))
            .is_some_and(|original| original.ack_consumed)
    }

    fn accept_complete(&mut self, index: usize) -> Result<(), NativeWholeControlError> {
        let original = &mut self.history[index];
        match self.read.kind {
            Some(WholeFrameKind::Result) => {
                let extent = WHOLE_FRAME_HEADER_BYTES + self.read.extent;
                WholeResult::decode(&original.result[WHOLE_FRAME_HEADER_BYTES..extent])?
                    .validate_against(
                        &original.request[WHOLE_FRAME_HEADER_BYTES..original.request_extent],
                    )?;
                original.result_extent = extent;
            }
            Some(WholeFrameKind::Acknowledgement) => {
                if original.ack_sent != original.offered_ack.len()
                    || original.consumed_ack != original.offered_ack
                {
                    return Err(NativeWholeControlError::Custody);
                }
                original.ack_consumed = true;
                self.settled += 1;
            }
            _ => return Err(NativeWholeControlError::Custody),
        }
        Ok(())
    }

    fn live(&mut self) -> Result<(), NativeWholeControlError> {
        if self.refused || std::process::id() != self.process {
            return Err(NativeWholeControlError::Custody);
        }
        match monotonic_ns() {
            Ok(now) if now < self.profile.deadline_monotonic_ns => Ok(()),
            Ok(_) => self.refuse(NativeWholeControlError::Exhausted),
            Err(error) => self.refuse(error.into()),
        }
    }

    fn write_allowance(&mut self) -> Result<usize, NativeWholeControlError> {
        if self.write_attempts >= self.profile.administrative_write_attempt_limit
            || self.write_bytes >= self.profile.administrative_write_byte_limit
        {
            return self.refuse(NativeWholeControlError::Exhausted);
        }
        Ok(
            usize::try_from(self.profile.administrative_write_byte_limit - self.write_bytes)
                .unwrap_or(usize::MAX),
        )
    }

    fn charge(
        &mut self,
        used: u64,
        offered: u64,
        limit: u64,
    ) -> Result<u64, NativeWholeControlError> {
        match used.checked_add(offered) {
            Some(charged) if charged <= limit => Ok(charged),
            _ => self.refuse(NativeWholeControlError::Exhausted),
        }
    }

    fn refuse<T>(&mut self, error: NativeWholeControlError) -> Result<T, NativeWholeControlError> {
        self.refused = true;
        Err(error)
    }
}

impl ReadPrefix {
    fn new() -> Self {
        Self {
            header: [0; WHOLE_FRAME_HEADER_BYTES],
            received_header: 0,
            extent: 0,
            received_body: 0,
            kind: None,
        }
    }
}

// Passive custody keeps the actual endpoint and its consumed parser prefix.
// The transport has no authenticated whole-world terminal release API yet.
struct QuarantinedWholeControl {
    _socket: UnixStream,
    _profile: WholeControlProfile,
    _history: Vec<OperationHistory>,
    _read: ReadPrefix,
    _admitted: usize,
    _settled: usize,
    _charged: WholeOperationQuota,
    _administrative: [u64; 4],
    _refused: bool,
}

impl Drop for NativeWholeControlTransport {
    fn drop(&mut self) {
        if self.admitted == 0 && !self.refused {
            return;
        }
        let Some(socket) = self.socket.take() else {
            return;
        };
        let custody = QuarantinedWholeControl {
            _socket: socket,
            _profile: self.profile.clone(),
            _history: std::mem::take(&mut self.history),
            _read: std::mem::replace(&mut self.read, ReadPrefix::new()),
            _admitted: self.admitted,
            _settled: self.settled,
            _charged: self.charged,
            _administrative: [
                self.read_attempts,
                self.read_bytes,
                self.write_attempts,
                self.write_bytes,
            ],
            _refused: self.refused,
        };
        static QUARANTINE: std::sync::OnceLock<std::sync::Mutex<Vec<QuarantinedWholeControl>>> =
            std::sync::OnceLock::new();
        let retained = QUARANTINE.get_or_init(|| std::sync::Mutex::new(Vec::new()));
        match retained.lock() {
            Ok(mut retained) => {
                if retained.try_reserve(1).is_ok() {
                    retained.push(custody);
                } else {
                    std::mem::forget(custody);
                }
            }
            Err(_) => {
                // Custody storage failure never closes the original socket or
                // abandons complete/partial bytes under an admitted world.
                std::mem::forget(custody);
            }
        }
    }
}

fn allocated_body(extent: usize) -> Result<Vec<u8>, NativeWholeControlError> {
    let mut body = Vec::new();
    body.try_reserve_exact(extent)
        .map_err(|_| NativeWholeControlError::Allocation)?;
    body.resize(extent, 0);
    Ok(body)
}

fn monotonic_ns() -> io::Result<u64> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: The writable timespec lives throughout this synchronous call.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } != 0 {
        return Err(io::Error::last_os_error());
    }
    u64::try_from(time.tv_sec)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .and_then(|seconds| {
            u64::try_from(time.tv_nsec)
                .ok()
                .and_then(|nanos| seconds.checked_add(nanos))
        })
        .ok_or_else(|| io::Error::other("monotonic clock extent overflow"))
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- Actual socket controls panic on invalid native vectors or custody failures.
    #![allow(clippy::unwrap_used)]

    use super::*;

    const REQUEST: &[u8] = include_bytes!(
        "../../crucible-qemu-protocol/src/whole_control/testdata/native-zero-request.bin"
    );
    const RESULT: &[u8] = include_bytes!(
        "../../crucible-qemu-protocol/src/whole_control/testdata/native-zero-result.bin"
    );
    const ACK: &[u8] = include_bytes!(
        "../../crucible-qemu-protocol/src/whole_control/testdata/native-zero-ack.bin"
    );

    fn profile() -> WholeControlProfile {
        WholeControlProfile {
            scope: WholeRequest::decode(REQUEST).unwrap().scope,
            operation_capacity: 2,
            body_byte_limit: 512,
            native_history_byte_limit: 1_000_000,
            provider_history_byte_limit: 1_000_000,
            administrative_read_attempt_limit: 100,
            administrative_read_byte_limit: 100_000,
            administrative_write_attempt_limit: 100,
            administrative_write_byte_limit: 100_000,
            deadline_monotonic_ns: monotonic_ns().unwrap() + 10_000_000_000,
            cpu_retirement_limit: 1000,
            event_step_limit: 1000,
            input_byte_limit: 0,
            input_record_limit: 0,
            output_byte_limit: 0,
            output_record_limit: 0,
        }
    }

    fn frame(kind: WholeFrameKind, body: &[u8]) -> Vec<u8> {
        let mut bytes = encode_whole_frame_header(kind, body.len(), 512)
            .unwrap()
            .to_vec();
        bytes.extend_from_slice(body);
        bytes
    }

    #[test]
    fn same_socket_native_result_and_consumed_ack_keep_full_original_history() {
        let (socket, mut peer) = UnixStream::pair().unwrap();
        let mut transport = NativeWholeControlTransport::new(socket, profile()).unwrap();
        transport.retain_original(REQUEST).unwrap();
        assert!(transport.transmit_original().unwrap());
        let mut received = vec![0; WHOLE_FRAME_HEADER_BYTES + REQUEST.len()];
        peer.read_exact(&mut received).unwrap();
        assert_eq!(received, frame(WholeFrameKind::Request, REQUEST));

        let native_result = frame(WholeFrameKind::Result, RESULT);
        peer.write_all(&native_result[..9]).unwrap();
        assert!(!transport.poll_original().unwrap());
        assert_eq!(&transport.read.header[..9], &native_result[..9]);
        assert!(transport.original_result(1).is_none());
        peer.write_all(&native_result[9..]).unwrap();
        assert!(!transport.poll_original().unwrap());
        assert!(transport.poll_original().unwrap());
        assert_eq!(transport.original_result(1).unwrap(), RESULT);
        assert!(!transport.acknowledgement_consumed(1));

        assert!(transport.transmit_acknowledgement().unwrap());
        let mut offered = vec![0; WHOLE_FRAME_HEADER_BYTES + ACK.len()];
        peer.read_exact(&mut offered).unwrap();
        assert_eq!(offered, frame(WholeFrameKind::Acknowledgement, ACK));
        assert!(!transport.acknowledgement_consumed(1));
        peer.write_all(&offered).unwrap();
        assert!(!transport.poll_original().unwrap());
        assert!(transport.poll_original().unwrap());
        assert!(transport.acknowledgement_consumed(1));
        assert_eq!(transport.original_result(1).unwrap(), RESULT);
        assert_eq!(transport.settled, 1);
        assert_eq!(
            &transport.history[0].request
                [WHOLE_FRAME_HEADER_BYTES..transport.history[0].request_extent],
            REQUEST
        );
    }

    #[test]
    fn changed_consumed_ack_refuses_without_releasing_previous_bodies() {
        let (socket, mut peer) = UnixStream::pair().unwrap();
        let mut transport = NativeWholeControlTransport::new(socket, profile()).unwrap();
        transport.retain_original(REQUEST).unwrap();
        transport.transmit_original().unwrap();
        let mut request = vec![0; WHOLE_FRAME_HEADER_BYTES + REQUEST.len()];
        peer.read_exact(&mut request).unwrap();
        peer.write_all(&frame(WholeFrameKind::Result, RESULT))
            .unwrap();
        assert!(!transport.poll_original().unwrap());
        assert!(transport.poll_original().unwrap());
        transport.transmit_acknowledgement().unwrap();
        let mut offered = vec![0; WHOLE_FRAME_HEADER_BYTES + ACK.len()];
        peer.read_exact(&mut offered).unwrap();
        offered[WHOLE_FRAME_HEADER_BYTES + 96] ^= 1;
        peer.write_all(&offered).unwrap();
        assert!(!transport.poll_original().unwrap());
        assert!(matches!(
            transport.poll_original(),
            Err(NativeWholeControlError::Custody)
        ));
        assert_eq!(transport.original_result(1).unwrap(), RESULT);
        assert!(!transport.acknowledgement_consumed(1));
        assert_eq!(transport.settled, 0);
        assert!(transport.refused);
    }

    #[test]
    fn exhausting_offered_cpu_budget_never_refunds_or_recycles() {
        let (socket, _peer) = UnixStream::pair().unwrap();
        let mut selected = profile();
        selected.cpu_retirement_limit = 1;
        let mut request = WholeRequest::decode(REQUEST).unwrap();
        request.quota.cpu_retirements = 2;
        let mut request_body = vec![0; REQUEST.len()];
        request.encode_into(&mut request_body).unwrap();
        let mut transport = NativeWholeControlTransport::new(socket, selected).unwrap();
        assert!(matches!(
            transport.retain_original(&request_body),
            Err(NativeWholeControlError::Exhausted)
        ));
        assert_eq!(transport.admitted, 0);
        assert_eq!(transport.charged.cpu_retirements, 0);
        assert!(matches!(
            transport.retain_original(&request_body),
            Err(NativeWholeControlError::Custody)
        ));
    }
}
