//! Encodes the closed version-one maintenance operation and bounded results.
//!
//! All integers use little endian. No packet carries descriptors or row data.
//!
//! ```text
//! request: magic[8] | operation:u64=1 | sequence:u64
//! reply:   magic[8] | outcome:u64 | sequence:u64 | checked:u64 | completed:u64 | blocked:u64
//! magic = "TRNMNT01"; success = 0; errors = 2..6 with all counts zero
//! ```

use crate::host_cache::NativeExposureReconciliation;
use std::io;

pub(super) const MAX_PACKET: usize = 48;
const MAGIC: &[u8; 8] = b"TRNMNT01";

pub(super) fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

pub(super) fn encode_request(sequence: u64) -> [u8; 24] {
    let mut packet = [0; 24];
    packet[..8].copy_from_slice(MAGIC);
    packet[8..16].copy_from_slice(&1_u64.to_le_bytes());
    packet[16..].copy_from_slice(&sequence.to_le_bytes());
    packet
}

pub(super) fn request(packet: &[u8], sequence: u64) -> io::Result<()> {
    if sequence == 0 || packet != encode_request(sequence) {
        return Err(invalid("unsupported or replayed maintenance request"));
    }
    Ok(())
}

pub(super) fn reply(
    sequence: u64,
    result: &io::Result<NativeExposureReconciliation>,
) -> io::Result<[u8; MAX_PACKET]> {
    let values = match result {
        Ok(report) => [
            0,
            sequence,
            u64::try_from(report.checked).map_err(|_| invalid("maintenance count overflow"))?,
            u64::try_from(report.completed).map_err(|_| invalid("maintenance count overflow"))?,
            u64::try_from(report.blocked).map_err(|_| invalid("maintenance count overflow"))?,
        ],
        Err(error) => [error_code(error.kind()), sequence, 0, 0, 0],
    };
    let mut packet = [0; MAX_PACKET];
    packet[..8].copy_from_slice(MAGIC);
    for (target, value) in packet[8..].as_chunks_mut::<8>().0.iter_mut().zip(values) {
        target.copy_from_slice(&value.to_le_bytes());
    }
    Ok(packet)
}

pub(super) fn decode_reply(
    packet: &[u8],
    sequence: u64,
) -> io::Result<io::Result<NativeExposureReconciliation>> {
    if sequence == 0 || packet.len() != MAX_PACKET || &packet[..8] != MAGIC {
        return Err(invalid("unsupported maintenance reply"));
    }
    let mut values = [0_u64; 5];
    for (value, bytes) in values.iter_mut().zip(packet[8..].as_chunks::<8>().0) {
        *value = u64::from_le_bytes(*bytes);
    }
    let [outcome, received, checked, completed, blocked] = values;
    if received != sequence {
        return Err(invalid("maintenance reply sequence differs"));
    }
    if outcome != 0 {
        if checked != 0 || completed != 0 || blocked != 0 {
            return Err(invalid("failed maintenance reply carries counts"));
        }
        let kind = match outcome {
            2 => io::ErrorKind::PermissionDenied,
            3 => io::ErrorKind::WouldBlock,
            4 => io::ErrorKind::Unsupported,
            5 => io::ErrorKind::BrokenPipe,
            6 => io::ErrorKind::Other,
            _ => return Err(invalid("unregistered maintenance outcome")),
        };
        return Ok(Err(io::Error::new(
            kind,
            "native maintenance request refused",
        )));
    }
    if completed.checked_add(blocked) != Some(checked) {
        return Err(invalid("maintenance result counts differ"));
    }
    let count = |value| usize::try_from(value).map_err(|_| invalid("maintenance count overflow"));
    Ok(Ok(NativeExposureReconciliation {
        checked: count(checked)?,
        completed: count(completed)?,
        blocked: count(blocked)?,
    }))
}

fn error_code(kind: io::ErrorKind) -> u64 {
    match kind {
        io::ErrorKind::PermissionDenied => 2,
        io::ErrorKind::WouldBlock => 3,
        io::ErrorKind::Unsupported => 4,
        io::ErrorKind::BrokenPipe => 5,
        _ => 6,
    }
}
