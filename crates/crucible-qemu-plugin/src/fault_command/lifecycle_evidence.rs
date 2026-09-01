//! Lifecycle evidence translation between raw QEMU and logical coordinates.

use super::*;

const LIFECYCLE_EVIDENCE_BYTES: usize = 304;
const LIFECYCLE_OBSERVED_ICOUNT_OFFSET: usize = 24;

pub(super) fn translate_lifecycle_evidence(
    payload: &[u8],
    event: &QemuFaultEvent,
    logical_icount_offset: u64,
) -> Result<Vec<u8>, FaultCommandBridgeError> {
    if payload.len() != LIFECYCLE_EVIDENCE_BYTES || payload.get(..8) != Some(b"CRUCLIF1") {
        return Err(FaultCommandBridgeError::EventEnvelope);
    }
    let observed_bytes = payload
        .get(LIFECYCLE_OBSERVED_ICOUNT_OFFSET..LIFECYCLE_OBSERVED_ICOUNT_OFFSET + 8)
        .ok_or(FaultCommandBridgeError::EventEnvelope)?;
    let raw_observed_icount = u64::from_le_bytes(
        observed_bytes
            .try_into()
            .map_err(|_source| FaultCommandBridgeError::EventEnvelope)?,
    );
    if raw_observed_icount != event.observed_icount {
        return Err(FaultCommandBridgeError::EventEnvelope);
    }
    let logical_observed_icount = raw_observed_icount
        .checked_add(logical_icount_offset)
        .ok_or(FaultCommandBridgeError::CoordinateOverflow)?;
    let mut translated = payload.to_vec();
    translated[LIFECYCLE_OBSERVED_ICOUNT_OFFSET..LIFECYCLE_OBSERVED_ICOUNT_OFFSET + 8]
        .copy_from_slice(&logical_observed_icount.to_le_bytes());
    Ok(translated)
}
