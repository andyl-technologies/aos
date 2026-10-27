//! Retains the reached record-vector, constructor and canonical encoding work.

use super::*;
use super::super::history::HistoryBuildOriginalsV1;

#[doc(hidden)]
pub struct HistoryDecodeOriginalsV1 {
    pub(super) records: Option<Vec<HierarchyHistoryRecordV1>>,
    pub(super) allocation: Option<Result<(), std::collections::TryReserveError>>,
    pub(super) model: HistoryBuildOriginalsV1,
    history: Option<HierarchyHistoryV1>,
    outcome: Option<Result<(), HierarchyCodecError>>,
    closed: Option<HierarchyCodecError>,
    entered: bool,
}

impl HistoryDecodeOriginalsV1 {
    /// Preserves the canonical new DATA operation.
    pub const fn new() -> Self {
        Self {
            records: None,
            allocation: None,
            model: HistoryBuildOriginalsV1::new(),
            history: None,
            outcome: None,
            closed: None,
            entered: false,
        }
    }

    /// Preserves the canonical history DATA operation.
    pub fn history(&self) -> Option<&HierarchyHistoryV1> {
        if self.failure().is_some() { None } else { self.history.as_ref() }
    }

    /// Preserves the canonical failure DATA operation.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.allocation.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.model.failure().map(|cause| cause as _))
            .or_else(|| self.outcome.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    /// Preserves the canonical fixed footprint v1 DATA operation.
    pub fn fixed_footprint_v1() -> Option<(usize, usize)> {
        use aos_sandbox_model::bounded_codec::CaptureOnDropV1;
        use std::mem::size_of;

        let (model_bytes, model_cells) = HistoryBuildOriginalsV1::fixed_footprint_v1()?;
        let bytes = size_of::<Self>().checked_mul(2)?
            .checked_add(model_bytes.checked_sub(size_of::<HistoryBuildOriginalsV1>().checked_mul(2)?)?)?
            .checked_add(size_of::<CaptureOnDropV1<'static, Vec<HierarchyHistoryRecordV1>>>())?;
        // 7 fields, model's actual destinations, record Vec guard, 4 history roots.
        Some((bytes, 7usize.checked_add(model_cells)?.checked_add(2 + 4)?))
    }
}

/// Preserves the canonical decode history retaining v1 DATA operation.
///
/// # Errors
/// Rejects noncanonical fixed fields, a mismatched history chain,
/// a failed checked bound, allocation failure or repeated capture use.
pub fn decode_history_retaining_v1(
    bytes: &[u8],
    originals: &mut HistoryDecodeOriginalsV1,
) -> Result<(), HierarchyCodecError> {
    if originals.entered {
        originals.closed.get_or_insert(HierarchyCodecError::CorruptEncoding);
        return Err(HierarchyCodecError::CorruptEncoding);
    }
    originals.entered = true;
    let result = decode_history_with_originals(bytes, Some(originals));
    originals.outcome = Some(match result {
        Ok(history) => { originals.history = Some(history); Ok(()) }
        Err(cause) => Err(cause),
    });
    match &originals.outcome {
        Some(Ok(())) => Ok(()),
        _ => Err(HierarchyCodecError::CorruptEncoding),
    }
}

/// Preserves the canonical encode history retaining v1 DATA operation.
///
/// # Errors
/// Rejects noncanonical fixed fields, a mismatched history chain,
/// a failed checked bound, allocation failure or repeated capture use.
pub fn encode_history_retaining_v1(
    history: &HierarchyHistoryV1,
    originals: &mut CanonicalEncodingOriginalsV1,
) -> Result<(), HierarchyCodecError> {
    originals.enter_once()?;
    let result = encode_history_with_originals(history, Some(originals));
    originals.park_returned(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project() -> ProjectId { ProjectId::from_bytes([1; 16]) }

    fn record(sequence: u64, predecessor: Option<ObjectDigest>) -> HierarchyHistoryRecordV1 {
        HierarchyHistoryRecordV1::from_parts(
            project(), sequence, HierarchyHistorySubjectV1::Sandbox(SandboxId::from_bytes([2; 16])),
            HierarchyTransitionKindV1::CreateRoot, OperationId::from_bytes([3; 16]),
            ObjectDigest::from_bytes([4; 32]), ObjectDigest::from_bytes([5; 32]),
            None, predecessor, ObjectDigest::from_bytes([6; 32]),
        ).unwrap()
    }

    fn encoded_records(records: &[HierarchyHistoryRecordV1]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(HISTORY_LOG_MAGIC);
        bytes.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
        bytes.extend_from_slice(&[0; 2]);
        bytes.extend_from_slice(project().as_bytes());
        bytes.extend_from_slice(&(records.len() as u32).to_be_bytes());
        for record in records { bytes.extend_from_slice(&encode_history_record_v1(*record).unwrap()); }
        bytes
    }

    #[test]
    fn malformed_second_record_keeps_the_actual_decoded_prefix() {
        let first = record(1, None);
        let mut bytes = encoded_records(&[first, record(2, Some(first.record_commitment()))]);
        bytes[HISTORY_LOG_HEADER_BYTES + HISTORY_RECORD_BYTES] ^= 1;
        assert!(decode_history_v1(&bytes).is_err());
        let mut originals = HistoryDecodeOriginalsV1::new();

        assert!(decode_history_retaining_v1(&bytes, &mut originals).is_err());
        assert_eq!(originals.records.as_deref(), Some([first].as_slice()));
        assert!(matches!(originals.allocation, Some(Ok(()))));
        assert!(matches!(originals.outcome, Some(Err(HierarchyCodecError::InvalidHeader))));
        let cause = originals.failure().unwrap() as *const dyn std::error::Error;
        assert!(decode_history_retaining_v1(&[], &mut originals).is_err());
        assert!(std::ptr::addr_eq(originals.failure().unwrap(), cause));
        assert_eq!(originals.records.as_deref(), Some([first].as_slice()));
    }

    #[test]
    fn constructor_refusal_retains_records_and_all_reached_indexes() {
        let first = record(1, None);
        let bytes = encoded_records(&[first, record(3, Some(first.record_commitment()))]);
        assert!(decode_history_v1(&bytes).is_err());
        let mut originals = HistoryDecodeOriginalsV1::new();

        assert!(decode_history_retaining_v1(&bytes, &mut originals).is_err());
        assert_eq!(originals.model.retained_counts_v1(), (Some(2), Some(1), Some(1), Some(1)));
        assert!(originals.records.is_none());
        assert!(matches!(originals.failure().unwrap().downcast_ref::<HierarchyHistoryError>(),
            Some(HierarchyHistoryError::CorruptHistory)));
    }

    #[test]
    fn ordinary_and_retained_positive_history_share_the_same_canonical_result() {
        let bytes = encoded_records(&[record(1, None)]);
        let ordinary = decode_history_v1(&bytes).unwrap();
        let mut decoded = HistoryDecodeOriginalsV1::new();
        decode_history_retaining_v1(&bytes, &mut decoded).unwrap();
        assert_eq!(decoded.history(), Some(&ordinary));

        let mut encoded = CanonicalEncodingOriginalsV1::new();
        encode_history_retaining_v1(decoded.history().unwrap(), &mut encoded).unwrap();
        assert_eq!(encoded.bytes(), Some(bytes.as_slice()));
        assert_eq!(encode_history_v1(&ordinary).unwrap(), bytes);
        assert!(HistoryDecodeOriginalsV1::fixed_footprint_v1().is_some());
        assert!(CanonicalEncodingOriginalsV1::fixed_footprint_v1().is_some());
    }
}
