//! Retains the actual canonical Tree or History encoding and reservation cause.

use std::collections::TryReserveError;
use std::mem::size_of;

use aos_sandbox_model::bounded_codec::CaptureOnDropV1;

use super::{HierarchyCodecError, SandboxTreeV1, encode_tree_with_originals};

/// Owns pure encoding work; it grants no journal or receiving access.
#[doc(hidden)]
pub struct CanonicalEncodingOriginalsV1 {
    pub(super) bytes: Option<Vec<u8>>,
    pub(super) allocation: Option<Result<(), TryReserveError>>,
    outcome: Option<Result<Vec<u8>, HierarchyCodecError>>,
    closed: Option<HierarchyCodecError>,
    entered: bool,
}

impl CanonicalEncodingOriginalsV1 {
    /// Preserves the canonical new DATA operation.
    pub const fn new() -> Self {
        Self { bytes: None, allocation: None, outcome: None, closed: None, entered: false }
    }

    /// Preserves the canonical bytes DATA operation.
    pub fn bytes(&self) -> Option<&[u8]> {
        if self.failure().is_some() { return None; }
        self.outcome.as_ref()?.as_ref().ok().map(Vec::as_slice)
    }

    /// Preserves the canonical failure DATA operation.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.allocation.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.outcome.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    pub(super) fn enter_once(&mut self) -> Result<(), HierarchyCodecError> {
        if self.entered {
            self.closed.get_or_insert(HierarchyCodecError::CorruptEncoding);
            return Err(HierarchyCodecError::CorruptEncoding);
        }
        self.entered = true;
        Ok(())
    }

    pub(super) fn park_returned(
        &mut self,
        result: Result<Vec<u8>, HierarchyCodecError>,
    ) -> Result<(), HierarchyCodecError> {
        self.outcome = Some(result);
        match &self.outcome {
            Some(Ok(_)) => Ok(()),
            _ => Err(HierarchyCodecError::CorruptEncoding),
        }
    }

    /// Preserves the canonical fixed footprint v1 DATA operation.
    pub fn fixed_footprint_v1() -> Option<(usize, usize)> {
        // Two concrete owner lanes cover construction plus its destination.
        // The remaining terms name the guard, engine argument/two sink loans,
        // reserve call, pattern loans, and named wrapper/result controls.
        let bytes = size_of::<Self>().checked_mul(2)?
            .checked_add(size_of::<CaptureOnDropV1<'static, Vec<u8>>>())?
            .checked_add(size_of::<Option<&'static mut Self>>())?
            .checked_add(size_of::<Option<&'static mut Option<Vec<u8>>>>())?
            .checked_add(size_of::<Option<&'static mut Option<Result<(), TryReserveError>>>>().checked_mul(2)?)?
            .checked_add(size_of::<&'static mut Vec<u8>>())?
            .checked_add(size_of::<usize>())?
            .checked_add(size_of::<Result<(), HierarchyCodecError>>().checked_mul(2)?)?
            .checked_add(size_of::<Result<Vec<u8>, HierarchyCodecError>>())?
            .checked_add(size_of::<&'static mut Self>())?
            .checked_add(size_of::<&'static mut Option<Result<(), TryReserveError>>>())?
            .checked_add(size_of::<&'static Option<Result<Vec<u8>, HierarchyCodecError>>>())?
            .checked_add(size_of::<&'static SandboxTreeV1>())?
            .checked_add(size_of::<&'static super::HierarchyHistoryV1>())?;
        // Owner fields5, guard2, engine argument/pattern/sinks4, reserve
        // arguments/pattern/result5, wrapper model/owner/result/entry4 and
        // outcome inspection1. Both named model-reference widths are priced.
        // Encoded byte backing is charged by the reached-row supplier.
        Some((bytes, 5 + 2 + 4 + 5 + 4 + 1))
    }
}

/// Preserves the canonical encode tree retaining v1 DATA operation.
///
/// # Errors
/// Rejects noncanonical fixed fields, a mismatched history chain,
/// a failed checked bound, allocation failure or repeated capture use.
pub fn encode_tree_retaining_v1(
    tree: &SandboxTreeV1,
    originals: &mut CanonicalEncodingOriginalsV1,
) -> Result<(), HierarchyCodecError> {
    originals.enter_once()?;
    let result = encode_tree_with_originals(tree, Some(originals));
    originals.park_returned(result)
}

// Both encoders use this exact reservation. None keeps the original consuming
// map_err boundary; Some parks the same native error before coarse projection.
pub(super) fn reserve_encoding_capacity(
    bytes: &mut Vec<u8>,
    amount: usize,
    allocation: Option<&mut Option<Result<(), TryReserveError>>>,
) -> Result<(), HierarchyCodecError> {
    match allocation {
        Some(allocation) => {
            *allocation = Some(bytes.try_reserve_exact(amount));
            if matches!(allocation, Some(Ok(()))) {
                Ok(())
            } else {
                Err(HierarchyCodecError::Capacity)
            }
        }
        None => bytes.try_reserve_exact(amount).map_err(|_| HierarchyCodecError::Capacity),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{ProjectId, Revision, TreeLimitsV1, encode_tree_v1};

    #[test]
    fn actual_capacity_failure_keeps_the_prefix_and_original_reservation_error() {
        let mut originals = CanonicalEncodingOriginalsV1::new();
        originals.enter_once().unwrap();
        let result = {
            let mut bytes = CaptureOnDropV1::new(vec![1, 2, 3], Some(&mut originals.bytes));
            reserve_encoding_capacity(&mut bytes, usize::MAX, Some(&mut originals.allocation))
                .map(|()| bytes.into_inner())
        };
        assert!(matches!(result, Err(HierarchyCodecError::Capacity)));
        assert!(originals.park_returned(result).is_err());
        assert_eq!(originals.bytes.as_deref(), Some([1, 2, 3].as_slice()));
        let cause = originals.failure().unwrap();
        assert!(cause.downcast_ref::<TryReserveError>().is_some());
        let cause = cause as *const dyn std::error::Error;

        assert!(originals.enter_once().is_err());
        assert!(std::ptr::addr_eq(originals.failure().unwrap(), cause));
        assert_eq!(originals.bytes.as_deref(), Some([1, 2, 3].as_slice()));
        assert!(matches!(originals.outcome, Some(Err(HierarchyCodecError::Capacity))));
    }

    #[test]
    fn ordinary_and_retained_tree_encodings_match_and_reentry_keeps_the_allocation() {
        let tree = SandboxTreeV1::from_records(
            ProjectId::from_bytes([1; 16]), Revision::new(1),
            TreeLimitsV1::new(1, 8, 7, 6, 5, 4, 3).unwrap(), Vec::new(),
        ).unwrap();
        let ordinary = encode_tree_v1(&tree).unwrap();
        let mut originals = CanonicalEncodingOriginalsV1::new();

        encode_tree_retaining_v1(&tree, &mut originals).unwrap();
        assert_eq!(originals.bytes(), Some(ordinary.as_slice()));
        assert!(matches!(originals.allocation, Some(Ok(()))));
        let allocation = originals.outcome.as_ref().unwrap().as_ref().unwrap().as_ptr();
        assert!(encode_tree_retaining_v1(&tree, &mut originals).is_err());
        assert!(originals.bytes().is_none());
        assert_eq!(originals.outcome.as_ref().unwrap().as_ref().unwrap().as_ptr(), allocation);
        assert!(CanonicalEncodingOriginalsV1::fixed_footprint_v1().is_some());
    }
}
