//! Carries the closed P input stream and original trusted lifecycle fence DATA.
//!
//! ```text
//! AOSNPI02 || version:u16=2 || method:u16=63|9 || total:u32 ||
//! dispatch-length:u32 || trusted-fence-length:u32 || dispatch || trusted-fence
//! ```
//!
//! The signed dispatch retains its original canonical codec. Only actual9
//! carries the separately borrowed genuine coordinator fence; claimed dispatch
//! bytes cannot stand in for that supplier. Native Source binding and signed
//! admission remain mandatory and cannot be constructed by this DATA codec.

use super::MAXIMUM_NETWORK_WORKER_REQUEST_BYTES;

pub(super) const INPUT_HEADER_BYTES: usize = 24;

/// Borrows the exact framed input without granting dispatch or Source authority.
pub(crate) struct PreparationInputDataV2<'a> {
    pub(crate) method: u16,
    pub(crate) dispatch: &'a [u8],
    pub(crate) trusted_current_fence: &'a [u8],
}

impl<'a> PreparationInputDataV2<'a> {
    pub(crate) fn decode(bytes: &'a [u8]) -> Option<Self> {
        let (method, dispatch, fence, total) = header_data_v2(bytes.get(..INPUT_HEADER_BYTES)?)?;
        if bytes.len() != total {
            return None;
        }
        let end = INPUT_HEADER_BYTES.checked_add(dispatch)?;
        Some(Self { method, dispatch: bytes.get(INPUT_HEADER_BYTES..end)?,
            trusted_current_fence: bytes.get(end..end.checked_add(fence)?)? })
    }
}

pub(super) fn header_data_v2(header: &[u8]) -> Option<(u16, usize, usize, usize)> {
    if header.len() != INPUT_HEADER_BYTES || &header[..8] != b"AOSNPI02"
        || header[8..10] != 2_u16.to_be_bytes() {
        return None;
    }
    let method = u16::from_be_bytes(header[10..12].try_into().ok()?);
    let total = usize::try_from(u32::from_be_bytes(header[12..16].try_into().ok()?)).ok()?;
    let dispatch = usize::try_from(u32::from_be_bytes(header[16..20].try_into().ok()?)).ok()?;
    let fence = usize::try_from(u32::from_be_bytes(header[20..24].try_into().ok()?)).ok()?;
    if encoded_length_data_v2(method, dispatch, fence)? != total { return None; }
    Some((method, dispatch, fence, total))
}

pub(super) fn encoded_length_data_v2(method: u16, dispatch: usize, fence: usize) -> Option<usize> {
    if dispatch == 0 || !matches!((method, fence), (63, 0) | (9, 1..)) { return None; }
    INPUT_HEADER_BYTES.checked_add(dispatch)?.checked_add(fence)
        .filter(|total| *total <= MAXIMUM_NETWORK_WORKER_REQUEST_BYTES)
}

pub(super) fn encode_data_v2(method: u16, dispatch: &[u8], fence: &[u8]) -> Option<Vec<u8>> {
    let total = encoded_length_data_v2(method, dispatch.len(), fence.len())?;
    let mut bytes = Vec::with_capacity(total);
    bytes.extend_from_slice(b"AOSNPI02");
    bytes.extend_from_slice(&2_u16.to_be_bytes());
    bytes.extend_from_slice(&method.to_be_bytes());
    for length in [total, dispatch.len(), fence.len()] {
        bytes.extend_from_slice(&u32::try_from(length).ok()?.to_be_bytes());
    }
    bytes.extend_from_slice(dispatch);
    bytes.extend_from_slice(fence);
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_nine_fence_is_distinct_and_sixty_three_has_none() {
        let bytes = encode_data_v2(9, b"original-nine-dispatch", b"actual-coordinator-fence").unwrap();
        let decoded = PreparationInputDataV2::decode(&bytes).unwrap();
        assert_eq!(decoded.method, 9);
        assert_eq!(decoded.dispatch, b"original-nine-dispatch");
        assert_eq!(decoded.trusted_current_fence, b"actual-coordinator-fence");
        assert!(encode_data_v2(9, b"dispatch", b"").is_none());
        assert!(encode_data_v2(63, b"dispatch", b"claimed").is_none());
        assert!(PreparationInputDataV2::decode(b"AOSNLW01").is_none());
        assert!(encoded_length_data_v2(63, MAXIMUM_NETWORK_WORKER_REQUEST_BYTES, 0).is_none());
    }
}
