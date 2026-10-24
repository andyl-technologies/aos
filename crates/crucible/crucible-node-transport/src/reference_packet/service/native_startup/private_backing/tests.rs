//! Compares the actual upper compiled layout suppliers with the saved originals.

use super::*;

fn original_bank() -> Result<usize, ProviderError> {
    use crate::transport::original_frames::OriginalFrameReservation;
    use std::{
        cell::RefCell,
        mem::{align_of, size_of},
    };
    size_of::<RefCell<OriginalFrameReservation>>()
        .checked_add(
            crate::retained_metadata::requested_storage::shared_header_storage_data(
                1,
                align_of::<RefCell<OriginalFrameReservation>>(),
            )?,
        )
        .ok_or_else(invalid)
}

fn original_invocation() -> Result<usize, ProviderError> {
    if !cfg!(all(target_os = "linux", target_pointer_width = "64")) {
        return Err(invalid());
    }
    let slots = 4usize
        .checked_mul(std::mem::size_of::<std::ffi::OsString>())
        .ok_or_else(invalid)?;
    8192usize
        .checked_add(2 * 4096 + "--original-native-startup14".len())
        .and_then(|bytes| bytes.checked_add(slots))
        .ok_or_else(invalid)
}

#[test]
fn actual_compiled_payload_and_os_string_facts_match_both_original_bodies()
-> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(LAYOUT_DATA.os_string_bytes, size_of::<std::ffi::OsString>());
    assert_eq!(
        LAYOUT_DATA.frame_reservation_bytes,
        size_of::<RefCell<OriginalFrameReservation>>()
    );
    assert_eq!(
        LAYOUT_DATA.frame_reservation_alignment,
        align_of::<RefCell<OriginalFrameReservation>>()
    );

    assert_eq!(
        super::super::original_native_private_bank_shared_layout_data()?,
        original_bank()?
    );
    if cfg!(all(target_os = "linux", target_pointer_width = "64")) {
        assert_eq!(
            super::super::original_native_private_invocation_backing_data()?,
            original_invocation()?
        );
    } else {
        assert!(super::super::original_native_private_invocation_backing_data().is_err());
        assert!(original_invocation().is_err());
    }
    Ok(())
}

fn invalid() -> ProviderError {
    ProviderError::Correlation("original native startup allocation data")
}
