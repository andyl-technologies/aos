//! Counts fixed private bootstrap backing from genuine compiled primitive facts.
//!
//! These requested-layout numbers create no private bank, Source permission or
//! native scope. Transport retains the original authenticated bootstrap floor.
//! Linux64 invocation arithmetic follows the selected original ArgsOs/Stdin path.

use crate::ProviderError;

/// Names the actual upper primitive headers needed by private-bank arithmetic.
///
/// Values describe compiled types only; they are not final requested backing,
/// retained/transient/scratch rows, allocator sizes or evidence of native origin.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivateBackingLayoutData {
    /// Names the actual compiled OsString inline width.
    pub os_string_bytes: usize,
    /// Names the actual compiled RefCell<OriginalFrameReservation> payload width.
    pub frame_reservation_bytes: usize,
    /// Names that same actual payload's compiled alignment.
    pub frame_reservation_alignment: usize,
}

/// Counts the actual shared reservation payload and defining aligned header.
///
/// # Errors
/// Preserves the defining shared-header alignment/overflow refusal before the
/// original final payload-addition overflow diagnostic.
pub fn shared_bank_layout_data(
    frame_reservation_bytes: usize,
    frame_reservation_alignment: usize,
) -> Result<usize, ProviderError> {
    frame_reservation_bytes
        .checked_add(
            crate::profile::requested_storage::shared_header_storage_data(
                1,
                frame_reservation_alignment,
            )?,
        )
        .ok_or_else(invalid)
}

/// Counts the selected original Linux64 ArgsOs slots and Stdin backing.
///
/// The real launcher fixes executable/socket/flag and both path extents at most
/// 4096. This API derives the actual compiled target itself; no public caller
/// predicate can select a supported target or create native authority.
///
/// # Errors
/// Refuses another compiled target or the original checked slots/backing overflow.
pub fn invocation_backing_data(os_string_bytes: usize) -> Result<usize, ProviderError> {
    invocation_backing_for_target_data(
        os_string_bytes,
        cfg!(all(target_os = "linux", target_pointer_width = "64")),
    )
}

// The production caller supplies only its actual compiled target. Keeping this
// gate private permits an unsupported-branch control without a public override.
fn invocation_backing_for_target_data(
    os_string_bytes: usize,
    linux64: bool,
) -> Result<usize, ProviderError> {
    if !linux64 {
        return Err(invalid());
    }
    let slots = 4usize.checked_mul(os_string_bytes).ok_or_else(invalid)?;
    8192usize
        .checked_add(2 * 4096 + "--original-native-startup14".len())
        .and_then(|bytes| bytes.checked_add(slots))
        .ok_or_else(invalid)
}

fn invalid() -> ProviderError {
    ProviderError::Correlation("original native startup allocation data")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_invocation_uses_the_actual_target_and_private_unsupported_guard_refuses() {
        let actual = invocation_backing_data(0);
        assert_eq!(
            actual.is_ok(),
            cfg!(all(target_os = "linux", target_pointer_width = "64"))
        );
        assert!(matches!(
            invocation_backing_for_target_data(0, false),
            Err(ProviderError::Correlation(
                "original native startup allocation data"
            ))
        ));
    }

    #[test]
    fn checked_invocation_overflow_and_shared_alignment_errors_keep_original_diagnostics() {
        assert!(matches!(
            invocation_backing_for_target_data(usize::MAX, true),
            Err(ProviderError::Correlation(
                "original native startup allocation data"
            ))
        ));
        assert!(matches!(
            shared_bank_layout_data(usize::MAX, 3),
            Err(ProviderError::ResourceExhausted(
                "metadata requested backing storage"
            ))
        ));
        assert!(matches!(
            shared_bank_layout_data(usize::MAX, 8),
            Err(ProviderError::Correlation(
                "original native startup allocation data"
            ))
        ));
    }
}
